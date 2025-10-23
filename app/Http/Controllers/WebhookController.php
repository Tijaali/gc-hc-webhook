<?php

namespace App\Http\Controllers;

use Carbon\Carbon;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Storage;

class WebhookController extends Controller
{
    private string $hsTokenUrl = 'https://api.helpscout.net/v2/oauth2/token';
    private string $hsApi      = 'https://api.helpscout.net/v2';

    /* ============================================================
     * Help Scout OAuth: start + callback (+ persisted refresh token)
     * ============================================================ */
    public function hsStart()
    {
        $clientId    = env('HS_CLIENT_ID');
        $redirectUri = env('HS_REDIRECT_URI');
        abort_unless($clientId && $redirectUri, 500, 'Missing HS_CLIENT_ID or HS_REDIRECT_URI');

        $authUrl = 'https://secure.helpscout.net/authentication/authorizeClientApplication'
            . '?client_id='    . urlencode($clientId)
            . '&redirect_uri=' . urlencode($redirectUri);

        return redirect($authUrl);
    }

    public function hsCallback(Request $r)
    {
        abort_unless($r->has('code'), 400, 'Missing code');

        $resp = Http::asForm()->post($this->hsTokenUrl, [
            'grant_type'    => 'authorization_code',
            'code'          => $r->query('code'),
            'client_id'     => env('HS_CLIENT_ID'),
            'client_secret' => env('HS_CLIENT_SECRET'),
            'redirect_uri'  => env('HS_REDIRECT_URI'),
        ]);

        if (!$resp->ok()) {
            return response()->json(['error' => 'oauth_exchange_failed', 'raw' => $resp->json()], $resp->status());
        }

        $data = $resp->json();
        if (!empty($data['refresh_token'])) {
            $this->saveHsRefreshToken($data['refresh_token']);
        }

        return response()->json([
            'access_token_first8'  => substr((string)($data['access_token'] ?? ''), 0, 8),
            'refresh_token_saved'  => !empty($data['refresh_token']),
            'token_type'           => $data['token_type'] ?? null,
            'expires_in'           => $data['expires_in'] ?? null,
        ]);
    }

    private function getHsRefreshToken(): ?string
    {
        $path = 'hs_oauth.json';
        if (Storage::exists($path)) {
            $saved = json_decode(Storage::get($path), true);
            if (!empty($saved['refresh_token'])) {
                return (string)$saved['refresh_token'];
            }
        }
        $env = env('HS_REFRESH_TOKEN');
        return $env ? (string)$env : null;
    }

    private function saveHsRefreshToken(string $refreshToken): void
    {
        Storage::put('hs_oauth.json', json_encode([
            'refresh_token' => $refreshToken,
            'saved_at'      => now()->toISOString(),
        ], JSON_PRETTY_PRINT));
    }

    private function hsAccessToken(): string
    {
        return Cache::remember('hs_access_token', now()->addMinutes(30), function () {
            $refreshToken = $this->getHsRefreshToken();
            abort_unless($refreshToken, 500, 'No Help Scout refresh token. Visit /oauth/hs/start to connect.');

            $resp = Http::asForm()->post($this->hsTokenUrl, [
                'grant_type'    => 'refresh_token',
                'refresh_token' => $refreshToken,
                'client_id'     => env('HS_CLIENT_ID'),
                'client_secret' => env('HS_CLIENT_SECRET'),
            ]);

            if (!$resp->ok()) {
                abort(500, 'HS refresh failed: ' . $resp->body());
            }

            $data = $resp->json();
            if (!empty($data['refresh_token'])) {
                $this->saveHsRefreshToken($data['refresh_token']);
            }
            return (string)$data['access_token'];
        });
    }

    /* =========================
     * Help Scout: customers
     * ========================= */
    private function hsFindCustomer(string $token, string $email): ?array
    {
        // A) DSL query
        $r = Http::withToken($token)->get("{$this->hsApi}/customers", [
            'query' => '(email:"' . $email . '")',
            'page'  => 1,
        ]);
        if ($r->ok()) {
            $hit = data_get($r->json(), '_embedded.customers.0');
            if ($hit) return $hit;
        } else {
            Log::warning('HS search A failed', ['status' => $r->status(), 'body' => $r->body()]);
        }

        // B) Simple param
        $r2 = Http::withToken($token)->get("{$this->hsApi}/customers", [
            'email' => $email,
            'page'  => 1,
        ]);
        if ($r2->ok()) {
            $hit = data_get($r2->json(), '_embedded.customers.0');
            if ($hit) return $hit;
        } else {
            Log::warning('HS search B failed', ['status' => $r2->status(), 'body' => $r2->body()]);
        }

        // C) Search endpoint (if plan allows)
        $r3 = Http::withToken($token)->get("{$this->hsApi}/search/customers", [
            'query' => 'email:"' . $email . '"',
            'page'  => 1,
        ]);
        if ($r3->ok()) {
            $hit = data_get($r3->json(), '_embedded.customers.0');
            if ($hit) return $hit;
        } else {
            Log::warning('HS search C failed', ['status' => $r3->status(), 'body' => $r3->body()]);
        }

        return null;
    }

    private function hsCreateCustomer(string $token, ?string $first, ?string $last, string $email): int
    {
        $safeFirst = $first ?: ucfirst(strtolower(explode('@', $email)[0]));
        $payload = [
            'firstName' => $safeFirst,
            'emails'    => [['type' => 'work', 'value' => $email]],
        ];
        if ($last) $payload['lastName'] = $last;

        $r = Http::withToken($token)->acceptJson()->asJson()->post("{$this->hsApi}/customers", $payload);

        if ($r->status() === 409) {
            Log::info('HS create returned 409; fetching existing', ['email' => $email]);
            $existing = $this->hsFindCustomer($token, $email);
            if ($existing && isset($existing['id'])) {
                return (int)$existing['id'];
            }
        }

        if ($r->successful()) {
            return (int)($r->json('id') ?? 0);
        }

        Log::error('HS create failed', ['status' => $r->status(), 'body' => $r->body(), 'payload' => $payload]);
        abort(500, 'HS create failed: ' . $r->body());
    }

    private function hsUpdateNamesIfChanged(string $token, int $customerId, ?string $first, ?string $last): void
    {
        if (!$first && !$last) return;

        $body = array_filter([
            'firstName' => $first,
            'lastName'  => $last,
        ], fn($v) => $v !== null && $v !== '');

        if (!$body) return;

        // PUT is supported for updating a customer
        $r = Http::withToken($token)->acceptJson()->asJson()
            ->put("{$this->hsApi}/customers/{$customerId}", $body);

        if (!$r->successful()) {
            Log::warning('HS name update failed', ['status' => $r->status(), 'body' => $r->body()]);
        }
    }

    private function hsPropertySlugs(string $token): array
    {
        return Cache::remember('hs_prop_slugs', now()->addMinutes(30), function () use ($token) {
            $r = Http::withToken($token)->get("{$this->hsApi}/customer-properties");
            if (!$r->ok()) abort(500, 'HS properties list failed: ' . $r->body());
            return collect(data_get($r->json(), '_embedded.customer-properties', []))
                ->pluck('slug')
                ->all();
        });
    }

    /**
     * JSON-Patch the properties. Only sends ops for slugs that exist.
     */
    private function hsPatchProperties(string $token, int $customerId, array $kv): void
    {
        // Concept -> Help Scout property slugs
        $slugMap = [
            'donor_id'             => 'donor-id',
            'last_donation_amount' => 'last-donation-amount',
            'last_donation_date'   => 'last-order',
            'lifetime_donation'    => 'lifetime-donation',
            'donor_profile_url'    => 'gc-donor-profile',
            'payment_method'       => 'payment-method',
            'recurring_summary'    => 'recurring-summary',

            'sponsorship_name'     => 'sponsorship-name',
            'sponsorship_ref'      => 'sponsorship-ref',
            'sponsorship_url'      => 'sponsorship-url',

            'country'              => 'country',
            'province'             => 'state',
            'phone_numeric'        => 'phone-no',

            // Optional address as properties (create them first if you want these)
            'billing_address1'     => 'billing-address1',
            'billing_address2'     => 'billing-address2',
            'billing_city'         => 'billing-city',
            'billing_postal'       => 'billing-postal',
        ];

        $numericSlugs = ['donor-id', 'lifetime-donation', 'phone-no'];

        $existing = $this->hsPropertySlugs($token);
        $ops = [];

        foreach ($kv as $concept => $value) {
            if ($value === null || $value === '') continue;

            $slug = $slugMap[$concept] ?? null;
            if (!$slug) continue;
            if (!in_array($slug, $existing, true)) continue;

            if (in_array($slug, $numericSlugs, true)) {
                if (!is_numeric($value)) continue;
                $value = $value + 0;
            }

            if ($slug === 'last-order') {
                try { $value = Carbon::parse($value)->toDateString(); }
                catch (\Throwable $e) { $value = substr((string)$value, 0, 10); }
            }

            $ops[] = ['op' => 'replace', 'path' => "/{$slug}", 'value' => $value];
        }

        if (!$ops) return;

        $r = Http::withToken($token)->acceptJson()->asJson()
            ->patch("{$this->hsApi}/customers/{$customerId}/properties", $ops);

        if (!in_array($r->status(), [200, 204], true)) {
            Log::error('HS properties failed', ['status' => $r->status(), 'body' => $r->body(), 'ops' => $ops]);
            abort(500, 'HS properties failed: ' . $r->body());
        }
    }

    /* =========================
     * Givecloud: verify + ingest
     * ========================= */
    private function verifyGivecloud(Request $r): void
    {
        $secret = (string) env('GC_WEBHOOK_SECRET', '');
        abort_unless($secret !== '', 500, 'Missing GC_WEBHOOK_SECRET');
        $sig  = $r->header('X-Givecloud-Signature') ?? $r->header('x-givecloud-signature');
        $raw  = $r->getContent();
        $calc = hash_hmac('sha1', $raw, $secret);

        if (env('GC_LOG_SIG', false)) {
            Log::debug('GC sig debug', [
                'received' => (string)$sig,
                'calc'     => (string)$calc,
                'match'    => $sig && hash_equals((string)$sig, (string)$calc),
            ]);
        }
        abort_unless($sig && hash_equals((string)$sig, (string)$calc), 401, 'Invalid signature');
    }

    public function gc(Request $r)
    {
        $this->verifyGivecloud($r);
        $event = strtolower((string)($r->header('X-Givecloud-Event') ?? ''));
        $b     = $r->json()->all();

        // supporter_* can batch multiple supporters
        if (in_array($event, ['supporter_created', 'supporter_updated'], true) && is_array($b['supporters'] ?? null)) {
            $processed = 0;
            foreach ((array)$b['supporters'] as $s) {
                $ctx = $this->ctxFromSupporter($s);
                if (!$ctx['email']) {
                    Log::info('GC supporter: skipped (no email)', ['supporter_id' => data_get($s, 'id')]);
                    continue;
                }
                $this->upsertHelpScout($ctx);
                $processed++;
            }
            return response()->json(['ok' => true, 'processed' => $processed], 200);
        }

        // contribution_* / contributions_paid / recurring_profile_updated
        $ctx = $this->ctxFromContributionEnvelope($b);
        if (!$ctx['email']) {
            Log::info('GC webhook: skipped (no email)', ['body' => $b]);
            return response()->json(['status' => 'skipped', 'reason' => 'no email'], 202);
        }
        $this->upsertHelpScout($ctx);

        return response()->json(['ok' => true, 'email' => $ctx['email']], 200);
    }

    /* =========================
     * Context builders (GC → ctx)
     * ========================= */
    private function ctxFromSupporter(array $s): array
    {
        $billing = (array)($s['billing_address'] ?? []);
        $phonePretty = $billing['phone'] ?? null;
        $phoneDigits = $this->digits($phonePretty);

        return [
            'email'   => (string)($s['email'] ?? $billing['email'] ?? ''),
            'first'   => (string)($s['first_name'] ?? ''),
            'last'    => (string)($s['last_name']  ?? ''),
            'donorId' => $s['id'] ?? $s['vendor_contact_id'] ?? null,

            // location
            'country' => $billing['country'] ?? null,
            'state'   => $billing['state']   ?? null,

            // address (optionally mirrored into properties)
            'addr1'   => $billing['address1'] ?? null,
            'addr2'   => $billing['address2'] ?? null,
            'city'    => $billing['city']     ?? null,
            'postal'  => $billing['zip']      ?? null,

            // phone
            'phone_pretty' => $phonePretty,
            'phone_digits' => $phoneDigits,

            // these may be absent on supporter events
            'lastAmount' => null,
            'currency'   => null,
            'lastDate'   => null,
            'payment'    => null,
            'recurring'  => null,

            // sponsorship & donor profile (rare on supporter events)
            'sponsorship' => [
                'name' => null,
                'ref'  => null,
                'url'  => null,
            ],
            'donor_profile_url' => null,

            // lifetime (if your site provides it)
            'lifetime' => $s['lifetime_donation_amount'] ?? null,
        ];
    }

    private function ctxFromContributionEnvelope(array $b): array
    {
        // email & names (look across shapes)
        $billing = (array)($b['billing_address'] ?? []);
        $support = (array)($b['supporter'] ?? []);

        $email = $b['email']
            ?? $support['email']
            ?? $billing['email']
            ?? data_get($b, 'account.email')
            ?? data_get($b, 'customer.email');

        $first = $support['first_name']
            ?? $billing['first_name']
            ?? null;

        $last  = $support['last_name']
            ?? $billing['last_name']
            ?? null;

        // donor id
        $donorId = $support['id_deprecated'] ?? $support['id']
            ?? data_get($b, 'account.id')
            ?? data_get($b, 'vendor_contact_id');

        // last donation amount & currency
        $amount   = $b['total_amount'] ?? data_get($b, 'subtotal_amount') ?? data_get($b, 'amount');
        $currency = $b['currency'] ?? data_get($b, 'payments.0.currency.code');

        // last date
        $rawDate  = $b['ordered_at'] ?? $b['created_at'] ?? $b['updated_at'] ?? null;
        $lastDate = null;
        if ($rawDate) {
            try { $lastDate = Carbon::parse($rawDate)->toDateString(); }
            catch (\Throwable $e) { $lastDate = substr((string)$rawDate, 0, 10); }
        }

        // payment method (prefer card brand; fallback to type/wallet)
        $payment = $this->detectPaymentBrand($b);

        // recurring summary (try multiple shapes)
        $recurring = $this->buildRecurringSummary($b);

        // sponsorship (if present on line item)
        $spon = [
            'name' => data_get($b, 'line_items.0.sponsorship.full_name'),
            'ref'  => data_get($b, 'line_items.0.sponsorship.reference_number'),
            'url'  => data_get($b, 'line_items.0.sponsorship.url'),
        ];

        // donor profile url (if given by your site)
        $donorProfileUrl = $spon['url']
            ?? data_get($b, 'supporter.url')
            ?? data_get($b, 'supporter.profile_url');

        // phone
        $phonePretty = $billing['phone'] ?? null;
        $phoneDigits = $this->digits($phonePretty);

        return [
            'email'   => $email ? (string)$email : '',
            'first'   => $first ? (string)$first : null,
            'last'    => $last  ? (string)$last  : null,
            'donorId' => is_numeric($donorId) ? (int)$donorId : $donorId,

            'lastAmount' => $amount,
            'currency'   => $currency,
            'lastDate'   => $lastDate,
            'payment'    => $payment,
            'recurring'  => $recurring,

            // location
            'country' => $billing['country_code'] ?? $billing['country'] ?? null,
            'state'   => $billing['province_code'] ?? $billing['state'] ?? null,

            // address (optional mirror to props)
            'addr1'   => $billing['address1'] ?? null,
            'addr2'   => $billing['address2'] ?? null,
            'city'    => $billing['city']     ?? null,
            'postal'  => $billing['zip']      ?? null,

            // phone
            'phone_pretty' => $phonePretty,
            'phone_digits' => $phoneDigits,

            'sponsorship' => $spon,
            'donor_profile_url' => $donorProfileUrl,

            'lifetime' => data_get($b, 'supporter.lifetime_donation_amount'),
        ];
    }

    private function detectPaymentBrand(array $b): ?string
    {
        // contributions payload
        $brand = data_get($b, 'payments.0.card.brand');
        if ($brand) return (string)$brand;

        $type = data_get($b, 'payments.0.type') ?? data_get($b, 'payment_type');
        $wallet = data_get($b, 'payments.0.card.wallet');
        if ($wallet && is_string($wallet)) {
            // e.g., google_pay, apple_pay
            $wallet = str_replace('_', ' ', $wallet);
            $wallet = ucwords($wallet);
            return $wallet;
        }
        return $type ? (string)$type : null;
    }

    private function buildRecurringSummary(array $b): ?string
    {
        // Try line_items[].recurring_amount/frequency/day (varies per site)
        $amt = data_get($b, 'line_items.0.recurring_amount')
            ?? data_get($b, 'line_items.0.recurring.amount')
            ?? data_get($b, 'line_items.0.recurring_profile.amount');

        $freq = data_get($b, 'line_items.0.recurring.frequency')
            ?? data_get($b, 'line_items.0.recurring_profile.billing_period_description')
            ?? data_get($b, 'line_items.0.recurring_profile.billing_frequency');

        $day  = data_get($b, 'line_items.0.recurring.day')
            ?? data_get($b, 'line_items.0.recurring_profile.billing_period_day');

        if ($amt && $freq) {
            $freq = is_string($freq) ? $freq : (string)$freq;
            $freq = ucfirst(strtolower($freq)); // Monthly, Weekly, etc.
            $out  = '$' . $amt . ' / ' . $freq;
            if ($day) $out .= ' / ' . (is_string($day) ? $day : (string)$day);
            return $out;
        }

        // Another shape from your sample:
        $paymentString = data_get($b, 'line_items.0.payment_string');
        if ($paymentString) {
            // Example: "$1,084.11 USD/mth starting Nov 23rd, 2025"
            return (string)$paymentString;
        }

        return null;
    }

    private function digits(?string $v): ?int
    {
        if (!$v) return null;
        $d = preg_replace('/\D+/', '', $v);
        return $d !== '' ? (int)$d : null;
    }

    /* =========================
     * Upsert into Help Scout
     * ========================= */
    private function upsertHelpScout(array $ctx): void
    {
        $token = $this->hsAccessToken();

        $customer = $this->hsFindCustomer($token, $ctx['email']);
        $id = $customer['id'] ?? 0;
        if (!$id) {
            $id = $this->hsCreateCustomer($token, $ctx['first'], $ctx['last'], $ctx['email']);
        } else {
            // keep names fresh
            $this->hsUpdateNamesIfChanged($token, $id, $ctx['first'], $ctx['last']);
        }

        // Prepare property values
        $lastAmountStr = ($ctx['lastAmount'] !== null && $ctx['currency'])
            ? "{$ctx['lastAmount']} {$ctx['currency']}"
            : null;

        $this->hsPatchProperties($token, $id, [
            'donor_id'             => is_numeric($ctx['donorId']) ? (int)$ctx['donorId'] : null,
            'last_donation_amount' => $lastAmountStr,
            'last_donation_date'   => $ctx['lastDate'],
            'payment_method'       => $ctx['payment'],
            'recurring_summary'    => $ctx['recurring'],
            'country'              => $ctx['country'],
            'province'             => $ctx['state'],
            'lifetime_donation'    => is_numeric($ctx['lifetime'] ?? null) ? (float)$ctx['lifetime'] : null,
            'donor_profile_url'    => $ctx['donor_profile_url'],

            // Sponsorship
            'sponsorship_name'     => data_get($ctx, 'sponsorship.name'),
            'sponsorship_ref'      => data_get($ctx, 'sponsorship.ref'),
            'sponsorship_url'      => data_get($ctx, 'sponsorship.url'),

            // Optional numeric phone property
            'phone_numeric'        => $ctx['phone_digits'],

            // Optional address as properties (only if you created them)
            'billing_address1'     => $ctx['addr1'],
            'billing_address2'     => $ctx['addr2'],
            'billing_city'         => $ctx['city'],
            'billing_postal'       => $ctx['postal'],
        ]);
    }

    /* =========================
     * Debug helpers
     * ========================= */
    public function debugHsProperties()
    {
        $token = $this->hsAccessToken();
        $r = Http::withToken($token)->get("{$this->hsApi}/customer-properties");
        return response($r->body(), $r->status())->header('Content-Type', 'application/json');
    }

    public function debugHsCustomer(Request $req)
    {
        $email = $req->query('email');
        abort_unless($email, 400, 'pass ?email=');
        $token = $this->hsAccessToken();
        $c = $this->hsFindCustomer($token, $email);
        return response()->json($c ?: null);
    }
}
