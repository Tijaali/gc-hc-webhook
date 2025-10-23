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

    /* =========================
     *    OAUTH (Help Scout)
     * ========================= */

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
            'access_token_first8' => substr((string)($data['access_token'] ?? ''), 0, 8),
            'refresh_token_saved' => !empty($data['refresh_token']),
            'token_type'          => $data['token_type'] ?? null,
            'expires_in'          => $data['expires_in'] ?? null,
        ]);
    }

    private function getHsRefreshToken(): ?string
    {
        $path = 'hs_oauth.json';
        if (Storage::exists($path)) {
            $saved = json_decode(Storage::get($path), true);
            if (!empty($saved['refresh_token'])) {
                return (string) $saved['refresh_token'];
            }
        }
        $env = env('HS_REFRESH_TOKEN');
        return $env ? (string) $env : null;
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

            return (string) $data['access_token'];
        });
    }

    /* =========================
     *  HELP SCOUT: Customers
     * ========================= */

    private function hsFindCustomer(string $token, string $email): ?array
    {
        // Strategy A: HS DSL
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

        // Strategy B: direct param
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

        // Strategy C: search endpoint (plan dependent)
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
                return (int) $existing['id'];
            }
        }

        if ($r->successful()) {
            return (int) ($r->json('id') ?? 0);
        }

        Log::error('HS create failed', ['status' => $r->status(), 'body' => $r->body(), 'payload' => $payload]);
        abort(500, 'HS create failed: ' . $r->body());
    }

    private function hsUpdateCustomerBasics(string $token, int $customerId, ?string $first, ?string $last): void
    {
        $payload = array_filter([
            'firstName' => $first,
            'lastName'  => $last,
        ], fn($v) => $v !== null && $v !== '');

        if (!$payload) return;

        $r = Http::withToken($token)->acceptJson()->asJson()->patch("{$this->hsApi}/customers/{$customerId}", $payload);
        if (!$r->ok()) {
            Log::warning('HS basic update failed (name)', ['status' => $r->status(), 'body' => $r->body(), 'payload' => $payload]);
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

    private function hsPatchProperties(string $token, int $customerId, array $kv): void
    {
        // Concept -> HS slugs
        $slugMap = [
            'donor_id'              => 'donor-id',              // number
            'donor_since'           => 'donor-since',           // date
            'last_donation_date'    => 'last-order',            // date YYYY-MM-DD
            'last_donation_amount'  => 'last-donation-amount',  // text
            'country'               => 'country',               // text
            'province'              => 'state',                 // text
            'lifetime_donation'     => 'lifetime-donation',     // number
            'donor_profile_url'     => 'gc-donor-profile',      // url/text
            'phone'                 => 'phone-no',              // number
            'payment_method'        => 'payment-method',        // text
            'payment_status'        => 'payment-status',        // text
            'payment_failure'       => 'payment-failure',       // text
            'recurring_summary'     => 'recurring-summary',     // text

            // Sponsorship (text/url)
            'sponsorship_name'      => 'sponsorship-name',
            'sponsorship_ref'       => 'sponsorship-ref',
            'sponsorship_url'       => 'sponsorship-url',

            // Billing
            'billing_address1'      => 'billing-address1',
            'billing_address2'      => 'billing-address2',
            'billing_city'          => 'billing-city',
            'billing_postal'        => 'billing-postal',

            // Shipping
            'shipping_address1'     => 'shipping-address1',
            'shipping_address2'     => 'shipping-address2',
            'shipping_city'         => 'shipping-city',
            'shipping_postal'       => 'shipping-postal',
        ];

        $numericSlugs = ['donor-id', 'lifetime-donation', 'phone-no'];
        $existing     = $this->hsPropertySlugs($token);

        // Warn once if any "important" slugs are missing
        static $warned = false;
        $important = [
            'donor-id','last-order','last-donation-amount','payment-method','country','state',
            'billing-address1','billing-city','billing-postal','recurring-summary',
            'sponsorship-name','sponsorship-ref','sponsorship-url'
        ];
        if (!$warned) {
            $missing = array_values(array_diff($important, $existing));
            if ($missing) {
                Log::warning('HS missing important custom properties (please create these slugs)', $missing);
            }
            $warned = true;
        }

        $ops = [];
        foreach ($kv as $concept => $val) {
            if ($val === null || $val === '') continue;
            $slug = $slugMap[$concept] ?? null;
            if (!$slug) continue;
            if (!in_array($slug, $existing, true)) continue;

            if (in_array($slug, $numericSlugs, true)) {
                if (!is_numeric($val)) continue;
                $val = $val + 0;
            }

            if (in_array($slug, ['last-order','donor-since'], true)) {
                try { $val = Carbon::parse($val)->toDateString(); }
                catch (\Throwable $e) { $val = substr((string) $val, 0, 10); }
            }

            $ops[] = ['op' => 'replace', 'path' => '/' . $slug, 'value' => $val];
        }

        if (!$ops) return;

        $r = Http::withToken($token)->acceptJson()->asJson()
            ->patch("{$this->hsApi}/customers/{$customerId}/properties", $ops);

        if (!in_array($r->status(), [200, 204], true)) {
            Log::error('HS properties failed', ['status' => $r->status(), 'body' => $r->body(), 'ops' => $ops]);
        }
    }

    /* =========================
     *   Givecloud webhook
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
                'received'   => (string) $sig,
                'calculated' => (string) $calc,
                'match'      => $sig && hash_equals((string)$sig, (string)$calc),
            ]);
        }

        abort_unless($sig && hash_equals((string)$sig, (string)$calc), 401, 'Invalid signature');
    }

    public function gc(Request $r)
    {
        $this->verifyGivecloud($r);
        $event = (string) ($r->header('X-Givecloud-Event') ?? '');
        $body  = $r->json()->all();

        try {
            switch ($event) {
                case 'supporter_created':
                case 'supporter_updated': {
                    $arr = (array) data_get($body, 'supporters', []);
                    $processed = 0;
                    foreach ($arr as $sup) {
                        $mini = [
                            'supporter'       => $sup,
                            'email'           => data_get($sup, 'email') ?? data_get($sup, 'billing_address.email'),
                            'billing_address' => data_get($sup, 'billing_address'),
                            'shipping_address'=> data_get($sup, 'shipping_address'),
                        ];
                        $processed += $this->processOne($mini, null);
                    }
                    return response()->json(['ok' => true, 'event' => $event, 'processed' => $processed], 200);
                }

                case 'contribution_paid':
                case 'contributions_paid':
                    $this->processOne($body, 'paid');
                    return response()->json(['ok' => true, 'event' => $event], 200);

                case 'contribution_refunded':
                    $this->processOne($body, 'refunded');
                    return response()->json(['ok' => true, 'event' => $event], 200);

                case 'recurring_profile_updated':
                    $this->processOne($body, null);
                    return response()->json(['ok' => true, 'event' => $event], 200);

                default:
                    $this->processOne($body, null);
                    return response()->json(['ok' => true, 'event' => $event, 'note' => 'generic'], 200);
            }
        } catch (\Throwable $e) {
            Log::error('GC handler error', [
                'event' => $event,
                'msg'   => $e->getMessage(),
                'file'  => $e->getFile(),
                'line'  => $e->getLine(),
            ]);
            // Always ACK Givecloud so the dashboard stays green
            return response()->json(['status' => 'ok'], 200);
        }
    }

    /**
     * Normalize ANY Givecloud payload and upsert into Help Scout.
     * Returns 1 if processed, 0 if skipped.
     */
    private function processOne(array $b, ?string $forcedPaymentStatus = null): int
    {
        // Email (required)
        $email = data_get($b, 'email')
            ?? data_get($b, 'supporter.email')
            ?? data_get($b, 'billing_address.email')
            ?? data_get($b, 'account.email')
            ?? data_get($b, 'customer.email');

        if (!$email) {
            Log::info('GC webhook: skipped (no email)', ['body' => $b]);
            return 0;
        }

        // Names
        $first = data_get($b, 'supporter.first_name') ?? data_get($b, 'billing_address.first_name');
        $last  = data_get($b, 'supporter.last_name')  ?? data_get($b, 'billing_address.last_name');

        // Donor IDs (prefer vendor_contact_id when present)
        $donorId = data_get($b, 'supporter.id_deprecated')
            ?? data_get($b, 'supporter.id')
            ?? data_get($b, 'vendor_contact_id')
            ?? data_get($b, 'account.id');
        $donorId = is_numeric($donorId) ? (int) $donorId : null;

        // Dates / amounts
        $amount   = data_get($b, 'total_amount') ?? data_get($b, 'amount') ?? data_get($b, 'subtotal_amount');
        $currency = data_get($b, 'currency') ?? data_get($b, 'payments.0.currency.code');
        $lastDonationAmount = ($amount !== null && $currency) ? (string) ($amount . ' ' . $currency) : null;

        $rawDate  = data_get($b, 'ordered_at') ?? data_get($b, 'created_at');
        $lastDate = $rawDate ? (function($dt){ try { return Carbon::parse($dt)->toDateString(); } catch (\Throwable $e) { return substr((string)$dt,0,10);} })($rawDate) : null;

        $donorSince = data_get($b, 'supporter.created_at') ?? null;

        // Payment method / status
        $pmBrand   = data_get($b, 'payments.0.card.brand');
        $pmType    = data_get($b, 'payments.0.type') ?? data_get($b, 'payment_type');
        $wallet    = data_get($b, 'payments.0.card.wallet');
        $txCcType  = data_get($b, 'transactions.0.cc_type'); // if provided by other payloads
        $pmMethod  = $txCcType ?: trim(implode(' ', array_filter([$pmType, $pmBrand, $wallet])));
        $pmStatus  = $forcedPaymentStatus ?? (data_get($b, 'payments.0.status') ?? data_get($b, 'payments.0.outcome'));
        $pmFailure = data_get($b, 'payments.0.failure_message') ?? null;

        // Recurring summary
        $recAmt = data_get($b, 'line_items.0.recurring_amount')
               ?? data_get($b, 'line_items.0.recurring.amount')
               ?? data_get($b, 'recurring_profile.amount')
               ?? data_get($b, 'recurring_profile.aggregate_amount');
        $freq = data_get($b, 'line_items.0.recurring.frequency')
             ?? data_get($b, 'line_items.0.recurring_profile.billing_period_description')
             ?? data_get($b, 'recurring_profile.billing_period_description')
             ?? data_get($b, 'recurring_profile.billing_period');
        $day  = data_get($b, 'line_items.0.recurring.day')
             ?? data_get($b, 'line_items.0.recurring_profile.billing_period_day')
             ?? data_get($b, 'recurring_profile.billing_period_day');
        $recurringSummary = ($recAmt && $freq) ? ('$' . $recAmt . ' / ' . $freq . ($day ? ' / ' . $day : '')) : null;

        // Sponsorship info
        $sName = data_get($b, 'line_items.0.sponsorship.full_name');
        $sRef  = data_get($b, 'line_items.0.sponsorship.reference_number');
        $sUrl  = data_get($b, 'line_items.0.sponsorship.url');

        // Location + addresses
        $country  = data_get($b, 'billing_address.country_code')
                 ?? data_get($b, 'billing_address.country')
                 ?? data_get($b, 'supporter.billing_address.country');
        $province = data_get($b, 'billing_address.province_code')
                 ?? data_get($b, 'billing_address.state')
                 ?? data_get($b, 'supporter.billing_address.state');

        $bill = (array) data_get($b, 'billing_address', []);
        $ship = (array) data_get($b, 'shipping_address', []);

        $phoneDigits = $this->normalizePhone(
            data_get($bill, 'phone') ?? data_get($b, 'supporter.billing_address.phone')
        );

        // Lifetime total
        $lifetime = data_get($b, 'supporter.lifetime_donation_amount');

        // Donor profile URL
        $profileUrl = data_get($b, 'supporter.profile_url')
                   ?? data_get($b, 'line_items.0.public_url')
                   ?? data_get($b, 'line_items.0.sponsorship.url');

        // Upsert in Help Scout
        $token    = $this->hsAccessToken();
        $customer = $this->hsFindCustomer($token, $email);
        $id       = $customer['id'] ?? 0;
        if (!$id) {
            $id = $this->hsCreateCustomer($token, $first, $last, $email);
        } else {
            // Update name if it changed
            $this->hsUpdateCustomerBasics($token, $id, $first, $last);
        }

        // Patch HS custom properties
        $this->hsPatchProperties($token, $id, [
            'donor_id'             => $donorId,
            'donor_since'          => $donorSince,
            'last_donation_date'   => $lastDate,
            'last_donation_amount' => $lastDonationAmount,
            'country'              => $country,
            'province'             => $province,
            'lifetime_donation'    => is_numeric($lifetime) ? (float) $lifetime : null,
            'donor_profile_url'    => $profileUrl,

            'phone'                => $phoneDigits,
            'payment_method'       => $pmMethod,
            'payment_status'       => $pmStatus,
            'payment_failure'      => $pmFailure,

            'recurring_summary'    => $recurringSummary,

            'sponsorship_name'     => $sName,
            'sponsorship_ref'      => $sRef,
            'sponsorship_url'      => $sUrl,

            // Billing
            'billing_address1'     => data_get($bill, 'address1'),
            'billing_address2'     => data_get($bill, 'address2'),
            'billing_city'         => data_get($bill, 'city'),
            'billing_postal'       => data_get($bill, 'zip') ?? data_get($bill, 'postal'),

            // Shipping
            'shipping_address1'    => data_get($ship, 'address1'),
            'shipping_address2'    => data_get($ship, 'address2'),
            'shipping_city'        => data_get($ship, 'city'),
            'shipping_postal'      => data_get($ship, 'zip') ?? data_get($ship, 'postal'),
        ]);

        return 1;
    }

    /* =========================
     *  Helpers & Debug
     * ========================= */

    private function normalizePhone(?string $raw): ?int
    {
        if (!$raw) return null;
        $digits = preg_replace('/\D+/', '', $raw);
        return $digits !== '' ? (int) $digits : null;
    }

    private function mapLanguage(?string $label): ?string
    {
        if (!$label) return null;
        $map = [
            'Punjabi' => '1368ba54-df11-4242-8bc0-5dd7fca6fd45',
            'English' => '5fee9398-4ef1-4b02-8d0e-0dafbfdff2c0',
            'Other'   => 'e48318ce-e476-4d26-be9e-58a9142b1193',
        ];
        return $map[$label] ?? null;
    }

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
