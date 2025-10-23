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

    /* --------------------------------------------------------------------
     | OAUTH (Help Scout)
     * ------------------------------------------------------------------ */

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
            'expires_in'          => $data['expires_in'] ?? null,
            'token_type'          => $data['token_type'] ?? null,
        ]);
    }

    private function getHsRefreshToken(): ?string
    {
        $path = 'hs_oauth.json';
        if (Storage::exists($path)) {
            $saved = json_decode(Storage::get($path), true);
            if (!empty($saved['refresh_token'])) return (string) $saved['refresh_token'];
        }
        return env('HS_REFRESH_TOKEN') ?: null;
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

    /* --------------------------------------------------------------------
     | HELP SCOUT: Customers
     * ------------------------------------------------------------------ */

    private function hsFindCustomer(string $token, string $email): ?array
    {
        // Strategy A: DSL query
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

        // (Skipping Strategy C: /search/customers — not enabled on your account, returns 404)
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

    private function hsUpdateCore(string $token, int $customerId, array $core): void
    {
        // Try to update core phone/address/website. If this fails, just log and move on.
        $payload = array_filter([
            'firstName' => $core['firstName'] ?? null,
            'lastName'  => $core['lastName'] ?? null,
            'phones'    => $core['phones'] ?? null,     // [['type'=>'work','value'=>'15551234567']]
            'websites'  => $core['websites'] ?? null,   // [['value'=>'https://...']]
            'addresses' => $core['addresses'] ?? null,  // [['type'=>'work','lines'=>['123 Main'], 'city'=>'','state'=>'','postalCode'=>'','country':'US']]
        ], fn($v) => $v !== null);

        if (!$payload) return;

        $r = Http::withToken($token)->acceptJson()->asJson()->put("{$this->hsApi}/customers/{$customerId}", $payload);

        if (!$r->successful()) {
            Log::warning('HS core update failed (non-fatal)', [
                'status' => $r->status(),
                'body'   => $r->body(),
                'pay'    => $payload,
            ]);
        }
    }

    private function hsPropertySlugs(string $token, bool $forceRefresh = false): array
    {
        if (!$forceRefresh) {
            $slugs = Cache::get('hs_prop_slugs');
            if (is_array($slugs)) return $slugs;
        }

        $r = Http::withToken($token)->get("{$this->hsApi}/customer-properties");
        if (!$r->ok()) abort(500, 'HS properties list failed: ' . $r->body());

        $slugs = collect(data_get($r->json(), '_embedded.customer-properties', []))
            ->pluck('slug')->all();

        Cache::put('hs_prop_slugs', $slugs, now()->addMinutes(30));
        return $slugs;
    }

    private function hsPatchProperties(string $token, int $customerId, array $kv): void
    {
        // Concept -> HS slugs
        $slugMap = [
            // IDs / dates / amounts
            'donor_id'             => 'donor-id',
            'donor_since'          => 'donor-since',
            'last_donation_amount' => 'last-donation-amount',
            'last_donation_date'   => 'last-order',
            'lifetime_donation'    => 'lifetime-donation',
            'donor_profile_url'    => 'gc-donor-profile',

            // payments / recurring
            'payment_method'       => 'payment-method',
            'payment_status'       => 'payment-status',
            'payment_failure'      => 'payment-failure',
            'recurring_summary'    => 'recurring-summary',

            // sponsorship
            'sponsorship_name'     => 'sponsorship-name',
            'sponsorship_ref'      => 'sponsorship-ref',
            'sponsorship_url'      => 'sponsorship-url',

            // location
            'country'              => 'country',
            'province'             => 'state',

            // address mirrors + phone
            'billing_address1'     => 'billing-address1',
            'billing_address2'     => 'billing-address2',
            'billing_city'         => 'billing-city',
            'billing_postal'       => 'billing-postal',
            'phone_numeric'        => 'phone-no',
        ];

        $numericSlugs = ['donor-id', 'lifetime-donation', 'phone-no'];

        // refresh property list if needed
        $existing = $this->hsPropertySlugs($token);
        $mappedSlugs = array_values($slugMap);
        if (count(array_intersect($mappedSlugs, $existing)) < count(array_unique($mappedSlugs))) {
            $existing = $this->hsPropertySlugs($token, true);
        }

        $payload = [];
        $missing = [];

        foreach ($kv as $concept => $val) {
            if ($val === null || $val === '') continue;

            $slug = $slugMap[$concept] ?? null;
            if (!$slug) continue;

            if (!in_array($slug, $existing, true)) {
                $missing[] = $slug;
                continue;
            }

            if (in_array($slug, $numericSlugs, true)) {
                if (!is_numeric($val)) continue;
                $val = $val + 0;
            }

            if ($slug === 'last-order' || $slug === 'donor-since') {
                try { $val = Carbon::parse($val)->toDateString(); }
                catch (\Throwable $e) { $val = substr((string)$val, 0, 10); }
            }

            $payload[] = ['slug' => $slug, 'value' => $val];
        }

        if ($missing) {
            Log::warning('HS missing important custom properties (please create these slugs)', $missing);
        }

        if (!$payload) return;

        // HS expects an array of {slug,value}
        $r = Http::withToken($token)->acceptJson()->asJson()
            ->patch("{$this->hsApi}/customers/{$customerId}/properties", $payload);

        if (!in_array($r->status(), [200, 204], true)) {
            Log::error('HS properties failed', ['status' => $r->status(), 'body' => $r->body(), 'payload' => $payload]);
            abort(500, 'HS properties failed: ' . $r->body());
        }
    }

    /* --------------------------------------------------------------------
     | Givecloud verification
     * ------------------------------------------------------------------ */

    private function verifyGivecloud(Request $r): void
    {
        $secret = (string) env('GC_WEBHOOK_SECRET', '');
        abort_unless($secret !== '', 500, 'Missing GC_WEBHOOK_SECRET');

        $sig = $r->header('X-Givecloud-Signature') ?? $r->header('x-givecloud-signature');
        $raw = $r->getContent();
        $calc = hash_hmac('sha1', $raw, $secret);

        if (env('GC_LOG_SIG', false)) {
            Log::debug('GC sig debug', [
                'received'   => (string) $sig,
                'calculated' => (string) $calc,
                'match'      => $sig && hash_equals((string)$sig, (string)$calc),
                'len_raw'    => strlen($raw),
            ]);
        }

        abort_unless($sig && hash_equals((string)$sig, (string)$calc), 401, 'Invalid signature');
    }

    /* --------------------------------------------------------------------
     | Webhook entry
     * ------------------------------------------------------------------ */

    public function gc(Request $r)
    {
        $this->verifyGivecloud($r);

        $event = (string) $r->header('X-Givecloud-Event');
        $body  = $r->json()->all();
        $token = $this->hsAccessToken();

        try {
            switch ($event) {
                case 'supporter_created':
                case 'supporter_updated':
                    $supporters = data_get($body, 'supporters', []);
                    if (!is_array($supporters)) $supporters = [];
                    foreach ($supporters as $s) {
                        $ctx = $this->ctxFromSupporter($s);
                        $this->upsertHelpScout($token, $ctx, $event);
                    }
                    break;

                case 'contribution_paid':
                case 'contributions_paid':
                case 'contribution_refunded':
                case 'recurring_profile_updated':
                    // envelope contains everything for a single transaction
                    $ctx = $this->ctxFromContributionEnvelope($body);
                    // annotate payment_status by event
                    if ($event === 'contribution_refunded') {
                        $ctx['payment_status'] = 'refunded';
                    } elseif (in_array($event, ['contribution_paid','contributions_paid','recurring_profile_updated'], true)) {
                        $ctx['payment_status'] = 'paid';
                    }
                    $this->upsertHelpScout($token, $ctx, $event);
                    break;

                default:
                    Log::info('GC webhook: unhandled event', ['event' => $event]);
                    return response()->json(['status' => 'ignored', 'event' => $event], 200);
            }
        } catch (\Throwable $e) {
            Log::error('GC handler error', [
                'event' => $event,
                'msg'   => $e->getMessage(),
                'file'  => $e->getFile(),
                'line'  => $e->getLine(),
            ]);
            return response()->json(['ok' => false, 'error' => 'internal'], 500);
        }

        return response()->json(['ok' => true], 200);
    }

    /* --------------------------------------------------------------------
     | Context builders
     * ------------------------------------------------------------------ */

    private function ctxFromSupporter(array $s): array
    {
        $email = $s['email'] ?? null;
        if (!$email) {
            Log::info('GC webhook: skipped (no email)', ['body' => $s]);
            return ['skip' => true];
        }

        $b = $s['billing_address'] ?? [];

        return [
            'skip'       => false,
            'email'      => $email,
            'firstName'  => $s['first_name'] ?? null,
            'lastName'   => $s['last_name']  ?? null,

            // IDs / since
            'donorId'    => $s['id'] ?? ($s['vendor_contact_id'] ?? null),
            'donorSince' => isset($s['created_at']) ? substr((string)$s['created_at'], 0, 10) : null,

            // amounts/dates (supporter-only event doesn’t include donation info)
            'lastDate'        => isset($s['updated_at']) ? substr((string)$s['updated_at'], 0, 10) : null,
            'lastAmountStr'   => null,
            'payment'         => null,
            'payment_status'  => null,
            'payment_failure' => null,

            // recurring & sponsorship (not available here)
            'recurring'       => null,
            'sponsorship'     => null,

            // location
            'country' => $b['country'] ?? null,
            'state'   => $b['state']   ?? null,

            // address mirrors
            'addr1'  => $b['address1'] ?? null,
            'addr2'  => $b['address2'] ?? null,
            'city'   => $b['city']     ?? null,
            'postal' => $b['zip']      ?? null,

            // phone
            'phone_pretty' => $b['phone'] ?? null,
            'phone_digits' => $this->digits($b['phone'] ?? null),

            // lifetime (only if GC includes it on supporter)
            'lifetime' => $s['lifetime_donation_amount'] ?? null,

            // donor profile url (none on supporter-only)
            'donor_profile_url' => null,
        ];
    }

    private function ctxFromContributionEnvelope(array $b): array
    {
        // email
        $email = $b['email']
            ?? data_get($b, 'supporter.email')
            ?? data_get($b, 'billing_address.email');

        if (!$email) {
            Log::info('GC webhook: skipped (no email)', ['body' => $b]);
            return ['skip' => true];
        }

        $support = $b['supporter'] ?? [];
        $billing = $b['billing_address'] ?? [];
        $li      = data_get($b, 'line_items.0', []);
        $rec     = $li['recurring_profile'] ?? $li['recurring'] ?? [];
        $pay0    = data_get($b, 'payments.0', []);

        // Recurring summary
        $recAmt  = $rec['amount'] ?? null;
        $recFreq = $rec['billing_period_description'] ?? ($rec['frequency'] ?? $li['variant']['billing_period'] ?? null);
        $recDay  = $rec['billing_period_day'] ?? ($rec['day'] ?? $li['recurring_day'] ?? null);
        $recSummary = null;
        if ($recAmt && $recFreq) {
            $recSummary = '$' . rtrim(rtrim(number_format((float)$recAmt, 2, '.', ''), '0'), '.') . ' / '
                        . ucfirst((string)$recFreq) . ($recDay ? ' / ' . $recDay : '');
        }

        // sponsorship (if provided)
        $spon = $li['sponsorship'] ?? null;
        $sponsorship = null;
        if (is_array($spon)) {
            $sponsorship = [
                'name' => $spon['full_name'] ?? null,
                'ref'  => $spon['reference_number'] ?? null,
                'url'  => $spon['url'] ?? null,
            ];
        }

        // Last donation amount (amount + currency code)
        $lastAmountStr = null;
        $amt = $b['total_amount'] ?? $b['subtotal_amount'] ?? $b['amount'] ?? null;
        $cur = $b['currency'] ?? data_get($b, 'payments.0.currency.code');
        if ($amt !== null && $cur) {
            $lastAmountStr = rtrim(rtrim(number_format((float)$amt, 2, '.', ''), '0'), '.') . ' ' . $cur;
        }

        // Date
        $orderedAt = $b['ordered_at'] ?? $b['created_at'] ?? null;
        $lastDate = null;
        if ($orderedAt) {
            try { $lastDate = Carbon::parse($orderedAt)->toDateString(); }
            catch (\Throwable $e) { $lastDate = substr((string) $orderedAt, 0, 10); }
        }

        // Payment method / failure
        $brand   = data_get($pay0, 'card.brand')
            ?? data_get($rec, 'payment_method.display_name')
            ?? data_get($b, 'payment_type');
        $failure = data_get($pay0, 'failure_message') ?? data_get($pay0, 'failure_code');

        // donor profile url fallbacks
        $donorProfileUrl = data_get($spon, 'url')
            ?? data_get($b, 'supporter.url')
            ?? data_get($b, 'supporter.profile_url')
            ?? data_get($li, 'public_url')
            ?? data_get($b, 'http_referer');

        return [
            'skip'       => false,
            'email'      => $email,
            'firstName'  => $support['first_name'] ?? data_get($billing, 'first_name'),
            'lastName'   => $support['last_name']  ?? data_get($billing, 'last_name'),

            // IDs / since
            'donorId'    => $support['id_deprecated'] ?? $support['id'] ?? null,
            'donorSince' => isset($support['created_at']) ? substr((string)$support['created_at'], 0, 10) : null,

            // amounts/dates
            'lastAmountStr'   => $lastAmountStr,
            'lastDate'        => $lastDate,
            'payment'         => $brand,
            'payment_status'  => null,  // set by caller based on event
            'payment_failure' => $failure,

            // recurring & sponsorship
            'recurring'   => $recSummary,
            'sponsorship' => $sponsorship,

            // location
            'country' => $billing['country_code'] ?? $billing['country'] ?? null,
            'state'   => $billing['province_code'] ?? $billing['state'] ?? null,

            // address mirrors
            'addr1'  => $billing['address1'] ?? null,
            'addr2'  => $billing['address2'] ?? null,
            'city'   => $billing['city']     ?? null,
            'postal' => $billing['zip'] ?? $billing['postal'] ?? null,

            // phones: billing -> supporter -> shipping
            'phone_pretty' => $billing['phone'] ?? ($support['phone'] ?? data_get($b, 'shipping_address.phone')),
            'phone_digits' => $this->digits($billing['phone'] ?? ($support['phone'] ?? data_get($b, 'shipping_address.phone'))),

            // lifetime (rarely present on contribution)
            'lifetime' => $support['lifetime_donation_amount'] ?? null,

            // donor profile url
            'donor_profile_url' => $donorProfileUrl,
        ];
    }

    /* --------------------------------------------------------------------
     | Upsert into Help Scout
     * ------------------------------------------------------------------ */

    private function upsertHelpScout(string $token, array $ctx, string $event): void
    {
        if (!empty($ctx['skip'])) return;

        $email = (string) $ctx['email'];

        // 1) find/create
        $existing = $this->hsFindCustomer($token, $email);
        $id = $existing['id'] ?? 0;
        if (!$id) {
            $id = $this->hsCreateCustomer($token, $ctx['firstName'] ?? null, $ctx['lastName'] ?? null, $email);
        }

        // 2) update core profile (phone, address, website)
        $phones = [];
        if (!empty($ctx['phone_digits'])) {
            $phones[] = ['type' => 'work', 'value' => (string) $ctx['phone_digits']];
        }

        $addresses = [];
        if ($ctx['addr1'] || $ctx['city'] || $ctx['state'] || $ctx['postal'] || $ctx['country']) {
            $addresses[] = [
                'type'       => 'work',
                'lines'      => array_values(array_filter([$ctx['addr1'], $ctx['addr2']])),
                'city'       => $ctx['city'],
                'state'      => $ctx['state'],
                'postalCode' => $ctx['postal'],
                'country'    => $ctx['country'],
            ];
        }

        $websites = [];
        if (!empty($ctx['donor_profile_url'])) {
            $websites[] = ['value' => (string) $ctx['donor_profile_url']];
        }

        $this->hsUpdateCore($token, $id, [
            'firstName' => $ctx['firstName'] ?? null,
            'lastName'  => $ctx['lastName'] ?? null,
            'phones'    => $phones ?: null,
            'addresses' => $addresses ?: null,
            'websites'  => $websites ?: null,
        ]);

        // 3) patch custom properties
        $this->hsPatchProperties($token, $id, [
            // donor / dates / amounts
            'donor_id'             => is_numeric($ctx['donorId']) ? (int) $ctx['donorId'] : null,
            'donor_since'          => $ctx['donorSince'],
            'last_donation_amount' => $ctx['lastAmountStr'],
            'last_donation_date'   => $ctx['lastDate'],
            'lifetime_donation'    => is_numeric($ctx['lifetime'] ?? null) ? (float)$ctx['lifetime'] : null,
            'donor_profile_url'    => $ctx['donor_profile_url'],

            // payments / recurring
            'payment_method'       => $ctx['payment'],
            'payment_status'       => $ctx['payment_status'] ?? null,
            'payment_failure'      => $ctx['payment_failure'] ?? null,
            'recurring_summary'    => $ctx['recurring'],

            // sponsorship
            'sponsorship_name'     => data_get($ctx,'sponsorship.name'),
            'sponsorship_ref'      => data_get($ctx,'sponsorship.ref'),
            'sponsorship_url'      => data_get($ctx,'sponsorship.url'),

            // location
            'country'              => $ctx['country'],
            'province'             => $ctx['state'],

            // mirrors
            'billing_address1'     => $ctx['addr1'],
            'billing_address2'     => $ctx['addr2'],
            'billing_city'         => $ctx['city'],
            'billing_postal'       => $ctx['postal'],
            'phone_numeric'        => $ctx['phone_digits'],
        ]);
    }

    /* --------------------------------------------------------------------
     | Helpers
     * ------------------------------------------------------------------ */

    private function digits(?string $raw): ?int
    {
        if (!$raw) return null;
        $d = preg_replace('/\D+/', '', $raw);
        return $d !== '' ? (int)$d : null;
    }

    /* --------------------------------------------------------------------
     | Debug endpoints
     * ------------------------------------------------------------------ */

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
