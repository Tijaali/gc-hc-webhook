<?php

namespace App\Http\Controllers;

use Carbon\Carbon;
use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Storage;

class WebhookController extends Controller
{
    private string $hsTokenUrl = 'https://api.helpscout.net/v2/oauth2/token';
    private string $hsApi      = 'https://api.helpscout.net/v2';

    /* =========================
     *  Help Scout OAuth
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
            'access_token_first8' => substr((string) ($data['access_token'] ?? ''), 0, 8),
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
            if (!empty($saved['refresh_token'])) return (string) $saved['refresh_token'];
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
     *  Help Scout: Customers
     * ========================= */
    private function hsFindCustomer(string $token, string $email): ?array
    {
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

        // Some accounts don’t have this endpoint; 404 is fine.
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
            if ($existing && isset($existing['id'])) return (int) $existing['id'];
        }

        if ($r->successful()) {
            return (int) ($r->json('id') ?? 0);
        }

        Log::error('HS create failed', ['status' => $r->status(), 'body' => $r->body(), 'payload' => $payload]);
        abort(500, 'HS create failed: ' . $r->body());
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
        // Your existing slugs + optional ones (create in HS if you want them shown)
        $slugMap = [
            'donor_id'             => 'donor-id',            // number
            'country'              => 'country',             // text
            'province'             => 'state',               // text
            'last_donation_date'   => 'last-order',          // date YYYY-MM-DD
            'last_donation_amount' => 'last-donation-amount',// text (optional — create in HS)
            'recurring_summary'    => 'recurring-summary',   // text (optional — create in HS)
            'payment_method'       => 'payment-method',      // text (optional — create in HS)
            'payment_status'       => 'payment-status',      // text
            'payment_failure'      => 'payment-failure',     // text
            'lifetime_donation'    => 'lifetime-donation',   // number
            'donor_profile_url'    => 'gc-donor-profile',    // url/text
            'phone'                => 'phone-no',            // number
        ];

        $numericSlugs = ['donor-id', 'lifetime-donation', 'phone-no'];
        $existing     = $this->hsPropertySlugs($token);

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

            if ($slug === 'last-order') {
                try { $val = Carbon::parse($val)->toDateString(); }
                catch (\Throwable $e) { $val = substr((string)$val, 0, 10); }
            }

            $ops[] = ['op' => 'replace', 'path' => '/' . $slug, 'value' => $val];
        }

        if (!$ops) return;

        // JSON Patch
        $r = Http::withToken($token)
            ->withBody(json_encode($ops), 'application/json-patch+json')
            ->send('PATCH', "{$this->hsApi}/customers/{$customerId}/properties");

        if (!in_array($r->status(), [200, 204], true)) {
            Log::error('HS properties failed', ['status' => $r->status(), 'body' => $r->body(), 'ops' => $ops]);
            // Don’t throw to Givecloud; let caller ack 200
        }
    }

    /* =========================
     *  Givecloud signature verify
     * ========================= */
    private function verifyGivecloud(Request $r): void
    {
        $secret = (string) env('GC_WEBHOOK_SECRET', '');
        abort_unless($secret !== '', 500, 'Missing GC_WEBHOOK_SECRET');

        $sig = $r->header('X-Givecloud-Signature') ?? $r->header('x-givecloud-signature');
        $raw = $r->getContent();
        $calc = hash_hmac('sha1', $raw, $secret);

        if (env('GC_LOG_SIG', false)) {
            Log::debug('GC sig', [
                'received' => (string) $sig,
                'calc'     => (string) $calc,
                'match'    => $sig && hash_equals((string)$sig, (string)$calc),
            ]);
        }

        abort_unless($sig && hash_equals((string)$sig, (string)$calc), 401, 'Invalid signature');
    }

    /* =========================
     *  Main webhook (all events)
     * ========================= */
   // In WebhookController.php

public function gc(Request $r)
{
    $this->verifyGivecloud($r);
    $event = (string) ($r->header('X-Givecloud-Event') ?? '');
    $body  = $r->json()->all();

    try {
        switch ($event) {
            case 'supporter_created':
            case 'supporter_updated': {
                $arr = data_get($body, 'supporters', []);
                $processed = 0;
                foreach ((array) $arr as $sup) {
                    // Build a minimal, contribution-like shape for the per-supporter upsert
                    $mini = [
                        'supporter'       => $sup,
                        'email'           => data_get($sup, 'email') ?? data_get($sup, 'billing_address.email'),
                        'billing_address' => data_get($sup, 'billing_address'),
                        // no amounts/dates in these events, that’s fine
                    ];
                    $processed += $this->processOne($mini, null);
                }
                return response()->json(['ok' => true, 'event' => $event, 'processed' => $processed], 200);
            }

            case 'contribution_paid':
            case 'contributions_paid': {
                // Normal paid contribution
                $this->processOne($body, 'paid');
                return response()->json(['ok' => true, 'event' => $event], 200);
            }

            case 'contribution_refunded': {
                // Mark status as refunded; still upsert donor + fields we can extract
                $this->processOne($body, 'refunded');
                return response()->json(['ok' => true, 'event' => $event], 200);
            }

            case 'recurring_profile_updated': {
                // Payload focuses on the recurring profile; helper knows how to read it
                $this->processOne($body, null);
                return response()->json(['ok' => true, 'event' => $event], 200);
            }

            default: {
                // Future/unknown events — try our best with generic extractor
                $this->processOne($body, null);
                return response()->json(['ok' => true, 'event' => $event, 'note' => 'generic'], 200);
            }
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
 * Normalize ANY Givecloud payload into the donor fields you want,
 * then upsert into Help Scout (create + JSON Patch custom properties).
 *
 * @return int 1 if processed, 0 if skipped
 */
private function processOne(array $b, ?string $forcedPaymentStatus = null): int
{
    // -------- Email (required) --------
    $email = data_get($b, 'email')
        ?? data_get($b, 'supporter.email')
        ?? data_get($b, 'billing_address.email')
        ?? data_get($b, 'account.email')
        ?? data_get($b, 'customer.email');

    if (!$email) {
        Log::info('GC webhook: skipped (no email)', ['body' => $b]);
        return 0;
    }

    // -------- Names --------
    $first = data_get($b, 'supporter.first_name') ?? data_get($b, 'billing_address.first_name');
    $last  = data_get($b, 'supporter.last_name')  ?? data_get($b, 'billing_address.last_name');

    // -------- Phone (numeric HS prop) --------
    $rawPhone = data_get($b, 'billing_address.phone')
        ?? data_get($b, 'supporter.billing_address.phone');
    $phoneDigits = null;
    if ($rawPhone) {
        $digits = preg_replace('/\D+/', '', (string) $rawPhone);
        if ($digits !== '') $phoneDigits = (int) $digits;
    }

    // -------- Location --------
    $country  = data_get($b, 'billing_address.country_code')
        ?? data_get($b, 'billing_address.country')
        ?? data_get($b, 'supporter.billing_address.country');
    $province = data_get($b, 'billing_address.province_code')
        ?? data_get($b, 'billing_address.state')
        ?? data_get($b, 'supporter.billing_address.state');

    // -------- Donor ID (numeric) --------
    $donorId = data_get($b, 'supporter.id_deprecated')
        ?? data_get($b, 'supporter.id')
        ?? data_get($b, 'account.id');
    $donorId = is_numeric($donorId) ? (int) $donorId : null;

    // -------- Amount / Currency / Last donation date --------
    $amount   = data_get($b, 'total_amount') ?? data_get($b, 'amount') ?? data_get($b, 'subtotal_amount');
    $currency = data_get($b, 'currency') ?? data_get($b, 'payments.0.currency.code');
    $lastDonationAmount = ($amount !== null && $currency) ? (string) ($amount . ' ' . $currency) : null;

    $rawDate  = data_get($b, 'ordered_at') ?? data_get($b, 'created_at');
    $lastDate = null;
    if ($rawDate) {
        try { $lastDate = \Carbon\Carbon::parse($rawDate)->toDateString(); }
        catch (\Throwable $e) { $lastDate = substr((string) $rawDate, 0, 10); }
    }

    // -------- Recurring summary (from line_items OR top-level recurring_profile) --------
    $recAmt = data_get($b, 'line_items.0.recurring_amount')
           ?? data_get($b, 'line_items.0.recurring.amount')
           ?? data_get($b, 'line_items.0.total')
           ?? data_get($b, 'recurring_profile.amount')
           ?? data_get($b, 'recurring_profile.aggregate_amount');
    $freq = data_get($b, 'line_items.0.recurring.frequency')
         ?? data_get($b, 'line_items.0.recurring_profile.billing_period_description')
         ?? data_get($b, 'recurring_profile.billing_period_description')
         ?? data_get($b, 'recurring_profile.billing_period');
    $day  = data_get($b, 'line_items.0.recurring.day')
         ?? data_get($b, 'line_items.0.recurring_profile.billing_period_day')
         ?? data_get($b, 'recurring_profile.billing_period_day');
    $recurringSummary = ($recAmt && $freq)
        ? ('$' . $recAmt . ' / ' . $freq . ($day ? ' / ' . $day : ''))
        : null;

    // -------- Payment info / status --------
    $pmBrand   = data_get($b, 'payments.0.card.brand');
    $pmType    = data_get($b, 'payments.0.type') ?? data_get($b, 'payment_type');
    $wallet    = data_get($b, 'payments.0.card.wallet');
    $pmDesc    = trim(implode(' ', array_filter([$pmType, $pmBrand, $wallet])));
    $pmStatus  = $forcedPaymentStatus ?? (data_get($b, 'payments.0.status') ?? data_get($b, 'payments.0.outcome'));
    $pmFailure = data_get($b, 'payments.0.failure_message') ?? null;

    // -------- Lifetime total --------
    $lifetime = data_get($b, 'supporter.lifetime_donation_amount');

    // -------- Donor profile URL --------
    $profileUrl = data_get($b, 'supporter.profile_url')
               ?? data_get($b, 'line_items.0.public_url')
               ?? data_get($b, 'line_items.0.sponsorship.url');

    // -------- Upsert in Help Scout --------
    $token    = $this->hsAccessToken();
    $customer = $this->hsFindCustomer($token, $email);
    $id       = $customer['id'] ?? 0;
    if (!$id) $id = $this->hsCreateCustomer($token, $first, $last, $email);

    // -------- Patch HS custom properties --------
    $this->hsPatchProperties($token, $id, [
        'donor_id'             => $donorId,
        'country'              => $country,
        'province'             => $province,
        'phone'                => $phoneDigits,
        'last_donation_date'   => $lastDate,
        'last_donation_amount' => $lastDonationAmount,  // needs HS text prop 'last-donation-amount'
        'recurring_summary'    => $recurringSummary,    // needs HS text prop 'recurring-summary'
        'payment_method'       => $pmDesc,              // needs HS text prop 'payment-method'
        'payment_status'       => $pmStatus,
        'payment_failure'      => $pmFailure,
        'lifetime_donation'    => is_numeric($lifetime) ? (float) $lifetime : null,
        'donor_profile_url'    => $profileUrl,
    ]);

    return 1;
}


    /* =========================
     *  Debug endpoints
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
