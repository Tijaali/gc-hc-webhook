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

        // B) direct email param
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

        // C) search API (not on all plans)
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
     * Update HS customer properties using an array of {slug,value} objects.
     * (Safer than JSON-Patch "ops" for your account, based on previous errors.)
     */
    private function hsPatchProperties(string $token, int $customerId, array $kv): void
    {
        $slugMap = [
            'donor_id'            => 'donor-id',           // number
            'last_donation_date'  => 'last-order',         // date YYYY-MM-DD
            'country'             => 'country',            // text
            'province'            => 'state',              // text
            'lifetime_donation'   => 'lifetime-donation',  // number
            'donor_profile_url'   => 'gc-donor-profile',   // url/text
            'phone'               => 'phone-no',           // number
            'preferred_language'  => 'preferred-language', // dropdown (option id)
            // If you add new HS properties, map them here:
            'last_donation_amount' => 'last-donation-amount',
            'payment_method'       => 'payment-method',
        ];

        $numericSlugs = ['donor-id', 'lifetime-donation', 'phone-no'];
        $existing     = $this->hsPropertySlugs($token);

        $payload = [];
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
                try {
                    $val = Carbon::parse($val)->toDateString();
                } catch (\Throwable $e) {
                    $val = substr((string) $val, 0, 10);
                }
            }

            $payload[] = ['slug' => $slug, 'value' => $val];
        }

        if (!$payload) return;

        $r = Http::withToken($token)
            ->acceptJson()->asJson()
            ->patch("{$this->hsApi}/customers/{$customerId}/properties", $payload);

        if (!in_array($r->status(), [200, 204], true)) {
            Log::error('HS properties failed', [
                'status'  => $r->status(),
                'body'    => $r->body(),
                'payload' => $payload,
            ]);
            abort(500, 'HS properties failed: ' . $r->body());
        }
    }

    /* =========================
     *   Givecloud validation
     * ========================= */

    private function verifyGivecloud(Request $r): void
    {
        $secret = (string) env('GC_WEBHOOK_SECRET', '');
        abort_unless($secret !== '', 500, 'Missing GC_WEBHOOK_SECRET');

        $sig = $r->header('X-Givecloud-Signature') ?? $r->header('x-givecloud-signature');
        $raw = $r->getContent();

        // Givecloud sends an HMAC-SHA1 of the raw body using your secret.
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

    /* =========================
     *       Webhook (GC)
     * ========================= */

    public function gc(Request $r)
    {
        $this->verifyGivecloud($r);

        $b = $r->json()->all();

        // ---- EMAIL (supporters array aware) ----
        $emails = array_filter(Arr::flatten([
            data_get($b, 'email'),
            data_get($b, 'supporter.email'),
            data_get($b, 'supporters.*.email'),
            data_get($b, 'billing_address.email'),
            data_get($b, 'supporters.*.billing_address.email'),
            data_get($b, 'account.email'),
            data_get($b, 'customer.email'),
        ]));
        $email = $emails ? reset($emails) : null;

        if (!$email) {
            Log::info('GC webhook: skipped (no email)', ['body' => $b]);
            return response()->json(['status' => 'skipped', 'reason' => 'no email'], 202);
        }

        // ---- NAMES ----
        $first = data_get($b, 'supporter.first_name')
            ?? data_get($b, 'supporters.0.first_name')
            ?? data_get($b, 'billing_address.first_name')
            ?? data_get($b, 'supporters.0.billing_address.first_name');

        $last  = data_get($b, 'supporter.last_name')
            ?? data_get($b, 'supporters.0.last_name')
            ?? data_get($b, 'billing_address.last_name')
            ?? data_get($b, 'supporters.0.billing_address.last_name');

        // ---- AMOUNT / CURRENCY (for optional props) ----
        $amount   = data_get($b, 'total_amount') ?? data_get($b, 'amount');
        $currency = data_get($b, 'currency') ?? data_get($b, 'payments.0.currency.code');
        $lastAmt  = ($amount !== null && $currency) ? "{$amount} {$currency}" : null;

        // ---- DATE (order/created/supporter updated) ----
        $rawDate  = data_get($b, 'ordered_at')
            ?? data_get($b, 'created_at')
            ?? data_get($b, 'supporters.0.updated_at')
            ?? data_get($b, 'supporters.0.created_at');

        $lastDate = null;
        if ($rawDate) {
            try {
                $lastDate = Carbon::parse($rawDate)->toDateString();
            } catch (\Throwable $e) {
                $lastDate = substr((string) $rawDate, 0, 10);
            }
        }

        // ---- PAYMENT METHOD (optional) ----
        $pm = data_get($b, 'payments.0.card.brand')
            ?? data_get($b, 'payments.0.type')
            ?? data_get($b, 'payment_type');

        // ---- GEO ----
        $country  = data_get($b, 'billing_address.country_code')
            ?? data_get($b, 'billing_address.country')
            ?? data_get($b, 'supporters.0.billing_address.country');

        $province = data_get($b, 'billing_address.province_code')
            ?? data_get($b, 'billing_address.state')
            ?? data_get($b, 'supporters.0.billing_address.state');

        // ---- LIFETIME & DONOR ID ----
        $lifetime = data_get($b, 'supporter.lifetime_donation_amount')
            ?? data_get($b, 'supporters.0.lifetime_donation_amount');

        $donorId  = data_get($b, 'supporter.id')
            ?? data_get($b, 'supporters.0.id')
            ?? data_get($b, 'account.id');

        // ---- PHONE ----
        $rawPhone = data_get($b, 'billing_address.phone')
            ?? data_get($b, 'supporters.0.billing_address.phone')
            ?? data_get($b, 'supporter.phone')
            ?? data_get($b, 'account.phone')
            ?? data_get($b, 'customer.phone');

        $phone = $this->normalizePhone($rawPhone);

        // ---- Preferred Language -> HS dropdown option id (optional) ----
        $preferredLang = $this->mapLanguage(
            data_get($b, 'supporter.preferred_language')
            ?? data_get($b, 'supporters.0.preferred_language')
        );

        // ---- Upsert in Help Scout ----
        $token    = $this->hsAccessToken();
        $customer = $this->hsFindCustomer($token, $email);
        $id       = (int) ($customer['id'] ?? 0);
        if (!$id) $id = $this->hsCreateCustomer($token, $first, $last, $email);

        if ($id > 0) {
            $this->hsPatchProperties($token, $id, [
                'donor_id'             => is_numeric($donorId) ? (int) $donorId : null,
                'last_donation_date'   => $lastDate,
                'country'              => $country,
                'province'             => $province,
                'lifetime_donation'    => is_numeric($lifetime) ? (float) $lifetime : null,
                'donor_profile_url'    => data_get($b, 'supporter.profile_url')
                    ?? data_get($b, 'supporters.0.profile_url')
                    ?? null,
                'phone'                => $phone,
                'preferred_language'   => $preferredLang,
                // The next two only work if you create matching HS properties and map in $slugMap:
                'payment_method'       => $pm ?: null,
                'last_donation_amount' => $lastAmt,
            ]);
        } else {
            Log::warning('HS upsert skipped (no id resolvable)', ['email' => $email]);
        }

        return response()->json(['ok' => true, 'customerId' => $id], 200);
    }

    /* =========================
     *         Helpers
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

    /* =========================
     *      Debug endpoints
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
