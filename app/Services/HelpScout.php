<?php

namespace App\Services;

use Carbon\Carbon;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Storage;

class HelpScout
{
    private string $tokenUrl = 'https://api.helpscout.net/v2/oauth2/token';
    private string $api      = 'https://api.helpscout.net/v2';

    /* =========================
     * OAuth
     * ========================= */
    public function accessToken(): string
    {
        return Cache::remember('hs_access_token', now()->addMinutes(29), function () {
            $refreshToken = $this->getRefreshToken();
            abort_unless($refreshToken, 500, 'No Help Scout refresh token. Visit /oauth/hs/start to connect.');

            $resp = Http::asForm()->post($this->tokenUrl, [
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
                $this->saveRefreshToken($data['refresh_token']);
            }

            return (string)$data['access_token'];
        });
    }

    public function exchangeCode(string $code): array
    {
        $resp = Http::asForm()->post($this->tokenUrl, [
            'grant_type'    => 'authorization_code',
            'code'          => $code,
            'client_id'     => env('HS_CLIENT_ID'),
            'client_secret' => env('HS_CLIENT_SECRET'),
            'redirect_uri'  => env('HS_REDIRECT_URI'),
        ]);

        if (!$resp->ok()) {
            return ['error' => 'oauth_exchange_failed', 'raw' => $resp->json()];
        }

        $data = $resp->json();
        if (!empty($data['refresh_token'])) {
            $this->saveRefreshToken($data['refresh_token']);
        }

        return [
            'access_token_first8' => substr((string)($data['access_token'] ?? ''), 0, 8),
            'refresh_token_saved' => !empty($data['refresh_token']),
            'token_type'          => $data['token_type'] ?? null,
            'expires_in'          => $data['expires_in'] ?? null,
        ];
    }

    private function getRefreshToken(): ?string
    {
        $path = 'hs_oauth.json';
        if (Storage::exists($path)) {
            $saved = json_decode(Storage::get($path), true);
            if (!empty($saved['refresh_token'])) {
                return (string) $saved['refresh_token'];
            }
        }
        $env = env('HS_REFRESH_TOKEN');
        return $env ? (string)$env : null;
    }

    private function saveRefreshToken(string $token): void
    {
        Storage::put('hs_oauth.json', json_encode([
            'refresh_token' => $token,
            'saved_at'      => now()->toISOString(),
        ], JSON_PRETTY_PRINT));
        \Illuminate\Support\Facades\Cache::forever('hs_refresh_file', $token);
    }


    /* =========================
     * Customers
     * ========================= */

    public function findCustomerByEmail(string $token, string $email): ?array
    {
        $http = fn() => Http::withToken($token)->connectTimeout(2)->timeout(6);

        // Fast path
        $r = $http()->get("{$this->api}/customers", ['email' => $email, 'page' => 1]);
        if ($r->ok()) {
            return data_get($r->json(), '_embedded.customers.0');
        }
        Log::warning('HS search (email) failed', ['status' => $r->status()]);

        // Fallback DSL
        $r2 = $http()->get("{$this->api}/customers", ['query' => '(email:"' . $email . '")', 'page' => 1]);
        if ($r2->ok()) {
            return data_get($r2->json(), '_embedded.customers.0');
        }
        Log::warning('HS search (dsl) failed', ['status' => $r2->status()]);

        return null;
    }

    public function createOrGetId(string $token, ?string $first, ?string $last, string $email): ?int
    {
        $safeFirst = $first ?: ucfirst(strtolower(strtok($email, '@')));
        $payload = [
            'firstName' => $safeFirst,
            'lastName'  => $last ?: null,
            'emails'    => [['type' => 'work', 'value' => $email]],
        ];

        $r = Http::withToken($token)->connectTimeout(2)->timeout(8)
            ->acceptJson()->asJson()
            ->post("{$this->api}/customers", $payload);

        if ($r->successful()) {
            return (int) ($r->json('id') ?? 0);
        }

        if ($r->status() === 409) { // already exists
            $existing = $this->findCustomerByEmail($token, $email);
            return $existing['id'] ?? null;
        }

        Log::warning('HS create failed', ['status' => $r->status()]);
        return null;
    }

    public function updateCore(string $token, int $customerId, array $core): void
    {
        if (!$core) return;

        $r = Http::withToken($token)->connectTimeout(2)->timeout(8)
            ->acceptJson()->asJson()
            ->put("{$this->api}/customers/{$customerId}", $core);

        if (!$r->successful()) {
            Log::warning('HS core update failed (non-fatal)', [
                'status' => $r->status(),
            ]);
        }
    }

    /* =========================
     * Custom Properties
     * ========================= */

    public function propertySlugs(string $token): array
    {
        return Cache::remember('hs_prop_slugs', now()->addMinutes(30), function () use ($token) {
            $r = Http::withToken($token)->connectTimeout(2)->timeout(8)
                ->get("{$this->api}/customer-properties");
            if (!$r->ok()) {
                abort(500, 'HS properties list failed: ' . $r->body());
            }
            return collect(data_get($r->json(), '_embedded.customer-properties', []))
                ->pluck('slug')->all();
        });
    }

    public function patchProperties(string $token, int $customerId, array $kv): void
    {
        $slugMap = $this->slugMap();
        $existing = $this->propertySlugs($token);

        // Warn once for important slugs
        $must = ['last-donation-amount', 'payment-method', 'billing-address1', 'billing-city', 'billing-postal', 'recurring-summary', 'sponsorship-name', 'sponsorship-ref', 'sponsorship-url'];
        $missing = array_values(array_diff($must, $existing));
        if ($missing) Log::warning('HS missing important custom properties (please create these slugs)', $missing);

        $numeric = ['donor-id', 'lifetime-donation', 'phone-no'];
        $ops = [];

        foreach ($kv as $concept => $val) {
            if ($val === null || $val === '') continue;
            $slug = $slugMap[$concept] ?? null;
            if (!$slug || !in_array($slug, $existing, true)) continue;

            if (in_array($slug, ['last-order', 'donor-since'], true)) {
                try {
                    $val = Carbon::parse($val)->toDateString();
                } catch (\Throwable $e) {
                    $val = substr((string)$val, 0, 10);
                }
            }
            if (in_array($slug, $numeric, true)) {
                if (!is_numeric($val)) continue;
                $val += 0;
            }

            $ops[] = ['op' => 'replace', 'path' => '/' . $slug, 'value' => $val];
        }

        if (!$ops) return;

        $r = Http::withToken($token)->connectTimeout(2)->timeout(8)
            ->acceptJson()->asJson()
            ->patch("{$this->api}/customers/{$customerId}/properties", $ops);

        if (!in_array($r->status(), [200, 204], true)) {
            Log::warning('HS properties patch failed (non-fatal)', [
                'status' => $r->status(),
                'body'   => substr($r->body(), 0, 250),
            ]);
        }
    }

    private function slugMap(): array
    {
        return [
            'donor_id'             => 'donor-id',
            'donor_since'          => 'donor-since',
            'last_donation_date'   => 'last-order',
            'last_donation_amount' => 'last-donation-amount',
            'country'              => 'country',
            'province'             => 'state',
            'payment_status'       => 'payment-status',
            'payment_method'       => 'payment-method',
            'recurring_summary'    => 'recurring-summary',
            'lifetime_donation'    => 'lifetime-donation',
            'donor_profile_url'    => 'gc-donor-profile',
            'phone'                => 'phone-no',
            // mirrored billing
            'billing_address1'     => 'billing-address1',
            'billing_city'         => 'billing-city',
            'billing_postal'       => 'billing-postal',
            // sponsorship
            'sponsorship_name'     => 'sponsorship-name',
            'sponsorship_ref'      => 'sponsorship-ref',
            'sponsorship_url'      => 'sponsorship-url',
        ];
    }
}
