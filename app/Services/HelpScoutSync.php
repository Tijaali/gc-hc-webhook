<?php

namespace App\Services;

use Carbon\Carbon;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class HelpScoutSync
{
    private string $hsTokenUrl = 'https://api.helpscout.net/v2/oauth2/token';
    private string $hsApi      = 'https://api.helpscout.net/v2';

    public function run(string $event, string $delivery, string $domain, array $b): void
    {
        // Guard: require donor email
        $email = $this->firstNonEmpty([
            'email',
            'supporter.email',
            'billing_address.email',
            'account.email',
            'customer.email',
        ], $b);

        if (!$email) {
            Log::warning('GC: no email in payload', compact('event', 'delivery'));
            return;
        }

        // Access token (cached)
        $token = $this->hsAccessToken();

        // Find or create customer
        $cust = $this->hsFindCustomer($token, $email);
        $id   = $cust['id'] ?? 0;

        if (!$id) {
            $first = $this->firstNonEmpty(['supporter.first_name', 'billing_address.first_name'], $b);
            $last  = $this->firstNonEmpty(['supporter.last_name', 'billing_address.last_name'], $b);
            $id    = $this->hsCreateCustomer($token, $first, $last, $email);
        }
        if (!$id) {
            Log::error('HS: cannot resolve customer id', compact('email', 'event'));
            return;
        }

        // Core profile (name, email, phones, addresses, website)
        $this->hsUpdateCore($token, $id, $b);

        // Custom properties
        $props = $this->buildProperties($b);
        $this->hsPatchProperties($token, $id, $props);

        Log::info('HS_SYNC_OK', [
            'event'      => $event,
            'delivery'   => $delivery,
            'email'      => $email,
            'customerId' => $id
        ]);
    }

    /* ---------- Build the properties you require ---------- */

    private function buildProperties(array $b): array
    {
        // IDs / dates
        $donorId    = $this->firstNonEmpty(['supporter.id', 'supporter.id_deprecated', 'account.id', 'vendor_contact_id'], $b);
        $orderedAt  = $this->firstNonEmpty(['ordered_at', 'created_at'], $b);
        $lastDate   = $this->dateOnly($orderedAt);
        $donorSince = $this->dateOnly($this->firstNonEmpty(['supporter.created_at'], $b));

        // amounts
        $amount   = $this->firstNonEmpty(['total_amount', 'subtotal_amount', 'amount'], $b);
        $currency = $this->firstNonEmpty(['currency', 'payments.0.currency.code'], $b);
        $lastDonationAmount = ($amount !== null && $currency)
            ? sprintf('%s %s', $this->money((float)$amount), $currency)
            : null;

        // payment method & status
        $payBrand  = $this->firstNonEmpty(['payments.0.card.brand', 'payments.0.type', 'payment_type'], $b);
        $isPaid    = $this->firstNonEmpty(['payments.0.status'], $b) === 'succeeded' || ($this->firstNonEmpty(['is_paid'], $b) === true);
        $payStatus = $isPaid ? 'paid' : null;

        // lifetime (if GC sends it)
        $lifetime = $this->firstNonEmpty(['supporter.lifetime_donation_amount'], $b);

        // contact/location
        $country = $this->firstNonEmpty(['billing_address.country_code', 'billing_address.country', 'supporter.billing_address.country'], $b);
        $state   = $this->firstNonEmpty(['billing_address.province_code', 'billing_address.state', 'supporter.billing_address.state'], $b);
        $addr1   = $this->firstNonEmpty(['billing_address.address1'], $b);
        $city    = $this->firstNonEmpty(['billing_address.city'], $b);
        $postal  = $this->firstNonEmpty(['billing_address.zip'], $b);
        $phone   = $this->digits($this->firstNonEmpty(['billing_address.phone', 'supporter.billing_address.phone'], $b));

        // URLs
        $profile = $this->firstNonEmpty(['supporter.profile_url', 'line_items.0.public_url'], $b);

        // recurring summary
        $recurring = $this->buildRecurringSummary($b);

        // sponsorship
        $sponsorship = $this->buildSponsorship($b);

        return array_filter([
            // Identity / donor meta
            'donor_id'             => is_numeric($donorId) ? (int)$donorId : null,
            'donor_since'          => $donorSince,
            'lifetime_donation'    => is_numeric($lifetime) ? (float)$lifetime : null,
            'donor_profile_url'    => $profile,

            // Donation info
            'last_donation_date'   => $lastDate,
            'last_donation_amount' => $lastDonationAmount,

            // Payment
            'payment_method'       => $payBrand,
            'payment_status'       => $payStatus,

            // Recurring
            'recurring_summary'    => $recurring,

            // Sponsorship
            'sponsorship_name'     => $sponsorship['name'] ?? null,
            'sponsorship_ref'      => $sponsorship['ref'] ?? null,
            'sponsorship_url'      => $sponsorship['url'] ?? null,

            // Location/contact
            'country'              => $country,
            'province'             => $state,
            'phone'                => $phone,
            'billing_address1'     => $addr1,
            'billing_city'         => $city,
            'billing_postal'       => $postal,
        ], fn($v) => $v !== null && $v !== '');
    }

    private function buildRecurringSummary(array $b): ?string
    {
        $li = data_get($b, 'line_items.0');
        if (!$li) return null;

        $amt    = data_get($li, 'recurring_amount') ?? data_get($li, 'price');
        $period = data_get($li, 'recurring_profile.billing_period_description') ?? data_get($li, 'variant.billing_period');
        $day    = data_get($li, 'recurring_day');

        if ($amt === null || !$period || !$day) return null;
        return sprintf('$%s / %s / %s', $this->money((float)$amt), $period, $this->ordinal((int)$day));
    }

    private function buildSponsorship(array $b): array
    {
        $li = data_get($b, 'line_items.0');
        return [
            'name' => data_get($li, 'sponsee.full_name') ?: null,
            'ref'  => data_get($li, 'reference') ?: null,
            'url'  => data_get($li, 'public_url') ?: null,
        ];
    }

    /* ---------- Help Scout API ---------- */

    private function hsAccessToken(): string
    {
        try {
            return Cache::remember('hs_access_token', now()->addMinutes(30), function () {
                $refresh = (string) (Cache::get('hs_refresh_file') ?? env('HS_REFRESH_TOKEN', ''));
                if ($refresh === '') {
                    Log::error('No HS refresh token configured');
                    return '';
                }

                $resp = Http::asForm()->timeout(8)->post($this->hsTokenUrl, [
                    'grant_type'    => 'refresh_token',
                    'refresh_token' => $refresh,
                    'client_id'     => env('HS_CLIENT_ID'),
                    'client_secret' => env('HS_CLIENT_SECRET'),
                ]);

                if (!$resp->ok()) {
                    Log::error('HS refresh failed', ['status' => $resp->status(), 'body' => $resp->body()]);
                    return '';
                }

                $data = $resp->json();
                if (!empty($data['refresh_token'])) {
                    Cache::forever('hs_refresh_file', (string)$data['refresh_token']);
                }
                return (string) ($data['access_token'] ?? '');
            });
        } catch (\Throwable $e) {
            Log::error('HS token exception', ['e' => $e->getMessage()]);
            return '';
        }
    }


    private function hsFindCustomer(string $token, string $email): ?array
    {
        // Primary: filter by email
        try {
            $r1 = Http::withToken($token)->timeout(8)->get("{$this->hsApi}/customers", [
                'email' => $email,
                'page'  => 1,
            ]);
            if ($r1->ok()) {
                $hit = data_get($r1->json(), '_embedded.customers.0');
                if ($hit) return $hit;
            }
        } catch (\Throwable $e) {
            Log::warning('HS customers?email failed', ['e' => $e->getMessage()]);
        }

        // Fallback: correct search endpoint
        try {
            $q  = '(email:"' . addslashes($email) . '")';
            $r2 = Http::withToken($token)->timeout(8)
                ->get("{$this->hsApi}/search/customers", ['query' => $q]);

            if ($r2->ok()) {
                // some accounts return results[].customer; others results[].id
                $hit = data_get($r2->json(), '_embedded.results.0.customer')
                    ?: data_get($r2->json(), '_embedded.results.0');

                if (is_array($hit)) return $hit;
            }

            Log::warning('HS find failed', [
                'email' => $email,
                's1'    => isset($r1) ? $r1->status() : null,
                's2'    => isset($r2) ? $r2->status() : null,
                'b2'    => isset($r2) ? $r2->body() : null,
            ]);
        } catch (\Throwable $e) {
            Log::warning('HS search/customers failed', ['e' => $e->getMessage()]);
        }

        return null;
    }


    private function hsCreateCustomer(string $token, ?string $first, ?string $last, string $email): int
    {
        $safeFirst = $first ?: ucfirst(strtolower(strtok($email, '@')));
        $payload = [
            'firstName' => $safeFirst,
            'lastName'  => $last ?: null,
            'emails'    => [['type' => 'work', 'value' => $email]],
        ];

        $r = Http::withToken($token)->acceptJson()->asJson()->timeout(8)
            ->post("{$this->hsApi}/customers", $payload);

        if ($r->status() === 409) {
            $existing = $this->hsFindCustomer($token, $email);
            if ($existing && isset($existing['id'])) {
                return (int)$existing['id'];
            }
        }

        if ($r->successful()) {
            return (int) ($r->json('id') ?? 0);
        }

        Log::error('HS create failed', ['status' => $r->status(), 'body' => $r->body(), 'payload' => $payload]);
        return 0;
    }

    private function hsUpdateCore(string $token, int $id, array $b): void
    {
        $first = $this->firstNonEmpty(['supporter.first_name', 'billing_address.first_name'], $b);
        $last  = $this->firstNonEmpty(['supporter.last_name', 'billing_address.last_name'], $b);
        $email = $this->firstNonEmpty(['email', 'supporter.email', 'billing_address.email'], $b);

        $addr1 = $this->firstNonEmpty(['billing_address.address1'], $b);
        $city  = $this->firstNonEmpty(['billing_address.city'], $b);
        $state = $this->firstNonEmpty(['billing_address.province_code', 'billing_address.state'], $b);
        $zip   = $this->firstNonEmpty(['billing_address.zip'], $b);
        $ctry  = $this->firstNonEmpty(['billing_address.country_code', 'billing_address.country'], $b);
        $phone = $this->digits($this->firstNonEmpty(['billing_address.phone', 'supporter.billing_address.phone'], $b));
        $site  = $this->firstNonEmpty(['supporter.profile_url', 'line_items.0.public_url'], $b);

        $payload = array_filter([
            'firstName' => $first ?: null,
            'lastName'  => $last ?: null,
            'emails'    => $email ? [['type' => 'work', 'value' => $email]] : null,
            'websites'  => $site ? [['value' => $site]] : null,
            'phones'    => $phone ? [['type' => 'work', 'value' => (string)$phone]] : null,
            'addresses' => ($addr1 || $city || $state || $zip || $ctry) ? [[
                'type'       => 'work',
                'lines'      => array_values(array_filter([$addr1])),
                'city'       => $city ?: null,
                'state'      => $state ?: null,
                'postalCode' => $zip ?: null,
                'country'    => $ctry ?: null,
            ]] : null,
        ], fn($v) => $v !== null);

        if (!$payload) return;

        $r = Http::withToken($token)->acceptJson()->asJson()->timeout(8)
            ->put("{$this->hsApi}/customers/{$id}", $payload);

        if (!$r->successful()) {
            Log::warning('HS core update failed (non-fatal)', [
                'status' => $r->status(),
                'body' => $r->body(),
                'pay' => $payload
            ]);
        }
    }

    private function hsPropertySlugs(string $token): array
    {
        // Optional: set a comma list to skip the GET call
        $prefill = (string) env('HS_KNOWN_SLUGS', '');
        if ($prefill !== '') {
            return collect(explode(',', $prefill))
                ->map(fn($s) => trim($s))->filter()->values()->all();
        }

        return Cache::remember('hs_prop_slugs', now()->addMinutes(30), function () use ($token) {
            $r = Http::withToken($token)->timeout(6)->get("{$this->hsApi}/customer-properties");
            if (!$r->ok()) {
                Log::warning('HS properties list failed', ['status' => $r->status(), 'body' => $r->body()]);
                return [];
            }
            return collect(data_get($r->json(), '_embedded.customer-properties', []))
                ->pluck('slug')->filter()->values()->all();
        });
    }

    private function hsPatchProperties(string $token, int $customerId, array $kv): void
    {
        // Map our concepts → HS slugs
        $slugMap = [
            'donor_id'             => 'donor-id',
            'donor_since'          => 'donor-since',
            'lifetime_donation'    => 'lifetime-donation',
            'donor_profile_url'    => 'gc-donor-profile',
            // If you actually want a *separate* "Last Donation Date", change this to 'last-donation-date'
            'last_donation_date'   => 'last-order',
            'last_donation_amount' => 'last-donation-amount',
            'payment_status'       => 'payment-status',
            'payment_method'       => 'payment-method',
            'recurring_summary'    => 'recurring-summary',
            'sponsorship_name'     => 'sponsorship-name',
            'sponsorship_ref'      => 'sponsorship-ref',
            'sponsorship_url'      => 'sponsorship-url',
            'country'              => 'country',
            'province'             => 'state',
            'phone'                => 'phone-no',
            'billing_address1'     => 'billing-address1',
            'billing_city'         => 'billing-city',
            'billing_postal'       => 'billing-postal',
        ];
        $numericSlugs = ['donor-id', 'lifetime-donation', 'phone-no'];

        // Fetch existing property slugs (cached) so we don’t patch unknown ones
        $existing = $this->hsPropertySlugs($token);

        // Build JSON Patch ops
        $ops = [];
        $missing = [];
        foreach ($kv as $concept => $val) {
            if ($val === null || $val === '') continue;

            $slug = $slugMap[$concept] ?? null;
            if (!$slug) continue;

            if (!in_array($slug, $existing, true)) {
                $missing[] = $slug;
                continue;
            }

            // normalize types
            if (in_array($slug, $numericSlugs, true)) {
                if (!is_numeric($val)) continue;
                $val = $val + 0;
            }
            if (in_array($slug, ['last-order', 'donor-since'], true)) {
                $val = $this->dateOnly((string)$val);
                if (!$val) continue;
            }

            $ops[] = ['op' => 'replace', 'path' => '/' . $slug, 'value' => $val];
        }

        if ($missing) {
            Log::warning('HS missing custom properties (create these slugs)', array_values(array_unique($missing)));
        }
        if (!$ops) return;

        // ✅ Correct payload shape: { "operations": [...] }
        try {
            $payload = ['operations' => $ops];
            $r = Http::withToken($token)->acceptJson()->asJson()->timeout(8)
                ->patch("{$this->hsApi}/customers/{$customerId}/properties", $payload);

            if (!$r->ok()) {
                Log::error('HS properties failed', ['status' => $r->status(), 'body' => $r->body(), 'ops' => $ops]);
            }
        } catch (\Throwable $e) {
            Log::error('HS properties exception', ['e' => $e->getMessage(), 'ops' => $ops]);
        }
    }


    /* ---------- utils ---------- */

    private function firstNonEmpty(array $paths, array $source): mixed
    {
        foreach ($paths as $p) {
            $v = data_get($source, $p);
            if ($v !== null && $v !== '') return $v;
        }
        return null;
    }

    private function digits(?string $raw): ?int
    {
        if (!$raw) return null;
        $d = preg_replace('/\D+/', '', $raw);
        return $d !== '' ? (int)$d : null;
    }

    private function dateOnly(?string $raw): ?string
    {
        if (!$raw) return null;
        try {
            return Carbon::parse($raw)->toDateString();
        } catch (\Throwable $e) {
            return substr((string)$raw, 0, 10);
        }
    }

    private function money(float $n): string
    {
        $s = number_format($n, 2, '.', '');
        return rtrim(rtrim($s, '0'), '.');
    }

    private function ordinal(int $n): string
    {
        if (in_array($n % 100, [11, 12, 13], true)) return $n . 'th';
        return $n . ([1 => 'st', 2 => 'nd', 3 => 'rd'][$n % 10] ?? 'th');
    }
}
