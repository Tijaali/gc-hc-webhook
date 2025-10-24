<?php

namespace App\Services;

use Carbon\Carbon;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class SyncAbort extends \RuntimeException {}

class HelpScoutSync
{
    private string $hsTokenUrl = 'https://api.helpscout.net/v2/oauth2/token';
    private string $hsApi      = 'https://api.helpscout.net/v2';

    /**
     * Strict runner: throws on any critical failure so controller can return 500 (retry).
     */
    public function runStrict(string $event, string $delivery, string $domain, array $body): void
    {
        $b = $this->normalize($event, $body);

        $email = $this->firstNonEmpty([
            'email',
            'supporter.email',
            'billing_address.email',
            'account.email',
            'customer.email',
        ], $b);
        if (!$email) throw new SyncAbort('No donor email in payload');

        $token = $this->hsAccessTokenStrict();

        $cust = $this->hsFindCustomer($token, $email);
        $id   = $cust['id'] ?? 0;
        if (!$id) {
            $first = $this->firstNonEmpty(['supporter.first_name', 'billing_address.first_name'], $b);
            $last  = $this->firstNonEmpty(['supporter.last_name', 'billing_address.last_name'], $b);
            $id    = $this->hsCreateCustomerStrict($token, $first, $last, $email);
        }
        if (!$id) throw new SyncAbort('Could not resolve or create HS customer');

        $this->hsUpdateCoreSoft($token, $id, $b);

        $props = $this->buildProperties($b);
        $this->hsPatchPropertiesStrict($token, $id, $props);

        Log::info('HS_SYNC_OK', compact('event', 'delivery', 'email') + ['customerId' => $id]);
    }

    /* ---------- Normalization across GC events ---------- */
    private function normalize(string $event, array $b): array
    {
        if (isset($b['supporters'][0])) {
            $b['supporter'] = $b['supporters'][0];
            $b['email'] = $b['supporter']['email']
                ?? ($b['billing_address']['email'] ?? ($b['supporter']['billing_address']['email'] ?? null));
            if (!isset($b['billing_address']) && isset($b['supporter']['billing_address'])) {
                $b['billing_address'] = $b['supporter']['billing_address'];
            }
            if (!isset($b['created_at']) && isset($b['supporter']['created_at'])) {
                $b['created_at'] = $b['supporter']['created_at'];
            }
        }

        if (isset($b['recurring_profile']) && is_array($b['recurring_profile'])) {
            $rp = $b['recurring_profile'];
            if (!isset($b['line_items'][0])) $b['line_items'][0] = [];
            $b['line_items'][0]['recurring_profile'] = $rp;
            $b['line_items'][0]['recurring_amount']  = $rp['amount'] ?? ($b['line_items'][0]['recurring_amount'] ?? null);
            $b['line_items'][0]['recurring_day']     = $this->extractDayNumber($rp['billing_period_day'] ?? null);

            $acctType = data_get($rp, 'payment_method.account_type') ?: data_get($rp, 'payment_method.display_name');
            if ($acctType) {
                $b['payments'][0]['type']           = 'card';
                $b['payments'][0]['status']         = ($rp['status'] ?? '') === 'Active' ? 'succeeded' : (data_get($b, 'payments.0.status') ?? null);
                $b['payments'][0]['card']['brand']  = $acctType;
            }
            if (!isset($b['currency'])) {
                $b['currency'] = data_get($rp, 'currency.code') ?: data_get($rp, 'currency.iso_code');
            }
        }

        return $b;
    }

    /* ---------- Build ALL requested properties ---------- */
    private function buildProperties(array $b): array
    {
        $donorId    = $this->firstNonEmpty(['supporter.id', 'supporter.id_deprecated', 'account.id', 'vendor_contact_id'], $b);
        $orderedAt  = $this->firstNonEmpty(['ordered_at', 'created_at'], $b);
        $lastDate   = $this->dateOnly($orderedAt);
        $donorSince = $this->dateOnly($this->firstNonEmpty(['supporter.created_at'], $b));

        $amount   = $this->firstNonEmpty(['total_amount', 'subtotal_amount', 'amount', 'line_items.0.recurring_amount'], $b);
        $currency = $this->firstNonEmpty(['currency', 'payments.0.currency.code', 'line_items.0.recurring_profile.currency.code'], $b);
        $lastDonationAmount = ($amount !== null && $currency)
            ? sprintf('%s %s', $this->money((float)$amount), $currency)
            : null;

        $payBrand  = $this->firstNonEmpty(['payments.0.card.brand', 'payments.0.type', 'payment_type', 'line_items.0.recurring_profile.payment_method.account_type'], $b);
        $isPaid    = $this->firstNonEmpty(['payments.0.status'], $b) === 'succeeded' || ($this->firstNonEmpty(['is_paid'], $b) === true);
        $payStatus = $isPaid ? 'paid' : null;
        $txnType   = $this->firstNonEmpty(['payments.0.type', 'payment_type'], $b);

        $rpStatus  = strtolower((string)($this->firstNonEmpty(['line_items.0.recurring_profile.status', 'recurring_profile.status'], $b) ?? ''));
        $recStatus = $rpStatus ? ucfirst($rpStatus) : null; // Active / Paused / Canceled etc.

        $lifetime  = $this->firstNonEmpty(['supporter.lifetime_donation_amount'], $b);

        $country = $this->firstNonEmpty(['billing_address.country_code', 'billing_address.country', 'supporter.billing_address.country'], $b);
        $state   = $this->firstNonEmpty(['billing_address.province_code', 'billing_address.state', 'supporter.billing_address.state'], $b);
        $addr1   = $this->firstNonEmpty(['billing_address.address1'], $b);
        $city    = $this->firstNonEmpty(['billing_address.city'], $b);
        $postal  = $this->firstNonEmpty(['billing_address.zip'], $b);
        $phone   = $this->firstNonEmpty(['billing_address.phone', 'supporter.billing_address.phone'], $b);

        $profile = $this->firstNonEmpty(['supporter.profile_url', 'line_items.0.public_url'], $b);

        $recurring = $this->buildRecurringSummary($b);

        $sponsorship = $this->buildSponsorship($b);

        return array_filter([
            'donor_id'             => is_numeric($donorId) ? (int)$donorId : null,
            'donor_since'          => $donorSince,
            'lifetime_donation'    => is_numeric($lifetime) ? (float)$lifetime : null,
            'donor_profile_url'    => $profile,

            'last_donation_date'   => $lastDate,
            'last_donation_amount' => $lastDonationAmount,

            'payment_method'       => $payBrand,      // Visa/MasterCard/etc
            'payment_status'       => $payStatus,     // paid / failed
            'transaction_type'     => $txnType,       // card/ach/wallet_pay

            'recurring_summary'    => $recurring,     // $X / Monthly / 23rd
            'recurring_status'     => $recStatus,     // Active/Paused/Cancelled

            'sponsorship_name'     => $sponsorship['name'] ?? null,
            'sponsorship_ref'      => $sponsorship['ref'] ?? null,
            'sponsorship_url'      => $sponsorship['url'] ?? null,

            'country'              => $country,
            'province'             => $state,
            'phone'                => $phone ? $this->cleanPhone($phone) : null,
            'billing_address1'     => $addr1,
            'billing_city'         => $city,
            'billing_postal'       => $postal,
        ], fn($v) => $v !== null && $v !== '');
    }

    private function buildRecurringSummary(array $b): ?string
    {
        $rp = data_get($b, 'recurring_profile');
        if ($rp) {
            $amt    = data_get($rp, 'amount');
            $period = data_get($rp, 'billing_period_description') ?: data_get($rp, 'billing_period');
            $day    = $this->extractDayNumber(data_get($rp, 'billing_period_day'));
            if ($amt !== null && $period && $day) {
                return sprintf('$%s / %s / %s', $this->money((float)$amt), $period, $this->ordinal((int)$day));
            }
        }
        $li0 = data_get($b, 'line_items.0');
        if ($li0) {
            $amt    = data_get($li0, 'recurring_amount') ?? data_get($li0, 'price');
            $period = data_get($li0, 'recurring_profile.billing_period_description') ?? data_get($li0, 'variant.billing_period');
            $day    = data_get($li0, 'recurring_day');
            if ($day && !is_numeric($day)) $day = $this->extractDayNumber((string)$day);
            if ($amt !== null && $period && $day) {
                return sprintf('$%s / %s / %s', $this->money((float)$amt), $period, $this->ordinal((int)$day));
            }
        }
        return null;
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

    /* ---------- Help Scout API (STRICT) ---------- */
    private function hsAccessTokenStrict(): string
    {
        $token = Cache::remember('hs_access_token', now()->addMinutes(30), function () {
            $refresh = (string) (Cache::get('hs_refresh_file') ?? env('HS_REFRESH_TOKEN', ''));
            if ($refresh === '') {
                try {
                    $path = 'hs_oauth.json';
                    if (\Illuminate\Support\Facades\Storage::exists($path)) {
                        $saved = json_decode(\Illuminate\Support\Facades\Storage::get($path), true);
                        if (!empty($saved['refresh_token'])) {
                            $refresh = (string) $saved['refresh_token'];
                        }
                    }
                } catch (\Throwable $e) {
                }
            }

            if ($refresh === '') throw new SyncAbort('Missing HS_REFRESH_TOKEN');

            $resp = Http::asForm()->timeout(8)->post($this->hsTokenUrl, [
                'grant_type'    => 'refresh_token',
                'refresh_token' => $refresh,
                'client_id'     => env('HS_CLIENT_ID'),
                'client_secret' => env('HS_CLIENT_SECRET'),
            ]);
            if (!$resp->ok()) {
                throw new SyncAbort('HS token refresh failed: ' . $resp->status() . ' ' . $resp->body());
            }
            $data = $resp->json();
            if (!empty($data['refresh_token'])) {
                Cache::forever('hs_refresh_file', (string)$data['refresh_token']);
            }
            return (string) ($data['access_token'] ?? '');
        });

        if ($token === '') throw new SyncAbort('Empty HS access token');
        return $token;
    }

    private function hsFindCustomer(string $token, string $email): ?array
    {
        $r1 = Http::withToken($token)->timeout(8)->get("{$this->hsApi}/customers", [
            'email' => $email,
            'page' => 1,
        ]);
        if ($r1->ok()) {
            $hit = data_get($r1->json(), '_embedded.customers.0');
            if ($hit) return $hit;
        }

        $q  = '(email:"' . addslashes($email) . '")';
        $r2 = Http::withToken($token)->timeout(8)->get("{$this->hsApi}/search/customers", ['query' => $q]);
        if ($r2->ok()) {
            $hit = data_get($r2->json(), '_embedded.results.0.customer')
                ?: data_get($r2->json(), '_embedded.results.0');
            if (is_array($hit)) return $hit;
        }

        Log::warning('HS find failed', ['email' => $email, 's1' => $r1->status(), 's2' => $r2->status(), 'b2' => $r2->body()]);
        return null;
    }

    private function hsCreateCustomerStrict(string $token, ?string $first, ?string $last, string $email): int
    {
        $safeFirst = $first ?: ucfirst(strtolower(strtok($email, '@')));
        $payload = [
            'firstName' => $safeFirst,
            'lastName'  => $last ?: null,
            'emails'    => [['type' => 'work', 'value' => $email]],
        ];

        $r = Http::withToken($token)->acceptJson()->asJson()->timeout(10)
            ->post("{$this->hsApi}/customers", $payload);

        if ($r->status() === 409) {
            $existing = $this->hsFindCustomer($token, $email);
            if ($existing && isset($existing['id'])) return (int)$existing['id'];
            throw new SyncAbort('HS create conflict but could not fetch existing');
        }

        if ($r->successful()) return (int)($r->json('id') ?? 0);

        throw new SyncAbort('HS create failed: ' . $r->status() . ' ' . $r->body());
    }

    private function hsUpdateCoreSoft(string $token, int $id, array $b): void
    {
        $first = $this->firstNonEmpty(['supporter.first_name', 'billing_address.first_name'], $b);
        $last  = $this->firstNonEmpty(['supporter.last_name', 'billing_address.last_name'], $b);
        $email = $this->firstNonEmpty(['email', 'supporter.email', 'billing_address.email'], $b);

        $addr1 = $this->firstNonEmpty(['billing_address.address1'], $b);
        $city  = $this->firstNonEmpty(['billing_address.city'], $b);
        $state = $this->firstNonEmpty(['billing_address.province_code', 'billing_address.state'], $b);
        $zip   = $this->firstNonEmpty(['billing_address.zip'], $b);
        $ctry  = $this->firstNonEmpty(['billing_address.country_code', 'billing_address.country'], $b);
        $phone = $this->firstNonEmpty(['billing_address.phone', 'supporter.billing_address.phone'], $b);
        $site  = $this->firstNonEmpty(['supporter.profile_url', 'line_items.0.public_url'], $b);

        $payload = array_filter([
            'firstName' => $first ?: null,
            'lastName'  => $last ?: null,
            'emails'    => $email ? [['type' => 'work', 'value' => $email]] : null,
            'websites'  => $site ? [['value' => $site]] : null,
            'phones'    => $phone ? [['type' => 'work', 'value' => $this->cleanPhone($phone)]] : null,
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

        $r = Http::withToken($token)->acceptJson()->asJson()->timeout(10)
            ->put("{$this->hsApi}/customers/{$id}", $payload);

        if (!$r->successful()) {
            Log::warning('HS core update failed (soft)', ['status' => $r->status(), 'body' => $r->body(), 'pay' => $payload]);
        }
    }

    private function hsPropertySlugs(string $token): array
    {
        $prefill = trim((string) env('HS_KNOWN_SLUGS', ''));
        if ($prefill !== '') {
            return collect(explode(',', $prefill))->map(fn($s) => trim($s))->filter()->values()->all();
        }

        $r = Http::withToken($token)->timeout(8)->get("{$this->hsApi}/customer-properties");
        if (!$r->ok()) {
            throw new SyncAbort('HS properties list failed: ' . $r->status() . ' ' . $r->body());
        }
        return collect(data_get($r->json(), '_embedded.customer-properties', []))
            ->pluck('slug')->filter()->values()->all();
    }

    private function hsPatchPropertiesStrict(string $token, int $customerId, array $kv): void
    {
        $slugMap = [
            'donor_id'             => 'donor-id',
            'donor_since'          => 'donor-since',
            'lifetime_donation'    => 'lifetime-donation',
            'donor_profile_url'    => 'gc-donor-profile',
            'last_donation_date'   => 'last-order',
            'last_donation_amount' => 'last-donation-amount',
            'payment_status'       => 'payment-status',
            'payment_method'       => 'payment-method',
            'transaction_type'     => 'transaction-type',
            'recurring_summary'    => 'recurring-summary',
            'recurring_status'     => 'recurring-status',
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
        $numericSlugs   = ['donor-id', 'lifetime-donation']; // phone kept as text
        $existing       = $this->hsPropertySlugs($token);

        // Required slugs (fatal if missing)
        $required = collect(explode(',', (string)env('HS_REQUIRED_SLUGS', '')))
            ->map(fn($s) => trim($s))->filter()->values()->all();

        $missingRequired = [];
        foreach ($required as $need) {
            if ($need !== '' && !in_array($need, $existing, true)) $missingRequired[] = $need;
        }
        if ($missingRequired) {
            throw new SyncAbort('Missing required HS custom properties: ' . implode(', ', $missingRequired));
        }

        $ops = [];
        foreach ($kv as $concept => $val) {
            if ($val === null || $val === '') continue;
            $slug = $slugMap[$concept] ?? null;
            if (!$slug) continue;
            if (!in_array($slug, $existing, true)) {
                // non-required unknown slugs are skipped
                continue;
            }
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

        if (!$ops) {
            // If we got here on a contribution/recurring event but nothing to set, treat as soft success.
            Log::info('HS properties no-op', ['customerId' => $customerId]);
            return;
        }

        $payload = ['operations' => $ops];
        $r = Http::withToken($token)->acceptJson()->asJson()->timeout(10)
            ->patch("{$this->hsApi}/customers/{$customerId}/properties", $payload);

        if (!$r->ok()) {
            throw new SyncAbort('HS properties failed: ' . $r->status() . ' ' . $r->body());
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

    private function cleanPhone(?string $raw): ?string
    {
        if (!$raw) return null;
        $d = preg_replace('/\D+/', '', $raw);
        return $d !== '' ? $d : null;
    }

    private function extractDayNumber($raw): ?int
    {
        if ($raw === null || $raw === '') return null;
        if (is_numeric($raw)) return (int)$raw;
        if (is_string($raw) && preg_match('/(\d{1,2})/', $raw, $m)) return (int)$m[1];
        return null;
    }

    private function dateOnly(?string $raw): ?string
    {
        if ($raw === null || $raw === '') return null;
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
