<?php

namespace App\Services;

use Carbon\Carbon;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Storage;

class SyncAbort extends \RuntimeException {}

class HelpScoutSync
{
    private string $hsTokenUrl = 'https://api.helpscout.net/v2/oauth2/token';
    private string $hsApi      = 'https://api.helpscout.net/v2';

    /**
     * Entry point used by WebhookController.
     * Throws on critical failures so controller can 500 (and GC retries).
     */
    public function runStrict(string $event, string $delivery, string $domain, array $body): void
    {
        $b = $this->normalize($event, $body);

        // Resolve donor email (required to find/create HS customer)
        $email = $this->firstNonEmpty([
            'account.email',
            'supporter.email',
            'billing_address.email',
            'customer.email',
            'email',
        ], $b);
        if (!$email) throw new SyncAbort('No donor email in payload');

        $token = $this->hsAccessTokenStrict();

        // Find or create HS customer
        $cust = $this->hsFindCustomerWithRetry($token, $email);
        $id   = $cust['id'] ?? 0;
        if (!$id) {
            $first = $this->firstNonEmpty(['account.first_name', 'supporter.first_name', 'billing_address.first_name'], $b);
            $last  = $this->firstNonEmpty(['account.last_name',  'supporter.last_name',  'billing_address.last_name'],  $b);
            $id    = $this->hsCreateCustomerStrict($token, $first, $last, $email);
        }
        if (!$id) throw new SyncAbort('Could not resolve or create HS customer');

        // Build & upsert exactly the fields the client wants
        $props = $this->buildClientProperties($b);
        $this->hsPatchClientPropertiesStrict($token, $id, $props);

        Log::info('HS_SYNC_OK', compact('event', 'delivery', 'email') + ['customerId' => $id]);
    }

    /* ---------------------------------------------------------------------
     | Normalization
     * --------------------------------------------------------------------*/
    private function normalize(string $event, array $b): array
    {
        // supporter_updated: lift supporter[0] into flat fields
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

        // If a recurring_profile exists, mirror key bits into line_items[0]
        if (isset($b['recurring_profile']) && is_array($b['recurring_profile'])) {
            $rp = $b['recurring_profile'];
            $b['line_items'][0]['recurring_profile'] = $rp;
            $b['line_items'][0]['recurring_amount']  = $rp['amount'] ?? ($b['line_items'][0]['recurring_amount'] ?? null);
            $b['line_items'][0]['recurring_day']     = $this->extractDayNumber($rp['billing_period_day'] ?? null);

            // Currency hint
            if (!isset($b['currency'])) {
                $b['currency'] = data_get($rp, 'currency.code') ?: data_get($rp, 'currency.iso_code');
            }

            // Payment brand/type signal
            $acctType = data_get($rp, 'payment_method.account_type') ?: data_get($rp, 'payment_method.display_name');
            if ($acctType) {
                $b['payments'][0]['type']          = 'card';
                $b['payments'][0]['status']        = ($rp['status'] ?? '') === 'Active' ? 'succeeded' : (data_get($b, 'payments.0.status') ?? null);
                $b['payments'][0]['card']['brand'] = $acctType;
            }
        }

        return $b;
    }

    /* ---------------------------------------------------------------------
     | Build the EXACT client properties (concept names → values)
     * --------------------------------------------------------------------*/
    private function buildClientProperties(array $b): array
    {
        // Name (Donor Identity)
        $first = $this->firstNonEmpty(['account.first_name','supporter.first_name','billing_address.first_name'], $b);
        $last  = $this->firstNonEmpty(['account.last_name','supporter.last_name','billing_address.last_name'], $b);
        $donorIdentity = trim(implode(' ', array_filter([$first, $last])));

        // Donor ID: account.email → account.id → vendor_contact_id
        $donorId = $this->firstNonEmpty(['account.email','account.id','vendor_contact_id'], $b);
        if (is_array($donorId) || is_object($donorId)) $donorId = null;

        // Last Donation Amount: "<amount> <currency>"
        $amount   = $this->firstNonEmpty(['total_amount','subtotal_amount','amount','line_items.0.recurring_amount'], $b);
        $currency = $this->firstNonEmpty(['currency','payments.0.currency.code','line_items.0.recurring_profile.currency.code'], $b);
        $lastDonationAmount = ($amount !== null && $currency)
            ? sprintf('%s %s', $this->money((float)$amount), $currency)
            : null;

        // Last Donation Date
        $lastDonationDate = $this->dateOnly($this->firstNonEmpty(['created_at','ordered_at'], $b));

        // Recurring Details: "$X / Monthly / 1st of Month"
        $recurringDetails = $this->buildRecurringDetails($b);

        // Sponsorship Info (+ helpful tickets) "Full Name, REF, URL"
        $li = data_get($b, 'line_items.0');
        $sName = data_get($li, 'sponsorship.full_name') ?: data_get($li, 'sponsee.full_name');
        $sRef  = data_get($li, 'sponsorship.reference_number') ?: data_get($li, 'reference');
        $sUrl  = data_get($li, 'sponsorship.url') ?: data_get($li, 'public_url');
        $sponsorshipInfo = $this->joinPretty([$sName, $sRef, $sUrl], ', ');

        // Location (single field): "Country / Province"
        $country  = $this->firstNonEmpty(['billing_address.country','billing_address.country_code','supporter.billing_address.country'], $b);
        $province = $this->firstNonEmpty(['billing_address.state','billing_address.province_code','supporter.billing_address.state'], $b);
        $location = ($country || $province) ? trim(($country ?: '') . ' / ' . ($province ?: '')) : null;

        // Payment Method normalized (Card / Visa, Wallet / Google Pay, etc.)
        $paymentMethod = $this->formatPaymentMethod($b);

        // Email + Phone
        $email = $this->firstNonEmpty([
            'account.email','supporter.email','billing_address.email','customer.email','email',
        ], $b);
        $phone = $this->firstNonEmpty(['billing_address.phone','supporter.billing_address.phone'], $b);
        $phone = $this->cleanPhone($phone);

        // GC Donor Profile (if present)
        $gcProfile = $this->firstNonEmpty(['supporter.profile_url','line_items.0.public_url'], $b);

        return [
            'donor_identity' => $donorIdentity,
            'donor_id'       => $donorId,
            'last_amt'       => $lastDonationAmount,
            'last_date'      => $lastDonationDate,
            'recur'          => $recurringDetails,
            'sponsor_help'   => $sponsorshipInfo,
            'sponsor_info'   => $sponsorshipInfo,
            'location'       => $location,
            'pay_method'     => $paymentMethod,
            'phone'          => $phone,
            'email'          => $email,
            'gc_profile'     => $gcProfile,
        ];
    }

    private function buildRecurringDetails(array $b): ?string
    {
        $li0 = data_get($b, 'line_items.0');
        if ($li0) {
            $amt    = data_get($li0, 'recurring_amount') ?? data_get($li0, 'price');
            $period = data_get($li0, 'recurring_profile.billing_period_description') ?? data_get($li0, 'variant.billing_period');
            $day    = data_get($li0, 'recurring_day') ?? data_get($li0, 'recurring_profile.billing_period_day');
            if ($day && !is_numeric($day)) $day = $this->extractDayNumber((string)$day);
            if ($amt !== null && $period && $day) {
                return sprintf('$%s / %s / %s of Month', $this->money((float)$amt), $this->humanPeriod((string)$period), $this->ordinal((int)$day));
            }
        }
        $rp = data_get($b, 'recurring_profile');
        if ($rp) {
            $amt    = data_get($rp, 'amount');
            $period = data_get($rp, 'billing_period_description') ?: data_get($rp, 'billing_period');
            $day    = $this->extractDayNumber(data_get($rp, 'billing_period_day'));
            if ($amt !== null && $period && $day) {
                return sprintf('$%s / %s / %s of Month', $this->money((float)$amt), $this->humanPeriod((string)$period), $this->ordinal((int)$day));
            }
        }
        return null;
    }

    private function formatPaymentMethod(array $b): ?string
    {
        $typeRaw = $this->firstNonEmpty(['payment_type','payments.0.type','transactions.0.type'], $b);
        $brandRaw = $this->firstNonEmpty([
            'payments.0.card.brand',
            'transactions.0.cc_type',
            'line_items.0.recurring_profile.payment_method.account_type',
            'line_items.0.recurring_profile.payment_method.display_name',
        ], $b);
        $walletRaw = $this->firstNonEmpty(['payments.0.card.wallet','transactions.0.wallet'], $b);

        $t = strtolower((string)$typeRaw);
        $type = match (true) {
            $t === 'card' => 'Card',
            $t === 'ach' || $t === 'bank' || $t === 'eft' => 'ACH',
            $t === 'wallet_pay' || $t === 'wallet' || ($walletRaw !== null) => 'Wallet',
            default => ($t ? ucfirst($t) : null),
        };

        $norm = function (?string $s): ?string {
            if (!$s) return null;
            $k = strtolower(trim($s));
            return match ($k) {
                'visa' => 'Visa',
                'master', 'mc', 'mastercard', 'master card' => 'MasterCard',
                'amex', 'american express', 'americanexpress' => 'American Express',
                'discover' => 'Discover',
                'diners', 'diners club', 'dinersclub' => 'Diners Club',
                'jcb' => 'JCB',
                'unionpay', 'china unionpay' => 'UnionPay',
                'google_pay', 'google pay' => 'Google Pay',
                'apple_pay', 'apple pay' => 'Apple Pay',
                'paypal' => 'PayPal',
                default => ucwords($k),
            };
        };

        $brand = $norm($brandRaw);
        if (($type === 'Wallet') && $walletRaw) {
            $brand = $norm($walletRaw) ?? $brand ?? 'Wallet';
        }

        $knownCardBrands = ['Visa','MasterCard','American Express','Discover','Diners Club','JCB','UnionPay'];
        if ($type && $brand) return "{$type} / {$brand}";
        if (!$type && $brand && in_array($brand, $knownCardBrands, true)) return "Card / {$brand}";
        if ($type && !$brand) return $type;
        return $brand ?: null;
    }

    /* ---------------------------------------------------------------------
     | Help Scout API (token, customer, properties)
     * --------------------------------------------------------------------*/
    private function hsAccessTokenStrict(): string
    {
        if ($cached = Cache::get('hs_access_token')) {
            Log::info('HS token: access cache HIT');
            return (string)$cached;
        }
        Log::info('HS token: access cache MISS → refreshing');

        $lock = Cache::lock('hs_token_refresh_lock', 10);
        try {
            $lock->block(10);

            if ($cached = Cache::get('hs_access_token')) {
                Log::info('HS token: access cache HIT after lock');
                return (string)$cached;
            }

            $refresh = '';
            $src = 'none';

            try {
                $path = 'hs_oauth.json';
                if (Storage::exists($path)) {
                    $j = json_decode(Storage::get($path), true) ?: [];
                    if (!empty($j['refresh_token'])) {
                        $refresh = (string)$j['refresh_token'];
                        $src = 'file';
                    }
                }
            } catch (\Throwable $e) {
                Log::warning('HS token: read file error', ['err' => $e->getMessage()]);
            }

            if ($refresh === '') {
                $rt = Cache::get('hs_refresh_file');
                if ($rt) {
                    $refresh = (string)$rt;
                    $src = 'cache';
                }
            }

            if ($refresh === '') throw new SyncAbort('Missing HS refresh token (visit /oauth/hs/start)');

            $rfHash = substr(sha1($refresh), 0, 10);
            Log::info('HS token: using refresh token', ['source' => $src, 'rf_hash' => $rfHash]);

            $resp = Http::asForm()->timeout(8)->post($this->hsTokenUrl, [
                'grant_type'    => 'refresh_token',
                'refresh_token' => $refresh,
                'client_id'     => env('HS_CLIENT_ID'),
                'client_secret' => env('HS_CLIENT_SECRET'),
            ]);

            if (!$resp->ok()) {
                Log::error('HS token: refresh FAILED', ['status' => $resp->status(), 'body' => $resp->body(), 'rf_src' => $src, 'rf_hash' => $rfHash]);
                throw new SyncAbort('HS token refresh failed: ' . $resp->status() . ' ' . $resp->body());
            }

            $data    = $resp->json();
            $access  = (string)($data['access_token'] ?? '');
            $expires = (int)($data['expires_in'] ?? 1800);
            if ($access === '') throw new SyncAbort('Empty HS access token');

            if (!empty($data['refresh_token'])) {
                $new = (string)$data['refresh_token'];
                Storage::put('hs_oauth.json', json_encode(['refresh_token' => $new, 'saved_at' => now()->toISOString()], JSON_PRETTY_PRINT));
                Cache::forever('hs_refresh_file', $new);
                Log::info('HS token: refresh token ROTATED', ['old_rf_hash' => $rfHash, 'new_rf_hash' => substr(sha1($new), 0, 10)]);
            }

            $ttl = max($expires - 60, 60);
            Cache::put('hs_access_token', $access, now()->addSeconds($ttl));
            Log::info('HS token: access token cached', ['ttl_sec' => $ttl, 'rf_src' => $src]);

            return $access;
        } finally {
            optional($lock)->release();
        }
    }

    private function hsFindCustomer(string $token, string $email): ?array
    {
        $r1 = Http::withToken($token)->timeout(8)->get("{$this->hsApi}/customers", ['email' => $email, 'page' => 1]);
        if ($r1->ok()) {
            $hit = data_get($r1->json(), '_embedded.customers.0');
            if ($hit) return $hit;
        }

        $q  = '(email:"' . addslashes($email) . '")';
        $r2 = Http::withToken($token)->timeout(8)->get("{$this->hsApi}/customers", ['query' => $q, 'page' => 1]);
        if ($r2->ok()) {
            $hit = data_get($r2->json(), '_embedded.customers.0');
            if ($hit) return $hit;
        }

        Log::warning('HS find failed', ['email' => $email, 's1' => $r1->status(), 's2' => $r2->status(), 'b2' => $r2->body()]);
        return null;
    }

    private function hsFindCustomerWithRetry(string $token, string $email, int $attempts = 4, int $baseMs = 200): ?array
    {
        for ($i = 1; $i <= $attempts; $i++) {
            $hit = $this->hsFindCustomer($token, $email);
            if ($hit) return $hit;
            usleep(($baseMs * $i + random_int(0, 60)) * 1000);
        }
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

        if ($r->status() === 201) {
            $rid = (string)($r->header('Resource-ID') ?? '');
            if ($rid !== '' && ctype_digit($rid)) {
                Log::info('HS create: 201 with Resource-ID', ['id' => (int)$rid]);
                return (int)$rid;
            }
            $loc = (string)($r->header('Location') ?? '');
            if ($loc && preg_match('~/customers/(\d+)~', $loc, $m)) {
                Log::info('HS create: 201, parsed id from Location', ['id' => (int)$m[1]]);
                return (int)$m[1];
            }
            Log::warning('HS create: 201 but no id header', ['headers' => $r->headers()]);
            throw new SyncAbort('HS create returned 201 but no id header');
        }

        if ($r->status() === 409) {
            $existing = $this->hsFindCustomerWithRetry($token, $email);
            if ($existing && isset($existing['id'])) {
                Log::info('HS create: 409 conflict → using existing id (after retry)', ['id' => (int)$existing['id']]);
                return (int)$existing['id'];
            }
            throw new SyncAbort('HS create conflict but could not fetch existing');
        }

        Log::warning('HS create failed', ['status' => $r->status(), 'body' => substr($r->body(), 300)]);
        throw new SyncAbort('HS create failed: ' . $r->status() . ' ' . $r->body());
    }

    /**
     * Upserts ONLY the client’s properties.
     * Always writes every property; sends "" to clear if missing.
     */
    private function hsPatchClientPropertiesStrict(string $token, int $customerId, array $kv): void
    {
        // Required property slugs with display names and types
        $need = [
            'donor-identity'                  => ['Name',                             'text'],
            'donor-id'                        => ['Donor ID',                         'text'],
            'last-donation-amount'            => ['Last Donation Amount',             'text'],
            'last-donation-date'              => ['Last Donation Date',               'date'],
            'recurring-details'               => ['Recurring Details',                'text'],
            'helpful-for-sponsorship-tickets' => ['Helpful for sponsorship tickets',  'text'],
            'sponsorship-info'                => ['Sponsorship Info',                 'text'],
            'location'                        => ['Location',                         'text'],
            'payment-method'                  => ['Payment Method',                   'text'],
            'phone-no'                        => ['Phone No',                         'text'],
            'email-address'                   => ['Email',                            'text'],
            'gc-donor-profile'                => ['GC Donor Profile',                 'url'],
        ];

        // Fetch existing slugs
        $r = Http::withToken($token)->timeout(8)->get("{$this->hsApi}/customer-properties");
        if (!$r->ok()) throw new SyncAbort('HS properties list failed: '.$r->status().' '.$r->body());

        $existing = collect(data_get($r->json(), '_embedded.customer-properties', []))
            ->pluck('slug')->all();

        // Create any missing
        foreach ($need as $slug => [$name, $type]) {
            if (in_array($slug, $existing, true)) continue;
            $resp = Http::withToken($token)->acceptJson()->asJson()->timeout(10)
                ->post("{$this->hsApi}/customer-properties", ['type'=>$type, 'slug'=>$slug, 'name'=>$name]);
            if ($resp->created()) {
                Log::info('HS property created', ['slug'=>$slug, 'type'=>$type]);
                $existing[] = $slug;
            } else {
                Log::warning('HS property create failed', ['slug'=>$slug, 'status'=>$resp->status(), 'body'=>substr($resp->body(), 200)]);
            }
        }

        // Concept → slug mapping
        $slugMap = [
            'donor_identity' => 'donor-identity',
            'donor_id'       => 'donor-id',
            'last_amt'       => 'last-donation-amount',
            'last_date'      => 'last-donation-date',
            'recur'          => 'recurring-details',
            'sponsor_help'   => 'helpful-for-sponsorship-tickets',
            'sponsor_info'   => 'sponsorship-info',
            'location'       => 'location',
            'pay_method'     => 'payment-method',
            'phone'          => 'phone-no',
            'email'          => 'email-address',
            'gc_profile'     => 'gc-donor-profile',
        ];

        // Build JSON Patch ops for ALL target properties (clear with "")
        $ops = [];
        foreach ($slugMap as $concept => $slug) {
            if (!in_array($slug, $existing, true)) continue; // safety
            $val = $kv[$concept] ?? null;

            // date formatting
            if ($slug === 'last-donation-date') {
                $val = $this->dateOnly($val);
            }

            // ALWAYS send a value ("" clears)
            $ops[] = ['op' => 'replace', 'path' => '/'.$slug, 'value' => ($val === null ? '' : $val)];
        }

        $r2 = Http::withToken($token)->acceptJson()->asJson()->timeout(10)
            ->patch("{$this->hsApi}/customers/{$customerId}/properties", $ops);

        if (!in_array($r2->status(), [200, 204], true)) {
            throw new SyncAbort('HS client properties failed: '.$r2->status().' '.substr($r2->body(), 250));
        }

        Log::info('HS client props: PATCH OK', ['status' => $r2->status(), 'ops' => count($ops)]);
    }

    /* ---------------------------------------------------------------------
     | Utilities
     * --------------------------------------------------------------------*/
    private function firstNonEmpty(array $paths, array $source): mixed
    {
        foreach ($paths as $p) {
            $v = data_get($source, $p);
            if ($v !== null && $v !== '') return $v;
        }
        return null;
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

    private function humanPeriod(string $raw): string
    {
        $raw = strtolower(trim($raw));
        return match ($raw) {
            'month', 'monthly'                   => 'Monthly',
            'year', 'yearly', 'annually'         => 'Yearly',
            'week', 'weekly'                     => 'Weekly',
            default                              => ucfirst($raw),
        };
    }

    private function joinPretty(array $parts, string $sep): ?string
    {
        $p = array_values(array_filter($parts, fn($v) => $v !== null && $v !== ''));
        return $p ? implode($sep, $p) : null;
    }

    private function cleanPhone(?string $raw): ?string
    {
        if (!$raw) return null;
        $d = preg_replace('/\D+/', '', $raw);
        return $d !== '' ? $d : null;
    }
}
