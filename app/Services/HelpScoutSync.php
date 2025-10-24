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
     * Entry point called by WebhookController.
     * Only writes the 7 merged properties your client asked for.
     */
    public function runStrict(string $event, string $delivery, string $domain, array $body): void
    {
        $b = $this->normalize($event, $body);

        // Resolve donor email (we still need it to look up/create contact)
        $email = $this->firstNonEmpty([
            'account.email',
            'supporter.email',
            'billing_address.email',
            'customer.email',
            'email',
        ], $b);
        if (!$email) throw new SyncAbort('No donor email in payload');

        $token = $this->hsAccessTokenStrict();

        // Find or create the HS customer
        $cust = $this->hsFindCustomerWithRetry($token, $email);
        $id   = $cust['id'] ?? 0;
        if (!$id) {
            $first = $this->firstNonEmpty(['account.first_name','supporter.first_name','billing_address.first_name'], $b);
            $last  = $this->firstNonEmpty(['account.last_name','supporter.last_name','billing_address.last_name'], $b);
            $id    = $this->hsCreateCustomerStrict($token, $first, $last, $email);
        }
        if (!$id) throw new SyncAbort('Could not resolve or create HS customer');

        // Build merged properties as single strings
        $props = $this->buildMergedProperties($b);

        // Upsert those 7 properties only
        $this->hsPatchMergedPropertiesStrict($token, $id, $props);

        Log::info('HS_SYNC_OK_MIN', compact('event','delivery','email') + ['customerId'=>$id]);
    }

    /* ───────────────────────────────────────────────────────────
     * Normalization across GC payload shapes
     * ─────────────────────────────────────────────────────────── */
    private function normalize(string $event, array $b): array
    {
        // If supporters[] present, surface as supporter and bridged bits
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

        // Bridge recurring profile into a line_items[0] shape if present
        if (isset($b['recurring_profile']) && is_array($b['recurring_profile'])) {
            $rp = $b['recurring_profile'];
            if (!isset($b['line_items'][0])) $b['line_items'][0] = [];
            $b['line_items'][0]['recurring_profile'] = $rp;
            $b['line_items'][0]['recurring_amount']  = $rp['amount'] ?? ($b['line_items'][0]['recurring_amount'] ?? null);
            $b['line_items'][0]['recurring_day']     = $this->extractDayNumber($rp['billing_period_day'] ?? null);

            // Fill currency if missing
            if (!isset($b['currency'])) {
                $b['currency'] = data_get($rp, 'currency.code') ?: data_get($rp, 'currency.iso_code');
            }

            // Payment brand hint
            $acctType = data_get($rp, 'payment_method.account_type') ?: data_get($rp, 'payment_method.display_name');
            if ($acctType) {
                $b['payments'][0]['type']           = 'card';
                $b['payments'][0]['status']         = ($rp['status'] ?? '') === 'Active' ? 'succeeded' : (data_get($b,'payments.0.status') ?? null);
                $b['payments'][0]['card']['brand']  = $acctType;
            }
        }

        return $b;
    }

    /* ───────────────────────────────────────────────────────────
     * Build ONLY the merged fields client requested
     * ─────────────────────────────────────────────────────────── */
    private function buildMergedProperties(array $b): array
    {
        // Donor Identity: First + Last (prefer account.*, fallback to supporter/billing)
        $first = $this->firstNonEmpty(['account.first_name','supporter.first_name','billing_address.first_name'], $b);
        $last  = $this->firstNonEmpty(['account.last_name','supporter.last_name','billing_address.last_name'], $b);
        $donorIdentity = trim(implode(' ', array_filter([$first, $last])));

        // Donor ID (single value): email > account.id > vendor_contact_id
        $donorId = $this->firstNonEmpty(['account.email','account.id','vendor_contact_id'], $b);
        if (is_array($donorId) || is_object($donorId)) $donorId = null; // safety

        // Last Donation Info: "<amount> <currency> — <date>"
        $amount   = $this->firstNonEmpty(['total_amount','subtotal_amount','amount','line_items.0.recurring_amount'], $b);
        $currency = $this->firstNonEmpty(['currency','payments.0.currency.code','line_items.0.recurring_profile.currency.code'], $b);
        $dateRaw  = $this->firstNonEmpty(['created_at','ordered_at'], $b);
        $date     = $this->dateOnly($dateRaw);
        $amtStr   = ($amount !== null && $currency) ? sprintf('%s %s', $this->money((float)$amount), $currency) : null;
        $lastDonationInfo = $this->joinPretty([$amtStr, $date], ' — ');

        // Recurring Details: "$X / Monthly / 1st of Month"
        $recurring = $this->buildRecurringDetails($b);

        // Sponsorship Info: "Full Name, REF, URL"
        $s = $this->buildSponsorship($b);
        $sponsorshipInfo = $this->joinPretty([$s['name'] ?? null, $s['ref'] ?? null, $s['url'] ?? null], ', ');

        // Location: "Country / Province"
        $country = $this->firstNonEmpty(['billing_address.country','billing_address.country_code','supporter.billing_address.country'], $b);
        $state   = $this->firstNonEmpty(['billing_address.state','billing_address.province_code','supporter.billing_address.state'], $b);
        $location = $this->joinPretty([$country, $state], ' / ');

        // Payment Type (brand): payments[0].card.brand OR transactions[0].cc_type
        $payType = $this->firstNonEmpty(['payments.0.card.brand','transactions.0.cc_type','payment_type','line_items.0.recurring_profile.payment_method.account_type'], $b);

        return array_filter([
            'donor_identity'   => $donorIdentity ?: null,
            'donor_id'         => $donorId ?: null,
            'last_donation'    => $lastDonationInfo ?: null,
            'recurring_details'=> $recurring ?: null,
            'sponsorship_info' => $sponsorshipInfo ?: null,
            'location'         => $location ?: null,
            'payment_type'     => $payType ?: null,
        ], fn($v) => $v !== null && $v !== '');
    }

    private function buildRecurringDetails(array $b): ?string
    {
        // Prefer embedded line_items[0] view (covers most GC payloads)
        $li0 = data_get($b, 'line_items.0');
        if ($li0) {
            $amt    = data_get($li0, 'recurring_amount') ?? data_get($li0, 'price');
            $period = data_get($li0, 'recurring_profile.billing_period_description') ?? data_get($li0, 'variant.billing_period');
            $day    = data_get($li0, 'recurring_day') ?? data_get($li0, 'recurring_profile.billing_period_day');
            if ($day && !is_numeric($day)) $day = $this->extractDayNumber((string)$day);

            if ($amt !== null && $period && $day) {
                return sprintf('$%s / %s / %s of Month', $this->money((float)$amt), $this->humanPeriod($period), $this->ordinal((int)$day));
            }
        }

        // Fallback to top-level recurring_profile (if any)
        $rp = data_get($b, 'recurring_profile');
        if ($rp) {
            $amt    = data_get($rp, 'amount');
            $period = data_get($rp, 'billing_period_description') ?: data_get($rp, 'billing_period');
            $day    = $this->extractDayNumber(data_get($rp, 'billing_period_day'));
            if ($amt !== null && $period && $day) {
                return sprintf('$%s / %s / %s of Month', $this->money((float)$amt), $this->humanPeriod($period), $this->ordinal((int)$day));
            }
        }

        return null;
    }

    private function buildSponsorship(array $b): array
    {
        $li = data_get($b, 'line_items.0');
        return [
            'name' => data_get($li, 'sponsee.full_name') ?: null,
            'ref'  => data_get($li, 'reference') ?: data_get($li, 'reference_number') ?: null,
            'url'  => data_get($li, 'public_url') ?: null,
        ];
    }

    /* ───────────────────────────────────────────────────────────
     * Help Scout API bits (token, customer lookup/create, props)
     * ─────────────────────────────────────────────────────────── */

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

            // Read refresh token (file → cache fallback)
            $refresh = '';
            $src = 'none';
            $path = 'hs_oauth.json';
            if (Storage::exists($path)) {
                $j = json_decode(Storage::get($path), true) ?: [];
                if (!empty($j['refresh_token'])) { $refresh = (string)$j['refresh_token']; $src = 'file'; }
            }
            if ($refresh === '') {
                $rt = Cache::get('hs_refresh_file');
                if ($rt) { $refresh = (string)$rt; $src = 'cache'; }
            }
            if ($refresh === '') throw new SyncAbort('Missing HS refresh token (visit /oauth/hs/start)');

            $rfHash = substr(sha1($refresh), 0, 10);
            Log::info('HS token: using refresh token', ['source'=>$src,'rf_hash'=>$rfHash]);

            $resp = Http::asForm()->timeout(8)->post($this->hsTokenUrl, [
                'grant_type'    => 'refresh_token',
                'refresh_token' => $refresh,
                'client_id'     => env('HS_CLIENT_ID'),
                'client_secret' => env('HS_CLIENT_SECRET'),
            ]);

            if (!$resp->ok()) {
                Log::error('HS token: refresh FAILED', ['status'=>$resp->status(),'body'=>$resp->body(),'rf_src'=>$src,'rf_hash'=>$rfHash]);
                throw new SyncAbort('HS token refresh failed: '.$resp->status().' '.$resp->body());
            }

            $data    = $resp->json();
            $access  = (string)($data['access_token'] ?? '');
            $expires = (int)($data['expires_in'] ?? 1800);
            if ($access === '') throw new SyncAbort('Empty HS access token');

            if (!empty($data['refresh_token'])) {
                $new = (string)$data['refresh_token'];
                Storage::put('hs_oauth.json', json_encode(['refresh_token'=>$new,'saved_at'=>now()->toISOString()], JSON_PRETTY_PRINT));
                Cache::forever('hs_refresh_file', $new);
                Log::info('HS token: refresh token ROTATED', ['old_rf_hash'=>$rfHash,'new_rf_hash'=>substr(sha1($new),0,10)]);
            }

            $ttl = max($expires - 60, 60);
            Cache::put('hs_access_token', $access, now()->addSeconds($ttl));
            Log::info('HS token: access token cached', ['ttl_sec'=>$ttl,'rf_src'=>$src]);

            return $access;
        } finally {
            optional($lock)->release();
        }
    }

    private function hsFindCustomer(string $token, string $email): ?array
    {
        // 1) direct email query
        $r1 = Http::withToken($token)->timeout(8)->get("{$this->hsApi}/customers", ['email'=>$email,'page'=>1]);
        if ($r1->ok()) {
            $hit = data_get($r1->json(), '_embedded.customers.0');
            if ($hit) return $hit;
        }

        // 2) DSL (their search supports query= for customers)
        $q  = '(email:"' . addslashes($email) . '")';
        $r2 = Http::withToken($token)->timeout(8)->get("{$this->hsApi}/customers", ['query'=>$q, 'page'=>1]);
        if ($r2->ok()) {
            $hit = data_get($r2->json(), '_embedded.customers.0');
            if ($hit) return $hit;
        }

        Log::warning('HS find failed', ['email'=>$email, 's1'=>$r1->status(), 's2'=>$r2->status(), 'b2'=>$r2->body()]);
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
                Log::info('HS create: 201 with Resource-ID', ['id'=>(int)$rid]);
                return (int)$rid;
            }
            $loc = (string)($r->header('Location') ?? '');
            if ($loc && preg_match('~/customers/(\d+)~', $loc, $m)) {
                Log::info('HS create: 201, parsed id from Location', ['id'=>(int)$m[1]]);
                return (int)$m[1];
            }
            Log::warning('HS create: 201 but no id header', ['headers'=>$r->headers()]);
            throw new SyncAbort('HS create returned 201 but no id header');
        }

        if ($r->status() === 409) { // exists
            $existing = $this->hsFindCustomerWithRetry($token, $email);
            if ($existing && isset($existing['id'])) {
                Log::info('HS create: 409 conflict → using existing id (after retry)', ['id'=>(int)$existing['id']]);
                return (int)$existing['id'];
            }
            throw new SyncAbort('HS create conflict but could not fetch existing');
        }

        Log::warning('HS create failed', ['status'=>$r->status(), 'body'=>substr($r->body(), 300)]);
        throw new SyncAbort('HS create failed: '.$r->status().' '.$r->body());
    }

    /**
     * Ensure the 7 merged slugs exist, then patch them.
     */
    private function hsPatchMergedPropertiesStrict(string $token, int $customerId, array $kv): void
    {
        $needSlugs = [
            'donor-identity','donor-id','last-donation-info',
            'recurring-details','sponsorship-info','location','payment-type',
        ];

        // Fetch existing slugs
        $r = Http::withToken($token)->timeout(8)->get("{$this->hsApi}/customer-properties");
        if (!$r->ok()) throw new SyncAbort('HS properties list failed: '.$r->status().' '.$r->body());

        $existing = collect(data_get($r->json(), '_embedded.customer-properties', []))
            ->pluck('slug')->all();

        // Create missing as text
        $missing = array_values(array_diff($needSlugs, $existing));
        foreach ($missing as $slug) {
            $name = ucwords(str_replace(['-', '_'], ' ', $slug));
            $resp = Http::withToken($token)->acceptJson()->asJson()->timeout(10)
                ->post("{$this->hsApi}/customer-properties", [
                    'type' => 'text',
                    'slug' => $slug,
                    'name' => $name,
                ]);
            if ($resp->created()) {
                Log::info('HS property created', ['slug'=>$slug,'type'=>'text']);
            } else {
                Log::warning('HS property create failed', ['slug'=>$slug,'status'=>$resp->status(),'body'=>substr($resp->body(),200)]);
            }
        }

        // Map our 7 concepts to slugs
        $slugMap = [
            'donor_identity'    => 'donor-identity',
            'donor_id'          => 'donor-id',
            'last_donation'     => 'last-donation-info',
            'recurring_details' => 'recurring-details',
            'sponsorship_info'  => 'sponsorship-info',
            'location'          => 'location',
            'payment_type'      => 'payment-type',
        ];

        $ops = [];
        foreach ($kv as $concept => $val) {
            if ($val === null || $val === '') continue;
            $slug = $slugMap[$concept] ?? null;
            if (!$slug) continue;
            $ops[] = ['op'=>'replace', 'path'=>'/'.$slug, 'value'=>$val];
        }

        if (!$ops) { Log::info('HS merged properties no-op', ['customerId'=>$customerId]); return; }

        // PATCH (array of operations)
        $r2 = Http::withToken($token)->acceptJson()->asJson()->timeout(10)
            ->patch("{$this->hsApi}/customers/{$customerId}/properties", $ops);

        if (!in_array($r2->status(), [200,204], true)) {
            throw new SyncAbort('HS merged properties failed: '.$r2->status().' '.substr($r2->body(),250));
        }

        Log::info('HS merged props: PATCH OK', ['status'=>$r2->status(),'ops'=>count($ops)]);
    }

    /* ───────────────────────────────────────────────────────────
     * Utils
     * ─────────────────────────────────────────────────────────── */
    private function firstNonEmpty(array $paths, array $source): mixed
    {
        foreach ($paths as $p) {
            $v = data_get($source, $p);
            if ($v !== null && $v !== '') return $v;
        }
        return null;
    }

    private function dateOnly(?string $raw): ?string
    {
        if ($raw === null || $raw === '') return null;
        try { return Carbon::parse($raw)->toDateString(); }
        catch (\Throwable $e) { return substr((string)$raw, 0, 10); }
    }

    private function extractDayNumber($raw): ?int
    {
        if ($raw === null || $raw === '') return null;
        if (is_numeric($raw)) return (int)$raw;
        if (is_string($raw) && preg_match('/(\d{1,2})/', $raw, $m)) return (int)$m[1];
        return null;
    }

    private function money(float $n): string
    {
        $s = number_format($n, 2, '.', '');
        return rtrim(rtrim($s, '0'), '.');
    }

    private function ordinal(int $n): string
    {
        if (in_array($n % 100, [11,12,13], true)) return $n.'th';
        return $n . ([1=>'st',2=>'nd',3=>'rd'][$n%10] ?? 'th');
    }

    private function humanPeriod(string $raw): string
    {
        $raw = strtolower(trim($raw));
        return match ($raw) {
            'month', 'monthly'   => 'Monthly',
            'year', 'yearly', 'annually' => 'Yearly',
            'week', 'weekly'     => 'Weekly',
            default               => ucfirst($raw),
        };
    }

    private function joinPretty(array $parts, string $sep): ?string
    {
        $p = array_values(array_filter($parts, fn($v)=>$v!==null && $v!==''));
        return $p ? implode($sep, $p) : null;
    }
}
