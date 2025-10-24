<?php

namespace App\Jobs;

use Carbon\Carbon;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue; // fine to keep, we call handle() inline
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class ProcessGivecloudEvent implements ShouldQueue
{
    use Dispatchable, Queueable, InteractsWithQueue, SerializesModels;

    public int $tries = 2;
    public int $timeout = 20;

    private string $hsTokenUrl = 'https://api.helpscout.net/v2/oauth2/token';
    private string $hsApi      = 'https://api.helpscout.net/v2';

    public function __construct(
        public string $event,
        public string $delivery,
        public string $domain,
        public array $payload
    ) {}

    public function handle(): void
    {
        // Ensure we never re-run the same delivery
        $lockKey = "gc:executed:{$this->delivery}";
        if (!Cache::add($lockKey, 1, now()->addMinutes(10))) {
            return;
        }

        $b = $this->payload;

        // --- email required for HS upsert ---
        $email = $this->firstNonEmpty([
            'email',
            'supporter.email',
            'billing_address.email',
            'account.email',
            'customer.email',
        ], $b);
        if (!$email) {
            Log::warning('GC: no email in payload', ['event' => $this->event, 'delivery' => $this->delivery]);
            return;
        }

        // Token
        $token = $this->hsAccessToken();

        // Find or create customer
        $customer = $this->hsFindCustomer($token, $email);
        $id = $customer['id'] ?? 0;

        if (!$id) {
            $first = $this->firstNonEmpty(['supporter.first_name','billing_address.first_name'], $b);
            $last  = $this->firstNonEmpty(['supporter.last_name', 'billing_address.last_name'], $b);
            $id    = $this->hsCreateCustomer($token, $first, $last, $email);
        }
        if (!$id) {
            Log::error('GC: unable to resolve HS customer id', ['email' => $email, 'event' => $this->event]);
            return;
        }

        // --- core fields (name, emails, phones, addresses) ---
        $this->hsUpdateCore($token, $id, $b);

        // --- custom properties ---
        $props = $this->buildProperties($b);
        $this->hsPatchProperties($token, $id, $props);

        Log::info('HS_SYNC_OK', [
            'delivery'   => $this->delivery,
            'event'      => $this->event,
            'email'      => $email,
            'customerId' => $id
        ]);
    }

    /* =========================
     *  Build properties (all required by you)
     * ========================= */

    private function buildProperties(array $b): array
    {
        // donor id
        $donorId = $this->firstNonEmpty(['supporter.id', 'supporter.id_deprecated', 'account.id', 'vendor_contact_id'], $b);

        // location + address
        $country = $this->firstNonEmpty(['billing_address.country_code','billing_address.country','supporter.billing_address.country'], $b);
        $state   = $this->firstNonEmpty(['billing_address.province_code','billing_address.state','supporter.billing_address.state'], $b);
        $addr1   = $this->firstNonEmpty(['billing_address.address1'], $b);
        $city    = $this->firstNonEmpty(['billing_address.city'], $b);
        $postal  = $this->firstNonEmpty(['billing_address.zip'], $b);
        $phone   = $this->digits($this->firstNonEmpty(['billing_address.phone','supporter.billing_address.phone'], $b));

        // profile URL
        $profile = $this->firstNonEmpty(['supporter.profile_url', 'line_items.0.public_url'], $b);

        // dates
        $orderedAt = $this->firstNonEmpty(['ordered_at','created_at'], $b);
        $lastDate  = $this->dateOnly($orderedAt);
        $donorSince = $this->dateOnly($this->firstNonEmpty(['supporter.created_at'], $b));

        // amount + currency
        $amount   = $this->firstNonEmpty(['total_amount','subtotal_amount','amount'], $b);
        $currency = $this->firstNonEmpty(['currency','payments.0.currency.code'], $b);
        $lastDonationAmount = ($amount !== null && $currency)
            ? sprintf('%s %s', $this->money((float)$amount), $currency)
            : null;

        // payment
        $payBrand  = $this->firstNonEmpty(['payments.0.card.brand','payments.0.type','payment_type'], $b);
        $isPaid    = $this->firstNonEmpty(['payments.0.status'], $b) === 'succeeded' || ($this->firstNonEmpty(['is_paid'], $b) === true);
        $payStatus = $isPaid ? 'paid' : null;

        // lifetime
        $lifetime = $this->firstNonEmpty(['supporter.lifetime_donation_amount'], $b);

        // recurring summary
        $recurring = $this->buildRecurringSummary($b);

        // sponsorship
        $sp = $this->buildSponsorship($b);

        return array_filter([
            'donor_id'             => is_numeric($donorId) ? (int)$donorId : null,
            'donor_since'          => $donorSince,
            'last_donation_date'   => $lastDate,
            'last_donation_amount' => $lastDonationAmount,
            'payment_status'       => $payStatus,
            'payment_method'       => $payBrand,
            'recurring_summary'    => $recurring,
            'lifetime_donation'    => is_numeric($lifetime) ? (float)$lifetime : null,
            'donor_profile_url'    => $profile,
            'country'              => $country,
            'province'             => $state,
            'phone'                => $phone,
            'billing_address1'     => $addr1,
            'billing_city'         => $city,
            'billing_postal'       => $postal,
            'sponsorship_name'     => $sp['name'] ?? null,
            'sponsorship_ref'      => $sp['ref'] ?? null,
            'sponsorship_url'      => $sp['url'] ?? null,
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

    /* =========================
     *  Help Scout API helpers
     * ========================= */

    private function hsAccessToken(): string
    {
        return Cache::remember('hs_access_token', now()->addMinutes(30), function () {
            $refresh = (string) (env('HS_REFRESH_TOKEN') ?? '');
            if ($saved = Cache::get('hs_refresh_file')) {
                $refresh = $saved;
            }
            abort_unless($refresh !== '', 500, 'No Help Scout refresh token.');

            $resp = Http::asForm()->timeout(8)->post($this->hsTokenUrl, [
                'grant_type'    => 'refresh_token',
                'refresh_token' => $refresh,
                'client_id'     => env('HS_CLIENT_ID'),
                'client_secret' => env('HS_CLIENT_SECRET'),
            ]);
            if (!$resp->ok()) {
                throw new \RuntimeException('HS refresh failed: '.$resp->body());
            }
            $data = $resp->json();
            if (!empty($data['refresh_token'])) {
                Cache::forever('hs_refresh_file', (string)$data['refresh_token']);
            }
            return (string) $data['access_token'];
        });
    }

    private function hsFindCustomer(string $token, string $email): ?array
    {
        // Primary: direct filter (fast, plan-agnostic)
        $r = Http::withToken($token)->timeout(6)->get("{$this->hsApi}/customers", [
            'email' => $email,
            'page'  => 1,
        ]);
        if ($r->ok()) {
            $hit = data_get($r->json(), '_embedded.customers.0');
            if ($hit) return $hit;
        }

        // Fallback: HS DSL (if enabled)
        $r2 = Http::withToken($token)->timeout(6)->get("{$this->hsApi}/customers", [
            'query' => '(email:"'.$email.'")',
            'page'  => 1,
        ]);
        if ($r2->ok()) {
            $hit = data_get($r2->json(), '_embedded.customers.0');
            if ($hit) return $hit;
        }

        Log::warning('HS find failed', ['email' => $email, 's1' => $r->status(), 's2' => $r2->status()]);
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
            // Already exists → fetch it
            $existing = $this->hsFindCustomer($token, $email);
            if ($existing && isset($existing['id'])) {
                return (int) $existing['id'];
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
        $first = $this->firstNonEmpty(['supporter.first_name','billing_address.first_name'], $b);
        $last  = $this->firstNonEmpty(['supporter.last_name','billing_address.last_name'], $b);
        $email = $this->firstNonEmpty(['email','supporter.email','billing_address.email'], $b);

        $addr1 = $this->firstNonEmpty(['billing_address.address1'], $b);
        $city  = $this->firstNonEmpty(['billing_address.city'], $b);
        $state = $this->firstNonEmpty(['billing_address.province_code','billing_address.state'], $b);
        $zip   = $this->firstNonEmpty(['billing_address.zip'], $b);
        $ctry  = $this->firstNonEmpty(['billing_address.country_code','billing_address.country'], $b);
        $phone = $this->digits($this->firstNonEmpty(['billing_address.phone','supporter.billing_address.phone'], $b));
        $site  = $this->firstNonEmpty(['supporter.profile_url','line_items.0.public_url'], $b);

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
            Log::warning('HS core update failed (non-fatal)', ['status' => $r->status(), 'body' => $r->body(), 'pay' => $payload]);
        }
    }

    private function hsPropertySlugs(string $token): array
    {
        // Optional prefill (comma-separated) to skip API hit
        $prefill = (string) env('HS_KNOWN_SLUGS', '');
        if ($prefill !== '') {
            return collect(explode(',', $prefill))->map(fn($s)=>trim($s))->filter()->values()->all();
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
        // Concept → HS slugs (create these custom properties once in HS admin)
        $slugMap = [
            // Identity & donation meta
            'donor_id'             => 'donor-id',
            'donor_since'          => 'donor-since',           // date
            'lifetime_donation'    => 'lifetime-donation',     // number
            'donor_profile_url'    => 'gc-donor-profile',      // url/text

            // Last donation info
            'last_donation_date'   => 'last-order',            // date
            'last_donation_amount' => 'last-donation-amount',  // text

            // Payment
            'payment_status'       => 'payment-status',        // text
            'payment_method'       => 'payment-method',        // text

            // Recurring & sponsorship
            'recurring_summary'    => 'recurring-summary',     // text ($35 / Monthly / 1st)
            'sponsorship_name'     => 'sponsorship-name',      // text
            'sponsorship_ref'      => 'sponsorship-ref',       // text
            'sponsorship_url'      => 'sponsorship-url',       // url/text

            // Location & contact
            'country'              => 'country',               // text
            'province'             => 'state',                 // text
            'phone'                => 'phone-no',              // number
            'billing_address1'     => 'billing-address1',      // text
            'billing_city'         => 'billing-city',          // text
            'billing_postal'       => 'billing-postal',        // text
        ];

        $numericSlugs = ['donor-id','lifetime-donation','phone-no'];
        $existing     = $this->hsPropertySlugs($token);

        // Soft warn once per request if some slugs don’t exist
        $missing = [];
        foreach ($kv as $concept => $_) {
            $slug = $slugMap[$concept] ?? null;
            if ($slug && !in_array($slug, $existing, true)) $missing[] = $slug;
        }
        if ($missing) {
            Log::warning('HS missing custom properties (create these slugs)', array_values(array_unique($missing)));
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
                $val = $this->dateOnly((string)$val);
            }

            $ops[] = ['op' => 'replace', 'path' => '/'.$slug, 'value' => $val];
        }

        if (!$ops) return;

        $r = Http::withToken($token)->acceptJson()->asJson()->timeout(8)
            ->patch("{$this->hsApi}/customers/{$customerId}/properties", $ops);

        if (!in_array($r->status(), [200, 204], true)) {
            Log::error('HS properties failed', ['status' => $r->status(), 'body' => $r->body(), 'ops' => $ops]);
        }
    }

    /* =========================
     *  Small utils
     * ========================= */

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
        try { return Carbon::parse($raw)->toDateString(); }
        catch (\Throwable $e) { return substr((string)$raw, 0, 10); }
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
}
