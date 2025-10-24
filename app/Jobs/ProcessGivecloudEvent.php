<?php

namespace App\Jobs;

use Carbon\Carbon;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\Middleware\WithoutOverlapping;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Foundation\Bus\Dispatchable;

class ProcessGivecloudEvent implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    public int $tries = 3;
    public int $timeout = 20; // seconds

    public function __construct(
        public string $event,
        public string $delivery,
        public string $domain,
        public array $payload
    ) {}

    public function middleware()
    {
        // Extra safety (per-job lock). Keyed by delivery.
        return [ new WithoutOverlapping("gc-lock:{$this->delivery}") ];
    }

    public function handle(): void
    {
        $lockKey = "gc:executed:{$this->delivery}";
        if (!Cache::add($lockKey, 1, now()->addMinutes(10))) {
            // Another path already finished this delivery
            return;
        }

        $b = $this->payload;
        $email = $this->extractEmail($b);
        if (!$email) {
            Log::warning('GC: no email in payload', ['event' => $this->event, 'delivery' => $this->delivery]);
            return;
        }

        $token = $this->hsAccessToken();

        // 1) Find or create customer in Help Scout
        $customer = $this->hsFindCustomer($token, $email);
        $id = $customer['id'] ?? 0;

        // Create if needed (handle 409 gracefully)
        if (!$id) {
            $first = $this->val($b, ['supporter.first_name','billing_address.first_name']);
            $last  = $this->val($b, ['supporter.last_name','billing_address.last_name']);
            $id = $this->hsCreateCustomer($token, $first, $last, $email);
        }
        if (!$id) {
            Log::error('GC: unable to resolve HS customer id', ['email' => $email, 'event' => $this->event]);
            return;
        }

        // 2) Build desired properties
        $props = $this->buildProperties($b);

        // 3) Patch custom properties (only slugs that actually exist)
        $this->hsPatchProperties($token, $id, $props);

        // 4) Done
        Log::info('HS_SYNC_OK', ['delivery' => $this->delivery, 'event' => $this->event, 'email' => $email, 'customerId' => $id]);
    }

    /* =========================
     *   Extractors
     * ========================= */

    private function extractEmail(array $b): ?string
    {
        return $this->val($b, [
            'email',
            'supporter.email',
            'billing_address.email',
            'account.email',
            'customer.email'
        ]);
    }

    private function val(array $a, array $paths, $default = null)
    {
        foreach ($paths as $p) {
            $v = data_get($a, $p);
            if ($v !== null && $v !== '') return $v;
        }
        return $default;
    }

    private function parseDate(?string $raw): ?string
    {
        if (!$raw) return null;
        try { return Carbon::parse($raw)->toDateString(); }
        catch (\Throwable $e) { return substr((string)$raw, 0, 10); }
    }

    private function digits(?string $raw): ?int
    {
        if (!$raw) return null;
        $d = preg_replace('/\D+/', '', $raw);
        return $d !== '' ? (int)$d : null;
    }

    private function buildRecurringSummary(array $b): ?string
    {
        $li = data_get($b, 'line_items.0'); // first item
        if (!$li) return null;

        $amt = data_get($li, 'recurring_amount') ?? data_get($li, 'price') ?? null;
        $period = data_get($li, 'recurring_profile.billing_period_description') // "Monthly"
               ?? data_get($li, 'variant.billing_period')
               ?? null;
        $day = data_get($li, 'recurring_day'); // 1..31
        if ($amt === null || !$period || !$day) return null;

        // Render like "$250 / Monthly / 23rd"
        $daySuffix = $this->ordinal((int)$day);
        return sprintf('$%s / %s / %s', rtrim(rtrim(number_format((float)$amt, 2, '.', ''), '0'), '.'), $period, $daySuffix);
    }

    private function ordinal(int $n): string
    {
        if (in_array($n % 100, [11,12,13], true)) return $n.'th';
        return $n . ([1=>'st',2=>'nd',3=>'rd'][$n%10] ?? 'th');
    }

    private function buildSponsorship(array $b): array
    {
        $li = data_get($b, 'line_items.0');
        return [
            'sponsorship_name' => data_get($li, 'sponsee.full_name') ?: null,
            'sponsorship_ref'  => data_get($li, 'reference') ?: null,
            'sponsorship_url'  => data_get($li, 'public_url') ?: null,
        ];
    }

    private function buildProperties(array $b): array
    {
        // Basics
        $donorId   = $this->val($b, ['supporter.id', 'supporter.id_deprecated', 'account.id', 'vendor_contact_id']);
        $country   = $this->val($b, ['billing_address.country_code','billing_address.country','supporter.billing_address.country']);
        $state     = $this->val($b, ['billing_address.province_code','billing_address.state','supporter.billing_address.state']);
        $addr1     = $this->val($b, ['billing_address.address1']);
        $city      = $this->val($b, ['billing_address.city']);
        $postal    = $this->val($b, ['billing_address.zip']);
        $phone     = $this->digits($this->val($b, ['billing_address.phone','supporter.billing_address.phone']));
        $profile   = $this->val($b, ['supporter.profile_url', 'line_items.0.public_url']);
        $orderedAt = $this->val($b, ['ordered_at','created_at']);
        $lastDate  = $this->parseDate($orderedAt);

        // Amount & currency (last donation)
        $amount   = $this->val($b, ['total_amount','subtotal_amount','amount']);
        $currency = $this->val($b, ['currency','payments.0.currency.code']);
        $lastDonationAmount = ($amount !== null && $currency) ? sprintf('%s %s', rtrim(rtrim(number_format((float)$amount, 2, '.', ''), '0'), '.'), $currency) : null;

        // Payment details
        $payBrand = $this->val($b, ['payments.0.card.brand','payments.0.type','payment_type']);
        $payStatus= ($this->val($b, ['payments.0.status']) === 'succeeded' || $this->val($b, ['is_paid']) === true) ? 'paid' : null;

        // Lifetime (only present on supporter payloads)
        $lifetime = $this->val($b, ['supporter.lifetime_donation_amount']);

        // Donor since
        $donorSince = $this->parseDate($this->val($b, ['supporter.created_at']));

        // Recurring summary
        $recurring = $this->buildRecurringSummary($b);

        // Sponsorship
        $sp = $this->buildSponsorship($b);

        return array_filter([
            'donor_id'             => is_numeric($donorId) ? (int)$donorId : null,
            'donor_since'          => $donorSince,
            'last_donation_date'   => $lastDate,
            'last_donation_amount' => $lastDonationAmount,
            'payment_method'       => $payBrand,
            'payment_status'       => $payStatus,
            'recurring_summary'    => $recurring,
            'lifetime_donation'    => is_numeric($lifetime) ? (float)$lifetime : null,
            'donor_profile_url'    => $profile,
            'country'              => $country,
            'province'             => $state,
            'phone'                => $phone,
            'billing_address1'     => $addr1,
            'billing_city'         => $city,
            'billing_postal'       => $postal,
            'sponsorship_name'     => $sp['sponsorship_name'] ?? null,
            'sponsorship_ref'      => $sp['sponsorship_ref'] ?? null,
            'sponsorship_url'      => $sp['sponsorship_url'] ?? null,
        ], fn($v) => $v !== null && $v !== '');
    }

    /* =========================
     *   Help Scout API
     * ========================= */

    private string $hsTokenUrl = 'https://api.helpscout.net/v2/oauth2/token';
    private string $hsApi      = 'https://api.helpscout.net/v2';

    private function hsAccessToken(): string
    {
        return Cache::remember('hs_access_token', now()->addMinutes(30), function () {
            $refresh = (string) (env('HS_REFRESH_TOKEN') ?? '');
            if ($saved = Cache::get('hs_refresh_file')) {
                $refresh = $saved;
            }

            abort_unless($refresh !== '', 500, 'No Help Scout refresh token. Connect OAuth first.');

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
        // Primary: direct query param (fast, plan-agnostic)
        $r = Http::withToken($token)->timeout(6)->get("{$this->hsApi}/customers", [
            'email' => $email,
            'page'  => 1,
        ]);
        if ($r->ok()) {
            return data_get($r->json(), '_embedded.customers.0');
        }

        // Fallback: DSL (some accounts)
        $r2 = Http::withToken($token)->timeout(6)->get("{$this->hsApi}/customers", [
            'query' => '(email:"'.$email.'")',
            'page'  => 1,
        ]);
        if ($r2->ok()) {
            return data_get($r2->json(), '_embedded.customers.0');
        }

        // We intentionally skip /search/customers due to 404 on some plans
        Log::warning('HS find failed (both strategies)', ['email' => $email, 's1' => $r->status(), 's2' => $r2->status()]);
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
            // Conflict: already exists -> fetch
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

    private function hsPropertySlugs(string $token): array
    {
        // Allow pre-seeding via env to avoid an extra GET
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
        // Concept -> HS slugs (configure these in Help Scout once)
        $slugMap = [
            'donor_id'             => 'donor-id',
            'donor_since'          => 'donor-since',
            'last_donation_date'   => 'last-order',
            'last_donation_amount' => 'last-donation-amount',
            'payment_status'       => 'payment-status',
            'payment_method'       => 'payment-method',
            'recurring_summary'    => 'recurring-summary',
            'lifetime_donation'    => 'lifetime-donation',
            'donor_profile_url'    => 'gc-donor-profile',
            'country'              => 'country',
            'province'             => 'state',
            'phone'                => 'phone-no',
            'billing_address1'     => 'billing-address1',
            'billing_city'         => 'billing-city',
            'billing_postal'       => 'billing-postal',
            'sponsorship_name'     => 'sponsorship-name',
            'sponsorship_ref'      => 'sponsorship-ref',
            'sponsorship_url'      => 'sponsorship-url',
        ];

        $numericSlugs = ['donor-id','lifetime-donation','phone-no'];
        $existing = $this->hsPropertySlugs($token);

        // Warn once if any important slug is missing
        $mustHave = ['donor-id','last-order','country','state','last-donation-amount','payment-method',
                     'recurring-summary','billing-address1','billing-city','billing-postal'];
        $missing = array_values(array_diff($mustHave, $existing));
        if ($missing) {
            Log::warning('HS missing important custom properties (please create these slugs)', $missing);
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
            if ($slug === 'last-order' || $slug === 'donor-since') {
                $val = $this->parseDate((string)$val);
            }

            $ops[] = ['op' => 'replace', 'path' => '/'.$slug, 'value' => $val];
        }

        if (!$ops) return;

        $r = Http::withToken($token)->acceptJson()->asJson()->timeout(8)
            ->patch("{$this->hsApi}/customers/{$customerId}/properties", $ops);

        if (!in_array($r->status(), [200, 204], true)) {
            Log::error('HS properties failed', ['status' => $r->status(), 'body' => $r->body(), 'ops' => $ops]);
            // Don’t throw – we don’t want the job to keep retrying if account lacks the feature
        }
    }
}
