<?php

namespace App\Jobs;

use App\Services\HelpScout;
use Carbon\Carbon;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Log;

class SyncHelpScoutFromGivecloud implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    public array $payload;
    public string $event;
    public string $deliveryId;

    public function __construct(array $payload, string $event, string $deliveryId)
    {
        $this->payload    = $payload;
        $this->event      = $event;
        $this->deliveryId = $deliveryId;
        $this->onQueue(env('GC_QUEUE', 'default'));
    }

    public function handle(HelpScout $hs): void
    {
        $b   = $this->payload;
        $evt = $this->event;

        // supporter_* events may include multiple records
        if (str_starts_with($evt, 'supporter_')) {
            $supporters = (array) data_get($b, 'supporters', []);
            foreach ($supporters as $s) {
                $this->syncOne($hs, $this->extractFromSupporter($s));
            }
            return;
        }

        // contribution / contributions / recurring_profile
        $this->syncOne($hs, $this->extractFromContributionEnvelope($b, $evt));
    }

    /* =========================
     * Extraction
     * ========================= */

    private function extractFromSupporter(array $s): array
    {
        $email = data_get($s, 'email') ?: data_get($s, 'billing_address.email');

        return [
            'email' => $email,
            'first' => data_get($s, 'first_name') ?: data_get($s, 'billing_address.first_name'),
            'last'  => data_get($s, 'last_name')  ?: data_get($s, 'billing_address.last_name'),

            'phone' => data_get($s, 'billing_address.phone'),
            'addr1' => data_get($s, 'billing_address.address1'),
            'addr2' => data_get($s, 'billing_address.address2'),
            'city'  => data_get($s, 'billing_address.city'),
            'state' => data_get($s, 'billing_address.state'),
            'postal'=> data_get($s, 'billing_address.zip'),
            'country'=>data_get($s, 'billing_address.country'),

            'props' => [
                'donor_id'            => data_get($s, 'id'),
                'donor_since'         => data_get($s, 'created_at'),
                'country'             => data_get($s, 'billing_address.country'),
                'province'            => data_get($s, 'billing_address.state'),
                // no last donation / payment info on pure supporter update
            ],
            'profile_url' => null,
        ];
    }

    private function extractFromContributionEnvelope(array $b, string $evt): array
    {
        $supporter = (array) data_get($b, 'supporter', []);
        $email = data_get($b, 'email')
              ?: data_get($supporter, 'email')
              ?: data_get($b, 'billing_address.email');

        $addrSrc = (array) data_get($b, 'billing_address', []);
        $line0   = (array) data_get($b, 'line_items.0', []);

        $props = [
            'donor_id'             => data_get($supporter, 'id') ?? data_get($supporter, 'id_deprecated'),
            'donor_since'          => data_get($supporter, 'created_at') ?? data_get($b, 'created_at'),
            'last_donation_date'   => data_get($b, 'ordered_at') ?? data_get($b, 'created_at'),
            'last_donation_amount' => $this->fmtAmountCurrency(data_get($b,'total_amount'), data_get($b,'currency')),
            'lifetime_donation'    => data_get($supporter, 'lifetime_donation_amount'),
            'payment_status'       => data_get($b, 'is_paid') ? 'paid' : (data_get($b,'refunded') ? 'refunded' : 'pending'),
            'payment_method'       => data_get($b,'payments.0.card.brand') ?: data_get($b,'payments.0.type') ?: data_get($b,'payment_type'),
            'recurring_summary'    => $this->recurringSummary($line0, data_get($b,'currency')),
            'country'              => data_get($addrSrc, 'country_code') ?: data_get($supporter, 'billing_address.country'),
            'province'             => data_get($addrSrc, 'province_code') ?: data_get($supporter, 'billing_address.state'),
            'donor_profile_url'    => data_get($supporter,'profile_url') ?: data_get($line0,'public_url'),
            // mirrored billing
            'billing_address1'     => data_get($addrSrc, 'address1'),
            'billing_city'         => data_get($addrSrc, 'city'),
            'billing_postal'       => data_get($addrSrc, 'zip'),
            // sponsorship
            'sponsorship_name'     => data_get($line0,'sponsorship.full_name'),
            'sponsorship_ref'      => data_get($line0,'sponsorship.reference_number'),
            'sponsorship_url'      => data_get($line0,'sponsorship.url'),
        ];

        // Special-case refunds
        if ($evt === 'contribution_refunded') {
            $props['payment_status'] = 'refunded';
        }

        return [
            'email'       => $email,
            'first'       => data_get($supporter, 'first_name') ?: data_get($addrSrc,'first_name'),
            'last'        => data_get($supporter, 'last_name')  ?: data_get($addrSrc,'last_name'),

            'phone'       => data_get($addrSrc,'phone'),
            'addr1'       => data_get($addrSrc,'address1'),
            'addr2'       => data_get($addrSrc,'address2'),
            'city'        => data_get($addrSrc,'city'),
            'state'       => data_get($addrSrc,'province_code') ?: data_get($addrSrc,'state'),
            'postal'      => data_get($addrSrc,'zip'),
            'country'     => data_get($addrSrc,'country_code') ?: data_get($addrSrc,'country'),

            'profile_url' => $props['donor_profile_url'],
            'props'       => $props,
        ];
    }

    /* =========================
     * Work
     * ========================= */

    private function syncOne(HelpScout $hs, array $d): void
    {
        $email = $d['email'] ?? null;
        if (!$email) {
            Log::info('GC webhook: skipped (no email)');
            return;
        }

        $token = $hs->accessToken();

        // Upsert id
        $existing = $hs->findCustomerByEmail($token, $email);
        $id = $existing['id'] ?? null;
        if (!$id) {
            $id = $hs->createOrGetId($token, $d['first'] ?? null, $d['last'] ?? null, $email);
        }
        if (!$id) {
            Log::info('HS upsert skipped (no id resolvable)', ['email' => $email]);
            return;
        }

        // Core update
        $core = [
            'firstName' => $d['first'] ?? null,
            'lastName'  => $d['last'] ?? null,
            'websites'  => $d['profile_url'] ? [['value' => (string)$d['profile_url']]] : [],
            'phones'    => $this->normPhone($d['phone']) ? [['type'=>'work','value'=>(string)$this->normPhone($d['phone'])]] : [],
            'addresses' => [[
                'type'       => 'work',
                'lines'      => array_values(array_filter([$d['addr1'] ?? null, $d['addr2'] ?? null])),
                'city'       => $d['city'] ?? null,
                'state'      => $d['state'] ?? null,
                'postalCode' => $d['postal'] ?? null,
                'country'    => $d['country'] ?? null,
            ]],
        ];
        // strip empties
        $core = array_filter($core, fn($v) => $v !== null && $v !== [] && $v !== '');

        $hs->updateCore($hs->accessToken(), $id, $core);

        // Properties update (only slugs that exist)
        $props = $d['props'] ?? [];
        $props['phone'] = $this->normPhone($d['phone']);
        $hs->patchProperties($token, $id, $props);
    }

    /* =========================
     * Helpers
     * ========================= */

    private function fmtAmountCurrency($amount, $currency): ?string
    {
        if ($amount === null || !$currency) return null;
        return sprintf('%.2f %s', (float)$amount, (string)$currency);
    }

    private function recurringSummary(array $line, ?string $currency): ?string
    {
        $amt  = data_get($line, 'recurring_amount') ?? data_get($line,'price');
        $freq = data_get($line, 'variant.billing_period') ?: data_get($line,'recurring_description'); // try best
        $day  = data_get($line, 'recurring_day');

        if (!$amt || !$currency) return null;

        $freqText = is_string($freq) ? (str_contains(strtolower($freq),'month') ? 'Monthly' : ucfirst((string)$freq)) : 'Monthly';
        $dayText  = $day ? $this->ordinal((int)$day) : null;

        return trim(sprintf('$%s / %s%s',
            number_format((float)$amt, 0),
            $freqText,
            $dayText ? (' / '.$dayText) : ''
        ));
    }

    private function ordinal(int $n): string
    {
        $suffix = 'th';
        if (($n % 100) < 11 || ($n % 100) > 13) {
            $suffix = ['th','st','nd','rd','th','th','th','th','th','th'][$n % 10] ?? 'th';
        }
        return $n . $suffix;
    }

    private function normPhone($raw): ?int
    {
        if (!$raw) return null;
        $digits = preg_replace('/\D+/', '', (string)$raw);
        return $digits !== '' ? (int)$digits : null;
    }
}
