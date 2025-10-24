<?php

namespace App\Http\Controllers;

use App\Jobs\ProcessGivecloudEvent;
use App\Jobs\SyncHelpScoutFromGivecloud;
use App\Services\HelpScout;
use App\Services\HelpScoutSync;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Response;

class WebhookController extends Controller
{
    /* =========================
     * OAuth (Help Scout)
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

    public function hsCallback(Request $r, HelpScout $hs)
    {
        abort_unless($r->has('code'), 400, 'Missing code');
        $data = $hs->exchangeCode((string)$r->query('code'));
        return response()->json($data);
    }

    /* =========================
     * Givecloud Webhook
     * ========================= */

    public function gc(Request $r)
    {
        // 1) Verify signature (hard fail if missing/wrong)
        $this->verifyGivecloud($r);

        // 2) Idempotency (avoid double-processing the same delivery)
        $deliveryId = (string)($r->header('X-Givecloud-Delivery') ?? '');
        if ($deliveryId === '') {
            $deliveryId = sha1($r->getContent());
        }
        if (!Cache::add("gc:seen:$deliveryId", 1, now()->addMinutes(15))) {
            return response()->json(['status' => 'duplicate'], 200);
        }

        $event   = (string)($r->header('X-Givecloud-Event') ?? 'unknown');
        $domain  = (string)($r->header('X-Givecloud-Domain') ?? '');
        $payload = $r->json()->all();

        try {
            // 3) Do the full HS sync NOW (synchronous & reliable)
            (new HelpScoutSync())->run($event, $deliveryId, $domain, $payload);

            // 4) Only after work is done, reply 200
            return response()->json(['status' => 'ok'], 200);
        } catch (\Throwable $e) {
            Log::error('GC webhook fatal', [
                'event'    => $event,
                'delivery' => $deliveryId,
                'err'      => $e->getMessage(),
                'line'     => $e->getLine(),
                'file'     => $e->getFile(),
            ]);

            // 5xx tells Givecloud to retry. Keep payload safe with idempotency key above.
            return response()->json(['status' => 'error', 'msg' => 'internal'], 500);
        }
    }

    private function verifyGivecloud(Request $r): void
    {
        $secret = (string) env('GC_WEBHOOK_SECRET', '');
        abort_unless($secret !== '', 500, 'Missing GC_WEBHOOK_SECRET');

        $sig  = $r->header('X-Givecloud-Signature') ?? $r->header('x-givecloud-signature');
        $raw  = $r->getContent();
        $calc = hash_hmac('sha1', $raw, $secret);

        abort_unless($sig && hash_equals((string)$sig, (string)$calc), 401, 'Invalid signature');
    }
}
