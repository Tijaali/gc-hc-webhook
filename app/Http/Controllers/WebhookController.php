<?php

namespace App\Http\Controllers;

use App\Jobs\SyncHelpScoutFromGivecloud;
use App\Services\HelpScout;
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
        // 1) Verify signature (constant-time compare)
        $this->verifyGivecloud($r);

        // 2) Idempotency key from delivery header
        $deliveryId = (string)($r->header('X-Givecloud-Delivery') ?? '');
        if ($deliveryId !== '') {
            $cacheKey = 'gc:delivery:' . $deliveryId;
            if (!Cache::add($cacheKey, 1, now()->addMinutes(10))) {
                // already processed
                return Response::json(['status' => 'duplicate'], 200);
            }
        }

        // 3) Read raw payload (don’t log big bodies)
        $event   = (string)($r->header('X-Givecloud-Event') ?? 'unknown');
        $payload = $r->json()->all();

        // 4) Ack fast — run async by default
        $async = filter_var(env('GC_ASYNC', true), FILTER_VALIDATE_BOOLEAN);
        if ($async) {
            SyncHelpScoutFromGivecloud::dispatch($payload, $event, $deliveryId);
            return Response::json(['accepted' => true], 202);
        }

        // Fallback: sync (useful for debugging)
        dispatch_sync(new SyncHelpScoutFromGivecloud($payload, $event, $deliveryId));
        return Response::json(['ok' => true], 200);
    }

    /* =========================
     * Helpers
     * ========================= */

    private function verifyGivecloud(Request $r): void
    {
        $secret = (string) env('GC_WEBHOOK_SECRET', '');
        abort_unless($secret !== '', 500, 'Missing GC_WEBHOOK_SECRET');

        $sig = $r->header('X-Givecloud-Signature') ?? $r->header('x-givecloud-signature');
        $raw = $r->getContent();
        $calc = hash_hmac('sha1', $raw, $secret);

        if (env('GC_LOG_SIG', false)) {
            Log::debug('GC sig', [
                'match' => $sig && hash_equals((string)$sig, (string)$calc),
            ]);
        }

        abort_unless($sig && hash_equals((string)$sig, (string)$calc), 401, 'Invalid signature');
    }
}
