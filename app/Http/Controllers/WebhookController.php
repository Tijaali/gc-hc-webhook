<?php

namespace App\Http\Controllers;

use App\Jobs\ProcessGivecloudEvent;
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
        $this->verifyGivecloud($r);

        // Idempotency by Givecloud delivery id (or hash of body)
        $delivery = (string) ($r->header('X-Givecloud-Delivery') ?? '');
        if ($delivery === '') {
            $delivery = sha1($r->getContent());
        }
        if (!Cache::add("gc:seen:$delivery", 1, now()->addMinutes(10))) {
            // Already processed
            return response()->noContent(202);
        }

        $event   = (string) ($r->header('X-Givecloud-Event') ?? 'unknown');
        $domain  = (string) ($r->header('X-Givecloud-Domain') ?? '');
        $payload = $r->json()->all();

        // --- Respond fast ---
        // Send 202 immediately to Givecloud
        $resp = response()->noContent(202);
        $resp->send();
        if (function_exists('fastcgi_finish_request')) {
            // Let the web server finish the HTTP response,
            // then keep running PHP for the HS sync.
            fastcgi_finish_request();
        }

        // --- Process inline (no queue worker required) ---
        try {
            (new ProcessGivecloudEvent($event, $delivery, $domain, $payload))->handle();
        } catch (\Throwable $e) {
            Log::error('GC inline handler error', [
                'event' => $event,
                'delivery' => $delivery,
                'err' => $e->getMessage(),
                'line' => $e->getLine(),
                'file' => $e->getFile(),
            ]);
        }
        return;
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
