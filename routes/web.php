<?php

use App\Http\Controllers\WebhookController;
use App\Http\Middleware\VerifyCsrfToken;
use Illuminate\Support\Facades\Route;
use Illuminate\Foundation\Http\Middleware\VerifyCsrfToken as FrameworkCsrf;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Storage;

Route::get('/', function () {
    return view('welcome');
});
Route::get('/health', fn () => response()->json(['ok' => true]));
Route::get('/debug/hs', function () {
    $fileHas = false;
    $fileHash = null;
    if (Storage::exists('hs_oauth.json')) {
        $j = json_decode(Storage::get('hs_oauth.json'), true) ?: [];
        if (!empty($j['refresh_token'])) {
            $fileHas = true;
            $fileHash = substr(sha1((string)$j['refresh_token']), 0, 10);
        }
    }
    $cacheRf = Cache::get('hs_refresh_file');
    return [
        'access_cached'   => (bool) Cache::get('hs_access_token'),
        'refresh_in_file' => $fileHas,
        'refresh_file_hash' => $fileHash,
        'refresh_in_cache'=> (bool) $cacheRf,
        'refresh_cache_hash' => $cacheRf ? substr(sha1((string)$cacheRf), 0, 10) : null,
        'cache_driver'    => config('cache.default'),
        'redirect_uri'    => env('HS_REDIRECT_URI'),
    ];
});


Route::get('/oauth/hs/start', [WebhookController::class, 'hsStart']);
Route::get('/oauth/hs/callback', [WebhookController::class, 'hsCallback']);

Route::post('/webhooks/givecloud', [WebhookController::class, 'gc'])->withoutMiddleware([FrameworkCsrf::class])->middleware(['throttle:240,1']);
