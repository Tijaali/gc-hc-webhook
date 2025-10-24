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
    return [
        'cache_refresh' => (bool) Cache::get('hs_refresh_file'),
        'env_refresh'   => env('HS_REFRESH_TOKEN') ? 'set' : 'missing',
        'file_refresh'  => Storage::exists('hs_oauth.json') ? (bool) data_get(json_decode(Storage::get('hs_oauth.json'), true), 'refresh_token') : false,
        'access_cached' => (bool) Cache::get('hs_access_token'),
    ];
});

Route::get('/oauth/hs/start', [WebhookController::class, 'hsStart']);
Route::get('/oauth/hs/callback', [WebhookController::class, 'hsCallback']);

Route::post('/webhooks/givecloud', [WebhookController::class, 'gc'])->withoutMiddleware([FrameworkCsrf::class])->middleware(['throttle:240,1']);
