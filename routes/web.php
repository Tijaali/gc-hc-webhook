<?php

use App\Http\Controllers\WebhookController;
use App\Http\Middleware\VerifyCsrfToken;
use Illuminate\Support\Facades\Route;
use Illuminate\Foundation\Http\Middleware\VerifyCsrfToken as FrameworkCsrf;

Route::get('/', function () {
    return view('welcome');
});
Route::get('/health', fn () => response()->json(['ok' => true]));
Route::get('/debug/env', fn() => [
  'HS_CLIENT_ID' => env('HS_CLIENT_ID') ? 'set' : 'missing',
  'HS_REDIRECT_URI' => env('HS_REDIRECT_URI'),
]);

Route::get('/oauth/hs/start', [WebhookController::class, 'hsStart']);
Route::get('/oauth/hs/callback', [WebhookController::class, 'hsCallback']);

Route::post('/webhooks/givecloud', [WebhookController::class, 'gc'])->withoutMiddleware([FrameworkCsrf::class]);
