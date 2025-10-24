<?php

namespace App\Jobs;

use App\Services\HelpScoutSync;
use Carbon\Carbon;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue; // fine to keep, we call handle() inline
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Queue\Middleware\RateLimited;

class ProcessGivecloudEvent implements ShouldQueue
{
    use Dispatchable, Queueable, InteractsWithQueue, SerializesModels;

    public array $data;
    public $timeout = 20;               // hard time budget per job
    public $tries   = 5;                // let HS hiccups retry
    public function __construct(array $data){ $this->data = $data; }

    public function middleware()
    {
        return [new RateLimited('helpscout')]; // optional: throttle HS calls globally
    }

    public function handle(): void
    {
        $t0 = microtime(true);
        (new HelpScoutSync())->runStrict(
            $this->data['event'],
            $this->data['delivery'],
            $this->data['domain'],
            $this->data['payload']
        );
        Log::info('GC job done', [
            'delivery' => $this->data['delivery'],
            'ms' => (int)((microtime(true)-$t0)*1000)
        ]);
    }
}
