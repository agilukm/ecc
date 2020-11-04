<?php

namespace App\Http\Middleware;

use Closure;
use App;
use Redirect;

class UseSSL
{

    public function handle($request, Closure $next)
    {
            //return Redirect::secure($request->path());

    }
}