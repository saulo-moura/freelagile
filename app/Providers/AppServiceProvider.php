<?php

namespace App\Providers;

use Illuminate\Support\Facades\App;
use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Bootstrap any application services.
     *
     * @return void
     */
    public function boot()
    {
        //
    }

    /**
     * Register any application services.
     *
     * @return void
     */
    public function register()
    {
        $locale = config('app.locale');

        //define the locale to carbon and php directly
        setlocale(LC_ALL, $locale, $locale . '.utf-8', $locale . '.utf-8', 'portuguese');
        \Carbon::setLocale(config('app.locale'));

        App::bind('prodeb', function () {
            return new \App\Util\Prodeb;
        });
    }
}
