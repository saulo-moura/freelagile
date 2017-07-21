<?php

namespace App\Providers;

use Illuminate\Support\Facades\App;
use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Facades\Schema;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Bootstrap any application services.
     *
     * @return void
     */
    public function boot()
    {
        Schema::defaultStringLength(191);
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
