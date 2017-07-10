<?php

namespace Tests;

use Illuminate\Contracts\Console\Kernel;

trait CreatesApplication
{
    /**
     * Creates the application.
     *
     * @return \Illuminate\Foundation\Application
     */
    public function createApplication()
    {
        $app = require __DIR__.'/../bootstrap/app.php';

        $app->make(Kernel::class)->bootstrap();

        $this->adminUserData = factory(\App\User::class)->states('admin-plain-password')->make()->getAttributes();
        $this->normalUserData = factory(\App\User::class)->states('normal-plain-password')->make()->getAttributes();

        return $app;
    }

    public function setUp()
    {
        parent::setUp();

        \Artisan::call('migrate:reset', []);

        \Artisan::call('migrate', ['--seed' => true]);
    }
}
