<?php

$factory->define(App\User::class, function (Faker\Generator $faker) {
    static $password;

    return [
        'name' => $faker->name,
        'email' => $faker->unique()->safeEmail,
        'password' => $password ?: $password = bcrypt('secret'),
        'remember_token' => str_random(10)
    ];
});

$factory->state(App\User::class, 'invalid', function () {
    return [
        'email' => '631837y1t3615361',
    ];
});


$factory->state(App\User::class, 'admin', function () {
    return [
        'name' => 'Admin',
        'email' => 'admin@freelagile.com',
        'password' => Hash::make('tccifba2017')
    ];
});

$factory->state(App\User::class, 'admin-plain-password', function () {
    return [
        'name' => 'Admin',
        'email' => 'admin@freelagile.com',
        'password' => 'tccifba2017'
    ];
});


$factory->state(App\User::class, 'normal', function () {
    return [
        'email' => 'normal-base@freelagile.com',
        'password' => Hash::make('tccifba2017')
    ];
});

$factory->state(App\User::class, 'normal-plain-password', function () {
    return [
        'email' => 'normal-base@freelagile.com',
        'password' => 'tccifba2017'
    ];
});

$factory->state(App\User::class, 'rest', function () {
    return [
        'roles' => []
    ];
});
