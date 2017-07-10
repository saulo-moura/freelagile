<?php

$factory->define(App\User::class, function (Faker\Generator $faker) {
    static $password;

    return [
        'name' => $faker->name,
        'cpf' => $faker->cpf(false),
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
        'cpf' => '81100413537',
        'name' => 'Admin',
        'email' => 'admin-base@prodeb.com',
        'password' => Hash::make('Prodeb01')
    ];
});

$factory->state(App\User::class, 'admin-plain-password', function () {
    return [
        'name' => 'Admin',
        'email' => 'admin-base@prodeb.com',
        'password' => 'Prodeb01'
    ];
});


$factory->state(App\User::class, 'normal', function () {
    return [
        'email' => 'normal-base@prodeb.com',
        'password' => Hash::make('Prodeb01')
    ];
});

$factory->state(App\User::class, 'normal-plain-password', function () {
    return [
        'email' => 'normal-base@prodeb.com',
        'password' => 'Prodeb01'
    ];
});

$factory->state(App\User::class, 'rest', function () {
    return [
        'roles' => []
    ];
});
