<?php

$factory->define(App\Role::class, function (Faker\Generator $faker) {
    static $password;

    return [
        'title' => $faker->unique()->name,
        'slug' => $faker->unique()->slug
    ];
});

$factory->state(App\Role::class, 'admin', function () {
    return [
        'title' => 'Admin',
        'slug' => 'admin'
    ];
});
