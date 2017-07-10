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
        'title' => 'ADMIN',
        'slug' => 'admin'
    ];
});

$factory->state(App\Role::class, 'gestorDoSistema', function () {
    return [
        'title' => 'GESTOR DO SISTEMA',
        'slug' => 'gestorDoSistema'
    ];
});

$factory->state(App\Role::class, 'gestorDaIes', function () {
    return [
        'title' => 'GESTOR DA IES',
        'slug' => 'gestorDaIes'
    ];
});

$factory->state(App\Role::class, 'gestorDaEs', function () {
    return [
        'title' => 'GESTOR DA ES',
        'slug' => 'gestorDaEs'
    ];
});

