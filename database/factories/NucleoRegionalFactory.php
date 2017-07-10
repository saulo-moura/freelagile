<?php

$factory->define(App\NucleoRegional::class, function (Faker\Generator $faker) {
    static $password;

    return [
        'nome' => $faker->unique()->name,
    ];
});

$factory->state(App\NucleoRegional::class, 'nordeste', function () {
    return [
        'nome' => 'Nordeste',
    ];
});

$factory->state(App\NucleoRegional::class, 'oeste', function () {
    return [
        'nome' => 'Oeste',
    ];
});

$factory->state(App\NucleoRegional::class, 'centroOeste', function () {
    return [
        'nome' => 'Centro-Oeste',
    ];
});

$factory->state(App\NucleoRegional::class, 'norte', function () {
    return [
        'nome' => 'Norte',
    ];
});

$factory->state(App\NucleoRegional::class, 'regiaoMetropolitana', function () {
    return [
        'nome' => 'Região Metropolitana',
    ];
});

$factory->state(App\NucleoRegional::class, 'leste', function () {
    return [
        'nome' => 'Leste',
    ];
});

$factory->state(App\NucleoRegional::class, 'extremoSul', function () {
    return [
        'nome' => 'Extremo-Sul',
    ];
});

$factory->state(App\NucleoRegional::class, 'sudoeste', function () {
    return [
        'nome' => 'Sudoeste',
    ];
});

$factory->state(App\NucleoRegional::class, 'centroLeste', function () {
    return [
        'nome' => 'Centro-Leste',
    ];
});

$factory->state(App\NucleoRegional::class, 'centroNorte', function () {
    return [
        'nome' => 'Centro-Norte',
    ];
});
