<?php

$factory->define(App\Modalidade::class, function (Faker\Generator $faker) {
    return [
        'nome' => $faker->unique()->name
    ];
});

$factory->state(App\Modalidade::class, 'estagio', function () {
    return [
        'id' => 1,
        'nome' => 'Estágio',
    ];
});

$factory->state(App\Modalidade::class, 'pratica', function () {
    return [
        'id' => 2,
        'nome' => 'Prática',
    ];
});

$factory->state(App\Modalidade::class, 'internato', function () {
    return [
        'id' => 3,
        'nome' => 'Internato',
    ];
});
