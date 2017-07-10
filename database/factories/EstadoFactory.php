<?php

$factory->define(App\Estado::class, function (Faker\Generator $faker) {
    return [
        'nome' => $faker->unique()->name,
        'sigla' => $faker->unique()->randomLetter
    ];
});

$factory->state(App\Estado::class, 'bahia', function () {
    return [
        'nome' => 'Bahia',
        'sigla' => 'BA',
    ];
});
