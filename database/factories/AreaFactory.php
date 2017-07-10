<?php

$factory->define(App\Area::class, function (Faker\Generator $faker) {
    return [
        'nome' => $faker->unique()->name
    ];
});

$factory->state(App\Area::class, 'pediatria', function () {
    return [
        'nome' => 'Pediatria',
    ];
});

$factory->state(App\Area::class, 'clinicaMedica', function () {
    return [
        'nome' => 'Clínica Médica',
    ];
});

$factory->state(App\Area::class, 'clinicaCirurgica', function () {
    return [
        'nome' => 'Clínica Cirúrgica',
    ];
});

$factory->state(App\Area::class, 'ginecoObstetricia', function () {
    return [
        'nome' => 'Gineco/Obstetricia',
    ];
});
