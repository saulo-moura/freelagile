<?php

$factory->define(App\Status::class, function (Faker\Generator $faker) {
    return [
        'nome' => $faker->unique()->name
    ];
});

$factory->state(App\Status::class, 'pendente', function () {
    return [
        'nome' => 'Pendente',
    ];
});

$factory->state(App\Status::class, 'aguardandoAprovacao', function () {
    return [
        'nome' => 'Aguardando Aprovação',
    ];
});

$factory->state(App\Status::class, 'aprovado', function () {
    return [
        'nome' => 'Aprovado',
    ];
});

$factory->state(App\Status::class, 'reprovado', function () {
    return [
        'nome' => 'Reprovado',
    ];
});
