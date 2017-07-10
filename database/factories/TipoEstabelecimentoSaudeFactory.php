<?php

$factory->define(App\TipoEstabelecimentoSaude::class, function (Faker\Generator $faker) {
    static $password;

    return [
        'nome' => $faker->unique()->name,
    ];
});

$factory->state(App\TipoEstabelecimentoSaude::class, 'hospital', function () {
    return [
        'nome' => 'Hospital',
    ];
});

$factory->state(App\TipoEstabelecimentoSaude::class, 'maternidade', function () {
    return [
        'nome' => 'Maternidade',
    ];
});


$factory->state(App\TipoEstabelecimentoSaude::class, 'centroDeReferencia', function () {
    return [
        'nome' => 'Centro de Referência',
    ];
});

$factory->state(App\TipoEstabelecimentoSaude::class, 'upa', function () {
    return [
        'nome' => 'Unidade de Emergência – UPA',
    ];
});

$factory->state(App\TipoEstabelecimentoSaude::class, 'ncs', function () {
    return [
        'nome' => 'Núcleo Regional de Saúde',
    ];
});

$factory->state(App\TipoEstabelecimentoSaude::class, 'fundacao', function () {
    return [
        'nome' => 'Fundação',
    ];
});

$factory->state(App\TipoEstabelecimentoSaude::class, 'diretoriasSesab', function () {
    return [
        'nome' => 'Diretorias / SESAB',
    ];
});
