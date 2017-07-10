<?php

$factory->define(App\Curso::class, function (Faker\Generator $faker) {
    return [
        'nome' => $faker->unique()->name
    ];
});

$factory->state(App\Curso::class, 'servicoSocial', function () {
    return [
        'nome' => 'Serviço Social',
    ];
});

$factory->state(App\Curso::class, 'biologia', function () {
    return [
        'nome' => 'Biologia',
    ];
});

$factory->state(App\Curso::class, 'biomedicina', function () {
    return [
        'nome' => 'Biomedicina',
    ];
});

$factory->state(App\Curso::class, 'educacaoFisica', function () {
    return [
        'nome' => 'Educação Física',
    ];
});

$factory->state(App\Curso::class, 'enfermagem', function () {
    return [
        'nome' => 'Enfermagem',
    ];
});

$factory->state(App\Curso::class, 'farmacia', function () {
    return [
        'nome' => 'Farmácia',
    ];
});

$factory->state(App\Curso::class, 'fisioterapia', function () {
    return [
        'nome' => 'Fisioterapia',
    ];
});

$factory->state(App\Curso::class, 'fonoaudiologia', function () {
    return [
        'nome' => 'Fonoaudiologia',
    ];
});

$factory->state(App\Curso::class, 'medicina', function () {
    return [
        'nome' => 'Medicina',
    ];
});

$factory->state(App\Curso::class, 'medicinaVeterinaria', function () {
    return [
        'nome' => 'Medicina Veterinária',
    ];
});

$factory->state(App\Curso::class, 'nutricao', function () {
    return [
        'nome' => 'Nutrição',
    ];
});

$factory->state(App\Curso::class, 'odontologia', function () {
    return [
        'nome' => 'Odontologia',
    ];
});

$factory->state(App\Curso::class, 'psicologia', function () {
    return [
        'nome' => 'Psicologia',
    ];
});

$factory->state(App\Curso::class, 'terapiaOcupacional', function () {
    return [
        'nome' => 'Terapia Ocupacional',
    ];
});

$factory->state(App\Curso::class, 'saudeColetiva', function () {
    return [
        'nome' => 'Saúde Coletiva',
    ];
});

$factory->state(App\Curso::class, 'bachareladoInterdisciplinarEmSaude', function () {
    return [
        'nome' => 'Bacharelado Interdisciplinar em Saúde',
    ];
});

$factory->state(App\Curso::class, 'tecnologoEmRadiologia', function () {
    return [
        'nome' => 'Tecnólogo em Radiologia',
    ];
});
