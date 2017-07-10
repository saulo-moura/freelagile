<?php

use Illuminate\Database\Seeder;
use App\TipoHorario;

class TiposHorarioTableSeeder extends Seeder
{
    /**
     * Run the database seeds.
     *
     * @return void
     */
    public function run()
    {
        TipoHorario::create([
            'id' => 1,
            'descricao' => 'Manhã',
            'duracao' => 4
        ]);
        TipoHorario::create([
            'id' => 2,
            'descricao' => 'Tarde',
            'duracao' => 4
        ]);
        TipoHorario::create([
            'id' => 3,
            'descricao' => 'Plantão Diurno',
            'duracao' => 12
        ]);
        TipoHorario::create([
            'id' => 4,
            'descricao' => 'Plantão Noturno',
            'duracao' => 12
        ]);
    }
}
