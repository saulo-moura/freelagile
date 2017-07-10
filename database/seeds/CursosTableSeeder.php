<?php

use Illuminate\Database\Seeder;

class CursosTableSeeder extends Seeder
{
    /**
     * Run the database seeds.
     *
     * @return void
     */
    public function run()
    {
        factory(\App\Curso::class)->states('servicoSocial')->create();
        factory(\App\Curso::class)->states('biologia')->create();
        factory(\App\Curso::class)->states('biomedicina')->create();
        factory(\App\Curso::class)->states('educacaoFisica')->create();
        factory(\App\Curso::class)->states('enfermagem')->create();
        factory(\App\Curso::class)->states('farmacia')->create();
        factory(\App\Curso::class)->states('fisioterapia')->create();
        factory(\App\Curso::class)->states('fonoaudiologia')->create();
        factory(\App\Curso::class)->states('medicina')->create();
        factory(\App\Curso::class)->states('medicinaVeterinaria')->create();
        factory(\App\Curso::class)->states('nutricao')->create();
        factory(\App\Curso::class)->states('odontologia')->create();
        factory(\App\Curso::class)->states('psicologia')->create();
        factory(\App\Curso::class)->states('terapiaOcupacional')->create();
        factory(\App\Curso::class)->states('saudeColetiva')->create();
        factory(\App\Curso::class)->states('bachareladoInterdisciplinarEmSaude')->create();
        factory(\App\Curso::class)->states('tecnologoEmRadiologia')->create();
    }
}
