<?php

use Illuminate\Database\Seeder;

class TiposEstabelecimentoSaudeTableSeeder extends Seeder
{
    /**
     * Run the database seeds.
     *
     * @return void
     */
    public function run()
    {
        factory(\App\TipoEstabelecimentoSaude::class)->states('hospital')->create();
        factory(\App\TipoEstabelecimentoSaude::class)->states('maternidade')->create();
        factory(\App\TipoEstabelecimentoSaude::class)->states('centroDeReferencia')->create();
        factory(\App\TipoEstabelecimentoSaude::class)->states('upa')->create();
        factory(\App\TipoEstabelecimentoSaude::class)->states('ncs')->create();
        factory(\App\TipoEstabelecimentoSaude::class)->states('fundacao')->create();
        factory(\App\TipoEstabelecimentoSaude::class)->states('diretoriasSesab')->create();
    }
}
