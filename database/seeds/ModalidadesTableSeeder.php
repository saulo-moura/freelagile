<?php

use Illuminate\Database\Seeder;

class ModalidadesTableSeeder extends Seeder
{
    /**
     * Run the database seeds.
     *
     * @return void
     */
    public function run()
    {
        // Criando Modalidades Necessários
        factory(\App\Modalidade::class)->states('estagio')->create();
        factory(\App\Modalidade::class)->states('pratica')->create();
        factory(\App\Modalidade::class)->states('internato')->create();
    }
}
