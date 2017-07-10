<?php

use Illuminate\Database\Seeder;

class StatusTableSeeder extends Seeder
{
    /**
     * Run the database seeds.
     *
     * @return void
     */
    public function run()
    {
        // Criando Status Necessários
        factory(\App\Status::class)->states('pendente')->create();
        factory(\App\Status::class)->states('aguardandoAprovacao')->create();
        factory(\App\Status::class)->states('aprovado')->create();
        factory(\App\Status::class)->states('reprovado')->create();
    }
}
