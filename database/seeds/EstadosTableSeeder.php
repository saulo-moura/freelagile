<?php

use Illuminate\Database\Seeder;

class EstadosTableSeeder extends Seeder
{
    /**
     * Run the database seeds.
     *
     * @return void
     */
    public function run()
    {
        // Criando Estados Necessários
        factory(\App\Estado::class)->states('bahia')->create();
    }
}
