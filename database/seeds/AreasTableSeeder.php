<?php

use Illuminate\Database\Seeder;

class AreasTableSeeder extends Seeder
{
    /**
     * Run the database seeds.
     *
     * @return void
     */
    public function run()
    {
        // Criando Areas Necessárias
        factory(\App\Area::class)->states('pediatria')->create();
        factory(\App\Area::class)->states('clinicaMedica')->create();
        factory(\App\Area::class)->states('clinicaCirurgica')->create();
        factory(\App\Area::class)->states('ginecoObstetricia')->create();
    }
}
