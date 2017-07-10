<?php

use Illuminate\Database\Seeder;

class NucleosRegionaisTableSeeder extends Seeder
{
    /**
     * Run the database seeds.
     *
     * @return void
     */
    public function run()
    {
        factory(\App\NucleoRegional::class)->states('nordeste')->create();
        factory(\App\NucleoRegional::class)->states('oeste')->create();
        factory(\App\NucleoRegional::class)->states('centroOeste')->create();
        factory(\App\NucleoRegional::class)->states('norte')->create();
        factory(\App\NucleoRegional::class)->states('regiaoMetropolitana')->create();
        factory(\App\NucleoRegional::class)->states('leste')->create();
        factory(\App\NucleoRegional::class)->states('extremoSul')->create();
        factory(\App\NucleoRegional::class)->states('sudoeste')->create();
        factory(\App\NucleoRegional::class)->states('centroLeste')->create();
        factory(\App\NucleoRegional::class)->states('centroNorte')->create();
    }
}
