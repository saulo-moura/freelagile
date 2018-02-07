<?php

use Illuminate\Database\Seeder;

class PrioritiesTaskSeeder extends Seeder
{
    /**
     * Run the database seeds.
     *
     * @return void
     */
    public function run() {
        DB::table('priorities')->insert([
            [
                'name' => 'Opcional',
                'slug' => 'baixa'
            ],
            [
                'name' => 'Importante',
                'slug' => 'normal'
            ],
            [
                'name' => 'Essencial',
                'slug' => 'alta'
            ]
        ]);
    }
}
