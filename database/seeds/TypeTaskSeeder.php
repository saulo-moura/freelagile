<?php

use Illuminate\Database\Seeder;

class TypeTaskSeeder extends Seeder
{
    /**
     * Run the database seeds.
     *
     * @return void
     */
    public function run() {
        DB::table('types')->insert([
            [
                'name' => 'Funcionalidade',
                'slug' => 'funcionalidade'
            ],
            [
                'name' => 'Bug',
                'slug' => 'bug'
            ],
            [
                'name' => 'Melhoria',
                'slug' => 'melhoria'
            ]
        ]);
    }
}
