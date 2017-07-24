<?php

use Illuminate\Database\Seeder;

class RolesFreelagile extends Seeder
{
    /**
     * Run the database seeds.
     *
     * @return void
     */
    public function run() {
        DB::table('roles')->insert([
            [
				'title' => 'Desenvolvedor',
				'slug'  => 'dev'
			],
            [
				'title' => 'Contratante',
				'slug'  => 'client'
            ],
            [
				'title' => 'Acompanhante',
				'slug'  => 'stakeholder'
			]
        ]);
    }
}
