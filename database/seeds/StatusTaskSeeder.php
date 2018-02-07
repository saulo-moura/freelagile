<?php

use Illuminate\Database\Seeder;

class StatusTaskSeeder extends Seeder
{
    /**
     * Run the database seeds.
     *
     * @return void
     */
    public function run() {
        DB::table('status')->insert([
            [
                'name' => 'Novo',
                'slug' => 'novo'
            ],
            [
                'name' => 'Em andamento',
                'slug' => 'emAndamento'
            ],
            [
                'name' => 'Feito',
                'slug' => 'feito'
            ],
            [
                'name' => 'Pendente de Aprovação',
                'slug' => 'pendenteAprovacao'
            ],
            [
                'name' => 'Aprovado',
                'slug' => 'aprovado'
            ],
            [
                'name' => 'Rejeitado',
                'slug' => 'rejeitado'
            ]
        ]);
    }
}
