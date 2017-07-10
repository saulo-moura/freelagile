<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class AlterEspecificacoesAddUniqueContraintNome extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::table('especificacoes', function (Blueprint $table) {
            $table->string('nome')->unique()->change();
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::table('especificacoes', function (Blueprint $table) {
            $table->dropUnique('especificacoes_nome_unique');
        });
    }
}
