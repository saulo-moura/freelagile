<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class AlterTiposEstabelecimentoSaudeAddUniqueContraintNome extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::table('tipos_estabelecimento_saude', function (Blueprint $table) {
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
        Schema::table('tipos_estabelecimento_saude', function (Blueprint $table) {
            $table->dropUnique('tipos_estabelecimento_saude_nome_unique');
        });
    }
}
