<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class AlterVagasAddEspecialideEspecificacao extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::table('vagas', function (Blueprint $table) {
            $table->integer('especialidade_id')->unsigned()->nullable();
            $table->integer('especificacao_id')->unsigned()->nullable();

            $table->foreign('especialidade_id')->references('id')->on('especialidades');
            $table->foreign('especificacao_id')->references('id')->on('especificacoes');
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::table('vagas', function (Blueprint $table) {
            $table->dropForeign(['especialidade_id']);
            $table->dropForeign(['especificacao_id']);

            $table->dropIfExists('especialidade_id');
            $table->dropIfExists('especificacao_id');
        });
    }
}
