<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class AlterSetoresTiposEstabelecimentoSaudeAddUniqueContraintSetorIdTipoEstabelecimentoSaudeId extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::table('setores_tipos_estabelecimento_saude', function (Blueprint $table) {
            $table->unique(['setor_id', 'tipo_estabelecimento_saude_id'],'setores_tp_es_setor_id_tp_es_unique');
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::table('setores_tipos_estabelecimento_saude', function (Blueprint $table) {
            $table->dropUnique('setores_tp_es_setor_id_tp_es_unique');
        });
    }
}
