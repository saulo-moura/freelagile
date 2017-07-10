<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class AlterNaturezasJuridicasAddUniqueContraintNomeTipoNaturezaJuridica extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::table('naturezas_juridicas', function (Blueprint $table) {
            $table->unique(['nome', 'tipo_natureza_juridica']);
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::table('naturezas_juridicas', function (Blueprint $table) {
            $table->dropUnique('naturezas_juridicas_nome_tipo_natureza_juridica_unique');
        });
    }
}
