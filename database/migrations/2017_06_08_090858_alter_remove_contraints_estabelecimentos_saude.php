<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class AlterRemoveContraintsEstabelecimentosSaude extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::table('estabelecimentos_saude', function (Blueprint $table) {
            $table->dropForeign(['municipio_id']);
            $table->dropForeign(['estado_id']);
            $table->dropColumn('municipio_id');
            $table->dropColumn('estado_id');
            $table->dropColumn('sigla');
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::table('estabelecimentos_saude', function (Blueprint $table) {
            $table->string('sigla', 6)->nullable();
            $table->integer('estado_id')->unsigned();
            $table->integer('municipio_id')->unsigned();
            $table->foreign('estado_id')->references('id')->on('estados');
            $table->foreign('municipio_id')->references('id')->on('municipios');
        });
    }
}
