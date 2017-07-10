<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class CreateSetoresTiposTable extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create('setores_tipos_estabelecimento_saude', function (Blueprint $table) {
            $table->increments('id');
            $table->integer('setor_id')->unsigned();
            $table->integer('tipo_estabelecimento_saude_id')->unsigned();
            $table->timestampTz('created_at');
            $table->timestampTz('updated_at');

            $table->foreign('setor_id')->references('id')->on('setores');
            $table->foreign('tipo_estabelecimento_saude_id','setores_tp_es_tp_es_foreign')->references('id')->on('tipos_estabelecimento_saude');
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::dropIfExists('setores_tipos_estabelecimento_saude');
    }
}
