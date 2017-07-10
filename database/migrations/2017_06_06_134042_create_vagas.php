<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class CreateVagas extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create('vagas', function (Blueprint $table) {
            $table->increments('id');
            $table->integer('curso_id')->unsigned();
            $table->integer('modalidade_id')->unsigned();
            $table->integer('area_id')->unsigned();
            $table->integer('setor_id')->unsigned();
            $table->integer('status_id')->unsigned();
            $table->date('data_inicio');
            $table->date('data_fim');
            $table->timestampTz('created_at');
            $table->timestampTz('updated_at');
            
            $table->foreign('curso_id')->references('id')->on('cursos');
            $table->foreign('modalidade_id')->references('id')->on('modalidades');
            $table->foreign('area_id')->references('id')->on('areas');
            $table->foreign('setor_id')->references('id')->on('setores');
            $table->foreign('status_id')->references('id')->on('status');
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::dropIfExists('vagas');
    }
}
