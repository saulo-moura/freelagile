<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class CreateHorariosTable extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create('horarios', function (Blueprint $table) {
            $table->increments('id');
            $table->integer('vaga_id')->unsigned();
            $table->integer('qtd_vagas');
            $table->string('titulo', 255);
            $table->integer('dia_semana');
            $table->integer('tipo_horario_id')->unsigned();
            $table->timestampTz('created_at');
            $table->timestampTz('updated_at');

            $table->foreign('vaga_id')->references('id')->on('vagas');
            $table->foreign('tipo_horario_id')->references('id')->on('tipos_horario');
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::dropIfExists('horarios');
    }
}
