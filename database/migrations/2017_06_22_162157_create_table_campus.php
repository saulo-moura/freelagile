<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class CreateTableCampus extends Migration{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up(){
        Schema::create('campus', function (Blueprint $table) {
            $table->increments('id');
            $table->string('nome', 150);
            $table->string('endereco', 255);
            $table->string('bairro', 255);
            $table->string('cep', 8);
            $table->integer('municipio_id')->unsigned();
            $table->integer('instituicao_ensino_id')->unsigned();
            $table->timestampsTz();

            $table->foreign('municipio_id')->references('id')->on('municipios');
            $table->foreign('instituicao_ensino_id')->references('id')->on('instituicoes_ensino_superior');

        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down() {
        Schema::dropIfExists('campus');
    }
}
