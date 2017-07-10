<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class CreateTableCursosIES extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create('cursos_ies', function (Blueprint $table) {
            $table->increments('id');
            $table->integer('curso_id')->unsigned();
            $table->integer('instituicao_ensino_id')->unsigned();
            $table->integer('campus_id')->unsigned();
            $table->integer('cordenador_id')->unsigned();
            $table->string('email');
            $table->string('telefone', 11);
            $table->timestamp('data_reconhecimento');
            $table->string('nota_enade', 8)->nullable();
            $table->string('autorizacao_funcionamento')->nullable();
            $table->timestampsTz();

            $table->foreign('instituicao_ensino_id')->references('id')->on('instituicoes_ensino_superior');
            $table->foreign('curso_id')->references('id')->on('cursos');
            $table->foreign('campus_id')->references('id')->on('campus');
            $table->foreign('cordenador_id')->references('id')->on('users');

        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::dropIfExists('cursos_ies');
    }
}
