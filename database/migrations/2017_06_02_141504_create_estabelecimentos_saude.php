<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class CreateEstabelecimentosSaude extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create('estabelecimentos_saude', function (Blueprint $table) {
            $table->increments('id');
            $table->string('nome', 150);
            $table->string('sigla', 6)->nullable();
            $table->string('cnes', 10)->unique();
            $table->string('cpf_cnpj', 14)->nullable();
            $table->string('endereco');
            $table->string('bairro');
            $table->string('cep', 8);
            $table->integer('estado_id')->unsigned();
            $table->integer('municipio_id')->unsigned();
            $table->integer('nucleo_regional_id')->nullable();
            $table->integer('natureza_juridica_id')->nullable();
            $table->integer('tipo_id')->unsigned()->nullable();
            $table->string('nome_diretor')->nullable();
            $table->string('email_diretor')->nullable();
            $table->string('telefone_diretor', 11)->nullable();
            $table->string('nome_responsavel_estagio')->nullable();
            $table->string('email_responsavel_estagio')->nullable();
            $table->string('telefone_responsavel_estagio', 11)->nullable();
            $table->foreign('tipo_id')->references('id')->on('tipos_estabelecimento_saude');
            $table->foreign('estado_id')->references('id')->on('estados');
            $table->foreign('municipio_id')->references('id')->on('municipios');
            $table->timestampTz('created_at');
            $table->timestampTz('updated_at');
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::dropIfExists('estabelecimentos_saude');
    }
}
