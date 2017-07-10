<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class AlterIntituicoesEnsinoTable extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::table('instituicoes_ensino_superior', function (Blueprint $table) {
            $table->string('razao_social')->nullable();
            $table->string('cnpj')->nullable();
            $table->string('mantenedora')->nullable();
            $table->string('cnpj_mantenedora')->nullable();
            $table->integer('natureza_juridica_id')->nullable();
            $table->string('endereco')->nullable();
            $table->string('numero')->nullable();
            $table->string('complemento')->nullable();
            $table->string('bairro')->nullable();
            $table->string('cep')->nullable();
            $table->integer('municipio_id')->nullable();
            $table->integer('nucleo_regional_id')->nullable();
            $table->string('telefone')->nullable();
            $table->string('telefone2')->nullable();
            $table->string('telefone3')->nullable();
            $table->decimal('igc')->nullable();
            $table->string('email')->nullable();
            $table->string('email2')->nullable();
            $table->string('email3')->nullable();
            $table->string('nome_reitor')->nullable();
            $table->string('telefone_reitor')->nullable();
            $table->string('telefone_reitor2')->nullable();
            $table->string('email_reitor')->nullable();
            $table->string('cpf_reitor')->nullable();
            $table->string('rg_reitor')->nullable();
            $table->boolean('validado')->default(0);
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::table('instituicoes_ensino_superior', function (Blueprint $table) {
            
            $table->dropColumn('razao_social');
            $table->dropColumn('cnpj');
            $table->dropColumn('mantenedora');
            $table->dropColumn('cnpj_mantenedora');
            $table->dropColumn('natureza_juridica_id');
            $table->dropColumn('endereco');
            $table->dropColumn('numero');
            $table->dropColumn('complemento');
            $table->dropColumn('bairro');
            $table->dropColumn('cep');
            $table->dropColumn('municipio_id');
            $table->dropColumn('nucleo_regional_id');
            $table->dropColumn('telefone');
            $table->dropColumn('telefone2');
            $table->dropColumn('telefone3');
            $table->dropColumn('igc');
            $table->dropColumn('email');
            $table->dropColumn('email2');
            $table->dropColumn('email3');
            $table->dropColumn('nome_reitor');
            $table->dropColumn('telefone_reitor');
            $table->dropColumn('telefone_reitor2');
            $table->dropColumn('email_reitor');
            $table->dropColumn('cpf_reitor');
            $table->dropColumn('rg_reitor');
            $table->dropColumn('validado');
        });
    }
}
