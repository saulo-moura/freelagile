<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class AddInstituicoesEstabelecimentosUsersTable extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::table('users', function (Blueprint $table) {
            $table->integer('instituicao_ensino_id')->unsigned()->after('id')->nullable();
            $table->integer('estabelecimento_saude_id')->unsigned()->after('id')->nullable();

            $table->foreign('instituicao_ensino_id')->references('id')->on('instituicoes_ensino_superior'); 
            $table->foreign('estabelecimento_saude_id')->references('id')->on('estabelecimentos_saude'); 
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
         Schema::table('users', function (Blueprint $table) {
            $table->dropForeign(['instituicao_ensino_id']);
            $table->dropColumn('instituicao_ensino_id');            
            
            $table->dropForeign(['estabelecimento_saude_id']);
            $table->dropColumn('estabelecimento_saude_id');            
        });
    }
}
