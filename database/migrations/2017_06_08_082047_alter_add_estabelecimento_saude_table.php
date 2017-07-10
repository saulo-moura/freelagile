<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class AlterAddEstabelecimentoSaudeTable extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::table('vagas', function (Blueprint $table) {
            $table->integer('estabelecimento_saude_id')->unsigned();
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
        Schema::table('vagas', function (Blueprint $table) {
            $table->dropForeign(['estabelecimento_saude_id']);
            $table->dropColumn('estabelecimento_saude_id');
        });
    }
}
