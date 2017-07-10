<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class AlterInstituicoesEnsinoSuperiorTable extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::table('instituicoes_ensino_superior', function (Blueprint $table) {
            $table->string('diario_oficial_uniao')->nullable();
            $table->string('alvara_funcionamento')->nullable();
            $table->string('atestado_funcionamento_regular')->nullable();
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
            $table->dropColumn('diario_oficial_uniao');
            $table->dropColumn('alvara_funcionamento');
            $table->dropColumn('atestado_funcionamento_regular');
        });
    }
}
