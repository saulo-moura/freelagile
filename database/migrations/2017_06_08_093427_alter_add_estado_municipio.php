<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class AlterAddEstadoMunicipio extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::table('estabelecimentos_saude', function (Blueprint $table) {
            $table->integer('estado_id')->nullable();
            $table->integer('municipio_id')->nullable();
            $table->string('sigla', 7)->nullable();
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::table('estabelecimentos_saude', function (Blueprint $table) {
            $table->dropColumn(['sigla']);
            $table->dropColumn(['municipio_id']);
            $table->dropColumn(['estado_id']);
        });
    }
}
