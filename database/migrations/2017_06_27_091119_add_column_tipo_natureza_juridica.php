<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class AddColumnTipoNaturezaJuridica extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up() {
        Schema::table('naturezas_juridicas', function (Blueprint $table) {
            $table->integer('tipo_natureza_juridica')->unsigned();
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down() {
        Schema::table('naturezas_juridicas', function (Blueprint $table) {
            $table->dropColumn('tipo_natureza_juridica');
        });
    }
}
