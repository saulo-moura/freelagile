<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class AlterRemoveNucleoRegionalIdFromEstabelecimentosSaudeTable extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::table('estabelecimentos_saude', function (Blueprint $table) {
            $table->dropColumn('nucleo_regional_id');
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
            $table->integer('nucleo_regional_id')->nullable();
        });
    }
}
