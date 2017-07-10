<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class AddNucleoRegionalIdToMunicipioTable extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::table('municipios', function (Blueprint $table) {
            $table->integer('nucleo_regional_id')->unsigned()->nullable()->unsigned();
            $table->foreign('nucleo_regional_id')->references('id')->on('nucleos_regionais');
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::table('municipios', function (Blueprint $table) {
            $table->dropForeign(['nucleo_regional_id']);
            $table->dropColumn('nucleo_regional_id');
        });
    }
}
