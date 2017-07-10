<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class AlterCampusAddUniqueConstraints extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up() {
        Schema::table('campus', function (Blueprint $table) {
            $table->unique(['nome', 'municipio_id', 'instituicao_ensino_id']);
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down() {
       Schema::table('campus', function (Blueprint $table) {
            $table->dropUnique('campus_nome_municipio_id_instituicao_ensino_id_unique');
        });
    }
}
