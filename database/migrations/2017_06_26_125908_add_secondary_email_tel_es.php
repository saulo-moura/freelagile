<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class AddSecondaryEmailTelEs extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up() {
        Schema::table('estabelecimentos_saude', function (Blueprint $table) {
            $table->string('email_alternativo_diretor',255)->nullable();
            $table->string('telefone_alternativo_diretor',11)->nullable();
            $table->string('email_alternativo_responsavel_estagio',255)->nullable();
            $table->string('telefone_alternativo_responsavel_estagio',11)->nullable();
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down() {
        Schema::table('estabelecimentos_saude', function (Blueprint $table) {
            $table->dropColumn('email_alternativo_diretor');
            $table->dropColumn('telefone_alternativo_diretor');
            $table->dropColumn('email_alternativo_responsavel_estagio');
            $table->dropColumn('telefone_alternativo_responsavel_estagio');
        });
    }
}
