<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class AlterEstabelecimentoSaudeAddNullable extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::table('estabelecimentos_saude', function (Blueprint $table) {
            $table->string('endereco')->nullable()->change();
            $table->string('bairro')->nullable()->change();
            $table->string('cep')->nullable()->change();
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
            $table->string('endereco')->change();
            $table->string('bairro')->change();
            $table->string('cep')->change();
        });
    }
}
