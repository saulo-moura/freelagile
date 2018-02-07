<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class AlterTableProjectAddColumnsRoles extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up() {
        Schema::table('projects', function (Blueprint $table) {
            $table->unsignedInteger('client_id')->nullable();
            $table->unsignedInteger('dev_id')->nullable();
            $table->unsignedInteger('stakeholder_id')->nullable();

            $table->foreign('client_id')->references('id')->on('users');
            $table->foreign('dev_id')->references('id')->on('users');
            $table->foreign('stakeholder_id')->references('id')->on('users');
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down() {
        Schema::table('projects', function (Blueprint $table) {
            $table->dropColumn('client_id');
            $table->dropColumn('dev_id');
            $table->dropColumn('stakeholder_id');
        });
    }
}
