<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class AlterTableProjectsAddColumnsPrice extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up() {
        Schema::table('users', function (Blueprint $table) {
            $table->dropColumn('hour_value');
        });
        Schema::table('projects', function (Blueprint $table) {
            $table->decimal('hour_value_developer')->nullable();
            $table->decimal('hour_value_client')->nullable();
            $table->decimal('hour_value_final')->nullable();
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down() {
        Schema::table('projects', function (Blueprint $table) {
            $table->dropColumn('hour_value_developer');
            $table->dropColumn('hour_value_client');
            $table->dropColumn('hour_value_final');
        });
        Schema::table('projects', function (Blueprint $table) {
            $table->decimal('hour_value')->nullable();
        });
    }
}
