<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class AlterTableProjectsAddColumnsGithubIntegration extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up() {
        Schema::table('projects', function (Blueprint $table) {
            $table->string('username_github')->nullable();
            $table->string('repo_github')->nullable();
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down() {
        Schema::table('projects', function (Blueprint $table) {
            $table->dropColumn('username_github');
            $table->dropColumn('repo_github');
        });
    }
}
