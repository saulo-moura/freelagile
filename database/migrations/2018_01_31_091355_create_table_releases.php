<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class CreateTableReleases extends Migration {
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up() {
        Schema::create('releases', function (Blueprint $table) {
            $table->increments('id');
            $table->string('title');
            $table->text('description');
            $table->boolean('done');
            $table->unsignedInteger('project_id')->nullable();
            $table->timestampsTz();

            $table->foreign('project_id')->references('id')->on('projects');
        });

        Schema::table('milestones', function (Blueprint $table) {
            $table->unsignedInteger('release_id')->nullable();
            $table->foreign('release_id')->references('id')->on('releases');
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down() {
        Schema::table('milestones', function (Blueprint $table) {
            $table->dropColumn('release_id');
        });

        Schema::dropIfExists('releases');
    }
}
