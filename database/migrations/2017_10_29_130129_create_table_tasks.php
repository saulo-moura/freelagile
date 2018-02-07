<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class CreateTableTasks extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up() {
        Schema::create('tasks', function (Blueprint $table) {
            $table->increments('id');
            $table->string('title');
            $table->text('description');
            $table->boolean('done');
            $table->unsignedInteger('milestone_id')->nullable();
            $table->unsignedInteger('status_id');
            $table->unsignedInteger('priority_id');
            $table->timestampsTz();
        });

        Schema::table('tasks', function (Blueprint $table) {
            $table->foreign('milestone_id')->references('id')->on('milestones');
            $table->foreign('priority_id')->references('id')->on('priorities');
            $table->foreign('status_id')->references('id')->on('status');
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down() {
        Schema::dropIfExists('tasks');
    }
}
