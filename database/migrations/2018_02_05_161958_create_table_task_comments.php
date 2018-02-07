<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class CreateTableTaskComments extends Migration {
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up() {
        Schema::create('task_comments', function (Blueprint $table) {
            $table->increments('id');
            $table->text('description');
            $table->unsignedInteger('task_id');
            $table->unsignedInteger('comment_id')->nullable();
            $table->timestampsTz();

            $table->foreign('task_id')->references('id')->on('tasks');
            $table->foreign('comment_id')->references('id')->on('task_comments');
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down() {
        Schema::dropIfExists('task_comments');
    }
}
