<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class CreateTableProjectsFreelagile extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up() { 
        Schema::dropIfExists('tasks');
        Schema::dropIfExists('projects');
        Schema::create('projects', function (Blueprint $table) {
            $table->increments('id');
            $table->string('name');
            $table->longText('description');
            $table->integer('owner')->unsigned();
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down() {
        Schema::dropIfExists('tasks');
        Schema::dropIfExists('projects');
        Schema::create('projects', function (Blueprint $table) {
            $table->increments('id');
            $table->string('name', 100)->unique()->index();
            $table->decimal('cost', 12, 2);

            $table->timestampTz('created_at');
            $table->timestampTz('updated_at');
        });
        Schema::create('tasks', function (Blueprint $table) {
            $table->increments('id');
            $table->text('description');
            $table->boolean('done');
            $table->tinyInteger('priority');
            $table->dateTimeTz('scheduled_to')->nullable();

            $table->integer('project_id')->unsigned();
            $table->foreign('project_id')->references('id')->on('projects')
                ->onDelete('cascade');

            $table->timestampTz('created_at');
            $table->timestampTz('updated_at');
        });
    }
}
