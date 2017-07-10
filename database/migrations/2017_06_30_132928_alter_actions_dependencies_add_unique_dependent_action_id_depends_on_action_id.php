<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class AlterActionsDependenciesAddUniqueDependentActionIdDependsOnActionId extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::table('actions_dependencies', function (Blueprint $table) {
            $table->unique(['dependent_action_id', 'depends_on_action_id'],'actions_dep_dep_action_id_dep_on_action_id_unique');
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::table('actions_dependencies', function (Blueprint $table) {
            $table->dropUnique('actions_dep_dep_action_id_dep_on_action_id_unique');
        });
    }
}
