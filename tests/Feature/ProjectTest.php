<?php

namespace Tests\Unit;

use Tests\TestCase;
use App\Role;
use App\User;
use App\Project;

class ProjectTest extends TestCase
{
    /**
     * Test show api
     */
    public function testApiShow()
    {
        $project = Project::first();

        $response = $this->get($this->apiPath . '/projects/' . $project->id, $this->createAuthHeaderToAdminUser());
        $response->assertStatus(200);

        $response->assertJsonStructure([
            'id', 'name', 'cost'
        ]);
    }

    /**
     * Test list api
     */
    public function testApiList()
    {
        $response = $this->get($this->apiPath . '/projects', $this->createAuthHeaderToAdminUser());
        $response->assertStatus(200);

        $response->assertJsonStructure([ '*' => [
            'id', 'name', 'cost', 'created_at', 'updated_at',
            'tasks' => [ '*' => [
                'id', 'description', 'done', 'priority', 'scheduled_to', 'project_id', 'created_at', 'updated_at'
            ]]
        ]]);
    }

    /**
     * Test search api
     */
    public function testApiSearch()
    {
        $project = factory(\App\Project::class)->create();

        $project->tasks()->saveMany(factory(\App\Task::class, 2)->states('no-project')->make());

        $header = $this->createAuthHeaderToAdminUser();
        $query = [
            'perPage' => 1,
            'page' => 1,
            'name' => $project->name
        ];

        $response = $this->get($this->apiPath . '/projects?' . http_build_query($query), $header);
        $response->assertStatus(200);

        $response->assertJsonStructure([
            'total',
            'items' => [ '*' => [
                'id', 'name', 'cost', 'created_at', 'updated_at',
                'tasks' => [ '*' => [
                    'id', 'description', 'done', 'priority', 'scheduled_to', 'project_id', 'created_at', 'updated_at'
                ]]
            ]]
        ]);
    }
}
