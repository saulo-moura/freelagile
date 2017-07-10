<?php

namespace Tests\Unit;

use Tests\TestCase;
use App\Role;
use App\User;
use App\Task;

class TaskTest extends TestCase
{
    /**
     * Test show api
     */
    public function testApiShow()
    {
        $task = Task::first();

        $response = $this->get($this->apiPath . '/tasks/' . $task->id, $this->createAuthHeaderToAdminUser());
        $response->assertStatus(200);

        $response->assertJsonStructure([
            'id', 'description', 'done', 'priority', 'scheduled_to', 'project_id', 'created_at', 'updated_at'
        ]);
    }

    /**
     * Test list api
     */
    public function testApiList()
    {
        $response = $this->get($this->apiPath . '/tasks', $this->createAuthHeaderToAdminUser());
        $response->assertStatus(200);

        $response->assertJsonStructure([ '*' => [
            'id', 'description', 'done', 'priority', 'scheduled_to', 'project_id', 'created_at', 'updated_at'
        ]]);
    }
}
