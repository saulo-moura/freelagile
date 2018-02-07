<?php

namespace Tests\Unit;

use Tests\TestCase;
use Illuminate\Foundation\Testing\WithoutMiddleware;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Foundation\Testing\DatabaseTransactions;

use Tymon\JWTAuth\Facades\JWTAuth;
use App\User;

class LoginTest extends TestCase
{

    public function testLoginInvalidCredentials()
    {
        $this->post($this->apiPath . '/authenticate', [
            'email' => 'invalidacredentials@prodeb.com',
            'password' => 'iu33j198uy8'
        ])->assertStatus(401);
    }

    public function testLoginValidCredentials()
    {
        $response = $this->post($this->apiPath . '/authenticate', $this->adminUserData);

        $response->assertStatus(200);
        $response->assertJsonStructure(['token']);
    }

    public function testGetAuthenticatedUserData()
    {
        $response = $this->get($this->apiPath . '/authenticate/user', $this->createAuthHeaderToAdminUser());

        $response->assertJsonStructure(['user' => [
            'email', 'name', 'roles'
        ]]);
    }
}
