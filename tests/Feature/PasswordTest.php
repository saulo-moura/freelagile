<?php

namespace Tests\Unit;

use Tests\TestCase;
use Illuminate\Foundation\Testing\WithoutMiddleware;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Foundation\Testing\DatabaseTransactions;

use Tymon\JWTAuth\Facades\JWTAuth;
use App\User;

class PasswordTest extends TestCase
{

    /**
     * Test api to send reset password mail
     */
    public function testApiSendResetMail()
    {
        $user = factory(\App\User::class)->create();
        $response = $this->post($this->apiPath . '/password/email', collect($user)->only('email')->toArray());
        $response->assertStatus(200);
    }
}
