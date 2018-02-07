<?php

namespace Tests\Unit;

use Tests\TestCase;
use Illuminate\Foundation\Testing\WithoutMiddleware;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Foundation\Testing\DatabaseTransactions;

use Tymon\JWTAuth\Facades\JWTAuth;
use Tymon\JWTAuth\Facades\JWTFactory;
use App\User;

class TokenTest extends TestCase
{
    public function testTokenNotProvided()
    {
        $response = $this->get($this->apiPath . '/authenticate/check');
        $response->assertStatus(400);
        $response->assertJson(['error' => 'token_not_provided']);
    }
}
