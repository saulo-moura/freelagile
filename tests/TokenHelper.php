<?php

namespace Tests;

use Tymon\JWTAuth\Facades\JWTAuth;
use App\User;

/**
 * Trait with Token functions related
 */
trait TokenHelper
{
     /**
     * Generate authenication headers
     *
     * @param string $token JWTToken
     *
     * @return array Array with the headers using the informed token
     */
    public function createAuthHeader($token)
    {
        return [
            'Accept' => 'application/json',
            'Authorization' => 'Bearer ' . $token
        ];
    }

    /**
    * Generate authenication headers to a admin user
    *
    * @return array Array with the headers
    */
    public function createAuthHeaderToAdminUser()
    {
        return $this->createAuthHeader($this->getTokenFromAdminUser());
    }

    /**
    * Generate authenication headers to a informed user
    *
    * @return array Array with the headers
    */
    public function createAuthHeaderToUser($user)
    {
        $token = JWTAuth::fromUser($user);
        return $this->createAuthHeader($token);
    }

    /**
    * Generate authenication headers to a normal user
    *
    * @return array Array with the headers
    */
    public function createAuthHeaderToNormalUser()
    {
        return $this->createAuthHeader($this->getTokenFromNormalUser());
    }

    /**
    * Generate a JWT token to admin user
    *
    * @return string Token in JWT standard
    */
    public function getTokenFromAdminUser()
    {
        $admin = User::where('email', $this->adminUserData['email'])->first();
        return JWTAuth::fromUser($admin);
    }

    /**
    * Generate a JWT token to normal user
    *
    * @return string Token in JWT standard
    */
    public function getTokenFromNormalUser()
    {
        $user = User::where('email', $this->normalUserData['email'])->first();
        return JWTAuth::fromUser($user);
    }
}
