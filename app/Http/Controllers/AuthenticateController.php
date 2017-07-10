<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

use App\Http\Requests;
use App\Http\Controllers\Controller;
use JWTAuth;
use Tymon\JWTAuth\Exceptions\JWTException;
use App\User;
use Adldap\Laravel\Facades\Adldap;

class AuthenticateController extends Controller
{
    public function __construct()
    {
    }

    public function authenticate(Request $request)
    {
        $credentials = $request->only('cpf', 'password');

        $this->validate($request, [
            'cpf' => 'required',
            'password' => 'required'
        ]);

        try {
            //check if need to use authentication through ldap
            if (env('AUTHENTICATION_MODE') === 'ldap') {
                if (!$token = $this->authenticateInLDAPAndCreateToken($credentials)) {
                    return response()->json(['error' => 'messages.login.invalidCredentials'], 401);
                }
            } else {
                // verify the credentials and create a token for the user
                if (!$token = JWTAuth::attempt($credentials)) {
                    return response()->json(['error' => 'messages.login.invalidCredentials'], 401);
                }
            }
        } catch (JWTException $e) {
            // something went wrong
            return response()->json(['error' => 'messages.login.unknownError'], 500);
        }

        // if no errors are encountered we can return a JWT
        return response()->json(compact('token'));
    }

    public function getAuthenticatedUser()
    {
        $user = \Auth::user();

        //get simple string array with only a slug
        $user->roles = $user->roles()->get()->toArray();

        // the token is valid and we have found the user via the sub claim
        return response()->json(compact('user'));
    }
    /**
     * Check credentials with ldap.
     * Get a user data in ldap and create a new user in database if not exists.
     * Generate a JWT token with user data
     *
     * @param  $credentials array with email and password
     */
/*    public function authenticateInLDAPAndCreateToken($credentials)
    {
        if (Adldap::auth()->attempt($credentials['email'], $credentials['password'])) {
            $userLdapData = Adldap::search()->users()->find($credentials['email']);

            //check if exits a user in database with email
            $user = User::where(['email' => $credentials['email']])->first();

            //create a user in database if not exists
            if (!$user) {
                $user = new User([
                    'email' => $credentials['email'],
                    'name' => $userLdapData['attributes']['displayname'][0]
                ]);
                $user->password = bcrypt($credentials['password']);
                $user->save();
            }

            //generate a token using user data
            return JWTAuth::fromUser($user);
        }

        return null;
    }*/
}
