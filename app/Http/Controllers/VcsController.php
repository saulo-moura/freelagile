<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Exceptions\BusinessException;

class VcsController extends Controller {
    private $client;

    public function __construct(\Github\Client $client) {
        $this->client = $client;
    }

    public function index(Request $request) {
        $user = $request->username;
        $repo = $request->repo;
        $path = isset($request->path) ? $request->path : '.';

        try {
            $result = $this->client->api('repos')->contents()->show($user, $repo, $path);
            if (isset($result['type']) && $result['type'] == 'file') {
                $data = [];
                $result['content'] = base64_decode($result['content']);
                $data[] = $result;
                return $data;
            }
            return $result;
        } catch (Exception $e) {
            throw new BusinessException($e->getMessage());
        }
    }
}
