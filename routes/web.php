<?php

/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Here is where you can register web routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| contains the "web" middleware group. Now create something great!
|
*/

Route::get('/', function () {
    return File::get(public_path().'/client/index.html');
});

Route::get('storage/instituicoes/{id}/{filename}', function ($id, $filename) {
    $path = storage_path('app/instituicoes/'. $id . '/' . $filename);

    if (!File::exists($path)) {
        abort(404);
    }

    $file = File::get($path);
    $type = File::mimeType($path);

    $response = Response::make($file, 200);
    $response->header("Content-Type", $type);

    return $response;
});

Route::group(['middleware' => 'develop.auth'], function () {
    Route::get('decompose', '\Lubusin\Decomposer\Controllers\DecomposerController@index');
});
