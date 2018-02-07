<?php

use Illuminate\Http\Request;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

// preflight to CORS
Route::options('{all}', function () {
    //Trata as requisições OPTIONS preflight
    return \Response::json('{"method":"OPTIONS"}', 200, \Prodeb::getCORSHeaders());
})->where('all', '.*');

Route::group(['prefix' => 'v1', 'middleware' => 'cors'], function () {
    //public area
    Route::post('authenticate', 'AuthenticateController@authenticate');

    Route::post('password/email', 'PasswordController@postEmail');
    Route::post('password/reset', 'PasswordController@postReset');

    Route::group(['prefix' => 'support'], function () {
        Route::get('langs', 'SupportController@langs');
    });

    Route::get('authenticate/check', function () {
        return response()->json(['status' => 'valid']);
    })->middleware('jwt.auth'); //just to check the token

    Route::post('users', 'UsersController@store');

    //authenticated area
    Route::group(['middleware' => ['jwt.auth', 'jwt.refresh']], function () {
        Route::get('authenticate/user', 'AuthenticateController@getAuthenticatedUser');

        Route::resource('users', 'UsersController', ['except' => ['updateProfile', 'store']]);

        Route::resource('projects', 'ProjectsController');
        Route::resource('roles', 'RolesController', ['only' => ['index']]);
        Route::resource('dashboards', 'DashboardsController');
        Route::resource('status', 'StatusController');
        Route::resource('types', 'TypesController');
        Route::resource('priorities', 'PrioritiesController');

        Route::resource('milestones', 'MilestonesController');
        Route::post('milestones/finalize', 'MilestonesController@finalize');
        Route::post('milestones/updateRelease', 'MilestonesController@updateRelease');

        Route::resource('tasks', 'TasksController', ['except' => ['updateMilestone', 'toggleDone', 'updateTaskByKanban']]);
        Route::put('tasks/toggleDone', 'TasksController@toggleDone');
        Route::post('tasks/updateMilestone', 'TasksController@updateMilestone');
        Route::post('tasks/updateTaskByKanban', 'TasksController@updateTaskByKanban');
        Route::resource('kanban', 'TasksController');

        Route::resource('releases', 'ReleasesController');
        Route::post('releases/finalize', 'ReleasesController@finalize');

        Route::post('task-comments/saveTaskComment', 'CommentsController@saveTaskComment');
        Route::post('task-comments/removeTaskComment', 'CommentsController@removeTaskComment');

        // Rotas da API Github
        Route::get('vcs', 'VcsController@index');

        Route::resource(
            'mails',
            'MailsController',
            ['only' => ['store']]
        );

        Route::put('profile', 'UsersController@updateProfile');

        //admin area
        Route::group(['middleware' => ['acl.role:admin']], function () {
            Route::get('audit', 'AuditController@index');
            Route::get('audit/models', 'AuditController@models');

            Route::group(['prefix' => 'dinamicQuery'], function () {
                Route::get('/', 'DinamicQueryController@index');
                Route::get('models', 'DinamicQueryController@models');
            });
        });
    });
});
