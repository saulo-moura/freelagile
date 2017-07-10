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
Route::options(
    '{all}', function () {
        //Trata as requisições OPTIONS preflight
        return \Response::json('{"method":"OPTIONS"}', 200, \Prodeb::getCORSHeaders());
    }
)->where('all', '.*');

Route::group(
    ['prefix' => 'v1', 'middleware' => 'cors'], function () {
        //public area
        Route::post('authenticate', 'AuthenticateController@authenticate');

        Route::post('password/email', 'PasswordController@postEmail');
        Route::post('password/reset', 'PasswordController@postReset');

        Route::group(
            ['prefix' => 'support'], function () {
                Route::get('langs', 'SupportController@langs');
            }
        );

        Route::get(
            'authenticate/check', function () {
                return response()->json(['status' => 'valid']);
            }
        )->middleware('jwt.auth'); //just to check the token

        //Rota para municipios
        Route::get('/municipios', 'MunicipiosController@index');

        //Rota para estados
        Route::get('/estados', 'EstadosController@index');

        //Rota para nucleos regionais
        Route::get('/nucleos-regionais', 'NucleosRegionaisController@index');

        //Rota para areas
        Route::get('/areas', 'AreasController@index');

        //Rota para modalidades
        Route::get('/modalidades', 'ModalidadesController@index');

        //Rota para status
        Route::get('/status', 'StatusController@index');

        //Rota para setores
        Route::get('setores', 'SetoresController@index');

        //Rota para vagas/historico
        Route::get('vagas/historico', 'VagasController@historico');

        //Rota para tipos de estabelecimento de saude
        Route::get('/tipos-estabelecimento-saude', 'TiposEstabelecimentoSaudeController@index');

        //Rota para Painel de Controle
        Route::get('/parametros-sistema', 'ParametrosSistemaController@index');

        //Rota para ativar usuario
        Route::put('users/ativar', 'UsersController@ativar');

        //Rota para Campus
        Route::get('campus', 'CampusController@index');

        //Rota para Natureza Juridica
        Route::get('naturezas-juridicas', 'NaturezasJuridicasController@index');

        //Rota para Especiliadade
        Route::get('especialidades', 'EspecialidadesController@index');

        //Rota para Especificacao
        Route::get('especificacoes', 'EspecificacoesController@index');

        //Rota para cursos
        Route::get('cursos', 'CursosController@index');

        //Rota para estabelecimentos saude
        Route::get('estabelecimentos-saude', 'EstabelecimentosSaudeController@index');

        //Rota para instiruições de ensino
        Route::get('instituicoes-ensino', 'InstituicoesEnsinoController@index');

        //authenticated area
        Route::group(
            ['middleware' => ['jwt.auth', 'jwt.refresh', 'acl.permission']], function () {
                Route::get('authenticate/user', 'AuthenticateController@getAuthenticatedUser');

                //Rota para Especiliadade
                Route::resource('especialidades', 'EspecialidadesController', ['except' => ['index']]);

                //Rota para Especificacao
                Route::resource('especificacoes', 'EspecificacoesController', ['except' => ['index']]);

                //Rota para cursos
                Route::resource('cursos', 'CursosController', ['except' => ['index']]);

                //Rota para Natureza Juridica
                Route::resource('naturezas-juridicas', 'NaturezasJuridicasController', ['except' => ['index']]);

                //Rota para Campus
                Route::resource('campus', 'CampusController', ['except' => ['index']]);

                //Rota para setores
                Route::resource('setores', 'SetoresController', ['except' => ['index']]);

                //Rota para areas
                Route::resource('areas', 'AreasController', ['except' => ['index']]);

                //Rota para modalidades
                Route::resource('modalidades', 'ModalidadesController', ['except' => ['index']]);

                //Rota para tipos de estabelecimento de saude
                Route::resource('tipos-estabelecimento-saude', 'TiposEstabelecimentoSaudeController', ['except' => ['index']]);

                //Rota para Painel de Controle
                Route::resource('parametros-sistema', 'ParametrosSistemaController', ['except' => ['index']]);

                //Rota para relatorio de estabelecimentos saude
                Route::get('relatorio-estabelecimentos-saude', 'EstabelecimentosSaudeController@index');

                //Rota para relatorio de disponibilidade de vaga
                Route::get('relatorio-disponibilidade-vagas', 'VagasController@index');

                Route::resource('projects', 'Samples\ProjectsController');

                //Rota para estabelecimentos saude
                Route::resource('estabelecimentos-saude', 'EstabelecimentosSaudeController', ['except' => ['index']]);

                //Rota para instiruições de ensino
                Route::resource('instituicoes-ensino', 'InstituicoesEnsinoController', ['except' => ['index']]);
                Route::post('instituicoes-ensino/{id}/upload-arquivos', 'InstituicoesEnsinoController@uploadArquivos');
                Route::post('instituicoes-ensino/{id}/excluir-arquivos', 'InstituicoesEnsinoController@excluirArquivos');

                //Rota para instiruições de ensino cursos
                Route::resource('instituicoes-ensino-cursos', 'InstituicoesEnsinoCursosController', ['except' => ['index']]);

                Route::resource('roles', 'RolesController');

                //Rota para disponibilidade de vagas
                Route::resource('/vagas', 'VagasController', ['except' => ['historico']]);

                //this route maps the request to the appropriated controller method
                //for example: /unidades-de-trabalho/modelo-gestao will be routed to the method DomainsController@modeloGestao
                Route::get('/authorization/{domainName}', 'AuthorizationController@getDomainData');

                Route::put('tasks/toggleDone', 'Samples\TasksController@toggleDone');
                Route::resource('tasks', 'Samples\TasksController');

                Route::resource(
                    'mails',
                    'MailsController',
                    ['only' => ['store']]
                );

                Route::put('profile', 'UsersController@updateProfile');

                Route::resource('users', 'UsersController', ['except' => ['updateProfile']]);

                //admin area
                Route::group(
                    ['middleware' => ['acl.role:admin']], function () {
                        Route::get('audit', 'AuditController@index');
                        Route::get('audit/models', 'AuditController@models');
                        Route::group(
                            ['prefix' => 'dinamicQuery'], function () {
                                Route::get('/', 'DinamicQueryController@index');
                                Route::get('models', 'DinamicQueryController@models');
                            }
                        );
                    }
                );
            }
        );
    }
);
