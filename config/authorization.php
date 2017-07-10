<?php
/*
 * This file is part of the Starter Pack Dynamic Authorization
 *
 * @author Amon Santana <amoncaldas@gmail.com>
 */

return [

    /* ------------------------------------------------------------------------------------------------
     |  Se os valores de allowNotListedControllers ou allowNotListedActions forem definidos como true
     |  o módulo de autorização passará a não controlar ações que forem executadas (aquelas não delclaradas neste aquivo)
     |  Isso pode abrir uma breach de segurança, então TENHA CERTEZA DO QUE ESTÁ FAZENDO!
     | ------------------------------------------------------------------------------------------------
     */
    /* Se definido como true, PERMITE que sejam executadas ações em controllers que não constam na listagem de resources */
    /* Se definido como false, NÃO PERMITE que sejam executadas ações em controlles que não constam na listagem de resources */
    //'allowNotListedControllers'=>false,

    /* Se definido como true, PERMITE que sejam executadas ações não listadas em um dado resource listado abaixo */
    /* Se definido como false, NÃO PERMITE que sejam executadas ações não listadas em um dado resource listado abaixo */
    //'allowNotListedActions'=>false,

    /* ------------------------------------------------------------------------------------------------
     |  Tipos de ações que podem ser associadas como permissão para cada recurso
     |  all, index, store, update e destroy são as ações padrões, implemtadas pelos controllers
     |  que herdam do CrudController. NÃO DEVEM SER REMOVIDAS
     | ------------------------------------------------------------------------------------------------
     */
    'actionTypes' => [
        /*## AÇÕES PADRÕES IMPLEMENTADAS PELO CrudController ##*/
        'all'=>['name' => 'Todas'],
        'index'=>['name' => 'Listar'],
        'store'=>['name' => 'Criar'],
        'update'=>['name' => 'Atualizar'],
        'destroy'=>['name' => 'Excluir'],
        /*## FIM DAS AÇÕES CRUD ##*/

        /*## OUTRAS AÇÕES IMPLEMENTADAS PELO StarterPack ##*/
        'authenticate'=>['name'=>'Autenticar'],
        'getAuthenticatedUser'=>['name'=>'Recuperar Usuário Autenticado'],
        'resources'=>['name' => 'Listar recursos'],
        'actions'=>['name' => 'Listar ações'],
        'updateProfile'=>['name' => 'Atualizar Senha'],

        /*## FIM DAS AÇÕES PADRÕES ##*/

        /* Aqui vem ações adicionais necessárias ao negócio. */
        /* Cada ação representa um método com mesmo nome no controller do recurso que vai lsitar essa ação como possível*/
        'approve'=>['name' => 'Aprovar'],
        'listarPendentes'=>['name' => 'Listar Pendentes'],
        'gerarRelatorio'=>['name' => 'Gerar Relatório'],
        'excluirArquivos' => ['name' => 'Exclusão de Arquivos'],
        'uploadArquivos' => ['name' => 'Upload de Arquivos'],
    ],

     /* ------------------------------------------------------------------------------------------------
     |  Recursos que passarão pela verificação da autorização dinâmica
     | ------------------------------------------------------------------------------------------------
     */
    'resources' => [
        /*## RECURSOS DO SISTEMA. NÃO DEVE SER REMOVIDO! ##*/
        'all'=>['name' => 'Todos', 'actions'=>['all','store','update','destroy']],

        // User
        'users'=>['name' => 'Usuários','controller_class'=>'UsersController',
            'actions'=>['all','store','update','destroy','index', 'updateProfile']
        ],


          // Roles
        'authorization'=>['name' => 'Autorizações','controller_class'=>'AuthorizationController',
             'actions'=>['all','resources','actions', 'getDomainData']
        ],

        // Roles
        'roles'=>['name' => 'Perfis','controller_class'=>'RolesController',
             'actions'=>[
                 'all',
                 [
                     'slug'=>'store',
                     'dependencies'=>[
                          ['resource_slug'=>'authorization','action_type_slug'=>'resources'],
                          ['resource_slug'=>'authorization','action_type_slug'=>'actions'],
                     ]
                 ],
                 [
                     'slug'=>'update',
                     'dependencies'=>[
                          ['resource_slug'=>'authorization','action_type_slug'=>'resources'],
                          ['resource_slug'=>'authorization','action_type_slug'=>'actions'],
                     ]
                 ],
                 'destroy',
                 'index'
             ]
        ],

        // Authentication
        'authentication'=>['name' => 'Autenticação','controller_class'=>'AuthenticateController',
            'actions'=>
            [
                'getAuthenticatedUser',
                [
                    'slug'=>'authenticate',
                    'dependencies'=>
                    [
                         ['resource_slug'=>'authentication','action_type_slug'=>'getAuthenticatedUser']
                    ]

                ]
            ]
        ],

        'estabelecimentosSaude'=>['name' => 'Estabelecimento de Saúde','controller_class'=>'EstabelecimentosSaudeController',
             'actions'=>['all','store','update','destroy','index', 'listarPendentes']
        ],

        'instituicoesEnsino'=>['name' => 'Instituições de Ensino','controller_class'=>'InstituicoesEnsinoController',
             'actions'=>['all','store','update','destroy','index', 'excluirArquivos', 'uploadArquivos']
        ],

        'especialidades'=>['name' => 'Especialidades','controller_class'=>'EspecialidadesController',
             'actions'=>['all','store','update','destroy','index']
        ],

        'especificacoes'=>['name' => 'Especificações','controller_class'=>'EspecificacoesController',
             'actions'=>['all','store','update','destroy','index']
        ],

        'cursos'=>['name' => 'Cursos','controller_class'=>'CursosController',
             'actions'=>['all','store','update','destroy','index']
        ],

        'modalidades'=>['name' => 'Modalidades','controller_class'=>'ModalidadesController',
             'actions'=>['all','store','update','destroy','index']
        ],

        'vagas'=>['name' => 'Vagas','controller_class'=>'VagasController',
            'actions'=>[
                'all'
		,'store'
                ,'update'
                ,'destroy'
                ,'index'
                ,'approve'
                ,[
                    'slug'=>'gerarRelatorio',
                    'dependencies'=>[
                        ['resource_slug'=>'vagas','action_type_slug'=>'index']
                    ]
                ]
            ]
        ],

        // Painel de Controle
        'parametrosSistema'=>['name' => 'Painel de Controle','controller_class'=>'ParametrosSistemaController',
            'actions'=>['all','store','update','destroy', 'index']
        ],

        // Tipos de ES
        'tiposEstabelecimentoSaude'=>['name' => 'Tipos de Estabelecimento de Saude','controller_class'=>'TiposEstabelecimentoSaudeController',
            'actions'=>['all','store','update','destroy', 'index']
        ],

        // Natureza Juridica
        'naturezasJuridicas'=>['name' => 'Naturezas Jurídicas','controller_class'=>'NaturezasJuridicasController',
            'actions'=>['all','store','update','destroy', 'index']
        ],

        // Area
        'areas'=>['name' => 'Áreas','controller_class'=>'AreasController',
            'actions'=>['all','store','update','destroy', 'index']
        ],

        // Setor
        'setores'=>['name' => 'Setores','controller_class'=>'SetoresController',
            'actions'=>['all','store','update','destroy', 'index']
        ],

        // Campus
        'campus'=>['name' => 'Campus','controller_class'=>'CampusController',
            'actions'=>['all','store','update','destroy', 'index']
        ]
    ]
];
