'use strict';

/*eslint angular/file-name: 0*/
(function () {
  'use strict';

  angular.module('app', ['ngAnimate', 'ngAria', 'ui.router', 'ngProdeb', 'ui.utils.masks', 'text-mask', 'ngMaterial', 'modelFactory', 'md.data.table', 'ngMaterialDatePicker', 'pascalprecht.translate', 'angularFileUpload']);
})();
'use strict';

(function () {
  'use strict';

  config.$inject = ["Global", "$mdThemingProvider", "$modelFactoryProvider", "$translateProvider", "moment", "$mdAriaProvider"];
  angular.module('app').config(config);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function config(Global, $mdThemingProvider, $modelFactoryProvider, // NOSONAR
  $translateProvider, moment, $mdAriaProvider) {

    $translateProvider.useLoader('languageLoader').useSanitizeValueStrategy('escape');

    $translateProvider.usePostCompiling(true);

    moment.locale('pt-BR');

    //os serviços referente aos models vai utilizar como base nas urls
    $modelFactoryProvider.defaultOptions.prefix = Global.apiPath;

    // Configuration theme
    $mdThemingProvider.theme('default').primaryPalette('brown', {
      default: '700'
    }).accentPalette('amber').warnPalette('deep-orange');

    // Enable browser color
    $mdThemingProvider.enableBrowserColor();

    $mdAriaProvider.disableWarnings();
  }
})();
'use strict';

(function () {

  'use strict';

  AppController.$inject = ["$state", "Auth", "Global"];
  angular.module('app').controller('AppController', AppController);

  /** @ngInject */
  /**
   * Controlador responsável por funcionalidades que são acionadas em qualquer tela do sistema
   *
   */
  function AppController($state, Auth, Global) {
    var vm = this;

    //ano atual para ser exibido no rodapé do sistema
    vm.anoAtual = null;

    vm.logout = logout;
    vm.getImagePerfil = getImagePerfil;

    activate();

    function activate() {
      var date = new Date();

      vm.anoAtual = date.getFullYear();
    }

    function logout() {
      Auth.logout().then(function () {
        $state.go(Global.loginState);
      });
    }

    function getImagePerfil() {
      return Auth.currentUser && Auth.currentUser.image ? Auth.currentUser.image : Global.imagePath + '/no_avatar.gif';
    }
  }
})();
'use strict';

/*eslint angular/file-name: 0, no-undef: 0*/
(function () {
  'use strict';

  /**
   * Transforma bibliotecas externas em serviços do angular para ser possível utilizar
   * através da injeção de dependência
   */

  angular.module('app').constant('lodash', _).constant('moment', moment);
})();
'use strict';

(function () {
  'use strict';

  angular.module('app').constant('Global', {
    appName: 'Freelagile',
    homeState: 'app.dashboard',
    loginUrl: 'app/login',
    loginState: 'app.login',
    resetPasswordState: 'app.password-reset',
    notAuthorizedState: 'app.not-authorized',
    tokenKey: 'server_token',
    clientPath: 'client/app',
    apiPath: 'api/v1',
    imagePath: 'client/images'
  });
})();
'use strict';

(function () {
  'use strict';

  routes.$inject = ["$stateProvider", "$urlRouterProvider", "Global"];
  angular.module('app').config(routes);

  /** @ngInject */
  function routes($stateProvider, $urlRouterProvider, Global) {
    $stateProvider.state('app', {
      url: '/app',
      templateUrl: Global.clientPath + '/layout/app.html',
      abstract: true,
      resolve: { //ensure langs is ready before render view
        translateReady: ['$translate', '$q', function ($translate, $q) {
          var deferred = $q.defer();

          $translate.use('pt-BR').then(function () {
            deferred.resolve();
          });

          return deferred.promise;
        }]
      }
    }).state(Global.notAuthorizedState, {
      url: '/acesso-negado',
      templateUrl: Global.clientPath + '/layout/not-authorized.html',
      data: { needAuthentication: false }
    });

    $urlRouterProvider.when('/app', Global.loginUrl);
    $urlRouterProvider.otherwise(Global.loginUrl);
  }
})();
'use strict';

(function () {
  'use strict';

  run.$inject = ["$rootScope", "$state", "$stateParams", "Auth", "Global"];
  angular.module('app').run(run);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function run($rootScope, $state, $stateParams, Auth, Global) {
    // NOSONAR
    //setado no rootScope para poder ser acessado nas views sem prefixo de controller
    $rootScope.$state = $state;
    $rootScope.$stateParams = $stateParams;
    $rootScope.auth = Auth;
    $rootScope.global = Global;

    //no inicio carrega o usuário do localstorage caso o usuário estaja abrindo o navegador
    //para voltar autenticado
    Auth.retrieveUserFromLocalStorage();
  }
})();
'use strict';

(function () {

  'use strict';

  AuditController.$inject = ["$controller", "AuditService", "PrDialog", "Global", "$translate"];
  angular.module('app').controller('AuditController', AuditController);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function AuditController($controller, AuditService, PrDialog, Global, $translate) {
    // NOSONAR
    var vm = this;

    vm.onActivate = onActivate;
    vm.applyFilters = applyFilters;
    vm.viewDetail = viewDetail;

    $controller('CRUDController', { vm: vm, modelService: AuditService, options: {} });

    function onActivate() {
      vm.models = [];
      vm.queryFilters = {};

      //Pega todos os models do server e monta uma lista pro ComboBox
      AuditService.getAuditedModels().then(function (data) {
        var models = [{ id: '', label: $translate.instant('global.all') }];

        data.models.sort();

        for (var index = 0; index < data.models.length; index++) {
          var model = data.models[index];

          models.push({
            id: model,
            label: $translate.instant('models.' + model.toLowerCase())
          });
        }

        vm.models = models;
        vm.queryFilters.model = vm.models[0].id;
      });

      vm.types = AuditService.listTypes();
      vm.queryFilters.type = vm.types[0].id;
    }

    function applyFilters(defaultQueryFilters) {
      return angular.extend(defaultQueryFilters, vm.queryFilters);
    }

    function viewDetail(auditDetail) {
      var config = {
        locals: { auditDetail: auditDetail },
        /** @ngInject */
        controller: ["auditDetail", "PrDialog", function controller(auditDetail, PrDialog) {
          var vm = this;

          vm.close = close;

          activate();

          function activate() {
            if (angular.isArray(auditDetail.old) && auditDetail.old.length === 0) auditDetail.old = null;
            if (angular.isArray(auditDetail.new) && auditDetail.new.length === 0) auditDetail.new = null;

            vm.auditDetail = auditDetail;
          }

          function close() {
            PrDialog.close();
          }
        }],
        controllerAs: 'auditDetailCtrl',
        templateUrl: Global.clientPath + '/audit/audit-detail.html',
        hasBackdrop: true
      };

      PrDialog.custom(config);
    }
  }
})();
'use strict';

(function () {
  'use strict';

  routes.$inject = ["$stateProvider", "Global"];
  angular.module('app').config(routes);

  /**
   * Arquivo de configuração com as rotas específicas de auditoria
   *
   * @param {any} $stateProvider
   * @param {any} Global
   */
  /** @ngInject */
  function routes($stateProvider, Global) {
    $stateProvider.state('app.audit', {
      url: '/auditoria',
      templateUrl: Global.clientPath + '/audit/audit.html',
      controller: 'AuditController as auditCtrl',
      data: { needAuthentication: true, needProfile: ['admin'] }
    });
  }
})();
'use strict';

(function () {
  'use strict';

  AuditService.$inject = ["serviceFactory", "$translate"];
  angular.module('app').factory('AuditService', AuditService);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function AuditService(serviceFactory, $translate) {
    return serviceFactory('audit', {
      actions: {
        getAuditedModels: {
          method: 'GET',
          url: 'models'
        }
      },
      instance: {},
      listTypes: function listTypes() {
        var auditPath = 'views.fields.audit.';

        return [{ id: '', label: $translate.instant(auditPath + 'allResources') }, { id: 'created', label: $translate.instant(auditPath + 'type.created') }, { id: 'updated', label: $translate.instant(auditPath + 'type.updated') }, { id: 'deleted', label: $translate.instant(auditPath + 'type.deleted') }];
      }
    });
  }
})();
'use strict';

(function () {
  'use strict';

  routes.$inject = ["$stateProvider", "Global"];
  angular.module('app').config(routes);

  /**
   * Arquivo de configuração com as rotas específicas do recurso user
   *
   * @param {any} $stateProvider
   * @param {any} Global
   */
  /** @ngInject */
  function routes($stateProvider, Global) {
    $stateProvider.state(Global.resetPasswordState, {
      url: '/password/reset/:token',
      templateUrl: Global.clientPath + '/auth/reset-pass-form.html',
      controller: 'PasswordController as passCtrl',
      data: { needAuthentication: false }
    }).state(Global.loginState, {
      url: '/login',
      templateUrl: Global.clientPath + '/auth/login.html',
      controller: 'LoginController as loginCtrl',
      data: { needAuthentication: false }
    });
  }
})();
'use strict';

(function () {
  'use strict';

  Auth.$inject = ["$http", "$q", "Global", "UsersService"];
  angular.module('app').factory('Auth', Auth);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function Auth($http, $q, Global, UsersService) {
    // NOSONAR
    var auth = {
      login: login,
      logout: logout,
      updateCurrentUser: updateCurrentUser,
      retrieveUserFromLocalStorage: retrieveUserFromLocalStorage,
      authenticated: authenticated,
      sendEmailResetPassword: sendEmailResetPassword,
      remoteValidateToken: remoteValidateToken,
      getToken: getToken,
      setToken: setToken,
      clearToken: clearToken,
      currentUser: null
    };

    function clearToken() {
      localStorage.removeItem(Global.tokenKey);
    }

    function setToken(token) {
      localStorage.setItem(Global.tokenKey, token);
    }

    function getToken() {
      return localStorage.getItem(Global.tokenKey);
    }

    function remoteValidateToken() {
      var deferred = $q.defer();

      if (auth.authenticated()) {
        $http.get(Global.apiPath + '/authenticate/check').then(function () {
          deferred.resolve(true);
        }, function () {
          auth.logout();

          deferred.reject(false);
        });
      } else {
        auth.logout();

        deferred.reject(false);
      }

      return deferred.promise;
    }

    /**
     * Verifica se o usuário está autenticado
     *
     * @returns {boolean}
     */
    function authenticated() {
      return auth.getToken() !== null;
    }

    /**
     * Recupera o usuário do localStorage
     */
    function retrieveUserFromLocalStorage() {
      var user = localStorage.getItem('user');

      if (user) {
        auth.currentUser = angular.merge(new UsersService(), angular.fromJson(user));
      }
    }

    /**
     * Guarda o usuário no localStorage para caso o usuário feche e abra o navegador
     * dentro do tempo de sessão seja possível recuperar o token autenticado.
     *
     * Mantém a variável auth.currentUser para facilitar o acesso ao usuário logado em toda a aplicação
     *
     *
     * @param {any} user Usuário a ser atualizado. Caso seja passado null limpa
     * todas as informações do usuário corrente.
     */
    function updateCurrentUser(user) {
      var deferred = $q.defer();

      if (user) {
        user = angular.merge(new UsersService(), user);

        var jsonUser = angular.toJson(user);

        localStorage.setItem('user', jsonUser);
        auth.currentUser = user;

        deferred.resolve(user);
      } else {
        localStorage.removeItem('user');
        auth.currentUser = null;
        auth.clearToken();

        deferred.reject();
      }

      return deferred.promise;
    }

    /**
     * Realiza o login do usuário
     *
     * @param {any} credentials Email e Senha do usuário
     * @returns {promise} Uma promise com o resultado do chamada no backend
     */
    function login(credentials) {
      var deferred = $q.defer();

      $http.post(Global.apiPath + '/authenticate', credentials).then(function (response) {
        auth.setToken(response.data.token);

        return $http.get(Global.apiPath + '/authenticate/user');
      }).then(function (response) {
        auth.updateCurrentUser(response.data.user);

        deferred.resolve();
      }, function (error) {
        auth.logout();

        deferred.reject(error);
      });

      return deferred.promise;
    }

    /**
     * Desloga os usuários. Como não ten nenhuma informação na sessão do servidor
     * e um token uma vez gerado não pode, por padrão, ser invalidado antes do seu tempo de expiração,
     * somente apagamos os dados do usuário e o token do navegador para efetivar o logout.
     *
     * @returns {promise} Uma promise com o resultado da operação
     */
    function logout() {
      var deferred = $q.defer();

      auth.updateCurrentUser(null);
      deferred.resolve();

      return deferred.promise;
    }

    /**
     * Envia um email para recuperação de senha
     * @param {Object} resetData - Objeto contendo o email
     * @return {Promise} - Retorna uma promise para ser resolvida
     */
    function sendEmailResetPassword(resetData) {
      var deferred = $q.defer();

      $http.post(Global.apiPath + '/password/email', resetData).then(function (response) {
        deferred.resolve(response.data);
      }, function (error) {
        deferred.reject(error);
      });

      return deferred.promise;
    }

    return auth;
  }
})();
'use strict';

(function () {

  'use strict';

  LoginController.$inject = ["$state", "Auth", "Global", "PrDialog"];
  angular.module('app').controller('LoginController', LoginController);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function LoginController($state, Auth, Global, PrDialog) {
    var vm = this;

    vm.login = login;
    vm.openDialogResetPass = openDialogResetPass;
    vm.openDialogSignUp = openDialogSignUp;

    activate();

    function activate() {
      vm.credentials = {};
    }

    function login() {
      var credentials = {
        email: vm.credentials.email,
        password: vm.credentials.password
      };

      Auth.login(credentials).then(function () {
        $state.go(Global.homeState);
      });
    }

    /**
     * Exibe o dialog para recuperação de senha
     */
    function openDialogResetPass() {
      var config = {
        templateUrl: Global.clientPath + '/auth/send-reset-dialog.html',
        controller: 'PasswordController as passCtrl',
        hasBackdrop: true
      };

      PrDialog.custom(config);
    }
    /**
     * Exibe o dialog para recuperação de senha
     */
    function openDialogSignUp() {
      var config = {
        templateUrl: Global.clientPath + '/users/user-form.html',
        controller: 'UsersController as usersCtrl',
        hasBackdrop: true
      };

      PrDialog.custom(config);
    }
  }
})();
'use strict';

(function () {

  'use strict';

  PasswordController.$inject = ["Global", "$stateParams", "$http", "$timeout", "$state", "PrToast", "PrDialog", "Auth", "$translate"];
  angular.module('app').controller('PasswordController', PasswordController);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function PasswordController(Global, $stateParams, $http, $timeout, $state, // NOSONAR
  PrToast, PrDialog, Auth, $translate) {

    var vm = this;

    vm.sendReset = sendReset;
    vm.closeDialog = closeDialog;
    vm.cleanForm = cleanForm;
    vm.sendEmailResetPassword = sendEmailResetPassword;

    activate();

    function activate() {
      vm.reset = { email: '', token: $stateParams.token };
    }

    /**
     * Realiza a alteração da senha do usuário e o redireciona para a tela de login
     */
    function sendReset() {
      $http.post(Global.apiPath + '/password/reset', vm.reset).then(function () {
        PrToast.success($translate.instant('messages.operationSuccess'));
        $timeout(function () {
          $state.go(Global.loginState);
        }, 1500);
      }, function (error) {
        if (error.status !== 400 && error.status !== 500) {
          var msg = '';

          for (var i = 0; i < error.data.password.length; i++) {
            msg += error.data.password[i] + '<br>';
          }
          PrToast.error(msg.toUpperCase());
        }
      });
    }

    /**
     * Envia um email de recuperação de senha com o token do usuário
     */
    function sendEmailResetPassword() {

      if (vm.reset.email === '') {
        PrToast.error($translate.instant('messages.validate.fieldRequired', { field: 'email' }));
        return;
      }

      Auth.sendEmailResetPassword(vm.reset).then(function (data) {
        PrToast.success(data.message);

        vm.cleanForm();
        vm.closeDialog();
      }, function (error) {
        if (error.data.email && error.data.email.length > 0) {
          var msg = '';

          for (var i = 0; i < error.data.email.length; i++) {
            msg += error.data.email[i] + '<br>';
          }

          PrToast.error(msg);
        }
      });
    }

    function closeDialog() {
      PrDialog.close();
    }

    function cleanForm() {
      vm.reset.email = '';
    }
  }
})();
'use strict';

/*eslint angular/file-name: 0*/
(function () {
  'use strict';

  serviceFactory.$inject = ["$modelFactory"];
  angular.module('app').factory('serviceFactory', serviceFactory);

  /** @ngInject */
  /**
   * Mais informações:
   * https://github.com/swimlane/angular-model-factory/wiki/API
   */
  function serviceFactory($modelFactory) {
    return function (url, options) {
      var model;
      var defaultOptions = {
        actions: {
          /**
           * Serviço comum para realizar busca com paginação
           * O mesmo espera que seja retornado um objeto com items e total
           */
          paginate: {
            method: 'GET',
            isArray: false,
            wrap: false,
            afterRequest: function afterRequest(response) {
              if (response['items']) {
                response['items'] = model.List(response['items']);
              }

              return response;
            }
          }
        }
      };

      model = $modelFactory(url, angular.merge(defaultOptions, options));

      return model;
    };
  }
})();
'use strict';

(function () {

  'use strict';

  CRUDController.$inject = ["vm", "modelService", "options", "PrToast", "PrPagination", "PrDialog", "$translate"];
  angular.module('app').controller('CRUDController', CRUDController);

  /** @ngInject */
  /**
   * Controlador Base que implementa todas as funções padrões de um CRUD
   *
   * Ações implementadas
   * activate()
   * search(page)
   * edit(resource)
   * save()
   * remove(resource)
   * goTo(viewName)
   * cleanForm()
   *
   * Gatilhos
   *
   * onActivate()
   * applyFilters(defaultQueryFilters)
   * beforeSearch(page) //retornando false cancela o fluxo
   * afterSearch(response)
   * beforeClean //retornando false cancela o fluxo
   * afterClean()
   * beforeSave() //retornando false cancela o fluxo
   * afterSave(resource)
   * onSaveError(error)
   * beforeRemove(resource) //retornando false cancela o fluxo
   * afterRemove(resource)
   *
   * @param {any} vm instancia do controller filho
   * @param {any} modelService serviço do model que vai ser utilizado
   * @param {any} options opções para sobreescrever comportamentos padrões
   */
  // eslint-disable-next-line max-params
  function CRUDController(vm, modelService, options, PrToast, PrPagination, // NOSONAR
  PrDialog, $translate) {

    //Functions Block
    vm.search = search;
    vm.paginateSearch = paginateSearch;
    vm.normalSearch = normalSearch;
    vm.edit = edit;
    vm.save = save;
    vm.remove = remove;
    vm.goTo = goTo;
    vm.cleanForm = cleanForm;

    activate();

    /**
     * Prepara o controlador
     * Faz o merge das opções
     * Inicializa o recurso
     * Inicializa o objeto paginador e realiza a pesquisa
     */
    function activate() {
      vm.defaultOptions = {
        redirectAfterSave: true,
        searchOnInit: true,
        perPage: 8,
        skipPagination: false
      };

      angular.merge(vm.defaultOptions, options);

      vm.viewForm = false;
      vm.resource = new modelService();

      if (angular.isFunction(vm.onActivate)) vm.onActivate();

      vm.paginator = PrPagination.getInstance(vm.search, vm.defaultOptions.perPage);

      if (vm.defaultOptions.searchOnInit) vm.search();
    }

    /**
     * Realiza a pesquisa
     * Verifica qual das funções de pesquisa deve ser realizada.
     *
     * @param {any} page página que deve ser carregada
     */
    function search(page) {
      vm.defaultOptions.skipPagination ? normalSearch() : paginateSearch(page);
    }

    /**
     * Realiza a pesquisa paginada com base nos filtros definidos
     *
     * @param {any} page página que deve ser carregada
     */
    function paginateSearch(page) {
      vm.paginator.currentPage = angular.isDefined(page) ? page : 1;
      vm.defaultQueryFilters = { page: vm.paginator.currentPage, perPage: vm.paginator.perPage };

      if (angular.isFunction(vm.applyFilters)) vm.defaultQueryFilters = vm.applyFilters(vm.defaultQueryFilters);
      if (angular.isFunction(vm.beforeSearch) && vm.beforeSearch(page) === false) return false;

      modelService.paginate(vm.defaultQueryFilters).then(function (response) {
        vm.paginator.calcNumberOfPages(response.total);
        vm.resources = response.items;

        if (angular.isFunction(vm.afterSearch)) vm.afterSearch(response);
      });
    }

    /**
     * Realiza a pesquisa com base nos filtros definidos
     *
     */
    function normalSearch() {
      vm.defaultQueryFilters = {};

      if (angular.isFunction(vm.applyFilters)) vm.defaultQueryFilters = vm.applyFilters(vm.defaultQueryFilters);
      if (angular.isFunction(vm.beforeSearch) && vm.beforeSearch() === false) return false;

      modelService.query(vm.defaultQueryFilters).then(function (response) {
        vm.resources = response;

        if (angular.isFunction(vm.afterSearch)) vm.afterSearch(response);
      });
    }

    /**
     * Limpa o formulário
     */
    function cleanForm(form) {
      if (angular.isFunction(vm.beforeClean) && vm.beforeClean() === false) return false;

      vm.resource = new modelService();

      if (angular.isDefined(form)) {
        form.$setPristine();
        form.$setUntouched();
      }

      if (angular.isFunction(vm.afterClean)) vm.afterClean();
    }

    /**
     * Carrega no formulário o recurso selecionado para edição
     *
     * @param {any} resource recurso selecionado
     */
    function edit(resource) {
      vm.goTo('form');
      vm.resource = new angular.copy(resource);

      if (angular.isFunction(vm.afterEdit)) vm.afterEdit();
    }

    /**
     * Salva ou atualiza o recurso corrente no formulário
     * No comportamento padrão redireciona o usuário para view de listagem
     * depois da execução
     *
     * @returns
     */
    function save(form) {
      if (angular.isFunction(vm.beforeSave) && vm.beforeSave() === false) return false;

      vm.resource.$save().then(function (resource) {
        vm.resource = resource;

        if (angular.isFunction(vm.afterSave)) vm.afterSave(resource);

        if (vm.defaultOptions.redirectAfterSave) {
          vm.cleanForm(form);
          vm.search(vm.paginator.currentPage);
          vm.goTo('list');
        }

        PrToast.success($translate.instant('messages.saveSuccess'));
      }, function (responseData) {
        if (angular.isFunction(vm.onSaveError)) vm.onSaveError(responseData);
      });
    }

    /**
     * Remove o recurso informado.
     * Antes exibe um dialogo de confirmação
     *
     * @param {any} resource recurso escolhido
     */
    function remove(resource) {
      var config = {
        title: $translate.instant('dialog.confirmTitle'),
        description: $translate.instant('dialog.confirmDescription')
      };

      PrDialog.confirm(config).then(function () {
        if (angular.isFunction(vm.beforeRemove) && vm.beforeRemove(resource) === false) return false;

        resource.$destroy().then(function () {
          if (angular.isFunction(vm.afterRemove)) vm.afterRemove(resource);

          vm.search();
          PrToast.info($translate.instant('messages.removeSuccess'));
        });
      });
    }

    /**
     * Alterna entre a view do formulário e listagem
     *
     * @param {any} viewName nome da view
     */
    function goTo(viewName) {
      vm.viewForm = false;

      if (viewName === 'form') {
        vm.cleanForm();
        vm.viewForm = true;
      }
    }
  }
})();
'use strict';

(function () {

  'use strict';

  angular.module('app').controller('DashboardController', DashboardController);

  /** @ngInject */
  /**
   * Dashboard Controller
   *
   * Painel com principais indicadores
   *
   */
  function DashboardController() {
    // Controller vazio somente para ser definido como página principal.
    // Deve ser identificado e adicionado gráficos
  }
})();
'use strict';

(function () {
  'use strict';

  routes.$inject = ["$stateProvider", "Global"];
  angular.module('app').config(routes);

  /**
   * Arquivo de configuração com as rotas específicas do dashboard
   *
   * @param {any} $stateProvider
   * @param {any} Global
   */
  /** @ngInject */
  function routes($stateProvider, Global) {
    $stateProvider.state(Global.homeState, {
      url: '/dashboard',
      templateUrl: Global.clientPath + '/dashboard/dashboard.html',
      controller: 'DashboardController as dashboardCtrl',
      data: { needAuthentication: true }
    });
  }
})();
'use strict';

(function () {
  'use strict';

  routes.$inject = ["$stateProvider", "Global"];
  angular.module('app').config(routes);

  /**
   * Arquivo de configuração com as rotas específicas do recurso user
   *
   * @param {any} $stateProvider
   * @param {any} Global
   */
  /** @ngInject */
  function routes($stateProvider, Global) {
    $stateProvider.state('app.dinamic-query', {
      url: '/consultas-dinamicas',
      templateUrl: Global.clientPath + '/dinamic-querys/dinamic-querys.html',
      controller: 'DinamicQuerysController as dinamicQueryCtrl',
      data: { needAuthentication: true, needProfile: ['admin'] }
    });
  }
})();
'use strict';

(function () {
  'use strict';

  DinamicQueryService.$inject = ["serviceFactory"];
  angular.module('app').factory('DinamicQueryService', DinamicQueryService);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function DinamicQueryService(serviceFactory) {
    return serviceFactory('dinamicQuery', {
      /**
       * ação adicionada para pegar uma lista de models existentes no servidor
       */
      actions: {
        getModels: {
          method: 'GET',
          url: 'models'
        }
      },
      instance: {}
    });
  }
})();
'use strict';

(function () {

  'use strict';

  DinamicQuerysController.$inject = ["$controller", "DinamicQueryService", "lodash", "PrToast", "$translate"];
  angular.module('app').controller('DinamicQuerysController', DinamicQuerysController);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function DinamicQuerysController($controller, DinamicQueryService, lodash, PrToast, // NOSONAR
  $translate) {

    var vm = this;

    //actions
    vm.onActivate = onActivate;
    vm.applyFilters = applyFilters;
    vm.loadAttributes = loadAttributes;
    vm.loadOperators = loadOperators;
    vm.addFilter = addFilter;
    vm.afterSearch = afterSearch;
    vm.runFilter = runFilter;
    vm.editFilter = editFilter;
    vm.loadModels = loadModels;
    vm.removeFilter = removeFilter;
    vm.clear = clear;
    vm.restart = restart;

    //herda o comportamento base do CRUD
    $controller('CRUDController', { vm: vm, modelService: DinamicQueryService, options: {
        searchOnInit: false
      } });

    function onActivate() {
      vm.restart();
    }

    /**
     * Prepara e aplica os filtro que vão ser enviados para o serviço
     *
     * @param {any} defaultQueryFilters
     * @returns
     */
    function applyFilters(defaultQueryFilters) {
      var where = {};

      /**
       * o serviço espera um objeto com:
       *  o nome de um model
       *  uma lista de filtros
       */
      if (vm.addedFilters.length > 0) {
        var addedFilters = angular.copy(vm.addedFilters);

        where.model = vm.addedFilters[0].model.name;

        for (var index = 0; index < addedFilters.length; index++) {
          var filter = addedFilters[index];

          filter.model = null;
          filter.attribute = filter.attribute.name;
          filter.operator = filter.operator.value;
        }

        where.filters = angular.toJson(addedFilters);
      } else {
        where.model = vm.queryFilters.model.name;
      }

      return angular.extend(defaultQueryFilters, where);
    }

    /**
     * Carrega todos os models criados no servidor com seus atributos
     */
    function loadModels() {
      //Pega todos os models do server e monta uma lista pro ComboBox
      DinamicQueryService.getModels().then(function (data) {
        vm.models = data;
        vm.queryFilters.model = vm.models[0];
        vm.loadAttributes();
      });
    }

    /**
     * Carrega os attributos do model escolhido
     */
    function loadAttributes() {
      vm.attributes = vm.queryFilters.model.attributes;
      vm.queryFilters.attribute = vm.attributes[0];

      vm.loadOperators();
    }

    /**
     * Carrega os operadores especificos para o tipo do atributo
     */
    function loadOperators() {
      var operators = [{ value: '=', label: $translate.instant('views.fields.queryDinamic.operators.equals') }, { value: '<>', label: $translate.instant('views.fields.queryDinamic.operators.diferent') }];

      if (vm.queryFilters.attribute.type.indexOf('varying') !== -1) {
        operators.push({ value: 'has',
          label: $translate.instant('views.fields.queryDinamic.operators.conteins') });
        operators.push({ value: 'startWith',
          label: $translate.instant('views.fields.queryDinamic.operators.startWith') });
        operators.push({ value: 'endWith',
          label: $translate.instant('views.fields.queryDinamic.operators.finishWith') });
      } else {
        operators.push({ value: '>',
          label: $translate.instant('views.fields.queryDinamic.operators.biggerThan') });
        operators.push({ value: '>=',
          label: $translate.instant('views.fields.queryDinamic.operators.equalsOrBiggerThan') });
        operators.push({ value: '<',
          label: $translate.instant('views.fields.queryDinamic.operators.lessThan') });
        operators.push({ value: '<=',
          label: $translate.instant('views.fields.queryDinamic.operators.equalsOrLessThan') });
      }

      vm.operators = operators;
      vm.queryFilters.operator = vm.operators[0];
    }

    /**
     * Adiciona/edita um filtro
     *
     * @param {any} form elemento html do formulário para validações
     */
    function addFilter(form) {
      if (angular.isUndefined(vm.queryFilters.value) || vm.queryFilters.value === '') {
        PrToast.error($translate.instant('messages.validate.fieldRequired', { field: 'valor' }));
        return;
      } else {
        if (vm.index < 0) {
          vm.addedFilters.push(angular.copy(vm.queryFilters));
        } else {
          vm.addedFilters[vm.index] = angular.copy(vm.queryFilters);
          vm.index = -1;
        }

        //reinicia o formulário e as validações existentes
        vm.queryFilters = {};
        form.$setPristine();
        form.$setUntouched();
      }
    }

    /**
     * Realiza a pesquisa tendo os filtros como parâmetros
     */
    function runFilter() {
      vm.search(vm.paginator.currentPage);
    }

    /**
     * Gatilho acionado depois da pesquisa responsável por identificar os atributos
     * contidos nos elementos resultantes da busca
     *
     * @param {any} data dados referente ao retorno da requisição
     */
    function afterSearch(data) {
      var keys = data.items.length > 0 ? Object.keys(data.items[0]) : [];

      //retira todos os atributos que começam com $.
      //Esses atributos são adicionados pelo serviço e não deve aparecer na listagem
      vm.keys = lodash.filter(keys, function (key) {
        return !lodash.startsWith(key, '$');
      });
    }

    /**
     * Coloaca no formulário o filtro escolhido para edição
     * @param {any} $index indice no array do filtro escolhido
     */
    function editFilter($index) {
      vm.index = $index;
      vm.queryFilters = vm.addedFilters[$index];
    }

    /**
     * Remove o filtro escolhido
     *
     * @param {any} $index indice no array do filtro escolhido
     */
    function removeFilter($index) {
      vm.addedFilters.splice($index);
    }

    /**
     * Limpa o formulário corrente
     */
    function clear() {
      //guarda o indice do registro que está sendo editado
      vm.index = -1;
      //vinculado aos campos do formulário
      vm.queryFilters = {};

      if (vm.models) vm.queryFilters.model = vm.models[0];
    }

    /**
     * Reinicia a construção da query limpando tudo
     *
     */
    function restart() {
      //guarda atributos do resultado da busca corrente
      vm.keys = [];

      //guarda os filtros adicionados
      vm.addedFilters = [];
      vm.clear();
      vm.loadModels();
    }
  }
})();
'use strict';

(function () {

  'use strict';

  LanguageLoader.$inject = ["$q", "SupportService", "$log", "$injector"];
  angular.module('app').factory('languageLoader', LanguageLoader);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function LanguageLoader($q, SupportService, $log, $injector) {
    var service = this;

    service.translate = function (locale) {
      return {
        global: $injector.get(locale + '.i18n.global'),
        views: $injector.get(locale + '.i18n.views'),
        attributes: $injector.get(locale + '.i18n.attributes'),
        dialog: $injector.get(locale + '.i18n.dialog'),
        messages: $injector.get(locale + '.i18n.messages'),
        models: $injector.get(locale + '.i18n.models')
      };
    };

    // return loaderFn
    return function (options) {
      $log.info('Carregando o conteudo da linguagem ' + options.key);

      var deferred = $q.defer();

      //Carrega as langs que precisam e estão no servidor para não precisar repetir aqui
      SupportService.langs().then(function (langs) {
        //Merge com os langs definidos no servidor
        var data = angular.merge(service.translate(options.key), langs);

        return deferred.resolve(data);
      }, function () {
        return deferred.resolve(service.translate(options.key));
      });

      return deferred.promise;
    };
  }
})();
'use strict';

(function () {

  'use strict';

  tAttr.$inject = ["$filter"];
  angular.module('app').filter('tAttr', tAttr);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function tAttr($filter) {
    /**
     * Filtro para tradução de um atributo de um model
     * 
     * @param {any} name nome do atributo
     * @returns o nome do atributo traduzido caso encontre se não o nome passado por parametro
     */
    return function (name) {
      var key = 'attributes.' + name;
      var translate = $filter('translate')(key);

      return translate === key ? name : translate;
    };
  }
})();
'use strict';

(function () {

  'use strict';

  tBreadcrumb.$inject = ["$filter"];
  angular.module('app').filter('tBreadcrumb', tBreadcrumb);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function tBreadcrumb($filter) {
    /**
     * Filtro para tradução do breadcrumb (titulo da tela com rastreio)
     *
     * @param {any} id chave com o nome do state referente tela
     * @returns a tradução caso encontre se não o id passado por parametro
     */
    return function (id) {
      //pega a segunda parte do nome do state, retirando a parte abstrata (app.)
      var key = 'views.breadcrumbs.' + id.split('.')[1];
      var translate = $filter('translate')(key);

      return translate === key ? id : translate;
    };
  }
})();
'use strict';

(function () {

  'use strict';

  tModel.$inject = ["$filter"];
  angular.module('app').filter('tModel', tModel);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function tModel($filter) {
    /**
     * Filtro para tradução de um atributo de um model
     *
     * @param {any} name nome do atributo
     * @returns o nome do atributo traduzido caso encontre se não o nome passado por parametro
     */
    return function (name) {
      var key = 'models.' + name.toLowerCase();
      var translate = $filter('translate')(key);

      return translate === key ? name : translate;
    };
  }
})();
'use strict';

(function () {
  'use strict';

  authenticationListener.$inject = ["$rootScope", "$state", "Global", "Auth", "PrToast", "$translate"];
  angular.module('app').run(authenticationListener);

  /**
   * Listen all state (page) changes. Every time a state change need to verify the user is authenticated or not to
   * redirect to correct page. When a user close the browser without logout, when him reopen the browser this event
   * reauthenticate the user with the persistent token of the local storage.
   *
   * We don't check if the token is expired or not in the page change, because is generate an unecessary overhead.
   * If the token is expired when the user try to call the first api to get data, him will be logoff and redirect
   * to login page.
   *
   * @param $rootScope
   * @param $state
   * @param $stateParams
   * @param Auth
   */
  /** @ngInject */
  // eslint-disable-next-line max-params
  function authenticationListener($rootScope, $state, Global, Auth, PrToast, // NOSONAR
  $translate) {

    //only when application start check if the existent token still valid
    Auth.remoteValidateToken().then(function () {
      //if the token is valid check if exists the user because the browser could be closed
      //and the user data isn't in memory
      if (Auth.currentUser === null) {
        Auth.updateCurrentUser(angular.fromJson(localStorage.getItem('user')));
      }
    });

    //Check if the token still valid.
    $rootScope.$on('$stateChangeStart', function (event, toState) {
      if (toState.data.needAuthentication || toState.data.needProfile) {
        //dont trait the success block because already did by token interceptor
        Auth.remoteValidateToken().catch(function () {
          PrToast.warn($translate.instant('messages.login.logoutInactive'));

          if (toState.name !== Global.loginState) {
            $state.go(Global.loginState);
          }

          event.preventDefault();
        });
      } else {
        //if the use is authenticated and need to enter in login page
        //him will be redirected to home page
        if (toState.name === Global.loginState && Auth.authenticated()) {
          $state.go(Global.homeState);
          event.preventDefault();
        }
      }
    });
  }
})();
'use strict';

(function () {
  'use strict';

  authorizationListener.$inject = ["$rootScope", "$state", "Global", "Auth"];
  angular.module('app').run(authorizationListener);

  /** @ngInject */
  function authorizationListener($rootScope, $state, Global, Auth) {
    /**
     * A cada mudança de estado ("página") verifica se o usuário tem o perfil
     * necessário para o acesso a mesma
     */
    $rootScope.$on('$stateChangeStart', function (event, toState) {
      if (toState.data && toState.data.needAuthentication && toState.data.needProfile && Auth.authenticated() && !Auth.currentUser.hasProfile(toState.data.needProfile, toState.data.allProfiles)) {

        $state.go(Global.notAuthorizedState);
        event.preventDefault();
      }
    });
  }
})();
'use strict';

(function () {
  'use strict';

  spinnerInterceptor.$inject = ["$httpProvider", "$provide"];
  angular.module('app').config(spinnerInterceptor);

  function spinnerInterceptor($httpProvider, $provide) {
    /**
     * Este interceptor é responsável por mostrar e esconder o
     * componente PrSpinner sempre que uma requisição ajax
     * iniciar e finalizar.
     *
     * @param {any} $q
     * @param {any} $injector
     * @returns
     */
    showHideSpinner.$inject = ["$q", "$injector"];
    function showHideSpinner($q, $injector) {
      return {
        request: function request(config) {
          $injector.get('PrSpinner').show();

          return config;
        },

        response: function response(_response) {
          $injector.get('PrSpinner').hide();

          return _response;
        },

        responseError: function responseError(rejection) {
          $injector.get('PrSpinner').hide();

          return $q.reject(rejection);
        }
      };
    }

    // Define uma factory para o $httpInterceptor
    $provide.factory('showHideSpinner', showHideSpinner);

    // Adiciona a factory no array de interceptors do $http
    $httpProvider.interceptors.push('showHideSpinner');
  }
})();
'use strict';

/*eslint angular/module-getter: 0*/

(function () {
  'use strict';

  tokenInterceptor.$inject = ["$httpProvider", "$provide", "Global"];
  angular.module('app').config(tokenInterceptor);

  /**
   * Intercept all response (success or error) to verify the returned token
   *
   * @param $httpProvider
   * @param $provide
   * @param Global
   */
  /** @ngInject */
  function tokenInterceptor($httpProvider, $provide, Global) {

    redirectWhenServerLoggedOut.$inject = ["$q", "$injector"];
    function redirectWhenServerLoggedOut($q, $injector) {
      return {
        request: function request(config) {
          var token = $injector.get('Auth').getToken();

          if (token) {
            config.headers['Authorization'] = 'Bearer ' + token;
          }

          return config;
        },
        response: function response(_response) {
          // get a new refresh token to use in the next request
          var token = _response.headers('Authorization');

          if (token) {
            $injector.get('Auth').setToken(token.split(' ')[1]);
          }
          return _response;
        },
        responseError: function responseError(rejection) {
          // Instead of checking for a status code of 400 which might be used
          // for other reasons in Laravel, we check for the specific rejection
          // reasons to tell us if we need to redirect to the login state
          var rejectionReasons = ['token_not_provided', 'token_expired', 'token_absent', 'token_invalid'];

          var tokenError = false;

          angular.forEach(rejectionReasons, function (value) {
            if (rejection.data && rejection.data.error === value) {
              tokenError = true;

              $injector.get('Auth').logout().then(function () {
                var $state = $injector.get('$state');

                // in case multiple ajax request fail at same time because token problems,
                // only the first will redirect
                if (!$state.is(Global.loginState)) {
                  $state.go(Global.loginState);

                  //close any dialog that is opened
                  $injector.get('PrDialog').close();

                  event.preventDefault();
                }
              });
            }
          });

          //define data to empty because already show PrToast token message
          if (tokenError) {
            rejection.data = {};
          }

          if (angular.isFunction(rejection.headers)) {
            // many servers errors (business) are intercept here but generated a new refresh token
            // and need update current token
            var token = rejection.headers('Authorization');

            if (token) {
              $injector.get('Auth').setToken(token.split(' ')[1]);
            }
          }

          return $q.reject(rejection);
        }
      };
    }

    // Setup for the $httpInterceptor
    $provide.factory('redirectWhenServerLoggedOut', redirectWhenServerLoggedOut);

    // Push the new factory onto the $http interceptor array
    $httpProvider.interceptors.push('redirectWhenServerLoggedOut');
  }
})();
'use strict';

(function () {
  'use strict';

  validationInterceptor.$inject = ["$httpProvider", "$provide"];
  angular.module('app').config(validationInterceptor);

  function validationInterceptor($httpProvider, $provide) {
    /**
     * Este interceptor é responsável por mostrar as
     * mensagens de erro referente as validações do back-end
     *
     * @param {any} $q
     * @param {any} $injector
     * @returns
     */
    showErrorValidation.$inject = ["$q", "$injector"];
    function showErrorValidation($q, $injector) {
      return {
        responseError: function responseError(rejection) {
          var PrToast = $injector.get('PrToast');
          var $translate = $injector.get('$translate');

          if (rejection.config.data && !rejection.config.data.skipValidation) {
            if (rejection.data && rejection.data.error) {

              //verifica se ocorreu algum erro referente ao token
              if (rejection.data.error.startsWith('token_')) {
                PrToast.warn($translate.instant('messages.login.logoutInactive'));
              } else {
                PrToast.error($translate.instant(rejection.data.error));
              }
            } else {
              PrToast.errorValidation(rejection.data);
            }
          }

          return $q.reject(rejection);
        }
      };
    }

    // Define uma factory para o $httpInterceptor
    $provide.factory('showErrorValidation', showErrorValidation);

    // Adiciona a factory no array de interceptors do $http
    $httpProvider.interceptors.push('showErrorValidation');
  }
})();
'use strict';

/*eslint-env es6*/

(function () {

  'use strict';

  MenuController.$inject = ["$mdSidenav", "$state", "$mdColors"];
  angular.module('app').controller('MenuController', MenuController);

  /** @ngInject */
  function MenuController($mdSidenav, $state, $mdColors) {
    var vm = this;

    //Bloco de declaracoes de funcoes
    vm.open = open;
    vm.openMenuOrRedirectToState = openMenuOrRedirectToState;

    activate();

    function activate() {
      var menuPrefix = 'views.layout.menu.';

      // Array contendo os itens que são mostrados no menu lateral
      vm.itensMenu = [{ state: 'app.dashboard', title: menuPrefix + 'dashboard', icon: 'dashboard', subItens: [] }, {
        state: '#', title: menuPrefix + 'examples', icon: 'view_carousel', profiles: ['admin'],
        subItens: [{ state: 'app.project', title: menuPrefix + 'project', icon: 'star' }]
      },
      // Coloque seus itens de menu a partir deste ponto
      {
        state: '#', title: menuPrefix + 'admin', icon: 'settings_applications', profiles: ['admin'],
        subItens: [{ state: 'app.user', title: menuPrefix + 'user', icon: 'people' }, { state: 'app.mail', title: menuPrefix + 'mail', icon: 'mail' }, { state: 'app.audit', title: menuPrefix + 'audit', icon: 'storage' }, { state: 'app.dinamic-query', title: menuPrefix + 'dinamicQuery', icon: 'location_searching' }]
      }];

      /**
       * Objeto que preenche o ng-style do menu lateral trocando as cores
       */
      vm.sidenavStyle = {
        top: {
          'border-bottom': '1px solid ' + getColor('primary'),
          'background-image': '-webkit-linear-gradient(top, ' + getColor('primary-500') + ', ' + getColor('primary-800') + ')'
        },
        content: {
          'background-color': getColor('primary-800')
        },
        textColor: {
          color: '#FFF'
        },
        lineBottom: {
          'border-bottom': '1px solid ' + getColor('primary-400')
        }
      };
    }

    function open() {
      $mdSidenav('left').toggle();
    }

    /**
     * Método que exibe o sub menu dos itens do menu lateral caso tenha sub itens
     * caso contrário redireciona para o state passado como parâmetro
     */
    function openMenuOrRedirectToState($mdMenu, ev, item) {
      if (angular.isDefined(item.subItens) && item.subItens.length > 0) {
        $mdMenu.open(ev);
      } else {
        $state.go(item.state);
        $mdSidenav('left').close();
      }
    }

    function getColor(colorPalettes) {
      return $mdColors.getThemeColor(colorPalettes);
    }
  }
})();
'use strict';

(function () {

  'use strict';

  MailsController.$inject = ["MailsService", "UsersService", "PrDialog", "PrToast", "$q", "lodash", "$translate", "Global"];
  angular.module('app').controller('MailsController', MailsController);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function MailsController(MailsService, UsersService, PrDialog, PrToast, // NOSONAR
  $q, lodash, $translate, Global) {

    var vm = this;

    vm.filterSelected = false;
    vm.options = {
      skin: 'kama',
      language: 'pt-br',
      allowedContent: true,
      entities: true,
      height: 300,
      extraPlugins: 'dialog,find,colordialog,preview,forms,iframe,flash'
    };

    vm.loadUsers = loadUsers;
    vm.openUserDialog = openUserDialog;
    vm.addUserMail = addUserMail;
    vm.cleanForm = cleanForm;
    vm.send = send;

    activate();

    function activate() {
      vm.cleanForm();
    }

    /**
     * Realiza a busca pelo usuário remotamente
     *
     * @params {string} - Recebe o valor para ser pesquisado
     * @return {promisse} - Retorna uma promisse que o componete resolve
     */
    function loadUsers(criteria) {
      var deferred = $q.defer();

      UsersService.query({
        nameOrEmail: criteria,
        notUsers: lodash.map(vm.mail.users, lodash.property('id')).toString(),
        limit: 5
      }).then(function (data) {

        // verifica se na lista de usuarios já existe o usuário com o email pesquisado
        data = lodash.filter(data, function (user) {
          return !lodash.find(vm.mail.users, { email: user.email });
        });

        deferred.resolve(data);
      });

      return deferred.promise;
    }

    /**
     * Abre o dialog para pesquisa de usuários
     */
    function openUserDialog() {
      var config = {
        locals: {
          onInit: true,
          userDialogInput: {
            transferUserFn: vm.addUserMail
          }
        },
        controller: 'UsersDialogController',
        controllerAs: 'ctrl',
        templateUrl: Global.clientPath + '/users/dialog/users-dialog.html',
        hasBackdrop: true
      };

      PrDialog.custom(config);
    }

    /**
     * Adiciona o usuário selecionado na lista para que seja enviado o email
     */
    function addUserMail(user) {
      var users = lodash.find(vm.mail.users, { email: user.email });

      if (vm.mail.users.length > 0 && angular.isDefined(users)) {
        PrToast.warn($translate.instant('messages.user.userExists'));
      } else {
        vm.mail.users.push({ name: user.name, email: user.email });
      }
    }

    /**
     * Realiza o envio do email para a lista de usuários selecionados
     */
    function send() {

      vm.mail.$save().then(function (response) {
        if (response.length > 0) {
          var msg = $translate.instant('messages.mail.mailErrors');

          for (var i = 0; i < response.length; i++) {
            msg += response + '\n';
          }
          PrToast.error(msg);
          vm.cleanForm();
        } else {
          PrToast.success($translate.instant('messages.mail.sendMailSuccess'));
          vm.cleanForm();
        }
      });
    }

    /**
     * Limpa o formulário de email
     */
    function cleanForm() {
      vm.mail = new MailsService();
      vm.mail.users = [];
    }
  }
})();
'use strict';

(function () {
  'use strict';

  routes.$inject = ["$stateProvider", "Global"];
  angular.module('app').config(routes);

  /**
   * Arquivo de configuração com as rotas específicas do recurso em questão
   *
   * @param {any} $stateProvider
   * @param {any} Global
   */
  /** @ngInject */
  function routes($stateProvider, Global) {
    $stateProvider.state('app.mail', {
      url: '/email',
      templateUrl: Global.clientPath + '/mail/mails-send.html',
      controller: 'MailsController as mailsCtrl',
      data: { needAuthentication: true, needProfile: ['admin'] }
    });
  }
})();
'use strict';

(function () {
  'use strict';

  MailsService.$inject = ["serviceFactory"];
  angular.module('app').factory('MailsService', MailsService);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function MailsService(serviceFactory) {
    return serviceFactory('mails', {});
  }
})();
'use strict';

(function () {

  'use strict';

  rolesStr.$inject = ["lodash"];
  angular.module('app').filter('rolesStr', rolesStr);

  /** @ngInject */
  function rolesStr(lodash) {
    /**
     * @param {array} roles lista de perfis
     * @return {string} perfis separados por ', '  
     */
    return function (roles) {
      return lodash.map(roles, 'slug').join(', ');
    };
  }
})();
'use strict';

(function () {
  'use strict';

  RolesService.$inject = ["serviceFactory"];
  angular.module('app').factory('RolesService', RolesService);

  /** @ngInject */
  function RolesService(serviceFactory) {
    return serviceFactory('roles');
  }
})();
'use strict';

(function () {
  'use strict';

  SupportService.$inject = ["serviceFactory"];
  angular.module('app').factory('SupportService', SupportService);

  /** @ngInject */
  function SupportService(serviceFactory) {
    return serviceFactory('support', {
      actions: {
        /**
         * Pega as traduções que estão no servidor
         *
         * @returns {promise} Uma promise com o resultado do chamada no backend
         */
        langs: {
          method: 'GET',
          url: 'langs',
          wrap: false,
          cache: true
        }
      }
    });
  }
})();
'use strict';

(function () {
  'use strict';

  /** @ngInject */

  angular.module('app').component('box', {
    replace: true,
    templateUrl: ['Global', function (Global) {
      return Global.clientPath + '/widgets/box.html';
    }],
    transclude: {
      toolbarButtons: '?boxToolbarButtons',
      footerButtons: '?boxFooterButtons'
    },
    bindings: {
      boxTitle: '@',
      toolbarClass: '@',
      toolbarBgColor: '@'
    },
    controller: ['$transclude', function ($transclude) {
      var ctrl = this;

      ctrl.transclude = $transclude;

      ctrl.$onInit = function () {
        if (angular.isUndefined(ctrl.toolbarBgColor)) ctrl.toolbarBgColor = 'default-primary';
      };
    }]
  });
})();
'use strict';

(function () {
  'use strict';

  /** @ngInject */

  angular.module('app').component('contentBody', {
    replace: true,
    transclude: true,
    templateUrl: ['Global', function (Global) {
      return Global.clientPath + '/widgets/content-body.html';
    }],
    bindings: {
      layoutAlign: '@'
    },
    controller: [function () {
      var ctrl = this;

      ctrl.$onInit = function () {
        // Make a copy of the initial value to be able to reset it later
        ctrl.layoutAlign = angular.isDefined(ctrl.layoutAlign) ? ctrl.layoutAlign : 'center start';
      };
    }]
  });
})();
'use strict';

(function () {
  'use strict';

  /** @ngInject */

  angular.module('app').component('contentHeader', {
    templateUrl: ['Global', function (Global) {
      return Global.clientPath + '/widgets/content-header.html';
    }],
    replace: true,
    bindings: {
      title: '@',
      description: '@'
    }
  });
})();
'use strict';

(function () {

  'use strict';

  ProfileController.$inject = ["UsersService", "Auth", "PrToast", "$translate"];
  angular.module('app').controller('ProfileController', ProfileController);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function ProfileController(UsersService, Auth, PrToast, $translate) {
    var vm = this;

    vm.update = update;

    activate();

    function activate() {
      vm.user = angular.copy(Auth.currentUser);
    }

    function update() {
      UsersService.updateProfile(vm.user).then(function (response) {
        //atualiza o usuário corrente com as novas informações
        Auth.updateCurrentUser(response);
        PrToast.success($translate.instant('messages.saveSuccess'));
      });
    }
  }
})();
'use strict';

(function () {

  'use strict';

  UsersController.$inject = ["$controller", "UsersService"];
  angular.module('app').controller('UsersController', UsersController);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function UsersController($controller, UsersService) {

    var vm = this;

    vm.onActivate = onActivate;
    // instantiate base controller
    $controller('CRUDController', { vm: vm, modelService: UsersService, options: {} });

    function onActivate() {
      vm.queryFilters = {};
    }
  }
})();
'use strict';

(function () {
  'use strict';

  routes.$inject = ["$stateProvider", "Global"];
  angular.module('app').config(routes);

  /**
   * Arquivo de configuração com as rotas específicas do recurso user
   *
   * @param {any} $stateProvider
   * @param {any} Global
   */
  /** @ngInject */
  function routes($stateProvider, Global) {
    $stateProvider.state('app.user', {
      url: '/usuario',
      templateUrl: Global.clientPath + '/users/users.html',
      controller: 'UsersController as usersCtrl',
      data: { needAuthentication: true, needProfile: ['admin'] }
    }).state('app.user-profile', {
      url: '/usuario/perfil',
      templateUrl: Global.clientPath + '/users/profile.html',
      controller: 'ProfileController as profileCtrl',
      data: { needAuthentication: true }
    });
  }
})();
'use strict';

(function () {
  'use strict';

  UsersService.$inject = ["lodash", "Global", "serviceFactory"];
  angular.module('app').factory('UsersService', UsersService);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function UsersService(lodash, Global, serviceFactory) {
    return serviceFactory('users', {
      //quando instancia um usuário sem passar parametro,
      //o mesmo vai ter os valores defaults abaixo
      defaults: {
        roles: []
      },

      actions: {
        /**
         * Serviço que atualiza os dados do perfil do usuário logado
         *
         * @param {object} attributes
         * @returns {promise} Uma promise com o resultado do chamada no backend
         */
        updateProfile: {
          method: 'PUT',
          url: Global.apiPath + '/profile',
          override: true,
          wrap: false
        }
      },

      instance: {
        /**
         * Verifica se o usuário tem os perfis informados.
         *
         * @param {any} roles perfis a serem verificados
         * @param {boolean} all flag para indicar se vai chegar todos os perfis ou somente um deles
         * @returns {boolean}
         */
        hasProfile: function hasProfile(roles, all) {
          roles = angular.isArray(roles) ? roles : [roles];

          var userRoles = lodash.map(this.roles, 'slug');

          if (all) {
            return lodash.intersection(userRoles, roles).length === roles.length;
          } else {
            //return the length because 0 is false in js
            return lodash.intersection(userRoles, roles).length;
          }
        },

        /**
         * Verifica se o usuário tem o perfil admin.
         *
         * @returns {boolean}
         */
        isAdmin: function isAdmin() {
          return this.hasProfile('admin');
        }
      }
    });
  }
})();
'use strict';

(function () {

  'use strict';

  auditDetailTitle.$inject = ["$translate"];
  angular.module('app').filter('auditDetailTitle', auditDetailTitle);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function auditDetailTitle($translate) {
    return function (auditDetail, status) {
      if (auditDetail.type === 'updated') {
        if (status === 'before') {
          return $translate.instant('dialog.audit.updatedBefore');
        } else {
          return $translate.instant('dialog.audit.updatedAfter');
        }
      } else {
        return $translate.instant('dialog.audit.' + auditDetail.type);
      }
    };
  }
})();
'use strict';

(function () {

  'use strict';

  auditModel.$inject = ["$translate"];
  angular.module('app').filter('auditModel', auditModel);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function auditModel($translate) {
    return function (modelId) {
      modelId = modelId.replace('App\\', '');
      var model = $translate.instant('models.' + modelId.toLowerCase());

      return model ? model : modelId;
    };
  }
})();
'use strict';

(function () {

  'use strict';

  auditType.$inject = ["lodash", "AuditService"];
  angular.module('app').filter('auditType', auditType);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function auditType(lodash, AuditService) {
    return function (typeId) {
      var type = lodash.find(AuditService.listTypes(), { id: typeId });

      return type ? type.label : type;
    };
  }
})();
'use strict';

(function () {

  'use strict';

  auditValue.$inject = ["$filter", "lodash"];
  angular.module('app').filter('auditValue', auditValue);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function auditValue($filter, lodash) {
    return function (value, key) {
      if (angular.isDate(value) || lodash.endsWith(key, '_at') || lodash.endsWith(key, '_to')) {
        return $filter('prDatetime')(value);
      }

      if (typeof value === 'boolean') {
        return $filter('translate')(value ? 'global.yes' : 'global.no');
      }

      //check is float
      if (Number(value) === value && value % 1 !== 0) {
        return $filter('real')(value);
      }

      return value;
    };
  }
})();
'use strict';

/*eslint angular/file-name: 0, no-undef: 0*/
(function () {
  'use strict';

  angular.module('app').constant('pt-BR.i18n.attributes', {
    email: 'Email',
    password: 'Senha',
    name: 'Nome',
    image: 'Imagem',
    roles: 'Perfis',
    date: 'Data',
    initialDate: 'Data Inicial',
    finalDate: 'Data Final',
    task: {
      description: 'Descrição',
      done: 'Feito?',
      priority: 'Prioridade',
      scheduled_to: 'Agendado Para?',
      project: 'Projeto'
    },
    project: {
      cost: 'Custo'
    },
    //é carregado do servidor caso esteja definido no mesmo
    auditModel: {}
  });
})();
'use strict';

/*eslint angular/file-name: 0, no-undef: 0*/
(function () {
  'use strict';

  angular.module('app').constant('pt-BR.i18n.dialog', {
    confirmTitle: 'Confirmação',
    confirmDescription: 'Confirma a ação?',
    removeDescription: 'Deseja remover permanentemente {{name}}?',
    audit: {
      created: 'Informações do Cadastro',
      updatedBefore: 'Antes da Atualização',
      updatedAfter: 'Depois da Atualização',
      deleted: 'Informações antes de remover'
    },
    login: {
      resetPassword: {
        description: 'Digite abaixo o email cadastrado no sistema.'
      }
    }
  });
})();
'use strict';

/*eslint angular/file-name: 0, no-undef: 0*/
(function () {
  'use strict';

  angular.module('app').constant('pt-BR.i18n.global', {
    loading: 'Carregando...',
    processing: 'Processando...',
    yes: 'Sim',
    no: 'Não',
    all: 'Todos'
  });
})();
'use strict';

/*eslint angular/file-name: 0, no-undef: 0*/
(function () {
  'use strict';

  angular.module('app').constant('pt-BR.i18n.messages', {
    internalError: 'Ocorreu um erro interno, contate o administrador do sistema',
    notFound: 'Nenhum registro encontrado',
    notAuthorized: 'Você não tem acesso a esta funcionalidade.',
    searchError: 'Não foi possível realizar a busca.',
    saveSuccess: 'Registro salvo com sucesso.',
    operationSuccess: 'Operação realizada com sucesso.',
    operationError: 'Erro ao realizar a operação',
    saveError: 'Erro ao tentar salvar o registro.',
    removeSuccess: 'Remoção realizada com sucesso.',
    removeError: 'Erro ao tentar remover o registro.',
    resourceNotFoundError: 'Recurso não encontrado',
    notNullError: 'Todos os campos obrigatórios devem ser preenchidos.',
    duplicatedResourceError: 'Já existe um recurso com essas informações.',
    validate: {
      fieldRequired: 'O campo {{field}} é obrigratório.'
    },
    layout: {
      error404: 'Página não encontrada'
    },
    login: {
      logoutInactive: 'Você foi deslogado do sistema por inatividade. Favor entrar no sistema novamente.',
      invalidCredentials: 'Credenciais Inválidas',
      unknownError: 'Não foi possível realizar o login. Tente novamente. ' + 'Caso não consiga favor encontrar em contato com o administrador do sistema.',
      userNotFound: 'Não foi possível encontrar seus dados'
    },
    dashboard: {
      welcome: 'Seja bem Vindo {{userName}}',
      description: 'Utilize o menu para navegação.'
    },
    mail: {
      mailErrors: 'Ocorreu um erro nos seguintes emails abaixo:\n',
      sendMailSuccess: 'Email enviado com sucesso!',
      sendMailError: 'Não foi possível enviar o email.',
      passwordSendingSuccess: 'O processo de recuperação de senha foi iniciado. Caso o email não chegue em 10 minutos tente novamente.'
    },
    user: {
      removeYourSelfError: 'Você não pode remover seu próprio usuário',
      userExists: 'Usuário já adicionado!',
      profile: {
        updateError: 'Não foi possível atualizar seu profile'
      }
    },
    queryDinamic: {
      noFilter: 'Nenhum filtro adicionado'
    }
  });
})();
'use strict';

/*eslint angular/file-name: 0, no-undef: 0*/
(function () {
  'use strict';

  angular.module('app').constant('pt-BR.i18n.models', {
    user: 'Usuário',
    task: 'Tarefa',
    project: 'Projeto'
  });
})();
'use strict';

/*eslint angular/file-name: 0, no-undef: 0*/
(function () {
  'use strict';

  angular.module('app').constant('pt-BR.i18n.views', {
    breadcrumbs: {
      user: 'Administração - Usuário',
      'user-profile': 'Perfil',
      dashboard: 'Dashboard',
      audit: 'Administração - Auditoria',
      mail: 'Administração - Envio de e-mail',
      project: 'Exemplos - Projetos',
      'dinamic-query': 'Administração - Consultas Dinâmicas',
      'not-authorized': 'Acesso Negado'
    },
    titles: {
      dashboard: 'Página inicial',
      mailSend: 'Enviar e-mail',
      taskList: 'Lista de Tarefas',
      userList: 'Lista de Usuários',
      auditList: 'Lista de Logs',
      register: 'Formulário de Cadastro',
      resetPassword: 'Redefinir Senha',
      update: 'Formulário de Atualização'
    },
    actions: {
      send: 'Enviar',
      save: 'Salvar',
      clear: 'Limpar',
      clearAll: 'Limpar Tudo',
      restart: 'Reiniciar',
      filter: 'Filtrar',
      search: 'Pesquisar',
      list: 'Listar',
      edit: 'Editar',
      cancel: 'Cancelar',
      update: 'Atualizar',
      remove: 'Remover',
      getOut: 'Sair',
      add: 'Adicionar',
      in: 'Entrar',
      loadImage: 'Carregar Imagem',
      signup: 'Cadastrar'
    },
    fields: {
      date: 'Data',
      action: 'Ação',
      actions: 'Ações',
      audit: {
        dateStart: 'Data Inicial',
        dateEnd: 'Data Final',
        resource: 'Recurso',
        allResources: 'Todos Recursos',
        type: {
          created: 'Cadastrado',
          updated: 'Atualizado',
          deleted: 'Removido'
        }
      },
      login: {
        resetPassword: 'Esqueci minha senha',
        confirmPassword: 'Confirmar senha'
      },
      mail: {
        to: 'Para',
        subject: 'Assunto',
        message: 'Mensagem'
      },
      queryDinamic: {
        filters: 'Filtros',
        results: 'Resultados',
        model: 'Model',
        attribute: 'Atributo',
        operator: 'Operador',
        resource: 'Recurso',
        value: 'Valor',
        operators: {
          equals: 'Igual',
          diferent: 'Diferente',
          conteins: 'Contém',
          startWith: 'Inicia com',
          finishWith: 'Finaliza com',
          biggerThan: 'Maior',
          equalsOrBiggerThan: 'Maior ou Igual',
          lessThan: 'Menor',
          equalsOrLessThan: 'Menor ou Igual'
        }
      },
      project: {
        name: 'Nome',
        totalTask: 'Total de Tarefas'
      },
      task: {
        done: 'Não Feito / Feito'
      },
      user: {
        perfils: 'Perfis',
        nameOrEmail: 'Nome ou Email'
      }
    },
    layout: {
      menu: {
        dashboard: 'Dashboard',
        project: 'Projetos',
        admin: 'Administração',
        examples: 'Exemplos',
        user: 'Usuários',
        mail: 'Enviar e-mail',
        audit: 'Auditoria',
        dinamicQuery: 'Consultas Dinamicas'
      }
    },
    tooltips: {
      audit: {
        viewDetail: 'Visualizar Detalhamento'
      },
      user: {
        perfil: 'Perfil',
        transfer: 'Transferir'
      },
      task: {
        listTask: 'Listar Tarefas'
      }
    }
  });
})();
'use strict';

(function () {

  'use strict';

  ProjectsController.$inject = ["Global", "$controller", "ProjectsService", "PrDialog"];
  angular.module('app').controller('ProjectsController', ProjectsController);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function ProjectsController(Global, $controller, ProjectsService, PrDialog) {
    var vm = this;

    //Attributes Block

    //Functions Block
    vm.onActivate = onActivate;
    vm.applyFilters = applyFilters;
    vm.viewTasks = viewTasks;

    // instantiate base controller
    $controller('CRUDController', { vm: vm, modelService: ProjectsService, options: {} });

    function onActivate() {
      vm.queryFilters = {};
    }

    function applyFilters(defaultQueryFilters) {
      return angular.extend(defaultQueryFilters, vm.queryFilters);
    }

    function viewTasks(projectId) {
      var config = {
        locals: {
          projectId: projectId
        },
        controller: 'TasksDialogController',
        controllerAs: 'tasksCtrl',
        templateUrl: Global.clientPath + '/samples/tasks/tasks-dialog.html',
        hasBackdrop: true
      };

      PrDialog.custom(config).finally(function () {
        vm.search(vm.paginator.currentPage);
      });
    }
  }
})();
'use strict';

(function () {
  'use strict';

  routes.$inject = ["$stateProvider", "Global"];
  angular.module('app').config(routes);

  /**
   * Arquivo de configuração com as rotas específicas do recurso project
   *
   * @param {any} $stateProvider
   * @param {any} Global
   */
  /** @ngInject */
  function routes($stateProvider, Global) {
    $stateProvider.state('app.project', {
      url: '/projetos',
      templateUrl: Global.clientPath + '/samples/projects/projects.html',
      controller: 'ProjectsController as projectsCtrl',
      data: { needAuthentication: true, needProfile: ['admin'] }
    });
  }
})();
'use strict';

(function () {
  'use strict';

  ProjectsService.$inject = ["serviceFactory"];
  angular.module('app').factory('ProjectsService', ProjectsService);

  /** @ngInject */
  function ProjectsService(serviceFactory) {
    return serviceFactory('projects', {
      actions: {},
      instance: {}
    });
  }
})();
'use strict';

(function () {

  'use strict';

  TasksDialogController.$inject = ["$controller", "TasksService", "projectId", "PrToast", "PrDialog", "$translate", "Global", "moment"];
  angular.module('app').controller('TasksDialogController', TasksDialogController);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function TasksDialogController($controller, TasksService, projectId, PrToast, // NOSONAR
  PrDialog, $translate, Global, moment) {

    var vm = this;

    //Functions Block
    vm.onActivate = onActivate;
    vm.close = close;
    vm.applyFilters = applyFilters;
    vm.beforeSave = beforeSave;
    vm.afterSave = afterSave;
    vm.toggleDone = toggleDone;

    // instantiate base controller
    $controller('CRUDController', { vm: vm, modelService: TasksService, options: {
        perPage: 5
      } });

    function onActivate() {
      vm.global = Global;
      vm.resource.scheduled_to = moment().add(30, 'minutes');
      vm.queryFilters = { projectId: projectId };
    }

    function applyFilters(defaultQueryFilters) {
      return angular.extend(defaultQueryFilters, vm.queryFilters);
    }

    function beforeSave() {
      vm.resource.project_id = vm.queryFilters.projectId;
      vm.resource.project = null;
    }

    function afterSave() {
      vm.cleanForm();
      vm.search(vm.paginator.currentPage);
    }

    function close() {
      vm.cleanForm();
      PrDialog.close();
    }

    function toggleDone(resource) {
      TasksService.toggleDone({ id: resource.id, done: resource.done }).then(function () {
        PrToast.success($translate.instant('messages.saveSuccess'));
        vm.search(vm.paginator.currentPage);
      }, function (error) {
        PrToast.errorValidation(error.data, $translate.instant('messages.operationError'));
      });
    }
  }
})();
'use strict';

(function () {
  'use strict';

  TasksService.$inject = ["serviceFactory", "moment"];
  angular.module('app').factory('TasksService', TasksService);

  /** @ngInject */
  function TasksService(serviceFactory, moment) {
    return serviceFactory('tasks', {
      //quando instancia um usuário sem passar parametro,
      //o mesmo vai ter os valores defaults abaixo
      defaults: {
        scheduled_to: new Date()
      },

      map: {
        //convert para objeto javascript date uma string formatada como data
        scheduled_to: function scheduled_to(value) {
          return moment(value).toDate();
        }
      },

      actions: {
        /**
         * Atualiza os status da tarefa
         *
         * @param {object} attributes
         */
        toggleDone: {
          method: 'PUT',
          url: 'toggleDone'
        }
      },
      instance: {}
    });
  }
})();
'use strict';

(function () {

  'use strict';

  UsersDialogController.$inject = ["$controller", "UsersService", "PrDialog", "userDialogInput", "onInit"];
  angular.module('app').controller('UsersDialogController', UsersDialogController);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function UsersDialogController($controller, UsersService, PrDialog, // NOSONAR
  userDialogInput, onInit) {

    var vm = this;

    vm.onActivate = onActivate;
    vm.applyFilters = applyFilters;
    vm.close = close;

    if (angular.isDefined(userDialogInput)) {
      vm.transferUser = userDialogInput.transferUserFn;
    }

    // instantiate base controller
    $controller('CRUDController', {
      vm: vm,
      modelService: UsersService,
      searchOnInit: onInit,
      options: {
        perPage: 5
      }
    });

    function onActivate() {
      vm.queryFilters = {};
    }

    function applyFilters() {
      return angular.extend(vm.defaultQueryFilters, vm.queryFilters);
    }

    function close() {
      PrDialog.close();
    }
  }
})();
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImFwcGxpY2F0aW9uLmpzIiwiYXBwLmpzIiwiYXBwLmNvbmZpZy5qcyIsImFwcC5jb250cm9sbGVyLmpzIiwiYXBwLmV4dGVybmFsLmpzIiwiYXBwLmdsb2JhbC5qcyIsImFwcC5yb3V0ZXMuanMiLCJhcHAucnVuLmpzIiwiYXVkaXQvYXVkaXQuY29udHJvbGxlci5qcyIsImF1ZGl0L2F1ZGl0LnJvdXRlLmpzIiwiYXVkaXQvYXVkaXQuc2VydmljZS5qcyIsImF1dGgvYXV0aC5yb3V0ZS5qcyIsImF1dGgvYXV0aC5zZXJ2aWNlLmpzIiwiYXV0aC9sb2dpbi5jb250cm9sbGVyLmpzIiwiYXV0aC9wYXNzd29yZC5jb250cm9sbGVyLmpzIiwiY29yZS9iYXNlLnNlcnZpY2UuanMiLCJjb3JlL2NydWQuY29udHJvbGxlci5qcyIsImRhc2hib2FyZC9kYXNoYm9hcmQuY29udHJvbGxlci5qcyIsImRhc2hib2FyZC9kYXNoYm9hcmQucm91dGUuanMiLCJkaW5hbWljLXF1ZXJ5cy9kaW5hbWljLXF1ZXJ5LnJvdXRlLmpzIiwiZGluYW1pYy1xdWVyeXMvZGluYW1pYy1xdWVyeS5zZXJ2aWNlLmpzIiwiZGluYW1pYy1xdWVyeXMvZGluYW1pYy1xdWVyeXMuY29udHJvbGxlci5qcyIsImkxOG4vbGFuZ3VhZ2UtbG9hZGVyLnNlcnZpY2UuanMiLCJpMThuL3QtYXR0ci5maWx0ZXIuanMiLCJpMThuL3QtYnJlYWRjcnVtYi5maWx0ZXIuanMiLCJpMThuL3QtbW9kZWwuZmlsdGVyLmpzIiwiaW50ZXJjZXB0b3JzL2F1dGhlbnRpY2F0aW9uLmxpc3RlbmVyLmpzIiwiaW50ZXJjZXB0b3JzL2F1dGhvcml6YXRpb24ubGlzdGVuZXIuanMiLCJpbnRlcmNlcHRvcnMvc3Bpbm5lci5pbnRlcmNlcHRvci5qcyIsImludGVyY2VwdG9ycy90b2tlbi5pbnRlcmNlcHRvci5qcyIsImludGVyY2VwdG9ycy92YWxpZGF0aW9uLmludGVyY2VwdG9yLmpzIiwibGF5b3V0L21lbnUuY29udHJvbGxlci5qcyIsIm1haWwvbWFpbHMuY29udHJvbGxlci5qcyIsIm1haWwvbWFpbHMucm91dGUuanMiLCJtYWlsL21haWxzLnNlcnZpY2UuanMiLCJyb2xlcy9yb2xlcy1zdHIuZmlsdGVyLmpzIiwicm9sZXMvcm9sZXMuc2VydmljZS5qcyIsInN1cHBvcnQvc3VwcG9ydC5zZXJ2aWNlLmpzIiwid2lkZ2V0cy9ib3guY29tcG9uZW50LmpzIiwid2lkZ2V0cy9jb250ZW50LWJvZHkuY29tcG9uZW50LmpzIiwid2lkZ2V0cy9jb250ZW50LWhlYWRlci5jb21wb25lbnQuanMiLCJ1c2Vycy9wcm9maWxlLmNvbnRyb2xsZXIuanMiLCJ1c2Vycy91c2Vycy5jb250cm9sbGVyLmpzIiwidXNlcnMvdXNlcnMucm91dGUuanMiLCJ1c2Vycy91c2Vycy5zZXJ2aWNlLmpzIiwiYXVkaXQvZmlsdGVycy9hdWRpdC1kZXRhaWwtdGl0bGUuZmlsdGVyLmpzIiwiYXVkaXQvZmlsdGVycy9hdWRpdC1tb2RlbC5maWx0ZXIuanMiLCJhdWRpdC9maWx0ZXJzL2F1ZGl0LXR5cGUuZmlsdGVyLmpzIiwiYXVkaXQvZmlsdGVycy9hdWRpdC12YWx1ZS5maWx0ZXIuanMiLCJpMThuL3B0LUJSL2F0dHJpYnV0ZXMuanMiLCJpMThuL3B0LUJSL2RpYWxvZy5qcyIsImkxOG4vcHQtQlIvZ2xvYmFsLmpzIiwiaTE4bi9wdC1CUi9tZXNzYWdlcy5qcyIsImkxOG4vcHQtQlIvbW9kZWxzLmpzIiwiaTE4bi9wdC1CUi92aWV3cy5qcyIsInNhbXBsZXMvcHJvamVjdHMvcHJvamVjdHMuY29udHJvbGxlci5qcyIsInNhbXBsZXMvcHJvamVjdHMvcHJvamVjdHMucm91dGUuanMiLCJzYW1wbGVzL3Byb2plY3RzL3Byb2plY3RzLnNlcnZpY2UuanMiLCJzYW1wbGVzL3Rhc2tzL3Rhc2tzLWRpYWxvZy5jb250cm9sbGVyLmpzIiwic2FtcGxlcy90YXNrcy90YXNrcy5zZXJ2aWNlLmpzIiwidXNlcnMvZGlhbG9nL3VzZXJzLWRpYWxvZy5jb250cm9sbGVyLmpzIl0sIm5hbWVzIjpbImFuZ3VsYXIiLCJtb2R1bGUiLCJjb25maWciLCJHbG9iYWwiLCIkbWRUaGVtaW5nUHJvdmlkZXIiLCIkbW9kZWxGYWN0b3J5UHJvdmlkZXIiLCIkdHJhbnNsYXRlUHJvdmlkZXIiLCJtb21lbnQiLCIkbWRBcmlhUHJvdmlkZXIiLCJ1c2VMb2FkZXIiLCJ1c2VTYW5pdGl6ZVZhbHVlU3RyYXRlZ3kiLCJ1c2VQb3N0Q29tcGlsaW5nIiwibG9jYWxlIiwiZGVmYXVsdE9wdGlvbnMiLCJwcmVmaXgiLCJhcGlQYXRoIiwidGhlbWUiLCJwcmltYXJ5UGFsZXR0ZSIsImRlZmF1bHQiLCJhY2NlbnRQYWxldHRlIiwid2FyblBhbGV0dGUiLCJlbmFibGVCcm93c2VyQ29sb3IiLCJkaXNhYmxlV2FybmluZ3MiLCJjb250cm9sbGVyIiwiQXBwQ29udHJvbGxlciIsIiRzdGF0ZSIsIkF1dGgiLCJ2bSIsImFub0F0dWFsIiwibG9nb3V0IiwiZ2V0SW1hZ2VQZXJmaWwiLCJhY3RpdmF0ZSIsImRhdGUiLCJEYXRlIiwiZ2V0RnVsbFllYXIiLCJ0aGVuIiwiZ28iLCJsb2dpblN0YXRlIiwiY3VycmVudFVzZXIiLCJpbWFnZSIsImltYWdlUGF0aCIsImNvbnN0YW50IiwiXyIsImFwcE5hbWUiLCJob21lU3RhdGUiLCJsb2dpblVybCIsInJlc2V0UGFzc3dvcmRTdGF0ZSIsIm5vdEF1dGhvcml6ZWRTdGF0ZSIsInRva2VuS2V5IiwiY2xpZW50UGF0aCIsInJvdXRlcyIsIiRzdGF0ZVByb3ZpZGVyIiwiJHVybFJvdXRlclByb3ZpZGVyIiwic3RhdGUiLCJ1cmwiLCJ0ZW1wbGF0ZVVybCIsImFic3RyYWN0IiwicmVzb2x2ZSIsInRyYW5zbGF0ZVJlYWR5IiwiJHRyYW5zbGF0ZSIsIiRxIiwiZGVmZXJyZWQiLCJkZWZlciIsInVzZSIsInByb21pc2UiLCJkYXRhIiwibmVlZEF1dGhlbnRpY2F0aW9uIiwid2hlbiIsIm90aGVyd2lzZSIsInJ1biIsIiRyb290U2NvcGUiLCIkc3RhdGVQYXJhbXMiLCJhdXRoIiwiZ2xvYmFsIiwicmV0cmlldmVVc2VyRnJvbUxvY2FsU3RvcmFnZSIsIkF1ZGl0Q29udHJvbGxlciIsIiRjb250cm9sbGVyIiwiQXVkaXRTZXJ2aWNlIiwiUHJEaWFsb2ciLCJvbkFjdGl2YXRlIiwiYXBwbHlGaWx0ZXJzIiwidmlld0RldGFpbCIsIm1vZGVsU2VydmljZSIsIm9wdGlvbnMiLCJtb2RlbHMiLCJxdWVyeUZpbHRlcnMiLCJnZXRBdWRpdGVkTW9kZWxzIiwiaWQiLCJsYWJlbCIsImluc3RhbnQiLCJzb3J0IiwiaW5kZXgiLCJsZW5ndGgiLCJtb2RlbCIsInB1c2giLCJ0b0xvd2VyQ2FzZSIsInR5cGVzIiwibGlzdFR5cGVzIiwidHlwZSIsImRlZmF1bHRRdWVyeUZpbHRlcnMiLCJleHRlbmQiLCJhdWRpdERldGFpbCIsImxvY2FscyIsImNsb3NlIiwiaXNBcnJheSIsIm9sZCIsIm5ldyIsImNvbnRyb2xsZXJBcyIsImhhc0JhY2tkcm9wIiwiY3VzdG9tIiwibmVlZFByb2ZpbGUiLCJmYWN0b3J5Iiwic2VydmljZUZhY3RvcnkiLCJhY3Rpb25zIiwibWV0aG9kIiwiaW5zdGFuY2UiLCJhdWRpdFBhdGgiLCIkaHR0cCIsIlVzZXJzU2VydmljZSIsImxvZ2luIiwidXBkYXRlQ3VycmVudFVzZXIiLCJhdXRoZW50aWNhdGVkIiwic2VuZEVtYWlsUmVzZXRQYXNzd29yZCIsInJlbW90ZVZhbGlkYXRlVG9rZW4iLCJnZXRUb2tlbiIsInNldFRva2VuIiwiY2xlYXJUb2tlbiIsImxvY2FsU3RvcmFnZSIsInJlbW92ZUl0ZW0iLCJ0b2tlbiIsInNldEl0ZW0iLCJnZXRJdGVtIiwiZ2V0IiwicmVqZWN0IiwidXNlciIsIm1lcmdlIiwiZnJvbUpzb24iLCJqc29uVXNlciIsInRvSnNvbiIsImNyZWRlbnRpYWxzIiwicG9zdCIsInJlc3BvbnNlIiwiZXJyb3IiLCJyZXNldERhdGEiLCJMb2dpbkNvbnRyb2xsZXIiLCJvcGVuRGlhbG9nUmVzZXRQYXNzIiwib3BlbkRpYWxvZ1NpZ25VcCIsImVtYWlsIiwicGFzc3dvcmQiLCJQYXNzd29yZENvbnRyb2xsZXIiLCIkdGltZW91dCIsIlByVG9hc3QiLCJzZW5kUmVzZXQiLCJjbG9zZURpYWxvZyIsImNsZWFuRm9ybSIsInJlc2V0Iiwic3VjY2VzcyIsInN0YXR1cyIsIm1zZyIsImkiLCJ0b1VwcGVyQ2FzZSIsImZpZWxkIiwibWVzc2FnZSIsIiRtb2RlbEZhY3RvcnkiLCJwYWdpbmF0ZSIsIndyYXAiLCJhZnRlclJlcXVlc3QiLCJMaXN0IiwiQ1JVRENvbnRyb2xsZXIiLCJQclBhZ2luYXRpb24iLCJzZWFyY2giLCJwYWdpbmF0ZVNlYXJjaCIsIm5vcm1hbFNlYXJjaCIsImVkaXQiLCJzYXZlIiwicmVtb3ZlIiwiZ29UbyIsInJlZGlyZWN0QWZ0ZXJTYXZlIiwic2VhcmNoT25Jbml0IiwicGVyUGFnZSIsInNraXBQYWdpbmF0aW9uIiwidmlld0Zvcm0iLCJyZXNvdXJjZSIsImlzRnVuY3Rpb24iLCJwYWdpbmF0b3IiLCJnZXRJbnN0YW5jZSIsInBhZ2UiLCJjdXJyZW50UGFnZSIsImlzRGVmaW5lZCIsImJlZm9yZVNlYXJjaCIsImNhbGNOdW1iZXJPZlBhZ2VzIiwidG90YWwiLCJyZXNvdXJjZXMiLCJpdGVtcyIsImFmdGVyU2VhcmNoIiwicXVlcnkiLCJmb3JtIiwiYmVmb3JlQ2xlYW4iLCIkc2V0UHJpc3RpbmUiLCIkc2V0VW50b3VjaGVkIiwiYWZ0ZXJDbGVhbiIsImNvcHkiLCJhZnRlckVkaXQiLCJiZWZvcmVTYXZlIiwiJHNhdmUiLCJhZnRlclNhdmUiLCJyZXNwb25zZURhdGEiLCJvblNhdmVFcnJvciIsInRpdGxlIiwiZGVzY3JpcHRpb24iLCJjb25maXJtIiwiYmVmb3JlUmVtb3ZlIiwiJGRlc3Ryb3kiLCJhZnRlclJlbW92ZSIsImluZm8iLCJ2aWV3TmFtZSIsIkRhc2hib2FyZENvbnRyb2xsZXIiLCJEaW5hbWljUXVlcnlTZXJ2aWNlIiwiZ2V0TW9kZWxzIiwiRGluYW1pY1F1ZXJ5c0NvbnRyb2xsZXIiLCJsb2Rhc2giLCJsb2FkQXR0cmlidXRlcyIsImxvYWRPcGVyYXRvcnMiLCJhZGRGaWx0ZXIiLCJydW5GaWx0ZXIiLCJlZGl0RmlsdGVyIiwibG9hZE1vZGVscyIsInJlbW92ZUZpbHRlciIsImNsZWFyIiwicmVzdGFydCIsIndoZXJlIiwiYWRkZWRGaWx0ZXJzIiwibmFtZSIsImZpbHRlciIsImF0dHJpYnV0ZSIsIm9wZXJhdG9yIiwidmFsdWUiLCJmaWx0ZXJzIiwiYXR0cmlidXRlcyIsIm9wZXJhdG9ycyIsImluZGV4T2YiLCJpc1VuZGVmaW5lZCIsImtleXMiLCJPYmplY3QiLCJrZXkiLCJzdGFydHNXaXRoIiwiJGluZGV4Iiwic3BsaWNlIiwiTGFuZ3VhZ2VMb2FkZXIiLCJTdXBwb3J0U2VydmljZSIsIiRsb2ciLCIkaW5qZWN0b3IiLCJzZXJ2aWNlIiwidHJhbnNsYXRlIiwidmlld3MiLCJkaWFsb2ciLCJtZXNzYWdlcyIsImxhbmdzIiwidEF0dHIiLCIkZmlsdGVyIiwidEJyZWFkY3J1bWIiLCJzcGxpdCIsInRNb2RlbCIsImF1dGhlbnRpY2F0aW9uTGlzdGVuZXIiLCIkb24iLCJldmVudCIsInRvU3RhdGUiLCJjYXRjaCIsIndhcm4iLCJwcmV2ZW50RGVmYXVsdCIsImF1dGhvcml6YXRpb25MaXN0ZW5lciIsImhhc1Byb2ZpbGUiLCJhbGxQcm9maWxlcyIsInNwaW5uZXJJbnRlcmNlcHRvciIsIiRodHRwUHJvdmlkZXIiLCIkcHJvdmlkZSIsInNob3dIaWRlU3Bpbm5lciIsInJlcXVlc3QiLCJzaG93IiwiaGlkZSIsInJlc3BvbnNlRXJyb3IiLCJyZWplY3Rpb24iLCJpbnRlcmNlcHRvcnMiLCJ0b2tlbkludGVyY2VwdG9yIiwicmVkaXJlY3RXaGVuU2VydmVyTG9nZ2VkT3V0IiwiaGVhZGVycyIsInJlamVjdGlvblJlYXNvbnMiLCJ0b2tlbkVycm9yIiwiZm9yRWFjaCIsImlzIiwidmFsaWRhdGlvbkludGVyY2VwdG9yIiwic2hvd0Vycm9yVmFsaWRhdGlvbiIsInNraXBWYWxpZGF0aW9uIiwiZXJyb3JWYWxpZGF0aW9uIiwiTWVudUNvbnRyb2xsZXIiLCIkbWRTaWRlbmF2IiwiJG1kQ29sb3JzIiwib3BlbiIsIm9wZW5NZW51T3JSZWRpcmVjdFRvU3RhdGUiLCJtZW51UHJlZml4IiwiaXRlbnNNZW51IiwiaWNvbiIsInN1Ykl0ZW5zIiwicHJvZmlsZXMiLCJzaWRlbmF2U3R5bGUiLCJ0b3AiLCJnZXRDb2xvciIsImNvbnRlbnQiLCJ0ZXh0Q29sb3IiLCJjb2xvciIsImxpbmVCb3R0b20iLCJ0b2dnbGUiLCIkbWRNZW51IiwiZXYiLCJpdGVtIiwiY29sb3JQYWxldHRlcyIsImdldFRoZW1lQ29sb3IiLCJNYWlsc0NvbnRyb2xsZXIiLCJNYWlsc1NlcnZpY2UiLCJmaWx0ZXJTZWxlY3RlZCIsInNraW4iLCJsYW5ndWFnZSIsImFsbG93ZWRDb250ZW50IiwiZW50aXRpZXMiLCJoZWlnaHQiLCJleHRyYVBsdWdpbnMiLCJsb2FkVXNlcnMiLCJvcGVuVXNlckRpYWxvZyIsImFkZFVzZXJNYWlsIiwic2VuZCIsImNyaXRlcmlhIiwibmFtZU9yRW1haWwiLCJub3RVc2VycyIsIm1hcCIsIm1haWwiLCJ1c2VycyIsInByb3BlcnR5IiwidG9TdHJpbmciLCJsaW1pdCIsImZpbmQiLCJvbkluaXQiLCJ1c2VyRGlhbG9nSW5wdXQiLCJ0cmFuc2ZlclVzZXJGbiIsInJvbGVzU3RyIiwicm9sZXMiLCJqb2luIiwiUm9sZXNTZXJ2aWNlIiwiY2FjaGUiLCJjb21wb25lbnQiLCJyZXBsYWNlIiwidHJhbnNjbHVkZSIsInRvb2xiYXJCdXR0b25zIiwiZm9vdGVyQnV0dG9ucyIsImJpbmRpbmdzIiwiYm94VGl0bGUiLCJ0b29sYmFyQ2xhc3MiLCJ0b29sYmFyQmdDb2xvciIsIiR0cmFuc2NsdWRlIiwiY3RybCIsIiRvbkluaXQiLCJsYXlvdXRBbGlnbiIsIlByb2ZpbGVDb250cm9sbGVyIiwidXBkYXRlIiwidXBkYXRlUHJvZmlsZSIsIlVzZXJzQ29udHJvbGxlciIsImRlZmF1bHRzIiwib3ZlcnJpZGUiLCJhbGwiLCJ1c2VyUm9sZXMiLCJpbnRlcnNlY3Rpb24iLCJpc0FkbWluIiwiYXVkaXREZXRhaWxUaXRsZSIsImF1ZGl0TW9kZWwiLCJtb2RlbElkIiwiYXVkaXRUeXBlIiwidHlwZUlkIiwiYXVkaXRWYWx1ZSIsImlzRGF0ZSIsImVuZHNXaXRoIiwiTnVtYmVyIiwiaW5pdGlhbERhdGUiLCJmaW5hbERhdGUiLCJ0YXNrIiwiZG9uZSIsInByaW9yaXR5Iiwic2NoZWR1bGVkX3RvIiwicHJvamVjdCIsImNvc3QiLCJjb25maXJtVGl0bGUiLCJjb25maXJtRGVzY3JpcHRpb24iLCJyZW1vdmVEZXNjcmlwdGlvbiIsImF1ZGl0IiwiY3JlYXRlZCIsInVwZGF0ZWRCZWZvcmUiLCJ1cGRhdGVkQWZ0ZXIiLCJkZWxldGVkIiwicmVzZXRQYXNzd29yZCIsImxvYWRpbmciLCJwcm9jZXNzaW5nIiwieWVzIiwibm8iLCJpbnRlcm5hbEVycm9yIiwibm90Rm91bmQiLCJub3RBdXRob3JpemVkIiwic2VhcmNoRXJyb3IiLCJzYXZlU3VjY2VzcyIsIm9wZXJhdGlvblN1Y2Nlc3MiLCJvcGVyYXRpb25FcnJvciIsInNhdmVFcnJvciIsInJlbW92ZVN1Y2Nlc3MiLCJyZW1vdmVFcnJvciIsInJlc291cmNlTm90Rm91bmRFcnJvciIsIm5vdE51bGxFcnJvciIsImR1cGxpY2F0ZWRSZXNvdXJjZUVycm9yIiwidmFsaWRhdGUiLCJmaWVsZFJlcXVpcmVkIiwibGF5b3V0IiwiZXJyb3I0MDQiLCJsb2dvdXRJbmFjdGl2ZSIsImludmFsaWRDcmVkZW50aWFscyIsInVua25vd25FcnJvciIsInVzZXJOb3RGb3VuZCIsImRhc2hib2FyZCIsIndlbGNvbWUiLCJtYWlsRXJyb3JzIiwic2VuZE1haWxTdWNjZXNzIiwic2VuZE1haWxFcnJvciIsInBhc3N3b3JkU2VuZGluZ1N1Y2Nlc3MiLCJyZW1vdmVZb3VyU2VsZkVycm9yIiwidXNlckV4aXN0cyIsInByb2ZpbGUiLCJ1cGRhdGVFcnJvciIsInF1ZXJ5RGluYW1pYyIsIm5vRmlsdGVyIiwiYnJlYWRjcnVtYnMiLCJ0aXRsZXMiLCJtYWlsU2VuZCIsInRhc2tMaXN0IiwidXNlckxpc3QiLCJhdWRpdExpc3QiLCJyZWdpc3RlciIsImNsZWFyQWxsIiwibGlzdCIsImNhbmNlbCIsImdldE91dCIsImFkZCIsImluIiwibG9hZEltYWdlIiwic2lnbnVwIiwiZmllbGRzIiwiYWN0aW9uIiwiZGF0ZVN0YXJ0IiwiZGF0ZUVuZCIsImFsbFJlc291cmNlcyIsInVwZGF0ZWQiLCJjb25maXJtUGFzc3dvcmQiLCJ0byIsInN1YmplY3QiLCJyZXN1bHRzIiwiZXF1YWxzIiwiZGlmZXJlbnQiLCJjb250ZWlucyIsInN0YXJ0V2l0aCIsImZpbmlzaFdpdGgiLCJiaWdnZXJUaGFuIiwiZXF1YWxzT3JCaWdnZXJUaGFuIiwibGVzc1RoYW4iLCJlcXVhbHNPckxlc3NUaGFuIiwidG90YWxUYXNrIiwicGVyZmlscyIsIm1lbnUiLCJhZG1pbiIsImV4YW1wbGVzIiwiZGluYW1pY1F1ZXJ5IiwidG9vbHRpcHMiLCJwZXJmaWwiLCJ0cmFuc2ZlciIsImxpc3RUYXNrIiwiUHJvamVjdHNDb250cm9sbGVyIiwiUHJvamVjdHNTZXJ2aWNlIiwidmlld1Rhc2tzIiwicHJvamVjdElkIiwiZmluYWxseSIsIlRhc2tzRGlhbG9nQ29udHJvbGxlciIsIlRhc2tzU2VydmljZSIsInRvZ2dsZURvbmUiLCJwcm9qZWN0X2lkIiwidG9EYXRlIiwiVXNlcnNEaWFsb2dDb250cm9sbGVyIiwidHJhbnNmZXJVc2VyIl0sIm1hcHBpbmdzIjoiQUFBQTs7O0FDQ0EsQ0FBQyxZQUFXO0VBQ1Y7O0VBRUFBLFFBQVFDLE9BQU8sT0FBTyxDQUNwQixhQUNBLFVBQ0EsYUFDQSxZQUNBLGtCQUNBLGFBQ0EsY0FDQSxnQkFDQSxpQkFDQSx3QkFDQSwwQkFDQTs7QURSSjs7QUVSQyxDQUFBLFlBQVk7RUFDWDs7O0VBRUFELFFBQ0dDLE9BQU8sT0FDUEMsT0FBT0E7Ozs7RUFJVixTQUFTQSxPQUFPQyxRQUFRQyxvQkFBb0JDO0VBQzFDQyxvQkFBb0JDLFFBQVFDLGlCQUFpQjs7SUFFN0NGLG1CQUNHRyxVQUFVLGtCQUNWQyx5QkFBeUI7O0lBRTVCSixtQkFBbUJLLGlCQUFpQjs7SUFFcENKLE9BQU9LLE9BQU87OztJQUdkUCxzQkFBc0JRLGVBQWVDLFNBQVNYLE9BQU9ZOzs7SUFHckRYLG1CQUFtQlksTUFBTSxXQUN0QkMsZUFBZSxTQUFTO01BQ3ZCQyxTQUFTO09BRVZDLGNBQWMsU0FDZEMsWUFBWTs7O0lBR2ZoQixtQkFBbUJpQjs7SUFFbkJiLGdCQUFnQmM7OztBRk1wQjs7QUd4Q0EsQ0FBQyxZQUFXOztFQUVWOzs7RUFFQXRCLFFBQ0dDLE9BQU8sT0FDUHNCLFdBQVcsaUJBQWlCQzs7Ozs7OztFQU8vQixTQUFTQSxjQUFjQyxRQUFRQyxNQUFNdkIsUUFBUTtJQUMzQyxJQUFJd0IsS0FBSzs7O0lBR1RBLEdBQUdDLFdBQVc7O0lBRWRELEdBQUdFLFNBQWFBO0lBQ2hCRixHQUFHRyxpQkFBaUJBOztJQUVwQkM7O0lBRUEsU0FBU0EsV0FBVztNQUNsQixJQUFJQyxPQUFPLElBQUlDOztNQUVmTixHQUFHQyxXQUFXSSxLQUFLRTs7O0lBR3JCLFNBQVNMLFNBQVM7TUFDaEJILEtBQUtHLFNBQVNNLEtBQUssWUFBVztRQUM1QlYsT0FBT1csR0FBR2pDLE9BQU9rQzs7OztJQUlyQixTQUFTUCxpQkFBaUI7TUFDeEIsT0FBUUosS0FBS1ksZUFBZVosS0FBS1ksWUFBWUMsUUFDekNiLEtBQUtZLFlBQVlDLFFBQ2pCcEMsT0FBT3FDLFlBQVk7Ozs7QUgwQzdCOzs7QUloRkMsQ0FBQSxZQUFXO0VBQ1Y7Ozs7Ozs7RUFNQXhDLFFBQ0dDLE9BQU8sT0FDUHdDLFNBQVMsVUFBVUMsR0FDbkJELFNBQVMsVUFBVWxDOztBSm1GeEI7O0FLOUZDLENBQUEsWUFBVztFQUNWOztFQUVBUCxRQUNHQyxPQUFPLE9BQ1B3QyxTQUFTLFVBQVU7SUFDbEJFLFNBQVM7SUFDVEMsV0FBVztJQUNYQyxVQUFVO0lBQ1ZSLFlBQVk7SUFDWlMsb0JBQW9CO0lBQ3BCQyxvQkFBb0I7SUFDcEJDLFVBQVU7SUFDVkMsWUFBWTtJQUNabEMsU0FBUztJQUNUeUIsV0FBVzs7O0FMaUdqQjs7QU1oSEMsQ0FBQSxZQUFXO0VBQ1Y7OztFQUVBeEMsUUFDR0MsT0FBTyxPQUNQQyxPQUFPZ0Q7OztFQUdWLFNBQVNBLE9BQU9DLGdCQUFnQkMsb0JBQW9CakQsUUFBUTtJQUMxRGdELGVBQ0dFLE1BQU0sT0FBTztNQUNaQyxLQUFLO01BQ0xDLGFBQWFwRCxPQUFPOEMsYUFBYTtNQUNqQ08sVUFBVTtNQUNWQyxTQUFTO1FBQ1BDLGdCQUFnQixDQUFDLGNBQWMsTUFBTSxVQUFTQyxZQUFZQyxJQUFJO1VBQzVELElBQUlDLFdBQVdELEdBQUdFOztVQUVsQkgsV0FBV0ksSUFBSSxTQUFTNUIsS0FBSyxZQUFXO1lBQ3RDMEIsU0FBU0o7OztVQUdYLE9BQU9JLFNBQVNHOzs7T0FJckJYLE1BQU1sRCxPQUFPNEMsb0JBQW9CO01BQ2hDTyxLQUFLO01BQ0xDLGFBQWFwRCxPQUFPOEMsYUFBYTtNQUNqQ2dCLE1BQU0sRUFBRUMsb0JBQW9COzs7SUFHaENkLG1CQUFtQmUsS0FBSyxRQUFRaEUsT0FBTzBDO0lBQ3ZDTyxtQkFBbUJnQixVQUFVakUsT0FBTzBDOzs7QU5pSHhDOztBT2xKQyxDQUFBLFlBQVc7RUFDVjs7O0VBRUE3QyxRQUNHQyxPQUFPLE9BQ1BvRSxJQUFJQTs7OztFQUlQLFNBQVNBLElBQUlDLFlBQVk3QyxRQUFROEMsY0FBYzdDLE1BQU12QixRQUFROzs7SUFFM0RtRSxXQUFXN0MsU0FBU0E7SUFDcEI2QyxXQUFXQyxlQUFlQTtJQUMxQkQsV0FBV0UsT0FBTzlDO0lBQ2xCNEMsV0FBV0csU0FBU3RFOzs7O0lBSXBCdUIsS0FBS2dEOzs7QVBzSlQ7O0FReEtBLENBQUMsWUFBVzs7RUFFVjs7O0VBRUExRSxRQUNHQyxPQUFPLE9BQ1BzQixXQUFXLG1CQUFtQm9EOzs7O0VBSWpDLFNBQVNBLGdCQUFnQkMsYUFBYUMsY0FBY0MsVUFBVTNFLFFBQVF3RCxZQUFZOztJQUNoRixJQUFJaEMsS0FBSzs7SUFFVEEsR0FBR29ELGFBQWFBO0lBQ2hCcEQsR0FBR3FELGVBQWVBO0lBQ2xCckQsR0FBR3NELGFBQWFBOztJQUVoQkwsWUFBWSxrQkFBa0IsRUFBRWpELElBQUlBLElBQUl1RCxjQUFjTCxjQUFjTSxTQUFTOztJQUU3RSxTQUFTSixhQUFhO01BQ3BCcEQsR0FBR3lELFNBQVM7TUFDWnpELEdBQUcwRCxlQUFlOzs7TUFHbEJSLGFBQWFTLG1CQUFtQm5ELEtBQUssVUFBUzhCLE1BQU07UUFDbEQsSUFBSW1CLFNBQVMsQ0FBQyxFQUFFRyxJQUFJLElBQUlDLE9BQU83QixXQUFXOEIsUUFBUTs7UUFFbER4QixLQUFLbUIsT0FBT007O1FBRVosS0FBSyxJQUFJQyxRQUFRLEdBQUdBLFFBQVExQixLQUFLbUIsT0FBT1EsUUFBUUQsU0FBUztVQUN2RCxJQUFJRSxRQUFRNUIsS0FBS21CLE9BQU9POztVQUV4QlAsT0FBT1UsS0FBSztZQUNWUCxJQUFJTTtZQUNKTCxPQUFPN0IsV0FBVzhCLFFBQVEsWUFBWUksTUFBTUU7Ozs7UUFJaERwRSxHQUFHeUQsU0FBU0E7UUFDWnpELEdBQUcwRCxhQUFhUSxRQUFRbEUsR0FBR3lELE9BQU8sR0FBR0c7OztNQUd2QzVELEdBQUdxRSxRQUFRbkIsYUFBYW9CO01BQ3hCdEUsR0FBRzBELGFBQWFhLE9BQU92RSxHQUFHcUUsTUFBTSxHQUFHVDs7O0lBR3JDLFNBQVNQLGFBQWFtQixxQkFBcUI7TUFDekMsT0FBT25HLFFBQVFvRyxPQUFPRCxxQkFBcUJ4RSxHQUFHMEQ7OztJQUdoRCxTQUFTSixXQUFXb0IsYUFBYTtNQUMvQixJQUFJbkcsU0FBUztRQUNYb0csUUFBUSxFQUFFRCxhQUFhQTs7UUFFdkI5RSx3Q0FBWSxTQUFBLFdBQVM4RSxhQUFhdkIsVUFBVTtVQUMxQyxJQUFJbkQsS0FBSzs7VUFFVEEsR0FBRzRFLFFBQVFBOztVQUVYeEU7O1VBRUEsU0FBU0EsV0FBVztZQUNsQixJQUFJL0IsUUFBUXdHLFFBQVFILFlBQVlJLFFBQVFKLFlBQVlJLElBQUliLFdBQVcsR0FBR1MsWUFBWUksTUFBTTtZQUN4RixJQUFJekcsUUFBUXdHLFFBQVFILFlBQVlLLFFBQVFMLFlBQVlLLElBQUlkLFdBQVcsR0FBR1MsWUFBWUssTUFBTTs7WUFFeEYvRSxHQUFHMEUsY0FBY0E7OztVQUduQixTQUFTRSxRQUFRO1lBQ2Z6QixTQUFTeUI7OztRQUliSSxjQUFjO1FBQ2RwRCxhQUFhcEQsT0FBTzhDLGFBQWE7UUFDakMyRCxhQUFhOzs7TUFHZjlCLFNBQVMrQixPQUFPM0c7Ozs7QVI0S3RCOztBUzFQQyxDQUFBLFlBQVc7RUFDVjs7O0VBRUFGLFFBQ0dDLE9BQU8sT0FDUEMsT0FBT2dEOzs7Ozs7Ozs7RUFTVixTQUFTQSxPQUFPQyxnQkFBZ0JoRCxRQUFRO0lBQ3RDZ0QsZUFDR0UsTUFBTSxhQUFhO01BQ2xCQyxLQUFLO01BQ0xDLGFBQWFwRCxPQUFPOEMsYUFBYTtNQUNqQzFCLFlBQVk7TUFDWjBDLE1BQU0sRUFBRUMsb0JBQW9CLE1BQU00QyxhQUFhLENBQUM7Ozs7QVQ2UHhEOztBVWpSQyxDQUFBLFlBQVc7RUFDVjs7O0VBRUE5RyxRQUNHQyxPQUFPLE9BQ1A4RyxRQUFRLGdCQUFnQmxDOzs7O0VBSTNCLFNBQVNBLGFBQWFtQyxnQkFBZ0JyRCxZQUFZO0lBQ2hELE9BQU9xRCxlQUFlLFNBQVM7TUFDN0JDLFNBQVM7UUFDUDNCLGtCQUFrQjtVQUNoQjRCLFFBQVE7VUFDUjVELEtBQUs7OztNQUdUNkQsVUFBVTtNQUVWbEIsV0FBVyxTQUFBLFlBQVc7UUFDcEIsSUFBSW1CLFlBQVk7O1FBRWhCLE9BQU8sQ0FDTCxFQUFFN0IsSUFBSSxJQUFJQyxPQUFPN0IsV0FBVzhCLFFBQVEyQixZQUFZLG1CQUNoRCxFQUFFN0IsSUFBSSxXQUFXQyxPQUFPN0IsV0FBVzhCLFFBQVEyQixZQUFZLG1CQUN2RCxFQUFFN0IsSUFBSSxXQUFXQyxPQUFPN0IsV0FBVzhCLFFBQVEyQixZQUFZLG1CQUN2RCxFQUFFN0IsSUFBSSxXQUFXQyxPQUFPN0IsV0FBVzhCLFFBQVEyQixZQUFZOzs7OztBVmlSakU7O0FXM1NDLENBQUEsWUFBVztFQUNWOzs7RUFFQXBILFFBQ0dDLE9BQU8sT0FDUEMsT0FBT2dEOzs7Ozs7Ozs7RUFTVixTQUFTQSxPQUFPQyxnQkFBZ0JoRCxRQUFRO0lBQ3RDZ0QsZUFDR0UsTUFBTWxELE9BQU8yQyxvQkFBb0I7TUFDaENRLEtBQUs7TUFDTEMsYUFBYXBELE9BQU84QyxhQUFhO01BQ2pDMUIsWUFBWTtNQUNaMEMsTUFBTSxFQUFFQyxvQkFBb0I7T0FFN0JiLE1BQU1sRCxPQUFPa0MsWUFBWTtNQUN4QmlCLEtBQUs7TUFDTEMsYUFBYXBELE9BQU84QyxhQUFhO01BQ2pDMUIsWUFBWTtNQUNaMEMsTUFBTSxFQUFFQyxvQkFBb0I7Ozs7QVg2U3BDOztBWXZVQyxDQUFBLFlBQVc7RUFDVjs7O0VBRUFsRSxRQUNHQyxPQUFPLE9BQ1A4RyxRQUFRLFFBQVFyRjs7OztFQUluQixTQUFTQSxLQUFLMkYsT0FBT3pELElBQUl6RCxRQUFRbUgsY0FBYzs7SUFDN0MsSUFBSTlDLE9BQU87TUFDVCtDLE9BQU9BO01BQ1AxRixRQUFRQTtNQUNSMkYsbUJBQW1CQTtNQUNuQjlDLDhCQUE4QkE7TUFDOUIrQyxlQUFlQTtNQUNmQyx3QkFBd0JBO01BQ3hCQyxxQkFBcUJBO01BQ3JCQyxVQUFVQTtNQUNWQyxVQUFVQTtNQUNWQyxZQUFZQTtNQUNaeEYsYUFBYTs7O0lBR2YsU0FBU3dGLGFBQWE7TUFDcEJDLGFBQWFDLFdBQVc3SCxPQUFPNkM7OztJQUdqQyxTQUFTNkUsU0FBU0ksT0FBTztNQUN2QkYsYUFBYUcsUUFBUS9ILE9BQU82QyxVQUFVaUY7OztJQUd4QyxTQUFTTCxXQUFXO01BQ2xCLE9BQU9HLGFBQWFJLFFBQVFoSSxPQUFPNkM7OztJQUdyQyxTQUFTMkUsc0JBQXNCO01BQzdCLElBQUk5RCxXQUFXRCxHQUFHRTs7TUFFbEIsSUFBSVUsS0FBS2lELGlCQUFpQjtRQUN4QkosTUFBTWUsSUFBSWpJLE9BQU9ZLFVBQVUsdUJBQ3hCb0IsS0FBSyxZQUFXO1VBQ2YwQixTQUFTSixRQUFRO1dBQ2hCLFlBQVc7VUFDWmUsS0FBSzNDOztVQUVMZ0MsU0FBU3dFLE9BQU87O2FBRWY7UUFDTDdELEtBQUszQzs7UUFFTGdDLFNBQVN3RSxPQUFPOzs7TUFHbEIsT0FBT3hFLFNBQVNHOzs7Ozs7OztJQVFsQixTQUFTeUQsZ0JBQWdCO01BQ3ZCLE9BQU9qRCxLQUFLb0QsZUFBZTs7Ozs7O0lBTTdCLFNBQVNsRCwrQkFBK0I7TUFDdEMsSUFBSTRELE9BQU9QLGFBQWFJLFFBQVE7O01BRWhDLElBQUlHLE1BQU07UUFDUjlELEtBQUtsQyxjQUFjdEMsUUFBUXVJLE1BQU0sSUFBSWpCLGdCQUFnQnRILFFBQVF3SSxTQUFTRjs7Ozs7Ozs7Ozs7Ozs7SUFjMUUsU0FBU2Qsa0JBQWtCYyxNQUFNO01BQy9CLElBQUl6RSxXQUFXRCxHQUFHRTs7TUFFbEIsSUFBSXdFLE1BQU07UUFDUkEsT0FBT3RJLFFBQVF1SSxNQUFNLElBQUlqQixnQkFBZ0JnQjs7UUFFekMsSUFBSUcsV0FBV3pJLFFBQVEwSSxPQUFPSjs7UUFFOUJQLGFBQWFHLFFBQVEsUUFBUU87UUFDN0JqRSxLQUFLbEMsY0FBY2dHOztRQUVuQnpFLFNBQVNKLFFBQVE2RTthQUNaO1FBQ0xQLGFBQWFDLFdBQVc7UUFDeEJ4RCxLQUFLbEMsY0FBYztRQUNuQmtDLEtBQUtzRDs7UUFFTGpFLFNBQVN3RTs7O01BR1gsT0FBT3hFLFNBQVNHOzs7Ozs7Ozs7SUFTbEIsU0FBU3VELE1BQU1vQixhQUFhO01BQzFCLElBQUk5RSxXQUFXRCxHQUFHRTs7TUFFbEJ1RCxNQUFNdUIsS0FBS3pJLE9BQU9ZLFVBQVUsaUJBQWlCNEgsYUFDMUN4RyxLQUFLLFVBQVMwRyxVQUFVO1FBQ3ZCckUsS0FBS3FELFNBQVNnQixTQUFTNUUsS0FBS2dFOztRQUU1QixPQUFPWixNQUFNZSxJQUFJakksT0FBT1ksVUFBVTtTQUVuQ29CLEtBQUssVUFBUzBHLFVBQVU7UUFDdkJyRSxLQUFLZ0Qsa0JBQWtCcUIsU0FBUzVFLEtBQUtxRTs7UUFFckN6RSxTQUFTSjtTQUNSLFVBQVNxRixPQUFPO1FBQ2pCdEUsS0FBSzNDOztRQUVMZ0MsU0FBU3dFLE9BQU9TOzs7TUFHcEIsT0FBT2pGLFNBQVNHOzs7Ozs7Ozs7O0lBVWxCLFNBQVNuQyxTQUFTO01BQ2hCLElBQUlnQyxXQUFXRCxHQUFHRTs7TUFFbEJVLEtBQUtnRCxrQkFBa0I7TUFDdkIzRCxTQUFTSjs7TUFFVCxPQUFPSSxTQUFTRzs7Ozs7Ozs7SUFRbEIsU0FBUzBELHVCQUF1QnFCLFdBQVc7TUFDekMsSUFBSWxGLFdBQVdELEdBQUdFOztNQUVsQnVELE1BQU11QixLQUFLekksT0FBT1ksVUFBVSxtQkFBbUJnSSxXQUM1QzVHLEtBQUssVUFBUzBHLFVBQVU7UUFDdkJoRixTQUFTSixRQUFRb0YsU0FBUzVFO1NBQ3pCLFVBQVM2RSxPQUFPO1FBQ2pCakYsU0FBU3dFLE9BQU9TOzs7TUFHcEIsT0FBT2pGLFNBQVNHOzs7SUFHbEIsT0FBT1E7OztBWnVVWDs7QWFuZkEsQ0FBQyxZQUFXOztFQUVWOzs7RUFFQXhFLFFBQ0dDLE9BQU8sT0FDUHNCLFdBQVcsbUJBQW1CeUg7Ozs7RUFJakMsU0FBU0EsZ0JBQWdCdkgsUUFBUUMsTUFBTXZCLFFBQVEyRSxVQUFVO0lBQ3ZELElBQUluRCxLQUFLOztJQUVUQSxHQUFHNEYsUUFBUUE7SUFDWDVGLEdBQUdzSCxzQkFBc0JBO0lBQ3pCdEgsR0FBR3VILG1CQUFtQkE7O0lBRXRCbkg7O0lBRUEsU0FBU0EsV0FBVztNQUNsQkosR0FBR2dILGNBQWM7OztJQUduQixTQUFTcEIsUUFBUTtNQUNmLElBQUlvQixjQUFjO1FBQ2hCUSxPQUFPeEgsR0FBR2dILFlBQVlRO1FBQ3RCQyxVQUFVekgsR0FBR2dILFlBQVlTOzs7TUFHM0IxSCxLQUFLNkYsTUFBTW9CLGFBQWF4RyxLQUFLLFlBQVc7UUFDdENWLE9BQU9XLEdBQUdqQyxPQUFPeUM7Ozs7Ozs7SUFPckIsU0FBU3FHLHNCQUFzQjtNQUM3QixJQUFJL0ksU0FBUztRQUNYcUQsYUFBYXBELE9BQU84QyxhQUFhO1FBQ2pDMUIsWUFBWTtRQUNacUYsYUFBYTs7O01BR2Y5QixTQUFTK0IsT0FBTzNHOzs7OztJQUtsQixTQUFTZ0osbUJBQW1CO01BQzFCLElBQUloSixTQUFTO1FBQ1hxRCxhQUFhcEQsT0FBTzhDLGFBQWE7UUFDakMxQixZQUFZO1FBQ1pxRixhQUFhOzs7TUFHZjlCLFNBQVMrQixPQUFPM0c7Ozs7QWJ1ZnRCOztBYy9pQkEsQ0FBQyxZQUFZOztFQUVYOzs7RUFFQUYsUUFDR0MsT0FBTyxPQUNQc0IsV0FBVyxzQkFBc0I4SDs7OztFQUlwQyxTQUFTQSxtQkFBbUJsSixRQUFRb0UsY0FBYzhDLE9BQU9pQyxVQUFVN0g7RUFDakU4SCxTQUFTekUsVUFBVXBELE1BQU1pQyxZQUFZOztJQUVyQyxJQUFJaEMsS0FBSzs7SUFFVEEsR0FBRzZILFlBQVlBO0lBQ2Y3SCxHQUFHOEgsY0FBY0E7SUFDakI5SCxHQUFHK0gsWUFBWUE7SUFDZi9ILEdBQUcrRix5QkFBeUJBOztJQUU1QjNGOztJQUVBLFNBQVNBLFdBQVc7TUFDbEJKLEdBQUdnSSxRQUFRLEVBQUVSLE9BQU8sSUFBSWxCLE9BQU8xRCxhQUFhMEQ7Ozs7OztJQU05QyxTQUFTdUIsWUFBWTtNQUNuQm5DLE1BQU11QixLQUFLekksT0FBT1ksVUFBVSxtQkFBbUJZLEdBQUdnSSxPQUMvQ3hILEtBQUssWUFBWTtRQUNoQm9ILFFBQVFLLFFBQVFqRyxXQUFXOEIsUUFBUTtRQUNuQzZELFNBQVMsWUFBWTtVQUNuQjdILE9BQU9XLEdBQUdqQyxPQUFPa0M7V0FDaEI7U0FDRixVQUFVeUcsT0FBTztRQUNsQixJQUFJQSxNQUFNZSxXQUFXLE9BQU9mLE1BQU1lLFdBQVcsS0FBSztVQUNoRCxJQUFJQyxNQUFNOztVQUVWLEtBQUssSUFBSUMsSUFBSSxHQUFHQSxJQUFJakIsTUFBTTdFLEtBQUttRixTQUFTeEQsUUFBUW1FLEtBQUs7WUFDbkRELE9BQU9oQixNQUFNN0UsS0FBS21GLFNBQVNXLEtBQUs7O1VBRWxDUixRQUFRVCxNQUFNZ0IsSUFBSUU7Ozs7Ozs7O0lBUTFCLFNBQVN0Qyx5QkFBeUI7O01BRWhDLElBQUkvRixHQUFHZ0ksTUFBTVIsVUFBVSxJQUFJO1FBQ3pCSSxRQUFRVCxNQUFNbkYsV0FBVzhCLFFBQVEsbUNBQW1DLEVBQUV3RSxPQUFPO1FBQzdFOzs7TUFHRnZJLEtBQUtnRyx1QkFBdUIvRixHQUFHZ0ksT0FBT3hILEtBQUssVUFBVThCLE1BQU07UUFDekRzRixRQUFRSyxRQUFRM0YsS0FBS2lHOztRQUVyQnZJLEdBQUcrSDtRQUNIL0gsR0FBRzhIO1NBQ0YsVUFBVVgsT0FBTztRQUNsQixJQUFJQSxNQUFNN0UsS0FBS2tGLFNBQVNMLE1BQU03RSxLQUFLa0YsTUFBTXZELFNBQVMsR0FBRztVQUNuRCxJQUFJa0UsTUFBTTs7VUFFVixLQUFLLElBQUlDLElBQUksR0FBR0EsSUFBSWpCLE1BQU03RSxLQUFLa0YsTUFBTXZELFFBQVFtRSxLQUFLO1lBQ2hERCxPQUFPaEIsTUFBTTdFLEtBQUtrRixNQUFNWSxLQUFLOzs7VUFHL0JSLFFBQVFULE1BQU1nQjs7Ozs7SUFLcEIsU0FBU0wsY0FBYztNQUNyQjNFLFNBQVN5Qjs7O0lBR1gsU0FBU21ELFlBQVk7TUFDbkIvSCxHQUFHZ0ksTUFBTVIsUUFBUTs7OztBZGtqQnZCOzs7QWVsb0JBLENBQUMsWUFBVztFQUNWOzs7RUFFQW5KLFFBQ0dDLE9BQU8sT0FDUDhHLFFBQVEsa0JBQWtCQzs7Ozs7OztFQU83QixTQUFTQSxlQUFlbUQsZUFBZTtJQUNyQyxPQUFPLFVBQVM3RyxLQUFLNkIsU0FBUztNQUM1QixJQUFJVTtNQUNKLElBQUloRixpQkFBaUI7UUFDbkJvRyxTQUFTOzs7OztVQUtQbUQsVUFBVTtZQUNSbEQsUUFBUTtZQUNSVixTQUFTO1lBQ1Q2RCxNQUFNO1lBQ05DLGNBQWMsU0FBQSxhQUFTekIsVUFBVTtjQUMvQixJQUFJQSxTQUFTLFVBQVU7Z0JBQ3JCQSxTQUFTLFdBQVdoRCxNQUFNMEUsS0FBSzFCLFNBQVM7OztjQUcxQyxPQUFPQTs7Ozs7O01BTWZoRCxRQUFRc0UsY0FBYzdHLEtBQUt0RCxRQUFRdUksTUFBTTFILGdCQUFnQnNFOztNQUV6RCxPQUFPVTs7OztBZnVvQmI7O0FnQjlxQkEsQ0FBQyxZQUFXOztFQUVWOzs7RUFFQTdGLFFBQ0dDLE9BQU8sT0FDUHNCLFdBQVcsa0JBQWtCaUo7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7RUFrQ2hDLFNBQVNBLGVBQWU3SSxJQUFJdUQsY0FBY0MsU0FBU29FLFNBQVNrQjtFQUMxRDNGLFVBQVVuQixZQUFZOzs7SUFHdEJoQyxHQUFHK0ksU0FBU0E7SUFDWi9JLEdBQUdnSixpQkFBaUJBO0lBQ3BCaEosR0FBR2lKLGVBQWVBO0lBQ2xCakosR0FBR2tKLE9BQU9BO0lBQ1ZsSixHQUFHbUosT0FBT0E7SUFDVm5KLEdBQUdvSixTQUFTQTtJQUNacEosR0FBR3FKLE9BQU9BO0lBQ1ZySixHQUFHK0gsWUFBWUE7O0lBRWYzSDs7Ozs7Ozs7SUFRQSxTQUFTQSxXQUFXO01BQ2xCSixHQUFHZCxpQkFBaUI7UUFDbEJvSyxtQkFBbUI7UUFDbkJDLGNBQWM7UUFDZEMsU0FBUztRQUNUQyxnQkFBZ0I7OztNQUdsQnBMLFFBQVF1SSxNQUFNNUcsR0FBR2QsZ0JBQWdCc0U7O01BRWpDeEQsR0FBRzBKLFdBQVc7TUFDZDFKLEdBQUcySixXQUFXLElBQUlwRzs7TUFFbEIsSUFBSWxGLFFBQVF1TCxXQUFXNUosR0FBR29ELGFBQWFwRCxHQUFHb0Q7O01BRTFDcEQsR0FBRzZKLFlBQVlmLGFBQWFnQixZQUFZOUosR0FBRytJLFFBQVEvSSxHQUFHZCxlQUFlc0s7O01BRXJFLElBQUl4SixHQUFHZCxlQUFlcUssY0FBY3ZKLEdBQUcrSTs7Ozs7Ozs7O0lBU3pDLFNBQVNBLE9BQU9nQixNQUFNO01BQ25CL0osR0FBR2QsZUFBZXVLLGlCQUFrQlIsaUJBQWlCRCxlQUFlZTs7Ozs7Ozs7SUFRdkUsU0FBU2YsZUFBZWUsTUFBTTtNQUM1Qi9KLEdBQUc2SixVQUFVRyxjQUFlM0wsUUFBUTRMLFVBQVVGLFFBQVNBLE9BQU87TUFDOUQvSixHQUFHd0Usc0JBQXNCLEVBQUV1RixNQUFNL0osR0FBRzZKLFVBQVVHLGFBQWFSLFNBQVN4SixHQUFHNkosVUFBVUw7O01BRWpGLElBQUluTCxRQUFRdUwsV0FBVzVKLEdBQUdxRCxlQUFlckQsR0FBR3dFLHNCQUFzQnhFLEdBQUdxRCxhQUFhckQsR0FBR3dFO01BQ3JGLElBQUluRyxRQUFRdUwsV0FBVzVKLEdBQUdrSyxpQkFBaUJsSyxHQUFHa0ssYUFBYUgsVUFBVSxPQUFPLE9BQU87O01BRW5GeEcsYUFBYWtGLFNBQVN6SSxHQUFHd0UscUJBQXFCaEUsS0FBSyxVQUFVMEcsVUFBVTtRQUNyRWxILEdBQUc2SixVQUFVTSxrQkFBa0JqRCxTQUFTa0Q7UUFDeENwSyxHQUFHcUssWUFBWW5ELFNBQVNvRDs7UUFFeEIsSUFBSWpNLFFBQVF1TCxXQUFXNUosR0FBR3VLLGNBQWN2SyxHQUFHdUssWUFBWXJEOzs7Ozs7OztJQVEzRCxTQUFTK0IsZUFBZTtNQUN0QmpKLEdBQUd3RSxzQkFBc0I7O01BRXpCLElBQUluRyxRQUFRdUwsV0FBVzVKLEdBQUdxRCxlQUFlckQsR0FBR3dFLHNCQUFzQnhFLEdBQUdxRCxhQUFhckQsR0FBR3dFO01BQ3JGLElBQUluRyxRQUFRdUwsV0FBVzVKLEdBQUdrSyxpQkFBaUJsSyxHQUFHa0ssbUJBQW1CLE9BQU8sT0FBTzs7TUFFL0UzRyxhQUFhaUgsTUFBTXhLLEdBQUd3RSxxQkFBcUJoRSxLQUFLLFVBQVUwRyxVQUFVO1FBQ2xFbEgsR0FBR3FLLFlBQVluRDs7UUFFZixJQUFJN0ksUUFBUXVMLFdBQVc1SixHQUFHdUssY0FBY3ZLLEdBQUd1SyxZQUFZckQ7Ozs7Ozs7SUFPM0QsU0FBU2EsVUFBVTBDLE1BQU07TUFDdkIsSUFBSXBNLFFBQVF1TCxXQUFXNUosR0FBRzBLLGdCQUFnQjFLLEdBQUcwSyxrQkFBa0IsT0FBTyxPQUFPOztNQUU3RTFLLEdBQUcySixXQUFXLElBQUlwRzs7TUFFbEIsSUFBSWxGLFFBQVE0TCxVQUFVUSxPQUFPO1FBQzNCQSxLQUFLRTtRQUNMRixLQUFLRzs7O01BR1AsSUFBSXZNLFFBQVF1TCxXQUFXNUosR0FBRzZLLGFBQWE3SyxHQUFHNks7Ozs7Ozs7O0lBUTVDLFNBQVMzQixLQUFLUyxVQUFVO01BQ3RCM0osR0FBR3FKLEtBQUs7TUFDUnJKLEdBQUcySixXQUFXLElBQUl0TCxRQUFReU0sS0FBS25COztNQUUvQixJQUFJdEwsUUFBUXVMLFdBQVc1SixHQUFHK0ssWUFBWS9LLEdBQUcrSzs7Ozs7Ozs7OztJQVUzQyxTQUFTNUIsS0FBS3NCLE1BQU07TUFDbEIsSUFBSXBNLFFBQVF1TCxXQUFXNUosR0FBR2dMLGVBQWVoTCxHQUFHZ0wsaUJBQWlCLE9BQU8sT0FBTzs7TUFFM0VoTCxHQUFHMkosU0FBU3NCLFFBQVF6SyxLQUFLLFVBQVVtSixVQUFVO1FBQzNDM0osR0FBRzJKLFdBQVdBOztRQUVkLElBQUl0TCxRQUFRdUwsV0FBVzVKLEdBQUdrTCxZQUFZbEwsR0FBR2tMLFVBQVV2Qjs7UUFFbkQsSUFBSTNKLEdBQUdkLGVBQWVvSyxtQkFBbUI7VUFDdkN0SixHQUFHK0gsVUFBVTBDO1VBQ2J6SyxHQUFHK0ksT0FBTy9JLEdBQUc2SixVQUFVRztVQUN2QmhLLEdBQUdxSixLQUFLOzs7UUFHVnpCLFFBQVFLLFFBQVFqRyxXQUFXOEIsUUFBUTtTQUVsQyxVQUFVcUgsY0FBYztRQUN6QixJQUFJOU0sUUFBUXVMLFdBQVc1SixHQUFHb0wsY0FBY3BMLEdBQUdvTCxZQUFZRDs7Ozs7Ozs7OztJQVUzRCxTQUFTL0IsT0FBT08sVUFBVTtNQUN4QixJQUFJcEwsU0FBUztRQUNYOE0sT0FBT3JKLFdBQVc4QixRQUFRO1FBQzFCd0gsYUFBYXRKLFdBQVc4QixRQUFROzs7TUFHbENYLFNBQVNvSSxRQUFRaE4sUUFBUWlDLEtBQUssWUFBVztRQUN2QyxJQUFJbkMsUUFBUXVMLFdBQVc1SixHQUFHd0wsaUJBQWlCeEwsR0FBR3dMLGFBQWE3QixjQUFjLE9BQU8sT0FBTzs7UUFFdkZBLFNBQVM4QixXQUFXakwsS0FBSyxZQUFZO1VBQ25DLElBQUluQyxRQUFRdUwsV0FBVzVKLEdBQUcwTCxjQUFjMUwsR0FBRzBMLFlBQVkvQjs7VUFFdkQzSixHQUFHK0k7VUFDSG5CLFFBQVErRCxLQUFLM0osV0FBVzhCLFFBQVE7Ozs7Ozs7Ozs7SUFVdEMsU0FBU3VGLEtBQUt1QyxVQUFVO01BQ3RCNUwsR0FBRzBKLFdBQVc7O01BRWQsSUFBSWtDLGFBQWEsUUFBUTtRQUN2QjVMLEdBQUcrSDtRQUNIL0gsR0FBRzBKLFdBQVc7Ozs7O0FoQmtyQnRCOztBaUI1NEJBLENBQUMsWUFBVzs7RUFFVjs7RUFFQXJMLFFBQ0dDLE9BQU8sT0FDUHNCLFdBQVcsdUJBQXVCaU07Ozs7Ozs7OztFQVNyQyxTQUFTQSxzQkFBc0I7Ozs7O0FqQmk1QmpDOztBa0JoNkJDLENBQUEsWUFBVztFQUNWOzs7RUFFQXhOLFFBQ0dDLE9BQU8sT0FDUEMsT0FBT2dEOzs7Ozs7Ozs7RUFTVixTQUFTQSxPQUFPQyxnQkFBZ0JoRCxRQUFRO0lBQ3RDZ0QsZUFDR0UsTUFBTWxELE9BQU95QyxXQUFXO01BQ3ZCVSxLQUFLO01BQ0xDLGFBQWFwRCxPQUFPOEMsYUFBYTtNQUNqQzFCLFlBQVk7TUFDWjBDLE1BQU0sRUFBRUMsb0JBQW9COzs7O0FsQm02QnBDOztBbUJ2N0JDLENBQUEsWUFBVztFQUNWOzs7RUFFQWxFLFFBQ0dDLE9BQU8sT0FDUEMsT0FBT2dEOzs7Ozs7Ozs7RUFTVixTQUFTQSxPQUFPQyxnQkFBZ0JoRCxRQUFRO0lBQ3RDZ0QsZUFDR0UsTUFBTSxxQkFBcUI7TUFDMUJDLEtBQUs7TUFDTEMsYUFBYXBELE9BQU84QyxhQUFhO01BQ2pDMUIsWUFBWTtNQUNaMEMsTUFBTSxFQUFFQyxvQkFBb0IsTUFBTTRDLGFBQWEsQ0FBQzs7OztBbkIwN0J4RDs7QW9COThCQyxDQUFBLFlBQVc7RUFDVjs7O0VBRUE5RyxRQUNHQyxPQUFPLE9BQ1A4RyxRQUFRLHVCQUF1QjBHOzs7O0VBSWxDLFNBQVNBLG9CQUFvQnpHLGdCQUFnQjtJQUMzQyxPQUFPQSxlQUFlLGdCQUFnQjs7OztNQUlwQ0MsU0FBUztRQUNQeUcsV0FBVztVQUNUeEcsUUFBUTtVQUNSNUQsS0FBSzs7O01BR1Q2RCxVQUFVOzs7O0FwQms5QmhCOztBcUJ0K0JBLENBQUMsWUFBVzs7RUFFVjs7O0VBRUFuSCxRQUNHQyxPQUFPLE9BQ1BzQixXQUFXLDJCQUEyQm9NOzs7O0VBSXpDLFNBQVNBLHdCQUF3Qi9JLGFBQWE2SSxxQkFBcUJHLFFBQVFyRTtFQUN6RTVGLFlBQVk7O0lBRVosSUFBSWhDLEtBQUs7OztJQUdUQSxHQUFHb0QsYUFBYUE7SUFDaEJwRCxHQUFHcUQsZUFBZUE7SUFDbEJyRCxHQUFHa00saUJBQWlCQTtJQUNwQmxNLEdBQUdtTSxnQkFBZ0JBO0lBQ25Cbk0sR0FBR29NLFlBQVlBO0lBQ2ZwTSxHQUFHdUssY0FBY0E7SUFDakJ2SyxHQUFHcU0sWUFBWUE7SUFDZnJNLEdBQUdzTSxhQUFhQTtJQUNoQnRNLEdBQUd1TSxhQUFhQTtJQUNoQnZNLEdBQUd3TSxlQUFlQTtJQUNsQnhNLEdBQUd5TSxRQUFRQTtJQUNYek0sR0FBRzBNLFVBQVVBOzs7SUFHYnpKLFlBQVksa0JBQWtCLEVBQUVqRCxJQUFJQSxJQUFJdUQsY0FBY3VJLHFCQUFxQnRJLFNBQVM7UUFDbEYrRixjQUFjOzs7SUFHaEIsU0FBU25HLGFBQWE7TUFDcEJwRCxHQUFHME07Ozs7Ozs7OztJQVNMLFNBQVNySixhQUFhbUIscUJBQXFCO01BQ3pDLElBQUltSSxRQUFROzs7Ozs7O01BT1osSUFBSTNNLEdBQUc0TSxhQUFhM0ksU0FBUyxHQUFHO1FBQzlCLElBQUkySSxlQUFldk8sUUFBUXlNLEtBQUs5SyxHQUFHNE07O1FBRW5DRCxNQUFNekksUUFBUWxFLEdBQUc0TSxhQUFhLEdBQUcxSSxNQUFNMkk7O1FBRXZDLEtBQUssSUFBSTdJLFFBQVEsR0FBR0EsUUFBUTRJLGFBQWEzSSxRQUFRRCxTQUFTO1VBQ3hELElBQUk4SSxTQUFTRixhQUFhNUk7O1VBRTFCOEksT0FBTzVJLFFBQVE7VUFDZjRJLE9BQU9DLFlBQVlELE9BQU9DLFVBQVVGO1VBQ3BDQyxPQUFPRSxXQUFXRixPQUFPRSxTQUFTQzs7O1FBR3BDTixNQUFNTyxVQUFVN08sUUFBUTBJLE9BQU82RjthQUMxQjtRQUNMRCxNQUFNekksUUFBUWxFLEdBQUcwRCxhQUFhUSxNQUFNMkk7OztNQUd0QyxPQUFPeE8sUUFBUW9HLE9BQU9ELHFCQUFxQm1JOzs7Ozs7SUFNN0MsU0FBU0osYUFBYTs7TUFFcEJULG9CQUFvQkMsWUFBWXZMLEtBQUssVUFBUzhCLE1BQU07UUFDbER0QyxHQUFHeUQsU0FBU25CO1FBQ1p0QyxHQUFHMEQsYUFBYVEsUUFBUWxFLEdBQUd5RCxPQUFPO1FBQ2xDekQsR0FBR2tNOzs7Ozs7O0lBT1AsU0FBU0EsaUJBQWlCO01BQ3hCbE0sR0FBR21OLGFBQWFuTixHQUFHMEQsYUFBYVEsTUFBTWlKO01BQ3RDbk4sR0FBRzBELGFBQWFxSixZQUFZL00sR0FBR21OLFdBQVc7O01BRTFDbk4sR0FBR21NOzs7Ozs7SUFNTCxTQUFTQSxnQkFBZ0I7TUFDdkIsSUFBSWlCLFlBQVksQ0FDZCxFQUFFSCxPQUFPLEtBQUtwSixPQUFPN0IsV0FBVzhCLFFBQVEsaURBQ3hDLEVBQUVtSixPQUFPLE1BQU1wSixPQUFPN0IsV0FBVzhCLFFBQVE7O01BRzNDLElBQUk5RCxHQUFHMEQsYUFBYXFKLFVBQVV4SSxLQUFLOEksUUFBUSxlQUFlLENBQUMsR0FBRztRQUM1REQsVUFBVWpKLEtBQUssRUFBRThJLE9BQU87VUFDdEJwSixPQUFPN0IsV0FBVzhCLFFBQVE7UUFDNUJzSixVQUFVakosS0FBSyxFQUFFOEksT0FBTztVQUN0QnBKLE9BQU83QixXQUFXOEIsUUFBUTtRQUM1QnNKLFVBQVVqSixLQUFLLEVBQUU4SSxPQUFPO1VBQ3RCcEosT0FBTzdCLFdBQVc4QixRQUFRO2FBQ3ZCO1FBQ0xzSixVQUFVakosS0FBSyxFQUFFOEksT0FBTztVQUN0QnBKLE9BQU83QixXQUFXOEIsUUFBUTtRQUM1QnNKLFVBQVVqSixLQUFLLEVBQUU4SSxPQUFPO1VBQ3RCcEosT0FBTzdCLFdBQVc4QixRQUFRO1FBQzVCc0osVUFBVWpKLEtBQUssRUFBRThJLE9BQU87VUFDdEJwSixPQUFPN0IsV0FBVzhCLFFBQVE7UUFDNUJzSixVQUFVakosS0FBSyxFQUFFOEksT0FBTztVQUN0QnBKLE9BQU83QixXQUFXOEIsUUFBUTs7O01BRzlCOUQsR0FBR29OLFlBQVlBO01BQ2ZwTixHQUFHMEQsYUFBYXNKLFdBQVdoTixHQUFHb04sVUFBVTs7Ozs7Ozs7SUFRMUMsU0FBU2hCLFVBQVUzQixNQUFNO01BQ3ZCLElBQUlwTSxRQUFRaVAsWUFBWXROLEdBQUcwRCxhQUFhdUosVUFBVWpOLEdBQUcwRCxhQUFhdUosVUFBVSxJQUFJO1FBQzlFckYsUUFBUVQsTUFBTW5GLFdBQVc4QixRQUFRLG1DQUFtQyxFQUFFd0UsT0FBTztRQUM3RTthQUNLO1FBQ0wsSUFBSXRJLEdBQUdnRSxRQUFRLEdBQUc7VUFDaEJoRSxHQUFHNE0sYUFBYXpJLEtBQUs5RixRQUFReU0sS0FBSzlLLEdBQUcwRDtlQUNoQztVQUNMMUQsR0FBRzRNLGFBQWE1TSxHQUFHZ0UsU0FBUzNGLFFBQVF5TSxLQUFLOUssR0FBRzBEO1VBQzVDMUQsR0FBR2dFLFFBQVEsQ0FBQzs7OztRQUlkaEUsR0FBRzBELGVBQWU7UUFDbEIrRyxLQUFLRTtRQUNMRixLQUFLRzs7Ozs7OztJQU9ULFNBQVN5QixZQUFZO01BQ25Cck0sR0FBRytJLE9BQU8vSSxHQUFHNkosVUFBVUc7Ozs7Ozs7OztJQVN6QixTQUFTTyxZQUFZakksTUFBTTtNQUN6QixJQUFJaUwsT0FBUWpMLEtBQUtnSSxNQUFNckcsU0FBUyxJQUFLdUosT0FBT0QsS0FBS2pMLEtBQUtnSSxNQUFNLE1BQU07Ozs7TUFJbEV0SyxHQUFHdU4sT0FBT3RCLE9BQU9hLE9BQU9TLE1BQU0sVUFBU0UsS0FBSztRQUMxQyxPQUFPLENBQUN4QixPQUFPeUIsV0FBV0QsS0FBSzs7Ozs7Ozs7SUFRbkMsU0FBU25CLFdBQVdxQixRQUFRO01BQzFCM04sR0FBR2dFLFFBQVEySjtNQUNYM04sR0FBRzBELGVBQWUxRCxHQUFHNE0sYUFBYWU7Ozs7Ozs7O0lBUXBDLFNBQVNuQixhQUFhbUIsUUFBUTtNQUM1QjNOLEdBQUc0TSxhQUFhZ0IsT0FBT0Q7Ozs7OztJQU16QixTQUFTbEIsUUFBUTs7TUFFZnpNLEdBQUdnRSxRQUFRLENBQUM7O01BRVpoRSxHQUFHMEQsZUFBZTs7TUFHbEIsSUFBSTFELEdBQUd5RCxRQUFRekQsR0FBRzBELGFBQWFRLFFBQVFsRSxHQUFHeUQsT0FBTzs7Ozs7OztJQU9uRCxTQUFTaUosVUFBVTs7TUFFakIxTSxHQUFHdU4sT0FBTzs7O01BR1Z2TixHQUFHNE0sZUFBZTtNQUNsQjVNLEdBQUd5TTtNQUNIek0sR0FBR3VNOzs7O0FyQnMrQlQ7O0FzQjdyQ0EsQ0FBQyxZQUFXOztFQUVWOzs7RUFFQWxPLFFBQ0dDLE9BQU8sT0FDUDhHLFFBQVEsa0JBQWtCeUk7Ozs7RUFJN0IsU0FBU0EsZUFBZTVMLElBQUk2TCxnQkFBZ0JDLE1BQU1DLFdBQVc7SUFDM0QsSUFBSUMsVUFBVTs7SUFFZEEsUUFBUUMsWUFBWSxVQUFTalAsUUFBUTtNQUNuQyxPQUFPO1FBQ0w2RCxRQUFRa0wsVUFBVXZILElBQUl4SCxTQUFTO1FBQy9Ca1AsT0FBT0gsVUFBVXZILElBQUl4SCxTQUFTO1FBQzlCa08sWUFBWWEsVUFBVXZILElBQUl4SCxTQUFTO1FBQ25DbVAsUUFBUUosVUFBVXZILElBQUl4SCxTQUFTO1FBQy9Cb1AsVUFBVUwsVUFBVXZILElBQUl4SCxTQUFTO1FBQ2pDd0UsUUFBUXVLLFVBQVV2SCxJQUFJeEgsU0FBUzs7Ozs7SUFLbkMsT0FBTyxVQUFTdUUsU0FBUztNQUN2QnVLLEtBQUtwQyxLQUFLLHdDQUF3Q25JLFFBQVFpSzs7TUFFMUQsSUFBSXZMLFdBQVdELEdBQUdFOzs7TUFHbEIyTCxlQUFlUSxRQUFROU4sS0FBSyxVQUFTOE4sT0FBTzs7UUFFMUMsSUFBSWhNLE9BQU9qRSxRQUFRdUksTUFBTXFILFFBQVFDLFVBQVUxSyxRQUFRaUssTUFBTWE7O1FBRXpELE9BQU9wTSxTQUFTSixRQUFRUTtTQUN2QixZQUFXO1FBQ1osT0FBT0osU0FBU0osUUFBUW1NLFFBQVFDLFVBQVUxSyxRQUFRaUs7OztNQUdwRCxPQUFPdkwsU0FBU0c7Ozs7QXRCaXNDdEI7O0F1Qnp1Q0EsQ0FBQyxZQUFXOztFQUVWOzs7RUFFQWhFLFFBQ0dDLE9BQU8sT0FDUHdPLE9BQU8sU0FBU3lCOzs7O0VBSW5CLFNBQVNBLE1BQU1DLFNBQVM7Ozs7Ozs7SUFPdEIsT0FBTyxVQUFTM0IsTUFBTTtNQUNwQixJQUFJWSxNQUFNLGdCQUFnQlo7TUFDMUIsSUFBSXFCLFlBQVlNLFFBQVEsYUFBYWY7O01BRXJDLE9BQVFTLGNBQWNULE1BQU9aLE9BQU9xQjs7OztBdkI2dUMxQzs7QXdCbHdDQSxDQUFDLFlBQVc7O0VBRVY7OztFQUVBN1AsUUFDR0MsT0FBTyxPQUNQd08sT0FBTyxlQUFlMkI7Ozs7RUFJekIsU0FBU0EsWUFBWUQsU0FBUzs7Ozs7OztJQU81QixPQUFPLFVBQVM1SyxJQUFJOztNQUVsQixJQUFJNkosTUFBTSx1QkFBdUI3SixHQUFHOEssTUFBTSxLQUFLO01BQy9DLElBQUlSLFlBQVlNLFFBQVEsYUFBYWY7O01BRXJDLE9BQVFTLGNBQWNULE1BQU83SixLQUFLc0s7Ozs7QXhCc3dDeEM7O0F5QjV4Q0EsQ0FBQyxZQUFXOztFQUVWOzs7RUFFQTdQLFFBQ0dDLE9BQU8sT0FDUHdPLE9BQU8sVUFBVTZCOzs7O0VBSXBCLFNBQVNBLE9BQU9ILFNBQVM7Ozs7Ozs7SUFPdkIsT0FBTyxVQUFTM0IsTUFBTTtNQUNwQixJQUFJWSxNQUFNLFlBQVlaLEtBQUt6STtNQUMzQixJQUFJOEosWUFBWU0sUUFBUSxhQUFhZjs7TUFFckMsT0FBUVMsY0FBY1QsTUFBT1osT0FBT3FCOzs7O0F6Qmd5QzFDOztBMEJyekNDLENBQUEsWUFBVztFQUNWOzs7RUFFQTdQLFFBQ0dDLE9BQU8sT0FDUG9FLElBQUlrTTs7Ozs7Ozs7Ozs7Ozs7Ozs7O0VBa0JQLFNBQVNBLHVCQUF1QmpNLFlBQVk3QyxRQUFRdEIsUUFBUXVCLE1BQU02SDtFQUNoRTVGLFlBQVk7OztJQUdaakMsS0FBS2lHLHNCQUFzQnhGLEtBQUssWUFBVzs7O01BR3pDLElBQUlULEtBQUtZLGdCQUFnQixNQUFNO1FBQzdCWixLQUFLOEYsa0JBQWtCeEgsUUFBUXdJLFNBQVNULGFBQWFJLFFBQVE7Ozs7O0lBS2pFN0QsV0FBV2tNLElBQUkscUJBQXFCLFVBQVNDLE9BQU9DLFNBQVM7TUFDM0QsSUFBSUEsUUFBUXpNLEtBQUtDLHNCQUFzQndNLFFBQVF6TSxLQUFLNkMsYUFBYTs7UUFFL0RwRixLQUFLaUcsc0JBQXNCZ0osTUFBTSxZQUFXO1VBQzFDcEgsUUFBUXFILEtBQUtqTixXQUFXOEIsUUFBUTs7VUFFaEMsSUFBSWlMLFFBQVFsQyxTQUFTck8sT0FBT2tDLFlBQVk7WUFDdENaLE9BQU9XLEdBQUdqQyxPQUFPa0M7OztVQUduQm9PLE1BQU1JOzthQUVIOzs7UUFHTCxJQUFJSCxRQUFRbEMsU0FBU3JPLE9BQU9rQyxjQUFjWCxLQUFLK0YsaUJBQWlCO1VBQzlEaEcsT0FBT1csR0FBR2pDLE9BQU95QztVQUNqQjZOLE1BQU1JOzs7Ozs7QTFCMnpDaEI7O0EyQmgzQ0MsQ0FBQSxZQUFXO0VBQ1Y7OztFQUVBN1EsUUFDR0MsT0FBTyxPQUNQb0UsSUFBSXlNOzs7RUFHUCxTQUFTQSxzQkFBc0J4TSxZQUFZN0MsUUFBUXRCLFFBQVF1QixNQUFNOzs7OztJQUsvRDRDLFdBQVdrTSxJQUFJLHFCQUFxQixVQUFTQyxPQUFPQyxTQUFTO01BQzNELElBQUlBLFFBQVF6TSxRQUFReU0sUUFBUXpNLEtBQUtDLHNCQUMvQndNLFFBQVF6TSxLQUFLNkMsZUFBZXBGLEtBQUsrRixtQkFDakMsQ0FBQy9GLEtBQUtZLFlBQVl5TyxXQUFXTCxRQUFRek0sS0FBSzZDLGFBQWE0SixRQUFRek0sS0FBSytNLGNBQWM7O1FBRWxGdlAsT0FBT1csR0FBR2pDLE9BQU80QztRQUNqQjBOLE1BQU1JOzs7OztBM0JtM0NkOztBNEJ0NENDLENBQUEsWUFBWTtFQUNYOzs7RUFFQTdRLFFBQ0dDLE9BQU8sT0FDUEMsT0FBTytROztFQUVWLFNBQVNBLG1CQUFtQkMsZUFBZUMsVUFBVTs7Ozs7Ozs7Ozs7SUFVbkQsU0FBU0MsZ0JBQWdCeE4sSUFBSStMLFdBQVc7TUFDdEMsT0FBTztRQUNMMEIsU0FBUyxTQUFBLFFBQVVuUixRQUFRO1VBQ3pCeVAsVUFBVXZILElBQUksYUFBYWtKOztVQUUzQixPQUFPcFI7OztRQUdUMkksVUFBVSxTQUFBLFNBQVVBLFdBQVU7VUFDNUI4RyxVQUFVdkgsSUFBSSxhQUFhbUo7O1VBRTNCLE9BQU8xSTs7O1FBR1QySSxlQUFlLFNBQUEsY0FBVUMsV0FBVztVQUNsQzlCLFVBQVV2SCxJQUFJLGFBQWFtSjs7VUFFM0IsT0FBTzNOLEdBQUd5RSxPQUFPb0o7Ozs7OztJQU12Qk4sU0FBU3BLLFFBQVEsbUJBQW1CcUs7OztJQUdwQ0YsY0FBY1EsYUFBYTVMLEtBQUs7OztBNUJ5NENwQzs7OztBNkJsN0NDLENBQUEsWUFBVztFQUNWOzs7RUFFQTlGLFFBQ0dDLE9BQU8sT0FDUEMsT0FBT3lSOzs7Ozs7Ozs7O0VBVVYsU0FBU0EsaUJBQWlCVCxlQUFlQyxVQUFVaFIsUUFBUTs7O0lBRXpELFNBQVN5Uiw0QkFBNEJoTyxJQUFJK0wsV0FBVztNQUNsRCxPQUFPO1FBQ0wwQixTQUFTLFNBQUEsUUFBU25SLFFBQVE7VUFDeEIsSUFBSStILFFBQVEwSCxVQUFVdkgsSUFBSSxRQUFRUjs7VUFFbEMsSUFBSUssT0FBTztZQUNUL0gsT0FBTzJSLFFBQVEsbUJBQW1CLFlBQVk1Sjs7O1VBR2hELE9BQU8vSDs7UUFFVDJJLFVBQVUsU0FBQSxTQUFTQSxXQUFVOztVQUUzQixJQUFJWixRQUFRWSxVQUFTZ0osUUFBUTs7VUFFN0IsSUFBSTVKLE9BQU87WUFDVDBILFVBQVV2SCxJQUFJLFFBQVFQLFNBQVNJLE1BQU1vSSxNQUFNLEtBQUs7O1VBRWxELE9BQU94SDs7UUFFVDJJLGVBQWUsU0FBQSxjQUFTQyxXQUFXOzs7O1VBSWpDLElBQUlLLG1CQUFtQixDQUFDLHNCQUFzQixpQkFBaUIsZ0JBQWdCOztVQUUvRSxJQUFJQyxhQUFhOztVQUVqQi9SLFFBQVFnUyxRQUFRRixrQkFBa0IsVUFBU2xELE9BQU87WUFDaEQsSUFBSTZDLFVBQVV4TixRQUFRd04sVUFBVXhOLEtBQUs2RSxVQUFVOEYsT0FBTztjQUNwRG1ELGFBQWE7O2NBRWJwQyxVQUFVdkgsSUFBSSxRQUFRdkcsU0FBU00sS0FBSyxZQUFXO2dCQUM3QyxJQUFJVixTQUFTa08sVUFBVXZILElBQUk7Ozs7Z0JBSTNCLElBQUksQ0FBQzNHLE9BQU93USxHQUFHOVIsT0FBT2tDLGFBQWE7a0JBQ2pDWixPQUFPVyxHQUFHakMsT0FBT2tDOzs7a0JBR2pCc04sVUFBVXZILElBQUksWUFBWTdCOztrQkFFMUJrSyxNQUFNSTs7Ozs7OztVQU9kLElBQUlrQixZQUFZO1lBQ2ROLFVBQVV4TixPQUFPOzs7VUFHbkIsSUFBSWpFLFFBQVF1TCxXQUFXa0csVUFBVUksVUFBVTs7O1lBR3pDLElBQUk1SixRQUFRd0osVUFBVUksUUFBUTs7WUFFOUIsSUFBSTVKLE9BQU87Y0FDVDBILFVBQVV2SCxJQUFJLFFBQVFQLFNBQVNJLE1BQU1vSSxNQUFNLEtBQUs7Ozs7VUFJcEQsT0FBT3pNLEdBQUd5RSxPQUFPb0o7Ozs7OztJQU12Qk4sU0FBU3BLLFFBQVEsK0JBQStCNks7OztJQUdoRFYsY0FBY1EsYUFBYTVMLEtBQUs7OztBN0J1N0NwQzs7QThCbmhEQyxDQUFBLFlBQVk7RUFDWDs7O0VBRUE5RixRQUNHQyxPQUFPLE9BQ1BDLE9BQU9nUzs7RUFFVixTQUFTQSxzQkFBc0JoQixlQUFlQyxVQUFVOzs7Ozs7Ozs7O0lBU3RELFNBQVNnQixvQkFBb0J2TyxJQUFJK0wsV0FBVztNQUMxQyxPQUFPO1FBQ0w2QixlQUFlLFNBQUEsY0FBVUMsV0FBVztVQUNsQyxJQUFJbEksVUFBVW9HLFVBQVV2SCxJQUFJO1VBQzVCLElBQUl6RSxhQUFhZ00sVUFBVXZILElBQUk7O1VBRS9CLElBQUlxSixVQUFVdlIsT0FBTytELFFBQVEsQ0FBQ3dOLFVBQVV2UixPQUFPK0QsS0FBS21PLGdCQUFnQjtZQUNsRSxJQUFJWCxVQUFVeE4sUUFBUXdOLFVBQVV4TixLQUFLNkUsT0FBTzs7O2NBRzFDLElBQUkySSxVQUFVeE4sS0FBSzZFLE1BQU11RyxXQUFXLFdBQVc7Z0JBQzdDOUYsUUFBUXFILEtBQUtqTixXQUFXOEIsUUFBUTtxQkFDM0I7Z0JBQ0w4RCxRQUFRVCxNQUFNbkYsV0FBVzhCLFFBQVFnTSxVQUFVeE4sS0FBSzZFOzttQkFFN0M7Y0FDTFMsUUFBUThJLGdCQUFnQlosVUFBVXhOOzs7O1VBSXRDLE9BQU9MLEdBQUd5RSxPQUFPb0o7Ozs7OztJQU12Qk4sU0FBU3BLLFFBQVEsdUJBQXVCb0w7OztJQUd4Q2pCLGNBQWNRLGFBQWE1TCxLQUFLOzs7QTlCc2hEcEM7Ozs7QStCamtEQSxDQUFDLFlBQVk7O0VBRVg7OztFQUVBOUYsUUFDR0MsT0FBTyxPQUNQc0IsV0FBVyxrQkFBa0IrUTs7O0VBR2hDLFNBQVNBLGVBQWVDLFlBQVk5USxRQUFRK1EsV0FBVztJQUNyRCxJQUFJN1EsS0FBSzs7O0lBR1RBLEdBQUc4USxPQUFPQTtJQUNWOVEsR0FBRytRLDRCQUE0QkE7O0lBRS9CM1E7O0lBRUEsU0FBU0EsV0FBVztNQUNsQixJQUFJNFEsYUFBYTs7O01BR2pCaFIsR0FBR2lSLFlBQVksQ0FDYixFQUFFdlAsT0FBTyxpQkFBaUIySixPQUFPMkYsYUFBYSxhQUFhRSxNQUFNLGFBQWFDLFVBQVUsTUFDeEY7UUFDRXpQLE9BQU8sS0FBSzJKLE9BQU8yRixhQUFhLFlBQVlFLE1BQU0saUJBQWlCRSxVQUFVLENBQUM7UUFDOUVELFVBQVUsQ0FDUixFQUFFelAsT0FBTyxlQUFlMkosT0FBTzJGLGFBQWEsV0FBV0UsTUFBTTs7O01BSWpFO1FBQ0V4UCxPQUFPLEtBQUsySixPQUFPMkYsYUFBYSxTQUFTRSxNQUFNLHlCQUF5QkUsVUFBVSxDQUFDO1FBQ25GRCxVQUFVLENBQ1IsRUFBRXpQLE9BQU8sWUFBWTJKLE9BQU8yRixhQUFhLFFBQVFFLE1BQU0sWUFDdkQsRUFBRXhQLE9BQU8sWUFBWTJKLE9BQU8yRixhQUFhLFFBQVFFLE1BQU0sVUFDdkQsRUFBRXhQLE9BQU8sYUFBYTJKLE9BQU8yRixhQUFhLFNBQVNFLE1BQU0sYUFDekQsRUFBRXhQLE9BQU8scUJBQXFCMkosT0FBTzJGLGFBQWEsZ0JBQWdCRSxNQUFNOzs7Ozs7TUFROUVsUixHQUFHcVIsZUFBZTtRQUNoQkMsS0FBSztVQUNILGlCQUFpQixlQUFlQyxTQUFTO1VBQ3pDLG9CQUFvQixrQ0FBZ0NBLFNBQVMsaUJBQWUsT0FBS0EsU0FBUyxpQkFBZTs7UUFFM0dDLFNBQVM7VUFDUCxvQkFBb0JELFNBQVM7O1FBRS9CRSxXQUFXO1VBQ1RDLE9BQU87O1FBRVRDLFlBQVk7VUFDVixpQkFBaUIsZUFBZUosU0FBUzs7Ozs7SUFLL0MsU0FBU1QsT0FBTztNQUNkRixXQUFXLFFBQVFnQjs7Ozs7OztJQU9yQixTQUFTYiwwQkFBMEJjLFNBQVNDLElBQUlDLE1BQU07TUFDcEQsSUFBSTFULFFBQVE0TCxVQUFVOEgsS0FBS1osYUFBYVksS0FBS1osU0FBU2xOLFNBQVMsR0FBRztRQUNoRTROLFFBQVFmLEtBQUtnQjthQUNSO1FBQ0xoUyxPQUFPVyxHQUFHc1IsS0FBS3JRO1FBQ2ZrUCxXQUFXLFFBQVFoTTs7OztJQUl2QixTQUFTMk0sU0FBU1MsZUFBZTtNQUMvQixPQUFPbkIsVUFBVW9CLGNBQWNEOzs7O0EvQjZqRHJDOztBZ0Mvb0RBLENBQUMsWUFBVzs7RUFFVjs7O0VBRUEzVCxRQUNHQyxPQUFPLE9BQ1BzQixXQUFXLG1CQUFtQnNTOzs7O0VBSWpDLFNBQVNBLGdCQUFnQkMsY0FBY3hNLGNBQWN4QyxVQUFVeUU7RUFDN0QzRixJQUFJZ0ssUUFBUWpLLFlBQVl4RCxRQUFROztJQUVoQyxJQUFJd0IsS0FBSzs7SUFFVEEsR0FBR29TLGlCQUFpQjtJQUNwQnBTLEdBQUd3RCxVQUFVO01BQ1g2TyxNQUFNO01BQ05DLFVBQVU7TUFDVkMsZ0JBQWdCO01BQ2hCQyxVQUFVO01BQ1ZDLFFBQVE7TUFDUkMsY0FBYzs7O0lBR2hCMVMsR0FBRzJTLFlBQVlBO0lBQ2YzUyxHQUFHNFMsaUJBQWlCQTtJQUNwQjVTLEdBQUc2UyxjQUFjQTtJQUNqQjdTLEdBQUcrSCxZQUFZQTtJQUNmL0gsR0FBRzhTLE9BQU9BOztJQUVWMVM7O0lBRUEsU0FBU0EsV0FBVztNQUNsQkosR0FBRytIOzs7Ozs7Ozs7SUFTTCxTQUFTNEssVUFBVUksVUFBVTtNQUMzQixJQUFJN1EsV0FBV0QsR0FBR0U7O01BRWxCd0QsYUFBYTZFLE1BQU07UUFDakJ3SSxhQUFhRDtRQUNiRSxVQUFVaEgsT0FBT2lILElBQUlsVCxHQUFHbVQsS0FBS0MsT0FBT25ILE9BQU9vSCxTQUFTLE9BQU9DO1FBQzNEQyxPQUFPO1NBQ04vUyxLQUFLLFVBQVM4QixNQUFNOzs7UUFHckJBLE9BQU8ySixPQUFPYSxPQUFPeEssTUFBTSxVQUFTcUUsTUFBTTtVQUN4QyxPQUFPLENBQUNzRixPQUFPdUgsS0FBS3hULEdBQUdtVCxLQUFLQyxPQUFPLEVBQUU1TCxPQUFPYixLQUFLYTs7O1FBR25EdEYsU0FBU0osUUFBUVE7OztNQUduQixPQUFPSixTQUFTRzs7Ozs7O0lBTWxCLFNBQVN1USxpQkFBaUI7TUFDeEIsSUFBSXJVLFNBQVM7UUFDWG9HLFFBQVE7VUFDTjhPLFFBQVE7VUFDUkMsaUJBQWlCO1lBQ2ZDLGdCQUFnQjNULEdBQUc2Uzs7O1FBR3ZCalQsWUFBWTtRQUNab0YsY0FBYztRQUNkcEQsYUFBYXBELE9BQU84QyxhQUFhO1FBQ2pDMkQsYUFBYTs7O01BR2Y5QixTQUFTK0IsT0FBTzNHOzs7Ozs7SUFNbEIsU0FBU3NVLFlBQVlsTSxNQUFNO01BQ3pCLElBQUl5TSxRQUFRbkgsT0FBT3VILEtBQUt4VCxHQUFHbVQsS0FBS0MsT0FBTyxFQUFFNUwsT0FBT2IsS0FBS2E7O01BRXJELElBQUl4SCxHQUFHbVQsS0FBS0MsTUFBTW5QLFNBQVMsS0FBSzVGLFFBQVE0TCxVQUFVbUosUUFBUTtRQUN4RHhMLFFBQVFxSCxLQUFLak4sV0FBVzhCLFFBQVE7YUFDM0I7UUFDTDlELEdBQUdtVCxLQUFLQyxNQUFNalAsS0FBSyxFQUFFMEksTUFBTWxHLEtBQUtrRyxNQUFNckYsT0FBT2IsS0FBS2E7Ozs7Ozs7SUFPdEQsU0FBU3NMLE9BQU87O01BRWQ5UyxHQUFHbVQsS0FBS2xJLFFBQVF6SyxLQUFLLFVBQVMwRyxVQUFVO1FBQ3RDLElBQUlBLFNBQVNqRCxTQUFTLEdBQUc7VUFDdkIsSUFBSWtFLE1BQU1uRyxXQUFXOEIsUUFBUTs7VUFFN0IsS0FBSyxJQUFJc0UsSUFBRSxHQUFHQSxJQUFJbEIsU0FBU2pELFFBQVFtRSxLQUFLO1lBQ3RDRCxPQUFPakIsV0FBVzs7VUFFcEJVLFFBQVFULE1BQU1nQjtVQUNkbkksR0FBRytIO2VBQ0U7VUFDTEgsUUFBUUssUUFBUWpHLFdBQVc4QixRQUFRO1VBQ25DOUQsR0FBRytIOzs7Ozs7OztJQVFULFNBQVNBLFlBQVk7TUFDbkIvSCxHQUFHbVQsT0FBTyxJQUFJaEI7TUFDZG5TLEdBQUdtVCxLQUFLQyxRQUFROzs7O0FoQ21wRHRCOztBaUM3d0RDLENBQUEsWUFBVztFQUNWOzs7RUFFQS9VLFFBQ0dDLE9BQU8sT0FDUEMsT0FBT2dEOzs7Ozs7Ozs7RUFTVixTQUFTQSxPQUFPQyxnQkFBZ0JoRCxRQUFRO0lBQ3RDZ0QsZUFDR0UsTUFBTSxZQUFZO01BQ2pCQyxLQUFLO01BQ0xDLGFBQWFwRCxPQUFPOEMsYUFBYTtNQUNqQzFCLFlBQVk7TUFDWjBDLE1BQU0sRUFBRUMsb0JBQW9CLE1BQU00QyxhQUFhLENBQUM7Ozs7QWpDZ3hEeEQ7O0FrQ3B5REMsQ0FBQSxZQUFXO0VBQ1Y7OztFQUVBOUcsUUFDR0MsT0FBTyxPQUNQOEcsUUFBUSxnQkFBZ0IrTTs7OztFQUkzQixTQUFTQSxhQUFhOU0sZ0JBQWdCO0lBQ3BDLE9BQU9BLGVBQWUsU0FBUzs7O0FsQ3V5RG5DOztBbUNqekRBLENBQUMsWUFBVzs7RUFFVjs7O0VBRUFoSCxRQUNHQyxPQUFPLE9BQ1B3TyxPQUFPLFlBQVk4Rzs7O0VBR3RCLFNBQVNBLFNBQVMzSCxRQUFROzs7OztJQUt4QixPQUFPLFVBQVM0SCxPQUFPO01BQ3JCLE9BQU81SCxPQUFPaUgsSUFBSVcsT0FBTyxRQUFRQyxLQUFLOzs7O0FuQ3F6RDVDOztBb0NwMERDLENBQUEsWUFBVztFQUNWOzs7RUFFQXpWLFFBQ0dDLE9BQU8sT0FDUDhHLFFBQVEsZ0JBQWdCMk87OztFQUczQixTQUFTQSxhQUFhMU8sZ0JBQWdCO0lBQ3BDLE9BQU9BLGVBQWU7OztBcEN1MEQxQjs7QXFDaDFEQyxDQUFBLFlBQVc7RUFDVjs7O0VBRUFoSCxRQUNHQyxPQUFPLE9BQ1A4RyxRQUFRLGtCQUFrQjBJOzs7RUFHN0IsU0FBU0EsZUFBZXpJLGdCQUFnQjtJQUN0QyxPQUFPQSxlQUFlLFdBQVc7TUFDL0JDLFNBQVM7Ozs7OztRQU1QZ0osT0FBTztVQUNML0ksUUFBUTtVQUNSNUQsS0FBSztVQUNMK0csTUFBTTtVQUNOc0wsT0FBTzs7Ozs7O0FyQ3MxRGpCOztBc0MxMkRDLENBQUEsWUFBVztFQUNWOzs7O0VBR0EzVixRQUNHQyxPQUFPLE9BQ1AyVixVQUFVLE9BQU87SUFDaEJDLFNBQVM7SUFDVHRTLGFBQWEsQ0FBQyxVQUFVLFVBQVNwRCxRQUFRO01BQ3ZDLE9BQU9BLE9BQU84QyxhQUFhOztJQUU3QjZTLFlBQVk7TUFDVkMsZ0JBQWdCO01BQ2hCQyxlQUFlOztJQUVqQkMsVUFBVTtNQUNSQyxVQUFVO01BQ1ZDLGNBQWM7TUFDZEMsZ0JBQWdCOztJQUVsQjdVLFlBQVksQ0FBQyxlQUFlLFVBQVM4VSxhQUFhO01BQ2hELElBQUlDLE9BQU87O01BRVhBLEtBQUtSLGFBQWFPOztNQUVsQkMsS0FBS0MsVUFBVSxZQUFXO1FBQ3hCLElBQUl2VyxRQUFRaVAsWUFBWXFILEtBQUtGLGlCQUFpQkUsS0FBS0YsaUJBQWlCOzs7OztBdENnM0Q5RTs7QXVDMTREQyxDQUFBLFlBQVc7RUFDVjs7OztFQUdBcFcsUUFDR0MsT0FBTyxPQUNQMlYsVUFBVSxlQUFlO0lBQ3hCQyxTQUFTO0lBQ1RDLFlBQVk7SUFDWnZTLGFBQWEsQ0FBQyxVQUFVLFVBQVNwRCxRQUFRO01BQ3ZDLE9BQU9BLE9BQU84QyxhQUFhOztJQUU3QmdULFVBQVU7TUFDUk8sYUFBYTs7SUFFZmpWLFlBQVksQ0FBQyxZQUFXO01BQ3RCLElBQUkrVSxPQUFPOztNQUVYQSxLQUFLQyxVQUFVLFlBQVc7O1FBRXhCRCxLQUFLRSxjQUFjeFcsUUFBUTRMLFVBQVUwSyxLQUFLRSxlQUFlRixLQUFLRSxjQUFjOzs7OztBdkNnNUR0Rjs7QXdDcDZEQyxDQUFBLFlBQVc7RUFDVjs7OztFQUdBeFcsUUFDR0MsT0FBTyxPQUNQMlYsVUFBVSxpQkFBaUI7SUFDMUJyUyxhQUFhLENBQUMsVUFBVSxVQUFTcEQsUUFBUTtNQUN2QyxPQUFPQSxPQUFPOEMsYUFBYTs7SUFFN0I0UyxTQUFTO0lBQ1RJLFVBQVU7TUFDUmpKLE9BQU87TUFDUEMsYUFBYTs7OztBeEN5NkRyQjs7QXlDdDdEQSxDQUFDLFlBQVc7O0VBRVY7OztFQUVBak4sUUFDR0MsT0FBTyxPQUNQc0IsV0FBVyxxQkFBcUJrVjs7OztFQUluQyxTQUFTQSxrQkFBa0JuUCxjQUFjNUYsTUFBTTZILFNBQVM1RixZQUFZO0lBQ2xFLElBQUloQyxLQUFLOztJQUVUQSxHQUFHK1UsU0FBU0E7O0lBRVozVTs7SUFFQSxTQUFTQSxXQUFXO01BQ2xCSixHQUFHMkcsT0FBT3RJLFFBQVF5TSxLQUFLL0ssS0FBS1k7OztJQUc5QixTQUFTb1UsU0FBUztNQUNoQnBQLGFBQWFxUCxjQUFjaFYsR0FBRzJHLE1BQU1uRyxLQUFLLFVBQVUwRyxVQUFVOztRQUUzRG5ILEtBQUs4RixrQkFBa0JxQjtRQUN2QlUsUUFBUUssUUFBUWpHLFdBQVc4QixRQUFROzs7OztBekMyN0QzQzs7QTBDcDlEQSxDQUFDLFlBQVc7O0VBRVY7OztFQUVBekYsUUFDR0MsT0FBTyxPQUNQc0IsV0FBVyxtQkFBbUJxVjs7OztFQUlqQyxTQUFTQSxnQkFBZ0JoUyxhQUFhMEMsY0FBYzs7SUFFbEQsSUFBSTNGLEtBQUs7O0lBRVRBLEdBQUdvRCxhQUFhQTs7SUFFaEJILFlBQVksa0JBQWtCLEVBQUVqRCxJQUFJQSxJQUFJdUQsY0FBY29DLGNBQWNuQyxTQUFTOztJQUU3RSxTQUFTSixhQUFhO01BQ3BCcEQsR0FBRzBELGVBQWU7Ozs7QTFDdzlEeEI7O0EyQzMrREMsQ0FBQSxZQUFXO0VBQ1Y7OztFQUVBckYsUUFDR0MsT0FBTyxPQUNQQyxPQUFPZ0Q7Ozs7Ozs7OztFQVNWLFNBQVNBLE9BQU9DLGdCQUFnQmhELFFBQVE7SUFDdENnRCxlQUNHRSxNQUFNLFlBQVk7TUFDakJDLEtBQUs7TUFDTEMsYUFBYXBELE9BQU84QyxhQUFhO01BQ2pDMUIsWUFBWTtNQUNaMEMsTUFBTSxFQUFFQyxvQkFBb0IsTUFBTTRDLGFBQWEsQ0FBQztPQUVqRHpELE1BQU0sb0JBQW9CO01BQ3pCQyxLQUFLO01BQ0xDLGFBQWFwRCxPQUFPOEMsYUFBYTtNQUNqQzFCLFlBQVk7TUFDWjBDLE1BQU0sRUFBRUMsb0JBQW9COzs7O0EzQzYrRHBDOztBNEN2Z0VDLENBQUEsWUFBVztFQUNWOzs7RUFFQWxFLFFBQ0dDLE9BQU8sT0FDUDhHLFFBQVEsZ0JBQWdCTzs7OztFQUkzQixTQUFTQSxhQUFhc0csUUFBUXpOLFFBQVE2RyxnQkFBZ0I7SUFDcEQsT0FBT0EsZUFBZSxTQUFTOzs7TUFHN0I2UCxVQUFVO1FBQ1JyQixPQUFPOzs7TUFHVHZPLFNBQVM7Ozs7Ozs7UUFPUDBQLGVBQWU7VUFDYnpQLFFBQVE7VUFDUjVELEtBQUtuRCxPQUFPWSxVQUFVO1VBQ3RCK1YsVUFBVTtVQUNWek0sTUFBTTs7OztNQUlWbEQsVUFBVTs7Ozs7Ozs7UUFRUjRKLFlBQVksU0FBQSxXQUFTeUUsT0FBT3VCLEtBQUs7VUFDL0J2QixRQUFReFYsUUFBUXdHLFFBQVFnUCxTQUFTQSxRQUFRLENBQUNBOztVQUUxQyxJQUFJd0IsWUFBWXBKLE9BQU9pSCxJQUFJLEtBQUtXLE9BQU87O1VBRXZDLElBQUl1QixLQUFLO1lBQ1AsT0FBT25KLE9BQU9xSixhQUFhRCxXQUFXeEIsT0FBTzVQLFdBQVc0UCxNQUFNNVA7aUJBQ3pEOztZQUNMLE9BQU9nSSxPQUFPcUosYUFBYUQsV0FBV3hCLE9BQU81UDs7Ozs7Ozs7O1FBU2pEc1IsU0FBUyxTQUFBLFVBQVc7VUFDbEIsT0FBTyxLQUFLbkcsV0FBVzs7Ozs7O0E1QzhnRWpDOztBNkN4a0VBLENBQUMsWUFBVzs7RUFFVjs7O0VBRUEvUSxRQUNHQyxPQUFPLE9BQ1B3TyxPQUFPLG9CQUFvQjBJOzs7O0VBSTlCLFNBQVNBLGlCQUFpQnhULFlBQVk7SUFDcEMsT0FBTyxVQUFTMEMsYUFBYXdELFFBQVE7TUFDbkMsSUFBSXhELFlBQVlILFNBQVMsV0FBVztRQUNsQyxJQUFJMkQsV0FBVyxVQUFVO1VBQ3ZCLE9BQU9sRyxXQUFXOEIsUUFBUTtlQUNyQjtVQUNMLE9BQU85QixXQUFXOEIsUUFBUTs7YUFFdkI7UUFDTCxPQUFPOUIsV0FBVzhCLFFBQVEsa0JBQWtCWSxZQUFZSDs7Ozs7QTdDNmtFaEU7O0E4Q2htRUEsQ0FBQyxZQUFXOztFQUVWOzs7RUFFQWxHLFFBQ0dDLE9BQU8sT0FDUHdPLE9BQU8sY0FBYzJJOzs7O0VBSXhCLFNBQVNBLFdBQVd6VCxZQUFZO0lBQzlCLE9BQU8sVUFBUzBULFNBQVM7TUFDdkJBLFVBQVVBLFFBQVF4QixRQUFRLFNBQVM7TUFDbkMsSUFBSWhRLFFBQVFsQyxXQUFXOEIsUUFBUSxZQUFZNFIsUUFBUXRSOztNQUVuRCxPQUFRRixRQUFTQSxRQUFRd1I7Ozs7QTlDb21FL0I7O0ErQ25uRUEsQ0FBQyxZQUFXOztFQUVWOzs7RUFFQXJYLFFBQ0dDLE9BQU8sT0FDUHdPLE9BQU8sYUFBYTZJOzs7O0VBSXZCLFNBQVNBLFVBQVUxSixRQUFRL0ksY0FBYztJQUN2QyxPQUFPLFVBQVMwUyxRQUFRO01BQ3RCLElBQUlyUixPQUFPMEgsT0FBT3VILEtBQUt0USxhQUFhb0IsYUFBYSxFQUFFVixJQUFJZ1M7O01BRXZELE9BQVFyUixPQUFRQSxLQUFLVixRQUFRVTs7OztBL0N1bkVuQzs7QWdEcm9FQSxDQUFDLFlBQVc7O0VBRVY7OztFQUVBbEcsUUFDR0MsT0FBTyxPQUNQd08sT0FBTyxjQUFjK0k7Ozs7RUFJeEIsU0FBU0EsV0FBV3JILFNBQVN2QyxRQUFRO0lBQ25DLE9BQU8sVUFBU2dCLE9BQU9RLEtBQUs7TUFDMUIsSUFBSXBQLFFBQVF5WCxPQUFPN0ksVUFBVWhCLE9BQU84SixTQUFTdEksS0FBSyxVQUFXeEIsT0FBTzhKLFNBQVN0SSxLQUFLLFFBQVE7UUFDeEYsT0FBT2UsUUFBUSxjQUFjdkI7OztNQUcvQixJQUFJLE9BQU9BLFVBQVUsV0FBVztRQUM5QixPQUFPdUIsUUFBUSxhQUFjdkIsUUFBUyxlQUFlOzs7O01BSXZELElBQUkrSSxPQUFPL0ksV0FBV0EsU0FBU0EsUUFBUSxNQUFNLEdBQUc7UUFDOUMsT0FBT3VCLFFBQVEsUUFBUXZCOzs7TUFHekIsT0FBT0E7Ozs7QWhEeW9FYjs7O0FpRGpxRUMsQ0FBQSxZQUFXO0VBQ1Y7O0VBRUE1TyxRQUNHQyxPQUFPLE9BQ1B3QyxTQUFTLHlCQUF5QjtJQUNqQzBHLE9BQU87SUFDUEMsVUFBVTtJQUNWb0YsTUFBTTtJQUNOak0sT0FBTztJQUNQaVQsT0FBTztJQUNQeFQsTUFBTTtJQUNONFYsYUFBYTtJQUNiQyxXQUFXO0lBQ1hDLE1BQU07TUFDSjdLLGFBQWE7TUFDYjhLLE1BQU07TUFDTkMsVUFBVTtNQUNWQyxjQUFjO01BQ2RDLFNBQVM7O0lBRVhBLFNBQVM7TUFDUEMsTUFBTTs7O0lBR1JmLFlBQVk7OztBakRxcUVsQjs7O0FrRDlyRUMsQ0FBQSxZQUFXO0VBQ1Y7O0VBRUFwWCxRQUNHQyxPQUFPLE9BQ1B3QyxTQUFTLHFCQUFxQjtJQUM3QjJWLGNBQWM7SUFDZEMsb0JBQW9CO0lBQ3BCQyxtQkFBbUI7SUFDbkJDLE9BQU87TUFDTEMsU0FBUztNQUNUQyxlQUFlO01BQ2ZDLGNBQWM7TUFDZEMsU0FBUzs7SUFFWHBSLE9BQU87TUFDTHFSLGVBQWU7UUFDYjNMLGFBQWE7Ozs7O0FsRG9zRXZCOzs7QW1EcnRFQyxDQUFBLFlBQVc7RUFDVjs7RUFFQWpOLFFBQ0dDLE9BQU8sT0FDUHdDLFNBQVMscUJBQXFCO0lBQzdCb1csU0FBUztJQUNUQyxZQUFZO0lBQ1pDLEtBQUs7SUFDTEMsSUFBSTtJQUNKakMsS0FBSzs7O0FuRHl0RVg7OztBb0RudUVDLENBQUEsWUFBVztFQUNWOztFQUVBL1csUUFDR0MsT0FBTyxPQUNQd0MsU0FBUyx1QkFBdUI7SUFDL0J3VyxlQUFlO0lBQ2ZDLFVBQVU7SUFDVkMsZUFBZTtJQUNmQyxhQUFhO0lBQ2JDLGFBQWE7SUFDYkMsa0JBQWtCO0lBQ2xCQyxnQkFBZ0I7SUFDaEJDLFdBQVc7SUFDWEMsZUFBZTtJQUNmQyxhQUFhO0lBQ2JDLHVCQUF1QjtJQUN2QkMsY0FBYztJQUNkQyx5QkFBeUI7SUFDekJDLFVBQVU7TUFDUkMsZUFBZTs7SUFFakJDLFFBQVE7TUFDTkMsVUFBVTs7SUFFWjFTLE9BQU87TUFDTDJTLGdCQUFnQjtNQUNoQkMsb0JBQW9CO01BQ3BCQyxjQUFjLHlEQUNaO01BQ0ZDLGNBQWM7O0lBRWhCQyxXQUFXO01BQ1RDLFNBQVM7TUFDVHROLGFBQWE7O0lBRWY2SCxNQUFNO01BQ0owRixZQUFZO01BQ1pDLGlCQUFpQjtNQUNqQkMsZUFBZTtNQUNmQyx3QkFBd0I7O0lBRTFCclMsTUFBTTtNQUNKc1MscUJBQXFCO01BQ3JCQyxZQUFZO01BQ1pDLFNBQVM7UUFDUEMsYUFBYTs7O0lBR2pCQyxjQUFjO01BQ1pDLFVBQVU7Ozs7QXBEdXVFbEI7OztBcUR6eEVDLENBQUEsWUFBVztFQUNWOztFQUVBamIsUUFDR0MsT0FBTyxPQUNQd0MsU0FBUyxxQkFBcUI7SUFDN0I2RixNQUFNO0lBQ053UCxNQUFNO0lBQ05JLFNBQVM7OztBckQ2eEVmOzs7QXNEcnlFQyxDQUFBLFlBQVc7RUFDVjs7RUFFQWxZLFFBQ0dDLE9BQU8sT0FDUHdDLFNBQVMsb0JBQW9CO0lBQzVCeVksYUFBYTtNQUNYNVMsTUFBTTtNQUNOLGdCQUFnQjtNQUNoQmdTLFdBQVc7TUFDWC9CLE9BQU87TUFDUHpELE1BQU07TUFDTm9ELFNBQVM7TUFDVCxpQkFBaUI7TUFDakIsa0JBQWtCOztJQUVwQmlELFFBQVE7TUFDTmIsV0FBVztNQUNYYyxVQUFVO01BQ1ZDLFVBQVU7TUFDVkMsVUFBVTtNQUNWQyxXQUFXO01BQ1hDLFVBQVU7TUFDVjVDLGVBQWU7TUFDZmxDLFFBQVE7O0lBRVZ6UCxTQUFTO01BQ1B3TixNQUFNO01BQ04zSixNQUFNO01BQ05zRCxPQUFPO01BQ1BxTixVQUFVO01BQ1ZwTixTQUFTO01BQ1RJLFFBQVE7TUFDUi9ELFFBQVE7TUFDUmdSLE1BQU07TUFDTjdRLE1BQU07TUFDTjhRLFFBQVE7TUFDUmpGLFFBQVE7TUFDUjNMLFFBQVE7TUFDUjZRLFFBQVE7TUFDUkMsS0FBSztNQUNMQyxJQUFJO01BQ0pDLFdBQVc7TUFDWEMsUUFBUTs7SUFFVkMsUUFBUTtNQUNOamEsTUFBTTtNQUNOa2EsUUFBUTtNQUNSalYsU0FBUztNQUNUc1IsT0FBTztRQUNMNEQsV0FBVztRQUNYQyxTQUFTO1FBQ1Q5USxVQUFVO1FBQ1YrUSxjQUFjO1FBQ2RuVyxNQUFNO1VBQ0pzUyxTQUFTO1VBQ1Q4RCxTQUFTO1VBQ1QzRCxTQUFTOzs7TUFHYnBSLE9BQU87UUFDTHFSLGVBQWU7UUFDZjJELGlCQUFpQjs7TUFFbkJ6SCxNQUFNO1FBQ0owSCxJQUFJO1FBQ0pDLFNBQVM7UUFDVHZTLFNBQVM7O01BRVg4USxjQUFjO1FBQ1puTSxTQUFTO1FBQ1Q2TixTQUFTO1FBQ1Q3VyxPQUFPO1FBQ1A2SSxXQUFXO1FBQ1hDLFVBQVU7UUFDVnJELFVBQVU7UUFDVnNELE9BQU87UUFDUEcsV0FBVztVQUNUNE4sUUFBUTtVQUNSQyxVQUFVO1VBQ1ZDLFVBQVU7VUFDVkMsV0FBVztVQUNYQyxZQUFZO1VBQ1pDLFlBQVk7VUFDWkMsb0JBQW9CO1VBQ3BCQyxVQUFVO1VBQ1ZDLGtCQUFrQjs7O01BR3RCakYsU0FBUztRQUNQMUosTUFBTTtRQUNONE8sV0FBVzs7TUFFYnRGLE1BQU07UUFDSkMsTUFBTTs7TUFFUnpQLE1BQU07UUFDSitVLFNBQVM7UUFDVDFJLGFBQWE7OztJQUdqQnFGLFFBQVE7TUFDTnNELE1BQU07UUFDSmhELFdBQVc7UUFDWHBDLFNBQVM7UUFDVHFGLE9BQU87UUFDUEMsVUFBVTtRQUNWbFYsTUFBTTtRQUNOd00sTUFBTTtRQUNOeUQsT0FBTztRQUNQa0YsY0FBYzs7O0lBR2xCQyxVQUFVO01BQ1JuRixPQUFPO1FBQ0x0VCxZQUFZOztNQUVkcUQsTUFBTTtRQUNKcVYsUUFBUTtRQUNSQyxVQUFVOztNQUVaOUYsTUFBTTtRQUNKK0YsVUFBVTs7Ozs7QXREMnlFcEI7O0F1RHQ2RUEsQ0FBQyxZQUFXOztFQUVWOzs7RUFFQTdkLFFBQ0dDLE9BQU8sT0FDUHNCLFdBQVcsc0JBQXNCdWM7Ozs7RUFJcEMsU0FBU0EsbUJBQW1CM2QsUUFBUXlFLGFBQWFtWixpQkFBaUJqWixVQUFVO0lBQzFFLElBQUluRCxLQUFLOzs7OztJQUtUQSxHQUFHb0QsYUFBYUE7SUFDaEJwRCxHQUFHcUQsZUFBZUE7SUFDbEJyRCxHQUFHcWMsWUFBWUE7OztJQUdmcFosWUFBWSxrQkFBa0IsRUFBRWpELElBQUlBLElBQUl1RCxjQUFjNlksaUJBQWlCNVksU0FBUzs7SUFFaEYsU0FBU0osYUFBYTtNQUNwQnBELEdBQUcwRCxlQUFlOzs7SUFHcEIsU0FBU0wsYUFBYW1CLHFCQUFxQjtNQUN6QyxPQUFPbkcsUUFBUW9HLE9BQU9ELHFCQUFxQnhFLEdBQUcwRDs7O0lBR2hELFNBQVMyWSxVQUFVQyxXQUFXO01BQzVCLElBQUkvZCxTQUFTO1FBQ1hvRyxRQUFRO1VBQ04yWCxXQUFXQTs7UUFFYjFjLFlBQVk7UUFDWm9GLGNBQWM7UUFDZHBELGFBQWFwRCxPQUFPOEMsYUFBYTtRQUNqQzJELGFBQWE7OztNQUdmOUIsU0FBUytCLE9BQU8zRyxRQUFRZ2UsUUFBUSxZQUFXO1FBQ3pDdmMsR0FBRytJLE9BQU8vSSxHQUFHNkosVUFBVUc7Ozs7O0F2RDI2RS9COztBd0R0OUVDLENBQUEsWUFBVztFQUNWOzs7RUFFQTNMLFFBQ0dDLE9BQU8sT0FDUEMsT0FBT2dEOzs7Ozs7Ozs7RUFTVixTQUFTQSxPQUFPQyxnQkFBZ0JoRCxRQUFRO0lBQ3RDZ0QsZUFDR0UsTUFBTSxlQUFlO01BQ3BCQyxLQUFLO01BQ0xDLGFBQWFwRCxPQUFPOEMsYUFBYTtNQUNqQzFCLFlBQVk7TUFDWjBDLE1BQU0sRUFBRUMsb0JBQW9CLE1BQU00QyxhQUFhLENBQUM7Ozs7QXhEeTlFeEQ7O0F5RDcrRUMsQ0FBQSxZQUFXO0VBQ1Y7OztFQUVBOUcsUUFDR0MsT0FBTyxPQUNQOEcsUUFBUSxtQkFBbUJnWDs7O0VBRzlCLFNBQVNBLGdCQUFnQi9XLGdCQUFnQjtJQUN2QyxPQUFPQSxlQUFlLFlBQVk7TUFDaENDLFNBQVM7TUFDVEUsVUFBVTs7OztBekRpL0VoQjs7QTBENS9FQSxDQUFDLFlBQVc7O0VBRVY7OztFQUVBbkgsUUFDR0MsT0FBTyxPQUNQc0IsV0FBVyx5QkFBeUI0Yzs7OztFQUl2QyxTQUFTQSxzQkFBc0J2WixhQUFhd1osY0FBY0gsV0FBVzFVO0VBQ25FekUsVUFBVW5CLFlBQVl4RCxRQUFRSSxRQUFROztJQUV0QyxJQUFJb0IsS0FBSzs7O0lBR1RBLEdBQUdvRCxhQUFlQTtJQUNsQnBELEdBQUc0RSxRQUFlQTtJQUNsQjVFLEdBQUdxRCxlQUFlQTtJQUNsQnJELEdBQUdnTCxhQUFlQTtJQUNsQmhMLEdBQUdrTCxZQUFlQTtJQUNsQmxMLEdBQUcwYyxhQUFlQTs7O0lBR2xCelosWUFBWSxrQkFBa0IsRUFBRWpELElBQUlBLElBQUl1RCxjQUFja1osY0FBY2paLFNBQVM7UUFDM0VnRyxTQUFTOzs7SUFHWCxTQUFTcEcsYUFBYTtNQUNwQnBELEdBQUc4QyxTQUFTdEU7TUFDWndCLEdBQUcySixTQUFTMk0sZUFBZTFYLFNBQVNzYixJQUFJLElBQUk7TUFDNUNsYSxHQUFHMEQsZUFBZSxFQUFFNFksV0FBV0E7OztJQUdqQyxTQUFTalosYUFBYW1CLHFCQUFxQjtNQUN6QyxPQUFPbkcsUUFBUW9HLE9BQU9ELHFCQUFxQnhFLEdBQUcwRDs7O0lBR2hELFNBQVNzSCxhQUFhO01BQ3BCaEwsR0FBRzJKLFNBQVNnVCxhQUFhM2MsR0FBRzBELGFBQWE0WTtNQUN6Q3RjLEdBQUcySixTQUFTNE0sVUFBVTs7O0lBR3hCLFNBQVNyTCxZQUFZO01BQ25CbEwsR0FBRytIO01BQ0gvSCxHQUFHK0ksT0FBTy9JLEdBQUc2SixVQUFVRzs7O0lBR3pCLFNBQVNwRixRQUFRO01BQ2Y1RSxHQUFHK0g7TUFDSDVFLFNBQVN5Qjs7O0lBR1gsU0FBUzhYLFdBQVcvUyxVQUFVO01BQzVCOFMsYUFBYUMsV0FBVyxFQUFFOVksSUFBSStGLFNBQVMvRixJQUFJd1MsTUFBTXpNLFNBQVN5TSxRQUFRNVYsS0FBSyxZQUFXO1FBQ2hGb0gsUUFBUUssUUFBUWpHLFdBQVc4QixRQUFRO1FBQ25DOUQsR0FBRytJLE9BQU8vSSxHQUFHNkosVUFBVUc7U0FDdEIsVUFBUzdDLE9BQU87UUFDakJTLFFBQVE4SSxnQkFBZ0J2SixNQUFNN0UsTUFBTU4sV0FBVzhCLFFBQVE7Ozs7O0ExRGlnRi9EOztBMkQzakZDLENBQUEsWUFBVztFQUNWOzs7RUFFQXpGLFFBQ0dDLE9BQU8sT0FDUDhHLFFBQVEsZ0JBQWdCcVg7OztFQUczQixTQUFTQSxhQUFhcFgsZ0JBQWdCekcsUUFBUTtJQUM1QyxPQUFPeUcsZUFBZSxTQUFTOzs7TUFHN0I2UCxVQUFVO1FBQ1JvQixjQUFjLElBQUloVzs7O01BR3BCNFMsS0FBSzs7UUFFSG9ELGNBQWMsU0FBQSxhQUFTckosT0FBTztVQUM1QixPQUFPck8sT0FBT3FPLE9BQU8yUDs7OztNQUl6QnRYLFNBQVM7Ozs7OztRQU1Qb1gsWUFBWTtVQUNWblgsUUFBUTtVQUNSNUQsS0FBSzs7O01BR1Q2RCxVQUFVOzs7O0EzRCtqRmhCOztBNERqbUZBLENBQUMsWUFBVzs7RUFFVjs7O0VBRUFuSCxRQUNHQyxPQUFPLE9BQ1BzQixXQUFXLHlCQUF5QmlkOzs7O0VBSXZDLFNBQVNBLHNCQUFzQjVaLGFBQWEwQyxjQUFjeEM7RUFDeER1USxpQkFBaUJELFFBQVE7O0lBRXpCLElBQUl6VCxLQUFLOztJQUVUQSxHQUFHb0QsYUFBYUE7SUFDaEJwRCxHQUFHcUQsZUFBZUE7SUFDbEJyRCxHQUFHNEUsUUFBUUE7O0lBRVgsSUFBSXZHLFFBQVE0TCxVQUFVeUosa0JBQWtCO01BQ3RDMVQsR0FBRzhjLGVBQWVwSixnQkFBZ0JDOzs7O0lBSXBDMVEsWUFBWSxrQkFBa0I7TUFDNUJqRCxJQUFJQTtNQUNKdUQsY0FBY29DO01BQ2Q0RCxjQUFja0s7TUFDZGpRLFNBQVM7UUFDUGdHLFNBQVM7Ozs7SUFJYixTQUFTcEcsYUFBYTtNQUNwQnBELEdBQUcwRCxlQUFlOzs7SUFHcEIsU0FBU0wsZUFBZTtNQUN0QixPQUFPaEYsUUFBUW9HLE9BQU96RSxHQUFHd0UscUJBQXFCeEUsR0FBRzBEOzs7SUFHbkQsU0FBU2tCLFFBQVE7TUFDZnpCLFNBQVN5Qjs7O0tBMUNmIiwiZmlsZSI6ImFwcGxpY2F0aW9uLmpzIiwic291cmNlc0NvbnRlbnQiOlsiJ3VzZSBzdHJpY3QnO1xuXG4vKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCovXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcsIFsnbmdBbmltYXRlJywgJ25nQXJpYScsICd1aS5yb3V0ZXInLCAnbmdQcm9kZWInLCAndWkudXRpbHMubWFza3MnLCAndGV4dC1tYXNrJywgJ25nTWF0ZXJpYWwnLCAnbW9kZWxGYWN0b3J5JywgJ21kLmRhdGEudGFibGUnLCAnbmdNYXRlcmlhbERhdGVQaWNrZXInLCAncGFzY2FscHJlY2h0LnRyYW5zbGF0ZScsICdhbmd1bGFyRmlsZVVwbG9hZCddKTtcbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29uZmlnKGNvbmZpZyk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBjb25maWcoR2xvYmFsLCAkbWRUaGVtaW5nUHJvdmlkZXIsICRtb2RlbEZhY3RvcnlQcm92aWRlciwgLy8gTk9TT05BUlxuICAkdHJhbnNsYXRlUHJvdmlkZXIsIG1vbWVudCwgJG1kQXJpYVByb3ZpZGVyKSB7XG5cbiAgICAkdHJhbnNsYXRlUHJvdmlkZXIudXNlTG9hZGVyKCdsYW5ndWFnZUxvYWRlcicpLnVzZVNhbml0aXplVmFsdWVTdHJhdGVneSgnZXNjYXBlJyk7XG5cbiAgICAkdHJhbnNsYXRlUHJvdmlkZXIudXNlUG9zdENvbXBpbGluZyh0cnVlKTtcblxuICAgIG1vbWVudC5sb2NhbGUoJ3B0LUJSJyk7XG5cbiAgICAvL29zIHNlcnZpw6dvcyByZWZlcmVudGUgYW9zIG1vZGVscyB2YWkgdXRpbGl6YXIgY29tbyBiYXNlIG5hcyB1cmxzXG4gICAgJG1vZGVsRmFjdG9yeVByb3ZpZGVyLmRlZmF1bHRPcHRpb25zLnByZWZpeCA9IEdsb2JhbC5hcGlQYXRoO1xuXG4gICAgLy8gQ29uZmlndXJhdGlvbiB0aGVtZVxuICAgICRtZFRoZW1pbmdQcm92aWRlci50aGVtZSgnZGVmYXVsdCcpLnByaW1hcnlQYWxldHRlKCdicm93bicsIHtcbiAgICAgIGRlZmF1bHQ6ICc3MDAnXG4gICAgfSkuYWNjZW50UGFsZXR0ZSgnYW1iZXInKS53YXJuUGFsZXR0ZSgnZGVlcC1vcmFuZ2UnKTtcblxuICAgIC8vIEVuYWJsZSBicm93c2VyIGNvbG9yXG4gICAgJG1kVGhlbWluZ1Byb3ZpZGVyLmVuYWJsZUJyb3dzZXJDb2xvcigpO1xuXG4gICAgJG1kQXJpYVByb3ZpZGVyLmRpc2FibGVXYXJuaW5ncygpO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29udHJvbGxlcignQXBwQ29udHJvbGxlcicsIEFwcENvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLyoqXG4gICAqIENvbnRyb2xhZG9yIHJlc3BvbnPDoXZlbCBwb3IgZnVuY2lvbmFsaWRhZGVzIHF1ZSBzw6NvIGFjaW9uYWRhcyBlbSBxdWFscXVlciB0ZWxhIGRvIHNpc3RlbWFcbiAgICpcbiAgICovXG4gIGZ1bmN0aW9uIEFwcENvbnRyb2xsZXIoJHN0YXRlLCBBdXRoLCBHbG9iYWwpIHtcbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgLy9hbm8gYXR1YWwgcGFyYSBzZXIgZXhpYmlkbyBubyByb2RhcMOpIGRvIHNpc3RlbWFcbiAgICB2bS5hbm9BdHVhbCA9IG51bGw7XG5cbiAgICB2bS5sb2dvdXQgPSBsb2dvdXQ7XG4gICAgdm0uZ2V0SW1hZ2VQZXJmaWwgPSBnZXRJbWFnZVBlcmZpbDtcblxuICAgIGFjdGl2YXRlKCk7XG5cbiAgICBmdW5jdGlvbiBhY3RpdmF0ZSgpIHtcbiAgICAgIHZhciBkYXRlID0gbmV3IERhdGUoKTtcblxuICAgICAgdm0uYW5vQXR1YWwgPSBkYXRlLmdldEZ1bGxZZWFyKCk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gbG9nb3V0KCkge1xuICAgICAgQXV0aC5sb2dvdXQoKS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgJHN0YXRlLmdvKEdsb2JhbC5sb2dpblN0YXRlKTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGdldEltYWdlUGVyZmlsKCkge1xuICAgICAgcmV0dXJuIEF1dGguY3VycmVudFVzZXIgJiYgQXV0aC5jdXJyZW50VXNlci5pbWFnZSA/IEF1dGguY3VycmVudFVzZXIuaW1hZ2UgOiBHbG9iYWwuaW1hZ2VQYXRoICsgJy9ub19hdmF0YXIuZ2lmJztcbiAgICB9XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbi8qZXNsaW50IGFuZ3VsYXIvZmlsZS1uYW1lOiAwLCBuby11bmRlZjogMCovXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgLyoqXG4gICAqIFRyYW5zZm9ybWEgYmlibGlvdGVjYXMgZXh0ZXJuYXMgZW0gc2VydmnDp29zIGRvIGFuZ3VsYXIgcGFyYSBzZXIgcG9zc8OtdmVsIHV0aWxpemFyXG4gICAqIGF0cmF2w6lzIGRhIGluamXDp8OjbyBkZSBkZXBlbmTDqm5jaWFcbiAgICovXG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbnN0YW50KCdsb2Rhc2gnLCBfKS5jb25zdGFudCgnbW9tZW50JywgbW9tZW50KTtcbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29uc3RhbnQoJ0dsb2JhbCcsIHtcbiAgICBhcHBOYW1lOiAnRnJlZWxhZ2lsZScsXG4gICAgaG9tZVN0YXRlOiAnYXBwLmRhc2hib2FyZCcsXG4gICAgbG9naW5Vcmw6ICdhcHAvbG9naW4nLFxuICAgIGxvZ2luU3RhdGU6ICdhcHAubG9naW4nLFxuICAgIHJlc2V0UGFzc3dvcmRTdGF0ZTogJ2FwcC5wYXNzd29yZC1yZXNldCcsXG4gICAgbm90QXV0aG9yaXplZFN0YXRlOiAnYXBwLm5vdC1hdXRob3JpemVkJyxcbiAgICB0b2tlbktleTogJ3NlcnZlcl90b2tlbicsXG4gICAgY2xpZW50UGF0aDogJ2NsaWVudC9hcHAnLFxuICAgIGFwaVBhdGg6ICdhcGkvdjEnLFxuICAgIGltYWdlUGF0aDogJ2NsaWVudC9pbWFnZXMnXG4gIH0pO1xufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25maWcocm91dGVzKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvdXRlcygkc3RhdGVQcm92aWRlciwgJHVybFJvdXRlclByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnYXBwJywge1xuICAgICAgdXJsOiAnL2FwcCcsXG4gICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL2xheW91dC9hcHAuaHRtbCcsXG4gICAgICBhYnN0cmFjdDogdHJ1ZSxcbiAgICAgIHJlc29sdmU6IHsgLy9lbnN1cmUgbGFuZ3MgaXMgcmVhZHkgYmVmb3JlIHJlbmRlciB2aWV3XG4gICAgICAgIHRyYW5zbGF0ZVJlYWR5OiBbJyR0cmFuc2xhdGUnLCAnJHEnLCBmdW5jdGlvbiAoJHRyYW5zbGF0ZSwgJHEpIHtcbiAgICAgICAgICB2YXIgZGVmZXJyZWQgPSAkcS5kZWZlcigpO1xuXG4gICAgICAgICAgJHRyYW5zbGF0ZS51c2UoJ3B0LUJSJykudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICBkZWZlcnJlZC5yZXNvbHZlKCk7XG4gICAgICAgICAgfSk7XG5cbiAgICAgICAgICByZXR1cm4gZGVmZXJyZWQucHJvbWlzZTtcbiAgICAgICAgfV1cbiAgICAgIH1cbiAgICB9KS5zdGF0ZShHbG9iYWwubm90QXV0aG9yaXplZFN0YXRlLCB7XG4gICAgICB1cmw6ICcvYWNlc3NvLW5lZ2FkbycsXG4gICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL2xheW91dC9ub3QtYXV0aG9yaXplZC5odG1sJyxcbiAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiBmYWxzZSB9XG4gICAgfSk7XG5cbiAgICAkdXJsUm91dGVyUHJvdmlkZXIud2hlbignL2FwcCcsIEdsb2JhbC5sb2dpblVybCk7XG4gICAgJHVybFJvdXRlclByb3ZpZGVyLm90aGVyd2lzZShHbG9iYWwubG9naW5VcmwpO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLnJ1bihydW4pO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gcnVuKCRyb290U2NvcGUsICRzdGF0ZSwgJHN0YXRlUGFyYW1zLCBBdXRoLCBHbG9iYWwpIHtcbiAgICAvLyBOT1NPTkFSXG4gICAgLy9zZXRhZG8gbm8gcm9vdFNjb3BlIHBhcmEgcG9kZXIgc2VyIGFjZXNzYWRvIG5hcyB2aWV3cyBzZW0gcHJlZml4byBkZSBjb250cm9sbGVyXG4gICAgJHJvb3RTY29wZS4kc3RhdGUgPSAkc3RhdGU7XG4gICAgJHJvb3RTY29wZS4kc3RhdGVQYXJhbXMgPSAkc3RhdGVQYXJhbXM7XG4gICAgJHJvb3RTY29wZS5hdXRoID0gQXV0aDtcbiAgICAkcm9vdFNjb3BlLmdsb2JhbCA9IEdsb2JhbDtcblxuICAgIC8vbm8gaW5pY2lvIGNhcnJlZ2EgbyB1c3XDoXJpbyBkbyBsb2NhbHN0b3JhZ2UgY2FzbyBvIHVzdcOhcmlvIGVzdGFqYSBhYnJpbmRvIG8gbmF2ZWdhZG9yXG4gICAgLy9wYXJhIHZvbHRhciBhdXRlbnRpY2Fkb1xuICAgIEF1dGgucmV0cmlldmVVc2VyRnJvbUxvY2FsU3RvcmFnZSgpO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29udHJvbGxlcignQXVkaXRDb250cm9sbGVyJywgQXVkaXRDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIEF1ZGl0Q29udHJvbGxlcigkY29udHJvbGxlciwgQXVkaXRTZXJ2aWNlLCBQckRpYWxvZywgR2xvYmFsLCAkdHJhbnNsYXRlKSB7XG4gICAgLy8gTk9TT05BUlxuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICB2bS5vbkFjdGl2YXRlID0gb25BY3RpdmF0ZTtcbiAgICB2bS5hcHBseUZpbHRlcnMgPSBhcHBseUZpbHRlcnM7XG4gICAgdm0udmlld0RldGFpbCA9IHZpZXdEZXRhaWw7XG5cbiAgICAkY29udHJvbGxlcignQ1JVRENvbnRyb2xsZXInLCB7IHZtOiB2bSwgbW9kZWxTZXJ2aWNlOiBBdWRpdFNlcnZpY2UsIG9wdGlvbnM6IHt9IH0pO1xuXG4gICAgZnVuY3Rpb24gb25BY3RpdmF0ZSgpIHtcbiAgICAgIHZtLm1vZGVscyA9IFtdO1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0ge307XG5cbiAgICAgIC8vUGVnYSB0b2RvcyBvcyBtb2RlbHMgZG8gc2VydmVyIGUgbW9udGEgdW1hIGxpc3RhIHBybyBDb21ib0JveFxuICAgICAgQXVkaXRTZXJ2aWNlLmdldEF1ZGl0ZWRNb2RlbHMoKS50aGVuKGZ1bmN0aW9uIChkYXRhKSB7XG4gICAgICAgIHZhciBtb2RlbHMgPSBbeyBpZDogJycsIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ2dsb2JhbC5hbGwnKSB9XTtcblxuICAgICAgICBkYXRhLm1vZGVscy5zb3J0KCk7XG5cbiAgICAgICAgZm9yICh2YXIgaW5kZXggPSAwOyBpbmRleCA8IGRhdGEubW9kZWxzLmxlbmd0aDsgaW5kZXgrKykge1xuICAgICAgICAgIHZhciBtb2RlbCA9IGRhdGEubW9kZWxzW2luZGV4XTtcblxuICAgICAgICAgIG1vZGVscy5wdXNoKHtcbiAgICAgICAgICAgIGlkOiBtb2RlbCxcbiAgICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ21vZGVscy4nICsgbW9kZWwudG9Mb3dlckNhc2UoKSlcbiAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHZtLm1vZGVscyA9IG1vZGVscztcbiAgICAgICAgdm0ucXVlcnlGaWx0ZXJzLm1vZGVsID0gdm0ubW9kZWxzWzBdLmlkO1xuICAgICAgfSk7XG5cbiAgICAgIHZtLnR5cGVzID0gQXVkaXRTZXJ2aWNlLmxpc3RUeXBlcygpO1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzLnR5cGUgPSB2bS50eXBlc1swXS5pZDtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBhcHBseUZpbHRlcnMoZGVmYXVsdFF1ZXJ5RmlsdGVycykge1xuICAgICAgcmV0dXJuIGFuZ3VsYXIuZXh0ZW5kKGRlZmF1bHRRdWVyeUZpbHRlcnMsIHZtLnF1ZXJ5RmlsdGVycyk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gdmlld0RldGFpbChhdWRpdERldGFpbCkge1xuICAgICAgdmFyIGNvbmZpZyA9IHtcbiAgICAgICAgbG9jYWxzOiB7IGF1ZGl0RGV0YWlsOiBhdWRpdERldGFpbCB9LFxuICAgICAgICAvKiogQG5nSW5qZWN0ICovXG4gICAgICAgIGNvbnRyb2xsZXI6IGZ1bmN0aW9uIGNvbnRyb2xsZXIoYXVkaXREZXRhaWwsIFByRGlhbG9nKSB7XG4gICAgICAgICAgdmFyIHZtID0gdGhpcztcblxuICAgICAgICAgIHZtLmNsb3NlID0gY2xvc2U7XG5cbiAgICAgICAgICBhY3RpdmF0ZSgpO1xuXG4gICAgICAgICAgZnVuY3Rpb24gYWN0aXZhdGUoKSB7XG4gICAgICAgICAgICBpZiAoYW5ndWxhci5pc0FycmF5KGF1ZGl0RGV0YWlsLm9sZCkgJiYgYXVkaXREZXRhaWwub2xkLmxlbmd0aCA9PT0gMCkgYXVkaXREZXRhaWwub2xkID0gbnVsbDtcbiAgICAgICAgICAgIGlmIChhbmd1bGFyLmlzQXJyYXkoYXVkaXREZXRhaWwubmV3KSAmJiBhdWRpdERldGFpbC5uZXcubGVuZ3RoID09PSAwKSBhdWRpdERldGFpbC5uZXcgPSBudWxsO1xuXG4gICAgICAgICAgICB2bS5hdWRpdERldGFpbCA9IGF1ZGl0RGV0YWlsO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIGZ1bmN0aW9uIGNsb3NlKCkge1xuICAgICAgICAgICAgUHJEaWFsb2cuY2xvc2UoKTtcbiAgICAgICAgICB9XG4gICAgICAgIH0sXG4gICAgICAgIGNvbnRyb2xsZXJBczogJ2F1ZGl0RGV0YWlsQ3RybCcsXG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvYXVkaXQvYXVkaXQtZGV0YWlsLmh0bWwnLFxuICAgICAgICBoYXNCYWNrZHJvcDogdHJ1ZVxuICAgICAgfTtcblxuICAgICAgUHJEaWFsb2cuY3VzdG9tKGNvbmZpZyk7XG4gICAgfVxuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKlxuICAgKiBBcnF1aXZvIGRlIGNvbmZpZ3VyYcOnw6NvIGNvbSBhcyByb3RhcyBlc3BlY8OtZmljYXMgZGUgYXVkaXRvcmlhXG4gICAqXG4gICAqIEBwYXJhbSB7YW55fSAkc3RhdGVQcm92aWRlclxuICAgKiBAcGFyYW0ge2FueX0gR2xvYmFsXG4gICAqL1xuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvdXRlcygkc3RhdGVQcm92aWRlciwgR2xvYmFsKSB7XG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ2FwcC5hdWRpdCcsIHtcbiAgICAgIHVybDogJy9hdWRpdG9yaWEnLFxuICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9hdWRpdC9hdWRpdC5odG1sJyxcbiAgICAgIGNvbnRyb2xsZXI6ICdBdWRpdENvbnRyb2xsZXIgYXMgYXVkaXRDdHJsJyxcbiAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiB0cnVlLCBuZWVkUHJvZmlsZTogWydhZG1pbiddIH1cbiAgICB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5mYWN0b3J5KCdBdWRpdFNlcnZpY2UnLCBBdWRpdFNlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gQXVkaXRTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5LCAkdHJhbnNsYXRlKSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCdhdWRpdCcsIHtcbiAgICAgIGFjdGlvbnM6IHtcbiAgICAgICAgZ2V0QXVkaXRlZE1vZGVsczoge1xuICAgICAgICAgIG1ldGhvZDogJ0dFVCcsXG4gICAgICAgICAgdXJsOiAnbW9kZWxzJ1xuICAgICAgICB9XG4gICAgICB9LFxuICAgICAgaW5zdGFuY2U6IHt9LFxuICAgICAgbGlzdFR5cGVzOiBmdW5jdGlvbiBsaXN0VHlwZXMoKSB7XG4gICAgICAgIHZhciBhdWRpdFBhdGggPSAndmlld3MuZmllbGRzLmF1ZGl0Lic7XG5cbiAgICAgICAgcmV0dXJuIFt7IGlkOiAnJywgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudChhdWRpdFBhdGggKyAnYWxsUmVzb3VyY2VzJykgfSwgeyBpZDogJ2NyZWF0ZWQnLCBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KGF1ZGl0UGF0aCArICd0eXBlLmNyZWF0ZWQnKSB9LCB7IGlkOiAndXBkYXRlZCcsIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoYXVkaXRQYXRoICsgJ3R5cGUudXBkYXRlZCcpIH0sIHsgaWQ6ICdkZWxldGVkJywgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudChhdWRpdFBhdGggKyAndHlwZS5kZWxldGVkJykgfV07XG4gICAgICB9XG4gICAgfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqXG4gICAqIEFycXVpdm8gZGUgY29uZmlndXJhw6fDo28gY29tIGFzIHJvdGFzIGVzcGVjw61maWNhcyBkbyByZWN1cnNvIHVzZXJcbiAgICpcbiAgICogQHBhcmFtIHthbnl9ICRzdGF0ZVByb3ZpZGVyXG4gICAqIEBwYXJhbSB7YW55fSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZShHbG9iYWwucmVzZXRQYXNzd29yZFN0YXRlLCB7XG4gICAgICB1cmw6ICcvcGFzc3dvcmQvcmVzZXQvOnRva2VuJyxcbiAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvYXV0aC9yZXNldC1wYXNzLWZvcm0uaHRtbCcsXG4gICAgICBjb250cm9sbGVyOiAnUGFzc3dvcmRDb250cm9sbGVyIGFzIHBhc3NDdHJsJyxcbiAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiBmYWxzZSB9XG4gICAgfSkuc3RhdGUoR2xvYmFsLmxvZ2luU3RhdGUsIHtcbiAgICAgIHVybDogJy9sb2dpbicsXG4gICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL2F1dGgvbG9naW4uaHRtbCcsXG4gICAgICBjb250cm9sbGVyOiAnTG9naW5Db250cm9sbGVyIGFzIGxvZ2luQ3RybCcsXG4gICAgICBkYXRhOiB7IG5lZWRBdXRoZW50aWNhdGlvbjogZmFsc2UgfVxuICAgIH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZhY3RvcnkoJ0F1dGgnLCBBdXRoKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIEF1dGgoJGh0dHAsICRxLCBHbG9iYWwsIFVzZXJzU2VydmljZSkge1xuICAgIC8vIE5PU09OQVJcbiAgICB2YXIgYXV0aCA9IHtcbiAgICAgIGxvZ2luOiBsb2dpbixcbiAgICAgIGxvZ291dDogbG9nb3V0LFxuICAgICAgdXBkYXRlQ3VycmVudFVzZXI6IHVwZGF0ZUN1cnJlbnRVc2VyLFxuICAgICAgcmV0cmlldmVVc2VyRnJvbUxvY2FsU3RvcmFnZTogcmV0cmlldmVVc2VyRnJvbUxvY2FsU3RvcmFnZSxcbiAgICAgIGF1dGhlbnRpY2F0ZWQ6IGF1dGhlbnRpY2F0ZWQsXG4gICAgICBzZW5kRW1haWxSZXNldFBhc3N3b3JkOiBzZW5kRW1haWxSZXNldFBhc3N3b3JkLFxuICAgICAgcmVtb3RlVmFsaWRhdGVUb2tlbjogcmVtb3RlVmFsaWRhdGVUb2tlbixcbiAgICAgIGdldFRva2VuOiBnZXRUb2tlbixcbiAgICAgIHNldFRva2VuOiBzZXRUb2tlbixcbiAgICAgIGNsZWFyVG9rZW46IGNsZWFyVG9rZW4sXG4gICAgICBjdXJyZW50VXNlcjogbnVsbFxuICAgIH07XG5cbiAgICBmdW5jdGlvbiBjbGVhclRva2VuKCkge1xuICAgICAgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oR2xvYmFsLnRva2VuS2V5KTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBzZXRUb2tlbih0b2tlbikge1xuICAgICAgbG9jYWxTdG9yYWdlLnNldEl0ZW0oR2xvYmFsLnRva2VuS2V5LCB0b2tlbik7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gZ2V0VG9rZW4oKSB7XG4gICAgICByZXR1cm4gbG9jYWxTdG9yYWdlLmdldEl0ZW0oR2xvYmFsLnRva2VuS2V5KTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiByZW1vdGVWYWxpZGF0ZVRva2VuKCkge1xuICAgICAgdmFyIGRlZmVycmVkID0gJHEuZGVmZXIoKTtcblxuICAgICAgaWYgKGF1dGguYXV0aGVudGljYXRlZCgpKSB7XG4gICAgICAgICRodHRwLmdldChHbG9iYWwuYXBpUGF0aCArICcvYXV0aGVudGljYXRlL2NoZWNrJykudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgZGVmZXJyZWQucmVzb2x2ZSh0cnVlKTtcbiAgICAgICAgfSwgZnVuY3Rpb24gKCkge1xuICAgICAgICAgIGF1dGgubG9nb3V0KCk7XG5cbiAgICAgICAgICBkZWZlcnJlZC5yZWplY3QoZmFsc2UpO1xuICAgICAgICB9KTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIGF1dGgubG9nb3V0KCk7XG5cbiAgICAgICAgZGVmZXJyZWQucmVqZWN0KGZhbHNlKTtcbiAgICAgIH1cblxuICAgICAgcmV0dXJuIGRlZmVycmVkLnByb21pc2U7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogVmVyaWZpY2Egc2UgbyB1c3XDoXJpbyBlc3TDoSBhdXRlbnRpY2Fkb1xuICAgICAqXG4gICAgICogQHJldHVybnMge2Jvb2xlYW59XG4gICAgICovXG4gICAgZnVuY3Rpb24gYXV0aGVudGljYXRlZCgpIHtcbiAgICAgIHJldHVybiBhdXRoLmdldFRva2VuKCkgIT09IG51bGw7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVjdXBlcmEgbyB1c3XDoXJpbyBkbyBsb2NhbFN0b3JhZ2VcbiAgICAgKi9cbiAgICBmdW5jdGlvbiByZXRyaWV2ZVVzZXJGcm9tTG9jYWxTdG9yYWdlKCkge1xuICAgICAgdmFyIHVzZXIgPSBsb2NhbFN0b3JhZ2UuZ2V0SXRlbSgndXNlcicpO1xuXG4gICAgICBpZiAodXNlcikge1xuICAgICAgICBhdXRoLmN1cnJlbnRVc2VyID0gYW5ndWxhci5tZXJnZShuZXcgVXNlcnNTZXJ2aWNlKCksIGFuZ3VsYXIuZnJvbUpzb24odXNlcikpO1xuICAgICAgfVxuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEd1YXJkYSBvIHVzdcOhcmlvIG5vIGxvY2FsU3RvcmFnZSBwYXJhIGNhc28gbyB1c3XDoXJpbyBmZWNoZSBlIGFicmEgbyBuYXZlZ2Fkb3JcbiAgICAgKiBkZW50cm8gZG8gdGVtcG8gZGUgc2Vzc8OjbyBzZWphIHBvc3PDrXZlbCByZWN1cGVyYXIgbyB0b2tlbiBhdXRlbnRpY2Fkby5cbiAgICAgKlxuICAgICAqIE1hbnTDqW0gYSB2YXJpw6F2ZWwgYXV0aC5jdXJyZW50VXNlciBwYXJhIGZhY2lsaXRhciBvIGFjZXNzbyBhbyB1c3XDoXJpbyBsb2dhZG8gZW0gdG9kYSBhIGFwbGljYcOnw6NvXG4gICAgICpcbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSB1c2VyIFVzdcOhcmlvIGEgc2VyIGF0dWFsaXphZG8uIENhc28gc2VqYSBwYXNzYWRvIG51bGwgbGltcGFcbiAgICAgKiB0b2RhcyBhcyBpbmZvcm1hw6fDtWVzIGRvIHVzdcOhcmlvIGNvcnJlbnRlLlxuICAgICAqL1xuICAgIGZ1bmN0aW9uIHVwZGF0ZUN1cnJlbnRVc2VyKHVzZXIpIHtcbiAgICAgIHZhciBkZWZlcnJlZCA9ICRxLmRlZmVyKCk7XG5cbiAgICAgIGlmICh1c2VyKSB7XG4gICAgICAgIHVzZXIgPSBhbmd1bGFyLm1lcmdlKG5ldyBVc2Vyc1NlcnZpY2UoKSwgdXNlcik7XG5cbiAgICAgICAgdmFyIGpzb25Vc2VyID0gYW5ndWxhci50b0pzb24odXNlcik7XG5cbiAgICAgICAgbG9jYWxTdG9yYWdlLnNldEl0ZW0oJ3VzZXInLCBqc29uVXNlcik7XG4gICAgICAgIGF1dGguY3VycmVudFVzZXIgPSB1c2VyO1xuXG4gICAgICAgIGRlZmVycmVkLnJlc29sdmUodXNlcik7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbSgndXNlcicpO1xuICAgICAgICBhdXRoLmN1cnJlbnRVc2VyID0gbnVsbDtcbiAgICAgICAgYXV0aC5jbGVhclRva2VuKCk7XG5cbiAgICAgICAgZGVmZXJyZWQucmVqZWN0KCk7XG4gICAgICB9XG5cbiAgICAgIHJldHVybiBkZWZlcnJlZC5wcm9taXNlO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWxpemEgbyBsb2dpbiBkbyB1c3XDoXJpb1xuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IGNyZWRlbnRpYWxzIEVtYWlsIGUgU2VuaGEgZG8gdXN1w6FyaW9cbiAgICAgKiBAcmV0dXJucyB7cHJvbWlzZX0gVW1hIHByb21pc2UgY29tIG8gcmVzdWx0YWRvIGRvIGNoYW1hZGEgbm8gYmFja2VuZFxuICAgICAqL1xuICAgIGZ1bmN0aW9uIGxvZ2luKGNyZWRlbnRpYWxzKSB7XG4gICAgICB2YXIgZGVmZXJyZWQgPSAkcS5kZWZlcigpO1xuXG4gICAgICAkaHR0cC5wb3N0KEdsb2JhbC5hcGlQYXRoICsgJy9hdXRoZW50aWNhdGUnLCBjcmVkZW50aWFscykudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgYXV0aC5zZXRUb2tlbihyZXNwb25zZS5kYXRhLnRva2VuKTtcblxuICAgICAgICByZXR1cm4gJGh0dHAuZ2V0KEdsb2JhbC5hcGlQYXRoICsgJy9hdXRoZW50aWNhdGUvdXNlcicpO1xuICAgICAgfSkudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgYXV0aC51cGRhdGVDdXJyZW50VXNlcihyZXNwb25zZS5kYXRhLnVzZXIpO1xuXG4gICAgICAgIGRlZmVycmVkLnJlc29sdmUoKTtcbiAgICAgIH0sIGZ1bmN0aW9uIChlcnJvcikge1xuICAgICAgICBhdXRoLmxvZ291dCgpO1xuXG4gICAgICAgIGRlZmVycmVkLnJlamVjdChlcnJvcik7XG4gICAgICB9KTtcblxuICAgICAgcmV0dXJuIGRlZmVycmVkLnByb21pc2U7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogRGVzbG9nYSBvcyB1c3XDoXJpb3MuIENvbW8gbsOjbyB0ZW4gbmVuaHVtYSBpbmZvcm1hw6fDo28gbmEgc2Vzc8OjbyBkbyBzZXJ2aWRvclxuICAgICAqIGUgdW0gdG9rZW4gdW1hIHZleiBnZXJhZG8gbsOjbyBwb2RlLCBwb3IgcGFkcsOjbywgc2VyIGludmFsaWRhZG8gYW50ZXMgZG8gc2V1IHRlbXBvIGRlIGV4cGlyYcOnw6NvLFxuICAgICAqIHNvbWVudGUgYXBhZ2Ftb3Mgb3MgZGFkb3MgZG8gdXN1w6FyaW8gZSBvIHRva2VuIGRvIG5hdmVnYWRvciBwYXJhIGVmZXRpdmFyIG8gbG9nb3V0LlxuICAgICAqXG4gICAgICogQHJldHVybnMge3Byb21pc2V9IFVtYSBwcm9taXNlIGNvbSBvIHJlc3VsdGFkbyBkYSBvcGVyYcOnw6NvXG4gICAgICovXG4gICAgZnVuY3Rpb24gbG9nb3V0KCkge1xuICAgICAgdmFyIGRlZmVycmVkID0gJHEuZGVmZXIoKTtcblxuICAgICAgYXV0aC51cGRhdGVDdXJyZW50VXNlcihudWxsKTtcbiAgICAgIGRlZmVycmVkLnJlc29sdmUoKTtcblxuICAgICAgcmV0dXJuIGRlZmVycmVkLnByb21pc2U7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogRW52aWEgdW0gZW1haWwgcGFyYSByZWN1cGVyYcOnw6NvIGRlIHNlbmhhXG4gICAgICogQHBhcmFtIHtPYmplY3R9IHJlc2V0RGF0YSAtIE9iamV0byBjb250ZW5kbyBvIGVtYWlsXG4gICAgICogQHJldHVybiB7UHJvbWlzZX0gLSBSZXRvcm5hIHVtYSBwcm9taXNlIHBhcmEgc2VyIHJlc29sdmlkYVxuICAgICAqL1xuICAgIGZ1bmN0aW9uIHNlbmRFbWFpbFJlc2V0UGFzc3dvcmQocmVzZXREYXRhKSB7XG4gICAgICB2YXIgZGVmZXJyZWQgPSAkcS5kZWZlcigpO1xuXG4gICAgICAkaHR0cC5wb3N0KEdsb2JhbC5hcGlQYXRoICsgJy9wYXNzd29yZC9lbWFpbCcsIHJlc2V0RGF0YSkudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgZGVmZXJyZWQucmVzb2x2ZShyZXNwb25zZS5kYXRhKTtcbiAgICAgIH0sIGZ1bmN0aW9uIChlcnJvcikge1xuICAgICAgICBkZWZlcnJlZC5yZWplY3QoZXJyb3IpO1xuICAgICAgfSk7XG5cbiAgICAgIHJldHVybiBkZWZlcnJlZC5wcm9taXNlO1xuICAgIH1cblxuICAgIHJldHVybiBhdXRoO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29udHJvbGxlcignTG9naW5Db250cm9sbGVyJywgTG9naW5Db250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIExvZ2luQ29udHJvbGxlcigkc3RhdGUsIEF1dGgsIEdsb2JhbCwgUHJEaWFsb2cpIHtcbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0ubG9naW4gPSBsb2dpbjtcbiAgICB2bS5vcGVuRGlhbG9nUmVzZXRQYXNzID0gb3BlbkRpYWxvZ1Jlc2V0UGFzcztcbiAgICB2bS5vcGVuRGlhbG9nU2lnblVwID0gb3BlbkRpYWxvZ1NpZ25VcDtcblxuICAgIGFjdGl2YXRlKCk7XG5cbiAgICBmdW5jdGlvbiBhY3RpdmF0ZSgpIHtcbiAgICAgIHZtLmNyZWRlbnRpYWxzID0ge307XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gbG9naW4oKSB7XG4gICAgICB2YXIgY3JlZGVudGlhbHMgPSB7XG4gICAgICAgIGVtYWlsOiB2bS5jcmVkZW50aWFscy5lbWFpbCxcbiAgICAgICAgcGFzc3dvcmQ6IHZtLmNyZWRlbnRpYWxzLnBhc3N3b3JkXG4gICAgICB9O1xuXG4gICAgICBBdXRoLmxvZ2luKGNyZWRlbnRpYWxzKS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgJHN0YXRlLmdvKEdsb2JhbC5ob21lU3RhdGUpO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogRXhpYmUgbyBkaWFsb2cgcGFyYSByZWN1cGVyYcOnw6NvIGRlIHNlbmhhXG4gICAgICovXG4gICAgZnVuY3Rpb24gb3BlbkRpYWxvZ1Jlc2V0UGFzcygpIHtcbiAgICAgIHZhciBjb25maWcgPSB7XG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvYXV0aC9zZW5kLXJlc2V0LWRpYWxvZy5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ1Bhc3N3b3JkQ29udHJvbGxlciBhcyBwYXNzQ3RybCcsXG4gICAgICAgIGhhc0JhY2tkcm9wOiB0cnVlXG4gICAgICB9O1xuXG4gICAgICBQckRpYWxvZy5jdXN0b20oY29uZmlnKTtcbiAgICB9XG4gICAgLyoqXG4gICAgICogRXhpYmUgbyBkaWFsb2cgcGFyYSByZWN1cGVyYcOnw6NvIGRlIHNlbmhhXG4gICAgICovXG4gICAgZnVuY3Rpb24gb3BlbkRpYWxvZ1NpZ25VcCgpIHtcbiAgICAgIHZhciBjb25maWcgPSB7XG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvdXNlcnMvdXNlci1mb3JtLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnVXNlcnNDb250cm9sbGVyIGFzIHVzZXJzQ3RybCcsXG4gICAgICAgIGhhc0JhY2tkcm9wOiB0cnVlXG4gICAgICB9O1xuXG4gICAgICBQckRpYWxvZy5jdXN0b20oY29uZmlnKTtcbiAgICB9XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb250cm9sbGVyKCdQYXNzd29yZENvbnRyb2xsZXInLCBQYXNzd29yZENvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gUGFzc3dvcmRDb250cm9sbGVyKEdsb2JhbCwgJHN0YXRlUGFyYW1zLCAkaHR0cCwgJHRpbWVvdXQsICRzdGF0ZSwgLy8gTk9TT05BUlxuICBQclRvYXN0LCBQckRpYWxvZywgQXV0aCwgJHRyYW5zbGF0ZSkge1xuXG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIHZtLnNlbmRSZXNldCA9IHNlbmRSZXNldDtcbiAgICB2bS5jbG9zZURpYWxvZyA9IGNsb3NlRGlhbG9nO1xuICAgIHZtLmNsZWFuRm9ybSA9IGNsZWFuRm9ybTtcbiAgICB2bS5zZW5kRW1haWxSZXNldFBhc3N3b3JkID0gc2VuZEVtYWlsUmVzZXRQYXNzd29yZDtcblxuICAgIGFjdGl2YXRlKCk7XG5cbiAgICBmdW5jdGlvbiBhY3RpdmF0ZSgpIHtcbiAgICAgIHZtLnJlc2V0ID0geyBlbWFpbDogJycsIHRva2VuOiAkc3RhdGVQYXJhbXMudG9rZW4gfTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFsaXphIGEgYWx0ZXJhw6fDo28gZGEgc2VuaGEgZG8gdXN1w6FyaW8gZSBvIHJlZGlyZWNpb25hIHBhcmEgYSB0ZWxhIGRlIGxvZ2luXG4gICAgICovXG4gICAgZnVuY3Rpb24gc2VuZFJlc2V0KCkge1xuICAgICAgJGh0dHAucG9zdChHbG9iYWwuYXBpUGF0aCArICcvcGFzc3dvcmQvcmVzZXQnLCB2bS5yZXNldCkudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgIFByVG9hc3Quc3VjY2VzcygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLm9wZXJhdGlvblN1Y2Nlc3MnKSk7XG4gICAgICAgICR0aW1lb3V0KGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAkc3RhdGUuZ28oR2xvYmFsLmxvZ2luU3RhdGUpO1xuICAgICAgICB9LCAxNTAwKTtcbiAgICAgIH0sIGZ1bmN0aW9uIChlcnJvcikge1xuICAgICAgICBpZiAoZXJyb3Iuc3RhdHVzICE9PSA0MDAgJiYgZXJyb3Iuc3RhdHVzICE9PSA1MDApIHtcbiAgICAgICAgICB2YXIgbXNnID0gJyc7XG5cbiAgICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IGVycm9yLmRhdGEucGFzc3dvcmQubGVuZ3RoOyBpKyspIHtcbiAgICAgICAgICAgIG1zZyArPSBlcnJvci5kYXRhLnBhc3N3b3JkW2ldICsgJzxicj4nO1xuICAgICAgICAgIH1cbiAgICAgICAgICBQclRvYXN0LmVycm9yKG1zZy50b1VwcGVyQ2FzZSgpKTtcbiAgICAgICAgfVxuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogRW52aWEgdW0gZW1haWwgZGUgcmVjdXBlcmHDp8OjbyBkZSBzZW5oYSBjb20gbyB0b2tlbiBkbyB1c3XDoXJpb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIHNlbmRFbWFpbFJlc2V0UGFzc3dvcmQoKSB7XG5cbiAgICAgIGlmICh2bS5yZXNldC5lbWFpbCA9PT0gJycpIHtcbiAgICAgICAgUHJUb2FzdC5lcnJvcigkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnZhbGlkYXRlLmZpZWxkUmVxdWlyZWQnLCB7IGZpZWxkOiAnZW1haWwnIH0pKTtcbiAgICAgICAgcmV0dXJuO1xuICAgICAgfVxuXG4gICAgICBBdXRoLnNlbmRFbWFpbFJlc2V0UGFzc3dvcmQodm0ucmVzZXQpLnRoZW4oZnVuY3Rpb24gKGRhdGEpIHtcbiAgICAgICAgUHJUb2FzdC5zdWNjZXNzKGRhdGEubWVzc2FnZSk7XG5cbiAgICAgICAgdm0uY2xlYW5Gb3JtKCk7XG4gICAgICAgIHZtLmNsb3NlRGlhbG9nKCk7XG4gICAgICB9LCBmdW5jdGlvbiAoZXJyb3IpIHtcbiAgICAgICAgaWYgKGVycm9yLmRhdGEuZW1haWwgJiYgZXJyb3IuZGF0YS5lbWFpbC5sZW5ndGggPiAwKSB7XG4gICAgICAgICAgdmFyIG1zZyA9ICcnO1xuXG4gICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCBlcnJvci5kYXRhLmVtYWlsLmxlbmd0aDsgaSsrKSB7XG4gICAgICAgICAgICBtc2cgKz0gZXJyb3IuZGF0YS5lbWFpbFtpXSArICc8YnI+JztcbiAgICAgICAgICB9XG5cbiAgICAgICAgICBQclRvYXN0LmVycm9yKG1zZyk7XG4gICAgICAgIH1cbiAgICAgIH0pO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGNsb3NlRGlhbG9nKCkge1xuICAgICAgUHJEaWFsb2cuY2xvc2UoKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBjbGVhbkZvcm0oKSB7XG4gICAgICB2bS5yZXNldC5lbWFpbCA9ICcnO1xuICAgIH1cbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuLyplc2xpbnQgYW5ndWxhci9maWxlLW5hbWU6IDAqL1xuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5mYWN0b3J5KCdzZXJ2aWNlRmFjdG9yeScsIHNlcnZpY2VGYWN0b3J5KTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8qKlxuICAgKiBNYWlzIGluZm9ybWHDp8O1ZXM6XG4gICAqIGh0dHBzOi8vZ2l0aHViLmNvbS9zd2ltbGFuZS9hbmd1bGFyLW1vZGVsLWZhY3Rvcnkvd2lraS9BUElcbiAgICovXG4gIGZ1bmN0aW9uIHNlcnZpY2VGYWN0b3J5KCRtb2RlbEZhY3RvcnkpIHtcbiAgICByZXR1cm4gZnVuY3Rpb24gKHVybCwgb3B0aW9ucykge1xuICAgICAgdmFyIG1vZGVsO1xuICAgICAgdmFyIGRlZmF1bHRPcHRpb25zID0ge1xuICAgICAgICBhY3Rpb25zOiB7XG4gICAgICAgICAgLyoqXG4gICAgICAgICAgICogU2VydmnDp28gY29tdW0gcGFyYSByZWFsaXphciBidXNjYSBjb20gcGFnaW5hw6fDo29cbiAgICAgICAgICAgKiBPIG1lc21vIGVzcGVyYSBxdWUgc2VqYSByZXRvcm5hZG8gdW0gb2JqZXRvIGNvbSBpdGVtcyBlIHRvdGFsXG4gICAgICAgICAgICovXG4gICAgICAgICAgcGFnaW5hdGU6IHtcbiAgICAgICAgICAgIG1ldGhvZDogJ0dFVCcsXG4gICAgICAgICAgICBpc0FycmF5OiBmYWxzZSxcbiAgICAgICAgICAgIHdyYXA6IGZhbHNlLFxuICAgICAgICAgICAgYWZ0ZXJSZXF1ZXN0OiBmdW5jdGlvbiBhZnRlclJlcXVlc3QocmVzcG9uc2UpIHtcbiAgICAgICAgICAgICAgaWYgKHJlc3BvbnNlWydpdGVtcyddKSB7XG4gICAgICAgICAgICAgICAgcmVzcG9uc2VbJ2l0ZW1zJ10gPSBtb2RlbC5MaXN0KHJlc3BvbnNlWydpdGVtcyddKTtcbiAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgIHJldHVybiByZXNwb25zZTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgIH07XG5cbiAgICAgIG1vZGVsID0gJG1vZGVsRmFjdG9yeSh1cmwsIGFuZ3VsYXIubWVyZ2UoZGVmYXVsdE9wdGlvbnMsIG9wdGlvbnMpKTtcblxuICAgICAgcmV0dXJuIG1vZGVsO1xuICAgIH07XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIENSVURDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8qKlxuICAgKiBDb250cm9sYWRvciBCYXNlIHF1ZSBpbXBsZW1lbnRhIHRvZGFzIGFzIGZ1bsOnw7VlcyBwYWRyw7VlcyBkZSB1bSBDUlVEXG4gICAqXG4gICAqIEHDp8O1ZXMgaW1wbGVtZW50YWRhc1xuICAgKiBhY3RpdmF0ZSgpXG4gICAqIHNlYXJjaChwYWdlKVxuICAgKiBlZGl0KHJlc291cmNlKVxuICAgKiBzYXZlKClcbiAgICogcmVtb3ZlKHJlc291cmNlKVxuICAgKiBnb1RvKHZpZXdOYW1lKVxuICAgKiBjbGVhbkZvcm0oKVxuICAgKlxuICAgKiBHYXRpbGhvc1xuICAgKlxuICAgKiBvbkFjdGl2YXRlKClcbiAgICogYXBwbHlGaWx0ZXJzKGRlZmF1bHRRdWVyeUZpbHRlcnMpXG4gICAqIGJlZm9yZVNlYXJjaChwYWdlKSAvL3JldG9ybmFuZG8gZmFsc2UgY2FuY2VsYSBvIGZsdXhvXG4gICAqIGFmdGVyU2VhcmNoKHJlc3BvbnNlKVxuICAgKiBiZWZvcmVDbGVhbiAvL3JldG9ybmFuZG8gZmFsc2UgY2FuY2VsYSBvIGZsdXhvXG4gICAqIGFmdGVyQ2xlYW4oKVxuICAgKiBiZWZvcmVTYXZlKCkgLy9yZXRvcm5hbmRvIGZhbHNlIGNhbmNlbGEgbyBmbHV4b1xuICAgKiBhZnRlclNhdmUocmVzb3VyY2UpXG4gICAqIG9uU2F2ZUVycm9yKGVycm9yKVxuICAgKiBiZWZvcmVSZW1vdmUocmVzb3VyY2UpIC8vcmV0b3JuYW5kbyBmYWxzZSBjYW5jZWxhIG8gZmx1eG9cbiAgICogYWZ0ZXJSZW1vdmUocmVzb3VyY2UpXG4gICAqXG4gICAqIEBwYXJhbSB7YW55fSB2bSBpbnN0YW5jaWEgZG8gY29udHJvbGxlciBmaWxob1xuICAgKiBAcGFyYW0ge2FueX0gbW9kZWxTZXJ2aWNlIHNlcnZpw6dvIGRvIG1vZGVsIHF1ZSB2YWkgc2VyIHV0aWxpemFkb1xuICAgKiBAcGFyYW0ge2FueX0gb3B0aW9ucyBvcMOnw7VlcyBwYXJhIHNvYnJlZXNjcmV2ZXIgY29tcG9ydGFtZW50b3MgcGFkcsO1ZXNcbiAgICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIENSVURDb250cm9sbGVyKHZtLCBtb2RlbFNlcnZpY2UsIG9wdGlvbnMsIFByVG9hc3QsIFByUGFnaW5hdGlvbiwgLy8gTk9TT05BUlxuICBQckRpYWxvZywgJHRyYW5zbGF0ZSkge1xuXG4gICAgLy9GdW5jdGlvbnMgQmxvY2tcbiAgICB2bS5zZWFyY2ggPSBzZWFyY2g7XG4gICAgdm0ucGFnaW5hdGVTZWFyY2ggPSBwYWdpbmF0ZVNlYXJjaDtcbiAgICB2bS5ub3JtYWxTZWFyY2ggPSBub3JtYWxTZWFyY2g7XG4gICAgdm0uZWRpdCA9IGVkaXQ7XG4gICAgdm0uc2F2ZSA9IHNhdmU7XG4gICAgdm0ucmVtb3ZlID0gcmVtb3ZlO1xuICAgIHZtLmdvVG8gPSBnb1RvO1xuICAgIHZtLmNsZWFuRm9ybSA9IGNsZWFuRm9ybTtcblxuICAgIGFjdGl2YXRlKCk7XG5cbiAgICAvKipcbiAgICAgKiBQcmVwYXJhIG8gY29udHJvbGFkb3JcbiAgICAgKiBGYXogbyBtZXJnZSBkYXMgb3DDp8O1ZXNcbiAgICAgKiBJbmljaWFsaXphIG8gcmVjdXJzb1xuICAgICAqIEluaWNpYWxpemEgbyBvYmpldG8gcGFnaW5hZG9yIGUgcmVhbGl6YSBhIHBlc3F1aXNhXG4gICAgICovXG4gICAgZnVuY3Rpb24gYWN0aXZhdGUoKSB7XG4gICAgICB2bS5kZWZhdWx0T3B0aW9ucyA9IHtcbiAgICAgICAgcmVkaXJlY3RBZnRlclNhdmU6IHRydWUsXG4gICAgICAgIHNlYXJjaE9uSW5pdDogdHJ1ZSxcbiAgICAgICAgcGVyUGFnZTogOCxcbiAgICAgICAgc2tpcFBhZ2luYXRpb246IGZhbHNlXG4gICAgICB9O1xuXG4gICAgICBhbmd1bGFyLm1lcmdlKHZtLmRlZmF1bHRPcHRpb25zLCBvcHRpb25zKTtcblxuICAgICAgdm0udmlld0Zvcm0gPSBmYWxzZTtcbiAgICAgIHZtLnJlc291cmNlID0gbmV3IG1vZGVsU2VydmljZSgpO1xuXG4gICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLm9uQWN0aXZhdGUpKSB2bS5vbkFjdGl2YXRlKCk7XG5cbiAgICAgIHZtLnBhZ2luYXRvciA9IFByUGFnaW5hdGlvbi5nZXRJbnN0YW5jZSh2bS5zZWFyY2gsIHZtLmRlZmF1bHRPcHRpb25zLnBlclBhZ2UpO1xuXG4gICAgICBpZiAodm0uZGVmYXVsdE9wdGlvbnMuc2VhcmNoT25Jbml0KSB2bS5zZWFyY2goKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFsaXphIGEgcGVzcXVpc2FcbiAgICAgKiBWZXJpZmljYSBxdWFsIGRhcyBmdW7Dp8O1ZXMgZGUgcGVzcXVpc2EgZGV2ZSBzZXIgcmVhbGl6YWRhLlxuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IHBhZ2UgcMOhZ2luYSBxdWUgZGV2ZSBzZXIgY2FycmVnYWRhXG4gICAgICovXG4gICAgZnVuY3Rpb24gc2VhcmNoKHBhZ2UpIHtcbiAgICAgIHZtLmRlZmF1bHRPcHRpb25zLnNraXBQYWdpbmF0aW9uID8gbm9ybWFsU2VhcmNoKCkgOiBwYWdpbmF0ZVNlYXJjaChwYWdlKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFsaXphIGEgcGVzcXVpc2EgcGFnaW5hZGEgY29tIGJhc2Ugbm9zIGZpbHRyb3MgZGVmaW5pZG9zXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gcGFnZSBww6FnaW5hIHF1ZSBkZXZlIHNlciBjYXJyZWdhZGFcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBwYWdpbmF0ZVNlYXJjaChwYWdlKSB7XG4gICAgICB2bS5wYWdpbmF0b3IuY3VycmVudFBhZ2UgPSBhbmd1bGFyLmlzRGVmaW5lZChwYWdlKSA/IHBhZ2UgOiAxO1xuICAgICAgdm0uZGVmYXVsdFF1ZXJ5RmlsdGVycyA9IHsgcGFnZTogdm0ucGFnaW5hdG9yLmN1cnJlbnRQYWdlLCBwZXJQYWdlOiB2bS5wYWdpbmF0b3IucGVyUGFnZSB9O1xuXG4gICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmFwcGx5RmlsdGVycykpIHZtLmRlZmF1bHRRdWVyeUZpbHRlcnMgPSB2bS5hcHBseUZpbHRlcnModm0uZGVmYXVsdFF1ZXJ5RmlsdGVycyk7XG4gICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmJlZm9yZVNlYXJjaCkgJiYgdm0uYmVmb3JlU2VhcmNoKHBhZ2UpID09PSBmYWxzZSkgcmV0dXJuIGZhbHNlO1xuXG4gICAgICBtb2RlbFNlcnZpY2UucGFnaW5hdGUodm0uZGVmYXVsdFF1ZXJ5RmlsdGVycykudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgdm0ucGFnaW5hdG9yLmNhbGNOdW1iZXJPZlBhZ2VzKHJlc3BvbnNlLnRvdGFsKTtcbiAgICAgICAgdm0ucmVzb3VyY2VzID0gcmVzcG9uc2UuaXRlbXM7XG5cbiAgICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5hZnRlclNlYXJjaCkpIHZtLmFmdGVyU2VhcmNoKHJlc3BvbnNlKTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWxpemEgYSBwZXNxdWlzYSBjb20gYmFzZSBub3MgZmlsdHJvcyBkZWZpbmlkb3NcbiAgICAgKlxuICAgICAqL1xuICAgIGZ1bmN0aW9uIG5vcm1hbFNlYXJjaCgpIHtcbiAgICAgIHZtLmRlZmF1bHRRdWVyeUZpbHRlcnMgPSB7fTtcblxuICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5hcHBseUZpbHRlcnMpKSB2bS5kZWZhdWx0UXVlcnlGaWx0ZXJzID0gdm0uYXBwbHlGaWx0ZXJzKHZtLmRlZmF1bHRRdWVyeUZpbHRlcnMpO1xuICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5iZWZvcmVTZWFyY2gpICYmIHZtLmJlZm9yZVNlYXJjaCgpID09PSBmYWxzZSkgcmV0dXJuIGZhbHNlO1xuXG4gICAgICBtb2RlbFNlcnZpY2UucXVlcnkodm0uZGVmYXVsdFF1ZXJ5RmlsdGVycykudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgdm0ucmVzb3VyY2VzID0gcmVzcG9uc2U7XG5cbiAgICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5hZnRlclNlYXJjaCkpIHZtLmFmdGVyU2VhcmNoKHJlc3BvbnNlKTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIExpbXBhIG8gZm9ybXVsw6FyaW9cbiAgICAgKi9cbiAgICBmdW5jdGlvbiBjbGVhbkZvcm0oZm9ybSkge1xuICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5iZWZvcmVDbGVhbikgJiYgdm0uYmVmb3JlQ2xlYW4oKSA9PT0gZmFsc2UpIHJldHVybiBmYWxzZTtcblxuICAgICAgdm0ucmVzb3VyY2UgPSBuZXcgbW9kZWxTZXJ2aWNlKCk7XG5cbiAgICAgIGlmIChhbmd1bGFyLmlzRGVmaW5lZChmb3JtKSkge1xuICAgICAgICBmb3JtLiRzZXRQcmlzdGluZSgpO1xuICAgICAgICBmb3JtLiRzZXRVbnRvdWNoZWQoKTtcbiAgICAgIH1cblxuICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5hZnRlckNsZWFuKSkgdm0uYWZ0ZXJDbGVhbigpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENhcnJlZ2Egbm8gZm9ybXVsw6FyaW8gbyByZWN1cnNvIHNlbGVjaW9uYWRvIHBhcmEgZWRpw6fDo29cbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSByZXNvdXJjZSByZWN1cnNvIHNlbGVjaW9uYWRvXG4gICAgICovXG4gICAgZnVuY3Rpb24gZWRpdChyZXNvdXJjZSkge1xuICAgICAgdm0uZ29UbygnZm9ybScpO1xuICAgICAgdm0ucmVzb3VyY2UgPSBuZXcgYW5ndWxhci5jb3B5KHJlc291cmNlKTtcblxuICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5hZnRlckVkaXQpKSB2bS5hZnRlckVkaXQoKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBTYWx2YSBvdSBhdHVhbGl6YSBvIHJlY3Vyc28gY29ycmVudGUgbm8gZm9ybXVsw6FyaW9cbiAgICAgKiBObyBjb21wb3J0YW1lbnRvIHBhZHLDo28gcmVkaXJlY2lvbmEgbyB1c3XDoXJpbyBwYXJhIHZpZXcgZGUgbGlzdGFnZW1cbiAgICAgKiBkZXBvaXMgZGEgZXhlY3XDp8Ojb1xuICAgICAqXG4gICAgICogQHJldHVybnNcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBzYXZlKGZvcm0pIHtcbiAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYmVmb3JlU2F2ZSkgJiYgdm0uYmVmb3JlU2F2ZSgpID09PSBmYWxzZSkgcmV0dXJuIGZhbHNlO1xuXG4gICAgICB2bS5yZXNvdXJjZS4kc2F2ZSgpLnRoZW4oZnVuY3Rpb24gKHJlc291cmNlKSB7XG4gICAgICAgIHZtLnJlc291cmNlID0gcmVzb3VyY2U7XG5cbiAgICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5hZnRlclNhdmUpKSB2bS5hZnRlclNhdmUocmVzb3VyY2UpO1xuXG4gICAgICAgIGlmICh2bS5kZWZhdWx0T3B0aW9ucy5yZWRpcmVjdEFmdGVyU2F2ZSkge1xuICAgICAgICAgIHZtLmNsZWFuRm9ybShmb3JtKTtcbiAgICAgICAgICB2bS5zZWFyY2godm0ucGFnaW5hdG9yLmN1cnJlbnRQYWdlKTtcbiAgICAgICAgICB2bS5nb1RvKCdsaXN0Jyk7XG4gICAgICAgIH1cblxuICAgICAgICBQclRvYXN0LnN1Y2Nlc3MoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5zYXZlU3VjY2VzcycpKTtcbiAgICAgIH0sIGZ1bmN0aW9uIChyZXNwb25zZURhdGEpIHtcbiAgICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5vblNhdmVFcnJvcikpIHZtLm9uU2F2ZUVycm9yKHJlc3BvbnNlRGF0YSk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZW1vdmUgbyByZWN1cnNvIGluZm9ybWFkby5cbiAgICAgKiBBbnRlcyBleGliZSB1bSBkaWFsb2dvIGRlIGNvbmZpcm1hw6fDo29cbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSByZXNvdXJjZSByZWN1cnNvIGVzY29saGlkb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIHJlbW92ZShyZXNvdXJjZSkge1xuICAgICAgdmFyIGNvbmZpZyA9IHtcbiAgICAgICAgdGl0bGU6ICR0cmFuc2xhdGUuaW5zdGFudCgnZGlhbG9nLmNvbmZpcm1UaXRsZScpLFxuICAgICAgICBkZXNjcmlwdGlvbjogJHRyYW5zbGF0ZS5pbnN0YW50KCdkaWFsb2cuY29uZmlybURlc2NyaXB0aW9uJylcbiAgICAgIH07XG5cbiAgICAgIFByRGlhbG9nLmNvbmZpcm0oY29uZmlnKS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5iZWZvcmVSZW1vdmUpICYmIHZtLmJlZm9yZVJlbW92ZShyZXNvdXJjZSkgPT09IGZhbHNlKSByZXR1cm4gZmFsc2U7XG5cbiAgICAgICAgcmVzb3VyY2UuJGRlc3Ryb3koKS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmFmdGVyUmVtb3ZlKSkgdm0uYWZ0ZXJSZW1vdmUocmVzb3VyY2UpO1xuXG4gICAgICAgICAgdm0uc2VhcmNoKCk7XG4gICAgICAgICAgUHJUb2FzdC5pbmZvKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMucmVtb3ZlU3VjY2VzcycpKTtcbiAgICAgICAgfSk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBBbHRlcm5hIGVudHJlIGEgdmlldyBkbyBmb3JtdWzDoXJpbyBlIGxpc3RhZ2VtXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gdmlld05hbWUgbm9tZSBkYSB2aWV3XG4gICAgICovXG4gICAgZnVuY3Rpb24gZ29Ubyh2aWV3TmFtZSkge1xuICAgICAgdm0udmlld0Zvcm0gPSBmYWxzZTtcblxuICAgICAgaWYgKHZpZXdOYW1lID09PSAnZm9ybScpIHtcbiAgICAgICAgdm0uY2xlYW5Gb3JtKCk7XG4gICAgICAgIHZtLnZpZXdGb3JtID0gdHJ1ZTtcbiAgICAgIH1cbiAgICB9XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb250cm9sbGVyKCdEYXNoYm9hcmRDb250cm9sbGVyJywgRGFzaGJvYXJkQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvKipcbiAgICogRGFzaGJvYXJkIENvbnRyb2xsZXJcbiAgICpcbiAgICogUGFpbmVsIGNvbSBwcmluY2lwYWlzIGluZGljYWRvcmVzXG4gICAqXG4gICAqL1xuICBmdW5jdGlvbiBEYXNoYm9hcmRDb250cm9sbGVyKCkge1xuICAgIC8vIENvbnRyb2xsZXIgdmF6aW8gc29tZW50ZSBwYXJhIHNlciBkZWZpbmlkbyBjb21vIHDDoWdpbmEgcHJpbmNpcGFsLlxuICAgIC8vIERldmUgc2VyIGlkZW50aWZpY2FkbyBlIGFkaWNpb25hZG8gZ3LDoWZpY29zXG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqXG4gICAqIEFycXVpdm8gZGUgY29uZmlndXJhw6fDo28gY29tIGFzIHJvdGFzIGVzcGVjw61maWNhcyBkbyBkYXNoYm9hcmRcbiAgICpcbiAgICogQHBhcmFtIHthbnl9ICRzdGF0ZVByb3ZpZGVyXG4gICAqIEBwYXJhbSB7YW55fSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZShHbG9iYWwuaG9tZVN0YXRlLCB7XG4gICAgICB1cmw6ICcvZGFzaGJvYXJkJyxcbiAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvZGFzaGJvYXJkL2Rhc2hib2FyZC5odG1sJyxcbiAgICAgIGNvbnRyb2xsZXI6ICdEYXNoYm9hcmRDb250cm9sbGVyIGFzIGRhc2hib2FyZEN0cmwnLFxuICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IHRydWUgfVxuICAgIH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKlxuICAgKiBBcnF1aXZvIGRlIGNvbmZpZ3VyYcOnw6NvIGNvbSBhcyByb3RhcyBlc3BlY8OtZmljYXMgZG8gcmVjdXJzbyB1c2VyXG4gICAqXG4gICAqIEBwYXJhbSB7YW55fSAkc3RhdGVQcm92aWRlclxuICAgKiBAcGFyYW0ge2FueX0gR2xvYmFsXG4gICAqL1xuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvdXRlcygkc3RhdGVQcm92aWRlciwgR2xvYmFsKSB7XG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ2FwcC5kaW5hbWljLXF1ZXJ5Jywge1xuICAgICAgdXJsOiAnL2NvbnN1bHRhcy1kaW5hbWljYXMnLFxuICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9kaW5hbWljLXF1ZXJ5cy9kaW5hbWljLXF1ZXJ5cy5odG1sJyxcbiAgICAgIGNvbnRyb2xsZXI6ICdEaW5hbWljUXVlcnlzQ29udHJvbGxlciBhcyBkaW5hbWljUXVlcnlDdHJsJyxcbiAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiB0cnVlLCBuZWVkUHJvZmlsZTogWydhZG1pbiddIH1cbiAgICB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5mYWN0b3J5KCdEaW5hbWljUXVlcnlTZXJ2aWNlJywgRGluYW1pY1F1ZXJ5U2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBEaW5hbWljUXVlcnlTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCdkaW5hbWljUXVlcnknLCB7XG4gICAgICAvKipcbiAgICAgICAqIGHDp8OjbyBhZGljaW9uYWRhIHBhcmEgcGVnYXIgdW1hIGxpc3RhIGRlIG1vZGVscyBleGlzdGVudGVzIG5vIHNlcnZpZG9yXG4gICAgICAgKi9cbiAgICAgIGFjdGlvbnM6IHtcbiAgICAgICAgZ2V0TW9kZWxzOiB7XG4gICAgICAgICAgbWV0aG9kOiAnR0VUJyxcbiAgICAgICAgICB1cmw6ICdtb2RlbHMnXG4gICAgICAgIH1cbiAgICAgIH0sXG4gICAgICBpbnN0YW5jZToge31cbiAgICB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbnRyb2xsZXIoJ0RpbmFtaWNRdWVyeXNDb250cm9sbGVyJywgRGluYW1pY1F1ZXJ5c0NvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gRGluYW1pY1F1ZXJ5c0NvbnRyb2xsZXIoJGNvbnRyb2xsZXIsIERpbmFtaWNRdWVyeVNlcnZpY2UsIGxvZGFzaCwgUHJUb2FzdCwgLy8gTk9TT05BUlxuICAkdHJhbnNsYXRlKSB7XG5cbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgLy9hY3Rpb25zXG4gICAgdm0ub25BY3RpdmF0ZSA9IG9uQWN0aXZhdGU7XG4gICAgdm0uYXBwbHlGaWx0ZXJzID0gYXBwbHlGaWx0ZXJzO1xuICAgIHZtLmxvYWRBdHRyaWJ1dGVzID0gbG9hZEF0dHJpYnV0ZXM7XG4gICAgdm0ubG9hZE9wZXJhdG9ycyA9IGxvYWRPcGVyYXRvcnM7XG4gICAgdm0uYWRkRmlsdGVyID0gYWRkRmlsdGVyO1xuICAgIHZtLmFmdGVyU2VhcmNoID0gYWZ0ZXJTZWFyY2g7XG4gICAgdm0ucnVuRmlsdGVyID0gcnVuRmlsdGVyO1xuICAgIHZtLmVkaXRGaWx0ZXIgPSBlZGl0RmlsdGVyO1xuICAgIHZtLmxvYWRNb2RlbHMgPSBsb2FkTW9kZWxzO1xuICAgIHZtLnJlbW92ZUZpbHRlciA9IHJlbW92ZUZpbHRlcjtcbiAgICB2bS5jbGVhciA9IGNsZWFyO1xuICAgIHZtLnJlc3RhcnQgPSByZXN0YXJ0O1xuXG4gICAgLy9oZXJkYSBvIGNvbXBvcnRhbWVudG8gYmFzZSBkbyBDUlVEXG4gICAgJGNvbnRyb2xsZXIoJ0NSVURDb250cm9sbGVyJywgeyB2bTogdm0sIG1vZGVsU2VydmljZTogRGluYW1pY1F1ZXJ5U2VydmljZSwgb3B0aW9uczoge1xuICAgICAgICBzZWFyY2hPbkluaXQ6IGZhbHNlXG4gICAgICB9IH0pO1xuXG4gICAgZnVuY3Rpb24gb25BY3RpdmF0ZSgpIHtcbiAgICAgIHZtLnJlc3RhcnQoKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBQcmVwYXJhIGUgYXBsaWNhIG9zIGZpbHRybyBxdWUgdsOjbyBzZXIgZW52aWFkb3MgcGFyYSBvIHNlcnZpw6dvXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gZGVmYXVsdFF1ZXJ5RmlsdGVyc1xuICAgICAqIEByZXR1cm5zXG4gICAgICovXG4gICAgZnVuY3Rpb24gYXBwbHlGaWx0ZXJzKGRlZmF1bHRRdWVyeUZpbHRlcnMpIHtcbiAgICAgIHZhciB3aGVyZSA9IHt9O1xuXG4gICAgICAvKipcbiAgICAgICAqIG8gc2VydmnDp28gZXNwZXJhIHVtIG9iamV0byBjb206XG4gICAgICAgKiAgbyBub21lIGRlIHVtIG1vZGVsXG4gICAgICAgKiAgdW1hIGxpc3RhIGRlIGZpbHRyb3NcbiAgICAgICAqL1xuICAgICAgaWYgKHZtLmFkZGVkRmlsdGVycy5sZW5ndGggPiAwKSB7XG4gICAgICAgIHZhciBhZGRlZEZpbHRlcnMgPSBhbmd1bGFyLmNvcHkodm0uYWRkZWRGaWx0ZXJzKTtcblxuICAgICAgICB3aGVyZS5tb2RlbCA9IHZtLmFkZGVkRmlsdGVyc1swXS5tb2RlbC5uYW1lO1xuXG4gICAgICAgIGZvciAodmFyIGluZGV4ID0gMDsgaW5kZXggPCBhZGRlZEZpbHRlcnMubGVuZ3RoOyBpbmRleCsrKSB7XG4gICAgICAgICAgdmFyIGZpbHRlciA9IGFkZGVkRmlsdGVyc1tpbmRleF07XG5cbiAgICAgICAgICBmaWx0ZXIubW9kZWwgPSBudWxsO1xuICAgICAgICAgIGZpbHRlci5hdHRyaWJ1dGUgPSBmaWx0ZXIuYXR0cmlidXRlLm5hbWU7XG4gICAgICAgICAgZmlsdGVyLm9wZXJhdG9yID0gZmlsdGVyLm9wZXJhdG9yLnZhbHVlO1xuICAgICAgICB9XG5cbiAgICAgICAgd2hlcmUuZmlsdGVycyA9IGFuZ3VsYXIudG9Kc29uKGFkZGVkRmlsdGVycyk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICB3aGVyZS5tb2RlbCA9IHZtLnF1ZXJ5RmlsdGVycy5tb2RlbC5uYW1lO1xuICAgICAgfVxuXG4gICAgICByZXR1cm4gYW5ndWxhci5leHRlbmQoZGVmYXVsdFF1ZXJ5RmlsdGVycywgd2hlcmUpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENhcnJlZ2EgdG9kb3Mgb3MgbW9kZWxzIGNyaWFkb3Mgbm8gc2Vydmlkb3IgY29tIHNldXMgYXRyaWJ1dG9zXG4gICAgICovXG4gICAgZnVuY3Rpb24gbG9hZE1vZGVscygpIHtcbiAgICAgIC8vUGVnYSB0b2RvcyBvcyBtb2RlbHMgZG8gc2VydmVyIGUgbW9udGEgdW1hIGxpc3RhIHBybyBDb21ib0JveFxuICAgICAgRGluYW1pY1F1ZXJ5U2VydmljZS5nZXRNb2RlbHMoKS50aGVuKGZ1bmN0aW9uIChkYXRhKSB7XG4gICAgICAgIHZtLm1vZGVscyA9IGRhdGE7XG4gICAgICAgIHZtLnF1ZXJ5RmlsdGVycy5tb2RlbCA9IHZtLm1vZGVsc1swXTtcbiAgICAgICAgdm0ubG9hZEF0dHJpYnV0ZXMoKTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENhcnJlZ2Egb3MgYXR0cmlidXRvcyBkbyBtb2RlbCBlc2NvbGhpZG9cbiAgICAgKi9cbiAgICBmdW5jdGlvbiBsb2FkQXR0cmlidXRlcygpIHtcbiAgICAgIHZtLmF0dHJpYnV0ZXMgPSB2bS5xdWVyeUZpbHRlcnMubW9kZWwuYXR0cmlidXRlcztcbiAgICAgIHZtLnF1ZXJ5RmlsdGVycy5hdHRyaWJ1dGUgPSB2bS5hdHRyaWJ1dGVzWzBdO1xuXG4gICAgICB2bS5sb2FkT3BlcmF0b3JzKCk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ2FycmVnYSBvcyBvcGVyYWRvcmVzIGVzcGVjaWZpY29zIHBhcmEgbyB0aXBvIGRvIGF0cmlidXRvXG4gICAgICovXG4gICAgZnVuY3Rpb24gbG9hZE9wZXJhdG9ycygpIHtcbiAgICAgIHZhciBvcGVyYXRvcnMgPSBbeyB2YWx1ZTogJz0nLCBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KCd2aWV3cy5maWVsZHMucXVlcnlEaW5hbWljLm9wZXJhdG9ycy5lcXVhbHMnKSB9LCB7IHZhbHVlOiAnPD4nLCBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KCd2aWV3cy5maWVsZHMucXVlcnlEaW5hbWljLm9wZXJhdG9ycy5kaWZlcmVudCcpIH1dO1xuXG4gICAgICBpZiAodm0ucXVlcnlGaWx0ZXJzLmF0dHJpYnV0ZS50eXBlLmluZGV4T2YoJ3ZhcnlpbmcnKSAhPT0gLTEpIHtcbiAgICAgICAgb3BlcmF0b3JzLnB1c2goeyB2YWx1ZTogJ2hhcycsXG4gICAgICAgICAgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudCgndmlld3MuZmllbGRzLnF1ZXJ5RGluYW1pYy5vcGVyYXRvcnMuY29udGVpbnMnKSB9KTtcbiAgICAgICAgb3BlcmF0b3JzLnB1c2goeyB2YWx1ZTogJ3N0YXJ0V2l0aCcsXG4gICAgICAgICAgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudCgndmlld3MuZmllbGRzLnF1ZXJ5RGluYW1pYy5vcGVyYXRvcnMuc3RhcnRXaXRoJykgfSk7XG4gICAgICAgIG9wZXJhdG9ycy5wdXNoKHsgdmFsdWU6ICdlbmRXaXRoJyxcbiAgICAgICAgICBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KCd2aWV3cy5maWVsZHMucXVlcnlEaW5hbWljLm9wZXJhdG9ycy5maW5pc2hXaXRoJykgfSk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBvcGVyYXRvcnMucHVzaCh7IHZhbHVlOiAnPicsXG4gICAgICAgICAgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudCgndmlld3MuZmllbGRzLnF1ZXJ5RGluYW1pYy5vcGVyYXRvcnMuYmlnZ2VyVGhhbicpIH0pO1xuICAgICAgICBvcGVyYXRvcnMucHVzaCh7IHZhbHVlOiAnPj0nLFxuICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLmVxdWFsc09yQmlnZ2VyVGhhbicpIH0pO1xuICAgICAgICBvcGVyYXRvcnMucHVzaCh7IHZhbHVlOiAnPCcsXG4gICAgICAgICAgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudCgndmlld3MuZmllbGRzLnF1ZXJ5RGluYW1pYy5vcGVyYXRvcnMubGVzc1RoYW4nKSB9KTtcbiAgICAgICAgb3BlcmF0b3JzLnB1c2goeyB2YWx1ZTogJzw9JyxcbiAgICAgICAgICBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KCd2aWV3cy5maWVsZHMucXVlcnlEaW5hbWljLm9wZXJhdG9ycy5lcXVhbHNPckxlc3NUaGFuJykgfSk7XG4gICAgICB9XG5cbiAgICAgIHZtLm9wZXJhdG9ycyA9IG9wZXJhdG9ycztcbiAgICAgIHZtLnF1ZXJ5RmlsdGVycy5vcGVyYXRvciA9IHZtLm9wZXJhdG9yc1swXTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBBZGljaW9uYS9lZGl0YSB1bSBmaWx0cm9cbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSBmb3JtIGVsZW1lbnRvIGh0bWwgZG8gZm9ybXVsw6FyaW8gcGFyYSB2YWxpZGHDp8O1ZXNcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBhZGRGaWx0ZXIoZm9ybSkge1xuICAgICAgaWYgKGFuZ3VsYXIuaXNVbmRlZmluZWQodm0ucXVlcnlGaWx0ZXJzLnZhbHVlKSB8fCB2bS5xdWVyeUZpbHRlcnMudmFsdWUgPT09ICcnKSB7XG4gICAgICAgIFByVG9hc3QuZXJyb3IoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy52YWxpZGF0ZS5maWVsZFJlcXVpcmVkJywgeyBmaWVsZDogJ3ZhbG9yJyB9KSk7XG4gICAgICAgIHJldHVybjtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIGlmICh2bS5pbmRleCA8IDApIHtcbiAgICAgICAgICB2bS5hZGRlZEZpbHRlcnMucHVzaChhbmd1bGFyLmNvcHkodm0ucXVlcnlGaWx0ZXJzKSk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgdm0uYWRkZWRGaWx0ZXJzW3ZtLmluZGV4XSA9IGFuZ3VsYXIuY29weSh2bS5xdWVyeUZpbHRlcnMpO1xuICAgICAgICAgIHZtLmluZGV4ID0gLTE7XG4gICAgICAgIH1cblxuICAgICAgICAvL3JlaW5pY2lhIG8gZm9ybXVsw6FyaW8gZSBhcyB2YWxpZGHDp8O1ZXMgZXhpc3RlbnRlc1xuICAgICAgICB2bS5xdWVyeUZpbHRlcnMgPSB7fTtcbiAgICAgICAgZm9ybS4kc2V0UHJpc3RpbmUoKTtcbiAgICAgICAgZm9ybS4kc2V0VW50b3VjaGVkKCk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhbGl6YSBhIHBlc3F1aXNhIHRlbmRvIG9zIGZpbHRyb3MgY29tbyBwYXLDom1ldHJvc1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIHJ1bkZpbHRlcigpIHtcbiAgICAgIHZtLnNlYXJjaCh2bS5wYWdpbmF0b3IuY3VycmVudFBhZ2UpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEdhdGlsaG8gYWNpb25hZG8gZGVwb2lzIGRhIHBlc3F1aXNhIHJlc3BvbnPDoXZlbCBwb3IgaWRlbnRpZmljYXIgb3MgYXRyaWJ1dG9zXG4gICAgICogY29udGlkb3Mgbm9zIGVsZW1lbnRvcyByZXN1bHRhbnRlcyBkYSBidXNjYVxuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IGRhdGEgZGFkb3MgcmVmZXJlbnRlIGFvIHJldG9ybm8gZGEgcmVxdWlzacOnw6NvXG4gICAgICovXG4gICAgZnVuY3Rpb24gYWZ0ZXJTZWFyY2goZGF0YSkge1xuICAgICAgdmFyIGtleXMgPSBkYXRhLml0ZW1zLmxlbmd0aCA+IDAgPyBPYmplY3Qua2V5cyhkYXRhLml0ZW1zWzBdKSA6IFtdO1xuXG4gICAgICAvL3JldGlyYSB0b2RvcyBvcyBhdHJpYnV0b3MgcXVlIGNvbWXDp2FtIGNvbSAkLlxuICAgICAgLy9Fc3NlcyBhdHJpYnV0b3Mgc8OjbyBhZGljaW9uYWRvcyBwZWxvIHNlcnZpw6dvIGUgbsOjbyBkZXZlIGFwYXJlY2VyIG5hIGxpc3RhZ2VtXG4gICAgICB2bS5rZXlzID0gbG9kYXNoLmZpbHRlcihrZXlzLCBmdW5jdGlvbiAoa2V5KSB7XG4gICAgICAgIHJldHVybiAhbG9kYXNoLnN0YXJ0c1dpdGgoa2V5LCAnJCcpO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ29sb2FjYSBubyBmb3JtdWzDoXJpbyBvIGZpbHRybyBlc2NvbGhpZG8gcGFyYSBlZGnDp8Ojb1xuICAgICAqIEBwYXJhbSB7YW55fSAkaW5kZXggaW5kaWNlIG5vIGFycmF5IGRvIGZpbHRybyBlc2NvbGhpZG9cbiAgICAgKi9cbiAgICBmdW5jdGlvbiBlZGl0RmlsdGVyKCRpbmRleCkge1xuICAgICAgdm0uaW5kZXggPSAkaW5kZXg7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMgPSB2bS5hZGRlZEZpbHRlcnNbJGluZGV4XTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZW1vdmUgbyBmaWx0cm8gZXNjb2xoaWRvXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gJGluZGV4IGluZGljZSBubyBhcnJheSBkbyBmaWx0cm8gZXNjb2xoaWRvXG4gICAgICovXG4gICAgZnVuY3Rpb24gcmVtb3ZlRmlsdGVyKCRpbmRleCkge1xuICAgICAgdm0uYWRkZWRGaWx0ZXJzLnNwbGljZSgkaW5kZXgpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIExpbXBhIG8gZm9ybXVsw6FyaW8gY29ycmVudGVcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBjbGVhcigpIHtcbiAgICAgIC8vZ3VhcmRhIG8gaW5kaWNlIGRvIHJlZ2lzdHJvIHF1ZSBlc3TDoSBzZW5kbyBlZGl0YWRvXG4gICAgICB2bS5pbmRleCA9IC0xO1xuICAgICAgLy92aW5jdWxhZG8gYW9zIGNhbXBvcyBkbyBmb3JtdWzDoXJpb1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0ge307XG5cbiAgICAgIGlmICh2bS5tb2RlbHMpIHZtLnF1ZXJ5RmlsdGVycy5tb2RlbCA9IHZtLm1vZGVsc1swXTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWluaWNpYSBhIGNvbnN0cnXDp8OjbyBkYSBxdWVyeSBsaW1wYW5kbyB0dWRvXG4gICAgICpcbiAgICAgKi9cbiAgICBmdW5jdGlvbiByZXN0YXJ0KCkge1xuICAgICAgLy9ndWFyZGEgYXRyaWJ1dG9zIGRvIHJlc3VsdGFkbyBkYSBidXNjYSBjb3JyZW50ZVxuICAgICAgdm0ua2V5cyA9IFtdO1xuXG4gICAgICAvL2d1YXJkYSBvcyBmaWx0cm9zIGFkaWNpb25hZG9zXG4gICAgICB2bS5hZGRlZEZpbHRlcnMgPSBbXTtcbiAgICAgIHZtLmNsZWFyKCk7XG4gICAgICB2bS5sb2FkTW9kZWxzKCk7XG4gICAgfVxuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmFjdG9yeSgnbGFuZ3VhZ2VMb2FkZXInLCBMYW5ndWFnZUxvYWRlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBMYW5ndWFnZUxvYWRlcigkcSwgU3VwcG9ydFNlcnZpY2UsICRsb2csICRpbmplY3Rvcikge1xuICAgIHZhciBzZXJ2aWNlID0gdGhpcztcblxuICAgIHNlcnZpY2UudHJhbnNsYXRlID0gZnVuY3Rpb24gKGxvY2FsZSkge1xuICAgICAgcmV0dXJuIHtcbiAgICAgICAgZ2xvYmFsOiAkaW5qZWN0b3IuZ2V0KGxvY2FsZSArICcuaTE4bi5nbG9iYWwnKSxcbiAgICAgICAgdmlld3M6ICRpbmplY3Rvci5nZXQobG9jYWxlICsgJy5pMThuLnZpZXdzJyksXG4gICAgICAgIGF0dHJpYnV0ZXM6ICRpbmplY3Rvci5nZXQobG9jYWxlICsgJy5pMThuLmF0dHJpYnV0ZXMnKSxcbiAgICAgICAgZGlhbG9nOiAkaW5qZWN0b3IuZ2V0KGxvY2FsZSArICcuaTE4bi5kaWFsb2cnKSxcbiAgICAgICAgbWVzc2FnZXM6ICRpbmplY3Rvci5nZXQobG9jYWxlICsgJy5pMThuLm1lc3NhZ2VzJyksXG4gICAgICAgIG1vZGVsczogJGluamVjdG9yLmdldChsb2NhbGUgKyAnLmkxOG4ubW9kZWxzJylcbiAgICAgIH07XG4gICAgfTtcblxuICAgIC8vIHJldHVybiBsb2FkZXJGblxuICAgIHJldHVybiBmdW5jdGlvbiAob3B0aW9ucykge1xuICAgICAgJGxvZy5pbmZvKCdDYXJyZWdhbmRvIG8gY29udGV1ZG8gZGEgbGluZ3VhZ2VtICcgKyBvcHRpb25zLmtleSk7XG5cbiAgICAgIHZhciBkZWZlcnJlZCA9ICRxLmRlZmVyKCk7XG5cbiAgICAgIC8vQ2FycmVnYSBhcyBsYW5ncyBxdWUgcHJlY2lzYW0gZSBlc3TDo28gbm8gc2Vydmlkb3IgcGFyYSBuw6NvIHByZWNpc2FyIHJlcGV0aXIgYXF1aVxuICAgICAgU3VwcG9ydFNlcnZpY2UubGFuZ3MoKS50aGVuKGZ1bmN0aW9uIChsYW5ncykge1xuICAgICAgICAvL01lcmdlIGNvbSBvcyBsYW5ncyBkZWZpbmlkb3Mgbm8gc2Vydmlkb3JcbiAgICAgICAgdmFyIGRhdGEgPSBhbmd1bGFyLm1lcmdlKHNlcnZpY2UudHJhbnNsYXRlKG9wdGlvbnMua2V5KSwgbGFuZ3MpO1xuXG4gICAgICAgIHJldHVybiBkZWZlcnJlZC5yZXNvbHZlKGRhdGEpO1xuICAgICAgfSwgZnVuY3Rpb24gKCkge1xuICAgICAgICByZXR1cm4gZGVmZXJyZWQucmVzb2x2ZShzZXJ2aWNlLnRyYW5zbGF0ZShvcHRpb25zLmtleSkpO1xuICAgICAgfSk7XG5cbiAgICAgIHJldHVybiBkZWZlcnJlZC5wcm9taXNlO1xuICAgIH07XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5maWx0ZXIoJ3RBdHRyJywgdEF0dHIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gdEF0dHIoJGZpbHRlcikge1xuICAgIC8qKlxuICAgICAqIEZpbHRybyBwYXJhIHRyYWR1w6fDo28gZGUgdW0gYXRyaWJ1dG8gZGUgdW0gbW9kZWxcbiAgICAgKiBcbiAgICAgKiBAcGFyYW0ge2FueX0gbmFtZSBub21lIGRvIGF0cmlidXRvXG4gICAgICogQHJldHVybnMgbyBub21lIGRvIGF0cmlidXRvIHRyYWR1emlkbyBjYXNvIGVuY29udHJlIHNlIG7Do28gbyBub21lIHBhc3NhZG8gcG9yIHBhcmFtZXRyb1xuICAgICAqL1xuICAgIHJldHVybiBmdW5jdGlvbiAobmFtZSkge1xuICAgICAgdmFyIGtleSA9ICdhdHRyaWJ1dGVzLicgKyBuYW1lO1xuICAgICAgdmFyIHRyYW5zbGF0ZSA9ICRmaWx0ZXIoJ3RyYW5zbGF0ZScpKGtleSk7XG5cbiAgICAgIHJldHVybiB0cmFuc2xhdGUgPT09IGtleSA/IG5hbWUgOiB0cmFuc2xhdGU7XG4gICAgfTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZpbHRlcigndEJyZWFkY3J1bWInLCB0QnJlYWRjcnVtYik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiB0QnJlYWRjcnVtYigkZmlsdGVyKSB7XG4gICAgLyoqXG4gICAgICogRmlsdHJvIHBhcmEgdHJhZHXDp8OjbyBkbyBicmVhZGNydW1iICh0aXR1bG8gZGEgdGVsYSBjb20gcmFzdHJlaW8pXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gaWQgY2hhdmUgY29tIG8gbm9tZSBkbyBzdGF0ZSByZWZlcmVudGUgdGVsYVxuICAgICAqIEByZXR1cm5zIGEgdHJhZHXDp8OjbyBjYXNvIGVuY29udHJlIHNlIG7Do28gbyBpZCBwYXNzYWRvIHBvciBwYXJhbWV0cm9cbiAgICAgKi9cbiAgICByZXR1cm4gZnVuY3Rpb24gKGlkKSB7XG4gICAgICAvL3BlZ2EgYSBzZWd1bmRhIHBhcnRlIGRvIG5vbWUgZG8gc3RhdGUsIHJldGlyYW5kbyBhIHBhcnRlIGFic3RyYXRhIChhcHAuKVxuICAgICAgdmFyIGtleSA9ICd2aWV3cy5icmVhZGNydW1icy4nICsgaWQuc3BsaXQoJy4nKVsxXTtcbiAgICAgIHZhciB0cmFuc2xhdGUgPSAkZmlsdGVyKCd0cmFuc2xhdGUnKShrZXkpO1xuXG4gICAgICByZXR1cm4gdHJhbnNsYXRlID09PSBrZXkgPyBpZCA6IHRyYW5zbGF0ZTtcbiAgICB9O1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmlsdGVyKCd0TW9kZWwnLCB0TW9kZWwpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gdE1vZGVsKCRmaWx0ZXIpIHtcbiAgICAvKipcbiAgICAgKiBGaWx0cm8gcGFyYSB0cmFkdcOnw6NvIGRlIHVtIGF0cmlidXRvIGRlIHVtIG1vZGVsXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gbmFtZSBub21lIGRvIGF0cmlidXRvXG4gICAgICogQHJldHVybnMgbyBub21lIGRvIGF0cmlidXRvIHRyYWR1emlkbyBjYXNvIGVuY29udHJlIHNlIG7Do28gbyBub21lIHBhc3NhZG8gcG9yIHBhcmFtZXRyb1xuICAgICAqL1xuICAgIHJldHVybiBmdW5jdGlvbiAobmFtZSkge1xuICAgICAgdmFyIGtleSA9ICdtb2RlbHMuJyArIG5hbWUudG9Mb3dlckNhc2UoKTtcbiAgICAgIHZhciB0cmFuc2xhdGUgPSAkZmlsdGVyKCd0cmFuc2xhdGUnKShrZXkpO1xuXG4gICAgICByZXR1cm4gdHJhbnNsYXRlID09PSBrZXkgPyBuYW1lIDogdHJhbnNsYXRlO1xuICAgIH07XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykucnVuKGF1dGhlbnRpY2F0aW9uTGlzdGVuZXIpO1xuXG4gIC8qKlxuICAgKiBMaXN0ZW4gYWxsIHN0YXRlIChwYWdlKSBjaGFuZ2VzLiBFdmVyeSB0aW1lIGEgc3RhdGUgY2hhbmdlIG5lZWQgdG8gdmVyaWZ5IHRoZSB1c2VyIGlzIGF1dGhlbnRpY2F0ZWQgb3Igbm90IHRvXG4gICAqIHJlZGlyZWN0IHRvIGNvcnJlY3QgcGFnZS4gV2hlbiBhIHVzZXIgY2xvc2UgdGhlIGJyb3dzZXIgd2l0aG91dCBsb2dvdXQsIHdoZW4gaGltIHJlb3BlbiB0aGUgYnJvd3NlciB0aGlzIGV2ZW50XG4gICAqIHJlYXV0aGVudGljYXRlIHRoZSB1c2VyIHdpdGggdGhlIHBlcnNpc3RlbnQgdG9rZW4gb2YgdGhlIGxvY2FsIHN0b3JhZ2UuXG4gICAqXG4gICAqIFdlIGRvbid0IGNoZWNrIGlmIHRoZSB0b2tlbiBpcyBleHBpcmVkIG9yIG5vdCBpbiB0aGUgcGFnZSBjaGFuZ2UsIGJlY2F1c2UgaXMgZ2VuZXJhdGUgYW4gdW5lY2Vzc2FyeSBvdmVyaGVhZC5cbiAgICogSWYgdGhlIHRva2VuIGlzIGV4cGlyZWQgd2hlbiB0aGUgdXNlciB0cnkgdG8gY2FsbCB0aGUgZmlyc3QgYXBpIHRvIGdldCBkYXRhLCBoaW0gd2lsbCBiZSBsb2dvZmYgYW5kIHJlZGlyZWN0XG4gICAqIHRvIGxvZ2luIHBhZ2UuXG4gICAqXG4gICAqIEBwYXJhbSAkcm9vdFNjb3BlXG4gICAqIEBwYXJhbSAkc3RhdGVcbiAgICogQHBhcmFtICRzdGF0ZVBhcmFtc1xuICAgKiBAcGFyYW0gQXV0aFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBhdXRoZW50aWNhdGlvbkxpc3RlbmVyKCRyb290U2NvcGUsICRzdGF0ZSwgR2xvYmFsLCBBdXRoLCBQclRvYXN0LCAvLyBOT1NPTkFSXG4gICR0cmFuc2xhdGUpIHtcblxuICAgIC8vb25seSB3aGVuIGFwcGxpY2F0aW9uIHN0YXJ0IGNoZWNrIGlmIHRoZSBleGlzdGVudCB0b2tlbiBzdGlsbCB2YWxpZFxuICAgIEF1dGgucmVtb3RlVmFsaWRhdGVUb2tlbigpLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgLy9pZiB0aGUgdG9rZW4gaXMgdmFsaWQgY2hlY2sgaWYgZXhpc3RzIHRoZSB1c2VyIGJlY2F1c2UgdGhlIGJyb3dzZXIgY291bGQgYmUgY2xvc2VkXG4gICAgICAvL2FuZCB0aGUgdXNlciBkYXRhIGlzbid0IGluIG1lbW9yeVxuICAgICAgaWYgKEF1dGguY3VycmVudFVzZXIgPT09IG51bGwpIHtcbiAgICAgICAgQXV0aC51cGRhdGVDdXJyZW50VXNlcihhbmd1bGFyLmZyb21Kc29uKGxvY2FsU3RvcmFnZS5nZXRJdGVtKCd1c2VyJykpKTtcbiAgICAgIH1cbiAgICB9KTtcblxuICAgIC8vQ2hlY2sgaWYgdGhlIHRva2VuIHN0aWxsIHZhbGlkLlxuICAgICRyb290U2NvcGUuJG9uKCckc3RhdGVDaGFuZ2VTdGFydCcsIGZ1bmN0aW9uIChldmVudCwgdG9TdGF0ZSkge1xuICAgICAgaWYgKHRvU3RhdGUuZGF0YS5uZWVkQXV0aGVudGljYXRpb24gfHwgdG9TdGF0ZS5kYXRhLm5lZWRQcm9maWxlKSB7XG4gICAgICAgIC8vZG9udCB0cmFpdCB0aGUgc3VjY2VzcyBibG9jayBiZWNhdXNlIGFscmVhZHkgZGlkIGJ5IHRva2VuIGludGVyY2VwdG9yXG4gICAgICAgIEF1dGgucmVtb3RlVmFsaWRhdGVUb2tlbigpLmNhdGNoKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICBQclRvYXN0Lndhcm4oJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5sb2dpbi5sb2dvdXRJbmFjdGl2ZScpKTtcblxuICAgICAgICAgIGlmICh0b1N0YXRlLm5hbWUgIT09IEdsb2JhbC5sb2dpblN0YXRlKSB7XG4gICAgICAgICAgICAkc3RhdGUuZ28oR2xvYmFsLmxvZ2luU3RhdGUpO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIGV2ZW50LnByZXZlbnREZWZhdWx0KCk7XG4gICAgICAgIH0pO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgLy9pZiB0aGUgdXNlIGlzIGF1dGhlbnRpY2F0ZWQgYW5kIG5lZWQgdG8gZW50ZXIgaW4gbG9naW4gcGFnZVxuICAgICAgICAvL2hpbSB3aWxsIGJlIHJlZGlyZWN0ZWQgdG8gaG9tZSBwYWdlXG4gICAgICAgIGlmICh0b1N0YXRlLm5hbWUgPT09IEdsb2JhbC5sb2dpblN0YXRlICYmIEF1dGguYXV0aGVudGljYXRlZCgpKSB7XG4gICAgICAgICAgJHN0YXRlLmdvKEdsb2JhbC5ob21lU3RhdGUpO1xuICAgICAgICAgIGV2ZW50LnByZXZlbnREZWZhdWx0KCk7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5ydW4oYXV0aG9yaXphdGlvbkxpc3RlbmVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIGF1dGhvcml6YXRpb25MaXN0ZW5lcigkcm9vdFNjb3BlLCAkc3RhdGUsIEdsb2JhbCwgQXV0aCkge1xuICAgIC8qKlxuICAgICAqIEEgY2FkYSBtdWRhbsOnYSBkZSBlc3RhZG8gKFwicMOhZ2luYVwiKSB2ZXJpZmljYSBzZSBvIHVzdcOhcmlvIHRlbSBvIHBlcmZpbFxuICAgICAqIG5lY2Vzc8OhcmlvIHBhcmEgbyBhY2Vzc28gYSBtZXNtYVxuICAgICAqL1xuICAgICRyb290U2NvcGUuJG9uKCckc3RhdGVDaGFuZ2VTdGFydCcsIGZ1bmN0aW9uIChldmVudCwgdG9TdGF0ZSkge1xuICAgICAgaWYgKHRvU3RhdGUuZGF0YSAmJiB0b1N0YXRlLmRhdGEubmVlZEF1dGhlbnRpY2F0aW9uICYmIHRvU3RhdGUuZGF0YS5uZWVkUHJvZmlsZSAmJiBBdXRoLmF1dGhlbnRpY2F0ZWQoKSAmJiAhQXV0aC5jdXJyZW50VXNlci5oYXNQcm9maWxlKHRvU3RhdGUuZGF0YS5uZWVkUHJvZmlsZSwgdG9TdGF0ZS5kYXRhLmFsbFByb2ZpbGVzKSkge1xuXG4gICAgICAgICRzdGF0ZS5nbyhHbG9iYWwubm90QXV0aG9yaXplZFN0YXRlKTtcbiAgICAgICAgZXZlbnQucHJldmVudERlZmF1bHQoKTtcbiAgICAgIH1cbiAgICB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25maWcoc3Bpbm5lckludGVyY2VwdG9yKTtcblxuICBmdW5jdGlvbiBzcGlubmVySW50ZXJjZXB0b3IoJGh0dHBQcm92aWRlciwgJHByb3ZpZGUpIHtcbiAgICAvKipcbiAgICAgKiBFc3RlIGludGVyY2VwdG9yIMOpIHJlc3BvbnPDoXZlbCBwb3IgbW9zdHJhciBlIGVzY29uZGVyIG9cbiAgICAgKiBjb21wb25lbnRlIFByU3Bpbm5lciBzZW1wcmUgcXVlIHVtYSByZXF1aXNpw6fDo28gYWpheFxuICAgICAqIGluaWNpYXIgZSBmaW5hbGl6YXIuXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gJHFcbiAgICAgKiBAcGFyYW0ge2FueX0gJGluamVjdG9yXG4gICAgICogQHJldHVybnNcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBzaG93SGlkZVNwaW5uZXIoJHEsICRpbmplY3Rvcikge1xuICAgICAgcmV0dXJuIHtcbiAgICAgICAgcmVxdWVzdDogZnVuY3Rpb24gcmVxdWVzdChjb25maWcpIHtcbiAgICAgICAgICAkaW5qZWN0b3IuZ2V0KCdQclNwaW5uZXInKS5zaG93KCk7XG5cbiAgICAgICAgICByZXR1cm4gY29uZmlnO1xuICAgICAgICB9LFxuXG4gICAgICAgIHJlc3BvbnNlOiBmdW5jdGlvbiByZXNwb25zZShfcmVzcG9uc2UpIHtcbiAgICAgICAgICAkaW5qZWN0b3IuZ2V0KCdQclNwaW5uZXInKS5oaWRlKCk7XG5cbiAgICAgICAgICByZXR1cm4gX3Jlc3BvbnNlO1xuICAgICAgICB9LFxuXG4gICAgICAgIHJlc3BvbnNlRXJyb3I6IGZ1bmN0aW9uIHJlc3BvbnNlRXJyb3IocmVqZWN0aW9uKSB7XG4gICAgICAgICAgJGluamVjdG9yLmdldCgnUHJTcGlubmVyJykuaGlkZSgpO1xuXG4gICAgICAgICAgcmV0dXJuICRxLnJlamVjdChyZWplY3Rpb24pO1xuICAgICAgICB9XG4gICAgICB9O1xuICAgIH1cblxuICAgIC8vIERlZmluZSB1bWEgZmFjdG9yeSBwYXJhIG8gJGh0dHBJbnRlcmNlcHRvclxuICAgICRwcm92aWRlLmZhY3RvcnkoJ3Nob3dIaWRlU3Bpbm5lcicsIHNob3dIaWRlU3Bpbm5lcik7XG5cbiAgICAvLyBBZGljaW9uYSBhIGZhY3Rvcnkgbm8gYXJyYXkgZGUgaW50ZXJjZXB0b3JzIGRvICRodHRwXG4gICAgJGh0dHBQcm92aWRlci5pbnRlcmNlcHRvcnMucHVzaCgnc2hvd0hpZGVTcGlubmVyJyk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbi8qZXNsaW50IGFuZ3VsYXIvbW9kdWxlLWdldHRlcjogMCovXG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29uZmlnKHRva2VuSW50ZXJjZXB0b3IpO1xuXG4gIC8qKlxuICAgKiBJbnRlcmNlcHQgYWxsIHJlc3BvbnNlIChzdWNjZXNzIG9yIGVycm9yKSB0byB2ZXJpZnkgdGhlIHJldHVybmVkIHRva2VuXG4gICAqXG4gICAqIEBwYXJhbSAkaHR0cFByb3ZpZGVyXG4gICAqIEBwYXJhbSAkcHJvdmlkZVxuICAgKiBAcGFyYW0gR2xvYmFsXG4gICAqL1xuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHRva2VuSW50ZXJjZXB0b3IoJGh0dHBQcm92aWRlciwgJHByb3ZpZGUsIEdsb2JhbCkge1xuXG4gICAgZnVuY3Rpb24gcmVkaXJlY3RXaGVuU2VydmVyTG9nZ2VkT3V0KCRxLCAkaW5qZWN0b3IpIHtcbiAgICAgIHJldHVybiB7XG4gICAgICAgIHJlcXVlc3Q6IGZ1bmN0aW9uIHJlcXVlc3QoY29uZmlnKSB7XG4gICAgICAgICAgdmFyIHRva2VuID0gJGluamVjdG9yLmdldCgnQXV0aCcpLmdldFRva2VuKCk7XG5cbiAgICAgICAgICBpZiAodG9rZW4pIHtcbiAgICAgICAgICAgIGNvbmZpZy5oZWFkZXJzWydBdXRob3JpemF0aW9uJ10gPSAnQmVhcmVyICcgKyB0b2tlbjtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICByZXR1cm4gY29uZmlnO1xuICAgICAgICB9LFxuICAgICAgICByZXNwb25zZTogZnVuY3Rpb24gcmVzcG9uc2UoX3Jlc3BvbnNlKSB7XG4gICAgICAgICAgLy8gZ2V0IGEgbmV3IHJlZnJlc2ggdG9rZW4gdG8gdXNlIGluIHRoZSBuZXh0IHJlcXVlc3RcbiAgICAgICAgICB2YXIgdG9rZW4gPSBfcmVzcG9uc2UuaGVhZGVycygnQXV0aG9yaXphdGlvbicpO1xuXG4gICAgICAgICAgaWYgKHRva2VuKSB7XG4gICAgICAgICAgICAkaW5qZWN0b3IuZ2V0KCdBdXRoJykuc2V0VG9rZW4odG9rZW4uc3BsaXQoJyAnKVsxXSk7XG4gICAgICAgICAgfVxuICAgICAgICAgIHJldHVybiBfcmVzcG9uc2U7XG4gICAgICAgIH0sXG4gICAgICAgIHJlc3BvbnNlRXJyb3I6IGZ1bmN0aW9uIHJlc3BvbnNlRXJyb3IocmVqZWN0aW9uKSB7XG4gICAgICAgICAgLy8gSW5zdGVhZCBvZiBjaGVja2luZyBmb3IgYSBzdGF0dXMgY29kZSBvZiA0MDAgd2hpY2ggbWlnaHQgYmUgdXNlZFxuICAgICAgICAgIC8vIGZvciBvdGhlciByZWFzb25zIGluIExhcmF2ZWwsIHdlIGNoZWNrIGZvciB0aGUgc3BlY2lmaWMgcmVqZWN0aW9uXG4gICAgICAgICAgLy8gcmVhc29ucyB0byB0ZWxsIHVzIGlmIHdlIG5lZWQgdG8gcmVkaXJlY3QgdG8gdGhlIGxvZ2luIHN0YXRlXG4gICAgICAgICAgdmFyIHJlamVjdGlvblJlYXNvbnMgPSBbJ3Rva2VuX25vdF9wcm92aWRlZCcsICd0b2tlbl9leHBpcmVkJywgJ3Rva2VuX2Fic2VudCcsICd0b2tlbl9pbnZhbGlkJ107XG5cbiAgICAgICAgICB2YXIgdG9rZW5FcnJvciA9IGZhbHNlO1xuXG4gICAgICAgICAgYW5ndWxhci5mb3JFYWNoKHJlamVjdGlvblJlYXNvbnMsIGZ1bmN0aW9uICh2YWx1ZSkge1xuICAgICAgICAgICAgaWYgKHJlamVjdGlvbi5kYXRhICYmIHJlamVjdGlvbi5kYXRhLmVycm9yID09PSB2YWx1ZSkge1xuICAgICAgICAgICAgICB0b2tlbkVycm9yID0gdHJ1ZTtcblxuICAgICAgICAgICAgICAkaW5qZWN0b3IuZ2V0KCdBdXRoJykubG9nb3V0KCkudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgdmFyICRzdGF0ZSA9ICRpbmplY3Rvci5nZXQoJyRzdGF0ZScpO1xuXG4gICAgICAgICAgICAgICAgLy8gaW4gY2FzZSBtdWx0aXBsZSBhamF4IHJlcXVlc3QgZmFpbCBhdCBzYW1lIHRpbWUgYmVjYXVzZSB0b2tlbiBwcm9ibGVtcyxcbiAgICAgICAgICAgICAgICAvLyBvbmx5IHRoZSBmaXJzdCB3aWxsIHJlZGlyZWN0XG4gICAgICAgICAgICAgICAgaWYgKCEkc3RhdGUuaXMoR2xvYmFsLmxvZ2luU3RhdGUpKSB7XG4gICAgICAgICAgICAgICAgICAkc3RhdGUuZ28oR2xvYmFsLmxvZ2luU3RhdGUpO1xuXG4gICAgICAgICAgICAgICAgICAvL2Nsb3NlIGFueSBkaWFsb2cgdGhhdCBpcyBvcGVuZWRcbiAgICAgICAgICAgICAgICAgICRpbmplY3Rvci5nZXQoJ1ByRGlhbG9nJykuY2xvc2UoKTtcblxuICAgICAgICAgICAgICAgICAgZXZlbnQucHJldmVudERlZmF1bHQoKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgfVxuICAgICAgICAgIH0pO1xuXG4gICAgICAgICAgLy9kZWZpbmUgZGF0YSB0byBlbXB0eSBiZWNhdXNlIGFscmVhZHkgc2hvdyBQclRvYXN0IHRva2VuIG1lc3NhZ2VcbiAgICAgICAgICBpZiAodG9rZW5FcnJvcikge1xuICAgICAgICAgICAgcmVqZWN0aW9uLmRhdGEgPSB7fTtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHJlamVjdGlvbi5oZWFkZXJzKSkge1xuICAgICAgICAgICAgLy8gbWFueSBzZXJ2ZXJzIGVycm9ycyAoYnVzaW5lc3MpIGFyZSBpbnRlcmNlcHQgaGVyZSBidXQgZ2VuZXJhdGVkIGEgbmV3IHJlZnJlc2ggdG9rZW5cbiAgICAgICAgICAgIC8vIGFuZCBuZWVkIHVwZGF0ZSBjdXJyZW50IHRva2VuXG4gICAgICAgICAgICB2YXIgdG9rZW4gPSByZWplY3Rpb24uaGVhZGVycygnQXV0aG9yaXphdGlvbicpO1xuXG4gICAgICAgICAgICBpZiAodG9rZW4pIHtcbiAgICAgICAgICAgICAgJGluamVjdG9yLmdldCgnQXV0aCcpLnNldFRva2VuKHRva2VuLnNwbGl0KCcgJylbMV0pO1xuICAgICAgICAgICAgfVxuICAgICAgICAgIH1cblxuICAgICAgICAgIHJldHVybiAkcS5yZWplY3QocmVqZWN0aW9uKTtcbiAgICAgICAgfVxuICAgICAgfTtcbiAgICB9XG5cbiAgICAvLyBTZXR1cCBmb3IgdGhlICRodHRwSW50ZXJjZXB0b3JcbiAgICAkcHJvdmlkZS5mYWN0b3J5KCdyZWRpcmVjdFdoZW5TZXJ2ZXJMb2dnZWRPdXQnLCByZWRpcmVjdFdoZW5TZXJ2ZXJMb2dnZWRPdXQpO1xuXG4gICAgLy8gUHVzaCB0aGUgbmV3IGZhY3Rvcnkgb250byB0aGUgJGh0dHAgaW50ZXJjZXB0b3IgYXJyYXlcbiAgICAkaHR0cFByb3ZpZGVyLmludGVyY2VwdG9ycy5wdXNoKCdyZWRpcmVjdFdoZW5TZXJ2ZXJMb2dnZWRPdXQnKTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25maWcodmFsaWRhdGlvbkludGVyY2VwdG9yKTtcblxuICBmdW5jdGlvbiB2YWxpZGF0aW9uSW50ZXJjZXB0b3IoJGh0dHBQcm92aWRlciwgJHByb3ZpZGUpIHtcbiAgICAvKipcbiAgICAgKiBFc3RlIGludGVyY2VwdG9yIMOpIHJlc3BvbnPDoXZlbCBwb3IgbW9zdHJhciBhc1xuICAgICAqIG1lbnNhZ2VucyBkZSBlcnJvIHJlZmVyZW50ZSBhcyB2YWxpZGHDp8O1ZXMgZG8gYmFjay1lbmRcbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSAkcVxuICAgICAqIEBwYXJhbSB7YW55fSAkaW5qZWN0b3JcbiAgICAgKiBAcmV0dXJuc1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIHNob3dFcnJvclZhbGlkYXRpb24oJHEsICRpbmplY3Rvcikge1xuICAgICAgcmV0dXJuIHtcbiAgICAgICAgcmVzcG9uc2VFcnJvcjogZnVuY3Rpb24gcmVzcG9uc2VFcnJvcihyZWplY3Rpb24pIHtcbiAgICAgICAgICB2YXIgUHJUb2FzdCA9ICRpbmplY3Rvci5nZXQoJ1ByVG9hc3QnKTtcbiAgICAgICAgICB2YXIgJHRyYW5zbGF0ZSA9ICRpbmplY3Rvci5nZXQoJyR0cmFuc2xhdGUnKTtcblxuICAgICAgICAgIGlmIChyZWplY3Rpb24uY29uZmlnLmRhdGEgJiYgIXJlamVjdGlvbi5jb25maWcuZGF0YS5za2lwVmFsaWRhdGlvbikge1xuICAgICAgICAgICAgaWYgKHJlamVjdGlvbi5kYXRhICYmIHJlamVjdGlvbi5kYXRhLmVycm9yKSB7XG5cbiAgICAgICAgICAgICAgLy92ZXJpZmljYSBzZSBvY29ycmV1IGFsZ3VtIGVycm8gcmVmZXJlbnRlIGFvIHRva2VuXG4gICAgICAgICAgICAgIGlmIChyZWplY3Rpb24uZGF0YS5lcnJvci5zdGFydHNXaXRoKCd0b2tlbl8nKSkge1xuICAgICAgICAgICAgICAgIFByVG9hc3Qud2FybigkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLmxvZ2luLmxvZ291dEluYWN0aXZlJykpO1xuICAgICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICAgIFByVG9hc3QuZXJyb3IoJHRyYW5zbGF0ZS5pbnN0YW50KHJlamVjdGlvbi5kYXRhLmVycm9yKSk7XG4gICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgIFByVG9hc3QuZXJyb3JWYWxpZGF0aW9uKHJlamVjdGlvbi5kYXRhKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9XG5cbiAgICAgICAgICByZXR1cm4gJHEucmVqZWN0KHJlamVjdGlvbik7XG4gICAgICAgIH1cbiAgICAgIH07XG4gICAgfVxuXG4gICAgLy8gRGVmaW5lIHVtYSBmYWN0b3J5IHBhcmEgbyAkaHR0cEludGVyY2VwdG9yXG4gICAgJHByb3ZpZGUuZmFjdG9yeSgnc2hvd0Vycm9yVmFsaWRhdGlvbicsIHNob3dFcnJvclZhbGlkYXRpb24pO1xuXG4gICAgLy8gQWRpY2lvbmEgYSBmYWN0b3J5IG5vIGFycmF5IGRlIGludGVyY2VwdG9ycyBkbyAkaHR0cFxuICAgICRodHRwUHJvdmlkZXIuaW50ZXJjZXB0b3JzLnB1c2goJ3Nob3dFcnJvclZhbGlkYXRpb24nKTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuLyplc2xpbnQtZW52IGVzNiovXG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb250cm9sbGVyKCdNZW51Q29udHJvbGxlcicsIE1lbnVDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIE1lbnVDb250cm9sbGVyKCRtZFNpZGVuYXYsICRzdGF0ZSwgJG1kQ29sb3JzKSB7XG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIC8vQmxvY28gZGUgZGVjbGFyYWNvZXMgZGUgZnVuY29lc1xuICAgIHZtLm9wZW4gPSBvcGVuO1xuICAgIHZtLm9wZW5NZW51T3JSZWRpcmVjdFRvU3RhdGUgPSBvcGVuTWVudU9yUmVkaXJlY3RUb1N0YXRlO1xuXG4gICAgYWN0aXZhdGUoKTtcblxuICAgIGZ1bmN0aW9uIGFjdGl2YXRlKCkge1xuICAgICAgdmFyIG1lbnVQcmVmaXggPSAndmlld3MubGF5b3V0Lm1lbnUuJztcblxuICAgICAgLy8gQXJyYXkgY29udGVuZG8gb3MgaXRlbnMgcXVlIHPDo28gbW9zdHJhZG9zIG5vIG1lbnUgbGF0ZXJhbFxuICAgICAgdm0uaXRlbnNNZW51ID0gW3sgc3RhdGU6ICdhcHAuZGFzaGJvYXJkJywgdGl0bGU6IG1lbnVQcmVmaXggKyAnZGFzaGJvYXJkJywgaWNvbjogJ2Rhc2hib2FyZCcsIHN1Ykl0ZW5zOiBbXSB9LCB7XG4gICAgICAgIHN0YXRlOiAnIycsIHRpdGxlOiBtZW51UHJlZml4ICsgJ2V4YW1wbGVzJywgaWNvbjogJ3ZpZXdfY2Fyb3VzZWwnLCBwcm9maWxlczogWydhZG1pbiddLFxuICAgICAgICBzdWJJdGVuczogW3sgc3RhdGU6ICdhcHAucHJvamVjdCcsIHRpdGxlOiBtZW51UHJlZml4ICsgJ3Byb2plY3QnLCBpY29uOiAnc3RhcicgfV1cbiAgICAgIH0sXG4gICAgICAvLyBDb2xvcXVlIHNldXMgaXRlbnMgZGUgbWVudSBhIHBhcnRpciBkZXN0ZSBwb250b1xuICAgICAge1xuICAgICAgICBzdGF0ZTogJyMnLCB0aXRsZTogbWVudVByZWZpeCArICdhZG1pbicsIGljb246ICdzZXR0aW5nc19hcHBsaWNhdGlvbnMnLCBwcm9maWxlczogWydhZG1pbiddLFxuICAgICAgICBzdWJJdGVuczogW3sgc3RhdGU6ICdhcHAudXNlcicsIHRpdGxlOiBtZW51UHJlZml4ICsgJ3VzZXInLCBpY29uOiAncGVvcGxlJyB9LCB7IHN0YXRlOiAnYXBwLm1haWwnLCB0aXRsZTogbWVudVByZWZpeCArICdtYWlsJywgaWNvbjogJ21haWwnIH0sIHsgc3RhdGU6ICdhcHAuYXVkaXQnLCB0aXRsZTogbWVudVByZWZpeCArICdhdWRpdCcsIGljb246ICdzdG9yYWdlJyB9LCB7IHN0YXRlOiAnYXBwLmRpbmFtaWMtcXVlcnknLCB0aXRsZTogbWVudVByZWZpeCArICdkaW5hbWljUXVlcnknLCBpY29uOiAnbG9jYXRpb25fc2VhcmNoaW5nJyB9XVxuICAgICAgfV07XG5cbiAgICAgIC8qKlxuICAgICAgICogT2JqZXRvIHF1ZSBwcmVlbmNoZSBvIG5nLXN0eWxlIGRvIG1lbnUgbGF0ZXJhbCB0cm9jYW5kbyBhcyBjb3Jlc1xuICAgICAgICovXG4gICAgICB2bS5zaWRlbmF2U3R5bGUgPSB7XG4gICAgICAgIHRvcDoge1xuICAgICAgICAgICdib3JkZXItYm90dG9tJzogJzFweCBzb2xpZCAnICsgZ2V0Q29sb3IoJ3ByaW1hcnknKSxcbiAgICAgICAgICAnYmFja2dyb3VuZC1pbWFnZSc6ICctd2Via2l0LWxpbmVhci1ncmFkaWVudCh0b3AsICcgKyBnZXRDb2xvcigncHJpbWFyeS01MDAnKSArICcsICcgKyBnZXRDb2xvcigncHJpbWFyeS04MDAnKSArICcpJ1xuICAgICAgICB9LFxuICAgICAgICBjb250ZW50OiB7XG4gICAgICAgICAgJ2JhY2tncm91bmQtY29sb3InOiBnZXRDb2xvcigncHJpbWFyeS04MDAnKVxuICAgICAgICB9LFxuICAgICAgICB0ZXh0Q29sb3I6IHtcbiAgICAgICAgICBjb2xvcjogJyNGRkYnXG4gICAgICAgIH0sXG4gICAgICAgIGxpbmVCb3R0b206IHtcbiAgICAgICAgICAnYm9yZGVyLWJvdHRvbSc6ICcxcHggc29saWQgJyArIGdldENvbG9yKCdwcmltYXJ5LTQwMCcpXG4gICAgICAgIH1cbiAgICAgIH07XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gb3BlbigpIHtcbiAgICAgICRtZFNpZGVuYXYoJ2xlZnQnKS50b2dnbGUoKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBNw6l0b2RvIHF1ZSBleGliZSBvIHN1YiBtZW51IGRvcyBpdGVucyBkbyBtZW51IGxhdGVyYWwgY2FzbyB0ZW5oYSBzdWIgaXRlbnNcbiAgICAgKiBjYXNvIGNvbnRyw6FyaW8gcmVkaXJlY2lvbmEgcGFyYSBvIHN0YXRlIHBhc3NhZG8gY29tbyBwYXLDom1ldHJvXG4gICAgICovXG4gICAgZnVuY3Rpb24gb3Blbk1lbnVPclJlZGlyZWN0VG9TdGF0ZSgkbWRNZW51LCBldiwgaXRlbSkge1xuICAgICAgaWYgKGFuZ3VsYXIuaXNEZWZpbmVkKGl0ZW0uc3ViSXRlbnMpICYmIGl0ZW0uc3ViSXRlbnMubGVuZ3RoID4gMCkge1xuICAgICAgICAkbWRNZW51Lm9wZW4oZXYpO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgJHN0YXRlLmdvKGl0ZW0uc3RhdGUpO1xuICAgICAgICAkbWRTaWRlbmF2KCdsZWZ0JykuY2xvc2UoKTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICBmdW5jdGlvbiBnZXRDb2xvcihjb2xvclBhbGV0dGVzKSB7XG4gICAgICByZXR1cm4gJG1kQ29sb3JzLmdldFRoZW1lQ29sb3IoY29sb3JQYWxldHRlcyk7XG4gICAgfVxuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29udHJvbGxlcignTWFpbHNDb250cm9sbGVyJywgTWFpbHNDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIE1haWxzQ29udHJvbGxlcihNYWlsc1NlcnZpY2UsIFVzZXJzU2VydmljZSwgUHJEaWFsb2csIFByVG9hc3QsIC8vIE5PU09OQVJcbiAgJHEsIGxvZGFzaCwgJHRyYW5zbGF0ZSwgR2xvYmFsKSB7XG5cbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0uZmlsdGVyU2VsZWN0ZWQgPSBmYWxzZTtcbiAgICB2bS5vcHRpb25zID0ge1xuICAgICAgc2tpbjogJ2thbWEnLFxuICAgICAgbGFuZ3VhZ2U6ICdwdC1icicsXG4gICAgICBhbGxvd2VkQ29udGVudDogdHJ1ZSxcbiAgICAgIGVudGl0aWVzOiB0cnVlLFxuICAgICAgaGVpZ2h0OiAzMDAsXG4gICAgICBleHRyYVBsdWdpbnM6ICdkaWFsb2csZmluZCxjb2xvcmRpYWxvZyxwcmV2aWV3LGZvcm1zLGlmcmFtZSxmbGFzaCdcbiAgICB9O1xuXG4gICAgdm0ubG9hZFVzZXJzID0gbG9hZFVzZXJzO1xuICAgIHZtLm9wZW5Vc2VyRGlhbG9nID0gb3BlblVzZXJEaWFsb2c7XG4gICAgdm0uYWRkVXNlck1haWwgPSBhZGRVc2VyTWFpbDtcbiAgICB2bS5jbGVhbkZvcm0gPSBjbGVhbkZvcm07XG4gICAgdm0uc2VuZCA9IHNlbmQ7XG5cbiAgICBhY3RpdmF0ZSgpO1xuXG4gICAgZnVuY3Rpb24gYWN0aXZhdGUoKSB7XG4gICAgICB2bS5jbGVhbkZvcm0oKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFsaXphIGEgYnVzY2EgcGVsbyB1c3XDoXJpbyByZW1vdGFtZW50ZVxuICAgICAqXG4gICAgICogQHBhcmFtcyB7c3RyaW5nfSAtIFJlY2ViZSBvIHZhbG9yIHBhcmEgc2VyIHBlc3F1aXNhZG9cbiAgICAgKiBAcmV0dXJuIHtwcm9taXNzZX0gLSBSZXRvcm5hIHVtYSBwcm9taXNzZSBxdWUgbyBjb21wb25ldGUgcmVzb2x2ZVxuICAgICAqL1xuICAgIGZ1bmN0aW9uIGxvYWRVc2Vycyhjcml0ZXJpYSkge1xuICAgICAgdmFyIGRlZmVycmVkID0gJHEuZGVmZXIoKTtcblxuICAgICAgVXNlcnNTZXJ2aWNlLnF1ZXJ5KHtcbiAgICAgICAgbmFtZU9yRW1haWw6IGNyaXRlcmlhLFxuICAgICAgICBub3RVc2VyczogbG9kYXNoLm1hcCh2bS5tYWlsLnVzZXJzLCBsb2Rhc2gucHJvcGVydHkoJ2lkJykpLnRvU3RyaW5nKCksXG4gICAgICAgIGxpbWl0OiA1XG4gICAgICB9KS50aGVuKGZ1bmN0aW9uIChkYXRhKSB7XG5cbiAgICAgICAgLy8gdmVyaWZpY2Egc2UgbmEgbGlzdGEgZGUgdXN1YXJpb3MgasOhIGV4aXN0ZSBvIHVzdcOhcmlvIGNvbSBvIGVtYWlsIHBlc3F1aXNhZG9cbiAgICAgICAgZGF0YSA9IGxvZGFzaC5maWx0ZXIoZGF0YSwgZnVuY3Rpb24gKHVzZXIpIHtcbiAgICAgICAgICByZXR1cm4gIWxvZGFzaC5maW5kKHZtLm1haWwudXNlcnMsIHsgZW1haWw6IHVzZXIuZW1haWwgfSk7XG4gICAgICAgIH0pO1xuXG4gICAgICAgIGRlZmVycmVkLnJlc29sdmUoZGF0YSk7XG4gICAgICB9KTtcblxuICAgICAgcmV0dXJuIGRlZmVycmVkLnByb21pc2U7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQWJyZSBvIGRpYWxvZyBwYXJhIHBlc3F1aXNhIGRlIHVzdcOhcmlvc1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIG9wZW5Vc2VyRGlhbG9nKCkge1xuICAgICAgdmFyIGNvbmZpZyA9IHtcbiAgICAgICAgbG9jYWxzOiB7XG4gICAgICAgICAgb25Jbml0OiB0cnVlLFxuICAgICAgICAgIHVzZXJEaWFsb2dJbnB1dDoge1xuICAgICAgICAgICAgdHJhbnNmZXJVc2VyRm46IHZtLmFkZFVzZXJNYWlsXG4gICAgICAgICAgfVxuICAgICAgICB9LFxuICAgICAgICBjb250cm9sbGVyOiAnVXNlcnNEaWFsb2dDb250cm9sbGVyJyxcbiAgICAgICAgY29udHJvbGxlckFzOiAnY3RybCcsXG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvdXNlcnMvZGlhbG9nL3VzZXJzLWRpYWxvZy5odG1sJyxcbiAgICAgICAgaGFzQmFja2Ryb3A6IHRydWVcbiAgICAgIH07XG5cbiAgICAgIFByRGlhbG9nLmN1c3RvbShjb25maWcpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEFkaWNpb25hIG8gdXN1w6FyaW8gc2VsZWNpb25hZG8gbmEgbGlzdGEgcGFyYSBxdWUgc2VqYSBlbnZpYWRvIG8gZW1haWxcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBhZGRVc2VyTWFpbCh1c2VyKSB7XG4gICAgICB2YXIgdXNlcnMgPSBsb2Rhc2guZmluZCh2bS5tYWlsLnVzZXJzLCB7IGVtYWlsOiB1c2VyLmVtYWlsIH0pO1xuXG4gICAgICBpZiAodm0ubWFpbC51c2Vycy5sZW5ndGggPiAwICYmIGFuZ3VsYXIuaXNEZWZpbmVkKHVzZXJzKSkge1xuICAgICAgICBQclRvYXN0Lndhcm4oJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy51c2VyLnVzZXJFeGlzdHMnKSk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICB2bS5tYWlsLnVzZXJzLnB1c2goeyBuYW1lOiB1c2VyLm5hbWUsIGVtYWlsOiB1c2VyLmVtYWlsIH0pO1xuICAgICAgfVxuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWxpemEgbyBlbnZpbyBkbyBlbWFpbCBwYXJhIGEgbGlzdGEgZGUgdXN1w6FyaW9zIHNlbGVjaW9uYWRvc1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIHNlbmQoKSB7XG5cbiAgICAgIHZtLm1haWwuJHNhdmUoKS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICBpZiAocmVzcG9uc2UubGVuZ3RoID4gMCkge1xuICAgICAgICAgIHZhciBtc2cgPSAkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLm1haWwubWFpbEVycm9ycycpO1xuXG4gICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCByZXNwb25zZS5sZW5ndGg7IGkrKykge1xuICAgICAgICAgICAgbXNnICs9IHJlc3BvbnNlICsgJ1xcbic7XG4gICAgICAgICAgfVxuICAgICAgICAgIFByVG9hc3QuZXJyb3IobXNnKTtcbiAgICAgICAgICB2bS5jbGVhbkZvcm0oKTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICBQclRvYXN0LnN1Y2Nlc3MoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5tYWlsLnNlbmRNYWlsU3VjY2VzcycpKTtcbiAgICAgICAgICB2bS5jbGVhbkZvcm0oKTtcbiAgICAgICAgfVxuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogTGltcGEgbyBmb3JtdWzDoXJpbyBkZSBlbWFpbFxuICAgICAqL1xuICAgIGZ1bmN0aW9uIGNsZWFuRm9ybSgpIHtcbiAgICAgIHZtLm1haWwgPSBuZXcgTWFpbHNTZXJ2aWNlKCk7XG4gICAgICB2bS5tYWlsLnVzZXJzID0gW107XG4gICAgfVxuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKlxuICAgKiBBcnF1aXZvIGRlIGNvbmZpZ3VyYcOnw6NvIGNvbSBhcyByb3RhcyBlc3BlY8OtZmljYXMgZG8gcmVjdXJzbyBlbSBxdWVzdMOjb1xuICAgKlxuICAgKiBAcGFyYW0ge2FueX0gJHN0YXRlUHJvdmlkZXJcbiAgICogQHBhcmFtIHthbnl9IEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdhcHAubWFpbCcsIHtcbiAgICAgIHVybDogJy9lbWFpbCcsXG4gICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL21haWwvbWFpbHMtc2VuZC5odG1sJyxcbiAgICAgIGNvbnRyb2xsZXI6ICdNYWlsc0NvbnRyb2xsZXIgYXMgbWFpbHNDdHJsJyxcbiAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiB0cnVlLCBuZWVkUHJvZmlsZTogWydhZG1pbiddIH1cbiAgICB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5mYWN0b3J5KCdNYWlsc1NlcnZpY2UnLCBNYWlsc1NlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gTWFpbHNTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCdtYWlscycsIHt9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZpbHRlcigncm9sZXNTdHInLCByb2xlc1N0cik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb2xlc1N0cihsb2Rhc2gpIHtcbiAgICAvKipcbiAgICAgKiBAcGFyYW0ge2FycmF5fSByb2xlcyBsaXN0YSBkZSBwZXJmaXNcbiAgICAgKiBAcmV0dXJuIHtzdHJpbmd9IHBlcmZpcyBzZXBhcmFkb3MgcG9yICcsICcgIFxuICAgICAqL1xuICAgIHJldHVybiBmdW5jdGlvbiAocm9sZXMpIHtcbiAgICAgIHJldHVybiBsb2Rhc2gubWFwKHJvbGVzLCAnc2x1ZycpLmpvaW4oJywgJyk7XG4gICAgfTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5mYWN0b3J5KCdSb2xlc1NlcnZpY2UnLCBSb2xlc1NlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gUm9sZXNTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCdyb2xlcycpO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZhY3RvcnkoJ1N1cHBvcnRTZXJ2aWNlJywgU3VwcG9ydFNlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gU3VwcG9ydFNlcnZpY2Uoc2VydmljZUZhY3RvcnkpIHtcbiAgICByZXR1cm4gc2VydmljZUZhY3RvcnkoJ3N1cHBvcnQnLCB7XG4gICAgICBhY3Rpb25zOiB7XG4gICAgICAgIC8qKlxuICAgICAgICAgKiBQZWdhIGFzIHRyYWR1w6fDtWVzIHF1ZSBlc3TDo28gbm8gc2Vydmlkb3JcbiAgICAgICAgICpcbiAgICAgICAgICogQHJldHVybnMge3Byb21pc2V9IFVtYSBwcm9taXNlIGNvbSBvIHJlc3VsdGFkbyBkbyBjaGFtYWRhIG5vIGJhY2tlbmRcbiAgICAgICAgICovXG4gICAgICAgIGxhbmdzOiB7XG4gICAgICAgICAgbWV0aG9kOiAnR0VUJyxcbiAgICAgICAgICB1cmw6ICdsYW5ncycsXG4gICAgICAgICAgd3JhcDogZmFsc2UsXG4gICAgICAgICAgY2FjaGU6IHRydWVcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb21wb25lbnQoJ2JveCcsIHtcbiAgICByZXBsYWNlOiB0cnVlLFxuICAgIHRlbXBsYXRlVXJsOiBbJ0dsb2JhbCcsIGZ1bmN0aW9uIChHbG9iYWwpIHtcbiAgICAgIHJldHVybiBHbG9iYWwuY2xpZW50UGF0aCArICcvd2lkZ2V0cy9ib3guaHRtbCc7XG4gICAgfV0sXG4gICAgdHJhbnNjbHVkZToge1xuICAgICAgdG9vbGJhckJ1dHRvbnM6ICc/Ym94VG9vbGJhckJ1dHRvbnMnLFxuICAgICAgZm9vdGVyQnV0dG9uczogJz9ib3hGb290ZXJCdXR0b25zJ1xuICAgIH0sXG4gICAgYmluZGluZ3M6IHtcbiAgICAgIGJveFRpdGxlOiAnQCcsXG4gICAgICB0b29sYmFyQ2xhc3M6ICdAJyxcbiAgICAgIHRvb2xiYXJCZ0NvbG9yOiAnQCdcbiAgICB9LFxuICAgIGNvbnRyb2xsZXI6IFsnJHRyYW5zY2x1ZGUnLCBmdW5jdGlvbiAoJHRyYW5zY2x1ZGUpIHtcbiAgICAgIHZhciBjdHJsID0gdGhpcztcblxuICAgICAgY3RybC50cmFuc2NsdWRlID0gJHRyYW5zY2x1ZGU7XG5cbiAgICAgIGN0cmwuJG9uSW5pdCA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgaWYgKGFuZ3VsYXIuaXNVbmRlZmluZWQoY3RybC50b29sYmFyQmdDb2xvcikpIGN0cmwudG9vbGJhckJnQ29sb3IgPSAnZGVmYXVsdC1wcmltYXJ5JztcbiAgICAgIH07XG4gICAgfV1cbiAgfSk7XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb21wb25lbnQoJ2NvbnRlbnRCb2R5Jywge1xuICAgIHJlcGxhY2U6IHRydWUsXG4gICAgdHJhbnNjbHVkZTogdHJ1ZSxcbiAgICB0ZW1wbGF0ZVVybDogWydHbG9iYWwnLCBmdW5jdGlvbiAoR2xvYmFsKSB7XG4gICAgICByZXR1cm4gR2xvYmFsLmNsaWVudFBhdGggKyAnL3dpZGdldHMvY29udGVudC1ib2R5Lmh0bWwnO1xuICAgIH1dLFxuICAgIGJpbmRpbmdzOiB7XG4gICAgICBsYXlvdXRBbGlnbjogJ0AnXG4gICAgfSxcbiAgICBjb250cm9sbGVyOiBbZnVuY3Rpb24gKCkge1xuICAgICAgdmFyIGN0cmwgPSB0aGlzO1xuXG4gICAgICBjdHJsLiRvbkluaXQgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgIC8vIE1ha2UgYSBjb3B5IG9mIHRoZSBpbml0aWFsIHZhbHVlIHRvIGJlIGFibGUgdG8gcmVzZXQgaXQgbGF0ZXJcbiAgICAgICAgY3RybC5sYXlvdXRBbGlnbiA9IGFuZ3VsYXIuaXNEZWZpbmVkKGN0cmwubGF5b3V0QWxpZ24pID8gY3RybC5sYXlvdXRBbGlnbiA6ICdjZW50ZXIgc3RhcnQnO1xuICAgICAgfTtcbiAgICB9XVxuICB9KTtcbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICAvKiogQG5nSW5qZWN0ICovXG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbXBvbmVudCgnY29udGVudEhlYWRlcicsIHtcbiAgICB0ZW1wbGF0ZVVybDogWydHbG9iYWwnLCBmdW5jdGlvbiAoR2xvYmFsKSB7XG4gICAgICByZXR1cm4gR2xvYmFsLmNsaWVudFBhdGggKyAnL3dpZGdldHMvY29udGVudC1oZWFkZXIuaHRtbCc7XG4gICAgfV0sXG4gICAgcmVwbGFjZTogdHJ1ZSxcbiAgICBiaW5kaW5nczoge1xuICAgICAgdGl0bGU6ICdAJyxcbiAgICAgIGRlc2NyaXB0aW9uOiAnQCdcbiAgICB9XG4gIH0pO1xufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbnRyb2xsZXIoJ1Byb2ZpbGVDb250cm9sbGVyJywgUHJvZmlsZUNvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gUHJvZmlsZUNvbnRyb2xsZXIoVXNlcnNTZXJ2aWNlLCBBdXRoLCBQclRvYXN0LCAkdHJhbnNsYXRlKSB7XG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIHZtLnVwZGF0ZSA9IHVwZGF0ZTtcblxuICAgIGFjdGl2YXRlKCk7XG5cbiAgICBmdW5jdGlvbiBhY3RpdmF0ZSgpIHtcbiAgICAgIHZtLnVzZXIgPSBhbmd1bGFyLmNvcHkoQXV0aC5jdXJyZW50VXNlcik7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gdXBkYXRlKCkge1xuICAgICAgVXNlcnNTZXJ2aWNlLnVwZGF0ZVByb2ZpbGUodm0udXNlcikudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgLy9hdHVhbGl6YSBvIHVzdcOhcmlvIGNvcnJlbnRlIGNvbSBhcyBub3ZhcyBpbmZvcm1hw6fDtWVzXG4gICAgICAgIEF1dGgudXBkYXRlQ3VycmVudFVzZXIocmVzcG9uc2UpO1xuICAgICAgICBQclRvYXN0LnN1Y2Nlc3MoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5zYXZlU3VjY2VzcycpKTtcbiAgICAgIH0pO1xuICAgIH1cbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbnRyb2xsZXIoJ1VzZXJzQ29udHJvbGxlcicsIFVzZXJzQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBVc2Vyc0NvbnRyb2xsZXIoJGNvbnRyb2xsZXIsIFVzZXJzU2VydmljZSkge1xuXG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIHZtLm9uQWN0aXZhdGUgPSBvbkFjdGl2YXRlO1xuICAgIC8vIGluc3RhbnRpYXRlIGJhc2UgY29udHJvbGxlclxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHsgdm06IHZtLCBtb2RlbFNlcnZpY2U6IFVzZXJzU2VydmljZSwgb3B0aW9uczoge30gfSk7XG5cbiAgICBmdW5jdGlvbiBvbkFjdGl2YXRlKCkge1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0ge307XG4gICAgfVxuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKlxuICAgKiBBcnF1aXZvIGRlIGNvbmZpZ3VyYcOnw6NvIGNvbSBhcyByb3RhcyBlc3BlY8OtZmljYXMgZG8gcmVjdXJzbyB1c2VyXG4gICAqXG4gICAqIEBwYXJhbSB7YW55fSAkc3RhdGVQcm92aWRlclxuICAgKiBAcGFyYW0ge2FueX0gR2xvYmFsXG4gICAqL1xuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvdXRlcygkc3RhdGVQcm92aWRlciwgR2xvYmFsKSB7XG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ2FwcC51c2VyJywge1xuICAgICAgdXJsOiAnL3VzdWFyaW8nLFxuICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy91c2Vycy91c2Vycy5odG1sJyxcbiAgICAgIGNvbnRyb2xsZXI6ICdVc2Vyc0NvbnRyb2xsZXIgYXMgdXNlcnNDdHJsJyxcbiAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiB0cnVlLCBuZWVkUHJvZmlsZTogWydhZG1pbiddIH1cbiAgICB9KS5zdGF0ZSgnYXBwLnVzZXItcHJvZmlsZScsIHtcbiAgICAgIHVybDogJy91c3VhcmlvL3BlcmZpbCcsXG4gICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL3VzZXJzL3Byb2ZpbGUuaHRtbCcsXG4gICAgICBjb250cm9sbGVyOiAnUHJvZmlsZUNvbnRyb2xsZXIgYXMgcHJvZmlsZUN0cmwnLFxuICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IHRydWUgfVxuICAgIH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZhY3RvcnkoJ1VzZXJzU2VydmljZScsIFVzZXJzU2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBVc2Vyc1NlcnZpY2UobG9kYXNoLCBHbG9iYWwsIHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCd1c2VycycsIHtcbiAgICAgIC8vcXVhbmRvIGluc3RhbmNpYSB1bSB1c3XDoXJpbyBzZW0gcGFzc2FyIHBhcmFtZXRybyxcbiAgICAgIC8vbyBtZXNtbyB2YWkgdGVyIG9zIHZhbG9yZXMgZGVmYXVsdHMgYWJhaXhvXG4gICAgICBkZWZhdWx0czoge1xuICAgICAgICByb2xlczogW11cbiAgICAgIH0sXG5cbiAgICAgIGFjdGlvbnM6IHtcbiAgICAgICAgLyoqXG4gICAgICAgICAqIFNlcnZpw6dvIHF1ZSBhdHVhbGl6YSBvcyBkYWRvcyBkbyBwZXJmaWwgZG8gdXN1w6FyaW8gbG9nYWRvXG4gICAgICAgICAqXG4gICAgICAgICAqIEBwYXJhbSB7b2JqZWN0fSBhdHRyaWJ1dGVzXG4gICAgICAgICAqIEByZXR1cm5zIHtwcm9taXNlfSBVbWEgcHJvbWlzZSBjb20gbyByZXN1bHRhZG8gZG8gY2hhbWFkYSBubyBiYWNrZW5kXG4gICAgICAgICAqL1xuICAgICAgICB1cGRhdGVQcm9maWxlOiB7XG4gICAgICAgICAgbWV0aG9kOiAnUFVUJyxcbiAgICAgICAgICB1cmw6IEdsb2JhbC5hcGlQYXRoICsgJy9wcm9maWxlJyxcbiAgICAgICAgICBvdmVycmlkZTogdHJ1ZSxcbiAgICAgICAgICB3cmFwOiBmYWxzZVxuICAgICAgICB9XG4gICAgICB9LFxuXG4gICAgICBpbnN0YW5jZToge1xuICAgICAgICAvKipcbiAgICAgICAgICogVmVyaWZpY2Egc2UgbyB1c3XDoXJpbyB0ZW0gb3MgcGVyZmlzIGluZm9ybWFkb3MuXG4gICAgICAgICAqXG4gICAgICAgICAqIEBwYXJhbSB7YW55fSByb2xlcyBwZXJmaXMgYSBzZXJlbSB2ZXJpZmljYWRvc1xuICAgICAgICAgKiBAcGFyYW0ge2Jvb2xlYW59IGFsbCBmbGFnIHBhcmEgaW5kaWNhciBzZSB2YWkgY2hlZ2FyIHRvZG9zIG9zIHBlcmZpcyBvdSBzb21lbnRlIHVtIGRlbGVzXG4gICAgICAgICAqIEByZXR1cm5zIHtib29sZWFufVxuICAgICAgICAgKi9cbiAgICAgICAgaGFzUHJvZmlsZTogZnVuY3Rpb24gaGFzUHJvZmlsZShyb2xlcywgYWxsKSB7XG4gICAgICAgICAgcm9sZXMgPSBhbmd1bGFyLmlzQXJyYXkocm9sZXMpID8gcm9sZXMgOiBbcm9sZXNdO1xuXG4gICAgICAgICAgdmFyIHVzZXJSb2xlcyA9IGxvZGFzaC5tYXAodGhpcy5yb2xlcywgJ3NsdWcnKTtcblxuICAgICAgICAgIGlmIChhbGwpIHtcbiAgICAgICAgICAgIHJldHVybiBsb2Rhc2guaW50ZXJzZWN0aW9uKHVzZXJSb2xlcywgcm9sZXMpLmxlbmd0aCA9PT0gcm9sZXMubGVuZ3RoO1xuICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAvL3JldHVybiB0aGUgbGVuZ3RoIGJlY2F1c2UgMCBpcyBmYWxzZSBpbiBqc1xuICAgICAgICAgICAgcmV0dXJuIGxvZGFzaC5pbnRlcnNlY3Rpb24odXNlclJvbGVzLCByb2xlcykubGVuZ3RoO1xuICAgICAgICAgIH1cbiAgICAgICAgfSxcblxuICAgICAgICAvKipcbiAgICAgICAgICogVmVyaWZpY2Egc2UgbyB1c3XDoXJpbyB0ZW0gbyBwZXJmaWwgYWRtaW4uXG4gICAgICAgICAqXG4gICAgICAgICAqIEByZXR1cm5zIHtib29sZWFufVxuICAgICAgICAgKi9cbiAgICAgICAgaXNBZG1pbjogZnVuY3Rpb24gaXNBZG1pbigpIHtcbiAgICAgICAgICByZXR1cm4gdGhpcy5oYXNQcm9maWxlKCdhZG1pbicpO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5maWx0ZXIoJ2F1ZGl0RGV0YWlsVGl0bGUnLCBhdWRpdERldGFpbFRpdGxlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIGF1ZGl0RGV0YWlsVGl0bGUoJHRyYW5zbGF0ZSkge1xuICAgIHJldHVybiBmdW5jdGlvbiAoYXVkaXREZXRhaWwsIHN0YXR1cykge1xuICAgICAgaWYgKGF1ZGl0RGV0YWlsLnR5cGUgPT09ICd1cGRhdGVkJykge1xuICAgICAgICBpZiAoc3RhdHVzID09PSAnYmVmb3JlJykge1xuICAgICAgICAgIHJldHVybiAkdHJhbnNsYXRlLmluc3RhbnQoJ2RpYWxvZy5hdWRpdC51cGRhdGVkQmVmb3JlJyk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgcmV0dXJuICR0cmFuc2xhdGUuaW5zdGFudCgnZGlhbG9nLmF1ZGl0LnVwZGF0ZWRBZnRlcicpO1xuICAgICAgICB9XG4gICAgICB9IGVsc2Uge1xuICAgICAgICByZXR1cm4gJHRyYW5zbGF0ZS5pbnN0YW50KCdkaWFsb2cuYXVkaXQuJyArIGF1ZGl0RGV0YWlsLnR5cGUpO1xuICAgICAgfVxuICAgIH07XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5maWx0ZXIoJ2F1ZGl0TW9kZWwnLCBhdWRpdE1vZGVsKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIGF1ZGl0TW9kZWwoJHRyYW5zbGF0ZSkge1xuICAgIHJldHVybiBmdW5jdGlvbiAobW9kZWxJZCkge1xuICAgICAgbW9kZWxJZCA9IG1vZGVsSWQucmVwbGFjZSgnQXBwXFxcXCcsICcnKTtcbiAgICAgIHZhciBtb2RlbCA9ICR0cmFuc2xhdGUuaW5zdGFudCgnbW9kZWxzLicgKyBtb2RlbElkLnRvTG93ZXJDYXNlKCkpO1xuXG4gICAgICByZXR1cm4gbW9kZWwgPyBtb2RlbCA6IG1vZGVsSWQ7XG4gICAgfTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZpbHRlcignYXVkaXRUeXBlJywgYXVkaXRUeXBlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIGF1ZGl0VHlwZShsb2Rhc2gsIEF1ZGl0U2VydmljZSkge1xuICAgIHJldHVybiBmdW5jdGlvbiAodHlwZUlkKSB7XG4gICAgICB2YXIgdHlwZSA9IGxvZGFzaC5maW5kKEF1ZGl0U2VydmljZS5saXN0VHlwZXMoKSwgeyBpZDogdHlwZUlkIH0pO1xuXG4gICAgICByZXR1cm4gdHlwZSA/IHR5cGUubGFiZWwgOiB0eXBlO1xuICAgIH07XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5maWx0ZXIoJ2F1ZGl0VmFsdWUnLCBhdWRpdFZhbHVlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIGF1ZGl0VmFsdWUoJGZpbHRlciwgbG9kYXNoKSB7XG4gICAgcmV0dXJuIGZ1bmN0aW9uICh2YWx1ZSwga2V5KSB7XG4gICAgICBpZiAoYW5ndWxhci5pc0RhdGUodmFsdWUpIHx8IGxvZGFzaC5lbmRzV2l0aChrZXksICdfYXQnKSB8fCBsb2Rhc2guZW5kc1dpdGgoa2V5LCAnX3RvJykpIHtcbiAgICAgICAgcmV0dXJuICRmaWx0ZXIoJ3ByRGF0ZXRpbWUnKSh2YWx1ZSk7XG4gICAgICB9XG5cbiAgICAgIGlmICh0eXBlb2YgdmFsdWUgPT09ICdib29sZWFuJykge1xuICAgICAgICByZXR1cm4gJGZpbHRlcigndHJhbnNsYXRlJykodmFsdWUgPyAnZ2xvYmFsLnllcycgOiAnZ2xvYmFsLm5vJyk7XG4gICAgICB9XG5cbiAgICAgIC8vY2hlY2sgaXMgZmxvYXRcbiAgICAgIGlmIChOdW1iZXIodmFsdWUpID09PSB2YWx1ZSAmJiB2YWx1ZSAlIDEgIT09IDApIHtcbiAgICAgICAgcmV0dXJuICRmaWx0ZXIoJ3JlYWwnKSh2YWx1ZSk7XG4gICAgICB9XG5cbiAgICAgIHJldHVybiB2YWx1ZTtcbiAgICB9O1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4vKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCwgbm8tdW5kZWY6IDAqL1xuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25zdGFudCgncHQtQlIuaTE4bi5hdHRyaWJ1dGVzJywge1xuICAgIGVtYWlsOiAnRW1haWwnLFxuICAgIHBhc3N3b3JkOiAnU2VuaGEnLFxuICAgIG5hbWU6ICdOb21lJyxcbiAgICBpbWFnZTogJ0ltYWdlbScsXG4gICAgcm9sZXM6ICdQZXJmaXMnLFxuICAgIGRhdGU6ICdEYXRhJyxcbiAgICBpbml0aWFsRGF0ZTogJ0RhdGEgSW5pY2lhbCcsXG4gICAgZmluYWxEYXRlOiAnRGF0YSBGaW5hbCcsXG4gICAgdGFzazoge1xuICAgICAgZGVzY3JpcHRpb246ICdEZXNjcmnDp8OjbycsXG4gICAgICBkb25lOiAnRmVpdG8/JyxcbiAgICAgIHByaW9yaXR5OiAnUHJpb3JpZGFkZScsXG4gICAgICBzY2hlZHVsZWRfdG86ICdBZ2VuZGFkbyBQYXJhPycsXG4gICAgICBwcm9qZWN0OiAnUHJvamV0bydcbiAgICB9LFxuICAgIHByb2plY3Q6IHtcbiAgICAgIGNvc3Q6ICdDdXN0bydcbiAgICB9LFxuICAgIC8vw6kgY2FycmVnYWRvIGRvIHNlcnZpZG9yIGNhc28gZXN0ZWphIGRlZmluaWRvIG5vIG1lc21vXG4gICAgYXVkaXRNb2RlbDoge31cbiAgfSk7XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4vKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCwgbm8tdW5kZWY6IDAqL1xuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25zdGFudCgncHQtQlIuaTE4bi5kaWFsb2cnLCB7XG4gICAgY29uZmlybVRpdGxlOiAnQ29uZmlybWHDp8OjbycsXG4gICAgY29uZmlybURlc2NyaXB0aW9uOiAnQ29uZmlybWEgYSBhw6fDo28/JyxcbiAgICByZW1vdmVEZXNjcmlwdGlvbjogJ0Rlc2VqYSByZW1vdmVyIHBlcm1hbmVudGVtZW50ZSB7e25hbWV9fT8nLFxuICAgIGF1ZGl0OiB7XG4gICAgICBjcmVhdGVkOiAnSW5mb3JtYcOnw7VlcyBkbyBDYWRhc3RybycsXG4gICAgICB1cGRhdGVkQmVmb3JlOiAnQW50ZXMgZGEgQXR1YWxpemHDp8OjbycsXG4gICAgICB1cGRhdGVkQWZ0ZXI6ICdEZXBvaXMgZGEgQXR1YWxpemHDp8OjbycsXG4gICAgICBkZWxldGVkOiAnSW5mb3JtYcOnw7VlcyBhbnRlcyBkZSByZW1vdmVyJ1xuICAgIH0sXG4gICAgbG9naW46IHtcbiAgICAgIHJlc2V0UGFzc3dvcmQ6IHtcbiAgICAgICAgZGVzY3JpcHRpb246ICdEaWdpdGUgYWJhaXhvIG8gZW1haWwgY2FkYXN0cmFkbyBubyBzaXN0ZW1hLidcbiAgICAgIH1cbiAgICB9XG4gIH0pO1xufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuLyplc2xpbnQgYW5ndWxhci9maWxlLW5hbWU6IDAsIG5vLXVuZGVmOiAwKi9cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29uc3RhbnQoJ3B0LUJSLmkxOG4uZ2xvYmFsJywge1xuICAgIGxvYWRpbmc6ICdDYXJyZWdhbmRvLi4uJyxcbiAgICBwcm9jZXNzaW5nOiAnUHJvY2Vzc2FuZG8uLi4nLFxuICAgIHllczogJ1NpbScsXG4gICAgbm86ICdOw6NvJyxcbiAgICBhbGw6ICdUb2RvcydcbiAgfSk7XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4vKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCwgbm8tdW5kZWY6IDAqL1xuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25zdGFudCgncHQtQlIuaTE4bi5tZXNzYWdlcycsIHtcbiAgICBpbnRlcm5hbEVycm9yOiAnT2NvcnJldSB1bSBlcnJvIGludGVybm8sIGNvbnRhdGUgbyBhZG1pbmlzdHJhZG9yIGRvIHNpc3RlbWEnLFxuICAgIG5vdEZvdW5kOiAnTmVuaHVtIHJlZ2lzdHJvIGVuY29udHJhZG8nLFxuICAgIG5vdEF1dGhvcml6ZWQ6ICdWb2PDqiBuw6NvIHRlbSBhY2Vzc28gYSBlc3RhIGZ1bmNpb25hbGlkYWRlLicsXG4gICAgc2VhcmNoRXJyb3I6ICdOw6NvIGZvaSBwb3Nzw612ZWwgcmVhbGl6YXIgYSBidXNjYS4nLFxuICAgIHNhdmVTdWNjZXNzOiAnUmVnaXN0cm8gc2Fsdm8gY29tIHN1Y2Vzc28uJyxcbiAgICBvcGVyYXRpb25TdWNjZXNzOiAnT3BlcmHDp8OjbyByZWFsaXphZGEgY29tIHN1Y2Vzc28uJyxcbiAgICBvcGVyYXRpb25FcnJvcjogJ0Vycm8gYW8gcmVhbGl6YXIgYSBvcGVyYcOnw6NvJyxcbiAgICBzYXZlRXJyb3I6ICdFcnJvIGFvIHRlbnRhciBzYWx2YXIgbyByZWdpc3Ryby4nLFxuICAgIHJlbW92ZVN1Y2Nlc3M6ICdSZW1vw6fDo28gcmVhbGl6YWRhIGNvbSBzdWNlc3NvLicsXG4gICAgcmVtb3ZlRXJyb3I6ICdFcnJvIGFvIHRlbnRhciByZW1vdmVyIG8gcmVnaXN0cm8uJyxcbiAgICByZXNvdXJjZU5vdEZvdW5kRXJyb3I6ICdSZWN1cnNvIG7Do28gZW5jb250cmFkbycsXG4gICAgbm90TnVsbEVycm9yOiAnVG9kb3Mgb3MgY2FtcG9zIG9icmlnYXTDs3Jpb3MgZGV2ZW0gc2VyIHByZWVuY2hpZG9zLicsXG4gICAgZHVwbGljYXRlZFJlc291cmNlRXJyb3I6ICdKw6EgZXhpc3RlIHVtIHJlY3Vyc28gY29tIGVzc2FzIGluZm9ybWHDp8O1ZXMuJyxcbiAgICB2YWxpZGF0ZToge1xuICAgICAgZmllbGRSZXF1aXJlZDogJ08gY2FtcG8ge3tmaWVsZH19IMOpIG9icmlncmF0w7NyaW8uJ1xuICAgIH0sXG4gICAgbGF5b3V0OiB7XG4gICAgICBlcnJvcjQwNDogJ1DDoWdpbmEgbsOjbyBlbmNvbnRyYWRhJ1xuICAgIH0sXG4gICAgbG9naW46IHtcbiAgICAgIGxvZ291dEluYWN0aXZlOiAnVm9jw6ogZm9pIGRlc2xvZ2FkbyBkbyBzaXN0ZW1hIHBvciBpbmF0aXZpZGFkZS4gRmF2b3IgZW50cmFyIG5vIHNpc3RlbWEgbm92YW1lbnRlLicsXG4gICAgICBpbnZhbGlkQ3JlZGVudGlhbHM6ICdDcmVkZW5jaWFpcyBJbnbDoWxpZGFzJyxcbiAgICAgIHVua25vd25FcnJvcjogJ07Do28gZm9pIHBvc3PDrXZlbCByZWFsaXphciBvIGxvZ2luLiBUZW50ZSBub3ZhbWVudGUuICcgKyAnQ2FzbyBuw6NvIGNvbnNpZ2EgZmF2b3IgZW5jb250cmFyIGVtIGNvbnRhdG8gY29tIG8gYWRtaW5pc3RyYWRvciBkbyBzaXN0ZW1hLicsXG4gICAgICB1c2VyTm90Rm91bmQ6ICdOw6NvIGZvaSBwb3Nzw612ZWwgZW5jb250cmFyIHNldXMgZGFkb3MnXG4gICAgfSxcbiAgICBkYXNoYm9hcmQ6IHtcbiAgICAgIHdlbGNvbWU6ICdTZWphIGJlbSBWaW5kbyB7e3VzZXJOYW1lfX0nLFxuICAgICAgZGVzY3JpcHRpb246ICdVdGlsaXplIG8gbWVudSBwYXJhIG5hdmVnYcOnw6NvLidcbiAgICB9LFxuICAgIG1haWw6IHtcbiAgICAgIG1haWxFcnJvcnM6ICdPY29ycmV1IHVtIGVycm8gbm9zIHNlZ3VpbnRlcyBlbWFpbHMgYWJhaXhvOlxcbicsXG4gICAgICBzZW5kTWFpbFN1Y2Nlc3M6ICdFbWFpbCBlbnZpYWRvIGNvbSBzdWNlc3NvIScsXG4gICAgICBzZW5kTWFpbEVycm9yOiAnTsOjbyBmb2kgcG9zc8OtdmVsIGVudmlhciBvIGVtYWlsLicsXG4gICAgICBwYXNzd29yZFNlbmRpbmdTdWNjZXNzOiAnTyBwcm9jZXNzbyBkZSByZWN1cGVyYcOnw6NvIGRlIHNlbmhhIGZvaSBpbmljaWFkby4gQ2FzbyBvIGVtYWlsIG7Do28gY2hlZ3VlIGVtIDEwIG1pbnV0b3MgdGVudGUgbm92YW1lbnRlLidcbiAgICB9LFxuICAgIHVzZXI6IHtcbiAgICAgIHJlbW92ZVlvdXJTZWxmRXJyb3I6ICdWb2PDqiBuw6NvIHBvZGUgcmVtb3ZlciBzZXUgcHLDs3ByaW8gdXN1w6FyaW8nLFxuICAgICAgdXNlckV4aXN0czogJ1VzdcOhcmlvIGrDoSBhZGljaW9uYWRvIScsXG4gICAgICBwcm9maWxlOiB7XG4gICAgICAgIHVwZGF0ZUVycm9yOiAnTsOjbyBmb2kgcG9zc8OtdmVsIGF0dWFsaXphciBzZXUgcHJvZmlsZSdcbiAgICAgIH1cbiAgICB9LFxuICAgIHF1ZXJ5RGluYW1pYzoge1xuICAgICAgbm9GaWx0ZXI6ICdOZW5odW0gZmlsdHJvIGFkaWNpb25hZG8nXG4gICAgfVxuICB9KTtcbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbi8qZXNsaW50IGFuZ3VsYXIvZmlsZS1uYW1lOiAwLCBuby11bmRlZjogMCovXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbnN0YW50KCdwdC1CUi5pMThuLm1vZGVscycsIHtcbiAgICB1c2VyOiAnVXN1w6FyaW8nLFxuICAgIHRhc2s6ICdUYXJlZmEnLFxuICAgIHByb2plY3Q6ICdQcm9qZXRvJ1xuICB9KTtcbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbi8qZXNsaW50IGFuZ3VsYXIvZmlsZS1uYW1lOiAwLCBuby11bmRlZjogMCovXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbnN0YW50KCdwdC1CUi5pMThuLnZpZXdzJywge1xuICAgIGJyZWFkY3J1bWJzOiB7XG4gICAgICB1c2VyOiAnQWRtaW5pc3RyYcOnw6NvIC0gVXN1w6FyaW8nLFxuICAgICAgJ3VzZXItcHJvZmlsZSc6ICdQZXJmaWwnLFxuICAgICAgZGFzaGJvYXJkOiAnRGFzaGJvYXJkJyxcbiAgICAgIGF1ZGl0OiAnQWRtaW5pc3RyYcOnw6NvIC0gQXVkaXRvcmlhJyxcbiAgICAgIG1haWw6ICdBZG1pbmlzdHJhw6fDo28gLSBFbnZpbyBkZSBlLW1haWwnLFxuICAgICAgcHJvamVjdDogJ0V4ZW1wbG9zIC0gUHJvamV0b3MnLFxuICAgICAgJ2RpbmFtaWMtcXVlcnknOiAnQWRtaW5pc3RyYcOnw6NvIC0gQ29uc3VsdGFzIERpbsOibWljYXMnLFxuICAgICAgJ25vdC1hdXRob3JpemVkJzogJ0FjZXNzbyBOZWdhZG8nXG4gICAgfSxcbiAgICB0aXRsZXM6IHtcbiAgICAgIGRhc2hib2FyZDogJ1DDoWdpbmEgaW5pY2lhbCcsXG4gICAgICBtYWlsU2VuZDogJ0VudmlhciBlLW1haWwnLFxuICAgICAgdGFza0xpc3Q6ICdMaXN0YSBkZSBUYXJlZmFzJyxcbiAgICAgIHVzZXJMaXN0OiAnTGlzdGEgZGUgVXN1w6FyaW9zJyxcbiAgICAgIGF1ZGl0TGlzdDogJ0xpc3RhIGRlIExvZ3MnLFxuICAgICAgcmVnaXN0ZXI6ICdGb3JtdWzDoXJpbyBkZSBDYWRhc3RybycsXG4gICAgICByZXNldFBhc3N3b3JkOiAnUmVkZWZpbmlyIFNlbmhhJyxcbiAgICAgIHVwZGF0ZTogJ0Zvcm11bMOhcmlvIGRlIEF0dWFsaXphw6fDo28nXG4gICAgfSxcbiAgICBhY3Rpb25zOiB7XG4gICAgICBzZW5kOiAnRW52aWFyJyxcbiAgICAgIHNhdmU6ICdTYWx2YXInLFxuICAgICAgY2xlYXI6ICdMaW1wYXInLFxuICAgICAgY2xlYXJBbGw6ICdMaW1wYXIgVHVkbycsXG4gICAgICByZXN0YXJ0OiAnUmVpbmljaWFyJyxcbiAgICAgIGZpbHRlcjogJ0ZpbHRyYXInLFxuICAgICAgc2VhcmNoOiAnUGVzcXVpc2FyJyxcbiAgICAgIGxpc3Q6ICdMaXN0YXInLFxuICAgICAgZWRpdDogJ0VkaXRhcicsXG4gICAgICBjYW5jZWw6ICdDYW5jZWxhcicsXG4gICAgICB1cGRhdGU6ICdBdHVhbGl6YXInLFxuICAgICAgcmVtb3ZlOiAnUmVtb3ZlcicsXG4gICAgICBnZXRPdXQ6ICdTYWlyJyxcbiAgICAgIGFkZDogJ0FkaWNpb25hcicsXG4gICAgICBpbjogJ0VudHJhcicsXG4gICAgICBsb2FkSW1hZ2U6ICdDYXJyZWdhciBJbWFnZW0nLFxuICAgICAgc2lnbnVwOiAnQ2FkYXN0cmFyJ1xuICAgIH0sXG4gICAgZmllbGRzOiB7XG4gICAgICBkYXRlOiAnRGF0YScsXG4gICAgICBhY3Rpb246ICdBw6fDo28nLFxuICAgICAgYWN0aW9uczogJ0HDp8O1ZXMnLFxuICAgICAgYXVkaXQ6IHtcbiAgICAgICAgZGF0ZVN0YXJ0OiAnRGF0YSBJbmljaWFsJyxcbiAgICAgICAgZGF0ZUVuZDogJ0RhdGEgRmluYWwnLFxuICAgICAgICByZXNvdXJjZTogJ1JlY3Vyc28nLFxuICAgICAgICBhbGxSZXNvdXJjZXM6ICdUb2RvcyBSZWN1cnNvcycsXG4gICAgICAgIHR5cGU6IHtcbiAgICAgICAgICBjcmVhdGVkOiAnQ2FkYXN0cmFkbycsXG4gICAgICAgICAgdXBkYXRlZDogJ0F0dWFsaXphZG8nLFxuICAgICAgICAgIGRlbGV0ZWQ6ICdSZW1vdmlkbydcbiAgICAgICAgfVxuICAgICAgfSxcbiAgICAgIGxvZ2luOiB7XG4gICAgICAgIHJlc2V0UGFzc3dvcmQ6ICdFc3F1ZWNpIG1pbmhhIHNlbmhhJyxcbiAgICAgICAgY29uZmlybVBhc3N3b3JkOiAnQ29uZmlybWFyIHNlbmhhJ1xuICAgICAgfSxcbiAgICAgIG1haWw6IHtcbiAgICAgICAgdG86ICdQYXJhJyxcbiAgICAgICAgc3ViamVjdDogJ0Fzc3VudG8nLFxuICAgICAgICBtZXNzYWdlOiAnTWVuc2FnZW0nXG4gICAgICB9LFxuICAgICAgcXVlcnlEaW5hbWljOiB7XG4gICAgICAgIGZpbHRlcnM6ICdGaWx0cm9zJyxcbiAgICAgICAgcmVzdWx0czogJ1Jlc3VsdGFkb3MnLFxuICAgICAgICBtb2RlbDogJ01vZGVsJyxcbiAgICAgICAgYXR0cmlidXRlOiAnQXRyaWJ1dG8nLFxuICAgICAgICBvcGVyYXRvcjogJ09wZXJhZG9yJyxcbiAgICAgICAgcmVzb3VyY2U6ICdSZWN1cnNvJyxcbiAgICAgICAgdmFsdWU6ICdWYWxvcicsXG4gICAgICAgIG9wZXJhdG9yczoge1xuICAgICAgICAgIGVxdWFsczogJ0lndWFsJyxcbiAgICAgICAgICBkaWZlcmVudDogJ0RpZmVyZW50ZScsXG4gICAgICAgICAgY29udGVpbnM6ICdDb250w6ltJyxcbiAgICAgICAgICBzdGFydFdpdGg6ICdJbmljaWEgY29tJyxcbiAgICAgICAgICBmaW5pc2hXaXRoOiAnRmluYWxpemEgY29tJyxcbiAgICAgICAgICBiaWdnZXJUaGFuOiAnTWFpb3InLFxuICAgICAgICAgIGVxdWFsc09yQmlnZ2VyVGhhbjogJ01haW9yIG91IElndWFsJyxcbiAgICAgICAgICBsZXNzVGhhbjogJ01lbm9yJyxcbiAgICAgICAgICBlcXVhbHNPckxlc3NUaGFuOiAnTWVub3Igb3UgSWd1YWwnXG4gICAgICAgIH1cbiAgICAgIH0sXG4gICAgICBwcm9qZWN0OiB7XG4gICAgICAgIG5hbWU6ICdOb21lJyxcbiAgICAgICAgdG90YWxUYXNrOiAnVG90YWwgZGUgVGFyZWZhcydcbiAgICAgIH0sXG4gICAgICB0YXNrOiB7XG4gICAgICAgIGRvbmU6ICdOw6NvIEZlaXRvIC8gRmVpdG8nXG4gICAgICB9LFxuICAgICAgdXNlcjoge1xuICAgICAgICBwZXJmaWxzOiAnUGVyZmlzJyxcbiAgICAgICAgbmFtZU9yRW1haWw6ICdOb21lIG91IEVtYWlsJ1xuICAgICAgfVxuICAgIH0sXG4gICAgbGF5b3V0OiB7XG4gICAgICBtZW51OiB7XG4gICAgICAgIGRhc2hib2FyZDogJ0Rhc2hib2FyZCcsXG4gICAgICAgIHByb2plY3Q6ICdQcm9qZXRvcycsXG4gICAgICAgIGFkbWluOiAnQWRtaW5pc3RyYcOnw6NvJyxcbiAgICAgICAgZXhhbXBsZXM6ICdFeGVtcGxvcycsXG4gICAgICAgIHVzZXI6ICdVc3XDoXJpb3MnLFxuICAgICAgICBtYWlsOiAnRW52aWFyIGUtbWFpbCcsXG4gICAgICAgIGF1ZGl0OiAnQXVkaXRvcmlhJyxcbiAgICAgICAgZGluYW1pY1F1ZXJ5OiAnQ29uc3VsdGFzIERpbmFtaWNhcydcbiAgICAgIH1cbiAgICB9LFxuICAgIHRvb2x0aXBzOiB7XG4gICAgICBhdWRpdDoge1xuICAgICAgICB2aWV3RGV0YWlsOiAnVmlzdWFsaXphciBEZXRhbGhhbWVudG8nXG4gICAgICB9LFxuICAgICAgdXNlcjoge1xuICAgICAgICBwZXJmaWw6ICdQZXJmaWwnLFxuICAgICAgICB0cmFuc2ZlcjogJ1RyYW5zZmVyaXInXG4gICAgICB9LFxuICAgICAgdGFzazoge1xuICAgICAgICBsaXN0VGFzazogJ0xpc3RhciBUYXJlZmFzJ1xuICAgICAgfVxuICAgIH1cbiAgfSk7XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29udHJvbGxlcignUHJvamVjdHNDb250cm9sbGVyJywgUHJvamVjdHNDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIFByb2plY3RzQ29udHJvbGxlcihHbG9iYWwsICRjb250cm9sbGVyLCBQcm9qZWN0c1NlcnZpY2UsIFByRGlhbG9nKSB7XG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIC8vQXR0cmlidXRlcyBCbG9ja1xuXG4gICAgLy9GdW5jdGlvbnMgQmxvY2tcbiAgICB2bS5vbkFjdGl2YXRlID0gb25BY3RpdmF0ZTtcbiAgICB2bS5hcHBseUZpbHRlcnMgPSBhcHBseUZpbHRlcnM7XG4gICAgdm0udmlld1Rhc2tzID0gdmlld1Rhc2tzO1xuXG4gICAgLy8gaW5zdGFudGlhdGUgYmFzZSBjb250cm9sbGVyXG4gICAgJGNvbnRyb2xsZXIoJ0NSVURDb250cm9sbGVyJywgeyB2bTogdm0sIG1vZGVsU2VydmljZTogUHJvamVjdHNTZXJ2aWNlLCBvcHRpb25zOiB7fSB9KTtcblxuICAgIGZ1bmN0aW9uIG9uQWN0aXZhdGUoKSB7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMgPSB7fTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBhcHBseUZpbHRlcnMoZGVmYXVsdFF1ZXJ5RmlsdGVycykge1xuICAgICAgcmV0dXJuIGFuZ3VsYXIuZXh0ZW5kKGRlZmF1bHRRdWVyeUZpbHRlcnMsIHZtLnF1ZXJ5RmlsdGVycyk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gdmlld1Rhc2tzKHByb2plY3RJZCkge1xuICAgICAgdmFyIGNvbmZpZyA9IHtcbiAgICAgICAgbG9jYWxzOiB7XG4gICAgICAgICAgcHJvamVjdElkOiBwcm9qZWN0SWRcbiAgICAgICAgfSxcbiAgICAgICAgY29udHJvbGxlcjogJ1Rhc2tzRGlhbG9nQ29udHJvbGxlcicsXG4gICAgICAgIGNvbnRyb2xsZXJBczogJ3Rhc2tzQ3RybCcsXG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvc2FtcGxlcy90YXNrcy90YXNrcy1kaWFsb2cuaHRtbCcsXG4gICAgICAgIGhhc0JhY2tkcm9wOiB0cnVlXG4gICAgICB9O1xuXG4gICAgICBQckRpYWxvZy5jdXN0b20oY29uZmlnKS5maW5hbGx5KGZ1bmN0aW9uICgpIHtcbiAgICAgICAgdm0uc2VhcmNoKHZtLnBhZ2luYXRvci5jdXJyZW50UGFnZSk7XG4gICAgICB9KTtcbiAgICB9XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqXG4gICAqIEFycXVpdm8gZGUgY29uZmlndXJhw6fDo28gY29tIGFzIHJvdGFzIGVzcGVjw61maWNhcyBkbyByZWN1cnNvIHByb2plY3RcbiAgICpcbiAgICogQHBhcmFtIHthbnl9ICRzdGF0ZVByb3ZpZGVyXG4gICAqIEBwYXJhbSB7YW55fSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnYXBwLnByb2plY3QnLCB7XG4gICAgICB1cmw6ICcvcHJvamV0b3MnLFxuICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9zYW1wbGVzL3Byb2plY3RzL3Byb2plY3RzLmh0bWwnLFxuICAgICAgY29udHJvbGxlcjogJ1Byb2plY3RzQ29udHJvbGxlciBhcyBwcm9qZWN0c0N0cmwnLFxuICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IHRydWUsIG5lZWRQcm9maWxlOiBbJ2FkbWluJ10gfVxuICAgIH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZhY3RvcnkoJ1Byb2plY3RzU2VydmljZScsIFByb2plY3RzU2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiBQcm9qZWN0c1NlcnZpY2Uoc2VydmljZUZhY3RvcnkpIHtcbiAgICByZXR1cm4gc2VydmljZUZhY3RvcnkoJ3Byb2plY3RzJywge1xuICAgICAgYWN0aW9uczoge30sXG4gICAgICBpbnN0YW5jZToge31cbiAgICB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbnRyb2xsZXIoJ1Rhc2tzRGlhbG9nQ29udHJvbGxlcicsIFRhc2tzRGlhbG9nQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBUYXNrc0RpYWxvZ0NvbnRyb2xsZXIoJGNvbnRyb2xsZXIsIFRhc2tzU2VydmljZSwgcHJvamVjdElkLCBQclRvYXN0LCAvLyBOT1NPTkFSXG4gIFByRGlhbG9nLCAkdHJhbnNsYXRlLCBHbG9iYWwsIG1vbWVudCkge1xuXG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIC8vRnVuY3Rpb25zIEJsb2NrXG4gICAgdm0ub25BY3RpdmF0ZSA9IG9uQWN0aXZhdGU7XG4gICAgdm0uY2xvc2UgPSBjbG9zZTtcbiAgICB2bS5hcHBseUZpbHRlcnMgPSBhcHBseUZpbHRlcnM7XG4gICAgdm0uYmVmb3JlU2F2ZSA9IGJlZm9yZVNhdmU7XG4gICAgdm0uYWZ0ZXJTYXZlID0gYWZ0ZXJTYXZlO1xuICAgIHZtLnRvZ2dsZURvbmUgPSB0b2dnbGVEb25lO1xuXG4gICAgLy8gaW5zdGFudGlhdGUgYmFzZSBjb250cm9sbGVyXG4gICAgJGNvbnRyb2xsZXIoJ0NSVURDb250cm9sbGVyJywgeyB2bTogdm0sIG1vZGVsU2VydmljZTogVGFza3NTZXJ2aWNlLCBvcHRpb25zOiB7XG4gICAgICAgIHBlclBhZ2U6IDVcbiAgICAgIH0gfSk7XG5cbiAgICBmdW5jdGlvbiBvbkFjdGl2YXRlKCkge1xuICAgICAgdm0uZ2xvYmFsID0gR2xvYmFsO1xuICAgICAgdm0ucmVzb3VyY2Uuc2NoZWR1bGVkX3RvID0gbW9tZW50KCkuYWRkKDMwLCAnbWludXRlcycpO1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0geyBwcm9qZWN0SWQ6IHByb2plY3RJZCB9O1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGFwcGx5RmlsdGVycyhkZWZhdWx0UXVlcnlGaWx0ZXJzKSB7XG4gICAgICByZXR1cm4gYW5ndWxhci5leHRlbmQoZGVmYXVsdFF1ZXJ5RmlsdGVycywgdm0ucXVlcnlGaWx0ZXJzKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBiZWZvcmVTYXZlKCkge1xuICAgICAgdm0ucmVzb3VyY2UucHJvamVjdF9pZCA9IHZtLnF1ZXJ5RmlsdGVycy5wcm9qZWN0SWQ7XG4gICAgICB2bS5yZXNvdXJjZS5wcm9qZWN0ID0gbnVsbDtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBhZnRlclNhdmUoKSB7XG4gICAgICB2bS5jbGVhbkZvcm0oKTtcbiAgICAgIHZtLnNlYXJjaCh2bS5wYWdpbmF0b3IuY3VycmVudFBhZ2UpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGNsb3NlKCkge1xuICAgICAgdm0uY2xlYW5Gb3JtKCk7XG4gICAgICBQckRpYWxvZy5jbG9zZSgpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIHRvZ2dsZURvbmUocmVzb3VyY2UpIHtcbiAgICAgIFRhc2tzU2VydmljZS50b2dnbGVEb25lKHsgaWQ6IHJlc291cmNlLmlkLCBkb25lOiByZXNvdXJjZS5kb25lIH0pLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICBQclRvYXN0LnN1Y2Nlc3MoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5zYXZlU3VjY2VzcycpKTtcbiAgICAgICAgdm0uc2VhcmNoKHZtLnBhZ2luYXRvci5jdXJyZW50UGFnZSk7XG4gICAgICB9LCBmdW5jdGlvbiAoZXJyb3IpIHtcbiAgICAgICAgUHJUb2FzdC5lcnJvclZhbGlkYXRpb24oZXJyb3IuZGF0YSwgJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5vcGVyYXRpb25FcnJvcicpKTtcbiAgICAgIH0pO1xuICAgIH1cbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5mYWN0b3J5KCdUYXNrc1NlcnZpY2UnLCBUYXNrc1NlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gVGFza3NTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5LCBtb21lbnQpIHtcbiAgICByZXR1cm4gc2VydmljZUZhY3RvcnkoJ3Rhc2tzJywge1xuICAgICAgLy9xdWFuZG8gaW5zdGFuY2lhIHVtIHVzdcOhcmlvIHNlbSBwYXNzYXIgcGFyYW1ldHJvLFxuICAgICAgLy9vIG1lc21vIHZhaSB0ZXIgb3MgdmFsb3JlcyBkZWZhdWx0cyBhYmFpeG9cbiAgICAgIGRlZmF1bHRzOiB7XG4gICAgICAgIHNjaGVkdWxlZF90bzogbmV3IERhdGUoKVxuICAgICAgfSxcblxuICAgICAgbWFwOiB7XG4gICAgICAgIC8vY29udmVydCBwYXJhIG9iamV0byBqYXZhc2NyaXB0IGRhdGUgdW1hIHN0cmluZyBmb3JtYXRhZGEgY29tbyBkYXRhXG4gICAgICAgIHNjaGVkdWxlZF90bzogZnVuY3Rpb24gc2NoZWR1bGVkX3RvKHZhbHVlKSB7XG4gICAgICAgICAgcmV0dXJuIG1vbWVudCh2YWx1ZSkudG9EYXRlKCk7XG4gICAgICAgIH1cbiAgICAgIH0sXG5cbiAgICAgIGFjdGlvbnM6IHtcbiAgICAgICAgLyoqXG4gICAgICAgICAqIEF0dWFsaXphIG9zIHN0YXR1cyBkYSB0YXJlZmFcbiAgICAgICAgICpcbiAgICAgICAgICogQHBhcmFtIHtvYmplY3R9IGF0dHJpYnV0ZXNcbiAgICAgICAgICovXG4gICAgICAgIHRvZ2dsZURvbmU6IHtcbiAgICAgICAgICBtZXRob2Q6ICdQVVQnLFxuICAgICAgICAgIHVybDogJ3RvZ2dsZURvbmUnXG4gICAgICAgIH1cbiAgICAgIH0sXG4gICAgICBpbnN0YW5jZToge31cbiAgICB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbnRyb2xsZXIoJ1VzZXJzRGlhbG9nQ29udHJvbGxlcicsIFVzZXJzRGlhbG9nQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBVc2Vyc0RpYWxvZ0NvbnRyb2xsZXIoJGNvbnRyb2xsZXIsIFVzZXJzU2VydmljZSwgUHJEaWFsb2csIC8vIE5PU09OQVJcbiAgdXNlckRpYWxvZ0lucHV0LCBvbkluaXQpIHtcblxuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICB2bS5vbkFjdGl2YXRlID0gb25BY3RpdmF0ZTtcbiAgICB2bS5hcHBseUZpbHRlcnMgPSBhcHBseUZpbHRlcnM7XG4gICAgdm0uY2xvc2UgPSBjbG9zZTtcblxuICAgIGlmIChhbmd1bGFyLmlzRGVmaW5lZCh1c2VyRGlhbG9nSW5wdXQpKSB7XG4gICAgICB2bS50cmFuc2ZlclVzZXIgPSB1c2VyRGlhbG9nSW5wdXQudHJhbnNmZXJVc2VyRm47XG4gICAgfVxuXG4gICAgLy8gaW5zdGFudGlhdGUgYmFzZSBjb250cm9sbGVyXG4gICAgJGNvbnRyb2xsZXIoJ0NSVURDb250cm9sbGVyJywge1xuICAgICAgdm06IHZtLFxuICAgICAgbW9kZWxTZXJ2aWNlOiBVc2Vyc1NlcnZpY2UsXG4gICAgICBzZWFyY2hPbkluaXQ6IG9uSW5pdCxcbiAgICAgIG9wdGlvbnM6IHtcbiAgICAgICAgcGVyUGFnZTogNVxuICAgICAgfVxuICAgIH0pO1xuXG4gICAgZnVuY3Rpb24gb25BY3RpdmF0ZSgpIHtcbiAgICAgIHZtLnF1ZXJ5RmlsdGVycyA9IHt9O1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGFwcGx5RmlsdGVycygpIHtcbiAgICAgIHJldHVybiBhbmd1bGFyLmV4dGVuZCh2bS5kZWZhdWx0UXVlcnlGaWx0ZXJzLCB2bS5xdWVyeUZpbHRlcnMpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGNsb3NlKCkge1xuICAgICAgUHJEaWFsb2cuY2xvc2UoKTtcbiAgICB9XG4gIH1cbn0pKCk7IiwiLyplc2xpbnQgYW5ndWxhci9maWxlLW5hbWU6IDAqL1xuKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcsIFtcbiAgICAnbmdBbmltYXRlJyxcbiAgICAnbmdBcmlhJyxcbiAgICAndWkucm91dGVyJyxcbiAgICAnbmdQcm9kZWInLFxuICAgICd1aS51dGlscy5tYXNrcycsXG4gICAgJ3RleHQtbWFzaycsXG4gICAgJ25nTWF0ZXJpYWwnLFxuICAgICdtb2RlbEZhY3RvcnknLFxuICAgICdtZC5kYXRhLnRhYmxlJyxcbiAgICAnbmdNYXRlcmlhbERhdGVQaWNrZXInLFxuICAgICdwYXNjYWxwcmVjaHQudHJhbnNsYXRlJyxcbiAgICAnYW5ndWxhckZpbGVVcGxvYWQnXSk7XG59KSgpO1xuIiwiKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb25maWcoY29uZmlnKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIGNvbmZpZyhHbG9iYWwsICRtZFRoZW1pbmdQcm92aWRlciwgJG1vZGVsRmFjdG9yeVByb3ZpZGVyLCAgLy8gTk9TT05BUlxuICAgICR0cmFuc2xhdGVQcm92aWRlciwgbW9tZW50LCAkbWRBcmlhUHJvdmlkZXIpIHtcblxuICAgICR0cmFuc2xhdGVQcm92aWRlclxuICAgICAgLnVzZUxvYWRlcignbGFuZ3VhZ2VMb2FkZXInKVxuICAgICAgLnVzZVNhbml0aXplVmFsdWVTdHJhdGVneSgnZXNjYXBlJyk7XG5cbiAgICAkdHJhbnNsYXRlUHJvdmlkZXIudXNlUG9zdENvbXBpbGluZyh0cnVlKTtcblxuICAgIG1vbWVudC5sb2NhbGUoJ3B0LUJSJyk7XG5cbiAgICAvL29zIHNlcnZpw6dvcyByZWZlcmVudGUgYW9zIG1vZGVscyB2YWkgdXRpbGl6YXIgY29tbyBiYXNlIG5hcyB1cmxzXG4gICAgJG1vZGVsRmFjdG9yeVByb3ZpZGVyLmRlZmF1bHRPcHRpb25zLnByZWZpeCA9IEdsb2JhbC5hcGlQYXRoO1xuXG4gICAgLy8gQ29uZmlndXJhdGlvbiB0aGVtZVxuICAgICRtZFRoZW1pbmdQcm92aWRlci50aGVtZSgnZGVmYXVsdCcpXG4gICAgICAucHJpbWFyeVBhbGV0dGUoJ2Jyb3duJywge1xuICAgICAgICBkZWZhdWx0OiAnNzAwJ1xuICAgICAgfSlcbiAgICAgIC5hY2NlbnRQYWxldHRlKCdhbWJlcicpXG4gICAgICAud2FyblBhbGV0dGUoJ2RlZXAtb3JhbmdlJyk7XG5cbiAgICAvLyBFbmFibGUgYnJvd3NlciBjb2xvclxuICAgICRtZFRoZW1pbmdQcm92aWRlci5lbmFibGVCcm93c2VyQ29sb3IoKTtcblxuICAgICRtZEFyaWFQcm92aWRlci5kaXNhYmxlV2FybmluZ3MoKTtcblxuICB9XG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29udHJvbGxlcignQXBwQ29udHJvbGxlcicsIEFwcENvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLyoqXG4gICAqIENvbnRyb2xhZG9yIHJlc3BvbnPDoXZlbCBwb3IgZnVuY2lvbmFsaWRhZGVzIHF1ZSBzw6NvIGFjaW9uYWRhcyBlbSBxdWFscXVlciB0ZWxhIGRvIHNpc3RlbWFcbiAgICpcbiAgICovXG4gIGZ1bmN0aW9uIEFwcENvbnRyb2xsZXIoJHN0YXRlLCBBdXRoLCBHbG9iYWwpIHtcbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgLy9hbm8gYXR1YWwgcGFyYSBzZXIgZXhpYmlkbyBubyByb2RhcMOpIGRvIHNpc3RlbWFcbiAgICB2bS5hbm9BdHVhbCA9IG51bGw7XG5cbiAgICB2bS5sb2dvdXQgICAgID0gbG9nb3V0O1xuICAgIHZtLmdldEltYWdlUGVyZmlsID0gZ2V0SW1hZ2VQZXJmaWw7XG5cbiAgICBhY3RpdmF0ZSgpO1xuXG4gICAgZnVuY3Rpb24gYWN0aXZhdGUoKSB7XG4gICAgICB2YXIgZGF0ZSA9IG5ldyBEYXRlKCk7XG5cbiAgICAgIHZtLmFub0F0dWFsID0gZGF0ZS5nZXRGdWxsWWVhcigpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGxvZ291dCgpIHtcbiAgICAgIEF1dGgubG9nb3V0KCkudGhlbihmdW5jdGlvbigpIHtcbiAgICAgICAgJHN0YXRlLmdvKEdsb2JhbC5sb2dpblN0YXRlKTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGdldEltYWdlUGVyZmlsKCkge1xuICAgICAgcmV0dXJuIChBdXRoLmN1cnJlbnRVc2VyICYmIEF1dGguY3VycmVudFVzZXIuaW1hZ2UpXG4gICAgICAgID8gQXV0aC5jdXJyZW50VXNlci5pbWFnZVxuICAgICAgICA6IEdsb2JhbC5pbWFnZVBhdGggKyAnL25vX2F2YXRhci5naWYnO1xuICAgIH1cblxuICB9XG5cbn0pKCk7XG4iLCIvKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCwgbm8tdW5kZWY6IDAqL1xuKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgLyoqXG4gICAqIFRyYW5zZm9ybWEgYmlibGlvdGVjYXMgZXh0ZXJuYXMgZW0gc2VydmnDp29zIGRvIGFuZ3VsYXIgcGFyYSBzZXIgcG9zc8OtdmVsIHV0aWxpemFyXG4gICAqIGF0cmF2w6lzIGRhIGluamXDp8OjbyBkZSBkZXBlbmTDqm5jaWFcbiAgICovXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb25zdGFudCgnbG9kYXNoJywgXylcbiAgICAuY29uc3RhbnQoJ21vbWVudCcsIG1vbWVudCk7XG5cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uc3RhbnQoJ0dsb2JhbCcsIHtcbiAgICAgIGFwcE5hbWU6ICdGcmVlbGFnaWxlJyxcbiAgICAgIGhvbWVTdGF0ZTogJ2FwcC5kYXNoYm9hcmQnLFxuICAgICAgbG9naW5Vcmw6ICdhcHAvbG9naW4nLFxuICAgICAgbG9naW5TdGF0ZTogJ2FwcC5sb2dpbicsXG4gICAgICByZXNldFBhc3N3b3JkU3RhdGU6ICdhcHAucGFzc3dvcmQtcmVzZXQnLFxuICAgICAgbm90QXV0aG9yaXplZFN0YXRlOiAnYXBwLm5vdC1hdXRob3JpemVkJyxcbiAgICAgIHRva2VuS2V5OiAnc2VydmVyX3Rva2VuJyxcbiAgICAgIGNsaWVudFBhdGg6ICdjbGllbnQvYXBwJyxcbiAgICAgIGFwaVBhdGg6ICdhcGkvdjEnLFxuICAgICAgaW1hZ2VQYXRoOiAnY2xpZW50L2ltYWdlcydcbiAgICB9KTtcbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsICR1cmxSb3V0ZXJQcm92aWRlciwgR2xvYmFsKSB7XG4gICAgJHN0YXRlUHJvdmlkZXJcbiAgICAgIC5zdGF0ZSgnYXBwJywge1xuICAgICAgICB1cmw6ICcvYXBwJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9sYXlvdXQvYXBwLmh0bWwnLFxuICAgICAgICBhYnN0cmFjdDogdHJ1ZSxcbiAgICAgICAgcmVzb2x2ZTogeyAvL2Vuc3VyZSBsYW5ncyBpcyByZWFkeSBiZWZvcmUgcmVuZGVyIHZpZXdcbiAgICAgICAgICB0cmFuc2xhdGVSZWFkeTogWyckdHJhbnNsYXRlJywgJyRxJywgZnVuY3Rpb24oJHRyYW5zbGF0ZSwgJHEpIHtcbiAgICAgICAgICAgIHZhciBkZWZlcnJlZCA9ICRxLmRlZmVyKCk7XG5cbiAgICAgICAgICAgICR0cmFuc2xhdGUudXNlKCdwdC1CUicpLnRoZW4oZnVuY3Rpb24oKSB7XG4gICAgICAgICAgICAgIGRlZmVycmVkLnJlc29sdmUoKTtcbiAgICAgICAgICAgIH0pO1xuXG4gICAgICAgICAgICByZXR1cm4gZGVmZXJyZWQucHJvbWlzZTtcbiAgICAgICAgICB9XVxuICAgICAgICB9XG4gICAgICB9KVxuICAgICAgLnN0YXRlKEdsb2JhbC5ub3RBdXRob3JpemVkU3RhdGUsIHtcbiAgICAgICAgdXJsOiAnL2FjZXNzby1uZWdhZG8nLFxuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL2xheW91dC9ub3QtYXV0aG9yaXplZC5odG1sJyxcbiAgICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IGZhbHNlIH1cbiAgICAgIH0pO1xuXG4gICAgJHVybFJvdXRlclByb3ZpZGVyLndoZW4oJy9hcHAnLCBHbG9iYWwubG9naW5VcmwpO1xuICAgICR1cmxSb3V0ZXJQcm92aWRlci5vdGhlcndpc2UoR2xvYmFsLmxvZ2luVXJsKTtcbiAgfVxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5ydW4ocnVuKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIHJ1bigkcm9vdFNjb3BlLCAkc3RhdGUsICRzdGF0ZVBhcmFtcywgQXV0aCwgR2xvYmFsKSB7IC8vIE5PU09OQVJcbiAgICAvL3NldGFkbyBubyByb290U2NvcGUgcGFyYSBwb2RlciBzZXIgYWNlc3NhZG8gbmFzIHZpZXdzIHNlbSBwcmVmaXhvIGRlIGNvbnRyb2xsZXJcbiAgICAkcm9vdFNjb3BlLiRzdGF0ZSA9ICRzdGF0ZTtcbiAgICAkcm9vdFNjb3BlLiRzdGF0ZVBhcmFtcyA9ICRzdGF0ZVBhcmFtcztcbiAgICAkcm9vdFNjb3BlLmF1dGggPSBBdXRoO1xuICAgICRyb290U2NvcGUuZ2xvYmFsID0gR2xvYmFsO1xuXG4gICAgLy9ubyBpbmljaW8gY2FycmVnYSBvIHVzdcOhcmlvIGRvIGxvY2Fsc3RvcmFnZSBjYXNvIG8gdXN1w6FyaW8gZXN0YWphIGFicmluZG8gbyBuYXZlZ2Fkb3JcbiAgICAvL3BhcmEgdm9sdGFyIGF1dGVudGljYWRvXG4gICAgQXV0aC5yZXRyaWV2ZVVzZXJGcm9tTG9jYWxTdG9yYWdlKCk7XG4gIH1cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb250cm9sbGVyKCdBdWRpdENvbnRyb2xsZXInLCBBdWRpdENvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gQXVkaXRDb250cm9sbGVyKCRjb250cm9sbGVyLCBBdWRpdFNlcnZpY2UsIFByRGlhbG9nLCBHbG9iYWwsICR0cmFuc2xhdGUpIHsgLy8gTk9TT05BUlxuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICB2bS5vbkFjdGl2YXRlID0gb25BY3RpdmF0ZTtcbiAgICB2bS5hcHBseUZpbHRlcnMgPSBhcHBseUZpbHRlcnM7XG4gICAgdm0udmlld0RldGFpbCA9IHZpZXdEZXRhaWw7XG5cbiAgICAkY29udHJvbGxlcignQ1JVRENvbnRyb2xsZXInLCB7IHZtOiB2bSwgbW9kZWxTZXJ2aWNlOiBBdWRpdFNlcnZpY2UsIG9wdGlvbnM6IHt9IH0pO1xuXG4gICAgZnVuY3Rpb24gb25BY3RpdmF0ZSgpIHtcbiAgICAgIHZtLm1vZGVscyA9IFtdO1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0ge307XG5cbiAgICAgIC8vUGVnYSB0b2RvcyBvcyBtb2RlbHMgZG8gc2VydmVyIGUgbW9udGEgdW1hIGxpc3RhIHBybyBDb21ib0JveFxuICAgICAgQXVkaXRTZXJ2aWNlLmdldEF1ZGl0ZWRNb2RlbHMoKS50aGVuKGZ1bmN0aW9uKGRhdGEpIHtcbiAgICAgICAgdmFyIG1vZGVscyA9IFt7IGlkOiAnJywgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudCgnZ2xvYmFsLmFsbCcpIH1dO1xuXG4gICAgICAgIGRhdGEubW9kZWxzLnNvcnQoKTtcblxuICAgICAgICBmb3IgKHZhciBpbmRleCA9IDA7IGluZGV4IDwgZGF0YS5tb2RlbHMubGVuZ3RoOyBpbmRleCsrKSB7XG4gICAgICAgICAgdmFyIG1vZGVsID0gZGF0YS5tb2RlbHNbaW5kZXhdO1xuXG4gICAgICAgICAgbW9kZWxzLnB1c2goe1xuICAgICAgICAgICAgaWQ6IG1vZGVsLFxuICAgICAgICAgICAgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudCgnbW9kZWxzLicgKyBtb2RlbC50b0xvd2VyQ2FzZSgpKVxuICAgICAgICAgIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgdm0ubW9kZWxzID0gbW9kZWxzO1xuICAgICAgICB2bS5xdWVyeUZpbHRlcnMubW9kZWwgPSB2bS5tb2RlbHNbMF0uaWQ7XG4gICAgICB9KTtcblxuICAgICAgdm0udHlwZXMgPSBBdWRpdFNlcnZpY2UubGlzdFR5cGVzKCk7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMudHlwZSA9IHZtLnR5cGVzWzBdLmlkO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGFwcGx5RmlsdGVycyhkZWZhdWx0UXVlcnlGaWx0ZXJzKSB7XG4gICAgICByZXR1cm4gYW5ndWxhci5leHRlbmQoZGVmYXVsdFF1ZXJ5RmlsdGVycywgdm0ucXVlcnlGaWx0ZXJzKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiB2aWV3RGV0YWlsKGF1ZGl0RGV0YWlsKSB7XG4gICAgICB2YXIgY29uZmlnID0ge1xuICAgICAgICBsb2NhbHM6IHsgYXVkaXREZXRhaWw6IGF1ZGl0RGV0YWlsIH0sXG4gICAgICAgIC8qKiBAbmdJbmplY3QgKi9cbiAgICAgICAgY29udHJvbGxlcjogZnVuY3Rpb24oYXVkaXREZXRhaWwsIFByRGlhbG9nKSB7XG4gICAgICAgICAgdmFyIHZtID0gdGhpcztcblxuICAgICAgICAgIHZtLmNsb3NlID0gY2xvc2U7XG5cbiAgICAgICAgICBhY3RpdmF0ZSgpO1xuXG4gICAgICAgICAgZnVuY3Rpb24gYWN0aXZhdGUoKSB7XG4gICAgICAgICAgICBpZiAoYW5ndWxhci5pc0FycmF5KGF1ZGl0RGV0YWlsLm9sZCkgJiYgYXVkaXREZXRhaWwub2xkLmxlbmd0aCA9PT0gMCkgYXVkaXREZXRhaWwub2xkID0gbnVsbDtcbiAgICAgICAgICAgIGlmIChhbmd1bGFyLmlzQXJyYXkoYXVkaXREZXRhaWwubmV3KSAmJiBhdWRpdERldGFpbC5uZXcubGVuZ3RoID09PSAwKSBhdWRpdERldGFpbC5uZXcgPSBudWxsO1xuXG4gICAgICAgICAgICB2bS5hdWRpdERldGFpbCA9IGF1ZGl0RGV0YWlsO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIGZ1bmN0aW9uIGNsb3NlKCkge1xuICAgICAgICAgICAgUHJEaWFsb2cuY2xvc2UoKTtcbiAgICAgICAgICB9XG5cbiAgICAgICAgfSxcbiAgICAgICAgY29udHJvbGxlckFzOiAnYXVkaXREZXRhaWxDdHJsJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9hdWRpdC9hdWRpdC1kZXRhaWwuaHRtbCcsXG4gICAgICAgIGhhc0JhY2tkcm9wOiB0cnVlXG4gICAgICB9O1xuXG4gICAgICBQckRpYWxvZy5jdXN0b20oY29uZmlnKTtcbiAgICB9XG5cbiAgfVxuXG59KSgpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKlxuICAgKiBBcnF1aXZvIGRlIGNvbmZpZ3VyYcOnw6NvIGNvbSBhcyByb3RhcyBlc3BlY8OtZmljYXMgZGUgYXVkaXRvcmlhXG4gICAqXG4gICAqIEBwYXJhbSB7YW55fSAkc3RhdGVQcm92aWRlclxuICAgKiBAcGFyYW0ge2FueX0gR2xvYmFsXG4gICAqL1xuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvdXRlcygkc3RhdGVQcm92aWRlciwgR2xvYmFsKSB7XG4gICAgJHN0YXRlUHJvdmlkZXJcbiAgICAgIC5zdGF0ZSgnYXBwLmF1ZGl0Jywge1xuICAgICAgICB1cmw6ICcvYXVkaXRvcmlhJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9hdWRpdC9hdWRpdC5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ0F1ZGl0Q29udHJvbGxlciBhcyBhdWRpdEN0cmwnLFxuICAgICAgICBkYXRhOiB7IG5lZWRBdXRoZW50aWNhdGlvbjogdHJ1ZSwgbmVlZFByb2ZpbGU6IFsnYWRtaW4nXSB9XG4gICAgICB9KTtcblxuICB9XG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZhY3RvcnkoJ0F1ZGl0U2VydmljZScsIEF1ZGl0U2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBBdWRpdFNlcnZpY2Uoc2VydmljZUZhY3RvcnksICR0cmFuc2xhdGUpIHtcbiAgICByZXR1cm4gc2VydmljZUZhY3RvcnkoJ2F1ZGl0Jywge1xuICAgICAgYWN0aW9uczoge1xuICAgICAgICBnZXRBdWRpdGVkTW9kZWxzOiB7XG4gICAgICAgICAgbWV0aG9kOiAnR0VUJyxcbiAgICAgICAgICB1cmw6ICdtb2RlbHMnXG4gICAgICAgIH1cbiAgICAgIH0sXG4gICAgICBpbnN0YW5jZToge1xuICAgICAgfSxcbiAgICAgIGxpc3RUeXBlczogZnVuY3Rpb24oKSB7XG4gICAgICAgIHZhciBhdWRpdFBhdGggPSAndmlld3MuZmllbGRzLmF1ZGl0Lic7XG5cbiAgICAgICAgcmV0dXJuIFtcbiAgICAgICAgICB7IGlkOiAnJywgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudChhdWRpdFBhdGggKyAnYWxsUmVzb3VyY2VzJykgfSxcbiAgICAgICAgICB7IGlkOiAnY3JlYXRlZCcsIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoYXVkaXRQYXRoICsgJ3R5cGUuY3JlYXRlZCcpIH0sXG4gICAgICAgICAgeyBpZDogJ3VwZGF0ZWQnLCBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KGF1ZGl0UGF0aCArICd0eXBlLnVwZGF0ZWQnKSB9LFxuICAgICAgICAgIHsgaWQ6ICdkZWxldGVkJywgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudChhdWRpdFBhdGggKyAndHlwZS5kZWxldGVkJykgfVxuICAgICAgICBdO1xuICAgICAgfVxuICAgIH0pO1xuICB9XG5cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqXG4gICAqIEFycXVpdm8gZGUgY29uZmlndXJhw6fDo28gY29tIGFzIHJvdGFzIGVzcGVjw61maWNhcyBkbyByZWN1cnNvIHVzZXJcbiAgICpcbiAgICogQHBhcmFtIHthbnl9ICRzdGF0ZVByb3ZpZGVyXG4gICAqIEBwYXJhbSB7YW55fSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlclxuICAgICAgLnN0YXRlKEdsb2JhbC5yZXNldFBhc3N3b3JkU3RhdGUsIHtcbiAgICAgICAgdXJsOiAnL3Bhc3N3b3JkL3Jlc2V0Lzp0b2tlbicsXG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvYXV0aC9yZXNldC1wYXNzLWZvcm0uaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdQYXNzd29yZENvbnRyb2xsZXIgYXMgcGFzc0N0cmwnLFxuICAgICAgICBkYXRhOiB7IG5lZWRBdXRoZW50aWNhdGlvbjogZmFsc2UgfVxuICAgICAgfSlcbiAgICAgIC5zdGF0ZShHbG9iYWwubG9naW5TdGF0ZSwge1xuICAgICAgICB1cmw6ICcvbG9naW4nLFxuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL2F1dGgvbG9naW4uaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdMb2dpbkNvbnRyb2xsZXIgYXMgbG9naW5DdHJsJyxcbiAgICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IGZhbHNlIH1cbiAgICAgIH0pO1xuXG4gIH1cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmFjdG9yeSgnQXV0aCcsIEF1dGgpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gQXV0aCgkaHR0cCwgJHEsIEdsb2JhbCwgVXNlcnNTZXJ2aWNlKSB7IC8vIE5PU09OQVJcbiAgICB2YXIgYXV0aCA9IHtcbiAgICAgIGxvZ2luOiBsb2dpbixcbiAgICAgIGxvZ291dDogbG9nb3V0LFxuICAgICAgdXBkYXRlQ3VycmVudFVzZXI6IHVwZGF0ZUN1cnJlbnRVc2VyLFxuICAgICAgcmV0cmlldmVVc2VyRnJvbUxvY2FsU3RvcmFnZTogcmV0cmlldmVVc2VyRnJvbUxvY2FsU3RvcmFnZSxcbiAgICAgIGF1dGhlbnRpY2F0ZWQ6IGF1dGhlbnRpY2F0ZWQsXG4gICAgICBzZW5kRW1haWxSZXNldFBhc3N3b3JkOiBzZW5kRW1haWxSZXNldFBhc3N3b3JkLFxuICAgICAgcmVtb3RlVmFsaWRhdGVUb2tlbjogcmVtb3RlVmFsaWRhdGVUb2tlbixcbiAgICAgIGdldFRva2VuOiBnZXRUb2tlbixcbiAgICAgIHNldFRva2VuOiBzZXRUb2tlbixcbiAgICAgIGNsZWFyVG9rZW46IGNsZWFyVG9rZW4sXG4gICAgICBjdXJyZW50VXNlcjogbnVsbFxuICAgIH07XG5cbiAgICBmdW5jdGlvbiBjbGVhclRva2VuKCkge1xuICAgICAgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oR2xvYmFsLnRva2VuS2V5KTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBzZXRUb2tlbih0b2tlbikge1xuICAgICAgbG9jYWxTdG9yYWdlLnNldEl0ZW0oR2xvYmFsLnRva2VuS2V5LCB0b2tlbik7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gZ2V0VG9rZW4oKSB7XG4gICAgICByZXR1cm4gbG9jYWxTdG9yYWdlLmdldEl0ZW0oR2xvYmFsLnRva2VuS2V5KTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiByZW1vdGVWYWxpZGF0ZVRva2VuKCkge1xuICAgICAgdmFyIGRlZmVycmVkID0gJHEuZGVmZXIoKTtcblxuICAgICAgaWYgKGF1dGguYXV0aGVudGljYXRlZCgpKSB7XG4gICAgICAgICRodHRwLmdldChHbG9iYWwuYXBpUGF0aCArICcvYXV0aGVudGljYXRlL2NoZWNrJylcbiAgICAgICAgICAudGhlbihmdW5jdGlvbigpIHtcbiAgICAgICAgICAgIGRlZmVycmVkLnJlc29sdmUodHJ1ZSk7XG4gICAgICAgICAgfSwgZnVuY3Rpb24oKSB7XG4gICAgICAgICAgICBhdXRoLmxvZ291dCgpO1xuXG4gICAgICAgICAgICBkZWZlcnJlZC5yZWplY3QoZmFsc2UpO1xuICAgICAgICAgIH0pO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgYXV0aC5sb2dvdXQoKTtcblxuICAgICAgICBkZWZlcnJlZC5yZWplY3QoZmFsc2UpO1xuICAgICAgfVxuXG4gICAgICByZXR1cm4gZGVmZXJyZWQucHJvbWlzZTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBWZXJpZmljYSBzZSBvIHVzdcOhcmlvIGVzdMOhIGF1dGVudGljYWRvXG4gICAgICpcbiAgICAgKiBAcmV0dXJucyB7Ym9vbGVhbn1cbiAgICAgKi9cbiAgICBmdW5jdGlvbiBhdXRoZW50aWNhdGVkKCkge1xuICAgICAgcmV0dXJuIGF1dGguZ2V0VG9rZW4oKSAhPT0gbnVsbFxuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlY3VwZXJhIG8gdXN1w6FyaW8gZG8gbG9jYWxTdG9yYWdlXG4gICAgICovXG4gICAgZnVuY3Rpb24gcmV0cmlldmVVc2VyRnJvbUxvY2FsU3RvcmFnZSgpIHtcbiAgICAgIHZhciB1c2VyID0gbG9jYWxTdG9yYWdlLmdldEl0ZW0oJ3VzZXInKTtcblxuICAgICAgaWYgKHVzZXIpIHtcbiAgICAgICAgYXV0aC5jdXJyZW50VXNlciA9IGFuZ3VsYXIubWVyZ2UobmV3IFVzZXJzU2VydmljZSgpLCBhbmd1bGFyLmZyb21Kc29uKHVzZXIpKTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBHdWFyZGEgbyB1c3XDoXJpbyBubyBsb2NhbFN0b3JhZ2UgcGFyYSBjYXNvIG8gdXN1w6FyaW8gZmVjaGUgZSBhYnJhIG8gbmF2ZWdhZG9yXG4gICAgICogZGVudHJvIGRvIHRlbXBvIGRlIHNlc3PDo28gc2VqYSBwb3Nzw612ZWwgcmVjdXBlcmFyIG8gdG9rZW4gYXV0ZW50aWNhZG8uXG4gICAgICpcbiAgICAgKiBNYW50w6ltIGEgdmFyacOhdmVsIGF1dGguY3VycmVudFVzZXIgcGFyYSBmYWNpbGl0YXIgbyBhY2Vzc28gYW8gdXN1w6FyaW8gbG9nYWRvIGVtIHRvZGEgYSBhcGxpY2HDp8Ojb1xuICAgICAqXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gdXNlciBVc3XDoXJpbyBhIHNlciBhdHVhbGl6YWRvLiBDYXNvIHNlamEgcGFzc2FkbyBudWxsIGxpbXBhXG4gICAgICogdG9kYXMgYXMgaW5mb3JtYcOnw7VlcyBkbyB1c3XDoXJpbyBjb3JyZW50ZS5cbiAgICAgKi9cbiAgICBmdW5jdGlvbiB1cGRhdGVDdXJyZW50VXNlcih1c2VyKSB7XG4gICAgICB2YXIgZGVmZXJyZWQgPSAkcS5kZWZlcigpO1xuXG4gICAgICBpZiAodXNlcikge1xuICAgICAgICB1c2VyID0gYW5ndWxhci5tZXJnZShuZXcgVXNlcnNTZXJ2aWNlKCksIHVzZXIpO1xuXG4gICAgICAgIHZhciBqc29uVXNlciA9IGFuZ3VsYXIudG9Kc29uKHVzZXIpO1xuXG4gICAgICAgIGxvY2FsU3RvcmFnZS5zZXRJdGVtKCd1c2VyJywganNvblVzZXIpO1xuICAgICAgICBhdXRoLmN1cnJlbnRVc2VyID0gdXNlcjtcblxuICAgICAgICBkZWZlcnJlZC5yZXNvbHZlKHVzZXIpO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oJ3VzZXInKTtcbiAgICAgICAgYXV0aC5jdXJyZW50VXNlciA9IG51bGw7XG4gICAgICAgIGF1dGguY2xlYXJUb2tlbigpO1xuXG4gICAgICAgIGRlZmVycmVkLnJlamVjdCgpO1xuICAgICAgfVxuXG4gICAgICByZXR1cm4gZGVmZXJyZWQucHJvbWlzZTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFsaXphIG8gbG9naW4gZG8gdXN1w6FyaW9cbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSBjcmVkZW50aWFscyBFbWFpbCBlIFNlbmhhIGRvIHVzdcOhcmlvXG4gICAgICogQHJldHVybnMge3Byb21pc2V9IFVtYSBwcm9taXNlIGNvbSBvIHJlc3VsdGFkbyBkbyBjaGFtYWRhIG5vIGJhY2tlbmRcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBsb2dpbihjcmVkZW50aWFscykge1xuICAgICAgdmFyIGRlZmVycmVkID0gJHEuZGVmZXIoKTtcblxuICAgICAgJGh0dHAucG9zdChHbG9iYWwuYXBpUGF0aCArICcvYXV0aGVudGljYXRlJywgY3JlZGVudGlhbHMpXG4gICAgICAgIC50aGVuKGZ1bmN0aW9uKHJlc3BvbnNlKSB7XG4gICAgICAgICAgYXV0aC5zZXRUb2tlbihyZXNwb25zZS5kYXRhLnRva2VuKTtcblxuICAgICAgICAgIHJldHVybiAkaHR0cC5nZXQoR2xvYmFsLmFwaVBhdGggKyAnL2F1dGhlbnRpY2F0ZS91c2VyJyk7XG4gICAgICAgIH0pXG4gICAgICAgIC50aGVuKGZ1bmN0aW9uKHJlc3BvbnNlKSB7XG4gICAgICAgICAgYXV0aC51cGRhdGVDdXJyZW50VXNlcihyZXNwb25zZS5kYXRhLnVzZXIpO1xuXG4gICAgICAgICAgZGVmZXJyZWQucmVzb2x2ZSgpO1xuICAgICAgICB9LCBmdW5jdGlvbihlcnJvcikge1xuICAgICAgICAgIGF1dGgubG9nb3V0KCk7XG5cbiAgICAgICAgICBkZWZlcnJlZC5yZWplY3QoZXJyb3IpO1xuICAgICAgICB9KTtcblxuICAgICAgcmV0dXJuIGRlZmVycmVkLnByb21pc2U7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogRGVzbG9nYSBvcyB1c3XDoXJpb3MuIENvbW8gbsOjbyB0ZW4gbmVuaHVtYSBpbmZvcm1hw6fDo28gbmEgc2Vzc8OjbyBkbyBzZXJ2aWRvclxuICAgICAqIGUgdW0gdG9rZW4gdW1hIHZleiBnZXJhZG8gbsOjbyBwb2RlLCBwb3IgcGFkcsOjbywgc2VyIGludmFsaWRhZG8gYW50ZXMgZG8gc2V1IHRlbXBvIGRlIGV4cGlyYcOnw6NvLFxuICAgICAqIHNvbWVudGUgYXBhZ2Ftb3Mgb3MgZGFkb3MgZG8gdXN1w6FyaW8gZSBvIHRva2VuIGRvIG5hdmVnYWRvciBwYXJhIGVmZXRpdmFyIG8gbG9nb3V0LlxuICAgICAqXG4gICAgICogQHJldHVybnMge3Byb21pc2V9IFVtYSBwcm9taXNlIGNvbSBvIHJlc3VsdGFkbyBkYSBvcGVyYcOnw6NvXG4gICAgICovXG4gICAgZnVuY3Rpb24gbG9nb3V0KCkge1xuICAgICAgdmFyIGRlZmVycmVkID0gJHEuZGVmZXIoKTtcblxuICAgICAgYXV0aC51cGRhdGVDdXJyZW50VXNlcihudWxsKTtcbiAgICAgIGRlZmVycmVkLnJlc29sdmUoKTtcblxuICAgICAgcmV0dXJuIGRlZmVycmVkLnByb21pc2U7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogRW52aWEgdW0gZW1haWwgcGFyYSByZWN1cGVyYcOnw6NvIGRlIHNlbmhhXG4gICAgICogQHBhcmFtIHtPYmplY3R9IHJlc2V0RGF0YSAtIE9iamV0byBjb250ZW5kbyBvIGVtYWlsXG4gICAgICogQHJldHVybiB7UHJvbWlzZX0gLSBSZXRvcm5hIHVtYSBwcm9taXNlIHBhcmEgc2VyIHJlc29sdmlkYVxuICAgICAqL1xuICAgIGZ1bmN0aW9uIHNlbmRFbWFpbFJlc2V0UGFzc3dvcmQocmVzZXREYXRhKSB7XG4gICAgICB2YXIgZGVmZXJyZWQgPSAkcS5kZWZlcigpO1xuXG4gICAgICAkaHR0cC5wb3N0KEdsb2JhbC5hcGlQYXRoICsgJy9wYXNzd29yZC9lbWFpbCcsIHJlc2V0RGF0YSlcbiAgICAgICAgLnRoZW4oZnVuY3Rpb24ocmVzcG9uc2UpIHtcbiAgICAgICAgICBkZWZlcnJlZC5yZXNvbHZlKHJlc3BvbnNlLmRhdGEpO1xuICAgICAgICB9LCBmdW5jdGlvbihlcnJvcikge1xuICAgICAgICAgIGRlZmVycmVkLnJlamVjdChlcnJvcik7XG4gICAgICAgIH0pO1xuXG4gICAgICByZXR1cm4gZGVmZXJyZWQucHJvbWlzZTtcbiAgICB9XG5cbiAgICByZXR1cm4gYXV0aDtcbiAgfVxuXG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29udHJvbGxlcignTG9naW5Db250cm9sbGVyJywgTG9naW5Db250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIExvZ2luQ29udHJvbGxlcigkc3RhdGUsIEF1dGgsIEdsb2JhbCwgUHJEaWFsb2cpIHtcbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0ubG9naW4gPSBsb2dpbjtcbiAgICB2bS5vcGVuRGlhbG9nUmVzZXRQYXNzID0gb3BlbkRpYWxvZ1Jlc2V0UGFzcztcbiAgICB2bS5vcGVuRGlhbG9nU2lnblVwID0gb3BlbkRpYWxvZ1NpZ25VcDtcblxuICAgIGFjdGl2YXRlKCk7XG5cbiAgICBmdW5jdGlvbiBhY3RpdmF0ZSgpIHtcbiAgICAgIHZtLmNyZWRlbnRpYWxzID0ge307XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gbG9naW4oKSB7XG4gICAgICB2YXIgY3JlZGVudGlhbHMgPSB7XG4gICAgICAgIGVtYWlsOiB2bS5jcmVkZW50aWFscy5lbWFpbCxcbiAgICAgICAgcGFzc3dvcmQ6IHZtLmNyZWRlbnRpYWxzLnBhc3N3b3JkXG4gICAgICB9O1xuXG4gICAgICBBdXRoLmxvZ2luKGNyZWRlbnRpYWxzKS50aGVuKGZ1bmN0aW9uKCkge1xuICAgICAgICAkc3RhdGUuZ28oR2xvYmFsLmhvbWVTdGF0ZSk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBFeGliZSBvIGRpYWxvZyBwYXJhIHJlY3VwZXJhw6fDo28gZGUgc2VuaGFcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBvcGVuRGlhbG9nUmVzZXRQYXNzKCkge1xuICAgICAgdmFyIGNvbmZpZyA9IHtcbiAgICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9hdXRoL3NlbmQtcmVzZXQtZGlhbG9nLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnUGFzc3dvcmRDb250cm9sbGVyIGFzIHBhc3NDdHJsJyxcbiAgICAgICAgaGFzQmFja2Ryb3A6IHRydWVcbiAgICAgIH1cblxuICAgICAgUHJEaWFsb2cuY3VzdG9tKGNvbmZpZyk7XG4gICAgfVxuICAgIC8qKlxuICAgICAqIEV4aWJlIG8gZGlhbG9nIHBhcmEgcmVjdXBlcmHDp8OjbyBkZSBzZW5oYVxuICAgICAqL1xuICAgIGZ1bmN0aW9uIG9wZW5EaWFsb2dTaWduVXAoKSB7XG4gICAgICB2YXIgY29uZmlnID0ge1xuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL3VzZXJzL3VzZXItZm9ybS5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ1VzZXJzQ29udHJvbGxlciBhcyB1c2Vyc0N0cmwnLFxuICAgICAgICBoYXNCYWNrZHJvcDogdHJ1ZVxuICAgICAgfVxuXG4gICAgICBQckRpYWxvZy5jdXN0b20oY29uZmlnKTtcbiAgICB9XG5cbiAgfVxuXG59KSgpO1xuIiwiKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnRyb2xsZXIoJ1Bhc3N3b3JkQ29udHJvbGxlcicsIFBhc3N3b3JkQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBQYXNzd29yZENvbnRyb2xsZXIoR2xvYmFsLCAkc3RhdGVQYXJhbXMsICRodHRwLCAkdGltZW91dCwgJHN0YXRlLCAvLyBOT1NPTkFSXG4gICAgUHJUb2FzdCwgUHJEaWFsb2csIEF1dGgsICR0cmFuc2xhdGUpIHtcblxuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICB2bS5zZW5kUmVzZXQgPSBzZW5kUmVzZXQ7XG4gICAgdm0uY2xvc2VEaWFsb2cgPSBjbG9zZURpYWxvZztcbiAgICB2bS5jbGVhbkZvcm0gPSBjbGVhbkZvcm07XG4gICAgdm0uc2VuZEVtYWlsUmVzZXRQYXNzd29yZCA9IHNlbmRFbWFpbFJlc2V0UGFzc3dvcmQ7XG5cbiAgICBhY3RpdmF0ZSgpO1xuXG4gICAgZnVuY3Rpb24gYWN0aXZhdGUoKSB7XG4gICAgICB2bS5yZXNldCA9IHsgZW1haWw6ICcnLCB0b2tlbjogJHN0YXRlUGFyYW1zLnRva2VuIH07XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhbGl6YSBhIGFsdGVyYcOnw6NvIGRhIHNlbmhhIGRvIHVzdcOhcmlvIGUgbyByZWRpcmVjaW9uYSBwYXJhIGEgdGVsYSBkZSBsb2dpblxuICAgICAqL1xuICAgIGZ1bmN0aW9uIHNlbmRSZXNldCgpIHtcbiAgICAgICRodHRwLnBvc3QoR2xvYmFsLmFwaVBhdGggKyAnL3Bhc3N3b3JkL3Jlc2V0Jywgdm0ucmVzZXQpXG4gICAgICAgIC50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICBQclRvYXN0LnN1Y2Nlc3MoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5vcGVyYXRpb25TdWNjZXNzJykpO1xuICAgICAgICAgICR0aW1lb3V0KGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICRzdGF0ZS5nbyhHbG9iYWwubG9naW5TdGF0ZSk7XG4gICAgICAgICAgfSwgMTUwMCk7XG4gICAgICAgIH0sIGZ1bmN0aW9uIChlcnJvcikge1xuICAgICAgICAgIGlmIChlcnJvci5zdGF0dXMgIT09IDQwMCAmJiBlcnJvci5zdGF0dXMgIT09IDUwMCkge1xuICAgICAgICAgICAgdmFyIG1zZyA9ICcnO1xuXG4gICAgICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IGVycm9yLmRhdGEucGFzc3dvcmQubGVuZ3RoOyBpKyspIHtcbiAgICAgICAgICAgICAgbXNnICs9IGVycm9yLmRhdGEucGFzc3dvcmRbaV0gKyAnPGJyPic7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBQclRvYXN0LmVycm9yKG1zZy50b1VwcGVyQ2FzZSgpKTtcbiAgICAgICAgICB9XG4gICAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEVudmlhIHVtIGVtYWlsIGRlIHJlY3VwZXJhw6fDo28gZGUgc2VuaGEgY29tIG8gdG9rZW4gZG8gdXN1w6FyaW9cbiAgICAgKi9cbiAgICBmdW5jdGlvbiBzZW5kRW1haWxSZXNldFBhc3N3b3JkKCkge1xuXG4gICAgICBpZiAodm0ucmVzZXQuZW1haWwgPT09ICcnKSB7XG4gICAgICAgIFByVG9hc3QuZXJyb3IoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy52YWxpZGF0ZS5maWVsZFJlcXVpcmVkJywgeyBmaWVsZDogJ2VtYWlsJyB9KSk7XG4gICAgICAgIHJldHVybjtcbiAgICAgIH1cblxuICAgICAgQXV0aC5zZW5kRW1haWxSZXNldFBhc3N3b3JkKHZtLnJlc2V0KS50aGVuKGZ1bmN0aW9uIChkYXRhKSB7XG4gICAgICAgIFByVG9hc3Quc3VjY2VzcyhkYXRhLm1lc3NhZ2UpO1xuXG4gICAgICAgIHZtLmNsZWFuRm9ybSgpO1xuICAgICAgICB2bS5jbG9zZURpYWxvZygpO1xuICAgICAgfSwgZnVuY3Rpb24gKGVycm9yKSB7XG4gICAgICAgIGlmIChlcnJvci5kYXRhLmVtYWlsICYmIGVycm9yLmRhdGEuZW1haWwubGVuZ3RoID4gMCkge1xuICAgICAgICAgIHZhciBtc2cgPSAnJztcblxuICAgICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgZXJyb3IuZGF0YS5lbWFpbC5sZW5ndGg7IGkrKykge1xuICAgICAgICAgICAgbXNnICs9IGVycm9yLmRhdGEuZW1haWxbaV0gKyAnPGJyPic7XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgUHJUb2FzdC5lcnJvcihtc2cpO1xuICAgICAgICB9XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBjbG9zZURpYWxvZygpIHtcbiAgICAgIFByRGlhbG9nLmNsb3NlKCk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gY2xlYW5Gb3JtKCkge1xuICAgICAgdm0ucmVzZXQuZW1haWwgPSAnJztcbiAgICB9XG5cbiAgfVxuXG59KSgpO1xuIiwiLyplc2xpbnQgYW5ndWxhci9maWxlLW5hbWU6IDAqL1xuKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZhY3RvcnkoJ3NlcnZpY2VGYWN0b3J5Jywgc2VydmljZUZhY3RvcnkpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLyoqXG4gICAqIE1haXMgaW5mb3JtYcOnw7VlczpcbiAgICogaHR0cHM6Ly9naXRodWIuY29tL3N3aW1sYW5lL2FuZ3VsYXItbW9kZWwtZmFjdG9yeS93aWtpL0FQSVxuICAgKi9cbiAgZnVuY3Rpb24gc2VydmljZUZhY3RvcnkoJG1vZGVsRmFjdG9yeSkge1xuICAgIHJldHVybiBmdW5jdGlvbih1cmwsIG9wdGlvbnMpIHtcbiAgICAgIHZhciBtb2RlbDtcbiAgICAgIHZhciBkZWZhdWx0T3B0aW9ucyA9IHtcbiAgICAgICAgYWN0aW9uczoge1xuICAgICAgICAgIC8qKlxuICAgICAgICAgICAqIFNlcnZpw6dvIGNvbXVtIHBhcmEgcmVhbGl6YXIgYnVzY2EgY29tIHBhZ2luYcOnw6NvXG4gICAgICAgICAgICogTyBtZXNtbyBlc3BlcmEgcXVlIHNlamEgcmV0b3JuYWRvIHVtIG9iamV0byBjb20gaXRlbXMgZSB0b3RhbFxuICAgICAgICAgICAqL1xuICAgICAgICAgIHBhZ2luYXRlOiB7XG4gICAgICAgICAgICBtZXRob2Q6ICdHRVQnLFxuICAgICAgICAgICAgaXNBcnJheTogZmFsc2UsXG4gICAgICAgICAgICB3cmFwOiBmYWxzZSxcbiAgICAgICAgICAgIGFmdGVyUmVxdWVzdDogZnVuY3Rpb24ocmVzcG9uc2UpIHtcbiAgICAgICAgICAgICAgaWYgKHJlc3BvbnNlWydpdGVtcyddKSB7XG4gICAgICAgICAgICAgICAgcmVzcG9uc2VbJ2l0ZW1zJ10gPSBtb2RlbC5MaXN0KHJlc3BvbnNlWydpdGVtcyddKTtcbiAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgIHJldHVybiByZXNwb25zZTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgIH1cblxuICAgICAgbW9kZWwgPSAkbW9kZWxGYWN0b3J5KHVybCwgYW5ndWxhci5tZXJnZShkZWZhdWx0T3B0aW9ucywgb3B0aW9ucykpXG5cbiAgICAgIHJldHVybiBtb2RlbDtcbiAgICB9XG4gIH1cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIENSVURDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8qKlxuICAgKiBDb250cm9sYWRvciBCYXNlIHF1ZSBpbXBsZW1lbnRhIHRvZGFzIGFzIGZ1bsOnw7VlcyBwYWRyw7VlcyBkZSB1bSBDUlVEXG4gICAqXG4gICAqIEHDp8O1ZXMgaW1wbGVtZW50YWRhc1xuICAgKiBhY3RpdmF0ZSgpXG4gICAqIHNlYXJjaChwYWdlKVxuICAgKiBlZGl0KHJlc291cmNlKVxuICAgKiBzYXZlKClcbiAgICogcmVtb3ZlKHJlc291cmNlKVxuICAgKiBnb1RvKHZpZXdOYW1lKVxuICAgKiBjbGVhbkZvcm0oKVxuICAgKlxuICAgKiBHYXRpbGhvc1xuICAgKlxuICAgKiBvbkFjdGl2YXRlKClcbiAgICogYXBwbHlGaWx0ZXJzKGRlZmF1bHRRdWVyeUZpbHRlcnMpXG4gICAqIGJlZm9yZVNlYXJjaChwYWdlKSAvL3JldG9ybmFuZG8gZmFsc2UgY2FuY2VsYSBvIGZsdXhvXG4gICAqIGFmdGVyU2VhcmNoKHJlc3BvbnNlKVxuICAgKiBiZWZvcmVDbGVhbiAvL3JldG9ybmFuZG8gZmFsc2UgY2FuY2VsYSBvIGZsdXhvXG4gICAqIGFmdGVyQ2xlYW4oKVxuICAgKiBiZWZvcmVTYXZlKCkgLy9yZXRvcm5hbmRvIGZhbHNlIGNhbmNlbGEgbyBmbHV4b1xuICAgKiBhZnRlclNhdmUocmVzb3VyY2UpXG4gICAqIG9uU2F2ZUVycm9yKGVycm9yKVxuICAgKiBiZWZvcmVSZW1vdmUocmVzb3VyY2UpIC8vcmV0b3JuYW5kbyBmYWxzZSBjYW5jZWxhIG8gZmx1eG9cbiAgICogYWZ0ZXJSZW1vdmUocmVzb3VyY2UpXG4gICAqXG4gICAqIEBwYXJhbSB7YW55fSB2bSBpbnN0YW5jaWEgZG8gY29udHJvbGxlciBmaWxob1xuICAgKiBAcGFyYW0ge2FueX0gbW9kZWxTZXJ2aWNlIHNlcnZpw6dvIGRvIG1vZGVsIHF1ZSB2YWkgc2VyIHV0aWxpemFkb1xuICAgKiBAcGFyYW0ge2FueX0gb3B0aW9ucyBvcMOnw7VlcyBwYXJhIHNvYnJlZXNjcmV2ZXIgY29tcG9ydGFtZW50b3MgcGFkcsO1ZXNcbiAgICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIENSVURDb250cm9sbGVyKHZtLCBtb2RlbFNlcnZpY2UsIG9wdGlvbnMsIFByVG9hc3QsIFByUGFnaW5hdGlvbiwgLy8gTk9TT05BUlxuICAgIFByRGlhbG9nLCAkdHJhbnNsYXRlKSB7XG5cbiAgICAvL0Z1bmN0aW9ucyBCbG9ja1xuICAgIHZtLnNlYXJjaCA9IHNlYXJjaDtcbiAgICB2bS5wYWdpbmF0ZVNlYXJjaCA9IHBhZ2luYXRlU2VhcmNoO1xuICAgIHZtLm5vcm1hbFNlYXJjaCA9IG5vcm1hbFNlYXJjaDtcbiAgICB2bS5lZGl0ID0gZWRpdDtcbiAgICB2bS5zYXZlID0gc2F2ZTtcbiAgICB2bS5yZW1vdmUgPSByZW1vdmU7XG4gICAgdm0uZ29UbyA9IGdvVG87XG4gICAgdm0uY2xlYW5Gb3JtID0gY2xlYW5Gb3JtO1xuXG4gICAgYWN0aXZhdGUoKTtcblxuICAgIC8qKlxuICAgICAqIFByZXBhcmEgbyBjb250cm9sYWRvclxuICAgICAqIEZheiBvIG1lcmdlIGRhcyBvcMOnw7Vlc1xuICAgICAqIEluaWNpYWxpemEgbyByZWN1cnNvXG4gICAgICogSW5pY2lhbGl6YSBvIG9iamV0byBwYWdpbmFkb3IgZSByZWFsaXphIGEgcGVzcXVpc2FcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBhY3RpdmF0ZSgpIHtcbiAgICAgIHZtLmRlZmF1bHRPcHRpb25zID0ge1xuICAgICAgICByZWRpcmVjdEFmdGVyU2F2ZTogdHJ1ZSxcbiAgICAgICAgc2VhcmNoT25Jbml0OiB0cnVlLFxuICAgICAgICBwZXJQYWdlOiA4LFxuICAgICAgICBza2lwUGFnaW5hdGlvbjogZmFsc2VcbiAgICAgIH1cblxuICAgICAgYW5ndWxhci5tZXJnZSh2bS5kZWZhdWx0T3B0aW9ucywgb3B0aW9ucyk7XG5cbiAgICAgIHZtLnZpZXdGb3JtID0gZmFsc2U7XG4gICAgICB2bS5yZXNvdXJjZSA9IG5ldyBtb2RlbFNlcnZpY2UoKTtcblxuICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5vbkFjdGl2YXRlKSkgdm0ub25BY3RpdmF0ZSgpO1xuXG4gICAgICB2bS5wYWdpbmF0b3IgPSBQclBhZ2luYXRpb24uZ2V0SW5zdGFuY2Uodm0uc2VhcmNoLCB2bS5kZWZhdWx0T3B0aW9ucy5wZXJQYWdlKTtcblxuICAgICAgaWYgKHZtLmRlZmF1bHRPcHRpb25zLnNlYXJjaE9uSW5pdCkgdm0uc2VhcmNoKCk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhbGl6YSBhIHBlc3F1aXNhXG4gICAgICogVmVyaWZpY2EgcXVhbCBkYXMgZnVuw6fDtWVzIGRlIHBlc3F1aXNhIGRldmUgc2VyIHJlYWxpemFkYS5cbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSBwYWdlIHDDoWdpbmEgcXVlIGRldmUgc2VyIGNhcnJlZ2FkYVxuICAgICAqL1xuICAgIGZ1bmN0aW9uIHNlYXJjaChwYWdlKSB7XG4gICAgICAodm0uZGVmYXVsdE9wdGlvbnMuc2tpcFBhZ2luYXRpb24pID8gbm9ybWFsU2VhcmNoKCkgOiBwYWdpbmF0ZVNlYXJjaChwYWdlKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFsaXphIGEgcGVzcXVpc2EgcGFnaW5hZGEgY29tIGJhc2Ugbm9zIGZpbHRyb3MgZGVmaW5pZG9zXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gcGFnZSBww6FnaW5hIHF1ZSBkZXZlIHNlciBjYXJyZWdhZGFcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBwYWdpbmF0ZVNlYXJjaChwYWdlKSB7XG4gICAgICB2bS5wYWdpbmF0b3IuY3VycmVudFBhZ2UgPSAoYW5ndWxhci5pc0RlZmluZWQocGFnZSkpID8gcGFnZSA6IDE7XG4gICAgICB2bS5kZWZhdWx0UXVlcnlGaWx0ZXJzID0geyBwYWdlOiB2bS5wYWdpbmF0b3IuY3VycmVudFBhZ2UsIHBlclBhZ2U6IHZtLnBhZ2luYXRvci5wZXJQYWdlIH07XG5cbiAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYXBwbHlGaWx0ZXJzKSkgdm0uZGVmYXVsdFF1ZXJ5RmlsdGVycyA9IHZtLmFwcGx5RmlsdGVycyh2bS5kZWZhdWx0UXVlcnlGaWx0ZXJzKTtcbiAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYmVmb3JlU2VhcmNoKSAmJiB2bS5iZWZvcmVTZWFyY2gocGFnZSkgPT09IGZhbHNlKSByZXR1cm4gZmFsc2U7XG5cbiAgICAgIG1vZGVsU2VydmljZS5wYWdpbmF0ZSh2bS5kZWZhdWx0UXVlcnlGaWx0ZXJzKS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICB2bS5wYWdpbmF0b3IuY2FsY051bWJlck9mUGFnZXMocmVzcG9uc2UudG90YWwpO1xuICAgICAgICB2bS5yZXNvdXJjZXMgPSByZXNwb25zZS5pdGVtcztcblxuICAgICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmFmdGVyU2VhcmNoKSkgdm0uYWZ0ZXJTZWFyY2gocmVzcG9uc2UpO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhbGl6YSBhIHBlc3F1aXNhIGNvbSBiYXNlIG5vcyBmaWx0cm9zIGRlZmluaWRvc1xuICAgICAqXG4gICAgICovXG4gICAgZnVuY3Rpb24gbm9ybWFsU2VhcmNoKCkge1xuICAgICAgdm0uZGVmYXVsdFF1ZXJ5RmlsdGVycyA9IHsgfTtcblxuICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5hcHBseUZpbHRlcnMpKSB2bS5kZWZhdWx0UXVlcnlGaWx0ZXJzID0gdm0uYXBwbHlGaWx0ZXJzKHZtLmRlZmF1bHRRdWVyeUZpbHRlcnMpO1xuICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5iZWZvcmVTZWFyY2gpICYmIHZtLmJlZm9yZVNlYXJjaCgpID09PSBmYWxzZSkgcmV0dXJuIGZhbHNlO1xuXG4gICAgICBtb2RlbFNlcnZpY2UucXVlcnkodm0uZGVmYXVsdFF1ZXJ5RmlsdGVycykudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgdm0ucmVzb3VyY2VzID0gcmVzcG9uc2U7XG5cbiAgICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5hZnRlclNlYXJjaCkpIHZtLmFmdGVyU2VhcmNoKHJlc3BvbnNlKTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIExpbXBhIG8gZm9ybXVsw6FyaW9cbiAgICAgKi9cbiAgICBmdW5jdGlvbiBjbGVhbkZvcm0oZm9ybSkge1xuICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5iZWZvcmVDbGVhbikgJiYgdm0uYmVmb3JlQ2xlYW4oKSA9PT0gZmFsc2UpIHJldHVybiBmYWxzZTtcblxuICAgICAgdm0ucmVzb3VyY2UgPSBuZXcgbW9kZWxTZXJ2aWNlKCk7XG5cbiAgICAgIGlmIChhbmd1bGFyLmlzRGVmaW5lZChmb3JtKSkge1xuICAgICAgICBmb3JtLiRzZXRQcmlzdGluZSgpO1xuICAgICAgICBmb3JtLiRzZXRVbnRvdWNoZWQoKTtcbiAgICAgIH1cblxuICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5hZnRlckNsZWFuKSkgdm0uYWZ0ZXJDbGVhbigpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENhcnJlZ2Egbm8gZm9ybXVsw6FyaW8gbyByZWN1cnNvIHNlbGVjaW9uYWRvIHBhcmEgZWRpw6fDo29cbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSByZXNvdXJjZSByZWN1cnNvIHNlbGVjaW9uYWRvXG4gICAgICovXG4gICAgZnVuY3Rpb24gZWRpdChyZXNvdXJjZSkge1xuICAgICAgdm0uZ29UbygnZm9ybScpO1xuICAgICAgdm0ucmVzb3VyY2UgPSBuZXcgYW5ndWxhci5jb3B5KHJlc291cmNlKTtcblxuICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5hZnRlckVkaXQpKSB2bS5hZnRlckVkaXQoKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBTYWx2YSBvdSBhdHVhbGl6YSBvIHJlY3Vyc28gY29ycmVudGUgbm8gZm9ybXVsw6FyaW9cbiAgICAgKiBObyBjb21wb3J0YW1lbnRvIHBhZHLDo28gcmVkaXJlY2lvbmEgbyB1c3XDoXJpbyBwYXJhIHZpZXcgZGUgbGlzdGFnZW1cbiAgICAgKiBkZXBvaXMgZGEgZXhlY3XDp8Ojb1xuICAgICAqXG4gICAgICogQHJldHVybnNcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBzYXZlKGZvcm0pIHtcbiAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYmVmb3JlU2F2ZSkgJiYgdm0uYmVmb3JlU2F2ZSgpID09PSBmYWxzZSkgcmV0dXJuIGZhbHNlO1xuXG4gICAgICB2bS5yZXNvdXJjZS4kc2F2ZSgpLnRoZW4oZnVuY3Rpb24gKHJlc291cmNlKSB7XG4gICAgICAgIHZtLnJlc291cmNlID0gcmVzb3VyY2U7XG5cbiAgICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5hZnRlclNhdmUpKSB2bS5hZnRlclNhdmUocmVzb3VyY2UpO1xuXG4gICAgICAgIGlmICh2bS5kZWZhdWx0T3B0aW9ucy5yZWRpcmVjdEFmdGVyU2F2ZSkge1xuICAgICAgICAgIHZtLmNsZWFuRm9ybShmb3JtKTtcbiAgICAgICAgICB2bS5zZWFyY2godm0ucGFnaW5hdG9yLmN1cnJlbnRQYWdlKTtcbiAgICAgICAgICB2bS5nb1RvKCdsaXN0Jyk7XG4gICAgICAgIH1cblxuICAgICAgICBQclRvYXN0LnN1Y2Nlc3MoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5zYXZlU3VjY2VzcycpKTtcblxuICAgICAgfSwgZnVuY3Rpb24gKHJlc3BvbnNlRGF0YSkge1xuICAgICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLm9uU2F2ZUVycm9yKSkgdm0ub25TYXZlRXJyb3IocmVzcG9uc2VEYXRhKTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlbW92ZSBvIHJlY3Vyc28gaW5mb3JtYWRvLlxuICAgICAqIEFudGVzIGV4aWJlIHVtIGRpYWxvZ28gZGUgY29uZmlybWHDp8Ojb1xuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IHJlc291cmNlIHJlY3Vyc28gZXNjb2xoaWRvXG4gICAgICovXG4gICAgZnVuY3Rpb24gcmVtb3ZlKHJlc291cmNlKSB7XG4gICAgICB2YXIgY29uZmlnID0ge1xuICAgICAgICB0aXRsZTogJHRyYW5zbGF0ZS5pbnN0YW50KCdkaWFsb2cuY29uZmlybVRpdGxlJyksXG4gICAgICAgIGRlc2NyaXB0aW9uOiAkdHJhbnNsYXRlLmluc3RhbnQoJ2RpYWxvZy5jb25maXJtRGVzY3JpcHRpb24nKVxuICAgICAgfVxuXG4gICAgICBQckRpYWxvZy5jb25maXJtKGNvbmZpZykudGhlbihmdW5jdGlvbigpIHtcbiAgICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5iZWZvcmVSZW1vdmUpICYmIHZtLmJlZm9yZVJlbW92ZShyZXNvdXJjZSkgPT09IGZhbHNlKSByZXR1cm4gZmFsc2U7XG5cbiAgICAgICAgcmVzb3VyY2UuJGRlc3Ryb3koKS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmFmdGVyUmVtb3ZlKSkgdm0uYWZ0ZXJSZW1vdmUocmVzb3VyY2UpO1xuXG4gICAgICAgICAgdm0uc2VhcmNoKCk7XG4gICAgICAgICAgUHJUb2FzdC5pbmZvKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMucmVtb3ZlU3VjY2VzcycpKTtcbiAgICAgICAgfSk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBBbHRlcm5hIGVudHJlIGEgdmlldyBkbyBmb3JtdWzDoXJpbyBlIGxpc3RhZ2VtXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gdmlld05hbWUgbm9tZSBkYSB2aWV3XG4gICAgICovXG4gICAgZnVuY3Rpb24gZ29Ubyh2aWV3TmFtZSkge1xuICAgICAgdm0udmlld0Zvcm0gPSBmYWxzZTtcblxuICAgICAgaWYgKHZpZXdOYW1lID09PSAnZm9ybScpIHtcbiAgICAgICAgdm0uY2xlYW5Gb3JtKCk7XG4gICAgICAgIHZtLnZpZXdGb3JtID0gdHJ1ZTtcbiAgICAgIH1cbiAgICB9XG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnRyb2xsZXIoJ0Rhc2hib2FyZENvbnRyb2xsZXInLCBEYXNoYm9hcmRDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8qKlxuICAgKiBEYXNoYm9hcmQgQ29udHJvbGxlclxuICAgKlxuICAgKiBQYWluZWwgY29tIHByaW5jaXBhaXMgaW5kaWNhZG9yZXNcbiAgICpcbiAgICovXG4gIGZ1bmN0aW9uIERhc2hib2FyZENvbnRyb2xsZXIoKSB7XG4gICAgLy8gQ29udHJvbGxlciB2YXppbyBzb21lbnRlIHBhcmEgc2VyIGRlZmluaWRvIGNvbW8gcMOhZ2luYSBwcmluY2lwYWwuXG4gICAgLy8gRGV2ZSBzZXIgaWRlbnRpZmljYWRvIGUgYWRpY2lvbmFkbyBncsOhZmljb3NcbiAgfVxuXG59KSgpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKlxuICAgKiBBcnF1aXZvIGRlIGNvbmZpZ3VyYcOnw6NvIGNvbSBhcyByb3RhcyBlc3BlY8OtZmljYXMgZG8gZGFzaGJvYXJkXG4gICAqXG4gICAqIEBwYXJhbSB7YW55fSAkc3RhdGVQcm92aWRlclxuICAgKiBAcGFyYW0ge2FueX0gR2xvYmFsXG4gICAqL1xuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvdXRlcygkc3RhdGVQcm92aWRlciwgR2xvYmFsKSB7XG4gICAgJHN0YXRlUHJvdmlkZXJcbiAgICAgIC5zdGF0ZShHbG9iYWwuaG9tZVN0YXRlLCB7XG4gICAgICAgIHVybDogJy9kYXNoYm9hcmQnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL2Rhc2hib2FyZC9kYXNoYm9hcmQuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdEYXNoYm9hcmRDb250cm9sbGVyIGFzIGRhc2hib2FyZEN0cmwnLFxuICAgICAgICBkYXRhOiB7IG5lZWRBdXRoZW50aWNhdGlvbjogdHJ1ZSB9XG4gICAgICB9KVxuICB9XG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKlxuICAgKiBBcnF1aXZvIGRlIGNvbmZpZ3VyYcOnw6NvIGNvbSBhcyByb3RhcyBlc3BlY8OtZmljYXMgZG8gcmVjdXJzbyB1c2VyXG4gICAqXG4gICAqIEBwYXJhbSB7YW55fSAkc3RhdGVQcm92aWRlclxuICAgKiBAcGFyYW0ge2FueX0gR2xvYmFsXG4gICAqL1xuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvdXRlcygkc3RhdGVQcm92aWRlciwgR2xvYmFsKSB7XG4gICAgJHN0YXRlUHJvdmlkZXJcbiAgICAgIC5zdGF0ZSgnYXBwLmRpbmFtaWMtcXVlcnknLCB7XG4gICAgICAgIHVybDogJy9jb25zdWx0YXMtZGluYW1pY2FzJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9kaW5hbWljLXF1ZXJ5cy9kaW5hbWljLXF1ZXJ5cy5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ0RpbmFtaWNRdWVyeXNDb250cm9sbGVyIGFzIGRpbmFtaWNRdWVyeUN0cmwnLFxuICAgICAgICBkYXRhOiB7IG5lZWRBdXRoZW50aWNhdGlvbjogdHJ1ZSwgbmVlZFByb2ZpbGU6IFsnYWRtaW4nXSB9XG4gICAgICB9KTtcblxuICB9XG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZhY3RvcnkoJ0RpbmFtaWNRdWVyeVNlcnZpY2UnLCBEaW5hbWljUXVlcnlTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIERpbmFtaWNRdWVyeVNlcnZpY2Uoc2VydmljZUZhY3RvcnkpIHtcbiAgICByZXR1cm4gc2VydmljZUZhY3RvcnkoJ2RpbmFtaWNRdWVyeScsIHtcbiAgICAgIC8qKlxuICAgICAgICogYcOnw6NvIGFkaWNpb25hZGEgcGFyYSBwZWdhciB1bWEgbGlzdGEgZGUgbW9kZWxzIGV4aXN0ZW50ZXMgbm8gc2Vydmlkb3JcbiAgICAgICAqL1xuICAgICAgYWN0aW9uczoge1xuICAgICAgICBnZXRNb2RlbHM6IHtcbiAgICAgICAgICBtZXRob2Q6ICdHRVQnLFxuICAgICAgICAgIHVybDogJ21vZGVscydcbiAgICAgICAgfVxuICAgICAgfSxcbiAgICAgIGluc3RhbmNlOiB7XG4gICAgICB9XG4gICAgfSk7XG4gIH1cblxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnRyb2xsZXIoJ0RpbmFtaWNRdWVyeXNDb250cm9sbGVyJywgRGluYW1pY1F1ZXJ5c0NvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gRGluYW1pY1F1ZXJ5c0NvbnRyb2xsZXIoJGNvbnRyb2xsZXIsIERpbmFtaWNRdWVyeVNlcnZpY2UsIGxvZGFzaCwgUHJUb2FzdCwgLy8gTk9TT05BUlxuICAgICR0cmFuc2xhdGUpIHtcblxuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICAvL2FjdGlvbnNcbiAgICB2bS5vbkFjdGl2YXRlID0gb25BY3RpdmF0ZTtcbiAgICB2bS5hcHBseUZpbHRlcnMgPSBhcHBseUZpbHRlcnM7XG4gICAgdm0ubG9hZEF0dHJpYnV0ZXMgPSBsb2FkQXR0cmlidXRlcztcbiAgICB2bS5sb2FkT3BlcmF0b3JzID0gbG9hZE9wZXJhdG9ycztcbiAgICB2bS5hZGRGaWx0ZXIgPSBhZGRGaWx0ZXI7XG4gICAgdm0uYWZ0ZXJTZWFyY2ggPSBhZnRlclNlYXJjaDtcbiAgICB2bS5ydW5GaWx0ZXIgPSBydW5GaWx0ZXI7XG4gICAgdm0uZWRpdEZpbHRlciA9IGVkaXRGaWx0ZXI7XG4gICAgdm0ubG9hZE1vZGVscyA9IGxvYWRNb2RlbHM7XG4gICAgdm0ucmVtb3ZlRmlsdGVyID0gcmVtb3ZlRmlsdGVyO1xuICAgIHZtLmNsZWFyID0gY2xlYXI7XG4gICAgdm0ucmVzdGFydCA9IHJlc3RhcnQ7XG5cbiAgICAvL2hlcmRhIG8gY29tcG9ydGFtZW50byBiYXNlIGRvIENSVURcbiAgICAkY29udHJvbGxlcignQ1JVRENvbnRyb2xsZXInLCB7IHZtOiB2bSwgbW9kZWxTZXJ2aWNlOiBEaW5hbWljUXVlcnlTZXJ2aWNlLCBvcHRpb25zOiB7XG4gICAgICBzZWFyY2hPbkluaXQ6IGZhbHNlXG4gICAgfSB9KTtcblxuICAgIGZ1bmN0aW9uIG9uQWN0aXZhdGUoKSB7XG4gICAgICB2bS5yZXN0YXJ0KCk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUHJlcGFyYSBlIGFwbGljYSBvcyBmaWx0cm8gcXVlIHbDo28gc2VyIGVudmlhZG9zIHBhcmEgbyBzZXJ2acOnb1xuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IGRlZmF1bHRRdWVyeUZpbHRlcnNcbiAgICAgKiBAcmV0dXJuc1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGFwcGx5RmlsdGVycyhkZWZhdWx0UXVlcnlGaWx0ZXJzKSB7XG4gICAgICB2YXIgd2hlcmUgPSB7fTtcblxuICAgICAgLyoqXG4gICAgICAgKiBvIHNlcnZpw6dvIGVzcGVyYSB1bSBvYmpldG8gY29tOlxuICAgICAgICogIG8gbm9tZSBkZSB1bSBtb2RlbFxuICAgICAgICogIHVtYSBsaXN0YSBkZSBmaWx0cm9zXG4gICAgICAgKi9cbiAgICAgIGlmICh2bS5hZGRlZEZpbHRlcnMubGVuZ3RoID4gMCkge1xuICAgICAgICB2YXIgYWRkZWRGaWx0ZXJzID0gYW5ndWxhci5jb3B5KHZtLmFkZGVkRmlsdGVycyk7XG5cbiAgICAgICAgd2hlcmUubW9kZWwgPSB2bS5hZGRlZEZpbHRlcnNbMF0ubW9kZWwubmFtZTtcblxuICAgICAgICBmb3IgKHZhciBpbmRleCA9IDA7IGluZGV4IDwgYWRkZWRGaWx0ZXJzLmxlbmd0aDsgaW5kZXgrKykge1xuICAgICAgICAgIHZhciBmaWx0ZXIgPSBhZGRlZEZpbHRlcnNbaW5kZXhdO1xuXG4gICAgICAgICAgZmlsdGVyLm1vZGVsID0gbnVsbDtcbiAgICAgICAgICBmaWx0ZXIuYXR0cmlidXRlID0gZmlsdGVyLmF0dHJpYnV0ZS5uYW1lO1xuICAgICAgICAgIGZpbHRlci5vcGVyYXRvciA9IGZpbHRlci5vcGVyYXRvci52YWx1ZTtcbiAgICAgICAgfVxuXG4gICAgICAgIHdoZXJlLmZpbHRlcnMgPSBhbmd1bGFyLnRvSnNvbihhZGRlZEZpbHRlcnMpO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgd2hlcmUubW9kZWwgPSB2bS5xdWVyeUZpbHRlcnMubW9kZWwubmFtZTtcbiAgICAgIH1cblxuICAgICAgcmV0dXJuIGFuZ3VsYXIuZXh0ZW5kKGRlZmF1bHRRdWVyeUZpbHRlcnMsIHdoZXJlKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDYXJyZWdhIHRvZG9zIG9zIG1vZGVscyBjcmlhZG9zIG5vIHNlcnZpZG9yIGNvbSBzZXVzIGF0cmlidXRvc1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGxvYWRNb2RlbHMoKSB7XG4gICAgICAvL1BlZ2EgdG9kb3Mgb3MgbW9kZWxzIGRvIHNlcnZlciBlIG1vbnRhIHVtYSBsaXN0YSBwcm8gQ29tYm9Cb3hcbiAgICAgIERpbmFtaWNRdWVyeVNlcnZpY2UuZ2V0TW9kZWxzKCkudGhlbihmdW5jdGlvbihkYXRhKSB7XG4gICAgICAgIHZtLm1vZGVscyA9IGRhdGE7XG4gICAgICAgIHZtLnF1ZXJ5RmlsdGVycy5tb2RlbCA9IHZtLm1vZGVsc1swXTtcbiAgICAgICAgdm0ubG9hZEF0dHJpYnV0ZXMoKTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENhcnJlZ2Egb3MgYXR0cmlidXRvcyBkbyBtb2RlbCBlc2NvbGhpZG9cbiAgICAgKi9cbiAgICBmdW5jdGlvbiBsb2FkQXR0cmlidXRlcygpIHtcbiAgICAgIHZtLmF0dHJpYnV0ZXMgPSB2bS5xdWVyeUZpbHRlcnMubW9kZWwuYXR0cmlidXRlcztcbiAgICAgIHZtLnF1ZXJ5RmlsdGVycy5hdHRyaWJ1dGUgPSB2bS5hdHRyaWJ1dGVzWzBdO1xuXG4gICAgICB2bS5sb2FkT3BlcmF0b3JzKCk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ2FycmVnYSBvcyBvcGVyYWRvcmVzIGVzcGVjaWZpY29zIHBhcmEgbyB0aXBvIGRvIGF0cmlidXRvXG4gICAgICovXG4gICAgZnVuY3Rpb24gbG9hZE9wZXJhdG9ycygpIHtcbiAgICAgIHZhciBvcGVyYXRvcnMgPSBbXG4gICAgICAgIHsgdmFsdWU6ICc9JywgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudCgndmlld3MuZmllbGRzLnF1ZXJ5RGluYW1pYy5vcGVyYXRvcnMuZXF1YWxzJykgfSxcbiAgICAgICAgeyB2YWx1ZTogJzw+JywgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudCgndmlld3MuZmllbGRzLnF1ZXJ5RGluYW1pYy5vcGVyYXRvcnMuZGlmZXJlbnQnKSB9XG4gICAgICBdXG5cbiAgICAgIGlmICh2bS5xdWVyeUZpbHRlcnMuYXR0cmlidXRlLnR5cGUuaW5kZXhPZigndmFyeWluZycpICE9PSAtMSkge1xuICAgICAgICBvcGVyYXRvcnMucHVzaCh7IHZhbHVlOiAnaGFzJyxcbiAgICAgICAgICBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KCd2aWV3cy5maWVsZHMucXVlcnlEaW5hbWljLm9wZXJhdG9ycy5jb250ZWlucycpIH0pO1xuICAgICAgICBvcGVyYXRvcnMucHVzaCh7IHZhbHVlOiAnc3RhcnRXaXRoJyxcbiAgICAgICAgICBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KCd2aWV3cy5maWVsZHMucXVlcnlEaW5hbWljLm9wZXJhdG9ycy5zdGFydFdpdGgnKSB9KTtcbiAgICAgICAgb3BlcmF0b3JzLnB1c2goeyB2YWx1ZTogJ2VuZFdpdGgnLFxuICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLmZpbmlzaFdpdGgnKSB9KTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIG9wZXJhdG9ycy5wdXNoKHsgdmFsdWU6ICc+JyxcbiAgICAgICAgICBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KCd2aWV3cy5maWVsZHMucXVlcnlEaW5hbWljLm9wZXJhdG9ycy5iaWdnZXJUaGFuJykgfSk7XG4gICAgICAgIG9wZXJhdG9ycy5wdXNoKHsgdmFsdWU6ICc+PScsXG4gICAgICAgICAgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudCgndmlld3MuZmllbGRzLnF1ZXJ5RGluYW1pYy5vcGVyYXRvcnMuZXF1YWxzT3JCaWdnZXJUaGFuJykgfSk7XG4gICAgICAgIG9wZXJhdG9ycy5wdXNoKHsgdmFsdWU6ICc8JyxcbiAgICAgICAgICBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KCd2aWV3cy5maWVsZHMucXVlcnlEaW5hbWljLm9wZXJhdG9ycy5sZXNzVGhhbicpIH0pO1xuICAgICAgICBvcGVyYXRvcnMucHVzaCh7IHZhbHVlOiAnPD0nLFxuICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLmVxdWFsc09yTGVzc1RoYW4nKSB9KTtcbiAgICAgIH1cblxuICAgICAgdm0ub3BlcmF0b3JzID0gb3BlcmF0b3JzO1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzLm9wZXJhdG9yID0gdm0ub3BlcmF0b3JzWzBdO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEFkaWNpb25hL2VkaXRhIHVtIGZpbHRyb1xuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IGZvcm0gZWxlbWVudG8gaHRtbCBkbyBmb3JtdWzDoXJpbyBwYXJhIHZhbGlkYcOnw7Vlc1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGFkZEZpbHRlcihmb3JtKSB7XG4gICAgICBpZiAoYW5ndWxhci5pc1VuZGVmaW5lZCh2bS5xdWVyeUZpbHRlcnMudmFsdWUpIHx8IHZtLnF1ZXJ5RmlsdGVycy52YWx1ZSA9PT0gJycpIHtcbiAgICAgICAgUHJUb2FzdC5lcnJvcigkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnZhbGlkYXRlLmZpZWxkUmVxdWlyZWQnLCB7IGZpZWxkOiAndmFsb3InIH0pKTtcbiAgICAgICAgcmV0dXJuO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgaWYgKHZtLmluZGV4IDwgMCkge1xuICAgICAgICAgIHZtLmFkZGVkRmlsdGVycy5wdXNoKGFuZ3VsYXIuY29weSh2bS5xdWVyeUZpbHRlcnMpKTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICB2bS5hZGRlZEZpbHRlcnNbdm0uaW5kZXhdID0gYW5ndWxhci5jb3B5KHZtLnF1ZXJ5RmlsdGVycyk7XG4gICAgICAgICAgdm0uaW5kZXggPSAtMTtcbiAgICAgICAgfVxuXG4gICAgICAgIC8vcmVpbmljaWEgbyBmb3JtdWzDoXJpbyBlIGFzIHZhbGlkYcOnw7VlcyBleGlzdGVudGVzXG4gICAgICAgIHZtLnF1ZXJ5RmlsdGVycyA9IHt9O1xuICAgICAgICBmb3JtLiRzZXRQcmlzdGluZSgpO1xuICAgICAgICBmb3JtLiRzZXRVbnRvdWNoZWQoKTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFsaXphIGEgcGVzcXVpc2EgdGVuZG8gb3MgZmlsdHJvcyBjb21vIHBhcsOibWV0cm9zXG4gICAgICovXG4gICAgZnVuY3Rpb24gcnVuRmlsdGVyKCkge1xuICAgICAgdm0uc2VhcmNoKHZtLnBhZ2luYXRvci5jdXJyZW50UGFnZSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogR2F0aWxobyBhY2lvbmFkbyBkZXBvaXMgZGEgcGVzcXVpc2EgcmVzcG9uc8OhdmVsIHBvciBpZGVudGlmaWNhciBvcyBhdHJpYnV0b3NcbiAgICAgKiBjb250aWRvcyBub3MgZWxlbWVudG9zIHJlc3VsdGFudGVzIGRhIGJ1c2NhXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gZGF0YSBkYWRvcyByZWZlcmVudGUgYW8gcmV0b3JubyBkYSByZXF1aXNpw6fDo29cbiAgICAgKi9cbiAgICBmdW5jdGlvbiBhZnRlclNlYXJjaChkYXRhKSB7XG4gICAgICB2YXIga2V5cyA9IChkYXRhLml0ZW1zLmxlbmd0aCA+IDApID8gT2JqZWN0LmtleXMoZGF0YS5pdGVtc1swXSkgOiBbXTtcblxuICAgICAgLy9yZXRpcmEgdG9kb3Mgb3MgYXRyaWJ1dG9zIHF1ZSBjb21lw6dhbSBjb20gJC5cbiAgICAgIC8vRXNzZXMgYXRyaWJ1dG9zIHPDo28gYWRpY2lvbmFkb3MgcGVsbyBzZXJ2acOnbyBlIG7Do28gZGV2ZSBhcGFyZWNlciBuYSBsaXN0YWdlbVxuICAgICAgdm0ua2V5cyA9IGxvZGFzaC5maWx0ZXIoa2V5cywgZnVuY3Rpb24oa2V5KSB7XG4gICAgICAgIHJldHVybiAhbG9kYXNoLnN0YXJ0c1dpdGgoa2V5LCAnJCcpO1xuICAgICAgfSlcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDb2xvYWNhIG5vIGZvcm11bMOhcmlvIG8gZmlsdHJvIGVzY29saGlkbyBwYXJhIGVkacOnw6NvXG4gICAgICogQHBhcmFtIHthbnl9ICRpbmRleCBpbmRpY2Ugbm8gYXJyYXkgZG8gZmlsdHJvIGVzY29saGlkb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGVkaXRGaWx0ZXIoJGluZGV4KSB7XG4gICAgICB2bS5pbmRleCA9ICRpbmRleDtcbiAgICAgIHZtLnF1ZXJ5RmlsdGVycyA9IHZtLmFkZGVkRmlsdGVyc1skaW5kZXhdO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlbW92ZSBvIGZpbHRybyBlc2NvbGhpZG9cbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSAkaW5kZXggaW5kaWNlIG5vIGFycmF5IGRvIGZpbHRybyBlc2NvbGhpZG9cbiAgICAgKi9cbiAgICBmdW5jdGlvbiByZW1vdmVGaWx0ZXIoJGluZGV4KSB7XG4gICAgICB2bS5hZGRlZEZpbHRlcnMuc3BsaWNlKCRpbmRleCk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogTGltcGEgbyBmb3JtdWzDoXJpbyBjb3JyZW50ZVxuICAgICAqL1xuICAgIGZ1bmN0aW9uIGNsZWFyKCkge1xuICAgICAgLy9ndWFyZGEgbyBpbmRpY2UgZG8gcmVnaXN0cm8gcXVlIGVzdMOhIHNlbmRvIGVkaXRhZG9cbiAgICAgIHZtLmluZGV4ID0gLTE7XG4gICAgICAvL3ZpbmN1bGFkbyBhb3MgY2FtcG9zIGRvIGZvcm11bMOhcmlvXG4gICAgICB2bS5xdWVyeUZpbHRlcnMgPSB7XG4gICAgICB9O1xuXG4gICAgICBpZiAodm0ubW9kZWxzKSB2bS5xdWVyeUZpbHRlcnMubW9kZWwgPSB2bS5tb2RlbHNbMF07XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVpbmljaWEgYSBjb25zdHJ1w6fDo28gZGEgcXVlcnkgbGltcGFuZG8gdHVkb1xuICAgICAqXG4gICAgICovXG4gICAgZnVuY3Rpb24gcmVzdGFydCgpIHtcbiAgICAgIC8vZ3VhcmRhIGF0cmlidXRvcyBkbyByZXN1bHRhZG8gZGEgYnVzY2EgY29ycmVudGVcbiAgICAgIHZtLmtleXMgPSBbXTtcblxuICAgICAgLy9ndWFyZGEgb3MgZmlsdHJvcyBhZGljaW9uYWRvc1xuICAgICAgdm0uYWRkZWRGaWx0ZXJzID0gW107XG4gICAgICB2bS5jbGVhcigpO1xuICAgICAgdm0ubG9hZE1vZGVscygpO1xuICAgIH1cblxuICB9XG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5mYWN0b3J5KCdsYW5ndWFnZUxvYWRlcicsIExhbmd1YWdlTG9hZGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIExhbmd1YWdlTG9hZGVyKCRxLCBTdXBwb3J0U2VydmljZSwgJGxvZywgJGluamVjdG9yKSB7XG4gICAgdmFyIHNlcnZpY2UgPSB0aGlzO1xuXG4gICAgc2VydmljZS50cmFuc2xhdGUgPSBmdW5jdGlvbihsb2NhbGUpIHtcbiAgICAgIHJldHVybiB7XG4gICAgICAgIGdsb2JhbDogJGluamVjdG9yLmdldChsb2NhbGUgKyAnLmkxOG4uZ2xvYmFsJyksXG4gICAgICAgIHZpZXdzOiAkaW5qZWN0b3IuZ2V0KGxvY2FsZSArICcuaTE4bi52aWV3cycpLFxuICAgICAgICBhdHRyaWJ1dGVzOiAkaW5qZWN0b3IuZ2V0KGxvY2FsZSArICcuaTE4bi5hdHRyaWJ1dGVzJyksXG4gICAgICAgIGRpYWxvZzogJGluamVjdG9yLmdldChsb2NhbGUgKyAnLmkxOG4uZGlhbG9nJyksXG4gICAgICAgIG1lc3NhZ2VzOiAkaW5qZWN0b3IuZ2V0KGxvY2FsZSArICcuaTE4bi5tZXNzYWdlcycpLFxuICAgICAgICBtb2RlbHM6ICRpbmplY3Rvci5nZXQobG9jYWxlICsgJy5pMThuLm1vZGVscycpXG4gICAgICB9O1xuICAgIH1cblxuICAgIC8vIHJldHVybiBsb2FkZXJGblxuICAgIHJldHVybiBmdW5jdGlvbihvcHRpb25zKSB7XG4gICAgICAkbG9nLmluZm8oJ0NhcnJlZ2FuZG8gbyBjb250ZXVkbyBkYSBsaW5ndWFnZW0gJyArIG9wdGlvbnMua2V5KTtcblxuICAgICAgdmFyIGRlZmVycmVkID0gJHEuZGVmZXIoKTtcblxuICAgICAgLy9DYXJyZWdhIGFzIGxhbmdzIHF1ZSBwcmVjaXNhbSBlIGVzdMOjbyBubyBzZXJ2aWRvciBwYXJhIG7Do28gcHJlY2lzYXIgcmVwZXRpciBhcXVpXG4gICAgICBTdXBwb3J0U2VydmljZS5sYW5ncygpLnRoZW4oZnVuY3Rpb24obGFuZ3MpIHtcbiAgICAgICAgLy9NZXJnZSBjb20gb3MgbGFuZ3MgZGVmaW5pZG9zIG5vIHNlcnZpZG9yXG4gICAgICAgIHZhciBkYXRhID0gYW5ndWxhci5tZXJnZShzZXJ2aWNlLnRyYW5zbGF0ZShvcHRpb25zLmtleSksIGxhbmdzKTtcblxuICAgICAgICByZXR1cm4gZGVmZXJyZWQucmVzb2x2ZShkYXRhKTtcbiAgICAgIH0sIGZ1bmN0aW9uKCkge1xuICAgICAgICByZXR1cm4gZGVmZXJyZWQucmVzb2x2ZShzZXJ2aWNlLnRyYW5zbGF0ZShvcHRpb25zLmtleSkpO1xuICAgICAgfSk7XG5cbiAgICAgIHJldHVybiBkZWZlcnJlZC5wcm9taXNlO1xuICAgIH1cbiAgfVxuXG59KSgpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmlsdGVyKCd0QXR0cicsIHRBdHRyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIHRBdHRyKCRmaWx0ZXIpIHtcbiAgICAvKipcbiAgICAgKiBGaWx0cm8gcGFyYSB0cmFkdcOnw6NvIGRlIHVtIGF0cmlidXRvIGRlIHVtIG1vZGVsXG4gICAgICogXG4gICAgICogQHBhcmFtIHthbnl9IG5hbWUgbm9tZSBkbyBhdHJpYnV0b1xuICAgICAqIEByZXR1cm5zIG8gbm9tZSBkbyBhdHJpYnV0byB0cmFkdXppZG8gY2FzbyBlbmNvbnRyZSBzZSBuw6NvIG8gbm9tZSBwYXNzYWRvIHBvciBwYXJhbWV0cm9cbiAgICAgKi8gICAgXG4gICAgcmV0dXJuIGZ1bmN0aW9uKG5hbWUpIHtcbiAgICAgIHZhciBrZXkgPSAnYXR0cmlidXRlcy4nICsgbmFtZTtcbiAgICAgIHZhciB0cmFuc2xhdGUgPSAkZmlsdGVyKCd0cmFuc2xhdGUnKShrZXkpO1xuXG4gICAgICByZXR1cm4gKHRyYW5zbGF0ZSA9PT0ga2V5KSA/IG5hbWUgOiB0cmFuc2xhdGU7XG4gICAgfVxuICB9XG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5maWx0ZXIoJ3RCcmVhZGNydW1iJywgdEJyZWFkY3J1bWIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gdEJyZWFkY3J1bWIoJGZpbHRlcikge1xuICAgIC8qKlxuICAgICAqIEZpbHRybyBwYXJhIHRyYWR1w6fDo28gZG8gYnJlYWRjcnVtYiAodGl0dWxvIGRhIHRlbGEgY29tIHJhc3RyZWlvKVxuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IGlkIGNoYXZlIGNvbSBvIG5vbWUgZG8gc3RhdGUgcmVmZXJlbnRlIHRlbGFcbiAgICAgKiBAcmV0dXJucyBhIHRyYWR1w6fDo28gY2FzbyBlbmNvbnRyZSBzZSBuw6NvIG8gaWQgcGFzc2FkbyBwb3IgcGFyYW1ldHJvXG4gICAgICovXG4gICAgcmV0dXJuIGZ1bmN0aW9uKGlkKSB7XG4gICAgICAvL3BlZ2EgYSBzZWd1bmRhIHBhcnRlIGRvIG5vbWUgZG8gc3RhdGUsIHJldGlyYW5kbyBhIHBhcnRlIGFic3RyYXRhIChhcHAuKVxuICAgICAgdmFyIGtleSA9ICd2aWV3cy5icmVhZGNydW1icy4nICsgaWQuc3BsaXQoJy4nKVsxXTtcbiAgICAgIHZhciB0cmFuc2xhdGUgPSAkZmlsdGVyKCd0cmFuc2xhdGUnKShrZXkpO1xuXG4gICAgICByZXR1cm4gKHRyYW5zbGF0ZSA9PT0ga2V5KSA/IGlkIDogdHJhbnNsYXRlO1xuICAgIH1cbiAgfVxuXG59KSgpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmlsdGVyKCd0TW9kZWwnLCB0TW9kZWwpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gdE1vZGVsKCRmaWx0ZXIpIHtcbiAgICAvKipcbiAgICAgKiBGaWx0cm8gcGFyYSB0cmFkdcOnw6NvIGRlIHVtIGF0cmlidXRvIGRlIHVtIG1vZGVsXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gbmFtZSBub21lIGRvIGF0cmlidXRvXG4gICAgICogQHJldHVybnMgbyBub21lIGRvIGF0cmlidXRvIHRyYWR1emlkbyBjYXNvIGVuY29udHJlIHNlIG7Do28gbyBub21lIHBhc3NhZG8gcG9yIHBhcmFtZXRyb1xuICAgICAqL1xuICAgIHJldHVybiBmdW5jdGlvbihuYW1lKSB7XG4gICAgICB2YXIga2V5ID0gJ21vZGVscy4nICsgbmFtZS50b0xvd2VyQ2FzZSgpO1xuICAgICAgdmFyIHRyYW5zbGF0ZSA9ICRmaWx0ZXIoJ3RyYW5zbGF0ZScpKGtleSk7XG5cbiAgICAgIHJldHVybiAodHJhbnNsYXRlID09PSBrZXkpID8gbmFtZSA6IHRyYW5zbGF0ZTtcbiAgICB9XG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5ydW4oYXV0aGVudGljYXRpb25MaXN0ZW5lcik7XG5cbiAgLyoqXG4gICAqIExpc3RlbiBhbGwgc3RhdGUgKHBhZ2UpIGNoYW5nZXMuIEV2ZXJ5IHRpbWUgYSBzdGF0ZSBjaGFuZ2UgbmVlZCB0byB2ZXJpZnkgdGhlIHVzZXIgaXMgYXV0aGVudGljYXRlZCBvciBub3QgdG9cbiAgICogcmVkaXJlY3QgdG8gY29ycmVjdCBwYWdlLiBXaGVuIGEgdXNlciBjbG9zZSB0aGUgYnJvd3NlciB3aXRob3V0IGxvZ291dCwgd2hlbiBoaW0gcmVvcGVuIHRoZSBicm93c2VyIHRoaXMgZXZlbnRcbiAgICogcmVhdXRoZW50aWNhdGUgdGhlIHVzZXIgd2l0aCB0aGUgcGVyc2lzdGVudCB0b2tlbiBvZiB0aGUgbG9jYWwgc3RvcmFnZS5cbiAgICpcbiAgICogV2UgZG9uJ3QgY2hlY2sgaWYgdGhlIHRva2VuIGlzIGV4cGlyZWQgb3Igbm90IGluIHRoZSBwYWdlIGNoYW5nZSwgYmVjYXVzZSBpcyBnZW5lcmF0ZSBhbiB1bmVjZXNzYXJ5IG92ZXJoZWFkLlxuICAgKiBJZiB0aGUgdG9rZW4gaXMgZXhwaXJlZCB3aGVuIHRoZSB1c2VyIHRyeSB0byBjYWxsIHRoZSBmaXJzdCBhcGkgdG8gZ2V0IGRhdGEsIGhpbSB3aWxsIGJlIGxvZ29mZiBhbmQgcmVkaXJlY3RcbiAgICogdG8gbG9naW4gcGFnZS5cbiAgICpcbiAgICogQHBhcmFtICRyb290U2NvcGVcbiAgICogQHBhcmFtICRzdGF0ZVxuICAgKiBAcGFyYW0gJHN0YXRlUGFyYW1zXG4gICAqIEBwYXJhbSBBdXRoXG4gICAqL1xuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIGF1dGhlbnRpY2F0aW9uTGlzdGVuZXIoJHJvb3RTY29wZSwgJHN0YXRlLCBHbG9iYWwsIEF1dGgsIFByVG9hc3QsIC8vIE5PU09OQVJcbiAgICAkdHJhbnNsYXRlKSB7XG5cbiAgICAvL29ubHkgd2hlbiBhcHBsaWNhdGlvbiBzdGFydCBjaGVjayBpZiB0aGUgZXhpc3RlbnQgdG9rZW4gc3RpbGwgdmFsaWRcbiAgICBBdXRoLnJlbW90ZVZhbGlkYXRlVG9rZW4oKS50aGVuKGZ1bmN0aW9uKCkge1xuICAgICAgLy9pZiB0aGUgdG9rZW4gaXMgdmFsaWQgY2hlY2sgaWYgZXhpc3RzIHRoZSB1c2VyIGJlY2F1c2UgdGhlIGJyb3dzZXIgY291bGQgYmUgY2xvc2VkXG4gICAgICAvL2FuZCB0aGUgdXNlciBkYXRhIGlzbid0IGluIG1lbW9yeVxuICAgICAgaWYgKEF1dGguY3VycmVudFVzZXIgPT09IG51bGwpIHtcbiAgICAgICAgQXV0aC51cGRhdGVDdXJyZW50VXNlcihhbmd1bGFyLmZyb21Kc29uKGxvY2FsU3RvcmFnZS5nZXRJdGVtKCd1c2VyJykpKTtcbiAgICAgIH1cbiAgICB9KTtcblxuICAgIC8vQ2hlY2sgaWYgdGhlIHRva2VuIHN0aWxsIHZhbGlkLlxuICAgICRyb290U2NvcGUuJG9uKCckc3RhdGVDaGFuZ2VTdGFydCcsIGZ1bmN0aW9uKGV2ZW50LCB0b1N0YXRlKSB7XG4gICAgICBpZiAodG9TdGF0ZS5kYXRhLm5lZWRBdXRoZW50aWNhdGlvbiB8fCB0b1N0YXRlLmRhdGEubmVlZFByb2ZpbGUpIHtcbiAgICAgICAgLy9kb250IHRyYWl0IHRoZSBzdWNjZXNzIGJsb2NrIGJlY2F1c2UgYWxyZWFkeSBkaWQgYnkgdG9rZW4gaW50ZXJjZXB0b3JcbiAgICAgICAgQXV0aC5yZW1vdGVWYWxpZGF0ZVRva2VuKCkuY2F0Y2goZnVuY3Rpb24oKSB7XG4gICAgICAgICAgUHJUb2FzdC53YXJuKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMubG9naW4ubG9nb3V0SW5hY3RpdmUnKSk7XG5cbiAgICAgICAgICBpZiAodG9TdGF0ZS5uYW1lICE9PSBHbG9iYWwubG9naW5TdGF0ZSkge1xuICAgICAgICAgICAgJHN0YXRlLmdvKEdsb2JhbC5sb2dpblN0YXRlKTtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICBldmVudC5wcmV2ZW50RGVmYXVsdCgpO1xuICAgICAgICB9KTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIC8vaWYgdGhlIHVzZSBpcyBhdXRoZW50aWNhdGVkIGFuZCBuZWVkIHRvIGVudGVyIGluIGxvZ2luIHBhZ2VcbiAgICAgICAgLy9oaW0gd2lsbCBiZSByZWRpcmVjdGVkIHRvIGhvbWUgcGFnZVxuICAgICAgICBpZiAodG9TdGF0ZS5uYW1lID09PSBHbG9iYWwubG9naW5TdGF0ZSAmJiBBdXRoLmF1dGhlbnRpY2F0ZWQoKSkge1xuICAgICAgICAgICRzdGF0ZS5nbyhHbG9iYWwuaG9tZVN0YXRlKTtcbiAgICAgICAgICBldmVudC5wcmV2ZW50RGVmYXVsdCgpO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfSk7XG4gIH1cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAucnVuKGF1dGhvcml6YXRpb25MaXN0ZW5lcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiBhdXRob3JpemF0aW9uTGlzdGVuZXIoJHJvb3RTY29wZSwgJHN0YXRlLCBHbG9iYWwsIEF1dGgpIHtcbiAgICAvKipcbiAgICAgKiBBIGNhZGEgbXVkYW7Dp2EgZGUgZXN0YWRvIChcInDDoWdpbmFcIikgdmVyaWZpY2Egc2UgbyB1c3XDoXJpbyB0ZW0gbyBwZXJmaWxcbiAgICAgKiBuZWNlc3PDoXJpbyBwYXJhIG8gYWNlc3NvIGEgbWVzbWFcbiAgICAgKi9cbiAgICAkcm9vdFNjb3BlLiRvbignJHN0YXRlQ2hhbmdlU3RhcnQnLCBmdW5jdGlvbihldmVudCwgdG9TdGF0ZSkge1xuICAgICAgaWYgKHRvU3RhdGUuZGF0YSAmJiB0b1N0YXRlLmRhdGEubmVlZEF1dGhlbnRpY2F0aW9uICYmXG4gICAgICAgIHRvU3RhdGUuZGF0YS5uZWVkUHJvZmlsZSAmJiBBdXRoLmF1dGhlbnRpY2F0ZWQoKSAmJlxuICAgICAgICAhQXV0aC5jdXJyZW50VXNlci5oYXNQcm9maWxlKHRvU3RhdGUuZGF0YS5uZWVkUHJvZmlsZSwgdG9TdGF0ZS5kYXRhLmFsbFByb2ZpbGVzKSkge1xuXG4gICAgICAgICRzdGF0ZS5nbyhHbG9iYWwubm90QXV0aG9yaXplZFN0YXRlKTtcbiAgICAgICAgZXZlbnQucHJldmVudERlZmF1bHQoKTtcbiAgICAgIH1cblxuICAgIH0pO1xuICB9XG59KCkpO1xuIiwiKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb25maWcoc3Bpbm5lckludGVyY2VwdG9yKTtcblxuICBmdW5jdGlvbiBzcGlubmVySW50ZXJjZXB0b3IoJGh0dHBQcm92aWRlciwgJHByb3ZpZGUpIHtcbiAgICAvKipcbiAgICAgKiBFc3RlIGludGVyY2VwdG9yIMOpIHJlc3BvbnPDoXZlbCBwb3IgbW9zdHJhciBlIGVzY29uZGVyIG9cbiAgICAgKiBjb21wb25lbnRlIFByU3Bpbm5lciBzZW1wcmUgcXVlIHVtYSByZXF1aXNpw6fDo28gYWpheFxuICAgICAqIGluaWNpYXIgZSBmaW5hbGl6YXIuXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gJHFcbiAgICAgKiBAcGFyYW0ge2FueX0gJGluamVjdG9yXG4gICAgICogQHJldHVybnNcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBzaG93SGlkZVNwaW5uZXIoJHEsICRpbmplY3Rvcikge1xuICAgICAgcmV0dXJuIHtcbiAgICAgICAgcmVxdWVzdDogZnVuY3Rpb24gKGNvbmZpZykge1xuICAgICAgICAgICRpbmplY3Rvci5nZXQoJ1ByU3Bpbm5lcicpLnNob3coKTtcblxuICAgICAgICAgIHJldHVybiBjb25maWc7XG4gICAgICAgIH0sXG5cbiAgICAgICAgcmVzcG9uc2U6IGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICAgICRpbmplY3Rvci5nZXQoJ1ByU3Bpbm5lcicpLmhpZGUoKTtcblxuICAgICAgICAgIHJldHVybiByZXNwb25zZTtcbiAgICAgICAgfSxcblxuICAgICAgICByZXNwb25zZUVycm9yOiBmdW5jdGlvbiAocmVqZWN0aW9uKSB7XG4gICAgICAgICAgJGluamVjdG9yLmdldCgnUHJTcGlubmVyJykuaGlkZSgpO1xuXG4gICAgICAgICAgcmV0dXJuICRxLnJlamVjdChyZWplY3Rpb24pO1xuICAgICAgICB9XG4gICAgICB9O1xuICAgIH1cblxuICAgIC8vIERlZmluZSB1bWEgZmFjdG9yeSBwYXJhIG8gJGh0dHBJbnRlcmNlcHRvclxuICAgICRwcm92aWRlLmZhY3RvcnkoJ3Nob3dIaWRlU3Bpbm5lcicsIHNob3dIaWRlU3Bpbm5lcik7XG5cbiAgICAvLyBBZGljaW9uYSBhIGZhY3Rvcnkgbm8gYXJyYXkgZGUgaW50ZXJjZXB0b3JzIGRvICRodHRwXG4gICAgJGh0dHBQcm92aWRlci5pbnRlcmNlcHRvcnMucHVzaCgnc2hvd0hpZGVTcGlubmVyJyk7XG4gIH1cbn0oKSk7XG4iLCIvKmVzbGludCBhbmd1bGFyL21vZHVsZS1nZXR0ZXI6IDAqL1xuXG4oZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uZmlnKHRva2VuSW50ZXJjZXB0b3IpO1xuXG4gIC8qKlxuICAgKiBJbnRlcmNlcHQgYWxsIHJlc3BvbnNlIChzdWNjZXNzIG9yIGVycm9yKSB0byB2ZXJpZnkgdGhlIHJldHVybmVkIHRva2VuXG4gICAqXG4gICAqIEBwYXJhbSAkaHR0cFByb3ZpZGVyXG4gICAqIEBwYXJhbSAkcHJvdmlkZVxuICAgKiBAcGFyYW0gR2xvYmFsXG4gICAqL1xuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHRva2VuSW50ZXJjZXB0b3IoJGh0dHBQcm92aWRlciwgJHByb3ZpZGUsIEdsb2JhbCkge1xuXG4gICAgZnVuY3Rpb24gcmVkaXJlY3RXaGVuU2VydmVyTG9nZ2VkT3V0KCRxLCAkaW5qZWN0b3IpIHtcbiAgICAgIHJldHVybiB7XG4gICAgICAgIHJlcXVlc3Q6IGZ1bmN0aW9uKGNvbmZpZykge1xuICAgICAgICAgIHZhciB0b2tlbiA9ICRpbmplY3Rvci5nZXQoJ0F1dGgnKS5nZXRUb2tlbigpO1xuXG4gICAgICAgICAgaWYgKHRva2VuKSB7XG4gICAgICAgICAgICBjb25maWcuaGVhZGVyc1snQXV0aG9yaXphdGlvbiddID0gJ0JlYXJlciAnICsgdG9rZW47XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgcmV0dXJuIGNvbmZpZztcbiAgICAgICAgfSxcbiAgICAgICAgcmVzcG9uc2U6IGZ1bmN0aW9uKHJlc3BvbnNlKSB7XG4gICAgICAgICAgLy8gZ2V0IGEgbmV3IHJlZnJlc2ggdG9rZW4gdG8gdXNlIGluIHRoZSBuZXh0IHJlcXVlc3RcbiAgICAgICAgICB2YXIgdG9rZW4gPSByZXNwb25zZS5oZWFkZXJzKCdBdXRob3JpemF0aW9uJyk7XG5cbiAgICAgICAgICBpZiAodG9rZW4pIHtcbiAgICAgICAgICAgICRpbmplY3Rvci5nZXQoJ0F1dGgnKS5zZXRUb2tlbih0b2tlbi5zcGxpdCgnICcpWzFdKTtcbiAgICAgICAgICB9XG4gICAgICAgICAgcmV0dXJuIHJlc3BvbnNlO1xuICAgICAgICB9LFxuICAgICAgICByZXNwb25zZUVycm9yOiBmdW5jdGlvbihyZWplY3Rpb24pIHtcbiAgICAgICAgICAvLyBJbnN0ZWFkIG9mIGNoZWNraW5nIGZvciBhIHN0YXR1cyBjb2RlIG9mIDQwMCB3aGljaCBtaWdodCBiZSB1c2VkXG4gICAgICAgICAgLy8gZm9yIG90aGVyIHJlYXNvbnMgaW4gTGFyYXZlbCwgd2UgY2hlY2sgZm9yIHRoZSBzcGVjaWZpYyByZWplY3Rpb25cbiAgICAgICAgICAvLyByZWFzb25zIHRvIHRlbGwgdXMgaWYgd2UgbmVlZCB0byByZWRpcmVjdCB0byB0aGUgbG9naW4gc3RhdGVcbiAgICAgICAgICB2YXIgcmVqZWN0aW9uUmVhc29ucyA9IFsndG9rZW5fbm90X3Byb3ZpZGVkJywgJ3Rva2VuX2V4cGlyZWQnLCAndG9rZW5fYWJzZW50JywgJ3Rva2VuX2ludmFsaWQnXTtcblxuICAgICAgICAgIHZhciB0b2tlbkVycm9yID0gZmFsc2U7XG5cbiAgICAgICAgICBhbmd1bGFyLmZvckVhY2gocmVqZWN0aW9uUmVhc29ucywgZnVuY3Rpb24odmFsdWUpIHtcbiAgICAgICAgICAgIGlmIChyZWplY3Rpb24uZGF0YSAmJiByZWplY3Rpb24uZGF0YS5lcnJvciA9PT0gdmFsdWUpIHtcbiAgICAgICAgICAgICAgdG9rZW5FcnJvciA9IHRydWU7XG5cbiAgICAgICAgICAgICAgJGluamVjdG9yLmdldCgnQXV0aCcpLmxvZ291dCgpLnRoZW4oZnVuY3Rpb24oKSB7XG4gICAgICAgICAgICAgICAgdmFyICRzdGF0ZSA9ICRpbmplY3Rvci5nZXQoJyRzdGF0ZScpO1xuXG4gICAgICAgICAgICAgICAgLy8gaW4gY2FzZSBtdWx0aXBsZSBhamF4IHJlcXVlc3QgZmFpbCBhdCBzYW1lIHRpbWUgYmVjYXVzZSB0b2tlbiBwcm9ibGVtcyxcbiAgICAgICAgICAgICAgICAvLyBvbmx5IHRoZSBmaXJzdCB3aWxsIHJlZGlyZWN0XG4gICAgICAgICAgICAgICAgaWYgKCEkc3RhdGUuaXMoR2xvYmFsLmxvZ2luU3RhdGUpKSB7XG4gICAgICAgICAgICAgICAgICAkc3RhdGUuZ28oR2xvYmFsLmxvZ2luU3RhdGUpO1xuXG4gICAgICAgICAgICAgICAgICAvL2Nsb3NlIGFueSBkaWFsb2cgdGhhdCBpcyBvcGVuZWRcbiAgICAgICAgICAgICAgICAgICRpbmplY3Rvci5nZXQoJ1ByRGlhbG9nJykuY2xvc2UoKTtcblxuICAgICAgICAgICAgICAgICAgZXZlbnQucHJldmVudERlZmF1bHQoKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgfVxuICAgICAgICAgIH0pO1xuXG4gICAgICAgICAgLy9kZWZpbmUgZGF0YSB0byBlbXB0eSBiZWNhdXNlIGFscmVhZHkgc2hvdyBQclRvYXN0IHRva2VuIG1lc3NhZ2VcbiAgICAgICAgICBpZiAodG9rZW5FcnJvcikge1xuICAgICAgICAgICAgcmVqZWN0aW9uLmRhdGEgPSB7fTtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHJlamVjdGlvbi5oZWFkZXJzKSkge1xuICAgICAgICAgICAgLy8gbWFueSBzZXJ2ZXJzIGVycm9ycyAoYnVzaW5lc3MpIGFyZSBpbnRlcmNlcHQgaGVyZSBidXQgZ2VuZXJhdGVkIGEgbmV3IHJlZnJlc2ggdG9rZW5cbiAgICAgICAgICAgIC8vIGFuZCBuZWVkIHVwZGF0ZSBjdXJyZW50IHRva2VuXG4gICAgICAgICAgICB2YXIgdG9rZW4gPSByZWplY3Rpb24uaGVhZGVycygnQXV0aG9yaXphdGlvbicpO1xuXG4gICAgICAgICAgICBpZiAodG9rZW4pIHtcbiAgICAgICAgICAgICAgJGluamVjdG9yLmdldCgnQXV0aCcpLnNldFRva2VuKHRva2VuLnNwbGl0KCcgJylbMV0pO1xuICAgICAgICAgICAgfVxuICAgICAgICAgIH1cblxuICAgICAgICAgIHJldHVybiAkcS5yZWplY3QocmVqZWN0aW9uKTtcbiAgICAgICAgfVxuICAgICAgfTtcbiAgICB9XG5cbiAgICAvLyBTZXR1cCBmb3IgdGhlICRodHRwSW50ZXJjZXB0b3JcbiAgICAkcHJvdmlkZS5mYWN0b3J5KCdyZWRpcmVjdFdoZW5TZXJ2ZXJMb2dnZWRPdXQnLCByZWRpcmVjdFdoZW5TZXJ2ZXJMb2dnZWRPdXQpO1xuXG4gICAgLy8gUHVzaCB0aGUgbmV3IGZhY3Rvcnkgb250byB0aGUgJGh0dHAgaW50ZXJjZXB0b3IgYXJyYXlcbiAgICAkaHR0cFByb3ZpZGVyLmludGVyY2VwdG9ycy5wdXNoKCdyZWRpcmVjdFdoZW5TZXJ2ZXJMb2dnZWRPdXQnKTtcbiAgfVxuXG59KCkpO1xuIiwiKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb25maWcodmFsaWRhdGlvbkludGVyY2VwdG9yKTtcblxuICBmdW5jdGlvbiB2YWxpZGF0aW9uSW50ZXJjZXB0b3IoJGh0dHBQcm92aWRlciwgJHByb3ZpZGUpIHtcbiAgICAvKipcbiAgICAgKiBFc3RlIGludGVyY2VwdG9yIMOpIHJlc3BvbnPDoXZlbCBwb3IgbW9zdHJhciBhc1xuICAgICAqIG1lbnNhZ2VucyBkZSBlcnJvIHJlZmVyZW50ZSBhcyB2YWxpZGHDp8O1ZXMgZG8gYmFjay1lbmRcbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSAkcVxuICAgICAqIEBwYXJhbSB7YW55fSAkaW5qZWN0b3JcbiAgICAgKiBAcmV0dXJuc1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIHNob3dFcnJvclZhbGlkYXRpb24oJHEsICRpbmplY3Rvcikge1xuICAgICAgcmV0dXJuIHtcbiAgICAgICAgcmVzcG9uc2VFcnJvcjogZnVuY3Rpb24gKHJlamVjdGlvbikge1xuICAgICAgICAgIHZhciBQclRvYXN0ID0gJGluamVjdG9yLmdldCgnUHJUb2FzdCcpO1xuICAgICAgICAgIHZhciAkdHJhbnNsYXRlID0gJGluamVjdG9yLmdldCgnJHRyYW5zbGF0ZScpO1xuXG4gICAgICAgICAgaWYgKHJlamVjdGlvbi5jb25maWcuZGF0YSAmJiAhcmVqZWN0aW9uLmNvbmZpZy5kYXRhLnNraXBWYWxpZGF0aW9uKSB7XG4gICAgICAgICAgICBpZiAocmVqZWN0aW9uLmRhdGEgJiYgcmVqZWN0aW9uLmRhdGEuZXJyb3IpIHtcblxuICAgICAgICAgICAgICAvL3ZlcmlmaWNhIHNlIG9jb3JyZXUgYWxndW0gZXJybyByZWZlcmVudGUgYW8gdG9rZW5cbiAgICAgICAgICAgICAgaWYgKHJlamVjdGlvbi5kYXRhLmVycm9yLnN0YXJ0c1dpdGgoJ3Rva2VuXycpKSB7XG4gICAgICAgICAgICAgICAgUHJUb2FzdC53YXJuKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMubG9naW4ubG9nb3V0SW5hY3RpdmUnKSk7XG4gICAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgUHJUb2FzdC5lcnJvcigkdHJhbnNsYXRlLmluc3RhbnQocmVqZWN0aW9uLmRhdGEuZXJyb3IpKTtcbiAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgUHJUb2FzdC5lcnJvclZhbGlkYXRpb24ocmVqZWN0aW9uLmRhdGEpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgIH1cblxuICAgICAgICAgIHJldHVybiAkcS5yZWplY3QocmVqZWN0aW9uKTtcbiAgICAgICAgfVxuICAgICAgfTtcbiAgICB9XG5cbiAgICAvLyBEZWZpbmUgdW1hIGZhY3RvcnkgcGFyYSBvICRodHRwSW50ZXJjZXB0b3JcbiAgICAkcHJvdmlkZS5mYWN0b3J5KCdzaG93RXJyb3JWYWxpZGF0aW9uJywgc2hvd0Vycm9yVmFsaWRhdGlvbik7XG5cbiAgICAvLyBBZGljaW9uYSBhIGZhY3Rvcnkgbm8gYXJyYXkgZGUgaW50ZXJjZXB0b3JzIGRvICRodHRwXG4gICAgJGh0dHBQcm92aWRlci5pbnRlcmNlcHRvcnMucHVzaCgnc2hvd0Vycm9yVmFsaWRhdGlvbicpO1xuICB9XG59KCkpO1xuIiwiLyplc2xpbnQtZW52IGVzNiovXG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb250cm9sbGVyKCdNZW51Q29udHJvbGxlcicsIE1lbnVDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIE1lbnVDb250cm9sbGVyKCRtZFNpZGVuYXYsICRzdGF0ZSwgJG1kQ29sb3JzKSB7XG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIC8vQmxvY28gZGUgZGVjbGFyYWNvZXMgZGUgZnVuY29lc1xuICAgIHZtLm9wZW4gPSBvcGVuO1xuICAgIHZtLm9wZW5NZW51T3JSZWRpcmVjdFRvU3RhdGUgPSBvcGVuTWVudU9yUmVkaXJlY3RUb1N0YXRlO1xuXG4gICAgYWN0aXZhdGUoKTtcblxuICAgIGZ1bmN0aW9uIGFjdGl2YXRlKCkge1xuICAgICAgdmFyIG1lbnVQcmVmaXggPSAndmlld3MubGF5b3V0Lm1lbnUuJztcblxuICAgICAgLy8gQXJyYXkgY29udGVuZG8gb3MgaXRlbnMgcXVlIHPDo28gbW9zdHJhZG9zIG5vIG1lbnUgbGF0ZXJhbFxuICAgICAgdm0uaXRlbnNNZW51ID0gW1xuICAgICAgICB7IHN0YXRlOiAnYXBwLmRhc2hib2FyZCcsIHRpdGxlOiBtZW51UHJlZml4ICsgJ2Rhc2hib2FyZCcsIGljb246ICdkYXNoYm9hcmQnLCBzdWJJdGVuczogW10gfSxcbiAgICAgICAge1xuICAgICAgICAgIHN0YXRlOiAnIycsIHRpdGxlOiBtZW51UHJlZml4ICsgJ2V4YW1wbGVzJywgaWNvbjogJ3ZpZXdfY2Fyb3VzZWwnLCBwcm9maWxlczogWydhZG1pbiddLFxuICAgICAgICAgIHN1Ykl0ZW5zOiBbXG4gICAgICAgICAgICB7IHN0YXRlOiAnYXBwLnByb2plY3QnLCB0aXRsZTogbWVudVByZWZpeCArICdwcm9qZWN0JywgaWNvbjogJ3N0YXInIH1cbiAgICAgICAgICBdXG4gICAgICAgIH0sXG4gICAgICAgIC8vIENvbG9xdWUgc2V1cyBpdGVucyBkZSBtZW51IGEgcGFydGlyIGRlc3RlIHBvbnRvXG4gICAgICAgIHtcbiAgICAgICAgICBzdGF0ZTogJyMnLCB0aXRsZTogbWVudVByZWZpeCArICdhZG1pbicsIGljb246ICdzZXR0aW5nc19hcHBsaWNhdGlvbnMnLCBwcm9maWxlczogWydhZG1pbiddLFxuICAgICAgICAgIHN1Ykl0ZW5zOiBbXG4gICAgICAgICAgICB7IHN0YXRlOiAnYXBwLnVzZXInLCB0aXRsZTogbWVudVByZWZpeCArICd1c2VyJywgaWNvbjogJ3Blb3BsZScgfSxcbiAgICAgICAgICAgIHsgc3RhdGU6ICdhcHAubWFpbCcsIHRpdGxlOiBtZW51UHJlZml4ICsgJ21haWwnLCBpY29uOiAnbWFpbCcgfSxcbiAgICAgICAgICAgIHsgc3RhdGU6ICdhcHAuYXVkaXQnLCB0aXRsZTogbWVudVByZWZpeCArICdhdWRpdCcsIGljb246ICdzdG9yYWdlJyB9LFxuICAgICAgICAgICAgeyBzdGF0ZTogJ2FwcC5kaW5hbWljLXF1ZXJ5JywgdGl0bGU6IG1lbnVQcmVmaXggKyAnZGluYW1pY1F1ZXJ5JywgaWNvbjogJ2xvY2F0aW9uX3NlYXJjaGluZycgfVxuICAgICAgICAgIF1cbiAgICAgICAgfVxuICAgICAgXTtcblxuICAgICAgLyoqXG4gICAgICAgKiBPYmpldG8gcXVlIHByZWVuY2hlIG8gbmctc3R5bGUgZG8gbWVudSBsYXRlcmFsIHRyb2NhbmRvIGFzIGNvcmVzXG4gICAgICAgKi9cbiAgICAgIHZtLnNpZGVuYXZTdHlsZSA9IHtcbiAgICAgICAgdG9wOiB7XG4gICAgICAgICAgJ2JvcmRlci1ib3R0b20nOiAnMXB4IHNvbGlkICcgKyBnZXRDb2xvcigncHJpbWFyeScpLFxuICAgICAgICAgICdiYWNrZ3JvdW5kLWltYWdlJzogJy13ZWJraXQtbGluZWFyLWdyYWRpZW50KHRvcCwgJytnZXRDb2xvcigncHJpbWFyeS01MDAnKSsnLCAnK2dldENvbG9yKCdwcmltYXJ5LTgwMCcpKycpJ1xuICAgICAgICB9LFxuICAgICAgICBjb250ZW50OiB7XG4gICAgICAgICAgJ2JhY2tncm91bmQtY29sb3InOiBnZXRDb2xvcigncHJpbWFyeS04MDAnKVxuICAgICAgICB9LFxuICAgICAgICB0ZXh0Q29sb3I6IHtcbiAgICAgICAgICBjb2xvcjogJyNGRkYnXG4gICAgICAgIH0sXG4gICAgICAgIGxpbmVCb3R0b206IHtcbiAgICAgICAgICAnYm9yZGVyLWJvdHRvbSc6ICcxcHggc29saWQgJyArIGdldENvbG9yKCdwcmltYXJ5LTQwMCcpXG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9XG5cbiAgICBmdW5jdGlvbiBvcGVuKCkge1xuICAgICAgJG1kU2lkZW5hdignbGVmdCcpLnRvZ2dsZSgpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIE3DqXRvZG8gcXVlIGV4aWJlIG8gc3ViIG1lbnUgZG9zIGl0ZW5zIGRvIG1lbnUgbGF0ZXJhbCBjYXNvIHRlbmhhIHN1YiBpdGVuc1xuICAgICAqIGNhc28gY29udHLDoXJpbyByZWRpcmVjaW9uYSBwYXJhIG8gc3RhdGUgcGFzc2FkbyBjb21vIHBhcsOibWV0cm9cbiAgICAgKi9cbiAgICBmdW5jdGlvbiBvcGVuTWVudU9yUmVkaXJlY3RUb1N0YXRlKCRtZE1lbnUsIGV2LCBpdGVtKSB7XG4gICAgICBpZiAoYW5ndWxhci5pc0RlZmluZWQoaXRlbS5zdWJJdGVucykgJiYgaXRlbS5zdWJJdGVucy5sZW5ndGggPiAwKSB7XG4gICAgICAgICRtZE1lbnUub3Blbihldik7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICAkc3RhdGUuZ28oaXRlbS5zdGF0ZSk7XG4gICAgICAgICRtZFNpZGVuYXYoJ2xlZnQnKS5jbG9zZSgpO1xuICAgICAgfVxuICAgIH1cblxuICAgIGZ1bmN0aW9uIGdldENvbG9yKGNvbG9yUGFsZXR0ZXMpIHtcbiAgICAgIHJldHVybiAkbWRDb2xvcnMuZ2V0VGhlbWVDb2xvcihjb2xvclBhbGV0dGVzKTtcbiAgICB9XG5cbiAgfVxuXG59KSgpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29udHJvbGxlcignTWFpbHNDb250cm9sbGVyJywgTWFpbHNDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIE1haWxzQ29udHJvbGxlcihNYWlsc1NlcnZpY2UsIFVzZXJzU2VydmljZSwgUHJEaWFsb2csIFByVG9hc3QsIC8vIE5PU09OQVJcbiAgICAkcSwgbG9kYXNoLCAkdHJhbnNsYXRlLCBHbG9iYWwpIHtcblxuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICB2bS5maWx0ZXJTZWxlY3RlZCA9IGZhbHNlO1xuICAgIHZtLm9wdGlvbnMgPSB7XG4gICAgICBza2luOiAna2FtYScsXG4gICAgICBsYW5ndWFnZTogJ3B0LWJyJyxcbiAgICAgIGFsbG93ZWRDb250ZW50OiB0cnVlLFxuICAgICAgZW50aXRpZXM6IHRydWUsXG4gICAgICBoZWlnaHQ6IDMwMCxcbiAgICAgIGV4dHJhUGx1Z2luczogJ2RpYWxvZyxmaW5kLGNvbG9yZGlhbG9nLHByZXZpZXcsZm9ybXMsaWZyYW1lLGZsYXNoJ1xuICAgIH07XG5cbiAgICB2bS5sb2FkVXNlcnMgPSBsb2FkVXNlcnM7XG4gICAgdm0ub3BlblVzZXJEaWFsb2cgPSBvcGVuVXNlckRpYWxvZztcbiAgICB2bS5hZGRVc2VyTWFpbCA9IGFkZFVzZXJNYWlsO1xuICAgIHZtLmNsZWFuRm9ybSA9IGNsZWFuRm9ybTtcbiAgICB2bS5zZW5kID0gc2VuZDtcblxuICAgIGFjdGl2YXRlKCk7XG5cbiAgICBmdW5jdGlvbiBhY3RpdmF0ZSgpIHtcbiAgICAgIHZtLmNsZWFuRm9ybSgpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWxpemEgYSBidXNjYSBwZWxvIHVzdcOhcmlvIHJlbW90YW1lbnRlXG4gICAgICpcbiAgICAgKiBAcGFyYW1zIHtzdHJpbmd9IC0gUmVjZWJlIG8gdmFsb3IgcGFyYSBzZXIgcGVzcXVpc2Fkb1xuICAgICAqIEByZXR1cm4ge3Byb21pc3NlfSAtIFJldG9ybmEgdW1hIHByb21pc3NlIHF1ZSBvIGNvbXBvbmV0ZSByZXNvbHZlXG4gICAgICovXG4gICAgZnVuY3Rpb24gbG9hZFVzZXJzKGNyaXRlcmlhKSB7XG4gICAgICB2YXIgZGVmZXJyZWQgPSAkcS5kZWZlcigpO1xuXG4gICAgICBVc2Vyc1NlcnZpY2UucXVlcnkoe1xuICAgICAgICBuYW1lT3JFbWFpbDogY3JpdGVyaWEsXG4gICAgICAgIG5vdFVzZXJzOiBsb2Rhc2gubWFwKHZtLm1haWwudXNlcnMsIGxvZGFzaC5wcm9wZXJ0eSgnaWQnKSkudG9TdHJpbmcoKSxcbiAgICAgICAgbGltaXQ6IDVcbiAgICAgIH0pLnRoZW4oZnVuY3Rpb24oZGF0YSkge1xuXG4gICAgICAgIC8vIHZlcmlmaWNhIHNlIG5hIGxpc3RhIGRlIHVzdWFyaW9zIGrDoSBleGlzdGUgbyB1c3XDoXJpbyBjb20gbyBlbWFpbCBwZXNxdWlzYWRvXG4gICAgICAgIGRhdGEgPSBsb2Rhc2guZmlsdGVyKGRhdGEsIGZ1bmN0aW9uKHVzZXIpIHtcbiAgICAgICAgICByZXR1cm4gIWxvZGFzaC5maW5kKHZtLm1haWwudXNlcnMsIHsgZW1haWw6IHVzZXIuZW1haWwgfSk7XG4gICAgICAgIH0pO1xuXG4gICAgICAgIGRlZmVycmVkLnJlc29sdmUoZGF0YSk7XG4gICAgICB9KTtcblxuICAgICAgcmV0dXJuIGRlZmVycmVkLnByb21pc2U7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQWJyZSBvIGRpYWxvZyBwYXJhIHBlc3F1aXNhIGRlIHVzdcOhcmlvc1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIG9wZW5Vc2VyRGlhbG9nKCkge1xuICAgICAgdmFyIGNvbmZpZyA9IHtcbiAgICAgICAgbG9jYWxzOiB7XG4gICAgICAgICAgb25Jbml0OiB0cnVlLFxuICAgICAgICAgIHVzZXJEaWFsb2dJbnB1dDoge1xuICAgICAgICAgICAgdHJhbnNmZXJVc2VyRm46IHZtLmFkZFVzZXJNYWlsXG4gICAgICAgICAgfVxuICAgICAgICB9LFxuICAgICAgICBjb250cm9sbGVyOiAnVXNlcnNEaWFsb2dDb250cm9sbGVyJyxcbiAgICAgICAgY29udHJvbGxlckFzOiAnY3RybCcsXG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvdXNlcnMvZGlhbG9nL3VzZXJzLWRpYWxvZy5odG1sJyxcbiAgICAgICAgaGFzQmFja2Ryb3A6IHRydWVcbiAgICAgIH07XG5cbiAgICAgIFByRGlhbG9nLmN1c3RvbShjb25maWcpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEFkaWNpb25hIG8gdXN1w6FyaW8gc2VsZWNpb25hZG8gbmEgbGlzdGEgcGFyYSBxdWUgc2VqYSBlbnZpYWRvIG8gZW1haWxcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBhZGRVc2VyTWFpbCh1c2VyKSB7XG4gICAgICB2YXIgdXNlcnMgPSBsb2Rhc2guZmluZCh2bS5tYWlsLnVzZXJzLCB7IGVtYWlsOiB1c2VyLmVtYWlsIH0pO1xuXG4gICAgICBpZiAodm0ubWFpbC51c2Vycy5sZW5ndGggPiAwICYmIGFuZ3VsYXIuaXNEZWZpbmVkKHVzZXJzKSkge1xuICAgICAgICBQclRvYXN0Lndhcm4oJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy51c2VyLnVzZXJFeGlzdHMnKSk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICB2bS5tYWlsLnVzZXJzLnB1c2goeyBuYW1lOiB1c2VyLm5hbWUsIGVtYWlsOiB1c2VyLmVtYWlsIH0pXG4gICAgICB9XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhbGl6YSBvIGVudmlvIGRvIGVtYWlsIHBhcmEgYSBsaXN0YSBkZSB1c3XDoXJpb3Mgc2VsZWNpb25hZG9zXG4gICAgICovXG4gICAgZnVuY3Rpb24gc2VuZCgpIHtcblxuICAgICAgdm0ubWFpbC4kc2F2ZSgpLnRoZW4oZnVuY3Rpb24ocmVzcG9uc2UpIHtcbiAgICAgICAgaWYgKHJlc3BvbnNlLmxlbmd0aCA+IDApIHtcbiAgICAgICAgICB2YXIgbXNnID0gJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5tYWlsLm1haWxFcnJvcnMnKTtcblxuICAgICAgICAgIGZvciAodmFyIGk9MDsgaSA8IHJlc3BvbnNlLmxlbmd0aDsgaSsrKSB7XG4gICAgICAgICAgICBtc2cgKz0gcmVzcG9uc2UgKyAnXFxuJztcbiAgICAgICAgICB9XG4gICAgICAgICAgUHJUb2FzdC5lcnJvcihtc2cpO1xuICAgICAgICAgIHZtLmNsZWFuRm9ybSgpO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIFByVG9hc3Quc3VjY2VzcygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLm1haWwuc2VuZE1haWxTdWNjZXNzJykpO1xuICAgICAgICAgIHZtLmNsZWFuRm9ybSgpO1xuICAgICAgICB9XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBMaW1wYSBvIGZvcm11bMOhcmlvIGRlIGVtYWlsXG4gICAgICovXG4gICAgZnVuY3Rpb24gY2xlYW5Gb3JtKCkge1xuICAgICAgdm0ubWFpbCA9IG5ldyBNYWlsc1NlcnZpY2UoKTtcbiAgICAgIHZtLm1haWwudXNlcnMgPSBbXTtcbiAgICB9XG5cbiAgfVxuXG59KSgpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKlxuICAgKiBBcnF1aXZvIGRlIGNvbmZpZ3VyYcOnw6NvIGNvbSBhcyByb3RhcyBlc3BlY8OtZmljYXMgZG8gcmVjdXJzbyBlbSBxdWVzdMOjb1xuICAgKlxuICAgKiBAcGFyYW0ge2FueX0gJHN0YXRlUHJvdmlkZXJcbiAgICogQHBhcmFtIHthbnl9IEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyXG4gICAgICAuc3RhdGUoJ2FwcC5tYWlsJywge1xuICAgICAgICB1cmw6ICcvZW1haWwnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL21haWwvbWFpbHMtc2VuZC5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ01haWxzQ29udHJvbGxlciBhcyBtYWlsc0N0cmwnLFxuICAgICAgICBkYXRhOiB7IG5lZWRBdXRoZW50aWNhdGlvbjogdHJ1ZSwgbmVlZFByb2ZpbGU6IFsnYWRtaW4nXSB9XG4gICAgICB9KTtcblxuICB9XG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZhY3RvcnkoJ01haWxzU2VydmljZScsIE1haWxzU2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBNYWlsc1NlcnZpY2Uoc2VydmljZUZhY3RvcnkpIHtcbiAgICByZXR1cm4gc2VydmljZUZhY3RvcnkoJ21haWxzJywge30pO1xuICB9XG5cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5maWx0ZXIoJ3JvbGVzU3RyJywgcm9sZXNTdHIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm9sZXNTdHIobG9kYXNoKSB7XG4gICAgLyoqXG4gICAgICogQHBhcmFtIHthcnJheX0gcm9sZXMgbGlzdGEgZGUgcGVyZmlzXG4gICAgICogQHJldHVybiB7c3RyaW5nfSBwZXJmaXMgc2VwYXJhZG9zIHBvciAnLCAnICBcbiAgICAgKi9cbiAgICByZXR1cm4gZnVuY3Rpb24ocm9sZXMpIHtcbiAgICAgIHJldHVybiBsb2Rhc2gubWFwKHJvbGVzLCAnc2x1ZycpLmpvaW4oJywgJyk7XG4gICAgfTtcbiAgfVxuXG59KSgpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZhY3RvcnkoJ1JvbGVzU2VydmljZScsIFJvbGVzU2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiBSb2xlc1NlcnZpY2Uoc2VydmljZUZhY3RvcnkpIHtcbiAgICByZXR1cm4gc2VydmljZUZhY3RvcnkoJ3JvbGVzJyk7XG4gIH1cblxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5mYWN0b3J5KCdTdXBwb3J0U2VydmljZScsIFN1cHBvcnRTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIFN1cHBvcnRTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCdzdXBwb3J0Jywge1xuICAgICAgYWN0aW9uczoge1xuICAgICAgLyoqXG4gICAgICAgKiBQZWdhIGFzIHRyYWR1w6fDtWVzIHF1ZSBlc3TDo28gbm8gc2Vydmlkb3JcbiAgICAgICAqXG4gICAgICAgKiBAcmV0dXJucyB7cHJvbWlzZX0gVW1hIHByb21pc2UgY29tIG8gcmVzdWx0YWRvIGRvIGNoYW1hZGEgbm8gYmFja2VuZFxuICAgICAgICovXG4gICAgICAgIGxhbmdzOiB7XG4gICAgICAgICAgbWV0aG9kOiAnR0VUJyxcbiAgICAgICAgICB1cmw6ICdsYW5ncycsXG4gICAgICAgICAgd3JhcDogZmFsc2UsXG4gICAgICAgICAgY2FjaGU6IHRydWVcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pO1xuICB9XG5cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICAgLyoqIEBuZ0luamVjdCAqL1xuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29tcG9uZW50KCdib3gnLCB7XG4gICAgICByZXBsYWNlOiB0cnVlLFxuICAgICAgdGVtcGxhdGVVcmw6IFsnR2xvYmFsJywgZnVuY3Rpb24oR2xvYmFsKSB7XG4gICAgICAgIHJldHVybiBHbG9iYWwuY2xpZW50UGF0aCArICcvd2lkZ2V0cy9ib3guaHRtbCdcbiAgICAgIH1dLFxuICAgICAgdHJhbnNjbHVkZToge1xuICAgICAgICB0b29sYmFyQnV0dG9uczogJz9ib3hUb29sYmFyQnV0dG9ucycsXG4gICAgICAgIGZvb3RlckJ1dHRvbnM6ICc/Ym94Rm9vdGVyQnV0dG9ucydcbiAgICAgIH0sXG4gICAgICBiaW5kaW5nczoge1xuICAgICAgICBib3hUaXRsZTogJ0AnLFxuICAgICAgICB0b29sYmFyQ2xhc3M6ICdAJyxcbiAgICAgICAgdG9vbGJhckJnQ29sb3I6ICdAJ1xuICAgICAgfSxcbiAgICAgIGNvbnRyb2xsZXI6IFsnJHRyYW5zY2x1ZGUnLCBmdW5jdGlvbigkdHJhbnNjbHVkZSkge1xuICAgICAgICB2YXIgY3RybCA9IHRoaXM7XG5cbiAgICAgICAgY3RybC50cmFuc2NsdWRlID0gJHRyYW5zY2x1ZGU7XG5cbiAgICAgICAgY3RybC4kb25Jbml0ID0gZnVuY3Rpb24oKSB7XG4gICAgICAgICAgaWYgKGFuZ3VsYXIuaXNVbmRlZmluZWQoY3RybC50b29sYmFyQmdDb2xvcikpIGN0cmwudG9vbGJhckJnQ29sb3IgPSAnZGVmYXVsdC1wcmltYXJ5JztcbiAgICAgICAgfTtcbiAgICAgIH1dXG4gICAgfSk7XG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29tcG9uZW50KCdjb250ZW50Qm9keScsIHtcbiAgICAgIHJlcGxhY2U6IHRydWUsXG4gICAgICB0cmFuc2NsdWRlOiB0cnVlLFxuICAgICAgdGVtcGxhdGVVcmw6IFsnR2xvYmFsJywgZnVuY3Rpb24oR2xvYmFsKSB7XG4gICAgICAgIHJldHVybiBHbG9iYWwuY2xpZW50UGF0aCArICcvd2lkZ2V0cy9jb250ZW50LWJvZHkuaHRtbCdcbiAgICAgIH1dLFxuICAgICAgYmluZGluZ3M6IHtcbiAgICAgICAgbGF5b3V0QWxpZ246ICdAJ1xuICAgICAgfSxcbiAgICAgIGNvbnRyb2xsZXI6IFtmdW5jdGlvbigpIHtcbiAgICAgICAgdmFyIGN0cmwgPSB0aGlzO1xuXG4gICAgICAgIGN0cmwuJG9uSW5pdCA9IGZ1bmN0aW9uKCkge1xuICAgICAgICAgIC8vIE1ha2UgYSBjb3B5IG9mIHRoZSBpbml0aWFsIHZhbHVlIHRvIGJlIGFibGUgdG8gcmVzZXQgaXQgbGF0ZXJcbiAgICAgICAgICBjdHJsLmxheW91dEFsaWduID0gYW5ndWxhci5pc0RlZmluZWQoY3RybC5sYXlvdXRBbGlnbikgPyBjdHJsLmxheW91dEFsaWduIDogJ2NlbnRlciBzdGFydCc7XG4gICAgICAgIH07XG4gICAgICB9XVxuICAgIH0pO1xuXG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29tcG9uZW50KCdjb250ZW50SGVhZGVyJywge1xuICAgICAgdGVtcGxhdGVVcmw6IFsnR2xvYmFsJywgZnVuY3Rpb24oR2xvYmFsKSB7XG4gICAgICAgIHJldHVybiBHbG9iYWwuY2xpZW50UGF0aCArICcvd2lkZ2V0cy9jb250ZW50LWhlYWRlci5odG1sJ1xuICAgICAgfV0sXG4gICAgICByZXBsYWNlOiB0cnVlLFxuICAgICAgYmluZGluZ3M6IHtcbiAgICAgICAgdGl0bGU6ICdAJyxcbiAgICAgICAgZGVzY3JpcHRpb246ICdAJ1xuICAgICAgfVxuICAgIH0pO1xuXG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29udHJvbGxlcignUHJvZmlsZUNvbnRyb2xsZXInLCBQcm9maWxlQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBQcm9maWxlQ29udHJvbGxlcihVc2Vyc1NlcnZpY2UsIEF1dGgsIFByVG9hc3QsICR0cmFuc2xhdGUpIHtcbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0udXBkYXRlID0gdXBkYXRlO1xuXG4gICAgYWN0aXZhdGUoKTtcblxuICAgIGZ1bmN0aW9uIGFjdGl2YXRlKCkge1xuICAgICAgdm0udXNlciA9IGFuZ3VsYXIuY29weShBdXRoLmN1cnJlbnRVc2VyKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiB1cGRhdGUoKSB7XG4gICAgICBVc2Vyc1NlcnZpY2UudXBkYXRlUHJvZmlsZSh2bS51c2VyKS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICAvL2F0dWFsaXphIG8gdXN1w6FyaW8gY29ycmVudGUgY29tIGFzIG5vdmFzIGluZm9ybWHDp8O1ZXNcbiAgICAgICAgQXV0aC51cGRhdGVDdXJyZW50VXNlcihyZXNwb25zZSk7XG4gICAgICAgIFByVG9hc3Quc3VjY2VzcygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnNhdmVTdWNjZXNzJykpO1xuICAgICAgfSk7XG4gICAgfVxuICB9XG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb250cm9sbGVyKCdVc2Vyc0NvbnRyb2xsZXInLCBVc2Vyc0NvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gVXNlcnNDb250cm9sbGVyKCRjb250cm9sbGVyLCBVc2Vyc1NlcnZpY2UpIHtcblxuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICB2bS5vbkFjdGl2YXRlID0gb25BY3RpdmF0ZTtcbiAgICAvLyBpbnN0YW50aWF0ZSBiYXNlIGNvbnRyb2xsZXJcbiAgICAkY29udHJvbGxlcignQ1JVRENvbnRyb2xsZXInLCB7IHZtOiB2bSwgbW9kZWxTZXJ2aWNlOiBVc2Vyc1NlcnZpY2UsIG9wdGlvbnM6IHt9IH0pO1xuXG4gICAgZnVuY3Rpb24gb25BY3RpdmF0ZSgpIHtcbiAgICAgIHZtLnF1ZXJ5RmlsdGVycyA9IHt9O1xuICAgIH1cbiAgfVxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb25maWcocm91dGVzKTtcblxuICAvKipcbiAgICogQXJxdWl2byBkZSBjb25maWd1cmHDp8OjbyBjb20gYXMgcm90YXMgZXNwZWPDrWZpY2FzIGRvIHJlY3Vyc28gdXNlclxuICAgKlxuICAgKiBAcGFyYW0ge2FueX0gJHN0YXRlUHJvdmlkZXJcbiAgICogQHBhcmFtIHthbnl9IEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyXG4gICAgICAuc3RhdGUoJ2FwcC51c2VyJywge1xuICAgICAgICB1cmw6ICcvdXN1YXJpbycsXG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvdXNlcnMvdXNlcnMuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdVc2Vyc0NvbnRyb2xsZXIgYXMgdXNlcnNDdHJsJyxcbiAgICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IHRydWUsIG5lZWRQcm9maWxlOiBbJ2FkbWluJ10gfVxuICAgICAgfSlcbiAgICAgIC5zdGF0ZSgnYXBwLnVzZXItcHJvZmlsZScsIHtcbiAgICAgICAgdXJsOiAnL3VzdWFyaW8vcGVyZmlsJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy91c2Vycy9wcm9maWxlLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnUHJvZmlsZUNvbnRyb2xsZXIgYXMgcHJvZmlsZUN0cmwnLFxuICAgICAgICBkYXRhOiB7IG5lZWRBdXRoZW50aWNhdGlvbjogdHJ1ZSB9XG4gICAgICB9KTtcblxuICB9XG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZhY3RvcnkoJ1VzZXJzU2VydmljZScsIFVzZXJzU2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBVc2Vyc1NlcnZpY2UobG9kYXNoLCBHbG9iYWwsIHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCd1c2VycycsIHtcbiAgICAgIC8vcXVhbmRvIGluc3RhbmNpYSB1bSB1c3XDoXJpbyBzZW0gcGFzc2FyIHBhcmFtZXRybyxcbiAgICAgIC8vbyBtZXNtbyB2YWkgdGVyIG9zIHZhbG9yZXMgZGVmYXVsdHMgYWJhaXhvXG4gICAgICBkZWZhdWx0czoge1xuICAgICAgICByb2xlczogW11cbiAgICAgIH0sXG5cbiAgICAgIGFjdGlvbnM6IHtcbiAgICAgICAgLyoqXG4gICAgICAgICAqIFNlcnZpw6dvIHF1ZSBhdHVhbGl6YSBvcyBkYWRvcyBkbyBwZXJmaWwgZG8gdXN1w6FyaW8gbG9nYWRvXG4gICAgICAgICAqXG4gICAgICAgICAqIEBwYXJhbSB7b2JqZWN0fSBhdHRyaWJ1dGVzXG4gICAgICAgICAqIEByZXR1cm5zIHtwcm9taXNlfSBVbWEgcHJvbWlzZSBjb20gbyByZXN1bHRhZG8gZG8gY2hhbWFkYSBubyBiYWNrZW5kXG4gICAgICAgICAqL1xuICAgICAgICB1cGRhdGVQcm9maWxlOiB7XG4gICAgICAgICAgbWV0aG9kOiAnUFVUJyxcbiAgICAgICAgICB1cmw6IEdsb2JhbC5hcGlQYXRoICsgJy9wcm9maWxlJyxcbiAgICAgICAgICBvdmVycmlkZTogdHJ1ZSxcbiAgICAgICAgICB3cmFwOiBmYWxzZVxuICAgICAgICB9XG4gICAgICB9LFxuXG4gICAgICBpbnN0YW5jZToge1xuICAgICAgICAvKipcbiAgICAgICAgICogVmVyaWZpY2Egc2UgbyB1c3XDoXJpbyB0ZW0gb3MgcGVyZmlzIGluZm9ybWFkb3MuXG4gICAgICAgICAqXG4gICAgICAgICAqIEBwYXJhbSB7YW55fSByb2xlcyBwZXJmaXMgYSBzZXJlbSB2ZXJpZmljYWRvc1xuICAgICAgICAgKiBAcGFyYW0ge2Jvb2xlYW59IGFsbCBmbGFnIHBhcmEgaW5kaWNhciBzZSB2YWkgY2hlZ2FyIHRvZG9zIG9zIHBlcmZpcyBvdSBzb21lbnRlIHVtIGRlbGVzXG4gICAgICAgICAqIEByZXR1cm5zIHtib29sZWFufVxuICAgICAgICAgKi9cbiAgICAgICAgaGFzUHJvZmlsZTogZnVuY3Rpb24ocm9sZXMsIGFsbCkge1xuICAgICAgICAgIHJvbGVzID0gYW5ndWxhci5pc0FycmF5KHJvbGVzKSA/IHJvbGVzIDogW3JvbGVzXTtcblxuICAgICAgICAgIHZhciB1c2VyUm9sZXMgPSBsb2Rhc2gubWFwKHRoaXMucm9sZXMsICdzbHVnJyk7XG5cbiAgICAgICAgICBpZiAoYWxsKSB7XG4gICAgICAgICAgICByZXR1cm4gbG9kYXNoLmludGVyc2VjdGlvbih1c2VyUm9sZXMsIHJvbGVzKS5sZW5ndGggPT09IHJvbGVzLmxlbmd0aDtcbiAgICAgICAgICB9IGVsc2UgeyAvL3JldHVybiB0aGUgbGVuZ3RoIGJlY2F1c2UgMCBpcyBmYWxzZSBpbiBqc1xuICAgICAgICAgICAgcmV0dXJuIGxvZGFzaC5pbnRlcnNlY3Rpb24odXNlclJvbGVzLCByb2xlcykubGVuZ3RoO1xuICAgICAgICAgIH1cbiAgICAgICAgfSxcblxuICAgICAgICAvKipcbiAgICAgICAgICogVmVyaWZpY2Egc2UgbyB1c3XDoXJpbyB0ZW0gbyBwZXJmaWwgYWRtaW4uXG4gICAgICAgICAqXG4gICAgICAgICAqIEByZXR1cm5zIHtib29sZWFufVxuICAgICAgICAgKi9cbiAgICAgICAgaXNBZG1pbjogZnVuY3Rpb24oKSB7XG4gICAgICAgICAgcmV0dXJuIHRoaXMuaGFzUHJvZmlsZSgnYWRtaW4nKTtcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pO1xuICB9XG5cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5maWx0ZXIoJ2F1ZGl0RGV0YWlsVGl0bGUnLCBhdWRpdERldGFpbFRpdGxlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIGF1ZGl0RGV0YWlsVGl0bGUoJHRyYW5zbGF0ZSkge1xuICAgIHJldHVybiBmdW5jdGlvbihhdWRpdERldGFpbCwgc3RhdHVzKSB7XG4gICAgICBpZiAoYXVkaXREZXRhaWwudHlwZSA9PT0gJ3VwZGF0ZWQnKSB7XG4gICAgICAgIGlmIChzdGF0dXMgPT09ICdiZWZvcmUnKSB7XG4gICAgICAgICAgcmV0dXJuICR0cmFuc2xhdGUuaW5zdGFudCgnZGlhbG9nLmF1ZGl0LnVwZGF0ZWRCZWZvcmUnKTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICByZXR1cm4gJHRyYW5zbGF0ZS5pbnN0YW50KCdkaWFsb2cuYXVkaXQudXBkYXRlZEFmdGVyJyk7XG4gICAgICAgIH1cbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHJldHVybiAkdHJhbnNsYXRlLmluc3RhbnQoJ2RpYWxvZy5hdWRpdC4nICsgYXVkaXREZXRhaWwudHlwZSk7XG4gICAgICB9XG4gICAgfVxuICB9XG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5maWx0ZXIoJ2F1ZGl0TW9kZWwnLCBhdWRpdE1vZGVsKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIGF1ZGl0TW9kZWwoJHRyYW5zbGF0ZSkge1xuICAgIHJldHVybiBmdW5jdGlvbihtb2RlbElkKSB7XG4gICAgICBtb2RlbElkID0gbW9kZWxJZC5yZXBsYWNlKCdBcHBcXFxcJywgJycpO1xuICAgICAgdmFyIG1vZGVsID0gJHRyYW5zbGF0ZS5pbnN0YW50KCdtb2RlbHMuJyArIG1vZGVsSWQudG9Mb3dlckNhc2UoKSk7XG5cbiAgICAgIHJldHVybiAobW9kZWwpID8gbW9kZWwgOiBtb2RlbElkO1xuICAgIH1cbiAgfVxuXG59KSgpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmlsdGVyKCdhdWRpdFR5cGUnLCBhdWRpdFR5cGUpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gYXVkaXRUeXBlKGxvZGFzaCwgQXVkaXRTZXJ2aWNlKSB7XG4gICAgcmV0dXJuIGZ1bmN0aW9uKHR5cGVJZCkge1xuICAgICAgdmFyIHR5cGUgPSBsb2Rhc2guZmluZChBdWRpdFNlcnZpY2UubGlzdFR5cGVzKCksIHsgaWQ6IHR5cGVJZCB9KTtcblxuICAgICAgcmV0dXJuICh0eXBlKSA/IHR5cGUubGFiZWwgOiB0eXBlO1xuICAgIH1cbiAgfVxuXG59KSgpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmlsdGVyKCdhdWRpdFZhbHVlJywgYXVkaXRWYWx1ZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBhdWRpdFZhbHVlKCRmaWx0ZXIsIGxvZGFzaCkge1xuICAgIHJldHVybiBmdW5jdGlvbih2YWx1ZSwga2V5KSB7XG4gICAgICBpZiAoYW5ndWxhci5pc0RhdGUodmFsdWUpIHx8IGxvZGFzaC5lbmRzV2l0aChrZXksICdfYXQnKSB8fCAgbG9kYXNoLmVuZHNXaXRoKGtleSwgJ190bycpKSB7XG4gICAgICAgIHJldHVybiAkZmlsdGVyKCdwckRhdGV0aW1lJykodmFsdWUpO1xuICAgICAgfVxuXG4gICAgICBpZiAodHlwZW9mIHZhbHVlID09PSAnYm9vbGVhbicpIHtcbiAgICAgICAgcmV0dXJuICRmaWx0ZXIoJ3RyYW5zbGF0ZScpKCh2YWx1ZSkgPyAnZ2xvYmFsLnllcycgOiAnZ2xvYmFsLm5vJyk7XG4gICAgICB9XG5cbiAgICAgIC8vY2hlY2sgaXMgZmxvYXRcbiAgICAgIGlmIChOdW1iZXIodmFsdWUpID09PSB2YWx1ZSAmJiB2YWx1ZSAlIDEgIT09IDApIHtcbiAgICAgICAgcmV0dXJuICRmaWx0ZXIoJ3JlYWwnKSh2YWx1ZSk7XG4gICAgICB9XG5cbiAgICAgIHJldHVybiB2YWx1ZTtcbiAgICB9XG4gIH1cblxufSkoKTtcbiIsIi8qZXNsaW50IGFuZ3VsYXIvZmlsZS1uYW1lOiAwLCBuby11bmRlZjogMCovXG4oZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uc3RhbnQoJ3B0LUJSLmkxOG4uYXR0cmlidXRlcycsIHtcbiAgICAgIGVtYWlsOiAnRW1haWwnLFxuICAgICAgcGFzc3dvcmQ6ICdTZW5oYScsXG4gICAgICBuYW1lOiAnTm9tZScsXG4gICAgICBpbWFnZTogJ0ltYWdlbScsXG4gICAgICByb2xlczogJ1BlcmZpcycsXG4gICAgICBkYXRlOiAnRGF0YScsXG4gICAgICBpbml0aWFsRGF0ZTogJ0RhdGEgSW5pY2lhbCcsXG4gICAgICBmaW5hbERhdGU6ICdEYXRhIEZpbmFsJyxcbiAgICAgIHRhc2s6IHtcbiAgICAgICAgZGVzY3JpcHRpb246ICdEZXNjcmnDp8OjbycsXG4gICAgICAgIGRvbmU6ICdGZWl0bz8nLFxuICAgICAgICBwcmlvcml0eTogJ1ByaW9yaWRhZGUnLFxuICAgICAgICBzY2hlZHVsZWRfdG86ICdBZ2VuZGFkbyBQYXJhPycsXG4gICAgICAgIHByb2plY3Q6ICdQcm9qZXRvJ1xuICAgICAgfSxcbiAgICAgIHByb2plY3Q6IHtcbiAgICAgICAgY29zdDogJ0N1c3RvJ1xuICAgICAgfSxcbiAgICAgIC8vw6kgY2FycmVnYWRvIGRvIHNlcnZpZG9yIGNhc28gZXN0ZWphIGRlZmluaWRvIG5vIG1lc21vXG4gICAgICBhdWRpdE1vZGVsOiB7XG4gICAgICB9XG4gICAgfSlcblxufSgpKTtcbiIsIi8qZXNsaW50IGFuZ3VsYXIvZmlsZS1uYW1lOiAwLCBuby11bmRlZjogMCovXG4oZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uc3RhbnQoJ3B0LUJSLmkxOG4uZGlhbG9nJywge1xuICAgICAgY29uZmlybVRpdGxlOiAnQ29uZmlybWHDp8OjbycsXG4gICAgICBjb25maXJtRGVzY3JpcHRpb246ICdDb25maXJtYSBhIGHDp8Ojbz8nLFxuICAgICAgcmVtb3ZlRGVzY3JpcHRpb246ICdEZXNlamEgcmVtb3ZlciBwZXJtYW5lbnRlbWVudGUge3tuYW1lfX0/JyxcbiAgICAgIGF1ZGl0OiB7XG4gICAgICAgIGNyZWF0ZWQ6ICdJbmZvcm1hw6fDtWVzIGRvIENhZGFzdHJvJyxcbiAgICAgICAgdXBkYXRlZEJlZm9yZTogJ0FudGVzIGRhIEF0dWFsaXphw6fDo28nLFxuICAgICAgICB1cGRhdGVkQWZ0ZXI6ICdEZXBvaXMgZGEgQXR1YWxpemHDp8OjbycsXG4gICAgICAgIGRlbGV0ZWQ6ICdJbmZvcm1hw6fDtWVzIGFudGVzIGRlIHJlbW92ZXInXG4gICAgICB9LFxuICAgICAgbG9naW46IHtcbiAgICAgICAgcmVzZXRQYXNzd29yZDoge1xuICAgICAgICAgIGRlc2NyaXB0aW9uOiAnRGlnaXRlIGFiYWl4byBvIGVtYWlsIGNhZGFzdHJhZG8gbm8gc2lzdGVtYS4nXG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9KVxuXG59KCkpO1xuIiwiLyplc2xpbnQgYW5ndWxhci9maWxlLW5hbWU6IDAsIG5vLXVuZGVmOiAwKi9cbihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb25zdGFudCgncHQtQlIuaTE4bi5nbG9iYWwnLCB7XG4gICAgICBsb2FkaW5nOiAnQ2FycmVnYW5kby4uLicsXG4gICAgICBwcm9jZXNzaW5nOiAnUHJvY2Vzc2FuZG8uLi4nLFxuICAgICAgeWVzOiAnU2ltJyxcbiAgICAgIG5vOiAnTsOjbycsXG4gICAgICBhbGw6ICdUb2RvcydcbiAgICB9KVxuXG59KCkpO1xuIiwiLyplc2xpbnQgYW5ndWxhci9maWxlLW5hbWU6IDAsIG5vLXVuZGVmOiAwKi9cbihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb25zdGFudCgncHQtQlIuaTE4bi5tZXNzYWdlcycsIHtcbiAgICAgIGludGVybmFsRXJyb3I6ICdPY29ycmV1IHVtIGVycm8gaW50ZXJubywgY29udGF0ZSBvIGFkbWluaXN0cmFkb3IgZG8gc2lzdGVtYScsXG4gICAgICBub3RGb3VuZDogJ05lbmh1bSByZWdpc3RybyBlbmNvbnRyYWRvJyxcbiAgICAgIG5vdEF1dGhvcml6ZWQ6ICdWb2PDqiBuw6NvIHRlbSBhY2Vzc28gYSBlc3RhIGZ1bmNpb25hbGlkYWRlLicsXG4gICAgICBzZWFyY2hFcnJvcjogJ07Do28gZm9pIHBvc3PDrXZlbCByZWFsaXphciBhIGJ1c2NhLicsXG4gICAgICBzYXZlU3VjY2VzczogJ1JlZ2lzdHJvIHNhbHZvIGNvbSBzdWNlc3NvLicsXG4gICAgICBvcGVyYXRpb25TdWNjZXNzOiAnT3BlcmHDp8OjbyByZWFsaXphZGEgY29tIHN1Y2Vzc28uJyxcbiAgICAgIG9wZXJhdGlvbkVycm9yOiAnRXJybyBhbyByZWFsaXphciBhIG9wZXJhw6fDo28nLFxuICAgICAgc2F2ZUVycm9yOiAnRXJybyBhbyB0ZW50YXIgc2FsdmFyIG8gcmVnaXN0cm8uJyxcbiAgICAgIHJlbW92ZVN1Y2Nlc3M6ICdSZW1vw6fDo28gcmVhbGl6YWRhIGNvbSBzdWNlc3NvLicsXG4gICAgICByZW1vdmVFcnJvcjogJ0Vycm8gYW8gdGVudGFyIHJlbW92ZXIgbyByZWdpc3Ryby4nLFxuICAgICAgcmVzb3VyY2VOb3RGb3VuZEVycm9yOiAnUmVjdXJzbyBuw6NvIGVuY29udHJhZG8nLFxuICAgICAgbm90TnVsbEVycm9yOiAnVG9kb3Mgb3MgY2FtcG9zIG9icmlnYXTDs3Jpb3MgZGV2ZW0gc2VyIHByZWVuY2hpZG9zLicsXG4gICAgICBkdXBsaWNhdGVkUmVzb3VyY2VFcnJvcjogJ0rDoSBleGlzdGUgdW0gcmVjdXJzbyBjb20gZXNzYXMgaW5mb3JtYcOnw7Vlcy4nLFxuICAgICAgdmFsaWRhdGU6IHtcbiAgICAgICAgZmllbGRSZXF1aXJlZDogJ08gY2FtcG8ge3tmaWVsZH19IMOpIG9icmlncmF0w7NyaW8uJ1xuICAgICAgfSxcbiAgICAgIGxheW91dDoge1xuICAgICAgICBlcnJvcjQwNDogJ1DDoWdpbmEgbsOjbyBlbmNvbnRyYWRhJ1xuICAgICAgfSxcbiAgICAgIGxvZ2luOiB7XG4gICAgICAgIGxvZ291dEluYWN0aXZlOiAnVm9jw6ogZm9pIGRlc2xvZ2FkbyBkbyBzaXN0ZW1hIHBvciBpbmF0aXZpZGFkZS4gRmF2b3IgZW50cmFyIG5vIHNpc3RlbWEgbm92YW1lbnRlLicsXG4gICAgICAgIGludmFsaWRDcmVkZW50aWFsczogJ0NyZWRlbmNpYWlzIEludsOhbGlkYXMnLFxuICAgICAgICB1bmtub3duRXJyb3I6ICdOw6NvIGZvaSBwb3Nzw612ZWwgcmVhbGl6YXIgbyBsb2dpbi4gVGVudGUgbm92YW1lbnRlLiAnICtcbiAgICAgICAgICAnQ2FzbyBuw6NvIGNvbnNpZ2EgZmF2b3IgZW5jb250cmFyIGVtIGNvbnRhdG8gY29tIG8gYWRtaW5pc3RyYWRvciBkbyBzaXN0ZW1hLicsXG4gICAgICAgIHVzZXJOb3RGb3VuZDogJ07Do28gZm9pIHBvc3PDrXZlbCBlbmNvbnRyYXIgc2V1cyBkYWRvcydcbiAgICAgIH0sXG4gICAgICBkYXNoYm9hcmQ6IHtcbiAgICAgICAgd2VsY29tZTogJ1NlamEgYmVtIFZpbmRvIHt7dXNlck5hbWV9fScsXG4gICAgICAgIGRlc2NyaXB0aW9uOiAnVXRpbGl6ZSBvIG1lbnUgcGFyYSBuYXZlZ2HDp8Ojby4nXG4gICAgICB9LFxuICAgICAgbWFpbDoge1xuICAgICAgICBtYWlsRXJyb3JzOiAnT2NvcnJldSB1bSBlcnJvIG5vcyBzZWd1aW50ZXMgZW1haWxzIGFiYWl4bzpcXG4nLFxuICAgICAgICBzZW5kTWFpbFN1Y2Nlc3M6ICdFbWFpbCBlbnZpYWRvIGNvbSBzdWNlc3NvIScsXG4gICAgICAgIHNlbmRNYWlsRXJyb3I6ICdOw6NvIGZvaSBwb3Nzw612ZWwgZW52aWFyIG8gZW1haWwuJyxcbiAgICAgICAgcGFzc3dvcmRTZW5kaW5nU3VjY2VzczogJ08gcHJvY2Vzc28gZGUgcmVjdXBlcmHDp8OjbyBkZSBzZW5oYSBmb2kgaW5pY2lhZG8uIENhc28gbyBlbWFpbCBuw6NvIGNoZWd1ZSBlbSAxMCBtaW51dG9zIHRlbnRlIG5vdmFtZW50ZS4nXG4gICAgICB9LFxuICAgICAgdXNlcjoge1xuICAgICAgICByZW1vdmVZb3VyU2VsZkVycm9yOiAnVm9jw6ogbsOjbyBwb2RlIHJlbW92ZXIgc2V1IHByw7NwcmlvIHVzdcOhcmlvJyxcbiAgICAgICAgdXNlckV4aXN0czogJ1VzdcOhcmlvIGrDoSBhZGljaW9uYWRvIScsXG4gICAgICAgIHByb2ZpbGU6IHtcbiAgICAgICAgICB1cGRhdGVFcnJvcjogJ07Do28gZm9pIHBvc3PDrXZlbCBhdHVhbGl6YXIgc2V1IHByb2ZpbGUnXG4gICAgICAgIH1cbiAgICAgIH0sXG4gICAgICBxdWVyeURpbmFtaWM6IHtcbiAgICAgICAgbm9GaWx0ZXI6ICdOZW5odW0gZmlsdHJvIGFkaWNpb25hZG8nXG4gICAgICB9XG4gICAgfSlcblxufSgpKTtcbiIsIi8qZXNsaW50IGFuZ3VsYXIvZmlsZS1uYW1lOiAwLCBuby11bmRlZjogMCovXG4oZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uc3RhbnQoJ3B0LUJSLmkxOG4ubW9kZWxzJywge1xuICAgICAgdXNlcjogJ1VzdcOhcmlvJyxcbiAgICAgIHRhc2s6ICdUYXJlZmEnLFxuICAgICAgcHJvamVjdDogJ1Byb2pldG8nXG4gICAgfSlcblxufSgpKTtcbiIsIi8qZXNsaW50IGFuZ3VsYXIvZmlsZS1uYW1lOiAwLCBuby11bmRlZjogMCovXG4oZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uc3RhbnQoJ3B0LUJSLmkxOG4udmlld3MnLCB7XG4gICAgICBicmVhZGNydW1iczoge1xuICAgICAgICB1c2VyOiAnQWRtaW5pc3RyYcOnw6NvIC0gVXN1w6FyaW8nLFxuICAgICAgICAndXNlci1wcm9maWxlJzogJ1BlcmZpbCcsXG4gICAgICAgIGRhc2hib2FyZDogJ0Rhc2hib2FyZCcsXG4gICAgICAgIGF1ZGl0OiAnQWRtaW5pc3RyYcOnw6NvIC0gQXVkaXRvcmlhJyxcbiAgICAgICAgbWFpbDogJ0FkbWluaXN0cmHDp8OjbyAtIEVudmlvIGRlIGUtbWFpbCcsXG4gICAgICAgIHByb2plY3Q6ICdFeGVtcGxvcyAtIFByb2pldG9zJyxcbiAgICAgICAgJ2RpbmFtaWMtcXVlcnknOiAnQWRtaW5pc3RyYcOnw6NvIC0gQ29uc3VsdGFzIERpbsOibWljYXMnLFxuICAgICAgICAnbm90LWF1dGhvcml6ZWQnOiAnQWNlc3NvIE5lZ2FkbydcbiAgICAgIH0sXG4gICAgICB0aXRsZXM6IHtcbiAgICAgICAgZGFzaGJvYXJkOiAnUMOhZ2luYSBpbmljaWFsJyxcbiAgICAgICAgbWFpbFNlbmQ6ICdFbnZpYXIgZS1tYWlsJyxcbiAgICAgICAgdGFza0xpc3Q6ICdMaXN0YSBkZSBUYXJlZmFzJyxcbiAgICAgICAgdXNlckxpc3Q6ICdMaXN0YSBkZSBVc3XDoXJpb3MnLFxuICAgICAgICBhdWRpdExpc3Q6ICdMaXN0YSBkZSBMb2dzJyxcbiAgICAgICAgcmVnaXN0ZXI6ICdGb3JtdWzDoXJpbyBkZSBDYWRhc3RybycsXG4gICAgICAgIHJlc2V0UGFzc3dvcmQ6ICdSZWRlZmluaXIgU2VuaGEnLFxuICAgICAgICB1cGRhdGU6ICdGb3JtdWzDoXJpbyBkZSBBdHVhbGl6YcOnw6NvJ1xuICAgICAgfSxcbiAgICAgIGFjdGlvbnM6IHtcbiAgICAgICAgc2VuZDogJ0VudmlhcicsXG4gICAgICAgIHNhdmU6ICdTYWx2YXInLFxuICAgICAgICBjbGVhcjogJ0xpbXBhcicsXG4gICAgICAgIGNsZWFyQWxsOiAnTGltcGFyIFR1ZG8nLFxuICAgICAgICByZXN0YXJ0OiAnUmVpbmljaWFyJyxcbiAgICAgICAgZmlsdGVyOiAnRmlsdHJhcicsXG4gICAgICAgIHNlYXJjaDogJ1Blc3F1aXNhcicsXG4gICAgICAgIGxpc3Q6ICdMaXN0YXInLFxuICAgICAgICBlZGl0OiAnRWRpdGFyJyxcbiAgICAgICAgY2FuY2VsOiAnQ2FuY2VsYXInLFxuICAgICAgICB1cGRhdGU6ICdBdHVhbGl6YXInLFxuICAgICAgICByZW1vdmU6ICdSZW1vdmVyJyxcbiAgICAgICAgZ2V0T3V0OiAnU2FpcicsXG4gICAgICAgIGFkZDogJ0FkaWNpb25hcicsXG4gICAgICAgIGluOiAnRW50cmFyJyxcbiAgICAgICAgbG9hZEltYWdlOiAnQ2FycmVnYXIgSW1hZ2VtJyxcbiAgICAgICAgc2lnbnVwOiAnQ2FkYXN0cmFyJ1xuICAgICAgfSxcbiAgICAgIGZpZWxkczoge1xuICAgICAgICBkYXRlOiAnRGF0YScsXG4gICAgICAgIGFjdGlvbjogJ0HDp8OjbycsXG4gICAgICAgIGFjdGlvbnM6ICdBw6fDtWVzJyxcbiAgICAgICAgYXVkaXQ6IHtcbiAgICAgICAgICBkYXRlU3RhcnQ6ICdEYXRhIEluaWNpYWwnLFxuICAgICAgICAgIGRhdGVFbmQ6ICdEYXRhIEZpbmFsJyxcbiAgICAgICAgICByZXNvdXJjZTogJ1JlY3Vyc28nLFxuICAgICAgICAgIGFsbFJlc291cmNlczogJ1RvZG9zIFJlY3Vyc29zJyxcbiAgICAgICAgICB0eXBlOiB7XG4gICAgICAgICAgICBjcmVhdGVkOiAnQ2FkYXN0cmFkbycsXG4gICAgICAgICAgICB1cGRhdGVkOiAnQXR1YWxpemFkbycsXG4gICAgICAgICAgICBkZWxldGVkOiAnUmVtb3ZpZG8nXG4gICAgICAgICAgfVxuICAgICAgICB9LFxuICAgICAgICBsb2dpbjoge1xuICAgICAgICAgIHJlc2V0UGFzc3dvcmQ6ICdFc3F1ZWNpIG1pbmhhIHNlbmhhJyxcbiAgICAgICAgICBjb25maXJtUGFzc3dvcmQ6ICdDb25maXJtYXIgc2VuaGEnXG4gICAgICAgIH0sXG4gICAgICAgIG1haWw6IHtcbiAgICAgICAgICB0bzogJ1BhcmEnLFxuICAgICAgICAgIHN1YmplY3Q6ICdBc3N1bnRvJyxcbiAgICAgICAgICBtZXNzYWdlOiAnTWVuc2FnZW0nXG4gICAgICAgIH0sXG4gICAgICAgIHF1ZXJ5RGluYW1pYzoge1xuICAgICAgICAgIGZpbHRlcnM6ICdGaWx0cm9zJyxcbiAgICAgICAgICByZXN1bHRzOiAnUmVzdWx0YWRvcycsXG4gICAgICAgICAgbW9kZWw6ICdNb2RlbCcsXG4gICAgICAgICAgYXR0cmlidXRlOiAnQXRyaWJ1dG8nLFxuICAgICAgICAgIG9wZXJhdG9yOiAnT3BlcmFkb3InLFxuICAgICAgICAgIHJlc291cmNlOiAnUmVjdXJzbycsXG4gICAgICAgICAgdmFsdWU6ICdWYWxvcicsXG4gICAgICAgICAgb3BlcmF0b3JzOiB7XG4gICAgICAgICAgICBlcXVhbHM6ICdJZ3VhbCcsXG4gICAgICAgICAgICBkaWZlcmVudDogJ0RpZmVyZW50ZScsXG4gICAgICAgICAgICBjb250ZWluczogJ0NvbnTDqW0nLFxuICAgICAgICAgICAgc3RhcnRXaXRoOiAnSW5pY2lhIGNvbScsXG4gICAgICAgICAgICBmaW5pc2hXaXRoOiAnRmluYWxpemEgY29tJyxcbiAgICAgICAgICAgIGJpZ2dlclRoYW46ICdNYWlvcicsXG4gICAgICAgICAgICBlcXVhbHNPckJpZ2dlclRoYW46ICdNYWlvciBvdSBJZ3VhbCcsXG4gICAgICAgICAgICBsZXNzVGhhbjogJ01lbm9yJyxcbiAgICAgICAgICAgIGVxdWFsc09yTGVzc1RoYW46ICdNZW5vciBvdSBJZ3VhbCdcbiAgICAgICAgICB9XG4gICAgICAgIH0sXG4gICAgICAgIHByb2plY3Q6IHtcbiAgICAgICAgICBuYW1lOiAnTm9tZScsXG4gICAgICAgICAgdG90YWxUYXNrOiAnVG90YWwgZGUgVGFyZWZhcydcbiAgICAgICAgfSxcbiAgICAgICAgdGFzazoge1xuICAgICAgICAgIGRvbmU6ICdOw6NvIEZlaXRvIC8gRmVpdG8nXG4gICAgICAgIH0sXG4gICAgICAgIHVzZXI6IHtcbiAgICAgICAgICBwZXJmaWxzOiAnUGVyZmlzJyxcbiAgICAgICAgICBuYW1lT3JFbWFpbDogJ05vbWUgb3UgRW1haWwnXG4gICAgICAgIH1cbiAgICAgIH0sXG4gICAgICBsYXlvdXQ6IHtcbiAgICAgICAgbWVudToge1xuICAgICAgICAgIGRhc2hib2FyZDogJ0Rhc2hib2FyZCcsXG4gICAgICAgICAgcHJvamVjdDogJ1Byb2pldG9zJyxcbiAgICAgICAgICBhZG1pbjogJ0FkbWluaXN0cmHDp8OjbycsXG4gICAgICAgICAgZXhhbXBsZXM6ICdFeGVtcGxvcycsXG4gICAgICAgICAgdXNlcjogJ1VzdcOhcmlvcycsXG4gICAgICAgICAgbWFpbDogJ0VudmlhciBlLW1haWwnLFxuICAgICAgICAgIGF1ZGl0OiAnQXVkaXRvcmlhJyxcbiAgICAgICAgICBkaW5hbWljUXVlcnk6ICdDb25zdWx0YXMgRGluYW1pY2FzJ1xuICAgICAgICB9XG4gICAgICB9LFxuICAgICAgdG9vbHRpcHM6IHtcbiAgICAgICAgYXVkaXQ6IHtcbiAgICAgICAgICB2aWV3RGV0YWlsOiAnVmlzdWFsaXphciBEZXRhbGhhbWVudG8nXG4gICAgICAgIH0sXG4gICAgICAgIHVzZXI6IHtcbiAgICAgICAgICBwZXJmaWw6ICdQZXJmaWwnLFxuICAgICAgICAgIHRyYW5zZmVyOiAnVHJhbnNmZXJpcidcbiAgICAgICAgfSxcbiAgICAgICAgdGFzazoge1xuICAgICAgICAgIGxpc3RUYXNrOiAnTGlzdGFyIFRhcmVmYXMnXG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9KVxuXG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29udHJvbGxlcignUHJvamVjdHNDb250cm9sbGVyJywgUHJvamVjdHNDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIFByb2plY3RzQ29udHJvbGxlcihHbG9iYWwsICRjb250cm9sbGVyLCBQcm9qZWN0c1NlcnZpY2UsIFByRGlhbG9nKSB7XG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIC8vQXR0cmlidXRlcyBCbG9ja1xuXG4gICAgLy9GdW5jdGlvbnMgQmxvY2tcbiAgICB2bS5vbkFjdGl2YXRlID0gb25BY3RpdmF0ZTtcbiAgICB2bS5hcHBseUZpbHRlcnMgPSBhcHBseUZpbHRlcnM7XG4gICAgdm0udmlld1Rhc2tzID0gdmlld1Rhc2tzO1xuXG4gICAgLy8gaW5zdGFudGlhdGUgYmFzZSBjb250cm9sbGVyXG4gICAgJGNvbnRyb2xsZXIoJ0NSVURDb250cm9sbGVyJywgeyB2bTogdm0sIG1vZGVsU2VydmljZTogUHJvamVjdHNTZXJ2aWNlLCBvcHRpb25zOiB7fSB9KTtcblxuICAgIGZ1bmN0aW9uIG9uQWN0aXZhdGUoKSB7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMgPSB7fTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBhcHBseUZpbHRlcnMoZGVmYXVsdFF1ZXJ5RmlsdGVycykge1xuICAgICAgcmV0dXJuIGFuZ3VsYXIuZXh0ZW5kKGRlZmF1bHRRdWVyeUZpbHRlcnMsIHZtLnF1ZXJ5RmlsdGVycyk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gdmlld1Rhc2tzKHByb2plY3RJZCkge1xuICAgICAgdmFyIGNvbmZpZyA9IHtcbiAgICAgICAgbG9jYWxzOiB7XG4gICAgICAgICAgcHJvamVjdElkOiBwcm9qZWN0SWRcbiAgICAgICAgfSxcbiAgICAgICAgY29udHJvbGxlcjogJ1Rhc2tzRGlhbG9nQ29udHJvbGxlcicsXG4gICAgICAgIGNvbnRyb2xsZXJBczogJ3Rhc2tzQ3RybCcsXG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvc2FtcGxlcy90YXNrcy90YXNrcy1kaWFsb2cuaHRtbCcsXG4gICAgICAgIGhhc0JhY2tkcm9wOiB0cnVlXG4gICAgICB9O1xuXG4gICAgICBQckRpYWxvZy5jdXN0b20oY29uZmlnKS5maW5hbGx5KGZ1bmN0aW9uKCkge1xuICAgICAgICB2bS5zZWFyY2godm0ucGFnaW5hdG9yLmN1cnJlbnRQYWdlKTtcbiAgICAgIH0pO1xuXG4gICAgfVxuXG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb25maWcocm91dGVzKTtcblxuICAvKipcbiAgICogQXJxdWl2byBkZSBjb25maWd1cmHDp8OjbyBjb20gYXMgcm90YXMgZXNwZWPDrWZpY2FzIGRvIHJlY3Vyc28gcHJvamVjdFxuICAgKlxuICAgKiBAcGFyYW0ge2FueX0gJHN0YXRlUHJvdmlkZXJcbiAgICogQHBhcmFtIHthbnl9IEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyXG4gICAgICAuc3RhdGUoJ2FwcC5wcm9qZWN0Jywge1xuICAgICAgICB1cmw6ICcvcHJvamV0b3MnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL3NhbXBsZXMvcHJvamVjdHMvcHJvamVjdHMuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdQcm9qZWN0c0NvbnRyb2xsZXIgYXMgcHJvamVjdHNDdHJsJyxcbiAgICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IHRydWUsIG5lZWRQcm9maWxlOiBbJ2FkbWluJ10gfVxuICAgICAgfSk7XG4gIH1cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmFjdG9yeSgnUHJvamVjdHNTZXJ2aWNlJywgUHJvamVjdHNTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIFByb2plY3RzU2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHJldHVybiBzZXJ2aWNlRmFjdG9yeSgncHJvamVjdHMnLCB7XG4gICAgICBhY3Rpb25zOiB7IH0sXG4gICAgICBpbnN0YW5jZTogeyB9XG4gICAgfSk7XG4gIH1cblxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnRyb2xsZXIoJ1Rhc2tzRGlhbG9nQ29udHJvbGxlcicsIFRhc2tzRGlhbG9nQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBUYXNrc0RpYWxvZ0NvbnRyb2xsZXIoJGNvbnRyb2xsZXIsIFRhc2tzU2VydmljZSwgcHJvamVjdElkLCBQclRvYXN0LCAvLyBOT1NPTkFSXG4gICAgUHJEaWFsb2csICR0cmFuc2xhdGUsIEdsb2JhbCwgbW9tZW50KSB7XG5cbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgLy9GdW5jdGlvbnMgQmxvY2tcbiAgICB2bS5vbkFjdGl2YXRlICAgPSBvbkFjdGl2YXRlO1xuICAgIHZtLmNsb3NlICAgICAgICA9IGNsb3NlO1xuICAgIHZtLmFwcGx5RmlsdGVycyA9IGFwcGx5RmlsdGVycztcbiAgICB2bS5iZWZvcmVTYXZlICAgPSBiZWZvcmVTYXZlO1xuICAgIHZtLmFmdGVyU2F2ZSAgICA9IGFmdGVyU2F2ZTtcbiAgICB2bS50b2dnbGVEb25lICAgPSB0b2dnbGVEb25lO1xuXG4gICAgLy8gaW5zdGFudGlhdGUgYmFzZSBjb250cm9sbGVyXG4gICAgJGNvbnRyb2xsZXIoJ0NSVURDb250cm9sbGVyJywgeyB2bTogdm0sIG1vZGVsU2VydmljZTogVGFza3NTZXJ2aWNlLCBvcHRpb25zOiB7XG4gICAgICBwZXJQYWdlOiA1XG4gICAgfSB9KTtcblxuICAgIGZ1bmN0aW9uIG9uQWN0aXZhdGUoKSB7XG4gICAgICB2bS5nbG9iYWwgPSBHbG9iYWw7XG4gICAgICB2bS5yZXNvdXJjZS5zY2hlZHVsZWRfdG8gPSBtb21lbnQoKS5hZGQoMzAsICdtaW51dGVzJyk7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMgPSB7IHByb2plY3RJZDogcHJvamVjdElkIH07XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gYXBwbHlGaWx0ZXJzKGRlZmF1bHRRdWVyeUZpbHRlcnMpIHtcbiAgICAgIHJldHVybiBhbmd1bGFyLmV4dGVuZChkZWZhdWx0UXVlcnlGaWx0ZXJzLCB2bS5xdWVyeUZpbHRlcnMpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGJlZm9yZVNhdmUoKSB7XG4gICAgICB2bS5yZXNvdXJjZS5wcm9qZWN0X2lkID0gdm0ucXVlcnlGaWx0ZXJzLnByb2plY3RJZDtcbiAgICAgIHZtLnJlc291cmNlLnByb2plY3QgPSBudWxsO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGFmdGVyU2F2ZSgpIHtcbiAgICAgIHZtLmNsZWFuRm9ybSgpO1xuICAgICAgdm0uc2VhcmNoKHZtLnBhZ2luYXRvci5jdXJyZW50UGFnZSk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gY2xvc2UoKSB7XG4gICAgICB2bS5jbGVhbkZvcm0oKTtcbiAgICAgIFByRGlhbG9nLmNsb3NlKCk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gdG9nZ2xlRG9uZShyZXNvdXJjZSkge1xuICAgICAgVGFza3NTZXJ2aWNlLnRvZ2dsZURvbmUoeyBpZDogcmVzb3VyY2UuaWQsIGRvbmU6IHJlc291cmNlLmRvbmUgfSkudGhlbihmdW5jdGlvbigpIHtcbiAgICAgICAgUHJUb2FzdC5zdWNjZXNzKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMuc2F2ZVN1Y2Nlc3MnKSk7XG4gICAgICAgIHZtLnNlYXJjaCh2bS5wYWdpbmF0b3IuY3VycmVudFBhZ2UpO1xuICAgICAgfSwgZnVuY3Rpb24oZXJyb3IpIHtcbiAgICAgICAgUHJUb2FzdC5lcnJvclZhbGlkYXRpb24oZXJyb3IuZGF0YSwgJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5vcGVyYXRpb25FcnJvcicpKTtcbiAgICAgIH0pO1xuICAgIH1cblxuICB9XG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmFjdG9yeSgnVGFza3NTZXJ2aWNlJywgVGFza3NTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIFRhc2tzU2VydmljZShzZXJ2aWNlRmFjdG9yeSwgbW9tZW50KSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCd0YXNrcycsIHtcbiAgICAgIC8vcXVhbmRvIGluc3RhbmNpYSB1bSB1c3XDoXJpbyBzZW0gcGFzc2FyIHBhcmFtZXRybyxcbiAgICAgIC8vbyBtZXNtbyB2YWkgdGVyIG9zIHZhbG9yZXMgZGVmYXVsdHMgYWJhaXhvXG4gICAgICBkZWZhdWx0czoge1xuICAgICAgICBzY2hlZHVsZWRfdG86IG5ldyBEYXRlKClcbiAgICAgIH0sXG5cbiAgICAgIG1hcDoge1xuICAgICAgICAvL2NvbnZlcnQgcGFyYSBvYmpldG8gamF2YXNjcmlwdCBkYXRlIHVtYSBzdHJpbmcgZm9ybWF0YWRhIGNvbW8gZGF0YVxuICAgICAgICBzY2hlZHVsZWRfdG86IGZ1bmN0aW9uKHZhbHVlKSB7XG4gICAgICAgICAgcmV0dXJuIG1vbWVudCh2YWx1ZSkudG9EYXRlKCk7XG4gICAgICAgIH1cbiAgICAgIH0sXG5cbiAgICAgIGFjdGlvbnM6IHtcbiAgICAgICAgLyoqXG4gICAgICAgICAqIEF0dWFsaXphIG9zIHN0YXR1cyBkYSB0YXJlZmFcbiAgICAgICAgICpcbiAgICAgICAgICogQHBhcmFtIHtvYmplY3R9IGF0dHJpYnV0ZXNcbiAgICAgICAgICovXG4gICAgICAgIHRvZ2dsZURvbmU6IHtcbiAgICAgICAgICBtZXRob2Q6ICdQVVQnLFxuICAgICAgICAgIHVybDogJ3RvZ2dsZURvbmUnXG4gICAgICAgIH1cbiAgICAgIH0sXG4gICAgICBpbnN0YW5jZTogeyB9XG4gICAgfSk7XG4gIH1cblxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnRyb2xsZXIoJ1VzZXJzRGlhbG9nQ29udHJvbGxlcicsIFVzZXJzRGlhbG9nQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBVc2Vyc0RpYWxvZ0NvbnRyb2xsZXIoJGNvbnRyb2xsZXIsIFVzZXJzU2VydmljZSwgUHJEaWFsb2csICAvLyBOT1NPTkFSXG4gICAgdXNlckRpYWxvZ0lucHV0LCBvbkluaXQpIHtcblxuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICB2bS5vbkFjdGl2YXRlID0gb25BY3RpdmF0ZTtcbiAgICB2bS5hcHBseUZpbHRlcnMgPSBhcHBseUZpbHRlcnM7XG4gICAgdm0uY2xvc2UgPSBjbG9zZTtcblxuICAgIGlmIChhbmd1bGFyLmlzRGVmaW5lZCh1c2VyRGlhbG9nSW5wdXQpKSB7XG4gICAgICB2bS50cmFuc2ZlclVzZXIgPSB1c2VyRGlhbG9nSW5wdXQudHJhbnNmZXJVc2VyRm47XG4gICAgfVxuXG4gICAgLy8gaW5zdGFudGlhdGUgYmFzZSBjb250cm9sbGVyXG4gICAgJGNvbnRyb2xsZXIoJ0NSVURDb250cm9sbGVyJywge1xuICAgICAgdm06IHZtLFxuICAgICAgbW9kZWxTZXJ2aWNlOiBVc2Vyc1NlcnZpY2UsXG4gICAgICBzZWFyY2hPbkluaXQ6IG9uSW5pdCxcbiAgICAgIG9wdGlvbnM6IHtcbiAgICAgICAgcGVyUGFnZTogNVxuICAgICAgfVxuICAgIH0pO1xuXG4gICAgZnVuY3Rpb24gb25BY3RpdmF0ZSgpIHtcbiAgICAgIHZtLnF1ZXJ5RmlsdGVycyA9IHt9O1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGFwcGx5RmlsdGVycygpIHtcbiAgICAgIHJldHVybiBhbmd1bGFyLmV4dGVuZCh2bS5kZWZhdWx0UXVlcnlGaWx0ZXJzLCB2bS5xdWVyeUZpbHRlcnMpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGNsb3NlKCkge1xuICAgICAgUHJEaWFsb2cuY2xvc2UoKTtcbiAgICB9XG5cbiAgfVxuXG59KSgpO1xuIl0sInNvdXJjZVJvb3QiOiIvc291cmNlLyJ9
