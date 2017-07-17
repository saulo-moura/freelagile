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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImFwcGxpY2F0aW9uLmpzIiwiYXBwLmpzIiwiYXBwLmNvbmZpZy5qcyIsImFwcC5jb250cm9sbGVyLmpzIiwiYXBwLmV4dGVybmFsLmpzIiwiYXBwLmdsb2JhbC5qcyIsImFwcC5yb3V0ZXMuanMiLCJhcHAucnVuLmpzIiwiYXVkaXQvYXVkaXQuY29udHJvbGxlci5qcyIsImF1ZGl0L2F1ZGl0LnJvdXRlLmpzIiwiYXVkaXQvYXVkaXQuc2VydmljZS5qcyIsImF1dGgvYXV0aC5yb3V0ZS5qcyIsImF1dGgvYXV0aC5zZXJ2aWNlLmpzIiwiYXV0aC9sb2dpbi5jb250cm9sbGVyLmpzIiwiYXV0aC9wYXNzd29yZC5jb250cm9sbGVyLmpzIiwiY29yZS9iYXNlLnNlcnZpY2UuanMiLCJjb3JlL2NydWQuY29udHJvbGxlci5qcyIsImRhc2hib2FyZC9kYXNoYm9hcmQuY29udHJvbGxlci5qcyIsImRhc2hib2FyZC9kYXNoYm9hcmQucm91dGUuanMiLCJkaW5hbWljLXF1ZXJ5cy9kaW5hbWljLXF1ZXJ5LnJvdXRlLmpzIiwiZGluYW1pYy1xdWVyeXMvZGluYW1pYy1xdWVyeS5zZXJ2aWNlLmpzIiwiZGluYW1pYy1xdWVyeXMvZGluYW1pYy1xdWVyeXMuY29udHJvbGxlci5qcyIsImkxOG4vbGFuZ3VhZ2UtbG9hZGVyLnNlcnZpY2UuanMiLCJpMThuL3QtYXR0ci5maWx0ZXIuanMiLCJpMThuL3QtYnJlYWRjcnVtYi5maWx0ZXIuanMiLCJpMThuL3QtbW9kZWwuZmlsdGVyLmpzIiwiaW50ZXJjZXB0b3JzL2F1dGhlbnRpY2F0aW9uLmxpc3RlbmVyLmpzIiwiaW50ZXJjZXB0b3JzL2F1dGhvcml6YXRpb24ubGlzdGVuZXIuanMiLCJpbnRlcmNlcHRvcnMvc3Bpbm5lci5pbnRlcmNlcHRvci5qcyIsImludGVyY2VwdG9ycy90b2tlbi5pbnRlcmNlcHRvci5qcyIsImludGVyY2VwdG9ycy92YWxpZGF0aW9uLmludGVyY2VwdG9yLmpzIiwibGF5b3V0L21lbnUuY29udHJvbGxlci5qcyIsIm1haWwvbWFpbHMuY29udHJvbGxlci5qcyIsIm1haWwvbWFpbHMucm91dGUuanMiLCJtYWlsL21haWxzLnNlcnZpY2UuanMiLCJyb2xlcy9yb2xlcy1zdHIuZmlsdGVyLmpzIiwicm9sZXMvcm9sZXMuc2VydmljZS5qcyIsInN1cHBvcnQvc3VwcG9ydC5zZXJ2aWNlLmpzIiwidXNlcnMvcHJvZmlsZS5jb250cm9sbGVyLmpzIiwidXNlcnMvdXNlcnMuY29udHJvbGxlci5qcyIsInVzZXJzL3VzZXJzLnJvdXRlLmpzIiwidXNlcnMvdXNlcnMuc2VydmljZS5qcyIsIndpZGdldHMvYm94LmNvbXBvbmVudC5qcyIsIndpZGdldHMvY29udGVudC1ib2R5LmNvbXBvbmVudC5qcyIsIndpZGdldHMvY29udGVudC1oZWFkZXIuY29tcG9uZW50LmpzIiwiYXVkaXQvZmlsdGVycy9hdWRpdC1kZXRhaWwtdGl0bGUuZmlsdGVyLmpzIiwiYXVkaXQvZmlsdGVycy9hdWRpdC1tb2RlbC5maWx0ZXIuanMiLCJhdWRpdC9maWx0ZXJzL2F1ZGl0LXR5cGUuZmlsdGVyLmpzIiwiYXVkaXQvZmlsdGVycy9hdWRpdC12YWx1ZS5maWx0ZXIuanMiLCJpMThuL3B0LUJSL2F0dHJpYnV0ZXMuanMiLCJpMThuL3B0LUJSL2RpYWxvZy5qcyIsImkxOG4vcHQtQlIvZ2xvYmFsLmpzIiwiaTE4bi9wdC1CUi9tZXNzYWdlcy5qcyIsImkxOG4vcHQtQlIvbW9kZWxzLmpzIiwiaTE4bi9wdC1CUi92aWV3cy5qcyIsInNhbXBsZXMvcHJvamVjdHMvcHJvamVjdHMuY29udHJvbGxlci5qcyIsInNhbXBsZXMvcHJvamVjdHMvcHJvamVjdHMucm91dGUuanMiLCJzYW1wbGVzL3Byb2plY3RzL3Byb2plY3RzLnNlcnZpY2UuanMiLCJzYW1wbGVzL3Rhc2tzL3Rhc2tzLWRpYWxvZy5jb250cm9sbGVyLmpzIiwic2FtcGxlcy90YXNrcy90YXNrcy5zZXJ2aWNlLmpzIiwidXNlcnMvZGlhbG9nL3VzZXJzLWRpYWxvZy5jb250cm9sbGVyLmpzIl0sIm5hbWVzIjpbImFuZ3VsYXIiLCJtb2R1bGUiLCJjb25maWciLCJHbG9iYWwiLCIkbWRUaGVtaW5nUHJvdmlkZXIiLCIkbW9kZWxGYWN0b3J5UHJvdmlkZXIiLCIkdHJhbnNsYXRlUHJvdmlkZXIiLCJtb21lbnQiLCIkbWRBcmlhUHJvdmlkZXIiLCJ1c2VMb2FkZXIiLCJ1c2VTYW5pdGl6ZVZhbHVlU3RyYXRlZ3kiLCJ1c2VQb3N0Q29tcGlsaW5nIiwibG9jYWxlIiwiZGVmYXVsdE9wdGlvbnMiLCJwcmVmaXgiLCJhcGlQYXRoIiwidGhlbWUiLCJwcmltYXJ5UGFsZXR0ZSIsImRlZmF1bHQiLCJhY2NlbnRQYWxldHRlIiwid2FyblBhbGV0dGUiLCJlbmFibGVCcm93c2VyQ29sb3IiLCJkaXNhYmxlV2FybmluZ3MiLCJjb250cm9sbGVyIiwiQXBwQ29udHJvbGxlciIsIiRzdGF0ZSIsIkF1dGgiLCJ2bSIsImFub0F0dWFsIiwibG9nb3V0IiwiZ2V0SW1hZ2VQZXJmaWwiLCJhY3RpdmF0ZSIsImRhdGUiLCJEYXRlIiwiZ2V0RnVsbFllYXIiLCJ0aGVuIiwiZ28iLCJsb2dpblN0YXRlIiwiY3VycmVudFVzZXIiLCJpbWFnZSIsImltYWdlUGF0aCIsImNvbnN0YW50IiwiXyIsImFwcE5hbWUiLCJob21lU3RhdGUiLCJsb2dpblVybCIsInJlc2V0UGFzc3dvcmRTdGF0ZSIsIm5vdEF1dGhvcml6ZWRTdGF0ZSIsInRva2VuS2V5IiwiY2xpZW50UGF0aCIsInJvdXRlcyIsIiRzdGF0ZVByb3ZpZGVyIiwiJHVybFJvdXRlclByb3ZpZGVyIiwic3RhdGUiLCJ1cmwiLCJ0ZW1wbGF0ZVVybCIsImFic3RyYWN0IiwicmVzb2x2ZSIsInRyYW5zbGF0ZVJlYWR5IiwiJHRyYW5zbGF0ZSIsIiRxIiwiZGVmZXJyZWQiLCJkZWZlciIsInVzZSIsInByb21pc2UiLCJkYXRhIiwibmVlZEF1dGhlbnRpY2F0aW9uIiwid2hlbiIsIm90aGVyd2lzZSIsInJ1biIsIiRyb290U2NvcGUiLCIkc3RhdGVQYXJhbXMiLCJhdXRoIiwiZ2xvYmFsIiwicmV0cmlldmVVc2VyRnJvbUxvY2FsU3RvcmFnZSIsIkF1ZGl0Q29udHJvbGxlciIsIiRjb250cm9sbGVyIiwiQXVkaXRTZXJ2aWNlIiwiUHJEaWFsb2ciLCJvbkFjdGl2YXRlIiwiYXBwbHlGaWx0ZXJzIiwidmlld0RldGFpbCIsIm1vZGVsU2VydmljZSIsIm9wdGlvbnMiLCJtb2RlbHMiLCJxdWVyeUZpbHRlcnMiLCJnZXRBdWRpdGVkTW9kZWxzIiwiaWQiLCJsYWJlbCIsImluc3RhbnQiLCJzb3J0IiwiaW5kZXgiLCJsZW5ndGgiLCJtb2RlbCIsInB1c2giLCJ0b0xvd2VyQ2FzZSIsInR5cGVzIiwibGlzdFR5cGVzIiwidHlwZSIsImRlZmF1bHRRdWVyeUZpbHRlcnMiLCJleHRlbmQiLCJhdWRpdERldGFpbCIsImxvY2FscyIsImNsb3NlIiwiaXNBcnJheSIsIm9sZCIsIm5ldyIsImNvbnRyb2xsZXJBcyIsImhhc0JhY2tkcm9wIiwiY3VzdG9tIiwibmVlZFByb2ZpbGUiLCJmYWN0b3J5Iiwic2VydmljZUZhY3RvcnkiLCJhY3Rpb25zIiwibWV0aG9kIiwiaW5zdGFuY2UiLCJhdWRpdFBhdGgiLCIkaHR0cCIsIlVzZXJzU2VydmljZSIsImxvZ2luIiwidXBkYXRlQ3VycmVudFVzZXIiLCJhdXRoZW50aWNhdGVkIiwic2VuZEVtYWlsUmVzZXRQYXNzd29yZCIsInJlbW90ZVZhbGlkYXRlVG9rZW4iLCJnZXRUb2tlbiIsInNldFRva2VuIiwiY2xlYXJUb2tlbiIsImxvY2FsU3RvcmFnZSIsInJlbW92ZUl0ZW0iLCJ0b2tlbiIsInNldEl0ZW0iLCJnZXRJdGVtIiwiZ2V0IiwicmVqZWN0IiwidXNlciIsIm1lcmdlIiwiZnJvbUpzb24iLCJqc29uVXNlciIsInRvSnNvbiIsImNyZWRlbnRpYWxzIiwicG9zdCIsInJlc3BvbnNlIiwiZXJyb3IiLCJyZXNldERhdGEiLCJMb2dpbkNvbnRyb2xsZXIiLCJvcGVuRGlhbG9nUmVzZXRQYXNzIiwib3BlbkRpYWxvZ1NpZ25VcCIsImVtYWlsIiwicGFzc3dvcmQiLCJQYXNzd29yZENvbnRyb2xsZXIiLCIkdGltZW91dCIsIlByVG9hc3QiLCJzZW5kUmVzZXQiLCJjbG9zZURpYWxvZyIsImNsZWFuRm9ybSIsInJlc2V0Iiwic3VjY2VzcyIsInN0YXR1cyIsIm1zZyIsImkiLCJ0b1VwcGVyQ2FzZSIsImZpZWxkIiwibWVzc2FnZSIsIiRtb2RlbEZhY3RvcnkiLCJwYWdpbmF0ZSIsIndyYXAiLCJhZnRlclJlcXVlc3QiLCJMaXN0IiwiQ1JVRENvbnRyb2xsZXIiLCJQclBhZ2luYXRpb24iLCJzZWFyY2giLCJwYWdpbmF0ZVNlYXJjaCIsIm5vcm1hbFNlYXJjaCIsImVkaXQiLCJzYXZlIiwicmVtb3ZlIiwiZ29UbyIsInJlZGlyZWN0QWZ0ZXJTYXZlIiwic2VhcmNoT25Jbml0IiwicGVyUGFnZSIsInNraXBQYWdpbmF0aW9uIiwidmlld0Zvcm0iLCJyZXNvdXJjZSIsImlzRnVuY3Rpb24iLCJwYWdpbmF0b3IiLCJnZXRJbnN0YW5jZSIsInBhZ2UiLCJjdXJyZW50UGFnZSIsImlzRGVmaW5lZCIsImJlZm9yZVNlYXJjaCIsImNhbGNOdW1iZXJPZlBhZ2VzIiwidG90YWwiLCJyZXNvdXJjZXMiLCJpdGVtcyIsImFmdGVyU2VhcmNoIiwicXVlcnkiLCJmb3JtIiwiYmVmb3JlQ2xlYW4iLCIkc2V0UHJpc3RpbmUiLCIkc2V0VW50b3VjaGVkIiwiYWZ0ZXJDbGVhbiIsImNvcHkiLCJhZnRlckVkaXQiLCJiZWZvcmVTYXZlIiwiJHNhdmUiLCJhZnRlclNhdmUiLCJyZXNwb25zZURhdGEiLCJvblNhdmVFcnJvciIsInRpdGxlIiwiZGVzY3JpcHRpb24iLCJjb25maXJtIiwiYmVmb3JlUmVtb3ZlIiwiJGRlc3Ryb3kiLCJhZnRlclJlbW92ZSIsImluZm8iLCJ2aWV3TmFtZSIsIkRhc2hib2FyZENvbnRyb2xsZXIiLCJEaW5hbWljUXVlcnlTZXJ2aWNlIiwiZ2V0TW9kZWxzIiwiRGluYW1pY1F1ZXJ5c0NvbnRyb2xsZXIiLCJsb2Rhc2giLCJsb2FkQXR0cmlidXRlcyIsImxvYWRPcGVyYXRvcnMiLCJhZGRGaWx0ZXIiLCJydW5GaWx0ZXIiLCJlZGl0RmlsdGVyIiwibG9hZE1vZGVscyIsInJlbW92ZUZpbHRlciIsImNsZWFyIiwicmVzdGFydCIsIndoZXJlIiwiYWRkZWRGaWx0ZXJzIiwibmFtZSIsImZpbHRlciIsImF0dHJpYnV0ZSIsIm9wZXJhdG9yIiwidmFsdWUiLCJmaWx0ZXJzIiwiYXR0cmlidXRlcyIsIm9wZXJhdG9ycyIsImluZGV4T2YiLCJpc1VuZGVmaW5lZCIsImtleXMiLCJPYmplY3QiLCJrZXkiLCJzdGFydHNXaXRoIiwiJGluZGV4Iiwic3BsaWNlIiwiTGFuZ3VhZ2VMb2FkZXIiLCJTdXBwb3J0U2VydmljZSIsIiRsb2ciLCIkaW5qZWN0b3IiLCJzZXJ2aWNlIiwidHJhbnNsYXRlIiwidmlld3MiLCJkaWFsb2ciLCJtZXNzYWdlcyIsImxhbmdzIiwidEF0dHIiLCIkZmlsdGVyIiwidEJyZWFkY3J1bWIiLCJzcGxpdCIsInRNb2RlbCIsImF1dGhlbnRpY2F0aW9uTGlzdGVuZXIiLCIkb24iLCJldmVudCIsInRvU3RhdGUiLCJjYXRjaCIsIndhcm4iLCJwcmV2ZW50RGVmYXVsdCIsImF1dGhvcml6YXRpb25MaXN0ZW5lciIsImhhc1Byb2ZpbGUiLCJhbGxQcm9maWxlcyIsInNwaW5uZXJJbnRlcmNlcHRvciIsIiRodHRwUHJvdmlkZXIiLCIkcHJvdmlkZSIsInNob3dIaWRlU3Bpbm5lciIsInJlcXVlc3QiLCJzaG93IiwiaGlkZSIsInJlc3BvbnNlRXJyb3IiLCJyZWplY3Rpb24iLCJpbnRlcmNlcHRvcnMiLCJ0b2tlbkludGVyY2VwdG9yIiwicmVkaXJlY3RXaGVuU2VydmVyTG9nZ2VkT3V0IiwiaGVhZGVycyIsInJlamVjdGlvblJlYXNvbnMiLCJ0b2tlbkVycm9yIiwiZm9yRWFjaCIsImlzIiwidmFsaWRhdGlvbkludGVyY2VwdG9yIiwic2hvd0Vycm9yVmFsaWRhdGlvbiIsInNraXBWYWxpZGF0aW9uIiwiZXJyb3JWYWxpZGF0aW9uIiwiTWVudUNvbnRyb2xsZXIiLCIkbWRTaWRlbmF2IiwiJG1kQ29sb3JzIiwib3BlbiIsIm9wZW5NZW51T3JSZWRpcmVjdFRvU3RhdGUiLCJtZW51UHJlZml4IiwiaXRlbnNNZW51IiwiaWNvbiIsInN1Ykl0ZW5zIiwicHJvZmlsZXMiLCJzaWRlbmF2U3R5bGUiLCJ0b3AiLCJnZXRDb2xvciIsImNvbnRlbnQiLCJ0ZXh0Q29sb3IiLCJjb2xvciIsImxpbmVCb3R0b20iLCJ0b2dnbGUiLCIkbWRNZW51IiwiZXYiLCJpdGVtIiwiY29sb3JQYWxldHRlcyIsImdldFRoZW1lQ29sb3IiLCJNYWlsc0NvbnRyb2xsZXIiLCJNYWlsc1NlcnZpY2UiLCJmaWx0ZXJTZWxlY3RlZCIsInNraW4iLCJsYW5ndWFnZSIsImFsbG93ZWRDb250ZW50IiwiZW50aXRpZXMiLCJoZWlnaHQiLCJleHRyYVBsdWdpbnMiLCJsb2FkVXNlcnMiLCJvcGVuVXNlckRpYWxvZyIsImFkZFVzZXJNYWlsIiwic2VuZCIsImNyaXRlcmlhIiwibmFtZU9yRW1haWwiLCJub3RVc2VycyIsIm1hcCIsIm1haWwiLCJ1c2VycyIsInByb3BlcnR5IiwidG9TdHJpbmciLCJsaW1pdCIsImZpbmQiLCJvbkluaXQiLCJ1c2VyRGlhbG9nSW5wdXQiLCJ0cmFuc2ZlclVzZXJGbiIsInJvbGVzU3RyIiwicm9sZXMiLCJqb2luIiwiUm9sZXNTZXJ2aWNlIiwiY2FjaGUiLCJQcm9maWxlQ29udHJvbGxlciIsInVwZGF0ZSIsInVwZGF0ZVByb2ZpbGUiLCJVc2Vyc0NvbnRyb2xsZXIiLCJkZWZhdWx0cyIsIm92ZXJyaWRlIiwiYWxsIiwidXNlclJvbGVzIiwiaW50ZXJzZWN0aW9uIiwiaXNBZG1pbiIsImNvbXBvbmVudCIsInJlcGxhY2UiLCJ0cmFuc2NsdWRlIiwidG9vbGJhckJ1dHRvbnMiLCJmb290ZXJCdXR0b25zIiwiYmluZGluZ3MiLCJib3hUaXRsZSIsInRvb2xiYXJDbGFzcyIsInRvb2xiYXJCZ0NvbG9yIiwiJHRyYW5zY2x1ZGUiLCJjdHJsIiwiJG9uSW5pdCIsImxheW91dEFsaWduIiwiYXVkaXREZXRhaWxUaXRsZSIsImF1ZGl0TW9kZWwiLCJtb2RlbElkIiwiYXVkaXRUeXBlIiwidHlwZUlkIiwiYXVkaXRWYWx1ZSIsImlzRGF0ZSIsImVuZHNXaXRoIiwiTnVtYmVyIiwiaW5pdGlhbERhdGUiLCJmaW5hbERhdGUiLCJ0YXNrIiwiZG9uZSIsInByaW9yaXR5Iiwic2NoZWR1bGVkX3RvIiwicHJvamVjdCIsImNvc3QiLCJjb25maXJtVGl0bGUiLCJjb25maXJtRGVzY3JpcHRpb24iLCJyZW1vdmVEZXNjcmlwdGlvbiIsImF1ZGl0IiwiY3JlYXRlZCIsInVwZGF0ZWRCZWZvcmUiLCJ1cGRhdGVkQWZ0ZXIiLCJkZWxldGVkIiwicmVzZXRQYXNzd29yZCIsImxvYWRpbmciLCJwcm9jZXNzaW5nIiwieWVzIiwibm8iLCJpbnRlcm5hbEVycm9yIiwibm90Rm91bmQiLCJub3RBdXRob3JpemVkIiwic2VhcmNoRXJyb3IiLCJzYXZlU3VjY2VzcyIsIm9wZXJhdGlvblN1Y2Nlc3MiLCJvcGVyYXRpb25FcnJvciIsInNhdmVFcnJvciIsInJlbW92ZVN1Y2Nlc3MiLCJyZW1vdmVFcnJvciIsInJlc291cmNlTm90Rm91bmRFcnJvciIsIm5vdE51bGxFcnJvciIsImR1cGxpY2F0ZWRSZXNvdXJjZUVycm9yIiwidmFsaWRhdGUiLCJmaWVsZFJlcXVpcmVkIiwibGF5b3V0IiwiZXJyb3I0MDQiLCJsb2dvdXRJbmFjdGl2ZSIsImludmFsaWRDcmVkZW50aWFscyIsInVua25vd25FcnJvciIsInVzZXJOb3RGb3VuZCIsImRhc2hib2FyZCIsIndlbGNvbWUiLCJtYWlsRXJyb3JzIiwic2VuZE1haWxTdWNjZXNzIiwic2VuZE1haWxFcnJvciIsInBhc3N3b3JkU2VuZGluZ1N1Y2Nlc3MiLCJyZW1vdmVZb3VyU2VsZkVycm9yIiwidXNlckV4aXN0cyIsInByb2ZpbGUiLCJ1cGRhdGVFcnJvciIsInF1ZXJ5RGluYW1pYyIsIm5vRmlsdGVyIiwiYnJlYWRjcnVtYnMiLCJ0aXRsZXMiLCJtYWlsU2VuZCIsInRhc2tMaXN0IiwidXNlckxpc3QiLCJhdWRpdExpc3QiLCJyZWdpc3RlciIsImNsZWFyQWxsIiwibGlzdCIsImNhbmNlbCIsImdldE91dCIsImFkZCIsImluIiwibG9hZEltYWdlIiwic2lnbnVwIiwiZmllbGRzIiwiYWN0aW9uIiwiZGF0ZVN0YXJ0IiwiZGF0ZUVuZCIsImFsbFJlc291cmNlcyIsInVwZGF0ZWQiLCJjb25maXJtUGFzc3dvcmQiLCJ0byIsInN1YmplY3QiLCJyZXN1bHRzIiwiZXF1YWxzIiwiZGlmZXJlbnQiLCJjb250ZWlucyIsInN0YXJ0V2l0aCIsImZpbmlzaFdpdGgiLCJiaWdnZXJUaGFuIiwiZXF1YWxzT3JCaWdnZXJUaGFuIiwibGVzc1RoYW4iLCJlcXVhbHNPckxlc3NUaGFuIiwidG90YWxUYXNrIiwicGVyZmlscyIsIm1lbnUiLCJhZG1pbiIsImV4YW1wbGVzIiwiZGluYW1pY1F1ZXJ5IiwidG9vbHRpcHMiLCJwZXJmaWwiLCJ0cmFuc2ZlciIsImxpc3RUYXNrIiwiUHJvamVjdHNDb250cm9sbGVyIiwiUHJvamVjdHNTZXJ2aWNlIiwidmlld1Rhc2tzIiwicHJvamVjdElkIiwiZmluYWxseSIsIlRhc2tzRGlhbG9nQ29udHJvbGxlciIsIlRhc2tzU2VydmljZSIsInRvZ2dsZURvbmUiLCJwcm9qZWN0X2lkIiwidG9EYXRlIiwiVXNlcnNEaWFsb2dDb250cm9sbGVyIiwidHJhbnNmZXJVc2VyIl0sIm1hcHBpbmdzIjoiQUFBQTs7O0FDQ0EsQ0FBQyxZQUFXO0VBQ1Y7O0VBRUFBLFFBQVFDLE9BQU8sT0FBTyxDQUNwQixhQUNBLFVBQ0EsYUFDQSxZQUNBLGtCQUNBLGFBQ0EsY0FDQSxnQkFDQSxpQkFDQSx3QkFDQSwwQkFDQTs7QURSSjs7QUVSQyxDQUFBLFlBQVk7RUFDWDs7O0VBRUFELFFBQ0dDLE9BQU8sT0FDUEMsT0FBT0E7Ozs7RUFJVixTQUFTQSxPQUFPQyxRQUFRQyxvQkFBb0JDO0VBQzFDQyxvQkFBb0JDLFFBQVFDLGlCQUFp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TUFDdEIsT0FBT2hGLFFBQVFvRyxPQUFPekUsR0FBR3dFLHFCQUFxQnhFLEdBQUcwRDs7O0lBR25ELFNBQVNrQixRQUFRO01BQ2Z6QixTQUFTeUI7OztLQTFDZiIsImZpbGUiOiJhcHBsaWNhdGlvbi5qcyIsInNvdXJjZXNDb250ZW50IjpbIid1c2Ugc3RyaWN0JztcblxuLyplc2xpbnQgYW5ndWxhci9maWxlLW5hbWU6IDAqL1xuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnLCBbJ25nQW5pbWF0ZScsICduZ0FyaWEnLCAndWkucm91dGVyJywgJ25nUHJvZGViJywgJ3VpLnV0aWxzLm1hc2tzJywgJ3RleHQtbWFzaycsICduZ01hdGVyaWFsJywgJ21vZGVsRmFjdG9yeScsICdtZC5kYXRhLnRhYmxlJywgJ25nTWF0ZXJpYWxEYXRlUGlja2VyJywgJ3Bhc2NhbHByZWNodC50cmFuc2xhdGUnLCAnYW5ndWxhckZpbGVVcGxvYWQnXSk7XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbmZpZyhjb25maWcpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gY29uZmlnKEdsb2JhbCwgJG1kVGhlbWluZ1Byb3ZpZGVyLCAkbW9kZWxGYWN0b3J5UHJvdmlkZXIsIC8vIE5PU09OQVJcbiAgJHRyYW5zbGF0ZVByb3ZpZGVyLCBtb21lbnQsICRtZEFyaWFQcm92aWRlcikge1xuXG4gICAgJHRyYW5zbGF0ZVByb3ZpZGVyLnVzZUxvYWRlcignbGFuZ3VhZ2VMb2FkZXInKS51c2VTYW5pdGl6ZVZhbHVlU3RyYXRlZ3koJ2VzY2FwZScpO1xuXG4gICAgJHRyYW5zbGF0ZVByb3ZpZGVyLnVzZVBvc3RDb21waWxpbmcodHJ1ZSk7XG5cbiAgICBtb21lbnQubG9jYWxlKCdwdC1CUicpO1xuXG4gICAgLy9vcyBzZXJ2acOnb3MgcmVmZXJlbnRlIGFvcyBtb2RlbHMgdmFpIHV0aWxpemFyIGNvbW8gYmFzZSBuYXMgdXJsc1xuICAgICRtb2RlbEZhY3RvcnlQcm92aWRlci5kZWZhdWx0T3B0aW9ucy5wcmVmaXggPSBHbG9iYWwuYXBpUGF0aDtcblxuICAgIC8vIENvbmZpZ3VyYXRpb24gdGhlbWVcbiAgICAkbWRUaGVtaW5nUHJvdmlkZXIudGhlbWUoJ2RlZmF1bHQnKS5wcmltYXJ5UGFsZXR0ZSgnYnJvd24nLCB7XG4gICAgICBkZWZhdWx0OiAnNzAwJ1xuICAgIH0pLmFjY2VudFBhbGV0dGUoJ2FtYmVyJykud2FyblBhbGV0dGUoJ2RlZXAtb3JhbmdlJyk7XG5cbiAgICAvLyBFbmFibGUgYnJvd3NlciBjb2xvclxuICAgICRtZFRoZW1pbmdQcm92aWRlci5lbmFibGVCcm93c2VyQ29sb3IoKTtcblxuICAgICRtZEFyaWFQcm92aWRlci5kaXNhYmxlV2FybmluZ3MoKTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbnRyb2xsZXIoJ0FwcENvbnRyb2xsZXInLCBBcHBDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8qKlxuICAgKiBDb250cm9sYWRvciByZXNwb25zw6F2ZWwgcG9yIGZ1bmNpb25hbGlkYWRlcyBxdWUgc8OjbyBhY2lvbmFkYXMgZW0gcXVhbHF1ZXIgdGVsYSBkbyBzaXN0ZW1hXG4gICAqXG4gICAqL1xuICBmdW5jdGlvbiBBcHBDb250cm9sbGVyKCRzdGF0ZSwgQXV0aCwgR2xvYmFsKSB7XG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIC8vYW5vIGF0dWFsIHBhcmEgc2VyIGV4aWJpZG8gbm8gcm9kYXDDqSBkbyBzaXN0ZW1hXG4gICAgdm0uYW5vQXR1YWwgPSBudWxsO1xuXG4gICAgdm0ubG9nb3V0ID0gbG9nb3V0O1xuICAgIHZtLmdldEltYWdlUGVyZmlsID0gZ2V0SW1hZ2VQZXJmaWw7XG5cbiAgICBhY3RpdmF0ZSgpO1xuXG4gICAgZnVuY3Rpb24gYWN0aXZhdGUoKSB7XG4gICAgICB2YXIgZGF0ZSA9IG5ldyBEYXRlKCk7XG5cbiAgICAgIHZtLmFub0F0dWFsID0gZGF0ZS5nZXRGdWxsWWVhcigpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGxvZ291dCgpIHtcbiAgICAgIEF1dGgubG9nb3V0KCkudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgICRzdGF0ZS5nbyhHbG9iYWwubG9naW5TdGF0ZSk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBnZXRJbWFnZVBlcmZpbCgpIHtcbiAgICAgIHJldHVybiBBdXRoLmN1cnJlbnRVc2VyICYmIEF1dGguY3VycmVudFVzZXIuaW1hZ2UgPyBBdXRoLmN1cnJlbnRVc2VyLmltYWdlIDogR2xvYmFsLmltYWdlUGF0aCArICcvbm9fYXZhdGFyLmdpZic7XG4gICAgfVxuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4vKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCwgbm8tdW5kZWY6IDAqL1xuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIC8qKlxuICAgKiBUcmFuc2Zvcm1hIGJpYmxpb3RlY2FzIGV4dGVybmFzIGVtIHNlcnZpw6dvcyBkbyBhbmd1bGFyIHBhcmEgc2VyIHBvc3PDrXZlbCB1dGlsaXphclxuICAgKiBhdHJhdsOpcyBkYSBpbmplw6fDo28gZGUgZGVwZW5kw6puY2lhXG4gICAqL1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25zdGFudCgnbG9kYXNoJywgXykuY29uc3RhbnQoJ21vbWVudCcsIG1vbWVudCk7XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbnN0YW50KCdHbG9iYWwnLCB7XG4gICAgYXBwTmFtZTogJ0ZyZWVsYWdpbGUnLFxuICAgIGhvbWVTdGF0ZTogJ2FwcC5kYXNoYm9hcmQnLFxuICAgIGxvZ2luVXJsOiAnYXBwL2xvZ2luJyxcbiAgICBsb2dpblN0YXRlOiAnYXBwLmxvZ2luJyxcbiAgICByZXNldFBhc3N3b3JkU3RhdGU6ICdhcHAucGFzc3dvcmQtcmVzZXQnLFxuICAgIG5vdEF1dGhvcml6ZWRTdGF0ZTogJ2FwcC5ub3QtYXV0aG9yaXplZCcsXG4gICAgdG9rZW5LZXk6ICdzZXJ2ZXJfdG9rZW4nLFxuICAgIGNsaWVudFBhdGg6ICdjbGllbnQvYXBwJyxcbiAgICBhcGlQYXRoOiAnYXBpL3YxJyxcbiAgICBpbWFnZVBhdGg6ICdjbGllbnQvaW1hZ2VzJ1xuICB9KTtcbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsICR1cmxSb3V0ZXJQcm92aWRlciwgR2xvYmFsKSB7XG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ2FwcCcsIHtcbiAgICAgIHVybDogJy9hcHAnLFxuICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9sYXlvdXQvYXBwLmh0bWwnLFxuICAgICAgYWJzdHJhY3Q6IHRydWUsXG4gICAgICByZXNvbHZlOiB7IC8vZW5zdXJlIGxhbmdzIGlzIHJlYWR5IGJlZm9yZSByZW5kZXIgdmlld1xuICAgICAgICB0cmFuc2xhdGVSZWFkeTogWyckdHJhbnNsYXRlJywgJyRxJywgZnVuY3Rpb24gKCR0cmFuc2xhdGUsICRxKSB7XG4gICAgICAgICAgdmFyIGRlZmVycmVkID0gJHEuZGVmZXIoKTtcblxuICAgICAgICAgICR0cmFuc2xhdGUudXNlKCdwdC1CUicpLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgZGVmZXJyZWQucmVzb2x2ZSgpO1xuICAgICAgICAgIH0pO1xuXG4gICAgICAgICAgcmV0dXJuIGRlZmVycmVkLnByb21pc2U7XG4gICAgICAgIH1dXG4gICAgICB9XG4gICAgfSkuc3RhdGUoR2xvYmFsLm5vdEF1dGhvcml6ZWRTdGF0ZSwge1xuICAgICAgdXJsOiAnL2FjZXNzby1uZWdhZG8nLFxuICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9sYXlvdXQvbm90LWF1dGhvcml6ZWQuaHRtbCcsXG4gICAgICBkYXRhOiB7IG5lZWRBdXRoZW50aWNhdGlvbjogZmFsc2UgfVxuICAgIH0pO1xuXG4gICAgJHVybFJvdXRlclByb3ZpZGVyLndoZW4oJy9hcHAnLCBHbG9iYWwubG9naW5VcmwpO1xuICAgICR1cmxSb3V0ZXJQcm92aWRlci5vdGhlcndpc2UoR2xvYmFsLmxvZ2luVXJsKTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5ydW4ocnVuKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIHJ1bigkcm9vdFNjb3BlLCAkc3RhdGUsICRzdGF0ZVBhcmFtcywgQXV0aCwgR2xvYmFsKSB7XG4gICAgLy8gTk9TT05BUlxuICAgIC8vc2V0YWRvIG5vIHJvb3RTY29wZSBwYXJhIHBvZGVyIHNlciBhY2Vzc2FkbyBuYXMgdmlld3Mgc2VtIHByZWZpeG8gZGUgY29udHJvbGxlclxuICAgICRyb290U2NvcGUuJHN0YXRlID0gJHN0YXRlO1xuICAgICRyb290U2NvcGUuJHN0YXRlUGFyYW1zID0gJHN0YXRlUGFyYW1zO1xuICAgICRyb290U2NvcGUuYXV0aCA9IEF1dGg7XG4gICAgJHJvb3RTY29wZS5nbG9iYWwgPSBHbG9iYWw7XG5cbiAgICAvL25vIGluaWNpbyBjYXJyZWdhIG8gdXN1w6FyaW8gZG8gbG9jYWxzdG9yYWdlIGNhc28gbyB1c3XDoXJpbyBlc3RhamEgYWJyaW5kbyBvIG5hdmVnYWRvclxuICAgIC8vcGFyYSB2b2x0YXIgYXV0ZW50aWNhZG9cbiAgICBBdXRoLnJldHJpZXZlVXNlckZyb21Mb2NhbFN0b3JhZ2UoKTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbnRyb2xsZXIoJ0F1ZGl0Q29udHJvbGxlcicsIEF1ZGl0Q29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBBdWRpdENvbnRyb2xsZXIoJGNvbnRyb2xsZXIsIEF1ZGl0U2VydmljZSwgUHJEaWFsb2csIEdsb2JhbCwgJHRyYW5zbGF0ZSkge1xuICAgIC8vIE5PU09OQVJcbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0ub25BY3RpdmF0ZSA9IG9uQWN0aXZhdGU7XG4gICAgdm0uYXBwbHlGaWx0ZXJzID0gYXBwbHlGaWx0ZXJzO1xuICAgIHZtLnZpZXdEZXRhaWwgPSB2aWV3RGV0YWlsO1xuXG4gICAgJGNvbnRyb2xsZXIoJ0NSVURDb250cm9sbGVyJywgeyB2bTogdm0sIG1vZGVsU2VydmljZTogQXVkaXRTZXJ2aWNlLCBvcHRpb25zOiB7fSB9KTtcblxuICAgIGZ1bmN0aW9uIG9uQWN0aXZhdGUoKSB7XG4gICAgICB2bS5tb2RlbHMgPSBbXTtcbiAgICAgIHZtLnF1ZXJ5RmlsdGVycyA9IHt9O1xuXG4gICAgICAvL1BlZ2EgdG9kb3Mgb3MgbW9kZWxzIGRvIHNlcnZlciBlIG1vbnRhIHVtYSBsaXN0YSBwcm8gQ29tYm9Cb3hcbiAgICAgIEF1ZGl0U2VydmljZS5nZXRBdWRpdGVkTW9kZWxzKCkudGhlbihmdW5jdGlvbiAoZGF0YSkge1xuICAgICAgICB2YXIgbW9kZWxzID0gW3sgaWQ6ICcnLCBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KCdnbG9iYWwuYWxsJykgfV07XG5cbiAgICAgICAgZGF0YS5tb2RlbHMuc29ydCgpO1xuXG4gICAgICAgIGZvciAodmFyIGluZGV4ID0gMDsgaW5kZXggPCBkYXRhLm1vZGVscy5sZW5ndGg7IGluZGV4KyspIHtcbiAgICAgICAgICB2YXIgbW9kZWwgPSBkYXRhLm1vZGVsc1tpbmRleF07XG5cbiAgICAgICAgICBtb2RlbHMucHVzaCh7XG4gICAgICAgICAgICBpZDogbW9kZWwsXG4gICAgICAgICAgICBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KCdtb2RlbHMuJyArIG1vZGVsLnRvTG93ZXJDYXNlKCkpXG4gICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICB2bS5tb2RlbHMgPSBtb2RlbHM7XG4gICAgICAgIHZtLnF1ZXJ5RmlsdGVycy5tb2RlbCA9IHZtLm1vZGVsc1swXS5pZDtcbiAgICAgIH0pO1xuXG4gICAgICB2bS50eXBlcyA9IEF1ZGl0U2VydmljZS5saXN0VHlwZXMoKTtcbiAgICAgIHZtLnF1ZXJ5RmlsdGVycy50eXBlID0gdm0udHlwZXNbMF0uaWQ7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gYXBwbHlGaWx0ZXJzKGRlZmF1bHRRdWVyeUZpbHRlcnMpIHtcbiAgICAgIHJldHVybiBhbmd1bGFyLmV4dGVuZChkZWZhdWx0UXVlcnlGaWx0ZXJzLCB2bS5xdWVyeUZpbHRlcnMpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIHZpZXdEZXRhaWwoYXVkaXREZXRhaWwpIHtcbiAgICAgIHZhciBjb25maWcgPSB7XG4gICAgICAgIGxvY2FsczogeyBhdWRpdERldGFpbDogYXVkaXREZXRhaWwgfSxcbiAgICAgICAgLyoqIEBuZ0luamVjdCAqL1xuICAgICAgICBjb250cm9sbGVyOiBmdW5jdGlvbiBjb250cm9sbGVyKGF1ZGl0RGV0YWlsLCBQckRpYWxvZykge1xuICAgICAgICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICAgICAgICB2bS5jbG9zZSA9IGNsb3NlO1xuXG4gICAgICAgICAgYWN0aXZhdGUoKTtcblxuICAgICAgICAgIGZ1bmN0aW9uIGFjdGl2YXRlKCkge1xuICAgICAgICAgICAgaWYgKGFuZ3VsYXIuaXNBcnJheShhdWRpdERldGFpbC5vbGQpICYmIGF1ZGl0RGV0YWlsLm9sZC5sZW5ndGggPT09IDApIGF1ZGl0RGV0YWlsLm9sZCA9IG51bGw7XG4gICAgICAgICAgICBpZiAoYW5ndWxhci5pc0FycmF5KGF1ZGl0RGV0YWlsLm5ldykgJiYgYXVkaXREZXRhaWwubmV3Lmxlbmd0aCA9PT0gMCkgYXVkaXREZXRhaWwubmV3ID0gbnVsbDtcblxuICAgICAgICAgICAgdm0uYXVkaXREZXRhaWwgPSBhdWRpdERldGFpbDtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICBmdW5jdGlvbiBjbG9zZSgpIHtcbiAgICAgICAgICAgIFByRGlhbG9nLmNsb3NlKCk7XG4gICAgICAgICAgfVxuICAgICAgICB9LFxuICAgICAgICBjb250cm9sbGVyQXM6ICdhdWRpdERldGFpbEN0cmwnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL2F1ZGl0L2F1ZGl0LWRldGFpbC5odG1sJyxcbiAgICAgICAgaGFzQmFja2Ryb3A6IHRydWVcbiAgICAgIH07XG5cbiAgICAgIFByRGlhbG9nLmN1c3RvbShjb25maWcpO1xuICAgIH1cbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25maWcocm91dGVzKTtcblxuICAvKipcbiAgICogQXJxdWl2byBkZSBjb25maWd1cmHDp8OjbyBjb20gYXMgcm90YXMgZXNwZWPDrWZpY2FzIGRlIGF1ZGl0b3JpYVxuICAgKlxuICAgKiBAcGFyYW0ge2FueX0gJHN0YXRlUHJvdmlkZXJcbiAgICogQHBhcmFtIHthbnl9IEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdhcHAuYXVkaXQnLCB7XG4gICAgICB1cmw6ICcvYXVkaXRvcmlhJyxcbiAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvYXVkaXQvYXVkaXQuaHRtbCcsXG4gICAgICBjb250cm9sbGVyOiAnQXVkaXRDb250cm9sbGVyIGFzIGF1ZGl0Q3RybCcsXG4gICAgICBkYXRhOiB7IG5lZWRBdXRoZW50aWNhdGlvbjogdHJ1ZSwgbmVlZFByb2ZpbGU6IFsnYWRtaW4nXSB9XG4gICAgfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmFjdG9yeSgnQXVkaXRTZXJ2aWNlJywgQXVkaXRTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIEF1ZGl0U2VydmljZShzZXJ2aWNlRmFjdG9yeSwgJHRyYW5zbGF0ZSkge1xuICAgIHJldHVybiBzZXJ2aWNlRmFjdG9yeSgnYXVkaXQnLCB7XG4gICAgICBhY3Rpb25zOiB7XG4gICAgICAgIGdldEF1ZGl0ZWRNb2RlbHM6IHtcbiAgICAgICAgICBtZXRob2Q6ICdHRVQnLFxuICAgICAgICAgIHVybDogJ21vZGVscydcbiAgICAgICAgfVxuICAgICAgfSxcbiAgICAgIGluc3RhbmNlOiB7fSxcbiAgICAgIGxpc3RUeXBlczogZnVuY3Rpb24gbGlzdFR5cGVzKCkge1xuICAgICAgICB2YXIgYXVkaXRQYXRoID0gJ3ZpZXdzLmZpZWxkcy5hdWRpdC4nO1xuXG4gICAgICAgIHJldHVybiBbeyBpZDogJycsIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoYXVkaXRQYXRoICsgJ2FsbFJlc291cmNlcycpIH0sIHsgaWQ6ICdjcmVhdGVkJywgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudChhdWRpdFBhdGggKyAndHlwZS5jcmVhdGVkJykgfSwgeyBpZDogJ3VwZGF0ZWQnLCBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KGF1ZGl0UGF0aCArICd0eXBlLnVwZGF0ZWQnKSB9LCB7IGlkOiAnZGVsZXRlZCcsIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoYXVkaXRQYXRoICsgJ3R5cGUuZGVsZXRlZCcpIH1dO1xuICAgICAgfVxuICAgIH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKlxuICAgKiBBcnF1aXZvIGRlIGNvbmZpZ3VyYcOnw6NvIGNvbSBhcyByb3RhcyBlc3BlY8OtZmljYXMgZG8gcmVjdXJzbyB1c2VyXG4gICAqXG4gICAqIEBwYXJhbSB7YW55fSAkc3RhdGVQcm92aWRlclxuICAgKiBAcGFyYW0ge2FueX0gR2xvYmFsXG4gICAqL1xuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvdXRlcygkc3RhdGVQcm92aWRlciwgR2xvYmFsKSB7XG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoR2xvYmFsLnJlc2V0UGFzc3dvcmRTdGF0ZSwge1xuICAgICAgdXJsOiAnL3Bhc3N3b3JkL3Jlc2V0Lzp0b2tlbicsXG4gICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL2F1dGgvcmVzZXQtcGFzcy1mb3JtLmh0bWwnLFxuICAgICAgY29udHJvbGxlcjogJ1Bhc3N3b3JkQ29udHJvbGxlciBhcyBwYXNzQ3RybCcsXG4gICAgICBkYXRhOiB7IG5lZWRBdXRoZW50aWNhdGlvbjogZmFsc2UgfVxuICAgIH0pLnN0YXRlKEdsb2JhbC5sb2dpblN0YXRlLCB7XG4gICAgICB1cmw6ICcvbG9naW4nLFxuICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9hdXRoL2xvZ2luLmh0bWwnLFxuICAgICAgY29udHJvbGxlcjogJ0xvZ2luQ29udHJvbGxlciBhcyBsb2dpbkN0cmwnLFxuICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IGZhbHNlIH1cbiAgICB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5mYWN0b3J5KCdBdXRoJywgQXV0aCk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBBdXRoKCRodHRwLCAkcSwgR2xvYmFsLCBVc2Vyc1NlcnZpY2UpIHtcbiAgICAvLyBOT1NPTkFSXG4gICAgdmFyIGF1dGggPSB7XG4gICAgICBsb2dpbjogbG9naW4sXG4gICAgICBsb2dvdXQ6IGxvZ291dCxcbiAgICAgIHVwZGF0ZUN1cnJlbnRVc2VyOiB1cGRhdGVDdXJyZW50VXNlcixcbiAgICAgIHJldHJpZXZlVXNlckZyb21Mb2NhbFN0b3JhZ2U6IHJldHJpZXZlVXNlckZyb21Mb2NhbFN0b3JhZ2UsXG4gICAgICBhdXRoZW50aWNhdGVkOiBhdXRoZW50aWNhdGVkLFxuICAgICAgc2VuZEVtYWlsUmVzZXRQYXNzd29yZDogc2VuZEVtYWlsUmVzZXRQYXNzd29yZCxcbiAgICAgIHJlbW90ZVZhbGlkYXRlVG9rZW46IHJlbW90ZVZhbGlkYXRlVG9rZW4sXG4gICAgICBnZXRUb2tlbjogZ2V0VG9rZW4sXG4gICAgICBzZXRUb2tlbjogc2V0VG9rZW4sXG4gICAgICBjbGVhclRva2VuOiBjbGVhclRva2VuLFxuICAgICAgY3VycmVudFVzZXI6IG51bGxcbiAgICB9O1xuXG4gICAgZnVuY3Rpb24gY2xlYXJUb2tlbigpIHtcbiAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKEdsb2JhbC50b2tlbktleSk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gc2V0VG9rZW4odG9rZW4pIHtcbiAgICAgIGxvY2FsU3RvcmFnZS5zZXRJdGVtKEdsb2JhbC50b2tlbktleSwgdG9rZW4pO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGdldFRva2VuKCkge1xuICAgICAgcmV0dXJuIGxvY2FsU3RvcmFnZS5nZXRJdGVtKEdsb2JhbC50b2tlbktleSk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gcmVtb3RlVmFsaWRhdGVUb2tlbigpIHtcbiAgICAgIHZhciBkZWZlcnJlZCA9ICRxLmRlZmVyKCk7XG5cbiAgICAgIGlmIChhdXRoLmF1dGhlbnRpY2F0ZWQoKSkge1xuICAgICAgICAkaHR0cC5nZXQoR2xvYmFsLmFwaVBhdGggKyAnL2F1dGhlbnRpY2F0ZS9jaGVjaycpLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICAgIGRlZmVycmVkLnJlc29sdmUodHJ1ZSk7XG4gICAgICAgIH0sIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICBhdXRoLmxvZ291dCgpO1xuXG4gICAgICAgICAgZGVmZXJyZWQucmVqZWN0KGZhbHNlKTtcbiAgICAgICAgfSk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBhdXRoLmxvZ291dCgpO1xuXG4gICAgICAgIGRlZmVycmVkLnJlamVjdChmYWxzZSk7XG4gICAgICB9XG5cbiAgICAgIHJldHVybiBkZWZlcnJlZC5wcm9taXNlO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFZlcmlmaWNhIHNlIG8gdXN1w6FyaW8gZXN0w6EgYXV0ZW50aWNhZG9cbiAgICAgKlxuICAgICAqIEByZXR1cm5zIHtib29sZWFufVxuICAgICAqL1xuICAgIGZ1bmN0aW9uIGF1dGhlbnRpY2F0ZWQoKSB7XG4gICAgICByZXR1cm4gYXV0aC5nZXRUb2tlbigpICE9PSBudWxsO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlY3VwZXJhIG8gdXN1w6FyaW8gZG8gbG9jYWxTdG9yYWdlXG4gICAgICovXG4gICAgZnVuY3Rpb24gcmV0cmlldmVVc2VyRnJvbUxvY2FsU3RvcmFnZSgpIHtcbiAgICAgIHZhciB1c2VyID0gbG9jYWxTdG9yYWdlLmdldEl0ZW0oJ3VzZXInKTtcblxuICAgICAgaWYgKHVzZXIpIHtcbiAgICAgICAgYXV0aC5jdXJyZW50VXNlciA9IGFuZ3VsYXIubWVyZ2UobmV3IFVzZXJzU2VydmljZSgpLCBhbmd1bGFyLmZyb21Kc29uKHVzZXIpKTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBHdWFyZGEgbyB1c3XDoXJpbyBubyBsb2NhbFN0b3JhZ2UgcGFyYSBjYXNvIG8gdXN1w6FyaW8gZmVjaGUgZSBhYnJhIG8gbmF2ZWdhZG9yXG4gICAgICogZGVudHJvIGRvIHRlbXBvIGRlIHNlc3PDo28gc2VqYSBwb3Nzw612ZWwgcmVjdXBlcmFyIG8gdG9rZW4gYXV0ZW50aWNhZG8uXG4gICAgICpcbiAgICAgKiBNYW50w6ltIGEgdmFyacOhdmVsIGF1dGguY3VycmVudFVzZXIgcGFyYSBmYWNpbGl0YXIgbyBhY2Vzc28gYW8gdXN1w6FyaW8gbG9nYWRvIGVtIHRvZGEgYSBhcGxpY2HDp8Ojb1xuICAgICAqXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gdXNlciBVc3XDoXJpbyBhIHNlciBhdHVhbGl6YWRvLiBDYXNvIHNlamEgcGFzc2FkbyBudWxsIGxpbXBhXG4gICAgICogdG9kYXMgYXMgaW5mb3JtYcOnw7VlcyBkbyB1c3XDoXJpbyBjb3JyZW50ZS5cbiAgICAgKi9cbiAgICBmdW5jdGlvbiB1cGRhdGVDdXJyZW50VXNlcih1c2VyKSB7XG4gICAgICB2YXIgZGVmZXJyZWQgPSAkcS5kZWZlcigpO1xuXG4gICAgICBpZiAodXNlcikge1xuICAgICAgICB1c2VyID0gYW5ndWxhci5tZXJnZShuZXcgVXNlcnNTZXJ2aWNlKCksIHVzZXIpO1xuXG4gICAgICAgIHZhciBqc29uVXNlciA9IGFuZ3VsYXIudG9Kc29uKHVzZXIpO1xuXG4gICAgICAgIGxvY2FsU3RvcmFnZS5zZXRJdGVtKCd1c2VyJywganNvblVzZXIpO1xuICAgICAgICBhdXRoLmN1cnJlbnRVc2VyID0gdXNlcjtcblxuICAgICAgICBkZWZlcnJlZC5yZXNvbHZlKHVzZXIpO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oJ3VzZXInKTtcbiAgICAgICAgYXV0aC5jdXJyZW50VXNlciA9IG51bGw7XG4gICAgICAgIGF1dGguY2xlYXJUb2tlbigpO1xuXG4gICAgICAgIGRlZmVycmVkLnJlamVjdCgpO1xuICAgICAgfVxuXG4gICAgICByZXR1cm4gZGVmZXJyZWQucHJvbWlzZTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFsaXphIG8gbG9naW4gZG8gdXN1w6FyaW9cbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSBjcmVkZW50aWFscyBFbWFpbCBlIFNlbmhhIGRvIHVzdcOhcmlvXG4gICAgICogQHJldHVybnMge3Byb21pc2V9IFVtYSBwcm9taXNlIGNvbSBvIHJlc3VsdGFkbyBkbyBjaGFtYWRhIG5vIGJhY2tlbmRcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBsb2dpbihjcmVkZW50aWFscykge1xuICAgICAgdmFyIGRlZmVycmVkID0gJHEuZGVmZXIoKTtcblxuICAgICAgJGh0dHAucG9zdChHbG9iYWwuYXBpUGF0aCArICcvYXV0aGVudGljYXRlJywgY3JlZGVudGlhbHMpLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgIGF1dGguc2V0VG9rZW4ocmVzcG9uc2UuZGF0YS50b2tlbik7XG5cbiAgICAgICAgcmV0dXJuICRodHRwLmdldChHbG9iYWwuYXBpUGF0aCArICcvYXV0aGVudGljYXRlL3VzZXInKTtcbiAgICAgIH0pLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgIGF1dGgudXBkYXRlQ3VycmVudFVzZXIocmVzcG9uc2UuZGF0YS51c2VyKTtcblxuICAgICAgICBkZWZlcnJlZC5yZXNvbHZlKCk7XG4gICAgICB9LCBmdW5jdGlvbiAoZXJyb3IpIHtcbiAgICAgICAgYXV0aC5sb2dvdXQoKTtcblxuICAgICAgICBkZWZlcnJlZC5yZWplY3QoZXJyb3IpO1xuICAgICAgfSk7XG5cbiAgICAgIHJldHVybiBkZWZlcnJlZC5wcm9taXNlO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIERlc2xvZ2Egb3MgdXN1w6FyaW9zLiBDb21vIG7Do28gdGVuIG5lbmh1bWEgaW5mb3JtYcOnw6NvIG5hIHNlc3PDo28gZG8gc2Vydmlkb3JcbiAgICAgKiBlIHVtIHRva2VuIHVtYSB2ZXogZ2VyYWRvIG7Do28gcG9kZSwgcG9yIHBhZHLDo28sIHNlciBpbnZhbGlkYWRvIGFudGVzIGRvIHNldSB0ZW1wbyBkZSBleHBpcmHDp8OjbyxcbiAgICAgKiBzb21lbnRlIGFwYWdhbW9zIG9zIGRhZG9zIGRvIHVzdcOhcmlvIGUgbyB0b2tlbiBkbyBuYXZlZ2Fkb3IgcGFyYSBlZmV0aXZhciBvIGxvZ291dC5cbiAgICAgKlxuICAgICAqIEByZXR1cm5zIHtwcm9taXNlfSBVbWEgcHJvbWlzZSBjb20gbyByZXN1bHRhZG8gZGEgb3BlcmHDp8Ojb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGxvZ291dCgpIHtcbiAgICAgIHZhciBkZWZlcnJlZCA9ICRxLmRlZmVyKCk7XG5cbiAgICAgIGF1dGgudXBkYXRlQ3VycmVudFVzZXIobnVsbCk7XG4gICAgICBkZWZlcnJlZC5yZXNvbHZlKCk7XG5cbiAgICAgIHJldHVybiBkZWZlcnJlZC5wcm9taXNlO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEVudmlhIHVtIGVtYWlsIHBhcmEgcmVjdXBlcmHDp8OjbyBkZSBzZW5oYVxuICAgICAqIEBwYXJhbSB7T2JqZWN0fSByZXNldERhdGEgLSBPYmpldG8gY29udGVuZG8gbyBlbWFpbFxuICAgICAqIEByZXR1cm4ge1Byb21pc2V9IC0gUmV0b3JuYSB1bWEgcHJvbWlzZSBwYXJhIHNlciByZXNvbHZpZGFcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBzZW5kRW1haWxSZXNldFBhc3N3b3JkKHJlc2V0RGF0YSkge1xuICAgICAgdmFyIGRlZmVycmVkID0gJHEuZGVmZXIoKTtcblxuICAgICAgJGh0dHAucG9zdChHbG9iYWwuYXBpUGF0aCArICcvcGFzc3dvcmQvZW1haWwnLCByZXNldERhdGEpLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgIGRlZmVycmVkLnJlc29sdmUocmVzcG9uc2UuZGF0YSk7XG4gICAgICB9LCBmdW5jdGlvbiAoZXJyb3IpIHtcbiAgICAgICAgZGVmZXJyZWQucmVqZWN0KGVycm9yKTtcbiAgICAgIH0pO1xuXG4gICAgICByZXR1cm4gZGVmZXJyZWQucHJvbWlzZTtcbiAgICB9XG5cbiAgICByZXR1cm4gYXV0aDtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbnRyb2xsZXIoJ0xvZ2luQ29udHJvbGxlcicsIExvZ2luQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBMb2dpbkNvbnRyb2xsZXIoJHN0YXRlLCBBdXRoLCBHbG9iYWwsIFByRGlhbG9nKSB7XG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIHZtLmxvZ2luID0gbG9naW47XG4gICAgdm0ub3BlbkRpYWxvZ1Jlc2V0UGFzcyA9IG9wZW5EaWFsb2dSZXNldFBhc3M7XG4gICAgdm0ub3BlbkRpYWxvZ1NpZ25VcCA9IG9wZW5EaWFsb2dTaWduVXA7XG5cbiAgICBhY3RpdmF0ZSgpO1xuXG4gICAgZnVuY3Rpb24gYWN0aXZhdGUoKSB7XG4gICAgICB2bS5jcmVkZW50aWFscyA9IHt9O1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGxvZ2luKCkge1xuICAgICAgdmFyIGNyZWRlbnRpYWxzID0ge1xuICAgICAgICBlbWFpbDogdm0uY3JlZGVudGlhbHMuZW1haWwsXG4gICAgICAgIHBhc3N3b3JkOiB2bS5jcmVkZW50aWFscy5wYXNzd29yZFxuICAgICAgfTtcblxuICAgICAgQXV0aC5sb2dpbihjcmVkZW50aWFscykudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgICRzdGF0ZS5nbyhHbG9iYWwuaG9tZVN0YXRlKTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEV4aWJlIG8gZGlhbG9nIHBhcmEgcmVjdXBlcmHDp8OjbyBkZSBzZW5oYVxuICAgICAqL1xuICAgIGZ1bmN0aW9uIG9wZW5EaWFsb2dSZXNldFBhc3MoKSB7XG4gICAgICB2YXIgY29uZmlnID0ge1xuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL2F1dGgvc2VuZC1yZXNldC1kaWFsb2cuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdQYXNzd29yZENvbnRyb2xsZXIgYXMgcGFzc0N0cmwnLFxuICAgICAgICBoYXNCYWNrZHJvcDogdHJ1ZVxuICAgICAgfTtcblxuICAgICAgUHJEaWFsb2cuY3VzdG9tKGNvbmZpZyk7XG4gICAgfVxuICAgIC8qKlxuICAgICAqIEV4aWJlIG8gZGlhbG9nIHBhcmEgcmVjdXBlcmHDp8OjbyBkZSBzZW5oYVxuICAgICAqL1xuICAgIGZ1bmN0aW9uIG9wZW5EaWFsb2dTaWduVXAoKSB7XG4gICAgICB2YXIgY29uZmlnID0ge1xuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL3VzZXJzL3VzZXItZm9ybS5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ1VzZXJzQ29udHJvbGxlciBhcyB1c2Vyc0N0cmwnLFxuICAgICAgICBoYXNCYWNrZHJvcDogdHJ1ZVxuICAgICAgfTtcblxuICAgICAgUHJEaWFsb2cuY3VzdG9tKGNvbmZpZyk7XG4gICAgfVxuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29udHJvbGxlcignUGFzc3dvcmRDb250cm9sbGVyJywgUGFzc3dvcmRDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIFBhc3N3b3JkQ29udHJvbGxlcihHbG9iYWwsICRzdGF0ZVBhcmFtcywgJGh0dHAsICR0aW1lb3V0LCAkc3RhdGUsIC8vIE5PU09OQVJcbiAgUHJUb2FzdCwgUHJEaWFsb2csIEF1dGgsICR0cmFuc2xhdGUpIHtcblxuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICB2bS5zZW5kUmVzZXQgPSBzZW5kUmVzZXQ7XG4gICAgdm0uY2xvc2VEaWFsb2cgPSBjbG9zZURpYWxvZztcbiAgICB2bS5jbGVhbkZvcm0gPSBjbGVhbkZvcm07XG4gICAgdm0uc2VuZEVtYWlsUmVzZXRQYXNzd29yZCA9IHNlbmRFbWFpbFJlc2V0UGFzc3dvcmQ7XG5cbiAgICBhY3RpdmF0ZSgpO1xuXG4gICAgZnVuY3Rpb24gYWN0aXZhdGUoKSB7XG4gICAgICB2bS5yZXNldCA9IHsgZW1haWw6ICcnLCB0b2tlbjogJHN0YXRlUGFyYW1zLnRva2VuIH07XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhbGl6YSBhIGFsdGVyYcOnw6NvIGRhIHNlbmhhIGRvIHVzdcOhcmlvIGUgbyByZWRpcmVjaW9uYSBwYXJhIGEgdGVsYSBkZSBsb2dpblxuICAgICAqL1xuICAgIGZ1bmN0aW9uIHNlbmRSZXNldCgpIHtcbiAgICAgICRodHRwLnBvc3QoR2xvYmFsLmFwaVBhdGggKyAnL3Bhc3N3b3JkL3Jlc2V0Jywgdm0ucmVzZXQpLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICBQclRvYXN0LnN1Y2Nlc3MoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5vcGVyYXRpb25TdWNjZXNzJykpO1xuICAgICAgICAkdGltZW91dChmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgJHN0YXRlLmdvKEdsb2JhbC5sb2dpblN0YXRlKTtcbiAgICAgICAgfSwgMTUwMCk7XG4gICAgICB9LCBmdW5jdGlvbiAoZXJyb3IpIHtcbiAgICAgICAgaWYgKGVycm9yLnN0YXR1cyAhPT0gNDAwICYmIGVycm9yLnN0YXR1cyAhPT0gNTAwKSB7XG4gICAgICAgICAgdmFyIG1zZyA9ICcnO1xuXG4gICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCBlcnJvci5kYXRhLnBhc3N3b3JkLmxlbmd0aDsgaSsrKSB7XG4gICAgICAgICAgICBtc2cgKz0gZXJyb3IuZGF0YS5wYXNzd29yZFtpXSArICc8YnI+JztcbiAgICAgICAgICB9XG4gICAgICAgICAgUHJUb2FzdC5lcnJvcihtc2cudG9VcHBlckNhc2UoKSk7XG4gICAgICAgIH1cbiAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEVudmlhIHVtIGVtYWlsIGRlIHJlY3VwZXJhw6fDo28gZGUgc2VuaGEgY29tIG8gdG9rZW4gZG8gdXN1w6FyaW9cbiAgICAgKi9cbiAgICBmdW5jdGlvbiBzZW5kRW1haWxSZXNldFBhc3N3b3JkKCkge1xuXG4gICAgICBpZiAodm0ucmVzZXQuZW1haWwgPT09ICcnKSB7XG4gICAgICAgIFByVG9hc3QuZXJyb3IoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy52YWxpZGF0ZS5maWVsZFJlcXVpcmVkJywgeyBmaWVsZDogJ2VtYWlsJyB9KSk7XG4gICAgICAgIHJldHVybjtcbiAgICAgIH1cblxuICAgICAgQXV0aC5zZW5kRW1haWxSZXNldFBhc3N3b3JkKHZtLnJlc2V0KS50aGVuKGZ1bmN0aW9uIChkYXRhKSB7XG4gICAgICAgIFByVG9hc3Quc3VjY2VzcyhkYXRhLm1lc3NhZ2UpO1xuXG4gICAgICAgIHZtLmNsZWFuRm9ybSgpO1xuICAgICAgICB2bS5jbG9zZURpYWxvZygpO1xuICAgICAgfSwgZnVuY3Rpb24gKGVycm9yKSB7XG4gICAgICAgIGlmIChlcnJvci5kYXRhLmVtYWlsICYmIGVycm9yLmRhdGEuZW1haWwubGVuZ3RoID4gMCkge1xuICAgICAgICAgIHZhciBtc2cgPSAnJztcblxuICAgICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgZXJyb3IuZGF0YS5lbWFpbC5sZW5ndGg7IGkrKykge1xuICAgICAgICAgICAgbXNnICs9IGVycm9yLmRhdGEuZW1haWxbaV0gKyAnPGJyPic7XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgUHJUb2FzdC5lcnJvcihtc2cpO1xuICAgICAgICB9XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBjbG9zZURpYWxvZygpIHtcbiAgICAgIFByRGlhbG9nLmNsb3NlKCk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gY2xlYW5Gb3JtKCkge1xuICAgICAgdm0ucmVzZXQuZW1haWwgPSAnJztcbiAgICB9XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbi8qZXNsaW50IGFuZ3VsYXIvZmlsZS1uYW1lOiAwKi9cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmFjdG9yeSgnc2VydmljZUZhY3RvcnknLCBzZXJ2aWNlRmFjdG9yeSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvKipcbiAgICogTWFpcyBpbmZvcm1hw6fDtWVzOlxuICAgKiBodHRwczovL2dpdGh1Yi5jb20vc3dpbWxhbmUvYW5ndWxhci1tb2RlbC1mYWN0b3J5L3dpa2kvQVBJXG4gICAqL1xuICBmdW5jdGlvbiBzZXJ2aWNlRmFjdG9yeSgkbW9kZWxGYWN0b3J5KSB7XG4gICAgcmV0dXJuIGZ1bmN0aW9uICh1cmwsIG9wdGlvbnMpIHtcbiAgICAgIHZhciBtb2RlbDtcbiAgICAgIHZhciBkZWZhdWx0T3B0aW9ucyA9IHtcbiAgICAgICAgYWN0aW9uczoge1xuICAgICAgICAgIC8qKlxuICAgICAgICAgICAqIFNlcnZpw6dvIGNvbXVtIHBhcmEgcmVhbGl6YXIgYnVzY2EgY29tIHBhZ2luYcOnw6NvXG4gICAgICAgICAgICogTyBtZXNtbyBlc3BlcmEgcXVlIHNlamEgcmV0b3JuYWRvIHVtIG9iamV0byBjb20gaXRlbXMgZSB0b3RhbFxuICAgICAgICAgICAqL1xuICAgICAgICAgIHBhZ2luYXRlOiB7XG4gICAgICAgICAgICBtZXRob2Q6ICdHRVQnLFxuICAgICAgICAgICAgaXNBcnJheTogZmFsc2UsXG4gICAgICAgICAgICB3cmFwOiBmYWxzZSxcbiAgICAgICAgICAgIGFmdGVyUmVxdWVzdDogZnVuY3Rpb24gYWZ0ZXJSZXF1ZXN0KHJlc3BvbnNlKSB7XG4gICAgICAgICAgICAgIGlmIChyZXNwb25zZVsnaXRlbXMnXSkge1xuICAgICAgICAgICAgICAgIHJlc3BvbnNlWydpdGVtcyddID0gbW9kZWwuTGlzdChyZXNwb25zZVsnaXRlbXMnXSk7XG4gICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICByZXR1cm4gcmVzcG9uc2U7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICB9O1xuXG4gICAgICBtb2RlbCA9ICRtb2RlbEZhY3RvcnkodXJsLCBhbmd1bGFyLm1lcmdlKGRlZmF1bHRPcHRpb25zLCBvcHRpb25zKSk7XG5cbiAgICAgIHJldHVybiBtb2RlbDtcbiAgICB9O1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29udHJvbGxlcignQ1JVRENvbnRyb2xsZXInLCBDUlVEQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvKipcbiAgICogQ29udHJvbGFkb3IgQmFzZSBxdWUgaW1wbGVtZW50YSB0b2RhcyBhcyBmdW7Dp8O1ZXMgcGFkcsO1ZXMgZGUgdW0gQ1JVRFxuICAgKlxuICAgKiBBw6fDtWVzIGltcGxlbWVudGFkYXNcbiAgICogYWN0aXZhdGUoKVxuICAgKiBzZWFyY2gocGFnZSlcbiAgICogZWRpdChyZXNvdXJjZSlcbiAgICogc2F2ZSgpXG4gICAqIHJlbW92ZShyZXNvdXJjZSlcbiAgICogZ29Ubyh2aWV3TmFtZSlcbiAgICogY2xlYW5Gb3JtKClcbiAgICpcbiAgICogR2F0aWxob3NcbiAgICpcbiAgICogb25BY3RpdmF0ZSgpXG4gICAqIGFwcGx5RmlsdGVycyhkZWZhdWx0UXVlcnlGaWx0ZXJzKVxuICAgKiBiZWZvcmVTZWFyY2gocGFnZSkgLy9yZXRvcm5hbmRvIGZhbHNlIGNhbmNlbGEgbyBmbHV4b1xuICAgKiBhZnRlclNlYXJjaChyZXNwb25zZSlcbiAgICogYmVmb3JlQ2xlYW4gLy9yZXRvcm5hbmRvIGZhbHNlIGNhbmNlbGEgbyBmbHV4b1xuICAgKiBhZnRlckNsZWFuKClcbiAgICogYmVmb3JlU2F2ZSgpIC8vcmV0b3JuYW5kbyBmYWxzZSBjYW5jZWxhIG8gZmx1eG9cbiAgICogYWZ0ZXJTYXZlKHJlc291cmNlKVxuICAgKiBvblNhdmVFcnJvcihlcnJvcilcbiAgICogYmVmb3JlUmVtb3ZlKHJlc291cmNlKSAvL3JldG9ybmFuZG8gZmFsc2UgY2FuY2VsYSBvIGZsdXhvXG4gICAqIGFmdGVyUmVtb3ZlKHJlc291cmNlKVxuICAgKlxuICAgKiBAcGFyYW0ge2FueX0gdm0gaW5zdGFuY2lhIGRvIGNvbnRyb2xsZXIgZmlsaG9cbiAgICogQHBhcmFtIHthbnl9IG1vZGVsU2VydmljZSBzZXJ2acOnbyBkbyBtb2RlbCBxdWUgdmFpIHNlciB1dGlsaXphZG9cbiAgICogQHBhcmFtIHthbnl9IG9wdGlvbnMgb3DDp8O1ZXMgcGFyYSBzb2JyZWVzY3JldmVyIGNvbXBvcnRhbWVudG9zIHBhZHLDtWVzXG4gICAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBDUlVEQ29udHJvbGxlcih2bSwgbW9kZWxTZXJ2aWNlLCBvcHRpb25zLCBQclRvYXN0LCBQclBhZ2luYXRpb24sIC8vIE5PU09OQVJcbiAgUHJEaWFsb2csICR0cmFuc2xhdGUpIHtcblxuICAgIC8vRnVuY3Rpb25zIEJsb2NrXG4gICAgdm0uc2VhcmNoID0gc2VhcmNoO1xuICAgIHZtLnBhZ2luYXRlU2VhcmNoID0gcGFnaW5hdGVTZWFyY2g7XG4gICAgdm0ubm9ybWFsU2VhcmNoID0gbm9ybWFsU2VhcmNoO1xuICAgIHZtLmVkaXQgPSBlZGl0O1xuICAgIHZtLnNhdmUgPSBzYXZlO1xuICAgIHZtLnJlbW92ZSA9IHJlbW92ZTtcbiAgICB2bS5nb1RvID0gZ29UbztcbiAgICB2bS5jbGVhbkZvcm0gPSBjbGVhbkZvcm07XG5cbiAgICBhY3RpdmF0ZSgpO1xuXG4gICAgLyoqXG4gICAgICogUHJlcGFyYSBvIGNvbnRyb2xhZG9yXG4gICAgICogRmF6IG8gbWVyZ2UgZGFzIG9ww6fDtWVzXG4gICAgICogSW5pY2lhbGl6YSBvIHJlY3Vyc29cbiAgICAgKiBJbmljaWFsaXphIG8gb2JqZXRvIHBhZ2luYWRvciBlIHJlYWxpemEgYSBwZXNxdWlzYVxuICAgICAqL1xuICAgIGZ1bmN0aW9uIGFjdGl2YXRlKCkge1xuICAgICAgdm0uZGVmYXVsdE9wdGlvbnMgPSB7XG4gICAgICAgIHJlZGlyZWN0QWZ0ZXJTYXZlOiB0cnVlLFxuICAgICAgICBzZWFyY2hPbkluaXQ6IHRydWUsXG4gICAgICAgIHBlclBhZ2U6IDgsXG4gICAgICAgIHNraXBQYWdpbmF0aW9uOiBmYWxzZVxuICAgICAgfTtcblxuICAgICAgYW5ndWxhci5tZXJnZSh2bS5kZWZhdWx0T3B0aW9ucywgb3B0aW9ucyk7XG5cbiAgICAgIHZtLnZpZXdGb3JtID0gZmFsc2U7XG4gICAgICB2bS5yZXNvdXJjZSA9IG5ldyBtb2RlbFNlcnZpY2UoKTtcblxuICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5vbkFjdGl2YXRlKSkgdm0ub25BY3RpdmF0ZSgpO1xuXG4gICAgICB2bS5wYWdpbmF0b3IgPSBQclBhZ2luYXRpb24uZ2V0SW5zdGFuY2Uodm0uc2VhcmNoLCB2bS5kZWZhdWx0T3B0aW9ucy5wZXJQYWdlKTtcblxuICAgICAgaWYgKHZtLmRlZmF1bHRPcHRpb25zLnNlYXJjaE9uSW5pdCkgdm0uc2VhcmNoKCk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhbGl6YSBhIHBlc3F1aXNhXG4gICAgICogVmVyaWZpY2EgcXVhbCBkYXMgZnVuw6fDtWVzIGRlIHBlc3F1aXNhIGRldmUgc2VyIHJlYWxpemFkYS5cbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSBwYWdlIHDDoWdpbmEgcXVlIGRldmUgc2VyIGNhcnJlZ2FkYVxuICAgICAqL1xuICAgIGZ1bmN0aW9uIHNlYXJjaChwYWdlKSB7XG4gICAgICB2bS5kZWZhdWx0T3B0aW9ucy5za2lwUGFnaW5hdGlvbiA/IG5vcm1hbFNlYXJjaCgpIDogcGFnaW5hdGVTZWFyY2gocGFnZSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhbGl6YSBhIHBlc3F1aXNhIHBhZ2luYWRhIGNvbSBiYXNlIG5vcyBmaWx0cm9zIGRlZmluaWRvc1xuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IHBhZ2UgcMOhZ2luYSBxdWUgZGV2ZSBzZXIgY2FycmVnYWRhXG4gICAgICovXG4gICAgZnVuY3Rpb24gcGFnaW5hdGVTZWFyY2gocGFnZSkge1xuICAgICAgdm0ucGFnaW5hdG9yLmN1cnJlbnRQYWdlID0gYW5ndWxhci5pc0RlZmluZWQocGFnZSkgPyBwYWdlIDogMTtcbiAgICAgIHZtLmRlZmF1bHRRdWVyeUZpbHRlcnMgPSB7IHBhZ2U6IHZtLnBhZ2luYXRvci5jdXJyZW50UGFnZSwgcGVyUGFnZTogdm0ucGFnaW5hdG9yLnBlclBhZ2UgfTtcblxuICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5hcHBseUZpbHRlcnMpKSB2bS5kZWZhdWx0UXVlcnlGaWx0ZXJzID0gdm0uYXBwbHlGaWx0ZXJzKHZtLmRlZmF1bHRRdWVyeUZpbHRlcnMpO1xuICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5iZWZvcmVTZWFyY2gpICYmIHZtLmJlZm9yZVNlYXJjaChwYWdlKSA9PT0gZmFsc2UpIHJldHVybiBmYWxzZTtcblxuICAgICAgbW9kZWxTZXJ2aWNlLnBhZ2luYXRlKHZtLmRlZmF1bHRRdWVyeUZpbHRlcnMpLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgIHZtLnBhZ2luYXRvci5jYWxjTnVtYmVyT2ZQYWdlcyhyZXNwb25zZS50b3RhbCk7XG4gICAgICAgIHZtLnJlc291cmNlcyA9IHJlc3BvbnNlLml0ZW1zO1xuXG4gICAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYWZ0ZXJTZWFyY2gpKSB2bS5hZnRlclNlYXJjaChyZXNwb25zZSk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFsaXphIGEgcGVzcXVpc2EgY29tIGJhc2Ugbm9zIGZpbHRyb3MgZGVmaW5pZG9zXG4gICAgICpcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBub3JtYWxTZWFyY2goKSB7XG4gICAgICB2bS5kZWZhdWx0UXVlcnlGaWx0ZXJzID0ge307XG5cbiAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYXBwbHlGaWx0ZXJzKSkgdm0uZGVmYXVsdFF1ZXJ5RmlsdGVycyA9IHZtLmFwcGx5RmlsdGVycyh2bS5kZWZhdWx0UXVlcnlGaWx0ZXJzKTtcbiAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYmVmb3JlU2VhcmNoKSAmJiB2bS5iZWZvcmVTZWFyY2goKSA9PT0gZmFsc2UpIHJldHVybiBmYWxzZTtcblxuICAgICAgbW9kZWxTZXJ2aWNlLnF1ZXJ5KHZtLmRlZmF1bHRRdWVyeUZpbHRlcnMpLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgIHZtLnJlc291cmNlcyA9IHJlc3BvbnNlO1xuXG4gICAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYWZ0ZXJTZWFyY2gpKSB2bS5hZnRlclNlYXJjaChyZXNwb25zZSk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBMaW1wYSBvIGZvcm11bMOhcmlvXG4gICAgICovXG4gICAgZnVuY3Rpb24gY2xlYW5Gb3JtKGZvcm0pIHtcbiAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYmVmb3JlQ2xlYW4pICYmIHZtLmJlZm9yZUNsZWFuKCkgPT09IGZhbHNlKSByZXR1cm4gZmFsc2U7XG5cbiAgICAgIHZtLnJlc291cmNlID0gbmV3IG1vZGVsU2VydmljZSgpO1xuXG4gICAgICBpZiAoYW5ndWxhci5pc0RlZmluZWQoZm9ybSkpIHtcbiAgICAgICAgZm9ybS4kc2V0UHJpc3RpbmUoKTtcbiAgICAgICAgZm9ybS4kc2V0VW50b3VjaGVkKCk7XG4gICAgICB9XG5cbiAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYWZ0ZXJDbGVhbikpIHZtLmFmdGVyQ2xlYW4oKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDYXJyZWdhIG5vIGZvcm11bMOhcmlvIG8gcmVjdXJzbyBzZWxlY2lvbmFkbyBwYXJhIGVkacOnw6NvXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gcmVzb3VyY2UgcmVjdXJzbyBzZWxlY2lvbmFkb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGVkaXQocmVzb3VyY2UpIHtcbiAgICAgIHZtLmdvVG8oJ2Zvcm0nKTtcbiAgICAgIHZtLnJlc291cmNlID0gbmV3IGFuZ3VsYXIuY29weShyZXNvdXJjZSk7XG5cbiAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYWZ0ZXJFZGl0KSkgdm0uYWZ0ZXJFZGl0KCk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogU2FsdmEgb3UgYXR1YWxpemEgbyByZWN1cnNvIGNvcnJlbnRlIG5vIGZvcm11bMOhcmlvXG4gICAgICogTm8gY29tcG9ydGFtZW50byBwYWRyw6NvIHJlZGlyZWNpb25hIG8gdXN1w6FyaW8gcGFyYSB2aWV3IGRlIGxpc3RhZ2VtXG4gICAgICogZGVwb2lzIGRhIGV4ZWN1w6fDo29cbiAgICAgKlxuICAgICAqIEByZXR1cm5zXG4gICAgICovXG4gICAgZnVuY3Rpb24gc2F2ZShmb3JtKSB7XG4gICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmJlZm9yZVNhdmUpICYmIHZtLmJlZm9yZVNhdmUoKSA9PT0gZmFsc2UpIHJldHVybiBmYWxzZTtcblxuICAgICAgdm0ucmVzb3VyY2UuJHNhdmUoKS50aGVuKGZ1bmN0aW9uIChyZXNvdXJjZSkge1xuICAgICAgICB2bS5yZXNvdXJjZSA9IHJlc291cmNlO1xuXG4gICAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYWZ0ZXJTYXZlKSkgdm0uYWZ0ZXJTYXZlKHJlc291cmNlKTtcblxuICAgICAgICBpZiAodm0uZGVmYXVsdE9wdGlvbnMucmVkaXJlY3RBZnRlclNhdmUpIHtcbiAgICAgICAgICB2bS5jbGVhbkZvcm0oZm9ybSk7XG4gICAgICAgICAgdm0uc2VhcmNoKHZtLnBhZ2luYXRvci5jdXJyZW50UGFnZSk7XG4gICAgICAgICAgdm0uZ29UbygnbGlzdCcpO1xuICAgICAgICB9XG5cbiAgICAgICAgUHJUb2FzdC5zdWNjZXNzKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMuc2F2ZVN1Y2Nlc3MnKSk7XG4gICAgICB9LCBmdW5jdGlvbiAocmVzcG9uc2VEYXRhKSB7XG4gICAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0ub25TYXZlRXJyb3IpKSB2bS5vblNhdmVFcnJvcihyZXNwb25zZURhdGEpO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVtb3ZlIG8gcmVjdXJzbyBpbmZvcm1hZG8uXG4gICAgICogQW50ZXMgZXhpYmUgdW0gZGlhbG9nbyBkZSBjb25maXJtYcOnw6NvXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gcmVzb3VyY2UgcmVjdXJzbyBlc2NvbGhpZG9cbiAgICAgKi9cbiAgICBmdW5jdGlvbiByZW1vdmUocmVzb3VyY2UpIHtcbiAgICAgIHZhciBjb25maWcgPSB7XG4gICAgICAgIHRpdGxlOiAkdHJhbnNsYXRlLmluc3RhbnQoJ2RpYWxvZy5jb25maXJtVGl0bGUnKSxcbiAgICAgICAgZGVzY3JpcHRpb246ICR0cmFuc2xhdGUuaW5zdGFudCgnZGlhbG9nLmNvbmZpcm1EZXNjcmlwdGlvbicpXG4gICAgICB9O1xuXG4gICAgICBQckRpYWxvZy5jb25maXJtKGNvbmZpZykudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYmVmb3JlUmVtb3ZlKSAmJiB2bS5iZWZvcmVSZW1vdmUocmVzb3VyY2UpID09PSBmYWxzZSkgcmV0dXJuIGZhbHNlO1xuXG4gICAgICAgIHJlc291cmNlLiRkZXN0cm95KCkudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5hZnRlclJlbW92ZSkpIHZtLmFmdGVyUmVtb3ZlKHJlc291cmNlKTtcblxuICAgICAgICAgIHZtLnNlYXJjaCgpO1xuICAgICAgICAgIFByVG9hc3QuaW5mbygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnJlbW92ZVN1Y2Nlc3MnKSk7XG4gICAgICAgIH0pO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQWx0ZXJuYSBlbnRyZSBhIHZpZXcgZG8gZm9ybXVsw6FyaW8gZSBsaXN0YWdlbVxuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IHZpZXdOYW1lIG5vbWUgZGEgdmlld1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGdvVG8odmlld05hbWUpIHtcbiAgICAgIHZtLnZpZXdGb3JtID0gZmFsc2U7XG5cbiAgICAgIGlmICh2aWV3TmFtZSA9PT0gJ2Zvcm0nKSB7XG4gICAgICAgIHZtLmNsZWFuRm9ybSgpO1xuICAgICAgICB2bS52aWV3Rm9ybSA9IHRydWU7XG4gICAgICB9XG4gICAgfVxuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29udHJvbGxlcignRGFzaGJvYXJkQ29udHJvbGxlcicsIERhc2hib2FyZENvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLyoqXG4gICAqIERhc2hib2FyZCBDb250cm9sbGVyXG4gICAqXG4gICAqIFBhaW5lbCBjb20gcHJpbmNpcGFpcyBpbmRpY2Fkb3Jlc1xuICAgKlxuICAgKi9cbiAgZnVuY3Rpb24gRGFzaGJvYXJkQ29udHJvbGxlcigpIHtcbiAgICAvLyBDb250cm9sbGVyIHZhemlvIHNvbWVudGUgcGFyYSBzZXIgZGVmaW5pZG8gY29tbyBww6FnaW5hIHByaW5jaXBhbC5cbiAgICAvLyBEZXZlIHNlciBpZGVudGlmaWNhZG8gZSBhZGljaW9uYWRvIGdyw6FmaWNvc1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKlxuICAgKiBBcnF1aXZvIGRlIGNvbmZpZ3VyYcOnw6NvIGNvbSBhcyByb3RhcyBlc3BlY8OtZmljYXMgZG8gZGFzaGJvYXJkXG4gICAqXG4gICAqIEBwYXJhbSB7YW55fSAkc3RhdGVQcm92aWRlclxuICAgKiBAcGFyYW0ge2FueX0gR2xvYmFsXG4gICAqL1xuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvdXRlcygkc3RhdGVQcm92aWRlciwgR2xvYmFsKSB7XG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoR2xvYmFsLmhvbWVTdGF0ZSwge1xuICAgICAgdXJsOiAnL2Rhc2hib2FyZCcsXG4gICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL2Rhc2hib2FyZC9kYXNoYm9hcmQuaHRtbCcsXG4gICAgICBjb250cm9sbGVyOiAnRGFzaGJvYXJkQ29udHJvbGxlciBhcyBkYXNoYm9hcmRDdHJsJyxcbiAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiB0cnVlIH1cbiAgICB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25maWcocm91dGVzKTtcblxuICAvKipcbiAgICogQXJxdWl2byBkZSBjb25maWd1cmHDp8OjbyBjb20gYXMgcm90YXMgZXNwZWPDrWZpY2FzIGRvIHJlY3Vyc28gdXNlclxuICAgKlxuICAgKiBAcGFyYW0ge2FueX0gJHN0YXRlUHJvdmlkZXJcbiAgICogQHBhcmFtIHthbnl9IEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdhcHAuZGluYW1pYy1xdWVyeScsIHtcbiAgICAgIHVybDogJy9jb25zdWx0YXMtZGluYW1pY2FzJyxcbiAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvZGluYW1pYy1xdWVyeXMvZGluYW1pYy1xdWVyeXMuaHRtbCcsXG4gICAgICBjb250cm9sbGVyOiAnRGluYW1pY1F1ZXJ5c0NvbnRyb2xsZXIgYXMgZGluYW1pY1F1ZXJ5Q3RybCcsXG4gICAgICBkYXRhOiB7IG5lZWRBdXRoZW50aWNhdGlvbjogdHJ1ZSwgbmVlZFByb2ZpbGU6IFsnYWRtaW4nXSB9XG4gICAgfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmFjdG9yeSgnRGluYW1pY1F1ZXJ5U2VydmljZScsIERpbmFtaWNRdWVyeVNlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gRGluYW1pY1F1ZXJ5U2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHJldHVybiBzZXJ2aWNlRmFjdG9yeSgnZGluYW1pY1F1ZXJ5Jywge1xuICAgICAgLyoqXG4gICAgICAgKiBhw6fDo28gYWRpY2lvbmFkYSBwYXJhIHBlZ2FyIHVtYSBsaXN0YSBkZSBtb2RlbHMgZXhpc3RlbnRlcyBubyBzZXJ2aWRvclxuICAgICAgICovXG4gICAgICBhY3Rpb25zOiB7XG4gICAgICAgIGdldE1vZGVsczoge1xuICAgICAgICAgIG1ldGhvZDogJ0dFVCcsXG4gICAgICAgICAgdXJsOiAnbW9kZWxzJ1xuICAgICAgICB9XG4gICAgICB9LFxuICAgICAgaW5zdGFuY2U6IHt9XG4gICAgfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb250cm9sbGVyKCdEaW5hbWljUXVlcnlzQ29udHJvbGxlcicsIERpbmFtaWNRdWVyeXNDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIERpbmFtaWNRdWVyeXNDb250cm9sbGVyKCRjb250cm9sbGVyLCBEaW5hbWljUXVlcnlTZXJ2aWNlLCBsb2Rhc2gsIFByVG9hc3QsIC8vIE5PU09OQVJcbiAgJHRyYW5zbGF0ZSkge1xuXG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIC8vYWN0aW9uc1xuICAgIHZtLm9uQWN0aXZhdGUgPSBvbkFjdGl2YXRlO1xuICAgIHZtLmFwcGx5RmlsdGVycyA9IGFwcGx5RmlsdGVycztcbiAgICB2bS5sb2FkQXR0cmlidXRlcyA9IGxvYWRBdHRyaWJ1dGVzO1xuICAgIHZtLmxvYWRPcGVyYXRvcnMgPSBsb2FkT3BlcmF0b3JzO1xuICAgIHZtLmFkZEZpbHRlciA9IGFkZEZpbHRlcjtcbiAgICB2bS5hZnRlclNlYXJjaCA9IGFmdGVyU2VhcmNoO1xuICAgIHZtLnJ1bkZpbHRlciA9IHJ1bkZpbHRlcjtcbiAgICB2bS5lZGl0RmlsdGVyID0gZWRpdEZpbHRlcjtcbiAgICB2bS5sb2FkTW9kZWxzID0gbG9hZE1vZGVscztcbiAgICB2bS5yZW1vdmVGaWx0ZXIgPSByZW1vdmVGaWx0ZXI7XG4gICAgdm0uY2xlYXIgPSBjbGVhcjtcbiAgICB2bS5yZXN0YXJ0ID0gcmVzdGFydDtcblxuICAgIC8vaGVyZGEgbyBjb21wb3J0YW1lbnRvIGJhc2UgZG8gQ1JVRFxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHsgdm06IHZtLCBtb2RlbFNlcnZpY2U6IERpbmFtaWNRdWVyeVNlcnZpY2UsIG9wdGlvbnM6IHtcbiAgICAgICAgc2VhcmNoT25Jbml0OiBmYWxzZVxuICAgICAgfSB9KTtcblxuICAgIGZ1bmN0aW9uIG9uQWN0aXZhdGUoKSB7XG4gICAgICB2bS5yZXN0YXJ0KCk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUHJlcGFyYSBlIGFwbGljYSBvcyBmaWx0cm8gcXVlIHbDo28gc2VyIGVudmlhZG9zIHBhcmEgbyBzZXJ2acOnb1xuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IGRlZmF1bHRRdWVyeUZpbHRlcnNcbiAgICAgKiBAcmV0dXJuc1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGFwcGx5RmlsdGVycyhkZWZhdWx0UXVlcnlGaWx0ZXJzKSB7XG4gICAgICB2YXIgd2hlcmUgPSB7fTtcblxuICAgICAgLyoqXG4gICAgICAgKiBvIHNlcnZpw6dvIGVzcGVyYSB1bSBvYmpldG8gY29tOlxuICAgICAgICogIG8gbm9tZSBkZSB1bSBtb2RlbFxuICAgICAgICogIHVtYSBsaXN0YSBkZSBmaWx0cm9zXG4gICAgICAgKi9cbiAgICAgIGlmICh2bS5hZGRlZEZpbHRlcnMubGVuZ3RoID4gMCkge1xuICAgICAgICB2YXIgYWRkZWRGaWx0ZXJzID0gYW5ndWxhci5jb3B5KHZtLmFkZGVkRmlsdGVycyk7XG5cbiAgICAgICAgd2hlcmUubW9kZWwgPSB2bS5hZGRlZEZpbHRlcnNbMF0ubW9kZWwubmFtZTtcblxuICAgICAgICBmb3IgKHZhciBpbmRleCA9IDA7IGluZGV4IDwgYWRkZWRGaWx0ZXJzLmxlbmd0aDsgaW5kZXgrKykge1xuICAgICAgICAgIHZhciBmaWx0ZXIgPSBhZGRlZEZpbHRlcnNbaW5kZXhdO1xuXG4gICAgICAgICAgZmlsdGVyLm1vZGVsID0gbnVsbDtcbiAgICAgICAgICBmaWx0ZXIuYXR0cmlidXRlID0gZmlsdGVyLmF0dHJpYnV0ZS5uYW1lO1xuICAgICAgICAgIGZpbHRlci5vcGVyYXRvciA9IGZpbHRlci5vcGVyYXRvci52YWx1ZTtcbiAgICAgICAgfVxuXG4gICAgICAgIHdoZXJlLmZpbHRlcnMgPSBhbmd1bGFyLnRvSnNvbihhZGRlZEZpbHRlcnMpO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgd2hlcmUubW9kZWwgPSB2bS5xdWVyeUZpbHRlcnMubW9kZWwubmFtZTtcbiAgICAgIH1cblxuICAgICAgcmV0dXJuIGFuZ3VsYXIuZXh0ZW5kKGRlZmF1bHRRdWVyeUZpbHRlcnMsIHdoZXJlKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDYXJyZWdhIHRvZG9zIG9zIG1vZGVscyBjcmlhZG9zIG5vIHNlcnZpZG9yIGNvbSBzZXVzIGF0cmlidXRvc1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGxvYWRNb2RlbHMoKSB7XG4gICAgICAvL1BlZ2EgdG9kb3Mgb3MgbW9kZWxzIGRvIHNlcnZlciBlIG1vbnRhIHVtYSBsaXN0YSBwcm8gQ29tYm9Cb3hcbiAgICAgIERpbmFtaWNRdWVyeVNlcnZpY2UuZ2V0TW9kZWxzKCkudGhlbihmdW5jdGlvbiAoZGF0YSkge1xuICAgICAgICB2bS5tb2RlbHMgPSBkYXRhO1xuICAgICAgICB2bS5xdWVyeUZpbHRlcnMubW9kZWwgPSB2bS5tb2RlbHNbMF07XG4gICAgICAgIHZtLmxvYWRBdHRyaWJ1dGVzKCk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDYXJyZWdhIG9zIGF0dHJpYnV0b3MgZG8gbW9kZWwgZXNjb2xoaWRvXG4gICAgICovXG4gICAgZnVuY3Rpb24gbG9hZEF0dHJpYnV0ZXMoKSB7XG4gICAgICB2bS5hdHRyaWJ1dGVzID0gdm0ucXVlcnlGaWx0ZXJzLm1vZGVsLmF0dHJpYnV0ZXM7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMuYXR0cmlidXRlID0gdm0uYXR0cmlidXRlc1swXTtcblxuICAgICAgdm0ubG9hZE9wZXJhdG9ycygpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENhcnJlZ2Egb3Mgb3BlcmFkb3JlcyBlc3BlY2lmaWNvcyBwYXJhIG8gdGlwbyBkbyBhdHJpYnV0b1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGxvYWRPcGVyYXRvcnMoKSB7XG4gICAgICB2YXIgb3BlcmF0b3JzID0gW3sgdmFsdWU6ICc9JywgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudCgndmlld3MuZmllbGRzLnF1ZXJ5RGluYW1pYy5vcGVyYXRvcnMuZXF1YWxzJykgfSwgeyB2YWx1ZTogJzw+JywgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudCgndmlld3MuZmllbGRzLnF1ZXJ5RGluYW1pYy5vcGVyYXRvcnMuZGlmZXJlbnQnKSB9XTtcblxuICAgICAgaWYgKHZtLnF1ZXJ5RmlsdGVycy5hdHRyaWJ1dGUudHlwZS5pbmRleE9mKCd2YXJ5aW5nJykgIT09IC0xKSB7XG4gICAgICAgIG9wZXJhdG9ycy5wdXNoKHsgdmFsdWU6ICdoYXMnLFxuICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLmNvbnRlaW5zJykgfSk7XG4gICAgICAgIG9wZXJhdG9ycy5wdXNoKHsgdmFsdWU6ICdzdGFydFdpdGgnLFxuICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLnN0YXJ0V2l0aCcpIH0pO1xuICAgICAgICBvcGVyYXRvcnMucHVzaCh7IHZhbHVlOiAnZW5kV2l0aCcsXG4gICAgICAgICAgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudCgndmlld3MuZmllbGRzLnF1ZXJ5RGluYW1pYy5vcGVyYXRvcnMuZmluaXNoV2l0aCcpIH0pO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgb3BlcmF0b3JzLnB1c2goeyB2YWx1ZTogJz4nLFxuICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLmJpZ2dlclRoYW4nKSB9KTtcbiAgICAgICAgb3BlcmF0b3JzLnB1c2goeyB2YWx1ZTogJz49JyxcbiAgICAgICAgICBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KCd2aWV3cy5maWVsZHMucXVlcnlEaW5hbWljLm9wZXJhdG9ycy5lcXVhbHNPckJpZ2dlclRoYW4nKSB9KTtcbiAgICAgICAgb3BlcmF0b3JzLnB1c2goeyB2YWx1ZTogJzwnLFxuICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLmxlc3NUaGFuJykgfSk7XG4gICAgICAgIG9wZXJhdG9ycy5wdXNoKHsgdmFsdWU6ICc8PScsXG4gICAgICAgICAgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudCgndmlld3MuZmllbGRzLnF1ZXJ5RGluYW1pYy5vcGVyYXRvcnMuZXF1YWxzT3JMZXNzVGhhbicpIH0pO1xuICAgICAgfVxuXG4gICAgICB2bS5vcGVyYXRvcnMgPSBvcGVyYXRvcnM7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMub3BlcmF0b3IgPSB2bS5vcGVyYXRvcnNbMF07XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQWRpY2lvbmEvZWRpdGEgdW0gZmlsdHJvXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gZm9ybSBlbGVtZW50byBodG1sIGRvIGZvcm11bMOhcmlvIHBhcmEgdmFsaWRhw6fDtWVzXG4gICAgICovXG4gICAgZnVuY3Rpb24gYWRkRmlsdGVyKGZvcm0pIHtcbiAgICAgIGlmIChhbmd1bGFyLmlzVW5kZWZpbmVkKHZtLnF1ZXJ5RmlsdGVycy52YWx1ZSkgfHwgdm0ucXVlcnlGaWx0ZXJzLnZhbHVlID09PSAnJykge1xuICAgICAgICBQclRvYXN0LmVycm9yKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMudmFsaWRhdGUuZmllbGRSZXF1aXJlZCcsIHsgZmllbGQ6ICd2YWxvcicgfSkpO1xuICAgICAgICByZXR1cm47XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBpZiAodm0uaW5kZXggPCAwKSB7XG4gICAgICAgICAgdm0uYWRkZWRGaWx0ZXJzLnB1c2goYW5ndWxhci5jb3B5KHZtLnF1ZXJ5RmlsdGVycykpO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIHZtLmFkZGVkRmlsdGVyc1t2bS5pbmRleF0gPSBhbmd1bGFyLmNvcHkodm0ucXVlcnlGaWx0ZXJzKTtcbiAgICAgICAgICB2bS5pbmRleCA9IC0xO1xuICAgICAgICB9XG5cbiAgICAgICAgLy9yZWluaWNpYSBvIGZvcm11bMOhcmlvIGUgYXMgdmFsaWRhw6fDtWVzIGV4aXN0ZW50ZXNcbiAgICAgICAgdm0ucXVlcnlGaWx0ZXJzID0ge307XG4gICAgICAgIGZvcm0uJHNldFByaXN0aW5lKCk7XG4gICAgICAgIGZvcm0uJHNldFVudG91Y2hlZCgpO1xuICAgICAgfVxuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWxpemEgYSBwZXNxdWlzYSB0ZW5kbyBvcyBmaWx0cm9zIGNvbW8gcGFyw6JtZXRyb3NcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBydW5GaWx0ZXIoKSB7XG4gICAgICB2bS5zZWFyY2godm0ucGFnaW5hdG9yLmN1cnJlbnRQYWdlKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBHYXRpbGhvIGFjaW9uYWRvIGRlcG9pcyBkYSBwZXNxdWlzYSByZXNwb25zw6F2ZWwgcG9yIGlkZW50aWZpY2FyIG9zIGF0cmlidXRvc1xuICAgICAqIGNvbnRpZG9zIG5vcyBlbGVtZW50b3MgcmVzdWx0YW50ZXMgZGEgYnVzY2FcbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSBkYXRhIGRhZG9zIHJlZmVyZW50ZSBhbyByZXRvcm5vIGRhIHJlcXVpc2nDp8Ojb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGFmdGVyU2VhcmNoKGRhdGEpIHtcbiAgICAgIHZhciBrZXlzID0gZGF0YS5pdGVtcy5sZW5ndGggPiAwID8gT2JqZWN0LmtleXMoZGF0YS5pdGVtc1swXSkgOiBbXTtcblxuICAgICAgLy9yZXRpcmEgdG9kb3Mgb3MgYXRyaWJ1dG9zIHF1ZSBjb21lw6dhbSBjb20gJC5cbiAgICAgIC8vRXNzZXMgYXRyaWJ1dG9zIHPDo28gYWRpY2lvbmFkb3MgcGVsbyBzZXJ2acOnbyBlIG7Do28gZGV2ZSBhcGFyZWNlciBuYSBsaXN0YWdlbVxuICAgICAgdm0ua2V5cyA9IGxvZGFzaC5maWx0ZXIoa2V5cywgZnVuY3Rpb24gKGtleSkge1xuICAgICAgICByZXR1cm4gIWxvZGFzaC5zdGFydHNXaXRoKGtleSwgJyQnKTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENvbG9hY2Egbm8gZm9ybXVsw6FyaW8gbyBmaWx0cm8gZXNjb2xoaWRvIHBhcmEgZWRpw6fDo29cbiAgICAgKiBAcGFyYW0ge2FueX0gJGluZGV4IGluZGljZSBubyBhcnJheSBkbyBmaWx0cm8gZXNjb2xoaWRvXG4gICAgICovXG4gICAgZnVuY3Rpb24gZWRpdEZpbHRlcigkaW5kZXgpIHtcbiAgICAgIHZtLmluZGV4ID0gJGluZGV4O1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0gdm0uYWRkZWRGaWx0ZXJzWyRpbmRleF07XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVtb3ZlIG8gZmlsdHJvIGVzY29saGlkb1xuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9ICRpbmRleCBpbmRpY2Ugbm8gYXJyYXkgZG8gZmlsdHJvIGVzY29saGlkb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIHJlbW92ZUZpbHRlcigkaW5kZXgpIHtcbiAgICAgIHZtLmFkZGVkRmlsdGVycy5zcGxpY2UoJGluZGV4KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBMaW1wYSBvIGZvcm11bMOhcmlvIGNvcnJlbnRlXG4gICAgICovXG4gICAgZnVuY3Rpb24gY2xlYXIoKSB7XG4gICAgICAvL2d1YXJkYSBvIGluZGljZSBkbyByZWdpc3RybyBxdWUgZXN0w6Egc2VuZG8gZWRpdGFkb1xuICAgICAgdm0uaW5kZXggPSAtMTtcbiAgICAgIC8vdmluY3VsYWRvIGFvcyBjYW1wb3MgZG8gZm9ybXVsw6FyaW9cbiAgICAgIHZtLnF1ZXJ5RmlsdGVycyA9IHt9O1xuXG4gICAgICBpZiAodm0ubW9kZWxzKSB2bS5xdWVyeUZpbHRlcnMubW9kZWwgPSB2bS5tb2RlbHNbMF07XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVpbmljaWEgYSBjb25zdHJ1w6fDo28gZGEgcXVlcnkgbGltcGFuZG8gdHVkb1xuICAgICAqXG4gICAgICovXG4gICAgZnVuY3Rpb24gcmVzdGFydCgpIHtcbiAgICAgIC8vZ3VhcmRhIGF0cmlidXRvcyBkbyByZXN1bHRhZG8gZGEgYnVzY2EgY29ycmVudGVcbiAgICAgIHZtLmtleXMgPSBbXTtcblxuICAgICAgLy9ndWFyZGEgb3MgZmlsdHJvcyBhZGljaW9uYWRvc1xuICAgICAgdm0uYWRkZWRGaWx0ZXJzID0gW107XG4gICAgICB2bS5jbGVhcigpO1xuICAgICAgdm0ubG9hZE1vZGVscygpO1xuICAgIH1cbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZhY3RvcnkoJ2xhbmd1YWdlTG9hZGVyJywgTGFuZ3VhZ2VMb2FkZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gTGFuZ3VhZ2VMb2FkZXIoJHEsIFN1cHBvcnRTZXJ2aWNlLCAkbG9nLCAkaW5qZWN0b3IpIHtcbiAgICB2YXIgc2VydmljZSA9IHRoaXM7XG5cbiAgICBzZXJ2aWNlLnRyYW5zbGF0ZSA9IGZ1bmN0aW9uIChsb2NhbGUpIHtcbiAgICAgIHJldHVybiB7XG4gICAgICAgIGdsb2JhbDogJGluamVjdG9yLmdldChsb2NhbGUgKyAnLmkxOG4uZ2xvYmFsJyksXG4gICAgICAgIHZpZXdzOiAkaW5qZWN0b3IuZ2V0KGxvY2FsZSArICcuaTE4bi52aWV3cycpLFxuICAgICAgICBhdHRyaWJ1dGVzOiAkaW5qZWN0b3IuZ2V0KGxvY2FsZSArICcuaTE4bi5hdHRyaWJ1dGVzJyksXG4gICAgICAgIGRpYWxvZzogJGluamVjdG9yLmdldChsb2NhbGUgKyAnLmkxOG4uZGlhbG9nJyksXG4gICAgICAgIG1lc3NhZ2VzOiAkaW5qZWN0b3IuZ2V0KGxvY2FsZSArICcuaTE4bi5tZXNzYWdlcycpLFxuICAgICAgICBtb2RlbHM6ICRpbmplY3Rvci5nZXQobG9jYWxlICsgJy5pMThuLm1vZGVscycpXG4gICAgICB9O1xuICAgIH07XG5cbiAgICAvLyByZXR1cm4gbG9hZGVyRm5cbiAgICByZXR1cm4gZnVuY3Rpb24gKG9wdGlvbnMpIHtcbiAgICAgICRsb2cuaW5mbygnQ2FycmVnYW5kbyBvIGNvbnRldWRvIGRhIGxpbmd1YWdlbSAnICsgb3B0aW9ucy5rZXkpO1xuXG4gICAgICB2YXIgZGVmZXJyZWQgPSAkcS5kZWZlcigpO1xuXG4gICAgICAvL0NhcnJlZ2EgYXMgbGFuZ3MgcXVlIHByZWNpc2FtIGUgZXN0w6NvIG5vIHNlcnZpZG9yIHBhcmEgbsOjbyBwcmVjaXNhciByZXBldGlyIGFxdWlcbiAgICAgIFN1cHBvcnRTZXJ2aWNlLmxhbmdzKCkudGhlbihmdW5jdGlvbiAobGFuZ3MpIHtcbiAgICAgICAgLy9NZXJnZSBjb20gb3MgbGFuZ3MgZGVmaW5pZG9zIG5vIHNlcnZpZG9yXG4gICAgICAgIHZhciBkYXRhID0gYW5ndWxhci5tZXJnZShzZXJ2aWNlLnRyYW5zbGF0ZShvcHRpb25zLmtleSksIGxhbmdzKTtcblxuICAgICAgICByZXR1cm4gZGVmZXJyZWQucmVzb2x2ZShkYXRhKTtcbiAgICAgIH0sIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgcmV0dXJuIGRlZmVycmVkLnJlc29sdmUoc2VydmljZS50cmFuc2xhdGUob3B0aW9ucy5rZXkpKTtcbiAgICAgIH0pO1xuXG4gICAgICByZXR1cm4gZGVmZXJyZWQucHJvbWlzZTtcbiAgICB9O1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmlsdGVyKCd0QXR0cicsIHRBdHRyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIHRBdHRyKCRmaWx0ZXIpIHtcbiAgICAvKipcbiAgICAgKiBGaWx0cm8gcGFyYSB0cmFkdcOnw6NvIGRlIHVtIGF0cmlidXRvIGRlIHVtIG1vZGVsXG4gICAgICogXG4gICAgICogQHBhcmFtIHthbnl9IG5hbWUgbm9tZSBkbyBhdHJpYnV0b1xuICAgICAqIEByZXR1cm5zIG8gbm9tZSBkbyBhdHJpYnV0byB0cmFkdXppZG8gY2FzbyBlbmNvbnRyZSBzZSBuw6NvIG8gbm9tZSBwYXNzYWRvIHBvciBwYXJhbWV0cm9cbiAgICAgKi9cbiAgICByZXR1cm4gZnVuY3Rpb24gKG5hbWUpIHtcbiAgICAgIHZhciBrZXkgPSAnYXR0cmlidXRlcy4nICsgbmFtZTtcbiAgICAgIHZhciB0cmFuc2xhdGUgPSAkZmlsdGVyKCd0cmFuc2xhdGUnKShrZXkpO1xuXG4gICAgICByZXR1cm4gdHJhbnNsYXRlID09PSBrZXkgPyBuYW1lIDogdHJhbnNsYXRlO1xuICAgIH07XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5maWx0ZXIoJ3RCcmVhZGNydW1iJywgdEJyZWFkY3J1bWIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gdEJyZWFkY3J1bWIoJGZpbHRlcikge1xuICAgIC8qKlxuICAgICAqIEZpbHRybyBwYXJhIHRyYWR1w6fDo28gZG8gYnJlYWRjcnVtYiAodGl0dWxvIGRhIHRlbGEgY29tIHJhc3RyZWlvKVxuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IGlkIGNoYXZlIGNvbSBvIG5vbWUgZG8gc3RhdGUgcmVmZXJlbnRlIHRlbGFcbiAgICAgKiBAcmV0dXJucyBhIHRyYWR1w6fDo28gY2FzbyBlbmNvbnRyZSBzZSBuw6NvIG8gaWQgcGFzc2FkbyBwb3IgcGFyYW1ldHJvXG4gICAgICovXG4gICAgcmV0dXJuIGZ1bmN0aW9uIChpZCkge1xuICAgICAgLy9wZWdhIGEgc2VndW5kYSBwYXJ0ZSBkbyBub21lIGRvIHN0YXRlLCByZXRpcmFuZG8gYSBwYXJ0ZSBhYnN0cmF0YSAoYXBwLilcbiAgICAgIHZhciBrZXkgPSAndmlld3MuYnJlYWRjcnVtYnMuJyArIGlkLnNwbGl0KCcuJylbMV07XG4gICAgICB2YXIgdHJhbnNsYXRlID0gJGZpbHRlcigndHJhbnNsYXRlJykoa2V5KTtcblxuICAgICAgcmV0dXJuIHRyYW5zbGF0ZSA9PT0ga2V5ID8gaWQgOiB0cmFuc2xhdGU7XG4gICAgfTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZpbHRlcigndE1vZGVsJywgdE1vZGVsKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIHRNb2RlbCgkZmlsdGVyKSB7XG4gICAgLyoqXG4gICAgICogRmlsdHJvIHBhcmEgdHJhZHXDp8OjbyBkZSB1bSBhdHJpYnV0byBkZSB1bSBtb2RlbFxuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IG5hbWUgbm9tZSBkbyBhdHJpYnV0b1xuICAgICAqIEByZXR1cm5zIG8gbm9tZSBkbyBhdHJpYnV0byB0cmFkdXppZG8gY2FzbyBlbmNvbnRyZSBzZSBuw6NvIG8gbm9tZSBwYXNzYWRvIHBvciBwYXJhbWV0cm9cbiAgICAgKi9cbiAgICByZXR1cm4gZnVuY3Rpb24gKG5hbWUpIHtcbiAgICAgIHZhciBrZXkgPSAnbW9kZWxzLicgKyBuYW1lLnRvTG93ZXJDYXNlKCk7XG4gICAgICB2YXIgdHJhbnNsYXRlID0gJGZpbHRlcigndHJhbnNsYXRlJykoa2V5KTtcblxuICAgICAgcmV0dXJuIHRyYW5zbGF0ZSA9PT0ga2V5ID8gbmFtZSA6IHRyYW5zbGF0ZTtcbiAgICB9O1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLnJ1bihhdXRoZW50aWNhdGlvbkxpc3RlbmVyKTtcblxuICAvKipcbiAgICogTGlzdGVuIGFsbCBzdGF0ZSAocGFnZSkgY2hhbmdlcy4gRXZlcnkgdGltZSBhIHN0YXRlIGNoYW5nZSBuZWVkIHRvIHZlcmlmeSB0aGUgdXNlciBpcyBhdXRoZW50aWNhdGVkIG9yIG5vdCB0b1xuICAgKiByZWRpcmVjdCB0byBjb3JyZWN0IHBhZ2UuIFdoZW4gYSB1c2VyIGNsb3NlIHRoZSBicm93c2VyIHdpdGhvdXQgbG9nb3V0LCB3aGVuIGhpbSByZW9wZW4gdGhlIGJyb3dzZXIgdGhpcyBldmVudFxuICAgKiByZWF1dGhlbnRpY2F0ZSB0aGUgdXNlciB3aXRoIHRoZSBwZXJzaXN0ZW50IHRva2VuIG9mIHRoZSBsb2NhbCBzdG9yYWdlLlxuICAgKlxuICAgKiBXZSBkb24ndCBjaGVjayBpZiB0aGUgdG9rZW4gaXMgZXhwaXJlZCBvciBub3QgaW4gdGhlIHBhZ2UgY2hhbmdlLCBiZWNhdXNlIGlzIGdlbmVyYXRlIGFuIHVuZWNlc3Nhcnkgb3ZlcmhlYWQuXG4gICAqIElmIHRoZSB0b2tlbiBpcyBleHBpcmVkIHdoZW4gdGhlIHVzZXIgdHJ5IHRvIGNhbGwgdGhlIGZpcnN0IGFwaSB0byBnZXQgZGF0YSwgaGltIHdpbGwgYmUgbG9nb2ZmIGFuZCByZWRpcmVjdFxuICAgKiB0byBsb2dpbiBwYWdlLlxuICAgKlxuICAgKiBAcGFyYW0gJHJvb3RTY29wZVxuICAgKiBAcGFyYW0gJHN0YXRlXG4gICAqIEBwYXJhbSAkc3RhdGVQYXJhbXNcbiAgICogQHBhcmFtIEF1dGhcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gYXV0aGVudGljYXRpb25MaXN0ZW5lcigkcm9vdFNjb3BlLCAkc3RhdGUsIEdsb2JhbCwgQXV0aCwgUHJUb2FzdCwgLy8gTk9TT05BUlxuICAkdHJhbnNsYXRlKSB7XG5cbiAgICAvL29ubHkgd2hlbiBhcHBsaWNhdGlvbiBzdGFydCBjaGVjayBpZiB0aGUgZXhpc3RlbnQgdG9rZW4gc3RpbGwgdmFsaWRcbiAgICBBdXRoLnJlbW90ZVZhbGlkYXRlVG9rZW4oKS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgIC8vaWYgdGhlIHRva2VuIGlzIHZhbGlkIGNoZWNrIGlmIGV4aXN0cyB0aGUgdXNlciBiZWNhdXNlIHRoZSBicm93c2VyIGNvdWxkIGJlIGNsb3NlZFxuICAgICAgLy9hbmQgdGhlIHVzZXIgZGF0YSBpc24ndCBpbiBtZW1vcnlcbiAgICAgIGlmIChBdXRoLmN1cnJlbnRVc2VyID09PSBudWxsKSB7XG4gICAgICAgIEF1dGgudXBkYXRlQ3VycmVudFVzZXIoYW5ndWxhci5mcm9tSnNvbihsb2NhbFN0b3JhZ2UuZ2V0SXRlbSgndXNlcicpKSk7XG4gICAgICB9XG4gICAgfSk7XG5cbiAgICAvL0NoZWNrIGlmIHRoZSB0b2tlbiBzdGlsbCB2YWxpZC5cbiAgICAkcm9vdFNjb3BlLiRvbignJHN0YXRlQ2hhbmdlU3RhcnQnLCBmdW5jdGlvbiAoZXZlbnQsIHRvU3RhdGUpIHtcbiAgICAgIGlmICh0b1N0YXRlLmRhdGEubmVlZEF1dGhlbnRpY2F0aW9uIHx8IHRvU3RhdGUuZGF0YS5uZWVkUHJvZmlsZSkge1xuICAgICAgICAvL2RvbnQgdHJhaXQgdGhlIHN1Y2Nlc3MgYmxvY2sgYmVjYXVzZSBhbHJlYWR5IGRpZCBieSB0b2tlbiBpbnRlcmNlcHRvclxuICAgICAgICBBdXRoLnJlbW90ZVZhbGlkYXRlVG9rZW4oKS5jYXRjaChmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgUHJUb2FzdC53YXJuKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMubG9naW4ubG9nb3V0SW5hY3RpdmUnKSk7XG5cbiAgICAgICAgICBpZiAodG9TdGF0ZS5uYW1lICE9PSBHbG9iYWwubG9naW5TdGF0ZSkge1xuICAgICAgICAgICAgJHN0YXRlLmdvKEdsb2JhbC5sb2dpblN0YXRlKTtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICBldmVudC5wcmV2ZW50RGVmYXVsdCgpO1xuICAgICAgICB9KTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIC8vaWYgdGhlIHVzZSBpcyBhdXRoZW50aWNhdGVkIGFuZCBuZWVkIHRvIGVudGVyIGluIGxvZ2luIHBhZ2VcbiAgICAgICAgLy9oaW0gd2lsbCBiZSByZWRpcmVjdGVkIHRvIGhvbWUgcGFnZVxuICAgICAgICBpZiAodG9TdGF0ZS5uYW1lID09PSBHbG9iYWwubG9naW5TdGF0ZSAmJiBBdXRoLmF1dGhlbnRpY2F0ZWQoKSkge1xuICAgICAgICAgICRzdGF0ZS5nbyhHbG9iYWwuaG9tZVN0YXRlKTtcbiAgICAgICAgICBldmVudC5wcmV2ZW50RGVmYXVsdCgpO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykucnVuKGF1dGhvcml6YXRpb25MaXN0ZW5lcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiBhdXRob3JpemF0aW9uTGlzdGVuZXIoJHJvb3RTY29wZSwgJHN0YXRlLCBHbG9iYWwsIEF1dGgpIHtcbiAgICAvKipcbiAgICAgKiBBIGNhZGEgbXVkYW7Dp2EgZGUgZXN0YWRvIChcInDDoWdpbmFcIikgdmVyaWZpY2Egc2UgbyB1c3XDoXJpbyB0ZW0gbyBwZXJmaWxcbiAgICAgKiBuZWNlc3PDoXJpbyBwYXJhIG8gYWNlc3NvIGEgbWVzbWFcbiAgICAgKi9cbiAgICAkcm9vdFNjb3BlLiRvbignJHN0YXRlQ2hhbmdlU3RhcnQnLCBmdW5jdGlvbiAoZXZlbnQsIHRvU3RhdGUpIHtcbiAgICAgIGlmICh0b1N0YXRlLmRhdGEgJiYgdG9TdGF0ZS5kYXRhLm5lZWRBdXRoZW50aWNhdGlvbiAmJiB0b1N0YXRlLmRhdGEubmVlZFByb2ZpbGUgJiYgQXV0aC5hdXRoZW50aWNhdGVkKCkgJiYgIUF1dGguY3VycmVudFVzZXIuaGFzUHJvZmlsZSh0b1N0YXRlLmRhdGEubmVlZFByb2ZpbGUsIHRvU3RhdGUuZGF0YS5hbGxQcm9maWxlcykpIHtcblxuICAgICAgICAkc3RhdGUuZ28oR2xvYmFsLm5vdEF1dGhvcml6ZWRTdGF0ZSk7XG4gICAgICAgIGV2ZW50LnByZXZlbnREZWZhdWx0KCk7XG4gICAgICB9XG4gICAgfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29uZmlnKHNwaW5uZXJJbnRlcmNlcHRvcik7XG5cbiAgZnVuY3Rpb24gc3Bpbm5lckludGVyY2VwdG9yKCRodHRwUHJvdmlkZXIsICRwcm92aWRlKSB7XG4gICAgLyoqXG4gICAgICogRXN0ZSBpbnRlcmNlcHRvciDDqSByZXNwb25zw6F2ZWwgcG9yIG1vc3RyYXIgZSBlc2NvbmRlciBvXG4gICAgICogY29tcG9uZW50ZSBQclNwaW5uZXIgc2VtcHJlIHF1ZSB1bWEgcmVxdWlzacOnw6NvIGFqYXhcbiAgICAgKiBpbmljaWFyIGUgZmluYWxpemFyLlxuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9ICRxXG4gICAgICogQHBhcmFtIHthbnl9ICRpbmplY3RvclxuICAgICAqIEByZXR1cm5zXG4gICAgICovXG4gICAgZnVuY3Rpb24gc2hvd0hpZGVTcGlubmVyKCRxLCAkaW5qZWN0b3IpIHtcbiAgICAgIHJldHVybiB7XG4gICAgICAgIHJlcXVlc3Q6IGZ1bmN0aW9uIHJlcXVlc3QoY29uZmlnKSB7XG4gICAgICAgICAgJGluamVjdG9yLmdldCgnUHJTcGlubmVyJykuc2hvdygpO1xuXG4gICAgICAgICAgcmV0dXJuIGNvbmZpZztcbiAgICAgICAgfSxcblxuICAgICAgICByZXNwb25zZTogZnVuY3Rpb24gcmVzcG9uc2UoX3Jlc3BvbnNlKSB7XG4gICAgICAgICAgJGluamVjdG9yLmdldCgnUHJTcGlubmVyJykuaGlkZSgpO1xuXG4gICAgICAgICAgcmV0dXJuIF9yZXNwb25zZTtcbiAgICAgICAgfSxcblxuICAgICAgICByZXNwb25zZUVycm9yOiBmdW5jdGlvbiByZXNwb25zZUVycm9yKHJlamVjdGlvbikge1xuICAgICAgICAgICRpbmplY3Rvci5nZXQoJ1ByU3Bpbm5lcicpLmhpZGUoKTtcblxuICAgICAgICAgIHJldHVybiAkcS5yZWplY3QocmVqZWN0aW9uKTtcbiAgICAgICAgfVxuICAgICAgfTtcbiAgICB9XG5cbiAgICAvLyBEZWZpbmUgdW1hIGZhY3RvcnkgcGFyYSBvICRodHRwSW50ZXJjZXB0b3JcbiAgICAkcHJvdmlkZS5mYWN0b3J5KCdzaG93SGlkZVNwaW5uZXInLCBzaG93SGlkZVNwaW5uZXIpO1xuXG4gICAgLy8gQWRpY2lvbmEgYSBmYWN0b3J5IG5vIGFycmF5IGRlIGludGVyY2VwdG9ycyBkbyAkaHR0cFxuICAgICRodHRwUHJvdmlkZXIuaW50ZXJjZXB0b3JzLnB1c2goJ3Nob3dIaWRlU3Bpbm5lcicpO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4vKmVzbGludCBhbmd1bGFyL21vZHVsZS1nZXR0ZXI6IDAqL1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbmZpZyh0b2tlbkludGVyY2VwdG9yKTtcblxuICAvKipcbiAgICogSW50ZXJjZXB0IGFsbCByZXNwb25zZSAoc3VjY2VzcyBvciBlcnJvcikgdG8gdmVyaWZ5IHRoZSByZXR1cm5lZCB0b2tlblxuICAgKlxuICAgKiBAcGFyYW0gJGh0dHBQcm92aWRlclxuICAgKiBAcGFyYW0gJHByb3ZpZGVcbiAgICogQHBhcmFtIEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiB0b2tlbkludGVyY2VwdG9yKCRodHRwUHJvdmlkZXIsICRwcm92aWRlLCBHbG9iYWwpIHtcblxuICAgIGZ1bmN0aW9uIHJlZGlyZWN0V2hlblNlcnZlckxvZ2dlZE91dCgkcSwgJGluamVjdG9yKSB7XG4gICAgICByZXR1cm4ge1xuICAgICAgICByZXF1ZXN0OiBmdW5jdGlvbiByZXF1ZXN0KGNvbmZpZykge1xuICAgICAgICAgIHZhciB0b2tlbiA9ICRpbmplY3Rvci5nZXQoJ0F1dGgnKS5nZXRUb2tlbigpO1xuXG4gICAgICAgICAgaWYgKHRva2VuKSB7XG4gICAgICAgICAgICBjb25maWcuaGVhZGVyc1snQXV0aG9yaXphdGlvbiddID0gJ0JlYXJlciAnICsgdG9rZW47XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgcmV0dXJuIGNvbmZpZztcbiAgICAgICAgfSxcbiAgICAgICAgcmVzcG9uc2U6IGZ1bmN0aW9uIHJlc3BvbnNlKF9yZXNwb25zZSkge1xuICAgICAgICAgIC8vIGdldCBhIG5ldyByZWZyZXNoIHRva2VuIHRvIHVzZSBpbiB0aGUgbmV4dCByZXF1ZXN0XG4gICAgICAgICAgdmFyIHRva2VuID0gX3Jlc3BvbnNlLmhlYWRlcnMoJ0F1dGhvcml6YXRpb24nKTtcblxuICAgICAgICAgIGlmICh0b2tlbikge1xuICAgICAgICAgICAgJGluamVjdG9yLmdldCgnQXV0aCcpLnNldFRva2VuKHRva2VuLnNwbGl0KCcgJylbMV0pO1xuICAgICAgICAgIH1cbiAgICAgICAgICByZXR1cm4gX3Jlc3BvbnNlO1xuICAgICAgICB9LFxuICAgICAgICByZXNwb25zZUVycm9yOiBmdW5jdGlvbiByZXNwb25zZUVycm9yKHJlamVjdGlvbikge1xuICAgICAgICAgIC8vIEluc3RlYWQgb2YgY2hlY2tpbmcgZm9yIGEgc3RhdHVzIGNvZGUgb2YgNDAwIHdoaWNoIG1pZ2h0IGJlIHVzZWRcbiAgICAgICAgICAvLyBmb3Igb3RoZXIgcmVhc29ucyBpbiBMYXJhdmVsLCB3ZSBjaGVjayBmb3IgdGhlIHNwZWNpZmljIHJlamVjdGlvblxuICAgICAgICAgIC8vIHJlYXNvbnMgdG8gdGVsbCB1cyBpZiB3ZSBuZWVkIHRvIHJlZGlyZWN0IHRvIHRoZSBsb2dpbiBzdGF0ZVxuICAgICAgICAgIHZhciByZWplY3Rpb25SZWFzb25zID0gWyd0b2tlbl9ub3RfcHJvdmlkZWQnLCAndG9rZW5fZXhwaXJlZCcsICd0b2tlbl9hYnNlbnQnLCAndG9rZW5faW52YWxpZCddO1xuXG4gICAgICAgICAgdmFyIHRva2VuRXJyb3IgPSBmYWxzZTtcblxuICAgICAgICAgIGFuZ3VsYXIuZm9yRWFjaChyZWplY3Rpb25SZWFzb25zLCBmdW5jdGlvbiAodmFsdWUpIHtcbiAgICAgICAgICAgIGlmIChyZWplY3Rpb24uZGF0YSAmJiByZWplY3Rpb24uZGF0YS5lcnJvciA9PT0gdmFsdWUpIHtcbiAgICAgICAgICAgICAgdG9rZW5FcnJvciA9IHRydWU7XG5cbiAgICAgICAgICAgICAgJGluamVjdG9yLmdldCgnQXV0aCcpLmxvZ291dCgpLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgIHZhciAkc3RhdGUgPSAkaW5qZWN0b3IuZ2V0KCckc3RhdGUnKTtcblxuICAgICAgICAgICAgICAgIC8vIGluIGNhc2UgbXVsdGlwbGUgYWpheCByZXF1ZXN0IGZhaWwgYXQgc2FtZSB0aW1lIGJlY2F1c2UgdG9rZW4gcHJvYmxlbXMsXG4gICAgICAgICAgICAgICAgLy8gb25seSB0aGUgZmlyc3Qgd2lsbCByZWRpcmVjdFxuICAgICAgICAgICAgICAgIGlmICghJHN0YXRlLmlzKEdsb2JhbC5sb2dpblN0YXRlKSkge1xuICAgICAgICAgICAgICAgICAgJHN0YXRlLmdvKEdsb2JhbC5sb2dpblN0YXRlKTtcblxuICAgICAgICAgICAgICAgICAgLy9jbG9zZSBhbnkgZGlhbG9nIHRoYXQgaXMgb3BlbmVkXG4gICAgICAgICAgICAgICAgICAkaW5qZWN0b3IuZ2V0KCdQckRpYWxvZycpLmNsb3NlKCk7XG5cbiAgICAgICAgICAgICAgICAgIGV2ZW50LnByZXZlbnREZWZhdWx0KCk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9KTtcblxuICAgICAgICAgIC8vZGVmaW5lIGRhdGEgdG8gZW1wdHkgYmVjYXVzZSBhbHJlYWR5IHNob3cgUHJUb2FzdCB0b2tlbiBtZXNzYWdlXG4gICAgICAgICAgaWYgKHRva2VuRXJyb3IpIHtcbiAgICAgICAgICAgIHJlamVjdGlvbi5kYXRhID0ge307XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbihyZWplY3Rpb24uaGVhZGVycykpIHtcbiAgICAgICAgICAgIC8vIG1hbnkgc2VydmVycyBlcnJvcnMgKGJ1c2luZXNzKSBhcmUgaW50ZXJjZXB0IGhlcmUgYnV0IGdlbmVyYXRlZCBhIG5ldyByZWZyZXNoIHRva2VuXG4gICAgICAgICAgICAvLyBhbmQgbmVlZCB1cGRhdGUgY3VycmVudCB0b2tlblxuICAgICAgICAgICAgdmFyIHRva2VuID0gcmVqZWN0aW9uLmhlYWRlcnMoJ0F1dGhvcml6YXRpb24nKTtcblxuICAgICAgICAgICAgaWYgKHRva2VuKSB7XG4gICAgICAgICAgICAgICRpbmplY3Rvci5nZXQoJ0F1dGgnKS5zZXRUb2tlbih0b2tlbi5zcGxpdCgnICcpWzFdKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9XG5cbiAgICAgICAgICByZXR1cm4gJHEucmVqZWN0KHJlamVjdGlvbik7XG4gICAgICAgIH1cbiAgICAgIH07XG4gICAgfVxuXG4gICAgLy8gU2V0dXAgZm9yIHRoZSAkaHR0cEludGVyY2VwdG9yXG4gICAgJHByb3ZpZGUuZmFjdG9yeSgncmVkaXJlY3RXaGVuU2VydmVyTG9nZ2VkT3V0JywgcmVkaXJlY3RXaGVuU2VydmVyTG9nZ2VkT3V0KTtcblxuICAgIC8vIFB1c2ggdGhlIG5ldyBmYWN0b3J5IG9udG8gdGhlICRodHRwIGludGVyY2VwdG9yIGFycmF5XG4gICAgJGh0dHBQcm92aWRlci5pbnRlcmNlcHRvcnMucHVzaCgncmVkaXJlY3RXaGVuU2VydmVyTG9nZ2VkT3V0Jyk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29uZmlnKHZhbGlkYXRpb25JbnRlcmNlcHRvcik7XG5cbiAgZnVuY3Rpb24gdmFsaWRhdGlvbkludGVyY2VwdG9yKCRodHRwUHJvdmlkZXIsICRwcm92aWRlKSB7XG4gICAgLyoqXG4gICAgICogRXN0ZSBpbnRlcmNlcHRvciDDqSByZXNwb25zw6F2ZWwgcG9yIG1vc3RyYXIgYXNcbiAgICAgKiBtZW5zYWdlbnMgZGUgZXJybyByZWZlcmVudGUgYXMgdmFsaWRhw6fDtWVzIGRvIGJhY2stZW5kXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gJHFcbiAgICAgKiBAcGFyYW0ge2FueX0gJGluamVjdG9yXG4gICAgICogQHJldHVybnNcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBzaG93RXJyb3JWYWxpZGF0aW9uKCRxLCAkaW5qZWN0b3IpIHtcbiAgICAgIHJldHVybiB7XG4gICAgICAgIHJlc3BvbnNlRXJyb3I6IGZ1bmN0aW9uIHJlc3BvbnNlRXJyb3IocmVqZWN0aW9uKSB7XG4gICAgICAgICAgdmFyIFByVG9hc3QgPSAkaW5qZWN0b3IuZ2V0KCdQclRvYXN0Jyk7XG4gICAgICAgICAgdmFyICR0cmFuc2xhdGUgPSAkaW5qZWN0b3IuZ2V0KCckdHJhbnNsYXRlJyk7XG5cbiAgICAgICAgICBpZiAocmVqZWN0aW9uLmNvbmZpZy5kYXRhICYmICFyZWplY3Rpb24uY29uZmlnLmRhdGEuc2tpcFZhbGlkYXRpb24pIHtcbiAgICAgICAgICAgIGlmIChyZWplY3Rpb24uZGF0YSAmJiByZWplY3Rpb24uZGF0YS5lcnJvcikge1xuXG4gICAgICAgICAgICAgIC8vdmVyaWZpY2Egc2Ugb2NvcnJldSBhbGd1bSBlcnJvIHJlZmVyZW50ZSBhbyB0b2tlblxuICAgICAgICAgICAgICBpZiAocmVqZWN0aW9uLmRhdGEuZXJyb3Iuc3RhcnRzV2l0aCgndG9rZW5fJykpIHtcbiAgICAgICAgICAgICAgICBQclRvYXN0Lndhcm4oJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5sb2dpbi5sb2dvdXRJbmFjdGl2ZScpKTtcbiAgICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICBQclRvYXN0LmVycm9yKCR0cmFuc2xhdGUuaW5zdGFudChyZWplY3Rpb24uZGF0YS5lcnJvcikpO1xuICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICBQclRvYXN0LmVycm9yVmFsaWRhdGlvbihyZWplY3Rpb24uZGF0YSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgcmV0dXJuICRxLnJlamVjdChyZWplY3Rpb24pO1xuICAgICAgICB9XG4gICAgICB9O1xuICAgIH1cblxuICAgIC8vIERlZmluZSB1bWEgZmFjdG9yeSBwYXJhIG8gJGh0dHBJbnRlcmNlcHRvclxuICAgICRwcm92aWRlLmZhY3RvcnkoJ3Nob3dFcnJvclZhbGlkYXRpb24nLCBzaG93RXJyb3JWYWxpZGF0aW9uKTtcblxuICAgIC8vIEFkaWNpb25hIGEgZmFjdG9yeSBubyBhcnJheSBkZSBpbnRlcmNlcHRvcnMgZG8gJGh0dHBcbiAgICAkaHR0cFByb3ZpZGVyLmludGVyY2VwdG9ycy5wdXNoKCdzaG93RXJyb3JWYWxpZGF0aW9uJyk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbi8qZXNsaW50LWVudiBlczYqL1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29udHJvbGxlcignTWVudUNvbnRyb2xsZXInLCBNZW51Q29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiBNZW51Q29udHJvbGxlcigkbWRTaWRlbmF2LCAkc3RhdGUsICRtZENvbG9ycykge1xuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICAvL0Jsb2NvIGRlIGRlY2xhcmFjb2VzIGRlIGZ1bmNvZXNcbiAgICB2bS5vcGVuID0gb3BlbjtcbiAgICB2bS5vcGVuTWVudU9yUmVkaXJlY3RUb1N0YXRlID0gb3Blbk1lbnVPclJlZGlyZWN0VG9TdGF0ZTtcblxuICAgIGFjdGl2YXRlKCk7XG5cbiAgICBmdW5jdGlvbiBhY3RpdmF0ZSgpIHtcbiAgICAgIHZhciBtZW51UHJlZml4ID0gJ3ZpZXdzLmxheW91dC5tZW51Lic7XG5cbiAgICAgIC8vIEFycmF5IGNvbnRlbmRvIG9zIGl0ZW5zIHF1ZSBzw6NvIG1vc3RyYWRvcyBubyBtZW51IGxhdGVyYWxcbiAgICAgIHZtLml0ZW5zTWVudSA9IFt7IHN0YXRlOiAnYXBwLmRhc2hib2FyZCcsIHRpdGxlOiBtZW51UHJlZml4ICsgJ2Rhc2hib2FyZCcsIGljb246ICdkYXNoYm9hcmQnLCBzdWJJdGVuczogW10gfSwge1xuICAgICAgICBzdGF0ZTogJyMnLCB0aXRsZTogbWVudVByZWZpeCArICdleGFtcGxlcycsIGljb246ICd2aWV3X2Nhcm91c2VsJywgcHJvZmlsZXM6IFsnYWRtaW4nXSxcbiAgICAgICAgc3ViSXRlbnM6IFt7IHN0YXRlOiAnYXBwLnByb2plY3QnLCB0aXRsZTogbWVudVByZWZpeCArICdwcm9qZWN0JywgaWNvbjogJ3N0YXInIH1dXG4gICAgICB9LFxuICAgICAgLy8gQ29sb3F1ZSBzZXVzIGl0ZW5zIGRlIG1lbnUgYSBwYXJ0aXIgZGVzdGUgcG9udG9cbiAgICAgIHtcbiAgICAgICAgc3RhdGU6ICcjJywgdGl0bGU6IG1lbnVQcmVmaXggKyAnYWRtaW4nLCBpY29uOiAnc2V0dGluZ3NfYXBwbGljYXRpb25zJywgcHJvZmlsZXM6IFsnYWRtaW4nXSxcbiAgICAgICAgc3ViSXRlbnM6IFt7IHN0YXRlOiAnYXBwLnVzZXInLCB0aXRsZTogbWVudVByZWZpeCArICd1c2VyJywgaWNvbjogJ3Blb3BsZScgfSwgeyBzdGF0ZTogJ2FwcC5tYWlsJywgdGl0bGU6IG1lbnVQcmVmaXggKyAnbWFpbCcsIGljb246ICdtYWlsJyB9LCB7IHN0YXRlOiAnYXBwLmF1ZGl0JywgdGl0bGU6IG1lbnVQcmVmaXggKyAnYXVkaXQnLCBpY29uOiAnc3RvcmFnZScgfSwgeyBzdGF0ZTogJ2FwcC5kaW5hbWljLXF1ZXJ5JywgdGl0bGU6IG1lbnVQcmVmaXggKyAnZGluYW1pY1F1ZXJ5JywgaWNvbjogJ2xvY2F0aW9uX3NlYXJjaGluZycgfV1cbiAgICAgIH1dO1xuXG4gICAgICAvKipcbiAgICAgICAqIE9iamV0byBxdWUgcHJlZW5jaGUgbyBuZy1zdHlsZSBkbyBtZW51IGxhdGVyYWwgdHJvY2FuZG8gYXMgY29yZXNcbiAgICAgICAqL1xuICAgICAgdm0uc2lkZW5hdlN0eWxlID0ge1xuICAgICAgICB0b3A6IHtcbiAgICAgICAgICAnYm9yZGVyLWJvdHRvbSc6ICcxcHggc29saWQgJyArIGdldENvbG9yKCdwcmltYXJ5JyksXG4gICAgICAgICAgJ2JhY2tncm91bmQtaW1hZ2UnOiAnLXdlYmtpdC1saW5lYXItZ3JhZGllbnQodG9wLCAnICsgZ2V0Q29sb3IoJ3ByaW1hcnktNTAwJykgKyAnLCAnICsgZ2V0Q29sb3IoJ3ByaW1hcnktODAwJykgKyAnKSdcbiAgICAgICAgfSxcbiAgICAgICAgY29udGVudDoge1xuICAgICAgICAgICdiYWNrZ3JvdW5kLWNvbG9yJzogZ2V0Q29sb3IoJ3ByaW1hcnktODAwJylcbiAgICAgICAgfSxcbiAgICAgICAgdGV4dENvbG9yOiB7XG4gICAgICAgICAgY29sb3I6ICcjRkZGJ1xuICAgICAgICB9LFxuICAgICAgICBsaW5lQm90dG9tOiB7XG4gICAgICAgICAgJ2JvcmRlci1ib3R0b20nOiAnMXB4IHNvbGlkICcgKyBnZXRDb2xvcigncHJpbWFyeS00MDAnKVxuICAgICAgICB9XG4gICAgICB9O1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIG9wZW4oKSB7XG4gICAgICAkbWRTaWRlbmF2KCdsZWZ0JykudG9nZ2xlKCk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogTcOpdG9kbyBxdWUgZXhpYmUgbyBzdWIgbWVudSBkb3MgaXRlbnMgZG8gbWVudSBsYXRlcmFsIGNhc28gdGVuaGEgc3ViIGl0ZW5zXG4gICAgICogY2FzbyBjb250csOhcmlvIHJlZGlyZWNpb25hIHBhcmEgbyBzdGF0ZSBwYXNzYWRvIGNvbW8gcGFyw6JtZXRyb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIG9wZW5NZW51T3JSZWRpcmVjdFRvU3RhdGUoJG1kTWVudSwgZXYsIGl0ZW0pIHtcbiAgICAgIGlmIChhbmd1bGFyLmlzRGVmaW5lZChpdGVtLnN1Ykl0ZW5zKSAmJiBpdGVtLnN1Ykl0ZW5zLmxlbmd0aCA+IDApIHtcbiAgICAgICAgJG1kTWVudS5vcGVuKGV2KTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgICRzdGF0ZS5nbyhpdGVtLnN0YXRlKTtcbiAgICAgICAgJG1kU2lkZW5hdignbGVmdCcpLmNsb3NlKCk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gZ2V0Q29sb3IoY29sb3JQYWxldHRlcykge1xuICAgICAgcmV0dXJuICRtZENvbG9ycy5nZXRUaGVtZUNvbG9yKGNvbG9yUGFsZXR0ZXMpO1xuICAgIH1cbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbnRyb2xsZXIoJ01haWxzQ29udHJvbGxlcicsIE1haWxzQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBNYWlsc0NvbnRyb2xsZXIoTWFpbHNTZXJ2aWNlLCBVc2Vyc1NlcnZpY2UsIFByRGlhbG9nLCBQclRvYXN0LCAvLyBOT1NPTkFSXG4gICRxLCBsb2Rhc2gsICR0cmFuc2xhdGUsIEdsb2JhbCkge1xuXG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIHZtLmZpbHRlclNlbGVjdGVkID0gZmFsc2U7XG4gICAgdm0ub3B0aW9ucyA9IHtcbiAgICAgIHNraW46ICdrYW1hJyxcbiAgICAgIGxhbmd1YWdlOiAncHQtYnInLFxuICAgICAgYWxsb3dlZENvbnRlbnQ6IHRydWUsXG4gICAgICBlbnRpdGllczogdHJ1ZSxcbiAgICAgIGhlaWdodDogMzAwLFxuICAgICAgZXh0cmFQbHVnaW5zOiAnZGlhbG9nLGZpbmQsY29sb3JkaWFsb2cscHJldmlldyxmb3JtcyxpZnJhbWUsZmxhc2gnXG4gICAgfTtcblxuICAgIHZtLmxvYWRVc2VycyA9IGxvYWRVc2VycztcbiAgICB2bS5vcGVuVXNlckRpYWxvZyA9IG9wZW5Vc2VyRGlhbG9nO1xuICAgIHZtLmFkZFVzZXJNYWlsID0gYWRkVXNlck1haWw7XG4gICAgdm0uY2xlYW5Gb3JtID0gY2xlYW5Gb3JtO1xuICAgIHZtLnNlbmQgPSBzZW5kO1xuXG4gICAgYWN0aXZhdGUoKTtcblxuICAgIGZ1bmN0aW9uIGFjdGl2YXRlKCkge1xuICAgICAgdm0uY2xlYW5Gb3JtKCk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhbGl6YSBhIGJ1c2NhIHBlbG8gdXN1w6FyaW8gcmVtb3RhbWVudGVcbiAgICAgKlxuICAgICAqIEBwYXJhbXMge3N0cmluZ30gLSBSZWNlYmUgbyB2YWxvciBwYXJhIHNlciBwZXNxdWlzYWRvXG4gICAgICogQHJldHVybiB7cHJvbWlzc2V9IC0gUmV0b3JuYSB1bWEgcHJvbWlzc2UgcXVlIG8gY29tcG9uZXRlIHJlc29sdmVcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBsb2FkVXNlcnMoY3JpdGVyaWEpIHtcbiAgICAgIHZhciBkZWZlcnJlZCA9ICRxLmRlZmVyKCk7XG5cbiAgICAgIFVzZXJzU2VydmljZS5xdWVyeSh7XG4gICAgICAgIG5hbWVPckVtYWlsOiBjcml0ZXJpYSxcbiAgICAgICAgbm90VXNlcnM6IGxvZGFzaC5tYXAodm0ubWFpbC51c2VycywgbG9kYXNoLnByb3BlcnR5KCdpZCcpKS50b1N0cmluZygpLFxuICAgICAgICBsaW1pdDogNVxuICAgICAgfSkudGhlbihmdW5jdGlvbiAoZGF0YSkge1xuXG4gICAgICAgIC8vIHZlcmlmaWNhIHNlIG5hIGxpc3RhIGRlIHVzdWFyaW9zIGrDoSBleGlzdGUgbyB1c3XDoXJpbyBjb20gbyBlbWFpbCBwZXNxdWlzYWRvXG4gICAgICAgIGRhdGEgPSBsb2Rhc2guZmlsdGVyKGRhdGEsIGZ1bmN0aW9uICh1c2VyKSB7XG4gICAgICAgICAgcmV0dXJuICFsb2Rhc2guZmluZCh2bS5tYWlsLnVzZXJzLCB7IGVtYWlsOiB1c2VyLmVtYWlsIH0pO1xuICAgICAgICB9KTtcblxuICAgICAgICBkZWZlcnJlZC5yZXNvbHZlKGRhdGEpO1xuICAgICAgfSk7XG5cbiAgICAgIHJldHVybiBkZWZlcnJlZC5wcm9taXNlO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEFicmUgbyBkaWFsb2cgcGFyYSBwZXNxdWlzYSBkZSB1c3XDoXJpb3NcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBvcGVuVXNlckRpYWxvZygpIHtcbiAgICAgIHZhciBjb25maWcgPSB7XG4gICAgICAgIGxvY2Fsczoge1xuICAgICAgICAgIG9uSW5pdDogdHJ1ZSxcbiAgICAgICAgICB1c2VyRGlhbG9nSW5wdXQ6IHtcbiAgICAgICAgICAgIHRyYW5zZmVyVXNlckZuOiB2bS5hZGRVc2VyTWFpbFxuICAgICAgICAgIH1cbiAgICAgICAgfSxcbiAgICAgICAgY29udHJvbGxlcjogJ1VzZXJzRGlhbG9nQ29udHJvbGxlcicsXG4gICAgICAgIGNvbnRyb2xsZXJBczogJ2N0cmwnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL3VzZXJzL2RpYWxvZy91c2Vycy1kaWFsb2cuaHRtbCcsXG4gICAgICAgIGhhc0JhY2tkcm9wOiB0cnVlXG4gICAgICB9O1xuXG4gICAgICBQckRpYWxvZy5jdXN0b20oY29uZmlnKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBBZGljaW9uYSBvIHVzdcOhcmlvIHNlbGVjaW9uYWRvIG5hIGxpc3RhIHBhcmEgcXVlIHNlamEgZW52aWFkbyBvIGVtYWlsXG4gICAgICovXG4gICAgZnVuY3Rpb24gYWRkVXNlck1haWwodXNlcikge1xuICAgICAgdmFyIHVzZXJzID0gbG9kYXNoLmZpbmQodm0ubWFpbC51c2VycywgeyBlbWFpbDogdXNlci5lbWFpbCB9KTtcblxuICAgICAgaWYgKHZtLm1haWwudXNlcnMubGVuZ3RoID4gMCAmJiBhbmd1bGFyLmlzRGVmaW5lZCh1c2VycykpIHtcbiAgICAgICAgUHJUb2FzdC53YXJuKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMudXNlci51c2VyRXhpc3RzJykpO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgdm0ubWFpbC51c2Vycy5wdXNoKHsgbmFtZTogdXNlci5uYW1lLCBlbWFpbDogdXNlci5lbWFpbCB9KTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFsaXphIG8gZW52aW8gZG8gZW1haWwgcGFyYSBhIGxpc3RhIGRlIHVzdcOhcmlvcyBzZWxlY2lvbmFkb3NcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBzZW5kKCkge1xuXG4gICAgICB2bS5tYWlsLiRzYXZlKCkudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgaWYgKHJlc3BvbnNlLmxlbmd0aCA+IDApIHtcbiAgICAgICAgICB2YXIgbXNnID0gJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5tYWlsLm1haWxFcnJvcnMnKTtcblxuICAgICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgcmVzcG9uc2UubGVuZ3RoOyBpKyspIHtcbiAgICAgICAgICAgIG1zZyArPSByZXNwb25zZSArICdcXG4nO1xuICAgICAgICAgIH1cbiAgICAgICAgICBQclRvYXN0LmVycm9yKG1zZyk7XG4gICAgICAgICAgdm0uY2xlYW5Gb3JtKCk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgUHJUb2FzdC5zdWNjZXNzKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMubWFpbC5zZW5kTWFpbFN1Y2Nlc3MnKSk7XG4gICAgICAgICAgdm0uY2xlYW5Gb3JtKCk7XG4gICAgICAgIH1cbiAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIExpbXBhIG8gZm9ybXVsw6FyaW8gZGUgZW1haWxcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBjbGVhbkZvcm0oKSB7XG4gICAgICB2bS5tYWlsID0gbmV3IE1haWxzU2VydmljZSgpO1xuICAgICAgdm0ubWFpbC51c2VycyA9IFtdO1xuICAgIH1cbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25maWcocm91dGVzKTtcblxuICAvKipcbiAgICogQXJxdWl2byBkZSBjb25maWd1cmHDp8OjbyBjb20gYXMgcm90YXMgZXNwZWPDrWZpY2FzIGRvIHJlY3Vyc28gZW0gcXVlc3TDo29cbiAgICpcbiAgICogQHBhcmFtIHthbnl9ICRzdGF0ZVByb3ZpZGVyXG4gICAqIEBwYXJhbSB7YW55fSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnYXBwLm1haWwnLCB7XG4gICAgICB1cmw6ICcvZW1haWwnLFxuICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9tYWlsL21haWxzLXNlbmQuaHRtbCcsXG4gICAgICBjb250cm9sbGVyOiAnTWFpbHNDb250cm9sbGVyIGFzIG1haWxzQ3RybCcsXG4gICAgICBkYXRhOiB7IG5lZWRBdXRoZW50aWNhdGlvbjogdHJ1ZSwgbmVlZFByb2ZpbGU6IFsnYWRtaW4nXSB9XG4gICAgfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmFjdG9yeSgnTWFpbHNTZXJ2aWNlJywgTWFpbHNTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIE1haWxzU2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHJldHVybiBzZXJ2aWNlRmFjdG9yeSgnbWFpbHMnLCB7fSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5maWx0ZXIoJ3JvbGVzU3RyJywgcm9sZXNTdHIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm9sZXNTdHIobG9kYXNoKSB7XG4gICAgLyoqXG4gICAgICogQHBhcmFtIHthcnJheX0gcm9sZXMgbGlzdGEgZGUgcGVyZmlzXG4gICAgICogQHJldHVybiB7c3RyaW5nfSBwZXJmaXMgc2VwYXJhZG9zIHBvciAnLCAnICBcbiAgICAgKi9cbiAgICByZXR1cm4gZnVuY3Rpb24gKHJvbGVzKSB7XG4gICAgICByZXR1cm4gbG9kYXNoLm1hcChyb2xlcywgJ3NsdWcnKS5qb2luKCcsICcpO1xuICAgIH07XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmFjdG9yeSgnUm9sZXNTZXJ2aWNlJywgUm9sZXNTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIFJvbGVzU2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHJldHVybiBzZXJ2aWNlRmFjdG9yeSgncm9sZXMnKTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5mYWN0b3J5KCdTdXBwb3J0U2VydmljZScsIFN1cHBvcnRTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIFN1cHBvcnRTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCdzdXBwb3J0Jywge1xuICAgICAgYWN0aW9uczoge1xuICAgICAgICAvKipcbiAgICAgICAgICogUGVnYSBhcyB0cmFkdcOnw7VlcyBxdWUgZXN0w6NvIG5vIHNlcnZpZG9yXG4gICAgICAgICAqXG4gICAgICAgICAqIEByZXR1cm5zIHtwcm9taXNlfSBVbWEgcHJvbWlzZSBjb20gbyByZXN1bHRhZG8gZG8gY2hhbWFkYSBubyBiYWNrZW5kXG4gICAgICAgICAqL1xuICAgICAgICBsYW5nczoge1xuICAgICAgICAgIG1ldGhvZDogJ0dFVCcsXG4gICAgICAgICAgdXJsOiAnbGFuZ3MnLFxuICAgICAgICAgIHdyYXA6IGZhbHNlLFxuICAgICAgICAgIGNhY2hlOiB0cnVlXG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbnRyb2xsZXIoJ1Byb2ZpbGVDb250cm9sbGVyJywgUHJvZmlsZUNvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gUHJvZmlsZUNvbnRyb2xsZXIoVXNlcnNTZXJ2aWNlLCBBdXRoLCBQclRvYXN0LCAkdHJhbnNsYXRlKSB7XG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIHZtLnVwZGF0ZSA9IHVwZGF0ZTtcblxuICAgIGFjdGl2YXRlKCk7XG5cbiAgICBmdW5jdGlvbiBhY3RpdmF0ZSgpIHtcbiAgICAgIHZtLnVzZXIgPSBhbmd1bGFyLmNvcHkoQXV0aC5jdXJyZW50VXNlcik7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gdXBkYXRlKCkge1xuICAgICAgVXNlcnNTZXJ2aWNlLnVwZGF0ZVByb2ZpbGUodm0udXNlcikudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgLy9hdHVhbGl6YSBvIHVzdcOhcmlvIGNvcnJlbnRlIGNvbSBhcyBub3ZhcyBpbmZvcm1hw6fDtWVzXG4gICAgICAgIEF1dGgudXBkYXRlQ3VycmVudFVzZXIocmVzcG9uc2UpO1xuICAgICAgICBQclRvYXN0LnN1Y2Nlc3MoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5zYXZlU3VjY2VzcycpKTtcbiAgICAgIH0pO1xuICAgIH1cbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbnRyb2xsZXIoJ1VzZXJzQ29udHJvbGxlcicsIFVzZXJzQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBVc2Vyc0NvbnRyb2xsZXIoJGNvbnRyb2xsZXIsIFVzZXJzU2VydmljZSkge1xuXG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIHZtLm9uQWN0aXZhdGUgPSBvbkFjdGl2YXRlO1xuICAgIC8vIGluc3RhbnRpYXRlIGJhc2UgY29udHJvbGxlclxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHsgdm06IHZtLCBtb2RlbFNlcnZpY2U6IFVzZXJzU2VydmljZSwgb3B0aW9uczoge30gfSk7XG5cbiAgICBmdW5jdGlvbiBvbkFjdGl2YXRlKCkge1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0ge307XG4gICAgfVxuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKlxuICAgKiBBcnF1aXZvIGRlIGNvbmZpZ3VyYcOnw6NvIGNvbSBhcyByb3RhcyBlc3BlY8OtZmljYXMgZG8gcmVjdXJzbyB1c2VyXG4gICAqXG4gICAqIEBwYXJhbSB7YW55fSAkc3RhdGVQcm92aWRlclxuICAgKiBAcGFyYW0ge2FueX0gR2xvYmFsXG4gICAqL1xuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvdXRlcygkc3RhdGVQcm92aWRlciwgR2xvYmFsKSB7XG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ2FwcC51c2VyJywge1xuICAgICAgdXJsOiAnL3VzdWFyaW8nLFxuICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy91c2Vycy91c2Vycy5odG1sJyxcbiAgICAgIGNvbnRyb2xsZXI6ICdVc2Vyc0NvbnRyb2xsZXIgYXMgdXNlcnNDdHJsJyxcbiAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiB0cnVlLCBuZWVkUHJvZmlsZTogWydhZG1pbiddIH1cbiAgICB9KS5zdGF0ZSgnYXBwLnVzZXItcHJvZmlsZScsIHtcbiAgICAgIHVybDogJy91c3VhcmlvL3BlcmZpbCcsXG4gICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL3VzZXJzL3Byb2ZpbGUuaHRtbCcsXG4gICAgICBjb250cm9sbGVyOiAnUHJvZmlsZUNvbnRyb2xsZXIgYXMgcHJvZmlsZUN0cmwnLFxuICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IHRydWUgfVxuICAgIH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZhY3RvcnkoJ1VzZXJzU2VydmljZScsIFVzZXJzU2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBVc2Vyc1NlcnZpY2UobG9kYXNoLCBHbG9iYWwsIHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCd1c2VycycsIHtcbiAgICAgIC8vcXVhbmRvIGluc3RhbmNpYSB1bSB1c3XDoXJpbyBzZW0gcGFzc2FyIHBhcmFtZXRybyxcbiAgICAgIC8vbyBtZXNtbyB2YWkgdGVyIG9zIHZhbG9yZXMgZGVmYXVsdHMgYWJhaXhvXG4gICAgICBkZWZhdWx0czoge1xuICAgICAgICByb2xlczogW11cbiAgICAgIH0sXG5cbiAgICAgIGFjdGlvbnM6IHtcbiAgICAgICAgLyoqXG4gICAgICAgICAqIFNlcnZpw6dvIHF1ZSBhdHVhbGl6YSBvcyBkYWRvcyBkbyBwZXJmaWwgZG8gdXN1w6FyaW8gbG9nYWRvXG4gICAgICAgICAqXG4gICAgICAgICAqIEBwYXJhbSB7b2JqZWN0fSBhdHRyaWJ1dGVzXG4gICAgICAgICAqIEByZXR1cm5zIHtwcm9taXNlfSBVbWEgcHJvbWlzZSBjb20gbyByZXN1bHRhZG8gZG8gY2hhbWFkYSBubyBiYWNrZW5kXG4gICAgICAgICAqL1xuICAgICAgICB1cGRhdGVQcm9maWxlOiB7XG4gICAgICAgICAgbWV0aG9kOiAnUFVUJyxcbiAgICAgICAgICB1cmw6IEdsb2JhbC5hcGlQYXRoICsgJy9wcm9maWxlJyxcbiAgICAgICAgICBvdmVycmlkZTogdHJ1ZSxcbiAgICAgICAgICB3cmFwOiBmYWxzZVxuICAgICAgICB9XG4gICAgICB9LFxuXG4gICAgICBpbnN0YW5jZToge1xuICAgICAgICAvKipcbiAgICAgICAgICogVmVyaWZpY2Egc2UgbyB1c3XDoXJpbyB0ZW0gb3MgcGVyZmlzIGluZm9ybWFkb3MuXG4gICAgICAgICAqXG4gICAgICAgICAqIEBwYXJhbSB7YW55fSByb2xlcyBwZXJmaXMgYSBzZXJlbSB2ZXJpZmljYWRvc1xuICAgICAgICAgKiBAcGFyYW0ge2Jvb2xlYW59IGFsbCBmbGFnIHBhcmEgaW5kaWNhciBzZSB2YWkgY2hlZ2FyIHRvZG9zIG9zIHBlcmZpcyBvdSBzb21lbnRlIHVtIGRlbGVzXG4gICAgICAgICAqIEByZXR1cm5zIHtib29sZWFufVxuICAgICAgICAgKi9cbiAgICAgICAgaGFzUHJvZmlsZTogZnVuY3Rpb24gaGFzUHJvZmlsZShyb2xlcywgYWxsKSB7XG4gICAgICAgICAgcm9sZXMgPSBhbmd1bGFyLmlzQXJyYXkocm9sZXMpID8gcm9sZXMgOiBbcm9sZXNdO1xuXG4gICAgICAgICAgdmFyIHVzZXJSb2xlcyA9IGxvZGFzaC5tYXAodGhpcy5yb2xlcywgJ3NsdWcnKTtcblxuICAgICAgICAgIGlmIChhbGwpIHtcbiAgICAgICAgICAgIHJldHVybiBsb2Rhc2guaW50ZXJzZWN0aW9uKHVzZXJSb2xlcywgcm9sZXMpLmxlbmd0aCA9PT0gcm9sZXMubGVuZ3RoO1xuICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAvL3JldHVybiB0aGUgbGVuZ3RoIGJlY2F1c2UgMCBpcyBmYWxzZSBpbiBqc1xuICAgICAgICAgICAgcmV0dXJuIGxvZGFzaC5pbnRlcnNlY3Rpb24odXNlclJvbGVzLCByb2xlcykubGVuZ3RoO1xuICAgICAgICAgIH1cbiAgICAgICAgfSxcblxuICAgICAgICAvKipcbiAgICAgICAgICogVmVyaWZpY2Egc2UgbyB1c3XDoXJpbyB0ZW0gbyBwZXJmaWwgYWRtaW4uXG4gICAgICAgICAqXG4gICAgICAgICAqIEByZXR1cm5zIHtib29sZWFufVxuICAgICAgICAgKi9cbiAgICAgICAgaXNBZG1pbjogZnVuY3Rpb24gaXNBZG1pbigpIHtcbiAgICAgICAgICByZXR1cm4gdGhpcy5oYXNQcm9maWxlKCdhZG1pbicpO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICAvKiogQG5nSW5qZWN0ICovXG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbXBvbmVudCgnYm94Jywge1xuICAgIHJlcGxhY2U6IHRydWUsXG4gICAgdGVtcGxhdGVVcmw6IFsnR2xvYmFsJywgZnVuY3Rpb24gKEdsb2JhbCkge1xuICAgICAgcmV0dXJuIEdsb2JhbC5jbGllbnRQYXRoICsgJy93aWRnZXRzL2JveC5odG1sJztcbiAgICB9XSxcbiAgICB0cmFuc2NsdWRlOiB7XG4gICAgICB0b29sYmFyQnV0dG9uczogJz9ib3hUb29sYmFyQnV0dG9ucycsXG4gICAgICBmb290ZXJCdXR0b25zOiAnP2JveEZvb3RlckJ1dHRvbnMnXG4gICAgfSxcbiAgICBiaW5kaW5nczoge1xuICAgICAgYm94VGl0bGU6ICdAJyxcbiAgICAgIHRvb2xiYXJDbGFzczogJ0AnLFxuICAgICAgdG9vbGJhckJnQ29sb3I6ICdAJ1xuICAgIH0sXG4gICAgY29udHJvbGxlcjogWyckdHJhbnNjbHVkZScsIGZ1bmN0aW9uICgkdHJhbnNjbHVkZSkge1xuICAgICAgdmFyIGN0cmwgPSB0aGlzO1xuXG4gICAgICBjdHJsLnRyYW5zY2x1ZGUgPSAkdHJhbnNjbHVkZTtcblxuICAgICAgY3RybC4kb25Jbml0ID0gZnVuY3Rpb24gKCkge1xuICAgICAgICBpZiAoYW5ndWxhci5pc1VuZGVmaW5lZChjdHJsLnRvb2xiYXJCZ0NvbG9yKSkgY3RybC50b29sYmFyQmdDb2xvciA9ICdkZWZhdWx0LXByaW1hcnknO1xuICAgICAgfTtcbiAgICB9XVxuICB9KTtcbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICAvKiogQG5nSW5qZWN0ICovXG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbXBvbmVudCgnY29udGVudEJvZHknLCB7XG4gICAgcmVwbGFjZTogdHJ1ZSxcbiAgICB0cmFuc2NsdWRlOiB0cnVlLFxuICAgIHRlbXBsYXRlVXJsOiBbJ0dsb2JhbCcsIGZ1bmN0aW9uIChHbG9iYWwpIHtcbiAgICAgIHJldHVybiBHbG9iYWwuY2xpZW50UGF0aCArICcvd2lkZ2V0cy9jb250ZW50LWJvZHkuaHRtbCc7XG4gICAgfV0sXG4gICAgYmluZGluZ3M6IHtcbiAgICAgIGxheW91dEFsaWduOiAnQCdcbiAgICB9LFxuICAgIGNvbnRyb2xsZXI6IFtmdW5jdGlvbiAoKSB7XG4gICAgICB2YXIgY3RybCA9IHRoaXM7XG5cbiAgICAgIGN0cmwuJG9uSW5pdCA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgLy8gTWFrZSBhIGNvcHkgb2YgdGhlIGluaXRpYWwgdmFsdWUgdG8gYmUgYWJsZSB0byByZXNldCBpdCBsYXRlclxuICAgICAgICBjdHJsLmxheW91dEFsaWduID0gYW5ndWxhci5pc0RlZmluZWQoY3RybC5sYXlvdXRBbGlnbikgPyBjdHJsLmxheW91dEFsaWduIDogJ2NlbnRlciBzdGFydCc7XG4gICAgICB9O1xuICAgIH1dXG4gIH0pO1xufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29tcG9uZW50KCdjb250ZW50SGVhZGVyJywge1xuICAgIHRlbXBsYXRlVXJsOiBbJ0dsb2JhbCcsIGZ1bmN0aW9uIChHbG9iYWwpIHtcbiAgICAgIHJldHVybiBHbG9iYWwuY2xpZW50UGF0aCArICcvd2lkZ2V0cy9jb250ZW50LWhlYWRlci5odG1sJztcbiAgICB9XSxcbiAgICByZXBsYWNlOiB0cnVlLFxuICAgIGJpbmRpbmdzOiB7XG4gICAgICB0aXRsZTogJ0AnLFxuICAgICAgZGVzY3JpcHRpb246ICdAJ1xuICAgIH1cbiAgfSk7XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmlsdGVyKCdhdWRpdERldGFpbFRpdGxlJywgYXVkaXREZXRhaWxUaXRsZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBhdWRpdERldGFpbFRpdGxlKCR0cmFuc2xhdGUpIHtcbiAgICByZXR1cm4gZnVuY3Rpb24gKGF1ZGl0RGV0YWlsLCBzdGF0dXMpIHtcbiAgICAgIGlmIChhdWRpdERldGFpbC50eXBlID09PSAndXBkYXRlZCcpIHtcbiAgICAgICAgaWYgKHN0YXR1cyA9PT0gJ2JlZm9yZScpIHtcbiAgICAgICAgICByZXR1cm4gJHRyYW5zbGF0ZS5pbnN0YW50KCdkaWFsb2cuYXVkaXQudXBkYXRlZEJlZm9yZScpO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIHJldHVybiAkdHJhbnNsYXRlLmluc3RhbnQoJ2RpYWxvZy5hdWRpdC51cGRhdGVkQWZ0ZXInKTtcbiAgICAgICAgfVxuICAgICAgfSBlbHNlIHtcbiAgICAgICAgcmV0dXJuICR0cmFuc2xhdGUuaW5zdGFudCgnZGlhbG9nLmF1ZGl0LicgKyBhdWRpdERldGFpbC50eXBlKTtcbiAgICAgIH1cbiAgICB9O1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmlsdGVyKCdhdWRpdE1vZGVsJywgYXVkaXRNb2RlbCk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBhdWRpdE1vZGVsKCR0cmFuc2xhdGUpIHtcbiAgICByZXR1cm4gZnVuY3Rpb24gKG1vZGVsSWQpIHtcbiAgICAgIG1vZGVsSWQgPSBtb2RlbElkLnJlcGxhY2UoJ0FwcFxcXFwnLCAnJyk7XG4gICAgICB2YXIgbW9kZWwgPSAkdHJhbnNsYXRlLmluc3RhbnQoJ21vZGVscy4nICsgbW9kZWxJZC50b0xvd2VyQ2FzZSgpKTtcblxuICAgICAgcmV0dXJuIG1vZGVsID8gbW9kZWwgOiBtb2RlbElkO1xuICAgIH07XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5maWx0ZXIoJ2F1ZGl0VHlwZScsIGF1ZGl0VHlwZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBhdWRpdFR5cGUobG9kYXNoLCBBdWRpdFNlcnZpY2UpIHtcbiAgICByZXR1cm4gZnVuY3Rpb24gKHR5cGVJZCkge1xuICAgICAgdmFyIHR5cGUgPSBsb2Rhc2guZmluZChBdWRpdFNlcnZpY2UubGlzdFR5cGVzKCksIHsgaWQ6IHR5cGVJZCB9KTtcblxuICAgICAgcmV0dXJuIHR5cGUgPyB0eXBlLmxhYmVsIDogdHlwZTtcbiAgICB9O1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmlsdGVyKCdhdWRpdFZhbHVlJywgYXVkaXRWYWx1ZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBhdWRpdFZhbHVlKCRmaWx0ZXIsIGxvZGFzaCkge1xuICAgIHJldHVybiBmdW5jdGlvbiAodmFsdWUsIGtleSkge1xuICAgICAgaWYgKGFuZ3VsYXIuaXNEYXRlKHZhbHVlKSB8fCBsb2Rhc2guZW5kc1dpdGgoa2V5LCAnX2F0JykgfHwgbG9kYXNoLmVuZHNXaXRoKGtleSwgJ190bycpKSB7XG4gICAgICAgIHJldHVybiAkZmlsdGVyKCdwckRhdGV0aW1lJykodmFsdWUpO1xuICAgICAgfVxuXG4gICAgICBpZiAodHlwZW9mIHZhbHVlID09PSAnYm9vbGVhbicpIHtcbiAgICAgICAgcmV0dXJuICRmaWx0ZXIoJ3RyYW5zbGF0ZScpKHZhbHVlID8gJ2dsb2JhbC55ZXMnIDogJ2dsb2JhbC5ubycpO1xuICAgICAgfVxuXG4gICAgICAvL2NoZWNrIGlzIGZsb2F0XG4gICAgICBpZiAoTnVtYmVyKHZhbHVlKSA9PT0gdmFsdWUgJiYgdmFsdWUgJSAxICE9PSAwKSB7XG4gICAgICAgIHJldHVybiAkZmlsdGVyKCdyZWFsJykodmFsdWUpO1xuICAgICAgfVxuXG4gICAgICByZXR1cm4gdmFsdWU7XG4gICAgfTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuLyplc2xpbnQgYW5ndWxhci9maWxlLW5hbWU6IDAsIG5vLXVuZGVmOiAwKi9cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29uc3RhbnQoJ3B0LUJSLmkxOG4uYXR0cmlidXRlcycsIHtcbiAgICBlbWFpbDogJ0VtYWlsJyxcbiAgICBwYXNzd29yZDogJ1NlbmhhJyxcbiAgICBuYW1lOiAnTm9tZScsXG4gICAgaW1hZ2U6ICdJbWFnZW0nLFxuICAgIHJvbGVzOiAnUGVyZmlzJyxcbiAgICBkYXRlOiAnRGF0YScsXG4gICAgaW5pdGlhbERhdGU6ICdEYXRhIEluaWNpYWwnLFxuICAgIGZpbmFsRGF0ZTogJ0RhdGEgRmluYWwnLFxuICAgIHRhc2s6IHtcbiAgICAgIGRlc2NyaXB0aW9uOiAnRGVzY3Jpw6fDo28nLFxuICAgICAgZG9uZTogJ0ZlaXRvPycsXG4gICAgICBwcmlvcml0eTogJ1ByaW9yaWRhZGUnLFxuICAgICAgc2NoZWR1bGVkX3RvOiAnQWdlbmRhZG8gUGFyYT8nLFxuICAgICAgcHJvamVjdDogJ1Byb2pldG8nXG4gICAgfSxcbiAgICBwcm9qZWN0OiB7XG4gICAgICBjb3N0OiAnQ3VzdG8nXG4gICAgfSxcbiAgICAvL8OpIGNhcnJlZ2FkbyBkbyBzZXJ2aWRvciBjYXNvIGVzdGVqYSBkZWZpbmlkbyBubyBtZXNtb1xuICAgIGF1ZGl0TW9kZWw6IHt9XG4gIH0pO1xufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuLyplc2xpbnQgYW5ndWxhci9maWxlLW5hbWU6IDAsIG5vLXVuZGVmOiAwKi9cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29uc3RhbnQoJ3B0LUJSLmkxOG4uZGlhbG9nJywge1xuICAgIGNvbmZpcm1UaXRsZTogJ0NvbmZpcm1hw6fDo28nLFxuICAgIGNvbmZpcm1EZXNjcmlwdGlvbjogJ0NvbmZpcm1hIGEgYcOnw6NvPycsXG4gICAgcmVtb3ZlRGVzY3JpcHRpb246ICdEZXNlamEgcmVtb3ZlciBwZXJtYW5lbnRlbWVudGUge3tuYW1lfX0/JyxcbiAgICBhdWRpdDoge1xuICAgICAgY3JlYXRlZDogJ0luZm9ybWHDp8O1ZXMgZG8gQ2FkYXN0cm8nLFxuICAgICAgdXBkYXRlZEJlZm9yZTogJ0FudGVzIGRhIEF0dWFsaXphw6fDo28nLFxuICAgICAgdXBkYXRlZEFmdGVyOiAnRGVwb2lzIGRhIEF0dWFsaXphw6fDo28nLFxuICAgICAgZGVsZXRlZDogJ0luZm9ybWHDp8O1ZXMgYW50ZXMgZGUgcmVtb3ZlcidcbiAgICB9LFxuICAgIGxvZ2luOiB7XG4gICAgICByZXNldFBhc3N3b3JkOiB7XG4gICAgICAgIGRlc2NyaXB0aW9uOiAnRGlnaXRlIGFiYWl4byBvIGVtYWlsIGNhZGFzdHJhZG8gbm8gc2lzdGVtYS4nXG4gICAgICB9XG4gICAgfVxuICB9KTtcbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbi8qZXNsaW50IGFuZ3VsYXIvZmlsZS1uYW1lOiAwLCBuby11bmRlZjogMCovXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbnN0YW50KCdwdC1CUi5pMThuLmdsb2JhbCcsIHtcbiAgICBsb2FkaW5nOiAnQ2FycmVnYW5kby4uLicsXG4gICAgcHJvY2Vzc2luZzogJ1Byb2Nlc3NhbmRvLi4uJyxcbiAgICB5ZXM6ICdTaW0nLFxuICAgIG5vOiAnTsOjbycsXG4gICAgYWxsOiAnVG9kb3MnXG4gIH0pO1xufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuLyplc2xpbnQgYW5ndWxhci9maWxlLW5hbWU6IDAsIG5vLXVuZGVmOiAwKi9cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29uc3RhbnQoJ3B0LUJSLmkxOG4ubWVzc2FnZXMnLCB7XG4gICAgaW50ZXJuYWxFcnJvcjogJ09jb3JyZXUgdW0gZXJybyBpbnRlcm5vLCBjb250YXRlIG8gYWRtaW5pc3RyYWRvciBkbyBzaXN0ZW1hJyxcbiAgICBub3RGb3VuZDogJ05lbmh1bSByZWdpc3RybyBlbmNvbnRyYWRvJyxcbiAgICBub3RBdXRob3JpemVkOiAnVm9jw6ogbsOjbyB0ZW0gYWNlc3NvIGEgZXN0YSBmdW5jaW9uYWxpZGFkZS4nLFxuICAgIHNlYXJjaEVycm9yOiAnTsOjbyBmb2kgcG9zc8OtdmVsIHJlYWxpemFyIGEgYnVzY2EuJyxcbiAgICBzYXZlU3VjY2VzczogJ1JlZ2lzdHJvIHNhbHZvIGNvbSBzdWNlc3NvLicsXG4gICAgb3BlcmF0aW9uU3VjY2VzczogJ09wZXJhw6fDo28gcmVhbGl6YWRhIGNvbSBzdWNlc3NvLicsXG4gICAgb3BlcmF0aW9uRXJyb3I6ICdFcnJvIGFvIHJlYWxpemFyIGEgb3BlcmHDp8OjbycsXG4gICAgc2F2ZUVycm9yOiAnRXJybyBhbyB0ZW50YXIgc2FsdmFyIG8gcmVnaXN0cm8uJyxcbiAgICByZW1vdmVTdWNjZXNzOiAnUmVtb8Onw6NvIHJlYWxpemFkYSBjb20gc3VjZXNzby4nLFxuICAgIHJlbW92ZUVycm9yOiAnRXJybyBhbyB0ZW50YXIgcmVtb3ZlciBvIHJlZ2lzdHJvLicsXG4gICAgcmVzb3VyY2VOb3RGb3VuZEVycm9yOiAnUmVjdXJzbyBuw6NvIGVuY29udHJhZG8nLFxuICAgIG5vdE51bGxFcnJvcjogJ1RvZG9zIG9zIGNhbXBvcyBvYnJpZ2F0w7NyaW9zIGRldmVtIHNlciBwcmVlbmNoaWRvcy4nLFxuICAgIGR1cGxpY2F0ZWRSZXNvdXJjZUVycm9yOiAnSsOhIGV4aXN0ZSB1bSByZWN1cnNvIGNvbSBlc3NhcyBpbmZvcm1hw6fDtWVzLicsXG4gICAgdmFsaWRhdGU6IHtcbiAgICAgIGZpZWxkUmVxdWlyZWQ6ICdPIGNhbXBvIHt7ZmllbGR9fSDDqSBvYnJpZ3JhdMOzcmlvLidcbiAgICB9LFxuICAgIGxheW91dDoge1xuICAgICAgZXJyb3I0MDQ6ICdQw6FnaW5hIG7Do28gZW5jb250cmFkYSdcbiAgICB9LFxuICAgIGxvZ2luOiB7XG4gICAgICBsb2dvdXRJbmFjdGl2ZTogJ1ZvY8OqIGZvaSBkZXNsb2dhZG8gZG8gc2lzdGVtYSBwb3IgaW5hdGl2aWRhZGUuIEZhdm9yIGVudHJhciBubyBzaXN0ZW1hIG5vdmFtZW50ZS4nLFxuICAgICAgaW52YWxpZENyZWRlbnRpYWxzOiAnQ3JlZGVuY2lhaXMgSW52w6FsaWRhcycsXG4gICAgICB1bmtub3duRXJyb3I6ICdOw6NvIGZvaSBwb3Nzw612ZWwgcmVhbGl6YXIgbyBsb2dpbi4gVGVudGUgbm92YW1lbnRlLiAnICsgJ0Nhc28gbsOjbyBjb25zaWdhIGZhdm9yIGVuY29udHJhciBlbSBjb250YXRvIGNvbSBvIGFkbWluaXN0cmFkb3IgZG8gc2lzdGVtYS4nLFxuICAgICAgdXNlck5vdEZvdW5kOiAnTsOjbyBmb2kgcG9zc8OtdmVsIGVuY29udHJhciBzZXVzIGRhZG9zJ1xuICAgIH0sXG4gICAgZGFzaGJvYXJkOiB7XG4gICAgICB3ZWxjb21lOiAnU2VqYSBiZW0gVmluZG8ge3t1c2VyTmFtZX19JyxcbiAgICAgIGRlc2NyaXB0aW9uOiAnVXRpbGl6ZSBvIG1lbnUgcGFyYSBuYXZlZ2HDp8Ojby4nXG4gICAgfSxcbiAgICBtYWlsOiB7XG4gICAgICBtYWlsRXJyb3JzOiAnT2NvcnJldSB1bSBlcnJvIG5vcyBzZWd1aW50ZXMgZW1haWxzIGFiYWl4bzpcXG4nLFxuICAgICAgc2VuZE1haWxTdWNjZXNzOiAnRW1haWwgZW52aWFkbyBjb20gc3VjZXNzbyEnLFxuICAgICAgc2VuZE1haWxFcnJvcjogJ07Do28gZm9pIHBvc3PDrXZlbCBlbnZpYXIgbyBlbWFpbC4nLFxuICAgICAgcGFzc3dvcmRTZW5kaW5nU3VjY2VzczogJ08gcHJvY2Vzc28gZGUgcmVjdXBlcmHDp8OjbyBkZSBzZW5oYSBmb2kgaW5pY2lhZG8uIENhc28gbyBlbWFpbCBuw6NvIGNoZWd1ZSBlbSAxMCBtaW51dG9zIHRlbnRlIG5vdmFtZW50ZS4nXG4gICAgfSxcbiAgICB1c2VyOiB7XG4gICAgICByZW1vdmVZb3VyU2VsZkVycm9yOiAnVm9jw6ogbsOjbyBwb2RlIHJlbW92ZXIgc2V1IHByw7NwcmlvIHVzdcOhcmlvJyxcbiAgICAgIHVzZXJFeGlzdHM6ICdVc3XDoXJpbyBqw6EgYWRpY2lvbmFkbyEnLFxuICAgICAgcHJvZmlsZToge1xuICAgICAgICB1cGRhdGVFcnJvcjogJ07Do28gZm9pIHBvc3PDrXZlbCBhdHVhbGl6YXIgc2V1IHByb2ZpbGUnXG4gICAgICB9XG4gICAgfSxcbiAgICBxdWVyeURpbmFtaWM6IHtcbiAgICAgIG5vRmlsdGVyOiAnTmVuaHVtIGZpbHRybyBhZGljaW9uYWRvJ1xuICAgIH1cbiAgfSk7XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4vKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCwgbm8tdW5kZWY6IDAqL1xuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25zdGFudCgncHQtQlIuaTE4bi5tb2RlbHMnLCB7XG4gICAgdXNlcjogJ1VzdcOhcmlvJyxcbiAgICB0YXNrOiAnVGFyZWZhJyxcbiAgICBwcm9qZWN0OiAnUHJvamV0bydcbiAgfSk7XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4vKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCwgbm8tdW5kZWY6IDAqL1xuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25zdGFudCgncHQtQlIuaTE4bi52aWV3cycsIHtcbiAgICBicmVhZGNydW1iczoge1xuICAgICAgdXNlcjogJ0FkbWluaXN0cmHDp8OjbyAtIFVzdcOhcmlvJyxcbiAgICAgICd1c2VyLXByb2ZpbGUnOiAnUGVyZmlsJyxcbiAgICAgIGRhc2hib2FyZDogJ0Rhc2hib2FyZCcsXG4gICAgICBhdWRpdDogJ0FkbWluaXN0cmHDp8OjbyAtIEF1ZGl0b3JpYScsXG4gICAgICBtYWlsOiAnQWRtaW5pc3RyYcOnw6NvIC0gRW52aW8gZGUgZS1tYWlsJyxcbiAgICAgIHByb2plY3Q6ICdFeGVtcGxvcyAtIFByb2pldG9zJyxcbiAgICAgICdkaW5hbWljLXF1ZXJ5JzogJ0FkbWluaXN0cmHDp8OjbyAtIENvbnN1bHRhcyBEaW7Dom1pY2FzJyxcbiAgICAgICdub3QtYXV0aG9yaXplZCc6ICdBY2Vzc28gTmVnYWRvJ1xuICAgIH0sXG4gICAgdGl0bGVzOiB7XG4gICAgICBkYXNoYm9hcmQ6ICdQw6FnaW5hIGluaWNpYWwnLFxuICAgICAgbWFpbFNlbmQ6ICdFbnZpYXIgZS1tYWlsJyxcbiAgICAgIHRhc2tMaXN0OiAnTGlzdGEgZGUgVGFyZWZhcycsXG4gICAgICB1c2VyTGlzdDogJ0xpc3RhIGRlIFVzdcOhcmlvcycsXG4gICAgICBhdWRpdExpc3Q6ICdMaXN0YSBkZSBMb2dzJyxcbiAgICAgIHJlZ2lzdGVyOiAnRm9ybXVsw6FyaW8gZGUgQ2FkYXN0cm8nLFxuICAgICAgcmVzZXRQYXNzd29yZDogJ1JlZGVmaW5pciBTZW5oYScsXG4gICAgICB1cGRhdGU6ICdGb3JtdWzDoXJpbyBkZSBBdHVhbGl6YcOnw6NvJ1xuICAgIH0sXG4gICAgYWN0aW9uczoge1xuICAgICAgc2VuZDogJ0VudmlhcicsXG4gICAgICBzYXZlOiAnU2FsdmFyJyxcbiAgICAgIGNsZWFyOiAnTGltcGFyJyxcbiAgICAgIGNsZWFyQWxsOiAnTGltcGFyIFR1ZG8nLFxuICAgICAgcmVzdGFydDogJ1JlaW5pY2lhcicsXG4gICAgICBmaWx0ZXI6ICdGaWx0cmFyJyxcbiAgICAgIHNlYXJjaDogJ1Blc3F1aXNhcicsXG4gICAgICBsaXN0OiAnTGlzdGFyJyxcbiAgICAgIGVkaXQ6ICdFZGl0YXInLFxuICAgICAgY2FuY2VsOiAnQ2FuY2VsYXInLFxuICAgICAgdXBkYXRlOiAnQXR1YWxpemFyJyxcbiAgICAgIHJlbW92ZTogJ1JlbW92ZXInLFxuICAgICAgZ2V0T3V0OiAnU2FpcicsXG4gICAgICBhZGQ6ICdBZGljaW9uYXInLFxuICAgICAgaW46ICdFbnRyYXInLFxuICAgICAgbG9hZEltYWdlOiAnQ2FycmVnYXIgSW1hZ2VtJyxcbiAgICAgIHNpZ251cDogJ0NhZGFzdHJhcidcbiAgICB9LFxuICAgIGZpZWxkczoge1xuICAgICAgZGF0ZTogJ0RhdGEnLFxuICAgICAgYWN0aW9uOiAnQcOnw6NvJyxcbiAgICAgIGFjdGlvbnM6ICdBw6fDtWVzJyxcbiAgICAgIGF1ZGl0OiB7XG4gICAgICAgIGRhdGVTdGFydDogJ0RhdGEgSW5pY2lhbCcsXG4gICAgICAgIGRhdGVFbmQ6ICdEYXRhIEZpbmFsJyxcbiAgICAgICAgcmVzb3VyY2U6ICdSZWN1cnNvJyxcbiAgICAgICAgYWxsUmVzb3VyY2VzOiAnVG9kb3MgUmVjdXJzb3MnLFxuICAgICAgICB0eXBlOiB7XG4gICAgICAgICAgY3JlYXRlZDogJ0NhZGFzdHJhZG8nLFxuICAgICAgICAgIHVwZGF0ZWQ6ICdBdHVhbGl6YWRvJyxcbiAgICAgICAgICBkZWxldGVkOiAnUmVtb3ZpZG8nXG4gICAgICAgIH1cbiAgICAgIH0sXG4gICAgICBsb2dpbjoge1xuICAgICAgICByZXNldFBhc3N3b3JkOiAnRXNxdWVjaSBtaW5oYSBzZW5oYScsXG4gICAgICAgIGNvbmZpcm1QYXNzd29yZDogJ0NvbmZpcm1hciBzZW5oYSdcbiAgICAgIH0sXG4gICAgICBtYWlsOiB7XG4gICAgICAgIHRvOiAnUGFyYScsXG4gICAgICAgIHN1YmplY3Q6ICdBc3N1bnRvJyxcbiAgICAgICAgbWVzc2FnZTogJ01lbnNhZ2VtJ1xuICAgICAgfSxcbiAgICAgIHF1ZXJ5RGluYW1pYzoge1xuICAgICAgICBmaWx0ZXJzOiAnRmlsdHJvcycsXG4gICAgICAgIHJlc3VsdHM6ICdSZXN1bHRhZG9zJyxcbiAgICAgICAgbW9kZWw6ICdNb2RlbCcsXG4gICAgICAgIGF0dHJpYnV0ZTogJ0F0cmlidXRvJyxcbiAgICAgICAgb3BlcmF0b3I6ICdPcGVyYWRvcicsXG4gICAgICAgIHJlc291cmNlOiAnUmVjdXJzbycsXG4gICAgICAgIHZhbHVlOiAnVmFsb3InLFxuICAgICAgICBvcGVyYXRvcnM6IHtcbiAgICAgICAgICBlcXVhbHM6ICdJZ3VhbCcsXG4gICAgICAgICAgZGlmZXJlbnQ6ICdEaWZlcmVudGUnLFxuICAgICAgICAgIGNvbnRlaW5zOiAnQ29udMOpbScsXG4gICAgICAgICAgc3RhcnRXaXRoOiAnSW5pY2lhIGNvbScsXG4gICAgICAgICAgZmluaXNoV2l0aDogJ0ZpbmFsaXphIGNvbScsXG4gICAgICAgICAgYmlnZ2VyVGhhbjogJ01haW9yJyxcbiAgICAgICAgICBlcXVhbHNPckJpZ2dlclRoYW46ICdNYWlvciBvdSBJZ3VhbCcsXG4gICAgICAgICAgbGVzc1RoYW46ICdNZW5vcicsXG4gICAgICAgICAgZXF1YWxzT3JMZXNzVGhhbjogJ01lbm9yIG91IElndWFsJ1xuICAgICAgICB9XG4gICAgICB9LFxuICAgICAgcHJvamVjdDoge1xuICAgICAgICBuYW1lOiAnTm9tZScsXG4gICAgICAgIHRvdGFsVGFzazogJ1RvdGFsIGRlIFRhcmVmYXMnXG4gICAgICB9LFxuICAgICAgdGFzazoge1xuICAgICAgICBkb25lOiAnTsOjbyBGZWl0byAvIEZlaXRvJ1xuICAgICAgfSxcbiAgICAgIHVzZXI6IHtcbiAgICAgICAgcGVyZmlsczogJ1BlcmZpcycsXG4gICAgICAgIG5hbWVPckVtYWlsOiAnTm9tZSBvdSBFbWFpbCdcbiAgICAgIH1cbiAgICB9LFxuICAgIGxheW91dDoge1xuICAgICAgbWVudToge1xuICAgICAgICBkYXNoYm9hcmQ6ICdEYXNoYm9hcmQnLFxuICAgICAgICBwcm9qZWN0OiAnUHJvamV0b3MnLFxuICAgICAgICBhZG1pbjogJ0FkbWluaXN0cmHDp8OjbycsXG4gICAgICAgIGV4YW1wbGVzOiAnRXhlbXBsb3MnLFxuICAgICAgICB1c2VyOiAnVXN1w6FyaW9zJyxcbiAgICAgICAgbWFpbDogJ0VudmlhciBlLW1haWwnLFxuICAgICAgICBhdWRpdDogJ0F1ZGl0b3JpYScsXG4gICAgICAgIGRpbmFtaWNRdWVyeTogJ0NvbnN1bHRhcyBEaW5hbWljYXMnXG4gICAgICB9XG4gICAgfSxcbiAgICB0b29sdGlwczoge1xuICAgICAgYXVkaXQ6IHtcbiAgICAgICAgdmlld0RldGFpbDogJ1Zpc3VhbGl6YXIgRGV0YWxoYW1lbnRvJ1xuICAgICAgfSxcbiAgICAgIHVzZXI6IHtcbiAgICAgICAgcGVyZmlsOiAnUGVyZmlsJyxcbiAgICAgICAgdHJhbnNmZXI6ICdUcmFuc2ZlcmlyJ1xuICAgICAgfSxcbiAgICAgIHRhc2s6IHtcbiAgICAgICAgbGlzdFRhc2s6ICdMaXN0YXIgVGFyZWZhcydcbiAgICAgIH1cbiAgICB9XG4gIH0pO1xufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbnRyb2xsZXIoJ1Byb2plY3RzQ29udHJvbGxlcicsIFByb2plY3RzQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBQcm9qZWN0c0NvbnRyb2xsZXIoR2xvYmFsLCAkY29udHJvbGxlciwgUHJvamVjdHNTZXJ2aWNlLCBQckRpYWxvZykge1xuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICAvL0F0dHJpYnV0ZXMgQmxvY2tcblxuICAgIC8vRnVuY3Rpb25zIEJsb2NrXG4gICAgdm0ub25BY3RpdmF0ZSA9IG9uQWN0aXZhdGU7XG4gICAgdm0uYXBwbHlGaWx0ZXJzID0gYXBwbHlGaWx0ZXJzO1xuICAgIHZtLnZpZXdUYXNrcyA9IHZpZXdUYXNrcztcblxuICAgIC8vIGluc3RhbnRpYXRlIGJhc2UgY29udHJvbGxlclxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHsgdm06IHZtLCBtb2RlbFNlcnZpY2U6IFByb2plY3RzU2VydmljZSwgb3B0aW9uczoge30gfSk7XG5cbiAgICBmdW5jdGlvbiBvbkFjdGl2YXRlKCkge1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0ge307XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gYXBwbHlGaWx0ZXJzKGRlZmF1bHRRdWVyeUZpbHRlcnMpIHtcbiAgICAgIHJldHVybiBhbmd1bGFyLmV4dGVuZChkZWZhdWx0UXVlcnlGaWx0ZXJzLCB2bS5xdWVyeUZpbHRlcnMpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIHZpZXdUYXNrcyhwcm9qZWN0SWQpIHtcbiAgICAgIHZhciBjb25maWcgPSB7XG4gICAgICAgIGxvY2Fsczoge1xuICAgICAgICAgIHByb2plY3RJZDogcHJvamVjdElkXG4gICAgICAgIH0sXG4gICAgICAgIGNvbnRyb2xsZXI6ICdUYXNrc0RpYWxvZ0NvbnRyb2xsZXInLFxuICAgICAgICBjb250cm9sbGVyQXM6ICd0YXNrc0N0cmwnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL3NhbXBsZXMvdGFza3MvdGFza3MtZGlhbG9nLmh0bWwnLFxuICAgICAgICBoYXNCYWNrZHJvcDogdHJ1ZVxuICAgICAgfTtcblxuICAgICAgUHJEaWFsb2cuY3VzdG9tKGNvbmZpZykuZmluYWxseShmdW5jdGlvbiAoKSB7XG4gICAgICAgIHZtLnNlYXJjaCh2bS5wYWdpbmF0b3IuY3VycmVudFBhZ2UpO1xuICAgICAgfSk7XG4gICAgfVxuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKlxuICAgKiBBcnF1aXZvIGRlIGNvbmZpZ3VyYcOnw6NvIGNvbSBhcyByb3RhcyBlc3BlY8OtZmljYXMgZG8gcmVjdXJzbyBwcm9qZWN0XG4gICAqXG4gICAqIEBwYXJhbSB7YW55fSAkc3RhdGVQcm92aWRlclxuICAgKiBAcGFyYW0ge2FueX0gR2xvYmFsXG4gICAqL1xuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvdXRlcygkc3RhdGVQcm92aWRlciwgR2xvYmFsKSB7XG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ2FwcC5wcm9qZWN0Jywge1xuICAgICAgdXJsOiAnL3Byb2pldG9zJyxcbiAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvc2FtcGxlcy9wcm9qZWN0cy9wcm9qZWN0cy5odG1sJyxcbiAgICAgIGNvbnRyb2xsZXI6ICdQcm9qZWN0c0NvbnRyb2xsZXIgYXMgcHJvamVjdHNDdHJsJyxcbiAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiB0cnVlLCBuZWVkUHJvZmlsZTogWydhZG1pbiddIH1cbiAgICB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5mYWN0b3J5KCdQcm9qZWN0c1NlcnZpY2UnLCBQcm9qZWN0c1NlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gUHJvamVjdHNTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCdwcm9qZWN0cycsIHtcbiAgICAgIGFjdGlvbnM6IHt9LFxuICAgICAgaW5zdGFuY2U6IHt9XG4gICAgfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb250cm9sbGVyKCdUYXNrc0RpYWxvZ0NvbnRyb2xsZXInLCBUYXNrc0RpYWxvZ0NvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gVGFza3NEaWFsb2dDb250cm9sbGVyKCRjb250cm9sbGVyLCBUYXNrc1NlcnZpY2UsIHByb2plY3RJZCwgUHJUb2FzdCwgLy8gTk9TT05BUlxuICBQckRpYWxvZywgJHRyYW5zbGF0ZSwgR2xvYmFsLCBtb21lbnQpIHtcblxuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICAvL0Z1bmN0aW9ucyBCbG9ja1xuICAgIHZtLm9uQWN0aXZhdGUgPSBvbkFjdGl2YXRlO1xuICAgIHZtLmNsb3NlID0gY2xvc2U7XG4gICAgdm0uYXBwbHlGaWx0ZXJzID0gYXBwbHlGaWx0ZXJzO1xuICAgIHZtLmJlZm9yZVNhdmUgPSBiZWZvcmVTYXZlO1xuICAgIHZtLmFmdGVyU2F2ZSA9IGFmdGVyU2F2ZTtcbiAgICB2bS50b2dnbGVEb25lID0gdG9nZ2xlRG9uZTtcblxuICAgIC8vIGluc3RhbnRpYXRlIGJhc2UgY29udHJvbGxlclxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHsgdm06IHZtLCBtb2RlbFNlcnZpY2U6IFRhc2tzU2VydmljZSwgb3B0aW9uczoge1xuICAgICAgICBwZXJQYWdlOiA1XG4gICAgICB9IH0pO1xuXG4gICAgZnVuY3Rpb24gb25BY3RpdmF0ZSgpIHtcbiAgICAgIHZtLmdsb2JhbCA9IEdsb2JhbDtcbiAgICAgIHZtLnJlc291cmNlLnNjaGVkdWxlZF90byA9IG1vbWVudCgpLmFkZCgzMCwgJ21pbnV0ZXMnKTtcbiAgICAgIHZtLnF1ZXJ5RmlsdGVycyA9IHsgcHJvamVjdElkOiBwcm9qZWN0SWQgfTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBhcHBseUZpbHRlcnMoZGVmYXVsdFF1ZXJ5RmlsdGVycykge1xuICAgICAgcmV0dXJuIGFuZ3VsYXIuZXh0ZW5kKGRlZmF1bHRRdWVyeUZpbHRlcnMsIHZtLnF1ZXJ5RmlsdGVycyk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gYmVmb3JlU2F2ZSgpIHtcbiAgICAgIHZtLnJlc291cmNlLnByb2plY3RfaWQgPSB2bS5xdWVyeUZpbHRlcnMucHJvamVjdElkO1xuICAgICAgdm0ucmVzb3VyY2UucHJvamVjdCA9IG51bGw7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gYWZ0ZXJTYXZlKCkge1xuICAgICAgdm0uY2xlYW5Gb3JtKCk7XG4gICAgICB2bS5zZWFyY2godm0ucGFnaW5hdG9yLmN1cnJlbnRQYWdlKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBjbG9zZSgpIHtcbiAgICAgIHZtLmNsZWFuRm9ybSgpO1xuICAgICAgUHJEaWFsb2cuY2xvc2UoKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiB0b2dnbGVEb25lKHJlc291cmNlKSB7XG4gICAgICBUYXNrc1NlcnZpY2UudG9nZ2xlRG9uZSh7IGlkOiByZXNvdXJjZS5pZCwgZG9uZTogcmVzb3VyY2UuZG9uZSB9KS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgUHJUb2FzdC5zdWNjZXNzKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMuc2F2ZVN1Y2Nlc3MnKSk7XG4gICAgICAgIHZtLnNlYXJjaCh2bS5wYWdpbmF0b3IuY3VycmVudFBhZ2UpO1xuICAgICAgfSwgZnVuY3Rpb24gKGVycm9yKSB7XG4gICAgICAgIFByVG9hc3QuZXJyb3JWYWxpZGF0aW9uKGVycm9yLmRhdGEsICR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMub3BlcmF0aW9uRXJyb3InKSk7XG4gICAgICB9KTtcbiAgICB9XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmFjdG9yeSgnVGFza3NTZXJ2aWNlJywgVGFza3NTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIFRhc2tzU2VydmljZShzZXJ2aWNlRmFjdG9yeSwgbW9tZW50KSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCd0YXNrcycsIHtcbiAgICAgIC8vcXVhbmRvIGluc3RhbmNpYSB1bSB1c3XDoXJpbyBzZW0gcGFzc2FyIHBhcmFtZXRybyxcbiAgICAgIC8vbyBtZXNtbyB2YWkgdGVyIG9zIHZhbG9yZXMgZGVmYXVsdHMgYWJhaXhvXG4gICAgICBkZWZhdWx0czoge1xuICAgICAgICBzY2hlZHVsZWRfdG86IG5ldyBEYXRlKClcbiAgICAgIH0sXG5cbiAgICAgIG1hcDoge1xuICAgICAgICAvL2NvbnZlcnQgcGFyYSBvYmpldG8gamF2YXNjcmlwdCBkYXRlIHVtYSBzdHJpbmcgZm9ybWF0YWRhIGNvbW8gZGF0YVxuICAgICAgICBzY2hlZHVsZWRfdG86IGZ1bmN0aW9uIHNjaGVkdWxlZF90byh2YWx1ZSkge1xuICAgICAgICAgIHJldHVybiBtb21lbnQodmFsdWUpLnRvRGF0ZSgpO1xuICAgICAgICB9XG4gICAgICB9LFxuXG4gICAgICBhY3Rpb25zOiB7XG4gICAgICAgIC8qKlxuICAgICAgICAgKiBBdHVhbGl6YSBvcyBzdGF0dXMgZGEgdGFyZWZhXG4gICAgICAgICAqXG4gICAgICAgICAqIEBwYXJhbSB7b2JqZWN0fSBhdHRyaWJ1dGVzXG4gICAgICAgICAqL1xuICAgICAgICB0b2dnbGVEb25lOiB7XG4gICAgICAgICAgbWV0aG9kOiAnUFVUJyxcbiAgICAgICAgICB1cmw6ICd0b2dnbGVEb25lJ1xuICAgICAgICB9XG4gICAgICB9LFxuICAgICAgaW5zdGFuY2U6IHt9XG4gICAgfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb250cm9sbGVyKCdVc2Vyc0RpYWxvZ0NvbnRyb2xsZXInLCBVc2Vyc0RpYWxvZ0NvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gVXNlcnNEaWFsb2dDb250cm9sbGVyKCRjb250cm9sbGVyLCBVc2Vyc1NlcnZpY2UsIFByRGlhbG9nLCAvLyBOT1NPTkFSXG4gIHVzZXJEaWFsb2dJbnB1dCwgb25Jbml0KSB7XG5cbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0ub25BY3RpdmF0ZSA9IG9uQWN0aXZhdGU7XG4gICAgdm0uYXBwbHlGaWx0ZXJzID0gYXBwbHlGaWx0ZXJzO1xuICAgIHZtLmNsb3NlID0gY2xvc2U7XG5cbiAgICBpZiAoYW5ndWxhci5pc0RlZmluZWQodXNlckRpYWxvZ0lucHV0KSkge1xuICAgICAgdm0udHJhbnNmZXJVc2VyID0gdXNlckRpYWxvZ0lucHV0LnRyYW5zZmVyVXNlckZuO1xuICAgIH1cblxuICAgIC8vIGluc3RhbnRpYXRlIGJhc2UgY29udHJvbGxlclxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHtcbiAgICAgIHZtOiB2bSxcbiAgICAgIG1vZGVsU2VydmljZTogVXNlcnNTZXJ2aWNlLFxuICAgICAgc2VhcmNoT25Jbml0OiBvbkluaXQsXG4gICAgICBvcHRpb25zOiB7XG4gICAgICAgIHBlclBhZ2U6IDVcbiAgICAgIH1cbiAgICB9KTtcblxuICAgIGZ1bmN0aW9uIG9uQWN0aXZhdGUoKSB7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMgPSB7fTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBhcHBseUZpbHRlcnMoKSB7XG4gICAgICByZXR1cm4gYW5ndWxhci5leHRlbmQodm0uZGVmYXVsdFF1ZXJ5RmlsdGVycywgdm0ucXVlcnlGaWx0ZXJzKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBjbG9zZSgpIHtcbiAgICAgIFByRGlhbG9nLmNsb3NlKCk7XG4gICAgfVxuICB9XG59KSgpOyIsIi8qZXNsaW50IGFuZ3VsYXIvZmlsZS1uYW1lOiAwKi9cbihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnLCBbXG4gICAgJ25nQW5pbWF0ZScsXG4gICAgJ25nQXJpYScsXG4gICAgJ3VpLnJvdXRlcicsXG4gICAgJ25nUHJvZGViJyxcbiAgICAndWkudXRpbHMubWFza3MnLFxuICAgICd0ZXh0LW1hc2snLFxuICAgICduZ01hdGVyaWFsJyxcbiAgICAnbW9kZWxGYWN0b3J5JyxcbiAgICAnbWQuZGF0YS50YWJsZScsXG4gICAgJ25nTWF0ZXJpYWxEYXRlUGlja2VyJyxcbiAgICAncGFzY2FscHJlY2h0LnRyYW5zbGF0ZScsXG4gICAgJ2FuZ3VsYXJGaWxlVXBsb2FkJ10pO1xufSkoKTtcbiIsIihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uZmlnKGNvbmZpZyk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBjb25maWcoR2xvYmFsLCAkbWRUaGVtaW5nUHJvdmlkZXIsICRtb2RlbEZhY3RvcnlQcm92aWRlciwgIC8vIE5PU09OQVJcbiAgICAkdHJhbnNsYXRlUHJvdmlkZXIsIG1vbWVudCwgJG1kQXJpYVByb3ZpZGVyKSB7XG5cbiAgICAkdHJhbnNsYXRlUHJvdmlkZXJcbiAgICAgIC51c2VMb2FkZXIoJ2xhbmd1YWdlTG9hZGVyJylcbiAgICAgIC51c2VTYW5pdGl6ZVZhbHVlU3RyYXRlZ3koJ2VzY2FwZScpO1xuXG4gICAgJHRyYW5zbGF0ZVByb3ZpZGVyLnVzZVBvc3RDb21waWxpbmcodHJ1ZSk7XG5cbiAgICBtb21lbnQubG9jYWxlKCdwdC1CUicpO1xuXG4gICAgLy9vcyBzZXJ2acOnb3MgcmVmZXJlbnRlIGFvcyBtb2RlbHMgdmFpIHV0aWxpemFyIGNvbW8gYmFzZSBuYXMgdXJsc1xuICAgICRtb2RlbEZhY3RvcnlQcm92aWRlci5kZWZhdWx0T3B0aW9ucy5wcmVmaXggPSBHbG9iYWwuYXBpUGF0aDtcblxuICAgIC8vIENvbmZpZ3VyYXRpb24gdGhlbWVcbiAgICAkbWRUaGVtaW5nUHJvdmlkZXIudGhlbWUoJ2RlZmF1bHQnKVxuICAgICAgLnByaW1hcnlQYWxldHRlKCdicm93bicsIHtcbiAgICAgICAgZGVmYXVsdDogJzcwMCdcbiAgICAgIH0pXG4gICAgICAuYWNjZW50UGFsZXR0ZSgnYW1iZXInKVxuICAgICAgLndhcm5QYWxldHRlKCdkZWVwLW9yYW5nZScpO1xuXG4gICAgLy8gRW5hYmxlIGJyb3dzZXIgY29sb3JcbiAgICAkbWRUaGVtaW5nUHJvdmlkZXIuZW5hYmxlQnJvd3NlckNvbG9yKCk7XG5cbiAgICAkbWRBcmlhUHJvdmlkZXIuZGlzYWJsZVdhcm5pbmdzKCk7XG5cbiAgfVxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnRyb2xsZXIoJ0FwcENvbnRyb2xsZXInLCBBcHBDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8qKlxuICAgKiBDb250cm9sYWRvciByZXNwb25zw6F2ZWwgcG9yIGZ1bmNpb25hbGlkYWRlcyBxdWUgc8OjbyBhY2lvbmFkYXMgZW0gcXVhbHF1ZXIgdGVsYSBkbyBzaXN0ZW1hXG4gICAqXG4gICAqL1xuICBmdW5jdGlvbiBBcHBDb250cm9sbGVyKCRzdGF0ZSwgQXV0aCwgR2xvYmFsKSB7XG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIC8vYW5vIGF0dWFsIHBhcmEgc2VyIGV4aWJpZG8gbm8gcm9kYXDDqSBkbyBzaXN0ZW1hXG4gICAgdm0uYW5vQXR1YWwgPSBudWxsO1xuXG4gICAgdm0ubG9nb3V0ICAgICA9IGxvZ291dDtcbiAgICB2bS5nZXRJbWFnZVBlcmZpbCA9IGdldEltYWdlUGVyZmlsO1xuXG4gICAgYWN0aXZhdGUoKTtcblxuICAgIGZ1bmN0aW9uIGFjdGl2YXRlKCkge1xuICAgICAgdmFyIGRhdGUgPSBuZXcgRGF0ZSgpO1xuXG4gICAgICB2bS5hbm9BdHVhbCA9IGRhdGUuZ2V0RnVsbFllYXIoKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBsb2dvdXQoKSB7XG4gICAgICBBdXRoLmxvZ291dCgpLnRoZW4oZnVuY3Rpb24oKSB7XG4gICAgICAgICRzdGF0ZS5nbyhHbG9iYWwubG9naW5TdGF0ZSk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBnZXRJbWFnZVBlcmZpbCgpIHtcbiAgICAgIHJldHVybiAoQXV0aC5jdXJyZW50VXNlciAmJiBBdXRoLmN1cnJlbnRVc2VyLmltYWdlKVxuICAgICAgICA/IEF1dGguY3VycmVudFVzZXIuaW1hZ2VcbiAgICAgICAgOiBHbG9iYWwuaW1hZ2VQYXRoICsgJy9ub19hdmF0YXIuZ2lmJztcbiAgICB9XG5cbiAgfVxuXG59KSgpO1xuIiwiLyplc2xpbnQgYW5ndWxhci9maWxlLW5hbWU6IDAsIG5vLXVuZGVmOiAwKi9cbihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIC8qKlxuICAgKiBUcmFuc2Zvcm1hIGJpYmxpb3RlY2FzIGV4dGVybmFzIGVtIHNlcnZpw6dvcyBkbyBhbmd1bGFyIHBhcmEgc2VyIHBvc3PDrXZlbCB1dGlsaXphclxuICAgKiBhdHJhdsOpcyBkYSBpbmplw6fDo28gZGUgZGVwZW5kw6puY2lhXG4gICAqL1xuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uc3RhbnQoJ2xvZGFzaCcsIF8pXG4gICAgLmNvbnN0YW50KCdtb21lbnQnLCBtb21lbnQpO1xuXG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnN0YW50KCdHbG9iYWwnLCB7XG4gICAgICBhcHBOYW1lOiAnRnJlZWxhZ2lsZScsXG4gICAgICBob21lU3RhdGU6ICdhcHAuZGFzaGJvYXJkJyxcbiAgICAgIGxvZ2luVXJsOiAnYXBwL2xvZ2luJyxcbiAgICAgIGxvZ2luU3RhdGU6ICdhcHAubG9naW4nLFxuICAgICAgcmVzZXRQYXNzd29yZFN0YXRlOiAnYXBwLnBhc3N3b3JkLXJlc2V0JyxcbiAgICAgIG5vdEF1dGhvcml6ZWRTdGF0ZTogJ2FwcC5ub3QtYXV0aG9yaXplZCcsXG4gICAgICB0b2tlbktleTogJ3NlcnZlcl90b2tlbicsXG4gICAgICBjbGllbnRQYXRoOiAnY2xpZW50L2FwcCcsXG4gICAgICBhcGlQYXRoOiAnYXBpL3YxJyxcbiAgICAgIGltYWdlUGF0aDogJ2NsaWVudC9pbWFnZXMnXG4gICAgfSk7XG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCAkdXJsUm91dGVyUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyXG4gICAgICAuc3RhdGUoJ2FwcCcsIHtcbiAgICAgICAgdXJsOiAnL2FwcCcsXG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvbGF5b3V0L2FwcC5odG1sJyxcbiAgICAgICAgYWJzdHJhY3Q6IHRydWUsXG4gICAgICAgIHJlc29sdmU6IHsgLy9lbnN1cmUgbGFuZ3MgaXMgcmVhZHkgYmVmb3JlIHJlbmRlciB2aWV3XG4gICAgICAgICAgdHJhbnNsYXRlUmVhZHk6IFsnJHRyYW5zbGF0ZScsICckcScsIGZ1bmN0aW9uKCR0cmFuc2xhdGUsICRxKSB7XG4gICAgICAgICAgICB2YXIgZGVmZXJyZWQgPSAkcS5kZWZlcigpO1xuXG4gICAgICAgICAgICAkdHJhbnNsYXRlLnVzZSgncHQtQlInKS50aGVuKGZ1bmN0aW9uKCkge1xuICAgICAgICAgICAgICBkZWZlcnJlZC5yZXNvbHZlKCk7XG4gICAgICAgICAgICB9KTtcblxuICAgICAgICAgICAgcmV0dXJuIGRlZmVycmVkLnByb21pc2U7XG4gICAgICAgICAgfV1cbiAgICAgICAgfVxuICAgICAgfSlcbiAgICAgIC5zdGF0ZShHbG9iYWwubm90QXV0aG9yaXplZFN0YXRlLCB7XG4gICAgICAgIHVybDogJy9hY2Vzc28tbmVnYWRvJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9sYXlvdXQvbm90LWF1dGhvcml6ZWQuaHRtbCcsXG4gICAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiBmYWxzZSB9XG4gICAgICB9KTtcblxuICAgICR1cmxSb3V0ZXJQcm92aWRlci53aGVuKCcvYXBwJywgR2xvYmFsLmxvZ2luVXJsKTtcbiAgICAkdXJsUm91dGVyUHJvdmlkZXIub3RoZXJ3aXNlKEdsb2JhbC5sb2dpblVybCk7XG4gIH1cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAucnVuKHJ1bik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBydW4oJHJvb3RTY29wZSwgJHN0YXRlLCAkc3RhdGVQYXJhbXMsIEF1dGgsIEdsb2JhbCkgeyAvLyBOT1NPTkFSXG4gICAgLy9zZXRhZG8gbm8gcm9vdFNjb3BlIHBhcmEgcG9kZXIgc2VyIGFjZXNzYWRvIG5hcyB2aWV3cyBzZW0gcHJlZml4byBkZSBjb250cm9sbGVyXG4gICAgJHJvb3RTY29wZS4kc3RhdGUgPSAkc3RhdGU7XG4gICAgJHJvb3RTY29wZS4kc3RhdGVQYXJhbXMgPSAkc3RhdGVQYXJhbXM7XG4gICAgJHJvb3RTY29wZS5hdXRoID0gQXV0aDtcbiAgICAkcm9vdFNjb3BlLmdsb2JhbCA9IEdsb2JhbDtcblxuICAgIC8vbm8gaW5pY2lvIGNhcnJlZ2EgbyB1c3XDoXJpbyBkbyBsb2NhbHN0b3JhZ2UgY2FzbyBvIHVzdcOhcmlvIGVzdGFqYSBhYnJpbmRvIG8gbmF2ZWdhZG9yXG4gICAgLy9wYXJhIHZvbHRhciBhdXRlbnRpY2Fkb1xuICAgIEF1dGgucmV0cmlldmVVc2VyRnJvbUxvY2FsU3RvcmFnZSgpO1xuICB9XG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29udHJvbGxlcignQXVkaXRDb250cm9sbGVyJywgQXVkaXRDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIEF1ZGl0Q29udHJvbGxlcigkY29udHJvbGxlciwgQXVkaXRTZXJ2aWNlLCBQckRpYWxvZywgR2xvYmFsLCAkdHJhbnNsYXRlKSB7IC8vIE5PU09OQVJcbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0ub25BY3RpdmF0ZSA9IG9uQWN0aXZhdGU7XG4gICAgdm0uYXBwbHlGaWx0ZXJzID0gYXBwbHlGaWx0ZXJzO1xuICAgIHZtLnZpZXdEZXRhaWwgPSB2aWV3RGV0YWlsO1xuXG4gICAgJGNvbnRyb2xsZXIoJ0NSVURDb250cm9sbGVyJywgeyB2bTogdm0sIG1vZGVsU2VydmljZTogQXVkaXRTZXJ2aWNlLCBvcHRpb25zOiB7fSB9KTtcblxuICAgIGZ1bmN0aW9uIG9uQWN0aXZhdGUoKSB7XG4gICAgICB2bS5tb2RlbHMgPSBbXTtcbiAgICAgIHZtLnF1ZXJ5RmlsdGVycyA9IHt9O1xuXG4gICAgICAvL1BlZ2EgdG9kb3Mgb3MgbW9kZWxzIGRvIHNlcnZlciBlIG1vbnRhIHVtYSBsaXN0YSBwcm8gQ29tYm9Cb3hcbiAgICAgIEF1ZGl0U2VydmljZS5nZXRBdWRpdGVkTW9kZWxzKCkudGhlbihmdW5jdGlvbihkYXRhKSB7XG4gICAgICAgIHZhciBtb2RlbHMgPSBbeyBpZDogJycsIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ2dsb2JhbC5hbGwnKSB9XTtcblxuICAgICAgICBkYXRhLm1vZGVscy5zb3J0KCk7XG5cbiAgICAgICAgZm9yICh2YXIgaW5kZXggPSAwOyBpbmRleCA8IGRhdGEubW9kZWxzLmxlbmd0aDsgaW5kZXgrKykge1xuICAgICAgICAgIHZhciBtb2RlbCA9IGRhdGEubW9kZWxzW2luZGV4XTtcblxuICAgICAgICAgIG1vZGVscy5wdXNoKHtcbiAgICAgICAgICAgIGlkOiBtb2RlbCxcbiAgICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ21vZGVscy4nICsgbW9kZWwudG9Mb3dlckNhc2UoKSlcbiAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHZtLm1vZGVscyA9IG1vZGVscztcbiAgICAgICAgdm0ucXVlcnlGaWx0ZXJzLm1vZGVsID0gdm0ubW9kZWxzWzBdLmlkO1xuICAgICAgfSk7XG5cbiAgICAgIHZtLnR5cGVzID0gQXVkaXRTZXJ2aWNlLmxpc3RUeXBlcygpO1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzLnR5cGUgPSB2bS50eXBlc1swXS5pZDtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBhcHBseUZpbHRlcnMoZGVmYXVsdFF1ZXJ5RmlsdGVycykge1xuICAgICAgcmV0dXJuIGFuZ3VsYXIuZXh0ZW5kKGRlZmF1bHRRdWVyeUZpbHRlcnMsIHZtLnF1ZXJ5RmlsdGVycyk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gdmlld0RldGFpbChhdWRpdERldGFpbCkge1xuICAgICAgdmFyIGNvbmZpZyA9IHtcbiAgICAgICAgbG9jYWxzOiB7IGF1ZGl0RGV0YWlsOiBhdWRpdERldGFpbCB9LFxuICAgICAgICAvKiogQG5nSW5qZWN0ICovXG4gICAgICAgIGNvbnRyb2xsZXI6IGZ1bmN0aW9uKGF1ZGl0RGV0YWlsLCBQckRpYWxvZykge1xuICAgICAgICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICAgICAgICB2bS5jbG9zZSA9IGNsb3NlO1xuXG4gICAgICAgICAgYWN0aXZhdGUoKTtcblxuICAgICAgICAgIGZ1bmN0aW9uIGFjdGl2YXRlKCkge1xuICAgICAgICAgICAgaWYgKGFuZ3VsYXIuaXNBcnJheShhdWRpdERldGFpbC5vbGQpICYmIGF1ZGl0RGV0YWlsLm9sZC5sZW5ndGggPT09IDApIGF1ZGl0RGV0YWlsLm9sZCA9IG51bGw7XG4gICAgICAgICAgICBpZiAoYW5ndWxhci5pc0FycmF5KGF1ZGl0RGV0YWlsLm5ldykgJiYgYXVkaXREZXRhaWwubmV3Lmxlbmd0aCA9PT0gMCkgYXVkaXREZXRhaWwubmV3ID0gbnVsbDtcblxuICAgICAgICAgICAgdm0uYXVkaXREZXRhaWwgPSBhdWRpdERldGFpbDtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICBmdW5jdGlvbiBjbG9zZSgpIHtcbiAgICAgICAgICAgIFByRGlhbG9nLmNsb3NlKCk7XG4gICAgICAgICAgfVxuXG4gICAgICAgIH0sXG4gICAgICAgIGNvbnRyb2xsZXJBczogJ2F1ZGl0RGV0YWlsQ3RybCcsXG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvYXVkaXQvYXVkaXQtZGV0YWlsLmh0bWwnLFxuICAgICAgICBoYXNCYWNrZHJvcDogdHJ1ZVxuICAgICAgfTtcblxuICAgICAgUHJEaWFsb2cuY3VzdG9tKGNvbmZpZyk7XG4gICAgfVxuXG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb25maWcocm91dGVzKTtcblxuICAvKipcbiAgICogQXJxdWl2byBkZSBjb25maWd1cmHDp8OjbyBjb20gYXMgcm90YXMgZXNwZWPDrWZpY2FzIGRlIGF1ZGl0b3JpYVxuICAgKlxuICAgKiBAcGFyYW0ge2FueX0gJHN0YXRlUHJvdmlkZXJcbiAgICogQHBhcmFtIHthbnl9IEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyXG4gICAgICAuc3RhdGUoJ2FwcC5hdWRpdCcsIHtcbiAgICAgICAgdXJsOiAnL2F1ZGl0b3JpYScsXG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvYXVkaXQvYXVkaXQuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdBdWRpdENvbnRyb2xsZXIgYXMgYXVkaXRDdHJsJyxcbiAgICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IHRydWUsIG5lZWRQcm9maWxlOiBbJ2FkbWluJ10gfVxuICAgICAgfSk7XG5cbiAgfVxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5mYWN0b3J5KCdBdWRpdFNlcnZpY2UnLCBBdWRpdFNlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gQXVkaXRTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5LCAkdHJhbnNsYXRlKSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCdhdWRpdCcsIHtcbiAgICAgIGFjdGlvbnM6IHtcbiAgICAgICAgZ2V0QXVkaXRlZE1vZGVsczoge1xuICAgICAgICAgIG1ldGhvZDogJ0dFVCcsXG4gICAgICAgICAgdXJsOiAnbW9kZWxzJ1xuICAgICAgICB9XG4gICAgICB9LFxuICAgICAgaW5zdGFuY2U6IHtcbiAgICAgIH0sXG4gICAgICBsaXN0VHlwZXM6IGZ1bmN0aW9uKCkge1xuICAgICAgICB2YXIgYXVkaXRQYXRoID0gJ3ZpZXdzLmZpZWxkcy5hdWRpdC4nO1xuXG4gICAgICAgIHJldHVybiBbXG4gICAgICAgICAgeyBpZDogJycsIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoYXVkaXRQYXRoICsgJ2FsbFJlc291cmNlcycpIH0sXG4gICAgICAgICAgeyBpZDogJ2NyZWF0ZWQnLCBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KGF1ZGl0UGF0aCArICd0eXBlLmNyZWF0ZWQnKSB9LFxuICAgICAgICAgIHsgaWQ6ICd1cGRhdGVkJywgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudChhdWRpdFBhdGggKyAndHlwZS51cGRhdGVkJykgfSxcbiAgICAgICAgICB7IGlkOiAnZGVsZXRlZCcsIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoYXVkaXRQYXRoICsgJ3R5cGUuZGVsZXRlZCcpIH1cbiAgICAgICAgXTtcbiAgICAgIH1cbiAgICB9KTtcbiAgfVxuXG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKlxuICAgKiBBcnF1aXZvIGRlIGNvbmZpZ3VyYcOnw6NvIGNvbSBhcyByb3RhcyBlc3BlY8OtZmljYXMgZG8gcmVjdXJzbyB1c2VyXG4gICAqXG4gICAqIEBwYXJhbSB7YW55fSAkc3RhdGVQcm92aWRlclxuICAgKiBAcGFyYW0ge2FueX0gR2xvYmFsXG4gICAqL1xuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvdXRlcygkc3RhdGVQcm92aWRlciwgR2xvYmFsKSB7XG4gICAgJHN0YXRlUHJvdmlkZXJcbiAgICAgIC5zdGF0ZShHbG9iYWwucmVzZXRQYXNzd29yZFN0YXRlLCB7XG4gICAgICAgIHVybDogJy9wYXNzd29yZC9yZXNldC86dG9rZW4nLFxuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL2F1dGgvcmVzZXQtcGFzcy1mb3JtLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnUGFzc3dvcmRDb250cm9sbGVyIGFzIHBhc3NDdHJsJyxcbiAgICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IGZhbHNlIH1cbiAgICAgIH0pXG4gICAgICAuc3RhdGUoR2xvYmFsLmxvZ2luU3RhdGUsIHtcbiAgICAgICAgdXJsOiAnL2xvZ2luJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9hdXRoL2xvZ2luLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnTG9naW5Db250cm9sbGVyIGFzIGxvZ2luQ3RybCcsXG4gICAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiBmYWxzZSB9XG4gICAgICB9KTtcblxuICB9XG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZhY3RvcnkoJ0F1dGgnLCBBdXRoKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIEF1dGgoJGh0dHAsICRxLCBHbG9iYWwsIFVzZXJzU2VydmljZSkgeyAvLyBOT1NPTkFSXG4gICAgdmFyIGF1dGggPSB7XG4gICAgICBsb2dpbjogbG9naW4sXG4gICAgICBsb2dvdXQ6IGxvZ291dCxcbiAgICAgIHVwZGF0ZUN1cnJlbnRVc2VyOiB1cGRhdGVDdXJyZW50VXNlcixcbiAgICAgIHJldHJpZXZlVXNlckZyb21Mb2NhbFN0b3JhZ2U6IHJldHJpZXZlVXNlckZyb21Mb2NhbFN0b3JhZ2UsXG4gICAgICBhdXRoZW50aWNhdGVkOiBhdXRoZW50aWNhdGVkLFxuICAgICAgc2VuZEVtYWlsUmVzZXRQYXNzd29yZDogc2VuZEVtYWlsUmVzZXRQYXNzd29yZCxcbiAgICAgIHJlbW90ZVZhbGlkYXRlVG9rZW46IHJlbW90ZVZhbGlkYXRlVG9rZW4sXG4gICAgICBnZXRUb2tlbjogZ2V0VG9rZW4sXG4gICAgICBzZXRUb2tlbjogc2V0VG9rZW4sXG4gICAgICBjbGVhclRva2VuOiBjbGVhclRva2VuLFxuICAgICAgY3VycmVudFVzZXI6IG51bGxcbiAgICB9O1xuXG4gICAgZnVuY3Rpb24gY2xlYXJUb2tlbigpIHtcbiAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKEdsb2JhbC50b2tlbktleSk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gc2V0VG9rZW4odG9rZW4pIHtcbiAgICAgIGxvY2FsU3RvcmFnZS5zZXRJdGVtKEdsb2JhbC50b2tlbktleSwgdG9rZW4pO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGdldFRva2VuKCkge1xuICAgICAgcmV0dXJuIGxvY2FsU3RvcmFnZS5nZXRJdGVtKEdsb2JhbC50b2tlbktleSk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gcmVtb3RlVmFsaWRhdGVUb2tlbigpIHtcbiAgICAgIHZhciBkZWZlcnJlZCA9ICRxLmRlZmVyKCk7XG5cbiAgICAgIGlmIChhdXRoLmF1dGhlbnRpY2F0ZWQoKSkge1xuICAgICAgICAkaHR0cC5nZXQoR2xvYmFsLmFwaVBhdGggKyAnL2F1dGhlbnRpY2F0ZS9jaGVjaycpXG4gICAgICAgICAgLnRoZW4oZnVuY3Rpb24oKSB7XG4gICAgICAgICAgICBkZWZlcnJlZC5yZXNvbHZlKHRydWUpO1xuICAgICAgICAgIH0sIGZ1bmN0aW9uKCkge1xuICAgICAgICAgICAgYXV0aC5sb2dvdXQoKTtcblxuICAgICAgICAgICAgZGVmZXJyZWQucmVqZWN0KGZhbHNlKTtcbiAgICAgICAgICB9KTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIGF1dGgubG9nb3V0KCk7XG5cbiAgICAgICAgZGVmZXJyZWQucmVqZWN0KGZhbHNlKTtcbiAgICAgIH1cblxuICAgICAgcmV0dXJuIGRlZmVycmVkLnByb21pc2U7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogVmVyaWZpY2Egc2UgbyB1c3XDoXJpbyBlc3TDoSBhdXRlbnRpY2Fkb1xuICAgICAqXG4gICAgICogQHJldHVybnMge2Jvb2xlYW59XG4gICAgICovXG4gICAgZnVuY3Rpb24gYXV0aGVudGljYXRlZCgpIHtcbiAgICAgIHJldHVybiBhdXRoLmdldFRva2VuKCkgIT09IG51bGxcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWN1cGVyYSBvIHVzdcOhcmlvIGRvIGxvY2FsU3RvcmFnZVxuICAgICAqL1xuICAgIGZ1bmN0aW9uIHJldHJpZXZlVXNlckZyb21Mb2NhbFN0b3JhZ2UoKSB7XG4gICAgICB2YXIgdXNlciA9IGxvY2FsU3RvcmFnZS5nZXRJdGVtKCd1c2VyJyk7XG5cbiAgICAgIGlmICh1c2VyKSB7XG4gICAgICAgIGF1dGguY3VycmVudFVzZXIgPSBhbmd1bGFyLm1lcmdlKG5ldyBVc2Vyc1NlcnZpY2UoKSwgYW5ndWxhci5mcm9tSnNvbih1c2VyKSk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogR3VhcmRhIG8gdXN1w6FyaW8gbm8gbG9jYWxTdG9yYWdlIHBhcmEgY2FzbyBvIHVzdcOhcmlvIGZlY2hlIGUgYWJyYSBvIG5hdmVnYWRvclxuICAgICAqIGRlbnRybyBkbyB0ZW1wbyBkZSBzZXNzw6NvIHNlamEgcG9zc8OtdmVsIHJlY3VwZXJhciBvIHRva2VuIGF1dGVudGljYWRvLlxuICAgICAqXG4gICAgICogTWFudMOpbSBhIHZhcmnDoXZlbCBhdXRoLmN1cnJlbnRVc2VyIHBhcmEgZmFjaWxpdGFyIG8gYWNlc3NvIGFvIHVzdcOhcmlvIGxvZ2FkbyBlbSB0b2RhIGEgYXBsaWNhw6fDo29cbiAgICAgKlxuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IHVzZXIgVXN1w6FyaW8gYSBzZXIgYXR1YWxpemFkby4gQ2FzbyBzZWphIHBhc3NhZG8gbnVsbCBsaW1wYVxuICAgICAqIHRvZGFzIGFzIGluZm9ybWHDp8O1ZXMgZG8gdXN1w6FyaW8gY29ycmVudGUuXG4gICAgICovXG4gICAgZnVuY3Rpb24gdXBkYXRlQ3VycmVudFVzZXIodXNlcikge1xuICAgICAgdmFyIGRlZmVycmVkID0gJHEuZGVmZXIoKTtcblxuICAgICAgaWYgKHVzZXIpIHtcbiAgICAgICAgdXNlciA9IGFuZ3VsYXIubWVyZ2UobmV3IFVzZXJzU2VydmljZSgpLCB1c2VyKTtcblxuICAgICAgICB2YXIganNvblVzZXIgPSBhbmd1bGFyLnRvSnNvbih1c2VyKTtcblxuICAgICAgICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbSgndXNlcicsIGpzb25Vc2VyKTtcbiAgICAgICAgYXV0aC5jdXJyZW50VXNlciA9IHVzZXI7XG5cbiAgICAgICAgZGVmZXJyZWQucmVzb2x2ZSh1c2VyKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKCd1c2VyJyk7XG4gICAgICAgIGF1dGguY3VycmVudFVzZXIgPSBudWxsO1xuICAgICAgICBhdXRoLmNsZWFyVG9rZW4oKTtcblxuICAgICAgICBkZWZlcnJlZC5yZWplY3QoKTtcbiAgICAgIH1cblxuICAgICAgcmV0dXJuIGRlZmVycmVkLnByb21pc2U7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhbGl6YSBvIGxvZ2luIGRvIHVzdcOhcmlvXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gY3JlZGVudGlhbHMgRW1haWwgZSBTZW5oYSBkbyB1c3XDoXJpb1xuICAgICAqIEByZXR1cm5zIHtwcm9taXNlfSBVbWEgcHJvbWlzZSBjb20gbyByZXN1bHRhZG8gZG8gY2hhbWFkYSBubyBiYWNrZW5kXG4gICAgICovXG4gICAgZnVuY3Rpb24gbG9naW4oY3JlZGVudGlhbHMpIHtcbiAgICAgIHZhciBkZWZlcnJlZCA9ICRxLmRlZmVyKCk7XG5cbiAgICAgICRodHRwLnBvc3QoR2xvYmFsLmFwaVBhdGggKyAnL2F1dGhlbnRpY2F0ZScsIGNyZWRlbnRpYWxzKVxuICAgICAgICAudGhlbihmdW5jdGlvbihyZXNwb25zZSkge1xuICAgICAgICAgIGF1dGguc2V0VG9rZW4ocmVzcG9uc2UuZGF0YS50b2tlbik7XG5cbiAgICAgICAgICByZXR1cm4gJGh0dHAuZ2V0KEdsb2JhbC5hcGlQYXRoICsgJy9hdXRoZW50aWNhdGUvdXNlcicpO1xuICAgICAgICB9KVxuICAgICAgICAudGhlbihmdW5jdGlvbihyZXNwb25zZSkge1xuICAgICAgICAgIGF1dGgudXBkYXRlQ3VycmVudFVzZXIocmVzcG9uc2UuZGF0YS51c2VyKTtcblxuICAgICAgICAgIGRlZmVycmVkLnJlc29sdmUoKTtcbiAgICAgICAgfSwgZnVuY3Rpb24oZXJyb3IpIHtcbiAgICAgICAgICBhdXRoLmxvZ291dCgpO1xuXG4gICAgICAgICAgZGVmZXJyZWQucmVqZWN0KGVycm9yKTtcbiAgICAgICAgfSk7XG5cbiAgICAgIHJldHVybiBkZWZlcnJlZC5wcm9taXNlO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIERlc2xvZ2Egb3MgdXN1w6FyaW9zLiBDb21vIG7Do28gdGVuIG5lbmh1bWEgaW5mb3JtYcOnw6NvIG5hIHNlc3PDo28gZG8gc2Vydmlkb3JcbiAgICAgKiBlIHVtIHRva2VuIHVtYSB2ZXogZ2VyYWRvIG7Do28gcG9kZSwgcG9yIHBhZHLDo28sIHNlciBpbnZhbGlkYWRvIGFudGVzIGRvIHNldSB0ZW1wbyBkZSBleHBpcmHDp8OjbyxcbiAgICAgKiBzb21lbnRlIGFwYWdhbW9zIG9zIGRhZG9zIGRvIHVzdcOhcmlvIGUgbyB0b2tlbiBkbyBuYXZlZ2Fkb3IgcGFyYSBlZmV0aXZhciBvIGxvZ291dC5cbiAgICAgKlxuICAgICAqIEByZXR1cm5zIHtwcm9taXNlfSBVbWEgcHJvbWlzZSBjb20gbyByZXN1bHRhZG8gZGEgb3BlcmHDp8Ojb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGxvZ291dCgpIHtcbiAgICAgIHZhciBkZWZlcnJlZCA9ICRxLmRlZmVyKCk7XG5cbiAgICAgIGF1dGgudXBkYXRlQ3VycmVudFVzZXIobnVsbCk7XG4gICAgICBkZWZlcnJlZC5yZXNvbHZlKCk7XG5cbiAgICAgIHJldHVybiBkZWZlcnJlZC5wcm9taXNlO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEVudmlhIHVtIGVtYWlsIHBhcmEgcmVjdXBlcmHDp8OjbyBkZSBzZW5oYVxuICAgICAqIEBwYXJhbSB7T2JqZWN0fSByZXNldERhdGEgLSBPYmpldG8gY29udGVuZG8gbyBlbWFpbFxuICAgICAqIEByZXR1cm4ge1Byb21pc2V9IC0gUmV0b3JuYSB1bWEgcHJvbWlzZSBwYXJhIHNlciByZXNvbHZpZGFcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBzZW5kRW1haWxSZXNldFBhc3N3b3JkKHJlc2V0RGF0YSkge1xuICAgICAgdmFyIGRlZmVycmVkID0gJHEuZGVmZXIoKTtcblxuICAgICAgJGh0dHAucG9zdChHbG9iYWwuYXBpUGF0aCArICcvcGFzc3dvcmQvZW1haWwnLCByZXNldERhdGEpXG4gICAgICAgIC50aGVuKGZ1bmN0aW9uKHJlc3BvbnNlKSB7XG4gICAgICAgICAgZGVmZXJyZWQucmVzb2x2ZShyZXNwb25zZS5kYXRhKTtcbiAgICAgICAgfSwgZnVuY3Rpb24oZXJyb3IpIHtcbiAgICAgICAgICBkZWZlcnJlZC5yZWplY3QoZXJyb3IpO1xuICAgICAgICB9KTtcblxuICAgICAgcmV0dXJuIGRlZmVycmVkLnByb21pc2U7XG4gICAgfVxuXG4gICAgcmV0dXJuIGF1dGg7XG4gIH1cblxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnRyb2xsZXIoJ0xvZ2luQ29udHJvbGxlcicsIExvZ2luQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBMb2dpbkNvbnRyb2xsZXIoJHN0YXRlLCBBdXRoLCBHbG9iYWwsIFByRGlhbG9nKSB7XG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIHZtLmxvZ2luID0gbG9naW47XG4gICAgdm0ub3BlbkRpYWxvZ1Jlc2V0UGFzcyA9IG9wZW5EaWFsb2dSZXNldFBhc3M7XG4gICAgdm0ub3BlbkRpYWxvZ1NpZ25VcCA9IG9wZW5EaWFsb2dTaWduVXA7XG5cbiAgICBhY3RpdmF0ZSgpO1xuXG4gICAgZnVuY3Rpb24gYWN0aXZhdGUoKSB7XG4gICAgICB2bS5jcmVkZW50aWFscyA9IHt9O1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGxvZ2luKCkge1xuICAgICAgdmFyIGNyZWRlbnRpYWxzID0ge1xuICAgICAgICBlbWFpbDogdm0uY3JlZGVudGlhbHMuZW1haWwsXG4gICAgICAgIHBhc3N3b3JkOiB2bS5jcmVkZW50aWFscy5wYXNzd29yZFxuICAgICAgfTtcblxuICAgICAgQXV0aC5sb2dpbihjcmVkZW50aWFscykudGhlbihmdW5jdGlvbigpIHtcbiAgICAgICAgJHN0YXRlLmdvKEdsb2JhbC5ob21lU3RhdGUpO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogRXhpYmUgbyBkaWFsb2cgcGFyYSByZWN1cGVyYcOnw6NvIGRlIHNlbmhhXG4gICAgICovXG4gICAgZnVuY3Rpb24gb3BlbkRpYWxvZ1Jlc2V0UGFzcygpIHtcbiAgICAgIHZhciBjb25maWcgPSB7XG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvYXV0aC9zZW5kLXJlc2V0LWRpYWxvZy5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ1Bhc3N3b3JkQ29udHJvbGxlciBhcyBwYXNzQ3RybCcsXG4gICAgICAgIGhhc0JhY2tkcm9wOiB0cnVlXG4gICAgICB9XG5cbiAgICAgIFByRGlhbG9nLmN1c3RvbShjb25maWcpO1xuICAgIH1cbiAgICAvKipcbiAgICAgKiBFeGliZSBvIGRpYWxvZyBwYXJhIHJlY3VwZXJhw6fDo28gZGUgc2VuaGFcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBvcGVuRGlhbG9nU2lnblVwKCkge1xuICAgICAgdmFyIGNvbmZpZyA9IHtcbiAgICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy91c2Vycy91c2VyLWZvcm0uaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdVc2Vyc0NvbnRyb2xsZXIgYXMgdXNlcnNDdHJsJyxcbiAgICAgICAgaGFzQmFja2Ryb3A6IHRydWVcbiAgICAgIH1cblxuICAgICAgUHJEaWFsb2cuY3VzdG9tKGNvbmZpZyk7XG4gICAgfVxuXG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb250cm9sbGVyKCdQYXNzd29yZENvbnRyb2xsZXInLCBQYXNzd29yZENvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gUGFzc3dvcmRDb250cm9sbGVyKEdsb2JhbCwgJHN0YXRlUGFyYW1zLCAkaHR0cCwgJHRpbWVvdXQsICRzdGF0ZSwgLy8gTk9TT05BUlxuICAgIFByVG9hc3QsIFByRGlhbG9nLCBBdXRoLCAkdHJhbnNsYXRlKSB7XG5cbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0uc2VuZFJlc2V0ID0gc2VuZFJlc2V0O1xuICAgIHZtLmNsb3NlRGlhbG9nID0gY2xvc2VEaWFsb2c7XG4gICAgdm0uY2xlYW5Gb3JtID0gY2xlYW5Gb3JtO1xuICAgIHZtLnNlbmRFbWFpbFJlc2V0UGFzc3dvcmQgPSBzZW5kRW1haWxSZXNldFBhc3N3b3JkO1xuXG4gICAgYWN0aXZhdGUoKTtcblxuICAgIGZ1bmN0aW9uIGFjdGl2YXRlKCkge1xuICAgICAgdm0ucmVzZXQgPSB7IGVtYWlsOiAnJywgdG9rZW46ICRzdGF0ZVBhcmFtcy50b2tlbiB9O1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWxpemEgYSBhbHRlcmHDp8OjbyBkYSBzZW5oYSBkbyB1c3XDoXJpbyBlIG8gcmVkaXJlY2lvbmEgcGFyYSBhIHRlbGEgZGUgbG9naW5cbiAgICAgKi9cbiAgICBmdW5jdGlvbiBzZW5kUmVzZXQoKSB7XG4gICAgICAkaHR0cC5wb3N0KEdsb2JhbC5hcGlQYXRoICsgJy9wYXNzd29yZC9yZXNldCcsIHZtLnJlc2V0KVxuICAgICAgICAudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgUHJUb2FzdC5zdWNjZXNzKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMub3BlcmF0aW9uU3VjY2VzcycpKTtcbiAgICAgICAgICAkdGltZW91dChmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAkc3RhdGUuZ28oR2xvYmFsLmxvZ2luU3RhdGUpO1xuICAgICAgICAgIH0sIDE1MDApO1xuICAgICAgICB9LCBmdW5jdGlvbiAoZXJyb3IpIHtcbiAgICAgICAgICBpZiAoZXJyb3Iuc3RhdHVzICE9PSA0MDAgJiYgZXJyb3Iuc3RhdHVzICE9PSA1MDApIHtcbiAgICAgICAgICAgIHZhciBtc2cgPSAnJztcblxuICAgICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCBlcnJvci5kYXRhLnBhc3N3b3JkLmxlbmd0aDsgaSsrKSB7XG4gICAgICAgICAgICAgIG1zZyArPSBlcnJvci5kYXRhLnBhc3N3b3JkW2ldICsgJzxicj4nO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgUHJUb2FzdC5lcnJvcihtc2cudG9VcHBlckNhc2UoKSk7XG4gICAgICAgICAgfVxuICAgICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBFbnZpYSB1bSBlbWFpbCBkZSByZWN1cGVyYcOnw6NvIGRlIHNlbmhhIGNvbSBvIHRva2VuIGRvIHVzdcOhcmlvXG4gICAgICovXG4gICAgZnVuY3Rpb24gc2VuZEVtYWlsUmVzZXRQYXNzd29yZCgpIHtcblxuICAgICAgaWYgKHZtLnJlc2V0LmVtYWlsID09PSAnJykge1xuICAgICAgICBQclRvYXN0LmVycm9yKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMudmFsaWRhdGUuZmllbGRSZXF1aXJlZCcsIHsgZmllbGQ6ICdlbWFpbCcgfSkpO1xuICAgICAgICByZXR1cm47XG4gICAgICB9XG5cbiAgICAgIEF1dGguc2VuZEVtYWlsUmVzZXRQYXNzd29yZCh2bS5yZXNldCkudGhlbihmdW5jdGlvbiAoZGF0YSkge1xuICAgICAgICBQclRvYXN0LnN1Y2Nlc3MoZGF0YS5tZXNzYWdlKTtcblxuICAgICAgICB2bS5jbGVhbkZvcm0oKTtcbiAgICAgICAgdm0uY2xvc2VEaWFsb2coKTtcbiAgICAgIH0sIGZ1bmN0aW9uIChlcnJvcikge1xuICAgICAgICBpZiAoZXJyb3IuZGF0YS5lbWFpbCAmJiBlcnJvci5kYXRhLmVtYWlsLmxlbmd0aCA+IDApIHtcbiAgICAgICAgICB2YXIgbXNnID0gJyc7XG5cbiAgICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IGVycm9yLmRhdGEuZW1haWwubGVuZ3RoOyBpKyspIHtcbiAgICAgICAgICAgIG1zZyArPSBlcnJvci5kYXRhLmVtYWlsW2ldICsgJzxicj4nO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIFByVG9hc3QuZXJyb3IobXNnKTtcbiAgICAgICAgfVxuICAgICAgfSk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gY2xvc2VEaWFsb2coKSB7XG4gICAgICBQckRpYWxvZy5jbG9zZSgpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGNsZWFuRm9ybSgpIHtcbiAgICAgIHZtLnJlc2V0LmVtYWlsID0gJyc7XG4gICAgfVxuXG4gIH1cblxufSkoKTtcbiIsIi8qZXNsaW50IGFuZ3VsYXIvZmlsZS1uYW1lOiAwKi9cbihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5mYWN0b3J5KCdzZXJ2aWNlRmFjdG9yeScsIHNlcnZpY2VGYWN0b3J5KTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8qKlxuICAgKiBNYWlzIGluZm9ybWHDp8O1ZXM6XG4gICAqIGh0dHBzOi8vZ2l0aHViLmNvbS9zd2ltbGFuZS9hbmd1bGFyLW1vZGVsLWZhY3Rvcnkvd2lraS9BUElcbiAgICovXG4gIGZ1bmN0aW9uIHNlcnZpY2VGYWN0b3J5KCRtb2RlbEZhY3RvcnkpIHtcbiAgICByZXR1cm4gZnVuY3Rpb24odXJsLCBvcHRpb25zKSB7XG4gICAgICB2YXIgbW9kZWw7XG4gICAgICB2YXIgZGVmYXVsdE9wdGlvbnMgPSB7XG4gICAgICAgIGFjdGlvbnM6IHtcbiAgICAgICAgICAvKipcbiAgICAgICAgICAgKiBTZXJ2acOnbyBjb211bSBwYXJhIHJlYWxpemFyIGJ1c2NhIGNvbSBwYWdpbmHDp8Ojb1xuICAgICAgICAgICAqIE8gbWVzbW8gZXNwZXJhIHF1ZSBzZWphIHJldG9ybmFkbyB1bSBvYmpldG8gY29tIGl0ZW1zIGUgdG90YWxcbiAgICAgICAgICAgKi9cbiAgICAgICAgICBwYWdpbmF0ZToge1xuICAgICAgICAgICAgbWV0aG9kOiAnR0VUJyxcbiAgICAgICAgICAgIGlzQXJyYXk6IGZhbHNlLFxuICAgICAgICAgICAgd3JhcDogZmFsc2UsXG4gICAgICAgICAgICBhZnRlclJlcXVlc3Q6IGZ1bmN0aW9uKHJlc3BvbnNlKSB7XG4gICAgICAgICAgICAgIGlmIChyZXNwb25zZVsnaXRlbXMnXSkge1xuICAgICAgICAgICAgICAgIHJlc3BvbnNlWydpdGVtcyddID0gbW9kZWwuTGlzdChyZXNwb25zZVsnaXRlbXMnXSk7XG4gICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICByZXR1cm4gcmVzcG9uc2U7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICB9XG5cbiAgICAgIG1vZGVsID0gJG1vZGVsRmFjdG9yeSh1cmwsIGFuZ3VsYXIubWVyZ2UoZGVmYXVsdE9wdGlvbnMsIG9wdGlvbnMpKVxuXG4gICAgICByZXR1cm4gbW9kZWw7XG4gICAgfVxuICB9XG59KSgpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29udHJvbGxlcignQ1JVRENvbnRyb2xsZXInLCBDUlVEQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvKipcbiAgICogQ29udHJvbGFkb3IgQmFzZSBxdWUgaW1wbGVtZW50YSB0b2RhcyBhcyBmdW7Dp8O1ZXMgcGFkcsO1ZXMgZGUgdW0gQ1JVRFxuICAgKlxuICAgKiBBw6fDtWVzIGltcGxlbWVudGFkYXNcbiAgICogYWN0aXZhdGUoKVxuICAgKiBzZWFyY2gocGFnZSlcbiAgICogZWRpdChyZXNvdXJjZSlcbiAgICogc2F2ZSgpXG4gICAqIHJlbW92ZShyZXNvdXJjZSlcbiAgICogZ29Ubyh2aWV3TmFtZSlcbiAgICogY2xlYW5Gb3JtKClcbiAgICpcbiAgICogR2F0aWxob3NcbiAgICpcbiAgICogb25BY3RpdmF0ZSgpXG4gICAqIGFwcGx5RmlsdGVycyhkZWZhdWx0UXVlcnlGaWx0ZXJzKVxuICAgKiBiZWZvcmVTZWFyY2gocGFnZSkgLy9yZXRvcm5hbmRvIGZhbHNlIGNhbmNlbGEgbyBmbHV4b1xuICAgKiBhZnRlclNlYXJjaChyZXNwb25zZSlcbiAgICogYmVmb3JlQ2xlYW4gLy9yZXRvcm5hbmRvIGZhbHNlIGNhbmNlbGEgbyBmbHV4b1xuICAgKiBhZnRlckNsZWFuKClcbiAgICogYmVmb3JlU2F2ZSgpIC8vcmV0b3JuYW5kbyBmYWxzZSBjYW5jZWxhIG8gZmx1eG9cbiAgICogYWZ0ZXJTYXZlKHJlc291cmNlKVxuICAgKiBvblNhdmVFcnJvcihlcnJvcilcbiAgICogYmVmb3JlUmVtb3ZlKHJlc291cmNlKSAvL3JldG9ybmFuZG8gZmFsc2UgY2FuY2VsYSBvIGZsdXhvXG4gICAqIGFmdGVyUmVtb3ZlKHJlc291cmNlKVxuICAgKlxuICAgKiBAcGFyYW0ge2FueX0gdm0gaW5zdGFuY2lhIGRvIGNvbnRyb2xsZXIgZmlsaG9cbiAgICogQHBhcmFtIHthbnl9IG1vZGVsU2VydmljZSBzZXJ2acOnbyBkbyBtb2RlbCBxdWUgdmFpIHNlciB1dGlsaXphZG9cbiAgICogQHBhcmFtIHthbnl9IG9wdGlvbnMgb3DDp8O1ZXMgcGFyYSBzb2JyZWVzY3JldmVyIGNvbXBvcnRhbWVudG9zIHBhZHLDtWVzXG4gICAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBDUlVEQ29udHJvbGxlcih2bSwgbW9kZWxTZXJ2aWNlLCBvcHRpb25zLCBQclRvYXN0LCBQclBhZ2luYXRpb24sIC8vIE5PU09OQVJcbiAgICBQckRpYWxvZywgJHRyYW5zbGF0ZSkge1xuXG4gICAgLy9GdW5jdGlvbnMgQmxvY2tcbiAgICB2bS5zZWFyY2ggPSBzZWFyY2g7XG4gICAgdm0ucGFnaW5hdGVTZWFyY2ggPSBwYWdpbmF0ZVNlYXJjaDtcbiAgICB2bS5ub3JtYWxTZWFyY2ggPSBub3JtYWxTZWFyY2g7XG4gICAgdm0uZWRpdCA9IGVkaXQ7XG4gICAgdm0uc2F2ZSA9IHNhdmU7XG4gICAgdm0ucmVtb3ZlID0gcmVtb3ZlO1xuICAgIHZtLmdvVG8gPSBnb1RvO1xuICAgIHZtLmNsZWFuRm9ybSA9IGNsZWFuRm9ybTtcblxuICAgIGFjdGl2YXRlKCk7XG5cbiAgICAvKipcbiAgICAgKiBQcmVwYXJhIG8gY29udHJvbGFkb3JcbiAgICAgKiBGYXogbyBtZXJnZSBkYXMgb3DDp8O1ZXNcbiAgICAgKiBJbmljaWFsaXphIG8gcmVjdXJzb1xuICAgICAqIEluaWNpYWxpemEgbyBvYmpldG8gcGFnaW5hZG9yIGUgcmVhbGl6YSBhIHBlc3F1aXNhXG4gICAgICovXG4gICAgZnVuY3Rpb24gYWN0aXZhdGUoKSB7XG4gICAgICB2bS5kZWZhdWx0T3B0aW9ucyA9IHtcbiAgICAgICAgcmVkaXJlY3RBZnRlclNhdmU6IHRydWUsXG4gICAgICAgIHNlYXJjaE9uSW5pdDogdHJ1ZSxcbiAgICAgICAgcGVyUGFnZTogOCxcbiAgICAgICAgc2tpcFBhZ2luYXRpb246IGZhbHNlXG4gICAgICB9XG5cbiAgICAgIGFuZ3VsYXIubWVyZ2Uodm0uZGVmYXVsdE9wdGlvbnMsIG9wdGlvbnMpO1xuXG4gICAgICB2bS52aWV3Rm9ybSA9IGZhbHNlO1xuICAgICAgdm0ucmVzb3VyY2UgPSBuZXcgbW9kZWxTZXJ2aWNlKCk7XG5cbiAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0ub25BY3RpdmF0ZSkpIHZtLm9uQWN0aXZhdGUoKTtcblxuICAgICAgdm0ucGFnaW5hdG9yID0gUHJQYWdpbmF0aW9uLmdldEluc3RhbmNlKHZtLnNlYXJjaCwgdm0uZGVmYXVsdE9wdGlvbnMucGVyUGFnZSk7XG5cbiAgICAgIGlmICh2bS5kZWZhdWx0T3B0aW9ucy5zZWFyY2hPbkluaXQpIHZtLnNlYXJjaCgpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWxpemEgYSBwZXNxdWlzYVxuICAgICAqIFZlcmlmaWNhIHF1YWwgZGFzIGZ1bsOnw7VlcyBkZSBwZXNxdWlzYSBkZXZlIHNlciByZWFsaXphZGEuXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gcGFnZSBww6FnaW5hIHF1ZSBkZXZlIHNlciBjYXJyZWdhZGFcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBzZWFyY2gocGFnZSkge1xuICAgICAgKHZtLmRlZmF1bHRPcHRpb25zLnNraXBQYWdpbmF0aW9uKSA/IG5vcm1hbFNlYXJjaCgpIDogcGFnaW5hdGVTZWFyY2gocGFnZSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhbGl6YSBhIHBlc3F1aXNhIHBhZ2luYWRhIGNvbSBiYXNlIG5vcyBmaWx0cm9zIGRlZmluaWRvc1xuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IHBhZ2UgcMOhZ2luYSBxdWUgZGV2ZSBzZXIgY2FycmVnYWRhXG4gICAgICovXG4gICAgZnVuY3Rpb24gcGFnaW5hdGVTZWFyY2gocGFnZSkge1xuICAgICAgdm0ucGFnaW5hdG9yLmN1cnJlbnRQYWdlID0gKGFuZ3VsYXIuaXNEZWZpbmVkKHBhZ2UpKSA/IHBhZ2UgOiAxO1xuICAgICAgdm0uZGVmYXVsdFF1ZXJ5RmlsdGVycyA9IHsgcGFnZTogdm0ucGFnaW5hdG9yLmN1cnJlbnRQYWdlLCBwZXJQYWdlOiB2bS5wYWdpbmF0b3IucGVyUGFnZSB9O1xuXG4gICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmFwcGx5RmlsdGVycykpIHZtLmRlZmF1bHRRdWVyeUZpbHRlcnMgPSB2bS5hcHBseUZpbHRlcnModm0uZGVmYXVsdFF1ZXJ5RmlsdGVycyk7XG4gICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmJlZm9yZVNlYXJjaCkgJiYgdm0uYmVmb3JlU2VhcmNoKHBhZ2UpID09PSBmYWxzZSkgcmV0dXJuIGZhbHNlO1xuXG4gICAgICBtb2RlbFNlcnZpY2UucGFnaW5hdGUodm0uZGVmYXVsdFF1ZXJ5RmlsdGVycykudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgdm0ucGFnaW5hdG9yLmNhbGNOdW1iZXJPZlBhZ2VzKHJlc3BvbnNlLnRvdGFsKTtcbiAgICAgICAgdm0ucmVzb3VyY2VzID0gcmVzcG9uc2UuaXRlbXM7XG5cbiAgICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5hZnRlclNlYXJjaCkpIHZtLmFmdGVyU2VhcmNoKHJlc3BvbnNlKTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWxpemEgYSBwZXNxdWlzYSBjb20gYmFzZSBub3MgZmlsdHJvcyBkZWZpbmlkb3NcbiAgICAgKlxuICAgICAqL1xuICAgIGZ1bmN0aW9uIG5vcm1hbFNlYXJjaCgpIHtcbiAgICAgIHZtLmRlZmF1bHRRdWVyeUZpbHRlcnMgPSB7IH07XG5cbiAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYXBwbHlGaWx0ZXJzKSkgdm0uZGVmYXVsdFF1ZXJ5RmlsdGVycyA9IHZtLmFwcGx5RmlsdGVycyh2bS5kZWZhdWx0UXVlcnlGaWx0ZXJzKTtcbiAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYmVmb3JlU2VhcmNoKSAmJiB2bS5iZWZvcmVTZWFyY2goKSA9PT0gZmFsc2UpIHJldHVybiBmYWxzZTtcblxuICAgICAgbW9kZWxTZXJ2aWNlLnF1ZXJ5KHZtLmRlZmF1bHRRdWVyeUZpbHRlcnMpLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgIHZtLnJlc291cmNlcyA9IHJlc3BvbnNlO1xuXG4gICAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYWZ0ZXJTZWFyY2gpKSB2bS5hZnRlclNlYXJjaChyZXNwb25zZSk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBMaW1wYSBvIGZvcm11bMOhcmlvXG4gICAgICovXG4gICAgZnVuY3Rpb24gY2xlYW5Gb3JtKGZvcm0pIHtcbiAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYmVmb3JlQ2xlYW4pICYmIHZtLmJlZm9yZUNsZWFuKCkgPT09IGZhbHNlKSByZXR1cm4gZmFsc2U7XG5cbiAgICAgIHZtLnJlc291cmNlID0gbmV3IG1vZGVsU2VydmljZSgpO1xuXG4gICAgICBpZiAoYW5ndWxhci5pc0RlZmluZWQoZm9ybSkpIHtcbiAgICAgICAgZm9ybS4kc2V0UHJpc3RpbmUoKTtcbiAgICAgICAgZm9ybS4kc2V0VW50b3VjaGVkKCk7XG4gICAgICB9XG5cbiAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYWZ0ZXJDbGVhbikpIHZtLmFmdGVyQ2xlYW4oKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDYXJyZWdhIG5vIGZvcm11bMOhcmlvIG8gcmVjdXJzbyBzZWxlY2lvbmFkbyBwYXJhIGVkacOnw6NvXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gcmVzb3VyY2UgcmVjdXJzbyBzZWxlY2lvbmFkb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGVkaXQocmVzb3VyY2UpIHtcbiAgICAgIHZtLmdvVG8oJ2Zvcm0nKTtcbiAgICAgIHZtLnJlc291cmNlID0gbmV3IGFuZ3VsYXIuY29weShyZXNvdXJjZSk7XG5cbiAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYWZ0ZXJFZGl0KSkgdm0uYWZ0ZXJFZGl0KCk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogU2FsdmEgb3UgYXR1YWxpemEgbyByZWN1cnNvIGNvcnJlbnRlIG5vIGZvcm11bMOhcmlvXG4gICAgICogTm8gY29tcG9ydGFtZW50byBwYWRyw6NvIHJlZGlyZWNpb25hIG8gdXN1w6FyaW8gcGFyYSB2aWV3IGRlIGxpc3RhZ2VtXG4gICAgICogZGVwb2lzIGRhIGV4ZWN1w6fDo29cbiAgICAgKlxuICAgICAqIEByZXR1cm5zXG4gICAgICovXG4gICAgZnVuY3Rpb24gc2F2ZShmb3JtKSB7XG4gICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmJlZm9yZVNhdmUpICYmIHZtLmJlZm9yZVNhdmUoKSA9PT0gZmFsc2UpIHJldHVybiBmYWxzZTtcblxuICAgICAgdm0ucmVzb3VyY2UuJHNhdmUoKS50aGVuKGZ1bmN0aW9uIChyZXNvdXJjZSkge1xuICAgICAgICB2bS5yZXNvdXJjZSA9IHJlc291cmNlO1xuXG4gICAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYWZ0ZXJTYXZlKSkgdm0uYWZ0ZXJTYXZlKHJlc291cmNlKTtcblxuICAgICAgICBpZiAodm0uZGVmYXVsdE9wdGlvbnMucmVkaXJlY3RBZnRlclNhdmUpIHtcbiAgICAgICAgICB2bS5jbGVhbkZvcm0oZm9ybSk7XG4gICAgICAgICAgdm0uc2VhcmNoKHZtLnBhZ2luYXRvci5jdXJyZW50UGFnZSk7XG4gICAgICAgICAgdm0uZ29UbygnbGlzdCcpO1xuICAgICAgICB9XG5cbiAgICAgICAgUHJUb2FzdC5zdWNjZXNzKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMuc2F2ZVN1Y2Nlc3MnKSk7XG5cbiAgICAgIH0sIGZ1bmN0aW9uIChyZXNwb25zZURhdGEpIHtcbiAgICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5vblNhdmVFcnJvcikpIHZtLm9uU2F2ZUVycm9yKHJlc3BvbnNlRGF0YSk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZW1vdmUgbyByZWN1cnNvIGluZm9ybWFkby5cbiAgICAgKiBBbnRlcyBleGliZSB1bSBkaWFsb2dvIGRlIGNvbmZpcm1hw6fDo29cbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSByZXNvdXJjZSByZWN1cnNvIGVzY29saGlkb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIHJlbW92ZShyZXNvdXJjZSkge1xuICAgICAgdmFyIGNvbmZpZyA9IHtcbiAgICAgICAgdGl0bGU6ICR0cmFuc2xhdGUuaW5zdGFudCgnZGlhbG9nLmNvbmZpcm1UaXRsZScpLFxuICAgICAgICBkZXNjcmlwdGlvbjogJHRyYW5zbGF0ZS5pbnN0YW50KCdkaWFsb2cuY29uZmlybURlc2NyaXB0aW9uJylcbiAgICAgIH1cblxuICAgICAgUHJEaWFsb2cuY29uZmlybShjb25maWcpLnRoZW4oZnVuY3Rpb24oKSB7XG4gICAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYmVmb3JlUmVtb3ZlKSAmJiB2bS5iZWZvcmVSZW1vdmUocmVzb3VyY2UpID09PSBmYWxzZSkgcmV0dXJuIGZhbHNlO1xuXG4gICAgICAgIHJlc291cmNlLiRkZXN0cm95KCkudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5hZnRlclJlbW92ZSkpIHZtLmFmdGVyUmVtb3ZlKHJlc291cmNlKTtcblxuICAgICAgICAgIHZtLnNlYXJjaCgpO1xuICAgICAgICAgIFByVG9hc3QuaW5mbygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnJlbW92ZVN1Y2Nlc3MnKSk7XG4gICAgICAgIH0pO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQWx0ZXJuYSBlbnRyZSBhIHZpZXcgZG8gZm9ybXVsw6FyaW8gZSBsaXN0YWdlbVxuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IHZpZXdOYW1lIG5vbWUgZGEgdmlld1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGdvVG8odmlld05hbWUpIHtcbiAgICAgIHZtLnZpZXdGb3JtID0gZmFsc2U7XG5cbiAgICAgIGlmICh2aWV3TmFtZSA9PT0gJ2Zvcm0nKSB7XG4gICAgICAgIHZtLmNsZWFuRm9ybSgpO1xuICAgICAgICB2bS52aWV3Rm9ybSA9IHRydWU7XG4gICAgICB9XG4gICAgfVxuICB9XG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb250cm9sbGVyKCdEYXNoYm9hcmRDb250cm9sbGVyJywgRGFzaGJvYXJkQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvKipcbiAgICogRGFzaGJvYXJkIENvbnRyb2xsZXJcbiAgICpcbiAgICogUGFpbmVsIGNvbSBwcmluY2lwYWlzIGluZGljYWRvcmVzXG4gICAqXG4gICAqL1xuICBmdW5jdGlvbiBEYXNoYm9hcmRDb250cm9sbGVyKCkge1xuICAgIC8vIENvbnRyb2xsZXIgdmF6aW8gc29tZW50ZSBwYXJhIHNlciBkZWZpbmlkbyBjb21vIHDDoWdpbmEgcHJpbmNpcGFsLlxuICAgIC8vIERldmUgc2VyIGlkZW50aWZpY2FkbyBlIGFkaWNpb25hZG8gZ3LDoWZpY29zXG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb25maWcocm91dGVzKTtcblxuICAvKipcbiAgICogQXJxdWl2byBkZSBjb25maWd1cmHDp8OjbyBjb20gYXMgcm90YXMgZXNwZWPDrWZpY2FzIGRvIGRhc2hib2FyZFxuICAgKlxuICAgKiBAcGFyYW0ge2FueX0gJHN0YXRlUHJvdmlkZXJcbiAgICogQHBhcmFtIHthbnl9IEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyXG4gICAgICAuc3RhdGUoR2xvYmFsLmhvbWVTdGF0ZSwge1xuICAgICAgICB1cmw6ICcvZGFzaGJvYXJkJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9kYXNoYm9hcmQvZGFzaGJvYXJkLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnRGFzaGJvYXJkQ29udHJvbGxlciBhcyBkYXNoYm9hcmRDdHJsJyxcbiAgICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IHRydWUgfVxuICAgICAgfSlcbiAgfVxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb25maWcocm91dGVzKTtcblxuICAvKipcbiAgICogQXJxdWl2byBkZSBjb25maWd1cmHDp8OjbyBjb20gYXMgcm90YXMgZXNwZWPDrWZpY2FzIGRvIHJlY3Vyc28gdXNlclxuICAgKlxuICAgKiBAcGFyYW0ge2FueX0gJHN0YXRlUHJvdmlkZXJcbiAgICogQHBhcmFtIHthbnl9IEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyXG4gICAgICAuc3RhdGUoJ2FwcC5kaW5hbWljLXF1ZXJ5Jywge1xuICAgICAgICB1cmw6ICcvY29uc3VsdGFzLWRpbmFtaWNhcycsXG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvZGluYW1pYy1xdWVyeXMvZGluYW1pYy1xdWVyeXMuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdEaW5hbWljUXVlcnlzQ29udHJvbGxlciBhcyBkaW5hbWljUXVlcnlDdHJsJyxcbiAgICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IHRydWUsIG5lZWRQcm9maWxlOiBbJ2FkbWluJ10gfVxuICAgICAgfSk7XG5cbiAgfVxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5mYWN0b3J5KCdEaW5hbWljUXVlcnlTZXJ2aWNlJywgRGluYW1pY1F1ZXJ5U2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBEaW5hbWljUXVlcnlTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCdkaW5hbWljUXVlcnknLCB7XG4gICAgICAvKipcbiAgICAgICAqIGHDp8OjbyBhZGljaW9uYWRhIHBhcmEgcGVnYXIgdW1hIGxpc3RhIGRlIG1vZGVscyBleGlzdGVudGVzIG5vIHNlcnZpZG9yXG4gICAgICAgKi9cbiAgICAgIGFjdGlvbnM6IHtcbiAgICAgICAgZ2V0TW9kZWxzOiB7XG4gICAgICAgICAgbWV0aG9kOiAnR0VUJyxcbiAgICAgICAgICB1cmw6ICdtb2RlbHMnXG4gICAgICAgIH1cbiAgICAgIH0sXG4gICAgICBpbnN0YW5jZToge1xuICAgICAgfVxuICAgIH0pO1xuICB9XG5cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb250cm9sbGVyKCdEaW5hbWljUXVlcnlzQ29udHJvbGxlcicsIERpbmFtaWNRdWVyeXNDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIERpbmFtaWNRdWVyeXNDb250cm9sbGVyKCRjb250cm9sbGVyLCBEaW5hbWljUXVlcnlTZXJ2aWNlLCBsb2Rhc2gsIFByVG9hc3QsIC8vIE5PU09OQVJcbiAgICAkdHJhbnNsYXRlKSB7XG5cbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgLy9hY3Rpb25zXG4gICAgdm0ub25BY3RpdmF0ZSA9IG9uQWN0aXZhdGU7XG4gICAgdm0uYXBwbHlGaWx0ZXJzID0gYXBwbHlGaWx0ZXJzO1xuICAgIHZtLmxvYWRBdHRyaWJ1dGVzID0gbG9hZEF0dHJpYnV0ZXM7XG4gICAgdm0ubG9hZE9wZXJhdG9ycyA9IGxvYWRPcGVyYXRvcnM7XG4gICAgdm0uYWRkRmlsdGVyID0gYWRkRmlsdGVyO1xuICAgIHZtLmFmdGVyU2VhcmNoID0gYWZ0ZXJTZWFyY2g7XG4gICAgdm0ucnVuRmlsdGVyID0gcnVuRmlsdGVyO1xuICAgIHZtLmVkaXRGaWx0ZXIgPSBlZGl0RmlsdGVyO1xuICAgIHZtLmxvYWRNb2RlbHMgPSBsb2FkTW9kZWxzO1xuICAgIHZtLnJlbW92ZUZpbHRlciA9IHJlbW92ZUZpbHRlcjtcbiAgICB2bS5jbGVhciA9IGNsZWFyO1xuICAgIHZtLnJlc3RhcnQgPSByZXN0YXJ0O1xuXG4gICAgLy9oZXJkYSBvIGNvbXBvcnRhbWVudG8gYmFzZSBkbyBDUlVEXG4gICAgJGNvbnRyb2xsZXIoJ0NSVURDb250cm9sbGVyJywgeyB2bTogdm0sIG1vZGVsU2VydmljZTogRGluYW1pY1F1ZXJ5U2VydmljZSwgb3B0aW9uczoge1xuICAgICAgc2VhcmNoT25Jbml0OiBmYWxzZVxuICAgIH0gfSk7XG5cbiAgICBmdW5jdGlvbiBvbkFjdGl2YXRlKCkge1xuICAgICAgdm0ucmVzdGFydCgpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFByZXBhcmEgZSBhcGxpY2Egb3MgZmlsdHJvIHF1ZSB2w6NvIHNlciBlbnZpYWRvcyBwYXJhIG8gc2VydmnDp29cbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSBkZWZhdWx0UXVlcnlGaWx0ZXJzXG4gICAgICogQHJldHVybnNcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBhcHBseUZpbHRlcnMoZGVmYXVsdFF1ZXJ5RmlsdGVycykge1xuICAgICAgdmFyIHdoZXJlID0ge307XG5cbiAgICAgIC8qKlxuICAgICAgICogbyBzZXJ2acOnbyBlc3BlcmEgdW0gb2JqZXRvIGNvbTpcbiAgICAgICAqICBvIG5vbWUgZGUgdW0gbW9kZWxcbiAgICAgICAqICB1bWEgbGlzdGEgZGUgZmlsdHJvc1xuICAgICAgICovXG4gICAgICBpZiAodm0uYWRkZWRGaWx0ZXJzLmxlbmd0aCA+IDApIHtcbiAgICAgICAgdmFyIGFkZGVkRmlsdGVycyA9IGFuZ3VsYXIuY29weSh2bS5hZGRlZEZpbHRlcnMpO1xuXG4gICAgICAgIHdoZXJlLm1vZGVsID0gdm0uYWRkZWRGaWx0ZXJzWzBdLm1vZGVsLm5hbWU7XG5cbiAgICAgICAgZm9yICh2YXIgaW5kZXggPSAwOyBpbmRleCA8IGFkZGVkRmlsdGVycy5sZW5ndGg7IGluZGV4KyspIHtcbiAgICAgICAgICB2YXIgZmlsdGVyID0gYWRkZWRGaWx0ZXJzW2luZGV4XTtcblxuICAgICAgICAgIGZpbHRlci5tb2RlbCA9IG51bGw7XG4gICAgICAgICAgZmlsdGVyLmF0dHJpYnV0ZSA9IGZpbHRlci5hdHRyaWJ1dGUubmFtZTtcbiAgICAgICAgICBmaWx0ZXIub3BlcmF0b3IgPSBmaWx0ZXIub3BlcmF0b3IudmFsdWU7XG4gICAgICAgIH1cblxuICAgICAgICB3aGVyZS5maWx0ZXJzID0gYW5ndWxhci50b0pzb24oYWRkZWRGaWx0ZXJzKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHdoZXJlLm1vZGVsID0gdm0ucXVlcnlGaWx0ZXJzLm1vZGVsLm5hbWU7XG4gICAgICB9XG5cbiAgICAgIHJldHVybiBhbmd1bGFyLmV4dGVuZChkZWZhdWx0UXVlcnlGaWx0ZXJzLCB3aGVyZSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ2FycmVnYSB0b2RvcyBvcyBtb2RlbHMgY3JpYWRvcyBubyBzZXJ2aWRvciBjb20gc2V1cyBhdHJpYnV0b3NcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBsb2FkTW9kZWxzKCkge1xuICAgICAgLy9QZWdhIHRvZG9zIG9zIG1vZGVscyBkbyBzZXJ2ZXIgZSBtb250YSB1bWEgbGlzdGEgcHJvIENvbWJvQm94XG4gICAgICBEaW5hbWljUXVlcnlTZXJ2aWNlLmdldE1vZGVscygpLnRoZW4oZnVuY3Rpb24oZGF0YSkge1xuICAgICAgICB2bS5tb2RlbHMgPSBkYXRhO1xuICAgICAgICB2bS5xdWVyeUZpbHRlcnMubW9kZWwgPSB2bS5tb2RlbHNbMF07XG4gICAgICAgIHZtLmxvYWRBdHRyaWJ1dGVzKCk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDYXJyZWdhIG9zIGF0dHJpYnV0b3MgZG8gbW9kZWwgZXNjb2xoaWRvXG4gICAgICovXG4gICAgZnVuY3Rpb24gbG9hZEF0dHJpYnV0ZXMoKSB7XG4gICAgICB2bS5hdHRyaWJ1dGVzID0gdm0ucXVlcnlGaWx0ZXJzLm1vZGVsLmF0dHJpYnV0ZXM7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMuYXR0cmlidXRlID0gdm0uYXR0cmlidXRlc1swXTtcblxuICAgICAgdm0ubG9hZE9wZXJhdG9ycygpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENhcnJlZ2Egb3Mgb3BlcmFkb3JlcyBlc3BlY2lmaWNvcyBwYXJhIG8gdGlwbyBkbyBhdHJpYnV0b1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGxvYWRPcGVyYXRvcnMoKSB7XG4gICAgICB2YXIgb3BlcmF0b3JzID0gW1xuICAgICAgICB7IHZhbHVlOiAnPScsIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLmVxdWFscycpIH0sXG4gICAgICAgIHsgdmFsdWU6ICc8PicsIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLmRpZmVyZW50JykgfVxuICAgICAgXVxuXG4gICAgICBpZiAodm0ucXVlcnlGaWx0ZXJzLmF0dHJpYnV0ZS50eXBlLmluZGV4T2YoJ3ZhcnlpbmcnKSAhPT0gLTEpIHtcbiAgICAgICAgb3BlcmF0b3JzLnB1c2goeyB2YWx1ZTogJ2hhcycsXG4gICAgICAgICAgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudCgndmlld3MuZmllbGRzLnF1ZXJ5RGluYW1pYy5vcGVyYXRvcnMuY29udGVpbnMnKSB9KTtcbiAgICAgICAgb3BlcmF0b3JzLnB1c2goeyB2YWx1ZTogJ3N0YXJ0V2l0aCcsXG4gICAgICAgICAgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudCgndmlld3MuZmllbGRzLnF1ZXJ5RGluYW1pYy5vcGVyYXRvcnMuc3RhcnRXaXRoJykgfSk7XG4gICAgICAgIG9wZXJhdG9ycy5wdXNoKHsgdmFsdWU6ICdlbmRXaXRoJyxcbiAgICAgICAgICBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KCd2aWV3cy5maWVsZHMucXVlcnlEaW5hbWljLm9wZXJhdG9ycy5maW5pc2hXaXRoJykgfSk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBvcGVyYXRvcnMucHVzaCh7IHZhbHVlOiAnPicsXG4gICAgICAgICAgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudCgndmlld3MuZmllbGRzLnF1ZXJ5RGluYW1pYy5vcGVyYXRvcnMuYmlnZ2VyVGhhbicpIH0pO1xuICAgICAgICBvcGVyYXRvcnMucHVzaCh7IHZhbHVlOiAnPj0nLFxuICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLmVxdWFsc09yQmlnZ2VyVGhhbicpIH0pO1xuICAgICAgICBvcGVyYXRvcnMucHVzaCh7IHZhbHVlOiAnPCcsXG4gICAgICAgICAgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudCgndmlld3MuZmllbGRzLnF1ZXJ5RGluYW1pYy5vcGVyYXRvcnMubGVzc1RoYW4nKSB9KTtcbiAgICAgICAgb3BlcmF0b3JzLnB1c2goeyB2YWx1ZTogJzw9JyxcbiAgICAgICAgICBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KCd2aWV3cy5maWVsZHMucXVlcnlEaW5hbWljLm9wZXJhdG9ycy5lcXVhbHNPckxlc3NUaGFuJykgfSk7XG4gICAgICB9XG5cbiAgICAgIHZtLm9wZXJhdG9ycyA9IG9wZXJhdG9ycztcbiAgICAgIHZtLnF1ZXJ5RmlsdGVycy5vcGVyYXRvciA9IHZtLm9wZXJhdG9yc1swXTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBBZGljaW9uYS9lZGl0YSB1bSBmaWx0cm9cbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSBmb3JtIGVsZW1lbnRvIGh0bWwgZG8gZm9ybXVsw6FyaW8gcGFyYSB2YWxpZGHDp8O1ZXNcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBhZGRGaWx0ZXIoZm9ybSkge1xuICAgICAgaWYgKGFuZ3VsYXIuaXNVbmRlZmluZWQodm0ucXVlcnlGaWx0ZXJzLnZhbHVlKSB8fCB2bS5xdWVyeUZpbHRlcnMudmFsdWUgPT09ICcnKSB7XG4gICAgICAgIFByVG9hc3QuZXJyb3IoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy52YWxpZGF0ZS5maWVsZFJlcXVpcmVkJywgeyBmaWVsZDogJ3ZhbG9yJyB9KSk7XG4gICAgICAgIHJldHVybjtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIGlmICh2bS5pbmRleCA8IDApIHtcbiAgICAgICAgICB2bS5hZGRlZEZpbHRlcnMucHVzaChhbmd1bGFyLmNvcHkodm0ucXVlcnlGaWx0ZXJzKSk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgdm0uYWRkZWRGaWx0ZXJzW3ZtLmluZGV4XSA9IGFuZ3VsYXIuY29weSh2bS5xdWVyeUZpbHRlcnMpO1xuICAgICAgICAgIHZtLmluZGV4ID0gLTE7XG4gICAgICAgIH1cblxuICAgICAgICAvL3JlaW5pY2lhIG8gZm9ybXVsw6FyaW8gZSBhcyB2YWxpZGHDp8O1ZXMgZXhpc3RlbnRlc1xuICAgICAgICB2bS5xdWVyeUZpbHRlcnMgPSB7fTtcbiAgICAgICAgZm9ybS4kc2V0UHJpc3RpbmUoKTtcbiAgICAgICAgZm9ybS4kc2V0VW50b3VjaGVkKCk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhbGl6YSBhIHBlc3F1aXNhIHRlbmRvIG9zIGZpbHRyb3MgY29tbyBwYXLDom1ldHJvc1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIHJ1bkZpbHRlcigpIHtcbiAgICAgIHZtLnNlYXJjaCh2bS5wYWdpbmF0b3IuY3VycmVudFBhZ2UpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEdhdGlsaG8gYWNpb25hZG8gZGVwb2lzIGRhIHBlc3F1aXNhIHJlc3BvbnPDoXZlbCBwb3IgaWRlbnRpZmljYXIgb3MgYXRyaWJ1dG9zXG4gICAgICogY29udGlkb3Mgbm9zIGVsZW1lbnRvcyByZXN1bHRhbnRlcyBkYSBidXNjYVxuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IGRhdGEgZGFkb3MgcmVmZXJlbnRlIGFvIHJldG9ybm8gZGEgcmVxdWlzacOnw6NvXG4gICAgICovXG4gICAgZnVuY3Rpb24gYWZ0ZXJTZWFyY2goZGF0YSkge1xuICAgICAgdmFyIGtleXMgPSAoZGF0YS5pdGVtcy5sZW5ndGggPiAwKSA/IE9iamVjdC5rZXlzKGRhdGEuaXRlbXNbMF0pIDogW107XG5cbiAgICAgIC8vcmV0aXJhIHRvZG9zIG9zIGF0cmlidXRvcyBxdWUgY29tZcOnYW0gY29tICQuXG4gICAgICAvL0Vzc2VzIGF0cmlidXRvcyBzw6NvIGFkaWNpb25hZG9zIHBlbG8gc2VydmnDp28gZSBuw6NvIGRldmUgYXBhcmVjZXIgbmEgbGlzdGFnZW1cbiAgICAgIHZtLmtleXMgPSBsb2Rhc2guZmlsdGVyKGtleXMsIGZ1bmN0aW9uKGtleSkge1xuICAgICAgICByZXR1cm4gIWxvZGFzaC5zdGFydHNXaXRoKGtleSwgJyQnKTtcbiAgICAgIH0pXG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ29sb2FjYSBubyBmb3JtdWzDoXJpbyBvIGZpbHRybyBlc2NvbGhpZG8gcGFyYSBlZGnDp8Ojb1xuICAgICAqIEBwYXJhbSB7YW55fSAkaW5kZXggaW5kaWNlIG5vIGFycmF5IGRvIGZpbHRybyBlc2NvbGhpZG9cbiAgICAgKi9cbiAgICBmdW5jdGlvbiBlZGl0RmlsdGVyKCRpbmRleCkge1xuICAgICAgdm0uaW5kZXggPSAkaW5kZXg7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMgPSB2bS5hZGRlZEZpbHRlcnNbJGluZGV4XTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZW1vdmUgbyBmaWx0cm8gZXNjb2xoaWRvXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gJGluZGV4IGluZGljZSBubyBhcnJheSBkbyBmaWx0cm8gZXNjb2xoaWRvXG4gICAgICovXG4gICAgZnVuY3Rpb24gcmVtb3ZlRmlsdGVyKCRpbmRleCkge1xuICAgICAgdm0uYWRkZWRGaWx0ZXJzLnNwbGljZSgkaW5kZXgpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIExpbXBhIG8gZm9ybXVsw6FyaW8gY29ycmVudGVcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBjbGVhcigpIHtcbiAgICAgIC8vZ3VhcmRhIG8gaW5kaWNlIGRvIHJlZ2lzdHJvIHF1ZSBlc3TDoSBzZW5kbyBlZGl0YWRvXG4gICAgICB2bS5pbmRleCA9IC0xO1xuICAgICAgLy92aW5jdWxhZG8gYW9zIGNhbXBvcyBkbyBmb3JtdWzDoXJpb1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0ge1xuICAgICAgfTtcblxuICAgICAgaWYgKHZtLm1vZGVscykgdm0ucXVlcnlGaWx0ZXJzLm1vZGVsID0gdm0ubW9kZWxzWzBdO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlaW5pY2lhIGEgY29uc3RydcOnw6NvIGRhIHF1ZXJ5IGxpbXBhbmRvIHR1ZG9cbiAgICAgKlxuICAgICAqL1xuICAgIGZ1bmN0aW9uIHJlc3RhcnQoKSB7XG4gICAgICAvL2d1YXJkYSBhdHJpYnV0b3MgZG8gcmVzdWx0YWRvIGRhIGJ1c2NhIGNvcnJlbnRlXG4gICAgICB2bS5rZXlzID0gW107XG5cbiAgICAgIC8vZ3VhcmRhIG9zIGZpbHRyb3MgYWRpY2lvbmFkb3NcbiAgICAgIHZtLmFkZGVkRmlsdGVycyA9IFtdO1xuICAgICAgdm0uY2xlYXIoKTtcbiAgICAgIHZtLmxvYWRNb2RlbHMoKTtcbiAgICB9XG5cbiAgfVxuXG59KSgpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmFjdG9yeSgnbGFuZ3VhZ2VMb2FkZXInLCBMYW5ndWFnZUxvYWRlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBMYW5ndWFnZUxvYWRlcigkcSwgU3VwcG9ydFNlcnZpY2UsICRsb2csICRpbmplY3Rvcikge1xuICAgIHZhciBzZXJ2aWNlID0gdGhpcztcblxuICAgIHNlcnZpY2UudHJhbnNsYXRlID0gZnVuY3Rpb24obG9jYWxlKSB7XG4gICAgICByZXR1cm4ge1xuICAgICAgICBnbG9iYWw6ICRpbmplY3Rvci5nZXQobG9jYWxlICsgJy5pMThuLmdsb2JhbCcpLFxuICAgICAgICB2aWV3czogJGluamVjdG9yLmdldChsb2NhbGUgKyAnLmkxOG4udmlld3MnKSxcbiAgICAgICAgYXR0cmlidXRlczogJGluamVjdG9yLmdldChsb2NhbGUgKyAnLmkxOG4uYXR0cmlidXRlcycpLFxuICAgICAgICBkaWFsb2c6ICRpbmplY3Rvci5nZXQobG9jYWxlICsgJy5pMThuLmRpYWxvZycpLFxuICAgICAgICBtZXNzYWdlczogJGluamVjdG9yLmdldChsb2NhbGUgKyAnLmkxOG4ubWVzc2FnZXMnKSxcbiAgICAgICAgbW9kZWxzOiAkaW5qZWN0b3IuZ2V0KGxvY2FsZSArICcuaTE4bi5tb2RlbHMnKVxuICAgICAgfTtcbiAgICB9XG5cbiAgICAvLyByZXR1cm4gbG9hZGVyRm5cbiAgICByZXR1cm4gZnVuY3Rpb24ob3B0aW9ucykge1xuICAgICAgJGxvZy5pbmZvKCdDYXJyZWdhbmRvIG8gY29udGV1ZG8gZGEgbGluZ3VhZ2VtICcgKyBvcHRpb25zLmtleSk7XG5cbiAgICAgIHZhciBkZWZlcnJlZCA9ICRxLmRlZmVyKCk7XG5cbiAgICAgIC8vQ2FycmVnYSBhcyBsYW5ncyBxdWUgcHJlY2lzYW0gZSBlc3TDo28gbm8gc2Vydmlkb3IgcGFyYSBuw6NvIHByZWNpc2FyIHJlcGV0aXIgYXF1aVxuICAgICAgU3VwcG9ydFNlcnZpY2UubGFuZ3MoKS50aGVuKGZ1bmN0aW9uKGxhbmdzKSB7XG4gICAgICAgIC8vTWVyZ2UgY29tIG9zIGxhbmdzIGRlZmluaWRvcyBubyBzZXJ2aWRvclxuICAgICAgICB2YXIgZGF0YSA9IGFuZ3VsYXIubWVyZ2Uoc2VydmljZS50cmFuc2xhdGUob3B0aW9ucy5rZXkpLCBsYW5ncyk7XG5cbiAgICAgICAgcmV0dXJuIGRlZmVycmVkLnJlc29sdmUoZGF0YSk7XG4gICAgICB9LCBmdW5jdGlvbigpIHtcbiAgICAgICAgcmV0dXJuIGRlZmVycmVkLnJlc29sdmUoc2VydmljZS50cmFuc2xhdGUob3B0aW9ucy5rZXkpKTtcbiAgICAgIH0pO1xuXG4gICAgICByZXR1cm4gZGVmZXJyZWQucHJvbWlzZTtcbiAgICB9XG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZpbHRlcigndEF0dHInLCB0QXR0cik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiB0QXR0cigkZmlsdGVyKSB7XG4gICAgLyoqXG4gICAgICogRmlsdHJvIHBhcmEgdHJhZHXDp8OjbyBkZSB1bSBhdHJpYnV0byBkZSB1bSBtb2RlbFxuICAgICAqIFxuICAgICAqIEBwYXJhbSB7YW55fSBuYW1lIG5vbWUgZG8gYXRyaWJ1dG9cbiAgICAgKiBAcmV0dXJucyBvIG5vbWUgZG8gYXRyaWJ1dG8gdHJhZHV6aWRvIGNhc28gZW5jb250cmUgc2UgbsOjbyBvIG5vbWUgcGFzc2FkbyBwb3IgcGFyYW1ldHJvXG4gICAgICovICAgIFxuICAgIHJldHVybiBmdW5jdGlvbihuYW1lKSB7XG4gICAgICB2YXIga2V5ID0gJ2F0dHJpYnV0ZXMuJyArIG5hbWU7XG4gICAgICB2YXIgdHJhbnNsYXRlID0gJGZpbHRlcigndHJhbnNsYXRlJykoa2V5KTtcblxuICAgICAgcmV0dXJuICh0cmFuc2xhdGUgPT09IGtleSkgPyBuYW1lIDogdHJhbnNsYXRlO1xuICAgIH1cbiAgfVxuXG59KSgpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmlsdGVyKCd0QnJlYWRjcnVtYicsIHRCcmVhZGNydW1iKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIHRCcmVhZGNydW1iKCRmaWx0ZXIpIHtcbiAgICAvKipcbiAgICAgKiBGaWx0cm8gcGFyYSB0cmFkdcOnw6NvIGRvIGJyZWFkY3J1bWIgKHRpdHVsbyBkYSB0ZWxhIGNvbSByYXN0cmVpbylcbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSBpZCBjaGF2ZSBjb20gbyBub21lIGRvIHN0YXRlIHJlZmVyZW50ZSB0ZWxhXG4gICAgICogQHJldHVybnMgYSB0cmFkdcOnw6NvIGNhc28gZW5jb250cmUgc2UgbsOjbyBvIGlkIHBhc3NhZG8gcG9yIHBhcmFtZXRyb1xuICAgICAqL1xuICAgIHJldHVybiBmdW5jdGlvbihpZCkge1xuICAgICAgLy9wZWdhIGEgc2VndW5kYSBwYXJ0ZSBkbyBub21lIGRvIHN0YXRlLCByZXRpcmFuZG8gYSBwYXJ0ZSBhYnN0cmF0YSAoYXBwLilcbiAgICAgIHZhciBrZXkgPSAndmlld3MuYnJlYWRjcnVtYnMuJyArIGlkLnNwbGl0KCcuJylbMV07XG4gICAgICB2YXIgdHJhbnNsYXRlID0gJGZpbHRlcigndHJhbnNsYXRlJykoa2V5KTtcblxuICAgICAgcmV0dXJuICh0cmFuc2xhdGUgPT09IGtleSkgPyBpZCA6IHRyYW5zbGF0ZTtcbiAgICB9XG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZpbHRlcigndE1vZGVsJywgdE1vZGVsKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIHRNb2RlbCgkZmlsdGVyKSB7XG4gICAgLyoqXG4gICAgICogRmlsdHJvIHBhcmEgdHJhZHXDp8OjbyBkZSB1bSBhdHJpYnV0byBkZSB1bSBtb2RlbFxuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IG5hbWUgbm9tZSBkbyBhdHJpYnV0b1xuICAgICAqIEByZXR1cm5zIG8gbm9tZSBkbyBhdHJpYnV0byB0cmFkdXppZG8gY2FzbyBlbmNvbnRyZSBzZSBuw6NvIG8gbm9tZSBwYXNzYWRvIHBvciBwYXJhbWV0cm9cbiAgICAgKi9cbiAgICByZXR1cm4gZnVuY3Rpb24obmFtZSkge1xuICAgICAgdmFyIGtleSA9ICdtb2RlbHMuJyArIG5hbWUudG9Mb3dlckNhc2UoKTtcbiAgICAgIHZhciB0cmFuc2xhdGUgPSAkZmlsdGVyKCd0cmFuc2xhdGUnKShrZXkpO1xuXG4gICAgICByZXR1cm4gKHRyYW5zbGF0ZSA9PT0ga2V5KSA/IG5hbWUgOiB0cmFuc2xhdGU7XG4gICAgfVxuICB9XG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAucnVuKGF1dGhlbnRpY2F0aW9uTGlzdGVuZXIpO1xuXG4gIC8qKlxuICAgKiBMaXN0ZW4gYWxsIHN0YXRlIChwYWdlKSBjaGFuZ2VzLiBFdmVyeSB0aW1lIGEgc3RhdGUgY2hhbmdlIG5lZWQgdG8gdmVyaWZ5IHRoZSB1c2VyIGlzIGF1dGhlbnRpY2F0ZWQgb3Igbm90IHRvXG4gICAqIHJlZGlyZWN0IHRvIGNvcnJlY3QgcGFnZS4gV2hlbiBhIHVzZXIgY2xvc2UgdGhlIGJyb3dzZXIgd2l0aG91dCBsb2dvdXQsIHdoZW4gaGltIHJlb3BlbiB0aGUgYnJvd3NlciB0aGlzIGV2ZW50XG4gICAqIHJlYXV0aGVudGljYXRlIHRoZSB1c2VyIHdpdGggdGhlIHBlcnNpc3RlbnQgdG9rZW4gb2YgdGhlIGxvY2FsIHN0b3JhZ2UuXG4gICAqXG4gICAqIFdlIGRvbid0IGNoZWNrIGlmIHRoZSB0b2tlbiBpcyBleHBpcmVkIG9yIG5vdCBpbiB0aGUgcGFnZSBjaGFuZ2UsIGJlY2F1c2UgaXMgZ2VuZXJhdGUgYW4gdW5lY2Vzc2FyeSBvdmVyaGVhZC5cbiAgICogSWYgdGhlIHRva2VuIGlzIGV4cGlyZWQgd2hlbiB0aGUgdXNlciB0cnkgdG8gY2FsbCB0aGUgZmlyc3QgYXBpIHRvIGdldCBkYXRhLCBoaW0gd2lsbCBiZSBsb2dvZmYgYW5kIHJlZGlyZWN0XG4gICAqIHRvIGxvZ2luIHBhZ2UuXG4gICAqXG4gICAqIEBwYXJhbSAkcm9vdFNjb3BlXG4gICAqIEBwYXJhbSAkc3RhdGVcbiAgICogQHBhcmFtICRzdGF0ZVBhcmFtc1xuICAgKiBAcGFyYW0gQXV0aFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBhdXRoZW50aWNhdGlvbkxpc3RlbmVyKCRyb290U2NvcGUsICRzdGF0ZSwgR2xvYmFsLCBBdXRoLCBQclRvYXN0LCAvLyBOT1NPTkFSXG4gICAgJHRyYW5zbGF0ZSkge1xuXG4gICAgLy9vbmx5IHdoZW4gYXBwbGljYXRpb24gc3RhcnQgY2hlY2sgaWYgdGhlIGV4aXN0ZW50IHRva2VuIHN0aWxsIHZhbGlkXG4gICAgQXV0aC5yZW1vdGVWYWxpZGF0ZVRva2VuKCkudGhlbihmdW5jdGlvbigpIHtcbiAgICAgIC8vaWYgdGhlIHRva2VuIGlzIHZhbGlkIGNoZWNrIGlmIGV4aXN0cyB0aGUgdXNlciBiZWNhdXNlIHRoZSBicm93c2VyIGNvdWxkIGJlIGNsb3NlZFxuICAgICAgLy9hbmQgdGhlIHVzZXIgZGF0YSBpc24ndCBpbiBtZW1vcnlcbiAgICAgIGlmIChBdXRoLmN1cnJlbnRVc2VyID09PSBudWxsKSB7XG4gICAgICAgIEF1dGgudXBkYXRlQ3VycmVudFVzZXIoYW5ndWxhci5mcm9tSnNvbihsb2NhbFN0b3JhZ2UuZ2V0SXRlbSgndXNlcicpKSk7XG4gICAgICB9XG4gICAgfSk7XG5cbiAgICAvL0NoZWNrIGlmIHRoZSB0b2tlbiBzdGlsbCB2YWxpZC5cbiAgICAkcm9vdFNjb3BlLiRvbignJHN0YXRlQ2hhbmdlU3RhcnQnLCBmdW5jdGlvbihldmVudCwgdG9TdGF0ZSkge1xuICAgICAgaWYgKHRvU3RhdGUuZGF0YS5uZWVkQXV0aGVudGljYXRpb24gfHwgdG9TdGF0ZS5kYXRhLm5lZWRQcm9maWxlKSB7XG4gICAgICAgIC8vZG9udCB0cmFpdCB0aGUgc3VjY2VzcyBibG9jayBiZWNhdXNlIGFscmVhZHkgZGlkIGJ5IHRva2VuIGludGVyY2VwdG9yXG4gICAgICAgIEF1dGgucmVtb3RlVmFsaWRhdGVUb2tlbigpLmNhdGNoKGZ1bmN0aW9uKCkge1xuICAgICAgICAgIFByVG9hc3Qud2FybigkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLmxvZ2luLmxvZ291dEluYWN0aXZlJykpO1xuXG4gICAgICAgICAgaWYgKHRvU3RhdGUubmFtZSAhPT0gR2xvYmFsLmxvZ2luU3RhdGUpIHtcbiAgICAgICAgICAgICRzdGF0ZS5nbyhHbG9iYWwubG9naW5TdGF0ZSk7XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgZXZlbnQucHJldmVudERlZmF1bHQoKTtcbiAgICAgICAgfSk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICAvL2lmIHRoZSB1c2UgaXMgYXV0aGVudGljYXRlZCBhbmQgbmVlZCB0byBlbnRlciBpbiBsb2dpbiBwYWdlXG4gICAgICAgIC8vaGltIHdpbGwgYmUgcmVkaXJlY3RlZCB0byBob21lIHBhZ2VcbiAgICAgICAgaWYgKHRvU3RhdGUubmFtZSA9PT0gR2xvYmFsLmxvZ2luU3RhdGUgJiYgQXV0aC5hdXRoZW50aWNhdGVkKCkpIHtcbiAgICAgICAgICAkc3RhdGUuZ28oR2xvYmFsLmhvbWVTdGF0ZSk7XG4gICAgICAgICAgZXZlbnQucHJldmVudERlZmF1bHQoKTtcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pO1xuICB9XG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLnJ1bihhdXRob3JpemF0aW9uTGlzdGVuZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gYXV0aG9yaXphdGlvbkxpc3RlbmVyKCRyb290U2NvcGUsICRzdGF0ZSwgR2xvYmFsLCBBdXRoKSB7XG4gICAgLyoqXG4gICAgICogQSBjYWRhIG11ZGFuw6dhIGRlIGVzdGFkbyAoXCJww6FnaW5hXCIpIHZlcmlmaWNhIHNlIG8gdXN1w6FyaW8gdGVtIG8gcGVyZmlsXG4gICAgICogbmVjZXNzw6FyaW8gcGFyYSBvIGFjZXNzbyBhIG1lc21hXG4gICAgICovXG4gICAgJHJvb3RTY29wZS4kb24oJyRzdGF0ZUNoYW5nZVN0YXJ0JywgZnVuY3Rpb24oZXZlbnQsIHRvU3RhdGUpIHtcbiAgICAgIGlmICh0b1N0YXRlLmRhdGEgJiYgdG9TdGF0ZS5kYXRhLm5lZWRBdXRoZW50aWNhdGlvbiAmJlxuICAgICAgICB0b1N0YXRlLmRhdGEubmVlZFByb2ZpbGUgJiYgQXV0aC5hdXRoZW50aWNhdGVkKCkgJiZcbiAgICAgICAgIUF1dGguY3VycmVudFVzZXIuaGFzUHJvZmlsZSh0b1N0YXRlLmRhdGEubmVlZFByb2ZpbGUsIHRvU3RhdGUuZGF0YS5hbGxQcm9maWxlcykpIHtcblxuICAgICAgICAkc3RhdGUuZ28oR2xvYmFsLm5vdEF1dGhvcml6ZWRTdGF0ZSk7XG4gICAgICAgIGV2ZW50LnByZXZlbnREZWZhdWx0KCk7XG4gICAgICB9XG5cbiAgICB9KTtcbiAgfVxufSgpKTtcbiIsIihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uZmlnKHNwaW5uZXJJbnRlcmNlcHRvcik7XG5cbiAgZnVuY3Rpb24gc3Bpbm5lckludGVyY2VwdG9yKCRodHRwUHJvdmlkZXIsICRwcm92aWRlKSB7XG4gICAgLyoqXG4gICAgICogRXN0ZSBpbnRlcmNlcHRvciDDqSByZXNwb25zw6F2ZWwgcG9yIG1vc3RyYXIgZSBlc2NvbmRlciBvXG4gICAgICogY29tcG9uZW50ZSBQclNwaW5uZXIgc2VtcHJlIHF1ZSB1bWEgcmVxdWlzacOnw6NvIGFqYXhcbiAgICAgKiBpbmljaWFyIGUgZmluYWxpemFyLlxuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9ICRxXG4gICAgICogQHBhcmFtIHthbnl9ICRpbmplY3RvclxuICAgICAqIEByZXR1cm5zXG4gICAgICovXG4gICAgZnVuY3Rpb24gc2hvd0hpZGVTcGlubmVyKCRxLCAkaW5qZWN0b3IpIHtcbiAgICAgIHJldHVybiB7XG4gICAgICAgIHJlcXVlc3Q6IGZ1bmN0aW9uIChjb25maWcpIHtcbiAgICAgICAgICAkaW5qZWN0b3IuZ2V0KCdQclNwaW5uZXInKS5zaG93KCk7XG5cbiAgICAgICAgICByZXR1cm4gY29uZmlnO1xuICAgICAgICB9LFxuXG4gICAgICAgIHJlc3BvbnNlOiBmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgICAkaW5qZWN0b3IuZ2V0KCdQclNwaW5uZXInKS5oaWRlKCk7XG5cbiAgICAgICAgICByZXR1cm4gcmVzcG9uc2U7XG4gICAgICAgIH0sXG5cbiAgICAgICAgcmVzcG9uc2VFcnJvcjogZnVuY3Rpb24gKHJlamVjdGlvbikge1xuICAgICAgICAgICRpbmplY3Rvci5nZXQoJ1ByU3Bpbm5lcicpLmhpZGUoKTtcblxuICAgICAgICAgIHJldHVybiAkcS5yZWplY3QocmVqZWN0aW9uKTtcbiAgICAgICAgfVxuICAgICAgfTtcbiAgICB9XG5cbiAgICAvLyBEZWZpbmUgdW1hIGZhY3RvcnkgcGFyYSBvICRodHRwSW50ZXJjZXB0b3JcbiAgICAkcHJvdmlkZS5mYWN0b3J5KCdzaG93SGlkZVNwaW5uZXInLCBzaG93SGlkZVNwaW5uZXIpO1xuXG4gICAgLy8gQWRpY2lvbmEgYSBmYWN0b3J5IG5vIGFycmF5IGRlIGludGVyY2VwdG9ycyBkbyAkaHR0cFxuICAgICRodHRwUHJvdmlkZXIuaW50ZXJjZXB0b3JzLnB1c2goJ3Nob3dIaWRlU3Bpbm5lcicpO1xuICB9XG59KCkpO1xuIiwiLyplc2xpbnQgYW5ndWxhci9tb2R1bGUtZ2V0dGVyOiAwKi9cblxuKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbmZpZyh0b2tlbkludGVyY2VwdG9yKTtcblxuICAvKipcbiAgICogSW50ZXJjZXB0IGFsbCByZXNwb25zZSAoc3VjY2VzcyBvciBlcnJvcikgdG8gdmVyaWZ5IHRoZSByZXR1cm5lZCB0b2tlblxuICAgKlxuICAgKiBAcGFyYW0gJGh0dHBQcm92aWRlclxuICAgKiBAcGFyYW0gJHByb3ZpZGVcbiAgICogQHBhcmFtIEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiB0b2tlbkludGVyY2VwdG9yKCRodHRwUHJvdmlkZXIsICRwcm92aWRlLCBHbG9iYWwpIHtcblxuICAgIGZ1bmN0aW9uIHJlZGlyZWN0V2hlblNlcnZlckxvZ2dlZE91dCgkcSwgJGluamVjdG9yKSB7XG4gICAgICByZXR1cm4ge1xuICAgICAgICByZXF1ZXN0OiBmdW5jdGlvbihjb25maWcpIHtcbiAgICAgICAgICB2YXIgdG9rZW4gPSAkaW5qZWN0b3IuZ2V0KCdBdXRoJykuZ2V0VG9rZW4oKTtcblxuICAgICAgICAgIGlmICh0b2tlbikge1xuICAgICAgICAgICAgY29uZmlnLmhlYWRlcnNbJ0F1dGhvcml6YXRpb24nXSA9ICdCZWFyZXIgJyArIHRva2VuO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIHJldHVybiBjb25maWc7XG4gICAgICAgIH0sXG4gICAgICAgIHJlc3BvbnNlOiBmdW5jdGlvbihyZXNwb25zZSkge1xuICAgICAgICAgIC8vIGdldCBhIG5ldyByZWZyZXNoIHRva2VuIHRvIHVzZSBpbiB0aGUgbmV4dCByZXF1ZXN0XG4gICAgICAgICAgdmFyIHRva2VuID0gcmVzcG9uc2UuaGVhZGVycygnQXV0aG9yaXphdGlvbicpO1xuXG4gICAgICAgICAgaWYgKHRva2VuKSB7XG4gICAgICAgICAgICAkaW5qZWN0b3IuZ2V0KCdBdXRoJykuc2V0VG9rZW4odG9rZW4uc3BsaXQoJyAnKVsxXSk7XG4gICAgICAgICAgfVxuICAgICAgICAgIHJldHVybiByZXNwb25zZTtcbiAgICAgICAgfSxcbiAgICAgICAgcmVzcG9uc2VFcnJvcjogZnVuY3Rpb24ocmVqZWN0aW9uKSB7XG4gICAgICAgICAgLy8gSW5zdGVhZCBvZiBjaGVja2luZyBmb3IgYSBzdGF0dXMgY29kZSBvZiA0MDAgd2hpY2ggbWlnaHQgYmUgdXNlZFxuICAgICAgICAgIC8vIGZvciBvdGhlciByZWFzb25zIGluIExhcmF2ZWwsIHdlIGNoZWNrIGZvciB0aGUgc3BlY2lmaWMgcmVqZWN0aW9uXG4gICAgICAgICAgLy8gcmVhc29ucyB0byB0ZWxsIHVzIGlmIHdlIG5lZWQgdG8gcmVkaXJlY3QgdG8gdGhlIGxvZ2luIHN0YXRlXG4gICAgICAgICAgdmFyIHJlamVjdGlvblJlYXNvbnMgPSBbJ3Rva2VuX25vdF9wcm92aWRlZCcsICd0b2tlbl9leHBpcmVkJywgJ3Rva2VuX2Fic2VudCcsICd0b2tlbl9pbnZhbGlkJ107XG5cbiAgICAgICAgICB2YXIgdG9rZW5FcnJvciA9IGZhbHNlO1xuXG4gICAgICAgICAgYW5ndWxhci5mb3JFYWNoKHJlamVjdGlvblJlYXNvbnMsIGZ1bmN0aW9uKHZhbHVlKSB7XG4gICAgICAgICAgICBpZiAocmVqZWN0aW9uLmRhdGEgJiYgcmVqZWN0aW9uLmRhdGEuZXJyb3IgPT09IHZhbHVlKSB7XG4gICAgICAgICAgICAgIHRva2VuRXJyb3IgPSB0cnVlO1xuXG4gICAgICAgICAgICAgICRpbmplY3Rvci5nZXQoJ0F1dGgnKS5sb2dvdXQoKS50aGVuKGZ1bmN0aW9uKCkge1xuICAgICAgICAgICAgICAgIHZhciAkc3RhdGUgPSAkaW5qZWN0b3IuZ2V0KCckc3RhdGUnKTtcblxuICAgICAgICAgICAgICAgIC8vIGluIGNhc2UgbXVsdGlwbGUgYWpheCByZXF1ZXN0IGZhaWwgYXQgc2FtZSB0aW1lIGJlY2F1c2UgdG9rZW4gcHJvYmxlbXMsXG4gICAgICAgICAgICAgICAgLy8gb25seSB0aGUgZmlyc3Qgd2lsbCByZWRpcmVjdFxuICAgICAgICAgICAgICAgIGlmICghJHN0YXRlLmlzKEdsb2JhbC5sb2dpblN0YXRlKSkge1xuICAgICAgICAgICAgICAgICAgJHN0YXRlLmdvKEdsb2JhbC5sb2dpblN0YXRlKTtcblxuICAgICAgICAgICAgICAgICAgLy9jbG9zZSBhbnkgZGlhbG9nIHRoYXQgaXMgb3BlbmVkXG4gICAgICAgICAgICAgICAgICAkaW5qZWN0b3IuZ2V0KCdQckRpYWxvZycpLmNsb3NlKCk7XG5cbiAgICAgICAgICAgICAgICAgIGV2ZW50LnByZXZlbnREZWZhdWx0KCk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9KTtcblxuICAgICAgICAgIC8vZGVmaW5lIGRhdGEgdG8gZW1wdHkgYmVjYXVzZSBhbHJlYWR5IHNob3cgUHJUb2FzdCB0b2tlbiBtZXNzYWdlXG4gICAgICAgICAgaWYgKHRva2VuRXJyb3IpIHtcbiAgICAgICAgICAgIHJlamVjdGlvbi5kYXRhID0ge307XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbihyZWplY3Rpb24uaGVhZGVycykpIHtcbiAgICAgICAgICAgIC8vIG1hbnkgc2VydmVycyBlcnJvcnMgKGJ1c2luZXNzKSBhcmUgaW50ZXJjZXB0IGhlcmUgYnV0IGdlbmVyYXRlZCBhIG5ldyByZWZyZXNoIHRva2VuXG4gICAgICAgICAgICAvLyBhbmQgbmVlZCB1cGRhdGUgY3VycmVudCB0b2tlblxuICAgICAgICAgICAgdmFyIHRva2VuID0gcmVqZWN0aW9uLmhlYWRlcnMoJ0F1dGhvcml6YXRpb24nKTtcblxuICAgICAgICAgICAgaWYgKHRva2VuKSB7XG4gICAgICAgICAgICAgICRpbmplY3Rvci5nZXQoJ0F1dGgnKS5zZXRUb2tlbih0b2tlbi5zcGxpdCgnICcpWzFdKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9XG5cbiAgICAgICAgICByZXR1cm4gJHEucmVqZWN0KHJlamVjdGlvbik7XG4gICAgICAgIH1cbiAgICAgIH07XG4gICAgfVxuXG4gICAgLy8gU2V0dXAgZm9yIHRoZSAkaHR0cEludGVyY2VwdG9yXG4gICAgJHByb3ZpZGUuZmFjdG9yeSgncmVkaXJlY3RXaGVuU2VydmVyTG9nZ2VkT3V0JywgcmVkaXJlY3RXaGVuU2VydmVyTG9nZ2VkT3V0KTtcblxuICAgIC8vIFB1c2ggdGhlIG5ldyBmYWN0b3J5IG9udG8gdGhlICRodHRwIGludGVyY2VwdG9yIGFycmF5XG4gICAgJGh0dHBQcm92aWRlci5pbnRlcmNlcHRvcnMucHVzaCgncmVkaXJlY3RXaGVuU2VydmVyTG9nZ2VkT3V0Jyk7XG4gIH1cblxufSgpKTtcbiIsIihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uZmlnKHZhbGlkYXRpb25JbnRlcmNlcHRvcik7XG5cbiAgZnVuY3Rpb24gdmFsaWRhdGlvbkludGVyY2VwdG9yKCRodHRwUHJvdmlkZXIsICRwcm92aWRlKSB7XG4gICAgLyoqXG4gICAgICogRXN0ZSBpbnRlcmNlcHRvciDDqSByZXNwb25zw6F2ZWwgcG9yIG1vc3RyYXIgYXNcbiAgICAgKiBtZW5zYWdlbnMgZGUgZXJybyByZWZlcmVudGUgYXMgdmFsaWRhw6fDtWVzIGRvIGJhY2stZW5kXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gJHFcbiAgICAgKiBAcGFyYW0ge2FueX0gJGluamVjdG9yXG4gICAgICogQHJldHVybnNcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBzaG93RXJyb3JWYWxpZGF0aW9uKCRxLCAkaW5qZWN0b3IpIHtcbiAgICAgIHJldHVybiB7XG4gICAgICAgIHJlc3BvbnNlRXJyb3I6IGZ1bmN0aW9uIChyZWplY3Rpb24pIHtcbiAgICAgICAgICB2YXIgUHJUb2FzdCA9ICRpbmplY3Rvci5nZXQoJ1ByVG9hc3QnKTtcbiAgICAgICAgICB2YXIgJHRyYW5zbGF0ZSA9ICRpbmplY3Rvci5nZXQoJyR0cmFuc2xhdGUnKTtcblxuICAgICAgICAgIGlmIChyZWplY3Rpb24uY29uZmlnLmRhdGEgJiYgIXJlamVjdGlvbi5jb25maWcuZGF0YS5za2lwVmFsaWRhdGlvbikge1xuICAgICAgICAgICAgaWYgKHJlamVjdGlvbi5kYXRhICYmIHJlamVjdGlvbi5kYXRhLmVycm9yKSB7XG5cbiAgICAgICAgICAgICAgLy92ZXJpZmljYSBzZSBvY29ycmV1IGFsZ3VtIGVycm8gcmVmZXJlbnRlIGFvIHRva2VuXG4gICAgICAgICAgICAgIGlmIChyZWplY3Rpb24uZGF0YS5lcnJvci5zdGFydHNXaXRoKCd0b2tlbl8nKSkge1xuICAgICAgICAgICAgICAgIFByVG9hc3Qud2FybigkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLmxvZ2luLmxvZ291dEluYWN0aXZlJykpO1xuICAgICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICAgIFByVG9hc3QuZXJyb3IoJHRyYW5zbGF0ZS5pbnN0YW50KHJlamVjdGlvbi5kYXRhLmVycm9yKSk7XG4gICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgIFByVG9hc3QuZXJyb3JWYWxpZGF0aW9uKHJlamVjdGlvbi5kYXRhKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9XG5cbiAgICAgICAgICByZXR1cm4gJHEucmVqZWN0KHJlamVjdGlvbik7XG4gICAgICAgIH1cbiAgICAgIH07XG4gICAgfVxuXG4gICAgLy8gRGVmaW5lIHVtYSBmYWN0b3J5IHBhcmEgbyAkaHR0cEludGVyY2VwdG9yXG4gICAgJHByb3ZpZGUuZmFjdG9yeSgnc2hvd0Vycm9yVmFsaWRhdGlvbicsIHNob3dFcnJvclZhbGlkYXRpb24pO1xuXG4gICAgLy8gQWRpY2lvbmEgYSBmYWN0b3J5IG5vIGFycmF5IGRlIGludGVyY2VwdG9ycyBkbyAkaHR0cFxuICAgICRodHRwUHJvdmlkZXIuaW50ZXJjZXB0b3JzLnB1c2goJ3Nob3dFcnJvclZhbGlkYXRpb24nKTtcbiAgfVxufSgpKTtcbiIsIi8qZXNsaW50LWVudiBlczYqL1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29udHJvbGxlcignTWVudUNvbnRyb2xsZXInLCBNZW51Q29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiBNZW51Q29udHJvbGxlcigkbWRTaWRlbmF2LCAkc3RhdGUsICRtZENvbG9ycykge1xuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICAvL0Jsb2NvIGRlIGRlY2xhcmFjb2VzIGRlIGZ1bmNvZXNcbiAgICB2bS5vcGVuID0gb3BlbjtcbiAgICB2bS5vcGVuTWVudU9yUmVkaXJlY3RUb1N0YXRlID0gb3Blbk1lbnVPclJlZGlyZWN0VG9TdGF0ZTtcblxuICAgIGFjdGl2YXRlKCk7XG5cbiAgICBmdW5jdGlvbiBhY3RpdmF0ZSgpIHtcbiAgICAgIHZhciBtZW51UHJlZml4ID0gJ3ZpZXdzLmxheW91dC5tZW51Lic7XG5cbiAgICAgIC8vIEFycmF5IGNvbnRlbmRvIG9zIGl0ZW5zIHF1ZSBzw6NvIG1vc3RyYWRvcyBubyBtZW51IGxhdGVyYWxcbiAgICAgIHZtLml0ZW5zTWVudSA9IFtcbiAgICAgICAgeyBzdGF0ZTogJ2FwcC5kYXNoYm9hcmQnLCB0aXRsZTogbWVudVByZWZpeCArICdkYXNoYm9hcmQnLCBpY29uOiAnZGFzaGJvYXJkJywgc3ViSXRlbnM6IFtdIH0sXG4gICAgICAgIHtcbiAgICAgICAgICBzdGF0ZTogJyMnLCB0aXRsZTogbWVudVByZWZpeCArICdleGFtcGxlcycsIGljb246ICd2aWV3X2Nhcm91c2VsJywgcHJvZmlsZXM6IFsnYWRtaW4nXSxcbiAgICAgICAgICBzdWJJdGVuczogW1xuICAgICAgICAgICAgeyBzdGF0ZTogJ2FwcC5wcm9qZWN0JywgdGl0bGU6IG1lbnVQcmVmaXggKyAncHJvamVjdCcsIGljb246ICdzdGFyJyB9XG4gICAgICAgICAgXVxuICAgICAgICB9LFxuICAgICAgICAvLyBDb2xvcXVlIHNldXMgaXRlbnMgZGUgbWVudSBhIHBhcnRpciBkZXN0ZSBwb250b1xuICAgICAgICB7XG4gICAgICAgICAgc3RhdGU6ICcjJywgdGl0bGU6IG1lbnVQcmVmaXggKyAnYWRtaW4nLCBpY29uOiAnc2V0dGluZ3NfYXBwbGljYXRpb25zJywgcHJvZmlsZXM6IFsnYWRtaW4nXSxcbiAgICAgICAgICBzdWJJdGVuczogW1xuICAgICAgICAgICAgeyBzdGF0ZTogJ2FwcC51c2VyJywgdGl0bGU6IG1lbnVQcmVmaXggKyAndXNlcicsIGljb246ICdwZW9wbGUnIH0sXG4gICAgICAgICAgICB7IHN0YXRlOiAnYXBwLm1haWwnLCB0aXRsZTogbWVudVByZWZpeCArICdtYWlsJywgaWNvbjogJ21haWwnIH0sXG4gICAgICAgICAgICB7IHN0YXRlOiAnYXBwLmF1ZGl0JywgdGl0bGU6IG1lbnVQcmVmaXggKyAnYXVkaXQnLCBpY29uOiAnc3RvcmFnZScgfSxcbiAgICAgICAgICAgIHsgc3RhdGU6ICdhcHAuZGluYW1pYy1xdWVyeScsIHRpdGxlOiBtZW51UHJlZml4ICsgJ2RpbmFtaWNRdWVyeScsIGljb246ICdsb2NhdGlvbl9zZWFyY2hpbmcnIH1cbiAgICAgICAgICBdXG4gICAgICAgIH1cbiAgICAgIF07XG5cbiAgICAgIC8qKlxuICAgICAgICogT2JqZXRvIHF1ZSBwcmVlbmNoZSBvIG5nLXN0eWxlIGRvIG1lbnUgbGF0ZXJhbCB0cm9jYW5kbyBhcyBjb3Jlc1xuICAgICAgICovXG4gICAgICB2bS5zaWRlbmF2U3R5bGUgPSB7XG4gICAgICAgIHRvcDoge1xuICAgICAgICAgICdib3JkZXItYm90dG9tJzogJzFweCBzb2xpZCAnICsgZ2V0Q29sb3IoJ3ByaW1hcnknKSxcbiAgICAgICAgICAnYmFja2dyb3VuZC1pbWFnZSc6ICctd2Via2l0LWxpbmVhci1ncmFkaWVudCh0b3AsICcrZ2V0Q29sb3IoJ3ByaW1hcnktNTAwJykrJywgJytnZXRDb2xvcigncHJpbWFyeS04MDAnKSsnKSdcbiAgICAgICAgfSxcbiAgICAgICAgY29udGVudDoge1xuICAgICAgICAgICdiYWNrZ3JvdW5kLWNvbG9yJzogZ2V0Q29sb3IoJ3ByaW1hcnktODAwJylcbiAgICAgICAgfSxcbiAgICAgICAgdGV4dENvbG9yOiB7XG4gICAgICAgICAgY29sb3I6ICcjRkZGJ1xuICAgICAgICB9LFxuICAgICAgICBsaW5lQm90dG9tOiB7XG4gICAgICAgICAgJ2JvcmRlci1ib3R0b20nOiAnMXB4IHNvbGlkICcgKyBnZXRDb2xvcigncHJpbWFyeS00MDAnKVxuICAgICAgICB9XG4gICAgICB9XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gb3BlbigpIHtcbiAgICAgICRtZFNpZGVuYXYoJ2xlZnQnKS50b2dnbGUoKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBNw6l0b2RvIHF1ZSBleGliZSBvIHN1YiBtZW51IGRvcyBpdGVucyBkbyBtZW51IGxhdGVyYWwgY2FzbyB0ZW5oYSBzdWIgaXRlbnNcbiAgICAgKiBjYXNvIGNvbnRyw6FyaW8gcmVkaXJlY2lvbmEgcGFyYSBvIHN0YXRlIHBhc3NhZG8gY29tbyBwYXLDom1ldHJvXG4gICAgICovXG4gICAgZnVuY3Rpb24gb3Blbk1lbnVPclJlZGlyZWN0VG9TdGF0ZSgkbWRNZW51LCBldiwgaXRlbSkge1xuICAgICAgaWYgKGFuZ3VsYXIuaXNEZWZpbmVkKGl0ZW0uc3ViSXRlbnMpICYmIGl0ZW0uc3ViSXRlbnMubGVuZ3RoID4gMCkge1xuICAgICAgICAkbWRNZW51Lm9wZW4oZXYpO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgJHN0YXRlLmdvKGl0ZW0uc3RhdGUpO1xuICAgICAgICAkbWRTaWRlbmF2KCdsZWZ0JykuY2xvc2UoKTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICBmdW5jdGlvbiBnZXRDb2xvcihjb2xvclBhbGV0dGVzKSB7XG4gICAgICByZXR1cm4gJG1kQ29sb3JzLmdldFRoZW1lQ29sb3IoY29sb3JQYWxldHRlcyk7XG4gICAgfVxuXG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnRyb2xsZXIoJ01haWxzQ29udHJvbGxlcicsIE1haWxzQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBNYWlsc0NvbnRyb2xsZXIoTWFpbHNTZXJ2aWNlLCBVc2Vyc1NlcnZpY2UsIFByRGlhbG9nLCBQclRvYXN0LCAvLyBOT1NPTkFSXG4gICAgJHEsIGxvZGFzaCwgJHRyYW5zbGF0ZSwgR2xvYmFsKSB7XG5cbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0uZmlsdGVyU2VsZWN0ZWQgPSBmYWxzZTtcbiAgICB2bS5vcHRpb25zID0ge1xuICAgICAgc2tpbjogJ2thbWEnLFxuICAgICAgbGFuZ3VhZ2U6ICdwdC1icicsXG4gICAgICBhbGxvd2VkQ29udGVudDogdHJ1ZSxcbiAgICAgIGVudGl0aWVzOiB0cnVlLFxuICAgICAgaGVpZ2h0OiAzMDAsXG4gICAgICBleHRyYVBsdWdpbnM6ICdkaWFsb2csZmluZCxjb2xvcmRpYWxvZyxwcmV2aWV3LGZvcm1zLGlmcmFtZSxmbGFzaCdcbiAgICB9O1xuXG4gICAgdm0ubG9hZFVzZXJzID0gbG9hZFVzZXJzO1xuICAgIHZtLm9wZW5Vc2VyRGlhbG9nID0gb3BlblVzZXJEaWFsb2c7XG4gICAgdm0uYWRkVXNlck1haWwgPSBhZGRVc2VyTWFpbDtcbiAgICB2bS5jbGVhbkZvcm0gPSBjbGVhbkZvcm07XG4gICAgdm0uc2VuZCA9IHNlbmQ7XG5cbiAgICBhY3RpdmF0ZSgpO1xuXG4gICAgZnVuY3Rpb24gYWN0aXZhdGUoKSB7XG4gICAgICB2bS5jbGVhbkZvcm0oKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFsaXphIGEgYnVzY2EgcGVsbyB1c3XDoXJpbyByZW1vdGFtZW50ZVxuICAgICAqXG4gICAgICogQHBhcmFtcyB7c3RyaW5nfSAtIFJlY2ViZSBvIHZhbG9yIHBhcmEgc2VyIHBlc3F1aXNhZG9cbiAgICAgKiBAcmV0dXJuIHtwcm9taXNzZX0gLSBSZXRvcm5hIHVtYSBwcm9taXNzZSBxdWUgbyBjb21wb25ldGUgcmVzb2x2ZVxuICAgICAqL1xuICAgIGZ1bmN0aW9uIGxvYWRVc2Vycyhjcml0ZXJpYSkge1xuICAgICAgdmFyIGRlZmVycmVkID0gJHEuZGVmZXIoKTtcblxuICAgICAgVXNlcnNTZXJ2aWNlLnF1ZXJ5KHtcbiAgICAgICAgbmFtZU9yRW1haWw6IGNyaXRlcmlhLFxuICAgICAgICBub3RVc2VyczogbG9kYXNoLm1hcCh2bS5tYWlsLnVzZXJzLCBsb2Rhc2gucHJvcGVydHkoJ2lkJykpLnRvU3RyaW5nKCksXG4gICAgICAgIGxpbWl0OiA1XG4gICAgICB9KS50aGVuKGZ1bmN0aW9uKGRhdGEpIHtcblxuICAgICAgICAvLyB2ZXJpZmljYSBzZSBuYSBsaXN0YSBkZSB1c3VhcmlvcyBqw6EgZXhpc3RlIG8gdXN1w6FyaW8gY29tIG8gZW1haWwgcGVzcXVpc2Fkb1xuICAgICAgICBkYXRhID0gbG9kYXNoLmZpbHRlcihkYXRhLCBmdW5jdGlvbih1c2VyKSB7XG4gICAgICAgICAgcmV0dXJuICFsb2Rhc2guZmluZCh2bS5tYWlsLnVzZXJzLCB7IGVtYWlsOiB1c2VyLmVtYWlsIH0pO1xuICAgICAgICB9KTtcblxuICAgICAgICBkZWZlcnJlZC5yZXNvbHZlKGRhdGEpO1xuICAgICAgfSk7XG5cbiAgICAgIHJldHVybiBkZWZlcnJlZC5wcm9taXNlO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEFicmUgbyBkaWFsb2cgcGFyYSBwZXNxdWlzYSBkZSB1c3XDoXJpb3NcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBvcGVuVXNlckRpYWxvZygpIHtcbiAgICAgIHZhciBjb25maWcgPSB7XG4gICAgICAgIGxvY2Fsczoge1xuICAgICAgICAgIG9uSW5pdDogdHJ1ZSxcbiAgICAgICAgICB1c2VyRGlhbG9nSW5wdXQ6IHtcbiAgICAgICAgICAgIHRyYW5zZmVyVXNlckZuOiB2bS5hZGRVc2VyTWFpbFxuICAgICAgICAgIH1cbiAgICAgICAgfSxcbiAgICAgICAgY29udHJvbGxlcjogJ1VzZXJzRGlhbG9nQ29udHJvbGxlcicsXG4gICAgICAgIGNvbnRyb2xsZXJBczogJ2N0cmwnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL3VzZXJzL2RpYWxvZy91c2Vycy1kaWFsb2cuaHRtbCcsXG4gICAgICAgIGhhc0JhY2tkcm9wOiB0cnVlXG4gICAgICB9O1xuXG4gICAgICBQckRpYWxvZy5jdXN0b20oY29uZmlnKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBBZGljaW9uYSBvIHVzdcOhcmlvIHNlbGVjaW9uYWRvIG5hIGxpc3RhIHBhcmEgcXVlIHNlamEgZW52aWFkbyBvIGVtYWlsXG4gICAgICovXG4gICAgZnVuY3Rpb24gYWRkVXNlck1haWwodXNlcikge1xuICAgICAgdmFyIHVzZXJzID0gbG9kYXNoLmZpbmQodm0ubWFpbC51c2VycywgeyBlbWFpbDogdXNlci5lbWFpbCB9KTtcblxuICAgICAgaWYgKHZtLm1haWwudXNlcnMubGVuZ3RoID4gMCAmJiBhbmd1bGFyLmlzRGVmaW5lZCh1c2VycykpIHtcbiAgICAgICAgUHJUb2FzdC53YXJuKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMudXNlci51c2VyRXhpc3RzJykpO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgdm0ubWFpbC51c2Vycy5wdXNoKHsgbmFtZTogdXNlci5uYW1lLCBlbWFpbDogdXNlci5lbWFpbCB9KVxuICAgICAgfVxuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWxpemEgbyBlbnZpbyBkbyBlbWFpbCBwYXJhIGEgbGlzdGEgZGUgdXN1w6FyaW9zIHNlbGVjaW9uYWRvc1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIHNlbmQoKSB7XG5cbiAgICAgIHZtLm1haWwuJHNhdmUoKS50aGVuKGZ1bmN0aW9uKHJlc3BvbnNlKSB7XG4gICAgICAgIGlmIChyZXNwb25zZS5sZW5ndGggPiAwKSB7XG4gICAgICAgICAgdmFyIG1zZyA9ICR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMubWFpbC5tYWlsRXJyb3JzJyk7XG5cbiAgICAgICAgICBmb3IgKHZhciBpPTA7IGkgPCByZXNwb25zZS5sZW5ndGg7IGkrKykge1xuICAgICAgICAgICAgbXNnICs9IHJlc3BvbnNlICsgJ1xcbic7XG4gICAgICAgICAgfVxuICAgICAgICAgIFByVG9hc3QuZXJyb3IobXNnKTtcbiAgICAgICAgICB2bS5jbGVhbkZvcm0oKTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICBQclRvYXN0LnN1Y2Nlc3MoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5tYWlsLnNlbmRNYWlsU3VjY2VzcycpKTtcbiAgICAgICAgICB2bS5jbGVhbkZvcm0oKTtcbiAgICAgICAgfVxuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogTGltcGEgbyBmb3JtdWzDoXJpbyBkZSBlbWFpbFxuICAgICAqL1xuICAgIGZ1bmN0aW9uIGNsZWFuRm9ybSgpIHtcbiAgICAgIHZtLm1haWwgPSBuZXcgTWFpbHNTZXJ2aWNlKCk7XG4gICAgICB2bS5tYWlsLnVzZXJzID0gW107XG4gICAgfVxuXG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb25maWcocm91dGVzKTtcblxuICAvKipcbiAgICogQXJxdWl2byBkZSBjb25maWd1cmHDp8OjbyBjb20gYXMgcm90YXMgZXNwZWPDrWZpY2FzIGRvIHJlY3Vyc28gZW0gcXVlc3TDo29cbiAgICpcbiAgICogQHBhcmFtIHthbnl9ICRzdGF0ZVByb3ZpZGVyXG4gICAqIEBwYXJhbSB7YW55fSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlclxuICAgICAgLnN0YXRlKCdhcHAubWFpbCcsIHtcbiAgICAgICAgdXJsOiAnL2VtYWlsJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9tYWlsL21haWxzLXNlbmQuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdNYWlsc0NvbnRyb2xsZXIgYXMgbWFpbHNDdHJsJyxcbiAgICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IHRydWUsIG5lZWRQcm9maWxlOiBbJ2FkbWluJ10gfVxuICAgICAgfSk7XG5cbiAgfVxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5mYWN0b3J5KCdNYWlsc1NlcnZpY2UnLCBNYWlsc1NlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gTWFpbHNTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCdtYWlscycsIHt9KTtcbiAgfVxuXG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmlsdGVyKCdyb2xlc1N0cicsIHJvbGVzU3RyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvbGVzU3RyKGxvZGFzaCkge1xuICAgIC8qKlxuICAgICAqIEBwYXJhbSB7YXJyYXl9IHJvbGVzIGxpc3RhIGRlIHBlcmZpc1xuICAgICAqIEByZXR1cm4ge3N0cmluZ30gcGVyZmlzIHNlcGFyYWRvcyBwb3IgJywgJyAgXG4gICAgICovXG4gICAgcmV0dXJuIGZ1bmN0aW9uKHJvbGVzKSB7XG4gICAgICByZXR1cm4gbG9kYXNoLm1hcChyb2xlcywgJ3NsdWcnKS5qb2luKCcsICcpO1xuICAgIH07XG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5mYWN0b3J5KCdSb2xlc1NlcnZpY2UnLCBSb2xlc1NlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gUm9sZXNTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCdyb2xlcycpO1xuICB9XG5cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmFjdG9yeSgnU3VwcG9ydFNlcnZpY2UnLCBTdXBwb3J0U2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiBTdXBwb3J0U2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHJldHVybiBzZXJ2aWNlRmFjdG9yeSgnc3VwcG9ydCcsIHtcbiAgICAgIGFjdGlvbnM6IHtcbiAgICAgIC8qKlxuICAgICAgICogUGVnYSBhcyB0cmFkdcOnw7VlcyBxdWUgZXN0w6NvIG5vIHNlcnZpZG9yXG4gICAgICAgKlxuICAgICAgICogQHJldHVybnMge3Byb21pc2V9IFVtYSBwcm9taXNlIGNvbSBvIHJlc3VsdGFkbyBkbyBjaGFtYWRhIG5vIGJhY2tlbmRcbiAgICAgICAqL1xuICAgICAgICBsYW5nczoge1xuICAgICAgICAgIG1ldGhvZDogJ0dFVCcsXG4gICAgICAgICAgdXJsOiAnbGFuZ3MnLFxuICAgICAgICAgIHdyYXA6IGZhbHNlLFxuICAgICAgICAgIGNhY2hlOiB0cnVlXG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9KTtcbiAgfVxuXG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29udHJvbGxlcignUHJvZmlsZUNvbnRyb2xsZXInLCBQcm9maWxlQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBQcm9maWxlQ29udHJvbGxlcihVc2Vyc1NlcnZpY2UsIEF1dGgsIFByVG9hc3QsICR0cmFuc2xhdGUpIHtcbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0udXBkYXRlID0gdXBkYXRlO1xuXG4gICAgYWN0aXZhdGUoKTtcblxuICAgIGZ1bmN0aW9uIGFjdGl2YXRlKCkge1xuICAgICAgdm0udXNlciA9IGFuZ3VsYXIuY29weShBdXRoLmN1cnJlbnRVc2VyKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiB1cGRhdGUoKSB7XG4gICAgICBVc2Vyc1NlcnZpY2UudXBkYXRlUHJvZmlsZSh2bS51c2VyKS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICAvL2F0dWFsaXphIG8gdXN1w6FyaW8gY29ycmVudGUgY29tIGFzIG5vdmFzIGluZm9ybWHDp8O1ZXNcbiAgICAgICAgQXV0aC51cGRhdGVDdXJyZW50VXNlcihyZXNwb25zZSk7XG4gICAgICAgIFByVG9hc3Quc3VjY2VzcygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnNhdmVTdWNjZXNzJykpO1xuICAgICAgfSk7XG4gICAgfVxuICB9XG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb250cm9sbGVyKCdVc2Vyc0NvbnRyb2xsZXInLCBVc2Vyc0NvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gVXNlcnNDb250cm9sbGVyKCRjb250cm9sbGVyLCBVc2Vyc1NlcnZpY2UpIHtcblxuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICB2bS5vbkFjdGl2YXRlID0gb25BY3RpdmF0ZTtcbiAgICAvLyBpbnN0YW50aWF0ZSBiYXNlIGNvbnRyb2xsZXJcbiAgICAkY29udHJvbGxlcignQ1JVRENvbnRyb2xsZXInLCB7IHZtOiB2bSwgbW9kZWxTZXJ2aWNlOiBVc2Vyc1NlcnZpY2UsIG9wdGlvbnM6IHt9IH0pO1xuXG4gICAgZnVuY3Rpb24gb25BY3RpdmF0ZSgpIHtcbiAgICAgIHZtLnF1ZXJ5RmlsdGVycyA9IHt9O1xuICAgIH1cbiAgfVxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb25maWcocm91dGVzKTtcblxuICAvKipcbiAgICogQXJxdWl2byBkZSBjb25maWd1cmHDp8OjbyBjb20gYXMgcm90YXMgZXNwZWPDrWZpY2FzIGRvIHJlY3Vyc28gdXNlclxuICAgKlxuICAgKiBAcGFyYW0ge2FueX0gJHN0YXRlUHJvdmlkZXJcbiAgICogQHBhcmFtIHthbnl9IEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyXG4gICAgICAuc3RhdGUoJ2FwcC51c2VyJywge1xuICAgICAgICB1cmw6ICcvdXN1YXJpbycsXG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvdXNlcnMvdXNlcnMuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdVc2Vyc0NvbnRyb2xsZXIgYXMgdXNlcnNDdHJsJyxcbiAgICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IHRydWUsIG5lZWRQcm9maWxlOiBbJ2FkbWluJ10gfVxuICAgICAgfSlcbiAgICAgIC5zdGF0ZSgnYXBwLnVzZXItcHJvZmlsZScsIHtcbiAgICAgICAgdXJsOiAnL3VzdWFyaW8vcGVyZmlsJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy91c2Vycy9wcm9maWxlLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnUHJvZmlsZUNvbnRyb2xsZXIgYXMgcHJvZmlsZUN0cmwnLFxuICAgICAgICBkYXRhOiB7IG5lZWRBdXRoZW50aWNhdGlvbjogdHJ1ZSB9XG4gICAgICB9KTtcblxuICB9XG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZhY3RvcnkoJ1VzZXJzU2VydmljZScsIFVzZXJzU2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBVc2Vyc1NlcnZpY2UobG9kYXNoLCBHbG9iYWwsIHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCd1c2VycycsIHtcbiAgICAgIC8vcXVhbmRvIGluc3RhbmNpYSB1bSB1c3XDoXJpbyBzZW0gcGFzc2FyIHBhcmFtZXRybyxcbiAgICAgIC8vbyBtZXNtbyB2YWkgdGVyIG9zIHZhbG9yZXMgZGVmYXVsdHMgYWJhaXhvXG4gICAgICBkZWZhdWx0czoge1xuICAgICAgICByb2xlczogW11cbiAgICAgIH0sXG5cbiAgICAgIGFjdGlvbnM6IHtcbiAgICAgICAgLyoqXG4gICAgICAgICAqIFNlcnZpw6dvIHF1ZSBhdHVhbGl6YSBvcyBkYWRvcyBkbyBwZXJmaWwgZG8gdXN1w6FyaW8gbG9nYWRvXG4gICAgICAgICAqXG4gICAgICAgICAqIEBwYXJhbSB7b2JqZWN0fSBhdHRyaWJ1dGVzXG4gICAgICAgICAqIEByZXR1cm5zIHtwcm9taXNlfSBVbWEgcHJvbWlzZSBjb20gbyByZXN1bHRhZG8gZG8gY2hhbWFkYSBubyBiYWNrZW5kXG4gICAgICAgICAqL1xuICAgICAgICB1cGRhdGVQcm9maWxlOiB7XG4gICAgICAgICAgbWV0aG9kOiAnUFVUJyxcbiAgICAgICAgICB1cmw6IEdsb2JhbC5hcGlQYXRoICsgJy9wcm9maWxlJyxcbiAgICAgICAgICBvdmVycmlkZTogdHJ1ZSxcbiAgICAgICAgICB3cmFwOiBmYWxzZVxuICAgICAgICB9XG4gICAgICB9LFxuXG4gICAgICBpbnN0YW5jZToge1xuICAgICAgICAvKipcbiAgICAgICAgICogVmVyaWZpY2Egc2UgbyB1c3XDoXJpbyB0ZW0gb3MgcGVyZmlzIGluZm9ybWFkb3MuXG4gICAgICAgICAqXG4gICAgICAgICAqIEBwYXJhbSB7YW55fSByb2xlcyBwZXJmaXMgYSBzZXJlbSB2ZXJpZmljYWRvc1xuICAgICAgICAgKiBAcGFyYW0ge2Jvb2xlYW59IGFsbCBmbGFnIHBhcmEgaW5kaWNhciBzZSB2YWkgY2hlZ2FyIHRvZG9zIG9zIHBlcmZpcyBvdSBzb21lbnRlIHVtIGRlbGVzXG4gICAgICAgICAqIEByZXR1cm5zIHtib29sZWFufVxuICAgICAgICAgKi9cbiAgICAgICAgaGFzUHJvZmlsZTogZnVuY3Rpb24ocm9sZXMsIGFsbCkge1xuICAgICAgICAgIHJvbGVzID0gYW5ndWxhci5pc0FycmF5KHJvbGVzKSA/IHJvbGVzIDogW3JvbGVzXTtcblxuICAgICAgICAgIHZhciB1c2VyUm9sZXMgPSBsb2Rhc2gubWFwKHRoaXMucm9sZXMsICdzbHVnJyk7XG5cbiAgICAgICAgICBpZiAoYWxsKSB7XG4gICAgICAgICAgICByZXR1cm4gbG9kYXNoLmludGVyc2VjdGlvbih1c2VyUm9sZXMsIHJvbGVzKS5sZW5ndGggPT09IHJvbGVzLmxlbmd0aDtcbiAgICAgICAgICB9IGVsc2UgeyAvL3JldHVybiB0aGUgbGVuZ3RoIGJlY2F1c2UgMCBpcyBmYWxzZSBpbiBqc1xuICAgICAgICAgICAgcmV0dXJuIGxvZGFzaC5pbnRlcnNlY3Rpb24odXNlclJvbGVzLCByb2xlcykubGVuZ3RoO1xuICAgICAgICAgIH1cbiAgICAgICAgfSxcblxuICAgICAgICAvKipcbiAgICAgICAgICogVmVyaWZpY2Egc2UgbyB1c3XDoXJpbyB0ZW0gbyBwZXJmaWwgYWRtaW4uXG4gICAgICAgICAqXG4gICAgICAgICAqIEByZXR1cm5zIHtib29sZWFufVxuICAgICAgICAgKi9cbiAgICAgICAgaXNBZG1pbjogZnVuY3Rpb24oKSB7XG4gICAgICAgICAgcmV0dXJuIHRoaXMuaGFzUHJvZmlsZSgnYWRtaW4nKTtcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pO1xuICB9XG5cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICAgLyoqIEBuZ0luamVjdCAqL1xuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29tcG9uZW50KCdib3gnLCB7XG4gICAgICByZXBsYWNlOiB0cnVlLFxuICAgICAgdGVtcGxhdGVVcmw6IFsnR2xvYmFsJywgZnVuY3Rpb24oR2xvYmFsKSB7XG4gICAgICAgIHJldHVybiBHbG9iYWwuY2xpZW50UGF0aCArICcvd2lkZ2V0cy9ib3guaHRtbCdcbiAgICAgIH1dLFxuICAgICAgdHJhbnNjbHVkZToge1xuICAgICAgICB0b29sYmFyQnV0dG9uczogJz9ib3hUb29sYmFyQnV0dG9ucycsXG4gICAgICAgIGZvb3RlckJ1dHRvbnM6ICc/Ym94Rm9vdGVyQnV0dG9ucydcbiAgICAgIH0sXG4gICAgICBiaW5kaW5nczoge1xuICAgICAgICBib3hUaXRsZTogJ0AnLFxuICAgICAgICB0b29sYmFyQ2xhc3M6ICdAJyxcbiAgICAgICAgdG9vbGJhckJnQ29sb3I6ICdAJ1xuICAgICAgfSxcbiAgICAgIGNvbnRyb2xsZXI6IFsnJHRyYW5zY2x1ZGUnLCBmdW5jdGlvbigkdHJhbnNjbHVkZSkge1xuICAgICAgICB2YXIgY3RybCA9IHRoaXM7XG5cbiAgICAgICAgY3RybC50cmFuc2NsdWRlID0gJHRyYW5zY2x1ZGU7XG5cbiAgICAgICAgY3RybC4kb25Jbml0ID0gZnVuY3Rpb24oKSB7XG4gICAgICAgICAgaWYgKGFuZ3VsYXIuaXNVbmRlZmluZWQoY3RybC50b29sYmFyQmdDb2xvcikpIGN0cmwudG9vbGJhckJnQ29sb3IgPSAnZGVmYXVsdC1wcmltYXJ5JztcbiAgICAgICAgfTtcbiAgICAgIH1dXG4gICAgfSk7XG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29tcG9uZW50KCdjb250ZW50Qm9keScsIHtcbiAgICAgIHJlcGxhY2U6IHRydWUsXG4gICAgICB0cmFuc2NsdWRlOiB0cnVlLFxuICAgICAgdGVtcGxhdGVVcmw6IFsnR2xvYmFsJywgZnVuY3Rpb24oR2xvYmFsKSB7XG4gICAgICAgIHJldHVybiBHbG9iYWwuY2xpZW50UGF0aCArICcvd2lkZ2V0cy9jb250ZW50LWJvZHkuaHRtbCdcbiAgICAgIH1dLFxuICAgICAgYmluZGluZ3M6IHtcbiAgICAgICAgbGF5b3V0QWxpZ246ICdAJ1xuICAgICAgfSxcbiAgICAgIGNvbnRyb2xsZXI6IFtmdW5jdGlvbigpIHtcbiAgICAgICAgdmFyIGN0cmwgPSB0aGlzO1xuXG4gICAgICAgIGN0cmwuJG9uSW5pdCA9IGZ1bmN0aW9uKCkge1xuICAgICAgICAgIC8vIE1ha2UgYSBjb3B5IG9mIHRoZSBpbml0aWFsIHZhbHVlIHRvIGJlIGFibGUgdG8gcmVzZXQgaXQgbGF0ZXJcbiAgICAgICAgICBjdHJsLmxheW91dEFsaWduID0gYW5ndWxhci5pc0RlZmluZWQoY3RybC5sYXlvdXRBbGlnbikgPyBjdHJsLmxheW91dEFsaWduIDogJ2NlbnRlciBzdGFydCc7XG4gICAgICAgIH07XG4gICAgICB9XVxuICAgIH0pO1xuXG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29tcG9uZW50KCdjb250ZW50SGVhZGVyJywge1xuICAgICAgdGVtcGxhdGVVcmw6IFsnR2xvYmFsJywgZnVuY3Rpb24oR2xvYmFsKSB7XG4gICAgICAgIHJldHVybiBHbG9iYWwuY2xpZW50UGF0aCArICcvd2lkZ2V0cy9jb250ZW50LWhlYWRlci5odG1sJ1xuICAgICAgfV0sXG4gICAgICByZXBsYWNlOiB0cnVlLFxuICAgICAgYmluZGluZ3M6IHtcbiAgICAgICAgdGl0bGU6ICdAJyxcbiAgICAgICAgZGVzY3JpcHRpb246ICdAJ1xuICAgICAgfVxuICAgIH0pO1xuXG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmlsdGVyKCdhdWRpdERldGFpbFRpdGxlJywgYXVkaXREZXRhaWxUaXRsZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBhdWRpdERldGFpbFRpdGxlKCR0cmFuc2xhdGUpIHtcbiAgICByZXR1cm4gZnVuY3Rpb24oYXVkaXREZXRhaWwsIHN0YXR1cykge1xuICAgICAgaWYgKGF1ZGl0RGV0YWlsLnR5cGUgPT09ICd1cGRhdGVkJykge1xuICAgICAgICBpZiAoc3RhdHVzID09PSAnYmVmb3JlJykge1xuICAgICAgICAgIHJldHVybiAkdHJhbnNsYXRlLmluc3RhbnQoJ2RpYWxvZy5hdWRpdC51cGRhdGVkQmVmb3JlJyk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgcmV0dXJuICR0cmFuc2xhdGUuaW5zdGFudCgnZGlhbG9nLmF1ZGl0LnVwZGF0ZWRBZnRlcicpO1xuICAgICAgICB9XG4gICAgICB9IGVsc2Uge1xuICAgICAgICByZXR1cm4gJHRyYW5zbGF0ZS5pbnN0YW50KCdkaWFsb2cuYXVkaXQuJyArIGF1ZGl0RGV0YWlsLnR5cGUpO1xuICAgICAgfVxuICAgIH1cbiAgfVxuXG59KSgpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmlsdGVyKCdhdWRpdE1vZGVsJywgYXVkaXRNb2RlbCk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBhdWRpdE1vZGVsKCR0cmFuc2xhdGUpIHtcbiAgICByZXR1cm4gZnVuY3Rpb24obW9kZWxJZCkge1xuICAgICAgbW9kZWxJZCA9IG1vZGVsSWQucmVwbGFjZSgnQXBwXFxcXCcsICcnKTtcbiAgICAgIHZhciBtb2RlbCA9ICR0cmFuc2xhdGUuaW5zdGFudCgnbW9kZWxzLicgKyBtb2RlbElkLnRvTG93ZXJDYXNlKCkpO1xuXG4gICAgICByZXR1cm4gKG1vZGVsKSA/IG1vZGVsIDogbW9kZWxJZDtcbiAgICB9XG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZpbHRlcignYXVkaXRUeXBlJywgYXVkaXRUeXBlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIGF1ZGl0VHlwZShsb2Rhc2gsIEF1ZGl0U2VydmljZSkge1xuICAgIHJldHVybiBmdW5jdGlvbih0eXBlSWQpIHtcbiAgICAgIHZhciB0eXBlID0gbG9kYXNoLmZpbmQoQXVkaXRTZXJ2aWNlLmxpc3RUeXBlcygpLCB7IGlkOiB0eXBlSWQgfSk7XG5cbiAgICAgIHJldHVybiAodHlwZSkgPyB0eXBlLmxhYmVsIDogdHlwZTtcbiAgICB9XG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZpbHRlcignYXVkaXRWYWx1ZScsIGF1ZGl0VmFsdWUpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gYXVkaXRWYWx1ZSgkZmlsdGVyLCBsb2Rhc2gpIHtcbiAgICByZXR1cm4gZnVuY3Rpb24odmFsdWUsIGtleSkge1xuICAgICAgaWYgKGFuZ3VsYXIuaXNEYXRlKHZhbHVlKSB8fCBsb2Rhc2guZW5kc1dpdGgoa2V5LCAnX2F0JykgfHwgIGxvZGFzaC5lbmRzV2l0aChrZXksICdfdG8nKSkge1xuICAgICAgICByZXR1cm4gJGZpbHRlcigncHJEYXRldGltZScpKHZhbHVlKTtcbiAgICAgIH1cblxuICAgICAgaWYgKHR5cGVvZiB2YWx1ZSA9PT0gJ2Jvb2xlYW4nKSB7XG4gICAgICAgIHJldHVybiAkZmlsdGVyKCd0cmFuc2xhdGUnKSgodmFsdWUpID8gJ2dsb2JhbC55ZXMnIDogJ2dsb2JhbC5ubycpO1xuICAgICAgfVxuXG4gICAgICAvL2NoZWNrIGlzIGZsb2F0XG4gICAgICBpZiAoTnVtYmVyKHZhbHVlKSA9PT0gdmFsdWUgJiYgdmFsdWUgJSAxICE9PSAwKSB7XG4gICAgICAgIHJldHVybiAkZmlsdGVyKCdyZWFsJykodmFsdWUpO1xuICAgICAgfVxuXG4gICAgICByZXR1cm4gdmFsdWU7XG4gICAgfVxuICB9XG5cbn0pKCk7XG4iLCIvKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCwgbm8tdW5kZWY6IDAqL1xuKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnN0YW50KCdwdC1CUi5pMThuLmF0dHJpYnV0ZXMnLCB7XG4gICAgICBlbWFpbDogJ0VtYWlsJyxcbiAgICAgIHBhc3N3b3JkOiAnU2VuaGEnLFxuICAgICAgbmFtZTogJ05vbWUnLFxuICAgICAgaW1hZ2U6ICdJbWFnZW0nLFxuICAgICAgcm9sZXM6ICdQZXJmaXMnLFxuICAgICAgZGF0ZTogJ0RhdGEnLFxuICAgICAgaW5pdGlhbERhdGU6ICdEYXRhIEluaWNpYWwnLFxuICAgICAgZmluYWxEYXRlOiAnRGF0YSBGaW5hbCcsXG4gICAgICB0YXNrOiB7XG4gICAgICAgIGRlc2NyaXB0aW9uOiAnRGVzY3Jpw6fDo28nLFxuICAgICAgICBkb25lOiAnRmVpdG8/JyxcbiAgICAgICAgcHJpb3JpdHk6ICdQcmlvcmlkYWRlJyxcbiAgICAgICAgc2NoZWR1bGVkX3RvOiAnQWdlbmRhZG8gUGFyYT8nLFxuICAgICAgICBwcm9qZWN0OiAnUHJvamV0bydcbiAgICAgIH0sXG4gICAgICBwcm9qZWN0OiB7XG4gICAgICAgIGNvc3Q6ICdDdXN0bydcbiAgICAgIH0sXG4gICAgICAvL8OpIGNhcnJlZ2FkbyBkbyBzZXJ2aWRvciBjYXNvIGVzdGVqYSBkZWZpbmlkbyBubyBtZXNtb1xuICAgICAgYXVkaXRNb2RlbDoge1xuICAgICAgfVxuICAgIH0pXG5cbn0oKSk7XG4iLCIvKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCwgbm8tdW5kZWY6IDAqL1xuKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnN0YW50KCdwdC1CUi5pMThuLmRpYWxvZycsIHtcbiAgICAgIGNvbmZpcm1UaXRsZTogJ0NvbmZpcm1hw6fDo28nLFxuICAgICAgY29uZmlybURlc2NyaXB0aW9uOiAnQ29uZmlybWEgYSBhw6fDo28/JyxcbiAgICAgIHJlbW92ZURlc2NyaXB0aW9uOiAnRGVzZWphIHJlbW92ZXIgcGVybWFuZW50ZW1lbnRlIHt7bmFtZX19PycsXG4gICAgICBhdWRpdDoge1xuICAgICAgICBjcmVhdGVkOiAnSW5mb3JtYcOnw7VlcyBkbyBDYWRhc3RybycsXG4gICAgICAgIHVwZGF0ZWRCZWZvcmU6ICdBbnRlcyBkYSBBdHVhbGl6YcOnw6NvJyxcbiAgICAgICAgdXBkYXRlZEFmdGVyOiAnRGVwb2lzIGRhIEF0dWFsaXphw6fDo28nLFxuICAgICAgICBkZWxldGVkOiAnSW5mb3JtYcOnw7VlcyBhbnRlcyBkZSByZW1vdmVyJ1xuICAgICAgfSxcbiAgICAgIGxvZ2luOiB7XG4gICAgICAgIHJlc2V0UGFzc3dvcmQ6IHtcbiAgICAgICAgICBkZXNjcmlwdGlvbjogJ0RpZ2l0ZSBhYmFpeG8gbyBlbWFpbCBjYWRhc3RyYWRvIG5vIHNpc3RlbWEuJ1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfSlcblxufSgpKTtcbiIsIi8qZXNsaW50IGFuZ3VsYXIvZmlsZS1uYW1lOiAwLCBuby11bmRlZjogMCovXG4oZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uc3RhbnQoJ3B0LUJSLmkxOG4uZ2xvYmFsJywge1xuICAgICAgbG9hZGluZzogJ0NhcnJlZ2FuZG8uLi4nLFxuICAgICAgcHJvY2Vzc2luZzogJ1Byb2Nlc3NhbmRvLi4uJyxcbiAgICAgIHllczogJ1NpbScsXG4gICAgICBubzogJ07Do28nLFxuICAgICAgYWxsOiAnVG9kb3MnXG4gICAgfSlcblxufSgpKTtcbiIsIi8qZXNsaW50IGFuZ3VsYXIvZmlsZS1uYW1lOiAwLCBuby11bmRlZjogMCovXG4oZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uc3RhbnQoJ3B0LUJSLmkxOG4ubWVzc2FnZXMnLCB7XG4gICAgICBpbnRlcm5hbEVycm9yOiAnT2NvcnJldSB1bSBlcnJvIGludGVybm8sIGNvbnRhdGUgbyBhZG1pbmlzdHJhZG9yIGRvIHNpc3RlbWEnLFxuICAgICAgbm90Rm91bmQ6ICdOZW5odW0gcmVnaXN0cm8gZW5jb250cmFkbycsXG4gICAgICBub3RBdXRob3JpemVkOiAnVm9jw6ogbsOjbyB0ZW0gYWNlc3NvIGEgZXN0YSBmdW5jaW9uYWxpZGFkZS4nLFxuICAgICAgc2VhcmNoRXJyb3I6ICdOw6NvIGZvaSBwb3Nzw612ZWwgcmVhbGl6YXIgYSBidXNjYS4nLFxuICAgICAgc2F2ZVN1Y2Nlc3M6ICdSZWdpc3RybyBzYWx2byBjb20gc3VjZXNzby4nLFxuICAgICAgb3BlcmF0aW9uU3VjY2VzczogJ09wZXJhw6fDo28gcmVhbGl6YWRhIGNvbSBzdWNlc3NvLicsXG4gICAgICBvcGVyYXRpb25FcnJvcjogJ0Vycm8gYW8gcmVhbGl6YXIgYSBvcGVyYcOnw6NvJyxcbiAgICAgIHNhdmVFcnJvcjogJ0Vycm8gYW8gdGVudGFyIHNhbHZhciBvIHJlZ2lzdHJvLicsXG4gICAgICByZW1vdmVTdWNjZXNzOiAnUmVtb8Onw6NvIHJlYWxpemFkYSBjb20gc3VjZXNzby4nLFxuICAgICAgcmVtb3ZlRXJyb3I6ICdFcnJvIGFvIHRlbnRhciByZW1vdmVyIG8gcmVnaXN0cm8uJyxcbiAgICAgIHJlc291cmNlTm90Rm91bmRFcnJvcjogJ1JlY3Vyc28gbsOjbyBlbmNvbnRyYWRvJyxcbiAgICAgIG5vdE51bGxFcnJvcjogJ1RvZG9zIG9zIGNhbXBvcyBvYnJpZ2F0w7NyaW9zIGRldmVtIHNlciBwcmVlbmNoaWRvcy4nLFxuICAgICAgZHVwbGljYXRlZFJlc291cmNlRXJyb3I6ICdKw6EgZXhpc3RlIHVtIHJlY3Vyc28gY29tIGVzc2FzIGluZm9ybWHDp8O1ZXMuJyxcbiAgICAgIHZhbGlkYXRlOiB7XG4gICAgICAgIGZpZWxkUmVxdWlyZWQ6ICdPIGNhbXBvIHt7ZmllbGR9fSDDqSBvYnJpZ3JhdMOzcmlvLidcbiAgICAgIH0sXG4gICAgICBsYXlvdXQ6IHtcbiAgICAgICAgZXJyb3I0MDQ6ICdQw6FnaW5hIG7Do28gZW5jb250cmFkYSdcbiAgICAgIH0sXG4gICAgICBsb2dpbjoge1xuICAgICAgICBsb2dvdXRJbmFjdGl2ZTogJ1ZvY8OqIGZvaSBkZXNsb2dhZG8gZG8gc2lzdGVtYSBwb3IgaW5hdGl2aWRhZGUuIEZhdm9yIGVudHJhciBubyBzaXN0ZW1hIG5vdmFtZW50ZS4nLFxuICAgICAgICBpbnZhbGlkQ3JlZGVudGlhbHM6ICdDcmVkZW5jaWFpcyBJbnbDoWxpZGFzJyxcbiAgICAgICAgdW5rbm93bkVycm9yOiAnTsOjbyBmb2kgcG9zc8OtdmVsIHJlYWxpemFyIG8gbG9naW4uIFRlbnRlIG5vdmFtZW50ZS4gJyArXG4gICAgICAgICAgJ0Nhc28gbsOjbyBjb25zaWdhIGZhdm9yIGVuY29udHJhciBlbSBjb250YXRvIGNvbSBvIGFkbWluaXN0cmFkb3IgZG8gc2lzdGVtYS4nLFxuICAgICAgICB1c2VyTm90Rm91bmQ6ICdOw6NvIGZvaSBwb3Nzw612ZWwgZW5jb250cmFyIHNldXMgZGFkb3MnXG4gICAgICB9LFxuICAgICAgZGFzaGJvYXJkOiB7XG4gICAgICAgIHdlbGNvbWU6ICdTZWphIGJlbSBWaW5kbyB7e3VzZXJOYW1lfX0nLFxuICAgICAgICBkZXNjcmlwdGlvbjogJ1V0aWxpemUgbyBtZW51IHBhcmEgbmF2ZWdhw6fDo28uJ1xuICAgICAgfSxcbiAgICAgIG1haWw6IHtcbiAgICAgICAgbWFpbEVycm9yczogJ09jb3JyZXUgdW0gZXJybyBub3Mgc2VndWludGVzIGVtYWlscyBhYmFpeG86XFxuJyxcbiAgICAgICAgc2VuZE1haWxTdWNjZXNzOiAnRW1haWwgZW52aWFkbyBjb20gc3VjZXNzbyEnLFxuICAgICAgICBzZW5kTWFpbEVycm9yOiAnTsOjbyBmb2kgcG9zc8OtdmVsIGVudmlhciBvIGVtYWlsLicsXG4gICAgICAgIHBhc3N3b3JkU2VuZGluZ1N1Y2Nlc3M6ICdPIHByb2Nlc3NvIGRlIHJlY3VwZXJhw6fDo28gZGUgc2VuaGEgZm9pIGluaWNpYWRvLiBDYXNvIG8gZW1haWwgbsOjbyBjaGVndWUgZW0gMTAgbWludXRvcyB0ZW50ZSBub3ZhbWVudGUuJ1xuICAgICAgfSxcbiAgICAgIHVzZXI6IHtcbiAgICAgICAgcmVtb3ZlWW91clNlbGZFcnJvcjogJ1ZvY8OqIG7Do28gcG9kZSByZW1vdmVyIHNldSBwcsOzcHJpbyB1c3XDoXJpbycsXG4gICAgICAgIHVzZXJFeGlzdHM6ICdVc3XDoXJpbyBqw6EgYWRpY2lvbmFkbyEnLFxuICAgICAgICBwcm9maWxlOiB7XG4gICAgICAgICAgdXBkYXRlRXJyb3I6ICdOw6NvIGZvaSBwb3Nzw612ZWwgYXR1YWxpemFyIHNldSBwcm9maWxlJ1xuICAgICAgICB9XG4gICAgICB9LFxuICAgICAgcXVlcnlEaW5hbWljOiB7XG4gICAgICAgIG5vRmlsdGVyOiAnTmVuaHVtIGZpbHRybyBhZGljaW9uYWRvJ1xuICAgICAgfVxuICAgIH0pXG5cbn0oKSk7XG4iLCIvKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCwgbm8tdW5kZWY6IDAqL1xuKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnN0YW50KCdwdC1CUi5pMThuLm1vZGVscycsIHtcbiAgICAgIHVzZXI6ICdVc3XDoXJpbycsXG4gICAgICB0YXNrOiAnVGFyZWZhJyxcbiAgICAgIHByb2plY3Q6ICdQcm9qZXRvJ1xuICAgIH0pXG5cbn0oKSk7XG4iLCIvKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCwgbm8tdW5kZWY6IDAqL1xuKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnN0YW50KCdwdC1CUi5pMThuLnZpZXdzJywge1xuICAgICAgYnJlYWRjcnVtYnM6IHtcbiAgICAgICAgdXNlcjogJ0FkbWluaXN0cmHDp8OjbyAtIFVzdcOhcmlvJyxcbiAgICAgICAgJ3VzZXItcHJvZmlsZSc6ICdQZXJmaWwnLFxuICAgICAgICBkYXNoYm9hcmQ6ICdEYXNoYm9hcmQnLFxuICAgICAgICBhdWRpdDogJ0FkbWluaXN0cmHDp8OjbyAtIEF1ZGl0b3JpYScsXG4gICAgICAgIG1haWw6ICdBZG1pbmlzdHJhw6fDo28gLSBFbnZpbyBkZSBlLW1haWwnLFxuICAgICAgICBwcm9qZWN0OiAnRXhlbXBsb3MgLSBQcm9qZXRvcycsXG4gICAgICAgICdkaW5hbWljLXF1ZXJ5JzogJ0FkbWluaXN0cmHDp8OjbyAtIENvbnN1bHRhcyBEaW7Dom1pY2FzJyxcbiAgICAgICAgJ25vdC1hdXRob3JpemVkJzogJ0FjZXNzbyBOZWdhZG8nXG4gICAgICB9LFxuICAgICAgdGl0bGVzOiB7XG4gICAgICAgIGRhc2hib2FyZDogJ1DDoWdpbmEgaW5pY2lhbCcsXG4gICAgICAgIG1haWxTZW5kOiAnRW52aWFyIGUtbWFpbCcsXG4gICAgICAgIHRhc2tMaXN0OiAnTGlzdGEgZGUgVGFyZWZhcycsXG4gICAgICAgIHVzZXJMaXN0OiAnTGlzdGEgZGUgVXN1w6FyaW9zJyxcbiAgICAgICAgYXVkaXRMaXN0OiAnTGlzdGEgZGUgTG9ncycsXG4gICAgICAgIHJlZ2lzdGVyOiAnRm9ybXVsw6FyaW8gZGUgQ2FkYXN0cm8nLFxuICAgICAgICByZXNldFBhc3N3b3JkOiAnUmVkZWZpbmlyIFNlbmhhJyxcbiAgICAgICAgdXBkYXRlOiAnRm9ybXVsw6FyaW8gZGUgQXR1YWxpemHDp8OjbydcbiAgICAgIH0sXG4gICAgICBhY3Rpb25zOiB7XG4gICAgICAgIHNlbmQ6ICdFbnZpYXInLFxuICAgICAgICBzYXZlOiAnU2FsdmFyJyxcbiAgICAgICAgY2xlYXI6ICdMaW1wYXInLFxuICAgICAgICBjbGVhckFsbDogJ0xpbXBhciBUdWRvJyxcbiAgICAgICAgcmVzdGFydDogJ1JlaW5pY2lhcicsXG4gICAgICAgIGZpbHRlcjogJ0ZpbHRyYXInLFxuICAgICAgICBzZWFyY2g6ICdQZXNxdWlzYXInLFxuICAgICAgICBsaXN0OiAnTGlzdGFyJyxcbiAgICAgICAgZWRpdDogJ0VkaXRhcicsXG4gICAgICAgIGNhbmNlbDogJ0NhbmNlbGFyJyxcbiAgICAgICAgdXBkYXRlOiAnQXR1YWxpemFyJyxcbiAgICAgICAgcmVtb3ZlOiAnUmVtb3ZlcicsXG4gICAgICAgIGdldE91dDogJ1NhaXInLFxuICAgICAgICBhZGQ6ICdBZGljaW9uYXInLFxuICAgICAgICBpbjogJ0VudHJhcicsXG4gICAgICAgIGxvYWRJbWFnZTogJ0NhcnJlZ2FyIEltYWdlbScsXG4gICAgICAgIHNpZ251cDogJ0NhZGFzdHJhcidcbiAgICAgIH0sXG4gICAgICBmaWVsZHM6IHtcbiAgICAgICAgZGF0ZTogJ0RhdGEnLFxuICAgICAgICBhY3Rpb246ICdBw6fDo28nLFxuICAgICAgICBhY3Rpb25zOiAnQcOnw7VlcycsXG4gICAgICAgIGF1ZGl0OiB7XG4gICAgICAgICAgZGF0ZVN0YXJ0OiAnRGF0YSBJbmljaWFsJyxcbiAgICAgICAgICBkYXRlRW5kOiAnRGF0YSBGaW5hbCcsXG4gICAgICAgICAgcmVzb3VyY2U6ICdSZWN1cnNvJyxcbiAgICAgICAgICBhbGxSZXNvdXJjZXM6ICdUb2RvcyBSZWN1cnNvcycsXG4gICAgICAgICAgdHlwZToge1xuICAgICAgICAgICAgY3JlYXRlZDogJ0NhZGFzdHJhZG8nLFxuICAgICAgICAgICAgdXBkYXRlZDogJ0F0dWFsaXphZG8nLFxuICAgICAgICAgICAgZGVsZXRlZDogJ1JlbW92aWRvJ1xuICAgICAgICAgIH1cbiAgICAgICAgfSxcbiAgICAgICAgbG9naW46IHtcbiAgICAgICAgICByZXNldFBhc3N3b3JkOiAnRXNxdWVjaSBtaW5oYSBzZW5oYScsXG4gICAgICAgICAgY29uZmlybVBhc3N3b3JkOiAnQ29uZmlybWFyIHNlbmhhJ1xuICAgICAgICB9LFxuICAgICAgICBtYWlsOiB7XG4gICAgICAgICAgdG86ICdQYXJhJyxcbiAgICAgICAgICBzdWJqZWN0OiAnQXNzdW50bycsXG4gICAgICAgICAgbWVzc2FnZTogJ01lbnNhZ2VtJ1xuICAgICAgICB9LFxuICAgICAgICBxdWVyeURpbmFtaWM6IHtcbiAgICAgICAgICBmaWx0ZXJzOiAnRmlsdHJvcycsXG4gICAgICAgICAgcmVzdWx0czogJ1Jlc3VsdGFkb3MnLFxuICAgICAgICAgIG1vZGVsOiAnTW9kZWwnLFxuICAgICAgICAgIGF0dHJpYnV0ZTogJ0F0cmlidXRvJyxcbiAgICAgICAgICBvcGVyYXRvcjogJ09wZXJhZG9yJyxcbiAgICAgICAgICByZXNvdXJjZTogJ1JlY3Vyc28nLFxuICAgICAgICAgIHZhbHVlOiAnVmFsb3InLFxuICAgICAgICAgIG9wZXJhdG9yczoge1xuICAgICAgICAgICAgZXF1YWxzOiAnSWd1YWwnLFxuICAgICAgICAgICAgZGlmZXJlbnQ6ICdEaWZlcmVudGUnLFxuICAgICAgICAgICAgY29udGVpbnM6ICdDb250w6ltJyxcbiAgICAgICAgICAgIHN0YXJ0V2l0aDogJ0luaWNpYSBjb20nLFxuICAgICAgICAgICAgZmluaXNoV2l0aDogJ0ZpbmFsaXphIGNvbScsXG4gICAgICAgICAgICBiaWdnZXJUaGFuOiAnTWFpb3InLFxuICAgICAgICAgICAgZXF1YWxzT3JCaWdnZXJUaGFuOiAnTWFpb3Igb3UgSWd1YWwnLFxuICAgICAgICAgICAgbGVzc1RoYW46ICdNZW5vcicsXG4gICAgICAgICAgICBlcXVhbHNPckxlc3NUaGFuOiAnTWVub3Igb3UgSWd1YWwnXG4gICAgICAgICAgfVxuICAgICAgICB9LFxuICAgICAgICBwcm9qZWN0OiB7XG4gICAgICAgICAgbmFtZTogJ05vbWUnLFxuICAgICAgICAgIHRvdGFsVGFzazogJ1RvdGFsIGRlIFRhcmVmYXMnXG4gICAgICAgIH0sXG4gICAgICAgIHRhc2s6IHtcbiAgICAgICAgICBkb25lOiAnTsOjbyBGZWl0byAvIEZlaXRvJ1xuICAgICAgICB9LFxuICAgICAgICB1c2VyOiB7XG4gICAgICAgICAgcGVyZmlsczogJ1BlcmZpcycsXG4gICAgICAgICAgbmFtZU9yRW1haWw6ICdOb21lIG91IEVtYWlsJ1xuICAgICAgICB9XG4gICAgICB9LFxuICAgICAgbGF5b3V0OiB7XG4gICAgICAgIG1lbnU6IHtcbiAgICAgICAgICBkYXNoYm9hcmQ6ICdEYXNoYm9hcmQnLFxuICAgICAgICAgIHByb2plY3Q6ICdQcm9qZXRvcycsXG4gICAgICAgICAgYWRtaW46ICdBZG1pbmlzdHJhw6fDo28nLFxuICAgICAgICAgIGV4YW1wbGVzOiAnRXhlbXBsb3MnLFxuICAgICAgICAgIHVzZXI6ICdVc3XDoXJpb3MnLFxuICAgICAgICAgIG1haWw6ICdFbnZpYXIgZS1tYWlsJyxcbiAgICAgICAgICBhdWRpdDogJ0F1ZGl0b3JpYScsXG4gICAgICAgICAgZGluYW1pY1F1ZXJ5OiAnQ29uc3VsdGFzIERpbmFtaWNhcydcbiAgICAgICAgfVxuICAgICAgfSxcbiAgICAgIHRvb2x0aXBzOiB7XG4gICAgICAgIGF1ZGl0OiB7XG4gICAgICAgICAgdmlld0RldGFpbDogJ1Zpc3VhbGl6YXIgRGV0YWxoYW1lbnRvJ1xuICAgICAgICB9LFxuICAgICAgICB1c2VyOiB7XG4gICAgICAgICAgcGVyZmlsOiAnUGVyZmlsJyxcbiAgICAgICAgICB0cmFuc2ZlcjogJ1RyYW5zZmVyaXInXG4gICAgICAgIH0sXG4gICAgICAgIHRhc2s6IHtcbiAgICAgICAgICBsaXN0VGFzazogJ0xpc3RhciBUYXJlZmFzJ1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfSlcblxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnRyb2xsZXIoJ1Byb2plY3RzQ29udHJvbGxlcicsIFByb2plY3RzQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBQcm9qZWN0c0NvbnRyb2xsZXIoR2xvYmFsLCAkY29udHJvbGxlciwgUHJvamVjdHNTZXJ2aWNlLCBQckRpYWxvZykge1xuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICAvL0F0dHJpYnV0ZXMgQmxvY2tcblxuICAgIC8vRnVuY3Rpb25zIEJsb2NrXG4gICAgdm0ub25BY3RpdmF0ZSA9IG9uQWN0aXZhdGU7XG4gICAgdm0uYXBwbHlGaWx0ZXJzID0gYXBwbHlGaWx0ZXJzO1xuICAgIHZtLnZpZXdUYXNrcyA9IHZpZXdUYXNrcztcblxuICAgIC8vIGluc3RhbnRpYXRlIGJhc2UgY29udHJvbGxlclxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHsgdm06IHZtLCBtb2RlbFNlcnZpY2U6IFByb2plY3RzU2VydmljZSwgb3B0aW9uczoge30gfSk7XG5cbiAgICBmdW5jdGlvbiBvbkFjdGl2YXRlKCkge1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0ge307XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gYXBwbHlGaWx0ZXJzKGRlZmF1bHRRdWVyeUZpbHRlcnMpIHtcbiAgICAgIHJldHVybiBhbmd1bGFyLmV4dGVuZChkZWZhdWx0UXVlcnlGaWx0ZXJzLCB2bS5xdWVyeUZpbHRlcnMpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIHZpZXdUYXNrcyhwcm9qZWN0SWQpIHtcbiAgICAgIHZhciBjb25maWcgPSB7XG4gICAgICAgIGxvY2Fsczoge1xuICAgICAgICAgIHByb2plY3RJZDogcHJvamVjdElkXG4gICAgICAgIH0sXG4gICAgICAgIGNvbnRyb2xsZXI6ICdUYXNrc0RpYWxvZ0NvbnRyb2xsZXInLFxuICAgICAgICBjb250cm9sbGVyQXM6ICd0YXNrc0N0cmwnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL3NhbXBsZXMvdGFza3MvdGFza3MtZGlhbG9nLmh0bWwnLFxuICAgICAgICBoYXNCYWNrZHJvcDogdHJ1ZVxuICAgICAgfTtcblxuICAgICAgUHJEaWFsb2cuY3VzdG9tKGNvbmZpZykuZmluYWxseShmdW5jdGlvbigpIHtcbiAgICAgICAgdm0uc2VhcmNoKHZtLnBhZ2luYXRvci5jdXJyZW50UGFnZSk7XG4gICAgICB9KTtcblxuICAgIH1cblxuICB9XG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqXG4gICAqIEFycXVpdm8gZGUgY29uZmlndXJhw6fDo28gY29tIGFzIHJvdGFzIGVzcGVjw61maWNhcyBkbyByZWN1cnNvIHByb2plY3RcbiAgICpcbiAgICogQHBhcmFtIHthbnl9ICRzdGF0ZVByb3ZpZGVyXG4gICAqIEBwYXJhbSB7YW55fSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlclxuICAgICAgLnN0YXRlKCdhcHAucHJvamVjdCcsIHtcbiAgICAgICAgdXJsOiAnL3Byb2pldG9zJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9zYW1wbGVzL3Byb2plY3RzL3Byb2plY3RzLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnUHJvamVjdHNDb250cm9sbGVyIGFzIHByb2plY3RzQ3RybCcsXG4gICAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiB0cnVlLCBuZWVkUHJvZmlsZTogWydhZG1pbiddIH1cbiAgICAgIH0pO1xuICB9XG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZhY3RvcnkoJ1Byb2plY3RzU2VydmljZScsIFByb2plY3RzU2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiBQcm9qZWN0c1NlcnZpY2Uoc2VydmljZUZhY3RvcnkpIHtcbiAgICByZXR1cm4gc2VydmljZUZhY3RvcnkoJ3Byb2plY3RzJywge1xuICAgICAgYWN0aW9uczogeyB9LFxuICAgICAgaW5zdGFuY2U6IHsgfVxuICAgIH0pO1xuICB9XG5cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb250cm9sbGVyKCdUYXNrc0RpYWxvZ0NvbnRyb2xsZXInLCBUYXNrc0RpYWxvZ0NvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gVGFza3NEaWFsb2dDb250cm9sbGVyKCRjb250cm9sbGVyLCBUYXNrc1NlcnZpY2UsIHByb2plY3RJZCwgUHJUb2FzdCwgLy8gTk9TT05BUlxuICAgIFByRGlhbG9nLCAkdHJhbnNsYXRlLCBHbG9iYWwsIG1vbWVudCkge1xuXG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIC8vRnVuY3Rpb25zIEJsb2NrXG4gICAgdm0ub25BY3RpdmF0ZSAgID0gb25BY3RpdmF0ZTtcbiAgICB2bS5jbG9zZSAgICAgICAgPSBjbG9zZTtcbiAgICB2bS5hcHBseUZpbHRlcnMgPSBhcHBseUZpbHRlcnM7XG4gICAgdm0uYmVmb3JlU2F2ZSAgID0gYmVmb3JlU2F2ZTtcbiAgICB2bS5hZnRlclNhdmUgICAgPSBhZnRlclNhdmU7XG4gICAgdm0udG9nZ2xlRG9uZSAgID0gdG9nZ2xlRG9uZTtcblxuICAgIC8vIGluc3RhbnRpYXRlIGJhc2UgY29udHJvbGxlclxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHsgdm06IHZtLCBtb2RlbFNlcnZpY2U6IFRhc2tzU2VydmljZSwgb3B0aW9uczoge1xuICAgICAgcGVyUGFnZTogNVxuICAgIH0gfSk7XG5cbiAgICBmdW5jdGlvbiBvbkFjdGl2YXRlKCkge1xuICAgICAgdm0uZ2xvYmFsID0gR2xvYmFsO1xuICAgICAgdm0ucmVzb3VyY2Uuc2NoZWR1bGVkX3RvID0gbW9tZW50KCkuYWRkKDMwLCAnbWludXRlcycpO1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0geyBwcm9qZWN0SWQ6IHByb2plY3RJZCB9O1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGFwcGx5RmlsdGVycyhkZWZhdWx0UXVlcnlGaWx0ZXJzKSB7XG4gICAgICByZXR1cm4gYW5ndWxhci5leHRlbmQoZGVmYXVsdFF1ZXJ5RmlsdGVycywgdm0ucXVlcnlGaWx0ZXJzKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBiZWZvcmVTYXZlKCkge1xuICAgICAgdm0ucmVzb3VyY2UucHJvamVjdF9pZCA9IHZtLnF1ZXJ5RmlsdGVycy5wcm9qZWN0SWQ7XG4gICAgICB2bS5yZXNvdXJjZS5wcm9qZWN0ID0gbnVsbDtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBhZnRlclNhdmUoKSB7XG4gICAgICB2bS5jbGVhbkZvcm0oKTtcbiAgICAgIHZtLnNlYXJjaCh2bS5wYWdpbmF0b3IuY3VycmVudFBhZ2UpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGNsb3NlKCkge1xuICAgICAgdm0uY2xlYW5Gb3JtKCk7XG4gICAgICBQckRpYWxvZy5jbG9zZSgpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIHRvZ2dsZURvbmUocmVzb3VyY2UpIHtcbiAgICAgIFRhc2tzU2VydmljZS50b2dnbGVEb25lKHsgaWQ6IHJlc291cmNlLmlkLCBkb25lOiByZXNvdXJjZS5kb25lIH0pLnRoZW4oZnVuY3Rpb24oKSB7XG4gICAgICAgIFByVG9hc3Quc3VjY2VzcygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnNhdmVTdWNjZXNzJykpO1xuICAgICAgICB2bS5zZWFyY2godm0ucGFnaW5hdG9yLmN1cnJlbnRQYWdlKTtcbiAgICAgIH0sIGZ1bmN0aW9uKGVycm9yKSB7XG4gICAgICAgIFByVG9hc3QuZXJyb3JWYWxpZGF0aW9uKGVycm9yLmRhdGEsICR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMub3BlcmF0aW9uRXJyb3InKSk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgfVxuXG59KSgpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZhY3RvcnkoJ1Rhc2tzU2VydmljZScsIFRhc2tzU2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiBUYXNrc1NlcnZpY2Uoc2VydmljZUZhY3RvcnksIG1vbWVudCkge1xuICAgIHJldHVybiBzZXJ2aWNlRmFjdG9yeSgndGFza3MnLCB7XG4gICAgICAvL3F1YW5kbyBpbnN0YW5jaWEgdW0gdXN1w6FyaW8gc2VtIHBhc3NhciBwYXJhbWV0cm8sXG4gICAgICAvL28gbWVzbW8gdmFpIHRlciBvcyB2YWxvcmVzIGRlZmF1bHRzIGFiYWl4b1xuICAgICAgZGVmYXVsdHM6IHtcbiAgICAgICAgc2NoZWR1bGVkX3RvOiBuZXcgRGF0ZSgpXG4gICAgICB9LFxuXG4gICAgICBtYXA6IHtcbiAgICAgICAgLy9jb252ZXJ0IHBhcmEgb2JqZXRvIGphdmFzY3JpcHQgZGF0ZSB1bWEgc3RyaW5nIGZvcm1hdGFkYSBjb21vIGRhdGFcbiAgICAgICAgc2NoZWR1bGVkX3RvOiBmdW5jdGlvbih2YWx1ZSkge1xuICAgICAgICAgIHJldHVybiBtb21lbnQodmFsdWUpLnRvRGF0ZSgpO1xuICAgICAgICB9XG4gICAgICB9LFxuXG4gICAgICBhY3Rpb25zOiB7XG4gICAgICAgIC8qKlxuICAgICAgICAgKiBBdHVhbGl6YSBvcyBzdGF0dXMgZGEgdGFyZWZhXG4gICAgICAgICAqXG4gICAgICAgICAqIEBwYXJhbSB7b2JqZWN0fSBhdHRyaWJ1dGVzXG4gICAgICAgICAqL1xuICAgICAgICB0b2dnbGVEb25lOiB7XG4gICAgICAgICAgbWV0aG9kOiAnUFVUJyxcbiAgICAgICAgICB1cmw6ICd0b2dnbGVEb25lJ1xuICAgICAgICB9XG4gICAgICB9LFxuICAgICAgaW5zdGFuY2U6IHsgfVxuICAgIH0pO1xuICB9XG5cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb250cm9sbGVyKCdVc2Vyc0RpYWxvZ0NvbnRyb2xsZXInLCBVc2Vyc0RpYWxvZ0NvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gVXNlcnNEaWFsb2dDb250cm9sbGVyKCRjb250cm9sbGVyLCBVc2Vyc1NlcnZpY2UsIFByRGlhbG9nLCAgLy8gTk9TT05BUlxuICAgIHVzZXJEaWFsb2dJbnB1dCwgb25Jbml0KSB7XG5cbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0ub25BY3RpdmF0ZSA9IG9uQWN0aXZhdGU7XG4gICAgdm0uYXBwbHlGaWx0ZXJzID0gYXBwbHlGaWx0ZXJzO1xuICAgIHZtLmNsb3NlID0gY2xvc2U7XG5cbiAgICBpZiAoYW5ndWxhci5pc0RlZmluZWQodXNlckRpYWxvZ0lucHV0KSkge1xuICAgICAgdm0udHJhbnNmZXJVc2VyID0gdXNlckRpYWxvZ0lucHV0LnRyYW5zZmVyVXNlckZuO1xuICAgIH1cblxuICAgIC8vIGluc3RhbnRpYXRlIGJhc2UgY29udHJvbGxlclxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHtcbiAgICAgIHZtOiB2bSxcbiAgICAgIG1vZGVsU2VydmljZTogVXNlcnNTZXJ2aWNlLFxuICAgICAgc2VhcmNoT25Jbml0OiBvbkluaXQsXG4gICAgICBvcHRpb25zOiB7XG4gICAgICAgIHBlclBhZ2U6IDVcbiAgICAgIH1cbiAgICB9KTtcblxuICAgIGZ1bmN0aW9uIG9uQWN0aXZhdGUoKSB7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMgPSB7fTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBhcHBseUZpbHRlcnMoKSB7XG4gICAgICByZXR1cm4gYW5ndWxhci5leHRlbmQodm0uZGVmYXVsdFF1ZXJ5RmlsdGVycywgdm0ucXVlcnlGaWx0ZXJzKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBjbG9zZSgpIHtcbiAgICAgIFByRGlhbG9nLmNsb3NlKCk7XG4gICAgfVxuXG4gIH1cblxufSkoKTtcbiJdLCJzb3VyY2VSb290IjoiL3NvdXJjZS8ifQ==
