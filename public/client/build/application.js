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

  UsersController.$inject = ["$controller", "lodash", "UsersService", "RolesService", "PrToast", "Auth", "$translate"];
  angular.module('app').controller('UsersController', UsersController);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function UsersController($controller, lodash, UsersService, RolesService, // NOSONAR
  PrToast, Auth, $translate) {

    var vm = this;

    vm.onActivate = onActivate;
    vm.applyFilters = applyFilters;
    vm.afterEdit = afterEdit;
    vm.afterClean = afterClean;
    vm.beforeSave = beforeSave;
    vm.afterSave = afterSave;
    vm.beforeRemove = beforeRemove;

    // instantiate base controller
    $controller('CRUDController', { vm: vm, modelService: UsersService, options: {} });

    function onActivate() {
      vm.queryFilters = {};

      vm.roles = RolesService.query().then(function (response) {
        vm.roles = response;
      });
    }

    function applyFilters(defaultQueryFilters) {
      return angular.extend(defaultQueryFilters, vm.queryFilters);
    }

    function afterClean() {
      vm.roles.forEach(function (role) {
        role.selected = false;
      });
    }

    function afterEdit() {
      vm.roles.forEach(function (role) {
        vm.resource.roles.forEach(function (roleUser) {
          if (role.id === roleUser.id) {
            role.selected = true;
          }
        });
      });
    }

    function beforeSave() {
      //filtra o array de roles para extrair somente os ids
      vm.resource.roles = lodash.map(lodash.filter(angular.copy(vm.roles), { selected: true }), function (role) {
        return { id: role.id };
      });
    }

    function afterSave(resource) {
      if (vm.resource.id === Auth.currentUser.id) {
        Auth.updateCurrentUser(resource);
      }
    }

    function beforeRemove(resource) {
      if (resource.id === Auth.currentUser.id) {
        PrToast.error($translate.instant('messages.user.removeYourSelfError'));
        return false;
      }
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImFwcGxpY2F0aW9uLmpzIiwiYXBwLmpzIiwiYXBwLmNvbmZpZy5qcyIsImFwcC5jb250cm9sbGVyLmpzIiwiYXBwLmV4dGVybmFsLmpzIiwiYXBwLmdsb2JhbC5qcyIsImFwcC5yb3V0ZXMuanMiLCJhcHAucnVuLmpzIiwiYXVkaXQvYXVkaXQuY29udHJvbGxlci5qcyIsImF1ZGl0L2F1ZGl0LnJvdXRlLmpzIiwiYXVkaXQvYXVkaXQuc2VydmljZS5qcyIsImF1dGgvYXV0aC5yb3V0ZS5qcyIsImF1dGgvYXV0aC5zZXJ2aWNlLmpzIiwiYXV0aC9sb2dpbi5jb250cm9sbGVyLmpzIiwiYXV0aC9wYXNzd29yZC5jb250cm9sbGVyLmpzIiwiY29yZS9iYXNlLnNlcnZpY2UuanMiLCJjb3JlL2NydWQuY29udHJvbGxlci5qcyIsImRhc2hib2FyZC9kYXNoYm9hcmQuY29udHJvbGxlci5qcyIsImRhc2hib2FyZC9kYXNoYm9hcmQucm91dGUuanMiLCJkaW5hbWljLXF1ZXJ5cy9kaW5hbWljLXF1ZXJ5LnJvdXRlLmpzIiwiZGluYW1pYy1xdWVyeXMvZGluYW1pYy1xdWVyeS5zZXJ2aWNlLmpzIiwiZGluYW1pYy1xdWVyeXMvZGluYW1pYy1xdWVyeXMuY29udHJvbGxlci5qcyIsImkxOG4vbGFuZ3VhZ2UtbG9hZGVyLnNlcnZpY2UuanMiLCJpMThuL3QtYXR0ci5maWx0ZXIuanMiLCJpMThuL3QtYnJlYWRjcnVtYi5maWx0ZXIuanMiLCJpMThuL3QtbW9kZWwuZmlsdGVyLmpzIiwiaW50ZXJjZXB0b3JzL2F1dGhlbnRpY2F0aW9uLmxpc3RlbmVyLmpzIiwiaW50ZXJjZXB0b3JzL2F1dGhvcml6YXRpb24ubGlzdGVuZXIuanMiLCJpbnRlcmNlcHRvcnMvc3Bpbm5lci5pbnRlcmNlcHRvci5qcyIsImludGVyY2VwdG9ycy90b2tlbi5pbnRlcmNlcHRvci5qcyIsImludGVyY2VwdG9ycy92YWxpZGF0aW9uLmludGVyY2VwdG9yLmpzIiwibGF5b3V0L21lbnUuY29udHJvbGxlci5qcyIsIm1haWwvbWFpbHMuY29udHJvbGxlci5qcyIsIm1haWwvbWFpbHMucm91dGUuanMiLCJtYWlsL21haWxzLnNlcnZpY2UuanMiLCJyb2xlcy9yb2xlcy1zdHIuZmlsdGVyLmpzIiwicm9sZXMvcm9sZXMuc2VydmljZS5qcyIsInN1cHBvcnQvc3VwcG9ydC5zZXJ2aWNlLmpzIiwidXNlcnMvcHJvZmlsZS5jb250cm9sbGVyLmpzIiwidXNlcnMvdXNlcnMuY29udHJvbGxlci5qcyIsInVzZXJzL3VzZXJzLnJvdXRlLmpzIiwidXNlcnMvdXNlcnMuc2VydmljZS5qcyIsIndpZGdldHMvYm94LmNvbXBvbmVudC5qcyIsIndpZGdldHMvY29udGVudC1ib2R5LmNvbXBvbmVudC5qcyIsIndpZGdldHMvY29udGVudC1oZWFkZXIuY29tcG9uZW50LmpzIiwiYXVkaXQvZmlsdGVycy9hdWRpdC1kZXRhaWwtdGl0bGUuZmlsdGVyLmpzIiwiYXVkaXQvZmlsdGVycy9hdWRpdC1tb2RlbC5maWx0ZXIuanMiLCJhdWRpdC9maWx0ZXJzL2F1ZGl0LXR5cGUuZmlsdGVyLmpzIiwiYXVkaXQvZmlsdGVycy9hdWRpdC12YWx1ZS5maWx0ZXIuanMiLCJpMThuL3B0LUJSL2F0dHJpYnV0ZXMuanMiLCJpMThuL3B0LUJSL2RpYWxvZy5qcyIsImkxOG4vcHQtQlIvZ2xvYmFsLmpzIiwiaTE4bi9wdC1CUi9tZXNzYWdlcy5qcyIsImkxOG4vcHQtQlIvbW9kZWxzLmpzIiwiaTE4bi9wdC1CUi92aWV3cy5qcyIsInNhbXBsZXMvcHJvamVjdHMvcHJvamVjdHMuY29udHJvbGxlci5qcyIsInNhbXBsZXMvcHJvamVjdHMvcHJvamVjdHMucm91dGUuanMiLCJzYW1wbGVzL3Byb2plY3RzL3Byb2plY3RzLnNlcnZpY2UuanMiLCJzYW1wbGVzL3Rhc2tzL3Rhc2tzLWRpYWxvZy5jb250cm9sbGVyLmpzIiwic2FtcGxlcy90YXNrcy90YXNrcy5zZXJ2aWNlLmpzIiwidXNlcnMvZGlhbG9nL3VzZXJzLWRpYWxvZy5jb250cm9sbGVyLmpzIl0sIm5hbWVzIjpbImFuZ3VsYXIiLCJtb2R1bGUiLCJjb25maWciLCJHbG9iYWwiLCIkbWRUaGVtaW5nUHJvdmlkZXIiLCIkbW9kZWxGYWN0b3J5UHJvdmlkZXIiLCIkdHJhbnNsYXRlUHJvdmlkZXIiLCJtb21lbnQiLCIkbWRBcmlhUHJvdmlkZXIiLCJ1c2VMb2FkZXIiLCJ1c2VTYW5pdGl6ZVZhbHVlU3RyYXRlZ3kiLCJ1c2VQb3N0Q29tcGlsaW5nIiwibG9jYWxlIiwiZGVmYXVsdE9wdGlvbnMiLCJwcmVmaXgiLCJhcGlQYXRoIiwidGhlbWUiLCJwcmltYXJ5UGFsZXR0ZSIsImRlZmF1bHQiLCJhY2NlbnRQYWxldHRlIiwid2FyblBhbGV0dGUiLCJlbmFibGVCcm93c2VyQ29sb3IiLCJkaXNhYmxlV2FybmluZ3MiLCJjb250cm9sbGVyIiwiQXBwQ29udHJvbGxlciIsIiRzdGF0ZSIsIkF1dGgiLCJ2bSIsImFub0F0dWFsIiwibG9nb3V0IiwiZ2V0SW1hZ2VQZXJmaWwiLCJhY3RpdmF0ZSIsImRhdGUiLCJEYXRlIiwiZ2V0RnVsbFllYXIiLCJ0aGVuIiwiZ28iLCJsb2dpblN0YXRlIiwiY3VycmVudFVzZXIiLCJpbWFnZSIsImltYWdlUGF0aCIsImNvbnN0YW50IiwiXyIsImFwcE5hbWUiLCJob21lU3RhdGUiLCJsb2dpblVybCIsInJlc2V0UGFzc3dvcmRTdGF0ZSIsIm5vdEF1dGhvcml6ZWRTdGF0ZSIsInRva2VuS2V5IiwiY2xpZW50UGF0aCIsInJvdXRlcyIsIiRzdGF0ZVByb3ZpZGVyIiwiJHVybFJvdXRlclByb3ZpZGVyIiwic3RhdGUiLCJ1cmwiLCJ0ZW1wbGF0ZVVybCIsImFic3RyYWN0IiwicmVzb2x2ZSIsInRyYW5zbGF0ZVJlYWR5IiwiJHRyYW5zbGF0ZSIsIiRxIiwiZGVmZXJyZWQiLCJkZWZlciIsInVzZSIsInByb21pc2UiLCJkYXRhIiwibmVlZEF1dGhlbnRpY2F0aW9uIiwid2hlbiIsIm90aGVyd2lzZSIsInJ1biIsIiRyb290U2NvcGUiLCIkc3RhdGVQYXJhbXMiLCJhdXRoIiwiZ2xvYmFsIiwicmV0cmlldmVVc2VyRnJvbUxvY2FsU3RvcmFnZSIsIkF1ZGl0Q29udHJvbGxlciIsIiRjb250cm9sbGVyIiwiQXVkaXRTZXJ2aWNlIiwiUHJEaWFsb2ciLCJvbkFjdGl2YXRlIiwiYXBwbHlGaWx0ZXJzIiwidmlld0RldGFpbCIsIm1vZGVsU2VydmljZSIsIm9wdGlvbnMiLCJtb2RlbHMiLCJxdWVyeUZpbHRlcnMiLCJnZXRBdWRpdGVkTW9kZWxzIiwiaWQiLCJsYWJlbCIsImluc3RhbnQiLCJzb3J0IiwiaW5kZXgiLCJsZW5ndGgiLCJtb2RlbCIsInB1c2giLCJ0b0xvd2VyQ2FzZSIsInR5cGVzIiwibGlzdFR5cGVzIiwidHlwZSIsImRlZmF1bHRRdWVyeUZpbHRlcnMiLCJleHRlbmQiLCJhdWRpdERldGFpbCIsImxvY2FscyIsImNsb3NlIiwiaXNBcnJheSIsIm9sZCIsIm5ldyIsImNvbnRyb2xsZXJBcyIsImhhc0JhY2tkcm9wIiwiY3VzdG9tIiwibmVlZFByb2ZpbGUiLCJmYWN0b3J5Iiwic2VydmljZUZhY3RvcnkiLCJhY3Rpb25zIiwibWV0aG9kIiwiaW5zdGFuY2UiLCJhdWRpdFBhdGgiLCIkaHR0cCIsIlVzZXJzU2VydmljZSIsImxvZ2luIiwidXBkYXRlQ3VycmVudFVzZXIiLCJhdXRoZW50aWNhdGVkIiwic2VuZEVtYWlsUmVzZXRQYXNzd29yZCIsInJlbW90ZVZhbGlkYXRlVG9rZW4iLCJnZXRUb2tlbiIsInNldFRva2VuIiwiY2xlYXJUb2tlbiIsImxvY2FsU3RvcmFnZSIsInJlbW92ZUl0ZW0iLCJ0b2tlbiIsInNldEl0ZW0iLCJnZXRJdGVtIiwiZ2V0IiwicmVqZWN0IiwidXNlciIsIm1lcmdlIiwiZnJvbUpzb24iLCJqc29uVXNlciIsInRvSnNvbiIsImNyZWRlbnRpYWxzIiwicG9zdCIsInJlc3BvbnNlIiwiZXJyb3IiLCJyZXNldERhdGEiLCJMb2dpbkNvbnRyb2xsZXIiLCJvcGVuRGlhbG9nUmVzZXRQYXNzIiwiZW1haWwiLCJwYXNzd29yZCIsIlBhc3N3b3JkQ29udHJvbGxlciIsIiR0aW1lb3V0IiwiUHJUb2FzdCIsInNlbmRSZXNldCIsImNsb3NlRGlhbG9nIiwiY2xlYW5Gb3JtIiwicmVzZXQiLCJzdWNjZXNzIiwic3RhdHVzIiwibXNnIiwiaSIsInRvVXBwZXJDYXNlIiwiZmllbGQiLCJtZXNzYWdlIiwiJG1vZGVsRmFjdG9yeSIsInBhZ2luYXRlIiwid3JhcCIsImFmdGVyUmVxdWVzdCIsIkxpc3QiLCJDUlVEQ29udHJvbGxlciIsIlByUGFnaW5hdGlvbiIsInNlYXJjaCIsInBhZ2luYXRlU2VhcmNoIiwibm9ybWFsU2VhcmNoIiwiZWRpdCIsInNhdmUiLCJyZW1vdmUiLCJnb1RvIiwicmVkaXJlY3RBZnRlclNhdmUiLCJzZWFyY2hPbkluaXQiLCJwZXJQYWdlIiwic2tpcFBhZ2luYXRpb24iLCJ2aWV3Rm9ybSIsInJlc291cmNlIiwiaXNGdW5jdGlvbiIsInBhZ2luYXRvciIsImdldEluc3RhbmNlIiwicGFnZSIsImN1cnJlbnRQYWdlIiwiaXNEZWZpbmVkIiwiYmVmb3JlU2VhcmNoIiwiY2FsY051bWJlck9mUGFnZXMiLCJ0b3RhbCIsInJlc291cmNlcyIsIml0ZW1zIiwiYWZ0ZXJTZWFyY2giLCJxdWVyeSIsImZvcm0iLCJiZWZvcmVDbGVhbiIsIiRzZXRQcmlzdGluZSIsIiRzZXRVbnRvdWNoZWQiLCJhZnRlckNsZWFuIiwiY29weSIsImFmdGVyRWRpdCIsImJlZm9yZVNhdmUiLCIkc2F2ZSIsImFmdGVyU2F2ZSIsInJlc3BvbnNlRGF0YSIsIm9uU2F2ZUVycm9yIiwidGl0bGUiLCJkZXNjcmlwdGlvbiIsImNvbmZpcm0iLCJiZWZvcmVSZW1vdmUiLCIkZGVzdHJveSIsImFmdGVyUmVtb3ZlIiwiaW5mbyIsInZpZXdOYW1lIiwiRGFzaGJvYXJkQ29udHJvbGxlciIsIkRpbmFtaWNRdWVyeVNlcnZpY2UiLCJnZXRNb2RlbHMiLCJEaW5hbWljUXVlcnlzQ29udHJvbGxlciIsImxvZGFzaCIsImxvYWRBdHRyaWJ1dGVzIiwibG9hZE9wZXJhdG9ycyIsImFkZEZpbHRlciIsInJ1bkZpbHRlciIsImVkaXRGaWx0ZXIiLCJsb2FkTW9kZWxzIiwicmVtb3ZlRmlsdGVyIiwiY2xlYXIiLCJyZXN0YXJ0Iiwid2hlcmUiLCJhZGRlZEZpbHRlcnMiLCJuYW1lIiwiZmlsdGVyIiwiYXR0cmlidXRlIiwib3BlcmF0b3IiLCJ2YWx1ZSIsImZpbHRlcnMiLCJhdHRyaWJ1dGVzIiwib3BlcmF0b3JzIiwiaW5kZXhPZiIsImlzVW5kZWZpbmVkIiwia2V5cyIsIk9iamVjdCIsImtleSIsInN0YXJ0c1dpdGgiLCIkaW5kZXgiLCJzcGxpY2UiLCJMYW5ndWFnZUxvYWRlciIsIlN1cHBvcnRTZXJ2aWNlIiwiJGxvZyIsIiRpbmplY3RvciIsInNlcnZpY2UiLCJ0cmFuc2xhdGUiLCJ2aWV3cyIsImRpYWxvZyIsIm1lc3NhZ2VzIiwibGFuZ3MiLCJ0QXR0ciIsIiRmaWx0ZXIiLCJ0QnJlYWRjcnVtYiIsInNwbGl0IiwidE1vZGVsIiwiYXV0aGVudGljYXRpb25MaXN0ZW5lciIsIiRvbiIsImV2ZW50IiwidG9TdGF0ZSIsImNhdGNoIiwid2FybiIsInByZXZlbnREZWZhdWx0IiwiYXV0aG9yaXphdGlvbkxpc3RlbmVyIiwiaGFzUHJvZmlsZSIsImFsbFByb2ZpbGVzIiwic3Bpbm5lckludGVyY2VwdG9yIiwiJGh0dHBQcm92aWRlciIsIiRwcm92aWRlIiwic2hvd0hpZGVTcGlubmVyIiwicmVxdWVzdCIsInNob3ciLCJoaWRlIiwicmVzcG9uc2VFcnJvciIsInJlamVjdGlvbiIsImludGVyY2VwdG9ycyIsInRva2VuSW50ZXJjZXB0b3IiLCJyZWRpcmVjdFdoZW5TZXJ2ZXJMb2dnZWRPdXQiLCJoZWFkZXJzIiwicmVqZWN0aW9uUmVhc29ucyIsInRva2VuRXJyb3IiLCJmb3JFYWNoIiwiaXMiLCJ2YWxpZGF0aW9uSW50ZXJjZXB0b3IiLCJzaG93RXJyb3JWYWxpZGF0aW9uIiwic2tpcFZhbGlkYXRpb24iLCJlcnJvclZhbGlkYXRpb24iLCJNZW51Q29udHJvbGxlciIsIiRtZFNpZGVuYXYiLCIkbWRDb2xvcnMiLCJvcGVuIiwib3Blbk1lbnVPclJlZGlyZWN0VG9TdGF0ZSIsIm1lbnVQcmVmaXgiLCJpdGVuc01lbnUiLCJpY29uIiwic3ViSXRlbnMiLCJwcm9maWxlcyIsInNpZGVuYXZTdHlsZSIsInRvcCIsImdldENvbG9yIiwiY29udGVudCIsInRleHRDb2xvciIsImNvbG9yIiwibGluZUJvdHRvbSIsInRvZ2dsZSIsIiRtZE1lbnUiLCJldiIsIml0ZW0iLCJjb2xvclBhbGV0dGVzIiwiZ2V0VGhlbWVDb2xvciIsIk1haWxzQ29udHJvbGxlciIsIk1haWxzU2VydmljZSIsImZpbHRlclNlbGVjdGVkIiwic2tpbiIsImxhbmd1YWdlIiwiYWxsb3dlZENvbnRlbnQiLCJlbnRpdGllcyIsImhlaWdodCIsImV4dHJhUGx1Z2lucyIsImxvYWRVc2VycyIsIm9wZW5Vc2VyRGlhbG9nIiwiYWRkVXNlck1haWwiLCJzZW5kIiwiY3JpdGVyaWEiLCJuYW1lT3JFbWFpbCIsIm5vdFVzZXJzIiwibWFwIiwibWFpbCIsInVzZXJzIiwicHJvcGVydHkiLCJ0b1N0cmluZyIsImxpbWl0IiwiZmluZCIsIm9uSW5pdCIsInVzZXJEaWFsb2dJbnB1dCIsInRyYW5zZmVyVXNlckZuIiwicm9sZXNTdHIiLCJyb2xlcyIsImpvaW4iLCJSb2xlc1NlcnZpY2UiLCJjYWNoZSIsIlByb2ZpbGVDb250cm9sbGVyIiwidXBkYXRlIiwidXBkYXRlUHJvZmlsZSIsIlVzZXJzQ29udHJvbGxlciIsInJvbGUiLCJzZWxlY3RlZCIsInJvbGVVc2VyIiwiZGVmYXVsdHMiLCJvdmVycmlkZSIsImFsbCIsInVzZXJSb2xlcyIsImludGVyc2VjdGlvbiIsImlzQWRtaW4iLCJjb21wb25lbnQiLCJyZXBsYWNlIiwidHJhbnNjbHVkZSIsInRvb2xiYXJCdXR0b25zIiwiZm9vdGVyQnV0dG9ucyIsImJpbmRpbmdzIiwiYm94VGl0bGUiLCJ0b29sYmFyQ2xhc3MiLCJ0b29sYmFyQmdDb2xvciIsIiR0cmFuc2NsdWRlIiwiY3RybCIsIiRvbkluaXQiLCJsYXlvdXRBbGlnbiIsImF1ZGl0RGV0YWlsVGl0bGUiLCJhdWRpdE1vZGVsIiwibW9kZWxJZCIsImF1ZGl0VHlwZSIsInR5cGVJZCIsImF1ZGl0VmFsdWUiLCJpc0RhdGUiLCJlbmRzV2l0aCIsIk51bWJlciIsImluaXRpYWxEYXRlIiwiZmluYWxEYXRlIiwidGFzayIsImRvbmUiLCJwcmlvcml0eSIsInNjaGVkdWxlZF90byIsInByb2plY3QiLCJjb3N0IiwiY29uZmlybVRpdGxlIiwiY29uZmlybURlc2NyaXB0aW9uIiwicmVtb3ZlRGVzY3JpcHRpb24iLCJhdWRpdCIsImNyZWF0ZWQiLCJ1cGRhdGVkQmVmb3JlIiwidXBkYXRlZEFmdGVyIiwiZGVsZXRlZCIsInJlc2V0UGFzc3dvcmQiLCJsb2FkaW5nIiwicHJvY2Vzc2luZyIsInllcyIsIm5vIiwiaW50ZXJuYWxFcnJvciIsIm5vdEZvdW5kIiwibm90QXV0aG9yaXplZCIsInNlYXJjaEVycm9yIiwic2F2ZVN1Y2Nlc3MiLCJvcGVyYXRpb25TdWNjZXNzIiwib3BlcmF0aW9uRXJyb3IiLCJzYXZlRXJyb3IiLCJyZW1vdmVTdWNjZXNzIiwicmVtb3ZlRXJyb3IiLCJyZXNvdXJjZU5vdEZvdW5kRXJyb3IiLCJub3ROdWxsRXJyb3IiLCJkdXBsaWNhdGVkUmVzb3VyY2VFcnJvciIsInZhbGlkYXRlIiwiZmllbGRSZXF1aXJlZCIsImxheW91dCIsImVycm9yNDA0IiwibG9nb3V0SW5hY3RpdmUiLCJpbnZhbGlkQ3JlZGVudGlhbHMiLCJ1bmtub3duRXJyb3IiLCJ1c2VyTm90Rm91bmQiLCJkYXNoYm9hcmQiLCJ3ZWxjb21lIiwibWFpbEVycm9ycyIsInNlbmRNYWlsU3VjY2VzcyIsInNlbmRNYWlsRXJyb3IiLCJwYXNzd29yZFNlbmRpbmdTdWNjZXNzIiwicmVtb3ZlWW91clNlbGZFcnJvciIsInVzZXJFeGlzdHMiLCJwcm9maWxlIiwidXBkYXRlRXJyb3IiLCJxdWVyeURpbmFtaWMiLCJub0ZpbHRlciIsImJyZWFkY3J1bWJzIiwidGl0bGVzIiwibWFpbFNlbmQiLCJ0YXNrTGlzdCIsInVzZXJMaXN0IiwiYXVkaXRMaXN0IiwicmVnaXN0ZXIiLCJjbGVhckFsbCIsImxpc3QiLCJjYW5jZWwiLCJnZXRPdXQiLCJhZGQiLCJpbiIsImxvYWRJbWFnZSIsInNpZ251cCIsImZpZWxkcyIsImFjdGlvbiIsImRhdGVTdGFydCIsImRhdGVFbmQiLCJhbGxSZXNvdXJjZXMiLCJ1cGRhdGVkIiwiY29uZmlybVBhc3N3b3JkIiwidG8iLCJzdWJqZWN0IiwicmVzdWx0cyIsImVxdWFscyIsImRpZmVyZW50IiwiY29udGVpbnMiLCJzdGFydFdpdGgiLCJmaW5pc2hXaXRoIiwiYmlnZ2VyVGhhbiIsImVxdWFsc09yQmlnZ2VyVGhhbiIsImxlc3NUaGFuIiwiZXF1YWxzT3JMZXNzVGhhbiIsInRvdGFsVGFzayIsInBlcmZpbHMiLCJtZW51IiwiYWRtaW4iLCJleGFtcGxlcyIsImRpbmFtaWNRdWVyeSIsInRvb2x0aXBzIiwicGVyZmlsIiwidHJhbnNmZXIiLCJsaXN0VGFzayIsIlByb2plY3RzQ29udHJvbGxlciIsIlByb2plY3RzU2VydmljZSIsInZpZXdUYXNrcyIsInByb2plY3RJZCIsImZpbmFsbHkiLCJUYXNrc0RpYWxvZ0NvbnRyb2xsZXIiLCJUYXNrc1NlcnZpY2UiLCJ0b2dnbGVEb25lIiwicHJvamVjdF9pZCIsInRvRGF0ZSIsIlVzZXJzRGlhbG9nQ29udHJvbGxlciIsInRyYW5zZmVyVXNlciJdLCJtYXBwaW5ncyI6IkFBQUE7OztBQ0NBLENBQUMsWUFBVztFQUNWOztFQUVBQSxRQUFRQyxPQUFPLE9BQU8sQ0FDcEIsYUFDQSxVQUNBLGFBQ0EsWUFDQSxrQkFDQSxhQUNBLGNBQ0EsZ0JBQ0EsaUJBQ0Esd0JBQ0EsMEJBQ0E7O0FEUko7O0FFUkMsQ0FBQSxZQUFZO0VBQ1g7OztFQUVBRCxRQUNHQyxPQUFPLE9BQ1BDLE9BQU9BOzs7O0VBSVYsU0FBU0EsT0FBT0MsUUFBUUMsb0JBQW9CQztFQUMxQ0Msb0JBQW9CQyxR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YXBwbGljYXRpb24uanMiLCJzb3VyY2VzQ29udGVudCI6WyIndXNlIHN0cmljdCc7XG5cbi8qZXNsaW50IGFuZ3VsYXIvZmlsZS1uYW1lOiAwKi9cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJywgWyduZ0FuaW1hdGUnLCAnbmdBcmlhJywgJ3VpLnJvdXRlcicsICduZ1Byb2RlYicsICd1aS51dGlscy5tYXNrcycsICd0ZXh0LW1hc2snLCAnbmdNYXRlcmlhbCcsICdtb2RlbEZhY3RvcnknLCAnbWQuZGF0YS50YWJsZScsICduZ01hdGVyaWFsRGF0ZVBpY2tlcicsICdwYXNjYWxwcmVjaHQudHJhbnNsYXRlJywgJ2FuZ3VsYXJGaWxlVXBsb2FkJ10pO1xufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25maWcoY29uZmlnKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIGNvbmZpZyhHbG9iYWwsICRtZFRoZW1pbmdQcm92aWRlciwgJG1vZGVsRmFjdG9yeVByb3ZpZGVyLCAvLyBOT1NPTkFSXG4gICR0cmFuc2xhdGVQcm92aWRlciwgbW9tZW50LCAkbWRBcmlhUHJvdmlkZXIpIHtcblxuICAgICR0cmFuc2xhdGVQcm92aWRlci51c2VMb2FkZXIoJ2xhbmd1YWdlTG9hZGVyJykudXNlU2FuaXRpemVWYWx1ZVN0cmF0ZWd5KCdlc2NhcGUnKTtcblxuICAgICR0cmFuc2xhdGVQcm92aWRlci51c2VQb3N0Q29tcGlsaW5nKHRydWUpO1xuXG4gICAgbW9tZW50LmxvY2FsZSgncHQtQlInKTtcblxuICAgIC8vb3Mgc2VydmnDp29zIHJlZmVyZW50ZSBhb3MgbW9kZWxzIHZhaSB1dGlsaXphciBjb21vIGJhc2UgbmFzIHVybHNcbiAgICAkbW9kZWxGYWN0b3J5UHJvdmlkZXIuZGVmYXVsdE9wdGlvbnMucHJlZml4ID0gR2xvYmFsLmFwaVBhdGg7XG5cbiAgICAvLyBDb25maWd1cmF0aW9uIHRoZW1lXG4gICAgJG1kVGhlbWluZ1Byb3ZpZGVyLnRoZW1lKCdkZWZhdWx0JykucHJpbWFyeVBhbGV0dGUoJ2Jyb3duJywge1xuICAgICAgZGVmYXVsdDogJzcwMCdcbiAgICB9KS5hY2NlbnRQYWxldHRlKCdhbWJlcicpLndhcm5QYWxldHRlKCdkZWVwLW9yYW5nZScpO1xuXG4gICAgLy8gRW5hYmxlIGJyb3dzZXIgY29sb3JcbiAgICAkbWRUaGVtaW5nUHJvdmlkZXIuZW5hYmxlQnJvd3NlckNvbG9yKCk7XG5cbiAgICAkbWRBcmlhUHJvdmlkZXIuZGlzYWJsZVdhcm5pbmdzKCk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb250cm9sbGVyKCdBcHBDb250cm9sbGVyJywgQXBwQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvKipcbiAgICogQ29udHJvbGFkb3IgcmVzcG9uc8OhdmVsIHBvciBmdW5jaW9uYWxpZGFkZXMgcXVlIHPDo28gYWNpb25hZGFzIGVtIHF1YWxxdWVyIHRlbGEgZG8gc2lzdGVtYVxuICAgKlxuICAgKi9cbiAgZnVuY3Rpb24gQXBwQ29udHJvbGxlcigkc3RhdGUsIEF1dGgsIEdsb2JhbCkge1xuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICAvL2FubyBhdHVhbCBwYXJhIHNlciBleGliaWRvIG5vIHJvZGFww6kgZG8gc2lzdGVtYVxuICAgIHZtLmFub0F0dWFsID0gbnVsbDtcblxuICAgIHZtLmxvZ291dCA9IGxvZ291dDtcbiAgICB2bS5nZXRJbWFnZVBlcmZpbCA9IGdldEltYWdlUGVyZmlsO1xuXG4gICAgYWN0aXZhdGUoKTtcblxuICAgIGZ1bmN0aW9uIGFjdGl2YXRlKCkge1xuICAgICAgdmFyIGRhdGUgPSBuZXcgRGF0ZSgpO1xuXG4gICAgICB2bS5hbm9BdHVhbCA9IGRhdGUuZ2V0RnVsbFllYXIoKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBsb2dvdXQoKSB7XG4gICAgICBBdXRoLmxvZ291dCgpLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICAkc3RhdGUuZ28oR2xvYmFsLmxvZ2luU3RhdGUpO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gZ2V0SW1hZ2VQZXJmaWwoKSB7XG4gICAgICByZXR1cm4gQXV0aC5jdXJyZW50VXNlciAmJiBBdXRoLmN1cnJlbnRVc2VyLmltYWdlID8gQXV0aC5jdXJyZW50VXNlci5pbWFnZSA6IEdsb2JhbC5pbWFnZVBhdGggKyAnL25vX2F2YXRhci5naWYnO1xuICAgIH1cbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuLyplc2xpbnQgYW5ndWxhci9maWxlLW5hbWU6IDAsIG5vLXVuZGVmOiAwKi9cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICAvKipcbiAgICogVHJhbnNmb3JtYSBiaWJsaW90ZWNhcyBleHRlcm5hcyBlbSBzZXJ2acOnb3MgZG8gYW5ndWxhciBwYXJhIHNlciBwb3Nzw612ZWwgdXRpbGl6YXJcbiAgICogYXRyYXbDqXMgZGEgaW5qZcOnw6NvIGRlIGRlcGVuZMOqbmNpYVxuICAgKi9cblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29uc3RhbnQoJ2xvZGFzaCcsIF8pLmNvbnN0YW50KCdtb21lbnQnLCBtb21lbnQpO1xufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25zdGFudCgnR2xvYmFsJywge1xuICAgIGFwcE5hbWU6ICdGcmVlbGFnaWxlJyxcbiAgICBob21lU3RhdGU6ICdhcHAuZGFzaGJvYXJkJyxcbiAgICBsb2dpblVybDogJ2FwcC9sb2dpbicsXG4gICAgbG9naW5TdGF0ZTogJ2FwcC5sb2dpbicsXG4gICAgcmVzZXRQYXNzd29yZFN0YXRlOiAnYXBwLnBhc3N3b3JkLXJlc2V0JyxcbiAgICBub3RBdXRob3JpemVkU3RhdGU6ICdhcHAubm90LWF1dGhvcml6ZWQnLFxuICAgIHRva2VuS2V5OiAnc2VydmVyX3Rva2VuJyxcbiAgICBjbGllbnRQYXRoOiAnY2xpZW50L2FwcCcsXG4gICAgYXBpUGF0aDogJ2FwaS92MScsXG4gICAgaW1hZ2VQYXRoOiAnY2xpZW50L2ltYWdlcydcbiAgfSk7XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCAkdXJsUm91dGVyUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdhcHAnLCB7XG4gICAgICB1cmw6ICcvYXBwJyxcbiAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvbGF5b3V0L2FwcC5odG1sJyxcbiAgICAgIGFic3RyYWN0OiB0cnVlLFxuICAgICAgcmVzb2x2ZTogeyAvL2Vuc3VyZSBsYW5ncyBpcyByZWFkeSBiZWZvcmUgcmVuZGVyIHZpZXdcbiAgICAgICAgdHJhbnNsYXRlUmVhZHk6IFsnJHRyYW5zbGF0ZScsICckcScsIGZ1bmN0aW9uICgkdHJhbnNsYXRlLCAkcSkge1xuICAgICAgICAgIHZhciBkZWZlcnJlZCA9ICRxLmRlZmVyKCk7XG5cbiAgICAgICAgICAkdHJhbnNsYXRlLnVzZSgncHQtQlInKS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIGRlZmVycmVkLnJlc29sdmUoKTtcbiAgICAgICAgICB9KTtcblxuICAgICAgICAgIHJldHVybiBkZWZlcnJlZC5wcm9taXNlO1xuICAgICAgICB9XVxuICAgICAgfVxuICAgIH0pLnN0YXRlKEdsb2JhbC5ub3RBdXRob3JpemVkU3RhdGUsIHtcbiAgICAgIHVybDogJy9hY2Vzc28tbmVnYWRvJyxcbiAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvbGF5b3V0L25vdC1hdXRob3JpemVkLmh0bWwnLFxuICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IGZhbHNlIH1cbiAgICB9KTtcblxuICAgICR1cmxSb3V0ZXJQcm92aWRlci53aGVuKCcvYXBwJywgR2xvYmFsLmxvZ2luVXJsKTtcbiAgICAkdXJsUm91dGVyUHJvdmlkZXIub3RoZXJ3aXNlKEdsb2JhbC5sb2dpblVybCk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykucnVuKHJ1bik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBydW4oJHJvb3RTY29wZSwgJHN0YXRlLCAkc3RhdGVQYXJhbXMsIEF1dGgsIEdsb2JhbCkge1xuICAgIC8vIE5PU09OQVJcbiAgICAvL3NldGFkbyBubyByb290U2NvcGUgcGFyYSBwb2RlciBzZXIgYWNlc3NhZG8gbmFzIHZpZXdzIHNlbSBwcmVmaXhvIGRlIGNvbnRyb2xsZXJcbiAgICAkcm9vdFNjb3BlLiRzdGF0ZSA9ICRzdGF0ZTtcbiAgICAkcm9vdFNjb3BlLiRzdGF0ZVBhcmFtcyA9ICRzdGF0ZVBhcmFtcztcbiAgICAkcm9vdFNjb3BlLmF1dGggPSBBdXRoO1xuICAgICRyb290U2NvcGUuZ2xvYmFsID0gR2xvYmFsO1xuXG4gICAgLy9ubyBpbmljaW8gY2FycmVnYSBvIHVzdcOhcmlvIGRvIGxvY2Fsc3RvcmFnZSBjYXNvIG8gdXN1w6FyaW8gZXN0YWphIGFicmluZG8gbyBuYXZlZ2Fkb3JcbiAgICAvL3BhcmEgdm9sdGFyIGF1dGVudGljYWRvXG4gICAgQXV0aC5yZXRyaWV2ZVVzZXJGcm9tTG9jYWxTdG9yYWdlKCk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb250cm9sbGVyKCdBdWRpdENvbnRyb2xsZXInLCBBdWRpdENvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gQXVkaXRDb250cm9sbGVyKCRjb250cm9sbGVyLCBBdWRpdFNlcnZpY2UsIFByRGlhbG9nLCBHbG9iYWwsICR0cmFuc2xhdGUpIHtcbiAgICAvLyBOT1NPTkFSXG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIHZtLm9uQWN0aXZhdGUgPSBvbkFjdGl2YXRlO1xuICAgIHZtLmFwcGx5RmlsdGVycyA9IGFwcGx5RmlsdGVycztcbiAgICB2bS52aWV3RGV0YWlsID0gdmlld0RldGFpbDtcblxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHsgdm06IHZtLCBtb2RlbFNlcnZpY2U6IEF1ZGl0U2VydmljZSwgb3B0aW9uczoge30gfSk7XG5cbiAgICBmdW5jdGlvbiBvbkFjdGl2YXRlKCkge1xuICAgICAgdm0ubW9kZWxzID0gW107XG4gICAgICB2bS5xdWVyeUZpbHRlcnMgPSB7fTtcblxuICAgICAgLy9QZWdhIHRvZG9zIG9zIG1vZGVscyBkbyBzZXJ2ZXIgZSBtb250YSB1bWEgbGlzdGEgcHJvIENvbWJvQm94XG4gICAgICBBdWRpdFNlcnZpY2UuZ2V0QXVkaXRlZE1vZGVscygpLnRoZW4oZnVuY3Rpb24gKGRhdGEpIHtcbiAgICAgICAgdmFyIG1vZGVscyA9IFt7IGlkOiAnJywgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudCgnZ2xvYmFsLmFsbCcpIH1dO1xuXG4gICAgICAgIGRhdGEubW9kZWxzLnNvcnQoKTtcblxuICAgICAgICBmb3IgKHZhciBpbmRleCA9IDA7IGluZGV4IDwgZGF0YS5tb2RlbHMubGVuZ3RoOyBpbmRleCsrKSB7XG4gICAgICAgICAgdmFyIG1vZGVsID0gZGF0YS5tb2RlbHNbaW5kZXhdO1xuXG4gICAgICAgICAgbW9kZWxzLnB1c2goe1xuICAgICAgICAgICAgaWQ6IG1vZGVsLFxuICAgICAgICAgICAgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudCgnbW9kZWxzLicgKyBtb2RlbC50b0xvd2VyQ2FzZSgpKVxuICAgICAgICAgIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgdm0ubW9kZWxzID0gbW9kZWxzO1xuICAgICAgICB2bS5xdWVyeUZpbHRlcnMubW9kZWwgPSB2bS5tb2RlbHNbMF0uaWQ7XG4gICAgICB9KTtcblxuICAgICAgdm0udHlwZXMgPSBBdWRpdFNlcnZpY2UubGlzdFR5cGVzKCk7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMudHlwZSA9IHZtLnR5cGVzWzBdLmlkO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGFwcGx5RmlsdGVycyhkZWZhdWx0UXVlcnlGaWx0ZXJzKSB7XG4gICAgICByZXR1cm4gYW5ndWxhci5leHRlbmQoZGVmYXVsdFF1ZXJ5RmlsdGVycywgdm0ucXVlcnlGaWx0ZXJzKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiB2aWV3RGV0YWlsKGF1ZGl0RGV0YWlsKSB7XG4gICAgICB2YXIgY29uZmlnID0ge1xuICAgICAgICBsb2NhbHM6IHsgYXVkaXREZXRhaWw6IGF1ZGl0RGV0YWlsIH0sXG4gICAgICAgIC8qKiBAbmdJbmplY3QgKi9cbiAgICAgICAgY29udHJvbGxlcjogZnVuY3Rpb24gY29udHJvbGxlcihhdWRpdERldGFpbCwgUHJEaWFsb2cpIHtcbiAgICAgICAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgICAgICAgdm0uY2xvc2UgPSBjbG9zZTtcblxuICAgICAgICAgIGFjdGl2YXRlKCk7XG5cbiAgICAgICAgICBmdW5jdGlvbiBhY3RpdmF0ZSgpIHtcbiAgICAgICAgICAgIGlmIChhbmd1bGFyLmlzQXJyYXkoYXVkaXREZXRhaWwub2xkKSAmJiBhdWRpdERldGFpbC5vbGQubGVuZ3RoID09PSAwKSBhdWRpdERldGFpbC5vbGQgPSBudWxsO1xuICAgICAgICAgICAgaWYgKGFuZ3VsYXIuaXNBcnJheShhdWRpdERldGFpbC5uZXcpICYmIGF1ZGl0RGV0YWlsLm5ldy5sZW5ndGggPT09IDApIGF1ZGl0RGV0YWlsLm5ldyA9IG51bGw7XG5cbiAgICAgICAgICAgIHZtLmF1ZGl0RGV0YWlsID0gYXVkaXREZXRhaWw7XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgZnVuY3Rpb24gY2xvc2UoKSB7XG4gICAgICAgICAgICBQckRpYWxvZy5jbG9zZSgpO1xuICAgICAgICAgIH1cbiAgICAgICAgfSxcbiAgICAgICAgY29udHJvbGxlckFzOiAnYXVkaXREZXRhaWxDdHJsJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9hdWRpdC9hdWRpdC1kZXRhaWwuaHRtbCcsXG4gICAgICAgIGhhc0JhY2tkcm9wOiB0cnVlXG4gICAgICB9O1xuXG4gICAgICBQckRpYWxvZy5jdXN0b20oY29uZmlnKTtcbiAgICB9XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqXG4gICAqIEFycXVpdm8gZGUgY29uZmlndXJhw6fDo28gY29tIGFzIHJvdGFzIGVzcGVjw61maWNhcyBkZSBhdWRpdG9yaWFcbiAgICpcbiAgICogQHBhcmFtIHthbnl9ICRzdGF0ZVByb3ZpZGVyXG4gICAqIEBwYXJhbSB7YW55fSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnYXBwLmF1ZGl0Jywge1xuICAgICAgdXJsOiAnL2F1ZGl0b3JpYScsXG4gICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL2F1ZGl0L2F1ZGl0Lmh0bWwnLFxuICAgICAgY29udHJvbGxlcjogJ0F1ZGl0Q29udHJvbGxlciBhcyBhdWRpdEN0cmwnLFxuICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IHRydWUsIG5lZWRQcm9maWxlOiBbJ2FkbWluJ10gfVxuICAgIH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZhY3RvcnkoJ0F1ZGl0U2VydmljZScsIEF1ZGl0U2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBBdWRpdFNlcnZpY2Uoc2VydmljZUZhY3RvcnksICR0cmFuc2xhdGUpIHtcbiAgICByZXR1cm4gc2VydmljZUZhY3RvcnkoJ2F1ZGl0Jywge1xuICAgICAgYWN0aW9uczoge1xuICAgICAgICBnZXRBdWRpdGVkTW9kZWxzOiB7XG4gICAgICAgICAgbWV0aG9kOiAnR0VUJyxcbiAgICAgICAgICB1cmw6ICdtb2RlbHMnXG4gICAgICAgIH1cbiAgICAgIH0sXG4gICAgICBpbnN0YW5jZToge30sXG4gICAgICBsaXN0VHlwZXM6IGZ1bmN0aW9uIGxpc3RUeXBlcygpIHtcbiAgICAgICAgdmFyIGF1ZGl0UGF0aCA9ICd2aWV3cy5maWVsZHMuYXVkaXQuJztcblxuICAgICAgICByZXR1cm4gW3sgaWQ6ICcnLCBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KGF1ZGl0UGF0aCArICdhbGxSZXNvdXJjZXMnKSB9LCB7IGlkOiAnY3JlYXRlZCcsIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoYXVkaXRQYXRoICsgJ3R5cGUuY3JlYXRlZCcpIH0sIHsgaWQ6ICd1cGRhdGVkJywgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudChhdWRpdFBhdGggKyAndHlwZS51cGRhdGVkJykgfSwgeyBpZDogJ2RlbGV0ZWQnLCBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KGF1ZGl0UGF0aCArICd0eXBlLmRlbGV0ZWQnKSB9XTtcbiAgICAgIH1cbiAgICB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25maWcocm91dGVzKTtcblxuICAvKipcbiAgICogQXJxdWl2byBkZSBjb25maWd1cmHDp8OjbyBjb20gYXMgcm90YXMgZXNwZWPDrWZpY2FzIGRvIHJlY3Vyc28gdXNlclxuICAgKlxuICAgKiBAcGFyYW0ge2FueX0gJHN0YXRlUHJvdmlkZXJcbiAgICogQHBhcmFtIHthbnl9IEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKEdsb2JhbC5yZXNldFBhc3N3b3JkU3RhdGUsIHtcbiAgICAgIHVybDogJy9wYXNzd29yZC9yZXNldC86dG9rZW4nLFxuICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9hdXRoL3Jlc2V0LXBhc3MtZm9ybS5odG1sJyxcbiAgICAgIGNvbnRyb2xsZXI6ICdQYXNzd29yZENvbnRyb2xsZXIgYXMgcGFzc0N0cmwnLFxuICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IGZhbHNlIH1cbiAgICB9KS5zdGF0ZShHbG9iYWwubG9naW5TdGF0ZSwge1xuICAgICAgdXJsOiAnL2xvZ2luJyxcbiAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvYXV0aC9sb2dpbi5odG1sJyxcbiAgICAgIGNvbnRyb2xsZXI6ICdMb2dpbkNvbnRyb2xsZXIgYXMgbG9naW5DdHJsJyxcbiAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiBmYWxzZSB9XG4gICAgfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmFjdG9yeSgnQXV0aCcsIEF1dGgpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gQXV0aCgkaHR0cCwgJHEsIEdsb2JhbCwgVXNlcnNTZXJ2aWNlKSB7XG4gICAgLy8gTk9TT05BUlxuICAgIHZhciBhdXRoID0ge1xuICAgICAgbG9naW46IGxvZ2luLFxuICAgICAgbG9nb3V0OiBsb2dvdXQsXG4gICAgICB1cGRhdGVDdXJyZW50VXNlcjogdXBkYXRlQ3VycmVudFVzZXIsXG4gICAgICByZXRyaWV2ZVVzZXJGcm9tTG9jYWxTdG9yYWdlOiByZXRyaWV2ZVVzZXJGcm9tTG9jYWxTdG9yYWdlLFxuICAgICAgYXV0aGVudGljYXRlZDogYXV0aGVudGljYXRlZCxcbiAgICAgIHNlbmRFbWFpbFJlc2V0UGFzc3dvcmQ6IHNlbmRFbWFpbFJlc2V0UGFzc3dvcmQsXG4gICAgICByZW1vdGVWYWxpZGF0ZVRva2VuOiByZW1vdGVWYWxpZGF0ZVRva2VuLFxuICAgICAgZ2V0VG9rZW46IGdldFRva2VuLFxuICAgICAgc2V0VG9rZW46IHNldFRva2VuLFxuICAgICAgY2xlYXJUb2tlbjogY2xlYXJUb2tlbixcbiAgICAgIGN1cnJlbnRVc2VyOiBudWxsXG4gICAgfTtcblxuICAgIGZ1bmN0aW9uIGNsZWFyVG9rZW4oKSB7XG4gICAgICBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbShHbG9iYWwudG9rZW5LZXkpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIHNldFRva2VuKHRva2VuKSB7XG4gICAgICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbShHbG9iYWwudG9rZW5LZXksIHRva2VuKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBnZXRUb2tlbigpIHtcbiAgICAgIHJldHVybiBsb2NhbFN0b3JhZ2UuZ2V0SXRlbShHbG9iYWwudG9rZW5LZXkpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIHJlbW90ZVZhbGlkYXRlVG9rZW4oKSB7XG4gICAgICB2YXIgZGVmZXJyZWQgPSAkcS5kZWZlcigpO1xuXG4gICAgICBpZiAoYXV0aC5hdXRoZW50aWNhdGVkKCkpIHtcbiAgICAgICAgJGh0dHAuZ2V0KEdsb2JhbC5hcGlQYXRoICsgJy9hdXRoZW50aWNhdGUvY2hlY2snKS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICBkZWZlcnJlZC5yZXNvbHZlKHRydWUpO1xuICAgICAgICB9LCBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgYXV0aC5sb2dvdXQoKTtcblxuICAgICAgICAgIGRlZmVycmVkLnJlamVjdChmYWxzZSk7XG4gICAgICAgIH0pO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgYXV0aC5sb2dvdXQoKTtcblxuICAgICAgICBkZWZlcnJlZC5yZWplY3QoZmFsc2UpO1xuICAgICAgfVxuXG4gICAgICByZXR1cm4gZGVmZXJyZWQucHJvbWlzZTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBWZXJpZmljYSBzZSBvIHVzdcOhcmlvIGVzdMOhIGF1dGVudGljYWRvXG4gICAgICpcbiAgICAgKiBAcmV0dXJucyB7Ym9vbGVhbn1cbiAgICAgKi9cbiAgICBmdW5jdGlvbiBhdXRoZW50aWNhdGVkKCkge1xuICAgICAgcmV0dXJuIGF1dGguZ2V0VG9rZW4oKSAhPT0gbnVsbDtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWN1cGVyYSBvIHVzdcOhcmlvIGRvIGxvY2FsU3RvcmFnZVxuICAgICAqL1xuICAgIGZ1bmN0aW9uIHJldHJpZXZlVXNlckZyb21Mb2NhbFN0b3JhZ2UoKSB7XG4gICAgICB2YXIgdXNlciA9IGxvY2FsU3RvcmFnZS5nZXRJdGVtKCd1c2VyJyk7XG5cbiAgICAgIGlmICh1c2VyKSB7XG4gICAgICAgIGF1dGguY3VycmVudFVzZXIgPSBhbmd1bGFyLm1lcmdlKG5ldyBVc2Vyc1NlcnZpY2UoKSwgYW5ndWxhci5mcm9tSnNvbih1c2VyKSk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogR3VhcmRhIG8gdXN1w6FyaW8gbm8gbG9jYWxTdG9yYWdlIHBhcmEgY2FzbyBvIHVzdcOhcmlvIGZlY2hlIGUgYWJyYSBvIG5hdmVnYWRvclxuICAgICAqIGRlbnRybyBkbyB0ZW1wbyBkZSBzZXNzw6NvIHNlamEgcG9zc8OtdmVsIHJlY3VwZXJhciBvIHRva2VuIGF1dGVudGljYWRvLlxuICAgICAqXG4gICAgICogTWFudMOpbSBhIHZhcmnDoXZlbCBhdXRoLmN1cnJlbnRVc2VyIHBhcmEgZmFjaWxpdGFyIG8gYWNlc3NvIGFvIHVzdcOhcmlvIGxvZ2FkbyBlbSB0b2RhIGEgYXBsaWNhw6fDo29cbiAgICAgKlxuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IHVzZXIgVXN1w6FyaW8gYSBzZXIgYXR1YWxpemFkby4gQ2FzbyBzZWphIHBhc3NhZG8gbnVsbCBsaW1wYVxuICAgICAqIHRvZGFzIGFzIGluZm9ybWHDp8O1ZXMgZG8gdXN1w6FyaW8gY29ycmVudGUuXG4gICAgICovXG4gICAgZnVuY3Rpb24gdXBkYXRlQ3VycmVudFVzZXIodXNlcikge1xuICAgICAgdmFyIGRlZmVycmVkID0gJHEuZGVmZXIoKTtcblxuICAgICAgaWYgKHVzZXIpIHtcbiAgICAgICAgdXNlciA9IGFuZ3VsYXIubWVyZ2UobmV3IFVzZXJzU2VydmljZSgpLCB1c2VyKTtcblxuICAgICAgICB2YXIganNvblVzZXIgPSBhbmd1bGFyLnRvSnNvbih1c2VyKTtcblxuICAgICAgICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbSgndXNlcicsIGpzb25Vc2VyKTtcbiAgICAgICAgYXV0aC5jdXJyZW50VXNlciA9IHVzZXI7XG5cbiAgICAgICAgZGVmZXJyZWQucmVzb2x2ZSh1c2VyKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKCd1c2VyJyk7XG4gICAgICAgIGF1dGguY3VycmVudFVzZXIgPSBudWxsO1xuICAgICAgICBhdXRoLmNsZWFyVG9rZW4oKTtcblxuICAgICAgICBkZWZlcnJlZC5yZWplY3QoKTtcbiAgICAgIH1cblxuICAgICAgcmV0dXJuIGRlZmVycmVkLnByb21pc2U7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhbGl6YSBvIGxvZ2luIGRvIHVzdcOhcmlvXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gY3JlZGVudGlhbHMgRW1haWwgZSBTZW5oYSBkbyB1c3XDoXJpb1xuICAgICAqIEByZXR1cm5zIHtwcm9taXNlfSBVbWEgcHJvbWlzZSBjb20gbyByZXN1bHRhZG8gZG8gY2hhbWFkYSBubyBiYWNrZW5kXG4gICAgICovXG4gICAgZnVuY3Rpb24gbG9naW4oY3JlZGVudGlhbHMpIHtcbiAgICAgIHZhciBkZWZlcnJlZCA9ICRxLmRlZmVyKCk7XG5cbiAgICAgICRodHRwLnBvc3QoR2xvYmFsLmFwaVBhdGggKyAnL2F1dGhlbnRpY2F0ZScsIGNyZWRlbnRpYWxzKS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICBhdXRoLnNldFRva2VuKHJlc3BvbnNlLmRhdGEudG9rZW4pO1xuXG4gICAgICAgIHJldHVybiAkaHR0cC5nZXQoR2xvYmFsLmFwaVBhdGggKyAnL2F1dGhlbnRpY2F0ZS91c2VyJyk7XG4gICAgICB9KS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICBhdXRoLnVwZGF0ZUN1cnJlbnRVc2VyKHJlc3BvbnNlLmRhdGEudXNlcik7XG5cbiAgICAgICAgZGVmZXJyZWQucmVzb2x2ZSgpO1xuICAgICAgfSwgZnVuY3Rpb24gKGVycm9yKSB7XG4gICAgICAgIGF1dGgubG9nb3V0KCk7XG5cbiAgICAgICAgZGVmZXJyZWQucmVqZWN0KGVycm9yKTtcbiAgICAgIH0pO1xuXG4gICAgICByZXR1cm4gZGVmZXJyZWQucHJvbWlzZTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBEZXNsb2dhIG9zIHVzdcOhcmlvcy4gQ29tbyBuw6NvIHRlbiBuZW5odW1hIGluZm9ybWHDp8OjbyBuYSBzZXNzw6NvIGRvIHNlcnZpZG9yXG4gICAgICogZSB1bSB0b2tlbiB1bWEgdmV6IGdlcmFkbyBuw6NvIHBvZGUsIHBvciBwYWRyw6NvLCBzZXIgaW52YWxpZGFkbyBhbnRlcyBkbyBzZXUgdGVtcG8gZGUgZXhwaXJhw6fDo28sXG4gICAgICogc29tZW50ZSBhcGFnYW1vcyBvcyBkYWRvcyBkbyB1c3XDoXJpbyBlIG8gdG9rZW4gZG8gbmF2ZWdhZG9yIHBhcmEgZWZldGl2YXIgbyBsb2dvdXQuXG4gICAgICpcbiAgICAgKiBAcmV0dXJucyB7cHJvbWlzZX0gVW1hIHByb21pc2UgY29tIG8gcmVzdWx0YWRvIGRhIG9wZXJhw6fDo29cbiAgICAgKi9cbiAgICBmdW5jdGlvbiBsb2dvdXQoKSB7XG4gICAgICB2YXIgZGVmZXJyZWQgPSAkcS5kZWZlcigpO1xuXG4gICAgICBhdXRoLnVwZGF0ZUN1cnJlbnRVc2VyKG51bGwpO1xuICAgICAgZGVmZXJyZWQucmVzb2x2ZSgpO1xuXG4gICAgICByZXR1cm4gZGVmZXJyZWQucHJvbWlzZTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBFbnZpYSB1bSBlbWFpbCBwYXJhIHJlY3VwZXJhw6fDo28gZGUgc2VuaGFcbiAgICAgKiBAcGFyYW0ge09iamVjdH0gcmVzZXREYXRhIC0gT2JqZXRvIGNvbnRlbmRvIG8gZW1haWxcbiAgICAgKiBAcmV0dXJuIHtQcm9taXNlfSAtIFJldG9ybmEgdW1hIHByb21pc2UgcGFyYSBzZXIgcmVzb2x2aWRhXG4gICAgICovXG4gICAgZnVuY3Rpb24gc2VuZEVtYWlsUmVzZXRQYXNzd29yZChyZXNldERhdGEpIHtcbiAgICAgIHZhciBkZWZlcnJlZCA9ICRxLmRlZmVyKCk7XG5cbiAgICAgICRodHRwLnBvc3QoR2xvYmFsLmFwaVBhdGggKyAnL3Bhc3N3b3JkL2VtYWlsJywgcmVzZXREYXRhKS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICBkZWZlcnJlZC5yZXNvbHZlKHJlc3BvbnNlLmRhdGEpO1xuICAgICAgfSwgZnVuY3Rpb24gKGVycm9yKSB7XG4gICAgICAgIGRlZmVycmVkLnJlamVjdChlcnJvcik7XG4gICAgICB9KTtcblxuICAgICAgcmV0dXJuIGRlZmVycmVkLnByb21pc2U7XG4gICAgfVxuXG4gICAgcmV0dXJuIGF1dGg7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb250cm9sbGVyKCdMb2dpbkNvbnRyb2xsZXInLCBMb2dpbkNvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gTG9naW5Db250cm9sbGVyKCRzdGF0ZSwgQXV0aCwgR2xvYmFsLCBQckRpYWxvZykge1xuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICB2bS5sb2dpbiA9IGxvZ2luO1xuICAgIHZtLm9wZW5EaWFsb2dSZXNldFBhc3MgPSBvcGVuRGlhbG9nUmVzZXRQYXNzO1xuXG4gICAgYWN0aXZhdGUoKTtcblxuICAgIGZ1bmN0aW9uIGFjdGl2YXRlKCkge1xuICAgICAgdm0uY3JlZGVudGlhbHMgPSB7fTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBsb2dpbigpIHtcbiAgICAgIHZhciBjcmVkZW50aWFscyA9IHtcbiAgICAgICAgZW1haWw6IHZtLmNyZWRlbnRpYWxzLmVtYWlsLFxuICAgICAgICBwYXNzd29yZDogdm0uY3JlZGVudGlhbHMucGFzc3dvcmRcbiAgICAgIH07XG5cbiAgICAgIEF1dGgubG9naW4oY3JlZGVudGlhbHMpLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICAkc3RhdGUuZ28oR2xvYmFsLmhvbWVTdGF0ZSk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBFeGliZSBvIGRpYWxvZyBwYXJhIHJlY3VwZXJhw6fDo28gZGUgc2VuaGFcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBvcGVuRGlhbG9nUmVzZXRQYXNzKCkge1xuICAgICAgdmFyIGNvbmZpZyA9IHtcbiAgICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9hdXRoL3NlbmQtcmVzZXQtZGlhbG9nLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnUGFzc3dvcmRDb250cm9sbGVyIGFzIHBhc3NDdHJsJyxcbiAgICAgICAgaGFzQmFja2Ryb3A6IHRydWVcbiAgICAgIH07XG5cbiAgICAgIFByRGlhbG9nLmN1c3RvbShjb25maWcpO1xuICAgIH1cbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbnRyb2xsZXIoJ1Bhc3N3b3JkQ29udHJvbGxlcicsIFBhc3N3b3JkQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBQYXNzd29yZENvbnRyb2xsZXIoR2xvYmFsLCAkc3RhdGVQYXJhbXMsICRodHRwLCAkdGltZW91dCwgJHN0YXRlLCAvLyBOT1NPTkFSXG4gIFByVG9hc3QsIFByRGlhbG9nLCBBdXRoLCAkdHJhbnNsYXRlKSB7XG5cbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0uc2VuZFJlc2V0ID0gc2VuZFJlc2V0O1xuICAgIHZtLmNsb3NlRGlhbG9nID0gY2xvc2VEaWFsb2c7XG4gICAgdm0uY2xlYW5Gb3JtID0gY2xlYW5Gb3JtO1xuICAgIHZtLnNlbmRFbWFpbFJlc2V0UGFzc3dvcmQgPSBzZW5kRW1haWxSZXNldFBhc3N3b3JkO1xuXG4gICAgYWN0aXZhdGUoKTtcblxuICAgIGZ1bmN0aW9uIGFjdGl2YXRlKCkge1xuICAgICAgdm0ucmVzZXQgPSB7IGVtYWlsOiAnJywgdG9rZW46ICRzdGF0ZVBhcmFtcy50b2tlbiB9O1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWxpemEgYSBhbHRlcmHDp8OjbyBkYSBzZW5oYSBkbyB1c3XDoXJpbyBlIG8gcmVkaXJlY2lvbmEgcGFyYSBhIHRlbGEgZGUgbG9naW5cbiAgICAgKi9cbiAgICBmdW5jdGlvbiBzZW5kUmVzZXQoKSB7XG4gICAgICAkaHR0cC5wb3N0KEdsb2JhbC5hcGlQYXRoICsgJy9wYXNzd29yZC9yZXNldCcsIHZtLnJlc2V0KS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgUHJUb2FzdC5zdWNjZXNzKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMub3BlcmF0aW9uU3VjY2VzcycpKTtcbiAgICAgICAgJHRpbWVvdXQoZnVuY3Rpb24gKCkge1xuICAgICAgICAgICRzdGF0ZS5nbyhHbG9iYWwubG9naW5TdGF0ZSk7XG4gICAgICAgIH0sIDE1MDApO1xuICAgICAgfSwgZnVuY3Rpb24gKGVycm9yKSB7XG4gICAgICAgIGlmIChlcnJvci5zdGF0dXMgIT09IDQwMCAmJiBlcnJvci5zdGF0dXMgIT09IDUwMCkge1xuICAgICAgICAgIHZhciBtc2cgPSAnJztcblxuICAgICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgZXJyb3IuZGF0YS5wYXNzd29yZC5sZW5ndGg7IGkrKykge1xuICAgICAgICAgICAgbXNnICs9IGVycm9yLmRhdGEucGFzc3dvcmRbaV0gKyAnPGJyPic7XG4gICAgICAgICAgfVxuICAgICAgICAgIFByVG9hc3QuZXJyb3IobXNnLnRvVXBwZXJDYXNlKCkpO1xuICAgICAgICB9XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBFbnZpYSB1bSBlbWFpbCBkZSByZWN1cGVyYcOnw6NvIGRlIHNlbmhhIGNvbSBvIHRva2VuIGRvIHVzdcOhcmlvXG4gICAgICovXG4gICAgZnVuY3Rpb24gc2VuZEVtYWlsUmVzZXRQYXNzd29yZCgpIHtcblxuICAgICAgaWYgKHZtLnJlc2V0LmVtYWlsID09PSAnJykge1xuICAgICAgICBQclRvYXN0LmVycm9yKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMudmFsaWRhdGUuZmllbGRSZXF1aXJlZCcsIHsgZmllbGQ6ICdlbWFpbCcgfSkpO1xuICAgICAgICByZXR1cm47XG4gICAgICB9XG5cbiAgICAgIEF1dGguc2VuZEVtYWlsUmVzZXRQYXNzd29yZCh2bS5yZXNldCkudGhlbihmdW5jdGlvbiAoZGF0YSkge1xuICAgICAgICBQclRvYXN0LnN1Y2Nlc3MoZGF0YS5tZXNzYWdlKTtcblxuICAgICAgICB2bS5jbGVhbkZvcm0oKTtcbiAgICAgICAgdm0uY2xvc2VEaWFsb2coKTtcbiAgICAgIH0sIGZ1bmN0aW9uIChlcnJvcikge1xuICAgICAgICBpZiAoZXJyb3IuZGF0YS5lbWFpbCAmJiBlcnJvci5kYXRhLmVtYWlsLmxlbmd0aCA+IDApIHtcbiAgICAgICAgICB2YXIgbXNnID0gJyc7XG5cbiAgICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IGVycm9yLmRhdGEuZW1haWwubGVuZ3RoOyBpKyspIHtcbiAgICAgICAgICAgIG1zZyArPSBlcnJvci5kYXRhLmVtYWlsW2ldICsgJzxicj4nO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIFByVG9hc3QuZXJyb3IobXNnKTtcbiAgICAgICAgfVxuICAgICAgfSk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gY2xvc2VEaWFsb2coKSB7XG4gICAgICBQckRpYWxvZy5jbG9zZSgpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGNsZWFuRm9ybSgpIHtcbiAgICAgIHZtLnJlc2V0LmVtYWlsID0gJyc7XG4gICAgfVxuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4vKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCovXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZhY3RvcnkoJ3NlcnZpY2VGYWN0b3J5Jywgc2VydmljZUZhY3RvcnkpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLyoqXG4gICAqIE1haXMgaW5mb3JtYcOnw7VlczpcbiAgICogaHR0cHM6Ly9naXRodWIuY29tL3N3aW1sYW5lL2FuZ3VsYXItbW9kZWwtZmFjdG9yeS93aWtpL0FQSVxuICAgKi9cbiAgZnVuY3Rpb24gc2VydmljZUZhY3RvcnkoJG1vZGVsRmFjdG9yeSkge1xuICAgIHJldHVybiBmdW5jdGlvbiAodXJsLCBvcHRpb25zKSB7XG4gICAgICB2YXIgbW9kZWw7XG4gICAgICB2YXIgZGVmYXVsdE9wdGlvbnMgPSB7XG4gICAgICAgIGFjdGlvbnM6IHtcbiAgICAgICAgICAvKipcbiAgICAgICAgICAgKiBTZXJ2acOnbyBjb211bSBwYXJhIHJlYWxpemFyIGJ1c2NhIGNvbSBwYWdpbmHDp8Ojb1xuICAgICAgICAgICAqIE8gbWVzbW8gZXNwZXJhIHF1ZSBzZWphIHJldG9ybmFkbyB1bSBvYmpldG8gY29tIGl0ZW1zIGUgdG90YWxcbiAgICAgICAgICAgKi9cbiAgICAgICAgICBwYWdpbmF0ZToge1xuICAgICAgICAgICAgbWV0aG9kOiAnR0VUJyxcbiAgICAgICAgICAgIGlzQXJyYXk6IGZhbHNlLFxuICAgICAgICAgICAgd3JhcDogZmFsc2UsXG4gICAgICAgICAgICBhZnRlclJlcXVlc3Q6IGZ1bmN0aW9uIGFmdGVyUmVxdWVzdChyZXNwb25zZSkge1xuICAgICAgICAgICAgICBpZiAocmVzcG9uc2VbJ2l0ZW1zJ10pIHtcbiAgICAgICAgICAgICAgICByZXNwb25zZVsnaXRlbXMnXSA9IG1vZGVsLkxpc3QocmVzcG9uc2VbJ2l0ZW1zJ10pO1xuICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgcmV0dXJuIHJlc3BvbnNlO1xuICAgICAgICAgICAgfVxuICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgfTtcblxuICAgICAgbW9kZWwgPSAkbW9kZWxGYWN0b3J5KHVybCwgYW5ndWxhci5tZXJnZShkZWZhdWx0T3B0aW9ucywgb3B0aW9ucykpO1xuXG4gICAgICByZXR1cm4gbW9kZWw7XG4gICAgfTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbnRyb2xsZXIoJ0NSVURDb250cm9sbGVyJywgQ1JVRENvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLyoqXG4gICAqIENvbnRyb2xhZG9yIEJhc2UgcXVlIGltcGxlbWVudGEgdG9kYXMgYXMgZnVuw6fDtWVzIHBhZHLDtWVzIGRlIHVtIENSVURcbiAgICpcbiAgICogQcOnw7VlcyBpbXBsZW1lbnRhZGFzXG4gICAqIGFjdGl2YXRlKClcbiAgICogc2VhcmNoKHBhZ2UpXG4gICAqIGVkaXQocmVzb3VyY2UpXG4gICAqIHNhdmUoKVxuICAgKiByZW1vdmUocmVzb3VyY2UpXG4gICAqIGdvVG8odmlld05hbWUpXG4gICAqIGNsZWFuRm9ybSgpXG4gICAqXG4gICAqIEdhdGlsaG9zXG4gICAqXG4gICAqIG9uQWN0aXZhdGUoKVxuICAgKiBhcHBseUZpbHRlcnMoZGVmYXVsdFF1ZXJ5RmlsdGVycylcbiAgICogYmVmb3JlU2VhcmNoKHBhZ2UpIC8vcmV0b3JuYW5kbyBmYWxzZSBjYW5jZWxhIG8gZmx1eG9cbiAgICogYWZ0ZXJTZWFyY2gocmVzcG9uc2UpXG4gICAqIGJlZm9yZUNsZWFuIC8vcmV0b3JuYW5kbyBmYWxzZSBjYW5jZWxhIG8gZmx1eG9cbiAgICogYWZ0ZXJDbGVhbigpXG4gICAqIGJlZm9yZVNhdmUoKSAvL3JldG9ybmFuZG8gZmFsc2UgY2FuY2VsYSBvIGZsdXhvXG4gICAqIGFmdGVyU2F2ZShyZXNvdXJjZSlcbiAgICogb25TYXZlRXJyb3IoZXJyb3IpXG4gICAqIGJlZm9yZVJlbW92ZShyZXNvdXJjZSkgLy9yZXRvcm5hbmRvIGZhbHNlIGNhbmNlbGEgbyBmbHV4b1xuICAgKiBhZnRlclJlbW92ZShyZXNvdXJjZSlcbiAgICpcbiAgICogQHBhcmFtIHthbnl9IHZtIGluc3RhbmNpYSBkbyBjb250cm9sbGVyIGZpbGhvXG4gICAqIEBwYXJhbSB7YW55fSBtb2RlbFNlcnZpY2Ugc2VydmnDp28gZG8gbW9kZWwgcXVlIHZhaSBzZXIgdXRpbGl6YWRvXG4gICAqIEBwYXJhbSB7YW55fSBvcHRpb25zIG9ww6fDtWVzIHBhcmEgc29icmVlc2NyZXZlciBjb21wb3J0YW1lbnRvcyBwYWRyw7Vlc1xuICAgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gQ1JVRENvbnRyb2xsZXIodm0sIG1vZGVsU2VydmljZSwgb3B0aW9ucywgUHJUb2FzdCwgUHJQYWdpbmF0aW9uLCAvLyBOT1NPTkFSXG4gIFByRGlhbG9nLCAkdHJhbnNsYXRlKSB7XG5cbiAgICAvL0Z1bmN0aW9ucyBCbG9ja1xuICAgIHZtLnNlYXJjaCA9IHNlYXJjaDtcbiAgICB2bS5wYWdpbmF0ZVNlYXJjaCA9IHBhZ2luYXRlU2VhcmNoO1xuICAgIHZtLm5vcm1hbFNlYXJjaCA9IG5vcm1hbFNlYXJjaDtcbiAgICB2bS5lZGl0ID0gZWRpdDtcbiAgICB2bS5zYXZlID0gc2F2ZTtcbiAgICB2bS5yZW1vdmUgPSByZW1vdmU7XG4gICAgdm0uZ29UbyA9IGdvVG87XG4gICAgdm0uY2xlYW5Gb3JtID0gY2xlYW5Gb3JtO1xuXG4gICAgYWN0aXZhdGUoKTtcblxuICAgIC8qKlxuICAgICAqIFByZXBhcmEgbyBjb250cm9sYWRvclxuICAgICAqIEZheiBvIG1lcmdlIGRhcyBvcMOnw7Vlc1xuICAgICAqIEluaWNpYWxpemEgbyByZWN1cnNvXG4gICAgICogSW5pY2lhbGl6YSBvIG9iamV0byBwYWdpbmFkb3IgZSByZWFsaXphIGEgcGVzcXVpc2FcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBhY3RpdmF0ZSgpIHtcbiAgICAgIHZtLmRlZmF1bHRPcHRpb25zID0ge1xuICAgICAgICByZWRpcmVjdEFmdGVyU2F2ZTogdHJ1ZSxcbiAgICAgICAgc2VhcmNoT25Jbml0OiB0cnVlLFxuICAgICAgICBwZXJQYWdlOiA4LFxuICAgICAgICBza2lwUGFnaW5hdGlvbjogZmFsc2VcbiAgICAgIH07XG5cbiAgICAgIGFuZ3VsYXIubWVyZ2Uodm0uZGVmYXVsdE9wdGlvbnMsIG9wdGlvbnMpO1xuXG4gICAgICB2bS52aWV3Rm9ybSA9IGZhbHNlO1xuICAgICAgdm0ucmVzb3VyY2UgPSBuZXcgbW9kZWxTZXJ2aWNlKCk7XG5cbiAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0ub25BY3RpdmF0ZSkpIHZtLm9uQWN0aXZhdGUoKTtcblxuICAgICAgdm0ucGFnaW5hdG9yID0gUHJQYWdpbmF0aW9uLmdldEluc3RhbmNlKHZtLnNlYXJjaCwgdm0uZGVmYXVsdE9wdGlvbnMucGVyUGFnZSk7XG5cbiAgICAgIGlmICh2bS5kZWZhdWx0T3B0aW9ucy5zZWFyY2hPbkluaXQpIHZtLnNlYXJjaCgpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWxpemEgYSBwZXNxdWlzYVxuICAgICAqIFZlcmlmaWNhIHF1YWwgZGFzIGZ1bsOnw7VlcyBkZSBwZXNxdWlzYSBkZXZlIHNlciByZWFsaXphZGEuXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gcGFnZSBww6FnaW5hIHF1ZSBkZXZlIHNlciBjYXJyZWdhZGFcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBzZWFyY2gocGFnZSkge1xuICAgICAgdm0uZGVmYXVsdE9wdGlvbnMuc2tpcFBhZ2luYXRpb24gPyBub3JtYWxTZWFyY2goKSA6IHBhZ2luYXRlU2VhcmNoKHBhZ2UpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWxpemEgYSBwZXNxdWlzYSBwYWdpbmFkYSBjb20gYmFzZSBub3MgZmlsdHJvcyBkZWZpbmlkb3NcbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSBwYWdlIHDDoWdpbmEgcXVlIGRldmUgc2VyIGNhcnJlZ2FkYVxuICAgICAqL1xuICAgIGZ1bmN0aW9uIHBhZ2luYXRlU2VhcmNoKHBhZ2UpIHtcbiAgICAgIHZtLnBhZ2luYXRvci5jdXJyZW50UGFnZSA9IGFuZ3VsYXIuaXNEZWZpbmVkKHBhZ2UpID8gcGFnZSA6IDE7XG4gICAgICB2bS5kZWZhdWx0UXVlcnlGaWx0ZXJzID0geyBwYWdlOiB2bS5wYWdpbmF0b3IuY3VycmVudFBhZ2UsIHBlclBhZ2U6IHZtLnBhZ2luYXRvci5wZXJQYWdlIH07XG5cbiAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYXBwbHlGaWx0ZXJzKSkgdm0uZGVmYXVsdFF1ZXJ5RmlsdGVycyA9IHZtLmFwcGx5RmlsdGVycyh2bS5kZWZhdWx0UXVlcnlGaWx0ZXJzKTtcbiAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYmVmb3JlU2VhcmNoKSAmJiB2bS5iZWZvcmVTZWFyY2gocGFnZSkgPT09IGZhbHNlKSByZXR1cm4gZmFsc2U7XG5cbiAgICAgIG1vZGVsU2VydmljZS5wYWdpbmF0ZSh2bS5kZWZhdWx0UXVlcnlGaWx0ZXJzKS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICB2bS5wYWdpbmF0b3IuY2FsY051bWJlck9mUGFnZXMocmVzcG9uc2UudG90YWwpO1xuICAgICAgICB2bS5yZXNvdXJjZXMgPSByZXNwb25zZS5pdGVtcztcblxuICAgICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmFmdGVyU2VhcmNoKSkgdm0uYWZ0ZXJTZWFyY2gocmVzcG9uc2UpO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhbGl6YSBhIHBlc3F1aXNhIGNvbSBiYXNlIG5vcyBmaWx0cm9zIGRlZmluaWRvc1xuICAgICAqXG4gICAgICovXG4gICAgZnVuY3Rpb24gbm9ybWFsU2VhcmNoKCkge1xuICAgICAgdm0uZGVmYXVsdFF1ZXJ5RmlsdGVycyA9IHt9O1xuXG4gICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmFwcGx5RmlsdGVycykpIHZtLmRlZmF1bHRRdWVyeUZpbHRlcnMgPSB2bS5hcHBseUZpbHRlcnModm0uZGVmYXVsdFF1ZXJ5RmlsdGVycyk7XG4gICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmJlZm9yZVNlYXJjaCkgJiYgdm0uYmVmb3JlU2VhcmNoKCkgPT09IGZhbHNlKSByZXR1cm4gZmFsc2U7XG5cbiAgICAgIG1vZGVsU2VydmljZS5xdWVyeSh2bS5kZWZhdWx0UXVlcnlGaWx0ZXJzKS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICB2bS5yZXNvdXJjZXMgPSByZXNwb25zZTtcblxuICAgICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmFmdGVyU2VhcmNoKSkgdm0uYWZ0ZXJTZWFyY2gocmVzcG9uc2UpO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogTGltcGEgbyBmb3JtdWzDoXJpb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGNsZWFuRm9ybShmb3JtKSB7XG4gICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmJlZm9yZUNsZWFuKSAmJiB2bS5iZWZvcmVDbGVhbigpID09PSBmYWxzZSkgcmV0dXJuIGZhbHNlO1xuXG4gICAgICB2bS5yZXNvdXJjZSA9IG5ldyBtb2RlbFNlcnZpY2UoKTtcblxuICAgICAgaWYgKGFuZ3VsYXIuaXNEZWZpbmVkKGZvcm0pKSB7XG4gICAgICAgIGZvcm0uJHNldFByaXN0aW5lKCk7XG4gICAgICAgIGZvcm0uJHNldFVudG91Y2hlZCgpO1xuICAgICAgfVxuXG4gICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmFmdGVyQ2xlYW4pKSB2bS5hZnRlckNsZWFuKCk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ2FycmVnYSBubyBmb3JtdWzDoXJpbyBvIHJlY3Vyc28gc2VsZWNpb25hZG8gcGFyYSBlZGnDp8Ojb1xuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IHJlc291cmNlIHJlY3Vyc28gc2VsZWNpb25hZG9cbiAgICAgKi9cbiAgICBmdW5jdGlvbiBlZGl0KHJlc291cmNlKSB7XG4gICAgICB2bS5nb1RvKCdmb3JtJyk7XG4gICAgICB2bS5yZXNvdXJjZSA9IG5ldyBhbmd1bGFyLmNvcHkocmVzb3VyY2UpO1xuXG4gICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmFmdGVyRWRpdCkpIHZtLmFmdGVyRWRpdCgpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFNhbHZhIG91IGF0dWFsaXphIG8gcmVjdXJzbyBjb3JyZW50ZSBubyBmb3JtdWzDoXJpb1xuICAgICAqIE5vIGNvbXBvcnRhbWVudG8gcGFkcsOjbyByZWRpcmVjaW9uYSBvIHVzdcOhcmlvIHBhcmEgdmlldyBkZSBsaXN0YWdlbVxuICAgICAqIGRlcG9pcyBkYSBleGVjdcOnw6NvXG4gICAgICpcbiAgICAgKiBAcmV0dXJuc1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIHNhdmUoZm9ybSkge1xuICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5iZWZvcmVTYXZlKSAmJiB2bS5iZWZvcmVTYXZlKCkgPT09IGZhbHNlKSByZXR1cm4gZmFsc2U7XG5cbiAgICAgIHZtLnJlc291cmNlLiRzYXZlKCkudGhlbihmdW5jdGlvbiAocmVzb3VyY2UpIHtcbiAgICAgICAgdm0ucmVzb3VyY2UgPSByZXNvdXJjZTtcblxuICAgICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmFmdGVyU2F2ZSkpIHZtLmFmdGVyU2F2ZShyZXNvdXJjZSk7XG5cbiAgICAgICAgaWYgKHZtLmRlZmF1bHRPcHRpb25zLnJlZGlyZWN0QWZ0ZXJTYXZlKSB7XG4gICAgICAgICAgdm0uY2xlYW5Gb3JtKGZvcm0pO1xuICAgICAgICAgIHZtLnNlYXJjaCh2bS5wYWdpbmF0b3IuY3VycmVudFBhZ2UpO1xuICAgICAgICAgIHZtLmdvVG8oJ2xpc3QnKTtcbiAgICAgICAgfVxuXG4gICAgICAgIFByVG9hc3Quc3VjY2VzcygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnNhdmVTdWNjZXNzJykpO1xuICAgICAgfSwgZnVuY3Rpb24gKHJlc3BvbnNlRGF0YSkge1xuICAgICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLm9uU2F2ZUVycm9yKSkgdm0ub25TYXZlRXJyb3IocmVzcG9uc2VEYXRhKTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlbW92ZSBvIHJlY3Vyc28gaW5mb3JtYWRvLlxuICAgICAqIEFudGVzIGV4aWJlIHVtIGRpYWxvZ28gZGUgY29uZmlybWHDp8Ojb1xuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IHJlc291cmNlIHJlY3Vyc28gZXNjb2xoaWRvXG4gICAgICovXG4gICAgZnVuY3Rpb24gcmVtb3ZlKHJlc291cmNlKSB7XG4gICAgICB2YXIgY29uZmlnID0ge1xuICAgICAgICB0aXRsZTogJHRyYW5zbGF0ZS5pbnN0YW50KCdkaWFsb2cuY29uZmlybVRpdGxlJyksXG4gICAgICAgIGRlc2NyaXB0aW9uOiAkdHJhbnNsYXRlLmluc3RhbnQoJ2RpYWxvZy5jb25maXJtRGVzY3JpcHRpb24nKVxuICAgICAgfTtcblxuICAgICAgUHJEaWFsb2cuY29uZmlybShjb25maWcpLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmJlZm9yZVJlbW92ZSkgJiYgdm0uYmVmb3JlUmVtb3ZlKHJlc291cmNlKSA9PT0gZmFsc2UpIHJldHVybiBmYWxzZTtcblxuICAgICAgICByZXNvdXJjZS4kZGVzdHJveSgpLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYWZ0ZXJSZW1vdmUpKSB2bS5hZnRlclJlbW92ZShyZXNvdXJjZSk7XG5cbiAgICAgICAgICB2bS5zZWFyY2goKTtcbiAgICAgICAgICBQclRvYXN0LmluZm8oJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5yZW1vdmVTdWNjZXNzJykpO1xuICAgICAgICB9KTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEFsdGVybmEgZW50cmUgYSB2aWV3IGRvIGZvcm11bMOhcmlvIGUgbGlzdGFnZW1cbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSB2aWV3TmFtZSBub21lIGRhIHZpZXdcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBnb1RvKHZpZXdOYW1lKSB7XG4gICAgICB2bS52aWV3Rm9ybSA9IGZhbHNlO1xuXG4gICAgICBpZiAodmlld05hbWUgPT09ICdmb3JtJykge1xuICAgICAgICB2bS5jbGVhbkZvcm0oKTtcbiAgICAgICAgdm0udmlld0Zvcm0gPSB0cnVlO1xuICAgICAgfVxuICAgIH1cbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbnRyb2xsZXIoJ0Rhc2hib2FyZENvbnRyb2xsZXInLCBEYXNoYm9hcmRDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8qKlxuICAgKiBEYXNoYm9hcmQgQ29udHJvbGxlclxuICAgKlxuICAgKiBQYWluZWwgY29tIHByaW5jaXBhaXMgaW5kaWNhZG9yZXNcbiAgICpcbiAgICovXG4gIGZ1bmN0aW9uIERhc2hib2FyZENvbnRyb2xsZXIoKSB7XG4gICAgLy8gQ29udHJvbGxlciB2YXppbyBzb21lbnRlIHBhcmEgc2VyIGRlZmluaWRvIGNvbW8gcMOhZ2luYSBwcmluY2lwYWwuXG4gICAgLy8gRGV2ZSBzZXIgaWRlbnRpZmljYWRvIGUgYWRpY2lvbmFkbyBncsOhZmljb3NcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25maWcocm91dGVzKTtcblxuICAvKipcbiAgICogQXJxdWl2byBkZSBjb25maWd1cmHDp8OjbyBjb20gYXMgcm90YXMgZXNwZWPDrWZpY2FzIGRvIGRhc2hib2FyZFxuICAgKlxuICAgKiBAcGFyYW0ge2FueX0gJHN0YXRlUHJvdmlkZXJcbiAgICogQHBhcmFtIHthbnl9IEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKEdsb2JhbC5ob21lU3RhdGUsIHtcbiAgICAgIHVybDogJy9kYXNoYm9hcmQnLFxuICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9kYXNoYm9hcmQvZGFzaGJvYXJkLmh0bWwnLFxuICAgICAgY29udHJvbGxlcjogJ0Rhc2hib2FyZENvbnRyb2xsZXIgYXMgZGFzaGJvYXJkQ3RybCcsXG4gICAgICBkYXRhOiB7IG5lZWRBdXRoZW50aWNhdGlvbjogdHJ1ZSB9XG4gICAgfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqXG4gICAqIEFycXVpdm8gZGUgY29uZmlndXJhw6fDo28gY29tIGFzIHJvdGFzIGVzcGVjw61maWNhcyBkbyByZWN1cnNvIHVzZXJcbiAgICpcbiAgICogQHBhcmFtIHthbnl9ICRzdGF0ZVByb3ZpZGVyXG4gICAqIEBwYXJhbSB7YW55fSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnYXBwLmRpbmFtaWMtcXVlcnknLCB7XG4gICAgICB1cmw6ICcvY29uc3VsdGFzLWRpbmFtaWNhcycsXG4gICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL2RpbmFtaWMtcXVlcnlzL2RpbmFtaWMtcXVlcnlzLmh0bWwnLFxuICAgICAgY29udHJvbGxlcjogJ0RpbmFtaWNRdWVyeXNDb250cm9sbGVyIGFzIGRpbmFtaWNRdWVyeUN0cmwnLFxuICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IHRydWUsIG5lZWRQcm9maWxlOiBbJ2FkbWluJ10gfVxuICAgIH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZhY3RvcnkoJ0RpbmFtaWNRdWVyeVNlcnZpY2UnLCBEaW5hbWljUXVlcnlTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIERpbmFtaWNRdWVyeVNlcnZpY2Uoc2VydmljZUZhY3RvcnkpIHtcbiAgICByZXR1cm4gc2VydmljZUZhY3RvcnkoJ2RpbmFtaWNRdWVyeScsIHtcbiAgICAgIC8qKlxuICAgICAgICogYcOnw6NvIGFkaWNpb25hZGEgcGFyYSBwZWdhciB1bWEgbGlzdGEgZGUgbW9kZWxzIGV4aXN0ZW50ZXMgbm8gc2Vydmlkb3JcbiAgICAgICAqL1xuICAgICAgYWN0aW9uczoge1xuICAgICAgICBnZXRNb2RlbHM6IHtcbiAgICAgICAgICBtZXRob2Q6ICdHRVQnLFxuICAgICAgICAgIHVybDogJ21vZGVscydcbiAgICAgICAgfVxuICAgICAgfSxcbiAgICAgIGluc3RhbmNlOiB7fVxuICAgIH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29udHJvbGxlcignRGluYW1pY1F1ZXJ5c0NvbnRyb2xsZXInLCBEaW5hbWljUXVlcnlzQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBEaW5hbWljUXVlcnlzQ29udHJvbGxlcigkY29udHJvbGxlciwgRGluYW1pY1F1ZXJ5U2VydmljZSwgbG9kYXNoLCBQclRvYXN0LCAvLyBOT1NPTkFSXG4gICR0cmFuc2xhdGUpIHtcblxuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICAvL2FjdGlvbnNcbiAgICB2bS5vbkFjdGl2YXRlID0gb25BY3RpdmF0ZTtcbiAgICB2bS5hcHBseUZpbHRlcnMgPSBhcHBseUZpbHRlcnM7XG4gICAgdm0ubG9hZEF0dHJpYnV0ZXMgPSBsb2FkQXR0cmlidXRlcztcbiAgICB2bS5sb2FkT3BlcmF0b3JzID0gbG9hZE9wZXJhdG9ycztcbiAgICB2bS5hZGRGaWx0ZXIgPSBhZGRGaWx0ZXI7XG4gICAgdm0uYWZ0ZXJTZWFyY2ggPSBhZnRlclNlYXJjaDtcbiAgICB2bS5ydW5GaWx0ZXIgPSBydW5GaWx0ZXI7XG4gICAgdm0uZWRpdEZpbHRlciA9IGVkaXRGaWx0ZXI7XG4gICAgdm0ubG9hZE1vZGVscyA9IGxvYWRNb2RlbHM7XG4gICAgdm0ucmVtb3ZlRmlsdGVyID0gcmVtb3ZlRmlsdGVyO1xuICAgIHZtLmNsZWFyID0gY2xlYXI7XG4gICAgdm0ucmVzdGFydCA9IHJlc3RhcnQ7XG5cbiAgICAvL2hlcmRhIG8gY29tcG9ydGFtZW50byBiYXNlIGRvIENSVURcbiAgICAkY29udHJvbGxlcignQ1JVRENvbnRyb2xsZXInLCB7IHZtOiB2bSwgbW9kZWxTZXJ2aWNlOiBEaW5hbWljUXVlcnlTZXJ2aWNlLCBvcHRpb25zOiB7XG4gICAgICAgIHNlYXJjaE9uSW5pdDogZmFsc2VcbiAgICAgIH0gfSk7XG5cbiAgICBmdW5jdGlvbiBvbkFjdGl2YXRlKCkge1xuICAgICAgdm0ucmVzdGFydCgpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFByZXBhcmEgZSBhcGxpY2Egb3MgZmlsdHJvIHF1ZSB2w6NvIHNlciBlbnZpYWRvcyBwYXJhIG8gc2VydmnDp29cbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSBkZWZhdWx0UXVlcnlGaWx0ZXJzXG4gICAgICogQHJldHVybnNcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBhcHBseUZpbHRlcnMoZGVmYXVsdFF1ZXJ5RmlsdGVycykge1xuICAgICAgdmFyIHdoZXJlID0ge307XG5cbiAgICAgIC8qKlxuICAgICAgICogbyBzZXJ2acOnbyBlc3BlcmEgdW0gb2JqZXRvIGNvbTpcbiAgICAgICAqICBvIG5vbWUgZGUgdW0gbW9kZWxcbiAgICAgICAqICB1bWEgbGlzdGEgZGUgZmlsdHJvc1xuICAgICAgICovXG4gICAgICBpZiAodm0uYWRkZWRGaWx0ZXJzLmxlbmd0aCA+IDApIHtcbiAgICAgICAgdmFyIGFkZGVkRmlsdGVycyA9IGFuZ3VsYXIuY29weSh2bS5hZGRlZEZpbHRlcnMpO1xuXG4gICAgICAgIHdoZXJlLm1vZGVsID0gdm0uYWRkZWRGaWx0ZXJzWzBdLm1vZGVsLm5hbWU7XG5cbiAgICAgICAgZm9yICh2YXIgaW5kZXggPSAwOyBpbmRleCA8IGFkZGVkRmlsdGVycy5sZW5ndGg7IGluZGV4KyspIHtcbiAgICAgICAgICB2YXIgZmlsdGVyID0gYWRkZWRGaWx0ZXJzW2luZGV4XTtcblxuICAgICAgICAgIGZpbHRlci5tb2RlbCA9IG51bGw7XG4gICAgICAgICAgZmlsdGVyLmF0dHJpYnV0ZSA9IGZpbHRlci5hdHRyaWJ1dGUubmFtZTtcbiAgICAgICAgICBmaWx0ZXIub3BlcmF0b3IgPSBmaWx0ZXIub3BlcmF0b3IudmFsdWU7XG4gICAgICAgIH1cblxuICAgICAgICB3aGVyZS5maWx0ZXJzID0gYW5ndWxhci50b0pzb24oYWRkZWRGaWx0ZXJzKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHdoZXJlLm1vZGVsID0gdm0ucXVlcnlGaWx0ZXJzLm1vZGVsLm5hbWU7XG4gICAgICB9XG5cbiAgICAgIHJldHVybiBhbmd1bGFyLmV4dGVuZChkZWZhdWx0UXVlcnlGaWx0ZXJzLCB3aGVyZSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ2FycmVnYSB0b2RvcyBvcyBtb2RlbHMgY3JpYWRvcyBubyBzZXJ2aWRvciBjb20gc2V1cyBhdHJpYnV0b3NcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBsb2FkTW9kZWxzKCkge1xuICAgICAgLy9QZWdhIHRvZG9zIG9zIG1vZGVscyBkbyBzZXJ2ZXIgZSBtb250YSB1bWEgbGlzdGEgcHJvIENvbWJvQm94XG4gICAgICBEaW5hbWljUXVlcnlTZXJ2aWNlLmdldE1vZGVscygpLnRoZW4oZnVuY3Rpb24gKGRhdGEpIHtcbiAgICAgICAgdm0ubW9kZWxzID0gZGF0YTtcbiAgICAgICAgdm0ucXVlcnlGaWx0ZXJzLm1vZGVsID0gdm0ubW9kZWxzWzBdO1xuICAgICAgICB2bS5sb2FkQXR0cmlidXRlcygpO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ2FycmVnYSBvcyBhdHRyaWJ1dG9zIGRvIG1vZGVsIGVzY29saGlkb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGxvYWRBdHRyaWJ1dGVzKCkge1xuICAgICAgdm0uYXR0cmlidXRlcyA9IHZtLnF1ZXJ5RmlsdGVycy5tb2RlbC5hdHRyaWJ1dGVzO1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzLmF0dHJpYnV0ZSA9IHZtLmF0dHJpYnV0ZXNbMF07XG5cbiAgICAgIHZtLmxvYWRPcGVyYXRvcnMoKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDYXJyZWdhIG9zIG9wZXJhZG9yZXMgZXNwZWNpZmljb3MgcGFyYSBvIHRpcG8gZG8gYXRyaWJ1dG9cbiAgICAgKi9cbiAgICBmdW5jdGlvbiBsb2FkT3BlcmF0b3JzKCkge1xuICAgICAgdmFyIG9wZXJhdG9ycyA9IFt7IHZhbHVlOiAnPScsIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLmVxdWFscycpIH0sIHsgdmFsdWU6ICc8PicsIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLmRpZmVyZW50JykgfV07XG5cbiAgICAgIGlmICh2bS5xdWVyeUZpbHRlcnMuYXR0cmlidXRlLnR5cGUuaW5kZXhPZigndmFyeWluZycpICE9PSAtMSkge1xuICAgICAgICBvcGVyYXRvcnMucHVzaCh7IHZhbHVlOiAnaGFzJyxcbiAgICAgICAgICBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KCd2aWV3cy5maWVsZHMucXVlcnlEaW5hbWljLm9wZXJhdG9ycy5jb250ZWlucycpIH0pO1xuICAgICAgICBvcGVyYXRvcnMucHVzaCh7IHZhbHVlOiAnc3RhcnRXaXRoJyxcbiAgICAgICAgICBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KCd2aWV3cy5maWVsZHMucXVlcnlEaW5hbWljLm9wZXJhdG9ycy5zdGFydFdpdGgnKSB9KTtcbiAgICAgICAgb3BlcmF0b3JzLnB1c2goeyB2YWx1ZTogJ2VuZFdpdGgnLFxuICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLmZpbmlzaFdpdGgnKSB9KTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIG9wZXJhdG9ycy5wdXNoKHsgdmFsdWU6ICc+JyxcbiAgICAgICAgICBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KCd2aWV3cy5maWVsZHMucXVlcnlEaW5hbWljLm9wZXJhdG9ycy5iaWdnZXJUaGFuJykgfSk7XG4gICAgICAgIG9wZXJhdG9ycy5wdXNoKHsgdmFsdWU6ICc+PScsXG4gICAgICAgICAgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudCgndmlld3MuZmllbGRzLnF1ZXJ5RGluYW1pYy5vcGVyYXRvcnMuZXF1YWxzT3JCaWdnZXJUaGFuJykgfSk7XG4gICAgICAgIG9wZXJhdG9ycy5wdXNoKHsgdmFsdWU6ICc8JyxcbiAgICAgICAgICBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KCd2aWV3cy5maWVsZHMucXVlcnlEaW5hbWljLm9wZXJhdG9ycy5sZXNzVGhhbicpIH0pO1xuICAgICAgICBvcGVyYXRvcnMucHVzaCh7IHZhbHVlOiAnPD0nLFxuICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLmVxdWFsc09yTGVzc1RoYW4nKSB9KTtcbiAgICAgIH1cblxuICAgICAgdm0ub3BlcmF0b3JzID0gb3BlcmF0b3JzO1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzLm9wZXJhdG9yID0gdm0ub3BlcmF0b3JzWzBdO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEFkaWNpb25hL2VkaXRhIHVtIGZpbHRyb1xuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IGZvcm0gZWxlbWVudG8gaHRtbCBkbyBmb3JtdWzDoXJpbyBwYXJhIHZhbGlkYcOnw7Vlc1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGFkZEZpbHRlcihmb3JtKSB7XG4gICAgICBpZiAoYW5ndWxhci5pc1VuZGVmaW5lZCh2bS5xdWVyeUZpbHRlcnMudmFsdWUpIHx8IHZtLnF1ZXJ5RmlsdGVycy52YWx1ZSA9PT0gJycpIHtcbiAgICAgICAgUHJUb2FzdC5lcnJvcigkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnZhbGlkYXRlLmZpZWxkUmVxdWlyZWQnLCB7IGZpZWxkOiAndmFsb3InIH0pKTtcbiAgICAgICAgcmV0dXJuO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgaWYgKHZtLmluZGV4IDwgMCkge1xuICAgICAgICAgIHZtLmFkZGVkRmlsdGVycy5wdXNoKGFuZ3VsYXIuY29weSh2bS5xdWVyeUZpbHRlcnMpKTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICB2bS5hZGRlZEZpbHRlcnNbdm0uaW5kZXhdID0gYW5ndWxhci5jb3B5KHZtLnF1ZXJ5RmlsdGVycyk7XG4gICAgICAgICAgdm0uaW5kZXggPSAtMTtcbiAgICAgICAgfVxuXG4gICAgICAgIC8vcmVpbmljaWEgbyBmb3JtdWzDoXJpbyBlIGFzIHZhbGlkYcOnw7VlcyBleGlzdGVudGVzXG4gICAgICAgIHZtLnF1ZXJ5RmlsdGVycyA9IHt9O1xuICAgICAgICBmb3JtLiRzZXRQcmlzdGluZSgpO1xuICAgICAgICBmb3JtLiRzZXRVbnRvdWNoZWQoKTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFsaXphIGEgcGVzcXVpc2EgdGVuZG8gb3MgZmlsdHJvcyBjb21vIHBhcsOibWV0cm9zXG4gICAgICovXG4gICAgZnVuY3Rpb24gcnVuRmlsdGVyKCkge1xuICAgICAgdm0uc2VhcmNoKHZtLnBhZ2luYXRvci5jdXJyZW50UGFnZSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogR2F0aWxobyBhY2lvbmFkbyBkZXBvaXMgZGEgcGVzcXVpc2EgcmVzcG9uc8OhdmVsIHBvciBpZGVudGlmaWNhciBvcyBhdHJpYnV0b3NcbiAgICAgKiBjb250aWRvcyBub3MgZWxlbWVudG9zIHJlc3VsdGFudGVzIGRhIGJ1c2NhXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gZGF0YSBkYWRvcyByZWZlcmVudGUgYW8gcmV0b3JubyBkYSByZXF1aXNpw6fDo29cbiAgICAgKi9cbiAgICBmdW5jdGlvbiBhZnRlclNlYXJjaChkYXRhKSB7XG4gICAgICB2YXIga2V5cyA9IGRhdGEuaXRlbXMubGVuZ3RoID4gMCA/IE9iamVjdC5rZXlzKGRhdGEuaXRlbXNbMF0pIDogW107XG5cbiAgICAgIC8vcmV0aXJhIHRvZG9zIG9zIGF0cmlidXRvcyBxdWUgY29tZcOnYW0gY29tICQuXG4gICAgICAvL0Vzc2VzIGF0cmlidXRvcyBzw6NvIGFkaWNpb25hZG9zIHBlbG8gc2VydmnDp28gZSBuw6NvIGRldmUgYXBhcmVjZXIgbmEgbGlzdGFnZW1cbiAgICAgIHZtLmtleXMgPSBsb2Rhc2guZmlsdGVyKGtleXMsIGZ1bmN0aW9uIChrZXkpIHtcbiAgICAgICAgcmV0dXJuICFsb2Rhc2guc3RhcnRzV2l0aChrZXksICckJyk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDb2xvYWNhIG5vIGZvcm11bMOhcmlvIG8gZmlsdHJvIGVzY29saGlkbyBwYXJhIGVkacOnw6NvXG4gICAgICogQHBhcmFtIHthbnl9ICRpbmRleCBpbmRpY2Ugbm8gYXJyYXkgZG8gZmlsdHJvIGVzY29saGlkb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGVkaXRGaWx0ZXIoJGluZGV4KSB7XG4gICAgICB2bS5pbmRleCA9ICRpbmRleDtcbiAgICAgIHZtLnF1ZXJ5RmlsdGVycyA9IHZtLmFkZGVkRmlsdGVyc1skaW5kZXhdO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlbW92ZSBvIGZpbHRybyBlc2NvbGhpZG9cbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSAkaW5kZXggaW5kaWNlIG5vIGFycmF5IGRvIGZpbHRybyBlc2NvbGhpZG9cbiAgICAgKi9cbiAgICBmdW5jdGlvbiByZW1vdmVGaWx0ZXIoJGluZGV4KSB7XG4gICAgICB2bS5hZGRlZEZpbHRlcnMuc3BsaWNlKCRpbmRleCk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogTGltcGEgbyBmb3JtdWzDoXJpbyBjb3JyZW50ZVxuICAgICAqL1xuICAgIGZ1bmN0aW9uIGNsZWFyKCkge1xuICAgICAgLy9ndWFyZGEgbyBpbmRpY2UgZG8gcmVnaXN0cm8gcXVlIGVzdMOhIHNlbmRvIGVkaXRhZG9cbiAgICAgIHZtLmluZGV4ID0gLTE7XG4gICAgICAvL3ZpbmN1bGFkbyBhb3MgY2FtcG9zIGRvIGZvcm11bMOhcmlvXG4gICAgICB2bS5xdWVyeUZpbHRlcnMgPSB7fTtcblxuICAgICAgaWYgKHZtLm1vZGVscykgdm0ucXVlcnlGaWx0ZXJzLm1vZGVsID0gdm0ubW9kZWxzWzBdO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlaW5pY2lhIGEgY29uc3RydcOnw6NvIGRhIHF1ZXJ5IGxpbXBhbmRvIHR1ZG9cbiAgICAgKlxuICAgICAqL1xuICAgIGZ1bmN0aW9uIHJlc3RhcnQoKSB7XG4gICAgICAvL2d1YXJkYSBhdHJpYnV0b3MgZG8gcmVzdWx0YWRvIGRhIGJ1c2NhIGNvcnJlbnRlXG4gICAgICB2bS5rZXlzID0gW107XG5cbiAgICAgIC8vZ3VhcmRhIG9zIGZpbHRyb3MgYWRpY2lvbmFkb3NcbiAgICAgIHZtLmFkZGVkRmlsdGVycyA9IFtdO1xuICAgICAgdm0uY2xlYXIoKTtcbiAgICAgIHZtLmxvYWRNb2RlbHMoKTtcbiAgICB9XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5mYWN0b3J5KCdsYW5ndWFnZUxvYWRlcicsIExhbmd1YWdlTG9hZGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIExhbmd1YWdlTG9hZGVyKCRxLCBTdXBwb3J0U2VydmljZSwgJGxvZywgJGluamVjdG9yKSB7XG4gICAgdmFyIHNlcnZpY2UgPSB0aGlzO1xuXG4gICAgc2VydmljZS50cmFuc2xhdGUgPSBmdW5jdGlvbiAobG9jYWxlKSB7XG4gICAgICByZXR1cm4ge1xuICAgICAgICBnbG9iYWw6ICRpbmplY3Rvci5nZXQobG9jYWxlICsgJy5pMThuLmdsb2JhbCcpLFxuICAgICAgICB2aWV3czogJGluamVjdG9yLmdldChsb2NhbGUgKyAnLmkxOG4udmlld3MnKSxcbiAgICAgICAgYXR0cmlidXRlczogJGluamVjdG9yLmdldChsb2NhbGUgKyAnLmkxOG4uYXR0cmlidXRlcycpLFxuICAgICAgICBkaWFsb2c6ICRpbmplY3Rvci5nZXQobG9jYWxlICsgJy5pMThuLmRpYWxvZycpLFxuICAgICAgICBtZXNzYWdlczogJGluamVjdG9yLmdldChsb2NhbGUgKyAnLmkxOG4ubWVzc2FnZXMnKSxcbiAgICAgICAgbW9kZWxzOiAkaW5qZWN0b3IuZ2V0KGxvY2FsZSArICcuaTE4bi5tb2RlbHMnKVxuICAgICAgfTtcbiAgICB9O1xuXG4gICAgLy8gcmV0dXJuIGxvYWRlckZuXG4gICAgcmV0dXJuIGZ1bmN0aW9uIChvcHRpb25zKSB7XG4gICAgICAkbG9nLmluZm8oJ0NhcnJlZ2FuZG8gbyBjb250ZXVkbyBkYSBsaW5ndWFnZW0gJyArIG9wdGlvbnMua2V5KTtcblxuICAgICAgdmFyIGRlZmVycmVkID0gJHEuZGVmZXIoKTtcblxuICAgICAgLy9DYXJyZWdhIGFzIGxhbmdzIHF1ZSBwcmVjaXNhbSBlIGVzdMOjbyBubyBzZXJ2aWRvciBwYXJhIG7Do28gcHJlY2lzYXIgcmVwZXRpciBhcXVpXG4gICAgICBTdXBwb3J0U2VydmljZS5sYW5ncygpLnRoZW4oZnVuY3Rpb24gKGxhbmdzKSB7XG4gICAgICAgIC8vTWVyZ2UgY29tIG9zIGxhbmdzIGRlZmluaWRvcyBubyBzZXJ2aWRvclxuICAgICAgICB2YXIgZGF0YSA9IGFuZ3VsYXIubWVyZ2Uoc2VydmljZS50cmFuc2xhdGUob3B0aW9ucy5rZXkpLCBsYW5ncyk7XG5cbiAgICAgICAgcmV0dXJuIGRlZmVycmVkLnJlc29sdmUoZGF0YSk7XG4gICAgICB9LCBmdW5jdGlvbiAoKSB7XG4gICAgICAgIHJldHVybiBkZWZlcnJlZC5yZXNvbHZlKHNlcnZpY2UudHJhbnNsYXRlKG9wdGlvbnMua2V5KSk7XG4gICAgICB9KTtcblxuICAgICAgcmV0dXJuIGRlZmVycmVkLnByb21pc2U7XG4gICAgfTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZpbHRlcigndEF0dHInLCB0QXR0cik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiB0QXR0cigkZmlsdGVyKSB7XG4gICAgLyoqXG4gICAgICogRmlsdHJvIHBhcmEgdHJhZHXDp8OjbyBkZSB1bSBhdHJpYnV0byBkZSB1bSBtb2RlbFxuICAgICAqIFxuICAgICAqIEBwYXJhbSB7YW55fSBuYW1lIG5vbWUgZG8gYXRyaWJ1dG9cbiAgICAgKiBAcmV0dXJucyBvIG5vbWUgZG8gYXRyaWJ1dG8gdHJhZHV6aWRvIGNhc28gZW5jb250cmUgc2UgbsOjbyBvIG5vbWUgcGFzc2FkbyBwb3IgcGFyYW1ldHJvXG4gICAgICovXG4gICAgcmV0dXJuIGZ1bmN0aW9uIChuYW1lKSB7XG4gICAgICB2YXIga2V5ID0gJ2F0dHJpYnV0ZXMuJyArIG5hbWU7XG4gICAgICB2YXIgdHJhbnNsYXRlID0gJGZpbHRlcigndHJhbnNsYXRlJykoa2V5KTtcblxuICAgICAgcmV0dXJuIHRyYW5zbGF0ZSA9PT0ga2V5ID8gbmFtZSA6IHRyYW5zbGF0ZTtcbiAgICB9O1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmlsdGVyKCd0QnJlYWRjcnVtYicsIHRCcmVhZGNydW1iKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIHRCcmVhZGNydW1iKCRmaWx0ZXIpIHtcbiAgICAvKipcbiAgICAgKiBGaWx0cm8gcGFyYSB0cmFkdcOnw6NvIGRvIGJyZWFkY3J1bWIgKHRpdHVsbyBkYSB0ZWxhIGNvbSByYXN0cmVpbylcbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSBpZCBjaGF2ZSBjb20gbyBub21lIGRvIHN0YXRlIHJlZmVyZW50ZSB0ZWxhXG4gICAgICogQHJldHVybnMgYSB0cmFkdcOnw6NvIGNhc28gZW5jb250cmUgc2UgbsOjbyBvIGlkIHBhc3NhZG8gcG9yIHBhcmFtZXRyb1xuICAgICAqL1xuICAgIHJldHVybiBmdW5jdGlvbiAoaWQpIHtcbiAgICAgIC8vcGVnYSBhIHNlZ3VuZGEgcGFydGUgZG8gbm9tZSBkbyBzdGF0ZSwgcmV0aXJhbmRvIGEgcGFydGUgYWJzdHJhdGEgKGFwcC4pXG4gICAgICB2YXIga2V5ID0gJ3ZpZXdzLmJyZWFkY3J1bWJzLicgKyBpZC5zcGxpdCgnLicpWzFdO1xuICAgICAgdmFyIHRyYW5zbGF0ZSA9ICRmaWx0ZXIoJ3RyYW5zbGF0ZScpKGtleSk7XG5cbiAgICAgIHJldHVybiB0cmFuc2xhdGUgPT09IGtleSA/IGlkIDogdHJhbnNsYXRlO1xuICAgIH07XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5maWx0ZXIoJ3RNb2RlbCcsIHRNb2RlbCk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiB0TW9kZWwoJGZpbHRlcikge1xuICAgIC8qKlxuICAgICAqIEZpbHRybyBwYXJhIHRyYWR1w6fDo28gZGUgdW0gYXRyaWJ1dG8gZGUgdW0gbW9kZWxcbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSBuYW1lIG5vbWUgZG8gYXRyaWJ1dG9cbiAgICAgKiBAcmV0dXJucyBvIG5vbWUgZG8gYXRyaWJ1dG8gdHJhZHV6aWRvIGNhc28gZW5jb250cmUgc2UgbsOjbyBvIG5vbWUgcGFzc2FkbyBwb3IgcGFyYW1ldHJvXG4gICAgICovXG4gICAgcmV0dXJuIGZ1bmN0aW9uIChuYW1lKSB7XG4gICAgICB2YXIga2V5ID0gJ21vZGVscy4nICsgbmFtZS50b0xvd2VyQ2FzZSgpO1xuICAgICAgdmFyIHRyYW5zbGF0ZSA9ICRmaWx0ZXIoJ3RyYW5zbGF0ZScpKGtleSk7XG5cbiAgICAgIHJldHVybiB0cmFuc2xhdGUgPT09IGtleSA/IG5hbWUgOiB0cmFuc2xhdGU7XG4gICAgfTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5ydW4oYXV0aGVudGljYXRpb25MaXN0ZW5lcik7XG5cbiAgLyoqXG4gICAqIExpc3RlbiBhbGwgc3RhdGUgKHBhZ2UpIGNoYW5nZXMuIEV2ZXJ5IHRpbWUgYSBzdGF0ZSBjaGFuZ2UgbmVlZCB0byB2ZXJpZnkgdGhlIHVzZXIgaXMgYXV0aGVudGljYXRlZCBvciBub3QgdG9cbiAgICogcmVkaXJlY3QgdG8gY29ycmVjdCBwYWdlLiBXaGVuIGEgdXNlciBjbG9zZSB0aGUgYnJvd3NlciB3aXRob3V0IGxvZ291dCwgd2hlbiBoaW0gcmVvcGVuIHRoZSBicm93c2VyIHRoaXMgZXZlbnRcbiAgICogcmVhdXRoZW50aWNhdGUgdGhlIHVzZXIgd2l0aCB0aGUgcGVyc2lzdGVudCB0b2tlbiBvZiB0aGUgbG9jYWwgc3RvcmFnZS5cbiAgICpcbiAgICogV2UgZG9uJ3QgY2hlY2sgaWYgdGhlIHRva2VuIGlzIGV4cGlyZWQgb3Igbm90IGluIHRoZSBwYWdlIGNoYW5nZSwgYmVjYXVzZSBpcyBnZW5lcmF0ZSBhbiB1bmVjZXNzYXJ5IG92ZXJoZWFkLlxuICAgKiBJZiB0aGUgdG9rZW4gaXMgZXhwaXJlZCB3aGVuIHRoZSB1c2VyIHRyeSB0byBjYWxsIHRoZSBmaXJzdCBhcGkgdG8gZ2V0IGRhdGEsIGhpbSB3aWxsIGJlIGxvZ29mZiBhbmQgcmVkaXJlY3RcbiAgICogdG8gbG9naW4gcGFnZS5cbiAgICpcbiAgICogQHBhcmFtICRyb290U2NvcGVcbiAgICogQHBhcmFtICRzdGF0ZVxuICAgKiBAcGFyYW0gJHN0YXRlUGFyYW1zXG4gICAqIEBwYXJhbSBBdXRoXG4gICAqL1xuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIGF1dGhlbnRpY2F0aW9uTGlzdGVuZXIoJHJvb3RTY29wZSwgJHN0YXRlLCBHbG9iYWwsIEF1dGgsIFByVG9hc3QsIC8vIE5PU09OQVJcbiAgJHRyYW5zbGF0ZSkge1xuXG4gICAgLy9vbmx5IHdoZW4gYXBwbGljYXRpb24gc3RhcnQgY2hlY2sgaWYgdGhlIGV4aXN0ZW50IHRva2VuIHN0aWxsIHZhbGlkXG4gICAgQXV0aC5yZW1vdGVWYWxpZGF0ZVRva2VuKCkudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAvL2lmIHRoZSB0b2tlbiBpcyB2YWxpZCBjaGVjayBpZiBleGlzdHMgdGhlIHVzZXIgYmVjYXVzZSB0aGUgYnJvd3NlciBjb3VsZCBiZSBjbG9zZWRcbiAgICAgIC8vYW5kIHRoZSB1c2VyIGRhdGEgaXNuJ3QgaW4gbWVtb3J5XG4gICAgICBpZiAoQXV0aC5jdXJyZW50VXNlciA9PT0gbnVsbCkge1xuICAgICAgICBBdXRoLnVwZGF0ZUN1cnJlbnRVc2VyKGFuZ3VsYXIuZnJvbUpzb24obG9jYWxTdG9yYWdlLmdldEl0ZW0oJ3VzZXInKSkpO1xuICAgICAgfVxuICAgIH0pO1xuXG4gICAgLy9DaGVjayBpZiB0aGUgdG9rZW4gc3RpbGwgdmFsaWQuXG4gICAgJHJvb3RTY29wZS4kb24oJyRzdGF0ZUNoYW5nZVN0YXJ0JywgZnVuY3Rpb24gKGV2ZW50LCB0b1N0YXRlKSB7XG4gICAgICBpZiAodG9TdGF0ZS5kYXRhLm5lZWRBdXRoZW50aWNhdGlvbiB8fCB0b1N0YXRlLmRhdGEubmVlZFByb2ZpbGUpIHtcbiAgICAgICAgLy9kb250IHRyYWl0IHRoZSBzdWNjZXNzIGJsb2NrIGJlY2F1c2UgYWxyZWFkeSBkaWQgYnkgdG9rZW4gaW50ZXJjZXB0b3JcbiAgICAgICAgQXV0aC5yZW1vdGVWYWxpZGF0ZVRva2VuKCkuY2F0Y2goZnVuY3Rpb24gKCkge1xuICAgICAgICAgIFByVG9hc3Qud2FybigkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLmxvZ2luLmxvZ291dEluYWN0aXZlJykpO1xuXG4gICAgICAgICAgaWYgKHRvU3RhdGUubmFtZSAhPT0gR2xvYmFsLmxvZ2luU3RhdGUpIHtcbiAgICAgICAgICAgICRzdGF0ZS5nbyhHbG9iYWwubG9naW5TdGF0ZSk7XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgZXZlbnQucHJldmVudERlZmF1bHQoKTtcbiAgICAgICAgfSk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICAvL2lmIHRoZSB1c2UgaXMgYXV0aGVudGljYXRlZCBhbmQgbmVlZCB0byBlbnRlciBpbiBsb2dpbiBwYWdlXG4gICAgICAgIC8vaGltIHdpbGwgYmUgcmVkaXJlY3RlZCB0byBob21lIHBhZ2VcbiAgICAgICAgaWYgKHRvU3RhdGUubmFtZSA9PT0gR2xvYmFsLmxvZ2luU3RhdGUgJiYgQXV0aC5hdXRoZW50aWNhdGVkKCkpIHtcbiAgICAgICAgICAkc3RhdGUuZ28oR2xvYmFsLmhvbWVTdGF0ZSk7XG4gICAgICAgICAgZXZlbnQucHJldmVudERlZmF1bHQoKTtcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLnJ1bihhdXRob3JpemF0aW9uTGlzdGVuZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gYXV0aG9yaXphdGlvbkxpc3RlbmVyKCRyb290U2NvcGUsICRzdGF0ZSwgR2xvYmFsLCBBdXRoKSB7XG4gICAgLyoqXG4gICAgICogQSBjYWRhIG11ZGFuw6dhIGRlIGVzdGFkbyAoXCJww6FnaW5hXCIpIHZlcmlmaWNhIHNlIG8gdXN1w6FyaW8gdGVtIG8gcGVyZmlsXG4gICAgICogbmVjZXNzw6FyaW8gcGFyYSBvIGFjZXNzbyBhIG1lc21hXG4gICAgICovXG4gICAgJHJvb3RTY29wZS4kb24oJyRzdGF0ZUNoYW5nZVN0YXJ0JywgZnVuY3Rpb24gKGV2ZW50LCB0b1N0YXRlKSB7XG4gICAgICBpZiAodG9TdGF0ZS5kYXRhICYmIHRvU3RhdGUuZGF0YS5uZWVkQXV0aGVudGljYXRpb24gJiYgdG9TdGF0ZS5kYXRhLm5lZWRQcm9maWxlICYmIEF1dGguYXV0aGVudGljYXRlZCgpICYmICFBdXRoLmN1cnJlbnRVc2VyLmhhc1Byb2ZpbGUodG9TdGF0ZS5kYXRhLm5lZWRQcm9maWxlLCB0b1N0YXRlLmRhdGEuYWxsUHJvZmlsZXMpKSB7XG5cbiAgICAgICAgJHN0YXRlLmdvKEdsb2JhbC5ub3RBdXRob3JpemVkU3RhdGUpO1xuICAgICAgICBldmVudC5wcmV2ZW50RGVmYXVsdCgpO1xuICAgICAgfVxuICAgIH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbmZpZyhzcGlubmVySW50ZXJjZXB0b3IpO1xuXG4gIGZ1bmN0aW9uIHNwaW5uZXJJbnRlcmNlcHRvcigkaHR0cFByb3ZpZGVyLCAkcHJvdmlkZSkge1xuICAgIC8qKlxuICAgICAqIEVzdGUgaW50ZXJjZXB0b3Igw6kgcmVzcG9uc8OhdmVsIHBvciBtb3N0cmFyIGUgZXNjb25kZXIgb1xuICAgICAqIGNvbXBvbmVudGUgUHJTcGlubmVyIHNlbXByZSBxdWUgdW1hIHJlcXVpc2nDp8OjbyBhamF4XG4gICAgICogaW5pY2lhciBlIGZpbmFsaXphci5cbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSAkcVxuICAgICAqIEBwYXJhbSB7YW55fSAkaW5qZWN0b3JcbiAgICAgKiBAcmV0dXJuc1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIHNob3dIaWRlU3Bpbm5lcigkcSwgJGluamVjdG9yKSB7XG4gICAgICByZXR1cm4ge1xuICAgICAgICByZXF1ZXN0OiBmdW5jdGlvbiByZXF1ZXN0KGNvbmZpZykge1xuICAgICAgICAgICRpbmplY3Rvci5nZXQoJ1ByU3Bpbm5lcicpLnNob3coKTtcblxuICAgICAgICAgIHJldHVybiBjb25maWc7XG4gICAgICAgIH0sXG5cbiAgICAgICAgcmVzcG9uc2U6IGZ1bmN0aW9uIHJlc3BvbnNlKF9yZXNwb25zZSkge1xuICAgICAgICAgICRpbmplY3Rvci5nZXQoJ1ByU3Bpbm5lcicpLmhpZGUoKTtcblxuICAgICAgICAgIHJldHVybiBfcmVzcG9uc2U7XG4gICAgICAgIH0sXG5cbiAgICAgICAgcmVzcG9uc2VFcnJvcjogZnVuY3Rpb24gcmVzcG9uc2VFcnJvcihyZWplY3Rpb24pIHtcbiAgICAgICAgICAkaW5qZWN0b3IuZ2V0KCdQclNwaW5uZXInKS5oaWRlKCk7XG5cbiAgICAgICAgICByZXR1cm4gJHEucmVqZWN0KHJlamVjdGlvbik7XG4gICAgICAgIH1cbiAgICAgIH07XG4gICAgfVxuXG4gICAgLy8gRGVmaW5lIHVtYSBmYWN0b3J5IHBhcmEgbyAkaHR0cEludGVyY2VwdG9yXG4gICAgJHByb3ZpZGUuZmFjdG9yeSgnc2hvd0hpZGVTcGlubmVyJywgc2hvd0hpZGVTcGlubmVyKTtcblxuICAgIC8vIEFkaWNpb25hIGEgZmFjdG9yeSBubyBhcnJheSBkZSBpbnRlcmNlcHRvcnMgZG8gJGh0dHBcbiAgICAkaHR0cFByb3ZpZGVyLmludGVyY2VwdG9ycy5wdXNoKCdzaG93SGlkZVNwaW5uZXInKTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuLyplc2xpbnQgYW5ndWxhci9tb2R1bGUtZ2V0dGVyOiAwKi9cblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25maWcodG9rZW5JbnRlcmNlcHRvcik7XG5cbiAgLyoqXG4gICAqIEludGVyY2VwdCBhbGwgcmVzcG9uc2UgKHN1Y2Nlc3Mgb3IgZXJyb3IpIHRvIHZlcmlmeSB0aGUgcmV0dXJuZWQgdG9rZW5cbiAgICpcbiAgICogQHBhcmFtICRodHRwUHJvdmlkZXJcbiAgICogQHBhcmFtICRwcm92aWRlXG4gICAqIEBwYXJhbSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gdG9rZW5JbnRlcmNlcHRvcigkaHR0cFByb3ZpZGVyLCAkcHJvdmlkZSwgR2xvYmFsKSB7XG5cbiAgICBmdW5jdGlvbiByZWRpcmVjdFdoZW5TZXJ2ZXJMb2dnZWRPdXQoJHEsICRpbmplY3Rvcikge1xuICAgICAgcmV0dXJuIHtcbiAgICAgICAgcmVxdWVzdDogZnVuY3Rpb24gcmVxdWVzdChjb25maWcpIHtcbiAgICAgICAgICB2YXIgdG9rZW4gPSAkaW5qZWN0b3IuZ2V0KCdBdXRoJykuZ2V0VG9rZW4oKTtcblxuICAgICAgICAgIGlmICh0b2tlbikge1xuICAgICAgICAgICAgY29uZmlnLmhlYWRlcnNbJ0F1dGhvcml6YXRpb24nXSA9ICdCZWFyZXIgJyArIHRva2VuO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIHJldHVybiBjb25maWc7XG4gICAgICAgIH0sXG4gICAgICAgIHJlc3BvbnNlOiBmdW5jdGlvbiByZXNwb25zZShfcmVzcG9uc2UpIHtcbiAgICAgICAgICAvLyBnZXQgYSBuZXcgcmVmcmVzaCB0b2tlbiB0byB1c2UgaW4gdGhlIG5leHQgcmVxdWVzdFxuICAgICAgICAgIHZhciB0b2tlbiA9IF9yZXNwb25zZS5oZWFkZXJzKCdBdXRob3JpemF0aW9uJyk7XG5cbiAgICAgICAgICBpZiAodG9rZW4pIHtcbiAgICAgICAgICAgICRpbmplY3Rvci5nZXQoJ0F1dGgnKS5zZXRUb2tlbih0b2tlbi5zcGxpdCgnICcpWzFdKTtcbiAgICAgICAgICB9XG4gICAgICAgICAgcmV0dXJuIF9yZXNwb25zZTtcbiAgICAgICAgfSxcbiAgICAgICAgcmVzcG9uc2VFcnJvcjogZnVuY3Rpb24gcmVzcG9uc2VFcnJvcihyZWplY3Rpb24pIHtcbiAgICAgICAgICAvLyBJbnN0ZWFkIG9mIGNoZWNraW5nIGZvciBhIHN0YXR1cyBjb2RlIG9mIDQwMCB3aGljaCBtaWdodCBiZSB1c2VkXG4gICAgICAgICAgLy8gZm9yIG90aGVyIHJlYXNvbnMgaW4gTGFyYXZlbCwgd2UgY2hlY2sgZm9yIHRoZSBzcGVjaWZpYyByZWplY3Rpb25cbiAgICAgICAgICAvLyByZWFzb25zIHRvIHRlbGwgdXMgaWYgd2UgbmVlZCB0byByZWRpcmVjdCB0byB0aGUgbG9naW4gc3RhdGVcbiAgICAgICAgICB2YXIgcmVqZWN0aW9uUmVhc29ucyA9IFsndG9rZW5fbm90X3Byb3ZpZGVkJywgJ3Rva2VuX2V4cGlyZWQnLCAndG9rZW5fYWJzZW50JywgJ3Rva2VuX2ludmFsaWQnXTtcblxuICAgICAgICAgIHZhciB0b2tlbkVycm9yID0gZmFsc2U7XG5cbiAgICAgICAgICBhbmd1bGFyLmZvckVhY2gocmVqZWN0aW9uUmVhc29ucywgZnVuY3Rpb24gKHZhbHVlKSB7XG4gICAgICAgICAgICBpZiAocmVqZWN0aW9uLmRhdGEgJiYgcmVqZWN0aW9uLmRhdGEuZXJyb3IgPT09IHZhbHVlKSB7XG4gICAgICAgICAgICAgIHRva2VuRXJyb3IgPSB0cnVlO1xuXG4gICAgICAgICAgICAgICRpbmplY3Rvci5nZXQoJ0F1dGgnKS5sb2dvdXQoKS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICB2YXIgJHN0YXRlID0gJGluamVjdG9yLmdldCgnJHN0YXRlJyk7XG5cbiAgICAgICAgICAgICAgICAvLyBpbiBjYXNlIG11bHRpcGxlIGFqYXggcmVxdWVzdCBmYWlsIGF0IHNhbWUgdGltZSBiZWNhdXNlIHRva2VuIHByb2JsZW1zLFxuICAgICAgICAgICAgICAgIC8vIG9ubHkgdGhlIGZpcnN0IHdpbGwgcmVkaXJlY3RcbiAgICAgICAgICAgICAgICBpZiAoISRzdGF0ZS5pcyhHbG9iYWwubG9naW5TdGF0ZSkpIHtcbiAgICAgICAgICAgICAgICAgICRzdGF0ZS5nbyhHbG9iYWwubG9naW5TdGF0ZSk7XG5cbiAgICAgICAgICAgICAgICAgIC8vY2xvc2UgYW55IGRpYWxvZyB0aGF0IGlzIG9wZW5lZFxuICAgICAgICAgICAgICAgICAgJGluamVjdG9yLmdldCgnUHJEaWFsb2cnKS5jbG9zZSgpO1xuXG4gICAgICAgICAgICAgICAgICBldmVudC5wcmV2ZW50RGVmYXVsdCgpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfSk7XG5cbiAgICAgICAgICAvL2RlZmluZSBkYXRhIHRvIGVtcHR5IGJlY2F1c2UgYWxyZWFkeSBzaG93IFByVG9hc3QgdG9rZW4gbWVzc2FnZVxuICAgICAgICAgIGlmICh0b2tlbkVycm9yKSB7XG4gICAgICAgICAgICByZWplY3Rpb24uZGF0YSA9IHt9O1xuICAgICAgICAgIH1cblxuICAgICAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24ocmVqZWN0aW9uLmhlYWRlcnMpKSB7XG4gICAgICAgICAgICAvLyBtYW55IHNlcnZlcnMgZXJyb3JzIChidXNpbmVzcykgYXJlIGludGVyY2VwdCBoZXJlIGJ1dCBnZW5lcmF0ZWQgYSBuZXcgcmVmcmVzaCB0b2tlblxuICAgICAgICAgICAgLy8gYW5kIG5lZWQgdXBkYXRlIGN1cnJlbnQgdG9rZW5cbiAgICAgICAgICAgIHZhciB0b2tlbiA9IHJlamVjdGlvbi5oZWFkZXJzKCdBdXRob3JpemF0aW9uJyk7XG5cbiAgICAgICAgICAgIGlmICh0b2tlbikge1xuICAgICAgICAgICAgICAkaW5qZWN0b3IuZ2V0KCdBdXRoJykuc2V0VG9rZW4odG9rZW4uc3BsaXQoJyAnKVsxXSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgcmV0dXJuICRxLnJlamVjdChyZWplY3Rpb24pO1xuICAgICAgICB9XG4gICAgICB9O1xuICAgIH1cblxuICAgIC8vIFNldHVwIGZvciB0aGUgJGh0dHBJbnRlcmNlcHRvclxuICAgICRwcm92aWRlLmZhY3RvcnkoJ3JlZGlyZWN0V2hlblNlcnZlckxvZ2dlZE91dCcsIHJlZGlyZWN0V2hlblNlcnZlckxvZ2dlZE91dCk7XG5cbiAgICAvLyBQdXNoIHRoZSBuZXcgZmFjdG9yeSBvbnRvIHRoZSAkaHR0cCBpbnRlcmNlcHRvciBhcnJheVxuICAgICRodHRwUHJvdmlkZXIuaW50ZXJjZXB0b3JzLnB1c2goJ3JlZGlyZWN0V2hlblNlcnZlckxvZ2dlZE91dCcpO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbmZpZyh2YWxpZGF0aW9uSW50ZXJjZXB0b3IpO1xuXG4gIGZ1bmN0aW9uIHZhbGlkYXRpb25JbnRlcmNlcHRvcigkaHR0cFByb3ZpZGVyLCAkcHJvdmlkZSkge1xuICAgIC8qKlxuICAgICAqIEVzdGUgaW50ZXJjZXB0b3Igw6kgcmVzcG9uc8OhdmVsIHBvciBtb3N0cmFyIGFzXG4gICAgICogbWVuc2FnZW5zIGRlIGVycm8gcmVmZXJlbnRlIGFzIHZhbGlkYcOnw7VlcyBkbyBiYWNrLWVuZFxuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9ICRxXG4gICAgICogQHBhcmFtIHthbnl9ICRpbmplY3RvclxuICAgICAqIEByZXR1cm5zXG4gICAgICovXG4gICAgZnVuY3Rpb24gc2hvd0Vycm9yVmFsaWRhdGlvbigkcSwgJGluamVjdG9yKSB7XG4gICAgICByZXR1cm4ge1xuICAgICAgICByZXNwb25zZUVycm9yOiBmdW5jdGlvbiByZXNwb25zZUVycm9yKHJlamVjdGlvbikge1xuICAgICAgICAgIHZhciBQclRvYXN0ID0gJGluamVjdG9yLmdldCgnUHJUb2FzdCcpO1xuICAgICAgICAgIHZhciAkdHJhbnNsYXRlID0gJGluamVjdG9yLmdldCgnJHRyYW5zbGF0ZScpO1xuXG4gICAgICAgICAgaWYgKHJlamVjdGlvbi5jb25maWcuZGF0YSAmJiAhcmVqZWN0aW9uLmNvbmZpZy5kYXRhLnNraXBWYWxpZGF0aW9uKSB7XG4gICAgICAgICAgICBpZiAocmVqZWN0aW9uLmRhdGEgJiYgcmVqZWN0aW9uLmRhdGEuZXJyb3IpIHtcblxuICAgICAgICAgICAgICAvL3ZlcmlmaWNhIHNlIG9jb3JyZXUgYWxndW0gZXJybyByZWZlcmVudGUgYW8gdG9rZW5cbiAgICAgICAgICAgICAgaWYgKHJlamVjdGlvbi5kYXRhLmVycm9yLnN0YXJ0c1dpdGgoJ3Rva2VuXycpKSB7XG4gICAgICAgICAgICAgICAgUHJUb2FzdC53YXJuKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMubG9naW4ubG9nb3V0SW5hY3RpdmUnKSk7XG4gICAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgUHJUb2FzdC5lcnJvcigkdHJhbnNsYXRlLmluc3RhbnQocmVqZWN0aW9uLmRhdGEuZXJyb3IpKTtcbiAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgUHJUb2FzdC5lcnJvclZhbGlkYXRpb24ocmVqZWN0aW9uLmRhdGEpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgIH1cblxuICAgICAgICAgIHJldHVybiAkcS5yZWplY3QocmVqZWN0aW9uKTtcbiAgICAgICAgfVxuICAgICAgfTtcbiAgICB9XG5cbiAgICAvLyBEZWZpbmUgdW1hIGZhY3RvcnkgcGFyYSBvICRodHRwSW50ZXJjZXB0b3JcbiAgICAkcHJvdmlkZS5mYWN0b3J5KCdzaG93RXJyb3JWYWxpZGF0aW9uJywgc2hvd0Vycm9yVmFsaWRhdGlvbik7XG5cbiAgICAvLyBBZGljaW9uYSBhIGZhY3Rvcnkgbm8gYXJyYXkgZGUgaW50ZXJjZXB0b3JzIGRvICRodHRwXG4gICAgJGh0dHBQcm92aWRlci5pbnRlcmNlcHRvcnMucHVzaCgnc2hvd0Vycm9yVmFsaWRhdGlvbicpO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4vKmVzbGludC1lbnYgZXM2Ki9cblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbnRyb2xsZXIoJ01lbnVDb250cm9sbGVyJywgTWVudUNvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gTWVudUNvbnRyb2xsZXIoJG1kU2lkZW5hdiwgJHN0YXRlLCAkbWRDb2xvcnMpIHtcbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgLy9CbG9jbyBkZSBkZWNsYXJhY29lcyBkZSBmdW5jb2VzXG4gICAgdm0ub3BlbiA9IG9wZW47XG4gICAgdm0ub3Blbk1lbnVPclJlZGlyZWN0VG9TdGF0ZSA9IG9wZW5NZW51T3JSZWRpcmVjdFRvU3RhdGU7XG5cbiAgICBhY3RpdmF0ZSgpO1xuXG4gICAgZnVuY3Rpb24gYWN0aXZhdGUoKSB7XG4gICAgICB2YXIgbWVudVByZWZpeCA9ICd2aWV3cy5sYXlvdXQubWVudS4nO1xuXG4gICAgICAvLyBBcnJheSBjb250ZW5kbyBvcyBpdGVucyBxdWUgc8OjbyBtb3N0cmFkb3Mgbm8gbWVudSBsYXRlcmFsXG4gICAgICB2bS5pdGVuc01lbnUgPSBbeyBzdGF0ZTogJ2FwcC5kYXNoYm9hcmQnLCB0aXRsZTogbWVudVByZWZpeCArICdkYXNoYm9hcmQnLCBpY29uOiAnZGFzaGJvYXJkJywgc3ViSXRlbnM6IFtdIH0sIHtcbiAgICAgICAgc3RhdGU6ICcjJywgdGl0bGU6IG1lbnVQcmVmaXggKyAnZXhhbXBsZXMnLCBpY29uOiAndmlld19jYXJvdXNlbCcsIHByb2ZpbGVzOiBbJ2FkbWluJ10sXG4gICAgICAgIHN1Ykl0ZW5zOiBbeyBzdGF0ZTogJ2FwcC5wcm9qZWN0JywgdGl0bGU6IG1lbnVQcmVmaXggKyAncHJvamVjdCcsIGljb246ICdzdGFyJyB9XVxuICAgICAgfSxcbiAgICAgIC8vIENvbG9xdWUgc2V1cyBpdGVucyBkZSBtZW51IGEgcGFydGlyIGRlc3RlIHBvbnRvXG4gICAgICB7XG4gICAgICAgIHN0YXRlOiAnIycsIHRpdGxlOiBtZW51UHJlZml4ICsgJ2FkbWluJywgaWNvbjogJ3NldHRpbmdzX2FwcGxpY2F0aW9ucycsIHByb2ZpbGVzOiBbJ2FkbWluJ10sXG4gICAgICAgIHN1Ykl0ZW5zOiBbeyBzdGF0ZTogJ2FwcC51c2VyJywgdGl0bGU6IG1lbnVQcmVmaXggKyAndXNlcicsIGljb246ICdwZW9wbGUnIH0sIHsgc3RhdGU6ICdhcHAubWFpbCcsIHRpdGxlOiBtZW51UHJlZml4ICsgJ21haWwnLCBpY29uOiAnbWFpbCcgfSwgeyBzdGF0ZTogJ2FwcC5hdWRpdCcsIHRpdGxlOiBtZW51UHJlZml4ICsgJ2F1ZGl0JywgaWNvbjogJ3N0b3JhZ2UnIH0sIHsgc3RhdGU6ICdhcHAuZGluYW1pYy1xdWVyeScsIHRpdGxlOiBtZW51UHJlZml4ICsgJ2RpbmFtaWNRdWVyeScsIGljb246ICdsb2NhdGlvbl9zZWFyY2hpbmcnIH1dXG4gICAgICB9XTtcblxuICAgICAgLyoqXG4gICAgICAgKiBPYmpldG8gcXVlIHByZWVuY2hlIG8gbmctc3R5bGUgZG8gbWVudSBsYXRlcmFsIHRyb2NhbmRvIGFzIGNvcmVzXG4gICAgICAgKi9cbiAgICAgIHZtLnNpZGVuYXZTdHlsZSA9IHtcbiAgICAgICAgdG9wOiB7XG4gICAgICAgICAgJ2JvcmRlci1ib3R0b20nOiAnMXB4IHNvbGlkICcgKyBnZXRDb2xvcigncHJpbWFyeScpLFxuICAgICAgICAgICdiYWNrZ3JvdW5kLWltYWdlJzogJy13ZWJraXQtbGluZWFyLWdyYWRpZW50KHRvcCwgJyArIGdldENvbG9yKCdwcmltYXJ5LTUwMCcpICsgJywgJyArIGdldENvbG9yKCdwcmltYXJ5LTgwMCcpICsgJyknXG4gICAgICAgIH0sXG4gICAgICAgIGNvbnRlbnQ6IHtcbiAgICAgICAgICAnYmFja2dyb3VuZC1jb2xvcic6IGdldENvbG9yKCdwcmltYXJ5LTgwMCcpXG4gICAgICAgIH0sXG4gICAgICAgIHRleHRDb2xvcjoge1xuICAgICAgICAgIGNvbG9yOiAnI0ZGRidcbiAgICAgICAgfSxcbiAgICAgICAgbGluZUJvdHRvbToge1xuICAgICAgICAgICdib3JkZXItYm90dG9tJzogJzFweCBzb2xpZCAnICsgZ2V0Q29sb3IoJ3ByaW1hcnktNDAwJylcbiAgICAgICAgfVxuICAgICAgfTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBvcGVuKCkge1xuICAgICAgJG1kU2lkZW5hdignbGVmdCcpLnRvZ2dsZSgpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIE3DqXRvZG8gcXVlIGV4aWJlIG8gc3ViIG1lbnUgZG9zIGl0ZW5zIGRvIG1lbnUgbGF0ZXJhbCBjYXNvIHRlbmhhIHN1YiBpdGVuc1xuICAgICAqIGNhc28gY29udHLDoXJpbyByZWRpcmVjaW9uYSBwYXJhIG8gc3RhdGUgcGFzc2FkbyBjb21vIHBhcsOibWV0cm9cbiAgICAgKi9cbiAgICBmdW5jdGlvbiBvcGVuTWVudU9yUmVkaXJlY3RUb1N0YXRlKCRtZE1lbnUsIGV2LCBpdGVtKSB7XG4gICAgICBpZiAoYW5ndWxhci5pc0RlZmluZWQoaXRlbS5zdWJJdGVucykgJiYgaXRlbS5zdWJJdGVucy5sZW5ndGggPiAwKSB7XG4gICAgICAgICRtZE1lbnUub3Blbihldik7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICAkc3RhdGUuZ28oaXRlbS5zdGF0ZSk7XG4gICAgICAgICRtZFNpZGVuYXYoJ2xlZnQnKS5jbG9zZSgpO1xuICAgICAgfVxuICAgIH1cblxuICAgIGZ1bmN0aW9uIGdldENvbG9yKGNvbG9yUGFsZXR0ZXMpIHtcbiAgICAgIHJldHVybiAkbWRDb2xvcnMuZ2V0VGhlbWVDb2xvcihjb2xvclBhbGV0dGVzKTtcbiAgICB9XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb250cm9sbGVyKCdNYWlsc0NvbnRyb2xsZXInLCBNYWlsc0NvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gTWFpbHNDb250cm9sbGVyKE1haWxzU2VydmljZSwgVXNlcnNTZXJ2aWNlLCBQckRpYWxvZywgUHJUb2FzdCwgLy8gTk9TT05BUlxuICAkcSwgbG9kYXNoLCAkdHJhbnNsYXRlLCBHbG9iYWwpIHtcblxuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICB2bS5maWx0ZXJTZWxlY3RlZCA9IGZhbHNlO1xuICAgIHZtLm9wdGlvbnMgPSB7XG4gICAgICBza2luOiAna2FtYScsXG4gICAgICBsYW5ndWFnZTogJ3B0LWJyJyxcbiAgICAgIGFsbG93ZWRDb250ZW50OiB0cnVlLFxuICAgICAgZW50aXRpZXM6IHRydWUsXG4gICAgICBoZWlnaHQ6IDMwMCxcbiAgICAgIGV4dHJhUGx1Z2luczogJ2RpYWxvZyxmaW5kLGNvbG9yZGlhbG9nLHByZXZpZXcsZm9ybXMsaWZyYW1lLGZsYXNoJ1xuICAgIH07XG5cbiAgICB2bS5sb2FkVXNlcnMgPSBsb2FkVXNlcnM7XG4gICAgdm0ub3BlblVzZXJEaWFsb2cgPSBvcGVuVXNlckRpYWxvZztcbiAgICB2bS5hZGRVc2VyTWFpbCA9IGFkZFVzZXJNYWlsO1xuICAgIHZtLmNsZWFuRm9ybSA9IGNsZWFuRm9ybTtcbiAgICB2bS5zZW5kID0gc2VuZDtcblxuICAgIGFjdGl2YXRlKCk7XG5cbiAgICBmdW5jdGlvbiBhY3RpdmF0ZSgpIHtcbiAgICAgIHZtLmNsZWFuRm9ybSgpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWxpemEgYSBidXNjYSBwZWxvIHVzdcOhcmlvIHJlbW90YW1lbnRlXG4gICAgICpcbiAgICAgKiBAcGFyYW1zIHtzdHJpbmd9IC0gUmVjZWJlIG8gdmFsb3IgcGFyYSBzZXIgcGVzcXVpc2Fkb1xuICAgICAqIEByZXR1cm4ge3Byb21pc3NlfSAtIFJldG9ybmEgdW1hIHByb21pc3NlIHF1ZSBvIGNvbXBvbmV0ZSByZXNvbHZlXG4gICAgICovXG4gICAgZnVuY3Rpb24gbG9hZFVzZXJzKGNyaXRlcmlhKSB7XG4gICAgICB2YXIgZGVmZXJyZWQgPSAkcS5kZWZlcigpO1xuXG4gICAgICBVc2Vyc1NlcnZpY2UucXVlcnkoe1xuICAgICAgICBuYW1lT3JFbWFpbDogY3JpdGVyaWEsXG4gICAgICAgIG5vdFVzZXJzOiBsb2Rhc2gubWFwKHZtLm1haWwudXNlcnMsIGxvZGFzaC5wcm9wZXJ0eSgnaWQnKSkudG9TdHJpbmcoKSxcbiAgICAgICAgbGltaXQ6IDVcbiAgICAgIH0pLnRoZW4oZnVuY3Rpb24gKGRhdGEpIHtcblxuICAgICAgICAvLyB2ZXJpZmljYSBzZSBuYSBsaXN0YSBkZSB1c3VhcmlvcyBqw6EgZXhpc3RlIG8gdXN1w6FyaW8gY29tIG8gZW1haWwgcGVzcXVpc2Fkb1xuICAgICAgICBkYXRhID0gbG9kYXNoLmZpbHRlcihkYXRhLCBmdW5jdGlvbiAodXNlcikge1xuICAgICAgICAgIHJldHVybiAhbG9kYXNoLmZpbmQodm0ubWFpbC51c2VycywgeyBlbWFpbDogdXNlci5lbWFpbCB9KTtcbiAgICAgICAgfSk7XG5cbiAgICAgICAgZGVmZXJyZWQucmVzb2x2ZShkYXRhKTtcbiAgICAgIH0pO1xuXG4gICAgICByZXR1cm4gZGVmZXJyZWQucHJvbWlzZTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBBYnJlIG8gZGlhbG9nIHBhcmEgcGVzcXVpc2EgZGUgdXN1w6FyaW9zXG4gICAgICovXG4gICAgZnVuY3Rpb24gb3BlblVzZXJEaWFsb2coKSB7XG4gICAgICB2YXIgY29uZmlnID0ge1xuICAgICAgICBsb2NhbHM6IHtcbiAgICAgICAgICBvbkluaXQ6IHRydWUsXG4gICAgICAgICAgdXNlckRpYWxvZ0lucHV0OiB7XG4gICAgICAgICAgICB0cmFuc2ZlclVzZXJGbjogdm0uYWRkVXNlck1haWxcbiAgICAgICAgICB9XG4gICAgICAgIH0sXG4gICAgICAgIGNvbnRyb2xsZXI6ICdVc2Vyc0RpYWxvZ0NvbnRyb2xsZXInLFxuICAgICAgICBjb250cm9sbGVyQXM6ICdjdHJsJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy91c2Vycy9kaWFsb2cvdXNlcnMtZGlhbG9nLmh0bWwnLFxuICAgICAgICBoYXNCYWNrZHJvcDogdHJ1ZVxuICAgICAgfTtcblxuICAgICAgUHJEaWFsb2cuY3VzdG9tKGNvbmZpZyk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQWRpY2lvbmEgbyB1c3XDoXJpbyBzZWxlY2lvbmFkbyBuYSBsaXN0YSBwYXJhIHF1ZSBzZWphIGVudmlhZG8gbyBlbWFpbFxuICAgICAqL1xuICAgIGZ1bmN0aW9uIGFkZFVzZXJNYWlsKHVzZXIpIHtcbiAgICAgIHZhciB1c2VycyA9IGxvZGFzaC5maW5kKHZtLm1haWwudXNlcnMsIHsgZW1haWw6IHVzZXIuZW1haWwgfSk7XG5cbiAgICAgIGlmICh2bS5tYWlsLnVzZXJzLmxlbmd0aCA+IDAgJiYgYW5ndWxhci5pc0RlZmluZWQodXNlcnMpKSB7XG4gICAgICAgIFByVG9hc3Qud2FybigkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnVzZXIudXNlckV4aXN0cycpKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHZtLm1haWwudXNlcnMucHVzaCh7IG5hbWU6IHVzZXIubmFtZSwgZW1haWw6IHVzZXIuZW1haWwgfSk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhbGl6YSBvIGVudmlvIGRvIGVtYWlsIHBhcmEgYSBsaXN0YSBkZSB1c3XDoXJpb3Mgc2VsZWNpb25hZG9zXG4gICAgICovXG4gICAgZnVuY3Rpb24gc2VuZCgpIHtcblxuICAgICAgdm0ubWFpbC4kc2F2ZSgpLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgIGlmIChyZXNwb25zZS5sZW5ndGggPiAwKSB7XG4gICAgICAgICAgdmFyIG1zZyA9ICR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMubWFpbC5tYWlsRXJyb3JzJyk7XG5cbiAgICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IHJlc3BvbnNlLmxlbmd0aDsgaSsrKSB7XG4gICAgICAgICAgICBtc2cgKz0gcmVzcG9uc2UgKyAnXFxuJztcbiAgICAgICAgICB9XG4gICAgICAgICAgUHJUb2FzdC5lcnJvcihtc2cpO1xuICAgICAgICAgIHZtLmNsZWFuRm9ybSgpO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIFByVG9hc3Quc3VjY2VzcygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLm1haWwuc2VuZE1haWxTdWNjZXNzJykpO1xuICAgICAgICAgIHZtLmNsZWFuRm9ybSgpO1xuICAgICAgICB9XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBMaW1wYSBvIGZvcm11bMOhcmlvIGRlIGVtYWlsXG4gICAgICovXG4gICAgZnVuY3Rpb24gY2xlYW5Gb3JtKCkge1xuICAgICAgdm0ubWFpbCA9IG5ldyBNYWlsc1NlcnZpY2UoKTtcbiAgICAgIHZtLm1haWwudXNlcnMgPSBbXTtcbiAgICB9XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqXG4gICAqIEFycXVpdm8gZGUgY29uZmlndXJhw6fDo28gY29tIGFzIHJvdGFzIGVzcGVjw61maWNhcyBkbyByZWN1cnNvIGVtIHF1ZXN0w6NvXG4gICAqXG4gICAqIEBwYXJhbSB7YW55fSAkc3RhdGVQcm92aWRlclxuICAgKiBAcGFyYW0ge2FueX0gR2xvYmFsXG4gICAqL1xuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvdXRlcygkc3RhdGVQcm92aWRlciwgR2xvYmFsKSB7XG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ2FwcC5tYWlsJywge1xuICAgICAgdXJsOiAnL2VtYWlsJyxcbiAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvbWFpbC9tYWlscy1zZW5kLmh0bWwnLFxuICAgICAgY29udHJvbGxlcjogJ01haWxzQ29udHJvbGxlciBhcyBtYWlsc0N0cmwnLFxuICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IHRydWUsIG5lZWRQcm9maWxlOiBbJ2FkbWluJ10gfVxuICAgIH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZhY3RvcnkoJ01haWxzU2VydmljZScsIE1haWxzU2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBNYWlsc1NlcnZpY2Uoc2VydmljZUZhY3RvcnkpIHtcbiAgICByZXR1cm4gc2VydmljZUZhY3RvcnkoJ21haWxzJywge30pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmlsdGVyKCdyb2xlc1N0cicsIHJvbGVzU3RyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvbGVzU3RyKGxvZGFzaCkge1xuICAgIC8qKlxuICAgICAqIEBwYXJhbSB7YXJyYXl9IHJvbGVzIGxpc3RhIGRlIHBlcmZpc1xuICAgICAqIEByZXR1cm4ge3N0cmluZ30gcGVyZmlzIHNlcGFyYWRvcyBwb3IgJywgJyAgXG4gICAgICovXG4gICAgcmV0dXJuIGZ1bmN0aW9uIChyb2xlcykge1xuICAgICAgcmV0dXJuIGxvZGFzaC5tYXAocm9sZXMsICdzbHVnJykuam9pbignLCAnKTtcbiAgICB9O1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZhY3RvcnkoJ1JvbGVzU2VydmljZScsIFJvbGVzU2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiBSb2xlc1NlcnZpY2Uoc2VydmljZUZhY3RvcnkpIHtcbiAgICByZXR1cm4gc2VydmljZUZhY3RvcnkoJ3JvbGVzJyk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmFjdG9yeSgnU3VwcG9ydFNlcnZpY2UnLCBTdXBwb3J0U2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiBTdXBwb3J0U2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHJldHVybiBzZXJ2aWNlRmFjdG9yeSgnc3VwcG9ydCcsIHtcbiAgICAgIGFjdGlvbnM6IHtcbiAgICAgICAgLyoqXG4gICAgICAgICAqIFBlZ2EgYXMgdHJhZHXDp8O1ZXMgcXVlIGVzdMOjbyBubyBzZXJ2aWRvclxuICAgICAgICAgKlxuICAgICAgICAgKiBAcmV0dXJucyB7cHJvbWlzZX0gVW1hIHByb21pc2UgY29tIG8gcmVzdWx0YWRvIGRvIGNoYW1hZGEgbm8gYmFja2VuZFxuICAgICAgICAgKi9cbiAgICAgICAgbGFuZ3M6IHtcbiAgICAgICAgICBtZXRob2Q6ICdHRVQnLFxuICAgICAgICAgIHVybDogJ2xhbmdzJyxcbiAgICAgICAgICB3cmFwOiBmYWxzZSxcbiAgICAgICAgICBjYWNoZTogdHJ1ZVxuICAgICAgICB9XG4gICAgICB9XG4gICAgfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb250cm9sbGVyKCdQcm9maWxlQ29udHJvbGxlcicsIFByb2ZpbGVDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIFByb2ZpbGVDb250cm9sbGVyKFVzZXJzU2VydmljZSwgQXV0aCwgUHJUb2FzdCwgJHRyYW5zbGF0ZSkge1xuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICB2bS51cGRhdGUgPSB1cGRhdGU7XG5cbiAgICBhY3RpdmF0ZSgpO1xuXG4gICAgZnVuY3Rpb24gYWN0aXZhdGUoKSB7XG4gICAgICB2bS51c2VyID0gYW5ndWxhci5jb3B5KEF1dGguY3VycmVudFVzZXIpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIHVwZGF0ZSgpIHtcbiAgICAgIFVzZXJzU2VydmljZS51cGRhdGVQcm9maWxlKHZtLnVzZXIpLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgIC8vYXR1YWxpemEgbyB1c3XDoXJpbyBjb3JyZW50ZSBjb20gYXMgbm92YXMgaW5mb3JtYcOnw7Vlc1xuICAgICAgICBBdXRoLnVwZGF0ZUN1cnJlbnRVc2VyKHJlc3BvbnNlKTtcbiAgICAgICAgUHJUb2FzdC5zdWNjZXNzKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMuc2F2ZVN1Y2Nlc3MnKSk7XG4gICAgICB9KTtcbiAgICB9XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb250cm9sbGVyKCdVc2Vyc0NvbnRyb2xsZXInLCBVc2Vyc0NvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gVXNlcnNDb250cm9sbGVyKCRjb250cm9sbGVyLCBsb2Rhc2gsIFVzZXJzU2VydmljZSwgUm9sZXNTZXJ2aWNlLCAvLyBOT1NPTkFSXG4gIFByVG9hc3QsIEF1dGgsICR0cmFuc2xhdGUpIHtcblxuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICB2bS5vbkFjdGl2YXRlID0gb25BY3RpdmF0ZTtcbiAgICB2bS5hcHBseUZpbHRlcnMgPSBhcHBseUZpbHRlcnM7XG4gICAgdm0uYWZ0ZXJFZGl0ID0gYWZ0ZXJFZGl0O1xuICAgIHZtLmFmdGVyQ2xlYW4gPSBhZnRlckNsZWFuO1xuICAgIHZtLmJlZm9yZVNhdmUgPSBiZWZvcmVTYXZlO1xuICAgIHZtLmFmdGVyU2F2ZSA9IGFmdGVyU2F2ZTtcbiAgICB2bS5iZWZvcmVSZW1vdmUgPSBiZWZvcmVSZW1vdmU7XG5cbiAgICAvLyBpbnN0YW50aWF0ZSBiYXNlIGNvbnRyb2xsZXJcbiAgICAkY29udHJvbGxlcignQ1JVRENvbnRyb2xsZXInLCB7IHZtOiB2bSwgbW9kZWxTZXJ2aWNlOiBVc2Vyc1NlcnZpY2UsIG9wdGlvbnM6IHt9IH0pO1xuXG4gICAgZnVuY3Rpb24gb25BY3RpdmF0ZSgpIHtcbiAgICAgIHZtLnF1ZXJ5RmlsdGVycyA9IHt9O1xuXG4gICAgICB2bS5yb2xlcyA9IFJvbGVzU2VydmljZS5xdWVyeSgpLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgIHZtLnJvbGVzID0gcmVzcG9uc2U7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBhcHBseUZpbHRlcnMoZGVmYXVsdFF1ZXJ5RmlsdGVycykge1xuICAgICAgcmV0dXJuIGFuZ3VsYXIuZXh0ZW5kKGRlZmF1bHRRdWVyeUZpbHRlcnMsIHZtLnF1ZXJ5RmlsdGVycyk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gYWZ0ZXJDbGVhbigpIHtcbiAgICAgIHZtLnJvbGVzLmZvckVhY2goZnVuY3Rpb24gKHJvbGUpIHtcbiAgICAgICAgcm9sZS5zZWxlY3RlZCA9IGZhbHNlO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gYWZ0ZXJFZGl0KCkge1xuICAgICAgdm0ucm9sZXMuZm9yRWFjaChmdW5jdGlvbiAocm9sZSkge1xuICAgICAgICB2bS5yZXNvdXJjZS5yb2xlcy5mb3JFYWNoKGZ1bmN0aW9uIChyb2xlVXNlcikge1xuICAgICAgICAgIGlmIChyb2xlLmlkID09PSByb2xlVXNlci5pZCkge1xuICAgICAgICAgICAgcm9sZS5zZWxlY3RlZCA9IHRydWU7XG4gICAgICAgICAgfVxuICAgICAgICB9KTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGJlZm9yZVNhdmUoKSB7XG4gICAgICAvL2ZpbHRyYSBvIGFycmF5IGRlIHJvbGVzIHBhcmEgZXh0cmFpciBzb21lbnRlIG9zIGlkc1xuICAgICAgdm0ucmVzb3VyY2Uucm9sZXMgPSBsb2Rhc2gubWFwKGxvZGFzaC5maWx0ZXIoYW5ndWxhci5jb3B5KHZtLnJvbGVzKSwgeyBzZWxlY3RlZDogdHJ1ZSB9KSwgZnVuY3Rpb24gKHJvbGUpIHtcbiAgICAgICAgcmV0dXJuIHsgaWQ6IHJvbGUuaWQgfTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGFmdGVyU2F2ZShyZXNvdXJjZSkge1xuICAgICAgaWYgKHZtLnJlc291cmNlLmlkID09PSBBdXRoLmN1cnJlbnRVc2VyLmlkKSB7XG4gICAgICAgIEF1dGgudXBkYXRlQ3VycmVudFVzZXIocmVzb3VyY2UpO1xuICAgICAgfVxuICAgIH1cblxuICAgIGZ1bmN0aW9uIGJlZm9yZVJlbW92ZShyZXNvdXJjZSkge1xuICAgICAgaWYgKHJlc291cmNlLmlkID09PSBBdXRoLmN1cnJlbnRVc2VyLmlkKSB7XG4gICAgICAgIFByVG9hc3QuZXJyb3IoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy51c2VyLnJlbW92ZVlvdXJTZWxmRXJyb3InKSk7XG4gICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgIH1cbiAgICB9XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqXG4gICAqIEFycXVpdm8gZGUgY29uZmlndXJhw6fDo28gY29tIGFzIHJvdGFzIGVzcGVjw61maWNhcyBkbyByZWN1cnNvIHVzZXJcbiAgICpcbiAgICogQHBhcmFtIHthbnl9ICRzdGF0ZVByb3ZpZGVyXG4gICAqIEBwYXJhbSB7YW55fSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnYXBwLnVzZXInLCB7XG4gICAgICB1cmw6ICcvdXN1YXJpbycsXG4gICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL3VzZXJzL3VzZXJzLmh0bWwnLFxuICAgICAgY29udHJvbGxlcjogJ1VzZXJzQ29udHJvbGxlciBhcyB1c2Vyc0N0cmwnLFxuICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IHRydWUsIG5lZWRQcm9maWxlOiBbJ2FkbWluJ10gfVxuICAgIH0pLnN0YXRlKCdhcHAudXNlci1wcm9maWxlJywge1xuICAgICAgdXJsOiAnL3VzdWFyaW8vcGVyZmlsJyxcbiAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvdXNlcnMvcHJvZmlsZS5odG1sJyxcbiAgICAgIGNvbnRyb2xsZXI6ICdQcm9maWxlQ29udHJvbGxlciBhcyBwcm9maWxlQ3RybCcsXG4gICAgICBkYXRhOiB7IG5lZWRBdXRoZW50aWNhdGlvbjogdHJ1ZSB9XG4gICAgfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmFjdG9yeSgnVXNlcnNTZXJ2aWNlJywgVXNlcnNTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIFVzZXJzU2VydmljZShsb2Rhc2gsIEdsb2JhbCwgc2VydmljZUZhY3RvcnkpIHtcbiAgICByZXR1cm4gc2VydmljZUZhY3RvcnkoJ3VzZXJzJywge1xuICAgICAgLy9xdWFuZG8gaW5zdGFuY2lhIHVtIHVzdcOhcmlvIHNlbSBwYXNzYXIgcGFyYW1ldHJvLFxuICAgICAgLy9vIG1lc21vIHZhaSB0ZXIgb3MgdmFsb3JlcyBkZWZhdWx0cyBhYmFpeG9cbiAgICAgIGRlZmF1bHRzOiB7XG4gICAgICAgIHJvbGVzOiBbXVxuICAgICAgfSxcblxuICAgICAgYWN0aW9uczoge1xuICAgICAgICAvKipcbiAgICAgICAgICogU2VydmnDp28gcXVlIGF0dWFsaXphIG9zIGRhZG9zIGRvIHBlcmZpbCBkbyB1c3XDoXJpbyBsb2dhZG9cbiAgICAgICAgICpcbiAgICAgICAgICogQHBhcmFtIHtvYmplY3R9IGF0dHJpYnV0ZXNcbiAgICAgICAgICogQHJldHVybnMge3Byb21pc2V9IFVtYSBwcm9taXNlIGNvbSBvIHJlc3VsdGFkbyBkbyBjaGFtYWRhIG5vIGJhY2tlbmRcbiAgICAgICAgICovXG4gICAgICAgIHVwZGF0ZVByb2ZpbGU6IHtcbiAgICAgICAgICBtZXRob2Q6ICdQVVQnLFxuICAgICAgICAgIHVybDogR2xvYmFsLmFwaVBhdGggKyAnL3Byb2ZpbGUnLFxuICAgICAgICAgIG92ZXJyaWRlOiB0cnVlLFxuICAgICAgICAgIHdyYXA6IGZhbHNlXG4gICAgICAgIH1cbiAgICAgIH0sXG5cbiAgICAgIGluc3RhbmNlOiB7XG4gICAgICAgIC8qKlxuICAgICAgICAgKiBWZXJpZmljYSBzZSBvIHVzdcOhcmlvIHRlbSBvcyBwZXJmaXMgaW5mb3JtYWRvcy5cbiAgICAgICAgICpcbiAgICAgICAgICogQHBhcmFtIHthbnl9IHJvbGVzIHBlcmZpcyBhIHNlcmVtIHZlcmlmaWNhZG9zXG4gICAgICAgICAqIEBwYXJhbSB7Ym9vbGVhbn0gYWxsIGZsYWcgcGFyYSBpbmRpY2FyIHNlIHZhaSBjaGVnYXIgdG9kb3Mgb3MgcGVyZmlzIG91IHNvbWVudGUgdW0gZGVsZXNcbiAgICAgICAgICogQHJldHVybnMge2Jvb2xlYW59XG4gICAgICAgICAqL1xuICAgICAgICBoYXNQcm9maWxlOiBmdW5jdGlvbiBoYXNQcm9maWxlKHJvbGVzLCBhbGwpIHtcbiAgICAgICAgICByb2xlcyA9IGFuZ3VsYXIuaXNBcnJheShyb2xlcykgPyByb2xlcyA6IFtyb2xlc107XG5cbiAgICAgICAgICB2YXIgdXNlclJvbGVzID0gbG9kYXNoLm1hcCh0aGlzLnJvbGVzLCAnc2x1ZycpO1xuXG4gICAgICAgICAgaWYgKGFsbCkge1xuICAgICAgICAgICAgcmV0dXJuIGxvZGFzaC5pbnRlcnNlY3Rpb24odXNlclJvbGVzLCByb2xlcykubGVuZ3RoID09PSByb2xlcy5sZW5ndGg7XG4gICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIC8vcmV0dXJuIHRoZSBsZW5ndGggYmVjYXVzZSAwIGlzIGZhbHNlIGluIGpzXG4gICAgICAgICAgICByZXR1cm4gbG9kYXNoLmludGVyc2VjdGlvbih1c2VyUm9sZXMsIHJvbGVzKS5sZW5ndGg7XG4gICAgICAgICAgfVxuICAgICAgICB9LFxuXG4gICAgICAgIC8qKlxuICAgICAgICAgKiBWZXJpZmljYSBzZSBvIHVzdcOhcmlvIHRlbSBvIHBlcmZpbCBhZG1pbi5cbiAgICAgICAgICpcbiAgICAgICAgICogQHJldHVybnMge2Jvb2xlYW59XG4gICAgICAgICAqL1xuICAgICAgICBpc0FkbWluOiBmdW5jdGlvbiBpc0FkbWluKCkge1xuICAgICAgICAgIHJldHVybiB0aGlzLmhhc1Byb2ZpbGUoJ2FkbWluJyk7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29tcG9uZW50KCdib3gnLCB7XG4gICAgcmVwbGFjZTogdHJ1ZSxcbiAgICB0ZW1wbGF0ZVVybDogWydHbG9iYWwnLCBmdW5jdGlvbiAoR2xvYmFsKSB7XG4gICAgICByZXR1cm4gR2xvYmFsLmNsaWVudFBhdGggKyAnL3dpZGdldHMvYm94Lmh0bWwnO1xuICAgIH1dLFxuICAgIHRyYW5zY2x1ZGU6IHtcbiAgICAgIHRvb2xiYXJCdXR0b25zOiAnP2JveFRvb2xiYXJCdXR0b25zJyxcbiAgICAgIGZvb3RlckJ1dHRvbnM6ICc/Ym94Rm9vdGVyQnV0dG9ucydcbiAgICB9LFxuICAgIGJpbmRpbmdzOiB7XG4gICAgICBib3hUaXRsZTogJ0AnLFxuICAgICAgdG9vbGJhckNsYXNzOiAnQCcsXG4gICAgICB0b29sYmFyQmdDb2xvcjogJ0AnXG4gICAgfSxcbiAgICBjb250cm9sbGVyOiBbJyR0cmFuc2NsdWRlJywgZnVuY3Rpb24gKCR0cmFuc2NsdWRlKSB7XG4gICAgICB2YXIgY3RybCA9IHRoaXM7XG5cbiAgICAgIGN0cmwudHJhbnNjbHVkZSA9ICR0cmFuc2NsdWRlO1xuXG4gICAgICBjdHJsLiRvbkluaXQgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgIGlmIChhbmd1bGFyLmlzVW5kZWZpbmVkKGN0cmwudG9vbGJhckJnQ29sb3IpKSBjdHJsLnRvb2xiYXJCZ0NvbG9yID0gJ2RlZmF1bHQtcHJpbWFyeSc7XG4gICAgICB9O1xuICAgIH1dXG4gIH0pO1xufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29tcG9uZW50KCdjb250ZW50Qm9keScsIHtcbiAgICByZXBsYWNlOiB0cnVlLFxuICAgIHRyYW5zY2x1ZGU6IHRydWUsXG4gICAgdGVtcGxhdGVVcmw6IFsnR2xvYmFsJywgZnVuY3Rpb24gKEdsb2JhbCkge1xuICAgICAgcmV0dXJuIEdsb2JhbC5jbGllbnRQYXRoICsgJy93aWRnZXRzL2NvbnRlbnQtYm9keS5odG1sJztcbiAgICB9XSxcbiAgICBiaW5kaW5nczoge1xuICAgICAgbGF5b3V0QWxpZ246ICdAJ1xuICAgIH0sXG4gICAgY29udHJvbGxlcjogW2Z1bmN0aW9uICgpIHtcbiAgICAgIHZhciBjdHJsID0gdGhpcztcblxuICAgICAgY3RybC4kb25Jbml0ID0gZnVuY3Rpb24gKCkge1xuICAgICAgICAvLyBNYWtlIGEgY29weSBvZiB0aGUgaW5pdGlhbCB2YWx1ZSB0byBiZSBhYmxlIHRvIHJlc2V0IGl0IGxhdGVyXG4gICAgICAgIGN0cmwubGF5b3V0QWxpZ24gPSBhbmd1bGFyLmlzRGVmaW5lZChjdHJsLmxheW91dEFsaWduKSA/IGN0cmwubGF5b3V0QWxpZ24gOiAnY2VudGVyIHN0YXJ0JztcbiAgICAgIH07XG4gICAgfV1cbiAgfSk7XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb21wb25lbnQoJ2NvbnRlbnRIZWFkZXInLCB7XG4gICAgdGVtcGxhdGVVcmw6IFsnR2xvYmFsJywgZnVuY3Rpb24gKEdsb2JhbCkge1xuICAgICAgcmV0dXJuIEdsb2JhbC5jbGllbnRQYXRoICsgJy93aWRnZXRzL2NvbnRlbnQtaGVhZGVyLmh0bWwnO1xuICAgIH1dLFxuICAgIHJlcGxhY2U6IHRydWUsXG4gICAgYmluZGluZ3M6IHtcbiAgICAgIHRpdGxlOiAnQCcsXG4gICAgICBkZXNjcmlwdGlvbjogJ0AnXG4gICAgfVxuICB9KTtcbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5maWx0ZXIoJ2F1ZGl0RGV0YWlsVGl0bGUnLCBhdWRpdERldGFpbFRpdGxlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIGF1ZGl0RGV0YWlsVGl0bGUoJHRyYW5zbGF0ZSkge1xuICAgIHJldHVybiBmdW5jdGlvbiAoYXVkaXREZXRhaWwsIHN0YXR1cykge1xuICAgICAgaWYgKGF1ZGl0RGV0YWlsLnR5cGUgPT09ICd1cGRhdGVkJykge1xuICAgICAgICBpZiAoc3RhdHVzID09PSAnYmVmb3JlJykge1xuICAgICAgICAgIHJldHVybiAkdHJhbnNsYXRlLmluc3RhbnQoJ2RpYWxvZy5hdWRpdC51cGRhdGVkQmVmb3JlJyk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgcmV0dXJuICR0cmFuc2xhdGUuaW5zdGFudCgnZGlhbG9nLmF1ZGl0LnVwZGF0ZWRBZnRlcicpO1xuICAgICAgICB9XG4gICAgICB9IGVsc2Uge1xuICAgICAgICByZXR1cm4gJHRyYW5zbGF0ZS5pbnN0YW50KCdkaWFsb2cuYXVkaXQuJyArIGF1ZGl0RGV0YWlsLnR5cGUpO1xuICAgICAgfVxuICAgIH07XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5maWx0ZXIoJ2F1ZGl0TW9kZWwnLCBhdWRpdE1vZGVsKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIGF1ZGl0TW9kZWwoJHRyYW5zbGF0ZSkge1xuICAgIHJldHVybiBmdW5jdGlvbiAobW9kZWxJZCkge1xuICAgICAgbW9kZWxJZCA9IG1vZGVsSWQucmVwbGFjZSgnQXBwXFxcXCcsICcnKTtcbiAgICAgIHZhciBtb2RlbCA9ICR0cmFuc2xhdGUuaW5zdGFudCgnbW9kZWxzLicgKyBtb2RlbElkLnRvTG93ZXJDYXNlKCkpO1xuXG4gICAgICByZXR1cm4gbW9kZWwgPyBtb2RlbCA6IG1vZGVsSWQ7XG4gICAgfTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZpbHRlcignYXVkaXRUeXBlJywgYXVkaXRUeXBlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIGF1ZGl0VHlwZShsb2Rhc2gsIEF1ZGl0U2VydmljZSkge1xuICAgIHJldHVybiBmdW5jdGlvbiAodHlwZUlkKSB7XG4gICAgICB2YXIgdHlwZSA9IGxvZGFzaC5maW5kKEF1ZGl0U2VydmljZS5saXN0VHlwZXMoKSwgeyBpZDogdHlwZUlkIH0pO1xuXG4gICAgICByZXR1cm4gdHlwZSA/IHR5cGUubGFiZWwgOiB0eXBlO1xuICAgIH07XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5maWx0ZXIoJ2F1ZGl0VmFsdWUnLCBhdWRpdFZhbHVlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIGF1ZGl0VmFsdWUoJGZpbHRlciwgbG9kYXNoKSB7XG4gICAgcmV0dXJuIGZ1bmN0aW9uICh2YWx1ZSwga2V5KSB7XG4gICAgICBpZiAoYW5ndWxhci5pc0RhdGUodmFsdWUpIHx8IGxvZGFzaC5lbmRzV2l0aChrZXksICdfYXQnKSB8fCBsb2Rhc2guZW5kc1dpdGgoa2V5LCAnX3RvJykpIHtcbiAgICAgICAgcmV0dXJuICRmaWx0ZXIoJ3ByRGF0ZXRpbWUnKSh2YWx1ZSk7XG4gICAgICB9XG5cbiAgICAgIGlmICh0eXBlb2YgdmFsdWUgPT09ICdib29sZWFuJykge1xuICAgICAgICByZXR1cm4gJGZpbHRlcigndHJhbnNsYXRlJykodmFsdWUgPyAnZ2xvYmFsLnllcycgOiAnZ2xvYmFsLm5vJyk7XG4gICAgICB9XG5cbiAgICAgIC8vY2hlY2sgaXMgZmxvYXRcbiAgICAgIGlmIChOdW1iZXIodmFsdWUpID09PSB2YWx1ZSAmJiB2YWx1ZSAlIDEgIT09IDApIHtcbiAgICAgICAgcmV0dXJuICRmaWx0ZXIoJ3JlYWwnKSh2YWx1ZSk7XG4gICAgICB9XG5cbiAgICAgIHJldHVybiB2YWx1ZTtcbiAgICB9O1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4vKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCwgbm8tdW5kZWY6IDAqL1xuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25zdGFudCgncHQtQlIuaTE4bi5hdHRyaWJ1dGVzJywge1xuICAgIGVtYWlsOiAnRW1haWwnLFxuICAgIHBhc3N3b3JkOiAnU2VuaGEnLFxuICAgIG5hbWU6ICdOb21lJyxcbiAgICBpbWFnZTogJ0ltYWdlbScsXG4gICAgcm9sZXM6ICdQZXJmaXMnLFxuICAgIGRhdGU6ICdEYXRhJyxcbiAgICBpbml0aWFsRGF0ZTogJ0RhdGEgSW5pY2lhbCcsXG4gICAgZmluYWxEYXRlOiAnRGF0YSBGaW5hbCcsXG4gICAgdGFzazoge1xuICAgICAgZGVzY3JpcHRpb246ICdEZXNjcmnDp8OjbycsXG4gICAgICBkb25lOiAnRmVpdG8/JyxcbiAgICAgIHByaW9yaXR5OiAnUHJpb3JpZGFkZScsXG4gICAgICBzY2hlZHVsZWRfdG86ICdBZ2VuZGFkbyBQYXJhPycsXG4gICAgICBwcm9qZWN0OiAnUHJvamV0bydcbiAgICB9LFxuICAgIHByb2plY3Q6IHtcbiAgICAgIGNvc3Q6ICdDdXN0bydcbiAgICB9LFxuICAgIC8vw6kgY2FycmVnYWRvIGRvIHNlcnZpZG9yIGNhc28gZXN0ZWphIGRlZmluaWRvIG5vIG1lc21vXG4gICAgYXVkaXRNb2RlbDoge31cbiAgfSk7XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4vKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCwgbm8tdW5kZWY6IDAqL1xuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25zdGFudCgncHQtQlIuaTE4bi5kaWFsb2cnLCB7XG4gICAgY29uZmlybVRpdGxlOiAnQ29uZmlybWHDp8OjbycsXG4gICAgY29uZmlybURlc2NyaXB0aW9uOiAnQ29uZmlybWEgYSBhw6fDo28/JyxcbiAgICByZW1vdmVEZXNjcmlwdGlvbjogJ0Rlc2VqYSByZW1vdmVyIHBlcm1hbmVudGVtZW50ZSB7e25hbWV9fT8nLFxuICAgIGF1ZGl0OiB7XG4gICAgICBjcmVhdGVkOiAnSW5mb3JtYcOnw7VlcyBkbyBDYWRhc3RybycsXG4gICAgICB1cGRhdGVkQmVmb3JlOiAnQW50ZXMgZGEgQXR1YWxpemHDp8OjbycsXG4gICAgICB1cGRhdGVkQWZ0ZXI6ICdEZXBvaXMgZGEgQXR1YWxpemHDp8OjbycsXG4gICAgICBkZWxldGVkOiAnSW5mb3JtYcOnw7VlcyBhbnRlcyBkZSByZW1vdmVyJ1xuICAgIH0sXG4gICAgbG9naW46IHtcbiAgICAgIHJlc2V0UGFzc3dvcmQ6IHtcbiAgICAgICAgZGVzY3JpcHRpb246ICdEaWdpdGUgYWJhaXhvIG8gZW1haWwgY2FkYXN0cmFkbyBubyBzaXN0ZW1hLidcbiAgICAgIH1cbiAgICB9XG4gIH0pO1xufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuLyplc2xpbnQgYW5ndWxhci9maWxlLW5hbWU6IDAsIG5vLXVuZGVmOiAwKi9cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29uc3RhbnQoJ3B0LUJSLmkxOG4uZ2xvYmFsJywge1xuICAgIGxvYWRpbmc6ICdDYXJyZWdhbmRvLi4uJyxcbiAgICBwcm9jZXNzaW5nOiAnUHJvY2Vzc2FuZG8uLi4nLFxuICAgIHllczogJ1NpbScsXG4gICAgbm86ICdOw6NvJyxcbiAgICBhbGw6ICdUb2RvcydcbiAgfSk7XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4vKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCwgbm8tdW5kZWY6IDAqL1xuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25zdGFudCgncHQtQlIuaTE4bi5tZXNzYWdlcycsIHtcbiAgICBpbnRlcm5hbEVycm9yOiAnT2NvcnJldSB1bSBlcnJvIGludGVybm8sIGNvbnRhdGUgbyBhZG1pbmlzdHJhZG9yIGRvIHNpc3RlbWEnLFxuICAgIG5vdEZvdW5kOiAnTmVuaHVtIHJlZ2lzdHJvIGVuY29udHJhZG8nLFxuICAgIG5vdEF1dGhvcml6ZWQ6ICdWb2PDqiBuw6NvIHRlbSBhY2Vzc28gYSBlc3RhIGZ1bmNpb25hbGlkYWRlLicsXG4gICAgc2VhcmNoRXJyb3I6ICdOw6NvIGZvaSBwb3Nzw612ZWwgcmVhbGl6YXIgYSBidXNjYS4nLFxuICAgIHNhdmVTdWNjZXNzOiAnUmVnaXN0cm8gc2Fsdm8gY29tIHN1Y2Vzc28uJyxcbiAgICBvcGVyYXRpb25TdWNjZXNzOiAnT3BlcmHDp8OjbyByZWFsaXphZGEgY29tIHN1Y2Vzc28uJyxcbiAgICBvcGVyYXRpb25FcnJvcjogJ0Vycm8gYW8gcmVhbGl6YXIgYSBvcGVyYcOnw6NvJyxcbiAgICBzYXZlRXJyb3I6ICdFcnJvIGFvIHRlbnRhciBzYWx2YXIgbyByZWdpc3Ryby4nLFxuICAgIHJlbW92ZVN1Y2Nlc3M6ICdSZW1vw6fDo28gcmVhbGl6YWRhIGNvbSBzdWNlc3NvLicsXG4gICAgcmVtb3ZlRXJyb3I6ICdFcnJvIGFvIHRlbnRhciByZW1vdmVyIG8gcmVnaXN0cm8uJyxcbiAgICByZXNvdXJjZU5vdEZvdW5kRXJyb3I6ICdSZWN1cnNvIG7Do28gZW5jb250cmFkbycsXG4gICAgbm90TnVsbEVycm9yOiAnVG9kb3Mgb3MgY2FtcG9zIG9icmlnYXTDs3Jpb3MgZGV2ZW0gc2VyIHByZWVuY2hpZG9zLicsXG4gICAgZHVwbGljYXRlZFJlc291cmNlRXJyb3I6ICdKw6EgZXhpc3RlIHVtIHJlY3Vyc28gY29tIGVzc2FzIGluZm9ybWHDp8O1ZXMuJyxcbiAgICB2YWxpZGF0ZToge1xuICAgICAgZmllbGRSZXF1aXJlZDogJ08gY2FtcG8ge3tmaWVsZH19IMOpIG9icmlncmF0w7NyaW8uJ1xuICAgIH0sXG4gICAgbGF5b3V0OiB7XG4gICAgICBlcnJvcjQwNDogJ1DDoWdpbmEgbsOjbyBlbmNvbnRyYWRhJ1xuICAgIH0sXG4gICAgbG9naW46IHtcbiAgICAgIGxvZ291dEluYWN0aXZlOiAnVm9jw6ogZm9pIGRlc2xvZ2FkbyBkbyBzaXN0ZW1hIHBvciBpbmF0aXZpZGFkZS4gRmF2b3IgZW50cmFyIG5vIHNpc3RlbWEgbm92YW1lbnRlLicsXG4gICAgICBpbnZhbGlkQ3JlZGVudGlhbHM6ICdDcmVkZW5jaWFpcyBJbnbDoWxpZGFzJyxcbiAgICAgIHVua25vd25FcnJvcjogJ07Do28gZm9pIHBvc3PDrXZlbCByZWFsaXphciBvIGxvZ2luLiBUZW50ZSBub3ZhbWVudGUuICcgKyAnQ2FzbyBuw6NvIGNvbnNpZ2EgZmF2b3IgZW5jb250cmFyIGVtIGNvbnRhdG8gY29tIG8gYWRtaW5pc3RyYWRvciBkbyBzaXN0ZW1hLicsXG4gICAgICB1c2VyTm90Rm91bmQ6ICdOw6NvIGZvaSBwb3Nzw612ZWwgZW5jb250cmFyIHNldXMgZGFkb3MnXG4gICAgfSxcbiAgICBkYXNoYm9hcmQ6IHtcbiAgICAgIHdlbGNvbWU6ICdTZWphIGJlbSBWaW5kbyB7e3VzZXJOYW1lfX0nLFxuICAgICAgZGVzY3JpcHRpb246ICdVdGlsaXplIG8gbWVudSBwYXJhIG5hdmVnYcOnw6NvLidcbiAgICB9LFxuICAgIG1haWw6IHtcbiAgICAgIG1haWxFcnJvcnM6ICdPY29ycmV1IHVtIGVycm8gbm9zIHNlZ3VpbnRlcyBlbWFpbHMgYWJhaXhvOlxcbicsXG4gICAgICBzZW5kTWFpbFN1Y2Nlc3M6ICdFbWFpbCBlbnZpYWRvIGNvbSBzdWNlc3NvIScsXG4gICAgICBzZW5kTWFpbEVycm9yOiAnTsOjbyBmb2kgcG9zc8OtdmVsIGVudmlhciBvIGVtYWlsLicsXG4gICAgICBwYXNzd29yZFNlbmRpbmdTdWNjZXNzOiAnTyBwcm9jZXNzbyBkZSByZWN1cGVyYcOnw6NvIGRlIHNlbmhhIGZvaSBpbmljaWFkby4gQ2FzbyBvIGVtYWlsIG7Do28gY2hlZ3VlIGVtIDEwIG1pbnV0b3MgdGVudGUgbm92YW1lbnRlLidcbiAgICB9LFxuICAgIHVzZXI6IHtcbiAgICAgIHJlbW92ZVlvdXJTZWxmRXJyb3I6ICdWb2PDqiBuw6NvIHBvZGUgcmVtb3ZlciBzZXUgcHLDs3ByaW8gdXN1w6FyaW8nLFxuICAgICAgdXNlckV4aXN0czogJ1VzdcOhcmlvIGrDoSBhZGljaW9uYWRvIScsXG4gICAgICBwcm9maWxlOiB7XG4gICAgICAgIHVwZGF0ZUVycm9yOiAnTsOjbyBmb2kgcG9zc8OtdmVsIGF0dWFsaXphciBzZXUgcHJvZmlsZSdcbiAgICAgIH1cbiAgICB9LFxuICAgIHF1ZXJ5RGluYW1pYzoge1xuICAgICAgbm9GaWx0ZXI6ICdOZW5odW0gZmlsdHJvIGFkaWNpb25hZG8nXG4gICAgfVxuICB9KTtcbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbi8qZXNsaW50IGFuZ3VsYXIvZmlsZS1uYW1lOiAwLCBuby11bmRlZjogMCovXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbnN0YW50KCdwdC1CUi5pMThuLm1vZGVscycsIHtcbiAgICB1c2VyOiAnVXN1w6FyaW8nLFxuICAgIHRhc2s6ICdUYXJlZmEnLFxuICAgIHByb2plY3Q6ICdQcm9qZXRvJ1xuICB9KTtcbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbi8qZXNsaW50IGFuZ3VsYXIvZmlsZS1uYW1lOiAwLCBuby11bmRlZjogMCovXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbnN0YW50KCdwdC1CUi5pMThuLnZpZXdzJywge1xuICAgIGJyZWFkY3J1bWJzOiB7XG4gICAgICB1c2VyOiAnQWRtaW5pc3RyYcOnw6NvIC0gVXN1w6FyaW8nLFxuICAgICAgJ3VzZXItcHJvZmlsZSc6ICdQZXJmaWwnLFxuICAgICAgZGFzaGJvYXJkOiAnRGFzaGJvYXJkJyxcbiAgICAgIGF1ZGl0OiAnQWRtaW5pc3RyYcOnw6NvIC0gQXVkaXRvcmlhJyxcbiAgICAgIG1haWw6ICdBZG1pbmlzdHJhw6fDo28gLSBFbnZpbyBkZSBlLW1haWwnLFxuICAgICAgcHJvamVjdDogJ0V4ZW1wbG9zIC0gUHJvamV0b3MnLFxuICAgICAgJ2RpbmFtaWMtcXVlcnknOiAnQWRtaW5pc3RyYcOnw6NvIC0gQ29uc3VsdGFzIERpbsOibWljYXMnLFxuICAgICAgJ25vdC1hdXRob3JpemVkJzogJ0FjZXNzbyBOZWdhZG8nXG4gICAgfSxcbiAgICB0aXRsZXM6IHtcbiAgICAgIGRhc2hib2FyZDogJ1DDoWdpbmEgaW5pY2lhbCcsXG4gICAgICBtYWlsU2VuZDogJ0VudmlhciBlLW1haWwnLFxuICAgICAgdGFza0xpc3Q6ICdMaXN0YSBkZSBUYXJlZmFzJyxcbiAgICAgIHVzZXJMaXN0OiAnTGlzdGEgZGUgVXN1w6FyaW9zJyxcbiAgICAgIGF1ZGl0TGlzdDogJ0xpc3RhIGRlIExvZ3MnLFxuICAgICAgcmVnaXN0ZXI6ICdGb3JtdWzDoXJpbyBkZSBDYWRhc3RybycsXG4gICAgICByZXNldFBhc3N3b3JkOiAnUmVkZWZpbmlyIFNlbmhhJyxcbiAgICAgIHVwZGF0ZTogJ0Zvcm11bMOhcmlvIGRlIEF0dWFsaXphw6fDo28nXG4gICAgfSxcbiAgICBhY3Rpb25zOiB7XG4gICAgICBzZW5kOiAnRW52aWFyJyxcbiAgICAgIHNhdmU6ICdTYWx2YXInLFxuICAgICAgY2xlYXI6ICdMaW1wYXInLFxuICAgICAgY2xlYXJBbGw6ICdMaW1wYXIgVHVkbycsXG4gICAgICByZXN0YXJ0OiAnUmVpbmljaWFyJyxcbiAgICAgIGZpbHRlcjogJ0ZpbHRyYXInLFxuICAgICAgc2VhcmNoOiAnUGVzcXVpc2FyJyxcbiAgICAgIGxpc3Q6ICdMaXN0YXInLFxuICAgICAgZWRpdDogJ0VkaXRhcicsXG4gICAgICBjYW5jZWw6ICdDYW5jZWxhcicsXG4gICAgICB1cGRhdGU6ICdBdHVhbGl6YXInLFxuICAgICAgcmVtb3ZlOiAnUmVtb3ZlcicsXG4gICAgICBnZXRPdXQ6ICdTYWlyJyxcbiAgICAgIGFkZDogJ0FkaWNpb25hcicsXG4gICAgICBpbjogJ0VudHJhcicsXG4gICAgICBsb2FkSW1hZ2U6ICdDYXJyZWdhciBJbWFnZW0nLFxuICAgICAgc2lnbnVwOiAnQ2FkYXN0cmFyJ1xuICAgIH0sXG4gICAgZmllbGRzOiB7XG4gICAgICBkYXRlOiAnRGF0YScsXG4gICAgICBhY3Rpb246ICdBw6fDo28nLFxuICAgICAgYWN0aW9uczogJ0HDp8O1ZXMnLFxuICAgICAgYXVkaXQ6IHtcbiAgICAgICAgZGF0ZVN0YXJ0OiAnRGF0YSBJbmljaWFsJyxcbiAgICAgICAgZGF0ZUVuZDogJ0RhdGEgRmluYWwnLFxuICAgICAgICByZXNvdXJjZTogJ1JlY3Vyc28nLFxuICAgICAgICBhbGxSZXNvdXJjZXM6ICdUb2RvcyBSZWN1cnNvcycsXG4gICAgICAgIHR5cGU6IHtcbiAgICAgICAgICBjcmVhdGVkOiAnQ2FkYXN0cmFkbycsXG4gICAgICAgICAgdXBkYXRlZDogJ0F0dWFsaXphZG8nLFxuICAgICAgICAgIGRlbGV0ZWQ6ICdSZW1vdmlkbydcbiAgICAgICAgfVxuICAgICAgfSxcbiAgICAgIGxvZ2luOiB7XG4gICAgICAgIHJlc2V0UGFzc3dvcmQ6ICdFc3F1ZWNpIG1pbmhhIHNlbmhhJyxcbiAgICAgICAgY29uZmlybVBhc3N3b3JkOiAnQ29uZmlybWFyIHNlbmhhJ1xuICAgICAgfSxcbiAgICAgIG1haWw6IHtcbiAgICAgICAgdG86ICdQYXJhJyxcbiAgICAgICAgc3ViamVjdDogJ0Fzc3VudG8nLFxuICAgICAgICBtZXNzYWdlOiAnTWVuc2FnZW0nXG4gICAgICB9LFxuICAgICAgcXVlcnlEaW5hbWljOiB7XG4gICAgICAgIGZpbHRlcnM6ICdGaWx0cm9zJyxcbiAgICAgICAgcmVzdWx0czogJ1Jlc3VsdGFkb3MnLFxuICAgICAgICBtb2RlbDogJ01vZGVsJyxcbiAgICAgICAgYXR0cmlidXRlOiAnQXRyaWJ1dG8nLFxuICAgICAgICBvcGVyYXRvcjogJ09wZXJhZG9yJyxcbiAgICAgICAgcmVzb3VyY2U6ICdSZWN1cnNvJyxcbiAgICAgICAgdmFsdWU6ICdWYWxvcicsXG4gICAgICAgIG9wZXJhdG9yczoge1xuICAgICAgICAgIGVxdWFsczogJ0lndWFsJyxcbiAgICAgICAgICBkaWZlcmVudDogJ0RpZmVyZW50ZScsXG4gICAgICAgICAgY29udGVpbnM6ICdDb250w6ltJyxcbiAgICAgICAgICBzdGFydFdpdGg6ICdJbmljaWEgY29tJyxcbiAgICAgICAgICBmaW5pc2hXaXRoOiAnRmluYWxpemEgY29tJyxcbiAgICAgICAgICBiaWdnZXJUaGFuOiAnTWFpb3InLFxuICAgICAgICAgIGVxdWFsc09yQmlnZ2VyVGhhbjogJ01haW9yIG91IElndWFsJyxcbiAgICAgICAgICBsZXNzVGhhbjogJ01lbm9yJyxcbiAgICAgICAgICBlcXVhbHNPckxlc3NUaGFuOiAnTWVub3Igb3UgSWd1YWwnXG4gICAgICAgIH1cbiAgICAgIH0sXG4gICAgICBwcm9qZWN0OiB7XG4gICAgICAgIG5hbWU6ICdOb21lJyxcbiAgICAgICAgdG90YWxUYXNrOiAnVG90YWwgZGUgVGFyZWZhcydcbiAgICAgIH0sXG4gICAgICB0YXNrOiB7XG4gICAgICAgIGRvbmU6ICdOw6NvIEZlaXRvIC8gRmVpdG8nXG4gICAgICB9LFxuICAgICAgdXNlcjoge1xuICAgICAgICBwZXJmaWxzOiAnUGVyZmlzJyxcbiAgICAgICAgbmFtZU9yRW1haWw6ICdOb21lIG91IEVtYWlsJ1xuICAgICAgfVxuICAgIH0sXG4gICAgbGF5b3V0OiB7XG4gICAgICBtZW51OiB7XG4gICAgICAgIGRhc2hib2FyZDogJ0Rhc2hib2FyZCcsXG4gICAgICAgIHByb2plY3Q6ICdQcm9qZXRvcycsXG4gICAgICAgIGFkbWluOiAnQWRtaW5pc3RyYcOnw6NvJyxcbiAgICAgICAgZXhhbXBsZXM6ICdFeGVtcGxvcycsXG4gICAgICAgIHVzZXI6ICdVc3XDoXJpb3MnLFxuICAgICAgICBtYWlsOiAnRW52aWFyIGUtbWFpbCcsXG4gICAgICAgIGF1ZGl0OiAnQXVkaXRvcmlhJyxcbiAgICAgICAgZGluYW1pY1F1ZXJ5OiAnQ29uc3VsdGFzIERpbmFtaWNhcydcbiAgICAgIH1cbiAgICB9LFxuICAgIHRvb2x0aXBzOiB7XG4gICAgICBhdWRpdDoge1xuICAgICAgICB2aWV3RGV0YWlsOiAnVmlzdWFsaXphciBEZXRhbGhhbWVudG8nXG4gICAgICB9LFxuICAgICAgdXNlcjoge1xuICAgICAgICBwZXJmaWw6ICdQZXJmaWwnLFxuICAgICAgICB0cmFuc2ZlcjogJ1RyYW5zZmVyaXInXG4gICAgICB9LFxuICAgICAgdGFzazoge1xuICAgICAgICBsaXN0VGFzazogJ0xpc3RhciBUYXJlZmFzJ1xuICAgICAgfVxuICAgIH1cbiAgfSk7XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29udHJvbGxlcignUHJvamVjdHNDb250cm9sbGVyJywgUHJvamVjdHNDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIFByb2plY3RzQ29udHJvbGxlcihHbG9iYWwsICRjb250cm9sbGVyLCBQcm9qZWN0c1NlcnZpY2UsIFByRGlhbG9nKSB7XG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIC8vQXR0cmlidXRlcyBCbG9ja1xuXG4gICAgLy9GdW5jdGlvbnMgQmxvY2tcbiAgICB2bS5vbkFjdGl2YXRlID0gb25BY3RpdmF0ZTtcbiAgICB2bS5hcHBseUZpbHRlcnMgPSBhcHBseUZpbHRlcnM7XG4gICAgdm0udmlld1Rhc2tzID0gdmlld1Rhc2tzO1xuXG4gICAgLy8gaW5zdGFudGlhdGUgYmFzZSBjb250cm9sbGVyXG4gICAgJGNvbnRyb2xsZXIoJ0NSVURDb250cm9sbGVyJywgeyB2bTogdm0sIG1vZGVsU2VydmljZTogUHJvamVjdHNTZXJ2aWNlLCBvcHRpb25zOiB7fSB9KTtcblxuICAgIGZ1bmN0aW9uIG9uQWN0aXZhdGUoKSB7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMgPSB7fTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBhcHBseUZpbHRlcnMoZGVmYXVsdFF1ZXJ5RmlsdGVycykge1xuICAgICAgcmV0dXJuIGFuZ3VsYXIuZXh0ZW5kKGRlZmF1bHRRdWVyeUZpbHRlcnMsIHZtLnF1ZXJ5RmlsdGVycyk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gdmlld1Rhc2tzKHByb2plY3RJZCkge1xuICAgICAgdmFyIGNvbmZpZyA9IHtcbiAgICAgICAgbG9jYWxzOiB7XG4gICAgICAgICAgcHJvamVjdElkOiBwcm9qZWN0SWRcbiAgICAgICAgfSxcbiAgICAgICAgY29udHJvbGxlcjogJ1Rhc2tzRGlhbG9nQ29udHJvbGxlcicsXG4gICAgICAgIGNvbnRyb2xsZXJBczogJ3Rhc2tzQ3RybCcsXG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvc2FtcGxlcy90YXNrcy90YXNrcy1kaWFsb2cuaHRtbCcsXG4gICAgICAgIGhhc0JhY2tkcm9wOiB0cnVlXG4gICAgICB9O1xuXG4gICAgICBQckRpYWxvZy5jdXN0b20oY29uZmlnKS5maW5hbGx5KGZ1bmN0aW9uICgpIHtcbiAgICAgICAgdm0uc2VhcmNoKHZtLnBhZ2luYXRvci5jdXJyZW50UGFnZSk7XG4gICAgICB9KTtcbiAgICB9XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqXG4gICAqIEFycXVpdm8gZGUgY29uZmlndXJhw6fDo28gY29tIGFzIHJvdGFzIGVzcGVjw61maWNhcyBkbyByZWN1cnNvIHByb2plY3RcbiAgICpcbiAgICogQHBhcmFtIHthbnl9ICRzdGF0ZVByb3ZpZGVyXG4gICAqIEBwYXJhbSB7YW55fSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnYXBwLnByb2plY3QnLCB7XG4gICAgICB1cmw6ICcvcHJvamV0b3MnLFxuICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9zYW1wbGVzL3Byb2plY3RzL3Byb2plY3RzLmh0bWwnLFxuICAgICAgY29udHJvbGxlcjogJ1Byb2plY3RzQ29udHJvbGxlciBhcyBwcm9qZWN0c0N0cmwnLFxuICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IHRydWUsIG5lZWRQcm9maWxlOiBbJ2FkbWluJ10gfVxuICAgIH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZhY3RvcnkoJ1Byb2plY3RzU2VydmljZScsIFByb2plY3RzU2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiBQcm9qZWN0c1NlcnZpY2Uoc2VydmljZUZhY3RvcnkpIHtcbiAgICByZXR1cm4gc2VydmljZUZhY3RvcnkoJ3Byb2plY3RzJywge1xuICAgICAgYWN0aW9uczoge30sXG4gICAgICBpbnN0YW5jZToge31cbiAgICB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbnRyb2xsZXIoJ1Rhc2tzRGlhbG9nQ29udHJvbGxlcicsIFRhc2tzRGlhbG9nQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBUYXNrc0RpYWxvZ0NvbnRyb2xsZXIoJGNvbnRyb2xsZXIsIFRhc2tzU2VydmljZSwgcHJvamVjdElkLCBQclRvYXN0LCAvLyBOT1NPTkFSXG4gIFByRGlhbG9nLCAkdHJhbnNsYXRlLCBHbG9iYWwsIG1vbWVudCkge1xuXG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIC8vRnVuY3Rpb25zIEJsb2NrXG4gICAgdm0ub25BY3RpdmF0ZSA9IG9uQWN0aXZhdGU7XG4gICAgdm0uY2xvc2UgPSBjbG9zZTtcbiAgICB2bS5hcHBseUZpbHRlcnMgPSBhcHBseUZpbHRlcnM7XG4gICAgdm0uYmVmb3JlU2F2ZSA9IGJlZm9yZVNhdmU7XG4gICAgdm0uYWZ0ZXJTYXZlID0gYWZ0ZXJTYXZlO1xuICAgIHZtLnRvZ2dsZURvbmUgPSB0b2dnbGVEb25lO1xuXG4gICAgLy8gaW5zdGFudGlhdGUgYmFzZSBjb250cm9sbGVyXG4gICAgJGNvbnRyb2xsZXIoJ0NSVURDb250cm9sbGVyJywgeyB2bTogdm0sIG1vZGVsU2VydmljZTogVGFza3NTZXJ2aWNlLCBvcHRpb25zOiB7XG4gICAgICAgIHBlclBhZ2U6IDVcbiAgICAgIH0gfSk7XG5cbiAgICBmdW5jdGlvbiBvbkFjdGl2YXRlKCkge1xuICAgICAgdm0uZ2xvYmFsID0gR2xvYmFsO1xuICAgICAgdm0ucmVzb3VyY2Uuc2NoZWR1bGVkX3RvID0gbW9tZW50KCkuYWRkKDMwLCAnbWludXRlcycpO1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0geyBwcm9qZWN0SWQ6IHByb2plY3RJZCB9O1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGFwcGx5RmlsdGVycyhkZWZhdWx0UXVlcnlGaWx0ZXJzKSB7XG4gICAgICByZXR1cm4gYW5ndWxhci5leHRlbmQoZGVmYXVsdFF1ZXJ5RmlsdGVycywgdm0ucXVlcnlGaWx0ZXJzKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBiZWZvcmVTYXZlKCkge1xuICAgICAgdm0ucmVzb3VyY2UucHJvamVjdF9pZCA9IHZtLnF1ZXJ5RmlsdGVycy5wcm9qZWN0SWQ7XG4gICAgICB2bS5yZXNvdXJjZS5wcm9qZWN0ID0gbnVsbDtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBhZnRlclNhdmUoKSB7XG4gICAgICB2bS5jbGVhbkZvcm0oKTtcbiAgICAgIHZtLnNlYXJjaCh2bS5wYWdpbmF0b3IuY3VycmVudFBhZ2UpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGNsb3NlKCkge1xuICAgICAgdm0uY2xlYW5Gb3JtKCk7XG4gICAgICBQckRpYWxvZy5jbG9zZSgpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIHRvZ2dsZURvbmUocmVzb3VyY2UpIHtcbiAgICAgIFRhc2tzU2VydmljZS50b2dnbGVEb25lKHsgaWQ6IHJlc291cmNlLmlkLCBkb25lOiByZXNvdXJjZS5kb25lIH0pLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICBQclRvYXN0LnN1Y2Nlc3MoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5zYXZlU3VjY2VzcycpKTtcbiAgICAgICAgdm0uc2VhcmNoKHZtLnBhZ2luYXRvci5jdXJyZW50UGFnZSk7XG4gICAgICB9LCBmdW5jdGlvbiAoZXJyb3IpIHtcbiAgICAgICAgUHJUb2FzdC5lcnJvclZhbGlkYXRpb24oZXJyb3IuZGF0YSwgJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5vcGVyYXRpb25FcnJvcicpKTtcbiAgICAgIH0pO1xuICAgIH1cbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5mYWN0b3J5KCdUYXNrc1NlcnZpY2UnLCBUYXNrc1NlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gVGFza3NTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5LCBtb21lbnQpIHtcbiAgICByZXR1cm4gc2VydmljZUZhY3RvcnkoJ3Rhc2tzJywge1xuICAgICAgLy9xdWFuZG8gaW5zdGFuY2lhIHVtIHVzdcOhcmlvIHNlbSBwYXNzYXIgcGFyYW1ldHJvLFxuICAgICAgLy9vIG1lc21vIHZhaSB0ZXIgb3MgdmFsb3JlcyBkZWZhdWx0cyBhYmFpeG9cbiAgICAgIGRlZmF1bHRzOiB7XG4gICAgICAgIHNjaGVkdWxlZF90bzogbmV3IERhdGUoKVxuICAgICAgfSxcblxuICAgICAgbWFwOiB7XG4gICAgICAgIC8vY29udmVydCBwYXJhIG9iamV0byBqYXZhc2NyaXB0IGRhdGUgdW1hIHN0cmluZyBmb3JtYXRhZGEgY29tbyBkYXRhXG4gICAgICAgIHNjaGVkdWxlZF90bzogZnVuY3Rpb24gc2NoZWR1bGVkX3RvKHZhbHVlKSB7XG4gICAgICAgICAgcmV0dXJuIG1vbWVudCh2YWx1ZSkudG9EYXRlKCk7XG4gICAgICAgIH1cbiAgICAgIH0sXG5cbiAgICAgIGFjdGlvbnM6IHtcbiAgICAgICAgLyoqXG4gICAgICAgICAqIEF0dWFsaXphIG9zIHN0YXR1cyBkYSB0YXJlZmFcbiAgICAgICAgICpcbiAgICAgICAgICogQHBhcmFtIHtvYmplY3R9IGF0dHJpYnV0ZXNcbiAgICAgICAgICovXG4gICAgICAgIHRvZ2dsZURvbmU6IHtcbiAgICAgICAgICBtZXRob2Q6ICdQVVQnLFxuICAgICAgICAgIHVybDogJ3RvZ2dsZURvbmUnXG4gICAgICAgIH1cbiAgICAgIH0sXG4gICAgICBpbnN0YW5jZToge31cbiAgICB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbnRyb2xsZXIoJ1VzZXJzRGlhbG9nQ29udHJvbGxlcicsIFVzZXJzRGlhbG9nQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBVc2Vyc0RpYWxvZ0NvbnRyb2xsZXIoJGNvbnRyb2xsZXIsIFVzZXJzU2VydmljZSwgUHJEaWFsb2csIC8vIE5PU09OQVJcbiAgdXNlckRpYWxvZ0lucHV0LCBvbkluaXQpIHtcblxuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICB2bS5vbkFjdGl2YXRlID0gb25BY3RpdmF0ZTtcbiAgICB2bS5hcHBseUZpbHRlcnMgPSBhcHBseUZpbHRlcnM7XG4gICAgdm0uY2xvc2UgPSBjbG9zZTtcblxuICAgIGlmIChhbmd1bGFyLmlzRGVmaW5lZCh1c2VyRGlhbG9nSW5wdXQpKSB7XG4gICAgICB2bS50cmFuc2ZlclVzZXIgPSB1c2VyRGlhbG9nSW5wdXQudHJhbnNmZXJVc2VyRm47XG4gICAgfVxuXG4gICAgLy8gaW5zdGFudGlhdGUgYmFzZSBjb250cm9sbGVyXG4gICAgJGNvbnRyb2xsZXIoJ0NSVURDb250cm9sbGVyJywge1xuICAgICAgdm06IHZtLFxuICAgICAgbW9kZWxTZXJ2aWNlOiBVc2Vyc1NlcnZpY2UsXG4gICAgICBzZWFyY2hPbkluaXQ6IG9uSW5pdCxcbiAgICAgIG9wdGlvbnM6IHtcbiAgICAgICAgcGVyUGFnZTogNVxuICAgICAgfVxuICAgIH0pO1xuXG4gICAgZnVuY3Rpb24gb25BY3RpdmF0ZSgpIHtcbiAgICAgIHZtLnF1ZXJ5RmlsdGVycyA9IHt9O1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGFwcGx5RmlsdGVycygpIHtcbiAgICAgIHJldHVybiBhbmd1bGFyLmV4dGVuZCh2bS5kZWZhdWx0UXVlcnlGaWx0ZXJzLCB2bS5xdWVyeUZpbHRlcnMpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGNsb3NlKCkge1xuICAgICAgUHJEaWFsb2cuY2xvc2UoKTtcbiAgICB9XG4gIH1cbn0pKCk7IiwiLyplc2xpbnQgYW5ndWxhci9maWxlLW5hbWU6IDAqL1xuKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcsIFtcbiAgICAnbmdBbmltYXRlJyxcbiAgICAnbmdBcmlhJyxcbiAgICAndWkucm91dGVyJyxcbiAgICAnbmdQcm9kZWInLFxuICAgICd1aS51dGlscy5tYXNrcycsXG4gICAgJ3RleHQtbWFzaycsXG4gICAgJ25nTWF0ZXJpYWwnLFxuICAgICdtb2RlbEZhY3RvcnknLFxuICAgICdtZC5kYXRhLnRhYmxlJyxcbiAgICAnbmdNYXRlcmlhbERhdGVQaWNrZXInLFxuICAgICdwYXNjYWxwcmVjaHQudHJhbnNsYXRlJyxcbiAgICAnYW5ndWxhckZpbGVVcGxvYWQnXSk7XG59KSgpO1xuIiwiKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb25maWcoY29uZmlnKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIGNvbmZpZyhHbG9iYWwsICRtZFRoZW1pbmdQcm92aWRlciwgJG1vZGVsRmFjdG9yeVByb3ZpZGVyLCAgLy8gTk9TT05BUlxuICAgICR0cmFuc2xhdGVQcm92aWRlciwgbW9tZW50LCAkbWRBcmlhUHJvdmlkZXIpIHtcblxuICAgICR0cmFuc2xhdGVQcm92aWRlclxuICAgICAgLnVzZUxvYWRlcignbGFuZ3VhZ2VMb2FkZXInKVxuICAgICAgLnVzZVNhbml0aXplVmFsdWVTdHJhdGVneSgnZXNjYXBlJyk7XG5cbiAgICAkdHJhbnNsYXRlUHJvdmlkZXIudXNlUG9zdENvbXBpbGluZyh0cnVlKTtcblxuICAgIG1vbWVudC5sb2NhbGUoJ3B0LUJSJyk7XG5cbiAgICAvL29zIHNlcnZpw6dvcyByZWZlcmVudGUgYW9zIG1vZGVscyB2YWkgdXRpbGl6YXIgY29tbyBiYXNlIG5hcyB1cmxzXG4gICAgJG1vZGVsRmFjdG9yeVByb3ZpZGVyLmRlZmF1bHRPcHRpb25zLnByZWZpeCA9IEdsb2JhbC5hcGlQYXRoO1xuXG4gICAgLy8gQ29uZmlndXJhdGlvbiB0aGVtZVxuICAgICRtZFRoZW1pbmdQcm92aWRlci50aGVtZSgnZGVmYXVsdCcpXG4gICAgICAucHJpbWFyeVBhbGV0dGUoJ2Jyb3duJywge1xuICAgICAgICBkZWZhdWx0OiAnNzAwJ1xuICAgICAgfSlcbiAgICAgIC5hY2NlbnRQYWxldHRlKCdhbWJlcicpXG4gICAgICAud2FyblBhbGV0dGUoJ2RlZXAtb3JhbmdlJyk7XG5cbiAgICAvLyBFbmFibGUgYnJvd3NlciBjb2xvclxuICAgICRtZFRoZW1pbmdQcm92aWRlci5lbmFibGVCcm93c2VyQ29sb3IoKTtcblxuICAgICRtZEFyaWFQcm92aWRlci5kaXNhYmxlV2FybmluZ3MoKTtcblxuICB9XG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29udHJvbGxlcignQXBwQ29udHJvbGxlcicsIEFwcENvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLyoqXG4gICAqIENvbnRyb2xhZG9yIHJlc3BvbnPDoXZlbCBwb3IgZnVuY2lvbmFsaWRhZGVzIHF1ZSBzw6NvIGFjaW9uYWRhcyBlbSBxdWFscXVlciB0ZWxhIGRvIHNpc3RlbWFcbiAgICpcbiAgICovXG4gIGZ1bmN0aW9uIEFwcENvbnRyb2xsZXIoJHN0YXRlLCBBdXRoLCBHbG9iYWwpIHtcbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgLy9hbm8gYXR1YWwgcGFyYSBzZXIgZXhpYmlkbyBubyByb2RhcMOpIGRvIHNpc3RlbWFcbiAgICB2bS5hbm9BdHVhbCA9IG51bGw7XG5cbiAgICB2bS5sb2dvdXQgICAgID0gbG9nb3V0O1xuICAgIHZtLmdldEltYWdlUGVyZmlsID0gZ2V0SW1hZ2VQZXJmaWw7XG5cbiAgICBhY3RpdmF0ZSgpO1xuXG4gICAgZnVuY3Rpb24gYWN0aXZhdGUoKSB7XG4gICAgICB2YXIgZGF0ZSA9IG5ldyBEYXRlKCk7XG5cbiAgICAgIHZtLmFub0F0dWFsID0gZGF0ZS5nZXRGdWxsWWVhcigpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGxvZ291dCgpIHtcbiAgICAgIEF1dGgubG9nb3V0KCkudGhlbihmdW5jdGlvbigpIHtcbiAgICAgICAgJHN0YXRlLmdvKEdsb2JhbC5sb2dpblN0YXRlKTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGdldEltYWdlUGVyZmlsKCkge1xuICAgICAgcmV0dXJuIChBdXRoLmN1cnJlbnRVc2VyICYmIEF1dGguY3VycmVudFVzZXIuaW1hZ2UpXG4gICAgICAgID8gQXV0aC5jdXJyZW50VXNlci5pbWFnZVxuICAgICAgICA6IEdsb2JhbC5pbWFnZVBhdGggKyAnL25vX2F2YXRhci5naWYnO1xuICAgIH1cblxuICB9XG5cbn0pKCk7XG4iLCIvKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCwgbm8tdW5kZWY6IDAqL1xuKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgLyoqXG4gICAqIFRyYW5zZm9ybWEgYmlibGlvdGVjYXMgZXh0ZXJuYXMgZW0gc2VydmnDp29zIGRvIGFuZ3VsYXIgcGFyYSBzZXIgcG9zc8OtdmVsIHV0aWxpemFyXG4gICAqIGF0cmF2w6lzIGRhIGluamXDp8OjbyBkZSBkZXBlbmTDqm5jaWFcbiAgICovXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb25zdGFudCgnbG9kYXNoJywgXylcbiAgICAuY29uc3RhbnQoJ21vbWVudCcsIG1vbWVudCk7XG5cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uc3RhbnQoJ0dsb2JhbCcsIHtcbiAgICAgIGFwcE5hbWU6ICdGcmVlbGFnaWxlJyxcbiAgICAgIGhvbWVTdGF0ZTogJ2FwcC5kYXNoYm9hcmQnLFxuICAgICAgbG9naW5Vcmw6ICdhcHAvbG9naW4nLFxuICAgICAgbG9naW5TdGF0ZTogJ2FwcC5sb2dpbicsXG4gICAgICByZXNldFBhc3N3b3JkU3RhdGU6ICdhcHAucGFzc3dvcmQtcmVzZXQnLFxuICAgICAgbm90QXV0aG9yaXplZFN0YXRlOiAnYXBwLm5vdC1hdXRob3JpemVkJyxcbiAgICAgIHRva2VuS2V5OiAnc2VydmVyX3Rva2VuJyxcbiAgICAgIGNsaWVudFBhdGg6ICdjbGllbnQvYXBwJyxcbiAgICAgIGFwaVBhdGg6ICdhcGkvdjEnLFxuICAgICAgaW1hZ2VQYXRoOiAnY2xpZW50L2ltYWdlcydcbiAgICB9KTtcbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsICR1cmxSb3V0ZXJQcm92aWRlciwgR2xvYmFsKSB7XG4gICAgJHN0YXRlUHJvdmlkZXJcbiAgICAgIC5zdGF0ZSgnYXBwJywge1xuICAgICAgICB1cmw6ICcvYXBwJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9sYXlvdXQvYXBwLmh0bWwnLFxuICAgICAgICBhYnN0cmFjdDogdHJ1ZSxcbiAgICAgICAgcmVzb2x2ZTogeyAvL2Vuc3VyZSBsYW5ncyBpcyByZWFkeSBiZWZvcmUgcmVuZGVyIHZpZXdcbiAgICAgICAgICB0cmFuc2xhdGVSZWFkeTogWyckdHJhbnNsYXRlJywgJyRxJywgZnVuY3Rpb24oJHRyYW5zbGF0ZSwgJHEpIHtcbiAgICAgICAgICAgIHZhciBkZWZlcnJlZCA9ICRxLmRlZmVyKCk7XG5cbiAgICAgICAgICAgICR0cmFuc2xhdGUudXNlKCdwdC1CUicpLnRoZW4oZnVuY3Rpb24oKSB7XG4gICAgICAgICAgICAgIGRlZmVycmVkLnJlc29sdmUoKTtcbiAgICAgICAgICAgIH0pO1xuXG4gICAgICAgICAgICByZXR1cm4gZGVmZXJyZWQucHJvbWlzZTtcbiAgICAgICAgICB9XVxuICAgICAgICB9XG4gICAgICB9KVxuICAgICAgLnN0YXRlKEdsb2JhbC5ub3RBdXRob3JpemVkU3RhdGUsIHtcbiAgICAgICAgdXJsOiAnL2FjZXNzby1uZWdhZG8nLFxuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL2xheW91dC9ub3QtYXV0aG9yaXplZC5odG1sJyxcbiAgICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IGZhbHNlIH1cbiAgICAgIH0pO1xuXG4gICAgJHVybFJvdXRlclByb3ZpZGVyLndoZW4oJy9hcHAnLCBHbG9iYWwubG9naW5VcmwpO1xuICAgICR1cmxSb3V0ZXJQcm92aWRlci5vdGhlcndpc2UoR2xvYmFsLmxvZ2luVXJsKTtcbiAgfVxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5ydW4ocnVuKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIHJ1bigkcm9vdFNjb3BlLCAkc3RhdGUsICRzdGF0ZVBhcmFtcywgQXV0aCwgR2xvYmFsKSB7IC8vIE5PU09OQVJcbiAgICAvL3NldGFkbyBubyByb290U2NvcGUgcGFyYSBwb2RlciBzZXIgYWNlc3NhZG8gbmFzIHZpZXdzIHNlbSBwcmVmaXhvIGRlIGNvbnRyb2xsZXJcbiAgICAkcm9vdFNjb3BlLiRzdGF0ZSA9ICRzdGF0ZTtcbiAgICAkcm9vdFNjb3BlLiRzdGF0ZVBhcmFtcyA9ICRzdGF0ZVBhcmFtcztcbiAgICAkcm9vdFNjb3BlLmF1dGggPSBBdXRoO1xuICAgICRyb290U2NvcGUuZ2xvYmFsID0gR2xvYmFsO1xuXG4gICAgLy9ubyBpbmljaW8gY2FycmVnYSBvIHVzdcOhcmlvIGRvIGxvY2Fsc3RvcmFnZSBjYXNvIG8gdXN1w6FyaW8gZXN0YWphIGFicmluZG8gbyBuYXZlZ2Fkb3JcbiAgICAvL3BhcmEgdm9sdGFyIGF1dGVudGljYWRvXG4gICAgQXV0aC5yZXRyaWV2ZVVzZXJGcm9tTG9jYWxTdG9yYWdlKCk7XG4gIH1cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb250cm9sbGVyKCdBdWRpdENvbnRyb2xsZXInLCBBdWRpdENvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gQXVkaXRDb250cm9sbGVyKCRjb250cm9sbGVyLCBBdWRpdFNlcnZpY2UsIFByRGlhbG9nLCBHbG9iYWwsICR0cmFuc2xhdGUpIHsgLy8gTk9TT05BUlxuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICB2bS5vbkFjdGl2YXRlID0gb25BY3RpdmF0ZTtcbiAgICB2bS5hcHBseUZpbHRlcnMgPSBhcHBseUZpbHRlcnM7XG4gICAgdm0udmlld0RldGFpbCA9IHZpZXdEZXRhaWw7XG5cbiAgICAkY29udHJvbGxlcignQ1JVRENvbnRyb2xsZXInLCB7IHZtOiB2bSwgbW9kZWxTZXJ2aWNlOiBBdWRpdFNlcnZpY2UsIG9wdGlvbnM6IHt9IH0pO1xuXG4gICAgZnVuY3Rpb24gb25BY3RpdmF0ZSgpIHtcbiAgICAgIHZtLm1vZGVscyA9IFtdO1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0ge307XG5cbiAgICAgIC8vUGVnYSB0b2RvcyBvcyBtb2RlbHMgZG8gc2VydmVyIGUgbW9udGEgdW1hIGxpc3RhIHBybyBDb21ib0JveFxuICAgICAgQXVkaXRTZXJ2aWNlLmdldEF1ZGl0ZWRNb2RlbHMoKS50aGVuKGZ1bmN0aW9uKGRhdGEpIHtcbiAgICAgICAgdmFyIG1vZGVscyA9IFt7IGlkOiAnJywgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudCgnZ2xvYmFsLmFsbCcpIH1dO1xuXG4gICAgICAgIGRhdGEubW9kZWxzLnNvcnQoKTtcblxuICAgICAgICBmb3IgKHZhciBpbmRleCA9IDA7IGluZGV4IDwgZGF0YS5tb2RlbHMubGVuZ3RoOyBpbmRleCsrKSB7XG4gICAgICAgICAgdmFyIG1vZGVsID0gZGF0YS5tb2RlbHNbaW5kZXhdO1xuXG4gICAgICAgICAgbW9kZWxzLnB1c2goe1xuICAgICAgICAgICAgaWQ6IG1vZGVsLFxuICAgICAgICAgICAgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudCgnbW9kZWxzLicgKyBtb2RlbC50b0xvd2VyQ2FzZSgpKVxuICAgICAgICAgIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgdm0ubW9kZWxzID0gbW9kZWxzO1xuICAgICAgICB2bS5xdWVyeUZpbHRlcnMubW9kZWwgPSB2bS5tb2RlbHNbMF0uaWQ7XG4gICAgICB9KTtcblxuICAgICAgdm0udHlwZXMgPSBBdWRpdFNlcnZpY2UubGlzdFR5cGVzKCk7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMudHlwZSA9IHZtLnR5cGVzWzBdLmlkO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGFwcGx5RmlsdGVycyhkZWZhdWx0UXVlcnlGaWx0ZXJzKSB7XG4gICAgICByZXR1cm4gYW5ndWxhci5leHRlbmQoZGVmYXVsdFF1ZXJ5RmlsdGVycywgdm0ucXVlcnlGaWx0ZXJzKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiB2aWV3RGV0YWlsKGF1ZGl0RGV0YWlsKSB7XG4gICAgICB2YXIgY29uZmlnID0ge1xuICAgICAgICBsb2NhbHM6IHsgYXVkaXREZXRhaWw6IGF1ZGl0RGV0YWlsIH0sXG4gICAgICAgIC8qKiBAbmdJbmplY3QgKi9cbiAgICAgICAgY29udHJvbGxlcjogZnVuY3Rpb24oYXVkaXREZXRhaWwsIFByRGlhbG9nKSB7XG4gICAgICAgICAgdmFyIHZtID0gdGhpcztcblxuICAgICAgICAgIHZtLmNsb3NlID0gY2xvc2U7XG5cbiAgICAgICAgICBhY3RpdmF0ZSgpO1xuXG4gICAgICAgICAgZnVuY3Rpb24gYWN0aXZhdGUoKSB7XG4gICAgICAgICAgICBpZiAoYW5ndWxhci5pc0FycmF5KGF1ZGl0RGV0YWlsLm9sZCkgJiYgYXVkaXREZXRhaWwub2xkLmxlbmd0aCA9PT0gMCkgYXVkaXREZXRhaWwub2xkID0gbnVsbDtcbiAgICAgICAgICAgIGlmIChhbmd1bGFyLmlzQXJyYXkoYXVkaXREZXRhaWwubmV3KSAmJiBhdWRpdERldGFpbC5uZXcubGVuZ3RoID09PSAwKSBhdWRpdERldGFpbC5uZXcgPSBudWxsO1xuXG4gICAgICAgICAgICB2bS5hdWRpdERldGFpbCA9IGF1ZGl0RGV0YWlsO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIGZ1bmN0aW9uIGNsb3NlKCkge1xuICAgICAgICAgICAgUHJEaWFsb2cuY2xvc2UoKTtcbiAgICAgICAgICB9XG5cbiAgICAgICAgfSxcbiAgICAgICAgY29udHJvbGxlckFzOiAnYXVkaXREZXRhaWxDdHJsJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9hdWRpdC9hdWRpdC1kZXRhaWwuaHRtbCcsXG4gICAgICAgIGhhc0JhY2tkcm9wOiB0cnVlXG4gICAgICB9O1xuXG4gICAgICBQckRpYWxvZy5jdXN0b20oY29uZmlnKTtcbiAgICB9XG5cbiAgfVxuXG59KSgpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKlxuICAgKiBBcnF1aXZvIGRlIGNvbmZpZ3VyYcOnw6NvIGNvbSBhcyByb3RhcyBlc3BlY8OtZmljYXMgZGUgYXVkaXRvcmlhXG4gICAqXG4gICAqIEBwYXJhbSB7YW55fSAkc3RhdGVQcm92aWRlclxuICAgKiBAcGFyYW0ge2FueX0gR2xvYmFsXG4gICAqL1xuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvdXRlcygkc3RhdGVQcm92aWRlciwgR2xvYmFsKSB7XG4gICAgJHN0YXRlUHJvdmlkZXJcbiAgICAgIC5zdGF0ZSgnYXBwLmF1ZGl0Jywge1xuICAgICAgICB1cmw6ICcvYXVkaXRvcmlhJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9hdWRpdC9hdWRpdC5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ0F1ZGl0Q29udHJvbGxlciBhcyBhdWRpdEN0cmwnLFxuICAgICAgICBkYXRhOiB7IG5lZWRBdXRoZW50aWNhdGlvbjogdHJ1ZSwgbmVlZFByb2ZpbGU6IFsnYWRtaW4nXSB9XG4gICAgICB9KTtcblxuICB9XG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZhY3RvcnkoJ0F1ZGl0U2VydmljZScsIEF1ZGl0U2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBBdWRpdFNlcnZpY2Uoc2VydmljZUZhY3RvcnksICR0cmFuc2xhdGUpIHtcbiAgICByZXR1cm4gc2VydmljZUZhY3RvcnkoJ2F1ZGl0Jywge1xuICAgICAgYWN0aW9uczoge1xuICAgICAgICBnZXRBdWRpdGVkTW9kZWxzOiB7XG4gICAgICAgICAgbWV0aG9kOiAnR0VUJyxcbiAgICAgICAgICB1cmw6ICdtb2RlbHMnXG4gICAgICAgIH1cbiAgICAgIH0sXG4gICAgICBpbnN0YW5jZToge1xuICAgICAgfSxcbiAgICAgIGxpc3RUeXBlczogZnVuY3Rpb24oKSB7XG4gICAgICAgIHZhciBhdWRpdFBhdGggPSAndmlld3MuZmllbGRzLmF1ZGl0Lic7XG5cbiAgICAgICAgcmV0dXJuIFtcbiAgICAgICAgICB7IGlkOiAnJywgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudChhdWRpdFBhdGggKyAnYWxsUmVzb3VyY2VzJykgfSxcbiAgICAgICAgICB7IGlkOiAnY3JlYXRlZCcsIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoYXVkaXRQYXRoICsgJ3R5cGUuY3JlYXRlZCcpIH0sXG4gICAgICAgICAgeyBpZDogJ3VwZGF0ZWQnLCBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KGF1ZGl0UGF0aCArICd0eXBlLnVwZGF0ZWQnKSB9LFxuICAgICAgICAgIHsgaWQ6ICdkZWxldGVkJywgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudChhdWRpdFBhdGggKyAndHlwZS5kZWxldGVkJykgfVxuICAgICAgICBdO1xuICAgICAgfVxuICAgIH0pO1xuICB9XG5cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqXG4gICAqIEFycXVpdm8gZGUgY29uZmlndXJhw6fDo28gY29tIGFzIHJvdGFzIGVzcGVjw61maWNhcyBkbyByZWN1cnNvIHVzZXJcbiAgICpcbiAgICogQHBhcmFtIHthbnl9ICRzdGF0ZVByb3ZpZGVyXG4gICAqIEBwYXJhbSB7YW55fSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlclxuICAgICAgLnN0YXRlKEdsb2JhbC5yZXNldFBhc3N3b3JkU3RhdGUsIHtcbiAgICAgICAgdXJsOiAnL3Bhc3N3b3JkL3Jlc2V0Lzp0b2tlbicsXG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvYXV0aC9yZXNldC1wYXNzLWZvcm0uaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdQYXNzd29yZENvbnRyb2xsZXIgYXMgcGFzc0N0cmwnLFxuICAgICAgICBkYXRhOiB7IG5lZWRBdXRoZW50aWNhdGlvbjogZmFsc2UgfVxuICAgICAgfSlcbiAgICAgIC5zdGF0ZShHbG9iYWwubG9naW5TdGF0ZSwge1xuICAgICAgICB1cmw6ICcvbG9naW4nLFxuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL2F1dGgvbG9naW4uaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdMb2dpbkNvbnRyb2xsZXIgYXMgbG9naW5DdHJsJyxcbiAgICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IGZhbHNlIH1cbiAgICAgIH0pO1xuXG4gIH1cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmFjdG9yeSgnQXV0aCcsIEF1dGgpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gQXV0aCgkaHR0cCwgJHEsIEdsb2JhbCwgVXNlcnNTZXJ2aWNlKSB7IC8vIE5PU09OQVJcbiAgICB2YXIgYXV0aCA9IHtcbiAgICAgIGxvZ2luOiBsb2dpbixcbiAgICAgIGxvZ291dDogbG9nb3V0LFxuICAgICAgdXBkYXRlQ3VycmVudFVzZXI6IHVwZGF0ZUN1cnJlbnRVc2VyLFxuICAgICAgcmV0cmlldmVVc2VyRnJvbUxvY2FsU3RvcmFnZTogcmV0cmlldmVVc2VyRnJvbUxvY2FsU3RvcmFnZSxcbiAgICAgIGF1dGhlbnRpY2F0ZWQ6IGF1dGhlbnRpY2F0ZWQsXG4gICAgICBzZW5kRW1haWxSZXNldFBhc3N3b3JkOiBzZW5kRW1haWxSZXNldFBhc3N3b3JkLFxuICAgICAgcmVtb3RlVmFsaWRhdGVUb2tlbjogcmVtb3RlVmFsaWRhdGVUb2tlbixcbiAgICAgIGdldFRva2VuOiBnZXRUb2tlbixcbiAgICAgIHNldFRva2VuOiBzZXRUb2tlbixcbiAgICAgIGNsZWFyVG9rZW46IGNsZWFyVG9rZW4sXG4gICAgICBjdXJyZW50VXNlcjogbnVsbFxuICAgIH07XG5cbiAgICBmdW5jdGlvbiBjbGVhclRva2VuKCkge1xuICAgICAgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oR2xvYmFsLnRva2VuS2V5KTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBzZXRUb2tlbih0b2tlbikge1xuICAgICAgbG9jYWxTdG9yYWdlLnNldEl0ZW0oR2xvYmFsLnRva2VuS2V5LCB0b2tlbik7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gZ2V0VG9rZW4oKSB7XG4gICAgICByZXR1cm4gbG9jYWxTdG9yYWdlLmdldEl0ZW0oR2xvYmFsLnRva2VuS2V5KTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiByZW1vdGVWYWxpZGF0ZVRva2VuKCkge1xuICAgICAgdmFyIGRlZmVycmVkID0gJHEuZGVmZXIoKTtcblxuICAgICAgaWYgKGF1dGguYXV0aGVudGljYXRlZCgpKSB7XG4gICAgICAgICRodHRwLmdldChHbG9iYWwuYXBpUGF0aCArICcvYXV0aGVudGljYXRlL2NoZWNrJylcbiAgICAgICAgICAudGhlbihmdW5jdGlvbigpIHtcbiAgICAgICAgICAgIGRlZmVycmVkLnJlc29sdmUodHJ1ZSk7XG4gICAgICAgICAgfSwgZnVuY3Rpb24oKSB7XG4gICAgICAgICAgICBhdXRoLmxvZ291dCgpO1xuXG4gICAgICAgICAgICBkZWZlcnJlZC5yZWplY3QoZmFsc2UpO1xuICAgICAgICAgIH0pO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgYXV0aC5sb2dvdXQoKTtcblxuICAgICAgICBkZWZlcnJlZC5yZWplY3QoZmFsc2UpO1xuICAgICAgfVxuXG4gICAgICByZXR1cm4gZGVmZXJyZWQucHJvbWlzZTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBWZXJpZmljYSBzZSBvIHVzdcOhcmlvIGVzdMOhIGF1dGVudGljYWRvXG4gICAgICpcbiAgICAgKiBAcmV0dXJucyB7Ym9vbGVhbn1cbiAgICAgKi9cbiAgICBmdW5jdGlvbiBhdXRoZW50aWNhdGVkKCkge1xuICAgICAgcmV0dXJuIGF1dGguZ2V0VG9rZW4oKSAhPT0gbnVsbFxuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlY3VwZXJhIG8gdXN1w6FyaW8gZG8gbG9jYWxTdG9yYWdlXG4gICAgICovXG4gICAgZnVuY3Rpb24gcmV0cmlldmVVc2VyRnJvbUxvY2FsU3RvcmFnZSgpIHtcbiAgICAgIHZhciB1c2VyID0gbG9jYWxTdG9yYWdlLmdldEl0ZW0oJ3VzZXInKTtcblxuICAgICAgaWYgKHVzZXIpIHtcbiAgICAgICAgYXV0aC5jdXJyZW50VXNlciA9IGFuZ3VsYXIubWVyZ2UobmV3IFVzZXJzU2VydmljZSgpLCBhbmd1bGFyLmZyb21Kc29uKHVzZXIpKTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBHdWFyZGEgbyB1c3XDoXJpbyBubyBsb2NhbFN0b3JhZ2UgcGFyYSBjYXNvIG8gdXN1w6FyaW8gZmVjaGUgZSBhYnJhIG8gbmF2ZWdhZG9yXG4gICAgICogZGVudHJvIGRvIHRlbXBvIGRlIHNlc3PDo28gc2VqYSBwb3Nzw612ZWwgcmVjdXBlcmFyIG8gdG9rZW4gYXV0ZW50aWNhZG8uXG4gICAgICpcbiAgICAgKiBNYW50w6ltIGEgdmFyacOhdmVsIGF1dGguY3VycmVudFVzZXIgcGFyYSBmYWNpbGl0YXIgbyBhY2Vzc28gYW8gdXN1w6FyaW8gbG9nYWRvIGVtIHRvZGEgYSBhcGxpY2HDp8Ojb1xuICAgICAqXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gdXNlciBVc3XDoXJpbyBhIHNlciBhdHVhbGl6YWRvLiBDYXNvIHNlamEgcGFzc2FkbyBudWxsIGxpbXBhXG4gICAgICogdG9kYXMgYXMgaW5mb3JtYcOnw7VlcyBkbyB1c3XDoXJpbyBjb3JyZW50ZS5cbiAgICAgKi9cbiAgICBmdW5jdGlvbiB1cGRhdGVDdXJyZW50VXNlcih1c2VyKSB7XG4gICAgICB2YXIgZGVmZXJyZWQgPSAkcS5kZWZlcigpO1xuXG4gICAgICBpZiAodXNlcikge1xuICAgICAgICB1c2VyID0gYW5ndWxhci5tZXJnZShuZXcgVXNlcnNTZXJ2aWNlKCksIHVzZXIpO1xuXG4gICAgICAgIHZhciBqc29uVXNlciA9IGFuZ3VsYXIudG9Kc29uKHVzZXIpO1xuXG4gICAgICAgIGxvY2FsU3RvcmFnZS5zZXRJdGVtKCd1c2VyJywganNvblVzZXIpO1xuICAgICAgICBhdXRoLmN1cnJlbnRVc2VyID0gdXNlcjtcblxuICAgICAgICBkZWZlcnJlZC5yZXNvbHZlKHVzZXIpO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oJ3VzZXInKTtcbiAgICAgICAgYXV0aC5jdXJyZW50VXNlciA9IG51bGw7XG4gICAgICAgIGF1dGguY2xlYXJUb2tlbigpO1xuXG4gICAgICAgIGRlZmVycmVkLnJlamVjdCgpO1xuICAgICAgfVxuXG4gICAgICByZXR1cm4gZGVmZXJyZWQucHJvbWlzZTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFsaXphIG8gbG9naW4gZG8gdXN1w6FyaW9cbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSBjcmVkZW50aWFscyBFbWFpbCBlIFNlbmhhIGRvIHVzdcOhcmlvXG4gICAgICogQHJldHVybnMge3Byb21pc2V9IFVtYSBwcm9taXNlIGNvbSBvIHJlc3VsdGFkbyBkbyBjaGFtYWRhIG5vIGJhY2tlbmRcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBsb2dpbihjcmVkZW50aWFscykge1xuICAgICAgdmFyIGRlZmVycmVkID0gJHEuZGVmZXIoKTtcblxuICAgICAgJGh0dHAucG9zdChHbG9iYWwuYXBpUGF0aCArICcvYXV0aGVudGljYXRlJywgY3JlZGVudGlhbHMpXG4gICAgICAgIC50aGVuKGZ1bmN0aW9uKHJlc3BvbnNlKSB7XG4gICAgICAgICAgYXV0aC5zZXRUb2tlbihyZXNwb25zZS5kYXRhLnRva2VuKTtcblxuICAgICAgICAgIHJldHVybiAkaHR0cC5nZXQoR2xvYmFsLmFwaVBhdGggKyAnL2F1dGhlbnRpY2F0ZS91c2VyJyk7XG4gICAgICAgIH0pXG4gICAgICAgIC50aGVuKGZ1bmN0aW9uKHJlc3BvbnNlKSB7XG4gICAgICAgICAgYXV0aC51cGRhdGVDdXJyZW50VXNlcihyZXNwb25zZS5kYXRhLnVzZXIpO1xuXG4gICAgICAgICAgZGVmZXJyZWQucmVzb2x2ZSgpO1xuICAgICAgICB9LCBmdW5jdGlvbihlcnJvcikge1xuICAgICAgICAgIGF1dGgubG9nb3V0KCk7XG5cbiAgICAgICAgICBkZWZlcnJlZC5yZWplY3QoZXJyb3IpO1xuICAgICAgICB9KTtcblxuICAgICAgcmV0dXJuIGRlZmVycmVkLnByb21pc2U7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogRGVzbG9nYSBvcyB1c3XDoXJpb3MuIENvbW8gbsOjbyB0ZW4gbmVuaHVtYSBpbmZvcm1hw6fDo28gbmEgc2Vzc8OjbyBkbyBzZXJ2aWRvclxuICAgICAqIGUgdW0gdG9rZW4gdW1hIHZleiBnZXJhZG8gbsOjbyBwb2RlLCBwb3IgcGFkcsOjbywgc2VyIGludmFsaWRhZG8gYW50ZXMgZG8gc2V1IHRlbXBvIGRlIGV4cGlyYcOnw6NvLFxuICAgICAqIHNvbWVudGUgYXBhZ2Ftb3Mgb3MgZGFkb3MgZG8gdXN1w6FyaW8gZSBvIHRva2VuIGRvIG5hdmVnYWRvciBwYXJhIGVmZXRpdmFyIG8gbG9nb3V0LlxuICAgICAqXG4gICAgICogQHJldHVybnMge3Byb21pc2V9IFVtYSBwcm9taXNlIGNvbSBvIHJlc3VsdGFkbyBkYSBvcGVyYcOnw6NvXG4gICAgICovXG4gICAgZnVuY3Rpb24gbG9nb3V0KCkge1xuICAgICAgdmFyIGRlZmVycmVkID0gJHEuZGVmZXIoKTtcblxuICAgICAgYXV0aC51cGRhdGVDdXJyZW50VXNlcihudWxsKTtcbiAgICAgIGRlZmVycmVkLnJlc29sdmUoKTtcblxuICAgICAgcmV0dXJuIGRlZmVycmVkLnByb21pc2U7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogRW52aWEgdW0gZW1haWwgcGFyYSByZWN1cGVyYcOnw6NvIGRlIHNlbmhhXG4gICAgICogQHBhcmFtIHtPYmplY3R9IHJlc2V0RGF0YSAtIE9iamV0byBjb250ZW5kbyBvIGVtYWlsXG4gICAgICogQHJldHVybiB7UHJvbWlzZX0gLSBSZXRvcm5hIHVtYSBwcm9taXNlIHBhcmEgc2VyIHJlc29sdmlkYVxuICAgICAqL1xuICAgIGZ1bmN0aW9uIHNlbmRFbWFpbFJlc2V0UGFzc3dvcmQocmVzZXREYXRhKSB7XG4gICAgICB2YXIgZGVmZXJyZWQgPSAkcS5kZWZlcigpO1xuXG4gICAgICAkaHR0cC5wb3N0KEdsb2JhbC5hcGlQYXRoICsgJy9wYXNzd29yZC9lbWFpbCcsIHJlc2V0RGF0YSlcbiAgICAgICAgLnRoZW4oZnVuY3Rpb24ocmVzcG9uc2UpIHtcbiAgICAgICAgICBkZWZlcnJlZC5yZXNvbHZlKHJlc3BvbnNlLmRhdGEpO1xuICAgICAgICB9LCBmdW5jdGlvbihlcnJvcikge1xuICAgICAgICAgIGRlZmVycmVkLnJlamVjdChlcnJvcik7XG4gICAgICAgIH0pO1xuXG4gICAgICByZXR1cm4gZGVmZXJyZWQucHJvbWlzZTtcbiAgICB9XG5cbiAgICByZXR1cm4gYXV0aDtcbiAgfVxuXG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29udHJvbGxlcignTG9naW5Db250cm9sbGVyJywgTG9naW5Db250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIExvZ2luQ29udHJvbGxlcigkc3RhdGUsIEF1dGgsIEdsb2JhbCwgUHJEaWFsb2cpIHtcbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0ubG9naW4gPSBsb2dpbjtcbiAgICB2bS5vcGVuRGlhbG9nUmVzZXRQYXNzID0gb3BlbkRpYWxvZ1Jlc2V0UGFzcztcblxuICAgIGFjdGl2YXRlKCk7XG5cbiAgICBmdW5jdGlvbiBhY3RpdmF0ZSgpIHtcbiAgICAgIHZtLmNyZWRlbnRpYWxzID0ge307XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gbG9naW4oKSB7XG4gICAgICB2YXIgY3JlZGVudGlhbHMgPSB7XG4gICAgICAgIGVtYWlsOiB2bS5jcmVkZW50aWFscy5lbWFpbCxcbiAgICAgICAgcGFzc3dvcmQ6IHZtLmNyZWRlbnRpYWxzLnBhc3N3b3JkXG4gICAgICB9O1xuXG4gICAgICBBdXRoLmxvZ2luKGNyZWRlbnRpYWxzKS50aGVuKGZ1bmN0aW9uKCkge1xuICAgICAgICAkc3RhdGUuZ28oR2xvYmFsLmhvbWVTdGF0ZSk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBFeGliZSBvIGRpYWxvZyBwYXJhIHJlY3VwZXJhw6fDo28gZGUgc2VuaGFcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBvcGVuRGlhbG9nUmVzZXRQYXNzKCkge1xuICAgICAgdmFyIGNvbmZpZyA9IHtcbiAgICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9hdXRoL3NlbmQtcmVzZXQtZGlhbG9nLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnUGFzc3dvcmRDb250cm9sbGVyIGFzIHBhc3NDdHJsJyxcbiAgICAgICAgaGFzQmFja2Ryb3A6IHRydWVcbiAgICAgIH1cblxuICAgICAgUHJEaWFsb2cuY3VzdG9tKGNvbmZpZyk7XG4gICAgfVxuXG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb250cm9sbGVyKCdQYXNzd29yZENvbnRyb2xsZXInLCBQYXNzd29yZENvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gUGFzc3dvcmRDb250cm9sbGVyKEdsb2JhbCwgJHN0YXRlUGFyYW1zLCAkaHR0cCwgJHRpbWVvdXQsICRzdGF0ZSwgLy8gTk9TT05BUlxuICAgIFByVG9hc3QsIFByRGlhbG9nLCBBdXRoLCAkdHJhbnNsYXRlKSB7XG5cbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0uc2VuZFJlc2V0ID0gc2VuZFJlc2V0O1xuICAgIHZtLmNsb3NlRGlhbG9nID0gY2xvc2VEaWFsb2c7XG4gICAgdm0uY2xlYW5Gb3JtID0gY2xlYW5Gb3JtO1xuICAgIHZtLnNlbmRFbWFpbFJlc2V0UGFzc3dvcmQgPSBzZW5kRW1haWxSZXNldFBhc3N3b3JkO1xuXG4gICAgYWN0aXZhdGUoKTtcblxuICAgIGZ1bmN0aW9uIGFjdGl2YXRlKCkge1xuICAgICAgdm0ucmVzZXQgPSB7IGVtYWlsOiAnJywgdG9rZW46ICRzdGF0ZVBhcmFtcy50b2tlbiB9O1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWxpemEgYSBhbHRlcmHDp8OjbyBkYSBzZW5oYSBkbyB1c3XDoXJpbyBlIG8gcmVkaXJlY2lvbmEgcGFyYSBhIHRlbGEgZGUgbG9naW5cbiAgICAgKi9cbiAgICBmdW5jdGlvbiBzZW5kUmVzZXQoKSB7XG4gICAgICAkaHR0cC5wb3N0KEdsb2JhbC5hcGlQYXRoICsgJy9wYXNzd29yZC9yZXNldCcsIHZtLnJlc2V0KVxuICAgICAgICAudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgUHJUb2FzdC5zdWNjZXNzKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMub3BlcmF0aW9uU3VjY2VzcycpKTtcbiAgICAgICAgICAkdGltZW91dChmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAkc3RhdGUuZ28oR2xvYmFsLmxvZ2luU3RhdGUpO1xuICAgICAgICAgIH0sIDE1MDApO1xuICAgICAgICB9LCBmdW5jdGlvbiAoZXJyb3IpIHtcbiAgICAgICAgICBpZiAoZXJyb3Iuc3RhdHVzICE9PSA0MDAgJiYgZXJyb3Iuc3RhdHVzICE9PSA1MDApIHtcbiAgICAgICAgICAgIHZhciBtc2cgPSAnJztcblxuICAgICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCBlcnJvci5kYXRhLnBhc3N3b3JkLmxlbmd0aDsgaSsrKSB7XG4gICAgICAgICAgICAgIG1zZyArPSBlcnJvci5kYXRhLnBhc3N3b3JkW2ldICsgJzxicj4nO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgUHJUb2FzdC5lcnJvcihtc2cudG9VcHBlckNhc2UoKSk7XG4gICAgICAgICAgfVxuICAgICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBFbnZpYSB1bSBlbWFpbCBkZSByZWN1cGVyYcOnw6NvIGRlIHNlbmhhIGNvbSBvIHRva2VuIGRvIHVzdcOhcmlvXG4gICAgICovXG4gICAgZnVuY3Rpb24gc2VuZEVtYWlsUmVzZXRQYXNzd29yZCgpIHtcblxuICAgICAgaWYgKHZtLnJlc2V0LmVtYWlsID09PSAnJykge1xuICAgICAgICBQclRvYXN0LmVycm9yKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMudmFsaWRhdGUuZmllbGRSZXF1aXJlZCcsIHsgZmllbGQ6ICdlbWFpbCcgfSkpO1xuICAgICAgICByZXR1cm47XG4gICAgICB9XG5cbiAgICAgIEF1dGguc2VuZEVtYWlsUmVzZXRQYXNzd29yZCh2bS5yZXNldCkudGhlbihmdW5jdGlvbiAoZGF0YSkge1xuICAgICAgICBQclRvYXN0LnN1Y2Nlc3MoZGF0YS5tZXNzYWdlKTtcblxuICAgICAgICB2bS5jbGVhbkZvcm0oKTtcbiAgICAgICAgdm0uY2xvc2VEaWFsb2coKTtcbiAgICAgIH0sIGZ1bmN0aW9uIChlcnJvcikge1xuICAgICAgICBpZiAoZXJyb3IuZGF0YS5lbWFpbCAmJiBlcnJvci5kYXRhLmVtYWlsLmxlbmd0aCA+IDApIHtcbiAgICAgICAgICB2YXIgbXNnID0gJyc7XG5cbiAgICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IGVycm9yLmRhdGEuZW1haWwubGVuZ3RoOyBpKyspIHtcbiAgICAgICAgICAgIG1zZyArPSBlcnJvci5kYXRhLmVtYWlsW2ldICsgJzxicj4nO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIFByVG9hc3QuZXJyb3IobXNnKTtcbiAgICAgICAgfVxuICAgICAgfSk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gY2xvc2VEaWFsb2coKSB7XG4gICAgICBQckRpYWxvZy5jbG9zZSgpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGNsZWFuRm9ybSgpIHtcbiAgICAgIHZtLnJlc2V0LmVtYWlsID0gJyc7XG4gICAgfVxuXG4gIH1cblxufSkoKTtcbiIsIi8qZXNsaW50IGFuZ3VsYXIvZmlsZS1uYW1lOiAwKi9cbihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5mYWN0b3J5KCdzZXJ2aWNlRmFjdG9yeScsIHNlcnZpY2VGYWN0b3J5KTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8qKlxuICAgKiBNYWlzIGluZm9ybWHDp8O1ZXM6XG4gICAqIGh0dHBzOi8vZ2l0aHViLmNvbS9zd2ltbGFuZS9hbmd1bGFyLW1vZGVsLWZhY3Rvcnkvd2lraS9BUElcbiAgICovXG4gIGZ1bmN0aW9uIHNlcnZpY2VGYWN0b3J5KCRtb2RlbEZhY3RvcnkpIHtcbiAgICByZXR1cm4gZnVuY3Rpb24odXJsLCBvcHRpb25zKSB7XG4gICAgICB2YXIgbW9kZWw7XG4gICAgICB2YXIgZGVmYXVsdE9wdGlvbnMgPSB7XG4gICAgICAgIGFjdGlvbnM6IHtcbiAgICAgICAgICAvKipcbiAgICAgICAgICAgKiBTZXJ2acOnbyBjb211bSBwYXJhIHJlYWxpemFyIGJ1c2NhIGNvbSBwYWdpbmHDp8Ojb1xuICAgICAgICAgICAqIE8gbWVzbW8gZXNwZXJhIHF1ZSBzZWphIHJldG9ybmFkbyB1bSBvYmpldG8gY29tIGl0ZW1zIGUgdG90YWxcbiAgICAgICAgICAgKi9cbiAgICAgICAgICBwYWdpbmF0ZToge1xuICAgICAgICAgICAgbWV0aG9kOiAnR0VUJyxcbiAgICAgICAgICAgIGlzQXJyYXk6IGZhbHNlLFxuICAgICAgICAgICAgd3JhcDogZmFsc2UsXG4gICAgICAgICAgICBhZnRlclJlcXVlc3Q6IGZ1bmN0aW9uKHJlc3BvbnNlKSB7XG4gICAgICAgICAgICAgIGlmIChyZXNwb25zZVsnaXRlbXMnXSkge1xuICAgICAgICAgICAgICAgIHJlc3BvbnNlWydpdGVtcyddID0gbW9kZWwuTGlzdChyZXNwb25zZVsnaXRlbXMnXSk7XG4gICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICByZXR1cm4gcmVzcG9uc2U7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICB9XG5cbiAgICAgIG1vZGVsID0gJG1vZGVsRmFjdG9yeSh1cmwsIGFuZ3VsYXIubWVyZ2UoZGVmYXVsdE9wdGlvbnMsIG9wdGlvbnMpKVxuXG4gICAgICByZXR1cm4gbW9kZWw7XG4gICAgfVxuICB9XG59KSgpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29udHJvbGxlcignQ1JVRENvbnRyb2xsZXInLCBDUlVEQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvKipcbiAgICogQ29udHJvbGFkb3IgQmFzZSBxdWUgaW1wbGVtZW50YSB0b2RhcyBhcyBmdW7Dp8O1ZXMgcGFkcsO1ZXMgZGUgdW0gQ1JVRFxuICAgKlxuICAgKiBBw6fDtWVzIGltcGxlbWVudGFkYXNcbiAgICogYWN0aXZhdGUoKVxuICAgKiBzZWFyY2gocGFnZSlcbiAgICogZWRpdChyZXNvdXJjZSlcbiAgICogc2F2ZSgpXG4gICAqIHJlbW92ZShyZXNvdXJjZSlcbiAgICogZ29Ubyh2aWV3TmFtZSlcbiAgICogY2xlYW5Gb3JtKClcbiAgICpcbiAgICogR2F0aWxob3NcbiAgICpcbiAgICogb25BY3RpdmF0ZSgpXG4gICAqIGFwcGx5RmlsdGVycyhkZWZhdWx0UXVlcnlGaWx0ZXJzKVxuICAgKiBiZWZvcmVTZWFyY2gocGFnZSkgLy9yZXRvcm5hbmRvIGZhbHNlIGNhbmNlbGEgbyBmbHV4b1xuICAgKiBhZnRlclNlYXJjaChyZXNwb25zZSlcbiAgICogYmVmb3JlQ2xlYW4gLy9yZXRvcm5hbmRvIGZhbHNlIGNhbmNlbGEgbyBmbHV4b1xuICAgKiBhZnRlckNsZWFuKClcbiAgICogYmVmb3JlU2F2ZSgpIC8vcmV0b3JuYW5kbyBmYWxzZSBjYW5jZWxhIG8gZmx1eG9cbiAgICogYWZ0ZXJTYXZlKHJlc291cmNlKVxuICAgKiBvblNhdmVFcnJvcihlcnJvcilcbiAgICogYmVmb3JlUmVtb3ZlKHJlc291cmNlKSAvL3JldG9ybmFuZG8gZmFsc2UgY2FuY2VsYSBvIGZsdXhvXG4gICAqIGFmdGVyUmVtb3ZlKHJlc291cmNlKVxuICAgKlxuICAgKiBAcGFyYW0ge2FueX0gdm0gaW5zdGFuY2lhIGRvIGNvbnRyb2xsZXIgZmlsaG9cbiAgICogQHBhcmFtIHthbnl9IG1vZGVsU2VydmljZSBzZXJ2acOnbyBkbyBtb2RlbCBxdWUgdmFpIHNlciB1dGlsaXphZG9cbiAgICogQHBhcmFtIHthbnl9IG9wdGlvbnMgb3DDp8O1ZXMgcGFyYSBzb2JyZWVzY3JldmVyIGNvbXBvcnRhbWVudG9zIHBhZHLDtWVzXG4gICAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBDUlVEQ29udHJvbGxlcih2bSwgbW9kZWxTZXJ2aWNlLCBvcHRpb25zLCBQclRvYXN0LCBQclBhZ2luYXRpb24sIC8vIE5PU09OQVJcbiAgICBQckRpYWxvZywgJHRyYW5zbGF0ZSkge1xuXG4gICAgLy9GdW5jdGlvbnMgQmxvY2tcbiAgICB2bS5zZWFyY2ggPSBzZWFyY2g7XG4gICAgdm0ucGFnaW5hdGVTZWFyY2ggPSBwYWdpbmF0ZVNlYXJjaDtcbiAgICB2bS5ub3JtYWxTZWFyY2ggPSBub3JtYWxTZWFyY2g7XG4gICAgdm0uZWRpdCA9IGVkaXQ7XG4gICAgdm0uc2F2ZSA9IHNhdmU7XG4gICAgdm0ucmVtb3ZlID0gcmVtb3ZlO1xuICAgIHZtLmdvVG8gPSBnb1RvO1xuICAgIHZtLmNsZWFuRm9ybSA9IGNsZWFuRm9ybTtcblxuICAgIGFjdGl2YXRlKCk7XG5cbiAgICAvKipcbiAgICAgKiBQcmVwYXJhIG8gY29udHJvbGFkb3JcbiAgICAgKiBGYXogbyBtZXJnZSBkYXMgb3DDp8O1ZXNcbiAgICAgKiBJbmljaWFsaXphIG8gcmVjdXJzb1xuICAgICAqIEluaWNpYWxpemEgbyBvYmpldG8gcGFnaW5hZG9yIGUgcmVhbGl6YSBhIHBlc3F1aXNhXG4gICAgICovXG4gICAgZnVuY3Rpb24gYWN0aXZhdGUoKSB7XG4gICAgICB2bS5kZWZhdWx0T3B0aW9ucyA9IHtcbiAgICAgICAgcmVkaXJlY3RBZnRlclNhdmU6IHRydWUsXG4gICAgICAgIHNlYXJjaE9uSW5pdDogdHJ1ZSxcbiAgICAgICAgcGVyUGFnZTogOCxcbiAgICAgICAgc2tpcFBhZ2luYXRpb246IGZhbHNlXG4gICAgICB9XG5cbiAgICAgIGFuZ3VsYXIubWVyZ2Uodm0uZGVmYXVsdE9wdGlvbnMsIG9wdGlvbnMpO1xuXG4gICAgICB2bS52aWV3Rm9ybSA9IGZhbHNlO1xuICAgICAgdm0ucmVzb3VyY2UgPSBuZXcgbW9kZWxTZXJ2aWNlKCk7XG5cbiAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0ub25BY3RpdmF0ZSkpIHZtLm9uQWN0aXZhdGUoKTtcblxuICAgICAgdm0ucGFnaW5hdG9yID0gUHJQYWdpbmF0aW9uLmdldEluc3RhbmNlKHZtLnNlYXJjaCwgdm0uZGVmYXVsdE9wdGlvbnMucGVyUGFnZSk7XG5cbiAgICAgIGlmICh2bS5kZWZhdWx0T3B0aW9ucy5zZWFyY2hPbkluaXQpIHZtLnNlYXJjaCgpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWxpemEgYSBwZXNxdWlzYVxuICAgICAqIFZlcmlmaWNhIHF1YWwgZGFzIGZ1bsOnw7VlcyBkZSBwZXNxdWlzYSBkZXZlIHNlciByZWFsaXphZGEuXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gcGFnZSBww6FnaW5hIHF1ZSBkZXZlIHNlciBjYXJyZWdhZGFcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBzZWFyY2gocGFnZSkge1xuICAgICAgKHZtLmRlZmF1bHRPcHRpb25zLnNraXBQYWdpbmF0aW9uKSA/IG5vcm1hbFNlYXJjaCgpIDogcGFnaW5hdGVTZWFyY2gocGFnZSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhbGl6YSBhIHBlc3F1aXNhIHBhZ2luYWRhIGNvbSBiYXNlIG5vcyBmaWx0cm9zIGRlZmluaWRvc1xuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IHBhZ2UgcMOhZ2luYSBxdWUgZGV2ZSBzZXIgY2FycmVnYWRhXG4gICAgICovXG4gICAgZnVuY3Rpb24gcGFnaW5hdGVTZWFyY2gocGFnZSkge1xuICAgICAgdm0ucGFnaW5hdG9yLmN1cnJlbnRQYWdlID0gKGFuZ3VsYXIuaXNEZWZpbmVkKHBhZ2UpKSA/IHBhZ2UgOiAxO1xuICAgICAgdm0uZGVmYXVsdFF1ZXJ5RmlsdGVycyA9IHsgcGFnZTogdm0ucGFnaW5hdG9yLmN1cnJlbnRQYWdlLCBwZXJQYWdlOiB2bS5wYWdpbmF0b3IucGVyUGFnZSB9O1xuXG4gICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmFwcGx5RmlsdGVycykpIHZtLmRlZmF1bHRRdWVyeUZpbHRlcnMgPSB2bS5hcHBseUZpbHRlcnModm0uZGVmYXVsdFF1ZXJ5RmlsdGVycyk7XG4gICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmJlZm9yZVNlYXJjaCkgJiYgdm0uYmVmb3JlU2VhcmNoKHBhZ2UpID09PSBmYWxzZSkgcmV0dXJuIGZhbHNlO1xuXG4gICAgICBtb2RlbFNlcnZpY2UucGFnaW5hdGUodm0uZGVmYXVsdFF1ZXJ5RmlsdGVycykudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgdm0ucGFnaW5hdG9yLmNhbGNOdW1iZXJPZlBhZ2VzKHJlc3BvbnNlLnRvdGFsKTtcbiAgICAgICAgdm0ucmVzb3VyY2VzID0gcmVzcG9uc2UuaXRlbXM7XG5cbiAgICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5hZnRlclNlYXJjaCkpIHZtLmFmdGVyU2VhcmNoKHJlc3BvbnNlKTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWxpemEgYSBwZXNxdWlzYSBjb20gYmFzZSBub3MgZmlsdHJvcyBkZWZpbmlkb3NcbiAgICAgKlxuICAgICAqL1xuICAgIGZ1bmN0aW9uIG5vcm1hbFNlYXJjaCgpIHtcbiAgICAgIHZtLmRlZmF1bHRRdWVyeUZpbHRlcnMgPSB7IH07XG5cbiAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYXBwbHlGaWx0ZXJzKSkgdm0uZGVmYXVsdFF1ZXJ5RmlsdGVycyA9IHZtLmFwcGx5RmlsdGVycyh2bS5kZWZhdWx0UXVlcnlGaWx0ZXJzKTtcbiAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYmVmb3JlU2VhcmNoKSAmJiB2bS5iZWZvcmVTZWFyY2goKSA9PT0gZmFsc2UpIHJldHVybiBmYWxzZTtcblxuICAgICAgbW9kZWxTZXJ2aWNlLnF1ZXJ5KHZtLmRlZmF1bHRRdWVyeUZpbHRlcnMpLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgIHZtLnJlc291cmNlcyA9IHJlc3BvbnNlO1xuXG4gICAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYWZ0ZXJTZWFyY2gpKSB2bS5hZnRlclNlYXJjaChyZXNwb25zZSk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBMaW1wYSBvIGZvcm11bMOhcmlvXG4gICAgICovXG4gICAgZnVuY3Rpb24gY2xlYW5Gb3JtKGZvcm0pIHtcbiAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYmVmb3JlQ2xlYW4pICYmIHZtLmJlZm9yZUNsZWFuKCkgPT09IGZhbHNlKSByZXR1cm4gZmFsc2U7XG5cbiAgICAgIHZtLnJlc291cmNlID0gbmV3IG1vZGVsU2VydmljZSgpO1xuXG4gICAgICBpZiAoYW5ndWxhci5pc0RlZmluZWQoZm9ybSkpIHtcbiAgICAgICAgZm9ybS4kc2V0UHJpc3RpbmUoKTtcbiAgICAgICAgZm9ybS4kc2V0VW50b3VjaGVkKCk7XG4gICAgICB9XG5cbiAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYWZ0ZXJDbGVhbikpIHZtLmFmdGVyQ2xlYW4oKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDYXJyZWdhIG5vIGZvcm11bMOhcmlvIG8gcmVjdXJzbyBzZWxlY2lvbmFkbyBwYXJhIGVkacOnw6NvXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gcmVzb3VyY2UgcmVjdXJzbyBzZWxlY2lvbmFkb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGVkaXQocmVzb3VyY2UpIHtcbiAgICAgIHZtLmdvVG8oJ2Zvcm0nKTtcbiAgICAgIHZtLnJlc291cmNlID0gbmV3IGFuZ3VsYXIuY29weShyZXNvdXJjZSk7XG5cbiAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYWZ0ZXJFZGl0KSkgdm0uYWZ0ZXJFZGl0KCk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogU2FsdmEgb3UgYXR1YWxpemEgbyByZWN1cnNvIGNvcnJlbnRlIG5vIGZvcm11bMOhcmlvXG4gICAgICogTm8gY29tcG9ydGFtZW50byBwYWRyw6NvIHJlZGlyZWNpb25hIG8gdXN1w6FyaW8gcGFyYSB2aWV3IGRlIGxpc3RhZ2VtXG4gICAgICogZGVwb2lzIGRhIGV4ZWN1w6fDo29cbiAgICAgKlxuICAgICAqIEByZXR1cm5zXG4gICAgICovXG4gICAgZnVuY3Rpb24gc2F2ZShmb3JtKSB7XG4gICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmJlZm9yZVNhdmUpICYmIHZtLmJlZm9yZVNhdmUoKSA9PT0gZmFsc2UpIHJldHVybiBmYWxzZTtcblxuICAgICAgdm0ucmVzb3VyY2UuJHNhdmUoKS50aGVuKGZ1bmN0aW9uIChyZXNvdXJjZSkge1xuICAgICAgICB2bS5yZXNvdXJjZSA9IHJlc291cmNlO1xuXG4gICAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYWZ0ZXJTYXZlKSkgdm0uYWZ0ZXJTYXZlKHJlc291cmNlKTtcblxuICAgICAgICBpZiAodm0uZGVmYXVsdE9wdGlvbnMucmVkaXJlY3RBZnRlclNhdmUpIHtcbiAgICAgICAgICB2bS5jbGVhbkZvcm0oZm9ybSk7XG4gICAgICAgICAgdm0uc2VhcmNoKHZtLnBhZ2luYXRvci5jdXJyZW50UGFnZSk7XG4gICAgICAgICAgdm0uZ29UbygnbGlzdCcpO1xuICAgICAgICB9XG5cbiAgICAgICAgUHJUb2FzdC5zdWNjZXNzKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMuc2F2ZVN1Y2Nlc3MnKSk7XG5cbiAgICAgIH0sIGZ1bmN0aW9uIChyZXNwb25zZURhdGEpIHtcbiAgICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5vblNhdmVFcnJvcikpIHZtLm9uU2F2ZUVycm9yKHJlc3BvbnNlRGF0YSk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZW1vdmUgbyByZWN1cnNvIGluZm9ybWFkby5cbiAgICAgKiBBbnRlcyBleGliZSB1bSBkaWFsb2dvIGRlIGNvbmZpcm1hw6fDo29cbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSByZXNvdXJjZSByZWN1cnNvIGVzY29saGlkb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIHJlbW92ZShyZXNvdXJjZSkge1xuICAgICAgdmFyIGNvbmZpZyA9IHtcbiAgICAgICAgdGl0bGU6ICR0cmFuc2xhdGUuaW5zdGFudCgnZGlhbG9nLmNvbmZpcm1UaXRsZScpLFxuICAgICAgICBkZXNjcmlwdGlvbjogJHRyYW5zbGF0ZS5pbnN0YW50KCdkaWFsb2cuY29uZmlybURlc2NyaXB0aW9uJylcbiAgICAgIH1cblxuICAgICAgUHJEaWFsb2cuY29uZmlybShjb25maWcpLnRoZW4oZnVuY3Rpb24oKSB7XG4gICAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYmVmb3JlUmVtb3ZlKSAmJiB2bS5iZWZvcmVSZW1vdmUocmVzb3VyY2UpID09PSBmYWxzZSkgcmV0dXJuIGZhbHNlO1xuXG4gICAgICAgIHJlc291cmNlLiRkZXN0cm95KCkudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5hZnRlclJlbW92ZSkpIHZtLmFmdGVyUmVtb3ZlKHJlc291cmNlKTtcblxuICAgICAgICAgIHZtLnNlYXJjaCgpO1xuICAgICAgICAgIFByVG9hc3QuaW5mbygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnJlbW92ZVN1Y2Nlc3MnKSk7XG4gICAgICAgIH0pO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQWx0ZXJuYSBlbnRyZSBhIHZpZXcgZG8gZm9ybXVsw6FyaW8gZSBsaXN0YWdlbVxuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IHZpZXdOYW1lIG5vbWUgZGEgdmlld1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGdvVG8odmlld05hbWUpIHtcbiAgICAgIHZtLnZpZXdGb3JtID0gZmFsc2U7XG5cbiAgICAgIGlmICh2aWV3TmFtZSA9PT0gJ2Zvcm0nKSB7XG4gICAgICAgIHZtLmNsZWFuRm9ybSgpO1xuICAgICAgICB2bS52aWV3Rm9ybSA9IHRydWU7XG4gICAgICB9XG4gICAgfVxuICB9XG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb250cm9sbGVyKCdEYXNoYm9hcmRDb250cm9sbGVyJywgRGFzaGJvYXJkQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvKipcbiAgICogRGFzaGJvYXJkIENvbnRyb2xsZXJcbiAgICpcbiAgICogUGFpbmVsIGNvbSBwcmluY2lwYWlzIGluZGljYWRvcmVzXG4gICAqXG4gICAqL1xuICBmdW5jdGlvbiBEYXNoYm9hcmRDb250cm9sbGVyKCkge1xuICAgIC8vIENvbnRyb2xsZXIgdmF6aW8gc29tZW50ZSBwYXJhIHNlciBkZWZpbmlkbyBjb21vIHDDoWdpbmEgcHJpbmNpcGFsLlxuICAgIC8vIERldmUgc2VyIGlkZW50aWZpY2FkbyBlIGFkaWNpb25hZG8gZ3LDoWZpY29zXG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb25maWcocm91dGVzKTtcblxuICAvKipcbiAgICogQXJxdWl2byBkZSBjb25maWd1cmHDp8OjbyBjb20gYXMgcm90YXMgZXNwZWPDrWZpY2FzIGRvIGRhc2hib2FyZFxuICAgKlxuICAgKiBAcGFyYW0ge2FueX0gJHN0YXRlUHJvdmlkZXJcbiAgICogQHBhcmFtIHthbnl9IEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyXG4gICAgICAuc3RhdGUoR2xvYmFsLmhvbWVTdGF0ZSwge1xuICAgICAgICB1cmw6ICcvZGFzaGJvYXJkJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9kYXNoYm9hcmQvZGFzaGJvYXJkLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnRGFzaGJvYXJkQ29udHJvbGxlciBhcyBkYXNoYm9hcmRDdHJsJyxcbiAgICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IHRydWUgfVxuICAgICAgfSlcbiAgfVxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb25maWcocm91dGVzKTtcblxuICAvKipcbiAgICogQXJxdWl2byBkZSBjb25maWd1cmHDp8OjbyBjb20gYXMgcm90YXMgZXNwZWPDrWZpY2FzIGRvIHJlY3Vyc28gdXNlclxuICAgKlxuICAgKiBAcGFyYW0ge2FueX0gJHN0YXRlUHJvdmlkZXJcbiAgICogQHBhcmFtIHthbnl9IEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyXG4gICAgICAuc3RhdGUoJ2FwcC5kaW5hbWljLXF1ZXJ5Jywge1xuICAgICAgICB1cmw6ICcvY29uc3VsdGFzLWRpbmFtaWNhcycsXG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvZGluYW1pYy1xdWVyeXMvZGluYW1pYy1xdWVyeXMuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdEaW5hbWljUXVlcnlzQ29udHJvbGxlciBhcyBkaW5hbWljUXVlcnlDdHJsJyxcbiAgICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IHRydWUsIG5lZWRQcm9maWxlOiBbJ2FkbWluJ10gfVxuICAgICAgfSk7XG5cbiAgfVxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5mYWN0b3J5KCdEaW5hbWljUXVlcnlTZXJ2aWNlJywgRGluYW1pY1F1ZXJ5U2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBEaW5hbWljUXVlcnlTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCdkaW5hbWljUXVlcnknLCB7XG4gICAgICAvKipcbiAgICAgICAqIGHDp8OjbyBhZGljaW9uYWRhIHBhcmEgcGVnYXIgdW1hIGxpc3RhIGRlIG1vZGVscyBleGlzdGVudGVzIG5vIHNlcnZpZG9yXG4gICAgICAgKi9cbiAgICAgIGFjdGlvbnM6IHtcbiAgICAgICAgZ2V0TW9kZWxzOiB7XG4gICAgICAgICAgbWV0aG9kOiAnR0VUJyxcbiAgICAgICAgICB1cmw6ICdtb2RlbHMnXG4gICAgICAgIH1cbiAgICAgIH0sXG4gICAgICBpbnN0YW5jZToge1xuICAgICAgfVxuICAgIH0pO1xuICB9XG5cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb250cm9sbGVyKCdEaW5hbWljUXVlcnlzQ29udHJvbGxlcicsIERpbmFtaWNRdWVyeXNDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIERpbmFtaWNRdWVyeXNDb250cm9sbGVyKCRjb250cm9sbGVyLCBEaW5hbWljUXVlcnlTZXJ2aWNlLCBsb2Rhc2gsIFByVG9hc3QsIC8vIE5PU09OQVJcbiAgICAkdHJhbnNsYXRlKSB7XG5cbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgLy9hY3Rpb25zXG4gICAgdm0ub25BY3RpdmF0ZSA9IG9uQWN0aXZhdGU7XG4gICAgdm0uYXBwbHlGaWx0ZXJzID0gYXBwbHlGaWx0ZXJzO1xuICAgIHZtLmxvYWRBdHRyaWJ1dGVzID0gbG9hZEF0dHJpYnV0ZXM7XG4gICAgdm0ubG9hZE9wZXJhdG9ycyA9IGxvYWRPcGVyYXRvcnM7XG4gICAgdm0uYWRkRmlsdGVyID0gYWRkRmlsdGVyO1xuICAgIHZtLmFmdGVyU2VhcmNoID0gYWZ0ZXJTZWFyY2g7XG4gICAgdm0ucnVuRmlsdGVyID0gcnVuRmlsdGVyO1xuICAgIHZtLmVkaXRGaWx0ZXIgPSBlZGl0RmlsdGVyO1xuICAgIHZtLmxvYWRNb2RlbHMgPSBsb2FkTW9kZWxzO1xuICAgIHZtLnJlbW92ZUZpbHRlciA9IHJlbW92ZUZpbHRlcjtcbiAgICB2bS5jbGVhciA9IGNsZWFyO1xuICAgIHZtLnJlc3RhcnQgPSByZXN0YXJ0O1xuXG4gICAgLy9oZXJkYSBvIGNvbXBvcnRhbWVudG8gYmFzZSBkbyBDUlVEXG4gICAgJGNvbnRyb2xsZXIoJ0NSVURDb250cm9sbGVyJywgeyB2bTogdm0sIG1vZGVsU2VydmljZTogRGluYW1pY1F1ZXJ5U2VydmljZSwgb3B0aW9uczoge1xuICAgICAgc2VhcmNoT25Jbml0OiBmYWxzZVxuICAgIH0gfSk7XG5cbiAgICBmdW5jdGlvbiBvbkFjdGl2YXRlKCkge1xuICAgICAgdm0ucmVzdGFydCgpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFByZXBhcmEgZSBhcGxpY2Egb3MgZmlsdHJvIHF1ZSB2w6NvIHNlciBlbnZpYWRvcyBwYXJhIG8gc2VydmnDp29cbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSBkZWZhdWx0UXVlcnlGaWx0ZXJzXG4gICAgICogQHJldHVybnNcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBhcHBseUZpbHRlcnMoZGVmYXVsdFF1ZXJ5RmlsdGVycykge1xuICAgICAgdmFyIHdoZXJlID0ge307XG5cbiAgICAgIC8qKlxuICAgICAgICogbyBzZXJ2acOnbyBlc3BlcmEgdW0gb2JqZXRvIGNvbTpcbiAgICAgICAqICBvIG5vbWUgZGUgdW0gbW9kZWxcbiAgICAgICAqICB1bWEgbGlzdGEgZGUgZmlsdHJvc1xuICAgICAgICovXG4gICAgICBpZiAodm0uYWRkZWRGaWx0ZXJzLmxlbmd0aCA+IDApIHtcbiAgICAgICAgdmFyIGFkZGVkRmlsdGVycyA9IGFuZ3VsYXIuY29weSh2bS5hZGRlZEZpbHRlcnMpO1xuXG4gICAgICAgIHdoZXJlLm1vZGVsID0gdm0uYWRkZWRGaWx0ZXJzWzBdLm1vZGVsLm5hbWU7XG5cbiAgICAgICAgZm9yICh2YXIgaW5kZXggPSAwOyBpbmRleCA8IGFkZGVkRmlsdGVycy5sZW5ndGg7IGluZGV4KyspIHtcbiAgICAgICAgICB2YXIgZmlsdGVyID0gYWRkZWRGaWx0ZXJzW2luZGV4XTtcblxuICAgICAgICAgIGZpbHRlci5tb2RlbCA9IG51bGw7XG4gICAgICAgICAgZmlsdGVyLmF0dHJpYnV0ZSA9IGZpbHRlci5hdHRyaWJ1dGUubmFtZTtcbiAgICAgICAgICBmaWx0ZXIub3BlcmF0b3IgPSBmaWx0ZXIub3BlcmF0b3IudmFsdWU7XG4gICAgICAgIH1cblxuICAgICAgICB3aGVyZS5maWx0ZXJzID0gYW5ndWxhci50b0pzb24oYWRkZWRGaWx0ZXJzKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHdoZXJlLm1vZGVsID0gdm0ucXVlcnlGaWx0ZXJzLm1vZGVsLm5hbWU7XG4gICAgICB9XG5cbiAgICAgIHJldHVybiBhbmd1bGFyLmV4dGVuZChkZWZhdWx0UXVlcnlGaWx0ZXJzLCB3aGVyZSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ2FycmVnYSB0b2RvcyBvcyBtb2RlbHMgY3JpYWRvcyBubyBzZXJ2aWRvciBjb20gc2V1cyBhdHJpYnV0b3NcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBsb2FkTW9kZWxzKCkge1xuICAgICAgLy9QZWdhIHRvZG9zIG9zIG1vZGVscyBkbyBzZXJ2ZXIgZSBtb250YSB1bWEgbGlzdGEgcHJvIENvbWJvQm94XG4gICAgICBEaW5hbWljUXVlcnlTZXJ2aWNlLmdldE1vZGVscygpLnRoZW4oZnVuY3Rpb24oZGF0YSkge1xuICAgICAgICB2bS5tb2RlbHMgPSBkYXRhO1xuICAgICAgICB2bS5xdWVyeUZpbHRlcnMubW9kZWwgPSB2bS5tb2RlbHNbMF07XG4gICAgICAgIHZtLmxvYWRBdHRyaWJ1dGVzKCk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDYXJyZWdhIG9zIGF0dHJpYnV0b3MgZG8gbW9kZWwgZXNjb2xoaWRvXG4gICAgICovXG4gICAgZnVuY3Rpb24gbG9hZEF0dHJpYnV0ZXMoKSB7XG4gICAgICB2bS5hdHRyaWJ1dGVzID0gdm0ucXVlcnlGaWx0ZXJzLm1vZGVsLmF0dHJpYnV0ZXM7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMuYXR0cmlidXRlID0gdm0uYXR0cmlidXRlc1swXTtcblxuICAgICAgdm0ubG9hZE9wZXJhdG9ycygpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENhcnJlZ2Egb3Mgb3BlcmFkb3JlcyBlc3BlY2lmaWNvcyBwYXJhIG8gdGlwbyBkbyBhdHJpYnV0b1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGxvYWRPcGVyYXRvcnMoKSB7XG4gICAgICB2YXIgb3BlcmF0b3JzID0gW1xuICAgICAgICB7IHZhbHVlOiAnPScsIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLmVxdWFscycpIH0sXG4gICAgICAgIHsgdmFsdWU6ICc8PicsIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLmRpZmVyZW50JykgfVxuICAgICAgXVxuXG4gICAgICBpZiAodm0ucXVlcnlGaWx0ZXJzLmF0dHJpYnV0ZS50eXBlLmluZGV4T2YoJ3ZhcnlpbmcnKSAhPT0gLTEpIHtcbiAgICAgICAgb3BlcmF0b3JzLnB1c2goeyB2YWx1ZTogJ2hhcycsXG4gICAgICAgICAgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudCgndmlld3MuZmllbGRzLnF1ZXJ5RGluYW1pYy5vcGVyYXRvcnMuY29udGVpbnMnKSB9KTtcbiAgICAgICAgb3BlcmF0b3JzLnB1c2goeyB2YWx1ZTogJ3N0YXJ0V2l0aCcsXG4gICAgICAgICAgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudCgndmlld3MuZmllbGRzLnF1ZXJ5RGluYW1pYy5vcGVyYXRvcnMuc3RhcnRXaXRoJykgfSk7XG4gICAgICAgIG9wZXJhdG9ycy5wdXNoKHsgdmFsdWU6ICdlbmRXaXRoJyxcbiAgICAgICAgICBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KCd2aWV3cy5maWVsZHMucXVlcnlEaW5hbWljLm9wZXJhdG9ycy5maW5pc2hXaXRoJykgfSk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBvcGVyYXRvcnMucHVzaCh7IHZhbHVlOiAnPicsXG4gICAgICAgICAgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudCgndmlld3MuZmllbGRzLnF1ZXJ5RGluYW1pYy5vcGVyYXRvcnMuYmlnZ2VyVGhhbicpIH0pO1xuICAgICAgICBvcGVyYXRvcnMucHVzaCh7IHZhbHVlOiAnPj0nLFxuICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLmVxdWFsc09yQmlnZ2VyVGhhbicpIH0pO1xuICAgICAgICBvcGVyYXRvcnMucHVzaCh7IHZhbHVlOiAnPCcsXG4gICAgICAgICAgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudCgndmlld3MuZmllbGRzLnF1ZXJ5RGluYW1pYy5vcGVyYXRvcnMubGVzc1RoYW4nKSB9KTtcbiAgICAgICAgb3BlcmF0b3JzLnB1c2goeyB2YWx1ZTogJzw9JyxcbiAgICAgICAgICBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KCd2aWV3cy5maWVsZHMucXVlcnlEaW5hbWljLm9wZXJhdG9ycy5lcXVhbHNPckxlc3NUaGFuJykgfSk7XG4gICAgICB9XG5cbiAgICAgIHZtLm9wZXJhdG9ycyA9IG9wZXJhdG9ycztcbiAgICAgIHZtLnF1ZXJ5RmlsdGVycy5vcGVyYXRvciA9IHZtLm9wZXJhdG9yc1swXTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBBZGljaW9uYS9lZGl0YSB1bSBmaWx0cm9cbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSBmb3JtIGVsZW1lbnRvIGh0bWwgZG8gZm9ybXVsw6FyaW8gcGFyYSB2YWxpZGHDp8O1ZXNcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBhZGRGaWx0ZXIoZm9ybSkge1xuICAgICAgaWYgKGFuZ3VsYXIuaXNVbmRlZmluZWQodm0ucXVlcnlGaWx0ZXJzLnZhbHVlKSB8fCB2bS5xdWVyeUZpbHRlcnMudmFsdWUgPT09ICcnKSB7XG4gICAgICAgIFByVG9hc3QuZXJyb3IoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy52YWxpZGF0ZS5maWVsZFJlcXVpcmVkJywgeyBmaWVsZDogJ3ZhbG9yJyB9KSk7XG4gICAgICAgIHJldHVybjtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIGlmICh2bS5pbmRleCA8IDApIHtcbiAgICAgICAgICB2bS5hZGRlZEZpbHRlcnMucHVzaChhbmd1bGFyLmNvcHkodm0ucXVlcnlGaWx0ZXJzKSk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgdm0uYWRkZWRGaWx0ZXJzW3ZtLmluZGV4XSA9IGFuZ3VsYXIuY29weSh2bS5xdWVyeUZpbHRlcnMpO1xuICAgICAgICAgIHZtLmluZGV4ID0gLTE7XG4gICAgICAgIH1cblxuICAgICAgICAvL3JlaW5pY2lhIG8gZm9ybXVsw6FyaW8gZSBhcyB2YWxpZGHDp8O1ZXMgZXhpc3RlbnRlc1xuICAgICAgICB2bS5xdWVyeUZpbHRlcnMgPSB7fTtcbiAgICAgICAgZm9ybS4kc2V0UHJpc3RpbmUoKTtcbiAgICAgICAgZm9ybS4kc2V0VW50b3VjaGVkKCk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhbGl6YSBhIHBlc3F1aXNhIHRlbmRvIG9zIGZpbHRyb3MgY29tbyBwYXLDom1ldHJvc1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIHJ1bkZpbHRlcigpIHtcbiAgICAgIHZtLnNlYXJjaCh2bS5wYWdpbmF0b3IuY3VycmVudFBhZ2UpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEdhdGlsaG8gYWNpb25hZG8gZGVwb2lzIGRhIHBlc3F1aXNhIHJlc3BvbnPDoXZlbCBwb3IgaWRlbnRpZmljYXIgb3MgYXRyaWJ1dG9zXG4gICAgICogY29udGlkb3Mgbm9zIGVsZW1lbnRvcyByZXN1bHRhbnRlcyBkYSBidXNjYVxuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IGRhdGEgZGFkb3MgcmVmZXJlbnRlIGFvIHJldG9ybm8gZGEgcmVxdWlzacOnw6NvXG4gICAgICovXG4gICAgZnVuY3Rpb24gYWZ0ZXJTZWFyY2goZGF0YSkge1xuICAgICAgdmFyIGtleXMgPSAoZGF0YS5pdGVtcy5sZW5ndGggPiAwKSA/IE9iamVjdC5rZXlzKGRhdGEuaXRlbXNbMF0pIDogW107XG5cbiAgICAgIC8vcmV0aXJhIHRvZG9zIG9zIGF0cmlidXRvcyBxdWUgY29tZcOnYW0gY29tICQuXG4gICAgICAvL0Vzc2VzIGF0cmlidXRvcyBzw6NvIGFkaWNpb25hZG9zIHBlbG8gc2VydmnDp28gZSBuw6NvIGRldmUgYXBhcmVjZXIgbmEgbGlzdGFnZW1cbiAgICAgIHZtLmtleXMgPSBsb2Rhc2guZmlsdGVyKGtleXMsIGZ1bmN0aW9uKGtleSkge1xuICAgICAgICByZXR1cm4gIWxvZGFzaC5zdGFydHNXaXRoKGtleSwgJyQnKTtcbiAgICAgIH0pXG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ29sb2FjYSBubyBmb3JtdWzDoXJpbyBvIGZpbHRybyBlc2NvbGhpZG8gcGFyYSBlZGnDp8Ojb1xuICAgICAqIEBwYXJhbSB7YW55fSAkaW5kZXggaW5kaWNlIG5vIGFycmF5IGRvIGZpbHRybyBlc2NvbGhpZG9cbiAgICAgKi9cbiAgICBmdW5jdGlvbiBlZGl0RmlsdGVyKCRpbmRleCkge1xuICAgICAgdm0uaW5kZXggPSAkaW5kZXg7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMgPSB2bS5hZGRlZEZpbHRlcnNbJGluZGV4XTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZW1vdmUgbyBmaWx0cm8gZXNjb2xoaWRvXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gJGluZGV4IGluZGljZSBubyBhcnJheSBkbyBmaWx0cm8gZXNjb2xoaWRvXG4gICAgICovXG4gICAgZnVuY3Rpb24gcmVtb3ZlRmlsdGVyKCRpbmRleCkge1xuICAgICAgdm0uYWRkZWRGaWx0ZXJzLnNwbGljZSgkaW5kZXgpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIExpbXBhIG8gZm9ybXVsw6FyaW8gY29ycmVudGVcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBjbGVhcigpIHtcbiAgICAgIC8vZ3VhcmRhIG8gaW5kaWNlIGRvIHJlZ2lzdHJvIHF1ZSBlc3TDoSBzZW5kbyBlZGl0YWRvXG4gICAgICB2bS5pbmRleCA9IC0xO1xuICAgICAgLy92aW5jdWxhZG8gYW9zIGNhbXBvcyBkbyBmb3JtdWzDoXJpb1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0ge1xuICAgICAgfTtcblxuICAgICAgaWYgKHZtLm1vZGVscykgdm0ucXVlcnlGaWx0ZXJzLm1vZGVsID0gdm0ubW9kZWxzWzBdO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlaW5pY2lhIGEgY29uc3RydcOnw6NvIGRhIHF1ZXJ5IGxpbXBhbmRvIHR1ZG9cbiAgICAgKlxuICAgICAqL1xuICAgIGZ1bmN0aW9uIHJlc3RhcnQoKSB7XG4gICAgICAvL2d1YXJkYSBhdHJpYnV0b3MgZG8gcmVzdWx0YWRvIGRhIGJ1c2NhIGNvcnJlbnRlXG4gICAgICB2bS5rZXlzID0gW107XG5cbiAgICAgIC8vZ3VhcmRhIG9zIGZpbHRyb3MgYWRpY2lvbmFkb3NcbiAgICAgIHZtLmFkZGVkRmlsdGVycyA9IFtdO1xuICAgICAgdm0uY2xlYXIoKTtcbiAgICAgIHZtLmxvYWRNb2RlbHMoKTtcbiAgICB9XG5cbiAgfVxuXG59KSgpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmFjdG9yeSgnbGFuZ3VhZ2VMb2FkZXInLCBMYW5ndWFnZUxvYWRlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBMYW5ndWFnZUxvYWRlcigkcSwgU3VwcG9ydFNlcnZpY2UsICRsb2csICRpbmplY3Rvcikge1xuICAgIHZhciBzZXJ2aWNlID0gdGhpcztcblxuICAgIHNlcnZpY2UudHJhbnNsYXRlID0gZnVuY3Rpb24obG9jYWxlKSB7XG4gICAgICByZXR1cm4ge1xuICAgICAgICBnbG9iYWw6ICRpbmplY3Rvci5nZXQobG9jYWxlICsgJy5pMThuLmdsb2JhbCcpLFxuICAgICAgICB2aWV3czogJGluamVjdG9yLmdldChsb2NhbGUgKyAnLmkxOG4udmlld3MnKSxcbiAgICAgICAgYXR0cmlidXRlczogJGluamVjdG9yLmdldChsb2NhbGUgKyAnLmkxOG4uYXR0cmlidXRlcycpLFxuICAgICAgICBkaWFsb2c6ICRpbmplY3Rvci5nZXQobG9jYWxlICsgJy5pMThuLmRpYWxvZycpLFxuICAgICAgICBtZXNzYWdlczogJGluamVjdG9yLmdldChsb2NhbGUgKyAnLmkxOG4ubWVzc2FnZXMnKSxcbiAgICAgICAgbW9kZWxzOiAkaW5qZWN0b3IuZ2V0KGxvY2FsZSArICcuaTE4bi5tb2RlbHMnKVxuICAgICAgfTtcbiAgICB9XG5cbiAgICAvLyByZXR1cm4gbG9hZGVyRm5cbiAgICByZXR1cm4gZnVuY3Rpb24ob3B0aW9ucykge1xuICAgICAgJGxvZy5pbmZvKCdDYXJyZWdhbmRvIG8gY29udGV1ZG8gZGEgbGluZ3VhZ2VtICcgKyBvcHRpb25zLmtleSk7XG5cbiAgICAgIHZhciBkZWZlcnJlZCA9ICRxLmRlZmVyKCk7XG5cbiAgICAgIC8vQ2FycmVnYSBhcyBsYW5ncyBxdWUgcHJlY2lzYW0gZSBlc3TDo28gbm8gc2Vydmlkb3IgcGFyYSBuw6NvIHByZWNpc2FyIHJlcGV0aXIgYXF1aVxuICAgICAgU3VwcG9ydFNlcnZpY2UubGFuZ3MoKS50aGVuKGZ1bmN0aW9uKGxhbmdzKSB7XG4gICAgICAgIC8vTWVyZ2UgY29tIG9zIGxhbmdzIGRlZmluaWRvcyBubyBzZXJ2aWRvclxuICAgICAgICB2YXIgZGF0YSA9IGFuZ3VsYXIubWVyZ2Uoc2VydmljZS50cmFuc2xhdGUob3B0aW9ucy5rZXkpLCBsYW5ncyk7XG5cbiAgICAgICAgcmV0dXJuIGRlZmVycmVkLnJlc29sdmUoZGF0YSk7XG4gICAgICB9LCBmdW5jdGlvbigpIHtcbiAgICAgICAgcmV0dXJuIGRlZmVycmVkLnJlc29sdmUoc2VydmljZS50cmFuc2xhdGUob3B0aW9ucy5rZXkpKTtcbiAgICAgIH0pO1xuXG4gICAgICByZXR1cm4gZGVmZXJyZWQucHJvbWlzZTtcbiAgICB9XG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZpbHRlcigndEF0dHInLCB0QXR0cik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiB0QXR0cigkZmlsdGVyKSB7XG4gICAgLyoqXG4gICAgICogRmlsdHJvIHBhcmEgdHJhZHXDp8OjbyBkZSB1bSBhdHJpYnV0byBkZSB1bSBtb2RlbFxuICAgICAqIFxuICAgICAqIEBwYXJhbSB7YW55fSBuYW1lIG5vbWUgZG8gYXRyaWJ1dG9cbiAgICAgKiBAcmV0dXJucyBvIG5vbWUgZG8gYXRyaWJ1dG8gdHJhZHV6aWRvIGNhc28gZW5jb250cmUgc2UgbsOjbyBvIG5vbWUgcGFzc2FkbyBwb3IgcGFyYW1ldHJvXG4gICAgICovICAgIFxuICAgIHJldHVybiBmdW5jdGlvbihuYW1lKSB7XG4gICAgICB2YXIga2V5ID0gJ2F0dHJpYnV0ZXMuJyArIG5hbWU7XG4gICAgICB2YXIgdHJhbnNsYXRlID0gJGZpbHRlcigndHJhbnNsYXRlJykoa2V5KTtcblxuICAgICAgcmV0dXJuICh0cmFuc2xhdGUgPT09IGtleSkgPyBuYW1lIDogdHJhbnNsYXRlO1xuICAgIH1cbiAgfVxuXG59KSgpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmlsdGVyKCd0QnJlYWRjcnVtYicsIHRCcmVhZGNydW1iKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIHRCcmVhZGNydW1iKCRmaWx0ZXIpIHtcbiAgICAvKipcbiAgICAgKiBGaWx0cm8gcGFyYSB0cmFkdcOnw6NvIGRvIGJyZWFkY3J1bWIgKHRpdHVsbyBkYSB0ZWxhIGNvbSByYXN0cmVpbylcbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSBpZCBjaGF2ZSBjb20gbyBub21lIGRvIHN0YXRlIHJlZmVyZW50ZSB0ZWxhXG4gICAgICogQHJldHVybnMgYSB0cmFkdcOnw6NvIGNhc28gZW5jb250cmUgc2UgbsOjbyBvIGlkIHBhc3NhZG8gcG9yIHBhcmFtZXRyb1xuICAgICAqL1xuICAgIHJldHVybiBmdW5jdGlvbihpZCkge1xuICAgICAgLy9wZWdhIGEgc2VndW5kYSBwYXJ0ZSBkbyBub21lIGRvIHN0YXRlLCByZXRpcmFuZG8gYSBwYXJ0ZSBhYnN0cmF0YSAoYXBwLilcbiAgICAgIHZhciBrZXkgPSAndmlld3MuYnJlYWRjcnVtYnMuJyArIGlkLnNwbGl0KCcuJylbMV07XG4gICAgICB2YXIgdHJhbnNsYXRlID0gJGZpbHRlcigndHJhbnNsYXRlJykoa2V5KTtcblxuICAgICAgcmV0dXJuICh0cmFuc2xhdGUgPT09IGtleSkgPyBpZCA6IHRyYW5zbGF0ZTtcbiAgICB9XG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZpbHRlcigndE1vZGVsJywgdE1vZGVsKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIHRNb2RlbCgkZmlsdGVyKSB7XG4gICAgLyoqXG4gICAgICogRmlsdHJvIHBhcmEgdHJhZHXDp8OjbyBkZSB1bSBhdHJpYnV0byBkZSB1bSBtb2RlbFxuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IG5hbWUgbm9tZSBkbyBhdHJpYnV0b1xuICAgICAqIEByZXR1cm5zIG8gbm9tZSBkbyBhdHJpYnV0byB0cmFkdXppZG8gY2FzbyBlbmNvbnRyZSBzZSBuw6NvIG8gbm9tZSBwYXNzYWRvIHBvciBwYXJhbWV0cm9cbiAgICAgKi9cbiAgICByZXR1cm4gZnVuY3Rpb24obmFtZSkge1xuICAgICAgdmFyIGtleSA9ICdtb2RlbHMuJyArIG5hbWUudG9Mb3dlckNhc2UoKTtcbiAgICAgIHZhciB0cmFuc2xhdGUgPSAkZmlsdGVyKCd0cmFuc2xhdGUnKShrZXkpO1xuXG4gICAgICByZXR1cm4gKHRyYW5zbGF0ZSA9PT0ga2V5KSA/IG5hbWUgOiB0cmFuc2xhdGU7XG4gICAgfVxuICB9XG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAucnVuKGF1dGhlbnRpY2F0aW9uTGlzdGVuZXIpO1xuXG4gIC8qKlxuICAgKiBMaXN0ZW4gYWxsIHN0YXRlIChwYWdlKSBjaGFuZ2VzLiBFdmVyeSB0aW1lIGEgc3RhdGUgY2hhbmdlIG5lZWQgdG8gdmVyaWZ5IHRoZSB1c2VyIGlzIGF1dGhlbnRpY2F0ZWQgb3Igbm90IHRvXG4gICAqIHJlZGlyZWN0IHRvIGNvcnJlY3QgcGFnZS4gV2hlbiBhIHVzZXIgY2xvc2UgdGhlIGJyb3dzZXIgd2l0aG91dCBsb2dvdXQsIHdoZW4gaGltIHJlb3BlbiB0aGUgYnJvd3NlciB0aGlzIGV2ZW50XG4gICAqIHJlYXV0aGVudGljYXRlIHRoZSB1c2VyIHdpdGggdGhlIHBlcnNpc3RlbnQgdG9rZW4gb2YgdGhlIGxvY2FsIHN0b3JhZ2UuXG4gICAqXG4gICAqIFdlIGRvbid0IGNoZWNrIGlmIHRoZSB0b2tlbiBpcyBleHBpcmVkIG9yIG5vdCBpbiB0aGUgcGFnZSBjaGFuZ2UsIGJlY2F1c2UgaXMgZ2VuZXJhdGUgYW4gdW5lY2Vzc2FyeSBvdmVyaGVhZC5cbiAgICogSWYgdGhlIHRva2VuIGlzIGV4cGlyZWQgd2hlbiB0aGUgdXNlciB0cnkgdG8gY2FsbCB0aGUgZmlyc3QgYXBpIHRvIGdldCBkYXRhLCBoaW0gd2lsbCBiZSBsb2dvZmYgYW5kIHJlZGlyZWN0XG4gICAqIHRvIGxvZ2luIHBhZ2UuXG4gICAqXG4gICAqIEBwYXJhbSAkcm9vdFNjb3BlXG4gICAqIEBwYXJhbSAkc3RhdGVcbiAgICogQHBhcmFtICRzdGF0ZVBhcmFtc1xuICAgKiBAcGFyYW0gQXV0aFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBhdXRoZW50aWNhdGlvbkxpc3RlbmVyKCRyb290U2NvcGUsICRzdGF0ZSwgR2xvYmFsLCBBdXRoLCBQclRvYXN0LCAvLyBOT1NPTkFSXG4gICAgJHRyYW5zbGF0ZSkge1xuXG4gICAgLy9vbmx5IHdoZW4gYXBwbGljYXRpb24gc3RhcnQgY2hlY2sgaWYgdGhlIGV4aXN0ZW50IHRva2VuIHN0aWxsIHZhbGlkXG4gICAgQXV0aC5yZW1vdGVWYWxpZGF0ZVRva2VuKCkudGhlbihmdW5jdGlvbigpIHtcbiAgICAgIC8vaWYgdGhlIHRva2VuIGlzIHZhbGlkIGNoZWNrIGlmIGV4aXN0cyB0aGUgdXNlciBiZWNhdXNlIHRoZSBicm93c2VyIGNvdWxkIGJlIGNsb3NlZFxuICAgICAgLy9hbmQgdGhlIHVzZXIgZGF0YSBpc24ndCBpbiBtZW1vcnlcbiAgICAgIGlmIChBdXRoLmN1cnJlbnRVc2VyID09PSBudWxsKSB7XG4gICAgICAgIEF1dGgudXBkYXRlQ3VycmVudFVzZXIoYW5ndWxhci5mcm9tSnNvbihsb2NhbFN0b3JhZ2UuZ2V0SXRlbSgndXNlcicpKSk7XG4gICAgICB9XG4gICAgfSk7XG5cbiAgICAvL0NoZWNrIGlmIHRoZSB0b2tlbiBzdGlsbCB2YWxpZC5cbiAgICAkcm9vdFNjb3BlLiRvbignJHN0YXRlQ2hhbmdlU3RhcnQnLCBmdW5jdGlvbihldmVudCwgdG9TdGF0ZSkge1xuICAgICAgaWYgKHRvU3RhdGUuZGF0YS5uZWVkQXV0aGVudGljYXRpb24gfHwgdG9TdGF0ZS5kYXRhLm5lZWRQcm9maWxlKSB7XG4gICAgICAgIC8vZG9udCB0cmFpdCB0aGUgc3VjY2VzcyBibG9jayBiZWNhdXNlIGFscmVhZHkgZGlkIGJ5IHRva2VuIGludGVyY2VwdG9yXG4gICAgICAgIEF1dGgucmVtb3RlVmFsaWRhdGVUb2tlbigpLmNhdGNoKGZ1bmN0aW9uKCkge1xuICAgICAgICAgIFByVG9hc3Qud2FybigkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLmxvZ2luLmxvZ291dEluYWN0aXZlJykpO1xuXG4gICAgICAgICAgaWYgKHRvU3RhdGUubmFtZSAhPT0gR2xvYmFsLmxvZ2luU3RhdGUpIHtcbiAgICAgICAgICAgICRzdGF0ZS5nbyhHbG9iYWwubG9naW5TdGF0ZSk7XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgZXZlbnQucHJldmVudERlZmF1bHQoKTtcbiAgICAgICAgfSk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICAvL2lmIHRoZSB1c2UgaXMgYXV0aGVudGljYXRlZCBhbmQgbmVlZCB0byBlbnRlciBpbiBsb2dpbiBwYWdlXG4gICAgICAgIC8vaGltIHdpbGwgYmUgcmVkaXJlY3RlZCB0byBob21lIHBhZ2VcbiAgICAgICAgaWYgKHRvU3RhdGUubmFtZSA9PT0gR2xvYmFsLmxvZ2luU3RhdGUgJiYgQXV0aC5hdXRoZW50aWNhdGVkKCkpIHtcbiAgICAgICAgICAkc3RhdGUuZ28oR2xvYmFsLmhvbWVTdGF0ZSk7XG4gICAgICAgICAgZXZlbnQucHJldmVudERlZmF1bHQoKTtcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pO1xuICB9XG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLnJ1bihhdXRob3JpemF0aW9uTGlzdGVuZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gYXV0aG9yaXphdGlvbkxpc3RlbmVyKCRyb290U2NvcGUsICRzdGF0ZSwgR2xvYmFsLCBBdXRoKSB7XG4gICAgLyoqXG4gICAgICogQSBjYWRhIG11ZGFuw6dhIGRlIGVzdGFkbyAoXCJww6FnaW5hXCIpIHZlcmlmaWNhIHNlIG8gdXN1w6FyaW8gdGVtIG8gcGVyZmlsXG4gICAgICogbmVjZXNzw6FyaW8gcGFyYSBvIGFjZXNzbyBhIG1lc21hXG4gICAgICovXG4gICAgJHJvb3RTY29wZS4kb24oJyRzdGF0ZUNoYW5nZVN0YXJ0JywgZnVuY3Rpb24oZXZlbnQsIHRvU3RhdGUpIHtcbiAgICAgIGlmICh0b1N0YXRlLmRhdGEgJiYgdG9TdGF0ZS5kYXRhLm5lZWRBdXRoZW50aWNhdGlvbiAmJlxuICAgICAgICB0b1N0YXRlLmRhdGEubmVlZFByb2ZpbGUgJiYgQXV0aC5hdXRoZW50aWNhdGVkKCkgJiZcbiAgICAgICAgIUF1dGguY3VycmVudFVzZXIuaGFzUHJvZmlsZSh0b1N0YXRlLmRhdGEubmVlZFByb2ZpbGUsIHRvU3RhdGUuZGF0YS5hbGxQcm9maWxlcykpIHtcblxuICAgICAgICAkc3RhdGUuZ28oR2xvYmFsLm5vdEF1dGhvcml6ZWRTdGF0ZSk7XG4gICAgICAgIGV2ZW50LnByZXZlbnREZWZhdWx0KCk7XG4gICAgICB9XG5cbiAgICB9KTtcbiAgfVxufSgpKTtcbiIsIihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uZmlnKHNwaW5uZXJJbnRlcmNlcHRvcik7XG5cbiAgZnVuY3Rpb24gc3Bpbm5lckludGVyY2VwdG9yKCRodHRwUHJvdmlkZXIsICRwcm92aWRlKSB7XG4gICAgLyoqXG4gICAgICogRXN0ZSBpbnRlcmNlcHRvciDDqSByZXNwb25zw6F2ZWwgcG9yIG1vc3RyYXIgZSBlc2NvbmRlciBvXG4gICAgICogY29tcG9uZW50ZSBQclNwaW5uZXIgc2VtcHJlIHF1ZSB1bWEgcmVxdWlzacOnw6NvIGFqYXhcbiAgICAgKiBpbmljaWFyIGUgZmluYWxpemFyLlxuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9ICRxXG4gICAgICogQHBhcmFtIHthbnl9ICRpbmplY3RvclxuICAgICAqIEByZXR1cm5zXG4gICAgICovXG4gICAgZnVuY3Rpb24gc2hvd0hpZGVTcGlubmVyKCRxLCAkaW5qZWN0b3IpIHtcbiAgICAgIHJldHVybiB7XG4gICAgICAgIHJlcXVlc3Q6IGZ1bmN0aW9uIChjb25maWcpIHtcbiAgICAgICAgICAkaW5qZWN0b3IuZ2V0KCdQclNwaW5uZXInKS5zaG93KCk7XG5cbiAgICAgICAgICByZXR1cm4gY29uZmlnO1xuICAgICAgICB9LFxuXG4gICAgICAgIHJlc3BvbnNlOiBmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgICAkaW5qZWN0b3IuZ2V0KCdQclNwaW5uZXInKS5oaWRlKCk7XG5cbiAgICAgICAgICByZXR1cm4gcmVzcG9uc2U7XG4gICAgICAgIH0sXG5cbiAgICAgICAgcmVzcG9uc2VFcnJvcjogZnVuY3Rpb24gKHJlamVjdGlvbikge1xuICAgICAgICAgICRpbmplY3Rvci5nZXQoJ1ByU3Bpbm5lcicpLmhpZGUoKTtcblxuICAgICAgICAgIHJldHVybiAkcS5yZWplY3QocmVqZWN0aW9uKTtcbiAgICAgICAgfVxuICAgICAgfTtcbiAgICB9XG5cbiAgICAvLyBEZWZpbmUgdW1hIGZhY3RvcnkgcGFyYSBvICRodHRwSW50ZXJjZXB0b3JcbiAgICAkcHJvdmlkZS5mYWN0b3J5KCdzaG93SGlkZVNwaW5uZXInLCBzaG93SGlkZVNwaW5uZXIpO1xuXG4gICAgLy8gQWRpY2lvbmEgYSBmYWN0b3J5IG5vIGFycmF5IGRlIGludGVyY2VwdG9ycyBkbyAkaHR0cFxuICAgICRodHRwUHJvdmlkZXIuaW50ZXJjZXB0b3JzLnB1c2goJ3Nob3dIaWRlU3Bpbm5lcicpO1xuICB9XG59KCkpO1xuIiwiLyplc2xpbnQgYW5ndWxhci9tb2R1bGUtZ2V0dGVyOiAwKi9cblxuKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbmZpZyh0b2tlbkludGVyY2VwdG9yKTtcblxuICAvKipcbiAgICogSW50ZXJjZXB0IGFsbCByZXNwb25zZSAoc3VjY2VzcyBvciBlcnJvcikgdG8gdmVyaWZ5IHRoZSByZXR1cm5lZCB0b2tlblxuICAgKlxuICAgKiBAcGFyYW0gJGh0dHBQcm92aWRlclxuICAgKiBAcGFyYW0gJHByb3ZpZGVcbiAgICogQHBhcmFtIEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiB0b2tlbkludGVyY2VwdG9yKCRodHRwUHJvdmlkZXIsICRwcm92aWRlLCBHbG9iYWwpIHtcblxuICAgIGZ1bmN0aW9uIHJlZGlyZWN0V2hlblNlcnZlckxvZ2dlZE91dCgkcSwgJGluamVjdG9yKSB7XG4gICAgICByZXR1cm4ge1xuICAgICAgICByZXF1ZXN0OiBmdW5jdGlvbihjb25maWcpIHtcbiAgICAgICAgICB2YXIgdG9rZW4gPSAkaW5qZWN0b3IuZ2V0KCdBdXRoJykuZ2V0VG9rZW4oKTtcblxuICAgICAgICAgIGlmICh0b2tlbikge1xuICAgICAgICAgICAgY29uZmlnLmhlYWRlcnNbJ0F1dGhvcml6YXRpb24nXSA9ICdCZWFyZXIgJyArIHRva2VuO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIHJldHVybiBjb25maWc7XG4gICAgICAgIH0sXG4gICAgICAgIHJlc3BvbnNlOiBmdW5jdGlvbihyZXNwb25zZSkge1xuICAgICAgICAgIC8vIGdldCBhIG5ldyByZWZyZXNoIHRva2VuIHRvIHVzZSBpbiB0aGUgbmV4dCByZXF1ZXN0XG4gICAgICAgICAgdmFyIHRva2VuID0gcmVzcG9uc2UuaGVhZGVycygnQXV0aG9yaXphdGlvbicpO1xuXG4gICAgICAgICAgaWYgKHRva2VuKSB7XG4gICAgICAgICAgICAkaW5qZWN0b3IuZ2V0KCdBdXRoJykuc2V0VG9rZW4odG9rZW4uc3BsaXQoJyAnKVsxXSk7XG4gICAgICAgICAgfVxuICAgICAgICAgIHJldHVybiByZXNwb25zZTtcbiAgICAgICAgfSxcbiAgICAgICAgcmVzcG9uc2VFcnJvcjogZnVuY3Rpb24ocmVqZWN0aW9uKSB7XG4gICAgICAgICAgLy8gSW5zdGVhZCBvZiBjaGVja2luZyBmb3IgYSBzdGF0dXMgY29kZSBvZiA0MDAgd2hpY2ggbWlnaHQgYmUgdXNlZFxuICAgICAgICAgIC8vIGZvciBvdGhlciByZWFzb25zIGluIExhcmF2ZWwsIHdlIGNoZWNrIGZvciB0aGUgc3BlY2lmaWMgcmVqZWN0aW9uXG4gICAgICAgICAgLy8gcmVhc29ucyB0byB0ZWxsIHVzIGlmIHdlIG5lZWQgdG8gcmVkaXJlY3QgdG8gdGhlIGxvZ2luIHN0YXRlXG4gICAgICAgICAgdmFyIHJlamVjdGlvblJlYXNvbnMgPSBbJ3Rva2VuX25vdF9wcm92aWRlZCcsICd0b2tlbl9leHBpcmVkJywgJ3Rva2VuX2Fic2VudCcsICd0b2tlbl9pbnZhbGlkJ107XG5cbiAgICAgICAgICB2YXIgdG9rZW5FcnJvciA9IGZhbHNlO1xuXG4gICAgICAgICAgYW5ndWxhci5mb3JFYWNoKHJlamVjdGlvblJlYXNvbnMsIGZ1bmN0aW9uKHZhbHVlKSB7XG4gICAgICAgICAgICBpZiAocmVqZWN0aW9uLmRhdGEgJiYgcmVqZWN0aW9uLmRhdGEuZXJyb3IgPT09IHZhbHVlKSB7XG4gICAgICAgICAgICAgIHRva2VuRXJyb3IgPSB0cnVlO1xuXG4gICAgICAgICAgICAgICRpbmplY3Rvci5nZXQoJ0F1dGgnKS5sb2dvdXQoKS50aGVuKGZ1bmN0aW9uKCkge1xuICAgICAgICAgICAgICAgIHZhciAkc3RhdGUgPSAkaW5qZWN0b3IuZ2V0KCckc3RhdGUnKTtcblxuICAgICAgICAgICAgICAgIC8vIGluIGNhc2UgbXVsdGlwbGUgYWpheCByZXF1ZXN0IGZhaWwgYXQgc2FtZSB0aW1lIGJlY2F1c2UgdG9rZW4gcHJvYmxlbXMsXG4gICAgICAgICAgICAgICAgLy8gb25seSB0aGUgZmlyc3Qgd2lsbCByZWRpcmVjdFxuICAgICAgICAgICAgICAgIGlmICghJHN0YXRlLmlzKEdsb2JhbC5sb2dpblN0YXRlKSkge1xuICAgICAgICAgICAgICAgICAgJHN0YXRlLmdvKEdsb2JhbC5sb2dpblN0YXRlKTtcblxuICAgICAgICAgICAgICAgICAgLy9jbG9zZSBhbnkgZGlhbG9nIHRoYXQgaXMgb3BlbmVkXG4gICAgICAgICAgICAgICAgICAkaW5qZWN0b3IuZ2V0KCdQckRpYWxvZycpLmNsb3NlKCk7XG5cbiAgICAgICAgICAgICAgICAgIGV2ZW50LnByZXZlbnREZWZhdWx0KCk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9KTtcblxuICAgICAgICAgIC8vZGVmaW5lIGRhdGEgdG8gZW1wdHkgYmVjYXVzZSBhbHJlYWR5IHNob3cgUHJUb2FzdCB0b2tlbiBtZXNzYWdlXG4gICAgICAgICAgaWYgKHRva2VuRXJyb3IpIHtcbiAgICAgICAgICAgIHJlamVjdGlvbi5kYXRhID0ge307XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbihyZWplY3Rpb24uaGVhZGVycykpIHtcbiAgICAgICAgICAgIC8vIG1hbnkgc2VydmVycyBlcnJvcnMgKGJ1c2luZXNzKSBhcmUgaW50ZXJjZXB0IGhlcmUgYnV0IGdlbmVyYXRlZCBhIG5ldyByZWZyZXNoIHRva2VuXG4gICAgICAgICAgICAvLyBhbmQgbmVlZCB1cGRhdGUgY3VycmVudCB0b2tlblxuICAgICAgICAgICAgdmFyIHRva2VuID0gcmVqZWN0aW9uLmhlYWRlcnMoJ0F1dGhvcml6YXRpb24nKTtcblxuICAgICAgICAgICAgaWYgKHRva2VuKSB7XG4gICAgICAgICAgICAgICRpbmplY3Rvci5nZXQoJ0F1dGgnKS5zZXRUb2tlbih0b2tlbi5zcGxpdCgnICcpWzFdKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9XG5cbiAgICAgICAgICByZXR1cm4gJHEucmVqZWN0KHJlamVjdGlvbik7XG4gICAgICAgIH1cbiAgICAgIH07XG4gICAgfVxuXG4gICAgLy8gU2V0dXAgZm9yIHRoZSAkaHR0cEludGVyY2VwdG9yXG4gICAgJHByb3ZpZGUuZmFjdG9yeSgncmVkaXJlY3RXaGVuU2VydmVyTG9nZ2VkT3V0JywgcmVkaXJlY3RXaGVuU2VydmVyTG9nZ2VkT3V0KTtcblxuICAgIC8vIFB1c2ggdGhlIG5ldyBmYWN0b3J5IG9udG8gdGhlICRodHRwIGludGVyY2VwdG9yIGFycmF5XG4gICAgJGh0dHBQcm92aWRlci5pbnRlcmNlcHRvcnMucHVzaCgncmVkaXJlY3RXaGVuU2VydmVyTG9nZ2VkT3V0Jyk7XG4gIH1cblxufSgpKTtcbiIsIihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uZmlnKHZhbGlkYXRpb25JbnRlcmNlcHRvcik7XG5cbiAgZnVuY3Rpb24gdmFsaWRhdGlvbkludGVyY2VwdG9yKCRodHRwUHJvdmlkZXIsICRwcm92aWRlKSB7XG4gICAgLyoqXG4gICAgICogRXN0ZSBpbnRlcmNlcHRvciDDqSByZXNwb25zw6F2ZWwgcG9yIG1vc3RyYXIgYXNcbiAgICAgKiBtZW5zYWdlbnMgZGUgZXJybyByZWZlcmVudGUgYXMgdmFsaWRhw6fDtWVzIGRvIGJhY2stZW5kXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gJHFcbiAgICAgKiBAcGFyYW0ge2FueX0gJGluamVjdG9yXG4gICAgICogQHJldHVybnNcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBzaG93RXJyb3JWYWxpZGF0aW9uKCRxLCAkaW5qZWN0b3IpIHtcbiAgICAgIHJldHVybiB7XG4gICAgICAgIHJlc3BvbnNlRXJyb3I6IGZ1bmN0aW9uIChyZWplY3Rpb24pIHtcbiAgICAgICAgICB2YXIgUHJUb2FzdCA9ICRpbmplY3Rvci5nZXQoJ1ByVG9hc3QnKTtcbiAgICAgICAgICB2YXIgJHRyYW5zbGF0ZSA9ICRpbmplY3Rvci5nZXQoJyR0cmFuc2xhdGUnKTtcblxuICAgICAgICAgIGlmIChyZWplY3Rpb24uY29uZmlnLmRhdGEgJiYgIXJlamVjdGlvbi5jb25maWcuZGF0YS5za2lwVmFsaWRhdGlvbikge1xuICAgICAgICAgICAgaWYgKHJlamVjdGlvbi5kYXRhICYmIHJlamVjdGlvbi5kYXRhLmVycm9yKSB7XG5cbiAgICAgICAgICAgICAgLy92ZXJpZmljYSBzZSBvY29ycmV1IGFsZ3VtIGVycm8gcmVmZXJlbnRlIGFvIHRva2VuXG4gICAgICAgICAgICAgIGlmIChyZWplY3Rpb24uZGF0YS5lcnJvci5zdGFydHNXaXRoKCd0b2tlbl8nKSkge1xuICAgICAgICAgICAgICAgIFByVG9hc3Qud2FybigkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLmxvZ2luLmxvZ291dEluYWN0aXZlJykpO1xuICAgICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICAgIFByVG9hc3QuZXJyb3IoJHRyYW5zbGF0ZS5pbnN0YW50KHJlamVjdGlvbi5kYXRhLmVycm9yKSk7XG4gICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgIFByVG9hc3QuZXJyb3JWYWxpZGF0aW9uKHJlamVjdGlvbi5kYXRhKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9XG5cbiAgICAgICAgICByZXR1cm4gJHEucmVqZWN0KHJlamVjdGlvbik7XG4gICAgICAgIH1cbiAgICAgIH07XG4gICAgfVxuXG4gICAgLy8gRGVmaW5lIHVtYSBmYWN0b3J5IHBhcmEgbyAkaHR0cEludGVyY2VwdG9yXG4gICAgJHByb3ZpZGUuZmFjdG9yeSgnc2hvd0Vycm9yVmFsaWRhdGlvbicsIHNob3dFcnJvclZhbGlkYXRpb24pO1xuXG4gICAgLy8gQWRpY2lvbmEgYSBmYWN0b3J5IG5vIGFycmF5IGRlIGludGVyY2VwdG9ycyBkbyAkaHR0cFxuICAgICRodHRwUHJvdmlkZXIuaW50ZXJjZXB0b3JzLnB1c2goJ3Nob3dFcnJvclZhbGlkYXRpb24nKTtcbiAgfVxufSgpKTtcbiIsIi8qZXNsaW50LWVudiBlczYqL1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29udHJvbGxlcignTWVudUNvbnRyb2xsZXInLCBNZW51Q29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiBNZW51Q29udHJvbGxlcigkbWRTaWRlbmF2LCAkc3RhdGUsICRtZENvbG9ycykge1xuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICAvL0Jsb2NvIGRlIGRlY2xhcmFjb2VzIGRlIGZ1bmNvZXNcbiAgICB2bS5vcGVuID0gb3BlbjtcbiAgICB2bS5vcGVuTWVudU9yUmVkaXJlY3RUb1N0YXRlID0gb3Blbk1lbnVPclJlZGlyZWN0VG9TdGF0ZTtcblxuICAgIGFjdGl2YXRlKCk7XG5cbiAgICBmdW5jdGlvbiBhY3RpdmF0ZSgpIHtcbiAgICAgIHZhciBtZW51UHJlZml4ID0gJ3ZpZXdzLmxheW91dC5tZW51Lic7XG5cbiAgICAgIC8vIEFycmF5IGNvbnRlbmRvIG9zIGl0ZW5zIHF1ZSBzw6NvIG1vc3RyYWRvcyBubyBtZW51IGxhdGVyYWxcbiAgICAgIHZtLml0ZW5zTWVudSA9IFtcbiAgICAgICAgeyBzdGF0ZTogJ2FwcC5kYXNoYm9hcmQnLCB0aXRsZTogbWVudVByZWZpeCArICdkYXNoYm9hcmQnLCBpY29uOiAnZGFzaGJvYXJkJywgc3ViSXRlbnM6IFtdIH0sXG4gICAgICAgIHtcbiAgICAgICAgICBzdGF0ZTogJyMnLCB0aXRsZTogbWVudVByZWZpeCArICdleGFtcGxlcycsIGljb246ICd2aWV3X2Nhcm91c2VsJywgcHJvZmlsZXM6IFsnYWRtaW4nXSxcbiAgICAgICAgICBzdWJJdGVuczogW1xuICAgICAgICAgICAgeyBzdGF0ZTogJ2FwcC5wcm9qZWN0JywgdGl0bGU6IG1lbnVQcmVmaXggKyAncHJvamVjdCcsIGljb246ICdzdGFyJyB9XG4gICAgICAgICAgXVxuICAgICAgICB9LFxuICAgICAgICAvLyBDb2xvcXVlIHNldXMgaXRlbnMgZGUgbWVudSBhIHBhcnRpciBkZXN0ZSBwb250b1xuICAgICAgICB7XG4gICAgICAgICAgc3RhdGU6ICcjJywgdGl0bGU6IG1lbnVQcmVmaXggKyAnYWRtaW4nLCBpY29uOiAnc2V0dGluZ3NfYXBwbGljYXRpb25zJywgcHJvZmlsZXM6IFsnYWRtaW4nXSxcbiAgICAgICAgICBzdWJJdGVuczogW1xuICAgICAgICAgICAgeyBzdGF0ZTogJ2FwcC51c2VyJywgdGl0bGU6IG1lbnVQcmVmaXggKyAndXNlcicsIGljb246ICdwZW9wbGUnIH0sXG4gICAgICAgICAgICB7IHN0YXRlOiAnYXBwLm1haWwnLCB0aXRsZTogbWVudVByZWZpeCArICdtYWlsJywgaWNvbjogJ21haWwnIH0sXG4gICAgICAgICAgICB7IHN0YXRlOiAnYXBwLmF1ZGl0JywgdGl0bGU6IG1lbnVQcmVmaXggKyAnYXVkaXQnLCBpY29uOiAnc3RvcmFnZScgfSxcbiAgICAgICAgICAgIHsgc3RhdGU6ICdhcHAuZGluYW1pYy1xdWVyeScsIHRpdGxlOiBtZW51UHJlZml4ICsgJ2RpbmFtaWNRdWVyeScsIGljb246ICdsb2NhdGlvbl9zZWFyY2hpbmcnIH1cbiAgICAgICAgICBdXG4gICAgICAgIH1cbiAgICAgIF07XG5cbiAgICAgIC8qKlxuICAgICAgICogT2JqZXRvIHF1ZSBwcmVlbmNoZSBvIG5nLXN0eWxlIGRvIG1lbnUgbGF0ZXJhbCB0cm9jYW5kbyBhcyBjb3Jlc1xuICAgICAgICovXG4gICAgICB2bS5zaWRlbmF2U3R5bGUgPSB7XG4gICAgICAgIHRvcDoge1xuICAgICAgICAgICdib3JkZXItYm90dG9tJzogJzFweCBzb2xpZCAnICsgZ2V0Q29sb3IoJ3ByaW1hcnknKSxcbiAgICAgICAgICAnYmFja2dyb3VuZC1pbWFnZSc6ICctd2Via2l0LWxpbmVhci1ncmFkaWVudCh0b3AsICcrZ2V0Q29sb3IoJ3ByaW1hcnktNTAwJykrJywgJytnZXRDb2xvcigncHJpbWFyeS04MDAnKSsnKSdcbiAgICAgICAgfSxcbiAgICAgICAgY29udGVudDoge1xuICAgICAgICAgICdiYWNrZ3JvdW5kLWNvbG9yJzogZ2V0Q29sb3IoJ3ByaW1hcnktODAwJylcbiAgICAgICAgfSxcbiAgICAgICAgdGV4dENvbG9yOiB7XG4gICAgICAgICAgY29sb3I6ICcjRkZGJ1xuICAgICAgICB9LFxuICAgICAgICBsaW5lQm90dG9tOiB7XG4gICAgICAgICAgJ2JvcmRlci1ib3R0b20nOiAnMXB4IHNvbGlkICcgKyBnZXRDb2xvcigncHJpbWFyeS00MDAnKVxuICAgICAgICB9XG4gICAgICB9XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gb3BlbigpIHtcbiAgICAgICRtZFNpZGVuYXYoJ2xlZnQnKS50b2dnbGUoKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBNw6l0b2RvIHF1ZSBleGliZSBvIHN1YiBtZW51IGRvcyBpdGVucyBkbyBtZW51IGxhdGVyYWwgY2FzbyB0ZW5oYSBzdWIgaXRlbnNcbiAgICAgKiBjYXNvIGNvbnRyw6FyaW8gcmVkaXJlY2lvbmEgcGFyYSBvIHN0YXRlIHBhc3NhZG8gY29tbyBwYXLDom1ldHJvXG4gICAgICovXG4gICAgZnVuY3Rpb24gb3Blbk1lbnVPclJlZGlyZWN0VG9TdGF0ZSgkbWRNZW51LCBldiwgaXRlbSkge1xuICAgICAgaWYgKGFuZ3VsYXIuaXNEZWZpbmVkKGl0ZW0uc3ViSXRlbnMpICYmIGl0ZW0uc3ViSXRlbnMubGVuZ3RoID4gMCkge1xuICAgICAgICAkbWRNZW51Lm9wZW4oZXYpO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgJHN0YXRlLmdvKGl0ZW0uc3RhdGUpO1xuICAgICAgICAkbWRTaWRlbmF2KCdsZWZ0JykuY2xvc2UoKTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICBmdW5jdGlvbiBnZXRDb2xvcihjb2xvclBhbGV0dGVzKSB7XG4gICAgICByZXR1cm4gJG1kQ29sb3JzLmdldFRoZW1lQ29sb3IoY29sb3JQYWxldHRlcyk7XG4gICAgfVxuXG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnRyb2xsZXIoJ01haWxzQ29udHJvbGxlcicsIE1haWxzQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBNYWlsc0NvbnRyb2xsZXIoTWFpbHNTZXJ2aWNlLCBVc2Vyc1NlcnZpY2UsIFByRGlhbG9nLCBQclRvYXN0LCAvLyBOT1NPTkFSXG4gICAgJHEsIGxvZGFzaCwgJHRyYW5zbGF0ZSwgR2xvYmFsKSB7XG5cbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0uZmlsdGVyU2VsZWN0ZWQgPSBmYWxzZTtcbiAgICB2bS5vcHRpb25zID0ge1xuICAgICAgc2tpbjogJ2thbWEnLFxuICAgICAgbGFuZ3VhZ2U6ICdwdC1icicsXG4gICAgICBhbGxvd2VkQ29udGVudDogdHJ1ZSxcbiAgICAgIGVudGl0aWVzOiB0cnVlLFxuICAgICAgaGVpZ2h0OiAzMDAsXG4gICAgICBleHRyYVBsdWdpbnM6ICdkaWFsb2csZmluZCxjb2xvcmRpYWxvZyxwcmV2aWV3LGZvcm1zLGlmcmFtZSxmbGFzaCdcbiAgICB9O1xuXG4gICAgdm0ubG9hZFVzZXJzID0gbG9hZFVzZXJzO1xuICAgIHZtLm9wZW5Vc2VyRGlhbG9nID0gb3BlblVzZXJEaWFsb2c7XG4gICAgdm0uYWRkVXNlck1haWwgPSBhZGRVc2VyTWFpbDtcbiAgICB2bS5jbGVhbkZvcm0gPSBjbGVhbkZvcm07XG4gICAgdm0uc2VuZCA9IHNlbmQ7XG5cbiAgICBhY3RpdmF0ZSgpO1xuXG4gICAgZnVuY3Rpb24gYWN0aXZhdGUoKSB7XG4gICAgICB2bS5jbGVhbkZvcm0oKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFsaXphIGEgYnVzY2EgcGVsbyB1c3XDoXJpbyByZW1vdGFtZW50ZVxuICAgICAqXG4gICAgICogQHBhcmFtcyB7c3RyaW5nfSAtIFJlY2ViZSBvIHZhbG9yIHBhcmEgc2VyIHBlc3F1aXNhZG9cbiAgICAgKiBAcmV0dXJuIHtwcm9taXNzZX0gLSBSZXRvcm5hIHVtYSBwcm9taXNzZSBxdWUgbyBjb21wb25ldGUgcmVzb2x2ZVxuICAgICAqL1xuICAgIGZ1bmN0aW9uIGxvYWRVc2Vycyhjcml0ZXJpYSkge1xuICAgICAgdmFyIGRlZmVycmVkID0gJHEuZGVmZXIoKTtcblxuICAgICAgVXNlcnNTZXJ2aWNlLnF1ZXJ5KHtcbiAgICAgICAgbmFtZU9yRW1haWw6IGNyaXRlcmlhLFxuICAgICAgICBub3RVc2VyczogbG9kYXNoLm1hcCh2bS5tYWlsLnVzZXJzLCBsb2Rhc2gucHJvcGVydHkoJ2lkJykpLnRvU3RyaW5nKCksXG4gICAgICAgIGxpbWl0OiA1XG4gICAgICB9KS50aGVuKGZ1bmN0aW9uKGRhdGEpIHtcblxuICAgICAgICAvLyB2ZXJpZmljYSBzZSBuYSBsaXN0YSBkZSB1c3VhcmlvcyBqw6EgZXhpc3RlIG8gdXN1w6FyaW8gY29tIG8gZW1haWwgcGVzcXVpc2Fkb1xuICAgICAgICBkYXRhID0gbG9kYXNoLmZpbHRlcihkYXRhLCBmdW5jdGlvbih1c2VyKSB7XG4gICAgICAgICAgcmV0dXJuICFsb2Rhc2guZmluZCh2bS5tYWlsLnVzZXJzLCB7IGVtYWlsOiB1c2VyLmVtYWlsIH0pO1xuICAgICAgICB9KTtcblxuICAgICAgICBkZWZlcnJlZC5yZXNvbHZlKGRhdGEpO1xuICAgICAgfSk7XG5cbiAgICAgIHJldHVybiBkZWZlcnJlZC5wcm9taXNlO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEFicmUgbyBkaWFsb2cgcGFyYSBwZXNxdWlzYSBkZSB1c3XDoXJpb3NcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBvcGVuVXNlckRpYWxvZygpIHtcbiAgICAgIHZhciBjb25maWcgPSB7XG4gICAgICAgIGxvY2Fsczoge1xuICAgICAgICAgIG9uSW5pdDogdHJ1ZSxcbiAgICAgICAgICB1c2VyRGlhbG9nSW5wdXQ6IHtcbiAgICAgICAgICAgIHRyYW5zZmVyVXNlckZuOiB2bS5hZGRVc2VyTWFpbFxuICAgICAgICAgIH1cbiAgICAgICAgfSxcbiAgICAgICAgY29udHJvbGxlcjogJ1VzZXJzRGlhbG9nQ29udHJvbGxlcicsXG4gICAgICAgIGNvbnRyb2xsZXJBczogJ2N0cmwnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL3VzZXJzL2RpYWxvZy91c2Vycy1kaWFsb2cuaHRtbCcsXG4gICAgICAgIGhhc0JhY2tkcm9wOiB0cnVlXG4gICAgICB9O1xuXG4gICAgICBQckRpYWxvZy5jdXN0b20oY29uZmlnKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBBZGljaW9uYSBvIHVzdcOhcmlvIHNlbGVjaW9uYWRvIG5hIGxpc3RhIHBhcmEgcXVlIHNlamEgZW52aWFkbyBvIGVtYWlsXG4gICAgICovXG4gICAgZnVuY3Rpb24gYWRkVXNlck1haWwodXNlcikge1xuICAgICAgdmFyIHVzZXJzID0gbG9kYXNoLmZpbmQodm0ubWFpbC51c2VycywgeyBlbWFpbDogdXNlci5lbWFpbCB9KTtcblxuICAgICAgaWYgKHZtLm1haWwudXNlcnMubGVuZ3RoID4gMCAmJiBhbmd1bGFyLmlzRGVmaW5lZCh1c2VycykpIHtcbiAgICAgICAgUHJUb2FzdC53YXJuKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMudXNlci51c2VyRXhpc3RzJykpO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgdm0ubWFpbC51c2Vycy5wdXNoKHsgbmFtZTogdXNlci5uYW1lLCBlbWFpbDogdXNlci5lbWFpbCB9KVxuICAgICAgfVxuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWxpemEgbyBlbnZpbyBkbyBlbWFpbCBwYXJhIGEgbGlzdGEgZGUgdXN1w6FyaW9zIHNlbGVjaW9uYWRvc1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIHNlbmQoKSB7XG5cbiAgICAgIHZtLm1haWwuJHNhdmUoKS50aGVuKGZ1bmN0aW9uKHJlc3BvbnNlKSB7XG4gICAgICAgIGlmIChyZXNwb25zZS5sZW5ndGggPiAwKSB7XG4gICAgICAgICAgdmFyIG1zZyA9ICR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMubWFpbC5tYWlsRXJyb3JzJyk7XG5cbiAgICAgICAgICBmb3IgKHZhciBpPTA7IGkgPCByZXNwb25zZS5sZW5ndGg7IGkrKykge1xuICAgICAgICAgICAgbXNnICs9IHJlc3BvbnNlICsgJ1xcbic7XG4gICAgICAgICAgfVxuICAgICAgICAgIFByVG9hc3QuZXJyb3IobXNnKTtcbiAgICAgICAgICB2bS5jbGVhbkZvcm0oKTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICBQclRvYXN0LnN1Y2Nlc3MoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5tYWlsLnNlbmRNYWlsU3VjY2VzcycpKTtcbiAgICAgICAgICB2bS5jbGVhbkZvcm0oKTtcbiAgICAgICAgfVxuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogTGltcGEgbyBmb3JtdWzDoXJpbyBkZSBlbWFpbFxuICAgICAqL1xuICAgIGZ1bmN0aW9uIGNsZWFuRm9ybSgpIHtcbiAgICAgIHZtLm1haWwgPSBuZXcgTWFpbHNTZXJ2aWNlKCk7XG4gICAgICB2bS5tYWlsLnVzZXJzID0gW107XG4gICAgfVxuXG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb25maWcocm91dGVzKTtcblxuICAvKipcbiAgICogQXJxdWl2byBkZSBjb25maWd1cmHDp8OjbyBjb20gYXMgcm90YXMgZXNwZWPDrWZpY2FzIGRvIHJlY3Vyc28gZW0gcXVlc3TDo29cbiAgICpcbiAgICogQHBhcmFtIHthbnl9ICRzdGF0ZVByb3ZpZGVyXG4gICAqIEBwYXJhbSB7YW55fSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlclxuICAgICAgLnN0YXRlKCdhcHAubWFpbCcsIHtcbiAgICAgICAgdXJsOiAnL2VtYWlsJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9tYWlsL21haWxzLXNlbmQuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdNYWlsc0NvbnRyb2xsZXIgYXMgbWFpbHNDdHJsJyxcbiAgICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IHRydWUsIG5lZWRQcm9maWxlOiBbJ2FkbWluJ10gfVxuICAgICAgfSk7XG5cbiAgfVxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5mYWN0b3J5KCdNYWlsc1NlcnZpY2UnLCBNYWlsc1NlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gTWFpbHNTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCdtYWlscycsIHt9KTtcbiAgfVxuXG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmlsdGVyKCdyb2xlc1N0cicsIHJvbGVzU3RyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvbGVzU3RyKGxvZGFzaCkge1xuICAgIC8qKlxuICAgICAqIEBwYXJhbSB7YXJyYXl9IHJvbGVzIGxpc3RhIGRlIHBlcmZpc1xuICAgICAqIEByZXR1cm4ge3N0cmluZ30gcGVyZmlzIHNlcGFyYWRvcyBwb3IgJywgJyAgXG4gICAgICovXG4gICAgcmV0dXJuIGZ1bmN0aW9uKHJvbGVzKSB7XG4gICAgICByZXR1cm4gbG9kYXNoLm1hcChyb2xlcywgJ3NsdWcnKS5qb2luKCcsICcpO1xuICAgIH07XG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5mYWN0b3J5KCdSb2xlc1NlcnZpY2UnLCBSb2xlc1NlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gUm9sZXNTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCdyb2xlcycpO1xuICB9XG5cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmFjdG9yeSgnU3VwcG9ydFNlcnZpY2UnLCBTdXBwb3J0U2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiBTdXBwb3J0U2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHJldHVybiBzZXJ2aWNlRmFjdG9yeSgnc3VwcG9ydCcsIHtcbiAgICAgIGFjdGlvbnM6IHtcbiAgICAgIC8qKlxuICAgICAgICogUGVnYSBhcyB0cmFkdcOnw7VlcyBxdWUgZXN0w6NvIG5vIHNlcnZpZG9yXG4gICAgICAgKlxuICAgICAgICogQHJldHVybnMge3Byb21pc2V9IFVtYSBwcm9taXNlIGNvbSBvIHJlc3VsdGFkbyBkbyBjaGFtYWRhIG5vIGJhY2tlbmRcbiAgICAgICAqL1xuICAgICAgICBsYW5nczoge1xuICAgICAgICAgIG1ldGhvZDogJ0dFVCcsXG4gICAgICAgICAgdXJsOiAnbGFuZ3MnLFxuICAgICAgICAgIHdyYXA6IGZhbHNlLFxuICAgICAgICAgIGNhY2hlOiB0cnVlXG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9KTtcbiAgfVxuXG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29udHJvbGxlcignUHJvZmlsZUNvbnRyb2xsZXInLCBQcm9maWxlQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBQcm9maWxlQ29udHJvbGxlcihVc2Vyc1NlcnZpY2UsIEF1dGgsIFByVG9hc3QsICR0cmFuc2xhdGUpIHtcbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0udXBkYXRlID0gdXBkYXRlO1xuXG4gICAgYWN0aXZhdGUoKTtcblxuICAgIGZ1bmN0aW9uIGFjdGl2YXRlKCkge1xuICAgICAgdm0udXNlciA9IGFuZ3VsYXIuY29weShBdXRoLmN1cnJlbnRVc2VyKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiB1cGRhdGUoKSB7XG4gICAgICBVc2Vyc1NlcnZpY2UudXBkYXRlUHJvZmlsZSh2bS51c2VyKS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICAvL2F0dWFsaXphIG8gdXN1w6FyaW8gY29ycmVudGUgY29tIGFzIG5vdmFzIGluZm9ybWHDp8O1ZXNcbiAgICAgICAgQXV0aC51cGRhdGVDdXJyZW50VXNlcihyZXNwb25zZSk7XG4gICAgICAgIFByVG9hc3Quc3VjY2VzcygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnNhdmVTdWNjZXNzJykpO1xuICAgICAgfSk7XG4gICAgfVxuICB9XG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb250cm9sbGVyKCdVc2Vyc0NvbnRyb2xsZXInLCBVc2Vyc0NvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gVXNlcnNDb250cm9sbGVyKCRjb250cm9sbGVyLCBsb2Rhc2gsIFVzZXJzU2VydmljZSwgUm9sZXNTZXJ2aWNlLCAvLyBOT1NPTkFSXG4gICAgUHJUb2FzdCwgQXV0aCwgJHRyYW5zbGF0ZSkge1xuXG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIHZtLm9uQWN0aXZhdGUgPSBvbkFjdGl2YXRlO1xuICAgIHZtLmFwcGx5RmlsdGVycyA9IGFwcGx5RmlsdGVycztcbiAgICB2bS5hZnRlckVkaXQgPSBhZnRlckVkaXQ7XG4gICAgdm0uYWZ0ZXJDbGVhbiA9IGFmdGVyQ2xlYW47XG4gICAgdm0uYmVmb3JlU2F2ZSA9IGJlZm9yZVNhdmU7XG4gICAgdm0uYWZ0ZXJTYXZlID0gYWZ0ZXJTYXZlO1xuICAgIHZtLmJlZm9yZVJlbW92ZSA9IGJlZm9yZVJlbW92ZTtcblxuICAgIC8vIGluc3RhbnRpYXRlIGJhc2UgY29udHJvbGxlclxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHsgdm06IHZtLCBtb2RlbFNlcnZpY2U6IFVzZXJzU2VydmljZSwgb3B0aW9uczoge30gfSk7XG5cbiAgICBmdW5jdGlvbiBvbkFjdGl2YXRlKCkge1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0ge307XG5cbiAgICAgIHZtLnJvbGVzID0gUm9sZXNTZXJ2aWNlLnF1ZXJ5KCkudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgdm0ucm9sZXMgPSByZXNwb25zZTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGFwcGx5RmlsdGVycyhkZWZhdWx0UXVlcnlGaWx0ZXJzKSB7XG4gICAgICByZXR1cm4gYW5ndWxhci5leHRlbmQoZGVmYXVsdFF1ZXJ5RmlsdGVycywgdm0ucXVlcnlGaWx0ZXJzKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBhZnRlckNsZWFuKCkge1xuICAgICAgdm0ucm9sZXMuZm9yRWFjaChmdW5jdGlvbihyb2xlKSB7XG4gICAgICAgIHJvbGUuc2VsZWN0ZWQgPSBmYWxzZTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGFmdGVyRWRpdCgpIHtcbiAgICAgIHZtLnJvbGVzLmZvckVhY2goZnVuY3Rpb24ocm9sZSkge1xuICAgICAgICB2bS5yZXNvdXJjZS5yb2xlcy5mb3JFYWNoKGZ1bmN0aW9uKHJvbGVVc2VyKSB7XG4gICAgICAgICAgaWYgKHJvbGUuaWQgPT09IHJvbGVVc2VyLmlkKSB7XG4gICAgICAgICAgICByb2xlLnNlbGVjdGVkID0gdHJ1ZTtcbiAgICAgICAgICB9XG4gICAgICAgIH0pO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gYmVmb3JlU2F2ZSgpIHtcbiAgICAgIC8vZmlsdHJhIG8gYXJyYXkgZGUgcm9sZXMgcGFyYSBleHRyYWlyIHNvbWVudGUgb3MgaWRzXG4gICAgICB2bS5yZXNvdXJjZS5yb2xlcyA9IGxvZGFzaC5tYXAobG9kYXNoLmZpbHRlcihhbmd1bGFyLmNvcHkodm0ucm9sZXMpLCB7IHNlbGVjdGVkOiB0cnVlIH0pLCBmdW5jdGlvbihyb2xlKSB7XG4gICAgICAgIHJldHVybiB7IGlkOiByb2xlLmlkIH07XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBhZnRlclNhdmUocmVzb3VyY2UpIHtcbiAgICAgIGlmICh2bS5yZXNvdXJjZS5pZCA9PT0gQXV0aC5jdXJyZW50VXNlci5pZCkge1xuICAgICAgICBBdXRoLnVwZGF0ZUN1cnJlbnRVc2VyKHJlc291cmNlKTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICBmdW5jdGlvbiBiZWZvcmVSZW1vdmUocmVzb3VyY2UpIHtcbiAgICAgIGlmIChyZXNvdXJjZS5pZCA9PT0gQXV0aC5jdXJyZW50VXNlci5pZCkge1xuICAgICAgICBQclRvYXN0LmVycm9yKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMudXNlci5yZW1vdmVZb3VyU2VsZkVycm9yJykpO1xuICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICB9XG4gICAgfVxuICB9XG59KSgpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKlxuICAgKiBBcnF1aXZvIGRlIGNvbmZpZ3VyYcOnw6NvIGNvbSBhcyByb3RhcyBlc3BlY8OtZmljYXMgZG8gcmVjdXJzbyB1c2VyXG4gICAqXG4gICAqIEBwYXJhbSB7YW55fSAkc3RhdGVQcm92aWRlclxuICAgKiBAcGFyYW0ge2FueX0gR2xvYmFsXG4gICAqL1xuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvdXRlcygkc3RhdGVQcm92aWRlciwgR2xvYmFsKSB7XG4gICAgJHN0YXRlUHJvdmlkZXJcbiAgICAgIC5zdGF0ZSgnYXBwLnVzZXInLCB7XG4gICAgICAgIHVybDogJy91c3VhcmlvJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy91c2Vycy91c2Vycy5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ1VzZXJzQ29udHJvbGxlciBhcyB1c2Vyc0N0cmwnLFxuICAgICAgICBkYXRhOiB7IG5lZWRBdXRoZW50aWNhdGlvbjogdHJ1ZSwgbmVlZFByb2ZpbGU6IFsnYWRtaW4nXSB9XG4gICAgICB9KVxuICAgICAgLnN0YXRlKCdhcHAudXNlci1wcm9maWxlJywge1xuICAgICAgICB1cmw6ICcvdXN1YXJpby9wZXJmaWwnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL3VzZXJzL3Byb2ZpbGUuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdQcm9maWxlQ29udHJvbGxlciBhcyBwcm9maWxlQ3RybCcsXG4gICAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiB0cnVlIH1cbiAgICAgIH0pO1xuXG4gIH1cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmFjdG9yeSgnVXNlcnNTZXJ2aWNlJywgVXNlcnNTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIFVzZXJzU2VydmljZShsb2Rhc2gsIEdsb2JhbCwgc2VydmljZUZhY3RvcnkpIHtcbiAgICByZXR1cm4gc2VydmljZUZhY3RvcnkoJ3VzZXJzJywge1xuICAgICAgLy9xdWFuZG8gaW5zdGFuY2lhIHVtIHVzdcOhcmlvIHNlbSBwYXNzYXIgcGFyYW1ldHJvLFxuICAgICAgLy9vIG1lc21vIHZhaSB0ZXIgb3MgdmFsb3JlcyBkZWZhdWx0cyBhYmFpeG9cbiAgICAgIGRlZmF1bHRzOiB7XG4gICAgICAgIHJvbGVzOiBbXVxuICAgICAgfSxcblxuICAgICAgYWN0aW9uczoge1xuICAgICAgICAvKipcbiAgICAgICAgICogU2VydmnDp28gcXVlIGF0dWFsaXphIG9zIGRhZG9zIGRvIHBlcmZpbCBkbyB1c3XDoXJpbyBsb2dhZG9cbiAgICAgICAgICpcbiAgICAgICAgICogQHBhcmFtIHtvYmplY3R9IGF0dHJpYnV0ZXNcbiAgICAgICAgICogQHJldHVybnMge3Byb21pc2V9IFVtYSBwcm9taXNlIGNvbSBvIHJlc3VsdGFkbyBkbyBjaGFtYWRhIG5vIGJhY2tlbmRcbiAgICAgICAgICovXG4gICAgICAgIHVwZGF0ZVByb2ZpbGU6IHtcbiAgICAgICAgICBtZXRob2Q6ICdQVVQnLFxuICAgICAgICAgIHVybDogR2xvYmFsLmFwaVBhdGggKyAnL3Byb2ZpbGUnLFxuICAgICAgICAgIG92ZXJyaWRlOiB0cnVlLFxuICAgICAgICAgIHdyYXA6IGZhbHNlXG4gICAgICAgIH1cbiAgICAgIH0sXG5cbiAgICAgIGluc3RhbmNlOiB7XG4gICAgICAgIC8qKlxuICAgICAgICAgKiBWZXJpZmljYSBzZSBvIHVzdcOhcmlvIHRlbSBvcyBwZXJmaXMgaW5mb3JtYWRvcy5cbiAgICAgICAgICpcbiAgICAgICAgICogQHBhcmFtIHthbnl9IHJvbGVzIHBlcmZpcyBhIHNlcmVtIHZlcmlmaWNhZG9zXG4gICAgICAgICAqIEBwYXJhbSB7Ym9vbGVhbn0gYWxsIGZsYWcgcGFyYSBpbmRpY2FyIHNlIHZhaSBjaGVnYXIgdG9kb3Mgb3MgcGVyZmlzIG91IHNvbWVudGUgdW0gZGVsZXNcbiAgICAgICAgICogQHJldHVybnMge2Jvb2xlYW59XG4gICAgICAgICAqL1xuICAgICAgICBoYXNQcm9maWxlOiBmdW5jdGlvbihyb2xlcywgYWxsKSB7XG4gICAgICAgICAgcm9sZXMgPSBhbmd1bGFyLmlzQXJyYXkocm9sZXMpID8gcm9sZXMgOiBbcm9sZXNdO1xuXG4gICAgICAgICAgdmFyIHVzZXJSb2xlcyA9IGxvZGFzaC5tYXAodGhpcy5yb2xlcywgJ3NsdWcnKTtcblxuICAgICAgICAgIGlmIChhbGwpIHtcbiAgICAgICAgICAgIHJldHVybiBsb2Rhc2guaW50ZXJzZWN0aW9uKHVzZXJSb2xlcywgcm9sZXMpLmxlbmd0aCA9PT0gcm9sZXMubGVuZ3RoO1xuICAgICAgICAgIH0gZWxzZSB7IC8vcmV0dXJuIHRoZSBsZW5ndGggYmVjYXVzZSAwIGlzIGZhbHNlIGluIGpzXG4gICAgICAgICAgICByZXR1cm4gbG9kYXNoLmludGVyc2VjdGlvbih1c2VyUm9sZXMsIHJvbGVzKS5sZW5ndGg7XG4gICAgICAgICAgfVxuICAgICAgICB9LFxuXG4gICAgICAgIC8qKlxuICAgICAgICAgKiBWZXJpZmljYSBzZSBvIHVzdcOhcmlvIHRlbSBvIHBlcmZpbCBhZG1pbi5cbiAgICAgICAgICpcbiAgICAgICAgICogQHJldHVybnMge2Jvb2xlYW59XG4gICAgICAgICAqL1xuICAgICAgICBpc0FkbWluOiBmdW5jdGlvbigpIHtcbiAgICAgICAgICByZXR1cm4gdGhpcy5oYXNQcm9maWxlKCdhZG1pbicpO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfSk7XG4gIH1cblxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gICAvKiogQG5nSW5qZWN0ICovXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb21wb25lbnQoJ2JveCcsIHtcbiAgICAgIHJlcGxhY2U6IHRydWUsXG4gICAgICB0ZW1wbGF0ZVVybDogWydHbG9iYWwnLCBmdW5jdGlvbihHbG9iYWwpIHtcbiAgICAgICAgcmV0dXJuIEdsb2JhbC5jbGllbnRQYXRoICsgJy93aWRnZXRzL2JveC5odG1sJ1xuICAgICAgfV0sXG4gICAgICB0cmFuc2NsdWRlOiB7XG4gICAgICAgIHRvb2xiYXJCdXR0b25zOiAnP2JveFRvb2xiYXJCdXR0b25zJyxcbiAgICAgICAgZm9vdGVyQnV0dG9uczogJz9ib3hGb290ZXJCdXR0b25zJ1xuICAgICAgfSxcbiAgICAgIGJpbmRpbmdzOiB7XG4gICAgICAgIGJveFRpdGxlOiAnQCcsXG4gICAgICAgIHRvb2xiYXJDbGFzczogJ0AnLFxuICAgICAgICB0b29sYmFyQmdDb2xvcjogJ0AnXG4gICAgICB9LFxuICAgICAgY29udHJvbGxlcjogWyckdHJhbnNjbHVkZScsIGZ1bmN0aW9uKCR0cmFuc2NsdWRlKSB7XG4gICAgICAgIHZhciBjdHJsID0gdGhpcztcblxuICAgICAgICBjdHJsLnRyYW5zY2x1ZGUgPSAkdHJhbnNjbHVkZTtcblxuICAgICAgICBjdHJsLiRvbkluaXQgPSBmdW5jdGlvbigpIHtcbiAgICAgICAgICBpZiAoYW5ndWxhci5pc1VuZGVmaW5lZChjdHJsLnRvb2xiYXJCZ0NvbG9yKSkgY3RybC50b29sYmFyQmdDb2xvciA9ICdkZWZhdWx0LXByaW1hcnknO1xuICAgICAgICB9O1xuICAgICAgfV1cbiAgICB9KTtcbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb21wb25lbnQoJ2NvbnRlbnRCb2R5Jywge1xuICAgICAgcmVwbGFjZTogdHJ1ZSxcbiAgICAgIHRyYW5zY2x1ZGU6IHRydWUsXG4gICAgICB0ZW1wbGF0ZVVybDogWydHbG9iYWwnLCBmdW5jdGlvbihHbG9iYWwpIHtcbiAgICAgICAgcmV0dXJuIEdsb2JhbC5jbGllbnRQYXRoICsgJy93aWRnZXRzL2NvbnRlbnQtYm9keS5odG1sJ1xuICAgICAgfV0sXG4gICAgICBiaW5kaW5nczoge1xuICAgICAgICBsYXlvdXRBbGlnbjogJ0AnXG4gICAgICB9LFxuICAgICAgY29udHJvbGxlcjogW2Z1bmN0aW9uKCkge1xuICAgICAgICB2YXIgY3RybCA9IHRoaXM7XG5cbiAgICAgICAgY3RybC4kb25Jbml0ID0gZnVuY3Rpb24oKSB7XG4gICAgICAgICAgLy8gTWFrZSBhIGNvcHkgb2YgdGhlIGluaXRpYWwgdmFsdWUgdG8gYmUgYWJsZSB0byByZXNldCBpdCBsYXRlclxuICAgICAgICAgIGN0cmwubGF5b3V0QWxpZ24gPSBhbmd1bGFyLmlzRGVmaW5lZChjdHJsLmxheW91dEFsaWduKSA/IGN0cmwubGF5b3V0QWxpZ24gOiAnY2VudGVyIHN0YXJ0JztcbiAgICAgICAgfTtcbiAgICAgIH1dXG4gICAgfSk7XG5cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb21wb25lbnQoJ2NvbnRlbnRIZWFkZXInLCB7XG4gICAgICB0ZW1wbGF0ZVVybDogWydHbG9iYWwnLCBmdW5jdGlvbihHbG9iYWwpIHtcbiAgICAgICAgcmV0dXJuIEdsb2JhbC5jbGllbnRQYXRoICsgJy93aWRnZXRzL2NvbnRlbnQtaGVhZGVyLmh0bWwnXG4gICAgICB9XSxcbiAgICAgIHJlcGxhY2U6IHRydWUsXG4gICAgICBiaW5kaW5nczoge1xuICAgICAgICB0aXRsZTogJ0AnLFxuICAgICAgICBkZXNjcmlwdGlvbjogJ0AnXG4gICAgICB9XG4gICAgfSk7XG5cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5maWx0ZXIoJ2F1ZGl0RGV0YWlsVGl0bGUnLCBhdWRpdERldGFpbFRpdGxlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIGF1ZGl0RGV0YWlsVGl0bGUoJHRyYW5zbGF0ZSkge1xuICAgIHJldHVybiBmdW5jdGlvbihhdWRpdERldGFpbCwgc3RhdHVzKSB7XG4gICAgICBpZiAoYXVkaXREZXRhaWwudHlwZSA9PT0gJ3VwZGF0ZWQnKSB7XG4gICAgICAgIGlmIChzdGF0dXMgPT09ICdiZWZvcmUnKSB7XG4gICAgICAgICAgcmV0dXJuICR0cmFuc2xhdGUuaW5zdGFudCgnZGlhbG9nLmF1ZGl0LnVwZGF0ZWRCZWZvcmUnKTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICByZXR1cm4gJHRyYW5zbGF0ZS5pbnN0YW50KCdkaWFsb2cuYXVkaXQudXBkYXRlZEFmdGVyJyk7XG4gICAgICAgIH1cbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHJldHVybiAkdHJhbnNsYXRlLmluc3RhbnQoJ2RpYWxvZy5hdWRpdC4nICsgYXVkaXREZXRhaWwudHlwZSk7XG4gICAgICB9XG4gICAgfVxuICB9XG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5maWx0ZXIoJ2F1ZGl0TW9kZWwnLCBhdWRpdE1vZGVsKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIGF1ZGl0TW9kZWwoJHRyYW5zbGF0ZSkge1xuICAgIHJldHVybiBmdW5jdGlvbihtb2RlbElkKSB7XG4gICAgICBtb2RlbElkID0gbW9kZWxJZC5yZXBsYWNlKCdBcHBcXFxcJywgJycpO1xuICAgICAgdmFyIG1vZGVsID0gJHRyYW5zbGF0ZS5pbnN0YW50KCdtb2RlbHMuJyArIG1vZGVsSWQudG9Mb3dlckNhc2UoKSk7XG5cbiAgICAgIHJldHVybiAobW9kZWwpID8gbW9kZWwgOiBtb2RlbElkO1xuICAgIH1cbiAgfVxuXG59KSgpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmlsdGVyKCdhdWRpdFR5cGUnLCBhdWRpdFR5cGUpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gYXVkaXRUeXBlKGxvZGFzaCwgQXVkaXRTZXJ2aWNlKSB7XG4gICAgcmV0dXJuIGZ1bmN0aW9uKHR5cGVJZCkge1xuICAgICAgdmFyIHR5cGUgPSBsb2Rhc2guZmluZChBdWRpdFNlcnZpY2UubGlzdFR5cGVzKCksIHsgaWQ6IHR5cGVJZCB9KTtcblxuICAgICAgcmV0dXJuICh0eXBlKSA/IHR5cGUubGFiZWwgOiB0eXBlO1xuICAgIH1cbiAgfVxuXG59KSgpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmlsdGVyKCdhdWRpdFZhbHVlJywgYXVkaXRWYWx1ZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBhdWRpdFZhbHVlKCRmaWx0ZXIsIGxvZGFzaCkge1xuICAgIHJldHVybiBmdW5jdGlvbih2YWx1ZSwga2V5KSB7XG4gICAgICBpZiAoYW5ndWxhci5pc0RhdGUodmFsdWUpIHx8IGxvZGFzaC5lbmRzV2l0aChrZXksICdfYXQnKSB8fCAgbG9kYXNoLmVuZHNXaXRoKGtleSwgJ190bycpKSB7XG4gICAgICAgIHJldHVybiAkZmlsdGVyKCdwckRhdGV0aW1lJykodmFsdWUpO1xuICAgICAgfVxuXG4gICAgICBpZiAodHlwZW9mIHZhbHVlID09PSAnYm9vbGVhbicpIHtcbiAgICAgICAgcmV0dXJuICRmaWx0ZXIoJ3RyYW5zbGF0ZScpKCh2YWx1ZSkgPyAnZ2xvYmFsLnllcycgOiAnZ2xvYmFsLm5vJyk7XG4gICAgICB9XG5cbiAgICAgIC8vY2hlY2sgaXMgZmxvYXRcbiAgICAgIGlmIChOdW1iZXIodmFsdWUpID09PSB2YWx1ZSAmJiB2YWx1ZSAlIDEgIT09IDApIHtcbiAgICAgICAgcmV0dXJuICRmaWx0ZXIoJ3JlYWwnKSh2YWx1ZSk7XG4gICAgICB9XG5cbiAgICAgIHJldHVybiB2YWx1ZTtcbiAgICB9XG4gIH1cblxufSkoKTtcbiIsIi8qZXNsaW50IGFuZ3VsYXIvZmlsZS1uYW1lOiAwLCBuby11bmRlZjogMCovXG4oZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uc3RhbnQoJ3B0LUJSLmkxOG4uYXR0cmlidXRlcycsIHtcbiAgICAgIGVtYWlsOiAnRW1haWwnLFxuICAgICAgcGFzc3dvcmQ6ICdTZW5oYScsXG4gICAgICBuYW1lOiAnTm9tZScsXG4gICAgICBpbWFnZTogJ0ltYWdlbScsXG4gICAgICByb2xlczogJ1BlcmZpcycsXG4gICAgICBkYXRlOiAnRGF0YScsXG4gICAgICBpbml0aWFsRGF0ZTogJ0RhdGEgSW5pY2lhbCcsXG4gICAgICBmaW5hbERhdGU6ICdEYXRhIEZpbmFsJyxcbiAgICAgIHRhc2s6IHtcbiAgICAgICAgZGVzY3JpcHRpb246ICdEZXNjcmnDp8OjbycsXG4gICAgICAgIGRvbmU6ICdGZWl0bz8nLFxuICAgICAgICBwcmlvcml0eTogJ1ByaW9yaWRhZGUnLFxuICAgICAgICBzY2hlZHVsZWRfdG86ICdBZ2VuZGFkbyBQYXJhPycsXG4gICAgICAgIHByb2plY3Q6ICdQcm9qZXRvJ1xuICAgICAgfSxcbiAgICAgIHByb2plY3Q6IHtcbiAgICAgICAgY29zdDogJ0N1c3RvJ1xuICAgICAgfSxcbiAgICAgIC8vw6kgY2FycmVnYWRvIGRvIHNlcnZpZG9yIGNhc28gZXN0ZWphIGRlZmluaWRvIG5vIG1lc21vXG4gICAgICBhdWRpdE1vZGVsOiB7XG4gICAgICB9XG4gICAgfSlcblxufSgpKTtcbiIsIi8qZXNsaW50IGFuZ3VsYXIvZmlsZS1uYW1lOiAwLCBuby11bmRlZjogMCovXG4oZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uc3RhbnQoJ3B0LUJSLmkxOG4uZGlhbG9nJywge1xuICAgICAgY29uZmlybVRpdGxlOiAnQ29uZmlybWHDp8OjbycsXG4gICAgICBjb25maXJtRGVzY3JpcHRpb246ICdDb25maXJtYSBhIGHDp8Ojbz8nLFxuICAgICAgcmVtb3ZlRGVzY3JpcHRpb246ICdEZXNlamEgcmVtb3ZlciBwZXJtYW5lbnRlbWVudGUge3tuYW1lfX0/JyxcbiAgICAgIGF1ZGl0OiB7XG4gICAgICAgIGNyZWF0ZWQ6ICdJbmZvcm1hw6fDtWVzIGRvIENhZGFzdHJvJyxcbiAgICAgICAgdXBkYXRlZEJlZm9yZTogJ0FudGVzIGRhIEF0dWFsaXphw6fDo28nLFxuICAgICAgICB1cGRhdGVkQWZ0ZXI6ICdEZXBvaXMgZGEgQXR1YWxpemHDp8OjbycsXG4gICAgICAgIGRlbGV0ZWQ6ICdJbmZvcm1hw6fDtWVzIGFudGVzIGRlIHJlbW92ZXInXG4gICAgICB9LFxuICAgICAgbG9naW46IHtcbiAgICAgICAgcmVzZXRQYXNzd29yZDoge1xuICAgICAgICAgIGRlc2NyaXB0aW9uOiAnRGlnaXRlIGFiYWl4byBvIGVtYWlsIGNhZGFzdHJhZG8gbm8gc2lzdGVtYS4nXG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9KVxuXG59KCkpO1xuIiwiLyplc2xpbnQgYW5ndWxhci9maWxlLW5hbWU6IDAsIG5vLXVuZGVmOiAwKi9cbihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb25zdGFudCgncHQtQlIuaTE4bi5nbG9iYWwnLCB7XG4gICAgICBsb2FkaW5nOiAnQ2FycmVnYW5kby4uLicsXG4gICAgICBwcm9jZXNzaW5nOiAnUHJvY2Vzc2FuZG8uLi4nLFxuICAgICAgeWVzOiAnU2ltJyxcbiAgICAgIG5vOiAnTsOjbycsXG4gICAgICBhbGw6ICdUb2RvcydcbiAgICB9KVxuXG59KCkpO1xuIiwiLyplc2xpbnQgYW5ndWxhci9maWxlLW5hbWU6IDAsIG5vLXVuZGVmOiAwKi9cbihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb25zdGFudCgncHQtQlIuaTE4bi5tZXNzYWdlcycsIHtcbiAgICAgIGludGVybmFsRXJyb3I6ICdPY29ycmV1IHVtIGVycm8gaW50ZXJubywgY29udGF0ZSBvIGFkbWluaXN0cmFkb3IgZG8gc2lzdGVtYScsXG4gICAgICBub3RGb3VuZDogJ05lbmh1bSByZWdpc3RybyBlbmNvbnRyYWRvJyxcbiAgICAgIG5vdEF1dGhvcml6ZWQ6ICdWb2PDqiBuw6NvIHRlbSBhY2Vzc28gYSBlc3RhIGZ1bmNpb25hbGlkYWRlLicsXG4gICAgICBzZWFyY2hFcnJvcjogJ07Do28gZm9pIHBvc3PDrXZlbCByZWFsaXphciBhIGJ1c2NhLicsXG4gICAgICBzYXZlU3VjY2VzczogJ1JlZ2lzdHJvIHNhbHZvIGNvbSBzdWNlc3NvLicsXG4gICAgICBvcGVyYXRpb25TdWNjZXNzOiAnT3BlcmHDp8OjbyByZWFsaXphZGEgY29tIHN1Y2Vzc28uJyxcbiAgICAgIG9wZXJhdGlvbkVycm9yOiAnRXJybyBhbyByZWFsaXphciBhIG9wZXJhw6fDo28nLFxuICAgICAgc2F2ZUVycm9yOiAnRXJybyBhbyB0ZW50YXIgc2FsdmFyIG8gcmVnaXN0cm8uJyxcbiAgICAgIHJlbW92ZVN1Y2Nlc3M6ICdSZW1vw6fDo28gcmVhbGl6YWRhIGNvbSBzdWNlc3NvLicsXG4gICAgICByZW1vdmVFcnJvcjogJ0Vycm8gYW8gdGVudGFyIHJlbW92ZXIgbyByZWdpc3Ryby4nLFxuICAgICAgcmVzb3VyY2VOb3RGb3VuZEVycm9yOiAnUmVjdXJzbyBuw6NvIGVuY29udHJhZG8nLFxuICAgICAgbm90TnVsbEVycm9yOiAnVG9kb3Mgb3MgY2FtcG9zIG9icmlnYXTDs3Jpb3MgZGV2ZW0gc2VyIHByZWVuY2hpZG9zLicsXG4gICAgICBkdXBsaWNhdGVkUmVzb3VyY2VFcnJvcjogJ0rDoSBleGlzdGUgdW0gcmVjdXJzbyBjb20gZXNzYXMgaW5mb3JtYcOnw7Vlcy4nLFxuICAgICAgdmFsaWRhdGU6IHtcbiAgICAgICAgZmllbGRSZXF1aXJlZDogJ08gY2FtcG8ge3tmaWVsZH19IMOpIG9icmlncmF0w7NyaW8uJ1xuICAgICAgfSxcbiAgICAgIGxheW91dDoge1xuICAgICAgICBlcnJvcjQwNDogJ1DDoWdpbmEgbsOjbyBlbmNvbnRyYWRhJ1xuICAgICAgfSxcbiAgICAgIGxvZ2luOiB7XG4gICAgICAgIGxvZ291dEluYWN0aXZlOiAnVm9jw6ogZm9pIGRlc2xvZ2FkbyBkbyBzaXN0ZW1hIHBvciBpbmF0aXZpZGFkZS4gRmF2b3IgZW50cmFyIG5vIHNpc3RlbWEgbm92YW1lbnRlLicsXG4gICAgICAgIGludmFsaWRDcmVkZW50aWFsczogJ0NyZWRlbmNpYWlzIEludsOhbGlkYXMnLFxuICAgICAgICB1bmtub3duRXJyb3I6ICdOw6NvIGZvaSBwb3Nzw612ZWwgcmVhbGl6YXIgbyBsb2dpbi4gVGVudGUgbm92YW1lbnRlLiAnICtcbiAgICAgICAgICAnQ2FzbyBuw6NvIGNvbnNpZ2EgZmF2b3IgZW5jb250cmFyIGVtIGNvbnRhdG8gY29tIG8gYWRtaW5pc3RyYWRvciBkbyBzaXN0ZW1hLicsXG4gICAgICAgIHVzZXJOb3RGb3VuZDogJ07Do28gZm9pIHBvc3PDrXZlbCBlbmNvbnRyYXIgc2V1cyBkYWRvcydcbiAgICAgIH0sXG4gICAgICBkYXNoYm9hcmQ6IHtcbiAgICAgICAgd2VsY29tZTogJ1NlamEgYmVtIFZpbmRvIHt7dXNlck5hbWV9fScsXG4gICAgICAgIGRlc2NyaXB0aW9uOiAnVXRpbGl6ZSBvIG1lbnUgcGFyYSBuYXZlZ2HDp8Ojby4nXG4gICAgICB9LFxuICAgICAgbWFpbDoge1xuICAgICAgICBtYWlsRXJyb3JzOiAnT2NvcnJldSB1bSBlcnJvIG5vcyBzZWd1aW50ZXMgZW1haWxzIGFiYWl4bzpcXG4nLFxuICAgICAgICBzZW5kTWFpbFN1Y2Nlc3M6ICdFbWFpbCBlbnZpYWRvIGNvbSBzdWNlc3NvIScsXG4gICAgICAgIHNlbmRNYWlsRXJyb3I6ICdOw6NvIGZvaSBwb3Nzw612ZWwgZW52aWFyIG8gZW1haWwuJyxcbiAgICAgICAgcGFzc3dvcmRTZW5kaW5nU3VjY2VzczogJ08gcHJvY2Vzc28gZGUgcmVjdXBlcmHDp8OjbyBkZSBzZW5oYSBmb2kgaW5pY2lhZG8uIENhc28gbyBlbWFpbCBuw6NvIGNoZWd1ZSBlbSAxMCBtaW51dG9zIHRlbnRlIG5vdmFtZW50ZS4nXG4gICAgICB9LFxuICAgICAgdXNlcjoge1xuICAgICAgICByZW1vdmVZb3VyU2VsZkVycm9yOiAnVm9jw6ogbsOjbyBwb2RlIHJlbW92ZXIgc2V1IHByw7NwcmlvIHVzdcOhcmlvJyxcbiAgICAgICAgdXNlckV4aXN0czogJ1VzdcOhcmlvIGrDoSBhZGljaW9uYWRvIScsXG4gICAgICAgIHByb2ZpbGU6IHtcbiAgICAgICAgICB1cGRhdGVFcnJvcjogJ07Do28gZm9pIHBvc3PDrXZlbCBhdHVhbGl6YXIgc2V1IHByb2ZpbGUnXG4gICAgICAgIH1cbiAgICAgIH0sXG4gICAgICBxdWVyeURpbmFtaWM6IHtcbiAgICAgICAgbm9GaWx0ZXI6ICdOZW5odW0gZmlsdHJvIGFkaWNpb25hZG8nXG4gICAgICB9XG4gICAgfSlcblxufSgpKTtcbiIsIi8qZXNsaW50IGFuZ3VsYXIvZmlsZS1uYW1lOiAwLCBuby11bmRlZjogMCovXG4oZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uc3RhbnQoJ3B0LUJSLmkxOG4ubW9kZWxzJywge1xuICAgICAgdXNlcjogJ1VzdcOhcmlvJyxcbiAgICAgIHRhc2s6ICdUYXJlZmEnLFxuICAgICAgcHJvamVjdDogJ1Byb2pldG8nXG4gICAgfSlcblxufSgpKTtcbiIsIi8qZXNsaW50IGFuZ3VsYXIvZmlsZS1uYW1lOiAwLCBuby11bmRlZjogMCovXG4oZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uc3RhbnQoJ3B0LUJSLmkxOG4udmlld3MnLCB7XG4gICAgICBicmVhZGNydW1iczoge1xuICAgICAgICB1c2VyOiAnQWRtaW5pc3RyYcOnw6NvIC0gVXN1w6FyaW8nLFxuICAgICAgICAndXNlci1wcm9maWxlJzogJ1BlcmZpbCcsXG4gICAgICAgIGRhc2hib2FyZDogJ0Rhc2hib2FyZCcsXG4gICAgICAgIGF1ZGl0OiAnQWRtaW5pc3RyYcOnw6NvIC0gQXVkaXRvcmlhJyxcbiAgICAgICAgbWFpbDogJ0FkbWluaXN0cmHDp8OjbyAtIEVudmlvIGRlIGUtbWFpbCcsXG4gICAgICAgIHByb2plY3Q6ICdFeGVtcGxvcyAtIFByb2pldG9zJyxcbiAgICAgICAgJ2RpbmFtaWMtcXVlcnknOiAnQWRtaW5pc3RyYcOnw6NvIC0gQ29uc3VsdGFzIERpbsOibWljYXMnLFxuICAgICAgICAnbm90LWF1dGhvcml6ZWQnOiAnQWNlc3NvIE5lZ2FkbydcbiAgICAgIH0sXG4gICAgICB0aXRsZXM6IHtcbiAgICAgICAgZGFzaGJvYXJkOiAnUMOhZ2luYSBpbmljaWFsJyxcbiAgICAgICAgbWFpbFNlbmQ6ICdFbnZpYXIgZS1tYWlsJyxcbiAgICAgICAgdGFza0xpc3Q6ICdMaXN0YSBkZSBUYXJlZmFzJyxcbiAgICAgICAgdXNlckxpc3Q6ICdMaXN0YSBkZSBVc3XDoXJpb3MnLFxuICAgICAgICBhdWRpdExpc3Q6ICdMaXN0YSBkZSBMb2dzJyxcbiAgICAgICAgcmVnaXN0ZXI6ICdGb3JtdWzDoXJpbyBkZSBDYWRhc3RybycsXG4gICAgICAgIHJlc2V0UGFzc3dvcmQ6ICdSZWRlZmluaXIgU2VuaGEnLFxuICAgICAgICB1cGRhdGU6ICdGb3JtdWzDoXJpbyBkZSBBdHVhbGl6YcOnw6NvJ1xuICAgICAgfSxcbiAgICAgIGFjdGlvbnM6IHtcbiAgICAgICAgc2VuZDogJ0VudmlhcicsXG4gICAgICAgIHNhdmU6ICdTYWx2YXInLFxuICAgICAgICBjbGVhcjogJ0xpbXBhcicsXG4gICAgICAgIGNsZWFyQWxsOiAnTGltcGFyIFR1ZG8nLFxuICAgICAgICByZXN0YXJ0OiAnUmVpbmljaWFyJyxcbiAgICAgICAgZmlsdGVyOiAnRmlsdHJhcicsXG4gICAgICAgIHNlYXJjaDogJ1Blc3F1aXNhcicsXG4gICAgICAgIGxpc3Q6ICdMaXN0YXInLFxuICAgICAgICBlZGl0OiAnRWRpdGFyJyxcbiAgICAgICAgY2FuY2VsOiAnQ2FuY2VsYXInLFxuICAgICAgICB1cGRhdGU6ICdBdHVhbGl6YXInLFxuICAgICAgICByZW1vdmU6ICdSZW1vdmVyJyxcbiAgICAgICAgZ2V0T3V0OiAnU2FpcicsXG4gICAgICAgIGFkZDogJ0FkaWNpb25hcicsXG4gICAgICAgIGluOiAnRW50cmFyJyxcbiAgICAgICAgbG9hZEltYWdlOiAnQ2FycmVnYXIgSW1hZ2VtJyxcbiAgICAgICAgc2lnbnVwOiAnQ2FkYXN0cmFyJ1xuICAgICAgfSxcbiAgICAgIGZpZWxkczoge1xuICAgICAgICBkYXRlOiAnRGF0YScsXG4gICAgICAgIGFjdGlvbjogJ0HDp8OjbycsXG4gICAgICAgIGFjdGlvbnM6ICdBw6fDtWVzJyxcbiAgICAgICAgYXVkaXQ6IHtcbiAgICAgICAgICBkYXRlU3RhcnQ6ICdEYXRhIEluaWNpYWwnLFxuICAgICAgICAgIGRhdGVFbmQ6ICdEYXRhIEZpbmFsJyxcbiAgICAgICAgICByZXNvdXJjZTogJ1JlY3Vyc28nLFxuICAgICAgICAgIGFsbFJlc291cmNlczogJ1RvZG9zIFJlY3Vyc29zJyxcbiAgICAgICAgICB0eXBlOiB7XG4gICAgICAgICAgICBjcmVhdGVkOiAnQ2FkYXN0cmFkbycsXG4gICAgICAgICAgICB1cGRhdGVkOiAnQXR1YWxpemFkbycsXG4gICAgICAgICAgICBkZWxldGVkOiAnUmVtb3ZpZG8nXG4gICAgICAgICAgfVxuICAgICAgICB9LFxuICAgICAgICBsb2dpbjoge1xuICAgICAgICAgIHJlc2V0UGFzc3dvcmQ6ICdFc3F1ZWNpIG1pbmhhIHNlbmhhJyxcbiAgICAgICAgICBjb25maXJtUGFzc3dvcmQ6ICdDb25maXJtYXIgc2VuaGEnXG4gICAgICAgIH0sXG4gICAgICAgIG1haWw6IHtcbiAgICAgICAgICB0bzogJ1BhcmEnLFxuICAgICAgICAgIHN1YmplY3Q6ICdBc3N1bnRvJyxcbiAgICAgICAgICBtZXNzYWdlOiAnTWVuc2FnZW0nXG4gICAgICAgIH0sXG4gICAgICAgIHF1ZXJ5RGluYW1pYzoge1xuICAgICAgICAgIGZpbHRlcnM6ICdGaWx0cm9zJyxcbiAgICAgICAgICByZXN1bHRzOiAnUmVzdWx0YWRvcycsXG4gICAgICAgICAgbW9kZWw6ICdNb2RlbCcsXG4gICAgICAgICAgYXR0cmlidXRlOiAnQXRyaWJ1dG8nLFxuICAgICAgICAgIG9wZXJhdG9yOiAnT3BlcmFkb3InLFxuICAgICAgICAgIHJlc291cmNlOiAnUmVjdXJzbycsXG4gICAgICAgICAgdmFsdWU6ICdWYWxvcicsXG4gICAgICAgICAgb3BlcmF0b3JzOiB7XG4gICAgICAgICAgICBlcXVhbHM6ICdJZ3VhbCcsXG4gICAgICAgICAgICBkaWZlcmVudDogJ0RpZmVyZW50ZScsXG4gICAgICAgICAgICBjb250ZWluczogJ0NvbnTDqW0nLFxuICAgICAgICAgICAgc3RhcnRXaXRoOiAnSW5pY2lhIGNvbScsXG4gICAgICAgICAgICBmaW5pc2hXaXRoOiAnRmluYWxpemEgY29tJyxcbiAgICAgICAgICAgIGJpZ2dlclRoYW46ICdNYWlvcicsXG4gICAgICAgICAgICBlcXVhbHNPckJpZ2dlclRoYW46ICdNYWlvciBvdSBJZ3VhbCcsXG4gICAgICAgICAgICBsZXNzVGhhbjogJ01lbm9yJyxcbiAgICAgICAgICAgIGVxdWFsc09yTGVzc1RoYW46ICdNZW5vciBvdSBJZ3VhbCdcbiAgICAgICAgICB9XG4gICAgICAgIH0sXG4gICAgICAgIHByb2plY3Q6IHtcbiAgICAgICAgICBuYW1lOiAnTm9tZScsXG4gICAgICAgICAgdG90YWxUYXNrOiAnVG90YWwgZGUgVGFyZWZhcydcbiAgICAgICAgfSxcbiAgICAgICAgdGFzazoge1xuICAgICAgICAgIGRvbmU6ICdOw6NvIEZlaXRvIC8gRmVpdG8nXG4gICAgICAgIH0sXG4gICAgICAgIHVzZXI6IHtcbiAgICAgICAgICBwZXJmaWxzOiAnUGVyZmlzJyxcbiAgICAgICAgICBuYW1lT3JFbWFpbDogJ05vbWUgb3UgRW1haWwnXG4gICAgICAgIH1cbiAgICAgIH0sXG4gICAgICBsYXlvdXQ6IHtcbiAgICAgICAgbWVudToge1xuICAgICAgICAgIGRhc2hib2FyZDogJ0Rhc2hib2FyZCcsXG4gICAgICAgICAgcHJvamVjdDogJ1Byb2pldG9zJyxcbiAgICAgICAgICBhZG1pbjogJ0FkbWluaXN0cmHDp8OjbycsXG4gICAgICAgICAgZXhhbXBsZXM6ICdFeGVtcGxvcycsXG4gICAgICAgICAgdXNlcjogJ1VzdcOhcmlvcycsXG4gICAgICAgICAgbWFpbDogJ0VudmlhciBlLW1haWwnLFxuICAgICAgICAgIGF1ZGl0OiAnQXVkaXRvcmlhJyxcbiAgICAgICAgICBkaW5hbWljUXVlcnk6ICdDb25zdWx0YXMgRGluYW1pY2FzJ1xuICAgICAgICB9XG4gICAgICB9LFxuICAgICAgdG9vbHRpcHM6IHtcbiAgICAgICAgYXVkaXQ6IHtcbiAgICAgICAgICB2aWV3RGV0YWlsOiAnVmlzdWFsaXphciBEZXRhbGhhbWVudG8nXG4gICAgICAgIH0sXG4gICAgICAgIHVzZXI6IHtcbiAgICAgICAgICBwZXJmaWw6ICdQZXJmaWwnLFxuICAgICAgICAgIHRyYW5zZmVyOiAnVHJhbnNmZXJpcidcbiAgICAgICAgfSxcbiAgICAgICAgdGFzazoge1xuICAgICAgICAgIGxpc3RUYXNrOiAnTGlzdGFyIFRhcmVmYXMnXG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9KVxuXG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29udHJvbGxlcignUHJvamVjdHNDb250cm9sbGVyJywgUHJvamVjdHNDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIFByb2plY3RzQ29udHJvbGxlcihHbG9iYWwsICRjb250cm9sbGVyLCBQcm9qZWN0c1NlcnZpY2UsIFByRGlhbG9nKSB7XG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIC8vQXR0cmlidXRlcyBCbG9ja1xuXG4gICAgLy9GdW5jdGlvbnMgQmxvY2tcbiAgICB2bS5vbkFjdGl2YXRlID0gb25BY3RpdmF0ZTtcbiAgICB2bS5hcHBseUZpbHRlcnMgPSBhcHBseUZpbHRlcnM7XG4gICAgdm0udmlld1Rhc2tzID0gdmlld1Rhc2tzO1xuXG4gICAgLy8gaW5zdGFudGlhdGUgYmFzZSBjb250cm9sbGVyXG4gICAgJGNvbnRyb2xsZXIoJ0NSVURDb250cm9sbGVyJywgeyB2bTogdm0sIG1vZGVsU2VydmljZTogUHJvamVjdHNTZXJ2aWNlLCBvcHRpb25zOiB7fSB9KTtcblxuICAgIGZ1bmN0aW9uIG9uQWN0aXZhdGUoKSB7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMgPSB7fTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBhcHBseUZpbHRlcnMoZGVmYXVsdFF1ZXJ5RmlsdGVycykge1xuICAgICAgcmV0dXJuIGFuZ3VsYXIuZXh0ZW5kKGRlZmF1bHRRdWVyeUZpbHRlcnMsIHZtLnF1ZXJ5RmlsdGVycyk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gdmlld1Rhc2tzKHByb2plY3RJZCkge1xuICAgICAgdmFyIGNvbmZpZyA9IHtcbiAgICAgICAgbG9jYWxzOiB7XG4gICAgICAgICAgcHJvamVjdElkOiBwcm9qZWN0SWRcbiAgICAgICAgfSxcbiAgICAgICAgY29udHJvbGxlcjogJ1Rhc2tzRGlhbG9nQ29udHJvbGxlcicsXG4gICAgICAgIGNvbnRyb2xsZXJBczogJ3Rhc2tzQ3RybCcsXG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvc2FtcGxlcy90YXNrcy90YXNrcy1kaWFsb2cuaHRtbCcsXG4gICAgICAgIGhhc0JhY2tkcm9wOiB0cnVlXG4gICAgICB9O1xuXG4gICAgICBQckRpYWxvZy5jdXN0b20oY29uZmlnKS5maW5hbGx5KGZ1bmN0aW9uKCkge1xuICAgICAgICB2bS5zZWFyY2godm0ucGFnaW5hdG9yLmN1cnJlbnRQYWdlKTtcbiAgICAgIH0pO1xuXG4gICAgfVxuXG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb25maWcocm91dGVzKTtcblxuICAvKipcbiAgICogQXJxdWl2byBkZSBjb25maWd1cmHDp8OjbyBjb20gYXMgcm90YXMgZXNwZWPDrWZpY2FzIGRvIHJlY3Vyc28gcHJvamVjdFxuICAgKlxuICAgKiBAcGFyYW0ge2FueX0gJHN0YXRlUHJvdmlkZXJcbiAgICogQHBhcmFtIHthbnl9IEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyXG4gICAgICAuc3RhdGUoJ2FwcC5wcm9qZWN0Jywge1xuICAgICAgICB1cmw6ICcvcHJvamV0b3MnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL3NhbXBsZXMvcHJvamVjdHMvcHJvamVjdHMuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdQcm9qZWN0c0NvbnRyb2xsZXIgYXMgcHJvamVjdHNDdHJsJyxcbiAgICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IHRydWUsIG5lZWRQcm9maWxlOiBbJ2FkbWluJ10gfVxuICAgICAgfSk7XG4gIH1cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmFjdG9yeSgnUHJvamVjdHNTZXJ2aWNlJywgUHJvamVjdHNTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIFByb2plY3RzU2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHJldHVybiBzZXJ2aWNlRmFjdG9yeSgncHJvamVjdHMnLCB7XG4gICAgICBhY3Rpb25zOiB7IH0sXG4gICAgICBpbnN0YW5jZTogeyB9XG4gICAgfSk7XG4gIH1cblxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnRyb2xsZXIoJ1Rhc2tzRGlhbG9nQ29udHJvbGxlcicsIFRhc2tzRGlhbG9nQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBUYXNrc0RpYWxvZ0NvbnRyb2xsZXIoJGNvbnRyb2xsZXIsIFRhc2tzU2VydmljZSwgcHJvamVjdElkLCBQclRvYXN0LCAvLyBOT1NPTkFSXG4gICAgUHJEaWFsb2csICR0cmFuc2xhdGUsIEdsb2JhbCwgbW9tZW50KSB7XG5cbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgLy9GdW5jdGlvbnMgQmxvY2tcbiAgICB2bS5vbkFjdGl2YXRlICAgPSBvbkFjdGl2YXRlO1xuICAgIHZtLmNsb3NlICAgICAgICA9IGNsb3NlO1xuICAgIHZtLmFwcGx5RmlsdGVycyA9IGFwcGx5RmlsdGVycztcbiAgICB2bS5iZWZvcmVTYXZlICAgPSBiZWZvcmVTYXZlO1xuICAgIHZtLmFmdGVyU2F2ZSAgICA9IGFmdGVyU2F2ZTtcbiAgICB2bS50b2dnbGVEb25lICAgPSB0b2dnbGVEb25lO1xuXG4gICAgLy8gaW5zdGFudGlhdGUgYmFzZSBjb250cm9sbGVyXG4gICAgJGNvbnRyb2xsZXIoJ0NSVURDb250cm9sbGVyJywgeyB2bTogdm0sIG1vZGVsU2VydmljZTogVGFza3NTZXJ2aWNlLCBvcHRpb25zOiB7XG4gICAgICBwZXJQYWdlOiA1XG4gICAgfSB9KTtcblxuICAgIGZ1bmN0aW9uIG9uQWN0aXZhdGUoKSB7XG4gICAgICB2bS5nbG9iYWwgPSBHbG9iYWw7XG4gICAgICB2bS5yZXNvdXJjZS5zY2hlZHVsZWRfdG8gPSBtb21lbnQoKS5hZGQoMzAsICdtaW51dGVzJyk7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMgPSB7IHByb2plY3RJZDogcHJvamVjdElkIH07XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gYXBwbHlGaWx0ZXJzKGRlZmF1bHRRdWVyeUZpbHRlcnMpIHtcbiAgICAgIHJldHVybiBhbmd1bGFyLmV4dGVuZChkZWZhdWx0UXVlcnlGaWx0ZXJzLCB2bS5xdWVyeUZpbHRlcnMpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGJlZm9yZVNhdmUoKSB7XG4gICAgICB2bS5yZXNvdXJjZS5wcm9qZWN0X2lkID0gdm0ucXVlcnlGaWx0ZXJzLnByb2plY3RJZDtcbiAgICAgIHZtLnJlc291cmNlLnByb2plY3QgPSBudWxsO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGFmdGVyU2F2ZSgpIHtcbiAgICAgIHZtLmNsZWFuRm9ybSgpO1xuICAgICAgdm0uc2VhcmNoKHZtLnBhZ2luYXRvci5jdXJyZW50UGFnZSk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gY2xvc2UoKSB7XG4gICAgICB2bS5jbGVhbkZvcm0oKTtcbiAgICAgIFByRGlhbG9nLmNsb3NlKCk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gdG9nZ2xlRG9uZShyZXNvdXJjZSkge1xuICAgICAgVGFza3NTZXJ2aWNlLnRvZ2dsZURvbmUoeyBpZDogcmVzb3VyY2UuaWQsIGRvbmU6IHJlc291cmNlLmRvbmUgfSkudGhlbihmdW5jdGlvbigpIHtcbiAgICAgICAgUHJUb2FzdC5zdWNjZXNzKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMuc2F2ZVN1Y2Nlc3MnKSk7XG4gICAgICAgIHZtLnNlYXJjaCh2bS5wYWdpbmF0b3IuY3VycmVudFBhZ2UpO1xuICAgICAgfSwgZnVuY3Rpb24oZXJyb3IpIHtcbiAgICAgICAgUHJUb2FzdC5lcnJvclZhbGlkYXRpb24oZXJyb3IuZGF0YSwgJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5vcGVyYXRpb25FcnJvcicpKTtcbiAgICAgIH0pO1xuICAgIH1cblxuICB9XG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmFjdG9yeSgnVGFza3NTZXJ2aWNlJywgVGFza3NTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIFRhc2tzU2VydmljZShzZXJ2aWNlRmFjdG9yeSwgbW9tZW50KSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCd0YXNrcycsIHtcbiAgICAgIC8vcXVhbmRvIGluc3RhbmNpYSB1bSB1c3XDoXJpbyBzZW0gcGFzc2FyIHBhcmFtZXRybyxcbiAgICAgIC8vbyBtZXNtbyB2YWkgdGVyIG9zIHZhbG9yZXMgZGVmYXVsdHMgYWJhaXhvXG4gICAgICBkZWZhdWx0czoge1xuICAgICAgICBzY2hlZHVsZWRfdG86IG5ldyBEYXRlKClcbiAgICAgIH0sXG5cbiAgICAgIG1hcDoge1xuICAgICAgICAvL2NvbnZlcnQgcGFyYSBvYmpldG8gamF2YXNjcmlwdCBkYXRlIHVtYSBzdHJpbmcgZm9ybWF0YWRhIGNvbW8gZGF0YVxuICAgICAgICBzY2hlZHVsZWRfdG86IGZ1bmN0aW9uKHZhbHVlKSB7XG4gICAgICAgICAgcmV0dXJuIG1vbWVudCh2YWx1ZSkudG9EYXRlKCk7XG4gICAgICAgIH1cbiAgICAgIH0sXG5cbiAgICAgIGFjdGlvbnM6IHtcbiAgICAgICAgLyoqXG4gICAgICAgICAqIEF0dWFsaXphIG9zIHN0YXR1cyBkYSB0YXJlZmFcbiAgICAgICAgICpcbiAgICAgICAgICogQHBhcmFtIHtvYmplY3R9IGF0dHJpYnV0ZXNcbiAgICAgICAgICovXG4gICAgICAgIHRvZ2dsZURvbmU6IHtcbiAgICAgICAgICBtZXRob2Q6ICdQVVQnLFxuICAgICAgICAgIHVybDogJ3RvZ2dsZURvbmUnXG4gICAgICAgIH1cbiAgICAgIH0sXG4gICAgICBpbnN0YW5jZTogeyB9XG4gICAgfSk7XG4gIH1cblxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnRyb2xsZXIoJ1VzZXJzRGlhbG9nQ29udHJvbGxlcicsIFVzZXJzRGlhbG9nQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBVc2Vyc0RpYWxvZ0NvbnRyb2xsZXIoJGNvbnRyb2xsZXIsIFVzZXJzU2VydmljZSwgUHJEaWFsb2csICAvLyBOT1NPTkFSXG4gICAgdXNlckRpYWxvZ0lucHV0LCBvbkluaXQpIHtcblxuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICB2bS5vbkFjdGl2YXRlID0gb25BY3RpdmF0ZTtcbiAgICB2bS5hcHBseUZpbHRlcnMgPSBhcHBseUZpbHRlcnM7XG4gICAgdm0uY2xvc2UgPSBjbG9zZTtcblxuICAgIGlmIChhbmd1bGFyLmlzRGVmaW5lZCh1c2VyRGlhbG9nSW5wdXQpKSB7XG4gICAgICB2bS50cmFuc2ZlclVzZXIgPSB1c2VyRGlhbG9nSW5wdXQudHJhbnNmZXJVc2VyRm47XG4gICAgfVxuXG4gICAgLy8gaW5zdGFudGlhdGUgYmFzZSBjb250cm9sbGVyXG4gICAgJGNvbnRyb2xsZXIoJ0NSVURDb250cm9sbGVyJywge1xuICAgICAgdm06IHZtLFxuICAgICAgbW9kZWxTZXJ2aWNlOiBVc2Vyc1NlcnZpY2UsXG4gICAgICBzZWFyY2hPbkluaXQ6IG9uSW5pdCxcbiAgICAgIG9wdGlvbnM6IHtcbiAgICAgICAgcGVyUGFnZTogNVxuICAgICAgfVxuICAgIH0pO1xuXG4gICAgZnVuY3Rpb24gb25BY3RpdmF0ZSgpIHtcbiAgICAgIHZtLnF1ZXJ5RmlsdGVycyA9IHt9O1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGFwcGx5RmlsdGVycygpIHtcbiAgICAgIHJldHVybiBhbmd1bGFyLmV4dGVuZCh2bS5kZWZhdWx0UXVlcnlGaWx0ZXJzLCB2bS5xdWVyeUZpbHRlcnMpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGNsb3NlKCkge1xuICAgICAgUHJEaWFsb2cuY2xvc2UoKTtcbiAgICB9XG5cbiAgfVxuXG59KSgpO1xuIl0sInNvdXJjZVJvb3QiOiIvc291cmNlLyJ9
