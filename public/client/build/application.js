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
    homeState: 'app.projects',
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
      vm.itensMenu = [{ state: 'app.dashboard', title: menuPrefix + 'dashboard', icon: 'dashboard', subItens: [] },
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

  ProjectsController.$inject = ["Global", "$controller", "ProjectsService", "Auth", "RolesService"];
  angular.module('app').controller('ProjectsController', ProjectsController);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function ProjectsController(Global, $controller, ProjectsService, Auth, RolesService) {
    var vm = this;

    //Attributes Block

    //Functions Block
    vm.onActivate = onActivate;
    vm.applyFilters = applyFilters;
    vm.beforeSave = beforeSave;
    vm.afterSearch = afterSearch;

    vm.roles = {};

    // instantiate base controller
    $controller('CRUDController', { vm: vm, modelService: ProjectsService, options: {} });

    function onActivate() {
      RolesService.query().then(function (response) {
        vm.roles = response;
      });
      vm.queryFilters = {};
    }

    function afterSearch() {
      console.log(vm.resources);
    }

    function applyFilters(defaultQueryFilters) {
      return angular.extend(defaultQueryFilters, vm.querylters);
    }

    function beforeSave() {
      vm.resource.owner = Auth.currentUser.id;
      vm.resource.user_id = Auth.currentUser.id;
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
    $stateProvider.state('app.projects', {
      url: '/projects',
      templateUrl: Global.clientPath + '/projects/projects.html',
      controller: 'ProjectsController as projectsCtrl',
      data: { needAuthentication: true }
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
      projects: 'Projetos',
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
      signup: 'Cadastrar',
      criarProjeto: 'Criar Projeto',
      projectList: 'Lista de Projetos'
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImFwcGxpY2F0aW9uLmpzIiwiYXBwLmpzIiwiYXBwLmNvbmZpZy5qcyIsImFwcC5jb250cm9sbGVyLmpzIiwiYXBwLmV4dGVybmFsLmpzIiwiYXBwLmdsb2JhbC5qcyIsImFwcC5yb3V0ZXMuanMiLCJhcHAucnVuLmpzIiwiYXVkaXQvYXVkaXQuY29udHJvbGxlci5qcyIsImF1ZGl0L2F1ZGl0LnJvdXRlLmpzIiwiYXVkaXQvYXVkaXQuc2VydmljZS5qcyIsImF1dGgvYXV0aC5yb3V0ZS5qcyIsImF1dGgvYXV0aC5zZXJ2aWNlLmpzIiwiYXV0aC9sb2dpbi5jb250cm9sbGVyLmpzIiwiYXV0aC9wYXNzd29yZC5jb250cm9sbGVyLmpzIiwiY29yZS9iYXNlLnNlcnZpY2UuanMiLCJjb3JlL2NydWQuY29udHJvbGxlci5qcyIsImRpbmFtaWMtcXVlcnlzL2RpbmFtaWMtcXVlcnkucm91dGUuanMiLCJkaW5hbWljLXF1ZXJ5cy9kaW5hbWljLXF1ZXJ5LnNlcnZpY2UuanMiLCJkaW5hbWljLXF1ZXJ5cy9kaW5hbWljLXF1ZXJ5cy5jb250cm9sbGVyLmpzIiwiaTE4bi9sYW5ndWFnZS1sb2FkZXIuc2VydmljZS5qcyIsImkxOG4vdC1hdHRyLmZpbHRlci5qcyIsImkxOG4vdC1icmVhZGNydW1iLmZpbHRlci5qcyIsImkxOG4vdC1tb2RlbC5maWx0ZXIuanMiLCJpbnRlcmNlcHRvcnMvYXV0aGVudGljYXRpb24ubGlzdGVuZXIuanMiLCJpbnRlcmNlcHRvcnMvYXV0aG9yaXphdGlvbi5saXN0ZW5lci5qcyIsImludGVyY2VwdG9ycy9zcGlubmVyLmludGVyY2VwdG9yLmpzIiwiaW50ZXJjZXB0b3JzL3Rva2VuLmludGVyY2VwdG9yLmpzIiwiaW50ZXJjZXB0b3JzL3ZhbGlkYXRpb24uaW50ZXJjZXB0b3IuanMiLCJsYXlvdXQvbWVudS5jb250cm9sbGVyLmpzIiwibWFpbC9tYWlscy5jb250cm9sbGVyLmpzIiwibWFpbC9tYWlscy5yb3V0ZS5qcyIsIm1haWwvbWFpbHMuc2VydmljZS5qcyIsInByb2plY3RzL3Byb2plY3RzLmNvbnRyb2xsZXIuanMiLCJwcm9qZWN0cy9wcm9qZWN0cy5yb3V0ZS5qcyIsInByb2plY3RzL3Byb2plY3RzLnNlcnZpY2UuanMiLCJyb2xlcy9yb2xlcy1zdHIuZmlsdGVyLmpzIiwicm9sZXMvcm9sZXMuc2VydmljZS5qcyIsInN1cHBvcnQvc3VwcG9ydC5zZXJ2aWNlLmpzIiwidXNlcnMvcHJvZmlsZS5jb250cm9sbGVyLmpzIiwidXNlcnMvdXNlcnMuY29udHJvbGxlci5qcyIsInVzZXJzL3VzZXJzLnJvdXRlLmpzIiwidXNlcnMvdXNlcnMuc2VydmljZS5qcyIsIndpZGdldHMvYm94LmNvbXBvbmVudC5qcyIsIndpZGdldHMvY29udGVudC1ib2R5LmNvbXBvbmVudC5qcyIsIndpZGdldHMvY29udGVudC1oZWFkZXIuY29tcG9uZW50LmpzIiwiYXVkaXQvZmlsdGVycy9hdWRpdC1kZXRhaWwtdGl0bGUuZmlsdGVyLmpzIiwiYXVkaXQvZmlsdGVycy9hdWRpdC1tb2RlbC5maWx0ZXIuanMiLCJhdWRpdC9maWx0ZXJzL2F1ZGl0LXR5cGUuZmlsdGVyLmpzIiwiYXVkaXQvZmlsdGVycy9hdWRpdC12YWx1ZS5maWx0ZXIuanMiLCJpMThuL3B0LUJSL2F0dHJpYnV0ZXMuanMiLCJpMThuL3B0LUJSL2RpYWxvZy5qcyIsImkxOG4vcHQtQlIvZ2xvYmFsLmpzIiwiaTE4bi9wdC1CUi9tZXNzYWdlcy5qcyIsImkxOG4vcHQtQlIvbW9kZWxzLmpzIiwiaTE4bi9wdC1CUi92aWV3cy5qcyIsInNhbXBsZXMvdGFza3MvdGFza3MtZGlhbG9nLmNvbnRyb2xsZXIuanMiLCJzYW1wbGVzL3Rhc2tzL3Rhc2tzLnNlcnZpY2UuanMiLCJ1c2Vycy9kaWFsb2cvdXNlcnMtZGlhbG9nLmNvbnRyb2xsZXIuanMiXSwibmFtZXMiOlsiYW5ndWxhciIsIm1vZHVsZSIsImNvbmZpZyIsIkdsb2JhbCIsIiRtZFRoZW1pbmdQcm92aWRlciIsIiRtb2RlbEZhY3RvcnlQcm92aWRlciIsIiR0cmFuc2xhdGVQcm92aWRlciIsIm1vbWVudCIsIiRtZEFyaWFQcm92aWRlciIsInVzZUxvYWRlciIsInVzZVNhbml0aXplVmFsdWVTdHJhdGVneSIsInVzZVBvc3RDb21waWxpbmciLCJsb2NhbGUiLCJkZWZhdWx0T3B0aW9ucyIsInByZWZpeCIsImFwaVBhdGgiLCJ0aGVtZSIsInByaW1hcnlQYWxldHRlIiwiZGVmYXVsdCIsImFjY2VudFBhbGV0dGUiLCJ3YXJuUGFsZXR0ZSIsImVuYWJsZUJyb3dzZXJDb2xvciIsImRpc2FibGVXYXJuaW5ncyIsImNvbnRyb2xsZXIiLCJBcHBDb250cm9sbGVyIiwiJHN0YXRlIiwiQXV0aCIsInZtIiwiYW5vQXR1YWwiLCJsb2dvdXQiLCJnZXRJbWFnZVBlcmZpbCIsImFjdGl2YXRlIiwiZGF0ZSIsIkRhdGUiLCJnZXRGdWxsWWVhciIsInRoZW4iLCJnbyIsImxvZ2luU3RhdGUiLCJjdXJyZW50VXNlciIsImltYWdlIiwiaW1hZ2VQYXRoIiwiY29uc3RhbnQiLCJfIiwiYXBwTmFtZSIsImhvbWVTdGF0ZSIsImxvZ2luVXJsIiwicmVzZXRQYXNzd29yZFN0YXRlIiwibm90QXV0aG9yaXplZFN0YXRlIiwidG9rZW5LZXkiLCJjbGllbnRQYXRoIiwicm91dGVzIiwiJHN0YXRlUHJvdmlkZXIiLCIkdXJsUm91dGVyUHJvdmlkZXIiLCJzdGF0ZSIsInVybCIsInRlbXBsYXRlVXJsIiwiYWJzdHJhY3QiLCJyZXNvbHZlIiwidHJhbnNsYXRlUmVhZHkiLCIkdHJhbnNsYXRlIiwiJHEiLCJkZWZlcnJlZCIsImRlZmVyIiwidXNlIiwicHJvbWlzZSIsImRhdGEiLCJuZWVkQXV0aGVudGljYXRpb24iLCJ3aGVuIiwib3RoZXJ3aXNlIiwicnVuIiwiJHJvb3RTY29wZSIsIiRzdGF0ZVBhcmFtcyIsImF1dGgiLCJnbG9iYWwiLCJyZXRyaWV2ZVVzZXJGcm9tTG9jYWxTdG9yYWdlIiwiQXVkaXRDb250cm9sbGVyIiwiJGNvbnRyb2xsZXIiLCJBdWRpdFNlcnZpY2UiLCJQckRpYWxvZyIsIm9uQWN0aXZhdGUiLCJhcHBseUZpbHRlcnMiLCJ2aWV3RGV0YWlsIiwibW9kZWxTZXJ2aWNlIiwib3B0aW9ucyIsIm1vZGVscyIsInF1ZXJ5RmlsdGVycyIsImdldEF1ZGl0ZWRNb2RlbHMiLCJpZCIsImxhYmVsIiwiaW5zdGFudCIsInNvcnQiLCJpbmRleCIsImxlbmd0aCIsIm1vZGVsIiwicHVzaCIsInRvTG93ZXJDYXNlIiwidHlwZXMiLCJsaXN0VHlwZXMiLCJ0eXBlIiwiZGVmYXVsdFF1ZXJ5RmlsdGVycyIsImV4dGVuZCIsImF1ZGl0RGV0YWlsIiwibG9jYWxzIiwiY2xvc2UiLCJpc0FycmF5Iiwib2xkIiwibmV3IiwiY29udHJvbGxlckFzIiwiaGFzQmFja2Ryb3AiLCJjdXN0b20iLCJuZWVkUHJvZmlsZSIsImZhY3RvcnkiLCJzZXJ2aWNlRmFjdG9yeSIsImFjdGlvbnMiLCJtZXRob2QiLCJpbnN0YW5jZSIsImF1ZGl0UGF0aCIsIiRodHRwIiwiVXNlcnNTZXJ2aWNlIiwibG9naW4iLCJ1cGRhdGVDdXJyZW50VXNlciIsImF1dGhlbnRpY2F0ZWQiLCJzZW5kRW1haWxSZXNldFBhc3N3b3JkIiwicmVtb3RlVmFsaWRhdGVUb2tlbiIsImdldFRva2VuIiwic2V0VG9rZW4iLCJjbGVhclRva2VuIiwibG9jYWxTdG9yYWdlIiwicmVtb3ZlSXRlbSIsInRva2VuIiwic2V0SXRlbSIsImdldEl0ZW0iLCJnZXQiLCJyZWplY3QiLCJ1c2VyIiwibWVyZ2UiLCJmcm9tSnNvbiIsImpzb25Vc2VyIiwidG9Kc29uIiwiY3JlZGVudGlhbHMiLCJwb3N0IiwicmVzcG9uc2UiLCJlcnJvciIsInJlc2V0RGF0YSIsIkxvZ2luQ29udHJvbGxlciIsIm9wZW5EaWFsb2dSZXNldFBhc3MiLCJvcGVuRGlhbG9nU2lnblVwIiwiZW1haWwiLCJwYXNzd29yZCIsIlBhc3N3b3JkQ29udHJvbGxlciIsIiR0aW1lb3V0IiwiUHJUb2FzdCIsInNlbmRSZXNldCIsImNsb3NlRGlhbG9nIiwiY2xlYW5Gb3JtIiwicmVzZXQiLCJzdWNjZXNzIiwic3RhdHVzIiwibXNnIiwiaSIsInRvVXBwZXJDYXNlIiwiZmllbGQiLCJtZXNzYWdlIiwiJG1vZGVsRmFjdG9yeSIsInBhZ2luYXRlIiwid3JhcCIsImFmdGVyUmVxdWVzdCIsIkxpc3QiLCJDUlVEQ29udHJvbGxlciIsIlByUGFnaW5hdGlvbiIsInNlYXJjaCIsInBhZ2luYXRlU2VhcmNoIiwibm9ybWFsU2VhcmNoIiwiZWRpdCIsInNhdmUiLCJyZW1vdmUiLCJnb1RvIiwicmVkaXJlY3RBZnRlclNhdmUiLCJzZWFyY2hPbkluaXQiLCJwZXJQYWdlIiwic2tpcFBhZ2luYXRpb24iLCJ2aWV3Rm9ybSIsInJlc291cmNlIiwiaXNGdW5jdGlvbiIsInBhZ2luYXRvciIsImdldEluc3RhbmNlIiwicGFnZSIsImN1cnJlbnRQYWdlIiwiaXNEZWZpbmVkIiwiYmVmb3JlU2VhcmNoIiwiY2FsY051bWJlck9mUGFnZXMiLCJ0b3RhbCIsInJlc291cmNlcyIsIml0ZW1zIiwiYWZ0ZXJTZWFyY2giLCJxdWVyeSIsImZvcm0iLCJiZWZvcmVDbGVhbiIsIiRzZXRQcmlzdGluZSIsIiRzZXRVbnRvdWNoZWQiLCJhZnRlckNsZWFuIiwiY29weSIsImFmdGVyRWRpdCIsImJlZm9yZVNhdmUiLCIkc2F2ZSIsImFmdGVyU2F2ZSIsInJlc3BvbnNlRGF0YSIsIm9uU2F2ZUVycm9yIiwidGl0bGUiLCJkZXNjcmlwdGlvbiIsImNvbmZpcm0iLCJiZWZvcmVSZW1vdmUiLCIkZGVzdHJveSIsImFmdGVyUmVtb3ZlIiwiaW5mbyIsInZpZXdOYW1lIiwiRGluYW1pY1F1ZXJ5U2VydmljZSIsImdldE1vZGVscyIsIkRpbmFtaWNRdWVyeXNDb250cm9sbGVyIiwibG9kYXNoIiwibG9hZEF0dHJpYnV0ZXMiLCJsb2FkT3BlcmF0b3JzIiwiYWRkRmlsdGVyIiwicnVuRmlsdGVyIiwiZWRpdEZpbHRlciIsImxvYWRNb2RlbHMiLCJyZW1vdmVGaWx0ZXIiLCJjbGVhciIsInJlc3RhcnQiLCJ3aGVyZSIsImFkZGVkRmlsdGVycyIsIm5hbWUiLCJmaWx0ZXIiLCJhdHRyaWJ1dGUiLCJvcGVyYXRvciIsInZhbHVlIiwiZmlsdGVycyIsImF0dHJpYnV0ZXMiLCJvcGVyYXRvcnMiLCJpbmRleE9mIiwiaXNVbmRlZmluZWQiLCJrZXlzIiwiT2JqZWN0Iiwia2V5Iiwic3RhcnRzV2l0aCIsIiRpbmRleCIsInNwbGljZSIsIkxhbmd1YWdlTG9hZGVyIiwiU3VwcG9ydFNlcnZpY2UiLCIkbG9nIiwiJGluamVjdG9yIiwic2VydmljZSIsInRyYW5zbGF0ZSIsInZpZXdzIiwiZGlhbG9nIiwibWVzc2FnZXMiLCJsYW5ncyIsInRBdHRyIiwiJGZpbHRlciIsInRCcmVhZGNydW1iIiwic3BsaXQiLCJ0TW9kZWwiLCJhdXRoZW50aWNhdGlvbkxpc3RlbmVyIiwiJG9uIiwiZXZlbnQiLCJ0b1N0YXRlIiwiY2F0Y2giLCJ3YXJuIiwicHJldmVudERlZmF1bHQiLCJhdXRob3JpemF0aW9uTGlzdGVuZXIiLCJoYXNQcm9maWxlIiwiYWxsUHJvZmlsZXMiLCJzcGlubmVySW50ZXJjZXB0b3IiLCIkaHR0cFByb3ZpZGVyIiwiJHByb3ZpZGUiLCJzaG93SGlkZVNwaW5uZXIiLCJyZXF1ZXN0Iiwic2hvdyIsImhpZGUiLCJyZXNwb25zZUVycm9yIiwicmVqZWN0aW9uIiwiaW50ZXJjZXB0b3JzIiwidG9rZW5JbnRlcmNlcHRvciIsInJlZGlyZWN0V2hlblNlcnZlckxvZ2dlZE91dCIsImhlYWRlcnMiLCJyZWplY3Rpb25SZWFzb25zIiwidG9rZW5FcnJvciIsImZvckVhY2giLCJpcyIsInZhbGlkYXRpb25JbnRlcmNlcHRvciIsInNob3dFcnJvclZhbGlkYXRpb24iLCJza2lwVmFsaWRhdGlvbiIsImVycm9yVmFsaWRhdGlvbiIsIk1lbnVDb250cm9sbGVyIiwiJG1kU2lkZW5hdiIsIiRtZENvbG9ycyIsIm9wZW4iLCJvcGVuTWVudU9yUmVkaXJlY3RUb1N0YXRlIiwibWVudVByZWZpeCIsIml0ZW5zTWVudSIsImljb24iLCJzdWJJdGVucyIsInByb2ZpbGVzIiwic2lkZW5hdlN0eWxlIiwidG9wIiwiZ2V0Q29sb3IiLCJjb250ZW50IiwidGV4dENvbG9yIiwiY29sb3IiLCJsaW5lQm90dG9tIiwidG9nZ2xlIiwiJG1kTWVudSIsImV2IiwiaXRlbSIsImNvbG9yUGFsZXR0ZXMiLCJnZXRUaGVtZUNvbG9yIiwiTWFpbHNDb250cm9sbGVyIiwiTWFpbHNTZXJ2aWNlIiwiZmlsdGVyU2VsZWN0ZWQiLCJza2luIiwibGFuZ3VhZ2UiLCJhbGxvd2VkQ29udGVudCIsImVudGl0aWVzIiwiaGVpZ2h0IiwiZXh0cmFQbHVnaW5zIiwibG9hZFVzZXJzIiwib3BlblVzZXJEaWFsb2ciLCJhZGRVc2VyTWFpbCIsInNlbmQiLCJjcml0ZXJpYSIsIm5hbWVPckVtYWlsIiwibm90VXNlcnMiLCJtYXAiLCJtYWlsIiwidXNlcnMiLCJwcm9wZXJ0eSIsInRvU3RyaW5nIiwibGltaXQiLCJmaW5kIiwib25Jbml0IiwidXNlckRpYWxvZ0lucHV0IiwidHJhbnNmZXJVc2VyRm4iLCJQcm9qZWN0c0NvbnRyb2xsZXIiLCJQcm9qZWN0c1NlcnZpY2UiLCJSb2xlc1NlcnZpY2UiLCJyb2xlcyIsImNvbnNvbGUiLCJsb2ciLCJxdWVyeWx0ZXJzIiwib3duZXIiLCJ1c2VyX2lkIiwicm9sZXNTdHIiLCJqb2luIiwiY2FjaGUiLCJQcm9maWxlQ29udHJvbGxlciIsInVwZGF0ZSIsInVwZGF0ZVByb2ZpbGUiLCJVc2Vyc0NvbnRyb2xsZXIiLCJkZWZhdWx0cyIsIm92ZXJyaWRlIiwiYWxsIiwidXNlclJvbGVzIiwiaW50ZXJzZWN0aW9uIiwiaXNBZG1pbiIsImNvbXBvbmVudCIsInJlcGxhY2UiLCJ0cmFuc2NsdWRlIiwidG9vbGJhckJ1dHRvbnMiLCJmb290ZXJCdXR0b25zIiwiYmluZGluZ3MiLCJib3hUaXRsZSIsInRvb2xiYXJDbGFzcyIsInRvb2xiYXJCZ0NvbG9yIiwiJHRyYW5zY2x1ZGUiLCJjdHJsIiwiJG9uSW5pdCIsImxheW91dEFsaWduIiwiYXVkaXREZXRhaWxUaXRsZSIsImF1ZGl0TW9kZWwiLCJtb2RlbElkIiwiYXVkaXRUeXBlIiwidHlwZUlkIiwiYXVkaXRWYWx1ZSIsImlzRGF0ZSIsImVuZHNXaXRoIiwiTnVtYmVyIiwiaW5pdGlhbERhdGUiLCJmaW5hbERhdGUiLCJ0YXNrIiwiZG9uZSIsInByaW9yaXR5Iiwic2NoZWR1bGVkX3RvIiwicHJvamVjdCIsImNvc3QiLCJjb25maXJtVGl0bGUiLCJjb25maXJtRGVzY3JpcHRpb24iLCJyZW1vdmVEZXNjcmlwdGlvbiIsImF1ZGl0IiwiY3JlYXRlZCIsInVwZGF0ZWRCZWZvcmUiLCJ1cGRhdGVkQWZ0ZXIiLCJkZWxldGVkIiwicmVzZXRQYXNzd29yZCIsImxvYWRpbmciLCJwcm9jZXNzaW5nIiwieWVzIiwibm8iLCJpbnRlcm5hbEVycm9yIiwibm90Rm91bmQiLCJub3RBdXRob3JpemVkIiwic2VhcmNoRXJyb3IiLCJzYXZlU3VjY2VzcyIsIm9wZXJhdGlvblN1Y2Nlc3MiLCJvcGVyYXRpb25FcnJvciIsInNhdmVFcnJvciIsInJlbW92ZVN1Y2Nlc3MiLCJyZW1vdmVFcnJvciIsInJlc291cmNlTm90Rm91bmRFcnJvciIsIm5vdE51bGxFcnJvciIsImR1cGxpY2F0ZWRSZXNvdXJjZUVycm9yIiwidmFsaWRhdGUiLCJmaWVsZFJlcXVpcmVkIiwibGF5b3V0IiwiZXJyb3I0MDQiLCJsb2dvdXRJbmFjdGl2ZSIsImludmFsaWRDcmVkZW50aWFscyIsInVua25vd25FcnJvciIsInVzZXJOb3RGb3VuZCIsImRhc2hib2FyZCIsIndlbGNvbWUiLCJtYWlsRXJyb3JzIiwic2VuZE1haWxTdWNjZXNzIiwic2VuZE1haWxFcnJvciIsInBhc3N3b3JkU2VuZGluZ1N1Y2Nlc3MiLCJyZW1vdmVZb3VyU2VsZkVycm9yIiwidXNlckV4aXN0cyIsInByb2ZpbGUiLCJ1cGRhdGVFcnJvciIsInF1ZXJ5RGluYW1pYyIsIm5vRmlsdGVyIiwiYnJlYWRjcnVtYnMiLCJwcm9qZWN0cyIsInRpdGxlcyIsIm1haWxTZW5kIiwidGFza0xpc3QiLCJ1c2VyTGlzdCIsImF1ZGl0TGlzdCIsInJlZ2lzdGVyIiwiY2xlYXJBbGwiLCJsaXN0IiwiY2FuY2VsIiwiZ2V0T3V0IiwiYWRkIiwiaW4iLCJsb2FkSW1hZ2UiLCJzaWdudXAiLCJjcmlhclByb2pldG8iLCJwcm9qZWN0TGlzdCIsImZpZWxkcyIsImFjdGlvbiIsImRhdGVTdGFydCIsImRhdGVFbmQiLCJhbGxSZXNvdXJjZXMiLCJ1cGRhdGVkIiwiY29uZmlybVBhc3N3b3JkIiwidG8iLCJzdWJqZWN0IiwicmVzdWx0cyIsImVxdWFscyIsImRpZmVyZW50IiwiY29udGVpbnMiLCJzdGFydFdpdGgiLCJmaW5pc2hXaXRoIiwiYmlnZ2VyVGhhbiIsImVxdWFsc09yQmlnZ2VyVGhhbiIsImxlc3NUaGFuIiwiZXF1YWxzT3JMZXNzVGhhbiIsInRvdGFsVGFzayIsInBlcmZpbHMiLCJtZW51IiwiYWRtaW4iLCJleGFtcGxlcyIsImRpbmFtaWNRdWVyeSIsInRvb2x0aXBzIiwicGVyZmlsIiwidHJhbnNmZXIiLCJsaXN0VGFzayIsIlRhc2tzRGlhbG9nQ29udHJvbGxlciIsIlRhc2tzU2VydmljZSIsInByb2plY3RJZCIsInRvZ2dsZURvbmUiLCJwcm9qZWN0X2lkIiwidG9EYXRlIiwiVXNlcnNEaWFsb2dDb250cm9sbGVyIiwidHJhbnNmZXJVc2VyIl0sIm1hcHBpbmdzIjoiQUFBQTs7O0FDQ0EsQ0FBQyxZQUFXO0VBQ1Y7O0VBRUFBLFFBQVFDLE9BQU8sT0FBTyxDQUNwQixhQUNBLFVBQ0EsYUFDQSxZQUNBLGtCQUNBLGFBQ0EsY0FDQSxnQkFDQSxpQkFDQSx3QkFDQSwwQkFDQTs7QURSSjs7QUVSQyxDQUFBLFlBQVk7RUFDWDs7O0VBRUFELFFBQ0dDLE9BQU8sT0FDUEMsT0FBT0E7Ozs7RUFJVixTQUFTQSxPQUFPQyxRQUFRQyxvQkFBb0JDO0VBQzFDQyxvQkFBb0JDLFFBQVFDLGlCQUFpQjs7SUFFN0NGLG1CQUNHRyxVQUFVLGtCQUNWQyx5QkFBeUI7O0lBRTVCSixtQkFB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QUNWeFgsUUFBUTtVQUNSNUQsS0FBSzs7O01BR1Q2RCxVQUFVOzs7O0F6RGtoRmhCOztBMERwakZBLENBQUMsWUFBVzs7RUFFVjs7O0VBRUFuSCxRQUNHQyxPQUFPLE9BQ1BzQixXQUFXLHlCQUF5QnNkOzs7O0VBSXZDLFNBQVNBLHNCQUFzQmphLGFBQWEwQyxjQUFjeEM7RUFDeERzUSxpQkFBaUJELFFBQVE7O0lBRXpCLElBQUl4VCxLQUFLOztJQUVUQSxHQUFHb0QsYUFBYUE7SUFDaEJwRCxHQUFHcUQsZUFBZUE7SUFDbEJyRCxHQUFHNEUsUUFBUUE7O0lBRVgsSUFBSXZHLFFBQVE0TCxVQUFVd0osa0JBQWtCO01BQ3RDelQsR0FBR21kLGVBQWUxSixnQkFBZ0JDOzs7O0lBSXBDelEsWUFBWSxrQkFBa0I7TUFDNUJqRCxJQUFJQTtNQUNKdUQsY0FBY29DO01BQ2Q0RCxjQUFjaUs7TUFDZGhRLFNBQVM7UUFDUGdHLFNBQVM7Ozs7SUFJYixTQUFTcEcsYUFBYTtNQUNwQnBELEdBQUcwRCxlQUFlOzs7SUFHcEIsU0FBU0wsZUFBZTtNQUN0QixPQUFPaEYsUUFBUW9HLE9BQU96RSxHQUFHd0UscUJBQXFCeEUsR0FBRzBEOzs7SUFHbkQsU0FBU2tCLFFBQVE7TUFDZnpCLFNBQVN5Qjs7O0tBMUNmIiwiZmlsZSI6ImFwcGxpY2F0aW9uLmpzIiwic291cmNlc0NvbnRlbnQiOlsiJ3VzZSBzdHJpY3QnO1xuXG4vKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCovXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcsIFsnbmdBbmltYXRlJywgJ25nQXJpYScsICd1aS5yb3V0ZXInLCAnbmdQcm9kZWInLCAndWkudXRpbHMubWFza3MnLCAndGV4dC1tYXNrJywgJ25nTWF0ZXJpYWwnLCAnbW9kZWxGYWN0b3J5JywgJ21kLmRhdGEudGFibGUnLCAnbmdNYXRlcmlhbERhdGVQaWNrZXInLCAncGFzY2FscHJlY2h0LnRyYW5zbGF0ZScsICdhbmd1bGFyRmlsZVVwbG9hZCddKTtcbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29uZmlnKGNvbmZpZyk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBjb25maWcoR2xvYmFsLCAkbWRUaGVtaW5nUHJvdmlkZXIsICRtb2RlbEZhY3RvcnlQcm92aWRlciwgLy8gTk9TT05BUlxuICAkdHJhbnNsYXRlUHJvdmlkZXIsIG1vbWVudCwgJG1kQXJpYVByb3ZpZGVyKSB7XG5cbiAgICAkdHJhbnNsYXRlUHJvdmlkZXIudXNlTG9hZGVyKCdsYW5ndWFnZUxvYWRlcicpLnVzZVNhbml0aXplVmFsdWVTdHJhdGVneSgnZXNjYXBlJyk7XG5cbiAgICAkdHJhbnNsYXRlUHJvdmlkZXIudXNlUG9zdENvbXBpbGluZyh0cnVlKTtcblxuICAgIG1vbWVudC5sb2NhbGUoJ3B0LUJSJyk7XG5cbiAgICAvL29zIHNlcnZpw6dvcyByZWZlcmVudGUgYW9zIG1vZGVscyB2YWkgdXRpbGl6YXIgY29tbyBiYXNlIG5hcyB1cmxzXG4gICAgJG1vZGVsRmFjdG9yeVByb3ZpZGVyLmRlZmF1bHRPcHRpb25zLnByZWZpeCA9IEdsb2JhbC5hcGlQYXRoO1xuXG4gICAgLy8gQ29uZmlndXJhdGlvbiB0aGVtZVxuICAgICRtZFRoZW1pbmdQcm92aWRlci50aGVtZSgnZGVmYXVsdCcpLnByaW1hcnlQYWxldHRlKCdicm93bicsIHtcbiAgICAgIGRlZmF1bHQ6ICc3MDAnXG4gICAgfSkuYWNjZW50UGFsZXR0ZSgnYW1iZXInKS53YXJuUGFsZXR0ZSgnZGVlcC1vcmFuZ2UnKTtcblxuICAgIC8vIEVuYWJsZSBicm93c2VyIGNvbG9yXG4gICAgJG1kVGhlbWluZ1Byb3ZpZGVyLmVuYWJsZUJyb3dzZXJDb2xvcigpO1xuXG4gICAgJG1kQXJpYVByb3ZpZGVyLmRpc2FibGVXYXJuaW5ncygpO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29udHJvbGxlcignQXBwQ29udHJvbGxlcicsIEFwcENvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLyoqXG4gICAqIENvbnRyb2xhZG9yIHJlc3BvbnPDoXZlbCBwb3IgZnVuY2lvbmFsaWRhZGVzIHF1ZSBzw6NvIGFjaW9uYWRhcyBlbSBxdWFscXVlciB0ZWxhIGRvIHNpc3RlbWFcbiAgICpcbiAgICovXG4gIGZ1bmN0aW9uIEFwcENvbnRyb2xsZXIoJHN0YXRlLCBBdXRoLCBHbG9iYWwpIHtcbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgLy9hbm8gYXR1YWwgcGFyYSBzZXIgZXhpYmlkbyBubyByb2RhcMOpIGRvIHNpc3RlbWFcbiAgICB2bS5hbm9BdHVhbCA9IG51bGw7XG5cbiAgICB2bS5sb2dvdXQgPSBsb2dvdXQ7XG4gICAgdm0uZ2V0SW1hZ2VQZXJmaWwgPSBnZXRJbWFnZVBlcmZpbDtcblxuICAgIGFjdGl2YXRlKCk7XG5cbiAgICBmdW5jdGlvbiBhY3RpdmF0ZSgpIHtcbiAgICAgIHZhciBkYXRlID0gbmV3IERhdGUoKTtcblxuICAgICAgdm0uYW5vQXR1YWwgPSBkYXRlLmdldEZ1bGxZZWFyKCk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gbG9nb3V0KCkge1xuICAgICAgQXV0aC5sb2dvdXQoKS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgJHN0YXRlLmdvKEdsb2JhbC5sb2dpblN0YXRlKTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGdldEltYWdlUGVyZmlsKCkge1xuICAgICAgcmV0dXJuIEF1dGguY3VycmVudFVzZXIgJiYgQXV0aC5jdXJyZW50VXNlci5pbWFnZSA/IEF1dGguY3VycmVudFVzZXIuaW1hZ2UgOiBHbG9iYWwuaW1hZ2VQYXRoICsgJy9ub19hdmF0YXIuZ2lmJztcbiAgICB9XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbi8qZXNsaW50IGFuZ3VsYXIvZmlsZS1uYW1lOiAwLCBuby11bmRlZjogMCovXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgLyoqXG4gICAqIFRyYW5zZm9ybWEgYmlibGlvdGVjYXMgZXh0ZXJuYXMgZW0gc2VydmnDp29zIGRvIGFuZ3VsYXIgcGFyYSBzZXIgcG9zc8OtdmVsIHV0aWxpemFyXG4gICAqIGF0cmF2w6lzIGRhIGluamXDp8OjbyBkZSBkZXBlbmTDqm5jaWFcbiAgICovXG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbnN0YW50KCdsb2Rhc2gnLCBfKS5jb25zdGFudCgnbW9tZW50JywgbW9tZW50KTtcbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29uc3RhbnQoJ0dsb2JhbCcsIHtcbiAgICBhcHBOYW1lOiAnRnJlZWxhZ2lsZScsXG4gICAgaG9tZVN0YXRlOiAnYXBwLnByb2plY3RzJyxcbiAgICBsb2dpblVybDogJ2FwcC9sb2dpbicsXG4gICAgbG9naW5TdGF0ZTogJ2FwcC5sb2dpbicsXG4gICAgcmVzZXRQYXNzd29yZFN0YXRlOiAnYXBwLnBhc3N3b3JkLXJlc2V0JyxcbiAgICBub3RBdXRob3JpemVkU3RhdGU6ICdhcHAubm90LWF1dGhvcml6ZWQnLFxuICAgIHRva2VuS2V5OiAnc2VydmVyX3Rva2VuJyxcbiAgICBjbGllbnRQYXRoOiAnY2xpZW50L2FwcCcsXG4gICAgYXBpUGF0aDogJ2FwaS92MScsXG4gICAgaW1hZ2VQYXRoOiAnY2xpZW50L2ltYWdlcydcbiAgfSk7XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCAkdXJsUm91dGVyUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdhcHAnLCB7XG4gICAgICB1cmw6ICcvYXBwJyxcbiAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvbGF5b3V0L2FwcC5odG1sJyxcbiAgICAgIGFic3RyYWN0OiB0cnVlLFxuICAgICAgcmVzb2x2ZTogeyAvL2Vuc3VyZSBsYW5ncyBpcyByZWFkeSBiZWZvcmUgcmVuZGVyIHZpZXdcbiAgICAgICAgdHJhbnNsYXRlUmVhZHk6IFsnJHRyYW5zbGF0ZScsICckcScsIGZ1bmN0aW9uICgkdHJhbnNsYXRlLCAkcSkge1xuICAgICAgICAgIHZhciBkZWZlcnJlZCA9ICRxLmRlZmVyKCk7XG5cbiAgICAgICAgICAkdHJhbnNsYXRlLnVzZSgncHQtQlInKS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIGRlZmVycmVkLnJlc29sdmUoKTtcbiAgICAgICAgICB9KTtcblxuICAgICAgICAgIHJldHVybiBkZWZlcnJlZC5wcm9taXNlO1xuICAgICAgICB9XVxuICAgICAgfVxuICAgIH0pLnN0YXRlKEdsb2JhbC5ub3RBdXRob3JpemVkU3RhdGUsIHtcbiAgICAgIHVybDogJy9hY2Vzc28tbmVnYWRvJyxcbiAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvbGF5b3V0L25vdC1hdXRob3JpemVkLmh0bWwnLFxuICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IGZhbHNlIH1cbiAgICB9KTtcblxuICAgICR1cmxSb3V0ZXJQcm92aWRlci53aGVuKCcvYXBwJywgR2xvYmFsLmxvZ2luVXJsKTtcbiAgICAkdXJsUm91dGVyUHJvdmlkZXIub3RoZXJ3aXNlKEdsb2JhbC5sb2dpblVybCk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykucnVuKHJ1bik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBydW4oJHJvb3RTY29wZSwgJHN0YXRlLCAkc3RhdGVQYXJhbXMsIEF1dGgsIEdsb2JhbCkge1xuICAgIC8vIE5PU09OQVJcbiAgICAvL3NldGFkbyBubyByb290U2NvcGUgcGFyYSBwb2RlciBzZXIgYWNlc3NhZG8gbmFzIHZpZXdzIHNlbSBwcmVmaXhvIGRlIGNvbnRyb2xsZXJcbiAgICAkcm9vdFNjb3BlLiRzdGF0ZSA9ICRzdGF0ZTtcbiAgICAkcm9vdFNjb3BlLiRzdGF0ZVBhcmFtcyA9ICRzdGF0ZVBhcmFtcztcbiAgICAkcm9vdFNjb3BlLmF1dGggPSBBdXRoO1xuICAgICRyb290U2NvcGUuZ2xvYmFsID0gR2xvYmFsO1xuXG4gICAgLy9ubyBpbmljaW8gY2FycmVnYSBvIHVzdcOhcmlvIGRvIGxvY2Fsc3RvcmFnZSBjYXNvIG8gdXN1w6FyaW8gZXN0YWphIGFicmluZG8gbyBuYXZlZ2Fkb3JcbiAgICAvL3BhcmEgdm9sdGFyIGF1dGVudGljYWRvXG4gICAgQXV0aC5yZXRyaWV2ZVVzZXJGcm9tTG9jYWxTdG9yYWdlKCk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb250cm9sbGVyKCdBdWRpdENvbnRyb2xsZXInLCBBdWRpdENvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gQXVkaXRDb250cm9sbGVyKCRjb250cm9sbGVyLCBBdWRpdFNlcnZpY2UsIFByRGlhbG9nLCBHbG9iYWwsICR0cmFuc2xhdGUpIHtcbiAgICAvLyBOT1NPTkFSXG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIHZtLm9uQWN0aXZhdGUgPSBvbkFjdGl2YXRlO1xuICAgIHZtLmFwcGx5RmlsdGVycyA9IGFwcGx5RmlsdGVycztcbiAgICB2bS52aWV3RGV0YWlsID0gdmlld0RldGFpbDtcblxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHsgdm06IHZtLCBtb2RlbFNlcnZpY2U6IEF1ZGl0U2VydmljZSwgb3B0aW9uczoge30gfSk7XG5cbiAgICBmdW5jdGlvbiBvbkFjdGl2YXRlKCkge1xuICAgICAgdm0ubW9kZWxzID0gW107XG4gICAgICB2bS5xdWVyeUZpbHRlcnMgPSB7fTtcblxuICAgICAgLy9QZWdhIHRvZG9zIG9zIG1vZGVscyBkbyBzZXJ2ZXIgZSBtb250YSB1bWEgbGlzdGEgcHJvIENvbWJvQm94XG4gICAgICBBdWRpdFNlcnZpY2UuZ2V0QXVkaXRlZE1vZGVscygpLnRoZW4oZnVuY3Rpb24gKGRhdGEpIHtcbiAgICAgICAgdmFyIG1vZGVscyA9IFt7IGlkOiAnJywgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudCgnZ2xvYmFsLmFsbCcpIH1dO1xuXG4gICAgICAgIGRhdGEubW9kZWxzLnNvcnQoKTtcblxuICAgICAgICBmb3IgKHZhciBpbmRleCA9IDA7IGluZGV4IDwgZGF0YS5tb2RlbHMubGVuZ3RoOyBpbmRleCsrKSB7XG4gICAgICAgICAgdmFyIG1vZGVsID0gZGF0YS5tb2RlbHNbaW5kZXhdO1xuXG4gICAgICAgICAgbW9kZWxzLnB1c2goe1xuICAgICAgICAgICAgaWQ6IG1vZGVsLFxuICAgICAgICAgICAgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudCgnbW9kZWxzLicgKyBtb2RlbC50b0xvd2VyQ2FzZSgpKVxuICAgICAgICAgIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgdm0ubW9kZWxzID0gbW9kZWxzO1xuICAgICAgICB2bS5xdWVyeUZpbHRlcnMubW9kZWwgPSB2bS5tb2RlbHNbMF0uaWQ7XG4gICAgICB9KTtcblxuICAgICAgdm0udHlwZXMgPSBBdWRpdFNlcnZpY2UubGlzdFR5cGVzKCk7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMudHlwZSA9IHZtLnR5cGVzWzBdLmlkO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGFwcGx5RmlsdGVycyhkZWZhdWx0UXVlcnlGaWx0ZXJzKSB7XG4gICAgICByZXR1cm4gYW5ndWxhci5leHRlbmQoZGVmYXVsdFF1ZXJ5RmlsdGVycywgdm0ucXVlcnlGaWx0ZXJzKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiB2aWV3RGV0YWlsKGF1ZGl0RGV0YWlsKSB7XG4gICAgICB2YXIgY29uZmlnID0ge1xuICAgICAgICBsb2NhbHM6IHsgYXVkaXREZXRhaWw6IGF1ZGl0RGV0YWlsIH0sXG4gICAgICAgIC8qKiBAbmdJbmplY3QgKi9cbiAgICAgICAgY29udHJvbGxlcjogZnVuY3Rpb24gY29udHJvbGxlcihhdWRpdERldGFpbCwgUHJEaWFsb2cpIHtcbiAgICAgICAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgICAgICAgdm0uY2xvc2UgPSBjbG9zZTtcblxuICAgICAgICAgIGFjdGl2YXRlKCk7XG5cbiAgICAgICAgICBmdW5jdGlvbiBhY3RpdmF0ZSgpIHtcbiAgICAgICAgICAgIGlmIChhbmd1bGFyLmlzQXJyYXkoYXVkaXREZXRhaWwub2xkKSAmJiBhdWRpdERldGFpbC5vbGQubGVuZ3RoID09PSAwKSBhdWRpdERldGFpbC5vbGQgPSBudWxsO1xuICAgICAgICAgICAgaWYgKGFuZ3VsYXIuaXNBcnJheShhdWRpdERldGFpbC5uZXcpICYmIGF1ZGl0RGV0YWlsLm5ldy5sZW5ndGggPT09IDApIGF1ZGl0RGV0YWlsLm5ldyA9IG51bGw7XG5cbiAgICAgICAgICAgIHZtLmF1ZGl0RGV0YWlsID0gYXVkaXREZXRhaWw7XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgZnVuY3Rpb24gY2xvc2UoKSB7XG4gICAgICAgICAgICBQckRpYWxvZy5jbG9zZSgpO1xuICAgICAgICAgIH1cbiAgICAgICAgfSxcbiAgICAgICAgY29udHJvbGxlckFzOiAnYXVkaXREZXRhaWxDdHJsJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9hdWRpdC9hdWRpdC1kZXRhaWwuaHRtbCcsXG4gICAgICAgIGhhc0JhY2tkcm9wOiB0cnVlXG4gICAgICB9O1xuXG4gICAgICBQckRpYWxvZy5jdXN0b20oY29uZmlnKTtcbiAgICB9XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqXG4gICAqIEFycXVpdm8gZGUgY29uZmlndXJhw6fDo28gY29tIGFzIHJvdGFzIGVzcGVjw61maWNhcyBkZSBhdWRpdG9yaWFcbiAgICpcbiAgICogQHBhcmFtIHthbnl9ICRzdGF0ZVByb3ZpZGVyXG4gICAqIEBwYXJhbSB7YW55fSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnYXBwLmF1ZGl0Jywge1xuICAgICAgdXJsOiAnL2F1ZGl0b3JpYScsXG4gICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL2F1ZGl0L2F1ZGl0Lmh0bWwnLFxuICAgICAgY29udHJvbGxlcjogJ0F1ZGl0Q29udHJvbGxlciBhcyBhdWRpdEN0cmwnLFxuICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IHRydWUsIG5lZWRQcm9maWxlOiBbJ2FkbWluJ10gfVxuICAgIH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZhY3RvcnkoJ0F1ZGl0U2VydmljZScsIEF1ZGl0U2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBBdWRpdFNlcnZpY2Uoc2VydmljZUZhY3RvcnksICR0cmFuc2xhdGUpIHtcbiAgICByZXR1cm4gc2VydmljZUZhY3RvcnkoJ2F1ZGl0Jywge1xuICAgICAgYWN0aW9uczoge1xuICAgICAgICBnZXRBdWRpdGVkTW9kZWxzOiB7XG4gICAgICAgICAgbWV0aG9kOiAnR0VUJyxcbiAgICAgICAgICB1cmw6ICdtb2RlbHMnXG4gICAgICAgIH1cbiAgICAgIH0sXG4gICAgICBpbnN0YW5jZToge30sXG4gICAgICBsaXN0VHlwZXM6IGZ1bmN0aW9uIGxpc3RUeXBlcygpIHtcbiAgICAgICAgdmFyIGF1ZGl0UGF0aCA9ICd2aWV3cy5maWVsZHMuYXVkaXQuJztcblxuICAgICAgICByZXR1cm4gW3sgaWQ6ICcnLCBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KGF1ZGl0UGF0aCArICdhbGxSZXNvdXJjZXMnKSB9LCB7IGlkOiAnY3JlYXRlZCcsIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoYXVkaXRQYXRoICsgJ3R5cGUuY3JlYXRlZCcpIH0sIHsgaWQ6ICd1cGRhdGVkJywgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudChhdWRpdFBhdGggKyAndHlwZS51cGRhdGVkJykgfSwgeyBpZDogJ2RlbGV0ZWQnLCBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KGF1ZGl0UGF0aCArICd0eXBlLmRlbGV0ZWQnKSB9XTtcbiAgICAgIH1cbiAgICB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25maWcocm91dGVzKTtcblxuICAvKipcbiAgICogQXJxdWl2byBkZSBjb25maWd1cmHDp8OjbyBjb20gYXMgcm90YXMgZXNwZWPDrWZpY2FzIGRvIHJlY3Vyc28gdXNlclxuICAgKlxuICAgKiBAcGFyYW0ge2FueX0gJHN0YXRlUHJvdmlkZXJcbiAgICogQHBhcmFtIHthbnl9IEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKEdsb2JhbC5yZXNldFBhc3N3b3JkU3RhdGUsIHtcbiAgICAgIHVybDogJy9wYXNzd29yZC9yZXNldC86dG9rZW4nLFxuICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9hdXRoL3Jlc2V0LXBhc3MtZm9ybS5odG1sJyxcbiAgICAgIGNvbnRyb2xsZXI6ICdQYXNzd29yZENvbnRyb2xsZXIgYXMgcGFzc0N0cmwnLFxuICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IGZhbHNlIH1cbiAgICB9KS5zdGF0ZShHbG9iYWwubG9naW5TdGF0ZSwge1xuICAgICAgdXJsOiAnL2xvZ2luJyxcbiAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvYXV0aC9sb2dpbi5odG1sJyxcbiAgICAgIGNvbnRyb2xsZXI6ICdMb2dpbkNvbnRyb2xsZXIgYXMgbG9naW5DdHJsJyxcbiAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiBmYWxzZSB9XG4gICAgfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmFjdG9yeSgnQXV0aCcsIEF1dGgpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gQXV0aCgkaHR0cCwgJHEsIEdsb2JhbCwgVXNlcnNTZXJ2aWNlKSB7XG4gICAgLy8gTk9TT05BUlxuICAgIHZhciBhdXRoID0ge1xuICAgICAgbG9naW46IGxvZ2luLFxuICAgICAgbG9nb3V0OiBsb2dvdXQsXG4gICAgICB1cGRhdGVDdXJyZW50VXNlcjogdXBkYXRlQ3VycmVudFVzZXIsXG4gICAgICByZXRyaWV2ZVVzZXJGcm9tTG9jYWxTdG9yYWdlOiByZXRyaWV2ZVVzZXJGcm9tTG9jYWxTdG9yYWdlLFxuICAgICAgYXV0aGVudGljYXRlZDogYXV0aGVudGljYXRlZCxcbiAgICAgIHNlbmRFbWFpbFJlc2V0UGFzc3dvcmQ6IHNlbmRFbWFpbFJlc2V0UGFzc3dvcmQsXG4gICAgICByZW1vdGVWYWxpZGF0ZVRva2VuOiByZW1vdGVWYWxpZGF0ZVRva2VuLFxuICAgICAgZ2V0VG9rZW46IGdldFRva2VuLFxuICAgICAgc2V0VG9rZW46IHNldFRva2VuLFxuICAgICAgY2xlYXJUb2tlbjogY2xlYXJUb2tlbixcbiAgICAgIGN1cnJlbnRVc2VyOiBudWxsXG4gICAgfTtcblxuICAgIGZ1bmN0aW9uIGNsZWFyVG9rZW4oKSB7XG4gICAgICBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbShHbG9iYWwudG9rZW5LZXkpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIHNldFRva2VuKHRva2VuKSB7XG4gICAgICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbShHbG9iYWwudG9rZW5LZXksIHRva2VuKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBnZXRUb2tlbigpIHtcbiAgICAgIHJldHVybiBsb2NhbFN0b3JhZ2UuZ2V0SXRlbShHbG9iYWwudG9rZW5LZXkpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIHJlbW90ZVZhbGlkYXRlVG9rZW4oKSB7XG4gICAgICB2YXIgZGVmZXJyZWQgPSAkcS5kZWZlcigpO1xuXG4gICAgICBpZiAoYXV0aC5hdXRoZW50aWNhdGVkKCkpIHtcbiAgICAgICAgJGh0dHAuZ2V0KEdsb2JhbC5hcGlQYXRoICsgJy9hdXRoZW50aWNhdGUvY2hlY2snKS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICBkZWZlcnJlZC5yZXNvbHZlKHRydWUpO1xuICAgICAgICB9LCBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgYXV0aC5sb2dvdXQoKTtcblxuICAgICAgICAgIGRlZmVycmVkLnJlamVjdChmYWxzZSk7XG4gICAgICAgIH0pO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgYXV0aC5sb2dvdXQoKTtcblxuICAgICAgICBkZWZlcnJlZC5yZWplY3QoZmFsc2UpO1xuICAgICAgfVxuXG4gICAgICByZXR1cm4gZGVmZXJyZWQucHJvbWlzZTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBWZXJpZmljYSBzZSBvIHVzdcOhcmlvIGVzdMOhIGF1dGVudGljYWRvXG4gICAgICpcbiAgICAgKiBAcmV0dXJucyB7Ym9vbGVhbn1cbiAgICAgKi9cbiAgICBmdW5jdGlvbiBhdXRoZW50aWNhdGVkKCkge1xuICAgICAgcmV0dXJuIGF1dGguZ2V0VG9rZW4oKSAhPT0gbnVsbDtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWN1cGVyYSBvIHVzdcOhcmlvIGRvIGxvY2FsU3RvcmFnZVxuICAgICAqL1xuICAgIGZ1bmN0aW9uIHJldHJpZXZlVXNlckZyb21Mb2NhbFN0b3JhZ2UoKSB7XG4gICAgICB2YXIgdXNlciA9IGxvY2FsU3RvcmFnZS5nZXRJdGVtKCd1c2VyJyk7XG5cbiAgICAgIGlmICh1c2VyKSB7XG4gICAgICAgIGF1dGguY3VycmVudFVzZXIgPSBhbmd1bGFyLm1lcmdlKG5ldyBVc2Vyc1NlcnZpY2UoKSwgYW5ndWxhci5mcm9tSnNvbih1c2VyKSk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogR3VhcmRhIG8gdXN1w6FyaW8gbm8gbG9jYWxTdG9yYWdlIHBhcmEgY2FzbyBvIHVzdcOhcmlvIGZlY2hlIGUgYWJyYSBvIG5hdmVnYWRvclxuICAgICAqIGRlbnRybyBkbyB0ZW1wbyBkZSBzZXNzw6NvIHNlamEgcG9zc8OtdmVsIHJlY3VwZXJhciBvIHRva2VuIGF1dGVudGljYWRvLlxuICAgICAqXG4gICAgICogTWFudMOpbSBhIHZhcmnDoXZlbCBhdXRoLmN1cnJlbnRVc2VyIHBhcmEgZmFjaWxpdGFyIG8gYWNlc3NvIGFvIHVzdcOhcmlvIGxvZ2FkbyBlbSB0b2RhIGEgYXBsaWNhw6fDo29cbiAgICAgKlxuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IHVzZXIgVXN1w6FyaW8gYSBzZXIgYXR1YWxpemFkby4gQ2FzbyBzZWphIHBhc3NhZG8gbnVsbCBsaW1wYVxuICAgICAqIHRvZGFzIGFzIGluZm9ybWHDp8O1ZXMgZG8gdXN1w6FyaW8gY29ycmVudGUuXG4gICAgICovXG4gICAgZnVuY3Rpb24gdXBkYXRlQ3VycmVudFVzZXIodXNlcikge1xuICAgICAgdmFyIGRlZmVycmVkID0gJHEuZGVmZXIoKTtcblxuICAgICAgaWYgKHVzZXIpIHtcbiAgICAgICAgdXNlciA9IGFuZ3VsYXIubWVyZ2UobmV3IFVzZXJzU2VydmljZSgpLCB1c2VyKTtcblxuICAgICAgICB2YXIganNvblVzZXIgPSBhbmd1bGFyLnRvSnNvbih1c2VyKTtcblxuICAgICAgICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbSgndXNlcicsIGpzb25Vc2VyKTtcbiAgICAgICAgYXV0aC5jdXJyZW50VXNlciA9IHVzZXI7XG5cbiAgICAgICAgZGVmZXJyZWQucmVzb2x2ZSh1c2VyKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKCd1c2VyJyk7XG4gICAgICAgIGF1dGguY3VycmVudFVzZXIgPSBudWxsO1xuICAgICAgICBhdXRoLmNsZWFyVG9rZW4oKTtcblxuICAgICAgICBkZWZlcnJlZC5yZWplY3QoKTtcbiAgICAgIH1cblxuICAgICAgcmV0dXJuIGRlZmVycmVkLnByb21pc2U7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhbGl6YSBvIGxvZ2luIGRvIHVzdcOhcmlvXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gY3JlZGVudGlhbHMgRW1haWwgZSBTZW5oYSBkbyB1c3XDoXJpb1xuICAgICAqIEByZXR1cm5zIHtwcm9taXNlfSBVbWEgcHJvbWlzZSBjb20gbyByZXN1bHRhZG8gZG8gY2hhbWFkYSBubyBiYWNrZW5kXG4gICAgICovXG4gICAgZnVuY3Rpb24gbG9naW4oY3JlZGVudGlhbHMpIHtcbiAgICAgIHZhciBkZWZlcnJlZCA9ICRxLmRlZmVyKCk7XG5cbiAgICAgICRodHRwLnBvc3QoR2xvYmFsLmFwaVBhdGggKyAnL2F1dGhlbnRpY2F0ZScsIGNyZWRlbnRpYWxzKS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICBhdXRoLnNldFRva2VuKHJlc3BvbnNlLmRhdGEudG9rZW4pO1xuXG4gICAgICAgIHJldHVybiAkaHR0cC5nZXQoR2xvYmFsLmFwaVBhdGggKyAnL2F1dGhlbnRpY2F0ZS91c2VyJyk7XG4gICAgICB9KS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICBhdXRoLnVwZGF0ZUN1cnJlbnRVc2VyKHJlc3BvbnNlLmRhdGEudXNlcik7XG5cbiAgICAgICAgZGVmZXJyZWQucmVzb2x2ZSgpO1xuICAgICAgfSwgZnVuY3Rpb24gKGVycm9yKSB7XG4gICAgICAgIGF1dGgubG9nb3V0KCk7XG5cbiAgICAgICAgZGVmZXJyZWQucmVqZWN0KGVycm9yKTtcbiAgICAgIH0pO1xuXG4gICAgICByZXR1cm4gZGVmZXJyZWQucHJvbWlzZTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBEZXNsb2dhIG9zIHVzdcOhcmlvcy4gQ29tbyBuw6NvIHRlbiBuZW5odW1hIGluZm9ybWHDp8OjbyBuYSBzZXNzw6NvIGRvIHNlcnZpZG9yXG4gICAgICogZSB1bSB0b2tlbiB1bWEgdmV6IGdlcmFkbyBuw6NvIHBvZGUsIHBvciBwYWRyw6NvLCBzZXIgaW52YWxpZGFkbyBhbnRlcyBkbyBzZXUgdGVtcG8gZGUgZXhwaXJhw6fDo28sXG4gICAgICogc29tZW50ZSBhcGFnYW1vcyBvcyBkYWRvcyBkbyB1c3XDoXJpbyBlIG8gdG9rZW4gZG8gbmF2ZWdhZG9yIHBhcmEgZWZldGl2YXIgbyBsb2dvdXQuXG4gICAgICpcbiAgICAgKiBAcmV0dXJucyB7cHJvbWlzZX0gVW1hIHByb21pc2UgY29tIG8gcmVzdWx0YWRvIGRhIG9wZXJhw6fDo29cbiAgICAgKi9cbiAgICBmdW5jdGlvbiBsb2dvdXQoKSB7XG4gICAgICB2YXIgZGVmZXJyZWQgPSAkcS5kZWZlcigpO1xuXG4gICAgICBhdXRoLnVwZGF0ZUN1cnJlbnRVc2VyKG51bGwpO1xuICAgICAgZGVmZXJyZWQucmVzb2x2ZSgpO1xuXG4gICAgICByZXR1cm4gZGVmZXJyZWQucHJvbWlzZTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBFbnZpYSB1bSBlbWFpbCBwYXJhIHJlY3VwZXJhw6fDo28gZGUgc2VuaGFcbiAgICAgKiBAcGFyYW0ge09iamVjdH0gcmVzZXREYXRhIC0gT2JqZXRvIGNvbnRlbmRvIG8gZW1haWxcbiAgICAgKiBAcmV0dXJuIHtQcm9taXNlfSAtIFJldG9ybmEgdW1hIHByb21pc2UgcGFyYSBzZXIgcmVzb2x2aWRhXG4gICAgICovXG4gICAgZnVuY3Rpb24gc2VuZEVtYWlsUmVzZXRQYXNzd29yZChyZXNldERhdGEpIHtcbiAgICAgIHZhciBkZWZlcnJlZCA9ICRxLmRlZmVyKCk7XG5cbiAgICAgICRodHRwLnBvc3QoR2xvYmFsLmFwaVBhdGggKyAnL3Bhc3N3b3JkL2VtYWlsJywgcmVzZXREYXRhKS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICBkZWZlcnJlZC5yZXNvbHZlKHJlc3BvbnNlLmRhdGEpO1xuICAgICAgfSwgZnVuY3Rpb24gKGVycm9yKSB7XG4gICAgICAgIGRlZmVycmVkLnJlamVjdChlcnJvcik7XG4gICAgICB9KTtcblxuICAgICAgcmV0dXJuIGRlZmVycmVkLnByb21pc2U7XG4gICAgfVxuXG4gICAgcmV0dXJuIGF1dGg7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb250cm9sbGVyKCdMb2dpbkNvbnRyb2xsZXInLCBMb2dpbkNvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gTG9naW5Db250cm9sbGVyKCRzdGF0ZSwgQXV0aCwgR2xvYmFsLCBQckRpYWxvZykge1xuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICB2bS5sb2dpbiA9IGxvZ2luO1xuICAgIHZtLm9wZW5EaWFsb2dSZXNldFBhc3MgPSBvcGVuRGlhbG9nUmVzZXRQYXNzO1xuICAgIHZtLm9wZW5EaWFsb2dTaWduVXAgPSBvcGVuRGlhbG9nU2lnblVwO1xuXG4gICAgYWN0aXZhdGUoKTtcblxuICAgIGZ1bmN0aW9uIGFjdGl2YXRlKCkge1xuICAgICAgdm0uY3JlZGVudGlhbHMgPSB7fTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBsb2dpbigpIHtcbiAgICAgIHZhciBjcmVkZW50aWFscyA9IHtcbiAgICAgICAgZW1haWw6IHZtLmNyZWRlbnRpYWxzLmVtYWlsLFxuICAgICAgICBwYXNzd29yZDogdm0uY3JlZGVudGlhbHMucGFzc3dvcmRcbiAgICAgIH07XG5cbiAgICAgIEF1dGgubG9naW4oY3JlZGVudGlhbHMpLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICAkc3RhdGUuZ28oR2xvYmFsLmhvbWVTdGF0ZSk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBFeGliZSBvIGRpYWxvZyBwYXJhIHJlY3VwZXJhw6fDo28gZGUgc2VuaGFcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBvcGVuRGlhbG9nUmVzZXRQYXNzKCkge1xuICAgICAgdmFyIGNvbmZpZyA9IHtcbiAgICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9hdXRoL3NlbmQtcmVzZXQtZGlhbG9nLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnUGFzc3dvcmRDb250cm9sbGVyIGFzIHBhc3NDdHJsJyxcbiAgICAgICAgaGFzQmFja2Ryb3A6IHRydWVcbiAgICAgIH07XG5cbiAgICAgIFByRGlhbG9nLmN1c3RvbShjb25maWcpO1xuICAgIH1cbiAgICAvKipcbiAgICAgKiBFeGliZSBvIGRpYWxvZyBwYXJhIHJlY3VwZXJhw6fDo28gZGUgc2VuaGFcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBvcGVuRGlhbG9nU2lnblVwKCkge1xuICAgICAgdmFyIGNvbmZpZyA9IHtcbiAgICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy91c2Vycy91c2VyLWZvcm0uaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdVc2Vyc0NvbnRyb2xsZXIgYXMgdXNlcnNDdHJsJyxcbiAgICAgICAgaGFzQmFja2Ryb3A6IHRydWVcbiAgICAgIH07XG5cbiAgICAgIFByRGlhbG9nLmN1c3RvbShjb25maWcpO1xuICAgIH1cbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbnRyb2xsZXIoJ1Bhc3N3b3JkQ29udHJvbGxlcicsIFBhc3N3b3JkQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBQYXNzd29yZENvbnRyb2xsZXIoR2xvYmFsLCAkc3RhdGVQYXJhbXMsICRodHRwLCAkdGltZW91dCwgJHN0YXRlLCAvLyBOT1NPTkFSXG4gIFByVG9hc3QsIFByRGlhbG9nLCBBdXRoLCAkdHJhbnNsYXRlKSB7XG5cbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0uc2VuZFJlc2V0ID0gc2VuZFJlc2V0O1xuICAgIHZtLmNsb3NlRGlhbG9nID0gY2xvc2VEaWFsb2c7XG4gICAgdm0uY2xlYW5Gb3JtID0gY2xlYW5Gb3JtO1xuICAgIHZtLnNlbmRFbWFpbFJlc2V0UGFzc3dvcmQgPSBzZW5kRW1haWxSZXNldFBhc3N3b3JkO1xuXG4gICAgYWN0aXZhdGUoKTtcblxuICAgIGZ1bmN0aW9uIGFjdGl2YXRlKCkge1xuICAgICAgdm0ucmVzZXQgPSB7IGVtYWlsOiAnJywgdG9rZW46ICRzdGF0ZVBhcmFtcy50b2tlbiB9O1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWxpemEgYSBhbHRlcmHDp8OjbyBkYSBzZW5oYSBkbyB1c3XDoXJpbyBlIG8gcmVkaXJlY2lvbmEgcGFyYSBhIHRlbGEgZGUgbG9naW5cbiAgICAgKi9cbiAgICBmdW5jdGlvbiBzZW5kUmVzZXQoKSB7XG4gICAgICAkaHR0cC5wb3N0KEdsb2JhbC5hcGlQYXRoICsgJy9wYXNzd29yZC9yZXNldCcsIHZtLnJlc2V0KS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgUHJUb2FzdC5zdWNjZXNzKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMub3BlcmF0aW9uU3VjY2VzcycpKTtcbiAgICAgICAgJHRpbWVvdXQoZnVuY3Rpb24gKCkge1xuICAgICAgICAgICRzdGF0ZS5nbyhHbG9iYWwubG9naW5TdGF0ZSk7XG4gICAgICAgIH0sIDE1MDApO1xuICAgICAgfSwgZnVuY3Rpb24gKGVycm9yKSB7XG4gICAgICAgIGlmIChlcnJvci5zdGF0dXMgIT09IDQwMCAmJiBlcnJvci5zdGF0dXMgIT09IDUwMCkge1xuICAgICAgICAgIHZhciBtc2cgPSAnJztcblxuICAgICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgZXJyb3IuZGF0YS5wYXNzd29yZC5sZW5ndGg7IGkrKykge1xuICAgICAgICAgICAgbXNnICs9IGVycm9yLmRhdGEucGFzc3dvcmRbaV0gKyAnPGJyPic7XG4gICAgICAgICAgfVxuICAgICAgICAgIFByVG9hc3QuZXJyb3IobXNnLnRvVXBwZXJDYXNlKCkpO1xuICAgICAgICB9XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBFbnZpYSB1bSBlbWFpbCBkZSByZWN1cGVyYcOnw6NvIGRlIHNlbmhhIGNvbSBvIHRva2VuIGRvIHVzdcOhcmlvXG4gICAgICovXG4gICAgZnVuY3Rpb24gc2VuZEVtYWlsUmVzZXRQYXNzd29yZCgpIHtcblxuICAgICAgaWYgKHZtLnJlc2V0LmVtYWlsID09PSAnJykge1xuICAgICAgICBQclRvYXN0LmVycm9yKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMudmFsaWRhdGUuZmllbGRSZXF1aXJlZCcsIHsgZmllbGQ6ICdlbWFpbCcgfSkpO1xuICAgICAgICByZXR1cm47XG4gICAgICB9XG5cbiAgICAgIEF1dGguc2VuZEVtYWlsUmVzZXRQYXNzd29yZCh2bS5yZXNldCkudGhlbihmdW5jdGlvbiAoZGF0YSkge1xuICAgICAgICBQclRvYXN0LnN1Y2Nlc3MoZGF0YS5tZXNzYWdlKTtcblxuICAgICAgICB2bS5jbGVhbkZvcm0oKTtcbiAgICAgICAgdm0uY2xvc2VEaWFsb2coKTtcbiAgICAgIH0sIGZ1bmN0aW9uIChlcnJvcikge1xuICAgICAgICBpZiAoZXJyb3IuZGF0YS5lbWFpbCAmJiBlcnJvci5kYXRhLmVtYWlsLmxlbmd0aCA+IDApIHtcbiAgICAgICAgICB2YXIgbXNnID0gJyc7XG5cbiAgICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IGVycm9yLmRhdGEuZW1haWwubGVuZ3RoOyBpKyspIHtcbiAgICAgICAgICAgIG1zZyArPSBlcnJvci5kYXRhLmVtYWlsW2ldICsgJzxicj4nO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIFByVG9hc3QuZXJyb3IobXNnKTtcbiAgICAgICAgfVxuICAgICAgfSk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gY2xvc2VEaWFsb2coKSB7XG4gICAgICBQckRpYWxvZy5jbG9zZSgpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGNsZWFuRm9ybSgpIHtcbiAgICAgIHZtLnJlc2V0LmVtYWlsID0gJyc7XG4gICAgfVxuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4vKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCovXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZhY3RvcnkoJ3NlcnZpY2VGYWN0b3J5Jywgc2VydmljZUZhY3RvcnkpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLyoqXG4gICAqIE1haXMgaW5mb3JtYcOnw7VlczpcbiAgICogaHR0cHM6Ly9naXRodWIuY29tL3N3aW1sYW5lL2FuZ3VsYXItbW9kZWwtZmFjdG9yeS93aWtpL0FQSVxuICAgKi9cbiAgZnVuY3Rpb24gc2VydmljZUZhY3RvcnkoJG1vZGVsRmFjdG9yeSkge1xuICAgIHJldHVybiBmdW5jdGlvbiAodXJsLCBvcHRpb25zKSB7XG4gICAgICB2YXIgbW9kZWw7XG4gICAgICB2YXIgZGVmYXVsdE9wdGlvbnMgPSB7XG4gICAgICAgIGFjdGlvbnM6IHtcbiAgICAgICAgICAvKipcbiAgICAgICAgICAgKiBTZXJ2acOnbyBjb211bSBwYXJhIHJlYWxpemFyIGJ1c2NhIGNvbSBwYWdpbmHDp8Ojb1xuICAgICAgICAgICAqIE8gbWVzbW8gZXNwZXJhIHF1ZSBzZWphIHJldG9ybmFkbyB1bSBvYmpldG8gY29tIGl0ZW1zIGUgdG90YWxcbiAgICAgICAgICAgKi9cbiAgICAgICAgICBwYWdpbmF0ZToge1xuICAgICAgICAgICAgbWV0aG9kOiAnR0VUJyxcbiAgICAgICAgICAgIGlzQXJyYXk6IGZhbHNlLFxuICAgICAgICAgICAgd3JhcDogZmFsc2UsXG4gICAgICAgICAgICBhZnRlclJlcXVlc3Q6IGZ1bmN0aW9uIGFmdGVyUmVxdWVzdChyZXNwb25zZSkge1xuICAgICAgICAgICAgICBpZiAocmVzcG9uc2VbJ2l0ZW1zJ10pIHtcbiAgICAgICAgICAgICAgICByZXNwb25zZVsnaXRlbXMnXSA9IG1vZGVsLkxpc3QocmVzcG9uc2VbJ2l0ZW1zJ10pO1xuICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgcmV0dXJuIHJlc3BvbnNlO1xuICAgICAgICAgICAgfVxuICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgfTtcblxuICAgICAgbW9kZWwgPSAkbW9kZWxGYWN0b3J5KHVybCwgYW5ndWxhci5tZXJnZShkZWZhdWx0T3B0aW9ucywgb3B0aW9ucykpO1xuXG4gICAgICByZXR1cm4gbW9kZWw7XG4gICAgfTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbnRyb2xsZXIoJ0NSVURDb250cm9sbGVyJywgQ1JVRENvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLyoqXG4gICAqIENvbnRyb2xhZG9yIEJhc2UgcXVlIGltcGxlbWVudGEgdG9kYXMgYXMgZnVuw6fDtWVzIHBhZHLDtWVzIGRlIHVtIENSVURcbiAgICpcbiAgICogQcOnw7VlcyBpbXBsZW1lbnRhZGFzXG4gICAqIGFjdGl2YXRlKClcbiAgICogc2VhcmNoKHBhZ2UpXG4gICAqIGVkaXQocmVzb3VyY2UpXG4gICAqIHNhdmUoKVxuICAgKiByZW1vdmUocmVzb3VyY2UpXG4gICAqIGdvVG8odmlld05hbWUpXG4gICAqIGNsZWFuRm9ybSgpXG4gICAqXG4gICAqIEdhdGlsaG9zXG4gICAqXG4gICAqIG9uQWN0aXZhdGUoKVxuICAgKiBhcHBseUZpbHRlcnMoZGVmYXVsdFF1ZXJ5RmlsdGVycylcbiAgICogYmVmb3JlU2VhcmNoKHBhZ2UpIC8vcmV0b3JuYW5kbyBmYWxzZSBjYW5jZWxhIG8gZmx1eG9cbiAgICogYWZ0ZXJTZWFyY2gocmVzcG9uc2UpXG4gICAqIGJlZm9yZUNsZWFuIC8vcmV0b3JuYW5kbyBmYWxzZSBjYW5jZWxhIG8gZmx1eG9cbiAgICogYWZ0ZXJDbGVhbigpXG4gICAqIGJlZm9yZVNhdmUoKSAvL3JldG9ybmFuZG8gZmFsc2UgY2FuY2VsYSBvIGZsdXhvXG4gICAqIGFmdGVyU2F2ZShyZXNvdXJjZSlcbiAgICogb25TYXZlRXJyb3IoZXJyb3IpXG4gICAqIGJlZm9yZVJlbW92ZShyZXNvdXJjZSkgLy9yZXRvcm5hbmRvIGZhbHNlIGNhbmNlbGEgbyBmbHV4b1xuICAgKiBhZnRlclJlbW92ZShyZXNvdXJjZSlcbiAgICpcbiAgICogQHBhcmFtIHthbnl9IHZtIGluc3RhbmNpYSBkbyBjb250cm9sbGVyIGZpbGhvXG4gICAqIEBwYXJhbSB7YW55fSBtb2RlbFNlcnZpY2Ugc2VydmnDp28gZG8gbW9kZWwgcXVlIHZhaSBzZXIgdXRpbGl6YWRvXG4gICAqIEBwYXJhbSB7YW55fSBvcHRpb25zIG9ww6fDtWVzIHBhcmEgc29icmVlc2NyZXZlciBjb21wb3J0YW1lbnRvcyBwYWRyw7Vlc1xuICAgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gQ1JVRENvbnRyb2xsZXIodm0sIG1vZGVsU2VydmljZSwgb3B0aW9ucywgUHJUb2FzdCwgUHJQYWdpbmF0aW9uLCAvLyBOT1NPTkFSXG4gIFByRGlhbG9nLCAkdHJhbnNsYXRlKSB7XG5cbiAgICAvL0Z1bmN0aW9ucyBCbG9ja1xuICAgIHZtLnNlYXJjaCA9IHNlYXJjaDtcbiAgICB2bS5wYWdpbmF0ZVNlYXJjaCA9IHBhZ2luYXRlU2VhcmNoO1xuICAgIHZtLm5vcm1hbFNlYXJjaCA9IG5vcm1hbFNlYXJjaDtcbiAgICB2bS5lZGl0ID0gZWRpdDtcbiAgICB2bS5zYXZlID0gc2F2ZTtcbiAgICB2bS5yZW1vdmUgPSByZW1vdmU7XG4gICAgdm0uZ29UbyA9IGdvVG87XG4gICAgdm0uY2xlYW5Gb3JtID0gY2xlYW5Gb3JtO1xuXG4gICAgYWN0aXZhdGUoKTtcblxuICAgIC8qKlxuICAgICAqIFByZXBhcmEgbyBjb250cm9sYWRvclxuICAgICAqIEZheiBvIG1lcmdlIGRhcyBvcMOnw7Vlc1xuICAgICAqIEluaWNpYWxpemEgbyByZWN1cnNvXG4gICAgICogSW5pY2lhbGl6YSBvIG9iamV0byBwYWdpbmFkb3IgZSByZWFsaXphIGEgcGVzcXVpc2FcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBhY3RpdmF0ZSgpIHtcbiAgICAgIHZtLmRlZmF1bHRPcHRpb25zID0ge1xuICAgICAgICByZWRpcmVjdEFmdGVyU2F2ZTogdHJ1ZSxcbiAgICAgICAgc2VhcmNoT25Jbml0OiB0cnVlLFxuICAgICAgICBwZXJQYWdlOiA4LFxuICAgICAgICBza2lwUGFnaW5hdGlvbjogZmFsc2VcbiAgICAgIH07XG5cbiAgICAgIGFuZ3VsYXIubWVyZ2Uodm0uZGVmYXVsdE9wdGlvbnMsIG9wdGlvbnMpO1xuXG4gICAgICB2bS52aWV3Rm9ybSA9IGZhbHNlO1xuICAgICAgdm0ucmVzb3VyY2UgPSBuZXcgbW9kZWxTZXJ2aWNlKCk7XG5cbiAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0ub25BY3RpdmF0ZSkpIHZtLm9uQWN0aXZhdGUoKTtcblxuICAgICAgdm0ucGFnaW5hdG9yID0gUHJQYWdpbmF0aW9uLmdldEluc3RhbmNlKHZtLnNlYXJjaCwgdm0uZGVmYXVsdE9wdGlvbnMucGVyUGFnZSk7XG5cbiAgICAgIGlmICh2bS5kZWZhdWx0T3B0aW9ucy5zZWFyY2hPbkluaXQpIHZtLnNlYXJjaCgpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWxpemEgYSBwZXNxdWlzYVxuICAgICAqIFZlcmlmaWNhIHF1YWwgZGFzIGZ1bsOnw7VlcyBkZSBwZXNxdWlzYSBkZXZlIHNlciByZWFsaXphZGEuXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gcGFnZSBww6FnaW5hIHF1ZSBkZXZlIHNlciBjYXJyZWdhZGFcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBzZWFyY2gocGFnZSkge1xuICAgICAgdm0uZGVmYXVsdE9wdGlvbnMuc2tpcFBhZ2luYXRpb24gPyBub3JtYWxTZWFyY2goKSA6IHBhZ2luYXRlU2VhcmNoKHBhZ2UpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWxpemEgYSBwZXNxdWlzYSBwYWdpbmFkYSBjb20gYmFzZSBub3MgZmlsdHJvcyBkZWZpbmlkb3NcbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSBwYWdlIHDDoWdpbmEgcXVlIGRldmUgc2VyIGNhcnJlZ2FkYVxuICAgICAqL1xuICAgIGZ1bmN0aW9uIHBhZ2luYXRlU2VhcmNoKHBhZ2UpIHtcbiAgICAgIHZtLnBhZ2luYXRvci5jdXJyZW50UGFnZSA9IGFuZ3VsYXIuaXNEZWZpbmVkKHBhZ2UpID8gcGFnZSA6IDE7XG4gICAgICB2bS5kZWZhdWx0UXVlcnlGaWx0ZXJzID0geyBwYWdlOiB2bS5wYWdpbmF0b3IuY3VycmVudFBhZ2UsIHBlclBhZ2U6IHZtLnBhZ2luYXRvci5wZXJQYWdlIH07XG5cbiAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYXBwbHlGaWx0ZXJzKSkgdm0uZGVmYXVsdFF1ZXJ5RmlsdGVycyA9IHZtLmFwcGx5RmlsdGVycyh2bS5kZWZhdWx0UXVlcnlGaWx0ZXJzKTtcbiAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYmVmb3JlU2VhcmNoKSAmJiB2bS5iZWZvcmVTZWFyY2gocGFnZSkgPT09IGZhbHNlKSByZXR1cm4gZmFsc2U7XG5cbiAgICAgIG1vZGVsU2VydmljZS5wYWdpbmF0ZSh2bS5kZWZhdWx0UXVlcnlGaWx0ZXJzKS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICB2bS5wYWdpbmF0b3IuY2FsY051bWJlck9mUGFnZXMocmVzcG9uc2UudG90YWwpO1xuICAgICAgICB2bS5yZXNvdXJjZXMgPSByZXNwb25zZS5pdGVtcztcblxuICAgICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmFmdGVyU2VhcmNoKSkgdm0uYWZ0ZXJTZWFyY2gocmVzcG9uc2UpO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhbGl6YSBhIHBlc3F1aXNhIGNvbSBiYXNlIG5vcyBmaWx0cm9zIGRlZmluaWRvc1xuICAgICAqXG4gICAgICovXG4gICAgZnVuY3Rpb24gbm9ybWFsU2VhcmNoKCkge1xuICAgICAgdm0uZGVmYXVsdFF1ZXJ5RmlsdGVycyA9IHt9O1xuXG4gICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmFwcGx5RmlsdGVycykpIHZtLmRlZmF1bHRRdWVyeUZpbHRlcnMgPSB2bS5hcHBseUZpbHRlcnModm0uZGVmYXVsdFF1ZXJ5RmlsdGVycyk7XG4gICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmJlZm9yZVNlYXJjaCkgJiYgdm0uYmVmb3JlU2VhcmNoKCkgPT09IGZhbHNlKSByZXR1cm4gZmFsc2U7XG5cbiAgICAgIG1vZGVsU2VydmljZS5xdWVyeSh2bS5kZWZhdWx0UXVlcnlGaWx0ZXJzKS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICB2bS5yZXNvdXJjZXMgPSByZXNwb25zZTtcblxuICAgICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmFmdGVyU2VhcmNoKSkgdm0uYWZ0ZXJTZWFyY2gocmVzcG9uc2UpO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogTGltcGEgbyBmb3JtdWzDoXJpb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGNsZWFuRm9ybShmb3JtKSB7XG4gICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmJlZm9yZUNsZWFuKSAmJiB2bS5iZWZvcmVDbGVhbigpID09PSBmYWxzZSkgcmV0dXJuIGZhbHNlO1xuXG4gICAgICB2bS5yZXNvdXJjZSA9IG5ldyBtb2RlbFNlcnZpY2UoKTtcblxuICAgICAgaWYgKGFuZ3VsYXIuaXNEZWZpbmVkKGZvcm0pKSB7XG4gICAgICAgIGZvcm0uJHNldFByaXN0aW5lKCk7XG4gICAgICAgIGZvcm0uJHNldFVudG91Y2hlZCgpO1xuICAgICAgfVxuXG4gICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmFmdGVyQ2xlYW4pKSB2bS5hZnRlckNsZWFuKCk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ2FycmVnYSBubyBmb3JtdWzDoXJpbyBvIHJlY3Vyc28gc2VsZWNpb25hZG8gcGFyYSBlZGnDp8Ojb1xuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IHJlc291cmNlIHJlY3Vyc28gc2VsZWNpb25hZG9cbiAgICAgKi9cbiAgICBmdW5jdGlvbiBlZGl0KHJlc291cmNlKSB7XG4gICAgICB2bS5nb1RvKCdmb3JtJyk7XG4gICAgICB2bS5yZXNvdXJjZSA9IG5ldyBhbmd1bGFyLmNvcHkocmVzb3VyY2UpO1xuXG4gICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmFmdGVyRWRpdCkpIHZtLmFmdGVyRWRpdCgpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFNhbHZhIG91IGF0dWFsaXphIG8gcmVjdXJzbyBjb3JyZW50ZSBubyBmb3JtdWzDoXJpb1xuICAgICAqIE5vIGNvbXBvcnRhbWVudG8gcGFkcsOjbyByZWRpcmVjaW9uYSBvIHVzdcOhcmlvIHBhcmEgdmlldyBkZSBsaXN0YWdlbVxuICAgICAqIGRlcG9pcyBkYSBleGVjdcOnw6NvXG4gICAgICpcbiAgICAgKiBAcmV0dXJuc1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIHNhdmUoZm9ybSkge1xuICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5iZWZvcmVTYXZlKSAmJiB2bS5iZWZvcmVTYXZlKCkgPT09IGZhbHNlKSByZXR1cm4gZmFsc2U7XG5cbiAgICAgIHZtLnJlc291cmNlLiRzYXZlKCkudGhlbihmdW5jdGlvbiAocmVzb3VyY2UpIHtcbiAgICAgICAgdm0ucmVzb3VyY2UgPSByZXNvdXJjZTtcblxuICAgICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmFmdGVyU2F2ZSkpIHZtLmFmdGVyU2F2ZShyZXNvdXJjZSk7XG5cbiAgICAgICAgaWYgKHZtLmRlZmF1bHRPcHRpb25zLnJlZGlyZWN0QWZ0ZXJTYXZlKSB7XG4gICAgICAgICAgdm0uY2xlYW5Gb3JtKGZvcm0pO1xuICAgICAgICAgIHZtLnNlYXJjaCh2bS5wYWdpbmF0b3IuY3VycmVudFBhZ2UpO1xuICAgICAgICAgIHZtLmdvVG8oJ2xpc3QnKTtcbiAgICAgICAgfVxuXG4gICAgICAgIFByVG9hc3Quc3VjY2VzcygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnNhdmVTdWNjZXNzJykpO1xuICAgICAgfSwgZnVuY3Rpb24gKHJlc3BvbnNlRGF0YSkge1xuICAgICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLm9uU2F2ZUVycm9yKSkgdm0ub25TYXZlRXJyb3IocmVzcG9uc2VEYXRhKTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlbW92ZSBvIHJlY3Vyc28gaW5mb3JtYWRvLlxuICAgICAqIEFudGVzIGV4aWJlIHVtIGRpYWxvZ28gZGUgY29uZmlybWHDp8Ojb1xuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IHJlc291cmNlIHJlY3Vyc28gZXNjb2xoaWRvXG4gICAgICovXG4gICAgZnVuY3Rpb24gcmVtb3ZlKHJlc291cmNlKSB7XG4gICAgICB2YXIgY29uZmlnID0ge1xuICAgICAgICB0aXRsZTogJHRyYW5zbGF0ZS5pbnN0YW50KCdkaWFsb2cuY29uZmlybVRpdGxlJyksXG4gICAgICAgIGRlc2NyaXB0aW9uOiAkdHJhbnNsYXRlLmluc3RhbnQoJ2RpYWxvZy5jb25maXJtRGVzY3JpcHRpb24nKVxuICAgICAgfTtcblxuICAgICAgUHJEaWFsb2cuY29uZmlybShjb25maWcpLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmJlZm9yZVJlbW92ZSkgJiYgdm0uYmVmb3JlUmVtb3ZlKHJlc291cmNlKSA9PT0gZmFsc2UpIHJldHVybiBmYWxzZTtcblxuICAgICAgICByZXNvdXJjZS4kZGVzdHJveSgpLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYWZ0ZXJSZW1vdmUpKSB2bS5hZnRlclJlbW92ZShyZXNvdXJjZSk7XG5cbiAgICAgICAgICB2bS5zZWFyY2goKTtcbiAgICAgICAgICBQclRvYXN0LmluZm8oJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5yZW1vdmVTdWNjZXNzJykpO1xuICAgICAgICB9KTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEFsdGVybmEgZW50cmUgYSB2aWV3IGRvIGZvcm11bMOhcmlvIGUgbGlzdGFnZW1cbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSB2aWV3TmFtZSBub21lIGRhIHZpZXdcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBnb1RvKHZpZXdOYW1lKSB7XG4gICAgICB2bS52aWV3Rm9ybSA9IGZhbHNlO1xuXG4gICAgICBpZiAodmlld05hbWUgPT09ICdmb3JtJykge1xuICAgICAgICB2bS5jbGVhbkZvcm0oKTtcbiAgICAgICAgdm0udmlld0Zvcm0gPSB0cnVlO1xuICAgICAgfVxuICAgIH1cbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25maWcocm91dGVzKTtcblxuICAvKipcbiAgICogQXJxdWl2byBkZSBjb25maWd1cmHDp8OjbyBjb20gYXMgcm90YXMgZXNwZWPDrWZpY2FzIGRvIHJlY3Vyc28gdXNlclxuICAgKlxuICAgKiBAcGFyYW0ge2FueX0gJHN0YXRlUHJvdmlkZXJcbiAgICogQHBhcmFtIHthbnl9IEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdhcHAuZGluYW1pYy1xdWVyeScsIHtcbiAgICAgIHVybDogJy9jb25zdWx0YXMtZGluYW1pY2FzJyxcbiAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvZGluYW1pYy1xdWVyeXMvZGluYW1pYy1xdWVyeXMuaHRtbCcsXG4gICAgICBjb250cm9sbGVyOiAnRGluYW1pY1F1ZXJ5c0NvbnRyb2xsZXIgYXMgZGluYW1pY1F1ZXJ5Q3RybCcsXG4gICAgICBkYXRhOiB7IG5lZWRBdXRoZW50aWNhdGlvbjogdHJ1ZSwgbmVlZFByb2ZpbGU6IFsnYWRtaW4nXSB9XG4gICAgfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmFjdG9yeSgnRGluYW1pY1F1ZXJ5U2VydmljZScsIERpbmFtaWNRdWVyeVNlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gRGluYW1pY1F1ZXJ5U2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHJldHVybiBzZXJ2aWNlRmFjdG9yeSgnZGluYW1pY1F1ZXJ5Jywge1xuICAgICAgLyoqXG4gICAgICAgKiBhw6fDo28gYWRpY2lvbmFkYSBwYXJhIHBlZ2FyIHVtYSBsaXN0YSBkZSBtb2RlbHMgZXhpc3RlbnRlcyBubyBzZXJ2aWRvclxuICAgICAgICovXG4gICAgICBhY3Rpb25zOiB7XG4gICAgICAgIGdldE1vZGVsczoge1xuICAgICAgICAgIG1ldGhvZDogJ0dFVCcsXG4gICAgICAgICAgdXJsOiAnbW9kZWxzJ1xuICAgICAgICB9XG4gICAgICB9LFxuICAgICAgaW5zdGFuY2U6IHt9XG4gICAgfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb250cm9sbGVyKCdEaW5hbWljUXVlcnlzQ29udHJvbGxlcicsIERpbmFtaWNRdWVyeXNDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIERpbmFtaWNRdWVyeXNDb250cm9sbGVyKCRjb250cm9sbGVyLCBEaW5hbWljUXVlcnlTZXJ2aWNlLCBsb2Rhc2gsIFByVG9hc3QsIC8vIE5PU09OQVJcbiAgJHRyYW5zbGF0ZSkge1xuXG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIC8vYWN0aW9uc1xuICAgIHZtLm9uQWN0aXZhdGUgPSBvbkFjdGl2YXRlO1xuICAgIHZtLmFwcGx5RmlsdGVycyA9IGFwcGx5RmlsdGVycztcbiAgICB2bS5sb2FkQXR0cmlidXRlcyA9IGxvYWRBdHRyaWJ1dGVzO1xuICAgIHZtLmxvYWRPcGVyYXRvcnMgPSBsb2FkT3BlcmF0b3JzO1xuICAgIHZtLmFkZEZpbHRlciA9IGFkZEZpbHRlcjtcbiAgICB2bS5hZnRlclNlYXJjaCA9IGFmdGVyU2VhcmNoO1xuICAgIHZtLnJ1bkZpbHRlciA9IHJ1bkZpbHRlcjtcbiAgICB2bS5lZGl0RmlsdGVyID0gZWRpdEZpbHRlcjtcbiAgICB2bS5sb2FkTW9kZWxzID0gbG9hZE1vZGVscztcbiAgICB2bS5yZW1vdmVGaWx0ZXIgPSByZW1vdmVGaWx0ZXI7XG4gICAgdm0uY2xlYXIgPSBjbGVhcjtcbiAgICB2bS5yZXN0YXJ0ID0gcmVzdGFydDtcblxuICAgIC8vaGVyZGEgbyBjb21wb3J0YW1lbnRvIGJhc2UgZG8gQ1JVRFxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHsgdm06IHZtLCBtb2RlbFNlcnZpY2U6IERpbmFtaWNRdWVyeVNlcnZpY2UsIG9wdGlvbnM6IHtcbiAgICAgICAgc2VhcmNoT25Jbml0OiBmYWxzZVxuICAgICAgfSB9KTtcblxuICAgIGZ1bmN0aW9uIG9uQWN0aXZhdGUoKSB7XG4gICAgICB2bS5yZXN0YXJ0KCk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUHJlcGFyYSBlIGFwbGljYSBvcyBmaWx0cm8gcXVlIHbDo28gc2VyIGVudmlhZG9zIHBhcmEgbyBzZXJ2acOnb1xuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IGRlZmF1bHRRdWVyeUZpbHRlcnNcbiAgICAgKiBAcmV0dXJuc1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGFwcGx5RmlsdGVycyhkZWZhdWx0UXVlcnlGaWx0ZXJzKSB7XG4gICAgICB2YXIgd2hlcmUgPSB7fTtcblxuICAgICAgLyoqXG4gICAgICAgKiBvIHNlcnZpw6dvIGVzcGVyYSB1bSBvYmpldG8gY29tOlxuICAgICAgICogIG8gbm9tZSBkZSB1bSBtb2RlbFxuICAgICAgICogIHVtYSBsaXN0YSBkZSBmaWx0cm9zXG4gICAgICAgKi9cbiAgICAgIGlmICh2bS5hZGRlZEZpbHRlcnMubGVuZ3RoID4gMCkge1xuICAgICAgICB2YXIgYWRkZWRGaWx0ZXJzID0gYW5ndWxhci5jb3B5KHZtLmFkZGVkRmlsdGVycyk7XG5cbiAgICAgICAgd2hlcmUubW9kZWwgPSB2bS5hZGRlZEZpbHRlcnNbMF0ubW9kZWwubmFtZTtcblxuICAgICAgICBmb3IgKHZhciBpbmRleCA9IDA7IGluZGV4IDwgYWRkZWRGaWx0ZXJzLmxlbmd0aDsgaW5kZXgrKykge1xuICAgICAgICAgIHZhciBmaWx0ZXIgPSBhZGRlZEZpbHRlcnNbaW5kZXhdO1xuXG4gICAgICAgICAgZmlsdGVyLm1vZGVsID0gbnVsbDtcbiAgICAgICAgICBmaWx0ZXIuYXR0cmlidXRlID0gZmlsdGVyLmF0dHJpYnV0ZS5uYW1lO1xuICAgICAgICAgIGZpbHRlci5vcGVyYXRvciA9IGZpbHRlci5vcGVyYXRvci52YWx1ZTtcbiAgICAgICAgfVxuXG4gICAgICAgIHdoZXJlLmZpbHRlcnMgPSBhbmd1bGFyLnRvSnNvbihhZGRlZEZpbHRlcnMpO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgd2hlcmUubW9kZWwgPSB2bS5xdWVyeUZpbHRlcnMubW9kZWwubmFtZTtcbiAgICAgIH1cblxuICAgICAgcmV0dXJuIGFuZ3VsYXIuZXh0ZW5kKGRlZmF1bHRRdWVyeUZpbHRlcnMsIHdoZXJlKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDYXJyZWdhIHRvZG9zIG9zIG1vZGVscyBjcmlhZG9zIG5vIHNlcnZpZG9yIGNvbSBzZXVzIGF0cmlidXRvc1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGxvYWRNb2RlbHMoKSB7XG4gICAgICAvL1BlZ2EgdG9kb3Mgb3MgbW9kZWxzIGRvIHNlcnZlciBlIG1vbnRhIHVtYSBsaXN0YSBwcm8gQ29tYm9Cb3hcbiAgICAgIERpbmFtaWNRdWVyeVNlcnZpY2UuZ2V0TW9kZWxzKCkudGhlbihmdW5jdGlvbiAoZGF0YSkge1xuICAgICAgICB2bS5tb2RlbHMgPSBkYXRhO1xuICAgICAgICB2bS5xdWVyeUZpbHRlcnMubW9kZWwgPSB2bS5tb2RlbHNbMF07XG4gICAgICAgIHZtLmxvYWRBdHRyaWJ1dGVzKCk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDYXJyZWdhIG9zIGF0dHJpYnV0b3MgZG8gbW9kZWwgZXNjb2xoaWRvXG4gICAgICovXG4gICAgZnVuY3Rpb24gbG9hZEF0dHJpYnV0ZXMoKSB7XG4gICAgICB2bS5hdHRyaWJ1dGVzID0gdm0ucXVlcnlGaWx0ZXJzLm1vZGVsLmF0dHJpYnV0ZXM7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMuYXR0cmlidXRlID0gdm0uYXR0cmlidXRlc1swXTtcblxuICAgICAgdm0ubG9hZE9wZXJhdG9ycygpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENhcnJlZ2Egb3Mgb3BlcmFkb3JlcyBlc3BlY2lmaWNvcyBwYXJhIG8gdGlwbyBkbyBhdHJpYnV0b1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGxvYWRPcGVyYXRvcnMoKSB7XG4gICAgICB2YXIgb3BlcmF0b3JzID0gW3sgdmFsdWU6ICc9JywgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudCgndmlld3MuZmllbGRzLnF1ZXJ5RGluYW1pYy5vcGVyYXRvcnMuZXF1YWxzJykgfSwgeyB2YWx1ZTogJzw+JywgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudCgndmlld3MuZmllbGRzLnF1ZXJ5RGluYW1pYy5vcGVyYXRvcnMuZGlmZXJlbnQnKSB9XTtcblxuICAgICAgaWYgKHZtLnF1ZXJ5RmlsdGVycy5hdHRyaWJ1dGUudHlwZS5pbmRleE9mKCd2YXJ5aW5nJykgIT09IC0xKSB7XG4gICAgICAgIG9wZXJhdG9ycy5wdXNoKHsgdmFsdWU6ICdoYXMnLFxuICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLmNvbnRlaW5zJykgfSk7XG4gICAgICAgIG9wZXJhdG9ycy5wdXNoKHsgdmFsdWU6ICdzdGFydFdpdGgnLFxuICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLnN0YXJ0V2l0aCcpIH0pO1xuICAgICAgICBvcGVyYXRvcnMucHVzaCh7IHZhbHVlOiAnZW5kV2l0aCcsXG4gICAgICAgICAgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudCgndmlld3MuZmllbGRzLnF1ZXJ5RGluYW1pYy5vcGVyYXRvcnMuZmluaXNoV2l0aCcpIH0pO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgb3BlcmF0b3JzLnB1c2goeyB2YWx1ZTogJz4nLFxuICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLmJpZ2dlclRoYW4nKSB9KTtcbiAgICAgICAgb3BlcmF0b3JzLnB1c2goeyB2YWx1ZTogJz49JyxcbiAgICAgICAgICBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KCd2aWV3cy5maWVsZHMucXVlcnlEaW5hbWljLm9wZXJhdG9ycy5lcXVhbHNPckJpZ2dlclRoYW4nKSB9KTtcbiAgICAgICAgb3BlcmF0b3JzLnB1c2goeyB2YWx1ZTogJzwnLFxuICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLmxlc3NUaGFuJykgfSk7XG4gICAgICAgIG9wZXJhdG9ycy5wdXNoKHsgdmFsdWU6ICc8PScsXG4gICAgICAgICAgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudCgndmlld3MuZmllbGRzLnF1ZXJ5RGluYW1pYy5vcGVyYXRvcnMuZXF1YWxzT3JMZXNzVGhhbicpIH0pO1xuICAgICAgfVxuXG4gICAgICB2bS5vcGVyYXRvcnMgPSBvcGVyYXRvcnM7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMub3BlcmF0b3IgPSB2bS5vcGVyYXRvcnNbMF07XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQWRpY2lvbmEvZWRpdGEgdW0gZmlsdHJvXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gZm9ybSBlbGVtZW50byBodG1sIGRvIGZvcm11bMOhcmlvIHBhcmEgdmFsaWRhw6fDtWVzXG4gICAgICovXG4gICAgZnVuY3Rpb24gYWRkRmlsdGVyKGZvcm0pIHtcbiAgICAgIGlmIChhbmd1bGFyLmlzVW5kZWZpbmVkKHZtLnF1ZXJ5RmlsdGVycy52YWx1ZSkgfHwgdm0ucXVlcnlGaWx0ZXJzLnZhbHVlID09PSAnJykge1xuICAgICAgICBQclRvYXN0LmVycm9yKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMudmFsaWRhdGUuZmllbGRSZXF1aXJlZCcsIHsgZmllbGQ6ICd2YWxvcicgfSkpO1xuICAgICAgICByZXR1cm47XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBpZiAodm0uaW5kZXggPCAwKSB7XG4gICAgICAgICAgdm0uYWRkZWRGaWx0ZXJzLnB1c2goYW5ndWxhci5jb3B5KHZtLnF1ZXJ5RmlsdGVycykpO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIHZtLmFkZGVkRmlsdGVyc1t2bS5pbmRleF0gPSBhbmd1bGFyLmNvcHkodm0ucXVlcnlGaWx0ZXJzKTtcbiAgICAgICAgICB2bS5pbmRleCA9IC0xO1xuICAgICAgICB9XG5cbiAgICAgICAgLy9yZWluaWNpYSBvIGZvcm11bMOhcmlvIGUgYXMgdmFsaWRhw6fDtWVzIGV4aXN0ZW50ZXNcbiAgICAgICAgdm0ucXVlcnlGaWx0ZXJzID0ge307XG4gICAgICAgIGZvcm0uJHNldFByaXN0aW5lKCk7XG4gICAgICAgIGZvcm0uJHNldFVudG91Y2hlZCgpO1xuICAgICAgfVxuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWxpemEgYSBwZXNxdWlzYSB0ZW5kbyBvcyBmaWx0cm9zIGNvbW8gcGFyw6JtZXRyb3NcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBydW5GaWx0ZXIoKSB7XG4gICAgICB2bS5zZWFyY2godm0ucGFnaW5hdG9yLmN1cnJlbnRQYWdlKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBHYXRpbGhvIGFjaW9uYWRvIGRlcG9pcyBkYSBwZXNxdWlzYSByZXNwb25zw6F2ZWwgcG9yIGlkZW50aWZpY2FyIG9zIGF0cmlidXRvc1xuICAgICAqIGNvbnRpZG9zIG5vcyBlbGVtZW50b3MgcmVzdWx0YW50ZXMgZGEgYnVzY2FcbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSBkYXRhIGRhZG9zIHJlZmVyZW50ZSBhbyByZXRvcm5vIGRhIHJlcXVpc2nDp8Ojb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGFmdGVyU2VhcmNoKGRhdGEpIHtcbiAgICAgIHZhciBrZXlzID0gZGF0YS5pdGVtcy5sZW5ndGggPiAwID8gT2JqZWN0LmtleXMoZGF0YS5pdGVtc1swXSkgOiBbXTtcblxuICAgICAgLy9yZXRpcmEgdG9kb3Mgb3MgYXRyaWJ1dG9zIHF1ZSBjb21lw6dhbSBjb20gJC5cbiAgICAgIC8vRXNzZXMgYXRyaWJ1dG9zIHPDo28gYWRpY2lvbmFkb3MgcGVsbyBzZXJ2acOnbyBlIG7Do28gZGV2ZSBhcGFyZWNlciBuYSBsaXN0YWdlbVxuICAgICAgdm0ua2V5cyA9IGxvZGFzaC5maWx0ZXIoa2V5cywgZnVuY3Rpb24gKGtleSkge1xuICAgICAgICByZXR1cm4gIWxvZGFzaC5zdGFydHNXaXRoKGtleSwgJyQnKTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENvbG9hY2Egbm8gZm9ybXVsw6FyaW8gbyBmaWx0cm8gZXNjb2xoaWRvIHBhcmEgZWRpw6fDo29cbiAgICAgKiBAcGFyYW0ge2FueX0gJGluZGV4IGluZGljZSBubyBhcnJheSBkbyBmaWx0cm8gZXNjb2xoaWRvXG4gICAgICovXG4gICAgZnVuY3Rpb24gZWRpdEZpbHRlcigkaW5kZXgpIHtcbiAgICAgIHZtLmluZGV4ID0gJGluZGV4O1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0gdm0uYWRkZWRGaWx0ZXJzWyRpbmRleF07XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVtb3ZlIG8gZmlsdHJvIGVzY29saGlkb1xuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9ICRpbmRleCBpbmRpY2Ugbm8gYXJyYXkgZG8gZmlsdHJvIGVzY29saGlkb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIHJlbW92ZUZpbHRlcigkaW5kZXgpIHtcbiAgICAgIHZtLmFkZGVkRmlsdGVycy5zcGxpY2UoJGluZGV4KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBMaW1wYSBvIGZvcm11bMOhcmlvIGNvcnJlbnRlXG4gICAgICovXG4gICAgZnVuY3Rpb24gY2xlYXIoKSB7XG4gICAgICAvL2d1YXJkYSBvIGluZGljZSBkbyByZWdpc3RybyBxdWUgZXN0w6Egc2VuZG8gZWRpdGFkb1xuICAgICAgdm0uaW5kZXggPSAtMTtcbiAgICAgIC8vdmluY3VsYWRvIGFvcyBjYW1wb3MgZG8gZm9ybXVsw6FyaW9cbiAgICAgIHZtLnF1ZXJ5RmlsdGVycyA9IHt9O1xuXG4gICAgICBpZiAodm0ubW9kZWxzKSB2bS5xdWVyeUZpbHRlcnMubW9kZWwgPSB2bS5tb2RlbHNbMF07XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVpbmljaWEgYSBjb25zdHJ1w6fDo28gZGEgcXVlcnkgbGltcGFuZG8gdHVkb1xuICAgICAqXG4gICAgICovXG4gICAgZnVuY3Rpb24gcmVzdGFydCgpIHtcbiAgICAgIC8vZ3VhcmRhIGF0cmlidXRvcyBkbyByZXN1bHRhZG8gZGEgYnVzY2EgY29ycmVudGVcbiAgICAgIHZtLmtleXMgPSBbXTtcblxuICAgICAgLy9ndWFyZGEgb3MgZmlsdHJvcyBhZGljaW9uYWRvc1xuICAgICAgdm0uYWRkZWRGaWx0ZXJzID0gW107XG4gICAgICB2bS5jbGVhcigpO1xuICAgICAgdm0ubG9hZE1vZGVscygpO1xuICAgIH1cbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZhY3RvcnkoJ2xhbmd1YWdlTG9hZGVyJywgTGFuZ3VhZ2VMb2FkZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gTGFuZ3VhZ2VMb2FkZXIoJHEsIFN1cHBvcnRTZXJ2aWNlLCAkbG9nLCAkaW5qZWN0b3IpIHtcbiAgICB2YXIgc2VydmljZSA9IHRoaXM7XG5cbiAgICBzZXJ2aWNlLnRyYW5zbGF0ZSA9IGZ1bmN0aW9uIChsb2NhbGUpIHtcbiAgICAgIHJldHVybiB7XG4gICAgICAgIGdsb2JhbDogJGluamVjdG9yLmdldChsb2NhbGUgKyAnLmkxOG4uZ2xvYmFsJyksXG4gICAgICAgIHZpZXdzOiAkaW5qZWN0b3IuZ2V0KGxvY2FsZSArICcuaTE4bi52aWV3cycpLFxuICAgICAgICBhdHRyaWJ1dGVzOiAkaW5qZWN0b3IuZ2V0KGxvY2FsZSArICcuaTE4bi5hdHRyaWJ1dGVzJyksXG4gICAgICAgIGRpYWxvZzogJGluamVjdG9yLmdldChsb2NhbGUgKyAnLmkxOG4uZGlhbG9nJyksXG4gICAgICAgIG1lc3NhZ2VzOiAkaW5qZWN0b3IuZ2V0KGxvY2FsZSArICcuaTE4bi5tZXNzYWdlcycpLFxuICAgICAgICBtb2RlbHM6ICRpbmplY3Rvci5nZXQobG9jYWxlICsgJy5pMThuLm1vZGVscycpXG4gICAgICB9O1xuICAgIH07XG5cbiAgICAvLyByZXR1cm4gbG9hZGVyRm5cbiAgICByZXR1cm4gZnVuY3Rpb24gKG9wdGlvbnMpIHtcbiAgICAgICRsb2cuaW5mbygnQ2FycmVnYW5kbyBvIGNvbnRldWRvIGRhIGxpbmd1YWdlbSAnICsgb3B0aW9ucy5rZXkpO1xuXG4gICAgICB2YXIgZGVmZXJyZWQgPSAkcS5kZWZlcigpO1xuXG4gICAgICAvL0NhcnJlZ2EgYXMgbGFuZ3MgcXVlIHByZWNpc2FtIGUgZXN0w6NvIG5vIHNlcnZpZG9yIHBhcmEgbsOjbyBwcmVjaXNhciByZXBldGlyIGFxdWlcbiAgICAgIFN1cHBvcnRTZXJ2aWNlLmxhbmdzKCkudGhlbihmdW5jdGlvbiAobGFuZ3MpIHtcbiAgICAgICAgLy9NZXJnZSBjb20gb3MgbGFuZ3MgZGVmaW5pZG9zIG5vIHNlcnZpZG9yXG4gICAgICAgIHZhciBkYXRhID0gYW5ndWxhci5tZXJnZShzZXJ2aWNlLnRyYW5zbGF0ZShvcHRpb25zLmtleSksIGxhbmdzKTtcblxuICAgICAgICByZXR1cm4gZGVmZXJyZWQucmVzb2x2ZShkYXRhKTtcbiAgICAgIH0sIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgcmV0dXJuIGRlZmVycmVkLnJlc29sdmUoc2VydmljZS50cmFuc2xhdGUob3B0aW9ucy5rZXkpKTtcbiAgICAgIH0pO1xuXG4gICAgICByZXR1cm4gZGVmZXJyZWQucHJvbWlzZTtcbiAgICB9O1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmlsdGVyKCd0QXR0cicsIHRBdHRyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIHRBdHRyKCRmaWx0ZXIpIHtcbiAgICAvKipcbiAgICAgKiBGaWx0cm8gcGFyYSB0cmFkdcOnw6NvIGRlIHVtIGF0cmlidXRvIGRlIHVtIG1vZGVsXG4gICAgICogXG4gICAgICogQHBhcmFtIHthbnl9IG5hbWUgbm9tZSBkbyBhdHJpYnV0b1xuICAgICAqIEByZXR1cm5zIG8gbm9tZSBkbyBhdHJpYnV0byB0cmFkdXppZG8gY2FzbyBlbmNvbnRyZSBzZSBuw6NvIG8gbm9tZSBwYXNzYWRvIHBvciBwYXJhbWV0cm9cbiAgICAgKi9cbiAgICByZXR1cm4gZnVuY3Rpb24gKG5hbWUpIHtcbiAgICAgIHZhciBrZXkgPSAnYXR0cmlidXRlcy4nICsgbmFtZTtcbiAgICAgIHZhciB0cmFuc2xhdGUgPSAkZmlsdGVyKCd0cmFuc2xhdGUnKShrZXkpO1xuXG4gICAgICByZXR1cm4gdHJhbnNsYXRlID09PSBrZXkgPyBuYW1lIDogdHJhbnNsYXRlO1xuICAgIH07XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5maWx0ZXIoJ3RCcmVhZGNydW1iJywgdEJyZWFkY3J1bWIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gdEJyZWFkY3J1bWIoJGZpbHRlcikge1xuICAgIC8qKlxuICAgICAqIEZpbHRybyBwYXJhIHRyYWR1w6fDo28gZG8gYnJlYWRjcnVtYiAodGl0dWxvIGRhIHRlbGEgY29tIHJhc3RyZWlvKVxuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IGlkIGNoYXZlIGNvbSBvIG5vbWUgZG8gc3RhdGUgcmVmZXJlbnRlIHRlbGFcbiAgICAgKiBAcmV0dXJucyBhIHRyYWR1w6fDo28gY2FzbyBlbmNvbnRyZSBzZSBuw6NvIG8gaWQgcGFzc2FkbyBwb3IgcGFyYW1ldHJvXG4gICAgICovXG4gICAgcmV0dXJuIGZ1bmN0aW9uIChpZCkge1xuICAgICAgLy9wZWdhIGEgc2VndW5kYSBwYXJ0ZSBkbyBub21lIGRvIHN0YXRlLCByZXRpcmFuZG8gYSBwYXJ0ZSBhYnN0cmF0YSAoYXBwLilcbiAgICAgIHZhciBrZXkgPSAndmlld3MuYnJlYWRjcnVtYnMuJyArIGlkLnNwbGl0KCcuJylbMV07XG4gICAgICB2YXIgdHJhbnNsYXRlID0gJGZpbHRlcigndHJhbnNsYXRlJykoa2V5KTtcblxuICAgICAgcmV0dXJuIHRyYW5zbGF0ZSA9PT0ga2V5ID8gaWQgOiB0cmFuc2xhdGU7XG4gICAgfTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZpbHRlcigndE1vZGVsJywgdE1vZGVsKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIHRNb2RlbCgkZmlsdGVyKSB7XG4gICAgLyoqXG4gICAgICogRmlsdHJvIHBhcmEgdHJhZHXDp8OjbyBkZSB1bSBhdHJpYnV0byBkZSB1bSBtb2RlbFxuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IG5hbWUgbm9tZSBkbyBhdHJpYnV0b1xuICAgICAqIEByZXR1cm5zIG8gbm9tZSBkbyBhdHJpYnV0byB0cmFkdXppZG8gY2FzbyBlbmNvbnRyZSBzZSBuw6NvIG8gbm9tZSBwYXNzYWRvIHBvciBwYXJhbWV0cm9cbiAgICAgKi9cbiAgICByZXR1cm4gZnVuY3Rpb24gKG5hbWUpIHtcbiAgICAgIHZhciBrZXkgPSAnbW9kZWxzLicgKyBuYW1lLnRvTG93ZXJDYXNlKCk7XG4gICAgICB2YXIgdHJhbnNsYXRlID0gJGZpbHRlcigndHJhbnNsYXRlJykoa2V5KTtcblxuICAgICAgcmV0dXJuIHRyYW5zbGF0ZSA9PT0ga2V5ID8gbmFtZSA6IHRyYW5zbGF0ZTtcbiAgICB9O1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLnJ1bihhdXRoZW50aWNhdGlvbkxpc3RlbmVyKTtcblxuICAvKipcbiAgICogTGlzdGVuIGFsbCBzdGF0ZSAocGFnZSkgY2hhbmdlcy4gRXZlcnkgdGltZSBhIHN0YXRlIGNoYW5nZSBuZWVkIHRvIHZlcmlmeSB0aGUgdXNlciBpcyBhdXRoZW50aWNhdGVkIG9yIG5vdCB0b1xuICAgKiByZWRpcmVjdCB0byBjb3JyZWN0IHBhZ2UuIFdoZW4gYSB1c2VyIGNsb3NlIHRoZSBicm93c2VyIHdpdGhvdXQgbG9nb3V0LCB3aGVuIGhpbSByZW9wZW4gdGhlIGJyb3dzZXIgdGhpcyBldmVudFxuICAgKiByZWF1dGhlbnRpY2F0ZSB0aGUgdXNlciB3aXRoIHRoZSBwZXJzaXN0ZW50IHRva2VuIG9mIHRoZSBsb2NhbCBzdG9yYWdlLlxuICAgKlxuICAgKiBXZSBkb24ndCBjaGVjayBpZiB0aGUgdG9rZW4gaXMgZXhwaXJlZCBvciBub3QgaW4gdGhlIHBhZ2UgY2hhbmdlLCBiZWNhdXNlIGlzIGdlbmVyYXRlIGFuIHVuZWNlc3Nhcnkgb3ZlcmhlYWQuXG4gICAqIElmIHRoZSB0b2tlbiBpcyBleHBpcmVkIHdoZW4gdGhlIHVzZXIgdHJ5IHRvIGNhbGwgdGhlIGZpcnN0IGFwaSB0byBnZXQgZGF0YSwgaGltIHdpbGwgYmUgbG9nb2ZmIGFuZCByZWRpcmVjdFxuICAgKiB0byBsb2dpbiBwYWdlLlxuICAgKlxuICAgKiBAcGFyYW0gJHJvb3RTY29wZVxuICAgKiBAcGFyYW0gJHN0YXRlXG4gICAqIEBwYXJhbSAkc3RhdGVQYXJhbXNcbiAgICogQHBhcmFtIEF1dGhcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gYXV0aGVudGljYXRpb25MaXN0ZW5lcigkcm9vdFNjb3BlLCAkc3RhdGUsIEdsb2JhbCwgQXV0aCwgUHJUb2FzdCwgLy8gTk9TT05BUlxuICAkdHJhbnNsYXRlKSB7XG5cbiAgICAvL29ubHkgd2hlbiBhcHBsaWNhdGlvbiBzdGFydCBjaGVjayBpZiB0aGUgZXhpc3RlbnQgdG9rZW4gc3RpbGwgdmFsaWRcbiAgICBBdXRoLnJlbW90ZVZhbGlkYXRlVG9rZW4oKS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgIC8vaWYgdGhlIHRva2VuIGlzIHZhbGlkIGNoZWNrIGlmIGV4aXN0cyB0aGUgdXNlciBiZWNhdXNlIHRoZSBicm93c2VyIGNvdWxkIGJlIGNsb3NlZFxuICAgICAgLy9hbmQgdGhlIHVzZXIgZGF0YSBpc24ndCBpbiBtZW1vcnlcbiAgICAgIGlmIChBdXRoLmN1cnJlbnRVc2VyID09PSBudWxsKSB7XG4gICAgICAgIEF1dGgudXBkYXRlQ3VycmVudFVzZXIoYW5ndWxhci5mcm9tSnNvbihsb2NhbFN0b3JhZ2UuZ2V0SXRlbSgndXNlcicpKSk7XG4gICAgICB9XG4gICAgfSk7XG5cbiAgICAvL0NoZWNrIGlmIHRoZSB0b2tlbiBzdGlsbCB2YWxpZC5cbiAgICAkcm9vdFNjb3BlLiRvbignJHN0YXRlQ2hhbmdlU3RhcnQnLCBmdW5jdGlvbiAoZXZlbnQsIHRvU3RhdGUpIHtcbiAgICAgIGlmICh0b1N0YXRlLmRhdGEubmVlZEF1dGhlbnRpY2F0aW9uIHx8IHRvU3RhdGUuZGF0YS5uZWVkUHJvZmlsZSkge1xuICAgICAgICAvL2RvbnQgdHJhaXQgdGhlIHN1Y2Nlc3MgYmxvY2sgYmVjYXVzZSBhbHJlYWR5IGRpZCBieSB0b2tlbiBpbnRlcmNlcHRvclxuICAgICAgICBBdXRoLnJlbW90ZVZhbGlkYXRlVG9rZW4oKS5jYXRjaChmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgUHJUb2FzdC53YXJuKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMubG9naW4ubG9nb3V0SW5hY3RpdmUnKSk7XG5cbiAgICAgICAgICBpZiAodG9TdGF0ZS5uYW1lICE9PSBHbG9iYWwubG9naW5TdGF0ZSkge1xuICAgICAgICAgICAgJHN0YXRlLmdvKEdsb2JhbC5sb2dpblN0YXRlKTtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICBldmVudC5wcmV2ZW50RGVmYXVsdCgpO1xuICAgICAgICB9KTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIC8vaWYgdGhlIHVzZSBpcyBhdXRoZW50aWNhdGVkIGFuZCBuZWVkIHRvIGVudGVyIGluIGxvZ2luIHBhZ2VcbiAgICAgICAgLy9oaW0gd2lsbCBiZSByZWRpcmVjdGVkIHRvIGhvbWUgcGFnZVxuICAgICAgICBpZiAodG9TdGF0ZS5uYW1lID09PSBHbG9iYWwubG9naW5TdGF0ZSAmJiBBdXRoLmF1dGhlbnRpY2F0ZWQoKSkge1xuICAgICAgICAgICRzdGF0ZS5nbyhHbG9iYWwuaG9tZVN0YXRlKTtcbiAgICAgICAgICBldmVudC5wcmV2ZW50RGVmYXVsdCgpO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykucnVuKGF1dGhvcml6YXRpb25MaXN0ZW5lcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiBhdXRob3JpemF0aW9uTGlzdGVuZXIoJHJvb3RTY29wZSwgJHN0YXRlLCBHbG9iYWwsIEF1dGgpIHtcbiAgICAvKipcbiAgICAgKiBBIGNhZGEgbXVkYW7Dp2EgZGUgZXN0YWRvIChcInDDoWdpbmFcIikgdmVyaWZpY2Egc2UgbyB1c3XDoXJpbyB0ZW0gbyBwZXJmaWxcbiAgICAgKiBuZWNlc3PDoXJpbyBwYXJhIG8gYWNlc3NvIGEgbWVzbWFcbiAgICAgKi9cbiAgICAkcm9vdFNjb3BlLiRvbignJHN0YXRlQ2hhbmdlU3RhcnQnLCBmdW5jdGlvbiAoZXZlbnQsIHRvU3RhdGUpIHtcbiAgICAgIGlmICh0b1N0YXRlLmRhdGEgJiYgdG9TdGF0ZS5kYXRhLm5lZWRBdXRoZW50aWNhdGlvbiAmJiB0b1N0YXRlLmRhdGEubmVlZFByb2ZpbGUgJiYgQXV0aC5hdXRoZW50aWNhdGVkKCkgJiYgIUF1dGguY3VycmVudFVzZXIuaGFzUHJvZmlsZSh0b1N0YXRlLmRhdGEubmVlZFByb2ZpbGUsIHRvU3RhdGUuZGF0YS5hbGxQcm9maWxlcykpIHtcblxuICAgICAgICAkc3RhdGUuZ28oR2xvYmFsLm5vdEF1dGhvcml6ZWRTdGF0ZSk7XG4gICAgICAgIGV2ZW50LnByZXZlbnREZWZhdWx0KCk7XG4gICAgICB9XG4gICAgfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29uZmlnKHNwaW5uZXJJbnRlcmNlcHRvcik7XG5cbiAgZnVuY3Rpb24gc3Bpbm5lckludGVyY2VwdG9yKCRodHRwUHJvdmlkZXIsICRwcm92aWRlKSB7XG4gICAgLyoqXG4gICAgICogRXN0ZSBpbnRlcmNlcHRvciDDqSByZXNwb25zw6F2ZWwgcG9yIG1vc3RyYXIgZSBlc2NvbmRlciBvXG4gICAgICogY29tcG9uZW50ZSBQclNwaW5uZXIgc2VtcHJlIHF1ZSB1bWEgcmVxdWlzacOnw6NvIGFqYXhcbiAgICAgKiBpbmljaWFyIGUgZmluYWxpemFyLlxuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9ICRxXG4gICAgICogQHBhcmFtIHthbnl9ICRpbmplY3RvclxuICAgICAqIEByZXR1cm5zXG4gICAgICovXG4gICAgZnVuY3Rpb24gc2hvd0hpZGVTcGlubmVyKCRxLCAkaW5qZWN0b3IpIHtcbiAgICAgIHJldHVybiB7XG4gICAgICAgIHJlcXVlc3Q6IGZ1bmN0aW9uIHJlcXVlc3QoY29uZmlnKSB7XG4gICAgICAgICAgJGluamVjdG9yLmdldCgnUHJTcGlubmVyJykuc2hvdygpO1xuXG4gICAgICAgICAgcmV0dXJuIGNvbmZpZztcbiAgICAgICAgfSxcblxuICAgICAgICByZXNwb25zZTogZnVuY3Rpb24gcmVzcG9uc2UoX3Jlc3BvbnNlKSB7XG4gICAgICAgICAgJGluamVjdG9yLmdldCgnUHJTcGlubmVyJykuaGlkZSgpO1xuXG4gICAgICAgICAgcmV0dXJuIF9yZXNwb25zZTtcbiAgICAgICAgfSxcblxuICAgICAgICByZXNwb25zZUVycm9yOiBmdW5jdGlvbiByZXNwb25zZUVycm9yKHJlamVjdGlvbikge1xuICAgICAgICAgICRpbmplY3Rvci5nZXQoJ1ByU3Bpbm5lcicpLmhpZGUoKTtcblxuICAgICAgICAgIHJldHVybiAkcS5yZWplY3QocmVqZWN0aW9uKTtcbiAgICAgICAgfVxuICAgICAgfTtcbiAgICB9XG5cbiAgICAvLyBEZWZpbmUgdW1hIGZhY3RvcnkgcGFyYSBvICRodHRwSW50ZXJjZXB0b3JcbiAgICAkcHJvdmlkZS5mYWN0b3J5KCdzaG93SGlkZVNwaW5uZXInLCBzaG93SGlkZVNwaW5uZXIpO1xuXG4gICAgLy8gQWRpY2lvbmEgYSBmYWN0b3J5IG5vIGFycmF5IGRlIGludGVyY2VwdG9ycyBkbyAkaHR0cFxuICAgICRodHRwUHJvdmlkZXIuaW50ZXJjZXB0b3JzLnB1c2goJ3Nob3dIaWRlU3Bpbm5lcicpO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4vKmVzbGludCBhbmd1bGFyL21vZHVsZS1nZXR0ZXI6IDAqL1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbmZpZyh0b2tlbkludGVyY2VwdG9yKTtcblxuICAvKipcbiAgICogSW50ZXJjZXB0IGFsbCByZXNwb25zZSAoc3VjY2VzcyBvciBlcnJvcikgdG8gdmVyaWZ5IHRoZSByZXR1cm5lZCB0b2tlblxuICAgKlxuICAgKiBAcGFyYW0gJGh0dHBQcm92aWRlclxuICAgKiBAcGFyYW0gJHByb3ZpZGVcbiAgICogQHBhcmFtIEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiB0b2tlbkludGVyY2VwdG9yKCRodHRwUHJvdmlkZXIsICRwcm92aWRlLCBHbG9iYWwpIHtcblxuICAgIGZ1bmN0aW9uIHJlZGlyZWN0V2hlblNlcnZlckxvZ2dlZE91dCgkcSwgJGluamVjdG9yKSB7XG4gICAgICByZXR1cm4ge1xuICAgICAgICByZXF1ZXN0OiBmdW5jdGlvbiByZXF1ZXN0KGNvbmZpZykge1xuICAgICAgICAgIHZhciB0b2tlbiA9ICRpbmplY3Rvci5nZXQoJ0F1dGgnKS5nZXRUb2tlbigpO1xuXG4gICAgICAgICAgaWYgKHRva2VuKSB7XG4gICAgICAgICAgICBjb25maWcuaGVhZGVyc1snQXV0aG9yaXphdGlvbiddID0gJ0JlYXJlciAnICsgdG9rZW47XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgcmV0dXJuIGNvbmZpZztcbiAgICAgICAgfSxcbiAgICAgICAgcmVzcG9uc2U6IGZ1bmN0aW9uIHJlc3BvbnNlKF9yZXNwb25zZSkge1xuICAgICAgICAgIC8vIGdldCBhIG5ldyByZWZyZXNoIHRva2VuIHRvIHVzZSBpbiB0aGUgbmV4dCByZXF1ZXN0XG4gICAgICAgICAgdmFyIHRva2VuID0gX3Jlc3BvbnNlLmhlYWRlcnMoJ0F1dGhvcml6YXRpb24nKTtcblxuICAgICAgICAgIGlmICh0b2tlbikge1xuICAgICAgICAgICAgJGluamVjdG9yLmdldCgnQXV0aCcpLnNldFRva2VuKHRva2VuLnNwbGl0KCcgJylbMV0pO1xuICAgICAgICAgIH1cbiAgICAgICAgICByZXR1cm4gX3Jlc3BvbnNlO1xuICAgICAgICB9LFxuICAgICAgICByZXNwb25zZUVycm9yOiBmdW5jdGlvbiByZXNwb25zZUVycm9yKHJlamVjdGlvbikge1xuICAgICAgICAgIC8vIEluc3RlYWQgb2YgY2hlY2tpbmcgZm9yIGEgc3RhdHVzIGNvZGUgb2YgNDAwIHdoaWNoIG1pZ2h0IGJlIHVzZWRcbiAgICAgICAgICAvLyBmb3Igb3RoZXIgcmVhc29ucyBpbiBMYXJhdmVsLCB3ZSBjaGVjayBmb3IgdGhlIHNwZWNpZmljIHJlamVjdGlvblxuICAgICAgICAgIC8vIHJlYXNvbnMgdG8gdGVsbCB1cyBpZiB3ZSBuZWVkIHRvIHJlZGlyZWN0IHRvIHRoZSBsb2dpbiBzdGF0ZVxuICAgICAgICAgIHZhciByZWplY3Rpb25SZWFzb25zID0gWyd0b2tlbl9ub3RfcHJvdmlkZWQnLCAndG9rZW5fZXhwaXJlZCcsICd0b2tlbl9hYnNlbnQnLCAndG9rZW5faW52YWxpZCddO1xuXG4gICAgICAgICAgdmFyIHRva2VuRXJyb3IgPSBmYWxzZTtcblxuICAgICAgICAgIGFuZ3VsYXIuZm9yRWFjaChyZWplY3Rpb25SZWFzb25zLCBmdW5jdGlvbiAodmFsdWUpIHtcbiAgICAgICAgICAgIGlmIChyZWplY3Rpb24uZGF0YSAmJiByZWplY3Rpb24uZGF0YS5lcnJvciA9PT0gdmFsdWUpIHtcbiAgICAgICAgICAgICAgdG9rZW5FcnJvciA9IHRydWU7XG5cbiAgICAgICAgICAgICAgJGluamVjdG9yLmdldCgnQXV0aCcpLmxvZ291dCgpLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgIHZhciAkc3RhdGUgPSAkaW5qZWN0b3IuZ2V0KCckc3RhdGUnKTtcblxuICAgICAgICAgICAgICAgIC8vIGluIGNhc2UgbXVsdGlwbGUgYWpheCByZXF1ZXN0IGZhaWwgYXQgc2FtZSB0aW1lIGJlY2F1c2UgdG9rZW4gcHJvYmxlbXMsXG4gICAgICAgICAgICAgICAgLy8gb25seSB0aGUgZmlyc3Qgd2lsbCByZWRpcmVjdFxuICAgICAgICAgICAgICAgIGlmICghJHN0YXRlLmlzKEdsb2JhbC5sb2dpblN0YXRlKSkge1xuICAgICAgICAgICAgICAgICAgJHN0YXRlLmdvKEdsb2JhbC5sb2dpblN0YXRlKTtcblxuICAgICAgICAgICAgICAgICAgLy9jbG9zZSBhbnkgZGlhbG9nIHRoYXQgaXMgb3BlbmVkXG4gICAgICAgICAgICAgICAgICAkaW5qZWN0b3IuZ2V0KCdQckRpYWxvZycpLmNsb3NlKCk7XG5cbiAgICAgICAgICAgICAgICAgIGV2ZW50LnByZXZlbnREZWZhdWx0KCk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9KTtcblxuICAgICAgICAgIC8vZGVmaW5lIGRhdGEgdG8gZW1wdHkgYmVjYXVzZSBhbHJlYWR5IHNob3cgUHJUb2FzdCB0b2tlbiBtZXNzYWdlXG4gICAgICAgICAgaWYgKHRva2VuRXJyb3IpIHtcbiAgICAgICAgICAgIHJlamVjdGlvbi5kYXRhID0ge307XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbihyZWplY3Rpb24uaGVhZGVycykpIHtcbiAgICAgICAgICAgIC8vIG1hbnkgc2VydmVycyBlcnJvcnMgKGJ1c2luZXNzKSBhcmUgaW50ZXJjZXB0IGhlcmUgYnV0IGdlbmVyYXRlZCBhIG5ldyByZWZyZXNoIHRva2VuXG4gICAgICAgICAgICAvLyBhbmQgbmVlZCB1cGRhdGUgY3VycmVudCB0b2tlblxuICAgICAgICAgICAgdmFyIHRva2VuID0gcmVqZWN0aW9uLmhlYWRlcnMoJ0F1dGhvcml6YXRpb24nKTtcblxuICAgICAgICAgICAgaWYgKHRva2VuKSB7XG4gICAgICAgICAgICAgICRpbmplY3Rvci5nZXQoJ0F1dGgnKS5zZXRUb2tlbih0b2tlbi5zcGxpdCgnICcpWzFdKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9XG5cbiAgICAgICAgICByZXR1cm4gJHEucmVqZWN0KHJlamVjdGlvbik7XG4gICAgICAgIH1cbiAgICAgIH07XG4gICAgfVxuXG4gICAgLy8gU2V0dXAgZm9yIHRoZSAkaHR0cEludGVyY2VwdG9yXG4gICAgJHByb3ZpZGUuZmFjdG9yeSgncmVkaXJlY3RXaGVuU2VydmVyTG9nZ2VkT3V0JywgcmVkaXJlY3RXaGVuU2VydmVyTG9nZ2VkT3V0KTtcblxuICAgIC8vIFB1c2ggdGhlIG5ldyBmYWN0b3J5IG9udG8gdGhlICRodHRwIGludGVyY2VwdG9yIGFycmF5XG4gICAgJGh0dHBQcm92aWRlci5pbnRlcmNlcHRvcnMucHVzaCgncmVkaXJlY3RXaGVuU2VydmVyTG9nZ2VkT3V0Jyk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29uZmlnKHZhbGlkYXRpb25JbnRlcmNlcHRvcik7XG5cbiAgZnVuY3Rpb24gdmFsaWRhdGlvbkludGVyY2VwdG9yKCRodHRwUHJvdmlkZXIsICRwcm92aWRlKSB7XG4gICAgLyoqXG4gICAgICogRXN0ZSBpbnRlcmNlcHRvciDDqSByZXNwb25zw6F2ZWwgcG9yIG1vc3RyYXIgYXNcbiAgICAgKiBtZW5zYWdlbnMgZGUgZXJybyByZWZlcmVudGUgYXMgdmFsaWRhw6fDtWVzIGRvIGJhY2stZW5kXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gJHFcbiAgICAgKiBAcGFyYW0ge2FueX0gJGluamVjdG9yXG4gICAgICogQHJldHVybnNcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBzaG93RXJyb3JWYWxpZGF0aW9uKCRxLCAkaW5qZWN0b3IpIHtcbiAgICAgIHJldHVybiB7XG4gICAgICAgIHJlc3BvbnNlRXJyb3I6IGZ1bmN0aW9uIHJlc3BvbnNlRXJyb3IocmVqZWN0aW9uKSB7XG4gICAgICAgICAgdmFyIFByVG9hc3QgPSAkaW5qZWN0b3IuZ2V0KCdQclRvYXN0Jyk7XG4gICAgICAgICAgdmFyICR0cmFuc2xhdGUgPSAkaW5qZWN0b3IuZ2V0KCckdHJhbnNsYXRlJyk7XG5cbiAgICAgICAgICBpZiAocmVqZWN0aW9uLmNvbmZpZy5kYXRhICYmICFyZWplY3Rpb24uY29uZmlnLmRhdGEuc2tpcFZhbGlkYXRpb24pIHtcbiAgICAgICAgICAgIGlmIChyZWplY3Rpb24uZGF0YSAmJiByZWplY3Rpb24uZGF0YS5lcnJvcikge1xuXG4gICAgICAgICAgICAgIC8vdmVyaWZpY2Egc2Ugb2NvcnJldSBhbGd1bSBlcnJvIHJlZmVyZW50ZSBhbyB0b2tlblxuICAgICAgICAgICAgICBpZiAocmVqZWN0aW9uLmRhdGEuZXJyb3Iuc3RhcnRzV2l0aCgndG9rZW5fJykpIHtcbiAgICAgICAgICAgICAgICBQclRvYXN0Lndhcm4oJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5sb2dpbi5sb2dvdXRJbmFjdGl2ZScpKTtcbiAgICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICBQclRvYXN0LmVycm9yKCR0cmFuc2xhdGUuaW5zdGFudChyZWplY3Rpb24uZGF0YS5lcnJvcikpO1xuICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICBQclRvYXN0LmVycm9yVmFsaWRhdGlvbihyZWplY3Rpb24uZGF0YSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgcmV0dXJuICRxLnJlamVjdChyZWplY3Rpb24pO1xuICAgICAgICB9XG4gICAgICB9O1xuICAgIH1cblxuICAgIC8vIERlZmluZSB1bWEgZmFjdG9yeSBwYXJhIG8gJGh0dHBJbnRlcmNlcHRvclxuICAgICRwcm92aWRlLmZhY3RvcnkoJ3Nob3dFcnJvclZhbGlkYXRpb24nLCBzaG93RXJyb3JWYWxpZGF0aW9uKTtcblxuICAgIC8vIEFkaWNpb25hIGEgZmFjdG9yeSBubyBhcnJheSBkZSBpbnRlcmNlcHRvcnMgZG8gJGh0dHBcbiAgICAkaHR0cFByb3ZpZGVyLmludGVyY2VwdG9ycy5wdXNoKCdzaG93RXJyb3JWYWxpZGF0aW9uJyk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbi8qZXNsaW50LWVudiBlczYqL1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29udHJvbGxlcignTWVudUNvbnRyb2xsZXInLCBNZW51Q29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiBNZW51Q29udHJvbGxlcigkbWRTaWRlbmF2LCAkc3RhdGUsICRtZENvbG9ycykge1xuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICAvL0Jsb2NvIGRlIGRlY2xhcmFjb2VzIGRlIGZ1bmNvZXNcbiAgICB2bS5vcGVuID0gb3BlbjtcbiAgICB2bS5vcGVuTWVudU9yUmVkaXJlY3RUb1N0YXRlID0gb3Blbk1lbnVPclJlZGlyZWN0VG9TdGF0ZTtcblxuICAgIGFjdGl2YXRlKCk7XG5cbiAgICBmdW5jdGlvbiBhY3RpdmF0ZSgpIHtcbiAgICAgIHZhciBtZW51UHJlZml4ID0gJ3ZpZXdzLmxheW91dC5tZW51Lic7XG5cbiAgICAgIC8vIEFycmF5IGNvbnRlbmRvIG9zIGl0ZW5zIHF1ZSBzw6NvIG1vc3RyYWRvcyBubyBtZW51IGxhdGVyYWxcbiAgICAgIHZtLml0ZW5zTWVudSA9IFt7IHN0YXRlOiAnYXBwLmRhc2hib2FyZCcsIHRpdGxlOiBtZW51UHJlZml4ICsgJ2Rhc2hib2FyZCcsIGljb246ICdkYXNoYm9hcmQnLCBzdWJJdGVuczogW10gfSxcbiAgICAgIC8vIENvbG9xdWUgc2V1cyBpdGVucyBkZSBtZW51IGEgcGFydGlyIGRlc3RlIHBvbnRvXG4gICAgICB7XG4gICAgICAgIHN0YXRlOiAnIycsIHRpdGxlOiBtZW51UHJlZml4ICsgJ2FkbWluJywgaWNvbjogJ3NldHRpbmdzX2FwcGxpY2F0aW9ucycsIHByb2ZpbGVzOiBbJ2FkbWluJ10sXG4gICAgICAgIHN1Ykl0ZW5zOiBbeyBzdGF0ZTogJ2FwcC51c2VyJywgdGl0bGU6IG1lbnVQcmVmaXggKyAndXNlcicsIGljb246ICdwZW9wbGUnIH0sIHsgc3RhdGU6ICdhcHAubWFpbCcsIHRpdGxlOiBtZW51UHJlZml4ICsgJ21haWwnLCBpY29uOiAnbWFpbCcgfSwgeyBzdGF0ZTogJ2FwcC5hdWRpdCcsIHRpdGxlOiBtZW51UHJlZml4ICsgJ2F1ZGl0JywgaWNvbjogJ3N0b3JhZ2UnIH0sIHsgc3RhdGU6ICdhcHAuZGluYW1pYy1xdWVyeScsIHRpdGxlOiBtZW51UHJlZml4ICsgJ2RpbmFtaWNRdWVyeScsIGljb246ICdsb2NhdGlvbl9zZWFyY2hpbmcnIH1dXG4gICAgICB9XTtcblxuICAgICAgLyoqXG4gICAgICAgKiBPYmpldG8gcXVlIHByZWVuY2hlIG8gbmctc3R5bGUgZG8gbWVudSBsYXRlcmFsIHRyb2NhbmRvIGFzIGNvcmVzXG4gICAgICAgKi9cbiAgICAgIHZtLnNpZGVuYXZTdHlsZSA9IHtcbiAgICAgICAgdG9wOiB7XG4gICAgICAgICAgJ2JvcmRlci1ib3R0b20nOiAnMXB4IHNvbGlkICcgKyBnZXRDb2xvcigncHJpbWFyeScpLFxuICAgICAgICAgICdiYWNrZ3JvdW5kLWltYWdlJzogJy13ZWJraXQtbGluZWFyLWdyYWRpZW50KHRvcCwgJyArIGdldENvbG9yKCdwcmltYXJ5LTUwMCcpICsgJywgJyArIGdldENvbG9yKCdwcmltYXJ5LTgwMCcpICsgJyknXG4gICAgICAgIH0sXG4gICAgICAgIGNvbnRlbnQ6IHtcbiAgICAgICAgICAnYmFja2dyb3VuZC1jb2xvcic6IGdldENvbG9yKCdwcmltYXJ5LTgwMCcpXG4gICAgICAgIH0sXG4gICAgICAgIHRleHRDb2xvcjoge1xuICAgICAgICAgIGNvbG9yOiAnI0ZGRidcbiAgICAgICAgfSxcbiAgICAgICAgbGluZUJvdHRvbToge1xuICAgICAgICAgICdib3JkZXItYm90dG9tJzogJzFweCBzb2xpZCAnICsgZ2V0Q29sb3IoJ3ByaW1hcnktNDAwJylcbiAgICAgICAgfVxuICAgICAgfTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBvcGVuKCkge1xuICAgICAgJG1kU2lkZW5hdignbGVmdCcpLnRvZ2dsZSgpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIE3DqXRvZG8gcXVlIGV4aWJlIG8gc3ViIG1lbnUgZG9zIGl0ZW5zIGRvIG1lbnUgbGF0ZXJhbCBjYXNvIHRlbmhhIHN1YiBpdGVuc1xuICAgICAqIGNhc28gY29udHLDoXJpbyByZWRpcmVjaW9uYSBwYXJhIG8gc3RhdGUgcGFzc2FkbyBjb21vIHBhcsOibWV0cm9cbiAgICAgKi9cbiAgICBmdW5jdGlvbiBvcGVuTWVudU9yUmVkaXJlY3RUb1N0YXRlKCRtZE1lbnUsIGV2LCBpdGVtKSB7XG4gICAgICBpZiAoYW5ndWxhci5pc0RlZmluZWQoaXRlbS5zdWJJdGVucykgJiYgaXRlbS5zdWJJdGVucy5sZW5ndGggPiAwKSB7XG4gICAgICAgICRtZE1lbnUub3Blbihldik7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICAkc3RhdGUuZ28oaXRlbS5zdGF0ZSk7XG4gICAgICAgICRtZFNpZGVuYXYoJ2xlZnQnKS5jbG9zZSgpO1xuICAgICAgfVxuICAgIH1cblxuICAgIGZ1bmN0aW9uIGdldENvbG9yKGNvbG9yUGFsZXR0ZXMpIHtcbiAgICAgIHJldHVybiAkbWRDb2xvcnMuZ2V0VGhlbWVDb2xvcihjb2xvclBhbGV0dGVzKTtcbiAgICB9XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb250cm9sbGVyKCdNYWlsc0NvbnRyb2xsZXInLCBNYWlsc0NvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gTWFpbHNDb250cm9sbGVyKE1haWxzU2VydmljZSwgVXNlcnNTZXJ2aWNlLCBQckRpYWxvZywgUHJUb2FzdCwgLy8gTk9TT05BUlxuICAkcSwgbG9kYXNoLCAkdHJhbnNsYXRlLCBHbG9iYWwpIHtcblxuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICB2bS5maWx0ZXJTZWxlY3RlZCA9IGZhbHNlO1xuICAgIHZtLm9wdGlvbnMgPSB7XG4gICAgICBza2luOiAna2FtYScsXG4gICAgICBsYW5ndWFnZTogJ3B0LWJyJyxcbiAgICAgIGFsbG93ZWRDb250ZW50OiB0cnVlLFxuICAgICAgZW50aXRpZXM6IHRydWUsXG4gICAgICBoZWlnaHQ6IDMwMCxcbiAgICAgIGV4dHJhUGx1Z2luczogJ2RpYWxvZyxmaW5kLGNvbG9yZGlhbG9nLHByZXZpZXcsZm9ybXMsaWZyYW1lLGZsYXNoJ1xuICAgIH07XG5cbiAgICB2bS5sb2FkVXNlcnMgPSBsb2FkVXNlcnM7XG4gICAgdm0ub3BlblVzZXJEaWFsb2cgPSBvcGVuVXNlckRpYWxvZztcbiAgICB2bS5hZGRVc2VyTWFpbCA9IGFkZFVzZXJNYWlsO1xuICAgIHZtLmNsZWFuRm9ybSA9IGNsZWFuRm9ybTtcbiAgICB2bS5zZW5kID0gc2VuZDtcblxuICAgIGFjdGl2YXRlKCk7XG5cbiAgICBmdW5jdGlvbiBhY3RpdmF0ZSgpIHtcbiAgICAgIHZtLmNsZWFuRm9ybSgpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWxpemEgYSBidXNjYSBwZWxvIHVzdcOhcmlvIHJlbW90YW1lbnRlXG4gICAgICpcbiAgICAgKiBAcGFyYW1zIHtzdHJpbmd9IC0gUmVjZWJlIG8gdmFsb3IgcGFyYSBzZXIgcGVzcXVpc2Fkb1xuICAgICAqIEByZXR1cm4ge3Byb21pc3NlfSAtIFJldG9ybmEgdW1hIHByb21pc3NlIHF1ZSBvIGNvbXBvbmV0ZSByZXNvbHZlXG4gICAgICovXG4gICAgZnVuY3Rpb24gbG9hZFVzZXJzKGNyaXRlcmlhKSB7XG4gICAgICB2YXIgZGVmZXJyZWQgPSAkcS5kZWZlcigpO1xuXG4gICAgICBVc2Vyc1NlcnZpY2UucXVlcnkoe1xuICAgICAgICBuYW1lT3JFbWFpbDogY3JpdGVyaWEsXG4gICAgICAgIG5vdFVzZXJzOiBsb2Rhc2gubWFwKHZtLm1haWwudXNlcnMsIGxvZGFzaC5wcm9wZXJ0eSgnaWQnKSkudG9TdHJpbmcoKSxcbiAgICAgICAgbGltaXQ6IDVcbiAgICAgIH0pLnRoZW4oZnVuY3Rpb24gKGRhdGEpIHtcblxuICAgICAgICAvLyB2ZXJpZmljYSBzZSBuYSBsaXN0YSBkZSB1c3VhcmlvcyBqw6EgZXhpc3RlIG8gdXN1w6FyaW8gY29tIG8gZW1haWwgcGVzcXVpc2Fkb1xuICAgICAgICBkYXRhID0gbG9kYXNoLmZpbHRlcihkYXRhLCBmdW5jdGlvbiAodXNlcikge1xuICAgICAgICAgIHJldHVybiAhbG9kYXNoLmZpbmQodm0ubWFpbC51c2VycywgeyBlbWFpbDogdXNlci5lbWFpbCB9KTtcbiAgICAgICAgfSk7XG5cbiAgICAgICAgZGVmZXJyZWQucmVzb2x2ZShkYXRhKTtcbiAgICAgIH0pO1xuXG4gICAgICByZXR1cm4gZGVmZXJyZWQucHJvbWlzZTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBBYnJlIG8gZGlhbG9nIHBhcmEgcGVzcXVpc2EgZGUgdXN1w6FyaW9zXG4gICAgICovXG4gICAgZnVuY3Rpb24gb3BlblVzZXJEaWFsb2coKSB7XG4gICAgICB2YXIgY29uZmlnID0ge1xuICAgICAgICBsb2NhbHM6IHtcbiAgICAgICAgICBvbkluaXQ6IHRydWUsXG4gICAgICAgICAgdXNlckRpYWxvZ0lucHV0OiB7XG4gICAgICAgICAgICB0cmFuc2ZlclVzZXJGbjogdm0uYWRkVXNlck1haWxcbiAgICAgICAgICB9XG4gICAgICAgIH0sXG4gICAgICAgIGNvbnRyb2xsZXI6ICdVc2Vyc0RpYWxvZ0NvbnRyb2xsZXInLFxuICAgICAgICBjb250cm9sbGVyQXM6ICdjdHJsJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy91c2Vycy9kaWFsb2cvdXNlcnMtZGlhbG9nLmh0bWwnLFxuICAgICAgICBoYXNCYWNrZHJvcDogdHJ1ZVxuICAgICAgfTtcblxuICAgICAgUHJEaWFsb2cuY3VzdG9tKGNvbmZpZyk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQWRpY2lvbmEgbyB1c3XDoXJpbyBzZWxlY2lvbmFkbyBuYSBsaXN0YSBwYXJhIHF1ZSBzZWphIGVudmlhZG8gbyBlbWFpbFxuICAgICAqL1xuICAgIGZ1bmN0aW9uIGFkZFVzZXJNYWlsKHVzZXIpIHtcbiAgICAgIHZhciB1c2VycyA9IGxvZGFzaC5maW5kKHZtLm1haWwudXNlcnMsIHsgZW1haWw6IHVzZXIuZW1haWwgfSk7XG5cbiAgICAgIGlmICh2bS5tYWlsLnVzZXJzLmxlbmd0aCA+IDAgJiYgYW5ndWxhci5pc0RlZmluZWQodXNlcnMpKSB7XG4gICAgICAgIFByVG9hc3Qud2FybigkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnVzZXIudXNlckV4aXN0cycpKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHZtLm1haWwudXNlcnMucHVzaCh7IG5hbWU6IHVzZXIubmFtZSwgZW1haWw6IHVzZXIuZW1haWwgfSk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhbGl6YSBvIGVudmlvIGRvIGVtYWlsIHBhcmEgYSBsaXN0YSBkZSB1c3XDoXJpb3Mgc2VsZWNpb25hZG9zXG4gICAgICovXG4gICAgZnVuY3Rpb24gc2VuZCgpIHtcblxuICAgICAgdm0ubWFpbC4kc2F2ZSgpLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgIGlmIChyZXNwb25zZS5sZW5ndGggPiAwKSB7XG4gICAgICAgICAgdmFyIG1zZyA9ICR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMubWFpbC5tYWlsRXJyb3JzJyk7XG5cbiAgICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IHJlc3BvbnNlLmxlbmd0aDsgaSsrKSB7XG4gICAgICAgICAgICBtc2cgKz0gcmVzcG9uc2UgKyAnXFxuJztcbiAgICAgICAgICB9XG4gICAgICAgICAgUHJUb2FzdC5lcnJvcihtc2cpO1xuICAgICAgICAgIHZtLmNsZWFuRm9ybSgpO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIFByVG9hc3Quc3VjY2VzcygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLm1haWwuc2VuZE1haWxTdWNjZXNzJykpO1xuICAgICAgICAgIHZtLmNsZWFuRm9ybSgpO1xuICAgICAgICB9XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBMaW1wYSBvIGZvcm11bMOhcmlvIGRlIGVtYWlsXG4gICAgICovXG4gICAgZnVuY3Rpb24gY2xlYW5Gb3JtKCkge1xuICAgICAgdm0ubWFpbCA9IG5ldyBNYWlsc1NlcnZpY2UoKTtcbiAgICAgIHZtLm1haWwudXNlcnMgPSBbXTtcbiAgICB9XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqXG4gICAqIEFycXVpdm8gZGUgY29uZmlndXJhw6fDo28gY29tIGFzIHJvdGFzIGVzcGVjw61maWNhcyBkbyByZWN1cnNvIGVtIHF1ZXN0w6NvXG4gICAqXG4gICAqIEBwYXJhbSB7YW55fSAkc3RhdGVQcm92aWRlclxuICAgKiBAcGFyYW0ge2FueX0gR2xvYmFsXG4gICAqL1xuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvdXRlcygkc3RhdGVQcm92aWRlciwgR2xvYmFsKSB7XG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ2FwcC5tYWlsJywge1xuICAgICAgdXJsOiAnL2VtYWlsJyxcbiAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvbWFpbC9tYWlscy1zZW5kLmh0bWwnLFxuICAgICAgY29udHJvbGxlcjogJ01haWxzQ29udHJvbGxlciBhcyBtYWlsc0N0cmwnLFxuICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IHRydWUsIG5lZWRQcm9maWxlOiBbJ2FkbWluJ10gfVxuICAgIH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZhY3RvcnkoJ01haWxzU2VydmljZScsIE1haWxzU2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBNYWlsc1NlcnZpY2Uoc2VydmljZUZhY3RvcnkpIHtcbiAgICByZXR1cm4gc2VydmljZUZhY3RvcnkoJ21haWxzJywge30pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29udHJvbGxlcignUHJvamVjdHNDb250cm9sbGVyJywgUHJvamVjdHNDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIFByb2plY3RzQ29udHJvbGxlcihHbG9iYWwsICRjb250cm9sbGVyLCBQcm9qZWN0c1NlcnZpY2UsIEF1dGgsIFJvbGVzU2VydmljZSkge1xuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICAvL0F0dHJpYnV0ZXMgQmxvY2tcblxuICAgIC8vRnVuY3Rpb25zIEJsb2NrXG4gICAgdm0ub25BY3RpdmF0ZSA9IG9uQWN0aXZhdGU7XG4gICAgdm0uYXBwbHlGaWx0ZXJzID0gYXBwbHlGaWx0ZXJzO1xuICAgIHZtLmJlZm9yZVNhdmUgPSBiZWZvcmVTYXZlO1xuICAgIHZtLmFmdGVyU2VhcmNoID0gYWZ0ZXJTZWFyY2g7XG5cbiAgICB2bS5yb2xlcyA9IHt9O1xuXG4gICAgLy8gaW5zdGFudGlhdGUgYmFzZSBjb250cm9sbGVyXG4gICAgJGNvbnRyb2xsZXIoJ0NSVURDb250cm9sbGVyJywgeyB2bTogdm0sIG1vZGVsU2VydmljZTogUHJvamVjdHNTZXJ2aWNlLCBvcHRpb25zOiB7fSB9KTtcblxuICAgIGZ1bmN0aW9uIG9uQWN0aXZhdGUoKSB7XG4gICAgICBSb2xlc1NlcnZpY2UucXVlcnkoKS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICB2bS5yb2xlcyA9IHJlc3BvbnNlO1xuICAgICAgfSk7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMgPSB7fTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBhZnRlclNlYXJjaCgpIHtcbiAgICAgIGNvbnNvbGUubG9nKHZtLnJlc291cmNlcyk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gYXBwbHlGaWx0ZXJzKGRlZmF1bHRRdWVyeUZpbHRlcnMpIHtcbiAgICAgIHJldHVybiBhbmd1bGFyLmV4dGVuZChkZWZhdWx0UXVlcnlGaWx0ZXJzLCB2bS5xdWVyeWx0ZXJzKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBiZWZvcmVTYXZlKCkge1xuICAgICAgdm0ucmVzb3VyY2Uub3duZXIgPSBBdXRoLmN1cnJlbnRVc2VyLmlkO1xuICAgICAgdm0ucmVzb3VyY2UudXNlcl9pZCA9IEF1dGguY3VycmVudFVzZXIuaWQ7XG4gICAgfVxuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKlxuICAgKiBBcnF1aXZvIGRlIGNvbmZpZ3VyYcOnw6NvIGNvbSBhcyByb3RhcyBlc3BlY8OtZmljYXMgZG8gcmVjdXJzbyBwcm9qZWN0XG4gICAqXG4gICAqIEBwYXJhbSB7YW55fSAkc3RhdGVQcm92aWRlclxuICAgKiBAcGFyYW0ge2FueX0gR2xvYmFsXG4gICAqL1xuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvdXRlcygkc3RhdGVQcm92aWRlciwgR2xvYmFsKSB7XG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ2FwcC5wcm9qZWN0cycsIHtcbiAgICAgIHVybDogJy9wcm9qZWN0cycsXG4gICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL3Byb2plY3RzL3Byb2plY3RzLmh0bWwnLFxuICAgICAgY29udHJvbGxlcjogJ1Byb2plY3RzQ29udHJvbGxlciBhcyBwcm9qZWN0c0N0cmwnLFxuICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IHRydWUgfVxuICAgIH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZhY3RvcnkoJ1Byb2plY3RzU2VydmljZScsIFByb2plY3RzU2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiBQcm9qZWN0c1NlcnZpY2Uoc2VydmljZUZhY3RvcnkpIHtcbiAgICByZXR1cm4gc2VydmljZUZhY3RvcnkoJ3Byb2plY3RzJywge1xuICAgICAgYWN0aW9uczoge30sXG4gICAgICBpbnN0YW5jZToge31cbiAgICB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZpbHRlcigncm9sZXNTdHInLCByb2xlc1N0cik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb2xlc1N0cihsb2Rhc2gpIHtcbiAgICAvKipcbiAgICAgKiBAcGFyYW0ge2FycmF5fSByb2xlcyBsaXN0YSBkZSBwZXJmaXNcbiAgICAgKiBAcmV0dXJuIHtzdHJpbmd9IHBlcmZpcyBzZXBhcmFkb3MgcG9yICcsICcgIFxuICAgICAqL1xuICAgIHJldHVybiBmdW5jdGlvbiAocm9sZXMpIHtcbiAgICAgIHJldHVybiBsb2Rhc2gubWFwKHJvbGVzLCAnc2x1ZycpLmpvaW4oJywgJyk7XG4gICAgfTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5mYWN0b3J5KCdSb2xlc1NlcnZpY2UnLCBSb2xlc1NlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gUm9sZXNTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCdyb2xlcycpO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZhY3RvcnkoJ1N1cHBvcnRTZXJ2aWNlJywgU3VwcG9ydFNlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gU3VwcG9ydFNlcnZpY2Uoc2VydmljZUZhY3RvcnkpIHtcbiAgICByZXR1cm4gc2VydmljZUZhY3RvcnkoJ3N1cHBvcnQnLCB7XG4gICAgICBhY3Rpb25zOiB7XG4gICAgICAgIC8qKlxuICAgICAgICAgKiBQZWdhIGFzIHRyYWR1w6fDtWVzIHF1ZSBlc3TDo28gbm8gc2Vydmlkb3JcbiAgICAgICAgICpcbiAgICAgICAgICogQHJldHVybnMge3Byb21pc2V9IFVtYSBwcm9taXNlIGNvbSBvIHJlc3VsdGFkbyBkbyBjaGFtYWRhIG5vIGJhY2tlbmRcbiAgICAgICAgICovXG4gICAgICAgIGxhbmdzOiB7XG4gICAgICAgICAgbWV0aG9kOiAnR0VUJyxcbiAgICAgICAgICB1cmw6ICdsYW5ncycsXG4gICAgICAgICAgd3JhcDogZmFsc2UsXG4gICAgICAgICAgY2FjaGU6IHRydWVcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29udHJvbGxlcignUHJvZmlsZUNvbnRyb2xsZXInLCBQcm9maWxlQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBQcm9maWxlQ29udHJvbGxlcihVc2Vyc1NlcnZpY2UsIEF1dGgsIFByVG9hc3QsICR0cmFuc2xhdGUpIHtcbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0udXBkYXRlID0gdXBkYXRlO1xuXG4gICAgYWN0aXZhdGUoKTtcblxuICAgIGZ1bmN0aW9uIGFjdGl2YXRlKCkge1xuICAgICAgdm0udXNlciA9IGFuZ3VsYXIuY29weShBdXRoLmN1cnJlbnRVc2VyKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiB1cGRhdGUoKSB7XG4gICAgICBVc2Vyc1NlcnZpY2UudXBkYXRlUHJvZmlsZSh2bS51c2VyKS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICAvL2F0dWFsaXphIG8gdXN1w6FyaW8gY29ycmVudGUgY29tIGFzIG5vdmFzIGluZm9ybWHDp8O1ZXNcbiAgICAgICAgQXV0aC51cGRhdGVDdXJyZW50VXNlcihyZXNwb25zZSk7XG4gICAgICAgIFByVG9hc3Quc3VjY2VzcygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnNhdmVTdWNjZXNzJykpO1xuICAgICAgfSk7XG4gICAgfVxuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29udHJvbGxlcignVXNlcnNDb250cm9sbGVyJywgVXNlcnNDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIFVzZXJzQ29udHJvbGxlcigkY29udHJvbGxlciwgVXNlcnNTZXJ2aWNlKSB7XG5cbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0ub25BY3RpdmF0ZSA9IG9uQWN0aXZhdGU7XG4gICAgLy8gaW5zdGFudGlhdGUgYmFzZSBjb250cm9sbGVyXG4gICAgJGNvbnRyb2xsZXIoJ0NSVURDb250cm9sbGVyJywgeyB2bTogdm0sIG1vZGVsU2VydmljZTogVXNlcnNTZXJ2aWNlLCBvcHRpb25zOiB7fSB9KTtcblxuICAgIGZ1bmN0aW9uIG9uQWN0aXZhdGUoKSB7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMgPSB7fTtcbiAgICB9XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqXG4gICAqIEFycXVpdm8gZGUgY29uZmlndXJhw6fDo28gY29tIGFzIHJvdGFzIGVzcGVjw61maWNhcyBkbyByZWN1cnNvIHVzZXJcbiAgICpcbiAgICogQHBhcmFtIHthbnl9ICRzdGF0ZVByb3ZpZGVyXG4gICAqIEBwYXJhbSB7YW55fSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnYXBwLnVzZXInLCB7XG4gICAgICB1cmw6ICcvdXN1YXJpbycsXG4gICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL3VzZXJzL3VzZXJzLmh0bWwnLFxuICAgICAgY29udHJvbGxlcjogJ1VzZXJzQ29udHJvbGxlciBhcyB1c2Vyc0N0cmwnLFxuICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IHRydWUsIG5lZWRQcm9maWxlOiBbJ2FkbWluJ10gfVxuICAgIH0pLnN0YXRlKCdhcHAudXNlci1wcm9maWxlJywge1xuICAgICAgdXJsOiAnL3VzdWFyaW8vcGVyZmlsJyxcbiAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvdXNlcnMvcHJvZmlsZS5odG1sJyxcbiAgICAgIGNvbnRyb2xsZXI6ICdQcm9maWxlQ29udHJvbGxlciBhcyBwcm9maWxlQ3RybCcsXG4gICAgICBkYXRhOiB7IG5lZWRBdXRoZW50aWNhdGlvbjogdHJ1ZSB9XG4gICAgfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmFjdG9yeSgnVXNlcnNTZXJ2aWNlJywgVXNlcnNTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIFVzZXJzU2VydmljZShsb2Rhc2gsIEdsb2JhbCwgc2VydmljZUZhY3RvcnkpIHtcbiAgICByZXR1cm4gc2VydmljZUZhY3RvcnkoJ3VzZXJzJywge1xuICAgICAgLy9xdWFuZG8gaW5zdGFuY2lhIHVtIHVzdcOhcmlvIHNlbSBwYXNzYXIgcGFyYW1ldHJvLFxuICAgICAgLy9vIG1lc21vIHZhaSB0ZXIgb3MgdmFsb3JlcyBkZWZhdWx0cyBhYmFpeG9cbiAgICAgIGRlZmF1bHRzOiB7XG4gICAgICAgIHJvbGVzOiBbXVxuICAgICAgfSxcblxuICAgICAgYWN0aW9uczoge1xuICAgICAgICAvKipcbiAgICAgICAgICogU2VydmnDp28gcXVlIGF0dWFsaXphIG9zIGRhZG9zIGRvIHBlcmZpbCBkbyB1c3XDoXJpbyBsb2dhZG9cbiAgICAgICAgICpcbiAgICAgICAgICogQHBhcmFtIHtvYmplY3R9IGF0dHJpYnV0ZXNcbiAgICAgICAgICogQHJldHVybnMge3Byb21pc2V9IFVtYSBwcm9taXNlIGNvbSBvIHJlc3VsdGFkbyBkbyBjaGFtYWRhIG5vIGJhY2tlbmRcbiAgICAgICAgICovXG4gICAgICAgIHVwZGF0ZVByb2ZpbGU6IHtcbiAgICAgICAgICBtZXRob2Q6ICdQVVQnLFxuICAgICAgICAgIHVybDogR2xvYmFsLmFwaVBhdGggKyAnL3Byb2ZpbGUnLFxuICAgICAgICAgIG92ZXJyaWRlOiB0cnVlLFxuICAgICAgICAgIHdyYXA6IGZhbHNlXG4gICAgICAgIH1cbiAgICAgIH0sXG5cbiAgICAgIGluc3RhbmNlOiB7XG4gICAgICAgIC8qKlxuICAgICAgICAgKiBWZXJpZmljYSBzZSBvIHVzdcOhcmlvIHRlbSBvcyBwZXJmaXMgaW5mb3JtYWRvcy5cbiAgICAgICAgICpcbiAgICAgICAgICogQHBhcmFtIHthbnl9IHJvbGVzIHBlcmZpcyBhIHNlcmVtIHZlcmlmaWNhZG9zXG4gICAgICAgICAqIEBwYXJhbSB7Ym9vbGVhbn0gYWxsIGZsYWcgcGFyYSBpbmRpY2FyIHNlIHZhaSBjaGVnYXIgdG9kb3Mgb3MgcGVyZmlzIG91IHNvbWVudGUgdW0gZGVsZXNcbiAgICAgICAgICogQHJldHVybnMge2Jvb2xlYW59XG4gICAgICAgICAqL1xuICAgICAgICBoYXNQcm9maWxlOiBmdW5jdGlvbiBoYXNQcm9maWxlKHJvbGVzLCBhbGwpIHtcbiAgICAgICAgICByb2xlcyA9IGFuZ3VsYXIuaXNBcnJheShyb2xlcykgPyByb2xlcyA6IFtyb2xlc107XG5cbiAgICAgICAgICB2YXIgdXNlclJvbGVzID0gbG9kYXNoLm1hcCh0aGlzLnJvbGVzLCAnc2x1ZycpO1xuXG4gICAgICAgICAgaWYgKGFsbCkge1xuICAgICAgICAgICAgcmV0dXJuIGxvZGFzaC5pbnRlcnNlY3Rpb24odXNlclJvbGVzLCByb2xlcykubGVuZ3RoID09PSByb2xlcy5sZW5ndGg7XG4gICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIC8vcmV0dXJuIHRoZSBsZW5ndGggYmVjYXVzZSAwIGlzIGZhbHNlIGluIGpzXG4gICAgICAgICAgICByZXR1cm4gbG9kYXNoLmludGVyc2VjdGlvbih1c2VyUm9sZXMsIHJvbGVzKS5sZW5ndGg7XG4gICAgICAgICAgfVxuICAgICAgICB9LFxuXG4gICAgICAgIC8qKlxuICAgICAgICAgKiBWZXJpZmljYSBzZSBvIHVzdcOhcmlvIHRlbSBvIHBlcmZpbCBhZG1pbi5cbiAgICAgICAgICpcbiAgICAgICAgICogQHJldHVybnMge2Jvb2xlYW59XG4gICAgICAgICAqL1xuICAgICAgICBpc0FkbWluOiBmdW5jdGlvbiBpc0FkbWluKCkge1xuICAgICAgICAgIHJldHVybiB0aGlzLmhhc1Byb2ZpbGUoJ2FkbWluJyk7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29tcG9uZW50KCdib3gnLCB7XG4gICAgcmVwbGFjZTogdHJ1ZSxcbiAgICB0ZW1wbGF0ZVVybDogWydHbG9iYWwnLCBmdW5jdGlvbiAoR2xvYmFsKSB7XG4gICAgICByZXR1cm4gR2xvYmFsLmNsaWVudFBhdGggKyAnL3dpZGdldHMvYm94Lmh0bWwnO1xuICAgIH1dLFxuICAgIHRyYW5zY2x1ZGU6IHtcbiAgICAgIHRvb2xiYXJCdXR0b25zOiAnP2JveFRvb2xiYXJCdXR0b25zJyxcbiAgICAgIGZvb3RlckJ1dHRvbnM6ICc/Ym94Rm9vdGVyQnV0dG9ucydcbiAgICB9LFxuICAgIGJpbmRpbmdzOiB7XG4gICAgICBib3hUaXRsZTogJ0AnLFxuICAgICAgdG9vbGJhckNsYXNzOiAnQCcsXG4gICAgICB0b29sYmFyQmdDb2xvcjogJ0AnXG4gICAgfSxcbiAgICBjb250cm9sbGVyOiBbJyR0cmFuc2NsdWRlJywgZnVuY3Rpb24gKCR0cmFuc2NsdWRlKSB7XG4gICAgICB2YXIgY3RybCA9IHRoaXM7XG5cbiAgICAgIGN0cmwudHJhbnNjbHVkZSA9ICR0cmFuc2NsdWRlO1xuXG4gICAgICBjdHJsLiRvbkluaXQgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgIGlmIChhbmd1bGFyLmlzVW5kZWZpbmVkKGN0cmwudG9vbGJhckJnQ29sb3IpKSBjdHJsLnRvb2xiYXJCZ0NvbG9yID0gJ2RlZmF1bHQtcHJpbWFyeSc7XG4gICAgICB9O1xuICAgIH1dXG4gIH0pO1xufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29tcG9uZW50KCdjb250ZW50Qm9keScsIHtcbiAgICByZXBsYWNlOiB0cnVlLFxuICAgIHRyYW5zY2x1ZGU6IHRydWUsXG4gICAgdGVtcGxhdGVVcmw6IFsnR2xvYmFsJywgZnVuY3Rpb24gKEdsb2JhbCkge1xuICAgICAgcmV0dXJuIEdsb2JhbC5jbGllbnRQYXRoICsgJy93aWRnZXRzL2NvbnRlbnQtYm9keS5odG1sJztcbiAgICB9XSxcbiAgICBiaW5kaW5nczoge1xuICAgICAgbGF5b3V0QWxpZ246ICdAJ1xuICAgIH0sXG4gICAgY29udHJvbGxlcjogW2Z1bmN0aW9uICgpIHtcbiAgICAgIHZhciBjdHJsID0gdGhpcztcblxuICAgICAgY3RybC4kb25Jbml0ID0gZnVuY3Rpb24gKCkge1xuICAgICAgICAvLyBNYWtlIGEgY29weSBvZiB0aGUgaW5pdGlhbCB2YWx1ZSB0byBiZSBhYmxlIHRvIHJlc2V0IGl0IGxhdGVyXG4gICAgICAgIGN0cmwubGF5b3V0QWxpZ24gPSBhbmd1bGFyLmlzRGVmaW5lZChjdHJsLmxheW91dEFsaWduKSA/IGN0cmwubGF5b3V0QWxpZ24gOiAnY2VudGVyIHN0YXJ0JztcbiAgICAgIH07XG4gICAgfV1cbiAgfSk7XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb21wb25lbnQoJ2NvbnRlbnRIZWFkZXInLCB7XG4gICAgdGVtcGxhdGVVcmw6IFsnR2xvYmFsJywgZnVuY3Rpb24gKEdsb2JhbCkge1xuICAgICAgcmV0dXJuIEdsb2JhbC5jbGllbnRQYXRoICsgJy93aWRnZXRzL2NvbnRlbnQtaGVhZGVyLmh0bWwnO1xuICAgIH1dLFxuICAgIHJlcGxhY2U6IHRydWUsXG4gICAgYmluZGluZ3M6IHtcbiAgICAgIHRpdGxlOiAnQCcsXG4gICAgICBkZXNjcmlwdGlvbjogJ0AnXG4gICAgfVxuICB9KTtcbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5maWx0ZXIoJ2F1ZGl0RGV0YWlsVGl0bGUnLCBhdWRpdERldGFpbFRpdGxlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIGF1ZGl0RGV0YWlsVGl0bGUoJHRyYW5zbGF0ZSkge1xuICAgIHJldHVybiBmdW5jdGlvbiAoYXVkaXREZXRhaWwsIHN0YXR1cykge1xuICAgICAgaWYgKGF1ZGl0RGV0YWlsLnR5cGUgPT09ICd1cGRhdGVkJykge1xuICAgICAgICBpZiAoc3RhdHVzID09PSAnYmVmb3JlJykge1xuICAgICAgICAgIHJldHVybiAkdHJhbnNsYXRlLmluc3RhbnQoJ2RpYWxvZy5hdWRpdC51cGRhdGVkQmVmb3JlJyk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgcmV0dXJuICR0cmFuc2xhdGUuaW5zdGFudCgnZGlhbG9nLmF1ZGl0LnVwZGF0ZWRBZnRlcicpO1xuICAgICAgICB9XG4gICAgICB9IGVsc2Uge1xuICAgICAgICByZXR1cm4gJHRyYW5zbGF0ZS5pbnN0YW50KCdkaWFsb2cuYXVkaXQuJyArIGF1ZGl0RGV0YWlsLnR5cGUpO1xuICAgICAgfVxuICAgIH07XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5maWx0ZXIoJ2F1ZGl0TW9kZWwnLCBhdWRpdE1vZGVsKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIGF1ZGl0TW9kZWwoJHRyYW5zbGF0ZSkge1xuICAgIHJldHVybiBmdW5jdGlvbiAobW9kZWxJZCkge1xuICAgICAgbW9kZWxJZCA9IG1vZGVsSWQucmVwbGFjZSgnQXBwXFxcXCcsICcnKTtcbiAgICAgIHZhciBtb2RlbCA9ICR0cmFuc2xhdGUuaW5zdGFudCgnbW9kZWxzLicgKyBtb2RlbElkLnRvTG93ZXJDYXNlKCkpO1xuXG4gICAgICByZXR1cm4gbW9kZWwgPyBtb2RlbCA6IG1vZGVsSWQ7XG4gICAgfTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZpbHRlcignYXVkaXRUeXBlJywgYXVkaXRUeXBlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIGF1ZGl0VHlwZShsb2Rhc2gsIEF1ZGl0U2VydmljZSkge1xuICAgIHJldHVybiBmdW5jdGlvbiAodHlwZUlkKSB7XG4gICAgICB2YXIgdHlwZSA9IGxvZGFzaC5maW5kKEF1ZGl0U2VydmljZS5saXN0VHlwZXMoKSwgeyBpZDogdHlwZUlkIH0pO1xuXG4gICAgICByZXR1cm4gdHlwZSA/IHR5cGUubGFiZWwgOiB0eXBlO1xuICAgIH07XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5maWx0ZXIoJ2F1ZGl0VmFsdWUnLCBhdWRpdFZhbHVlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIGF1ZGl0VmFsdWUoJGZpbHRlciwgbG9kYXNoKSB7XG4gICAgcmV0dXJuIGZ1bmN0aW9uICh2YWx1ZSwga2V5KSB7XG4gICAgICBpZiAoYW5ndWxhci5pc0RhdGUodmFsdWUpIHx8IGxvZGFzaC5lbmRzV2l0aChrZXksICdfYXQnKSB8fCBsb2Rhc2guZW5kc1dpdGgoa2V5LCAnX3RvJykpIHtcbiAgICAgICAgcmV0dXJuICRmaWx0ZXIoJ3ByRGF0ZXRpbWUnKSh2YWx1ZSk7XG4gICAgICB9XG5cbiAgICAgIGlmICh0eXBlb2YgdmFsdWUgPT09ICdib29sZWFuJykge1xuICAgICAgICByZXR1cm4gJGZpbHRlcigndHJhbnNsYXRlJykodmFsdWUgPyAnZ2xvYmFsLnllcycgOiAnZ2xvYmFsLm5vJyk7XG4gICAgICB9XG5cbiAgICAgIC8vY2hlY2sgaXMgZmxvYXRcbiAgICAgIGlmIChOdW1iZXIodmFsdWUpID09PSB2YWx1ZSAmJiB2YWx1ZSAlIDEgIT09IDApIHtcbiAgICAgICAgcmV0dXJuICRmaWx0ZXIoJ3JlYWwnKSh2YWx1ZSk7XG4gICAgICB9XG5cbiAgICAgIHJldHVybiB2YWx1ZTtcbiAgICB9O1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4vKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCwgbm8tdW5kZWY6IDAqL1xuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25zdGFudCgncHQtQlIuaTE4bi5hdHRyaWJ1dGVzJywge1xuICAgIGVtYWlsOiAnRW1haWwnLFxuICAgIHBhc3N3b3JkOiAnU2VuaGEnLFxuICAgIG5hbWU6ICdOb21lJyxcbiAgICBpbWFnZTogJ0ltYWdlbScsXG4gICAgcm9sZXM6ICdQZXJmaXMnLFxuICAgIGRhdGU6ICdEYXRhJyxcbiAgICBpbml0aWFsRGF0ZTogJ0RhdGEgSW5pY2lhbCcsXG4gICAgZmluYWxEYXRlOiAnRGF0YSBGaW5hbCcsXG4gICAgdGFzazoge1xuICAgICAgZGVzY3JpcHRpb246ICdEZXNjcmnDp8OjbycsXG4gICAgICBkb25lOiAnRmVpdG8/JyxcbiAgICAgIHByaW9yaXR5OiAnUHJpb3JpZGFkZScsXG4gICAgICBzY2hlZHVsZWRfdG86ICdBZ2VuZGFkbyBQYXJhPycsXG4gICAgICBwcm9qZWN0OiAnUHJvamV0bydcbiAgICB9LFxuICAgIHByb2plY3Q6IHtcbiAgICAgIGNvc3Q6ICdDdXN0bydcbiAgICB9LFxuICAgIC8vw6kgY2FycmVnYWRvIGRvIHNlcnZpZG9yIGNhc28gZXN0ZWphIGRlZmluaWRvIG5vIG1lc21vXG4gICAgYXVkaXRNb2RlbDoge31cbiAgfSk7XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4vKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCwgbm8tdW5kZWY6IDAqL1xuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25zdGFudCgncHQtQlIuaTE4bi5kaWFsb2cnLCB7XG4gICAgY29uZmlybVRpdGxlOiAnQ29uZmlybWHDp8OjbycsXG4gICAgY29uZmlybURlc2NyaXB0aW9uOiAnQ29uZmlybWEgYSBhw6fDo28/JyxcbiAgICByZW1vdmVEZXNjcmlwdGlvbjogJ0Rlc2VqYSByZW1vdmVyIHBlcm1hbmVudGVtZW50ZSB7e25hbWV9fT8nLFxuICAgIGF1ZGl0OiB7XG4gICAgICBjcmVhdGVkOiAnSW5mb3JtYcOnw7VlcyBkbyBDYWRhc3RybycsXG4gICAgICB1cGRhdGVkQmVmb3JlOiAnQW50ZXMgZGEgQXR1YWxpemHDp8OjbycsXG4gICAgICB1cGRhdGVkQWZ0ZXI6ICdEZXBvaXMgZGEgQXR1YWxpemHDp8OjbycsXG4gICAgICBkZWxldGVkOiAnSW5mb3JtYcOnw7VlcyBhbnRlcyBkZSByZW1vdmVyJ1xuICAgIH0sXG4gICAgbG9naW46IHtcbiAgICAgIHJlc2V0UGFzc3dvcmQ6IHtcbiAgICAgICAgZGVzY3JpcHRpb246ICdEaWdpdGUgYWJhaXhvIG8gZW1haWwgY2FkYXN0cmFkbyBubyBzaXN0ZW1hLidcbiAgICAgIH1cbiAgICB9XG4gIH0pO1xufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuLyplc2xpbnQgYW5ndWxhci9maWxlLW5hbWU6IDAsIG5vLXVuZGVmOiAwKi9cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29uc3RhbnQoJ3B0LUJSLmkxOG4uZ2xvYmFsJywge1xuICAgIGxvYWRpbmc6ICdDYXJyZWdhbmRvLi4uJyxcbiAgICBwcm9jZXNzaW5nOiAnUHJvY2Vzc2FuZG8uLi4nLFxuICAgIHllczogJ1NpbScsXG4gICAgbm86ICdOw6NvJyxcbiAgICBhbGw6ICdUb2RvcydcbiAgfSk7XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4vKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCwgbm8tdW5kZWY6IDAqL1xuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25zdGFudCgncHQtQlIuaTE4bi5tZXNzYWdlcycsIHtcbiAgICBpbnRlcm5hbEVycm9yOiAnT2NvcnJldSB1bSBlcnJvIGludGVybm8sIGNvbnRhdGUgbyBhZG1pbmlzdHJhZG9yIGRvIHNpc3RlbWEnLFxuICAgIG5vdEZvdW5kOiAnTmVuaHVtIHJlZ2lzdHJvIGVuY29udHJhZG8nLFxuICAgIG5vdEF1dGhvcml6ZWQ6ICdWb2PDqiBuw6NvIHRlbSBhY2Vzc28gYSBlc3RhIGZ1bmNpb25hbGlkYWRlLicsXG4gICAgc2VhcmNoRXJyb3I6ICdOw6NvIGZvaSBwb3Nzw612ZWwgcmVhbGl6YXIgYSBidXNjYS4nLFxuICAgIHNhdmVTdWNjZXNzOiAnUmVnaXN0cm8gc2Fsdm8gY29tIHN1Y2Vzc28uJyxcbiAgICBvcGVyYXRpb25TdWNjZXNzOiAnT3BlcmHDp8OjbyByZWFsaXphZGEgY29tIHN1Y2Vzc28uJyxcbiAgICBvcGVyYXRpb25FcnJvcjogJ0Vycm8gYW8gcmVhbGl6YXIgYSBvcGVyYcOnw6NvJyxcbiAgICBzYXZlRXJyb3I6ICdFcnJvIGFvIHRlbnRhciBzYWx2YXIgbyByZWdpc3Ryby4nLFxuICAgIHJlbW92ZVN1Y2Nlc3M6ICdSZW1vw6fDo28gcmVhbGl6YWRhIGNvbSBzdWNlc3NvLicsXG4gICAgcmVtb3ZlRXJyb3I6ICdFcnJvIGFvIHRlbnRhciByZW1vdmVyIG8gcmVnaXN0cm8uJyxcbiAgICByZXNvdXJjZU5vdEZvdW5kRXJyb3I6ICdSZWN1cnNvIG7Do28gZW5jb250cmFkbycsXG4gICAgbm90TnVsbEVycm9yOiAnVG9kb3Mgb3MgY2FtcG9zIG9icmlnYXTDs3Jpb3MgZGV2ZW0gc2VyIHByZWVuY2hpZG9zLicsXG4gICAgZHVwbGljYXRlZFJlc291cmNlRXJyb3I6ICdKw6EgZXhpc3RlIHVtIHJlY3Vyc28gY29tIGVzc2FzIGluZm9ybWHDp8O1ZXMuJyxcbiAgICB2YWxpZGF0ZToge1xuICAgICAgZmllbGRSZXF1aXJlZDogJ08gY2FtcG8ge3tmaWVsZH19IMOpIG9icmlncmF0w7NyaW8uJ1xuICAgIH0sXG4gICAgbGF5b3V0OiB7XG4gICAgICBlcnJvcjQwNDogJ1DDoWdpbmEgbsOjbyBlbmNvbnRyYWRhJ1xuICAgIH0sXG4gICAgbG9naW46IHtcbiAgICAgIGxvZ291dEluYWN0aXZlOiAnVm9jw6ogZm9pIGRlc2xvZ2FkbyBkbyBzaXN0ZW1hIHBvciBpbmF0aXZpZGFkZS4gRmF2b3IgZW50cmFyIG5vIHNpc3RlbWEgbm92YW1lbnRlLicsXG4gICAgICBpbnZhbGlkQ3JlZGVudGlhbHM6ICdDcmVkZW5jaWFpcyBJbnbDoWxpZGFzJyxcbiAgICAgIHVua25vd25FcnJvcjogJ07Do28gZm9pIHBvc3PDrXZlbCByZWFsaXphciBvIGxvZ2luLiBUZW50ZSBub3ZhbWVudGUuICcgKyAnQ2FzbyBuw6NvIGNvbnNpZ2EgZmF2b3IgZW5jb250cmFyIGVtIGNvbnRhdG8gY29tIG8gYWRtaW5pc3RyYWRvciBkbyBzaXN0ZW1hLicsXG4gICAgICB1c2VyTm90Rm91bmQ6ICdOw6NvIGZvaSBwb3Nzw612ZWwgZW5jb250cmFyIHNldXMgZGFkb3MnXG4gICAgfSxcbiAgICBkYXNoYm9hcmQ6IHtcbiAgICAgIHdlbGNvbWU6ICdTZWphIGJlbSBWaW5kbyB7e3VzZXJOYW1lfX0nLFxuICAgICAgZGVzY3JpcHRpb246ICdVdGlsaXplIG8gbWVudSBwYXJhIG5hdmVnYcOnw6NvLidcbiAgICB9LFxuICAgIG1haWw6IHtcbiAgICAgIG1haWxFcnJvcnM6ICdPY29ycmV1IHVtIGVycm8gbm9zIHNlZ3VpbnRlcyBlbWFpbHMgYWJhaXhvOlxcbicsXG4gICAgICBzZW5kTWFpbFN1Y2Nlc3M6ICdFbWFpbCBlbnZpYWRvIGNvbSBzdWNlc3NvIScsXG4gICAgICBzZW5kTWFpbEVycm9yOiAnTsOjbyBmb2kgcG9zc8OtdmVsIGVudmlhciBvIGVtYWlsLicsXG4gICAgICBwYXNzd29yZFNlbmRpbmdTdWNjZXNzOiAnTyBwcm9jZXNzbyBkZSByZWN1cGVyYcOnw6NvIGRlIHNlbmhhIGZvaSBpbmljaWFkby4gQ2FzbyBvIGVtYWlsIG7Do28gY2hlZ3VlIGVtIDEwIG1pbnV0b3MgdGVudGUgbm92YW1lbnRlLidcbiAgICB9LFxuICAgIHVzZXI6IHtcbiAgICAgIHJlbW92ZVlvdXJTZWxmRXJyb3I6ICdWb2PDqiBuw6NvIHBvZGUgcmVtb3ZlciBzZXUgcHLDs3ByaW8gdXN1w6FyaW8nLFxuICAgICAgdXNlckV4aXN0czogJ1VzdcOhcmlvIGrDoSBhZGljaW9uYWRvIScsXG4gICAgICBwcm9maWxlOiB7XG4gICAgICAgIHVwZGF0ZUVycm9yOiAnTsOjbyBmb2kgcG9zc8OtdmVsIGF0dWFsaXphciBzZXUgcHJvZmlsZSdcbiAgICAgIH1cbiAgICB9LFxuICAgIHF1ZXJ5RGluYW1pYzoge1xuICAgICAgbm9GaWx0ZXI6ICdOZW5odW0gZmlsdHJvIGFkaWNpb25hZG8nXG4gICAgfVxuICB9KTtcbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbi8qZXNsaW50IGFuZ3VsYXIvZmlsZS1uYW1lOiAwLCBuby11bmRlZjogMCovXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbnN0YW50KCdwdC1CUi5pMThuLm1vZGVscycsIHtcbiAgICB1c2VyOiAnVXN1w6FyaW8nLFxuICAgIHRhc2s6ICdUYXJlZmEnLFxuICAgIHByb2plY3Q6ICdQcm9qZXRvJ1xuICB9KTtcbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbi8qZXNsaW50IGFuZ3VsYXIvZmlsZS1uYW1lOiAwLCBuby11bmRlZjogMCovXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbnN0YW50KCdwdC1CUi5pMThuLnZpZXdzJywge1xuICAgIGJyZWFkY3J1bWJzOiB7XG4gICAgICB1c2VyOiAnQWRtaW5pc3RyYcOnw6NvIC0gVXN1w6FyaW8nLFxuICAgICAgJ3VzZXItcHJvZmlsZSc6ICdQZXJmaWwnLFxuICAgICAgZGFzaGJvYXJkOiAnRGFzaGJvYXJkJyxcbiAgICAgIGF1ZGl0OiAnQWRtaW5pc3RyYcOnw6NvIC0gQXVkaXRvcmlhJyxcbiAgICAgIG1haWw6ICdBZG1pbmlzdHJhw6fDo28gLSBFbnZpbyBkZSBlLW1haWwnLFxuICAgICAgcHJvamVjdHM6ICdQcm9qZXRvcycsXG4gICAgICAnZGluYW1pYy1xdWVyeSc6ICdBZG1pbmlzdHJhw6fDo28gLSBDb25zdWx0YXMgRGluw6JtaWNhcycsXG4gICAgICAnbm90LWF1dGhvcml6ZWQnOiAnQWNlc3NvIE5lZ2FkbydcbiAgICB9LFxuICAgIHRpdGxlczoge1xuICAgICAgZGFzaGJvYXJkOiAnUMOhZ2luYSBpbmljaWFsJyxcbiAgICAgIG1haWxTZW5kOiAnRW52aWFyIGUtbWFpbCcsXG4gICAgICB0YXNrTGlzdDogJ0xpc3RhIGRlIFRhcmVmYXMnLFxuICAgICAgdXNlckxpc3Q6ICdMaXN0YSBkZSBVc3XDoXJpb3MnLFxuICAgICAgYXVkaXRMaXN0OiAnTGlzdGEgZGUgTG9ncycsXG4gICAgICByZWdpc3RlcjogJ0Zvcm11bMOhcmlvIGRlIENhZGFzdHJvJyxcbiAgICAgIHJlc2V0UGFzc3dvcmQ6ICdSZWRlZmluaXIgU2VuaGEnLFxuICAgICAgdXBkYXRlOiAnRm9ybXVsw6FyaW8gZGUgQXR1YWxpemHDp8OjbydcbiAgICB9LFxuICAgIGFjdGlvbnM6IHtcbiAgICAgIHNlbmQ6ICdFbnZpYXInLFxuICAgICAgc2F2ZTogJ1NhbHZhcicsXG4gICAgICBjbGVhcjogJ0xpbXBhcicsXG4gICAgICBjbGVhckFsbDogJ0xpbXBhciBUdWRvJyxcbiAgICAgIHJlc3RhcnQ6ICdSZWluaWNpYXInLFxuICAgICAgZmlsdGVyOiAnRmlsdHJhcicsXG4gICAgICBzZWFyY2g6ICdQZXNxdWlzYXInLFxuICAgICAgbGlzdDogJ0xpc3RhcicsXG4gICAgICBlZGl0OiAnRWRpdGFyJyxcbiAgICAgIGNhbmNlbDogJ0NhbmNlbGFyJyxcbiAgICAgIHVwZGF0ZTogJ0F0dWFsaXphcicsXG4gICAgICByZW1vdmU6ICdSZW1vdmVyJyxcbiAgICAgIGdldE91dDogJ1NhaXInLFxuICAgICAgYWRkOiAnQWRpY2lvbmFyJyxcbiAgICAgIGluOiAnRW50cmFyJyxcbiAgICAgIGxvYWRJbWFnZTogJ0NhcnJlZ2FyIEltYWdlbScsXG4gICAgICBzaWdudXA6ICdDYWRhc3RyYXInLFxuICAgICAgY3JpYXJQcm9qZXRvOiAnQ3JpYXIgUHJvamV0bycsXG4gICAgICBwcm9qZWN0TGlzdDogJ0xpc3RhIGRlIFByb2pldG9zJ1xuICAgIH0sXG4gICAgZmllbGRzOiB7XG4gICAgICBkYXRlOiAnRGF0YScsXG4gICAgICBhY3Rpb246ICdBw6fDo28nLFxuICAgICAgYWN0aW9uczogJ0HDp8O1ZXMnLFxuICAgICAgYXVkaXQ6IHtcbiAgICAgICAgZGF0ZVN0YXJ0OiAnRGF0YSBJbmljaWFsJyxcbiAgICAgICAgZGF0ZUVuZDogJ0RhdGEgRmluYWwnLFxuICAgICAgICByZXNvdXJjZTogJ1JlY3Vyc28nLFxuICAgICAgICBhbGxSZXNvdXJjZXM6ICdUb2RvcyBSZWN1cnNvcycsXG4gICAgICAgIHR5cGU6IHtcbiAgICAgICAgICBjcmVhdGVkOiAnQ2FkYXN0cmFkbycsXG4gICAgICAgICAgdXBkYXRlZDogJ0F0dWFsaXphZG8nLFxuICAgICAgICAgIGRlbGV0ZWQ6ICdSZW1vdmlkbydcbiAgICAgICAgfVxuICAgICAgfSxcbiAgICAgIGxvZ2luOiB7XG4gICAgICAgIHJlc2V0UGFzc3dvcmQ6ICdFc3F1ZWNpIG1pbmhhIHNlbmhhJyxcbiAgICAgICAgY29uZmlybVBhc3N3b3JkOiAnQ29uZmlybWFyIHNlbmhhJ1xuICAgICAgfSxcbiAgICAgIG1haWw6IHtcbiAgICAgICAgdG86ICdQYXJhJyxcbiAgICAgICAgc3ViamVjdDogJ0Fzc3VudG8nLFxuICAgICAgICBtZXNzYWdlOiAnTWVuc2FnZW0nXG4gICAgICB9LFxuICAgICAgcXVlcnlEaW5hbWljOiB7XG4gICAgICAgIGZpbHRlcnM6ICdGaWx0cm9zJyxcbiAgICAgICAgcmVzdWx0czogJ1Jlc3VsdGFkb3MnLFxuICAgICAgICBtb2RlbDogJ01vZGVsJyxcbiAgICAgICAgYXR0cmlidXRlOiAnQXRyaWJ1dG8nLFxuICAgICAgICBvcGVyYXRvcjogJ09wZXJhZG9yJyxcbiAgICAgICAgcmVzb3VyY2U6ICdSZWN1cnNvJyxcbiAgICAgICAgdmFsdWU6ICdWYWxvcicsXG4gICAgICAgIG9wZXJhdG9yczoge1xuICAgICAgICAgIGVxdWFsczogJ0lndWFsJyxcbiAgICAgICAgICBkaWZlcmVudDogJ0RpZmVyZW50ZScsXG4gICAgICAgICAgY29udGVpbnM6ICdDb250w6ltJyxcbiAgICAgICAgICBzdGFydFdpdGg6ICdJbmljaWEgY29tJyxcbiAgICAgICAgICBmaW5pc2hXaXRoOiAnRmluYWxpemEgY29tJyxcbiAgICAgICAgICBiaWdnZXJUaGFuOiAnTWFpb3InLFxuICAgICAgICAgIGVxdWFsc09yQmlnZ2VyVGhhbjogJ01haW9yIG91IElndWFsJyxcbiAgICAgICAgICBsZXNzVGhhbjogJ01lbm9yJyxcbiAgICAgICAgICBlcXVhbHNPckxlc3NUaGFuOiAnTWVub3Igb3UgSWd1YWwnXG4gICAgICAgIH1cbiAgICAgIH0sXG4gICAgICBwcm9qZWN0OiB7XG4gICAgICAgIG5hbWU6ICdOb21lJyxcbiAgICAgICAgdG90YWxUYXNrOiAnVG90YWwgZGUgVGFyZWZhcydcbiAgICAgIH0sXG4gICAgICB0YXNrOiB7XG4gICAgICAgIGRvbmU6ICdOw6NvIEZlaXRvIC8gRmVpdG8nXG4gICAgICB9LFxuICAgICAgdXNlcjoge1xuICAgICAgICBwZXJmaWxzOiAnUGVyZmlzJyxcbiAgICAgICAgbmFtZU9yRW1haWw6ICdOb21lIG91IEVtYWlsJ1xuICAgICAgfVxuICAgIH0sXG4gICAgbGF5b3V0OiB7XG4gICAgICBtZW51OiB7XG4gICAgICAgIGRhc2hib2FyZDogJ0Rhc2hib2FyZCcsXG4gICAgICAgIHByb2plY3Q6ICdQcm9qZXRvcycsXG4gICAgICAgIGFkbWluOiAnQWRtaW5pc3RyYcOnw6NvJyxcbiAgICAgICAgZXhhbXBsZXM6ICdFeGVtcGxvcycsXG4gICAgICAgIHVzZXI6ICdVc3XDoXJpb3MnLFxuICAgICAgICBtYWlsOiAnRW52aWFyIGUtbWFpbCcsXG4gICAgICAgIGF1ZGl0OiAnQXVkaXRvcmlhJyxcbiAgICAgICAgZGluYW1pY1F1ZXJ5OiAnQ29uc3VsdGFzIERpbmFtaWNhcydcbiAgICAgIH1cbiAgICB9LFxuICAgIHRvb2x0aXBzOiB7XG4gICAgICBhdWRpdDoge1xuICAgICAgICB2aWV3RGV0YWlsOiAnVmlzdWFsaXphciBEZXRhbGhhbWVudG8nXG4gICAgICB9LFxuICAgICAgdXNlcjoge1xuICAgICAgICBwZXJmaWw6ICdQZXJmaWwnLFxuICAgICAgICB0cmFuc2ZlcjogJ1RyYW5zZmVyaXInXG4gICAgICB9LFxuICAgICAgdGFzazoge1xuICAgICAgICBsaXN0VGFzazogJ0xpc3RhciBUYXJlZmFzJ1xuICAgICAgfVxuICAgIH1cbiAgfSk7XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29udHJvbGxlcignVGFza3NEaWFsb2dDb250cm9sbGVyJywgVGFza3NEaWFsb2dDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIFRhc2tzRGlhbG9nQ29udHJvbGxlcigkY29udHJvbGxlciwgVGFza3NTZXJ2aWNlLCBwcm9qZWN0SWQsIFByVG9hc3QsIC8vIE5PU09OQVJcbiAgUHJEaWFsb2csICR0cmFuc2xhdGUsIEdsb2JhbCwgbW9tZW50KSB7XG5cbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgLy9GdW5jdGlvbnMgQmxvY2tcbiAgICB2bS5vbkFjdGl2YXRlID0gb25BY3RpdmF0ZTtcbiAgICB2bS5jbG9zZSA9IGNsb3NlO1xuICAgIHZtLmFwcGx5RmlsdGVycyA9IGFwcGx5RmlsdGVycztcbiAgICB2bS5iZWZvcmVTYXZlID0gYmVmb3JlU2F2ZTtcbiAgICB2bS5hZnRlclNhdmUgPSBhZnRlclNhdmU7XG4gICAgdm0udG9nZ2xlRG9uZSA9IHRvZ2dsZURvbmU7XG5cbiAgICAvLyBpbnN0YW50aWF0ZSBiYXNlIGNvbnRyb2xsZXJcbiAgICAkY29udHJvbGxlcignQ1JVRENvbnRyb2xsZXInLCB7IHZtOiB2bSwgbW9kZWxTZXJ2aWNlOiBUYXNrc1NlcnZpY2UsIG9wdGlvbnM6IHtcbiAgICAgICAgcGVyUGFnZTogNVxuICAgICAgfSB9KTtcblxuICAgIGZ1bmN0aW9uIG9uQWN0aXZhdGUoKSB7XG4gICAgICB2bS5nbG9iYWwgPSBHbG9iYWw7XG4gICAgICB2bS5yZXNvdXJjZS5zY2hlZHVsZWRfdG8gPSBtb21lbnQoKS5hZGQoMzAsICdtaW51dGVzJyk7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMgPSB7IHByb2plY3RJZDogcHJvamVjdElkIH07XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gYXBwbHlGaWx0ZXJzKGRlZmF1bHRRdWVyeUZpbHRlcnMpIHtcbiAgICAgIHJldHVybiBhbmd1bGFyLmV4dGVuZChkZWZhdWx0UXVlcnlGaWx0ZXJzLCB2bS5xdWVyeUZpbHRlcnMpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGJlZm9yZVNhdmUoKSB7XG4gICAgICB2bS5yZXNvdXJjZS5wcm9qZWN0X2lkID0gdm0ucXVlcnlGaWx0ZXJzLnByb2plY3RJZDtcbiAgICAgIHZtLnJlc291cmNlLnByb2plY3QgPSBudWxsO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGFmdGVyU2F2ZSgpIHtcbiAgICAgIHZtLmNsZWFuRm9ybSgpO1xuICAgICAgdm0uc2VhcmNoKHZtLnBhZ2luYXRvci5jdXJyZW50UGFnZSk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gY2xvc2UoKSB7XG4gICAgICB2bS5jbGVhbkZvcm0oKTtcbiAgICAgIFByRGlhbG9nLmNsb3NlKCk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gdG9nZ2xlRG9uZShyZXNvdXJjZSkge1xuICAgICAgVGFza3NTZXJ2aWNlLnRvZ2dsZURvbmUoeyBpZDogcmVzb3VyY2UuaWQsIGRvbmU6IHJlc291cmNlLmRvbmUgfSkudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgIFByVG9hc3Quc3VjY2VzcygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnNhdmVTdWNjZXNzJykpO1xuICAgICAgICB2bS5zZWFyY2godm0ucGFnaW5hdG9yLmN1cnJlbnRQYWdlKTtcbiAgICAgIH0sIGZ1bmN0aW9uIChlcnJvcikge1xuICAgICAgICBQclRvYXN0LmVycm9yVmFsaWRhdGlvbihlcnJvci5kYXRhLCAkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLm9wZXJhdGlvbkVycm9yJykpO1xuICAgICAgfSk7XG4gICAgfVxuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZhY3RvcnkoJ1Rhc2tzU2VydmljZScsIFRhc2tzU2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiBUYXNrc1NlcnZpY2Uoc2VydmljZUZhY3RvcnksIG1vbWVudCkge1xuICAgIHJldHVybiBzZXJ2aWNlRmFjdG9yeSgndGFza3MnLCB7XG4gICAgICAvL3F1YW5kbyBpbnN0YW5jaWEgdW0gdXN1w6FyaW8gc2VtIHBhc3NhciBwYXJhbWV0cm8sXG4gICAgICAvL28gbWVzbW8gdmFpIHRlciBvcyB2YWxvcmVzIGRlZmF1bHRzIGFiYWl4b1xuICAgICAgZGVmYXVsdHM6IHtcbiAgICAgICAgc2NoZWR1bGVkX3RvOiBuZXcgRGF0ZSgpXG4gICAgICB9LFxuXG4gICAgICBtYXA6IHtcbiAgICAgICAgLy9jb252ZXJ0IHBhcmEgb2JqZXRvIGphdmFzY3JpcHQgZGF0ZSB1bWEgc3RyaW5nIGZvcm1hdGFkYSBjb21vIGRhdGFcbiAgICAgICAgc2NoZWR1bGVkX3RvOiBmdW5jdGlvbiBzY2hlZHVsZWRfdG8odmFsdWUpIHtcbiAgICAgICAgICByZXR1cm4gbW9tZW50KHZhbHVlKS50b0RhdGUoKTtcbiAgICAgICAgfVxuICAgICAgfSxcblxuICAgICAgYWN0aW9uczoge1xuICAgICAgICAvKipcbiAgICAgICAgICogQXR1YWxpemEgb3Mgc3RhdHVzIGRhIHRhcmVmYVxuICAgICAgICAgKlxuICAgICAgICAgKiBAcGFyYW0ge29iamVjdH0gYXR0cmlidXRlc1xuICAgICAgICAgKi9cbiAgICAgICAgdG9nZ2xlRG9uZToge1xuICAgICAgICAgIG1ldGhvZDogJ1BVVCcsXG4gICAgICAgICAgdXJsOiAndG9nZ2xlRG9uZSdcbiAgICAgICAgfVxuICAgICAgfSxcbiAgICAgIGluc3RhbmNlOiB7fVxuICAgIH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29udHJvbGxlcignVXNlcnNEaWFsb2dDb250cm9sbGVyJywgVXNlcnNEaWFsb2dDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIFVzZXJzRGlhbG9nQ29udHJvbGxlcigkY29udHJvbGxlciwgVXNlcnNTZXJ2aWNlLCBQckRpYWxvZywgLy8gTk9TT05BUlxuICB1c2VyRGlhbG9nSW5wdXQsIG9uSW5pdCkge1xuXG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIHZtLm9uQWN0aXZhdGUgPSBvbkFjdGl2YXRlO1xuICAgIHZtLmFwcGx5RmlsdGVycyA9IGFwcGx5RmlsdGVycztcbiAgICB2bS5jbG9zZSA9IGNsb3NlO1xuXG4gICAgaWYgKGFuZ3VsYXIuaXNEZWZpbmVkKHVzZXJEaWFsb2dJbnB1dCkpIHtcbiAgICAgIHZtLnRyYW5zZmVyVXNlciA9IHVzZXJEaWFsb2dJbnB1dC50cmFuc2ZlclVzZXJGbjtcbiAgICB9XG5cbiAgICAvLyBpbnN0YW50aWF0ZSBiYXNlIGNvbnRyb2xsZXJcbiAgICAkY29udHJvbGxlcignQ1JVRENvbnRyb2xsZXInLCB7XG4gICAgICB2bTogdm0sXG4gICAgICBtb2RlbFNlcnZpY2U6IFVzZXJzU2VydmljZSxcbiAgICAgIHNlYXJjaE9uSW5pdDogb25Jbml0LFxuICAgICAgb3B0aW9uczoge1xuICAgICAgICBwZXJQYWdlOiA1XG4gICAgICB9XG4gICAgfSk7XG5cbiAgICBmdW5jdGlvbiBvbkFjdGl2YXRlKCkge1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0ge307XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gYXBwbHlGaWx0ZXJzKCkge1xuICAgICAgcmV0dXJuIGFuZ3VsYXIuZXh0ZW5kKHZtLmRlZmF1bHRRdWVyeUZpbHRlcnMsIHZtLnF1ZXJ5RmlsdGVycyk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gY2xvc2UoKSB7XG4gICAgICBQckRpYWxvZy5jbG9zZSgpO1xuICAgIH1cbiAgfVxufSkoKTsiLCIvKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCovXG4oZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJywgW1xuICAgICduZ0FuaW1hdGUnLFxuICAgICduZ0FyaWEnLFxuICAgICd1aS5yb3V0ZXInLFxuICAgICduZ1Byb2RlYicsXG4gICAgJ3VpLnV0aWxzLm1hc2tzJyxcbiAgICAndGV4dC1tYXNrJyxcbiAgICAnbmdNYXRlcmlhbCcsXG4gICAgJ21vZGVsRmFjdG9yeScsXG4gICAgJ21kLmRhdGEudGFibGUnLFxuICAgICduZ01hdGVyaWFsRGF0ZVBpY2tlcicsXG4gICAgJ3Bhc2NhbHByZWNodC50cmFuc2xhdGUnLFxuICAgICdhbmd1bGFyRmlsZVVwbG9hZCddKTtcbn0pKCk7XG4iLCIoZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbmZpZyhjb25maWcpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gY29uZmlnKEdsb2JhbCwgJG1kVGhlbWluZ1Byb3ZpZGVyLCAkbW9kZWxGYWN0b3J5UHJvdmlkZXIsICAvLyBOT1NPTkFSXG4gICAgJHRyYW5zbGF0ZVByb3ZpZGVyLCBtb21lbnQsICRtZEFyaWFQcm92aWRlcikge1xuXG4gICAgJHRyYW5zbGF0ZVByb3ZpZGVyXG4gICAgICAudXNlTG9hZGVyKCdsYW5ndWFnZUxvYWRlcicpXG4gICAgICAudXNlU2FuaXRpemVWYWx1ZVN0cmF0ZWd5KCdlc2NhcGUnKTtcblxuICAgICR0cmFuc2xhdGVQcm92aWRlci51c2VQb3N0Q29tcGlsaW5nKHRydWUpO1xuXG4gICAgbW9tZW50LmxvY2FsZSgncHQtQlInKTtcblxuICAgIC8vb3Mgc2VydmnDp29zIHJlZmVyZW50ZSBhb3MgbW9kZWxzIHZhaSB1dGlsaXphciBjb21vIGJhc2UgbmFzIHVybHNcbiAgICAkbW9kZWxGYWN0b3J5UHJvdmlkZXIuZGVmYXVsdE9wdGlvbnMucHJlZml4ID0gR2xvYmFsLmFwaVBhdGg7XG5cbiAgICAvLyBDb25maWd1cmF0aW9uIHRoZW1lXG4gICAgJG1kVGhlbWluZ1Byb3ZpZGVyLnRoZW1lKCdkZWZhdWx0JylcbiAgICAgIC5wcmltYXJ5UGFsZXR0ZSgnYnJvd24nLCB7XG4gICAgICAgIGRlZmF1bHQ6ICc3MDAnXG4gICAgICB9KVxuICAgICAgLmFjY2VudFBhbGV0dGUoJ2FtYmVyJylcbiAgICAgIC53YXJuUGFsZXR0ZSgnZGVlcC1vcmFuZ2UnKTtcblxuICAgIC8vIEVuYWJsZSBicm93c2VyIGNvbG9yXG4gICAgJG1kVGhlbWluZ1Byb3ZpZGVyLmVuYWJsZUJyb3dzZXJDb2xvcigpO1xuXG4gICAgJG1kQXJpYVByb3ZpZGVyLmRpc2FibGVXYXJuaW5ncygpO1xuXG4gIH1cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb250cm9sbGVyKCdBcHBDb250cm9sbGVyJywgQXBwQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvKipcbiAgICogQ29udHJvbGFkb3IgcmVzcG9uc8OhdmVsIHBvciBmdW5jaW9uYWxpZGFkZXMgcXVlIHPDo28gYWNpb25hZGFzIGVtIHF1YWxxdWVyIHRlbGEgZG8gc2lzdGVtYVxuICAgKlxuICAgKi9cbiAgZnVuY3Rpb24gQXBwQ29udHJvbGxlcigkc3RhdGUsIEF1dGgsIEdsb2JhbCkge1xuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICAvL2FubyBhdHVhbCBwYXJhIHNlciBleGliaWRvIG5vIHJvZGFww6kgZG8gc2lzdGVtYVxuICAgIHZtLmFub0F0dWFsID0gbnVsbDtcblxuICAgIHZtLmxvZ291dCAgICAgPSBsb2dvdXQ7XG4gICAgdm0uZ2V0SW1hZ2VQZXJmaWwgPSBnZXRJbWFnZVBlcmZpbDtcblxuICAgIGFjdGl2YXRlKCk7XG5cbiAgICBmdW5jdGlvbiBhY3RpdmF0ZSgpIHtcbiAgICAgIHZhciBkYXRlID0gbmV3IERhdGUoKTtcblxuICAgICAgdm0uYW5vQXR1YWwgPSBkYXRlLmdldEZ1bGxZZWFyKCk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gbG9nb3V0KCkge1xuICAgICAgQXV0aC5sb2dvdXQoKS50aGVuKGZ1bmN0aW9uKCkge1xuICAgICAgICAkc3RhdGUuZ28oR2xvYmFsLmxvZ2luU3RhdGUpO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gZ2V0SW1hZ2VQZXJmaWwoKSB7XG4gICAgICByZXR1cm4gKEF1dGguY3VycmVudFVzZXIgJiYgQXV0aC5jdXJyZW50VXNlci5pbWFnZSlcbiAgICAgICAgPyBBdXRoLmN1cnJlbnRVc2VyLmltYWdlXG4gICAgICAgIDogR2xvYmFsLmltYWdlUGF0aCArICcvbm9fYXZhdGFyLmdpZic7XG4gICAgfVxuXG4gIH1cblxufSkoKTtcbiIsIi8qZXNsaW50IGFuZ3VsYXIvZmlsZS1uYW1lOiAwLCBuby11bmRlZjogMCovXG4oZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICAvKipcbiAgICogVHJhbnNmb3JtYSBiaWJsaW90ZWNhcyBleHRlcm5hcyBlbSBzZXJ2acOnb3MgZG8gYW5ndWxhciBwYXJhIHNlciBwb3Nzw612ZWwgdXRpbGl6YXJcbiAgICogYXRyYXbDqXMgZGEgaW5qZcOnw6NvIGRlIGRlcGVuZMOqbmNpYVxuICAgKi9cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnN0YW50KCdsb2Rhc2gnLCBfKVxuICAgIC5jb25zdGFudCgnbW9tZW50JywgbW9tZW50KTtcblxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb25zdGFudCgnR2xvYmFsJywge1xuICAgICAgYXBwTmFtZTogJ0ZyZWVsYWdpbGUnLFxuICAgICAgaG9tZVN0YXRlOiAnYXBwLnByb2plY3RzJyxcbiAgICAgIGxvZ2luVXJsOiAnYXBwL2xvZ2luJyxcbiAgICAgIGxvZ2luU3RhdGU6ICdhcHAubG9naW4nLFxuICAgICAgcmVzZXRQYXNzd29yZFN0YXRlOiAnYXBwLnBhc3N3b3JkLXJlc2V0JyxcbiAgICAgIG5vdEF1dGhvcml6ZWRTdGF0ZTogJ2FwcC5ub3QtYXV0aG9yaXplZCcsXG4gICAgICB0b2tlbktleTogJ3NlcnZlcl90b2tlbicsXG4gICAgICBjbGllbnRQYXRoOiAnY2xpZW50L2FwcCcsXG4gICAgICBhcGlQYXRoOiAnYXBpL3YxJyxcbiAgICAgIGltYWdlUGF0aDogJ2NsaWVudC9pbWFnZXMnXG4gICAgfSk7XG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCAkdXJsUm91dGVyUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyXG4gICAgICAuc3RhdGUoJ2FwcCcsIHtcbiAgICAgICAgdXJsOiAnL2FwcCcsXG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvbGF5b3V0L2FwcC5odG1sJyxcbiAgICAgICAgYWJzdHJhY3Q6IHRydWUsXG4gICAgICAgIHJlc29sdmU6IHsgLy9lbnN1cmUgbGFuZ3MgaXMgcmVhZHkgYmVmb3JlIHJlbmRlciB2aWV3XG4gICAgICAgICAgdHJhbnNsYXRlUmVhZHk6IFsnJHRyYW5zbGF0ZScsICckcScsIGZ1bmN0aW9uKCR0cmFuc2xhdGUsICRxKSB7XG4gICAgICAgICAgICB2YXIgZGVmZXJyZWQgPSAkcS5kZWZlcigpO1xuXG4gICAgICAgICAgICAkdHJhbnNsYXRlLnVzZSgncHQtQlInKS50aGVuKGZ1bmN0aW9uKCkge1xuICAgICAgICAgICAgICBkZWZlcnJlZC5yZXNvbHZlKCk7XG4gICAgICAgICAgICB9KTtcblxuICAgICAgICAgICAgcmV0dXJuIGRlZmVycmVkLnByb21pc2U7XG4gICAgICAgICAgfV1cbiAgICAgICAgfVxuICAgICAgfSlcbiAgICAgIC5zdGF0ZShHbG9iYWwubm90QXV0aG9yaXplZFN0YXRlLCB7XG4gICAgICAgIHVybDogJy9hY2Vzc28tbmVnYWRvJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9sYXlvdXQvbm90LWF1dGhvcml6ZWQuaHRtbCcsXG4gICAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiBmYWxzZSB9XG4gICAgICB9KTtcblxuICAgICR1cmxSb3V0ZXJQcm92aWRlci53aGVuKCcvYXBwJywgR2xvYmFsLmxvZ2luVXJsKTtcbiAgICAkdXJsUm91dGVyUHJvdmlkZXIub3RoZXJ3aXNlKEdsb2JhbC5sb2dpblVybCk7XG4gIH1cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAucnVuKHJ1bik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBydW4oJHJvb3RTY29wZSwgJHN0YXRlLCAkc3RhdGVQYXJhbXMsIEF1dGgsIEdsb2JhbCkgeyAvLyBOT1NPTkFSXG4gICAgLy9zZXRhZG8gbm8gcm9vdFNjb3BlIHBhcmEgcG9kZXIgc2VyIGFjZXNzYWRvIG5hcyB2aWV3cyBzZW0gcHJlZml4byBkZSBjb250cm9sbGVyXG4gICAgJHJvb3RTY29wZS4kc3RhdGUgPSAkc3RhdGU7XG4gICAgJHJvb3RTY29wZS4kc3RhdGVQYXJhbXMgPSAkc3RhdGVQYXJhbXM7XG4gICAgJHJvb3RTY29wZS5hdXRoID0gQXV0aDtcbiAgICAkcm9vdFNjb3BlLmdsb2JhbCA9IEdsb2JhbDtcblxuICAgIC8vbm8gaW5pY2lvIGNhcnJlZ2EgbyB1c3XDoXJpbyBkbyBsb2NhbHN0b3JhZ2UgY2FzbyBvIHVzdcOhcmlvIGVzdGFqYSBhYnJpbmRvIG8gbmF2ZWdhZG9yXG4gICAgLy9wYXJhIHZvbHRhciBhdXRlbnRpY2Fkb1xuICAgIEF1dGgucmV0cmlldmVVc2VyRnJvbUxvY2FsU3RvcmFnZSgpO1xuICB9XG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29udHJvbGxlcignQXVkaXRDb250cm9sbGVyJywgQXVkaXRDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIEF1ZGl0Q29udHJvbGxlcigkY29udHJvbGxlciwgQXVkaXRTZXJ2aWNlLCBQckRpYWxvZywgR2xvYmFsLCAkdHJhbnNsYXRlKSB7IC8vIE5PU09OQVJcbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0ub25BY3RpdmF0ZSA9IG9uQWN0aXZhdGU7XG4gICAgdm0uYXBwbHlGaWx0ZXJzID0gYXBwbHlGaWx0ZXJzO1xuICAgIHZtLnZpZXdEZXRhaWwgPSB2aWV3RGV0YWlsO1xuXG4gICAgJGNvbnRyb2xsZXIoJ0NSVURDb250cm9sbGVyJywgeyB2bTogdm0sIG1vZGVsU2VydmljZTogQXVkaXRTZXJ2aWNlLCBvcHRpb25zOiB7fSB9KTtcblxuICAgIGZ1bmN0aW9uIG9uQWN0aXZhdGUoKSB7XG4gICAgICB2bS5tb2RlbHMgPSBbXTtcbiAgICAgIHZtLnF1ZXJ5RmlsdGVycyA9IHt9O1xuXG4gICAgICAvL1BlZ2EgdG9kb3Mgb3MgbW9kZWxzIGRvIHNlcnZlciBlIG1vbnRhIHVtYSBsaXN0YSBwcm8gQ29tYm9Cb3hcbiAgICAgIEF1ZGl0U2VydmljZS5nZXRBdWRpdGVkTW9kZWxzKCkudGhlbihmdW5jdGlvbihkYXRhKSB7XG4gICAgICAgIHZhciBtb2RlbHMgPSBbeyBpZDogJycsIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ2dsb2JhbC5hbGwnKSB9XTtcblxuICAgICAgICBkYXRhLm1vZGVscy5zb3J0KCk7XG5cbiAgICAgICAgZm9yICh2YXIgaW5kZXggPSAwOyBpbmRleCA8IGRhdGEubW9kZWxzLmxlbmd0aDsgaW5kZXgrKykge1xuICAgICAgICAgIHZhciBtb2RlbCA9IGRhdGEubW9kZWxzW2luZGV4XTtcblxuICAgICAgICAgIG1vZGVscy5wdXNoKHtcbiAgICAgICAgICAgIGlkOiBtb2RlbCxcbiAgICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ21vZGVscy4nICsgbW9kZWwudG9Mb3dlckNhc2UoKSlcbiAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHZtLm1vZGVscyA9IG1vZGVscztcbiAgICAgICAgdm0ucXVlcnlGaWx0ZXJzLm1vZGVsID0gdm0ubW9kZWxzWzBdLmlkO1xuICAgICAgfSk7XG5cbiAgICAgIHZtLnR5cGVzID0gQXVkaXRTZXJ2aWNlLmxpc3RUeXBlcygpO1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzLnR5cGUgPSB2bS50eXBlc1swXS5pZDtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBhcHBseUZpbHRlcnMoZGVmYXVsdFF1ZXJ5RmlsdGVycykge1xuICAgICAgcmV0dXJuIGFuZ3VsYXIuZXh0ZW5kKGRlZmF1bHRRdWVyeUZpbHRlcnMsIHZtLnF1ZXJ5RmlsdGVycyk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gdmlld0RldGFpbChhdWRpdERldGFpbCkge1xuICAgICAgdmFyIGNvbmZpZyA9IHtcbiAgICAgICAgbG9jYWxzOiB7IGF1ZGl0RGV0YWlsOiBhdWRpdERldGFpbCB9LFxuICAgICAgICAvKiogQG5nSW5qZWN0ICovXG4gICAgICAgIGNvbnRyb2xsZXI6IGZ1bmN0aW9uKGF1ZGl0RGV0YWlsLCBQckRpYWxvZykge1xuICAgICAgICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICAgICAgICB2bS5jbG9zZSA9IGNsb3NlO1xuXG4gICAgICAgICAgYWN0aXZhdGUoKTtcblxuICAgICAgICAgIGZ1bmN0aW9uIGFjdGl2YXRlKCkge1xuICAgICAgICAgICAgaWYgKGFuZ3VsYXIuaXNBcnJheShhdWRpdERldGFpbC5vbGQpICYmIGF1ZGl0RGV0YWlsLm9sZC5sZW5ndGggPT09IDApIGF1ZGl0RGV0YWlsLm9sZCA9IG51bGw7XG4gICAgICAgICAgICBpZiAoYW5ndWxhci5pc0FycmF5KGF1ZGl0RGV0YWlsLm5ldykgJiYgYXVkaXREZXRhaWwubmV3Lmxlbmd0aCA9PT0gMCkgYXVkaXREZXRhaWwubmV3ID0gbnVsbDtcblxuICAgICAgICAgICAgdm0uYXVkaXREZXRhaWwgPSBhdWRpdERldGFpbDtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICBmdW5jdGlvbiBjbG9zZSgpIHtcbiAgICAgICAgICAgIFByRGlhbG9nLmNsb3NlKCk7XG4gICAgICAgICAgfVxuXG4gICAgICAgIH0sXG4gICAgICAgIGNvbnRyb2xsZXJBczogJ2F1ZGl0RGV0YWlsQ3RybCcsXG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvYXVkaXQvYXVkaXQtZGV0YWlsLmh0bWwnLFxuICAgICAgICBoYXNCYWNrZHJvcDogdHJ1ZVxuICAgICAgfTtcblxuICAgICAgUHJEaWFsb2cuY3VzdG9tKGNvbmZpZyk7XG4gICAgfVxuXG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb25maWcocm91dGVzKTtcblxuICAvKipcbiAgICogQXJxdWl2byBkZSBjb25maWd1cmHDp8OjbyBjb20gYXMgcm90YXMgZXNwZWPDrWZpY2FzIGRlIGF1ZGl0b3JpYVxuICAgKlxuICAgKiBAcGFyYW0ge2FueX0gJHN0YXRlUHJvdmlkZXJcbiAgICogQHBhcmFtIHthbnl9IEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyXG4gICAgICAuc3RhdGUoJ2FwcC5hdWRpdCcsIHtcbiAgICAgICAgdXJsOiAnL2F1ZGl0b3JpYScsXG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvYXVkaXQvYXVkaXQuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdBdWRpdENvbnRyb2xsZXIgYXMgYXVkaXRDdHJsJyxcbiAgICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IHRydWUsIG5lZWRQcm9maWxlOiBbJ2FkbWluJ10gfVxuICAgICAgfSk7XG5cbiAgfVxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5mYWN0b3J5KCdBdWRpdFNlcnZpY2UnLCBBdWRpdFNlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gQXVkaXRTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5LCAkdHJhbnNsYXRlKSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCdhdWRpdCcsIHtcbiAgICAgIGFjdGlvbnM6IHtcbiAgICAgICAgZ2V0QXVkaXRlZE1vZGVsczoge1xuICAgICAgICAgIG1ldGhvZDogJ0dFVCcsXG4gICAgICAgICAgdXJsOiAnbW9kZWxzJ1xuICAgICAgICB9XG4gICAgICB9LFxuICAgICAgaW5zdGFuY2U6IHtcbiAgICAgIH0sXG4gICAgICBsaXN0VHlwZXM6IGZ1bmN0aW9uKCkge1xuICAgICAgICB2YXIgYXVkaXRQYXRoID0gJ3ZpZXdzLmZpZWxkcy5hdWRpdC4nO1xuXG4gICAgICAgIHJldHVybiBbXG4gICAgICAgICAgeyBpZDogJycsIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoYXVkaXRQYXRoICsgJ2FsbFJlc291cmNlcycpIH0sXG4gICAgICAgICAgeyBpZDogJ2NyZWF0ZWQnLCBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KGF1ZGl0UGF0aCArICd0eXBlLmNyZWF0ZWQnKSB9LFxuICAgICAgICAgIHsgaWQ6ICd1cGRhdGVkJywgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudChhdWRpdFBhdGggKyAndHlwZS51cGRhdGVkJykgfSxcbiAgICAgICAgICB7IGlkOiAnZGVsZXRlZCcsIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoYXVkaXRQYXRoICsgJ3R5cGUuZGVsZXRlZCcpIH1cbiAgICAgICAgXTtcbiAgICAgIH1cbiAgICB9KTtcbiAgfVxuXG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKlxuICAgKiBBcnF1aXZvIGRlIGNvbmZpZ3VyYcOnw6NvIGNvbSBhcyByb3RhcyBlc3BlY8OtZmljYXMgZG8gcmVjdXJzbyB1c2VyXG4gICAqXG4gICAqIEBwYXJhbSB7YW55fSAkc3RhdGVQcm92aWRlclxuICAgKiBAcGFyYW0ge2FueX0gR2xvYmFsXG4gICAqL1xuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvdXRlcygkc3RhdGVQcm92aWRlciwgR2xvYmFsKSB7XG4gICAgJHN0YXRlUHJvdmlkZXJcbiAgICAgIC5zdGF0ZShHbG9iYWwucmVzZXRQYXNzd29yZFN0YXRlLCB7XG4gICAgICAgIHVybDogJy9wYXNzd29yZC9yZXNldC86dG9rZW4nLFxuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL2F1dGgvcmVzZXQtcGFzcy1mb3JtLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnUGFzc3dvcmRDb250cm9sbGVyIGFzIHBhc3NDdHJsJyxcbiAgICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IGZhbHNlIH1cbiAgICAgIH0pXG4gICAgICAuc3RhdGUoR2xvYmFsLmxvZ2luU3RhdGUsIHtcbiAgICAgICAgdXJsOiAnL2xvZ2luJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9hdXRoL2xvZ2luLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnTG9naW5Db250cm9sbGVyIGFzIGxvZ2luQ3RybCcsXG4gICAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiBmYWxzZSB9XG4gICAgICB9KTtcblxuICB9XG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZhY3RvcnkoJ0F1dGgnLCBBdXRoKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIEF1dGgoJGh0dHAsICRxLCBHbG9iYWwsIFVzZXJzU2VydmljZSkgeyAvLyBOT1NPTkFSXG4gICAgdmFyIGF1dGggPSB7XG4gICAgICBsb2dpbjogbG9naW4sXG4gICAgICBsb2dvdXQ6IGxvZ291dCxcbiAgICAgIHVwZGF0ZUN1cnJlbnRVc2VyOiB1cGRhdGVDdXJyZW50VXNlcixcbiAgICAgIHJldHJpZXZlVXNlckZyb21Mb2NhbFN0b3JhZ2U6IHJldHJpZXZlVXNlckZyb21Mb2NhbFN0b3JhZ2UsXG4gICAgICBhdXRoZW50aWNhdGVkOiBhdXRoZW50aWNhdGVkLFxuICAgICAgc2VuZEVtYWlsUmVzZXRQYXNzd29yZDogc2VuZEVtYWlsUmVzZXRQYXNzd29yZCxcbiAgICAgIHJlbW90ZVZhbGlkYXRlVG9rZW46IHJlbW90ZVZhbGlkYXRlVG9rZW4sXG4gICAgICBnZXRUb2tlbjogZ2V0VG9rZW4sXG4gICAgICBzZXRUb2tlbjogc2V0VG9rZW4sXG4gICAgICBjbGVhclRva2VuOiBjbGVhclRva2VuLFxuICAgICAgY3VycmVudFVzZXI6IG51bGxcbiAgICB9O1xuXG4gICAgZnVuY3Rpb24gY2xlYXJUb2tlbigpIHtcbiAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKEdsb2JhbC50b2tlbktleSk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gc2V0VG9rZW4odG9rZW4pIHtcbiAgICAgIGxvY2FsU3RvcmFnZS5zZXRJdGVtKEdsb2JhbC50b2tlbktleSwgdG9rZW4pO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGdldFRva2VuKCkge1xuICAgICAgcmV0dXJuIGxvY2FsU3RvcmFnZS5nZXRJdGVtKEdsb2JhbC50b2tlbktleSk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gcmVtb3RlVmFsaWRhdGVUb2tlbigpIHtcbiAgICAgIHZhciBkZWZlcnJlZCA9ICRxLmRlZmVyKCk7XG5cbiAgICAgIGlmIChhdXRoLmF1dGhlbnRpY2F0ZWQoKSkge1xuICAgICAgICAkaHR0cC5nZXQoR2xvYmFsLmFwaVBhdGggKyAnL2F1dGhlbnRpY2F0ZS9jaGVjaycpXG4gICAgICAgICAgLnRoZW4oZnVuY3Rpb24oKSB7XG4gICAgICAgICAgICBkZWZlcnJlZC5yZXNvbHZlKHRydWUpO1xuICAgICAgICAgIH0sIGZ1bmN0aW9uKCkge1xuICAgICAgICAgICAgYXV0aC5sb2dvdXQoKTtcblxuICAgICAgICAgICAgZGVmZXJyZWQucmVqZWN0KGZhbHNlKTtcbiAgICAgICAgICB9KTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIGF1dGgubG9nb3V0KCk7XG5cbiAgICAgICAgZGVmZXJyZWQucmVqZWN0KGZhbHNlKTtcbiAgICAgIH1cblxuICAgICAgcmV0dXJuIGRlZmVycmVkLnByb21pc2U7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogVmVyaWZpY2Egc2UgbyB1c3XDoXJpbyBlc3TDoSBhdXRlbnRpY2Fkb1xuICAgICAqXG4gICAgICogQHJldHVybnMge2Jvb2xlYW59XG4gICAgICovXG4gICAgZnVuY3Rpb24gYXV0aGVudGljYXRlZCgpIHtcbiAgICAgIHJldHVybiBhdXRoLmdldFRva2VuKCkgIT09IG51bGxcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWN1cGVyYSBvIHVzdcOhcmlvIGRvIGxvY2FsU3RvcmFnZVxuICAgICAqL1xuICAgIGZ1bmN0aW9uIHJldHJpZXZlVXNlckZyb21Mb2NhbFN0b3JhZ2UoKSB7XG4gICAgICB2YXIgdXNlciA9IGxvY2FsU3RvcmFnZS5nZXRJdGVtKCd1c2VyJyk7XG5cbiAgICAgIGlmICh1c2VyKSB7XG4gICAgICAgIGF1dGguY3VycmVudFVzZXIgPSBhbmd1bGFyLm1lcmdlKG5ldyBVc2Vyc1NlcnZpY2UoKSwgYW5ndWxhci5mcm9tSnNvbih1c2VyKSk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogR3VhcmRhIG8gdXN1w6FyaW8gbm8gbG9jYWxTdG9yYWdlIHBhcmEgY2FzbyBvIHVzdcOhcmlvIGZlY2hlIGUgYWJyYSBvIG5hdmVnYWRvclxuICAgICAqIGRlbnRybyBkbyB0ZW1wbyBkZSBzZXNzw6NvIHNlamEgcG9zc8OtdmVsIHJlY3VwZXJhciBvIHRva2VuIGF1dGVudGljYWRvLlxuICAgICAqXG4gICAgICogTWFudMOpbSBhIHZhcmnDoXZlbCBhdXRoLmN1cnJlbnRVc2VyIHBhcmEgZmFjaWxpdGFyIG8gYWNlc3NvIGFvIHVzdcOhcmlvIGxvZ2FkbyBlbSB0b2RhIGEgYXBsaWNhw6fDo29cbiAgICAgKlxuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IHVzZXIgVXN1w6FyaW8gYSBzZXIgYXR1YWxpemFkby4gQ2FzbyBzZWphIHBhc3NhZG8gbnVsbCBsaW1wYVxuICAgICAqIHRvZGFzIGFzIGluZm9ybWHDp8O1ZXMgZG8gdXN1w6FyaW8gY29ycmVudGUuXG4gICAgICovXG4gICAgZnVuY3Rpb24gdXBkYXRlQ3VycmVudFVzZXIodXNlcikge1xuICAgICAgdmFyIGRlZmVycmVkID0gJHEuZGVmZXIoKTtcblxuICAgICAgaWYgKHVzZXIpIHtcbiAgICAgICAgdXNlciA9IGFuZ3VsYXIubWVyZ2UobmV3IFVzZXJzU2VydmljZSgpLCB1c2VyKTtcblxuICAgICAgICB2YXIganNvblVzZXIgPSBhbmd1bGFyLnRvSnNvbih1c2VyKTtcblxuICAgICAgICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbSgndXNlcicsIGpzb25Vc2VyKTtcbiAgICAgICAgYXV0aC5jdXJyZW50VXNlciA9IHVzZXI7XG5cbiAgICAgICAgZGVmZXJyZWQucmVzb2x2ZSh1c2VyKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKCd1c2VyJyk7XG4gICAgICAgIGF1dGguY3VycmVudFVzZXIgPSBudWxsO1xuICAgICAgICBhdXRoLmNsZWFyVG9rZW4oKTtcblxuICAgICAgICBkZWZlcnJlZC5yZWplY3QoKTtcbiAgICAgIH1cblxuICAgICAgcmV0dXJuIGRlZmVycmVkLnByb21pc2U7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhbGl6YSBvIGxvZ2luIGRvIHVzdcOhcmlvXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gY3JlZGVudGlhbHMgRW1haWwgZSBTZW5oYSBkbyB1c3XDoXJpb1xuICAgICAqIEByZXR1cm5zIHtwcm9taXNlfSBVbWEgcHJvbWlzZSBjb20gbyByZXN1bHRhZG8gZG8gY2hhbWFkYSBubyBiYWNrZW5kXG4gICAgICovXG4gICAgZnVuY3Rpb24gbG9naW4oY3JlZGVudGlhbHMpIHtcbiAgICAgIHZhciBkZWZlcnJlZCA9ICRxLmRlZmVyKCk7XG5cbiAgICAgICRodHRwLnBvc3QoR2xvYmFsLmFwaVBhdGggKyAnL2F1dGhlbnRpY2F0ZScsIGNyZWRlbnRpYWxzKVxuICAgICAgICAudGhlbihmdW5jdGlvbihyZXNwb25zZSkge1xuICAgICAgICAgIGF1dGguc2V0VG9rZW4ocmVzcG9uc2UuZGF0YS50b2tlbik7XG5cbiAgICAgICAgICByZXR1cm4gJGh0dHAuZ2V0KEdsb2JhbC5hcGlQYXRoICsgJy9hdXRoZW50aWNhdGUvdXNlcicpO1xuICAgICAgICB9KVxuICAgICAgICAudGhlbihmdW5jdGlvbihyZXNwb25zZSkge1xuICAgICAgICAgIGF1dGgudXBkYXRlQ3VycmVudFVzZXIocmVzcG9uc2UuZGF0YS51c2VyKTtcblxuICAgICAgICAgIGRlZmVycmVkLnJlc29sdmUoKTtcbiAgICAgICAgfSwgZnVuY3Rpb24oZXJyb3IpIHtcbiAgICAgICAgICBhdXRoLmxvZ291dCgpO1xuXG4gICAgICAgICAgZGVmZXJyZWQucmVqZWN0KGVycm9yKTtcbiAgICAgICAgfSk7XG5cbiAgICAgIHJldHVybiBkZWZlcnJlZC5wcm9taXNlO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIERlc2xvZ2Egb3MgdXN1w6FyaW9zLiBDb21vIG7Do28gdGVuIG5lbmh1bWEgaW5mb3JtYcOnw6NvIG5hIHNlc3PDo28gZG8gc2Vydmlkb3JcbiAgICAgKiBlIHVtIHRva2VuIHVtYSB2ZXogZ2VyYWRvIG7Do28gcG9kZSwgcG9yIHBhZHLDo28sIHNlciBpbnZhbGlkYWRvIGFudGVzIGRvIHNldSB0ZW1wbyBkZSBleHBpcmHDp8OjbyxcbiAgICAgKiBzb21lbnRlIGFwYWdhbW9zIG9zIGRhZG9zIGRvIHVzdcOhcmlvIGUgbyB0b2tlbiBkbyBuYXZlZ2Fkb3IgcGFyYSBlZmV0aXZhciBvIGxvZ291dC5cbiAgICAgKlxuICAgICAqIEByZXR1cm5zIHtwcm9taXNlfSBVbWEgcHJvbWlzZSBjb20gbyByZXN1bHRhZG8gZGEgb3BlcmHDp8Ojb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGxvZ291dCgpIHtcbiAgICAgIHZhciBkZWZlcnJlZCA9ICRxLmRlZmVyKCk7XG5cbiAgICAgIGF1dGgudXBkYXRlQ3VycmVudFVzZXIobnVsbCk7XG4gICAgICBkZWZlcnJlZC5yZXNvbHZlKCk7XG5cbiAgICAgIHJldHVybiBkZWZlcnJlZC5wcm9taXNlO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEVudmlhIHVtIGVtYWlsIHBhcmEgcmVjdXBlcmHDp8OjbyBkZSBzZW5oYVxuICAgICAqIEBwYXJhbSB7T2JqZWN0fSByZXNldERhdGEgLSBPYmpldG8gY29udGVuZG8gbyBlbWFpbFxuICAgICAqIEByZXR1cm4ge1Byb21pc2V9IC0gUmV0b3JuYSB1bWEgcHJvbWlzZSBwYXJhIHNlciByZXNvbHZpZGFcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBzZW5kRW1haWxSZXNldFBhc3N3b3JkKHJlc2V0RGF0YSkge1xuICAgICAgdmFyIGRlZmVycmVkID0gJHEuZGVmZXIoKTtcblxuICAgICAgJGh0dHAucG9zdChHbG9iYWwuYXBpUGF0aCArICcvcGFzc3dvcmQvZW1haWwnLCByZXNldERhdGEpXG4gICAgICAgIC50aGVuKGZ1bmN0aW9uKHJlc3BvbnNlKSB7XG4gICAgICAgICAgZGVmZXJyZWQucmVzb2x2ZShyZXNwb25zZS5kYXRhKTtcbiAgICAgICAgfSwgZnVuY3Rpb24oZXJyb3IpIHtcbiAgICAgICAgICBkZWZlcnJlZC5yZWplY3QoZXJyb3IpO1xuICAgICAgICB9KTtcblxuICAgICAgcmV0dXJuIGRlZmVycmVkLnByb21pc2U7XG4gICAgfVxuXG4gICAgcmV0dXJuIGF1dGg7XG4gIH1cblxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnRyb2xsZXIoJ0xvZ2luQ29udHJvbGxlcicsIExvZ2luQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBMb2dpbkNvbnRyb2xsZXIoJHN0YXRlLCBBdXRoLCBHbG9iYWwsIFByRGlhbG9nKSB7XG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIHZtLmxvZ2luID0gbG9naW47XG4gICAgdm0ub3BlbkRpYWxvZ1Jlc2V0UGFzcyA9IG9wZW5EaWFsb2dSZXNldFBhc3M7XG4gICAgdm0ub3BlbkRpYWxvZ1NpZ25VcCA9IG9wZW5EaWFsb2dTaWduVXA7XG5cbiAgICBhY3RpdmF0ZSgpO1xuXG4gICAgZnVuY3Rpb24gYWN0aXZhdGUoKSB7XG4gICAgICB2bS5jcmVkZW50aWFscyA9IHt9O1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGxvZ2luKCkge1xuICAgICAgdmFyIGNyZWRlbnRpYWxzID0ge1xuICAgICAgICBlbWFpbDogdm0uY3JlZGVudGlhbHMuZW1haWwsXG4gICAgICAgIHBhc3N3b3JkOiB2bS5jcmVkZW50aWFscy5wYXNzd29yZFxuICAgICAgfTtcblxuICAgICAgQXV0aC5sb2dpbihjcmVkZW50aWFscykudGhlbihmdW5jdGlvbigpIHtcbiAgICAgICAgJHN0YXRlLmdvKEdsb2JhbC5ob21lU3RhdGUpO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogRXhpYmUgbyBkaWFsb2cgcGFyYSByZWN1cGVyYcOnw6NvIGRlIHNlbmhhXG4gICAgICovXG4gICAgZnVuY3Rpb24gb3BlbkRpYWxvZ1Jlc2V0UGFzcygpIHtcbiAgICAgIHZhciBjb25maWcgPSB7XG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvYXV0aC9zZW5kLXJlc2V0LWRpYWxvZy5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ1Bhc3N3b3JkQ29udHJvbGxlciBhcyBwYXNzQ3RybCcsXG4gICAgICAgIGhhc0JhY2tkcm9wOiB0cnVlXG4gICAgICB9XG5cbiAgICAgIFByRGlhbG9nLmN1c3RvbShjb25maWcpO1xuICAgIH1cbiAgICAvKipcbiAgICAgKiBFeGliZSBvIGRpYWxvZyBwYXJhIHJlY3VwZXJhw6fDo28gZGUgc2VuaGFcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBvcGVuRGlhbG9nU2lnblVwKCkge1xuICAgICAgdmFyIGNvbmZpZyA9IHtcbiAgICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy91c2Vycy91c2VyLWZvcm0uaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdVc2Vyc0NvbnRyb2xsZXIgYXMgdXNlcnNDdHJsJyxcbiAgICAgICAgaGFzQmFja2Ryb3A6IHRydWVcbiAgICAgIH1cblxuICAgICAgUHJEaWFsb2cuY3VzdG9tKGNvbmZpZyk7XG4gICAgfVxuXG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb250cm9sbGVyKCdQYXNzd29yZENvbnRyb2xsZXInLCBQYXNzd29yZENvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gUGFzc3dvcmRDb250cm9sbGVyKEdsb2JhbCwgJHN0YXRlUGFyYW1zLCAkaHR0cCwgJHRpbWVvdXQsICRzdGF0ZSwgLy8gTk9TT05BUlxuICAgIFByVG9hc3QsIFByRGlhbG9nLCBBdXRoLCAkdHJhbnNsYXRlKSB7XG5cbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0uc2VuZFJlc2V0ID0gc2VuZFJlc2V0O1xuICAgIHZtLmNsb3NlRGlhbG9nID0gY2xvc2VEaWFsb2c7XG4gICAgdm0uY2xlYW5Gb3JtID0gY2xlYW5Gb3JtO1xuICAgIHZtLnNlbmRFbWFpbFJlc2V0UGFzc3dvcmQgPSBzZW5kRW1haWxSZXNldFBhc3N3b3JkO1xuXG4gICAgYWN0aXZhdGUoKTtcblxuICAgIGZ1bmN0aW9uIGFjdGl2YXRlKCkge1xuICAgICAgdm0ucmVzZXQgPSB7IGVtYWlsOiAnJywgdG9rZW46ICRzdGF0ZVBhcmFtcy50b2tlbiB9O1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWxpemEgYSBhbHRlcmHDp8OjbyBkYSBzZW5oYSBkbyB1c3XDoXJpbyBlIG8gcmVkaXJlY2lvbmEgcGFyYSBhIHRlbGEgZGUgbG9naW5cbiAgICAgKi9cbiAgICBmdW5jdGlvbiBzZW5kUmVzZXQoKSB7XG4gICAgICAkaHR0cC5wb3N0KEdsb2JhbC5hcGlQYXRoICsgJy9wYXNzd29yZC9yZXNldCcsIHZtLnJlc2V0KVxuICAgICAgICAudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgUHJUb2FzdC5zdWNjZXNzKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMub3BlcmF0aW9uU3VjY2VzcycpKTtcbiAgICAgICAgICAkdGltZW91dChmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAkc3RhdGUuZ28oR2xvYmFsLmxvZ2luU3RhdGUpO1xuICAgICAgICAgIH0sIDE1MDApO1xuICAgICAgICB9LCBmdW5jdGlvbiAoZXJyb3IpIHtcbiAgICAgICAgICBpZiAoZXJyb3Iuc3RhdHVzICE9PSA0MDAgJiYgZXJyb3Iuc3RhdHVzICE9PSA1MDApIHtcbiAgICAgICAgICAgIHZhciBtc2cgPSAnJztcblxuICAgICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCBlcnJvci5kYXRhLnBhc3N3b3JkLmxlbmd0aDsgaSsrKSB7XG4gICAgICAgICAgICAgIG1zZyArPSBlcnJvci5kYXRhLnBhc3N3b3JkW2ldICsgJzxicj4nO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgUHJUb2FzdC5lcnJvcihtc2cudG9VcHBlckNhc2UoKSk7XG4gICAgICAgICAgfVxuICAgICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBFbnZpYSB1bSBlbWFpbCBkZSByZWN1cGVyYcOnw6NvIGRlIHNlbmhhIGNvbSBvIHRva2VuIGRvIHVzdcOhcmlvXG4gICAgICovXG4gICAgZnVuY3Rpb24gc2VuZEVtYWlsUmVzZXRQYXNzd29yZCgpIHtcblxuICAgICAgaWYgKHZtLnJlc2V0LmVtYWlsID09PSAnJykge1xuICAgICAgICBQclRvYXN0LmVycm9yKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMudmFsaWRhdGUuZmllbGRSZXF1aXJlZCcsIHsgZmllbGQ6ICdlbWFpbCcgfSkpO1xuICAgICAgICByZXR1cm47XG4gICAgICB9XG5cbiAgICAgIEF1dGguc2VuZEVtYWlsUmVzZXRQYXNzd29yZCh2bS5yZXNldCkudGhlbihmdW5jdGlvbiAoZGF0YSkge1xuICAgICAgICBQclRvYXN0LnN1Y2Nlc3MoZGF0YS5tZXNzYWdlKTtcblxuICAgICAgICB2bS5jbGVhbkZvcm0oKTtcbiAgICAgICAgdm0uY2xvc2VEaWFsb2coKTtcbiAgICAgIH0sIGZ1bmN0aW9uIChlcnJvcikge1xuICAgICAgICBpZiAoZXJyb3IuZGF0YS5lbWFpbCAmJiBlcnJvci5kYXRhLmVtYWlsLmxlbmd0aCA+IDApIHtcbiAgICAgICAgICB2YXIgbXNnID0gJyc7XG5cbiAgICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IGVycm9yLmRhdGEuZW1haWwubGVuZ3RoOyBpKyspIHtcbiAgICAgICAgICAgIG1zZyArPSBlcnJvci5kYXRhLmVtYWlsW2ldICsgJzxicj4nO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIFByVG9hc3QuZXJyb3IobXNnKTtcbiAgICAgICAgfVxuICAgICAgfSk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gY2xvc2VEaWFsb2coKSB7XG4gICAgICBQckRpYWxvZy5jbG9zZSgpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGNsZWFuRm9ybSgpIHtcbiAgICAgIHZtLnJlc2V0LmVtYWlsID0gJyc7XG4gICAgfVxuXG4gIH1cblxufSkoKTtcbiIsIi8qZXNsaW50IGFuZ3VsYXIvZmlsZS1uYW1lOiAwKi9cbihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5mYWN0b3J5KCdzZXJ2aWNlRmFjdG9yeScsIHNlcnZpY2VGYWN0b3J5KTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8qKlxuICAgKiBNYWlzIGluZm9ybWHDp8O1ZXM6XG4gICAqIGh0dHBzOi8vZ2l0aHViLmNvbS9zd2ltbGFuZS9hbmd1bGFyLW1vZGVsLWZhY3Rvcnkvd2lraS9BUElcbiAgICovXG4gIGZ1bmN0aW9uIHNlcnZpY2VGYWN0b3J5KCRtb2RlbEZhY3RvcnkpIHtcbiAgICByZXR1cm4gZnVuY3Rpb24odXJsLCBvcHRpb25zKSB7XG4gICAgICB2YXIgbW9kZWw7XG4gICAgICB2YXIgZGVmYXVsdE9wdGlvbnMgPSB7XG4gICAgICAgIGFjdGlvbnM6IHtcbiAgICAgICAgICAvKipcbiAgICAgICAgICAgKiBTZXJ2acOnbyBjb211bSBwYXJhIHJlYWxpemFyIGJ1c2NhIGNvbSBwYWdpbmHDp8Ojb1xuICAgICAgICAgICAqIE8gbWVzbW8gZXNwZXJhIHF1ZSBzZWphIHJldG9ybmFkbyB1bSBvYmpldG8gY29tIGl0ZW1zIGUgdG90YWxcbiAgICAgICAgICAgKi9cbiAgICAgICAgICBwYWdpbmF0ZToge1xuICAgICAgICAgICAgbWV0aG9kOiAnR0VUJyxcbiAgICAgICAgICAgIGlzQXJyYXk6IGZhbHNlLFxuICAgICAgICAgICAgd3JhcDogZmFsc2UsXG4gICAgICAgICAgICBhZnRlclJlcXVlc3Q6IGZ1bmN0aW9uKHJlc3BvbnNlKSB7XG4gICAgICAgICAgICAgIGlmIChyZXNwb25zZVsnaXRlbXMnXSkge1xuICAgICAgICAgICAgICAgIHJlc3BvbnNlWydpdGVtcyddID0gbW9kZWwuTGlzdChyZXNwb25zZVsnaXRlbXMnXSk7XG4gICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICByZXR1cm4gcmVzcG9uc2U7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICB9XG5cbiAgICAgIG1vZGVsID0gJG1vZGVsRmFjdG9yeSh1cmwsIGFuZ3VsYXIubWVyZ2UoZGVmYXVsdE9wdGlvbnMsIG9wdGlvbnMpKVxuXG4gICAgICByZXR1cm4gbW9kZWw7XG4gICAgfVxuICB9XG59KSgpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29udHJvbGxlcignQ1JVRENvbnRyb2xsZXInLCBDUlVEQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvKipcbiAgICogQ29udHJvbGFkb3IgQmFzZSBxdWUgaW1wbGVtZW50YSB0b2RhcyBhcyBmdW7Dp8O1ZXMgcGFkcsO1ZXMgZGUgdW0gQ1JVRFxuICAgKlxuICAgKiBBw6fDtWVzIGltcGxlbWVudGFkYXNcbiAgICogYWN0aXZhdGUoKVxuICAgKiBzZWFyY2gocGFnZSlcbiAgICogZWRpdChyZXNvdXJjZSlcbiAgICogc2F2ZSgpXG4gICAqIHJlbW92ZShyZXNvdXJjZSlcbiAgICogZ29Ubyh2aWV3TmFtZSlcbiAgICogY2xlYW5Gb3JtKClcbiAgICpcbiAgICogR2F0aWxob3NcbiAgICpcbiAgICogb25BY3RpdmF0ZSgpXG4gICAqIGFwcGx5RmlsdGVycyhkZWZhdWx0UXVlcnlGaWx0ZXJzKVxuICAgKiBiZWZvcmVTZWFyY2gocGFnZSkgLy9yZXRvcm5hbmRvIGZhbHNlIGNhbmNlbGEgbyBmbHV4b1xuICAgKiBhZnRlclNlYXJjaChyZXNwb25zZSlcbiAgICogYmVmb3JlQ2xlYW4gLy9yZXRvcm5hbmRvIGZhbHNlIGNhbmNlbGEgbyBmbHV4b1xuICAgKiBhZnRlckNsZWFuKClcbiAgICogYmVmb3JlU2F2ZSgpIC8vcmV0b3JuYW5kbyBmYWxzZSBjYW5jZWxhIG8gZmx1eG9cbiAgICogYWZ0ZXJTYXZlKHJlc291cmNlKVxuICAgKiBvblNhdmVFcnJvcihlcnJvcilcbiAgICogYmVmb3JlUmVtb3ZlKHJlc291cmNlKSAvL3JldG9ybmFuZG8gZmFsc2UgY2FuY2VsYSBvIGZsdXhvXG4gICAqIGFmdGVyUmVtb3ZlKHJlc291cmNlKVxuICAgKlxuICAgKiBAcGFyYW0ge2FueX0gdm0gaW5zdGFuY2lhIGRvIGNvbnRyb2xsZXIgZmlsaG9cbiAgICogQHBhcmFtIHthbnl9IG1vZGVsU2VydmljZSBzZXJ2acOnbyBkbyBtb2RlbCBxdWUgdmFpIHNlciB1dGlsaXphZG9cbiAgICogQHBhcmFtIHthbnl9IG9wdGlvbnMgb3DDp8O1ZXMgcGFyYSBzb2JyZWVzY3JldmVyIGNvbXBvcnRhbWVudG9zIHBhZHLDtWVzXG4gICAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBDUlVEQ29udHJvbGxlcih2bSwgbW9kZWxTZXJ2aWNlLCBvcHRpb25zLCBQclRvYXN0LCBQclBhZ2luYXRpb24sIC8vIE5PU09OQVJcbiAgICBQckRpYWxvZywgJHRyYW5zbGF0ZSkge1xuXG4gICAgLy9GdW5jdGlvbnMgQmxvY2tcbiAgICB2bS5zZWFyY2ggPSBzZWFyY2g7XG4gICAgdm0ucGFnaW5hdGVTZWFyY2ggPSBwYWdpbmF0ZVNlYXJjaDtcbiAgICB2bS5ub3JtYWxTZWFyY2ggPSBub3JtYWxTZWFyY2g7XG4gICAgdm0uZWRpdCA9IGVkaXQ7XG4gICAgdm0uc2F2ZSA9IHNhdmU7XG4gICAgdm0ucmVtb3ZlID0gcmVtb3ZlO1xuICAgIHZtLmdvVG8gPSBnb1RvO1xuICAgIHZtLmNsZWFuRm9ybSA9IGNsZWFuRm9ybTtcblxuICAgIGFjdGl2YXRlKCk7XG5cbiAgICAvKipcbiAgICAgKiBQcmVwYXJhIG8gY29udHJvbGFkb3JcbiAgICAgKiBGYXogbyBtZXJnZSBkYXMgb3DDp8O1ZXNcbiAgICAgKiBJbmljaWFsaXphIG8gcmVjdXJzb1xuICAgICAqIEluaWNpYWxpemEgbyBvYmpldG8gcGFnaW5hZG9yIGUgcmVhbGl6YSBhIHBlc3F1aXNhXG4gICAgICovXG4gICAgZnVuY3Rpb24gYWN0aXZhdGUoKSB7XG4gICAgICB2bS5kZWZhdWx0T3B0aW9ucyA9IHtcbiAgICAgICAgcmVkaXJlY3RBZnRlclNhdmU6IHRydWUsXG4gICAgICAgIHNlYXJjaE9uSW5pdDogdHJ1ZSxcbiAgICAgICAgcGVyUGFnZTogOCxcbiAgICAgICAgc2tpcFBhZ2luYXRpb246IGZhbHNlXG4gICAgICB9XG5cbiAgICAgIGFuZ3VsYXIubWVyZ2Uodm0uZGVmYXVsdE9wdGlvbnMsIG9wdGlvbnMpO1xuXG4gICAgICB2bS52aWV3Rm9ybSA9IGZhbHNlO1xuICAgICAgdm0ucmVzb3VyY2UgPSBuZXcgbW9kZWxTZXJ2aWNlKCk7XG5cbiAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0ub25BY3RpdmF0ZSkpIHZtLm9uQWN0aXZhdGUoKTtcblxuICAgICAgdm0ucGFnaW5hdG9yID0gUHJQYWdpbmF0aW9uLmdldEluc3RhbmNlKHZtLnNlYXJjaCwgdm0uZGVmYXVsdE9wdGlvbnMucGVyUGFnZSk7XG5cbiAgICAgIGlmICh2bS5kZWZhdWx0T3B0aW9ucy5zZWFyY2hPbkluaXQpIHZtLnNlYXJjaCgpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWxpemEgYSBwZXNxdWlzYVxuICAgICAqIFZlcmlmaWNhIHF1YWwgZGFzIGZ1bsOnw7VlcyBkZSBwZXNxdWlzYSBkZXZlIHNlciByZWFsaXphZGEuXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gcGFnZSBww6FnaW5hIHF1ZSBkZXZlIHNlciBjYXJyZWdhZGFcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBzZWFyY2gocGFnZSkge1xuICAgICAgKHZtLmRlZmF1bHRPcHRpb25zLnNraXBQYWdpbmF0aW9uKSA/IG5vcm1hbFNlYXJjaCgpIDogcGFnaW5hdGVTZWFyY2gocGFnZSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhbGl6YSBhIHBlc3F1aXNhIHBhZ2luYWRhIGNvbSBiYXNlIG5vcyBmaWx0cm9zIGRlZmluaWRvc1xuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IHBhZ2UgcMOhZ2luYSBxdWUgZGV2ZSBzZXIgY2FycmVnYWRhXG4gICAgICovXG4gICAgZnVuY3Rpb24gcGFnaW5hdGVTZWFyY2gocGFnZSkge1xuICAgICAgdm0ucGFnaW5hdG9yLmN1cnJlbnRQYWdlID0gKGFuZ3VsYXIuaXNEZWZpbmVkKHBhZ2UpKSA/IHBhZ2UgOiAxO1xuICAgICAgdm0uZGVmYXVsdFF1ZXJ5RmlsdGVycyA9IHsgcGFnZTogdm0ucGFnaW5hdG9yLmN1cnJlbnRQYWdlLCBwZXJQYWdlOiB2bS5wYWdpbmF0b3IucGVyUGFnZSB9O1xuXG4gICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmFwcGx5RmlsdGVycykpIHZtLmRlZmF1bHRRdWVyeUZpbHRlcnMgPSB2bS5hcHBseUZpbHRlcnModm0uZGVmYXVsdFF1ZXJ5RmlsdGVycyk7XG4gICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmJlZm9yZVNlYXJjaCkgJiYgdm0uYmVmb3JlU2VhcmNoKHBhZ2UpID09PSBmYWxzZSkgcmV0dXJuIGZhbHNlO1xuXG4gICAgICBtb2RlbFNlcnZpY2UucGFnaW5hdGUodm0uZGVmYXVsdFF1ZXJ5RmlsdGVycykudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgdm0ucGFnaW5hdG9yLmNhbGNOdW1iZXJPZlBhZ2VzKHJlc3BvbnNlLnRvdGFsKTtcbiAgICAgICAgdm0ucmVzb3VyY2VzID0gcmVzcG9uc2UuaXRlbXM7XG5cbiAgICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5hZnRlclNlYXJjaCkpIHZtLmFmdGVyU2VhcmNoKHJlc3BvbnNlKTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWxpemEgYSBwZXNxdWlzYSBjb20gYmFzZSBub3MgZmlsdHJvcyBkZWZpbmlkb3NcbiAgICAgKlxuICAgICAqL1xuICAgIGZ1bmN0aW9uIG5vcm1hbFNlYXJjaCgpIHtcbiAgICAgIHZtLmRlZmF1bHRRdWVyeUZpbHRlcnMgPSB7IH07XG5cbiAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYXBwbHlGaWx0ZXJzKSkgdm0uZGVmYXVsdFF1ZXJ5RmlsdGVycyA9IHZtLmFwcGx5RmlsdGVycyh2bS5kZWZhdWx0UXVlcnlGaWx0ZXJzKTtcbiAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYmVmb3JlU2VhcmNoKSAmJiB2bS5iZWZvcmVTZWFyY2goKSA9PT0gZmFsc2UpIHJldHVybiBmYWxzZTtcblxuICAgICAgbW9kZWxTZXJ2aWNlLnF1ZXJ5KHZtLmRlZmF1bHRRdWVyeUZpbHRlcnMpLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgIHZtLnJlc291cmNlcyA9IHJlc3BvbnNlO1xuXG4gICAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYWZ0ZXJTZWFyY2gpKSB2bS5hZnRlclNlYXJjaChyZXNwb25zZSk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBMaW1wYSBvIGZvcm11bMOhcmlvXG4gICAgICovXG4gICAgZnVuY3Rpb24gY2xlYW5Gb3JtKGZvcm0pIHtcbiAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYmVmb3JlQ2xlYW4pICYmIHZtLmJlZm9yZUNsZWFuKCkgPT09IGZhbHNlKSByZXR1cm4gZmFsc2U7XG5cbiAgICAgIHZtLnJlc291cmNlID0gbmV3IG1vZGVsU2VydmljZSgpO1xuXG4gICAgICBpZiAoYW5ndWxhci5pc0RlZmluZWQoZm9ybSkpIHtcbiAgICAgICAgZm9ybS4kc2V0UHJpc3RpbmUoKTtcbiAgICAgICAgZm9ybS4kc2V0VW50b3VjaGVkKCk7XG4gICAgICB9XG5cbiAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYWZ0ZXJDbGVhbikpIHZtLmFmdGVyQ2xlYW4oKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDYXJyZWdhIG5vIGZvcm11bMOhcmlvIG8gcmVjdXJzbyBzZWxlY2lvbmFkbyBwYXJhIGVkacOnw6NvXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gcmVzb3VyY2UgcmVjdXJzbyBzZWxlY2lvbmFkb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGVkaXQocmVzb3VyY2UpIHtcbiAgICAgIHZtLmdvVG8oJ2Zvcm0nKTtcbiAgICAgIHZtLnJlc291cmNlID0gbmV3IGFuZ3VsYXIuY29weShyZXNvdXJjZSk7XG5cbiAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYWZ0ZXJFZGl0KSkgdm0uYWZ0ZXJFZGl0KCk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogU2FsdmEgb3UgYXR1YWxpemEgbyByZWN1cnNvIGNvcnJlbnRlIG5vIGZvcm11bMOhcmlvXG4gICAgICogTm8gY29tcG9ydGFtZW50byBwYWRyw6NvIHJlZGlyZWNpb25hIG8gdXN1w6FyaW8gcGFyYSB2aWV3IGRlIGxpc3RhZ2VtXG4gICAgICogZGVwb2lzIGRhIGV4ZWN1w6fDo29cbiAgICAgKlxuICAgICAqIEByZXR1cm5zXG4gICAgICovXG4gICAgZnVuY3Rpb24gc2F2ZShmb3JtKSB7XG4gICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmJlZm9yZVNhdmUpICYmIHZtLmJlZm9yZVNhdmUoKSA9PT0gZmFsc2UpIHJldHVybiBmYWxzZTtcblxuICAgICAgdm0ucmVzb3VyY2UuJHNhdmUoKS50aGVuKGZ1bmN0aW9uIChyZXNvdXJjZSkge1xuICAgICAgICB2bS5yZXNvdXJjZSA9IHJlc291cmNlO1xuXG4gICAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYWZ0ZXJTYXZlKSkgdm0uYWZ0ZXJTYXZlKHJlc291cmNlKTtcblxuICAgICAgICBpZiAodm0uZGVmYXVsdE9wdGlvbnMucmVkaXJlY3RBZnRlclNhdmUpIHtcbiAgICAgICAgICB2bS5jbGVhbkZvcm0oZm9ybSk7XG4gICAgICAgICAgdm0uc2VhcmNoKHZtLnBhZ2luYXRvci5jdXJyZW50UGFnZSk7XG4gICAgICAgICAgdm0uZ29UbygnbGlzdCcpO1xuICAgICAgICB9XG5cbiAgICAgICAgUHJUb2FzdC5zdWNjZXNzKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMuc2F2ZVN1Y2Nlc3MnKSk7XG5cbiAgICAgIH0sIGZ1bmN0aW9uIChyZXNwb25zZURhdGEpIHtcbiAgICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5vblNhdmVFcnJvcikpIHZtLm9uU2F2ZUVycm9yKHJlc3BvbnNlRGF0YSk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZW1vdmUgbyByZWN1cnNvIGluZm9ybWFkby5cbiAgICAgKiBBbnRlcyBleGliZSB1bSBkaWFsb2dvIGRlIGNvbmZpcm1hw6fDo29cbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSByZXNvdXJjZSByZWN1cnNvIGVzY29saGlkb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIHJlbW92ZShyZXNvdXJjZSkge1xuICAgICAgdmFyIGNvbmZpZyA9IHtcbiAgICAgICAgdGl0bGU6ICR0cmFuc2xhdGUuaW5zdGFudCgnZGlhbG9nLmNvbmZpcm1UaXRsZScpLFxuICAgICAgICBkZXNjcmlwdGlvbjogJHRyYW5zbGF0ZS5pbnN0YW50KCdkaWFsb2cuY29uZmlybURlc2NyaXB0aW9uJylcbiAgICAgIH1cblxuICAgICAgUHJEaWFsb2cuY29uZmlybShjb25maWcpLnRoZW4oZnVuY3Rpb24oKSB7XG4gICAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYmVmb3JlUmVtb3ZlKSAmJiB2bS5iZWZvcmVSZW1vdmUocmVzb3VyY2UpID09PSBmYWxzZSkgcmV0dXJuIGZhbHNlO1xuXG4gICAgICAgIHJlc291cmNlLiRkZXN0cm95KCkudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5hZnRlclJlbW92ZSkpIHZtLmFmdGVyUmVtb3ZlKHJlc291cmNlKTtcblxuICAgICAgICAgIHZtLnNlYXJjaCgpO1xuICAgICAgICAgIFByVG9hc3QuaW5mbygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnJlbW92ZVN1Y2Nlc3MnKSk7XG4gICAgICAgIH0pO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQWx0ZXJuYSBlbnRyZSBhIHZpZXcgZG8gZm9ybXVsw6FyaW8gZSBsaXN0YWdlbVxuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IHZpZXdOYW1lIG5vbWUgZGEgdmlld1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGdvVG8odmlld05hbWUpIHtcbiAgICAgIHZtLnZpZXdGb3JtID0gZmFsc2U7XG5cbiAgICAgIGlmICh2aWV3TmFtZSA9PT0gJ2Zvcm0nKSB7XG4gICAgICAgIHZtLmNsZWFuRm9ybSgpO1xuICAgICAgICB2bS52aWV3Rm9ybSA9IHRydWU7XG4gICAgICB9XG4gICAgfVxuICB9XG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqXG4gICAqIEFycXVpdm8gZGUgY29uZmlndXJhw6fDo28gY29tIGFzIHJvdGFzIGVzcGVjw61maWNhcyBkbyByZWN1cnNvIHVzZXJcbiAgICpcbiAgICogQHBhcmFtIHthbnl9ICRzdGF0ZVByb3ZpZGVyXG4gICAqIEBwYXJhbSB7YW55fSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlclxuICAgICAgLnN0YXRlKCdhcHAuZGluYW1pYy1xdWVyeScsIHtcbiAgICAgICAgdXJsOiAnL2NvbnN1bHRhcy1kaW5hbWljYXMnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL2RpbmFtaWMtcXVlcnlzL2RpbmFtaWMtcXVlcnlzLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnRGluYW1pY1F1ZXJ5c0NvbnRyb2xsZXIgYXMgZGluYW1pY1F1ZXJ5Q3RybCcsXG4gICAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiB0cnVlLCBuZWVkUHJvZmlsZTogWydhZG1pbiddIH1cbiAgICAgIH0pO1xuXG4gIH1cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmFjdG9yeSgnRGluYW1pY1F1ZXJ5U2VydmljZScsIERpbmFtaWNRdWVyeVNlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gRGluYW1pY1F1ZXJ5U2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHJldHVybiBzZXJ2aWNlRmFjdG9yeSgnZGluYW1pY1F1ZXJ5Jywge1xuICAgICAgLyoqXG4gICAgICAgKiBhw6fDo28gYWRpY2lvbmFkYSBwYXJhIHBlZ2FyIHVtYSBsaXN0YSBkZSBtb2RlbHMgZXhpc3RlbnRlcyBubyBzZXJ2aWRvclxuICAgICAgICovXG4gICAgICBhY3Rpb25zOiB7XG4gICAgICAgIGdldE1vZGVsczoge1xuICAgICAgICAgIG1ldGhvZDogJ0dFVCcsXG4gICAgICAgICAgdXJsOiAnbW9kZWxzJ1xuICAgICAgICB9XG4gICAgICB9LFxuICAgICAgaW5zdGFuY2U6IHtcbiAgICAgIH1cbiAgICB9KTtcbiAgfVxuXG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29udHJvbGxlcignRGluYW1pY1F1ZXJ5c0NvbnRyb2xsZXInLCBEaW5hbWljUXVlcnlzQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBEaW5hbWljUXVlcnlzQ29udHJvbGxlcigkY29udHJvbGxlciwgRGluYW1pY1F1ZXJ5U2VydmljZSwgbG9kYXNoLCBQclRvYXN0LCAvLyBOT1NPTkFSXG4gICAgJHRyYW5zbGF0ZSkge1xuXG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIC8vYWN0aW9uc1xuICAgIHZtLm9uQWN0aXZhdGUgPSBvbkFjdGl2YXRlO1xuICAgIHZtLmFwcGx5RmlsdGVycyA9IGFwcGx5RmlsdGVycztcbiAgICB2bS5sb2FkQXR0cmlidXRlcyA9IGxvYWRBdHRyaWJ1dGVzO1xuICAgIHZtLmxvYWRPcGVyYXRvcnMgPSBsb2FkT3BlcmF0b3JzO1xuICAgIHZtLmFkZEZpbHRlciA9IGFkZEZpbHRlcjtcbiAgICB2bS5hZnRlclNlYXJjaCA9IGFmdGVyU2VhcmNoO1xuICAgIHZtLnJ1bkZpbHRlciA9IHJ1bkZpbHRlcjtcbiAgICB2bS5lZGl0RmlsdGVyID0gZWRpdEZpbHRlcjtcbiAgICB2bS5sb2FkTW9kZWxzID0gbG9hZE1vZGVscztcbiAgICB2bS5yZW1vdmVGaWx0ZXIgPSByZW1vdmVGaWx0ZXI7XG4gICAgdm0uY2xlYXIgPSBjbGVhcjtcbiAgICB2bS5yZXN0YXJ0ID0gcmVzdGFydDtcblxuICAgIC8vaGVyZGEgbyBjb21wb3J0YW1lbnRvIGJhc2UgZG8gQ1JVRFxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHsgdm06IHZtLCBtb2RlbFNlcnZpY2U6IERpbmFtaWNRdWVyeVNlcnZpY2UsIG9wdGlvbnM6IHtcbiAgICAgIHNlYXJjaE9uSW5pdDogZmFsc2VcbiAgICB9IH0pO1xuXG4gICAgZnVuY3Rpb24gb25BY3RpdmF0ZSgpIHtcbiAgICAgIHZtLnJlc3RhcnQoKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBQcmVwYXJhIGUgYXBsaWNhIG9zIGZpbHRybyBxdWUgdsOjbyBzZXIgZW52aWFkb3MgcGFyYSBvIHNlcnZpw6dvXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gZGVmYXVsdFF1ZXJ5RmlsdGVyc1xuICAgICAqIEByZXR1cm5zXG4gICAgICovXG4gICAgZnVuY3Rpb24gYXBwbHlGaWx0ZXJzKGRlZmF1bHRRdWVyeUZpbHRlcnMpIHtcbiAgICAgIHZhciB3aGVyZSA9IHt9O1xuXG4gICAgICAvKipcbiAgICAgICAqIG8gc2VydmnDp28gZXNwZXJhIHVtIG9iamV0byBjb206XG4gICAgICAgKiAgbyBub21lIGRlIHVtIG1vZGVsXG4gICAgICAgKiAgdW1hIGxpc3RhIGRlIGZpbHRyb3NcbiAgICAgICAqL1xuICAgICAgaWYgKHZtLmFkZGVkRmlsdGVycy5sZW5ndGggPiAwKSB7XG4gICAgICAgIHZhciBhZGRlZEZpbHRlcnMgPSBhbmd1bGFyLmNvcHkodm0uYWRkZWRGaWx0ZXJzKTtcblxuICAgICAgICB3aGVyZS5tb2RlbCA9IHZtLmFkZGVkRmlsdGVyc1swXS5tb2RlbC5uYW1lO1xuXG4gICAgICAgIGZvciAodmFyIGluZGV4ID0gMDsgaW5kZXggPCBhZGRlZEZpbHRlcnMubGVuZ3RoOyBpbmRleCsrKSB7XG4gICAgICAgICAgdmFyIGZpbHRlciA9IGFkZGVkRmlsdGVyc1tpbmRleF07XG5cbiAgICAgICAgICBmaWx0ZXIubW9kZWwgPSBudWxsO1xuICAgICAgICAgIGZpbHRlci5hdHRyaWJ1dGUgPSBmaWx0ZXIuYXR0cmlidXRlLm5hbWU7XG4gICAgICAgICAgZmlsdGVyLm9wZXJhdG9yID0gZmlsdGVyLm9wZXJhdG9yLnZhbHVlO1xuICAgICAgICB9XG5cbiAgICAgICAgd2hlcmUuZmlsdGVycyA9IGFuZ3VsYXIudG9Kc29uKGFkZGVkRmlsdGVycyk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICB3aGVyZS5tb2RlbCA9IHZtLnF1ZXJ5RmlsdGVycy5tb2RlbC5uYW1lO1xuICAgICAgfVxuXG4gICAgICByZXR1cm4gYW5ndWxhci5leHRlbmQoZGVmYXVsdFF1ZXJ5RmlsdGVycywgd2hlcmUpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENhcnJlZ2EgdG9kb3Mgb3MgbW9kZWxzIGNyaWFkb3Mgbm8gc2Vydmlkb3IgY29tIHNldXMgYXRyaWJ1dG9zXG4gICAgICovXG4gICAgZnVuY3Rpb24gbG9hZE1vZGVscygpIHtcbiAgICAgIC8vUGVnYSB0b2RvcyBvcyBtb2RlbHMgZG8gc2VydmVyIGUgbW9udGEgdW1hIGxpc3RhIHBybyBDb21ib0JveFxuICAgICAgRGluYW1pY1F1ZXJ5U2VydmljZS5nZXRNb2RlbHMoKS50aGVuKGZ1bmN0aW9uKGRhdGEpIHtcbiAgICAgICAgdm0ubW9kZWxzID0gZGF0YTtcbiAgICAgICAgdm0ucXVlcnlGaWx0ZXJzLm1vZGVsID0gdm0ubW9kZWxzWzBdO1xuICAgICAgICB2bS5sb2FkQXR0cmlidXRlcygpO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ2FycmVnYSBvcyBhdHRyaWJ1dG9zIGRvIG1vZGVsIGVzY29saGlkb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGxvYWRBdHRyaWJ1dGVzKCkge1xuICAgICAgdm0uYXR0cmlidXRlcyA9IHZtLnF1ZXJ5RmlsdGVycy5tb2RlbC5hdHRyaWJ1dGVzO1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzLmF0dHJpYnV0ZSA9IHZtLmF0dHJpYnV0ZXNbMF07XG5cbiAgICAgIHZtLmxvYWRPcGVyYXRvcnMoKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDYXJyZWdhIG9zIG9wZXJhZG9yZXMgZXNwZWNpZmljb3MgcGFyYSBvIHRpcG8gZG8gYXRyaWJ1dG9cbiAgICAgKi9cbiAgICBmdW5jdGlvbiBsb2FkT3BlcmF0b3JzKCkge1xuICAgICAgdmFyIG9wZXJhdG9ycyA9IFtcbiAgICAgICAgeyB2YWx1ZTogJz0nLCBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KCd2aWV3cy5maWVsZHMucXVlcnlEaW5hbWljLm9wZXJhdG9ycy5lcXVhbHMnKSB9LFxuICAgICAgICB7IHZhbHVlOiAnPD4nLCBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KCd2aWV3cy5maWVsZHMucXVlcnlEaW5hbWljLm9wZXJhdG9ycy5kaWZlcmVudCcpIH1cbiAgICAgIF1cblxuICAgICAgaWYgKHZtLnF1ZXJ5RmlsdGVycy5hdHRyaWJ1dGUudHlwZS5pbmRleE9mKCd2YXJ5aW5nJykgIT09IC0xKSB7XG4gICAgICAgIG9wZXJhdG9ycy5wdXNoKHsgdmFsdWU6ICdoYXMnLFxuICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLmNvbnRlaW5zJykgfSk7XG4gICAgICAgIG9wZXJhdG9ycy5wdXNoKHsgdmFsdWU6ICdzdGFydFdpdGgnLFxuICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLnN0YXJ0V2l0aCcpIH0pO1xuICAgICAgICBvcGVyYXRvcnMucHVzaCh7IHZhbHVlOiAnZW5kV2l0aCcsXG4gICAgICAgICAgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudCgndmlld3MuZmllbGRzLnF1ZXJ5RGluYW1pYy5vcGVyYXRvcnMuZmluaXNoV2l0aCcpIH0pO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgb3BlcmF0b3JzLnB1c2goeyB2YWx1ZTogJz4nLFxuICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLmJpZ2dlclRoYW4nKSB9KTtcbiAgICAgICAgb3BlcmF0b3JzLnB1c2goeyB2YWx1ZTogJz49JyxcbiAgICAgICAgICBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KCd2aWV3cy5maWVsZHMucXVlcnlEaW5hbWljLm9wZXJhdG9ycy5lcXVhbHNPckJpZ2dlclRoYW4nKSB9KTtcbiAgICAgICAgb3BlcmF0b3JzLnB1c2goeyB2YWx1ZTogJzwnLFxuICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLmxlc3NUaGFuJykgfSk7XG4gICAgICAgIG9wZXJhdG9ycy5wdXNoKHsgdmFsdWU6ICc8PScsXG4gICAgICAgICAgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudCgndmlld3MuZmllbGRzLnF1ZXJ5RGluYW1pYy5vcGVyYXRvcnMuZXF1YWxzT3JMZXNzVGhhbicpIH0pO1xuICAgICAgfVxuXG4gICAgICB2bS5vcGVyYXRvcnMgPSBvcGVyYXRvcnM7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMub3BlcmF0b3IgPSB2bS5vcGVyYXRvcnNbMF07XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQWRpY2lvbmEvZWRpdGEgdW0gZmlsdHJvXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gZm9ybSBlbGVtZW50byBodG1sIGRvIGZvcm11bMOhcmlvIHBhcmEgdmFsaWRhw6fDtWVzXG4gICAgICovXG4gICAgZnVuY3Rpb24gYWRkRmlsdGVyKGZvcm0pIHtcbiAgICAgIGlmIChhbmd1bGFyLmlzVW5kZWZpbmVkKHZtLnF1ZXJ5RmlsdGVycy52YWx1ZSkgfHwgdm0ucXVlcnlGaWx0ZXJzLnZhbHVlID09PSAnJykge1xuICAgICAgICBQclRvYXN0LmVycm9yKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMudmFsaWRhdGUuZmllbGRSZXF1aXJlZCcsIHsgZmllbGQ6ICd2YWxvcicgfSkpO1xuICAgICAgICByZXR1cm47XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBpZiAodm0uaW5kZXggPCAwKSB7XG4gICAgICAgICAgdm0uYWRkZWRGaWx0ZXJzLnB1c2goYW5ndWxhci5jb3B5KHZtLnF1ZXJ5RmlsdGVycykpO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIHZtLmFkZGVkRmlsdGVyc1t2bS5pbmRleF0gPSBhbmd1bGFyLmNvcHkodm0ucXVlcnlGaWx0ZXJzKTtcbiAgICAgICAgICB2bS5pbmRleCA9IC0xO1xuICAgICAgICB9XG5cbiAgICAgICAgLy9yZWluaWNpYSBvIGZvcm11bMOhcmlvIGUgYXMgdmFsaWRhw6fDtWVzIGV4aXN0ZW50ZXNcbiAgICAgICAgdm0ucXVlcnlGaWx0ZXJzID0ge307XG4gICAgICAgIGZvcm0uJHNldFByaXN0aW5lKCk7XG4gICAgICAgIGZvcm0uJHNldFVudG91Y2hlZCgpO1xuICAgICAgfVxuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWxpemEgYSBwZXNxdWlzYSB0ZW5kbyBvcyBmaWx0cm9zIGNvbW8gcGFyw6JtZXRyb3NcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBydW5GaWx0ZXIoKSB7XG4gICAgICB2bS5zZWFyY2godm0ucGFnaW5hdG9yLmN1cnJlbnRQYWdlKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBHYXRpbGhvIGFjaW9uYWRvIGRlcG9pcyBkYSBwZXNxdWlzYSByZXNwb25zw6F2ZWwgcG9yIGlkZW50aWZpY2FyIG9zIGF0cmlidXRvc1xuICAgICAqIGNvbnRpZG9zIG5vcyBlbGVtZW50b3MgcmVzdWx0YW50ZXMgZGEgYnVzY2FcbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSBkYXRhIGRhZG9zIHJlZmVyZW50ZSBhbyByZXRvcm5vIGRhIHJlcXVpc2nDp8Ojb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGFmdGVyU2VhcmNoKGRhdGEpIHtcbiAgICAgIHZhciBrZXlzID0gKGRhdGEuaXRlbXMubGVuZ3RoID4gMCkgPyBPYmplY3Qua2V5cyhkYXRhLml0ZW1zWzBdKSA6IFtdO1xuXG4gICAgICAvL3JldGlyYSB0b2RvcyBvcyBhdHJpYnV0b3MgcXVlIGNvbWXDp2FtIGNvbSAkLlxuICAgICAgLy9Fc3NlcyBhdHJpYnV0b3Mgc8OjbyBhZGljaW9uYWRvcyBwZWxvIHNlcnZpw6dvIGUgbsOjbyBkZXZlIGFwYXJlY2VyIG5hIGxpc3RhZ2VtXG4gICAgICB2bS5rZXlzID0gbG9kYXNoLmZpbHRlcihrZXlzLCBmdW5jdGlvbihrZXkpIHtcbiAgICAgICAgcmV0dXJuICFsb2Rhc2guc3RhcnRzV2l0aChrZXksICckJyk7XG4gICAgICB9KVxuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENvbG9hY2Egbm8gZm9ybXVsw6FyaW8gbyBmaWx0cm8gZXNjb2xoaWRvIHBhcmEgZWRpw6fDo29cbiAgICAgKiBAcGFyYW0ge2FueX0gJGluZGV4IGluZGljZSBubyBhcnJheSBkbyBmaWx0cm8gZXNjb2xoaWRvXG4gICAgICovXG4gICAgZnVuY3Rpb24gZWRpdEZpbHRlcigkaW5kZXgpIHtcbiAgICAgIHZtLmluZGV4ID0gJGluZGV4O1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0gdm0uYWRkZWRGaWx0ZXJzWyRpbmRleF07XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVtb3ZlIG8gZmlsdHJvIGVzY29saGlkb1xuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9ICRpbmRleCBpbmRpY2Ugbm8gYXJyYXkgZG8gZmlsdHJvIGVzY29saGlkb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIHJlbW92ZUZpbHRlcigkaW5kZXgpIHtcbiAgICAgIHZtLmFkZGVkRmlsdGVycy5zcGxpY2UoJGluZGV4KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBMaW1wYSBvIGZvcm11bMOhcmlvIGNvcnJlbnRlXG4gICAgICovXG4gICAgZnVuY3Rpb24gY2xlYXIoKSB7XG4gICAgICAvL2d1YXJkYSBvIGluZGljZSBkbyByZWdpc3RybyBxdWUgZXN0w6Egc2VuZG8gZWRpdGFkb1xuICAgICAgdm0uaW5kZXggPSAtMTtcbiAgICAgIC8vdmluY3VsYWRvIGFvcyBjYW1wb3MgZG8gZm9ybXVsw6FyaW9cbiAgICAgIHZtLnF1ZXJ5RmlsdGVycyA9IHtcbiAgICAgIH07XG5cbiAgICAgIGlmICh2bS5tb2RlbHMpIHZtLnF1ZXJ5RmlsdGVycy5tb2RlbCA9IHZtLm1vZGVsc1swXTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWluaWNpYSBhIGNvbnN0cnXDp8OjbyBkYSBxdWVyeSBsaW1wYW5kbyB0dWRvXG4gICAgICpcbiAgICAgKi9cbiAgICBmdW5jdGlvbiByZXN0YXJ0KCkge1xuICAgICAgLy9ndWFyZGEgYXRyaWJ1dG9zIGRvIHJlc3VsdGFkbyBkYSBidXNjYSBjb3JyZW50ZVxuICAgICAgdm0ua2V5cyA9IFtdO1xuXG4gICAgICAvL2d1YXJkYSBvcyBmaWx0cm9zIGFkaWNpb25hZG9zXG4gICAgICB2bS5hZGRlZEZpbHRlcnMgPSBbXTtcbiAgICAgIHZtLmNsZWFyKCk7XG4gICAgICB2bS5sb2FkTW9kZWxzKCk7XG4gICAgfVxuXG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZhY3RvcnkoJ2xhbmd1YWdlTG9hZGVyJywgTGFuZ3VhZ2VMb2FkZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gTGFuZ3VhZ2VMb2FkZXIoJHEsIFN1cHBvcnRTZXJ2aWNlLCAkbG9nLCAkaW5qZWN0b3IpIHtcbiAgICB2YXIgc2VydmljZSA9IHRoaXM7XG5cbiAgICBzZXJ2aWNlLnRyYW5zbGF0ZSA9IGZ1bmN0aW9uKGxvY2FsZSkge1xuICAgICAgcmV0dXJuIHtcbiAgICAgICAgZ2xvYmFsOiAkaW5qZWN0b3IuZ2V0KGxvY2FsZSArICcuaTE4bi5nbG9iYWwnKSxcbiAgICAgICAgdmlld3M6ICRpbmplY3Rvci5nZXQobG9jYWxlICsgJy5pMThuLnZpZXdzJyksXG4gICAgICAgIGF0dHJpYnV0ZXM6ICRpbmplY3Rvci5nZXQobG9jYWxlICsgJy5pMThuLmF0dHJpYnV0ZXMnKSxcbiAgICAgICAgZGlhbG9nOiAkaW5qZWN0b3IuZ2V0KGxvY2FsZSArICcuaTE4bi5kaWFsb2cnKSxcbiAgICAgICAgbWVzc2FnZXM6ICRpbmplY3Rvci5nZXQobG9jYWxlICsgJy5pMThuLm1lc3NhZ2VzJyksXG4gICAgICAgIG1vZGVsczogJGluamVjdG9yLmdldChsb2NhbGUgKyAnLmkxOG4ubW9kZWxzJylcbiAgICAgIH07XG4gICAgfVxuXG4gICAgLy8gcmV0dXJuIGxvYWRlckZuXG4gICAgcmV0dXJuIGZ1bmN0aW9uKG9wdGlvbnMpIHtcbiAgICAgICRsb2cuaW5mbygnQ2FycmVnYW5kbyBvIGNvbnRldWRvIGRhIGxpbmd1YWdlbSAnICsgb3B0aW9ucy5rZXkpO1xuXG4gICAgICB2YXIgZGVmZXJyZWQgPSAkcS5kZWZlcigpO1xuXG4gICAgICAvL0NhcnJlZ2EgYXMgbGFuZ3MgcXVlIHByZWNpc2FtIGUgZXN0w6NvIG5vIHNlcnZpZG9yIHBhcmEgbsOjbyBwcmVjaXNhciByZXBldGlyIGFxdWlcbiAgICAgIFN1cHBvcnRTZXJ2aWNlLmxhbmdzKCkudGhlbihmdW5jdGlvbihsYW5ncykge1xuICAgICAgICAvL01lcmdlIGNvbSBvcyBsYW5ncyBkZWZpbmlkb3Mgbm8gc2Vydmlkb3JcbiAgICAgICAgdmFyIGRhdGEgPSBhbmd1bGFyLm1lcmdlKHNlcnZpY2UudHJhbnNsYXRlKG9wdGlvbnMua2V5KSwgbGFuZ3MpO1xuXG4gICAgICAgIHJldHVybiBkZWZlcnJlZC5yZXNvbHZlKGRhdGEpO1xuICAgICAgfSwgZnVuY3Rpb24oKSB7XG4gICAgICAgIHJldHVybiBkZWZlcnJlZC5yZXNvbHZlKHNlcnZpY2UudHJhbnNsYXRlKG9wdGlvbnMua2V5KSk7XG4gICAgICB9KTtcblxuICAgICAgcmV0dXJuIGRlZmVycmVkLnByb21pc2U7XG4gICAgfVxuICB9XG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5maWx0ZXIoJ3RBdHRyJywgdEF0dHIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gdEF0dHIoJGZpbHRlcikge1xuICAgIC8qKlxuICAgICAqIEZpbHRybyBwYXJhIHRyYWR1w6fDo28gZGUgdW0gYXRyaWJ1dG8gZGUgdW0gbW9kZWxcbiAgICAgKiBcbiAgICAgKiBAcGFyYW0ge2FueX0gbmFtZSBub21lIGRvIGF0cmlidXRvXG4gICAgICogQHJldHVybnMgbyBub21lIGRvIGF0cmlidXRvIHRyYWR1emlkbyBjYXNvIGVuY29udHJlIHNlIG7Do28gbyBub21lIHBhc3NhZG8gcG9yIHBhcmFtZXRyb1xuICAgICAqLyAgICBcbiAgICByZXR1cm4gZnVuY3Rpb24obmFtZSkge1xuICAgICAgdmFyIGtleSA9ICdhdHRyaWJ1dGVzLicgKyBuYW1lO1xuICAgICAgdmFyIHRyYW5zbGF0ZSA9ICRmaWx0ZXIoJ3RyYW5zbGF0ZScpKGtleSk7XG5cbiAgICAgIHJldHVybiAodHJhbnNsYXRlID09PSBrZXkpID8gbmFtZSA6IHRyYW5zbGF0ZTtcbiAgICB9XG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZpbHRlcigndEJyZWFkY3J1bWInLCB0QnJlYWRjcnVtYik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiB0QnJlYWRjcnVtYigkZmlsdGVyKSB7XG4gICAgLyoqXG4gICAgICogRmlsdHJvIHBhcmEgdHJhZHXDp8OjbyBkbyBicmVhZGNydW1iICh0aXR1bG8gZGEgdGVsYSBjb20gcmFzdHJlaW8pXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gaWQgY2hhdmUgY29tIG8gbm9tZSBkbyBzdGF0ZSByZWZlcmVudGUgdGVsYVxuICAgICAqIEByZXR1cm5zIGEgdHJhZHXDp8OjbyBjYXNvIGVuY29udHJlIHNlIG7Do28gbyBpZCBwYXNzYWRvIHBvciBwYXJhbWV0cm9cbiAgICAgKi9cbiAgICByZXR1cm4gZnVuY3Rpb24oaWQpIHtcbiAgICAgIC8vcGVnYSBhIHNlZ3VuZGEgcGFydGUgZG8gbm9tZSBkbyBzdGF0ZSwgcmV0aXJhbmRvIGEgcGFydGUgYWJzdHJhdGEgKGFwcC4pXG4gICAgICB2YXIga2V5ID0gJ3ZpZXdzLmJyZWFkY3J1bWJzLicgKyBpZC5zcGxpdCgnLicpWzFdO1xuICAgICAgdmFyIHRyYW5zbGF0ZSA9ICRmaWx0ZXIoJ3RyYW5zbGF0ZScpKGtleSk7XG5cbiAgICAgIHJldHVybiAodHJhbnNsYXRlID09PSBrZXkpID8gaWQgOiB0cmFuc2xhdGU7XG4gICAgfVxuICB9XG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5maWx0ZXIoJ3RNb2RlbCcsIHRNb2RlbCk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiB0TW9kZWwoJGZpbHRlcikge1xuICAgIC8qKlxuICAgICAqIEZpbHRybyBwYXJhIHRyYWR1w6fDo28gZGUgdW0gYXRyaWJ1dG8gZGUgdW0gbW9kZWxcbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSBuYW1lIG5vbWUgZG8gYXRyaWJ1dG9cbiAgICAgKiBAcmV0dXJucyBvIG5vbWUgZG8gYXRyaWJ1dG8gdHJhZHV6aWRvIGNhc28gZW5jb250cmUgc2UgbsOjbyBvIG5vbWUgcGFzc2FkbyBwb3IgcGFyYW1ldHJvXG4gICAgICovXG4gICAgcmV0dXJuIGZ1bmN0aW9uKG5hbWUpIHtcbiAgICAgIHZhciBrZXkgPSAnbW9kZWxzLicgKyBuYW1lLnRvTG93ZXJDYXNlKCk7XG4gICAgICB2YXIgdHJhbnNsYXRlID0gJGZpbHRlcigndHJhbnNsYXRlJykoa2V5KTtcblxuICAgICAgcmV0dXJuICh0cmFuc2xhdGUgPT09IGtleSkgPyBuYW1lIDogdHJhbnNsYXRlO1xuICAgIH1cbiAgfVxuXG59KSgpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLnJ1bihhdXRoZW50aWNhdGlvbkxpc3RlbmVyKTtcblxuICAvKipcbiAgICogTGlzdGVuIGFsbCBzdGF0ZSAocGFnZSkgY2hhbmdlcy4gRXZlcnkgdGltZSBhIHN0YXRlIGNoYW5nZSBuZWVkIHRvIHZlcmlmeSB0aGUgdXNlciBpcyBhdXRoZW50aWNhdGVkIG9yIG5vdCB0b1xuICAgKiByZWRpcmVjdCB0byBjb3JyZWN0IHBhZ2UuIFdoZW4gYSB1c2VyIGNsb3NlIHRoZSBicm93c2VyIHdpdGhvdXQgbG9nb3V0LCB3aGVuIGhpbSByZW9wZW4gdGhlIGJyb3dzZXIgdGhpcyBldmVudFxuICAgKiByZWF1dGhlbnRpY2F0ZSB0aGUgdXNlciB3aXRoIHRoZSBwZXJzaXN0ZW50IHRva2VuIG9mIHRoZSBsb2NhbCBzdG9yYWdlLlxuICAgKlxuICAgKiBXZSBkb24ndCBjaGVjayBpZiB0aGUgdG9rZW4gaXMgZXhwaXJlZCBvciBub3QgaW4gdGhlIHBhZ2UgY2hhbmdlLCBiZWNhdXNlIGlzIGdlbmVyYXRlIGFuIHVuZWNlc3Nhcnkgb3ZlcmhlYWQuXG4gICAqIElmIHRoZSB0b2tlbiBpcyBleHBpcmVkIHdoZW4gdGhlIHVzZXIgdHJ5IHRvIGNhbGwgdGhlIGZpcnN0IGFwaSB0byBnZXQgZGF0YSwgaGltIHdpbGwgYmUgbG9nb2ZmIGFuZCByZWRpcmVjdFxuICAgKiB0byBsb2dpbiBwYWdlLlxuICAgKlxuICAgKiBAcGFyYW0gJHJvb3RTY29wZVxuICAgKiBAcGFyYW0gJHN0YXRlXG4gICAqIEBwYXJhbSAkc3RhdGVQYXJhbXNcbiAgICogQHBhcmFtIEF1dGhcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gYXV0aGVudGljYXRpb25MaXN0ZW5lcigkcm9vdFNjb3BlLCAkc3RhdGUsIEdsb2JhbCwgQXV0aCwgUHJUb2FzdCwgLy8gTk9TT05BUlxuICAgICR0cmFuc2xhdGUpIHtcblxuICAgIC8vb25seSB3aGVuIGFwcGxpY2F0aW9uIHN0YXJ0IGNoZWNrIGlmIHRoZSBleGlzdGVudCB0b2tlbiBzdGlsbCB2YWxpZFxuICAgIEF1dGgucmVtb3RlVmFsaWRhdGVUb2tlbigpLnRoZW4oZnVuY3Rpb24oKSB7XG4gICAgICAvL2lmIHRoZSB0b2tlbiBpcyB2YWxpZCBjaGVjayBpZiBleGlzdHMgdGhlIHVzZXIgYmVjYXVzZSB0aGUgYnJvd3NlciBjb3VsZCBiZSBjbG9zZWRcbiAgICAgIC8vYW5kIHRoZSB1c2VyIGRhdGEgaXNuJ3QgaW4gbWVtb3J5XG4gICAgICBpZiAoQXV0aC5jdXJyZW50VXNlciA9PT0gbnVsbCkge1xuICAgICAgICBBdXRoLnVwZGF0ZUN1cnJlbnRVc2VyKGFuZ3VsYXIuZnJvbUpzb24obG9jYWxTdG9yYWdlLmdldEl0ZW0oJ3VzZXInKSkpO1xuICAgICAgfVxuICAgIH0pO1xuXG4gICAgLy9DaGVjayBpZiB0aGUgdG9rZW4gc3RpbGwgdmFsaWQuXG4gICAgJHJvb3RTY29wZS4kb24oJyRzdGF0ZUNoYW5nZVN0YXJ0JywgZnVuY3Rpb24oZXZlbnQsIHRvU3RhdGUpIHtcbiAgICAgIGlmICh0b1N0YXRlLmRhdGEubmVlZEF1dGhlbnRpY2F0aW9uIHx8IHRvU3RhdGUuZGF0YS5uZWVkUHJvZmlsZSkge1xuICAgICAgICAvL2RvbnQgdHJhaXQgdGhlIHN1Y2Nlc3MgYmxvY2sgYmVjYXVzZSBhbHJlYWR5IGRpZCBieSB0b2tlbiBpbnRlcmNlcHRvclxuICAgICAgICBBdXRoLnJlbW90ZVZhbGlkYXRlVG9rZW4oKS5jYXRjaChmdW5jdGlvbigpIHtcbiAgICAgICAgICBQclRvYXN0Lndhcm4oJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5sb2dpbi5sb2dvdXRJbmFjdGl2ZScpKTtcblxuICAgICAgICAgIGlmICh0b1N0YXRlLm5hbWUgIT09IEdsb2JhbC5sb2dpblN0YXRlKSB7XG4gICAgICAgICAgICAkc3RhdGUuZ28oR2xvYmFsLmxvZ2luU3RhdGUpO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIGV2ZW50LnByZXZlbnREZWZhdWx0KCk7XG4gICAgICAgIH0pO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgLy9pZiB0aGUgdXNlIGlzIGF1dGhlbnRpY2F0ZWQgYW5kIG5lZWQgdG8gZW50ZXIgaW4gbG9naW4gcGFnZVxuICAgICAgICAvL2hpbSB3aWxsIGJlIHJlZGlyZWN0ZWQgdG8gaG9tZSBwYWdlXG4gICAgICAgIGlmICh0b1N0YXRlLm5hbWUgPT09IEdsb2JhbC5sb2dpblN0YXRlICYmIEF1dGguYXV0aGVudGljYXRlZCgpKSB7XG4gICAgICAgICAgJHN0YXRlLmdvKEdsb2JhbC5ob21lU3RhdGUpO1xuICAgICAgICAgIGV2ZW50LnByZXZlbnREZWZhdWx0KCk7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9KTtcbiAgfVxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5ydW4oYXV0aG9yaXphdGlvbkxpc3RlbmVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIGF1dGhvcml6YXRpb25MaXN0ZW5lcigkcm9vdFNjb3BlLCAkc3RhdGUsIEdsb2JhbCwgQXV0aCkge1xuICAgIC8qKlxuICAgICAqIEEgY2FkYSBtdWRhbsOnYSBkZSBlc3RhZG8gKFwicMOhZ2luYVwiKSB2ZXJpZmljYSBzZSBvIHVzdcOhcmlvIHRlbSBvIHBlcmZpbFxuICAgICAqIG5lY2Vzc8OhcmlvIHBhcmEgbyBhY2Vzc28gYSBtZXNtYVxuICAgICAqL1xuICAgICRyb290U2NvcGUuJG9uKCckc3RhdGVDaGFuZ2VTdGFydCcsIGZ1bmN0aW9uKGV2ZW50LCB0b1N0YXRlKSB7XG4gICAgICBpZiAodG9TdGF0ZS5kYXRhICYmIHRvU3RhdGUuZGF0YS5uZWVkQXV0aGVudGljYXRpb24gJiZcbiAgICAgICAgdG9TdGF0ZS5kYXRhLm5lZWRQcm9maWxlICYmIEF1dGguYXV0aGVudGljYXRlZCgpICYmXG4gICAgICAgICFBdXRoLmN1cnJlbnRVc2VyLmhhc1Byb2ZpbGUodG9TdGF0ZS5kYXRhLm5lZWRQcm9maWxlLCB0b1N0YXRlLmRhdGEuYWxsUHJvZmlsZXMpKSB7XG5cbiAgICAgICAgJHN0YXRlLmdvKEdsb2JhbC5ub3RBdXRob3JpemVkU3RhdGUpO1xuICAgICAgICBldmVudC5wcmV2ZW50RGVmYXVsdCgpO1xuICAgICAgfVxuXG4gICAgfSk7XG4gIH1cbn0oKSk7XG4iLCIoZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbmZpZyhzcGlubmVySW50ZXJjZXB0b3IpO1xuXG4gIGZ1bmN0aW9uIHNwaW5uZXJJbnRlcmNlcHRvcigkaHR0cFByb3ZpZGVyLCAkcHJvdmlkZSkge1xuICAgIC8qKlxuICAgICAqIEVzdGUgaW50ZXJjZXB0b3Igw6kgcmVzcG9uc8OhdmVsIHBvciBtb3N0cmFyIGUgZXNjb25kZXIgb1xuICAgICAqIGNvbXBvbmVudGUgUHJTcGlubmVyIHNlbXByZSBxdWUgdW1hIHJlcXVpc2nDp8OjbyBhamF4XG4gICAgICogaW5pY2lhciBlIGZpbmFsaXphci5cbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSAkcVxuICAgICAqIEBwYXJhbSB7YW55fSAkaW5qZWN0b3JcbiAgICAgKiBAcmV0dXJuc1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIHNob3dIaWRlU3Bpbm5lcigkcSwgJGluamVjdG9yKSB7XG4gICAgICByZXR1cm4ge1xuICAgICAgICByZXF1ZXN0OiBmdW5jdGlvbiAoY29uZmlnKSB7XG4gICAgICAgICAgJGluamVjdG9yLmdldCgnUHJTcGlubmVyJykuc2hvdygpO1xuXG4gICAgICAgICAgcmV0dXJuIGNvbmZpZztcbiAgICAgICAgfSxcblxuICAgICAgICByZXNwb25zZTogZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgICAgJGluamVjdG9yLmdldCgnUHJTcGlubmVyJykuaGlkZSgpO1xuXG4gICAgICAgICAgcmV0dXJuIHJlc3BvbnNlO1xuICAgICAgICB9LFxuXG4gICAgICAgIHJlc3BvbnNlRXJyb3I6IGZ1bmN0aW9uIChyZWplY3Rpb24pIHtcbiAgICAgICAgICAkaW5qZWN0b3IuZ2V0KCdQclNwaW5uZXInKS5oaWRlKCk7XG5cbiAgICAgICAgICByZXR1cm4gJHEucmVqZWN0KHJlamVjdGlvbik7XG4gICAgICAgIH1cbiAgICAgIH07XG4gICAgfVxuXG4gICAgLy8gRGVmaW5lIHVtYSBmYWN0b3J5IHBhcmEgbyAkaHR0cEludGVyY2VwdG9yXG4gICAgJHByb3ZpZGUuZmFjdG9yeSgnc2hvd0hpZGVTcGlubmVyJywgc2hvd0hpZGVTcGlubmVyKTtcblxuICAgIC8vIEFkaWNpb25hIGEgZmFjdG9yeSBubyBhcnJheSBkZSBpbnRlcmNlcHRvcnMgZG8gJGh0dHBcbiAgICAkaHR0cFByb3ZpZGVyLmludGVyY2VwdG9ycy5wdXNoKCdzaG93SGlkZVNwaW5uZXInKTtcbiAgfVxufSgpKTtcbiIsIi8qZXNsaW50IGFuZ3VsYXIvbW9kdWxlLWdldHRlcjogMCovXG5cbihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb25maWcodG9rZW5JbnRlcmNlcHRvcik7XG5cbiAgLyoqXG4gICAqIEludGVyY2VwdCBhbGwgcmVzcG9uc2UgKHN1Y2Nlc3Mgb3IgZXJyb3IpIHRvIHZlcmlmeSB0aGUgcmV0dXJuZWQgdG9rZW5cbiAgICpcbiAgICogQHBhcmFtICRodHRwUHJvdmlkZXJcbiAgICogQHBhcmFtICRwcm92aWRlXG4gICAqIEBwYXJhbSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gdG9rZW5JbnRlcmNlcHRvcigkaHR0cFByb3ZpZGVyLCAkcHJvdmlkZSwgR2xvYmFsKSB7XG5cbiAgICBmdW5jdGlvbiByZWRpcmVjdFdoZW5TZXJ2ZXJMb2dnZWRPdXQoJHEsICRpbmplY3Rvcikge1xuICAgICAgcmV0dXJuIHtcbiAgICAgICAgcmVxdWVzdDogZnVuY3Rpb24oY29uZmlnKSB7XG4gICAgICAgICAgdmFyIHRva2VuID0gJGluamVjdG9yLmdldCgnQXV0aCcpLmdldFRva2VuKCk7XG5cbiAgICAgICAgICBpZiAodG9rZW4pIHtcbiAgICAgICAgICAgIGNvbmZpZy5oZWFkZXJzWydBdXRob3JpemF0aW9uJ10gPSAnQmVhcmVyICcgKyB0b2tlbjtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICByZXR1cm4gY29uZmlnO1xuICAgICAgICB9LFxuICAgICAgICByZXNwb25zZTogZnVuY3Rpb24ocmVzcG9uc2UpIHtcbiAgICAgICAgICAvLyBnZXQgYSBuZXcgcmVmcmVzaCB0b2tlbiB0byB1c2UgaW4gdGhlIG5leHQgcmVxdWVzdFxuICAgICAgICAgIHZhciB0b2tlbiA9IHJlc3BvbnNlLmhlYWRlcnMoJ0F1dGhvcml6YXRpb24nKTtcblxuICAgICAgICAgIGlmICh0b2tlbikge1xuICAgICAgICAgICAgJGluamVjdG9yLmdldCgnQXV0aCcpLnNldFRva2VuKHRva2VuLnNwbGl0KCcgJylbMV0pO1xuICAgICAgICAgIH1cbiAgICAgICAgICByZXR1cm4gcmVzcG9uc2U7XG4gICAgICAgIH0sXG4gICAgICAgIHJlc3BvbnNlRXJyb3I6IGZ1bmN0aW9uKHJlamVjdGlvbikge1xuICAgICAgICAgIC8vIEluc3RlYWQgb2YgY2hlY2tpbmcgZm9yIGEgc3RhdHVzIGNvZGUgb2YgNDAwIHdoaWNoIG1pZ2h0IGJlIHVzZWRcbiAgICAgICAgICAvLyBmb3Igb3RoZXIgcmVhc29ucyBpbiBMYXJhdmVsLCB3ZSBjaGVjayBmb3IgdGhlIHNwZWNpZmljIHJlamVjdGlvblxuICAgICAgICAgIC8vIHJlYXNvbnMgdG8gdGVsbCB1cyBpZiB3ZSBuZWVkIHRvIHJlZGlyZWN0IHRvIHRoZSBsb2dpbiBzdGF0ZVxuICAgICAgICAgIHZhciByZWplY3Rpb25SZWFzb25zID0gWyd0b2tlbl9ub3RfcHJvdmlkZWQnLCAndG9rZW5fZXhwaXJlZCcsICd0b2tlbl9hYnNlbnQnLCAndG9rZW5faW52YWxpZCddO1xuXG4gICAgICAgICAgdmFyIHRva2VuRXJyb3IgPSBmYWxzZTtcblxuICAgICAgICAgIGFuZ3VsYXIuZm9yRWFjaChyZWplY3Rpb25SZWFzb25zLCBmdW5jdGlvbih2YWx1ZSkge1xuICAgICAgICAgICAgaWYgKHJlamVjdGlvbi5kYXRhICYmIHJlamVjdGlvbi5kYXRhLmVycm9yID09PSB2YWx1ZSkge1xuICAgICAgICAgICAgICB0b2tlbkVycm9yID0gdHJ1ZTtcblxuICAgICAgICAgICAgICAkaW5qZWN0b3IuZ2V0KCdBdXRoJykubG9nb3V0KCkudGhlbihmdW5jdGlvbigpIHtcbiAgICAgICAgICAgICAgICB2YXIgJHN0YXRlID0gJGluamVjdG9yLmdldCgnJHN0YXRlJyk7XG5cbiAgICAgICAgICAgICAgICAvLyBpbiBjYXNlIG11bHRpcGxlIGFqYXggcmVxdWVzdCBmYWlsIGF0IHNhbWUgdGltZSBiZWNhdXNlIHRva2VuIHByb2JsZW1zLFxuICAgICAgICAgICAgICAgIC8vIG9ubHkgdGhlIGZpcnN0IHdpbGwgcmVkaXJlY3RcbiAgICAgICAgICAgICAgICBpZiAoISRzdGF0ZS5pcyhHbG9iYWwubG9naW5TdGF0ZSkpIHtcbiAgICAgICAgICAgICAgICAgICRzdGF0ZS5nbyhHbG9iYWwubG9naW5TdGF0ZSk7XG5cbiAgICAgICAgICAgICAgICAgIC8vY2xvc2UgYW55IGRpYWxvZyB0aGF0IGlzIG9wZW5lZFxuICAgICAgICAgICAgICAgICAgJGluamVjdG9yLmdldCgnUHJEaWFsb2cnKS5jbG9zZSgpO1xuXG4gICAgICAgICAgICAgICAgICBldmVudC5wcmV2ZW50RGVmYXVsdCgpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfSk7XG5cbiAgICAgICAgICAvL2RlZmluZSBkYXRhIHRvIGVtcHR5IGJlY2F1c2UgYWxyZWFkeSBzaG93IFByVG9hc3QgdG9rZW4gbWVzc2FnZVxuICAgICAgICAgIGlmICh0b2tlbkVycm9yKSB7XG4gICAgICAgICAgICByZWplY3Rpb24uZGF0YSA9IHt9O1xuICAgICAgICAgIH1cblxuICAgICAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24ocmVqZWN0aW9uLmhlYWRlcnMpKSB7XG4gICAgICAgICAgICAvLyBtYW55IHNlcnZlcnMgZXJyb3JzIChidXNpbmVzcykgYXJlIGludGVyY2VwdCBoZXJlIGJ1dCBnZW5lcmF0ZWQgYSBuZXcgcmVmcmVzaCB0b2tlblxuICAgICAgICAgICAgLy8gYW5kIG5lZWQgdXBkYXRlIGN1cnJlbnQgdG9rZW5cbiAgICAgICAgICAgIHZhciB0b2tlbiA9IHJlamVjdGlvbi5oZWFkZXJzKCdBdXRob3JpemF0aW9uJyk7XG5cbiAgICAgICAgICAgIGlmICh0b2tlbikge1xuICAgICAgICAgICAgICAkaW5qZWN0b3IuZ2V0KCdBdXRoJykuc2V0VG9rZW4odG9rZW4uc3BsaXQoJyAnKVsxXSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgcmV0dXJuICRxLnJlamVjdChyZWplY3Rpb24pO1xuICAgICAgICB9XG4gICAgICB9O1xuICAgIH1cblxuICAgIC8vIFNldHVwIGZvciB0aGUgJGh0dHBJbnRlcmNlcHRvclxuICAgICRwcm92aWRlLmZhY3RvcnkoJ3JlZGlyZWN0V2hlblNlcnZlckxvZ2dlZE91dCcsIHJlZGlyZWN0V2hlblNlcnZlckxvZ2dlZE91dCk7XG5cbiAgICAvLyBQdXNoIHRoZSBuZXcgZmFjdG9yeSBvbnRvIHRoZSAkaHR0cCBpbnRlcmNlcHRvciBhcnJheVxuICAgICRodHRwUHJvdmlkZXIuaW50ZXJjZXB0b3JzLnB1c2goJ3JlZGlyZWN0V2hlblNlcnZlckxvZ2dlZE91dCcpO1xuICB9XG5cbn0oKSk7XG4iLCIoZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbmZpZyh2YWxpZGF0aW9uSW50ZXJjZXB0b3IpO1xuXG4gIGZ1bmN0aW9uIHZhbGlkYXRpb25JbnRlcmNlcHRvcigkaHR0cFByb3ZpZGVyLCAkcHJvdmlkZSkge1xuICAgIC8qKlxuICAgICAqIEVzdGUgaW50ZXJjZXB0b3Igw6kgcmVzcG9uc8OhdmVsIHBvciBtb3N0cmFyIGFzXG4gICAgICogbWVuc2FnZW5zIGRlIGVycm8gcmVmZXJlbnRlIGFzIHZhbGlkYcOnw7VlcyBkbyBiYWNrLWVuZFxuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9ICRxXG4gICAgICogQHBhcmFtIHthbnl9ICRpbmplY3RvclxuICAgICAqIEByZXR1cm5zXG4gICAgICovXG4gICAgZnVuY3Rpb24gc2hvd0Vycm9yVmFsaWRhdGlvbigkcSwgJGluamVjdG9yKSB7XG4gICAgICByZXR1cm4ge1xuICAgICAgICByZXNwb25zZUVycm9yOiBmdW5jdGlvbiAocmVqZWN0aW9uKSB7XG4gICAgICAgICAgdmFyIFByVG9hc3QgPSAkaW5qZWN0b3IuZ2V0KCdQclRvYXN0Jyk7XG4gICAgICAgICAgdmFyICR0cmFuc2xhdGUgPSAkaW5qZWN0b3IuZ2V0KCckdHJhbnNsYXRlJyk7XG5cbiAgICAgICAgICBpZiAocmVqZWN0aW9uLmNvbmZpZy5kYXRhICYmICFyZWplY3Rpb24uY29uZmlnLmRhdGEuc2tpcFZhbGlkYXRpb24pIHtcbiAgICAgICAgICAgIGlmIChyZWplY3Rpb24uZGF0YSAmJiByZWplY3Rpb24uZGF0YS5lcnJvcikge1xuXG4gICAgICAgICAgICAgIC8vdmVyaWZpY2Egc2Ugb2NvcnJldSBhbGd1bSBlcnJvIHJlZmVyZW50ZSBhbyB0b2tlblxuICAgICAgICAgICAgICBpZiAocmVqZWN0aW9uLmRhdGEuZXJyb3Iuc3RhcnRzV2l0aCgndG9rZW5fJykpIHtcbiAgICAgICAgICAgICAgICBQclRvYXN0Lndhcm4oJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5sb2dpbi5sb2dvdXRJbmFjdGl2ZScpKTtcbiAgICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICBQclRvYXN0LmVycm9yKCR0cmFuc2xhdGUuaW5zdGFudChyZWplY3Rpb24uZGF0YS5lcnJvcikpO1xuICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICBQclRvYXN0LmVycm9yVmFsaWRhdGlvbihyZWplY3Rpb24uZGF0YSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgcmV0dXJuICRxLnJlamVjdChyZWplY3Rpb24pO1xuICAgICAgICB9XG4gICAgICB9O1xuICAgIH1cblxuICAgIC8vIERlZmluZSB1bWEgZmFjdG9yeSBwYXJhIG8gJGh0dHBJbnRlcmNlcHRvclxuICAgICRwcm92aWRlLmZhY3RvcnkoJ3Nob3dFcnJvclZhbGlkYXRpb24nLCBzaG93RXJyb3JWYWxpZGF0aW9uKTtcblxuICAgIC8vIEFkaWNpb25hIGEgZmFjdG9yeSBubyBhcnJheSBkZSBpbnRlcmNlcHRvcnMgZG8gJGh0dHBcbiAgICAkaHR0cFByb3ZpZGVyLmludGVyY2VwdG9ycy5wdXNoKCdzaG93RXJyb3JWYWxpZGF0aW9uJyk7XG4gIH1cbn0oKSk7XG4iLCIvKmVzbGludC1lbnYgZXM2Ki9cblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnRyb2xsZXIoJ01lbnVDb250cm9sbGVyJywgTWVudUNvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gTWVudUNvbnRyb2xsZXIoJG1kU2lkZW5hdiwgJHN0YXRlLCAkbWRDb2xvcnMpIHtcbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgLy9CbG9jbyBkZSBkZWNsYXJhY29lcyBkZSBmdW5jb2VzXG4gICAgdm0ub3BlbiA9IG9wZW47XG4gICAgdm0ub3Blbk1lbnVPclJlZGlyZWN0VG9TdGF0ZSA9IG9wZW5NZW51T3JSZWRpcmVjdFRvU3RhdGU7XG5cbiAgICBhY3RpdmF0ZSgpO1xuXG4gICAgZnVuY3Rpb24gYWN0aXZhdGUoKSB7XG4gICAgICB2YXIgbWVudVByZWZpeCA9ICd2aWV3cy5sYXlvdXQubWVudS4nO1xuXG4gICAgICAvLyBBcnJheSBjb250ZW5kbyBvcyBpdGVucyBxdWUgc8OjbyBtb3N0cmFkb3Mgbm8gbWVudSBsYXRlcmFsXG4gICAgICB2bS5pdGVuc01lbnUgPSBbXG4gICAgICAgIHsgc3RhdGU6ICdhcHAuZGFzaGJvYXJkJywgdGl0bGU6IG1lbnVQcmVmaXggKyAnZGFzaGJvYXJkJywgaWNvbjogJ2Rhc2hib2FyZCcsIHN1Ykl0ZW5zOiBbXSB9LFxuICAgICAgICAvLyBDb2xvcXVlIHNldXMgaXRlbnMgZGUgbWVudSBhIHBhcnRpciBkZXN0ZSBwb250b1xuICAgICAgICB7XG4gICAgICAgICAgc3RhdGU6ICcjJywgdGl0bGU6IG1lbnVQcmVmaXggKyAnYWRtaW4nLCBpY29uOiAnc2V0dGluZ3NfYXBwbGljYXRpb25zJywgcHJvZmlsZXM6IFsnYWRtaW4nXSxcbiAgICAgICAgICBzdWJJdGVuczogW1xuICAgICAgICAgICAgeyBzdGF0ZTogJ2FwcC51c2VyJywgdGl0bGU6IG1lbnVQcmVmaXggKyAndXNlcicsIGljb246ICdwZW9wbGUnIH0sXG4gICAgICAgICAgICB7IHN0YXRlOiAnYXBwLm1haWwnLCB0aXRsZTogbWVudVByZWZpeCArICdtYWlsJywgaWNvbjogJ21haWwnIH0sXG4gICAgICAgICAgICB7IHN0YXRlOiAnYXBwLmF1ZGl0JywgdGl0bGU6IG1lbnVQcmVmaXggKyAnYXVkaXQnLCBpY29uOiAnc3RvcmFnZScgfSxcbiAgICAgICAgICAgIHsgc3RhdGU6ICdhcHAuZGluYW1pYy1xdWVyeScsIHRpdGxlOiBtZW51UHJlZml4ICsgJ2RpbmFtaWNRdWVyeScsIGljb246ICdsb2NhdGlvbl9zZWFyY2hpbmcnIH1cbiAgICAgICAgICBdXG4gICAgICAgIH1cbiAgICAgIF07XG5cbiAgICAgIC8qKlxuICAgICAgICogT2JqZXRvIHF1ZSBwcmVlbmNoZSBvIG5nLXN0eWxlIGRvIG1lbnUgbGF0ZXJhbCB0cm9jYW5kbyBhcyBjb3Jlc1xuICAgICAgICovXG4gICAgICB2bS5zaWRlbmF2U3R5bGUgPSB7XG4gICAgICAgIHRvcDoge1xuICAgICAgICAgICdib3JkZXItYm90dG9tJzogJzFweCBzb2xpZCAnICsgZ2V0Q29sb3IoJ3ByaW1hcnknKSxcbiAgICAgICAgICAnYmFja2dyb3VuZC1pbWFnZSc6ICctd2Via2l0LWxpbmVhci1ncmFkaWVudCh0b3AsICcrZ2V0Q29sb3IoJ3ByaW1hcnktNTAwJykrJywgJytnZXRDb2xvcigncHJpbWFyeS04MDAnKSsnKSdcbiAgICAgICAgfSxcbiAgICAgICAgY29udGVudDoge1xuICAgICAgICAgICdiYWNrZ3JvdW5kLWNvbG9yJzogZ2V0Q29sb3IoJ3ByaW1hcnktODAwJylcbiAgICAgICAgfSxcbiAgICAgICAgdGV4dENvbG9yOiB7XG4gICAgICAgICAgY29sb3I6ICcjRkZGJ1xuICAgICAgICB9LFxuICAgICAgICBsaW5lQm90dG9tOiB7XG4gICAgICAgICAgJ2JvcmRlci1ib3R0b20nOiAnMXB4IHNvbGlkICcgKyBnZXRDb2xvcigncHJpbWFyeS00MDAnKVxuICAgICAgICB9XG4gICAgICB9XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gb3BlbigpIHtcbiAgICAgICRtZFNpZGVuYXYoJ2xlZnQnKS50b2dnbGUoKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBNw6l0b2RvIHF1ZSBleGliZSBvIHN1YiBtZW51IGRvcyBpdGVucyBkbyBtZW51IGxhdGVyYWwgY2FzbyB0ZW5oYSBzdWIgaXRlbnNcbiAgICAgKiBjYXNvIGNvbnRyw6FyaW8gcmVkaXJlY2lvbmEgcGFyYSBvIHN0YXRlIHBhc3NhZG8gY29tbyBwYXLDom1ldHJvXG4gICAgICovXG4gICAgZnVuY3Rpb24gb3Blbk1lbnVPclJlZGlyZWN0VG9TdGF0ZSgkbWRNZW51LCBldiwgaXRlbSkge1xuICAgICAgaWYgKGFuZ3VsYXIuaXNEZWZpbmVkKGl0ZW0uc3ViSXRlbnMpICYmIGl0ZW0uc3ViSXRlbnMubGVuZ3RoID4gMCkge1xuICAgICAgICAkbWRNZW51Lm9wZW4oZXYpO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgJHN0YXRlLmdvKGl0ZW0uc3RhdGUpO1xuICAgICAgICAkbWRTaWRlbmF2KCdsZWZ0JykuY2xvc2UoKTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICBmdW5jdGlvbiBnZXRDb2xvcihjb2xvclBhbGV0dGVzKSB7XG4gICAgICByZXR1cm4gJG1kQ29sb3JzLmdldFRoZW1lQ29sb3IoY29sb3JQYWxldHRlcyk7XG4gICAgfVxuXG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnRyb2xsZXIoJ01haWxzQ29udHJvbGxlcicsIE1haWxzQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBNYWlsc0NvbnRyb2xsZXIoTWFpbHNTZXJ2aWNlLCBVc2Vyc1NlcnZpY2UsIFByRGlhbG9nLCBQclRvYXN0LCAvLyBOT1NPTkFSXG4gICAgJHEsIGxvZGFzaCwgJHRyYW5zbGF0ZSwgR2xvYmFsKSB7XG5cbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0uZmlsdGVyU2VsZWN0ZWQgPSBmYWxzZTtcbiAgICB2bS5vcHRpb25zID0ge1xuICAgICAgc2tpbjogJ2thbWEnLFxuICAgICAgbGFuZ3VhZ2U6ICdwdC1icicsXG4gICAgICBhbGxvd2VkQ29udGVudDogdHJ1ZSxcbiAgICAgIGVudGl0aWVzOiB0cnVlLFxuICAgICAgaGVpZ2h0OiAzMDAsXG4gICAgICBleHRyYVBsdWdpbnM6ICdkaWFsb2csZmluZCxjb2xvcmRpYWxvZyxwcmV2aWV3LGZvcm1zLGlmcmFtZSxmbGFzaCdcbiAgICB9O1xuXG4gICAgdm0ubG9hZFVzZXJzID0gbG9hZFVzZXJzO1xuICAgIHZtLm9wZW5Vc2VyRGlhbG9nID0gb3BlblVzZXJEaWFsb2c7XG4gICAgdm0uYWRkVXNlck1haWwgPSBhZGRVc2VyTWFpbDtcbiAgICB2bS5jbGVhbkZvcm0gPSBjbGVhbkZvcm07XG4gICAgdm0uc2VuZCA9IHNlbmQ7XG5cbiAgICBhY3RpdmF0ZSgpO1xuXG4gICAgZnVuY3Rpb24gYWN0aXZhdGUoKSB7XG4gICAgICB2bS5jbGVhbkZvcm0oKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFsaXphIGEgYnVzY2EgcGVsbyB1c3XDoXJpbyByZW1vdGFtZW50ZVxuICAgICAqXG4gICAgICogQHBhcmFtcyB7c3RyaW5nfSAtIFJlY2ViZSBvIHZhbG9yIHBhcmEgc2VyIHBlc3F1aXNhZG9cbiAgICAgKiBAcmV0dXJuIHtwcm9taXNzZX0gLSBSZXRvcm5hIHVtYSBwcm9taXNzZSBxdWUgbyBjb21wb25ldGUgcmVzb2x2ZVxuICAgICAqL1xuICAgIGZ1bmN0aW9uIGxvYWRVc2Vycyhjcml0ZXJpYSkge1xuICAgICAgdmFyIGRlZmVycmVkID0gJHEuZGVmZXIoKTtcblxuICAgICAgVXNlcnNTZXJ2aWNlLnF1ZXJ5KHtcbiAgICAgICAgbmFtZU9yRW1haWw6IGNyaXRlcmlhLFxuICAgICAgICBub3RVc2VyczogbG9kYXNoLm1hcCh2bS5tYWlsLnVzZXJzLCBsb2Rhc2gucHJvcGVydHkoJ2lkJykpLnRvU3RyaW5nKCksXG4gICAgICAgIGxpbWl0OiA1XG4gICAgICB9KS50aGVuKGZ1bmN0aW9uKGRhdGEpIHtcblxuICAgICAgICAvLyB2ZXJpZmljYSBzZSBuYSBsaXN0YSBkZSB1c3VhcmlvcyBqw6EgZXhpc3RlIG8gdXN1w6FyaW8gY29tIG8gZW1haWwgcGVzcXVpc2Fkb1xuICAgICAgICBkYXRhID0gbG9kYXNoLmZpbHRlcihkYXRhLCBmdW5jdGlvbih1c2VyKSB7XG4gICAgICAgICAgcmV0dXJuICFsb2Rhc2guZmluZCh2bS5tYWlsLnVzZXJzLCB7IGVtYWlsOiB1c2VyLmVtYWlsIH0pO1xuICAgICAgICB9KTtcblxuICAgICAgICBkZWZlcnJlZC5yZXNvbHZlKGRhdGEpO1xuICAgICAgfSk7XG5cbiAgICAgIHJldHVybiBkZWZlcnJlZC5wcm9taXNlO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEFicmUgbyBkaWFsb2cgcGFyYSBwZXNxdWlzYSBkZSB1c3XDoXJpb3NcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBvcGVuVXNlckRpYWxvZygpIHtcbiAgICAgIHZhciBjb25maWcgPSB7XG4gICAgICAgIGxvY2Fsczoge1xuICAgICAgICAgIG9uSW5pdDogdHJ1ZSxcbiAgICAgICAgICB1c2VyRGlhbG9nSW5wdXQ6IHtcbiAgICAgICAgICAgIHRyYW5zZmVyVXNlckZuOiB2bS5hZGRVc2VyTWFpbFxuICAgICAgICAgIH1cbiAgICAgICAgfSxcbiAgICAgICAgY29udHJvbGxlcjogJ1VzZXJzRGlhbG9nQ29udHJvbGxlcicsXG4gICAgICAgIGNvbnRyb2xsZXJBczogJ2N0cmwnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL3VzZXJzL2RpYWxvZy91c2Vycy1kaWFsb2cuaHRtbCcsXG4gICAgICAgIGhhc0JhY2tkcm9wOiB0cnVlXG4gICAgICB9O1xuXG4gICAgICBQckRpYWxvZy5jdXN0b20oY29uZmlnKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBBZGljaW9uYSBvIHVzdcOhcmlvIHNlbGVjaW9uYWRvIG5hIGxpc3RhIHBhcmEgcXVlIHNlamEgZW52aWFkbyBvIGVtYWlsXG4gICAgICovXG4gICAgZnVuY3Rpb24gYWRkVXNlck1haWwodXNlcikge1xuICAgICAgdmFyIHVzZXJzID0gbG9kYXNoLmZpbmQodm0ubWFpbC51c2VycywgeyBlbWFpbDogdXNlci5lbWFpbCB9KTtcblxuICAgICAgaWYgKHZtLm1haWwudXNlcnMubGVuZ3RoID4gMCAmJiBhbmd1bGFyLmlzRGVmaW5lZCh1c2VycykpIHtcbiAgICAgICAgUHJUb2FzdC53YXJuKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMudXNlci51c2VyRXhpc3RzJykpO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgdm0ubWFpbC51c2Vycy5wdXNoKHsgbmFtZTogdXNlci5uYW1lLCBlbWFpbDogdXNlci5lbWFpbCB9KVxuICAgICAgfVxuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWxpemEgbyBlbnZpbyBkbyBlbWFpbCBwYXJhIGEgbGlzdGEgZGUgdXN1w6FyaW9zIHNlbGVjaW9uYWRvc1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIHNlbmQoKSB7XG5cbiAgICAgIHZtLm1haWwuJHNhdmUoKS50aGVuKGZ1bmN0aW9uKHJlc3BvbnNlKSB7XG4gICAgICAgIGlmIChyZXNwb25zZS5sZW5ndGggPiAwKSB7XG4gICAgICAgICAgdmFyIG1zZyA9ICR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMubWFpbC5tYWlsRXJyb3JzJyk7XG5cbiAgICAgICAgICBmb3IgKHZhciBpPTA7IGkgPCByZXNwb25zZS5sZW5ndGg7IGkrKykge1xuICAgICAgICAgICAgbXNnICs9IHJlc3BvbnNlICsgJ1xcbic7XG4gICAgICAgICAgfVxuICAgICAgICAgIFByVG9hc3QuZXJyb3IobXNnKTtcbiAgICAgICAgICB2bS5jbGVhbkZvcm0oKTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICBQclRvYXN0LnN1Y2Nlc3MoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5tYWlsLnNlbmRNYWlsU3VjY2VzcycpKTtcbiAgICAgICAgICB2bS5jbGVhbkZvcm0oKTtcbiAgICAgICAgfVxuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogTGltcGEgbyBmb3JtdWzDoXJpbyBkZSBlbWFpbFxuICAgICAqL1xuICAgIGZ1bmN0aW9uIGNsZWFuRm9ybSgpIHtcbiAgICAgIHZtLm1haWwgPSBuZXcgTWFpbHNTZXJ2aWNlKCk7XG4gICAgICB2bS5tYWlsLnVzZXJzID0gW107XG4gICAgfVxuXG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb25maWcocm91dGVzKTtcblxuICAvKipcbiAgICogQXJxdWl2byBkZSBjb25maWd1cmHDp8OjbyBjb20gYXMgcm90YXMgZXNwZWPDrWZpY2FzIGRvIHJlY3Vyc28gZW0gcXVlc3TDo29cbiAgICpcbiAgICogQHBhcmFtIHthbnl9ICRzdGF0ZVByb3ZpZGVyXG4gICAqIEBwYXJhbSB7YW55fSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlclxuICAgICAgLnN0YXRlKCdhcHAubWFpbCcsIHtcbiAgICAgICAgdXJsOiAnL2VtYWlsJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9tYWlsL21haWxzLXNlbmQuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdNYWlsc0NvbnRyb2xsZXIgYXMgbWFpbHNDdHJsJyxcbiAgICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IHRydWUsIG5lZWRQcm9maWxlOiBbJ2FkbWluJ10gfVxuICAgICAgfSk7XG5cbiAgfVxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5mYWN0b3J5KCdNYWlsc1NlcnZpY2UnLCBNYWlsc1NlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gTWFpbHNTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCdtYWlscycsIHt9KTtcbiAgfVxuXG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29udHJvbGxlcignUHJvamVjdHNDb250cm9sbGVyJywgUHJvamVjdHNDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIFByb2plY3RzQ29udHJvbGxlcihHbG9iYWwsICRjb250cm9sbGVyLCBQcm9qZWN0c1NlcnZpY2UsIEF1dGgsIFJvbGVzU2VydmljZSkge1xuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICAvL0F0dHJpYnV0ZXMgQmxvY2tcblxuICAgIC8vRnVuY3Rpb25zIEJsb2NrXG4gICAgdm0ub25BY3RpdmF0ZSA9IG9uQWN0aXZhdGU7XG4gICAgdm0uYXBwbHlGaWx0ZXJzID0gYXBwbHlGaWx0ZXJzO1xuICAgIHZtLmJlZm9yZVNhdmUgPSBiZWZvcmVTYXZlO1xuICAgIHZtLmFmdGVyU2VhcmNoID0gYWZ0ZXJTZWFyY2g7XG4gICAgXG4gICAgdm0ucm9sZXMgPSB7fTtcblxuICAgIC8vIGluc3RhbnRpYXRlIGJhc2UgY29udHJvbGxlclxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHsgdm06IHZtLCBtb2RlbFNlcnZpY2U6IFByb2plY3RzU2VydmljZSwgb3B0aW9uczoge30gfSk7XG5cbiAgICBmdW5jdGlvbiBvbkFjdGl2YXRlKCkge1xuXHRcdFJvbGVzU2VydmljZS5xdWVyeSgpLnRoZW4oZnVuY3Rpb24ocmVzcG9uc2Upe1xuXHRcdFx0dm0ucm9sZXMgPSByZXNwb25zZTtcblx0XHR9KTtcblx0XHR2bS5xdWVyeUZpbHRlcnMgPSB7fTtcbiAgICB9XG4gICAgXG4gICAgZnVuY3Rpb24gYWZ0ZXJTZWFyY2goKSB7XG5cdFx0Y29uc29sZS5sb2codm0ucmVzb3VyY2VzKTtcblx0fVxuXG4gICAgZnVuY3Rpb24gYXBwbHlGaWx0ZXJzKGRlZmF1bHRRdWVyeUZpbHRlcnMpIHtcbiAgICAgIHJldHVybiBhbmd1bGFyLmV4dGVuZChkZWZhdWx0UXVlcnlGaWx0ZXJzLCB2bS5xdWVyeWx0ZXJzKTtcbiAgICB9XG4gICAgXG4gICAgZnVuY3Rpb24gYmVmb3JlU2F2ZSgpIHtcblx0XHR2bS5yZXNvdXJjZS5vd25lciA9IEF1dGguY3VycmVudFVzZXIuaWQ7XG5cdFx0dm0ucmVzb3VyY2UudXNlcl9pZCA9IEF1dGguY3VycmVudFVzZXIuaWQ7XG5cdH1cblxuICB9XG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqXG4gICAqIEFycXVpdm8gZGUgY29uZmlndXJhw6fDo28gY29tIGFzIHJvdGFzIGVzcGVjw61maWNhcyBkbyByZWN1cnNvIHByb2plY3RcbiAgICpcbiAgICogQHBhcmFtIHthbnl9ICRzdGF0ZVByb3ZpZGVyXG4gICAqIEBwYXJhbSB7YW55fSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlclxuICAgICAgLnN0YXRlKCdhcHAucHJvamVjdHMnLCB7XG4gICAgICAgIHVybDogJy9wcm9qZWN0cycsXG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvcHJvamVjdHMvcHJvamVjdHMuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdQcm9qZWN0c0NvbnRyb2xsZXIgYXMgcHJvamVjdHNDdHJsJyxcbiAgICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IHRydWV9XG4gICAgICB9KTtcbiAgfVxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5mYWN0b3J5KCdQcm9qZWN0c1NlcnZpY2UnLCBQcm9qZWN0c1NlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gUHJvamVjdHNTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCdwcm9qZWN0cycsIHtcbiAgICAgIGFjdGlvbnM6IHsgfSxcbiAgICAgIGluc3RhbmNlOiB7IH1cbiAgICB9KTtcbiAgfVxuXG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmlsdGVyKCdyb2xlc1N0cicsIHJvbGVzU3RyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvbGVzU3RyKGxvZGFzaCkge1xuICAgIC8qKlxuICAgICAqIEBwYXJhbSB7YXJyYXl9IHJvbGVzIGxpc3RhIGRlIHBlcmZpc1xuICAgICAqIEByZXR1cm4ge3N0cmluZ30gcGVyZmlzIHNlcGFyYWRvcyBwb3IgJywgJyAgXG4gICAgICovXG4gICAgcmV0dXJuIGZ1bmN0aW9uKHJvbGVzKSB7XG4gICAgICByZXR1cm4gbG9kYXNoLm1hcChyb2xlcywgJ3NsdWcnKS5qb2luKCcsICcpO1xuICAgIH07XG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5mYWN0b3J5KCdSb2xlc1NlcnZpY2UnLCBSb2xlc1NlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gUm9sZXNTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCdyb2xlcycpO1xuICB9XG5cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmFjdG9yeSgnU3VwcG9ydFNlcnZpY2UnLCBTdXBwb3J0U2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiBTdXBwb3J0U2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHJldHVybiBzZXJ2aWNlRmFjdG9yeSgnc3VwcG9ydCcsIHtcbiAgICAgIGFjdGlvbnM6IHtcbiAgICAgIC8qKlxuICAgICAgICogUGVnYSBhcyB0cmFkdcOnw7VlcyBxdWUgZXN0w6NvIG5vIHNlcnZpZG9yXG4gICAgICAgKlxuICAgICAgICogQHJldHVybnMge3Byb21pc2V9IFVtYSBwcm9taXNlIGNvbSBvIHJlc3VsdGFkbyBkbyBjaGFtYWRhIG5vIGJhY2tlbmRcbiAgICAgICAqL1xuICAgICAgICBsYW5nczoge1xuICAgICAgICAgIG1ldGhvZDogJ0dFVCcsXG4gICAgICAgICAgdXJsOiAnbGFuZ3MnLFxuICAgICAgICAgIHdyYXA6IGZhbHNlLFxuICAgICAgICAgIGNhY2hlOiB0cnVlXG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9KTtcbiAgfVxuXG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29udHJvbGxlcignUHJvZmlsZUNvbnRyb2xsZXInLCBQcm9maWxlQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBQcm9maWxlQ29udHJvbGxlcihVc2Vyc1NlcnZpY2UsIEF1dGgsIFByVG9hc3QsICR0cmFuc2xhdGUpIHtcbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0udXBkYXRlID0gdXBkYXRlO1xuXG4gICAgYWN0aXZhdGUoKTtcblxuICAgIGZ1bmN0aW9uIGFjdGl2YXRlKCkge1xuICAgICAgdm0udXNlciA9IGFuZ3VsYXIuY29weShBdXRoLmN1cnJlbnRVc2VyKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiB1cGRhdGUoKSB7XG4gICAgICBVc2Vyc1NlcnZpY2UudXBkYXRlUHJvZmlsZSh2bS51c2VyKS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICAvL2F0dWFsaXphIG8gdXN1w6FyaW8gY29ycmVudGUgY29tIGFzIG5vdmFzIGluZm9ybWHDp8O1ZXNcbiAgICAgICAgQXV0aC51cGRhdGVDdXJyZW50VXNlcihyZXNwb25zZSk7XG4gICAgICAgIFByVG9hc3Quc3VjY2VzcygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnNhdmVTdWNjZXNzJykpO1xuICAgICAgfSk7XG4gICAgfVxuICB9XG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb250cm9sbGVyKCdVc2Vyc0NvbnRyb2xsZXInLCBVc2Vyc0NvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gVXNlcnNDb250cm9sbGVyKCRjb250cm9sbGVyLCBVc2Vyc1NlcnZpY2UpIHtcblxuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICB2bS5vbkFjdGl2YXRlID0gb25BY3RpdmF0ZTtcbiAgICAvLyBpbnN0YW50aWF0ZSBiYXNlIGNvbnRyb2xsZXJcbiAgICAkY29udHJvbGxlcignQ1JVRENvbnRyb2xsZXInLCB7IHZtOiB2bSwgbW9kZWxTZXJ2aWNlOiBVc2Vyc1NlcnZpY2UsIG9wdGlvbnM6IHt9IH0pO1xuXG4gICAgZnVuY3Rpb24gb25BY3RpdmF0ZSgpIHtcbiAgICAgIHZtLnF1ZXJ5RmlsdGVycyA9IHt9O1xuICAgIH1cbiAgfVxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb25maWcocm91dGVzKTtcblxuICAvKipcbiAgICogQXJxdWl2byBkZSBjb25maWd1cmHDp8OjbyBjb20gYXMgcm90YXMgZXNwZWPDrWZpY2FzIGRvIHJlY3Vyc28gdXNlclxuICAgKlxuICAgKiBAcGFyYW0ge2FueX0gJHN0YXRlUHJvdmlkZXJcbiAgICogQHBhcmFtIHthbnl9IEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyXG4gICAgICAuc3RhdGUoJ2FwcC51c2VyJywge1xuICAgICAgICB1cmw6ICcvdXN1YXJpbycsXG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvdXNlcnMvdXNlcnMuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdVc2Vyc0NvbnRyb2xsZXIgYXMgdXNlcnNDdHJsJyxcbiAgICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IHRydWUsIG5lZWRQcm9maWxlOiBbJ2FkbWluJ10gfVxuICAgICAgfSlcbiAgICAgIC5zdGF0ZSgnYXBwLnVzZXItcHJvZmlsZScsIHtcbiAgICAgICAgdXJsOiAnL3VzdWFyaW8vcGVyZmlsJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy91c2Vycy9wcm9maWxlLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnUHJvZmlsZUNvbnRyb2xsZXIgYXMgcHJvZmlsZUN0cmwnLFxuICAgICAgICBkYXRhOiB7IG5lZWRBdXRoZW50aWNhdGlvbjogdHJ1ZSB9XG4gICAgICB9KTtcblxuICB9XG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZhY3RvcnkoJ1VzZXJzU2VydmljZScsIFVzZXJzU2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBVc2Vyc1NlcnZpY2UobG9kYXNoLCBHbG9iYWwsIHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCd1c2VycycsIHtcbiAgICAgIC8vcXVhbmRvIGluc3RhbmNpYSB1bSB1c3XDoXJpbyBzZW0gcGFzc2FyIHBhcmFtZXRybyxcbiAgICAgIC8vbyBtZXNtbyB2YWkgdGVyIG9zIHZhbG9yZXMgZGVmYXVsdHMgYWJhaXhvXG4gICAgICBkZWZhdWx0czoge1xuICAgICAgICByb2xlczogW11cbiAgICAgIH0sXG5cbiAgICAgIGFjdGlvbnM6IHtcbiAgICAgICAgLyoqXG4gICAgICAgICAqIFNlcnZpw6dvIHF1ZSBhdHVhbGl6YSBvcyBkYWRvcyBkbyBwZXJmaWwgZG8gdXN1w6FyaW8gbG9nYWRvXG4gICAgICAgICAqXG4gICAgICAgICAqIEBwYXJhbSB7b2JqZWN0fSBhdHRyaWJ1dGVzXG4gICAgICAgICAqIEByZXR1cm5zIHtwcm9taXNlfSBVbWEgcHJvbWlzZSBjb20gbyByZXN1bHRhZG8gZG8gY2hhbWFkYSBubyBiYWNrZW5kXG4gICAgICAgICAqL1xuICAgICAgICB1cGRhdGVQcm9maWxlOiB7XG4gICAgICAgICAgbWV0aG9kOiAnUFVUJyxcbiAgICAgICAgICB1cmw6IEdsb2JhbC5hcGlQYXRoICsgJy9wcm9maWxlJyxcbiAgICAgICAgICBvdmVycmlkZTogdHJ1ZSxcbiAgICAgICAgICB3cmFwOiBmYWxzZVxuICAgICAgICB9XG4gICAgICB9LFxuXG4gICAgICBpbnN0YW5jZToge1xuICAgICAgICAvKipcbiAgICAgICAgICogVmVyaWZpY2Egc2UgbyB1c3XDoXJpbyB0ZW0gb3MgcGVyZmlzIGluZm9ybWFkb3MuXG4gICAgICAgICAqXG4gICAgICAgICAqIEBwYXJhbSB7YW55fSByb2xlcyBwZXJmaXMgYSBzZXJlbSB2ZXJpZmljYWRvc1xuICAgICAgICAgKiBAcGFyYW0ge2Jvb2xlYW59IGFsbCBmbGFnIHBhcmEgaW5kaWNhciBzZSB2YWkgY2hlZ2FyIHRvZG9zIG9zIHBlcmZpcyBvdSBzb21lbnRlIHVtIGRlbGVzXG4gICAgICAgICAqIEByZXR1cm5zIHtib29sZWFufVxuICAgICAgICAgKi9cbiAgICAgICAgaGFzUHJvZmlsZTogZnVuY3Rpb24ocm9sZXMsIGFsbCkge1xuICAgICAgICAgIHJvbGVzID0gYW5ndWxhci5pc0FycmF5KHJvbGVzKSA/IHJvbGVzIDogW3JvbGVzXTtcblxuICAgICAgICAgIHZhciB1c2VyUm9sZXMgPSBsb2Rhc2gubWFwKHRoaXMucm9sZXMsICdzbHVnJyk7XG5cbiAgICAgICAgICBpZiAoYWxsKSB7XG4gICAgICAgICAgICByZXR1cm4gbG9kYXNoLmludGVyc2VjdGlvbih1c2VyUm9sZXMsIHJvbGVzKS5sZW5ndGggPT09IHJvbGVzLmxlbmd0aDtcbiAgICAgICAgICB9IGVsc2UgeyAvL3JldHVybiB0aGUgbGVuZ3RoIGJlY2F1c2UgMCBpcyBmYWxzZSBpbiBqc1xuICAgICAgICAgICAgcmV0dXJuIGxvZGFzaC5pbnRlcnNlY3Rpb24odXNlclJvbGVzLCByb2xlcykubGVuZ3RoO1xuICAgICAgICAgIH1cbiAgICAgICAgfSxcblxuICAgICAgICAvKipcbiAgICAgICAgICogVmVyaWZpY2Egc2UgbyB1c3XDoXJpbyB0ZW0gbyBwZXJmaWwgYWRtaW4uXG4gICAgICAgICAqXG4gICAgICAgICAqIEByZXR1cm5zIHtib29sZWFufVxuICAgICAgICAgKi9cbiAgICAgICAgaXNBZG1pbjogZnVuY3Rpb24oKSB7XG4gICAgICAgICAgcmV0dXJuIHRoaXMuaGFzUHJvZmlsZSgnYWRtaW4nKTtcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pO1xuICB9XG5cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICAgLyoqIEBuZ0luamVjdCAqL1xuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29tcG9uZW50KCdib3gnLCB7XG4gICAgICByZXBsYWNlOiB0cnVlLFxuICAgICAgdGVtcGxhdGVVcmw6IFsnR2xvYmFsJywgZnVuY3Rpb24oR2xvYmFsKSB7XG4gICAgICAgIHJldHVybiBHbG9iYWwuY2xpZW50UGF0aCArICcvd2lkZ2V0cy9ib3guaHRtbCdcbiAgICAgIH1dLFxuICAgICAgdHJhbnNjbHVkZToge1xuICAgICAgICB0b29sYmFyQnV0dG9uczogJz9ib3hUb29sYmFyQnV0dG9ucycsXG4gICAgICAgIGZvb3RlckJ1dHRvbnM6ICc/Ym94Rm9vdGVyQnV0dG9ucydcbiAgICAgIH0sXG4gICAgICBiaW5kaW5nczoge1xuICAgICAgICBib3hUaXRsZTogJ0AnLFxuICAgICAgICB0b29sYmFyQ2xhc3M6ICdAJyxcbiAgICAgICAgdG9vbGJhckJnQ29sb3I6ICdAJ1xuICAgICAgfSxcbiAgICAgIGNvbnRyb2xsZXI6IFsnJHRyYW5zY2x1ZGUnLCBmdW5jdGlvbigkdHJhbnNjbHVkZSkge1xuICAgICAgICB2YXIgY3RybCA9IHRoaXM7XG5cbiAgICAgICAgY3RybC50cmFuc2NsdWRlID0gJHRyYW5zY2x1ZGU7XG5cbiAgICAgICAgY3RybC4kb25Jbml0ID0gZnVuY3Rpb24oKSB7XG4gICAgICAgICAgaWYgKGFuZ3VsYXIuaXNVbmRlZmluZWQoY3RybC50b29sYmFyQmdDb2xvcikpIGN0cmwudG9vbGJhckJnQ29sb3IgPSAnZGVmYXVsdC1wcmltYXJ5JztcbiAgICAgICAgfTtcbiAgICAgIH1dXG4gICAgfSk7XG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29tcG9uZW50KCdjb250ZW50Qm9keScsIHtcbiAgICAgIHJlcGxhY2U6IHRydWUsXG4gICAgICB0cmFuc2NsdWRlOiB0cnVlLFxuICAgICAgdGVtcGxhdGVVcmw6IFsnR2xvYmFsJywgZnVuY3Rpb24oR2xvYmFsKSB7XG4gICAgICAgIHJldHVybiBHbG9iYWwuY2xpZW50UGF0aCArICcvd2lkZ2V0cy9jb250ZW50LWJvZHkuaHRtbCdcbiAgICAgIH1dLFxuICAgICAgYmluZGluZ3M6IHtcbiAgICAgICAgbGF5b3V0QWxpZ246ICdAJ1xuICAgICAgfSxcbiAgICAgIGNvbnRyb2xsZXI6IFtmdW5jdGlvbigpIHtcbiAgICAgICAgdmFyIGN0cmwgPSB0aGlzO1xuXG4gICAgICAgIGN0cmwuJG9uSW5pdCA9IGZ1bmN0aW9uKCkge1xuICAgICAgICAgIC8vIE1ha2UgYSBjb3B5IG9mIHRoZSBpbml0aWFsIHZhbHVlIHRvIGJlIGFibGUgdG8gcmVzZXQgaXQgbGF0ZXJcbiAgICAgICAgICBjdHJsLmxheW91dEFsaWduID0gYW5ndWxhci5pc0RlZmluZWQoY3RybC5sYXlvdXRBbGlnbikgPyBjdHJsLmxheW91dEFsaWduIDogJ2NlbnRlciBzdGFydCc7XG4gICAgICAgIH07XG4gICAgICB9XVxuICAgIH0pO1xuXG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29tcG9uZW50KCdjb250ZW50SGVhZGVyJywge1xuICAgICAgdGVtcGxhdGVVcmw6IFsnR2xvYmFsJywgZnVuY3Rpb24oR2xvYmFsKSB7XG4gICAgICAgIHJldHVybiBHbG9iYWwuY2xpZW50UGF0aCArICcvd2lkZ2V0cy9jb250ZW50LWhlYWRlci5odG1sJ1xuICAgICAgfV0sXG4gICAgICByZXBsYWNlOiB0cnVlLFxuICAgICAgYmluZGluZ3M6IHtcbiAgICAgICAgdGl0bGU6ICdAJyxcbiAgICAgICAgZGVzY3JpcHRpb246ICdAJ1xuICAgICAgfVxuICAgIH0pO1xuXG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmlsdGVyKCdhdWRpdERldGFpbFRpdGxlJywgYXVkaXREZXRhaWxUaXRsZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBhdWRpdERldGFpbFRpdGxlKCR0cmFuc2xhdGUpIHtcbiAgICByZXR1cm4gZnVuY3Rpb24oYXVkaXREZXRhaWwsIHN0YXR1cykge1xuICAgICAgaWYgKGF1ZGl0RGV0YWlsLnR5cGUgPT09ICd1cGRhdGVkJykge1xuICAgICAgICBpZiAoc3RhdHVzID09PSAnYmVmb3JlJykge1xuICAgICAgICAgIHJldHVybiAkdHJhbnNsYXRlLmluc3RhbnQoJ2RpYWxvZy5hdWRpdC51cGRhdGVkQmVmb3JlJyk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgcmV0dXJuICR0cmFuc2xhdGUuaW5zdGFudCgnZGlhbG9nLmF1ZGl0LnVwZGF0ZWRBZnRlcicpO1xuICAgICAgICB9XG4gICAgICB9IGVsc2Uge1xuICAgICAgICByZXR1cm4gJHRyYW5zbGF0ZS5pbnN0YW50KCdkaWFsb2cuYXVkaXQuJyArIGF1ZGl0RGV0YWlsLnR5cGUpO1xuICAgICAgfVxuICAgIH1cbiAgfVxuXG59KSgpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmlsdGVyKCdhdWRpdE1vZGVsJywgYXVkaXRNb2RlbCk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBhdWRpdE1vZGVsKCR0cmFuc2xhdGUpIHtcbiAgICByZXR1cm4gZnVuY3Rpb24obW9kZWxJZCkge1xuICAgICAgbW9kZWxJZCA9IG1vZGVsSWQucmVwbGFjZSgnQXBwXFxcXCcsICcnKTtcbiAgICAgIHZhciBtb2RlbCA9ICR0cmFuc2xhdGUuaW5zdGFudCgnbW9kZWxzLicgKyBtb2RlbElkLnRvTG93ZXJDYXNlKCkpO1xuXG4gICAgICByZXR1cm4gKG1vZGVsKSA/IG1vZGVsIDogbW9kZWxJZDtcbiAgICB9XG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZpbHRlcignYXVkaXRUeXBlJywgYXVkaXRUeXBlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIGF1ZGl0VHlwZShsb2Rhc2gsIEF1ZGl0U2VydmljZSkge1xuICAgIHJldHVybiBmdW5jdGlvbih0eXBlSWQpIHtcbiAgICAgIHZhciB0eXBlID0gbG9kYXNoLmZpbmQoQXVkaXRTZXJ2aWNlLmxpc3RUeXBlcygpLCB7IGlkOiB0eXBlSWQgfSk7XG5cbiAgICAgIHJldHVybiAodHlwZSkgPyB0eXBlLmxhYmVsIDogdHlwZTtcbiAgICB9XG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZpbHRlcignYXVkaXRWYWx1ZScsIGF1ZGl0VmFsdWUpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gYXVkaXRWYWx1ZSgkZmlsdGVyLCBsb2Rhc2gpIHtcbiAgICByZXR1cm4gZnVuY3Rpb24odmFsdWUsIGtleSkge1xuICAgICAgaWYgKGFuZ3VsYXIuaXNEYXRlKHZhbHVlKSB8fCBsb2Rhc2guZW5kc1dpdGgoa2V5LCAnX2F0JykgfHwgIGxvZGFzaC5lbmRzV2l0aChrZXksICdfdG8nKSkge1xuICAgICAgICByZXR1cm4gJGZpbHRlcigncHJEYXRldGltZScpKHZhbHVlKTtcbiAgICAgIH1cblxuICAgICAgaWYgKHR5cGVvZiB2YWx1ZSA9PT0gJ2Jvb2xlYW4nKSB7XG4gICAgICAgIHJldHVybiAkZmlsdGVyKCd0cmFuc2xhdGUnKSgodmFsdWUpID8gJ2dsb2JhbC55ZXMnIDogJ2dsb2JhbC5ubycpO1xuICAgICAgfVxuXG4gICAgICAvL2NoZWNrIGlzIGZsb2F0XG4gICAgICBpZiAoTnVtYmVyKHZhbHVlKSA9PT0gdmFsdWUgJiYgdmFsdWUgJSAxICE9PSAwKSB7XG4gICAgICAgIHJldHVybiAkZmlsdGVyKCdyZWFsJykodmFsdWUpO1xuICAgICAgfVxuXG4gICAgICByZXR1cm4gdmFsdWU7XG4gICAgfVxuICB9XG5cbn0pKCk7XG4iLCIvKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCwgbm8tdW5kZWY6IDAqL1xuKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnN0YW50KCdwdC1CUi5pMThuLmF0dHJpYnV0ZXMnLCB7XG4gICAgICBlbWFpbDogJ0VtYWlsJyxcbiAgICAgIHBhc3N3b3JkOiAnU2VuaGEnLFxuICAgICAgbmFtZTogJ05vbWUnLFxuICAgICAgaW1hZ2U6ICdJbWFnZW0nLFxuICAgICAgcm9sZXM6ICdQZXJmaXMnLFxuICAgICAgZGF0ZTogJ0RhdGEnLFxuICAgICAgaW5pdGlhbERhdGU6ICdEYXRhIEluaWNpYWwnLFxuICAgICAgZmluYWxEYXRlOiAnRGF0YSBGaW5hbCcsXG4gICAgICB0YXNrOiB7XG4gICAgICAgIGRlc2NyaXB0aW9uOiAnRGVzY3Jpw6fDo28nLFxuICAgICAgICBkb25lOiAnRmVpdG8/JyxcbiAgICAgICAgcHJpb3JpdHk6ICdQcmlvcmlkYWRlJyxcbiAgICAgICAgc2NoZWR1bGVkX3RvOiAnQWdlbmRhZG8gUGFyYT8nLFxuICAgICAgICBwcm9qZWN0OiAnUHJvamV0bydcbiAgICAgIH0sXG4gICAgICBwcm9qZWN0OiB7XG4gICAgICAgIGNvc3Q6ICdDdXN0bydcbiAgICAgIH0sXG4gICAgICAvL8OpIGNhcnJlZ2FkbyBkbyBzZXJ2aWRvciBjYXNvIGVzdGVqYSBkZWZpbmlkbyBubyBtZXNtb1xuICAgICAgYXVkaXRNb2RlbDoge1xuICAgICAgfVxuICAgIH0pXG5cbn0oKSk7XG4iLCIvKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCwgbm8tdW5kZWY6IDAqL1xuKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnN0YW50KCdwdC1CUi5pMThuLmRpYWxvZycsIHtcbiAgICAgIGNvbmZpcm1UaXRsZTogJ0NvbmZpcm1hw6fDo28nLFxuICAgICAgY29uZmlybURlc2NyaXB0aW9uOiAnQ29uZmlybWEgYSBhw6fDo28/JyxcbiAgICAgIHJlbW92ZURlc2NyaXB0aW9uOiAnRGVzZWphIHJlbW92ZXIgcGVybWFuZW50ZW1lbnRlIHt7bmFtZX19PycsXG4gICAgICBhdWRpdDoge1xuICAgICAgICBjcmVhdGVkOiAnSW5mb3JtYcOnw7VlcyBkbyBDYWRhc3RybycsXG4gICAgICAgIHVwZGF0ZWRCZWZvcmU6ICdBbnRlcyBkYSBBdHVhbGl6YcOnw6NvJyxcbiAgICAgICAgdXBkYXRlZEFmdGVyOiAnRGVwb2lzIGRhIEF0dWFsaXphw6fDo28nLFxuICAgICAgICBkZWxldGVkOiAnSW5mb3JtYcOnw7VlcyBhbnRlcyBkZSByZW1vdmVyJ1xuICAgICAgfSxcbiAgICAgIGxvZ2luOiB7XG4gICAgICAgIHJlc2V0UGFzc3dvcmQ6IHtcbiAgICAgICAgICBkZXNjcmlwdGlvbjogJ0RpZ2l0ZSBhYmFpeG8gbyBlbWFpbCBjYWRhc3RyYWRvIG5vIHNpc3RlbWEuJ1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfSlcblxufSgpKTtcbiIsIi8qZXNsaW50IGFuZ3VsYXIvZmlsZS1uYW1lOiAwLCBuby11bmRlZjogMCovXG4oZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uc3RhbnQoJ3B0LUJSLmkxOG4uZ2xvYmFsJywge1xuICAgICAgbG9hZGluZzogJ0NhcnJlZ2FuZG8uLi4nLFxuICAgICAgcHJvY2Vzc2luZzogJ1Byb2Nlc3NhbmRvLi4uJyxcbiAgICAgIHllczogJ1NpbScsXG4gICAgICBubzogJ07Do28nLFxuICAgICAgYWxsOiAnVG9kb3MnXG4gICAgfSlcblxufSgpKTtcbiIsIi8qZXNsaW50IGFuZ3VsYXIvZmlsZS1uYW1lOiAwLCBuby11bmRlZjogMCovXG4oZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uc3RhbnQoJ3B0LUJSLmkxOG4ubWVzc2FnZXMnLCB7XG4gICAgICBpbnRlcm5hbEVycm9yOiAnT2NvcnJldSB1bSBlcnJvIGludGVybm8sIGNvbnRhdGUgbyBhZG1pbmlzdHJhZG9yIGRvIHNpc3RlbWEnLFxuICAgICAgbm90Rm91bmQ6ICdOZW5odW0gcmVnaXN0cm8gZW5jb250cmFkbycsXG4gICAgICBub3RBdXRob3JpemVkOiAnVm9jw6ogbsOjbyB0ZW0gYWNlc3NvIGEgZXN0YSBmdW5jaW9uYWxpZGFkZS4nLFxuICAgICAgc2VhcmNoRXJyb3I6ICdOw6NvIGZvaSBwb3Nzw612ZWwgcmVhbGl6YXIgYSBidXNjYS4nLFxuICAgICAgc2F2ZVN1Y2Nlc3M6ICdSZWdpc3RybyBzYWx2byBjb20gc3VjZXNzby4nLFxuICAgICAgb3BlcmF0aW9uU3VjY2VzczogJ09wZXJhw6fDo28gcmVhbGl6YWRhIGNvbSBzdWNlc3NvLicsXG4gICAgICBvcGVyYXRpb25FcnJvcjogJ0Vycm8gYW8gcmVhbGl6YXIgYSBvcGVyYcOnw6NvJyxcbiAgICAgIHNhdmVFcnJvcjogJ0Vycm8gYW8gdGVudGFyIHNhbHZhciBvIHJlZ2lzdHJvLicsXG4gICAgICByZW1vdmVTdWNjZXNzOiAnUmVtb8Onw6NvIHJlYWxpemFkYSBjb20gc3VjZXNzby4nLFxuICAgICAgcmVtb3ZlRXJyb3I6ICdFcnJvIGFvIHRlbnRhciByZW1vdmVyIG8gcmVnaXN0cm8uJyxcbiAgICAgIHJlc291cmNlTm90Rm91bmRFcnJvcjogJ1JlY3Vyc28gbsOjbyBlbmNvbnRyYWRvJyxcbiAgICAgIG5vdE51bGxFcnJvcjogJ1RvZG9zIG9zIGNhbXBvcyBvYnJpZ2F0w7NyaW9zIGRldmVtIHNlciBwcmVlbmNoaWRvcy4nLFxuICAgICAgZHVwbGljYXRlZFJlc291cmNlRXJyb3I6ICdKw6EgZXhpc3RlIHVtIHJlY3Vyc28gY29tIGVzc2FzIGluZm9ybWHDp8O1ZXMuJyxcbiAgICAgIHZhbGlkYXRlOiB7XG4gICAgICAgIGZpZWxkUmVxdWlyZWQ6ICdPIGNhbXBvIHt7ZmllbGR9fSDDqSBvYnJpZ3JhdMOzcmlvLidcbiAgICAgIH0sXG4gICAgICBsYXlvdXQ6IHtcbiAgICAgICAgZXJyb3I0MDQ6ICdQw6FnaW5hIG7Do28gZW5jb250cmFkYSdcbiAgICAgIH0sXG4gICAgICBsb2dpbjoge1xuICAgICAgICBsb2dvdXRJbmFjdGl2ZTogJ1ZvY8OqIGZvaSBkZXNsb2dhZG8gZG8gc2lzdGVtYSBwb3IgaW5hdGl2aWRhZGUuIEZhdm9yIGVudHJhciBubyBzaXN0ZW1hIG5vdmFtZW50ZS4nLFxuICAgICAgICBpbnZhbGlkQ3JlZGVudGlhbHM6ICdDcmVkZW5jaWFpcyBJbnbDoWxpZGFzJyxcbiAgICAgICAgdW5rbm93bkVycm9yOiAnTsOjbyBmb2kgcG9zc8OtdmVsIHJlYWxpemFyIG8gbG9naW4uIFRlbnRlIG5vdmFtZW50ZS4gJyArXG4gICAgICAgICAgJ0Nhc28gbsOjbyBjb25zaWdhIGZhdm9yIGVuY29udHJhciBlbSBjb250YXRvIGNvbSBvIGFkbWluaXN0cmFkb3IgZG8gc2lzdGVtYS4nLFxuICAgICAgICB1c2VyTm90Rm91bmQ6ICdOw6NvIGZvaSBwb3Nzw612ZWwgZW5jb250cmFyIHNldXMgZGFkb3MnXG4gICAgICB9LFxuICAgICAgZGFzaGJvYXJkOiB7XG4gICAgICAgIHdlbGNvbWU6ICdTZWphIGJlbSBWaW5kbyB7e3VzZXJOYW1lfX0nLFxuICAgICAgICBkZXNjcmlwdGlvbjogJ1V0aWxpemUgbyBtZW51IHBhcmEgbmF2ZWdhw6fDo28uJ1xuICAgICAgfSxcbiAgICAgIG1haWw6IHtcbiAgICAgICAgbWFpbEVycm9yczogJ09jb3JyZXUgdW0gZXJybyBub3Mgc2VndWludGVzIGVtYWlscyBhYmFpeG86XFxuJyxcbiAgICAgICAgc2VuZE1haWxTdWNjZXNzOiAnRW1haWwgZW52aWFkbyBjb20gc3VjZXNzbyEnLFxuICAgICAgICBzZW5kTWFpbEVycm9yOiAnTsOjbyBmb2kgcG9zc8OtdmVsIGVudmlhciBvIGVtYWlsLicsXG4gICAgICAgIHBhc3N3b3JkU2VuZGluZ1N1Y2Nlc3M6ICdPIHByb2Nlc3NvIGRlIHJlY3VwZXJhw6fDo28gZGUgc2VuaGEgZm9pIGluaWNpYWRvLiBDYXNvIG8gZW1haWwgbsOjbyBjaGVndWUgZW0gMTAgbWludXRvcyB0ZW50ZSBub3ZhbWVudGUuJ1xuICAgICAgfSxcbiAgICAgIHVzZXI6IHtcbiAgICAgICAgcmVtb3ZlWW91clNlbGZFcnJvcjogJ1ZvY8OqIG7Do28gcG9kZSByZW1vdmVyIHNldSBwcsOzcHJpbyB1c3XDoXJpbycsXG4gICAgICAgIHVzZXJFeGlzdHM6ICdVc3XDoXJpbyBqw6EgYWRpY2lvbmFkbyEnLFxuICAgICAgICBwcm9maWxlOiB7XG4gICAgICAgICAgdXBkYXRlRXJyb3I6ICdOw6NvIGZvaSBwb3Nzw612ZWwgYXR1YWxpemFyIHNldSBwcm9maWxlJ1xuICAgICAgICB9XG4gICAgICB9LFxuICAgICAgcXVlcnlEaW5hbWljOiB7XG4gICAgICAgIG5vRmlsdGVyOiAnTmVuaHVtIGZpbHRybyBhZGljaW9uYWRvJ1xuICAgICAgfVxuICAgIH0pXG5cbn0oKSk7XG4iLCIvKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCwgbm8tdW5kZWY6IDAqL1xuKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnN0YW50KCdwdC1CUi5pMThuLm1vZGVscycsIHtcbiAgICAgIHVzZXI6ICdVc3XDoXJpbycsXG4gICAgICB0YXNrOiAnVGFyZWZhJyxcbiAgICAgIHByb2plY3Q6ICdQcm9qZXRvJ1xuICAgIH0pXG5cbn0oKSk7XG4iLCIvKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCwgbm8tdW5kZWY6IDAqL1xuKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnN0YW50KCdwdC1CUi5pMThuLnZpZXdzJywge1xuICAgICAgYnJlYWRjcnVtYnM6IHtcbiAgICAgICAgdXNlcjogJ0FkbWluaXN0cmHDp8OjbyAtIFVzdcOhcmlvJyxcbiAgICAgICAgJ3VzZXItcHJvZmlsZSc6ICdQZXJmaWwnLFxuICAgICAgICBkYXNoYm9hcmQ6ICdEYXNoYm9hcmQnLFxuICAgICAgICBhdWRpdDogJ0FkbWluaXN0cmHDp8OjbyAtIEF1ZGl0b3JpYScsXG4gICAgICAgIG1haWw6ICdBZG1pbmlzdHJhw6fDo28gLSBFbnZpbyBkZSBlLW1haWwnLFxuICAgICAgICBwcm9qZWN0czogJ1Byb2pldG9zJyxcbiAgICAgICAgJ2RpbmFtaWMtcXVlcnknOiAnQWRtaW5pc3RyYcOnw6NvIC0gQ29uc3VsdGFzIERpbsOibWljYXMnLFxuICAgICAgICAnbm90LWF1dGhvcml6ZWQnOiAnQWNlc3NvIE5lZ2FkbydcbiAgICAgIH0sXG4gICAgICB0aXRsZXM6IHtcbiAgICAgICAgZGFzaGJvYXJkOiAnUMOhZ2luYSBpbmljaWFsJyxcbiAgICAgICAgbWFpbFNlbmQ6ICdFbnZpYXIgZS1tYWlsJyxcbiAgICAgICAgdGFza0xpc3Q6ICdMaXN0YSBkZSBUYXJlZmFzJyxcbiAgICAgICAgdXNlckxpc3Q6ICdMaXN0YSBkZSBVc3XDoXJpb3MnLFxuICAgICAgICBhdWRpdExpc3Q6ICdMaXN0YSBkZSBMb2dzJyxcbiAgICAgICAgcmVnaXN0ZXI6ICdGb3JtdWzDoXJpbyBkZSBDYWRhc3RybycsXG4gICAgICAgIHJlc2V0UGFzc3dvcmQ6ICdSZWRlZmluaXIgU2VuaGEnLFxuICAgICAgICB1cGRhdGU6ICdGb3JtdWzDoXJpbyBkZSBBdHVhbGl6YcOnw6NvJ1xuICAgICAgfSxcbiAgICAgIGFjdGlvbnM6IHtcbiAgICAgICAgc2VuZDogJ0VudmlhcicsXG4gICAgICAgIHNhdmU6ICdTYWx2YXInLFxuICAgICAgICBjbGVhcjogJ0xpbXBhcicsXG4gICAgICAgIGNsZWFyQWxsOiAnTGltcGFyIFR1ZG8nLFxuICAgICAgICByZXN0YXJ0OiAnUmVpbmljaWFyJyxcbiAgICAgICAgZmlsdGVyOiAnRmlsdHJhcicsXG4gICAgICAgIHNlYXJjaDogJ1Blc3F1aXNhcicsXG4gICAgICAgIGxpc3Q6ICdMaXN0YXInLFxuICAgICAgICBlZGl0OiAnRWRpdGFyJyxcbiAgICAgICAgY2FuY2VsOiAnQ2FuY2VsYXInLFxuICAgICAgICB1cGRhdGU6ICdBdHVhbGl6YXInLFxuICAgICAgICByZW1vdmU6ICdSZW1vdmVyJyxcbiAgICAgICAgZ2V0T3V0OiAnU2FpcicsXG4gICAgICAgIGFkZDogJ0FkaWNpb25hcicsXG4gICAgICAgIGluOiAnRW50cmFyJyxcbiAgICAgICAgbG9hZEltYWdlOiAnQ2FycmVnYXIgSW1hZ2VtJyxcbiAgICAgICAgc2lnbnVwOiAnQ2FkYXN0cmFyJyxcbiAgICAgICAgY3JpYXJQcm9qZXRvOiAnQ3JpYXIgUHJvamV0bycsXG4gICAgICAgIHByb2plY3RMaXN0OiAnTGlzdGEgZGUgUHJvamV0b3MnXG4gICAgICB9LFxuICAgICAgZmllbGRzOiB7XG4gICAgICAgIGRhdGU6ICdEYXRhJyxcbiAgICAgICAgYWN0aW9uOiAnQcOnw6NvJyxcbiAgICAgICAgYWN0aW9uczogJ0HDp8O1ZXMnLFxuICAgICAgICBhdWRpdDoge1xuICAgICAgICAgIGRhdGVTdGFydDogJ0RhdGEgSW5pY2lhbCcsXG4gICAgICAgICAgZGF0ZUVuZDogJ0RhdGEgRmluYWwnLFxuICAgICAgICAgIHJlc291cmNlOiAnUmVjdXJzbycsXG4gICAgICAgICAgYWxsUmVzb3VyY2VzOiAnVG9kb3MgUmVjdXJzb3MnLFxuICAgICAgICAgIHR5cGU6IHtcbiAgICAgICAgICAgIGNyZWF0ZWQ6ICdDYWRhc3RyYWRvJyxcbiAgICAgICAgICAgIHVwZGF0ZWQ6ICdBdHVhbGl6YWRvJyxcbiAgICAgICAgICAgIGRlbGV0ZWQ6ICdSZW1vdmlkbydcbiAgICAgICAgICB9XG4gICAgICAgIH0sXG4gICAgICAgIGxvZ2luOiB7XG4gICAgICAgICAgcmVzZXRQYXNzd29yZDogJ0VzcXVlY2kgbWluaGEgc2VuaGEnLFxuICAgICAgICAgIGNvbmZpcm1QYXNzd29yZDogJ0NvbmZpcm1hciBzZW5oYSdcbiAgICAgICAgfSxcbiAgICAgICAgbWFpbDoge1xuICAgICAgICAgIHRvOiAnUGFyYScsXG4gICAgICAgICAgc3ViamVjdDogJ0Fzc3VudG8nLFxuICAgICAgICAgIG1lc3NhZ2U6ICdNZW5zYWdlbSdcbiAgICAgICAgfSxcbiAgICAgICAgcXVlcnlEaW5hbWljOiB7XG4gICAgICAgICAgZmlsdGVyczogJ0ZpbHRyb3MnLFxuICAgICAgICAgIHJlc3VsdHM6ICdSZXN1bHRhZG9zJyxcbiAgICAgICAgICBtb2RlbDogJ01vZGVsJyxcbiAgICAgICAgICBhdHRyaWJ1dGU6ICdBdHJpYnV0bycsXG4gICAgICAgICAgb3BlcmF0b3I6ICdPcGVyYWRvcicsXG4gICAgICAgICAgcmVzb3VyY2U6ICdSZWN1cnNvJyxcbiAgICAgICAgICB2YWx1ZTogJ1ZhbG9yJyxcbiAgICAgICAgICBvcGVyYXRvcnM6IHtcbiAgICAgICAgICAgIGVxdWFsczogJ0lndWFsJyxcbiAgICAgICAgICAgIGRpZmVyZW50OiAnRGlmZXJlbnRlJyxcbiAgICAgICAgICAgIGNvbnRlaW5zOiAnQ29udMOpbScsXG4gICAgICAgICAgICBzdGFydFdpdGg6ICdJbmljaWEgY29tJyxcbiAgICAgICAgICAgIGZpbmlzaFdpdGg6ICdGaW5hbGl6YSBjb20nLFxuICAgICAgICAgICAgYmlnZ2VyVGhhbjogJ01haW9yJyxcbiAgICAgICAgICAgIGVxdWFsc09yQmlnZ2VyVGhhbjogJ01haW9yIG91IElndWFsJyxcbiAgICAgICAgICAgIGxlc3NUaGFuOiAnTWVub3InLFxuICAgICAgICAgICAgZXF1YWxzT3JMZXNzVGhhbjogJ01lbm9yIG91IElndWFsJ1xuICAgICAgICAgIH1cbiAgICAgICAgfSxcbiAgICAgICAgcHJvamVjdDoge1xuICAgICAgICAgIG5hbWU6ICdOb21lJyxcbiAgICAgICAgICB0b3RhbFRhc2s6ICdUb3RhbCBkZSBUYXJlZmFzJ1xuICAgICAgICB9LFxuICAgICAgICB0YXNrOiB7XG4gICAgICAgICAgZG9uZTogJ07Do28gRmVpdG8gLyBGZWl0bydcbiAgICAgICAgfSxcbiAgICAgICAgdXNlcjoge1xuICAgICAgICAgIHBlcmZpbHM6ICdQZXJmaXMnLFxuICAgICAgICAgIG5hbWVPckVtYWlsOiAnTm9tZSBvdSBFbWFpbCdcbiAgICAgICAgfVxuICAgICAgfSxcbiAgICAgIGxheW91dDoge1xuICAgICAgICBtZW51OiB7XG4gICAgICAgICAgZGFzaGJvYXJkOiAnRGFzaGJvYXJkJyxcbiAgICAgICAgICBwcm9qZWN0OiAnUHJvamV0b3MnLFxuICAgICAgICAgIGFkbWluOiAnQWRtaW5pc3RyYcOnw6NvJyxcbiAgICAgICAgICBleGFtcGxlczogJ0V4ZW1wbG9zJyxcbiAgICAgICAgICB1c2VyOiAnVXN1w6FyaW9zJyxcbiAgICAgICAgICBtYWlsOiAnRW52aWFyIGUtbWFpbCcsXG4gICAgICAgICAgYXVkaXQ6ICdBdWRpdG9yaWEnLFxuICAgICAgICAgIGRpbmFtaWNRdWVyeTogJ0NvbnN1bHRhcyBEaW5hbWljYXMnXG4gICAgICAgIH1cbiAgICAgIH0sXG4gICAgICB0b29sdGlwczoge1xuICAgICAgICBhdWRpdDoge1xuICAgICAgICAgIHZpZXdEZXRhaWw6ICdWaXN1YWxpemFyIERldGFsaGFtZW50bydcbiAgICAgICAgfSxcbiAgICAgICAgdXNlcjoge1xuICAgICAgICAgIHBlcmZpbDogJ1BlcmZpbCcsXG4gICAgICAgICAgdHJhbnNmZXI6ICdUcmFuc2ZlcmlyJ1xuICAgICAgICB9LFxuICAgICAgICB0YXNrOiB7XG4gICAgICAgICAgbGlzdFRhc2s6ICdMaXN0YXIgVGFyZWZhcydcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pXG5cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb250cm9sbGVyKCdUYXNrc0RpYWxvZ0NvbnRyb2xsZXInLCBUYXNrc0RpYWxvZ0NvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gVGFza3NEaWFsb2dDb250cm9sbGVyKCRjb250cm9sbGVyLCBUYXNrc1NlcnZpY2UsIHByb2plY3RJZCwgUHJUb2FzdCwgLy8gTk9TT05BUlxuICAgIFByRGlhbG9nLCAkdHJhbnNsYXRlLCBHbG9iYWwsIG1vbWVudCkge1xuXG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIC8vRnVuY3Rpb25zIEJsb2NrXG4gICAgdm0ub25BY3RpdmF0ZSAgID0gb25BY3RpdmF0ZTtcbiAgICB2bS5jbG9zZSAgICAgICAgPSBjbG9zZTtcbiAgICB2bS5hcHBseUZpbHRlcnMgPSBhcHBseUZpbHRlcnM7XG4gICAgdm0uYmVmb3JlU2F2ZSAgID0gYmVmb3JlU2F2ZTtcbiAgICB2bS5hZnRlclNhdmUgICAgPSBhZnRlclNhdmU7XG4gICAgdm0udG9nZ2xlRG9uZSAgID0gdG9nZ2xlRG9uZTtcblxuICAgIC8vIGluc3RhbnRpYXRlIGJhc2UgY29udHJvbGxlclxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHsgdm06IHZtLCBtb2RlbFNlcnZpY2U6IFRhc2tzU2VydmljZSwgb3B0aW9uczoge1xuICAgICAgcGVyUGFnZTogNVxuICAgIH0gfSk7XG5cbiAgICBmdW5jdGlvbiBvbkFjdGl2YXRlKCkge1xuICAgICAgdm0uZ2xvYmFsID0gR2xvYmFsO1xuICAgICAgdm0ucmVzb3VyY2Uuc2NoZWR1bGVkX3RvID0gbW9tZW50KCkuYWRkKDMwLCAnbWludXRlcycpO1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0geyBwcm9qZWN0SWQ6IHByb2plY3RJZCB9O1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGFwcGx5RmlsdGVycyhkZWZhdWx0UXVlcnlGaWx0ZXJzKSB7XG4gICAgICByZXR1cm4gYW5ndWxhci5leHRlbmQoZGVmYXVsdFF1ZXJ5RmlsdGVycywgdm0ucXVlcnlGaWx0ZXJzKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBiZWZvcmVTYXZlKCkge1xuICAgICAgdm0ucmVzb3VyY2UucHJvamVjdF9pZCA9IHZtLnF1ZXJ5RmlsdGVycy5wcm9qZWN0SWQ7XG4gICAgICB2bS5yZXNvdXJjZS5wcm9qZWN0ID0gbnVsbDtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBhZnRlclNhdmUoKSB7XG4gICAgICB2bS5jbGVhbkZvcm0oKTtcbiAgICAgIHZtLnNlYXJjaCh2bS5wYWdpbmF0b3IuY3VycmVudFBhZ2UpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGNsb3NlKCkge1xuICAgICAgdm0uY2xlYW5Gb3JtKCk7XG4gICAgICBQckRpYWxvZy5jbG9zZSgpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIHRvZ2dsZURvbmUocmVzb3VyY2UpIHtcbiAgICAgIFRhc2tzU2VydmljZS50b2dnbGVEb25lKHsgaWQ6IHJlc291cmNlLmlkLCBkb25lOiByZXNvdXJjZS5kb25lIH0pLnRoZW4oZnVuY3Rpb24oKSB7XG4gICAgICAgIFByVG9hc3Quc3VjY2VzcygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnNhdmVTdWNjZXNzJykpO1xuICAgICAgICB2bS5zZWFyY2godm0ucGFnaW5hdG9yLmN1cnJlbnRQYWdlKTtcbiAgICAgIH0sIGZ1bmN0aW9uKGVycm9yKSB7XG4gICAgICAgIFByVG9hc3QuZXJyb3JWYWxpZGF0aW9uKGVycm9yLmRhdGEsICR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMub3BlcmF0aW9uRXJyb3InKSk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgfVxuXG59KSgpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZhY3RvcnkoJ1Rhc2tzU2VydmljZScsIFRhc2tzU2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiBUYXNrc1NlcnZpY2Uoc2VydmljZUZhY3RvcnksIG1vbWVudCkge1xuICAgIHJldHVybiBzZXJ2aWNlRmFjdG9yeSgndGFza3MnLCB7XG4gICAgICAvL3F1YW5kbyBpbnN0YW5jaWEgdW0gdXN1w6FyaW8gc2VtIHBhc3NhciBwYXJhbWV0cm8sXG4gICAgICAvL28gbWVzbW8gdmFpIHRlciBvcyB2YWxvcmVzIGRlZmF1bHRzIGFiYWl4b1xuICAgICAgZGVmYXVsdHM6IHtcbiAgICAgICAgc2NoZWR1bGVkX3RvOiBuZXcgRGF0ZSgpXG4gICAgICB9LFxuXG4gICAgICBtYXA6IHtcbiAgICAgICAgLy9jb252ZXJ0IHBhcmEgb2JqZXRvIGphdmFzY3JpcHQgZGF0ZSB1bWEgc3RyaW5nIGZvcm1hdGFkYSBjb21vIGRhdGFcbiAgICAgICAgc2NoZWR1bGVkX3RvOiBmdW5jdGlvbih2YWx1ZSkge1xuICAgICAgICAgIHJldHVybiBtb21lbnQodmFsdWUpLnRvRGF0ZSgpO1xuICAgICAgICB9XG4gICAgICB9LFxuXG4gICAgICBhY3Rpb25zOiB7XG4gICAgICAgIC8qKlxuICAgICAgICAgKiBBdHVhbGl6YSBvcyBzdGF0dXMgZGEgdGFyZWZhXG4gICAgICAgICAqXG4gICAgICAgICAqIEBwYXJhbSB7b2JqZWN0fSBhdHRyaWJ1dGVzXG4gICAgICAgICAqL1xuICAgICAgICB0b2dnbGVEb25lOiB7XG4gICAgICAgICAgbWV0aG9kOiAnUFVUJyxcbiAgICAgICAgICB1cmw6ICd0b2dnbGVEb25lJ1xuICAgICAgICB9XG4gICAgICB9LFxuICAgICAgaW5zdGFuY2U6IHsgfVxuICAgIH0pO1xuICB9XG5cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb250cm9sbGVyKCdVc2Vyc0RpYWxvZ0NvbnRyb2xsZXInLCBVc2Vyc0RpYWxvZ0NvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gVXNlcnNEaWFsb2dDb250cm9sbGVyKCRjb250cm9sbGVyLCBVc2Vyc1NlcnZpY2UsIFByRGlhbG9nLCAgLy8gTk9TT05BUlxuICAgIHVzZXJEaWFsb2dJbnB1dCwgb25Jbml0KSB7XG5cbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0ub25BY3RpdmF0ZSA9IG9uQWN0aXZhdGU7XG4gICAgdm0uYXBwbHlGaWx0ZXJzID0gYXBwbHlGaWx0ZXJzO1xuICAgIHZtLmNsb3NlID0gY2xvc2U7XG5cbiAgICBpZiAoYW5ndWxhci5pc0RlZmluZWQodXNlckRpYWxvZ0lucHV0KSkge1xuICAgICAgdm0udHJhbnNmZXJVc2VyID0gdXNlckRpYWxvZ0lucHV0LnRyYW5zZmVyVXNlckZuO1xuICAgIH1cblxuICAgIC8vIGluc3RhbnRpYXRlIGJhc2UgY29udHJvbGxlclxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHtcbiAgICAgIHZtOiB2bSxcbiAgICAgIG1vZGVsU2VydmljZTogVXNlcnNTZXJ2aWNlLFxuICAgICAgc2VhcmNoT25Jbml0OiBvbkluaXQsXG4gICAgICBvcHRpb25zOiB7XG4gICAgICAgIHBlclBhZ2U6IDVcbiAgICAgIH1cbiAgICB9KTtcblxuICAgIGZ1bmN0aW9uIG9uQWN0aXZhdGUoKSB7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMgPSB7fTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBhcHBseUZpbHRlcnMoKSB7XG4gICAgICByZXR1cm4gYW5ndWxhci5leHRlbmQodm0uZGVmYXVsdFF1ZXJ5RmlsdGVycywgdm0ucXVlcnlGaWx0ZXJzKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBjbG9zZSgpIHtcbiAgICAgIFByRGlhbG9nLmNsb3NlKCk7XG4gICAgfVxuXG4gIH1cblxufSkoKTtcbiJdLCJzb3VyY2VSb290IjoiL3NvdXJjZS8ifQ==
