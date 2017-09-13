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
      vm.itensMenu = [{ state: 'app.projects', title: menuPrefix + 'dashboard', icon: 'dashboard', subItens: [] },
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

  ProjectsController.$inject = ["Global", "$controller", "ProjectsService", "Auth", "RolesService", "UsersService"];
  angular.module('app').controller('ProjectsController', ProjectsController);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function ProjectsController(Global, $controller, ProjectsService, Auth, RolesService, UsersService) {
    var vm = this;

    //Attributes Block

    //Functions Block
    vm.onActivate = onActivate;
    vm.applyFilters = applyFilters;
    vm.beforeSave = beforeSave;
    vm.searchUser = searchUser;
    vm.addUser = addUser;
    vm.removeUser = removeUser;

    vm.roles = {};

    function onActivate() {
      vm.queryFilters = { user_id: Auth.currentUser.id };
      RolesService.query().then(function (response) {
        vm.roles = response;
      });
    }

    function applyFilters(defaultQueryFilters) {
      return angular.extend(defaultQueryFilters, vm.querylters);
    }

    function beforeSave() {
      vm.resource.owner = Auth.currentUser.id;
      vm.resource.user_id = Auth.currentUser.id;
    }

    function searchUser(text) {
      return UsersService.query({ name: vm.userName });
    }

    function addUser(user) {
      if (user) {
        vm.resource.users.push(user);
        vm.userName = '';
      }
    }

    function removeUser(index) {
      vm.resource.users.splice(index, 1);
    }

    function applyFilters(defaultQueryFilters) {
      return angular.extend(defaultQueryFilters, vm.queryFilters);
    }

    // instantiate base controller
    $controller('CRUDController', { vm: vm, modelService: ProjectsService, options: {} });
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImFwcGxpY2F0aW9uLmpzIiwiYXBwLmpzIiwiYXBwLmNvbmZpZy5qcyIsImFwcC5jb250cm9sbGVyLmpzIiwiYXBwLmV4dGVybmFsLmpzIiwiYXBwLmdsb2JhbC5qcyIsImFwcC5yb3V0ZXMuanMiLCJhcHAucnVuLmpzIiwiYXVkaXQvYXVkaXQuY29udHJvbGxlci5qcyIsImF1ZGl0L2F1ZGl0LnJvdXRlLmpzIiwiYXVkaXQvYXVkaXQuc2VydmljZS5qcyIsImF1dGgvYXV0aC5yb3V0ZS5qcyIsImF1dGgvYXV0aC5zZXJ2aWNlLmpzIiwiYXV0aC9sb2dpbi5jb250cm9sbGVyLmpzIiwiYXV0aC9wYXNzd29yZC5jb250cm9sbGVyLmpzIiwiY29yZS9iYXNlLnNlcnZpY2UuanMiLCJjb3JlL2NydWQuY29udHJvbGxlci5qcyIsImRpbmFtaWMtcXVlcnlzL2RpbmFtaWMtcXVlcnkucm91dGUuanMiLCJkaW5hbWljLXF1ZXJ5cy9kaW5hbWljLXF1ZXJ5LnNlcnZpY2UuanMiLCJkaW5hbWljLXF1ZXJ5cy9kaW5hbWljLXF1ZXJ5cy5jb250cm9sbGVyLmpzIiwiaTE4bi9sYW5ndWFnZS1sb2FkZXIuc2VydmljZS5qcyIsImkxOG4vdC1hdHRyLmZpbHRlci5qcyIsImkxOG4vdC1icmVhZGNydW1iLmZpbHRlci5qcyIsImkxOG4vdC1tb2RlbC5maWx0ZXIuanMiLCJpbnRlcmNlcHRvcnMvYXV0aGVudGljYXRpb24ubGlzdGVuZXIuanMiLCJpbnRlcmNlcHRvcnMvYXV0aG9yaXphdGlvbi5saXN0ZW5lci5qcyIsImludGVyY2VwdG9ycy9zcGlubmVyLmludGVyY2VwdG9yLmpzIiwiaW50ZXJjZXB0b3JzL3Rva2VuLmludGVyY2VwdG9yLmpzIiwiaW50ZXJjZXB0b3JzL3ZhbGlkYXRpb24uaW50ZXJjZXB0b3IuanMiLCJsYXlvdXQvbWVudS5jb250cm9sbGVyLmpzIiwibWFpbC9tYWlscy5jb250cm9sbGVyLmpzIiwibWFpbC9tYWlscy5yb3V0ZS5qcyIsIm1haWwvbWFpbHMuc2VydmljZS5qcyIsInByb2plY3RzL3Byb2plY3RzLmNvbnRyb2xsZXIuanMiLCJwcm9qZWN0cy9wcm9qZWN0cy5yb3V0ZS5qcyIsInByb2plY3RzL3Byb2plY3RzLnNlcnZpY2UuanMiLCJyb2xlcy9yb2xlcy1zdHIuZmlsdGVyLmpzIiwicm9sZXMvcm9sZXMuc2VydmljZS5qcyIsInN1cHBvcnQvc3VwcG9ydC5zZXJ2aWNlLmpzIiwidXNlcnMvcHJvZmlsZS5jb250cm9sbGVyLmpzIiwidXNlcnMvdXNlcnMuY29udHJvbGxlci5qcyIsInVzZXJzL3VzZXJzLnJvdXRlLmpzIiwidXNlcnMvdXNlcnMuc2VydmljZS5qcyIsIndpZGdldHMvYm94LmNvbXBvbmVudC5qcyIsIndpZGdldHMvY29udGVudC1ib2R5LmNvbXBvbmVudC5qcyIsIndpZGdldHMvY29udGVudC1oZWFkZXIuY29tcG9uZW50LmpzIiwiYXVkaXQvZmlsdGVycy9hdWRpdC1kZXRhaWwtdGl0bGUuZmlsdGVyLmpzIiwiYXVkaXQvZmlsdGVycy9hdWRpdC1tb2RlbC5maWx0ZXIuanMiLCJhdWRpdC9maWx0ZXJzL2F1ZGl0LXR5cGUuZmlsdGVyLmpzIiwiYXVkaXQvZmlsdGVycy9hdWRpdC12YWx1ZS5maWx0ZXIuanMiLCJpMThuL3B0LUJSL2F0dHJpYnV0ZXMuanMiLCJpMThuL3B0LUJSL2RpYWxvZy5qcyIsImkxOG4vcHQtQlIvZ2xvYmFsLmpzIiwiaTE4bi9wdC1CUi9tZXNzYWdlcy5qcyIsImkxOG4vcHQtQlIvbW9kZWxzLmpzIiwiaTE4bi9wdC1CUi92aWV3cy5qcyIsInNhbXBsZXMvdGFza3MvdGFza3MtZGlhbG9nLmNvbnRyb2xsZXIuanMiLCJzYW1wbGVzL3Rhc2tzL3Rhc2tzLnNlcnZpY2UuanMiLCJ1c2Vycy9kaWFsb2cvdXNlcnMtZGlhbG9nLmNvbnRyb2xsZXIuanMiXSwibmFtZXMiOlsiYW5ndWxhciIsIm1vZHVsZSIsImNvbmZpZyIsIkdsb2JhbCIsIiRtZFRoZW1pbmdQcm92aWRlciIsIiRtb2RlbEZhY3RvcnlQcm92aWRlciIsIiR0cmFuc2xhdGVQcm92aWRlciIsIm1vbWVudCIsIiRtZEFyaWFQcm92aWRlciIsInVzZUxvYWRlciIsInVzZVNhbml0aXplVmFsdWVTdHJhdGVneSIsInVzZVBvc3RDb21waWxpbmciLCJsb2NhbGUiLCJkZWZhdWx0T3B0aW9ucyIsInByZWZpeCIsImFwaVBhdGgiLCJ0aGVtZSIsInByaW1hcnlQYWxldHRlIiwiZGVmYXVsdCIsImFjY2VudFBhbGV0dGUiLCJ3YXJuUGFsZXR0ZSIsImVuYWJsZUJyb3dzZXJDb2xvciIsImRpc2FibGVXYXJuaW5ncyIsImNvbnRyb2xsZXIiLCJBcHBDb250cm9sbGVyIiwiJHN0YXRlIiwiQXV0aCIsInZtIiwiYW5vQXR1YWwiLCJsb2dvdXQiLCJnZXRJbWFnZVBlcmZpbCIsImFjdGl2YXRlIiwiZGF0ZSIsIkRhdGUiLCJnZXRGdWxsWWVhciIsInRoZW4iLCJnbyIsImxvZ2luU3RhdGUiLCJjdXJyZW50VXNlciIsImltYWdlIiwiaW1hZ2VQYXRoIiwiY29uc3RhbnQiLCJfIiwiYXBwTmFtZSIsImhvbWVTdGF0ZSIsImxvZ2luVXJsIiwicmVzZXRQYXNzd29yZFN0YXRlIiwibm90QXV0aG9yaXplZFN0YXRlIiwidG9rZW5LZXkiLCJjbGllbnRQYXRoIiwicm91dGVzIiwiJHN0YXRlUHJvdmlkZXIiLCIkdXJsUm91dGVyUHJvdmlkZXIiLCJzdGF0ZSIsInVybCIsInRlbXBsYXRlVXJsIiwiYWJzdHJhY3QiLCJyZXNvbHZlIiwidHJhbnNsYXRlUmVhZHkiLCIkdHJhbnNsYXRlIiwiJHEiLCJkZWZlcnJlZCIsImRlZmVyIiwidXNlIiwicHJvbWlzZSIsImRhdGEiLCJuZWVkQXV0aGVudGljYXRpb24iLCJ3aGVuIiwib3RoZXJ3aXNlIiwicnVuIiwiJHJvb3RTY29wZSIsIiRzdGF0ZVBhcmFtcyIsImF1dGgiLCJnbG9iYWwiLCJyZXRyaWV2ZVVzZXJGcm9tTG9jYWxTdG9yYWdlIiwiQXVkaXRDb250cm9sbGVyIiwiJGNvbnRyb2xsZXIiLCJBdWRpdFNlcnZpY2UiLCJQckRpYWxvZyIsIm9uQWN0aXZhdGUiLCJhcHBseUZpbHRlcnMiLCJ2aWV3RGV0YWlsIiwibW9kZWxTZXJ2aWNlIiwib3B0aW9ucyIsIm1vZGVscyIsInF1ZXJ5RmlsdGVycyIsImdldEF1ZGl0ZWRNb2RlbHMiLCJpZCIsImxhYmVsIiwiaW5zdGFudCIsInNvcnQiLCJpbmRleCIsImxlbmd0aCIsIm1vZGVsIiwicHVzaCIsInRvTG93ZXJDYXNlIiwidHlwZXMiLCJsaXN0VHlwZXMiLCJ0eXBlIiwiZGVmYXVsdFF1ZXJ5RmlsdGVycyIsImV4dGVuZCIsImF1ZGl0RGV0YWlsIiwibG9jYWxzIiwiY2xvc2UiLCJpc0FycmF5Iiwib2xkIiwibmV3IiwiY29udHJvbGxlckFzIiwiaGFzQmFja2Ryb3AiLCJjdXN0b20iLCJuZWVkUHJvZmlsZSIsImZhY3RvcnkiLCJzZXJ2aWNlRmFjdG9yeSIsImFjdGlvbnMiLCJtZXRob2QiLCJpbnN0YW5jZSIsImF1ZGl0UGF0aCIsIiRodHRwIiwiVXNlcnNTZXJ2aWNlIiwibG9naW4iLCJ1cGRhdGVDdXJyZW50VXNlciIsImF1dGhlbnRpY2F0ZWQiLCJzZW5kRW1haWxSZXNldFBhc3N3b3JkIiwicmVtb3RlVmFsaWRhdGVUb2tlbiIsImdldFRva2VuIiwic2V0VG9rZW4iLCJjbGVhclRva2VuIiwibG9jYWxTdG9yYWdlIiwicmVtb3ZlSXRlbSIsInRva2VuIiwic2V0SXRlbSIsImdldEl0ZW0iLCJnZXQiLCJyZWplY3QiLCJ1c2VyIiwibWVyZ2UiLCJmcm9tSnNvbiIsImpzb25Vc2VyIiwidG9Kc29uIiwiY3JlZGVudGlhbHMiLCJwb3N0IiwicmVzcG9uc2UiLCJlcnJvciIsInJlc2V0RGF0YSIsIkxvZ2luQ29udHJvbGxlciIsIm9wZW5EaWFsb2dSZXNldFBhc3MiLCJvcGVuRGlhbG9nU2lnblVwIiwiZW1haWwiLCJwYXNzd29yZCIsIlBhc3N3b3JkQ29udHJvbGxlciIsIiR0aW1lb3V0IiwiUHJUb2FzdCIsInNlbmRSZXNldCIsImNsb3NlRGlhbG9nIiwiY2xlYW5Gb3JtIiwicmVzZXQiLCJzdWNjZXNzIiwic3RhdHVzIiwibXNnIiwiaSIsInRvVXBwZXJDYXNlIiwiZmllbGQiLCJtZXNzYWdlIiwiJG1vZGVsRmFjdG9yeSIsInBhZ2luYXRlIiwid3JhcCIsImFmdGVyUmVxdWVzdCIsIkxpc3QiLCJDUlVEQ29udHJvbGxlciIsIlByUGFnaW5hdGlvbiIsInNlYXJjaCIsInBhZ2luYXRlU2VhcmNoIiwibm9ybWFsU2VhcmNoIiwiZWRpdCIsInNhdmUiLCJyZW1vdmUiLCJnb1RvIiwicmVkaXJlY3RBZnRlclNhdmUiLCJzZWFyY2hPbkluaXQiLCJwZXJQYWdlIiwic2tpcFBhZ2luYXRpb24iLCJ2aWV3Rm9ybSIsInJlc291cmNlIiwiaXNGdW5jdGlvbiIsInBhZ2luYXRvciIsImdldEluc3RhbmNlIiwicGFnZSIsImN1cnJlbnRQYWdlIiwiaXNEZWZpbmVkIiwiYmVmb3JlU2VhcmNoIiwiY2FsY051bWJlck9mUGFnZXMiLCJ0b3RhbCIsInJlc291cmNlcyIsIml0ZW1zIiwiYWZ0ZXJTZWFyY2giLCJxdWVyeSIsImZvcm0iLCJiZWZvcmVDbGVhbiIsIiRzZXRQcmlzdGluZSIsIiRzZXRVbnRvdWNoZWQiLCJhZnRlckNsZWFuIiwiY29weSIsImFmdGVyRWRpdCIsImJlZm9yZVNhdmUiLCIkc2F2ZSIsImFmdGVyU2F2ZSIsInJlc3BvbnNlRGF0YSIsIm9uU2F2ZUVycm9yIiwidGl0bGUiLCJkZXNjcmlwdGlvbiIsImNvbmZpcm0iLCJiZWZvcmVSZW1vdmUiLCIkZGVzdHJveSIsImFmdGVyUmVtb3ZlIiwiaW5mbyIsInZpZXdOYW1lIiwiRGluYW1pY1F1ZXJ5U2VydmljZSIsImdldE1vZGVscyIsIkRpbmFtaWNRdWVyeXNDb250cm9sbGVyIiwibG9kYXNoIiwibG9hZEF0dHJpYnV0ZXMiLCJsb2FkT3BlcmF0b3JzIiwiYWRkRmlsdGVyIiwicnVuRmlsdGVyIiwiZWRpdEZpbHRlciIsImxvYWRNb2RlbHMiLCJyZW1vdmVGaWx0ZXIiLCJjbGVhciIsInJlc3RhcnQiLCJ3aGVyZSIsImFkZGVkRmlsdGVycyIsIm5hbWUiLCJmaWx0ZXIiLCJhdHRyaWJ1dGUiLCJvcGVyYXRvciIsInZhbHVlIiwiZmlsdGVycyIsImF0dHJpYnV0ZXMiLCJvcGVyYXRvcnMiLCJpbmRleE9mIiwiaXNVbmRlZmluZWQiLCJrZXlzIiwiT2JqZWN0Iiwia2V5Iiwic3RhcnRzV2l0aCIsIiRpbmRleCIsInNwbGljZSIsIkxhbmd1YWdlTG9hZGVyIiwiU3VwcG9ydFNlcnZpY2UiLCIkbG9nIiwiJGluamVjdG9yIiwic2VydmljZSIsInRyYW5zbGF0ZSIsInZpZXdzIiwiZGlhbG9nIiwibWVzc2FnZXMiLCJsYW5ncyIsInRBdHRyIiwiJGZpbHRlciIsInRCcmVhZGNydW1iIiwic3BsaXQiLCJ0TW9kZWwiLCJhdXRoZW50aWNhdGlvbkxpc3RlbmVyIiwiJG9uIiwiZXZlbnQiLCJ0b1N0YXRlIiwiY2F0Y2giLCJ3YXJuIiwicHJldmVudERlZmF1bHQiLCJhdXRob3JpemF0aW9uTGlzdGVuZXIiLCJoYXNQcm9maWxlIiwiYWxsUHJvZmlsZXMiLCJzcGlubmVySW50ZXJjZXB0b3IiLCIkaHR0cFByb3ZpZGVyIiwiJHByb3ZpZGUiLCJzaG93SGlkZVNwaW5uZXIiLCJyZXF1ZXN0Iiwic2hvdyIsImhpZGUiLCJyZXNwb25zZUVycm9yIiwicmVqZWN0aW9uIiwiaW50ZXJjZXB0b3JzIiwidG9rZW5JbnRlcmNlcHRvciIsInJlZGlyZWN0V2hlblNlcnZlckxvZ2dlZE91dCIsImhlYWRlcnMiLCJyZWplY3Rpb25SZWFzb25zIiwidG9rZW5FcnJvciIsImZvckVhY2giLCJpcyIsInZhbGlkYXRpb25JbnRlcmNlcHRvciIsInNob3dFcnJvclZhbGlkYXRpb24iLCJza2lwVmFsaWRhdGlvbiIsImVycm9yVmFsaWRhdGlvbiIsIk1lbnVDb250cm9sbGVyIiwiJG1kU2lkZW5hdiIsIiRtZENvbG9ycyIsIm9wZW4iLCJvcGVuTWVudU9yUmVkaXJlY3RUb1N0YXRlIiwibWVudVByZWZpeCIsIml0ZW5zTWVudSIsImljb24iLCJzdWJJdGVucyIsInByb2ZpbGVzIiwic2lkZW5hdlN0eWxlIiwidG9wIiwiZ2V0Q29sb3IiLCJjb250ZW50IiwidGV4dENvbG9yIiwiY29sb3IiLCJsaW5lQm90dG9tIiwidG9nZ2xlIiwiJG1kTWVudSIsImV2IiwiaXRlbSIsImNvbG9yUGFsZXR0ZXMiLCJnZXRUaGVtZUNvbG9yIiwiTWFpbHNDb250cm9sbGVyIiwiTWFpbHNTZXJ2aWNlIiwiZmlsdGVyU2VsZWN0ZWQiLCJza2luIiwibGFuZ3VhZ2UiLCJhbGxvd2VkQ29udGVudCIsImVudGl0aWVzIiwiaGVpZ2h0IiwiZXh0cmFQbHVnaW5zIiwibG9hZFVzZXJzIiwib3BlblVzZXJEaWFsb2ciLCJhZGRVc2VyTWFpbCIsInNlbmQiLCJjcml0ZXJpYSIsIm5hbWVPckVtYWlsIiwibm90VXNlcnMiLCJtYXAiLCJtYWlsIiwidXNlcnMiLCJwcm9wZXJ0eSIsInRvU3RyaW5nIiwibGltaXQiLCJmaW5kIiwib25Jbml0IiwidXNlckRpYWxvZ0lucHV0IiwidHJhbnNmZXJVc2VyRm4iLCJQcm9qZWN0c0NvbnRyb2xsZXIiLCJQcm9qZWN0c1NlcnZpY2UiLCJSb2xlc1NlcnZpY2UiLCJzZWFyY2hVc2VyIiwiYWRkVXNlciIsInJlbW92ZVVzZXIiLCJyb2xlcyIsInVzZXJfaWQiLCJxdWVyeWx0ZXJzIiwib3duZXIiLCJ0ZXh0IiwidXNlck5hbWUiLCJyb2xlc1N0ciIsImpvaW4iLCJjYWNoZSIsIlByb2ZpbGVDb250cm9sbGVyIiwidXBkYXRlIiwidXBkYXRlUHJvZmlsZSIsIlVzZXJzQ29udHJvbGxlciIsImRlZmF1bHRzIiwib3ZlcnJpZGUiLCJhbGwiLCJ1c2VyUm9sZXMiLCJpbnRlcnNlY3Rpb24iLCJpc0FkbWluIiwiY29tcG9uZW50IiwicmVwbGFjZSIsInRyYW5zY2x1ZGUiLCJ0b29sYmFyQnV0dG9ucyIsImZvb3RlckJ1dHRvbnMiLCJiaW5kaW5ncyIsImJveFRpdGxlIiwidG9vbGJhckNsYXNzIiwidG9vbGJhckJnQ29sb3IiLCIkdHJhbnNjbHVkZSIsImN0cmwiLCIkb25Jbml0IiwibGF5b3V0QWxpZ24iLCJhdWRpdERldGFpbFRpdGxlIiwiYXVkaXRNb2RlbCIsIm1vZGVsSWQiLCJhdWRpdFR5cGUiLCJ0eXBlSWQiLCJhdWRpdFZhbHVlIiwiaXNEYXRlIiwiZW5kc1dpdGgiLCJOdW1iZXIiLCJpbml0aWFsRGF0ZSIsImZpbmFsRGF0ZSIsInRhc2siLCJkb25lIiwicHJpb3JpdHkiLCJzY2hlZHVsZWRfdG8iLCJwcm9qZWN0IiwiY29zdCIsImNvbmZpcm1UaXRsZSIsImNvbmZpcm1EZXNjcmlwdGlvbiIsInJlbW92ZURlc2NyaXB0aW9uIiwiYXVkaXQiLCJjcmVhdGVkIiwidXBkYXRlZEJlZm9yZSIsInVwZGF0ZWRBZnRlciIsImRlbGV0ZWQiLCJyZXNldFBhc3N3b3JkIiwibG9hZGluZyIsInByb2Nlc3NpbmciLCJ5ZXMiLCJubyIsImludGVybmFsRXJyb3IiLCJub3RGb3VuZCIsIm5vdEF1dGhvcml6ZWQiLCJzZWFyY2hFcnJvciIsInNhdmVTdWNjZXNzIiwib3BlcmF0aW9uU3VjY2VzcyIsIm9wZXJhdGlvbkVycm9yIiwic2F2ZUVycm9yIiwicmVtb3ZlU3VjY2VzcyIsInJlbW92ZUVycm9yIiwicmVzb3VyY2VOb3RGb3VuZEVycm9yIiwibm90TnVsbEVycm9yIiwiZHVwbGljYXRlZFJlc291cmNlRXJyb3IiLCJ2YWxpZGF0ZSIsImZpZWxkUmVxdWlyZWQiLCJsYXlvdXQiLCJlcnJvcjQwNCIsImxvZ291dEluYWN0aXZlIiwiaW52YWxpZENyZWRlbnRpYWxzIiwidW5rbm93bkVycm9yIiwidXNlck5vdEZvdW5kIiwiZGFzaGJvYXJkIiwid2VsY29tZSIsIm1haWxFcnJvcnMiLCJzZW5kTWFpbFN1Y2Nlc3MiLCJzZW5kTWFpbEVycm9yIiwicGFzc3dvcmRTZW5kaW5nU3VjY2VzcyIsInJlbW92ZVlvdXJTZWxmRXJyb3IiLCJ1c2VyRXhpc3RzIiwicHJvZmlsZSIsInVwZGF0ZUVycm9yIiwicXVlcnlEaW5hbWljIiwibm9GaWx0ZXIiLCJicmVhZGNydW1icyIsInByb2plY3RzIiwidGl0bGVzIiwibWFpbFNlbmQiLCJ0YXNrTGlzdCIsInVzZXJMaXN0IiwiYXVkaXRMaXN0IiwicmVnaXN0ZXIiLCJjbGVhckFsbCIsImxpc3QiLCJjYW5jZWwiLCJnZXRPdXQiLCJhZGQiLCJpbiIsImxvYWRJbWFnZSIsInNpZ251cCIsImNyaWFyUHJvamV0byIsInByb2plY3RMaXN0IiwiZmllbGRzIiwiYWN0aW9uIiwiZGF0ZVN0YXJ0IiwiZGF0ZUVuZCIsImFsbFJlc291cmNlcyIsInVwZGF0ZWQiLCJjb25maXJtUGFzc3dvcmQiLCJ0byIsInN1YmplY3QiLCJyZXN1bHRzIiwiZXF1YWxzIiwiZGlmZXJlbnQiLCJjb250ZWlucyIsInN0YXJ0V2l0aCIsImZpbmlzaFdpdGgiLCJiaWdnZXJUaGFuIiwiZXF1YWxzT3JCaWdnZXJUaGFuIiwibGVzc1RoYW4iLCJlcXVhbHNPckxlc3NUaGFuIiwidG90YWxUYXNrIiwicGVyZmlscyIsIm1lbnUiLCJhZG1pbiIsImV4YW1wbGVzIiwiZGluYW1pY1F1ZXJ5IiwidG9vbHRpcHMiLCJwZXJmaWwiLCJ0cmFuc2ZlciIsImxpc3RUYXNrIiwiVGFza3NEaWFsb2dDb250cm9sbGVyIiwiVGFza3NTZXJ2aWNlIiwicHJvamVjdElkIiwidG9nZ2xlRG9uZSIsInByb2plY3RfaWQiLCJ0b0RhdGUiLCJVc2Vyc0RpYWxvZ0NvbnRyb2xsZXIiLCJ0cmFuc2ZlclVzZXIiXSwibWFwcGluZ3MiOiJBQUFBOzs7QUNDQSxDQUFDLFlBQVc7RUFDVjs7RUFFQUEsUUFBUUMsT0FBTyxPQUFPLENBQ3BCLGFBQ0EsVUFDQSxhQUNBLFlBQ0Esa0JBQ0EsYUFDQSxjQUNBLGdCQUNBLGlCQUNBLHdCQUNBLDBCQUNBOztBRFJKOztBRVJDLENBQUEsWUFBWTtFQUNYOzs7RUFFQUQsUUFDR0MsT0FBTyxPQUNQQyxPQUFPQTs7OztFQUlWLFNBQVNBLE9BQU9DLFFBQVFDLG9CQUFvQkM7RUFDMUNDLG9CQUFvQkMsUUFBUUMsaUJBQWlCOztJQUU3Q0Ys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LFNBQVNrQixRQUFRO01BQ2Z6QixTQUFTeUI7OztLQTFDZiIsImZpbGUiOiJhcHBsaWNhdGlvbi5qcyIsInNvdXJjZXNDb250ZW50IjpbIid1c2Ugc3RyaWN0JztcblxuLyplc2xpbnQgYW5ndWxhci9maWxlLW5hbWU6IDAqL1xuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnLCBbJ25nQW5pbWF0ZScsICduZ0FyaWEnLCAndWkucm91dGVyJywgJ25nUHJvZGViJywgJ3VpLnV0aWxzLm1hc2tzJywgJ3RleHQtbWFzaycsICduZ01hdGVyaWFsJywgJ21vZGVsRmFjdG9yeScsICdtZC5kYXRhLnRhYmxlJywgJ25nTWF0ZXJpYWxEYXRlUGlja2VyJywgJ3Bhc2NhbHByZWNodC50cmFuc2xhdGUnLCAnYW5ndWxhckZpbGVVcGxvYWQnXSk7XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbmZpZyhjb25maWcpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gY29uZmlnKEdsb2JhbCwgJG1kVGhlbWluZ1Byb3ZpZGVyLCAkbW9kZWxGYWN0b3J5UHJvdmlkZXIsIC8vIE5PU09OQVJcbiAgJHRyYW5zbGF0ZVByb3ZpZGVyLCBtb21lbnQsICRtZEFyaWFQcm92aWRlcikge1xuXG4gICAgJHRyYW5zbGF0ZVByb3ZpZGVyLnVzZUxvYWRlcignbGFuZ3VhZ2VMb2FkZXInKS51c2VTYW5pdGl6ZVZhbHVlU3RyYXRlZ3koJ2VzY2FwZScpO1xuXG4gICAgJHRyYW5zbGF0ZVByb3ZpZGVyLnVzZVBvc3RDb21waWxpbmcodHJ1ZSk7XG5cbiAgICBtb21lbnQubG9jYWxlKCdwdC1CUicpO1xuXG4gICAgLy9vcyBzZXJ2acOnb3MgcmVmZXJlbnRlIGFvcyBtb2RlbHMgdmFpIHV0aWxpemFyIGNvbW8gYmFzZSBuYXMgdXJsc1xuICAgICRtb2RlbEZhY3RvcnlQcm92aWRlci5kZWZhdWx0T3B0aW9ucy5wcmVmaXggPSBHbG9iYWwuYXBpUGF0aDtcblxuICAgIC8vIENvbmZpZ3VyYXRpb24gdGhlbWVcbiAgICAkbWRUaGVtaW5nUHJvdmlkZXIudGhlbWUoJ2RlZmF1bHQnKS5wcmltYXJ5UGFsZXR0ZSgnYnJvd24nLCB7XG4gICAgICBkZWZhdWx0OiAnNzAwJ1xuICAgIH0pLmFjY2VudFBhbGV0dGUoJ2FtYmVyJykud2FyblBhbGV0dGUoJ2RlZXAtb3JhbmdlJyk7XG5cbiAgICAvLyBFbmFibGUgYnJvd3NlciBjb2xvclxuICAgICRtZFRoZW1pbmdQcm92aWRlci5lbmFibGVCcm93c2VyQ29sb3IoKTtcblxuICAgICRtZEFyaWFQcm92aWRlci5kaXNhYmxlV2FybmluZ3MoKTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbnRyb2xsZXIoJ0FwcENvbnRyb2xsZXInLCBBcHBDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8qKlxuICAgKiBDb250cm9sYWRvciByZXNwb25zw6F2ZWwgcG9yIGZ1bmNpb25hbGlkYWRlcyBxdWUgc8OjbyBhY2lvbmFkYXMgZW0gcXVhbHF1ZXIgdGVsYSBkbyBzaXN0ZW1hXG4gICAqXG4gICAqL1xuICBmdW5jdGlvbiBBcHBDb250cm9sbGVyKCRzdGF0ZSwgQXV0aCwgR2xvYmFsKSB7XG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIC8vYW5vIGF0dWFsIHBhcmEgc2VyIGV4aWJpZG8gbm8gcm9kYXDDqSBkbyBzaXN0ZW1hXG4gICAgdm0uYW5vQXR1YWwgPSBudWxsO1xuXG4gICAgdm0ubG9nb3V0ID0gbG9nb3V0O1xuICAgIHZtLmdldEltYWdlUGVyZmlsID0gZ2V0SW1hZ2VQZXJmaWw7XG5cbiAgICBhY3RpdmF0ZSgpO1xuXG4gICAgZnVuY3Rpb24gYWN0aXZhdGUoKSB7XG4gICAgICB2YXIgZGF0ZSA9IG5ldyBEYXRlKCk7XG5cbiAgICAgIHZtLmFub0F0dWFsID0gZGF0ZS5nZXRGdWxsWWVhcigpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGxvZ291dCgpIHtcbiAgICAgIEF1dGgubG9nb3V0KCkudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgICRzdGF0ZS5nbyhHbG9iYWwubG9naW5TdGF0ZSk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBnZXRJbWFnZVBlcmZpbCgpIHtcbiAgICAgIHJldHVybiBBdXRoLmN1cnJlbnRVc2VyICYmIEF1dGguY3VycmVudFVzZXIuaW1hZ2UgPyBBdXRoLmN1cnJlbnRVc2VyLmltYWdlIDogR2xvYmFsLmltYWdlUGF0aCArICcvbm9fYXZhdGFyLmdpZic7XG4gICAgfVxuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4vKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCwgbm8tdW5kZWY6IDAqL1xuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIC8qKlxuICAgKiBUcmFuc2Zvcm1hIGJpYmxpb3RlY2FzIGV4dGVybmFzIGVtIHNlcnZpw6dvcyBkbyBhbmd1bGFyIHBhcmEgc2VyIHBvc3PDrXZlbCB1dGlsaXphclxuICAgKiBhdHJhdsOpcyBkYSBpbmplw6fDo28gZGUgZGVwZW5kw6puY2lhXG4gICAqL1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25zdGFudCgnbG9kYXNoJywgXykuY29uc3RhbnQoJ21vbWVudCcsIG1vbWVudCk7XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbnN0YW50KCdHbG9iYWwnLCB7XG4gICAgYXBwTmFtZTogJ0ZyZWVsYWdpbGUnLFxuICAgIGhvbWVTdGF0ZTogJ2FwcC5wcm9qZWN0cycsXG4gICAgbG9naW5Vcmw6ICdhcHAvbG9naW4nLFxuICAgIGxvZ2luU3RhdGU6ICdhcHAubG9naW4nLFxuICAgIHJlc2V0UGFzc3dvcmRTdGF0ZTogJ2FwcC5wYXNzd29yZC1yZXNldCcsXG4gICAgbm90QXV0aG9yaXplZFN0YXRlOiAnYXBwLm5vdC1hdXRob3JpemVkJyxcbiAgICB0b2tlbktleTogJ3NlcnZlcl90b2tlbicsXG4gICAgY2xpZW50UGF0aDogJ2NsaWVudC9hcHAnLFxuICAgIGFwaVBhdGg6ICdhcGkvdjEnLFxuICAgIGltYWdlUGF0aDogJ2NsaWVudC9pbWFnZXMnXG4gIH0pO1xufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25maWcocm91dGVzKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvdXRlcygkc3RhdGVQcm92aWRlciwgJHVybFJvdXRlclByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnYXBwJywge1xuICAgICAgdXJsOiAnL2FwcCcsXG4gICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL2xheW91dC9hcHAuaHRtbCcsXG4gICAgICBhYnN0cmFjdDogdHJ1ZSxcbiAgICAgIHJlc29sdmU6IHsgLy9lbnN1cmUgbGFuZ3MgaXMgcmVhZHkgYmVmb3JlIHJlbmRlciB2aWV3XG4gICAgICAgIHRyYW5zbGF0ZVJlYWR5OiBbJyR0cmFuc2xhdGUnLCAnJHEnLCBmdW5jdGlvbiAoJHRyYW5zbGF0ZSwgJHEpIHtcbiAgICAgICAgICB2YXIgZGVmZXJyZWQgPSAkcS5kZWZlcigpO1xuXG4gICAgICAgICAgJHRyYW5zbGF0ZS51c2UoJ3B0LUJSJykudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICBkZWZlcnJlZC5yZXNvbHZlKCk7XG4gICAgICAgICAgfSk7XG5cbiAgICAgICAgICByZXR1cm4gZGVmZXJyZWQucHJvbWlzZTtcbiAgICAgICAgfV1cbiAgICAgIH1cbiAgICB9KS5zdGF0ZShHbG9iYWwubm90QXV0aG9yaXplZFN0YXRlLCB7XG4gICAgICB1cmw6ICcvYWNlc3NvLW5lZ2FkbycsXG4gICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL2xheW91dC9ub3QtYXV0aG9yaXplZC5odG1sJyxcbiAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiBmYWxzZSB9XG4gICAgfSk7XG5cbiAgICAkdXJsUm91dGVyUHJvdmlkZXIud2hlbignL2FwcCcsIEdsb2JhbC5sb2dpblVybCk7XG4gICAgJHVybFJvdXRlclByb3ZpZGVyLm90aGVyd2lzZShHbG9iYWwubG9naW5VcmwpO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLnJ1bihydW4pO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gcnVuKCRyb290U2NvcGUsICRzdGF0ZSwgJHN0YXRlUGFyYW1zLCBBdXRoLCBHbG9iYWwpIHtcbiAgICAvLyBOT1NPTkFSXG4gICAgLy9zZXRhZG8gbm8gcm9vdFNjb3BlIHBhcmEgcG9kZXIgc2VyIGFjZXNzYWRvIG5hcyB2aWV3cyBzZW0gcHJlZml4byBkZSBjb250cm9sbGVyXG4gICAgJHJvb3RTY29wZS4kc3RhdGUgPSAkc3RhdGU7XG4gICAgJHJvb3RTY29wZS4kc3RhdGVQYXJhbXMgPSAkc3RhdGVQYXJhbXM7XG4gICAgJHJvb3RTY29wZS5hdXRoID0gQXV0aDtcbiAgICAkcm9vdFNjb3BlLmdsb2JhbCA9IEdsb2JhbDtcblxuICAgIC8vbm8gaW5pY2lvIGNhcnJlZ2EgbyB1c3XDoXJpbyBkbyBsb2NhbHN0b3JhZ2UgY2FzbyBvIHVzdcOhcmlvIGVzdGFqYSBhYnJpbmRvIG8gbmF2ZWdhZG9yXG4gICAgLy9wYXJhIHZvbHRhciBhdXRlbnRpY2Fkb1xuICAgIEF1dGgucmV0cmlldmVVc2VyRnJvbUxvY2FsU3RvcmFnZSgpO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29udHJvbGxlcignQXVkaXRDb250cm9sbGVyJywgQXVkaXRDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIEF1ZGl0Q29udHJvbGxlcigkY29udHJvbGxlciwgQXVkaXRTZXJ2aWNlLCBQckRpYWxvZywgR2xvYmFsLCAkdHJhbnNsYXRlKSB7XG4gICAgLy8gTk9TT05BUlxuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICB2bS5vbkFjdGl2YXRlID0gb25BY3RpdmF0ZTtcbiAgICB2bS5hcHBseUZpbHRlcnMgPSBhcHBseUZpbHRlcnM7XG4gICAgdm0udmlld0RldGFpbCA9IHZpZXdEZXRhaWw7XG5cbiAgICAkY29udHJvbGxlcignQ1JVRENvbnRyb2xsZXInLCB7IHZtOiB2bSwgbW9kZWxTZXJ2aWNlOiBBdWRpdFNlcnZpY2UsIG9wdGlvbnM6IHt9IH0pO1xuXG4gICAgZnVuY3Rpb24gb25BY3RpdmF0ZSgpIHtcbiAgICAgIHZtLm1vZGVscyA9IFtdO1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0ge307XG5cbiAgICAgIC8vUGVnYSB0b2RvcyBvcyBtb2RlbHMgZG8gc2VydmVyIGUgbW9udGEgdW1hIGxpc3RhIHBybyBDb21ib0JveFxuICAgICAgQXVkaXRTZXJ2aWNlLmdldEF1ZGl0ZWRNb2RlbHMoKS50aGVuKGZ1bmN0aW9uIChkYXRhKSB7XG4gICAgICAgIHZhciBtb2RlbHMgPSBbeyBpZDogJycsIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ2dsb2JhbC5hbGwnKSB9XTtcblxuICAgICAgICBkYXRhLm1vZGVscy5zb3J0KCk7XG5cbiAgICAgICAgZm9yICh2YXIgaW5kZXggPSAwOyBpbmRleCA8IGRhdGEubW9kZWxzLmxlbmd0aDsgaW5kZXgrKykge1xuICAgICAgICAgIHZhciBtb2RlbCA9IGRhdGEubW9kZWxzW2luZGV4XTtcblxuICAgICAgICAgIG1vZGVscy5wdXNoKHtcbiAgICAgICAgICAgIGlkOiBtb2RlbCxcbiAgICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ21vZGVscy4nICsgbW9kZWwudG9Mb3dlckNhc2UoKSlcbiAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHZtLm1vZGVscyA9IG1vZGVscztcbiAgICAgICAgdm0ucXVlcnlGaWx0ZXJzLm1vZGVsID0gdm0ubW9kZWxzWzBdLmlkO1xuICAgICAgfSk7XG5cbiAgICAgIHZtLnR5cGVzID0gQXVkaXRTZXJ2aWNlLmxpc3RUeXBlcygpO1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzLnR5cGUgPSB2bS50eXBlc1swXS5pZDtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBhcHBseUZpbHRlcnMoZGVmYXVsdFF1ZXJ5RmlsdGVycykge1xuICAgICAgcmV0dXJuIGFuZ3VsYXIuZXh0ZW5kKGRlZmF1bHRRdWVyeUZpbHRlcnMsIHZtLnF1ZXJ5RmlsdGVycyk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gdmlld0RldGFpbChhdWRpdERldGFpbCkge1xuICAgICAgdmFyIGNvbmZpZyA9IHtcbiAgICAgICAgbG9jYWxzOiB7IGF1ZGl0RGV0YWlsOiBhdWRpdERldGFpbCB9LFxuICAgICAgICAvKiogQG5nSW5qZWN0ICovXG4gICAgICAgIGNvbnRyb2xsZXI6IGZ1bmN0aW9uIGNvbnRyb2xsZXIoYXVkaXREZXRhaWwsIFByRGlhbG9nKSB7XG4gICAgICAgICAgdmFyIHZtID0gdGhpcztcblxuICAgICAgICAgIHZtLmNsb3NlID0gY2xvc2U7XG5cbiAgICAgICAgICBhY3RpdmF0ZSgpO1xuXG4gICAgICAgICAgZnVuY3Rpb24gYWN0aXZhdGUoKSB7XG4gICAgICAgICAgICBpZiAoYW5ndWxhci5pc0FycmF5KGF1ZGl0RGV0YWlsLm9sZCkgJiYgYXVkaXREZXRhaWwub2xkLmxlbmd0aCA9PT0gMCkgYXVkaXREZXRhaWwub2xkID0gbnVsbDtcbiAgICAgICAgICAgIGlmIChhbmd1bGFyLmlzQXJyYXkoYXVkaXREZXRhaWwubmV3KSAmJiBhdWRpdERldGFpbC5uZXcubGVuZ3RoID09PSAwKSBhdWRpdERldGFpbC5uZXcgPSBudWxsO1xuXG4gICAgICAgICAgICB2bS5hdWRpdERldGFpbCA9IGF1ZGl0RGV0YWlsO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIGZ1bmN0aW9uIGNsb3NlKCkge1xuICAgICAgICAgICAgUHJEaWFsb2cuY2xvc2UoKTtcbiAgICAgICAgICB9XG4gICAgICAgIH0sXG4gICAgICAgIGNvbnRyb2xsZXJBczogJ2F1ZGl0RGV0YWlsQ3RybCcsXG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvYXVkaXQvYXVkaXQtZGV0YWlsLmh0bWwnLFxuICAgICAgICBoYXNCYWNrZHJvcDogdHJ1ZVxuICAgICAgfTtcblxuICAgICAgUHJEaWFsb2cuY3VzdG9tKGNvbmZpZyk7XG4gICAgfVxuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKlxuICAgKiBBcnF1aXZvIGRlIGNvbmZpZ3VyYcOnw6NvIGNvbSBhcyByb3RhcyBlc3BlY8OtZmljYXMgZGUgYXVkaXRvcmlhXG4gICAqXG4gICAqIEBwYXJhbSB7YW55fSAkc3RhdGVQcm92aWRlclxuICAgKiBAcGFyYW0ge2FueX0gR2xvYmFsXG4gICAqL1xuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvdXRlcygkc3RhdGVQcm92aWRlciwgR2xvYmFsKSB7XG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ2FwcC5hdWRpdCcsIHtcbiAgICAgIHVybDogJy9hdWRpdG9yaWEnLFxuICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9hdWRpdC9hdWRpdC5odG1sJyxcbiAgICAgIGNvbnRyb2xsZXI6ICdBdWRpdENvbnRyb2xsZXIgYXMgYXVkaXRDdHJsJyxcbiAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiB0cnVlLCBuZWVkUHJvZmlsZTogWydhZG1pbiddIH1cbiAgICB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5mYWN0b3J5KCdBdWRpdFNlcnZpY2UnLCBBdWRpdFNlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gQXVkaXRTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5LCAkdHJhbnNsYXRlKSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCdhdWRpdCcsIHtcbiAgICAgIGFjdGlvbnM6IHtcbiAgICAgICAgZ2V0QXVkaXRlZE1vZGVsczoge1xuICAgICAgICAgIG1ldGhvZDogJ0dFVCcsXG4gICAgICAgICAgdXJsOiAnbW9kZWxzJ1xuICAgICAgICB9XG4gICAgICB9LFxuICAgICAgaW5zdGFuY2U6IHt9LFxuICAgICAgbGlzdFR5cGVzOiBmdW5jdGlvbiBsaXN0VHlwZXMoKSB7XG4gICAgICAgIHZhciBhdWRpdFBhdGggPSAndmlld3MuZmllbGRzLmF1ZGl0Lic7XG5cbiAgICAgICAgcmV0dXJuIFt7IGlkOiAnJywgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudChhdWRpdFBhdGggKyAnYWxsUmVzb3VyY2VzJykgfSwgeyBpZDogJ2NyZWF0ZWQnLCBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KGF1ZGl0UGF0aCArICd0eXBlLmNyZWF0ZWQnKSB9LCB7IGlkOiAndXBkYXRlZCcsIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoYXVkaXRQYXRoICsgJ3R5cGUudXBkYXRlZCcpIH0sIHsgaWQ6ICdkZWxldGVkJywgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudChhdWRpdFBhdGggKyAndHlwZS5kZWxldGVkJykgfV07XG4gICAgICB9XG4gICAgfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqXG4gICAqIEFycXVpdm8gZGUgY29uZmlndXJhw6fDo28gY29tIGFzIHJvdGFzIGVzcGVjw61maWNhcyBkbyByZWN1cnNvIHVzZXJcbiAgICpcbiAgICogQHBhcmFtIHthbnl9ICRzdGF0ZVByb3ZpZGVyXG4gICAqIEBwYXJhbSB7YW55fSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZShHbG9iYWwucmVzZXRQYXNzd29yZFN0YXRlLCB7XG4gICAgICB1cmw6ICcvcGFzc3dvcmQvcmVzZXQvOnRva2VuJyxcbiAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvYXV0aC9yZXNldC1wYXNzLWZvcm0uaHRtbCcsXG4gICAgICBjb250cm9sbGVyOiAnUGFzc3dvcmRDb250cm9sbGVyIGFzIHBhc3NDdHJsJyxcbiAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiBmYWxzZSB9XG4gICAgfSkuc3RhdGUoR2xvYmFsLmxvZ2luU3RhdGUsIHtcbiAgICAgIHVybDogJy9sb2dpbicsXG4gICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL2F1dGgvbG9naW4uaHRtbCcsXG4gICAgICBjb250cm9sbGVyOiAnTG9naW5Db250cm9sbGVyIGFzIGxvZ2luQ3RybCcsXG4gICAgICBkYXRhOiB7IG5lZWRBdXRoZW50aWNhdGlvbjogZmFsc2UgfVxuICAgIH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZhY3RvcnkoJ0F1dGgnLCBBdXRoKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIEF1dGgoJGh0dHAsICRxLCBHbG9iYWwsIFVzZXJzU2VydmljZSkge1xuICAgIC8vIE5PU09OQVJcbiAgICB2YXIgYXV0aCA9IHtcbiAgICAgIGxvZ2luOiBsb2dpbixcbiAgICAgIGxvZ291dDogbG9nb3V0LFxuICAgICAgdXBkYXRlQ3VycmVudFVzZXI6IHVwZGF0ZUN1cnJlbnRVc2VyLFxuICAgICAgcmV0cmlldmVVc2VyRnJvbUxvY2FsU3RvcmFnZTogcmV0cmlldmVVc2VyRnJvbUxvY2FsU3RvcmFnZSxcbiAgICAgIGF1dGhlbnRpY2F0ZWQ6IGF1dGhlbnRpY2F0ZWQsXG4gICAgICBzZW5kRW1haWxSZXNldFBhc3N3b3JkOiBzZW5kRW1haWxSZXNldFBhc3N3b3JkLFxuICAgICAgcmVtb3RlVmFsaWRhdGVUb2tlbjogcmVtb3RlVmFsaWRhdGVUb2tlbixcbiAgICAgIGdldFRva2VuOiBnZXRUb2tlbixcbiAgICAgIHNldFRva2VuOiBzZXRUb2tlbixcbiAgICAgIGNsZWFyVG9rZW46IGNsZWFyVG9rZW4sXG4gICAgICBjdXJyZW50VXNlcjogbnVsbFxuICAgIH07XG5cbiAgICBmdW5jdGlvbiBjbGVhclRva2VuKCkge1xuICAgICAgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oR2xvYmFsLnRva2VuS2V5KTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBzZXRUb2tlbih0b2tlbikge1xuICAgICAgbG9jYWxTdG9yYWdlLnNldEl0ZW0oR2xvYmFsLnRva2VuS2V5LCB0b2tlbik7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gZ2V0VG9rZW4oKSB7XG4gICAgICByZXR1cm4gbG9jYWxTdG9yYWdlLmdldEl0ZW0oR2xvYmFsLnRva2VuS2V5KTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiByZW1vdGVWYWxpZGF0ZVRva2VuKCkge1xuICAgICAgdmFyIGRlZmVycmVkID0gJHEuZGVmZXIoKTtcblxuICAgICAgaWYgKGF1dGguYXV0aGVudGljYXRlZCgpKSB7XG4gICAgICAgICRodHRwLmdldChHbG9iYWwuYXBpUGF0aCArICcvYXV0aGVudGljYXRlL2NoZWNrJykudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgZGVmZXJyZWQucmVzb2x2ZSh0cnVlKTtcbiAgICAgICAgfSwgZnVuY3Rpb24gKCkge1xuICAgICAgICAgIGF1dGgubG9nb3V0KCk7XG5cbiAgICAgICAgICBkZWZlcnJlZC5yZWplY3QoZmFsc2UpO1xuICAgICAgICB9KTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIGF1dGgubG9nb3V0KCk7XG5cbiAgICAgICAgZGVmZXJyZWQucmVqZWN0KGZhbHNlKTtcbiAgICAgIH1cblxuICAgICAgcmV0dXJuIGRlZmVycmVkLnByb21pc2U7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogVmVyaWZpY2Egc2UgbyB1c3XDoXJpbyBlc3TDoSBhdXRlbnRpY2Fkb1xuICAgICAqXG4gICAgICogQHJldHVybnMge2Jvb2xlYW59XG4gICAgICovXG4gICAgZnVuY3Rpb24gYXV0aGVudGljYXRlZCgpIHtcbiAgICAgIHJldHVybiBhdXRoLmdldFRva2VuKCkgIT09IG51bGw7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVjdXBlcmEgbyB1c3XDoXJpbyBkbyBsb2NhbFN0b3JhZ2VcbiAgICAgKi9cbiAgICBmdW5jdGlvbiByZXRyaWV2ZVVzZXJGcm9tTG9jYWxTdG9yYWdlKCkge1xuICAgICAgdmFyIHVzZXIgPSBsb2NhbFN0b3JhZ2UuZ2V0SXRlbSgndXNlcicpO1xuXG4gICAgICBpZiAodXNlcikge1xuICAgICAgICBhdXRoLmN1cnJlbnRVc2VyID0gYW5ndWxhci5tZXJnZShuZXcgVXNlcnNTZXJ2aWNlKCksIGFuZ3VsYXIuZnJvbUpzb24odXNlcikpO1xuICAgICAgfVxuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEd1YXJkYSBvIHVzdcOhcmlvIG5vIGxvY2FsU3RvcmFnZSBwYXJhIGNhc28gbyB1c3XDoXJpbyBmZWNoZSBlIGFicmEgbyBuYXZlZ2Fkb3JcbiAgICAgKiBkZW50cm8gZG8gdGVtcG8gZGUgc2Vzc8OjbyBzZWphIHBvc3PDrXZlbCByZWN1cGVyYXIgbyB0b2tlbiBhdXRlbnRpY2Fkby5cbiAgICAgKlxuICAgICAqIE1hbnTDqW0gYSB2YXJpw6F2ZWwgYXV0aC5jdXJyZW50VXNlciBwYXJhIGZhY2lsaXRhciBvIGFjZXNzbyBhbyB1c3XDoXJpbyBsb2dhZG8gZW0gdG9kYSBhIGFwbGljYcOnw6NvXG4gICAgICpcbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSB1c2VyIFVzdcOhcmlvIGEgc2VyIGF0dWFsaXphZG8uIENhc28gc2VqYSBwYXNzYWRvIG51bGwgbGltcGFcbiAgICAgKiB0b2RhcyBhcyBpbmZvcm1hw6fDtWVzIGRvIHVzdcOhcmlvIGNvcnJlbnRlLlxuICAgICAqL1xuICAgIGZ1bmN0aW9uIHVwZGF0ZUN1cnJlbnRVc2VyKHVzZXIpIHtcbiAgICAgIHZhciBkZWZlcnJlZCA9ICRxLmRlZmVyKCk7XG5cbiAgICAgIGlmICh1c2VyKSB7XG4gICAgICAgIHVzZXIgPSBhbmd1bGFyLm1lcmdlKG5ldyBVc2Vyc1NlcnZpY2UoKSwgdXNlcik7XG5cbiAgICAgICAgdmFyIGpzb25Vc2VyID0gYW5ndWxhci50b0pzb24odXNlcik7XG5cbiAgICAgICAgbG9jYWxTdG9yYWdlLnNldEl0ZW0oJ3VzZXInLCBqc29uVXNlcik7XG4gICAgICAgIGF1dGguY3VycmVudFVzZXIgPSB1c2VyO1xuXG4gICAgICAgIGRlZmVycmVkLnJlc29sdmUodXNlcik7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbSgndXNlcicpO1xuICAgICAgICBhdXRoLmN1cnJlbnRVc2VyID0gbnVsbDtcbiAgICAgICAgYXV0aC5jbGVhclRva2VuKCk7XG5cbiAgICAgICAgZGVmZXJyZWQucmVqZWN0KCk7XG4gICAgICB9XG5cbiAgICAgIHJldHVybiBkZWZlcnJlZC5wcm9taXNlO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWxpemEgbyBsb2dpbiBkbyB1c3XDoXJpb1xuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IGNyZWRlbnRpYWxzIEVtYWlsIGUgU2VuaGEgZG8gdXN1w6FyaW9cbiAgICAgKiBAcmV0dXJucyB7cHJvbWlzZX0gVW1hIHByb21pc2UgY29tIG8gcmVzdWx0YWRvIGRvIGNoYW1hZGEgbm8gYmFja2VuZFxuICAgICAqL1xuICAgIGZ1bmN0aW9uIGxvZ2luKGNyZWRlbnRpYWxzKSB7XG4gICAgICB2YXIgZGVmZXJyZWQgPSAkcS5kZWZlcigpO1xuXG4gICAgICAkaHR0cC5wb3N0KEdsb2JhbC5hcGlQYXRoICsgJy9hdXRoZW50aWNhdGUnLCBjcmVkZW50aWFscykudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgYXV0aC5zZXRUb2tlbihyZXNwb25zZS5kYXRhLnRva2VuKTtcblxuICAgICAgICByZXR1cm4gJGh0dHAuZ2V0KEdsb2JhbC5hcGlQYXRoICsgJy9hdXRoZW50aWNhdGUvdXNlcicpO1xuICAgICAgfSkudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgYXV0aC51cGRhdGVDdXJyZW50VXNlcihyZXNwb25zZS5kYXRhLnVzZXIpO1xuXG4gICAgICAgIGRlZmVycmVkLnJlc29sdmUoKTtcbiAgICAgIH0sIGZ1bmN0aW9uIChlcnJvcikge1xuICAgICAgICBhdXRoLmxvZ291dCgpO1xuXG4gICAgICAgIGRlZmVycmVkLnJlamVjdChlcnJvcik7XG4gICAgICB9KTtcblxuICAgICAgcmV0dXJuIGRlZmVycmVkLnByb21pc2U7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogRGVzbG9nYSBvcyB1c3XDoXJpb3MuIENvbW8gbsOjbyB0ZW4gbmVuaHVtYSBpbmZvcm1hw6fDo28gbmEgc2Vzc8OjbyBkbyBzZXJ2aWRvclxuICAgICAqIGUgdW0gdG9rZW4gdW1hIHZleiBnZXJhZG8gbsOjbyBwb2RlLCBwb3IgcGFkcsOjbywgc2VyIGludmFsaWRhZG8gYW50ZXMgZG8gc2V1IHRlbXBvIGRlIGV4cGlyYcOnw6NvLFxuICAgICAqIHNvbWVudGUgYXBhZ2Ftb3Mgb3MgZGFkb3MgZG8gdXN1w6FyaW8gZSBvIHRva2VuIGRvIG5hdmVnYWRvciBwYXJhIGVmZXRpdmFyIG8gbG9nb3V0LlxuICAgICAqXG4gICAgICogQHJldHVybnMge3Byb21pc2V9IFVtYSBwcm9taXNlIGNvbSBvIHJlc3VsdGFkbyBkYSBvcGVyYcOnw6NvXG4gICAgICovXG4gICAgZnVuY3Rpb24gbG9nb3V0KCkge1xuICAgICAgdmFyIGRlZmVycmVkID0gJHEuZGVmZXIoKTtcblxuICAgICAgYXV0aC51cGRhdGVDdXJyZW50VXNlcihudWxsKTtcbiAgICAgIGRlZmVycmVkLnJlc29sdmUoKTtcblxuICAgICAgcmV0dXJuIGRlZmVycmVkLnByb21pc2U7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogRW52aWEgdW0gZW1haWwgcGFyYSByZWN1cGVyYcOnw6NvIGRlIHNlbmhhXG4gICAgICogQHBhcmFtIHtPYmplY3R9IHJlc2V0RGF0YSAtIE9iamV0byBjb250ZW5kbyBvIGVtYWlsXG4gICAgICogQHJldHVybiB7UHJvbWlzZX0gLSBSZXRvcm5hIHVtYSBwcm9taXNlIHBhcmEgc2VyIHJlc29sdmlkYVxuICAgICAqL1xuICAgIGZ1bmN0aW9uIHNlbmRFbWFpbFJlc2V0UGFzc3dvcmQocmVzZXREYXRhKSB7XG4gICAgICB2YXIgZGVmZXJyZWQgPSAkcS5kZWZlcigpO1xuXG4gICAgICAkaHR0cC5wb3N0KEdsb2JhbC5hcGlQYXRoICsgJy9wYXNzd29yZC9lbWFpbCcsIHJlc2V0RGF0YSkudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgZGVmZXJyZWQucmVzb2x2ZShyZXNwb25zZS5kYXRhKTtcbiAgICAgIH0sIGZ1bmN0aW9uIChlcnJvcikge1xuICAgICAgICBkZWZlcnJlZC5yZWplY3QoZXJyb3IpO1xuICAgICAgfSk7XG5cbiAgICAgIHJldHVybiBkZWZlcnJlZC5wcm9taXNlO1xuICAgIH1cblxuICAgIHJldHVybiBhdXRoO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29udHJvbGxlcignTG9naW5Db250cm9sbGVyJywgTG9naW5Db250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIExvZ2luQ29udHJvbGxlcigkc3RhdGUsIEF1dGgsIEdsb2JhbCwgUHJEaWFsb2cpIHtcbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0ubG9naW4gPSBsb2dpbjtcbiAgICB2bS5vcGVuRGlhbG9nUmVzZXRQYXNzID0gb3BlbkRpYWxvZ1Jlc2V0UGFzcztcbiAgICB2bS5vcGVuRGlhbG9nU2lnblVwID0gb3BlbkRpYWxvZ1NpZ25VcDtcblxuICAgIGFjdGl2YXRlKCk7XG5cbiAgICBmdW5jdGlvbiBhY3RpdmF0ZSgpIHtcbiAgICAgIHZtLmNyZWRlbnRpYWxzID0ge307XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gbG9naW4oKSB7XG4gICAgICB2YXIgY3JlZGVudGlhbHMgPSB7XG4gICAgICAgIGVtYWlsOiB2bS5jcmVkZW50aWFscy5lbWFpbCxcbiAgICAgICAgcGFzc3dvcmQ6IHZtLmNyZWRlbnRpYWxzLnBhc3N3b3JkXG4gICAgICB9O1xuXG4gICAgICBBdXRoLmxvZ2luKGNyZWRlbnRpYWxzKS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgJHN0YXRlLmdvKEdsb2JhbC5ob21lU3RhdGUpO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogRXhpYmUgbyBkaWFsb2cgcGFyYSByZWN1cGVyYcOnw6NvIGRlIHNlbmhhXG4gICAgICovXG4gICAgZnVuY3Rpb24gb3BlbkRpYWxvZ1Jlc2V0UGFzcygpIHtcbiAgICAgIHZhciBjb25maWcgPSB7XG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvYXV0aC9zZW5kLXJlc2V0LWRpYWxvZy5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ1Bhc3N3b3JkQ29udHJvbGxlciBhcyBwYXNzQ3RybCcsXG4gICAgICAgIGhhc0JhY2tkcm9wOiB0cnVlXG4gICAgICB9O1xuXG4gICAgICBQckRpYWxvZy5jdXN0b20oY29uZmlnKTtcbiAgICB9XG4gICAgLyoqXG4gICAgICogRXhpYmUgbyBkaWFsb2cgcGFyYSByZWN1cGVyYcOnw6NvIGRlIHNlbmhhXG4gICAgICovXG4gICAgZnVuY3Rpb24gb3BlbkRpYWxvZ1NpZ25VcCgpIHtcbiAgICAgIHZhciBjb25maWcgPSB7XG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvdXNlcnMvdXNlci1mb3JtLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnVXNlcnNDb250cm9sbGVyIGFzIHVzZXJzQ3RybCcsXG4gICAgICAgIGhhc0JhY2tkcm9wOiB0cnVlXG4gICAgICB9O1xuXG4gICAgICBQckRpYWxvZy5jdXN0b20oY29uZmlnKTtcbiAgICB9XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb250cm9sbGVyKCdQYXNzd29yZENvbnRyb2xsZXInLCBQYXNzd29yZENvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gUGFzc3dvcmRDb250cm9sbGVyKEdsb2JhbCwgJHN0YXRlUGFyYW1zLCAkaHR0cCwgJHRpbWVvdXQsICRzdGF0ZSwgLy8gTk9TT05BUlxuICBQclRvYXN0LCBQckRpYWxvZywgQXV0aCwgJHRyYW5zbGF0ZSkge1xuXG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIHZtLnNlbmRSZXNldCA9IHNlbmRSZXNldDtcbiAgICB2bS5jbG9zZURpYWxvZyA9IGNsb3NlRGlhbG9nO1xuICAgIHZtLmNsZWFuRm9ybSA9IGNsZWFuRm9ybTtcbiAgICB2bS5zZW5kRW1haWxSZXNldFBhc3N3b3JkID0gc2VuZEVtYWlsUmVzZXRQYXNzd29yZDtcblxuICAgIGFjdGl2YXRlKCk7XG5cbiAgICBmdW5jdGlvbiBhY3RpdmF0ZSgpIHtcbiAgICAgIHZtLnJlc2V0ID0geyBlbWFpbDogJycsIHRva2VuOiAkc3RhdGVQYXJhbXMudG9rZW4gfTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFsaXphIGEgYWx0ZXJhw6fDo28gZGEgc2VuaGEgZG8gdXN1w6FyaW8gZSBvIHJlZGlyZWNpb25hIHBhcmEgYSB0ZWxhIGRlIGxvZ2luXG4gICAgICovXG4gICAgZnVuY3Rpb24gc2VuZFJlc2V0KCkge1xuICAgICAgJGh0dHAucG9zdChHbG9iYWwuYXBpUGF0aCArICcvcGFzc3dvcmQvcmVzZXQnLCB2bS5yZXNldCkudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgIFByVG9hc3Quc3VjY2VzcygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLm9wZXJhdGlvblN1Y2Nlc3MnKSk7XG4gICAgICAgICR0aW1lb3V0KGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAkc3RhdGUuZ28oR2xvYmFsLmxvZ2luU3RhdGUpO1xuICAgICAgICB9LCAxNTAwKTtcbiAgICAgIH0sIGZ1bmN0aW9uIChlcnJvcikge1xuICAgICAgICBpZiAoZXJyb3Iuc3RhdHVzICE9PSA0MDAgJiYgZXJyb3Iuc3RhdHVzICE9PSA1MDApIHtcbiAgICAgICAgICB2YXIgbXNnID0gJyc7XG5cbiAgICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IGVycm9yLmRhdGEucGFzc3dvcmQubGVuZ3RoOyBpKyspIHtcbiAgICAgICAgICAgIG1zZyArPSBlcnJvci5kYXRhLnBhc3N3b3JkW2ldICsgJzxicj4nO1xuICAgICAgICAgIH1cbiAgICAgICAgICBQclRvYXN0LmVycm9yKG1zZy50b1VwcGVyQ2FzZSgpKTtcbiAgICAgICAgfVxuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogRW52aWEgdW0gZW1haWwgZGUgcmVjdXBlcmHDp8OjbyBkZSBzZW5oYSBjb20gbyB0b2tlbiBkbyB1c3XDoXJpb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIHNlbmRFbWFpbFJlc2V0UGFzc3dvcmQoKSB7XG5cbiAgICAgIGlmICh2bS5yZXNldC5lbWFpbCA9PT0gJycpIHtcbiAgICAgICAgUHJUb2FzdC5lcnJvcigkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnZhbGlkYXRlLmZpZWxkUmVxdWlyZWQnLCB7IGZpZWxkOiAnZW1haWwnIH0pKTtcbiAgICAgICAgcmV0dXJuO1xuICAgICAgfVxuXG4gICAgICBBdXRoLnNlbmRFbWFpbFJlc2V0UGFzc3dvcmQodm0ucmVzZXQpLnRoZW4oZnVuY3Rpb24gKGRhdGEpIHtcbiAgICAgICAgUHJUb2FzdC5zdWNjZXNzKGRhdGEubWVzc2FnZSk7XG5cbiAgICAgICAgdm0uY2xlYW5Gb3JtKCk7XG4gICAgICAgIHZtLmNsb3NlRGlhbG9nKCk7XG4gICAgICB9LCBmdW5jdGlvbiAoZXJyb3IpIHtcbiAgICAgICAgaWYgKGVycm9yLmRhdGEuZW1haWwgJiYgZXJyb3IuZGF0YS5lbWFpbC5sZW5ndGggPiAwKSB7XG4gICAgICAgICAgdmFyIG1zZyA9ICcnO1xuXG4gICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCBlcnJvci5kYXRhLmVtYWlsLmxlbmd0aDsgaSsrKSB7XG4gICAgICAgICAgICBtc2cgKz0gZXJyb3IuZGF0YS5lbWFpbFtpXSArICc8YnI+JztcbiAgICAgICAgICB9XG5cbiAgICAgICAgICBQclRvYXN0LmVycm9yKG1zZyk7XG4gICAgICAgIH1cbiAgICAgIH0pO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGNsb3NlRGlhbG9nKCkge1xuICAgICAgUHJEaWFsb2cuY2xvc2UoKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBjbGVhbkZvcm0oKSB7XG4gICAgICB2bS5yZXNldC5lbWFpbCA9ICcnO1xuICAgIH1cbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuLyplc2xpbnQgYW5ndWxhci9maWxlLW5hbWU6IDAqL1xuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5mYWN0b3J5KCdzZXJ2aWNlRmFjdG9yeScsIHNlcnZpY2VGYWN0b3J5KTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8qKlxuICAgKiBNYWlzIGluZm9ybWHDp8O1ZXM6XG4gICAqIGh0dHBzOi8vZ2l0aHViLmNvbS9zd2ltbGFuZS9hbmd1bGFyLW1vZGVsLWZhY3Rvcnkvd2lraS9BUElcbiAgICovXG4gIGZ1bmN0aW9uIHNlcnZpY2VGYWN0b3J5KCRtb2RlbEZhY3RvcnkpIHtcbiAgICByZXR1cm4gZnVuY3Rpb24gKHVybCwgb3B0aW9ucykge1xuICAgICAgdmFyIG1vZGVsO1xuICAgICAgdmFyIGRlZmF1bHRPcHRpb25zID0ge1xuICAgICAgICBhY3Rpb25zOiB7XG4gICAgICAgICAgLyoqXG4gICAgICAgICAgICogU2VydmnDp28gY29tdW0gcGFyYSByZWFsaXphciBidXNjYSBjb20gcGFnaW5hw6fDo29cbiAgICAgICAgICAgKiBPIG1lc21vIGVzcGVyYSBxdWUgc2VqYSByZXRvcm5hZG8gdW0gb2JqZXRvIGNvbSBpdGVtcyBlIHRvdGFsXG4gICAgICAgICAgICovXG4gICAgICAgICAgcGFnaW5hdGU6IHtcbiAgICAgICAgICAgIG1ldGhvZDogJ0dFVCcsXG4gICAgICAgICAgICBpc0FycmF5OiBmYWxzZSxcbiAgICAgICAgICAgIHdyYXA6IGZhbHNlLFxuICAgICAgICAgICAgYWZ0ZXJSZXF1ZXN0OiBmdW5jdGlvbiBhZnRlclJlcXVlc3QocmVzcG9uc2UpIHtcbiAgICAgICAgICAgICAgaWYgKHJlc3BvbnNlWydpdGVtcyddKSB7XG4gICAgICAgICAgICAgICAgcmVzcG9uc2VbJ2l0ZW1zJ10gPSBtb2RlbC5MaXN0KHJlc3BvbnNlWydpdGVtcyddKTtcbiAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgIHJldHVybiByZXNwb25zZTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgIH07XG5cbiAgICAgIG1vZGVsID0gJG1vZGVsRmFjdG9yeSh1cmwsIGFuZ3VsYXIubWVyZ2UoZGVmYXVsdE9wdGlvbnMsIG9wdGlvbnMpKTtcblxuICAgICAgcmV0dXJuIG1vZGVsO1xuICAgIH07XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIENSVURDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8qKlxuICAgKiBDb250cm9sYWRvciBCYXNlIHF1ZSBpbXBsZW1lbnRhIHRvZGFzIGFzIGZ1bsOnw7VlcyBwYWRyw7VlcyBkZSB1bSBDUlVEXG4gICAqXG4gICAqIEHDp8O1ZXMgaW1wbGVtZW50YWRhc1xuICAgKiBhY3RpdmF0ZSgpXG4gICAqIHNlYXJjaChwYWdlKVxuICAgKiBlZGl0KHJlc291cmNlKVxuICAgKiBzYXZlKClcbiAgICogcmVtb3ZlKHJlc291cmNlKVxuICAgKiBnb1RvKHZpZXdOYW1lKVxuICAgKiBjbGVhbkZvcm0oKVxuICAgKlxuICAgKiBHYXRpbGhvc1xuICAgKlxuICAgKiBvbkFjdGl2YXRlKClcbiAgICogYXBwbHlGaWx0ZXJzKGRlZmF1bHRRdWVyeUZpbHRlcnMpXG4gICAqIGJlZm9yZVNlYXJjaChwYWdlKSAvL3JldG9ybmFuZG8gZmFsc2UgY2FuY2VsYSBvIGZsdXhvXG4gICAqIGFmdGVyU2VhcmNoKHJlc3BvbnNlKVxuICAgKiBiZWZvcmVDbGVhbiAvL3JldG9ybmFuZG8gZmFsc2UgY2FuY2VsYSBvIGZsdXhvXG4gICAqIGFmdGVyQ2xlYW4oKVxuICAgKiBiZWZvcmVTYXZlKCkgLy9yZXRvcm5hbmRvIGZhbHNlIGNhbmNlbGEgbyBmbHV4b1xuICAgKiBhZnRlclNhdmUocmVzb3VyY2UpXG4gICAqIG9uU2F2ZUVycm9yKGVycm9yKVxuICAgKiBiZWZvcmVSZW1vdmUocmVzb3VyY2UpIC8vcmV0b3JuYW5kbyBmYWxzZSBjYW5jZWxhIG8gZmx1eG9cbiAgICogYWZ0ZXJSZW1vdmUocmVzb3VyY2UpXG4gICAqXG4gICAqIEBwYXJhbSB7YW55fSB2bSBpbnN0YW5jaWEgZG8gY29udHJvbGxlciBmaWxob1xuICAgKiBAcGFyYW0ge2FueX0gbW9kZWxTZXJ2aWNlIHNlcnZpw6dvIGRvIG1vZGVsIHF1ZSB2YWkgc2VyIHV0aWxpemFkb1xuICAgKiBAcGFyYW0ge2FueX0gb3B0aW9ucyBvcMOnw7VlcyBwYXJhIHNvYnJlZXNjcmV2ZXIgY29tcG9ydGFtZW50b3MgcGFkcsO1ZXNcbiAgICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIENSVURDb250cm9sbGVyKHZtLCBtb2RlbFNlcnZpY2UsIG9wdGlvbnMsIFByVG9hc3QsIFByUGFnaW5hdGlvbiwgLy8gTk9TT05BUlxuICBQckRpYWxvZywgJHRyYW5zbGF0ZSkge1xuXG4gICAgLy9GdW5jdGlvbnMgQmxvY2tcbiAgICB2bS5zZWFyY2ggPSBzZWFyY2g7XG4gICAgdm0ucGFnaW5hdGVTZWFyY2ggPSBwYWdpbmF0ZVNlYXJjaDtcbiAgICB2bS5ub3JtYWxTZWFyY2ggPSBub3JtYWxTZWFyY2g7XG4gICAgdm0uZWRpdCA9IGVkaXQ7XG4gICAgdm0uc2F2ZSA9IHNhdmU7XG4gICAgdm0ucmVtb3ZlID0gcmVtb3ZlO1xuICAgIHZtLmdvVG8gPSBnb1RvO1xuICAgIHZtLmNsZWFuRm9ybSA9IGNsZWFuRm9ybTtcblxuICAgIGFjdGl2YXRlKCk7XG5cbiAgICAvKipcbiAgICAgKiBQcmVwYXJhIG8gY29udHJvbGFkb3JcbiAgICAgKiBGYXogbyBtZXJnZSBkYXMgb3DDp8O1ZXNcbiAgICAgKiBJbmljaWFsaXphIG8gcmVjdXJzb1xuICAgICAqIEluaWNpYWxpemEgbyBvYmpldG8gcGFnaW5hZG9yIGUgcmVhbGl6YSBhIHBlc3F1aXNhXG4gICAgICovXG4gICAgZnVuY3Rpb24gYWN0aXZhdGUoKSB7XG4gICAgICB2bS5kZWZhdWx0T3B0aW9ucyA9IHtcbiAgICAgICAgcmVkaXJlY3RBZnRlclNhdmU6IHRydWUsXG4gICAgICAgIHNlYXJjaE9uSW5pdDogdHJ1ZSxcbiAgICAgICAgcGVyUGFnZTogOCxcbiAgICAgICAgc2tpcFBhZ2luYXRpb246IGZhbHNlXG4gICAgICB9O1xuXG4gICAgICBhbmd1bGFyLm1lcmdlKHZtLmRlZmF1bHRPcHRpb25zLCBvcHRpb25zKTtcblxuICAgICAgdm0udmlld0Zvcm0gPSBmYWxzZTtcbiAgICAgIHZtLnJlc291cmNlID0gbmV3IG1vZGVsU2VydmljZSgpO1xuXG4gICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLm9uQWN0aXZhdGUpKSB2bS5vbkFjdGl2YXRlKCk7XG5cbiAgICAgIHZtLnBhZ2luYXRvciA9IFByUGFnaW5hdGlvbi5nZXRJbnN0YW5jZSh2bS5zZWFyY2gsIHZtLmRlZmF1bHRPcHRpb25zLnBlclBhZ2UpO1xuXG4gICAgICBpZiAodm0uZGVmYXVsdE9wdGlvbnMuc2VhcmNoT25Jbml0KSB2bS5zZWFyY2goKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFsaXphIGEgcGVzcXVpc2FcbiAgICAgKiBWZXJpZmljYSBxdWFsIGRhcyBmdW7Dp8O1ZXMgZGUgcGVzcXVpc2EgZGV2ZSBzZXIgcmVhbGl6YWRhLlxuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IHBhZ2UgcMOhZ2luYSBxdWUgZGV2ZSBzZXIgY2FycmVnYWRhXG4gICAgICovXG4gICAgZnVuY3Rpb24gc2VhcmNoKHBhZ2UpIHtcbiAgICAgIHZtLmRlZmF1bHRPcHRpb25zLnNraXBQYWdpbmF0aW9uID8gbm9ybWFsU2VhcmNoKCkgOiBwYWdpbmF0ZVNlYXJjaChwYWdlKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFsaXphIGEgcGVzcXVpc2EgcGFnaW5hZGEgY29tIGJhc2Ugbm9zIGZpbHRyb3MgZGVmaW5pZG9zXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gcGFnZSBww6FnaW5hIHF1ZSBkZXZlIHNlciBjYXJyZWdhZGFcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBwYWdpbmF0ZVNlYXJjaChwYWdlKSB7XG4gICAgICB2bS5wYWdpbmF0b3IuY3VycmVudFBhZ2UgPSBhbmd1bGFyLmlzRGVmaW5lZChwYWdlKSA/IHBhZ2UgOiAxO1xuICAgICAgdm0uZGVmYXVsdFF1ZXJ5RmlsdGVycyA9IHsgcGFnZTogdm0ucGFnaW5hdG9yLmN1cnJlbnRQYWdlLCBwZXJQYWdlOiB2bS5wYWdpbmF0b3IucGVyUGFnZSB9O1xuXG4gICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmFwcGx5RmlsdGVycykpIHZtLmRlZmF1bHRRdWVyeUZpbHRlcnMgPSB2bS5hcHBseUZpbHRlcnModm0uZGVmYXVsdFF1ZXJ5RmlsdGVycyk7XG4gICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmJlZm9yZVNlYXJjaCkgJiYgdm0uYmVmb3JlU2VhcmNoKHBhZ2UpID09PSBmYWxzZSkgcmV0dXJuIGZhbHNlO1xuXG4gICAgICBtb2RlbFNlcnZpY2UucGFnaW5hdGUodm0uZGVmYXVsdFF1ZXJ5RmlsdGVycykudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgdm0ucGFnaW5hdG9yLmNhbGNOdW1iZXJPZlBhZ2VzKHJlc3BvbnNlLnRvdGFsKTtcbiAgICAgICAgdm0ucmVzb3VyY2VzID0gcmVzcG9uc2UuaXRlbXM7XG5cbiAgICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5hZnRlclNlYXJjaCkpIHZtLmFmdGVyU2VhcmNoKHJlc3BvbnNlKTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWxpemEgYSBwZXNxdWlzYSBjb20gYmFzZSBub3MgZmlsdHJvcyBkZWZpbmlkb3NcbiAgICAgKlxuICAgICAqL1xuICAgIGZ1bmN0aW9uIG5vcm1hbFNlYXJjaCgpIHtcbiAgICAgIHZtLmRlZmF1bHRRdWVyeUZpbHRlcnMgPSB7fTtcblxuICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5hcHBseUZpbHRlcnMpKSB2bS5kZWZhdWx0UXVlcnlGaWx0ZXJzID0gdm0uYXBwbHlGaWx0ZXJzKHZtLmRlZmF1bHRRdWVyeUZpbHRlcnMpO1xuICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5iZWZvcmVTZWFyY2gpICYmIHZtLmJlZm9yZVNlYXJjaCgpID09PSBmYWxzZSkgcmV0dXJuIGZhbHNlO1xuXG4gICAgICBtb2RlbFNlcnZpY2UucXVlcnkodm0uZGVmYXVsdFF1ZXJ5RmlsdGVycykudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgdm0ucmVzb3VyY2VzID0gcmVzcG9uc2U7XG5cbiAgICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5hZnRlclNlYXJjaCkpIHZtLmFmdGVyU2VhcmNoKHJlc3BvbnNlKTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIExpbXBhIG8gZm9ybXVsw6FyaW9cbiAgICAgKi9cbiAgICBmdW5jdGlvbiBjbGVhbkZvcm0oZm9ybSkge1xuICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5iZWZvcmVDbGVhbikgJiYgdm0uYmVmb3JlQ2xlYW4oKSA9PT0gZmFsc2UpIHJldHVybiBmYWxzZTtcblxuICAgICAgdm0ucmVzb3VyY2UgPSBuZXcgbW9kZWxTZXJ2aWNlKCk7XG5cbiAgICAgIGlmIChhbmd1bGFyLmlzRGVmaW5lZChmb3JtKSkge1xuICAgICAgICBmb3JtLiRzZXRQcmlzdGluZSgpO1xuICAgICAgICBmb3JtLiRzZXRVbnRvdWNoZWQoKTtcbiAgICAgIH1cblxuICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5hZnRlckNsZWFuKSkgdm0uYWZ0ZXJDbGVhbigpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENhcnJlZ2Egbm8gZm9ybXVsw6FyaW8gbyByZWN1cnNvIHNlbGVjaW9uYWRvIHBhcmEgZWRpw6fDo29cbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSByZXNvdXJjZSByZWN1cnNvIHNlbGVjaW9uYWRvXG4gICAgICovXG4gICAgZnVuY3Rpb24gZWRpdChyZXNvdXJjZSkge1xuICAgICAgdm0uZ29UbygnZm9ybScpO1xuICAgICAgdm0ucmVzb3VyY2UgPSBuZXcgYW5ndWxhci5jb3B5KHJlc291cmNlKTtcblxuICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5hZnRlckVkaXQpKSB2bS5hZnRlckVkaXQoKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBTYWx2YSBvdSBhdHVhbGl6YSBvIHJlY3Vyc28gY29ycmVudGUgbm8gZm9ybXVsw6FyaW9cbiAgICAgKiBObyBjb21wb3J0YW1lbnRvIHBhZHLDo28gcmVkaXJlY2lvbmEgbyB1c3XDoXJpbyBwYXJhIHZpZXcgZGUgbGlzdGFnZW1cbiAgICAgKiBkZXBvaXMgZGEgZXhlY3XDp8Ojb1xuICAgICAqXG4gICAgICogQHJldHVybnNcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBzYXZlKGZvcm0pIHtcbiAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYmVmb3JlU2F2ZSkgJiYgdm0uYmVmb3JlU2F2ZSgpID09PSBmYWxzZSkgcmV0dXJuIGZhbHNlO1xuXG4gICAgICB2bS5yZXNvdXJjZS4kc2F2ZSgpLnRoZW4oZnVuY3Rpb24gKHJlc291cmNlKSB7XG4gICAgICAgIHZtLnJlc291cmNlID0gcmVzb3VyY2U7XG5cbiAgICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5hZnRlclNhdmUpKSB2bS5hZnRlclNhdmUocmVzb3VyY2UpO1xuXG4gICAgICAgIGlmICh2bS5kZWZhdWx0T3B0aW9ucy5yZWRpcmVjdEFmdGVyU2F2ZSkge1xuICAgICAgICAgIHZtLmNsZWFuRm9ybShmb3JtKTtcbiAgICAgICAgICB2bS5zZWFyY2godm0ucGFnaW5hdG9yLmN1cnJlbnRQYWdlKTtcbiAgICAgICAgICB2bS5nb1RvKCdsaXN0Jyk7XG4gICAgICAgIH1cblxuICAgICAgICBQclRvYXN0LnN1Y2Nlc3MoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5zYXZlU3VjY2VzcycpKTtcbiAgICAgIH0sIGZ1bmN0aW9uIChyZXNwb25zZURhdGEpIHtcbiAgICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5vblNhdmVFcnJvcikpIHZtLm9uU2F2ZUVycm9yKHJlc3BvbnNlRGF0YSk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZW1vdmUgbyByZWN1cnNvIGluZm9ybWFkby5cbiAgICAgKiBBbnRlcyBleGliZSB1bSBkaWFsb2dvIGRlIGNvbmZpcm1hw6fDo29cbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSByZXNvdXJjZSByZWN1cnNvIGVzY29saGlkb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIHJlbW92ZShyZXNvdXJjZSkge1xuICAgICAgdmFyIGNvbmZpZyA9IHtcbiAgICAgICAgdGl0bGU6ICR0cmFuc2xhdGUuaW5zdGFudCgnZGlhbG9nLmNvbmZpcm1UaXRsZScpLFxuICAgICAgICBkZXNjcmlwdGlvbjogJHRyYW5zbGF0ZS5pbnN0YW50KCdkaWFsb2cuY29uZmlybURlc2NyaXB0aW9uJylcbiAgICAgIH07XG5cbiAgICAgIFByRGlhbG9nLmNvbmZpcm0oY29uZmlnKS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5iZWZvcmVSZW1vdmUpICYmIHZtLmJlZm9yZVJlbW92ZShyZXNvdXJjZSkgPT09IGZhbHNlKSByZXR1cm4gZmFsc2U7XG5cbiAgICAgICAgcmVzb3VyY2UuJGRlc3Ryb3koKS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmFmdGVyUmVtb3ZlKSkgdm0uYWZ0ZXJSZW1vdmUocmVzb3VyY2UpO1xuXG4gICAgICAgICAgdm0uc2VhcmNoKCk7XG4gICAgICAgICAgUHJUb2FzdC5pbmZvKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMucmVtb3ZlU3VjY2VzcycpKTtcbiAgICAgICAgfSk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBBbHRlcm5hIGVudHJlIGEgdmlldyBkbyBmb3JtdWzDoXJpbyBlIGxpc3RhZ2VtXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gdmlld05hbWUgbm9tZSBkYSB2aWV3XG4gICAgICovXG4gICAgZnVuY3Rpb24gZ29Ubyh2aWV3TmFtZSkge1xuICAgICAgdm0udmlld0Zvcm0gPSBmYWxzZTtcblxuICAgICAgaWYgKHZpZXdOYW1lID09PSAnZm9ybScpIHtcbiAgICAgICAgdm0uY2xlYW5Gb3JtKCk7XG4gICAgICAgIHZtLnZpZXdGb3JtID0gdHJ1ZTtcbiAgICAgIH1cbiAgICB9XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqXG4gICAqIEFycXVpdm8gZGUgY29uZmlndXJhw6fDo28gY29tIGFzIHJvdGFzIGVzcGVjw61maWNhcyBkbyByZWN1cnNvIHVzZXJcbiAgICpcbiAgICogQHBhcmFtIHthbnl9ICRzdGF0ZVByb3ZpZGVyXG4gICAqIEBwYXJhbSB7YW55fSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnYXBwLmRpbmFtaWMtcXVlcnknLCB7XG4gICAgICB1cmw6ICcvY29uc3VsdGFzLWRpbmFtaWNhcycsXG4gICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL2RpbmFtaWMtcXVlcnlzL2RpbmFtaWMtcXVlcnlzLmh0bWwnLFxuICAgICAgY29udHJvbGxlcjogJ0RpbmFtaWNRdWVyeXNDb250cm9sbGVyIGFzIGRpbmFtaWNRdWVyeUN0cmwnLFxuICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IHRydWUsIG5lZWRQcm9maWxlOiBbJ2FkbWluJ10gfVxuICAgIH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZhY3RvcnkoJ0RpbmFtaWNRdWVyeVNlcnZpY2UnLCBEaW5hbWljUXVlcnlTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIERpbmFtaWNRdWVyeVNlcnZpY2Uoc2VydmljZUZhY3RvcnkpIHtcbiAgICByZXR1cm4gc2VydmljZUZhY3RvcnkoJ2RpbmFtaWNRdWVyeScsIHtcbiAgICAgIC8qKlxuICAgICAgICogYcOnw6NvIGFkaWNpb25hZGEgcGFyYSBwZWdhciB1bWEgbGlzdGEgZGUgbW9kZWxzIGV4aXN0ZW50ZXMgbm8gc2Vydmlkb3JcbiAgICAgICAqL1xuICAgICAgYWN0aW9uczoge1xuICAgICAgICBnZXRNb2RlbHM6IHtcbiAgICAgICAgICBtZXRob2Q6ICdHRVQnLFxuICAgICAgICAgIHVybDogJ21vZGVscydcbiAgICAgICAgfVxuICAgICAgfSxcbiAgICAgIGluc3RhbmNlOiB7fVxuICAgIH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29udHJvbGxlcignRGluYW1pY1F1ZXJ5c0NvbnRyb2xsZXInLCBEaW5hbWljUXVlcnlzQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBEaW5hbWljUXVlcnlzQ29udHJvbGxlcigkY29udHJvbGxlciwgRGluYW1pY1F1ZXJ5U2VydmljZSwgbG9kYXNoLCBQclRvYXN0LCAvLyBOT1NPTkFSXG4gICR0cmFuc2xhdGUpIHtcblxuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICAvL2FjdGlvbnNcbiAgICB2bS5vbkFjdGl2YXRlID0gb25BY3RpdmF0ZTtcbiAgICB2bS5hcHBseUZpbHRlcnMgPSBhcHBseUZpbHRlcnM7XG4gICAgdm0ubG9hZEF0dHJpYnV0ZXMgPSBsb2FkQXR0cmlidXRlcztcbiAgICB2bS5sb2FkT3BlcmF0b3JzID0gbG9hZE9wZXJhdG9ycztcbiAgICB2bS5hZGRGaWx0ZXIgPSBhZGRGaWx0ZXI7XG4gICAgdm0uYWZ0ZXJTZWFyY2ggPSBhZnRlclNlYXJjaDtcbiAgICB2bS5ydW5GaWx0ZXIgPSBydW5GaWx0ZXI7XG4gICAgdm0uZWRpdEZpbHRlciA9IGVkaXRGaWx0ZXI7XG4gICAgdm0ubG9hZE1vZGVscyA9IGxvYWRNb2RlbHM7XG4gICAgdm0ucmVtb3ZlRmlsdGVyID0gcmVtb3ZlRmlsdGVyO1xuICAgIHZtLmNsZWFyID0gY2xlYXI7XG4gICAgdm0ucmVzdGFydCA9IHJlc3RhcnQ7XG5cbiAgICAvL2hlcmRhIG8gY29tcG9ydGFtZW50byBiYXNlIGRvIENSVURcbiAgICAkY29udHJvbGxlcignQ1JVRENvbnRyb2xsZXInLCB7IHZtOiB2bSwgbW9kZWxTZXJ2aWNlOiBEaW5hbWljUXVlcnlTZXJ2aWNlLCBvcHRpb25zOiB7XG4gICAgICAgIHNlYXJjaE9uSW5pdDogZmFsc2VcbiAgICAgIH0gfSk7XG5cbiAgICBmdW5jdGlvbiBvbkFjdGl2YXRlKCkge1xuICAgICAgdm0ucmVzdGFydCgpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFByZXBhcmEgZSBhcGxpY2Egb3MgZmlsdHJvIHF1ZSB2w6NvIHNlciBlbnZpYWRvcyBwYXJhIG8gc2VydmnDp29cbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSBkZWZhdWx0UXVlcnlGaWx0ZXJzXG4gICAgICogQHJldHVybnNcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBhcHBseUZpbHRlcnMoZGVmYXVsdFF1ZXJ5RmlsdGVycykge1xuICAgICAgdmFyIHdoZXJlID0ge307XG5cbiAgICAgIC8qKlxuICAgICAgICogbyBzZXJ2acOnbyBlc3BlcmEgdW0gb2JqZXRvIGNvbTpcbiAgICAgICAqICBvIG5vbWUgZGUgdW0gbW9kZWxcbiAgICAgICAqICB1bWEgbGlzdGEgZGUgZmlsdHJvc1xuICAgICAgICovXG4gICAgICBpZiAodm0uYWRkZWRGaWx0ZXJzLmxlbmd0aCA+IDApIHtcbiAgICAgICAgdmFyIGFkZGVkRmlsdGVycyA9IGFuZ3VsYXIuY29weSh2bS5hZGRlZEZpbHRlcnMpO1xuXG4gICAgICAgIHdoZXJlLm1vZGVsID0gdm0uYWRkZWRGaWx0ZXJzWzBdLm1vZGVsLm5hbWU7XG5cbiAgICAgICAgZm9yICh2YXIgaW5kZXggPSAwOyBpbmRleCA8IGFkZGVkRmlsdGVycy5sZW5ndGg7IGluZGV4KyspIHtcbiAgICAgICAgICB2YXIgZmlsdGVyID0gYWRkZWRGaWx0ZXJzW2luZGV4XTtcblxuICAgICAgICAgIGZpbHRlci5tb2RlbCA9IG51bGw7XG4gICAgICAgICAgZmlsdGVyLmF0dHJpYnV0ZSA9IGZpbHRlci5hdHRyaWJ1dGUubmFtZTtcbiAgICAgICAgICBmaWx0ZXIub3BlcmF0b3IgPSBmaWx0ZXIub3BlcmF0b3IudmFsdWU7XG4gICAgICAgIH1cblxuICAgICAgICB3aGVyZS5maWx0ZXJzID0gYW5ndWxhci50b0pzb24oYWRkZWRGaWx0ZXJzKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHdoZXJlLm1vZGVsID0gdm0ucXVlcnlGaWx0ZXJzLm1vZGVsLm5hbWU7XG4gICAgICB9XG5cbiAgICAgIHJldHVybiBhbmd1bGFyLmV4dGVuZChkZWZhdWx0UXVlcnlGaWx0ZXJzLCB3aGVyZSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ2FycmVnYSB0b2RvcyBvcyBtb2RlbHMgY3JpYWRvcyBubyBzZXJ2aWRvciBjb20gc2V1cyBhdHJpYnV0b3NcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBsb2FkTW9kZWxzKCkge1xuICAgICAgLy9QZWdhIHRvZG9zIG9zIG1vZGVscyBkbyBzZXJ2ZXIgZSBtb250YSB1bWEgbGlzdGEgcHJvIENvbWJvQm94XG4gICAgICBEaW5hbWljUXVlcnlTZXJ2aWNlLmdldE1vZGVscygpLnRoZW4oZnVuY3Rpb24gKGRhdGEpIHtcbiAgICAgICAgdm0ubW9kZWxzID0gZGF0YTtcbiAgICAgICAgdm0ucXVlcnlGaWx0ZXJzLm1vZGVsID0gdm0ubW9kZWxzWzBdO1xuICAgICAgICB2bS5sb2FkQXR0cmlidXRlcygpO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ2FycmVnYSBvcyBhdHRyaWJ1dG9zIGRvIG1vZGVsIGVzY29saGlkb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGxvYWRBdHRyaWJ1dGVzKCkge1xuICAgICAgdm0uYXR0cmlidXRlcyA9IHZtLnF1ZXJ5RmlsdGVycy5tb2RlbC5hdHRyaWJ1dGVzO1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzLmF0dHJpYnV0ZSA9IHZtLmF0dHJpYnV0ZXNbMF07XG5cbiAgICAgIHZtLmxvYWRPcGVyYXRvcnMoKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDYXJyZWdhIG9zIG9wZXJhZG9yZXMgZXNwZWNpZmljb3MgcGFyYSBvIHRpcG8gZG8gYXRyaWJ1dG9cbiAgICAgKi9cbiAgICBmdW5jdGlvbiBsb2FkT3BlcmF0b3JzKCkge1xuICAgICAgdmFyIG9wZXJhdG9ycyA9IFt7IHZhbHVlOiAnPScsIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLmVxdWFscycpIH0sIHsgdmFsdWU6ICc8PicsIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLmRpZmVyZW50JykgfV07XG5cbiAgICAgIGlmICh2bS5xdWVyeUZpbHRlcnMuYXR0cmlidXRlLnR5cGUuaW5kZXhPZigndmFyeWluZycpICE9PSAtMSkge1xuICAgICAgICBvcGVyYXRvcnMucHVzaCh7IHZhbHVlOiAnaGFzJyxcbiAgICAgICAgICBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KCd2aWV3cy5maWVsZHMucXVlcnlEaW5hbWljLm9wZXJhdG9ycy5jb250ZWlucycpIH0pO1xuICAgICAgICBvcGVyYXRvcnMucHVzaCh7IHZhbHVlOiAnc3RhcnRXaXRoJyxcbiAgICAgICAgICBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KCd2aWV3cy5maWVsZHMucXVlcnlEaW5hbWljLm9wZXJhdG9ycy5zdGFydFdpdGgnKSB9KTtcbiAgICAgICAgb3BlcmF0b3JzLnB1c2goeyB2YWx1ZTogJ2VuZFdpdGgnLFxuICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLmZpbmlzaFdpdGgnKSB9KTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIG9wZXJhdG9ycy5wdXNoKHsgdmFsdWU6ICc+JyxcbiAgICAgICAgICBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KCd2aWV3cy5maWVsZHMucXVlcnlEaW5hbWljLm9wZXJhdG9ycy5iaWdnZXJUaGFuJykgfSk7XG4gICAgICAgIG9wZXJhdG9ycy5wdXNoKHsgdmFsdWU6ICc+PScsXG4gICAgICAgICAgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudCgndmlld3MuZmllbGRzLnF1ZXJ5RGluYW1pYy5vcGVyYXRvcnMuZXF1YWxzT3JCaWdnZXJUaGFuJykgfSk7XG4gICAgICAgIG9wZXJhdG9ycy5wdXNoKHsgdmFsdWU6ICc8JyxcbiAgICAgICAgICBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KCd2aWV3cy5maWVsZHMucXVlcnlEaW5hbWljLm9wZXJhdG9ycy5sZXNzVGhhbicpIH0pO1xuICAgICAgICBvcGVyYXRvcnMucHVzaCh7IHZhbHVlOiAnPD0nLFxuICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLmVxdWFsc09yTGVzc1RoYW4nKSB9KTtcbiAgICAgIH1cblxuICAgICAgdm0ub3BlcmF0b3JzID0gb3BlcmF0b3JzO1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzLm9wZXJhdG9yID0gdm0ub3BlcmF0b3JzWzBdO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEFkaWNpb25hL2VkaXRhIHVtIGZpbHRyb1xuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IGZvcm0gZWxlbWVudG8gaHRtbCBkbyBmb3JtdWzDoXJpbyBwYXJhIHZhbGlkYcOnw7Vlc1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGFkZEZpbHRlcihmb3JtKSB7XG4gICAgICBpZiAoYW5ndWxhci5pc1VuZGVmaW5lZCh2bS5xdWVyeUZpbHRlcnMudmFsdWUpIHx8IHZtLnF1ZXJ5RmlsdGVycy52YWx1ZSA9PT0gJycpIHtcbiAgICAgICAgUHJUb2FzdC5lcnJvcigkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnZhbGlkYXRlLmZpZWxkUmVxdWlyZWQnLCB7IGZpZWxkOiAndmFsb3InIH0pKTtcbiAgICAgICAgcmV0dXJuO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgaWYgKHZtLmluZGV4IDwgMCkge1xuICAgICAgICAgIHZtLmFkZGVkRmlsdGVycy5wdXNoKGFuZ3VsYXIuY29weSh2bS5xdWVyeUZpbHRlcnMpKTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICB2bS5hZGRlZEZpbHRlcnNbdm0uaW5kZXhdID0gYW5ndWxhci5jb3B5KHZtLnF1ZXJ5RmlsdGVycyk7XG4gICAgICAgICAgdm0uaW5kZXggPSAtMTtcbiAgICAgICAgfVxuXG4gICAgICAgIC8vcmVpbmljaWEgbyBmb3JtdWzDoXJpbyBlIGFzIHZhbGlkYcOnw7VlcyBleGlzdGVudGVzXG4gICAgICAgIHZtLnF1ZXJ5RmlsdGVycyA9IHt9O1xuICAgICAgICBmb3JtLiRzZXRQcmlzdGluZSgpO1xuICAgICAgICBmb3JtLiRzZXRVbnRvdWNoZWQoKTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFsaXphIGEgcGVzcXVpc2EgdGVuZG8gb3MgZmlsdHJvcyBjb21vIHBhcsOibWV0cm9zXG4gICAgICovXG4gICAgZnVuY3Rpb24gcnVuRmlsdGVyKCkge1xuICAgICAgdm0uc2VhcmNoKHZtLnBhZ2luYXRvci5jdXJyZW50UGFnZSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogR2F0aWxobyBhY2lvbmFkbyBkZXBvaXMgZGEgcGVzcXVpc2EgcmVzcG9uc8OhdmVsIHBvciBpZGVudGlmaWNhciBvcyBhdHJpYnV0b3NcbiAgICAgKiBjb250aWRvcyBub3MgZWxlbWVudG9zIHJlc3VsdGFudGVzIGRhIGJ1c2NhXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gZGF0YSBkYWRvcyByZWZlcmVudGUgYW8gcmV0b3JubyBkYSByZXF1aXNpw6fDo29cbiAgICAgKi9cbiAgICBmdW5jdGlvbiBhZnRlclNlYXJjaChkYXRhKSB7XG4gICAgICB2YXIga2V5cyA9IGRhdGEuaXRlbXMubGVuZ3RoID4gMCA/IE9iamVjdC5rZXlzKGRhdGEuaXRlbXNbMF0pIDogW107XG5cbiAgICAgIC8vcmV0aXJhIHRvZG9zIG9zIGF0cmlidXRvcyBxdWUgY29tZcOnYW0gY29tICQuXG4gICAgICAvL0Vzc2VzIGF0cmlidXRvcyBzw6NvIGFkaWNpb25hZG9zIHBlbG8gc2VydmnDp28gZSBuw6NvIGRldmUgYXBhcmVjZXIgbmEgbGlzdGFnZW1cbiAgICAgIHZtLmtleXMgPSBsb2Rhc2guZmlsdGVyKGtleXMsIGZ1bmN0aW9uIChrZXkpIHtcbiAgICAgICAgcmV0dXJuICFsb2Rhc2guc3RhcnRzV2l0aChrZXksICckJyk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDb2xvYWNhIG5vIGZvcm11bMOhcmlvIG8gZmlsdHJvIGVzY29saGlkbyBwYXJhIGVkacOnw6NvXG4gICAgICogQHBhcmFtIHthbnl9ICRpbmRleCBpbmRpY2Ugbm8gYXJyYXkgZG8gZmlsdHJvIGVzY29saGlkb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGVkaXRGaWx0ZXIoJGluZGV4KSB7XG4gICAgICB2bS5pbmRleCA9ICRpbmRleDtcbiAgICAgIHZtLnF1ZXJ5RmlsdGVycyA9IHZtLmFkZGVkRmlsdGVyc1skaW5kZXhdO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlbW92ZSBvIGZpbHRybyBlc2NvbGhpZG9cbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSAkaW5kZXggaW5kaWNlIG5vIGFycmF5IGRvIGZpbHRybyBlc2NvbGhpZG9cbiAgICAgKi9cbiAgICBmdW5jdGlvbiByZW1vdmVGaWx0ZXIoJGluZGV4KSB7XG4gICAgICB2bS5hZGRlZEZpbHRlcnMuc3BsaWNlKCRpbmRleCk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogTGltcGEgbyBmb3JtdWzDoXJpbyBjb3JyZW50ZVxuICAgICAqL1xuICAgIGZ1bmN0aW9uIGNsZWFyKCkge1xuICAgICAgLy9ndWFyZGEgbyBpbmRpY2UgZG8gcmVnaXN0cm8gcXVlIGVzdMOhIHNlbmRvIGVkaXRhZG9cbiAgICAgIHZtLmluZGV4ID0gLTE7XG4gICAgICAvL3ZpbmN1bGFkbyBhb3MgY2FtcG9zIGRvIGZvcm11bMOhcmlvXG4gICAgICB2bS5xdWVyeUZpbHRlcnMgPSB7fTtcblxuICAgICAgaWYgKHZtLm1vZGVscykgdm0ucXVlcnlGaWx0ZXJzLm1vZGVsID0gdm0ubW9kZWxzWzBdO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlaW5pY2lhIGEgY29uc3RydcOnw6NvIGRhIHF1ZXJ5IGxpbXBhbmRvIHR1ZG9cbiAgICAgKlxuICAgICAqL1xuICAgIGZ1bmN0aW9uIHJlc3RhcnQoKSB7XG4gICAgICAvL2d1YXJkYSBhdHJpYnV0b3MgZG8gcmVzdWx0YWRvIGRhIGJ1c2NhIGNvcnJlbnRlXG4gICAgICB2bS5rZXlzID0gW107XG5cbiAgICAgIC8vZ3VhcmRhIG9zIGZpbHRyb3MgYWRpY2lvbmFkb3NcbiAgICAgIHZtLmFkZGVkRmlsdGVycyA9IFtdO1xuICAgICAgdm0uY2xlYXIoKTtcbiAgICAgIHZtLmxvYWRNb2RlbHMoKTtcbiAgICB9XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5mYWN0b3J5KCdsYW5ndWFnZUxvYWRlcicsIExhbmd1YWdlTG9hZGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIExhbmd1YWdlTG9hZGVyKCRxLCBTdXBwb3J0U2VydmljZSwgJGxvZywgJGluamVjdG9yKSB7XG4gICAgdmFyIHNlcnZpY2UgPSB0aGlzO1xuXG4gICAgc2VydmljZS50cmFuc2xhdGUgPSBmdW5jdGlvbiAobG9jYWxlKSB7XG4gICAgICByZXR1cm4ge1xuICAgICAgICBnbG9iYWw6ICRpbmplY3Rvci5nZXQobG9jYWxlICsgJy5pMThuLmdsb2JhbCcpLFxuICAgICAgICB2aWV3czogJGluamVjdG9yLmdldChsb2NhbGUgKyAnLmkxOG4udmlld3MnKSxcbiAgICAgICAgYXR0cmlidXRlczogJGluamVjdG9yLmdldChsb2NhbGUgKyAnLmkxOG4uYXR0cmlidXRlcycpLFxuICAgICAgICBkaWFsb2c6ICRpbmplY3Rvci5nZXQobG9jYWxlICsgJy5pMThuLmRpYWxvZycpLFxuICAgICAgICBtZXNzYWdlczogJGluamVjdG9yLmdldChsb2NhbGUgKyAnLmkxOG4ubWVzc2FnZXMnKSxcbiAgICAgICAgbW9kZWxzOiAkaW5qZWN0b3IuZ2V0KGxvY2FsZSArICcuaTE4bi5tb2RlbHMnKVxuICAgICAgfTtcbiAgICB9O1xuXG4gICAgLy8gcmV0dXJuIGxvYWRlckZuXG4gICAgcmV0dXJuIGZ1bmN0aW9uIChvcHRpb25zKSB7XG4gICAgICAkbG9nLmluZm8oJ0NhcnJlZ2FuZG8gbyBjb250ZXVkbyBkYSBsaW5ndWFnZW0gJyArIG9wdGlvbnMua2V5KTtcblxuICAgICAgdmFyIGRlZmVycmVkID0gJHEuZGVmZXIoKTtcblxuICAgICAgLy9DYXJyZWdhIGFzIGxhbmdzIHF1ZSBwcmVjaXNhbSBlIGVzdMOjbyBubyBzZXJ2aWRvciBwYXJhIG7Do28gcHJlY2lzYXIgcmVwZXRpciBhcXVpXG4gICAgICBTdXBwb3J0U2VydmljZS5sYW5ncygpLnRoZW4oZnVuY3Rpb24gKGxhbmdzKSB7XG4gICAgICAgIC8vTWVyZ2UgY29tIG9zIGxhbmdzIGRlZmluaWRvcyBubyBzZXJ2aWRvclxuICAgICAgICB2YXIgZGF0YSA9IGFuZ3VsYXIubWVyZ2Uoc2VydmljZS50cmFuc2xhdGUob3B0aW9ucy5rZXkpLCBsYW5ncyk7XG5cbiAgICAgICAgcmV0dXJuIGRlZmVycmVkLnJlc29sdmUoZGF0YSk7XG4gICAgICB9LCBmdW5jdGlvbiAoKSB7XG4gICAgICAgIHJldHVybiBkZWZlcnJlZC5yZXNvbHZlKHNlcnZpY2UudHJhbnNsYXRlKG9wdGlvbnMua2V5KSk7XG4gICAgICB9KTtcblxuICAgICAgcmV0dXJuIGRlZmVycmVkLnByb21pc2U7XG4gICAgfTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZpbHRlcigndEF0dHInLCB0QXR0cik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiB0QXR0cigkZmlsdGVyKSB7XG4gICAgLyoqXG4gICAgICogRmlsdHJvIHBhcmEgdHJhZHXDp8OjbyBkZSB1bSBhdHJpYnV0byBkZSB1bSBtb2RlbFxuICAgICAqIFxuICAgICAqIEBwYXJhbSB7YW55fSBuYW1lIG5vbWUgZG8gYXRyaWJ1dG9cbiAgICAgKiBAcmV0dXJucyBvIG5vbWUgZG8gYXRyaWJ1dG8gdHJhZHV6aWRvIGNhc28gZW5jb250cmUgc2UgbsOjbyBvIG5vbWUgcGFzc2FkbyBwb3IgcGFyYW1ldHJvXG4gICAgICovXG4gICAgcmV0dXJuIGZ1bmN0aW9uIChuYW1lKSB7XG4gICAgICB2YXIga2V5ID0gJ2F0dHJpYnV0ZXMuJyArIG5hbWU7XG4gICAgICB2YXIgdHJhbnNsYXRlID0gJGZpbHRlcigndHJhbnNsYXRlJykoa2V5KTtcblxuICAgICAgcmV0dXJuIHRyYW5zbGF0ZSA9PT0ga2V5ID8gbmFtZSA6IHRyYW5zbGF0ZTtcbiAgICB9O1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmlsdGVyKCd0QnJlYWRjcnVtYicsIHRCcmVhZGNydW1iKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIHRCcmVhZGNydW1iKCRmaWx0ZXIpIHtcbiAgICAvKipcbiAgICAgKiBGaWx0cm8gcGFyYSB0cmFkdcOnw6NvIGRvIGJyZWFkY3J1bWIgKHRpdHVsbyBkYSB0ZWxhIGNvbSByYXN0cmVpbylcbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSBpZCBjaGF2ZSBjb20gbyBub21lIGRvIHN0YXRlIHJlZmVyZW50ZSB0ZWxhXG4gICAgICogQHJldHVybnMgYSB0cmFkdcOnw6NvIGNhc28gZW5jb250cmUgc2UgbsOjbyBvIGlkIHBhc3NhZG8gcG9yIHBhcmFtZXRyb1xuICAgICAqL1xuICAgIHJldHVybiBmdW5jdGlvbiAoaWQpIHtcbiAgICAgIC8vcGVnYSBhIHNlZ3VuZGEgcGFydGUgZG8gbm9tZSBkbyBzdGF0ZSwgcmV0aXJhbmRvIGEgcGFydGUgYWJzdHJhdGEgKGFwcC4pXG4gICAgICB2YXIga2V5ID0gJ3ZpZXdzLmJyZWFkY3J1bWJzLicgKyBpZC5zcGxpdCgnLicpWzFdO1xuICAgICAgdmFyIHRyYW5zbGF0ZSA9ICRmaWx0ZXIoJ3RyYW5zbGF0ZScpKGtleSk7XG5cbiAgICAgIHJldHVybiB0cmFuc2xhdGUgPT09IGtleSA/IGlkIDogdHJhbnNsYXRlO1xuICAgIH07XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5maWx0ZXIoJ3RNb2RlbCcsIHRNb2RlbCk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiB0TW9kZWwoJGZpbHRlcikge1xuICAgIC8qKlxuICAgICAqIEZpbHRybyBwYXJhIHRyYWR1w6fDo28gZGUgdW0gYXRyaWJ1dG8gZGUgdW0gbW9kZWxcbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSBuYW1lIG5vbWUgZG8gYXRyaWJ1dG9cbiAgICAgKiBAcmV0dXJucyBvIG5vbWUgZG8gYXRyaWJ1dG8gdHJhZHV6aWRvIGNhc28gZW5jb250cmUgc2UgbsOjbyBvIG5vbWUgcGFzc2FkbyBwb3IgcGFyYW1ldHJvXG4gICAgICovXG4gICAgcmV0dXJuIGZ1bmN0aW9uIChuYW1lKSB7XG4gICAgICB2YXIga2V5ID0gJ21vZGVscy4nICsgbmFtZS50b0xvd2VyQ2FzZSgpO1xuICAgICAgdmFyIHRyYW5zbGF0ZSA9ICRmaWx0ZXIoJ3RyYW5zbGF0ZScpKGtleSk7XG5cbiAgICAgIHJldHVybiB0cmFuc2xhdGUgPT09IGtleSA/IG5hbWUgOiB0cmFuc2xhdGU7XG4gICAgfTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5ydW4oYXV0aGVudGljYXRpb25MaXN0ZW5lcik7XG5cbiAgLyoqXG4gICAqIExpc3RlbiBhbGwgc3RhdGUgKHBhZ2UpIGNoYW5nZXMuIEV2ZXJ5IHRpbWUgYSBzdGF0ZSBjaGFuZ2UgbmVlZCB0byB2ZXJpZnkgdGhlIHVzZXIgaXMgYXV0aGVudGljYXRlZCBvciBub3QgdG9cbiAgICogcmVkaXJlY3QgdG8gY29ycmVjdCBwYWdlLiBXaGVuIGEgdXNlciBjbG9zZSB0aGUgYnJvd3NlciB3aXRob3V0IGxvZ291dCwgd2hlbiBoaW0gcmVvcGVuIHRoZSBicm93c2VyIHRoaXMgZXZlbnRcbiAgICogcmVhdXRoZW50aWNhdGUgdGhlIHVzZXIgd2l0aCB0aGUgcGVyc2lzdGVudCB0b2tlbiBvZiB0aGUgbG9jYWwgc3RvcmFnZS5cbiAgICpcbiAgICogV2UgZG9uJ3QgY2hlY2sgaWYgdGhlIHRva2VuIGlzIGV4cGlyZWQgb3Igbm90IGluIHRoZSBwYWdlIGNoYW5nZSwgYmVjYXVzZSBpcyBnZW5lcmF0ZSBhbiB1bmVjZXNzYXJ5IG92ZXJoZWFkLlxuICAgKiBJZiB0aGUgdG9rZW4gaXMgZXhwaXJlZCB3aGVuIHRoZSB1c2VyIHRyeSB0byBjYWxsIHRoZSBmaXJzdCBhcGkgdG8gZ2V0IGRhdGEsIGhpbSB3aWxsIGJlIGxvZ29mZiBhbmQgcmVkaXJlY3RcbiAgICogdG8gbG9naW4gcGFnZS5cbiAgICpcbiAgICogQHBhcmFtICRyb290U2NvcGVcbiAgICogQHBhcmFtICRzdGF0ZVxuICAgKiBAcGFyYW0gJHN0YXRlUGFyYW1zXG4gICAqIEBwYXJhbSBBdXRoXG4gICAqL1xuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIGF1dGhlbnRpY2F0aW9uTGlzdGVuZXIoJHJvb3RTY29wZSwgJHN0YXRlLCBHbG9iYWwsIEF1dGgsIFByVG9hc3QsIC8vIE5PU09OQVJcbiAgJHRyYW5zbGF0ZSkge1xuXG4gICAgLy9vbmx5IHdoZW4gYXBwbGljYXRpb24gc3RhcnQgY2hlY2sgaWYgdGhlIGV4aXN0ZW50IHRva2VuIHN0aWxsIHZhbGlkXG4gICAgQXV0aC5yZW1vdGVWYWxpZGF0ZVRva2VuKCkudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAvL2lmIHRoZSB0b2tlbiBpcyB2YWxpZCBjaGVjayBpZiBleGlzdHMgdGhlIHVzZXIgYmVjYXVzZSB0aGUgYnJvd3NlciBjb3VsZCBiZSBjbG9zZWRcbiAgICAgIC8vYW5kIHRoZSB1c2VyIGRhdGEgaXNuJ3QgaW4gbWVtb3J5XG4gICAgICBpZiAoQXV0aC5jdXJyZW50VXNlciA9PT0gbnVsbCkge1xuICAgICAgICBBdXRoLnVwZGF0ZUN1cnJlbnRVc2VyKGFuZ3VsYXIuZnJvbUpzb24obG9jYWxTdG9yYWdlLmdldEl0ZW0oJ3VzZXInKSkpO1xuICAgICAgfVxuICAgIH0pO1xuXG4gICAgLy9DaGVjayBpZiB0aGUgdG9rZW4gc3RpbGwgdmFsaWQuXG4gICAgJHJvb3RTY29wZS4kb24oJyRzdGF0ZUNoYW5nZVN0YXJ0JywgZnVuY3Rpb24gKGV2ZW50LCB0b1N0YXRlKSB7XG4gICAgICBpZiAodG9TdGF0ZS5kYXRhLm5lZWRBdXRoZW50aWNhdGlvbiB8fCB0b1N0YXRlLmRhdGEubmVlZFByb2ZpbGUpIHtcbiAgICAgICAgLy9kb250IHRyYWl0IHRoZSBzdWNjZXNzIGJsb2NrIGJlY2F1c2UgYWxyZWFkeSBkaWQgYnkgdG9rZW4gaW50ZXJjZXB0b3JcbiAgICAgICAgQXV0aC5yZW1vdGVWYWxpZGF0ZVRva2VuKCkuY2F0Y2goZnVuY3Rpb24gKCkge1xuICAgICAgICAgIFByVG9hc3Qud2FybigkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLmxvZ2luLmxvZ291dEluYWN0aXZlJykpO1xuXG4gICAgICAgICAgaWYgKHRvU3RhdGUubmFtZSAhPT0gR2xvYmFsLmxvZ2luU3RhdGUpIHtcbiAgICAgICAgICAgICRzdGF0ZS5nbyhHbG9iYWwubG9naW5TdGF0ZSk7XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgZXZlbnQucHJldmVudERlZmF1bHQoKTtcbiAgICAgICAgfSk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICAvL2lmIHRoZSB1c2UgaXMgYXV0aGVudGljYXRlZCBhbmQgbmVlZCB0byBlbnRlciBpbiBsb2dpbiBwYWdlXG4gICAgICAgIC8vaGltIHdpbGwgYmUgcmVkaXJlY3RlZCB0byBob21lIHBhZ2VcbiAgICAgICAgaWYgKHRvU3RhdGUubmFtZSA9PT0gR2xvYmFsLmxvZ2luU3RhdGUgJiYgQXV0aC5hdXRoZW50aWNhdGVkKCkpIHtcbiAgICAgICAgICAkc3RhdGUuZ28oR2xvYmFsLmhvbWVTdGF0ZSk7XG4gICAgICAgICAgZXZlbnQucHJldmVudERlZmF1bHQoKTtcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLnJ1bihhdXRob3JpemF0aW9uTGlzdGVuZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gYXV0aG9yaXphdGlvbkxpc3RlbmVyKCRyb290U2NvcGUsICRzdGF0ZSwgR2xvYmFsLCBBdXRoKSB7XG4gICAgLyoqXG4gICAgICogQSBjYWRhIG11ZGFuw6dhIGRlIGVzdGFkbyAoXCJww6FnaW5hXCIpIHZlcmlmaWNhIHNlIG8gdXN1w6FyaW8gdGVtIG8gcGVyZmlsXG4gICAgICogbmVjZXNzw6FyaW8gcGFyYSBvIGFjZXNzbyBhIG1lc21hXG4gICAgICovXG4gICAgJHJvb3RTY29wZS4kb24oJyRzdGF0ZUNoYW5nZVN0YXJ0JywgZnVuY3Rpb24gKGV2ZW50LCB0b1N0YXRlKSB7XG4gICAgICBpZiAodG9TdGF0ZS5kYXRhICYmIHRvU3RhdGUuZGF0YS5uZWVkQXV0aGVudGljYXRpb24gJiYgdG9TdGF0ZS5kYXRhLm5lZWRQcm9maWxlICYmIEF1dGguYXV0aGVudGljYXRlZCgpICYmICFBdXRoLmN1cnJlbnRVc2VyLmhhc1Byb2ZpbGUodG9TdGF0ZS5kYXRhLm5lZWRQcm9maWxlLCB0b1N0YXRlLmRhdGEuYWxsUHJvZmlsZXMpKSB7XG5cbiAgICAgICAgJHN0YXRlLmdvKEdsb2JhbC5ub3RBdXRob3JpemVkU3RhdGUpO1xuICAgICAgICBldmVudC5wcmV2ZW50RGVmYXVsdCgpO1xuICAgICAgfVxuICAgIH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbmZpZyhzcGlubmVySW50ZXJjZXB0b3IpO1xuXG4gIGZ1bmN0aW9uIHNwaW5uZXJJbnRlcmNlcHRvcigkaHR0cFByb3ZpZGVyLCAkcHJvdmlkZSkge1xuICAgIC8qKlxuICAgICAqIEVzdGUgaW50ZXJjZXB0b3Igw6kgcmVzcG9uc8OhdmVsIHBvciBtb3N0cmFyIGUgZXNjb25kZXIgb1xuICAgICAqIGNvbXBvbmVudGUgUHJTcGlubmVyIHNlbXByZSBxdWUgdW1hIHJlcXVpc2nDp8OjbyBhamF4XG4gICAgICogaW5pY2lhciBlIGZpbmFsaXphci5cbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSAkcVxuICAgICAqIEBwYXJhbSB7YW55fSAkaW5qZWN0b3JcbiAgICAgKiBAcmV0dXJuc1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIHNob3dIaWRlU3Bpbm5lcigkcSwgJGluamVjdG9yKSB7XG4gICAgICByZXR1cm4ge1xuICAgICAgICByZXF1ZXN0OiBmdW5jdGlvbiByZXF1ZXN0KGNvbmZpZykge1xuICAgICAgICAgICRpbmplY3Rvci5nZXQoJ1ByU3Bpbm5lcicpLnNob3coKTtcblxuICAgICAgICAgIHJldHVybiBjb25maWc7XG4gICAgICAgIH0sXG5cbiAgICAgICAgcmVzcG9uc2U6IGZ1bmN0aW9uIHJlc3BvbnNlKF9yZXNwb25zZSkge1xuICAgICAgICAgICRpbmplY3Rvci5nZXQoJ1ByU3Bpbm5lcicpLmhpZGUoKTtcblxuICAgICAgICAgIHJldHVybiBfcmVzcG9uc2U7XG4gICAgICAgIH0sXG5cbiAgICAgICAgcmVzcG9uc2VFcnJvcjogZnVuY3Rpb24gcmVzcG9uc2VFcnJvcihyZWplY3Rpb24pIHtcbiAgICAgICAgICAkaW5qZWN0b3IuZ2V0KCdQclNwaW5uZXInKS5oaWRlKCk7XG5cbiAgICAgICAgICByZXR1cm4gJHEucmVqZWN0KHJlamVjdGlvbik7XG4gICAgICAgIH1cbiAgICAgIH07XG4gICAgfVxuXG4gICAgLy8gRGVmaW5lIHVtYSBmYWN0b3J5IHBhcmEgbyAkaHR0cEludGVyY2VwdG9yXG4gICAgJHByb3ZpZGUuZmFjdG9yeSgnc2hvd0hpZGVTcGlubmVyJywgc2hvd0hpZGVTcGlubmVyKTtcblxuICAgIC8vIEFkaWNpb25hIGEgZmFjdG9yeSBubyBhcnJheSBkZSBpbnRlcmNlcHRvcnMgZG8gJGh0dHBcbiAgICAkaHR0cFByb3ZpZGVyLmludGVyY2VwdG9ycy5wdXNoKCdzaG93SGlkZVNwaW5uZXInKTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuLyplc2xpbnQgYW5ndWxhci9tb2R1bGUtZ2V0dGVyOiAwKi9cblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25maWcodG9rZW5JbnRlcmNlcHRvcik7XG5cbiAgLyoqXG4gICAqIEludGVyY2VwdCBhbGwgcmVzcG9uc2UgKHN1Y2Nlc3Mgb3IgZXJyb3IpIHRvIHZlcmlmeSB0aGUgcmV0dXJuZWQgdG9rZW5cbiAgICpcbiAgICogQHBhcmFtICRodHRwUHJvdmlkZXJcbiAgICogQHBhcmFtICRwcm92aWRlXG4gICAqIEBwYXJhbSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gdG9rZW5JbnRlcmNlcHRvcigkaHR0cFByb3ZpZGVyLCAkcHJvdmlkZSwgR2xvYmFsKSB7XG5cbiAgICBmdW5jdGlvbiByZWRpcmVjdFdoZW5TZXJ2ZXJMb2dnZWRPdXQoJHEsICRpbmplY3Rvcikge1xuICAgICAgcmV0dXJuIHtcbiAgICAgICAgcmVxdWVzdDogZnVuY3Rpb24gcmVxdWVzdChjb25maWcpIHtcbiAgICAgICAgICB2YXIgdG9rZW4gPSAkaW5qZWN0b3IuZ2V0KCdBdXRoJykuZ2V0VG9rZW4oKTtcblxuICAgICAgICAgIGlmICh0b2tlbikge1xuICAgICAgICAgICAgY29uZmlnLmhlYWRlcnNbJ0F1dGhvcml6YXRpb24nXSA9ICdCZWFyZXIgJyArIHRva2VuO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIHJldHVybiBjb25maWc7XG4gICAgICAgIH0sXG4gICAgICAgIHJlc3BvbnNlOiBmdW5jdGlvbiByZXNwb25zZShfcmVzcG9uc2UpIHtcbiAgICAgICAgICAvLyBnZXQgYSBuZXcgcmVmcmVzaCB0b2tlbiB0byB1c2UgaW4gdGhlIG5leHQgcmVxdWVzdFxuICAgICAgICAgIHZhciB0b2tlbiA9IF9yZXNwb25zZS5oZWFkZXJzKCdBdXRob3JpemF0aW9uJyk7XG5cbiAgICAgICAgICBpZiAodG9rZW4pIHtcbiAgICAgICAgICAgICRpbmplY3Rvci5nZXQoJ0F1dGgnKS5zZXRUb2tlbih0b2tlbi5zcGxpdCgnICcpWzFdKTtcbiAgICAgICAgICB9XG4gICAgICAgICAgcmV0dXJuIF9yZXNwb25zZTtcbiAgICAgICAgfSxcbiAgICAgICAgcmVzcG9uc2VFcnJvcjogZnVuY3Rpb24gcmVzcG9uc2VFcnJvcihyZWplY3Rpb24pIHtcbiAgICAgICAgICAvLyBJbnN0ZWFkIG9mIGNoZWNraW5nIGZvciBhIHN0YXR1cyBjb2RlIG9mIDQwMCB3aGljaCBtaWdodCBiZSB1c2VkXG4gICAgICAgICAgLy8gZm9yIG90aGVyIHJlYXNvbnMgaW4gTGFyYXZlbCwgd2UgY2hlY2sgZm9yIHRoZSBzcGVjaWZpYyByZWplY3Rpb25cbiAgICAgICAgICAvLyByZWFzb25zIHRvIHRlbGwgdXMgaWYgd2UgbmVlZCB0byByZWRpcmVjdCB0byB0aGUgbG9naW4gc3RhdGVcbiAgICAgICAgICB2YXIgcmVqZWN0aW9uUmVhc29ucyA9IFsndG9rZW5fbm90X3Byb3ZpZGVkJywgJ3Rva2VuX2V4cGlyZWQnLCAndG9rZW5fYWJzZW50JywgJ3Rva2VuX2ludmFsaWQnXTtcblxuICAgICAgICAgIHZhciB0b2tlbkVycm9yID0gZmFsc2U7XG5cbiAgICAgICAgICBhbmd1bGFyLmZvckVhY2gocmVqZWN0aW9uUmVhc29ucywgZnVuY3Rpb24gKHZhbHVlKSB7XG4gICAgICAgICAgICBpZiAocmVqZWN0aW9uLmRhdGEgJiYgcmVqZWN0aW9uLmRhdGEuZXJyb3IgPT09IHZhbHVlKSB7XG4gICAgICAgICAgICAgIHRva2VuRXJyb3IgPSB0cnVlO1xuXG4gICAgICAgICAgICAgICRpbmplY3Rvci5nZXQoJ0F1dGgnKS5sb2dvdXQoKS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICB2YXIgJHN0YXRlID0gJGluamVjdG9yLmdldCgnJHN0YXRlJyk7XG5cbiAgICAgICAgICAgICAgICAvLyBpbiBjYXNlIG11bHRpcGxlIGFqYXggcmVxdWVzdCBmYWlsIGF0IHNhbWUgdGltZSBiZWNhdXNlIHRva2VuIHByb2JsZW1zLFxuICAgICAgICAgICAgICAgIC8vIG9ubHkgdGhlIGZpcnN0IHdpbGwgcmVkaXJlY3RcbiAgICAgICAgICAgICAgICBpZiAoISRzdGF0ZS5pcyhHbG9iYWwubG9naW5TdGF0ZSkpIHtcbiAgICAgICAgICAgICAgICAgICRzdGF0ZS5nbyhHbG9iYWwubG9naW5TdGF0ZSk7XG5cbiAgICAgICAgICAgICAgICAgIC8vY2xvc2UgYW55IGRpYWxvZyB0aGF0IGlzIG9wZW5lZFxuICAgICAgICAgICAgICAgICAgJGluamVjdG9yLmdldCgnUHJEaWFsb2cnKS5jbG9zZSgpO1xuXG4gICAgICAgICAgICAgICAgICBldmVudC5wcmV2ZW50RGVmYXVsdCgpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfSk7XG5cbiAgICAgICAgICAvL2RlZmluZSBkYXRhIHRvIGVtcHR5IGJlY2F1c2UgYWxyZWFkeSBzaG93IFByVG9hc3QgdG9rZW4gbWVzc2FnZVxuICAgICAgICAgIGlmICh0b2tlbkVycm9yKSB7XG4gICAgICAgICAgICByZWplY3Rpb24uZGF0YSA9IHt9O1xuICAgICAgICAgIH1cblxuICAgICAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24ocmVqZWN0aW9uLmhlYWRlcnMpKSB7XG4gICAgICAgICAgICAvLyBtYW55IHNlcnZlcnMgZXJyb3JzIChidXNpbmVzcykgYXJlIGludGVyY2VwdCBoZXJlIGJ1dCBnZW5lcmF0ZWQgYSBuZXcgcmVmcmVzaCB0b2tlblxuICAgICAgICAgICAgLy8gYW5kIG5lZWQgdXBkYXRlIGN1cnJlbnQgdG9rZW5cbiAgICAgICAgICAgIHZhciB0b2tlbiA9IHJlamVjdGlvbi5oZWFkZXJzKCdBdXRob3JpemF0aW9uJyk7XG5cbiAgICAgICAgICAgIGlmICh0b2tlbikge1xuICAgICAgICAgICAgICAkaW5qZWN0b3IuZ2V0KCdBdXRoJykuc2V0VG9rZW4odG9rZW4uc3BsaXQoJyAnKVsxXSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgcmV0dXJuICRxLnJlamVjdChyZWplY3Rpb24pO1xuICAgICAgICB9XG4gICAgICB9O1xuICAgIH1cblxuICAgIC8vIFNldHVwIGZvciB0aGUgJGh0dHBJbnRlcmNlcHRvclxuICAgICRwcm92aWRlLmZhY3RvcnkoJ3JlZGlyZWN0V2hlblNlcnZlckxvZ2dlZE91dCcsIHJlZGlyZWN0V2hlblNlcnZlckxvZ2dlZE91dCk7XG5cbiAgICAvLyBQdXNoIHRoZSBuZXcgZmFjdG9yeSBvbnRvIHRoZSAkaHR0cCBpbnRlcmNlcHRvciBhcnJheVxuICAgICRodHRwUHJvdmlkZXIuaW50ZXJjZXB0b3JzLnB1c2goJ3JlZGlyZWN0V2hlblNlcnZlckxvZ2dlZE91dCcpO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbmZpZyh2YWxpZGF0aW9uSW50ZXJjZXB0b3IpO1xuXG4gIGZ1bmN0aW9uIHZhbGlkYXRpb25JbnRlcmNlcHRvcigkaHR0cFByb3ZpZGVyLCAkcHJvdmlkZSkge1xuICAgIC8qKlxuICAgICAqIEVzdGUgaW50ZXJjZXB0b3Igw6kgcmVzcG9uc8OhdmVsIHBvciBtb3N0cmFyIGFzXG4gICAgICogbWVuc2FnZW5zIGRlIGVycm8gcmVmZXJlbnRlIGFzIHZhbGlkYcOnw7VlcyBkbyBiYWNrLWVuZFxuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9ICRxXG4gICAgICogQHBhcmFtIHthbnl9ICRpbmplY3RvclxuICAgICAqIEByZXR1cm5zXG4gICAgICovXG4gICAgZnVuY3Rpb24gc2hvd0Vycm9yVmFsaWRhdGlvbigkcSwgJGluamVjdG9yKSB7XG4gICAgICByZXR1cm4ge1xuICAgICAgICByZXNwb25zZUVycm9yOiBmdW5jdGlvbiByZXNwb25zZUVycm9yKHJlamVjdGlvbikge1xuICAgICAgICAgIHZhciBQclRvYXN0ID0gJGluamVjdG9yLmdldCgnUHJUb2FzdCcpO1xuICAgICAgICAgIHZhciAkdHJhbnNsYXRlID0gJGluamVjdG9yLmdldCgnJHRyYW5zbGF0ZScpO1xuXG4gICAgICAgICAgaWYgKHJlamVjdGlvbi5jb25maWcuZGF0YSAmJiAhcmVqZWN0aW9uLmNvbmZpZy5kYXRhLnNraXBWYWxpZGF0aW9uKSB7XG4gICAgICAgICAgICBpZiAocmVqZWN0aW9uLmRhdGEgJiYgcmVqZWN0aW9uLmRhdGEuZXJyb3IpIHtcblxuICAgICAgICAgICAgICAvL3ZlcmlmaWNhIHNlIG9jb3JyZXUgYWxndW0gZXJybyByZWZlcmVudGUgYW8gdG9rZW5cbiAgICAgICAgICAgICAgaWYgKHJlamVjdGlvbi5kYXRhLmVycm9yLnN0YXJ0c1dpdGgoJ3Rva2VuXycpKSB7XG4gICAgICAgICAgICAgICAgUHJUb2FzdC53YXJuKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMubG9naW4ubG9nb3V0SW5hY3RpdmUnKSk7XG4gICAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgUHJUb2FzdC5lcnJvcigkdHJhbnNsYXRlLmluc3RhbnQocmVqZWN0aW9uLmRhdGEuZXJyb3IpKTtcbiAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgUHJUb2FzdC5lcnJvclZhbGlkYXRpb24ocmVqZWN0aW9uLmRhdGEpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgIH1cblxuICAgICAgICAgIHJldHVybiAkcS5yZWplY3QocmVqZWN0aW9uKTtcbiAgICAgICAgfVxuICAgICAgfTtcbiAgICB9XG5cbiAgICAvLyBEZWZpbmUgdW1hIGZhY3RvcnkgcGFyYSBvICRodHRwSW50ZXJjZXB0b3JcbiAgICAkcHJvdmlkZS5mYWN0b3J5KCdzaG93RXJyb3JWYWxpZGF0aW9uJywgc2hvd0Vycm9yVmFsaWRhdGlvbik7XG5cbiAgICAvLyBBZGljaW9uYSBhIGZhY3Rvcnkgbm8gYXJyYXkgZGUgaW50ZXJjZXB0b3JzIGRvICRodHRwXG4gICAgJGh0dHBQcm92aWRlci5pbnRlcmNlcHRvcnMucHVzaCgnc2hvd0Vycm9yVmFsaWRhdGlvbicpO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4vKmVzbGludC1lbnYgZXM2Ki9cblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbnRyb2xsZXIoJ01lbnVDb250cm9sbGVyJywgTWVudUNvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gTWVudUNvbnRyb2xsZXIoJG1kU2lkZW5hdiwgJHN0YXRlLCAkbWRDb2xvcnMpIHtcbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgLy9CbG9jbyBkZSBkZWNsYXJhY29lcyBkZSBmdW5jb2VzXG4gICAgdm0ub3BlbiA9IG9wZW47XG4gICAgdm0ub3Blbk1lbnVPclJlZGlyZWN0VG9TdGF0ZSA9IG9wZW5NZW51T3JSZWRpcmVjdFRvU3RhdGU7XG5cbiAgICBhY3RpdmF0ZSgpO1xuXG4gICAgZnVuY3Rpb24gYWN0aXZhdGUoKSB7XG4gICAgICB2YXIgbWVudVByZWZpeCA9ICd2aWV3cy5sYXlvdXQubWVudS4nO1xuXG4gICAgICAvLyBBcnJheSBjb250ZW5kbyBvcyBpdGVucyBxdWUgc8OjbyBtb3N0cmFkb3Mgbm8gbWVudSBsYXRlcmFsXG4gICAgICB2bS5pdGVuc01lbnUgPSBbeyBzdGF0ZTogJ2FwcC5wcm9qZWN0cycsIHRpdGxlOiBtZW51UHJlZml4ICsgJ2Rhc2hib2FyZCcsIGljb246ICdkYXNoYm9hcmQnLCBzdWJJdGVuczogW10gfSxcbiAgICAgIC8vIENvbG9xdWUgc2V1cyBpdGVucyBkZSBtZW51IGEgcGFydGlyIGRlc3RlIHBvbnRvXG4gICAgICB7XG4gICAgICAgIHN0YXRlOiAnIycsIHRpdGxlOiBtZW51UHJlZml4ICsgJ2FkbWluJywgaWNvbjogJ3NldHRpbmdzX2FwcGxpY2F0aW9ucycsIHByb2ZpbGVzOiBbJ2FkbWluJ10sXG4gICAgICAgIHN1Ykl0ZW5zOiBbeyBzdGF0ZTogJ2FwcC51c2VyJywgdGl0bGU6IG1lbnVQcmVmaXggKyAndXNlcicsIGljb246ICdwZW9wbGUnIH0sIHsgc3RhdGU6ICdhcHAubWFpbCcsIHRpdGxlOiBtZW51UHJlZml4ICsgJ21haWwnLCBpY29uOiAnbWFpbCcgfSwgeyBzdGF0ZTogJ2FwcC5hdWRpdCcsIHRpdGxlOiBtZW51UHJlZml4ICsgJ2F1ZGl0JywgaWNvbjogJ3N0b3JhZ2UnIH0sIHsgc3RhdGU6ICdhcHAuZGluYW1pYy1xdWVyeScsIHRpdGxlOiBtZW51UHJlZml4ICsgJ2RpbmFtaWNRdWVyeScsIGljb246ICdsb2NhdGlvbl9zZWFyY2hpbmcnIH1dXG4gICAgICB9XTtcblxuICAgICAgLyoqXG4gICAgICAgKiBPYmpldG8gcXVlIHByZWVuY2hlIG8gbmctc3R5bGUgZG8gbWVudSBsYXRlcmFsIHRyb2NhbmRvIGFzIGNvcmVzXG4gICAgICAgKi9cbiAgICAgIHZtLnNpZGVuYXZTdHlsZSA9IHtcbiAgICAgICAgdG9wOiB7XG4gICAgICAgICAgJ2JvcmRlci1ib3R0b20nOiAnMXB4IHNvbGlkICcgKyBnZXRDb2xvcigncHJpbWFyeScpLFxuICAgICAgICAgICdiYWNrZ3JvdW5kLWltYWdlJzogJy13ZWJraXQtbGluZWFyLWdyYWRpZW50KHRvcCwgJyArIGdldENvbG9yKCdwcmltYXJ5LTUwMCcpICsgJywgJyArIGdldENvbG9yKCdwcmltYXJ5LTgwMCcpICsgJyknXG4gICAgICAgIH0sXG4gICAgICAgIGNvbnRlbnQ6IHtcbiAgICAgICAgICAnYmFja2dyb3VuZC1jb2xvcic6IGdldENvbG9yKCdwcmltYXJ5LTgwMCcpXG4gICAgICAgIH0sXG4gICAgICAgIHRleHRDb2xvcjoge1xuICAgICAgICAgIGNvbG9yOiAnI0ZGRidcbiAgICAgICAgfSxcbiAgICAgICAgbGluZUJvdHRvbToge1xuICAgICAgICAgICdib3JkZXItYm90dG9tJzogJzFweCBzb2xpZCAnICsgZ2V0Q29sb3IoJ3ByaW1hcnktNDAwJylcbiAgICAgICAgfVxuICAgICAgfTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBvcGVuKCkge1xuICAgICAgJG1kU2lkZW5hdignbGVmdCcpLnRvZ2dsZSgpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIE3DqXRvZG8gcXVlIGV4aWJlIG8gc3ViIG1lbnUgZG9zIGl0ZW5zIGRvIG1lbnUgbGF0ZXJhbCBjYXNvIHRlbmhhIHN1YiBpdGVuc1xuICAgICAqIGNhc28gY29udHLDoXJpbyByZWRpcmVjaW9uYSBwYXJhIG8gc3RhdGUgcGFzc2FkbyBjb21vIHBhcsOibWV0cm9cbiAgICAgKi9cbiAgICBmdW5jdGlvbiBvcGVuTWVudU9yUmVkaXJlY3RUb1N0YXRlKCRtZE1lbnUsIGV2LCBpdGVtKSB7XG4gICAgICBpZiAoYW5ndWxhci5pc0RlZmluZWQoaXRlbS5zdWJJdGVucykgJiYgaXRlbS5zdWJJdGVucy5sZW5ndGggPiAwKSB7XG4gICAgICAgICRtZE1lbnUub3Blbihldik7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICAkc3RhdGUuZ28oaXRlbS5zdGF0ZSk7XG4gICAgICAgICRtZFNpZGVuYXYoJ2xlZnQnKS5jbG9zZSgpO1xuICAgICAgfVxuICAgIH1cblxuICAgIGZ1bmN0aW9uIGdldENvbG9yKGNvbG9yUGFsZXR0ZXMpIHtcbiAgICAgIHJldHVybiAkbWRDb2xvcnMuZ2V0VGhlbWVDb2xvcihjb2xvclBhbGV0dGVzKTtcbiAgICB9XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb250cm9sbGVyKCdNYWlsc0NvbnRyb2xsZXInLCBNYWlsc0NvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gTWFpbHNDb250cm9sbGVyKE1haWxzU2VydmljZSwgVXNlcnNTZXJ2aWNlLCBQckRpYWxvZywgUHJUb2FzdCwgLy8gTk9TT05BUlxuICAkcSwgbG9kYXNoLCAkdHJhbnNsYXRlLCBHbG9iYWwpIHtcblxuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICB2bS5maWx0ZXJTZWxlY3RlZCA9IGZhbHNlO1xuICAgIHZtLm9wdGlvbnMgPSB7XG4gICAgICBza2luOiAna2FtYScsXG4gICAgICBsYW5ndWFnZTogJ3B0LWJyJyxcbiAgICAgIGFsbG93ZWRDb250ZW50OiB0cnVlLFxuICAgICAgZW50aXRpZXM6IHRydWUsXG4gICAgICBoZWlnaHQ6IDMwMCxcbiAgICAgIGV4dHJhUGx1Z2luczogJ2RpYWxvZyxmaW5kLGNvbG9yZGlhbG9nLHByZXZpZXcsZm9ybXMsaWZyYW1lLGZsYXNoJ1xuICAgIH07XG5cbiAgICB2bS5sb2FkVXNlcnMgPSBsb2FkVXNlcnM7XG4gICAgdm0ub3BlblVzZXJEaWFsb2cgPSBvcGVuVXNlckRpYWxvZztcbiAgICB2bS5hZGRVc2VyTWFpbCA9IGFkZFVzZXJNYWlsO1xuICAgIHZtLmNsZWFuRm9ybSA9IGNsZWFuRm9ybTtcbiAgICB2bS5zZW5kID0gc2VuZDtcblxuICAgIGFjdGl2YXRlKCk7XG5cbiAgICBmdW5jdGlvbiBhY3RpdmF0ZSgpIHtcbiAgICAgIHZtLmNsZWFuRm9ybSgpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWxpemEgYSBidXNjYSBwZWxvIHVzdcOhcmlvIHJlbW90YW1lbnRlXG4gICAgICpcbiAgICAgKiBAcGFyYW1zIHtzdHJpbmd9IC0gUmVjZWJlIG8gdmFsb3IgcGFyYSBzZXIgcGVzcXVpc2Fkb1xuICAgICAqIEByZXR1cm4ge3Byb21pc3NlfSAtIFJldG9ybmEgdW1hIHByb21pc3NlIHF1ZSBvIGNvbXBvbmV0ZSByZXNvbHZlXG4gICAgICovXG4gICAgZnVuY3Rpb24gbG9hZFVzZXJzKGNyaXRlcmlhKSB7XG4gICAgICB2YXIgZGVmZXJyZWQgPSAkcS5kZWZlcigpO1xuXG4gICAgICBVc2Vyc1NlcnZpY2UucXVlcnkoe1xuICAgICAgICBuYW1lT3JFbWFpbDogY3JpdGVyaWEsXG4gICAgICAgIG5vdFVzZXJzOiBsb2Rhc2gubWFwKHZtLm1haWwudXNlcnMsIGxvZGFzaC5wcm9wZXJ0eSgnaWQnKSkudG9TdHJpbmcoKSxcbiAgICAgICAgbGltaXQ6IDVcbiAgICAgIH0pLnRoZW4oZnVuY3Rpb24gKGRhdGEpIHtcblxuICAgICAgICAvLyB2ZXJpZmljYSBzZSBuYSBsaXN0YSBkZSB1c3VhcmlvcyBqw6EgZXhpc3RlIG8gdXN1w6FyaW8gY29tIG8gZW1haWwgcGVzcXVpc2Fkb1xuICAgICAgICBkYXRhID0gbG9kYXNoLmZpbHRlcihkYXRhLCBmdW5jdGlvbiAodXNlcikge1xuICAgICAgICAgIHJldHVybiAhbG9kYXNoLmZpbmQodm0ubWFpbC51c2VycywgeyBlbWFpbDogdXNlci5lbWFpbCB9KTtcbiAgICAgICAgfSk7XG5cbiAgICAgICAgZGVmZXJyZWQucmVzb2x2ZShkYXRhKTtcbiAgICAgIH0pO1xuXG4gICAgICByZXR1cm4gZGVmZXJyZWQucHJvbWlzZTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBBYnJlIG8gZGlhbG9nIHBhcmEgcGVzcXVpc2EgZGUgdXN1w6FyaW9zXG4gICAgICovXG4gICAgZnVuY3Rpb24gb3BlblVzZXJEaWFsb2coKSB7XG4gICAgICB2YXIgY29uZmlnID0ge1xuICAgICAgICBsb2NhbHM6IHtcbiAgICAgICAgICBvbkluaXQ6IHRydWUsXG4gICAgICAgICAgdXNlckRpYWxvZ0lucHV0OiB7XG4gICAgICAgICAgICB0cmFuc2ZlclVzZXJGbjogdm0uYWRkVXNlck1haWxcbiAgICAgICAgICB9XG4gICAgICAgIH0sXG4gICAgICAgIGNvbnRyb2xsZXI6ICdVc2Vyc0RpYWxvZ0NvbnRyb2xsZXInLFxuICAgICAgICBjb250cm9sbGVyQXM6ICdjdHJsJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy91c2Vycy9kaWFsb2cvdXNlcnMtZGlhbG9nLmh0bWwnLFxuICAgICAgICBoYXNCYWNrZHJvcDogdHJ1ZVxuICAgICAgfTtcblxuICAgICAgUHJEaWFsb2cuY3VzdG9tKGNvbmZpZyk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQWRpY2lvbmEgbyB1c3XDoXJpbyBzZWxlY2lvbmFkbyBuYSBsaXN0YSBwYXJhIHF1ZSBzZWphIGVudmlhZG8gbyBlbWFpbFxuICAgICAqL1xuICAgIGZ1bmN0aW9uIGFkZFVzZXJNYWlsKHVzZXIpIHtcbiAgICAgIHZhciB1c2VycyA9IGxvZGFzaC5maW5kKHZtLm1haWwudXNlcnMsIHsgZW1haWw6IHVzZXIuZW1haWwgfSk7XG5cbiAgICAgIGlmICh2bS5tYWlsLnVzZXJzLmxlbmd0aCA+IDAgJiYgYW5ndWxhci5pc0RlZmluZWQodXNlcnMpKSB7XG4gICAgICAgIFByVG9hc3Qud2FybigkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnVzZXIudXNlckV4aXN0cycpKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHZtLm1haWwudXNlcnMucHVzaCh7IG5hbWU6IHVzZXIubmFtZSwgZW1haWw6IHVzZXIuZW1haWwgfSk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhbGl6YSBvIGVudmlvIGRvIGVtYWlsIHBhcmEgYSBsaXN0YSBkZSB1c3XDoXJpb3Mgc2VsZWNpb25hZG9zXG4gICAgICovXG4gICAgZnVuY3Rpb24gc2VuZCgpIHtcblxuICAgICAgdm0ubWFpbC4kc2F2ZSgpLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgIGlmIChyZXNwb25zZS5sZW5ndGggPiAwKSB7XG4gICAgICAgICAgdmFyIG1zZyA9ICR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMubWFpbC5tYWlsRXJyb3JzJyk7XG5cbiAgICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IHJlc3BvbnNlLmxlbmd0aDsgaSsrKSB7XG4gICAgICAgICAgICBtc2cgKz0gcmVzcG9uc2UgKyAnXFxuJztcbiAgICAgICAgICB9XG4gICAgICAgICAgUHJUb2FzdC5lcnJvcihtc2cpO1xuICAgICAgICAgIHZtLmNsZWFuRm9ybSgpO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIFByVG9hc3Quc3VjY2VzcygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLm1haWwuc2VuZE1haWxTdWNjZXNzJykpO1xuICAgICAgICAgIHZtLmNsZWFuRm9ybSgpO1xuICAgICAgICB9XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBMaW1wYSBvIGZvcm11bMOhcmlvIGRlIGVtYWlsXG4gICAgICovXG4gICAgZnVuY3Rpb24gY2xlYW5Gb3JtKCkge1xuICAgICAgdm0ubWFpbCA9IG5ldyBNYWlsc1NlcnZpY2UoKTtcbiAgICAgIHZtLm1haWwudXNlcnMgPSBbXTtcbiAgICB9XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqXG4gICAqIEFycXVpdm8gZGUgY29uZmlndXJhw6fDo28gY29tIGFzIHJvdGFzIGVzcGVjw61maWNhcyBkbyByZWN1cnNvIGVtIHF1ZXN0w6NvXG4gICAqXG4gICAqIEBwYXJhbSB7YW55fSAkc3RhdGVQcm92aWRlclxuICAgKiBAcGFyYW0ge2FueX0gR2xvYmFsXG4gICAqL1xuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvdXRlcygkc3RhdGVQcm92aWRlciwgR2xvYmFsKSB7XG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ2FwcC5tYWlsJywge1xuICAgICAgdXJsOiAnL2VtYWlsJyxcbiAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvbWFpbC9tYWlscy1zZW5kLmh0bWwnLFxuICAgICAgY29udHJvbGxlcjogJ01haWxzQ29udHJvbGxlciBhcyBtYWlsc0N0cmwnLFxuICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IHRydWUsIG5lZWRQcm9maWxlOiBbJ2FkbWluJ10gfVxuICAgIH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZhY3RvcnkoJ01haWxzU2VydmljZScsIE1haWxzU2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBNYWlsc1NlcnZpY2Uoc2VydmljZUZhY3RvcnkpIHtcbiAgICByZXR1cm4gc2VydmljZUZhY3RvcnkoJ21haWxzJywge30pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29udHJvbGxlcignUHJvamVjdHNDb250cm9sbGVyJywgUHJvamVjdHNDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIFByb2plY3RzQ29udHJvbGxlcihHbG9iYWwsICRjb250cm9sbGVyLCBQcm9qZWN0c1NlcnZpY2UsIEF1dGgsIFJvbGVzU2VydmljZSwgVXNlcnNTZXJ2aWNlKSB7XG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIC8vQXR0cmlidXRlcyBCbG9ja1xuXG4gICAgLy9GdW5jdGlvbnMgQmxvY2tcbiAgICB2bS5vbkFjdGl2YXRlID0gb25BY3RpdmF0ZTtcbiAgICB2bS5hcHBseUZpbHRlcnMgPSBhcHBseUZpbHRlcnM7XG4gICAgdm0uYmVmb3JlU2F2ZSA9IGJlZm9yZVNhdmU7XG4gICAgdm0uc2VhcmNoVXNlciA9IHNlYXJjaFVzZXI7XG4gICAgdm0uYWRkVXNlciA9IGFkZFVzZXI7XG4gICAgdm0ucmVtb3ZlVXNlciA9IHJlbW92ZVVzZXI7XG5cbiAgICB2bS5yb2xlcyA9IHt9O1xuXG4gICAgZnVuY3Rpb24gb25BY3RpdmF0ZSgpIHtcbiAgICAgIHZtLnF1ZXJ5RmlsdGVycyA9IHsgdXNlcl9pZDogQXV0aC5jdXJyZW50VXNlci5pZCB9O1xuICAgICAgUm9sZXNTZXJ2aWNlLnF1ZXJ5KCkudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgdm0ucm9sZXMgPSByZXNwb25zZTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGFwcGx5RmlsdGVycyhkZWZhdWx0UXVlcnlGaWx0ZXJzKSB7XG4gICAgICByZXR1cm4gYW5ndWxhci5leHRlbmQoZGVmYXVsdFF1ZXJ5RmlsdGVycywgdm0ucXVlcnlsdGVycyk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gYmVmb3JlU2F2ZSgpIHtcbiAgICAgIHZtLnJlc291cmNlLm93bmVyID0gQXV0aC5jdXJyZW50VXNlci5pZDtcbiAgICAgIHZtLnJlc291cmNlLnVzZXJfaWQgPSBBdXRoLmN1cnJlbnRVc2VyLmlkO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIHNlYXJjaFVzZXIodGV4dCkge1xuICAgICAgcmV0dXJuIFVzZXJzU2VydmljZS5xdWVyeSh7IG5hbWU6IHZtLnVzZXJOYW1lIH0pO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGFkZFVzZXIodXNlcikge1xuICAgICAgaWYgKHVzZXIpIHtcbiAgICAgICAgdm0ucmVzb3VyY2UudXNlcnMucHVzaCh1c2VyKTtcbiAgICAgICAgdm0udXNlck5hbWUgPSAnJztcbiAgICAgIH1cbiAgICB9XG5cbiAgICBmdW5jdGlvbiByZW1vdmVVc2VyKGluZGV4KSB7XG4gICAgICB2bS5yZXNvdXJjZS51c2Vycy5zcGxpY2UoaW5kZXgsIDEpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGFwcGx5RmlsdGVycyhkZWZhdWx0UXVlcnlGaWx0ZXJzKSB7XG4gICAgICByZXR1cm4gYW5ndWxhci5leHRlbmQoZGVmYXVsdFF1ZXJ5RmlsdGVycywgdm0ucXVlcnlGaWx0ZXJzKTtcbiAgICB9XG5cbiAgICAvLyBpbnN0YW50aWF0ZSBiYXNlIGNvbnRyb2xsZXJcbiAgICAkY29udHJvbGxlcignQ1JVRENvbnRyb2xsZXInLCB7IHZtOiB2bSwgbW9kZWxTZXJ2aWNlOiBQcm9qZWN0c1NlcnZpY2UsIG9wdGlvbnM6IHt9IH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKlxuICAgKiBBcnF1aXZvIGRlIGNvbmZpZ3VyYcOnw6NvIGNvbSBhcyByb3RhcyBlc3BlY8OtZmljYXMgZG8gcmVjdXJzbyBwcm9qZWN0XG4gICAqXG4gICAqIEBwYXJhbSB7YW55fSAkc3RhdGVQcm92aWRlclxuICAgKiBAcGFyYW0ge2FueX0gR2xvYmFsXG4gICAqL1xuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvdXRlcygkc3RhdGVQcm92aWRlciwgR2xvYmFsKSB7XG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ2FwcC5wcm9qZWN0cycsIHtcbiAgICAgIHVybDogJy9wcm9qZWN0cycsXG4gICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL3Byb2plY3RzL3Byb2plY3RzLmh0bWwnLFxuICAgICAgY29udHJvbGxlcjogJ1Byb2plY3RzQ29udHJvbGxlciBhcyBwcm9qZWN0c0N0cmwnLFxuICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IHRydWUgfVxuICAgIH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZhY3RvcnkoJ1Byb2plY3RzU2VydmljZScsIFByb2plY3RzU2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiBQcm9qZWN0c1NlcnZpY2Uoc2VydmljZUZhY3RvcnkpIHtcbiAgICByZXR1cm4gc2VydmljZUZhY3RvcnkoJ3Byb2plY3RzJywge1xuICAgICAgYWN0aW9uczoge30sXG4gICAgICBpbnN0YW5jZToge31cbiAgICB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZpbHRlcigncm9sZXNTdHInLCByb2xlc1N0cik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb2xlc1N0cihsb2Rhc2gpIHtcbiAgICAvKipcbiAgICAgKiBAcGFyYW0ge2FycmF5fSByb2xlcyBsaXN0YSBkZSBwZXJmaXNcbiAgICAgKiBAcmV0dXJuIHtzdHJpbmd9IHBlcmZpcyBzZXBhcmFkb3MgcG9yICcsICcgIFxuICAgICAqL1xuICAgIHJldHVybiBmdW5jdGlvbiAocm9sZXMpIHtcbiAgICAgIHJldHVybiBsb2Rhc2gubWFwKHJvbGVzLCAnc2x1ZycpLmpvaW4oJywgJyk7XG4gICAgfTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5mYWN0b3J5KCdSb2xlc1NlcnZpY2UnLCBSb2xlc1NlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gUm9sZXNTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCdyb2xlcycpO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZhY3RvcnkoJ1N1cHBvcnRTZXJ2aWNlJywgU3VwcG9ydFNlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gU3VwcG9ydFNlcnZpY2Uoc2VydmljZUZhY3RvcnkpIHtcbiAgICByZXR1cm4gc2VydmljZUZhY3RvcnkoJ3N1cHBvcnQnLCB7XG4gICAgICBhY3Rpb25zOiB7XG4gICAgICAgIC8qKlxuICAgICAgICAgKiBQZWdhIGFzIHRyYWR1w6fDtWVzIHF1ZSBlc3TDo28gbm8gc2Vydmlkb3JcbiAgICAgICAgICpcbiAgICAgICAgICogQHJldHVybnMge3Byb21pc2V9IFVtYSBwcm9taXNlIGNvbSBvIHJlc3VsdGFkbyBkbyBjaGFtYWRhIG5vIGJhY2tlbmRcbiAgICAgICAgICovXG4gICAgICAgIGxhbmdzOiB7XG4gICAgICAgICAgbWV0aG9kOiAnR0VUJyxcbiAgICAgICAgICB1cmw6ICdsYW5ncycsXG4gICAgICAgICAgd3JhcDogZmFsc2UsXG4gICAgICAgICAgY2FjaGU6IHRydWVcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29udHJvbGxlcignUHJvZmlsZUNvbnRyb2xsZXInLCBQcm9maWxlQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBQcm9maWxlQ29udHJvbGxlcihVc2Vyc1NlcnZpY2UsIEF1dGgsIFByVG9hc3QsICR0cmFuc2xhdGUpIHtcbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0udXBkYXRlID0gdXBkYXRlO1xuXG4gICAgYWN0aXZhdGUoKTtcblxuICAgIGZ1bmN0aW9uIGFjdGl2YXRlKCkge1xuICAgICAgdm0udXNlciA9IGFuZ3VsYXIuY29weShBdXRoLmN1cnJlbnRVc2VyKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiB1cGRhdGUoKSB7XG4gICAgICBVc2Vyc1NlcnZpY2UudXBkYXRlUHJvZmlsZSh2bS51c2VyKS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICAvL2F0dWFsaXphIG8gdXN1w6FyaW8gY29ycmVudGUgY29tIGFzIG5vdmFzIGluZm9ybWHDp8O1ZXNcbiAgICAgICAgQXV0aC51cGRhdGVDdXJyZW50VXNlcihyZXNwb25zZSk7XG4gICAgICAgIFByVG9hc3Quc3VjY2VzcygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnNhdmVTdWNjZXNzJykpO1xuICAgICAgfSk7XG4gICAgfVxuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29udHJvbGxlcignVXNlcnNDb250cm9sbGVyJywgVXNlcnNDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIFVzZXJzQ29udHJvbGxlcigkY29udHJvbGxlciwgVXNlcnNTZXJ2aWNlKSB7XG5cbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0ub25BY3RpdmF0ZSA9IG9uQWN0aXZhdGU7XG4gICAgLy8gaW5zdGFudGlhdGUgYmFzZSBjb250cm9sbGVyXG4gICAgJGNvbnRyb2xsZXIoJ0NSVURDb250cm9sbGVyJywgeyB2bTogdm0sIG1vZGVsU2VydmljZTogVXNlcnNTZXJ2aWNlLCBvcHRpb25zOiB7fSB9KTtcblxuICAgIGZ1bmN0aW9uIG9uQWN0aXZhdGUoKSB7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMgPSB7fTtcbiAgICB9XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqXG4gICAqIEFycXVpdm8gZGUgY29uZmlndXJhw6fDo28gY29tIGFzIHJvdGFzIGVzcGVjw61maWNhcyBkbyByZWN1cnNvIHVzZXJcbiAgICpcbiAgICogQHBhcmFtIHthbnl9ICRzdGF0ZVByb3ZpZGVyXG4gICAqIEBwYXJhbSB7YW55fSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnYXBwLnVzZXInLCB7XG4gICAgICB1cmw6ICcvdXN1YXJpbycsXG4gICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL3VzZXJzL3VzZXJzLmh0bWwnLFxuICAgICAgY29udHJvbGxlcjogJ1VzZXJzQ29udHJvbGxlciBhcyB1c2Vyc0N0cmwnLFxuICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IHRydWUsIG5lZWRQcm9maWxlOiBbJ2FkbWluJ10gfVxuICAgIH0pLnN0YXRlKCdhcHAudXNlci1wcm9maWxlJywge1xuICAgICAgdXJsOiAnL3VzdWFyaW8vcGVyZmlsJyxcbiAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvdXNlcnMvcHJvZmlsZS5odG1sJyxcbiAgICAgIGNvbnRyb2xsZXI6ICdQcm9maWxlQ29udHJvbGxlciBhcyBwcm9maWxlQ3RybCcsXG4gICAgICBkYXRhOiB7IG5lZWRBdXRoZW50aWNhdGlvbjogdHJ1ZSB9XG4gICAgfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmFjdG9yeSgnVXNlcnNTZXJ2aWNlJywgVXNlcnNTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIFVzZXJzU2VydmljZShsb2Rhc2gsIEdsb2JhbCwgc2VydmljZUZhY3RvcnkpIHtcbiAgICByZXR1cm4gc2VydmljZUZhY3RvcnkoJ3VzZXJzJywge1xuICAgICAgLy9xdWFuZG8gaW5zdGFuY2lhIHVtIHVzdcOhcmlvIHNlbSBwYXNzYXIgcGFyYW1ldHJvLFxuICAgICAgLy9vIG1lc21vIHZhaSB0ZXIgb3MgdmFsb3JlcyBkZWZhdWx0cyBhYmFpeG9cbiAgICAgIGRlZmF1bHRzOiB7XG4gICAgICAgIHJvbGVzOiBbXVxuICAgICAgfSxcblxuICAgICAgYWN0aW9uczoge1xuICAgICAgICAvKipcbiAgICAgICAgICogU2VydmnDp28gcXVlIGF0dWFsaXphIG9zIGRhZG9zIGRvIHBlcmZpbCBkbyB1c3XDoXJpbyBsb2dhZG9cbiAgICAgICAgICpcbiAgICAgICAgICogQHBhcmFtIHtvYmplY3R9IGF0dHJpYnV0ZXNcbiAgICAgICAgICogQHJldHVybnMge3Byb21pc2V9IFVtYSBwcm9taXNlIGNvbSBvIHJlc3VsdGFkbyBkbyBjaGFtYWRhIG5vIGJhY2tlbmRcbiAgICAgICAgICovXG4gICAgICAgIHVwZGF0ZVByb2ZpbGU6IHtcbiAgICAgICAgICBtZXRob2Q6ICdQVVQnLFxuICAgICAgICAgIHVybDogR2xvYmFsLmFwaVBhdGggKyAnL3Byb2ZpbGUnLFxuICAgICAgICAgIG92ZXJyaWRlOiB0cnVlLFxuICAgICAgICAgIHdyYXA6IGZhbHNlXG4gICAgICAgIH1cbiAgICAgIH0sXG5cbiAgICAgIGluc3RhbmNlOiB7XG4gICAgICAgIC8qKlxuICAgICAgICAgKiBWZXJpZmljYSBzZSBvIHVzdcOhcmlvIHRlbSBvcyBwZXJmaXMgaW5mb3JtYWRvcy5cbiAgICAgICAgICpcbiAgICAgICAgICogQHBhcmFtIHthbnl9IHJvbGVzIHBlcmZpcyBhIHNlcmVtIHZlcmlmaWNhZG9zXG4gICAgICAgICAqIEBwYXJhbSB7Ym9vbGVhbn0gYWxsIGZsYWcgcGFyYSBpbmRpY2FyIHNlIHZhaSBjaGVnYXIgdG9kb3Mgb3MgcGVyZmlzIG91IHNvbWVudGUgdW0gZGVsZXNcbiAgICAgICAgICogQHJldHVybnMge2Jvb2xlYW59XG4gICAgICAgICAqL1xuICAgICAgICBoYXNQcm9maWxlOiBmdW5jdGlvbiBoYXNQcm9maWxlKHJvbGVzLCBhbGwpIHtcbiAgICAgICAgICByb2xlcyA9IGFuZ3VsYXIuaXNBcnJheShyb2xlcykgPyByb2xlcyA6IFtyb2xlc107XG5cbiAgICAgICAgICB2YXIgdXNlclJvbGVzID0gbG9kYXNoLm1hcCh0aGlzLnJvbGVzLCAnc2x1ZycpO1xuXG4gICAgICAgICAgaWYgKGFsbCkge1xuICAgICAgICAgICAgcmV0dXJuIGxvZGFzaC5pbnRlcnNlY3Rpb24odXNlclJvbGVzLCByb2xlcykubGVuZ3RoID09PSByb2xlcy5sZW5ndGg7XG4gICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIC8vcmV0dXJuIHRoZSBsZW5ndGggYmVjYXVzZSAwIGlzIGZhbHNlIGluIGpzXG4gICAgICAgICAgICByZXR1cm4gbG9kYXNoLmludGVyc2VjdGlvbih1c2VyUm9sZXMsIHJvbGVzKS5sZW5ndGg7XG4gICAgICAgICAgfVxuICAgICAgICB9LFxuXG4gICAgICAgIC8qKlxuICAgICAgICAgKiBWZXJpZmljYSBzZSBvIHVzdcOhcmlvIHRlbSBvIHBlcmZpbCBhZG1pbi5cbiAgICAgICAgICpcbiAgICAgICAgICogQHJldHVybnMge2Jvb2xlYW59XG4gICAgICAgICAqL1xuICAgICAgICBpc0FkbWluOiBmdW5jdGlvbiBpc0FkbWluKCkge1xuICAgICAgICAgIHJldHVybiB0aGlzLmhhc1Byb2ZpbGUoJ2FkbWluJyk7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29tcG9uZW50KCdib3gnLCB7XG4gICAgcmVwbGFjZTogdHJ1ZSxcbiAgICB0ZW1wbGF0ZVVybDogWydHbG9iYWwnLCBmdW5jdGlvbiAoR2xvYmFsKSB7XG4gICAgICByZXR1cm4gR2xvYmFsLmNsaWVudFBhdGggKyAnL3dpZGdldHMvYm94Lmh0bWwnO1xuICAgIH1dLFxuICAgIHRyYW5zY2x1ZGU6IHtcbiAgICAgIHRvb2xiYXJCdXR0b25zOiAnP2JveFRvb2xiYXJCdXR0b25zJyxcbiAgICAgIGZvb3RlckJ1dHRvbnM6ICc/Ym94Rm9vdGVyQnV0dG9ucydcbiAgICB9LFxuICAgIGJpbmRpbmdzOiB7XG4gICAgICBib3hUaXRsZTogJ0AnLFxuICAgICAgdG9vbGJhckNsYXNzOiAnQCcsXG4gICAgICB0b29sYmFyQmdDb2xvcjogJ0AnXG4gICAgfSxcbiAgICBjb250cm9sbGVyOiBbJyR0cmFuc2NsdWRlJywgZnVuY3Rpb24gKCR0cmFuc2NsdWRlKSB7XG4gICAgICB2YXIgY3RybCA9IHRoaXM7XG5cbiAgICAgIGN0cmwudHJhbnNjbHVkZSA9ICR0cmFuc2NsdWRlO1xuXG4gICAgICBjdHJsLiRvbkluaXQgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgIGlmIChhbmd1bGFyLmlzVW5kZWZpbmVkKGN0cmwudG9vbGJhckJnQ29sb3IpKSBjdHJsLnRvb2xiYXJCZ0NvbG9yID0gJ2RlZmF1bHQtcHJpbWFyeSc7XG4gICAgICB9O1xuICAgIH1dXG4gIH0pO1xufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29tcG9uZW50KCdjb250ZW50Qm9keScsIHtcbiAgICByZXBsYWNlOiB0cnVlLFxuICAgIHRyYW5zY2x1ZGU6IHRydWUsXG4gICAgdGVtcGxhdGVVcmw6IFsnR2xvYmFsJywgZnVuY3Rpb24gKEdsb2JhbCkge1xuICAgICAgcmV0dXJuIEdsb2JhbC5jbGllbnRQYXRoICsgJy93aWRnZXRzL2NvbnRlbnQtYm9keS5odG1sJztcbiAgICB9XSxcbiAgICBiaW5kaW5nczoge1xuICAgICAgbGF5b3V0QWxpZ246ICdAJ1xuICAgIH0sXG4gICAgY29udHJvbGxlcjogW2Z1bmN0aW9uICgpIHtcbiAgICAgIHZhciBjdHJsID0gdGhpcztcblxuICAgICAgY3RybC4kb25Jbml0ID0gZnVuY3Rpb24gKCkge1xuICAgICAgICAvLyBNYWtlIGEgY29weSBvZiB0aGUgaW5pdGlhbCB2YWx1ZSB0byBiZSBhYmxlIHRvIHJlc2V0IGl0IGxhdGVyXG4gICAgICAgIGN0cmwubGF5b3V0QWxpZ24gPSBhbmd1bGFyLmlzRGVmaW5lZChjdHJsLmxheW91dEFsaWduKSA/IGN0cmwubGF5b3V0QWxpZ24gOiAnY2VudGVyIHN0YXJ0JztcbiAgICAgIH07XG4gICAgfV1cbiAgfSk7XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb21wb25lbnQoJ2NvbnRlbnRIZWFkZXInLCB7XG4gICAgdGVtcGxhdGVVcmw6IFsnR2xvYmFsJywgZnVuY3Rpb24gKEdsb2JhbCkge1xuICAgICAgcmV0dXJuIEdsb2JhbC5jbGllbnRQYXRoICsgJy93aWRnZXRzL2NvbnRlbnQtaGVhZGVyLmh0bWwnO1xuICAgIH1dLFxuICAgIHJlcGxhY2U6IHRydWUsXG4gICAgYmluZGluZ3M6IHtcbiAgICAgIHRpdGxlOiAnQCcsXG4gICAgICBkZXNjcmlwdGlvbjogJ0AnXG4gICAgfVxuICB9KTtcbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5maWx0ZXIoJ2F1ZGl0RGV0YWlsVGl0bGUnLCBhdWRpdERldGFpbFRpdGxlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIGF1ZGl0RGV0YWlsVGl0bGUoJHRyYW5zbGF0ZSkge1xuICAgIHJldHVybiBmdW5jdGlvbiAoYXVkaXREZXRhaWwsIHN0YXR1cykge1xuICAgICAgaWYgKGF1ZGl0RGV0YWlsLnR5cGUgPT09ICd1cGRhdGVkJykge1xuICAgICAgICBpZiAoc3RhdHVzID09PSAnYmVmb3JlJykge1xuICAgICAgICAgIHJldHVybiAkdHJhbnNsYXRlLmluc3RhbnQoJ2RpYWxvZy5hdWRpdC51cGRhdGVkQmVmb3JlJyk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgcmV0dXJuICR0cmFuc2xhdGUuaW5zdGFudCgnZGlhbG9nLmF1ZGl0LnVwZGF0ZWRBZnRlcicpO1xuICAgICAgICB9XG4gICAgICB9IGVsc2Uge1xuICAgICAgICByZXR1cm4gJHRyYW5zbGF0ZS5pbnN0YW50KCdkaWFsb2cuYXVkaXQuJyArIGF1ZGl0RGV0YWlsLnR5cGUpO1xuICAgICAgfVxuICAgIH07XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5maWx0ZXIoJ2F1ZGl0TW9kZWwnLCBhdWRpdE1vZGVsKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIGF1ZGl0TW9kZWwoJHRyYW5zbGF0ZSkge1xuICAgIHJldHVybiBmdW5jdGlvbiAobW9kZWxJZCkge1xuICAgICAgbW9kZWxJZCA9IG1vZGVsSWQucmVwbGFjZSgnQXBwXFxcXCcsICcnKTtcbiAgICAgIHZhciBtb2RlbCA9ICR0cmFuc2xhdGUuaW5zdGFudCgnbW9kZWxzLicgKyBtb2RlbElkLnRvTG93ZXJDYXNlKCkpO1xuXG4gICAgICByZXR1cm4gbW9kZWwgPyBtb2RlbCA6IG1vZGVsSWQ7XG4gICAgfTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZpbHRlcignYXVkaXRUeXBlJywgYXVkaXRUeXBlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIGF1ZGl0VHlwZShsb2Rhc2gsIEF1ZGl0U2VydmljZSkge1xuICAgIHJldHVybiBmdW5jdGlvbiAodHlwZUlkKSB7XG4gICAgICB2YXIgdHlwZSA9IGxvZGFzaC5maW5kKEF1ZGl0U2VydmljZS5saXN0VHlwZXMoKSwgeyBpZDogdHlwZUlkIH0pO1xuXG4gICAgICByZXR1cm4gdHlwZSA/IHR5cGUubGFiZWwgOiB0eXBlO1xuICAgIH07XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5maWx0ZXIoJ2F1ZGl0VmFsdWUnLCBhdWRpdFZhbHVlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIGF1ZGl0VmFsdWUoJGZpbHRlciwgbG9kYXNoKSB7XG4gICAgcmV0dXJuIGZ1bmN0aW9uICh2YWx1ZSwga2V5KSB7XG4gICAgICBpZiAoYW5ndWxhci5pc0RhdGUodmFsdWUpIHx8IGxvZGFzaC5lbmRzV2l0aChrZXksICdfYXQnKSB8fCBsb2Rhc2guZW5kc1dpdGgoa2V5LCAnX3RvJykpIHtcbiAgICAgICAgcmV0dXJuICRmaWx0ZXIoJ3ByRGF0ZXRpbWUnKSh2YWx1ZSk7XG4gICAgICB9XG5cbiAgICAgIGlmICh0eXBlb2YgdmFsdWUgPT09ICdib29sZWFuJykge1xuICAgICAgICByZXR1cm4gJGZpbHRlcigndHJhbnNsYXRlJykodmFsdWUgPyAnZ2xvYmFsLnllcycgOiAnZ2xvYmFsLm5vJyk7XG4gICAgICB9XG5cbiAgICAgIC8vY2hlY2sgaXMgZmxvYXRcbiAgICAgIGlmIChOdW1iZXIodmFsdWUpID09PSB2YWx1ZSAmJiB2YWx1ZSAlIDEgIT09IDApIHtcbiAgICAgICAgcmV0dXJuICRmaWx0ZXIoJ3JlYWwnKSh2YWx1ZSk7XG4gICAgICB9XG5cbiAgICAgIHJldHVybiB2YWx1ZTtcbiAgICB9O1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4vKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCwgbm8tdW5kZWY6IDAqL1xuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25zdGFudCgncHQtQlIuaTE4bi5hdHRyaWJ1dGVzJywge1xuICAgIGVtYWlsOiAnRW1haWwnLFxuICAgIHBhc3N3b3JkOiAnU2VuaGEnLFxuICAgIG5hbWU6ICdOb21lJyxcbiAgICBpbWFnZTogJ0ltYWdlbScsXG4gICAgcm9sZXM6ICdQZXJmaXMnLFxuICAgIGRhdGU6ICdEYXRhJyxcbiAgICBpbml0aWFsRGF0ZTogJ0RhdGEgSW5pY2lhbCcsXG4gICAgZmluYWxEYXRlOiAnRGF0YSBGaW5hbCcsXG4gICAgdGFzazoge1xuICAgICAgZGVzY3JpcHRpb246ICdEZXNjcmnDp8OjbycsXG4gICAgICBkb25lOiAnRmVpdG8/JyxcbiAgICAgIHByaW9yaXR5OiAnUHJpb3JpZGFkZScsXG4gICAgICBzY2hlZHVsZWRfdG86ICdBZ2VuZGFkbyBQYXJhPycsXG4gICAgICBwcm9qZWN0OiAnUHJvamV0bydcbiAgICB9LFxuICAgIHByb2plY3Q6IHtcbiAgICAgIGNvc3Q6ICdDdXN0bydcbiAgICB9LFxuICAgIC8vw6kgY2FycmVnYWRvIGRvIHNlcnZpZG9yIGNhc28gZXN0ZWphIGRlZmluaWRvIG5vIG1lc21vXG4gICAgYXVkaXRNb2RlbDoge31cbiAgfSk7XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4vKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCwgbm8tdW5kZWY6IDAqL1xuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25zdGFudCgncHQtQlIuaTE4bi5kaWFsb2cnLCB7XG4gICAgY29uZmlybVRpdGxlOiAnQ29uZmlybWHDp8OjbycsXG4gICAgY29uZmlybURlc2NyaXB0aW9uOiAnQ29uZmlybWEgYSBhw6fDo28/JyxcbiAgICByZW1vdmVEZXNjcmlwdGlvbjogJ0Rlc2VqYSByZW1vdmVyIHBlcm1hbmVudGVtZW50ZSB7e25hbWV9fT8nLFxuICAgIGF1ZGl0OiB7XG4gICAgICBjcmVhdGVkOiAnSW5mb3JtYcOnw7VlcyBkbyBDYWRhc3RybycsXG4gICAgICB1cGRhdGVkQmVmb3JlOiAnQW50ZXMgZGEgQXR1YWxpemHDp8OjbycsXG4gICAgICB1cGRhdGVkQWZ0ZXI6ICdEZXBvaXMgZGEgQXR1YWxpemHDp8OjbycsXG4gICAgICBkZWxldGVkOiAnSW5mb3JtYcOnw7VlcyBhbnRlcyBkZSByZW1vdmVyJ1xuICAgIH0sXG4gICAgbG9naW46IHtcbiAgICAgIHJlc2V0UGFzc3dvcmQ6IHtcbiAgICAgICAgZGVzY3JpcHRpb246ICdEaWdpdGUgYWJhaXhvIG8gZW1haWwgY2FkYXN0cmFkbyBubyBzaXN0ZW1hLidcbiAgICAgIH1cbiAgICB9XG4gIH0pO1xufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuLyplc2xpbnQgYW5ndWxhci9maWxlLW5hbWU6IDAsIG5vLXVuZGVmOiAwKi9cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29uc3RhbnQoJ3B0LUJSLmkxOG4uZ2xvYmFsJywge1xuICAgIGxvYWRpbmc6ICdDYXJyZWdhbmRvLi4uJyxcbiAgICBwcm9jZXNzaW5nOiAnUHJvY2Vzc2FuZG8uLi4nLFxuICAgIHllczogJ1NpbScsXG4gICAgbm86ICdOw6NvJyxcbiAgICBhbGw6ICdUb2RvcydcbiAgfSk7XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4vKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCwgbm8tdW5kZWY6IDAqL1xuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25zdGFudCgncHQtQlIuaTE4bi5tZXNzYWdlcycsIHtcbiAgICBpbnRlcm5hbEVycm9yOiAnT2NvcnJldSB1bSBlcnJvIGludGVybm8sIGNvbnRhdGUgbyBhZG1pbmlzdHJhZG9yIGRvIHNpc3RlbWEnLFxuICAgIG5vdEZvdW5kOiAnTmVuaHVtIHJlZ2lzdHJvIGVuY29udHJhZG8nLFxuICAgIG5vdEF1dGhvcml6ZWQ6ICdWb2PDqiBuw6NvIHRlbSBhY2Vzc28gYSBlc3RhIGZ1bmNpb25hbGlkYWRlLicsXG4gICAgc2VhcmNoRXJyb3I6ICdOw6NvIGZvaSBwb3Nzw612ZWwgcmVhbGl6YXIgYSBidXNjYS4nLFxuICAgIHNhdmVTdWNjZXNzOiAnUmVnaXN0cm8gc2Fsdm8gY29tIHN1Y2Vzc28uJyxcbiAgICBvcGVyYXRpb25TdWNjZXNzOiAnT3BlcmHDp8OjbyByZWFsaXphZGEgY29tIHN1Y2Vzc28uJyxcbiAgICBvcGVyYXRpb25FcnJvcjogJ0Vycm8gYW8gcmVhbGl6YXIgYSBvcGVyYcOnw6NvJyxcbiAgICBzYXZlRXJyb3I6ICdFcnJvIGFvIHRlbnRhciBzYWx2YXIgbyByZWdpc3Ryby4nLFxuICAgIHJlbW92ZVN1Y2Nlc3M6ICdSZW1vw6fDo28gcmVhbGl6YWRhIGNvbSBzdWNlc3NvLicsXG4gICAgcmVtb3ZlRXJyb3I6ICdFcnJvIGFvIHRlbnRhciByZW1vdmVyIG8gcmVnaXN0cm8uJyxcbiAgICByZXNvdXJjZU5vdEZvdW5kRXJyb3I6ICdSZWN1cnNvIG7Do28gZW5jb250cmFkbycsXG4gICAgbm90TnVsbEVycm9yOiAnVG9kb3Mgb3MgY2FtcG9zIG9icmlnYXTDs3Jpb3MgZGV2ZW0gc2VyIHByZWVuY2hpZG9zLicsXG4gICAgZHVwbGljYXRlZFJlc291cmNlRXJyb3I6ICdKw6EgZXhpc3RlIHVtIHJlY3Vyc28gY29tIGVzc2FzIGluZm9ybWHDp8O1ZXMuJyxcbiAgICB2YWxpZGF0ZToge1xuICAgICAgZmllbGRSZXF1aXJlZDogJ08gY2FtcG8ge3tmaWVsZH19IMOpIG9icmlncmF0w7NyaW8uJ1xuICAgIH0sXG4gICAgbGF5b3V0OiB7XG4gICAgICBlcnJvcjQwNDogJ1DDoWdpbmEgbsOjbyBlbmNvbnRyYWRhJ1xuICAgIH0sXG4gICAgbG9naW46IHtcbiAgICAgIGxvZ291dEluYWN0aXZlOiAnVm9jw6ogZm9pIGRlc2xvZ2FkbyBkbyBzaXN0ZW1hIHBvciBpbmF0aXZpZGFkZS4gRmF2b3IgZW50cmFyIG5vIHNpc3RlbWEgbm92YW1lbnRlLicsXG4gICAgICBpbnZhbGlkQ3JlZGVudGlhbHM6ICdDcmVkZW5jaWFpcyBJbnbDoWxpZGFzJyxcbiAgICAgIHVua25vd25FcnJvcjogJ07Do28gZm9pIHBvc3PDrXZlbCByZWFsaXphciBvIGxvZ2luLiBUZW50ZSBub3ZhbWVudGUuICcgKyAnQ2FzbyBuw6NvIGNvbnNpZ2EgZmF2b3IgZW5jb250cmFyIGVtIGNvbnRhdG8gY29tIG8gYWRtaW5pc3RyYWRvciBkbyBzaXN0ZW1hLicsXG4gICAgICB1c2VyTm90Rm91bmQ6ICdOw6NvIGZvaSBwb3Nzw612ZWwgZW5jb250cmFyIHNldXMgZGFkb3MnXG4gICAgfSxcbiAgICBkYXNoYm9hcmQ6IHtcbiAgICAgIHdlbGNvbWU6ICdTZWphIGJlbSBWaW5kbyB7e3VzZXJOYW1lfX0nLFxuICAgICAgZGVzY3JpcHRpb246ICdVdGlsaXplIG8gbWVudSBwYXJhIG5hdmVnYcOnw6NvLidcbiAgICB9LFxuICAgIG1haWw6IHtcbiAgICAgIG1haWxFcnJvcnM6ICdPY29ycmV1IHVtIGVycm8gbm9zIHNlZ3VpbnRlcyBlbWFpbHMgYWJhaXhvOlxcbicsXG4gICAgICBzZW5kTWFpbFN1Y2Nlc3M6ICdFbWFpbCBlbnZpYWRvIGNvbSBzdWNlc3NvIScsXG4gICAgICBzZW5kTWFpbEVycm9yOiAnTsOjbyBmb2kgcG9zc8OtdmVsIGVudmlhciBvIGVtYWlsLicsXG4gICAgICBwYXNzd29yZFNlbmRpbmdTdWNjZXNzOiAnTyBwcm9jZXNzbyBkZSByZWN1cGVyYcOnw6NvIGRlIHNlbmhhIGZvaSBpbmljaWFkby4gQ2FzbyBvIGVtYWlsIG7Do28gY2hlZ3VlIGVtIDEwIG1pbnV0b3MgdGVudGUgbm92YW1lbnRlLidcbiAgICB9LFxuICAgIHVzZXI6IHtcbiAgICAgIHJlbW92ZVlvdXJTZWxmRXJyb3I6ICdWb2PDqiBuw6NvIHBvZGUgcmVtb3ZlciBzZXUgcHLDs3ByaW8gdXN1w6FyaW8nLFxuICAgICAgdXNlckV4aXN0czogJ1VzdcOhcmlvIGrDoSBhZGljaW9uYWRvIScsXG4gICAgICBwcm9maWxlOiB7XG4gICAgICAgIHVwZGF0ZUVycm9yOiAnTsOjbyBmb2kgcG9zc8OtdmVsIGF0dWFsaXphciBzZXUgcHJvZmlsZSdcbiAgICAgIH1cbiAgICB9LFxuICAgIHF1ZXJ5RGluYW1pYzoge1xuICAgICAgbm9GaWx0ZXI6ICdOZW5odW0gZmlsdHJvIGFkaWNpb25hZG8nXG4gICAgfVxuICB9KTtcbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbi8qZXNsaW50IGFuZ3VsYXIvZmlsZS1uYW1lOiAwLCBuby11bmRlZjogMCovXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbnN0YW50KCdwdC1CUi5pMThuLm1vZGVscycsIHtcbiAgICB1c2VyOiAnVXN1w6FyaW8nLFxuICAgIHRhc2s6ICdUYXJlZmEnLFxuICAgIHByb2plY3Q6ICdQcm9qZXRvJ1xuICB9KTtcbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbi8qZXNsaW50IGFuZ3VsYXIvZmlsZS1uYW1lOiAwLCBuby11bmRlZjogMCovXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbnN0YW50KCdwdC1CUi5pMThuLnZpZXdzJywge1xuICAgIGJyZWFkY3J1bWJzOiB7XG4gICAgICB1c2VyOiAnQWRtaW5pc3RyYcOnw6NvIC0gVXN1w6FyaW8nLFxuICAgICAgJ3VzZXItcHJvZmlsZSc6ICdQZXJmaWwnLFxuICAgICAgZGFzaGJvYXJkOiAnRGFzaGJvYXJkJyxcbiAgICAgIGF1ZGl0OiAnQWRtaW5pc3RyYcOnw6NvIC0gQXVkaXRvcmlhJyxcbiAgICAgIG1haWw6ICdBZG1pbmlzdHJhw6fDo28gLSBFbnZpbyBkZSBlLW1haWwnLFxuICAgICAgcHJvamVjdHM6ICdQcm9qZXRvcycsXG4gICAgICAnZGluYW1pYy1xdWVyeSc6ICdBZG1pbmlzdHJhw6fDo28gLSBDb25zdWx0YXMgRGluw6JtaWNhcycsXG4gICAgICAnbm90LWF1dGhvcml6ZWQnOiAnQWNlc3NvIE5lZ2FkbydcbiAgICB9LFxuICAgIHRpdGxlczoge1xuICAgICAgZGFzaGJvYXJkOiAnUMOhZ2luYSBpbmljaWFsJyxcbiAgICAgIG1haWxTZW5kOiAnRW52aWFyIGUtbWFpbCcsXG4gICAgICB0YXNrTGlzdDogJ0xpc3RhIGRlIFRhcmVmYXMnLFxuICAgICAgdXNlckxpc3Q6ICdMaXN0YSBkZSBVc3XDoXJpb3MnLFxuICAgICAgYXVkaXRMaXN0OiAnTGlzdGEgZGUgTG9ncycsXG4gICAgICByZWdpc3RlcjogJ0Zvcm11bMOhcmlvIGRlIENhZGFzdHJvJyxcbiAgICAgIHJlc2V0UGFzc3dvcmQ6ICdSZWRlZmluaXIgU2VuaGEnLFxuICAgICAgdXBkYXRlOiAnRm9ybXVsw6FyaW8gZGUgQXR1YWxpemHDp8OjbydcbiAgICB9LFxuICAgIGFjdGlvbnM6IHtcbiAgICAgIHNlbmQ6ICdFbnZpYXInLFxuICAgICAgc2F2ZTogJ1NhbHZhcicsXG4gICAgICBjbGVhcjogJ0xpbXBhcicsXG4gICAgICBjbGVhckFsbDogJ0xpbXBhciBUdWRvJyxcbiAgICAgIHJlc3RhcnQ6ICdSZWluaWNpYXInLFxuICAgICAgZmlsdGVyOiAnRmlsdHJhcicsXG4gICAgICBzZWFyY2g6ICdQZXNxdWlzYXInLFxuICAgICAgbGlzdDogJ0xpc3RhcicsXG4gICAgICBlZGl0OiAnRWRpdGFyJyxcbiAgICAgIGNhbmNlbDogJ0NhbmNlbGFyJyxcbiAgICAgIHVwZGF0ZTogJ0F0dWFsaXphcicsXG4gICAgICByZW1vdmU6ICdSZW1vdmVyJyxcbiAgICAgIGdldE91dDogJ1NhaXInLFxuICAgICAgYWRkOiAnQWRpY2lvbmFyJyxcbiAgICAgIGluOiAnRW50cmFyJyxcbiAgICAgIGxvYWRJbWFnZTogJ0NhcnJlZ2FyIEltYWdlbScsXG4gICAgICBzaWdudXA6ICdDYWRhc3RyYXInLFxuICAgICAgY3JpYXJQcm9qZXRvOiAnQ3JpYXIgUHJvamV0bycsXG4gICAgICBwcm9qZWN0TGlzdDogJ0xpc3RhIGRlIFByb2pldG9zJ1xuICAgIH0sXG4gICAgZmllbGRzOiB7XG4gICAgICBkYXRlOiAnRGF0YScsXG4gICAgICBhY3Rpb246ICdBw6fDo28nLFxuICAgICAgYWN0aW9uczogJ0HDp8O1ZXMnLFxuICAgICAgYXVkaXQ6IHtcbiAgICAgICAgZGF0ZVN0YXJ0OiAnRGF0YSBJbmljaWFsJyxcbiAgICAgICAgZGF0ZUVuZDogJ0RhdGEgRmluYWwnLFxuICAgICAgICByZXNvdXJjZTogJ1JlY3Vyc28nLFxuICAgICAgICBhbGxSZXNvdXJjZXM6ICdUb2RvcyBSZWN1cnNvcycsXG4gICAgICAgIHR5cGU6IHtcbiAgICAgICAgICBjcmVhdGVkOiAnQ2FkYXN0cmFkbycsXG4gICAgICAgICAgdXBkYXRlZDogJ0F0dWFsaXphZG8nLFxuICAgICAgICAgIGRlbGV0ZWQ6ICdSZW1vdmlkbydcbiAgICAgICAgfVxuICAgICAgfSxcbiAgICAgIGxvZ2luOiB7XG4gICAgICAgIHJlc2V0UGFzc3dvcmQ6ICdFc3F1ZWNpIG1pbmhhIHNlbmhhJyxcbiAgICAgICAgY29uZmlybVBhc3N3b3JkOiAnQ29uZmlybWFyIHNlbmhhJ1xuICAgICAgfSxcbiAgICAgIG1haWw6IHtcbiAgICAgICAgdG86ICdQYXJhJyxcbiAgICAgICAgc3ViamVjdDogJ0Fzc3VudG8nLFxuICAgICAgICBtZXNzYWdlOiAnTWVuc2FnZW0nXG4gICAgICB9LFxuICAgICAgcXVlcnlEaW5hbWljOiB7XG4gICAgICAgIGZpbHRlcnM6ICdGaWx0cm9zJyxcbiAgICAgICAgcmVzdWx0czogJ1Jlc3VsdGFkb3MnLFxuICAgICAgICBtb2RlbDogJ01vZGVsJyxcbiAgICAgICAgYXR0cmlidXRlOiAnQXRyaWJ1dG8nLFxuICAgICAgICBvcGVyYXRvcjogJ09wZXJhZG9yJyxcbiAgICAgICAgcmVzb3VyY2U6ICdSZWN1cnNvJyxcbiAgICAgICAgdmFsdWU6ICdWYWxvcicsXG4gICAgICAgIG9wZXJhdG9yczoge1xuICAgICAgICAgIGVxdWFsczogJ0lndWFsJyxcbiAgICAgICAgICBkaWZlcmVudDogJ0RpZmVyZW50ZScsXG4gICAgICAgICAgY29udGVpbnM6ICdDb250w6ltJyxcbiAgICAgICAgICBzdGFydFdpdGg6ICdJbmljaWEgY29tJyxcbiAgICAgICAgICBmaW5pc2hXaXRoOiAnRmluYWxpemEgY29tJyxcbiAgICAgICAgICBiaWdnZXJUaGFuOiAnTWFpb3InLFxuICAgICAgICAgIGVxdWFsc09yQmlnZ2VyVGhhbjogJ01haW9yIG91IElndWFsJyxcbiAgICAgICAgICBsZXNzVGhhbjogJ01lbm9yJyxcbiAgICAgICAgICBlcXVhbHNPckxlc3NUaGFuOiAnTWVub3Igb3UgSWd1YWwnXG4gICAgICAgIH1cbiAgICAgIH0sXG4gICAgICBwcm9qZWN0OiB7XG4gICAgICAgIG5hbWU6ICdOb21lJyxcbiAgICAgICAgdG90YWxUYXNrOiAnVG90YWwgZGUgVGFyZWZhcydcbiAgICAgIH0sXG4gICAgICB0YXNrOiB7XG4gICAgICAgIGRvbmU6ICdOw6NvIEZlaXRvIC8gRmVpdG8nXG4gICAgICB9LFxuICAgICAgdXNlcjoge1xuICAgICAgICBwZXJmaWxzOiAnUGVyZmlzJyxcbiAgICAgICAgbmFtZU9yRW1haWw6ICdOb21lIG91IEVtYWlsJ1xuICAgICAgfVxuICAgIH0sXG4gICAgbGF5b3V0OiB7XG4gICAgICBtZW51OiB7XG4gICAgICAgIGRhc2hib2FyZDogJ0Rhc2hib2FyZCcsXG4gICAgICAgIHByb2plY3Q6ICdQcm9qZXRvcycsXG4gICAgICAgIGFkbWluOiAnQWRtaW5pc3RyYcOnw6NvJyxcbiAgICAgICAgZXhhbXBsZXM6ICdFeGVtcGxvcycsXG4gICAgICAgIHVzZXI6ICdVc3XDoXJpb3MnLFxuICAgICAgICBtYWlsOiAnRW52aWFyIGUtbWFpbCcsXG4gICAgICAgIGF1ZGl0OiAnQXVkaXRvcmlhJyxcbiAgICAgICAgZGluYW1pY1F1ZXJ5OiAnQ29uc3VsdGFzIERpbmFtaWNhcydcbiAgICAgIH1cbiAgICB9LFxuICAgIHRvb2x0aXBzOiB7XG4gICAgICBhdWRpdDoge1xuICAgICAgICB2aWV3RGV0YWlsOiAnVmlzdWFsaXphciBEZXRhbGhhbWVudG8nXG4gICAgICB9LFxuICAgICAgdXNlcjoge1xuICAgICAgICBwZXJmaWw6ICdQZXJmaWwnLFxuICAgICAgICB0cmFuc2ZlcjogJ1RyYW5zZmVyaXInXG4gICAgICB9LFxuICAgICAgdGFzazoge1xuICAgICAgICBsaXN0VGFzazogJ0xpc3RhciBUYXJlZmFzJ1xuICAgICAgfVxuICAgIH1cbiAgfSk7XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29udHJvbGxlcignVGFza3NEaWFsb2dDb250cm9sbGVyJywgVGFza3NEaWFsb2dDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIFRhc2tzRGlhbG9nQ29udHJvbGxlcigkY29udHJvbGxlciwgVGFza3NTZXJ2aWNlLCBwcm9qZWN0SWQsIFByVG9hc3QsIC8vIE5PU09OQVJcbiAgUHJEaWFsb2csICR0cmFuc2xhdGUsIEdsb2JhbCwgbW9tZW50KSB7XG5cbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgLy9GdW5jdGlvbnMgQmxvY2tcbiAgICB2bS5vbkFjdGl2YXRlID0gb25BY3RpdmF0ZTtcbiAgICB2bS5jbG9zZSA9IGNsb3NlO1xuICAgIHZtLmFwcGx5RmlsdGVycyA9IGFwcGx5RmlsdGVycztcbiAgICB2bS5iZWZvcmVTYXZlID0gYmVmb3JlU2F2ZTtcbiAgICB2bS5hZnRlclNhdmUgPSBhZnRlclNhdmU7XG4gICAgdm0udG9nZ2xlRG9uZSA9IHRvZ2dsZURvbmU7XG5cbiAgICAvLyBpbnN0YW50aWF0ZSBiYXNlIGNvbnRyb2xsZXJcbiAgICAkY29udHJvbGxlcignQ1JVRENvbnRyb2xsZXInLCB7IHZtOiB2bSwgbW9kZWxTZXJ2aWNlOiBUYXNrc1NlcnZpY2UsIG9wdGlvbnM6IHtcbiAgICAgICAgcGVyUGFnZTogNVxuICAgICAgfSB9KTtcblxuICAgIGZ1bmN0aW9uIG9uQWN0aXZhdGUoKSB7XG4gICAgICB2bS5nbG9iYWwgPSBHbG9iYWw7XG4gICAgICB2bS5yZXNvdXJjZS5zY2hlZHVsZWRfdG8gPSBtb21lbnQoKS5hZGQoMzAsICdtaW51dGVzJyk7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMgPSB7IHByb2plY3RJZDogcHJvamVjdElkIH07XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gYXBwbHlGaWx0ZXJzKGRlZmF1bHRRdWVyeUZpbHRlcnMpIHtcbiAgICAgIHJldHVybiBhbmd1bGFyLmV4dGVuZChkZWZhdWx0UXVlcnlGaWx0ZXJzLCB2bS5xdWVyeUZpbHRlcnMpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGJlZm9yZVNhdmUoKSB7XG4gICAgICB2bS5yZXNvdXJjZS5wcm9qZWN0X2lkID0gdm0ucXVlcnlGaWx0ZXJzLnByb2plY3RJZDtcbiAgICAgIHZtLnJlc291cmNlLnByb2plY3QgPSBudWxsO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGFmdGVyU2F2ZSgpIHtcbiAgICAgIHZtLmNsZWFuRm9ybSgpO1xuICAgICAgdm0uc2VhcmNoKHZtLnBhZ2luYXRvci5jdXJyZW50UGFnZSk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gY2xvc2UoKSB7XG4gICAgICB2bS5jbGVhbkZvcm0oKTtcbiAgICAgIFByRGlhbG9nLmNsb3NlKCk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gdG9nZ2xlRG9uZShyZXNvdXJjZSkge1xuICAgICAgVGFza3NTZXJ2aWNlLnRvZ2dsZURvbmUoeyBpZDogcmVzb3VyY2UuaWQsIGRvbmU6IHJlc291cmNlLmRvbmUgfSkudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgIFByVG9hc3Quc3VjY2VzcygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnNhdmVTdWNjZXNzJykpO1xuICAgICAgICB2bS5zZWFyY2godm0ucGFnaW5hdG9yLmN1cnJlbnRQYWdlKTtcbiAgICAgIH0sIGZ1bmN0aW9uIChlcnJvcikge1xuICAgICAgICBQclRvYXN0LmVycm9yVmFsaWRhdGlvbihlcnJvci5kYXRhLCAkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLm9wZXJhdGlvbkVycm9yJykpO1xuICAgICAgfSk7XG4gICAgfVxuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZhY3RvcnkoJ1Rhc2tzU2VydmljZScsIFRhc2tzU2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiBUYXNrc1NlcnZpY2Uoc2VydmljZUZhY3RvcnksIG1vbWVudCkge1xuICAgIHJldHVybiBzZXJ2aWNlRmFjdG9yeSgndGFza3MnLCB7XG4gICAgICAvL3F1YW5kbyBpbnN0YW5jaWEgdW0gdXN1w6FyaW8gc2VtIHBhc3NhciBwYXJhbWV0cm8sXG4gICAgICAvL28gbWVzbW8gdmFpIHRlciBvcyB2YWxvcmVzIGRlZmF1bHRzIGFiYWl4b1xuICAgICAgZGVmYXVsdHM6IHtcbiAgICAgICAgc2NoZWR1bGVkX3RvOiBuZXcgRGF0ZSgpXG4gICAgICB9LFxuXG4gICAgICBtYXA6IHtcbiAgICAgICAgLy9jb252ZXJ0IHBhcmEgb2JqZXRvIGphdmFzY3JpcHQgZGF0ZSB1bWEgc3RyaW5nIGZvcm1hdGFkYSBjb21vIGRhdGFcbiAgICAgICAgc2NoZWR1bGVkX3RvOiBmdW5jdGlvbiBzY2hlZHVsZWRfdG8odmFsdWUpIHtcbiAgICAgICAgICByZXR1cm4gbW9tZW50KHZhbHVlKS50b0RhdGUoKTtcbiAgICAgICAgfVxuICAgICAgfSxcblxuICAgICAgYWN0aW9uczoge1xuICAgICAgICAvKipcbiAgICAgICAgICogQXR1YWxpemEgb3Mgc3RhdHVzIGRhIHRhcmVmYVxuICAgICAgICAgKlxuICAgICAgICAgKiBAcGFyYW0ge29iamVjdH0gYXR0cmlidXRlc1xuICAgICAgICAgKi9cbiAgICAgICAgdG9nZ2xlRG9uZToge1xuICAgICAgICAgIG1ldGhvZDogJ1BVVCcsXG4gICAgICAgICAgdXJsOiAndG9nZ2xlRG9uZSdcbiAgICAgICAgfVxuICAgICAgfSxcbiAgICAgIGluc3RhbmNlOiB7fVxuICAgIH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29udHJvbGxlcignVXNlcnNEaWFsb2dDb250cm9sbGVyJywgVXNlcnNEaWFsb2dDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIFVzZXJzRGlhbG9nQ29udHJvbGxlcigkY29udHJvbGxlciwgVXNlcnNTZXJ2aWNlLCBQckRpYWxvZywgLy8gTk9TT05BUlxuICB1c2VyRGlhbG9nSW5wdXQsIG9uSW5pdCkge1xuXG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIHZtLm9uQWN0aXZhdGUgPSBvbkFjdGl2YXRlO1xuICAgIHZtLmFwcGx5RmlsdGVycyA9IGFwcGx5RmlsdGVycztcbiAgICB2bS5jbG9zZSA9IGNsb3NlO1xuXG4gICAgaWYgKGFuZ3VsYXIuaXNEZWZpbmVkKHVzZXJEaWFsb2dJbnB1dCkpIHtcbiAgICAgIHZtLnRyYW5zZmVyVXNlciA9IHVzZXJEaWFsb2dJbnB1dC50cmFuc2ZlclVzZXJGbjtcbiAgICB9XG5cbiAgICAvLyBpbnN0YW50aWF0ZSBiYXNlIGNvbnRyb2xsZXJcbiAgICAkY29udHJvbGxlcignQ1JVRENvbnRyb2xsZXInLCB7XG4gICAgICB2bTogdm0sXG4gICAgICBtb2RlbFNlcnZpY2U6IFVzZXJzU2VydmljZSxcbiAgICAgIHNlYXJjaE9uSW5pdDogb25Jbml0LFxuICAgICAgb3B0aW9uczoge1xuICAgICAgICBwZXJQYWdlOiA1XG4gICAgICB9XG4gICAgfSk7XG5cbiAgICBmdW5jdGlvbiBvbkFjdGl2YXRlKCkge1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0ge307XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gYXBwbHlGaWx0ZXJzKCkge1xuICAgICAgcmV0dXJuIGFuZ3VsYXIuZXh0ZW5kKHZtLmRlZmF1bHRRdWVyeUZpbHRlcnMsIHZtLnF1ZXJ5RmlsdGVycyk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gY2xvc2UoKSB7XG4gICAgICBQckRpYWxvZy5jbG9zZSgpO1xuICAgIH1cbiAgfVxufSkoKTsiLCIvKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCovXG4oZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJywgW1xuICAgICduZ0FuaW1hdGUnLFxuICAgICduZ0FyaWEnLFxuICAgICd1aS5yb3V0ZXInLFxuICAgICduZ1Byb2RlYicsXG4gICAgJ3VpLnV0aWxzLm1hc2tzJyxcbiAgICAndGV4dC1tYXNrJyxcbiAgICAnbmdNYXRlcmlhbCcsXG4gICAgJ21vZGVsRmFjdG9yeScsXG4gICAgJ21kLmRhdGEudGFibGUnLFxuICAgICduZ01hdGVyaWFsRGF0ZVBpY2tlcicsXG4gICAgJ3Bhc2NhbHByZWNodC50cmFuc2xhdGUnLFxuICAgICdhbmd1bGFyRmlsZVVwbG9hZCddKTtcbn0pKCk7XG4iLCIoZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbmZpZyhjb25maWcpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gY29uZmlnKEdsb2JhbCwgJG1kVGhlbWluZ1Byb3ZpZGVyLCAkbW9kZWxGYWN0b3J5UHJvdmlkZXIsICAvLyBOT1NPTkFSXG4gICAgJHRyYW5zbGF0ZVByb3ZpZGVyLCBtb21lbnQsICRtZEFyaWFQcm92aWRlcikge1xuXG4gICAgJHRyYW5zbGF0ZVByb3ZpZGVyXG4gICAgICAudXNlTG9hZGVyKCdsYW5ndWFnZUxvYWRlcicpXG4gICAgICAudXNlU2FuaXRpemVWYWx1ZVN0cmF0ZWd5KCdlc2NhcGUnKTtcblxuICAgICR0cmFuc2xhdGVQcm92aWRlci51c2VQb3N0Q29tcGlsaW5nKHRydWUpO1xuXG4gICAgbW9tZW50LmxvY2FsZSgncHQtQlInKTtcblxuICAgIC8vb3Mgc2VydmnDp29zIHJlZmVyZW50ZSBhb3MgbW9kZWxzIHZhaSB1dGlsaXphciBjb21vIGJhc2UgbmFzIHVybHNcbiAgICAkbW9kZWxGYWN0b3J5UHJvdmlkZXIuZGVmYXVsdE9wdGlvbnMucHJlZml4ID0gR2xvYmFsLmFwaVBhdGg7XG5cbiAgICAvLyBDb25maWd1cmF0aW9uIHRoZW1lXG4gICAgJG1kVGhlbWluZ1Byb3ZpZGVyLnRoZW1lKCdkZWZhdWx0JylcbiAgICAgIC5wcmltYXJ5UGFsZXR0ZSgnYnJvd24nLCB7XG4gICAgICAgIGRlZmF1bHQ6ICc3MDAnXG4gICAgICB9KVxuICAgICAgLmFjY2VudFBhbGV0dGUoJ2FtYmVyJylcbiAgICAgIC53YXJuUGFsZXR0ZSgnZGVlcC1vcmFuZ2UnKTtcblxuICAgIC8vIEVuYWJsZSBicm93c2VyIGNvbG9yXG4gICAgJG1kVGhlbWluZ1Byb3ZpZGVyLmVuYWJsZUJyb3dzZXJDb2xvcigpO1xuXG4gICAgJG1kQXJpYVByb3ZpZGVyLmRpc2FibGVXYXJuaW5ncygpO1xuXG4gIH1cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb250cm9sbGVyKCdBcHBDb250cm9sbGVyJywgQXBwQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvKipcbiAgICogQ29udHJvbGFkb3IgcmVzcG9uc8OhdmVsIHBvciBmdW5jaW9uYWxpZGFkZXMgcXVlIHPDo28gYWNpb25hZGFzIGVtIHF1YWxxdWVyIHRlbGEgZG8gc2lzdGVtYVxuICAgKlxuICAgKi9cbiAgZnVuY3Rpb24gQXBwQ29udHJvbGxlcigkc3RhdGUsIEF1dGgsIEdsb2JhbCkge1xuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICAvL2FubyBhdHVhbCBwYXJhIHNlciBleGliaWRvIG5vIHJvZGFww6kgZG8gc2lzdGVtYVxuICAgIHZtLmFub0F0dWFsID0gbnVsbDtcblxuICAgIHZtLmxvZ291dCAgICAgPSBsb2dvdXQ7XG4gICAgdm0uZ2V0SW1hZ2VQZXJmaWwgPSBnZXRJbWFnZVBlcmZpbDtcblxuICAgIGFjdGl2YXRlKCk7XG5cbiAgICBmdW5jdGlvbiBhY3RpdmF0ZSgpIHtcbiAgICAgIHZhciBkYXRlID0gbmV3IERhdGUoKTtcblxuICAgICAgdm0uYW5vQXR1YWwgPSBkYXRlLmdldEZ1bGxZZWFyKCk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gbG9nb3V0KCkge1xuICAgICAgQXV0aC5sb2dvdXQoKS50aGVuKGZ1bmN0aW9uKCkge1xuICAgICAgICAkc3RhdGUuZ28oR2xvYmFsLmxvZ2luU3RhdGUpO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gZ2V0SW1hZ2VQZXJmaWwoKSB7XG4gICAgICByZXR1cm4gKEF1dGguY3VycmVudFVzZXIgJiYgQXV0aC5jdXJyZW50VXNlci5pbWFnZSlcbiAgICAgICAgPyBBdXRoLmN1cnJlbnRVc2VyLmltYWdlXG4gICAgICAgIDogR2xvYmFsLmltYWdlUGF0aCArICcvbm9fYXZhdGFyLmdpZic7XG4gICAgfVxuXG4gIH1cblxufSkoKTtcbiIsIi8qZXNsaW50IGFuZ3VsYXIvZmlsZS1uYW1lOiAwLCBuby11bmRlZjogMCovXG4oZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICAvKipcbiAgICogVHJhbnNmb3JtYSBiaWJsaW90ZWNhcyBleHRlcm5hcyBlbSBzZXJ2acOnb3MgZG8gYW5ndWxhciBwYXJhIHNlciBwb3Nzw612ZWwgdXRpbGl6YXJcbiAgICogYXRyYXbDqXMgZGEgaW5qZcOnw6NvIGRlIGRlcGVuZMOqbmNpYVxuICAgKi9cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnN0YW50KCdsb2Rhc2gnLCBfKVxuICAgIC5jb25zdGFudCgnbW9tZW50JywgbW9tZW50KTtcblxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb25zdGFudCgnR2xvYmFsJywge1xuICAgICAgYXBwTmFtZTogJ0ZyZWVsYWdpbGUnLFxuICAgICAgaG9tZVN0YXRlOiAnYXBwLnByb2plY3RzJyxcbiAgICAgIGxvZ2luVXJsOiAnYXBwL2xvZ2luJyxcbiAgICAgIGxvZ2luU3RhdGU6ICdhcHAubG9naW4nLFxuICAgICAgcmVzZXRQYXNzd29yZFN0YXRlOiAnYXBwLnBhc3N3b3JkLXJlc2V0JyxcbiAgICAgIG5vdEF1dGhvcml6ZWRTdGF0ZTogJ2FwcC5ub3QtYXV0aG9yaXplZCcsXG4gICAgICB0b2tlbktleTogJ3NlcnZlcl90b2tlbicsXG4gICAgICBjbGllbnRQYXRoOiAnY2xpZW50L2FwcCcsXG4gICAgICBhcGlQYXRoOiAnYXBpL3YxJyxcbiAgICAgIGltYWdlUGF0aDogJ2NsaWVudC9pbWFnZXMnXG4gICAgfSk7XG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCAkdXJsUm91dGVyUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyXG4gICAgICAuc3RhdGUoJ2FwcCcsIHtcbiAgICAgICAgdXJsOiAnL2FwcCcsXG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvbGF5b3V0L2FwcC5odG1sJyxcbiAgICAgICAgYWJzdHJhY3Q6IHRydWUsXG4gICAgICAgIHJlc29sdmU6IHsgLy9lbnN1cmUgbGFuZ3MgaXMgcmVhZHkgYmVmb3JlIHJlbmRlciB2aWV3XG4gICAgICAgICAgdHJhbnNsYXRlUmVhZHk6IFsnJHRyYW5zbGF0ZScsICckcScsIGZ1bmN0aW9uKCR0cmFuc2xhdGUsICRxKSB7XG4gICAgICAgICAgICB2YXIgZGVmZXJyZWQgPSAkcS5kZWZlcigpO1xuXG4gICAgICAgICAgICAkdHJhbnNsYXRlLnVzZSgncHQtQlInKS50aGVuKGZ1bmN0aW9uKCkge1xuICAgICAgICAgICAgICBkZWZlcnJlZC5yZXNvbHZlKCk7XG4gICAgICAgICAgICB9KTtcblxuICAgICAgICAgICAgcmV0dXJuIGRlZmVycmVkLnByb21pc2U7XG4gICAgICAgICAgfV1cbiAgICAgICAgfVxuICAgICAgfSlcbiAgICAgIC5zdGF0ZShHbG9iYWwubm90QXV0aG9yaXplZFN0YXRlLCB7XG4gICAgICAgIHVybDogJy9hY2Vzc28tbmVnYWRvJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9sYXlvdXQvbm90LWF1dGhvcml6ZWQuaHRtbCcsXG4gICAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiBmYWxzZSB9XG4gICAgICB9KTtcblxuICAgICR1cmxSb3V0ZXJQcm92aWRlci53aGVuKCcvYXBwJywgR2xvYmFsLmxvZ2luVXJsKTtcbiAgICAkdXJsUm91dGVyUHJvdmlkZXIub3RoZXJ3aXNlKEdsb2JhbC5sb2dpblVybCk7XG4gIH1cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAucnVuKHJ1bik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBydW4oJHJvb3RTY29wZSwgJHN0YXRlLCAkc3RhdGVQYXJhbXMsIEF1dGgsIEdsb2JhbCkgeyAvLyBOT1NPTkFSXG4gICAgLy9zZXRhZG8gbm8gcm9vdFNjb3BlIHBhcmEgcG9kZXIgc2VyIGFjZXNzYWRvIG5hcyB2aWV3cyBzZW0gcHJlZml4byBkZSBjb250cm9sbGVyXG4gICAgJHJvb3RTY29wZS4kc3RhdGUgPSAkc3RhdGU7XG4gICAgJHJvb3RTY29wZS4kc3RhdGVQYXJhbXMgPSAkc3RhdGVQYXJhbXM7XG4gICAgJHJvb3RTY29wZS5hdXRoID0gQXV0aDtcbiAgICAkcm9vdFNjb3BlLmdsb2JhbCA9IEdsb2JhbDtcblxuICAgIC8vbm8gaW5pY2lvIGNhcnJlZ2EgbyB1c3XDoXJpbyBkbyBsb2NhbHN0b3JhZ2UgY2FzbyBvIHVzdcOhcmlvIGVzdGFqYSBhYnJpbmRvIG8gbmF2ZWdhZG9yXG4gICAgLy9wYXJhIHZvbHRhciBhdXRlbnRpY2Fkb1xuICAgIEF1dGgucmV0cmlldmVVc2VyRnJvbUxvY2FsU3RvcmFnZSgpO1xuICB9XG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29udHJvbGxlcignQXVkaXRDb250cm9sbGVyJywgQXVkaXRDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIEF1ZGl0Q29udHJvbGxlcigkY29udHJvbGxlciwgQXVkaXRTZXJ2aWNlLCBQckRpYWxvZywgR2xvYmFsLCAkdHJhbnNsYXRlKSB7IC8vIE5PU09OQVJcbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0ub25BY3RpdmF0ZSA9IG9uQWN0aXZhdGU7XG4gICAgdm0uYXBwbHlGaWx0ZXJzID0gYXBwbHlGaWx0ZXJzO1xuICAgIHZtLnZpZXdEZXRhaWwgPSB2aWV3RGV0YWlsO1xuXG4gICAgJGNvbnRyb2xsZXIoJ0NSVURDb250cm9sbGVyJywgeyB2bTogdm0sIG1vZGVsU2VydmljZTogQXVkaXRTZXJ2aWNlLCBvcHRpb25zOiB7fSB9KTtcblxuICAgIGZ1bmN0aW9uIG9uQWN0aXZhdGUoKSB7XG4gICAgICB2bS5tb2RlbHMgPSBbXTtcbiAgICAgIHZtLnF1ZXJ5RmlsdGVycyA9IHt9O1xuXG4gICAgICAvL1BlZ2EgdG9kb3Mgb3MgbW9kZWxzIGRvIHNlcnZlciBlIG1vbnRhIHVtYSBsaXN0YSBwcm8gQ29tYm9Cb3hcbiAgICAgIEF1ZGl0U2VydmljZS5nZXRBdWRpdGVkTW9kZWxzKCkudGhlbihmdW5jdGlvbihkYXRhKSB7XG4gICAgICAgIHZhciBtb2RlbHMgPSBbeyBpZDogJycsIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ2dsb2JhbC5hbGwnKSB9XTtcblxuICAgICAgICBkYXRhLm1vZGVscy5zb3J0KCk7XG5cbiAgICAgICAgZm9yICh2YXIgaW5kZXggPSAwOyBpbmRleCA8IGRhdGEubW9kZWxzLmxlbmd0aDsgaW5kZXgrKykge1xuICAgICAgICAgIHZhciBtb2RlbCA9IGRhdGEubW9kZWxzW2luZGV4XTtcblxuICAgICAgICAgIG1vZGVscy5wdXNoKHtcbiAgICAgICAgICAgIGlkOiBtb2RlbCxcbiAgICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ21vZGVscy4nICsgbW9kZWwudG9Mb3dlckNhc2UoKSlcbiAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHZtLm1vZGVscyA9IG1vZGVscztcbiAgICAgICAgdm0ucXVlcnlGaWx0ZXJzLm1vZGVsID0gdm0ubW9kZWxzWzBdLmlkO1xuICAgICAgfSk7XG5cbiAgICAgIHZtLnR5cGVzID0gQXVkaXRTZXJ2aWNlLmxpc3RUeXBlcygpO1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzLnR5cGUgPSB2bS50eXBlc1swXS5pZDtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBhcHBseUZpbHRlcnMoZGVmYXVsdFF1ZXJ5RmlsdGVycykge1xuICAgICAgcmV0dXJuIGFuZ3VsYXIuZXh0ZW5kKGRlZmF1bHRRdWVyeUZpbHRlcnMsIHZtLnF1ZXJ5RmlsdGVycyk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gdmlld0RldGFpbChhdWRpdERldGFpbCkge1xuICAgICAgdmFyIGNvbmZpZyA9IHtcbiAgICAgICAgbG9jYWxzOiB7IGF1ZGl0RGV0YWlsOiBhdWRpdERldGFpbCB9LFxuICAgICAgICAvKiogQG5nSW5qZWN0ICovXG4gICAgICAgIGNvbnRyb2xsZXI6IGZ1bmN0aW9uKGF1ZGl0RGV0YWlsLCBQckRpYWxvZykge1xuICAgICAgICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICAgICAgICB2bS5jbG9zZSA9IGNsb3NlO1xuXG4gICAgICAgICAgYWN0aXZhdGUoKTtcblxuICAgICAgICAgIGZ1bmN0aW9uIGFjdGl2YXRlKCkge1xuICAgICAgICAgICAgaWYgKGFuZ3VsYXIuaXNBcnJheShhdWRpdERldGFpbC5vbGQpICYmIGF1ZGl0RGV0YWlsLm9sZC5sZW5ndGggPT09IDApIGF1ZGl0RGV0YWlsLm9sZCA9IG51bGw7XG4gICAgICAgICAgICBpZiAoYW5ndWxhci5pc0FycmF5KGF1ZGl0RGV0YWlsLm5ldykgJiYgYXVkaXREZXRhaWwubmV3Lmxlbmd0aCA9PT0gMCkgYXVkaXREZXRhaWwubmV3ID0gbnVsbDtcblxuICAgICAgICAgICAgdm0uYXVkaXREZXRhaWwgPSBhdWRpdERldGFpbDtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICBmdW5jdGlvbiBjbG9zZSgpIHtcbiAgICAgICAgICAgIFByRGlhbG9nLmNsb3NlKCk7XG4gICAgICAgICAgfVxuXG4gICAgICAgIH0sXG4gICAgICAgIGNvbnRyb2xsZXJBczogJ2F1ZGl0RGV0YWlsQ3RybCcsXG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvYXVkaXQvYXVkaXQtZGV0YWlsLmh0bWwnLFxuICAgICAgICBoYXNCYWNrZHJvcDogdHJ1ZVxuICAgICAgfTtcblxuICAgICAgUHJEaWFsb2cuY3VzdG9tKGNvbmZpZyk7XG4gICAgfVxuXG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb25maWcocm91dGVzKTtcblxuICAvKipcbiAgICogQXJxdWl2byBkZSBjb25maWd1cmHDp8OjbyBjb20gYXMgcm90YXMgZXNwZWPDrWZpY2FzIGRlIGF1ZGl0b3JpYVxuICAgKlxuICAgKiBAcGFyYW0ge2FueX0gJHN0YXRlUHJvdmlkZXJcbiAgICogQHBhcmFtIHthbnl9IEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyXG4gICAgICAuc3RhdGUoJ2FwcC5hdWRpdCcsIHtcbiAgICAgICAgdXJsOiAnL2F1ZGl0b3JpYScsXG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvYXVkaXQvYXVkaXQuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdBdWRpdENvbnRyb2xsZXIgYXMgYXVkaXRDdHJsJyxcbiAgICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IHRydWUsIG5lZWRQcm9maWxlOiBbJ2FkbWluJ10gfVxuICAgICAgfSk7XG5cbiAgfVxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5mYWN0b3J5KCdBdWRpdFNlcnZpY2UnLCBBdWRpdFNlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gQXVkaXRTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5LCAkdHJhbnNsYXRlKSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCdhdWRpdCcsIHtcbiAgICAgIGFjdGlvbnM6IHtcbiAgICAgICAgZ2V0QXVkaXRlZE1vZGVsczoge1xuICAgICAgICAgIG1ldGhvZDogJ0dFVCcsXG4gICAgICAgICAgdXJsOiAnbW9kZWxzJ1xuICAgICAgICB9XG4gICAgICB9LFxuICAgICAgaW5zdGFuY2U6IHtcbiAgICAgIH0sXG4gICAgICBsaXN0VHlwZXM6IGZ1bmN0aW9uKCkge1xuICAgICAgICB2YXIgYXVkaXRQYXRoID0gJ3ZpZXdzLmZpZWxkcy5hdWRpdC4nO1xuXG4gICAgICAgIHJldHVybiBbXG4gICAgICAgICAgeyBpZDogJycsIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoYXVkaXRQYXRoICsgJ2FsbFJlc291cmNlcycpIH0sXG4gICAgICAgICAgeyBpZDogJ2NyZWF0ZWQnLCBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KGF1ZGl0UGF0aCArICd0eXBlLmNyZWF0ZWQnKSB9LFxuICAgICAgICAgIHsgaWQ6ICd1cGRhdGVkJywgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudChhdWRpdFBhdGggKyAndHlwZS51cGRhdGVkJykgfSxcbiAgICAgICAgICB7IGlkOiAnZGVsZXRlZCcsIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoYXVkaXRQYXRoICsgJ3R5cGUuZGVsZXRlZCcpIH1cbiAgICAgICAgXTtcbiAgICAgIH1cbiAgICB9KTtcbiAgfVxuXG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKlxuICAgKiBBcnF1aXZvIGRlIGNvbmZpZ3VyYcOnw6NvIGNvbSBhcyByb3RhcyBlc3BlY8OtZmljYXMgZG8gcmVjdXJzbyB1c2VyXG4gICAqXG4gICAqIEBwYXJhbSB7YW55fSAkc3RhdGVQcm92aWRlclxuICAgKiBAcGFyYW0ge2FueX0gR2xvYmFsXG4gICAqL1xuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvdXRlcygkc3RhdGVQcm92aWRlciwgR2xvYmFsKSB7XG4gICAgJHN0YXRlUHJvdmlkZXJcbiAgICAgIC5zdGF0ZShHbG9iYWwucmVzZXRQYXNzd29yZFN0YXRlLCB7XG4gICAgICAgIHVybDogJy9wYXNzd29yZC9yZXNldC86dG9rZW4nLFxuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL2F1dGgvcmVzZXQtcGFzcy1mb3JtLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnUGFzc3dvcmRDb250cm9sbGVyIGFzIHBhc3NDdHJsJyxcbiAgICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IGZhbHNlIH1cbiAgICAgIH0pXG4gICAgICAuc3RhdGUoR2xvYmFsLmxvZ2luU3RhdGUsIHtcbiAgICAgICAgdXJsOiAnL2xvZ2luJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9hdXRoL2xvZ2luLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnTG9naW5Db250cm9sbGVyIGFzIGxvZ2luQ3RybCcsXG4gICAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiBmYWxzZSB9XG4gICAgICB9KTtcblxuICB9XG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZhY3RvcnkoJ0F1dGgnLCBBdXRoKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIEF1dGgoJGh0dHAsICRxLCBHbG9iYWwsIFVzZXJzU2VydmljZSkgeyAvLyBOT1NPTkFSXG4gICAgdmFyIGF1dGggPSB7XG4gICAgICBsb2dpbjogbG9naW4sXG4gICAgICBsb2dvdXQ6IGxvZ291dCxcbiAgICAgIHVwZGF0ZUN1cnJlbnRVc2VyOiB1cGRhdGVDdXJyZW50VXNlcixcbiAgICAgIHJldHJpZXZlVXNlckZyb21Mb2NhbFN0b3JhZ2U6IHJldHJpZXZlVXNlckZyb21Mb2NhbFN0b3JhZ2UsXG4gICAgICBhdXRoZW50aWNhdGVkOiBhdXRoZW50aWNhdGVkLFxuICAgICAgc2VuZEVtYWlsUmVzZXRQYXNzd29yZDogc2VuZEVtYWlsUmVzZXRQYXNzd29yZCxcbiAgICAgIHJlbW90ZVZhbGlkYXRlVG9rZW46IHJlbW90ZVZhbGlkYXRlVG9rZW4sXG4gICAgICBnZXRUb2tlbjogZ2V0VG9rZW4sXG4gICAgICBzZXRUb2tlbjogc2V0VG9rZW4sXG4gICAgICBjbGVhclRva2VuOiBjbGVhclRva2VuLFxuICAgICAgY3VycmVudFVzZXI6IG51bGxcbiAgICB9O1xuXG4gICAgZnVuY3Rpb24gY2xlYXJUb2tlbigpIHtcbiAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKEdsb2JhbC50b2tlbktleSk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gc2V0VG9rZW4odG9rZW4pIHtcbiAgICAgIGxvY2FsU3RvcmFnZS5zZXRJdGVtKEdsb2JhbC50b2tlbktleSwgdG9rZW4pO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGdldFRva2VuKCkge1xuICAgICAgcmV0dXJuIGxvY2FsU3RvcmFnZS5nZXRJdGVtKEdsb2JhbC50b2tlbktleSk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gcmVtb3RlVmFsaWRhdGVUb2tlbigpIHtcbiAgICAgIHZhciBkZWZlcnJlZCA9ICRxLmRlZmVyKCk7XG5cbiAgICAgIGlmIChhdXRoLmF1dGhlbnRpY2F0ZWQoKSkge1xuICAgICAgICAkaHR0cC5nZXQoR2xvYmFsLmFwaVBhdGggKyAnL2F1dGhlbnRpY2F0ZS9jaGVjaycpXG4gICAgICAgICAgLnRoZW4oZnVuY3Rpb24oKSB7XG4gICAgICAgICAgICBkZWZlcnJlZC5yZXNvbHZlKHRydWUpO1xuICAgICAgICAgIH0sIGZ1bmN0aW9uKCkge1xuICAgICAgICAgICAgYXV0aC5sb2dvdXQoKTtcblxuICAgICAgICAgICAgZGVmZXJyZWQucmVqZWN0KGZhbHNlKTtcbiAgICAgICAgICB9KTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIGF1dGgubG9nb3V0KCk7XG5cbiAgICAgICAgZGVmZXJyZWQucmVqZWN0KGZhbHNlKTtcbiAgICAgIH1cblxuICAgICAgcmV0dXJuIGRlZmVycmVkLnByb21pc2U7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogVmVyaWZpY2Egc2UgbyB1c3XDoXJpbyBlc3TDoSBhdXRlbnRpY2Fkb1xuICAgICAqXG4gICAgICogQHJldHVybnMge2Jvb2xlYW59XG4gICAgICovXG4gICAgZnVuY3Rpb24gYXV0aGVudGljYXRlZCgpIHtcbiAgICAgIHJldHVybiBhdXRoLmdldFRva2VuKCkgIT09IG51bGxcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWN1cGVyYSBvIHVzdcOhcmlvIGRvIGxvY2FsU3RvcmFnZVxuICAgICAqL1xuICAgIGZ1bmN0aW9uIHJldHJpZXZlVXNlckZyb21Mb2NhbFN0b3JhZ2UoKSB7XG4gICAgICB2YXIgdXNlciA9IGxvY2FsU3RvcmFnZS5nZXRJdGVtKCd1c2VyJyk7XG5cbiAgICAgIGlmICh1c2VyKSB7XG4gICAgICAgIGF1dGguY3VycmVudFVzZXIgPSBhbmd1bGFyLm1lcmdlKG5ldyBVc2Vyc1NlcnZpY2UoKSwgYW5ndWxhci5mcm9tSnNvbih1c2VyKSk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogR3VhcmRhIG8gdXN1w6FyaW8gbm8gbG9jYWxTdG9yYWdlIHBhcmEgY2FzbyBvIHVzdcOhcmlvIGZlY2hlIGUgYWJyYSBvIG5hdmVnYWRvclxuICAgICAqIGRlbnRybyBkbyB0ZW1wbyBkZSBzZXNzw6NvIHNlamEgcG9zc8OtdmVsIHJlY3VwZXJhciBvIHRva2VuIGF1dGVudGljYWRvLlxuICAgICAqXG4gICAgICogTWFudMOpbSBhIHZhcmnDoXZlbCBhdXRoLmN1cnJlbnRVc2VyIHBhcmEgZmFjaWxpdGFyIG8gYWNlc3NvIGFvIHVzdcOhcmlvIGxvZ2FkbyBlbSB0b2RhIGEgYXBsaWNhw6fDo29cbiAgICAgKlxuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IHVzZXIgVXN1w6FyaW8gYSBzZXIgYXR1YWxpemFkby4gQ2FzbyBzZWphIHBhc3NhZG8gbnVsbCBsaW1wYVxuICAgICAqIHRvZGFzIGFzIGluZm9ybWHDp8O1ZXMgZG8gdXN1w6FyaW8gY29ycmVudGUuXG4gICAgICovXG4gICAgZnVuY3Rpb24gdXBkYXRlQ3VycmVudFVzZXIodXNlcikge1xuICAgICAgdmFyIGRlZmVycmVkID0gJHEuZGVmZXIoKTtcblxuICAgICAgaWYgKHVzZXIpIHtcbiAgICAgICAgdXNlciA9IGFuZ3VsYXIubWVyZ2UobmV3IFVzZXJzU2VydmljZSgpLCB1c2VyKTtcblxuICAgICAgICB2YXIganNvblVzZXIgPSBhbmd1bGFyLnRvSnNvbih1c2VyKTtcblxuICAgICAgICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbSgndXNlcicsIGpzb25Vc2VyKTtcbiAgICAgICAgYXV0aC5jdXJyZW50VXNlciA9IHVzZXI7XG5cbiAgICAgICAgZGVmZXJyZWQucmVzb2x2ZSh1c2VyKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKCd1c2VyJyk7XG4gICAgICAgIGF1dGguY3VycmVudFVzZXIgPSBudWxsO1xuICAgICAgICBhdXRoLmNsZWFyVG9rZW4oKTtcblxuICAgICAgICBkZWZlcnJlZC5yZWplY3QoKTtcbiAgICAgIH1cblxuICAgICAgcmV0dXJuIGRlZmVycmVkLnByb21pc2U7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhbGl6YSBvIGxvZ2luIGRvIHVzdcOhcmlvXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gY3JlZGVudGlhbHMgRW1haWwgZSBTZW5oYSBkbyB1c3XDoXJpb1xuICAgICAqIEByZXR1cm5zIHtwcm9taXNlfSBVbWEgcHJvbWlzZSBjb20gbyByZXN1bHRhZG8gZG8gY2hhbWFkYSBubyBiYWNrZW5kXG4gICAgICovXG4gICAgZnVuY3Rpb24gbG9naW4oY3JlZGVudGlhbHMpIHtcbiAgICAgIHZhciBkZWZlcnJlZCA9ICRxLmRlZmVyKCk7XG5cbiAgICAgICRodHRwLnBvc3QoR2xvYmFsLmFwaVBhdGggKyAnL2F1dGhlbnRpY2F0ZScsIGNyZWRlbnRpYWxzKVxuICAgICAgICAudGhlbihmdW5jdGlvbihyZXNwb25zZSkge1xuICAgICAgICAgIGF1dGguc2V0VG9rZW4ocmVzcG9uc2UuZGF0YS50b2tlbik7XG5cbiAgICAgICAgICByZXR1cm4gJGh0dHAuZ2V0KEdsb2JhbC5hcGlQYXRoICsgJy9hdXRoZW50aWNhdGUvdXNlcicpO1xuICAgICAgICB9KVxuICAgICAgICAudGhlbihmdW5jdGlvbihyZXNwb25zZSkge1xuICAgICAgICAgIGF1dGgudXBkYXRlQ3VycmVudFVzZXIocmVzcG9uc2UuZGF0YS51c2VyKTtcblxuICAgICAgICAgIGRlZmVycmVkLnJlc29sdmUoKTtcbiAgICAgICAgfSwgZnVuY3Rpb24oZXJyb3IpIHtcbiAgICAgICAgICBhdXRoLmxvZ291dCgpO1xuXG4gICAgICAgICAgZGVmZXJyZWQucmVqZWN0KGVycm9yKTtcbiAgICAgICAgfSk7XG5cbiAgICAgIHJldHVybiBkZWZlcnJlZC5wcm9taXNlO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIERlc2xvZ2Egb3MgdXN1w6FyaW9zLiBDb21vIG7Do28gdGVuIG5lbmh1bWEgaW5mb3JtYcOnw6NvIG5hIHNlc3PDo28gZG8gc2Vydmlkb3JcbiAgICAgKiBlIHVtIHRva2VuIHVtYSB2ZXogZ2VyYWRvIG7Do28gcG9kZSwgcG9yIHBhZHLDo28sIHNlciBpbnZhbGlkYWRvIGFudGVzIGRvIHNldSB0ZW1wbyBkZSBleHBpcmHDp8OjbyxcbiAgICAgKiBzb21lbnRlIGFwYWdhbW9zIG9zIGRhZG9zIGRvIHVzdcOhcmlvIGUgbyB0b2tlbiBkbyBuYXZlZ2Fkb3IgcGFyYSBlZmV0aXZhciBvIGxvZ291dC5cbiAgICAgKlxuICAgICAqIEByZXR1cm5zIHtwcm9taXNlfSBVbWEgcHJvbWlzZSBjb20gbyByZXN1bHRhZG8gZGEgb3BlcmHDp8Ojb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGxvZ291dCgpIHtcbiAgICAgIHZhciBkZWZlcnJlZCA9ICRxLmRlZmVyKCk7XG5cbiAgICAgIGF1dGgudXBkYXRlQ3VycmVudFVzZXIobnVsbCk7XG4gICAgICBkZWZlcnJlZC5yZXNvbHZlKCk7XG5cbiAgICAgIHJldHVybiBkZWZlcnJlZC5wcm9taXNlO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEVudmlhIHVtIGVtYWlsIHBhcmEgcmVjdXBlcmHDp8OjbyBkZSBzZW5oYVxuICAgICAqIEBwYXJhbSB7T2JqZWN0fSByZXNldERhdGEgLSBPYmpldG8gY29udGVuZG8gbyBlbWFpbFxuICAgICAqIEByZXR1cm4ge1Byb21pc2V9IC0gUmV0b3JuYSB1bWEgcHJvbWlzZSBwYXJhIHNlciByZXNvbHZpZGFcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBzZW5kRW1haWxSZXNldFBhc3N3b3JkKHJlc2V0RGF0YSkge1xuICAgICAgdmFyIGRlZmVycmVkID0gJHEuZGVmZXIoKTtcblxuICAgICAgJGh0dHAucG9zdChHbG9iYWwuYXBpUGF0aCArICcvcGFzc3dvcmQvZW1haWwnLCByZXNldERhdGEpXG4gICAgICAgIC50aGVuKGZ1bmN0aW9uKHJlc3BvbnNlKSB7XG4gICAgICAgICAgZGVmZXJyZWQucmVzb2x2ZShyZXNwb25zZS5kYXRhKTtcbiAgICAgICAgfSwgZnVuY3Rpb24oZXJyb3IpIHtcbiAgICAgICAgICBkZWZlcnJlZC5yZWplY3QoZXJyb3IpO1xuICAgICAgICB9KTtcblxuICAgICAgcmV0dXJuIGRlZmVycmVkLnByb21pc2U7XG4gICAgfVxuXG4gICAgcmV0dXJuIGF1dGg7XG4gIH1cblxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnRyb2xsZXIoJ0xvZ2luQ29udHJvbGxlcicsIExvZ2luQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBMb2dpbkNvbnRyb2xsZXIoJHN0YXRlLCBBdXRoLCBHbG9iYWwsIFByRGlhbG9nKSB7XG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIHZtLmxvZ2luID0gbG9naW47XG4gICAgdm0ub3BlbkRpYWxvZ1Jlc2V0UGFzcyA9IG9wZW5EaWFsb2dSZXNldFBhc3M7XG4gICAgdm0ub3BlbkRpYWxvZ1NpZ25VcCA9IG9wZW5EaWFsb2dTaWduVXA7XG5cbiAgICBhY3RpdmF0ZSgpO1xuXG4gICAgZnVuY3Rpb24gYWN0aXZhdGUoKSB7XG4gICAgICB2bS5jcmVkZW50aWFscyA9IHt9O1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGxvZ2luKCkge1xuICAgICAgdmFyIGNyZWRlbnRpYWxzID0ge1xuICAgICAgICBlbWFpbDogdm0uY3JlZGVudGlhbHMuZW1haWwsXG4gICAgICAgIHBhc3N3b3JkOiB2bS5jcmVkZW50aWFscy5wYXNzd29yZFxuICAgICAgfTtcblxuICAgICAgQXV0aC5sb2dpbihjcmVkZW50aWFscykudGhlbihmdW5jdGlvbigpIHtcbiAgICAgICAgJHN0YXRlLmdvKEdsb2JhbC5ob21lU3RhdGUpO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogRXhpYmUgbyBkaWFsb2cgcGFyYSByZWN1cGVyYcOnw6NvIGRlIHNlbmhhXG4gICAgICovXG4gICAgZnVuY3Rpb24gb3BlbkRpYWxvZ1Jlc2V0UGFzcygpIHtcbiAgICAgIHZhciBjb25maWcgPSB7XG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvYXV0aC9zZW5kLXJlc2V0LWRpYWxvZy5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ1Bhc3N3b3JkQ29udHJvbGxlciBhcyBwYXNzQ3RybCcsXG4gICAgICAgIGhhc0JhY2tkcm9wOiB0cnVlXG4gICAgICB9XG5cbiAgICAgIFByRGlhbG9nLmN1c3RvbShjb25maWcpO1xuICAgIH1cbiAgICAvKipcbiAgICAgKiBFeGliZSBvIGRpYWxvZyBwYXJhIHJlY3VwZXJhw6fDo28gZGUgc2VuaGFcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBvcGVuRGlhbG9nU2lnblVwKCkge1xuICAgICAgdmFyIGNvbmZpZyA9IHtcbiAgICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy91c2Vycy91c2VyLWZvcm0uaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdVc2Vyc0NvbnRyb2xsZXIgYXMgdXNlcnNDdHJsJyxcbiAgICAgICAgaGFzQmFja2Ryb3A6IHRydWVcbiAgICAgIH1cblxuICAgICAgUHJEaWFsb2cuY3VzdG9tKGNvbmZpZyk7XG4gICAgfVxuXG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb250cm9sbGVyKCdQYXNzd29yZENvbnRyb2xsZXInLCBQYXNzd29yZENvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gUGFzc3dvcmRDb250cm9sbGVyKEdsb2JhbCwgJHN0YXRlUGFyYW1zLCAkaHR0cCwgJHRpbWVvdXQsICRzdGF0ZSwgLy8gTk9TT05BUlxuICAgIFByVG9hc3QsIFByRGlhbG9nLCBBdXRoLCAkdHJhbnNsYXRlKSB7XG5cbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0uc2VuZFJlc2V0ID0gc2VuZFJlc2V0O1xuICAgIHZtLmNsb3NlRGlhbG9nID0gY2xvc2VEaWFsb2c7XG4gICAgdm0uY2xlYW5Gb3JtID0gY2xlYW5Gb3JtO1xuICAgIHZtLnNlbmRFbWFpbFJlc2V0UGFzc3dvcmQgPSBzZW5kRW1haWxSZXNldFBhc3N3b3JkO1xuXG4gICAgYWN0aXZhdGUoKTtcblxuICAgIGZ1bmN0aW9uIGFjdGl2YXRlKCkge1xuICAgICAgdm0ucmVzZXQgPSB7IGVtYWlsOiAnJywgdG9rZW46ICRzdGF0ZVBhcmFtcy50b2tlbiB9O1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWxpemEgYSBhbHRlcmHDp8OjbyBkYSBzZW5oYSBkbyB1c3XDoXJpbyBlIG8gcmVkaXJlY2lvbmEgcGFyYSBhIHRlbGEgZGUgbG9naW5cbiAgICAgKi9cbiAgICBmdW5jdGlvbiBzZW5kUmVzZXQoKSB7XG4gICAgICAkaHR0cC5wb3N0KEdsb2JhbC5hcGlQYXRoICsgJy9wYXNzd29yZC9yZXNldCcsIHZtLnJlc2V0KVxuICAgICAgICAudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgUHJUb2FzdC5zdWNjZXNzKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMub3BlcmF0aW9uU3VjY2VzcycpKTtcbiAgICAgICAgICAkdGltZW91dChmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAkc3RhdGUuZ28oR2xvYmFsLmxvZ2luU3RhdGUpO1xuICAgICAgICAgIH0sIDE1MDApO1xuICAgICAgICB9LCBmdW5jdGlvbiAoZXJyb3IpIHtcbiAgICAgICAgICBpZiAoZXJyb3Iuc3RhdHVzICE9PSA0MDAgJiYgZXJyb3Iuc3RhdHVzICE9PSA1MDApIHtcbiAgICAgICAgICAgIHZhciBtc2cgPSAnJztcblxuICAgICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCBlcnJvci5kYXRhLnBhc3N3b3JkLmxlbmd0aDsgaSsrKSB7XG4gICAgICAgICAgICAgIG1zZyArPSBlcnJvci5kYXRhLnBhc3N3b3JkW2ldICsgJzxicj4nO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgUHJUb2FzdC5lcnJvcihtc2cudG9VcHBlckNhc2UoKSk7XG4gICAgICAgICAgfVxuICAgICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBFbnZpYSB1bSBlbWFpbCBkZSByZWN1cGVyYcOnw6NvIGRlIHNlbmhhIGNvbSBvIHRva2VuIGRvIHVzdcOhcmlvXG4gICAgICovXG4gICAgZnVuY3Rpb24gc2VuZEVtYWlsUmVzZXRQYXNzd29yZCgpIHtcblxuICAgICAgaWYgKHZtLnJlc2V0LmVtYWlsID09PSAnJykge1xuICAgICAgICBQclRvYXN0LmVycm9yKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMudmFsaWRhdGUuZmllbGRSZXF1aXJlZCcsIHsgZmllbGQ6ICdlbWFpbCcgfSkpO1xuICAgICAgICByZXR1cm47XG4gICAgICB9XG5cbiAgICAgIEF1dGguc2VuZEVtYWlsUmVzZXRQYXNzd29yZCh2bS5yZXNldCkudGhlbihmdW5jdGlvbiAoZGF0YSkge1xuICAgICAgICBQclRvYXN0LnN1Y2Nlc3MoZGF0YS5tZXNzYWdlKTtcblxuICAgICAgICB2bS5jbGVhbkZvcm0oKTtcbiAgICAgICAgdm0uY2xvc2VEaWFsb2coKTtcbiAgICAgIH0sIGZ1bmN0aW9uIChlcnJvcikge1xuICAgICAgICBpZiAoZXJyb3IuZGF0YS5lbWFpbCAmJiBlcnJvci5kYXRhLmVtYWlsLmxlbmd0aCA+IDApIHtcbiAgICAgICAgICB2YXIgbXNnID0gJyc7XG5cbiAgICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IGVycm9yLmRhdGEuZW1haWwubGVuZ3RoOyBpKyspIHtcbiAgICAgICAgICAgIG1zZyArPSBlcnJvci5kYXRhLmVtYWlsW2ldICsgJzxicj4nO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIFByVG9hc3QuZXJyb3IobXNnKTtcbiAgICAgICAgfVxuICAgICAgfSk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gY2xvc2VEaWFsb2coKSB7XG4gICAgICBQckRpYWxvZy5jbG9zZSgpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGNsZWFuRm9ybSgpIHtcbiAgICAgIHZtLnJlc2V0LmVtYWlsID0gJyc7XG4gICAgfVxuXG4gIH1cblxufSkoKTtcbiIsIi8qZXNsaW50IGFuZ3VsYXIvZmlsZS1uYW1lOiAwKi9cbihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5mYWN0b3J5KCdzZXJ2aWNlRmFjdG9yeScsIHNlcnZpY2VGYWN0b3J5KTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8qKlxuICAgKiBNYWlzIGluZm9ybWHDp8O1ZXM6XG4gICAqIGh0dHBzOi8vZ2l0aHViLmNvbS9zd2ltbGFuZS9hbmd1bGFyLW1vZGVsLWZhY3Rvcnkvd2lraS9BUElcbiAgICovXG4gIGZ1bmN0aW9uIHNlcnZpY2VGYWN0b3J5KCRtb2RlbEZhY3RvcnkpIHtcbiAgICByZXR1cm4gZnVuY3Rpb24odXJsLCBvcHRpb25zKSB7XG4gICAgICB2YXIgbW9kZWw7XG4gICAgICB2YXIgZGVmYXVsdE9wdGlvbnMgPSB7XG4gICAgICAgIGFjdGlvbnM6IHtcbiAgICAgICAgICAvKipcbiAgICAgICAgICAgKiBTZXJ2acOnbyBjb211bSBwYXJhIHJlYWxpemFyIGJ1c2NhIGNvbSBwYWdpbmHDp8Ojb1xuICAgICAgICAgICAqIE8gbWVzbW8gZXNwZXJhIHF1ZSBzZWphIHJldG9ybmFkbyB1bSBvYmpldG8gY29tIGl0ZW1zIGUgdG90YWxcbiAgICAgICAgICAgKi9cbiAgICAgICAgICBwYWdpbmF0ZToge1xuICAgICAgICAgICAgbWV0aG9kOiAnR0VUJyxcbiAgICAgICAgICAgIGlzQXJyYXk6IGZhbHNlLFxuICAgICAgICAgICAgd3JhcDogZmFsc2UsXG4gICAgICAgICAgICBhZnRlclJlcXVlc3Q6IGZ1bmN0aW9uKHJlc3BvbnNlKSB7XG4gICAgICAgICAgICAgIGlmIChyZXNwb25zZVsnaXRlbXMnXSkge1xuICAgICAgICAgICAgICAgIHJlc3BvbnNlWydpdGVtcyddID0gbW9kZWwuTGlzdChyZXNwb25zZVsnaXRlbXMnXSk7XG4gICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICByZXR1cm4gcmVzcG9uc2U7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICB9XG5cbiAgICAgIG1vZGVsID0gJG1vZGVsRmFjdG9yeSh1cmwsIGFuZ3VsYXIubWVyZ2UoZGVmYXVsdE9wdGlvbnMsIG9wdGlvbnMpKVxuXG4gICAgICByZXR1cm4gbW9kZWw7XG4gICAgfVxuICB9XG59KSgpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29udHJvbGxlcignQ1JVRENvbnRyb2xsZXInLCBDUlVEQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvKipcbiAgICogQ29udHJvbGFkb3IgQmFzZSBxdWUgaW1wbGVtZW50YSB0b2RhcyBhcyBmdW7Dp8O1ZXMgcGFkcsO1ZXMgZGUgdW0gQ1JVRFxuICAgKlxuICAgKiBBw6fDtWVzIGltcGxlbWVudGFkYXNcbiAgICogYWN0aXZhdGUoKVxuICAgKiBzZWFyY2gocGFnZSlcbiAgICogZWRpdChyZXNvdXJjZSlcbiAgICogc2F2ZSgpXG4gICAqIHJlbW92ZShyZXNvdXJjZSlcbiAgICogZ29Ubyh2aWV3TmFtZSlcbiAgICogY2xlYW5Gb3JtKClcbiAgICpcbiAgICogR2F0aWxob3NcbiAgICpcbiAgICogb25BY3RpdmF0ZSgpXG4gICAqIGFwcGx5RmlsdGVycyhkZWZhdWx0UXVlcnlGaWx0ZXJzKVxuICAgKiBiZWZvcmVTZWFyY2gocGFnZSkgLy9yZXRvcm5hbmRvIGZhbHNlIGNhbmNlbGEgbyBmbHV4b1xuICAgKiBhZnRlclNlYXJjaChyZXNwb25zZSlcbiAgICogYmVmb3JlQ2xlYW4gLy9yZXRvcm5hbmRvIGZhbHNlIGNhbmNlbGEgbyBmbHV4b1xuICAgKiBhZnRlckNsZWFuKClcbiAgICogYmVmb3JlU2F2ZSgpIC8vcmV0b3JuYW5kbyBmYWxzZSBjYW5jZWxhIG8gZmx1eG9cbiAgICogYWZ0ZXJTYXZlKHJlc291cmNlKVxuICAgKiBvblNhdmVFcnJvcihlcnJvcilcbiAgICogYmVmb3JlUmVtb3ZlKHJlc291cmNlKSAvL3JldG9ybmFuZG8gZmFsc2UgY2FuY2VsYSBvIGZsdXhvXG4gICAqIGFmdGVyUmVtb3ZlKHJlc291cmNlKVxuICAgKlxuICAgKiBAcGFyYW0ge2FueX0gdm0gaW5zdGFuY2lhIGRvIGNvbnRyb2xsZXIgZmlsaG9cbiAgICogQHBhcmFtIHthbnl9IG1vZGVsU2VydmljZSBzZXJ2acOnbyBkbyBtb2RlbCBxdWUgdmFpIHNlciB1dGlsaXphZG9cbiAgICogQHBhcmFtIHthbnl9IG9wdGlvbnMgb3DDp8O1ZXMgcGFyYSBzb2JyZWVzY3JldmVyIGNvbXBvcnRhbWVudG9zIHBhZHLDtWVzXG4gICAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBDUlVEQ29udHJvbGxlcih2bSwgbW9kZWxTZXJ2aWNlLCBvcHRpb25zLCBQclRvYXN0LCBQclBhZ2luYXRpb24sIC8vIE5PU09OQVJcbiAgICBQckRpYWxvZywgJHRyYW5zbGF0ZSkge1xuXG4gICAgLy9GdW5jdGlvbnMgQmxvY2tcbiAgICB2bS5zZWFyY2ggPSBzZWFyY2g7XG4gICAgdm0ucGFnaW5hdGVTZWFyY2ggPSBwYWdpbmF0ZVNlYXJjaDtcbiAgICB2bS5ub3JtYWxTZWFyY2ggPSBub3JtYWxTZWFyY2g7XG4gICAgdm0uZWRpdCA9IGVkaXQ7XG4gICAgdm0uc2F2ZSA9IHNhdmU7XG4gICAgdm0ucmVtb3ZlID0gcmVtb3ZlO1xuICAgIHZtLmdvVG8gPSBnb1RvO1xuICAgIHZtLmNsZWFuRm9ybSA9IGNsZWFuRm9ybTtcblxuICAgIGFjdGl2YXRlKCk7XG5cbiAgICAvKipcbiAgICAgKiBQcmVwYXJhIG8gY29udHJvbGFkb3JcbiAgICAgKiBGYXogbyBtZXJnZSBkYXMgb3DDp8O1ZXNcbiAgICAgKiBJbmljaWFsaXphIG8gcmVjdXJzb1xuICAgICAqIEluaWNpYWxpemEgbyBvYmpldG8gcGFnaW5hZG9yIGUgcmVhbGl6YSBhIHBlc3F1aXNhXG4gICAgICovXG4gICAgZnVuY3Rpb24gYWN0aXZhdGUoKSB7XG4gICAgICB2bS5kZWZhdWx0T3B0aW9ucyA9IHtcbiAgICAgICAgcmVkaXJlY3RBZnRlclNhdmU6IHRydWUsXG4gICAgICAgIHNlYXJjaE9uSW5pdDogdHJ1ZSxcbiAgICAgICAgcGVyUGFnZTogOCxcbiAgICAgICAgc2tpcFBhZ2luYXRpb246IGZhbHNlXG4gICAgICB9XG5cbiAgICAgIGFuZ3VsYXIubWVyZ2Uodm0uZGVmYXVsdE9wdGlvbnMsIG9wdGlvbnMpO1xuXG4gICAgICB2bS52aWV3Rm9ybSA9IGZhbHNlO1xuICAgICAgdm0ucmVzb3VyY2UgPSBuZXcgbW9kZWxTZXJ2aWNlKCk7XG5cbiAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0ub25BY3RpdmF0ZSkpIHZtLm9uQWN0aXZhdGUoKTtcblxuICAgICAgdm0ucGFnaW5hdG9yID0gUHJQYWdpbmF0aW9uLmdldEluc3RhbmNlKHZtLnNlYXJjaCwgdm0uZGVmYXVsdE9wdGlvbnMucGVyUGFnZSk7XG5cbiAgICAgIGlmICh2bS5kZWZhdWx0T3B0aW9ucy5zZWFyY2hPbkluaXQpIHZtLnNlYXJjaCgpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWxpemEgYSBwZXNxdWlzYVxuICAgICAqIFZlcmlmaWNhIHF1YWwgZGFzIGZ1bsOnw7VlcyBkZSBwZXNxdWlzYSBkZXZlIHNlciByZWFsaXphZGEuXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gcGFnZSBww6FnaW5hIHF1ZSBkZXZlIHNlciBjYXJyZWdhZGFcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBzZWFyY2gocGFnZSkge1xuICAgICAgKHZtLmRlZmF1bHRPcHRpb25zLnNraXBQYWdpbmF0aW9uKSA/IG5vcm1hbFNlYXJjaCgpIDogcGFnaW5hdGVTZWFyY2gocGFnZSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhbGl6YSBhIHBlc3F1aXNhIHBhZ2luYWRhIGNvbSBiYXNlIG5vcyBmaWx0cm9zIGRlZmluaWRvc1xuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IHBhZ2UgcMOhZ2luYSBxdWUgZGV2ZSBzZXIgY2FycmVnYWRhXG4gICAgICovXG4gICAgZnVuY3Rpb24gcGFnaW5hdGVTZWFyY2gocGFnZSkge1xuICAgICAgdm0ucGFnaW5hdG9yLmN1cnJlbnRQYWdlID0gKGFuZ3VsYXIuaXNEZWZpbmVkKHBhZ2UpKSA/IHBhZ2UgOiAxO1xuICAgICAgdm0uZGVmYXVsdFF1ZXJ5RmlsdGVycyA9IHsgcGFnZTogdm0ucGFnaW5hdG9yLmN1cnJlbnRQYWdlLCBwZXJQYWdlOiB2bS5wYWdpbmF0b3IucGVyUGFnZSB9O1xuXG4gICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmFwcGx5RmlsdGVycykpIHZtLmRlZmF1bHRRdWVyeUZpbHRlcnMgPSB2bS5hcHBseUZpbHRlcnModm0uZGVmYXVsdFF1ZXJ5RmlsdGVycyk7XG4gICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmJlZm9yZVNlYXJjaCkgJiYgdm0uYmVmb3JlU2VhcmNoKHBhZ2UpID09PSBmYWxzZSkgcmV0dXJuIGZhbHNlO1xuXG4gICAgICBtb2RlbFNlcnZpY2UucGFnaW5hdGUodm0uZGVmYXVsdFF1ZXJ5RmlsdGVycykudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgdm0ucGFnaW5hdG9yLmNhbGNOdW1iZXJPZlBhZ2VzKHJlc3BvbnNlLnRvdGFsKTtcbiAgICAgICAgdm0ucmVzb3VyY2VzID0gcmVzcG9uc2UuaXRlbXM7XG5cbiAgICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5hZnRlclNlYXJjaCkpIHZtLmFmdGVyU2VhcmNoKHJlc3BvbnNlKTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWxpemEgYSBwZXNxdWlzYSBjb20gYmFzZSBub3MgZmlsdHJvcyBkZWZpbmlkb3NcbiAgICAgKlxuICAgICAqL1xuICAgIGZ1bmN0aW9uIG5vcm1hbFNlYXJjaCgpIHtcbiAgICAgIHZtLmRlZmF1bHRRdWVyeUZpbHRlcnMgPSB7IH07XG5cbiAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYXBwbHlGaWx0ZXJzKSkgdm0uZGVmYXVsdFF1ZXJ5RmlsdGVycyA9IHZtLmFwcGx5RmlsdGVycyh2bS5kZWZhdWx0UXVlcnlGaWx0ZXJzKTtcbiAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYmVmb3JlU2VhcmNoKSAmJiB2bS5iZWZvcmVTZWFyY2goKSA9PT0gZmFsc2UpIHJldHVybiBmYWxzZTtcblxuICAgICAgbW9kZWxTZXJ2aWNlLnF1ZXJ5KHZtLmRlZmF1bHRRdWVyeUZpbHRlcnMpLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgIHZtLnJlc291cmNlcyA9IHJlc3BvbnNlO1xuXG4gICAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYWZ0ZXJTZWFyY2gpKSB2bS5hZnRlclNlYXJjaChyZXNwb25zZSk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBMaW1wYSBvIGZvcm11bMOhcmlvXG4gICAgICovXG4gICAgZnVuY3Rpb24gY2xlYW5Gb3JtKGZvcm0pIHtcbiAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYmVmb3JlQ2xlYW4pICYmIHZtLmJlZm9yZUNsZWFuKCkgPT09IGZhbHNlKSByZXR1cm4gZmFsc2U7XG5cbiAgICAgIHZtLnJlc291cmNlID0gbmV3IG1vZGVsU2VydmljZSgpO1xuXG4gICAgICBpZiAoYW5ndWxhci5pc0RlZmluZWQoZm9ybSkpIHtcbiAgICAgICAgZm9ybS4kc2V0UHJpc3RpbmUoKTtcbiAgICAgICAgZm9ybS4kc2V0VW50b3VjaGVkKCk7XG4gICAgICB9XG5cbiAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYWZ0ZXJDbGVhbikpIHZtLmFmdGVyQ2xlYW4oKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDYXJyZWdhIG5vIGZvcm11bMOhcmlvIG8gcmVjdXJzbyBzZWxlY2lvbmFkbyBwYXJhIGVkacOnw6NvXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gcmVzb3VyY2UgcmVjdXJzbyBzZWxlY2lvbmFkb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGVkaXQocmVzb3VyY2UpIHtcbiAgICAgIHZtLmdvVG8oJ2Zvcm0nKTtcbiAgICAgIHZtLnJlc291cmNlID0gbmV3IGFuZ3VsYXIuY29weShyZXNvdXJjZSk7XG5cbiAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYWZ0ZXJFZGl0KSkgdm0uYWZ0ZXJFZGl0KCk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogU2FsdmEgb3UgYXR1YWxpemEgbyByZWN1cnNvIGNvcnJlbnRlIG5vIGZvcm11bMOhcmlvXG4gICAgICogTm8gY29tcG9ydGFtZW50byBwYWRyw6NvIHJlZGlyZWNpb25hIG8gdXN1w6FyaW8gcGFyYSB2aWV3IGRlIGxpc3RhZ2VtXG4gICAgICogZGVwb2lzIGRhIGV4ZWN1w6fDo29cbiAgICAgKlxuICAgICAqIEByZXR1cm5zXG4gICAgICovXG4gICAgZnVuY3Rpb24gc2F2ZShmb3JtKSB7XG4gICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmJlZm9yZVNhdmUpICYmIHZtLmJlZm9yZVNhdmUoKSA9PT0gZmFsc2UpIHJldHVybiBmYWxzZTtcblxuICAgICAgdm0ucmVzb3VyY2UuJHNhdmUoKS50aGVuKGZ1bmN0aW9uIChyZXNvdXJjZSkge1xuICAgICAgICB2bS5yZXNvdXJjZSA9IHJlc291cmNlO1xuXG4gICAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYWZ0ZXJTYXZlKSkgdm0uYWZ0ZXJTYXZlKHJlc291cmNlKTtcblxuICAgICAgICBpZiAodm0uZGVmYXVsdE9wdGlvbnMucmVkaXJlY3RBZnRlclNhdmUpIHtcbiAgICAgICAgICB2bS5jbGVhbkZvcm0oZm9ybSk7XG4gICAgICAgICAgdm0uc2VhcmNoKHZtLnBhZ2luYXRvci5jdXJyZW50UGFnZSk7XG4gICAgICAgICAgdm0uZ29UbygnbGlzdCcpO1xuICAgICAgICB9XG5cbiAgICAgICAgUHJUb2FzdC5zdWNjZXNzKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMuc2F2ZVN1Y2Nlc3MnKSk7XG5cbiAgICAgIH0sIGZ1bmN0aW9uIChyZXNwb25zZURhdGEpIHtcbiAgICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5vblNhdmVFcnJvcikpIHZtLm9uU2F2ZUVycm9yKHJlc3BvbnNlRGF0YSk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZW1vdmUgbyByZWN1cnNvIGluZm9ybWFkby5cbiAgICAgKiBBbnRlcyBleGliZSB1bSBkaWFsb2dvIGRlIGNvbmZpcm1hw6fDo29cbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSByZXNvdXJjZSByZWN1cnNvIGVzY29saGlkb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIHJlbW92ZShyZXNvdXJjZSkge1xuICAgICAgdmFyIGNvbmZpZyA9IHtcbiAgICAgICAgdGl0bGU6ICR0cmFuc2xhdGUuaW5zdGFudCgnZGlhbG9nLmNvbmZpcm1UaXRsZScpLFxuICAgICAgICBkZXNjcmlwdGlvbjogJHRyYW5zbGF0ZS5pbnN0YW50KCdkaWFsb2cuY29uZmlybURlc2NyaXB0aW9uJylcbiAgICAgIH1cblxuICAgICAgUHJEaWFsb2cuY29uZmlybShjb25maWcpLnRoZW4oZnVuY3Rpb24oKSB7XG4gICAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYmVmb3JlUmVtb3ZlKSAmJiB2bS5iZWZvcmVSZW1vdmUocmVzb3VyY2UpID09PSBmYWxzZSkgcmV0dXJuIGZhbHNlO1xuXG4gICAgICAgIHJlc291cmNlLiRkZXN0cm95KCkudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5hZnRlclJlbW92ZSkpIHZtLmFmdGVyUmVtb3ZlKHJlc291cmNlKTtcblxuICAgICAgICAgIHZtLnNlYXJjaCgpO1xuICAgICAgICAgIFByVG9hc3QuaW5mbygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnJlbW92ZVN1Y2Nlc3MnKSk7XG4gICAgICAgIH0pO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQWx0ZXJuYSBlbnRyZSBhIHZpZXcgZG8gZm9ybXVsw6FyaW8gZSBsaXN0YWdlbVxuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IHZpZXdOYW1lIG5vbWUgZGEgdmlld1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGdvVG8odmlld05hbWUpIHtcbiAgICAgIHZtLnZpZXdGb3JtID0gZmFsc2U7XG5cbiAgICAgIGlmICh2aWV3TmFtZSA9PT0gJ2Zvcm0nKSB7XG4gICAgICAgIHZtLmNsZWFuRm9ybSgpO1xuICAgICAgICB2bS52aWV3Rm9ybSA9IHRydWU7XG4gICAgICB9XG4gICAgfVxuICB9XG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqXG4gICAqIEFycXVpdm8gZGUgY29uZmlndXJhw6fDo28gY29tIGFzIHJvdGFzIGVzcGVjw61maWNhcyBkbyByZWN1cnNvIHVzZXJcbiAgICpcbiAgICogQHBhcmFtIHthbnl9ICRzdGF0ZVByb3ZpZGVyXG4gICAqIEBwYXJhbSB7YW55fSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlclxuICAgICAgLnN0YXRlKCdhcHAuZGluYW1pYy1xdWVyeScsIHtcbiAgICAgICAgdXJsOiAnL2NvbnN1bHRhcy1kaW5hbWljYXMnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL2RpbmFtaWMtcXVlcnlzL2RpbmFtaWMtcXVlcnlzLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnRGluYW1pY1F1ZXJ5c0NvbnRyb2xsZXIgYXMgZGluYW1pY1F1ZXJ5Q3RybCcsXG4gICAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiB0cnVlLCBuZWVkUHJvZmlsZTogWydhZG1pbiddIH1cbiAgICAgIH0pO1xuXG4gIH1cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmFjdG9yeSgnRGluYW1pY1F1ZXJ5U2VydmljZScsIERpbmFtaWNRdWVyeVNlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gRGluYW1pY1F1ZXJ5U2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHJldHVybiBzZXJ2aWNlRmFjdG9yeSgnZGluYW1pY1F1ZXJ5Jywge1xuICAgICAgLyoqXG4gICAgICAgKiBhw6fDo28gYWRpY2lvbmFkYSBwYXJhIHBlZ2FyIHVtYSBsaXN0YSBkZSBtb2RlbHMgZXhpc3RlbnRlcyBubyBzZXJ2aWRvclxuICAgICAgICovXG4gICAgICBhY3Rpb25zOiB7XG4gICAgICAgIGdldE1vZGVsczoge1xuICAgICAgICAgIG1ldGhvZDogJ0dFVCcsXG4gICAgICAgICAgdXJsOiAnbW9kZWxzJ1xuICAgICAgICB9XG4gICAgICB9LFxuICAgICAgaW5zdGFuY2U6IHtcbiAgICAgIH1cbiAgICB9KTtcbiAgfVxuXG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29udHJvbGxlcignRGluYW1pY1F1ZXJ5c0NvbnRyb2xsZXInLCBEaW5hbWljUXVlcnlzQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBEaW5hbWljUXVlcnlzQ29udHJvbGxlcigkY29udHJvbGxlciwgRGluYW1pY1F1ZXJ5U2VydmljZSwgbG9kYXNoLCBQclRvYXN0LCAvLyBOT1NPTkFSXG4gICAgJHRyYW5zbGF0ZSkge1xuXG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIC8vYWN0aW9uc1xuICAgIHZtLm9uQWN0aXZhdGUgPSBvbkFjdGl2YXRlO1xuICAgIHZtLmFwcGx5RmlsdGVycyA9IGFwcGx5RmlsdGVycztcbiAgICB2bS5sb2FkQXR0cmlidXRlcyA9IGxvYWRBdHRyaWJ1dGVzO1xuICAgIHZtLmxvYWRPcGVyYXRvcnMgPSBsb2FkT3BlcmF0b3JzO1xuICAgIHZtLmFkZEZpbHRlciA9IGFkZEZpbHRlcjtcbiAgICB2bS5hZnRlclNlYXJjaCA9IGFmdGVyU2VhcmNoO1xuICAgIHZtLnJ1bkZpbHRlciA9IHJ1bkZpbHRlcjtcbiAgICB2bS5lZGl0RmlsdGVyID0gZWRpdEZpbHRlcjtcbiAgICB2bS5sb2FkTW9kZWxzID0gbG9hZE1vZGVscztcbiAgICB2bS5yZW1vdmVGaWx0ZXIgPSByZW1vdmVGaWx0ZXI7XG4gICAgdm0uY2xlYXIgPSBjbGVhcjtcbiAgICB2bS5yZXN0YXJ0ID0gcmVzdGFydDtcblxuICAgIC8vaGVyZGEgbyBjb21wb3J0YW1lbnRvIGJhc2UgZG8gQ1JVRFxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHsgdm06IHZtLCBtb2RlbFNlcnZpY2U6IERpbmFtaWNRdWVyeVNlcnZpY2UsIG9wdGlvbnM6IHtcbiAgICAgIHNlYXJjaE9uSW5pdDogZmFsc2VcbiAgICB9IH0pO1xuXG4gICAgZnVuY3Rpb24gb25BY3RpdmF0ZSgpIHtcbiAgICAgIHZtLnJlc3RhcnQoKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBQcmVwYXJhIGUgYXBsaWNhIG9zIGZpbHRybyBxdWUgdsOjbyBzZXIgZW52aWFkb3MgcGFyYSBvIHNlcnZpw6dvXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gZGVmYXVsdFF1ZXJ5RmlsdGVyc1xuICAgICAqIEByZXR1cm5zXG4gICAgICovXG4gICAgZnVuY3Rpb24gYXBwbHlGaWx0ZXJzKGRlZmF1bHRRdWVyeUZpbHRlcnMpIHtcbiAgICAgIHZhciB3aGVyZSA9IHt9O1xuXG4gICAgICAvKipcbiAgICAgICAqIG8gc2VydmnDp28gZXNwZXJhIHVtIG9iamV0byBjb206XG4gICAgICAgKiAgbyBub21lIGRlIHVtIG1vZGVsXG4gICAgICAgKiAgdW1hIGxpc3RhIGRlIGZpbHRyb3NcbiAgICAgICAqL1xuICAgICAgaWYgKHZtLmFkZGVkRmlsdGVycy5sZW5ndGggPiAwKSB7XG4gICAgICAgIHZhciBhZGRlZEZpbHRlcnMgPSBhbmd1bGFyLmNvcHkodm0uYWRkZWRGaWx0ZXJzKTtcblxuICAgICAgICB3aGVyZS5tb2RlbCA9IHZtLmFkZGVkRmlsdGVyc1swXS5tb2RlbC5uYW1lO1xuXG4gICAgICAgIGZvciAodmFyIGluZGV4ID0gMDsgaW5kZXggPCBhZGRlZEZpbHRlcnMubGVuZ3RoOyBpbmRleCsrKSB7XG4gICAgICAgICAgdmFyIGZpbHRlciA9IGFkZGVkRmlsdGVyc1tpbmRleF07XG5cbiAgICAgICAgICBmaWx0ZXIubW9kZWwgPSBudWxsO1xuICAgICAgICAgIGZpbHRlci5hdHRyaWJ1dGUgPSBmaWx0ZXIuYXR0cmlidXRlLm5hbWU7XG4gICAgICAgICAgZmlsdGVyLm9wZXJhdG9yID0gZmlsdGVyLm9wZXJhdG9yLnZhbHVlO1xuICAgICAgICB9XG5cbiAgICAgICAgd2hlcmUuZmlsdGVycyA9IGFuZ3VsYXIudG9Kc29uKGFkZGVkRmlsdGVycyk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICB3aGVyZS5tb2RlbCA9IHZtLnF1ZXJ5RmlsdGVycy5tb2RlbC5uYW1lO1xuICAgICAgfVxuXG4gICAgICByZXR1cm4gYW5ndWxhci5leHRlbmQoZGVmYXVsdFF1ZXJ5RmlsdGVycywgd2hlcmUpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENhcnJlZ2EgdG9kb3Mgb3MgbW9kZWxzIGNyaWFkb3Mgbm8gc2Vydmlkb3IgY29tIHNldXMgYXRyaWJ1dG9zXG4gICAgICovXG4gICAgZnVuY3Rpb24gbG9hZE1vZGVscygpIHtcbiAgICAgIC8vUGVnYSB0b2RvcyBvcyBtb2RlbHMgZG8gc2VydmVyIGUgbW9udGEgdW1hIGxpc3RhIHBybyBDb21ib0JveFxuICAgICAgRGluYW1pY1F1ZXJ5U2VydmljZS5nZXRNb2RlbHMoKS50aGVuKGZ1bmN0aW9uKGRhdGEpIHtcbiAgICAgICAgdm0ubW9kZWxzID0gZGF0YTtcbiAgICAgICAgdm0ucXVlcnlGaWx0ZXJzLm1vZGVsID0gdm0ubW9kZWxzWzBdO1xuICAgICAgICB2bS5sb2FkQXR0cmlidXRlcygpO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ2FycmVnYSBvcyBhdHRyaWJ1dG9zIGRvIG1vZGVsIGVzY29saGlkb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGxvYWRBdHRyaWJ1dGVzKCkge1xuICAgICAgdm0uYXR0cmlidXRlcyA9IHZtLnF1ZXJ5RmlsdGVycy5tb2RlbC5hdHRyaWJ1dGVzO1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzLmF0dHJpYnV0ZSA9IHZtLmF0dHJpYnV0ZXNbMF07XG5cbiAgICAgIHZtLmxvYWRPcGVyYXRvcnMoKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDYXJyZWdhIG9zIG9wZXJhZG9yZXMgZXNwZWNpZmljb3MgcGFyYSBvIHRpcG8gZG8gYXRyaWJ1dG9cbiAgICAgKi9cbiAgICBmdW5jdGlvbiBsb2FkT3BlcmF0b3JzKCkge1xuICAgICAgdmFyIG9wZXJhdG9ycyA9IFtcbiAgICAgICAgeyB2YWx1ZTogJz0nLCBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KCd2aWV3cy5maWVsZHMucXVlcnlEaW5hbWljLm9wZXJhdG9ycy5lcXVhbHMnKSB9LFxuICAgICAgICB7IHZhbHVlOiAnPD4nLCBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KCd2aWV3cy5maWVsZHMucXVlcnlEaW5hbWljLm9wZXJhdG9ycy5kaWZlcmVudCcpIH1cbiAgICAgIF1cblxuICAgICAgaWYgKHZtLnF1ZXJ5RmlsdGVycy5hdHRyaWJ1dGUudHlwZS5pbmRleE9mKCd2YXJ5aW5nJykgIT09IC0xKSB7XG4gICAgICAgIG9wZXJhdG9ycy5wdXNoKHsgdmFsdWU6ICdoYXMnLFxuICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLmNvbnRlaW5zJykgfSk7XG4gICAgICAgIG9wZXJhdG9ycy5wdXNoKHsgdmFsdWU6ICdzdGFydFdpdGgnLFxuICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLnN0YXJ0V2l0aCcpIH0pO1xuICAgICAgICBvcGVyYXRvcnMucHVzaCh7IHZhbHVlOiAnZW5kV2l0aCcsXG4gICAgICAgICAgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudCgndmlld3MuZmllbGRzLnF1ZXJ5RGluYW1pYy5vcGVyYXRvcnMuZmluaXNoV2l0aCcpIH0pO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgb3BlcmF0b3JzLnB1c2goeyB2YWx1ZTogJz4nLFxuICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLmJpZ2dlclRoYW4nKSB9KTtcbiAgICAgICAgb3BlcmF0b3JzLnB1c2goeyB2YWx1ZTogJz49JyxcbiAgICAgICAgICBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KCd2aWV3cy5maWVsZHMucXVlcnlEaW5hbWljLm9wZXJhdG9ycy5lcXVhbHNPckJpZ2dlclRoYW4nKSB9KTtcbiAgICAgICAgb3BlcmF0b3JzLnB1c2goeyB2YWx1ZTogJzwnLFxuICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLmxlc3NUaGFuJykgfSk7XG4gICAgICAgIG9wZXJhdG9ycy5wdXNoKHsgdmFsdWU6ICc8PScsXG4gICAgICAgICAgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudCgndmlld3MuZmllbGRzLnF1ZXJ5RGluYW1pYy5vcGVyYXRvcnMuZXF1YWxzT3JMZXNzVGhhbicpIH0pO1xuICAgICAgfVxuXG4gICAgICB2bS5vcGVyYXRvcnMgPSBvcGVyYXRvcnM7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMub3BlcmF0b3IgPSB2bS5vcGVyYXRvcnNbMF07XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQWRpY2lvbmEvZWRpdGEgdW0gZmlsdHJvXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gZm9ybSBlbGVtZW50byBodG1sIGRvIGZvcm11bMOhcmlvIHBhcmEgdmFsaWRhw6fDtWVzXG4gICAgICovXG4gICAgZnVuY3Rpb24gYWRkRmlsdGVyKGZvcm0pIHtcbiAgICAgIGlmIChhbmd1bGFyLmlzVW5kZWZpbmVkKHZtLnF1ZXJ5RmlsdGVycy52YWx1ZSkgfHwgdm0ucXVlcnlGaWx0ZXJzLnZhbHVlID09PSAnJykge1xuICAgICAgICBQclRvYXN0LmVycm9yKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMudmFsaWRhdGUuZmllbGRSZXF1aXJlZCcsIHsgZmllbGQ6ICd2YWxvcicgfSkpO1xuICAgICAgICByZXR1cm47XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBpZiAodm0uaW5kZXggPCAwKSB7XG4gICAgICAgICAgdm0uYWRkZWRGaWx0ZXJzLnB1c2goYW5ndWxhci5jb3B5KHZtLnF1ZXJ5RmlsdGVycykpO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIHZtLmFkZGVkRmlsdGVyc1t2bS5pbmRleF0gPSBhbmd1bGFyLmNvcHkodm0ucXVlcnlGaWx0ZXJzKTtcbiAgICAgICAgICB2bS5pbmRleCA9IC0xO1xuICAgICAgICB9XG5cbiAgICAgICAgLy9yZWluaWNpYSBvIGZvcm11bMOhcmlvIGUgYXMgdmFsaWRhw6fDtWVzIGV4aXN0ZW50ZXNcbiAgICAgICAgdm0ucXVlcnlGaWx0ZXJzID0ge307XG4gICAgICAgIGZvcm0uJHNldFByaXN0aW5lKCk7XG4gICAgICAgIGZvcm0uJHNldFVudG91Y2hlZCgpO1xuICAgICAgfVxuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWxpemEgYSBwZXNxdWlzYSB0ZW5kbyBvcyBmaWx0cm9zIGNvbW8gcGFyw6JtZXRyb3NcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBydW5GaWx0ZXIoKSB7XG4gICAgICB2bS5zZWFyY2godm0ucGFnaW5hdG9yLmN1cnJlbnRQYWdlKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBHYXRpbGhvIGFjaW9uYWRvIGRlcG9pcyBkYSBwZXNxdWlzYSByZXNwb25zw6F2ZWwgcG9yIGlkZW50aWZpY2FyIG9zIGF0cmlidXRvc1xuICAgICAqIGNvbnRpZG9zIG5vcyBlbGVtZW50b3MgcmVzdWx0YW50ZXMgZGEgYnVzY2FcbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSBkYXRhIGRhZG9zIHJlZmVyZW50ZSBhbyByZXRvcm5vIGRhIHJlcXVpc2nDp8Ojb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGFmdGVyU2VhcmNoKGRhdGEpIHtcbiAgICAgIHZhciBrZXlzID0gKGRhdGEuaXRlbXMubGVuZ3RoID4gMCkgPyBPYmplY3Qua2V5cyhkYXRhLml0ZW1zWzBdKSA6IFtdO1xuXG4gICAgICAvL3JldGlyYSB0b2RvcyBvcyBhdHJpYnV0b3MgcXVlIGNvbWXDp2FtIGNvbSAkLlxuICAgICAgLy9Fc3NlcyBhdHJpYnV0b3Mgc8OjbyBhZGljaW9uYWRvcyBwZWxvIHNlcnZpw6dvIGUgbsOjbyBkZXZlIGFwYXJlY2VyIG5hIGxpc3RhZ2VtXG4gICAgICB2bS5rZXlzID0gbG9kYXNoLmZpbHRlcihrZXlzLCBmdW5jdGlvbihrZXkpIHtcbiAgICAgICAgcmV0dXJuICFsb2Rhc2guc3RhcnRzV2l0aChrZXksICckJyk7XG4gICAgICB9KVxuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENvbG9hY2Egbm8gZm9ybXVsw6FyaW8gbyBmaWx0cm8gZXNjb2xoaWRvIHBhcmEgZWRpw6fDo29cbiAgICAgKiBAcGFyYW0ge2FueX0gJGluZGV4IGluZGljZSBubyBhcnJheSBkbyBmaWx0cm8gZXNjb2xoaWRvXG4gICAgICovXG4gICAgZnVuY3Rpb24gZWRpdEZpbHRlcigkaW5kZXgpIHtcbiAgICAgIHZtLmluZGV4ID0gJGluZGV4O1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0gdm0uYWRkZWRGaWx0ZXJzWyRpbmRleF07XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVtb3ZlIG8gZmlsdHJvIGVzY29saGlkb1xuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9ICRpbmRleCBpbmRpY2Ugbm8gYXJyYXkgZG8gZmlsdHJvIGVzY29saGlkb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIHJlbW92ZUZpbHRlcigkaW5kZXgpIHtcbiAgICAgIHZtLmFkZGVkRmlsdGVycy5zcGxpY2UoJGluZGV4KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBMaW1wYSBvIGZvcm11bMOhcmlvIGNvcnJlbnRlXG4gICAgICovXG4gICAgZnVuY3Rpb24gY2xlYXIoKSB7XG4gICAgICAvL2d1YXJkYSBvIGluZGljZSBkbyByZWdpc3RybyBxdWUgZXN0w6Egc2VuZG8gZWRpdGFkb1xuICAgICAgdm0uaW5kZXggPSAtMTtcbiAgICAgIC8vdmluY3VsYWRvIGFvcyBjYW1wb3MgZG8gZm9ybXVsw6FyaW9cbiAgICAgIHZtLnF1ZXJ5RmlsdGVycyA9IHtcbiAgICAgIH07XG5cbiAgICAgIGlmICh2bS5tb2RlbHMpIHZtLnF1ZXJ5RmlsdGVycy5tb2RlbCA9IHZtLm1vZGVsc1swXTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWluaWNpYSBhIGNvbnN0cnXDp8OjbyBkYSBxdWVyeSBsaW1wYW5kbyB0dWRvXG4gICAgICpcbiAgICAgKi9cbiAgICBmdW5jdGlvbiByZXN0YXJ0KCkge1xuICAgICAgLy9ndWFyZGEgYXRyaWJ1dG9zIGRvIHJlc3VsdGFkbyBkYSBidXNjYSBjb3JyZW50ZVxuICAgICAgdm0ua2V5cyA9IFtdO1xuXG4gICAgICAvL2d1YXJkYSBvcyBmaWx0cm9zIGFkaWNpb25hZG9zXG4gICAgICB2bS5hZGRlZEZpbHRlcnMgPSBbXTtcbiAgICAgIHZtLmNsZWFyKCk7XG4gICAgICB2bS5sb2FkTW9kZWxzKCk7XG4gICAgfVxuXG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZhY3RvcnkoJ2xhbmd1YWdlTG9hZGVyJywgTGFuZ3VhZ2VMb2FkZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gTGFuZ3VhZ2VMb2FkZXIoJHEsIFN1cHBvcnRTZXJ2aWNlLCAkbG9nLCAkaW5qZWN0b3IpIHtcbiAgICB2YXIgc2VydmljZSA9IHRoaXM7XG5cbiAgICBzZXJ2aWNlLnRyYW5zbGF0ZSA9IGZ1bmN0aW9uKGxvY2FsZSkge1xuICAgICAgcmV0dXJuIHtcbiAgICAgICAgZ2xvYmFsOiAkaW5qZWN0b3IuZ2V0KGxvY2FsZSArICcuaTE4bi5nbG9iYWwnKSxcbiAgICAgICAgdmlld3M6ICRpbmplY3Rvci5nZXQobG9jYWxlICsgJy5pMThuLnZpZXdzJyksXG4gICAgICAgIGF0dHJpYnV0ZXM6ICRpbmplY3Rvci5nZXQobG9jYWxlICsgJy5pMThuLmF0dHJpYnV0ZXMnKSxcbiAgICAgICAgZGlhbG9nOiAkaW5qZWN0b3IuZ2V0KGxvY2FsZSArICcuaTE4bi5kaWFsb2cnKSxcbiAgICAgICAgbWVzc2FnZXM6ICRpbmplY3Rvci5nZXQobG9jYWxlICsgJy5pMThuLm1lc3NhZ2VzJyksXG4gICAgICAgIG1vZGVsczogJGluamVjdG9yLmdldChsb2NhbGUgKyAnLmkxOG4ubW9kZWxzJylcbiAgICAgIH07XG4gICAgfVxuXG4gICAgLy8gcmV0dXJuIGxvYWRlckZuXG4gICAgcmV0dXJuIGZ1bmN0aW9uKG9wdGlvbnMpIHtcbiAgICAgICRsb2cuaW5mbygnQ2FycmVnYW5kbyBvIGNvbnRldWRvIGRhIGxpbmd1YWdlbSAnICsgb3B0aW9ucy5rZXkpO1xuXG4gICAgICB2YXIgZGVmZXJyZWQgPSAkcS5kZWZlcigpO1xuXG4gICAgICAvL0NhcnJlZ2EgYXMgbGFuZ3MgcXVlIHByZWNpc2FtIGUgZXN0w6NvIG5vIHNlcnZpZG9yIHBhcmEgbsOjbyBwcmVjaXNhciByZXBldGlyIGFxdWlcbiAgICAgIFN1cHBvcnRTZXJ2aWNlLmxhbmdzKCkudGhlbihmdW5jdGlvbihsYW5ncykge1xuICAgICAgICAvL01lcmdlIGNvbSBvcyBsYW5ncyBkZWZpbmlkb3Mgbm8gc2Vydmlkb3JcbiAgICAgICAgdmFyIGRhdGEgPSBhbmd1bGFyLm1lcmdlKHNlcnZpY2UudHJhbnNsYXRlKG9wdGlvbnMua2V5KSwgbGFuZ3MpO1xuXG4gICAgICAgIHJldHVybiBkZWZlcnJlZC5yZXNvbHZlKGRhdGEpO1xuICAgICAgfSwgZnVuY3Rpb24oKSB7XG4gICAgICAgIHJldHVybiBkZWZlcnJlZC5yZXNvbHZlKHNlcnZpY2UudHJhbnNsYXRlKG9wdGlvbnMua2V5KSk7XG4gICAgICB9KTtcblxuICAgICAgcmV0dXJuIGRlZmVycmVkLnByb21pc2U7XG4gICAgfVxuICB9XG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5maWx0ZXIoJ3RBdHRyJywgdEF0dHIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gdEF0dHIoJGZpbHRlcikge1xuICAgIC8qKlxuICAgICAqIEZpbHRybyBwYXJhIHRyYWR1w6fDo28gZGUgdW0gYXRyaWJ1dG8gZGUgdW0gbW9kZWxcbiAgICAgKiBcbiAgICAgKiBAcGFyYW0ge2FueX0gbmFtZSBub21lIGRvIGF0cmlidXRvXG4gICAgICogQHJldHVybnMgbyBub21lIGRvIGF0cmlidXRvIHRyYWR1emlkbyBjYXNvIGVuY29udHJlIHNlIG7Do28gbyBub21lIHBhc3NhZG8gcG9yIHBhcmFtZXRyb1xuICAgICAqLyAgICBcbiAgICByZXR1cm4gZnVuY3Rpb24obmFtZSkge1xuICAgICAgdmFyIGtleSA9ICdhdHRyaWJ1dGVzLicgKyBuYW1lO1xuICAgICAgdmFyIHRyYW5zbGF0ZSA9ICRmaWx0ZXIoJ3RyYW5zbGF0ZScpKGtleSk7XG5cbiAgICAgIHJldHVybiAodHJhbnNsYXRlID09PSBrZXkpID8gbmFtZSA6IHRyYW5zbGF0ZTtcbiAgICB9XG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZpbHRlcigndEJyZWFkY3J1bWInLCB0QnJlYWRjcnVtYik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiB0QnJlYWRjcnVtYigkZmlsdGVyKSB7XG4gICAgLyoqXG4gICAgICogRmlsdHJvIHBhcmEgdHJhZHXDp8OjbyBkbyBicmVhZGNydW1iICh0aXR1bG8gZGEgdGVsYSBjb20gcmFzdHJlaW8pXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gaWQgY2hhdmUgY29tIG8gbm9tZSBkbyBzdGF0ZSByZWZlcmVudGUgdGVsYVxuICAgICAqIEByZXR1cm5zIGEgdHJhZHXDp8OjbyBjYXNvIGVuY29udHJlIHNlIG7Do28gbyBpZCBwYXNzYWRvIHBvciBwYXJhbWV0cm9cbiAgICAgKi9cbiAgICByZXR1cm4gZnVuY3Rpb24oaWQpIHtcbiAgICAgIC8vcGVnYSBhIHNlZ3VuZGEgcGFydGUgZG8gbm9tZSBkbyBzdGF0ZSwgcmV0aXJhbmRvIGEgcGFydGUgYWJzdHJhdGEgKGFwcC4pXG4gICAgICB2YXIga2V5ID0gJ3ZpZXdzLmJyZWFkY3J1bWJzLicgKyBpZC5zcGxpdCgnLicpWzFdO1xuICAgICAgdmFyIHRyYW5zbGF0ZSA9ICRmaWx0ZXIoJ3RyYW5zbGF0ZScpKGtleSk7XG5cbiAgICAgIHJldHVybiAodHJhbnNsYXRlID09PSBrZXkpID8gaWQgOiB0cmFuc2xhdGU7XG4gICAgfVxuICB9XG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5maWx0ZXIoJ3RNb2RlbCcsIHRNb2RlbCk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiB0TW9kZWwoJGZpbHRlcikge1xuICAgIC8qKlxuICAgICAqIEZpbHRybyBwYXJhIHRyYWR1w6fDo28gZGUgdW0gYXRyaWJ1dG8gZGUgdW0gbW9kZWxcbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSBuYW1lIG5vbWUgZG8gYXRyaWJ1dG9cbiAgICAgKiBAcmV0dXJucyBvIG5vbWUgZG8gYXRyaWJ1dG8gdHJhZHV6aWRvIGNhc28gZW5jb250cmUgc2UgbsOjbyBvIG5vbWUgcGFzc2FkbyBwb3IgcGFyYW1ldHJvXG4gICAgICovXG4gICAgcmV0dXJuIGZ1bmN0aW9uKG5hbWUpIHtcbiAgICAgIHZhciBrZXkgPSAnbW9kZWxzLicgKyBuYW1lLnRvTG93ZXJDYXNlKCk7XG4gICAgICB2YXIgdHJhbnNsYXRlID0gJGZpbHRlcigndHJhbnNsYXRlJykoa2V5KTtcblxuICAgICAgcmV0dXJuICh0cmFuc2xhdGUgPT09IGtleSkgPyBuYW1lIDogdHJhbnNsYXRlO1xuICAgIH1cbiAgfVxuXG59KSgpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLnJ1bihhdXRoZW50aWNhdGlvbkxpc3RlbmVyKTtcblxuICAvKipcbiAgICogTGlzdGVuIGFsbCBzdGF0ZSAocGFnZSkgY2hhbmdlcy4gRXZlcnkgdGltZSBhIHN0YXRlIGNoYW5nZSBuZWVkIHRvIHZlcmlmeSB0aGUgdXNlciBpcyBhdXRoZW50aWNhdGVkIG9yIG5vdCB0b1xuICAgKiByZWRpcmVjdCB0byBjb3JyZWN0IHBhZ2UuIFdoZW4gYSB1c2VyIGNsb3NlIHRoZSBicm93c2VyIHdpdGhvdXQgbG9nb3V0LCB3aGVuIGhpbSByZW9wZW4gdGhlIGJyb3dzZXIgdGhpcyBldmVudFxuICAgKiByZWF1dGhlbnRpY2F0ZSB0aGUgdXNlciB3aXRoIHRoZSBwZXJzaXN0ZW50IHRva2VuIG9mIHRoZSBsb2NhbCBzdG9yYWdlLlxuICAgKlxuICAgKiBXZSBkb24ndCBjaGVjayBpZiB0aGUgdG9rZW4gaXMgZXhwaXJlZCBvciBub3QgaW4gdGhlIHBhZ2UgY2hhbmdlLCBiZWNhdXNlIGlzIGdlbmVyYXRlIGFuIHVuZWNlc3Nhcnkgb3ZlcmhlYWQuXG4gICAqIElmIHRoZSB0b2tlbiBpcyBleHBpcmVkIHdoZW4gdGhlIHVzZXIgdHJ5IHRvIGNhbGwgdGhlIGZpcnN0IGFwaSB0byBnZXQgZGF0YSwgaGltIHdpbGwgYmUgbG9nb2ZmIGFuZCByZWRpcmVjdFxuICAgKiB0byBsb2dpbiBwYWdlLlxuICAgKlxuICAgKiBAcGFyYW0gJHJvb3RTY29wZVxuICAgKiBAcGFyYW0gJHN0YXRlXG4gICAqIEBwYXJhbSAkc3RhdGVQYXJhbXNcbiAgICogQHBhcmFtIEF1dGhcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gYXV0aGVudGljYXRpb25MaXN0ZW5lcigkcm9vdFNjb3BlLCAkc3RhdGUsIEdsb2JhbCwgQXV0aCwgUHJUb2FzdCwgLy8gTk9TT05BUlxuICAgICR0cmFuc2xhdGUpIHtcblxuICAgIC8vb25seSB3aGVuIGFwcGxpY2F0aW9uIHN0YXJ0IGNoZWNrIGlmIHRoZSBleGlzdGVudCB0b2tlbiBzdGlsbCB2YWxpZFxuICAgIEF1dGgucmVtb3RlVmFsaWRhdGVUb2tlbigpLnRoZW4oZnVuY3Rpb24oKSB7XG4gICAgICAvL2lmIHRoZSB0b2tlbiBpcyB2YWxpZCBjaGVjayBpZiBleGlzdHMgdGhlIHVzZXIgYmVjYXVzZSB0aGUgYnJvd3NlciBjb3VsZCBiZSBjbG9zZWRcbiAgICAgIC8vYW5kIHRoZSB1c2VyIGRhdGEgaXNuJ3QgaW4gbWVtb3J5XG4gICAgICBpZiAoQXV0aC5jdXJyZW50VXNlciA9PT0gbnVsbCkge1xuICAgICAgICBBdXRoLnVwZGF0ZUN1cnJlbnRVc2VyKGFuZ3VsYXIuZnJvbUpzb24obG9jYWxTdG9yYWdlLmdldEl0ZW0oJ3VzZXInKSkpO1xuICAgICAgfVxuICAgIH0pO1xuXG4gICAgLy9DaGVjayBpZiB0aGUgdG9rZW4gc3RpbGwgdmFsaWQuXG4gICAgJHJvb3RTY29wZS4kb24oJyRzdGF0ZUNoYW5nZVN0YXJ0JywgZnVuY3Rpb24oZXZlbnQsIHRvU3RhdGUpIHtcbiAgICAgIGlmICh0b1N0YXRlLmRhdGEubmVlZEF1dGhlbnRpY2F0aW9uIHx8IHRvU3RhdGUuZGF0YS5uZWVkUHJvZmlsZSkge1xuICAgICAgICAvL2RvbnQgdHJhaXQgdGhlIHN1Y2Nlc3MgYmxvY2sgYmVjYXVzZSBhbHJlYWR5IGRpZCBieSB0b2tlbiBpbnRlcmNlcHRvclxuICAgICAgICBBdXRoLnJlbW90ZVZhbGlkYXRlVG9rZW4oKS5jYXRjaChmdW5jdGlvbigpIHtcbiAgICAgICAgICBQclRvYXN0Lndhcm4oJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5sb2dpbi5sb2dvdXRJbmFjdGl2ZScpKTtcblxuICAgICAgICAgIGlmICh0b1N0YXRlLm5hbWUgIT09IEdsb2JhbC5sb2dpblN0YXRlKSB7XG4gICAgICAgICAgICAkc3RhdGUuZ28oR2xvYmFsLmxvZ2luU3RhdGUpO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIGV2ZW50LnByZXZlbnREZWZhdWx0KCk7XG4gICAgICAgIH0pO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgLy9pZiB0aGUgdXNlIGlzIGF1dGhlbnRpY2F0ZWQgYW5kIG5lZWQgdG8gZW50ZXIgaW4gbG9naW4gcGFnZVxuICAgICAgICAvL2hpbSB3aWxsIGJlIHJlZGlyZWN0ZWQgdG8gaG9tZSBwYWdlXG4gICAgICAgIGlmICh0b1N0YXRlLm5hbWUgPT09IEdsb2JhbC5sb2dpblN0YXRlICYmIEF1dGguYXV0aGVudGljYXRlZCgpKSB7XG4gICAgICAgICAgJHN0YXRlLmdvKEdsb2JhbC5ob21lU3RhdGUpO1xuICAgICAgICAgIGV2ZW50LnByZXZlbnREZWZhdWx0KCk7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9KTtcbiAgfVxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5ydW4oYXV0aG9yaXphdGlvbkxpc3RlbmVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIGF1dGhvcml6YXRpb25MaXN0ZW5lcigkcm9vdFNjb3BlLCAkc3RhdGUsIEdsb2JhbCwgQXV0aCkge1xuICAgIC8qKlxuICAgICAqIEEgY2FkYSBtdWRhbsOnYSBkZSBlc3RhZG8gKFwicMOhZ2luYVwiKSB2ZXJpZmljYSBzZSBvIHVzdcOhcmlvIHRlbSBvIHBlcmZpbFxuICAgICAqIG5lY2Vzc8OhcmlvIHBhcmEgbyBhY2Vzc28gYSBtZXNtYVxuICAgICAqL1xuICAgICRyb290U2NvcGUuJG9uKCckc3RhdGVDaGFuZ2VTdGFydCcsIGZ1bmN0aW9uKGV2ZW50LCB0b1N0YXRlKSB7XG4gICAgICBpZiAodG9TdGF0ZS5kYXRhICYmIHRvU3RhdGUuZGF0YS5uZWVkQXV0aGVudGljYXRpb24gJiZcbiAgICAgICAgdG9TdGF0ZS5kYXRhLm5lZWRQcm9maWxlICYmIEF1dGguYXV0aGVudGljYXRlZCgpICYmXG4gICAgICAgICFBdXRoLmN1cnJlbnRVc2VyLmhhc1Byb2ZpbGUodG9TdGF0ZS5kYXRhLm5lZWRQcm9maWxlLCB0b1N0YXRlLmRhdGEuYWxsUHJvZmlsZXMpKSB7XG5cbiAgICAgICAgJHN0YXRlLmdvKEdsb2JhbC5ub3RBdXRob3JpemVkU3RhdGUpO1xuICAgICAgICBldmVudC5wcmV2ZW50RGVmYXVsdCgpO1xuICAgICAgfVxuXG4gICAgfSk7XG4gIH1cbn0oKSk7XG4iLCIoZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbmZpZyhzcGlubmVySW50ZXJjZXB0b3IpO1xuXG4gIGZ1bmN0aW9uIHNwaW5uZXJJbnRlcmNlcHRvcigkaHR0cFByb3ZpZGVyLCAkcHJvdmlkZSkge1xuICAgIC8qKlxuICAgICAqIEVzdGUgaW50ZXJjZXB0b3Igw6kgcmVzcG9uc8OhdmVsIHBvciBtb3N0cmFyIGUgZXNjb25kZXIgb1xuICAgICAqIGNvbXBvbmVudGUgUHJTcGlubmVyIHNlbXByZSBxdWUgdW1hIHJlcXVpc2nDp8OjbyBhamF4XG4gICAgICogaW5pY2lhciBlIGZpbmFsaXphci5cbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSAkcVxuICAgICAqIEBwYXJhbSB7YW55fSAkaW5qZWN0b3JcbiAgICAgKiBAcmV0dXJuc1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIHNob3dIaWRlU3Bpbm5lcigkcSwgJGluamVjdG9yKSB7XG4gICAgICByZXR1cm4ge1xuICAgICAgICByZXF1ZXN0OiBmdW5jdGlvbiAoY29uZmlnKSB7XG4gICAgICAgICAgJGluamVjdG9yLmdldCgnUHJTcGlubmVyJykuc2hvdygpO1xuXG4gICAgICAgICAgcmV0dXJuIGNvbmZpZztcbiAgICAgICAgfSxcblxuICAgICAgICByZXNwb25zZTogZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgICAgJGluamVjdG9yLmdldCgnUHJTcGlubmVyJykuaGlkZSgpO1xuXG4gICAgICAgICAgcmV0dXJuIHJlc3BvbnNlO1xuICAgICAgICB9LFxuXG4gICAgICAgIHJlc3BvbnNlRXJyb3I6IGZ1bmN0aW9uIChyZWplY3Rpb24pIHtcbiAgICAgICAgICAkaW5qZWN0b3IuZ2V0KCdQclNwaW5uZXInKS5oaWRlKCk7XG5cbiAgICAgICAgICByZXR1cm4gJHEucmVqZWN0KHJlamVjdGlvbik7XG4gICAgICAgIH1cbiAgICAgIH07XG4gICAgfVxuXG4gICAgLy8gRGVmaW5lIHVtYSBmYWN0b3J5IHBhcmEgbyAkaHR0cEludGVyY2VwdG9yXG4gICAgJHByb3ZpZGUuZmFjdG9yeSgnc2hvd0hpZGVTcGlubmVyJywgc2hvd0hpZGVTcGlubmVyKTtcblxuICAgIC8vIEFkaWNpb25hIGEgZmFjdG9yeSBubyBhcnJheSBkZSBpbnRlcmNlcHRvcnMgZG8gJGh0dHBcbiAgICAkaHR0cFByb3ZpZGVyLmludGVyY2VwdG9ycy5wdXNoKCdzaG93SGlkZVNwaW5uZXInKTtcbiAgfVxufSgpKTtcbiIsIi8qZXNsaW50IGFuZ3VsYXIvbW9kdWxlLWdldHRlcjogMCovXG5cbihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb25maWcodG9rZW5JbnRlcmNlcHRvcik7XG5cbiAgLyoqXG4gICAqIEludGVyY2VwdCBhbGwgcmVzcG9uc2UgKHN1Y2Nlc3Mgb3IgZXJyb3IpIHRvIHZlcmlmeSB0aGUgcmV0dXJuZWQgdG9rZW5cbiAgICpcbiAgICogQHBhcmFtICRodHRwUHJvdmlkZXJcbiAgICogQHBhcmFtICRwcm92aWRlXG4gICAqIEBwYXJhbSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gdG9rZW5JbnRlcmNlcHRvcigkaHR0cFByb3ZpZGVyLCAkcHJvdmlkZSwgR2xvYmFsKSB7XG5cbiAgICBmdW5jdGlvbiByZWRpcmVjdFdoZW5TZXJ2ZXJMb2dnZWRPdXQoJHEsICRpbmplY3Rvcikge1xuICAgICAgcmV0dXJuIHtcbiAgICAgICAgcmVxdWVzdDogZnVuY3Rpb24oY29uZmlnKSB7XG4gICAgICAgICAgdmFyIHRva2VuID0gJGluamVjdG9yLmdldCgnQXV0aCcpLmdldFRva2VuKCk7XG5cbiAgICAgICAgICBpZiAodG9rZW4pIHtcbiAgICAgICAgICAgIGNvbmZpZy5oZWFkZXJzWydBdXRob3JpemF0aW9uJ10gPSAnQmVhcmVyICcgKyB0b2tlbjtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICByZXR1cm4gY29uZmlnO1xuICAgICAgICB9LFxuICAgICAgICByZXNwb25zZTogZnVuY3Rpb24ocmVzcG9uc2UpIHtcbiAgICAgICAgICAvLyBnZXQgYSBuZXcgcmVmcmVzaCB0b2tlbiB0byB1c2UgaW4gdGhlIG5leHQgcmVxdWVzdFxuICAgICAgICAgIHZhciB0b2tlbiA9IHJlc3BvbnNlLmhlYWRlcnMoJ0F1dGhvcml6YXRpb24nKTtcblxuICAgICAgICAgIGlmICh0b2tlbikge1xuICAgICAgICAgICAgJGluamVjdG9yLmdldCgnQXV0aCcpLnNldFRva2VuKHRva2VuLnNwbGl0KCcgJylbMV0pO1xuICAgICAgICAgIH1cbiAgICAgICAgICByZXR1cm4gcmVzcG9uc2U7XG4gICAgICAgIH0sXG4gICAgICAgIHJlc3BvbnNlRXJyb3I6IGZ1bmN0aW9uKHJlamVjdGlvbikge1xuICAgICAgICAgIC8vIEluc3RlYWQgb2YgY2hlY2tpbmcgZm9yIGEgc3RhdHVzIGNvZGUgb2YgNDAwIHdoaWNoIG1pZ2h0IGJlIHVzZWRcbiAgICAgICAgICAvLyBmb3Igb3RoZXIgcmVhc29ucyBpbiBMYXJhdmVsLCB3ZSBjaGVjayBmb3IgdGhlIHNwZWNpZmljIHJlamVjdGlvblxuICAgICAgICAgIC8vIHJlYXNvbnMgdG8gdGVsbCB1cyBpZiB3ZSBuZWVkIHRvIHJlZGlyZWN0IHRvIHRoZSBsb2dpbiBzdGF0ZVxuICAgICAgICAgIHZhciByZWplY3Rpb25SZWFzb25zID0gWyd0b2tlbl9ub3RfcHJvdmlkZWQnLCAndG9rZW5fZXhwaXJlZCcsICd0b2tlbl9hYnNlbnQnLCAndG9rZW5faW52YWxpZCddO1xuXG4gICAgICAgICAgdmFyIHRva2VuRXJyb3IgPSBmYWxzZTtcblxuICAgICAgICAgIGFuZ3VsYXIuZm9yRWFjaChyZWplY3Rpb25SZWFzb25zLCBmdW5jdGlvbih2YWx1ZSkge1xuICAgICAgICAgICAgaWYgKHJlamVjdGlvbi5kYXRhICYmIHJlamVjdGlvbi5kYXRhLmVycm9yID09PSB2YWx1ZSkge1xuICAgICAgICAgICAgICB0b2tlbkVycm9yID0gdHJ1ZTtcblxuICAgICAgICAgICAgICAkaW5qZWN0b3IuZ2V0KCdBdXRoJykubG9nb3V0KCkudGhlbihmdW5jdGlvbigpIHtcbiAgICAgICAgICAgICAgICB2YXIgJHN0YXRlID0gJGluamVjdG9yLmdldCgnJHN0YXRlJyk7XG5cbiAgICAgICAgICAgICAgICAvLyBpbiBjYXNlIG11bHRpcGxlIGFqYXggcmVxdWVzdCBmYWlsIGF0IHNhbWUgdGltZSBiZWNhdXNlIHRva2VuIHByb2JsZW1zLFxuICAgICAgICAgICAgICAgIC8vIG9ubHkgdGhlIGZpcnN0IHdpbGwgcmVkaXJlY3RcbiAgICAgICAgICAgICAgICBpZiAoISRzdGF0ZS5pcyhHbG9iYWwubG9naW5TdGF0ZSkpIHtcbiAgICAgICAgICAgICAgICAgICRzdGF0ZS5nbyhHbG9iYWwubG9naW5TdGF0ZSk7XG5cbiAgICAgICAgICAgICAgICAgIC8vY2xvc2UgYW55IGRpYWxvZyB0aGF0IGlzIG9wZW5lZFxuICAgICAgICAgICAgICAgICAgJGluamVjdG9yLmdldCgnUHJEaWFsb2cnKS5jbG9zZSgpO1xuXG4gICAgICAgICAgICAgICAgICBldmVudC5wcmV2ZW50RGVmYXVsdCgpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfSk7XG5cbiAgICAgICAgICAvL2RlZmluZSBkYXRhIHRvIGVtcHR5IGJlY2F1c2UgYWxyZWFkeSBzaG93IFByVG9hc3QgdG9rZW4gbWVzc2FnZVxuICAgICAgICAgIGlmICh0b2tlbkVycm9yKSB7XG4gICAgICAgICAgICByZWplY3Rpb24uZGF0YSA9IHt9O1xuICAgICAgICAgIH1cblxuICAgICAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24ocmVqZWN0aW9uLmhlYWRlcnMpKSB7XG4gICAgICAgICAgICAvLyBtYW55IHNlcnZlcnMgZXJyb3JzIChidXNpbmVzcykgYXJlIGludGVyY2VwdCBoZXJlIGJ1dCBnZW5lcmF0ZWQgYSBuZXcgcmVmcmVzaCB0b2tlblxuICAgICAgICAgICAgLy8gYW5kIG5lZWQgdXBkYXRlIGN1cnJlbnQgdG9rZW5cbiAgICAgICAgICAgIHZhciB0b2tlbiA9IHJlamVjdGlvbi5oZWFkZXJzKCdBdXRob3JpemF0aW9uJyk7XG5cbiAgICAgICAgICAgIGlmICh0b2tlbikge1xuICAgICAgICAgICAgICAkaW5qZWN0b3IuZ2V0KCdBdXRoJykuc2V0VG9rZW4odG9rZW4uc3BsaXQoJyAnKVsxXSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgcmV0dXJuICRxLnJlamVjdChyZWplY3Rpb24pO1xuICAgICAgICB9XG4gICAgICB9O1xuICAgIH1cblxuICAgIC8vIFNldHVwIGZvciB0aGUgJGh0dHBJbnRlcmNlcHRvclxuICAgICRwcm92aWRlLmZhY3RvcnkoJ3JlZGlyZWN0V2hlblNlcnZlckxvZ2dlZE91dCcsIHJlZGlyZWN0V2hlblNlcnZlckxvZ2dlZE91dCk7XG5cbiAgICAvLyBQdXNoIHRoZSBuZXcgZmFjdG9yeSBvbnRvIHRoZSAkaHR0cCBpbnRlcmNlcHRvciBhcnJheVxuICAgICRodHRwUHJvdmlkZXIuaW50ZXJjZXB0b3JzLnB1c2goJ3JlZGlyZWN0V2hlblNlcnZlckxvZ2dlZE91dCcpO1xuICB9XG5cbn0oKSk7XG4iLCIoZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbmZpZyh2YWxpZGF0aW9uSW50ZXJjZXB0b3IpO1xuXG4gIGZ1bmN0aW9uIHZhbGlkYXRpb25JbnRlcmNlcHRvcigkaHR0cFByb3ZpZGVyLCAkcHJvdmlkZSkge1xuICAgIC8qKlxuICAgICAqIEVzdGUgaW50ZXJjZXB0b3Igw6kgcmVzcG9uc8OhdmVsIHBvciBtb3N0cmFyIGFzXG4gICAgICogbWVuc2FnZW5zIGRlIGVycm8gcmVmZXJlbnRlIGFzIHZhbGlkYcOnw7VlcyBkbyBiYWNrLWVuZFxuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9ICRxXG4gICAgICogQHBhcmFtIHthbnl9ICRpbmplY3RvclxuICAgICAqIEByZXR1cm5zXG4gICAgICovXG4gICAgZnVuY3Rpb24gc2hvd0Vycm9yVmFsaWRhdGlvbigkcSwgJGluamVjdG9yKSB7XG4gICAgICByZXR1cm4ge1xuICAgICAgICByZXNwb25zZUVycm9yOiBmdW5jdGlvbiAocmVqZWN0aW9uKSB7XG4gICAgICAgICAgdmFyIFByVG9hc3QgPSAkaW5qZWN0b3IuZ2V0KCdQclRvYXN0Jyk7XG4gICAgICAgICAgdmFyICR0cmFuc2xhdGUgPSAkaW5qZWN0b3IuZ2V0KCckdHJhbnNsYXRlJyk7XG5cbiAgICAgICAgICBpZiAocmVqZWN0aW9uLmNvbmZpZy5kYXRhICYmICFyZWplY3Rpb24uY29uZmlnLmRhdGEuc2tpcFZhbGlkYXRpb24pIHtcbiAgICAgICAgICAgIGlmIChyZWplY3Rpb24uZGF0YSAmJiByZWplY3Rpb24uZGF0YS5lcnJvcikge1xuXG4gICAgICAgICAgICAgIC8vdmVyaWZpY2Egc2Ugb2NvcnJldSBhbGd1bSBlcnJvIHJlZmVyZW50ZSBhbyB0b2tlblxuICAgICAgICAgICAgICBpZiAocmVqZWN0aW9uLmRhdGEuZXJyb3Iuc3RhcnRzV2l0aCgndG9rZW5fJykpIHtcbiAgICAgICAgICAgICAgICBQclRvYXN0Lndhcm4oJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5sb2dpbi5sb2dvdXRJbmFjdGl2ZScpKTtcbiAgICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICBQclRvYXN0LmVycm9yKCR0cmFuc2xhdGUuaW5zdGFudChyZWplY3Rpb24uZGF0YS5lcnJvcikpO1xuICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICBQclRvYXN0LmVycm9yVmFsaWRhdGlvbihyZWplY3Rpb24uZGF0YSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgcmV0dXJuICRxLnJlamVjdChyZWplY3Rpb24pO1xuICAgICAgICB9XG4gICAgICB9O1xuICAgIH1cblxuICAgIC8vIERlZmluZSB1bWEgZmFjdG9yeSBwYXJhIG8gJGh0dHBJbnRlcmNlcHRvclxuICAgICRwcm92aWRlLmZhY3RvcnkoJ3Nob3dFcnJvclZhbGlkYXRpb24nLCBzaG93RXJyb3JWYWxpZGF0aW9uKTtcblxuICAgIC8vIEFkaWNpb25hIGEgZmFjdG9yeSBubyBhcnJheSBkZSBpbnRlcmNlcHRvcnMgZG8gJGh0dHBcbiAgICAkaHR0cFByb3ZpZGVyLmludGVyY2VwdG9ycy5wdXNoKCdzaG93RXJyb3JWYWxpZGF0aW9uJyk7XG4gIH1cbn0oKSk7XG4iLCIvKmVzbGludC1lbnYgZXM2Ki9cblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnRyb2xsZXIoJ01lbnVDb250cm9sbGVyJywgTWVudUNvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gTWVudUNvbnRyb2xsZXIoJG1kU2lkZW5hdiwgJHN0YXRlLCAkbWRDb2xvcnMpIHtcbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgLy9CbG9jbyBkZSBkZWNsYXJhY29lcyBkZSBmdW5jb2VzXG4gICAgdm0ub3BlbiA9IG9wZW47XG4gICAgdm0ub3Blbk1lbnVPclJlZGlyZWN0VG9TdGF0ZSA9IG9wZW5NZW51T3JSZWRpcmVjdFRvU3RhdGU7XG5cbiAgICBhY3RpdmF0ZSgpO1xuXG4gICAgZnVuY3Rpb24gYWN0aXZhdGUoKSB7XG4gICAgICB2YXIgbWVudVByZWZpeCA9ICd2aWV3cy5sYXlvdXQubWVudS4nO1xuXG4gICAgICAvLyBBcnJheSBjb250ZW5kbyBvcyBpdGVucyBxdWUgc8OjbyBtb3N0cmFkb3Mgbm8gbWVudSBsYXRlcmFsXG4gICAgICB2bS5pdGVuc01lbnUgPSBbXG4gICAgICAgIHsgc3RhdGU6ICdhcHAucHJvamVjdHMnLCB0aXRsZTogbWVudVByZWZpeCArICdkYXNoYm9hcmQnLCBpY29uOiAnZGFzaGJvYXJkJywgc3ViSXRlbnM6IFtdIH0sXG4gICAgICAgIC8vIENvbG9xdWUgc2V1cyBpdGVucyBkZSBtZW51IGEgcGFydGlyIGRlc3RlIHBvbnRvXG4gICAgICAgIHtcbiAgICAgICAgICBzdGF0ZTogJyMnLCB0aXRsZTogbWVudVByZWZpeCArICdhZG1pbicsIGljb246ICdzZXR0aW5nc19hcHBsaWNhdGlvbnMnLCBwcm9maWxlczogWydhZG1pbiddLFxuICAgICAgICAgIHN1Ykl0ZW5zOiBbXG4gICAgICAgICAgICB7IHN0YXRlOiAnYXBwLnVzZXInLCB0aXRsZTogbWVudVByZWZpeCArICd1c2VyJywgaWNvbjogJ3Blb3BsZScgfSxcbiAgICAgICAgICAgIHsgc3RhdGU6ICdhcHAubWFpbCcsIHRpdGxlOiBtZW51UHJlZml4ICsgJ21haWwnLCBpY29uOiAnbWFpbCcgfSxcbiAgICAgICAgICAgIHsgc3RhdGU6ICdhcHAuYXVkaXQnLCB0aXRsZTogbWVudVByZWZpeCArICdhdWRpdCcsIGljb246ICdzdG9yYWdlJyB9LFxuICAgICAgICAgICAgeyBzdGF0ZTogJ2FwcC5kaW5hbWljLXF1ZXJ5JywgdGl0bGU6IG1lbnVQcmVmaXggKyAnZGluYW1pY1F1ZXJ5JywgaWNvbjogJ2xvY2F0aW9uX3NlYXJjaGluZycgfVxuICAgICAgICAgIF1cbiAgICAgICAgfVxuICAgICAgXTtcblxuICAgICAgLyoqXG4gICAgICAgKiBPYmpldG8gcXVlIHByZWVuY2hlIG8gbmctc3R5bGUgZG8gbWVudSBsYXRlcmFsIHRyb2NhbmRvIGFzIGNvcmVzXG4gICAgICAgKi9cbiAgICAgIHZtLnNpZGVuYXZTdHlsZSA9IHtcbiAgICAgICAgdG9wOiB7XG4gICAgICAgICAgJ2JvcmRlci1ib3R0b20nOiAnMXB4IHNvbGlkICcgKyBnZXRDb2xvcigncHJpbWFyeScpLFxuICAgICAgICAgICdiYWNrZ3JvdW5kLWltYWdlJzogJy13ZWJraXQtbGluZWFyLWdyYWRpZW50KHRvcCwgJytnZXRDb2xvcigncHJpbWFyeS01MDAnKSsnLCAnK2dldENvbG9yKCdwcmltYXJ5LTgwMCcpKycpJ1xuICAgICAgICB9LFxuICAgICAgICBjb250ZW50OiB7XG4gICAgICAgICAgJ2JhY2tncm91bmQtY29sb3InOiBnZXRDb2xvcigncHJpbWFyeS04MDAnKVxuICAgICAgICB9LFxuICAgICAgICB0ZXh0Q29sb3I6IHtcbiAgICAgICAgICBjb2xvcjogJyNGRkYnXG4gICAgICAgIH0sXG4gICAgICAgIGxpbmVCb3R0b206IHtcbiAgICAgICAgICAnYm9yZGVyLWJvdHRvbSc6ICcxcHggc29saWQgJyArIGdldENvbG9yKCdwcmltYXJ5LTQwMCcpXG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9XG5cbiAgICBmdW5jdGlvbiBvcGVuKCkge1xuICAgICAgJG1kU2lkZW5hdignbGVmdCcpLnRvZ2dsZSgpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIE3DqXRvZG8gcXVlIGV4aWJlIG8gc3ViIG1lbnUgZG9zIGl0ZW5zIGRvIG1lbnUgbGF0ZXJhbCBjYXNvIHRlbmhhIHN1YiBpdGVuc1xuICAgICAqIGNhc28gY29udHLDoXJpbyByZWRpcmVjaW9uYSBwYXJhIG8gc3RhdGUgcGFzc2FkbyBjb21vIHBhcsOibWV0cm9cbiAgICAgKi9cbiAgICBmdW5jdGlvbiBvcGVuTWVudU9yUmVkaXJlY3RUb1N0YXRlKCRtZE1lbnUsIGV2LCBpdGVtKSB7XG4gICAgICBpZiAoYW5ndWxhci5pc0RlZmluZWQoaXRlbS5zdWJJdGVucykgJiYgaXRlbS5zdWJJdGVucy5sZW5ndGggPiAwKSB7XG4gICAgICAgICRtZE1lbnUub3Blbihldik7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICAkc3RhdGUuZ28oaXRlbS5zdGF0ZSk7XG4gICAgICAgICRtZFNpZGVuYXYoJ2xlZnQnKS5jbG9zZSgpO1xuICAgICAgfVxuICAgIH1cblxuICAgIGZ1bmN0aW9uIGdldENvbG9yKGNvbG9yUGFsZXR0ZXMpIHtcbiAgICAgIHJldHVybiAkbWRDb2xvcnMuZ2V0VGhlbWVDb2xvcihjb2xvclBhbGV0dGVzKTtcbiAgICB9XG5cbiAgfVxuXG59KSgpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29udHJvbGxlcignTWFpbHNDb250cm9sbGVyJywgTWFpbHNDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIE1haWxzQ29udHJvbGxlcihNYWlsc1NlcnZpY2UsIFVzZXJzU2VydmljZSwgUHJEaWFsb2csIFByVG9hc3QsIC8vIE5PU09OQVJcbiAgICAkcSwgbG9kYXNoLCAkdHJhbnNsYXRlLCBHbG9iYWwpIHtcblxuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICB2bS5maWx0ZXJTZWxlY3RlZCA9IGZhbHNlO1xuICAgIHZtLm9wdGlvbnMgPSB7XG4gICAgICBza2luOiAna2FtYScsXG4gICAgICBsYW5ndWFnZTogJ3B0LWJyJyxcbiAgICAgIGFsbG93ZWRDb250ZW50OiB0cnVlLFxuICAgICAgZW50aXRpZXM6IHRydWUsXG4gICAgICBoZWlnaHQ6IDMwMCxcbiAgICAgIGV4dHJhUGx1Z2luczogJ2RpYWxvZyxmaW5kLGNvbG9yZGlhbG9nLHByZXZpZXcsZm9ybXMsaWZyYW1lLGZsYXNoJ1xuICAgIH07XG5cbiAgICB2bS5sb2FkVXNlcnMgPSBsb2FkVXNlcnM7XG4gICAgdm0ub3BlblVzZXJEaWFsb2cgPSBvcGVuVXNlckRpYWxvZztcbiAgICB2bS5hZGRVc2VyTWFpbCA9IGFkZFVzZXJNYWlsO1xuICAgIHZtLmNsZWFuRm9ybSA9IGNsZWFuRm9ybTtcbiAgICB2bS5zZW5kID0gc2VuZDtcblxuICAgIGFjdGl2YXRlKCk7XG5cbiAgICBmdW5jdGlvbiBhY3RpdmF0ZSgpIHtcbiAgICAgIHZtLmNsZWFuRm9ybSgpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWxpemEgYSBidXNjYSBwZWxvIHVzdcOhcmlvIHJlbW90YW1lbnRlXG4gICAgICpcbiAgICAgKiBAcGFyYW1zIHtzdHJpbmd9IC0gUmVjZWJlIG8gdmFsb3IgcGFyYSBzZXIgcGVzcXVpc2Fkb1xuICAgICAqIEByZXR1cm4ge3Byb21pc3NlfSAtIFJldG9ybmEgdW1hIHByb21pc3NlIHF1ZSBvIGNvbXBvbmV0ZSByZXNvbHZlXG4gICAgICovXG4gICAgZnVuY3Rpb24gbG9hZFVzZXJzKGNyaXRlcmlhKSB7XG4gICAgICB2YXIgZGVmZXJyZWQgPSAkcS5kZWZlcigpO1xuXG4gICAgICBVc2Vyc1NlcnZpY2UucXVlcnkoe1xuICAgICAgICBuYW1lT3JFbWFpbDogY3JpdGVyaWEsXG4gICAgICAgIG5vdFVzZXJzOiBsb2Rhc2gubWFwKHZtLm1haWwudXNlcnMsIGxvZGFzaC5wcm9wZXJ0eSgnaWQnKSkudG9TdHJpbmcoKSxcbiAgICAgICAgbGltaXQ6IDVcbiAgICAgIH0pLnRoZW4oZnVuY3Rpb24oZGF0YSkge1xuXG4gICAgICAgIC8vIHZlcmlmaWNhIHNlIG5hIGxpc3RhIGRlIHVzdWFyaW9zIGrDoSBleGlzdGUgbyB1c3XDoXJpbyBjb20gbyBlbWFpbCBwZXNxdWlzYWRvXG4gICAgICAgIGRhdGEgPSBsb2Rhc2guZmlsdGVyKGRhdGEsIGZ1bmN0aW9uKHVzZXIpIHtcbiAgICAgICAgICByZXR1cm4gIWxvZGFzaC5maW5kKHZtLm1haWwudXNlcnMsIHsgZW1haWw6IHVzZXIuZW1haWwgfSk7XG4gICAgICAgIH0pO1xuXG4gICAgICAgIGRlZmVycmVkLnJlc29sdmUoZGF0YSk7XG4gICAgICB9KTtcblxuICAgICAgcmV0dXJuIGRlZmVycmVkLnByb21pc2U7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQWJyZSBvIGRpYWxvZyBwYXJhIHBlc3F1aXNhIGRlIHVzdcOhcmlvc1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIG9wZW5Vc2VyRGlhbG9nKCkge1xuICAgICAgdmFyIGNvbmZpZyA9IHtcbiAgICAgICAgbG9jYWxzOiB7XG4gICAgICAgICAgb25Jbml0OiB0cnVlLFxuICAgICAgICAgIHVzZXJEaWFsb2dJbnB1dDoge1xuICAgICAgICAgICAgdHJhbnNmZXJVc2VyRm46IHZtLmFkZFVzZXJNYWlsXG4gICAgICAgICAgfVxuICAgICAgICB9LFxuICAgICAgICBjb250cm9sbGVyOiAnVXNlcnNEaWFsb2dDb250cm9sbGVyJyxcbiAgICAgICAgY29udHJvbGxlckFzOiAnY3RybCcsXG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvdXNlcnMvZGlhbG9nL3VzZXJzLWRpYWxvZy5odG1sJyxcbiAgICAgICAgaGFzQmFja2Ryb3A6IHRydWVcbiAgICAgIH07XG5cbiAgICAgIFByRGlhbG9nLmN1c3RvbShjb25maWcpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEFkaWNpb25hIG8gdXN1w6FyaW8gc2VsZWNpb25hZG8gbmEgbGlzdGEgcGFyYSBxdWUgc2VqYSBlbnZpYWRvIG8gZW1haWxcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBhZGRVc2VyTWFpbCh1c2VyKSB7XG4gICAgICB2YXIgdXNlcnMgPSBsb2Rhc2guZmluZCh2bS5tYWlsLnVzZXJzLCB7IGVtYWlsOiB1c2VyLmVtYWlsIH0pO1xuXG4gICAgICBpZiAodm0ubWFpbC51c2Vycy5sZW5ndGggPiAwICYmIGFuZ3VsYXIuaXNEZWZpbmVkKHVzZXJzKSkge1xuICAgICAgICBQclRvYXN0Lndhcm4oJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy51c2VyLnVzZXJFeGlzdHMnKSk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICB2bS5tYWlsLnVzZXJzLnB1c2goeyBuYW1lOiB1c2VyLm5hbWUsIGVtYWlsOiB1c2VyLmVtYWlsIH0pXG4gICAgICB9XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhbGl6YSBvIGVudmlvIGRvIGVtYWlsIHBhcmEgYSBsaXN0YSBkZSB1c3XDoXJpb3Mgc2VsZWNpb25hZG9zXG4gICAgICovXG4gICAgZnVuY3Rpb24gc2VuZCgpIHtcblxuICAgICAgdm0ubWFpbC4kc2F2ZSgpLnRoZW4oZnVuY3Rpb24ocmVzcG9uc2UpIHtcbiAgICAgICAgaWYgKHJlc3BvbnNlLmxlbmd0aCA+IDApIHtcbiAgICAgICAgICB2YXIgbXNnID0gJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5tYWlsLm1haWxFcnJvcnMnKTtcblxuICAgICAgICAgIGZvciAodmFyIGk9MDsgaSA8IHJlc3BvbnNlLmxlbmd0aDsgaSsrKSB7XG4gICAgICAgICAgICBtc2cgKz0gcmVzcG9uc2UgKyAnXFxuJztcbiAgICAgICAgICB9XG4gICAgICAgICAgUHJUb2FzdC5lcnJvcihtc2cpO1xuICAgICAgICAgIHZtLmNsZWFuRm9ybSgpO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIFByVG9hc3Quc3VjY2VzcygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLm1haWwuc2VuZE1haWxTdWNjZXNzJykpO1xuICAgICAgICAgIHZtLmNsZWFuRm9ybSgpO1xuICAgICAgICB9XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBMaW1wYSBvIGZvcm11bMOhcmlvIGRlIGVtYWlsXG4gICAgICovXG4gICAgZnVuY3Rpb24gY2xlYW5Gb3JtKCkge1xuICAgICAgdm0ubWFpbCA9IG5ldyBNYWlsc1NlcnZpY2UoKTtcbiAgICAgIHZtLm1haWwudXNlcnMgPSBbXTtcbiAgICB9XG5cbiAgfVxuXG59KSgpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKlxuICAgKiBBcnF1aXZvIGRlIGNvbmZpZ3VyYcOnw6NvIGNvbSBhcyByb3RhcyBlc3BlY8OtZmljYXMgZG8gcmVjdXJzbyBlbSBxdWVzdMOjb1xuICAgKlxuICAgKiBAcGFyYW0ge2FueX0gJHN0YXRlUHJvdmlkZXJcbiAgICogQHBhcmFtIHthbnl9IEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyXG4gICAgICAuc3RhdGUoJ2FwcC5tYWlsJywge1xuICAgICAgICB1cmw6ICcvZW1haWwnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL21haWwvbWFpbHMtc2VuZC5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ01haWxzQ29udHJvbGxlciBhcyBtYWlsc0N0cmwnLFxuICAgICAgICBkYXRhOiB7IG5lZWRBdXRoZW50aWNhdGlvbjogdHJ1ZSwgbmVlZFByb2ZpbGU6IFsnYWRtaW4nXSB9XG4gICAgICB9KTtcblxuICB9XG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZhY3RvcnkoJ01haWxzU2VydmljZScsIE1haWxzU2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBNYWlsc1NlcnZpY2Uoc2VydmljZUZhY3RvcnkpIHtcbiAgICByZXR1cm4gc2VydmljZUZhY3RvcnkoJ21haWxzJywge30pO1xuICB9XG5cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb250cm9sbGVyKCdQcm9qZWN0c0NvbnRyb2xsZXInLCBQcm9qZWN0c0NvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gUHJvamVjdHNDb250cm9sbGVyKEdsb2JhbCwgJGNvbnRyb2xsZXIsIFByb2plY3RzU2VydmljZSwgQXV0aCwgUm9sZXNTZXJ2aWNlLCBVc2Vyc1NlcnZpY2UpIHtcbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgLy9BdHRyaWJ1dGVzIEJsb2NrXG5cbiAgICAvL0Z1bmN0aW9ucyBCbG9ja1xuICAgIHZtLm9uQWN0aXZhdGUgPSBvbkFjdGl2YXRlO1xuICAgIHZtLmFwcGx5RmlsdGVycyA9IGFwcGx5RmlsdGVycztcbiAgICB2bS5iZWZvcmVTYXZlID0gYmVmb3JlU2F2ZTtcbiAgICB2bS5zZWFyY2hVc2VyID0gc2VhcmNoVXNlcjtcbiAgICB2bS5hZGRVc2VyID0gYWRkVXNlcjtcbiAgICB2bS5yZW1vdmVVc2VyID0gcmVtb3ZlVXNlcjtcbiAgICBcbiAgICB2bS5yb2xlcyA9IHt9O1xuXG4gICAgZnVuY3Rpb24gb25BY3RpdmF0ZSgpIHsgXG4gICAgICB2bS5xdWVyeUZpbHRlcnMgPSB7dXNlcl9pZDogQXV0aC5jdXJyZW50VXNlci5pZH07XG4gIFx0XHRSb2xlc1NlcnZpY2UucXVlcnkoKS50aGVuKGZ1bmN0aW9uKHJlc3BvbnNlKXtcbiAgXHRcdFx0dm0ucm9sZXMgPSByZXNwb25zZTtcbiAgXHRcdH0pO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGFwcGx5RmlsdGVycyhkZWZhdWx0UXVlcnlGaWx0ZXJzKSB7XG4gICAgICByZXR1cm4gYW5ndWxhci5leHRlbmQoZGVmYXVsdFF1ZXJ5RmlsdGVycywgdm0ucXVlcnlsdGVycyk7XG4gICAgfVxuICAgIFxuICAgIGZ1bmN0aW9uIGJlZm9yZVNhdmUoKSB7XG4gIFx0XHR2bS5yZXNvdXJjZS5vd25lciA9IEF1dGguY3VycmVudFVzZXIuaWQ7XG4gIFx0XHR2bS5yZXNvdXJjZS51c2VyX2lkID0gQXV0aC5jdXJyZW50VXNlci5pZDtcbiAgXHR9XG5cbiAgICBmdW5jdGlvbiBzZWFyY2hVc2VyKHRleHQpIHtcbiAgICAgIHJldHVybiBVc2Vyc1NlcnZpY2UucXVlcnkoe25hbWU6IHZtLnVzZXJOYW1lfSk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gYWRkVXNlcih1c2VyKSB7XG4gICAgICBpZih1c2VyKSB7XG4gICAgICAgIHZtLnJlc291cmNlLnVzZXJzLnB1c2godXNlcik7XG4gICAgICAgIHZtLnVzZXJOYW1lID0gJyc7IFxuICAgICAgfVxuICAgIH1cblxuICAgIGZ1bmN0aW9uIHJlbW92ZVVzZXIoaW5kZXgpIHtcbiAgICAgIHZtLnJlc291cmNlLnVzZXJzLnNwbGljZShpbmRleCwgMSk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gYXBwbHlGaWx0ZXJzKGRlZmF1bHRRdWVyeUZpbHRlcnMpIHtcbiAgICAgIHJldHVybiBhbmd1bGFyLmV4dGVuZChkZWZhdWx0UXVlcnlGaWx0ZXJzLCB2bS5xdWVyeUZpbHRlcnMpOyAgICBcbiAgICB9XG5cbiAgICAvLyBpbnN0YW50aWF0ZSBiYXNlIGNvbnRyb2xsZXJcbiAgICAkY29udHJvbGxlcignQ1JVRENvbnRyb2xsZXInLCB7IHZtOiB2bSwgbW9kZWxTZXJ2aWNlOiBQcm9qZWN0c1NlcnZpY2UsIG9wdGlvbnM6IHt9IH0pO1xuICB9XG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqXG4gICAqIEFycXVpdm8gZGUgY29uZmlndXJhw6fDo28gY29tIGFzIHJvdGFzIGVzcGVjw61maWNhcyBkbyByZWN1cnNvIHByb2plY3RcbiAgICpcbiAgICogQHBhcmFtIHthbnl9ICRzdGF0ZVByb3ZpZGVyXG4gICAqIEBwYXJhbSB7YW55fSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlclxuICAgICAgLnN0YXRlKCdhcHAucHJvamVjdHMnLCB7XG4gICAgICAgIHVybDogJy9wcm9qZWN0cycsXG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvcHJvamVjdHMvcHJvamVjdHMuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdQcm9qZWN0c0NvbnRyb2xsZXIgYXMgcHJvamVjdHNDdHJsJyxcbiAgICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IHRydWV9XG4gICAgICB9KTtcbiAgfVxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5mYWN0b3J5KCdQcm9qZWN0c1NlcnZpY2UnLCBQcm9qZWN0c1NlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gUHJvamVjdHNTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCdwcm9qZWN0cycsIHtcbiAgICAgIGFjdGlvbnM6IHsgfSxcbiAgICAgIGluc3RhbmNlOiB7IH1cbiAgICB9KTtcbiAgfVxuXG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmlsdGVyKCdyb2xlc1N0cicsIHJvbGVzU3RyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvbGVzU3RyKGxvZGFzaCkge1xuICAgIC8qKlxuICAgICAqIEBwYXJhbSB7YXJyYXl9IHJvbGVzIGxpc3RhIGRlIHBlcmZpc1xuICAgICAqIEByZXR1cm4ge3N0cmluZ30gcGVyZmlzIHNlcGFyYWRvcyBwb3IgJywgJyAgXG4gICAgICovXG4gICAgcmV0dXJuIGZ1bmN0aW9uKHJvbGVzKSB7XG4gICAgICByZXR1cm4gbG9kYXNoLm1hcChyb2xlcywgJ3NsdWcnKS5qb2luKCcsICcpO1xuICAgIH07XG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5mYWN0b3J5KCdSb2xlc1NlcnZpY2UnLCBSb2xlc1NlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gUm9sZXNTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCdyb2xlcycpO1xuICB9XG5cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmFjdG9yeSgnU3VwcG9ydFNlcnZpY2UnLCBTdXBwb3J0U2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiBTdXBwb3J0U2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHJldHVybiBzZXJ2aWNlRmFjdG9yeSgnc3VwcG9ydCcsIHtcbiAgICAgIGFjdGlvbnM6IHtcbiAgICAgIC8qKlxuICAgICAgICogUGVnYSBhcyB0cmFkdcOnw7VlcyBxdWUgZXN0w6NvIG5vIHNlcnZpZG9yXG4gICAgICAgKlxuICAgICAgICogQHJldHVybnMge3Byb21pc2V9IFVtYSBwcm9taXNlIGNvbSBvIHJlc3VsdGFkbyBkbyBjaGFtYWRhIG5vIGJhY2tlbmRcbiAgICAgICAqL1xuICAgICAgICBsYW5nczoge1xuICAgICAgICAgIG1ldGhvZDogJ0dFVCcsXG4gICAgICAgICAgdXJsOiAnbGFuZ3MnLFxuICAgICAgICAgIHdyYXA6IGZhbHNlLFxuICAgICAgICAgIGNhY2hlOiB0cnVlXG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9KTtcbiAgfVxuXG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29udHJvbGxlcignUHJvZmlsZUNvbnRyb2xsZXInLCBQcm9maWxlQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBQcm9maWxlQ29udHJvbGxlcihVc2Vyc1NlcnZpY2UsIEF1dGgsIFByVG9hc3QsICR0cmFuc2xhdGUpIHtcbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0udXBkYXRlID0gdXBkYXRlO1xuXG4gICAgYWN0aXZhdGUoKTtcblxuICAgIGZ1bmN0aW9uIGFjdGl2YXRlKCkge1xuICAgICAgdm0udXNlciA9IGFuZ3VsYXIuY29weShBdXRoLmN1cnJlbnRVc2VyKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiB1cGRhdGUoKSB7XG4gICAgICBVc2Vyc1NlcnZpY2UudXBkYXRlUHJvZmlsZSh2bS51c2VyKS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICAvL2F0dWFsaXphIG8gdXN1w6FyaW8gY29ycmVudGUgY29tIGFzIG5vdmFzIGluZm9ybWHDp8O1ZXNcbiAgICAgICAgQXV0aC51cGRhdGVDdXJyZW50VXNlcihyZXNwb25zZSk7XG4gICAgICAgIFByVG9hc3Quc3VjY2VzcygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnNhdmVTdWNjZXNzJykpO1xuICAgICAgfSk7XG4gICAgfVxuICB9XG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb250cm9sbGVyKCdVc2Vyc0NvbnRyb2xsZXInLCBVc2Vyc0NvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gVXNlcnNDb250cm9sbGVyKCRjb250cm9sbGVyLCBVc2Vyc1NlcnZpY2UpIHtcblxuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICB2bS5vbkFjdGl2YXRlID0gb25BY3RpdmF0ZTtcbiAgICAvLyBpbnN0YW50aWF0ZSBiYXNlIGNvbnRyb2xsZXJcbiAgICAkY29udHJvbGxlcignQ1JVRENvbnRyb2xsZXInLCB7IHZtOiB2bSwgbW9kZWxTZXJ2aWNlOiBVc2Vyc1NlcnZpY2UsIG9wdGlvbnM6IHt9IH0pO1xuXG4gICAgZnVuY3Rpb24gb25BY3RpdmF0ZSgpIHtcbiAgICAgIHZtLnF1ZXJ5RmlsdGVycyA9IHt9O1xuICAgIH1cbiAgfVxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb25maWcocm91dGVzKTtcblxuICAvKipcbiAgICogQXJxdWl2byBkZSBjb25maWd1cmHDp8OjbyBjb20gYXMgcm90YXMgZXNwZWPDrWZpY2FzIGRvIHJlY3Vyc28gdXNlclxuICAgKlxuICAgKiBAcGFyYW0ge2FueX0gJHN0YXRlUHJvdmlkZXJcbiAgICogQHBhcmFtIHthbnl9IEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyXG4gICAgICAuc3RhdGUoJ2FwcC51c2VyJywge1xuICAgICAgICB1cmw6ICcvdXN1YXJpbycsXG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvdXNlcnMvdXNlcnMuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdVc2Vyc0NvbnRyb2xsZXIgYXMgdXNlcnNDdHJsJyxcbiAgICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IHRydWUsIG5lZWRQcm9maWxlOiBbJ2FkbWluJ10gfVxuICAgICAgfSlcbiAgICAgIC5zdGF0ZSgnYXBwLnVzZXItcHJvZmlsZScsIHtcbiAgICAgICAgdXJsOiAnL3VzdWFyaW8vcGVyZmlsJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy91c2Vycy9wcm9maWxlLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnUHJvZmlsZUNvbnRyb2xsZXIgYXMgcHJvZmlsZUN0cmwnLFxuICAgICAgICBkYXRhOiB7IG5lZWRBdXRoZW50aWNhdGlvbjogdHJ1ZSB9XG4gICAgICB9KTtcblxuICB9XG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZhY3RvcnkoJ1VzZXJzU2VydmljZScsIFVzZXJzU2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBVc2Vyc1NlcnZpY2UobG9kYXNoLCBHbG9iYWwsIHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCd1c2VycycsIHtcbiAgICAgIC8vcXVhbmRvIGluc3RhbmNpYSB1bSB1c3XDoXJpbyBzZW0gcGFzc2FyIHBhcmFtZXRybyxcbiAgICAgIC8vbyBtZXNtbyB2YWkgdGVyIG9zIHZhbG9yZXMgZGVmYXVsdHMgYWJhaXhvXG4gICAgICBkZWZhdWx0czoge1xuICAgICAgICByb2xlczogW11cbiAgICAgIH0sXG5cbiAgICAgIGFjdGlvbnM6IHtcbiAgICAgICAgLyoqXG4gICAgICAgICAqIFNlcnZpw6dvIHF1ZSBhdHVhbGl6YSBvcyBkYWRvcyBkbyBwZXJmaWwgZG8gdXN1w6FyaW8gbG9nYWRvXG4gICAgICAgICAqXG4gICAgICAgICAqIEBwYXJhbSB7b2JqZWN0fSBhdHRyaWJ1dGVzXG4gICAgICAgICAqIEByZXR1cm5zIHtwcm9taXNlfSBVbWEgcHJvbWlzZSBjb20gbyByZXN1bHRhZG8gZG8gY2hhbWFkYSBubyBiYWNrZW5kXG4gICAgICAgICAqL1xuICAgICAgICB1cGRhdGVQcm9maWxlOiB7XG4gICAgICAgICAgbWV0aG9kOiAnUFVUJyxcbiAgICAgICAgICB1cmw6IEdsb2JhbC5hcGlQYXRoICsgJy9wcm9maWxlJyxcbiAgICAgICAgICBvdmVycmlkZTogdHJ1ZSxcbiAgICAgICAgICB3cmFwOiBmYWxzZVxuICAgICAgICB9XG4gICAgICB9LFxuXG4gICAgICBpbnN0YW5jZToge1xuICAgICAgICAvKipcbiAgICAgICAgICogVmVyaWZpY2Egc2UgbyB1c3XDoXJpbyB0ZW0gb3MgcGVyZmlzIGluZm9ybWFkb3MuXG4gICAgICAgICAqXG4gICAgICAgICAqIEBwYXJhbSB7YW55fSByb2xlcyBwZXJmaXMgYSBzZXJlbSB2ZXJpZmljYWRvc1xuICAgICAgICAgKiBAcGFyYW0ge2Jvb2xlYW59IGFsbCBmbGFnIHBhcmEgaW5kaWNhciBzZSB2YWkgY2hlZ2FyIHRvZG9zIG9zIHBlcmZpcyBvdSBzb21lbnRlIHVtIGRlbGVzXG4gICAgICAgICAqIEByZXR1cm5zIHtib29sZWFufVxuICAgICAgICAgKi9cbiAgICAgICAgaGFzUHJvZmlsZTogZnVuY3Rpb24ocm9sZXMsIGFsbCkge1xuICAgICAgICAgIHJvbGVzID0gYW5ndWxhci5pc0FycmF5KHJvbGVzKSA/IHJvbGVzIDogW3JvbGVzXTtcblxuICAgICAgICAgIHZhciB1c2VyUm9sZXMgPSBsb2Rhc2gubWFwKHRoaXMucm9sZXMsICdzbHVnJyk7XG5cbiAgICAgICAgICBpZiAoYWxsKSB7XG4gICAgICAgICAgICByZXR1cm4gbG9kYXNoLmludGVyc2VjdGlvbih1c2VyUm9sZXMsIHJvbGVzKS5sZW5ndGggPT09IHJvbGVzLmxlbmd0aDtcbiAgICAgICAgICB9IGVsc2UgeyAvL3JldHVybiB0aGUgbGVuZ3RoIGJlY2F1c2UgMCBpcyBmYWxzZSBpbiBqc1xuICAgICAgICAgICAgcmV0dXJuIGxvZGFzaC5pbnRlcnNlY3Rpb24odXNlclJvbGVzLCByb2xlcykubGVuZ3RoO1xuICAgICAgICAgIH1cbiAgICAgICAgfSxcblxuICAgICAgICAvKipcbiAgICAgICAgICogVmVyaWZpY2Egc2UgbyB1c3XDoXJpbyB0ZW0gbyBwZXJmaWwgYWRtaW4uXG4gICAgICAgICAqXG4gICAgICAgICAqIEByZXR1cm5zIHtib29sZWFufVxuICAgICAgICAgKi9cbiAgICAgICAgaXNBZG1pbjogZnVuY3Rpb24oKSB7XG4gICAgICAgICAgcmV0dXJuIHRoaXMuaGFzUHJvZmlsZSgnYWRtaW4nKTtcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pO1xuICB9XG5cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICAgLyoqIEBuZ0luamVjdCAqL1xuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29tcG9uZW50KCdib3gnLCB7XG4gICAgICByZXBsYWNlOiB0cnVlLFxuICAgICAgdGVtcGxhdGVVcmw6IFsnR2xvYmFsJywgZnVuY3Rpb24oR2xvYmFsKSB7XG4gICAgICAgIHJldHVybiBHbG9iYWwuY2xpZW50UGF0aCArICcvd2lkZ2V0cy9ib3guaHRtbCdcbiAgICAgIH1dLFxuICAgICAgdHJhbnNjbHVkZToge1xuICAgICAgICB0b29sYmFyQnV0dG9uczogJz9ib3hUb29sYmFyQnV0dG9ucycsXG4gICAgICAgIGZvb3RlckJ1dHRvbnM6ICc/Ym94Rm9vdGVyQnV0dG9ucydcbiAgICAgIH0sXG4gICAgICBiaW5kaW5nczoge1xuICAgICAgICBib3hUaXRsZTogJ0AnLFxuICAgICAgICB0b29sYmFyQ2xhc3M6ICdAJyxcbiAgICAgICAgdG9vbGJhckJnQ29sb3I6ICdAJ1xuICAgICAgfSxcbiAgICAgIGNvbnRyb2xsZXI6IFsnJHRyYW5zY2x1ZGUnLCBmdW5jdGlvbigkdHJhbnNjbHVkZSkge1xuICAgICAgICB2YXIgY3RybCA9IHRoaXM7XG5cbiAgICAgICAgY3RybC50cmFuc2NsdWRlID0gJHRyYW5zY2x1ZGU7XG5cbiAgICAgICAgY3RybC4kb25Jbml0ID0gZnVuY3Rpb24oKSB7XG4gICAgICAgICAgaWYgKGFuZ3VsYXIuaXNVbmRlZmluZWQoY3RybC50b29sYmFyQmdDb2xvcikpIGN0cmwudG9vbGJhckJnQ29sb3IgPSAnZGVmYXVsdC1wcmltYXJ5JztcbiAgICAgICAgfTtcbiAgICAgIH1dXG4gICAgfSk7XG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29tcG9uZW50KCdjb250ZW50Qm9keScsIHtcbiAgICAgIHJlcGxhY2U6IHRydWUsXG4gICAgICB0cmFuc2NsdWRlOiB0cnVlLFxuICAgICAgdGVtcGxhdGVVcmw6IFsnR2xvYmFsJywgZnVuY3Rpb24oR2xvYmFsKSB7XG4gICAgICAgIHJldHVybiBHbG9iYWwuY2xpZW50UGF0aCArICcvd2lkZ2V0cy9jb250ZW50LWJvZHkuaHRtbCdcbiAgICAgIH1dLFxuICAgICAgYmluZGluZ3M6IHtcbiAgICAgICAgbGF5b3V0QWxpZ246ICdAJ1xuICAgICAgfSxcbiAgICAgIGNvbnRyb2xsZXI6IFtmdW5jdGlvbigpIHtcbiAgICAgICAgdmFyIGN0cmwgPSB0aGlzO1xuXG4gICAgICAgIGN0cmwuJG9uSW5pdCA9IGZ1bmN0aW9uKCkge1xuICAgICAgICAgIC8vIE1ha2UgYSBjb3B5IG9mIHRoZSBpbml0aWFsIHZhbHVlIHRvIGJlIGFibGUgdG8gcmVzZXQgaXQgbGF0ZXJcbiAgICAgICAgICBjdHJsLmxheW91dEFsaWduID0gYW5ndWxhci5pc0RlZmluZWQoY3RybC5sYXlvdXRBbGlnbikgPyBjdHJsLmxheW91dEFsaWduIDogJ2NlbnRlciBzdGFydCc7XG4gICAgICAgIH07XG4gICAgICB9XVxuICAgIH0pO1xuXG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29tcG9uZW50KCdjb250ZW50SGVhZGVyJywge1xuICAgICAgdGVtcGxhdGVVcmw6IFsnR2xvYmFsJywgZnVuY3Rpb24oR2xvYmFsKSB7XG4gICAgICAgIHJldHVybiBHbG9iYWwuY2xpZW50UGF0aCArICcvd2lkZ2V0cy9jb250ZW50LWhlYWRlci5odG1sJ1xuICAgICAgfV0sXG4gICAgICByZXBsYWNlOiB0cnVlLFxuICAgICAgYmluZGluZ3M6IHtcbiAgICAgICAgdGl0bGU6ICdAJyxcbiAgICAgICAgZGVzY3JpcHRpb246ICdAJ1xuICAgICAgfVxuICAgIH0pO1xuXG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmlsdGVyKCdhdWRpdERldGFpbFRpdGxlJywgYXVkaXREZXRhaWxUaXRsZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBhdWRpdERldGFpbFRpdGxlKCR0cmFuc2xhdGUpIHtcbiAgICByZXR1cm4gZnVuY3Rpb24oYXVkaXREZXRhaWwsIHN0YXR1cykge1xuICAgICAgaWYgKGF1ZGl0RGV0YWlsLnR5cGUgPT09ICd1cGRhdGVkJykge1xuICAgICAgICBpZiAoc3RhdHVzID09PSAnYmVmb3JlJykge1xuICAgICAgICAgIHJldHVybiAkdHJhbnNsYXRlLmluc3RhbnQoJ2RpYWxvZy5hdWRpdC51cGRhdGVkQmVmb3JlJyk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgcmV0dXJuICR0cmFuc2xhdGUuaW5zdGFudCgnZGlhbG9nLmF1ZGl0LnVwZGF0ZWRBZnRlcicpO1xuICAgICAgICB9XG4gICAgICB9IGVsc2Uge1xuICAgICAgICByZXR1cm4gJHRyYW5zbGF0ZS5pbnN0YW50KCdkaWFsb2cuYXVkaXQuJyArIGF1ZGl0RGV0YWlsLnR5cGUpO1xuICAgICAgfVxuICAgIH1cbiAgfVxuXG59KSgpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmlsdGVyKCdhdWRpdE1vZGVsJywgYXVkaXRNb2RlbCk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBhdWRpdE1vZGVsKCR0cmFuc2xhdGUpIHtcbiAgICByZXR1cm4gZnVuY3Rpb24obW9kZWxJZCkge1xuICAgICAgbW9kZWxJZCA9IG1vZGVsSWQucmVwbGFjZSgnQXBwXFxcXCcsICcnKTtcbiAgICAgIHZhciBtb2RlbCA9ICR0cmFuc2xhdGUuaW5zdGFudCgnbW9kZWxzLicgKyBtb2RlbElkLnRvTG93ZXJDYXNlKCkpO1xuXG4gICAgICByZXR1cm4gKG1vZGVsKSA/IG1vZGVsIDogbW9kZWxJZDtcbiAgICB9XG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZpbHRlcignYXVkaXRUeXBlJywgYXVkaXRUeXBlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIGF1ZGl0VHlwZShsb2Rhc2gsIEF1ZGl0U2VydmljZSkge1xuICAgIHJldHVybiBmdW5jdGlvbih0eXBlSWQpIHtcbiAgICAgIHZhciB0eXBlID0gbG9kYXNoLmZpbmQoQXVkaXRTZXJ2aWNlLmxpc3RUeXBlcygpLCB7IGlkOiB0eXBlSWQgfSk7XG5cbiAgICAgIHJldHVybiAodHlwZSkgPyB0eXBlLmxhYmVsIDogdHlwZTtcbiAgICB9XG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZpbHRlcignYXVkaXRWYWx1ZScsIGF1ZGl0VmFsdWUpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gYXVkaXRWYWx1ZSgkZmlsdGVyLCBsb2Rhc2gpIHtcbiAgICByZXR1cm4gZnVuY3Rpb24odmFsdWUsIGtleSkge1xuICAgICAgaWYgKGFuZ3VsYXIuaXNEYXRlKHZhbHVlKSB8fCBsb2Rhc2guZW5kc1dpdGgoa2V5LCAnX2F0JykgfHwgIGxvZGFzaC5lbmRzV2l0aChrZXksICdfdG8nKSkge1xuICAgICAgICByZXR1cm4gJGZpbHRlcigncHJEYXRldGltZScpKHZhbHVlKTtcbiAgICAgIH1cblxuICAgICAgaWYgKHR5cGVvZiB2YWx1ZSA9PT0gJ2Jvb2xlYW4nKSB7XG4gICAgICAgIHJldHVybiAkZmlsdGVyKCd0cmFuc2xhdGUnKSgodmFsdWUpID8gJ2dsb2JhbC55ZXMnIDogJ2dsb2JhbC5ubycpO1xuICAgICAgfVxuXG4gICAgICAvL2NoZWNrIGlzIGZsb2F0XG4gICAgICBpZiAoTnVtYmVyKHZhbHVlKSA9PT0gdmFsdWUgJiYgdmFsdWUgJSAxICE9PSAwKSB7XG4gICAgICAgIHJldHVybiAkZmlsdGVyKCdyZWFsJykodmFsdWUpO1xuICAgICAgfVxuXG4gICAgICByZXR1cm4gdmFsdWU7XG4gICAgfVxuICB9XG5cbn0pKCk7XG4iLCIvKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCwgbm8tdW5kZWY6IDAqL1xuKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnN0YW50KCdwdC1CUi5pMThuLmF0dHJpYnV0ZXMnLCB7XG4gICAgICBlbWFpbDogJ0VtYWlsJyxcbiAgICAgIHBhc3N3b3JkOiAnU2VuaGEnLFxuICAgICAgbmFtZTogJ05vbWUnLFxuICAgICAgaW1hZ2U6ICdJbWFnZW0nLFxuICAgICAgcm9sZXM6ICdQZXJmaXMnLFxuICAgICAgZGF0ZTogJ0RhdGEnLFxuICAgICAgaW5pdGlhbERhdGU6ICdEYXRhIEluaWNpYWwnLFxuICAgICAgZmluYWxEYXRlOiAnRGF0YSBGaW5hbCcsXG4gICAgICB0YXNrOiB7XG4gICAgICAgIGRlc2NyaXB0aW9uOiAnRGVzY3Jpw6fDo28nLFxuICAgICAgICBkb25lOiAnRmVpdG8/JyxcbiAgICAgICAgcHJpb3JpdHk6ICdQcmlvcmlkYWRlJyxcbiAgICAgICAgc2NoZWR1bGVkX3RvOiAnQWdlbmRhZG8gUGFyYT8nLFxuICAgICAgICBwcm9qZWN0OiAnUHJvamV0bydcbiAgICAgIH0sXG4gICAgICBwcm9qZWN0OiB7XG4gICAgICAgIGNvc3Q6ICdDdXN0bydcbiAgICAgIH0sXG4gICAgICAvL8OpIGNhcnJlZ2FkbyBkbyBzZXJ2aWRvciBjYXNvIGVzdGVqYSBkZWZpbmlkbyBubyBtZXNtb1xuICAgICAgYXVkaXRNb2RlbDoge1xuICAgICAgfVxuICAgIH0pXG5cbn0oKSk7XG4iLCIvKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCwgbm8tdW5kZWY6IDAqL1xuKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnN0YW50KCdwdC1CUi5pMThuLmRpYWxvZycsIHtcbiAgICAgIGNvbmZpcm1UaXRsZTogJ0NvbmZpcm1hw6fDo28nLFxuICAgICAgY29uZmlybURlc2NyaXB0aW9uOiAnQ29uZmlybWEgYSBhw6fDo28/JyxcbiAgICAgIHJlbW92ZURlc2NyaXB0aW9uOiAnRGVzZWphIHJlbW92ZXIgcGVybWFuZW50ZW1lbnRlIHt7bmFtZX19PycsXG4gICAgICBhdWRpdDoge1xuICAgICAgICBjcmVhdGVkOiAnSW5mb3JtYcOnw7VlcyBkbyBDYWRhc3RybycsXG4gICAgICAgIHVwZGF0ZWRCZWZvcmU6ICdBbnRlcyBkYSBBdHVhbGl6YcOnw6NvJyxcbiAgICAgICAgdXBkYXRlZEFmdGVyOiAnRGVwb2lzIGRhIEF0dWFsaXphw6fDo28nLFxuICAgICAgICBkZWxldGVkOiAnSW5mb3JtYcOnw7VlcyBhbnRlcyBkZSByZW1vdmVyJ1xuICAgICAgfSxcbiAgICAgIGxvZ2luOiB7XG4gICAgICAgIHJlc2V0UGFzc3dvcmQ6IHtcbiAgICAgICAgICBkZXNjcmlwdGlvbjogJ0RpZ2l0ZSBhYmFpeG8gbyBlbWFpbCBjYWRhc3RyYWRvIG5vIHNpc3RlbWEuJ1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfSlcblxufSgpKTtcbiIsIi8qZXNsaW50IGFuZ3VsYXIvZmlsZS1uYW1lOiAwLCBuby11bmRlZjogMCovXG4oZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uc3RhbnQoJ3B0LUJSLmkxOG4uZ2xvYmFsJywge1xuICAgICAgbG9hZGluZzogJ0NhcnJlZ2FuZG8uLi4nLFxuICAgICAgcHJvY2Vzc2luZzogJ1Byb2Nlc3NhbmRvLi4uJyxcbiAgICAgIHllczogJ1NpbScsXG4gICAgICBubzogJ07Do28nLFxuICAgICAgYWxsOiAnVG9kb3MnXG4gICAgfSlcblxufSgpKTtcbiIsIi8qZXNsaW50IGFuZ3VsYXIvZmlsZS1uYW1lOiAwLCBuby11bmRlZjogMCovXG4oZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uc3RhbnQoJ3B0LUJSLmkxOG4ubWVzc2FnZXMnLCB7XG4gICAgICBpbnRlcm5hbEVycm9yOiAnT2NvcnJldSB1bSBlcnJvIGludGVybm8sIGNvbnRhdGUgbyBhZG1pbmlzdHJhZG9yIGRvIHNpc3RlbWEnLFxuICAgICAgbm90Rm91bmQ6ICdOZW5odW0gcmVnaXN0cm8gZW5jb250cmFkbycsXG4gICAgICBub3RBdXRob3JpemVkOiAnVm9jw6ogbsOjbyB0ZW0gYWNlc3NvIGEgZXN0YSBmdW5jaW9uYWxpZGFkZS4nLFxuICAgICAgc2VhcmNoRXJyb3I6ICdOw6NvIGZvaSBwb3Nzw612ZWwgcmVhbGl6YXIgYSBidXNjYS4nLFxuICAgICAgc2F2ZVN1Y2Nlc3M6ICdSZWdpc3RybyBzYWx2byBjb20gc3VjZXNzby4nLFxuICAgICAgb3BlcmF0aW9uU3VjY2VzczogJ09wZXJhw6fDo28gcmVhbGl6YWRhIGNvbSBzdWNlc3NvLicsXG4gICAgICBvcGVyYXRpb25FcnJvcjogJ0Vycm8gYW8gcmVhbGl6YXIgYSBvcGVyYcOnw6NvJyxcbiAgICAgIHNhdmVFcnJvcjogJ0Vycm8gYW8gdGVudGFyIHNhbHZhciBvIHJlZ2lzdHJvLicsXG4gICAgICByZW1vdmVTdWNjZXNzOiAnUmVtb8Onw6NvIHJlYWxpemFkYSBjb20gc3VjZXNzby4nLFxuICAgICAgcmVtb3ZlRXJyb3I6ICdFcnJvIGFvIHRlbnRhciByZW1vdmVyIG8gcmVnaXN0cm8uJyxcbiAgICAgIHJlc291cmNlTm90Rm91bmRFcnJvcjogJ1JlY3Vyc28gbsOjbyBlbmNvbnRyYWRvJyxcbiAgICAgIG5vdE51bGxFcnJvcjogJ1RvZG9zIG9zIGNhbXBvcyBvYnJpZ2F0w7NyaW9zIGRldmVtIHNlciBwcmVlbmNoaWRvcy4nLFxuICAgICAgZHVwbGljYXRlZFJlc291cmNlRXJyb3I6ICdKw6EgZXhpc3RlIHVtIHJlY3Vyc28gY29tIGVzc2FzIGluZm9ybWHDp8O1ZXMuJyxcbiAgICAgIHZhbGlkYXRlOiB7XG4gICAgICAgIGZpZWxkUmVxdWlyZWQ6ICdPIGNhbXBvIHt7ZmllbGR9fSDDqSBvYnJpZ3JhdMOzcmlvLidcbiAgICAgIH0sXG4gICAgICBsYXlvdXQ6IHtcbiAgICAgICAgZXJyb3I0MDQ6ICdQw6FnaW5hIG7Do28gZW5jb250cmFkYSdcbiAgICAgIH0sXG4gICAgICBsb2dpbjoge1xuICAgICAgICBsb2dvdXRJbmFjdGl2ZTogJ1ZvY8OqIGZvaSBkZXNsb2dhZG8gZG8gc2lzdGVtYSBwb3IgaW5hdGl2aWRhZGUuIEZhdm9yIGVudHJhciBubyBzaXN0ZW1hIG5vdmFtZW50ZS4nLFxuICAgICAgICBpbnZhbGlkQ3JlZGVudGlhbHM6ICdDcmVkZW5jaWFpcyBJbnbDoWxpZGFzJyxcbiAgICAgICAgdW5rbm93bkVycm9yOiAnTsOjbyBmb2kgcG9zc8OtdmVsIHJlYWxpemFyIG8gbG9naW4uIFRlbnRlIG5vdmFtZW50ZS4gJyArXG4gICAgICAgICAgJ0Nhc28gbsOjbyBjb25zaWdhIGZhdm9yIGVuY29udHJhciBlbSBjb250YXRvIGNvbSBvIGFkbWluaXN0cmFkb3IgZG8gc2lzdGVtYS4nLFxuICAgICAgICB1c2VyTm90Rm91bmQ6ICdOw6NvIGZvaSBwb3Nzw612ZWwgZW5jb250cmFyIHNldXMgZGFkb3MnXG4gICAgICB9LFxuICAgICAgZGFzaGJvYXJkOiB7XG4gICAgICAgIHdlbGNvbWU6ICdTZWphIGJlbSBWaW5kbyB7e3VzZXJOYW1lfX0nLFxuICAgICAgICBkZXNjcmlwdGlvbjogJ1V0aWxpemUgbyBtZW51IHBhcmEgbmF2ZWdhw6fDo28uJ1xuICAgICAgfSxcbiAgICAgIG1haWw6IHtcbiAgICAgICAgbWFpbEVycm9yczogJ09jb3JyZXUgdW0gZXJybyBub3Mgc2VndWludGVzIGVtYWlscyBhYmFpeG86XFxuJyxcbiAgICAgICAgc2VuZE1haWxTdWNjZXNzOiAnRW1haWwgZW52aWFkbyBjb20gc3VjZXNzbyEnLFxuICAgICAgICBzZW5kTWFpbEVycm9yOiAnTsOjbyBmb2kgcG9zc8OtdmVsIGVudmlhciBvIGVtYWlsLicsXG4gICAgICAgIHBhc3N3b3JkU2VuZGluZ1N1Y2Nlc3M6ICdPIHByb2Nlc3NvIGRlIHJlY3VwZXJhw6fDo28gZGUgc2VuaGEgZm9pIGluaWNpYWRvLiBDYXNvIG8gZW1haWwgbsOjbyBjaGVndWUgZW0gMTAgbWludXRvcyB0ZW50ZSBub3ZhbWVudGUuJ1xuICAgICAgfSxcbiAgICAgIHVzZXI6IHtcbiAgICAgICAgcmVtb3ZlWW91clNlbGZFcnJvcjogJ1ZvY8OqIG7Do28gcG9kZSByZW1vdmVyIHNldSBwcsOzcHJpbyB1c3XDoXJpbycsXG4gICAgICAgIHVzZXJFeGlzdHM6ICdVc3XDoXJpbyBqw6EgYWRpY2lvbmFkbyEnLFxuICAgICAgICBwcm9maWxlOiB7XG4gICAgICAgICAgdXBkYXRlRXJyb3I6ICdOw6NvIGZvaSBwb3Nzw612ZWwgYXR1YWxpemFyIHNldSBwcm9maWxlJ1xuICAgICAgICB9XG4gICAgICB9LFxuICAgICAgcXVlcnlEaW5hbWljOiB7XG4gICAgICAgIG5vRmlsdGVyOiAnTmVuaHVtIGZpbHRybyBhZGljaW9uYWRvJ1xuICAgICAgfVxuICAgIH0pXG5cbn0oKSk7XG4iLCIvKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCwgbm8tdW5kZWY6IDAqL1xuKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnN0YW50KCdwdC1CUi5pMThuLm1vZGVscycsIHtcbiAgICAgIHVzZXI6ICdVc3XDoXJpbycsXG4gICAgICB0YXNrOiAnVGFyZWZhJyxcbiAgICAgIHByb2plY3Q6ICdQcm9qZXRvJ1xuICAgIH0pXG5cbn0oKSk7XG4iLCIvKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCwgbm8tdW5kZWY6IDAqL1xuKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnN0YW50KCdwdC1CUi5pMThuLnZpZXdzJywge1xuICAgICAgYnJlYWRjcnVtYnM6IHtcbiAgICAgICAgdXNlcjogJ0FkbWluaXN0cmHDp8OjbyAtIFVzdcOhcmlvJyxcbiAgICAgICAgJ3VzZXItcHJvZmlsZSc6ICdQZXJmaWwnLFxuICAgICAgICBkYXNoYm9hcmQ6ICdEYXNoYm9hcmQnLFxuICAgICAgICBhdWRpdDogJ0FkbWluaXN0cmHDp8OjbyAtIEF1ZGl0b3JpYScsXG4gICAgICAgIG1haWw6ICdBZG1pbmlzdHJhw6fDo28gLSBFbnZpbyBkZSBlLW1haWwnLFxuICAgICAgICBwcm9qZWN0czogJ1Byb2pldG9zJyxcbiAgICAgICAgJ2RpbmFtaWMtcXVlcnknOiAnQWRtaW5pc3RyYcOnw6NvIC0gQ29uc3VsdGFzIERpbsOibWljYXMnLFxuICAgICAgICAnbm90LWF1dGhvcml6ZWQnOiAnQWNlc3NvIE5lZ2FkbydcbiAgICAgIH0sXG4gICAgICB0aXRsZXM6IHtcbiAgICAgICAgZGFzaGJvYXJkOiAnUMOhZ2luYSBpbmljaWFsJyxcbiAgICAgICAgbWFpbFNlbmQ6ICdFbnZpYXIgZS1tYWlsJyxcbiAgICAgICAgdGFza0xpc3Q6ICdMaXN0YSBkZSBUYXJlZmFzJyxcbiAgICAgICAgdXNlckxpc3Q6ICdMaXN0YSBkZSBVc3XDoXJpb3MnLFxuICAgICAgICBhdWRpdExpc3Q6ICdMaXN0YSBkZSBMb2dzJyxcbiAgICAgICAgcmVnaXN0ZXI6ICdGb3JtdWzDoXJpbyBkZSBDYWRhc3RybycsXG4gICAgICAgIHJlc2V0UGFzc3dvcmQ6ICdSZWRlZmluaXIgU2VuaGEnLFxuICAgICAgICB1cGRhdGU6ICdGb3JtdWzDoXJpbyBkZSBBdHVhbGl6YcOnw6NvJ1xuICAgICAgfSxcbiAgICAgIGFjdGlvbnM6IHtcbiAgICAgICAgc2VuZDogJ0VudmlhcicsXG4gICAgICAgIHNhdmU6ICdTYWx2YXInLFxuICAgICAgICBjbGVhcjogJ0xpbXBhcicsXG4gICAgICAgIGNsZWFyQWxsOiAnTGltcGFyIFR1ZG8nLFxuICAgICAgICByZXN0YXJ0OiAnUmVpbmljaWFyJyxcbiAgICAgICAgZmlsdGVyOiAnRmlsdHJhcicsXG4gICAgICAgIHNlYXJjaDogJ1Blc3F1aXNhcicsXG4gICAgICAgIGxpc3Q6ICdMaXN0YXInLFxuICAgICAgICBlZGl0OiAnRWRpdGFyJyxcbiAgICAgICAgY2FuY2VsOiAnQ2FuY2VsYXInLFxuICAgICAgICB1cGRhdGU6ICdBdHVhbGl6YXInLFxuICAgICAgICByZW1vdmU6ICdSZW1vdmVyJyxcbiAgICAgICAgZ2V0T3V0OiAnU2FpcicsXG4gICAgICAgIGFkZDogJ0FkaWNpb25hcicsXG4gICAgICAgIGluOiAnRW50cmFyJyxcbiAgICAgICAgbG9hZEltYWdlOiAnQ2FycmVnYXIgSW1hZ2VtJyxcbiAgICAgICAgc2lnbnVwOiAnQ2FkYXN0cmFyJyxcbiAgICAgICAgY3JpYXJQcm9qZXRvOiAnQ3JpYXIgUHJvamV0bycsXG4gICAgICAgIHByb2plY3RMaXN0OiAnTGlzdGEgZGUgUHJvamV0b3MnXG4gICAgICB9LFxuICAgICAgZmllbGRzOiB7XG4gICAgICAgIGRhdGU6ICdEYXRhJyxcbiAgICAgICAgYWN0aW9uOiAnQcOnw6NvJyxcbiAgICAgICAgYWN0aW9uczogJ0HDp8O1ZXMnLFxuICAgICAgICBhdWRpdDoge1xuICAgICAgICAgIGRhdGVTdGFydDogJ0RhdGEgSW5pY2lhbCcsXG4gICAgICAgICAgZGF0ZUVuZDogJ0RhdGEgRmluYWwnLFxuICAgICAgICAgIHJlc291cmNlOiAnUmVjdXJzbycsXG4gICAgICAgICAgYWxsUmVzb3VyY2VzOiAnVG9kb3MgUmVjdXJzb3MnLFxuICAgICAgICAgIHR5cGU6IHtcbiAgICAgICAgICAgIGNyZWF0ZWQ6ICdDYWRhc3RyYWRvJyxcbiAgICAgICAgICAgIHVwZGF0ZWQ6ICdBdHVhbGl6YWRvJyxcbiAgICAgICAgICAgIGRlbGV0ZWQ6ICdSZW1vdmlkbydcbiAgICAgICAgICB9XG4gICAgICAgIH0sXG4gICAgICAgIGxvZ2luOiB7XG4gICAgICAgICAgcmVzZXRQYXNzd29yZDogJ0VzcXVlY2kgbWluaGEgc2VuaGEnLFxuICAgICAgICAgIGNvbmZpcm1QYXNzd29yZDogJ0NvbmZpcm1hciBzZW5oYSdcbiAgICAgICAgfSxcbiAgICAgICAgbWFpbDoge1xuICAgICAgICAgIHRvOiAnUGFyYScsXG4gICAgICAgICAgc3ViamVjdDogJ0Fzc3VudG8nLFxuICAgICAgICAgIG1lc3NhZ2U6ICdNZW5zYWdlbSdcbiAgICAgICAgfSxcbiAgICAgICAgcXVlcnlEaW5hbWljOiB7XG4gICAgICAgICAgZmlsdGVyczogJ0ZpbHRyb3MnLFxuICAgICAgICAgIHJlc3VsdHM6ICdSZXN1bHRhZG9zJyxcbiAgICAgICAgICBtb2RlbDogJ01vZGVsJyxcbiAgICAgICAgICBhdHRyaWJ1dGU6ICdBdHJpYnV0bycsXG4gICAgICAgICAgb3BlcmF0b3I6ICdPcGVyYWRvcicsXG4gICAgICAgICAgcmVzb3VyY2U6ICdSZWN1cnNvJyxcbiAgICAgICAgICB2YWx1ZTogJ1ZhbG9yJyxcbiAgICAgICAgICBvcGVyYXRvcnM6IHtcbiAgICAgICAgICAgIGVxdWFsczogJ0lndWFsJyxcbiAgICAgICAgICAgIGRpZmVyZW50OiAnRGlmZXJlbnRlJyxcbiAgICAgICAgICAgIGNvbnRlaW5zOiAnQ29udMOpbScsXG4gICAgICAgICAgICBzdGFydFdpdGg6ICdJbmljaWEgY29tJyxcbiAgICAgICAgICAgIGZpbmlzaFdpdGg6ICdGaW5hbGl6YSBjb20nLFxuICAgICAgICAgICAgYmlnZ2VyVGhhbjogJ01haW9yJyxcbiAgICAgICAgICAgIGVxdWFsc09yQmlnZ2VyVGhhbjogJ01haW9yIG91IElndWFsJyxcbiAgICAgICAgICAgIGxlc3NUaGFuOiAnTWVub3InLFxuICAgICAgICAgICAgZXF1YWxzT3JMZXNzVGhhbjogJ01lbm9yIG91IElndWFsJ1xuICAgICAgICAgIH1cbiAgICAgICAgfSxcbiAgICAgICAgcHJvamVjdDoge1xuICAgICAgICAgIG5hbWU6ICdOb21lJyxcbiAgICAgICAgICB0b3RhbFRhc2s6ICdUb3RhbCBkZSBUYXJlZmFzJ1xuICAgICAgICB9LFxuICAgICAgICB0YXNrOiB7XG4gICAgICAgICAgZG9uZTogJ07Do28gRmVpdG8gLyBGZWl0bydcbiAgICAgICAgfSxcbiAgICAgICAgdXNlcjoge1xuICAgICAgICAgIHBlcmZpbHM6ICdQZXJmaXMnLFxuICAgICAgICAgIG5hbWVPckVtYWlsOiAnTm9tZSBvdSBFbWFpbCdcbiAgICAgICAgfVxuICAgICAgfSxcbiAgICAgIGxheW91dDoge1xuICAgICAgICBtZW51OiB7XG4gICAgICAgICAgZGFzaGJvYXJkOiAnRGFzaGJvYXJkJyxcbiAgICAgICAgICBwcm9qZWN0OiAnUHJvamV0b3MnLFxuICAgICAgICAgIGFkbWluOiAnQWRtaW5pc3RyYcOnw6NvJyxcbiAgICAgICAgICBleGFtcGxlczogJ0V4ZW1wbG9zJyxcbiAgICAgICAgICB1c2VyOiAnVXN1w6FyaW9zJyxcbiAgICAgICAgICBtYWlsOiAnRW52aWFyIGUtbWFpbCcsXG4gICAgICAgICAgYXVkaXQ6ICdBdWRpdG9yaWEnLFxuICAgICAgICAgIGRpbmFtaWNRdWVyeTogJ0NvbnN1bHRhcyBEaW5hbWljYXMnXG4gICAgICAgIH1cbiAgICAgIH0sXG4gICAgICB0b29sdGlwczoge1xuICAgICAgICBhdWRpdDoge1xuICAgICAgICAgIHZpZXdEZXRhaWw6ICdWaXN1YWxpemFyIERldGFsaGFtZW50bydcbiAgICAgICAgfSxcbiAgICAgICAgdXNlcjoge1xuICAgICAgICAgIHBlcmZpbDogJ1BlcmZpbCcsXG4gICAgICAgICAgdHJhbnNmZXI6ICdUcmFuc2ZlcmlyJ1xuICAgICAgICB9LFxuICAgICAgICB0YXNrOiB7XG4gICAgICAgICAgbGlzdFRhc2s6ICdMaXN0YXIgVGFyZWZhcydcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pXG5cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb250cm9sbGVyKCdUYXNrc0RpYWxvZ0NvbnRyb2xsZXInLCBUYXNrc0RpYWxvZ0NvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gVGFza3NEaWFsb2dDb250cm9sbGVyKCRjb250cm9sbGVyLCBUYXNrc1NlcnZpY2UsIHByb2plY3RJZCwgUHJUb2FzdCwgLy8gTk9TT05BUlxuICAgIFByRGlhbG9nLCAkdHJhbnNsYXRlLCBHbG9iYWwsIG1vbWVudCkge1xuXG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIC8vRnVuY3Rpb25zIEJsb2NrXG4gICAgdm0ub25BY3RpdmF0ZSAgID0gb25BY3RpdmF0ZTtcbiAgICB2bS5jbG9zZSAgICAgICAgPSBjbG9zZTtcbiAgICB2bS5hcHBseUZpbHRlcnMgPSBhcHBseUZpbHRlcnM7XG4gICAgdm0uYmVmb3JlU2F2ZSAgID0gYmVmb3JlU2F2ZTtcbiAgICB2bS5hZnRlclNhdmUgICAgPSBhZnRlclNhdmU7XG4gICAgdm0udG9nZ2xlRG9uZSAgID0gdG9nZ2xlRG9uZTtcblxuICAgIC8vIGluc3RhbnRpYXRlIGJhc2UgY29udHJvbGxlclxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHsgdm06IHZtLCBtb2RlbFNlcnZpY2U6IFRhc2tzU2VydmljZSwgb3B0aW9uczoge1xuICAgICAgcGVyUGFnZTogNVxuICAgIH0gfSk7XG5cbiAgICBmdW5jdGlvbiBvbkFjdGl2YXRlKCkge1xuICAgICAgdm0uZ2xvYmFsID0gR2xvYmFsO1xuICAgICAgdm0ucmVzb3VyY2Uuc2NoZWR1bGVkX3RvID0gbW9tZW50KCkuYWRkKDMwLCAnbWludXRlcycpO1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0geyBwcm9qZWN0SWQ6IHByb2plY3RJZCB9O1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGFwcGx5RmlsdGVycyhkZWZhdWx0UXVlcnlGaWx0ZXJzKSB7XG4gICAgICByZXR1cm4gYW5ndWxhci5leHRlbmQoZGVmYXVsdFF1ZXJ5RmlsdGVycywgdm0ucXVlcnlGaWx0ZXJzKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBiZWZvcmVTYXZlKCkge1xuICAgICAgdm0ucmVzb3VyY2UucHJvamVjdF9pZCA9IHZtLnF1ZXJ5RmlsdGVycy5wcm9qZWN0SWQ7XG4gICAgICB2bS5yZXNvdXJjZS5wcm9qZWN0ID0gbnVsbDtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBhZnRlclNhdmUoKSB7XG4gICAgICB2bS5jbGVhbkZvcm0oKTtcbiAgICAgIHZtLnNlYXJjaCh2bS5wYWdpbmF0b3IuY3VycmVudFBhZ2UpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGNsb3NlKCkge1xuICAgICAgdm0uY2xlYW5Gb3JtKCk7XG4gICAgICBQckRpYWxvZy5jbG9zZSgpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIHRvZ2dsZURvbmUocmVzb3VyY2UpIHtcbiAgICAgIFRhc2tzU2VydmljZS50b2dnbGVEb25lKHsgaWQ6IHJlc291cmNlLmlkLCBkb25lOiByZXNvdXJjZS5kb25lIH0pLnRoZW4oZnVuY3Rpb24oKSB7XG4gICAgICAgIFByVG9hc3Quc3VjY2VzcygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnNhdmVTdWNjZXNzJykpO1xuICAgICAgICB2bS5zZWFyY2godm0ucGFnaW5hdG9yLmN1cnJlbnRQYWdlKTtcbiAgICAgIH0sIGZ1bmN0aW9uKGVycm9yKSB7XG4gICAgICAgIFByVG9hc3QuZXJyb3JWYWxpZGF0aW9uKGVycm9yLmRhdGEsICR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMub3BlcmF0aW9uRXJyb3InKSk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgfVxuXG59KSgpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZhY3RvcnkoJ1Rhc2tzU2VydmljZScsIFRhc2tzU2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiBUYXNrc1NlcnZpY2Uoc2VydmljZUZhY3RvcnksIG1vbWVudCkge1xuICAgIHJldHVybiBzZXJ2aWNlRmFjdG9yeSgndGFza3MnLCB7XG4gICAgICAvL3F1YW5kbyBpbnN0YW5jaWEgdW0gdXN1w6FyaW8gc2VtIHBhc3NhciBwYXJhbWV0cm8sXG4gICAgICAvL28gbWVzbW8gdmFpIHRlciBvcyB2YWxvcmVzIGRlZmF1bHRzIGFiYWl4b1xuICAgICAgZGVmYXVsdHM6IHtcbiAgICAgICAgc2NoZWR1bGVkX3RvOiBuZXcgRGF0ZSgpXG4gICAgICB9LFxuXG4gICAgICBtYXA6IHtcbiAgICAgICAgLy9jb252ZXJ0IHBhcmEgb2JqZXRvIGphdmFzY3JpcHQgZGF0ZSB1bWEgc3RyaW5nIGZvcm1hdGFkYSBjb21vIGRhdGFcbiAgICAgICAgc2NoZWR1bGVkX3RvOiBmdW5jdGlvbih2YWx1ZSkge1xuICAgICAgICAgIHJldHVybiBtb21lbnQodmFsdWUpLnRvRGF0ZSgpO1xuICAgICAgICB9XG4gICAgICB9LFxuXG4gICAgICBhY3Rpb25zOiB7XG4gICAgICAgIC8qKlxuICAgICAgICAgKiBBdHVhbGl6YSBvcyBzdGF0dXMgZGEgdGFyZWZhXG4gICAgICAgICAqXG4gICAgICAgICAqIEBwYXJhbSB7b2JqZWN0fSBhdHRyaWJ1dGVzXG4gICAgICAgICAqL1xuICAgICAgICB0b2dnbGVEb25lOiB7XG4gICAgICAgICAgbWV0aG9kOiAnUFVUJyxcbiAgICAgICAgICB1cmw6ICd0b2dnbGVEb25lJ1xuICAgICAgICB9XG4gICAgICB9LFxuICAgICAgaW5zdGFuY2U6IHsgfVxuICAgIH0pO1xuICB9XG5cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb250cm9sbGVyKCdVc2Vyc0RpYWxvZ0NvbnRyb2xsZXInLCBVc2Vyc0RpYWxvZ0NvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gVXNlcnNEaWFsb2dDb250cm9sbGVyKCRjb250cm9sbGVyLCBVc2Vyc1NlcnZpY2UsIFByRGlhbG9nLCAgLy8gTk9TT05BUlxuICAgIHVzZXJEaWFsb2dJbnB1dCwgb25Jbml0KSB7XG5cbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0ub25BY3RpdmF0ZSA9IG9uQWN0aXZhdGU7XG4gICAgdm0uYXBwbHlGaWx0ZXJzID0gYXBwbHlGaWx0ZXJzO1xuICAgIHZtLmNsb3NlID0gY2xvc2U7XG5cbiAgICBpZiAoYW5ndWxhci5pc0RlZmluZWQodXNlckRpYWxvZ0lucHV0KSkge1xuICAgICAgdm0udHJhbnNmZXJVc2VyID0gdXNlckRpYWxvZ0lucHV0LnRyYW5zZmVyVXNlckZuO1xuICAgIH1cblxuICAgIC8vIGluc3RhbnRpYXRlIGJhc2UgY29udHJvbGxlclxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHtcbiAgICAgIHZtOiB2bSxcbiAgICAgIG1vZGVsU2VydmljZTogVXNlcnNTZXJ2aWNlLFxuICAgICAgc2VhcmNoT25Jbml0OiBvbkluaXQsXG4gICAgICBvcHRpb25zOiB7XG4gICAgICAgIHBlclBhZ2U6IDVcbiAgICAgIH1cbiAgICB9KTtcblxuICAgIGZ1bmN0aW9uIG9uQWN0aXZhdGUoKSB7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMgPSB7fTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBhcHBseUZpbHRlcnMoKSB7XG4gICAgICByZXR1cm4gYW5ndWxhci5leHRlbmQodm0uZGVmYXVsdFF1ZXJ5RmlsdGVycywgdm0ucXVlcnlGaWx0ZXJzKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBjbG9zZSgpIHtcbiAgICAgIFByRGlhbG9nLmNsb3NlKCk7XG4gICAgfVxuXG4gIH1cblxufSkoKTtcbiJdLCJzb3VyY2VSb290IjoiL3NvdXJjZS8ifQ==
