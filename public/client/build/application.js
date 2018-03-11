'use strict';

/*eslint angular/file-name: 0*/
(function () {
  'use strict';

  angular.module('app', ['ngAnimate', 'ngAria', 'ui.router', 'ngProdeb', 'ui.utils.masks', 'text-mask', 'ngMaterial', 'modelFactory', 'md.data.table', 'ngMaterialDatePicker', 'pascalprecht.translate', 'angularFileUpload', 'ngMessages', 'jqwidgets', 'ui.mask', 'ngRoute', 'ngSanitize']);
})();
'use strict';

(function () {
  'use strict';

  config.$inject = ["Global", "$mdThemingProvider", "$modelFactoryProvider", "$translateProvider", "moment", "$mdAriaProvider", "$mdDateLocaleProvider"];
  angular.module('app').config(config);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function config(Global, $mdThemingProvider, $modelFactoryProvider, // NOSONAR
  $translateProvider, moment, $mdAriaProvider, $mdDateLocaleProvider) {

    $translateProvider.useLoader('languageLoader').useSanitizeValueStrategy('escape');

    $translateProvider.usePostCompiling(true);

    moment.locale('pt-BR');

    //os serviços referente aos models vai utilizar como base nas urls
    $modelFactoryProvider.defaultOptions.prefix = Global.apiPath;

    // Configuration theme
    $mdThemingProvider.theme('default').primaryPalette('grey', {
      default: '800'
    }).accentPalette('amber').warnPalette('deep-orange');

    // Enable browser color
    $mdThemingProvider.enableBrowserColor();

    $mdAriaProvider.disableWarnings();

    $mdDateLocaleProvider.formatDate = function (date) {
      return date ? moment(date).format('DD/MM/YYYY') : '';
    };
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
    vm.activeProject = null;

    vm.logout = logout;
    vm.getImagePerfil = getImagePerfil;
    vm.getLogoMenu = getLogoMenu;
    vm.setActiveProject = setActiveProject;
    vm.getActiveProject = getActiveProject;
    vm.removeActiveProject = removeActiveProject;

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

    function getLogoMenu() {
      return Global.imagePath + '/logo-vertical.png';
    }

    function setActiveProject(project) {
      localStorage.setItem('project', project);
    }

    function getActiveProject() {
      return localStorage.getItem('project');
    }

    function removeActiveProject() {
      localStorage.removeItem('project');
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
    resetPasswordUrl: 'app/password/reset',
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

    $urlRouterProvider.when('/password/reset', Global.resetPasswordUrl);
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
      }, function (responseData) {
        if (angular.isFunction(vm.onSearchError)) vm.onSearchError(responseData);
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
      }, function (responseData) {
        if (angular.isFunction(vm.onSearchError)) vm.onSearchError(responseData);
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
      vm.onView = false;
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

  DashboardController.$inject = ["$controller", "$state", "$mdDialog", "$translate", "DashboardsService", "ProjectsService", "moment", "PrToast", "Auth", "Global"];
  angular.module('app').filter('elapsed', function () {
    return function (date) {
      if (!date) return;
      var time = Date.parse(date),
          timeNow = new Date().getTime(),
          difference = timeNow - time,
          seconds = Math.floor(difference / 1000),
          minutes = Math.floor(seconds / 60),
          hours = Math.floor(minutes / 60),
          days = Math.floor(hours / 24),
          months = Math.floor(days / 30);

      if (months > 1) {
        return months + ' meses atrás';
      } else if (months === 1) {
        return '1 mês atrás';
      } else if (days > 1) {
        return days + ' dias atrás';
      } else if (days === 1) {
        return '1 dia atrás';
      } else if (hours > 1) {
        return hours + ' horas atrás';
      } else if (hours === 1) {
        return 'uma hora atrás';
      } else if (minutes > 1) {
        return minutes + ' minutos atrás';
      } else if (minutes === 1) {
        return 'um minuto atrás';
      } else {
        return 'há poucos segundos';
      }
    };
  }).controller('DashboardController', DashboardController);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function DashboardController($controller, $state, $mdDialog, $translate, DashboardsService, ProjectsService, moment, PrToast, Auth, Global) {
    var vm = this;

    //Attributes Block

    //Functions Block
    vm.onActivate = onActivate;
    vm.applyFilters = applyFilters;
    vm.fixDate = fixDate;

    function onActivate() {
      var project = localStorage.getItem('project');

      vm.imagePath = Global.imagePath + '/no_avatar.gif';
      vm.currentUser = Auth.currentUser;
      ProjectsService.query({ project_id: project }).then(function (response) {
        vm.actualProject = response[0];
      });
      vm.queryFilters = { project_id: project };
    }

    function applyFilters(defaultQueryFilters) {
      return angular.extend(defaultQueryFilters, vm.queryFilters);
    }

    function fixDate(dateString) {
      return moment(dateString);
    }

    vm.goToProject = function () {
      $state.go('app.projects', { obj: 'edit', resource: vm.actualProject });
    };

    vm.totalCost = function () {
      var estimated_cost = 0;

      if (vm.actualProject.hour_value_final) {
        vm.actualProject.tasks.forEach(function (task) {
          if (task.estimated_time > 0) {
            estimated_cost += parseFloat(vm.actualProject.hour_value_final) * task.estimated_time;
          }
        });
      }
      return estimated_cost.toLocaleString('Pt-br', { minimumFractionDigits: 2 });
    };

    vm.finalizeProject = function () {
      ProjectsService.verifyReleases({ project_id: vm.actualProject.id }).then(function (response) {
        if (response.success) {
          var confirm = $mdDialog.confirm().title('Finalizar Projeto').htmlContent('Tem certeza que deseja finalizar o projeto ' + vm.actualProject.name + '?<br /> Ainda existem releases não finalizadas.').ok('Sim').cancel('Não');

          $mdDialog.show(confirm).then(function () {
            var reason = $mdDialog.prompt().title('Finalizar Projeto').textContent('Qual o motivo para a finalização do projeto?').placeholder('Motivo').initialValue('').required(true).ok('Confirmar').cancel('Cancelar');

            $mdDialog.show(reason).then(function (reasonText) {
              ProjectsService.finalize({ project_id: vm.actualProject.id, reason: reasonText }).then(function () {
                PrToast.success($translate.instant('messages.projectEndedSuccess'));
                onActivate();
                vm.search();
              }, function () {
                PrToast.Error($translate.instant('messages.projectEndedError'));
              });
            });
          });
        } else {
          var confirm = $mdDialog.confirm().title('Finalizar Projeto').textContent('Tem certeza que deseja finalizar o projeto ' + vm.actualProject.name + '?').ok('Sim').cancel('Não');

          $mdDialog.show(confirm).then(function () {
            ProjectsService.finalize({ project_id: vm.actualProject.id }).then(function () {
              PrToast.success($translate.instant('messages.projectEndedSuccess'));
              onActivate();
              vm.search();
            }, function () {
              PrToast.Error($translate.instant('messages.projectEndedError'));
            });
          });
        }
      });
    };

    // instantiate base controller
    $controller('CRUDController', { vm: vm, modelService: DashboardsService, options: {} });
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
    $stateProvider.state('app.dashboard', {
      url: '/dashboards',
      templateUrl: Global.clientPath + '/dashboard/dashboard.html',
      controller: 'DashboardController as dashboardCtrl',
      data: { needAuthentication: true },
      obj: { resource: null }
    });
  }
})();
'use strict';

(function () {
  'use strict';

  DashboardsService.$inject = ["serviceFactory"];
  angular.module('app').factory('DashboardsService', DashboardsService);

  /** @ngInject */
  function DashboardsService(serviceFactory) {
    return serviceFactory('dashboards', {
      actions: {},
      instance: {}
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
              } else if (rejection.data.error !== 'Not Found') {
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

(function () {

  'use strict';

  KanbanController.$inject = ["$controller", "TasksService", "StatusService", "PrToast", "$mdDialog", "$document", "Auth", "ProjectsService"];
  angular.module('app').controller('KanbanController', KanbanController);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function KanbanController($controller, TasksService, StatusService, PrToast, $mdDialog, $document, Auth, ProjectsService) {
    //Attributes Block
    var vm = this;
    var fields = [{ name: 'id', type: 'string' }, { name: 'status', map: 'state', type: 'string' }, { name: 'text', map: 'label', type: 'string' }, { name: 'tags', type: 'string' }];

    vm.onActivate = function () {
      vm.project = localStorage.getItem('project');
      ProjectsService.query({ project_id: vm.project }).then(function (response) {
        vm.actualProject = response[0];
      });
      vm.queryFilters = { project_id: vm.project };
      vm.isMoved = false;
    };

    vm.applyFilters = function (defaultQueryFilters) {
      return angular.extend(defaultQueryFilters, vm.queryFilters);
    };

    vm.afterSearch = function () {
      var columns = [];
      var tasks = [];

      StatusService.query().then(function (response) {
        response.forEach(function (status) {
          columns.push({ text: status.name, dataField: status.slug, collapsible: false });
        });

        if (vm.resources.length > 0) {
          vm.resources.forEach(function (task) {
            tasks.push({
              id: task.id,
              state: task.status.slug,
              label: task.title,
              tags: task.type.name + ', ' + task.priority.name
            });
          });

          var source = {
            localData: tasks,
            dataType: 'array',
            dataFields: fields
          };
          var dataAdapter = new $.jqx.dataAdapter(source);

          vm.settings = {
            source: dataAdapter,
            columns: columns,
            theme: 'light'
          };
        } else {
          vm.settings = {
            source: [{}],
            columns: columns,
            theme: 'light'
          };
        }
        vm.kanbanReady = true;
      });
    };

    vm.onItemMoved = function (event) {
      if (!vm.actualProject.done && Auth.currentUser.id === vm.actualProject.owner) {
        vm.isMoved = true;
        TasksService.query({ task_id: event.args.itemId }).then(function (response) {
          if (response[0].milestone && response[0].milestone.done || response[0].project.done) {
            PrToast.error('Não é possível modificar o status de uma tarefa finalizada.');
            vm.afterSearch();
            vm.isMoved = false;
          } else {
            TasksService.updateTaskByKanban({
              project_id: vm.project,
              id: event.args.itemId,
              oldColumn: event.args.oldColumn,
              newColumn: event.args.newColumn }).then(function () {
              vm.isMoved = false;
            });
          }
        });
      } else {
        vm.afterSearch();
      }
    };

    vm.onItemClicked = function (event) {
      if (!vm.isMoved) {
        TasksService.query({ task_id: event.args.itemId }).then(function (response) {
          vm.taskInfo = response[0];
          $mdDialog.show({
            parent: angular.element($document.body),
            templateUrl: 'client/app/kanban/task-info-dialog/taskInfo.html',
            controllerAs: 'taskInfoCtrl',
            controller: 'TaskInfoController',
            bindToController: true,
            locals: {
              task: vm.taskInfo,
              close: close
            },
            escapeToClose: true,
            clickOutsideToClose: true
          });
        });
      } else {
        vm.isMoved = false;
      }
    };

    function close() {
      $mdDialog.hide();
    }

    // instantiate base controller
    $controller('CRUDController', { vm: vm, modelService: TasksService, options: {} });
  }
})();
'use strict';

(function () {
  'use strict';

  routes.$inject = ["$stateProvider", "Global"];
  angular.module('app').config(routes);

  /**
   * Arquivo de configuração com as rotas específicas do recurso kanban
   *
   * @param {object} $stateProvider
   * @param {object} Global
   */
  /** @ngInject */
  function routes($stateProvider, Global) {
    $stateProvider.state('app.kanban', {
      url: '/kanban',
      templateUrl: Global.clientPath + '/kanban/kanban.html',
      controller: 'KanbanController as kanbanCtrl',
      data: {}
    });
  }
})();
'use strict';

(function () {
  'use strict';

  KanbanService.$inject = ["serviceFactory"];
  angular.module('app').factory('KanbanService', KanbanService);

  /** @ngInject */
  function KanbanService(serviceFactory) {
    var model = serviceFactory('kanban', {
      actions: {},
      instance: {}
    });

    return model;
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
      vm.itensMenu = [{ state: 'app.projects', title: menuPrefix + 'projects', icon: 'work', subItens: [] }, { state: 'app.dashboard', title: menuPrefix + 'dashboard', icon: 'dashboard', subItens: [] }, { state: 'app.tasks', title: menuPrefix + 'tasks', icon: 'view_list', subItens: [] }, { state: 'app.milestones', title: menuPrefix + 'milestones', icon: 'view_module', subItens: [] }, { state: 'app.releases', title: menuPrefix + 'releases', icon: 'subscriptions', subItens: [] }, { state: 'app.kanban', title: menuPrefix + 'kanban', icon: 'view_column', subItens: [] }, { state: 'app.vcs', title: menuPrefix + 'vcs', icon: 'group_work', subItens: []
        // Coloque seus itens de menu a partir deste ponto
        /* {
          state: '#', title: menuPrefix + 'admin', icon: 'settings_applications', profiles: ['admin'],
          subItens: [
            { state: 'app.user', title: menuPrefix + 'user', icon: 'people' },
            { state: 'app.mail', title: menuPrefix + 'mail', icon: 'mail' },
            { state: 'app.audit', title: menuPrefix + 'audit', icon: 'storage' },
            { state: 'app.dinamic-query', title: menuPrefix + 'dinamicQuery', icon: 'location_searching' }
          ]
        } */
      }];

      /**
       * Objeto que preenche o ng-style do menu lateral trocando as cores
       */
      vm.sidenavStyle = {
        top: {
          'border-bottom': '1px solid rgb(210, 210, 210)',
          'background-image': '-webkit-linear-gradient(top, rgb(144, 144, 144), rgb(210, 210, 210))'
        },
        content: {
          'background-color': 'rgb(210, 210, 210)'
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
     * caso contrário redireciona para o state passado como parÃ¢metro
     */
    function openMenuOrRedirectToState($mdMenu, ev, item) {
      if (angular.isDefined(item.subItens) && item.subItens.length > 0) {
        $mdMenu.open(ev);
      } else {
        $state.go(item.state, { obj: null });
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

  MilestonesController.$inject = ["$controller", "MilestonesService", "moment", "TasksService", "ProjectsService", "PrToast", "$translate", "$mdDialog", "Auth"];
  angular.module('app').controller('MilestonesController', MilestonesController);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function MilestonesController($controller, MilestonesService, moment, TasksService, ProjectsService, PrToast, $translate, $mdDialog, Auth) {

    var vm = this;

    vm.estimatedPrice = estimatedPrice;

    vm.onActivate = function () {
      vm.currentUser = Auth.currentUser;
      vm.project = localStorage.getItem('project');
      ProjectsService.query({ project_id: vm.project }).then(function (response) {
        vm.actualProject = response[0];
      });
      vm.queryFilters = { project_id: vm.project };
    };

    function estimatedPrice(milestone) {
      milestone.estimated_value = 0;
      if (milestone.tasks.length > 0 && milestone.project.hour_value_final) {
        milestone.tasks.forEach(function (task) {
          milestone.estimated_value += parseFloat(milestone.project.hour_value_final) * task.estimated_time;
        });
      }
      return milestone.estimated_value.toLocaleString('Pt-br', { minimumFractionDigits: 2 });
    }

    vm.estimatedTime = function (milestone) {
      milestone.estimated_time = 0;
      if (milestone.tasks.length > 0) {
        milestone.tasks.forEach(function (task) {
          milestone.estimated_time += task.estimated_time;
        });
      }
      milestone.estimated_time = milestone.estimated_time / 8;
      var dateEnd = moment(milestone.date_end);
      var dateBegin = moment(milestone.date_begin);

      if (dateEnd.diff(dateBegin, 'days') < milestone.estimated_time) {
        milestone.color_estimated_time = { color: 'red' };
      } else {
        milestone.color_estimated_time = { color: 'green' };
      }
      return milestone.estimated_time;
    };

    vm.applyFilters = function (defaultQueryFilters) {
      return angular.extend(defaultQueryFilters, vm.queryFilters);
    };

    vm.beforeSave = function () {
      vm.resource.project_id = vm.project;
    };

    vm.beforeRemove = function () {
      vm.resource.project_id = vm.project;
    };

    vm.formatDate = function (date) {
      return moment(date).format('DD/MM/YYYY');
    };

    vm.afterEdit = function () {
      vm.resource.date_begin = moment(vm.resource.date_begin)._d;
      vm.resource.date_end = moment(vm.resource.date_end)._d;
    };

    vm.view = function (resource) {
      vm.resource = resource;
      vm.resource.date_begin = moment(vm.resource.date_begin);
      vm.resource.date_end = moment(vm.resource.date_end);
      vm.onView = true;
      vm.viewForm = false;
    };

    vm.searchTask = function (taskTerm) {
      return TasksService.query({
        milestoneSearch: true,
        project_id: vm.resource.project_id,
        title: taskTerm
      });
    };

    vm.onTaskChange = function () {
      if (vm.task !== null && vm.resource.tasks.findIndex(function (i) {
        return i.id === vm.task.id;
      }) === -1) {
        vm.resource.tasks.push(vm.task);
      }
    };

    vm.removeTask = function (task) {
      vm.resource.tasks.slice(0).forEach(function (element) {
        if (element.id === task.id) {
          vm.resource.tasks.splice(vm.resource.tasks.indexOf(element), 1);
        }
      });
    };

    vm.saveTasks = function () {
      TasksService.updateMilestone({ project_id: vm.resource.project_id, milestone_id: vm.resource.id, tasks: vm.resource.tasks }).then(function () {
        PrToast.success($translate.instant('messages.saveSuccess'));
        vm.viewForm = false;
        vm.onView = false;
      }, function () {
        PrToast.error($translate.instant('messages.operationError'));
      });
    };

    vm.finalize = function (milestone) {
      var confirm = $mdDialog.confirm().title('Finalizar Sprint').textContent('Tem certeza que deseja finalizar a sprint ' + milestone.title + '?').ok('Sim').cancel('Não');

      $mdDialog.show(confirm).then(function () {
        MilestonesService.finalize({ project_id: vm.project, milestone_id: milestone.id }).then(function () {
          PrToast.success($translate.instant('messages.sprintEndedSuccess'));
          vm.search();
        }, function () {
          PrToast.Error($translate.instant('messages.sprintEndedError'));
        });
      });
    };

    // instantiate base controller
    $controller('CRUDController', { vm: vm, modelService: MilestonesService, options: {} });
  }
})();
'use strict';

(function () {
  'use strict';

  routes.$inject = ["$stateProvider", "Global"];
  angular.module('app').config(routes);

  /**
   * Arquivo de configuração com as rotas específicas do recurso milestones
   *
   * @param {object} $stateProvider
   * @param {object} Global
   */
  /** @ngInject */
  function routes($stateProvider, Global) {
    $stateProvider.state('app.milestones', {
      url: '/milestones',
      templateUrl: Global.clientPath + '/milestones/milestones.html',
      controller: 'MilestonesController as milestonesCtrl',
      data: {}
    });
  }
})();
'use strict';

(function () {
  'use strict';

  MilestonesService.$inject = ["serviceFactory"];
  angular.module('app').factory('MilestonesService', MilestonesService);

  /** @ngInject */
  function MilestonesService(serviceFactory) {
    var model = serviceFactory('milestones', {
      actions: {
        finalize: {
          method: 'POST',
          url: 'finalize'
        },
        updateRelease: {
          method: 'POST',
          url: 'updateRelease'
        }
      },
      instance: {}
    });

    return model;
  }
})();
'use strict';

(function () {
  'use strict';

  PrioritiesService.$inject = ["serviceFactory"];
  angular.module('app').factory('PrioritiesService', PrioritiesService);

  /** @ngInject */
  function PrioritiesService(serviceFactory) {
    var model = serviceFactory('priorities', {
      actions: {},
      instance: {}
    });

    return model;
  }
})();
'use strict';

(function () {

  'use strict';

  ProjectsController.$inject = ["$controller", "ProjectsService", "Auth", "RolesService", "UsersService", "$state", "$filter", "$stateParams", "$window"];
  angular.module('app').controller('ProjectsController', ProjectsController);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function ProjectsController($controller, ProjectsService, Auth, RolesService, UsersService, $state, $filter, $stateParams, $window) {
    var vm = this;

    //Attributes Block

    //Functions Block
    vm.onActivate = onActivate;
    vm.applyFilters = applyFilters;
    vm.beforeSave = beforeSave;
    vm.searchUser = searchUser;
    vm.addUser = addUser;
    vm.removeUser = removeUser;
    vm.viewProject = viewProject;

    vm.roles = {};
    vm.users = [];

    function onActivate() {
      vm.currentUser = Auth.currentUser;
      vm.queryFilters = { user_id: vm.currentUser.id };
      RolesService.query().then(function (response) {
        vm.roles = response;
        if ($stateParams.obj === 'edit') {
          vm.cleanForm();
          vm.viewForm = true;
          vm.resource = $stateParams.resource;
          usersArray(vm.resource);
        } else {
          localStorage.removeItem('project');
        }
      });
    }

    function applyFilters(defaultQueryFilters) {
      return angular.extend(defaultQueryFilters, vm.querylters);
    }

    function beforeSave() {
      if (!vm.resource.owner) {
        vm.resource.owner = Auth.currentUser.id;
      }
      vm.resource.user_id = Auth.currentUser.id;
    }

    function searchUser() {
      return UsersService.query({ name: vm.userName });
    }

    function addUser(user) {
      if (!vm.resource.users) {
        vm.resource.users = [];
      }
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

    function viewProject() {
      $state.go('app.dashboard');
    }

    vm.afterSearch = function () {
      if (vm.resources.length > 0) {
        vm.resources.forEach(function (project) {
          usersArray(project);
        });
      }
    };

    function usersArray(project) {
      project.users = [];
      if (project.client_id) {
        project.client.role = $filter('filter')(vm.roles, { slug: 'client' })[0];
        project.users.push(project.client);
      }
      if (project.dev_id) {
        project.developer.role = $filter('filter')(vm.roles, { slug: 'dev' })[0];
        project.users.push(project.developer);
      }
      if (project.stakeholder_id) {
        project.stakeholder.role = $filter('filter')(vm.roles, { slug: 'stakeholder' })[0];
        project.users.push(project.stakeholder);
      }
    }

    vm.historyBack = function () {
      if ($stateParams.obj) {
        $window.history.back();
      } else {
        vm.viewForm = false;
      }
    };

    vm.afterSave = function (resource) {
      localStorage.setItem('project', resource.id);
      $state.go('app.dashboard');
    };

    // instantiate base controller
    $controller('CRUDController', { vm: vm, modelService: ProjectsService, options: { redirectAfterSave: false } });
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
      data: { needAuthentication: true },
      params: { obj: null, resource: null }
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
      actions: {
        finalize: {
          method: 'POST',
          url: 'finalize'
        },
        verifyReleases: {
          method: 'POST',
          url: 'verifyReleases'
        }
      },
      instance: {}
    });
  }
})();
'use strict';

(function () {

  'use strict';

  ReleasesController.$inject = ["$controller", "ReleasesService", "MilestonesService", "ProjectsService", "Auth", "PrToast", "moment", "$mdDialog", "$translate"];
  angular.module('app').controller('ReleasesController', ReleasesController);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function ReleasesController($controller, ReleasesService, MilestonesService, ProjectsService, Auth, PrToast, moment, $mdDialog, $translate) {
    var vm = this;

    //Attributes Block
    vm.applyFilters = applyFilters;

    //Functions Block
    vm.onActivate = function () {
      vm.currentUser = Auth.currentUser;
      vm.project = localStorage.getItem('project');
      ProjectsService.query({ project_id: vm.project }).then(function (response) {
        vm.actualProject = response[0];
      });
      vm.queryFilters = { project_id: vm.project };
    };

    function applyFilters(defaultQueryFilters) {
      return angular.extend(defaultQueryFilters, vm.queryFilters);
    }

    vm.beforeSave = function () {
      vm.resource.project_id = vm.project;
    };

    vm.beforeRemove = function () {
      vm.resource.project_id = vm.project;
    };

    vm.view = function (resource) {
      vm.resource = resource;
      vm.onView = true;
      vm.viewForm = false;
    };

    vm.finalize = function (release) {
      var confirm = $mdDialog.confirm().title('Finalizar Release').textContent('Tem certeza que deseja finalizar a release ' + release.title + '?').ok('Sim').cancel('Não');

      $mdDialog.show(confirm).then(function () {
        ReleasesService.finalize({ project_id: vm.project, release_id: release.id }).then(function () {
          PrToast.success($translate.instant('messages.releaseEndedSuccess'));
          vm.search();
        }, function () {
          PrToast.Error($translate.instant('messages.releaseEndedError'));
        });
      });
    };

    vm.formatDate = function (date) {
      return moment(date).format('DD/MM/YYYY');
    };

    vm.searchMilestone = function (milestoneTerm) {
      return MilestonesService.query({
        releaseSearch: true,
        project_id: vm.resource.project_id,
        title: milestoneTerm
      });
    };

    vm.onMilestoneChange = function () {
      if (vm.milestone !== null && vm.resource.milestones.findIndex(function (i) {
        return i.id === vm.milestone.id;
      }) === -1) {
        vm.resource.milestones.push(vm.milestone);
      }
    };

    vm.removeMilestone = function (milestone) {
      vm.resource.milestones.slice(0).forEach(function (element) {
        if (element.id === milestone.id) {
          vm.resource.milestones.splice(vm.resource.milestones.indexOf(element), 1);
        }
      });
    };

    vm.saveMilestones = function () {
      MilestonesService.updateRelease({ project_id: vm.resource.project_id, release_id: vm.resource.id, milestones: vm.resource.milestones }).then(function () {
        PrToast.success($translate.instant('messages.saveSuccess'));
        vm.viewForm = false;
        vm.onView = false;
      }, function () {
        PrToast.error($translate.instant('messages.operationError'));
      });
    };

    vm.estimatedTime = function (milestone) {
      milestone.estimated_time = 0;
      if (milestone.tasks.length > 0) {
        milestone.tasks.forEach(function (task) {
          milestone.estimated_time += task.estimated_time;
        });
      }
      return milestone.estimated_time / 8;
    };

    // instantiate base controller
    $controller('CRUDController', { vm: vm, modelService: ReleasesService, options: {} });
  }
})();
'use strict';

(function () {
  'use strict';

  routes.$inject = ["$stateProvider", "Global"];
  angular.module('app').config(routes);

  /**
   * Arquivo de configuração com as rotas específicas do recurso releases
   *
   * @param {object} $stateProvider
   * @param {object} Global
   */
  /** @ngInject */
  function routes($stateProvider, Global) {
    $stateProvider.state('app.releases', {
      url: '/releases',
      templateUrl: Global.clientPath + '/releases/releases.html',
      controller: 'ReleasesController as releasesCtrl',
      data: {}
    });
  }
})();
'use strict';

(function () {
  'use strict';

  ReleasesService.$inject = ["serviceFactory"];
  angular.module('app').factory('ReleasesService', ReleasesService);

  /** @ngInject */
  function ReleasesService(serviceFactory) {
    var model = serviceFactory('releases', {
      actions: {
        finalize: {
          method: 'POST',
          url: 'finalize'
        }
      },
      instance: {}
    });

    return model;
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

  StatusService.$inject = ["serviceFactory"];
  angular.module('app').factory('StatusService', StatusService);

  /** @ngInject */
  function StatusService(serviceFactory) {
    var model = serviceFactory('status', {
      actions: {},
      instance: {}
    });

    return model;
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

  TaskCommentsService.$inject = ["serviceFactory"];
  angular.module('app').factory('TaskCommentsService', TaskCommentsService);

  /** @ngInject */
  function TaskCommentsService(serviceFactory) {
    var model = serviceFactory('task-comments', {
      actions: {
        saveTaskComment: {
          method: 'POST',
          url: 'saveTaskComment'
        },
        removeTaskComment: {
          method: 'POST',
          url: 'removeTaskComment'
        }
      },
      instance: {}
    });

    return model;
  }
})();
'use strict';

(function () {

  'use strict';

  TasksController.$inject = ["$controller", "TasksService", "StatusService", "PrioritiesService", "TypesService", "TaskCommentsService", "ProjectsService", "moment", "Auth", "PrToast", "$translate", "$filter", "Global"];
  angular.module('app').filter('elapsed', function () {
    return function (date) {
      if (!date) return;
      var time = Date.parse(date),
          timeNow = new Date().getTime(),
          difference = timeNow - time,
          seconds = Math.floor(difference / 1000),
          minutes = Math.floor(seconds / 60),
          hours = Math.floor(minutes / 60),
          days = Math.floor(hours / 24),
          months = Math.floor(days / 30);

      if (months > 1) {
        return months + ' meses atrás';
      } else if (months === 1) {
        return '1 mês atrás';
      } else if (days > 1) {
        return days + ' dias atrás';
      } else if (days === 1) {
        return '1 dia atrás';
      } else if (hours > 1) {
        return hours + ' horas atrás';
      } else if (hours === 1) {
        return 'uma hora atrás';
      } else if (minutes > 1) {
        return minutes + ' minutos atrás';
      } else if (minutes === 1) {
        return 'um minuto atrás';
      } else {
        return 'há poucos segundos';
      }
    };
  }).controller('TasksController', TasksController);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function TasksController($controller, TasksService, StatusService, PrioritiesService, TypesService, TaskCommentsService, ProjectsService, moment, Auth, PrToast, $translate, $filter, Global) {
    var vm = this;

    //Attributes Block

    //Functions Block
    vm.onActivate = onActivate;
    vm.applyFilters = applyFilters;
    vm.beforeSave = beforeSave;
    vm.beforeRemove = beforeRemove;

    function onActivate() {
      vm.currentUser = Auth.currentUser;
      vm.imagePath = Global.imagePath + '/no_avatar.gif';
      vm.project = localStorage.getItem('project');
      ProjectsService.query({ project_id: vm.project }).then(function (response) {
        vm.actualProject = response[0];
      });
      vm.queryFilters = { project_id: vm.project };

      StatusService.query().then(function (response) {
        vm.status = response;
      });

      PrioritiesService.query().then(function (response) {
        vm.priorities = response;
      });

      TypesService.query().then(function (response) {
        vm.types = response;
      });
    }

    function applyFilters(defaultQueryFilters) {
      return angular.extend(defaultQueryFilters, vm.queryFilters);
    }

    function beforeSave() {
      vm.resource.project_id = vm.project;
    }

    function beforeRemove() {
      vm.resource.project_id = vm.project;
    }

    vm.view = function (resource) {
      vm.resource = resource;
      vm.onView = true;
      vm.viewForm = false;
    };

    vm.saveComment = function (comment) {
      var description = '';
      var comment_id = null;

      if (comment) {
        description = vm.answer;
        comment_id = comment.id;
      } else {
        description = vm.comment;
      }
      TaskCommentsService.saveTaskComment({ project_id: vm.project, task_id: vm.resource.id, comment_text: description, comment_id: comment_id }).then(function () {
        vm.comment = '';
        vm.answer = '';
        vm.search();
        PrToast.success($translate.instant('messages.saveSuccess'));
      }, function () {
        PrToast.error($translate.instant('messages.operationError'));
      });
    };

    vm.removeComment = function (comment) {
      TaskCommentsService.removeTaskComment({ comment_id: comment.id }).then(function () {
        vm.search();
        PrToast.success($translate.instant('messages.removeSuccess'));
      }, function () {
        PrToast.error($translate.instant('messages.operationError'));
      });
    };

    vm.afterSearch = function () {
      if (vm.resource.id) {
        vm.resource = $filter('filter')(vm.resources, { id: vm.resource.id })[0];
      }
    };

    vm.fixDate = function (dateString) {
      return moment(dateString);
    };

    // instantiate base controller
    $controller('CRUDController', { vm: vm, modelService: TasksService, options: { skipPagination: true } });
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
    $stateProvider.state('app.tasks', {
      url: '/tasks',
      templateUrl: Global.clientPath + '/tasks/tasks.html',
      controller: 'TasksController as tasksCtrl',
      data: { needAuthentication: true }
    });
  }
})();
'use strict';

(function () {
  'use strict';

  TasksService.$inject = ["serviceFactory"];
  angular.module('app').factory('TasksService', TasksService);

  /** @ngInject */
  function TasksService(serviceFactory) {
    return serviceFactory('tasks', {
      actions: {
        updateMilestone: {
          method: 'POST',
          url: 'updateMilestone'
        },
        updateTaskByKanban: {
          method: 'POST',
          url: 'updateTaskByKanban'
        }
      },
      instance: {}
    });
  }
})();
'use strict';

(function () {
  'use strict';

  TypesService.$inject = ["serviceFactory"];
  angular.module('app').factory('TypesService', TypesService);

  /** @ngInject */
  function TypesService(serviceFactory) {
    var model = serviceFactory('types', {
      actions: {},
      instance: {}
    });

    return model;
  }
})();
'use strict';

(function () {

  'use strict';

  ProfileController.$inject = ["UsersService", "Auth", "PrToast", "$translate", "$window", "moment"];
  angular.module('app').controller('ProfileController', ProfileController);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function ProfileController(UsersService, Auth, PrToast, $translate, $window, moment) {
    var vm = this;

    vm.update = update;
    vm.historyBack = historyBack;

    activate();

    function activate() {
      vm.user = angular.copy(Auth.currentUser);
      if (vm.user.birthday) {
        vm.user.birthday = moment(vm.user.birthday).format('DD/MM/YYYY');
      }
    }

    function update() {
      if (vm.user.birthday) {
        vm.user.birthday = moment(vm.user.birthday);
      }
      UsersService.updateProfile(vm.user).then(function (response) {
        //atualiza o usuário corrente com as novas informações
        Auth.updateCurrentUser(response);
        PrToast.success($translate.instant('messages.saveSuccess'));
        historyBack();
      });
    }

    function historyBack() {
      $window.history.back();
    }
  }
})();
'use strict';

(function () {

  'use strict';

  UsersController.$inject = ["$controller", "UsersService", "PrToast", "$mdDialog", "$translate"];
  angular.module('app').controller('UsersController', UsersController);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function UsersController($controller, UsersService, PrToast, $mdDialog, $translate) {

    var vm = this;

    vm.onActivate = onActivate;
    // instantiate base controller
    $controller('CRUDController', { vm: vm, modelService: UsersService, options: {} });

    function onActivate() {
      vm.queryFilters = {};
    }

    vm.hideDialog = function () {
      $mdDialog.hide();
    };

    vm.saveNewUser = function () {
      vm.resource.$save().then(function (resource) {
        vm.resource = resource;
        PrToast.success($translate.instant('messages.successSignUp'));
        $mdDialog.hide();
      });
    };
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

//token cacb91235873a8c4875d23578ac9f326ef894b66
// OAtuth https://github.com/login/oauth/authorize?client_id=829468e7fdee79445ba6&scope=user,public_repo&redirect_uri=http://0.0.0.0:5000/#!/app/vcs

(function () {
  'use strict';

  VcsController.$inject = ["$controller", "VcsService", "$window", "ProjectsService", "PrToast", "$translate"];
  angular.module('app').filter('bytes', function () {
    return function (bytes, precision) {
      if (isNaN(parseFloat(bytes)) || !isFinite(bytes)) return '-';
      if (typeof precision === 'undefined') precision = 1;
      var units = ['bytes', 'kB', 'MB', 'GB', 'TB', 'PB'],
          number = Math.floor(Math.log(bytes) / Math.log(1024));

      return (bytes / Math.pow(1024, Math.floor(number))).toFixed(precision) + ' ' + units[number];
    };
  }).controller('VcsController', VcsController);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function VcsController($controller, VcsService, $window, ProjectsService, PrToast, $translate) {
    var vm = this;

    vm.index = 0;
    vm.paths = [];

    //Attributes Block

    //Functions Block
    vm.onActivate = function () {
      toggleSplashScreen();
      ProjectsService.query({ project_id: localStorage.getItem('project') }).then(function (response) {
        vm.username = response[0].username_github;
        vm.repo = response[0].repo_github;
        if (vm.username && vm.repo) {
          vm.queryFilters = {
            username: vm.username,
            repo: vm.repo,
            path: '.'
          };
          vm.paths.push(vm.queryFilters.path);
          vm.search();
        } else {
          $window.loading_screen.finish();
        }
      });
    };

    vm.applyFilters = function (defaultQueryFilters) {
      return angular.extend(defaultQueryFilters, vm.queryFilters);
    };

    vm.afterSearch = function () {
      sortResources();
      $window.loading_screen.finish();
    };

    function sortResources() {
      if (vm.resources.length > 0) {
        vm.resources.sort(function (a, b) {
          return a.type < b.type ? -1 : a.type > b.type ? 1 : 0;
        });
      }
    }

    vm.openFileOrDirectory = function (resource) {
      toggleSplashScreen();
      if (resource) {
        vm.queryFilters.path = resource.path;
        vm.paths.push(vm.queryFilters.path);
        vm.index++;
      } else {
        vm.queryFilters.path = vm.paths[vm.index - 1];
        vm.paths.splice(vm.index, 1);
        vm.index--;
      }
      vm.search();
    };

    vm.onSearchError = function (response) {
      if (response.data.error === 'Not Found') {
        PrToast.info($translate.instant('Repositório não encontrado'));
        $window.loading_screen.finish();
      }
    };

    /**
     * Método para mostrar a tela de espera
     */
    function toggleSplashScreen() {
      $window.loading_screen = $window.pleaseWait({
        logo: '',
        backgroundColor: 'rgba(255,255,255,0.4)',
        loadingHtml: '<div class="spinner"> ' + '  <div class="rect1"></div> ' + '  <div class="rect2"></div> ' + '  <div class="rect3"></div> ' + '  <div class="rect4"></div> ' + '  <div class="rect5"></div> ' + ' <p class="loading-message">Carregando</p> ' + '</div>'
      });
    }

    // instantiate base controller
    $controller('CRUDController', { vm: vm, modelService: VcsService, options: { skipPagination: true, searchOnInit: false } });
  }
})();
'use strict';

(function () {
  'use strict';

  routes.$inject = ["$stateProvider", "Global"];
  angular.module('app').config(routes);

  /**
   * Arquivo de configuração com as rotas específicas do recurso vcs
   *
   * @param {object} $stateProvider
   * @param {object} Global
   */
  /** @ngInject */
  function routes($stateProvider, Global) {
    $stateProvider.state('app.vcs', {
      url: '/vcs',
      templateUrl: Global.clientPath + '/vcs/vcs.html',
      controller: 'VcsController as vcsCtrl',
      data: {}
    });
  }
})();
'use strict';

(function () {
  'use strict';

  VcsService.$inject = ["serviceFactory"];
  angular.module('app').factory('VcsService', VcsService);

  /** @ngInject */
  function VcsService(serviceFactory) {
    var model = serviceFactory('vcs', {
      actions: {},
      instance: {}
    });

    return model;
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
    birthday: 'Data de Nascimento',
    task: {
      description: 'Descrição',
      done: 'Feito?',
      priority: 'Prioridade',
      scheduled_to: 'Agendado Para?',
      project: 'Projeto',
      status: 'Status',
      title: 'Título',
      type: 'Tipo',
      milestone: 'Sprint',
      estimated_time: 'Tempo Estimado'
    },
    milestone: {
      title: 'Título',
      description: 'Descrição',
      date_start: 'Data Estimada para Início',
      date_end: 'Data Estimada para Fim',
      estimated_time: 'Tempo Estimado',
      estimated_value: 'Valor Estimado'
    },
    project: {
      cost: 'Custo',
      hourValueDeveloper: 'Valor da Hora Desenvolvedor',
      hourValueClient: 'Valor da Hora Cliente',
      hourValueFinal: 'Valor da Hora Projeto'
    },
    release: {
      title: 'Título',
      description: 'Descrição',
      release_date: 'Data de Entrega',
      milestone: 'Milestone',
      tasks: 'Tarefas'
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
    sprintEndedSuccess: 'Sprint finalizada com sucesso',
    sprintEndedError: 'Erro ao finalizar a sprint',
    successSignUp: 'Cadastro realizado com sucesso. Um e-mail foi enviado com seus dados de login',
    errorsSignUp: 'Houve um erro ao realizar o seu cadastro. Tente novamente mais tarde!',
    releasetEndedSuccess: 'Release finalizada com sucesso',
    releaseEndedError: 'Erro ao finalizar a release',
    projectEndedSuccess: 'Projeto finalizado com sucesso',
    projectEndedError: 'Erro ao finalizar o projeto',
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
      'not-authorized': 'Acesso Negado',
      tasks: 'Tarefas',
      milestones: 'Sprints',
      kanban: 'Kanban Board',
      vcs: 'Controle de Versão',
      releases: 'Releases'
    },
    titles: {
      dashboard: 'Dashboard',
      mailSend: 'Enviar e-mail',
      taskList: 'Lista de Tarefas',
      userList: 'Lista de Usuários',
      auditList: 'Lista de Logs',
      register: 'Formulário de Cadastro',
      resetPassword: 'Redefinir Senha',
      update: 'Formulário de Atualização',
      tasks: 'Tarefas',
      milestones: 'Sprints',
      kanban: 'Kanban Board',
      vcs: 'Controle de Versão',
      releases: 'Releases'
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
      projectList: 'Lista de Projetos',
      tasksList: 'Lista de Tarefas',
      milestonesList: 'Lista de Sprints',
      finalize: 'Finalizar',
      reply: 'Responder'
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
        projects: 'Projetos',
        dashboard: 'Dashboard',
        milestones: 'Sprints',
        tasks: 'Tarefas',
        kanban: 'Kanban',
        vcs: 'Controle de Versão',
        releases: 'Releases'
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

  TaskInfoController.$inject = ["$controller", "TasksService", "locals"];
  angular.module('app').controller('TaskInfoController', TaskInfoController);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function TaskInfoController($controller, TasksService, locals) {
    //Attributes Block
    var vm = this;

    vm.closeDialog = closeDialog;

    vm.onActivate = function () {
      vm.task = locals.task;
      vm.task.estimated_time = vm.task.estimated_time.toString() + ' horas';
    };

    function closeDialog() {
      vm.close();
      console.log("fechar");
    }

    // instantiate base controller
    $controller('CRUDController', { vm: vm, modelService: TasksService, options: {} });
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImFwcGxpY2F0aW9uLmpzIiwiYXBwLmpzIiwiYXBwLmNvbmZpZy5qcyIsImFwcC5jb250cm9sbGVyLmpzIiwiYXBwLmV4dGVybmFsLmpzIiwiYXBwLmdsb2JhbC5qcyIsImFwcC5yb3V0ZXMuanMiLCJhcHAucnVuLmpzIiwiYXVkaXQvYXVkaXQuY29udHJvbGxlci5qcyIsImF1ZGl0L2F1ZGl0LnJvdXRlLmpzIiwiYXVkaXQvYXVkaXQuc2VydmljZS5qcyIsImF1dGgvYXV0aC5yb3V0ZS5qcyIsImF1dGgvYXV0aC5zZXJ2aWNlLmpzIiwiYXV0aC9sb2dpbi5jb250cm9sbGVyLmpzIiwiYXV0aC9wYXNzd29yZC5jb250cm9sbGVyLmpzIiwiY29yZS9iYXNlLnNlcnZpY2UuanMiLCJjb3JlL2NydWQuY29udHJvbGxlci5qcyIsImRhc2hib2FyZC9kYXNoYm9hcmQuY29udHJvbGxlci5qcyIsImRhc2hib2FyZC9kYXNoYm9hcmQucm91dGUuanMiLCJkYXNoYm9hcmQvZGFzaGJvYXJkLnNlcnZpY2UuanMiLCJkaW5hbWljLXF1ZXJ5cy9kaW5hbWljLXF1ZXJ5LnJvdXRlLmpzIiwiZGluYW1pYy1xdWVyeXMvZGluYW1pYy1xdWVyeS5zZXJ2aWNlLmpzIiwiZGluYW1pYy1xdWVyeXMvZGluYW1pYy1xdWVyeXMuY29udHJvbGxlci5qcyIsImkxOG4vbGFuZ3VhZ2UtbG9hZGVyLnNlcnZpY2UuanMiLCJpMThuL3QtYXR0ci5maWx0ZXIuanMiLCJpMThuL3QtYnJlYWRjcnVtYi5maWx0ZXIuanMiLCJpMThuL3QtbW9kZWwuZmlsdGVyLmpzIiwiaW50ZXJjZXB0b3JzL2F1dGhlbnRpY2F0aW9uLmxpc3RlbmVyLmpzIiwiaW50ZXJjZXB0b3JzL2F1dGhvcml6YXRpb24ubGlzdGVuZXIuanMiLCJpbnRlcmNlcHRvcnMvc3Bpbm5lci5pbnRlcmNlcHRvci5qcyIsImludGVyY2VwdG9ycy90b2tlbi5pbnRlcmNlcHRvci5qcyIsImludGVyY2VwdG9ycy92YWxpZGF0aW9uLmludGVyY2VwdG9yLmpzIiwia2FuYmFuL2thbmJhbi5jb250cm9sbGVyLmpzIiwia2FuYmFuL2thbmJhbi5yb3V0ZS5qcyIsImthbmJhbi9rYW5iYW4uc2VydmljZS5qcyIsImxheW91dC9tZW51LmNvbnRyb2xsZXIuanMiLCJtYWlsL21haWxzLmNvbnRyb2xsZXIuanMiLCJtYWlsL21haWxzLnJvdXRlLmpzIiwibWFpbC9tYWlscy5zZXJ2aWNlLmpzIiwibWlsZXN0b25lcy9taWxlc3RvbmVzLmNvbnRyb2xsZXIuanMiLCJtaWxlc3RvbmVzL21pbGVzdG9uZXMucm91dGUuanMiLCJtaWxlc3RvbmVzL21pbGVzdG9uZXMuc2VydmljZS5qcyIsInByaW9yaXRpZXMvcHJpb3JpdGllcy5zZXJ2aWNlLmpzIiwicHJvamVjdHMvcHJvamVjdHMuY29udHJvbGxlci5qcyIsInByb2plY3RzL3Byb2plY3RzLnJvdXRlLmpzIiwicHJvamVjdHMvcHJvamVjdHMuc2VydmljZS5qcyIsInJlbGVhc2VzL3JlbGVhc2VzLmNvbnRyb2xsZXIuanMiLCJyZWxlYXNlcy9yZWxlYXNlcy5yb3V0ZS5qcyIsInJlbGVhc2VzL3JlbGVhc2VzLnNlcnZpY2UuanMiLCJyb2xlcy9yb2xlcy1zdHIuZmlsdGVyLmpzIiwicm9sZXMvcm9sZXMuc2VydmljZS5qcyIsInN0YXR1cy9zdGF0dXMuc2VydmljZS5qcyIsInN1cHBvcnQvc3VwcG9ydC5zZXJ2aWNlLmpzIiwidGFzay1jb21tZW50cy90YXNrLWNvbW1lbnRzLnNlcnZpY2UuanMiLCJ0YXNrcy90YXNrcy5jb250cm9sbGVyLmpzIiwidGFza3MvdGFza3Mucm91dGUuanMiLCJ0YXNrcy90YXNrcy5zZXJ2aWNlLmpzIiwidHlwZXMvdHlwZXMuc2VydmljZS5qcyIsInVzZXJzL3Byb2ZpbGUuY29udHJvbGxlci5qcyIsInVzZXJzL3VzZXJzLmNvbnRyb2xsZXIuanMiLCJ1c2Vycy91c2Vycy5yb3V0ZS5qcyIsInVzZXJzL3VzZXJzLnNlcnZpY2UuanMiLCJ2Y3MvdmNzLmNvbnRyb2xsZXIuanMiLCJ2Y3MvdmNzLnJvdXRlLmpzIiwidmNzL3Zjcy5zZXJ2aWNlLmpzIiwid2lkZ2V0cy9ib3guY29tcG9uZW50LmpzIiwid2lkZ2V0cy9jb250ZW50LWJvZHkuY29tcG9uZW50LmpzIiwid2lkZ2V0cy9jb250ZW50LWhlYWRlci5jb21wb25lbnQuanMiLCJhdWRpdC9maWx0ZXJzL2F1ZGl0LWRldGFpbC10aXRsZS5maWx0ZXIuanMiLCJhdWRpdC9maWx0ZXJzL2F1ZGl0LW1vZGVsLmZpbHRlci5qcyIsImF1ZGl0L2ZpbHRlcnMvYXVkaXQtdHlwZS5maWx0ZXIuanMiLCJhdWRpdC9maWx0ZXJzL2F1ZGl0LXZhbHVlLmZpbHRlci5qcyIsImkxOG4vcHQtQlIvYXR0cmlidXRlcy5qcyIsImkxOG4vcHQtQlIvZGlhbG9nLmpzIiwiaTE4bi9wdC1CUi9nbG9iYWwuanMiLCJpMThuL3B0LUJSL21lc3NhZ2VzLmpzIiwiaTE4bi9wdC1CUi9tb2RlbHMuanMiLCJpMThuL3B0LUJSL3ZpZXdzLmpzIiwia2FuYmFuL3Rhc2staW5mby1kaWFsb2cvdGFzay1pbmZvLmNvbnRyb2xsZXIuanMiLCJ1c2Vycy9kaWFsb2cvdXNlcnMtZGlhbG9nLmNvbnRyb2xsZXIuanMiXSwibmFtZXMiOlsiYW5ndWxhciIsIm1vZHVsZSIsImNvbmZpZyIsIkdsb2JhbCIsIiRtZFRoZW1pbmdQcm92aWRlciIsIiRtb2RlbEZhY3RvcnlQcm92aWRlciIsIiR0cmFuc2xhdGVQcm92aWRlciIsIm1vbWVudCIsIiRtZEFyaWFQcm92aWRlciIsIiRtZERhdGVMb2NhbGVQcm92aWRlciIsInVzZUxvYWRlciIsInVzZVNhbml0aXplVmFsdWVTdHJhdGVneSIsInVzZVBvc3RDb21waWxpbmciLCJsb2NhbGUiLCJkZWZhdWx0T3B0aW9ucyIsInByZWZpeCIsImFwaVBhdGgiLCJ0aGVtZSIsInByaW1hcnlQYWxldHRlIiwiZGVmYXVsdCIsImFjY2VudFBhbGV0dGUiLCJ3YXJuUGFsZXR0ZSIsImVuYWJsZUJyb3dzZXJDb2xvciIsImRpc2FibGVXYXJuaW5ncyIsImZvcm1hdERhdGUiLCJkYXRlIiwiZm9ybWF0IiwiY29udHJvbGxlciIsIkFwcENvbnRyb2xsZXIiLCIkc3RhdGUiLCJBdXRoIiwidm0iLCJhbm9BdHVhbCIsImFjdGl2ZVByb2plY3QiLCJsb2dvdXQiLCJnZXRJbWFnZVBlcmZpbCIsImdldExvZ29NZW51Iiwic2V0QWN0aXZlUHJvamVjdCIsImdldEFjdGl2ZVByb2plY3QiLCJyZW1vdmVBY3RpdmVQcm9qZWN0IiwiYWN0aXZhdGUiLCJEYXRlIiwiZ2V0RnVsbFllYXIiLCJ0aGVuIiwiZ28iLCJsb2dpblN0YXRlIiwiY3VycmVudFVzZXIiLCJpbWFnZSIsImltYWdlUGF0aCIsInByb2plY3QiLCJsb2NhbFN0b3JhZ2UiLCJzZXRJdGVtIiwiZ2V0SXRlbSIsInJlbW92ZUl0ZW0iLCJjb25zdGFudCIsIl8iLCJhcHBOYW1lIiwiaG9tZVN0YXRlIiwibG9naW5VcmwiLCJyZXNldFBhc3N3b3JkVXJsIiwicmVzZXRQYXNzd29yZFN0YXRlIiwibm90QXV0aG9yaXplZFN0YXRlIiwidG9rZW5LZXkiLCJjbGllbnRQYXRoIiwicm91dGVzIiwiJHN0YXRlUHJvdmlkZXIiLCIkdXJsUm91dGVyUHJvdmlkZXIiLCJzdGF0ZSIsInVybCIsInRlbXBsYXRlVXJsIiwiYWJzdHJhY3QiLCJyZXNvbHZlIiwidHJhbnNsYXRlUmVhZHkiLCIkdHJhbnNsYXRlIiwiJHEiLCJkZWZlcnJlZCIsImRlZmVyIiwidXNlIiwicHJvbWlzZSIsImRhdGEiLCJuZWVkQXV0aGVudGljYXRpb24iLCJ3aGVuIiwib3RoZXJ3aXNlIiwicnVuIiwiJHJvb3RTY29wZSIsIiRzdGF0ZVBhcmFtcyIsImF1dGgiLCJnbG9iYWwiLCJyZXRyaWV2ZVVzZXJGcm9tTG9jYWxTdG9yYWdlIiwiQXVkaXRDb250cm9sbGVyIiwiJGNvbnRyb2xsZXIiLCJBdWRpdFNlcnZpY2UiLCJQckRpYWxvZyIsIm9uQWN0aXZhdGUiLCJhcHBseUZpbHRlcnMiLCJ2aWV3RGV0YWlsIiwibW9kZWxTZXJ2aWNlIiwib3B0aW9ucyIsIm1vZGVscyIsInF1ZXJ5RmlsdGVycyIsImdldEF1ZGl0ZWRNb2RlbHMiLCJpZCIsImxhYmVsIiwiaW5zdGFudCIsInNvcnQiLCJpbmRleCIsImxlbmd0aCIsIm1vZGVsIiwicHVzaCIsInRvTG93ZXJDYXNlIiwidHlwZXMiLCJsaXN0VHlwZXMiLCJ0eXBlIiwiZGVmYXVsdFF1ZXJ5RmlsdGVycyIsImV4dGVuZCIsImF1ZGl0RGV0YWlsIiwibG9jYWxzIiwiY2xvc2UiLCJpc0FycmF5Iiwib2xkIiwibmV3IiwiY29udHJvbGxlckFzIiwiaGFzQmFja2Ryb3AiLCJjdXN0b20iLCJuZWVkUHJvZmlsZSIsImZhY3RvcnkiLCJzZXJ2aWNlRmFjdG9yeSIsImFjdGlvbnMiLCJtZXRob2QiLCJpbnN0YW5jZSIsImF1ZGl0UGF0aCIsIiRodHRwIiwiVXNlcnNTZXJ2aWNlIiwibG9naW4iLCJ1cGRhdGVDdXJyZW50VXNlciIsImF1dGhlbnRpY2F0ZWQiLCJzZW5kRW1haWxSZXNldFBhc3N3b3JkIiwicmVtb3RlVmFsaWRhdGVUb2tlbiIsImdldFRva2VuIiwic2V0VG9rZW4iLCJjbGVhclRva2VuIiwidG9rZW4iLCJnZXQiLCJyZWplY3QiLCJ1c2VyIiwibWVyZ2UiLCJmcm9tSnNvbiIsImpzb25Vc2VyIiwidG9Kc29uIiwiY3JlZGVudGlhbHMiLCJwb3N0IiwicmVzcG9uc2UiLCJlcnJvciIsInJlc2V0RGF0YSIsIkxvZ2luQ29udHJvbGxlciIsIm9wZW5EaWFsb2dSZXNldFBhc3MiLCJvcGVuRGlhbG9nU2lnblVwIiwiZW1haWwiLCJwYXNzd29yZCIsIlBhc3N3b3JkQ29udHJvbGxlciIsIiR0aW1lb3V0IiwiUHJUb2FzdCIsInNlbmRSZXNldCIsImNsb3NlRGlhbG9nIiwiY2xlYW5Gb3JtIiwicmVzZXQiLCJzdWNjZXNzIiwic3RhdHVzIiwibXNnIiwiaSIsInRvVXBwZXJDYXNlIiwiZmllbGQiLCJtZXNzYWdlIiwiJG1vZGVsRmFjdG9yeSIsInBhZ2luYXRlIiwid3JhcCIsImFmdGVyUmVxdWVzdCIsIkxpc3QiLCJDUlVEQ29udHJvbGxlciIsIlByUGFnaW5hdGlvbiIsInNlYXJjaCIsInBhZ2luYXRlU2VhcmNoIiwibm9ybWFsU2VhcmNoIiwiZWRpdCIsInNhdmUiLCJyZW1vdmUiLCJnb1RvIiwicmVkaXJlY3RBZnRlclNhdmUiLCJzZWFyY2hPbkluaXQiLCJwZXJQYWdlIiwic2tpcFBhZ2luYXRpb24iLCJ2aWV3Rm9ybSIsInJlc291cmNlIiwiaXNGdW5jdGlvbiIsInBhZ2luYXRvciIsImdldEluc3RhbmNlIiwicGFnZSIsImN1cnJlbnRQYWdlIiwiaXNEZWZpbmVkIiwiYmVmb3JlU2VhcmNoIiwiY2FsY051bWJlck9mUGFnZXMiLCJ0b3RhbCIsInJlc291cmNlcyIsIml0ZW1zIiwiYWZ0ZXJTZWFyY2giLCJyZXNwb25zZURhdGEiLCJvblNlYXJjaEVycm9yIiwicXVlcnkiLCJmb3JtIiwiYmVmb3JlQ2xlYW4iLCIkc2V0UHJpc3RpbmUiLCIkc2V0VW50b3VjaGVkIiwiYWZ0ZXJDbGVhbiIsImNvcHkiLCJhZnRlckVkaXQiLCJiZWZvcmVTYXZlIiwiJHNhdmUiLCJhZnRlclNhdmUiLCJvblNhdmVFcnJvciIsInRpdGxlIiwiZGVzY3JpcHRpb24iLCJjb25maXJtIiwiYmVmb3JlUmVtb3ZlIiwiJGRlc3Ryb3kiLCJhZnRlclJlbW92ZSIsImluZm8iLCJ2aWV3TmFtZSIsIm9uVmlldyIsImZpbHRlciIsInRpbWUiLCJwYXJzZSIsInRpbWVOb3ciLCJnZXRUaW1lIiwiZGlmZmVyZW5jZSIsInNlY29uZHMiLCJNYXRoIiwiZmxvb3IiLCJtaW51dGVzIiwiaG91cnMiLCJkYXlzIiwibW9udGhzIiwiRGFzaGJvYXJkQ29udHJvbGxlciIsIiRtZERpYWxvZyIsIkRhc2hib2FyZHNTZXJ2aWNlIiwiUHJvamVjdHNTZXJ2aWNlIiwiZml4RGF0ZSIsInByb2plY3RfaWQiLCJhY3R1YWxQcm9qZWN0IiwiZGF0ZVN0cmluZyIsImdvVG9Qcm9qZWN0Iiwib2JqIiwidG90YWxDb3N0IiwiZXN0aW1hdGVkX2Nvc3QiLCJob3VyX3ZhbHVlX2ZpbmFsIiwidGFza3MiLCJmb3JFYWNoIiwidGFzayIsImVzdGltYXRlZF90aW1lIiwicGFyc2VGbG9hdCIsInRvTG9jYWxlU3RyaW5nIiwibWluaW11bUZyYWN0aW9uRGlnaXRzIiwiZmluYWxpemVQcm9qZWN0IiwidmVyaWZ5UmVsZWFzZXMiLCJodG1sQ29udGVudCIsIm5hbWUiLCJvayIsImNhbmNlbCIsInNob3ciLCJyZWFzb24iLCJwcm9tcHQiLCJ0ZXh0Q29udGVudCIsInBsYWNlaG9sZGVyIiwiaW5pdGlhbFZhbHVlIiwicmVxdWlyZWQiLCJyZWFzb25UZXh0IiwiZmluYWxpemUiLCJFcnJvciIsIkRpbmFtaWNRdWVyeVNlcnZpY2UiLCJnZXRNb2RlbHMiLCJEaW5hbWljUXVlcnlzQ29udHJvbGxlciIsImxvZGFzaCIsImxvYWRBdHRyaWJ1dGVzIiwibG9hZE9wZXJhdG9ycyIsImFkZEZpbHRlciIsInJ1bkZpbHRlciIsImVkaXRGaWx0ZXIiLCJsb2FkTW9kZWxzIiwicmVtb3ZlRmlsdGVyIiwiY2xlYXIiLCJyZXN0YXJ0Iiwid2hlcmUiLCJhZGRlZEZpbHRlcnMiLCJhdHRyaWJ1dGUiLCJvcGVyYXRvciIsInZhbHVlIiwiZmlsdGVycyIsImF0dHJpYnV0ZXMiLCJvcGVyYXRvcnMiLCJpbmRleE9mIiwiaXNVbmRlZmluZWQiLCJrZXlzIiwiT2JqZWN0Iiwia2V5Iiwic3RhcnRzV2l0aCIsIiRpbmRleCIsInNwbGljZSIsIkxhbmd1YWdlTG9hZGVyIiwiU3VwcG9ydFNlcnZpY2UiLCIkbG9nIiwiJGluamVjdG9yIiwic2VydmljZSIsInRyYW5zbGF0ZSIsInZpZXdzIiwiZGlhbG9nIiwibWVzc2FnZXMiLCJsYW5ncyIsInRBdHRyIiwiJGZpbHRlciIsInRCcmVhZGNydW1iIiwic3BsaXQiLCJ0TW9kZWwiLCJhdXRoZW50aWNhdGlvbkxpc3RlbmVyIiwiJG9uIiwiZXZlbnQiLCJ0b1N0YXRlIiwiY2F0Y2giLCJ3YXJuIiwicHJldmVudERlZmF1bHQiLCJhdXRob3JpemF0aW9uTGlzdGVuZXIiLCJoYXNQcm9maWxlIiwiYWxsUHJvZmlsZXMiLCJzcGlubmVySW50ZXJjZXB0b3IiLCIkaHR0cFByb3ZpZGVyIiwiJHByb3ZpZGUiLCJzaG93SGlkZVNwaW5uZXIiLCJyZXF1ZXN0IiwiaGlkZSIsInJlc3BvbnNlRXJyb3IiLCJyZWplY3Rpb24iLCJpbnRlcmNlcHRvcnMiLCJ0b2tlbkludGVyY2VwdG9yIiwicmVkaXJlY3RXaGVuU2VydmVyTG9nZ2VkT3V0IiwiaGVhZGVycyIsInJlamVjdGlvblJlYXNvbnMiLCJ0b2tlbkVycm9yIiwiaXMiLCJ2YWxpZGF0aW9uSW50ZXJjZXB0b3IiLCJzaG93RXJyb3JWYWxpZGF0aW9uIiwic2tpcFZhbGlkYXRpb24iLCJlcnJvclZhbGlkYXRpb24iLCJLYW5iYW5Db250cm9sbGVyIiwiVGFza3NTZXJ2aWNlIiwiU3RhdHVzU2VydmljZSIsIiRkb2N1bWVudCIsImZpZWxkcyIsIm1hcCIsImlzTW92ZWQiLCJjb2x1bW5zIiwidGV4dCIsImRhdGFGaWVsZCIsInNsdWciLCJjb2xsYXBzaWJsZSIsInRhZ3MiLCJwcmlvcml0eSIsInNvdXJjZSIsImxvY2FsRGF0YSIsImRhdGFUeXBlIiwiZGF0YUZpZWxkcyIsImRhdGFBZGFwdGVyIiwiJCIsImpxeCIsInNldHRpbmdzIiwia2FuYmFuUmVhZHkiLCJvbkl0ZW1Nb3ZlZCIsImRvbmUiLCJvd25lciIsInRhc2tfaWQiLCJhcmdzIiwiaXRlbUlkIiwibWlsZXN0b25lIiwidXBkYXRlVGFza0J5S2FuYmFuIiwib2xkQ29sdW1uIiwibmV3Q29sdW1uIiwib25JdGVtQ2xpY2tlZCIsInRhc2tJbmZvIiwicGFyZW50IiwiZWxlbWVudCIsImJvZHkiLCJiaW5kVG9Db250cm9sbGVyIiwiZXNjYXBlVG9DbG9zZSIsImNsaWNrT3V0c2lkZVRvQ2xvc2UiLCJLYW5iYW5TZXJ2aWNlIiwiTWVudUNvbnRyb2xsZXIiLCIkbWRTaWRlbmF2IiwiJG1kQ29sb3JzIiwib3BlbiIsIm9wZW5NZW51T3JSZWRpcmVjdFRvU3RhdGUiLCJtZW51UHJlZml4IiwiaXRlbnNNZW51IiwiaWNvbiIsInN1Ykl0ZW5zIiwic2lkZW5hdlN0eWxlIiwidG9wIiwiY29udGVudCIsInRleHRDb2xvciIsImNvbG9yIiwibGluZUJvdHRvbSIsImdldENvbG9yIiwidG9nZ2xlIiwiJG1kTWVudSIsImV2IiwiaXRlbSIsImNvbG9yUGFsZXR0ZXMiLCJnZXRUaGVtZUNvbG9yIiwiTWFpbHNDb250cm9sbGVyIiwiTWFpbHNTZXJ2aWNlIiwiZmlsdGVyU2VsZWN0ZWQiLCJza2luIiwibGFuZ3VhZ2UiLCJhbGxvd2VkQ29udGVudCIsImVudGl0aWVzIiwiaGVpZ2h0IiwiZXh0cmFQbHVnaW5zIiwibG9hZFVzZXJzIiwib3BlblVzZXJEaWFsb2ciLCJhZGRVc2VyTWFpbCIsInNlbmQiLCJjcml0ZXJpYSIsIm5hbWVPckVtYWlsIiwibm90VXNlcnMiLCJtYWlsIiwidXNlcnMiLCJwcm9wZXJ0eSIsInRvU3RyaW5nIiwibGltaXQiLCJmaW5kIiwib25Jbml0IiwidXNlckRpYWxvZ0lucHV0IiwidHJhbnNmZXJVc2VyRm4iLCJNaWxlc3RvbmVzQ29udHJvbGxlciIsIk1pbGVzdG9uZXNTZXJ2aWNlIiwiZXN0aW1hdGVkUHJpY2UiLCJlc3RpbWF0ZWRfdmFsdWUiLCJlc3RpbWF0ZWRUaW1lIiwiZGF0ZUVuZCIsImRhdGVfZW5kIiwiZGF0ZUJlZ2luIiwiZGF0ZV9iZWdpbiIsImRpZmYiLCJjb2xvcl9lc3RpbWF0ZWRfdGltZSIsIl9kIiwidmlldyIsInNlYXJjaFRhc2siLCJ0YXNrVGVybSIsIm1pbGVzdG9uZVNlYXJjaCIsIm9uVGFza0NoYW5nZSIsImZpbmRJbmRleCIsInJlbW92ZVRhc2siLCJzbGljZSIsInNhdmVUYXNrcyIsInVwZGF0ZU1pbGVzdG9uZSIsIm1pbGVzdG9uZV9pZCIsInVwZGF0ZVJlbGVhc2UiLCJQcmlvcml0aWVzU2VydmljZSIsIlByb2plY3RzQ29udHJvbGxlciIsIlJvbGVzU2VydmljZSIsIiR3aW5kb3ciLCJzZWFyY2hVc2VyIiwiYWRkVXNlciIsInJlbW92ZVVzZXIiLCJ2aWV3UHJvamVjdCIsInJvbGVzIiwidXNlcl9pZCIsInVzZXJzQXJyYXkiLCJxdWVyeWx0ZXJzIiwidXNlck5hbWUiLCJjbGllbnRfaWQiLCJjbGllbnQiLCJyb2xlIiwiZGV2X2lkIiwiZGV2ZWxvcGVyIiwic3Rha2Vob2xkZXJfaWQiLCJzdGFrZWhvbGRlciIsImhpc3RvcnlCYWNrIiwiaGlzdG9yeSIsImJhY2siLCJwYXJhbXMiLCJSZWxlYXNlc0NvbnRyb2xsZXIiLCJSZWxlYXNlc1NlcnZpY2UiLCJyZWxlYXNlIiwicmVsZWFzZV9pZCIsInNlYXJjaE1pbGVzdG9uZSIsIm1pbGVzdG9uZVRlcm0iLCJyZWxlYXNlU2VhcmNoIiwib25NaWxlc3RvbmVDaGFuZ2UiLCJtaWxlc3RvbmVzIiwicmVtb3ZlTWlsZXN0b25lIiwic2F2ZU1pbGVzdG9uZXMiLCJyb2xlc1N0ciIsImpvaW4iLCJjYWNoZSIsIlRhc2tDb21tZW50c1NlcnZpY2UiLCJzYXZlVGFza0NvbW1lbnQiLCJyZW1vdmVUYXNrQ29tbWVudCIsIlRhc2tzQ29udHJvbGxlciIsIlR5cGVzU2VydmljZSIsInByaW9yaXRpZXMiLCJzYXZlQ29tbWVudCIsImNvbW1lbnQiLCJjb21tZW50X2lkIiwiYW5zd2VyIiwiY29tbWVudF90ZXh0IiwicmVtb3ZlQ29tbWVudCIsIlByb2ZpbGVDb250cm9sbGVyIiwidXBkYXRlIiwiYmlydGhkYXkiLCJ1cGRhdGVQcm9maWxlIiwiVXNlcnNDb250cm9sbGVyIiwiaGlkZURpYWxvZyIsInNhdmVOZXdVc2VyIiwiZGVmYXVsdHMiLCJvdmVycmlkZSIsImFsbCIsInVzZXJSb2xlcyIsImludGVyc2VjdGlvbiIsImlzQWRtaW4iLCJieXRlcyIsInByZWNpc2lvbiIsImlzTmFOIiwiaXNGaW5pdGUiLCJ1bml0cyIsIm51bWJlciIsImxvZyIsInBvdyIsInRvRml4ZWQiLCJWY3NDb250cm9sbGVyIiwiVmNzU2VydmljZSIsInBhdGhzIiwidG9nZ2xlU3BsYXNoU2NyZWVuIiwidXNlcm5hbWUiLCJ1c2VybmFtZV9naXRodWIiLCJyZXBvIiwicmVwb19naXRodWIiLCJwYXRoIiwibG9hZGluZ19zY3JlZW4iLCJmaW5pc2giLCJzb3J0UmVzb3VyY2VzIiwiYSIsImIiLCJvcGVuRmlsZU9yRGlyZWN0b3J5IiwicGxlYXNlV2FpdCIsImxvZ28iLCJiYWNrZ3JvdW5kQ29sb3IiLCJsb2FkaW5nSHRtbCIsImNvbXBvbmVudCIsInJlcGxhY2UiLCJ0cmFuc2NsdWRlIiwidG9vbGJhckJ1dHRvbnMiLCJmb290ZXJCdXR0b25zIiwiYmluZGluZ3MiLCJib3hUaXRsZSIsInRvb2xiYXJDbGFzcyIsInRvb2xiYXJCZ0NvbG9yIiwiJHRyYW5zY2x1ZGUiLCJjdHJsIiwiJG9uSW5pdCIsImxheW91dEFsaWduIiwiYXVkaXREZXRhaWxUaXRsZSIsImF1ZGl0TW9kZWwiLCJtb2RlbElkIiwiYXVkaXRUeXBlIiwidHlwZUlkIiwiYXVkaXRWYWx1ZSIsImlzRGF0ZSIsImVuZHNXaXRoIiwiTnVtYmVyIiwiaW5pdGlhbERhdGUiLCJmaW5hbERhdGUiLCJzY2hlZHVsZWRfdG8iLCJkYXRlX3N0YXJ0IiwiY29zdCIsImhvdXJWYWx1ZURldmVsb3BlciIsImhvdXJWYWx1ZUNsaWVudCIsImhvdXJWYWx1ZUZpbmFsIiwicmVsZWFzZV9kYXRlIiwiY29uZmlybVRpdGxlIiwiY29uZmlybURlc2NyaXB0aW9uIiwicmVtb3ZlRGVzY3JpcHRpb24iLCJhdWRpdCIsImNyZWF0ZWQiLCJ1cGRhdGVkQmVmb3JlIiwidXBkYXRlZEFmdGVyIiwiZGVsZXRlZCIsInJlc2V0UGFzc3dvcmQiLCJsb2FkaW5nIiwicHJvY2Vzc2luZyIsInllcyIsIm5vIiwiaW50ZXJuYWxFcnJvciIsIm5vdEZvdW5kIiwibm90QXV0aG9yaXplZCIsInNlYXJjaEVycm9yIiwic2F2ZVN1Y2Nlc3MiLCJvcGVyYXRpb25TdWNjZXNzIiwib3BlcmF0aW9uRXJyb3IiLCJzYXZlRXJyb3IiLCJyZW1vdmVTdWNjZXNzIiwicmVtb3ZlRXJyb3IiLCJyZXNvdXJjZU5vdEZvdW5kRXJyb3IiLCJub3ROdWxsRXJyb3IiLCJkdXBsaWNhdGVkUmVzb3VyY2VFcnJvciIsInNwcmludEVuZGVkU3VjY2VzcyIsInNwcmludEVuZGVkRXJyb3IiLCJzdWNjZXNzU2lnblVwIiwiZXJyb3JzU2lnblVwIiwicmVsZWFzZXRFbmRlZFN1Y2Nlc3MiLCJyZWxlYXNlRW5kZWRFcnJvciIsInByb2plY3RFbmRlZFN1Y2Nlc3MiLCJwcm9qZWN0RW5kZWRFcnJvciIsInZhbGlkYXRlIiwiZmllbGRSZXF1aXJlZCIsImxheW91dCIsImVycm9yNDA0IiwibG9nb3V0SW5hY3RpdmUiLCJpbnZhbGlkQ3JlZGVudGlhbHMiLCJ1bmtub3duRXJyb3IiLCJ1c2VyTm90Rm91bmQiLCJkYXNoYm9hcmQiLCJ3ZWxjb21lIiwibWFpbEVycm9ycyIsInNlbmRNYWlsU3VjY2VzcyIsInNlbmRNYWlsRXJyb3IiLCJwYXNzd29yZFNlbmRpbmdTdWNjZXNzIiwicmVtb3ZlWW91clNlbGZFcnJvciIsInVzZXJFeGlzdHMiLCJwcm9maWxlIiwidXBkYXRlRXJyb3IiLCJxdWVyeURpbmFtaWMiLCJub0ZpbHRlciIsImJyZWFkY3J1bWJzIiwicHJvamVjdHMiLCJrYW5iYW4iLCJ2Y3MiLCJyZWxlYXNlcyIsInRpdGxlcyIsIm1haWxTZW5kIiwidGFza0xpc3QiLCJ1c2VyTGlzdCIsImF1ZGl0TGlzdCIsInJlZ2lzdGVyIiwiY2xlYXJBbGwiLCJsaXN0IiwiZ2V0T3V0IiwiYWRkIiwiaW4iLCJsb2FkSW1hZ2UiLCJzaWdudXAiLCJjcmlhclByb2pldG8iLCJwcm9qZWN0TGlzdCIsInRhc2tzTGlzdCIsIm1pbGVzdG9uZXNMaXN0IiwicmVwbHkiLCJhY3Rpb24iLCJkYXRlU3RhcnQiLCJhbGxSZXNvdXJjZXMiLCJ1cGRhdGVkIiwiY29uZmlybVBhc3N3b3JkIiwidG8iLCJzdWJqZWN0IiwicmVzdWx0cyIsImVxdWFscyIsImRpZmVyZW50IiwiY29udGVpbnMiLCJzdGFydFdpdGgiLCJmaW5pc2hXaXRoIiwiYmlnZ2VyVGhhbiIsImVxdWFsc09yQmlnZ2VyVGhhbiIsImxlc3NUaGFuIiwiZXF1YWxzT3JMZXNzVGhhbiIsInRvdGFsVGFzayIsInBlcmZpbHMiLCJtZW51IiwidG9vbHRpcHMiLCJwZXJmaWwiLCJ0cmFuc2ZlciIsImxpc3RUYXNrIiwiVGFza0luZm9Db250cm9sbGVyIiwiY29uc29sZSIsIlVzZXJzRGlhbG9nQ29udHJvbGxlciIsInRyYW5zZmVyVXNlciJdLCJtYXBwaW5ncyI6IkFBQUE7OztBQ0NBLENBQUMsWUFBVztFQUNWOztFQUVBQSxRQUFRQyxPQUFPLE9BQU8sQ0FDcEIsYUFDQSxVQUNBLGFBQ0EsWUFDQSxrQkFDQSxhQUNBLGNBQ0EsZ0JBQ0EsaUJBQ0Esd0JBQ0EsMEJBQ0EscUJBQ0EsY0FDQSxhQUNBLFdBQ0EsV0FDQTs7QURiSjs7QUVSQyxDQUFBLFlBQVk7RUFDWDs7O0VBRUFELFFBQ0dDLE9BQU8sT0FDUEMsT0FBT0E7Ozs7RUFJVixTQUFTQSxPQUFPQyxRQUFRQyxvQkFBb0JDO0VBQzFDQyxvQkFBb0JDLFFBQVFDLGlCQUFpQkMsdUJBQXVCOztJQUVwRUgsbUJBQ0dJLFVBQVUsa0JBQ1ZDLHlCQUF5Qjs7SUFFNUJMLG1CQUFtQk0saUJBQWlCOztJQUVwQ0wsT0FBT00sT0FBTzs7O0lBR2RSLHNCQUFzQlMsZUFBZUMsU0FBU1osT0FBT2E7OztJQUdyRFosbUJBQW1CYSxNQUFNLFdBQ3RCQyxlQUFlLFFBQVE7TUFDdEJDLFNBQVM7T0FFVkMsY0FBYyxTQUNkQyxZQUFZOzs7SUFHZmpCLG1CQUFtQmtCOztJQUVuQmQsZ0JBQWdCZTs7SUFFaEJkLHNCQUFzQmUsYUFBYSxVQUFTQyxNQUFNO01BQ2hELE9BQU9BLE9BQU9sQixPQUFPa0IsTUFBTUMsT0FBTyxnQkFBZ0I7Ozs7QUZPeEQ7O0FHNUNBLENBQUMsWUFBVzs7RUFFVjs7O0VBRUExQixRQUNHQyxPQUFPLE9BQ1AwQixXQUFXLGlCQUFpQkM7Ozs7Ozs7RUFPL0IsU0FBU0EsY0FBY0MsUUFBUUMsTUFBTTNCLFFBQVE7SUFDM0MsSUFBSTRCLEtBQUs7OztJQUdUQSxHQUFHQyxXQUFXO0lBQ2RELEdBQUdFLGdCQUFnQjs7SUFFbkJGLEdBQUdHLFNBQWFBO0lBQ2hCSCxHQUFHSSxpQkFBaUJBO0lBQ3BCSixHQUFHSyxjQUFjQTtJQUNqQkwsR0FBR00sbUJBQW1CQTtJQUN0Qk4sR0FBR08sbUJBQW1CQTtJQUN0QlAsR0FBR1Esc0JBQXNCQTs7SUFFekJDOztJQUVBLFNBQVNBLFdBQVc7TUFDbEIsSUFBSWYsT0FBTyxJQUFJZ0I7O01BRWZWLEdBQUdDLFdBQVdQLEtBQUtpQjs7O0lBR3JCLFNBQVNSLFNBQVM7TUFDaEJKLEtBQUtJLFNBQVNTLEtBQUssWUFBVztRQUM1QmQsT0FBT2UsR0FBR3pDLE9BQU8wQzs7OztJQUlyQixTQUFTVixpQkFBaUI7TUFDeEIsT0FBUUwsS0FBS2dCLGVBQWVoQixLQUFLZ0IsWUFBWUMsUUFDekNqQixLQUFLZ0IsWUFBWUMsUUFDakI1QyxPQUFPNkMsWUFBWTs7O0lBR3pCLFNBQVNaLGNBQWM7TUFDckIsT0FBT2pDLE9BQU82QyxZQUFZOzs7SUFHNUIsU0FBU1gsaUJBQWlCWSxTQUFTO01BQ2pDQyxhQUFhQyxRQUFRLFdBQVdGOzs7SUFHbEMsU0FBU1gsbUJBQW1CO01BQzFCLE9BQU9ZLGFBQWFFLFFBQVE7OztJQUc5QixTQUFTYixzQkFBc0I7TUFDN0JXLGFBQWFHLFdBQVc7Ozs7QUg4QzlCOzs7QUl6R0MsQ0FBQSxZQUFXO0VBQ1Y7Ozs7Ozs7RUFNQXJELFFBQ0dDLE9BQU8sT0FDUHFELFNBQVMsVUFBVUMsR0FDbkJELFNBQVMsVUFBVS9DOztBSjRHeEI7O0FLdkhDLENBQUEsWUFBVztFQUNWOztFQUVBUCxRQUNHQyxPQUFPLE9BQ1BxRCxTQUFTLFVBQVU7SUFDbEJFLFNBQVM7SUFDVEMsV0FBVztJQUNYQyxVQUFVO0lBQ1ZDLGtCQUFrQjtJQUNsQmQsWUFBWTtJQUNaZSxvQkFBb0I7SUFDcEJDLG9CQUFvQjtJQUNwQkMsVUFBVTtJQUNWQyxZQUFZO0lBQ1ovQyxTQUFTO0lBQ1RnQyxXQUFXOzs7QUwwSGpCOztBTTFJQyxDQUFBLFlBQVc7RUFDVjs7O0VBRUFoRCxRQUNHQyxPQUFPLE9BQ1BDLE9BQU84RDs7O0VBR1YsU0FBU0EsT0FBT0MsZ0JBQWdCQyxvQkFBb0IvRCxRQUFRO0lBQzFEOEQsZUFDR0UsTUFBTSxPQUFPO01BQ1pDLEtBQUs7TUFDTEMsYUFBYWxFLE9BQU80RCxhQUFhO01BQ2pDTyxVQUFVO01BQ1ZDLFNBQVM7UUFDUEMsZ0JBQWdCLENBQUMsY0FBYyxNQUFNLFVBQVNDLFlBQVlDLElBQUk7VUFDNUQsSUFBSUMsV0FBV0QsR0FBR0U7O1VBRWxCSCxXQUFXSSxJQUFJLFNBQVNsQyxLQUFLLFlBQVc7WUFDdENnQyxTQUFTSjs7O1VBR1gsT0FBT0ksU0FBU0c7OztPQUlyQlgsTUFBTWhFLE9BQU8wRCxvQkFBb0I7TUFDaENPLEtBQUs7TUFDTEMsYUFBYWxFLE9BQU80RCxhQUFhO01BQ2pDZ0IsTUFBTSxFQUFFQyxvQkFBb0I7OztJQUdoQ2QsbUJBQW1CZSxLQUFLLG1CQUFtQjlFLE9BQU93RDtJQUNsRE8sbUJBQW1CZSxLQUFLLFFBQVE5RSxPQUFPdUQ7SUFDdkNRLG1CQUFtQmdCLFVBQVUvRSxPQUFPdUQ7OztBTjJJeEM7O0FPN0tDLENBQUEsWUFBVztFQUNWOzs7RUFFQTFELFFBQ0dDLE9BQU8sT0FDUGtGLElBQUlBOzs7O0VBSVAsU0FBU0EsSUFBSUMsWUFBWXZELFFBQVF3RCxjQUFjdkQsTUFBTTNCLFFBQVE7OztJQUUzRGlGLFdBQVd2RCxTQUFTQTtJQUNwQnVELFdBQVdDLGVBQWVBO0lBQzFCRCxXQUFXRSxPQUFPeEQ7SUFDbEJzRCxXQUFXRyxTQUFTcEY7Ozs7SUFJcEIyQixLQUFLMEQ7OztBUGlMVDs7QVFuTUEsQ0FBQyxZQUFXOztFQUVWOzs7RUFFQXhGLFFBQ0dDLE9BQU8sT0FDUDBCLFdBQVcsbUJBQW1COEQ7Ozs7RUFJakMsU0FBU0EsZ0JBQWdCQyxhQUFhQyxjQUFjQyxVQUFVekYsUUFBUXNFLFlBQVk7O0lBQ2hGLElBQUkxQyxLQUFLOztJQUVUQSxHQUFHOEQsYUFBYUE7SUFDaEI5RCxHQUFHK0QsZUFBZUE7SUFDbEIvRCxHQUFHZ0UsYUFBYUE7O0lBRWhCTCxZQUFZLGtCQUFrQixFQUFFM0QsSUFBSUEsSUFBSWlFLGNBQWNMLGNBQWNNLFNBQVM7O0lBRTdFLFNBQVNKLGFBQWE7TUFDcEI5RCxHQUFHbUUsU0FBUztNQUNabkUsR0FBR29FLGVBQWU7OztNQUdsQlIsYUFBYVMsbUJBQW1CekQsS0FBSyxVQUFTb0MsTUFBTTtRQUNsRCxJQUFJbUIsU0FBUyxDQUFDLEVBQUVHLElBQUksSUFBSUMsT0FBTzdCLFdBQVc4QixRQUFROztRQUVsRHhCLEtBQUttQixPQUFPTTs7UUFFWixLQUFLLElBQUlDLFFBQVEsR0FBR0EsUUFBUTFCLEtBQUttQixPQUFPUSxRQUFRRCxTQUFTO1VBQ3ZELElBQUlFLFFBQVE1QixLQUFLbUIsT0FBT087O1VBRXhCUCxPQUFPVSxLQUFLO1lBQ1ZQLElBQUlNO1lBQ0pMLE9BQU83QixXQUFXOEIsUUFBUSxZQUFZSSxNQUFNRTs7OztRQUloRDlFLEdBQUdtRSxTQUFTQTtRQUNabkUsR0FBR29FLGFBQWFRLFFBQVE1RSxHQUFHbUUsT0FBTyxHQUFHRzs7O01BR3ZDdEUsR0FBRytFLFFBQVFuQixhQUFhb0I7TUFDeEJoRixHQUFHb0UsYUFBYWEsT0FBT2pGLEdBQUcrRSxNQUFNLEdBQUdUOzs7SUFHckMsU0FBU1AsYUFBYW1CLHFCQUFxQjtNQUN6QyxPQUFPakgsUUFBUWtILE9BQU9ELHFCQUFxQmxGLEdBQUdvRTs7O0lBR2hELFNBQVNKLFdBQVdvQixhQUFhO01BQy9CLElBQUlqSCxTQUFTO1FBQ1hrSCxRQUFRLEVBQUVELGFBQWFBOztRQUV2QnhGLHdDQUFZLFNBQUEsV0FBU3dGLGFBQWF2QixVQUFVO1VBQzFDLElBQUk3RCxLQUFLOztVQUVUQSxHQUFHc0YsUUFBUUE7O1VBRVg3RTs7VUFFQSxTQUFTQSxXQUFXO1lBQ2xCLElBQUl4QyxRQUFRc0gsUUFBUUgsWUFBWUksUUFBUUosWUFBWUksSUFBSWIsV0FBVyxHQUFHUyxZQUFZSSxNQUFNO1lBQ3hGLElBQUl2SCxRQUFRc0gsUUFBUUgsWUFBWUssUUFBUUwsWUFBWUssSUFBSWQsV0FBVyxHQUFHUyxZQUFZSyxNQUFNOztZQUV4RnpGLEdBQUdvRixjQUFjQTs7O1VBR25CLFNBQVNFLFFBQVE7WUFDZnpCLFNBQVN5Qjs7O1FBSWJJLGNBQWM7UUFDZHBELGFBQWFsRSxPQUFPNEQsYUFBYTtRQUNqQzJELGFBQWE7OztNQUdmOUIsU0FBUytCLE9BQU96SDs7OztBUnVNdEI7O0FTclJDLENBQUEsWUFBVztFQUNWOzs7RUFFQUYsUUFDR0MsT0FBTyxPQUNQQyxPQUFPOEQ7Ozs7Ozs7OztFQVNWLFNBQVNBLE9BQU9DLGdCQUFnQjlELFFBQVE7SUFDdEM4RCxlQUNHRSxNQUFNLGFBQWE7TUFDbEJDLEtBQUs7TUFDTEMsYUFBYWxFLE9BQU80RCxhQUFhO01BQ2pDcEMsWUFBWTtNQUNab0QsTUFBTSxFQUFFQyxvQkFBb0IsTUFBTTRDLGFBQWEsQ0FBQzs7OztBVHdSeEQ7O0FVNVNDLENBQUEsWUFBVztFQUNWOzs7RUFFQTVILFFBQ0dDLE9BQU8sT0FDUDRILFFBQVEsZ0JBQWdCbEM7Ozs7RUFJM0IsU0FBU0EsYUFBYW1DLGdCQUFnQnJELFlBQVk7SUFDaEQsT0FBT3FELGVBQWUsU0FBUztNQUM3QkMsU0FBUztRQUNQM0Isa0JBQWtCO1VBQ2hCNEIsUUFBUTtVQUNSNUQsS0FBSzs7O01BR1Q2RCxVQUFVO01BRVZsQixXQUFXLFNBQUEsWUFBVztRQUNwQixJQUFJbUIsWUFBWTs7UUFFaEIsT0FBTyxDQUNMLEVBQUU3QixJQUFJLElBQUlDLE9BQU83QixXQUFXOEIsUUFBUTJCLFlBQVksbUJBQ2hELEVBQUU3QixJQUFJLFdBQVdDLE9BQU83QixXQUFXOEIsUUFBUTJCLFlBQVksbUJBQ3ZELEVBQUU3QixJQUFJLFdBQVdDLE9BQU83QixXQUFXOEIsUUFBUTJCLFlBQVksbUJBQ3ZELEVBQUU3QixJQUFJLFdBQVdDLE9BQU83QixXQUFXOEIsUUFBUTJCLFlBQVk7Ozs7O0FWNFNqRTs7QVd0VUMsQ0FBQSxZQUFXO0VBQ1Y7OztFQUVBbEksUUFDR0MsT0FBTyxPQUNQQyxPQUFPOEQ7Ozs7Ozs7OztFQVNWLFNBQVNBLE9BQU9DLGdCQUFnQjlELFFBQVE7SUFDdEM4RCxlQUNHRSxNQUFNaEUsT0FBT3lELG9CQUFvQjtNQUNoQ1EsS0FBSztNQUNMQyxhQUFhbEUsT0FBTzRELGFBQWE7TUFDakNwQyxZQUFZO01BQ1pvRCxNQUFNLEVBQUVDLG9CQUFvQjtPQUU3QmIsTUFBTWhFLE9BQU8wQyxZQUFZO01BQ3hCdUIsS0FBSztNQUNMQyxhQUFhbEUsT0FBTzRELGFBQWE7TUFDakNwQyxZQUFZO01BQ1pvRCxNQUFNLEVBQUVDLG9CQUFvQjs7OztBWHdVcEM7O0FZbFdDLENBQUEsWUFBVztFQUNWOzs7RUFFQWhGLFFBQ0dDLE9BQU8sT0FDUDRILFFBQVEsUUFBUS9GOzs7O0VBSW5CLFNBQVNBLEtBQUtxRyxPQUFPekQsSUFBSXZFLFFBQVFpSSxjQUFjOztJQUM3QyxJQUFJOUMsT0FBTztNQUNUK0MsT0FBT0E7TUFDUG5HLFFBQVFBO01BQ1JvRyxtQkFBbUJBO01BQ25COUMsOEJBQThCQTtNQUM5QitDLGVBQWVBO01BQ2ZDLHdCQUF3QkE7TUFDeEJDLHFCQUFxQkE7TUFDckJDLFVBQVVBO01BQ1ZDLFVBQVVBO01BQ1ZDLFlBQVlBO01BQ1o5RixhQUFhOzs7SUFHZixTQUFTOEYsYUFBYTtNQUNwQjFGLGFBQWFHLFdBQVdsRCxPQUFPMkQ7OztJQUdqQyxTQUFTNkUsU0FBU0UsT0FBTztNQUN2QjNGLGFBQWFDLFFBQVFoRCxPQUFPMkQsVUFBVStFOzs7SUFHeEMsU0FBU0gsV0FBVztNQUNsQixPQUFPeEYsYUFBYUUsUUFBUWpELE9BQU8yRDs7O0lBR3JDLFNBQVMyRSxzQkFBc0I7TUFDN0IsSUFBSTlELFdBQVdELEdBQUdFOztNQUVsQixJQUFJVSxLQUFLaUQsaUJBQWlCO1FBQ3hCSixNQUFNVyxJQUFJM0ksT0FBT2EsVUFBVSx1QkFDeEIyQixLQUFLLFlBQVc7VUFDZmdDLFNBQVNKLFFBQVE7V0FDaEIsWUFBVztVQUNaZSxLQUFLcEQ7O1VBRUx5QyxTQUFTb0UsT0FBTzs7YUFFZjtRQUNMekQsS0FBS3BEOztRQUVMeUMsU0FBU29FLE9BQU87OztNQUdsQixPQUFPcEUsU0FBU0c7Ozs7Ozs7O0lBUWxCLFNBQVN5RCxnQkFBZ0I7TUFDdkIsT0FBT2pELEtBQUtvRCxlQUFlOzs7Ozs7SUFNN0IsU0FBU2xELCtCQUErQjtNQUN0QyxJQUFJd0QsT0FBTzlGLGFBQWFFLFFBQVE7O01BRWhDLElBQUk0RixNQUFNO1FBQ1IxRCxLQUFLeEMsY0FBYzlDLFFBQVFpSixNQUFNLElBQUliLGdCQUFnQnBJLFFBQVFrSixTQUFTRjs7Ozs7Ozs7Ozs7Ozs7SUFjMUUsU0FBU1Ysa0JBQWtCVSxNQUFNO01BQy9CLElBQUlyRSxXQUFXRCxHQUFHRTs7TUFFbEIsSUFBSW9FLE1BQU07UUFDUkEsT0FBT2hKLFFBQVFpSixNQUFNLElBQUliLGdCQUFnQlk7O1FBRXpDLElBQUlHLFdBQVduSixRQUFRb0osT0FBT0o7O1FBRTlCOUYsYUFBYUMsUUFBUSxRQUFRZ0c7UUFDN0I3RCxLQUFLeEMsY0FBY2tHOztRQUVuQnJFLFNBQVNKLFFBQVF5RTthQUNaO1FBQ0w5RixhQUFhRyxXQUFXO1FBQ3hCaUMsS0FBS3hDLGNBQWM7UUFDbkJ3QyxLQUFLc0Q7O1FBRUxqRSxTQUFTb0U7OztNQUdYLE9BQU9wRSxTQUFTRzs7Ozs7Ozs7O0lBU2xCLFNBQVN1RCxNQUFNZ0IsYUFBYTtNQUMxQixJQUFJMUUsV0FBV0QsR0FBR0U7O01BRWxCdUQsTUFBTW1CLEtBQUtuSixPQUFPYSxVQUFVLGlCQUFpQnFJLGFBQzFDMUcsS0FBSyxVQUFTNEcsVUFBVTtRQUN2QmpFLEtBQUtxRCxTQUFTWSxTQUFTeEUsS0FBSzhEOztRQUU1QixPQUFPVixNQUFNVyxJQUFJM0ksT0FBT2EsVUFBVTtTQUVuQzJCLEtBQUssVUFBUzRHLFVBQVU7UUFDdkJqRSxLQUFLZ0Qsa0JBQWtCaUIsU0FBU3hFLEtBQUtpRTs7UUFFckNyRSxTQUFTSjtTQUNSLFVBQVNpRixPQUFPO1FBQ2pCbEUsS0FBS3BEOztRQUVMeUMsU0FBU29FLE9BQU9TOzs7TUFHcEIsT0FBTzdFLFNBQVNHOzs7Ozs7Ozs7O0lBVWxCLFNBQVM1QyxTQUFTO01BQ2hCLElBQUl5QyxXQUFXRCxHQUFHRTs7TUFFbEJVLEtBQUtnRCxrQkFBa0I7TUFDdkIzRCxTQUFTSjs7TUFFVCxPQUFPSSxTQUFTRzs7Ozs7Ozs7SUFRbEIsU0FBUzBELHVCQUF1QmlCLFdBQVc7TUFDekMsSUFBSTlFLFdBQVdELEdBQUdFOztNQUVsQnVELE1BQU1tQixLQUFLbkosT0FBT2EsVUFBVSxtQkFBbUJ5SSxXQUM1QzlHLEtBQUssVUFBUzRHLFVBQVU7UUFDdkI1RSxTQUFTSixRQUFRZ0YsU0FBU3hFO1NBQ3pCLFVBQVN5RSxPQUFPO1FBQ2pCN0UsU0FBU29FLE9BQU9TOzs7TUFHcEIsT0FBTzdFLFNBQVNHOzs7SUFHbEIsT0FBT1E7OztBWmtXWDs7QWE5Z0JBLENBQUMsWUFBVzs7RUFFVjs7O0VBRUF0RixRQUNHQyxPQUFPLE9BQ1AwQixXQUFXLG1CQUFtQitIOzs7O0VBSWpDLFNBQVNBLGdCQUFnQjdILFFBQVFDLE1BQU0zQixRQUFReUYsVUFBVTtJQUN2RCxJQUFJN0QsS0FBSzs7SUFFVEEsR0FBR3NHLFFBQVFBO0lBQ1h0RyxHQUFHNEgsc0JBQXNCQTtJQUN6QjVILEdBQUc2SCxtQkFBbUJBOztJQUV0QnBIOztJQUVBLFNBQVNBLFdBQVc7TUFDbEJULEdBQUdzSCxjQUFjOzs7SUFHbkIsU0FBU2hCLFFBQVE7TUFDZixJQUFJZ0IsY0FBYztRQUNoQlEsT0FBTzlILEdBQUdzSCxZQUFZUTtRQUN0QkMsVUFBVS9ILEdBQUdzSCxZQUFZUzs7O01BRzNCaEksS0FBS3VHLE1BQU1nQixhQUFhMUcsS0FBSyxZQUFXO1FBQ3RDZCxPQUFPZSxHQUFHekMsT0FBT3NEOzs7Ozs7O0lBT3JCLFNBQVNrRyxzQkFBc0I7TUFDN0IsSUFBSXpKLFNBQVM7UUFDWG1FLGFBQWFsRSxPQUFPNEQsYUFBYTtRQUNqQ3BDLFlBQVk7UUFDWitGLGFBQWE7OztNQUdmOUIsU0FBUytCLE9BQU96SDs7Ozs7SUFLbEIsU0FBUzBKLG1CQUFtQjtNQUMxQixJQUFJMUosU0FBUztRQUNYbUUsYUFBYWxFLE9BQU80RCxhQUFhO1FBQ2pDcEMsWUFBWTtRQUNaK0YsYUFBYTs7O01BR2Y5QixTQUFTK0IsT0FBT3pIOzs7O0Fia2hCdEI7O0FjMWtCQSxDQUFDLFlBQVk7O0VBRVg7OztFQUVBRixRQUNHQyxPQUFPLE9BQ1AwQixXQUFXLHNCQUFzQm9JOzs7O0VBSXBDLFNBQVNBLG1CQUFtQjVKLFFBQVFrRixjQUFjOEMsT0FBTzZCLFVBQVVuSTtFQUNqRW9JLFNBQVNyRSxVQUFVOUQsTUFBTTJDLFlBQVk7O0lBRXJDLElBQUkxQyxLQUFLOztJQUVUQSxHQUFHbUksWUFBWUE7SUFDZm5JLEdBQUdvSSxjQUFjQTtJQUNqQnBJLEdBQUdxSSxZQUFZQTtJQUNmckksR0FBR3lHLHlCQUF5QkE7O0lBRTVCaEc7O0lBRUEsU0FBU0EsV0FBVztNQUNsQlQsR0FBR3NJLFFBQVEsRUFBRVIsT0FBTyxJQUFJaEIsT0FBT3hELGFBQWF3RDs7Ozs7O0lBTTlDLFNBQVNxQixZQUFZO01BQ25CL0IsTUFBTW1CLEtBQUtuSixPQUFPYSxVQUFVLG1CQUFtQmUsR0FBR3NJLE9BQy9DMUgsS0FBSyxZQUFZO1FBQ2hCc0gsUUFBUUssUUFBUTdGLFdBQVc4QixRQUFRO1FBQ25DeUQsU0FBUyxZQUFZO1VBQ25CbkksT0FBT2UsR0FBR3pDLE9BQU8wQztXQUNoQjtTQUNGLFVBQVUyRyxPQUFPO1FBQ2xCLElBQUlBLE1BQU1lLFdBQVcsT0FBT2YsTUFBTWUsV0FBVyxLQUFLO1VBQ2hELElBQUlDLE1BQU07O1VBRVYsS0FBSyxJQUFJQyxJQUFJLEdBQUdBLElBQUlqQixNQUFNekUsS0FBSytFLFNBQVNwRCxRQUFRK0QsS0FBSztZQUNuREQsT0FBT2hCLE1BQU16RSxLQUFLK0UsU0FBU1csS0FBSzs7VUFFbENSLFFBQVFULE1BQU1nQixJQUFJRTs7Ozs7Ozs7SUFRMUIsU0FBU2xDLHlCQUF5Qjs7TUFFaEMsSUFBSXpHLEdBQUdzSSxNQUFNUixVQUFVLElBQUk7UUFDekJJLFFBQVFULE1BQU0vRSxXQUFXOEIsUUFBUSxtQ0FBbUMsRUFBRW9FLE9BQU87UUFDN0U7OztNQUdGN0ksS0FBSzBHLHVCQUF1QnpHLEdBQUdzSSxPQUFPMUgsS0FBSyxVQUFVb0MsTUFBTTtRQUN6RGtGLFFBQVFLLFFBQVF2RixLQUFLNkY7O1FBRXJCN0ksR0FBR3FJO1FBQ0hySSxHQUFHb0k7U0FDRixVQUFVWCxPQUFPO1FBQ2xCLElBQUlBLE1BQU16RSxLQUFLOEUsU0FBU0wsTUFBTXpFLEtBQUs4RSxNQUFNbkQsU0FBUyxHQUFHO1VBQ25ELElBQUk4RCxNQUFNOztVQUVWLEtBQUssSUFBSUMsSUFBSSxHQUFHQSxJQUFJakIsTUFBTXpFLEtBQUs4RSxNQUFNbkQsUUFBUStELEtBQUs7WUFDaERELE9BQU9oQixNQUFNekUsS0FBSzhFLE1BQU1ZLEtBQUs7OztVQUcvQlIsUUFBUVQsTUFBTWdCOzs7OztJQUtwQixTQUFTTCxjQUFjO01BQ3JCdkUsU0FBU3lCOzs7SUFHWCxTQUFTK0MsWUFBWTtNQUNuQnJJLEdBQUdzSSxNQUFNUixRQUFROzs7O0FkNmtCdkI7OztBZTdwQkEsQ0FBQyxZQUFXO0VBQ1Y7OztFQUVBN0osUUFDR0MsT0FBTyxPQUNQNEgsUUFBUSxrQkFBa0JDOzs7Ozs7O0VBTzdCLFNBQVNBLGVBQWUrQyxlQUFlO0lBQ3JDLE9BQU8sVUFBU3pHLEtBQUs2QixTQUFTO01BQzVCLElBQUlVO01BQ0osSUFBSTdGLGlCQUFpQjtRQUNuQmlILFNBQVM7Ozs7O1VBS1ArQyxVQUFVO1lBQ1I5QyxRQUFRO1lBQ1JWLFNBQVM7WUFDVHlELE1BQU07WUFDTkMsY0FBYyxTQUFBLGFBQVN6QixVQUFVO2NBQy9CLElBQUlBLFNBQVMsVUFBVTtnQkFDckJBLFNBQVMsV0FBVzVDLE1BQU1zRSxLQUFLMUIsU0FBUzs7O2NBRzFDLE9BQU9BOzs7Ozs7TUFNZjVDLFFBQVFrRSxjQUFjekcsS0FBS3BFLFFBQVFpSixNQUFNbkksZ0JBQWdCbUY7O01BRXpELE9BQU9VOzs7O0Fma3FCYjs7QWdCenNCQSxDQUFDLFlBQVc7O0VBRVY7OztFQUVBM0csUUFDR0MsT0FBTyxPQUNQMEIsV0FBVyxrQkFBa0J1Sjs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztFQWtDaEMsU0FBU0EsZUFBZW5KLElBQUlpRSxjQUFjQyxTQUFTZ0UsU0FBU2tCO0VBQzFEdkYsVUFBVW5CLFlBQVk7OztJQUd0QjFDLEdBQUdxSixTQUFTQTtJQUNackosR0FBR3NKLGlCQUFpQkE7SUFDcEJ0SixHQUFHdUosZUFBZUE7SUFDbEJ2SixHQUFHd0osT0FBT0E7SUFDVnhKLEdBQUd5SixPQUFPQTtJQUNWekosR0FBRzBKLFNBQVNBO0lBQ1oxSixHQUFHMkosT0FBT0E7SUFDVjNKLEdBQUdxSSxZQUFZQTs7SUFFZjVIOzs7Ozs7OztJQVFBLFNBQVNBLFdBQVc7TUFDbEJULEdBQUdqQixpQkFBaUI7UUFDbEI2SyxtQkFBbUI7UUFDbkJDLGNBQWM7UUFDZEMsU0FBUztRQUNUQyxnQkFBZ0I7OztNQUdsQjlMLFFBQVFpSixNQUFNbEgsR0FBR2pCLGdCQUFnQm1GOztNQUVqQ2xFLEdBQUdnSyxXQUFXO01BQ2RoSyxHQUFHaUssV0FBVyxJQUFJaEc7O01BRWxCLElBQUloRyxRQUFRaU0sV0FBV2xLLEdBQUc4RCxhQUFhOUQsR0FBRzhEOztNQUUxQzlELEdBQUdtSyxZQUFZZixhQUFhZ0IsWUFBWXBLLEdBQUdxSixRQUFRckosR0FBR2pCLGVBQWUrSzs7TUFFckUsSUFBSTlKLEdBQUdqQixlQUFlOEssY0FBYzdKLEdBQUdxSjs7Ozs7Ozs7O0lBU3pDLFNBQVNBLE9BQU9nQixNQUFNO01BQ25CckssR0FBR2pCLGVBQWVnTCxpQkFBa0JSLGlCQUFpQkQsZUFBZWU7Ozs7Ozs7O0lBUXZFLFNBQVNmLGVBQWVlLE1BQU07TUFDNUJySyxHQUFHbUssVUFBVUcsY0FBZXJNLFFBQVFzTSxVQUFVRixRQUFTQSxPQUFPO01BQzlEckssR0FBR2tGLHNCQUFzQixFQUFFbUYsTUFBTXJLLEdBQUdtSyxVQUFVRyxhQUFhUixTQUFTOUosR0FBR21LLFVBQVVMOztNQUVqRixJQUFJN0wsUUFBUWlNLFdBQVdsSyxHQUFHK0QsZUFBZS9ELEdBQUdrRixzQkFBc0JsRixHQUFHK0QsYUFBYS9ELEdBQUdrRjtNQUNyRixJQUFJakgsUUFBUWlNLFdBQVdsSyxHQUFHd0ssaUJBQWlCeEssR0FBR3dLLGFBQWFILFVBQVUsT0FBTyxPQUFPOztNQUVuRnBHLGFBQWE4RSxTQUFTL0ksR0FBR2tGLHFCQUFxQnRFLEtBQUssVUFBVTRHLFVBQVU7UUFDckV4SCxHQUFHbUssVUFBVU0sa0JBQWtCakQsU0FBU2tEO1FBQ3hDMUssR0FBRzJLLFlBQVluRCxTQUFTb0Q7O1FBRXhCLElBQUkzTSxRQUFRaU0sV0FBV2xLLEdBQUc2SyxjQUFjN0ssR0FBRzZLLFlBQVlyRDtTQUN0RCxVQUFVc0QsY0FBYztRQUN6QixJQUFJN00sUUFBUWlNLFdBQVdsSyxHQUFHK0ssZ0JBQWdCL0ssR0FBRytLLGNBQWNEOzs7Ozs7OztJQVEvRCxTQUFTdkIsZUFBZTtNQUN0QnZKLEdBQUdrRixzQkFBc0I7O01BRXpCLElBQUlqSCxRQUFRaU0sV0FBV2xLLEdBQUcrRCxlQUFlL0QsR0FBR2tGLHNCQUFzQmxGLEdBQUcrRCxhQUFhL0QsR0FBR2tGO01BQ3JGLElBQUlqSCxRQUFRaU0sV0FBV2xLLEdBQUd3SyxpQkFBaUJ4SyxHQUFHd0ssbUJBQW1CLE9BQU8sT0FBTzs7TUFFL0V2RyxhQUFhK0csTUFBTWhMLEdBQUdrRixxQkFBcUJ0RSxLQUFLLFVBQVU0RyxVQUFVO1FBQ2xFeEgsR0FBRzJLLFlBQVluRDs7UUFFZixJQUFJdkosUUFBUWlNLFdBQVdsSyxHQUFHNkssY0FBYzdLLEdBQUc2SyxZQUFZckQ7U0FDdEQsVUFBVXNELGNBQWM7UUFDekIsSUFBSTdNLFFBQVFpTSxXQUFXbEssR0FBRytLLGdCQUFnQi9LLEdBQUcrSyxjQUFjRDs7Ozs7OztJQU8vRCxTQUFTekMsVUFBVTRDLE1BQU07TUFDdkIsSUFBSWhOLFFBQVFpTSxXQUFXbEssR0FBR2tMLGdCQUFnQmxMLEdBQUdrTCxrQkFBa0IsT0FBTyxPQUFPOztNQUU3RWxMLEdBQUdpSyxXQUFXLElBQUloRzs7TUFFbEIsSUFBSWhHLFFBQVFzTSxVQUFVVSxPQUFPO1FBQzNCQSxLQUFLRTtRQUNMRixLQUFLRzs7O01BR1AsSUFBSW5OLFFBQVFpTSxXQUFXbEssR0FBR3FMLGFBQWFyTCxHQUFHcUw7Ozs7Ozs7O0lBUTVDLFNBQVM3QixLQUFLUyxVQUFVO01BQ3RCakssR0FBRzJKLEtBQUs7TUFDUjNKLEdBQUdpSyxXQUFXLElBQUloTSxRQUFRcU4sS0FBS3JCOztNQUUvQixJQUFJaE0sUUFBUWlNLFdBQVdsSyxHQUFHdUwsWUFBWXZMLEdBQUd1TDs7Ozs7Ozs7OztJQVUzQyxTQUFTOUIsS0FBS3dCLE1BQU07TUFDbEIsSUFBSWhOLFFBQVFpTSxXQUFXbEssR0FBR3dMLGVBQWV4TCxHQUFHd0wsaUJBQWlCLE9BQU8sT0FBTzs7TUFFM0V4TCxHQUFHaUssU0FBU3dCLFFBQVE3SyxLQUFLLFVBQVVxSixVQUFVO1FBQzNDakssR0FBR2lLLFdBQVdBOztRQUVkLElBQUloTSxRQUFRaU0sV0FBV2xLLEdBQUcwTCxZQUFZMUwsR0FBRzBMLFVBQVV6Qjs7UUFFbkQsSUFBSWpLLEdBQUdqQixlQUFlNkssbUJBQW1CO1VBQ3ZDNUosR0FBR3FJLFVBQVU0QztVQUNiakwsR0FBR3FKLE9BQU9ySixHQUFHbUssVUFBVUc7VUFDdkJ0SyxHQUFHMkosS0FBSzs7O1FBR1Z6QixRQUFRSyxRQUFRN0YsV0FBVzhCLFFBQVE7U0FFbEMsVUFBVXNHLGNBQWM7UUFDekIsSUFBSTdNLFFBQVFpTSxXQUFXbEssR0FBRzJMLGNBQWMzTCxHQUFHMkwsWUFBWWI7Ozs7Ozs7Ozs7SUFVM0QsU0FBU3BCLE9BQU9PLFVBQVU7TUFDeEIsSUFBSTlMLFNBQVM7UUFDWHlOLE9BQU9sSixXQUFXOEIsUUFBUTtRQUMxQnFILGFBQWFuSixXQUFXOEIsUUFBUTs7O01BR2xDWCxTQUFTaUksUUFBUTNOLFFBQVF5QyxLQUFLLFlBQVc7UUFDdkMsSUFBSTNDLFFBQVFpTSxXQUFXbEssR0FBRytMLGlCQUFpQi9MLEdBQUcrTCxhQUFhOUIsY0FBYyxPQUFPLE9BQU87O1FBRXZGQSxTQUFTK0IsV0FBV3BMLEtBQUssWUFBWTtVQUNuQyxJQUFJM0MsUUFBUWlNLFdBQVdsSyxHQUFHaU0sY0FBY2pNLEdBQUdpTSxZQUFZaEM7O1VBRXZEakssR0FBR3FKO1VBQ0huQixRQUFRZ0UsS0FBS3hKLFdBQVc4QixRQUFROzs7Ozs7Ozs7O0lBVXRDLFNBQVNtRixLQUFLd0MsVUFBVTtNQUN0Qm5NLEdBQUdnSyxXQUFXO01BQ2RoSyxHQUFHb00sU0FBUztNQUNaLElBQUlELGFBQWEsUUFBUTtRQUN2Qm5NLEdBQUdxSTtRQUNIckksR0FBR2dLLFdBQVc7Ozs7O0FoQjZzQnRCOztBaUIzNkJBLENBQUMsWUFBVzs7RUFFVjs7O0VBRUEvTCxRQUNHQyxPQUFPLE9BQ1BtTyxPQUFPLFdBQVcsWUFBVztJQUM1QixPQUFPLFVBQVMzTSxNQUFNO01BQ3BCLElBQUksQ0FBQ0EsTUFBTTtNQUNYLElBQUk0TSxPQUFPNUwsS0FBSzZMLE1BQU03TTtVQUNwQjhNLFVBQVUsSUFBSTlMLE9BQU8rTDtVQUNyQkMsYUFBYUYsVUFBVUY7VUFDdkJLLFVBQVVDLEtBQUtDLE1BQU1ILGFBQWE7VUFDbENJLFVBQVVGLEtBQUtDLE1BQU1GLFVBQVU7VUFDL0JJLFFBQVFILEtBQUtDLE1BQU1DLFVBQVU7VUFDN0JFLE9BQU9KLEtBQUtDLE1BQU1FLFFBQVE7VUFDMUJFLFNBQVNMLEtBQUtDLE1BQU1HLE9BQU87O01BRTdCLElBQUlDLFNBQVMsR0FBRztRQUNkLE9BQU9BLFNBQVM7YUFDWCxJQUFJQSxXQUFXLEdBQUc7UUFDdkIsT0FBTzthQUNGLElBQUlELE9BQU8sR0FBRztRQUNuQixPQUFPQSxPQUFPO2FBQ1QsSUFBSUEsU0FBUyxHQUFHO1FBQ3JCLE9BQU87YUFDRixJQUFJRCxRQUFRLEdBQUc7UUFDcEIsT0FBT0EsUUFBUTthQUNWLElBQUlBLFVBQVUsR0FBRztRQUN0QixPQUFPO2FBQ0YsSUFBSUQsVUFBVSxHQUFHO1FBQ3RCLE9BQU9BLFVBQVU7YUFDWixJQUFJQSxZQUFZLEdBQUc7UUFDeEIsT0FBTzthQUNGO1FBQ0wsT0FBTzs7O0tBSVpsTixXQUFXLHVCQUF1QnNOOzs7O0VBSXJDLFNBQVNBLG9CQUFvQnZKLGFBQzNCN0QsUUFDQXFOLFdBQ0F6SyxZQUNBMEssbUJBQ0FDLGlCQUNBN08sUUFDQTBKLFNBQ0FuSSxNQUNBM0IsUUFBUTtJQUNSLElBQUk0QixLQUFLOzs7OztJQUtUQSxHQUFHOEQsYUFBYUE7SUFDaEI5RCxHQUFHK0QsZUFBZUE7SUFDbEIvRCxHQUFHc04sVUFBVUE7O0lBRWIsU0FBU3hKLGFBQWE7TUFDcEIsSUFBSTVDLFVBQVVDLGFBQWFFLFFBQVE7O01BRW5DckIsR0FBR2lCLFlBQVk3QyxPQUFPNkMsWUFBWTtNQUNsQ2pCLEdBQUdlLGNBQWNoQixLQUFLZ0I7TUFDdEJzTSxnQkFBZ0JyQyxNQUFNLEVBQUV1QyxZQUFZck0sV0FBV04sS0FBSyxVQUFTNEcsVUFBVTtRQUNyRXhILEdBQUd3TixnQkFBZ0JoRyxTQUFTOztNQUU5QnhILEdBQUdvRSxlQUFlLEVBQUVtSixZQUFZck07OztJQUdsQyxTQUFTNkMsYUFBYW1CLHFCQUFxQjtNQUN6QyxPQUFPakgsUUFBUWtILE9BQU9ELHFCQUFxQmxGLEdBQUdvRTs7O0lBR2hELFNBQVNrSixRQUFRRyxZQUFZO01BQzNCLE9BQU9qUCxPQUFPaVA7OztJQUdoQnpOLEdBQUcwTixjQUFjLFlBQVc7TUFDMUI1TixPQUFPZSxHQUFHLGdCQUFnQixFQUFFOE0sS0FBSyxRQUFRMUQsVUFBVWpLLEdBQUd3Tjs7O0lBR3hEeE4sR0FBRzROLFlBQVksWUFBVztNQUN4QixJQUFJQyxpQkFBaUI7O01BRXJCLElBQUk3TixHQUFHd04sY0FBY00sa0JBQWtCO1FBQ3JDOU4sR0FBR3dOLGNBQWNPLE1BQU1DLFFBQVEsVUFBU0MsTUFBTTtVQUM1QyxJQUFJQSxLQUFLQyxpQkFBaUIsR0FBRztZQUMzQkwsa0JBQW1CTSxXQUFXbk8sR0FBR3dOLGNBQWNNLG9CQUFvQkcsS0FBS0M7Ozs7TUFJOUUsT0FBT0wsZUFBZU8sZUFBZSxTQUFTLEVBQUVDLHVCQUF1Qjs7O0lBR3pFck8sR0FBR3NPLGtCQUFrQixZQUFXO01BQzlCakIsZ0JBQWdCa0IsZUFBZSxFQUFFaEIsWUFBWXZOLEdBQUd3TixjQUFjbEosTUFBTTFELEtBQUssVUFBUzRHLFVBQVU7UUFDMUYsSUFBSUEsU0FBU2UsU0FBUztVQUNwQixJQUFJdUQsVUFBVXFCLFVBQVVyQixVQUN2QkYsTUFBTSxxQkFDTjRDLFlBQVksZ0RBQWdEeE8sR0FBR3dOLGNBQWNpQixPQUFPLG1EQUNwRkMsR0FBRyxPQUNIQyxPQUFPOztVQUVSeEIsVUFBVXlCLEtBQUs5QyxTQUFTbEwsS0FBSyxZQUFXO1lBQ3RDLElBQUlpTyxTQUFTMUIsVUFBVTJCLFNBQ3RCbEQsTUFBTSxxQkFDTm1ELFlBQVksZ0RBQ1pDLFlBQVksVUFDWkMsYUFBYSxJQUNiQyxTQUFTLE1BQ1RSLEdBQUcsYUFDSEMsT0FBTzs7WUFFUnhCLFVBQVV5QixLQUFLQyxRQUFRak8sS0FBSyxVQUFTdU8sWUFBWTtjQUMvQzlCLGdCQUFnQitCLFNBQVMsRUFBRTdCLFlBQVl2TixHQUFHd04sY0FBY2xKLElBQUl1SyxRQUFRTSxjQUFjdk8sS0FBSyxZQUFXO2dCQUNoR3NILFFBQVFLLFFBQVE3RixXQUFXOEIsUUFBUTtnQkFDbkNWO2dCQUNBOUQsR0FBR3FKO2lCQUNGLFlBQVc7Z0JBQ1puQixRQUFRbUgsTUFBTTNNLFdBQVc4QixRQUFROzs7O2VBSWxDO1VBQ0wsSUFBSXNILFVBQVVxQixVQUFVckIsVUFDdkJGLE1BQU0scUJBQ05tRCxZQUFZLGdEQUFnRC9PLEdBQUd3TixjQUFjaUIsT0FBTyxLQUNwRkMsR0FBRyxPQUNIQyxPQUFPOztVQUVSeEIsVUFBVXlCLEtBQUs5QyxTQUFTbEwsS0FBSyxZQUFXO1lBQ3RDeU0sZ0JBQWdCK0IsU0FBUyxFQUFFN0IsWUFBWXZOLEdBQUd3TixjQUFjbEosTUFBTTFELEtBQUssWUFBVztjQUM1RXNILFFBQVFLLFFBQVE3RixXQUFXOEIsUUFBUTtjQUNuQ1Y7Y0FDQTlELEdBQUdxSjtlQUNGLFlBQVc7Y0FDWm5CLFFBQVFtSCxNQUFNM00sV0FBVzhCLFFBQVE7Ozs7Ozs7O0lBUTNDYixZQUFZLGtCQUFrQixFQUFFM0QsSUFBSUEsSUFBSWlFLGNBQWNtSixtQkFBbUJsSixTQUFTOzs7QWpCcTVCdEY7O0FrQnppQ0MsQ0FBQSxZQUFXO0VBQ1Y7OztFQUVBakcsUUFDR0MsT0FBTyxPQUNQQyxPQUFPOEQ7Ozs7Ozs7OztFQVNWLFNBQVNBLE9BQU9DLGdCQUFnQjlELFFBQVE7SUFDdEM4RCxlQUNHRSxNQUFNLGlCQUFpQjtNQUN0QkMsS0FBSztNQUNMQyxhQUFhbEUsT0FBTzRELGFBQWE7TUFDakNwQyxZQUFZO01BQ1pvRCxNQUFNLEVBQUVDLG9CQUFvQjtNQUM1QjBLLEtBQUssRUFBRTFELFVBQVU7Ozs7QWxCNGlDekI7O0FtQmprQ0MsQ0FBQSxZQUFXO0VBQ1Y7OztFQUVBaE0sUUFDR0MsT0FBTyxPQUNQNEgsUUFBUSxxQkFBcUJzSDs7O0VBR2hDLFNBQVNBLGtCQUFrQnJILGdCQUFnQjtJQUN6QyxPQUFPQSxlQUFlLGNBQWM7TUFDbENDLFNBQVM7TUFDVEUsVUFBVTs7OztBbkJxa0NoQjs7QW9CaGxDQyxDQUFBLFlBQVc7RUFDVjs7O0VBRUFqSSxRQUNHQyxPQUFPLE9BQ1BDLE9BQU84RDs7Ozs7Ozs7O0VBU1YsU0FBU0EsT0FBT0MsZ0JBQWdCOUQsUUFBUTtJQUN0QzhELGVBQ0dFLE1BQU0scUJBQXFCO01BQzFCQyxLQUFLO01BQ0xDLGFBQWFsRSxPQUFPNEQsYUFBYTtNQUNqQ3BDLFlBQVk7TUFDWm9ELE1BQU0sRUFBRUMsb0JBQW9CLE1BQU00QyxhQUFhLENBQUM7Ozs7QXBCbWxDeEQ7O0FxQnZtQ0MsQ0FBQSxZQUFXO0VBQ1Y7OztFQUVBNUgsUUFDR0MsT0FBTyxPQUNQNEgsUUFBUSx1QkFBdUJ3Sjs7OztFQUlsQyxTQUFTQSxvQkFBb0J2SixnQkFBZ0I7SUFDM0MsT0FBT0EsZUFBZSxnQkFBZ0I7Ozs7TUFJcENDLFNBQVM7UUFDUHVKLFdBQVc7VUFDVHRKLFFBQVE7VUFDUjVELEtBQUs7OztNQUdUNkQsVUFBVTs7OztBckIybUNoQjs7QXNCL25DQSxDQUFDLFlBQVc7O0VBRVY7OztFQUVBakksUUFDR0MsT0FBTyxPQUNQMEIsV0FBVywyQkFBMkI0UDs7OztFQUl6QyxTQUFTQSx3QkFBd0I3TCxhQUFhMkwscUJBQXFCRyxRQUFRdkg7RUFDekV4RixZQUFZOztJQUVaLElBQUkxQyxLQUFLOzs7SUFHVEEsR0FBRzhELGFBQWFBO0lBQ2hCOUQsR0FBRytELGVBQWVBO0lBQ2xCL0QsR0FBRzBQLGlCQUFpQkE7SUFDcEIxUCxHQUFHMlAsZ0JBQWdCQTtJQUNuQjNQLEdBQUc0UCxZQUFZQTtJQUNmNVAsR0FBRzZLLGNBQWNBO0lBQ2pCN0ssR0FBRzZQLFlBQVlBO0lBQ2Y3UCxHQUFHOFAsYUFBYUE7SUFDaEI5UCxHQUFHK1AsYUFBYUE7SUFDaEIvUCxHQUFHZ1EsZUFBZUE7SUFDbEJoUSxHQUFHaVEsUUFBUUE7SUFDWGpRLEdBQUdrUSxVQUFVQTs7O0lBR2J2TSxZQUFZLGtCQUFrQixFQUFFM0QsSUFBSUEsSUFBSWlFLGNBQWNxTCxxQkFBcUJwTCxTQUFTO1FBQ2xGMkYsY0FBYzs7O0lBR2hCLFNBQVMvRixhQUFhO01BQ3BCOUQsR0FBR2tROzs7Ozs7Ozs7SUFTTCxTQUFTbk0sYUFBYW1CLHFCQUFxQjtNQUN6QyxJQUFJaUwsUUFBUTs7Ozs7OztNQU9aLElBQUluUSxHQUFHb1EsYUFBYXpMLFNBQVMsR0FBRztRQUM5QixJQUFJeUwsZUFBZW5TLFFBQVFxTixLQUFLdEwsR0FBR29ROztRQUVuQ0QsTUFBTXZMLFFBQVE1RSxHQUFHb1EsYUFBYSxHQUFHeEwsTUFBTTZKOztRQUV2QyxLQUFLLElBQUkvSixRQUFRLEdBQUdBLFFBQVEwTCxhQUFhekwsUUFBUUQsU0FBUztVQUN4RCxJQUFJMkgsU0FBUytELGFBQWExTDs7VUFFMUIySCxPQUFPekgsUUFBUTtVQUNmeUgsT0FBT2dFLFlBQVloRSxPQUFPZ0UsVUFBVTVCO1VBQ3BDcEMsT0FBT2lFLFdBQVdqRSxPQUFPaUUsU0FBU0M7OztRQUdwQ0osTUFBTUssVUFBVXZTLFFBQVFvSixPQUFPK0k7YUFDMUI7UUFDTEQsTUFBTXZMLFFBQVE1RSxHQUFHb0UsYUFBYVEsTUFBTTZKOzs7TUFHdEMsT0FBT3hRLFFBQVFrSCxPQUFPRCxxQkFBcUJpTDs7Ozs7O0lBTTdDLFNBQVNKLGFBQWE7O01BRXBCVCxvQkFBb0JDLFlBQVkzTyxLQUFLLFVBQVNvQyxNQUFNO1FBQ2xEaEQsR0FBR21FLFNBQVNuQjtRQUNaaEQsR0FBR29FLGFBQWFRLFFBQVE1RSxHQUFHbUUsT0FBTztRQUNsQ25FLEdBQUcwUDs7Ozs7OztJQU9QLFNBQVNBLGlCQUFpQjtNQUN4QjFQLEdBQUd5USxhQUFhelEsR0FBR29FLGFBQWFRLE1BQU02TDtNQUN0Q3pRLEdBQUdvRSxhQUFhaU0sWUFBWXJRLEdBQUd5USxXQUFXOztNQUUxQ3pRLEdBQUcyUDs7Ozs7O0lBTUwsU0FBU0EsZ0JBQWdCO01BQ3ZCLElBQUllLFlBQVksQ0FDZCxFQUFFSCxPQUFPLEtBQUtoTSxPQUFPN0IsV0FBVzhCLFFBQVEsaURBQ3hDLEVBQUUrTCxPQUFPLE1BQU1oTSxPQUFPN0IsV0FBVzhCLFFBQVE7O01BRzNDLElBQUl4RSxHQUFHb0UsYUFBYWlNLFVBQVVwTCxLQUFLMEwsUUFBUSxlQUFlLENBQUMsR0FBRztRQUM1REQsVUFBVTdMLEtBQUssRUFBRTBMLE9BQU87VUFDdEJoTSxPQUFPN0IsV0FBVzhCLFFBQVE7UUFDNUJrTSxVQUFVN0wsS0FBSyxFQUFFMEwsT0FBTztVQUN0QmhNLE9BQU83QixXQUFXOEIsUUFBUTtRQUM1QmtNLFVBQVU3TCxLQUFLLEVBQUUwTCxPQUFPO1VBQ3RCaE0sT0FBTzdCLFdBQVc4QixRQUFRO2FBQ3ZCO1FBQ0xrTSxVQUFVN0wsS0FBSyxFQUFFMEwsT0FBTztVQUN0QmhNLE9BQU83QixXQUFXOEIsUUFBUTtRQUM1QmtNLFVBQVU3TCxLQUFLLEVBQUUwTCxPQUFPO1VBQ3RCaE0sT0FBTzdCLFdBQVc4QixRQUFRO1FBQzVCa00sVUFBVTdMLEtBQUssRUFBRTBMLE9BQU87VUFDdEJoTSxPQUFPN0IsV0FBVzhCLFFBQVE7UUFDNUJrTSxVQUFVN0wsS0FBSyxFQUFFMEwsT0FBTztVQUN0QmhNLE9BQU83QixXQUFXOEIsUUFBUTs7O01BRzlCeEUsR0FBRzBRLFlBQVlBO01BQ2YxUSxHQUFHb0UsYUFBYWtNLFdBQVd0USxHQUFHMFEsVUFBVTs7Ozs7Ozs7SUFRMUMsU0FBU2QsVUFBVTNFLE1BQU07TUFDdkIsSUFBSWhOLFFBQVEyUyxZQUFZNVEsR0FBR29FLGFBQWFtTSxVQUFVdlEsR0FBR29FLGFBQWFtTSxVQUFVLElBQUk7UUFDOUVySSxRQUFRVCxNQUFNL0UsV0FBVzhCLFFBQVEsbUNBQW1DLEVBQUVvRSxPQUFPO1FBQzdFO2FBQ0s7UUFDTCxJQUFJNUksR0FBRzBFLFFBQVEsR0FBRztVQUNoQjFFLEdBQUdvUSxhQUFhdkwsS0FBSzVHLFFBQVFxTixLQUFLdEwsR0FBR29FO2VBQ2hDO1VBQ0xwRSxHQUFHb1EsYUFBYXBRLEdBQUcwRSxTQUFTekcsUUFBUXFOLEtBQUt0TCxHQUFHb0U7VUFDNUNwRSxHQUFHMEUsUUFBUSxDQUFDOzs7O1FBSWQxRSxHQUFHb0UsZUFBZTtRQUNsQjZHLEtBQUtFO1FBQ0xGLEtBQUtHOzs7Ozs7O0lBT1QsU0FBU3lFLFlBQVk7TUFDbkI3UCxHQUFHcUosT0FBT3JKLEdBQUdtSyxVQUFVRzs7Ozs7Ozs7O0lBU3pCLFNBQVNPLFlBQVk3SCxNQUFNO01BQ3pCLElBQUk2TixPQUFRN04sS0FBSzRILE1BQU1qRyxTQUFTLElBQUttTSxPQUFPRCxLQUFLN04sS0FBSzRILE1BQU0sTUFBTTs7OztNQUlsRTVLLEdBQUc2USxPQUFPcEIsT0FBT3BELE9BQU93RSxNQUFNLFVBQVNFLEtBQUs7UUFDMUMsT0FBTyxDQUFDdEIsT0FBT3VCLFdBQVdELEtBQUs7Ozs7Ozs7O0lBUW5DLFNBQVNqQixXQUFXbUIsUUFBUTtNQUMxQmpSLEdBQUcwRSxRQUFRdU07TUFDWGpSLEdBQUdvRSxlQUFlcEUsR0FBR29RLGFBQWFhOzs7Ozs7OztJQVFwQyxTQUFTakIsYUFBYWlCLFFBQVE7TUFDNUJqUixHQUFHb1EsYUFBYWMsT0FBT0Q7Ozs7OztJQU16QixTQUFTaEIsUUFBUTs7TUFFZmpRLEdBQUcwRSxRQUFRLENBQUM7O01BRVoxRSxHQUFHb0UsZUFBZTs7TUFHbEIsSUFBSXBFLEdBQUdtRSxRQUFRbkUsR0FBR29FLGFBQWFRLFFBQVE1RSxHQUFHbUUsT0FBTzs7Ozs7OztJQU9uRCxTQUFTK0wsVUFBVTs7TUFFakJsUSxHQUFHNlEsT0FBTzs7O01BR1Y3USxHQUFHb1EsZUFBZTtNQUNsQnBRLEdBQUdpUTtNQUNIalEsR0FBRytQOzs7O0F0QituQ1Q7O0F1QnQxQ0EsQ0FBQyxZQUFXOztFQUVWOzs7RUFFQTlSLFFBQ0dDLE9BQU8sT0FDUDRILFFBQVEsa0JBQWtCcUw7Ozs7RUFJN0IsU0FBU0EsZUFBZXhPLElBQUl5TyxnQkFBZ0JDLE1BQU1DLFdBQVc7SUFDM0QsSUFBSUMsVUFBVTs7SUFFZEEsUUFBUUMsWUFBWSxVQUFTMVMsUUFBUTtNQUNuQyxPQUFPO1FBQ0wwRSxRQUFROE4sVUFBVXZLLElBQUlqSSxTQUFTO1FBQy9CMlMsT0FBT0gsVUFBVXZLLElBQUlqSSxTQUFTO1FBQzlCMlIsWUFBWWEsVUFBVXZLLElBQUlqSSxTQUFTO1FBQ25DNFMsUUFBUUosVUFBVXZLLElBQUlqSSxTQUFTO1FBQy9CNlMsVUFBVUwsVUFBVXZLLElBQUlqSSxTQUFTO1FBQ2pDcUYsUUFBUW1OLFVBQVV2SyxJQUFJakksU0FBUzs7Ozs7SUFLbkMsT0FBTyxVQUFTb0YsU0FBUztNQUN2Qm1OLEtBQUtuRixLQUFLLHdDQUF3Q2hJLFFBQVE2TTs7TUFFMUQsSUFBSW5PLFdBQVdELEdBQUdFOzs7TUFHbEJ1TyxlQUFlUSxRQUFRaFIsS0FBSyxVQUFTZ1IsT0FBTzs7UUFFMUMsSUFBSTVPLE9BQU8vRSxRQUFRaUosTUFBTXFLLFFBQVFDLFVBQVV0TixRQUFRNk0sTUFBTWE7O1FBRXpELE9BQU9oUCxTQUFTSixRQUFRUTtTQUN2QixZQUFXO1FBQ1osT0FBT0osU0FBU0osUUFBUStPLFFBQVFDLFVBQVV0TixRQUFRNk07OztNQUdwRCxPQUFPbk8sU0FBU0c7Ozs7QXZCMDFDdEI7O0F3Qmw0Q0EsQ0FBQyxZQUFXOztFQUVWOzs7RUFFQTlFLFFBQ0dDLE9BQU8sT0FDUG1PLE9BQU8sU0FBU3dGOzs7O0VBSW5CLFNBQVNBLE1BQU1DLFNBQVM7Ozs7Ozs7SUFPdEIsT0FBTyxVQUFTckQsTUFBTTtNQUNwQixJQUFJc0MsTUFBTSxnQkFBZ0J0QztNQUMxQixJQUFJK0MsWUFBWU0sUUFBUSxhQUFhZjs7TUFFckMsT0FBUVMsY0FBY1QsTUFBT3RDLE9BQU8rQzs7OztBeEJzNEMxQzs7QXlCMzVDQSxDQUFDLFlBQVc7O0VBRVY7OztFQUVBdlQsUUFDR0MsT0FBTyxPQUNQbU8sT0FBTyxlQUFlMEY7Ozs7RUFJekIsU0FBU0EsWUFBWUQsU0FBUzs7Ozs7OztJQU81QixPQUFPLFVBQVN4TixJQUFJOztNQUVsQixJQUFJeU0sTUFBTSx1QkFBdUJ6TSxHQUFHME4sTUFBTSxLQUFLO01BQy9DLElBQUlSLFlBQVlNLFFBQVEsYUFBYWY7O01BRXJDLE9BQVFTLGNBQWNULE1BQU96TSxLQUFLa047Ozs7QXpCKzVDeEM7O0EwQnI3Q0EsQ0FBQyxZQUFXOztFQUVWOzs7RUFFQXZULFFBQ0dDLE9BQU8sT0FDUG1PLE9BQU8sVUFBVTRGOzs7O0VBSXBCLFNBQVNBLE9BQU9ILFNBQVM7Ozs7Ozs7SUFPdkIsT0FBTyxVQUFTckQsTUFBTTtNQUNwQixJQUFJc0MsTUFBTSxZQUFZdEMsS0FBSzNKO01BQzNCLElBQUkwTSxZQUFZTSxRQUFRLGFBQWFmOztNQUVyQyxPQUFRUyxjQUFjVCxNQUFPdEMsT0FBTytDOzs7O0ExQnk3QzFDOztBMkI5OENDLENBQUEsWUFBVztFQUNWOzs7RUFFQXZULFFBQ0dDLE9BQU8sT0FDUGtGLElBQUk4Tzs7Ozs7Ozs7Ozs7Ozs7Ozs7O0VBa0JQLFNBQVNBLHVCQUF1QjdPLFlBQVl2RCxRQUFRMUIsUUFBUTJCLE1BQU1tSTtFQUNoRXhGLFlBQVk7OztJQUdaM0MsS0FBSzJHLHNCQUFzQjlGLEtBQUssWUFBVzs7O01BR3pDLElBQUliLEtBQUtnQixnQkFBZ0IsTUFBTTtRQUM3QmhCLEtBQUt3RyxrQkFBa0J0SSxRQUFRa0osU0FBU2hHLGFBQWFFLFFBQVE7Ozs7O0lBS2pFZ0MsV0FBVzhPLElBQUkscUJBQXFCLFVBQVNDLE9BQU9DLFNBQVM7TUFDM0QsSUFBSUEsUUFBUXJQLEtBQUtDLHNCQUFzQm9QLFFBQVFyUCxLQUFLNkMsYUFBYTs7UUFFL0Q5RixLQUFLMkcsc0JBQXNCNEwsTUFBTSxZQUFXO1VBQzFDcEssUUFBUXFLLEtBQUs3UCxXQUFXOEIsUUFBUTs7VUFFaEMsSUFBSTZOLFFBQVE1RCxTQUFTclEsT0FBTzBDLFlBQVk7WUFDdENoQixPQUFPZSxHQUFHekMsT0FBTzBDOzs7VUFHbkJzUixNQUFNSTs7YUFFSDs7O1FBR0wsSUFBSUgsUUFBUTVELFNBQVNyUSxPQUFPMEMsY0FBY2YsS0FBS3lHLGlCQUFpQjtVQUM5RDFHLE9BQU9lLEdBQUd6QyxPQUFPc0Q7VUFDakIwUSxNQUFNSTs7Ozs7O0EzQm85Q2hCOztBNEJ6Z0RDLENBQUEsWUFBVztFQUNWOzs7RUFFQXZVLFFBQ0dDLE9BQU8sT0FDUGtGLElBQUlxUDs7O0VBR1AsU0FBU0Esc0JBQXNCcFAsWUFBWXZELFFBQVExQixRQUFRMkIsTUFBTTs7Ozs7SUFLL0RzRCxXQUFXOE8sSUFBSSxxQkFBcUIsVUFBU0MsT0FBT0MsU0FBUztNQUMzRCxJQUFJQSxRQUFRclAsUUFBUXFQLFFBQVFyUCxLQUFLQyxzQkFDL0JvUCxRQUFRclAsS0FBSzZDLGVBQWU5RixLQUFLeUcsbUJBQ2pDLENBQUN6RyxLQUFLZ0IsWUFBWTJSLFdBQVdMLFFBQVFyUCxLQUFLNkMsYUFBYXdNLFFBQVFyUCxLQUFLMlAsY0FBYzs7UUFFbEY3UyxPQUFPZSxHQUFHekMsT0FBTzBEO1FBQ2pCc1EsTUFBTUk7Ozs7O0E1QjRnRGQ7O0E2Qi9oREMsQ0FBQSxZQUFZO0VBQ1g7OztFQUVBdlUsUUFDR0MsT0FBTyxPQUNQQyxPQUFPeVU7O0VBRVYsU0FBU0EsbUJBQW1CQyxlQUFlQyxVQUFVOzs7Ozs7Ozs7OztJQVVuRCxTQUFTQyxnQkFBZ0JwUSxJQUFJMk8sV0FBVztNQUN0QyxPQUFPO1FBQ0wwQixTQUFTLFNBQUEsUUFBVTdVLFFBQVE7VUFDekJtVCxVQUFVdkssSUFBSSxhQUFhNkg7O1VBRTNCLE9BQU96UTs7O1FBR1RxSixVQUFVLFNBQUEsU0FBVUEsV0FBVTtVQUM1QjhKLFVBQVV2SyxJQUFJLGFBQWFrTTs7VUFFM0IsT0FBT3pMOzs7UUFHVDBMLGVBQWUsU0FBQSxjQUFVQyxXQUFXO1VBQ2xDN0IsVUFBVXZLLElBQUksYUFBYWtNOztVQUUzQixPQUFPdFEsR0FBR3FFLE9BQU9tTTs7Ozs7O0lBTXZCTCxTQUFTaE4sUUFBUSxtQkFBbUJpTjs7O0lBR3BDRixjQUFjTyxhQUFhdk8sS0FBSzs7O0E3QmtpRHBDOzs7O0E4QjNrREMsQ0FBQSxZQUFXO0VBQ1Y7OztFQUVBNUcsUUFDR0MsT0FBTyxPQUNQQyxPQUFPa1Y7Ozs7Ozs7Ozs7RUFVVixTQUFTQSxpQkFBaUJSLGVBQWVDLFVBQVUxVSxRQUFROzs7SUFFekQsU0FBU2tWLDRCQUE0QjNRLElBQUkyTyxXQUFXO01BQ2xELE9BQU87UUFDTDBCLFNBQVMsU0FBQSxRQUFTN1UsUUFBUTtVQUN4QixJQUFJMkksUUFBUXdLLFVBQVV2SyxJQUFJLFFBQVFKOztVQUVsQyxJQUFJRyxPQUFPO1lBQ1QzSSxPQUFPb1YsUUFBUSxtQkFBbUIsWUFBWXpNOzs7VUFHaEQsT0FBTzNJOztRQUVUcUosVUFBVSxTQUFBLFNBQVNBLFdBQVU7O1VBRTNCLElBQUlWLFFBQVFVLFVBQVMrTCxRQUFROztVQUU3QixJQUFJek0sT0FBTztZQUNUd0ssVUFBVXZLLElBQUksUUFBUUgsU0FBU0UsTUFBTWtMLE1BQU0sS0FBSzs7VUFFbEQsT0FBT3hLOztRQUVUMEwsZUFBZSxTQUFBLGNBQVNDLFdBQVc7Ozs7VUFJakMsSUFBSUssbUJBQW1CLENBQUMsc0JBQXNCLGlCQUFpQixnQkFBZ0I7O1VBRS9FLElBQUlDLGFBQWE7O1VBRWpCeFYsUUFBUStQLFFBQVF3RixrQkFBa0IsVUFBU2pELE9BQU87WUFDaEQsSUFBSTRDLFVBQVVuUSxRQUFRbVEsVUFBVW5RLEtBQUt5RSxVQUFVOEksT0FBTztjQUNwRGtELGFBQWE7O2NBRWJuQyxVQUFVdkssSUFBSSxRQUFRNUcsU0FBU1MsS0FBSyxZQUFXO2dCQUM3QyxJQUFJZCxTQUFTd1IsVUFBVXZLLElBQUk7Ozs7Z0JBSTNCLElBQUksQ0FBQ2pILE9BQU80VCxHQUFHdFYsT0FBTzBDLGFBQWE7a0JBQ2pDaEIsT0FBT2UsR0FBR3pDLE9BQU8wQzs7O2tCQUdqQndRLFVBQVV2SyxJQUFJLFlBQVl6Qjs7a0JBRTFCOE0sTUFBTUk7Ozs7Ozs7VUFPZCxJQUFJaUIsWUFBWTtZQUNkTixVQUFVblEsT0FBTzs7O1VBR25CLElBQUkvRSxRQUFRaU0sV0FBV2lKLFVBQVVJLFVBQVU7OztZQUd6QyxJQUFJek0sUUFBUXFNLFVBQVVJLFFBQVE7O1lBRTlCLElBQUl6TSxPQUFPO2NBQ1R3SyxVQUFVdkssSUFBSSxRQUFRSCxTQUFTRSxNQUFNa0wsTUFBTSxLQUFLOzs7O1VBSXBELE9BQU9yUCxHQUFHcUUsT0FBT21NOzs7Ozs7SUFNdkJMLFNBQVNoTixRQUFRLCtCQUErQndOOzs7SUFHaERULGNBQWNPLGFBQWF2TyxLQUFLOzs7QTlCZ2xEcEM7O0ErQjVxREMsQ0FBQSxZQUFZO0VBQ1g7OztFQUVBNUcsUUFDR0MsT0FBTyxPQUNQQyxPQUFPd1Y7O0VBRVYsU0FBU0Esc0JBQXNCZCxlQUFlQyxVQUFVOzs7Ozs7Ozs7O0lBU3RELFNBQVNjLG9CQUFvQmpSLElBQUkyTyxXQUFXO01BQzFDLE9BQU87UUFDTDRCLGVBQWUsU0FBQSxjQUFVQyxXQUFXO1VBQ2xDLElBQUlqTCxVQUFVb0osVUFBVXZLLElBQUk7VUFDNUIsSUFBSXJFLGFBQWE0TyxVQUFVdkssSUFBSTs7VUFFL0IsSUFBSW9NLFVBQVVoVixPQUFPNkUsUUFBUSxDQUFDbVEsVUFBVWhWLE9BQU82RSxLQUFLNlEsZ0JBQWdCO1lBQ2xFLElBQUlWLFVBQVVuUSxRQUFRbVEsVUFBVW5RLEtBQUt5RSxPQUFPOzs7Y0FHMUMsSUFBSTBMLFVBQVVuUSxLQUFLeUUsTUFBTXVKLFdBQVcsV0FBVztnQkFDN0M5SSxRQUFRcUssS0FBSzdQLFdBQVc4QixRQUFRO3FCQUMzQixJQUFJMk8sVUFBVW5RLEtBQUt5RSxVQUFVLGFBQWE7Z0JBQy9DUyxRQUFRVCxNQUFNL0UsV0FBVzhCLFFBQVEyTyxVQUFVblEsS0FBS3lFOzttQkFFN0M7Y0FDTFMsUUFBUTRMLGdCQUFnQlgsVUFBVW5ROzs7O1VBSXRDLE9BQU9MLEdBQUdxRSxPQUFPbU07Ozs7OztJQU12QkwsU0FBU2hOLFFBQVEsdUJBQXVCOE47OztJQUd4Q2YsY0FBY08sYUFBYXZPLEtBQUs7OztBL0IrcURwQzs7QWdDNXREQSxDQUFDLFlBQVc7O0VBRVY7OztFQUVBNUcsUUFDR0MsT0FBTyxPQUNQMEIsV0FBVyxvQkFBb0JtVTs7OztFQUlsQyxTQUFTQSxpQkFBaUJwUSxhQUN4QnFRLGNBQ0FDLGVBQ0EvTCxTQUNBaUYsV0FDQStHLFdBQ0FuVSxNQUNBc04saUJBQWlCOztJQUVqQixJQUFJck4sS0FBSztJQUNULElBQUltVSxTQUFTLENBQ1gsRUFBRTFGLE1BQU0sTUFBTXhKLE1BQU0sWUFDcEIsRUFBRXdKLE1BQU0sVUFBVTJGLEtBQUssU0FBU25QLE1BQU0sWUFDdEMsRUFBRXdKLE1BQU0sUUFBUTJGLEtBQUssU0FBU25QLE1BQU0sWUFDcEMsRUFBRXdKLE1BQU0sUUFBUXhKLE1BQU07O0lBR3hCakYsR0FBRzhELGFBQWEsWUFBVztNQUN6QjlELEdBQUdrQixVQUFVQyxhQUFhRSxRQUFRO01BQ2xDZ00sZ0JBQWdCckMsTUFBTSxFQUFFdUMsWUFBWXZOLEdBQUdrQixXQUFXTixLQUFLLFVBQVM0RyxVQUFVO1FBQ3hFeEgsR0FBR3dOLGdCQUFnQmhHLFNBQVM7O01BRTlCeEgsR0FBR29FLGVBQWUsRUFBRW1KLFlBQVl2TixHQUFHa0I7TUFDbkNsQixHQUFHcVUsVUFBVTs7O0lBR2ZyVSxHQUFHK0QsZUFBZSxVQUFTbUIscUJBQXFCO01BQzlDLE9BQU9qSCxRQUFRa0gsT0FBT0QscUJBQXFCbEYsR0FBR29FOzs7SUFHaERwRSxHQUFHNkssY0FBYyxZQUFZO01BQzNCLElBQUl5SixVQUFVO01BQ2QsSUFBSXZHLFFBQVE7O01BRVprRyxjQUFjakosUUFBUXBLLEtBQUssVUFBUzRHLFVBQVU7UUFDNUNBLFNBQVN3RyxRQUFRLFVBQVN4RixRQUFRO1VBQ2hDOEwsUUFBUXpQLEtBQUssRUFBRTBQLE1BQU0vTCxPQUFPaUcsTUFBTStGLFdBQVdoTSxPQUFPaU0sTUFBTUMsYUFBYTs7O1FBR3pFLElBQUkxVSxHQUFHMkssVUFBVWhHLFNBQVMsR0FBRztVQUMzQjNFLEdBQUcySyxVQUFVcUQsUUFBUSxVQUFTQyxNQUFNO1lBQ2xDRixNQUFNbEosS0FBSztjQUNUUCxJQUFJMkosS0FBSzNKO2NBQ1RsQyxPQUFPNkwsS0FBS3pGLE9BQU9pTTtjQUNuQmxRLE9BQU8wSixLQUFLckM7Y0FDWitJLE1BQU0xRyxLQUFLaEosS0FBS3dKLE9BQU8sT0FBT1IsS0FBSzJHLFNBQVNuRzs7OztVQUloRCxJQUFJb0csU0FBUztZQUNYQyxXQUFXL0c7WUFDWGdILFVBQVU7WUFDVkMsWUFBWWI7O1VBRWQsSUFBSWMsY0FBYyxJQUFJQyxFQUFFQyxJQUFJRixZQUFZSjs7VUFFeEM3VSxHQUFHb1YsV0FBVztZQUNaUCxRQUFRSTtZQUNSWCxTQUFTQTtZQUNUcFYsT0FBTzs7ZUFFSjtVQUNMYyxHQUFHb1YsV0FBVztZQUNaUCxRQUFRLENBQUM7WUFDVFAsU0FBU0E7WUFDVHBWLE9BQU87OztRQUdYYyxHQUFHcVYsY0FBYzs7OztJQUlyQnJWLEdBQUdzVixjQUFjLFVBQVNsRCxPQUFPO01BQy9CLElBQUksQ0FBQ3BTLEdBQUd3TixjQUFjK0gsUUFBUXhWLEtBQUtnQixZQUFZdUQsT0FBT3RFLEdBQUd3TixjQUFjZ0ksT0FBTztRQUM1RXhWLEdBQUdxVSxVQUFVO1FBQ2JMLGFBQWFoSixNQUFNLEVBQUV5SyxTQUFTckQsTUFBTXNELEtBQUtDLFVBQVUvVSxLQUFLLFVBQVM0RyxVQUFVO1VBQ3pFLElBQUtBLFNBQVMsR0FBR29PLGFBQWFwTyxTQUFTLEdBQUdvTyxVQUFVTCxRQUFTL04sU0FBUyxHQUFHdEcsUUFBUXFVLE1BQU07WUFDckZyTixRQUFRVCxNQUFNO1lBQ2R6SCxHQUFHNks7WUFDSDdLLEdBQUdxVSxVQUFVO2lCQUNSO1lBQ0xMLGFBQWE2QixtQkFBbUI7Y0FDOUJ0SSxZQUFZdk4sR0FBR2tCO2NBQ2ZvRCxJQUFJOE4sTUFBTXNELEtBQUtDO2NBQ2ZHLFdBQVcxRCxNQUFNc0QsS0FBS0k7Y0FDdEJDLFdBQVczRCxNQUFNc0QsS0FBS0ssYUFBYW5WLEtBQUssWUFBVztjQUNqRFosR0FBR3FVLFVBQVU7Ozs7YUFJaEI7UUFDTHJVLEdBQUc2Szs7OztJQUlQN0ssR0FBR2dXLGdCQUFnQixVQUFTNUQsT0FBTztNQUNqQyxJQUFJLENBQUNwUyxHQUFHcVUsU0FBUztRQUNmTCxhQUFhaEosTUFBTSxFQUFFeUssU0FBU3JELE1BQU1zRCxLQUFLQyxVQUFVL1UsS0FBSyxVQUFTNEcsVUFBVTtVQUN6RXhILEdBQUdpVyxXQUFXek8sU0FBUztVQUN2QjJGLFVBQVV5QixLQUFLO1lBQ2JzSCxRQUFRalksUUFBUWtZLFFBQVFqQyxVQUFVa0M7WUFDbEM5VCxhQUFhO1lBQ2JvRCxjQUFjO1lBQ2Q5RixZQUFZO1lBQ1p5VyxrQkFBa0I7WUFDbEJoUixRQUFRO2NBQ040SSxNQUFNak8sR0FBR2lXO2NBQ1QzUSxPQUFPQTs7WUFFVGdSLGVBQWU7WUFDZkMscUJBQXFCOzs7YUFHcEI7UUFDTHZXLEdBQUdxVSxVQUFVOzs7O0lBSWpCLFNBQVMvTyxRQUFRO01BQ2Y2SCxVQUFVOEY7Ozs7SUFJWnRQLFlBQVksa0JBQWtCLEVBQUUzRCxJQUFJQSxJQUFJaUUsY0FBYytQLGNBQWM5UCxTQUFTOzs7QWhDbXREakY7O0FpQ3gxREMsQ0FBQSxZQUFXO0VBQ1Y7OztFQUVBakcsUUFDR0MsT0FBTyxPQUNQQyxPQUFPOEQ7Ozs7Ozs7OztFQVNWLFNBQVNBLE9BQU9DLGdCQUFnQjlELFFBQVE7SUFDdEM4RCxlQUNHRSxNQUFNLGNBQWM7TUFDbkJDLEtBQUs7TUFDTEMsYUFBYWxFLE9BQU80RCxhQUFhO01BQ2pDcEMsWUFBWTtNQUNab0QsTUFBTTs7OztBakMyMURkOztBa0MvMkRDLENBQUEsWUFBVztFQUNWOzs7RUFFQS9FLFFBQ0dDLE9BQU8sT0FDUDRILFFBQVEsaUJBQWlCMFE7OztFQUc1QixTQUFTQSxjQUFjelEsZ0JBQWdCO0lBQ3JDLElBQUluQixRQUFRbUIsZUFBZSxVQUFVO01BQ25DQyxTQUFTO01BQ1RFLFVBQVU7OztJQUdaLE9BQU90Qjs7O0FsQ2szRFg7Ozs7QW1DOTNEQSxDQUFDLFlBQVk7O0VBRVg7OztFQUVBM0csUUFDR0MsT0FBTyxPQUNQMEIsV0FBVyxrQkFBa0I2Vzs7O0VBR2hDLFNBQVNBLGVBQWVDLFlBQVk1VyxRQUFRNlcsV0FBVztJQUNyRCxJQUFJM1csS0FBSzs7O0lBR1RBLEdBQUc0VyxPQUFPQTtJQUNWNVcsR0FBRzZXLDRCQUE0QkE7O0lBRS9CcFc7O0lBRUEsU0FBU0EsV0FBVztNQUNsQixJQUFJcVcsYUFBYTs7O01BR2pCOVcsR0FBRytXLFlBQVksQ0FDYixFQUFFM1UsT0FBTyxnQkFBZ0J3SixPQUFPa0wsYUFBYSxZQUFZRSxNQUFNLFFBQVFDLFVBQVUsTUFDakYsRUFBRTdVLE9BQU8saUJBQWlCd0osT0FBT2tMLGFBQWEsYUFBYUUsTUFBTSxhQUFhQyxVQUFVLE1BQ3hGLEVBQUU3VSxPQUFPLGFBQWF3SixPQUFPa0wsYUFBYSxTQUFTRSxNQUFNLGFBQWFDLFVBQVUsTUFDaEYsRUFBRTdVLE9BQU8sa0JBQWtCd0osT0FBT2tMLGFBQWEsY0FBY0UsTUFBTSxlQUFlQyxVQUFVLE1BQzVGLEVBQUU3VSxPQUFPLGdCQUFnQndKLE9BQU9rTCxhQUFhLFlBQVlFLE1BQU0saUJBQWlCQyxVQUFVLE1BQzFGLEVBQUU3VSxPQUFPLGNBQWN3SixPQUFPa0wsYUFBYSxVQUFVRSxNQUFNLGVBQWVDLFVBQVUsTUFDcEYsRUFBRTdVLE9BQU8sV0FBV3dKLE9BQU9rTCxhQUFhLE9BQU9FLE1BQU0sY0FBY0MsVUFBVTs7Ozs7Ozs7Ozs7Ozs7OztNQWdCL0VqWCxHQUFHa1gsZUFBZTtRQUNoQkMsS0FBSztVQUNILGlCQUFpQjtVQUNqQixvQkFBb0I7O1FBRXRCQyxTQUFTO1VBQ1Asb0JBQW9COztRQUV0QkMsV0FBVztVQUNUQyxPQUFPOztRQUVUQyxZQUFZO1VBQ1YsaUJBQWlCLGVBQWVDLFNBQVM7Ozs7O0lBSy9DLFNBQVNaLE9BQU87TUFDZEYsV0FBVyxRQUFRZTs7Ozs7OztJQU9yQixTQUFTWiwwQkFBMEJhLFNBQVNDLElBQUlDLE1BQU07TUFDcEQsSUFBSTNaLFFBQVFzTSxVQUFVcU4sS0FBS1gsYUFBYVcsS0FBS1gsU0FBU3RTLFNBQVMsR0FBRztRQUNoRStTLFFBQVFkLEtBQUtlO2FBQ1I7UUFDTDdYLE9BQU9lLEdBQUcrVyxLQUFLeFYsT0FBTyxFQUFFdUwsS0FBSztRQUM3QitJLFdBQVcsUUFBUXBSOzs7O0lBSXZCLFNBQVNrUyxTQUFTSyxlQUFlO01BQy9CLE9BQU9sQixVQUFVbUIsY0FBY0Q7Ozs7QW5DNjNEckM7O0FvQy84REEsQ0FBQyxZQUFXOztFQUVWOzs7RUFFQTVaLFFBQ0dDLE9BQU8sT0FDUDBCLFdBQVcsbUJBQW1CbVk7Ozs7RUFJakMsU0FBU0EsZ0JBQWdCQyxjQUFjM1IsY0FBY3hDLFVBQVVxRTtFQUM3RHZGLElBQUk4TSxRQUFRL00sWUFBWXRFLFFBQVE7O0lBRWhDLElBQUk0QixLQUFLOztJQUVUQSxHQUFHaVksaUJBQWlCO0lBQ3BCalksR0FBR2tFLFVBQVU7TUFDWGdVLE1BQU07TUFDTkMsVUFBVTtNQUNWQyxnQkFBZ0I7TUFDaEJDLFVBQVU7TUFDVkMsUUFBUTtNQUNSQyxjQUFjOzs7SUFHaEJ2WSxHQUFHd1ksWUFBWUE7SUFDZnhZLEdBQUd5WSxpQkFBaUJBO0lBQ3BCelksR0FBRzBZLGNBQWNBO0lBQ2pCMVksR0FBR3FJLFlBQVlBO0lBQ2ZySSxHQUFHMlksT0FBT0E7O0lBRVZsWTs7SUFFQSxTQUFTQSxXQUFXO01BQ2xCVCxHQUFHcUk7Ozs7Ozs7OztJQVNMLFNBQVNtUSxVQUFVSSxVQUFVO01BQzNCLElBQUloVyxXQUFXRCxHQUFHRTs7TUFFbEJ3RCxhQUFhMkUsTUFBTTtRQUNqQjZOLGFBQWFEO1FBQ2JFLFVBQVVySixPQUFPMkUsSUFBSXBVLEdBQUcrWSxLQUFLQyxPQUFPdkosT0FBT3dKLFNBQVMsT0FBT0M7UUFDM0RDLE9BQU87U0FDTnZZLEtBQUssVUFBU29DLE1BQU07OztRQUdyQkEsT0FBT3lNLE9BQU9wRCxPQUFPckosTUFBTSxVQUFTaUUsTUFBTTtVQUN4QyxPQUFPLENBQUN3SSxPQUFPMkosS0FBS3BaLEdBQUcrWSxLQUFLQyxPQUFPLEVBQUVsUixPQUFPYixLQUFLYTs7O1FBR25EbEYsU0FBU0osUUFBUVE7OztNQUduQixPQUFPSixTQUFTRzs7Ozs7O0lBTWxCLFNBQVMwVixpQkFBaUI7TUFDeEIsSUFBSXRhLFNBQVM7UUFDWGtILFFBQVE7VUFDTmdVLFFBQVE7VUFDUkMsaUJBQWlCO1lBQ2ZDLGdCQUFnQnZaLEdBQUcwWTs7O1FBR3ZCOVksWUFBWTtRQUNaOEYsY0FBYztRQUNkcEQsYUFBYWxFLE9BQU80RCxhQUFhO1FBQ2pDMkQsYUFBYTs7O01BR2Y5QixTQUFTK0IsT0FBT3pIOzs7Ozs7SUFNbEIsU0FBU3VhLFlBQVl6UixNQUFNO01BQ3pCLElBQUkrUixRQUFRdkosT0FBTzJKLEtBQUtwWixHQUFHK1ksS0FBS0MsT0FBTyxFQUFFbFIsT0FBT2IsS0FBS2E7O01BRXJELElBQUk5SCxHQUFHK1ksS0FBS0MsTUFBTXJVLFNBQVMsS0FBSzFHLFFBQVFzTSxVQUFVeU8sUUFBUTtRQUN4RDlRLFFBQVFxSyxLQUFLN1AsV0FBVzhCLFFBQVE7YUFDM0I7UUFDTHhFLEdBQUcrWSxLQUFLQyxNQUFNblUsS0FBSyxFQUFFNEosTUFBTXhILEtBQUt3SCxNQUFNM0csT0FBT2IsS0FBS2E7Ozs7Ozs7SUFPdEQsU0FBUzZRLE9BQU87O01BRWQzWSxHQUFHK1ksS0FBS3ROLFFBQVE3SyxLQUFLLFVBQVM0RyxVQUFVO1FBQ3RDLElBQUlBLFNBQVM3QyxTQUFTLEdBQUc7VUFDdkIsSUFBSThELE1BQU0vRixXQUFXOEIsUUFBUTs7VUFFN0IsS0FBSyxJQUFJa0UsSUFBRSxHQUFHQSxJQUFJbEIsU0FBUzdDLFFBQVErRCxLQUFLO1lBQ3RDRCxPQUFPakIsV0FBVzs7VUFFcEJVLFFBQVFULE1BQU1nQjtVQUNkekksR0FBR3FJO2VBQ0U7VUFDTEgsUUFBUUssUUFBUTdGLFdBQVc4QixRQUFRO1VBQ25DeEUsR0FBR3FJOzs7Ozs7OztJQVFULFNBQVNBLFlBQVk7TUFDbkJySSxHQUFHK1ksT0FBTyxJQUFJZjtNQUNkaFksR0FBRytZLEtBQUtDLFFBQVE7Ozs7QXBDbTlEdEI7O0FxQzdrRUMsQ0FBQSxZQUFXO0VBQ1Y7OztFQUVBL2EsUUFDR0MsT0FBTyxPQUNQQyxPQUFPOEQ7Ozs7Ozs7OztFQVNWLFNBQVNBLE9BQU9DLGdCQUFnQjlELFFBQVE7SUFDdEM4RCxlQUNHRSxNQUFNLFlBQVk7TUFDakJDLEtBQUs7TUFDTEMsYUFBYWxFLE9BQU80RCxhQUFhO01BQ2pDcEMsWUFBWTtNQUNab0QsTUFBTSxFQUFFQyxvQkFBb0IsTUFBTTRDLGFBQWEsQ0FBQzs7OztBckNnbEV4RDs7QXNDcG1FQyxDQUFBLFlBQVc7RUFDVjs7O0VBRUE1SCxRQUNHQyxPQUFPLE9BQ1A0SCxRQUFRLGdCQUFnQmtTOzs7O0VBSTNCLFNBQVNBLGFBQWFqUyxnQkFBZ0I7SUFDcEMsT0FBT0EsZUFBZSxTQUFTOzs7QXRDdW1FbkM7O0F1Q2puRUEsQ0FBQyxZQUFXOztFQUVWOzs7RUFFQTlILFFBQ0dDLE9BQU8sT0FDUDBCLFdBQVcsd0JBQXdCNFo7Ozs7RUFJdEMsU0FBU0EscUJBQXFCN1YsYUFDNUI4VixtQkFDQWpiLFFBQ0F3VixjQUNBM0csaUJBQ0FuRixTQUNBeEYsWUFDQXlLLFdBQ0FwTixNQUFNOztJQUVOLElBQUlDLEtBQUs7O0lBRVRBLEdBQUcwWixpQkFBaUJBOztJQUVwQjFaLEdBQUc4RCxhQUFhLFlBQVc7TUFDekI5RCxHQUFHZSxjQUFjaEIsS0FBS2dCO01BQ3RCZixHQUFHa0IsVUFBVUMsYUFBYUUsUUFBUTtNQUNsQ2dNLGdCQUFnQnJDLE1BQU0sRUFBRXVDLFlBQVl2TixHQUFHa0IsV0FBV04sS0FBSyxVQUFTNEcsVUFBVTtRQUN4RXhILEdBQUd3TixnQkFBZ0JoRyxTQUFTOztNQUU5QnhILEdBQUdvRSxlQUFlLEVBQUVtSixZQUFZdk4sR0FBR2tCOzs7SUFHckMsU0FBU3dZLGVBQWU5RCxXQUFXO01BQ2pDQSxVQUFVK0Qsa0JBQWtCO01BQzVCLElBQUcvRCxVQUFVN0gsTUFBTXBKLFNBQVMsS0FBS2lSLFVBQVUxVSxRQUFRNE0sa0JBQWtCO1FBQ25FOEgsVUFBVTdILE1BQU1DLFFBQVEsVUFBU0MsTUFBTTtVQUNyQzJILFVBQVUrRCxtQkFBb0J4TCxXQUFXeUgsVUFBVTFVLFFBQVE0TSxvQkFBb0JHLEtBQUtDOzs7TUFHeEYsT0FBTzBILFVBQVUrRCxnQkFBZ0J2TCxlQUFlLFNBQVMsRUFBRUMsdUJBQXVCOzs7SUFHcEZyTyxHQUFHNFosZ0JBQWdCLFVBQVVoRSxXQUFXO01BQ3RDQSxVQUFVMUgsaUJBQWlCO01BQzNCLElBQUcwSCxVQUFVN0gsTUFBTXBKLFNBQVMsR0FBRztRQUM3QmlSLFVBQVU3SCxNQUFNQyxRQUFRLFVBQVNDLE1BQU07VUFDckMySCxVQUFVMUgsa0JBQWtCRCxLQUFLQzs7O01BR3JDMEgsVUFBVTFILGlCQUFpQjBILFVBQVUxSCxpQkFBaUI7TUFDdEQsSUFBSTJMLFVBQVVyYixPQUFPb1gsVUFBVWtFO01BQy9CLElBQUlDLFlBQVl2YixPQUFPb1gsVUFBVW9FOztNQUVqQyxJQUFJSCxRQUFRSSxLQUFLRixXQUFXLFVBQVVuRSxVQUFVMUgsZ0JBQWdCO1FBQzlEMEgsVUFBVXNFLHVCQUF1QixFQUFFNUMsT0FBTzthQUNyQztRQUNMMUIsVUFBVXNFLHVCQUF1QixFQUFFNUMsT0FBTzs7TUFFNUMsT0FBTzFCLFVBQVUxSDs7O0lBR25CbE8sR0FBRytELGVBQWUsVUFBU21CLHFCQUFxQjtNQUM5QyxPQUFPakgsUUFBUWtILE9BQU9ELHFCQUFxQmxGLEdBQUdvRTs7O0lBR2hEcEUsR0FBR3dMLGFBQWEsWUFBVztNQUN6QnhMLEdBQUdpSyxTQUFTc0QsYUFBYXZOLEdBQUdrQjs7O0lBRzlCbEIsR0FBRytMLGVBQWUsWUFBVztNQUMzQi9MLEdBQUdpSyxTQUFTc0QsYUFBYXZOLEdBQUdrQjs7O0lBRzlCbEIsR0FBR1AsYUFBYSxVQUFTQyxNQUFNO01BQzdCLE9BQU9sQixPQUFPa0IsTUFBTUMsT0FBTzs7O0lBRzdCSyxHQUFHdUwsWUFBWSxZQUFXO01BQ3hCdkwsR0FBR2lLLFNBQVMrUCxhQUFheGIsT0FBT3dCLEdBQUdpSyxTQUFTK1AsWUFBWUc7TUFDeERuYSxHQUFHaUssU0FBUzZQLFdBQVd0YixPQUFPd0IsR0FBR2lLLFNBQVM2UCxVQUFVSzs7O0lBR3REbmEsR0FBR29hLE9BQU8sVUFBVW5RLFVBQVU7TUFDNUJqSyxHQUFHaUssV0FBV0E7TUFDZGpLLEdBQUdpSyxTQUFTK1AsYUFBYXhiLE9BQU93QixHQUFHaUssU0FBUytQO01BQzVDaGEsR0FBR2lLLFNBQVM2UCxXQUFXdGIsT0FBT3dCLEdBQUdpSyxTQUFTNlA7TUFDMUM5WixHQUFHb00sU0FBUztNQUNacE0sR0FBR2dLLFdBQVc7OztJQUdoQmhLLEdBQUdxYSxhQUFhLFVBQVVDLFVBQVU7TUFDbEMsT0FBT3RHLGFBQWFoSixNQUFNO1FBQ3hCdVAsaUJBQWlCO1FBQ2pCaE4sWUFBWXZOLEdBQUdpSyxTQUFTc0Q7UUFDeEIzQixPQUFPME87Ozs7SUFJWHRhLEdBQUd3YSxlQUFlLFlBQVc7TUFDM0IsSUFBSXhhLEdBQUdpTyxTQUFTLFFBQVFqTyxHQUFHaUssU0FBUzhELE1BQU0wTSxVQUFVLFVBQUEsR0FBQTtRQUFBLE9BQUsvUixFQUFFcEUsT0FBT3RFLEdBQUdpTyxLQUFLM0o7YUFBUSxDQUFDLEdBQUc7UUFDcEZ0RSxHQUFHaUssU0FBUzhELE1BQU1sSixLQUFLN0UsR0FBR2lPOzs7O0lBSTlCak8sR0FBRzBhLGFBQWEsVUFBU3pNLE1BQU07TUFDN0JqTyxHQUFHaUssU0FBUzhELE1BQU00TSxNQUFNLEdBQUczTSxRQUFRLFVBQVNtSSxTQUFTO1FBQ25ELElBQUdBLFFBQVE3UixPQUFPMkosS0FBSzNKLElBQUk7VUFDekJ0RSxHQUFHaUssU0FBUzhELE1BQU1tRCxPQUFPbFIsR0FBR2lLLFNBQVM4RCxNQUFNNEMsUUFBUXdGLFVBQVU7Ozs7O0lBS25FblcsR0FBRzRhLFlBQVksWUFBVztNQUN4QjVHLGFBQWE2RyxnQkFBZ0IsRUFBQ3ROLFlBQVl2TixHQUFHaUssU0FBU3NELFlBQVl1TixjQUFjOWEsR0FBR2lLLFNBQVMzRixJQUFJeUosT0FBTy9OLEdBQUdpSyxTQUFTOEQsU0FBUW5OLEtBQUssWUFBVTtRQUN4SXNILFFBQVFLLFFBQVE3RixXQUFXOEIsUUFBUTtRQUNuQ3hFLEdBQUdnSyxXQUFXO1FBQ2RoSyxHQUFHb00sU0FBUztTQUNYLFlBQVc7UUFDWmxFLFFBQVFULE1BQU0vRSxXQUFXOEIsUUFBUTs7OztJQUlyQ3hFLEdBQUdvUCxXQUFXLFVBQVN3RyxXQUFXO01BQ2hDLElBQUk5SixVQUFVcUIsVUFBVXJCLFVBQ25CRixNQUFNLG9CQUNObUQsWUFBWSwrQ0FBK0M2RyxVQUFVaEssUUFBUSxLQUM3RThDLEdBQUcsT0FDSEMsT0FBTzs7TUFFWnhCLFVBQVV5QixLQUFLOUMsU0FBU2xMLEtBQUssWUFBVztRQUN0QzZZLGtCQUFrQnJLLFNBQVMsRUFBRTdCLFlBQVl2TixHQUFHa0IsU0FBUzRaLGNBQWNsRixVQUFVdFIsTUFBTTFELEtBQUssWUFBVztVQUNqR3NILFFBQVFLLFFBQVE3RixXQUFXOEIsUUFBUTtVQUNuQ3hFLEdBQUdxSjtXQUNGLFlBQVc7VUFDWm5CLFFBQVFtSCxNQUFNM00sV0FBVzhCLFFBQVE7Ozs7OztJQU12Q2IsWUFBWSxrQkFBa0IsRUFBRTNELElBQUlBLElBQUlpRSxjQUFjd1YsbUJBQW1CdlYsU0FBUzs7O0F2QzBtRXRGOztBd0N2dkVDLENBQUEsWUFBVztFQUNWOzs7RUFFQWpHLFFBQ0dDLE9BQU8sT0FDUEMsT0FBTzhEOzs7Ozs7Ozs7RUFTVixTQUFTQSxPQUFPQyxnQkFBZ0I5RCxRQUFRO0lBQ3RDOEQsZUFDR0UsTUFBTSxrQkFBa0I7TUFDdkJDLEtBQUs7TUFDTEMsYUFBYWxFLE9BQU80RCxhQUFhO01BQ2pDcEMsWUFBWTtNQUNab0QsTUFBTTs7OztBeEMwdkVkOztBeUM5d0VDLENBQUEsWUFBVztFQUNWOzs7RUFFQS9FLFFBQ0dDLE9BQU8sT0FDUDRILFFBQVEscUJBQXFCMlQ7OztFQUdoQyxTQUFTQSxrQkFBa0IxVCxnQkFBZ0I7SUFDekMsSUFBSW5CLFFBQVFtQixlQUFlLGNBQWM7TUFDdkNDLFNBQVM7UUFDUG9KLFVBQVU7VUFDUm5KLFFBQVE7VUFDUjVELEtBQUs7O1FBRVAwWSxlQUFlO1VBQ2I5VSxRQUFRO1VBQ1I1RCxLQUFLOzs7TUFHVDZELFVBQVU7OztJQUdaLE9BQU90Qjs7O0F6Q2l4RVg7O0EwQ3h5RUMsQ0FBQSxZQUFXO0VBQ1Y7OztFQUVBM0csUUFDR0MsT0FBTyxPQUNQNEgsUUFBUSxxQkFBcUJrVjs7O0VBR2hDLFNBQVNBLGtCQUFrQmpWLGdCQUFnQjtJQUN6QyxJQUFJbkIsUUFBUW1CLGVBQWUsY0FBYztNQUN2Q0MsU0FBUztNQUNURSxVQUFVOzs7SUFHWixPQUFPdEI7OztBMUMyeUVYOztBMkN6ekVBLENBQUMsWUFBVzs7RUFFVjs7O0VBRUEzRyxRQUNHQyxPQUFPLE9BQ1AwQixXQUFXLHNCQUFzQnFiOzs7O0VBSXBDLFNBQVNBLG1CQUFtQnRYLGFBQzFCMEosaUJBQ0F0TixNQUNBbWIsY0FDQTdVLGNBQ0F2RyxRQUNBZ1MsU0FDQXhPLGNBQ0E2WCxTQUFTO0lBQ1QsSUFBSW5iLEtBQUs7Ozs7O0lBS1RBLEdBQUc4RCxhQUFhQTtJQUNoQjlELEdBQUcrRCxlQUFlQTtJQUNsQi9ELEdBQUd3TCxhQUFhQTtJQUNoQnhMLEdBQUdvYixhQUFhQTtJQUNoQnBiLEdBQUdxYixVQUFVQTtJQUNicmIsR0FBR3NiLGFBQWFBO0lBQ2hCdGIsR0FBR3ViLGNBQWNBOztJQUVqQnZiLEdBQUd3YixRQUFRO0lBQ1h4YixHQUFHZ1osUUFBUTs7SUFFWCxTQUFTbFYsYUFBYTtNQUNwQjlELEdBQUdlLGNBQWNoQixLQUFLZ0I7TUFDdEJmLEdBQUdvRSxlQUFlLEVBQUVxWCxTQUFTemIsR0FBR2UsWUFBWXVEO01BQzVDNFcsYUFBYWxRLFFBQVFwSyxLQUFLLFVBQVM0RyxVQUFVO1FBQzNDeEgsR0FBR3diLFFBQVFoVTtRQUNYLElBQUlsRSxhQUFhcUssUUFBUSxRQUFRO1VBQy9CM04sR0FBR3FJO1VBQ0hySSxHQUFHZ0ssV0FBVztVQUNkaEssR0FBR2lLLFdBQVczRyxhQUFhMkc7VUFDM0J5UixXQUFXMWIsR0FBR2lLO2VBQ1Q7VUFDTDlJLGFBQWFHLFdBQVc7Ozs7O0lBSzlCLFNBQVN5QyxhQUFhbUIscUJBQXFCO01BQ3pDLE9BQU9qSCxRQUFRa0gsT0FBT0QscUJBQXFCbEYsR0FBRzJiOzs7SUFHaEQsU0FBU25RLGFBQWE7TUFDcEIsSUFBSSxDQUFDeEwsR0FBR2lLLFNBQVN1TCxPQUFPO1FBQ3RCeFYsR0FBR2lLLFNBQVN1TCxRQUFRelYsS0FBS2dCLFlBQVl1RDs7TUFFdkN0RSxHQUFHaUssU0FBU3dSLFVBQVUxYixLQUFLZ0IsWUFBWXVEOzs7SUFHekMsU0FBUzhXLGFBQWE7TUFDcEIsT0FBTy9VLGFBQWEyRSxNQUFNLEVBQUV5RCxNQUFNek8sR0FBRzRiOzs7SUFHdkMsU0FBU1AsUUFBUXBVLE1BQU07TUFDckIsSUFBSSxDQUFDakgsR0FBR2lLLFNBQVMrTyxPQUFPO1FBQ3RCaFosR0FBR2lLLFNBQVMrTyxRQUFROztNQUV0QixJQUFJL1IsTUFBTTtRQUNSakgsR0FBR2lLLFNBQVMrTyxNQUFNblUsS0FBS29DO1FBQ3ZCakgsR0FBRzRiLFdBQVc7Ozs7SUFJbEIsU0FBU04sV0FBVzVXLE9BQU87TUFDekIxRSxHQUFHaUssU0FBUytPLE1BQU05SCxPQUFPeE0sT0FBTzs7O0lBR2xDLFNBQVNYLGFBQWFtQixxQkFBcUI7TUFDekMsT0FBT2pILFFBQVFrSCxPQUFPRCxxQkFBcUJsRixHQUFHb0U7OztJQUdoRCxTQUFTbVgsY0FBYztNQUNyQnpiLE9BQU9lLEdBQUc7OztJQUdaYixHQUFHNkssY0FBYyxZQUFXO01BQzFCLElBQUk3SyxHQUFHMkssVUFBVWhHLFNBQVMsR0FBRztRQUMzQjNFLEdBQUcySyxVQUFVcUQsUUFBUSxVQUFTOU0sU0FBUztVQUNyQ3dhLFdBQVd4YTs7Ozs7SUFLakIsU0FBU3dhLFdBQVd4YSxTQUFTO01BQzNCQSxRQUFROFgsUUFBUTtNQUNoQixJQUFJOVgsUUFBUTJhLFdBQVc7UUFDckIzYSxRQUFRNGEsT0FBT0MsT0FBT2pLLFFBQVEsVUFBVTlSLEdBQUd3YixPQUFPLEVBQUUvRyxNQUFNLFlBQVk7UUFDdEV2VCxRQUFROFgsTUFBTW5VLEtBQUszRCxRQUFRNGE7O01BRTdCLElBQUk1YSxRQUFROGEsUUFBUTtRQUNsQjlhLFFBQVErYSxVQUFVRixPQUFPakssUUFBUSxVQUFVOVIsR0FBR3diLE9BQU8sRUFBRS9HLE1BQU0sU0FBUztRQUN0RXZULFFBQVE4WCxNQUFNblUsS0FBSzNELFFBQVErYTs7TUFFN0IsSUFBSS9hLFFBQVFnYixnQkFBZ0I7UUFDMUJoYixRQUFRaWIsWUFBWUosT0FBT2pLLFFBQVEsVUFBVTlSLEdBQUd3YixPQUFPLEVBQUUvRyxNQUFNLGlCQUFpQjtRQUNoRnZULFFBQVE4WCxNQUFNblUsS0FBSzNELFFBQVFpYjs7OztJQUkvQm5jLEdBQUdvYyxjQUFjLFlBQVc7TUFDMUIsSUFBSTlZLGFBQWFxSyxLQUFLO1FBQ3BCd04sUUFBUWtCLFFBQVFDO2FBQ1g7UUFDTHRjLEdBQUdnSyxXQUFXOzs7O0lBSWxCaEssR0FBRzBMLFlBQVksVUFBU3pCLFVBQVU7TUFDaEM5SSxhQUFhQyxRQUFRLFdBQVc2SSxTQUFTM0Y7TUFDekN4RSxPQUFPZSxHQUFHOzs7O0lBSVo4QyxZQUFZLGtCQUFrQixFQUFFM0QsSUFBSUEsSUFBSWlFLGNBQWNvSixpQkFBaUJuSixTQUFTLEVBQUUwRixtQkFBbUI7OztBM0NvekV6Rzs7QTRDbDdFQyxDQUFBLFlBQVc7RUFDVjs7O0VBRUEzTCxRQUNHQyxPQUFPLE9BQ1BDLE9BQU84RDs7Ozs7Ozs7O0VBU1YsU0FBU0EsT0FBT0MsZ0JBQWdCOUQsUUFBUTtJQUN0QzhELGVBQ0dFLE1BQU0sZ0JBQWdCO01BQ3JCQyxLQUFLO01BQ0xDLGFBQWFsRSxPQUFPNEQsYUFBYTtNQUNqQ3BDLFlBQVk7TUFDWm9ELE1BQU0sRUFBRUMsb0JBQW9CO01BQzVCc1osUUFBUSxFQUFFNU8sS0FBSyxNQUFNMUQsVUFBVTs7OztBNUNxN0V2Qzs7QTZDMThFQyxDQUFBLFlBQVc7RUFDVjs7O0VBRUFoTSxRQUNHQyxPQUFPLE9BQ1A0SCxRQUFRLG1CQUFtQnVIOzs7RUFHOUIsU0FBU0EsZ0JBQWdCdEgsZ0JBQWdCO0lBQ3ZDLE9BQU9BLGVBQWUsWUFBWTtNQUNoQ0MsU0FBUztRQUNQb0osVUFBVTtVQUNSbkosUUFBUTtVQUNSNUQsS0FBSzs7UUFFUGtNLGdCQUFnQjtVQUNkdEksUUFBUTtVQUNSNUQsS0FBSzs7O01BR1Q2RCxVQUFVOzs7O0E3Qzg4RWhCOztBOENsK0VBLENBQUMsWUFBVzs7RUFFVjs7O0VBRUFqSSxRQUNHQyxPQUFPLE9BQ1AwQixXQUFXLHNCQUFzQjRjOzs7O0VBSXBDLFNBQVNBLG1CQUFtQjdZLGFBQzFCOFksaUJBQ0FoRCxtQkFDQXBNLGlCQUNBdE4sTUFDQW1JLFNBQ0ExSixRQUNBMk8sV0FDQXpLLFlBQVk7SUFDWixJQUFJMUMsS0FBSzs7O0lBR1RBLEdBQUcrRCxlQUFlQTs7O0lBR2xCL0QsR0FBRzhELGFBQWEsWUFBVztNQUN6QjlELEdBQUdlLGNBQWNoQixLQUFLZ0I7TUFDdEJmLEdBQUdrQixVQUFVQyxhQUFhRSxRQUFRO01BQ2xDZ00sZ0JBQWdCckMsTUFBTSxFQUFFdUMsWUFBWXZOLEdBQUdrQixXQUFXTixLQUFLLFVBQVM0RyxVQUFVO1FBQ3hFeEgsR0FBR3dOLGdCQUFnQmhHLFNBQVM7O01BRTlCeEgsR0FBR29FLGVBQWUsRUFBRW1KLFlBQVl2TixHQUFHa0I7OztJQUdyQyxTQUFTNkMsYUFBYW1CLHFCQUFxQjtNQUN6QyxPQUFPakgsUUFBUWtILE9BQU9ELHFCQUFxQmxGLEdBQUdvRTs7O0lBR2hEcEUsR0FBR3dMLGFBQWEsWUFBVztNQUN6QnhMLEdBQUdpSyxTQUFTc0QsYUFBYXZOLEdBQUdrQjs7O0lBRzlCbEIsR0FBRytMLGVBQWUsWUFBVztNQUMzQi9MLEdBQUdpSyxTQUFTc0QsYUFBYXZOLEdBQUdrQjs7O0lBRzlCbEIsR0FBR29hLE9BQU8sVUFBVW5RLFVBQVU7TUFDNUJqSyxHQUFHaUssV0FBV0E7TUFDZGpLLEdBQUdvTSxTQUFTO01BQ1pwTSxHQUFHZ0ssV0FBVzs7O0lBR2hCaEssR0FBR29QLFdBQVcsVUFBU3NOLFNBQVM7TUFDOUIsSUFBSTVRLFVBQVVxQixVQUFVckIsVUFDbkJGLE1BQU0scUJBQ05tRCxZQUFZLGdEQUFnRDJOLFFBQVE5USxRQUFRLEtBQzVFOEMsR0FBRyxPQUNIQyxPQUFPOztNQUVaeEIsVUFBVXlCLEtBQUs5QyxTQUFTbEwsS0FBSyxZQUFXO1FBQ3RDNmIsZ0JBQWdCck4sU0FBUyxFQUFFN0IsWUFBWXZOLEdBQUdrQixTQUFTeWIsWUFBWUQsUUFBUXBZLE1BQU0xRCxLQUFLLFlBQVc7VUFDM0ZzSCxRQUFRSyxRQUFRN0YsV0FBVzhCLFFBQVE7VUFDbkN4RSxHQUFHcUo7V0FDRixZQUFXO1VBQ1puQixRQUFRbUgsTUFBTTNNLFdBQVc4QixRQUFROzs7OztJQUt2Q3hFLEdBQUdQLGFBQWEsVUFBU0MsTUFBTTtNQUM3QixPQUFPbEIsT0FBT2tCLE1BQU1DLE9BQU87OztJQUc3QkssR0FBRzRjLGtCQUFrQixVQUFVQyxlQUFlO01BQzVDLE9BQU9wRCxrQkFBa0J6TyxNQUFNO1FBQzdCOFIsZUFBZTtRQUNmdlAsWUFBWXZOLEdBQUdpSyxTQUFTc0Q7UUFDeEIzQixPQUFPaVI7Ozs7SUFJWDdjLEdBQUcrYyxvQkFBb0IsWUFBVztNQUNoQyxJQUFJL2MsR0FBRzRWLGNBQWMsUUFBUTVWLEdBQUdpSyxTQUFTK1MsV0FBV3ZDLFVBQVUsVUFBQSxHQUFBO1FBQUEsT0FBSy9SLEVBQUVwRSxPQUFPdEUsR0FBRzRWLFVBQVV0UjthQUFRLENBQUMsR0FBRztRQUNuR3RFLEdBQUdpSyxTQUFTK1MsV0FBV25ZLEtBQUs3RSxHQUFHNFY7Ozs7SUFJbkM1VixHQUFHaWQsa0JBQWtCLFVBQVNySCxXQUFXO01BQ3ZDNVYsR0FBR2lLLFNBQVMrUyxXQUFXckMsTUFBTSxHQUFHM00sUUFBUSxVQUFTbUksU0FBUztRQUN4RCxJQUFHQSxRQUFRN1IsT0FBT3NSLFVBQVV0UixJQUFJO1VBQzlCdEUsR0FBR2lLLFNBQVMrUyxXQUFXOUwsT0FBT2xSLEdBQUdpSyxTQUFTK1MsV0FBV3JNLFFBQVF3RixVQUFVOzs7OztJQUs3RW5XLEdBQUdrZCxpQkFBaUIsWUFBVztNQUM3QnpELGtCQUFrQnNCLGNBQWMsRUFBQ3hOLFlBQVl2TixHQUFHaUssU0FBU3NELFlBQVlvUCxZQUFZM2MsR0FBR2lLLFNBQVMzRixJQUFJMFksWUFBWWhkLEdBQUdpSyxTQUFTK1MsY0FBYXBjLEtBQUssWUFBVTtRQUNuSnNILFFBQVFLLFFBQVE3RixXQUFXOEIsUUFBUTtRQUNuQ3hFLEdBQUdnSyxXQUFXO1FBQ2RoSyxHQUFHb00sU0FBUztTQUNYLFlBQVc7UUFDWmxFLFFBQVFULE1BQU0vRSxXQUFXOEIsUUFBUTs7OztJQUlyQ3hFLEdBQUc0WixnQkFBZ0IsVUFBVWhFLFdBQVc7TUFDdENBLFVBQVUxSCxpQkFBaUI7TUFDM0IsSUFBRzBILFVBQVU3SCxNQUFNcEosU0FBUyxHQUFHO1FBQzdCaVIsVUFBVTdILE1BQU1DLFFBQVEsVUFBU0MsTUFBTTtVQUNyQzJILFVBQVUxSCxrQkFBa0JELEtBQUtDOzs7TUFHckMsT0FBTzBILFVBQVUxSCxpQkFBaUI7Ozs7SUFJcEN2SyxZQUFZLGtCQUFrQixFQUFFM0QsSUFBSUEsSUFBSWlFLGNBQWN3WSxpQkFBaUJ2WSxTQUFTOzs7QTlDMjlFcEY7O0ErQy9rRkMsQ0FBQSxZQUFXO0VBQ1Y7OztFQUVBakcsUUFDR0MsT0FBTyxPQUNQQyxPQUFPOEQ7Ozs7Ozs7OztFQVNWLFNBQVNBLE9BQU9DLGdCQUFnQjlELFFBQVE7SUFDdEM4RCxlQUNHRSxNQUFNLGdCQUFnQjtNQUNyQkMsS0FBSztNQUNMQyxhQUFhbEUsT0FBTzRELGFBQWE7TUFDakNwQyxZQUFZO01BQ1pvRCxNQUFNOzs7O0EvQ2tsRmQ7O0FnRHRtRkMsQ0FBQSxZQUFXO0VBQ1Y7OztFQUVBL0UsUUFDR0MsT0FBTyxPQUNQNEgsUUFBUSxtQkFBbUIyVzs7O0VBRzlCLFNBQVNBLGdCQUFnQjFXLGdCQUFnQjtJQUN2QyxJQUFJbkIsUUFBUW1CLGVBQWUsWUFBWTtNQUNyQ0MsU0FBUztRQUNQb0osVUFBVTtVQUNSbkosUUFBUTtVQUNSNUQsS0FBSzs7O01BR1Q2RCxVQUFVOzs7SUFHWixPQUFPdEI7OztBaER5bUZYOztBaUQ1bkZBLENBQUMsWUFBVzs7RUFFVjs7O0VBRUEzRyxRQUNHQyxPQUFPLE9BQ1BtTyxPQUFPLFlBQVk4UTs7O0VBR3RCLFNBQVNBLFNBQVMxTixRQUFROzs7OztJQUt4QixPQUFPLFVBQVMrTCxPQUFPO01BQ3JCLE9BQU8vTCxPQUFPMkUsSUFBSW9ILE9BQU8sUUFBUTRCLEtBQUs7Ozs7QWpEZ29GNUM7O0FrRC9vRkMsQ0FBQSxZQUFXO0VBQ1Y7OztFQUVBbmYsUUFDR0MsT0FBTyxPQUNQNEgsUUFBUSxnQkFBZ0JvVjs7O0VBRzNCLFNBQVNBLGFBQWFuVixnQkFBZ0I7SUFDcEMsT0FBT0EsZUFBZTs7O0FsRGtwRjFCOztBbUQzcEZDLENBQUEsWUFBVztFQUNWOzs7RUFFQTlILFFBQ0dDLE9BQU8sT0FDUDRILFFBQVEsaUJBQWlCbU87OztFQUc1QixTQUFTQSxjQUFjbE8sZ0JBQWdCO0lBQ3JDLElBQUluQixRQUFRbUIsZUFBZSxVQUFVO01BQ25DQyxTQUFTO01BQ1RFLFVBQVU7OztJQUdaLE9BQU90Qjs7O0FuRDhwRlg7O0FvRDVxRkMsQ0FBQSxZQUFXO0VBQ1Y7OztFQUVBM0csUUFDR0MsT0FBTyxPQUNQNEgsUUFBUSxrQkFBa0JzTDs7O0VBRzdCLFNBQVNBLGVBQWVyTCxnQkFBZ0I7SUFDdEMsT0FBT0EsZUFBZSxXQUFXO01BQy9CQyxTQUFTOzs7Ozs7UUFNUDRMLE9BQU87VUFDTDNMLFFBQVE7VUFDUjVELEtBQUs7VUFDTDJHLE1BQU07VUFDTnFVLE9BQU87Ozs7OztBcERrckZqQjs7QXFEdHNGQyxDQUFBLFlBQVc7RUFDVjs7O0VBRUFwZixRQUNHQyxPQUFPLE9BQ1A0SCxRQUFRLHVCQUF1QndYOzs7RUFHbEMsU0FBU0Esb0JBQW9CdlgsZ0JBQWdCO0lBQzNDLElBQUluQixRQUFRbUIsZUFBZSxpQkFBaUI7TUFDMUNDLFNBQVM7UUFDUHVYLGlCQUFpQjtVQUNmdFgsUUFBUTtVQUNSNUQsS0FBSzs7UUFFUG1iLG1CQUFtQjtVQUNqQnZYLFFBQVE7VUFDUjVELEtBQUs7OztNQUdUNkQsVUFBVTs7O0lBR1osT0FBT3RCOzs7QXJEeXNGWDs7QXNEaHVGQSxDQUFDLFlBQVc7O0VBRVY7OztFQUVBM0csUUFDR0MsT0FBTyxPQUNQbU8sT0FBTyxXQUFXLFlBQVc7SUFDNUIsT0FBTyxVQUFTM00sTUFBTTtNQUNwQixJQUFJLENBQUNBLE1BQU07TUFDWCxJQUFJNE0sT0FBTzVMLEtBQUs2TCxNQUFNN007VUFDcEI4TSxVQUFVLElBQUk5TCxPQUFPK0w7VUFDckJDLGFBQWFGLFVBQVVGO1VBQ3ZCSyxVQUFVQyxLQUFLQyxNQUFNSCxhQUFhO1VBQ2xDSSxVQUFVRixLQUFLQyxNQUFNRixVQUFVO1VBQy9CSSxRQUFRSCxLQUFLQyxNQUFNQyxVQUFVO1VBQzdCRSxPQUFPSixLQUFLQyxNQUFNRSxRQUFRO1VBQzFCRSxTQUFTTCxLQUFLQyxNQUFNRyxPQUFPOztNQUU3QixJQUFJQyxTQUFTLEdBQUc7UUFDZCxPQUFPQSxTQUFTO2FBQ1gsSUFBSUEsV0FBVyxHQUFHO1FBQ3ZCLE9BQU87YUFDRixJQUFJRCxPQUFPLEdBQUc7UUFDbkIsT0FBT0EsT0FBTzthQUNULElBQUlBLFNBQVMsR0FBRztRQUNyQixPQUFPO2FBQ0YsSUFBSUQsUUFBUSxHQUFHO1FBQ3BCLE9BQU9BLFFBQVE7YUFDVixJQUFJQSxVQUFVLEdBQUc7UUFDdEIsT0FBTzthQUNGLElBQUlELFVBQVUsR0FBRztRQUN0QixPQUFPQSxVQUFVO2FBQ1osSUFBSUEsWUFBWSxHQUFHO1FBQ3hCLE9BQU87YUFDRjtRQUNMLE9BQU87OztLQUlabE4sV0FBVyxtQkFBbUI2ZDs7OztFQUlqQyxTQUFTQSxnQkFBZ0I5WixhQUN2QnFRLGNBQ0FDLGVBQ0ErRyxtQkFDQTBDLGNBQ0FKLHFCQUNBalEsaUJBQ0E3TyxRQUNBdUIsTUFDQW1JLFNBQ0F4RixZQUNBb1AsU0FDQTFULFFBQVE7SUFDUixJQUFJNEIsS0FBSzs7Ozs7SUFLVEEsR0FBRzhELGFBQWFBO0lBQ2hCOUQsR0FBRytELGVBQWVBO0lBQ2xCL0QsR0FBR3dMLGFBQWFBO0lBQ2hCeEwsR0FBRytMLGVBQWVBOztJQUVsQixTQUFTakksYUFBYTtNQUNwQjlELEdBQUdlLGNBQWNoQixLQUFLZ0I7TUFDdEJmLEdBQUdpQixZQUFZN0MsT0FBTzZDLFlBQVk7TUFDbENqQixHQUFHa0IsVUFBVUMsYUFBYUUsUUFBUTtNQUNsQ2dNLGdCQUFnQnJDLE1BQU0sRUFBRXVDLFlBQVl2TixHQUFHa0IsV0FBV04sS0FBSyxVQUFTNEcsVUFBVTtRQUN4RXhILEdBQUd3TixnQkFBZ0JoRyxTQUFTOztNQUU5QnhILEdBQUdvRSxlQUFlLEVBQUVtSixZQUFZdk4sR0FBR2tCOztNQUVuQytTLGNBQWNqSixRQUFRcEssS0FBSyxVQUFTNEcsVUFBVTtRQUM1Q3hILEdBQUd3SSxTQUFTaEI7OztNQUdkd1Qsa0JBQWtCaFEsUUFBUXBLLEtBQUssVUFBUzRHLFVBQVU7UUFDaER4SCxHQUFHMmQsYUFBYW5XOzs7TUFHbEJrVyxhQUFhMVMsUUFBUXBLLEtBQUssVUFBUzRHLFVBQVU7UUFDM0N4SCxHQUFHK0UsUUFBUXlDOzs7O0lBSWYsU0FBU3pELGFBQWFtQixxQkFBcUI7TUFDekMsT0FBT2pILFFBQVFrSCxPQUFPRCxxQkFBcUJsRixHQUFHb0U7OztJQUdoRCxTQUFTb0gsYUFBYTtNQUNwQnhMLEdBQUdpSyxTQUFTc0QsYUFBYXZOLEdBQUdrQjs7O0lBRzlCLFNBQVM2SyxlQUFlO01BQ3RCL0wsR0FBR2lLLFNBQVNzRCxhQUFhdk4sR0FBR2tCOzs7SUFHOUJsQixHQUFHb2EsT0FBTyxVQUFVblEsVUFBVTtNQUM1QmpLLEdBQUdpSyxXQUFXQTtNQUNkakssR0FBR29NLFNBQVM7TUFDWnBNLEdBQUdnSyxXQUFXOzs7SUFHaEJoSyxHQUFHNGQsY0FBYyxVQUFTQyxTQUFTO01BQ2pDLElBQUloUyxjQUFjO01BQ2xCLElBQUlpUyxhQUFhOztNQUVqQixJQUFJRCxTQUFTO1FBQ1hoUyxjQUFjN0wsR0FBRytkO1FBQ2pCRCxhQUFhRCxRQUFRdlo7YUFDaEI7UUFDTHVILGNBQWM3TCxHQUFHNmQ7O01BRW5CUCxvQkFBb0JDLGdCQUFnQixFQUFFaFEsWUFBWXZOLEdBQUdrQixTQUFTdVUsU0FBU3pWLEdBQUdpSyxTQUFTM0YsSUFBSTBaLGNBQWNuUyxhQUFhaVMsWUFBWUEsY0FBY2xkLEtBQUssWUFBVztRQUMxSlosR0FBRzZkLFVBQVU7UUFDYjdkLEdBQUcrZCxTQUFTO1FBQ1ovZCxHQUFHcUo7UUFDSG5CLFFBQVFLLFFBQVE3RixXQUFXOEIsUUFBUTtTQUNsQyxZQUFXO1FBQ1owRCxRQUFRVCxNQUFNL0UsV0FBVzhCLFFBQVE7Ozs7SUFJckN4RSxHQUFHaWUsZ0JBQWdCLFVBQVNKLFNBQVM7TUFDbkNQLG9CQUFvQkUsa0JBQWtCLEVBQUVNLFlBQVlELFFBQVF2WixNQUFNMUQsS0FBSyxZQUFXO1FBQ2hGWixHQUFHcUo7UUFDSG5CLFFBQVFLLFFBQVE3RixXQUFXOEIsUUFBUTtTQUNsQyxZQUFXO1FBQ1owRCxRQUFRVCxNQUFNL0UsV0FBVzhCLFFBQVE7Ozs7SUFJckN4RSxHQUFHNkssY0FBYyxZQUFXO01BQzFCLElBQUk3SyxHQUFHaUssU0FBUzNGLElBQUk7UUFDbEJ0RSxHQUFHaUssV0FBVzZILFFBQVEsVUFBVTlSLEdBQUcySyxXQUFXLEVBQUVyRyxJQUFJdEUsR0FBR2lLLFNBQVMzRixNQUFNOzs7O0lBSTFFdEUsR0FBR3NOLFVBQVUsVUFBU0csWUFBWTtNQUNoQyxPQUFPalAsT0FBT2lQOzs7O0lBSWhCOUosWUFBWSxrQkFBa0IsRUFBRTNELElBQUlBLElBQUlpRSxjQUFjK1AsY0FBYzlQLFNBQVMsRUFBRTZGLGdCQUFnQjs7O0F0RHN0Rm5HOztBdUR4MkZDLENBQUEsWUFBVztFQUNWOzs7RUFFQTlMLFFBQ0dDLE9BQU8sT0FDUEMsT0FBTzhEOzs7Ozs7Ozs7RUFTVixTQUFTQSxPQUFPQyxnQkFBZ0I5RCxRQUFRO0lBQ3RDOEQsZUFDR0UsTUFBTSxhQUFhO01BQ2xCQyxLQUFLO01BQ0xDLGFBQWFsRSxPQUFPNEQsYUFBYTtNQUNqQ3BDLFlBQVk7TUFDWm9ELE1BQU0sRUFBRUMsb0JBQW9COzs7O0F2RDIyRnBDOztBd0QvM0ZDLENBQUEsWUFBVztFQUNWOzs7RUFFQWhGLFFBQ0dDLE9BQU8sT0FDUDRILFFBQVEsZ0JBQWdCa087OztFQUczQixTQUFTQSxhQUFhak8sZ0JBQWdCO0lBQ3BDLE9BQU9BLGVBQWUsU0FBUztNQUM3QkMsU0FBUztRQUNQNlUsaUJBQWlCO1VBQ2Y1VSxRQUFRO1VBQ1I1RCxLQUFLOztRQUVQd1Qsb0JBQW9CO1VBQ2xCNVAsUUFBUTtVQUNSNUQsS0FBSzs7O01BR1Q2RCxVQUFVOzs7O0F4RG00RmhCOztBeUR2NUZDLENBQUEsWUFBVztFQUNWOzs7RUFFQWpJLFFBQ0dDLE9BQU8sT0FDUDRILFFBQVEsZ0JBQWdCNFg7OztFQUczQixTQUFTQSxhQUFhM1gsZ0JBQWdCO0lBQ3BDLElBQUluQixRQUFRbUIsZUFBZSxTQUFTO01BQ2xDQyxTQUFTO01BQ1RFLFVBQVU7OztJQUdaLE9BQU90Qjs7O0F6RDA1Rlg7O0EwRHg2RkEsQ0FBQyxZQUFXOztFQUVWOzs7RUFFQTNHLFFBQ0dDLE9BQU8sT0FDUDBCLFdBQVcscUJBQXFCc2U7Ozs7RUFJbkMsU0FBU0Esa0JBQWtCN1gsY0FBY3RHLE1BQU1tSSxTQUFTeEYsWUFBWXlZLFNBQVMzYyxRQUFRO0lBQ25GLElBQUl3QixLQUFLOztJQUVUQSxHQUFHbWUsU0FBU0E7SUFDWm5lLEdBQUdvYyxjQUFjQTs7SUFFakIzYjs7SUFFQSxTQUFTQSxXQUFXO01BQ2xCVCxHQUFHaUgsT0FBT2hKLFFBQVFxTixLQUFLdkwsS0FBS2dCO01BQzVCLElBQUlmLEdBQUdpSCxLQUFLbVgsVUFBVTtRQUNwQnBlLEdBQUdpSCxLQUFLbVgsV0FBVzVmLE9BQU93QixHQUFHaUgsS0FBS21YLFVBQVV6ZSxPQUFPOzs7O0lBSXZELFNBQVN3ZSxTQUFTO01BQ2hCLElBQUluZSxHQUFHaUgsS0FBS21YLFVBQVU7UUFDcEJwZSxHQUFHaUgsS0FBS21YLFdBQVc1ZixPQUFPd0IsR0FBR2lILEtBQUttWDs7TUFFcEMvWCxhQUFhZ1ksY0FBY3JlLEdBQUdpSCxNQUFNckcsS0FBSyxVQUFVNEcsVUFBVTs7UUFFM0R6SCxLQUFLd0csa0JBQWtCaUI7UUFDdkJVLFFBQVFLLFFBQVE3RixXQUFXOEIsUUFBUTtRQUNuQzRYOzs7O0lBSUosU0FBU0EsY0FBYztNQUNyQmpCLFFBQVFrQixRQUFRQzs7OztBMUQ0NkZ0Qjs7QTJEbDlGQSxDQUFDLFlBQVc7O0VBRVY7OztFQUVBcmUsUUFDR0MsT0FBTyxPQUNQMEIsV0FBVyxtQkFBbUIwZTs7OztFQUlqQyxTQUFTQSxnQkFBZ0IzYSxhQUFhMEMsY0FBYzZCLFNBQVNpRixXQUFXekssWUFBWTs7SUFFbEYsSUFBSTFDLEtBQUs7O0lBRVRBLEdBQUc4RCxhQUFhQTs7SUFFaEJILFlBQVksa0JBQWtCLEVBQUUzRCxJQUFJQSxJQUFJaUUsY0FBY29DLGNBQWNuQyxTQUFTOztJQUU3RSxTQUFTSixhQUFhO01BQ3BCOUQsR0FBR29FLGVBQWU7OztJQUdwQnBFLEdBQUd1ZSxhQUFhLFlBQVc7TUFDekJwUixVQUFVOEY7OztJQUdaalQsR0FBR3dlLGNBQWMsWUFBVztNQUMxQnhlLEdBQUdpSyxTQUFTd0IsUUFBUTdLLEtBQUssVUFBVXFKLFVBQVU7UUFDM0NqSyxHQUFHaUssV0FBV0E7UUFDZC9CLFFBQVFLLFFBQVE3RixXQUFXOEIsUUFBUTtRQUNuQzJJLFVBQVU4Rjs7Ozs7QTNEdTlGbEI7O0E0RHIvRkMsQ0FBQSxZQUFXO0VBQ1Y7OztFQUVBaFYsUUFDR0MsT0FBTyxPQUNQQyxPQUFPOEQ7Ozs7Ozs7OztFQVNWLFNBQVNBLE9BQU9DLGdCQUFnQjlELFFBQVE7SUFDdEM4RCxlQUNHRSxNQUFNLFlBQVk7TUFDakJDLEtBQUs7TUFDTEMsYUFBYWxFLE9BQU80RCxhQUFhO01BQ2pDcEMsWUFBWTtNQUNab0QsTUFBTSxFQUFFQyxvQkFBb0IsTUFBTTRDLGFBQWEsQ0FBQztPQUVqRHpELE1BQU0sb0JBQW9CO01BQ3pCQyxLQUFLO01BQ0xDLGFBQWFsRSxPQUFPNEQsYUFBYTtNQUNqQ3BDLFlBQVk7TUFDWm9ELE1BQU0sRUFBRUMsb0JBQW9COzs7O0E1RHUvRnBDOztBNkRqaEdDLENBQUEsWUFBVztFQUNWOzs7RUFFQWhGLFFBQ0dDLE9BQU8sT0FDUDRILFFBQVEsZ0JBQWdCTzs7OztFQUkzQixTQUFTQSxhQUFhb0osUUFBUXJSLFFBQVEySCxnQkFBZ0I7SUFDcEQsT0FBT0EsZUFBZSxTQUFTOzs7TUFHN0IwWSxVQUFVO1FBQ1JqRCxPQUFPOzs7TUFHVHhWLFNBQVM7Ozs7Ozs7UUFPUHFZLGVBQWU7VUFDYnBZLFFBQVE7VUFDUjVELEtBQUtqRSxPQUFPYSxVQUFVO1VBQ3RCeWYsVUFBVTtVQUNWMVYsTUFBTTs7OztNQUlWOUMsVUFBVTs7Ozs7Ozs7UUFRUndNLFlBQVksU0FBQSxXQUFTOEksT0FBT21ELEtBQUs7VUFDL0JuRCxRQUFRdmQsUUFBUXNILFFBQVFpVyxTQUFTQSxRQUFRLENBQUNBOztVQUUxQyxJQUFJb0QsWUFBWW5QLE9BQU8yRSxJQUFJLEtBQUtvSCxPQUFPOztVQUV2QyxJQUFJbUQsS0FBSztZQUNQLE9BQU9sUCxPQUFPb1AsYUFBYUQsV0FBV3BELE9BQU83VyxXQUFXNlcsTUFBTTdXO2lCQUN6RDs7WUFDTCxPQUFPOEssT0FBT29QLGFBQWFELFdBQVdwRCxPQUFPN1c7Ozs7Ozs7OztRQVNqRG1hLFNBQVMsU0FBQSxVQUFXO1VBQ2xCLE9BQU8sS0FBS3BNLFdBQVc7Ozs7OztBN0R3aEdqQzs7Ozs7QThEL2tHQSxDQUFDLFlBQVc7RUFDVjs7O0VBQ0F6VSxRQUNHQyxPQUFPLE9BQ1BtTyxPQUFPLFNBQVMsWUFBVztJQUMxQixPQUFPLFVBQVMwUyxPQUFPQyxXQUFXO01BQ2hDLElBQUlDLE1BQU05USxXQUFXNFEsV0FBVyxDQUFDRyxTQUFTSCxRQUFRLE9BQU87TUFDekQsSUFBSSxPQUFPQyxjQUFjLGFBQWFBLFlBQVk7TUFDbEQsSUFBSUcsUUFBUSxDQUFDLFNBQVMsTUFBTSxNQUFNLE1BQU0sTUFBTTtVQUM1Q0MsU0FBU3hTLEtBQUtDLE1BQU1ELEtBQUt5UyxJQUFJTixTQUFTblMsS0FBS3lTLElBQUk7O01BRWpELE9BQU8sQ0FBQ04sUUFBUW5TLEtBQUswUyxJQUFJLE1BQU0xUyxLQUFLQyxNQUFNdVMsVUFBVUcsUUFBUVAsYUFBYyxNQUFNRyxNQUFNQzs7S0FHekZ4ZixXQUFXLGlCQUFpQjRmOzs7O0VBSS9CLFNBQVNBLGNBQWM3YixhQUFhOGIsWUFBWXRFLFNBQVM5TixpQkFBaUJuRixTQUFTeEYsWUFBWTtJQUM3RixJQUFJMUMsS0FBSzs7SUFFVEEsR0FBRzBFLFFBQVE7SUFDWDFFLEdBQUcwZixRQUFROzs7OztJQUtYMWYsR0FBRzhELGFBQWMsWUFBVztNQUMxQjZiO01BQ0F0UyxnQkFBZ0JyQyxNQUFNLEVBQUV1QyxZQUFZcE0sYUFBYUUsUUFBUSxjQUFjVCxLQUFLLFVBQVM0RyxVQUFVO1FBQzdGeEgsR0FBRzRmLFdBQVdwWSxTQUFTLEdBQUdxWTtRQUMxQjdmLEdBQUc4ZixPQUFPdFksU0FBUyxHQUFHdVk7UUFDdEIsSUFBSS9mLEdBQUc0ZixZQUFZNWYsR0FBRzhmLE1BQU07VUFDMUI5ZixHQUFHb0UsZUFBZTtZQUNoQndiLFVBQVU1ZixHQUFHNGY7WUFDYkUsTUFBTTlmLEdBQUc4ZjtZQUNURSxNQUFNOztVQUVSaGdCLEdBQUcwZixNQUFNN2EsS0FBSzdFLEdBQUdvRSxhQUFhNGI7VUFDOUJoZ0IsR0FBR3FKO2VBQ0U7VUFDTDhSLFFBQVE4RSxlQUFlQzs7Ozs7SUFLN0JsZ0IsR0FBRytELGVBQWUsVUFBU21CLHFCQUFxQjtNQUM5QyxPQUFPakgsUUFBUWtILE9BQU9ELHFCQUFxQmxGLEdBQUdvRTs7O0lBR2hEcEUsR0FBRzZLLGNBQWMsWUFBVztNQUMxQnNWO01BQ0FoRixRQUFROEUsZUFBZUM7OztJQUd6QixTQUFTQyxnQkFBZ0I7TUFDdkIsSUFBSW5nQixHQUFHMkssVUFBVWhHLFNBQVMsR0FBRztRQUMzQjNFLEdBQUcySyxVQUFVbEcsS0FBSyxVQUFTMmIsR0FBR0MsR0FBRztVQUMvQixPQUFPRCxFQUFFbmIsT0FBT29iLEVBQUVwYixPQUFPLENBQUMsSUFBSW1iLEVBQUVuYixPQUFPb2IsRUFBRXBiLE9BQU8sSUFBSTs7Ozs7SUFLMURqRixHQUFHc2dCLHNCQUFzQixVQUFTclcsVUFBVTtNQUMxQzBWO01BQ0EsSUFBSTFWLFVBQVU7UUFDWmpLLEdBQUdvRSxhQUFhNGIsT0FBTy9WLFNBQVMrVjtRQUNoQ2hnQixHQUFHMGYsTUFBTTdhLEtBQUs3RSxHQUFHb0UsYUFBYTRiO1FBQzlCaGdCLEdBQUcwRTthQUNFO1FBQ0wxRSxHQUFHb0UsYUFBYTRiLE9BQU9oZ0IsR0FBRzBmLE1BQU0xZixHQUFHMEUsUUFBUTtRQUMzQzFFLEdBQUcwZixNQUFNeE8sT0FBT2xSLEdBQUcwRSxPQUFPO1FBQzFCMUUsR0FBRzBFOztNQUVMMUUsR0FBR3FKOzs7SUFHTHJKLEdBQUcrSyxnQkFBZ0IsVUFBVXZELFVBQVU7TUFDckMsSUFBSUEsU0FBU3hFLEtBQUt5RSxVQUFVLGFBQWE7UUFDdkNTLFFBQVFnRSxLQUFLeEosV0FBVzhCLFFBQVE7UUFDaEMyVyxRQUFROEUsZUFBZUM7Ozs7Ozs7SUFPM0IsU0FBU1AscUJBQXFCO01BQzVCeEUsUUFBUThFLGlCQUFpQjlFLFFBQVFvRixXQUFXO1FBQzFDQyxNQUFNO1FBQ05DLGlCQUFpQjtRQUNqQkMsYUFDRSwyQkFDQSxpQ0FDQSxpQ0FDQSxpQ0FDQSxpQ0FDQSxpQ0FDQSxnREFDQTs7Ozs7SUFLTi9jLFlBQVksa0JBQWtCLEVBQUUzRCxJQUFJQSxJQUFJaUUsY0FBY3diLFlBQVl2YixTQUFTLEVBQUU2RixnQkFBZ0IsTUFBTUYsY0FBYzs7O0E5RDZrR3JIOztBK0R4ckdDLENBQUEsWUFBVztFQUNWOzs7RUFFQTVMLFFBQ0dDLE9BQU8sT0FDUEMsT0FBTzhEOzs7Ozs7Ozs7RUFTVixTQUFTQSxPQUFPQyxnQkFBZ0I5RCxRQUFRO0lBQ3RDOEQsZUFDR0UsTUFBTSxXQUFXO01BQ2hCQyxLQUFLO01BQ0xDLGFBQWFsRSxPQUFPNEQsYUFBYTtNQUNqQ3BDLFlBQVk7TUFDWm9ELE1BQU07Ozs7QS9EMnJHZDs7QWdFL3NHQyxDQUFBLFlBQVc7RUFDVjs7O0VBRUEvRSxRQUNHQyxPQUFPLE9BQ1A0SCxRQUFRLGNBQWMyWjs7O0VBR3pCLFNBQVNBLFdBQVcxWixnQkFBZ0I7SUFDbEMsSUFBSW5CLFFBQVFtQixlQUFlLE9BQU87TUFDaENDLFNBQVM7TUFDVEUsVUFBVTs7O0lBR1osT0FBT3RCOzs7QWhFa3RHWDs7QWlFaHVHQyxDQUFBLFlBQVc7RUFDVjs7OztFQUdBM0csUUFDR0MsT0FBTyxPQUNQeWlCLFVBQVUsT0FBTztJQUNoQkMsU0FBUztJQUNUdGUsYUFBYSxDQUFDLFVBQVUsVUFBU2xFLFFBQVE7TUFDdkMsT0FBT0EsT0FBTzRELGFBQWE7O0lBRTdCNmUsWUFBWTtNQUNWQyxnQkFBZ0I7TUFDaEJDLGVBQWU7O0lBRWpCQyxVQUFVO01BQ1JDLFVBQVU7TUFDVkMsY0FBYztNQUNkQyxnQkFBZ0I7O0lBRWxCdmhCLFlBQVksQ0FBQyxlQUFlLFVBQVN3aEIsYUFBYTtNQUNoRCxJQUFJQyxPQUFPOztNQUVYQSxLQUFLUixhQUFhTzs7TUFFbEJDLEtBQUtDLFVBQVUsWUFBVztRQUN4QixJQUFJcmpCLFFBQVEyUyxZQUFZeVEsS0FBS0YsaUJBQWlCRSxLQUFLRixpQkFBaUI7Ozs7O0FqRXN1RzlFOztBa0Vod0dDLENBQUEsWUFBVztFQUNWOzs7O0VBR0FsakIsUUFDR0MsT0FBTyxPQUNQeWlCLFVBQVUsZUFBZTtJQUN4QkMsU0FBUztJQUNUQyxZQUFZO0lBQ1p2ZSxhQUFhLENBQUMsVUFBVSxVQUFTbEUsUUFBUTtNQUN2QyxPQUFPQSxPQUFPNEQsYUFBYTs7SUFFN0JnZixVQUFVO01BQ1JPLGFBQWE7O0lBRWYzaEIsWUFBWSxDQUFDLFlBQVc7TUFDdEIsSUFBSXloQixPQUFPOztNQUVYQSxLQUFLQyxVQUFVLFlBQVc7O1FBRXhCRCxLQUFLRSxjQUFjdGpCLFFBQVFzTSxVQUFVOFcsS0FBS0UsZUFBZUYsS0FBS0UsY0FBYzs7Ozs7QWxFc3dHdEY7O0FtRTF4R0MsQ0FBQSxZQUFXO0VBQ1Y7Ozs7RUFHQXRqQixRQUNHQyxPQUFPLE9BQ1B5aUIsVUFBVSxpQkFBaUI7SUFDMUJyZSxhQUFhLENBQUMsVUFBVSxVQUFTbEUsUUFBUTtNQUN2QyxPQUFPQSxPQUFPNEQsYUFBYTs7SUFFN0I0ZSxTQUFTO0lBQ1RJLFVBQVU7TUFDUnBWLE9BQU87TUFDUEMsYUFBYTs7OztBbkUreEdyQjs7QW9FNXlHQSxDQUFDLFlBQVc7O0VBRVY7OztFQUVBNU4sUUFDR0MsT0FBTyxPQUNQbU8sT0FBTyxvQkFBb0JtVjs7OztFQUk5QixTQUFTQSxpQkFBaUI5ZSxZQUFZO0lBQ3BDLE9BQU8sVUFBUzBDLGFBQWFvRCxRQUFRO01BQ25DLElBQUlwRCxZQUFZSCxTQUFTLFdBQVc7UUFDbEMsSUFBSXVELFdBQVcsVUFBVTtVQUN2QixPQUFPOUYsV0FBVzhCLFFBQVE7ZUFDckI7VUFDTCxPQUFPOUIsV0FBVzhCLFFBQVE7O2FBRXZCO1FBQ0wsT0FBTzlCLFdBQVc4QixRQUFRLGtCQUFrQlksWUFBWUg7Ozs7O0FwRWl6R2hFOztBcUVwMEdBLENBQUMsWUFBVzs7RUFFVjs7O0VBRUFoSCxRQUNHQyxPQUFPLE9BQ1BtTyxPQUFPLGNBQWNvVjs7OztFQUl4QixTQUFTQSxXQUFXL2UsWUFBWTtJQUM5QixPQUFPLFVBQVNnZixTQUFTO01BQ3ZCQSxVQUFVQSxRQUFRZCxRQUFRLFNBQVM7TUFDbkMsSUFBSWhjLFFBQVFsQyxXQUFXOEIsUUFBUSxZQUFZa2QsUUFBUTVjOztNQUVuRCxPQUFRRixRQUFTQSxRQUFROGM7Ozs7QXJFdzBHL0I7O0FzRXYxR0EsQ0FBQyxZQUFXOztFQUVWOzs7RUFFQXpqQixRQUNHQyxPQUFPLE9BQ1BtTyxPQUFPLGFBQWFzVjs7OztFQUl2QixTQUFTQSxVQUFVbFMsUUFBUTdMLGNBQWM7SUFDdkMsT0FBTyxVQUFTZ2UsUUFBUTtNQUN0QixJQUFJM2MsT0FBT3dLLE9BQU8ySixLQUFLeFYsYUFBYW9CLGFBQWEsRUFBRVYsSUFBSXNkOztNQUV2RCxPQUFRM2MsT0FBUUEsS0FBS1YsUUFBUVU7Ozs7QXRFMjFHbkM7O0F1RXoyR0EsQ0FBQyxZQUFXOztFQUVWOzs7RUFFQWhILFFBQ0dDLE9BQU8sT0FDUG1PLE9BQU8sY0FBY3dWOzs7O0VBSXhCLFNBQVNBLFdBQVcvUCxTQUFTckMsUUFBUTtJQUNuQyxPQUFPLFVBQVNjLE9BQU9RLEtBQUs7TUFDMUIsSUFBSTlTLFFBQVE2akIsT0FBT3ZSLFVBQVVkLE9BQU9zUyxTQUFTaFIsS0FBSyxVQUFXdEIsT0FBT3NTLFNBQVNoUixLQUFLLFFBQVE7UUFDeEYsT0FBT2UsUUFBUSxjQUFjdkI7OztNQUcvQixJQUFJLE9BQU9BLFVBQVUsV0FBVztRQUM5QixPQUFPdUIsUUFBUSxhQUFjdkIsUUFBUyxlQUFlOzs7O01BSXZELElBQUl5UixPQUFPelIsV0FBV0EsU0FBU0EsUUFBUSxNQUFNLEdBQUc7UUFDOUMsT0FBT3VCLFFBQVEsUUFBUXZCOzs7TUFHekIsT0FBT0E7Ozs7QXZFNjJHYjs7O0F3RXI0R0MsQ0FBQSxZQUFXO0VBQ1Y7O0VBRUF0UyxRQUNHQyxPQUFPLE9BQ1BxRCxTQUFTLHlCQUF5QjtJQUNqQ3VHLE9BQU87SUFDUEMsVUFBVTtJQUNWMEcsTUFBTTtJQUNOek4sT0FBTztJQUNQd2EsT0FBTztJQUNQOWIsTUFBTTtJQUNOdWlCLGFBQWE7SUFDYkMsV0FBVztJQUNYOUQsVUFBVTtJQUNWblEsTUFBTTtNQUNKcEMsYUFBYTtNQUNiMEosTUFBTTtNQUNOWCxVQUFVO01BQ1Z1TixjQUFjO01BQ2RqaEIsU0FBUztNQUNUc0gsUUFBUTtNQUNSb0QsT0FBTztNQUNQM0csTUFBTTtNQUNOMlEsV0FBVztNQUNYMUgsZ0JBQWdCOztJQUVsQjBILFdBQVc7TUFDVGhLLE9BQU87TUFDUEMsYUFBYTtNQUNidVcsWUFBWTtNQUNadEksVUFBVTtNQUNWNUwsZ0JBQWdCO01BQ2hCeUwsaUJBQWlCOztJQUVuQnpZLFNBQVM7TUFDUG1oQixNQUFNO01BQ05DLG9CQUFvQjtNQUNwQkMsaUJBQWlCO01BQ2pCQyxnQkFBZ0I7O0lBRWxCOUYsU0FBUztNQUNQOVEsT0FBTztNQUNQQyxhQUFhO01BQ2I0VyxjQUFjO01BQ2Q3TSxXQUFXO01BQ1g3SCxPQUFPOzs7SUFHVDBULFlBQVk7OztBeEV5NEdsQjs7O0F5RTE3R0MsQ0FBQSxZQUFXO0VBQ1Y7O0VBRUF4akIsUUFDR0MsT0FBTyxPQUNQcUQsU0FBUyxxQkFBcUI7SUFDN0JtaEIsY0FBYztJQUNkQyxvQkFBb0I7SUFDcEJDLG1CQUFtQjtJQUNuQkMsT0FBTztNQUNMQyxTQUFTO01BQ1RDLGVBQWU7TUFDZkMsY0FBYztNQUNkQyxTQUFTOztJQUVYM2MsT0FBTztNQUNMNGMsZUFBZTtRQUNiclgsYUFBYTs7Ozs7QXpFZzhHdkI7OztBMEVqOUdDLENBQUEsWUFBVztFQUNWOztFQUVBNU4sUUFDR0MsT0FBTyxPQUNQcUQsU0FBUyxxQkFBcUI7SUFDN0I0aEIsU0FBUztJQUNUQyxZQUFZO0lBQ1pDLEtBQUs7SUFDTEMsSUFBSTtJQUNKM0UsS0FBSzs7O0ExRXE5R1g7OztBMkUvOUdDLENBQUEsWUFBVztFQUNWOztFQUVBMWdCLFFBQ0dDLE9BQU8sT0FDUHFELFNBQVMsdUJBQXVCO0lBQy9CZ2lCLGVBQWU7SUFDZkMsVUFBVTtJQUNWQyxlQUFlO0lBQ2ZDLGFBQWE7SUFDYkMsYUFBYTtJQUNiQyxrQkFBa0I7SUFDbEJDLGdCQUFnQjtJQUNoQkMsV0FBVztJQUNYQyxlQUFlO0lBQ2ZDLGFBQWE7SUFDYkMsdUJBQXVCO0lBQ3ZCQyxjQUFjO0lBQ2RDLHlCQUF5QjtJQUN6QkMsb0JBQW9CO0lBQ3BCQyxrQkFBa0I7SUFDbEJDLGVBQWU7SUFDZkMsY0FBYztJQUNkQyxzQkFBc0I7SUFDdEJDLG1CQUFtQjtJQUNuQkMscUJBQXFCO0lBQ3JCQyxtQkFBbUI7SUFDbkJDLFVBQVU7TUFDUkMsZUFBZTs7SUFFakJDLFFBQVE7TUFDTkMsVUFBVTs7SUFFWnplLE9BQU87TUFDTDBlLGdCQUFnQjtNQUNoQkMsb0JBQW9CO01BQ3BCQyxjQUFjLHlEQUNaO01BQ0ZDLGNBQWM7O0lBRWhCQyxXQUFXO01BQ1RDLFNBQVM7TUFDVHhaLGFBQWE7O0lBRWZrTixNQUFNO01BQ0p1TSxZQUFZO01BQ1pDLGlCQUFpQjtNQUNqQkMsZUFBZTtNQUNmQyx3QkFBd0I7O0lBRTFCeGUsTUFBTTtNQUNKeWUscUJBQXFCO01BQ3JCQyxZQUFZO01BQ1pDLFNBQVM7UUFDUEMsYUFBYTs7O0lBR2pCQyxjQUFjO01BQ1pDLFVBQVU7Ozs7QTNFbStHbEI7OztBNEU3aEhDLENBQUEsWUFBVztFQUNWOztFQUVBOW5CLFFBQ0dDLE9BQU8sT0FDUHFELFNBQVMscUJBQXFCO0lBQzdCMEYsTUFBTTtJQUNOZ0gsTUFBTTtJQUNOL00sU0FBUzs7O0E1RWlpSGY7OztBNkV6aUhDLENBQUEsWUFBVztFQUNWOztFQUVBakQsUUFDR0MsT0FBTyxPQUNQcUQsU0FBUyxvQkFBb0I7SUFDNUJ5a0IsYUFBYTtNQUNYL2UsTUFBTTtNQUNOLGdCQUFnQjtNQUNoQm1lLFdBQVc7TUFDWHZDLE9BQU87TUFDUDlKLE1BQU07TUFDTmtOLFVBQVU7TUFDVixpQkFBaUI7TUFDakIsa0JBQWtCO01BQ2xCbFksT0FBTztNQUNQaVAsWUFBWTtNQUNaa0osUUFBUTtNQUNSQyxLQUFLO01BQ0xDLFVBQVU7O0lBRVpDLFFBQVE7TUFDTmpCLFdBQVc7TUFDWGtCLFVBQVU7TUFDVkMsVUFBVTtNQUNWQyxVQUFVO01BQ1ZDLFdBQVc7TUFDWEMsVUFBVTtNQUNWeEQsZUFBZTtNQUNmL0UsUUFBUTtNQUNScFEsT0FBTztNQUNQaVAsWUFBWTtNQUNaa0osUUFBUTtNQUNSQyxLQUFLO01BQ0xDLFVBQVU7O0lBRVpwZ0IsU0FBUztNQUNQMlMsTUFBTTtNQUNObFAsTUFBTTtNQUNOd0csT0FBTztNQUNQMFcsVUFBVTtNQUNWelcsU0FBUztNQUNUN0QsUUFBUTtNQUNSaEQsUUFBUTtNQUNSdWQsTUFBTTtNQUNOcGQsTUFBTTtNQUNObUYsUUFBUTtNQUNSd1AsUUFBUTtNQUNSelUsUUFBUTtNQUNSbWQsUUFBUTtNQUNSQyxLQUFLO01BQ0xDLElBQUk7TUFDSkMsV0FBVztNQUNYQyxRQUFRO01BQ1JDLGNBQWM7TUFDZEMsYUFBYTtNQUNiQyxXQUFXO01BQ1hDLGdCQUFnQjtNQUNoQmpZLFVBQVU7TUFDVmtZLE9BQU87O0lBRVRuVCxRQUFRO01BQ056VSxNQUFNO01BQ042bkIsUUFBUTtNQUNSdmhCLFNBQVM7TUFDVDZjLE9BQU87UUFDTDJFLFdBQVc7UUFDWDNOLFNBQVM7UUFDVDVQLFVBQVU7UUFDVndkLGNBQWM7UUFDZHhpQixNQUFNO1VBQ0o2ZCxTQUFTO1VBQ1Q0RSxTQUFTO1VBQ1R6RSxTQUFTOzs7TUFHYjNjLE9BQU87UUFDTDRjLGVBQWU7UUFDZnlFLGlCQUFpQjs7TUFFbkI1TyxNQUFNO1FBQ0o2TyxJQUFJO1FBQ0pDLFNBQVM7UUFDVGhmLFNBQVM7O01BRVhpZCxjQUFjO1FBQ1p0VixTQUFTO1FBQ1RzWCxTQUFTO1FBQ1RsakIsT0FBTztRQUNQeUwsV0FBVztRQUNYQyxVQUFVO1FBQ1ZyRyxVQUFVO1FBQ1ZzRyxPQUFPO1FBQ1BHLFdBQVc7VUFDVHFYLFFBQVE7VUFDUkMsVUFBVTtVQUNWQyxVQUFVO1VBQ1ZDLFdBQVc7VUFDWEMsWUFBWTtVQUNaQyxZQUFZO1VBQ1pDLG9CQUFvQjtVQUNwQkMsVUFBVTtVQUNWQyxrQkFBa0I7OztNQUd0QnJuQixTQUFTO1FBQ1B1TixNQUFNO1FBQ04rWixXQUFXOztNQUVidmEsTUFBTTtRQUNKc0gsTUFBTTs7TUFFUnRPLE1BQU07UUFDSndoQixTQUFTO1FBQ1Q1UCxhQUFhOzs7SUFHakJpTSxRQUFRO01BQ040RCxNQUFNO1FBQ0p6QyxVQUFVO1FBQ1ZiLFdBQVc7UUFDWHBJLFlBQVk7UUFDWmpQLE9BQU87UUFDUG1ZLFFBQVE7UUFDUkMsS0FBSztRQUNMQyxVQUFVOzs7SUFHZHVDLFVBQVU7TUFDUjlGLE9BQU87UUFDTDdlLFlBQVk7O01BRWRpRCxNQUFNO1FBQ0oyaEIsUUFBUTtRQUNSQyxVQUFVOztNQUVaNWEsTUFBTTtRQUNKNmEsVUFBVTs7Ozs7QTdFK2lIcEI7O0E4RXpySEEsQ0FBQyxZQUFXOztFQUVWOzs7RUFFQTdxQixRQUNHQyxPQUFPLE9BQ1AwQixXQUFXLHNCQUFzQm1wQjs7OztFQUlwQyxTQUFTQSxtQkFBbUJwbEIsYUFBYXFRLGNBQWMzTyxRQUFROztJQUU3RCxJQUFJckYsS0FBSzs7SUFFVEEsR0FBR29JLGNBQWNBOztJQUVqQnBJLEdBQUc4RCxhQUFhLFlBQVc7TUFDekI5RCxHQUFHaU8sT0FBTzVJLE9BQU80STtNQUNqQmpPLEdBQUdpTyxLQUFLQyxpQkFBaUJsTyxHQUFHaU8sS0FBS0MsZUFBZWdMLGFBQWE7OztJQUcvRCxTQUFTOVEsY0FBYztNQUNyQnBJLEdBQUdzRjtNQUNIMGpCLFFBQVEzSixJQUFJOzs7O0lBSWQxYixZQUFZLGtCQUFrQixFQUFFM0QsSUFBSUEsSUFBSWlFLGNBQWMrUCxjQUFjOVAsU0FBUzs7O0E5RTRySGpGOztBK0V2dEhBLENBQUMsWUFBVzs7RUFFVjs7O0VBRUFqRyxRQUNHQyxPQUFPLE9BQ1AwQixXQUFXLHlCQUF5QnFwQjs7OztFQUl2QyxTQUFTQSxzQkFBc0J0bEIsYUFBYTBDLGNBQWN4QztFQUN4RHlWLGlCQUFpQkQsUUFBUTs7SUFFekIsSUFBSXJaLEtBQUs7O0lBRVRBLEdBQUc4RCxhQUFhQTtJQUNoQjlELEdBQUcrRCxlQUFlQTtJQUNsQi9ELEdBQUdzRixRQUFRQTs7SUFFWCxJQUFJckgsUUFBUXNNLFVBQVUrTyxrQkFBa0I7TUFDdEN0WixHQUFHa3BCLGVBQWU1UCxnQkFBZ0JDOzs7O0lBSXBDNVYsWUFBWSxrQkFBa0I7TUFDNUIzRCxJQUFJQTtNQUNKaUUsY0FBY29DO01BQ2R3RCxjQUFjd1A7TUFDZG5WLFNBQVM7UUFDUDRGLFNBQVM7Ozs7SUFJYixTQUFTaEcsYUFBYTtNQUNwQjlELEdBQUdvRSxlQUFlOzs7SUFHcEIsU0FBU0wsZUFBZTtNQUN0QixPQUFPOUYsUUFBUWtILE9BQU9uRixHQUFHa0YscUJBQXFCbEYsR0FBR29FOzs7SUFHbkQsU0FBU2tCLFFBQVE7TUFDZnpCLFNBQVN5Qjs7O0tBMUNmIiwiZmlsZSI6ImFwcGxpY2F0aW9uLmpzIiwic291cmNlc0NvbnRlbnQiOlsiJ3VzZSBzdHJpY3QnO1xuXG4vKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCovXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcsIFsnbmdBbmltYXRlJywgJ25nQXJpYScsICd1aS5yb3V0ZXInLCAnbmdQcm9kZWInLCAndWkudXRpbHMubWFza3MnLCAndGV4dC1tYXNrJywgJ25nTWF0ZXJpYWwnLCAnbW9kZWxGYWN0b3J5JywgJ21kLmRhdGEudGFibGUnLCAnbmdNYXRlcmlhbERhdGVQaWNrZXInLCAncGFzY2FscHJlY2h0LnRyYW5zbGF0ZScsICdhbmd1bGFyRmlsZVVwbG9hZCcsICduZ01lc3NhZ2VzJywgJ2pxd2lkZ2V0cycsICd1aS5tYXNrJywgJ25nUm91dGUnLCAnbmdTYW5pdGl6ZSddKTtcbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29uZmlnKGNvbmZpZyk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBjb25maWcoR2xvYmFsLCAkbWRUaGVtaW5nUHJvdmlkZXIsICRtb2RlbEZhY3RvcnlQcm92aWRlciwgLy8gTk9TT05BUlxuICAkdHJhbnNsYXRlUHJvdmlkZXIsIG1vbWVudCwgJG1kQXJpYVByb3ZpZGVyLCAkbWREYXRlTG9jYWxlUHJvdmlkZXIpIHtcblxuICAgICR0cmFuc2xhdGVQcm92aWRlci51c2VMb2FkZXIoJ2xhbmd1YWdlTG9hZGVyJykudXNlU2FuaXRpemVWYWx1ZVN0cmF0ZWd5KCdlc2NhcGUnKTtcblxuICAgICR0cmFuc2xhdGVQcm92aWRlci51c2VQb3N0Q29tcGlsaW5nKHRydWUpO1xuXG4gICAgbW9tZW50LmxvY2FsZSgncHQtQlInKTtcblxuICAgIC8vb3Mgc2VydmnDp29zIHJlZmVyZW50ZSBhb3MgbW9kZWxzIHZhaSB1dGlsaXphciBjb21vIGJhc2UgbmFzIHVybHNcbiAgICAkbW9kZWxGYWN0b3J5UHJvdmlkZXIuZGVmYXVsdE9wdGlvbnMucHJlZml4ID0gR2xvYmFsLmFwaVBhdGg7XG5cbiAgICAvLyBDb25maWd1cmF0aW9uIHRoZW1lXG4gICAgJG1kVGhlbWluZ1Byb3ZpZGVyLnRoZW1lKCdkZWZhdWx0JykucHJpbWFyeVBhbGV0dGUoJ2dyZXknLCB7XG4gICAgICBkZWZhdWx0OiAnODAwJ1xuICAgIH0pLmFjY2VudFBhbGV0dGUoJ2FtYmVyJykud2FyblBhbGV0dGUoJ2RlZXAtb3JhbmdlJyk7XG5cbiAgICAvLyBFbmFibGUgYnJvd3NlciBjb2xvclxuICAgICRtZFRoZW1pbmdQcm92aWRlci5lbmFibGVCcm93c2VyQ29sb3IoKTtcblxuICAgICRtZEFyaWFQcm92aWRlci5kaXNhYmxlV2FybmluZ3MoKTtcblxuICAgICRtZERhdGVMb2NhbGVQcm92aWRlci5mb3JtYXREYXRlID0gZnVuY3Rpb24gKGRhdGUpIHtcbiAgICAgIHJldHVybiBkYXRlID8gbW9tZW50KGRhdGUpLmZvcm1hdCgnREQvTU0vWVlZWScpIDogJyc7XG4gICAgfTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbnRyb2xsZXIoJ0FwcENvbnRyb2xsZXInLCBBcHBDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8qKlxuICAgKiBDb250cm9sYWRvciByZXNwb25zw6F2ZWwgcG9yIGZ1bmNpb25hbGlkYWRlcyBxdWUgc8OjbyBhY2lvbmFkYXMgZW0gcXVhbHF1ZXIgdGVsYSBkbyBzaXN0ZW1hXG4gICAqXG4gICAqL1xuICBmdW5jdGlvbiBBcHBDb250cm9sbGVyKCRzdGF0ZSwgQXV0aCwgR2xvYmFsKSB7XG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIC8vYW5vIGF0dWFsIHBhcmEgc2VyIGV4aWJpZG8gbm8gcm9kYXDDqSBkbyBzaXN0ZW1hXG4gICAgdm0uYW5vQXR1YWwgPSBudWxsO1xuICAgIHZtLmFjdGl2ZVByb2plY3QgPSBudWxsO1xuXG4gICAgdm0ubG9nb3V0ID0gbG9nb3V0O1xuICAgIHZtLmdldEltYWdlUGVyZmlsID0gZ2V0SW1hZ2VQZXJmaWw7XG4gICAgdm0uZ2V0TG9nb01lbnUgPSBnZXRMb2dvTWVudTtcbiAgICB2bS5zZXRBY3RpdmVQcm9qZWN0ID0gc2V0QWN0aXZlUHJvamVjdDtcbiAgICB2bS5nZXRBY3RpdmVQcm9qZWN0ID0gZ2V0QWN0aXZlUHJvamVjdDtcbiAgICB2bS5yZW1vdmVBY3RpdmVQcm9qZWN0ID0gcmVtb3ZlQWN0aXZlUHJvamVjdDtcblxuICAgIGFjdGl2YXRlKCk7XG5cbiAgICBmdW5jdGlvbiBhY3RpdmF0ZSgpIHtcbiAgICAgIHZhciBkYXRlID0gbmV3IERhdGUoKTtcblxuICAgICAgdm0uYW5vQXR1YWwgPSBkYXRlLmdldEZ1bGxZZWFyKCk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gbG9nb3V0KCkge1xuICAgICAgQXV0aC5sb2dvdXQoKS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgJHN0YXRlLmdvKEdsb2JhbC5sb2dpblN0YXRlKTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGdldEltYWdlUGVyZmlsKCkge1xuICAgICAgcmV0dXJuIEF1dGguY3VycmVudFVzZXIgJiYgQXV0aC5jdXJyZW50VXNlci5pbWFnZSA/IEF1dGguY3VycmVudFVzZXIuaW1hZ2UgOiBHbG9iYWwuaW1hZ2VQYXRoICsgJy9ub19hdmF0YXIuZ2lmJztcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBnZXRMb2dvTWVudSgpIHtcbiAgICAgIHJldHVybiBHbG9iYWwuaW1hZ2VQYXRoICsgJy9sb2dvLXZlcnRpY2FsLnBuZyc7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gc2V0QWN0aXZlUHJvamVjdChwcm9qZWN0KSB7XG4gICAgICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbSgncHJvamVjdCcsIHByb2plY3QpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGdldEFjdGl2ZVByb2plY3QoKSB7XG4gICAgICByZXR1cm4gbG9jYWxTdG9yYWdlLmdldEl0ZW0oJ3Byb2plY3QnKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiByZW1vdmVBY3RpdmVQcm9qZWN0KCkge1xuICAgICAgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oJ3Byb2plY3QnKTtcbiAgICB9XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbi8qZXNsaW50IGFuZ3VsYXIvZmlsZS1uYW1lOiAwLCBuby11bmRlZjogMCovXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgLyoqXG4gICAqIFRyYW5zZm9ybWEgYmlibGlvdGVjYXMgZXh0ZXJuYXMgZW0gc2VydmnDp29zIGRvIGFuZ3VsYXIgcGFyYSBzZXIgcG9zc8OtdmVsIHV0aWxpemFyXG4gICAqIGF0cmF2w6lzIGRhIGluamXDp8OjbyBkZSBkZXBlbmTDqm5jaWFcbiAgICovXG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbnN0YW50KCdsb2Rhc2gnLCBfKS5jb25zdGFudCgnbW9tZW50JywgbW9tZW50KTtcbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29uc3RhbnQoJ0dsb2JhbCcsIHtcbiAgICBhcHBOYW1lOiAnRnJlZWxhZ2lsZScsXG4gICAgaG9tZVN0YXRlOiAnYXBwLnByb2plY3RzJyxcbiAgICBsb2dpblVybDogJ2FwcC9sb2dpbicsXG4gICAgcmVzZXRQYXNzd29yZFVybDogJ2FwcC9wYXNzd29yZC9yZXNldCcsXG4gICAgbG9naW5TdGF0ZTogJ2FwcC5sb2dpbicsXG4gICAgcmVzZXRQYXNzd29yZFN0YXRlOiAnYXBwLnBhc3N3b3JkLXJlc2V0JyxcbiAgICBub3RBdXRob3JpemVkU3RhdGU6ICdhcHAubm90LWF1dGhvcml6ZWQnLFxuICAgIHRva2VuS2V5OiAnc2VydmVyX3Rva2VuJyxcbiAgICBjbGllbnRQYXRoOiAnY2xpZW50L2FwcCcsXG4gICAgYXBpUGF0aDogJ2FwaS92MScsXG4gICAgaW1hZ2VQYXRoOiAnY2xpZW50L2ltYWdlcydcbiAgfSk7XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCAkdXJsUm91dGVyUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdhcHAnLCB7XG4gICAgICB1cmw6ICcvYXBwJyxcbiAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvbGF5b3V0L2FwcC5odG1sJyxcbiAgICAgIGFic3RyYWN0OiB0cnVlLFxuICAgICAgcmVzb2x2ZTogeyAvL2Vuc3VyZSBsYW5ncyBpcyByZWFkeSBiZWZvcmUgcmVuZGVyIHZpZXdcbiAgICAgICAgdHJhbnNsYXRlUmVhZHk6IFsnJHRyYW5zbGF0ZScsICckcScsIGZ1bmN0aW9uICgkdHJhbnNsYXRlLCAkcSkge1xuICAgICAgICAgIHZhciBkZWZlcnJlZCA9ICRxLmRlZmVyKCk7XG5cbiAgICAgICAgICAkdHJhbnNsYXRlLnVzZSgncHQtQlInKS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIGRlZmVycmVkLnJlc29sdmUoKTtcbiAgICAgICAgICB9KTtcblxuICAgICAgICAgIHJldHVybiBkZWZlcnJlZC5wcm9taXNlO1xuICAgICAgICB9XVxuICAgICAgfVxuICAgIH0pLnN0YXRlKEdsb2JhbC5ub3RBdXRob3JpemVkU3RhdGUsIHtcbiAgICAgIHVybDogJy9hY2Vzc28tbmVnYWRvJyxcbiAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvbGF5b3V0L25vdC1hdXRob3JpemVkLmh0bWwnLFxuICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IGZhbHNlIH1cbiAgICB9KTtcblxuICAgICR1cmxSb3V0ZXJQcm92aWRlci53aGVuKCcvcGFzc3dvcmQvcmVzZXQnLCBHbG9iYWwucmVzZXRQYXNzd29yZFVybCk7XG4gICAgJHVybFJvdXRlclByb3ZpZGVyLndoZW4oJy9hcHAnLCBHbG9iYWwubG9naW5VcmwpO1xuICAgICR1cmxSb3V0ZXJQcm92aWRlci5vdGhlcndpc2UoR2xvYmFsLmxvZ2luVXJsKTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5ydW4ocnVuKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIHJ1bigkcm9vdFNjb3BlLCAkc3RhdGUsICRzdGF0ZVBhcmFtcywgQXV0aCwgR2xvYmFsKSB7XG4gICAgLy8gTk9TT05BUlxuICAgIC8vc2V0YWRvIG5vIHJvb3RTY29wZSBwYXJhIHBvZGVyIHNlciBhY2Vzc2FkbyBuYXMgdmlld3Mgc2VtIHByZWZpeG8gZGUgY29udHJvbGxlclxuICAgICRyb290U2NvcGUuJHN0YXRlID0gJHN0YXRlO1xuICAgICRyb290U2NvcGUuJHN0YXRlUGFyYW1zID0gJHN0YXRlUGFyYW1zO1xuICAgICRyb290U2NvcGUuYXV0aCA9IEF1dGg7XG4gICAgJHJvb3RTY29wZS5nbG9iYWwgPSBHbG9iYWw7XG5cbiAgICAvL25vIGluaWNpbyBjYXJyZWdhIG8gdXN1w6FyaW8gZG8gbG9jYWxzdG9yYWdlIGNhc28gbyB1c3XDoXJpbyBlc3RhamEgYWJyaW5kbyBvIG5hdmVnYWRvclxuICAgIC8vcGFyYSB2b2x0YXIgYXV0ZW50aWNhZG9cbiAgICBBdXRoLnJldHJpZXZlVXNlckZyb21Mb2NhbFN0b3JhZ2UoKTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbnRyb2xsZXIoJ0F1ZGl0Q29udHJvbGxlcicsIEF1ZGl0Q29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBBdWRpdENvbnRyb2xsZXIoJGNvbnRyb2xsZXIsIEF1ZGl0U2VydmljZSwgUHJEaWFsb2csIEdsb2JhbCwgJHRyYW5zbGF0ZSkge1xuICAgIC8vIE5PU09OQVJcbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0ub25BY3RpdmF0ZSA9IG9uQWN0aXZhdGU7XG4gICAgdm0uYXBwbHlGaWx0ZXJzID0gYXBwbHlGaWx0ZXJzO1xuICAgIHZtLnZpZXdEZXRhaWwgPSB2aWV3RGV0YWlsO1xuXG4gICAgJGNvbnRyb2xsZXIoJ0NSVURDb250cm9sbGVyJywgeyB2bTogdm0sIG1vZGVsU2VydmljZTogQXVkaXRTZXJ2aWNlLCBvcHRpb25zOiB7fSB9KTtcblxuICAgIGZ1bmN0aW9uIG9uQWN0aXZhdGUoKSB7XG4gICAgICB2bS5tb2RlbHMgPSBbXTtcbiAgICAgIHZtLnF1ZXJ5RmlsdGVycyA9IHt9O1xuXG4gICAgICAvL1BlZ2EgdG9kb3Mgb3MgbW9kZWxzIGRvIHNlcnZlciBlIG1vbnRhIHVtYSBsaXN0YSBwcm8gQ29tYm9Cb3hcbiAgICAgIEF1ZGl0U2VydmljZS5nZXRBdWRpdGVkTW9kZWxzKCkudGhlbihmdW5jdGlvbiAoZGF0YSkge1xuICAgICAgICB2YXIgbW9kZWxzID0gW3sgaWQ6ICcnLCBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KCdnbG9iYWwuYWxsJykgfV07XG5cbiAgICAgICAgZGF0YS5tb2RlbHMuc29ydCgpO1xuXG4gICAgICAgIGZvciAodmFyIGluZGV4ID0gMDsgaW5kZXggPCBkYXRhLm1vZGVscy5sZW5ndGg7IGluZGV4KyspIHtcbiAgICAgICAgICB2YXIgbW9kZWwgPSBkYXRhLm1vZGVsc1tpbmRleF07XG5cbiAgICAgICAgICBtb2RlbHMucHVzaCh7XG4gICAgICAgICAgICBpZDogbW9kZWwsXG4gICAgICAgICAgICBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KCdtb2RlbHMuJyArIG1vZGVsLnRvTG93ZXJDYXNlKCkpXG4gICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICB2bS5tb2RlbHMgPSBtb2RlbHM7XG4gICAgICAgIHZtLnF1ZXJ5RmlsdGVycy5tb2RlbCA9IHZtLm1vZGVsc1swXS5pZDtcbiAgICAgIH0pO1xuXG4gICAgICB2bS50eXBlcyA9IEF1ZGl0U2VydmljZS5saXN0VHlwZXMoKTtcbiAgICAgIHZtLnF1ZXJ5RmlsdGVycy50eXBlID0gdm0udHlwZXNbMF0uaWQ7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gYXBwbHlGaWx0ZXJzKGRlZmF1bHRRdWVyeUZpbHRlcnMpIHtcbiAgICAgIHJldHVybiBhbmd1bGFyLmV4dGVuZChkZWZhdWx0UXVlcnlGaWx0ZXJzLCB2bS5xdWVyeUZpbHRlcnMpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIHZpZXdEZXRhaWwoYXVkaXREZXRhaWwpIHtcbiAgICAgIHZhciBjb25maWcgPSB7XG4gICAgICAgIGxvY2FsczogeyBhdWRpdERldGFpbDogYXVkaXREZXRhaWwgfSxcbiAgICAgICAgLyoqIEBuZ0luamVjdCAqL1xuICAgICAgICBjb250cm9sbGVyOiBmdW5jdGlvbiBjb250cm9sbGVyKGF1ZGl0RGV0YWlsLCBQckRpYWxvZykge1xuICAgICAgICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICAgICAgICB2bS5jbG9zZSA9IGNsb3NlO1xuXG4gICAgICAgICAgYWN0aXZhdGUoKTtcblxuICAgICAgICAgIGZ1bmN0aW9uIGFjdGl2YXRlKCkge1xuICAgICAgICAgICAgaWYgKGFuZ3VsYXIuaXNBcnJheShhdWRpdERldGFpbC5vbGQpICYmIGF1ZGl0RGV0YWlsLm9sZC5sZW5ndGggPT09IDApIGF1ZGl0RGV0YWlsLm9sZCA9IG51bGw7XG4gICAgICAgICAgICBpZiAoYW5ndWxhci5pc0FycmF5KGF1ZGl0RGV0YWlsLm5ldykgJiYgYXVkaXREZXRhaWwubmV3Lmxlbmd0aCA9PT0gMCkgYXVkaXREZXRhaWwubmV3ID0gbnVsbDtcblxuICAgICAgICAgICAgdm0uYXVkaXREZXRhaWwgPSBhdWRpdERldGFpbDtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICBmdW5jdGlvbiBjbG9zZSgpIHtcbiAgICAgICAgICAgIFByRGlhbG9nLmNsb3NlKCk7XG4gICAgICAgICAgfVxuICAgICAgICB9LFxuICAgICAgICBjb250cm9sbGVyQXM6ICdhdWRpdERldGFpbEN0cmwnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL2F1ZGl0L2F1ZGl0LWRldGFpbC5odG1sJyxcbiAgICAgICAgaGFzQmFja2Ryb3A6IHRydWVcbiAgICAgIH07XG5cbiAgICAgIFByRGlhbG9nLmN1c3RvbShjb25maWcpO1xuICAgIH1cbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25maWcocm91dGVzKTtcblxuICAvKipcbiAgICogQXJxdWl2byBkZSBjb25maWd1cmHDp8OjbyBjb20gYXMgcm90YXMgZXNwZWPDrWZpY2FzIGRlIGF1ZGl0b3JpYVxuICAgKlxuICAgKiBAcGFyYW0ge2FueX0gJHN0YXRlUHJvdmlkZXJcbiAgICogQHBhcmFtIHthbnl9IEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdhcHAuYXVkaXQnLCB7XG4gICAgICB1cmw6ICcvYXVkaXRvcmlhJyxcbiAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvYXVkaXQvYXVkaXQuaHRtbCcsXG4gICAgICBjb250cm9sbGVyOiAnQXVkaXRDb250cm9sbGVyIGFzIGF1ZGl0Q3RybCcsXG4gICAgICBkYXRhOiB7IG5lZWRBdXRoZW50aWNhdGlvbjogdHJ1ZSwgbmVlZFByb2ZpbGU6IFsnYWRtaW4nXSB9XG4gICAgfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmFjdG9yeSgnQXVkaXRTZXJ2aWNlJywgQXVkaXRTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIEF1ZGl0U2VydmljZShzZXJ2aWNlRmFjdG9yeSwgJHRyYW5zbGF0ZSkge1xuICAgIHJldHVybiBzZXJ2aWNlRmFjdG9yeSgnYXVkaXQnLCB7XG4gICAgICBhY3Rpb25zOiB7XG4gICAgICAgIGdldEF1ZGl0ZWRNb2RlbHM6IHtcbiAgICAgICAgICBtZXRob2Q6ICdHRVQnLFxuICAgICAgICAgIHVybDogJ21vZGVscydcbiAgICAgICAgfVxuICAgICAgfSxcbiAgICAgIGluc3RhbmNlOiB7fSxcbiAgICAgIGxpc3RUeXBlczogZnVuY3Rpb24gbGlzdFR5cGVzKCkge1xuICAgICAgICB2YXIgYXVkaXRQYXRoID0gJ3ZpZXdzLmZpZWxkcy5hdWRpdC4nO1xuXG4gICAgICAgIHJldHVybiBbeyBpZDogJycsIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoYXVkaXRQYXRoICsgJ2FsbFJlc291cmNlcycpIH0sIHsgaWQ6ICdjcmVhdGVkJywgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudChhdWRpdFBhdGggKyAndHlwZS5jcmVhdGVkJykgfSwgeyBpZDogJ3VwZGF0ZWQnLCBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KGF1ZGl0UGF0aCArICd0eXBlLnVwZGF0ZWQnKSB9LCB7IGlkOiAnZGVsZXRlZCcsIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoYXVkaXRQYXRoICsgJ3R5cGUuZGVsZXRlZCcpIH1dO1xuICAgICAgfVxuICAgIH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKlxuICAgKiBBcnF1aXZvIGRlIGNvbmZpZ3VyYcOnw6NvIGNvbSBhcyByb3RhcyBlc3BlY8OtZmljYXMgZG8gcmVjdXJzbyB1c2VyXG4gICAqXG4gICAqIEBwYXJhbSB7YW55fSAkc3RhdGVQcm92aWRlclxuICAgKiBAcGFyYW0ge2FueX0gR2xvYmFsXG4gICAqL1xuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvdXRlcygkc3RhdGVQcm92aWRlciwgR2xvYmFsKSB7XG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoR2xvYmFsLnJlc2V0UGFzc3dvcmRTdGF0ZSwge1xuICAgICAgdXJsOiAnL3Bhc3N3b3JkL3Jlc2V0Lzp0b2tlbicsXG4gICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL2F1dGgvcmVzZXQtcGFzcy1mb3JtLmh0bWwnLFxuICAgICAgY29udHJvbGxlcjogJ1Bhc3N3b3JkQ29udHJvbGxlciBhcyBwYXNzQ3RybCcsXG4gICAgICBkYXRhOiB7IG5lZWRBdXRoZW50aWNhdGlvbjogZmFsc2UgfVxuICAgIH0pLnN0YXRlKEdsb2JhbC5sb2dpblN0YXRlLCB7XG4gICAgICB1cmw6ICcvbG9naW4nLFxuICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9hdXRoL2xvZ2luLmh0bWwnLFxuICAgICAgY29udHJvbGxlcjogJ0xvZ2luQ29udHJvbGxlciBhcyBsb2dpbkN0cmwnLFxuICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IGZhbHNlIH1cbiAgICB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5mYWN0b3J5KCdBdXRoJywgQXV0aCk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBBdXRoKCRodHRwLCAkcSwgR2xvYmFsLCBVc2Vyc1NlcnZpY2UpIHtcbiAgICAvLyBOT1NPTkFSXG4gICAgdmFyIGF1dGggPSB7XG4gICAgICBsb2dpbjogbG9naW4sXG4gICAgICBsb2dvdXQ6IGxvZ291dCxcbiAgICAgIHVwZGF0ZUN1cnJlbnRVc2VyOiB1cGRhdGVDdXJyZW50VXNlcixcbiAgICAgIHJldHJpZXZlVXNlckZyb21Mb2NhbFN0b3JhZ2U6IHJldHJpZXZlVXNlckZyb21Mb2NhbFN0b3JhZ2UsXG4gICAgICBhdXRoZW50aWNhdGVkOiBhdXRoZW50aWNhdGVkLFxuICAgICAgc2VuZEVtYWlsUmVzZXRQYXNzd29yZDogc2VuZEVtYWlsUmVzZXRQYXNzd29yZCxcbiAgICAgIHJlbW90ZVZhbGlkYXRlVG9rZW46IHJlbW90ZVZhbGlkYXRlVG9rZW4sXG4gICAgICBnZXRUb2tlbjogZ2V0VG9rZW4sXG4gICAgICBzZXRUb2tlbjogc2V0VG9rZW4sXG4gICAgICBjbGVhclRva2VuOiBjbGVhclRva2VuLFxuICAgICAgY3VycmVudFVzZXI6IG51bGxcbiAgICB9O1xuXG4gICAgZnVuY3Rpb24gY2xlYXJUb2tlbigpIHtcbiAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKEdsb2JhbC50b2tlbktleSk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gc2V0VG9rZW4odG9rZW4pIHtcbiAgICAgIGxvY2FsU3RvcmFnZS5zZXRJdGVtKEdsb2JhbC50b2tlbktleSwgdG9rZW4pO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGdldFRva2VuKCkge1xuICAgICAgcmV0dXJuIGxvY2FsU3RvcmFnZS5nZXRJdGVtKEdsb2JhbC50b2tlbktleSk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gcmVtb3RlVmFsaWRhdGVUb2tlbigpIHtcbiAgICAgIHZhciBkZWZlcnJlZCA9ICRxLmRlZmVyKCk7XG5cbiAgICAgIGlmIChhdXRoLmF1dGhlbnRpY2F0ZWQoKSkge1xuICAgICAgICAkaHR0cC5nZXQoR2xvYmFsLmFwaVBhdGggKyAnL2F1dGhlbnRpY2F0ZS9jaGVjaycpLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICAgIGRlZmVycmVkLnJlc29sdmUodHJ1ZSk7XG4gICAgICAgIH0sIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICBhdXRoLmxvZ291dCgpO1xuXG4gICAgICAgICAgZGVmZXJyZWQucmVqZWN0KGZhbHNlKTtcbiAgICAgICAgfSk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBhdXRoLmxvZ291dCgpO1xuXG4gICAgICAgIGRlZmVycmVkLnJlamVjdChmYWxzZSk7XG4gICAgICB9XG5cbiAgICAgIHJldHVybiBkZWZlcnJlZC5wcm9taXNlO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFZlcmlmaWNhIHNlIG8gdXN1w6FyaW8gZXN0w6EgYXV0ZW50aWNhZG9cbiAgICAgKlxuICAgICAqIEByZXR1cm5zIHtib29sZWFufVxuICAgICAqL1xuICAgIGZ1bmN0aW9uIGF1dGhlbnRpY2F0ZWQoKSB7XG4gICAgICByZXR1cm4gYXV0aC5nZXRUb2tlbigpICE9PSBudWxsO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlY3VwZXJhIG8gdXN1w6FyaW8gZG8gbG9jYWxTdG9yYWdlXG4gICAgICovXG4gICAgZnVuY3Rpb24gcmV0cmlldmVVc2VyRnJvbUxvY2FsU3RvcmFnZSgpIHtcbiAgICAgIHZhciB1c2VyID0gbG9jYWxTdG9yYWdlLmdldEl0ZW0oJ3VzZXInKTtcblxuICAgICAgaWYgKHVzZXIpIHtcbiAgICAgICAgYXV0aC5jdXJyZW50VXNlciA9IGFuZ3VsYXIubWVyZ2UobmV3IFVzZXJzU2VydmljZSgpLCBhbmd1bGFyLmZyb21Kc29uKHVzZXIpKTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBHdWFyZGEgbyB1c3XDoXJpbyBubyBsb2NhbFN0b3JhZ2UgcGFyYSBjYXNvIG8gdXN1w6FyaW8gZmVjaGUgZSBhYnJhIG8gbmF2ZWdhZG9yXG4gICAgICogZGVudHJvIGRvIHRlbXBvIGRlIHNlc3PDo28gc2VqYSBwb3Nzw612ZWwgcmVjdXBlcmFyIG8gdG9rZW4gYXV0ZW50aWNhZG8uXG4gICAgICpcbiAgICAgKiBNYW50w6ltIGEgdmFyacOhdmVsIGF1dGguY3VycmVudFVzZXIgcGFyYSBmYWNpbGl0YXIgbyBhY2Vzc28gYW8gdXN1w6FyaW8gbG9nYWRvIGVtIHRvZGEgYSBhcGxpY2HDp8Ojb1xuICAgICAqXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gdXNlciBVc3XDoXJpbyBhIHNlciBhdHVhbGl6YWRvLiBDYXNvIHNlamEgcGFzc2FkbyBudWxsIGxpbXBhXG4gICAgICogdG9kYXMgYXMgaW5mb3JtYcOnw7VlcyBkbyB1c3XDoXJpbyBjb3JyZW50ZS5cbiAgICAgKi9cbiAgICBmdW5jdGlvbiB1cGRhdGVDdXJyZW50VXNlcih1c2VyKSB7XG4gICAgICB2YXIgZGVmZXJyZWQgPSAkcS5kZWZlcigpO1xuXG4gICAgICBpZiAodXNlcikge1xuICAgICAgICB1c2VyID0gYW5ndWxhci5tZXJnZShuZXcgVXNlcnNTZXJ2aWNlKCksIHVzZXIpO1xuXG4gICAgICAgIHZhciBqc29uVXNlciA9IGFuZ3VsYXIudG9Kc29uKHVzZXIpO1xuXG4gICAgICAgIGxvY2FsU3RvcmFnZS5zZXRJdGVtKCd1c2VyJywganNvblVzZXIpO1xuICAgICAgICBhdXRoLmN1cnJlbnRVc2VyID0gdXNlcjtcblxuICAgICAgICBkZWZlcnJlZC5yZXNvbHZlKHVzZXIpO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oJ3VzZXInKTtcbiAgICAgICAgYXV0aC5jdXJyZW50VXNlciA9IG51bGw7XG4gICAgICAgIGF1dGguY2xlYXJUb2tlbigpO1xuXG4gICAgICAgIGRlZmVycmVkLnJlamVjdCgpO1xuICAgICAgfVxuXG4gICAgICByZXR1cm4gZGVmZXJyZWQucHJvbWlzZTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFsaXphIG8gbG9naW4gZG8gdXN1w6FyaW9cbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSBjcmVkZW50aWFscyBFbWFpbCBlIFNlbmhhIGRvIHVzdcOhcmlvXG4gICAgICogQHJldHVybnMge3Byb21pc2V9IFVtYSBwcm9taXNlIGNvbSBvIHJlc3VsdGFkbyBkbyBjaGFtYWRhIG5vIGJhY2tlbmRcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBsb2dpbihjcmVkZW50aWFscykge1xuICAgICAgdmFyIGRlZmVycmVkID0gJHEuZGVmZXIoKTtcblxuICAgICAgJGh0dHAucG9zdChHbG9iYWwuYXBpUGF0aCArICcvYXV0aGVudGljYXRlJywgY3JlZGVudGlhbHMpLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgIGF1dGguc2V0VG9rZW4ocmVzcG9uc2UuZGF0YS50b2tlbik7XG5cbiAgICAgICAgcmV0dXJuICRodHRwLmdldChHbG9iYWwuYXBpUGF0aCArICcvYXV0aGVudGljYXRlL3VzZXInKTtcbiAgICAgIH0pLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgIGF1dGgudXBkYXRlQ3VycmVudFVzZXIocmVzcG9uc2UuZGF0YS51c2VyKTtcblxuICAgICAgICBkZWZlcnJlZC5yZXNvbHZlKCk7XG4gICAgICB9LCBmdW5jdGlvbiAoZXJyb3IpIHtcbiAgICAgICAgYXV0aC5sb2dvdXQoKTtcblxuICAgICAgICBkZWZlcnJlZC5yZWplY3QoZXJyb3IpO1xuICAgICAgfSk7XG5cbiAgICAgIHJldHVybiBkZWZlcnJlZC5wcm9taXNlO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIERlc2xvZ2Egb3MgdXN1w6FyaW9zLiBDb21vIG7Do28gdGVuIG5lbmh1bWEgaW5mb3JtYcOnw6NvIG5hIHNlc3PDo28gZG8gc2Vydmlkb3JcbiAgICAgKiBlIHVtIHRva2VuIHVtYSB2ZXogZ2VyYWRvIG7Do28gcG9kZSwgcG9yIHBhZHLDo28sIHNlciBpbnZhbGlkYWRvIGFudGVzIGRvIHNldSB0ZW1wbyBkZSBleHBpcmHDp8OjbyxcbiAgICAgKiBzb21lbnRlIGFwYWdhbW9zIG9zIGRhZG9zIGRvIHVzdcOhcmlvIGUgbyB0b2tlbiBkbyBuYXZlZ2Fkb3IgcGFyYSBlZmV0aXZhciBvIGxvZ291dC5cbiAgICAgKlxuICAgICAqIEByZXR1cm5zIHtwcm9taXNlfSBVbWEgcHJvbWlzZSBjb20gbyByZXN1bHRhZG8gZGEgb3BlcmHDp8Ojb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGxvZ291dCgpIHtcbiAgICAgIHZhciBkZWZlcnJlZCA9ICRxLmRlZmVyKCk7XG5cbiAgICAgIGF1dGgudXBkYXRlQ3VycmVudFVzZXIobnVsbCk7XG4gICAgICBkZWZlcnJlZC5yZXNvbHZlKCk7XG5cbiAgICAgIHJldHVybiBkZWZlcnJlZC5wcm9taXNlO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEVudmlhIHVtIGVtYWlsIHBhcmEgcmVjdXBlcmHDp8OjbyBkZSBzZW5oYVxuICAgICAqIEBwYXJhbSB7T2JqZWN0fSByZXNldERhdGEgLSBPYmpldG8gY29udGVuZG8gbyBlbWFpbFxuICAgICAqIEByZXR1cm4ge1Byb21pc2V9IC0gUmV0b3JuYSB1bWEgcHJvbWlzZSBwYXJhIHNlciByZXNvbHZpZGFcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBzZW5kRW1haWxSZXNldFBhc3N3b3JkKHJlc2V0RGF0YSkge1xuICAgICAgdmFyIGRlZmVycmVkID0gJHEuZGVmZXIoKTtcblxuICAgICAgJGh0dHAucG9zdChHbG9iYWwuYXBpUGF0aCArICcvcGFzc3dvcmQvZW1haWwnLCByZXNldERhdGEpLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgIGRlZmVycmVkLnJlc29sdmUocmVzcG9uc2UuZGF0YSk7XG4gICAgICB9LCBmdW5jdGlvbiAoZXJyb3IpIHtcbiAgICAgICAgZGVmZXJyZWQucmVqZWN0KGVycm9yKTtcbiAgICAgIH0pO1xuXG4gICAgICByZXR1cm4gZGVmZXJyZWQucHJvbWlzZTtcbiAgICB9XG5cbiAgICByZXR1cm4gYXV0aDtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbnRyb2xsZXIoJ0xvZ2luQ29udHJvbGxlcicsIExvZ2luQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBMb2dpbkNvbnRyb2xsZXIoJHN0YXRlLCBBdXRoLCBHbG9iYWwsIFByRGlhbG9nKSB7XG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIHZtLmxvZ2luID0gbG9naW47XG4gICAgdm0ub3BlbkRpYWxvZ1Jlc2V0UGFzcyA9IG9wZW5EaWFsb2dSZXNldFBhc3M7XG4gICAgdm0ub3BlbkRpYWxvZ1NpZ25VcCA9IG9wZW5EaWFsb2dTaWduVXA7XG5cbiAgICBhY3RpdmF0ZSgpO1xuXG4gICAgZnVuY3Rpb24gYWN0aXZhdGUoKSB7XG4gICAgICB2bS5jcmVkZW50aWFscyA9IHt9O1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGxvZ2luKCkge1xuICAgICAgdmFyIGNyZWRlbnRpYWxzID0ge1xuICAgICAgICBlbWFpbDogdm0uY3JlZGVudGlhbHMuZW1haWwsXG4gICAgICAgIHBhc3N3b3JkOiB2bS5jcmVkZW50aWFscy5wYXNzd29yZFxuICAgICAgfTtcblxuICAgICAgQXV0aC5sb2dpbihjcmVkZW50aWFscykudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgICRzdGF0ZS5nbyhHbG9iYWwuaG9tZVN0YXRlKTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEV4aWJlIG8gZGlhbG9nIHBhcmEgcmVjdXBlcmHDp8OjbyBkZSBzZW5oYVxuICAgICAqL1xuICAgIGZ1bmN0aW9uIG9wZW5EaWFsb2dSZXNldFBhc3MoKSB7XG4gICAgICB2YXIgY29uZmlnID0ge1xuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL2F1dGgvc2VuZC1yZXNldC1kaWFsb2cuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdQYXNzd29yZENvbnRyb2xsZXIgYXMgcGFzc0N0cmwnLFxuICAgICAgICBoYXNCYWNrZHJvcDogdHJ1ZVxuICAgICAgfTtcblxuICAgICAgUHJEaWFsb2cuY3VzdG9tKGNvbmZpZyk7XG4gICAgfVxuICAgIC8qKlxuICAgICAqIEV4aWJlIG8gZGlhbG9nIHBhcmEgcmVjdXBlcmHDp8OjbyBkZSBzZW5oYVxuICAgICAqL1xuICAgIGZ1bmN0aW9uIG9wZW5EaWFsb2dTaWduVXAoKSB7XG4gICAgICB2YXIgY29uZmlnID0ge1xuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL3VzZXJzL3VzZXItZm9ybS5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ1VzZXJzQ29udHJvbGxlciBhcyB1c2Vyc0N0cmwnLFxuICAgICAgICBoYXNCYWNrZHJvcDogdHJ1ZVxuICAgICAgfTtcblxuICAgICAgUHJEaWFsb2cuY3VzdG9tKGNvbmZpZyk7XG4gICAgfVxuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29udHJvbGxlcignUGFzc3dvcmRDb250cm9sbGVyJywgUGFzc3dvcmRDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIFBhc3N3b3JkQ29udHJvbGxlcihHbG9iYWwsICRzdGF0ZVBhcmFtcywgJGh0dHAsICR0aW1lb3V0LCAkc3RhdGUsIC8vIE5PU09OQVJcbiAgUHJUb2FzdCwgUHJEaWFsb2csIEF1dGgsICR0cmFuc2xhdGUpIHtcblxuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICB2bS5zZW5kUmVzZXQgPSBzZW5kUmVzZXQ7XG4gICAgdm0uY2xvc2VEaWFsb2cgPSBjbG9zZURpYWxvZztcbiAgICB2bS5jbGVhbkZvcm0gPSBjbGVhbkZvcm07XG4gICAgdm0uc2VuZEVtYWlsUmVzZXRQYXNzd29yZCA9IHNlbmRFbWFpbFJlc2V0UGFzc3dvcmQ7XG5cbiAgICBhY3RpdmF0ZSgpO1xuXG4gICAgZnVuY3Rpb24gYWN0aXZhdGUoKSB7XG4gICAgICB2bS5yZXNldCA9IHsgZW1haWw6ICcnLCB0b2tlbjogJHN0YXRlUGFyYW1zLnRva2VuIH07XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhbGl6YSBhIGFsdGVyYcOnw6NvIGRhIHNlbmhhIGRvIHVzdcOhcmlvIGUgbyByZWRpcmVjaW9uYSBwYXJhIGEgdGVsYSBkZSBsb2dpblxuICAgICAqL1xuICAgIGZ1bmN0aW9uIHNlbmRSZXNldCgpIHtcbiAgICAgICRodHRwLnBvc3QoR2xvYmFsLmFwaVBhdGggKyAnL3Bhc3N3b3JkL3Jlc2V0Jywgdm0ucmVzZXQpLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICBQclRvYXN0LnN1Y2Nlc3MoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5vcGVyYXRpb25TdWNjZXNzJykpO1xuICAgICAgICAkdGltZW91dChmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgJHN0YXRlLmdvKEdsb2JhbC5sb2dpblN0YXRlKTtcbiAgICAgICAgfSwgMTUwMCk7XG4gICAgICB9LCBmdW5jdGlvbiAoZXJyb3IpIHtcbiAgICAgICAgaWYgKGVycm9yLnN0YXR1cyAhPT0gNDAwICYmIGVycm9yLnN0YXR1cyAhPT0gNTAwKSB7XG4gICAgICAgICAgdmFyIG1zZyA9ICcnO1xuXG4gICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCBlcnJvci5kYXRhLnBhc3N3b3JkLmxlbmd0aDsgaSsrKSB7XG4gICAgICAgICAgICBtc2cgKz0gZXJyb3IuZGF0YS5wYXNzd29yZFtpXSArICc8YnI+JztcbiAgICAgICAgICB9XG4gICAgICAgICAgUHJUb2FzdC5lcnJvcihtc2cudG9VcHBlckNhc2UoKSk7XG4gICAgICAgIH1cbiAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEVudmlhIHVtIGVtYWlsIGRlIHJlY3VwZXJhw6fDo28gZGUgc2VuaGEgY29tIG8gdG9rZW4gZG8gdXN1w6FyaW9cbiAgICAgKi9cbiAgICBmdW5jdGlvbiBzZW5kRW1haWxSZXNldFBhc3N3b3JkKCkge1xuXG4gICAgICBpZiAodm0ucmVzZXQuZW1haWwgPT09ICcnKSB7XG4gICAgICAgIFByVG9hc3QuZXJyb3IoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy52YWxpZGF0ZS5maWVsZFJlcXVpcmVkJywgeyBmaWVsZDogJ2VtYWlsJyB9KSk7XG4gICAgICAgIHJldHVybjtcbiAgICAgIH1cblxuICAgICAgQXV0aC5zZW5kRW1haWxSZXNldFBhc3N3b3JkKHZtLnJlc2V0KS50aGVuKGZ1bmN0aW9uIChkYXRhKSB7XG4gICAgICAgIFByVG9hc3Quc3VjY2VzcyhkYXRhLm1lc3NhZ2UpO1xuXG4gICAgICAgIHZtLmNsZWFuRm9ybSgpO1xuICAgICAgICB2bS5jbG9zZURpYWxvZygpO1xuICAgICAgfSwgZnVuY3Rpb24gKGVycm9yKSB7XG4gICAgICAgIGlmIChlcnJvci5kYXRhLmVtYWlsICYmIGVycm9yLmRhdGEuZW1haWwubGVuZ3RoID4gMCkge1xuICAgICAgICAgIHZhciBtc2cgPSAnJztcblxuICAgICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgZXJyb3IuZGF0YS5lbWFpbC5sZW5ndGg7IGkrKykge1xuICAgICAgICAgICAgbXNnICs9IGVycm9yLmRhdGEuZW1haWxbaV0gKyAnPGJyPic7XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgUHJUb2FzdC5lcnJvcihtc2cpO1xuICAgICAgICB9XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBjbG9zZURpYWxvZygpIHtcbiAgICAgIFByRGlhbG9nLmNsb3NlKCk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gY2xlYW5Gb3JtKCkge1xuICAgICAgdm0ucmVzZXQuZW1haWwgPSAnJztcbiAgICB9XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbi8qZXNsaW50IGFuZ3VsYXIvZmlsZS1uYW1lOiAwKi9cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmFjdG9yeSgnc2VydmljZUZhY3RvcnknLCBzZXJ2aWNlRmFjdG9yeSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvKipcbiAgICogTWFpcyBpbmZvcm1hw6fDtWVzOlxuICAgKiBodHRwczovL2dpdGh1Yi5jb20vc3dpbWxhbmUvYW5ndWxhci1tb2RlbC1mYWN0b3J5L3dpa2kvQVBJXG4gICAqL1xuICBmdW5jdGlvbiBzZXJ2aWNlRmFjdG9yeSgkbW9kZWxGYWN0b3J5KSB7XG4gICAgcmV0dXJuIGZ1bmN0aW9uICh1cmwsIG9wdGlvbnMpIHtcbiAgICAgIHZhciBtb2RlbDtcbiAgICAgIHZhciBkZWZhdWx0T3B0aW9ucyA9IHtcbiAgICAgICAgYWN0aW9uczoge1xuICAgICAgICAgIC8qKlxuICAgICAgICAgICAqIFNlcnZpw6dvIGNvbXVtIHBhcmEgcmVhbGl6YXIgYnVzY2EgY29tIHBhZ2luYcOnw6NvXG4gICAgICAgICAgICogTyBtZXNtbyBlc3BlcmEgcXVlIHNlamEgcmV0b3JuYWRvIHVtIG9iamV0byBjb20gaXRlbXMgZSB0b3RhbFxuICAgICAgICAgICAqL1xuICAgICAgICAgIHBhZ2luYXRlOiB7XG4gICAgICAgICAgICBtZXRob2Q6ICdHRVQnLFxuICAgICAgICAgICAgaXNBcnJheTogZmFsc2UsXG4gICAgICAgICAgICB3cmFwOiBmYWxzZSxcbiAgICAgICAgICAgIGFmdGVyUmVxdWVzdDogZnVuY3Rpb24gYWZ0ZXJSZXF1ZXN0KHJlc3BvbnNlKSB7XG4gICAgICAgICAgICAgIGlmIChyZXNwb25zZVsnaXRlbXMnXSkge1xuICAgICAgICAgICAgICAgIHJlc3BvbnNlWydpdGVtcyddID0gbW9kZWwuTGlzdChyZXNwb25zZVsnaXRlbXMnXSk7XG4gICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICByZXR1cm4gcmVzcG9uc2U7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICB9O1xuXG4gICAgICBtb2RlbCA9ICRtb2RlbEZhY3RvcnkodXJsLCBhbmd1bGFyLm1lcmdlKGRlZmF1bHRPcHRpb25zLCBvcHRpb25zKSk7XG5cbiAgICAgIHJldHVybiBtb2RlbDtcbiAgICB9O1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29udHJvbGxlcignQ1JVRENvbnRyb2xsZXInLCBDUlVEQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvKipcbiAgICogQ29udHJvbGFkb3IgQmFzZSBxdWUgaW1wbGVtZW50YSB0b2RhcyBhcyBmdW7Dp8O1ZXMgcGFkcsO1ZXMgZGUgdW0gQ1JVRFxuICAgKlxuICAgKiBBw6fDtWVzIGltcGxlbWVudGFkYXNcbiAgICogYWN0aXZhdGUoKVxuICAgKiBzZWFyY2gocGFnZSlcbiAgICogZWRpdChyZXNvdXJjZSlcbiAgICogc2F2ZSgpXG4gICAqIHJlbW92ZShyZXNvdXJjZSlcbiAgICogZ29Ubyh2aWV3TmFtZSlcbiAgICogY2xlYW5Gb3JtKClcbiAgICpcbiAgICogR2F0aWxob3NcbiAgICpcbiAgICogb25BY3RpdmF0ZSgpXG4gICAqIGFwcGx5RmlsdGVycyhkZWZhdWx0UXVlcnlGaWx0ZXJzKVxuICAgKiBiZWZvcmVTZWFyY2gocGFnZSkgLy9yZXRvcm5hbmRvIGZhbHNlIGNhbmNlbGEgbyBmbHV4b1xuICAgKiBhZnRlclNlYXJjaChyZXNwb25zZSlcbiAgICogYmVmb3JlQ2xlYW4gLy9yZXRvcm5hbmRvIGZhbHNlIGNhbmNlbGEgbyBmbHV4b1xuICAgKiBhZnRlckNsZWFuKClcbiAgICogYmVmb3JlU2F2ZSgpIC8vcmV0b3JuYW5kbyBmYWxzZSBjYW5jZWxhIG8gZmx1eG9cbiAgICogYWZ0ZXJTYXZlKHJlc291cmNlKVxuICAgKiBvblNhdmVFcnJvcihlcnJvcilcbiAgICogYmVmb3JlUmVtb3ZlKHJlc291cmNlKSAvL3JldG9ybmFuZG8gZmFsc2UgY2FuY2VsYSBvIGZsdXhvXG4gICAqIGFmdGVyUmVtb3ZlKHJlc291cmNlKVxuICAgKlxuICAgKiBAcGFyYW0ge2FueX0gdm0gaW5zdGFuY2lhIGRvIGNvbnRyb2xsZXIgZmlsaG9cbiAgICogQHBhcmFtIHthbnl9IG1vZGVsU2VydmljZSBzZXJ2acOnbyBkbyBtb2RlbCBxdWUgdmFpIHNlciB1dGlsaXphZG9cbiAgICogQHBhcmFtIHthbnl9IG9wdGlvbnMgb3DDp8O1ZXMgcGFyYSBzb2JyZWVzY3JldmVyIGNvbXBvcnRhbWVudG9zIHBhZHLDtWVzXG4gICAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBDUlVEQ29udHJvbGxlcih2bSwgbW9kZWxTZXJ2aWNlLCBvcHRpb25zLCBQclRvYXN0LCBQclBhZ2luYXRpb24sIC8vIE5PU09OQVJcbiAgUHJEaWFsb2csICR0cmFuc2xhdGUpIHtcblxuICAgIC8vRnVuY3Rpb25zIEJsb2NrXG4gICAgdm0uc2VhcmNoID0gc2VhcmNoO1xuICAgIHZtLnBhZ2luYXRlU2VhcmNoID0gcGFnaW5hdGVTZWFyY2g7XG4gICAgdm0ubm9ybWFsU2VhcmNoID0gbm9ybWFsU2VhcmNoO1xuICAgIHZtLmVkaXQgPSBlZGl0O1xuICAgIHZtLnNhdmUgPSBzYXZlO1xuICAgIHZtLnJlbW92ZSA9IHJlbW92ZTtcbiAgICB2bS5nb1RvID0gZ29UbztcbiAgICB2bS5jbGVhbkZvcm0gPSBjbGVhbkZvcm07XG5cbiAgICBhY3RpdmF0ZSgpO1xuXG4gICAgLyoqXG4gICAgICogUHJlcGFyYSBvIGNvbnRyb2xhZG9yXG4gICAgICogRmF6IG8gbWVyZ2UgZGFzIG9ww6fDtWVzXG4gICAgICogSW5pY2lhbGl6YSBvIHJlY3Vyc29cbiAgICAgKiBJbmljaWFsaXphIG8gb2JqZXRvIHBhZ2luYWRvciBlIHJlYWxpemEgYSBwZXNxdWlzYVxuICAgICAqL1xuICAgIGZ1bmN0aW9uIGFjdGl2YXRlKCkge1xuICAgICAgdm0uZGVmYXVsdE9wdGlvbnMgPSB7XG4gICAgICAgIHJlZGlyZWN0QWZ0ZXJTYXZlOiB0cnVlLFxuICAgICAgICBzZWFyY2hPbkluaXQ6IHRydWUsXG4gICAgICAgIHBlclBhZ2U6IDgsXG4gICAgICAgIHNraXBQYWdpbmF0aW9uOiBmYWxzZVxuICAgICAgfTtcblxuICAgICAgYW5ndWxhci5tZXJnZSh2bS5kZWZhdWx0T3B0aW9ucywgb3B0aW9ucyk7XG5cbiAgICAgIHZtLnZpZXdGb3JtID0gZmFsc2U7XG4gICAgICB2bS5yZXNvdXJjZSA9IG5ldyBtb2RlbFNlcnZpY2UoKTtcblxuICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5vbkFjdGl2YXRlKSkgdm0ub25BY3RpdmF0ZSgpO1xuXG4gICAgICB2bS5wYWdpbmF0b3IgPSBQclBhZ2luYXRpb24uZ2V0SW5zdGFuY2Uodm0uc2VhcmNoLCB2bS5kZWZhdWx0T3B0aW9ucy5wZXJQYWdlKTtcblxuICAgICAgaWYgKHZtLmRlZmF1bHRPcHRpb25zLnNlYXJjaE9uSW5pdCkgdm0uc2VhcmNoKCk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhbGl6YSBhIHBlc3F1aXNhXG4gICAgICogVmVyaWZpY2EgcXVhbCBkYXMgZnVuw6fDtWVzIGRlIHBlc3F1aXNhIGRldmUgc2VyIHJlYWxpemFkYS5cbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSBwYWdlIHDDoWdpbmEgcXVlIGRldmUgc2VyIGNhcnJlZ2FkYVxuICAgICAqL1xuICAgIGZ1bmN0aW9uIHNlYXJjaChwYWdlKSB7XG4gICAgICB2bS5kZWZhdWx0T3B0aW9ucy5za2lwUGFnaW5hdGlvbiA/IG5vcm1hbFNlYXJjaCgpIDogcGFnaW5hdGVTZWFyY2gocGFnZSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhbGl6YSBhIHBlc3F1aXNhIHBhZ2luYWRhIGNvbSBiYXNlIG5vcyBmaWx0cm9zIGRlZmluaWRvc1xuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IHBhZ2UgcMOhZ2luYSBxdWUgZGV2ZSBzZXIgY2FycmVnYWRhXG4gICAgICovXG4gICAgZnVuY3Rpb24gcGFnaW5hdGVTZWFyY2gocGFnZSkge1xuICAgICAgdm0ucGFnaW5hdG9yLmN1cnJlbnRQYWdlID0gYW5ndWxhci5pc0RlZmluZWQocGFnZSkgPyBwYWdlIDogMTtcbiAgICAgIHZtLmRlZmF1bHRRdWVyeUZpbHRlcnMgPSB7IHBhZ2U6IHZtLnBhZ2luYXRvci5jdXJyZW50UGFnZSwgcGVyUGFnZTogdm0ucGFnaW5hdG9yLnBlclBhZ2UgfTtcblxuICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5hcHBseUZpbHRlcnMpKSB2bS5kZWZhdWx0UXVlcnlGaWx0ZXJzID0gdm0uYXBwbHlGaWx0ZXJzKHZtLmRlZmF1bHRRdWVyeUZpbHRlcnMpO1xuICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5iZWZvcmVTZWFyY2gpICYmIHZtLmJlZm9yZVNlYXJjaChwYWdlKSA9PT0gZmFsc2UpIHJldHVybiBmYWxzZTtcblxuICAgICAgbW9kZWxTZXJ2aWNlLnBhZ2luYXRlKHZtLmRlZmF1bHRRdWVyeUZpbHRlcnMpLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgIHZtLnBhZ2luYXRvci5jYWxjTnVtYmVyT2ZQYWdlcyhyZXNwb25zZS50b3RhbCk7XG4gICAgICAgIHZtLnJlc291cmNlcyA9IHJlc3BvbnNlLml0ZW1zO1xuXG4gICAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYWZ0ZXJTZWFyY2gpKSB2bS5hZnRlclNlYXJjaChyZXNwb25zZSk7XG4gICAgICB9LCBmdW5jdGlvbiAocmVzcG9uc2VEYXRhKSB7XG4gICAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0ub25TZWFyY2hFcnJvcikpIHZtLm9uU2VhcmNoRXJyb3IocmVzcG9uc2VEYXRhKTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWxpemEgYSBwZXNxdWlzYSBjb20gYmFzZSBub3MgZmlsdHJvcyBkZWZpbmlkb3NcbiAgICAgKlxuICAgICAqL1xuICAgIGZ1bmN0aW9uIG5vcm1hbFNlYXJjaCgpIHtcbiAgICAgIHZtLmRlZmF1bHRRdWVyeUZpbHRlcnMgPSB7fTtcblxuICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5hcHBseUZpbHRlcnMpKSB2bS5kZWZhdWx0UXVlcnlGaWx0ZXJzID0gdm0uYXBwbHlGaWx0ZXJzKHZtLmRlZmF1bHRRdWVyeUZpbHRlcnMpO1xuICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5iZWZvcmVTZWFyY2gpICYmIHZtLmJlZm9yZVNlYXJjaCgpID09PSBmYWxzZSkgcmV0dXJuIGZhbHNlO1xuXG4gICAgICBtb2RlbFNlcnZpY2UucXVlcnkodm0uZGVmYXVsdFF1ZXJ5RmlsdGVycykudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgdm0ucmVzb3VyY2VzID0gcmVzcG9uc2U7XG5cbiAgICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5hZnRlclNlYXJjaCkpIHZtLmFmdGVyU2VhcmNoKHJlc3BvbnNlKTtcbiAgICAgIH0sIGZ1bmN0aW9uIChyZXNwb25zZURhdGEpIHtcbiAgICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5vblNlYXJjaEVycm9yKSkgdm0ub25TZWFyY2hFcnJvcihyZXNwb25zZURhdGEpO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogTGltcGEgbyBmb3JtdWzDoXJpb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGNsZWFuRm9ybShmb3JtKSB7XG4gICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmJlZm9yZUNsZWFuKSAmJiB2bS5iZWZvcmVDbGVhbigpID09PSBmYWxzZSkgcmV0dXJuIGZhbHNlO1xuXG4gICAgICB2bS5yZXNvdXJjZSA9IG5ldyBtb2RlbFNlcnZpY2UoKTtcblxuICAgICAgaWYgKGFuZ3VsYXIuaXNEZWZpbmVkKGZvcm0pKSB7XG4gICAgICAgIGZvcm0uJHNldFByaXN0aW5lKCk7XG4gICAgICAgIGZvcm0uJHNldFVudG91Y2hlZCgpO1xuICAgICAgfVxuXG4gICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmFmdGVyQ2xlYW4pKSB2bS5hZnRlckNsZWFuKCk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ2FycmVnYSBubyBmb3JtdWzDoXJpbyBvIHJlY3Vyc28gc2VsZWNpb25hZG8gcGFyYSBlZGnDp8Ojb1xuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IHJlc291cmNlIHJlY3Vyc28gc2VsZWNpb25hZG9cbiAgICAgKi9cbiAgICBmdW5jdGlvbiBlZGl0KHJlc291cmNlKSB7XG4gICAgICB2bS5nb1RvKCdmb3JtJyk7XG4gICAgICB2bS5yZXNvdXJjZSA9IG5ldyBhbmd1bGFyLmNvcHkocmVzb3VyY2UpO1xuXG4gICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmFmdGVyRWRpdCkpIHZtLmFmdGVyRWRpdCgpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFNhbHZhIG91IGF0dWFsaXphIG8gcmVjdXJzbyBjb3JyZW50ZSBubyBmb3JtdWzDoXJpb1xuICAgICAqIE5vIGNvbXBvcnRhbWVudG8gcGFkcsOjbyByZWRpcmVjaW9uYSBvIHVzdcOhcmlvIHBhcmEgdmlldyBkZSBsaXN0YWdlbVxuICAgICAqIGRlcG9pcyBkYSBleGVjdcOnw6NvXG4gICAgICpcbiAgICAgKiBAcmV0dXJuc1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIHNhdmUoZm9ybSkge1xuICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5iZWZvcmVTYXZlKSAmJiB2bS5iZWZvcmVTYXZlKCkgPT09IGZhbHNlKSByZXR1cm4gZmFsc2U7XG5cbiAgICAgIHZtLnJlc291cmNlLiRzYXZlKCkudGhlbihmdW5jdGlvbiAocmVzb3VyY2UpIHtcbiAgICAgICAgdm0ucmVzb3VyY2UgPSByZXNvdXJjZTtcblxuICAgICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmFmdGVyU2F2ZSkpIHZtLmFmdGVyU2F2ZShyZXNvdXJjZSk7XG5cbiAgICAgICAgaWYgKHZtLmRlZmF1bHRPcHRpb25zLnJlZGlyZWN0QWZ0ZXJTYXZlKSB7XG4gICAgICAgICAgdm0uY2xlYW5Gb3JtKGZvcm0pO1xuICAgICAgICAgIHZtLnNlYXJjaCh2bS5wYWdpbmF0b3IuY3VycmVudFBhZ2UpO1xuICAgICAgICAgIHZtLmdvVG8oJ2xpc3QnKTtcbiAgICAgICAgfVxuXG4gICAgICAgIFByVG9hc3Quc3VjY2VzcygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnNhdmVTdWNjZXNzJykpO1xuICAgICAgfSwgZnVuY3Rpb24gKHJlc3BvbnNlRGF0YSkge1xuICAgICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLm9uU2F2ZUVycm9yKSkgdm0ub25TYXZlRXJyb3IocmVzcG9uc2VEYXRhKTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlbW92ZSBvIHJlY3Vyc28gaW5mb3JtYWRvLlxuICAgICAqIEFudGVzIGV4aWJlIHVtIGRpYWxvZ28gZGUgY29uZmlybWHDp8Ojb1xuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IHJlc291cmNlIHJlY3Vyc28gZXNjb2xoaWRvXG4gICAgICovXG4gICAgZnVuY3Rpb24gcmVtb3ZlKHJlc291cmNlKSB7XG4gICAgICB2YXIgY29uZmlnID0ge1xuICAgICAgICB0aXRsZTogJHRyYW5zbGF0ZS5pbnN0YW50KCdkaWFsb2cuY29uZmlybVRpdGxlJyksXG4gICAgICAgIGRlc2NyaXB0aW9uOiAkdHJhbnNsYXRlLmluc3RhbnQoJ2RpYWxvZy5jb25maXJtRGVzY3JpcHRpb24nKVxuICAgICAgfTtcblxuICAgICAgUHJEaWFsb2cuY29uZmlybShjb25maWcpLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmJlZm9yZVJlbW92ZSkgJiYgdm0uYmVmb3JlUmVtb3ZlKHJlc291cmNlKSA9PT0gZmFsc2UpIHJldHVybiBmYWxzZTtcblxuICAgICAgICByZXNvdXJjZS4kZGVzdHJveSgpLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYWZ0ZXJSZW1vdmUpKSB2bS5hZnRlclJlbW92ZShyZXNvdXJjZSk7XG5cbiAgICAgICAgICB2bS5zZWFyY2goKTtcbiAgICAgICAgICBQclRvYXN0LmluZm8oJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5yZW1vdmVTdWNjZXNzJykpO1xuICAgICAgICB9KTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEFsdGVybmEgZW50cmUgYSB2aWV3IGRvIGZvcm11bMOhcmlvIGUgbGlzdGFnZW1cbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSB2aWV3TmFtZSBub21lIGRhIHZpZXdcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBnb1RvKHZpZXdOYW1lKSB7XG4gICAgICB2bS52aWV3Rm9ybSA9IGZhbHNlO1xuICAgICAgdm0ub25WaWV3ID0gZmFsc2U7XG4gICAgICBpZiAodmlld05hbWUgPT09ICdmb3JtJykge1xuICAgICAgICB2bS5jbGVhbkZvcm0oKTtcbiAgICAgICAgdm0udmlld0Zvcm0gPSB0cnVlO1xuICAgICAgfVxuICAgIH1cbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZpbHRlcignZWxhcHNlZCcsIGZ1bmN0aW9uICgpIHtcbiAgICByZXR1cm4gZnVuY3Rpb24gKGRhdGUpIHtcbiAgICAgIGlmICghZGF0ZSkgcmV0dXJuO1xuICAgICAgdmFyIHRpbWUgPSBEYXRlLnBhcnNlKGRhdGUpLFxuICAgICAgICAgIHRpbWVOb3cgPSBuZXcgRGF0ZSgpLmdldFRpbWUoKSxcbiAgICAgICAgICBkaWZmZXJlbmNlID0gdGltZU5vdyAtIHRpbWUsXG4gICAgICAgICAgc2Vjb25kcyA9IE1hdGguZmxvb3IoZGlmZmVyZW5jZSAvIDEwMDApLFxuICAgICAgICAgIG1pbnV0ZXMgPSBNYXRoLmZsb29yKHNlY29uZHMgLyA2MCksXG4gICAgICAgICAgaG91cnMgPSBNYXRoLmZsb29yKG1pbnV0ZXMgLyA2MCksXG4gICAgICAgICAgZGF5cyA9IE1hdGguZmxvb3IoaG91cnMgLyAyNCksXG4gICAgICAgICAgbW9udGhzID0gTWF0aC5mbG9vcihkYXlzIC8gMzApO1xuXG4gICAgICBpZiAobW9udGhzID4gMSkge1xuICAgICAgICByZXR1cm4gbW9udGhzICsgJyBtZXNlcyBhdHLDoXMnO1xuICAgICAgfSBlbHNlIGlmIChtb250aHMgPT09IDEpIHtcbiAgICAgICAgcmV0dXJuICcxIG3DqnMgYXRyw6FzJztcbiAgICAgIH0gZWxzZSBpZiAoZGF5cyA+IDEpIHtcbiAgICAgICAgcmV0dXJuIGRheXMgKyAnIGRpYXMgYXRyw6FzJztcbiAgICAgIH0gZWxzZSBpZiAoZGF5cyA9PT0gMSkge1xuICAgICAgICByZXR1cm4gJzEgZGlhIGF0csOhcyc7XG4gICAgICB9IGVsc2UgaWYgKGhvdXJzID4gMSkge1xuICAgICAgICByZXR1cm4gaG91cnMgKyAnIGhvcmFzIGF0csOhcyc7XG4gICAgICB9IGVsc2UgaWYgKGhvdXJzID09PSAxKSB7XG4gICAgICAgIHJldHVybiAndW1hIGhvcmEgYXRyw6FzJztcbiAgICAgIH0gZWxzZSBpZiAobWludXRlcyA+IDEpIHtcbiAgICAgICAgcmV0dXJuIG1pbnV0ZXMgKyAnIG1pbnV0b3MgYXRyw6FzJztcbiAgICAgIH0gZWxzZSBpZiAobWludXRlcyA9PT0gMSkge1xuICAgICAgICByZXR1cm4gJ3VtIG1pbnV0byBhdHLDoXMnO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgcmV0dXJuICdow6EgcG91Y29zIHNlZ3VuZG9zJztcbiAgICAgIH1cbiAgICB9O1xuICB9KS5jb250cm9sbGVyKCdEYXNoYm9hcmRDb250cm9sbGVyJywgRGFzaGJvYXJkQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBEYXNoYm9hcmRDb250cm9sbGVyKCRjb250cm9sbGVyLCAkc3RhdGUsICRtZERpYWxvZywgJHRyYW5zbGF0ZSwgRGFzaGJvYXJkc1NlcnZpY2UsIFByb2plY3RzU2VydmljZSwgbW9tZW50LCBQclRvYXN0LCBBdXRoLCBHbG9iYWwpIHtcbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgLy9BdHRyaWJ1dGVzIEJsb2NrXG5cbiAgICAvL0Z1bmN0aW9ucyBCbG9ja1xuICAgIHZtLm9uQWN0aXZhdGUgPSBvbkFjdGl2YXRlO1xuICAgIHZtLmFwcGx5RmlsdGVycyA9IGFwcGx5RmlsdGVycztcbiAgICB2bS5maXhEYXRlID0gZml4RGF0ZTtcblxuICAgIGZ1bmN0aW9uIG9uQWN0aXZhdGUoKSB7XG4gICAgICB2YXIgcHJvamVjdCA9IGxvY2FsU3RvcmFnZS5nZXRJdGVtKCdwcm9qZWN0Jyk7XG5cbiAgICAgIHZtLmltYWdlUGF0aCA9IEdsb2JhbC5pbWFnZVBhdGggKyAnL25vX2F2YXRhci5naWYnO1xuICAgICAgdm0uY3VycmVudFVzZXIgPSBBdXRoLmN1cnJlbnRVc2VyO1xuICAgICAgUHJvamVjdHNTZXJ2aWNlLnF1ZXJ5KHsgcHJvamVjdF9pZDogcHJvamVjdCB9KS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICB2bS5hY3R1YWxQcm9qZWN0ID0gcmVzcG9uc2VbMF07XG4gICAgICB9KTtcbiAgICAgIHZtLnF1ZXJ5RmlsdGVycyA9IHsgcHJvamVjdF9pZDogcHJvamVjdCB9O1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGFwcGx5RmlsdGVycyhkZWZhdWx0UXVlcnlGaWx0ZXJzKSB7XG4gICAgICByZXR1cm4gYW5ndWxhci5leHRlbmQoZGVmYXVsdFF1ZXJ5RmlsdGVycywgdm0ucXVlcnlGaWx0ZXJzKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBmaXhEYXRlKGRhdGVTdHJpbmcpIHtcbiAgICAgIHJldHVybiBtb21lbnQoZGF0ZVN0cmluZyk7XG4gICAgfVxuXG4gICAgdm0uZ29Ub1Byb2plY3QgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAkc3RhdGUuZ28oJ2FwcC5wcm9qZWN0cycsIHsgb2JqOiAnZWRpdCcsIHJlc291cmNlOiB2bS5hY3R1YWxQcm9qZWN0IH0pO1xuICAgIH07XG5cbiAgICB2bS50b3RhbENvc3QgPSBmdW5jdGlvbiAoKSB7XG4gICAgICB2YXIgZXN0aW1hdGVkX2Nvc3QgPSAwO1xuXG4gICAgICBpZiAodm0uYWN0dWFsUHJvamVjdC5ob3VyX3ZhbHVlX2ZpbmFsKSB7XG4gICAgICAgIHZtLmFjdHVhbFByb2plY3QudGFza3MuZm9yRWFjaChmdW5jdGlvbiAodGFzaykge1xuICAgICAgICAgIGlmICh0YXNrLmVzdGltYXRlZF90aW1lID4gMCkge1xuICAgICAgICAgICAgZXN0aW1hdGVkX2Nvc3QgKz0gcGFyc2VGbG9hdCh2bS5hY3R1YWxQcm9qZWN0LmhvdXJfdmFsdWVfZmluYWwpICogdGFzay5lc3RpbWF0ZWRfdGltZTtcbiAgICAgICAgICB9XG4gICAgICAgIH0pO1xuICAgICAgfVxuICAgICAgcmV0dXJuIGVzdGltYXRlZF9jb3N0LnRvTG9jYWxlU3RyaW5nKCdQdC1icicsIHsgbWluaW11bUZyYWN0aW9uRGlnaXRzOiAyIH0pO1xuICAgIH07XG5cbiAgICB2bS5maW5hbGl6ZVByb2plY3QgPSBmdW5jdGlvbiAoKSB7XG4gICAgICBQcm9qZWN0c1NlcnZpY2UudmVyaWZ5UmVsZWFzZXMoeyBwcm9qZWN0X2lkOiB2bS5hY3R1YWxQcm9qZWN0LmlkIH0pLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgIGlmIChyZXNwb25zZS5zdWNjZXNzKSB7XG4gICAgICAgICAgdmFyIGNvbmZpcm0gPSAkbWREaWFsb2cuY29uZmlybSgpLnRpdGxlKCdGaW5hbGl6YXIgUHJvamV0bycpLmh0bWxDb250ZW50KCdUZW0gY2VydGV6YSBxdWUgZGVzZWphIGZpbmFsaXphciBvIHByb2pldG8gJyArIHZtLmFjdHVhbFByb2plY3QubmFtZSArICc/PGJyIC8+IEFpbmRhIGV4aXN0ZW0gcmVsZWFzZXMgbsOjbyBmaW5hbGl6YWRhcy4nKS5vaygnU2ltJykuY2FuY2VsKCdOw6NvJyk7XG5cbiAgICAgICAgICAkbWREaWFsb2cuc2hvdyhjb25maXJtKS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIHZhciByZWFzb24gPSAkbWREaWFsb2cucHJvbXB0KCkudGl0bGUoJ0ZpbmFsaXphciBQcm9qZXRvJykudGV4dENvbnRlbnQoJ1F1YWwgbyBtb3Rpdm8gcGFyYSBhIGZpbmFsaXphw6fDo28gZG8gcHJvamV0bz8nKS5wbGFjZWhvbGRlcignTW90aXZvJykuaW5pdGlhbFZhbHVlKCcnKS5yZXF1aXJlZCh0cnVlKS5vaygnQ29uZmlybWFyJykuY2FuY2VsKCdDYW5jZWxhcicpO1xuXG4gICAgICAgICAgICAkbWREaWFsb2cuc2hvdyhyZWFzb24pLnRoZW4oZnVuY3Rpb24gKHJlYXNvblRleHQpIHtcbiAgICAgICAgICAgICAgUHJvamVjdHNTZXJ2aWNlLmZpbmFsaXplKHsgcHJvamVjdF9pZDogdm0uYWN0dWFsUHJvamVjdC5pZCwgcmVhc29uOiByZWFzb25UZXh0IH0pLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgIFByVG9hc3Quc3VjY2VzcygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnByb2plY3RFbmRlZFN1Y2Nlc3MnKSk7XG4gICAgICAgICAgICAgICAgb25BY3RpdmF0ZSgpO1xuICAgICAgICAgICAgICAgIHZtLnNlYXJjaCgpO1xuICAgICAgICAgICAgICB9LCBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgUHJUb2FzdC5FcnJvcigkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnByb2plY3RFbmRlZEVycm9yJykpO1xuICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICAgIH0pO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIHZhciBjb25maXJtID0gJG1kRGlhbG9nLmNvbmZpcm0oKS50aXRsZSgnRmluYWxpemFyIFByb2pldG8nKS50ZXh0Q29udGVudCgnVGVtIGNlcnRlemEgcXVlIGRlc2VqYSBmaW5hbGl6YXIgbyBwcm9qZXRvICcgKyB2bS5hY3R1YWxQcm9qZWN0Lm5hbWUgKyAnPycpLm9rKCdTaW0nKS5jYW5jZWwoJ07Do28nKTtcblxuICAgICAgICAgICRtZERpYWxvZy5zaG93KGNvbmZpcm0pLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgUHJvamVjdHNTZXJ2aWNlLmZpbmFsaXplKHsgcHJvamVjdF9pZDogdm0uYWN0dWFsUHJvamVjdC5pZCB9KS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgUHJUb2FzdC5zdWNjZXNzKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMucHJvamVjdEVuZGVkU3VjY2VzcycpKTtcbiAgICAgICAgICAgICAgb25BY3RpdmF0ZSgpO1xuICAgICAgICAgICAgICB2bS5zZWFyY2goKTtcbiAgICAgICAgICAgIH0sIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgUHJUb2FzdC5FcnJvcigkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnByb2plY3RFbmRlZEVycm9yJykpO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgfSk7XG4gICAgICAgIH1cbiAgICAgIH0pO1xuICAgIH07XG5cbiAgICAvLyBpbnN0YW50aWF0ZSBiYXNlIGNvbnRyb2xsZXJcbiAgICAkY29udHJvbGxlcignQ1JVRENvbnRyb2xsZXInLCB7IHZtOiB2bSwgbW9kZWxTZXJ2aWNlOiBEYXNoYm9hcmRzU2VydmljZSwgb3B0aW9uczoge30gfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqXG4gICAqIEFycXVpdm8gZGUgY29uZmlndXJhw6fDo28gY29tIGFzIHJvdGFzIGVzcGVjw61maWNhcyBkbyByZWN1cnNvIHByb2plY3RcbiAgICpcbiAgICogQHBhcmFtIHthbnl9ICRzdGF0ZVByb3ZpZGVyXG4gICAqIEBwYXJhbSB7YW55fSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnYXBwLmRhc2hib2FyZCcsIHtcbiAgICAgIHVybDogJy9kYXNoYm9hcmRzJyxcbiAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvZGFzaGJvYXJkL2Rhc2hib2FyZC5odG1sJyxcbiAgICAgIGNvbnRyb2xsZXI6ICdEYXNoYm9hcmRDb250cm9sbGVyIGFzIGRhc2hib2FyZEN0cmwnLFxuICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IHRydWUgfSxcbiAgICAgIG9iajogeyByZXNvdXJjZTogbnVsbCB9XG4gICAgfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmFjdG9yeSgnRGFzaGJvYXJkc1NlcnZpY2UnLCBEYXNoYm9hcmRzU2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiBEYXNoYm9hcmRzU2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHJldHVybiBzZXJ2aWNlRmFjdG9yeSgnZGFzaGJvYXJkcycsIHtcbiAgICAgIGFjdGlvbnM6IHt9LFxuICAgICAgaW5zdGFuY2U6IHt9XG4gICAgfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqXG4gICAqIEFycXVpdm8gZGUgY29uZmlndXJhw6fDo28gY29tIGFzIHJvdGFzIGVzcGVjw61maWNhcyBkbyByZWN1cnNvIHVzZXJcbiAgICpcbiAgICogQHBhcmFtIHthbnl9ICRzdGF0ZVByb3ZpZGVyXG4gICAqIEBwYXJhbSB7YW55fSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnYXBwLmRpbmFtaWMtcXVlcnknLCB7XG4gICAgICB1cmw6ICcvY29uc3VsdGFzLWRpbmFtaWNhcycsXG4gICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL2RpbmFtaWMtcXVlcnlzL2RpbmFtaWMtcXVlcnlzLmh0bWwnLFxuICAgICAgY29udHJvbGxlcjogJ0RpbmFtaWNRdWVyeXNDb250cm9sbGVyIGFzIGRpbmFtaWNRdWVyeUN0cmwnLFxuICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IHRydWUsIG5lZWRQcm9maWxlOiBbJ2FkbWluJ10gfVxuICAgIH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZhY3RvcnkoJ0RpbmFtaWNRdWVyeVNlcnZpY2UnLCBEaW5hbWljUXVlcnlTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIERpbmFtaWNRdWVyeVNlcnZpY2Uoc2VydmljZUZhY3RvcnkpIHtcbiAgICByZXR1cm4gc2VydmljZUZhY3RvcnkoJ2RpbmFtaWNRdWVyeScsIHtcbiAgICAgIC8qKlxuICAgICAgICogYcOnw6NvIGFkaWNpb25hZGEgcGFyYSBwZWdhciB1bWEgbGlzdGEgZGUgbW9kZWxzIGV4aXN0ZW50ZXMgbm8gc2Vydmlkb3JcbiAgICAgICAqL1xuICAgICAgYWN0aW9uczoge1xuICAgICAgICBnZXRNb2RlbHM6IHtcbiAgICAgICAgICBtZXRob2Q6ICdHRVQnLFxuICAgICAgICAgIHVybDogJ21vZGVscydcbiAgICAgICAgfVxuICAgICAgfSxcbiAgICAgIGluc3RhbmNlOiB7fVxuICAgIH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29udHJvbGxlcignRGluYW1pY1F1ZXJ5c0NvbnRyb2xsZXInLCBEaW5hbWljUXVlcnlzQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBEaW5hbWljUXVlcnlzQ29udHJvbGxlcigkY29udHJvbGxlciwgRGluYW1pY1F1ZXJ5U2VydmljZSwgbG9kYXNoLCBQclRvYXN0LCAvLyBOT1NPTkFSXG4gICR0cmFuc2xhdGUpIHtcblxuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICAvL2FjdGlvbnNcbiAgICB2bS5vbkFjdGl2YXRlID0gb25BY3RpdmF0ZTtcbiAgICB2bS5hcHBseUZpbHRlcnMgPSBhcHBseUZpbHRlcnM7XG4gICAgdm0ubG9hZEF0dHJpYnV0ZXMgPSBsb2FkQXR0cmlidXRlcztcbiAgICB2bS5sb2FkT3BlcmF0b3JzID0gbG9hZE9wZXJhdG9ycztcbiAgICB2bS5hZGRGaWx0ZXIgPSBhZGRGaWx0ZXI7XG4gICAgdm0uYWZ0ZXJTZWFyY2ggPSBhZnRlclNlYXJjaDtcbiAgICB2bS5ydW5GaWx0ZXIgPSBydW5GaWx0ZXI7XG4gICAgdm0uZWRpdEZpbHRlciA9IGVkaXRGaWx0ZXI7XG4gICAgdm0ubG9hZE1vZGVscyA9IGxvYWRNb2RlbHM7XG4gICAgdm0ucmVtb3ZlRmlsdGVyID0gcmVtb3ZlRmlsdGVyO1xuICAgIHZtLmNsZWFyID0gY2xlYXI7XG4gICAgdm0ucmVzdGFydCA9IHJlc3RhcnQ7XG5cbiAgICAvL2hlcmRhIG8gY29tcG9ydGFtZW50byBiYXNlIGRvIENSVURcbiAgICAkY29udHJvbGxlcignQ1JVRENvbnRyb2xsZXInLCB7IHZtOiB2bSwgbW9kZWxTZXJ2aWNlOiBEaW5hbWljUXVlcnlTZXJ2aWNlLCBvcHRpb25zOiB7XG4gICAgICAgIHNlYXJjaE9uSW5pdDogZmFsc2VcbiAgICAgIH0gfSk7XG5cbiAgICBmdW5jdGlvbiBvbkFjdGl2YXRlKCkge1xuICAgICAgdm0ucmVzdGFydCgpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFByZXBhcmEgZSBhcGxpY2Egb3MgZmlsdHJvIHF1ZSB2w6NvIHNlciBlbnZpYWRvcyBwYXJhIG8gc2VydmnDp29cbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSBkZWZhdWx0UXVlcnlGaWx0ZXJzXG4gICAgICogQHJldHVybnNcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBhcHBseUZpbHRlcnMoZGVmYXVsdFF1ZXJ5RmlsdGVycykge1xuICAgICAgdmFyIHdoZXJlID0ge307XG5cbiAgICAgIC8qKlxuICAgICAgICogbyBzZXJ2acOnbyBlc3BlcmEgdW0gb2JqZXRvIGNvbTpcbiAgICAgICAqICBvIG5vbWUgZGUgdW0gbW9kZWxcbiAgICAgICAqICB1bWEgbGlzdGEgZGUgZmlsdHJvc1xuICAgICAgICovXG4gICAgICBpZiAodm0uYWRkZWRGaWx0ZXJzLmxlbmd0aCA+IDApIHtcbiAgICAgICAgdmFyIGFkZGVkRmlsdGVycyA9IGFuZ3VsYXIuY29weSh2bS5hZGRlZEZpbHRlcnMpO1xuXG4gICAgICAgIHdoZXJlLm1vZGVsID0gdm0uYWRkZWRGaWx0ZXJzWzBdLm1vZGVsLm5hbWU7XG5cbiAgICAgICAgZm9yICh2YXIgaW5kZXggPSAwOyBpbmRleCA8IGFkZGVkRmlsdGVycy5sZW5ndGg7IGluZGV4KyspIHtcbiAgICAgICAgICB2YXIgZmlsdGVyID0gYWRkZWRGaWx0ZXJzW2luZGV4XTtcblxuICAgICAgICAgIGZpbHRlci5tb2RlbCA9IG51bGw7XG4gICAgICAgICAgZmlsdGVyLmF0dHJpYnV0ZSA9IGZpbHRlci5hdHRyaWJ1dGUubmFtZTtcbiAgICAgICAgICBmaWx0ZXIub3BlcmF0b3IgPSBmaWx0ZXIub3BlcmF0b3IudmFsdWU7XG4gICAgICAgIH1cblxuICAgICAgICB3aGVyZS5maWx0ZXJzID0gYW5ndWxhci50b0pzb24oYWRkZWRGaWx0ZXJzKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHdoZXJlLm1vZGVsID0gdm0ucXVlcnlGaWx0ZXJzLm1vZGVsLm5hbWU7XG4gICAgICB9XG5cbiAgICAgIHJldHVybiBhbmd1bGFyLmV4dGVuZChkZWZhdWx0UXVlcnlGaWx0ZXJzLCB3aGVyZSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ2FycmVnYSB0b2RvcyBvcyBtb2RlbHMgY3JpYWRvcyBubyBzZXJ2aWRvciBjb20gc2V1cyBhdHJpYnV0b3NcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBsb2FkTW9kZWxzKCkge1xuICAgICAgLy9QZWdhIHRvZG9zIG9zIG1vZGVscyBkbyBzZXJ2ZXIgZSBtb250YSB1bWEgbGlzdGEgcHJvIENvbWJvQm94XG4gICAgICBEaW5hbWljUXVlcnlTZXJ2aWNlLmdldE1vZGVscygpLnRoZW4oZnVuY3Rpb24gKGRhdGEpIHtcbiAgICAgICAgdm0ubW9kZWxzID0gZGF0YTtcbiAgICAgICAgdm0ucXVlcnlGaWx0ZXJzLm1vZGVsID0gdm0ubW9kZWxzWzBdO1xuICAgICAgICB2bS5sb2FkQXR0cmlidXRlcygpO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ2FycmVnYSBvcyBhdHRyaWJ1dG9zIGRvIG1vZGVsIGVzY29saGlkb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGxvYWRBdHRyaWJ1dGVzKCkge1xuICAgICAgdm0uYXR0cmlidXRlcyA9IHZtLnF1ZXJ5RmlsdGVycy5tb2RlbC5hdHRyaWJ1dGVzO1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzLmF0dHJpYnV0ZSA9IHZtLmF0dHJpYnV0ZXNbMF07XG5cbiAgICAgIHZtLmxvYWRPcGVyYXRvcnMoKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDYXJyZWdhIG9zIG9wZXJhZG9yZXMgZXNwZWNpZmljb3MgcGFyYSBvIHRpcG8gZG8gYXRyaWJ1dG9cbiAgICAgKi9cbiAgICBmdW5jdGlvbiBsb2FkT3BlcmF0b3JzKCkge1xuICAgICAgdmFyIG9wZXJhdG9ycyA9IFt7IHZhbHVlOiAnPScsIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLmVxdWFscycpIH0sIHsgdmFsdWU6ICc8PicsIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLmRpZmVyZW50JykgfV07XG5cbiAgICAgIGlmICh2bS5xdWVyeUZpbHRlcnMuYXR0cmlidXRlLnR5cGUuaW5kZXhPZigndmFyeWluZycpICE9PSAtMSkge1xuICAgICAgICBvcGVyYXRvcnMucHVzaCh7IHZhbHVlOiAnaGFzJyxcbiAgICAgICAgICBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KCd2aWV3cy5maWVsZHMucXVlcnlEaW5hbWljLm9wZXJhdG9ycy5jb250ZWlucycpIH0pO1xuICAgICAgICBvcGVyYXRvcnMucHVzaCh7IHZhbHVlOiAnc3RhcnRXaXRoJyxcbiAgICAgICAgICBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KCd2aWV3cy5maWVsZHMucXVlcnlEaW5hbWljLm9wZXJhdG9ycy5zdGFydFdpdGgnKSB9KTtcbiAgICAgICAgb3BlcmF0b3JzLnB1c2goeyB2YWx1ZTogJ2VuZFdpdGgnLFxuICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLmZpbmlzaFdpdGgnKSB9KTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIG9wZXJhdG9ycy5wdXNoKHsgdmFsdWU6ICc+JyxcbiAgICAgICAgICBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KCd2aWV3cy5maWVsZHMucXVlcnlEaW5hbWljLm9wZXJhdG9ycy5iaWdnZXJUaGFuJykgfSk7XG4gICAgICAgIG9wZXJhdG9ycy5wdXNoKHsgdmFsdWU6ICc+PScsXG4gICAgICAgICAgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudCgndmlld3MuZmllbGRzLnF1ZXJ5RGluYW1pYy5vcGVyYXRvcnMuZXF1YWxzT3JCaWdnZXJUaGFuJykgfSk7XG4gICAgICAgIG9wZXJhdG9ycy5wdXNoKHsgdmFsdWU6ICc8JyxcbiAgICAgICAgICBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KCd2aWV3cy5maWVsZHMucXVlcnlEaW5hbWljLm9wZXJhdG9ycy5sZXNzVGhhbicpIH0pO1xuICAgICAgICBvcGVyYXRvcnMucHVzaCh7IHZhbHVlOiAnPD0nLFxuICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLmVxdWFsc09yTGVzc1RoYW4nKSB9KTtcbiAgICAgIH1cblxuICAgICAgdm0ub3BlcmF0b3JzID0gb3BlcmF0b3JzO1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzLm9wZXJhdG9yID0gdm0ub3BlcmF0b3JzWzBdO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEFkaWNpb25hL2VkaXRhIHVtIGZpbHRyb1xuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IGZvcm0gZWxlbWVudG8gaHRtbCBkbyBmb3JtdWzDoXJpbyBwYXJhIHZhbGlkYcOnw7Vlc1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGFkZEZpbHRlcihmb3JtKSB7XG4gICAgICBpZiAoYW5ndWxhci5pc1VuZGVmaW5lZCh2bS5xdWVyeUZpbHRlcnMudmFsdWUpIHx8IHZtLnF1ZXJ5RmlsdGVycy52YWx1ZSA9PT0gJycpIHtcbiAgICAgICAgUHJUb2FzdC5lcnJvcigkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnZhbGlkYXRlLmZpZWxkUmVxdWlyZWQnLCB7IGZpZWxkOiAndmFsb3InIH0pKTtcbiAgICAgICAgcmV0dXJuO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgaWYgKHZtLmluZGV4IDwgMCkge1xuICAgICAgICAgIHZtLmFkZGVkRmlsdGVycy5wdXNoKGFuZ3VsYXIuY29weSh2bS5xdWVyeUZpbHRlcnMpKTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICB2bS5hZGRlZEZpbHRlcnNbdm0uaW5kZXhdID0gYW5ndWxhci5jb3B5KHZtLnF1ZXJ5RmlsdGVycyk7XG4gICAgICAgICAgdm0uaW5kZXggPSAtMTtcbiAgICAgICAgfVxuXG4gICAgICAgIC8vcmVpbmljaWEgbyBmb3JtdWzDoXJpbyBlIGFzIHZhbGlkYcOnw7VlcyBleGlzdGVudGVzXG4gICAgICAgIHZtLnF1ZXJ5RmlsdGVycyA9IHt9O1xuICAgICAgICBmb3JtLiRzZXRQcmlzdGluZSgpO1xuICAgICAgICBmb3JtLiRzZXRVbnRvdWNoZWQoKTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFsaXphIGEgcGVzcXVpc2EgdGVuZG8gb3MgZmlsdHJvcyBjb21vIHBhcsOibWV0cm9zXG4gICAgICovXG4gICAgZnVuY3Rpb24gcnVuRmlsdGVyKCkge1xuICAgICAgdm0uc2VhcmNoKHZtLnBhZ2luYXRvci5jdXJyZW50UGFnZSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogR2F0aWxobyBhY2lvbmFkbyBkZXBvaXMgZGEgcGVzcXVpc2EgcmVzcG9uc8OhdmVsIHBvciBpZGVudGlmaWNhciBvcyBhdHJpYnV0b3NcbiAgICAgKiBjb250aWRvcyBub3MgZWxlbWVudG9zIHJlc3VsdGFudGVzIGRhIGJ1c2NhXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gZGF0YSBkYWRvcyByZWZlcmVudGUgYW8gcmV0b3JubyBkYSByZXF1aXNpw6fDo29cbiAgICAgKi9cbiAgICBmdW5jdGlvbiBhZnRlclNlYXJjaChkYXRhKSB7XG4gICAgICB2YXIga2V5cyA9IGRhdGEuaXRlbXMubGVuZ3RoID4gMCA/IE9iamVjdC5rZXlzKGRhdGEuaXRlbXNbMF0pIDogW107XG5cbiAgICAgIC8vcmV0aXJhIHRvZG9zIG9zIGF0cmlidXRvcyBxdWUgY29tZcOnYW0gY29tICQuXG4gICAgICAvL0Vzc2VzIGF0cmlidXRvcyBzw6NvIGFkaWNpb25hZG9zIHBlbG8gc2VydmnDp28gZSBuw6NvIGRldmUgYXBhcmVjZXIgbmEgbGlzdGFnZW1cbiAgICAgIHZtLmtleXMgPSBsb2Rhc2guZmlsdGVyKGtleXMsIGZ1bmN0aW9uIChrZXkpIHtcbiAgICAgICAgcmV0dXJuICFsb2Rhc2guc3RhcnRzV2l0aChrZXksICckJyk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDb2xvYWNhIG5vIGZvcm11bMOhcmlvIG8gZmlsdHJvIGVzY29saGlkbyBwYXJhIGVkacOnw6NvXG4gICAgICogQHBhcmFtIHthbnl9ICRpbmRleCBpbmRpY2Ugbm8gYXJyYXkgZG8gZmlsdHJvIGVzY29saGlkb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGVkaXRGaWx0ZXIoJGluZGV4KSB7XG4gICAgICB2bS5pbmRleCA9ICRpbmRleDtcbiAgICAgIHZtLnF1ZXJ5RmlsdGVycyA9IHZtLmFkZGVkRmlsdGVyc1skaW5kZXhdO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlbW92ZSBvIGZpbHRybyBlc2NvbGhpZG9cbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSAkaW5kZXggaW5kaWNlIG5vIGFycmF5IGRvIGZpbHRybyBlc2NvbGhpZG9cbiAgICAgKi9cbiAgICBmdW5jdGlvbiByZW1vdmVGaWx0ZXIoJGluZGV4KSB7XG4gICAgICB2bS5hZGRlZEZpbHRlcnMuc3BsaWNlKCRpbmRleCk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogTGltcGEgbyBmb3JtdWzDoXJpbyBjb3JyZW50ZVxuICAgICAqL1xuICAgIGZ1bmN0aW9uIGNsZWFyKCkge1xuICAgICAgLy9ndWFyZGEgbyBpbmRpY2UgZG8gcmVnaXN0cm8gcXVlIGVzdMOhIHNlbmRvIGVkaXRhZG9cbiAgICAgIHZtLmluZGV4ID0gLTE7XG4gICAgICAvL3ZpbmN1bGFkbyBhb3MgY2FtcG9zIGRvIGZvcm11bMOhcmlvXG4gICAgICB2bS5xdWVyeUZpbHRlcnMgPSB7fTtcblxuICAgICAgaWYgKHZtLm1vZGVscykgdm0ucXVlcnlGaWx0ZXJzLm1vZGVsID0gdm0ubW9kZWxzWzBdO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlaW5pY2lhIGEgY29uc3RydcOnw6NvIGRhIHF1ZXJ5IGxpbXBhbmRvIHR1ZG9cbiAgICAgKlxuICAgICAqL1xuICAgIGZ1bmN0aW9uIHJlc3RhcnQoKSB7XG4gICAgICAvL2d1YXJkYSBhdHJpYnV0b3MgZG8gcmVzdWx0YWRvIGRhIGJ1c2NhIGNvcnJlbnRlXG4gICAgICB2bS5rZXlzID0gW107XG5cbiAgICAgIC8vZ3VhcmRhIG9zIGZpbHRyb3MgYWRpY2lvbmFkb3NcbiAgICAgIHZtLmFkZGVkRmlsdGVycyA9IFtdO1xuICAgICAgdm0uY2xlYXIoKTtcbiAgICAgIHZtLmxvYWRNb2RlbHMoKTtcbiAgICB9XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5mYWN0b3J5KCdsYW5ndWFnZUxvYWRlcicsIExhbmd1YWdlTG9hZGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIExhbmd1YWdlTG9hZGVyKCRxLCBTdXBwb3J0U2VydmljZSwgJGxvZywgJGluamVjdG9yKSB7XG4gICAgdmFyIHNlcnZpY2UgPSB0aGlzO1xuXG4gICAgc2VydmljZS50cmFuc2xhdGUgPSBmdW5jdGlvbiAobG9jYWxlKSB7XG4gICAgICByZXR1cm4ge1xuICAgICAgICBnbG9iYWw6ICRpbmplY3Rvci5nZXQobG9jYWxlICsgJy5pMThuLmdsb2JhbCcpLFxuICAgICAgICB2aWV3czogJGluamVjdG9yLmdldChsb2NhbGUgKyAnLmkxOG4udmlld3MnKSxcbiAgICAgICAgYXR0cmlidXRlczogJGluamVjdG9yLmdldChsb2NhbGUgKyAnLmkxOG4uYXR0cmlidXRlcycpLFxuICAgICAgICBkaWFsb2c6ICRpbmplY3Rvci5nZXQobG9jYWxlICsgJy5pMThuLmRpYWxvZycpLFxuICAgICAgICBtZXNzYWdlczogJGluamVjdG9yLmdldChsb2NhbGUgKyAnLmkxOG4ubWVzc2FnZXMnKSxcbiAgICAgICAgbW9kZWxzOiAkaW5qZWN0b3IuZ2V0KGxvY2FsZSArICcuaTE4bi5tb2RlbHMnKVxuICAgICAgfTtcbiAgICB9O1xuXG4gICAgLy8gcmV0dXJuIGxvYWRlckZuXG4gICAgcmV0dXJuIGZ1bmN0aW9uIChvcHRpb25zKSB7XG4gICAgICAkbG9nLmluZm8oJ0NhcnJlZ2FuZG8gbyBjb250ZXVkbyBkYSBsaW5ndWFnZW0gJyArIG9wdGlvbnMua2V5KTtcblxuICAgICAgdmFyIGRlZmVycmVkID0gJHEuZGVmZXIoKTtcblxuICAgICAgLy9DYXJyZWdhIGFzIGxhbmdzIHF1ZSBwcmVjaXNhbSBlIGVzdMOjbyBubyBzZXJ2aWRvciBwYXJhIG7Do28gcHJlY2lzYXIgcmVwZXRpciBhcXVpXG4gICAgICBTdXBwb3J0U2VydmljZS5sYW5ncygpLnRoZW4oZnVuY3Rpb24gKGxhbmdzKSB7XG4gICAgICAgIC8vTWVyZ2UgY29tIG9zIGxhbmdzIGRlZmluaWRvcyBubyBzZXJ2aWRvclxuICAgICAgICB2YXIgZGF0YSA9IGFuZ3VsYXIubWVyZ2Uoc2VydmljZS50cmFuc2xhdGUob3B0aW9ucy5rZXkpLCBsYW5ncyk7XG5cbiAgICAgICAgcmV0dXJuIGRlZmVycmVkLnJlc29sdmUoZGF0YSk7XG4gICAgICB9LCBmdW5jdGlvbiAoKSB7XG4gICAgICAgIHJldHVybiBkZWZlcnJlZC5yZXNvbHZlKHNlcnZpY2UudHJhbnNsYXRlKG9wdGlvbnMua2V5KSk7XG4gICAgICB9KTtcblxuICAgICAgcmV0dXJuIGRlZmVycmVkLnByb21pc2U7XG4gICAgfTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZpbHRlcigndEF0dHInLCB0QXR0cik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiB0QXR0cigkZmlsdGVyKSB7XG4gICAgLyoqXG4gICAgICogRmlsdHJvIHBhcmEgdHJhZHXDp8OjbyBkZSB1bSBhdHJpYnV0byBkZSB1bSBtb2RlbFxuICAgICAqIFxuICAgICAqIEBwYXJhbSB7YW55fSBuYW1lIG5vbWUgZG8gYXRyaWJ1dG9cbiAgICAgKiBAcmV0dXJucyBvIG5vbWUgZG8gYXRyaWJ1dG8gdHJhZHV6aWRvIGNhc28gZW5jb250cmUgc2UgbsOjbyBvIG5vbWUgcGFzc2FkbyBwb3IgcGFyYW1ldHJvXG4gICAgICovXG4gICAgcmV0dXJuIGZ1bmN0aW9uIChuYW1lKSB7XG4gICAgICB2YXIga2V5ID0gJ2F0dHJpYnV0ZXMuJyArIG5hbWU7XG4gICAgICB2YXIgdHJhbnNsYXRlID0gJGZpbHRlcigndHJhbnNsYXRlJykoa2V5KTtcblxuICAgICAgcmV0dXJuIHRyYW5zbGF0ZSA9PT0ga2V5ID8gbmFtZSA6IHRyYW5zbGF0ZTtcbiAgICB9O1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmlsdGVyKCd0QnJlYWRjcnVtYicsIHRCcmVhZGNydW1iKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIHRCcmVhZGNydW1iKCRmaWx0ZXIpIHtcbiAgICAvKipcbiAgICAgKiBGaWx0cm8gcGFyYSB0cmFkdcOnw6NvIGRvIGJyZWFkY3J1bWIgKHRpdHVsbyBkYSB0ZWxhIGNvbSByYXN0cmVpbylcbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSBpZCBjaGF2ZSBjb20gbyBub21lIGRvIHN0YXRlIHJlZmVyZW50ZSB0ZWxhXG4gICAgICogQHJldHVybnMgYSB0cmFkdcOnw6NvIGNhc28gZW5jb250cmUgc2UgbsOjbyBvIGlkIHBhc3NhZG8gcG9yIHBhcmFtZXRyb1xuICAgICAqL1xuICAgIHJldHVybiBmdW5jdGlvbiAoaWQpIHtcbiAgICAgIC8vcGVnYSBhIHNlZ3VuZGEgcGFydGUgZG8gbm9tZSBkbyBzdGF0ZSwgcmV0aXJhbmRvIGEgcGFydGUgYWJzdHJhdGEgKGFwcC4pXG4gICAgICB2YXIga2V5ID0gJ3ZpZXdzLmJyZWFkY3J1bWJzLicgKyBpZC5zcGxpdCgnLicpWzFdO1xuICAgICAgdmFyIHRyYW5zbGF0ZSA9ICRmaWx0ZXIoJ3RyYW5zbGF0ZScpKGtleSk7XG5cbiAgICAgIHJldHVybiB0cmFuc2xhdGUgPT09IGtleSA/IGlkIDogdHJhbnNsYXRlO1xuICAgIH07XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5maWx0ZXIoJ3RNb2RlbCcsIHRNb2RlbCk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiB0TW9kZWwoJGZpbHRlcikge1xuICAgIC8qKlxuICAgICAqIEZpbHRybyBwYXJhIHRyYWR1w6fDo28gZGUgdW0gYXRyaWJ1dG8gZGUgdW0gbW9kZWxcbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSBuYW1lIG5vbWUgZG8gYXRyaWJ1dG9cbiAgICAgKiBAcmV0dXJucyBvIG5vbWUgZG8gYXRyaWJ1dG8gdHJhZHV6aWRvIGNhc28gZW5jb250cmUgc2UgbsOjbyBvIG5vbWUgcGFzc2FkbyBwb3IgcGFyYW1ldHJvXG4gICAgICovXG4gICAgcmV0dXJuIGZ1bmN0aW9uIChuYW1lKSB7XG4gICAgICB2YXIga2V5ID0gJ21vZGVscy4nICsgbmFtZS50b0xvd2VyQ2FzZSgpO1xuICAgICAgdmFyIHRyYW5zbGF0ZSA9ICRmaWx0ZXIoJ3RyYW5zbGF0ZScpKGtleSk7XG5cbiAgICAgIHJldHVybiB0cmFuc2xhdGUgPT09IGtleSA/IG5hbWUgOiB0cmFuc2xhdGU7XG4gICAgfTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5ydW4oYXV0aGVudGljYXRpb25MaXN0ZW5lcik7XG5cbiAgLyoqXG4gICAqIExpc3RlbiBhbGwgc3RhdGUgKHBhZ2UpIGNoYW5nZXMuIEV2ZXJ5IHRpbWUgYSBzdGF0ZSBjaGFuZ2UgbmVlZCB0byB2ZXJpZnkgdGhlIHVzZXIgaXMgYXV0aGVudGljYXRlZCBvciBub3QgdG9cbiAgICogcmVkaXJlY3QgdG8gY29ycmVjdCBwYWdlLiBXaGVuIGEgdXNlciBjbG9zZSB0aGUgYnJvd3NlciB3aXRob3V0IGxvZ291dCwgd2hlbiBoaW0gcmVvcGVuIHRoZSBicm93c2VyIHRoaXMgZXZlbnRcbiAgICogcmVhdXRoZW50aWNhdGUgdGhlIHVzZXIgd2l0aCB0aGUgcGVyc2lzdGVudCB0b2tlbiBvZiB0aGUgbG9jYWwgc3RvcmFnZS5cbiAgICpcbiAgICogV2UgZG9uJ3QgY2hlY2sgaWYgdGhlIHRva2VuIGlzIGV4cGlyZWQgb3Igbm90IGluIHRoZSBwYWdlIGNoYW5nZSwgYmVjYXVzZSBpcyBnZW5lcmF0ZSBhbiB1bmVjZXNzYXJ5IG92ZXJoZWFkLlxuICAgKiBJZiB0aGUgdG9rZW4gaXMgZXhwaXJlZCB3aGVuIHRoZSB1c2VyIHRyeSB0byBjYWxsIHRoZSBmaXJzdCBhcGkgdG8gZ2V0IGRhdGEsIGhpbSB3aWxsIGJlIGxvZ29mZiBhbmQgcmVkaXJlY3RcbiAgICogdG8gbG9naW4gcGFnZS5cbiAgICpcbiAgICogQHBhcmFtICRyb290U2NvcGVcbiAgICogQHBhcmFtICRzdGF0ZVxuICAgKiBAcGFyYW0gJHN0YXRlUGFyYW1zXG4gICAqIEBwYXJhbSBBdXRoXG4gICAqL1xuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIGF1dGhlbnRpY2F0aW9uTGlzdGVuZXIoJHJvb3RTY29wZSwgJHN0YXRlLCBHbG9iYWwsIEF1dGgsIFByVG9hc3QsIC8vIE5PU09OQVJcbiAgJHRyYW5zbGF0ZSkge1xuXG4gICAgLy9vbmx5IHdoZW4gYXBwbGljYXRpb24gc3RhcnQgY2hlY2sgaWYgdGhlIGV4aXN0ZW50IHRva2VuIHN0aWxsIHZhbGlkXG4gICAgQXV0aC5yZW1vdGVWYWxpZGF0ZVRva2VuKCkudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAvL2lmIHRoZSB0b2tlbiBpcyB2YWxpZCBjaGVjayBpZiBleGlzdHMgdGhlIHVzZXIgYmVjYXVzZSB0aGUgYnJvd3NlciBjb3VsZCBiZSBjbG9zZWRcbiAgICAgIC8vYW5kIHRoZSB1c2VyIGRhdGEgaXNuJ3QgaW4gbWVtb3J5XG4gICAgICBpZiAoQXV0aC5jdXJyZW50VXNlciA9PT0gbnVsbCkge1xuICAgICAgICBBdXRoLnVwZGF0ZUN1cnJlbnRVc2VyKGFuZ3VsYXIuZnJvbUpzb24obG9jYWxTdG9yYWdlLmdldEl0ZW0oJ3VzZXInKSkpO1xuICAgICAgfVxuICAgIH0pO1xuXG4gICAgLy9DaGVjayBpZiB0aGUgdG9rZW4gc3RpbGwgdmFsaWQuXG4gICAgJHJvb3RTY29wZS4kb24oJyRzdGF0ZUNoYW5nZVN0YXJ0JywgZnVuY3Rpb24gKGV2ZW50LCB0b1N0YXRlKSB7XG4gICAgICBpZiAodG9TdGF0ZS5kYXRhLm5lZWRBdXRoZW50aWNhdGlvbiB8fCB0b1N0YXRlLmRhdGEubmVlZFByb2ZpbGUpIHtcbiAgICAgICAgLy9kb250IHRyYWl0IHRoZSBzdWNjZXNzIGJsb2NrIGJlY2F1c2UgYWxyZWFkeSBkaWQgYnkgdG9rZW4gaW50ZXJjZXB0b3JcbiAgICAgICAgQXV0aC5yZW1vdGVWYWxpZGF0ZVRva2VuKCkuY2F0Y2goZnVuY3Rpb24gKCkge1xuICAgICAgICAgIFByVG9hc3Qud2FybigkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLmxvZ2luLmxvZ291dEluYWN0aXZlJykpO1xuXG4gICAgICAgICAgaWYgKHRvU3RhdGUubmFtZSAhPT0gR2xvYmFsLmxvZ2luU3RhdGUpIHtcbiAgICAgICAgICAgICRzdGF0ZS5nbyhHbG9iYWwubG9naW5TdGF0ZSk7XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgZXZlbnQucHJldmVudERlZmF1bHQoKTtcbiAgICAgICAgfSk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICAvL2lmIHRoZSB1c2UgaXMgYXV0aGVudGljYXRlZCBhbmQgbmVlZCB0byBlbnRlciBpbiBsb2dpbiBwYWdlXG4gICAgICAgIC8vaGltIHdpbGwgYmUgcmVkaXJlY3RlZCB0byBob21lIHBhZ2VcbiAgICAgICAgaWYgKHRvU3RhdGUubmFtZSA9PT0gR2xvYmFsLmxvZ2luU3RhdGUgJiYgQXV0aC5hdXRoZW50aWNhdGVkKCkpIHtcbiAgICAgICAgICAkc3RhdGUuZ28oR2xvYmFsLmhvbWVTdGF0ZSk7XG4gICAgICAgICAgZXZlbnQucHJldmVudERlZmF1bHQoKTtcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLnJ1bihhdXRob3JpemF0aW9uTGlzdGVuZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gYXV0aG9yaXphdGlvbkxpc3RlbmVyKCRyb290U2NvcGUsICRzdGF0ZSwgR2xvYmFsLCBBdXRoKSB7XG4gICAgLyoqXG4gICAgICogQSBjYWRhIG11ZGFuw6dhIGRlIGVzdGFkbyAoXCJww6FnaW5hXCIpIHZlcmlmaWNhIHNlIG8gdXN1w6FyaW8gdGVtIG8gcGVyZmlsXG4gICAgICogbmVjZXNzw6FyaW8gcGFyYSBvIGFjZXNzbyBhIG1lc21hXG4gICAgICovXG4gICAgJHJvb3RTY29wZS4kb24oJyRzdGF0ZUNoYW5nZVN0YXJ0JywgZnVuY3Rpb24gKGV2ZW50LCB0b1N0YXRlKSB7XG4gICAgICBpZiAodG9TdGF0ZS5kYXRhICYmIHRvU3RhdGUuZGF0YS5uZWVkQXV0aGVudGljYXRpb24gJiYgdG9TdGF0ZS5kYXRhLm5lZWRQcm9maWxlICYmIEF1dGguYXV0aGVudGljYXRlZCgpICYmICFBdXRoLmN1cnJlbnRVc2VyLmhhc1Byb2ZpbGUodG9TdGF0ZS5kYXRhLm5lZWRQcm9maWxlLCB0b1N0YXRlLmRhdGEuYWxsUHJvZmlsZXMpKSB7XG5cbiAgICAgICAgJHN0YXRlLmdvKEdsb2JhbC5ub3RBdXRob3JpemVkU3RhdGUpO1xuICAgICAgICBldmVudC5wcmV2ZW50RGVmYXVsdCgpO1xuICAgICAgfVxuICAgIH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbmZpZyhzcGlubmVySW50ZXJjZXB0b3IpO1xuXG4gIGZ1bmN0aW9uIHNwaW5uZXJJbnRlcmNlcHRvcigkaHR0cFByb3ZpZGVyLCAkcHJvdmlkZSkge1xuICAgIC8qKlxuICAgICAqIEVzdGUgaW50ZXJjZXB0b3Igw6kgcmVzcG9uc8OhdmVsIHBvciBtb3N0cmFyIGUgZXNjb25kZXIgb1xuICAgICAqIGNvbXBvbmVudGUgUHJTcGlubmVyIHNlbXByZSBxdWUgdW1hIHJlcXVpc2nDp8OjbyBhamF4XG4gICAgICogaW5pY2lhciBlIGZpbmFsaXphci5cbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSAkcVxuICAgICAqIEBwYXJhbSB7YW55fSAkaW5qZWN0b3JcbiAgICAgKiBAcmV0dXJuc1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIHNob3dIaWRlU3Bpbm5lcigkcSwgJGluamVjdG9yKSB7XG4gICAgICByZXR1cm4ge1xuICAgICAgICByZXF1ZXN0OiBmdW5jdGlvbiByZXF1ZXN0KGNvbmZpZykge1xuICAgICAgICAgICRpbmplY3Rvci5nZXQoJ1ByU3Bpbm5lcicpLnNob3coKTtcblxuICAgICAgICAgIHJldHVybiBjb25maWc7XG4gICAgICAgIH0sXG5cbiAgICAgICAgcmVzcG9uc2U6IGZ1bmN0aW9uIHJlc3BvbnNlKF9yZXNwb25zZSkge1xuICAgICAgICAgICRpbmplY3Rvci5nZXQoJ1ByU3Bpbm5lcicpLmhpZGUoKTtcblxuICAgICAgICAgIHJldHVybiBfcmVzcG9uc2U7XG4gICAgICAgIH0sXG5cbiAgICAgICAgcmVzcG9uc2VFcnJvcjogZnVuY3Rpb24gcmVzcG9uc2VFcnJvcihyZWplY3Rpb24pIHtcbiAgICAgICAgICAkaW5qZWN0b3IuZ2V0KCdQclNwaW5uZXInKS5oaWRlKCk7XG5cbiAgICAgICAgICByZXR1cm4gJHEucmVqZWN0KHJlamVjdGlvbik7XG4gICAgICAgIH1cbiAgICAgIH07XG4gICAgfVxuXG4gICAgLy8gRGVmaW5lIHVtYSBmYWN0b3J5IHBhcmEgbyAkaHR0cEludGVyY2VwdG9yXG4gICAgJHByb3ZpZGUuZmFjdG9yeSgnc2hvd0hpZGVTcGlubmVyJywgc2hvd0hpZGVTcGlubmVyKTtcblxuICAgIC8vIEFkaWNpb25hIGEgZmFjdG9yeSBubyBhcnJheSBkZSBpbnRlcmNlcHRvcnMgZG8gJGh0dHBcbiAgICAkaHR0cFByb3ZpZGVyLmludGVyY2VwdG9ycy5wdXNoKCdzaG93SGlkZVNwaW5uZXInKTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuLyplc2xpbnQgYW5ndWxhci9tb2R1bGUtZ2V0dGVyOiAwKi9cblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25maWcodG9rZW5JbnRlcmNlcHRvcik7XG5cbiAgLyoqXG4gICAqIEludGVyY2VwdCBhbGwgcmVzcG9uc2UgKHN1Y2Nlc3Mgb3IgZXJyb3IpIHRvIHZlcmlmeSB0aGUgcmV0dXJuZWQgdG9rZW5cbiAgICpcbiAgICogQHBhcmFtICRodHRwUHJvdmlkZXJcbiAgICogQHBhcmFtICRwcm92aWRlXG4gICAqIEBwYXJhbSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gdG9rZW5JbnRlcmNlcHRvcigkaHR0cFByb3ZpZGVyLCAkcHJvdmlkZSwgR2xvYmFsKSB7XG5cbiAgICBmdW5jdGlvbiByZWRpcmVjdFdoZW5TZXJ2ZXJMb2dnZWRPdXQoJHEsICRpbmplY3Rvcikge1xuICAgICAgcmV0dXJuIHtcbiAgICAgICAgcmVxdWVzdDogZnVuY3Rpb24gcmVxdWVzdChjb25maWcpIHtcbiAgICAgICAgICB2YXIgdG9rZW4gPSAkaW5qZWN0b3IuZ2V0KCdBdXRoJykuZ2V0VG9rZW4oKTtcblxuICAgICAgICAgIGlmICh0b2tlbikge1xuICAgICAgICAgICAgY29uZmlnLmhlYWRlcnNbJ0F1dGhvcml6YXRpb24nXSA9ICdCZWFyZXIgJyArIHRva2VuO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIHJldHVybiBjb25maWc7XG4gICAgICAgIH0sXG4gICAgICAgIHJlc3BvbnNlOiBmdW5jdGlvbiByZXNwb25zZShfcmVzcG9uc2UpIHtcbiAgICAgICAgICAvLyBnZXQgYSBuZXcgcmVmcmVzaCB0b2tlbiB0byB1c2UgaW4gdGhlIG5leHQgcmVxdWVzdFxuICAgICAgICAgIHZhciB0b2tlbiA9IF9yZXNwb25zZS5oZWFkZXJzKCdBdXRob3JpemF0aW9uJyk7XG5cbiAgICAgICAgICBpZiAodG9rZW4pIHtcbiAgICAgICAgICAgICRpbmplY3Rvci5nZXQoJ0F1dGgnKS5zZXRUb2tlbih0b2tlbi5zcGxpdCgnICcpWzFdKTtcbiAgICAgICAgICB9XG4gICAgICAgICAgcmV0dXJuIF9yZXNwb25zZTtcbiAgICAgICAgfSxcbiAgICAgICAgcmVzcG9uc2VFcnJvcjogZnVuY3Rpb24gcmVzcG9uc2VFcnJvcihyZWplY3Rpb24pIHtcbiAgICAgICAgICAvLyBJbnN0ZWFkIG9mIGNoZWNraW5nIGZvciBhIHN0YXR1cyBjb2RlIG9mIDQwMCB3aGljaCBtaWdodCBiZSB1c2VkXG4gICAgICAgICAgLy8gZm9yIG90aGVyIHJlYXNvbnMgaW4gTGFyYXZlbCwgd2UgY2hlY2sgZm9yIHRoZSBzcGVjaWZpYyByZWplY3Rpb25cbiAgICAgICAgICAvLyByZWFzb25zIHRvIHRlbGwgdXMgaWYgd2UgbmVlZCB0byByZWRpcmVjdCB0byB0aGUgbG9naW4gc3RhdGVcbiAgICAgICAgICB2YXIgcmVqZWN0aW9uUmVhc29ucyA9IFsndG9rZW5fbm90X3Byb3ZpZGVkJywgJ3Rva2VuX2V4cGlyZWQnLCAndG9rZW5fYWJzZW50JywgJ3Rva2VuX2ludmFsaWQnXTtcblxuICAgICAgICAgIHZhciB0b2tlbkVycm9yID0gZmFsc2U7XG5cbiAgICAgICAgICBhbmd1bGFyLmZvckVhY2gocmVqZWN0aW9uUmVhc29ucywgZnVuY3Rpb24gKHZhbHVlKSB7XG4gICAgICAgICAgICBpZiAocmVqZWN0aW9uLmRhdGEgJiYgcmVqZWN0aW9uLmRhdGEuZXJyb3IgPT09IHZhbHVlKSB7XG4gICAgICAgICAgICAgIHRva2VuRXJyb3IgPSB0cnVlO1xuXG4gICAgICAgICAgICAgICRpbmplY3Rvci5nZXQoJ0F1dGgnKS5sb2dvdXQoKS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICB2YXIgJHN0YXRlID0gJGluamVjdG9yLmdldCgnJHN0YXRlJyk7XG5cbiAgICAgICAgICAgICAgICAvLyBpbiBjYXNlIG11bHRpcGxlIGFqYXggcmVxdWVzdCBmYWlsIGF0IHNhbWUgdGltZSBiZWNhdXNlIHRva2VuIHByb2JsZW1zLFxuICAgICAgICAgICAgICAgIC8vIG9ubHkgdGhlIGZpcnN0IHdpbGwgcmVkaXJlY3RcbiAgICAgICAgICAgICAgICBpZiAoISRzdGF0ZS5pcyhHbG9iYWwubG9naW5TdGF0ZSkpIHtcbiAgICAgICAgICAgICAgICAgICRzdGF0ZS5nbyhHbG9iYWwubG9naW5TdGF0ZSk7XG5cbiAgICAgICAgICAgICAgICAgIC8vY2xvc2UgYW55IGRpYWxvZyB0aGF0IGlzIG9wZW5lZFxuICAgICAgICAgICAgICAgICAgJGluamVjdG9yLmdldCgnUHJEaWFsb2cnKS5jbG9zZSgpO1xuXG4gICAgICAgICAgICAgICAgICBldmVudC5wcmV2ZW50RGVmYXVsdCgpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfSk7XG5cbiAgICAgICAgICAvL2RlZmluZSBkYXRhIHRvIGVtcHR5IGJlY2F1c2UgYWxyZWFkeSBzaG93IFByVG9hc3QgdG9rZW4gbWVzc2FnZVxuICAgICAgICAgIGlmICh0b2tlbkVycm9yKSB7XG4gICAgICAgICAgICByZWplY3Rpb24uZGF0YSA9IHt9O1xuICAgICAgICAgIH1cblxuICAgICAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24ocmVqZWN0aW9uLmhlYWRlcnMpKSB7XG4gICAgICAgICAgICAvLyBtYW55IHNlcnZlcnMgZXJyb3JzIChidXNpbmVzcykgYXJlIGludGVyY2VwdCBoZXJlIGJ1dCBnZW5lcmF0ZWQgYSBuZXcgcmVmcmVzaCB0b2tlblxuICAgICAgICAgICAgLy8gYW5kIG5lZWQgdXBkYXRlIGN1cnJlbnQgdG9rZW5cbiAgICAgICAgICAgIHZhciB0b2tlbiA9IHJlamVjdGlvbi5oZWFkZXJzKCdBdXRob3JpemF0aW9uJyk7XG5cbiAgICAgICAgICAgIGlmICh0b2tlbikge1xuICAgICAgICAgICAgICAkaW5qZWN0b3IuZ2V0KCdBdXRoJykuc2V0VG9rZW4odG9rZW4uc3BsaXQoJyAnKVsxXSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgcmV0dXJuICRxLnJlamVjdChyZWplY3Rpb24pO1xuICAgICAgICB9XG4gICAgICB9O1xuICAgIH1cblxuICAgIC8vIFNldHVwIGZvciB0aGUgJGh0dHBJbnRlcmNlcHRvclxuICAgICRwcm92aWRlLmZhY3RvcnkoJ3JlZGlyZWN0V2hlblNlcnZlckxvZ2dlZE91dCcsIHJlZGlyZWN0V2hlblNlcnZlckxvZ2dlZE91dCk7XG5cbiAgICAvLyBQdXNoIHRoZSBuZXcgZmFjdG9yeSBvbnRvIHRoZSAkaHR0cCBpbnRlcmNlcHRvciBhcnJheVxuICAgICRodHRwUHJvdmlkZXIuaW50ZXJjZXB0b3JzLnB1c2goJ3JlZGlyZWN0V2hlblNlcnZlckxvZ2dlZE91dCcpO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbmZpZyh2YWxpZGF0aW9uSW50ZXJjZXB0b3IpO1xuXG4gIGZ1bmN0aW9uIHZhbGlkYXRpb25JbnRlcmNlcHRvcigkaHR0cFByb3ZpZGVyLCAkcHJvdmlkZSkge1xuICAgIC8qKlxuICAgICAqIEVzdGUgaW50ZXJjZXB0b3Igw6kgcmVzcG9uc8OhdmVsIHBvciBtb3N0cmFyIGFzXG4gICAgICogbWVuc2FnZW5zIGRlIGVycm8gcmVmZXJlbnRlIGFzIHZhbGlkYcOnw7VlcyBkbyBiYWNrLWVuZFxuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9ICRxXG4gICAgICogQHBhcmFtIHthbnl9ICRpbmplY3RvclxuICAgICAqIEByZXR1cm5zXG4gICAgICovXG4gICAgZnVuY3Rpb24gc2hvd0Vycm9yVmFsaWRhdGlvbigkcSwgJGluamVjdG9yKSB7XG4gICAgICByZXR1cm4ge1xuICAgICAgICByZXNwb25zZUVycm9yOiBmdW5jdGlvbiByZXNwb25zZUVycm9yKHJlamVjdGlvbikge1xuICAgICAgICAgIHZhciBQclRvYXN0ID0gJGluamVjdG9yLmdldCgnUHJUb2FzdCcpO1xuICAgICAgICAgIHZhciAkdHJhbnNsYXRlID0gJGluamVjdG9yLmdldCgnJHRyYW5zbGF0ZScpO1xuXG4gICAgICAgICAgaWYgKHJlamVjdGlvbi5jb25maWcuZGF0YSAmJiAhcmVqZWN0aW9uLmNvbmZpZy5kYXRhLnNraXBWYWxpZGF0aW9uKSB7XG4gICAgICAgICAgICBpZiAocmVqZWN0aW9uLmRhdGEgJiYgcmVqZWN0aW9uLmRhdGEuZXJyb3IpIHtcblxuICAgICAgICAgICAgICAvL3ZlcmlmaWNhIHNlIG9jb3JyZXUgYWxndW0gZXJybyByZWZlcmVudGUgYW8gdG9rZW5cbiAgICAgICAgICAgICAgaWYgKHJlamVjdGlvbi5kYXRhLmVycm9yLnN0YXJ0c1dpdGgoJ3Rva2VuXycpKSB7XG4gICAgICAgICAgICAgICAgUHJUb2FzdC53YXJuKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMubG9naW4ubG9nb3V0SW5hY3RpdmUnKSk7XG4gICAgICAgICAgICAgIH0gZWxzZSBpZiAocmVqZWN0aW9uLmRhdGEuZXJyb3IgIT09ICdOb3QgRm91bmQnKSB7XG4gICAgICAgICAgICAgICAgUHJUb2FzdC5lcnJvcigkdHJhbnNsYXRlLmluc3RhbnQocmVqZWN0aW9uLmRhdGEuZXJyb3IpKTtcbiAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgUHJUb2FzdC5lcnJvclZhbGlkYXRpb24ocmVqZWN0aW9uLmRhdGEpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgIH1cblxuICAgICAgICAgIHJldHVybiAkcS5yZWplY3QocmVqZWN0aW9uKTtcbiAgICAgICAgfVxuICAgICAgfTtcbiAgICB9XG5cbiAgICAvLyBEZWZpbmUgdW1hIGZhY3RvcnkgcGFyYSBvICRodHRwSW50ZXJjZXB0b3JcbiAgICAkcHJvdmlkZS5mYWN0b3J5KCdzaG93RXJyb3JWYWxpZGF0aW9uJywgc2hvd0Vycm9yVmFsaWRhdGlvbik7XG5cbiAgICAvLyBBZGljaW9uYSBhIGZhY3Rvcnkgbm8gYXJyYXkgZGUgaW50ZXJjZXB0b3JzIGRvICRodHRwXG4gICAgJGh0dHBQcm92aWRlci5pbnRlcmNlcHRvcnMucHVzaCgnc2hvd0Vycm9yVmFsaWRhdGlvbicpO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29udHJvbGxlcignS2FuYmFuQ29udHJvbGxlcicsIEthbmJhbkNvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gS2FuYmFuQ29udHJvbGxlcigkY29udHJvbGxlciwgVGFza3NTZXJ2aWNlLCBTdGF0dXNTZXJ2aWNlLCBQclRvYXN0LCAkbWREaWFsb2csICRkb2N1bWVudCwgQXV0aCwgUHJvamVjdHNTZXJ2aWNlKSB7XG4gICAgLy9BdHRyaWJ1dGVzIEJsb2NrXG4gICAgdmFyIHZtID0gdGhpcztcbiAgICB2YXIgZmllbGRzID0gW3sgbmFtZTogJ2lkJywgdHlwZTogJ3N0cmluZycgfSwgeyBuYW1lOiAnc3RhdHVzJywgbWFwOiAnc3RhdGUnLCB0eXBlOiAnc3RyaW5nJyB9LCB7IG5hbWU6ICd0ZXh0JywgbWFwOiAnbGFiZWwnLCB0eXBlOiAnc3RyaW5nJyB9LCB7IG5hbWU6ICd0YWdzJywgdHlwZTogJ3N0cmluZycgfV07XG5cbiAgICB2bS5vbkFjdGl2YXRlID0gZnVuY3Rpb24gKCkge1xuICAgICAgdm0ucHJvamVjdCA9IGxvY2FsU3RvcmFnZS5nZXRJdGVtKCdwcm9qZWN0Jyk7XG4gICAgICBQcm9qZWN0c1NlcnZpY2UucXVlcnkoeyBwcm9qZWN0X2lkOiB2bS5wcm9qZWN0IH0pLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgIHZtLmFjdHVhbFByb2plY3QgPSByZXNwb25zZVswXTtcbiAgICAgIH0pO1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0geyBwcm9qZWN0X2lkOiB2bS5wcm9qZWN0IH07XG4gICAgICB2bS5pc01vdmVkID0gZmFsc2U7XG4gICAgfTtcblxuICAgIHZtLmFwcGx5RmlsdGVycyA9IGZ1bmN0aW9uIChkZWZhdWx0UXVlcnlGaWx0ZXJzKSB7XG4gICAgICByZXR1cm4gYW5ndWxhci5leHRlbmQoZGVmYXVsdFF1ZXJ5RmlsdGVycywgdm0ucXVlcnlGaWx0ZXJzKTtcbiAgICB9O1xuXG4gICAgdm0uYWZ0ZXJTZWFyY2ggPSBmdW5jdGlvbiAoKSB7XG4gICAgICB2YXIgY29sdW1ucyA9IFtdO1xuICAgICAgdmFyIHRhc2tzID0gW107XG5cbiAgICAgIFN0YXR1c1NlcnZpY2UucXVlcnkoKS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICByZXNwb25zZS5mb3JFYWNoKGZ1bmN0aW9uIChzdGF0dXMpIHtcbiAgICAgICAgICBjb2x1bW5zLnB1c2goeyB0ZXh0OiBzdGF0dXMubmFtZSwgZGF0YUZpZWxkOiBzdGF0dXMuc2x1ZywgY29sbGFwc2libGU6IGZhbHNlIH0pO1xuICAgICAgICB9KTtcblxuICAgICAgICBpZiAodm0ucmVzb3VyY2VzLmxlbmd0aCA+IDApIHtcbiAgICAgICAgICB2bS5yZXNvdXJjZXMuZm9yRWFjaChmdW5jdGlvbiAodGFzaykge1xuICAgICAgICAgICAgdGFza3MucHVzaCh7XG4gICAgICAgICAgICAgIGlkOiB0YXNrLmlkLFxuICAgICAgICAgICAgICBzdGF0ZTogdGFzay5zdGF0dXMuc2x1ZyxcbiAgICAgICAgICAgICAgbGFiZWw6IHRhc2sudGl0bGUsXG4gICAgICAgICAgICAgIHRhZ3M6IHRhc2sudHlwZS5uYW1lICsgJywgJyArIHRhc2sucHJpb3JpdHkubmFtZVxuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgfSk7XG5cbiAgICAgICAgICB2YXIgc291cmNlID0ge1xuICAgICAgICAgICAgbG9jYWxEYXRhOiB0YXNrcyxcbiAgICAgICAgICAgIGRhdGFUeXBlOiAnYXJyYXknLFxuICAgICAgICAgICAgZGF0YUZpZWxkczogZmllbGRzXG4gICAgICAgICAgfTtcbiAgICAgICAgICB2YXIgZGF0YUFkYXB0ZXIgPSBuZXcgJC5qcXguZGF0YUFkYXB0ZXIoc291cmNlKTtcblxuICAgICAgICAgIHZtLnNldHRpbmdzID0ge1xuICAgICAgICAgICAgc291cmNlOiBkYXRhQWRhcHRlcixcbiAgICAgICAgICAgIGNvbHVtbnM6IGNvbHVtbnMsXG4gICAgICAgICAgICB0aGVtZTogJ2xpZ2h0J1xuICAgICAgICAgIH07XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgdm0uc2V0dGluZ3MgPSB7XG4gICAgICAgICAgICBzb3VyY2U6IFt7fV0sXG4gICAgICAgICAgICBjb2x1bW5zOiBjb2x1bW5zLFxuICAgICAgICAgICAgdGhlbWU6ICdsaWdodCdcbiAgICAgICAgICB9O1xuICAgICAgICB9XG4gICAgICAgIHZtLmthbmJhblJlYWR5ID0gdHJ1ZTtcbiAgICAgIH0pO1xuICAgIH07XG5cbiAgICB2bS5vbkl0ZW1Nb3ZlZCA9IGZ1bmN0aW9uIChldmVudCkge1xuICAgICAgaWYgKCF2bS5hY3R1YWxQcm9qZWN0LmRvbmUgJiYgQXV0aC5jdXJyZW50VXNlci5pZCA9PT0gdm0uYWN0dWFsUHJvamVjdC5vd25lcikge1xuICAgICAgICB2bS5pc01vdmVkID0gdHJ1ZTtcbiAgICAgICAgVGFza3NTZXJ2aWNlLnF1ZXJ5KHsgdGFza19pZDogZXZlbnQuYXJncy5pdGVtSWQgfSkudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgICBpZiAocmVzcG9uc2VbMF0ubWlsZXN0b25lICYmIHJlc3BvbnNlWzBdLm1pbGVzdG9uZS5kb25lIHx8IHJlc3BvbnNlWzBdLnByb2plY3QuZG9uZSkge1xuICAgICAgICAgICAgUHJUb2FzdC5lcnJvcignTsOjbyDDqSBwb3Nzw612ZWwgbW9kaWZpY2FyIG8gc3RhdHVzIGRlIHVtYSB0YXJlZmEgZmluYWxpemFkYS4nKTtcbiAgICAgICAgICAgIHZtLmFmdGVyU2VhcmNoKCk7XG4gICAgICAgICAgICB2bS5pc01vdmVkID0gZmFsc2U7XG4gICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIFRhc2tzU2VydmljZS51cGRhdGVUYXNrQnlLYW5iYW4oe1xuICAgICAgICAgICAgICBwcm9qZWN0X2lkOiB2bS5wcm9qZWN0LFxuICAgICAgICAgICAgICBpZDogZXZlbnQuYXJncy5pdGVtSWQsXG4gICAgICAgICAgICAgIG9sZENvbHVtbjogZXZlbnQuYXJncy5vbGRDb2x1bW4sXG4gICAgICAgICAgICAgIG5ld0NvbHVtbjogZXZlbnQuYXJncy5uZXdDb2x1bW4gfSkudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgIHZtLmlzTW92ZWQgPSBmYWxzZTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICAgIH1cbiAgICAgICAgfSk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICB2bS5hZnRlclNlYXJjaCgpO1xuICAgICAgfVxuICAgIH07XG5cbiAgICB2bS5vbkl0ZW1DbGlja2VkID0gZnVuY3Rpb24gKGV2ZW50KSB7XG4gICAgICBpZiAoIXZtLmlzTW92ZWQpIHtcbiAgICAgICAgVGFza3NTZXJ2aWNlLnF1ZXJ5KHsgdGFza19pZDogZXZlbnQuYXJncy5pdGVtSWQgfSkudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgICB2bS50YXNrSW5mbyA9IHJlc3BvbnNlWzBdO1xuICAgICAgICAgICRtZERpYWxvZy5zaG93KHtcbiAgICAgICAgICAgIHBhcmVudDogYW5ndWxhci5lbGVtZW50KCRkb2N1bWVudC5ib2R5KSxcbiAgICAgICAgICAgIHRlbXBsYXRlVXJsOiAnY2xpZW50L2FwcC9rYW5iYW4vdGFzay1pbmZvLWRpYWxvZy90YXNrSW5mby5odG1sJyxcbiAgICAgICAgICAgIGNvbnRyb2xsZXJBczogJ3Rhc2tJbmZvQ3RybCcsXG4gICAgICAgICAgICBjb250cm9sbGVyOiAnVGFza0luZm9Db250cm9sbGVyJyxcbiAgICAgICAgICAgIGJpbmRUb0NvbnRyb2xsZXI6IHRydWUsXG4gICAgICAgICAgICBsb2NhbHM6IHtcbiAgICAgICAgICAgICAgdGFzazogdm0udGFza0luZm8sXG4gICAgICAgICAgICAgIGNsb3NlOiBjbG9zZVxuICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIGVzY2FwZVRvQ2xvc2U6IHRydWUsXG4gICAgICAgICAgICBjbGlja091dHNpZGVUb0Nsb3NlOiB0cnVlXG4gICAgICAgICAgfSk7XG4gICAgICAgIH0pO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgdm0uaXNNb3ZlZCA9IGZhbHNlO1xuICAgICAgfVxuICAgIH07XG5cbiAgICBmdW5jdGlvbiBjbG9zZSgpIHtcbiAgICAgICRtZERpYWxvZy5oaWRlKCk7XG4gICAgfVxuXG4gICAgLy8gaW5zdGFudGlhdGUgYmFzZSBjb250cm9sbGVyXG4gICAgJGNvbnRyb2xsZXIoJ0NSVURDb250cm9sbGVyJywgeyB2bTogdm0sIG1vZGVsU2VydmljZTogVGFza3NTZXJ2aWNlLCBvcHRpb25zOiB7fSB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25maWcocm91dGVzKTtcblxuICAvKipcbiAgICogQXJxdWl2byBkZSBjb25maWd1cmHDp8OjbyBjb20gYXMgcm90YXMgZXNwZWPDrWZpY2FzIGRvIHJlY3Vyc28ga2FuYmFuXG4gICAqXG4gICAqIEBwYXJhbSB7b2JqZWN0fSAkc3RhdGVQcm92aWRlclxuICAgKiBAcGFyYW0ge29iamVjdH0gR2xvYmFsXG4gICAqL1xuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvdXRlcygkc3RhdGVQcm92aWRlciwgR2xvYmFsKSB7XG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ2FwcC5rYW5iYW4nLCB7XG4gICAgICB1cmw6ICcva2FuYmFuJyxcbiAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcva2FuYmFuL2thbmJhbi5odG1sJyxcbiAgICAgIGNvbnRyb2xsZXI6ICdLYW5iYW5Db250cm9sbGVyIGFzIGthbmJhbkN0cmwnLFxuICAgICAgZGF0YToge31cbiAgICB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5mYWN0b3J5KCdLYW5iYW5TZXJ2aWNlJywgS2FuYmFuU2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiBLYW5iYW5TZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgdmFyIG1vZGVsID0gc2VydmljZUZhY3RvcnkoJ2thbmJhbicsIHtcbiAgICAgIGFjdGlvbnM6IHt9LFxuICAgICAgaW5zdGFuY2U6IHt9XG4gICAgfSk7XG5cbiAgICByZXR1cm4gbW9kZWw7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbi8qZXNsaW50LWVudiBlczYqL1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29udHJvbGxlcignTWVudUNvbnRyb2xsZXInLCBNZW51Q29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiBNZW51Q29udHJvbGxlcigkbWRTaWRlbmF2LCAkc3RhdGUsICRtZENvbG9ycykge1xuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICAvL0Jsb2NvIGRlIGRlY2xhcmFjb2VzIGRlIGZ1bmNvZXNcbiAgICB2bS5vcGVuID0gb3BlbjtcbiAgICB2bS5vcGVuTWVudU9yUmVkaXJlY3RUb1N0YXRlID0gb3Blbk1lbnVPclJlZGlyZWN0VG9TdGF0ZTtcblxuICAgIGFjdGl2YXRlKCk7XG5cbiAgICBmdW5jdGlvbiBhY3RpdmF0ZSgpIHtcbiAgICAgIHZhciBtZW51UHJlZml4ID0gJ3ZpZXdzLmxheW91dC5tZW51Lic7XG5cbiAgICAgIC8vIEFycmF5IGNvbnRlbmRvIG9zIGl0ZW5zIHF1ZSBzw6NvIG1vc3RyYWRvcyBubyBtZW51IGxhdGVyYWxcbiAgICAgIHZtLml0ZW5zTWVudSA9IFt7IHN0YXRlOiAnYXBwLnByb2plY3RzJywgdGl0bGU6IG1lbnVQcmVmaXggKyAncHJvamVjdHMnLCBpY29uOiAnd29yaycsIHN1Ykl0ZW5zOiBbXSB9LCB7IHN0YXRlOiAnYXBwLmRhc2hib2FyZCcsIHRpdGxlOiBtZW51UHJlZml4ICsgJ2Rhc2hib2FyZCcsIGljb246ICdkYXNoYm9hcmQnLCBzdWJJdGVuczogW10gfSwgeyBzdGF0ZTogJ2FwcC50YXNrcycsIHRpdGxlOiBtZW51UHJlZml4ICsgJ3Rhc2tzJywgaWNvbjogJ3ZpZXdfbGlzdCcsIHN1Ykl0ZW5zOiBbXSB9LCB7IHN0YXRlOiAnYXBwLm1pbGVzdG9uZXMnLCB0aXRsZTogbWVudVByZWZpeCArICdtaWxlc3RvbmVzJywgaWNvbjogJ3ZpZXdfbW9kdWxlJywgc3ViSXRlbnM6IFtdIH0sIHsgc3RhdGU6ICdhcHAucmVsZWFzZXMnLCB0aXRsZTogbWVudVByZWZpeCArICdyZWxlYXNlcycsIGljb246ICdzdWJzY3JpcHRpb25zJywgc3ViSXRlbnM6IFtdIH0sIHsgc3RhdGU6ICdhcHAua2FuYmFuJywgdGl0bGU6IG1lbnVQcmVmaXggKyAna2FuYmFuJywgaWNvbjogJ3ZpZXdfY29sdW1uJywgc3ViSXRlbnM6IFtdIH0sIHsgc3RhdGU6ICdhcHAudmNzJywgdGl0bGU6IG1lbnVQcmVmaXggKyAndmNzJywgaWNvbjogJ2dyb3VwX3dvcmsnLCBzdWJJdGVuczogW11cbiAgICAgICAgLy8gQ29sb3F1ZSBzZXVzIGl0ZW5zIGRlIG1lbnUgYSBwYXJ0aXIgZGVzdGUgcG9udG9cbiAgICAgICAgLyoge1xuICAgICAgICAgIHN0YXRlOiAnIycsIHRpdGxlOiBtZW51UHJlZml4ICsgJ2FkbWluJywgaWNvbjogJ3NldHRpbmdzX2FwcGxpY2F0aW9ucycsIHByb2ZpbGVzOiBbJ2FkbWluJ10sXG4gICAgICAgICAgc3ViSXRlbnM6IFtcbiAgICAgICAgICAgIHsgc3RhdGU6ICdhcHAudXNlcicsIHRpdGxlOiBtZW51UHJlZml4ICsgJ3VzZXInLCBpY29uOiAncGVvcGxlJyB9LFxuICAgICAgICAgICAgeyBzdGF0ZTogJ2FwcC5tYWlsJywgdGl0bGU6IG1lbnVQcmVmaXggKyAnbWFpbCcsIGljb246ICdtYWlsJyB9LFxuICAgICAgICAgICAgeyBzdGF0ZTogJ2FwcC5hdWRpdCcsIHRpdGxlOiBtZW51UHJlZml4ICsgJ2F1ZGl0JywgaWNvbjogJ3N0b3JhZ2UnIH0sXG4gICAgICAgICAgICB7IHN0YXRlOiAnYXBwLmRpbmFtaWMtcXVlcnknLCB0aXRsZTogbWVudVByZWZpeCArICdkaW5hbWljUXVlcnknLCBpY29uOiAnbG9jYXRpb25fc2VhcmNoaW5nJyB9XG4gICAgICAgICAgXVxuICAgICAgICB9ICovXG4gICAgICB9XTtcblxuICAgICAgLyoqXG4gICAgICAgKiBPYmpldG8gcXVlIHByZWVuY2hlIG8gbmctc3R5bGUgZG8gbWVudSBsYXRlcmFsIHRyb2NhbmRvIGFzIGNvcmVzXG4gICAgICAgKi9cbiAgICAgIHZtLnNpZGVuYXZTdHlsZSA9IHtcbiAgICAgICAgdG9wOiB7XG4gICAgICAgICAgJ2JvcmRlci1ib3R0b20nOiAnMXB4IHNvbGlkIHJnYigyMTAsIDIxMCwgMjEwKScsXG4gICAgICAgICAgJ2JhY2tncm91bmQtaW1hZ2UnOiAnLXdlYmtpdC1saW5lYXItZ3JhZGllbnQodG9wLCByZ2IoMTQ0LCAxNDQsIDE0NCksIHJnYigyMTAsIDIxMCwgMjEwKSknXG4gICAgICAgIH0sXG4gICAgICAgIGNvbnRlbnQ6IHtcbiAgICAgICAgICAnYmFja2dyb3VuZC1jb2xvcic6ICdyZ2IoMjEwLCAyMTAsIDIxMCknXG4gICAgICAgIH0sXG4gICAgICAgIHRleHRDb2xvcjoge1xuICAgICAgICAgIGNvbG9yOiAnI0ZGRidcbiAgICAgICAgfSxcbiAgICAgICAgbGluZUJvdHRvbToge1xuICAgICAgICAgICdib3JkZXItYm90dG9tJzogJzFweCBzb2xpZCAnICsgZ2V0Q29sb3IoJ3ByaW1hcnktNDAwJylcbiAgICAgICAgfVxuICAgICAgfTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBvcGVuKCkge1xuICAgICAgJG1kU2lkZW5hdignbGVmdCcpLnRvZ2dsZSgpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIE3DqXRvZG8gcXVlIGV4aWJlIG8gc3ViIG1lbnUgZG9zIGl0ZW5zIGRvIG1lbnUgbGF0ZXJhbCBjYXNvIHRlbmhhIHN1YiBpdGVuc1xuICAgICAqIGNhc28gY29udHLDoXJpbyByZWRpcmVjaW9uYSBwYXJhIG8gc3RhdGUgcGFzc2FkbyBjb21vIHBhcsODwqJtZXRyb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIG9wZW5NZW51T3JSZWRpcmVjdFRvU3RhdGUoJG1kTWVudSwgZXYsIGl0ZW0pIHtcbiAgICAgIGlmIChhbmd1bGFyLmlzRGVmaW5lZChpdGVtLnN1Ykl0ZW5zKSAmJiBpdGVtLnN1Ykl0ZW5zLmxlbmd0aCA+IDApIHtcbiAgICAgICAgJG1kTWVudS5vcGVuKGV2KTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgICRzdGF0ZS5nbyhpdGVtLnN0YXRlLCB7IG9iajogbnVsbCB9KTtcbiAgICAgICAgJG1kU2lkZW5hdignbGVmdCcpLmNsb3NlKCk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gZ2V0Q29sb3IoY29sb3JQYWxldHRlcykge1xuICAgICAgcmV0dXJuICRtZENvbG9ycy5nZXRUaGVtZUNvbG9yKGNvbG9yUGFsZXR0ZXMpO1xuICAgIH1cbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbnRyb2xsZXIoJ01haWxzQ29udHJvbGxlcicsIE1haWxzQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBNYWlsc0NvbnRyb2xsZXIoTWFpbHNTZXJ2aWNlLCBVc2Vyc1NlcnZpY2UsIFByRGlhbG9nLCBQclRvYXN0LCAvLyBOT1NPTkFSXG4gICRxLCBsb2Rhc2gsICR0cmFuc2xhdGUsIEdsb2JhbCkge1xuXG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIHZtLmZpbHRlclNlbGVjdGVkID0gZmFsc2U7XG4gICAgdm0ub3B0aW9ucyA9IHtcbiAgICAgIHNraW46ICdrYW1hJyxcbiAgICAgIGxhbmd1YWdlOiAncHQtYnInLFxuICAgICAgYWxsb3dlZENvbnRlbnQ6IHRydWUsXG4gICAgICBlbnRpdGllczogdHJ1ZSxcbiAgICAgIGhlaWdodDogMzAwLFxuICAgICAgZXh0cmFQbHVnaW5zOiAnZGlhbG9nLGZpbmQsY29sb3JkaWFsb2cscHJldmlldyxmb3JtcyxpZnJhbWUsZmxhc2gnXG4gICAgfTtcblxuICAgIHZtLmxvYWRVc2VycyA9IGxvYWRVc2VycztcbiAgICB2bS5vcGVuVXNlckRpYWxvZyA9IG9wZW5Vc2VyRGlhbG9nO1xuICAgIHZtLmFkZFVzZXJNYWlsID0gYWRkVXNlck1haWw7XG4gICAgdm0uY2xlYW5Gb3JtID0gY2xlYW5Gb3JtO1xuICAgIHZtLnNlbmQgPSBzZW5kO1xuXG4gICAgYWN0aXZhdGUoKTtcblxuICAgIGZ1bmN0aW9uIGFjdGl2YXRlKCkge1xuICAgICAgdm0uY2xlYW5Gb3JtKCk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhbGl6YSBhIGJ1c2NhIHBlbG8gdXN1w6FyaW8gcmVtb3RhbWVudGVcbiAgICAgKlxuICAgICAqIEBwYXJhbXMge3N0cmluZ30gLSBSZWNlYmUgbyB2YWxvciBwYXJhIHNlciBwZXNxdWlzYWRvXG4gICAgICogQHJldHVybiB7cHJvbWlzc2V9IC0gUmV0b3JuYSB1bWEgcHJvbWlzc2UgcXVlIG8gY29tcG9uZXRlIHJlc29sdmVcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBsb2FkVXNlcnMoY3JpdGVyaWEpIHtcbiAgICAgIHZhciBkZWZlcnJlZCA9ICRxLmRlZmVyKCk7XG5cbiAgICAgIFVzZXJzU2VydmljZS5xdWVyeSh7XG4gICAgICAgIG5hbWVPckVtYWlsOiBjcml0ZXJpYSxcbiAgICAgICAgbm90VXNlcnM6IGxvZGFzaC5tYXAodm0ubWFpbC51c2VycywgbG9kYXNoLnByb3BlcnR5KCdpZCcpKS50b1N0cmluZygpLFxuICAgICAgICBsaW1pdDogNVxuICAgICAgfSkudGhlbihmdW5jdGlvbiAoZGF0YSkge1xuXG4gICAgICAgIC8vIHZlcmlmaWNhIHNlIG5hIGxpc3RhIGRlIHVzdWFyaW9zIGrDoSBleGlzdGUgbyB1c3XDoXJpbyBjb20gbyBlbWFpbCBwZXNxdWlzYWRvXG4gICAgICAgIGRhdGEgPSBsb2Rhc2guZmlsdGVyKGRhdGEsIGZ1bmN0aW9uICh1c2VyKSB7XG4gICAgICAgICAgcmV0dXJuICFsb2Rhc2guZmluZCh2bS5tYWlsLnVzZXJzLCB7IGVtYWlsOiB1c2VyLmVtYWlsIH0pO1xuICAgICAgICB9KTtcblxuICAgICAgICBkZWZlcnJlZC5yZXNvbHZlKGRhdGEpO1xuICAgICAgfSk7XG5cbiAgICAgIHJldHVybiBkZWZlcnJlZC5wcm9taXNlO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEFicmUgbyBkaWFsb2cgcGFyYSBwZXNxdWlzYSBkZSB1c3XDoXJpb3NcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBvcGVuVXNlckRpYWxvZygpIHtcbiAgICAgIHZhciBjb25maWcgPSB7XG4gICAgICAgIGxvY2Fsczoge1xuICAgICAgICAgIG9uSW5pdDogdHJ1ZSxcbiAgICAgICAgICB1c2VyRGlhbG9nSW5wdXQ6IHtcbiAgICAgICAgICAgIHRyYW5zZmVyVXNlckZuOiB2bS5hZGRVc2VyTWFpbFxuICAgICAgICAgIH1cbiAgICAgICAgfSxcbiAgICAgICAgY29udHJvbGxlcjogJ1VzZXJzRGlhbG9nQ29udHJvbGxlcicsXG4gICAgICAgIGNvbnRyb2xsZXJBczogJ2N0cmwnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL3VzZXJzL2RpYWxvZy91c2Vycy1kaWFsb2cuaHRtbCcsXG4gICAgICAgIGhhc0JhY2tkcm9wOiB0cnVlXG4gICAgICB9O1xuXG4gICAgICBQckRpYWxvZy5jdXN0b20oY29uZmlnKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBBZGljaW9uYSBvIHVzdcOhcmlvIHNlbGVjaW9uYWRvIG5hIGxpc3RhIHBhcmEgcXVlIHNlamEgZW52aWFkbyBvIGVtYWlsXG4gICAgICovXG4gICAgZnVuY3Rpb24gYWRkVXNlck1haWwodXNlcikge1xuICAgICAgdmFyIHVzZXJzID0gbG9kYXNoLmZpbmQodm0ubWFpbC51c2VycywgeyBlbWFpbDogdXNlci5lbWFpbCB9KTtcblxuICAgICAgaWYgKHZtLm1haWwudXNlcnMubGVuZ3RoID4gMCAmJiBhbmd1bGFyLmlzRGVmaW5lZCh1c2VycykpIHtcbiAgICAgICAgUHJUb2FzdC53YXJuKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMudXNlci51c2VyRXhpc3RzJykpO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgdm0ubWFpbC51c2Vycy5wdXNoKHsgbmFtZTogdXNlci5uYW1lLCBlbWFpbDogdXNlci5lbWFpbCB9KTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFsaXphIG8gZW52aW8gZG8gZW1haWwgcGFyYSBhIGxpc3RhIGRlIHVzdcOhcmlvcyBzZWxlY2lvbmFkb3NcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBzZW5kKCkge1xuXG4gICAgICB2bS5tYWlsLiRzYXZlKCkudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgaWYgKHJlc3BvbnNlLmxlbmd0aCA+IDApIHtcbiAgICAgICAgICB2YXIgbXNnID0gJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5tYWlsLm1haWxFcnJvcnMnKTtcblxuICAgICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgcmVzcG9uc2UubGVuZ3RoOyBpKyspIHtcbiAgICAgICAgICAgIG1zZyArPSByZXNwb25zZSArICdcXG4nO1xuICAgICAgICAgIH1cbiAgICAgICAgICBQclRvYXN0LmVycm9yKG1zZyk7XG4gICAgICAgICAgdm0uY2xlYW5Gb3JtKCk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgUHJUb2FzdC5zdWNjZXNzKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMubWFpbC5zZW5kTWFpbFN1Y2Nlc3MnKSk7XG4gICAgICAgICAgdm0uY2xlYW5Gb3JtKCk7XG4gICAgICAgIH1cbiAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIExpbXBhIG8gZm9ybXVsw6FyaW8gZGUgZW1haWxcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBjbGVhbkZvcm0oKSB7XG4gICAgICB2bS5tYWlsID0gbmV3IE1haWxzU2VydmljZSgpO1xuICAgICAgdm0ubWFpbC51c2VycyA9IFtdO1xuICAgIH1cbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25maWcocm91dGVzKTtcblxuICAvKipcbiAgICogQXJxdWl2byBkZSBjb25maWd1cmHDp8OjbyBjb20gYXMgcm90YXMgZXNwZWPDrWZpY2FzIGRvIHJlY3Vyc28gZW0gcXVlc3TDo29cbiAgICpcbiAgICogQHBhcmFtIHthbnl9ICRzdGF0ZVByb3ZpZGVyXG4gICAqIEBwYXJhbSB7YW55fSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnYXBwLm1haWwnLCB7XG4gICAgICB1cmw6ICcvZW1haWwnLFxuICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9tYWlsL21haWxzLXNlbmQuaHRtbCcsXG4gICAgICBjb250cm9sbGVyOiAnTWFpbHNDb250cm9sbGVyIGFzIG1haWxzQ3RybCcsXG4gICAgICBkYXRhOiB7IG5lZWRBdXRoZW50aWNhdGlvbjogdHJ1ZSwgbmVlZFByb2ZpbGU6IFsnYWRtaW4nXSB9XG4gICAgfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmFjdG9yeSgnTWFpbHNTZXJ2aWNlJywgTWFpbHNTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIE1haWxzU2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHJldHVybiBzZXJ2aWNlRmFjdG9yeSgnbWFpbHMnLCB7fSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb250cm9sbGVyKCdNaWxlc3RvbmVzQ29udHJvbGxlcicsIE1pbGVzdG9uZXNDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIE1pbGVzdG9uZXNDb250cm9sbGVyKCRjb250cm9sbGVyLCBNaWxlc3RvbmVzU2VydmljZSwgbW9tZW50LCBUYXNrc1NlcnZpY2UsIFByb2plY3RzU2VydmljZSwgUHJUb2FzdCwgJHRyYW5zbGF0ZSwgJG1kRGlhbG9nLCBBdXRoKSB7XG5cbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0uZXN0aW1hdGVkUHJpY2UgPSBlc3RpbWF0ZWRQcmljZTtcblxuICAgIHZtLm9uQWN0aXZhdGUgPSBmdW5jdGlvbiAoKSB7XG4gICAgICB2bS5jdXJyZW50VXNlciA9IEF1dGguY3VycmVudFVzZXI7XG4gICAgICB2bS5wcm9qZWN0ID0gbG9jYWxTdG9yYWdlLmdldEl0ZW0oJ3Byb2plY3QnKTtcbiAgICAgIFByb2plY3RzU2VydmljZS5xdWVyeSh7IHByb2plY3RfaWQ6IHZtLnByb2plY3QgfSkudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgdm0uYWN0dWFsUHJvamVjdCA9IHJlc3BvbnNlWzBdO1xuICAgICAgfSk7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMgPSB7IHByb2plY3RfaWQ6IHZtLnByb2plY3QgfTtcbiAgICB9O1xuXG4gICAgZnVuY3Rpb24gZXN0aW1hdGVkUHJpY2UobWlsZXN0b25lKSB7XG4gICAgICBtaWxlc3RvbmUuZXN0aW1hdGVkX3ZhbHVlID0gMDtcbiAgICAgIGlmIChtaWxlc3RvbmUudGFza3MubGVuZ3RoID4gMCAmJiBtaWxlc3RvbmUucHJvamVjdC5ob3VyX3ZhbHVlX2ZpbmFsKSB7XG4gICAgICAgIG1pbGVzdG9uZS50YXNrcy5mb3JFYWNoKGZ1bmN0aW9uICh0YXNrKSB7XG4gICAgICAgICAgbWlsZXN0b25lLmVzdGltYXRlZF92YWx1ZSArPSBwYXJzZUZsb2F0KG1pbGVzdG9uZS5wcm9qZWN0LmhvdXJfdmFsdWVfZmluYWwpICogdGFzay5lc3RpbWF0ZWRfdGltZTtcbiAgICAgICAgfSk7XG4gICAgICB9XG4gICAgICByZXR1cm4gbWlsZXN0b25lLmVzdGltYXRlZF92YWx1ZS50b0xvY2FsZVN0cmluZygnUHQtYnInLCB7IG1pbmltdW1GcmFjdGlvbkRpZ2l0czogMiB9KTtcbiAgICB9XG5cbiAgICB2bS5lc3RpbWF0ZWRUaW1lID0gZnVuY3Rpb24gKG1pbGVzdG9uZSkge1xuICAgICAgbWlsZXN0b25lLmVzdGltYXRlZF90aW1lID0gMDtcbiAgICAgIGlmIChtaWxlc3RvbmUudGFza3MubGVuZ3RoID4gMCkge1xuICAgICAgICBtaWxlc3RvbmUudGFza3MuZm9yRWFjaChmdW5jdGlvbiAodGFzaykge1xuICAgICAgICAgIG1pbGVzdG9uZS5lc3RpbWF0ZWRfdGltZSArPSB0YXNrLmVzdGltYXRlZF90aW1lO1xuICAgICAgICB9KTtcbiAgICAgIH1cbiAgICAgIG1pbGVzdG9uZS5lc3RpbWF0ZWRfdGltZSA9IG1pbGVzdG9uZS5lc3RpbWF0ZWRfdGltZSAvIDg7XG4gICAgICB2YXIgZGF0ZUVuZCA9IG1vbWVudChtaWxlc3RvbmUuZGF0ZV9lbmQpO1xuICAgICAgdmFyIGRhdGVCZWdpbiA9IG1vbWVudChtaWxlc3RvbmUuZGF0ZV9iZWdpbik7XG5cbiAgICAgIGlmIChkYXRlRW5kLmRpZmYoZGF0ZUJlZ2luLCAnZGF5cycpIDwgbWlsZXN0b25lLmVzdGltYXRlZF90aW1lKSB7XG4gICAgICAgIG1pbGVzdG9uZS5jb2xvcl9lc3RpbWF0ZWRfdGltZSA9IHsgY29sb3I6ICdyZWQnIH07XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBtaWxlc3RvbmUuY29sb3JfZXN0aW1hdGVkX3RpbWUgPSB7IGNvbG9yOiAnZ3JlZW4nIH07XG4gICAgICB9XG4gICAgICByZXR1cm4gbWlsZXN0b25lLmVzdGltYXRlZF90aW1lO1xuICAgIH07XG5cbiAgICB2bS5hcHBseUZpbHRlcnMgPSBmdW5jdGlvbiAoZGVmYXVsdFF1ZXJ5RmlsdGVycykge1xuICAgICAgcmV0dXJuIGFuZ3VsYXIuZXh0ZW5kKGRlZmF1bHRRdWVyeUZpbHRlcnMsIHZtLnF1ZXJ5RmlsdGVycyk7XG4gICAgfTtcblxuICAgIHZtLmJlZm9yZVNhdmUgPSBmdW5jdGlvbiAoKSB7XG4gICAgICB2bS5yZXNvdXJjZS5wcm9qZWN0X2lkID0gdm0ucHJvamVjdDtcbiAgICB9O1xuXG4gICAgdm0uYmVmb3JlUmVtb3ZlID0gZnVuY3Rpb24gKCkge1xuICAgICAgdm0ucmVzb3VyY2UucHJvamVjdF9pZCA9IHZtLnByb2plY3Q7XG4gICAgfTtcblxuICAgIHZtLmZvcm1hdERhdGUgPSBmdW5jdGlvbiAoZGF0ZSkge1xuICAgICAgcmV0dXJuIG1vbWVudChkYXRlKS5mb3JtYXQoJ0REL01NL1lZWVknKTtcbiAgICB9O1xuXG4gICAgdm0uYWZ0ZXJFZGl0ID0gZnVuY3Rpb24gKCkge1xuICAgICAgdm0ucmVzb3VyY2UuZGF0ZV9iZWdpbiA9IG1vbWVudCh2bS5yZXNvdXJjZS5kYXRlX2JlZ2luKS5fZDtcbiAgICAgIHZtLnJlc291cmNlLmRhdGVfZW5kID0gbW9tZW50KHZtLnJlc291cmNlLmRhdGVfZW5kKS5fZDtcbiAgICB9O1xuXG4gICAgdm0udmlldyA9IGZ1bmN0aW9uIChyZXNvdXJjZSkge1xuICAgICAgdm0ucmVzb3VyY2UgPSByZXNvdXJjZTtcbiAgICAgIHZtLnJlc291cmNlLmRhdGVfYmVnaW4gPSBtb21lbnQodm0ucmVzb3VyY2UuZGF0ZV9iZWdpbik7XG4gICAgICB2bS5yZXNvdXJjZS5kYXRlX2VuZCA9IG1vbWVudCh2bS5yZXNvdXJjZS5kYXRlX2VuZCk7XG4gICAgICB2bS5vblZpZXcgPSB0cnVlO1xuICAgICAgdm0udmlld0Zvcm0gPSBmYWxzZTtcbiAgICB9O1xuXG4gICAgdm0uc2VhcmNoVGFzayA9IGZ1bmN0aW9uICh0YXNrVGVybSkge1xuICAgICAgcmV0dXJuIFRhc2tzU2VydmljZS5xdWVyeSh7XG4gICAgICAgIG1pbGVzdG9uZVNlYXJjaDogdHJ1ZSxcbiAgICAgICAgcHJvamVjdF9pZDogdm0ucmVzb3VyY2UucHJvamVjdF9pZCxcbiAgICAgICAgdGl0bGU6IHRhc2tUZXJtXG4gICAgICB9KTtcbiAgICB9O1xuXG4gICAgdm0ub25UYXNrQ2hhbmdlID0gZnVuY3Rpb24gKCkge1xuICAgICAgaWYgKHZtLnRhc2sgIT09IG51bGwgJiYgdm0ucmVzb3VyY2UudGFza3MuZmluZEluZGV4KGZ1bmN0aW9uIChpKSB7XG4gICAgICAgIHJldHVybiBpLmlkID09PSB2bS50YXNrLmlkO1xuICAgICAgfSkgPT09IC0xKSB7XG4gICAgICAgIHZtLnJlc291cmNlLnRhc2tzLnB1c2godm0udGFzayk7XG4gICAgICB9XG4gICAgfTtcblxuICAgIHZtLnJlbW92ZVRhc2sgPSBmdW5jdGlvbiAodGFzaykge1xuICAgICAgdm0ucmVzb3VyY2UudGFza3Muc2xpY2UoMCkuZm9yRWFjaChmdW5jdGlvbiAoZWxlbWVudCkge1xuICAgICAgICBpZiAoZWxlbWVudC5pZCA9PT0gdGFzay5pZCkge1xuICAgICAgICAgIHZtLnJlc291cmNlLnRhc2tzLnNwbGljZSh2bS5yZXNvdXJjZS50YXNrcy5pbmRleE9mKGVsZW1lbnQpLCAxKTtcbiAgICAgICAgfVxuICAgICAgfSk7XG4gICAgfTtcblxuICAgIHZtLnNhdmVUYXNrcyA9IGZ1bmN0aW9uICgpIHtcbiAgICAgIFRhc2tzU2VydmljZS51cGRhdGVNaWxlc3RvbmUoeyBwcm9qZWN0X2lkOiB2bS5yZXNvdXJjZS5wcm9qZWN0X2lkLCBtaWxlc3RvbmVfaWQ6IHZtLnJlc291cmNlLmlkLCB0YXNrczogdm0ucmVzb3VyY2UudGFza3MgfSkudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgIFByVG9hc3Quc3VjY2VzcygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnNhdmVTdWNjZXNzJykpO1xuICAgICAgICB2bS52aWV3Rm9ybSA9IGZhbHNlO1xuICAgICAgICB2bS5vblZpZXcgPSBmYWxzZTtcbiAgICAgIH0sIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgUHJUb2FzdC5lcnJvcigkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLm9wZXJhdGlvbkVycm9yJykpO1xuICAgICAgfSk7XG4gICAgfTtcblxuICAgIHZtLmZpbmFsaXplID0gZnVuY3Rpb24gKG1pbGVzdG9uZSkge1xuICAgICAgdmFyIGNvbmZpcm0gPSAkbWREaWFsb2cuY29uZmlybSgpLnRpdGxlKCdGaW5hbGl6YXIgU3ByaW50JykudGV4dENvbnRlbnQoJ1RlbSBjZXJ0ZXphIHF1ZSBkZXNlamEgZmluYWxpemFyIGEgc3ByaW50ICcgKyBtaWxlc3RvbmUudGl0bGUgKyAnPycpLm9rKCdTaW0nKS5jYW5jZWwoJ07Do28nKTtcblxuICAgICAgJG1kRGlhbG9nLnNob3coY29uZmlybSkudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgIE1pbGVzdG9uZXNTZXJ2aWNlLmZpbmFsaXplKHsgcHJvamVjdF9pZDogdm0ucHJvamVjdCwgbWlsZXN0b25lX2lkOiBtaWxlc3RvbmUuaWQgfSkudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgUHJUb2FzdC5zdWNjZXNzKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMuc3ByaW50RW5kZWRTdWNjZXNzJykpO1xuICAgICAgICAgIHZtLnNlYXJjaCgpO1xuICAgICAgICB9LCBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgUHJUb2FzdC5FcnJvcigkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnNwcmludEVuZGVkRXJyb3InKSk7XG4gICAgICAgIH0pO1xuICAgICAgfSk7XG4gICAgfTtcblxuICAgIC8vIGluc3RhbnRpYXRlIGJhc2UgY29udHJvbGxlclxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHsgdm06IHZtLCBtb2RlbFNlcnZpY2U6IE1pbGVzdG9uZXNTZXJ2aWNlLCBvcHRpb25zOiB7fSB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25maWcocm91dGVzKTtcblxuICAvKipcbiAgICogQXJxdWl2byBkZSBjb25maWd1cmHDp8OjbyBjb20gYXMgcm90YXMgZXNwZWPDrWZpY2FzIGRvIHJlY3Vyc28gbWlsZXN0b25lc1xuICAgKlxuICAgKiBAcGFyYW0ge29iamVjdH0gJHN0YXRlUHJvdmlkZXJcbiAgICogQHBhcmFtIHtvYmplY3R9IEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdhcHAubWlsZXN0b25lcycsIHtcbiAgICAgIHVybDogJy9taWxlc3RvbmVzJyxcbiAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvbWlsZXN0b25lcy9taWxlc3RvbmVzLmh0bWwnLFxuICAgICAgY29udHJvbGxlcjogJ01pbGVzdG9uZXNDb250cm9sbGVyIGFzIG1pbGVzdG9uZXNDdHJsJyxcbiAgICAgIGRhdGE6IHt9XG4gICAgfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmFjdG9yeSgnTWlsZXN0b25lc1NlcnZpY2UnLCBNaWxlc3RvbmVzU2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiBNaWxlc3RvbmVzU2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHZhciBtb2RlbCA9IHNlcnZpY2VGYWN0b3J5KCdtaWxlc3RvbmVzJywge1xuICAgICAgYWN0aW9uczoge1xuICAgICAgICBmaW5hbGl6ZToge1xuICAgICAgICAgIG1ldGhvZDogJ1BPU1QnLFxuICAgICAgICAgIHVybDogJ2ZpbmFsaXplJ1xuICAgICAgICB9LFxuICAgICAgICB1cGRhdGVSZWxlYXNlOiB7XG4gICAgICAgICAgbWV0aG9kOiAnUE9TVCcsXG4gICAgICAgICAgdXJsOiAndXBkYXRlUmVsZWFzZSdcbiAgICAgICAgfVxuICAgICAgfSxcbiAgICAgIGluc3RhbmNlOiB7fVxuICAgIH0pO1xuXG4gICAgcmV0dXJuIG1vZGVsO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZhY3RvcnkoJ1ByaW9yaXRpZXNTZXJ2aWNlJywgUHJpb3JpdGllc1NlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gUHJpb3JpdGllc1NlcnZpY2Uoc2VydmljZUZhY3RvcnkpIHtcbiAgICB2YXIgbW9kZWwgPSBzZXJ2aWNlRmFjdG9yeSgncHJpb3JpdGllcycsIHtcbiAgICAgIGFjdGlvbnM6IHt9LFxuICAgICAgaW5zdGFuY2U6IHt9XG4gICAgfSk7XG5cbiAgICByZXR1cm4gbW9kZWw7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb250cm9sbGVyKCdQcm9qZWN0c0NvbnRyb2xsZXInLCBQcm9qZWN0c0NvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gUHJvamVjdHNDb250cm9sbGVyKCRjb250cm9sbGVyLCBQcm9qZWN0c1NlcnZpY2UsIEF1dGgsIFJvbGVzU2VydmljZSwgVXNlcnNTZXJ2aWNlLCAkc3RhdGUsICRmaWx0ZXIsICRzdGF0ZVBhcmFtcywgJHdpbmRvdykge1xuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICAvL0F0dHJpYnV0ZXMgQmxvY2tcblxuICAgIC8vRnVuY3Rpb25zIEJsb2NrXG4gICAgdm0ub25BY3RpdmF0ZSA9IG9uQWN0aXZhdGU7XG4gICAgdm0uYXBwbHlGaWx0ZXJzID0gYXBwbHlGaWx0ZXJzO1xuICAgIHZtLmJlZm9yZVNhdmUgPSBiZWZvcmVTYXZlO1xuICAgIHZtLnNlYXJjaFVzZXIgPSBzZWFyY2hVc2VyO1xuICAgIHZtLmFkZFVzZXIgPSBhZGRVc2VyO1xuICAgIHZtLnJlbW92ZVVzZXIgPSByZW1vdmVVc2VyO1xuICAgIHZtLnZpZXdQcm9qZWN0ID0gdmlld1Byb2plY3Q7XG5cbiAgICB2bS5yb2xlcyA9IHt9O1xuICAgIHZtLnVzZXJzID0gW107XG5cbiAgICBmdW5jdGlvbiBvbkFjdGl2YXRlKCkge1xuICAgICAgdm0uY3VycmVudFVzZXIgPSBBdXRoLmN1cnJlbnRVc2VyO1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0geyB1c2VyX2lkOiB2bS5jdXJyZW50VXNlci5pZCB9O1xuICAgICAgUm9sZXNTZXJ2aWNlLnF1ZXJ5KCkudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgdm0ucm9sZXMgPSByZXNwb25zZTtcbiAgICAgICAgaWYgKCRzdGF0ZVBhcmFtcy5vYmogPT09ICdlZGl0Jykge1xuICAgICAgICAgIHZtLmNsZWFuRm9ybSgpO1xuICAgICAgICAgIHZtLnZpZXdGb3JtID0gdHJ1ZTtcbiAgICAgICAgICB2bS5yZXNvdXJjZSA9ICRzdGF0ZVBhcmFtcy5yZXNvdXJjZTtcbiAgICAgICAgICB1c2Vyc0FycmF5KHZtLnJlc291cmNlKTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbSgncHJvamVjdCcpO1xuICAgICAgICB9XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBhcHBseUZpbHRlcnMoZGVmYXVsdFF1ZXJ5RmlsdGVycykge1xuICAgICAgcmV0dXJuIGFuZ3VsYXIuZXh0ZW5kKGRlZmF1bHRRdWVyeUZpbHRlcnMsIHZtLnF1ZXJ5bHRlcnMpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGJlZm9yZVNhdmUoKSB7XG4gICAgICBpZiAoIXZtLnJlc291cmNlLm93bmVyKSB7XG4gICAgICAgIHZtLnJlc291cmNlLm93bmVyID0gQXV0aC5jdXJyZW50VXNlci5pZDtcbiAgICAgIH1cbiAgICAgIHZtLnJlc291cmNlLnVzZXJfaWQgPSBBdXRoLmN1cnJlbnRVc2VyLmlkO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIHNlYXJjaFVzZXIoKSB7XG4gICAgICByZXR1cm4gVXNlcnNTZXJ2aWNlLnF1ZXJ5KHsgbmFtZTogdm0udXNlck5hbWUgfSk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gYWRkVXNlcih1c2VyKSB7XG4gICAgICBpZiAoIXZtLnJlc291cmNlLnVzZXJzKSB7XG4gICAgICAgIHZtLnJlc291cmNlLnVzZXJzID0gW107XG4gICAgICB9XG4gICAgICBpZiAodXNlcikge1xuICAgICAgICB2bS5yZXNvdXJjZS51c2Vycy5wdXNoKHVzZXIpO1xuICAgICAgICB2bS51c2VyTmFtZSA9ICcnO1xuICAgICAgfVxuICAgIH1cblxuICAgIGZ1bmN0aW9uIHJlbW92ZVVzZXIoaW5kZXgpIHtcbiAgICAgIHZtLnJlc291cmNlLnVzZXJzLnNwbGljZShpbmRleCwgMSk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gYXBwbHlGaWx0ZXJzKGRlZmF1bHRRdWVyeUZpbHRlcnMpIHtcbiAgICAgIHJldHVybiBhbmd1bGFyLmV4dGVuZChkZWZhdWx0UXVlcnlGaWx0ZXJzLCB2bS5xdWVyeUZpbHRlcnMpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIHZpZXdQcm9qZWN0KCkge1xuICAgICAgJHN0YXRlLmdvKCdhcHAuZGFzaGJvYXJkJyk7XG4gICAgfVxuXG4gICAgdm0uYWZ0ZXJTZWFyY2ggPSBmdW5jdGlvbiAoKSB7XG4gICAgICBpZiAodm0ucmVzb3VyY2VzLmxlbmd0aCA+IDApIHtcbiAgICAgICAgdm0ucmVzb3VyY2VzLmZvckVhY2goZnVuY3Rpb24gKHByb2plY3QpIHtcbiAgICAgICAgICB1c2Vyc0FycmF5KHByb2plY3QpO1xuICAgICAgICB9KTtcbiAgICAgIH1cbiAgICB9O1xuXG4gICAgZnVuY3Rpb24gdXNlcnNBcnJheShwcm9qZWN0KSB7XG4gICAgICBwcm9qZWN0LnVzZXJzID0gW107XG4gICAgICBpZiAocHJvamVjdC5jbGllbnRfaWQpIHtcbiAgICAgICAgcHJvamVjdC5jbGllbnQucm9sZSA9ICRmaWx0ZXIoJ2ZpbHRlcicpKHZtLnJvbGVzLCB7IHNsdWc6ICdjbGllbnQnIH0pWzBdO1xuICAgICAgICBwcm9qZWN0LnVzZXJzLnB1c2gocHJvamVjdC5jbGllbnQpO1xuICAgICAgfVxuICAgICAgaWYgKHByb2plY3QuZGV2X2lkKSB7XG4gICAgICAgIHByb2plY3QuZGV2ZWxvcGVyLnJvbGUgPSAkZmlsdGVyKCdmaWx0ZXInKSh2bS5yb2xlcywgeyBzbHVnOiAnZGV2JyB9KVswXTtcbiAgICAgICAgcHJvamVjdC51c2Vycy5wdXNoKHByb2plY3QuZGV2ZWxvcGVyKTtcbiAgICAgIH1cbiAgICAgIGlmIChwcm9qZWN0LnN0YWtlaG9sZGVyX2lkKSB7XG4gICAgICAgIHByb2plY3Quc3Rha2Vob2xkZXIucm9sZSA9ICRmaWx0ZXIoJ2ZpbHRlcicpKHZtLnJvbGVzLCB7IHNsdWc6ICdzdGFrZWhvbGRlcicgfSlbMF07XG4gICAgICAgIHByb2plY3QudXNlcnMucHVzaChwcm9qZWN0LnN0YWtlaG9sZGVyKTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICB2bS5oaXN0b3J5QmFjayA9IGZ1bmN0aW9uICgpIHtcbiAgICAgIGlmICgkc3RhdGVQYXJhbXMub2JqKSB7XG4gICAgICAgICR3aW5kb3cuaGlzdG9yeS5iYWNrKCk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICB2bS52aWV3Rm9ybSA9IGZhbHNlO1xuICAgICAgfVxuICAgIH07XG5cbiAgICB2bS5hZnRlclNhdmUgPSBmdW5jdGlvbiAocmVzb3VyY2UpIHtcbiAgICAgIGxvY2FsU3RvcmFnZS5zZXRJdGVtKCdwcm9qZWN0JywgcmVzb3VyY2UuaWQpO1xuICAgICAgJHN0YXRlLmdvKCdhcHAuZGFzaGJvYXJkJyk7XG4gICAgfTtcblxuICAgIC8vIGluc3RhbnRpYXRlIGJhc2UgY29udHJvbGxlclxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHsgdm06IHZtLCBtb2RlbFNlcnZpY2U6IFByb2plY3RzU2VydmljZSwgb3B0aW9uczogeyByZWRpcmVjdEFmdGVyU2F2ZTogZmFsc2UgfSB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25maWcocm91dGVzKTtcblxuICAvKipcbiAgICogQXJxdWl2byBkZSBjb25maWd1cmHDp8OjbyBjb20gYXMgcm90YXMgZXNwZWPDrWZpY2FzIGRvIHJlY3Vyc28gcHJvamVjdFxuICAgKlxuICAgKiBAcGFyYW0ge2FueX0gJHN0YXRlUHJvdmlkZXJcbiAgICogQHBhcmFtIHthbnl9IEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdhcHAucHJvamVjdHMnLCB7XG4gICAgICB1cmw6ICcvcHJvamVjdHMnLFxuICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9wcm9qZWN0cy9wcm9qZWN0cy5odG1sJyxcbiAgICAgIGNvbnRyb2xsZXI6ICdQcm9qZWN0c0NvbnRyb2xsZXIgYXMgcHJvamVjdHNDdHJsJyxcbiAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiB0cnVlIH0sXG4gICAgICBwYXJhbXM6IHsgb2JqOiBudWxsLCByZXNvdXJjZTogbnVsbCB9XG4gICAgfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmFjdG9yeSgnUHJvamVjdHNTZXJ2aWNlJywgUHJvamVjdHNTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIFByb2plY3RzU2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHJldHVybiBzZXJ2aWNlRmFjdG9yeSgncHJvamVjdHMnLCB7XG4gICAgICBhY3Rpb25zOiB7XG4gICAgICAgIGZpbmFsaXplOiB7XG4gICAgICAgICAgbWV0aG9kOiAnUE9TVCcsXG4gICAgICAgICAgdXJsOiAnZmluYWxpemUnXG4gICAgICAgIH0sXG4gICAgICAgIHZlcmlmeVJlbGVhc2VzOiB7XG4gICAgICAgICAgbWV0aG9kOiAnUE9TVCcsXG4gICAgICAgICAgdXJsOiAndmVyaWZ5UmVsZWFzZXMnXG4gICAgICAgIH1cbiAgICAgIH0sXG4gICAgICBpbnN0YW5jZToge31cbiAgICB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbnRyb2xsZXIoJ1JlbGVhc2VzQ29udHJvbGxlcicsIFJlbGVhc2VzQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBSZWxlYXNlc0NvbnRyb2xsZXIoJGNvbnRyb2xsZXIsIFJlbGVhc2VzU2VydmljZSwgTWlsZXN0b25lc1NlcnZpY2UsIFByb2plY3RzU2VydmljZSwgQXV0aCwgUHJUb2FzdCwgbW9tZW50LCAkbWREaWFsb2csICR0cmFuc2xhdGUpIHtcbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgLy9BdHRyaWJ1dGVzIEJsb2NrXG4gICAgdm0uYXBwbHlGaWx0ZXJzID0gYXBwbHlGaWx0ZXJzO1xuXG4gICAgLy9GdW5jdGlvbnMgQmxvY2tcbiAgICB2bS5vbkFjdGl2YXRlID0gZnVuY3Rpb24gKCkge1xuICAgICAgdm0uY3VycmVudFVzZXIgPSBBdXRoLmN1cnJlbnRVc2VyO1xuICAgICAgdm0ucHJvamVjdCA9IGxvY2FsU3RvcmFnZS5nZXRJdGVtKCdwcm9qZWN0Jyk7XG4gICAgICBQcm9qZWN0c1NlcnZpY2UucXVlcnkoeyBwcm9qZWN0X2lkOiB2bS5wcm9qZWN0IH0pLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgIHZtLmFjdHVhbFByb2plY3QgPSByZXNwb25zZVswXTtcbiAgICAgIH0pO1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0geyBwcm9qZWN0X2lkOiB2bS5wcm9qZWN0IH07XG4gICAgfTtcblxuICAgIGZ1bmN0aW9uIGFwcGx5RmlsdGVycyhkZWZhdWx0UXVlcnlGaWx0ZXJzKSB7XG4gICAgICByZXR1cm4gYW5ndWxhci5leHRlbmQoZGVmYXVsdFF1ZXJ5RmlsdGVycywgdm0ucXVlcnlGaWx0ZXJzKTtcbiAgICB9XG5cbiAgICB2bS5iZWZvcmVTYXZlID0gZnVuY3Rpb24gKCkge1xuICAgICAgdm0ucmVzb3VyY2UucHJvamVjdF9pZCA9IHZtLnByb2plY3Q7XG4gICAgfTtcblxuICAgIHZtLmJlZm9yZVJlbW92ZSA9IGZ1bmN0aW9uICgpIHtcbiAgICAgIHZtLnJlc291cmNlLnByb2plY3RfaWQgPSB2bS5wcm9qZWN0O1xuICAgIH07XG5cbiAgICB2bS52aWV3ID0gZnVuY3Rpb24gKHJlc291cmNlKSB7XG4gICAgICB2bS5yZXNvdXJjZSA9IHJlc291cmNlO1xuICAgICAgdm0ub25WaWV3ID0gdHJ1ZTtcbiAgICAgIHZtLnZpZXdGb3JtID0gZmFsc2U7XG4gICAgfTtcblxuICAgIHZtLmZpbmFsaXplID0gZnVuY3Rpb24gKHJlbGVhc2UpIHtcbiAgICAgIHZhciBjb25maXJtID0gJG1kRGlhbG9nLmNvbmZpcm0oKS50aXRsZSgnRmluYWxpemFyIFJlbGVhc2UnKS50ZXh0Q29udGVudCgnVGVtIGNlcnRlemEgcXVlIGRlc2VqYSBmaW5hbGl6YXIgYSByZWxlYXNlICcgKyByZWxlYXNlLnRpdGxlICsgJz8nKS5vaygnU2ltJykuY2FuY2VsKCdOw6NvJyk7XG5cbiAgICAgICRtZERpYWxvZy5zaG93KGNvbmZpcm0pLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICBSZWxlYXNlc1NlcnZpY2UuZmluYWxpemUoeyBwcm9qZWN0X2lkOiB2bS5wcm9qZWN0LCByZWxlYXNlX2lkOiByZWxlYXNlLmlkIH0pLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICAgIFByVG9hc3Quc3VjY2VzcygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnJlbGVhc2VFbmRlZFN1Y2Nlc3MnKSk7XG4gICAgICAgICAgdm0uc2VhcmNoKCk7XG4gICAgICAgIH0sIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICBQclRvYXN0LkVycm9yKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMucmVsZWFzZUVuZGVkRXJyb3InKSk7XG4gICAgICAgIH0pO1xuICAgICAgfSk7XG4gICAgfTtcblxuICAgIHZtLmZvcm1hdERhdGUgPSBmdW5jdGlvbiAoZGF0ZSkge1xuICAgICAgcmV0dXJuIG1vbWVudChkYXRlKS5mb3JtYXQoJ0REL01NL1lZWVknKTtcbiAgICB9O1xuXG4gICAgdm0uc2VhcmNoTWlsZXN0b25lID0gZnVuY3Rpb24gKG1pbGVzdG9uZVRlcm0pIHtcbiAgICAgIHJldHVybiBNaWxlc3RvbmVzU2VydmljZS5xdWVyeSh7XG4gICAgICAgIHJlbGVhc2VTZWFyY2g6IHRydWUsXG4gICAgICAgIHByb2plY3RfaWQ6IHZtLnJlc291cmNlLnByb2plY3RfaWQsXG4gICAgICAgIHRpdGxlOiBtaWxlc3RvbmVUZXJtXG4gICAgICB9KTtcbiAgICB9O1xuXG4gICAgdm0ub25NaWxlc3RvbmVDaGFuZ2UgPSBmdW5jdGlvbiAoKSB7XG4gICAgICBpZiAodm0ubWlsZXN0b25lICE9PSBudWxsICYmIHZtLnJlc291cmNlLm1pbGVzdG9uZXMuZmluZEluZGV4KGZ1bmN0aW9uIChpKSB7XG4gICAgICAgIHJldHVybiBpLmlkID09PSB2bS5taWxlc3RvbmUuaWQ7XG4gICAgICB9KSA9PT0gLTEpIHtcbiAgICAgICAgdm0ucmVzb3VyY2UubWlsZXN0b25lcy5wdXNoKHZtLm1pbGVzdG9uZSk7XG4gICAgICB9XG4gICAgfTtcblxuICAgIHZtLnJlbW92ZU1pbGVzdG9uZSA9IGZ1bmN0aW9uIChtaWxlc3RvbmUpIHtcbiAgICAgIHZtLnJlc291cmNlLm1pbGVzdG9uZXMuc2xpY2UoMCkuZm9yRWFjaChmdW5jdGlvbiAoZWxlbWVudCkge1xuICAgICAgICBpZiAoZWxlbWVudC5pZCA9PT0gbWlsZXN0b25lLmlkKSB7XG4gICAgICAgICAgdm0ucmVzb3VyY2UubWlsZXN0b25lcy5zcGxpY2Uodm0ucmVzb3VyY2UubWlsZXN0b25lcy5pbmRleE9mKGVsZW1lbnQpLCAxKTtcbiAgICAgICAgfVxuICAgICAgfSk7XG4gICAgfTtcblxuICAgIHZtLnNhdmVNaWxlc3RvbmVzID0gZnVuY3Rpb24gKCkge1xuICAgICAgTWlsZXN0b25lc1NlcnZpY2UudXBkYXRlUmVsZWFzZSh7IHByb2plY3RfaWQ6IHZtLnJlc291cmNlLnByb2plY3RfaWQsIHJlbGVhc2VfaWQ6IHZtLnJlc291cmNlLmlkLCBtaWxlc3RvbmVzOiB2bS5yZXNvdXJjZS5taWxlc3RvbmVzIH0pLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICBQclRvYXN0LnN1Y2Nlc3MoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5zYXZlU3VjY2VzcycpKTtcbiAgICAgICAgdm0udmlld0Zvcm0gPSBmYWxzZTtcbiAgICAgICAgdm0ub25WaWV3ID0gZmFsc2U7XG4gICAgICB9LCBmdW5jdGlvbiAoKSB7XG4gICAgICAgIFByVG9hc3QuZXJyb3IoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5vcGVyYXRpb25FcnJvcicpKTtcbiAgICAgIH0pO1xuICAgIH07XG5cbiAgICB2bS5lc3RpbWF0ZWRUaW1lID0gZnVuY3Rpb24gKG1pbGVzdG9uZSkge1xuICAgICAgbWlsZXN0b25lLmVzdGltYXRlZF90aW1lID0gMDtcbiAgICAgIGlmIChtaWxlc3RvbmUudGFza3MubGVuZ3RoID4gMCkge1xuICAgICAgICBtaWxlc3RvbmUudGFza3MuZm9yRWFjaChmdW5jdGlvbiAodGFzaykge1xuICAgICAgICAgIG1pbGVzdG9uZS5lc3RpbWF0ZWRfdGltZSArPSB0YXNrLmVzdGltYXRlZF90aW1lO1xuICAgICAgICB9KTtcbiAgICAgIH1cbiAgICAgIHJldHVybiBtaWxlc3RvbmUuZXN0aW1hdGVkX3RpbWUgLyA4O1xuICAgIH07XG5cbiAgICAvLyBpbnN0YW50aWF0ZSBiYXNlIGNvbnRyb2xsZXJcbiAgICAkY29udHJvbGxlcignQ1JVRENvbnRyb2xsZXInLCB7IHZtOiB2bSwgbW9kZWxTZXJ2aWNlOiBSZWxlYXNlc1NlcnZpY2UsIG9wdGlvbnM6IHt9IH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKlxuICAgKiBBcnF1aXZvIGRlIGNvbmZpZ3VyYcOnw6NvIGNvbSBhcyByb3RhcyBlc3BlY8OtZmljYXMgZG8gcmVjdXJzbyByZWxlYXNlc1xuICAgKlxuICAgKiBAcGFyYW0ge29iamVjdH0gJHN0YXRlUHJvdmlkZXJcbiAgICogQHBhcmFtIHtvYmplY3R9IEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdhcHAucmVsZWFzZXMnLCB7XG4gICAgICB1cmw6ICcvcmVsZWFzZXMnLFxuICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9yZWxlYXNlcy9yZWxlYXNlcy5odG1sJyxcbiAgICAgIGNvbnRyb2xsZXI6ICdSZWxlYXNlc0NvbnRyb2xsZXIgYXMgcmVsZWFzZXNDdHJsJyxcbiAgICAgIGRhdGE6IHt9XG4gICAgfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmFjdG9yeSgnUmVsZWFzZXNTZXJ2aWNlJywgUmVsZWFzZXNTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIFJlbGVhc2VzU2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHZhciBtb2RlbCA9IHNlcnZpY2VGYWN0b3J5KCdyZWxlYXNlcycsIHtcbiAgICAgIGFjdGlvbnM6IHtcbiAgICAgICAgZmluYWxpemU6IHtcbiAgICAgICAgICBtZXRob2Q6ICdQT1NUJyxcbiAgICAgICAgICB1cmw6ICdmaW5hbGl6ZSdcbiAgICAgICAgfVxuICAgICAgfSxcbiAgICAgIGluc3RhbmNlOiB7fVxuICAgIH0pO1xuXG4gICAgcmV0dXJuIG1vZGVsO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmlsdGVyKCdyb2xlc1N0cicsIHJvbGVzU3RyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvbGVzU3RyKGxvZGFzaCkge1xuICAgIC8qKlxuICAgICAqIEBwYXJhbSB7YXJyYXl9IHJvbGVzIGxpc3RhIGRlIHBlcmZpc1xuICAgICAqIEByZXR1cm4ge3N0cmluZ30gcGVyZmlzIHNlcGFyYWRvcyBwb3IgJywgJyAgXG4gICAgICovXG4gICAgcmV0dXJuIGZ1bmN0aW9uIChyb2xlcykge1xuICAgICAgcmV0dXJuIGxvZGFzaC5tYXAocm9sZXMsICdzbHVnJykuam9pbignLCAnKTtcbiAgICB9O1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZhY3RvcnkoJ1JvbGVzU2VydmljZScsIFJvbGVzU2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiBSb2xlc1NlcnZpY2Uoc2VydmljZUZhY3RvcnkpIHtcbiAgICByZXR1cm4gc2VydmljZUZhY3RvcnkoJ3JvbGVzJyk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmFjdG9yeSgnU3RhdHVzU2VydmljZScsIFN0YXR1c1NlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gU3RhdHVzU2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHZhciBtb2RlbCA9IHNlcnZpY2VGYWN0b3J5KCdzdGF0dXMnLCB7XG4gICAgICBhY3Rpb25zOiB7fSxcbiAgICAgIGluc3RhbmNlOiB7fVxuICAgIH0pO1xuXG4gICAgcmV0dXJuIG1vZGVsO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZhY3RvcnkoJ1N1cHBvcnRTZXJ2aWNlJywgU3VwcG9ydFNlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gU3VwcG9ydFNlcnZpY2Uoc2VydmljZUZhY3RvcnkpIHtcbiAgICByZXR1cm4gc2VydmljZUZhY3RvcnkoJ3N1cHBvcnQnLCB7XG4gICAgICBhY3Rpb25zOiB7XG4gICAgICAgIC8qKlxuICAgICAgICAgKiBQZWdhIGFzIHRyYWR1w6fDtWVzIHF1ZSBlc3TDo28gbm8gc2Vydmlkb3JcbiAgICAgICAgICpcbiAgICAgICAgICogQHJldHVybnMge3Byb21pc2V9IFVtYSBwcm9taXNlIGNvbSBvIHJlc3VsdGFkbyBkbyBjaGFtYWRhIG5vIGJhY2tlbmRcbiAgICAgICAgICovXG4gICAgICAgIGxhbmdzOiB7XG4gICAgICAgICAgbWV0aG9kOiAnR0VUJyxcbiAgICAgICAgICB1cmw6ICdsYW5ncycsXG4gICAgICAgICAgd3JhcDogZmFsc2UsXG4gICAgICAgICAgY2FjaGU6IHRydWVcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZhY3RvcnkoJ1Rhc2tDb21tZW50c1NlcnZpY2UnLCBUYXNrQ29tbWVudHNTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIFRhc2tDb21tZW50c1NlcnZpY2Uoc2VydmljZUZhY3RvcnkpIHtcbiAgICB2YXIgbW9kZWwgPSBzZXJ2aWNlRmFjdG9yeSgndGFzay1jb21tZW50cycsIHtcbiAgICAgIGFjdGlvbnM6IHtcbiAgICAgICAgc2F2ZVRhc2tDb21tZW50OiB7XG4gICAgICAgICAgbWV0aG9kOiAnUE9TVCcsXG4gICAgICAgICAgdXJsOiAnc2F2ZVRhc2tDb21tZW50J1xuICAgICAgICB9LFxuICAgICAgICByZW1vdmVUYXNrQ29tbWVudDoge1xuICAgICAgICAgIG1ldGhvZDogJ1BPU1QnLFxuICAgICAgICAgIHVybDogJ3JlbW92ZVRhc2tDb21tZW50J1xuICAgICAgICB9XG4gICAgICB9LFxuICAgICAgaW5zdGFuY2U6IHt9XG4gICAgfSk7XG5cbiAgICByZXR1cm4gbW9kZWw7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5maWx0ZXIoJ2VsYXBzZWQnLCBmdW5jdGlvbiAoKSB7XG4gICAgcmV0dXJuIGZ1bmN0aW9uIChkYXRlKSB7XG4gICAgICBpZiAoIWRhdGUpIHJldHVybjtcbiAgICAgIHZhciB0aW1lID0gRGF0ZS5wYXJzZShkYXRlKSxcbiAgICAgICAgICB0aW1lTm93ID0gbmV3IERhdGUoKS5nZXRUaW1lKCksXG4gICAgICAgICAgZGlmZmVyZW5jZSA9IHRpbWVOb3cgLSB0aW1lLFxuICAgICAgICAgIHNlY29uZHMgPSBNYXRoLmZsb29yKGRpZmZlcmVuY2UgLyAxMDAwKSxcbiAgICAgICAgICBtaW51dGVzID0gTWF0aC5mbG9vcihzZWNvbmRzIC8gNjApLFxuICAgICAgICAgIGhvdXJzID0gTWF0aC5mbG9vcihtaW51dGVzIC8gNjApLFxuICAgICAgICAgIGRheXMgPSBNYXRoLmZsb29yKGhvdXJzIC8gMjQpLFxuICAgICAgICAgIG1vbnRocyA9IE1hdGguZmxvb3IoZGF5cyAvIDMwKTtcblxuICAgICAgaWYgKG1vbnRocyA+IDEpIHtcbiAgICAgICAgcmV0dXJuIG1vbnRocyArICcgbWVzZXMgYXRyw6FzJztcbiAgICAgIH0gZWxzZSBpZiAobW9udGhzID09PSAxKSB7XG4gICAgICAgIHJldHVybiAnMSBtw6pzIGF0csOhcyc7XG4gICAgICB9IGVsc2UgaWYgKGRheXMgPiAxKSB7XG4gICAgICAgIHJldHVybiBkYXlzICsgJyBkaWFzIGF0csOhcyc7XG4gICAgICB9IGVsc2UgaWYgKGRheXMgPT09IDEpIHtcbiAgICAgICAgcmV0dXJuICcxIGRpYSBhdHLDoXMnO1xuICAgICAgfSBlbHNlIGlmIChob3VycyA+IDEpIHtcbiAgICAgICAgcmV0dXJuIGhvdXJzICsgJyBob3JhcyBhdHLDoXMnO1xuICAgICAgfSBlbHNlIGlmIChob3VycyA9PT0gMSkge1xuICAgICAgICByZXR1cm4gJ3VtYSBob3JhIGF0csOhcyc7XG4gICAgICB9IGVsc2UgaWYgKG1pbnV0ZXMgPiAxKSB7XG4gICAgICAgIHJldHVybiBtaW51dGVzICsgJyBtaW51dG9zIGF0csOhcyc7XG4gICAgICB9IGVsc2UgaWYgKG1pbnV0ZXMgPT09IDEpIHtcbiAgICAgICAgcmV0dXJuICd1bSBtaW51dG8gYXRyw6FzJztcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHJldHVybiAnaMOhIHBvdWNvcyBzZWd1bmRvcyc7XG4gICAgICB9XG4gICAgfTtcbiAgfSkuY29udHJvbGxlcignVGFza3NDb250cm9sbGVyJywgVGFza3NDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIFRhc2tzQ29udHJvbGxlcigkY29udHJvbGxlciwgVGFza3NTZXJ2aWNlLCBTdGF0dXNTZXJ2aWNlLCBQcmlvcml0aWVzU2VydmljZSwgVHlwZXNTZXJ2aWNlLCBUYXNrQ29tbWVudHNTZXJ2aWNlLCBQcm9qZWN0c1NlcnZpY2UsIG1vbWVudCwgQXV0aCwgUHJUb2FzdCwgJHRyYW5zbGF0ZSwgJGZpbHRlciwgR2xvYmFsKSB7XG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIC8vQXR0cmlidXRlcyBCbG9ja1xuXG4gICAgLy9GdW5jdGlvbnMgQmxvY2tcbiAgICB2bS5vbkFjdGl2YXRlID0gb25BY3RpdmF0ZTtcbiAgICB2bS5hcHBseUZpbHRlcnMgPSBhcHBseUZpbHRlcnM7XG4gICAgdm0uYmVmb3JlU2F2ZSA9IGJlZm9yZVNhdmU7XG4gICAgdm0uYmVmb3JlUmVtb3ZlID0gYmVmb3JlUmVtb3ZlO1xuXG4gICAgZnVuY3Rpb24gb25BY3RpdmF0ZSgpIHtcbiAgICAgIHZtLmN1cnJlbnRVc2VyID0gQXV0aC5jdXJyZW50VXNlcjtcbiAgICAgIHZtLmltYWdlUGF0aCA9IEdsb2JhbC5pbWFnZVBhdGggKyAnL25vX2F2YXRhci5naWYnO1xuICAgICAgdm0ucHJvamVjdCA9IGxvY2FsU3RvcmFnZS5nZXRJdGVtKCdwcm9qZWN0Jyk7XG4gICAgICBQcm9qZWN0c1NlcnZpY2UucXVlcnkoeyBwcm9qZWN0X2lkOiB2bS5wcm9qZWN0IH0pLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgIHZtLmFjdHVhbFByb2plY3QgPSByZXNwb25zZVswXTtcbiAgICAgIH0pO1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0geyBwcm9qZWN0X2lkOiB2bS5wcm9qZWN0IH07XG5cbiAgICAgIFN0YXR1c1NlcnZpY2UucXVlcnkoKS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICB2bS5zdGF0dXMgPSByZXNwb25zZTtcbiAgICAgIH0pO1xuXG4gICAgICBQcmlvcml0aWVzU2VydmljZS5xdWVyeSgpLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgIHZtLnByaW9yaXRpZXMgPSByZXNwb25zZTtcbiAgICAgIH0pO1xuXG4gICAgICBUeXBlc1NlcnZpY2UucXVlcnkoKS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICB2bS50eXBlcyA9IHJlc3BvbnNlO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gYXBwbHlGaWx0ZXJzKGRlZmF1bHRRdWVyeUZpbHRlcnMpIHtcbiAgICAgIHJldHVybiBhbmd1bGFyLmV4dGVuZChkZWZhdWx0UXVlcnlGaWx0ZXJzLCB2bS5xdWVyeUZpbHRlcnMpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGJlZm9yZVNhdmUoKSB7XG4gICAgICB2bS5yZXNvdXJjZS5wcm9qZWN0X2lkID0gdm0ucHJvamVjdDtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBiZWZvcmVSZW1vdmUoKSB7XG4gICAgICB2bS5yZXNvdXJjZS5wcm9qZWN0X2lkID0gdm0ucHJvamVjdDtcbiAgICB9XG5cbiAgICB2bS52aWV3ID0gZnVuY3Rpb24gKHJlc291cmNlKSB7XG4gICAgICB2bS5yZXNvdXJjZSA9IHJlc291cmNlO1xuICAgICAgdm0ub25WaWV3ID0gdHJ1ZTtcbiAgICAgIHZtLnZpZXdGb3JtID0gZmFsc2U7XG4gICAgfTtcblxuICAgIHZtLnNhdmVDb21tZW50ID0gZnVuY3Rpb24gKGNvbW1lbnQpIHtcbiAgICAgIHZhciBkZXNjcmlwdGlvbiA9ICcnO1xuICAgICAgdmFyIGNvbW1lbnRfaWQgPSBudWxsO1xuXG4gICAgICBpZiAoY29tbWVudCkge1xuICAgICAgICBkZXNjcmlwdGlvbiA9IHZtLmFuc3dlcjtcbiAgICAgICAgY29tbWVudF9pZCA9IGNvbW1lbnQuaWQ7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBkZXNjcmlwdGlvbiA9IHZtLmNvbW1lbnQ7XG4gICAgICB9XG4gICAgICBUYXNrQ29tbWVudHNTZXJ2aWNlLnNhdmVUYXNrQ29tbWVudCh7IHByb2plY3RfaWQ6IHZtLnByb2plY3QsIHRhc2tfaWQ6IHZtLnJlc291cmNlLmlkLCBjb21tZW50X3RleHQ6IGRlc2NyaXB0aW9uLCBjb21tZW50X2lkOiBjb21tZW50X2lkIH0pLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICB2bS5jb21tZW50ID0gJyc7XG4gICAgICAgIHZtLmFuc3dlciA9ICcnO1xuICAgICAgICB2bS5zZWFyY2goKTtcbiAgICAgICAgUHJUb2FzdC5zdWNjZXNzKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMuc2F2ZVN1Y2Nlc3MnKSk7XG4gICAgICB9LCBmdW5jdGlvbiAoKSB7XG4gICAgICAgIFByVG9hc3QuZXJyb3IoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5vcGVyYXRpb25FcnJvcicpKTtcbiAgICAgIH0pO1xuICAgIH07XG5cbiAgICB2bS5yZW1vdmVDb21tZW50ID0gZnVuY3Rpb24gKGNvbW1lbnQpIHtcbiAgICAgIFRhc2tDb21tZW50c1NlcnZpY2UucmVtb3ZlVGFza0NvbW1lbnQoeyBjb21tZW50X2lkOiBjb21tZW50LmlkIH0pLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICB2bS5zZWFyY2goKTtcbiAgICAgICAgUHJUb2FzdC5zdWNjZXNzKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMucmVtb3ZlU3VjY2VzcycpKTtcbiAgICAgIH0sIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgUHJUb2FzdC5lcnJvcigkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLm9wZXJhdGlvbkVycm9yJykpO1xuICAgICAgfSk7XG4gICAgfTtcblxuICAgIHZtLmFmdGVyU2VhcmNoID0gZnVuY3Rpb24gKCkge1xuICAgICAgaWYgKHZtLnJlc291cmNlLmlkKSB7XG4gICAgICAgIHZtLnJlc291cmNlID0gJGZpbHRlcignZmlsdGVyJykodm0ucmVzb3VyY2VzLCB7IGlkOiB2bS5yZXNvdXJjZS5pZCB9KVswXTtcbiAgICAgIH1cbiAgICB9O1xuXG4gICAgdm0uZml4RGF0ZSA9IGZ1bmN0aW9uIChkYXRlU3RyaW5nKSB7XG4gICAgICByZXR1cm4gbW9tZW50KGRhdGVTdHJpbmcpO1xuICAgIH07XG5cbiAgICAvLyBpbnN0YW50aWF0ZSBiYXNlIGNvbnRyb2xsZXJcbiAgICAkY29udHJvbGxlcignQ1JVRENvbnRyb2xsZXInLCB7IHZtOiB2bSwgbW9kZWxTZXJ2aWNlOiBUYXNrc1NlcnZpY2UsIG9wdGlvbnM6IHsgc2tpcFBhZ2luYXRpb246IHRydWUgfSB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25maWcocm91dGVzKTtcblxuICAvKipcbiAgICogQXJxdWl2byBkZSBjb25maWd1cmHDp8OjbyBjb20gYXMgcm90YXMgZXNwZWPDrWZpY2FzIGRvIHJlY3Vyc28gcHJvamVjdFxuICAgKlxuICAgKiBAcGFyYW0ge2FueX0gJHN0YXRlUHJvdmlkZXJcbiAgICogQHBhcmFtIHthbnl9IEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdhcHAudGFza3MnLCB7XG4gICAgICB1cmw6ICcvdGFza3MnLFxuICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy90YXNrcy90YXNrcy5odG1sJyxcbiAgICAgIGNvbnRyb2xsZXI6ICdUYXNrc0NvbnRyb2xsZXIgYXMgdGFza3NDdHJsJyxcbiAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiB0cnVlIH1cbiAgICB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5mYWN0b3J5KCdUYXNrc1NlcnZpY2UnLCBUYXNrc1NlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gVGFza3NTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCd0YXNrcycsIHtcbiAgICAgIGFjdGlvbnM6IHtcbiAgICAgICAgdXBkYXRlTWlsZXN0b25lOiB7XG4gICAgICAgICAgbWV0aG9kOiAnUE9TVCcsXG4gICAgICAgICAgdXJsOiAndXBkYXRlTWlsZXN0b25lJ1xuICAgICAgICB9LFxuICAgICAgICB1cGRhdGVUYXNrQnlLYW5iYW46IHtcbiAgICAgICAgICBtZXRob2Q6ICdQT1NUJyxcbiAgICAgICAgICB1cmw6ICd1cGRhdGVUYXNrQnlLYW5iYW4nXG4gICAgICAgIH1cbiAgICAgIH0sXG4gICAgICBpbnN0YW5jZToge31cbiAgICB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5mYWN0b3J5KCdUeXBlc1NlcnZpY2UnLCBUeXBlc1NlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gVHlwZXNTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgdmFyIG1vZGVsID0gc2VydmljZUZhY3RvcnkoJ3R5cGVzJywge1xuICAgICAgYWN0aW9uczoge30sXG4gICAgICBpbnN0YW5jZToge31cbiAgICB9KTtcblxuICAgIHJldHVybiBtb2RlbDtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbnRyb2xsZXIoJ1Byb2ZpbGVDb250cm9sbGVyJywgUHJvZmlsZUNvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gUHJvZmlsZUNvbnRyb2xsZXIoVXNlcnNTZXJ2aWNlLCBBdXRoLCBQclRvYXN0LCAkdHJhbnNsYXRlLCAkd2luZG93LCBtb21lbnQpIHtcbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0udXBkYXRlID0gdXBkYXRlO1xuICAgIHZtLmhpc3RvcnlCYWNrID0gaGlzdG9yeUJhY2s7XG5cbiAgICBhY3RpdmF0ZSgpO1xuXG4gICAgZnVuY3Rpb24gYWN0aXZhdGUoKSB7XG4gICAgICB2bS51c2VyID0gYW5ndWxhci5jb3B5KEF1dGguY3VycmVudFVzZXIpO1xuICAgICAgaWYgKHZtLnVzZXIuYmlydGhkYXkpIHtcbiAgICAgICAgdm0udXNlci5iaXJ0aGRheSA9IG1vbWVudCh2bS51c2VyLmJpcnRoZGF5KS5mb3JtYXQoJ0REL01NL1lZWVknKTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICBmdW5jdGlvbiB1cGRhdGUoKSB7XG4gICAgICBpZiAodm0udXNlci5iaXJ0aGRheSkge1xuICAgICAgICB2bS51c2VyLmJpcnRoZGF5ID0gbW9tZW50KHZtLnVzZXIuYmlydGhkYXkpO1xuICAgICAgfVxuICAgICAgVXNlcnNTZXJ2aWNlLnVwZGF0ZVByb2ZpbGUodm0udXNlcikudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgLy9hdHVhbGl6YSBvIHVzdcOhcmlvIGNvcnJlbnRlIGNvbSBhcyBub3ZhcyBpbmZvcm1hw6fDtWVzXG4gICAgICAgIEF1dGgudXBkYXRlQ3VycmVudFVzZXIocmVzcG9uc2UpO1xuICAgICAgICBQclRvYXN0LnN1Y2Nlc3MoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5zYXZlU3VjY2VzcycpKTtcbiAgICAgICAgaGlzdG9yeUJhY2soKTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGhpc3RvcnlCYWNrKCkge1xuICAgICAgJHdpbmRvdy5oaXN0b3J5LmJhY2soKTtcbiAgICB9XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb250cm9sbGVyKCdVc2Vyc0NvbnRyb2xsZXInLCBVc2Vyc0NvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gVXNlcnNDb250cm9sbGVyKCRjb250cm9sbGVyLCBVc2Vyc1NlcnZpY2UsIFByVG9hc3QsICRtZERpYWxvZywgJHRyYW5zbGF0ZSkge1xuXG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIHZtLm9uQWN0aXZhdGUgPSBvbkFjdGl2YXRlO1xuICAgIC8vIGluc3RhbnRpYXRlIGJhc2UgY29udHJvbGxlclxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHsgdm06IHZtLCBtb2RlbFNlcnZpY2U6IFVzZXJzU2VydmljZSwgb3B0aW9uczoge30gfSk7XG5cbiAgICBmdW5jdGlvbiBvbkFjdGl2YXRlKCkge1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0ge307XG4gICAgfVxuXG4gICAgdm0uaGlkZURpYWxvZyA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICRtZERpYWxvZy5oaWRlKCk7XG4gICAgfTtcblxuICAgIHZtLnNhdmVOZXdVc2VyID0gZnVuY3Rpb24gKCkge1xuICAgICAgdm0ucmVzb3VyY2UuJHNhdmUoKS50aGVuKGZ1bmN0aW9uIChyZXNvdXJjZSkge1xuICAgICAgICB2bS5yZXNvdXJjZSA9IHJlc291cmNlO1xuICAgICAgICBQclRvYXN0LnN1Y2Nlc3MoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5zdWNjZXNzU2lnblVwJykpO1xuICAgICAgICAkbWREaWFsb2cuaGlkZSgpO1xuICAgICAgfSk7XG4gICAgfTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25maWcocm91dGVzKTtcblxuICAvKipcbiAgICogQXJxdWl2byBkZSBjb25maWd1cmHDp8OjbyBjb20gYXMgcm90YXMgZXNwZWPDrWZpY2FzIGRvIHJlY3Vyc28gdXNlclxuICAgKlxuICAgKiBAcGFyYW0ge2FueX0gJHN0YXRlUHJvdmlkZXJcbiAgICogQHBhcmFtIHthbnl9IEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdhcHAudXNlcicsIHtcbiAgICAgIHVybDogJy91c3VhcmlvJyxcbiAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvdXNlcnMvdXNlcnMuaHRtbCcsXG4gICAgICBjb250cm9sbGVyOiAnVXNlcnNDb250cm9sbGVyIGFzIHVzZXJzQ3RybCcsXG4gICAgICBkYXRhOiB7IG5lZWRBdXRoZW50aWNhdGlvbjogdHJ1ZSwgbmVlZFByb2ZpbGU6IFsnYWRtaW4nXSB9XG4gICAgfSkuc3RhdGUoJ2FwcC51c2VyLXByb2ZpbGUnLCB7XG4gICAgICB1cmw6ICcvdXN1YXJpby9wZXJmaWwnLFxuICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy91c2Vycy9wcm9maWxlLmh0bWwnLFxuICAgICAgY29udHJvbGxlcjogJ1Byb2ZpbGVDb250cm9sbGVyIGFzIHByb2ZpbGVDdHJsJyxcbiAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiB0cnVlIH1cbiAgICB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5mYWN0b3J5KCdVc2Vyc1NlcnZpY2UnLCBVc2Vyc1NlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gVXNlcnNTZXJ2aWNlKGxvZGFzaCwgR2xvYmFsLCBzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHJldHVybiBzZXJ2aWNlRmFjdG9yeSgndXNlcnMnLCB7XG4gICAgICAvL3F1YW5kbyBpbnN0YW5jaWEgdW0gdXN1w6FyaW8gc2VtIHBhc3NhciBwYXJhbWV0cm8sXG4gICAgICAvL28gbWVzbW8gdmFpIHRlciBvcyB2YWxvcmVzIGRlZmF1bHRzIGFiYWl4b1xuICAgICAgZGVmYXVsdHM6IHtcbiAgICAgICAgcm9sZXM6IFtdXG4gICAgICB9LFxuXG4gICAgICBhY3Rpb25zOiB7XG4gICAgICAgIC8qKlxuICAgICAgICAgKiBTZXJ2acOnbyBxdWUgYXR1YWxpemEgb3MgZGFkb3MgZG8gcGVyZmlsIGRvIHVzdcOhcmlvIGxvZ2Fkb1xuICAgICAgICAgKlxuICAgICAgICAgKiBAcGFyYW0ge29iamVjdH0gYXR0cmlidXRlc1xuICAgICAgICAgKiBAcmV0dXJucyB7cHJvbWlzZX0gVW1hIHByb21pc2UgY29tIG8gcmVzdWx0YWRvIGRvIGNoYW1hZGEgbm8gYmFja2VuZFxuICAgICAgICAgKi9cbiAgICAgICAgdXBkYXRlUHJvZmlsZToge1xuICAgICAgICAgIG1ldGhvZDogJ1BVVCcsXG4gICAgICAgICAgdXJsOiBHbG9iYWwuYXBpUGF0aCArICcvcHJvZmlsZScsXG4gICAgICAgICAgb3ZlcnJpZGU6IHRydWUsXG4gICAgICAgICAgd3JhcDogZmFsc2VcbiAgICAgICAgfVxuICAgICAgfSxcblxuICAgICAgaW5zdGFuY2U6IHtcbiAgICAgICAgLyoqXG4gICAgICAgICAqIFZlcmlmaWNhIHNlIG8gdXN1w6FyaW8gdGVtIG9zIHBlcmZpcyBpbmZvcm1hZG9zLlxuICAgICAgICAgKlxuICAgICAgICAgKiBAcGFyYW0ge2FueX0gcm9sZXMgcGVyZmlzIGEgc2VyZW0gdmVyaWZpY2Fkb3NcbiAgICAgICAgICogQHBhcmFtIHtib29sZWFufSBhbGwgZmxhZyBwYXJhIGluZGljYXIgc2UgdmFpIGNoZWdhciB0b2RvcyBvcyBwZXJmaXMgb3Ugc29tZW50ZSB1bSBkZWxlc1xuICAgICAgICAgKiBAcmV0dXJucyB7Ym9vbGVhbn1cbiAgICAgICAgICovXG4gICAgICAgIGhhc1Byb2ZpbGU6IGZ1bmN0aW9uIGhhc1Byb2ZpbGUocm9sZXMsIGFsbCkge1xuICAgICAgICAgIHJvbGVzID0gYW5ndWxhci5pc0FycmF5KHJvbGVzKSA/IHJvbGVzIDogW3JvbGVzXTtcblxuICAgICAgICAgIHZhciB1c2VyUm9sZXMgPSBsb2Rhc2gubWFwKHRoaXMucm9sZXMsICdzbHVnJyk7XG5cbiAgICAgICAgICBpZiAoYWxsKSB7XG4gICAgICAgICAgICByZXR1cm4gbG9kYXNoLmludGVyc2VjdGlvbih1c2VyUm9sZXMsIHJvbGVzKS5sZW5ndGggPT09IHJvbGVzLmxlbmd0aDtcbiAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgLy9yZXR1cm4gdGhlIGxlbmd0aCBiZWNhdXNlIDAgaXMgZmFsc2UgaW4ganNcbiAgICAgICAgICAgIHJldHVybiBsb2Rhc2guaW50ZXJzZWN0aW9uKHVzZXJSb2xlcywgcm9sZXMpLmxlbmd0aDtcbiAgICAgICAgICB9XG4gICAgICAgIH0sXG5cbiAgICAgICAgLyoqXG4gICAgICAgICAqIFZlcmlmaWNhIHNlIG8gdXN1w6FyaW8gdGVtIG8gcGVyZmlsIGFkbWluLlxuICAgICAgICAgKlxuICAgICAgICAgKiBAcmV0dXJucyB7Ym9vbGVhbn1cbiAgICAgICAgICovXG4gICAgICAgIGlzQWRtaW46IGZ1bmN0aW9uIGlzQWRtaW4oKSB7XG4gICAgICAgICAgcmV0dXJuIHRoaXMuaGFzUHJvZmlsZSgnYWRtaW4nKTtcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4vL3Rva2VuIGNhY2I5MTIzNTg3M2E4YzQ4NzVkMjM1NzhhYzlmMzI2ZWY4OTRiNjZcbi8vIE9BdHV0aCBodHRwczovL2dpdGh1Yi5jb20vbG9naW4vb2F1dGgvYXV0aG9yaXplP2NsaWVudF9pZD04Mjk0NjhlN2ZkZWU3OTQ0NWJhNiZzY29wZT11c2VyLHB1YmxpY19yZXBvJnJlZGlyZWN0X3VyaT1odHRwOi8vMC4wLjAuMDo1MDAwLyMhL2FwcC92Y3NcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5maWx0ZXIoJ2J5dGVzJywgZnVuY3Rpb24gKCkge1xuICAgIHJldHVybiBmdW5jdGlvbiAoYnl0ZXMsIHByZWNpc2lvbikge1xuICAgICAgaWYgKGlzTmFOKHBhcnNlRmxvYXQoYnl0ZXMpKSB8fCAhaXNGaW5pdGUoYnl0ZXMpKSByZXR1cm4gJy0nO1xuICAgICAgaWYgKHR5cGVvZiBwcmVjaXNpb24gPT09ICd1bmRlZmluZWQnKSBwcmVjaXNpb24gPSAxO1xuICAgICAgdmFyIHVuaXRzID0gWydieXRlcycsICdrQicsICdNQicsICdHQicsICdUQicsICdQQiddLFxuICAgICAgICAgIG51bWJlciA9IE1hdGguZmxvb3IoTWF0aC5sb2coYnl0ZXMpIC8gTWF0aC5sb2coMTAyNCkpO1xuXG4gICAgICByZXR1cm4gKGJ5dGVzIC8gTWF0aC5wb3coMTAyNCwgTWF0aC5mbG9vcihudW1iZXIpKSkudG9GaXhlZChwcmVjaXNpb24pICsgJyAnICsgdW5pdHNbbnVtYmVyXTtcbiAgICB9O1xuICB9KS5jb250cm9sbGVyKCdWY3NDb250cm9sbGVyJywgVmNzQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBWY3NDb250cm9sbGVyKCRjb250cm9sbGVyLCBWY3NTZXJ2aWNlLCAkd2luZG93LCBQcm9qZWN0c1NlcnZpY2UsIFByVG9hc3QsICR0cmFuc2xhdGUpIHtcbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0uaW5kZXggPSAwO1xuICAgIHZtLnBhdGhzID0gW107XG5cbiAgICAvL0F0dHJpYnV0ZXMgQmxvY2tcblxuICAgIC8vRnVuY3Rpb25zIEJsb2NrXG4gICAgdm0ub25BY3RpdmF0ZSA9IGZ1bmN0aW9uICgpIHtcbiAgICAgIHRvZ2dsZVNwbGFzaFNjcmVlbigpO1xuICAgICAgUHJvamVjdHNTZXJ2aWNlLnF1ZXJ5KHsgcHJvamVjdF9pZDogbG9jYWxTdG9yYWdlLmdldEl0ZW0oJ3Byb2plY3QnKSB9KS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICB2bS51c2VybmFtZSA9IHJlc3BvbnNlWzBdLnVzZXJuYW1lX2dpdGh1YjtcbiAgICAgICAgdm0ucmVwbyA9IHJlc3BvbnNlWzBdLnJlcG9fZ2l0aHViO1xuICAgICAgICBpZiAodm0udXNlcm5hbWUgJiYgdm0ucmVwbykge1xuICAgICAgICAgIHZtLnF1ZXJ5RmlsdGVycyA9IHtcbiAgICAgICAgICAgIHVzZXJuYW1lOiB2bS51c2VybmFtZSxcbiAgICAgICAgICAgIHJlcG86IHZtLnJlcG8sXG4gICAgICAgICAgICBwYXRoOiAnLidcbiAgICAgICAgICB9O1xuICAgICAgICAgIHZtLnBhdGhzLnB1c2godm0ucXVlcnlGaWx0ZXJzLnBhdGgpO1xuICAgICAgICAgIHZtLnNlYXJjaCgpO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICR3aW5kb3cubG9hZGluZ19zY3JlZW4uZmluaXNoKCk7XG4gICAgICAgIH1cbiAgICAgIH0pO1xuICAgIH07XG5cbiAgICB2bS5hcHBseUZpbHRlcnMgPSBmdW5jdGlvbiAoZGVmYXVsdFF1ZXJ5RmlsdGVycykge1xuICAgICAgcmV0dXJuIGFuZ3VsYXIuZXh0ZW5kKGRlZmF1bHRRdWVyeUZpbHRlcnMsIHZtLnF1ZXJ5RmlsdGVycyk7XG4gICAgfTtcblxuICAgIHZtLmFmdGVyU2VhcmNoID0gZnVuY3Rpb24gKCkge1xuICAgICAgc29ydFJlc291cmNlcygpO1xuICAgICAgJHdpbmRvdy5sb2FkaW5nX3NjcmVlbi5maW5pc2goKTtcbiAgICB9O1xuXG4gICAgZnVuY3Rpb24gc29ydFJlc291cmNlcygpIHtcbiAgICAgIGlmICh2bS5yZXNvdXJjZXMubGVuZ3RoID4gMCkge1xuICAgICAgICB2bS5yZXNvdXJjZXMuc29ydChmdW5jdGlvbiAoYSwgYikge1xuICAgICAgICAgIHJldHVybiBhLnR5cGUgPCBiLnR5cGUgPyAtMSA6IGEudHlwZSA+IGIudHlwZSA/IDEgOiAwO1xuICAgICAgICB9KTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICB2bS5vcGVuRmlsZU9yRGlyZWN0b3J5ID0gZnVuY3Rpb24gKHJlc291cmNlKSB7XG4gICAgICB0b2dnbGVTcGxhc2hTY3JlZW4oKTtcbiAgICAgIGlmIChyZXNvdXJjZSkge1xuICAgICAgICB2bS5xdWVyeUZpbHRlcnMucGF0aCA9IHJlc291cmNlLnBhdGg7XG4gICAgICAgIHZtLnBhdGhzLnB1c2godm0ucXVlcnlGaWx0ZXJzLnBhdGgpO1xuICAgICAgICB2bS5pbmRleCsrO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgdm0ucXVlcnlGaWx0ZXJzLnBhdGggPSB2bS5wYXRoc1t2bS5pbmRleCAtIDFdO1xuICAgICAgICB2bS5wYXRocy5zcGxpY2Uodm0uaW5kZXgsIDEpO1xuICAgICAgICB2bS5pbmRleC0tO1xuICAgICAgfVxuICAgICAgdm0uc2VhcmNoKCk7XG4gICAgfTtcblxuICAgIHZtLm9uU2VhcmNoRXJyb3IgPSBmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgIGlmIChyZXNwb25zZS5kYXRhLmVycm9yID09PSAnTm90IEZvdW5kJykge1xuICAgICAgICBQclRvYXN0LmluZm8oJHRyYW5zbGF0ZS5pbnN0YW50KCdSZXBvc2l0w7NyaW8gbsOjbyBlbmNvbnRyYWRvJykpO1xuICAgICAgICAkd2luZG93LmxvYWRpbmdfc2NyZWVuLmZpbmlzaCgpO1xuICAgICAgfVxuICAgIH07XG5cbiAgICAvKipcbiAgICAgKiBNw6l0b2RvIHBhcmEgbW9zdHJhciBhIHRlbGEgZGUgZXNwZXJhXG4gICAgICovXG4gICAgZnVuY3Rpb24gdG9nZ2xlU3BsYXNoU2NyZWVuKCkge1xuICAgICAgJHdpbmRvdy5sb2FkaW5nX3NjcmVlbiA9ICR3aW5kb3cucGxlYXNlV2FpdCh7XG4gICAgICAgIGxvZ286ICcnLFxuICAgICAgICBiYWNrZ3JvdW5kQ29sb3I6ICdyZ2JhKDI1NSwyNTUsMjU1LDAuNCknLFxuICAgICAgICBsb2FkaW5nSHRtbDogJzxkaXYgY2xhc3M9XCJzcGlubmVyXCI+ICcgKyAnICA8ZGl2IGNsYXNzPVwicmVjdDFcIj48L2Rpdj4gJyArICcgIDxkaXYgY2xhc3M9XCJyZWN0MlwiPjwvZGl2PiAnICsgJyAgPGRpdiBjbGFzcz1cInJlY3QzXCI+PC9kaXY+ICcgKyAnICA8ZGl2IGNsYXNzPVwicmVjdDRcIj48L2Rpdj4gJyArICcgIDxkaXYgY2xhc3M9XCJyZWN0NVwiPjwvZGl2PiAnICsgJyA8cCBjbGFzcz1cImxvYWRpbmctbWVzc2FnZVwiPkNhcnJlZ2FuZG88L3A+ICcgKyAnPC9kaXY+J1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLy8gaW5zdGFudGlhdGUgYmFzZSBjb250cm9sbGVyXG4gICAgJGNvbnRyb2xsZXIoJ0NSVURDb250cm9sbGVyJywgeyB2bTogdm0sIG1vZGVsU2VydmljZTogVmNzU2VydmljZSwgb3B0aW9uczogeyBza2lwUGFnaW5hdGlvbjogdHJ1ZSwgc2VhcmNoT25Jbml0OiBmYWxzZSB9IH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKlxuICAgKiBBcnF1aXZvIGRlIGNvbmZpZ3VyYcOnw6NvIGNvbSBhcyByb3RhcyBlc3BlY8OtZmljYXMgZG8gcmVjdXJzbyB2Y3NcbiAgICpcbiAgICogQHBhcmFtIHtvYmplY3R9ICRzdGF0ZVByb3ZpZGVyXG4gICAqIEBwYXJhbSB7b2JqZWN0fSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnYXBwLnZjcycsIHtcbiAgICAgIHVybDogJy92Y3MnLFxuICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy92Y3MvdmNzLmh0bWwnLFxuICAgICAgY29udHJvbGxlcjogJ1Zjc0NvbnRyb2xsZXIgYXMgdmNzQ3RybCcsXG4gICAgICBkYXRhOiB7fVxuICAgIH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZhY3RvcnkoJ1Zjc1NlcnZpY2UnLCBWY3NTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIFZjc1NlcnZpY2Uoc2VydmljZUZhY3RvcnkpIHtcbiAgICB2YXIgbW9kZWwgPSBzZXJ2aWNlRmFjdG9yeSgndmNzJywge1xuICAgICAgYWN0aW9uczoge30sXG4gICAgICBpbnN0YW5jZToge31cbiAgICB9KTtcblxuICAgIHJldHVybiBtb2RlbDtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29tcG9uZW50KCdib3gnLCB7XG4gICAgcmVwbGFjZTogdHJ1ZSxcbiAgICB0ZW1wbGF0ZVVybDogWydHbG9iYWwnLCBmdW5jdGlvbiAoR2xvYmFsKSB7XG4gICAgICByZXR1cm4gR2xvYmFsLmNsaWVudFBhdGggKyAnL3dpZGdldHMvYm94Lmh0bWwnO1xuICAgIH1dLFxuICAgIHRyYW5zY2x1ZGU6IHtcbiAgICAgIHRvb2xiYXJCdXR0b25zOiAnP2JveFRvb2xiYXJCdXR0b25zJyxcbiAgICAgIGZvb3RlckJ1dHRvbnM6ICc/Ym94Rm9vdGVyQnV0dG9ucydcbiAgICB9LFxuICAgIGJpbmRpbmdzOiB7XG4gICAgICBib3hUaXRsZTogJ0AnLFxuICAgICAgdG9vbGJhckNsYXNzOiAnQCcsXG4gICAgICB0b29sYmFyQmdDb2xvcjogJ0AnXG4gICAgfSxcbiAgICBjb250cm9sbGVyOiBbJyR0cmFuc2NsdWRlJywgZnVuY3Rpb24gKCR0cmFuc2NsdWRlKSB7XG4gICAgICB2YXIgY3RybCA9IHRoaXM7XG5cbiAgICAgIGN0cmwudHJhbnNjbHVkZSA9ICR0cmFuc2NsdWRlO1xuXG4gICAgICBjdHJsLiRvbkluaXQgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgIGlmIChhbmd1bGFyLmlzVW5kZWZpbmVkKGN0cmwudG9vbGJhckJnQ29sb3IpKSBjdHJsLnRvb2xiYXJCZ0NvbG9yID0gJ2RlZmF1bHQtcHJpbWFyeSc7XG4gICAgICB9O1xuICAgIH1dXG4gIH0pO1xufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29tcG9uZW50KCdjb250ZW50Qm9keScsIHtcbiAgICByZXBsYWNlOiB0cnVlLFxuICAgIHRyYW5zY2x1ZGU6IHRydWUsXG4gICAgdGVtcGxhdGVVcmw6IFsnR2xvYmFsJywgZnVuY3Rpb24gKEdsb2JhbCkge1xuICAgICAgcmV0dXJuIEdsb2JhbC5jbGllbnRQYXRoICsgJy93aWRnZXRzL2NvbnRlbnQtYm9keS5odG1sJztcbiAgICB9XSxcbiAgICBiaW5kaW5nczoge1xuICAgICAgbGF5b3V0QWxpZ246ICdAJ1xuICAgIH0sXG4gICAgY29udHJvbGxlcjogW2Z1bmN0aW9uICgpIHtcbiAgICAgIHZhciBjdHJsID0gdGhpcztcblxuICAgICAgY3RybC4kb25Jbml0ID0gZnVuY3Rpb24gKCkge1xuICAgICAgICAvLyBNYWtlIGEgY29weSBvZiB0aGUgaW5pdGlhbCB2YWx1ZSB0byBiZSBhYmxlIHRvIHJlc2V0IGl0IGxhdGVyXG4gICAgICAgIGN0cmwubGF5b3V0QWxpZ24gPSBhbmd1bGFyLmlzRGVmaW5lZChjdHJsLmxheW91dEFsaWduKSA/IGN0cmwubGF5b3V0QWxpZ24gOiAnY2VudGVyIHN0YXJ0JztcbiAgICAgIH07XG4gICAgfV1cbiAgfSk7XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb21wb25lbnQoJ2NvbnRlbnRIZWFkZXInLCB7XG4gICAgdGVtcGxhdGVVcmw6IFsnR2xvYmFsJywgZnVuY3Rpb24gKEdsb2JhbCkge1xuICAgICAgcmV0dXJuIEdsb2JhbC5jbGllbnRQYXRoICsgJy93aWRnZXRzL2NvbnRlbnQtaGVhZGVyLmh0bWwnO1xuICAgIH1dLFxuICAgIHJlcGxhY2U6IHRydWUsXG4gICAgYmluZGluZ3M6IHtcbiAgICAgIHRpdGxlOiAnQCcsXG4gICAgICBkZXNjcmlwdGlvbjogJ0AnXG4gICAgfVxuICB9KTtcbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5maWx0ZXIoJ2F1ZGl0RGV0YWlsVGl0bGUnLCBhdWRpdERldGFpbFRpdGxlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIGF1ZGl0RGV0YWlsVGl0bGUoJHRyYW5zbGF0ZSkge1xuICAgIHJldHVybiBmdW5jdGlvbiAoYXVkaXREZXRhaWwsIHN0YXR1cykge1xuICAgICAgaWYgKGF1ZGl0RGV0YWlsLnR5cGUgPT09ICd1cGRhdGVkJykge1xuICAgICAgICBpZiAoc3RhdHVzID09PSAnYmVmb3JlJykge1xuICAgICAgICAgIHJldHVybiAkdHJhbnNsYXRlLmluc3RhbnQoJ2RpYWxvZy5hdWRpdC51cGRhdGVkQmVmb3JlJyk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgcmV0dXJuICR0cmFuc2xhdGUuaW5zdGFudCgnZGlhbG9nLmF1ZGl0LnVwZGF0ZWRBZnRlcicpO1xuICAgICAgICB9XG4gICAgICB9IGVsc2Uge1xuICAgICAgICByZXR1cm4gJHRyYW5zbGF0ZS5pbnN0YW50KCdkaWFsb2cuYXVkaXQuJyArIGF1ZGl0RGV0YWlsLnR5cGUpO1xuICAgICAgfVxuICAgIH07XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5maWx0ZXIoJ2F1ZGl0TW9kZWwnLCBhdWRpdE1vZGVsKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIGF1ZGl0TW9kZWwoJHRyYW5zbGF0ZSkge1xuICAgIHJldHVybiBmdW5jdGlvbiAobW9kZWxJZCkge1xuICAgICAgbW9kZWxJZCA9IG1vZGVsSWQucmVwbGFjZSgnQXBwXFxcXCcsICcnKTtcbiAgICAgIHZhciBtb2RlbCA9ICR0cmFuc2xhdGUuaW5zdGFudCgnbW9kZWxzLicgKyBtb2RlbElkLnRvTG93ZXJDYXNlKCkpO1xuXG4gICAgICByZXR1cm4gbW9kZWwgPyBtb2RlbCA6IG1vZGVsSWQ7XG4gICAgfTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZpbHRlcignYXVkaXRUeXBlJywgYXVkaXRUeXBlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIGF1ZGl0VHlwZShsb2Rhc2gsIEF1ZGl0U2VydmljZSkge1xuICAgIHJldHVybiBmdW5jdGlvbiAodHlwZUlkKSB7XG4gICAgICB2YXIgdHlwZSA9IGxvZGFzaC5maW5kKEF1ZGl0U2VydmljZS5saXN0VHlwZXMoKSwgeyBpZDogdHlwZUlkIH0pO1xuXG4gICAgICByZXR1cm4gdHlwZSA/IHR5cGUubGFiZWwgOiB0eXBlO1xuICAgIH07XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5maWx0ZXIoJ2F1ZGl0VmFsdWUnLCBhdWRpdFZhbHVlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIGF1ZGl0VmFsdWUoJGZpbHRlciwgbG9kYXNoKSB7XG4gICAgcmV0dXJuIGZ1bmN0aW9uICh2YWx1ZSwga2V5KSB7XG4gICAgICBpZiAoYW5ndWxhci5pc0RhdGUodmFsdWUpIHx8IGxvZGFzaC5lbmRzV2l0aChrZXksICdfYXQnKSB8fCBsb2Rhc2guZW5kc1dpdGgoa2V5LCAnX3RvJykpIHtcbiAgICAgICAgcmV0dXJuICRmaWx0ZXIoJ3ByRGF0ZXRpbWUnKSh2YWx1ZSk7XG4gICAgICB9XG5cbiAgICAgIGlmICh0eXBlb2YgdmFsdWUgPT09ICdib29sZWFuJykge1xuICAgICAgICByZXR1cm4gJGZpbHRlcigndHJhbnNsYXRlJykodmFsdWUgPyAnZ2xvYmFsLnllcycgOiAnZ2xvYmFsLm5vJyk7XG4gICAgICB9XG5cbiAgICAgIC8vY2hlY2sgaXMgZmxvYXRcbiAgICAgIGlmIChOdW1iZXIodmFsdWUpID09PSB2YWx1ZSAmJiB2YWx1ZSAlIDEgIT09IDApIHtcbiAgICAgICAgcmV0dXJuICRmaWx0ZXIoJ3JlYWwnKSh2YWx1ZSk7XG4gICAgICB9XG5cbiAgICAgIHJldHVybiB2YWx1ZTtcbiAgICB9O1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4vKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCwgbm8tdW5kZWY6IDAqL1xuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25zdGFudCgncHQtQlIuaTE4bi5hdHRyaWJ1dGVzJywge1xuICAgIGVtYWlsOiAnRW1haWwnLFxuICAgIHBhc3N3b3JkOiAnU2VuaGEnLFxuICAgIG5hbWU6ICdOb21lJyxcbiAgICBpbWFnZTogJ0ltYWdlbScsXG4gICAgcm9sZXM6ICdQZXJmaXMnLFxuICAgIGRhdGU6ICdEYXRhJyxcbiAgICBpbml0aWFsRGF0ZTogJ0RhdGEgSW5pY2lhbCcsXG4gICAgZmluYWxEYXRlOiAnRGF0YSBGaW5hbCcsXG4gICAgYmlydGhkYXk6ICdEYXRhIGRlIE5hc2NpbWVudG8nLFxuICAgIHRhc2s6IHtcbiAgICAgIGRlc2NyaXB0aW9uOiAnRGVzY3Jpw6fDo28nLFxuICAgICAgZG9uZTogJ0ZlaXRvPycsXG4gICAgICBwcmlvcml0eTogJ1ByaW9yaWRhZGUnLFxuICAgICAgc2NoZWR1bGVkX3RvOiAnQWdlbmRhZG8gUGFyYT8nLFxuICAgICAgcHJvamVjdDogJ1Byb2pldG8nLFxuICAgICAgc3RhdHVzOiAnU3RhdHVzJyxcbiAgICAgIHRpdGxlOiAnVMOtdHVsbycsXG4gICAgICB0eXBlOiAnVGlwbycsXG4gICAgICBtaWxlc3RvbmU6ICdTcHJpbnQnLFxuICAgICAgZXN0aW1hdGVkX3RpbWU6ICdUZW1wbyBFc3RpbWFkbydcbiAgICB9LFxuICAgIG1pbGVzdG9uZToge1xuICAgICAgdGl0bGU6ICdUw610dWxvJyxcbiAgICAgIGRlc2NyaXB0aW9uOiAnRGVzY3Jpw6fDo28nLFxuICAgICAgZGF0ZV9zdGFydDogJ0RhdGEgRXN0aW1hZGEgcGFyYSBJbsOtY2lvJyxcbiAgICAgIGRhdGVfZW5kOiAnRGF0YSBFc3RpbWFkYSBwYXJhIEZpbScsXG4gICAgICBlc3RpbWF0ZWRfdGltZTogJ1RlbXBvIEVzdGltYWRvJyxcbiAgICAgIGVzdGltYXRlZF92YWx1ZTogJ1ZhbG9yIEVzdGltYWRvJ1xuICAgIH0sXG4gICAgcHJvamVjdDoge1xuICAgICAgY29zdDogJ0N1c3RvJyxcbiAgICAgIGhvdXJWYWx1ZURldmVsb3BlcjogJ1ZhbG9yIGRhIEhvcmEgRGVzZW52b2x2ZWRvcicsXG4gICAgICBob3VyVmFsdWVDbGllbnQ6ICdWYWxvciBkYSBIb3JhIENsaWVudGUnLFxuICAgICAgaG91clZhbHVlRmluYWw6ICdWYWxvciBkYSBIb3JhIFByb2pldG8nXG4gICAgfSxcbiAgICByZWxlYXNlOiB7XG4gICAgICB0aXRsZTogJ1TDrXR1bG8nLFxuICAgICAgZGVzY3JpcHRpb246ICdEZXNjcmnDp8OjbycsXG4gICAgICByZWxlYXNlX2RhdGU6ICdEYXRhIGRlIEVudHJlZ2EnLFxuICAgICAgbWlsZXN0b25lOiAnTWlsZXN0b25lJyxcbiAgICAgIHRhc2tzOiAnVGFyZWZhcydcbiAgICB9LFxuICAgIC8vw6kgY2FycmVnYWRvIGRvIHNlcnZpZG9yIGNhc28gZXN0ZWphIGRlZmluaWRvIG5vIG1lc21vXG4gICAgYXVkaXRNb2RlbDoge31cbiAgfSk7XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4vKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCwgbm8tdW5kZWY6IDAqL1xuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25zdGFudCgncHQtQlIuaTE4bi5kaWFsb2cnLCB7XG4gICAgY29uZmlybVRpdGxlOiAnQ29uZmlybWHDp8OjbycsXG4gICAgY29uZmlybURlc2NyaXB0aW9uOiAnQ29uZmlybWEgYSBhw6fDo28/JyxcbiAgICByZW1vdmVEZXNjcmlwdGlvbjogJ0Rlc2VqYSByZW1vdmVyIHBlcm1hbmVudGVtZW50ZSB7e25hbWV9fT8nLFxuICAgIGF1ZGl0OiB7XG4gICAgICBjcmVhdGVkOiAnSW5mb3JtYcOnw7VlcyBkbyBDYWRhc3RybycsXG4gICAgICB1cGRhdGVkQmVmb3JlOiAnQW50ZXMgZGEgQXR1YWxpemHDp8OjbycsXG4gICAgICB1cGRhdGVkQWZ0ZXI6ICdEZXBvaXMgZGEgQXR1YWxpemHDp8OjbycsXG4gICAgICBkZWxldGVkOiAnSW5mb3JtYcOnw7VlcyBhbnRlcyBkZSByZW1vdmVyJ1xuICAgIH0sXG4gICAgbG9naW46IHtcbiAgICAgIHJlc2V0UGFzc3dvcmQ6IHtcbiAgICAgICAgZGVzY3JpcHRpb246ICdEaWdpdGUgYWJhaXhvIG8gZW1haWwgY2FkYXN0cmFkbyBubyBzaXN0ZW1hLidcbiAgICAgIH1cbiAgICB9XG4gIH0pO1xufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuLyplc2xpbnQgYW5ndWxhci9maWxlLW5hbWU6IDAsIG5vLXVuZGVmOiAwKi9cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29uc3RhbnQoJ3B0LUJSLmkxOG4uZ2xvYmFsJywge1xuICAgIGxvYWRpbmc6ICdDYXJyZWdhbmRvLi4uJyxcbiAgICBwcm9jZXNzaW5nOiAnUHJvY2Vzc2FuZG8uLi4nLFxuICAgIHllczogJ1NpbScsXG4gICAgbm86ICdOw6NvJyxcbiAgICBhbGw6ICdUb2RvcydcbiAgfSk7XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4vKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCwgbm8tdW5kZWY6IDAqL1xuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25zdGFudCgncHQtQlIuaTE4bi5tZXNzYWdlcycsIHtcbiAgICBpbnRlcm5hbEVycm9yOiAnT2NvcnJldSB1bSBlcnJvIGludGVybm8sIGNvbnRhdGUgbyBhZG1pbmlzdHJhZG9yIGRvIHNpc3RlbWEnLFxuICAgIG5vdEZvdW5kOiAnTmVuaHVtIHJlZ2lzdHJvIGVuY29udHJhZG8nLFxuICAgIG5vdEF1dGhvcml6ZWQ6ICdWb2PDqiBuw6NvIHRlbSBhY2Vzc28gYSBlc3RhIGZ1bmNpb25hbGlkYWRlLicsXG4gICAgc2VhcmNoRXJyb3I6ICdOw6NvIGZvaSBwb3Nzw612ZWwgcmVhbGl6YXIgYSBidXNjYS4nLFxuICAgIHNhdmVTdWNjZXNzOiAnUmVnaXN0cm8gc2Fsdm8gY29tIHN1Y2Vzc28uJyxcbiAgICBvcGVyYXRpb25TdWNjZXNzOiAnT3BlcmHDp8OjbyByZWFsaXphZGEgY29tIHN1Y2Vzc28uJyxcbiAgICBvcGVyYXRpb25FcnJvcjogJ0Vycm8gYW8gcmVhbGl6YXIgYSBvcGVyYcOnw6NvJyxcbiAgICBzYXZlRXJyb3I6ICdFcnJvIGFvIHRlbnRhciBzYWx2YXIgbyByZWdpc3Ryby4nLFxuICAgIHJlbW92ZVN1Y2Nlc3M6ICdSZW1vw6fDo28gcmVhbGl6YWRhIGNvbSBzdWNlc3NvLicsXG4gICAgcmVtb3ZlRXJyb3I6ICdFcnJvIGFvIHRlbnRhciByZW1vdmVyIG8gcmVnaXN0cm8uJyxcbiAgICByZXNvdXJjZU5vdEZvdW5kRXJyb3I6ICdSZWN1cnNvIG7Do28gZW5jb250cmFkbycsXG4gICAgbm90TnVsbEVycm9yOiAnVG9kb3Mgb3MgY2FtcG9zIG9icmlnYXTDs3Jpb3MgZGV2ZW0gc2VyIHByZWVuY2hpZG9zLicsXG4gICAgZHVwbGljYXRlZFJlc291cmNlRXJyb3I6ICdKw6EgZXhpc3RlIHVtIHJlY3Vyc28gY29tIGVzc2FzIGluZm9ybWHDp8O1ZXMuJyxcbiAgICBzcHJpbnRFbmRlZFN1Y2Nlc3M6ICdTcHJpbnQgZmluYWxpemFkYSBjb20gc3VjZXNzbycsXG4gICAgc3ByaW50RW5kZWRFcnJvcjogJ0Vycm8gYW8gZmluYWxpemFyIGEgc3ByaW50JyxcbiAgICBzdWNjZXNzU2lnblVwOiAnQ2FkYXN0cm8gcmVhbGl6YWRvIGNvbSBzdWNlc3NvLiBVbSBlLW1haWwgZm9pIGVudmlhZG8gY29tIHNldXMgZGFkb3MgZGUgbG9naW4nLFxuICAgIGVycm9yc1NpZ25VcDogJ0hvdXZlIHVtIGVycm8gYW8gcmVhbGl6YXIgbyBzZXUgY2FkYXN0cm8uIFRlbnRlIG5vdmFtZW50ZSBtYWlzIHRhcmRlIScsXG4gICAgcmVsZWFzZXRFbmRlZFN1Y2Nlc3M6ICdSZWxlYXNlIGZpbmFsaXphZGEgY29tIHN1Y2Vzc28nLFxuICAgIHJlbGVhc2VFbmRlZEVycm9yOiAnRXJybyBhbyBmaW5hbGl6YXIgYSByZWxlYXNlJyxcbiAgICBwcm9qZWN0RW5kZWRTdWNjZXNzOiAnUHJvamV0byBmaW5hbGl6YWRvIGNvbSBzdWNlc3NvJyxcbiAgICBwcm9qZWN0RW5kZWRFcnJvcjogJ0Vycm8gYW8gZmluYWxpemFyIG8gcHJvamV0bycsXG4gICAgdmFsaWRhdGU6IHtcbiAgICAgIGZpZWxkUmVxdWlyZWQ6ICdPIGNhbXBvIHt7ZmllbGR9fSDDqSBvYnJpZ3JhdMOzcmlvLidcbiAgICB9LFxuICAgIGxheW91dDoge1xuICAgICAgZXJyb3I0MDQ6ICdQw6FnaW5hIG7Do28gZW5jb250cmFkYSdcbiAgICB9LFxuICAgIGxvZ2luOiB7XG4gICAgICBsb2dvdXRJbmFjdGl2ZTogJ1ZvY8OqIGZvaSBkZXNsb2dhZG8gZG8gc2lzdGVtYSBwb3IgaW5hdGl2aWRhZGUuIEZhdm9yIGVudHJhciBubyBzaXN0ZW1hIG5vdmFtZW50ZS4nLFxuICAgICAgaW52YWxpZENyZWRlbnRpYWxzOiAnQ3JlZGVuY2lhaXMgSW52w6FsaWRhcycsXG4gICAgICB1bmtub3duRXJyb3I6ICdOw6NvIGZvaSBwb3Nzw612ZWwgcmVhbGl6YXIgbyBsb2dpbi4gVGVudGUgbm92YW1lbnRlLiAnICsgJ0Nhc28gbsOjbyBjb25zaWdhIGZhdm9yIGVuY29udHJhciBlbSBjb250YXRvIGNvbSBvIGFkbWluaXN0cmFkb3IgZG8gc2lzdGVtYS4nLFxuICAgICAgdXNlck5vdEZvdW5kOiAnTsOjbyBmb2kgcG9zc8OtdmVsIGVuY29udHJhciBzZXVzIGRhZG9zJ1xuICAgIH0sXG4gICAgZGFzaGJvYXJkOiB7XG4gICAgICB3ZWxjb21lOiAnU2VqYSBiZW0gVmluZG8ge3t1c2VyTmFtZX19JyxcbiAgICAgIGRlc2NyaXB0aW9uOiAnVXRpbGl6ZSBvIG1lbnUgcGFyYSBuYXZlZ2HDp8Ojby4nXG4gICAgfSxcbiAgICBtYWlsOiB7XG4gICAgICBtYWlsRXJyb3JzOiAnT2NvcnJldSB1bSBlcnJvIG5vcyBzZWd1aW50ZXMgZW1haWxzIGFiYWl4bzpcXG4nLFxuICAgICAgc2VuZE1haWxTdWNjZXNzOiAnRW1haWwgZW52aWFkbyBjb20gc3VjZXNzbyEnLFxuICAgICAgc2VuZE1haWxFcnJvcjogJ07Do28gZm9pIHBvc3PDrXZlbCBlbnZpYXIgbyBlbWFpbC4nLFxuICAgICAgcGFzc3dvcmRTZW5kaW5nU3VjY2VzczogJ08gcHJvY2Vzc28gZGUgcmVjdXBlcmHDp8OjbyBkZSBzZW5oYSBmb2kgaW5pY2lhZG8uIENhc28gbyBlbWFpbCBuw6NvIGNoZWd1ZSBlbSAxMCBtaW51dG9zIHRlbnRlIG5vdmFtZW50ZS4nXG4gICAgfSxcbiAgICB1c2VyOiB7XG4gICAgICByZW1vdmVZb3VyU2VsZkVycm9yOiAnVm9jw6ogbsOjbyBwb2RlIHJlbW92ZXIgc2V1IHByw7NwcmlvIHVzdcOhcmlvJyxcbiAgICAgIHVzZXJFeGlzdHM6ICdVc3XDoXJpbyBqw6EgYWRpY2lvbmFkbyEnLFxuICAgICAgcHJvZmlsZToge1xuICAgICAgICB1cGRhdGVFcnJvcjogJ07Do28gZm9pIHBvc3PDrXZlbCBhdHVhbGl6YXIgc2V1IHByb2ZpbGUnXG4gICAgICB9XG4gICAgfSxcbiAgICBxdWVyeURpbmFtaWM6IHtcbiAgICAgIG5vRmlsdGVyOiAnTmVuaHVtIGZpbHRybyBhZGljaW9uYWRvJ1xuICAgIH1cbiAgfSk7XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4vKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCwgbm8tdW5kZWY6IDAqL1xuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25zdGFudCgncHQtQlIuaTE4bi5tb2RlbHMnLCB7XG4gICAgdXNlcjogJ1VzdcOhcmlvJyxcbiAgICB0YXNrOiAnVGFyZWZhJyxcbiAgICBwcm9qZWN0OiAnUHJvamV0bydcbiAgfSk7XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4vKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCwgbm8tdW5kZWY6IDAqL1xuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25zdGFudCgncHQtQlIuaTE4bi52aWV3cycsIHtcbiAgICBicmVhZGNydW1iczoge1xuICAgICAgdXNlcjogJ0FkbWluaXN0cmHDp8OjbyAtIFVzdcOhcmlvJyxcbiAgICAgICd1c2VyLXByb2ZpbGUnOiAnUGVyZmlsJyxcbiAgICAgIGRhc2hib2FyZDogJ0Rhc2hib2FyZCcsXG4gICAgICBhdWRpdDogJ0FkbWluaXN0cmHDp8OjbyAtIEF1ZGl0b3JpYScsXG4gICAgICBtYWlsOiAnQWRtaW5pc3RyYcOnw6NvIC0gRW52aW8gZGUgZS1tYWlsJyxcbiAgICAgIHByb2plY3RzOiAnUHJvamV0b3MnLFxuICAgICAgJ2RpbmFtaWMtcXVlcnknOiAnQWRtaW5pc3RyYcOnw6NvIC0gQ29uc3VsdGFzIERpbsOibWljYXMnLFxuICAgICAgJ25vdC1hdXRob3JpemVkJzogJ0FjZXNzbyBOZWdhZG8nLFxuICAgICAgdGFza3M6ICdUYXJlZmFzJyxcbiAgICAgIG1pbGVzdG9uZXM6ICdTcHJpbnRzJyxcbiAgICAgIGthbmJhbjogJ0thbmJhbiBCb2FyZCcsXG4gICAgICB2Y3M6ICdDb250cm9sZSBkZSBWZXJzw6NvJyxcbiAgICAgIHJlbGVhc2VzOiAnUmVsZWFzZXMnXG4gICAgfSxcbiAgICB0aXRsZXM6IHtcbiAgICAgIGRhc2hib2FyZDogJ0Rhc2hib2FyZCcsXG4gICAgICBtYWlsU2VuZDogJ0VudmlhciBlLW1haWwnLFxuICAgICAgdGFza0xpc3Q6ICdMaXN0YSBkZSBUYXJlZmFzJyxcbiAgICAgIHVzZXJMaXN0OiAnTGlzdGEgZGUgVXN1w6FyaW9zJyxcbiAgICAgIGF1ZGl0TGlzdDogJ0xpc3RhIGRlIExvZ3MnLFxuICAgICAgcmVnaXN0ZXI6ICdGb3JtdWzDoXJpbyBkZSBDYWRhc3RybycsXG4gICAgICByZXNldFBhc3N3b3JkOiAnUmVkZWZpbmlyIFNlbmhhJyxcbiAgICAgIHVwZGF0ZTogJ0Zvcm11bMOhcmlvIGRlIEF0dWFsaXphw6fDo28nLFxuICAgICAgdGFza3M6ICdUYXJlZmFzJyxcbiAgICAgIG1pbGVzdG9uZXM6ICdTcHJpbnRzJyxcbiAgICAgIGthbmJhbjogJ0thbmJhbiBCb2FyZCcsXG4gICAgICB2Y3M6ICdDb250cm9sZSBkZSBWZXJzw6NvJyxcbiAgICAgIHJlbGVhc2VzOiAnUmVsZWFzZXMnXG4gICAgfSxcbiAgICBhY3Rpb25zOiB7XG4gICAgICBzZW5kOiAnRW52aWFyJyxcbiAgICAgIHNhdmU6ICdTYWx2YXInLFxuICAgICAgY2xlYXI6ICdMaW1wYXInLFxuICAgICAgY2xlYXJBbGw6ICdMaW1wYXIgVHVkbycsXG4gICAgICByZXN0YXJ0OiAnUmVpbmljaWFyJyxcbiAgICAgIGZpbHRlcjogJ0ZpbHRyYXInLFxuICAgICAgc2VhcmNoOiAnUGVzcXVpc2FyJyxcbiAgICAgIGxpc3Q6ICdMaXN0YXInLFxuICAgICAgZWRpdDogJ0VkaXRhcicsXG4gICAgICBjYW5jZWw6ICdDYW5jZWxhcicsXG4gICAgICB1cGRhdGU6ICdBdHVhbGl6YXInLFxuICAgICAgcmVtb3ZlOiAnUmVtb3ZlcicsXG4gICAgICBnZXRPdXQ6ICdTYWlyJyxcbiAgICAgIGFkZDogJ0FkaWNpb25hcicsXG4gICAgICBpbjogJ0VudHJhcicsXG4gICAgICBsb2FkSW1hZ2U6ICdDYXJyZWdhciBJbWFnZW0nLFxuICAgICAgc2lnbnVwOiAnQ2FkYXN0cmFyJyxcbiAgICAgIGNyaWFyUHJvamV0bzogJ0NyaWFyIFByb2pldG8nLFxuICAgICAgcHJvamVjdExpc3Q6ICdMaXN0YSBkZSBQcm9qZXRvcycsXG4gICAgICB0YXNrc0xpc3Q6ICdMaXN0YSBkZSBUYXJlZmFzJyxcbiAgICAgIG1pbGVzdG9uZXNMaXN0OiAnTGlzdGEgZGUgU3ByaW50cycsXG4gICAgICBmaW5hbGl6ZTogJ0ZpbmFsaXphcicsXG4gICAgICByZXBseTogJ1Jlc3BvbmRlcidcbiAgICB9LFxuICAgIGZpZWxkczoge1xuICAgICAgZGF0ZTogJ0RhdGEnLFxuICAgICAgYWN0aW9uOiAnQcOnw6NvJyxcbiAgICAgIGFjdGlvbnM6ICdBw6fDtWVzJyxcbiAgICAgIGF1ZGl0OiB7XG4gICAgICAgIGRhdGVTdGFydDogJ0RhdGEgSW5pY2lhbCcsXG4gICAgICAgIGRhdGVFbmQ6ICdEYXRhIEZpbmFsJyxcbiAgICAgICAgcmVzb3VyY2U6ICdSZWN1cnNvJyxcbiAgICAgICAgYWxsUmVzb3VyY2VzOiAnVG9kb3MgUmVjdXJzb3MnLFxuICAgICAgICB0eXBlOiB7XG4gICAgICAgICAgY3JlYXRlZDogJ0NhZGFzdHJhZG8nLFxuICAgICAgICAgIHVwZGF0ZWQ6ICdBdHVhbGl6YWRvJyxcbiAgICAgICAgICBkZWxldGVkOiAnUmVtb3ZpZG8nXG4gICAgICAgIH1cbiAgICAgIH0sXG4gICAgICBsb2dpbjoge1xuICAgICAgICByZXNldFBhc3N3b3JkOiAnRXNxdWVjaSBtaW5oYSBzZW5oYScsXG4gICAgICAgIGNvbmZpcm1QYXNzd29yZDogJ0NvbmZpcm1hciBzZW5oYSdcbiAgICAgIH0sXG4gICAgICBtYWlsOiB7XG4gICAgICAgIHRvOiAnUGFyYScsXG4gICAgICAgIHN1YmplY3Q6ICdBc3N1bnRvJyxcbiAgICAgICAgbWVzc2FnZTogJ01lbnNhZ2VtJ1xuICAgICAgfSxcbiAgICAgIHF1ZXJ5RGluYW1pYzoge1xuICAgICAgICBmaWx0ZXJzOiAnRmlsdHJvcycsXG4gICAgICAgIHJlc3VsdHM6ICdSZXN1bHRhZG9zJyxcbiAgICAgICAgbW9kZWw6ICdNb2RlbCcsXG4gICAgICAgIGF0dHJpYnV0ZTogJ0F0cmlidXRvJyxcbiAgICAgICAgb3BlcmF0b3I6ICdPcGVyYWRvcicsXG4gICAgICAgIHJlc291cmNlOiAnUmVjdXJzbycsXG4gICAgICAgIHZhbHVlOiAnVmFsb3InLFxuICAgICAgICBvcGVyYXRvcnM6IHtcbiAgICAgICAgICBlcXVhbHM6ICdJZ3VhbCcsXG4gICAgICAgICAgZGlmZXJlbnQ6ICdEaWZlcmVudGUnLFxuICAgICAgICAgIGNvbnRlaW5zOiAnQ29udMOpbScsXG4gICAgICAgICAgc3RhcnRXaXRoOiAnSW5pY2lhIGNvbScsXG4gICAgICAgICAgZmluaXNoV2l0aDogJ0ZpbmFsaXphIGNvbScsXG4gICAgICAgICAgYmlnZ2VyVGhhbjogJ01haW9yJyxcbiAgICAgICAgICBlcXVhbHNPckJpZ2dlclRoYW46ICdNYWlvciBvdSBJZ3VhbCcsXG4gICAgICAgICAgbGVzc1RoYW46ICdNZW5vcicsXG4gICAgICAgICAgZXF1YWxzT3JMZXNzVGhhbjogJ01lbm9yIG91IElndWFsJ1xuICAgICAgICB9XG4gICAgICB9LFxuICAgICAgcHJvamVjdDoge1xuICAgICAgICBuYW1lOiAnTm9tZScsXG4gICAgICAgIHRvdGFsVGFzazogJ1RvdGFsIGRlIFRhcmVmYXMnXG4gICAgICB9LFxuICAgICAgdGFzazoge1xuICAgICAgICBkb25lOiAnTsOjbyBGZWl0byAvIEZlaXRvJ1xuICAgICAgfSxcbiAgICAgIHVzZXI6IHtcbiAgICAgICAgcGVyZmlsczogJ1BlcmZpcycsXG4gICAgICAgIG5hbWVPckVtYWlsOiAnTm9tZSBvdSBFbWFpbCdcbiAgICAgIH1cbiAgICB9LFxuICAgIGxheW91dDoge1xuICAgICAgbWVudToge1xuICAgICAgICBwcm9qZWN0czogJ1Byb2pldG9zJyxcbiAgICAgICAgZGFzaGJvYXJkOiAnRGFzaGJvYXJkJyxcbiAgICAgICAgbWlsZXN0b25lczogJ1NwcmludHMnLFxuICAgICAgICB0YXNrczogJ1RhcmVmYXMnLFxuICAgICAgICBrYW5iYW46ICdLYW5iYW4nLFxuICAgICAgICB2Y3M6ICdDb250cm9sZSBkZSBWZXJzw6NvJyxcbiAgICAgICAgcmVsZWFzZXM6ICdSZWxlYXNlcydcbiAgICAgIH1cbiAgICB9LFxuICAgIHRvb2x0aXBzOiB7XG4gICAgICBhdWRpdDoge1xuICAgICAgICB2aWV3RGV0YWlsOiAnVmlzdWFsaXphciBEZXRhbGhhbWVudG8nXG4gICAgICB9LFxuICAgICAgdXNlcjoge1xuICAgICAgICBwZXJmaWw6ICdQZXJmaWwnLFxuICAgICAgICB0cmFuc2ZlcjogJ1RyYW5zZmVyaXInXG4gICAgICB9LFxuICAgICAgdGFzazoge1xuICAgICAgICBsaXN0VGFzazogJ0xpc3RhciBUYXJlZmFzJ1xuICAgICAgfVxuICAgIH1cbiAgfSk7XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29udHJvbGxlcignVGFza0luZm9Db250cm9sbGVyJywgVGFza0luZm9Db250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIFRhc2tJbmZvQ29udHJvbGxlcigkY29udHJvbGxlciwgVGFza3NTZXJ2aWNlLCBsb2NhbHMpIHtcbiAgICAvL0F0dHJpYnV0ZXMgQmxvY2tcbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0uY2xvc2VEaWFsb2cgPSBjbG9zZURpYWxvZztcblxuICAgIHZtLm9uQWN0aXZhdGUgPSBmdW5jdGlvbiAoKSB7XG4gICAgICB2bS50YXNrID0gbG9jYWxzLnRhc2s7XG4gICAgICB2bS50YXNrLmVzdGltYXRlZF90aW1lID0gdm0udGFzay5lc3RpbWF0ZWRfdGltZS50b1N0cmluZygpICsgJyBob3Jhcyc7XG4gICAgfTtcblxuICAgIGZ1bmN0aW9uIGNsb3NlRGlhbG9nKCkge1xuICAgICAgdm0uY2xvc2UoKTtcbiAgICAgIGNvbnNvbGUubG9nKFwiZmVjaGFyXCIpO1xuICAgIH1cblxuICAgIC8vIGluc3RhbnRpYXRlIGJhc2UgY29udHJvbGxlclxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHsgdm06IHZtLCBtb2RlbFNlcnZpY2U6IFRhc2tzU2VydmljZSwgb3B0aW9uczoge30gfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb250cm9sbGVyKCdVc2Vyc0RpYWxvZ0NvbnRyb2xsZXInLCBVc2Vyc0RpYWxvZ0NvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gVXNlcnNEaWFsb2dDb250cm9sbGVyKCRjb250cm9sbGVyLCBVc2Vyc1NlcnZpY2UsIFByRGlhbG9nLCAvLyBOT1NPTkFSXG4gIHVzZXJEaWFsb2dJbnB1dCwgb25Jbml0KSB7XG5cbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0ub25BY3RpdmF0ZSA9IG9uQWN0aXZhdGU7XG4gICAgdm0uYXBwbHlGaWx0ZXJzID0gYXBwbHlGaWx0ZXJzO1xuICAgIHZtLmNsb3NlID0gY2xvc2U7XG5cbiAgICBpZiAoYW5ndWxhci5pc0RlZmluZWQodXNlckRpYWxvZ0lucHV0KSkge1xuICAgICAgdm0udHJhbnNmZXJVc2VyID0gdXNlckRpYWxvZ0lucHV0LnRyYW5zZmVyVXNlckZuO1xuICAgIH1cblxuICAgIC8vIGluc3RhbnRpYXRlIGJhc2UgY29udHJvbGxlclxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHtcbiAgICAgIHZtOiB2bSxcbiAgICAgIG1vZGVsU2VydmljZTogVXNlcnNTZXJ2aWNlLFxuICAgICAgc2VhcmNoT25Jbml0OiBvbkluaXQsXG4gICAgICBvcHRpb25zOiB7XG4gICAgICAgIHBlclBhZ2U6IDVcbiAgICAgIH1cbiAgICB9KTtcblxuICAgIGZ1bmN0aW9uIG9uQWN0aXZhdGUoKSB7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMgPSB7fTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBhcHBseUZpbHRlcnMoKSB7XG4gICAgICByZXR1cm4gYW5ndWxhci5leHRlbmQodm0uZGVmYXVsdFF1ZXJ5RmlsdGVycywgdm0ucXVlcnlGaWx0ZXJzKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBjbG9zZSgpIHtcbiAgICAgIFByRGlhbG9nLmNsb3NlKCk7XG4gICAgfVxuICB9XG59KSgpOyIsIi8qZXNsaW50IGFuZ3VsYXIvZmlsZS1uYW1lOiAwKi9cbihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnLCBbXG4gICAgJ25nQW5pbWF0ZScsXG4gICAgJ25nQXJpYScsXG4gICAgJ3VpLnJvdXRlcicsXG4gICAgJ25nUHJvZGViJyxcbiAgICAndWkudXRpbHMubWFza3MnLFxuICAgICd0ZXh0LW1hc2snLFxuICAgICduZ01hdGVyaWFsJyxcbiAgICAnbW9kZWxGYWN0b3J5JyxcbiAgICAnbWQuZGF0YS50YWJsZScsXG4gICAgJ25nTWF0ZXJpYWxEYXRlUGlja2VyJyxcbiAgICAncGFzY2FscHJlY2h0LnRyYW5zbGF0ZScsXG4gICAgJ2FuZ3VsYXJGaWxlVXBsb2FkJyxcbiAgICAnbmdNZXNzYWdlcycsXG4gICAgJ2pxd2lkZ2V0cycsXG4gICAgJ3VpLm1hc2snLFxuICAgICduZ1JvdXRlJyxcbiAgICAnbmdTYW5pdGl6ZSddKTtcbn0pKCk7XG4iLCIoZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbmZpZyhjb25maWcpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gY29uZmlnKEdsb2JhbCwgJG1kVGhlbWluZ1Byb3ZpZGVyLCAkbW9kZWxGYWN0b3J5UHJvdmlkZXIsICAvLyBOT1NPTkFSXG4gICAgJHRyYW5zbGF0ZVByb3ZpZGVyLCBtb21lbnQsICRtZEFyaWFQcm92aWRlciwgJG1kRGF0ZUxvY2FsZVByb3ZpZGVyKSB7XG5cbiAgICAkdHJhbnNsYXRlUHJvdmlkZXJcbiAgICAgIC51c2VMb2FkZXIoJ2xhbmd1YWdlTG9hZGVyJylcbiAgICAgIC51c2VTYW5pdGl6ZVZhbHVlU3RyYXRlZ3koJ2VzY2FwZScpO1xuXG4gICAgJHRyYW5zbGF0ZVByb3ZpZGVyLnVzZVBvc3RDb21waWxpbmcodHJ1ZSk7XG5cbiAgICBtb21lbnQubG9jYWxlKCdwdC1CUicpO1xuXG4gICAgLy9vcyBzZXJ2acOnb3MgcmVmZXJlbnRlIGFvcyBtb2RlbHMgdmFpIHV0aWxpemFyIGNvbW8gYmFzZSBuYXMgdXJsc1xuICAgICRtb2RlbEZhY3RvcnlQcm92aWRlci5kZWZhdWx0T3B0aW9ucy5wcmVmaXggPSBHbG9iYWwuYXBpUGF0aDtcblxuICAgIC8vIENvbmZpZ3VyYXRpb24gdGhlbWVcbiAgICAkbWRUaGVtaW5nUHJvdmlkZXIudGhlbWUoJ2RlZmF1bHQnKVxuICAgICAgLnByaW1hcnlQYWxldHRlKCdncmV5Jywge1xuICAgICAgICBkZWZhdWx0OiAnODAwJ1xuICAgICAgfSlcbiAgICAgIC5hY2NlbnRQYWxldHRlKCdhbWJlcicpXG4gICAgICAud2FyblBhbGV0dGUoJ2RlZXAtb3JhbmdlJyk7XG5cbiAgICAvLyBFbmFibGUgYnJvd3NlciBjb2xvclxuICAgICRtZFRoZW1pbmdQcm92aWRlci5lbmFibGVCcm93c2VyQ29sb3IoKTtcblxuICAgICRtZEFyaWFQcm92aWRlci5kaXNhYmxlV2FybmluZ3MoKTtcblxuICAgICRtZERhdGVMb2NhbGVQcm92aWRlci5mb3JtYXREYXRlID0gZnVuY3Rpb24oZGF0ZSkge1xuICAgICAgcmV0dXJuIGRhdGUgPyBtb21lbnQoZGF0ZSkuZm9ybWF0KCdERC9NTS9ZWVlZJykgOiAnJztcbiAgICB9O1xuICB9XG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29udHJvbGxlcignQXBwQ29udHJvbGxlcicsIEFwcENvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLyoqXG4gICAqIENvbnRyb2xhZG9yIHJlc3BvbnPDoXZlbCBwb3IgZnVuY2lvbmFsaWRhZGVzIHF1ZSBzw6NvIGFjaW9uYWRhcyBlbSBxdWFscXVlciB0ZWxhIGRvIHNpc3RlbWFcbiAgICpcbiAgICovXG4gIGZ1bmN0aW9uIEFwcENvbnRyb2xsZXIoJHN0YXRlLCBBdXRoLCBHbG9iYWwpIHtcbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgLy9hbm8gYXR1YWwgcGFyYSBzZXIgZXhpYmlkbyBubyByb2RhcMOpIGRvIHNpc3RlbWFcbiAgICB2bS5hbm9BdHVhbCA9IG51bGw7XG4gICAgdm0uYWN0aXZlUHJvamVjdCA9IG51bGw7XG5cbiAgICB2bS5sb2dvdXQgICAgID0gbG9nb3V0O1xuICAgIHZtLmdldEltYWdlUGVyZmlsID0gZ2V0SW1hZ2VQZXJmaWw7XG4gICAgdm0uZ2V0TG9nb01lbnUgPSBnZXRMb2dvTWVudTtcbiAgICB2bS5zZXRBY3RpdmVQcm9qZWN0ID0gc2V0QWN0aXZlUHJvamVjdDtcbiAgICB2bS5nZXRBY3RpdmVQcm9qZWN0ID0gZ2V0QWN0aXZlUHJvamVjdDtcbiAgICB2bS5yZW1vdmVBY3RpdmVQcm9qZWN0ID0gcmVtb3ZlQWN0aXZlUHJvamVjdDtcblxuICAgIGFjdGl2YXRlKCk7XG5cbiAgICBmdW5jdGlvbiBhY3RpdmF0ZSgpIHtcbiAgICAgIHZhciBkYXRlID0gbmV3IERhdGUoKTtcblxuICAgICAgdm0uYW5vQXR1YWwgPSBkYXRlLmdldEZ1bGxZZWFyKCk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gbG9nb3V0KCkge1xuICAgICAgQXV0aC5sb2dvdXQoKS50aGVuKGZ1bmN0aW9uKCkge1xuICAgICAgICAkc3RhdGUuZ28oR2xvYmFsLmxvZ2luU3RhdGUpO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gZ2V0SW1hZ2VQZXJmaWwoKSB7XG4gICAgICByZXR1cm4gKEF1dGguY3VycmVudFVzZXIgJiYgQXV0aC5jdXJyZW50VXNlci5pbWFnZSlcbiAgICAgICAgPyBBdXRoLmN1cnJlbnRVc2VyLmltYWdlXG4gICAgICAgIDogR2xvYmFsLmltYWdlUGF0aCArICcvbm9fYXZhdGFyLmdpZic7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gZ2V0TG9nb01lbnUoKSB7XG4gICAgICByZXR1cm4gR2xvYmFsLmltYWdlUGF0aCArICcvbG9nby12ZXJ0aWNhbC5wbmcnO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIHNldEFjdGl2ZVByb2plY3QocHJvamVjdCkge1xuICAgICAgbG9jYWxTdG9yYWdlLnNldEl0ZW0oJ3Byb2plY3QnLCBwcm9qZWN0KTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBnZXRBY3RpdmVQcm9qZWN0KCkge1xuICAgICAgcmV0dXJuIGxvY2FsU3RvcmFnZS5nZXRJdGVtKCdwcm9qZWN0Jyk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gcmVtb3ZlQWN0aXZlUHJvamVjdCgpIHtcbiAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKCdwcm9qZWN0Jyk7XG4gICAgfVxuXG4gIH1cblxufSkoKTtcbiIsIi8qZXNsaW50IGFuZ3VsYXIvZmlsZS1uYW1lOiAwLCBuby11bmRlZjogMCovXG4oZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICAvKipcbiAgICogVHJhbnNmb3JtYSBiaWJsaW90ZWNhcyBleHRlcm5hcyBlbSBzZXJ2acOnb3MgZG8gYW5ndWxhciBwYXJhIHNlciBwb3Nzw612ZWwgdXRpbGl6YXJcbiAgICogYXRyYXbDqXMgZGEgaW5qZcOnw6NvIGRlIGRlcGVuZMOqbmNpYVxuICAgKi9cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnN0YW50KCdsb2Rhc2gnLCBfKVxuICAgIC5jb25zdGFudCgnbW9tZW50JywgbW9tZW50KTtcblxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb25zdGFudCgnR2xvYmFsJywge1xuICAgICAgYXBwTmFtZTogJ0ZyZWVsYWdpbGUnLFxuICAgICAgaG9tZVN0YXRlOiAnYXBwLnByb2plY3RzJyxcbiAgICAgIGxvZ2luVXJsOiAnYXBwL2xvZ2luJyxcbiAgICAgIHJlc2V0UGFzc3dvcmRVcmw6ICdhcHAvcGFzc3dvcmQvcmVzZXQnLFxuICAgICAgbG9naW5TdGF0ZTogJ2FwcC5sb2dpbicsXG4gICAgICByZXNldFBhc3N3b3JkU3RhdGU6ICdhcHAucGFzc3dvcmQtcmVzZXQnLFxuICAgICAgbm90QXV0aG9yaXplZFN0YXRlOiAnYXBwLm5vdC1hdXRob3JpemVkJyxcbiAgICAgIHRva2VuS2V5OiAnc2VydmVyX3Rva2VuJyxcbiAgICAgIGNsaWVudFBhdGg6ICdjbGllbnQvYXBwJyxcbiAgICAgIGFwaVBhdGg6ICdhcGkvdjEnLFxuICAgICAgaW1hZ2VQYXRoOiAnY2xpZW50L2ltYWdlcydcbiAgICB9KTtcbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsICR1cmxSb3V0ZXJQcm92aWRlciwgR2xvYmFsKSB7XG4gICAgJHN0YXRlUHJvdmlkZXJcbiAgICAgIC5zdGF0ZSgnYXBwJywge1xuICAgICAgICB1cmw6ICcvYXBwJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9sYXlvdXQvYXBwLmh0bWwnLFxuICAgICAgICBhYnN0cmFjdDogdHJ1ZSxcbiAgICAgICAgcmVzb2x2ZTogeyAvL2Vuc3VyZSBsYW5ncyBpcyByZWFkeSBiZWZvcmUgcmVuZGVyIHZpZXdcbiAgICAgICAgICB0cmFuc2xhdGVSZWFkeTogWyckdHJhbnNsYXRlJywgJyRxJywgZnVuY3Rpb24oJHRyYW5zbGF0ZSwgJHEpIHtcbiAgICAgICAgICAgIHZhciBkZWZlcnJlZCA9ICRxLmRlZmVyKCk7XG5cbiAgICAgICAgICAgICR0cmFuc2xhdGUudXNlKCdwdC1CUicpLnRoZW4oZnVuY3Rpb24oKSB7XG4gICAgICAgICAgICAgIGRlZmVycmVkLnJlc29sdmUoKTtcbiAgICAgICAgICAgIH0pO1xuXG4gICAgICAgICAgICByZXR1cm4gZGVmZXJyZWQucHJvbWlzZTtcbiAgICAgICAgICB9XVxuICAgICAgICB9XG4gICAgICB9KVxuICAgICAgLnN0YXRlKEdsb2JhbC5ub3RBdXRob3JpemVkU3RhdGUsIHtcbiAgICAgICAgdXJsOiAnL2FjZXNzby1uZWdhZG8nLFxuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL2xheW91dC9ub3QtYXV0aG9yaXplZC5odG1sJyxcbiAgICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IGZhbHNlIH1cbiAgICAgIH0pO1xuXG4gICAgJHVybFJvdXRlclByb3ZpZGVyLndoZW4oJy9wYXNzd29yZC9yZXNldCcsIEdsb2JhbC5yZXNldFBhc3N3b3JkVXJsKTtcbiAgICAkdXJsUm91dGVyUHJvdmlkZXIud2hlbignL2FwcCcsIEdsb2JhbC5sb2dpblVybCk7XG4gICAgJHVybFJvdXRlclByb3ZpZGVyLm90aGVyd2lzZShHbG9iYWwubG9naW5VcmwpO1xuICB9XG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLnJ1bihydW4pO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gcnVuKCRyb290U2NvcGUsICRzdGF0ZSwgJHN0YXRlUGFyYW1zLCBBdXRoLCBHbG9iYWwpIHsgLy8gTk9TT05BUlxuICAgIC8vc2V0YWRvIG5vIHJvb3RTY29wZSBwYXJhIHBvZGVyIHNlciBhY2Vzc2FkbyBuYXMgdmlld3Mgc2VtIHByZWZpeG8gZGUgY29udHJvbGxlclxuICAgICRyb290U2NvcGUuJHN0YXRlID0gJHN0YXRlO1xuICAgICRyb290U2NvcGUuJHN0YXRlUGFyYW1zID0gJHN0YXRlUGFyYW1zO1xuICAgICRyb290U2NvcGUuYXV0aCA9IEF1dGg7XG4gICAgJHJvb3RTY29wZS5nbG9iYWwgPSBHbG9iYWw7XG5cbiAgICAvL25vIGluaWNpbyBjYXJyZWdhIG8gdXN1w6FyaW8gZG8gbG9jYWxzdG9yYWdlIGNhc28gbyB1c3XDoXJpbyBlc3RhamEgYWJyaW5kbyBvIG5hdmVnYWRvclxuICAgIC8vcGFyYSB2b2x0YXIgYXV0ZW50aWNhZG9cbiAgICBBdXRoLnJldHJpZXZlVXNlckZyb21Mb2NhbFN0b3JhZ2UoKTtcbiAgfVxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnRyb2xsZXIoJ0F1ZGl0Q29udHJvbGxlcicsIEF1ZGl0Q29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBBdWRpdENvbnRyb2xsZXIoJGNvbnRyb2xsZXIsIEF1ZGl0U2VydmljZSwgUHJEaWFsb2csIEdsb2JhbCwgJHRyYW5zbGF0ZSkgeyAvLyBOT1NPTkFSXG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIHZtLm9uQWN0aXZhdGUgPSBvbkFjdGl2YXRlO1xuICAgIHZtLmFwcGx5RmlsdGVycyA9IGFwcGx5RmlsdGVycztcbiAgICB2bS52aWV3RGV0YWlsID0gdmlld0RldGFpbDtcblxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHsgdm06IHZtLCBtb2RlbFNlcnZpY2U6IEF1ZGl0U2VydmljZSwgb3B0aW9uczoge30gfSk7XG5cbiAgICBmdW5jdGlvbiBvbkFjdGl2YXRlKCkge1xuICAgICAgdm0ubW9kZWxzID0gW107XG4gICAgICB2bS5xdWVyeUZpbHRlcnMgPSB7fTtcblxuICAgICAgLy9QZWdhIHRvZG9zIG9zIG1vZGVscyBkbyBzZXJ2ZXIgZSBtb250YSB1bWEgbGlzdGEgcHJvIENvbWJvQm94XG4gICAgICBBdWRpdFNlcnZpY2UuZ2V0QXVkaXRlZE1vZGVscygpLnRoZW4oZnVuY3Rpb24oZGF0YSkge1xuICAgICAgICB2YXIgbW9kZWxzID0gW3sgaWQ6ICcnLCBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KCdnbG9iYWwuYWxsJykgfV07XG5cbiAgICAgICAgZGF0YS5tb2RlbHMuc29ydCgpO1xuXG4gICAgICAgIGZvciAodmFyIGluZGV4ID0gMDsgaW5kZXggPCBkYXRhLm1vZGVscy5sZW5ndGg7IGluZGV4KyspIHtcbiAgICAgICAgICB2YXIgbW9kZWwgPSBkYXRhLm1vZGVsc1tpbmRleF07XG5cbiAgICAgICAgICBtb2RlbHMucHVzaCh7XG4gICAgICAgICAgICBpZDogbW9kZWwsXG4gICAgICAgICAgICBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KCdtb2RlbHMuJyArIG1vZGVsLnRvTG93ZXJDYXNlKCkpXG4gICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICB2bS5tb2RlbHMgPSBtb2RlbHM7XG4gICAgICAgIHZtLnF1ZXJ5RmlsdGVycy5tb2RlbCA9IHZtLm1vZGVsc1swXS5pZDtcbiAgICAgIH0pO1xuXG4gICAgICB2bS50eXBlcyA9IEF1ZGl0U2VydmljZS5saXN0VHlwZXMoKTtcbiAgICAgIHZtLnF1ZXJ5RmlsdGVycy50eXBlID0gdm0udHlwZXNbMF0uaWQ7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gYXBwbHlGaWx0ZXJzKGRlZmF1bHRRdWVyeUZpbHRlcnMpIHtcbiAgICAgIHJldHVybiBhbmd1bGFyLmV4dGVuZChkZWZhdWx0UXVlcnlGaWx0ZXJzLCB2bS5xdWVyeUZpbHRlcnMpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIHZpZXdEZXRhaWwoYXVkaXREZXRhaWwpIHtcbiAgICAgIHZhciBjb25maWcgPSB7XG4gICAgICAgIGxvY2FsczogeyBhdWRpdERldGFpbDogYXVkaXREZXRhaWwgfSxcbiAgICAgICAgLyoqIEBuZ0luamVjdCAqL1xuICAgICAgICBjb250cm9sbGVyOiBmdW5jdGlvbihhdWRpdERldGFpbCwgUHJEaWFsb2cpIHtcbiAgICAgICAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgICAgICAgdm0uY2xvc2UgPSBjbG9zZTtcblxuICAgICAgICAgIGFjdGl2YXRlKCk7XG5cbiAgICAgICAgICBmdW5jdGlvbiBhY3RpdmF0ZSgpIHtcbiAgICAgICAgICAgIGlmIChhbmd1bGFyLmlzQXJyYXkoYXVkaXREZXRhaWwub2xkKSAmJiBhdWRpdERldGFpbC5vbGQubGVuZ3RoID09PSAwKSBhdWRpdERldGFpbC5vbGQgPSBudWxsO1xuICAgICAgICAgICAgaWYgKGFuZ3VsYXIuaXNBcnJheShhdWRpdERldGFpbC5uZXcpICYmIGF1ZGl0RGV0YWlsLm5ldy5sZW5ndGggPT09IDApIGF1ZGl0RGV0YWlsLm5ldyA9IG51bGw7XG5cbiAgICAgICAgICAgIHZtLmF1ZGl0RGV0YWlsID0gYXVkaXREZXRhaWw7XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgZnVuY3Rpb24gY2xvc2UoKSB7XG4gICAgICAgICAgICBQckRpYWxvZy5jbG9zZSgpO1xuICAgICAgICAgIH1cblxuICAgICAgICB9LFxuICAgICAgICBjb250cm9sbGVyQXM6ICdhdWRpdERldGFpbEN0cmwnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL2F1ZGl0L2F1ZGl0LWRldGFpbC5odG1sJyxcbiAgICAgICAgaGFzQmFja2Ryb3A6IHRydWVcbiAgICAgIH07XG5cbiAgICAgIFByRGlhbG9nLmN1c3RvbShjb25maWcpO1xuICAgIH1cblxuICB9XG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqXG4gICAqIEFycXVpdm8gZGUgY29uZmlndXJhw6fDo28gY29tIGFzIHJvdGFzIGVzcGVjw61maWNhcyBkZSBhdWRpdG9yaWFcbiAgICpcbiAgICogQHBhcmFtIHthbnl9ICRzdGF0ZVByb3ZpZGVyXG4gICAqIEBwYXJhbSB7YW55fSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlclxuICAgICAgLnN0YXRlKCdhcHAuYXVkaXQnLCB7XG4gICAgICAgIHVybDogJy9hdWRpdG9yaWEnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL2F1ZGl0L2F1ZGl0Lmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnQXVkaXRDb250cm9sbGVyIGFzIGF1ZGl0Q3RybCcsXG4gICAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiB0cnVlLCBuZWVkUHJvZmlsZTogWydhZG1pbiddIH1cbiAgICAgIH0pO1xuXG4gIH1cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmFjdG9yeSgnQXVkaXRTZXJ2aWNlJywgQXVkaXRTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIEF1ZGl0U2VydmljZShzZXJ2aWNlRmFjdG9yeSwgJHRyYW5zbGF0ZSkge1xuICAgIHJldHVybiBzZXJ2aWNlRmFjdG9yeSgnYXVkaXQnLCB7XG4gICAgICBhY3Rpb25zOiB7XG4gICAgICAgIGdldEF1ZGl0ZWRNb2RlbHM6IHtcbiAgICAgICAgICBtZXRob2Q6ICdHRVQnLFxuICAgICAgICAgIHVybDogJ21vZGVscydcbiAgICAgICAgfVxuICAgICAgfSxcbiAgICAgIGluc3RhbmNlOiB7XG4gICAgICB9LFxuICAgICAgbGlzdFR5cGVzOiBmdW5jdGlvbigpIHtcbiAgICAgICAgdmFyIGF1ZGl0UGF0aCA9ICd2aWV3cy5maWVsZHMuYXVkaXQuJztcblxuICAgICAgICByZXR1cm4gW1xuICAgICAgICAgIHsgaWQ6ICcnLCBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KGF1ZGl0UGF0aCArICdhbGxSZXNvdXJjZXMnKSB9LFxuICAgICAgICAgIHsgaWQ6ICdjcmVhdGVkJywgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudChhdWRpdFBhdGggKyAndHlwZS5jcmVhdGVkJykgfSxcbiAgICAgICAgICB7IGlkOiAndXBkYXRlZCcsIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoYXVkaXRQYXRoICsgJ3R5cGUudXBkYXRlZCcpIH0sXG4gICAgICAgICAgeyBpZDogJ2RlbGV0ZWQnLCBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KGF1ZGl0UGF0aCArICd0eXBlLmRlbGV0ZWQnKSB9XG4gICAgICAgIF07XG4gICAgICB9XG4gICAgfSk7XG4gIH1cblxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb25maWcocm91dGVzKTtcblxuICAvKipcbiAgICogQXJxdWl2byBkZSBjb25maWd1cmHDp8OjbyBjb20gYXMgcm90YXMgZXNwZWPDrWZpY2FzIGRvIHJlY3Vyc28gdXNlclxuICAgKlxuICAgKiBAcGFyYW0ge2FueX0gJHN0YXRlUHJvdmlkZXJcbiAgICogQHBhcmFtIHthbnl9IEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyXG4gICAgICAuc3RhdGUoR2xvYmFsLnJlc2V0UGFzc3dvcmRTdGF0ZSwge1xuICAgICAgICB1cmw6ICcvcGFzc3dvcmQvcmVzZXQvOnRva2VuJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9hdXRoL3Jlc2V0LXBhc3MtZm9ybS5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ1Bhc3N3b3JkQ29udHJvbGxlciBhcyBwYXNzQ3RybCcsXG4gICAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiBmYWxzZSB9XG4gICAgICB9KVxuICAgICAgLnN0YXRlKEdsb2JhbC5sb2dpblN0YXRlLCB7XG4gICAgICAgIHVybDogJy9sb2dpbicsXG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvYXV0aC9sb2dpbi5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ0xvZ2luQ29udHJvbGxlciBhcyBsb2dpbkN0cmwnLFxuICAgICAgICBkYXRhOiB7IG5lZWRBdXRoZW50aWNhdGlvbjogZmFsc2UgfVxuICAgICAgfSk7XG5cbiAgfVxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5mYWN0b3J5KCdBdXRoJywgQXV0aCk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBBdXRoKCRodHRwLCAkcSwgR2xvYmFsLCBVc2Vyc1NlcnZpY2UpIHsgLy8gTk9TT05BUlxuICAgIHZhciBhdXRoID0ge1xuICAgICAgbG9naW46IGxvZ2luLFxuICAgICAgbG9nb3V0OiBsb2dvdXQsXG4gICAgICB1cGRhdGVDdXJyZW50VXNlcjogdXBkYXRlQ3VycmVudFVzZXIsXG4gICAgICByZXRyaWV2ZVVzZXJGcm9tTG9jYWxTdG9yYWdlOiByZXRyaWV2ZVVzZXJGcm9tTG9jYWxTdG9yYWdlLFxuICAgICAgYXV0aGVudGljYXRlZDogYXV0aGVudGljYXRlZCxcbiAgICAgIHNlbmRFbWFpbFJlc2V0UGFzc3dvcmQ6IHNlbmRFbWFpbFJlc2V0UGFzc3dvcmQsXG4gICAgICByZW1vdGVWYWxpZGF0ZVRva2VuOiByZW1vdGVWYWxpZGF0ZVRva2VuLFxuICAgICAgZ2V0VG9rZW46IGdldFRva2VuLFxuICAgICAgc2V0VG9rZW46IHNldFRva2VuLFxuICAgICAgY2xlYXJUb2tlbjogY2xlYXJUb2tlbixcbiAgICAgIGN1cnJlbnRVc2VyOiBudWxsXG4gICAgfTtcblxuICAgIGZ1bmN0aW9uIGNsZWFyVG9rZW4oKSB7XG4gICAgICBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbShHbG9iYWwudG9rZW5LZXkpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIHNldFRva2VuKHRva2VuKSB7XG4gICAgICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbShHbG9iYWwudG9rZW5LZXksIHRva2VuKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBnZXRUb2tlbigpIHtcbiAgICAgIHJldHVybiBsb2NhbFN0b3JhZ2UuZ2V0SXRlbShHbG9iYWwudG9rZW5LZXkpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIHJlbW90ZVZhbGlkYXRlVG9rZW4oKSB7XG4gICAgICB2YXIgZGVmZXJyZWQgPSAkcS5kZWZlcigpO1xuXG4gICAgICBpZiAoYXV0aC5hdXRoZW50aWNhdGVkKCkpIHtcbiAgICAgICAgJGh0dHAuZ2V0KEdsb2JhbC5hcGlQYXRoICsgJy9hdXRoZW50aWNhdGUvY2hlY2snKVxuICAgICAgICAgIC50aGVuKGZ1bmN0aW9uKCkge1xuICAgICAgICAgICAgZGVmZXJyZWQucmVzb2x2ZSh0cnVlKTtcbiAgICAgICAgICB9LCBmdW5jdGlvbigpIHtcbiAgICAgICAgICAgIGF1dGgubG9nb3V0KCk7XG5cbiAgICAgICAgICAgIGRlZmVycmVkLnJlamVjdChmYWxzZSk7XG4gICAgICAgICAgfSk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBhdXRoLmxvZ291dCgpO1xuXG4gICAgICAgIGRlZmVycmVkLnJlamVjdChmYWxzZSk7XG4gICAgICB9XG5cbiAgICAgIHJldHVybiBkZWZlcnJlZC5wcm9taXNlO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFZlcmlmaWNhIHNlIG8gdXN1w6FyaW8gZXN0w6EgYXV0ZW50aWNhZG9cbiAgICAgKlxuICAgICAqIEByZXR1cm5zIHtib29sZWFufVxuICAgICAqL1xuICAgIGZ1bmN0aW9uIGF1dGhlbnRpY2F0ZWQoKSB7XG4gICAgICByZXR1cm4gYXV0aC5nZXRUb2tlbigpICE9PSBudWxsXG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVjdXBlcmEgbyB1c3XDoXJpbyBkbyBsb2NhbFN0b3JhZ2VcbiAgICAgKi9cbiAgICBmdW5jdGlvbiByZXRyaWV2ZVVzZXJGcm9tTG9jYWxTdG9yYWdlKCkge1xuICAgICAgdmFyIHVzZXIgPSBsb2NhbFN0b3JhZ2UuZ2V0SXRlbSgndXNlcicpO1xuXG4gICAgICBpZiAodXNlcikge1xuICAgICAgICBhdXRoLmN1cnJlbnRVc2VyID0gYW5ndWxhci5tZXJnZShuZXcgVXNlcnNTZXJ2aWNlKCksIGFuZ3VsYXIuZnJvbUpzb24odXNlcikpO1xuICAgICAgfVxuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEd1YXJkYSBvIHVzdcOhcmlvIG5vIGxvY2FsU3RvcmFnZSBwYXJhIGNhc28gbyB1c3XDoXJpbyBmZWNoZSBlIGFicmEgbyBuYXZlZ2Fkb3JcbiAgICAgKiBkZW50cm8gZG8gdGVtcG8gZGUgc2Vzc8OjbyBzZWphIHBvc3PDrXZlbCByZWN1cGVyYXIgbyB0b2tlbiBhdXRlbnRpY2Fkby5cbiAgICAgKlxuICAgICAqIE1hbnTDqW0gYSB2YXJpw6F2ZWwgYXV0aC5jdXJyZW50VXNlciBwYXJhIGZhY2lsaXRhciBvIGFjZXNzbyBhbyB1c3XDoXJpbyBsb2dhZG8gZW0gdG9kYSBhIGFwbGljYcOnw6NvXG4gICAgICpcbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSB1c2VyIFVzdcOhcmlvIGEgc2VyIGF0dWFsaXphZG8uIENhc28gc2VqYSBwYXNzYWRvIG51bGwgbGltcGFcbiAgICAgKiB0b2RhcyBhcyBpbmZvcm1hw6fDtWVzIGRvIHVzdcOhcmlvIGNvcnJlbnRlLlxuICAgICAqL1xuICAgIGZ1bmN0aW9uIHVwZGF0ZUN1cnJlbnRVc2VyKHVzZXIpIHtcbiAgICAgIHZhciBkZWZlcnJlZCA9ICRxLmRlZmVyKCk7XG5cbiAgICAgIGlmICh1c2VyKSB7XG4gICAgICAgIHVzZXIgPSBhbmd1bGFyLm1lcmdlKG5ldyBVc2Vyc1NlcnZpY2UoKSwgdXNlcik7XG5cbiAgICAgICAgdmFyIGpzb25Vc2VyID0gYW5ndWxhci50b0pzb24odXNlcik7XG5cbiAgICAgICAgbG9jYWxTdG9yYWdlLnNldEl0ZW0oJ3VzZXInLCBqc29uVXNlcik7XG4gICAgICAgIGF1dGguY3VycmVudFVzZXIgPSB1c2VyO1xuXG4gICAgICAgIGRlZmVycmVkLnJlc29sdmUodXNlcik7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbSgndXNlcicpO1xuICAgICAgICBhdXRoLmN1cnJlbnRVc2VyID0gbnVsbDtcbiAgICAgICAgYXV0aC5jbGVhclRva2VuKCk7XG5cbiAgICAgICAgZGVmZXJyZWQucmVqZWN0KCk7XG4gICAgICB9XG5cbiAgICAgIHJldHVybiBkZWZlcnJlZC5wcm9taXNlO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWxpemEgbyBsb2dpbiBkbyB1c3XDoXJpb1xuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IGNyZWRlbnRpYWxzIEVtYWlsIGUgU2VuaGEgZG8gdXN1w6FyaW9cbiAgICAgKiBAcmV0dXJucyB7cHJvbWlzZX0gVW1hIHByb21pc2UgY29tIG8gcmVzdWx0YWRvIGRvIGNoYW1hZGEgbm8gYmFja2VuZFxuICAgICAqL1xuICAgIGZ1bmN0aW9uIGxvZ2luKGNyZWRlbnRpYWxzKSB7XG4gICAgICB2YXIgZGVmZXJyZWQgPSAkcS5kZWZlcigpO1xuXG4gICAgICAkaHR0cC5wb3N0KEdsb2JhbC5hcGlQYXRoICsgJy9hdXRoZW50aWNhdGUnLCBjcmVkZW50aWFscylcbiAgICAgICAgLnRoZW4oZnVuY3Rpb24ocmVzcG9uc2UpIHtcbiAgICAgICAgICBhdXRoLnNldFRva2VuKHJlc3BvbnNlLmRhdGEudG9rZW4pO1xuXG4gICAgICAgICAgcmV0dXJuICRodHRwLmdldChHbG9iYWwuYXBpUGF0aCArICcvYXV0aGVudGljYXRlL3VzZXInKTtcbiAgICAgICAgfSlcbiAgICAgICAgLnRoZW4oZnVuY3Rpb24ocmVzcG9uc2UpIHtcbiAgICAgICAgICBhdXRoLnVwZGF0ZUN1cnJlbnRVc2VyKHJlc3BvbnNlLmRhdGEudXNlcik7XG5cbiAgICAgICAgICBkZWZlcnJlZC5yZXNvbHZlKCk7XG4gICAgICAgIH0sIGZ1bmN0aW9uKGVycm9yKSB7XG4gICAgICAgICAgYXV0aC5sb2dvdXQoKTtcblxuICAgICAgICAgIGRlZmVycmVkLnJlamVjdChlcnJvcik7XG4gICAgICAgIH0pO1xuXG4gICAgICByZXR1cm4gZGVmZXJyZWQucHJvbWlzZTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBEZXNsb2dhIG9zIHVzdcOhcmlvcy4gQ29tbyBuw6NvIHRlbiBuZW5odW1hIGluZm9ybWHDp8OjbyBuYSBzZXNzw6NvIGRvIHNlcnZpZG9yXG4gICAgICogZSB1bSB0b2tlbiB1bWEgdmV6IGdlcmFkbyBuw6NvIHBvZGUsIHBvciBwYWRyw6NvLCBzZXIgaW52YWxpZGFkbyBhbnRlcyBkbyBzZXUgdGVtcG8gZGUgZXhwaXJhw6fDo28sXG4gICAgICogc29tZW50ZSBhcGFnYW1vcyBvcyBkYWRvcyBkbyB1c3XDoXJpbyBlIG8gdG9rZW4gZG8gbmF2ZWdhZG9yIHBhcmEgZWZldGl2YXIgbyBsb2dvdXQuXG4gICAgICpcbiAgICAgKiBAcmV0dXJucyB7cHJvbWlzZX0gVW1hIHByb21pc2UgY29tIG8gcmVzdWx0YWRvIGRhIG9wZXJhw6fDo29cbiAgICAgKi9cbiAgICBmdW5jdGlvbiBsb2dvdXQoKSB7XG4gICAgICB2YXIgZGVmZXJyZWQgPSAkcS5kZWZlcigpO1xuXG4gICAgICBhdXRoLnVwZGF0ZUN1cnJlbnRVc2VyKG51bGwpO1xuICAgICAgZGVmZXJyZWQucmVzb2x2ZSgpO1xuXG4gICAgICByZXR1cm4gZGVmZXJyZWQucHJvbWlzZTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBFbnZpYSB1bSBlbWFpbCBwYXJhIHJlY3VwZXJhw6fDo28gZGUgc2VuaGFcbiAgICAgKiBAcGFyYW0ge09iamVjdH0gcmVzZXREYXRhIC0gT2JqZXRvIGNvbnRlbmRvIG8gZW1haWxcbiAgICAgKiBAcmV0dXJuIHtQcm9taXNlfSAtIFJldG9ybmEgdW1hIHByb21pc2UgcGFyYSBzZXIgcmVzb2x2aWRhXG4gICAgICovXG4gICAgZnVuY3Rpb24gc2VuZEVtYWlsUmVzZXRQYXNzd29yZChyZXNldERhdGEpIHtcbiAgICAgIHZhciBkZWZlcnJlZCA9ICRxLmRlZmVyKCk7XG5cbiAgICAgICRodHRwLnBvc3QoR2xvYmFsLmFwaVBhdGggKyAnL3Bhc3N3b3JkL2VtYWlsJywgcmVzZXREYXRhKVxuICAgICAgICAudGhlbihmdW5jdGlvbihyZXNwb25zZSkge1xuICAgICAgICAgIGRlZmVycmVkLnJlc29sdmUocmVzcG9uc2UuZGF0YSk7XG4gICAgICAgIH0sIGZ1bmN0aW9uKGVycm9yKSB7XG4gICAgICAgICAgZGVmZXJyZWQucmVqZWN0KGVycm9yKTtcbiAgICAgICAgfSk7XG5cbiAgICAgIHJldHVybiBkZWZlcnJlZC5wcm9taXNlO1xuICAgIH1cblxuICAgIHJldHVybiBhdXRoO1xuICB9XG5cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb250cm9sbGVyKCdMb2dpbkNvbnRyb2xsZXInLCBMb2dpbkNvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gTG9naW5Db250cm9sbGVyKCRzdGF0ZSwgQXV0aCwgR2xvYmFsLCBQckRpYWxvZykge1xuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICB2bS5sb2dpbiA9IGxvZ2luO1xuICAgIHZtLm9wZW5EaWFsb2dSZXNldFBhc3MgPSBvcGVuRGlhbG9nUmVzZXRQYXNzO1xuICAgIHZtLm9wZW5EaWFsb2dTaWduVXAgPSBvcGVuRGlhbG9nU2lnblVwO1xuXG4gICAgYWN0aXZhdGUoKTtcblxuICAgIGZ1bmN0aW9uIGFjdGl2YXRlKCkge1xuICAgICAgdm0uY3JlZGVudGlhbHMgPSB7fTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBsb2dpbigpIHtcbiAgICAgIHZhciBjcmVkZW50aWFscyA9IHtcbiAgICAgICAgZW1haWw6IHZtLmNyZWRlbnRpYWxzLmVtYWlsLFxuICAgICAgICBwYXNzd29yZDogdm0uY3JlZGVudGlhbHMucGFzc3dvcmRcbiAgICAgIH07XG5cbiAgICAgIEF1dGgubG9naW4oY3JlZGVudGlhbHMpLnRoZW4oZnVuY3Rpb24oKSB7XG4gICAgICAgICRzdGF0ZS5nbyhHbG9iYWwuaG9tZVN0YXRlKTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEV4aWJlIG8gZGlhbG9nIHBhcmEgcmVjdXBlcmHDp8OjbyBkZSBzZW5oYVxuICAgICAqL1xuICAgIGZ1bmN0aW9uIG9wZW5EaWFsb2dSZXNldFBhc3MoKSB7XG4gICAgICB2YXIgY29uZmlnID0ge1xuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL2F1dGgvc2VuZC1yZXNldC1kaWFsb2cuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdQYXNzd29yZENvbnRyb2xsZXIgYXMgcGFzc0N0cmwnLFxuICAgICAgICBoYXNCYWNrZHJvcDogdHJ1ZVxuICAgICAgfVxuXG4gICAgICBQckRpYWxvZy5jdXN0b20oY29uZmlnKTtcbiAgICB9XG4gICAgLyoqXG4gICAgICogRXhpYmUgbyBkaWFsb2cgcGFyYSByZWN1cGVyYcOnw6NvIGRlIHNlbmhhXG4gICAgICovXG4gICAgZnVuY3Rpb24gb3BlbkRpYWxvZ1NpZ25VcCgpIHtcbiAgICAgIHZhciBjb25maWcgPSB7XG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvdXNlcnMvdXNlci1mb3JtLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnVXNlcnNDb250cm9sbGVyIGFzIHVzZXJzQ3RybCcsXG4gICAgICAgIGhhc0JhY2tkcm9wOiB0cnVlXG4gICAgICB9XG5cbiAgICAgIFByRGlhbG9nLmN1c3RvbShjb25maWcpO1xuICAgIH1cblxuICB9XG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29udHJvbGxlcignUGFzc3dvcmRDb250cm9sbGVyJywgUGFzc3dvcmRDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIFBhc3N3b3JkQ29udHJvbGxlcihHbG9iYWwsICRzdGF0ZVBhcmFtcywgJGh0dHAsICR0aW1lb3V0LCAkc3RhdGUsIC8vIE5PU09OQVJcbiAgICBQclRvYXN0LCBQckRpYWxvZywgQXV0aCwgJHRyYW5zbGF0ZSkge1xuXG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIHZtLnNlbmRSZXNldCA9IHNlbmRSZXNldDtcbiAgICB2bS5jbG9zZURpYWxvZyA9IGNsb3NlRGlhbG9nO1xuICAgIHZtLmNsZWFuRm9ybSA9IGNsZWFuRm9ybTtcbiAgICB2bS5zZW5kRW1haWxSZXNldFBhc3N3b3JkID0gc2VuZEVtYWlsUmVzZXRQYXNzd29yZDtcblxuICAgIGFjdGl2YXRlKCk7XG5cbiAgICBmdW5jdGlvbiBhY3RpdmF0ZSgpIHtcbiAgICAgIHZtLnJlc2V0ID0geyBlbWFpbDogJycsIHRva2VuOiAkc3RhdGVQYXJhbXMudG9rZW4gfTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFsaXphIGEgYWx0ZXJhw6fDo28gZGEgc2VuaGEgZG8gdXN1w6FyaW8gZSBvIHJlZGlyZWNpb25hIHBhcmEgYSB0ZWxhIGRlIGxvZ2luXG4gICAgICovXG4gICAgZnVuY3Rpb24gc2VuZFJlc2V0KCkge1xuICAgICAgJGh0dHAucG9zdChHbG9iYWwuYXBpUGF0aCArICcvcGFzc3dvcmQvcmVzZXQnLCB2bS5yZXNldClcbiAgICAgICAgLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICAgIFByVG9hc3Quc3VjY2VzcygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLm9wZXJhdGlvblN1Y2Nlc3MnKSk7XG4gICAgICAgICAgJHRpbWVvdXQoZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgJHN0YXRlLmdvKEdsb2JhbC5sb2dpblN0YXRlKTtcbiAgICAgICAgICB9LCAxNTAwKTtcbiAgICAgICAgfSwgZnVuY3Rpb24gKGVycm9yKSB7XG4gICAgICAgICAgaWYgKGVycm9yLnN0YXR1cyAhPT0gNDAwICYmIGVycm9yLnN0YXR1cyAhPT0gNTAwKSB7XG4gICAgICAgICAgICB2YXIgbXNnID0gJyc7XG5cbiAgICAgICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgZXJyb3IuZGF0YS5wYXNzd29yZC5sZW5ndGg7IGkrKykge1xuICAgICAgICAgICAgICBtc2cgKz0gZXJyb3IuZGF0YS5wYXNzd29yZFtpXSArICc8YnI+JztcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIFByVG9hc3QuZXJyb3IobXNnLnRvVXBwZXJDYXNlKCkpO1xuICAgICAgICAgIH1cbiAgICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogRW52aWEgdW0gZW1haWwgZGUgcmVjdXBlcmHDp8OjbyBkZSBzZW5oYSBjb20gbyB0b2tlbiBkbyB1c3XDoXJpb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIHNlbmRFbWFpbFJlc2V0UGFzc3dvcmQoKSB7XG5cbiAgICAgIGlmICh2bS5yZXNldC5lbWFpbCA9PT0gJycpIHtcbiAgICAgICAgUHJUb2FzdC5lcnJvcigkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnZhbGlkYXRlLmZpZWxkUmVxdWlyZWQnLCB7IGZpZWxkOiAnZW1haWwnIH0pKTtcbiAgICAgICAgcmV0dXJuO1xuICAgICAgfVxuXG4gICAgICBBdXRoLnNlbmRFbWFpbFJlc2V0UGFzc3dvcmQodm0ucmVzZXQpLnRoZW4oZnVuY3Rpb24gKGRhdGEpIHtcbiAgICAgICAgUHJUb2FzdC5zdWNjZXNzKGRhdGEubWVzc2FnZSk7XG5cbiAgICAgICAgdm0uY2xlYW5Gb3JtKCk7XG4gICAgICAgIHZtLmNsb3NlRGlhbG9nKCk7XG4gICAgICB9LCBmdW5jdGlvbiAoZXJyb3IpIHtcbiAgICAgICAgaWYgKGVycm9yLmRhdGEuZW1haWwgJiYgZXJyb3IuZGF0YS5lbWFpbC5sZW5ndGggPiAwKSB7XG4gICAgICAgICAgdmFyIG1zZyA9ICcnO1xuXG4gICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCBlcnJvci5kYXRhLmVtYWlsLmxlbmd0aDsgaSsrKSB7XG4gICAgICAgICAgICBtc2cgKz0gZXJyb3IuZGF0YS5lbWFpbFtpXSArICc8YnI+JztcbiAgICAgICAgICB9XG5cbiAgICAgICAgICBQclRvYXN0LmVycm9yKG1zZyk7XG4gICAgICAgIH1cbiAgICAgIH0pO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGNsb3NlRGlhbG9nKCkge1xuICAgICAgUHJEaWFsb2cuY2xvc2UoKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBjbGVhbkZvcm0oKSB7XG4gICAgICB2bS5yZXNldC5lbWFpbCA9ICcnO1xuICAgIH1cblxuICB9XG5cbn0pKCk7XG4iLCIvKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCovXG4oZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmFjdG9yeSgnc2VydmljZUZhY3RvcnknLCBzZXJ2aWNlRmFjdG9yeSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvKipcbiAgICogTWFpcyBpbmZvcm1hw6fDtWVzOlxuICAgKiBodHRwczovL2dpdGh1Yi5jb20vc3dpbWxhbmUvYW5ndWxhci1tb2RlbC1mYWN0b3J5L3dpa2kvQVBJXG4gICAqL1xuICBmdW5jdGlvbiBzZXJ2aWNlRmFjdG9yeSgkbW9kZWxGYWN0b3J5KSB7XG4gICAgcmV0dXJuIGZ1bmN0aW9uKHVybCwgb3B0aW9ucykge1xuICAgICAgdmFyIG1vZGVsO1xuICAgICAgdmFyIGRlZmF1bHRPcHRpb25zID0ge1xuICAgICAgICBhY3Rpb25zOiB7XG4gICAgICAgICAgLyoqXG4gICAgICAgICAgICogU2VydmnDp28gY29tdW0gcGFyYSByZWFsaXphciBidXNjYSBjb20gcGFnaW5hw6fDo29cbiAgICAgICAgICAgKiBPIG1lc21vIGVzcGVyYSBxdWUgc2VqYSByZXRvcm5hZG8gdW0gb2JqZXRvIGNvbSBpdGVtcyBlIHRvdGFsXG4gICAgICAgICAgICovXG4gICAgICAgICAgcGFnaW5hdGU6IHtcbiAgICAgICAgICAgIG1ldGhvZDogJ0dFVCcsXG4gICAgICAgICAgICBpc0FycmF5OiBmYWxzZSxcbiAgICAgICAgICAgIHdyYXA6IGZhbHNlLFxuICAgICAgICAgICAgYWZ0ZXJSZXF1ZXN0OiBmdW5jdGlvbihyZXNwb25zZSkge1xuICAgICAgICAgICAgICBpZiAocmVzcG9uc2VbJ2l0ZW1zJ10pIHtcbiAgICAgICAgICAgICAgICByZXNwb25zZVsnaXRlbXMnXSA9IG1vZGVsLkxpc3QocmVzcG9uc2VbJ2l0ZW1zJ10pO1xuICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgcmV0dXJuIHJlc3BvbnNlO1xuICAgICAgICAgICAgfVxuICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgfVxuXG4gICAgICBtb2RlbCA9ICRtb2RlbEZhY3RvcnkodXJsLCBhbmd1bGFyLm1lcmdlKGRlZmF1bHRPcHRpb25zLCBvcHRpb25zKSlcblxuICAgICAgcmV0dXJuIG1vZGVsO1xuICAgIH1cbiAgfVxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnRyb2xsZXIoJ0NSVURDb250cm9sbGVyJywgQ1JVRENvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLyoqXG4gICAqIENvbnRyb2xhZG9yIEJhc2UgcXVlIGltcGxlbWVudGEgdG9kYXMgYXMgZnVuw6fDtWVzIHBhZHLDtWVzIGRlIHVtIENSVURcbiAgICpcbiAgICogQcOnw7VlcyBpbXBsZW1lbnRhZGFzXG4gICAqIGFjdGl2YXRlKClcbiAgICogc2VhcmNoKHBhZ2UpXG4gICAqIGVkaXQocmVzb3VyY2UpXG4gICAqIHNhdmUoKVxuICAgKiByZW1vdmUocmVzb3VyY2UpXG4gICAqIGdvVG8odmlld05hbWUpXG4gICAqIGNsZWFuRm9ybSgpXG4gICAqXG4gICAqIEdhdGlsaG9zXG4gICAqXG4gICAqIG9uQWN0aXZhdGUoKVxuICAgKiBhcHBseUZpbHRlcnMoZGVmYXVsdFF1ZXJ5RmlsdGVycylcbiAgICogYmVmb3JlU2VhcmNoKHBhZ2UpIC8vcmV0b3JuYW5kbyBmYWxzZSBjYW5jZWxhIG8gZmx1eG9cbiAgICogYWZ0ZXJTZWFyY2gocmVzcG9uc2UpXG4gICAqIGJlZm9yZUNsZWFuIC8vcmV0b3JuYW5kbyBmYWxzZSBjYW5jZWxhIG8gZmx1eG9cbiAgICogYWZ0ZXJDbGVhbigpXG4gICAqIGJlZm9yZVNhdmUoKSAvL3JldG9ybmFuZG8gZmFsc2UgY2FuY2VsYSBvIGZsdXhvXG4gICAqIGFmdGVyU2F2ZShyZXNvdXJjZSlcbiAgICogb25TYXZlRXJyb3IoZXJyb3IpXG4gICAqIGJlZm9yZVJlbW92ZShyZXNvdXJjZSkgLy9yZXRvcm5hbmRvIGZhbHNlIGNhbmNlbGEgbyBmbHV4b1xuICAgKiBhZnRlclJlbW92ZShyZXNvdXJjZSlcbiAgICpcbiAgICogQHBhcmFtIHthbnl9IHZtIGluc3RhbmNpYSBkbyBjb250cm9sbGVyIGZpbGhvXG4gICAqIEBwYXJhbSB7YW55fSBtb2RlbFNlcnZpY2Ugc2VydmnDp28gZG8gbW9kZWwgcXVlIHZhaSBzZXIgdXRpbGl6YWRvXG4gICAqIEBwYXJhbSB7YW55fSBvcHRpb25zIG9ww6fDtWVzIHBhcmEgc29icmVlc2NyZXZlciBjb21wb3J0YW1lbnRvcyBwYWRyw7Vlc1xuICAgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gQ1JVRENvbnRyb2xsZXIodm0sIG1vZGVsU2VydmljZSwgb3B0aW9ucywgUHJUb2FzdCwgUHJQYWdpbmF0aW9uLCAvLyBOT1NPTkFSXG4gICAgUHJEaWFsb2csICR0cmFuc2xhdGUpIHtcblxuICAgIC8vRnVuY3Rpb25zIEJsb2NrXG4gICAgdm0uc2VhcmNoID0gc2VhcmNoO1xuICAgIHZtLnBhZ2luYXRlU2VhcmNoID0gcGFnaW5hdGVTZWFyY2g7XG4gICAgdm0ubm9ybWFsU2VhcmNoID0gbm9ybWFsU2VhcmNoO1xuICAgIHZtLmVkaXQgPSBlZGl0O1xuICAgIHZtLnNhdmUgPSBzYXZlO1xuICAgIHZtLnJlbW92ZSA9IHJlbW92ZTtcbiAgICB2bS5nb1RvID0gZ29UbztcbiAgICB2bS5jbGVhbkZvcm0gPSBjbGVhbkZvcm07XG5cbiAgICBhY3RpdmF0ZSgpO1xuXG4gICAgLyoqXG4gICAgICogUHJlcGFyYSBvIGNvbnRyb2xhZG9yXG4gICAgICogRmF6IG8gbWVyZ2UgZGFzIG9ww6fDtWVzXG4gICAgICogSW5pY2lhbGl6YSBvIHJlY3Vyc29cbiAgICAgKiBJbmljaWFsaXphIG8gb2JqZXRvIHBhZ2luYWRvciBlIHJlYWxpemEgYSBwZXNxdWlzYVxuICAgICAqL1xuICAgIGZ1bmN0aW9uIGFjdGl2YXRlKCkge1xuICAgICAgdm0uZGVmYXVsdE9wdGlvbnMgPSB7XG4gICAgICAgIHJlZGlyZWN0QWZ0ZXJTYXZlOiB0cnVlLFxuICAgICAgICBzZWFyY2hPbkluaXQ6IHRydWUsXG4gICAgICAgIHBlclBhZ2U6IDgsXG4gICAgICAgIHNraXBQYWdpbmF0aW9uOiBmYWxzZVxuICAgICAgfVxuXG4gICAgICBhbmd1bGFyLm1lcmdlKHZtLmRlZmF1bHRPcHRpb25zLCBvcHRpb25zKTtcblxuICAgICAgdm0udmlld0Zvcm0gPSBmYWxzZTtcbiAgICAgIHZtLnJlc291cmNlID0gbmV3IG1vZGVsU2VydmljZSgpO1xuXG4gICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLm9uQWN0aXZhdGUpKSB2bS5vbkFjdGl2YXRlKCk7XG5cbiAgICAgIHZtLnBhZ2luYXRvciA9IFByUGFnaW5hdGlvbi5nZXRJbnN0YW5jZSh2bS5zZWFyY2gsIHZtLmRlZmF1bHRPcHRpb25zLnBlclBhZ2UpO1xuXG4gICAgICBpZiAodm0uZGVmYXVsdE9wdGlvbnMuc2VhcmNoT25Jbml0KSB2bS5zZWFyY2goKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFsaXphIGEgcGVzcXVpc2FcbiAgICAgKiBWZXJpZmljYSBxdWFsIGRhcyBmdW7Dp8O1ZXMgZGUgcGVzcXVpc2EgZGV2ZSBzZXIgcmVhbGl6YWRhLlxuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IHBhZ2UgcMOhZ2luYSBxdWUgZGV2ZSBzZXIgY2FycmVnYWRhXG4gICAgICovXG4gICAgZnVuY3Rpb24gc2VhcmNoKHBhZ2UpIHtcbiAgICAgICh2bS5kZWZhdWx0T3B0aW9ucy5za2lwUGFnaW5hdGlvbikgPyBub3JtYWxTZWFyY2goKSA6IHBhZ2luYXRlU2VhcmNoKHBhZ2UpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWxpemEgYSBwZXNxdWlzYSBwYWdpbmFkYSBjb20gYmFzZSBub3MgZmlsdHJvcyBkZWZpbmlkb3NcbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSBwYWdlIHDDoWdpbmEgcXVlIGRldmUgc2VyIGNhcnJlZ2FkYVxuICAgICAqL1xuICAgIGZ1bmN0aW9uIHBhZ2luYXRlU2VhcmNoKHBhZ2UpIHtcbiAgICAgIHZtLnBhZ2luYXRvci5jdXJyZW50UGFnZSA9IChhbmd1bGFyLmlzRGVmaW5lZChwYWdlKSkgPyBwYWdlIDogMTtcbiAgICAgIHZtLmRlZmF1bHRRdWVyeUZpbHRlcnMgPSB7IHBhZ2U6IHZtLnBhZ2luYXRvci5jdXJyZW50UGFnZSwgcGVyUGFnZTogdm0ucGFnaW5hdG9yLnBlclBhZ2UgfTtcblxuICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5hcHBseUZpbHRlcnMpKSB2bS5kZWZhdWx0UXVlcnlGaWx0ZXJzID0gdm0uYXBwbHlGaWx0ZXJzKHZtLmRlZmF1bHRRdWVyeUZpbHRlcnMpO1xuICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5iZWZvcmVTZWFyY2gpICYmIHZtLmJlZm9yZVNlYXJjaChwYWdlKSA9PT0gZmFsc2UpIHJldHVybiBmYWxzZTtcblxuICAgICAgbW9kZWxTZXJ2aWNlLnBhZ2luYXRlKHZtLmRlZmF1bHRRdWVyeUZpbHRlcnMpLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgIHZtLnBhZ2luYXRvci5jYWxjTnVtYmVyT2ZQYWdlcyhyZXNwb25zZS50b3RhbCk7XG4gICAgICAgIHZtLnJlc291cmNlcyA9IHJlc3BvbnNlLml0ZW1zO1xuXG4gICAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYWZ0ZXJTZWFyY2gpKSB2bS5hZnRlclNlYXJjaChyZXNwb25zZSk7XG4gICAgICB9LCBmdW5jdGlvbiAocmVzcG9uc2VEYXRhKSB7XG4gICAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0ub25TZWFyY2hFcnJvcikpIHZtLm9uU2VhcmNoRXJyb3IocmVzcG9uc2VEYXRhKTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWxpemEgYSBwZXNxdWlzYSBjb20gYmFzZSBub3MgZmlsdHJvcyBkZWZpbmlkb3NcbiAgICAgKlxuICAgICAqL1xuICAgIGZ1bmN0aW9uIG5vcm1hbFNlYXJjaCgpIHtcbiAgICAgIHZtLmRlZmF1bHRRdWVyeUZpbHRlcnMgPSB7IH07XG5cbiAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYXBwbHlGaWx0ZXJzKSkgdm0uZGVmYXVsdFF1ZXJ5RmlsdGVycyA9IHZtLmFwcGx5RmlsdGVycyh2bS5kZWZhdWx0UXVlcnlGaWx0ZXJzKTtcbiAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYmVmb3JlU2VhcmNoKSAmJiB2bS5iZWZvcmVTZWFyY2goKSA9PT0gZmFsc2UpIHJldHVybiBmYWxzZTtcblxuICAgICAgbW9kZWxTZXJ2aWNlLnF1ZXJ5KHZtLmRlZmF1bHRRdWVyeUZpbHRlcnMpLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgIHZtLnJlc291cmNlcyA9IHJlc3BvbnNlO1xuXG4gICAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYWZ0ZXJTZWFyY2gpKSB2bS5hZnRlclNlYXJjaChyZXNwb25zZSk7XG4gICAgICB9LCBmdW5jdGlvbiAocmVzcG9uc2VEYXRhKSB7XG4gICAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0ub25TZWFyY2hFcnJvcikpIHZtLm9uU2VhcmNoRXJyb3IocmVzcG9uc2VEYXRhKTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIExpbXBhIG8gZm9ybXVsw6FyaW9cbiAgICAgKi9cbiAgICBmdW5jdGlvbiBjbGVhbkZvcm0oZm9ybSkge1xuICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5iZWZvcmVDbGVhbikgJiYgdm0uYmVmb3JlQ2xlYW4oKSA9PT0gZmFsc2UpIHJldHVybiBmYWxzZTtcblxuICAgICAgdm0ucmVzb3VyY2UgPSBuZXcgbW9kZWxTZXJ2aWNlKCk7XG5cbiAgICAgIGlmIChhbmd1bGFyLmlzRGVmaW5lZChmb3JtKSkge1xuICAgICAgICBmb3JtLiRzZXRQcmlzdGluZSgpO1xuICAgICAgICBmb3JtLiRzZXRVbnRvdWNoZWQoKTtcbiAgICAgIH1cblxuICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5hZnRlckNsZWFuKSkgdm0uYWZ0ZXJDbGVhbigpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENhcnJlZ2Egbm8gZm9ybXVsw6FyaW8gbyByZWN1cnNvIHNlbGVjaW9uYWRvIHBhcmEgZWRpw6fDo29cbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSByZXNvdXJjZSByZWN1cnNvIHNlbGVjaW9uYWRvXG4gICAgICovXG4gICAgZnVuY3Rpb24gZWRpdChyZXNvdXJjZSkge1xuICAgICAgdm0uZ29UbygnZm9ybScpO1xuICAgICAgdm0ucmVzb3VyY2UgPSBuZXcgYW5ndWxhci5jb3B5KHJlc291cmNlKTtcblxuICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5hZnRlckVkaXQpKSB2bS5hZnRlckVkaXQoKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBTYWx2YSBvdSBhdHVhbGl6YSBvIHJlY3Vyc28gY29ycmVudGUgbm8gZm9ybXVsw6FyaW9cbiAgICAgKiBObyBjb21wb3J0YW1lbnRvIHBhZHLDo28gcmVkaXJlY2lvbmEgbyB1c3XDoXJpbyBwYXJhIHZpZXcgZGUgbGlzdGFnZW1cbiAgICAgKiBkZXBvaXMgZGEgZXhlY3XDp8Ojb1xuICAgICAqXG4gICAgICogQHJldHVybnNcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBzYXZlKGZvcm0pIHtcbiAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYmVmb3JlU2F2ZSkgJiYgdm0uYmVmb3JlU2F2ZSgpID09PSBmYWxzZSkgcmV0dXJuIGZhbHNlO1xuXG4gICAgICB2bS5yZXNvdXJjZS4kc2F2ZSgpLnRoZW4oZnVuY3Rpb24gKHJlc291cmNlKSB7XG4gICAgICAgIHZtLnJlc291cmNlID0gcmVzb3VyY2U7XG5cbiAgICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5hZnRlclNhdmUpKSB2bS5hZnRlclNhdmUocmVzb3VyY2UpO1xuXG4gICAgICAgIGlmICh2bS5kZWZhdWx0T3B0aW9ucy5yZWRpcmVjdEFmdGVyU2F2ZSkge1xuICAgICAgICAgIHZtLmNsZWFuRm9ybShmb3JtKTtcbiAgICAgICAgICB2bS5zZWFyY2godm0ucGFnaW5hdG9yLmN1cnJlbnRQYWdlKTtcbiAgICAgICAgICB2bS5nb1RvKCdsaXN0Jyk7XG4gICAgICAgIH1cblxuICAgICAgICBQclRvYXN0LnN1Y2Nlc3MoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5zYXZlU3VjY2VzcycpKTtcblxuICAgICAgfSwgZnVuY3Rpb24gKHJlc3BvbnNlRGF0YSkge1xuICAgICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLm9uU2F2ZUVycm9yKSkgdm0ub25TYXZlRXJyb3IocmVzcG9uc2VEYXRhKTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlbW92ZSBvIHJlY3Vyc28gaW5mb3JtYWRvLlxuICAgICAqIEFudGVzIGV4aWJlIHVtIGRpYWxvZ28gZGUgY29uZmlybWHDp8Ojb1xuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IHJlc291cmNlIHJlY3Vyc28gZXNjb2xoaWRvXG4gICAgICovXG4gICAgZnVuY3Rpb24gcmVtb3ZlKHJlc291cmNlKSB7XG4gICAgICB2YXIgY29uZmlnID0ge1xuICAgICAgICB0aXRsZTogJHRyYW5zbGF0ZS5pbnN0YW50KCdkaWFsb2cuY29uZmlybVRpdGxlJyksXG4gICAgICAgIGRlc2NyaXB0aW9uOiAkdHJhbnNsYXRlLmluc3RhbnQoJ2RpYWxvZy5jb25maXJtRGVzY3JpcHRpb24nKVxuICAgICAgfVxuXG4gICAgICBQckRpYWxvZy5jb25maXJtKGNvbmZpZykudGhlbihmdW5jdGlvbigpIHtcbiAgICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5iZWZvcmVSZW1vdmUpICYmIHZtLmJlZm9yZVJlbW92ZShyZXNvdXJjZSkgPT09IGZhbHNlKSByZXR1cm4gZmFsc2U7XG5cbiAgICAgICAgcmVzb3VyY2UuJGRlc3Ryb3koKS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmFmdGVyUmVtb3ZlKSkgdm0uYWZ0ZXJSZW1vdmUocmVzb3VyY2UpO1xuXG4gICAgICAgICAgdm0uc2VhcmNoKCk7XG4gICAgICAgICAgUHJUb2FzdC5pbmZvKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMucmVtb3ZlU3VjY2VzcycpKTtcbiAgICAgICAgfSk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBBbHRlcm5hIGVudHJlIGEgdmlldyBkbyBmb3JtdWzDoXJpbyBlIGxpc3RhZ2VtXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gdmlld05hbWUgbm9tZSBkYSB2aWV3XG4gICAgICovXG4gICAgZnVuY3Rpb24gZ29Ubyh2aWV3TmFtZSkge1xuICAgICAgdm0udmlld0Zvcm0gPSBmYWxzZTtcbiAgICAgIHZtLm9uVmlldyA9IGZhbHNlO1xuICAgICAgaWYgKHZpZXdOYW1lID09PSAnZm9ybScpIHtcbiAgICAgICAgdm0uY2xlYW5Gb3JtKCk7XG4gICAgICAgIHZtLnZpZXdGb3JtID0gdHJ1ZTtcbiAgICAgIH1cbiAgICB9XG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZpbHRlcignZWxhcHNlZCcsIGZ1bmN0aW9uKCkge1xuICAgICAgcmV0dXJuIGZ1bmN0aW9uKGRhdGUpIHtcbiAgICAgICAgaWYgKCFkYXRlKSByZXR1cm47XG4gICAgICAgIHZhciB0aW1lID0gRGF0ZS5wYXJzZShkYXRlKSxcbiAgICAgICAgICB0aW1lTm93ID0gbmV3IERhdGUoKS5nZXRUaW1lKCksXG4gICAgICAgICAgZGlmZmVyZW5jZSA9IHRpbWVOb3cgLSB0aW1lLFxuICAgICAgICAgIHNlY29uZHMgPSBNYXRoLmZsb29yKGRpZmZlcmVuY2UgLyAxMDAwKSxcbiAgICAgICAgICBtaW51dGVzID0gTWF0aC5mbG9vcihzZWNvbmRzIC8gNjApLFxuICAgICAgICAgIGhvdXJzID0gTWF0aC5mbG9vcihtaW51dGVzIC8gNjApLFxuICAgICAgICAgIGRheXMgPSBNYXRoLmZsb29yKGhvdXJzIC8gMjQpLFxuICAgICAgICAgIG1vbnRocyA9IE1hdGguZmxvb3IoZGF5cyAvIDMwKTtcblxuICAgICAgICBpZiAobW9udGhzID4gMSkge1xuICAgICAgICAgIHJldHVybiBtb250aHMgKyAnIG1lc2VzIGF0csOhcyc7XG4gICAgICAgIH0gZWxzZSBpZiAobW9udGhzID09PSAxKSB7XG4gICAgICAgICAgcmV0dXJuICcxIG3DqnMgYXRyw6FzJztcbiAgICAgICAgfSBlbHNlIGlmIChkYXlzID4gMSkge1xuICAgICAgICAgIHJldHVybiBkYXlzICsgJyBkaWFzIGF0csOhcyc7XG4gICAgICAgIH0gZWxzZSBpZiAoZGF5cyA9PT0gMSkge1xuICAgICAgICAgIHJldHVybiAnMSBkaWEgYXRyw6FzJ1xuICAgICAgICB9IGVsc2UgaWYgKGhvdXJzID4gMSkge1xuICAgICAgICAgIHJldHVybiBob3VycyArICcgaG9yYXMgYXRyw6FzJztcbiAgICAgICAgfSBlbHNlIGlmIChob3VycyA9PT0gMSkge1xuICAgICAgICAgIHJldHVybiAndW1hIGhvcmEgYXRyw6FzJztcbiAgICAgICAgfSBlbHNlIGlmIChtaW51dGVzID4gMSkge1xuICAgICAgICAgIHJldHVybiBtaW51dGVzICsgJyBtaW51dG9zIGF0csOhcyc7XG4gICAgICAgIH0gZWxzZSBpZiAobWludXRlcyA9PT0gMSkge1xuICAgICAgICAgIHJldHVybiAndW0gbWludXRvIGF0csOhcyc7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgcmV0dXJuICdow6EgcG91Y29zIHNlZ3VuZG9zJztcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pXG4gICAgLmNvbnRyb2xsZXIoJ0Rhc2hib2FyZENvbnRyb2xsZXInLCBEYXNoYm9hcmRDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIERhc2hib2FyZENvbnRyb2xsZXIoJGNvbnRyb2xsZXIsXG4gICAgJHN0YXRlLFxuICAgICRtZERpYWxvZyxcbiAgICAkdHJhbnNsYXRlLFxuICAgIERhc2hib2FyZHNTZXJ2aWNlLFxuICAgIFByb2plY3RzU2VydmljZSxcbiAgICBtb21lbnQsXG4gICAgUHJUb2FzdCxcbiAgICBBdXRoLFxuICAgIEdsb2JhbCkge1xuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICAvL0F0dHJpYnV0ZXMgQmxvY2tcblxuICAgIC8vRnVuY3Rpb25zIEJsb2NrXG4gICAgdm0ub25BY3RpdmF0ZSA9IG9uQWN0aXZhdGU7XG4gICAgdm0uYXBwbHlGaWx0ZXJzID0gYXBwbHlGaWx0ZXJzO1xuICAgIHZtLmZpeERhdGUgPSBmaXhEYXRlO1xuXG4gICAgZnVuY3Rpb24gb25BY3RpdmF0ZSgpIHtcbiAgICAgIHZhciBwcm9qZWN0ID0gbG9jYWxTdG9yYWdlLmdldEl0ZW0oJ3Byb2plY3QnKTtcblxuICAgICAgdm0uaW1hZ2VQYXRoID0gR2xvYmFsLmltYWdlUGF0aCArICcvbm9fYXZhdGFyLmdpZic7XG4gICAgICB2bS5jdXJyZW50VXNlciA9IEF1dGguY3VycmVudFVzZXI7XG4gICAgICBQcm9qZWN0c1NlcnZpY2UucXVlcnkoeyBwcm9qZWN0X2lkOiBwcm9qZWN0IH0pLnRoZW4oZnVuY3Rpb24ocmVzcG9uc2UpIHtcbiAgICAgICAgdm0uYWN0dWFsUHJvamVjdCA9IHJlc3BvbnNlWzBdO1xuICAgICAgfSlcbiAgICAgIHZtLnF1ZXJ5RmlsdGVycyA9IHsgcHJvamVjdF9pZDogcHJvamVjdCB9O1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGFwcGx5RmlsdGVycyhkZWZhdWx0UXVlcnlGaWx0ZXJzKSB7XG4gICAgICByZXR1cm4gYW5ndWxhci5leHRlbmQoZGVmYXVsdFF1ZXJ5RmlsdGVycywgdm0ucXVlcnlGaWx0ZXJzKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBmaXhEYXRlKGRhdGVTdHJpbmcpIHtcbiAgICAgIHJldHVybiBtb21lbnQoZGF0ZVN0cmluZyk7XG4gICAgfVxuXG4gICAgdm0uZ29Ub1Byb2plY3QgPSBmdW5jdGlvbigpIHtcbiAgICAgICRzdGF0ZS5nbygnYXBwLnByb2plY3RzJywgeyBvYmo6ICdlZGl0JywgcmVzb3VyY2U6IHZtLmFjdHVhbFByb2plY3QgfSk7XG4gICAgfVxuXG4gICAgdm0udG90YWxDb3N0ID0gZnVuY3Rpb24oKSB7XG4gICAgICB2YXIgZXN0aW1hdGVkX2Nvc3QgPSAwO1xuXG4gICAgICBpZiAodm0uYWN0dWFsUHJvamVjdC5ob3VyX3ZhbHVlX2ZpbmFsKSB7XG4gICAgICAgIHZtLmFjdHVhbFByb2plY3QudGFza3MuZm9yRWFjaChmdW5jdGlvbih0YXNrKSB7XG4gICAgICAgICAgaWYgKHRhc2suZXN0aW1hdGVkX3RpbWUgPiAwKSB7XG4gICAgICAgICAgICBlc3RpbWF0ZWRfY29zdCArPSAocGFyc2VGbG9hdCh2bS5hY3R1YWxQcm9qZWN0LmhvdXJfdmFsdWVfZmluYWwpICogdGFzay5lc3RpbWF0ZWRfdGltZSk7XG4gICAgICAgICAgfVxuICAgICAgICB9KTtcbiAgICAgIH1cbiAgICAgIHJldHVybiBlc3RpbWF0ZWRfY29zdC50b0xvY2FsZVN0cmluZygnUHQtYnInLCB7IG1pbmltdW1GcmFjdGlvbkRpZ2l0czogMiB9KTtcbiAgICB9XG5cbiAgICB2bS5maW5hbGl6ZVByb2plY3QgPSBmdW5jdGlvbigpIHtcbiAgICAgIFByb2plY3RzU2VydmljZS52ZXJpZnlSZWxlYXNlcyh7IHByb2plY3RfaWQ6IHZtLmFjdHVhbFByb2plY3QuaWQgfSkudGhlbihmdW5jdGlvbihyZXNwb25zZSkge1xuICAgICAgICBpZiAocmVzcG9uc2Uuc3VjY2Vzcykge1xuICAgICAgICAgIHZhciBjb25maXJtID0gJG1kRGlhbG9nLmNvbmZpcm0oKVxuICAgICAgICAgIC50aXRsZSgnRmluYWxpemFyIFByb2pldG8nKVxuICAgICAgICAgIC5odG1sQ29udGVudCgnVGVtIGNlcnRlemEgcXVlIGRlc2VqYSBmaW5hbGl6YXIgbyBwcm9qZXRvICcgKyB2bS5hY3R1YWxQcm9qZWN0Lm5hbWUgKyAnPzxiciAvPiBBaW5kYSBleGlzdGVtIHJlbGVhc2VzIG7Do28gZmluYWxpemFkYXMuJylcbiAgICAgICAgICAub2soJ1NpbScpXG4gICAgICAgICAgLmNhbmNlbCgnTsOjbycpO1xuXG4gICAgICAgICAgJG1kRGlhbG9nLnNob3coY29uZmlybSkudGhlbihmdW5jdGlvbigpIHtcbiAgICAgICAgICAgIHZhciByZWFzb24gPSAkbWREaWFsb2cucHJvbXB0KClcbiAgICAgICAgICAgIC50aXRsZSgnRmluYWxpemFyIFByb2pldG8nKVxuICAgICAgICAgICAgLnRleHRDb250ZW50KCdRdWFsIG8gbW90aXZvIHBhcmEgYSBmaW5hbGl6YcOnw6NvIGRvIHByb2pldG8/JylcbiAgICAgICAgICAgIC5wbGFjZWhvbGRlcignTW90aXZvJylcbiAgICAgICAgICAgIC5pbml0aWFsVmFsdWUoJycpXG4gICAgICAgICAgICAucmVxdWlyZWQodHJ1ZSlcbiAgICAgICAgICAgIC5vaygnQ29uZmlybWFyJylcbiAgICAgICAgICAgIC5jYW5jZWwoJ0NhbmNlbGFyJyk7XG5cbiAgICAgICAgICAgICRtZERpYWxvZy5zaG93KHJlYXNvbikudGhlbihmdW5jdGlvbihyZWFzb25UZXh0KSB7XG4gICAgICAgICAgICAgIFByb2plY3RzU2VydmljZS5maW5hbGl6ZSh7IHByb2plY3RfaWQ6IHZtLmFjdHVhbFByb2plY3QuaWQsIHJlYXNvbjogcmVhc29uVGV4dCB9KS50aGVuKGZ1bmN0aW9uKCkge1xuICAgICAgICAgICAgICAgIFByVG9hc3Quc3VjY2VzcygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnByb2plY3RFbmRlZFN1Y2Nlc3MnKSk7XG4gICAgICAgICAgICAgICAgb25BY3RpdmF0ZSgpO1xuICAgICAgICAgICAgICAgIHZtLnNlYXJjaCgpO1xuICAgICAgICAgICAgICB9LCBmdW5jdGlvbigpIHtcbiAgICAgICAgICAgICAgICBQclRvYXN0LkVycm9yKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMucHJvamVjdEVuZGVkRXJyb3InKSk7XG4gICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgfSk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgdmFyIGNvbmZpcm0gPSAkbWREaWFsb2cuY29uZmlybSgpXG4gICAgICAgICAgLnRpdGxlKCdGaW5hbGl6YXIgUHJvamV0bycpXG4gICAgICAgICAgLnRleHRDb250ZW50KCdUZW0gY2VydGV6YSBxdWUgZGVzZWphIGZpbmFsaXphciBvIHByb2pldG8gJyArIHZtLmFjdHVhbFByb2plY3QubmFtZSArICc/JylcbiAgICAgICAgICAub2soJ1NpbScpXG4gICAgICAgICAgLmNhbmNlbCgnTsOjbycpO1xuXG4gICAgICAgICAgJG1kRGlhbG9nLnNob3coY29uZmlybSkudGhlbihmdW5jdGlvbigpIHtcbiAgICAgICAgICAgIFByb2plY3RzU2VydmljZS5maW5hbGl6ZSh7IHByb2plY3RfaWQ6IHZtLmFjdHVhbFByb2plY3QuaWQgfSkudGhlbihmdW5jdGlvbigpIHtcbiAgICAgICAgICAgICAgUHJUb2FzdC5zdWNjZXNzKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMucHJvamVjdEVuZGVkU3VjY2VzcycpKTtcbiAgICAgICAgICAgICAgb25BY3RpdmF0ZSgpO1xuICAgICAgICAgICAgICB2bS5zZWFyY2goKTtcbiAgICAgICAgICAgIH0sIGZ1bmN0aW9uKCkge1xuICAgICAgICAgICAgICBQclRvYXN0LkVycm9yKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMucHJvamVjdEVuZGVkRXJyb3InKSk7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgICB9KTtcbiAgICAgICAgfVxuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLy8gaW5zdGFudGlhdGUgYmFzZSBjb250cm9sbGVyXG4gICAgJGNvbnRyb2xsZXIoJ0NSVURDb250cm9sbGVyJywgeyB2bTogdm0sIG1vZGVsU2VydmljZTogRGFzaGJvYXJkc1NlcnZpY2UsIG9wdGlvbnM6IHt9IH0pO1xuICB9XG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqXG4gICAqIEFycXVpdm8gZGUgY29uZmlndXJhw6fDo28gY29tIGFzIHJvdGFzIGVzcGVjw61maWNhcyBkbyByZWN1cnNvIHByb2plY3RcbiAgICpcbiAgICogQHBhcmFtIHthbnl9ICRzdGF0ZVByb3ZpZGVyXG4gICAqIEBwYXJhbSB7YW55fSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlclxuICAgICAgLnN0YXRlKCdhcHAuZGFzaGJvYXJkJywge1xuICAgICAgICB1cmw6ICcvZGFzaGJvYXJkcycsXG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvZGFzaGJvYXJkL2Rhc2hib2FyZC5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ0Rhc2hib2FyZENvbnRyb2xsZXIgYXMgZGFzaGJvYXJkQ3RybCcsXG4gICAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiB0cnVlIH0sXG4gICAgICAgIG9iajogeyByZXNvdXJjZTogbnVsbCB9XG4gICAgICB9KTtcbiAgfVxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5mYWN0b3J5KCdEYXNoYm9hcmRzU2VydmljZScsIERhc2hib2FyZHNTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIERhc2hib2FyZHNTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCdkYXNoYm9hcmRzJywge1xuICAgICAgYWN0aW9uczogeyB9LFxuICAgICAgaW5zdGFuY2U6IHsgfVxuICAgIH0pO1xuICB9XG5cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqXG4gICAqIEFycXVpdm8gZGUgY29uZmlndXJhw6fDo28gY29tIGFzIHJvdGFzIGVzcGVjw61maWNhcyBkbyByZWN1cnNvIHVzZXJcbiAgICpcbiAgICogQHBhcmFtIHthbnl9ICRzdGF0ZVByb3ZpZGVyXG4gICAqIEBwYXJhbSB7YW55fSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlclxuICAgICAgLnN0YXRlKCdhcHAuZGluYW1pYy1xdWVyeScsIHtcbiAgICAgICAgdXJsOiAnL2NvbnN1bHRhcy1kaW5hbWljYXMnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL2RpbmFtaWMtcXVlcnlzL2RpbmFtaWMtcXVlcnlzLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnRGluYW1pY1F1ZXJ5c0NvbnRyb2xsZXIgYXMgZGluYW1pY1F1ZXJ5Q3RybCcsXG4gICAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiB0cnVlLCBuZWVkUHJvZmlsZTogWydhZG1pbiddIH1cbiAgICAgIH0pO1xuXG4gIH1cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmFjdG9yeSgnRGluYW1pY1F1ZXJ5U2VydmljZScsIERpbmFtaWNRdWVyeVNlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gRGluYW1pY1F1ZXJ5U2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHJldHVybiBzZXJ2aWNlRmFjdG9yeSgnZGluYW1pY1F1ZXJ5Jywge1xuICAgICAgLyoqXG4gICAgICAgKiBhw6fDo28gYWRpY2lvbmFkYSBwYXJhIHBlZ2FyIHVtYSBsaXN0YSBkZSBtb2RlbHMgZXhpc3RlbnRlcyBubyBzZXJ2aWRvclxuICAgICAgICovXG4gICAgICBhY3Rpb25zOiB7XG4gICAgICAgIGdldE1vZGVsczoge1xuICAgICAgICAgIG1ldGhvZDogJ0dFVCcsXG4gICAgICAgICAgdXJsOiAnbW9kZWxzJ1xuICAgICAgICB9XG4gICAgICB9LFxuICAgICAgaW5zdGFuY2U6IHtcbiAgICAgIH1cbiAgICB9KTtcbiAgfVxuXG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29udHJvbGxlcignRGluYW1pY1F1ZXJ5c0NvbnRyb2xsZXInLCBEaW5hbWljUXVlcnlzQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBEaW5hbWljUXVlcnlzQ29udHJvbGxlcigkY29udHJvbGxlciwgRGluYW1pY1F1ZXJ5U2VydmljZSwgbG9kYXNoLCBQclRvYXN0LCAvLyBOT1NPTkFSXG4gICAgJHRyYW5zbGF0ZSkge1xuXG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIC8vYWN0aW9uc1xuICAgIHZtLm9uQWN0aXZhdGUgPSBvbkFjdGl2YXRlO1xuICAgIHZtLmFwcGx5RmlsdGVycyA9IGFwcGx5RmlsdGVycztcbiAgICB2bS5sb2FkQXR0cmlidXRlcyA9IGxvYWRBdHRyaWJ1dGVzO1xuICAgIHZtLmxvYWRPcGVyYXRvcnMgPSBsb2FkT3BlcmF0b3JzO1xuICAgIHZtLmFkZEZpbHRlciA9IGFkZEZpbHRlcjtcbiAgICB2bS5hZnRlclNlYXJjaCA9IGFmdGVyU2VhcmNoO1xuICAgIHZtLnJ1bkZpbHRlciA9IHJ1bkZpbHRlcjtcbiAgICB2bS5lZGl0RmlsdGVyID0gZWRpdEZpbHRlcjtcbiAgICB2bS5sb2FkTW9kZWxzID0gbG9hZE1vZGVscztcbiAgICB2bS5yZW1vdmVGaWx0ZXIgPSByZW1vdmVGaWx0ZXI7XG4gICAgdm0uY2xlYXIgPSBjbGVhcjtcbiAgICB2bS5yZXN0YXJ0ID0gcmVzdGFydDtcblxuICAgIC8vaGVyZGEgbyBjb21wb3J0YW1lbnRvIGJhc2UgZG8gQ1JVRFxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHsgdm06IHZtLCBtb2RlbFNlcnZpY2U6IERpbmFtaWNRdWVyeVNlcnZpY2UsIG9wdGlvbnM6IHtcbiAgICAgIHNlYXJjaE9uSW5pdDogZmFsc2VcbiAgICB9IH0pO1xuXG4gICAgZnVuY3Rpb24gb25BY3RpdmF0ZSgpIHtcbiAgICAgIHZtLnJlc3RhcnQoKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBQcmVwYXJhIGUgYXBsaWNhIG9zIGZpbHRybyBxdWUgdsOjbyBzZXIgZW52aWFkb3MgcGFyYSBvIHNlcnZpw6dvXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gZGVmYXVsdFF1ZXJ5RmlsdGVyc1xuICAgICAqIEByZXR1cm5zXG4gICAgICovXG4gICAgZnVuY3Rpb24gYXBwbHlGaWx0ZXJzKGRlZmF1bHRRdWVyeUZpbHRlcnMpIHtcbiAgICAgIHZhciB3aGVyZSA9IHt9O1xuXG4gICAgICAvKipcbiAgICAgICAqIG8gc2VydmnDp28gZXNwZXJhIHVtIG9iamV0byBjb206XG4gICAgICAgKiAgbyBub21lIGRlIHVtIG1vZGVsXG4gICAgICAgKiAgdW1hIGxpc3RhIGRlIGZpbHRyb3NcbiAgICAgICAqL1xuICAgICAgaWYgKHZtLmFkZGVkRmlsdGVycy5sZW5ndGggPiAwKSB7XG4gICAgICAgIHZhciBhZGRlZEZpbHRlcnMgPSBhbmd1bGFyLmNvcHkodm0uYWRkZWRGaWx0ZXJzKTtcblxuICAgICAgICB3aGVyZS5tb2RlbCA9IHZtLmFkZGVkRmlsdGVyc1swXS5tb2RlbC5uYW1lO1xuXG4gICAgICAgIGZvciAodmFyIGluZGV4ID0gMDsgaW5kZXggPCBhZGRlZEZpbHRlcnMubGVuZ3RoOyBpbmRleCsrKSB7XG4gICAgICAgICAgdmFyIGZpbHRlciA9IGFkZGVkRmlsdGVyc1tpbmRleF07XG5cbiAgICAgICAgICBmaWx0ZXIubW9kZWwgPSBudWxsO1xuICAgICAgICAgIGZpbHRlci5hdHRyaWJ1dGUgPSBmaWx0ZXIuYXR0cmlidXRlLm5hbWU7XG4gICAgICAgICAgZmlsdGVyLm9wZXJhdG9yID0gZmlsdGVyLm9wZXJhdG9yLnZhbHVlO1xuICAgICAgICB9XG5cbiAgICAgICAgd2hlcmUuZmlsdGVycyA9IGFuZ3VsYXIudG9Kc29uKGFkZGVkRmlsdGVycyk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICB3aGVyZS5tb2RlbCA9IHZtLnF1ZXJ5RmlsdGVycy5tb2RlbC5uYW1lO1xuICAgICAgfVxuXG4gICAgICByZXR1cm4gYW5ndWxhci5leHRlbmQoZGVmYXVsdFF1ZXJ5RmlsdGVycywgd2hlcmUpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENhcnJlZ2EgdG9kb3Mgb3MgbW9kZWxzIGNyaWFkb3Mgbm8gc2Vydmlkb3IgY29tIHNldXMgYXRyaWJ1dG9zXG4gICAgICovXG4gICAgZnVuY3Rpb24gbG9hZE1vZGVscygpIHtcbiAgICAgIC8vUGVnYSB0b2RvcyBvcyBtb2RlbHMgZG8gc2VydmVyIGUgbW9udGEgdW1hIGxpc3RhIHBybyBDb21ib0JveFxuICAgICAgRGluYW1pY1F1ZXJ5U2VydmljZS5nZXRNb2RlbHMoKS50aGVuKGZ1bmN0aW9uKGRhdGEpIHtcbiAgICAgICAgdm0ubW9kZWxzID0gZGF0YTtcbiAgICAgICAgdm0ucXVlcnlGaWx0ZXJzLm1vZGVsID0gdm0ubW9kZWxzWzBdO1xuICAgICAgICB2bS5sb2FkQXR0cmlidXRlcygpO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ2FycmVnYSBvcyBhdHRyaWJ1dG9zIGRvIG1vZGVsIGVzY29saGlkb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGxvYWRBdHRyaWJ1dGVzKCkge1xuICAgICAgdm0uYXR0cmlidXRlcyA9IHZtLnF1ZXJ5RmlsdGVycy5tb2RlbC5hdHRyaWJ1dGVzO1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzLmF0dHJpYnV0ZSA9IHZtLmF0dHJpYnV0ZXNbMF07XG5cbiAgICAgIHZtLmxvYWRPcGVyYXRvcnMoKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDYXJyZWdhIG9zIG9wZXJhZG9yZXMgZXNwZWNpZmljb3MgcGFyYSBvIHRpcG8gZG8gYXRyaWJ1dG9cbiAgICAgKi9cbiAgICBmdW5jdGlvbiBsb2FkT3BlcmF0b3JzKCkge1xuICAgICAgdmFyIG9wZXJhdG9ycyA9IFtcbiAgICAgICAgeyB2YWx1ZTogJz0nLCBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KCd2aWV3cy5maWVsZHMucXVlcnlEaW5hbWljLm9wZXJhdG9ycy5lcXVhbHMnKSB9LFxuICAgICAgICB7IHZhbHVlOiAnPD4nLCBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KCd2aWV3cy5maWVsZHMucXVlcnlEaW5hbWljLm9wZXJhdG9ycy5kaWZlcmVudCcpIH1cbiAgICAgIF1cblxuICAgICAgaWYgKHZtLnF1ZXJ5RmlsdGVycy5hdHRyaWJ1dGUudHlwZS5pbmRleE9mKCd2YXJ5aW5nJykgIT09IC0xKSB7XG4gICAgICAgIG9wZXJhdG9ycy5wdXNoKHsgdmFsdWU6ICdoYXMnLFxuICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLmNvbnRlaW5zJykgfSk7XG4gICAgICAgIG9wZXJhdG9ycy5wdXNoKHsgdmFsdWU6ICdzdGFydFdpdGgnLFxuICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLnN0YXJ0V2l0aCcpIH0pO1xuICAgICAgICBvcGVyYXRvcnMucHVzaCh7IHZhbHVlOiAnZW5kV2l0aCcsXG4gICAgICAgICAgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudCgndmlld3MuZmllbGRzLnF1ZXJ5RGluYW1pYy5vcGVyYXRvcnMuZmluaXNoV2l0aCcpIH0pO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgb3BlcmF0b3JzLnB1c2goeyB2YWx1ZTogJz4nLFxuICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLmJpZ2dlclRoYW4nKSB9KTtcbiAgICAgICAgb3BlcmF0b3JzLnB1c2goeyB2YWx1ZTogJz49JyxcbiAgICAgICAgICBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KCd2aWV3cy5maWVsZHMucXVlcnlEaW5hbWljLm9wZXJhdG9ycy5lcXVhbHNPckJpZ2dlclRoYW4nKSB9KTtcbiAgICAgICAgb3BlcmF0b3JzLnB1c2goeyB2YWx1ZTogJzwnLFxuICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLmxlc3NUaGFuJykgfSk7XG4gICAgICAgIG9wZXJhdG9ycy5wdXNoKHsgdmFsdWU6ICc8PScsXG4gICAgICAgICAgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudCgndmlld3MuZmllbGRzLnF1ZXJ5RGluYW1pYy5vcGVyYXRvcnMuZXF1YWxzT3JMZXNzVGhhbicpIH0pO1xuICAgICAgfVxuXG4gICAgICB2bS5vcGVyYXRvcnMgPSBvcGVyYXRvcnM7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMub3BlcmF0b3IgPSB2bS5vcGVyYXRvcnNbMF07XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQWRpY2lvbmEvZWRpdGEgdW0gZmlsdHJvXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gZm9ybSBlbGVtZW50byBodG1sIGRvIGZvcm11bMOhcmlvIHBhcmEgdmFsaWRhw6fDtWVzXG4gICAgICovXG4gICAgZnVuY3Rpb24gYWRkRmlsdGVyKGZvcm0pIHtcbiAgICAgIGlmIChhbmd1bGFyLmlzVW5kZWZpbmVkKHZtLnF1ZXJ5RmlsdGVycy52YWx1ZSkgfHwgdm0ucXVlcnlGaWx0ZXJzLnZhbHVlID09PSAnJykge1xuICAgICAgICBQclRvYXN0LmVycm9yKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMudmFsaWRhdGUuZmllbGRSZXF1aXJlZCcsIHsgZmllbGQ6ICd2YWxvcicgfSkpO1xuICAgICAgICByZXR1cm47XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBpZiAodm0uaW5kZXggPCAwKSB7XG4gICAgICAgICAgdm0uYWRkZWRGaWx0ZXJzLnB1c2goYW5ndWxhci5jb3B5KHZtLnF1ZXJ5RmlsdGVycykpO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIHZtLmFkZGVkRmlsdGVyc1t2bS5pbmRleF0gPSBhbmd1bGFyLmNvcHkodm0ucXVlcnlGaWx0ZXJzKTtcbiAgICAgICAgICB2bS5pbmRleCA9IC0xO1xuICAgICAgICB9XG5cbiAgICAgICAgLy9yZWluaWNpYSBvIGZvcm11bMOhcmlvIGUgYXMgdmFsaWRhw6fDtWVzIGV4aXN0ZW50ZXNcbiAgICAgICAgdm0ucXVlcnlGaWx0ZXJzID0ge307XG4gICAgICAgIGZvcm0uJHNldFByaXN0aW5lKCk7XG4gICAgICAgIGZvcm0uJHNldFVudG91Y2hlZCgpO1xuICAgICAgfVxuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWxpemEgYSBwZXNxdWlzYSB0ZW5kbyBvcyBmaWx0cm9zIGNvbW8gcGFyw6JtZXRyb3NcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBydW5GaWx0ZXIoKSB7XG4gICAgICB2bS5zZWFyY2godm0ucGFnaW5hdG9yLmN1cnJlbnRQYWdlKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBHYXRpbGhvIGFjaW9uYWRvIGRlcG9pcyBkYSBwZXNxdWlzYSByZXNwb25zw6F2ZWwgcG9yIGlkZW50aWZpY2FyIG9zIGF0cmlidXRvc1xuICAgICAqIGNvbnRpZG9zIG5vcyBlbGVtZW50b3MgcmVzdWx0YW50ZXMgZGEgYnVzY2FcbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSBkYXRhIGRhZG9zIHJlZmVyZW50ZSBhbyByZXRvcm5vIGRhIHJlcXVpc2nDp8Ojb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGFmdGVyU2VhcmNoKGRhdGEpIHtcbiAgICAgIHZhciBrZXlzID0gKGRhdGEuaXRlbXMubGVuZ3RoID4gMCkgPyBPYmplY3Qua2V5cyhkYXRhLml0ZW1zWzBdKSA6IFtdO1xuXG4gICAgICAvL3JldGlyYSB0b2RvcyBvcyBhdHJpYnV0b3MgcXVlIGNvbWXDp2FtIGNvbSAkLlxuICAgICAgLy9Fc3NlcyBhdHJpYnV0b3Mgc8OjbyBhZGljaW9uYWRvcyBwZWxvIHNlcnZpw6dvIGUgbsOjbyBkZXZlIGFwYXJlY2VyIG5hIGxpc3RhZ2VtXG4gICAgICB2bS5rZXlzID0gbG9kYXNoLmZpbHRlcihrZXlzLCBmdW5jdGlvbihrZXkpIHtcbiAgICAgICAgcmV0dXJuICFsb2Rhc2guc3RhcnRzV2l0aChrZXksICckJyk7XG4gICAgICB9KVxuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENvbG9hY2Egbm8gZm9ybXVsw6FyaW8gbyBmaWx0cm8gZXNjb2xoaWRvIHBhcmEgZWRpw6fDo29cbiAgICAgKiBAcGFyYW0ge2FueX0gJGluZGV4IGluZGljZSBubyBhcnJheSBkbyBmaWx0cm8gZXNjb2xoaWRvXG4gICAgICovXG4gICAgZnVuY3Rpb24gZWRpdEZpbHRlcigkaW5kZXgpIHtcbiAgICAgIHZtLmluZGV4ID0gJGluZGV4O1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0gdm0uYWRkZWRGaWx0ZXJzWyRpbmRleF07XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVtb3ZlIG8gZmlsdHJvIGVzY29saGlkb1xuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9ICRpbmRleCBpbmRpY2Ugbm8gYXJyYXkgZG8gZmlsdHJvIGVzY29saGlkb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIHJlbW92ZUZpbHRlcigkaW5kZXgpIHtcbiAgICAgIHZtLmFkZGVkRmlsdGVycy5zcGxpY2UoJGluZGV4KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBMaW1wYSBvIGZvcm11bMOhcmlvIGNvcnJlbnRlXG4gICAgICovXG4gICAgZnVuY3Rpb24gY2xlYXIoKSB7XG4gICAgICAvL2d1YXJkYSBvIGluZGljZSBkbyByZWdpc3RybyBxdWUgZXN0w6Egc2VuZG8gZWRpdGFkb1xuICAgICAgdm0uaW5kZXggPSAtMTtcbiAgICAgIC8vdmluY3VsYWRvIGFvcyBjYW1wb3MgZG8gZm9ybXVsw6FyaW9cbiAgICAgIHZtLnF1ZXJ5RmlsdGVycyA9IHtcbiAgICAgIH07XG5cbiAgICAgIGlmICh2bS5tb2RlbHMpIHZtLnF1ZXJ5RmlsdGVycy5tb2RlbCA9IHZtLm1vZGVsc1swXTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWluaWNpYSBhIGNvbnN0cnXDp8OjbyBkYSBxdWVyeSBsaW1wYW5kbyB0dWRvXG4gICAgICpcbiAgICAgKi9cbiAgICBmdW5jdGlvbiByZXN0YXJ0KCkge1xuICAgICAgLy9ndWFyZGEgYXRyaWJ1dG9zIGRvIHJlc3VsdGFkbyBkYSBidXNjYSBjb3JyZW50ZVxuICAgICAgdm0ua2V5cyA9IFtdO1xuXG4gICAgICAvL2d1YXJkYSBvcyBmaWx0cm9zIGFkaWNpb25hZG9zXG4gICAgICB2bS5hZGRlZEZpbHRlcnMgPSBbXTtcbiAgICAgIHZtLmNsZWFyKCk7XG4gICAgICB2bS5sb2FkTW9kZWxzKCk7XG4gICAgfVxuXG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZhY3RvcnkoJ2xhbmd1YWdlTG9hZGVyJywgTGFuZ3VhZ2VMb2FkZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gTGFuZ3VhZ2VMb2FkZXIoJHEsIFN1cHBvcnRTZXJ2aWNlLCAkbG9nLCAkaW5qZWN0b3IpIHtcbiAgICB2YXIgc2VydmljZSA9IHRoaXM7XG5cbiAgICBzZXJ2aWNlLnRyYW5zbGF0ZSA9IGZ1bmN0aW9uKGxvY2FsZSkge1xuICAgICAgcmV0dXJuIHtcbiAgICAgICAgZ2xvYmFsOiAkaW5qZWN0b3IuZ2V0KGxvY2FsZSArICcuaTE4bi5nbG9iYWwnKSxcbiAgICAgICAgdmlld3M6ICRpbmplY3Rvci5nZXQobG9jYWxlICsgJy5pMThuLnZpZXdzJyksXG4gICAgICAgIGF0dHJpYnV0ZXM6ICRpbmplY3Rvci5nZXQobG9jYWxlICsgJy5pMThuLmF0dHJpYnV0ZXMnKSxcbiAgICAgICAgZGlhbG9nOiAkaW5qZWN0b3IuZ2V0KGxvY2FsZSArICcuaTE4bi5kaWFsb2cnKSxcbiAgICAgICAgbWVzc2FnZXM6ICRpbmplY3Rvci5nZXQobG9jYWxlICsgJy5pMThuLm1lc3NhZ2VzJyksXG4gICAgICAgIG1vZGVsczogJGluamVjdG9yLmdldChsb2NhbGUgKyAnLmkxOG4ubW9kZWxzJylcbiAgICAgIH07XG4gICAgfVxuXG4gICAgLy8gcmV0dXJuIGxvYWRlckZuXG4gICAgcmV0dXJuIGZ1bmN0aW9uKG9wdGlvbnMpIHtcbiAgICAgICRsb2cuaW5mbygnQ2FycmVnYW5kbyBvIGNvbnRldWRvIGRhIGxpbmd1YWdlbSAnICsgb3B0aW9ucy5rZXkpO1xuXG4gICAgICB2YXIgZGVmZXJyZWQgPSAkcS5kZWZlcigpO1xuXG4gICAgICAvL0NhcnJlZ2EgYXMgbGFuZ3MgcXVlIHByZWNpc2FtIGUgZXN0w6NvIG5vIHNlcnZpZG9yIHBhcmEgbsOjbyBwcmVjaXNhciByZXBldGlyIGFxdWlcbiAgICAgIFN1cHBvcnRTZXJ2aWNlLmxhbmdzKCkudGhlbihmdW5jdGlvbihsYW5ncykge1xuICAgICAgICAvL01lcmdlIGNvbSBvcyBsYW5ncyBkZWZpbmlkb3Mgbm8gc2Vydmlkb3JcbiAgICAgICAgdmFyIGRhdGEgPSBhbmd1bGFyLm1lcmdlKHNlcnZpY2UudHJhbnNsYXRlKG9wdGlvbnMua2V5KSwgbGFuZ3MpO1xuXG4gICAgICAgIHJldHVybiBkZWZlcnJlZC5yZXNvbHZlKGRhdGEpO1xuICAgICAgfSwgZnVuY3Rpb24oKSB7XG4gICAgICAgIHJldHVybiBkZWZlcnJlZC5yZXNvbHZlKHNlcnZpY2UudHJhbnNsYXRlKG9wdGlvbnMua2V5KSk7XG4gICAgICB9KTtcblxuICAgICAgcmV0dXJuIGRlZmVycmVkLnByb21pc2U7XG4gICAgfVxuICB9XG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5maWx0ZXIoJ3RBdHRyJywgdEF0dHIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gdEF0dHIoJGZpbHRlcikge1xuICAgIC8qKlxuICAgICAqIEZpbHRybyBwYXJhIHRyYWR1w6fDo28gZGUgdW0gYXRyaWJ1dG8gZGUgdW0gbW9kZWxcbiAgICAgKiBcbiAgICAgKiBAcGFyYW0ge2FueX0gbmFtZSBub21lIGRvIGF0cmlidXRvXG4gICAgICogQHJldHVybnMgbyBub21lIGRvIGF0cmlidXRvIHRyYWR1emlkbyBjYXNvIGVuY29udHJlIHNlIG7Do28gbyBub21lIHBhc3NhZG8gcG9yIHBhcmFtZXRyb1xuICAgICAqLyAgICBcbiAgICByZXR1cm4gZnVuY3Rpb24obmFtZSkge1xuICAgICAgdmFyIGtleSA9ICdhdHRyaWJ1dGVzLicgKyBuYW1lO1xuICAgICAgdmFyIHRyYW5zbGF0ZSA9ICRmaWx0ZXIoJ3RyYW5zbGF0ZScpKGtleSk7XG5cbiAgICAgIHJldHVybiAodHJhbnNsYXRlID09PSBrZXkpID8gbmFtZSA6IHRyYW5zbGF0ZTtcbiAgICB9XG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZpbHRlcigndEJyZWFkY3J1bWInLCB0QnJlYWRjcnVtYik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiB0QnJlYWRjcnVtYigkZmlsdGVyKSB7XG4gICAgLyoqXG4gICAgICogRmlsdHJvIHBhcmEgdHJhZHXDp8OjbyBkbyBicmVhZGNydW1iICh0aXR1bG8gZGEgdGVsYSBjb20gcmFzdHJlaW8pXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gaWQgY2hhdmUgY29tIG8gbm9tZSBkbyBzdGF0ZSByZWZlcmVudGUgdGVsYVxuICAgICAqIEByZXR1cm5zIGEgdHJhZHXDp8OjbyBjYXNvIGVuY29udHJlIHNlIG7Do28gbyBpZCBwYXNzYWRvIHBvciBwYXJhbWV0cm9cbiAgICAgKi9cbiAgICByZXR1cm4gZnVuY3Rpb24oaWQpIHtcbiAgICAgIC8vcGVnYSBhIHNlZ3VuZGEgcGFydGUgZG8gbm9tZSBkbyBzdGF0ZSwgcmV0aXJhbmRvIGEgcGFydGUgYWJzdHJhdGEgKGFwcC4pXG4gICAgICB2YXIga2V5ID0gJ3ZpZXdzLmJyZWFkY3J1bWJzLicgKyBpZC5zcGxpdCgnLicpWzFdO1xuICAgICAgdmFyIHRyYW5zbGF0ZSA9ICRmaWx0ZXIoJ3RyYW5zbGF0ZScpKGtleSk7XG5cbiAgICAgIHJldHVybiAodHJhbnNsYXRlID09PSBrZXkpID8gaWQgOiB0cmFuc2xhdGU7XG4gICAgfVxuICB9XG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5maWx0ZXIoJ3RNb2RlbCcsIHRNb2RlbCk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiB0TW9kZWwoJGZpbHRlcikge1xuICAgIC8qKlxuICAgICAqIEZpbHRybyBwYXJhIHRyYWR1w6fDo28gZGUgdW0gYXRyaWJ1dG8gZGUgdW0gbW9kZWxcbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSBuYW1lIG5vbWUgZG8gYXRyaWJ1dG9cbiAgICAgKiBAcmV0dXJucyBvIG5vbWUgZG8gYXRyaWJ1dG8gdHJhZHV6aWRvIGNhc28gZW5jb250cmUgc2UgbsOjbyBvIG5vbWUgcGFzc2FkbyBwb3IgcGFyYW1ldHJvXG4gICAgICovXG4gICAgcmV0dXJuIGZ1bmN0aW9uKG5hbWUpIHtcbiAgICAgIHZhciBrZXkgPSAnbW9kZWxzLicgKyBuYW1lLnRvTG93ZXJDYXNlKCk7XG4gICAgICB2YXIgdHJhbnNsYXRlID0gJGZpbHRlcigndHJhbnNsYXRlJykoa2V5KTtcblxuICAgICAgcmV0dXJuICh0cmFuc2xhdGUgPT09IGtleSkgPyBuYW1lIDogdHJhbnNsYXRlO1xuICAgIH1cbiAgfVxuXG59KSgpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLnJ1bihhdXRoZW50aWNhdGlvbkxpc3RlbmVyKTtcblxuICAvKipcbiAgICogTGlzdGVuIGFsbCBzdGF0ZSAocGFnZSkgY2hhbmdlcy4gRXZlcnkgdGltZSBhIHN0YXRlIGNoYW5nZSBuZWVkIHRvIHZlcmlmeSB0aGUgdXNlciBpcyBhdXRoZW50aWNhdGVkIG9yIG5vdCB0b1xuICAgKiByZWRpcmVjdCB0byBjb3JyZWN0IHBhZ2UuIFdoZW4gYSB1c2VyIGNsb3NlIHRoZSBicm93c2VyIHdpdGhvdXQgbG9nb3V0LCB3aGVuIGhpbSByZW9wZW4gdGhlIGJyb3dzZXIgdGhpcyBldmVudFxuICAgKiByZWF1dGhlbnRpY2F0ZSB0aGUgdXNlciB3aXRoIHRoZSBwZXJzaXN0ZW50IHRva2VuIG9mIHRoZSBsb2NhbCBzdG9yYWdlLlxuICAgKlxuICAgKiBXZSBkb24ndCBjaGVjayBpZiB0aGUgdG9rZW4gaXMgZXhwaXJlZCBvciBub3QgaW4gdGhlIHBhZ2UgY2hhbmdlLCBiZWNhdXNlIGlzIGdlbmVyYXRlIGFuIHVuZWNlc3Nhcnkgb3ZlcmhlYWQuXG4gICAqIElmIHRoZSB0b2tlbiBpcyBleHBpcmVkIHdoZW4gdGhlIHVzZXIgdHJ5IHRvIGNhbGwgdGhlIGZpcnN0IGFwaSB0byBnZXQgZGF0YSwgaGltIHdpbGwgYmUgbG9nb2ZmIGFuZCByZWRpcmVjdFxuICAgKiB0byBsb2dpbiBwYWdlLlxuICAgKlxuICAgKiBAcGFyYW0gJHJvb3RTY29wZVxuICAgKiBAcGFyYW0gJHN0YXRlXG4gICAqIEBwYXJhbSAkc3RhdGVQYXJhbXNcbiAgICogQHBhcmFtIEF1dGhcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gYXV0aGVudGljYXRpb25MaXN0ZW5lcigkcm9vdFNjb3BlLCAkc3RhdGUsIEdsb2JhbCwgQXV0aCwgUHJUb2FzdCwgLy8gTk9TT05BUlxuICAgICR0cmFuc2xhdGUpIHtcblxuICAgIC8vb25seSB3aGVuIGFwcGxpY2F0aW9uIHN0YXJ0IGNoZWNrIGlmIHRoZSBleGlzdGVudCB0b2tlbiBzdGlsbCB2YWxpZFxuICAgIEF1dGgucmVtb3RlVmFsaWRhdGVUb2tlbigpLnRoZW4oZnVuY3Rpb24oKSB7XG4gICAgICAvL2lmIHRoZSB0b2tlbiBpcyB2YWxpZCBjaGVjayBpZiBleGlzdHMgdGhlIHVzZXIgYmVjYXVzZSB0aGUgYnJvd3NlciBjb3VsZCBiZSBjbG9zZWRcbiAgICAgIC8vYW5kIHRoZSB1c2VyIGRhdGEgaXNuJ3QgaW4gbWVtb3J5XG4gICAgICBpZiAoQXV0aC5jdXJyZW50VXNlciA9PT0gbnVsbCkge1xuICAgICAgICBBdXRoLnVwZGF0ZUN1cnJlbnRVc2VyKGFuZ3VsYXIuZnJvbUpzb24obG9jYWxTdG9yYWdlLmdldEl0ZW0oJ3VzZXInKSkpO1xuICAgICAgfVxuICAgIH0pO1xuXG4gICAgLy9DaGVjayBpZiB0aGUgdG9rZW4gc3RpbGwgdmFsaWQuXG4gICAgJHJvb3RTY29wZS4kb24oJyRzdGF0ZUNoYW5nZVN0YXJ0JywgZnVuY3Rpb24oZXZlbnQsIHRvU3RhdGUpIHtcbiAgICAgIGlmICh0b1N0YXRlLmRhdGEubmVlZEF1dGhlbnRpY2F0aW9uIHx8IHRvU3RhdGUuZGF0YS5uZWVkUHJvZmlsZSkge1xuICAgICAgICAvL2RvbnQgdHJhaXQgdGhlIHN1Y2Nlc3MgYmxvY2sgYmVjYXVzZSBhbHJlYWR5IGRpZCBieSB0b2tlbiBpbnRlcmNlcHRvclxuICAgICAgICBBdXRoLnJlbW90ZVZhbGlkYXRlVG9rZW4oKS5jYXRjaChmdW5jdGlvbigpIHtcbiAgICAgICAgICBQclRvYXN0Lndhcm4oJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5sb2dpbi5sb2dvdXRJbmFjdGl2ZScpKTtcblxuICAgICAgICAgIGlmICh0b1N0YXRlLm5hbWUgIT09IEdsb2JhbC5sb2dpblN0YXRlKSB7XG4gICAgICAgICAgICAkc3RhdGUuZ28oR2xvYmFsLmxvZ2luU3RhdGUpO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIGV2ZW50LnByZXZlbnREZWZhdWx0KCk7XG4gICAgICAgIH0pO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgLy9pZiB0aGUgdXNlIGlzIGF1dGhlbnRpY2F0ZWQgYW5kIG5lZWQgdG8gZW50ZXIgaW4gbG9naW4gcGFnZVxuICAgICAgICAvL2hpbSB3aWxsIGJlIHJlZGlyZWN0ZWQgdG8gaG9tZSBwYWdlXG4gICAgICAgIGlmICh0b1N0YXRlLm5hbWUgPT09IEdsb2JhbC5sb2dpblN0YXRlICYmIEF1dGguYXV0aGVudGljYXRlZCgpKSB7XG4gICAgICAgICAgJHN0YXRlLmdvKEdsb2JhbC5ob21lU3RhdGUpO1xuICAgICAgICAgIGV2ZW50LnByZXZlbnREZWZhdWx0KCk7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9KTtcbiAgfVxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5ydW4oYXV0aG9yaXphdGlvbkxpc3RlbmVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIGF1dGhvcml6YXRpb25MaXN0ZW5lcigkcm9vdFNjb3BlLCAkc3RhdGUsIEdsb2JhbCwgQXV0aCkge1xuICAgIC8qKlxuICAgICAqIEEgY2FkYSBtdWRhbsOnYSBkZSBlc3RhZG8gKFwicMOhZ2luYVwiKSB2ZXJpZmljYSBzZSBvIHVzdcOhcmlvIHRlbSBvIHBlcmZpbFxuICAgICAqIG5lY2Vzc8OhcmlvIHBhcmEgbyBhY2Vzc28gYSBtZXNtYVxuICAgICAqL1xuICAgICRyb290U2NvcGUuJG9uKCckc3RhdGVDaGFuZ2VTdGFydCcsIGZ1bmN0aW9uKGV2ZW50LCB0b1N0YXRlKSB7XG4gICAgICBpZiAodG9TdGF0ZS5kYXRhICYmIHRvU3RhdGUuZGF0YS5uZWVkQXV0aGVudGljYXRpb24gJiZcbiAgICAgICAgdG9TdGF0ZS5kYXRhLm5lZWRQcm9maWxlICYmIEF1dGguYXV0aGVudGljYXRlZCgpICYmXG4gICAgICAgICFBdXRoLmN1cnJlbnRVc2VyLmhhc1Byb2ZpbGUodG9TdGF0ZS5kYXRhLm5lZWRQcm9maWxlLCB0b1N0YXRlLmRhdGEuYWxsUHJvZmlsZXMpKSB7XG5cbiAgICAgICAgJHN0YXRlLmdvKEdsb2JhbC5ub3RBdXRob3JpemVkU3RhdGUpO1xuICAgICAgICBldmVudC5wcmV2ZW50RGVmYXVsdCgpO1xuICAgICAgfVxuXG4gICAgfSk7XG4gIH1cbn0oKSk7XG4iLCIoZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbmZpZyhzcGlubmVySW50ZXJjZXB0b3IpO1xuXG4gIGZ1bmN0aW9uIHNwaW5uZXJJbnRlcmNlcHRvcigkaHR0cFByb3ZpZGVyLCAkcHJvdmlkZSkge1xuICAgIC8qKlxuICAgICAqIEVzdGUgaW50ZXJjZXB0b3Igw6kgcmVzcG9uc8OhdmVsIHBvciBtb3N0cmFyIGUgZXNjb25kZXIgb1xuICAgICAqIGNvbXBvbmVudGUgUHJTcGlubmVyIHNlbXByZSBxdWUgdW1hIHJlcXVpc2nDp8OjbyBhamF4XG4gICAgICogaW5pY2lhciBlIGZpbmFsaXphci5cbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSAkcVxuICAgICAqIEBwYXJhbSB7YW55fSAkaW5qZWN0b3JcbiAgICAgKiBAcmV0dXJuc1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIHNob3dIaWRlU3Bpbm5lcigkcSwgJGluamVjdG9yKSB7XG4gICAgICByZXR1cm4ge1xuICAgICAgICByZXF1ZXN0OiBmdW5jdGlvbiAoY29uZmlnKSB7XG4gICAgICAgICAgJGluamVjdG9yLmdldCgnUHJTcGlubmVyJykuc2hvdygpO1xuXG4gICAgICAgICAgcmV0dXJuIGNvbmZpZztcbiAgICAgICAgfSxcblxuICAgICAgICByZXNwb25zZTogZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgICAgJGluamVjdG9yLmdldCgnUHJTcGlubmVyJykuaGlkZSgpO1xuXG4gICAgICAgICAgcmV0dXJuIHJlc3BvbnNlO1xuICAgICAgICB9LFxuXG4gICAgICAgIHJlc3BvbnNlRXJyb3I6IGZ1bmN0aW9uIChyZWplY3Rpb24pIHtcbiAgICAgICAgICAkaW5qZWN0b3IuZ2V0KCdQclNwaW5uZXInKS5oaWRlKCk7XG5cbiAgICAgICAgICByZXR1cm4gJHEucmVqZWN0KHJlamVjdGlvbik7XG4gICAgICAgIH1cbiAgICAgIH07XG4gICAgfVxuXG4gICAgLy8gRGVmaW5lIHVtYSBmYWN0b3J5IHBhcmEgbyAkaHR0cEludGVyY2VwdG9yXG4gICAgJHByb3ZpZGUuZmFjdG9yeSgnc2hvd0hpZGVTcGlubmVyJywgc2hvd0hpZGVTcGlubmVyKTtcblxuICAgIC8vIEFkaWNpb25hIGEgZmFjdG9yeSBubyBhcnJheSBkZSBpbnRlcmNlcHRvcnMgZG8gJGh0dHBcbiAgICAkaHR0cFByb3ZpZGVyLmludGVyY2VwdG9ycy5wdXNoKCdzaG93SGlkZVNwaW5uZXInKTtcbiAgfVxufSgpKTtcbiIsIi8qZXNsaW50IGFuZ3VsYXIvbW9kdWxlLWdldHRlcjogMCovXG5cbihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb25maWcodG9rZW5JbnRlcmNlcHRvcik7XG5cbiAgLyoqXG4gICAqIEludGVyY2VwdCBhbGwgcmVzcG9uc2UgKHN1Y2Nlc3Mgb3IgZXJyb3IpIHRvIHZlcmlmeSB0aGUgcmV0dXJuZWQgdG9rZW5cbiAgICpcbiAgICogQHBhcmFtICRodHRwUHJvdmlkZXJcbiAgICogQHBhcmFtICRwcm92aWRlXG4gICAqIEBwYXJhbSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gdG9rZW5JbnRlcmNlcHRvcigkaHR0cFByb3ZpZGVyLCAkcHJvdmlkZSwgR2xvYmFsKSB7XG5cbiAgICBmdW5jdGlvbiByZWRpcmVjdFdoZW5TZXJ2ZXJMb2dnZWRPdXQoJHEsICRpbmplY3Rvcikge1xuICAgICAgcmV0dXJuIHtcbiAgICAgICAgcmVxdWVzdDogZnVuY3Rpb24oY29uZmlnKSB7XG4gICAgICAgICAgdmFyIHRva2VuID0gJGluamVjdG9yLmdldCgnQXV0aCcpLmdldFRva2VuKCk7XG5cbiAgICAgICAgICBpZiAodG9rZW4pIHtcbiAgICAgICAgICAgIGNvbmZpZy5oZWFkZXJzWydBdXRob3JpemF0aW9uJ10gPSAnQmVhcmVyICcgKyB0b2tlbjtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICByZXR1cm4gY29uZmlnO1xuICAgICAgICB9LFxuICAgICAgICByZXNwb25zZTogZnVuY3Rpb24ocmVzcG9uc2UpIHtcbiAgICAgICAgICAvLyBnZXQgYSBuZXcgcmVmcmVzaCB0b2tlbiB0byB1c2UgaW4gdGhlIG5leHQgcmVxdWVzdFxuICAgICAgICAgIHZhciB0b2tlbiA9IHJlc3BvbnNlLmhlYWRlcnMoJ0F1dGhvcml6YXRpb24nKTtcblxuICAgICAgICAgIGlmICh0b2tlbikge1xuICAgICAgICAgICAgJGluamVjdG9yLmdldCgnQXV0aCcpLnNldFRva2VuKHRva2VuLnNwbGl0KCcgJylbMV0pO1xuICAgICAgICAgIH1cbiAgICAgICAgICByZXR1cm4gcmVzcG9uc2U7XG4gICAgICAgIH0sXG4gICAgICAgIHJlc3BvbnNlRXJyb3I6IGZ1bmN0aW9uKHJlamVjdGlvbikge1xuICAgICAgICAgIC8vIEluc3RlYWQgb2YgY2hlY2tpbmcgZm9yIGEgc3RhdHVzIGNvZGUgb2YgNDAwIHdoaWNoIG1pZ2h0IGJlIHVzZWRcbiAgICAgICAgICAvLyBmb3Igb3RoZXIgcmVhc29ucyBpbiBMYXJhdmVsLCB3ZSBjaGVjayBmb3IgdGhlIHNwZWNpZmljIHJlamVjdGlvblxuICAgICAgICAgIC8vIHJlYXNvbnMgdG8gdGVsbCB1cyBpZiB3ZSBuZWVkIHRvIHJlZGlyZWN0IHRvIHRoZSBsb2dpbiBzdGF0ZVxuICAgICAgICAgIHZhciByZWplY3Rpb25SZWFzb25zID0gWyd0b2tlbl9ub3RfcHJvdmlkZWQnLCAndG9rZW5fZXhwaXJlZCcsICd0b2tlbl9hYnNlbnQnLCAndG9rZW5faW52YWxpZCddO1xuXG4gICAgICAgICAgdmFyIHRva2VuRXJyb3IgPSBmYWxzZTtcblxuICAgICAgICAgIGFuZ3VsYXIuZm9yRWFjaChyZWplY3Rpb25SZWFzb25zLCBmdW5jdGlvbih2YWx1ZSkge1xuICAgICAgICAgICAgaWYgKHJlamVjdGlvbi5kYXRhICYmIHJlamVjdGlvbi5kYXRhLmVycm9yID09PSB2YWx1ZSkge1xuICAgICAgICAgICAgICB0b2tlbkVycm9yID0gdHJ1ZTtcblxuICAgICAgICAgICAgICAkaW5qZWN0b3IuZ2V0KCdBdXRoJykubG9nb3V0KCkudGhlbihmdW5jdGlvbigpIHtcbiAgICAgICAgICAgICAgICB2YXIgJHN0YXRlID0gJGluamVjdG9yLmdldCgnJHN0YXRlJyk7XG5cbiAgICAgICAgICAgICAgICAvLyBpbiBjYXNlIG11bHRpcGxlIGFqYXggcmVxdWVzdCBmYWlsIGF0IHNhbWUgdGltZSBiZWNhdXNlIHRva2VuIHByb2JsZW1zLFxuICAgICAgICAgICAgICAgIC8vIG9ubHkgdGhlIGZpcnN0IHdpbGwgcmVkaXJlY3RcbiAgICAgICAgICAgICAgICBpZiAoISRzdGF0ZS5pcyhHbG9iYWwubG9naW5TdGF0ZSkpIHtcbiAgICAgICAgICAgICAgICAgICRzdGF0ZS5nbyhHbG9iYWwubG9naW5TdGF0ZSk7XG5cbiAgICAgICAgICAgICAgICAgIC8vY2xvc2UgYW55IGRpYWxvZyB0aGF0IGlzIG9wZW5lZFxuICAgICAgICAgICAgICAgICAgJGluamVjdG9yLmdldCgnUHJEaWFsb2cnKS5jbG9zZSgpO1xuXG4gICAgICAgICAgICAgICAgICBldmVudC5wcmV2ZW50RGVmYXVsdCgpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfSk7XG5cbiAgICAgICAgICAvL2RlZmluZSBkYXRhIHRvIGVtcHR5IGJlY2F1c2UgYWxyZWFkeSBzaG93IFByVG9hc3QgdG9rZW4gbWVzc2FnZVxuICAgICAgICAgIGlmICh0b2tlbkVycm9yKSB7XG4gICAgICAgICAgICByZWplY3Rpb24uZGF0YSA9IHt9O1xuICAgICAgICAgIH1cblxuICAgICAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24ocmVqZWN0aW9uLmhlYWRlcnMpKSB7XG4gICAgICAgICAgICAvLyBtYW55IHNlcnZlcnMgZXJyb3JzIChidXNpbmVzcykgYXJlIGludGVyY2VwdCBoZXJlIGJ1dCBnZW5lcmF0ZWQgYSBuZXcgcmVmcmVzaCB0b2tlblxuICAgICAgICAgICAgLy8gYW5kIG5lZWQgdXBkYXRlIGN1cnJlbnQgdG9rZW5cbiAgICAgICAgICAgIHZhciB0b2tlbiA9IHJlamVjdGlvbi5oZWFkZXJzKCdBdXRob3JpemF0aW9uJyk7XG5cbiAgICAgICAgICAgIGlmICh0b2tlbikge1xuICAgICAgICAgICAgICAkaW5qZWN0b3IuZ2V0KCdBdXRoJykuc2V0VG9rZW4odG9rZW4uc3BsaXQoJyAnKVsxXSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgcmV0dXJuICRxLnJlamVjdChyZWplY3Rpb24pO1xuICAgICAgICB9XG4gICAgICB9O1xuICAgIH1cblxuICAgIC8vIFNldHVwIGZvciB0aGUgJGh0dHBJbnRlcmNlcHRvclxuICAgICRwcm92aWRlLmZhY3RvcnkoJ3JlZGlyZWN0V2hlblNlcnZlckxvZ2dlZE91dCcsIHJlZGlyZWN0V2hlblNlcnZlckxvZ2dlZE91dCk7XG5cbiAgICAvLyBQdXNoIHRoZSBuZXcgZmFjdG9yeSBvbnRvIHRoZSAkaHR0cCBpbnRlcmNlcHRvciBhcnJheVxuICAgICRodHRwUHJvdmlkZXIuaW50ZXJjZXB0b3JzLnB1c2goJ3JlZGlyZWN0V2hlblNlcnZlckxvZ2dlZE91dCcpO1xuICB9XG5cbn0oKSk7XG4iLCIoZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbmZpZyh2YWxpZGF0aW9uSW50ZXJjZXB0b3IpO1xuXG4gIGZ1bmN0aW9uIHZhbGlkYXRpb25JbnRlcmNlcHRvcigkaHR0cFByb3ZpZGVyLCAkcHJvdmlkZSkge1xuICAgIC8qKlxuICAgICAqIEVzdGUgaW50ZXJjZXB0b3Igw6kgcmVzcG9uc8OhdmVsIHBvciBtb3N0cmFyIGFzXG4gICAgICogbWVuc2FnZW5zIGRlIGVycm8gcmVmZXJlbnRlIGFzIHZhbGlkYcOnw7VlcyBkbyBiYWNrLWVuZFxuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9ICRxXG4gICAgICogQHBhcmFtIHthbnl9ICRpbmplY3RvclxuICAgICAqIEByZXR1cm5zXG4gICAgICovXG4gICAgZnVuY3Rpb24gc2hvd0Vycm9yVmFsaWRhdGlvbigkcSwgJGluamVjdG9yKSB7XG4gICAgICByZXR1cm4ge1xuICAgICAgICByZXNwb25zZUVycm9yOiBmdW5jdGlvbiAocmVqZWN0aW9uKSB7XG4gICAgICAgICAgdmFyIFByVG9hc3QgPSAkaW5qZWN0b3IuZ2V0KCdQclRvYXN0Jyk7XG4gICAgICAgICAgdmFyICR0cmFuc2xhdGUgPSAkaW5qZWN0b3IuZ2V0KCckdHJhbnNsYXRlJyk7XG5cbiAgICAgICAgICBpZiAocmVqZWN0aW9uLmNvbmZpZy5kYXRhICYmICFyZWplY3Rpb24uY29uZmlnLmRhdGEuc2tpcFZhbGlkYXRpb24pIHtcbiAgICAgICAgICAgIGlmIChyZWplY3Rpb24uZGF0YSAmJiByZWplY3Rpb24uZGF0YS5lcnJvcikge1xuXG4gICAgICAgICAgICAgIC8vdmVyaWZpY2Egc2Ugb2NvcnJldSBhbGd1bSBlcnJvIHJlZmVyZW50ZSBhbyB0b2tlblxuICAgICAgICAgICAgICBpZiAocmVqZWN0aW9uLmRhdGEuZXJyb3Iuc3RhcnRzV2l0aCgndG9rZW5fJykpIHtcbiAgICAgICAgICAgICAgICBQclRvYXN0Lndhcm4oJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5sb2dpbi5sb2dvdXRJbmFjdGl2ZScpKTtcbiAgICAgICAgICAgICAgfSBlbHNlIGlmIChyZWplY3Rpb24uZGF0YS5lcnJvciAhPT0gJ05vdCBGb3VuZCcpIHtcbiAgICAgICAgICAgICAgICBQclRvYXN0LmVycm9yKCR0cmFuc2xhdGUuaW5zdGFudChyZWplY3Rpb24uZGF0YS5lcnJvcikpO1xuICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICBQclRvYXN0LmVycm9yVmFsaWRhdGlvbihyZWplY3Rpb24uZGF0YSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgcmV0dXJuICRxLnJlamVjdChyZWplY3Rpb24pO1xuICAgICAgICB9XG4gICAgICB9O1xuICAgIH1cblxuICAgIC8vIERlZmluZSB1bWEgZmFjdG9yeSBwYXJhIG8gJGh0dHBJbnRlcmNlcHRvclxuICAgICRwcm92aWRlLmZhY3RvcnkoJ3Nob3dFcnJvclZhbGlkYXRpb24nLCBzaG93RXJyb3JWYWxpZGF0aW9uKTtcblxuICAgIC8vIEFkaWNpb25hIGEgZmFjdG9yeSBubyBhcnJheSBkZSBpbnRlcmNlcHRvcnMgZG8gJGh0dHBcbiAgICAkaHR0cFByb3ZpZGVyLmludGVyY2VwdG9ycy5wdXNoKCdzaG93RXJyb3JWYWxpZGF0aW9uJyk7XG4gIH1cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb250cm9sbGVyKCdLYW5iYW5Db250cm9sbGVyJywgS2FuYmFuQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBLYW5iYW5Db250cm9sbGVyKCRjb250cm9sbGVyLFxuICAgIFRhc2tzU2VydmljZSxcbiAgICBTdGF0dXNTZXJ2aWNlLFxuICAgIFByVG9hc3QsXG4gICAgJG1kRGlhbG9nLFxuICAgICRkb2N1bWVudCxcbiAgICBBdXRoLFxuICAgIFByb2plY3RzU2VydmljZSkge1xuICAgIC8vQXR0cmlidXRlcyBCbG9ja1xuICAgIHZhciB2bSA9IHRoaXM7XG4gICAgdmFyIGZpZWxkcyA9IFtcbiAgICAgIHsgbmFtZTogJ2lkJywgdHlwZTogJ3N0cmluZycgfSxcbiAgICAgIHsgbmFtZTogJ3N0YXR1cycsIG1hcDogJ3N0YXRlJywgdHlwZTogJ3N0cmluZycgfSxcbiAgICAgIHsgbmFtZTogJ3RleHQnLCBtYXA6ICdsYWJlbCcsIHR5cGU6ICdzdHJpbmcnIH0sXG4gICAgICB7IG5hbWU6ICd0YWdzJywgdHlwZTogJ3N0cmluZycgfVxuICAgIF07XG5cbiAgICB2bS5vbkFjdGl2YXRlID0gZnVuY3Rpb24oKSB7XG4gICAgICB2bS5wcm9qZWN0ID0gbG9jYWxTdG9yYWdlLmdldEl0ZW0oJ3Byb2plY3QnKTtcbiAgICAgIFByb2plY3RzU2VydmljZS5xdWVyeSh7IHByb2plY3RfaWQ6IHZtLnByb2plY3QgfSkudGhlbihmdW5jdGlvbihyZXNwb25zZSkge1xuICAgICAgICB2bS5hY3R1YWxQcm9qZWN0ID0gcmVzcG9uc2VbMF07XG4gICAgICB9KVxuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0geyBwcm9qZWN0X2lkOiB2bS5wcm9qZWN0IH07XG4gICAgICB2bS5pc01vdmVkID0gZmFsc2U7XG4gICAgfVxuXG4gICAgdm0uYXBwbHlGaWx0ZXJzID0gZnVuY3Rpb24oZGVmYXVsdFF1ZXJ5RmlsdGVycykge1xuICAgICAgcmV0dXJuIGFuZ3VsYXIuZXh0ZW5kKGRlZmF1bHRRdWVyeUZpbHRlcnMsIHZtLnF1ZXJ5RmlsdGVycyk7XG4gICAgfVxuXG4gICAgdm0uYWZ0ZXJTZWFyY2ggPSBmdW5jdGlvbiAoKSB7XG4gICAgICB2YXIgY29sdW1ucyA9IFtdO1xuICAgICAgdmFyIHRhc2tzID0gW107XG5cbiAgICAgIFN0YXR1c1NlcnZpY2UucXVlcnkoKS50aGVuKGZ1bmN0aW9uKHJlc3BvbnNlKSB7XG4gICAgICAgIHJlc3BvbnNlLmZvckVhY2goZnVuY3Rpb24oc3RhdHVzKSB7XG4gICAgICAgICAgY29sdW1ucy5wdXNoKHsgdGV4dDogc3RhdHVzLm5hbWUsIGRhdGFGaWVsZDogc3RhdHVzLnNsdWcsIGNvbGxhcHNpYmxlOiBmYWxzZSB9KTtcbiAgICAgICAgfSk7XG5cbiAgICAgICAgaWYgKHZtLnJlc291cmNlcy5sZW5ndGggPiAwKSB7XG4gICAgICAgICAgdm0ucmVzb3VyY2VzLmZvckVhY2goZnVuY3Rpb24odGFzaykge1xuICAgICAgICAgICAgdGFza3MucHVzaCh7XG4gICAgICAgICAgICAgIGlkOiB0YXNrLmlkLFxuICAgICAgICAgICAgICBzdGF0ZTogdGFzay5zdGF0dXMuc2x1ZyxcbiAgICAgICAgICAgICAgbGFiZWw6IHRhc2sudGl0bGUsXG4gICAgICAgICAgICAgIHRhZ3M6IHRhc2sudHlwZS5uYW1lICsgJywgJyArIHRhc2sucHJpb3JpdHkubmFtZVxuICAgICAgICAgICAgfSlcbiAgICAgICAgICB9KTtcblxuICAgICAgICAgIHZhciBzb3VyY2UgPSB7XG4gICAgICAgICAgICBsb2NhbERhdGE6IHRhc2tzLFxuICAgICAgICAgICAgZGF0YVR5cGU6ICdhcnJheScsXG4gICAgICAgICAgICBkYXRhRmllbGRzOiBmaWVsZHNcbiAgICAgICAgICB9O1xuICAgICAgICAgIHZhciBkYXRhQWRhcHRlciA9IG5ldyAkLmpxeC5kYXRhQWRhcHRlcihzb3VyY2UpO1xuXG4gICAgICAgICAgdm0uc2V0dGluZ3MgPSB7XG4gICAgICAgICAgICBzb3VyY2U6IGRhdGFBZGFwdGVyLFxuICAgICAgICAgICAgY29sdW1uczogY29sdW1ucyxcbiAgICAgICAgICAgIHRoZW1lOiAnbGlnaHQnXG4gICAgICAgICAgfTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICB2bS5zZXR0aW5ncyA9IHtcbiAgICAgICAgICAgIHNvdXJjZTogW3t9XSxcbiAgICAgICAgICAgIGNvbHVtbnM6IGNvbHVtbnMsXG4gICAgICAgICAgICB0aGVtZTogJ2xpZ2h0J1xuICAgICAgICAgIH07XG4gICAgICAgIH1cbiAgICAgICAgdm0ua2FuYmFuUmVhZHkgPSB0cnVlO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgdm0ub25JdGVtTW92ZWQgPSBmdW5jdGlvbihldmVudCkge1xuICAgICAgaWYgKCF2bS5hY3R1YWxQcm9qZWN0LmRvbmUgJiYgQXV0aC5jdXJyZW50VXNlci5pZCA9PT0gdm0uYWN0dWFsUHJvamVjdC5vd25lcikge1xuICAgICAgICB2bS5pc01vdmVkID0gdHJ1ZTtcbiAgICAgICAgVGFza3NTZXJ2aWNlLnF1ZXJ5KHsgdGFza19pZDogZXZlbnQuYXJncy5pdGVtSWQgfSkudGhlbihmdW5jdGlvbihyZXNwb25zZSkge1xuICAgICAgICAgIGlmICgocmVzcG9uc2VbMF0ubWlsZXN0b25lICYmIHJlc3BvbnNlWzBdLm1pbGVzdG9uZS5kb25lKSB8fCByZXNwb25zZVswXS5wcm9qZWN0LmRvbmUpIHtcbiAgICAgICAgICAgIFByVG9hc3QuZXJyb3IoJ07Do28gw6kgcG9zc8OtdmVsIG1vZGlmaWNhciBvIHN0YXR1cyBkZSB1bWEgdGFyZWZhIGZpbmFsaXphZGEuJyk7XG4gICAgICAgICAgICB2bS5hZnRlclNlYXJjaCgpO1xuICAgICAgICAgICAgdm0uaXNNb3ZlZCA9IGZhbHNlO1xuICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICBUYXNrc1NlcnZpY2UudXBkYXRlVGFza0J5S2FuYmFuKHtcbiAgICAgICAgICAgICAgcHJvamVjdF9pZDogdm0ucHJvamVjdCxcbiAgICAgICAgICAgICAgaWQ6IGV2ZW50LmFyZ3MuaXRlbUlkLFxuICAgICAgICAgICAgICBvbGRDb2x1bW46IGV2ZW50LmFyZ3Mub2xkQ29sdW1uLFxuICAgICAgICAgICAgICBuZXdDb2x1bW46IGV2ZW50LmFyZ3MubmV3Q29sdW1uIH0pLnRoZW4oZnVuY3Rpb24oKSB7XG4gICAgICAgICAgICAgICAgdm0uaXNNb3ZlZCA9IGZhbHNlO1xuICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICB9XG4gICAgICAgIH0pO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgdm0uYWZ0ZXJTZWFyY2goKTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICB2bS5vbkl0ZW1DbGlja2VkID0gZnVuY3Rpb24oZXZlbnQpIHtcbiAgICAgIGlmICghdm0uaXNNb3ZlZCkge1xuICAgICAgICBUYXNrc1NlcnZpY2UucXVlcnkoeyB0YXNrX2lkOiBldmVudC5hcmdzLml0ZW1JZCB9KS50aGVuKGZ1bmN0aW9uKHJlc3BvbnNlKSB7XG4gICAgICAgICAgdm0udGFza0luZm8gPSByZXNwb25zZVswXTtcbiAgICAgICAgICAkbWREaWFsb2cuc2hvdyh7XG4gICAgICAgICAgICBwYXJlbnQ6IGFuZ3VsYXIuZWxlbWVudCgkZG9jdW1lbnQuYm9keSksXG4gICAgICAgICAgICB0ZW1wbGF0ZVVybDogJ2NsaWVudC9hcHAva2FuYmFuL3Rhc2staW5mby1kaWFsb2cvdGFza0luZm8uaHRtbCcsXG4gICAgICAgICAgICBjb250cm9sbGVyQXM6ICd0YXNrSW5mb0N0cmwnLFxuICAgICAgICAgICAgY29udHJvbGxlcjogJ1Rhc2tJbmZvQ29udHJvbGxlcicsXG4gICAgICAgICAgICBiaW5kVG9Db250cm9sbGVyOiB0cnVlLFxuICAgICAgICAgICAgbG9jYWxzOiB7XG4gICAgICAgICAgICAgIHRhc2s6IHZtLnRhc2tJbmZvLFxuICAgICAgICAgICAgICBjbG9zZTogY2xvc2VcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICBlc2NhcGVUb0Nsb3NlOiB0cnVlLFxuICAgICAgICAgICAgY2xpY2tPdXRzaWRlVG9DbG9zZTogdHJ1ZVxuICAgICAgICAgIH0pO1xuICAgICAgICB9KTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHZtLmlzTW92ZWQgPSBmYWxzZTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICBmdW5jdGlvbiBjbG9zZSgpIHtcbiAgICAgICRtZERpYWxvZy5oaWRlKCk7XG4gICAgfVxuXG4gICAgLy8gaW5zdGFudGlhdGUgYmFzZSBjb250cm9sbGVyXG4gICAgJGNvbnRyb2xsZXIoJ0NSVURDb250cm9sbGVyJywgeyB2bTogdm0sIG1vZGVsU2VydmljZTogVGFza3NTZXJ2aWNlLCBvcHRpb25zOiB7IH0gfSk7XG5cbiAgfVxuXG59KSgpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKlxuICAgKiBBcnF1aXZvIGRlIGNvbmZpZ3VyYcOnw6NvIGNvbSBhcyByb3RhcyBlc3BlY8OtZmljYXMgZG8gcmVjdXJzbyBrYW5iYW5cbiAgICpcbiAgICogQHBhcmFtIHtvYmplY3R9ICRzdGF0ZVByb3ZpZGVyXG4gICAqIEBwYXJhbSB7b2JqZWN0fSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlclxuICAgICAgLnN0YXRlKCdhcHAua2FuYmFuJywge1xuICAgICAgICB1cmw6ICcva2FuYmFuJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9rYW5iYW4va2FuYmFuLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnS2FuYmFuQ29udHJvbGxlciBhcyBrYW5iYW5DdHJsJyxcbiAgICAgICAgZGF0YTogeyB9XG4gICAgICB9KTtcbiAgfVxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5mYWN0b3J5KCdLYW5iYW5TZXJ2aWNlJywgS2FuYmFuU2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiBLYW5iYW5TZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgdmFyIG1vZGVsID0gc2VydmljZUZhY3RvcnkoJ2thbmJhbicsIHtcbiAgICAgIGFjdGlvbnM6IHsgfSxcbiAgICAgIGluc3RhbmNlOiB7IH1cbiAgICB9KTtcblxuICAgIHJldHVybiBtb2RlbDtcbiAgfVxuXG59KCkpO1xuIiwiLyplc2xpbnQtZW52IGVzNiovXG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb250cm9sbGVyKCdNZW51Q29udHJvbGxlcicsIE1lbnVDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIE1lbnVDb250cm9sbGVyKCRtZFNpZGVuYXYsICRzdGF0ZSwgJG1kQ29sb3JzKSB7XG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIC8vQmxvY28gZGUgZGVjbGFyYWNvZXMgZGUgZnVuY29lc1xuICAgIHZtLm9wZW4gPSBvcGVuO1xuICAgIHZtLm9wZW5NZW51T3JSZWRpcmVjdFRvU3RhdGUgPSBvcGVuTWVudU9yUmVkaXJlY3RUb1N0YXRlO1xuXG4gICAgYWN0aXZhdGUoKTtcblxuICAgIGZ1bmN0aW9uIGFjdGl2YXRlKCkge1xuICAgICAgdmFyIG1lbnVQcmVmaXggPSAndmlld3MubGF5b3V0Lm1lbnUuJztcblxuICAgICAgLy8gQXJyYXkgY29udGVuZG8gb3MgaXRlbnMgcXVlIHPDo28gbW9zdHJhZG9zIG5vIG1lbnUgbGF0ZXJhbFxuICAgICAgdm0uaXRlbnNNZW51ID0gW1xuICAgICAgICB7IHN0YXRlOiAnYXBwLnByb2plY3RzJywgdGl0bGU6IG1lbnVQcmVmaXggKyAncHJvamVjdHMnLCBpY29uOiAnd29yaycsIHN1Ykl0ZW5zOiBbXSB9LFxuICAgICAgICB7IHN0YXRlOiAnYXBwLmRhc2hib2FyZCcsIHRpdGxlOiBtZW51UHJlZml4ICsgJ2Rhc2hib2FyZCcsIGljb246ICdkYXNoYm9hcmQnLCBzdWJJdGVuczogW10gfSxcbiAgICAgICAgeyBzdGF0ZTogJ2FwcC50YXNrcycsIHRpdGxlOiBtZW51UHJlZml4ICsgJ3Rhc2tzJywgaWNvbjogJ3ZpZXdfbGlzdCcsIHN1Ykl0ZW5zOiBbXSB9LFxuICAgICAgICB7IHN0YXRlOiAnYXBwLm1pbGVzdG9uZXMnLCB0aXRsZTogbWVudVByZWZpeCArICdtaWxlc3RvbmVzJywgaWNvbjogJ3ZpZXdfbW9kdWxlJywgc3ViSXRlbnM6IFtdIH0sXG4gICAgICAgIHsgc3RhdGU6ICdhcHAucmVsZWFzZXMnLCB0aXRsZTogbWVudVByZWZpeCArICdyZWxlYXNlcycsIGljb246ICdzdWJzY3JpcHRpb25zJywgc3ViSXRlbnM6IFtdIH0sXG4gICAgICAgIHsgc3RhdGU6ICdhcHAua2FuYmFuJywgdGl0bGU6IG1lbnVQcmVmaXggKyAna2FuYmFuJywgaWNvbjogJ3ZpZXdfY29sdW1uJywgc3ViSXRlbnM6IFtdIH0sXG4gICAgICAgIHsgc3RhdGU6ICdhcHAudmNzJywgdGl0bGU6IG1lbnVQcmVmaXggKyAndmNzJywgaWNvbjogJ2dyb3VwX3dvcmsnLCBzdWJJdGVuczogW10gfVxuICAgICAgICAvLyBDb2xvcXVlIHNldXMgaXRlbnMgZGUgbWVudSBhIHBhcnRpciBkZXN0ZSBwb250b1xuICAgICAgICAvKiB7XG4gICAgICAgICAgc3RhdGU6ICcjJywgdGl0bGU6IG1lbnVQcmVmaXggKyAnYWRtaW4nLCBpY29uOiAnc2V0dGluZ3NfYXBwbGljYXRpb25zJywgcHJvZmlsZXM6IFsnYWRtaW4nXSxcbiAgICAgICAgICBzdWJJdGVuczogW1xuICAgICAgICAgICAgeyBzdGF0ZTogJ2FwcC51c2VyJywgdGl0bGU6IG1lbnVQcmVmaXggKyAndXNlcicsIGljb246ICdwZW9wbGUnIH0sXG4gICAgICAgICAgICB7IHN0YXRlOiAnYXBwLm1haWwnLCB0aXRsZTogbWVudVByZWZpeCArICdtYWlsJywgaWNvbjogJ21haWwnIH0sXG4gICAgICAgICAgICB7IHN0YXRlOiAnYXBwLmF1ZGl0JywgdGl0bGU6IG1lbnVQcmVmaXggKyAnYXVkaXQnLCBpY29uOiAnc3RvcmFnZScgfSxcbiAgICAgICAgICAgIHsgc3RhdGU6ICdhcHAuZGluYW1pYy1xdWVyeScsIHRpdGxlOiBtZW51UHJlZml4ICsgJ2RpbmFtaWNRdWVyeScsIGljb246ICdsb2NhdGlvbl9zZWFyY2hpbmcnIH1cbiAgICAgICAgICBdXG4gICAgICAgIH0gKi9cbiAgICAgIF07XG5cbiAgICAgIC8qKlxuICAgICAgICogT2JqZXRvIHF1ZSBwcmVlbmNoZSBvIG5nLXN0eWxlIGRvIG1lbnUgbGF0ZXJhbCB0cm9jYW5kbyBhcyBjb3Jlc1xuICAgICAgICovXG4gICAgICB2bS5zaWRlbmF2U3R5bGUgPSB7XG4gICAgICAgIHRvcDoge1xuICAgICAgICAgICdib3JkZXItYm90dG9tJzogJzFweCBzb2xpZCByZ2IoMjEwLCAyMTAsIDIxMCknLFxuICAgICAgICAgICdiYWNrZ3JvdW5kLWltYWdlJzogJy13ZWJraXQtbGluZWFyLWdyYWRpZW50KHRvcCwgcmdiKDE0NCwgMTQ0LCAxNDQpLCByZ2IoMjEwLCAyMTAsIDIxMCkpJ1xuICAgICAgICB9LFxuICAgICAgICBjb250ZW50OiB7XG4gICAgICAgICAgJ2JhY2tncm91bmQtY29sb3InOiAncmdiKDIxMCwgMjEwLCAyMTApJ1xuICAgICAgICB9LFxuICAgICAgICB0ZXh0Q29sb3I6IHtcbiAgICAgICAgICBjb2xvcjogJyNGRkYnXG4gICAgICAgIH0sXG4gICAgICAgIGxpbmVCb3R0b206IHtcbiAgICAgICAgICAnYm9yZGVyLWJvdHRvbSc6ICcxcHggc29saWQgJyArIGdldENvbG9yKCdwcmltYXJ5LTQwMCcpXG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9XG5cbiAgICBmdW5jdGlvbiBvcGVuKCkge1xuICAgICAgJG1kU2lkZW5hdignbGVmdCcpLnRvZ2dsZSgpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIE3DqXRvZG8gcXVlIGV4aWJlIG8gc3ViIG1lbnUgZG9zIGl0ZW5zIGRvIG1lbnUgbGF0ZXJhbCBjYXNvIHRlbmhhIHN1YiBpdGVuc1xuICAgICAqIGNhc28gY29udHLDoXJpbyByZWRpcmVjaW9uYSBwYXJhIG8gc3RhdGUgcGFzc2FkbyBjb21vIHBhcsODwqJtZXRyb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIG9wZW5NZW51T3JSZWRpcmVjdFRvU3RhdGUoJG1kTWVudSwgZXYsIGl0ZW0pIHtcbiAgICAgIGlmIChhbmd1bGFyLmlzRGVmaW5lZChpdGVtLnN1Ykl0ZW5zKSAmJiBpdGVtLnN1Ykl0ZW5zLmxlbmd0aCA+IDApIHtcbiAgICAgICAgJG1kTWVudS5vcGVuKGV2KTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgICRzdGF0ZS5nbyhpdGVtLnN0YXRlLCB7IG9iajogbnVsbCB9KTtcbiAgICAgICAgJG1kU2lkZW5hdignbGVmdCcpLmNsb3NlKCk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gZ2V0Q29sb3IoY29sb3JQYWxldHRlcykge1xuICAgICAgcmV0dXJuICRtZENvbG9ycy5nZXRUaGVtZUNvbG9yKGNvbG9yUGFsZXR0ZXMpO1xuICAgIH1cblxuICB9XG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb250cm9sbGVyKCdNYWlsc0NvbnRyb2xsZXInLCBNYWlsc0NvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gTWFpbHNDb250cm9sbGVyKE1haWxzU2VydmljZSwgVXNlcnNTZXJ2aWNlLCBQckRpYWxvZywgUHJUb2FzdCwgLy8gTk9TT05BUlxuICAgICRxLCBsb2Rhc2gsICR0cmFuc2xhdGUsIEdsb2JhbCkge1xuXG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIHZtLmZpbHRlclNlbGVjdGVkID0gZmFsc2U7XG4gICAgdm0ub3B0aW9ucyA9IHtcbiAgICAgIHNraW46ICdrYW1hJyxcbiAgICAgIGxhbmd1YWdlOiAncHQtYnInLFxuICAgICAgYWxsb3dlZENvbnRlbnQ6IHRydWUsXG4gICAgICBlbnRpdGllczogdHJ1ZSxcbiAgICAgIGhlaWdodDogMzAwLFxuICAgICAgZXh0cmFQbHVnaW5zOiAnZGlhbG9nLGZpbmQsY29sb3JkaWFsb2cscHJldmlldyxmb3JtcyxpZnJhbWUsZmxhc2gnXG4gICAgfTtcblxuICAgIHZtLmxvYWRVc2VycyA9IGxvYWRVc2VycztcbiAgICB2bS5vcGVuVXNlckRpYWxvZyA9IG9wZW5Vc2VyRGlhbG9nO1xuICAgIHZtLmFkZFVzZXJNYWlsID0gYWRkVXNlck1haWw7XG4gICAgdm0uY2xlYW5Gb3JtID0gY2xlYW5Gb3JtO1xuICAgIHZtLnNlbmQgPSBzZW5kO1xuXG4gICAgYWN0aXZhdGUoKTtcblxuICAgIGZ1bmN0aW9uIGFjdGl2YXRlKCkge1xuICAgICAgdm0uY2xlYW5Gb3JtKCk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhbGl6YSBhIGJ1c2NhIHBlbG8gdXN1w6FyaW8gcmVtb3RhbWVudGVcbiAgICAgKlxuICAgICAqIEBwYXJhbXMge3N0cmluZ30gLSBSZWNlYmUgbyB2YWxvciBwYXJhIHNlciBwZXNxdWlzYWRvXG4gICAgICogQHJldHVybiB7cHJvbWlzc2V9IC0gUmV0b3JuYSB1bWEgcHJvbWlzc2UgcXVlIG8gY29tcG9uZXRlIHJlc29sdmVcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBsb2FkVXNlcnMoY3JpdGVyaWEpIHtcbiAgICAgIHZhciBkZWZlcnJlZCA9ICRxLmRlZmVyKCk7XG5cbiAgICAgIFVzZXJzU2VydmljZS5xdWVyeSh7XG4gICAgICAgIG5hbWVPckVtYWlsOiBjcml0ZXJpYSxcbiAgICAgICAgbm90VXNlcnM6IGxvZGFzaC5tYXAodm0ubWFpbC51c2VycywgbG9kYXNoLnByb3BlcnR5KCdpZCcpKS50b1N0cmluZygpLFxuICAgICAgICBsaW1pdDogNVxuICAgICAgfSkudGhlbihmdW5jdGlvbihkYXRhKSB7XG5cbiAgICAgICAgLy8gdmVyaWZpY2Egc2UgbmEgbGlzdGEgZGUgdXN1YXJpb3MgasOhIGV4aXN0ZSBvIHVzdcOhcmlvIGNvbSBvIGVtYWlsIHBlc3F1aXNhZG9cbiAgICAgICAgZGF0YSA9IGxvZGFzaC5maWx0ZXIoZGF0YSwgZnVuY3Rpb24odXNlcikge1xuICAgICAgICAgIHJldHVybiAhbG9kYXNoLmZpbmQodm0ubWFpbC51c2VycywgeyBlbWFpbDogdXNlci5lbWFpbCB9KTtcbiAgICAgICAgfSk7XG5cbiAgICAgICAgZGVmZXJyZWQucmVzb2x2ZShkYXRhKTtcbiAgICAgIH0pO1xuXG4gICAgICByZXR1cm4gZGVmZXJyZWQucHJvbWlzZTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBBYnJlIG8gZGlhbG9nIHBhcmEgcGVzcXVpc2EgZGUgdXN1w6FyaW9zXG4gICAgICovXG4gICAgZnVuY3Rpb24gb3BlblVzZXJEaWFsb2coKSB7XG4gICAgICB2YXIgY29uZmlnID0ge1xuICAgICAgICBsb2NhbHM6IHtcbiAgICAgICAgICBvbkluaXQ6IHRydWUsXG4gICAgICAgICAgdXNlckRpYWxvZ0lucHV0OiB7XG4gICAgICAgICAgICB0cmFuc2ZlclVzZXJGbjogdm0uYWRkVXNlck1haWxcbiAgICAgICAgICB9XG4gICAgICAgIH0sXG4gICAgICAgIGNvbnRyb2xsZXI6ICdVc2Vyc0RpYWxvZ0NvbnRyb2xsZXInLFxuICAgICAgICBjb250cm9sbGVyQXM6ICdjdHJsJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy91c2Vycy9kaWFsb2cvdXNlcnMtZGlhbG9nLmh0bWwnLFxuICAgICAgICBoYXNCYWNrZHJvcDogdHJ1ZVxuICAgICAgfTtcblxuICAgICAgUHJEaWFsb2cuY3VzdG9tKGNvbmZpZyk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQWRpY2lvbmEgbyB1c3XDoXJpbyBzZWxlY2lvbmFkbyBuYSBsaXN0YSBwYXJhIHF1ZSBzZWphIGVudmlhZG8gbyBlbWFpbFxuICAgICAqL1xuICAgIGZ1bmN0aW9uIGFkZFVzZXJNYWlsKHVzZXIpIHtcbiAgICAgIHZhciB1c2VycyA9IGxvZGFzaC5maW5kKHZtLm1haWwudXNlcnMsIHsgZW1haWw6IHVzZXIuZW1haWwgfSk7XG5cbiAgICAgIGlmICh2bS5tYWlsLnVzZXJzLmxlbmd0aCA+IDAgJiYgYW5ndWxhci5pc0RlZmluZWQodXNlcnMpKSB7XG4gICAgICAgIFByVG9hc3Qud2FybigkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnVzZXIudXNlckV4aXN0cycpKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHZtLm1haWwudXNlcnMucHVzaCh7IG5hbWU6IHVzZXIubmFtZSwgZW1haWw6IHVzZXIuZW1haWwgfSlcbiAgICAgIH1cbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFsaXphIG8gZW52aW8gZG8gZW1haWwgcGFyYSBhIGxpc3RhIGRlIHVzdcOhcmlvcyBzZWxlY2lvbmFkb3NcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBzZW5kKCkge1xuXG4gICAgICB2bS5tYWlsLiRzYXZlKCkudGhlbihmdW5jdGlvbihyZXNwb25zZSkge1xuICAgICAgICBpZiAocmVzcG9uc2UubGVuZ3RoID4gMCkge1xuICAgICAgICAgIHZhciBtc2cgPSAkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLm1haWwubWFpbEVycm9ycycpO1xuXG4gICAgICAgICAgZm9yICh2YXIgaT0wOyBpIDwgcmVzcG9uc2UubGVuZ3RoOyBpKyspIHtcbiAgICAgICAgICAgIG1zZyArPSByZXNwb25zZSArICdcXG4nO1xuICAgICAgICAgIH1cbiAgICAgICAgICBQclRvYXN0LmVycm9yKG1zZyk7XG4gICAgICAgICAgdm0uY2xlYW5Gb3JtKCk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgUHJUb2FzdC5zdWNjZXNzKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMubWFpbC5zZW5kTWFpbFN1Y2Nlc3MnKSk7XG4gICAgICAgICAgdm0uY2xlYW5Gb3JtKCk7XG4gICAgICAgIH1cbiAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIExpbXBhIG8gZm9ybXVsw6FyaW8gZGUgZW1haWxcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBjbGVhbkZvcm0oKSB7XG4gICAgICB2bS5tYWlsID0gbmV3IE1haWxzU2VydmljZSgpO1xuICAgICAgdm0ubWFpbC51c2VycyA9IFtdO1xuICAgIH1cblxuICB9XG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqXG4gICAqIEFycXVpdm8gZGUgY29uZmlndXJhw6fDo28gY29tIGFzIHJvdGFzIGVzcGVjw61maWNhcyBkbyByZWN1cnNvIGVtIHF1ZXN0w6NvXG4gICAqXG4gICAqIEBwYXJhbSB7YW55fSAkc3RhdGVQcm92aWRlclxuICAgKiBAcGFyYW0ge2FueX0gR2xvYmFsXG4gICAqL1xuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvdXRlcygkc3RhdGVQcm92aWRlciwgR2xvYmFsKSB7XG4gICAgJHN0YXRlUHJvdmlkZXJcbiAgICAgIC5zdGF0ZSgnYXBwLm1haWwnLCB7XG4gICAgICAgIHVybDogJy9lbWFpbCcsXG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvbWFpbC9tYWlscy1zZW5kLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnTWFpbHNDb250cm9sbGVyIGFzIG1haWxzQ3RybCcsXG4gICAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiB0cnVlLCBuZWVkUHJvZmlsZTogWydhZG1pbiddIH1cbiAgICAgIH0pO1xuXG4gIH1cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmFjdG9yeSgnTWFpbHNTZXJ2aWNlJywgTWFpbHNTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIE1haWxzU2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHJldHVybiBzZXJ2aWNlRmFjdG9yeSgnbWFpbHMnLCB7fSk7XG4gIH1cblxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnRyb2xsZXIoJ01pbGVzdG9uZXNDb250cm9sbGVyJywgTWlsZXN0b25lc0NvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gTWlsZXN0b25lc0NvbnRyb2xsZXIoJGNvbnRyb2xsZXIsXG4gICAgTWlsZXN0b25lc1NlcnZpY2UsXG4gICAgbW9tZW50LFxuICAgIFRhc2tzU2VydmljZSxcbiAgICBQcm9qZWN0c1NlcnZpY2UsXG4gICAgUHJUb2FzdCxcbiAgICAkdHJhbnNsYXRlLFxuICAgICRtZERpYWxvZyxcbiAgICBBdXRoKSB7XG5cbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0uZXN0aW1hdGVkUHJpY2UgPSBlc3RpbWF0ZWRQcmljZTtcblxuICAgIHZtLm9uQWN0aXZhdGUgPSBmdW5jdGlvbigpIHtcbiAgICAgIHZtLmN1cnJlbnRVc2VyID0gQXV0aC5jdXJyZW50VXNlcjtcbiAgICAgIHZtLnByb2plY3QgPSBsb2NhbFN0b3JhZ2UuZ2V0SXRlbSgncHJvamVjdCcpO1xuICAgICAgUHJvamVjdHNTZXJ2aWNlLnF1ZXJ5KHsgcHJvamVjdF9pZDogdm0ucHJvamVjdCB9KS50aGVuKGZ1bmN0aW9uKHJlc3BvbnNlKSB7XG4gICAgICAgIHZtLmFjdHVhbFByb2plY3QgPSByZXNwb25zZVswXTtcbiAgICAgIH0pO1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0geyBwcm9qZWN0X2lkOiB2bS5wcm9qZWN0IH07XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gZXN0aW1hdGVkUHJpY2UobWlsZXN0b25lKSB7XG4gICAgICBtaWxlc3RvbmUuZXN0aW1hdGVkX3ZhbHVlID0gMDtcbiAgICAgIGlmKG1pbGVzdG9uZS50YXNrcy5sZW5ndGggPiAwICYmIG1pbGVzdG9uZS5wcm9qZWN0LmhvdXJfdmFsdWVfZmluYWwpIHtcbiAgICAgICAgbWlsZXN0b25lLnRhc2tzLmZvckVhY2goZnVuY3Rpb24odGFzaykge1xuICAgICAgICAgIG1pbGVzdG9uZS5lc3RpbWF0ZWRfdmFsdWUgKz0gKHBhcnNlRmxvYXQobWlsZXN0b25lLnByb2plY3QuaG91cl92YWx1ZV9maW5hbCkgKiB0YXNrLmVzdGltYXRlZF90aW1lKTtcbiAgICAgICAgfSk7XG4gICAgICB9XG4gICAgICByZXR1cm4gbWlsZXN0b25lLmVzdGltYXRlZF92YWx1ZS50b0xvY2FsZVN0cmluZygnUHQtYnInLCB7IG1pbmltdW1GcmFjdGlvbkRpZ2l0czogMiB9KTtcbiAgICB9XG5cbiAgICB2bS5lc3RpbWF0ZWRUaW1lID0gZnVuY3Rpb24gKG1pbGVzdG9uZSkge1xuICAgICAgbWlsZXN0b25lLmVzdGltYXRlZF90aW1lID0gMDtcbiAgICAgIGlmKG1pbGVzdG9uZS50YXNrcy5sZW5ndGggPiAwKSB7XG4gICAgICAgIG1pbGVzdG9uZS50YXNrcy5mb3JFYWNoKGZ1bmN0aW9uKHRhc2spIHtcbiAgICAgICAgICBtaWxlc3RvbmUuZXN0aW1hdGVkX3RpbWUgKz0gdGFzay5lc3RpbWF0ZWRfdGltZTtcbiAgICAgICAgfSk7XG4gICAgICB9XG4gICAgICBtaWxlc3RvbmUuZXN0aW1hdGVkX3RpbWUgPSBtaWxlc3RvbmUuZXN0aW1hdGVkX3RpbWUgLyA4O1xuICAgICAgdmFyIGRhdGVFbmQgPSBtb21lbnQobWlsZXN0b25lLmRhdGVfZW5kKTtcbiAgICAgIHZhciBkYXRlQmVnaW4gPSBtb21lbnQobWlsZXN0b25lLmRhdGVfYmVnaW4pO1xuXG4gICAgICBpZiAoZGF0ZUVuZC5kaWZmKGRhdGVCZWdpbiwgJ2RheXMnKSA8IG1pbGVzdG9uZS5lc3RpbWF0ZWRfdGltZSkge1xuICAgICAgICBtaWxlc3RvbmUuY29sb3JfZXN0aW1hdGVkX3RpbWUgPSB7IGNvbG9yOiAncmVkJyB9O1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgbWlsZXN0b25lLmNvbG9yX2VzdGltYXRlZF90aW1lID0geyBjb2xvcjogJ2dyZWVuJyB9O1xuICAgICAgfVxuICAgICAgcmV0dXJuIG1pbGVzdG9uZS5lc3RpbWF0ZWRfdGltZTtcbiAgICB9XG5cbiAgICB2bS5hcHBseUZpbHRlcnMgPSBmdW5jdGlvbihkZWZhdWx0UXVlcnlGaWx0ZXJzKSB7XG4gICAgICByZXR1cm4gYW5ndWxhci5leHRlbmQoZGVmYXVsdFF1ZXJ5RmlsdGVycywgdm0ucXVlcnlGaWx0ZXJzKTtcbiAgICB9XG5cbiAgICB2bS5iZWZvcmVTYXZlID0gZnVuY3Rpb24oKSB7XG4gICAgICB2bS5yZXNvdXJjZS5wcm9qZWN0X2lkID0gdm0ucHJvamVjdDtcbiAgICB9XG5cbiAgICB2bS5iZWZvcmVSZW1vdmUgPSBmdW5jdGlvbigpIHtcbiAgICAgIHZtLnJlc291cmNlLnByb2plY3RfaWQgPSB2bS5wcm9qZWN0O1xuICAgIH1cblxuICAgIHZtLmZvcm1hdERhdGUgPSBmdW5jdGlvbihkYXRlKSB7XG4gICAgICByZXR1cm4gbW9tZW50KGRhdGUpLmZvcm1hdCgnREQvTU0vWVlZWScpO1xuICAgIH1cblxuICAgIHZtLmFmdGVyRWRpdCA9IGZ1bmN0aW9uKCkge1xuICAgICAgdm0ucmVzb3VyY2UuZGF0ZV9iZWdpbiA9IG1vbWVudCh2bS5yZXNvdXJjZS5kYXRlX2JlZ2luKS5fZDtcbiAgICAgIHZtLnJlc291cmNlLmRhdGVfZW5kID0gbW9tZW50KHZtLnJlc291cmNlLmRhdGVfZW5kKS5fZDtcbiAgICB9XG5cbiAgICB2bS52aWV3ID0gZnVuY3Rpb24gKHJlc291cmNlKSB7XG4gICAgICB2bS5yZXNvdXJjZSA9IHJlc291cmNlO1xuICAgICAgdm0ucmVzb3VyY2UuZGF0ZV9iZWdpbiA9IG1vbWVudCh2bS5yZXNvdXJjZS5kYXRlX2JlZ2luKTtcbiAgICAgIHZtLnJlc291cmNlLmRhdGVfZW5kID0gbW9tZW50KHZtLnJlc291cmNlLmRhdGVfZW5kKTtcbiAgICAgIHZtLm9uVmlldyA9IHRydWU7XG4gICAgICB2bS52aWV3Rm9ybSA9IGZhbHNlO1xuICAgIH1cblxuICAgIHZtLnNlYXJjaFRhc2sgPSBmdW5jdGlvbiAodGFza1Rlcm0pIHtcbiAgICAgIHJldHVybiBUYXNrc1NlcnZpY2UucXVlcnkoe1xuICAgICAgICBtaWxlc3RvbmVTZWFyY2g6IHRydWUsXG4gICAgICAgIHByb2plY3RfaWQ6IHZtLnJlc291cmNlLnByb2plY3RfaWQsXG4gICAgICAgIHRpdGxlOiB0YXNrVGVybVxuICAgICAgfSk7XG4gICAgfVxuXG4gICAgdm0ub25UYXNrQ2hhbmdlID0gZnVuY3Rpb24oKSB7XG4gICAgICBpZiAodm0udGFzayAhPT0gbnVsbCAmJiB2bS5yZXNvdXJjZS50YXNrcy5maW5kSW5kZXgoaSA9PiBpLmlkID09PSB2bS50YXNrLmlkKSA9PT0gLTEpIHtcbiAgICAgICAgdm0ucmVzb3VyY2UudGFza3MucHVzaCh2bS50YXNrKTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICB2bS5yZW1vdmVUYXNrID0gZnVuY3Rpb24odGFzaykge1xuICAgICAgdm0ucmVzb3VyY2UudGFza3Muc2xpY2UoMCkuZm9yRWFjaChmdW5jdGlvbihlbGVtZW50KSB7XG4gICAgICAgIGlmKGVsZW1lbnQuaWQgPT09IHRhc2suaWQpIHtcbiAgICAgICAgICB2bS5yZXNvdXJjZS50YXNrcy5zcGxpY2Uodm0ucmVzb3VyY2UudGFza3MuaW5kZXhPZihlbGVtZW50KSwgMSk7XG4gICAgICAgIH1cbiAgICAgIH0pO1xuICAgIH1cblxuICAgIHZtLnNhdmVUYXNrcyA9IGZ1bmN0aW9uKCkge1xuICAgICAgVGFza3NTZXJ2aWNlLnVwZGF0ZU1pbGVzdG9uZSh7cHJvamVjdF9pZDogdm0ucmVzb3VyY2UucHJvamVjdF9pZCwgbWlsZXN0b25lX2lkOiB2bS5yZXNvdXJjZS5pZCwgdGFza3M6IHZtLnJlc291cmNlLnRhc2tzfSkudGhlbihmdW5jdGlvbigpe1xuICAgICAgICBQclRvYXN0LnN1Y2Nlc3MoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5zYXZlU3VjY2VzcycpKTtcbiAgICAgICAgdm0udmlld0Zvcm0gPSBmYWxzZTtcbiAgICAgICAgdm0ub25WaWV3ID0gZmFsc2U7XG4gICAgICB9LCBmdW5jdGlvbigpIHtcbiAgICAgICAgUHJUb2FzdC5lcnJvcigkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLm9wZXJhdGlvbkVycm9yJykpO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgdm0uZmluYWxpemUgPSBmdW5jdGlvbihtaWxlc3RvbmUpIHtcbiAgICAgIHZhciBjb25maXJtID0gJG1kRGlhbG9nLmNvbmZpcm0oKVxuICAgICAgICAgIC50aXRsZSgnRmluYWxpemFyIFNwcmludCcpXG4gICAgICAgICAgLnRleHRDb250ZW50KCdUZW0gY2VydGV6YSBxdWUgZGVzZWphIGZpbmFsaXphciBhIHNwcmludCAnICsgbWlsZXN0b25lLnRpdGxlICsgJz8nKVxuICAgICAgICAgIC5vaygnU2ltJylcbiAgICAgICAgICAuY2FuY2VsKCdOw6NvJyk7XG5cbiAgICAgICRtZERpYWxvZy5zaG93KGNvbmZpcm0pLnRoZW4oZnVuY3Rpb24oKSB7XG4gICAgICAgIE1pbGVzdG9uZXNTZXJ2aWNlLmZpbmFsaXplKHsgcHJvamVjdF9pZDogdm0ucHJvamVjdCwgbWlsZXN0b25lX2lkOiBtaWxlc3RvbmUuaWQgfSkudGhlbihmdW5jdGlvbigpIHtcbiAgICAgICAgICBQclRvYXN0LnN1Y2Nlc3MoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5zcHJpbnRFbmRlZFN1Y2Nlc3MnKSk7XG4gICAgICAgICAgdm0uc2VhcmNoKCk7XG4gICAgICAgIH0sIGZ1bmN0aW9uKCkge1xuICAgICAgICAgIFByVG9hc3QuRXJyb3IoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5zcHJpbnRFbmRlZEVycm9yJykpO1xuICAgICAgICB9KTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIC8vIGluc3RhbnRpYXRlIGJhc2UgY29udHJvbGxlclxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHsgdm06IHZtLCBtb2RlbFNlcnZpY2U6IE1pbGVzdG9uZXNTZXJ2aWNlLCBvcHRpb25zOiB7IH0gfSk7XG5cbiAgfVxuXG59KSgpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKlxuICAgKiBBcnF1aXZvIGRlIGNvbmZpZ3VyYcOnw6NvIGNvbSBhcyByb3RhcyBlc3BlY8OtZmljYXMgZG8gcmVjdXJzbyBtaWxlc3RvbmVzXG4gICAqXG4gICAqIEBwYXJhbSB7b2JqZWN0fSAkc3RhdGVQcm92aWRlclxuICAgKiBAcGFyYW0ge29iamVjdH0gR2xvYmFsXG4gICAqL1xuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvdXRlcygkc3RhdGVQcm92aWRlciwgR2xvYmFsKSB7XG4gICAgJHN0YXRlUHJvdmlkZXJcbiAgICAgIC5zdGF0ZSgnYXBwLm1pbGVzdG9uZXMnLCB7XG4gICAgICAgIHVybDogJy9taWxlc3RvbmVzJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9taWxlc3RvbmVzL21pbGVzdG9uZXMuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdNaWxlc3RvbmVzQ29udHJvbGxlciBhcyBtaWxlc3RvbmVzQ3RybCcsXG4gICAgICAgIGRhdGE6IHsgfVxuICAgICAgfSk7XG4gIH1cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmFjdG9yeSgnTWlsZXN0b25lc1NlcnZpY2UnLCBNaWxlc3RvbmVzU2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiBNaWxlc3RvbmVzU2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHZhciBtb2RlbCA9IHNlcnZpY2VGYWN0b3J5KCdtaWxlc3RvbmVzJywge1xuICAgICAgYWN0aW9uczoge1xuICAgICAgICBmaW5hbGl6ZToge1xuICAgICAgICAgIG1ldGhvZDogJ1BPU1QnLFxuICAgICAgICAgIHVybDogJ2ZpbmFsaXplJ1xuICAgICAgICB9LFxuICAgICAgICB1cGRhdGVSZWxlYXNlOiB7XG4gICAgICAgICAgbWV0aG9kOiAnUE9TVCcsXG4gICAgICAgICAgdXJsOiAndXBkYXRlUmVsZWFzZSdcbiAgICAgICAgfVxuICAgICAgfSxcbiAgICAgIGluc3RhbmNlOiB7IH1cbiAgICB9KTtcblxuICAgIHJldHVybiBtb2RlbDtcbiAgfVxuXG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZhY3RvcnkoJ1ByaW9yaXRpZXNTZXJ2aWNlJywgUHJpb3JpdGllc1NlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gUHJpb3JpdGllc1NlcnZpY2Uoc2VydmljZUZhY3RvcnkpIHtcbiAgICB2YXIgbW9kZWwgPSBzZXJ2aWNlRmFjdG9yeSgncHJpb3JpdGllcycsIHtcbiAgICAgIGFjdGlvbnM6IHsgfSxcbiAgICAgIGluc3RhbmNlOiB7IH1cbiAgICB9KTtcblxuICAgIHJldHVybiBtb2RlbDtcbiAgfVxuXG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29udHJvbGxlcignUHJvamVjdHNDb250cm9sbGVyJywgUHJvamVjdHNDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIFByb2plY3RzQ29udHJvbGxlcigkY29udHJvbGxlcixcbiAgICBQcm9qZWN0c1NlcnZpY2UsXG4gICAgQXV0aCxcbiAgICBSb2xlc1NlcnZpY2UsXG4gICAgVXNlcnNTZXJ2aWNlLFxuICAgICRzdGF0ZSxcbiAgICAkZmlsdGVyLFxuICAgICRzdGF0ZVBhcmFtcyxcbiAgICAkd2luZG93KSB7XG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIC8vQXR0cmlidXRlcyBCbG9ja1xuXG4gICAgLy9GdW5jdGlvbnMgQmxvY2tcbiAgICB2bS5vbkFjdGl2YXRlID0gb25BY3RpdmF0ZTtcbiAgICB2bS5hcHBseUZpbHRlcnMgPSBhcHBseUZpbHRlcnM7XG4gICAgdm0uYmVmb3JlU2F2ZSA9IGJlZm9yZVNhdmU7XG4gICAgdm0uc2VhcmNoVXNlciA9IHNlYXJjaFVzZXI7XG4gICAgdm0uYWRkVXNlciA9IGFkZFVzZXI7XG4gICAgdm0ucmVtb3ZlVXNlciA9IHJlbW92ZVVzZXI7XG4gICAgdm0udmlld1Byb2plY3QgPSB2aWV3UHJvamVjdDtcblxuICAgIHZtLnJvbGVzID0ge307XG4gICAgdm0udXNlcnMgPSBbXTtcblxuICAgIGZ1bmN0aW9uIG9uQWN0aXZhdGUoKSB7XG4gICAgICB2bS5jdXJyZW50VXNlciA9IEF1dGguY3VycmVudFVzZXI7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMgPSB7IHVzZXJfaWQ6IHZtLmN1cnJlbnRVc2VyLmlkIH07XG4gICAgICBSb2xlc1NlcnZpY2UucXVlcnkoKS50aGVuKGZ1bmN0aW9uKHJlc3BvbnNlKSB7XG4gICAgICAgIHZtLnJvbGVzID0gcmVzcG9uc2U7XG4gICAgICAgIGlmICgkc3RhdGVQYXJhbXMub2JqID09PSAnZWRpdCcpIHtcbiAgICAgICAgICB2bS5jbGVhbkZvcm0oKTtcbiAgICAgICAgICB2bS52aWV3Rm9ybSA9IHRydWU7XG4gICAgICAgICAgdm0ucmVzb3VyY2UgPSAkc3RhdGVQYXJhbXMucmVzb3VyY2U7XG4gICAgICAgICAgdXNlcnNBcnJheSh2bS5yZXNvdXJjZSk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oJ3Byb2plY3QnKTtcbiAgICAgICAgfVxuICAgICAgfSk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gYXBwbHlGaWx0ZXJzKGRlZmF1bHRRdWVyeUZpbHRlcnMpIHtcbiAgICAgIHJldHVybiBhbmd1bGFyLmV4dGVuZChkZWZhdWx0UXVlcnlGaWx0ZXJzLCB2bS5xdWVyeWx0ZXJzKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBiZWZvcmVTYXZlKCkge1xuICAgICAgaWYgKCF2bS5yZXNvdXJjZS5vd25lcikge1xuICAgICAgICB2bS5yZXNvdXJjZS5vd25lciA9IEF1dGguY3VycmVudFVzZXIuaWQ7XG4gICAgICB9XG4gICAgICB2bS5yZXNvdXJjZS51c2VyX2lkID0gQXV0aC5jdXJyZW50VXNlci5pZDtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBzZWFyY2hVc2VyKCkge1xuICAgICAgcmV0dXJuIFVzZXJzU2VydmljZS5xdWVyeSh7IG5hbWU6IHZtLnVzZXJOYW1lIH0pO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGFkZFVzZXIodXNlcikge1xuICAgICAgaWYgKCF2bS5yZXNvdXJjZS51c2Vycykge1xuICAgICAgICB2bS5yZXNvdXJjZS51c2VycyA9IFtdO1xuICAgICAgfVxuICAgICAgaWYgKHVzZXIpIHtcbiAgICAgICAgdm0ucmVzb3VyY2UudXNlcnMucHVzaCh1c2VyKTtcbiAgICAgICAgdm0udXNlck5hbWUgPSAnJztcbiAgICAgIH1cbiAgICB9XG5cbiAgICBmdW5jdGlvbiByZW1vdmVVc2VyKGluZGV4KSB7XG4gICAgICB2bS5yZXNvdXJjZS51c2Vycy5zcGxpY2UoaW5kZXgsIDEpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGFwcGx5RmlsdGVycyhkZWZhdWx0UXVlcnlGaWx0ZXJzKSB7XG4gICAgICByZXR1cm4gYW5ndWxhci5leHRlbmQoZGVmYXVsdFF1ZXJ5RmlsdGVycywgdm0ucXVlcnlGaWx0ZXJzKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiB2aWV3UHJvamVjdCgpIHtcbiAgICAgICRzdGF0ZS5nbygnYXBwLmRhc2hib2FyZCcpO1xuICAgIH1cblxuICAgIHZtLmFmdGVyU2VhcmNoID0gZnVuY3Rpb24oKSB7XG4gICAgICBpZiAodm0ucmVzb3VyY2VzLmxlbmd0aCA+IDApIHtcbiAgICAgICAgdm0ucmVzb3VyY2VzLmZvckVhY2goZnVuY3Rpb24ocHJvamVjdCkge1xuICAgICAgICAgIHVzZXJzQXJyYXkocHJvamVjdCk7XG4gICAgICAgIH0pO1xuICAgICAgfVxuICAgIH1cblxuICAgIGZ1bmN0aW9uIHVzZXJzQXJyYXkocHJvamVjdCkge1xuICAgICAgcHJvamVjdC51c2VycyA9IFtdO1xuICAgICAgaWYgKHByb2plY3QuY2xpZW50X2lkKSB7XG4gICAgICAgIHByb2plY3QuY2xpZW50LnJvbGUgPSAkZmlsdGVyKCdmaWx0ZXInKSh2bS5yb2xlcywgeyBzbHVnOiAnY2xpZW50JyB9KVswXTtcbiAgICAgICAgcHJvamVjdC51c2Vycy5wdXNoKHByb2plY3QuY2xpZW50KTtcbiAgICAgIH1cbiAgICAgIGlmIChwcm9qZWN0LmRldl9pZCkge1xuICAgICAgICBwcm9qZWN0LmRldmVsb3Blci5yb2xlID0gJGZpbHRlcignZmlsdGVyJykodm0ucm9sZXMsIHsgc2x1ZzogJ2RldicgfSlbMF07XG4gICAgICAgIHByb2plY3QudXNlcnMucHVzaChwcm9qZWN0LmRldmVsb3Blcik7XG4gICAgICB9XG4gICAgICBpZiAocHJvamVjdC5zdGFrZWhvbGRlcl9pZCkge1xuICAgICAgICBwcm9qZWN0LnN0YWtlaG9sZGVyLnJvbGUgPSAkZmlsdGVyKCdmaWx0ZXInKSh2bS5yb2xlcywgeyBzbHVnOiAnc3Rha2Vob2xkZXInIH0pWzBdO1xuICAgICAgICBwcm9qZWN0LnVzZXJzLnB1c2gocHJvamVjdC5zdGFrZWhvbGRlcik7XG4gICAgICB9XG4gICAgfVxuXG4gICAgdm0uaGlzdG9yeUJhY2sgPSBmdW5jdGlvbigpIHtcbiAgICAgIGlmICgkc3RhdGVQYXJhbXMub2JqKSB7XG4gICAgICAgICR3aW5kb3cuaGlzdG9yeS5iYWNrKCk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICB2bS52aWV3Rm9ybSA9IGZhbHNlO1xuICAgICAgfVxuICAgIH1cblxuICAgIHZtLmFmdGVyU2F2ZSA9IGZ1bmN0aW9uKHJlc291cmNlKSB7XG4gICAgICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbSgncHJvamVjdCcsIHJlc291cmNlLmlkKTtcbiAgICAgICRzdGF0ZS5nbygnYXBwLmRhc2hib2FyZCcpO1xuICAgIH1cblxuICAgIC8vIGluc3RhbnRpYXRlIGJhc2UgY29udHJvbGxlclxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHsgdm06IHZtLCBtb2RlbFNlcnZpY2U6IFByb2plY3RzU2VydmljZSwgb3B0aW9uczogeyByZWRpcmVjdEFmdGVyU2F2ZTogZmFsc2UgfSB9KTtcbiAgfVxuXG59KSgpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKlxuICAgKiBBcnF1aXZvIGRlIGNvbmZpZ3VyYcOnw6NvIGNvbSBhcyByb3RhcyBlc3BlY8OtZmljYXMgZG8gcmVjdXJzbyBwcm9qZWN0XG4gICAqXG4gICAqIEBwYXJhbSB7YW55fSAkc3RhdGVQcm92aWRlclxuICAgKiBAcGFyYW0ge2FueX0gR2xvYmFsXG4gICAqL1xuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvdXRlcygkc3RhdGVQcm92aWRlciwgR2xvYmFsKSB7XG4gICAgJHN0YXRlUHJvdmlkZXJcbiAgICAgIC5zdGF0ZSgnYXBwLnByb2plY3RzJywge1xuICAgICAgICB1cmw6ICcvcHJvamVjdHMnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL3Byb2plY3RzL3Byb2plY3RzLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnUHJvamVjdHNDb250cm9sbGVyIGFzIHByb2plY3RzQ3RybCcsXG4gICAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiB0cnVlIH0sXG4gICAgICAgIHBhcmFtczogeyBvYmo6IG51bGwsIHJlc291cmNlOiBudWxsIH1cbiAgICAgIH0pO1xuICB9XG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZhY3RvcnkoJ1Byb2plY3RzU2VydmljZScsIFByb2plY3RzU2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiBQcm9qZWN0c1NlcnZpY2Uoc2VydmljZUZhY3RvcnkpIHtcbiAgICByZXR1cm4gc2VydmljZUZhY3RvcnkoJ3Byb2plY3RzJywge1xuICAgICAgYWN0aW9uczoge1xuICAgICAgICBmaW5hbGl6ZToge1xuICAgICAgICAgIG1ldGhvZDogJ1BPU1QnLFxuICAgICAgICAgIHVybDogJ2ZpbmFsaXplJ1xuICAgICAgICB9LFxuICAgICAgICB2ZXJpZnlSZWxlYXNlczoge1xuICAgICAgICAgIG1ldGhvZDogJ1BPU1QnLFxuICAgICAgICAgIHVybDogJ3ZlcmlmeVJlbGVhc2VzJ1xuICAgICAgICB9XG4gICAgICB9LFxuICAgICAgaW5zdGFuY2U6IHsgfVxuICAgIH0pO1xuICB9XG5cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb250cm9sbGVyKCdSZWxlYXNlc0NvbnRyb2xsZXInLCBSZWxlYXNlc0NvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gUmVsZWFzZXNDb250cm9sbGVyKCRjb250cm9sbGVyLFxuICAgIFJlbGVhc2VzU2VydmljZSxcbiAgICBNaWxlc3RvbmVzU2VydmljZSxcbiAgICBQcm9qZWN0c1NlcnZpY2UsXG4gICAgQXV0aCxcbiAgICBQclRvYXN0LFxuICAgIG1vbWVudCxcbiAgICAkbWREaWFsb2csXG4gICAgJHRyYW5zbGF0ZSkge1xuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICAvL0F0dHJpYnV0ZXMgQmxvY2tcbiAgICB2bS5hcHBseUZpbHRlcnMgPSBhcHBseUZpbHRlcnM7XG5cbiAgICAvL0Z1bmN0aW9ucyBCbG9ja1xuICAgIHZtLm9uQWN0aXZhdGUgPSBmdW5jdGlvbigpIHtcbiAgICAgIHZtLmN1cnJlbnRVc2VyID0gQXV0aC5jdXJyZW50VXNlcjtcbiAgICAgIHZtLnByb2plY3QgPSBsb2NhbFN0b3JhZ2UuZ2V0SXRlbSgncHJvamVjdCcpO1xuICAgICAgUHJvamVjdHNTZXJ2aWNlLnF1ZXJ5KHsgcHJvamVjdF9pZDogdm0ucHJvamVjdCB9KS50aGVuKGZ1bmN0aW9uKHJlc3BvbnNlKSB7XG4gICAgICAgIHZtLmFjdHVhbFByb2plY3QgPSByZXNwb25zZVswXTtcbiAgICAgIH0pO1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0geyBwcm9qZWN0X2lkOiB2bS5wcm9qZWN0IH07XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gYXBwbHlGaWx0ZXJzKGRlZmF1bHRRdWVyeUZpbHRlcnMpIHtcbiAgICAgIHJldHVybiBhbmd1bGFyLmV4dGVuZChkZWZhdWx0UXVlcnlGaWx0ZXJzLCB2bS5xdWVyeUZpbHRlcnMpO1xuICAgIH1cblxuICAgIHZtLmJlZm9yZVNhdmUgPSBmdW5jdGlvbigpIHtcbiAgICAgIHZtLnJlc291cmNlLnByb2plY3RfaWQgPSB2bS5wcm9qZWN0O1xuICAgIH1cblxuICAgIHZtLmJlZm9yZVJlbW92ZSA9IGZ1bmN0aW9uKCkge1xuICAgICAgdm0ucmVzb3VyY2UucHJvamVjdF9pZCA9IHZtLnByb2plY3Q7XG4gICAgfVxuXG4gICAgdm0udmlldyA9IGZ1bmN0aW9uIChyZXNvdXJjZSkge1xuICAgICAgdm0ucmVzb3VyY2UgPSByZXNvdXJjZTtcbiAgICAgIHZtLm9uVmlldyA9IHRydWU7XG4gICAgICB2bS52aWV3Rm9ybSA9IGZhbHNlO1xuICAgIH1cblxuICAgIHZtLmZpbmFsaXplID0gZnVuY3Rpb24ocmVsZWFzZSkge1xuICAgICAgdmFyIGNvbmZpcm0gPSAkbWREaWFsb2cuY29uZmlybSgpXG4gICAgICAgICAgLnRpdGxlKCdGaW5hbGl6YXIgUmVsZWFzZScpXG4gICAgICAgICAgLnRleHRDb250ZW50KCdUZW0gY2VydGV6YSBxdWUgZGVzZWphIGZpbmFsaXphciBhIHJlbGVhc2UgJyArIHJlbGVhc2UudGl0bGUgKyAnPycpXG4gICAgICAgICAgLm9rKCdTaW0nKVxuICAgICAgICAgIC5jYW5jZWwoJ07Do28nKTtcblxuICAgICAgJG1kRGlhbG9nLnNob3coY29uZmlybSkudGhlbihmdW5jdGlvbigpIHtcbiAgICAgICAgUmVsZWFzZXNTZXJ2aWNlLmZpbmFsaXplKHsgcHJvamVjdF9pZDogdm0ucHJvamVjdCwgcmVsZWFzZV9pZDogcmVsZWFzZS5pZCB9KS50aGVuKGZ1bmN0aW9uKCkge1xuICAgICAgICAgIFByVG9hc3Quc3VjY2VzcygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnJlbGVhc2VFbmRlZFN1Y2Nlc3MnKSk7XG4gICAgICAgICAgdm0uc2VhcmNoKCk7XG4gICAgICAgIH0sIGZ1bmN0aW9uKCkge1xuICAgICAgICAgIFByVG9hc3QuRXJyb3IoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5yZWxlYXNlRW5kZWRFcnJvcicpKTtcbiAgICAgICAgfSk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICB2bS5mb3JtYXREYXRlID0gZnVuY3Rpb24oZGF0ZSkge1xuICAgICAgcmV0dXJuIG1vbWVudChkYXRlKS5mb3JtYXQoJ0REL01NL1lZWVknKTtcbiAgICB9XG5cbiAgICB2bS5zZWFyY2hNaWxlc3RvbmUgPSBmdW5jdGlvbiAobWlsZXN0b25lVGVybSkge1xuICAgICAgcmV0dXJuIE1pbGVzdG9uZXNTZXJ2aWNlLnF1ZXJ5KHtcbiAgICAgICAgcmVsZWFzZVNlYXJjaDogdHJ1ZSxcbiAgICAgICAgcHJvamVjdF9pZDogdm0ucmVzb3VyY2UucHJvamVjdF9pZCxcbiAgICAgICAgdGl0bGU6IG1pbGVzdG9uZVRlcm1cbiAgICAgIH0pO1xuICAgIH1cblxuICAgIHZtLm9uTWlsZXN0b25lQ2hhbmdlID0gZnVuY3Rpb24oKSB7XG4gICAgICBpZiAodm0ubWlsZXN0b25lICE9PSBudWxsICYmIHZtLnJlc291cmNlLm1pbGVzdG9uZXMuZmluZEluZGV4KGkgPT4gaS5pZCA9PT0gdm0ubWlsZXN0b25lLmlkKSA9PT0gLTEpIHtcbiAgICAgICAgdm0ucmVzb3VyY2UubWlsZXN0b25lcy5wdXNoKHZtLm1pbGVzdG9uZSk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgdm0ucmVtb3ZlTWlsZXN0b25lID0gZnVuY3Rpb24obWlsZXN0b25lKSB7XG4gICAgICB2bS5yZXNvdXJjZS5taWxlc3RvbmVzLnNsaWNlKDApLmZvckVhY2goZnVuY3Rpb24oZWxlbWVudCkge1xuICAgICAgICBpZihlbGVtZW50LmlkID09PSBtaWxlc3RvbmUuaWQpIHtcbiAgICAgICAgICB2bS5yZXNvdXJjZS5taWxlc3RvbmVzLnNwbGljZSh2bS5yZXNvdXJjZS5taWxlc3RvbmVzLmluZGV4T2YoZWxlbWVudCksIDEpO1xuICAgICAgICB9XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICB2bS5zYXZlTWlsZXN0b25lcyA9IGZ1bmN0aW9uKCkge1xuICAgICAgTWlsZXN0b25lc1NlcnZpY2UudXBkYXRlUmVsZWFzZSh7cHJvamVjdF9pZDogdm0ucmVzb3VyY2UucHJvamVjdF9pZCwgcmVsZWFzZV9pZDogdm0ucmVzb3VyY2UuaWQsIG1pbGVzdG9uZXM6IHZtLnJlc291cmNlLm1pbGVzdG9uZXN9KS50aGVuKGZ1bmN0aW9uKCl7XG4gICAgICAgIFByVG9hc3Quc3VjY2VzcygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnNhdmVTdWNjZXNzJykpO1xuICAgICAgICB2bS52aWV3Rm9ybSA9IGZhbHNlO1xuICAgICAgICB2bS5vblZpZXcgPSBmYWxzZTtcbiAgICAgIH0sIGZ1bmN0aW9uKCkge1xuICAgICAgICBQclRvYXN0LmVycm9yKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMub3BlcmF0aW9uRXJyb3InKSk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICB2bS5lc3RpbWF0ZWRUaW1lID0gZnVuY3Rpb24gKG1pbGVzdG9uZSkge1xuICAgICAgbWlsZXN0b25lLmVzdGltYXRlZF90aW1lID0gMDtcbiAgICAgIGlmKG1pbGVzdG9uZS50YXNrcy5sZW5ndGggPiAwKSB7XG4gICAgICAgIG1pbGVzdG9uZS50YXNrcy5mb3JFYWNoKGZ1bmN0aW9uKHRhc2spIHtcbiAgICAgICAgICBtaWxlc3RvbmUuZXN0aW1hdGVkX3RpbWUgKz0gdGFzay5lc3RpbWF0ZWRfdGltZTtcbiAgICAgICAgfSk7XG4gICAgICB9XG4gICAgICByZXR1cm4gbWlsZXN0b25lLmVzdGltYXRlZF90aW1lIC8gODtcbiAgICB9XG5cbiAgICAvLyBpbnN0YW50aWF0ZSBiYXNlIGNvbnRyb2xsZXJcbiAgICAkY29udHJvbGxlcignQ1JVRENvbnRyb2xsZXInLCB7IHZtOiB2bSwgbW9kZWxTZXJ2aWNlOiBSZWxlYXNlc1NlcnZpY2UsIG9wdGlvbnM6IHsgfSB9KTtcblxuICB9XG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqXG4gICAqIEFycXVpdm8gZGUgY29uZmlndXJhw6fDo28gY29tIGFzIHJvdGFzIGVzcGVjw61maWNhcyBkbyByZWN1cnNvIHJlbGVhc2VzXG4gICAqXG4gICAqIEBwYXJhbSB7b2JqZWN0fSAkc3RhdGVQcm92aWRlclxuICAgKiBAcGFyYW0ge29iamVjdH0gR2xvYmFsXG4gICAqL1xuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvdXRlcygkc3RhdGVQcm92aWRlciwgR2xvYmFsKSB7XG4gICAgJHN0YXRlUHJvdmlkZXJcbiAgICAgIC5zdGF0ZSgnYXBwLnJlbGVhc2VzJywge1xuICAgICAgICB1cmw6ICcvcmVsZWFzZXMnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL3JlbGVhc2VzL3JlbGVhc2VzLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnUmVsZWFzZXNDb250cm9sbGVyIGFzIHJlbGVhc2VzQ3RybCcsXG4gICAgICAgIGRhdGE6IHsgfVxuICAgICAgfSk7XG4gIH1cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmFjdG9yeSgnUmVsZWFzZXNTZXJ2aWNlJywgUmVsZWFzZXNTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIFJlbGVhc2VzU2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHZhciBtb2RlbCA9IHNlcnZpY2VGYWN0b3J5KCdyZWxlYXNlcycsIHtcbiAgICAgIGFjdGlvbnM6IHtcbiAgICAgICAgZmluYWxpemU6IHtcbiAgICAgICAgICBtZXRob2Q6ICdQT1NUJyxcbiAgICAgICAgICB1cmw6ICdmaW5hbGl6ZSdcbiAgICAgICAgfVxuICAgICAgfSxcbiAgICAgIGluc3RhbmNlOiB7IH1cbiAgICB9KTtcblxuICAgIHJldHVybiBtb2RlbDtcbiAgfVxuXG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmlsdGVyKCdyb2xlc1N0cicsIHJvbGVzU3RyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvbGVzU3RyKGxvZGFzaCkge1xuICAgIC8qKlxuICAgICAqIEBwYXJhbSB7YXJyYXl9IHJvbGVzIGxpc3RhIGRlIHBlcmZpc1xuICAgICAqIEByZXR1cm4ge3N0cmluZ30gcGVyZmlzIHNlcGFyYWRvcyBwb3IgJywgJyAgXG4gICAgICovXG4gICAgcmV0dXJuIGZ1bmN0aW9uKHJvbGVzKSB7XG4gICAgICByZXR1cm4gbG9kYXNoLm1hcChyb2xlcywgJ3NsdWcnKS5qb2luKCcsICcpO1xuICAgIH07XG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5mYWN0b3J5KCdSb2xlc1NlcnZpY2UnLCBSb2xlc1NlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gUm9sZXNTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCdyb2xlcycpO1xuICB9XG5cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmFjdG9yeSgnU3RhdHVzU2VydmljZScsIFN0YXR1c1NlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gU3RhdHVzU2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHZhciBtb2RlbCA9IHNlcnZpY2VGYWN0b3J5KCdzdGF0dXMnLCB7XG4gICAgICBhY3Rpb25zOiB7IH0sXG4gICAgICBpbnN0YW5jZTogeyB9XG4gICAgfSk7XG5cbiAgICByZXR1cm4gbW9kZWw7XG4gIH1cblxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5mYWN0b3J5KCdTdXBwb3J0U2VydmljZScsIFN1cHBvcnRTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIFN1cHBvcnRTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCdzdXBwb3J0Jywge1xuICAgICAgYWN0aW9uczoge1xuICAgICAgLyoqXG4gICAgICAgKiBQZWdhIGFzIHRyYWR1w6fDtWVzIHF1ZSBlc3TDo28gbm8gc2Vydmlkb3JcbiAgICAgICAqXG4gICAgICAgKiBAcmV0dXJucyB7cHJvbWlzZX0gVW1hIHByb21pc2UgY29tIG8gcmVzdWx0YWRvIGRvIGNoYW1hZGEgbm8gYmFja2VuZFxuICAgICAgICovXG4gICAgICAgIGxhbmdzOiB7XG4gICAgICAgICAgbWV0aG9kOiAnR0VUJyxcbiAgICAgICAgICB1cmw6ICdsYW5ncycsXG4gICAgICAgICAgd3JhcDogZmFsc2UsXG4gICAgICAgICAgY2FjaGU6IHRydWVcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pO1xuICB9XG5cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmFjdG9yeSgnVGFza0NvbW1lbnRzU2VydmljZScsIFRhc2tDb21tZW50c1NlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gVGFza0NvbW1lbnRzU2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHZhciBtb2RlbCA9IHNlcnZpY2VGYWN0b3J5KCd0YXNrLWNvbW1lbnRzJywge1xuICAgICAgYWN0aW9uczoge1xuICAgICAgICBzYXZlVGFza0NvbW1lbnQ6IHtcbiAgICAgICAgICBtZXRob2Q6ICdQT1NUJyxcbiAgICAgICAgICB1cmw6ICdzYXZlVGFza0NvbW1lbnQnXG4gICAgICAgIH0sXG4gICAgICAgIHJlbW92ZVRhc2tDb21tZW50OiB7XG4gICAgICAgICAgbWV0aG9kOiAnUE9TVCcsXG4gICAgICAgICAgdXJsOiAncmVtb3ZlVGFza0NvbW1lbnQnXG4gICAgICAgIH1cbiAgICAgIH0sXG4gICAgICBpbnN0YW5jZTogeyB9XG4gICAgfSk7XG5cbiAgICByZXR1cm4gbW9kZWw7XG4gIH1cblxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZpbHRlcignZWxhcHNlZCcsIGZ1bmN0aW9uKCkge1xuICAgICAgcmV0dXJuIGZ1bmN0aW9uKGRhdGUpIHtcbiAgICAgICAgaWYgKCFkYXRlKSByZXR1cm47XG4gICAgICAgIHZhciB0aW1lID0gRGF0ZS5wYXJzZShkYXRlKSxcbiAgICAgICAgICB0aW1lTm93ID0gbmV3IERhdGUoKS5nZXRUaW1lKCksXG4gICAgICAgICAgZGlmZmVyZW5jZSA9IHRpbWVOb3cgLSB0aW1lLFxuICAgICAgICAgIHNlY29uZHMgPSBNYXRoLmZsb29yKGRpZmZlcmVuY2UgLyAxMDAwKSxcbiAgICAgICAgICBtaW51dGVzID0gTWF0aC5mbG9vcihzZWNvbmRzIC8gNjApLFxuICAgICAgICAgIGhvdXJzID0gTWF0aC5mbG9vcihtaW51dGVzIC8gNjApLFxuICAgICAgICAgIGRheXMgPSBNYXRoLmZsb29yKGhvdXJzIC8gMjQpLFxuICAgICAgICAgIG1vbnRocyA9IE1hdGguZmxvb3IoZGF5cyAvIDMwKTtcblxuICAgICAgICBpZiAobW9udGhzID4gMSkge1xuICAgICAgICAgIHJldHVybiBtb250aHMgKyAnIG1lc2VzIGF0csOhcyc7XG4gICAgICAgIH0gZWxzZSBpZiAobW9udGhzID09PSAxKSB7XG4gICAgICAgICAgcmV0dXJuICcxIG3DqnMgYXRyw6FzJztcbiAgICAgICAgfSBlbHNlIGlmIChkYXlzID4gMSkge1xuICAgICAgICAgIHJldHVybiBkYXlzICsgJyBkaWFzIGF0csOhcyc7XG4gICAgICAgIH0gZWxzZSBpZiAoZGF5cyA9PT0gMSkge1xuICAgICAgICAgIHJldHVybiAnMSBkaWEgYXRyw6FzJ1xuICAgICAgICB9IGVsc2UgaWYgKGhvdXJzID4gMSkge1xuICAgICAgICAgIHJldHVybiBob3VycyArICcgaG9yYXMgYXRyw6FzJztcbiAgICAgICAgfSBlbHNlIGlmIChob3VycyA9PT0gMSkge1xuICAgICAgICAgIHJldHVybiAndW1hIGhvcmEgYXRyw6FzJztcbiAgICAgICAgfSBlbHNlIGlmIChtaW51dGVzID4gMSkge1xuICAgICAgICAgIHJldHVybiBtaW51dGVzICsgJyBtaW51dG9zIGF0csOhcyc7XG4gICAgICAgIH0gZWxzZSBpZiAobWludXRlcyA9PT0gMSkge1xuICAgICAgICAgIHJldHVybiAndW0gbWludXRvIGF0csOhcyc7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgcmV0dXJuICdow6EgcG91Y29zIHNlZ3VuZG9zJztcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pXG4gICAgLmNvbnRyb2xsZXIoJ1Rhc2tzQ29udHJvbGxlcicsIFRhc2tzQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBUYXNrc0NvbnRyb2xsZXIoJGNvbnRyb2xsZXIsXG4gICAgVGFza3NTZXJ2aWNlLFxuICAgIFN0YXR1c1NlcnZpY2UsXG4gICAgUHJpb3JpdGllc1NlcnZpY2UsXG4gICAgVHlwZXNTZXJ2aWNlLFxuICAgIFRhc2tDb21tZW50c1NlcnZpY2UsXG4gICAgUHJvamVjdHNTZXJ2aWNlLFxuICAgIG1vbWVudCxcbiAgICBBdXRoLFxuICAgIFByVG9hc3QsXG4gICAgJHRyYW5zbGF0ZSxcbiAgICAkZmlsdGVyLFxuICAgIEdsb2JhbCkge1xuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICAvL0F0dHJpYnV0ZXMgQmxvY2tcblxuICAgIC8vRnVuY3Rpb25zIEJsb2NrXG4gICAgdm0ub25BY3RpdmF0ZSA9IG9uQWN0aXZhdGU7XG4gICAgdm0uYXBwbHlGaWx0ZXJzID0gYXBwbHlGaWx0ZXJzO1xuICAgIHZtLmJlZm9yZVNhdmUgPSBiZWZvcmVTYXZlO1xuICAgIHZtLmJlZm9yZVJlbW92ZSA9IGJlZm9yZVJlbW92ZTtcblxuICAgIGZ1bmN0aW9uIG9uQWN0aXZhdGUoKSB7XG4gICAgICB2bS5jdXJyZW50VXNlciA9IEF1dGguY3VycmVudFVzZXI7XG4gICAgICB2bS5pbWFnZVBhdGggPSBHbG9iYWwuaW1hZ2VQYXRoICsgJy9ub19hdmF0YXIuZ2lmJztcbiAgICAgIHZtLnByb2plY3QgPSBsb2NhbFN0b3JhZ2UuZ2V0SXRlbSgncHJvamVjdCcpO1xuICAgICAgUHJvamVjdHNTZXJ2aWNlLnF1ZXJ5KHsgcHJvamVjdF9pZDogdm0ucHJvamVjdCB9KS50aGVuKGZ1bmN0aW9uKHJlc3BvbnNlKSB7XG4gICAgICAgIHZtLmFjdHVhbFByb2plY3QgPSByZXNwb25zZVswXTtcbiAgICAgIH0pO1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0geyBwcm9qZWN0X2lkOiB2bS5wcm9qZWN0IH07XG5cbiAgICAgIFN0YXR1c1NlcnZpY2UucXVlcnkoKS50aGVuKGZ1bmN0aW9uKHJlc3BvbnNlKSB7XG4gICAgICAgIHZtLnN0YXR1cyA9IHJlc3BvbnNlO1xuICAgICAgfSk7XG5cbiAgICAgIFByaW9yaXRpZXNTZXJ2aWNlLnF1ZXJ5KCkudGhlbihmdW5jdGlvbihyZXNwb25zZSkge1xuICAgICAgICB2bS5wcmlvcml0aWVzID0gcmVzcG9uc2U7XG4gICAgICB9KTtcblxuICAgICAgVHlwZXNTZXJ2aWNlLnF1ZXJ5KCkudGhlbihmdW5jdGlvbihyZXNwb25zZSkge1xuICAgICAgICB2bS50eXBlcyA9IHJlc3BvbnNlO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gYXBwbHlGaWx0ZXJzKGRlZmF1bHRRdWVyeUZpbHRlcnMpIHtcbiAgICAgIHJldHVybiBhbmd1bGFyLmV4dGVuZChkZWZhdWx0UXVlcnlGaWx0ZXJzLCB2bS5xdWVyeUZpbHRlcnMpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGJlZm9yZVNhdmUoKSB7XG4gICAgICB2bS5yZXNvdXJjZS5wcm9qZWN0X2lkID0gdm0ucHJvamVjdDtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBiZWZvcmVSZW1vdmUoKSB7XG4gICAgICB2bS5yZXNvdXJjZS5wcm9qZWN0X2lkID0gdm0ucHJvamVjdDtcbiAgICB9XG5cbiAgICB2bS52aWV3ID0gZnVuY3Rpb24gKHJlc291cmNlKSB7XG4gICAgICB2bS5yZXNvdXJjZSA9IHJlc291cmNlO1xuICAgICAgdm0ub25WaWV3ID0gdHJ1ZTtcbiAgICAgIHZtLnZpZXdGb3JtID0gZmFsc2U7XG4gICAgfVxuXG4gICAgdm0uc2F2ZUNvbW1lbnQgPSBmdW5jdGlvbihjb21tZW50KSB7XG4gICAgICB2YXIgZGVzY3JpcHRpb24gPSAnJztcbiAgICAgIHZhciBjb21tZW50X2lkID0gbnVsbDtcblxuICAgICAgaWYgKGNvbW1lbnQpIHtcbiAgICAgICAgZGVzY3JpcHRpb24gPSB2bS5hbnN3ZXJcbiAgICAgICAgY29tbWVudF9pZCA9IGNvbW1lbnQuaWQ7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBkZXNjcmlwdGlvbiA9IHZtLmNvbW1lbnQ7XG4gICAgICB9XG4gICAgICBUYXNrQ29tbWVudHNTZXJ2aWNlLnNhdmVUYXNrQ29tbWVudCh7IHByb2plY3RfaWQ6IHZtLnByb2plY3QsIHRhc2tfaWQ6IHZtLnJlc291cmNlLmlkLCBjb21tZW50X3RleHQ6IGRlc2NyaXB0aW9uLCBjb21tZW50X2lkOiBjb21tZW50X2lkIH0pLnRoZW4oZnVuY3Rpb24oKSB7XG4gICAgICAgIHZtLmNvbW1lbnQgPSAnJztcbiAgICAgICAgdm0uYW5zd2VyID0gJyc7XG4gICAgICAgIHZtLnNlYXJjaCgpO1xuICAgICAgICBQclRvYXN0LnN1Y2Nlc3MoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5zYXZlU3VjY2VzcycpKTtcbiAgICAgIH0sIGZ1bmN0aW9uKCkge1xuICAgICAgICBQclRvYXN0LmVycm9yKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMub3BlcmF0aW9uRXJyb3InKSk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICB2bS5yZW1vdmVDb21tZW50ID0gZnVuY3Rpb24oY29tbWVudCkge1xuICAgICAgVGFza0NvbW1lbnRzU2VydmljZS5yZW1vdmVUYXNrQ29tbWVudCh7IGNvbW1lbnRfaWQ6IGNvbW1lbnQuaWQgfSkudGhlbihmdW5jdGlvbigpIHtcbiAgICAgICAgdm0uc2VhcmNoKCk7XG4gICAgICAgIFByVG9hc3Quc3VjY2VzcygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnJlbW92ZVN1Y2Nlc3MnKSk7XG4gICAgICB9LCBmdW5jdGlvbigpIHtcbiAgICAgICAgUHJUb2FzdC5lcnJvcigkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLm9wZXJhdGlvbkVycm9yJykpO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgdm0uYWZ0ZXJTZWFyY2ggPSBmdW5jdGlvbigpIHtcbiAgICAgIGlmICh2bS5yZXNvdXJjZS5pZCkge1xuICAgICAgICB2bS5yZXNvdXJjZSA9ICRmaWx0ZXIoJ2ZpbHRlcicpKHZtLnJlc291cmNlcywgeyBpZDogdm0ucmVzb3VyY2UuaWQgfSlbMF07XG4gICAgICB9XG4gICAgfVxuXG4gICAgdm0uZml4RGF0ZSA9IGZ1bmN0aW9uKGRhdGVTdHJpbmcpIHtcbiAgICAgIHJldHVybiBtb21lbnQoZGF0ZVN0cmluZyk7XG4gICAgfVxuXG4gICAgLy8gaW5zdGFudGlhdGUgYmFzZSBjb250cm9sbGVyXG4gICAgJGNvbnRyb2xsZXIoJ0NSVURDb250cm9sbGVyJywgeyB2bTogdm0sIG1vZGVsU2VydmljZTogVGFza3NTZXJ2aWNlLCBvcHRpb25zOiB7IHNraXBQYWdpbmF0aW9uOiB0cnVlIH0gfSk7XG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb25maWcocm91dGVzKTtcblxuICAvKipcbiAgICogQXJxdWl2byBkZSBjb25maWd1cmHDp8OjbyBjb20gYXMgcm90YXMgZXNwZWPDrWZpY2FzIGRvIHJlY3Vyc28gcHJvamVjdFxuICAgKlxuICAgKiBAcGFyYW0ge2FueX0gJHN0YXRlUHJvdmlkZXJcbiAgICogQHBhcmFtIHthbnl9IEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyXG4gICAgICAuc3RhdGUoJ2FwcC50YXNrcycsIHtcbiAgICAgICAgdXJsOiAnL3Rhc2tzJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy90YXNrcy90YXNrcy5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ1Rhc2tzQ29udHJvbGxlciBhcyB0YXNrc0N0cmwnLFxuICAgICAgICBkYXRhOiB7IG5lZWRBdXRoZW50aWNhdGlvbjogdHJ1ZX1cbiAgICAgIH0pO1xuICB9XG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZhY3RvcnkoJ1Rhc2tzU2VydmljZScsIFRhc2tzU2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiBUYXNrc1NlcnZpY2Uoc2VydmljZUZhY3RvcnkpIHtcbiAgICByZXR1cm4gc2VydmljZUZhY3RvcnkoJ3Rhc2tzJywge1xuICAgICAgYWN0aW9uczoge1xuICAgICAgICB1cGRhdGVNaWxlc3RvbmU6IHtcbiAgICAgICAgICBtZXRob2Q6ICdQT1NUJyxcbiAgICAgICAgICB1cmw6ICd1cGRhdGVNaWxlc3RvbmUnXG4gICAgICAgIH0sXG4gICAgICAgIHVwZGF0ZVRhc2tCeUthbmJhbjoge1xuICAgICAgICAgIG1ldGhvZDogJ1BPU1QnLFxuICAgICAgICAgIHVybDogJ3VwZGF0ZVRhc2tCeUthbmJhbidcbiAgICAgICAgfVxuICAgICAgfSxcbiAgICAgIGluc3RhbmNlOiB7IH1cbiAgICB9KTtcbiAgfVxuXG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZhY3RvcnkoJ1R5cGVzU2VydmljZScsIFR5cGVzU2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiBUeXBlc1NlcnZpY2Uoc2VydmljZUZhY3RvcnkpIHtcbiAgICB2YXIgbW9kZWwgPSBzZXJ2aWNlRmFjdG9yeSgndHlwZXMnLCB7XG4gICAgICBhY3Rpb25zOiB7IH0sXG4gICAgICBpbnN0YW5jZTogeyB9XG4gICAgfSk7XG5cbiAgICByZXR1cm4gbW9kZWw7XG4gIH1cblxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnRyb2xsZXIoJ1Byb2ZpbGVDb250cm9sbGVyJywgUHJvZmlsZUNvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gUHJvZmlsZUNvbnRyb2xsZXIoVXNlcnNTZXJ2aWNlLCBBdXRoLCBQclRvYXN0LCAkdHJhbnNsYXRlLCAkd2luZG93LCBtb21lbnQpIHtcbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0udXBkYXRlID0gdXBkYXRlO1xuICAgIHZtLmhpc3RvcnlCYWNrID0gaGlzdG9yeUJhY2s7XG5cbiAgICBhY3RpdmF0ZSgpO1xuXG4gICAgZnVuY3Rpb24gYWN0aXZhdGUoKSB7XG4gICAgICB2bS51c2VyID0gYW5ndWxhci5jb3B5KEF1dGguY3VycmVudFVzZXIpO1xuICAgICAgaWYgKHZtLnVzZXIuYmlydGhkYXkpIHtcbiAgICAgICAgdm0udXNlci5iaXJ0aGRheSA9IG1vbWVudCh2bS51c2VyLmJpcnRoZGF5KS5mb3JtYXQoJ0REL01NL1lZWVknKTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICBmdW5jdGlvbiB1cGRhdGUoKSB7XG4gICAgICBpZiAodm0udXNlci5iaXJ0aGRheSkge1xuICAgICAgICB2bS51c2VyLmJpcnRoZGF5ID0gbW9tZW50KHZtLnVzZXIuYmlydGhkYXkpO1xuICAgICAgfVxuICAgICAgVXNlcnNTZXJ2aWNlLnVwZGF0ZVByb2ZpbGUodm0udXNlcikudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgLy9hdHVhbGl6YSBvIHVzdcOhcmlvIGNvcnJlbnRlIGNvbSBhcyBub3ZhcyBpbmZvcm1hw6fDtWVzXG4gICAgICAgIEF1dGgudXBkYXRlQ3VycmVudFVzZXIocmVzcG9uc2UpO1xuICAgICAgICBQclRvYXN0LnN1Y2Nlc3MoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5zYXZlU3VjY2VzcycpKTtcbiAgICAgICAgaGlzdG9yeUJhY2soKTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGhpc3RvcnlCYWNrKCkge1xuICAgICAgJHdpbmRvdy5oaXN0b3J5LmJhY2soKTtcbiAgICB9XG5cbiAgfVxuXG59KSgpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29udHJvbGxlcignVXNlcnNDb250cm9sbGVyJywgVXNlcnNDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIFVzZXJzQ29udHJvbGxlcigkY29udHJvbGxlciwgVXNlcnNTZXJ2aWNlLCBQclRvYXN0LCAkbWREaWFsb2csICR0cmFuc2xhdGUpIHtcblxuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICB2bS5vbkFjdGl2YXRlID0gb25BY3RpdmF0ZTtcbiAgICAvLyBpbnN0YW50aWF0ZSBiYXNlIGNvbnRyb2xsZXJcbiAgICAkY29udHJvbGxlcignQ1JVRENvbnRyb2xsZXInLCB7IHZtOiB2bSwgbW9kZWxTZXJ2aWNlOiBVc2Vyc1NlcnZpY2UsIG9wdGlvbnM6IHt9IH0pO1xuXG4gICAgZnVuY3Rpb24gb25BY3RpdmF0ZSgpIHtcbiAgICAgIHZtLnF1ZXJ5RmlsdGVycyA9IHt9O1xuICAgIH1cblxuICAgIHZtLmhpZGVEaWFsb2cgPSBmdW5jdGlvbigpIHtcbiAgICAgICRtZERpYWxvZy5oaWRlKCk7XG4gICAgfVxuXG4gICAgdm0uc2F2ZU5ld1VzZXIgPSBmdW5jdGlvbigpIHtcbiAgICAgIHZtLnJlc291cmNlLiRzYXZlKCkudGhlbihmdW5jdGlvbiAocmVzb3VyY2UpIHtcbiAgICAgICAgdm0ucmVzb3VyY2UgPSByZXNvdXJjZTtcbiAgICAgICAgUHJUb2FzdC5zdWNjZXNzKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMuc3VjY2Vzc1NpZ25VcCcpKTtcbiAgICAgICAgJG1kRGlhbG9nLmhpZGUoKTtcbiAgICAgIH0pO1xuICAgIH1cbiAgfVxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb25maWcocm91dGVzKTtcblxuICAvKipcbiAgICogQXJxdWl2byBkZSBjb25maWd1cmHDp8OjbyBjb20gYXMgcm90YXMgZXNwZWPDrWZpY2FzIGRvIHJlY3Vyc28gdXNlclxuICAgKlxuICAgKiBAcGFyYW0ge2FueX0gJHN0YXRlUHJvdmlkZXJcbiAgICogQHBhcmFtIHthbnl9IEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyXG4gICAgICAuc3RhdGUoJ2FwcC51c2VyJywge1xuICAgICAgICB1cmw6ICcvdXN1YXJpbycsXG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvdXNlcnMvdXNlcnMuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdVc2Vyc0NvbnRyb2xsZXIgYXMgdXNlcnNDdHJsJyxcbiAgICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IHRydWUsIG5lZWRQcm9maWxlOiBbJ2FkbWluJ10gfVxuICAgICAgfSlcbiAgICAgIC5zdGF0ZSgnYXBwLnVzZXItcHJvZmlsZScsIHtcbiAgICAgICAgdXJsOiAnL3VzdWFyaW8vcGVyZmlsJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy91c2Vycy9wcm9maWxlLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnUHJvZmlsZUNvbnRyb2xsZXIgYXMgcHJvZmlsZUN0cmwnLFxuICAgICAgICBkYXRhOiB7IG5lZWRBdXRoZW50aWNhdGlvbjogdHJ1ZSB9XG4gICAgICB9KTtcblxuICB9XG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZhY3RvcnkoJ1VzZXJzU2VydmljZScsIFVzZXJzU2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBVc2Vyc1NlcnZpY2UobG9kYXNoLCBHbG9iYWwsIHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCd1c2VycycsIHtcbiAgICAgIC8vcXVhbmRvIGluc3RhbmNpYSB1bSB1c3XDoXJpbyBzZW0gcGFzc2FyIHBhcmFtZXRybyxcbiAgICAgIC8vbyBtZXNtbyB2YWkgdGVyIG9zIHZhbG9yZXMgZGVmYXVsdHMgYWJhaXhvXG4gICAgICBkZWZhdWx0czoge1xuICAgICAgICByb2xlczogW11cbiAgICAgIH0sXG5cbiAgICAgIGFjdGlvbnM6IHtcbiAgICAgICAgLyoqXG4gICAgICAgICAqIFNlcnZpw6dvIHF1ZSBhdHVhbGl6YSBvcyBkYWRvcyBkbyBwZXJmaWwgZG8gdXN1w6FyaW8gbG9nYWRvXG4gICAgICAgICAqXG4gICAgICAgICAqIEBwYXJhbSB7b2JqZWN0fSBhdHRyaWJ1dGVzXG4gICAgICAgICAqIEByZXR1cm5zIHtwcm9taXNlfSBVbWEgcHJvbWlzZSBjb20gbyByZXN1bHRhZG8gZG8gY2hhbWFkYSBubyBiYWNrZW5kXG4gICAgICAgICAqL1xuICAgICAgICB1cGRhdGVQcm9maWxlOiB7XG4gICAgICAgICAgbWV0aG9kOiAnUFVUJyxcbiAgICAgICAgICB1cmw6IEdsb2JhbC5hcGlQYXRoICsgJy9wcm9maWxlJyxcbiAgICAgICAgICBvdmVycmlkZTogdHJ1ZSxcbiAgICAgICAgICB3cmFwOiBmYWxzZVxuICAgICAgICB9XG4gICAgICB9LFxuXG4gICAgICBpbnN0YW5jZToge1xuICAgICAgICAvKipcbiAgICAgICAgICogVmVyaWZpY2Egc2UgbyB1c3XDoXJpbyB0ZW0gb3MgcGVyZmlzIGluZm9ybWFkb3MuXG4gICAgICAgICAqXG4gICAgICAgICAqIEBwYXJhbSB7YW55fSByb2xlcyBwZXJmaXMgYSBzZXJlbSB2ZXJpZmljYWRvc1xuICAgICAgICAgKiBAcGFyYW0ge2Jvb2xlYW59IGFsbCBmbGFnIHBhcmEgaW5kaWNhciBzZSB2YWkgY2hlZ2FyIHRvZG9zIG9zIHBlcmZpcyBvdSBzb21lbnRlIHVtIGRlbGVzXG4gICAgICAgICAqIEByZXR1cm5zIHtib29sZWFufVxuICAgICAgICAgKi9cbiAgICAgICAgaGFzUHJvZmlsZTogZnVuY3Rpb24ocm9sZXMsIGFsbCkge1xuICAgICAgICAgIHJvbGVzID0gYW5ndWxhci5pc0FycmF5KHJvbGVzKSA/IHJvbGVzIDogW3JvbGVzXTtcblxuICAgICAgICAgIHZhciB1c2VyUm9sZXMgPSBsb2Rhc2gubWFwKHRoaXMucm9sZXMsICdzbHVnJyk7XG5cbiAgICAgICAgICBpZiAoYWxsKSB7XG4gICAgICAgICAgICByZXR1cm4gbG9kYXNoLmludGVyc2VjdGlvbih1c2VyUm9sZXMsIHJvbGVzKS5sZW5ndGggPT09IHJvbGVzLmxlbmd0aDtcbiAgICAgICAgICB9IGVsc2UgeyAvL3JldHVybiB0aGUgbGVuZ3RoIGJlY2F1c2UgMCBpcyBmYWxzZSBpbiBqc1xuICAgICAgICAgICAgcmV0dXJuIGxvZGFzaC5pbnRlcnNlY3Rpb24odXNlclJvbGVzLCByb2xlcykubGVuZ3RoO1xuICAgICAgICAgIH1cbiAgICAgICAgfSxcblxuICAgICAgICAvKipcbiAgICAgICAgICogVmVyaWZpY2Egc2UgbyB1c3XDoXJpbyB0ZW0gbyBwZXJmaWwgYWRtaW4uXG4gICAgICAgICAqXG4gICAgICAgICAqIEByZXR1cm5zIHtib29sZWFufVxuICAgICAgICAgKi9cbiAgICAgICAgaXNBZG1pbjogZnVuY3Rpb24oKSB7XG4gICAgICAgICAgcmV0dXJuIHRoaXMuaGFzUHJvZmlsZSgnYWRtaW4nKTtcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pO1xuICB9XG5cbn0oKSk7XG4iLCIvL3Rva2VuIGNhY2I5MTIzNTg3M2E4YzQ4NzVkMjM1NzhhYzlmMzI2ZWY4OTRiNjZcbi8vIE9BdHV0aCBodHRwczovL2dpdGh1Yi5jb20vbG9naW4vb2F1dGgvYXV0aG9yaXplP2NsaWVudF9pZD04Mjk0NjhlN2ZkZWU3OTQ0NWJhNiZzY29wZT11c2VyLHB1YmxpY19yZXBvJnJlZGlyZWN0X3VyaT1odHRwOi8vMC4wLjAuMDo1MDAwLyMhL2FwcC92Y3NcblxuKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5maWx0ZXIoJ2J5dGVzJywgZnVuY3Rpb24oKSB7XG4gICAgICByZXR1cm4gZnVuY3Rpb24oYnl0ZXMsIHByZWNpc2lvbikge1xuICAgICAgICBpZiAoaXNOYU4ocGFyc2VGbG9hdChieXRlcykpIHx8ICFpc0Zpbml0ZShieXRlcykpIHJldHVybiAnLSc7XG4gICAgICAgIGlmICh0eXBlb2YgcHJlY2lzaW9uID09PSAndW5kZWZpbmVkJykgcHJlY2lzaW9uID0gMTtcbiAgICAgICAgdmFyIHVuaXRzID0gWydieXRlcycsICdrQicsICdNQicsICdHQicsICdUQicsICdQQiddLFxuICAgICAgICAgIG51bWJlciA9IE1hdGguZmxvb3IoTWF0aC5sb2coYnl0ZXMpIC8gTWF0aC5sb2coMTAyNCkpO1xuXG4gICAgICAgIHJldHVybiAoYnl0ZXMgLyBNYXRoLnBvdygxMDI0LCBNYXRoLmZsb29yKG51bWJlcikpKS50b0ZpeGVkKHByZWNpc2lvbikgKyAgJyAnICsgdW5pdHNbbnVtYmVyXTtcbiAgICAgIH1cbiAgICB9KVxuICAgIC5jb250cm9sbGVyKCdWY3NDb250cm9sbGVyJywgVmNzQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBWY3NDb250cm9sbGVyKCRjb250cm9sbGVyLCBWY3NTZXJ2aWNlLCAkd2luZG93LCBQcm9qZWN0c1NlcnZpY2UsIFByVG9hc3QsICR0cmFuc2xhdGUpIHtcbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0uaW5kZXggPSAwO1xuICAgIHZtLnBhdGhzID0gW107XG5cbiAgICAvL0F0dHJpYnV0ZXMgQmxvY2tcblxuICAgIC8vRnVuY3Rpb25zIEJsb2NrXG4gICAgdm0ub25BY3RpdmF0ZSA9ICBmdW5jdGlvbigpIHtcbiAgICAgIHRvZ2dsZVNwbGFzaFNjcmVlbigpO1xuICAgICAgUHJvamVjdHNTZXJ2aWNlLnF1ZXJ5KHsgcHJvamVjdF9pZDogbG9jYWxTdG9yYWdlLmdldEl0ZW0oJ3Byb2plY3QnKSB9KS50aGVuKGZ1bmN0aW9uKHJlc3BvbnNlKSB7XG4gICAgICAgIHZtLnVzZXJuYW1lID0gcmVzcG9uc2VbMF0udXNlcm5hbWVfZ2l0aHViO1xuICAgICAgICB2bS5yZXBvID0gcmVzcG9uc2VbMF0ucmVwb19naXRodWI7XG4gICAgICAgIGlmICh2bS51c2VybmFtZSAmJiB2bS5yZXBvKSB7XG4gICAgICAgICAgdm0ucXVlcnlGaWx0ZXJzID0ge1xuICAgICAgICAgICAgdXNlcm5hbWU6IHZtLnVzZXJuYW1lLFxuICAgICAgICAgICAgcmVwbzogdm0ucmVwbyxcbiAgICAgICAgICAgIHBhdGg6ICcuJ1xuICAgICAgICAgIH1cbiAgICAgICAgICB2bS5wYXRocy5wdXNoKHZtLnF1ZXJ5RmlsdGVycy5wYXRoKTtcbiAgICAgICAgICB2bS5zZWFyY2goKTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAkd2luZG93LmxvYWRpbmdfc2NyZWVuLmZpbmlzaCgpO1xuICAgICAgICB9XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICB2bS5hcHBseUZpbHRlcnMgPSBmdW5jdGlvbihkZWZhdWx0UXVlcnlGaWx0ZXJzKSB7XG4gICAgICByZXR1cm4gYW5ndWxhci5leHRlbmQoZGVmYXVsdFF1ZXJ5RmlsdGVycywgdm0ucXVlcnlGaWx0ZXJzKTtcbiAgICB9XG5cbiAgICB2bS5hZnRlclNlYXJjaCA9IGZ1bmN0aW9uKCkge1xuICAgICAgc29ydFJlc291cmNlcygpO1xuICAgICAgJHdpbmRvdy5sb2FkaW5nX3NjcmVlbi5maW5pc2goKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBzb3J0UmVzb3VyY2VzKCkge1xuICAgICAgaWYgKHZtLnJlc291cmNlcy5sZW5ndGggPiAwKSB7XG4gICAgICAgIHZtLnJlc291cmNlcy5zb3J0KGZ1bmN0aW9uKGEsIGIpIHtcbiAgICAgICAgICByZXR1cm4gYS50eXBlIDwgYi50eXBlID8gLTEgOiBhLnR5cGUgPiBiLnR5cGUgPyAxIDogMDtcbiAgICAgICAgfSk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgdm0ub3BlbkZpbGVPckRpcmVjdG9yeSA9IGZ1bmN0aW9uKHJlc291cmNlKSB7XG4gICAgICB0b2dnbGVTcGxhc2hTY3JlZW4oKTtcbiAgICAgIGlmIChyZXNvdXJjZSkge1xuICAgICAgICB2bS5xdWVyeUZpbHRlcnMucGF0aCA9IHJlc291cmNlLnBhdGg7XG4gICAgICAgIHZtLnBhdGhzLnB1c2godm0ucXVlcnlGaWx0ZXJzLnBhdGgpO1xuICAgICAgICB2bS5pbmRleCsrO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgdm0ucXVlcnlGaWx0ZXJzLnBhdGggPSB2bS5wYXRoc1t2bS5pbmRleCAtIDFdO1xuICAgICAgICB2bS5wYXRocy5zcGxpY2Uodm0uaW5kZXgsIDEpO1xuICAgICAgICB2bS5pbmRleC0tO1xuICAgICAgfVxuICAgICAgdm0uc2VhcmNoKCk7XG4gICAgfVxuXG4gICAgdm0ub25TZWFyY2hFcnJvciA9IGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgaWYgKHJlc3BvbnNlLmRhdGEuZXJyb3IgPT09ICdOb3QgRm91bmQnKSB7XG4gICAgICAgIFByVG9hc3QuaW5mbygkdHJhbnNsYXRlLmluc3RhbnQoJ1JlcG9zaXTDs3JpbyBuw6NvIGVuY29udHJhZG8nKSk7XG4gICAgICAgICR3aW5kb3cubG9hZGluZ19zY3JlZW4uZmluaXNoKCk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogTcOpdG9kbyBwYXJhIG1vc3RyYXIgYSB0ZWxhIGRlIGVzcGVyYVxuICAgICAqL1xuICAgIGZ1bmN0aW9uIHRvZ2dsZVNwbGFzaFNjcmVlbigpIHtcbiAgICAgICR3aW5kb3cubG9hZGluZ19zY3JlZW4gPSAkd2luZG93LnBsZWFzZVdhaXQoe1xuICAgICAgICBsb2dvOiAnJyxcbiAgICAgICAgYmFja2dyb3VuZENvbG9yOiAncmdiYSgyNTUsMjU1LDI1NSwwLjQpJyxcbiAgICAgICAgbG9hZGluZ0h0bWw6XG4gICAgICAgICAgJzxkaXYgY2xhc3M9XCJzcGlubmVyXCI+ICcgK1xuICAgICAgICAgICcgIDxkaXYgY2xhc3M9XCJyZWN0MVwiPjwvZGl2PiAnICtcbiAgICAgICAgICAnICA8ZGl2IGNsYXNzPVwicmVjdDJcIj48L2Rpdj4gJyArXG4gICAgICAgICAgJyAgPGRpdiBjbGFzcz1cInJlY3QzXCI+PC9kaXY+ICcgK1xuICAgICAgICAgICcgIDxkaXYgY2xhc3M9XCJyZWN0NFwiPjwvZGl2PiAnICtcbiAgICAgICAgICAnICA8ZGl2IGNsYXNzPVwicmVjdDVcIj48L2Rpdj4gJyArXG4gICAgICAgICAgJyA8cCBjbGFzcz1cImxvYWRpbmctbWVzc2FnZVwiPkNhcnJlZ2FuZG88L3A+ICcgK1xuICAgICAgICAgICc8L2Rpdj4nXG4gICAgICB9KTtcbiAgICB9XG5cbiAgICAvLyBpbnN0YW50aWF0ZSBiYXNlIGNvbnRyb2xsZXJcbiAgICAkY29udHJvbGxlcignQ1JVRENvbnRyb2xsZXInLCB7IHZtOiB2bSwgbW9kZWxTZXJ2aWNlOiBWY3NTZXJ2aWNlLCBvcHRpb25zOiB7IHNraXBQYWdpbmF0aW9uOiB0cnVlLCBzZWFyY2hPbkluaXQ6IGZhbHNlIH0gfSk7XG5cbiAgfVxuXG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqXG4gICAqIEFycXVpdm8gZGUgY29uZmlndXJhw6fDo28gY29tIGFzIHJvdGFzIGVzcGVjw61maWNhcyBkbyByZWN1cnNvIHZjc1xuICAgKlxuICAgKiBAcGFyYW0ge29iamVjdH0gJHN0YXRlUHJvdmlkZXJcbiAgICogQHBhcmFtIHtvYmplY3R9IEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyXG4gICAgICAuc3RhdGUoJ2FwcC52Y3MnLCB7XG4gICAgICAgIHVybDogJy92Y3MnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL3Zjcy92Y3MuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdWY3NDb250cm9sbGVyIGFzIHZjc0N0cmwnLFxuICAgICAgICBkYXRhOiB7IH1cbiAgICAgIH0pO1xuICB9XG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZhY3RvcnkoJ1Zjc1NlcnZpY2UnLCBWY3NTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIFZjc1NlcnZpY2Uoc2VydmljZUZhY3RvcnkpIHtcbiAgICB2YXIgbW9kZWwgPSBzZXJ2aWNlRmFjdG9yeSgndmNzJywge1xuICAgICAgYWN0aW9uczogeyB9LFxuICAgICAgaW5zdGFuY2U6IHsgfVxuICAgIH0pO1xuXG4gICAgcmV0dXJuIG1vZGVsO1xuICB9XG5cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICAgLyoqIEBuZ0luamVjdCAqL1xuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29tcG9uZW50KCdib3gnLCB7XG4gICAgICByZXBsYWNlOiB0cnVlLFxuICAgICAgdGVtcGxhdGVVcmw6IFsnR2xvYmFsJywgZnVuY3Rpb24oR2xvYmFsKSB7XG4gICAgICAgIHJldHVybiBHbG9iYWwuY2xpZW50UGF0aCArICcvd2lkZ2V0cy9ib3guaHRtbCdcbiAgICAgIH1dLFxuICAgICAgdHJhbnNjbHVkZToge1xuICAgICAgICB0b29sYmFyQnV0dG9uczogJz9ib3hUb29sYmFyQnV0dG9ucycsXG4gICAgICAgIGZvb3RlckJ1dHRvbnM6ICc/Ym94Rm9vdGVyQnV0dG9ucydcbiAgICAgIH0sXG4gICAgICBiaW5kaW5nczoge1xuICAgICAgICBib3hUaXRsZTogJ0AnLFxuICAgICAgICB0b29sYmFyQ2xhc3M6ICdAJyxcbiAgICAgICAgdG9vbGJhckJnQ29sb3I6ICdAJ1xuICAgICAgfSxcbiAgICAgIGNvbnRyb2xsZXI6IFsnJHRyYW5zY2x1ZGUnLCBmdW5jdGlvbigkdHJhbnNjbHVkZSkge1xuICAgICAgICB2YXIgY3RybCA9IHRoaXM7XG5cbiAgICAgICAgY3RybC50cmFuc2NsdWRlID0gJHRyYW5zY2x1ZGU7XG5cbiAgICAgICAgY3RybC4kb25Jbml0ID0gZnVuY3Rpb24oKSB7XG4gICAgICAgICAgaWYgKGFuZ3VsYXIuaXNVbmRlZmluZWQoY3RybC50b29sYmFyQmdDb2xvcikpIGN0cmwudG9vbGJhckJnQ29sb3IgPSAnZGVmYXVsdC1wcmltYXJ5JztcbiAgICAgICAgfTtcbiAgICAgIH1dXG4gICAgfSk7XG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29tcG9uZW50KCdjb250ZW50Qm9keScsIHtcbiAgICAgIHJlcGxhY2U6IHRydWUsXG4gICAgICB0cmFuc2NsdWRlOiB0cnVlLFxuICAgICAgdGVtcGxhdGVVcmw6IFsnR2xvYmFsJywgZnVuY3Rpb24oR2xvYmFsKSB7XG4gICAgICAgIHJldHVybiBHbG9iYWwuY2xpZW50UGF0aCArICcvd2lkZ2V0cy9jb250ZW50LWJvZHkuaHRtbCdcbiAgICAgIH1dLFxuICAgICAgYmluZGluZ3M6IHtcbiAgICAgICAgbGF5b3V0QWxpZ246ICdAJ1xuICAgICAgfSxcbiAgICAgIGNvbnRyb2xsZXI6IFtmdW5jdGlvbigpIHtcbiAgICAgICAgdmFyIGN0cmwgPSB0aGlzO1xuXG4gICAgICAgIGN0cmwuJG9uSW5pdCA9IGZ1bmN0aW9uKCkge1xuICAgICAgICAgIC8vIE1ha2UgYSBjb3B5IG9mIHRoZSBpbml0aWFsIHZhbHVlIHRvIGJlIGFibGUgdG8gcmVzZXQgaXQgbGF0ZXJcbiAgICAgICAgICBjdHJsLmxheW91dEFsaWduID0gYW5ndWxhci5pc0RlZmluZWQoY3RybC5sYXlvdXRBbGlnbikgPyBjdHJsLmxheW91dEFsaWduIDogJ2NlbnRlciBzdGFydCc7XG4gICAgICAgIH07XG4gICAgICB9XVxuICAgIH0pO1xuXG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29tcG9uZW50KCdjb250ZW50SGVhZGVyJywge1xuICAgICAgdGVtcGxhdGVVcmw6IFsnR2xvYmFsJywgZnVuY3Rpb24oR2xvYmFsKSB7XG4gICAgICAgIHJldHVybiBHbG9iYWwuY2xpZW50UGF0aCArICcvd2lkZ2V0cy9jb250ZW50LWhlYWRlci5odG1sJ1xuICAgICAgfV0sXG4gICAgICByZXBsYWNlOiB0cnVlLFxuICAgICAgYmluZGluZ3M6IHtcbiAgICAgICAgdGl0bGU6ICdAJyxcbiAgICAgICAgZGVzY3JpcHRpb246ICdAJ1xuICAgICAgfVxuICAgIH0pO1xuXG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmlsdGVyKCdhdWRpdERldGFpbFRpdGxlJywgYXVkaXREZXRhaWxUaXRsZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBhdWRpdERldGFpbFRpdGxlKCR0cmFuc2xhdGUpIHtcbiAgICByZXR1cm4gZnVuY3Rpb24oYXVkaXREZXRhaWwsIHN0YXR1cykge1xuICAgICAgaWYgKGF1ZGl0RGV0YWlsLnR5cGUgPT09ICd1cGRhdGVkJykge1xuICAgICAgICBpZiAoc3RhdHVzID09PSAnYmVmb3JlJykge1xuICAgICAgICAgIHJldHVybiAkdHJhbnNsYXRlLmluc3RhbnQoJ2RpYWxvZy5hdWRpdC51cGRhdGVkQmVmb3JlJyk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgcmV0dXJuICR0cmFuc2xhdGUuaW5zdGFudCgnZGlhbG9nLmF1ZGl0LnVwZGF0ZWRBZnRlcicpO1xuICAgICAgICB9XG4gICAgICB9IGVsc2Uge1xuICAgICAgICByZXR1cm4gJHRyYW5zbGF0ZS5pbnN0YW50KCdkaWFsb2cuYXVkaXQuJyArIGF1ZGl0RGV0YWlsLnR5cGUpO1xuICAgICAgfVxuICAgIH1cbiAgfVxuXG59KSgpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmlsdGVyKCdhdWRpdE1vZGVsJywgYXVkaXRNb2RlbCk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBhdWRpdE1vZGVsKCR0cmFuc2xhdGUpIHtcbiAgICByZXR1cm4gZnVuY3Rpb24obW9kZWxJZCkge1xuICAgICAgbW9kZWxJZCA9IG1vZGVsSWQucmVwbGFjZSgnQXBwXFxcXCcsICcnKTtcbiAgICAgIHZhciBtb2RlbCA9ICR0cmFuc2xhdGUuaW5zdGFudCgnbW9kZWxzLicgKyBtb2RlbElkLnRvTG93ZXJDYXNlKCkpO1xuXG4gICAgICByZXR1cm4gKG1vZGVsKSA/IG1vZGVsIDogbW9kZWxJZDtcbiAgICB9XG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZpbHRlcignYXVkaXRUeXBlJywgYXVkaXRUeXBlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIGF1ZGl0VHlwZShsb2Rhc2gsIEF1ZGl0U2VydmljZSkge1xuICAgIHJldHVybiBmdW5jdGlvbih0eXBlSWQpIHtcbiAgICAgIHZhciB0eXBlID0gbG9kYXNoLmZpbmQoQXVkaXRTZXJ2aWNlLmxpc3RUeXBlcygpLCB7IGlkOiB0eXBlSWQgfSk7XG5cbiAgICAgIHJldHVybiAodHlwZSkgPyB0eXBlLmxhYmVsIDogdHlwZTtcbiAgICB9XG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZpbHRlcignYXVkaXRWYWx1ZScsIGF1ZGl0VmFsdWUpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gYXVkaXRWYWx1ZSgkZmlsdGVyLCBsb2Rhc2gpIHtcbiAgICByZXR1cm4gZnVuY3Rpb24odmFsdWUsIGtleSkge1xuICAgICAgaWYgKGFuZ3VsYXIuaXNEYXRlKHZhbHVlKSB8fCBsb2Rhc2guZW5kc1dpdGgoa2V5LCAnX2F0JykgfHwgIGxvZGFzaC5lbmRzV2l0aChrZXksICdfdG8nKSkge1xuICAgICAgICByZXR1cm4gJGZpbHRlcigncHJEYXRldGltZScpKHZhbHVlKTtcbiAgICAgIH1cblxuICAgICAgaWYgKHR5cGVvZiB2YWx1ZSA9PT0gJ2Jvb2xlYW4nKSB7XG4gICAgICAgIHJldHVybiAkZmlsdGVyKCd0cmFuc2xhdGUnKSgodmFsdWUpID8gJ2dsb2JhbC55ZXMnIDogJ2dsb2JhbC5ubycpO1xuICAgICAgfVxuXG4gICAgICAvL2NoZWNrIGlzIGZsb2F0XG4gICAgICBpZiAoTnVtYmVyKHZhbHVlKSA9PT0gdmFsdWUgJiYgdmFsdWUgJSAxICE9PSAwKSB7XG4gICAgICAgIHJldHVybiAkZmlsdGVyKCdyZWFsJykodmFsdWUpO1xuICAgICAgfVxuXG4gICAgICByZXR1cm4gdmFsdWU7XG4gICAgfVxuICB9XG5cbn0pKCk7XG4iLCIvKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCwgbm8tdW5kZWY6IDAqL1xuKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnN0YW50KCdwdC1CUi5pMThuLmF0dHJpYnV0ZXMnLCB7XG4gICAgICBlbWFpbDogJ0VtYWlsJyxcbiAgICAgIHBhc3N3b3JkOiAnU2VuaGEnLFxuICAgICAgbmFtZTogJ05vbWUnLFxuICAgICAgaW1hZ2U6ICdJbWFnZW0nLFxuICAgICAgcm9sZXM6ICdQZXJmaXMnLFxuICAgICAgZGF0ZTogJ0RhdGEnLFxuICAgICAgaW5pdGlhbERhdGU6ICdEYXRhIEluaWNpYWwnLFxuICAgICAgZmluYWxEYXRlOiAnRGF0YSBGaW5hbCcsXG4gICAgICBiaXJ0aGRheTogJ0RhdGEgZGUgTmFzY2ltZW50bycsXG4gICAgICB0YXNrOiB7XG4gICAgICAgIGRlc2NyaXB0aW9uOiAnRGVzY3Jpw6fDo28nLFxuICAgICAgICBkb25lOiAnRmVpdG8/JyxcbiAgICAgICAgcHJpb3JpdHk6ICdQcmlvcmlkYWRlJyxcbiAgICAgICAgc2NoZWR1bGVkX3RvOiAnQWdlbmRhZG8gUGFyYT8nLFxuICAgICAgICBwcm9qZWN0OiAnUHJvamV0bycsXG4gICAgICAgIHN0YXR1czogJ1N0YXR1cycsXG4gICAgICAgIHRpdGxlOiAnVMOtdHVsbycsXG4gICAgICAgIHR5cGU6ICdUaXBvJyxcbiAgICAgICAgbWlsZXN0b25lOiAnU3ByaW50JyxcbiAgICAgICAgZXN0aW1hdGVkX3RpbWU6ICdUZW1wbyBFc3RpbWFkbydcbiAgICAgIH0sXG4gICAgICBtaWxlc3RvbmU6IHtcbiAgICAgICAgdGl0bGU6ICdUw610dWxvJyxcbiAgICAgICAgZGVzY3JpcHRpb246ICdEZXNjcmnDp8OjbycsXG4gICAgICAgIGRhdGVfc3RhcnQ6ICdEYXRhIEVzdGltYWRhIHBhcmEgSW7DrWNpbycsXG4gICAgICAgIGRhdGVfZW5kOiAnRGF0YSBFc3RpbWFkYSBwYXJhIEZpbScsXG4gICAgICAgIGVzdGltYXRlZF90aW1lOiAnVGVtcG8gRXN0aW1hZG8nLFxuICAgICAgICBlc3RpbWF0ZWRfdmFsdWU6ICdWYWxvciBFc3RpbWFkbydcbiAgICAgIH0sXG4gICAgICBwcm9qZWN0OiB7XG4gICAgICAgIGNvc3Q6ICdDdXN0bycsXG4gICAgICAgIGhvdXJWYWx1ZURldmVsb3BlcjogJ1ZhbG9yIGRhIEhvcmEgRGVzZW52b2x2ZWRvcicsXG4gICAgICAgIGhvdXJWYWx1ZUNsaWVudDogJ1ZhbG9yIGRhIEhvcmEgQ2xpZW50ZScsXG4gICAgICAgIGhvdXJWYWx1ZUZpbmFsOiAnVmFsb3IgZGEgSG9yYSBQcm9qZXRvJ1xuICAgICAgfSxcbiAgICAgIHJlbGVhc2U6IHtcbiAgICAgICAgdGl0bGU6ICdUw610dWxvJyxcbiAgICAgICAgZGVzY3JpcHRpb246ICdEZXNjcmnDp8OjbycsXG4gICAgICAgIHJlbGVhc2VfZGF0ZTogJ0RhdGEgZGUgRW50cmVnYScsXG4gICAgICAgIG1pbGVzdG9uZTogJ01pbGVzdG9uZScsXG4gICAgICAgIHRhc2tzOiAnVGFyZWZhcydcbiAgICAgIH0sXG4gICAgICAvL8OpIGNhcnJlZ2FkbyBkbyBzZXJ2aWRvciBjYXNvIGVzdGVqYSBkZWZpbmlkbyBubyBtZXNtb1xuICAgICAgYXVkaXRNb2RlbDoge1xuICAgICAgfVxuICAgIH0pXG5cbn0oKSk7XG4iLCIvKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCwgbm8tdW5kZWY6IDAqL1xuKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnN0YW50KCdwdC1CUi5pMThuLmRpYWxvZycsIHtcbiAgICAgIGNvbmZpcm1UaXRsZTogJ0NvbmZpcm1hw6fDo28nLFxuICAgICAgY29uZmlybURlc2NyaXB0aW9uOiAnQ29uZmlybWEgYSBhw6fDo28/JyxcbiAgICAgIHJlbW92ZURlc2NyaXB0aW9uOiAnRGVzZWphIHJlbW92ZXIgcGVybWFuZW50ZW1lbnRlIHt7bmFtZX19PycsXG4gICAgICBhdWRpdDoge1xuICAgICAgICBjcmVhdGVkOiAnSW5mb3JtYcOnw7VlcyBkbyBDYWRhc3RybycsXG4gICAgICAgIHVwZGF0ZWRCZWZvcmU6ICdBbnRlcyBkYSBBdHVhbGl6YcOnw6NvJyxcbiAgICAgICAgdXBkYXRlZEFmdGVyOiAnRGVwb2lzIGRhIEF0dWFsaXphw6fDo28nLFxuICAgICAgICBkZWxldGVkOiAnSW5mb3JtYcOnw7VlcyBhbnRlcyBkZSByZW1vdmVyJ1xuICAgICAgfSxcbiAgICAgIGxvZ2luOiB7XG4gICAgICAgIHJlc2V0UGFzc3dvcmQ6IHtcbiAgICAgICAgICBkZXNjcmlwdGlvbjogJ0RpZ2l0ZSBhYmFpeG8gbyBlbWFpbCBjYWRhc3RyYWRvIG5vIHNpc3RlbWEuJ1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfSlcblxufSgpKTtcbiIsIi8qZXNsaW50IGFuZ3VsYXIvZmlsZS1uYW1lOiAwLCBuby11bmRlZjogMCovXG4oZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uc3RhbnQoJ3B0LUJSLmkxOG4uZ2xvYmFsJywge1xuICAgICAgbG9hZGluZzogJ0NhcnJlZ2FuZG8uLi4nLFxuICAgICAgcHJvY2Vzc2luZzogJ1Byb2Nlc3NhbmRvLi4uJyxcbiAgICAgIHllczogJ1NpbScsXG4gICAgICBubzogJ07Do28nLFxuICAgICAgYWxsOiAnVG9kb3MnXG4gICAgfSlcblxufSgpKTtcbiIsIi8qZXNsaW50IGFuZ3VsYXIvZmlsZS1uYW1lOiAwLCBuby11bmRlZjogMCovXG4oZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uc3RhbnQoJ3B0LUJSLmkxOG4ubWVzc2FnZXMnLCB7XG4gICAgICBpbnRlcm5hbEVycm9yOiAnT2NvcnJldSB1bSBlcnJvIGludGVybm8sIGNvbnRhdGUgbyBhZG1pbmlzdHJhZG9yIGRvIHNpc3RlbWEnLFxuICAgICAgbm90Rm91bmQ6ICdOZW5odW0gcmVnaXN0cm8gZW5jb250cmFkbycsXG4gICAgICBub3RBdXRob3JpemVkOiAnVm9jw6ogbsOjbyB0ZW0gYWNlc3NvIGEgZXN0YSBmdW5jaW9uYWxpZGFkZS4nLFxuICAgICAgc2VhcmNoRXJyb3I6ICdOw6NvIGZvaSBwb3Nzw612ZWwgcmVhbGl6YXIgYSBidXNjYS4nLFxuICAgICAgc2F2ZVN1Y2Nlc3M6ICdSZWdpc3RybyBzYWx2byBjb20gc3VjZXNzby4nLFxuICAgICAgb3BlcmF0aW9uU3VjY2VzczogJ09wZXJhw6fDo28gcmVhbGl6YWRhIGNvbSBzdWNlc3NvLicsXG4gICAgICBvcGVyYXRpb25FcnJvcjogJ0Vycm8gYW8gcmVhbGl6YXIgYSBvcGVyYcOnw6NvJyxcbiAgICAgIHNhdmVFcnJvcjogJ0Vycm8gYW8gdGVudGFyIHNhbHZhciBvIHJlZ2lzdHJvLicsXG4gICAgICByZW1vdmVTdWNjZXNzOiAnUmVtb8Onw6NvIHJlYWxpemFkYSBjb20gc3VjZXNzby4nLFxuICAgICAgcmVtb3ZlRXJyb3I6ICdFcnJvIGFvIHRlbnRhciByZW1vdmVyIG8gcmVnaXN0cm8uJyxcbiAgICAgIHJlc291cmNlTm90Rm91bmRFcnJvcjogJ1JlY3Vyc28gbsOjbyBlbmNvbnRyYWRvJyxcbiAgICAgIG5vdE51bGxFcnJvcjogJ1RvZG9zIG9zIGNhbXBvcyBvYnJpZ2F0w7NyaW9zIGRldmVtIHNlciBwcmVlbmNoaWRvcy4nLFxuICAgICAgZHVwbGljYXRlZFJlc291cmNlRXJyb3I6ICdKw6EgZXhpc3RlIHVtIHJlY3Vyc28gY29tIGVzc2FzIGluZm9ybWHDp8O1ZXMuJyxcbiAgICAgIHNwcmludEVuZGVkU3VjY2VzczogJ1NwcmludCBmaW5hbGl6YWRhIGNvbSBzdWNlc3NvJyxcbiAgICAgIHNwcmludEVuZGVkRXJyb3I6ICdFcnJvIGFvIGZpbmFsaXphciBhIHNwcmludCcsXG4gICAgICBzdWNjZXNzU2lnblVwOiAnQ2FkYXN0cm8gcmVhbGl6YWRvIGNvbSBzdWNlc3NvLiBVbSBlLW1haWwgZm9pIGVudmlhZG8gY29tIHNldXMgZGFkb3MgZGUgbG9naW4nLFxuICAgICAgZXJyb3JzU2lnblVwOiAnSG91dmUgdW0gZXJybyBhbyByZWFsaXphciBvIHNldSBjYWRhc3Ryby4gVGVudGUgbm92YW1lbnRlIG1haXMgdGFyZGUhJyxcbiAgICAgIHJlbGVhc2V0RW5kZWRTdWNjZXNzOiAnUmVsZWFzZSBmaW5hbGl6YWRhIGNvbSBzdWNlc3NvJyxcbiAgICAgIHJlbGVhc2VFbmRlZEVycm9yOiAnRXJybyBhbyBmaW5hbGl6YXIgYSByZWxlYXNlJyxcbiAgICAgIHByb2plY3RFbmRlZFN1Y2Nlc3M6ICdQcm9qZXRvIGZpbmFsaXphZG8gY29tIHN1Y2Vzc28nLFxuICAgICAgcHJvamVjdEVuZGVkRXJyb3I6ICdFcnJvIGFvIGZpbmFsaXphciBvIHByb2pldG8nLFxuICAgICAgdmFsaWRhdGU6IHtcbiAgICAgICAgZmllbGRSZXF1aXJlZDogJ08gY2FtcG8ge3tmaWVsZH19IMOpIG9icmlncmF0w7NyaW8uJ1xuICAgICAgfSxcbiAgICAgIGxheW91dDoge1xuICAgICAgICBlcnJvcjQwNDogJ1DDoWdpbmEgbsOjbyBlbmNvbnRyYWRhJ1xuICAgICAgfSxcbiAgICAgIGxvZ2luOiB7XG4gICAgICAgIGxvZ291dEluYWN0aXZlOiAnVm9jw6ogZm9pIGRlc2xvZ2FkbyBkbyBzaXN0ZW1hIHBvciBpbmF0aXZpZGFkZS4gRmF2b3IgZW50cmFyIG5vIHNpc3RlbWEgbm92YW1lbnRlLicsXG4gICAgICAgIGludmFsaWRDcmVkZW50aWFsczogJ0NyZWRlbmNpYWlzIEludsOhbGlkYXMnLFxuICAgICAgICB1bmtub3duRXJyb3I6ICdOw6NvIGZvaSBwb3Nzw612ZWwgcmVhbGl6YXIgbyBsb2dpbi4gVGVudGUgbm92YW1lbnRlLiAnICtcbiAgICAgICAgICAnQ2FzbyBuw6NvIGNvbnNpZ2EgZmF2b3IgZW5jb250cmFyIGVtIGNvbnRhdG8gY29tIG8gYWRtaW5pc3RyYWRvciBkbyBzaXN0ZW1hLicsXG4gICAgICAgIHVzZXJOb3RGb3VuZDogJ07Do28gZm9pIHBvc3PDrXZlbCBlbmNvbnRyYXIgc2V1cyBkYWRvcydcbiAgICAgIH0sXG4gICAgICBkYXNoYm9hcmQ6IHtcbiAgICAgICAgd2VsY29tZTogJ1NlamEgYmVtIFZpbmRvIHt7dXNlck5hbWV9fScsXG4gICAgICAgIGRlc2NyaXB0aW9uOiAnVXRpbGl6ZSBvIG1lbnUgcGFyYSBuYXZlZ2HDp8Ojby4nXG4gICAgICB9LFxuICAgICAgbWFpbDoge1xuICAgICAgICBtYWlsRXJyb3JzOiAnT2NvcnJldSB1bSBlcnJvIG5vcyBzZWd1aW50ZXMgZW1haWxzIGFiYWl4bzpcXG4nLFxuICAgICAgICBzZW5kTWFpbFN1Y2Nlc3M6ICdFbWFpbCBlbnZpYWRvIGNvbSBzdWNlc3NvIScsXG4gICAgICAgIHNlbmRNYWlsRXJyb3I6ICdOw6NvIGZvaSBwb3Nzw612ZWwgZW52aWFyIG8gZW1haWwuJyxcbiAgICAgICAgcGFzc3dvcmRTZW5kaW5nU3VjY2VzczogJ08gcHJvY2Vzc28gZGUgcmVjdXBlcmHDp8OjbyBkZSBzZW5oYSBmb2kgaW5pY2lhZG8uIENhc28gbyBlbWFpbCBuw6NvIGNoZWd1ZSBlbSAxMCBtaW51dG9zIHRlbnRlIG5vdmFtZW50ZS4nXG4gICAgICB9LFxuICAgICAgdXNlcjoge1xuICAgICAgICByZW1vdmVZb3VyU2VsZkVycm9yOiAnVm9jw6ogbsOjbyBwb2RlIHJlbW92ZXIgc2V1IHByw7NwcmlvIHVzdcOhcmlvJyxcbiAgICAgICAgdXNlckV4aXN0czogJ1VzdcOhcmlvIGrDoSBhZGljaW9uYWRvIScsXG4gICAgICAgIHByb2ZpbGU6IHtcbiAgICAgICAgICB1cGRhdGVFcnJvcjogJ07Do28gZm9pIHBvc3PDrXZlbCBhdHVhbGl6YXIgc2V1IHByb2ZpbGUnXG4gICAgICAgIH1cbiAgICAgIH0sXG4gICAgICBxdWVyeURpbmFtaWM6IHtcbiAgICAgICAgbm9GaWx0ZXI6ICdOZW5odW0gZmlsdHJvIGFkaWNpb25hZG8nXG4gICAgICB9XG4gICAgfSlcblxufSgpKTtcbiIsIi8qZXNsaW50IGFuZ3VsYXIvZmlsZS1uYW1lOiAwLCBuby11bmRlZjogMCovXG4oZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uc3RhbnQoJ3B0LUJSLmkxOG4ubW9kZWxzJywge1xuICAgICAgdXNlcjogJ1VzdcOhcmlvJyxcbiAgICAgIHRhc2s6ICdUYXJlZmEnLFxuICAgICAgcHJvamVjdDogJ1Byb2pldG8nXG4gICAgfSlcblxufSgpKTtcbiIsIi8qZXNsaW50IGFuZ3VsYXIvZmlsZS1uYW1lOiAwLCBuby11bmRlZjogMCovXG4oZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uc3RhbnQoJ3B0LUJSLmkxOG4udmlld3MnLCB7XG4gICAgICBicmVhZGNydW1iczoge1xuICAgICAgICB1c2VyOiAnQWRtaW5pc3RyYcOnw6NvIC0gVXN1w6FyaW8nLFxuICAgICAgICAndXNlci1wcm9maWxlJzogJ1BlcmZpbCcsXG4gICAgICAgIGRhc2hib2FyZDogJ0Rhc2hib2FyZCcsXG4gICAgICAgIGF1ZGl0OiAnQWRtaW5pc3RyYcOnw6NvIC0gQXVkaXRvcmlhJyxcbiAgICAgICAgbWFpbDogJ0FkbWluaXN0cmHDp8OjbyAtIEVudmlvIGRlIGUtbWFpbCcsXG4gICAgICAgIHByb2plY3RzOiAnUHJvamV0b3MnLFxuICAgICAgICAnZGluYW1pYy1xdWVyeSc6ICdBZG1pbmlzdHJhw6fDo28gLSBDb25zdWx0YXMgRGluw6JtaWNhcycsXG4gICAgICAgICdub3QtYXV0aG9yaXplZCc6ICdBY2Vzc28gTmVnYWRvJyxcbiAgICAgICAgdGFza3M6ICdUYXJlZmFzJyxcbiAgICAgICAgbWlsZXN0b25lczogJ1NwcmludHMnLFxuICAgICAgICBrYW5iYW46ICdLYW5iYW4gQm9hcmQnLFxuICAgICAgICB2Y3M6ICdDb250cm9sZSBkZSBWZXJzw6NvJyxcbiAgICAgICAgcmVsZWFzZXM6ICdSZWxlYXNlcydcbiAgICAgIH0sXG4gICAgICB0aXRsZXM6IHtcbiAgICAgICAgZGFzaGJvYXJkOiAnRGFzaGJvYXJkJyxcbiAgICAgICAgbWFpbFNlbmQ6ICdFbnZpYXIgZS1tYWlsJyxcbiAgICAgICAgdGFza0xpc3Q6ICdMaXN0YSBkZSBUYXJlZmFzJyxcbiAgICAgICAgdXNlckxpc3Q6ICdMaXN0YSBkZSBVc3XDoXJpb3MnLFxuICAgICAgICBhdWRpdExpc3Q6ICdMaXN0YSBkZSBMb2dzJyxcbiAgICAgICAgcmVnaXN0ZXI6ICdGb3JtdWzDoXJpbyBkZSBDYWRhc3RybycsXG4gICAgICAgIHJlc2V0UGFzc3dvcmQ6ICdSZWRlZmluaXIgU2VuaGEnLFxuICAgICAgICB1cGRhdGU6ICdGb3JtdWzDoXJpbyBkZSBBdHVhbGl6YcOnw6NvJyxcbiAgICAgICAgdGFza3M6ICdUYXJlZmFzJyxcbiAgICAgICAgbWlsZXN0b25lczogJ1NwcmludHMnLFxuICAgICAgICBrYW5iYW46ICdLYW5iYW4gQm9hcmQnLFxuICAgICAgICB2Y3M6ICdDb250cm9sZSBkZSBWZXJzw6NvJyxcbiAgICAgICAgcmVsZWFzZXM6ICdSZWxlYXNlcydcbiAgICAgIH0sXG4gICAgICBhY3Rpb25zOiB7XG4gICAgICAgIHNlbmQ6ICdFbnZpYXInLFxuICAgICAgICBzYXZlOiAnU2FsdmFyJyxcbiAgICAgICAgY2xlYXI6ICdMaW1wYXInLFxuICAgICAgICBjbGVhckFsbDogJ0xpbXBhciBUdWRvJyxcbiAgICAgICAgcmVzdGFydDogJ1JlaW5pY2lhcicsXG4gICAgICAgIGZpbHRlcjogJ0ZpbHRyYXInLFxuICAgICAgICBzZWFyY2g6ICdQZXNxdWlzYXInLFxuICAgICAgICBsaXN0OiAnTGlzdGFyJyxcbiAgICAgICAgZWRpdDogJ0VkaXRhcicsXG4gICAgICAgIGNhbmNlbDogJ0NhbmNlbGFyJyxcbiAgICAgICAgdXBkYXRlOiAnQXR1YWxpemFyJyxcbiAgICAgICAgcmVtb3ZlOiAnUmVtb3ZlcicsXG4gICAgICAgIGdldE91dDogJ1NhaXInLFxuICAgICAgICBhZGQ6ICdBZGljaW9uYXInLFxuICAgICAgICBpbjogJ0VudHJhcicsXG4gICAgICAgIGxvYWRJbWFnZTogJ0NhcnJlZ2FyIEltYWdlbScsXG4gICAgICAgIHNpZ251cDogJ0NhZGFzdHJhcicsXG4gICAgICAgIGNyaWFyUHJvamV0bzogJ0NyaWFyIFByb2pldG8nLFxuICAgICAgICBwcm9qZWN0TGlzdDogJ0xpc3RhIGRlIFByb2pldG9zJyxcbiAgICAgICAgdGFza3NMaXN0OiAnTGlzdGEgZGUgVGFyZWZhcycsXG4gICAgICAgIG1pbGVzdG9uZXNMaXN0OiAnTGlzdGEgZGUgU3ByaW50cycsXG4gICAgICAgIGZpbmFsaXplOiAnRmluYWxpemFyJyxcbiAgICAgICAgcmVwbHk6ICdSZXNwb25kZXInXG4gICAgICB9LFxuICAgICAgZmllbGRzOiB7XG4gICAgICAgIGRhdGU6ICdEYXRhJyxcbiAgICAgICAgYWN0aW9uOiAnQcOnw6NvJyxcbiAgICAgICAgYWN0aW9uczogJ0HDp8O1ZXMnLFxuICAgICAgICBhdWRpdDoge1xuICAgICAgICAgIGRhdGVTdGFydDogJ0RhdGEgSW5pY2lhbCcsXG4gICAgICAgICAgZGF0ZUVuZDogJ0RhdGEgRmluYWwnLFxuICAgICAgICAgIHJlc291cmNlOiAnUmVjdXJzbycsXG4gICAgICAgICAgYWxsUmVzb3VyY2VzOiAnVG9kb3MgUmVjdXJzb3MnLFxuICAgICAgICAgIHR5cGU6IHtcbiAgICAgICAgICAgIGNyZWF0ZWQ6ICdDYWRhc3RyYWRvJyxcbiAgICAgICAgICAgIHVwZGF0ZWQ6ICdBdHVhbGl6YWRvJyxcbiAgICAgICAgICAgIGRlbGV0ZWQ6ICdSZW1vdmlkbydcbiAgICAgICAgICB9XG4gICAgICAgIH0sXG4gICAgICAgIGxvZ2luOiB7XG4gICAgICAgICAgcmVzZXRQYXNzd29yZDogJ0VzcXVlY2kgbWluaGEgc2VuaGEnLFxuICAgICAgICAgIGNvbmZpcm1QYXNzd29yZDogJ0NvbmZpcm1hciBzZW5oYSdcbiAgICAgICAgfSxcbiAgICAgICAgbWFpbDoge1xuICAgICAgICAgIHRvOiAnUGFyYScsXG4gICAgICAgICAgc3ViamVjdDogJ0Fzc3VudG8nLFxuICAgICAgICAgIG1lc3NhZ2U6ICdNZW5zYWdlbSdcbiAgICAgICAgfSxcbiAgICAgICAgcXVlcnlEaW5hbWljOiB7XG4gICAgICAgICAgZmlsdGVyczogJ0ZpbHRyb3MnLFxuICAgICAgICAgIHJlc3VsdHM6ICdSZXN1bHRhZG9zJyxcbiAgICAgICAgICBtb2RlbDogJ01vZGVsJyxcbiAgICAgICAgICBhdHRyaWJ1dGU6ICdBdHJpYnV0bycsXG4gICAgICAgICAgb3BlcmF0b3I6ICdPcGVyYWRvcicsXG4gICAgICAgICAgcmVzb3VyY2U6ICdSZWN1cnNvJyxcbiAgICAgICAgICB2YWx1ZTogJ1ZhbG9yJyxcbiAgICAgICAgICBvcGVyYXRvcnM6IHtcbiAgICAgICAgICAgIGVxdWFsczogJ0lndWFsJyxcbiAgICAgICAgICAgIGRpZmVyZW50OiAnRGlmZXJlbnRlJyxcbiAgICAgICAgICAgIGNvbnRlaW5zOiAnQ29udMOpbScsXG4gICAgICAgICAgICBzdGFydFdpdGg6ICdJbmljaWEgY29tJyxcbiAgICAgICAgICAgIGZpbmlzaFdpdGg6ICdGaW5hbGl6YSBjb20nLFxuICAgICAgICAgICAgYmlnZ2VyVGhhbjogJ01haW9yJyxcbiAgICAgICAgICAgIGVxdWFsc09yQmlnZ2VyVGhhbjogJ01haW9yIG91IElndWFsJyxcbiAgICAgICAgICAgIGxlc3NUaGFuOiAnTWVub3InLFxuICAgICAgICAgICAgZXF1YWxzT3JMZXNzVGhhbjogJ01lbm9yIG91IElndWFsJ1xuICAgICAgICAgIH1cbiAgICAgICAgfSxcbiAgICAgICAgcHJvamVjdDoge1xuICAgICAgICAgIG5hbWU6ICdOb21lJyxcbiAgICAgICAgICB0b3RhbFRhc2s6ICdUb3RhbCBkZSBUYXJlZmFzJ1xuICAgICAgICB9LFxuICAgICAgICB0YXNrOiB7XG4gICAgICAgICAgZG9uZTogJ07Do28gRmVpdG8gLyBGZWl0bydcbiAgICAgICAgfSxcbiAgICAgICAgdXNlcjoge1xuICAgICAgICAgIHBlcmZpbHM6ICdQZXJmaXMnLFxuICAgICAgICAgIG5hbWVPckVtYWlsOiAnTm9tZSBvdSBFbWFpbCdcbiAgICAgICAgfVxuICAgICAgfSxcbiAgICAgIGxheW91dDoge1xuICAgICAgICBtZW51OiB7XG4gICAgICAgICAgcHJvamVjdHM6ICdQcm9qZXRvcycsXG4gICAgICAgICAgZGFzaGJvYXJkOiAnRGFzaGJvYXJkJyxcbiAgICAgICAgICBtaWxlc3RvbmVzOiAnU3ByaW50cycsXG4gICAgICAgICAgdGFza3M6ICdUYXJlZmFzJyxcbiAgICAgICAgICBrYW5iYW46ICdLYW5iYW4nLFxuICAgICAgICAgIHZjczogJ0NvbnRyb2xlIGRlIFZlcnPDo28nLFxuICAgICAgICAgIHJlbGVhc2VzOiAnUmVsZWFzZXMnXG4gICAgICAgIH1cbiAgICAgIH0sXG4gICAgICB0b29sdGlwczoge1xuICAgICAgICBhdWRpdDoge1xuICAgICAgICAgIHZpZXdEZXRhaWw6ICdWaXN1YWxpemFyIERldGFsaGFtZW50bydcbiAgICAgICAgfSxcbiAgICAgICAgdXNlcjoge1xuICAgICAgICAgIHBlcmZpbDogJ1BlcmZpbCcsXG4gICAgICAgICAgdHJhbnNmZXI6ICdUcmFuc2ZlcmlyJ1xuICAgICAgICB9LFxuICAgICAgICB0YXNrOiB7XG4gICAgICAgICAgbGlzdFRhc2s6ICdMaXN0YXIgVGFyZWZhcydcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pXG5cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb250cm9sbGVyKCdUYXNrSW5mb0NvbnRyb2xsZXInLCBUYXNrSW5mb0NvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gVGFza0luZm9Db250cm9sbGVyKCRjb250cm9sbGVyLCBUYXNrc1NlcnZpY2UsIGxvY2Fscykge1xuICAgIC8vQXR0cmlidXRlcyBCbG9ja1xuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICB2bS5jbG9zZURpYWxvZyA9IGNsb3NlRGlhbG9nO1xuXG4gICAgdm0ub25BY3RpdmF0ZSA9IGZ1bmN0aW9uKCkge1xuICAgICAgdm0udGFzayA9IGxvY2Fscy50YXNrO1xuICAgICAgdm0udGFzay5lc3RpbWF0ZWRfdGltZSA9IHZtLnRhc2suZXN0aW1hdGVkX3RpbWUudG9TdHJpbmcoKSArICcgaG9yYXMnO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGNsb3NlRGlhbG9nKCkge1xuICAgICAgdm0uY2xvc2UoKTtcbiAgICAgIGNvbnNvbGUubG9nKFwiZmVjaGFyXCIpO1xuICAgIH1cblxuICAgIC8vIGluc3RhbnRpYXRlIGJhc2UgY29udHJvbGxlclxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHsgdm06IHZtLCBtb2RlbFNlcnZpY2U6IFRhc2tzU2VydmljZSwgb3B0aW9uczogeyB9IH0pO1xuICB9XG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb250cm9sbGVyKCdVc2Vyc0RpYWxvZ0NvbnRyb2xsZXInLCBVc2Vyc0RpYWxvZ0NvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gVXNlcnNEaWFsb2dDb250cm9sbGVyKCRjb250cm9sbGVyLCBVc2Vyc1NlcnZpY2UsIFByRGlhbG9nLCAgLy8gTk9TT05BUlxuICAgIHVzZXJEaWFsb2dJbnB1dCwgb25Jbml0KSB7XG5cbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0ub25BY3RpdmF0ZSA9IG9uQWN0aXZhdGU7XG4gICAgdm0uYXBwbHlGaWx0ZXJzID0gYXBwbHlGaWx0ZXJzO1xuICAgIHZtLmNsb3NlID0gY2xvc2U7XG5cbiAgICBpZiAoYW5ndWxhci5pc0RlZmluZWQodXNlckRpYWxvZ0lucHV0KSkge1xuICAgICAgdm0udHJhbnNmZXJVc2VyID0gdXNlckRpYWxvZ0lucHV0LnRyYW5zZmVyVXNlckZuO1xuICAgIH1cblxuICAgIC8vIGluc3RhbnRpYXRlIGJhc2UgY29udHJvbGxlclxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHtcbiAgICAgIHZtOiB2bSxcbiAgICAgIG1vZGVsU2VydmljZTogVXNlcnNTZXJ2aWNlLFxuICAgICAgc2VhcmNoT25Jbml0OiBvbkluaXQsXG4gICAgICBvcHRpb25zOiB7XG4gICAgICAgIHBlclBhZ2U6IDVcbiAgICAgIH1cbiAgICB9KTtcblxuICAgIGZ1bmN0aW9uIG9uQWN0aXZhdGUoKSB7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMgPSB7fTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBhcHBseUZpbHRlcnMoKSB7XG4gICAgICByZXR1cm4gYW5ndWxhci5leHRlbmQodm0uZGVmYXVsdFF1ZXJ5RmlsdGVycywgdm0ucXVlcnlGaWx0ZXJzKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBjbG9zZSgpIHtcbiAgICAgIFByRGlhbG9nLmNsb3NlKCk7XG4gICAgfVxuXG4gIH1cblxufSkoKTtcbiJdLCJzb3VyY2VSb290IjoiL3NvdXJjZS8ifQ==
