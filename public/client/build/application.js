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

  MilestonesController.$inject = ["$controller", "MilestonesService", "moment", "TasksService", "PrToast", "$translate", "$mdDialog", "Auth"];
  angular.module('app').controller('MilestonesController', MilestonesController);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function MilestonesController($controller, MilestonesService, moment, TasksService, PrToast, $translate, $mdDialog, Auth) {

    var vm = this;

    vm.estimatedPrice = estimatedPrice;

    vm.onActivate = function () {
      vm.currentUser = Auth.currentUser;
      vm.project = localStorage.getItem('project');
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

      if (dateEnd.diff(dateBegin, 'days') <= milestone.estimated_time) {
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
      vm.resource.date_begin = moment(vm.resource.date_begin);
      vm.resource.date_end = moment(vm.resource.date_end);
    };

    vm.view = function (resource) {
      resource.date_begin = moment(resource.date_begin);
      resource.date_end = moment(resource.date_end);
      vm.resource = resource;
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
      $window.history.back();
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

  ReleasesController.$inject = ["$controller", "ReleasesService", "MilestonesService", "Auth", "PrToast", "moment", "$mdDialog", "$translate"];
  angular.module('app').controller('ReleasesController', ReleasesController);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function ReleasesController($controller, ReleasesService, MilestonesService, Auth, PrToast, moment, $mdDialog, $translate) {
    var vm = this;

    //Attributes Block

    //Functions Block
    vm.onActivate = function () {
      vm.currentUser = Auth.currentUser;
      vm.project = localStorage.getItem('project');
      vm.queryFilters = { project_id: vm.project };
    };

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

  TasksController.$inject = ["$controller", "TasksService", "StatusService", "PrioritiesService", "TypesService", "TaskCommentsService", "moment", "Auth", "PrToast", "$translate", "$filter", "Global"];
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
  function TasksController($controller, TasksService, StatusService, PrioritiesService, TypesService, TaskCommentsService, moment, Auth, PrToast, $translate, $filter, Global) {
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImFwcGxpY2F0aW9uLmpzIiwiYXBwLmpzIiwiYXBwLmNvbmZpZy5qcyIsImFwcC5jb250cm9sbGVyLmpzIiwiYXBwLmV4dGVybmFsLmpzIiwiYXBwLmdsb2JhbC5qcyIsImFwcC5yb3V0ZXMuanMiLCJhcHAucnVuLmpzIiwiYXVkaXQvYXVkaXQuY29udHJvbGxlci5qcyIsImF1ZGl0L2F1ZGl0LnJvdXRlLmpzIiwiYXVkaXQvYXVkaXQuc2VydmljZS5qcyIsImF1dGgvYXV0aC5yb3V0ZS5qcyIsImF1dGgvYXV0aC5zZXJ2aWNlLmpzIiwiYXV0aC9sb2dpbi5jb250cm9sbGVyLmpzIiwiYXV0aC9wYXNzd29yZC5jb250cm9sbGVyLmpzIiwiY29yZS9iYXNlLnNlcnZpY2UuanMiLCJjb3JlL2NydWQuY29udHJvbGxlci5qcyIsImRhc2hib2FyZC9kYXNoYm9hcmQuY29udHJvbGxlci5qcyIsImRhc2hib2FyZC9kYXNoYm9hcmQucm91dGUuanMiLCJkYXNoYm9hcmQvZGFzaGJvYXJkLnNlcnZpY2UuanMiLCJkaW5hbWljLXF1ZXJ5cy9kaW5hbWljLXF1ZXJ5LnJvdXRlLmpzIiwiZGluYW1pYy1xdWVyeXMvZGluYW1pYy1xdWVyeS5zZXJ2aWNlLmpzIiwiZGluYW1pYy1xdWVyeXMvZGluYW1pYy1xdWVyeXMuY29udHJvbGxlci5qcyIsImkxOG4vbGFuZ3VhZ2UtbG9hZGVyLnNlcnZpY2UuanMiLCJpMThuL3QtYXR0ci5maWx0ZXIuanMiLCJpMThuL3QtYnJlYWRjcnVtYi5maWx0ZXIuanMiLCJpMThuL3QtbW9kZWwuZmlsdGVyLmpzIiwiaW50ZXJjZXB0b3JzL2F1dGhlbnRpY2F0aW9uLmxpc3RlbmVyLmpzIiwiaW50ZXJjZXB0b3JzL2F1dGhvcml6YXRpb24ubGlzdGVuZXIuanMiLCJpbnRlcmNlcHRvcnMvc3Bpbm5lci5pbnRlcmNlcHRvci5qcyIsImludGVyY2VwdG9ycy90b2tlbi5pbnRlcmNlcHRvci5qcyIsImludGVyY2VwdG9ycy92YWxpZGF0aW9uLmludGVyY2VwdG9yLmpzIiwia2FuYmFuL2thbmJhbi5jb250cm9sbGVyLmpzIiwia2FuYmFuL2thbmJhbi5yb3V0ZS5qcyIsImthbmJhbi9rYW5iYW4uc2VydmljZS5qcyIsImxheW91dC9tZW51LmNvbnRyb2xsZXIuanMiLCJtYWlsL21haWxzLmNvbnRyb2xsZXIuanMiLCJtYWlsL21haWxzLnJvdXRlLmpzIiwibWFpbC9tYWlscy5zZXJ2aWNlLmpzIiwibWlsZXN0b25lcy9taWxlc3RvbmVzLmNvbnRyb2xsZXIuanMiLCJtaWxlc3RvbmVzL21pbGVzdG9uZXMucm91dGUuanMiLCJtaWxlc3RvbmVzL21pbGVzdG9uZXMuc2VydmljZS5qcyIsInByaW9yaXRpZXMvcHJpb3JpdGllcy5zZXJ2aWNlLmpzIiwicHJvamVjdHMvcHJvamVjdHMuY29udHJvbGxlci5qcyIsInByb2plY3RzL3Byb2plY3RzLnJvdXRlLmpzIiwicHJvamVjdHMvcHJvamVjdHMuc2VydmljZS5qcyIsInJlbGVhc2VzL3JlbGVhc2VzLmNvbnRyb2xsZXIuanMiLCJyZWxlYXNlcy9yZWxlYXNlcy5yb3V0ZS5qcyIsInJlbGVhc2VzL3JlbGVhc2VzLnNlcnZpY2UuanMiLCJyb2xlcy9yb2xlcy1zdHIuZmlsdGVyLmpzIiwicm9sZXMvcm9sZXMuc2VydmljZS5qcyIsInN0YXR1cy9zdGF0dXMuc2VydmljZS5qcyIsInN1cHBvcnQvc3VwcG9ydC5zZXJ2aWNlLmpzIiwidGFzay1jb21tZW50cy90YXNrLWNvbW1lbnRzLnNlcnZpY2UuanMiLCJ0YXNrcy90YXNrcy5jb250cm9sbGVyLmpzIiwidGFza3MvdGFza3Mucm91dGUuanMiLCJ0YXNrcy90YXNrcy5zZXJ2aWNlLmpzIiwidHlwZXMvdHlwZXMuc2VydmljZS5qcyIsInVzZXJzL3Byb2ZpbGUuY29udHJvbGxlci5qcyIsInVzZXJzL3VzZXJzLmNvbnRyb2xsZXIuanMiLCJ1c2Vycy91c2Vycy5yb3V0ZS5qcyIsInVzZXJzL3VzZXJzLnNlcnZpY2UuanMiLCJ2Y3MvdmNzLmNvbnRyb2xsZXIuanMiLCJ2Y3MvdmNzLnJvdXRlLmpzIiwidmNzL3Zjcy5zZXJ2aWNlLmpzIiwid2lkZ2V0cy9ib3guY29tcG9uZW50LmpzIiwid2lkZ2V0cy9jb250ZW50LWJvZHkuY29tcG9uZW50LmpzIiwid2lkZ2V0cy9jb250ZW50LWhlYWRlci5jb21wb25lbnQuanMiLCJhdWRpdC9maWx0ZXJzL2F1ZGl0LWRldGFpbC10aXRsZS5maWx0ZXIuanMiLCJhdWRpdC9maWx0ZXJzL2F1ZGl0LW1vZGVsLmZpbHRlci5qcyIsImF1ZGl0L2ZpbHRlcnMvYXVkaXQtdHlwZS5maWx0ZXIuanMiLCJhdWRpdC9maWx0ZXJzL2F1ZGl0LXZhbHVlLmZpbHRlci5qcyIsImkxOG4vcHQtQlIvYXR0cmlidXRlcy5qcyIsImkxOG4vcHQtQlIvZGlhbG9nLmpzIiwiaTE4bi9wdC1CUi9nbG9iYWwuanMiLCJpMThuL3B0LUJSL21lc3NhZ2VzLmpzIiwiaTE4bi9wdC1CUi9tb2RlbHMuanMiLCJpMThuL3B0LUJSL3ZpZXdzLmpzIiwia2FuYmFuL3Rhc2staW5mby1kaWFsb2cvdGFzay1pbmZvLmNvbnRyb2xsZXIuanMiLCJ1c2Vycy9kaWFsb2cvdXNlcnMtZGlhbG9nLmNvbnRyb2xsZXIuanMiXSwibmFtZXMiOlsiYW5ndWxhciIsIm1vZHVsZSIsImNvbmZpZyIsIkdsb2JhbCIsIiRtZFRoZW1pbmdQcm92aWRlciIsIiRtb2RlbEZhY3RvcnlQcm92aWRlciIsIiR0cmFuc2xhdGVQcm92aWRlciIsIm1vbWVudCIsIiRtZEFyaWFQcm92aWRlciIsIiRtZERhdGVMb2NhbGVQcm92aWRlciIsInVzZUxvYWRlciIsInVzZVNhbml0aXplVmFsdWVTdHJhdGVneSIsInVzZVBvc3RDb21waWxpbmciLCJsb2NhbGUiLCJkZWZhdWx0T3B0aW9ucyIsInByZWZpeCIsImFwaVBhdGgiLCJ0aGVtZSIsInByaW1hcnlQYWxldHRlIiwiZGVmYXVsdCIsImFjY2VudFBhbGV0dGUiLCJ3YXJuUGFsZXR0ZSIsImVuYWJsZUJyb3dzZXJDb2xvciIsImRpc2FibGVXYXJuaW5ncyIsImZvcm1hdERhdGUiLCJkYXRlIiwiZm9ybWF0IiwiY29udHJvbGxlciIsIkFwcENvbnRyb2xsZXIiLCIkc3RhdGUiLCJBdXRoIiwidm0iLCJhbm9BdHVhbCIsImFjdGl2ZVByb2plY3QiLCJsb2dvdXQiLCJnZXRJbWFnZVBlcmZpbCIsImdldExvZ29NZW51Iiwic2V0QWN0aXZlUHJvamVjdCIsImdldEFjdGl2ZVByb2plY3QiLCJyZW1vdmVBY3RpdmVQcm9qZWN0IiwiYWN0aXZhdGUiLCJEYXRlIiwiZ2V0RnVsbFllYXIiLCJ0aGVuIiwiZ28iLCJsb2dpblN0YXRlIiwiY3VycmVudFVzZXIiLCJpbWFnZSIsImltYWdlUGF0aCIsInByb2plY3QiLCJsb2NhbFN0b3JhZ2UiLCJzZXRJdGVtIiwiZ2V0SXRlbSIsInJlbW92ZUl0ZW0iLCJjb25zdGFudCIsIl8iLCJhcHBOYW1lIiwiaG9tZVN0YXRlIiwibG9naW5VcmwiLCJyZXNldFBhc3N3b3JkVXJsIiwicmVzZXRQYXNzd29yZFN0YXRlIiwibm90QXV0aG9yaXplZFN0YXRlIiwidG9rZW5LZXkiLCJjbGllbnRQYXRoIiwicm91dGVzIiwiJHN0YXRlUHJvdmlkZXIiLCIkdXJsUm91dGVyUHJvdmlkZXIiLCJzdGF0ZSIsInVybCIsInRlbXBsYXRlVXJsIiwiYWJzdHJhY3QiLCJyZXNvbHZlIiwidHJhbnNsYXRlUmVhZHkiLCIkdHJhbnNsYXRlIiwiJHEiLCJkZWZlcnJlZCIsImRlZmVyIiwidXNlIiwicHJvbWlzZSIsImRhdGEiLCJuZWVkQXV0aGVudGljYXRpb24iLCJ3aGVuIiwib3RoZXJ3aXNlIiwicnVuIiwiJHJvb3RTY29wZSIsIiRzdGF0ZVBhcmFtcyIsImF1dGgiLCJnbG9iYWwiLCJyZXRyaWV2ZVVzZXJGcm9tTG9jYWxTdG9yYWdlIiwiQXVkaXRDb250cm9sbGVyIiwiJGNvbnRyb2xsZXIiLCJBdWRpdFNlcnZpY2UiLCJQckRpYWxvZyIsIm9uQWN0aXZhdGUiLCJhcHBseUZpbHRlcnMiLCJ2aWV3RGV0YWlsIiwibW9kZWxTZXJ2aWNlIiwib3B0aW9ucyIsIm1vZGVscyIsInF1ZXJ5RmlsdGVycyIsImdldEF1ZGl0ZWRNb2RlbHMiLCJpZCIsImxhYmVsIiwiaW5zdGFudCIsInNvcnQiLCJpbmRleCIsImxlbmd0aCIsIm1vZGVsIiwicHVzaCIsInRvTG93ZXJDYXNlIiwidHlwZXMiLCJsaXN0VHlwZXMiLCJ0eXBlIiwiZGVmYXVsdFF1ZXJ5RmlsdGVycyIsImV4dGVuZCIsImF1ZGl0RGV0YWlsIiwibG9jYWxzIiwiY2xvc2UiLCJpc0FycmF5Iiwib2xkIiwibmV3IiwiY29udHJvbGxlckFzIiwiaGFzQmFja2Ryb3AiLCJjdXN0b20iLCJuZWVkUHJvZmlsZSIsImZhY3RvcnkiLCJzZXJ2aWNlRmFjdG9yeSIsImFjdGlvbnMiLCJtZXRob2QiLCJpbnN0YW5jZSIsImF1ZGl0UGF0aCIsIiRodHRwIiwiVXNlcnNTZXJ2aWNlIiwibG9naW4iLCJ1cGRhdGVDdXJyZW50VXNlciIsImF1dGhlbnRpY2F0ZWQiLCJzZW5kRW1haWxSZXNldFBhc3N3b3JkIiwicmVtb3RlVmFsaWRhdGVUb2tlbiIsImdldFRva2VuIiwic2V0VG9rZW4iLCJjbGVhclRva2VuIiwidG9rZW4iLCJnZXQiLCJyZWplY3QiLCJ1c2VyIiwibWVyZ2UiLCJmcm9tSnNvbiIsImpzb25Vc2VyIiwidG9Kc29uIiwiY3JlZGVudGlhbHMiLCJwb3N0IiwicmVzcG9uc2UiLCJlcnJvciIsInJlc2V0RGF0YSIsIkxvZ2luQ29udHJvbGxlciIsIm9wZW5EaWFsb2dSZXNldFBhc3MiLCJvcGVuRGlhbG9nU2lnblVwIiwiZW1haWwiLCJwYXNzd29yZCIsIlBhc3N3b3JkQ29udHJvbGxlciIsIiR0aW1lb3V0IiwiUHJUb2FzdCIsInNlbmRSZXNldCIsImNsb3NlRGlhbG9nIiwiY2xlYW5Gb3JtIiwicmVzZXQiLCJzdWNjZXNzIiwic3RhdHVzIiwibXNnIiwiaSIsInRvVXBwZXJDYXNlIiwiZmllbGQiLCJtZXNzYWdlIiwiJG1vZGVsRmFjdG9yeSIsInBhZ2luYXRlIiwid3JhcCIsImFmdGVyUmVxdWVzdCIsIkxpc3QiLCJDUlVEQ29udHJvbGxlciIsIlByUGFnaW5hdGlvbiIsInNlYXJjaCIsInBhZ2luYXRlU2VhcmNoIiwibm9ybWFsU2VhcmNoIiwiZWRpdCIsInNhdmUiLCJyZW1vdmUiLCJnb1RvIiwicmVkaXJlY3RBZnRlclNhdmUiLCJzZWFyY2hPbkluaXQiLCJwZXJQYWdlIiwic2tpcFBhZ2luYXRpb24iLCJ2aWV3Rm9ybSIsInJlc291cmNlIiwiaXNGdW5jdGlvbiIsInBhZ2luYXRvciIsImdldEluc3RhbmNlIiwicGFnZSIsImN1cnJlbnRQYWdlIiwiaXNEZWZpbmVkIiwiYmVmb3JlU2VhcmNoIiwiY2FsY051bWJlck9mUGFnZXMiLCJ0b3RhbCIsInJlc291cmNlcyIsIml0ZW1zIiwiYWZ0ZXJTZWFyY2giLCJyZXNwb25zZURhdGEiLCJvblNlYXJjaEVycm9yIiwicXVlcnkiLCJmb3JtIiwiYmVmb3JlQ2xlYW4iLCIkc2V0UHJpc3RpbmUiLCIkc2V0VW50b3VjaGVkIiwiYWZ0ZXJDbGVhbiIsImNvcHkiLCJhZnRlckVkaXQiLCJiZWZvcmVTYXZlIiwiJHNhdmUiLCJhZnRlclNhdmUiLCJvblNhdmVFcnJvciIsInRpdGxlIiwiZGVzY3JpcHRpb24iLCJjb25maXJtIiwiYmVmb3JlUmVtb3ZlIiwiJGRlc3Ryb3kiLCJhZnRlclJlbW92ZSIsImluZm8iLCJ2aWV3TmFtZSIsIm9uVmlldyIsImZpbHRlciIsInRpbWUiLCJwYXJzZSIsInRpbWVOb3ciLCJnZXRUaW1lIiwiZGlmZmVyZW5jZSIsInNlY29uZHMiLCJNYXRoIiwiZmxvb3IiLCJtaW51dGVzIiwiaG91cnMiLCJkYXlzIiwibW9udGhzIiwiRGFzaGJvYXJkQ29udHJvbGxlciIsIiRtZERpYWxvZyIsIkRhc2hib2FyZHNTZXJ2aWNlIiwiUHJvamVjdHNTZXJ2aWNlIiwiZml4RGF0ZSIsInByb2plY3RfaWQiLCJhY3R1YWxQcm9qZWN0IiwiZGF0ZVN0cmluZyIsImdvVG9Qcm9qZWN0Iiwib2JqIiwidG90YWxDb3N0IiwiZXN0aW1hdGVkX2Nvc3QiLCJob3VyX3ZhbHVlX2ZpbmFsIiwidGFza3MiLCJmb3JFYWNoIiwidGFzayIsImVzdGltYXRlZF90aW1lIiwicGFyc2VGbG9hdCIsInRvTG9jYWxlU3RyaW5nIiwibWluaW11bUZyYWN0aW9uRGlnaXRzIiwiZmluYWxpemVQcm9qZWN0IiwidmVyaWZ5UmVsZWFzZXMiLCJodG1sQ29udGVudCIsIm5hbWUiLCJvayIsImNhbmNlbCIsInNob3ciLCJyZWFzb24iLCJwcm9tcHQiLCJ0ZXh0Q29udGVudCIsInBsYWNlaG9sZGVyIiwiaW5pdGlhbFZhbHVlIiwicmVxdWlyZWQiLCJyZWFzb25UZXh0IiwiZmluYWxpemUiLCJFcnJvciIsIkRpbmFtaWNRdWVyeVNlcnZpY2UiLCJnZXRNb2RlbHMiLCJEaW5hbWljUXVlcnlzQ29udHJvbGxlciIsImxvZGFzaCIsImxvYWRBdHRyaWJ1dGVzIiwibG9hZE9wZXJhdG9ycyIsImFkZEZpbHRlciIsInJ1bkZpbHRlciIsImVkaXRGaWx0ZXIiLCJsb2FkTW9kZWxzIiwicmVtb3ZlRmlsdGVyIiwiY2xlYXIiLCJyZXN0YXJ0Iiwid2hlcmUiLCJhZGRlZEZpbHRlcnMiLCJhdHRyaWJ1dGUiLCJvcGVyYXRvciIsInZhbHVlIiwiZmlsdGVycyIsImF0dHJpYnV0ZXMiLCJvcGVyYXRvcnMiLCJpbmRleE9mIiwiaXNVbmRlZmluZWQiLCJrZXlzIiwiT2JqZWN0Iiwia2V5Iiwic3RhcnRzV2l0aCIsIiRpbmRleCIsInNwbGljZSIsIkxhbmd1YWdlTG9hZGVyIiwiU3VwcG9ydFNlcnZpY2UiLCIkbG9nIiwiJGluamVjdG9yIiwic2VydmljZSIsInRyYW5zbGF0ZSIsInZpZXdzIiwiZGlhbG9nIiwibWVzc2FnZXMiLCJsYW5ncyIsInRBdHRyIiwiJGZpbHRlciIsInRCcmVhZGNydW1iIiwic3BsaXQiLCJ0TW9kZWwiLCJhdXRoZW50aWNhdGlvbkxpc3RlbmVyIiwiJG9uIiwiZXZlbnQiLCJ0b1N0YXRlIiwiY2F0Y2giLCJ3YXJuIiwicHJldmVudERlZmF1bHQiLCJhdXRob3JpemF0aW9uTGlzdGVuZXIiLCJoYXNQcm9maWxlIiwiYWxsUHJvZmlsZXMiLCJzcGlubmVySW50ZXJjZXB0b3IiLCIkaHR0cFByb3ZpZGVyIiwiJHByb3ZpZGUiLCJzaG93SGlkZVNwaW5uZXIiLCJyZXF1ZXN0IiwiaGlkZSIsInJlc3BvbnNlRXJyb3IiLCJyZWplY3Rpb24iLCJpbnRlcmNlcHRvcnMiLCJ0b2tlbkludGVyY2VwdG9yIiwicmVkaXJlY3RXaGVuU2VydmVyTG9nZ2VkT3V0IiwiaGVhZGVycyIsInJlamVjdGlvblJlYXNvbnMiLCJ0b2tlbkVycm9yIiwiaXMiLCJ2YWxpZGF0aW9uSW50ZXJjZXB0b3IiLCJzaG93RXJyb3JWYWxpZGF0aW9uIiwic2tpcFZhbGlkYXRpb24iLCJlcnJvclZhbGlkYXRpb24iLCJLYW5iYW5Db250cm9sbGVyIiwiVGFza3NTZXJ2aWNlIiwiU3RhdHVzU2VydmljZSIsIiRkb2N1bWVudCIsImZpZWxkcyIsIm1hcCIsImlzTW92ZWQiLCJjb2x1bW5zIiwidGV4dCIsImRhdGFGaWVsZCIsInNsdWciLCJjb2xsYXBzaWJsZSIsInRhZ3MiLCJwcmlvcml0eSIsInNvdXJjZSIsImxvY2FsRGF0YSIsImRhdGFUeXBlIiwiZGF0YUZpZWxkcyIsImRhdGFBZGFwdGVyIiwiJCIsImpxeCIsInNldHRpbmdzIiwia2FuYmFuUmVhZHkiLCJvbkl0ZW1Nb3ZlZCIsImRvbmUiLCJvd25lciIsInRhc2tfaWQiLCJhcmdzIiwiaXRlbUlkIiwibWlsZXN0b25lIiwidXBkYXRlVGFza0J5S2FuYmFuIiwib2xkQ29sdW1uIiwibmV3Q29sdW1uIiwib25JdGVtQ2xpY2tlZCIsInRhc2tJbmZvIiwicGFyZW50IiwiZWxlbWVudCIsImJvZHkiLCJiaW5kVG9Db250cm9sbGVyIiwiZXNjYXBlVG9DbG9zZSIsImNsaWNrT3V0c2lkZVRvQ2xvc2UiLCJLYW5iYW5TZXJ2aWNlIiwiTWVudUNvbnRyb2xsZXIiLCIkbWRTaWRlbmF2IiwiJG1kQ29sb3JzIiwib3BlbiIsIm9wZW5NZW51T3JSZWRpcmVjdFRvU3RhdGUiLCJtZW51UHJlZml4IiwiaXRlbnNNZW51IiwiaWNvbiIsInN1Ykl0ZW5zIiwic2lkZW5hdlN0eWxlIiwidG9wIiwiY29udGVudCIsInRleHRDb2xvciIsImNvbG9yIiwibGluZUJvdHRvbSIsImdldENvbG9yIiwidG9nZ2xlIiwiJG1kTWVudSIsImV2IiwiaXRlbSIsImNvbG9yUGFsZXR0ZXMiLCJnZXRUaGVtZUNvbG9yIiwiTWFpbHNDb250cm9sbGVyIiwiTWFpbHNTZXJ2aWNlIiwiZmlsdGVyU2VsZWN0ZWQiLCJza2luIiwibGFuZ3VhZ2UiLCJhbGxvd2VkQ29udGVudCIsImVudGl0aWVzIiwiaGVpZ2h0IiwiZXh0cmFQbHVnaW5zIiwibG9hZFVzZXJzIiwib3BlblVzZXJEaWFsb2ciLCJhZGRVc2VyTWFpbCIsInNlbmQiLCJjcml0ZXJpYSIsIm5hbWVPckVtYWlsIiwibm90VXNlcnMiLCJtYWlsIiwidXNlcnMiLCJwcm9wZXJ0eSIsInRvU3RyaW5nIiwibGltaXQiLCJmaW5kIiwib25Jbml0IiwidXNlckRpYWxvZ0lucHV0IiwidHJhbnNmZXJVc2VyRm4iLCJNaWxlc3RvbmVzQ29udHJvbGxlciIsIk1pbGVzdG9uZXNTZXJ2aWNlIiwiZXN0aW1hdGVkUHJpY2UiLCJlc3RpbWF0ZWRfdmFsdWUiLCJlc3RpbWF0ZWRUaW1lIiwiZGF0ZUVuZCIsImRhdGVfZW5kIiwiZGF0ZUJlZ2luIiwiZGF0ZV9iZWdpbiIsImRpZmYiLCJjb2xvcl9lc3RpbWF0ZWRfdGltZSIsInZpZXciLCJzZWFyY2hUYXNrIiwidGFza1Rlcm0iLCJtaWxlc3RvbmVTZWFyY2giLCJvblRhc2tDaGFuZ2UiLCJmaW5kSW5kZXgiLCJyZW1vdmVUYXNrIiwic2xpY2UiLCJzYXZlVGFza3MiLCJ1cGRhdGVNaWxlc3RvbmUiLCJtaWxlc3RvbmVfaWQiLCJ1cGRhdGVSZWxlYXNlIiwiUHJpb3JpdGllc1NlcnZpY2UiLCJQcm9qZWN0c0NvbnRyb2xsZXIiLCJSb2xlc1NlcnZpY2UiLCIkd2luZG93Iiwic2VhcmNoVXNlciIsImFkZFVzZXIiLCJyZW1vdmVVc2VyIiwidmlld1Byb2plY3QiLCJyb2xlcyIsInVzZXJfaWQiLCJ1c2Vyc0FycmF5IiwicXVlcnlsdGVycyIsInVzZXJOYW1lIiwiY2xpZW50X2lkIiwiY2xpZW50Iiwicm9sZSIsImRldl9pZCIsImRldmVsb3BlciIsInN0YWtlaG9sZGVyX2lkIiwic3Rha2Vob2xkZXIiLCJoaXN0b3J5QmFjayIsImhpc3RvcnkiLCJiYWNrIiwicGFyYW1zIiwiUmVsZWFzZXNDb250cm9sbGVyIiwiUmVsZWFzZXNTZXJ2aWNlIiwicmVsZWFzZSIsInJlbGVhc2VfaWQiLCJzZWFyY2hNaWxlc3RvbmUiLCJtaWxlc3RvbmVUZXJtIiwicmVsZWFzZVNlYXJjaCIsIm9uTWlsZXN0b25lQ2hhbmdlIiwibWlsZXN0b25lcyIsInJlbW92ZU1pbGVzdG9uZSIsInNhdmVNaWxlc3RvbmVzIiwicm9sZXNTdHIiLCJqb2luIiwiY2FjaGUiLCJUYXNrQ29tbWVudHNTZXJ2aWNlIiwic2F2ZVRhc2tDb21tZW50IiwicmVtb3ZlVGFza0NvbW1lbnQiLCJUYXNrc0NvbnRyb2xsZXIiLCJUeXBlc1NlcnZpY2UiLCJwcmlvcml0aWVzIiwic2F2ZUNvbW1lbnQiLCJjb21tZW50IiwiY29tbWVudF9pZCIsImFuc3dlciIsImNvbW1lbnRfdGV4dCIsInJlbW92ZUNvbW1lbnQiLCJQcm9maWxlQ29udHJvbGxlciIsInVwZGF0ZSIsImJpcnRoZGF5IiwidXBkYXRlUHJvZmlsZSIsIlVzZXJzQ29udHJvbGxlciIsImhpZGVEaWFsb2ciLCJzYXZlTmV3VXNlciIsImRlZmF1bHRzIiwib3ZlcnJpZGUiLCJhbGwiLCJ1c2VyUm9sZXMiLCJpbnRlcnNlY3Rpb24iLCJpc0FkbWluIiwiYnl0ZXMiLCJwcmVjaXNpb24iLCJpc05hTiIsImlzRmluaXRlIiwidW5pdHMiLCJudW1iZXIiLCJsb2ciLCJwb3ciLCJ0b0ZpeGVkIiwiVmNzQ29udHJvbGxlciIsIlZjc1NlcnZpY2UiLCJwYXRocyIsInRvZ2dsZVNwbGFzaFNjcmVlbiIsInVzZXJuYW1lIiwidXNlcm5hbWVfZ2l0aHViIiwicmVwbyIsInJlcG9fZ2l0aHViIiwicGF0aCIsImxvYWRpbmdfc2NyZWVuIiwiZmluaXNoIiwic29ydFJlc291cmNlcyIsImEiLCJiIiwib3BlbkZpbGVPckRpcmVjdG9yeSIsInBsZWFzZVdhaXQiLCJsb2dvIiwiYmFja2dyb3VuZENvbG9yIiwibG9hZGluZ0h0bWwiLCJjb21wb25lbnQiLCJyZXBsYWNlIiwidHJhbnNjbHVkZSIsInRvb2xiYXJCdXR0b25zIiwiZm9vdGVyQnV0dG9ucyIsImJpbmRpbmdzIiwiYm94VGl0bGUiLCJ0b29sYmFyQ2xhc3MiLCJ0b29sYmFyQmdDb2xvciIsIiR0cmFuc2NsdWRlIiwiY3RybCIsIiRvbkluaXQiLCJsYXlvdXRBbGlnbiIsImF1ZGl0RGV0YWlsVGl0bGUiLCJhdWRpdE1vZGVsIiwibW9kZWxJZCIsImF1ZGl0VHlwZSIsInR5cGVJZCIsImF1ZGl0VmFsdWUiLCJpc0RhdGUiLCJlbmRzV2l0aCIsIk51bWJlciIsImluaXRpYWxEYXRlIiwiZmluYWxEYXRlIiwic2NoZWR1bGVkX3RvIiwiZGF0ZV9zdGFydCIsImNvc3QiLCJob3VyVmFsdWVEZXZlbG9wZXIiLCJob3VyVmFsdWVDbGllbnQiLCJob3VyVmFsdWVGaW5hbCIsInJlbGVhc2VfZGF0ZSIsImNvbmZpcm1UaXRsZSIsImNvbmZpcm1EZXNjcmlwdGlvbiIsInJlbW92ZURlc2NyaXB0aW9uIiwiYXVkaXQiLCJjcmVhdGVkIiwidXBkYXRlZEJlZm9yZSIsInVwZGF0ZWRBZnRlciIsImRlbGV0ZWQiLCJyZXNldFBhc3N3b3JkIiwibG9hZGluZyIsInByb2Nlc3NpbmciLCJ5ZXMiLCJubyIsImludGVybmFsRXJyb3IiLCJub3RGb3VuZCIsIm5vdEF1dGhvcml6ZWQiLCJzZWFyY2hFcnJvciIsInNhdmVTdWNjZXNzIiwib3BlcmF0aW9uU3VjY2VzcyIsIm9wZXJhdGlvbkVycm9yIiwic2F2ZUVycm9yIiwicmVtb3ZlU3VjY2VzcyIsInJlbW92ZUVycm9yIiwicmVzb3VyY2VOb3RGb3VuZEVycm9yIiwibm90TnVsbEVycm9yIiwiZHVwbGljYXRlZFJlc291cmNlRXJyb3IiLCJzcHJpbnRFbmRlZFN1Y2Nlc3MiLCJzcHJpbnRFbmRlZEVycm9yIiwic3VjY2Vzc1NpZ25VcCIsImVycm9yc1NpZ25VcCIsInJlbGVhc2V0RW5kZWRTdWNjZXNzIiwicmVsZWFzZUVuZGVkRXJyb3IiLCJwcm9qZWN0RW5kZWRTdWNjZXNzIiwicHJvamVjdEVuZGVkRXJyb3IiLCJ2YWxpZGF0ZSIsImZpZWxkUmVxdWlyZWQiLCJsYXlvdXQiLCJlcnJvcjQwNCIsImxvZ291dEluYWN0aXZlIiwiaW52YWxpZENyZWRlbnRpYWxzIiwidW5rbm93bkVycm9yIiwidXNlck5vdEZvdW5kIiwiZGFzaGJvYXJkIiwid2VsY29tZSIsIm1haWxFcnJvcnMiLCJzZW5kTWFpbFN1Y2Nlc3MiLCJzZW5kTWFpbEVycm9yIiwicGFzc3dvcmRTZW5kaW5nU3VjY2VzcyIsInJlbW92ZVlvdXJTZWxmRXJyb3IiLCJ1c2VyRXhpc3RzIiwicHJvZmlsZSIsInVwZGF0ZUVycm9yIiwicXVlcnlEaW5hbWljIiwibm9GaWx0ZXIiLCJicmVhZGNydW1icyIsInByb2plY3RzIiwia2FuYmFuIiwidmNzIiwicmVsZWFzZXMiLCJ0aXRsZXMiLCJtYWlsU2VuZCIsInRhc2tMaXN0IiwidXNlckxpc3QiLCJhdWRpdExpc3QiLCJyZWdpc3RlciIsImNsZWFyQWxsIiwibGlzdCIsImdldE91dCIsImFkZCIsImluIiwibG9hZEltYWdlIiwic2lnbnVwIiwiY3JpYXJQcm9qZXRvIiwicHJvamVjdExpc3QiLCJ0YXNrc0xpc3QiLCJtaWxlc3RvbmVzTGlzdCIsInJlcGx5IiwiYWN0aW9uIiwiZGF0ZVN0YXJ0IiwiYWxsUmVzb3VyY2VzIiwidXBkYXRlZCIsImNvbmZpcm1QYXNzd29yZCIsInRvIiwic3ViamVjdCIsInJlc3VsdHMiLCJlcXVhbHMiLCJkaWZlcmVudCIsImNvbnRlaW5zIiwic3RhcnRXaXRoIiwiZmluaXNoV2l0aCIsImJpZ2dlclRoYW4iLCJlcXVhbHNPckJpZ2dlclRoYW4iLCJsZXNzVGhhbiIsImVxdWFsc09yTGVzc1RoYW4iLCJ0b3RhbFRhc2siLCJwZXJmaWxzIiwibWVudSIsInRvb2x0aXBzIiwicGVyZmlsIiwidHJhbnNmZXIiLCJsaXN0VGFzayIsIlRhc2tJbmZvQ29udHJvbGxlciIsImNvbnNvbGUiLCJVc2Vyc0RpYWxvZ0NvbnRyb2xsZXIiLCJ0cmFuc2ZlclVzZXIiXSwibWFwcGluZ3MiOiJBQUFBOzs7QUNDQSxDQUFDLFlBQVc7RUFDVjs7RUFFQUEsUUFBUUMsT0FBTyxPQUFPLENBQ3BCLGFBQ0EsVUFDQSxhQUNBLFlBQ0Esa0JBQ0EsYUFDQSxjQUNBLGdCQUNBLGlCQUNBLHdCQUNBLDBCQUNBLHFCQUNBLGNBQ0EsYUFDQSxXQUNBLFdBQ0E7O0FEYko7O0FFUkMsQ0FBQSxZQUFZO0VBQ1g7OztFQUVBRCxRQUNHQyxPQUFPLE9BQ1BDLE9BQU9BOzs7O0VBSVYsU0FBU0EsT0FBT0MsUUFBUUMsb0JBQW9CQztFQUMxQ0Msb0JBQW9CQyxRQUFRQyxpQkFBaUJDLHVCQUF1Qjs7SUFFcEVILG1CQUNHSSxVQUFVLGtCQUNWQyx5QkFBeUI7O0lBRTVCTCxtQkFBbUJNLGlCQUFpQjs7SUFFcENMLE9BQU9NLE9BQU87OztJQUdkUixzQkFBc0JTLGVBQWVDLFNBQVNaLE9BQU9hOzs7SUFHckRaLG1CQUFtQmEsTUFBTSxXQUN0QkMsZUFBZSxRQUFRO01BQ3RCQyxTQUFTO09BRVZDLGNBQWMsU0FDZEMsWUFBWTs7O0lBR2ZqQixtQkFBbUJrQjs7SUFFbkJkLGdCQUFnQmU7O0lBRWhCZCxzQkFBc0JlLGFBQWEsVUFBU0MsTUFBTTtNQUNoRCxPQUFPQSxPQUFPbEIsT0FBT2tCLE1BQU1DLE9BQU8sZ0JBQWdCOzs7O0FGT3hEOztBRzVDQSxDQUFDLFlBQVc7O0VBRVY7OztFQUVBMUIsUUFDR0MsT0FBTyxPQUNQMEIsV0FBVyxpQkFBaUJDOzs7Ozs7O0VBTy9CLFNBQVNBLGNBQWNDLFFBQVFDLE1B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Ozs7O0VBSXZDLFNBQVNBLHNCQUFzQnJsQixhQUFhMEMsY0FBY3hDO0VBQ3hEeVYsaUJBQWlCRCxRQUFROztJQUV6QixJQUFJclosS0FBSzs7SUFFVEEsR0FBRzhELGFBQWFBO0lBQ2hCOUQsR0FBRytELGVBQWVBO0lBQ2xCL0QsR0FBR3NGLFFBQVFBOztJQUVYLElBQUlySCxRQUFRc00sVUFBVStPLGtCQUFrQjtNQUN0Q3RaLEdBQUdpcEIsZUFBZTNQLGdCQUFnQkM7Ozs7SUFJcEM1VixZQUFZLGtCQUFrQjtNQUM1QjNELElBQUlBO01BQ0ppRSxjQUFjb0M7TUFDZHdELGNBQWN3UDtNQUNkblYsU0FBUztRQUNQNEYsU0FBUzs7OztJQUliLFNBQVNoRyxhQUFhO01BQ3BCOUQsR0FBR29FLGVBQWU7OztJQUdwQixTQUFTTCxlQUFlO01BQ3RCLE9BQU85RixRQUFRa0gsT0FBT25GLEdBQUdrRixxQkFBcUJsRixHQUFHb0U7OztJQUduRCxTQUFTa0IsUUFBUTtNQUNmekIsU0FBU3lCOzs7S0ExQ2YiLCJmaWxlIjoiYXBwbGljYXRpb24uanMiLCJzb3VyY2VzQ29udGVudCI6WyIndXNlIHN0cmljdCc7XG5cbi8qZXNsaW50IGFuZ3VsYXIvZmlsZS1uYW1lOiAwKi9cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJywgWyduZ0FuaW1hdGUnLCAnbmdBcmlhJywgJ3VpLnJvdXRlcicsICduZ1Byb2RlYicsICd1aS51dGlscy5tYXNrcycsICd0ZXh0LW1hc2snLCAnbmdNYXRlcmlhbCcsICdtb2RlbEZhY3RvcnknLCAnbWQuZGF0YS50YWJsZScsICduZ01hdGVyaWFsRGF0ZVBpY2tlcicsICdwYXNjYWxwcmVjaHQudHJhbnNsYXRlJywgJ2FuZ3VsYXJGaWxlVXBsb2FkJywgJ25nTWVzc2FnZXMnLCAnanF3aWRnZXRzJywgJ3VpLm1hc2snLCAnbmdSb3V0ZScsICduZ1Nhbml0aXplJ10pO1xufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25maWcoY29uZmlnKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIGNvbmZpZyhHbG9iYWwsICRtZFRoZW1pbmdQcm92aWRlciwgJG1vZGVsRmFjdG9yeVByb3ZpZGVyLCAvLyBOT1NPTkFSXG4gICR0cmFuc2xhdGVQcm92aWRlciwgbW9tZW50LCAkbWRBcmlhUHJvdmlkZXIsICRtZERhdGVMb2NhbGVQcm92aWRlcikge1xuXG4gICAgJHRyYW5zbGF0ZVByb3ZpZGVyLnVzZUxvYWRlcignbGFuZ3VhZ2VMb2FkZXInKS51c2VTYW5pdGl6ZVZhbHVlU3RyYXRlZ3koJ2VzY2FwZScpO1xuXG4gICAgJHRyYW5zbGF0ZVByb3ZpZGVyLnVzZVBvc3RDb21waWxpbmcodHJ1ZSk7XG5cbiAgICBtb21lbnQubG9jYWxlKCdwdC1CUicpO1xuXG4gICAgLy9vcyBzZXJ2acOnb3MgcmVmZXJlbnRlIGFvcyBtb2RlbHMgdmFpIHV0aWxpemFyIGNvbW8gYmFzZSBuYXMgdXJsc1xuICAgICRtb2RlbEZhY3RvcnlQcm92aWRlci5kZWZhdWx0T3B0aW9ucy5wcmVmaXggPSBHbG9iYWwuYXBpUGF0aDtcblxuICAgIC8vIENvbmZpZ3VyYXRpb24gdGhlbWVcbiAgICAkbWRUaGVtaW5nUHJvdmlkZXIudGhlbWUoJ2RlZmF1bHQnKS5wcmltYXJ5UGFsZXR0ZSgnZ3JleScsIHtcbiAgICAgIGRlZmF1bHQ6ICc4MDAnXG4gICAgfSkuYWNjZW50UGFsZXR0ZSgnYW1iZXInKS53YXJuUGFsZXR0ZSgnZGVlcC1vcmFuZ2UnKTtcblxuICAgIC8vIEVuYWJsZSBicm93c2VyIGNvbG9yXG4gICAgJG1kVGhlbWluZ1Byb3ZpZGVyLmVuYWJsZUJyb3dzZXJDb2xvcigpO1xuXG4gICAgJG1kQXJpYVByb3ZpZGVyLmRpc2FibGVXYXJuaW5ncygpO1xuXG4gICAgJG1kRGF0ZUxvY2FsZVByb3ZpZGVyLmZvcm1hdERhdGUgPSBmdW5jdGlvbiAoZGF0ZSkge1xuICAgICAgcmV0dXJuIGRhdGUgPyBtb21lbnQoZGF0ZSkuZm9ybWF0KCdERC9NTS9ZWVlZJykgOiAnJztcbiAgICB9O1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29udHJvbGxlcignQXBwQ29udHJvbGxlcicsIEFwcENvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLyoqXG4gICAqIENvbnRyb2xhZG9yIHJlc3BvbnPDoXZlbCBwb3IgZnVuY2lvbmFsaWRhZGVzIHF1ZSBzw6NvIGFjaW9uYWRhcyBlbSBxdWFscXVlciB0ZWxhIGRvIHNpc3RlbWFcbiAgICpcbiAgICovXG4gIGZ1bmN0aW9uIEFwcENvbnRyb2xsZXIoJHN0YXRlLCBBdXRoLCBHbG9iYWwpIHtcbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgLy9hbm8gYXR1YWwgcGFyYSBzZXIgZXhpYmlkbyBubyByb2RhcMOpIGRvIHNpc3RlbWFcbiAgICB2bS5hbm9BdHVhbCA9IG51bGw7XG4gICAgdm0uYWN0aXZlUHJvamVjdCA9IG51bGw7XG5cbiAgICB2bS5sb2dvdXQgPSBsb2dvdXQ7XG4gICAgdm0uZ2V0SW1hZ2VQZXJmaWwgPSBnZXRJbWFnZVBlcmZpbDtcbiAgICB2bS5nZXRMb2dvTWVudSA9IGdldExvZ29NZW51O1xuICAgIHZtLnNldEFjdGl2ZVByb2plY3QgPSBzZXRBY3RpdmVQcm9qZWN0O1xuICAgIHZtLmdldEFjdGl2ZVByb2plY3QgPSBnZXRBY3RpdmVQcm9qZWN0O1xuICAgIHZtLnJlbW92ZUFjdGl2ZVByb2plY3QgPSByZW1vdmVBY3RpdmVQcm9qZWN0O1xuXG4gICAgYWN0aXZhdGUoKTtcblxuICAgIGZ1bmN0aW9uIGFjdGl2YXRlKCkge1xuICAgICAgdmFyIGRhdGUgPSBuZXcgRGF0ZSgpO1xuXG4gICAgICB2bS5hbm9BdHVhbCA9IGRhdGUuZ2V0RnVsbFllYXIoKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBsb2dvdXQoKSB7XG4gICAgICBBdXRoLmxvZ291dCgpLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICAkc3RhdGUuZ28oR2xvYmFsLmxvZ2luU3RhdGUpO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gZ2V0SW1hZ2VQZXJmaWwoKSB7XG4gICAgICByZXR1cm4gQXV0aC5jdXJyZW50VXNlciAmJiBBdXRoLmN1cnJlbnRVc2VyLmltYWdlID8gQXV0aC5jdXJyZW50VXNlci5pbWFnZSA6IEdsb2JhbC5pbWFnZVBhdGggKyAnL25vX2F2YXRhci5naWYnO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGdldExvZ29NZW51KCkge1xuICAgICAgcmV0dXJuIEdsb2JhbC5pbWFnZVBhdGggKyAnL2xvZ28tdmVydGljYWwucG5nJztcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBzZXRBY3RpdmVQcm9qZWN0KHByb2plY3QpIHtcbiAgICAgIGxvY2FsU3RvcmFnZS5zZXRJdGVtKCdwcm9qZWN0JywgcHJvamVjdCk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gZ2V0QWN0aXZlUHJvamVjdCgpIHtcbiAgICAgIHJldHVybiBsb2NhbFN0b3JhZ2UuZ2V0SXRlbSgncHJvamVjdCcpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIHJlbW92ZUFjdGl2ZVByb2plY3QoKSB7XG4gICAgICBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbSgncHJvamVjdCcpO1xuICAgIH1cbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuLyplc2xpbnQgYW5ndWxhci9maWxlLW5hbWU6IDAsIG5vLXVuZGVmOiAwKi9cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICAvKipcbiAgICogVHJhbnNmb3JtYSBiaWJsaW90ZWNhcyBleHRlcm5hcyBlbSBzZXJ2acOnb3MgZG8gYW5ndWxhciBwYXJhIHNlciBwb3Nzw612ZWwgdXRpbGl6YXJcbiAgICogYXRyYXbDqXMgZGEgaW5qZcOnw6NvIGRlIGRlcGVuZMOqbmNpYVxuICAgKi9cblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29uc3RhbnQoJ2xvZGFzaCcsIF8pLmNvbnN0YW50KCdtb21lbnQnLCBtb21lbnQpO1xufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25zdGFudCgnR2xvYmFsJywge1xuICAgIGFwcE5hbWU6ICdGcmVlbGFnaWxlJyxcbiAgICBob21lU3RhdGU6ICdhcHAucHJvamVjdHMnLFxuICAgIGxvZ2luVXJsOiAnYXBwL2xvZ2luJyxcbiAgICByZXNldFBhc3N3b3JkVXJsOiAnYXBwL3Bhc3N3b3JkL3Jlc2V0JyxcbiAgICBsb2dpblN0YXRlOiAnYXBwLmxvZ2luJyxcbiAgICByZXNldFBhc3N3b3JkU3RhdGU6ICdhcHAucGFzc3dvcmQtcmVzZXQnLFxuICAgIG5vdEF1dGhvcml6ZWRTdGF0ZTogJ2FwcC5ub3QtYXV0aG9yaXplZCcsXG4gICAgdG9rZW5LZXk6ICdzZXJ2ZXJfdG9rZW4nLFxuICAgIGNsaWVudFBhdGg6ICdjbGllbnQvYXBwJyxcbiAgICBhcGlQYXRoOiAnYXBpL3YxJyxcbiAgICBpbWFnZVBhdGg6ICdjbGllbnQvaW1hZ2VzJ1xuICB9KTtcbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsICR1cmxSb3V0ZXJQcm92aWRlciwgR2xvYmFsKSB7XG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ2FwcCcsIHtcbiAgICAgIHVybDogJy9hcHAnLFxuICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9sYXlvdXQvYXBwLmh0bWwnLFxuICAgICAgYWJzdHJhY3Q6IHRydWUsXG4gICAgICByZXNvbHZlOiB7IC8vZW5zdXJlIGxhbmdzIGlzIHJlYWR5IGJlZm9yZSByZW5kZXIgdmlld1xuICAgICAgICB0cmFuc2xhdGVSZWFkeTogWyckdHJhbnNsYXRlJywgJyRxJywgZnVuY3Rpb24gKCR0cmFuc2xhdGUsICRxKSB7XG4gICAgICAgICAgdmFyIGRlZmVycmVkID0gJHEuZGVmZXIoKTtcblxuICAgICAgICAgICR0cmFuc2xhdGUudXNlKCdwdC1CUicpLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgZGVmZXJyZWQucmVzb2x2ZSgpO1xuICAgICAgICAgIH0pO1xuXG4gICAgICAgICAgcmV0dXJuIGRlZmVycmVkLnByb21pc2U7XG4gICAgICAgIH1dXG4gICAgICB9XG4gICAgfSkuc3RhdGUoR2xvYmFsLm5vdEF1dGhvcml6ZWRTdGF0ZSwge1xuICAgICAgdXJsOiAnL2FjZXNzby1uZWdhZG8nLFxuICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9sYXlvdXQvbm90LWF1dGhvcml6ZWQuaHRtbCcsXG4gICAgICBkYXRhOiB7IG5lZWRBdXRoZW50aWNhdGlvbjogZmFsc2UgfVxuICAgIH0pO1xuXG4gICAgJHVybFJvdXRlclByb3ZpZGVyLndoZW4oJy9wYXNzd29yZC9yZXNldCcsIEdsb2JhbC5yZXNldFBhc3N3b3JkVXJsKTtcbiAgICAkdXJsUm91dGVyUHJvdmlkZXIud2hlbignL2FwcCcsIEdsb2JhbC5sb2dpblVybCk7XG4gICAgJHVybFJvdXRlclByb3ZpZGVyLm90aGVyd2lzZShHbG9iYWwubG9naW5VcmwpO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLnJ1bihydW4pO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gcnVuKCRyb290U2NvcGUsICRzdGF0ZSwgJHN0YXRlUGFyYW1zLCBBdXRoLCBHbG9iYWwpIHtcbiAgICAvLyBOT1NPTkFSXG4gICAgLy9zZXRhZG8gbm8gcm9vdFNjb3BlIHBhcmEgcG9kZXIgc2VyIGFjZXNzYWRvIG5hcyB2aWV3cyBzZW0gcHJlZml4byBkZSBjb250cm9sbGVyXG4gICAgJHJvb3RTY29wZS4kc3RhdGUgPSAkc3RhdGU7XG4gICAgJHJvb3RTY29wZS4kc3RhdGVQYXJhbXMgPSAkc3RhdGVQYXJhbXM7XG4gICAgJHJvb3RTY29wZS5hdXRoID0gQXV0aDtcbiAgICAkcm9vdFNjb3BlLmdsb2JhbCA9IEdsb2JhbDtcblxuICAgIC8vbm8gaW5pY2lvIGNhcnJlZ2EgbyB1c3XDoXJpbyBkbyBsb2NhbHN0b3JhZ2UgY2FzbyBvIHVzdcOhcmlvIGVzdGFqYSBhYnJpbmRvIG8gbmF2ZWdhZG9yXG4gICAgLy9wYXJhIHZvbHRhciBhdXRlbnRpY2Fkb1xuICAgIEF1dGgucmV0cmlldmVVc2VyRnJvbUxvY2FsU3RvcmFnZSgpO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29udHJvbGxlcignQXVkaXRDb250cm9sbGVyJywgQXVkaXRDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIEF1ZGl0Q29udHJvbGxlcigkY29udHJvbGxlciwgQXVkaXRTZXJ2aWNlLCBQckRpYWxvZywgR2xvYmFsLCAkdHJhbnNsYXRlKSB7XG4gICAgLy8gTk9TT05BUlxuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICB2bS5vbkFjdGl2YXRlID0gb25BY3RpdmF0ZTtcbiAgICB2bS5hcHBseUZpbHRlcnMgPSBhcHBseUZpbHRlcnM7XG4gICAgdm0udmlld0RldGFpbCA9IHZpZXdEZXRhaWw7XG5cbiAgICAkY29udHJvbGxlcignQ1JVRENvbnRyb2xsZXInLCB7IHZtOiB2bSwgbW9kZWxTZXJ2aWNlOiBBdWRpdFNlcnZpY2UsIG9wdGlvbnM6IHt9IH0pO1xuXG4gICAgZnVuY3Rpb24gb25BY3RpdmF0ZSgpIHtcbiAgICAgIHZtLm1vZGVscyA9IFtdO1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0ge307XG5cbiAgICAgIC8vUGVnYSB0b2RvcyBvcyBtb2RlbHMgZG8gc2VydmVyIGUgbW9udGEgdW1hIGxpc3RhIHBybyBDb21ib0JveFxuICAgICAgQXVkaXRTZXJ2aWNlLmdldEF1ZGl0ZWRNb2RlbHMoKS50aGVuKGZ1bmN0aW9uIChkYXRhKSB7XG4gICAgICAgIHZhciBtb2RlbHMgPSBbeyBpZDogJycsIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ2dsb2JhbC5hbGwnKSB9XTtcblxuICAgICAgICBkYXRhLm1vZGVscy5zb3J0KCk7XG5cbiAgICAgICAgZm9yICh2YXIgaW5kZXggPSAwOyBpbmRleCA8IGRhdGEubW9kZWxzLmxlbmd0aDsgaW5kZXgrKykge1xuICAgICAgICAgIHZhciBtb2RlbCA9IGRhdGEubW9kZWxzW2luZGV4XTtcblxuICAgICAgICAgIG1vZGVscy5wdXNoKHtcbiAgICAgICAgICAgIGlkOiBtb2RlbCxcbiAgICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ21vZGVscy4nICsgbW9kZWwudG9Mb3dlckNhc2UoKSlcbiAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHZtLm1vZGVscyA9IG1vZGVscztcbiAgICAgICAgdm0ucXVlcnlGaWx0ZXJzLm1vZGVsID0gdm0ubW9kZWxzWzBdLmlkO1xuICAgICAgfSk7XG5cbiAgICAgIHZtLnR5cGVzID0gQXVkaXRTZXJ2aWNlLmxpc3RUeXBlcygpO1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzLnR5cGUgPSB2bS50eXBlc1swXS5pZDtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBhcHBseUZpbHRlcnMoZGVmYXVsdFF1ZXJ5RmlsdGVycykge1xuICAgICAgcmV0dXJuIGFuZ3VsYXIuZXh0ZW5kKGRlZmF1bHRRdWVyeUZpbHRlcnMsIHZtLnF1ZXJ5RmlsdGVycyk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gdmlld0RldGFpbChhdWRpdERldGFpbCkge1xuICAgICAgdmFyIGNvbmZpZyA9IHtcbiAgICAgICAgbG9jYWxzOiB7IGF1ZGl0RGV0YWlsOiBhdWRpdERldGFpbCB9LFxuICAgICAgICAvKiogQG5nSW5qZWN0ICovXG4gICAgICAgIGNvbnRyb2xsZXI6IGZ1bmN0aW9uIGNvbnRyb2xsZXIoYXVkaXREZXRhaWwsIFByRGlhbG9nKSB7XG4gICAgICAgICAgdmFyIHZtID0gdGhpcztcblxuICAgICAgICAgIHZtLmNsb3NlID0gY2xvc2U7XG5cbiAgICAgICAgICBhY3RpdmF0ZSgpO1xuXG4gICAgICAgICAgZnVuY3Rpb24gYWN0aXZhdGUoKSB7XG4gICAgICAgICAgICBpZiAoYW5ndWxhci5pc0FycmF5KGF1ZGl0RGV0YWlsLm9sZCkgJiYgYXVkaXREZXRhaWwub2xkLmxlbmd0aCA9PT0gMCkgYXVkaXREZXRhaWwub2xkID0gbnVsbDtcbiAgICAgICAgICAgIGlmIChhbmd1bGFyLmlzQXJyYXkoYXVkaXREZXRhaWwubmV3KSAmJiBhdWRpdERldGFpbC5uZXcubGVuZ3RoID09PSAwKSBhdWRpdERldGFpbC5uZXcgPSBudWxsO1xuXG4gICAgICAgICAgICB2bS5hdWRpdERldGFpbCA9IGF1ZGl0RGV0YWlsO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIGZ1bmN0aW9uIGNsb3NlKCkge1xuICAgICAgICAgICAgUHJEaWFsb2cuY2xvc2UoKTtcbiAgICAgICAgICB9XG4gICAgICAgIH0sXG4gICAgICAgIGNvbnRyb2xsZXJBczogJ2F1ZGl0RGV0YWlsQ3RybCcsXG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvYXVkaXQvYXVkaXQtZGV0YWlsLmh0bWwnLFxuICAgICAgICBoYXNCYWNrZHJvcDogdHJ1ZVxuICAgICAgfTtcblxuICAgICAgUHJEaWFsb2cuY3VzdG9tKGNvbmZpZyk7XG4gICAgfVxuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKlxuICAgKiBBcnF1aXZvIGRlIGNvbmZpZ3VyYcOnw6NvIGNvbSBhcyByb3RhcyBlc3BlY8OtZmljYXMgZGUgYXVkaXRvcmlhXG4gICAqXG4gICAqIEBwYXJhbSB7YW55fSAkc3RhdGVQcm92aWRlclxuICAgKiBAcGFyYW0ge2FueX0gR2xvYmFsXG4gICAqL1xuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvdXRlcygkc3RhdGVQcm92aWRlciwgR2xvYmFsKSB7XG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ2FwcC5hdWRpdCcsIHtcbiAgICAgIHVybDogJy9hdWRpdG9yaWEnLFxuICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9hdWRpdC9hdWRpdC5odG1sJyxcbiAgICAgIGNvbnRyb2xsZXI6ICdBdWRpdENvbnRyb2xsZXIgYXMgYXVkaXRDdHJsJyxcbiAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiB0cnVlLCBuZWVkUHJvZmlsZTogWydhZG1pbiddIH1cbiAgICB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5mYWN0b3J5KCdBdWRpdFNlcnZpY2UnLCBBdWRpdFNlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gQXVkaXRTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5LCAkdHJhbnNsYXRlKSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCdhdWRpdCcsIHtcbiAgICAgIGFjdGlvbnM6IHtcbiAgICAgICAgZ2V0QXVkaXRlZE1vZGVsczoge1xuICAgICAgICAgIG1ldGhvZDogJ0dFVCcsXG4gICAgICAgICAgdXJsOiAnbW9kZWxzJ1xuICAgICAgICB9XG4gICAgICB9LFxuICAgICAgaW5zdGFuY2U6IHt9LFxuICAgICAgbGlzdFR5cGVzOiBmdW5jdGlvbiBsaXN0VHlwZXMoKSB7XG4gICAgICAgIHZhciBhdWRpdFBhdGggPSAndmlld3MuZmllbGRzLmF1ZGl0Lic7XG5cbiAgICAgICAgcmV0dXJuIFt7IGlkOiAnJywgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudChhdWRpdFBhdGggKyAnYWxsUmVzb3VyY2VzJykgfSwgeyBpZDogJ2NyZWF0ZWQnLCBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KGF1ZGl0UGF0aCArICd0eXBlLmNyZWF0ZWQnKSB9LCB7IGlkOiAndXBkYXRlZCcsIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoYXVkaXRQYXRoICsgJ3R5cGUudXBkYXRlZCcpIH0sIHsgaWQ6ICdkZWxldGVkJywgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudChhdWRpdFBhdGggKyAndHlwZS5kZWxldGVkJykgfV07XG4gICAgICB9XG4gICAgfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqXG4gICAqIEFycXVpdm8gZGUgY29uZmlndXJhw6fDo28gY29tIGFzIHJvdGFzIGVzcGVjw61maWNhcyBkbyByZWN1cnNvIHVzZXJcbiAgICpcbiAgICogQHBhcmFtIHthbnl9ICRzdGF0ZVByb3ZpZGVyXG4gICAqIEBwYXJhbSB7YW55fSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZShHbG9iYWwucmVzZXRQYXNzd29yZFN0YXRlLCB7XG4gICAgICB1cmw6ICcvcGFzc3dvcmQvcmVzZXQvOnRva2VuJyxcbiAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvYXV0aC9yZXNldC1wYXNzLWZvcm0uaHRtbCcsXG4gICAgICBjb250cm9sbGVyOiAnUGFzc3dvcmRDb250cm9sbGVyIGFzIHBhc3NDdHJsJyxcbiAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiBmYWxzZSB9XG4gICAgfSkuc3RhdGUoR2xvYmFsLmxvZ2luU3RhdGUsIHtcbiAgICAgIHVybDogJy9sb2dpbicsXG4gICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL2F1dGgvbG9naW4uaHRtbCcsXG4gICAgICBjb250cm9sbGVyOiAnTG9naW5Db250cm9sbGVyIGFzIGxvZ2luQ3RybCcsXG4gICAgICBkYXRhOiB7IG5lZWRBdXRoZW50aWNhdGlvbjogZmFsc2UgfVxuICAgIH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZhY3RvcnkoJ0F1dGgnLCBBdXRoKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIEF1dGgoJGh0dHAsICRxLCBHbG9iYWwsIFVzZXJzU2VydmljZSkge1xuICAgIC8vIE5PU09OQVJcbiAgICB2YXIgYXV0aCA9IHtcbiAgICAgIGxvZ2luOiBsb2dpbixcbiAgICAgIGxvZ291dDogbG9nb3V0LFxuICAgICAgdXBkYXRlQ3VycmVudFVzZXI6IHVwZGF0ZUN1cnJlbnRVc2VyLFxuICAgICAgcmV0cmlldmVVc2VyRnJvbUxvY2FsU3RvcmFnZTogcmV0cmlldmVVc2VyRnJvbUxvY2FsU3RvcmFnZSxcbiAgICAgIGF1dGhlbnRpY2F0ZWQ6IGF1dGhlbnRpY2F0ZWQsXG4gICAgICBzZW5kRW1haWxSZXNldFBhc3N3b3JkOiBzZW5kRW1haWxSZXNldFBhc3N3b3JkLFxuICAgICAgcmVtb3RlVmFsaWRhdGVUb2tlbjogcmVtb3RlVmFsaWRhdGVUb2tlbixcbiAgICAgIGdldFRva2VuOiBnZXRUb2tlbixcbiAgICAgIHNldFRva2VuOiBzZXRUb2tlbixcbiAgICAgIGNsZWFyVG9rZW46IGNsZWFyVG9rZW4sXG4gICAgICBjdXJyZW50VXNlcjogbnVsbFxuICAgIH07XG5cbiAgICBmdW5jdGlvbiBjbGVhclRva2VuKCkge1xuICAgICAgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oR2xvYmFsLnRva2VuS2V5KTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBzZXRUb2tlbih0b2tlbikge1xuICAgICAgbG9jYWxTdG9yYWdlLnNldEl0ZW0oR2xvYmFsLnRva2VuS2V5LCB0b2tlbik7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gZ2V0VG9rZW4oKSB7XG4gICAgICByZXR1cm4gbG9jYWxTdG9yYWdlLmdldEl0ZW0oR2xvYmFsLnRva2VuS2V5KTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiByZW1vdGVWYWxpZGF0ZVRva2VuKCkge1xuICAgICAgdmFyIGRlZmVycmVkID0gJHEuZGVmZXIoKTtcblxuICAgICAgaWYgKGF1dGguYXV0aGVudGljYXRlZCgpKSB7XG4gICAgICAgICRodHRwLmdldChHbG9iYWwuYXBpUGF0aCArICcvYXV0aGVudGljYXRlL2NoZWNrJykudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgZGVmZXJyZWQucmVzb2x2ZSh0cnVlKTtcbiAgICAgICAgfSwgZnVuY3Rpb24gKCkge1xuICAgICAgICAgIGF1dGgubG9nb3V0KCk7XG5cbiAgICAgICAgICBkZWZlcnJlZC5yZWplY3QoZmFsc2UpO1xuICAgICAgICB9KTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIGF1dGgubG9nb3V0KCk7XG5cbiAgICAgICAgZGVmZXJyZWQucmVqZWN0KGZhbHNlKTtcbiAgICAgIH1cblxuICAgICAgcmV0dXJuIGRlZmVycmVkLnByb21pc2U7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogVmVyaWZpY2Egc2UgbyB1c3XDoXJpbyBlc3TDoSBhdXRlbnRpY2Fkb1xuICAgICAqXG4gICAgICogQHJldHVybnMge2Jvb2xlYW59XG4gICAgICovXG4gICAgZnVuY3Rpb24gYXV0aGVudGljYXRlZCgpIHtcbiAgICAgIHJldHVybiBhdXRoLmdldFRva2VuKCkgIT09IG51bGw7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVjdXBlcmEgbyB1c3XDoXJpbyBkbyBsb2NhbFN0b3JhZ2VcbiAgICAgKi9cbiAgICBmdW5jdGlvbiByZXRyaWV2ZVVzZXJGcm9tTG9jYWxTdG9yYWdlKCkge1xuICAgICAgdmFyIHVzZXIgPSBsb2NhbFN0b3JhZ2UuZ2V0SXRlbSgndXNlcicpO1xuXG4gICAgICBpZiAodXNlcikge1xuICAgICAgICBhdXRoLmN1cnJlbnRVc2VyID0gYW5ndWxhci5tZXJnZShuZXcgVXNlcnNTZXJ2aWNlKCksIGFuZ3VsYXIuZnJvbUpzb24odXNlcikpO1xuICAgICAgfVxuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEd1YXJkYSBvIHVzdcOhcmlvIG5vIGxvY2FsU3RvcmFnZSBwYXJhIGNhc28gbyB1c3XDoXJpbyBmZWNoZSBlIGFicmEgbyBuYXZlZ2Fkb3JcbiAgICAgKiBkZW50cm8gZG8gdGVtcG8gZGUgc2Vzc8OjbyBzZWphIHBvc3PDrXZlbCByZWN1cGVyYXIgbyB0b2tlbiBhdXRlbnRpY2Fkby5cbiAgICAgKlxuICAgICAqIE1hbnTDqW0gYSB2YXJpw6F2ZWwgYXV0aC5jdXJyZW50VXNlciBwYXJhIGZhY2lsaXRhciBvIGFjZXNzbyBhbyB1c3XDoXJpbyBsb2dhZG8gZW0gdG9kYSBhIGFwbGljYcOnw6NvXG4gICAgICpcbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSB1c2VyIFVzdcOhcmlvIGEgc2VyIGF0dWFsaXphZG8uIENhc28gc2VqYSBwYXNzYWRvIG51bGwgbGltcGFcbiAgICAgKiB0b2RhcyBhcyBpbmZvcm1hw6fDtWVzIGRvIHVzdcOhcmlvIGNvcnJlbnRlLlxuICAgICAqL1xuICAgIGZ1bmN0aW9uIHVwZGF0ZUN1cnJlbnRVc2VyKHVzZXIpIHtcbiAgICAgIHZhciBkZWZlcnJlZCA9ICRxLmRlZmVyKCk7XG5cbiAgICAgIGlmICh1c2VyKSB7XG4gICAgICAgIHVzZXIgPSBhbmd1bGFyLm1lcmdlKG5ldyBVc2Vyc1NlcnZpY2UoKSwgdXNlcik7XG5cbiAgICAgICAgdmFyIGpzb25Vc2VyID0gYW5ndWxhci50b0pzb24odXNlcik7XG5cbiAgICAgICAgbG9jYWxTdG9yYWdlLnNldEl0ZW0oJ3VzZXInLCBqc29uVXNlcik7XG4gICAgICAgIGF1dGguY3VycmVudFVzZXIgPSB1c2VyO1xuXG4gICAgICAgIGRlZmVycmVkLnJlc29sdmUodXNlcik7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbSgndXNlcicpO1xuICAgICAgICBhdXRoLmN1cnJlbnRVc2VyID0gbnVsbDtcbiAgICAgICAgYXV0aC5jbGVhclRva2VuKCk7XG5cbiAgICAgICAgZGVmZXJyZWQucmVqZWN0KCk7XG4gICAgICB9XG5cbiAgICAgIHJldHVybiBkZWZlcnJlZC5wcm9taXNlO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWxpemEgbyBsb2dpbiBkbyB1c3XDoXJpb1xuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IGNyZWRlbnRpYWxzIEVtYWlsIGUgU2VuaGEgZG8gdXN1w6FyaW9cbiAgICAgKiBAcmV0dXJucyB7cHJvbWlzZX0gVW1hIHByb21pc2UgY29tIG8gcmVzdWx0YWRvIGRvIGNoYW1hZGEgbm8gYmFja2VuZFxuICAgICAqL1xuICAgIGZ1bmN0aW9uIGxvZ2luKGNyZWRlbnRpYWxzKSB7XG4gICAgICB2YXIgZGVmZXJyZWQgPSAkcS5kZWZlcigpO1xuXG4gICAgICAkaHR0cC5wb3N0KEdsb2JhbC5hcGlQYXRoICsgJy9hdXRoZW50aWNhdGUnLCBjcmVkZW50aWFscykudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgYXV0aC5zZXRUb2tlbihyZXNwb25zZS5kYXRhLnRva2VuKTtcblxuICAgICAgICByZXR1cm4gJGh0dHAuZ2V0KEdsb2JhbC5hcGlQYXRoICsgJy9hdXRoZW50aWNhdGUvdXNlcicpO1xuICAgICAgfSkudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgYXV0aC51cGRhdGVDdXJyZW50VXNlcihyZXNwb25zZS5kYXRhLnVzZXIpO1xuXG4gICAgICAgIGRlZmVycmVkLnJlc29sdmUoKTtcbiAgICAgIH0sIGZ1bmN0aW9uIChlcnJvcikge1xuICAgICAgICBhdXRoLmxvZ291dCgpO1xuXG4gICAgICAgIGRlZmVycmVkLnJlamVjdChlcnJvcik7XG4gICAgICB9KTtcblxuICAgICAgcmV0dXJuIGRlZmVycmVkLnByb21pc2U7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogRGVzbG9nYSBvcyB1c3XDoXJpb3MuIENvbW8gbsOjbyB0ZW4gbmVuaHVtYSBpbmZvcm1hw6fDo28gbmEgc2Vzc8OjbyBkbyBzZXJ2aWRvclxuICAgICAqIGUgdW0gdG9rZW4gdW1hIHZleiBnZXJhZG8gbsOjbyBwb2RlLCBwb3IgcGFkcsOjbywgc2VyIGludmFsaWRhZG8gYW50ZXMgZG8gc2V1IHRlbXBvIGRlIGV4cGlyYcOnw6NvLFxuICAgICAqIHNvbWVudGUgYXBhZ2Ftb3Mgb3MgZGFkb3MgZG8gdXN1w6FyaW8gZSBvIHRva2VuIGRvIG5hdmVnYWRvciBwYXJhIGVmZXRpdmFyIG8gbG9nb3V0LlxuICAgICAqXG4gICAgICogQHJldHVybnMge3Byb21pc2V9IFVtYSBwcm9taXNlIGNvbSBvIHJlc3VsdGFkbyBkYSBvcGVyYcOnw6NvXG4gICAgICovXG4gICAgZnVuY3Rpb24gbG9nb3V0KCkge1xuICAgICAgdmFyIGRlZmVycmVkID0gJHEuZGVmZXIoKTtcblxuICAgICAgYXV0aC51cGRhdGVDdXJyZW50VXNlcihudWxsKTtcbiAgICAgIGRlZmVycmVkLnJlc29sdmUoKTtcblxuICAgICAgcmV0dXJuIGRlZmVycmVkLnByb21pc2U7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogRW52aWEgdW0gZW1haWwgcGFyYSByZWN1cGVyYcOnw6NvIGRlIHNlbmhhXG4gICAgICogQHBhcmFtIHtPYmplY3R9IHJlc2V0RGF0YSAtIE9iamV0byBjb250ZW5kbyBvIGVtYWlsXG4gICAgICogQHJldHVybiB7UHJvbWlzZX0gLSBSZXRvcm5hIHVtYSBwcm9taXNlIHBhcmEgc2VyIHJlc29sdmlkYVxuICAgICAqL1xuICAgIGZ1bmN0aW9uIHNlbmRFbWFpbFJlc2V0UGFzc3dvcmQocmVzZXREYXRhKSB7XG4gICAgICB2YXIgZGVmZXJyZWQgPSAkcS5kZWZlcigpO1xuXG4gICAgICAkaHR0cC5wb3N0KEdsb2JhbC5hcGlQYXRoICsgJy9wYXNzd29yZC9lbWFpbCcsIHJlc2V0RGF0YSkudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgZGVmZXJyZWQucmVzb2x2ZShyZXNwb25zZS5kYXRhKTtcbiAgICAgIH0sIGZ1bmN0aW9uIChlcnJvcikge1xuICAgICAgICBkZWZlcnJlZC5yZWplY3QoZXJyb3IpO1xuICAgICAgfSk7XG5cbiAgICAgIHJldHVybiBkZWZlcnJlZC5wcm9taXNlO1xuICAgIH1cblxuICAgIHJldHVybiBhdXRoO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29udHJvbGxlcignTG9naW5Db250cm9sbGVyJywgTG9naW5Db250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIExvZ2luQ29udHJvbGxlcigkc3RhdGUsIEF1dGgsIEdsb2JhbCwgUHJEaWFsb2cpIHtcbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0ubG9naW4gPSBsb2dpbjtcbiAgICB2bS5vcGVuRGlhbG9nUmVzZXRQYXNzID0gb3BlbkRpYWxvZ1Jlc2V0UGFzcztcbiAgICB2bS5vcGVuRGlhbG9nU2lnblVwID0gb3BlbkRpYWxvZ1NpZ25VcDtcblxuICAgIGFjdGl2YXRlKCk7XG5cbiAgICBmdW5jdGlvbiBhY3RpdmF0ZSgpIHtcbiAgICAgIHZtLmNyZWRlbnRpYWxzID0ge307XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gbG9naW4oKSB7XG4gICAgICB2YXIgY3JlZGVudGlhbHMgPSB7XG4gICAgICAgIGVtYWlsOiB2bS5jcmVkZW50aWFscy5lbWFpbCxcbiAgICAgICAgcGFzc3dvcmQ6IHZtLmNyZWRlbnRpYWxzLnBhc3N3b3JkXG4gICAgICB9O1xuXG4gICAgICBBdXRoLmxvZ2luKGNyZWRlbnRpYWxzKS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgJHN0YXRlLmdvKEdsb2JhbC5ob21lU3RhdGUpO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogRXhpYmUgbyBkaWFsb2cgcGFyYSByZWN1cGVyYcOnw6NvIGRlIHNlbmhhXG4gICAgICovXG4gICAgZnVuY3Rpb24gb3BlbkRpYWxvZ1Jlc2V0UGFzcygpIHtcbiAgICAgIHZhciBjb25maWcgPSB7XG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvYXV0aC9zZW5kLXJlc2V0LWRpYWxvZy5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ1Bhc3N3b3JkQ29udHJvbGxlciBhcyBwYXNzQ3RybCcsXG4gICAgICAgIGhhc0JhY2tkcm9wOiB0cnVlXG4gICAgICB9O1xuXG4gICAgICBQckRpYWxvZy5jdXN0b20oY29uZmlnKTtcbiAgICB9XG4gICAgLyoqXG4gICAgICogRXhpYmUgbyBkaWFsb2cgcGFyYSByZWN1cGVyYcOnw6NvIGRlIHNlbmhhXG4gICAgICovXG4gICAgZnVuY3Rpb24gb3BlbkRpYWxvZ1NpZ25VcCgpIHtcbiAgICAgIHZhciBjb25maWcgPSB7XG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvdXNlcnMvdXNlci1mb3JtLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnVXNlcnNDb250cm9sbGVyIGFzIHVzZXJzQ3RybCcsXG4gICAgICAgIGhhc0JhY2tkcm9wOiB0cnVlXG4gICAgICB9O1xuXG4gICAgICBQckRpYWxvZy5jdXN0b20oY29uZmlnKTtcbiAgICB9XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb250cm9sbGVyKCdQYXNzd29yZENvbnRyb2xsZXInLCBQYXNzd29yZENvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gUGFzc3dvcmRDb250cm9sbGVyKEdsb2JhbCwgJHN0YXRlUGFyYW1zLCAkaHR0cCwgJHRpbWVvdXQsICRzdGF0ZSwgLy8gTk9TT05BUlxuICBQclRvYXN0LCBQckRpYWxvZywgQXV0aCwgJHRyYW5zbGF0ZSkge1xuXG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIHZtLnNlbmRSZXNldCA9IHNlbmRSZXNldDtcbiAgICB2bS5jbG9zZURpYWxvZyA9IGNsb3NlRGlhbG9nO1xuICAgIHZtLmNsZWFuRm9ybSA9IGNsZWFuRm9ybTtcbiAgICB2bS5zZW5kRW1haWxSZXNldFBhc3N3b3JkID0gc2VuZEVtYWlsUmVzZXRQYXNzd29yZDtcblxuICAgIGFjdGl2YXRlKCk7XG5cbiAgICBmdW5jdGlvbiBhY3RpdmF0ZSgpIHtcbiAgICAgIHZtLnJlc2V0ID0geyBlbWFpbDogJycsIHRva2VuOiAkc3RhdGVQYXJhbXMudG9rZW4gfTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFsaXphIGEgYWx0ZXJhw6fDo28gZGEgc2VuaGEgZG8gdXN1w6FyaW8gZSBvIHJlZGlyZWNpb25hIHBhcmEgYSB0ZWxhIGRlIGxvZ2luXG4gICAgICovXG4gICAgZnVuY3Rpb24gc2VuZFJlc2V0KCkge1xuICAgICAgJGh0dHAucG9zdChHbG9iYWwuYXBpUGF0aCArICcvcGFzc3dvcmQvcmVzZXQnLCB2bS5yZXNldCkudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgIFByVG9hc3Quc3VjY2VzcygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLm9wZXJhdGlvblN1Y2Nlc3MnKSk7XG4gICAgICAgICR0aW1lb3V0KGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAkc3RhdGUuZ28oR2xvYmFsLmxvZ2luU3RhdGUpO1xuICAgICAgICB9LCAxNTAwKTtcbiAgICAgIH0sIGZ1bmN0aW9uIChlcnJvcikge1xuICAgICAgICBpZiAoZXJyb3Iuc3RhdHVzICE9PSA0MDAgJiYgZXJyb3Iuc3RhdHVzICE9PSA1MDApIHtcbiAgICAgICAgICB2YXIgbXNnID0gJyc7XG5cbiAgICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IGVycm9yLmRhdGEucGFzc3dvcmQubGVuZ3RoOyBpKyspIHtcbiAgICAgICAgICAgIG1zZyArPSBlcnJvci5kYXRhLnBhc3N3b3JkW2ldICsgJzxicj4nO1xuICAgICAgICAgIH1cbiAgICAgICAgICBQclRvYXN0LmVycm9yKG1zZy50b1VwcGVyQ2FzZSgpKTtcbiAgICAgICAgfVxuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogRW52aWEgdW0gZW1haWwgZGUgcmVjdXBlcmHDp8OjbyBkZSBzZW5oYSBjb20gbyB0b2tlbiBkbyB1c3XDoXJpb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIHNlbmRFbWFpbFJlc2V0UGFzc3dvcmQoKSB7XG5cbiAgICAgIGlmICh2bS5yZXNldC5lbWFpbCA9PT0gJycpIHtcbiAgICAgICAgUHJUb2FzdC5lcnJvcigkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnZhbGlkYXRlLmZpZWxkUmVxdWlyZWQnLCB7IGZpZWxkOiAnZW1haWwnIH0pKTtcbiAgICAgICAgcmV0dXJuO1xuICAgICAgfVxuXG4gICAgICBBdXRoLnNlbmRFbWFpbFJlc2V0UGFzc3dvcmQodm0ucmVzZXQpLnRoZW4oZnVuY3Rpb24gKGRhdGEpIHtcbiAgICAgICAgUHJUb2FzdC5zdWNjZXNzKGRhdGEubWVzc2FnZSk7XG5cbiAgICAgICAgdm0uY2xlYW5Gb3JtKCk7XG4gICAgICAgIHZtLmNsb3NlRGlhbG9nKCk7XG4gICAgICB9LCBmdW5jdGlvbiAoZXJyb3IpIHtcbiAgICAgICAgaWYgKGVycm9yLmRhdGEuZW1haWwgJiYgZXJyb3IuZGF0YS5lbWFpbC5sZW5ndGggPiAwKSB7XG4gICAgICAgICAgdmFyIG1zZyA9ICcnO1xuXG4gICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCBlcnJvci5kYXRhLmVtYWlsLmxlbmd0aDsgaSsrKSB7XG4gICAgICAgICAgICBtc2cgKz0gZXJyb3IuZGF0YS5lbWFpbFtpXSArICc8YnI+JztcbiAgICAgICAgICB9XG5cbiAgICAgICAgICBQclRvYXN0LmVycm9yKG1zZyk7XG4gICAgICAgIH1cbiAgICAgIH0pO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGNsb3NlRGlhbG9nKCkge1xuICAgICAgUHJEaWFsb2cuY2xvc2UoKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBjbGVhbkZvcm0oKSB7XG4gICAgICB2bS5yZXNldC5lbWFpbCA9ICcnO1xuICAgIH1cbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuLyplc2xpbnQgYW5ndWxhci9maWxlLW5hbWU6IDAqL1xuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5mYWN0b3J5KCdzZXJ2aWNlRmFjdG9yeScsIHNlcnZpY2VGYWN0b3J5KTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8qKlxuICAgKiBNYWlzIGluZm9ybWHDp8O1ZXM6XG4gICAqIGh0dHBzOi8vZ2l0aHViLmNvbS9zd2ltbGFuZS9hbmd1bGFyLW1vZGVsLWZhY3Rvcnkvd2lraS9BUElcbiAgICovXG4gIGZ1bmN0aW9uIHNlcnZpY2VGYWN0b3J5KCRtb2RlbEZhY3RvcnkpIHtcbiAgICByZXR1cm4gZnVuY3Rpb24gKHVybCwgb3B0aW9ucykge1xuICAgICAgdmFyIG1vZGVsO1xuICAgICAgdmFyIGRlZmF1bHRPcHRpb25zID0ge1xuICAgICAgICBhY3Rpb25zOiB7XG4gICAgICAgICAgLyoqXG4gICAgICAgICAgICogU2VydmnDp28gY29tdW0gcGFyYSByZWFsaXphciBidXNjYSBjb20gcGFnaW5hw6fDo29cbiAgICAgICAgICAgKiBPIG1lc21vIGVzcGVyYSBxdWUgc2VqYSByZXRvcm5hZG8gdW0gb2JqZXRvIGNvbSBpdGVtcyBlIHRvdGFsXG4gICAgICAgICAgICovXG4gICAgICAgICAgcGFnaW5hdGU6IHtcbiAgICAgICAgICAgIG1ldGhvZDogJ0dFVCcsXG4gICAgICAgICAgICBpc0FycmF5OiBmYWxzZSxcbiAgICAgICAgICAgIHdyYXA6IGZhbHNlLFxuICAgICAgICAgICAgYWZ0ZXJSZXF1ZXN0OiBmdW5jdGlvbiBhZnRlclJlcXVlc3QocmVzcG9uc2UpIHtcbiAgICAgICAgICAgICAgaWYgKHJlc3BvbnNlWydpdGVtcyddKSB7XG4gICAgICAgICAgICAgICAgcmVzcG9uc2VbJ2l0ZW1zJ10gPSBtb2RlbC5MaXN0KHJlc3BvbnNlWydpdGVtcyddKTtcbiAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgIHJldHVybiByZXNwb25zZTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgIH07XG5cbiAgICAgIG1vZGVsID0gJG1vZGVsRmFjdG9yeSh1cmwsIGFuZ3VsYXIubWVyZ2UoZGVmYXVsdE9wdGlvbnMsIG9wdGlvbnMpKTtcblxuICAgICAgcmV0dXJuIG1vZGVsO1xuICAgIH07XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIENSVURDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8qKlxuICAgKiBDb250cm9sYWRvciBCYXNlIHF1ZSBpbXBsZW1lbnRhIHRvZGFzIGFzIGZ1bsOnw7VlcyBwYWRyw7VlcyBkZSB1bSBDUlVEXG4gICAqXG4gICAqIEHDp8O1ZXMgaW1wbGVtZW50YWRhc1xuICAgKiBhY3RpdmF0ZSgpXG4gICAqIHNlYXJjaChwYWdlKVxuICAgKiBlZGl0KHJlc291cmNlKVxuICAgKiBzYXZlKClcbiAgICogcmVtb3ZlKHJlc291cmNlKVxuICAgKiBnb1RvKHZpZXdOYW1lKVxuICAgKiBjbGVhbkZvcm0oKVxuICAgKlxuICAgKiBHYXRpbGhvc1xuICAgKlxuICAgKiBvbkFjdGl2YXRlKClcbiAgICogYXBwbHlGaWx0ZXJzKGRlZmF1bHRRdWVyeUZpbHRlcnMpXG4gICAqIGJlZm9yZVNlYXJjaChwYWdlKSAvL3JldG9ybmFuZG8gZmFsc2UgY2FuY2VsYSBvIGZsdXhvXG4gICAqIGFmdGVyU2VhcmNoKHJlc3BvbnNlKVxuICAgKiBiZWZvcmVDbGVhbiAvL3JldG9ybmFuZG8gZmFsc2UgY2FuY2VsYSBvIGZsdXhvXG4gICAqIGFmdGVyQ2xlYW4oKVxuICAgKiBiZWZvcmVTYXZlKCkgLy9yZXRvcm5hbmRvIGZhbHNlIGNhbmNlbGEgbyBmbHV4b1xuICAgKiBhZnRlclNhdmUocmVzb3VyY2UpXG4gICAqIG9uU2F2ZUVycm9yKGVycm9yKVxuICAgKiBiZWZvcmVSZW1vdmUocmVzb3VyY2UpIC8vcmV0b3JuYW5kbyBmYWxzZSBjYW5jZWxhIG8gZmx1eG9cbiAgICogYWZ0ZXJSZW1vdmUocmVzb3VyY2UpXG4gICAqXG4gICAqIEBwYXJhbSB7YW55fSB2bSBpbnN0YW5jaWEgZG8gY29udHJvbGxlciBmaWxob1xuICAgKiBAcGFyYW0ge2FueX0gbW9kZWxTZXJ2aWNlIHNlcnZpw6dvIGRvIG1vZGVsIHF1ZSB2YWkgc2VyIHV0aWxpemFkb1xuICAgKiBAcGFyYW0ge2FueX0gb3B0aW9ucyBvcMOnw7VlcyBwYXJhIHNvYnJlZXNjcmV2ZXIgY29tcG9ydGFtZW50b3MgcGFkcsO1ZXNcbiAgICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIENSVURDb250cm9sbGVyKHZtLCBtb2RlbFNlcnZpY2UsIG9wdGlvbnMsIFByVG9hc3QsIFByUGFnaW5hdGlvbiwgLy8gTk9TT05BUlxuICBQckRpYWxvZywgJHRyYW5zbGF0ZSkge1xuXG4gICAgLy9GdW5jdGlvbnMgQmxvY2tcbiAgICB2bS5zZWFyY2ggPSBzZWFyY2g7XG4gICAgdm0ucGFnaW5hdGVTZWFyY2ggPSBwYWdpbmF0ZVNlYXJjaDtcbiAgICB2bS5ub3JtYWxTZWFyY2ggPSBub3JtYWxTZWFyY2g7XG4gICAgdm0uZWRpdCA9IGVkaXQ7XG4gICAgdm0uc2F2ZSA9IHNhdmU7XG4gICAgdm0ucmVtb3ZlID0gcmVtb3ZlO1xuICAgIHZtLmdvVG8gPSBnb1RvO1xuICAgIHZtLmNsZWFuRm9ybSA9IGNsZWFuRm9ybTtcblxuICAgIGFjdGl2YXRlKCk7XG5cbiAgICAvKipcbiAgICAgKiBQcmVwYXJhIG8gY29udHJvbGFkb3JcbiAgICAgKiBGYXogbyBtZXJnZSBkYXMgb3DDp8O1ZXNcbiAgICAgKiBJbmljaWFsaXphIG8gcmVjdXJzb1xuICAgICAqIEluaWNpYWxpemEgbyBvYmpldG8gcGFnaW5hZG9yIGUgcmVhbGl6YSBhIHBlc3F1aXNhXG4gICAgICovXG4gICAgZnVuY3Rpb24gYWN0aXZhdGUoKSB7XG4gICAgICB2bS5kZWZhdWx0T3B0aW9ucyA9IHtcbiAgICAgICAgcmVkaXJlY3RBZnRlclNhdmU6IHRydWUsXG4gICAgICAgIHNlYXJjaE9uSW5pdDogdHJ1ZSxcbiAgICAgICAgcGVyUGFnZTogOCxcbiAgICAgICAgc2tpcFBhZ2luYXRpb246IGZhbHNlXG4gICAgICB9O1xuXG4gICAgICBhbmd1bGFyLm1lcmdlKHZtLmRlZmF1bHRPcHRpb25zLCBvcHRpb25zKTtcblxuICAgICAgdm0udmlld0Zvcm0gPSBmYWxzZTtcbiAgICAgIHZtLnJlc291cmNlID0gbmV3IG1vZGVsU2VydmljZSgpO1xuXG4gICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLm9uQWN0aXZhdGUpKSB2bS5vbkFjdGl2YXRlKCk7XG5cbiAgICAgIHZtLnBhZ2luYXRvciA9IFByUGFnaW5hdGlvbi5nZXRJbnN0YW5jZSh2bS5zZWFyY2gsIHZtLmRlZmF1bHRPcHRpb25zLnBlclBhZ2UpO1xuXG4gICAgICBpZiAodm0uZGVmYXVsdE9wdGlvbnMuc2VhcmNoT25Jbml0KSB2bS5zZWFyY2goKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFsaXphIGEgcGVzcXVpc2FcbiAgICAgKiBWZXJpZmljYSBxdWFsIGRhcyBmdW7Dp8O1ZXMgZGUgcGVzcXVpc2EgZGV2ZSBzZXIgcmVhbGl6YWRhLlxuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IHBhZ2UgcMOhZ2luYSBxdWUgZGV2ZSBzZXIgY2FycmVnYWRhXG4gICAgICovXG4gICAgZnVuY3Rpb24gc2VhcmNoKHBhZ2UpIHtcbiAgICAgIHZtLmRlZmF1bHRPcHRpb25zLnNraXBQYWdpbmF0aW9uID8gbm9ybWFsU2VhcmNoKCkgOiBwYWdpbmF0ZVNlYXJjaChwYWdlKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFsaXphIGEgcGVzcXVpc2EgcGFnaW5hZGEgY29tIGJhc2Ugbm9zIGZpbHRyb3MgZGVmaW5pZG9zXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gcGFnZSBww6FnaW5hIHF1ZSBkZXZlIHNlciBjYXJyZWdhZGFcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBwYWdpbmF0ZVNlYXJjaChwYWdlKSB7XG4gICAgICB2bS5wYWdpbmF0b3IuY3VycmVudFBhZ2UgPSBhbmd1bGFyLmlzRGVmaW5lZChwYWdlKSA/IHBhZ2UgOiAxO1xuICAgICAgdm0uZGVmYXVsdFF1ZXJ5RmlsdGVycyA9IHsgcGFnZTogdm0ucGFnaW5hdG9yLmN1cnJlbnRQYWdlLCBwZXJQYWdlOiB2bS5wYWdpbmF0b3IucGVyUGFnZSB9O1xuXG4gICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmFwcGx5RmlsdGVycykpIHZtLmRlZmF1bHRRdWVyeUZpbHRlcnMgPSB2bS5hcHBseUZpbHRlcnModm0uZGVmYXVsdFF1ZXJ5RmlsdGVycyk7XG4gICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmJlZm9yZVNlYXJjaCkgJiYgdm0uYmVmb3JlU2VhcmNoKHBhZ2UpID09PSBmYWxzZSkgcmV0dXJuIGZhbHNlO1xuXG4gICAgICBtb2RlbFNlcnZpY2UucGFnaW5hdGUodm0uZGVmYXVsdFF1ZXJ5RmlsdGVycykudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgdm0ucGFnaW5hdG9yLmNhbGNOdW1iZXJPZlBhZ2VzKHJlc3BvbnNlLnRvdGFsKTtcbiAgICAgICAgdm0ucmVzb3VyY2VzID0gcmVzcG9uc2UuaXRlbXM7XG5cbiAgICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5hZnRlclNlYXJjaCkpIHZtLmFmdGVyU2VhcmNoKHJlc3BvbnNlKTtcbiAgICAgIH0sIGZ1bmN0aW9uIChyZXNwb25zZURhdGEpIHtcbiAgICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5vblNlYXJjaEVycm9yKSkgdm0ub25TZWFyY2hFcnJvcihyZXNwb25zZURhdGEpO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhbGl6YSBhIHBlc3F1aXNhIGNvbSBiYXNlIG5vcyBmaWx0cm9zIGRlZmluaWRvc1xuICAgICAqXG4gICAgICovXG4gICAgZnVuY3Rpb24gbm9ybWFsU2VhcmNoKCkge1xuICAgICAgdm0uZGVmYXVsdFF1ZXJ5RmlsdGVycyA9IHt9O1xuXG4gICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmFwcGx5RmlsdGVycykpIHZtLmRlZmF1bHRRdWVyeUZpbHRlcnMgPSB2bS5hcHBseUZpbHRlcnModm0uZGVmYXVsdFF1ZXJ5RmlsdGVycyk7XG4gICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmJlZm9yZVNlYXJjaCkgJiYgdm0uYmVmb3JlU2VhcmNoKCkgPT09IGZhbHNlKSByZXR1cm4gZmFsc2U7XG5cbiAgICAgIG1vZGVsU2VydmljZS5xdWVyeSh2bS5kZWZhdWx0UXVlcnlGaWx0ZXJzKS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICB2bS5yZXNvdXJjZXMgPSByZXNwb25zZTtcblxuICAgICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmFmdGVyU2VhcmNoKSkgdm0uYWZ0ZXJTZWFyY2gocmVzcG9uc2UpO1xuICAgICAgfSwgZnVuY3Rpb24gKHJlc3BvbnNlRGF0YSkge1xuICAgICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLm9uU2VhcmNoRXJyb3IpKSB2bS5vblNlYXJjaEVycm9yKHJlc3BvbnNlRGF0YSk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBMaW1wYSBvIGZvcm11bMOhcmlvXG4gICAgICovXG4gICAgZnVuY3Rpb24gY2xlYW5Gb3JtKGZvcm0pIHtcbiAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYmVmb3JlQ2xlYW4pICYmIHZtLmJlZm9yZUNsZWFuKCkgPT09IGZhbHNlKSByZXR1cm4gZmFsc2U7XG5cbiAgICAgIHZtLnJlc291cmNlID0gbmV3IG1vZGVsU2VydmljZSgpO1xuXG4gICAgICBpZiAoYW5ndWxhci5pc0RlZmluZWQoZm9ybSkpIHtcbiAgICAgICAgZm9ybS4kc2V0UHJpc3RpbmUoKTtcbiAgICAgICAgZm9ybS4kc2V0VW50b3VjaGVkKCk7XG4gICAgICB9XG5cbiAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYWZ0ZXJDbGVhbikpIHZtLmFmdGVyQ2xlYW4oKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDYXJyZWdhIG5vIGZvcm11bMOhcmlvIG8gcmVjdXJzbyBzZWxlY2lvbmFkbyBwYXJhIGVkacOnw6NvXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gcmVzb3VyY2UgcmVjdXJzbyBzZWxlY2lvbmFkb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGVkaXQocmVzb3VyY2UpIHtcbiAgICAgIHZtLmdvVG8oJ2Zvcm0nKTtcbiAgICAgIHZtLnJlc291cmNlID0gbmV3IGFuZ3VsYXIuY29weShyZXNvdXJjZSk7XG5cbiAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYWZ0ZXJFZGl0KSkgdm0uYWZ0ZXJFZGl0KCk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogU2FsdmEgb3UgYXR1YWxpemEgbyByZWN1cnNvIGNvcnJlbnRlIG5vIGZvcm11bMOhcmlvXG4gICAgICogTm8gY29tcG9ydGFtZW50byBwYWRyw6NvIHJlZGlyZWNpb25hIG8gdXN1w6FyaW8gcGFyYSB2aWV3IGRlIGxpc3RhZ2VtXG4gICAgICogZGVwb2lzIGRhIGV4ZWN1w6fDo29cbiAgICAgKlxuICAgICAqIEByZXR1cm5zXG4gICAgICovXG4gICAgZnVuY3Rpb24gc2F2ZShmb3JtKSB7XG4gICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmJlZm9yZVNhdmUpICYmIHZtLmJlZm9yZVNhdmUoKSA9PT0gZmFsc2UpIHJldHVybiBmYWxzZTtcblxuICAgICAgdm0ucmVzb3VyY2UuJHNhdmUoKS50aGVuKGZ1bmN0aW9uIChyZXNvdXJjZSkge1xuICAgICAgICB2bS5yZXNvdXJjZSA9IHJlc291cmNlO1xuXG4gICAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYWZ0ZXJTYXZlKSkgdm0uYWZ0ZXJTYXZlKHJlc291cmNlKTtcblxuICAgICAgICBpZiAodm0uZGVmYXVsdE9wdGlvbnMucmVkaXJlY3RBZnRlclNhdmUpIHtcbiAgICAgICAgICB2bS5jbGVhbkZvcm0oZm9ybSk7XG4gICAgICAgICAgdm0uc2VhcmNoKHZtLnBhZ2luYXRvci5jdXJyZW50UGFnZSk7XG4gICAgICAgICAgdm0uZ29UbygnbGlzdCcpO1xuICAgICAgICB9XG5cbiAgICAgICAgUHJUb2FzdC5zdWNjZXNzKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMuc2F2ZVN1Y2Nlc3MnKSk7XG4gICAgICB9LCBmdW5jdGlvbiAocmVzcG9uc2VEYXRhKSB7XG4gICAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0ub25TYXZlRXJyb3IpKSB2bS5vblNhdmVFcnJvcihyZXNwb25zZURhdGEpO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVtb3ZlIG8gcmVjdXJzbyBpbmZvcm1hZG8uXG4gICAgICogQW50ZXMgZXhpYmUgdW0gZGlhbG9nbyBkZSBjb25maXJtYcOnw6NvXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gcmVzb3VyY2UgcmVjdXJzbyBlc2NvbGhpZG9cbiAgICAgKi9cbiAgICBmdW5jdGlvbiByZW1vdmUocmVzb3VyY2UpIHtcbiAgICAgIHZhciBjb25maWcgPSB7XG4gICAgICAgIHRpdGxlOiAkdHJhbnNsYXRlLmluc3RhbnQoJ2RpYWxvZy5jb25maXJtVGl0bGUnKSxcbiAgICAgICAgZGVzY3JpcHRpb246ICR0cmFuc2xhdGUuaW5zdGFudCgnZGlhbG9nLmNvbmZpcm1EZXNjcmlwdGlvbicpXG4gICAgICB9O1xuXG4gICAgICBQckRpYWxvZy5jb25maXJtKGNvbmZpZykudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYmVmb3JlUmVtb3ZlKSAmJiB2bS5iZWZvcmVSZW1vdmUocmVzb3VyY2UpID09PSBmYWxzZSkgcmV0dXJuIGZhbHNlO1xuXG4gICAgICAgIHJlc291cmNlLiRkZXN0cm95KCkudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5hZnRlclJlbW92ZSkpIHZtLmFmdGVyUmVtb3ZlKHJlc291cmNlKTtcblxuICAgICAgICAgIHZtLnNlYXJjaCgpO1xuICAgICAgICAgIFByVG9hc3QuaW5mbygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnJlbW92ZVN1Y2Nlc3MnKSk7XG4gICAgICAgIH0pO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQWx0ZXJuYSBlbnRyZSBhIHZpZXcgZG8gZm9ybXVsw6FyaW8gZSBsaXN0YWdlbVxuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IHZpZXdOYW1lIG5vbWUgZGEgdmlld1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGdvVG8odmlld05hbWUpIHtcbiAgICAgIHZtLnZpZXdGb3JtID0gZmFsc2U7XG4gICAgICB2bS5vblZpZXcgPSBmYWxzZTtcbiAgICAgIGlmICh2aWV3TmFtZSA9PT0gJ2Zvcm0nKSB7XG4gICAgICAgIHZtLmNsZWFuRm9ybSgpO1xuICAgICAgICB2bS52aWV3Rm9ybSA9IHRydWU7XG4gICAgICB9XG4gICAgfVxuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmlsdGVyKCdlbGFwc2VkJywgZnVuY3Rpb24gKCkge1xuICAgIHJldHVybiBmdW5jdGlvbiAoZGF0ZSkge1xuICAgICAgaWYgKCFkYXRlKSByZXR1cm47XG4gICAgICB2YXIgdGltZSA9IERhdGUucGFyc2UoZGF0ZSksXG4gICAgICAgICAgdGltZU5vdyA9IG5ldyBEYXRlKCkuZ2V0VGltZSgpLFxuICAgICAgICAgIGRpZmZlcmVuY2UgPSB0aW1lTm93IC0gdGltZSxcbiAgICAgICAgICBzZWNvbmRzID0gTWF0aC5mbG9vcihkaWZmZXJlbmNlIC8gMTAwMCksXG4gICAgICAgICAgbWludXRlcyA9IE1hdGguZmxvb3Ioc2Vjb25kcyAvIDYwKSxcbiAgICAgICAgICBob3VycyA9IE1hdGguZmxvb3IobWludXRlcyAvIDYwKSxcbiAgICAgICAgICBkYXlzID0gTWF0aC5mbG9vcihob3VycyAvIDI0KSxcbiAgICAgICAgICBtb250aHMgPSBNYXRoLmZsb29yKGRheXMgLyAzMCk7XG5cbiAgICAgIGlmIChtb250aHMgPiAxKSB7XG4gICAgICAgIHJldHVybiBtb250aHMgKyAnIG1lc2VzIGF0csOhcyc7XG4gICAgICB9IGVsc2UgaWYgKG1vbnRocyA9PT0gMSkge1xuICAgICAgICByZXR1cm4gJzEgbcOqcyBhdHLDoXMnO1xuICAgICAgfSBlbHNlIGlmIChkYXlzID4gMSkge1xuICAgICAgICByZXR1cm4gZGF5cyArICcgZGlhcyBhdHLDoXMnO1xuICAgICAgfSBlbHNlIGlmIChkYXlzID09PSAxKSB7XG4gICAgICAgIHJldHVybiAnMSBkaWEgYXRyw6FzJztcbiAgICAgIH0gZWxzZSBpZiAoaG91cnMgPiAxKSB7XG4gICAgICAgIHJldHVybiBob3VycyArICcgaG9yYXMgYXRyw6FzJztcbiAgICAgIH0gZWxzZSBpZiAoaG91cnMgPT09IDEpIHtcbiAgICAgICAgcmV0dXJuICd1bWEgaG9yYSBhdHLDoXMnO1xuICAgICAgfSBlbHNlIGlmIChtaW51dGVzID4gMSkge1xuICAgICAgICByZXR1cm4gbWludXRlcyArICcgbWludXRvcyBhdHLDoXMnO1xuICAgICAgfSBlbHNlIGlmIChtaW51dGVzID09PSAxKSB7XG4gICAgICAgIHJldHVybiAndW0gbWludXRvIGF0csOhcyc7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICByZXR1cm4gJ2jDoSBwb3Vjb3Mgc2VndW5kb3MnO1xuICAgICAgfVxuICAgIH07XG4gIH0pLmNvbnRyb2xsZXIoJ0Rhc2hib2FyZENvbnRyb2xsZXInLCBEYXNoYm9hcmRDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIERhc2hib2FyZENvbnRyb2xsZXIoJGNvbnRyb2xsZXIsICRzdGF0ZSwgJG1kRGlhbG9nLCAkdHJhbnNsYXRlLCBEYXNoYm9hcmRzU2VydmljZSwgUHJvamVjdHNTZXJ2aWNlLCBtb21lbnQsIFByVG9hc3QsIEF1dGgsIEdsb2JhbCkge1xuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICAvL0F0dHJpYnV0ZXMgQmxvY2tcblxuICAgIC8vRnVuY3Rpb25zIEJsb2NrXG4gICAgdm0ub25BY3RpdmF0ZSA9IG9uQWN0aXZhdGU7XG4gICAgdm0uYXBwbHlGaWx0ZXJzID0gYXBwbHlGaWx0ZXJzO1xuICAgIHZtLmZpeERhdGUgPSBmaXhEYXRlO1xuXG4gICAgZnVuY3Rpb24gb25BY3RpdmF0ZSgpIHtcbiAgICAgIHZhciBwcm9qZWN0ID0gbG9jYWxTdG9yYWdlLmdldEl0ZW0oJ3Byb2plY3QnKTtcblxuICAgICAgdm0uaW1hZ2VQYXRoID0gR2xvYmFsLmltYWdlUGF0aCArICcvbm9fYXZhdGFyLmdpZic7XG4gICAgICB2bS5jdXJyZW50VXNlciA9IEF1dGguY3VycmVudFVzZXI7XG4gICAgICBQcm9qZWN0c1NlcnZpY2UucXVlcnkoeyBwcm9qZWN0X2lkOiBwcm9qZWN0IH0pLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgIHZtLmFjdHVhbFByb2plY3QgPSByZXNwb25zZVswXTtcbiAgICAgIH0pO1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0geyBwcm9qZWN0X2lkOiBwcm9qZWN0IH07XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gYXBwbHlGaWx0ZXJzKGRlZmF1bHRRdWVyeUZpbHRlcnMpIHtcbiAgICAgIHJldHVybiBhbmd1bGFyLmV4dGVuZChkZWZhdWx0UXVlcnlGaWx0ZXJzLCB2bS5xdWVyeUZpbHRlcnMpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGZpeERhdGUoZGF0ZVN0cmluZykge1xuICAgICAgcmV0dXJuIG1vbWVudChkYXRlU3RyaW5nKTtcbiAgICB9XG5cbiAgICB2bS5nb1RvUHJvamVjdCA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICRzdGF0ZS5nbygnYXBwLnByb2plY3RzJywgeyBvYmo6ICdlZGl0JywgcmVzb3VyY2U6IHZtLmFjdHVhbFByb2plY3QgfSk7XG4gICAgfTtcblxuICAgIHZtLnRvdGFsQ29zdCA9IGZ1bmN0aW9uICgpIHtcbiAgICAgIHZhciBlc3RpbWF0ZWRfY29zdCA9IDA7XG5cbiAgICAgIGlmICh2bS5hY3R1YWxQcm9qZWN0LmhvdXJfdmFsdWVfZmluYWwpIHtcbiAgICAgICAgdm0uYWN0dWFsUHJvamVjdC50YXNrcy5mb3JFYWNoKGZ1bmN0aW9uICh0YXNrKSB7XG4gICAgICAgICAgaWYgKHRhc2suZXN0aW1hdGVkX3RpbWUgPiAwKSB7XG4gICAgICAgICAgICBlc3RpbWF0ZWRfY29zdCArPSBwYXJzZUZsb2F0KHZtLmFjdHVhbFByb2plY3QuaG91cl92YWx1ZV9maW5hbCkgKiB0YXNrLmVzdGltYXRlZF90aW1lO1xuICAgICAgICAgIH1cbiAgICAgICAgfSk7XG4gICAgICB9XG4gICAgICByZXR1cm4gZXN0aW1hdGVkX2Nvc3QudG9Mb2NhbGVTdHJpbmcoJ1B0LWJyJywgeyBtaW5pbXVtRnJhY3Rpb25EaWdpdHM6IDIgfSk7XG4gICAgfTtcblxuICAgIHZtLmZpbmFsaXplUHJvamVjdCA9IGZ1bmN0aW9uICgpIHtcbiAgICAgIFByb2plY3RzU2VydmljZS52ZXJpZnlSZWxlYXNlcyh7IHByb2plY3RfaWQ6IHZtLmFjdHVhbFByb2plY3QuaWQgfSkudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgaWYgKHJlc3BvbnNlLnN1Y2Nlc3MpIHtcbiAgICAgICAgICB2YXIgY29uZmlybSA9ICRtZERpYWxvZy5jb25maXJtKCkudGl0bGUoJ0ZpbmFsaXphciBQcm9qZXRvJykuaHRtbENvbnRlbnQoJ1RlbSBjZXJ0ZXphIHF1ZSBkZXNlamEgZmluYWxpemFyIG8gcHJvamV0byAnICsgdm0uYWN0dWFsUHJvamVjdC5uYW1lICsgJz88YnIgLz4gQWluZGEgZXhpc3RlbSByZWxlYXNlcyBuw6NvIGZpbmFsaXphZGFzLicpLm9rKCdTaW0nKS5jYW5jZWwoJ07Do28nKTtcblxuICAgICAgICAgICRtZERpYWxvZy5zaG93KGNvbmZpcm0pLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgdmFyIHJlYXNvbiA9ICRtZERpYWxvZy5wcm9tcHQoKS50aXRsZSgnRmluYWxpemFyIFByb2pldG8nKS50ZXh0Q29udGVudCgnUXVhbCBvIG1vdGl2byBwYXJhIGEgZmluYWxpemHDp8OjbyBkbyBwcm9qZXRvPycpLnBsYWNlaG9sZGVyKCdNb3Rpdm8nKS5pbml0aWFsVmFsdWUoJycpLnJlcXVpcmVkKHRydWUpLm9rKCdDb25maXJtYXInKS5jYW5jZWwoJ0NhbmNlbGFyJyk7XG5cbiAgICAgICAgICAgICRtZERpYWxvZy5zaG93KHJlYXNvbikudGhlbihmdW5jdGlvbiAocmVhc29uVGV4dCkge1xuICAgICAgICAgICAgICBQcm9qZWN0c1NlcnZpY2UuZmluYWxpemUoeyBwcm9qZWN0X2lkOiB2bS5hY3R1YWxQcm9qZWN0LmlkLCByZWFzb246IHJlYXNvblRleHQgfSkudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgUHJUb2FzdC5zdWNjZXNzKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMucHJvamVjdEVuZGVkU3VjY2VzcycpKTtcbiAgICAgICAgICAgICAgICBvbkFjdGl2YXRlKCk7XG4gICAgICAgICAgICAgICAgdm0uc2VhcmNoKCk7XG4gICAgICAgICAgICAgIH0sIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICBQclRvYXN0LkVycm9yKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMucHJvamVjdEVuZGVkRXJyb3InKSk7XG4gICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgfSk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgdmFyIGNvbmZpcm0gPSAkbWREaWFsb2cuY29uZmlybSgpLnRpdGxlKCdGaW5hbGl6YXIgUHJvamV0bycpLnRleHRDb250ZW50KCdUZW0gY2VydGV6YSBxdWUgZGVzZWphIGZpbmFsaXphciBvIHByb2pldG8gJyArIHZtLmFjdHVhbFByb2plY3QubmFtZSArICc/Jykub2soJ1NpbScpLmNhbmNlbCgnTsOjbycpO1xuXG4gICAgICAgICAgJG1kRGlhbG9nLnNob3coY29uZmlybSkudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICBQcm9qZWN0c1NlcnZpY2UuZmluYWxpemUoeyBwcm9qZWN0X2lkOiB2bS5hY3R1YWxQcm9qZWN0LmlkIH0pLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICBQclRvYXN0LnN1Y2Nlc3MoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5wcm9qZWN0RW5kZWRTdWNjZXNzJykpO1xuICAgICAgICAgICAgICBvbkFjdGl2YXRlKCk7XG4gICAgICAgICAgICAgIHZtLnNlYXJjaCgpO1xuICAgICAgICAgICAgfSwgZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICBQclRvYXN0LkVycm9yKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMucHJvamVjdEVuZGVkRXJyb3InKSk7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgICB9KTtcbiAgICAgICAgfVxuICAgICAgfSk7XG4gICAgfTtcblxuICAgIC8vIGluc3RhbnRpYXRlIGJhc2UgY29udHJvbGxlclxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHsgdm06IHZtLCBtb2RlbFNlcnZpY2U6IERhc2hib2FyZHNTZXJ2aWNlLCBvcHRpb25zOiB7fSB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25maWcocm91dGVzKTtcblxuICAvKipcbiAgICogQXJxdWl2byBkZSBjb25maWd1cmHDp8OjbyBjb20gYXMgcm90YXMgZXNwZWPDrWZpY2FzIGRvIHJlY3Vyc28gcHJvamVjdFxuICAgKlxuICAgKiBAcGFyYW0ge2FueX0gJHN0YXRlUHJvdmlkZXJcbiAgICogQHBhcmFtIHthbnl9IEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdhcHAuZGFzaGJvYXJkJywge1xuICAgICAgdXJsOiAnL2Rhc2hib2FyZHMnLFxuICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9kYXNoYm9hcmQvZGFzaGJvYXJkLmh0bWwnLFxuICAgICAgY29udHJvbGxlcjogJ0Rhc2hib2FyZENvbnRyb2xsZXIgYXMgZGFzaGJvYXJkQ3RybCcsXG4gICAgICBkYXRhOiB7IG5lZWRBdXRoZW50aWNhdGlvbjogdHJ1ZSB9LFxuICAgICAgb2JqOiB7IHJlc291cmNlOiBudWxsIH1cbiAgICB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5mYWN0b3J5KCdEYXNoYm9hcmRzU2VydmljZScsIERhc2hib2FyZHNTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIERhc2hib2FyZHNTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCdkYXNoYm9hcmRzJywge1xuICAgICAgYWN0aW9uczoge30sXG4gICAgICBpbnN0YW5jZToge31cbiAgICB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25maWcocm91dGVzKTtcblxuICAvKipcbiAgICogQXJxdWl2byBkZSBjb25maWd1cmHDp8OjbyBjb20gYXMgcm90YXMgZXNwZWPDrWZpY2FzIGRvIHJlY3Vyc28gdXNlclxuICAgKlxuICAgKiBAcGFyYW0ge2FueX0gJHN0YXRlUHJvdmlkZXJcbiAgICogQHBhcmFtIHthbnl9IEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdhcHAuZGluYW1pYy1xdWVyeScsIHtcbiAgICAgIHVybDogJy9jb25zdWx0YXMtZGluYW1pY2FzJyxcbiAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvZGluYW1pYy1xdWVyeXMvZGluYW1pYy1xdWVyeXMuaHRtbCcsXG4gICAgICBjb250cm9sbGVyOiAnRGluYW1pY1F1ZXJ5c0NvbnRyb2xsZXIgYXMgZGluYW1pY1F1ZXJ5Q3RybCcsXG4gICAgICBkYXRhOiB7IG5lZWRBdXRoZW50aWNhdGlvbjogdHJ1ZSwgbmVlZFByb2ZpbGU6IFsnYWRtaW4nXSB9XG4gICAgfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmFjdG9yeSgnRGluYW1pY1F1ZXJ5U2VydmljZScsIERpbmFtaWNRdWVyeVNlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gRGluYW1pY1F1ZXJ5U2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHJldHVybiBzZXJ2aWNlRmFjdG9yeSgnZGluYW1pY1F1ZXJ5Jywge1xuICAgICAgLyoqXG4gICAgICAgKiBhw6fDo28gYWRpY2lvbmFkYSBwYXJhIHBlZ2FyIHVtYSBsaXN0YSBkZSBtb2RlbHMgZXhpc3RlbnRlcyBubyBzZXJ2aWRvclxuICAgICAgICovXG4gICAgICBhY3Rpb25zOiB7XG4gICAgICAgIGdldE1vZGVsczoge1xuICAgICAgICAgIG1ldGhvZDogJ0dFVCcsXG4gICAgICAgICAgdXJsOiAnbW9kZWxzJ1xuICAgICAgICB9XG4gICAgICB9LFxuICAgICAgaW5zdGFuY2U6IHt9XG4gICAgfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb250cm9sbGVyKCdEaW5hbWljUXVlcnlzQ29udHJvbGxlcicsIERpbmFtaWNRdWVyeXNDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIERpbmFtaWNRdWVyeXNDb250cm9sbGVyKCRjb250cm9sbGVyLCBEaW5hbWljUXVlcnlTZXJ2aWNlLCBsb2Rhc2gsIFByVG9hc3QsIC8vIE5PU09OQVJcbiAgJHRyYW5zbGF0ZSkge1xuXG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIC8vYWN0aW9uc1xuICAgIHZtLm9uQWN0aXZhdGUgPSBvbkFjdGl2YXRlO1xuICAgIHZtLmFwcGx5RmlsdGVycyA9IGFwcGx5RmlsdGVycztcbiAgICB2bS5sb2FkQXR0cmlidXRlcyA9IGxvYWRBdHRyaWJ1dGVzO1xuICAgIHZtLmxvYWRPcGVyYXRvcnMgPSBsb2FkT3BlcmF0b3JzO1xuICAgIHZtLmFkZEZpbHRlciA9IGFkZEZpbHRlcjtcbiAgICB2bS5hZnRlclNlYXJjaCA9IGFmdGVyU2VhcmNoO1xuICAgIHZtLnJ1bkZpbHRlciA9IHJ1bkZpbHRlcjtcbiAgICB2bS5lZGl0RmlsdGVyID0gZWRpdEZpbHRlcjtcbiAgICB2bS5sb2FkTW9kZWxzID0gbG9hZE1vZGVscztcbiAgICB2bS5yZW1vdmVGaWx0ZXIgPSByZW1vdmVGaWx0ZXI7XG4gICAgdm0uY2xlYXIgPSBjbGVhcjtcbiAgICB2bS5yZXN0YXJ0ID0gcmVzdGFydDtcblxuICAgIC8vaGVyZGEgbyBjb21wb3J0YW1lbnRvIGJhc2UgZG8gQ1JVRFxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHsgdm06IHZtLCBtb2RlbFNlcnZpY2U6IERpbmFtaWNRdWVyeVNlcnZpY2UsIG9wdGlvbnM6IHtcbiAgICAgICAgc2VhcmNoT25Jbml0OiBmYWxzZVxuICAgICAgfSB9KTtcblxuICAgIGZ1bmN0aW9uIG9uQWN0aXZhdGUoKSB7XG4gICAgICB2bS5yZXN0YXJ0KCk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUHJlcGFyYSBlIGFwbGljYSBvcyBmaWx0cm8gcXVlIHbDo28gc2VyIGVudmlhZG9zIHBhcmEgbyBzZXJ2acOnb1xuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IGRlZmF1bHRRdWVyeUZpbHRlcnNcbiAgICAgKiBAcmV0dXJuc1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGFwcGx5RmlsdGVycyhkZWZhdWx0UXVlcnlGaWx0ZXJzKSB7XG4gICAgICB2YXIgd2hlcmUgPSB7fTtcblxuICAgICAgLyoqXG4gICAgICAgKiBvIHNlcnZpw6dvIGVzcGVyYSB1bSBvYmpldG8gY29tOlxuICAgICAgICogIG8gbm9tZSBkZSB1bSBtb2RlbFxuICAgICAgICogIHVtYSBsaXN0YSBkZSBmaWx0cm9zXG4gICAgICAgKi9cbiAgICAgIGlmICh2bS5hZGRlZEZpbHRlcnMubGVuZ3RoID4gMCkge1xuICAgICAgICB2YXIgYWRkZWRGaWx0ZXJzID0gYW5ndWxhci5jb3B5KHZtLmFkZGVkRmlsdGVycyk7XG5cbiAgICAgICAgd2hlcmUubW9kZWwgPSB2bS5hZGRlZEZpbHRlcnNbMF0ubW9kZWwubmFtZTtcblxuICAgICAgICBmb3IgKHZhciBpbmRleCA9IDA7IGluZGV4IDwgYWRkZWRGaWx0ZXJzLmxlbmd0aDsgaW5kZXgrKykge1xuICAgICAgICAgIHZhciBmaWx0ZXIgPSBhZGRlZEZpbHRlcnNbaW5kZXhdO1xuXG4gICAgICAgICAgZmlsdGVyLm1vZGVsID0gbnVsbDtcbiAgICAgICAgICBmaWx0ZXIuYXR0cmlidXRlID0gZmlsdGVyLmF0dHJpYnV0ZS5uYW1lO1xuICAgICAgICAgIGZpbHRlci5vcGVyYXRvciA9IGZpbHRlci5vcGVyYXRvci52YWx1ZTtcbiAgICAgICAgfVxuXG4gICAgICAgIHdoZXJlLmZpbHRlcnMgPSBhbmd1bGFyLnRvSnNvbihhZGRlZEZpbHRlcnMpO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgd2hlcmUubW9kZWwgPSB2bS5xdWVyeUZpbHRlcnMubW9kZWwubmFtZTtcbiAgICAgIH1cblxuICAgICAgcmV0dXJuIGFuZ3VsYXIuZXh0ZW5kKGRlZmF1bHRRdWVyeUZpbHRlcnMsIHdoZXJlKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDYXJyZWdhIHRvZG9zIG9zIG1vZGVscyBjcmlhZG9zIG5vIHNlcnZpZG9yIGNvbSBzZXVzIGF0cmlidXRvc1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGxvYWRNb2RlbHMoKSB7XG4gICAgICAvL1BlZ2EgdG9kb3Mgb3MgbW9kZWxzIGRvIHNlcnZlciBlIG1vbnRhIHVtYSBsaXN0YSBwcm8gQ29tYm9Cb3hcbiAgICAgIERpbmFtaWNRdWVyeVNlcnZpY2UuZ2V0TW9kZWxzKCkudGhlbihmdW5jdGlvbiAoZGF0YSkge1xuICAgICAgICB2bS5tb2RlbHMgPSBkYXRhO1xuICAgICAgICB2bS5xdWVyeUZpbHRlcnMubW9kZWwgPSB2bS5tb2RlbHNbMF07XG4gICAgICAgIHZtLmxvYWRBdHRyaWJ1dGVzKCk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDYXJyZWdhIG9zIGF0dHJpYnV0b3MgZG8gbW9kZWwgZXNjb2xoaWRvXG4gICAgICovXG4gICAgZnVuY3Rpb24gbG9hZEF0dHJpYnV0ZXMoKSB7XG4gICAgICB2bS5hdHRyaWJ1dGVzID0gdm0ucXVlcnlGaWx0ZXJzLm1vZGVsLmF0dHJpYnV0ZXM7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMuYXR0cmlidXRlID0gdm0uYXR0cmlidXRlc1swXTtcblxuICAgICAgdm0ubG9hZE9wZXJhdG9ycygpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENhcnJlZ2Egb3Mgb3BlcmFkb3JlcyBlc3BlY2lmaWNvcyBwYXJhIG8gdGlwbyBkbyBhdHJpYnV0b1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGxvYWRPcGVyYXRvcnMoKSB7XG4gICAgICB2YXIgb3BlcmF0b3JzID0gW3sgdmFsdWU6ICc9JywgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudCgndmlld3MuZmllbGRzLnF1ZXJ5RGluYW1pYy5vcGVyYXRvcnMuZXF1YWxzJykgfSwgeyB2YWx1ZTogJzw+JywgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudCgndmlld3MuZmllbGRzLnF1ZXJ5RGluYW1pYy5vcGVyYXRvcnMuZGlmZXJlbnQnKSB9XTtcblxuICAgICAgaWYgKHZtLnF1ZXJ5RmlsdGVycy5hdHRyaWJ1dGUudHlwZS5pbmRleE9mKCd2YXJ5aW5nJykgIT09IC0xKSB7XG4gICAgICAgIG9wZXJhdG9ycy5wdXNoKHsgdmFsdWU6ICdoYXMnLFxuICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLmNvbnRlaW5zJykgfSk7XG4gICAgICAgIG9wZXJhdG9ycy5wdXNoKHsgdmFsdWU6ICdzdGFydFdpdGgnLFxuICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLnN0YXJ0V2l0aCcpIH0pO1xuICAgICAgICBvcGVyYXRvcnMucHVzaCh7IHZhbHVlOiAnZW5kV2l0aCcsXG4gICAgICAgICAgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudCgndmlld3MuZmllbGRzLnF1ZXJ5RGluYW1pYy5vcGVyYXRvcnMuZmluaXNoV2l0aCcpIH0pO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgb3BlcmF0b3JzLnB1c2goeyB2YWx1ZTogJz4nLFxuICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLmJpZ2dlclRoYW4nKSB9KTtcbiAgICAgICAgb3BlcmF0b3JzLnB1c2goeyB2YWx1ZTogJz49JyxcbiAgICAgICAgICBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KCd2aWV3cy5maWVsZHMucXVlcnlEaW5hbWljLm9wZXJhdG9ycy5lcXVhbHNPckJpZ2dlclRoYW4nKSB9KTtcbiAgICAgICAgb3BlcmF0b3JzLnB1c2goeyB2YWx1ZTogJzwnLFxuICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLmxlc3NUaGFuJykgfSk7XG4gICAgICAgIG9wZXJhdG9ycy5wdXNoKHsgdmFsdWU6ICc8PScsXG4gICAgICAgICAgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudCgndmlld3MuZmllbGRzLnF1ZXJ5RGluYW1pYy5vcGVyYXRvcnMuZXF1YWxzT3JMZXNzVGhhbicpIH0pO1xuICAgICAgfVxuXG4gICAgICB2bS5vcGVyYXRvcnMgPSBvcGVyYXRvcnM7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMub3BlcmF0b3IgPSB2bS5vcGVyYXRvcnNbMF07XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQWRpY2lvbmEvZWRpdGEgdW0gZmlsdHJvXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gZm9ybSBlbGVtZW50byBodG1sIGRvIGZvcm11bMOhcmlvIHBhcmEgdmFsaWRhw6fDtWVzXG4gICAgICovXG4gICAgZnVuY3Rpb24gYWRkRmlsdGVyKGZvcm0pIHtcbiAgICAgIGlmIChhbmd1bGFyLmlzVW5kZWZpbmVkKHZtLnF1ZXJ5RmlsdGVycy52YWx1ZSkgfHwgdm0ucXVlcnlGaWx0ZXJzLnZhbHVlID09PSAnJykge1xuICAgICAgICBQclRvYXN0LmVycm9yKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMudmFsaWRhdGUuZmllbGRSZXF1aXJlZCcsIHsgZmllbGQ6ICd2YWxvcicgfSkpO1xuICAgICAgICByZXR1cm47XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBpZiAodm0uaW5kZXggPCAwKSB7XG4gICAgICAgICAgdm0uYWRkZWRGaWx0ZXJzLnB1c2goYW5ndWxhci5jb3B5KHZtLnF1ZXJ5RmlsdGVycykpO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIHZtLmFkZGVkRmlsdGVyc1t2bS5pbmRleF0gPSBhbmd1bGFyLmNvcHkodm0ucXVlcnlGaWx0ZXJzKTtcbiAgICAgICAgICB2bS5pbmRleCA9IC0xO1xuICAgICAgICB9XG5cbiAgICAgICAgLy9yZWluaWNpYSBvIGZvcm11bMOhcmlvIGUgYXMgdmFsaWRhw6fDtWVzIGV4aXN0ZW50ZXNcbiAgICAgICAgdm0ucXVlcnlGaWx0ZXJzID0ge307XG4gICAgICAgIGZvcm0uJHNldFByaXN0aW5lKCk7XG4gICAgICAgIGZvcm0uJHNldFVudG91Y2hlZCgpO1xuICAgICAgfVxuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWxpemEgYSBwZXNxdWlzYSB0ZW5kbyBvcyBmaWx0cm9zIGNvbW8gcGFyw6JtZXRyb3NcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBydW5GaWx0ZXIoKSB7XG4gICAgICB2bS5zZWFyY2godm0ucGFnaW5hdG9yLmN1cnJlbnRQYWdlKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBHYXRpbGhvIGFjaW9uYWRvIGRlcG9pcyBkYSBwZXNxdWlzYSByZXNwb25zw6F2ZWwgcG9yIGlkZW50aWZpY2FyIG9zIGF0cmlidXRvc1xuICAgICAqIGNvbnRpZG9zIG5vcyBlbGVtZW50b3MgcmVzdWx0YW50ZXMgZGEgYnVzY2FcbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSBkYXRhIGRhZG9zIHJlZmVyZW50ZSBhbyByZXRvcm5vIGRhIHJlcXVpc2nDp8Ojb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGFmdGVyU2VhcmNoKGRhdGEpIHtcbiAgICAgIHZhciBrZXlzID0gZGF0YS5pdGVtcy5sZW5ndGggPiAwID8gT2JqZWN0LmtleXMoZGF0YS5pdGVtc1swXSkgOiBbXTtcblxuICAgICAgLy9yZXRpcmEgdG9kb3Mgb3MgYXRyaWJ1dG9zIHF1ZSBjb21lw6dhbSBjb20gJC5cbiAgICAgIC8vRXNzZXMgYXRyaWJ1dG9zIHPDo28gYWRpY2lvbmFkb3MgcGVsbyBzZXJ2acOnbyBlIG7Do28gZGV2ZSBhcGFyZWNlciBuYSBsaXN0YWdlbVxuICAgICAgdm0ua2V5cyA9IGxvZGFzaC5maWx0ZXIoa2V5cywgZnVuY3Rpb24gKGtleSkge1xuICAgICAgICByZXR1cm4gIWxvZGFzaC5zdGFydHNXaXRoKGtleSwgJyQnKTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENvbG9hY2Egbm8gZm9ybXVsw6FyaW8gbyBmaWx0cm8gZXNjb2xoaWRvIHBhcmEgZWRpw6fDo29cbiAgICAgKiBAcGFyYW0ge2FueX0gJGluZGV4IGluZGljZSBubyBhcnJheSBkbyBmaWx0cm8gZXNjb2xoaWRvXG4gICAgICovXG4gICAgZnVuY3Rpb24gZWRpdEZpbHRlcigkaW5kZXgpIHtcbiAgICAgIHZtLmluZGV4ID0gJGluZGV4O1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0gdm0uYWRkZWRGaWx0ZXJzWyRpbmRleF07XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVtb3ZlIG8gZmlsdHJvIGVzY29saGlkb1xuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9ICRpbmRleCBpbmRpY2Ugbm8gYXJyYXkgZG8gZmlsdHJvIGVzY29saGlkb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIHJlbW92ZUZpbHRlcigkaW5kZXgpIHtcbiAgICAgIHZtLmFkZGVkRmlsdGVycy5zcGxpY2UoJGluZGV4KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBMaW1wYSBvIGZvcm11bMOhcmlvIGNvcnJlbnRlXG4gICAgICovXG4gICAgZnVuY3Rpb24gY2xlYXIoKSB7XG4gICAgICAvL2d1YXJkYSBvIGluZGljZSBkbyByZWdpc3RybyBxdWUgZXN0w6Egc2VuZG8gZWRpdGFkb1xuICAgICAgdm0uaW5kZXggPSAtMTtcbiAgICAgIC8vdmluY3VsYWRvIGFvcyBjYW1wb3MgZG8gZm9ybXVsw6FyaW9cbiAgICAgIHZtLnF1ZXJ5RmlsdGVycyA9IHt9O1xuXG4gICAgICBpZiAodm0ubW9kZWxzKSB2bS5xdWVyeUZpbHRlcnMubW9kZWwgPSB2bS5tb2RlbHNbMF07XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVpbmljaWEgYSBjb25zdHJ1w6fDo28gZGEgcXVlcnkgbGltcGFuZG8gdHVkb1xuICAgICAqXG4gICAgICovXG4gICAgZnVuY3Rpb24gcmVzdGFydCgpIHtcbiAgICAgIC8vZ3VhcmRhIGF0cmlidXRvcyBkbyByZXN1bHRhZG8gZGEgYnVzY2EgY29ycmVudGVcbiAgICAgIHZtLmtleXMgPSBbXTtcblxuICAgICAgLy9ndWFyZGEgb3MgZmlsdHJvcyBhZGljaW9uYWRvc1xuICAgICAgdm0uYWRkZWRGaWx0ZXJzID0gW107XG4gICAgICB2bS5jbGVhcigpO1xuICAgICAgdm0ubG9hZE1vZGVscygpO1xuICAgIH1cbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZhY3RvcnkoJ2xhbmd1YWdlTG9hZGVyJywgTGFuZ3VhZ2VMb2FkZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gTGFuZ3VhZ2VMb2FkZXIoJHEsIFN1cHBvcnRTZXJ2aWNlLCAkbG9nLCAkaW5qZWN0b3IpIHtcbiAgICB2YXIgc2VydmljZSA9IHRoaXM7XG5cbiAgICBzZXJ2aWNlLnRyYW5zbGF0ZSA9IGZ1bmN0aW9uIChsb2NhbGUpIHtcbiAgICAgIHJldHVybiB7XG4gICAgICAgIGdsb2JhbDogJGluamVjdG9yLmdldChsb2NhbGUgKyAnLmkxOG4uZ2xvYmFsJyksXG4gICAgICAgIHZpZXdzOiAkaW5qZWN0b3IuZ2V0KGxvY2FsZSArICcuaTE4bi52aWV3cycpLFxuICAgICAgICBhdHRyaWJ1dGVzOiAkaW5qZWN0b3IuZ2V0KGxvY2FsZSArICcuaTE4bi5hdHRyaWJ1dGVzJyksXG4gICAgICAgIGRpYWxvZzogJGluamVjdG9yLmdldChsb2NhbGUgKyAnLmkxOG4uZGlhbG9nJyksXG4gICAgICAgIG1lc3NhZ2VzOiAkaW5qZWN0b3IuZ2V0KGxvY2FsZSArICcuaTE4bi5tZXNzYWdlcycpLFxuICAgICAgICBtb2RlbHM6ICRpbmplY3Rvci5nZXQobG9jYWxlICsgJy5pMThuLm1vZGVscycpXG4gICAgICB9O1xuICAgIH07XG5cbiAgICAvLyByZXR1cm4gbG9hZGVyRm5cbiAgICByZXR1cm4gZnVuY3Rpb24gKG9wdGlvbnMpIHtcbiAgICAgICRsb2cuaW5mbygnQ2FycmVnYW5kbyBvIGNvbnRldWRvIGRhIGxpbmd1YWdlbSAnICsgb3B0aW9ucy5rZXkpO1xuXG4gICAgICB2YXIgZGVmZXJyZWQgPSAkcS5kZWZlcigpO1xuXG4gICAgICAvL0NhcnJlZ2EgYXMgbGFuZ3MgcXVlIHByZWNpc2FtIGUgZXN0w6NvIG5vIHNlcnZpZG9yIHBhcmEgbsOjbyBwcmVjaXNhciByZXBldGlyIGFxdWlcbiAgICAgIFN1cHBvcnRTZXJ2aWNlLmxhbmdzKCkudGhlbihmdW5jdGlvbiAobGFuZ3MpIHtcbiAgICAgICAgLy9NZXJnZSBjb20gb3MgbGFuZ3MgZGVmaW5pZG9zIG5vIHNlcnZpZG9yXG4gICAgICAgIHZhciBkYXRhID0gYW5ndWxhci5tZXJnZShzZXJ2aWNlLnRyYW5zbGF0ZShvcHRpb25zLmtleSksIGxhbmdzKTtcblxuICAgICAgICByZXR1cm4gZGVmZXJyZWQucmVzb2x2ZShkYXRhKTtcbiAgICAgIH0sIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgcmV0dXJuIGRlZmVycmVkLnJlc29sdmUoc2VydmljZS50cmFuc2xhdGUob3B0aW9ucy5rZXkpKTtcbiAgICAgIH0pO1xuXG4gICAgICByZXR1cm4gZGVmZXJyZWQucHJvbWlzZTtcbiAgICB9O1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmlsdGVyKCd0QXR0cicsIHRBdHRyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIHRBdHRyKCRmaWx0ZXIpIHtcbiAgICAvKipcbiAgICAgKiBGaWx0cm8gcGFyYSB0cmFkdcOnw6NvIGRlIHVtIGF0cmlidXRvIGRlIHVtIG1vZGVsXG4gICAgICogXG4gICAgICogQHBhcmFtIHthbnl9IG5hbWUgbm9tZSBkbyBhdHJpYnV0b1xuICAgICAqIEByZXR1cm5zIG8gbm9tZSBkbyBhdHJpYnV0byB0cmFkdXppZG8gY2FzbyBlbmNvbnRyZSBzZSBuw6NvIG8gbm9tZSBwYXNzYWRvIHBvciBwYXJhbWV0cm9cbiAgICAgKi9cbiAgICByZXR1cm4gZnVuY3Rpb24gKG5hbWUpIHtcbiAgICAgIHZhciBrZXkgPSAnYXR0cmlidXRlcy4nICsgbmFtZTtcbiAgICAgIHZhciB0cmFuc2xhdGUgPSAkZmlsdGVyKCd0cmFuc2xhdGUnKShrZXkpO1xuXG4gICAgICByZXR1cm4gdHJhbnNsYXRlID09PSBrZXkgPyBuYW1lIDogdHJhbnNsYXRlO1xuICAgIH07XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5maWx0ZXIoJ3RCcmVhZGNydW1iJywgdEJyZWFkY3J1bWIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gdEJyZWFkY3J1bWIoJGZpbHRlcikge1xuICAgIC8qKlxuICAgICAqIEZpbHRybyBwYXJhIHRyYWR1w6fDo28gZG8gYnJlYWRjcnVtYiAodGl0dWxvIGRhIHRlbGEgY29tIHJhc3RyZWlvKVxuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IGlkIGNoYXZlIGNvbSBvIG5vbWUgZG8gc3RhdGUgcmVmZXJlbnRlIHRlbGFcbiAgICAgKiBAcmV0dXJucyBhIHRyYWR1w6fDo28gY2FzbyBlbmNvbnRyZSBzZSBuw6NvIG8gaWQgcGFzc2FkbyBwb3IgcGFyYW1ldHJvXG4gICAgICovXG4gICAgcmV0dXJuIGZ1bmN0aW9uIChpZCkge1xuICAgICAgLy9wZWdhIGEgc2VndW5kYSBwYXJ0ZSBkbyBub21lIGRvIHN0YXRlLCByZXRpcmFuZG8gYSBwYXJ0ZSBhYnN0cmF0YSAoYXBwLilcbiAgICAgIHZhciBrZXkgPSAndmlld3MuYnJlYWRjcnVtYnMuJyArIGlkLnNwbGl0KCcuJylbMV07XG4gICAgICB2YXIgdHJhbnNsYXRlID0gJGZpbHRlcigndHJhbnNsYXRlJykoa2V5KTtcblxuICAgICAgcmV0dXJuIHRyYW5zbGF0ZSA9PT0ga2V5ID8gaWQgOiB0cmFuc2xhdGU7XG4gICAgfTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZpbHRlcigndE1vZGVsJywgdE1vZGVsKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIHRNb2RlbCgkZmlsdGVyKSB7XG4gICAgLyoqXG4gICAgICogRmlsdHJvIHBhcmEgdHJhZHXDp8OjbyBkZSB1bSBhdHJpYnV0byBkZSB1bSBtb2RlbFxuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IG5hbWUgbm9tZSBkbyBhdHJpYnV0b1xuICAgICAqIEByZXR1cm5zIG8gbm9tZSBkbyBhdHJpYnV0byB0cmFkdXppZG8gY2FzbyBlbmNvbnRyZSBzZSBuw6NvIG8gbm9tZSBwYXNzYWRvIHBvciBwYXJhbWV0cm9cbiAgICAgKi9cbiAgICByZXR1cm4gZnVuY3Rpb24gKG5hbWUpIHtcbiAgICAgIHZhciBrZXkgPSAnbW9kZWxzLicgKyBuYW1lLnRvTG93ZXJDYXNlKCk7XG4gICAgICB2YXIgdHJhbnNsYXRlID0gJGZpbHRlcigndHJhbnNsYXRlJykoa2V5KTtcblxuICAgICAgcmV0dXJuIHRyYW5zbGF0ZSA9PT0ga2V5ID8gbmFtZSA6IHRyYW5zbGF0ZTtcbiAgICB9O1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLnJ1bihhdXRoZW50aWNhdGlvbkxpc3RlbmVyKTtcblxuICAvKipcbiAgICogTGlzdGVuIGFsbCBzdGF0ZSAocGFnZSkgY2hhbmdlcy4gRXZlcnkgdGltZSBhIHN0YXRlIGNoYW5nZSBuZWVkIHRvIHZlcmlmeSB0aGUgdXNlciBpcyBhdXRoZW50aWNhdGVkIG9yIG5vdCB0b1xuICAgKiByZWRpcmVjdCB0byBjb3JyZWN0IHBhZ2UuIFdoZW4gYSB1c2VyIGNsb3NlIHRoZSBicm93c2VyIHdpdGhvdXQgbG9nb3V0LCB3aGVuIGhpbSByZW9wZW4gdGhlIGJyb3dzZXIgdGhpcyBldmVudFxuICAgKiByZWF1dGhlbnRpY2F0ZSB0aGUgdXNlciB3aXRoIHRoZSBwZXJzaXN0ZW50IHRva2VuIG9mIHRoZSBsb2NhbCBzdG9yYWdlLlxuICAgKlxuICAgKiBXZSBkb24ndCBjaGVjayBpZiB0aGUgdG9rZW4gaXMgZXhwaXJlZCBvciBub3QgaW4gdGhlIHBhZ2UgY2hhbmdlLCBiZWNhdXNlIGlzIGdlbmVyYXRlIGFuIHVuZWNlc3Nhcnkgb3ZlcmhlYWQuXG4gICAqIElmIHRoZSB0b2tlbiBpcyBleHBpcmVkIHdoZW4gdGhlIHVzZXIgdHJ5IHRvIGNhbGwgdGhlIGZpcnN0IGFwaSB0byBnZXQgZGF0YSwgaGltIHdpbGwgYmUgbG9nb2ZmIGFuZCByZWRpcmVjdFxuICAgKiB0byBsb2dpbiBwYWdlLlxuICAgKlxuICAgKiBAcGFyYW0gJHJvb3RTY29wZVxuICAgKiBAcGFyYW0gJHN0YXRlXG4gICAqIEBwYXJhbSAkc3RhdGVQYXJhbXNcbiAgICogQHBhcmFtIEF1dGhcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gYXV0aGVudGljYXRpb25MaXN0ZW5lcigkcm9vdFNjb3BlLCAkc3RhdGUsIEdsb2JhbCwgQXV0aCwgUHJUb2FzdCwgLy8gTk9TT05BUlxuICAkdHJhbnNsYXRlKSB7XG5cbiAgICAvL29ubHkgd2hlbiBhcHBsaWNhdGlvbiBzdGFydCBjaGVjayBpZiB0aGUgZXhpc3RlbnQgdG9rZW4gc3RpbGwgdmFsaWRcbiAgICBBdXRoLnJlbW90ZVZhbGlkYXRlVG9rZW4oKS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgIC8vaWYgdGhlIHRva2VuIGlzIHZhbGlkIGNoZWNrIGlmIGV4aXN0cyB0aGUgdXNlciBiZWNhdXNlIHRoZSBicm93c2VyIGNvdWxkIGJlIGNsb3NlZFxuICAgICAgLy9hbmQgdGhlIHVzZXIgZGF0YSBpc24ndCBpbiBtZW1vcnlcbiAgICAgIGlmIChBdXRoLmN1cnJlbnRVc2VyID09PSBudWxsKSB7XG4gICAgICAgIEF1dGgudXBkYXRlQ3VycmVudFVzZXIoYW5ndWxhci5mcm9tSnNvbihsb2NhbFN0b3JhZ2UuZ2V0SXRlbSgndXNlcicpKSk7XG4gICAgICB9XG4gICAgfSk7XG5cbiAgICAvL0NoZWNrIGlmIHRoZSB0b2tlbiBzdGlsbCB2YWxpZC5cbiAgICAkcm9vdFNjb3BlLiRvbignJHN0YXRlQ2hhbmdlU3RhcnQnLCBmdW5jdGlvbiAoZXZlbnQsIHRvU3RhdGUpIHtcbiAgICAgIGlmICh0b1N0YXRlLmRhdGEubmVlZEF1dGhlbnRpY2F0aW9uIHx8IHRvU3RhdGUuZGF0YS5uZWVkUHJvZmlsZSkge1xuICAgICAgICAvL2RvbnQgdHJhaXQgdGhlIHN1Y2Nlc3MgYmxvY2sgYmVjYXVzZSBhbHJlYWR5IGRpZCBieSB0b2tlbiBpbnRlcmNlcHRvclxuICAgICAgICBBdXRoLnJlbW90ZVZhbGlkYXRlVG9rZW4oKS5jYXRjaChmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgUHJUb2FzdC53YXJuKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMubG9naW4ubG9nb3V0SW5hY3RpdmUnKSk7XG5cbiAgICAgICAgICBpZiAodG9TdGF0ZS5uYW1lICE9PSBHbG9iYWwubG9naW5TdGF0ZSkge1xuICAgICAgICAgICAgJHN0YXRlLmdvKEdsb2JhbC5sb2dpblN0YXRlKTtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICBldmVudC5wcmV2ZW50RGVmYXVsdCgpO1xuICAgICAgICB9KTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIC8vaWYgdGhlIHVzZSBpcyBhdXRoZW50aWNhdGVkIGFuZCBuZWVkIHRvIGVudGVyIGluIGxvZ2luIHBhZ2VcbiAgICAgICAgLy9oaW0gd2lsbCBiZSByZWRpcmVjdGVkIHRvIGhvbWUgcGFnZVxuICAgICAgICBpZiAodG9TdGF0ZS5uYW1lID09PSBHbG9iYWwubG9naW5TdGF0ZSAmJiBBdXRoLmF1dGhlbnRpY2F0ZWQoKSkge1xuICAgICAgICAgICRzdGF0ZS5nbyhHbG9iYWwuaG9tZVN0YXRlKTtcbiAgICAgICAgICBldmVudC5wcmV2ZW50RGVmYXVsdCgpO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykucnVuKGF1dGhvcml6YXRpb25MaXN0ZW5lcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiBhdXRob3JpemF0aW9uTGlzdGVuZXIoJHJvb3RTY29wZSwgJHN0YXRlLCBHbG9iYWwsIEF1dGgpIHtcbiAgICAvKipcbiAgICAgKiBBIGNhZGEgbXVkYW7Dp2EgZGUgZXN0YWRvIChcInDDoWdpbmFcIikgdmVyaWZpY2Egc2UgbyB1c3XDoXJpbyB0ZW0gbyBwZXJmaWxcbiAgICAgKiBuZWNlc3PDoXJpbyBwYXJhIG8gYWNlc3NvIGEgbWVzbWFcbiAgICAgKi9cbiAgICAkcm9vdFNjb3BlLiRvbignJHN0YXRlQ2hhbmdlU3RhcnQnLCBmdW5jdGlvbiAoZXZlbnQsIHRvU3RhdGUpIHtcbiAgICAgIGlmICh0b1N0YXRlLmRhdGEgJiYgdG9TdGF0ZS5kYXRhLm5lZWRBdXRoZW50aWNhdGlvbiAmJiB0b1N0YXRlLmRhdGEubmVlZFByb2ZpbGUgJiYgQXV0aC5hdXRoZW50aWNhdGVkKCkgJiYgIUF1dGguY3VycmVudFVzZXIuaGFzUHJvZmlsZSh0b1N0YXRlLmRhdGEubmVlZFByb2ZpbGUsIHRvU3RhdGUuZGF0YS5hbGxQcm9maWxlcykpIHtcblxuICAgICAgICAkc3RhdGUuZ28oR2xvYmFsLm5vdEF1dGhvcml6ZWRTdGF0ZSk7XG4gICAgICAgIGV2ZW50LnByZXZlbnREZWZhdWx0KCk7XG4gICAgICB9XG4gICAgfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29uZmlnKHNwaW5uZXJJbnRlcmNlcHRvcik7XG5cbiAgZnVuY3Rpb24gc3Bpbm5lckludGVyY2VwdG9yKCRodHRwUHJvdmlkZXIsICRwcm92aWRlKSB7XG4gICAgLyoqXG4gICAgICogRXN0ZSBpbnRlcmNlcHRvciDDqSByZXNwb25zw6F2ZWwgcG9yIG1vc3RyYXIgZSBlc2NvbmRlciBvXG4gICAgICogY29tcG9uZW50ZSBQclNwaW5uZXIgc2VtcHJlIHF1ZSB1bWEgcmVxdWlzacOnw6NvIGFqYXhcbiAgICAgKiBpbmljaWFyIGUgZmluYWxpemFyLlxuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9ICRxXG4gICAgICogQHBhcmFtIHthbnl9ICRpbmplY3RvclxuICAgICAqIEByZXR1cm5zXG4gICAgICovXG4gICAgZnVuY3Rpb24gc2hvd0hpZGVTcGlubmVyKCRxLCAkaW5qZWN0b3IpIHtcbiAgICAgIHJldHVybiB7XG4gICAgICAgIHJlcXVlc3Q6IGZ1bmN0aW9uIHJlcXVlc3QoY29uZmlnKSB7XG4gICAgICAgICAgJGluamVjdG9yLmdldCgnUHJTcGlubmVyJykuc2hvdygpO1xuXG4gICAgICAgICAgcmV0dXJuIGNvbmZpZztcbiAgICAgICAgfSxcblxuICAgICAgICByZXNwb25zZTogZnVuY3Rpb24gcmVzcG9uc2UoX3Jlc3BvbnNlKSB7XG4gICAgICAgICAgJGluamVjdG9yLmdldCgnUHJTcGlubmVyJykuaGlkZSgpO1xuXG4gICAgICAgICAgcmV0dXJuIF9yZXNwb25zZTtcbiAgICAgICAgfSxcblxuICAgICAgICByZXNwb25zZUVycm9yOiBmdW5jdGlvbiByZXNwb25zZUVycm9yKHJlamVjdGlvbikge1xuICAgICAgICAgICRpbmplY3Rvci5nZXQoJ1ByU3Bpbm5lcicpLmhpZGUoKTtcblxuICAgICAgICAgIHJldHVybiAkcS5yZWplY3QocmVqZWN0aW9uKTtcbiAgICAgICAgfVxuICAgICAgfTtcbiAgICB9XG5cbiAgICAvLyBEZWZpbmUgdW1hIGZhY3RvcnkgcGFyYSBvICRodHRwSW50ZXJjZXB0b3JcbiAgICAkcHJvdmlkZS5mYWN0b3J5KCdzaG93SGlkZVNwaW5uZXInLCBzaG93SGlkZVNwaW5uZXIpO1xuXG4gICAgLy8gQWRpY2lvbmEgYSBmYWN0b3J5IG5vIGFycmF5IGRlIGludGVyY2VwdG9ycyBkbyAkaHR0cFxuICAgICRodHRwUHJvdmlkZXIuaW50ZXJjZXB0b3JzLnB1c2goJ3Nob3dIaWRlU3Bpbm5lcicpO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4vKmVzbGludCBhbmd1bGFyL21vZHVsZS1nZXR0ZXI6IDAqL1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbmZpZyh0b2tlbkludGVyY2VwdG9yKTtcblxuICAvKipcbiAgICogSW50ZXJjZXB0IGFsbCByZXNwb25zZSAoc3VjY2VzcyBvciBlcnJvcikgdG8gdmVyaWZ5IHRoZSByZXR1cm5lZCB0b2tlblxuICAgKlxuICAgKiBAcGFyYW0gJGh0dHBQcm92aWRlclxuICAgKiBAcGFyYW0gJHByb3ZpZGVcbiAgICogQHBhcmFtIEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiB0b2tlbkludGVyY2VwdG9yKCRodHRwUHJvdmlkZXIsICRwcm92aWRlLCBHbG9iYWwpIHtcblxuICAgIGZ1bmN0aW9uIHJlZGlyZWN0V2hlblNlcnZlckxvZ2dlZE91dCgkcSwgJGluamVjdG9yKSB7XG4gICAgICByZXR1cm4ge1xuICAgICAgICByZXF1ZXN0OiBmdW5jdGlvbiByZXF1ZXN0KGNvbmZpZykge1xuICAgICAgICAgIHZhciB0b2tlbiA9ICRpbmplY3Rvci5nZXQoJ0F1dGgnKS5nZXRUb2tlbigpO1xuXG4gICAgICAgICAgaWYgKHRva2VuKSB7XG4gICAgICAgICAgICBjb25maWcuaGVhZGVyc1snQXV0aG9yaXphdGlvbiddID0gJ0JlYXJlciAnICsgdG9rZW47XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgcmV0dXJuIGNvbmZpZztcbiAgICAgICAgfSxcbiAgICAgICAgcmVzcG9uc2U6IGZ1bmN0aW9uIHJlc3BvbnNlKF9yZXNwb25zZSkge1xuICAgICAgICAgIC8vIGdldCBhIG5ldyByZWZyZXNoIHRva2VuIHRvIHVzZSBpbiB0aGUgbmV4dCByZXF1ZXN0XG4gICAgICAgICAgdmFyIHRva2VuID0gX3Jlc3BvbnNlLmhlYWRlcnMoJ0F1dGhvcml6YXRpb24nKTtcblxuICAgICAgICAgIGlmICh0b2tlbikge1xuICAgICAgICAgICAgJGluamVjdG9yLmdldCgnQXV0aCcpLnNldFRva2VuKHRva2VuLnNwbGl0KCcgJylbMV0pO1xuICAgICAgICAgIH1cbiAgICAgICAgICByZXR1cm4gX3Jlc3BvbnNlO1xuICAgICAgICB9LFxuICAgICAgICByZXNwb25zZUVycm9yOiBmdW5jdGlvbiByZXNwb25zZUVycm9yKHJlamVjdGlvbikge1xuICAgICAgICAgIC8vIEluc3RlYWQgb2YgY2hlY2tpbmcgZm9yIGEgc3RhdHVzIGNvZGUgb2YgNDAwIHdoaWNoIG1pZ2h0IGJlIHVzZWRcbiAgICAgICAgICAvLyBmb3Igb3RoZXIgcmVhc29ucyBpbiBMYXJhdmVsLCB3ZSBjaGVjayBmb3IgdGhlIHNwZWNpZmljIHJlamVjdGlvblxuICAgICAgICAgIC8vIHJlYXNvbnMgdG8gdGVsbCB1cyBpZiB3ZSBuZWVkIHRvIHJlZGlyZWN0IHRvIHRoZSBsb2dpbiBzdGF0ZVxuICAgICAgICAgIHZhciByZWplY3Rpb25SZWFzb25zID0gWyd0b2tlbl9ub3RfcHJvdmlkZWQnLCAndG9rZW5fZXhwaXJlZCcsICd0b2tlbl9hYnNlbnQnLCAndG9rZW5faW52YWxpZCddO1xuXG4gICAgICAgICAgdmFyIHRva2VuRXJyb3IgPSBmYWxzZTtcblxuICAgICAgICAgIGFuZ3VsYXIuZm9yRWFjaChyZWplY3Rpb25SZWFzb25zLCBmdW5jdGlvbiAodmFsdWUpIHtcbiAgICAgICAgICAgIGlmIChyZWplY3Rpb24uZGF0YSAmJiByZWplY3Rpb24uZGF0YS5lcnJvciA9PT0gdmFsdWUpIHtcbiAgICAgICAgICAgICAgdG9rZW5FcnJvciA9IHRydWU7XG5cbiAgICAgICAgICAgICAgJGluamVjdG9yLmdldCgnQXV0aCcpLmxvZ291dCgpLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgIHZhciAkc3RhdGUgPSAkaW5qZWN0b3IuZ2V0KCckc3RhdGUnKTtcblxuICAgICAgICAgICAgICAgIC8vIGluIGNhc2UgbXVsdGlwbGUgYWpheCByZXF1ZXN0IGZhaWwgYXQgc2FtZSB0aW1lIGJlY2F1c2UgdG9rZW4gcHJvYmxlbXMsXG4gICAgICAgICAgICAgICAgLy8gb25seSB0aGUgZmlyc3Qgd2lsbCByZWRpcmVjdFxuICAgICAgICAgICAgICAgIGlmICghJHN0YXRlLmlzKEdsb2JhbC5sb2dpblN0YXRlKSkge1xuICAgICAgICAgICAgICAgICAgJHN0YXRlLmdvKEdsb2JhbC5sb2dpblN0YXRlKTtcblxuICAgICAgICAgICAgICAgICAgLy9jbG9zZSBhbnkgZGlhbG9nIHRoYXQgaXMgb3BlbmVkXG4gICAgICAgICAgICAgICAgICAkaW5qZWN0b3IuZ2V0KCdQckRpYWxvZycpLmNsb3NlKCk7XG5cbiAgICAgICAgICAgICAgICAgIGV2ZW50LnByZXZlbnREZWZhdWx0KCk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9KTtcblxuICAgICAgICAgIC8vZGVmaW5lIGRhdGEgdG8gZW1wdHkgYmVjYXVzZSBhbHJlYWR5IHNob3cgUHJUb2FzdCB0b2tlbiBtZXNzYWdlXG4gICAgICAgICAgaWYgKHRva2VuRXJyb3IpIHtcbiAgICAgICAgICAgIHJlamVjdGlvbi5kYXRhID0ge307XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbihyZWplY3Rpb24uaGVhZGVycykpIHtcbiAgICAgICAgICAgIC8vIG1hbnkgc2VydmVycyBlcnJvcnMgKGJ1c2luZXNzKSBhcmUgaW50ZXJjZXB0IGhlcmUgYnV0IGdlbmVyYXRlZCBhIG5ldyByZWZyZXNoIHRva2VuXG4gICAgICAgICAgICAvLyBhbmQgbmVlZCB1cGRhdGUgY3VycmVudCB0b2tlblxuICAgICAgICAgICAgdmFyIHRva2VuID0gcmVqZWN0aW9uLmhlYWRlcnMoJ0F1dGhvcml6YXRpb24nKTtcblxuICAgICAgICAgICAgaWYgKHRva2VuKSB7XG4gICAgICAgICAgICAgICRpbmplY3Rvci5nZXQoJ0F1dGgnKS5zZXRUb2tlbih0b2tlbi5zcGxpdCgnICcpWzFdKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9XG5cbiAgICAgICAgICByZXR1cm4gJHEucmVqZWN0KHJlamVjdGlvbik7XG4gICAgICAgIH1cbiAgICAgIH07XG4gICAgfVxuXG4gICAgLy8gU2V0dXAgZm9yIHRoZSAkaHR0cEludGVyY2VwdG9yXG4gICAgJHByb3ZpZGUuZmFjdG9yeSgncmVkaXJlY3RXaGVuU2VydmVyTG9nZ2VkT3V0JywgcmVkaXJlY3RXaGVuU2VydmVyTG9nZ2VkT3V0KTtcblxuICAgIC8vIFB1c2ggdGhlIG5ldyBmYWN0b3J5IG9udG8gdGhlICRodHRwIGludGVyY2VwdG9yIGFycmF5XG4gICAgJGh0dHBQcm92aWRlci5pbnRlcmNlcHRvcnMucHVzaCgncmVkaXJlY3RXaGVuU2VydmVyTG9nZ2VkT3V0Jyk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29uZmlnKHZhbGlkYXRpb25JbnRlcmNlcHRvcik7XG5cbiAgZnVuY3Rpb24gdmFsaWRhdGlvbkludGVyY2VwdG9yKCRodHRwUHJvdmlkZXIsICRwcm92aWRlKSB7XG4gICAgLyoqXG4gICAgICogRXN0ZSBpbnRlcmNlcHRvciDDqSByZXNwb25zw6F2ZWwgcG9yIG1vc3RyYXIgYXNcbiAgICAgKiBtZW5zYWdlbnMgZGUgZXJybyByZWZlcmVudGUgYXMgdmFsaWRhw6fDtWVzIGRvIGJhY2stZW5kXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gJHFcbiAgICAgKiBAcGFyYW0ge2FueX0gJGluamVjdG9yXG4gICAgICogQHJldHVybnNcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBzaG93RXJyb3JWYWxpZGF0aW9uKCRxLCAkaW5qZWN0b3IpIHtcbiAgICAgIHJldHVybiB7XG4gICAgICAgIHJlc3BvbnNlRXJyb3I6IGZ1bmN0aW9uIHJlc3BvbnNlRXJyb3IocmVqZWN0aW9uKSB7XG4gICAgICAgICAgdmFyIFByVG9hc3QgPSAkaW5qZWN0b3IuZ2V0KCdQclRvYXN0Jyk7XG4gICAgICAgICAgdmFyICR0cmFuc2xhdGUgPSAkaW5qZWN0b3IuZ2V0KCckdHJhbnNsYXRlJyk7XG5cbiAgICAgICAgICBpZiAocmVqZWN0aW9uLmNvbmZpZy5kYXRhICYmICFyZWplY3Rpb24uY29uZmlnLmRhdGEuc2tpcFZhbGlkYXRpb24pIHtcbiAgICAgICAgICAgIGlmIChyZWplY3Rpb24uZGF0YSAmJiByZWplY3Rpb24uZGF0YS5lcnJvcikge1xuXG4gICAgICAgICAgICAgIC8vdmVyaWZpY2Egc2Ugb2NvcnJldSBhbGd1bSBlcnJvIHJlZmVyZW50ZSBhbyB0b2tlblxuICAgICAgICAgICAgICBpZiAocmVqZWN0aW9uLmRhdGEuZXJyb3Iuc3RhcnRzV2l0aCgndG9rZW5fJykpIHtcbiAgICAgICAgICAgICAgICBQclRvYXN0Lndhcm4oJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5sb2dpbi5sb2dvdXRJbmFjdGl2ZScpKTtcbiAgICAgICAgICAgICAgfSBlbHNlIGlmIChyZWplY3Rpb24uZGF0YS5lcnJvciAhPT0gJ05vdCBGb3VuZCcpIHtcbiAgICAgICAgICAgICAgICBQclRvYXN0LmVycm9yKCR0cmFuc2xhdGUuaW5zdGFudChyZWplY3Rpb24uZGF0YS5lcnJvcikpO1xuICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICBQclRvYXN0LmVycm9yVmFsaWRhdGlvbihyZWplY3Rpb24uZGF0YSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgcmV0dXJuICRxLnJlamVjdChyZWplY3Rpb24pO1xuICAgICAgICB9XG4gICAgICB9O1xuICAgIH1cblxuICAgIC8vIERlZmluZSB1bWEgZmFjdG9yeSBwYXJhIG8gJGh0dHBJbnRlcmNlcHRvclxuICAgICRwcm92aWRlLmZhY3RvcnkoJ3Nob3dFcnJvclZhbGlkYXRpb24nLCBzaG93RXJyb3JWYWxpZGF0aW9uKTtcblxuICAgIC8vIEFkaWNpb25hIGEgZmFjdG9yeSBubyBhcnJheSBkZSBpbnRlcmNlcHRvcnMgZG8gJGh0dHBcbiAgICAkaHR0cFByb3ZpZGVyLmludGVyY2VwdG9ycy5wdXNoKCdzaG93RXJyb3JWYWxpZGF0aW9uJyk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb250cm9sbGVyKCdLYW5iYW5Db250cm9sbGVyJywgS2FuYmFuQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBLYW5iYW5Db250cm9sbGVyKCRjb250cm9sbGVyLCBUYXNrc1NlcnZpY2UsIFN0YXR1c1NlcnZpY2UsIFByVG9hc3QsICRtZERpYWxvZywgJGRvY3VtZW50LCBBdXRoLCBQcm9qZWN0c1NlcnZpY2UpIHtcbiAgICAvL0F0dHJpYnV0ZXMgQmxvY2tcbiAgICB2YXIgdm0gPSB0aGlzO1xuICAgIHZhciBmaWVsZHMgPSBbeyBuYW1lOiAnaWQnLCB0eXBlOiAnc3RyaW5nJyB9LCB7IG5hbWU6ICdzdGF0dXMnLCBtYXA6ICdzdGF0ZScsIHR5cGU6ICdzdHJpbmcnIH0sIHsgbmFtZTogJ3RleHQnLCBtYXA6ICdsYWJlbCcsIHR5cGU6ICdzdHJpbmcnIH0sIHsgbmFtZTogJ3RhZ3MnLCB0eXBlOiAnc3RyaW5nJyB9XTtcblxuICAgIHZtLm9uQWN0aXZhdGUgPSBmdW5jdGlvbiAoKSB7XG4gICAgICB2bS5wcm9qZWN0ID0gbG9jYWxTdG9yYWdlLmdldEl0ZW0oJ3Byb2plY3QnKTtcbiAgICAgIFByb2plY3RzU2VydmljZS5xdWVyeSh7IHByb2plY3RfaWQ6IHZtLnByb2plY3QgfSkudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgdm0uYWN0dWFsUHJvamVjdCA9IHJlc3BvbnNlWzBdO1xuICAgICAgfSk7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMgPSB7IHByb2plY3RfaWQ6IHZtLnByb2plY3QgfTtcbiAgICAgIHZtLmlzTW92ZWQgPSBmYWxzZTtcbiAgICB9O1xuXG4gICAgdm0uYXBwbHlGaWx0ZXJzID0gZnVuY3Rpb24gKGRlZmF1bHRRdWVyeUZpbHRlcnMpIHtcbiAgICAgIHJldHVybiBhbmd1bGFyLmV4dGVuZChkZWZhdWx0UXVlcnlGaWx0ZXJzLCB2bS5xdWVyeUZpbHRlcnMpO1xuICAgIH07XG5cbiAgICB2bS5hZnRlclNlYXJjaCA9IGZ1bmN0aW9uICgpIHtcbiAgICAgIHZhciBjb2x1bW5zID0gW107XG4gICAgICB2YXIgdGFza3MgPSBbXTtcblxuICAgICAgU3RhdHVzU2VydmljZS5xdWVyeSgpLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgIHJlc3BvbnNlLmZvckVhY2goZnVuY3Rpb24gKHN0YXR1cykge1xuICAgICAgICAgIGNvbHVtbnMucHVzaCh7IHRleHQ6IHN0YXR1cy5uYW1lLCBkYXRhRmllbGQ6IHN0YXR1cy5zbHVnLCBjb2xsYXBzaWJsZTogZmFsc2UgfSk7XG4gICAgICAgIH0pO1xuXG4gICAgICAgIGlmICh2bS5yZXNvdXJjZXMubGVuZ3RoID4gMCkge1xuICAgICAgICAgIHZtLnJlc291cmNlcy5mb3JFYWNoKGZ1bmN0aW9uICh0YXNrKSB7XG4gICAgICAgICAgICB0YXNrcy5wdXNoKHtcbiAgICAgICAgICAgICAgaWQ6IHRhc2suaWQsXG4gICAgICAgICAgICAgIHN0YXRlOiB0YXNrLnN0YXR1cy5zbHVnLFxuICAgICAgICAgICAgICBsYWJlbDogdGFzay50aXRsZSxcbiAgICAgICAgICAgICAgdGFnczogdGFzay50eXBlLm5hbWUgKyAnLCAnICsgdGFzay5wcmlvcml0eS5uYW1lXG4gICAgICAgICAgICB9KTtcbiAgICAgICAgICB9KTtcblxuICAgICAgICAgIHZhciBzb3VyY2UgPSB7XG4gICAgICAgICAgICBsb2NhbERhdGE6IHRhc2tzLFxuICAgICAgICAgICAgZGF0YVR5cGU6ICdhcnJheScsXG4gICAgICAgICAgICBkYXRhRmllbGRzOiBmaWVsZHNcbiAgICAgICAgICB9O1xuICAgICAgICAgIHZhciBkYXRhQWRhcHRlciA9IG5ldyAkLmpxeC5kYXRhQWRhcHRlcihzb3VyY2UpO1xuXG4gICAgICAgICAgdm0uc2V0dGluZ3MgPSB7XG4gICAgICAgICAgICBzb3VyY2U6IGRhdGFBZGFwdGVyLFxuICAgICAgICAgICAgY29sdW1uczogY29sdW1ucyxcbiAgICAgICAgICAgIHRoZW1lOiAnbGlnaHQnXG4gICAgICAgICAgfTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICB2bS5zZXR0aW5ncyA9IHtcbiAgICAgICAgICAgIHNvdXJjZTogW3t9XSxcbiAgICAgICAgICAgIGNvbHVtbnM6IGNvbHVtbnMsXG4gICAgICAgICAgICB0aGVtZTogJ2xpZ2h0J1xuICAgICAgICAgIH07XG4gICAgICAgIH1cbiAgICAgICAgdm0ua2FuYmFuUmVhZHkgPSB0cnVlO1xuICAgICAgfSk7XG4gICAgfTtcblxuICAgIHZtLm9uSXRlbU1vdmVkID0gZnVuY3Rpb24gKGV2ZW50KSB7XG4gICAgICBpZiAoIXZtLmFjdHVhbFByb2plY3QuZG9uZSAmJiBBdXRoLmN1cnJlbnRVc2VyLmlkID09PSB2bS5hY3R1YWxQcm9qZWN0Lm93bmVyKSB7XG4gICAgICAgIHZtLmlzTW92ZWQgPSB0cnVlO1xuICAgICAgICBUYXNrc1NlcnZpY2UucXVlcnkoeyB0YXNrX2lkOiBldmVudC5hcmdzLml0ZW1JZCB9KS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICAgIGlmIChyZXNwb25zZVswXS5taWxlc3RvbmUgJiYgcmVzcG9uc2VbMF0ubWlsZXN0b25lLmRvbmUgfHwgcmVzcG9uc2VbMF0ucHJvamVjdC5kb25lKSB7XG4gICAgICAgICAgICBQclRvYXN0LmVycm9yKCdOw6NvIMOpIHBvc3PDrXZlbCBtb2RpZmljYXIgbyBzdGF0dXMgZGUgdW1hIHRhcmVmYSBmaW5hbGl6YWRhLicpO1xuICAgICAgICAgICAgdm0uYWZ0ZXJTZWFyY2goKTtcbiAgICAgICAgICAgIHZtLmlzTW92ZWQgPSBmYWxzZTtcbiAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgVGFza3NTZXJ2aWNlLnVwZGF0ZVRhc2tCeUthbmJhbih7XG4gICAgICAgICAgICAgIHByb2plY3RfaWQ6IHZtLnByb2plY3QsXG4gICAgICAgICAgICAgIGlkOiBldmVudC5hcmdzLml0ZW1JZCxcbiAgICAgICAgICAgICAgb2xkQ29sdW1uOiBldmVudC5hcmdzLm9sZENvbHVtbixcbiAgICAgICAgICAgICAgbmV3Q29sdW1uOiBldmVudC5hcmdzLm5ld0NvbHVtbiB9KS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgdm0uaXNNb3ZlZCA9IGZhbHNlO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgfVxuICAgICAgICB9KTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHZtLmFmdGVyU2VhcmNoKCk7XG4gICAgICB9XG4gICAgfTtcblxuICAgIHZtLm9uSXRlbUNsaWNrZWQgPSBmdW5jdGlvbiAoZXZlbnQpIHtcbiAgICAgIGlmICghdm0uaXNNb3ZlZCkge1xuICAgICAgICBUYXNrc1NlcnZpY2UucXVlcnkoeyB0YXNrX2lkOiBldmVudC5hcmdzLml0ZW1JZCB9KS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICAgIHZtLnRhc2tJbmZvID0gcmVzcG9uc2VbMF07XG4gICAgICAgICAgJG1kRGlhbG9nLnNob3coe1xuICAgICAgICAgICAgcGFyZW50OiBhbmd1bGFyLmVsZW1lbnQoJGRvY3VtZW50LmJvZHkpLFxuICAgICAgICAgICAgdGVtcGxhdGVVcmw6ICdjbGllbnQvYXBwL2thbmJhbi90YXNrLWluZm8tZGlhbG9nL3Rhc2tJbmZvLmh0bWwnLFxuICAgICAgICAgICAgY29udHJvbGxlckFzOiAndGFza0luZm9DdHJsJyxcbiAgICAgICAgICAgIGNvbnRyb2xsZXI6ICdUYXNrSW5mb0NvbnRyb2xsZXInLFxuICAgICAgICAgICAgYmluZFRvQ29udHJvbGxlcjogdHJ1ZSxcbiAgICAgICAgICAgIGxvY2Fsczoge1xuICAgICAgICAgICAgICB0YXNrOiB2bS50YXNrSW5mbyxcbiAgICAgICAgICAgICAgY2xvc2U6IGNsb3NlXG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgZXNjYXBlVG9DbG9zZTogdHJ1ZSxcbiAgICAgICAgICAgIGNsaWNrT3V0c2lkZVRvQ2xvc2U6IHRydWVcbiAgICAgICAgICB9KTtcbiAgICAgICAgfSk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICB2bS5pc01vdmVkID0gZmFsc2U7XG4gICAgICB9XG4gICAgfTtcblxuICAgIGZ1bmN0aW9uIGNsb3NlKCkge1xuICAgICAgJG1kRGlhbG9nLmhpZGUoKTtcbiAgICB9XG5cbiAgICAvLyBpbnN0YW50aWF0ZSBiYXNlIGNvbnRyb2xsZXJcbiAgICAkY29udHJvbGxlcignQ1JVRENvbnRyb2xsZXInLCB7IHZtOiB2bSwgbW9kZWxTZXJ2aWNlOiBUYXNrc1NlcnZpY2UsIG9wdGlvbnM6IHt9IH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKlxuICAgKiBBcnF1aXZvIGRlIGNvbmZpZ3VyYcOnw6NvIGNvbSBhcyByb3RhcyBlc3BlY8OtZmljYXMgZG8gcmVjdXJzbyBrYW5iYW5cbiAgICpcbiAgICogQHBhcmFtIHtvYmplY3R9ICRzdGF0ZVByb3ZpZGVyXG4gICAqIEBwYXJhbSB7b2JqZWN0fSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnYXBwLmthbmJhbicsIHtcbiAgICAgIHVybDogJy9rYW5iYW4nLFxuICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9rYW5iYW4va2FuYmFuLmh0bWwnLFxuICAgICAgY29udHJvbGxlcjogJ0thbmJhbkNvbnRyb2xsZXIgYXMga2FuYmFuQ3RybCcsXG4gICAgICBkYXRhOiB7fVxuICAgIH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZhY3RvcnkoJ0thbmJhblNlcnZpY2UnLCBLYW5iYW5TZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIEthbmJhblNlcnZpY2Uoc2VydmljZUZhY3RvcnkpIHtcbiAgICB2YXIgbW9kZWwgPSBzZXJ2aWNlRmFjdG9yeSgna2FuYmFuJywge1xuICAgICAgYWN0aW9uczoge30sXG4gICAgICBpbnN0YW5jZToge31cbiAgICB9KTtcblxuICAgIHJldHVybiBtb2RlbDtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuLyplc2xpbnQtZW52IGVzNiovXG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb250cm9sbGVyKCdNZW51Q29udHJvbGxlcicsIE1lbnVDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIE1lbnVDb250cm9sbGVyKCRtZFNpZGVuYXYsICRzdGF0ZSwgJG1kQ29sb3JzKSB7XG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIC8vQmxvY28gZGUgZGVjbGFyYWNvZXMgZGUgZnVuY29lc1xuICAgIHZtLm9wZW4gPSBvcGVuO1xuICAgIHZtLm9wZW5NZW51T3JSZWRpcmVjdFRvU3RhdGUgPSBvcGVuTWVudU9yUmVkaXJlY3RUb1N0YXRlO1xuXG4gICAgYWN0aXZhdGUoKTtcblxuICAgIGZ1bmN0aW9uIGFjdGl2YXRlKCkge1xuICAgICAgdmFyIG1lbnVQcmVmaXggPSAndmlld3MubGF5b3V0Lm1lbnUuJztcblxuICAgICAgLy8gQXJyYXkgY29udGVuZG8gb3MgaXRlbnMgcXVlIHPDo28gbW9zdHJhZG9zIG5vIG1lbnUgbGF0ZXJhbFxuICAgICAgdm0uaXRlbnNNZW51ID0gW3sgc3RhdGU6ICdhcHAucHJvamVjdHMnLCB0aXRsZTogbWVudVByZWZpeCArICdwcm9qZWN0cycsIGljb246ICd3b3JrJywgc3ViSXRlbnM6IFtdIH0sIHsgc3RhdGU6ICdhcHAuZGFzaGJvYXJkJywgdGl0bGU6IG1lbnVQcmVmaXggKyAnZGFzaGJvYXJkJywgaWNvbjogJ2Rhc2hib2FyZCcsIHN1Ykl0ZW5zOiBbXSB9LCB7IHN0YXRlOiAnYXBwLnRhc2tzJywgdGl0bGU6IG1lbnVQcmVmaXggKyAndGFza3MnLCBpY29uOiAndmlld19saXN0Jywgc3ViSXRlbnM6IFtdIH0sIHsgc3RhdGU6ICdhcHAubWlsZXN0b25lcycsIHRpdGxlOiBtZW51UHJlZml4ICsgJ21pbGVzdG9uZXMnLCBpY29uOiAndmlld19tb2R1bGUnLCBzdWJJdGVuczogW10gfSwgeyBzdGF0ZTogJ2FwcC5yZWxlYXNlcycsIHRpdGxlOiBtZW51UHJlZml4ICsgJ3JlbGVhc2VzJywgaWNvbjogJ3N1YnNjcmlwdGlvbnMnLCBzdWJJdGVuczogW10gfSwgeyBzdGF0ZTogJ2FwcC5rYW5iYW4nLCB0aXRsZTogbWVudVByZWZpeCArICdrYW5iYW4nLCBpY29uOiAndmlld19jb2x1bW4nLCBzdWJJdGVuczogW10gfSwgeyBzdGF0ZTogJ2FwcC52Y3MnLCB0aXRsZTogbWVudVByZWZpeCArICd2Y3MnLCBpY29uOiAnZ3JvdXBfd29yaycsIHN1Ykl0ZW5zOiBbXVxuICAgICAgICAvLyBDb2xvcXVlIHNldXMgaXRlbnMgZGUgbWVudSBhIHBhcnRpciBkZXN0ZSBwb250b1xuICAgICAgICAvKiB7XG4gICAgICAgICAgc3RhdGU6ICcjJywgdGl0bGU6IG1lbnVQcmVmaXggKyAnYWRtaW4nLCBpY29uOiAnc2V0dGluZ3NfYXBwbGljYXRpb25zJywgcHJvZmlsZXM6IFsnYWRtaW4nXSxcbiAgICAgICAgICBzdWJJdGVuczogW1xuICAgICAgICAgICAgeyBzdGF0ZTogJ2FwcC51c2VyJywgdGl0bGU6IG1lbnVQcmVmaXggKyAndXNlcicsIGljb246ICdwZW9wbGUnIH0sXG4gICAgICAgICAgICB7IHN0YXRlOiAnYXBwLm1haWwnLCB0aXRsZTogbWVudVByZWZpeCArICdtYWlsJywgaWNvbjogJ21haWwnIH0sXG4gICAgICAgICAgICB7IHN0YXRlOiAnYXBwLmF1ZGl0JywgdGl0bGU6IG1lbnVQcmVmaXggKyAnYXVkaXQnLCBpY29uOiAnc3RvcmFnZScgfSxcbiAgICAgICAgICAgIHsgc3RhdGU6ICdhcHAuZGluYW1pYy1xdWVyeScsIHRpdGxlOiBtZW51UHJlZml4ICsgJ2RpbmFtaWNRdWVyeScsIGljb246ICdsb2NhdGlvbl9zZWFyY2hpbmcnIH1cbiAgICAgICAgICBdXG4gICAgICAgIH0gKi9cbiAgICAgIH1dO1xuXG4gICAgICAvKipcbiAgICAgICAqIE9iamV0byBxdWUgcHJlZW5jaGUgbyBuZy1zdHlsZSBkbyBtZW51IGxhdGVyYWwgdHJvY2FuZG8gYXMgY29yZXNcbiAgICAgICAqL1xuICAgICAgdm0uc2lkZW5hdlN0eWxlID0ge1xuICAgICAgICB0b3A6IHtcbiAgICAgICAgICAnYm9yZGVyLWJvdHRvbSc6ICcxcHggc29saWQgcmdiKDIxMCwgMjEwLCAyMTApJyxcbiAgICAgICAgICAnYmFja2dyb3VuZC1pbWFnZSc6ICctd2Via2l0LWxpbmVhci1ncmFkaWVudCh0b3AsIHJnYigxNDQsIDE0NCwgMTQ0KSwgcmdiKDIxMCwgMjEwLCAyMTApKSdcbiAgICAgICAgfSxcbiAgICAgICAgY29udGVudDoge1xuICAgICAgICAgICdiYWNrZ3JvdW5kLWNvbG9yJzogJ3JnYigyMTAsIDIxMCwgMjEwKSdcbiAgICAgICAgfSxcbiAgICAgICAgdGV4dENvbG9yOiB7XG4gICAgICAgICAgY29sb3I6ICcjRkZGJ1xuICAgICAgICB9LFxuICAgICAgICBsaW5lQm90dG9tOiB7XG4gICAgICAgICAgJ2JvcmRlci1ib3R0b20nOiAnMXB4IHNvbGlkICcgKyBnZXRDb2xvcigncHJpbWFyeS00MDAnKVxuICAgICAgICB9XG4gICAgICB9O1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIG9wZW4oKSB7XG4gICAgICAkbWRTaWRlbmF2KCdsZWZ0JykudG9nZ2xlKCk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogTcOpdG9kbyBxdWUgZXhpYmUgbyBzdWIgbWVudSBkb3MgaXRlbnMgZG8gbWVudSBsYXRlcmFsIGNhc28gdGVuaGEgc3ViIGl0ZW5zXG4gICAgICogY2FzbyBjb250csOhcmlvIHJlZGlyZWNpb25hIHBhcmEgbyBzdGF0ZSBwYXNzYWRvIGNvbW8gcGFyw4PCom1ldHJvXG4gICAgICovXG4gICAgZnVuY3Rpb24gb3Blbk1lbnVPclJlZGlyZWN0VG9TdGF0ZSgkbWRNZW51LCBldiwgaXRlbSkge1xuICAgICAgaWYgKGFuZ3VsYXIuaXNEZWZpbmVkKGl0ZW0uc3ViSXRlbnMpICYmIGl0ZW0uc3ViSXRlbnMubGVuZ3RoID4gMCkge1xuICAgICAgICAkbWRNZW51Lm9wZW4oZXYpO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgJHN0YXRlLmdvKGl0ZW0uc3RhdGUsIHsgb2JqOiBudWxsIH0pO1xuICAgICAgICAkbWRTaWRlbmF2KCdsZWZ0JykuY2xvc2UoKTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICBmdW5jdGlvbiBnZXRDb2xvcihjb2xvclBhbGV0dGVzKSB7XG4gICAgICByZXR1cm4gJG1kQ29sb3JzLmdldFRoZW1lQ29sb3IoY29sb3JQYWxldHRlcyk7XG4gICAgfVxuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29udHJvbGxlcignTWFpbHNDb250cm9sbGVyJywgTWFpbHNDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIE1haWxzQ29udHJvbGxlcihNYWlsc1NlcnZpY2UsIFVzZXJzU2VydmljZSwgUHJEaWFsb2csIFByVG9hc3QsIC8vIE5PU09OQVJcbiAgJHEsIGxvZGFzaCwgJHRyYW5zbGF0ZSwgR2xvYmFsKSB7XG5cbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0uZmlsdGVyU2VsZWN0ZWQgPSBmYWxzZTtcbiAgICB2bS5vcHRpb25zID0ge1xuICAgICAgc2tpbjogJ2thbWEnLFxuICAgICAgbGFuZ3VhZ2U6ICdwdC1icicsXG4gICAgICBhbGxvd2VkQ29udGVudDogdHJ1ZSxcbiAgICAgIGVudGl0aWVzOiB0cnVlLFxuICAgICAgaGVpZ2h0OiAzMDAsXG4gICAgICBleHRyYVBsdWdpbnM6ICdkaWFsb2csZmluZCxjb2xvcmRpYWxvZyxwcmV2aWV3LGZvcm1zLGlmcmFtZSxmbGFzaCdcbiAgICB9O1xuXG4gICAgdm0ubG9hZFVzZXJzID0gbG9hZFVzZXJzO1xuICAgIHZtLm9wZW5Vc2VyRGlhbG9nID0gb3BlblVzZXJEaWFsb2c7XG4gICAgdm0uYWRkVXNlck1haWwgPSBhZGRVc2VyTWFpbDtcbiAgICB2bS5jbGVhbkZvcm0gPSBjbGVhbkZvcm07XG4gICAgdm0uc2VuZCA9IHNlbmQ7XG5cbiAgICBhY3RpdmF0ZSgpO1xuXG4gICAgZnVuY3Rpb24gYWN0aXZhdGUoKSB7XG4gICAgICB2bS5jbGVhbkZvcm0oKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFsaXphIGEgYnVzY2EgcGVsbyB1c3XDoXJpbyByZW1vdGFtZW50ZVxuICAgICAqXG4gICAgICogQHBhcmFtcyB7c3RyaW5nfSAtIFJlY2ViZSBvIHZhbG9yIHBhcmEgc2VyIHBlc3F1aXNhZG9cbiAgICAgKiBAcmV0dXJuIHtwcm9taXNzZX0gLSBSZXRvcm5hIHVtYSBwcm9taXNzZSBxdWUgbyBjb21wb25ldGUgcmVzb2x2ZVxuICAgICAqL1xuICAgIGZ1bmN0aW9uIGxvYWRVc2Vycyhjcml0ZXJpYSkge1xuICAgICAgdmFyIGRlZmVycmVkID0gJHEuZGVmZXIoKTtcblxuICAgICAgVXNlcnNTZXJ2aWNlLnF1ZXJ5KHtcbiAgICAgICAgbmFtZU9yRW1haWw6IGNyaXRlcmlhLFxuICAgICAgICBub3RVc2VyczogbG9kYXNoLm1hcCh2bS5tYWlsLnVzZXJzLCBsb2Rhc2gucHJvcGVydHkoJ2lkJykpLnRvU3RyaW5nKCksXG4gICAgICAgIGxpbWl0OiA1XG4gICAgICB9KS50aGVuKGZ1bmN0aW9uIChkYXRhKSB7XG5cbiAgICAgICAgLy8gdmVyaWZpY2Egc2UgbmEgbGlzdGEgZGUgdXN1YXJpb3MgasOhIGV4aXN0ZSBvIHVzdcOhcmlvIGNvbSBvIGVtYWlsIHBlc3F1aXNhZG9cbiAgICAgICAgZGF0YSA9IGxvZGFzaC5maWx0ZXIoZGF0YSwgZnVuY3Rpb24gKHVzZXIpIHtcbiAgICAgICAgICByZXR1cm4gIWxvZGFzaC5maW5kKHZtLm1haWwudXNlcnMsIHsgZW1haWw6IHVzZXIuZW1haWwgfSk7XG4gICAgICAgIH0pO1xuXG4gICAgICAgIGRlZmVycmVkLnJlc29sdmUoZGF0YSk7XG4gICAgICB9KTtcblxuICAgICAgcmV0dXJuIGRlZmVycmVkLnByb21pc2U7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQWJyZSBvIGRpYWxvZyBwYXJhIHBlc3F1aXNhIGRlIHVzdcOhcmlvc1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIG9wZW5Vc2VyRGlhbG9nKCkge1xuICAgICAgdmFyIGNvbmZpZyA9IHtcbiAgICAgICAgbG9jYWxzOiB7XG4gICAgICAgICAgb25Jbml0OiB0cnVlLFxuICAgICAgICAgIHVzZXJEaWFsb2dJbnB1dDoge1xuICAgICAgICAgICAgdHJhbnNmZXJVc2VyRm46IHZtLmFkZFVzZXJNYWlsXG4gICAgICAgICAgfVxuICAgICAgICB9LFxuICAgICAgICBjb250cm9sbGVyOiAnVXNlcnNEaWFsb2dDb250cm9sbGVyJyxcbiAgICAgICAgY29udHJvbGxlckFzOiAnY3RybCcsXG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvdXNlcnMvZGlhbG9nL3VzZXJzLWRpYWxvZy5odG1sJyxcbiAgICAgICAgaGFzQmFja2Ryb3A6IHRydWVcbiAgICAgIH07XG5cbiAgICAgIFByRGlhbG9nLmN1c3RvbShjb25maWcpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEFkaWNpb25hIG8gdXN1w6FyaW8gc2VsZWNpb25hZG8gbmEgbGlzdGEgcGFyYSBxdWUgc2VqYSBlbnZpYWRvIG8gZW1haWxcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBhZGRVc2VyTWFpbCh1c2VyKSB7XG4gICAgICB2YXIgdXNlcnMgPSBsb2Rhc2guZmluZCh2bS5tYWlsLnVzZXJzLCB7IGVtYWlsOiB1c2VyLmVtYWlsIH0pO1xuXG4gICAgICBpZiAodm0ubWFpbC51c2Vycy5sZW5ndGggPiAwICYmIGFuZ3VsYXIuaXNEZWZpbmVkKHVzZXJzKSkge1xuICAgICAgICBQclRvYXN0Lndhcm4oJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy51c2VyLnVzZXJFeGlzdHMnKSk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICB2bS5tYWlsLnVzZXJzLnB1c2goeyBuYW1lOiB1c2VyLm5hbWUsIGVtYWlsOiB1c2VyLmVtYWlsIH0pO1xuICAgICAgfVxuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWxpemEgbyBlbnZpbyBkbyBlbWFpbCBwYXJhIGEgbGlzdGEgZGUgdXN1w6FyaW9zIHNlbGVjaW9uYWRvc1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIHNlbmQoKSB7XG5cbiAgICAgIHZtLm1haWwuJHNhdmUoKS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICBpZiAocmVzcG9uc2UubGVuZ3RoID4gMCkge1xuICAgICAgICAgIHZhciBtc2cgPSAkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLm1haWwubWFpbEVycm9ycycpO1xuXG4gICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCByZXNwb25zZS5sZW5ndGg7IGkrKykge1xuICAgICAgICAgICAgbXNnICs9IHJlc3BvbnNlICsgJ1xcbic7XG4gICAgICAgICAgfVxuICAgICAgICAgIFByVG9hc3QuZXJyb3IobXNnKTtcbiAgICAgICAgICB2bS5jbGVhbkZvcm0oKTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICBQclRvYXN0LnN1Y2Nlc3MoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5tYWlsLnNlbmRNYWlsU3VjY2VzcycpKTtcbiAgICAgICAgICB2bS5jbGVhbkZvcm0oKTtcbiAgICAgICAgfVxuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogTGltcGEgbyBmb3JtdWzDoXJpbyBkZSBlbWFpbFxuICAgICAqL1xuICAgIGZ1bmN0aW9uIGNsZWFuRm9ybSgpIHtcbiAgICAgIHZtLm1haWwgPSBuZXcgTWFpbHNTZXJ2aWNlKCk7XG4gICAgICB2bS5tYWlsLnVzZXJzID0gW107XG4gICAgfVxuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKlxuICAgKiBBcnF1aXZvIGRlIGNvbmZpZ3VyYcOnw6NvIGNvbSBhcyByb3RhcyBlc3BlY8OtZmljYXMgZG8gcmVjdXJzbyBlbSBxdWVzdMOjb1xuICAgKlxuICAgKiBAcGFyYW0ge2FueX0gJHN0YXRlUHJvdmlkZXJcbiAgICogQHBhcmFtIHthbnl9IEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdhcHAubWFpbCcsIHtcbiAgICAgIHVybDogJy9lbWFpbCcsXG4gICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL21haWwvbWFpbHMtc2VuZC5odG1sJyxcbiAgICAgIGNvbnRyb2xsZXI6ICdNYWlsc0NvbnRyb2xsZXIgYXMgbWFpbHNDdHJsJyxcbiAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiB0cnVlLCBuZWVkUHJvZmlsZTogWydhZG1pbiddIH1cbiAgICB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5mYWN0b3J5KCdNYWlsc1NlcnZpY2UnLCBNYWlsc1NlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gTWFpbHNTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCdtYWlscycsIHt9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbnRyb2xsZXIoJ01pbGVzdG9uZXNDb250cm9sbGVyJywgTWlsZXN0b25lc0NvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gTWlsZXN0b25lc0NvbnRyb2xsZXIoJGNvbnRyb2xsZXIsIE1pbGVzdG9uZXNTZXJ2aWNlLCBtb21lbnQsIFRhc2tzU2VydmljZSwgUHJUb2FzdCwgJHRyYW5zbGF0ZSwgJG1kRGlhbG9nLCBBdXRoKSB7XG5cbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0uZXN0aW1hdGVkUHJpY2UgPSBlc3RpbWF0ZWRQcmljZTtcblxuICAgIHZtLm9uQWN0aXZhdGUgPSBmdW5jdGlvbiAoKSB7XG4gICAgICB2bS5jdXJyZW50VXNlciA9IEF1dGguY3VycmVudFVzZXI7XG4gICAgICB2bS5wcm9qZWN0ID0gbG9jYWxTdG9yYWdlLmdldEl0ZW0oJ3Byb2plY3QnKTtcbiAgICAgIHZtLnF1ZXJ5RmlsdGVycyA9IHsgcHJvamVjdF9pZDogdm0ucHJvamVjdCB9O1xuICAgIH07XG5cbiAgICBmdW5jdGlvbiBlc3RpbWF0ZWRQcmljZShtaWxlc3RvbmUpIHtcbiAgICAgIG1pbGVzdG9uZS5lc3RpbWF0ZWRfdmFsdWUgPSAwO1xuICAgICAgaWYgKG1pbGVzdG9uZS50YXNrcy5sZW5ndGggPiAwICYmIG1pbGVzdG9uZS5wcm9qZWN0LmhvdXJfdmFsdWVfZmluYWwpIHtcbiAgICAgICAgbWlsZXN0b25lLnRhc2tzLmZvckVhY2goZnVuY3Rpb24gKHRhc2spIHtcbiAgICAgICAgICBtaWxlc3RvbmUuZXN0aW1hdGVkX3ZhbHVlICs9IHBhcnNlRmxvYXQobWlsZXN0b25lLnByb2plY3QuaG91cl92YWx1ZV9maW5hbCkgKiB0YXNrLmVzdGltYXRlZF90aW1lO1xuICAgICAgICB9KTtcbiAgICAgIH1cbiAgICAgIHJldHVybiBtaWxlc3RvbmUuZXN0aW1hdGVkX3ZhbHVlLnRvTG9jYWxlU3RyaW5nKCdQdC1icicsIHsgbWluaW11bUZyYWN0aW9uRGlnaXRzOiAyIH0pO1xuICAgIH1cblxuICAgIHZtLmVzdGltYXRlZFRpbWUgPSBmdW5jdGlvbiAobWlsZXN0b25lKSB7XG4gICAgICBtaWxlc3RvbmUuZXN0aW1hdGVkX3RpbWUgPSAwO1xuICAgICAgaWYgKG1pbGVzdG9uZS50YXNrcy5sZW5ndGggPiAwKSB7XG4gICAgICAgIG1pbGVzdG9uZS50YXNrcy5mb3JFYWNoKGZ1bmN0aW9uICh0YXNrKSB7XG4gICAgICAgICAgbWlsZXN0b25lLmVzdGltYXRlZF90aW1lICs9IHRhc2suZXN0aW1hdGVkX3RpbWU7XG4gICAgICAgIH0pO1xuICAgICAgfVxuICAgICAgbWlsZXN0b25lLmVzdGltYXRlZF90aW1lID0gbWlsZXN0b25lLmVzdGltYXRlZF90aW1lIC8gODtcbiAgICAgIHZhciBkYXRlRW5kID0gbW9tZW50KG1pbGVzdG9uZS5kYXRlX2VuZCk7XG4gICAgICB2YXIgZGF0ZUJlZ2luID0gbW9tZW50KG1pbGVzdG9uZS5kYXRlX2JlZ2luKTtcblxuICAgICAgaWYgKGRhdGVFbmQuZGlmZihkYXRlQmVnaW4sICdkYXlzJykgPD0gbWlsZXN0b25lLmVzdGltYXRlZF90aW1lKSB7XG4gICAgICAgIG1pbGVzdG9uZS5jb2xvcl9lc3RpbWF0ZWRfdGltZSA9IHsgY29sb3I6ICdyZWQnIH07XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBtaWxlc3RvbmUuY29sb3JfZXN0aW1hdGVkX3RpbWUgPSB7IGNvbG9yOiAnZ3JlZW4nIH07XG4gICAgICB9XG4gICAgICByZXR1cm4gbWlsZXN0b25lLmVzdGltYXRlZF90aW1lO1xuICAgIH07XG5cbiAgICB2bS5hcHBseUZpbHRlcnMgPSBmdW5jdGlvbiAoZGVmYXVsdFF1ZXJ5RmlsdGVycykge1xuICAgICAgcmV0dXJuIGFuZ3VsYXIuZXh0ZW5kKGRlZmF1bHRRdWVyeUZpbHRlcnMsIHZtLnF1ZXJ5RmlsdGVycyk7XG4gICAgfTtcblxuICAgIHZtLmJlZm9yZVNhdmUgPSBmdW5jdGlvbiAoKSB7XG4gICAgICB2bS5yZXNvdXJjZS5wcm9qZWN0X2lkID0gdm0ucHJvamVjdDtcbiAgICB9O1xuXG4gICAgdm0uYmVmb3JlUmVtb3ZlID0gZnVuY3Rpb24gKCkge1xuICAgICAgdm0ucmVzb3VyY2UucHJvamVjdF9pZCA9IHZtLnByb2plY3Q7XG4gICAgfTtcblxuICAgIHZtLmZvcm1hdERhdGUgPSBmdW5jdGlvbiAoZGF0ZSkge1xuICAgICAgcmV0dXJuIG1vbWVudChkYXRlKS5mb3JtYXQoJ0REL01NL1lZWVknKTtcbiAgICB9O1xuXG4gICAgdm0uYWZ0ZXJFZGl0ID0gZnVuY3Rpb24gKCkge1xuICAgICAgdm0ucmVzb3VyY2UuZGF0ZV9iZWdpbiA9IG1vbWVudCh2bS5yZXNvdXJjZS5kYXRlX2JlZ2luKTtcbiAgICAgIHZtLnJlc291cmNlLmRhdGVfZW5kID0gbW9tZW50KHZtLnJlc291cmNlLmRhdGVfZW5kKTtcbiAgICB9O1xuXG4gICAgdm0udmlldyA9IGZ1bmN0aW9uIChyZXNvdXJjZSkge1xuICAgICAgcmVzb3VyY2UuZGF0ZV9iZWdpbiA9IG1vbWVudChyZXNvdXJjZS5kYXRlX2JlZ2luKTtcbiAgICAgIHJlc291cmNlLmRhdGVfZW5kID0gbW9tZW50KHJlc291cmNlLmRhdGVfZW5kKTtcbiAgICAgIHZtLnJlc291cmNlID0gcmVzb3VyY2U7XG4gICAgICB2bS5vblZpZXcgPSB0cnVlO1xuICAgICAgdm0udmlld0Zvcm0gPSBmYWxzZTtcbiAgICB9O1xuXG4gICAgdm0uc2VhcmNoVGFzayA9IGZ1bmN0aW9uICh0YXNrVGVybSkge1xuICAgICAgcmV0dXJuIFRhc2tzU2VydmljZS5xdWVyeSh7XG4gICAgICAgIG1pbGVzdG9uZVNlYXJjaDogdHJ1ZSxcbiAgICAgICAgcHJvamVjdF9pZDogdm0ucmVzb3VyY2UucHJvamVjdF9pZCxcbiAgICAgICAgdGl0bGU6IHRhc2tUZXJtXG4gICAgICB9KTtcbiAgICB9O1xuXG4gICAgdm0ub25UYXNrQ2hhbmdlID0gZnVuY3Rpb24gKCkge1xuICAgICAgaWYgKHZtLnRhc2sgIT09IG51bGwgJiYgdm0ucmVzb3VyY2UudGFza3MuZmluZEluZGV4KGZ1bmN0aW9uIChpKSB7XG4gICAgICAgIHJldHVybiBpLmlkID09PSB2bS50YXNrLmlkO1xuICAgICAgfSkgPT09IC0xKSB7XG4gICAgICAgIHZtLnJlc291cmNlLnRhc2tzLnB1c2godm0udGFzayk7XG4gICAgICB9XG4gICAgfTtcblxuICAgIHZtLnJlbW92ZVRhc2sgPSBmdW5jdGlvbiAodGFzaykge1xuICAgICAgdm0ucmVzb3VyY2UudGFza3Muc2xpY2UoMCkuZm9yRWFjaChmdW5jdGlvbiAoZWxlbWVudCkge1xuICAgICAgICBpZiAoZWxlbWVudC5pZCA9PT0gdGFzay5pZCkge1xuICAgICAgICAgIHZtLnJlc291cmNlLnRhc2tzLnNwbGljZSh2bS5yZXNvdXJjZS50YXNrcy5pbmRleE9mKGVsZW1lbnQpLCAxKTtcbiAgICAgICAgfVxuICAgICAgfSk7XG4gICAgfTtcblxuICAgIHZtLnNhdmVUYXNrcyA9IGZ1bmN0aW9uICgpIHtcbiAgICAgIFRhc2tzU2VydmljZS51cGRhdGVNaWxlc3RvbmUoeyBwcm9qZWN0X2lkOiB2bS5yZXNvdXJjZS5wcm9qZWN0X2lkLCBtaWxlc3RvbmVfaWQ6IHZtLnJlc291cmNlLmlkLCB0YXNrczogdm0ucmVzb3VyY2UudGFza3MgfSkudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgIFByVG9hc3Quc3VjY2VzcygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnNhdmVTdWNjZXNzJykpO1xuICAgICAgICB2bS52aWV3Rm9ybSA9IGZhbHNlO1xuICAgICAgICB2bS5vblZpZXcgPSBmYWxzZTtcbiAgICAgIH0sIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgUHJUb2FzdC5lcnJvcigkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLm9wZXJhdGlvbkVycm9yJykpO1xuICAgICAgfSk7XG4gICAgfTtcblxuICAgIHZtLmZpbmFsaXplID0gZnVuY3Rpb24gKG1pbGVzdG9uZSkge1xuICAgICAgdmFyIGNvbmZpcm0gPSAkbWREaWFsb2cuY29uZmlybSgpLnRpdGxlKCdGaW5hbGl6YXIgU3ByaW50JykudGV4dENvbnRlbnQoJ1RlbSBjZXJ0ZXphIHF1ZSBkZXNlamEgZmluYWxpemFyIGEgc3ByaW50ICcgKyBtaWxlc3RvbmUudGl0bGUgKyAnPycpLm9rKCdTaW0nKS5jYW5jZWwoJ07Do28nKTtcblxuICAgICAgJG1kRGlhbG9nLnNob3coY29uZmlybSkudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgIE1pbGVzdG9uZXNTZXJ2aWNlLmZpbmFsaXplKHsgcHJvamVjdF9pZDogdm0ucHJvamVjdCwgbWlsZXN0b25lX2lkOiBtaWxlc3RvbmUuaWQgfSkudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgUHJUb2FzdC5zdWNjZXNzKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMuc3ByaW50RW5kZWRTdWNjZXNzJykpO1xuICAgICAgICAgIHZtLnNlYXJjaCgpO1xuICAgICAgICB9LCBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgUHJUb2FzdC5FcnJvcigkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnNwcmludEVuZGVkRXJyb3InKSk7XG4gICAgICAgIH0pO1xuICAgICAgfSk7XG4gICAgfTtcblxuICAgIC8vIGluc3RhbnRpYXRlIGJhc2UgY29udHJvbGxlclxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHsgdm06IHZtLCBtb2RlbFNlcnZpY2U6IE1pbGVzdG9uZXNTZXJ2aWNlLCBvcHRpb25zOiB7fSB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25maWcocm91dGVzKTtcblxuICAvKipcbiAgICogQXJxdWl2byBkZSBjb25maWd1cmHDp8OjbyBjb20gYXMgcm90YXMgZXNwZWPDrWZpY2FzIGRvIHJlY3Vyc28gbWlsZXN0b25lc1xuICAgKlxuICAgKiBAcGFyYW0ge29iamVjdH0gJHN0YXRlUHJvdmlkZXJcbiAgICogQHBhcmFtIHtvYmplY3R9IEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdhcHAubWlsZXN0b25lcycsIHtcbiAgICAgIHVybDogJy9taWxlc3RvbmVzJyxcbiAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvbWlsZXN0b25lcy9taWxlc3RvbmVzLmh0bWwnLFxuICAgICAgY29udHJvbGxlcjogJ01pbGVzdG9uZXNDb250cm9sbGVyIGFzIG1pbGVzdG9uZXNDdHJsJyxcbiAgICAgIGRhdGE6IHt9XG4gICAgfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmFjdG9yeSgnTWlsZXN0b25lc1NlcnZpY2UnLCBNaWxlc3RvbmVzU2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiBNaWxlc3RvbmVzU2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHZhciBtb2RlbCA9IHNlcnZpY2VGYWN0b3J5KCdtaWxlc3RvbmVzJywge1xuICAgICAgYWN0aW9uczoge1xuICAgICAgICBmaW5hbGl6ZToge1xuICAgICAgICAgIG1ldGhvZDogJ1BPU1QnLFxuICAgICAgICAgIHVybDogJ2ZpbmFsaXplJ1xuICAgICAgICB9LFxuICAgICAgICB1cGRhdGVSZWxlYXNlOiB7XG4gICAgICAgICAgbWV0aG9kOiAnUE9TVCcsXG4gICAgICAgICAgdXJsOiAndXBkYXRlUmVsZWFzZSdcbiAgICAgICAgfVxuICAgICAgfSxcbiAgICAgIGluc3RhbmNlOiB7fVxuICAgIH0pO1xuXG4gICAgcmV0dXJuIG1vZGVsO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZhY3RvcnkoJ1ByaW9yaXRpZXNTZXJ2aWNlJywgUHJpb3JpdGllc1NlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gUHJpb3JpdGllc1NlcnZpY2Uoc2VydmljZUZhY3RvcnkpIHtcbiAgICB2YXIgbW9kZWwgPSBzZXJ2aWNlRmFjdG9yeSgncHJpb3JpdGllcycsIHtcbiAgICAgIGFjdGlvbnM6IHt9LFxuICAgICAgaW5zdGFuY2U6IHt9XG4gICAgfSk7XG5cbiAgICByZXR1cm4gbW9kZWw7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb250cm9sbGVyKCdQcm9qZWN0c0NvbnRyb2xsZXInLCBQcm9qZWN0c0NvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gUHJvamVjdHNDb250cm9sbGVyKCRjb250cm9sbGVyLCBQcm9qZWN0c1NlcnZpY2UsIEF1dGgsIFJvbGVzU2VydmljZSwgVXNlcnNTZXJ2aWNlLCAkc3RhdGUsICRmaWx0ZXIsICRzdGF0ZVBhcmFtcywgJHdpbmRvdykge1xuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICAvL0F0dHJpYnV0ZXMgQmxvY2tcblxuICAgIC8vRnVuY3Rpb25zIEJsb2NrXG4gICAgdm0ub25BY3RpdmF0ZSA9IG9uQWN0aXZhdGU7XG4gICAgdm0uYXBwbHlGaWx0ZXJzID0gYXBwbHlGaWx0ZXJzO1xuICAgIHZtLmJlZm9yZVNhdmUgPSBiZWZvcmVTYXZlO1xuICAgIHZtLnNlYXJjaFVzZXIgPSBzZWFyY2hVc2VyO1xuICAgIHZtLmFkZFVzZXIgPSBhZGRVc2VyO1xuICAgIHZtLnJlbW92ZVVzZXIgPSByZW1vdmVVc2VyO1xuICAgIHZtLnZpZXdQcm9qZWN0ID0gdmlld1Byb2plY3Q7XG5cbiAgICB2bS5yb2xlcyA9IHt9O1xuICAgIHZtLnVzZXJzID0gW107XG5cbiAgICBmdW5jdGlvbiBvbkFjdGl2YXRlKCkge1xuICAgICAgdm0uY3VycmVudFVzZXIgPSBBdXRoLmN1cnJlbnRVc2VyO1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0geyB1c2VyX2lkOiB2bS5jdXJyZW50VXNlci5pZCB9O1xuICAgICAgUm9sZXNTZXJ2aWNlLnF1ZXJ5KCkudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgdm0ucm9sZXMgPSByZXNwb25zZTtcbiAgICAgICAgaWYgKCRzdGF0ZVBhcmFtcy5vYmogPT09ICdlZGl0Jykge1xuICAgICAgICAgIHZtLmNsZWFuRm9ybSgpO1xuICAgICAgICAgIHZtLnZpZXdGb3JtID0gdHJ1ZTtcbiAgICAgICAgICB2bS5yZXNvdXJjZSA9ICRzdGF0ZVBhcmFtcy5yZXNvdXJjZTtcbiAgICAgICAgICB1c2Vyc0FycmF5KHZtLnJlc291cmNlKTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbSgncHJvamVjdCcpO1xuICAgICAgICB9XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBhcHBseUZpbHRlcnMoZGVmYXVsdFF1ZXJ5RmlsdGVycykge1xuICAgICAgcmV0dXJuIGFuZ3VsYXIuZXh0ZW5kKGRlZmF1bHRRdWVyeUZpbHRlcnMsIHZtLnF1ZXJ5bHRlcnMpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGJlZm9yZVNhdmUoKSB7XG4gICAgICBpZiAoIXZtLnJlc291cmNlLm93bmVyKSB7XG4gICAgICAgIHZtLnJlc291cmNlLm93bmVyID0gQXV0aC5jdXJyZW50VXNlci5pZDtcbiAgICAgIH1cbiAgICAgIHZtLnJlc291cmNlLnVzZXJfaWQgPSBBdXRoLmN1cnJlbnRVc2VyLmlkO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIHNlYXJjaFVzZXIoKSB7XG4gICAgICByZXR1cm4gVXNlcnNTZXJ2aWNlLnF1ZXJ5KHsgbmFtZTogdm0udXNlck5hbWUgfSk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gYWRkVXNlcih1c2VyKSB7XG4gICAgICBpZiAodXNlcikge1xuICAgICAgICB2bS5yZXNvdXJjZS51c2Vycy5wdXNoKHVzZXIpO1xuICAgICAgICB2bS51c2VyTmFtZSA9ICcnO1xuICAgICAgfVxuICAgIH1cblxuICAgIGZ1bmN0aW9uIHJlbW92ZVVzZXIoaW5kZXgpIHtcbiAgICAgIHZtLnJlc291cmNlLnVzZXJzLnNwbGljZShpbmRleCwgMSk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gYXBwbHlGaWx0ZXJzKGRlZmF1bHRRdWVyeUZpbHRlcnMpIHtcbiAgICAgIHJldHVybiBhbmd1bGFyLmV4dGVuZChkZWZhdWx0UXVlcnlGaWx0ZXJzLCB2bS5xdWVyeUZpbHRlcnMpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIHZpZXdQcm9qZWN0KCkge1xuICAgICAgJHN0YXRlLmdvKCdhcHAuZGFzaGJvYXJkJyk7XG4gICAgfVxuXG4gICAgdm0uYWZ0ZXJTZWFyY2ggPSBmdW5jdGlvbiAoKSB7XG4gICAgICBpZiAodm0ucmVzb3VyY2VzLmxlbmd0aCA+IDApIHtcbiAgICAgICAgdm0ucmVzb3VyY2VzLmZvckVhY2goZnVuY3Rpb24gKHByb2plY3QpIHtcbiAgICAgICAgICB1c2Vyc0FycmF5KHByb2plY3QpO1xuICAgICAgICB9KTtcbiAgICAgIH1cbiAgICB9O1xuXG4gICAgZnVuY3Rpb24gdXNlcnNBcnJheShwcm9qZWN0KSB7XG4gICAgICBwcm9qZWN0LnVzZXJzID0gW107XG4gICAgICBpZiAocHJvamVjdC5jbGllbnRfaWQpIHtcbiAgICAgICAgcHJvamVjdC5jbGllbnQucm9sZSA9ICRmaWx0ZXIoJ2ZpbHRlcicpKHZtLnJvbGVzLCB7IHNsdWc6ICdjbGllbnQnIH0pWzBdO1xuICAgICAgICBwcm9qZWN0LnVzZXJzLnB1c2gocHJvamVjdC5jbGllbnQpO1xuICAgICAgfVxuICAgICAgaWYgKHByb2plY3QuZGV2X2lkKSB7XG4gICAgICAgIHByb2plY3QuZGV2ZWxvcGVyLnJvbGUgPSAkZmlsdGVyKCdmaWx0ZXInKSh2bS5yb2xlcywgeyBzbHVnOiAnZGV2JyB9KVswXTtcbiAgICAgICAgcHJvamVjdC51c2Vycy5wdXNoKHByb2plY3QuZGV2ZWxvcGVyKTtcbiAgICAgIH1cbiAgICAgIGlmIChwcm9qZWN0LnN0YWtlaG9sZGVyX2lkKSB7XG4gICAgICAgIHByb2plY3Quc3Rha2Vob2xkZXIucm9sZSA9ICRmaWx0ZXIoJ2ZpbHRlcicpKHZtLnJvbGVzLCB7IHNsdWc6ICdzdGFrZWhvbGRlcicgfSlbMF07XG4gICAgICAgIHByb2plY3QudXNlcnMucHVzaChwcm9qZWN0LnN0YWtlaG9sZGVyKTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICB2bS5oaXN0b3J5QmFjayA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICR3aW5kb3cuaGlzdG9yeS5iYWNrKCk7XG4gICAgfTtcblxuICAgIHZtLmFmdGVyU2F2ZSA9IGZ1bmN0aW9uIChyZXNvdXJjZSkge1xuICAgICAgbG9jYWxTdG9yYWdlLnNldEl0ZW0oJ3Byb2plY3QnLCByZXNvdXJjZS5pZCk7XG4gICAgICAkc3RhdGUuZ28oJ2FwcC5kYXNoYm9hcmQnKTtcbiAgICB9O1xuXG4gICAgLy8gaW5zdGFudGlhdGUgYmFzZSBjb250cm9sbGVyXG4gICAgJGNvbnRyb2xsZXIoJ0NSVURDb250cm9sbGVyJywgeyB2bTogdm0sIG1vZGVsU2VydmljZTogUHJvamVjdHNTZXJ2aWNlLCBvcHRpb25zOiB7IHJlZGlyZWN0QWZ0ZXJTYXZlOiBmYWxzZSB9IH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKlxuICAgKiBBcnF1aXZvIGRlIGNvbmZpZ3VyYcOnw6NvIGNvbSBhcyByb3RhcyBlc3BlY8OtZmljYXMgZG8gcmVjdXJzbyBwcm9qZWN0XG4gICAqXG4gICAqIEBwYXJhbSB7YW55fSAkc3RhdGVQcm92aWRlclxuICAgKiBAcGFyYW0ge2FueX0gR2xvYmFsXG4gICAqL1xuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvdXRlcygkc3RhdGVQcm92aWRlciwgR2xvYmFsKSB7XG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ2FwcC5wcm9qZWN0cycsIHtcbiAgICAgIHVybDogJy9wcm9qZWN0cycsXG4gICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL3Byb2plY3RzL3Byb2plY3RzLmh0bWwnLFxuICAgICAgY29udHJvbGxlcjogJ1Byb2plY3RzQ29udHJvbGxlciBhcyBwcm9qZWN0c0N0cmwnLFxuICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IHRydWUgfSxcbiAgICAgIHBhcmFtczogeyBvYmo6IG51bGwsIHJlc291cmNlOiBudWxsIH1cbiAgICB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5mYWN0b3J5KCdQcm9qZWN0c1NlcnZpY2UnLCBQcm9qZWN0c1NlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gUHJvamVjdHNTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCdwcm9qZWN0cycsIHtcbiAgICAgIGFjdGlvbnM6IHtcbiAgICAgICAgZmluYWxpemU6IHtcbiAgICAgICAgICBtZXRob2Q6ICdQT1NUJyxcbiAgICAgICAgICB1cmw6ICdmaW5hbGl6ZSdcbiAgICAgICAgfSxcbiAgICAgICAgdmVyaWZ5UmVsZWFzZXM6IHtcbiAgICAgICAgICBtZXRob2Q6ICdQT1NUJyxcbiAgICAgICAgICB1cmw6ICd2ZXJpZnlSZWxlYXNlcydcbiAgICAgICAgfVxuICAgICAgfSxcbiAgICAgIGluc3RhbmNlOiB7fVxuICAgIH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29udHJvbGxlcignUmVsZWFzZXNDb250cm9sbGVyJywgUmVsZWFzZXNDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIFJlbGVhc2VzQ29udHJvbGxlcigkY29udHJvbGxlciwgUmVsZWFzZXNTZXJ2aWNlLCBNaWxlc3RvbmVzU2VydmljZSwgQXV0aCwgUHJUb2FzdCwgbW9tZW50LCAkbWREaWFsb2csICR0cmFuc2xhdGUpIHtcbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgLy9BdHRyaWJ1dGVzIEJsb2NrXG5cbiAgICAvL0Z1bmN0aW9ucyBCbG9ja1xuICAgIHZtLm9uQWN0aXZhdGUgPSBmdW5jdGlvbiAoKSB7XG4gICAgICB2bS5jdXJyZW50VXNlciA9IEF1dGguY3VycmVudFVzZXI7XG4gICAgICB2bS5wcm9qZWN0ID0gbG9jYWxTdG9yYWdlLmdldEl0ZW0oJ3Byb2plY3QnKTtcbiAgICAgIHZtLnF1ZXJ5RmlsdGVycyA9IHsgcHJvamVjdF9pZDogdm0ucHJvamVjdCB9O1xuICAgIH07XG5cbiAgICB2bS5iZWZvcmVTYXZlID0gZnVuY3Rpb24gKCkge1xuICAgICAgdm0ucmVzb3VyY2UucHJvamVjdF9pZCA9IHZtLnByb2plY3Q7XG4gICAgfTtcblxuICAgIHZtLmJlZm9yZVJlbW92ZSA9IGZ1bmN0aW9uICgpIHtcbiAgICAgIHZtLnJlc291cmNlLnByb2plY3RfaWQgPSB2bS5wcm9qZWN0O1xuICAgIH07XG5cbiAgICB2bS52aWV3ID0gZnVuY3Rpb24gKHJlc291cmNlKSB7XG4gICAgICB2bS5yZXNvdXJjZSA9IHJlc291cmNlO1xuICAgICAgdm0ub25WaWV3ID0gdHJ1ZTtcbiAgICAgIHZtLnZpZXdGb3JtID0gZmFsc2U7XG4gICAgfTtcblxuICAgIHZtLmZpbmFsaXplID0gZnVuY3Rpb24gKHJlbGVhc2UpIHtcbiAgICAgIHZhciBjb25maXJtID0gJG1kRGlhbG9nLmNvbmZpcm0oKS50aXRsZSgnRmluYWxpemFyIFJlbGVhc2UnKS50ZXh0Q29udGVudCgnVGVtIGNlcnRlemEgcXVlIGRlc2VqYSBmaW5hbGl6YXIgYSByZWxlYXNlICcgKyByZWxlYXNlLnRpdGxlICsgJz8nKS5vaygnU2ltJykuY2FuY2VsKCdOw6NvJyk7XG5cbiAgICAgICRtZERpYWxvZy5zaG93KGNvbmZpcm0pLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICBSZWxlYXNlc1NlcnZpY2UuZmluYWxpemUoeyBwcm9qZWN0X2lkOiB2bS5wcm9qZWN0LCByZWxlYXNlX2lkOiByZWxlYXNlLmlkIH0pLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICAgIFByVG9hc3Quc3VjY2VzcygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnJlbGVhc2VFbmRlZFN1Y2Nlc3MnKSk7XG4gICAgICAgICAgdm0uc2VhcmNoKCk7XG4gICAgICAgIH0sIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICBQclRvYXN0LkVycm9yKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMucmVsZWFzZUVuZGVkRXJyb3InKSk7XG4gICAgICAgIH0pO1xuICAgICAgfSk7XG4gICAgfTtcblxuICAgIHZtLmZvcm1hdERhdGUgPSBmdW5jdGlvbiAoZGF0ZSkge1xuICAgICAgcmV0dXJuIG1vbWVudChkYXRlKS5mb3JtYXQoJ0REL01NL1lZWVknKTtcbiAgICB9O1xuXG4gICAgdm0uc2VhcmNoTWlsZXN0b25lID0gZnVuY3Rpb24gKG1pbGVzdG9uZVRlcm0pIHtcbiAgICAgIHJldHVybiBNaWxlc3RvbmVzU2VydmljZS5xdWVyeSh7XG4gICAgICAgIHJlbGVhc2VTZWFyY2g6IHRydWUsXG4gICAgICAgIHByb2plY3RfaWQ6IHZtLnJlc291cmNlLnByb2plY3RfaWQsXG4gICAgICAgIHRpdGxlOiBtaWxlc3RvbmVUZXJtXG4gICAgICB9KTtcbiAgICB9O1xuXG4gICAgdm0ub25NaWxlc3RvbmVDaGFuZ2UgPSBmdW5jdGlvbiAoKSB7XG4gICAgICBpZiAodm0ubWlsZXN0b25lICE9PSBudWxsICYmIHZtLnJlc291cmNlLm1pbGVzdG9uZXMuZmluZEluZGV4KGZ1bmN0aW9uIChpKSB7XG4gICAgICAgIHJldHVybiBpLmlkID09PSB2bS5taWxlc3RvbmUuaWQ7XG4gICAgICB9KSA9PT0gLTEpIHtcbiAgICAgICAgdm0ucmVzb3VyY2UubWlsZXN0b25lcy5wdXNoKHZtLm1pbGVzdG9uZSk7XG4gICAgICB9XG4gICAgfTtcblxuICAgIHZtLnJlbW92ZU1pbGVzdG9uZSA9IGZ1bmN0aW9uIChtaWxlc3RvbmUpIHtcbiAgICAgIHZtLnJlc291cmNlLm1pbGVzdG9uZXMuc2xpY2UoMCkuZm9yRWFjaChmdW5jdGlvbiAoZWxlbWVudCkge1xuICAgICAgICBpZiAoZWxlbWVudC5pZCA9PT0gbWlsZXN0b25lLmlkKSB7XG4gICAgICAgICAgdm0ucmVzb3VyY2UubWlsZXN0b25lcy5zcGxpY2Uodm0ucmVzb3VyY2UubWlsZXN0b25lcy5pbmRleE9mKGVsZW1lbnQpLCAxKTtcbiAgICAgICAgfVxuICAgICAgfSk7XG4gICAgfTtcblxuICAgIHZtLnNhdmVNaWxlc3RvbmVzID0gZnVuY3Rpb24gKCkge1xuICAgICAgTWlsZXN0b25lc1NlcnZpY2UudXBkYXRlUmVsZWFzZSh7IHByb2plY3RfaWQ6IHZtLnJlc291cmNlLnByb2plY3RfaWQsIHJlbGVhc2VfaWQ6IHZtLnJlc291cmNlLmlkLCBtaWxlc3RvbmVzOiB2bS5yZXNvdXJjZS5taWxlc3RvbmVzIH0pLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICBQclRvYXN0LnN1Y2Nlc3MoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5zYXZlU3VjY2VzcycpKTtcbiAgICAgICAgdm0udmlld0Zvcm0gPSBmYWxzZTtcbiAgICAgICAgdm0ub25WaWV3ID0gZmFsc2U7XG4gICAgICB9LCBmdW5jdGlvbiAoKSB7XG4gICAgICAgIFByVG9hc3QuZXJyb3IoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5vcGVyYXRpb25FcnJvcicpKTtcbiAgICAgIH0pO1xuICAgIH07XG5cbiAgICB2bS5lc3RpbWF0ZWRUaW1lID0gZnVuY3Rpb24gKG1pbGVzdG9uZSkge1xuICAgICAgbWlsZXN0b25lLmVzdGltYXRlZF90aW1lID0gMDtcbiAgICAgIGlmIChtaWxlc3RvbmUudGFza3MubGVuZ3RoID4gMCkge1xuICAgICAgICBtaWxlc3RvbmUudGFza3MuZm9yRWFjaChmdW5jdGlvbiAodGFzaykge1xuICAgICAgICAgIG1pbGVzdG9uZS5lc3RpbWF0ZWRfdGltZSArPSB0YXNrLmVzdGltYXRlZF90aW1lO1xuICAgICAgICB9KTtcbiAgICAgIH1cbiAgICAgIHJldHVybiBtaWxlc3RvbmUuZXN0aW1hdGVkX3RpbWUgLyA4O1xuICAgIH07XG5cbiAgICAvLyBpbnN0YW50aWF0ZSBiYXNlIGNvbnRyb2xsZXJcbiAgICAkY29udHJvbGxlcignQ1JVRENvbnRyb2xsZXInLCB7IHZtOiB2bSwgbW9kZWxTZXJ2aWNlOiBSZWxlYXNlc1NlcnZpY2UsIG9wdGlvbnM6IHt9IH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKlxuICAgKiBBcnF1aXZvIGRlIGNvbmZpZ3VyYcOnw6NvIGNvbSBhcyByb3RhcyBlc3BlY8OtZmljYXMgZG8gcmVjdXJzbyByZWxlYXNlc1xuICAgKlxuICAgKiBAcGFyYW0ge29iamVjdH0gJHN0YXRlUHJvdmlkZXJcbiAgICogQHBhcmFtIHtvYmplY3R9IEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdhcHAucmVsZWFzZXMnLCB7XG4gICAgICB1cmw6ICcvcmVsZWFzZXMnLFxuICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9yZWxlYXNlcy9yZWxlYXNlcy5odG1sJyxcbiAgICAgIGNvbnRyb2xsZXI6ICdSZWxlYXNlc0NvbnRyb2xsZXIgYXMgcmVsZWFzZXNDdHJsJyxcbiAgICAgIGRhdGE6IHt9XG4gICAgfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmFjdG9yeSgnUmVsZWFzZXNTZXJ2aWNlJywgUmVsZWFzZXNTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIFJlbGVhc2VzU2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHZhciBtb2RlbCA9IHNlcnZpY2VGYWN0b3J5KCdyZWxlYXNlcycsIHtcbiAgICAgIGFjdGlvbnM6IHtcbiAgICAgICAgZmluYWxpemU6IHtcbiAgICAgICAgICBtZXRob2Q6ICdQT1NUJyxcbiAgICAgICAgICB1cmw6ICdmaW5hbGl6ZSdcbiAgICAgICAgfVxuICAgICAgfSxcbiAgICAgIGluc3RhbmNlOiB7fVxuICAgIH0pO1xuXG4gICAgcmV0dXJuIG1vZGVsO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmlsdGVyKCdyb2xlc1N0cicsIHJvbGVzU3RyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvbGVzU3RyKGxvZGFzaCkge1xuICAgIC8qKlxuICAgICAqIEBwYXJhbSB7YXJyYXl9IHJvbGVzIGxpc3RhIGRlIHBlcmZpc1xuICAgICAqIEByZXR1cm4ge3N0cmluZ30gcGVyZmlzIHNlcGFyYWRvcyBwb3IgJywgJyAgXG4gICAgICovXG4gICAgcmV0dXJuIGZ1bmN0aW9uIChyb2xlcykge1xuICAgICAgcmV0dXJuIGxvZGFzaC5tYXAocm9sZXMsICdzbHVnJykuam9pbignLCAnKTtcbiAgICB9O1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZhY3RvcnkoJ1JvbGVzU2VydmljZScsIFJvbGVzU2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiBSb2xlc1NlcnZpY2Uoc2VydmljZUZhY3RvcnkpIHtcbiAgICByZXR1cm4gc2VydmljZUZhY3RvcnkoJ3JvbGVzJyk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmFjdG9yeSgnU3RhdHVzU2VydmljZScsIFN0YXR1c1NlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gU3RhdHVzU2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHZhciBtb2RlbCA9IHNlcnZpY2VGYWN0b3J5KCdzdGF0dXMnLCB7XG4gICAgICBhY3Rpb25zOiB7fSxcbiAgICAgIGluc3RhbmNlOiB7fVxuICAgIH0pO1xuXG4gICAgcmV0dXJuIG1vZGVsO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZhY3RvcnkoJ1N1cHBvcnRTZXJ2aWNlJywgU3VwcG9ydFNlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gU3VwcG9ydFNlcnZpY2Uoc2VydmljZUZhY3RvcnkpIHtcbiAgICByZXR1cm4gc2VydmljZUZhY3RvcnkoJ3N1cHBvcnQnLCB7XG4gICAgICBhY3Rpb25zOiB7XG4gICAgICAgIC8qKlxuICAgICAgICAgKiBQZWdhIGFzIHRyYWR1w6fDtWVzIHF1ZSBlc3TDo28gbm8gc2Vydmlkb3JcbiAgICAgICAgICpcbiAgICAgICAgICogQHJldHVybnMge3Byb21pc2V9IFVtYSBwcm9taXNlIGNvbSBvIHJlc3VsdGFkbyBkbyBjaGFtYWRhIG5vIGJhY2tlbmRcbiAgICAgICAgICovXG4gICAgICAgIGxhbmdzOiB7XG4gICAgICAgICAgbWV0aG9kOiAnR0VUJyxcbiAgICAgICAgICB1cmw6ICdsYW5ncycsXG4gICAgICAgICAgd3JhcDogZmFsc2UsXG4gICAgICAgICAgY2FjaGU6IHRydWVcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZhY3RvcnkoJ1Rhc2tDb21tZW50c1NlcnZpY2UnLCBUYXNrQ29tbWVudHNTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIFRhc2tDb21tZW50c1NlcnZpY2Uoc2VydmljZUZhY3RvcnkpIHtcbiAgICB2YXIgbW9kZWwgPSBzZXJ2aWNlRmFjdG9yeSgndGFzay1jb21tZW50cycsIHtcbiAgICAgIGFjdGlvbnM6IHtcbiAgICAgICAgc2F2ZVRhc2tDb21tZW50OiB7XG4gICAgICAgICAgbWV0aG9kOiAnUE9TVCcsXG4gICAgICAgICAgdXJsOiAnc2F2ZVRhc2tDb21tZW50J1xuICAgICAgICB9LFxuICAgICAgICByZW1vdmVUYXNrQ29tbWVudDoge1xuICAgICAgICAgIG1ldGhvZDogJ1BPU1QnLFxuICAgICAgICAgIHVybDogJ3JlbW92ZVRhc2tDb21tZW50J1xuICAgICAgICB9XG4gICAgICB9LFxuICAgICAgaW5zdGFuY2U6IHt9XG4gICAgfSk7XG5cbiAgICByZXR1cm4gbW9kZWw7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5maWx0ZXIoJ2VsYXBzZWQnLCBmdW5jdGlvbiAoKSB7XG4gICAgcmV0dXJuIGZ1bmN0aW9uIChkYXRlKSB7XG4gICAgICBpZiAoIWRhdGUpIHJldHVybjtcbiAgICAgIHZhciB0aW1lID0gRGF0ZS5wYXJzZShkYXRlKSxcbiAgICAgICAgICB0aW1lTm93ID0gbmV3IERhdGUoKS5nZXRUaW1lKCksXG4gICAgICAgICAgZGlmZmVyZW5jZSA9IHRpbWVOb3cgLSB0aW1lLFxuICAgICAgICAgIHNlY29uZHMgPSBNYXRoLmZsb29yKGRpZmZlcmVuY2UgLyAxMDAwKSxcbiAgICAgICAgICBtaW51dGVzID0gTWF0aC5mbG9vcihzZWNvbmRzIC8gNjApLFxuICAgICAgICAgIGhvdXJzID0gTWF0aC5mbG9vcihtaW51dGVzIC8gNjApLFxuICAgICAgICAgIGRheXMgPSBNYXRoLmZsb29yKGhvdXJzIC8gMjQpLFxuICAgICAgICAgIG1vbnRocyA9IE1hdGguZmxvb3IoZGF5cyAvIDMwKTtcblxuICAgICAgaWYgKG1vbnRocyA+IDEpIHtcbiAgICAgICAgcmV0dXJuIG1vbnRocyArICcgbWVzZXMgYXRyw6FzJztcbiAgICAgIH0gZWxzZSBpZiAobW9udGhzID09PSAxKSB7XG4gICAgICAgIHJldHVybiAnMSBtw6pzIGF0csOhcyc7XG4gICAgICB9IGVsc2UgaWYgKGRheXMgPiAxKSB7XG4gICAgICAgIHJldHVybiBkYXlzICsgJyBkaWFzIGF0csOhcyc7XG4gICAgICB9IGVsc2UgaWYgKGRheXMgPT09IDEpIHtcbiAgICAgICAgcmV0dXJuICcxIGRpYSBhdHLDoXMnO1xuICAgICAgfSBlbHNlIGlmIChob3VycyA+IDEpIHtcbiAgICAgICAgcmV0dXJuIGhvdXJzICsgJyBob3JhcyBhdHLDoXMnO1xuICAgICAgfSBlbHNlIGlmIChob3VycyA9PT0gMSkge1xuICAgICAgICByZXR1cm4gJ3VtYSBob3JhIGF0csOhcyc7XG4gICAgICB9IGVsc2UgaWYgKG1pbnV0ZXMgPiAxKSB7XG4gICAgICAgIHJldHVybiBtaW51dGVzICsgJyBtaW51dG9zIGF0csOhcyc7XG4gICAgICB9IGVsc2UgaWYgKG1pbnV0ZXMgPT09IDEpIHtcbiAgICAgICAgcmV0dXJuICd1bSBtaW51dG8gYXRyw6FzJztcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHJldHVybiAnaMOhIHBvdWNvcyBzZWd1bmRvcyc7XG4gICAgICB9XG4gICAgfTtcbiAgfSkuY29udHJvbGxlcignVGFza3NDb250cm9sbGVyJywgVGFza3NDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIFRhc2tzQ29udHJvbGxlcigkY29udHJvbGxlciwgVGFza3NTZXJ2aWNlLCBTdGF0dXNTZXJ2aWNlLCBQcmlvcml0aWVzU2VydmljZSwgVHlwZXNTZXJ2aWNlLCBUYXNrQ29tbWVudHNTZXJ2aWNlLCBtb21lbnQsIEF1dGgsIFByVG9hc3QsICR0cmFuc2xhdGUsICRmaWx0ZXIsIEdsb2JhbCkge1xuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICAvL0F0dHJpYnV0ZXMgQmxvY2tcblxuICAgIC8vRnVuY3Rpb25zIEJsb2NrXG4gICAgdm0ub25BY3RpdmF0ZSA9IG9uQWN0aXZhdGU7XG4gICAgdm0uYXBwbHlGaWx0ZXJzID0gYXBwbHlGaWx0ZXJzO1xuICAgIHZtLmJlZm9yZVNhdmUgPSBiZWZvcmVTYXZlO1xuICAgIHZtLmJlZm9yZVJlbW92ZSA9IGJlZm9yZVJlbW92ZTtcblxuICAgIGZ1bmN0aW9uIG9uQWN0aXZhdGUoKSB7XG4gICAgICB2bS5jdXJyZW50VXNlciA9IEF1dGguY3VycmVudFVzZXI7XG4gICAgICB2bS5pbWFnZVBhdGggPSBHbG9iYWwuaW1hZ2VQYXRoICsgJy9ub19hdmF0YXIuZ2lmJztcbiAgICAgIHZtLnByb2plY3QgPSBsb2NhbFN0b3JhZ2UuZ2V0SXRlbSgncHJvamVjdCcpO1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0geyBwcm9qZWN0X2lkOiB2bS5wcm9qZWN0IH07XG5cbiAgICAgIFN0YXR1c1NlcnZpY2UucXVlcnkoKS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICB2bS5zdGF0dXMgPSByZXNwb25zZTtcbiAgICAgIH0pO1xuXG4gICAgICBQcmlvcml0aWVzU2VydmljZS5xdWVyeSgpLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgIHZtLnByaW9yaXRpZXMgPSByZXNwb25zZTtcbiAgICAgIH0pO1xuXG4gICAgICBUeXBlc1NlcnZpY2UucXVlcnkoKS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICB2bS50eXBlcyA9IHJlc3BvbnNlO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gYXBwbHlGaWx0ZXJzKGRlZmF1bHRRdWVyeUZpbHRlcnMpIHtcbiAgICAgIHJldHVybiBhbmd1bGFyLmV4dGVuZChkZWZhdWx0UXVlcnlGaWx0ZXJzLCB2bS5xdWVyeUZpbHRlcnMpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGJlZm9yZVNhdmUoKSB7XG4gICAgICB2bS5yZXNvdXJjZS5wcm9qZWN0X2lkID0gdm0ucHJvamVjdDtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBiZWZvcmVSZW1vdmUoKSB7XG4gICAgICB2bS5yZXNvdXJjZS5wcm9qZWN0X2lkID0gdm0ucHJvamVjdDtcbiAgICB9XG5cbiAgICB2bS52aWV3ID0gZnVuY3Rpb24gKHJlc291cmNlKSB7XG4gICAgICB2bS5yZXNvdXJjZSA9IHJlc291cmNlO1xuICAgICAgdm0ub25WaWV3ID0gdHJ1ZTtcbiAgICAgIHZtLnZpZXdGb3JtID0gZmFsc2U7XG4gICAgfTtcblxuICAgIHZtLnNhdmVDb21tZW50ID0gZnVuY3Rpb24gKGNvbW1lbnQpIHtcbiAgICAgIHZhciBkZXNjcmlwdGlvbiA9ICcnO1xuICAgICAgdmFyIGNvbW1lbnRfaWQgPSBudWxsO1xuXG4gICAgICBpZiAoY29tbWVudCkge1xuICAgICAgICBkZXNjcmlwdGlvbiA9IHZtLmFuc3dlcjtcbiAgICAgICAgY29tbWVudF9pZCA9IGNvbW1lbnQuaWQ7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBkZXNjcmlwdGlvbiA9IHZtLmNvbW1lbnQ7XG4gICAgICB9XG4gICAgICBUYXNrQ29tbWVudHNTZXJ2aWNlLnNhdmVUYXNrQ29tbWVudCh7IHByb2plY3RfaWQ6IHZtLnByb2plY3QsIHRhc2tfaWQ6IHZtLnJlc291cmNlLmlkLCBjb21tZW50X3RleHQ6IGRlc2NyaXB0aW9uLCBjb21tZW50X2lkOiBjb21tZW50X2lkIH0pLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICB2bS5jb21tZW50ID0gJyc7XG4gICAgICAgIHZtLmFuc3dlciA9ICcnO1xuICAgICAgICB2bS5zZWFyY2goKTtcbiAgICAgICAgUHJUb2FzdC5zdWNjZXNzKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMuc2F2ZVN1Y2Nlc3MnKSk7XG4gICAgICB9LCBmdW5jdGlvbiAoKSB7XG4gICAgICAgIFByVG9hc3QuZXJyb3IoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5vcGVyYXRpb25FcnJvcicpKTtcbiAgICAgIH0pO1xuICAgIH07XG5cbiAgICB2bS5yZW1vdmVDb21tZW50ID0gZnVuY3Rpb24gKGNvbW1lbnQpIHtcbiAgICAgIFRhc2tDb21tZW50c1NlcnZpY2UucmVtb3ZlVGFza0NvbW1lbnQoeyBjb21tZW50X2lkOiBjb21tZW50LmlkIH0pLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICB2bS5zZWFyY2goKTtcbiAgICAgICAgUHJUb2FzdC5zdWNjZXNzKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMucmVtb3ZlU3VjY2VzcycpKTtcbiAgICAgIH0sIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgUHJUb2FzdC5lcnJvcigkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLm9wZXJhdGlvbkVycm9yJykpO1xuICAgICAgfSk7XG4gICAgfTtcblxuICAgIHZtLmFmdGVyU2VhcmNoID0gZnVuY3Rpb24gKCkge1xuICAgICAgaWYgKHZtLnJlc291cmNlLmlkKSB7XG4gICAgICAgIHZtLnJlc291cmNlID0gJGZpbHRlcignZmlsdGVyJykodm0ucmVzb3VyY2VzLCB7IGlkOiB2bS5yZXNvdXJjZS5pZCB9KVswXTtcbiAgICAgIH1cbiAgICB9O1xuXG4gICAgdm0uZml4RGF0ZSA9IGZ1bmN0aW9uIChkYXRlU3RyaW5nKSB7XG4gICAgICByZXR1cm4gbW9tZW50KGRhdGVTdHJpbmcpO1xuICAgIH07XG5cbiAgICAvLyBpbnN0YW50aWF0ZSBiYXNlIGNvbnRyb2xsZXJcbiAgICAkY29udHJvbGxlcignQ1JVRENvbnRyb2xsZXInLCB7IHZtOiB2bSwgbW9kZWxTZXJ2aWNlOiBUYXNrc1NlcnZpY2UsIG9wdGlvbnM6IHsgc2tpcFBhZ2luYXRpb246IHRydWUgfSB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25maWcocm91dGVzKTtcblxuICAvKipcbiAgICogQXJxdWl2byBkZSBjb25maWd1cmHDp8OjbyBjb20gYXMgcm90YXMgZXNwZWPDrWZpY2FzIGRvIHJlY3Vyc28gcHJvamVjdFxuICAgKlxuICAgKiBAcGFyYW0ge2FueX0gJHN0YXRlUHJvdmlkZXJcbiAgICogQHBhcmFtIHthbnl9IEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdhcHAudGFza3MnLCB7XG4gICAgICB1cmw6ICcvdGFza3MnLFxuICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy90YXNrcy90YXNrcy5odG1sJyxcbiAgICAgIGNvbnRyb2xsZXI6ICdUYXNrc0NvbnRyb2xsZXIgYXMgdGFza3NDdHJsJyxcbiAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiB0cnVlIH1cbiAgICB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5mYWN0b3J5KCdUYXNrc1NlcnZpY2UnLCBUYXNrc1NlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gVGFza3NTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCd0YXNrcycsIHtcbiAgICAgIGFjdGlvbnM6IHtcbiAgICAgICAgdXBkYXRlTWlsZXN0b25lOiB7XG4gICAgICAgICAgbWV0aG9kOiAnUE9TVCcsXG4gICAgICAgICAgdXJsOiAndXBkYXRlTWlsZXN0b25lJ1xuICAgICAgICB9LFxuICAgICAgICB1cGRhdGVUYXNrQnlLYW5iYW46IHtcbiAgICAgICAgICBtZXRob2Q6ICdQT1NUJyxcbiAgICAgICAgICB1cmw6ICd1cGRhdGVUYXNrQnlLYW5iYW4nXG4gICAgICAgIH1cbiAgICAgIH0sXG4gICAgICBpbnN0YW5jZToge31cbiAgICB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5mYWN0b3J5KCdUeXBlc1NlcnZpY2UnLCBUeXBlc1NlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gVHlwZXNTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgdmFyIG1vZGVsID0gc2VydmljZUZhY3RvcnkoJ3R5cGVzJywge1xuICAgICAgYWN0aW9uczoge30sXG4gICAgICBpbnN0YW5jZToge31cbiAgICB9KTtcblxuICAgIHJldHVybiBtb2RlbDtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbnRyb2xsZXIoJ1Byb2ZpbGVDb250cm9sbGVyJywgUHJvZmlsZUNvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gUHJvZmlsZUNvbnRyb2xsZXIoVXNlcnNTZXJ2aWNlLCBBdXRoLCBQclRvYXN0LCAkdHJhbnNsYXRlLCAkd2luZG93LCBtb21lbnQpIHtcbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0udXBkYXRlID0gdXBkYXRlO1xuICAgIHZtLmhpc3RvcnlCYWNrID0gaGlzdG9yeUJhY2s7XG5cbiAgICBhY3RpdmF0ZSgpO1xuXG4gICAgZnVuY3Rpb24gYWN0aXZhdGUoKSB7XG4gICAgICB2bS51c2VyID0gYW5ndWxhci5jb3B5KEF1dGguY3VycmVudFVzZXIpO1xuICAgICAgaWYgKHZtLnVzZXIuYmlydGhkYXkpIHtcbiAgICAgICAgdm0udXNlci5iaXJ0aGRheSA9IG1vbWVudCh2bS51c2VyLmJpcnRoZGF5KS5mb3JtYXQoJ0REL01NL1lZWVknKTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICBmdW5jdGlvbiB1cGRhdGUoKSB7XG4gICAgICBpZiAodm0udXNlci5iaXJ0aGRheSkge1xuICAgICAgICB2bS51c2VyLmJpcnRoZGF5ID0gbW9tZW50KHZtLnVzZXIuYmlydGhkYXkpO1xuICAgICAgfVxuICAgICAgVXNlcnNTZXJ2aWNlLnVwZGF0ZVByb2ZpbGUodm0udXNlcikudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgLy9hdHVhbGl6YSBvIHVzdcOhcmlvIGNvcnJlbnRlIGNvbSBhcyBub3ZhcyBpbmZvcm1hw6fDtWVzXG4gICAgICAgIEF1dGgudXBkYXRlQ3VycmVudFVzZXIocmVzcG9uc2UpO1xuICAgICAgICBQclRvYXN0LnN1Y2Nlc3MoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5zYXZlU3VjY2VzcycpKTtcbiAgICAgICAgaGlzdG9yeUJhY2soKTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGhpc3RvcnlCYWNrKCkge1xuICAgICAgJHdpbmRvdy5oaXN0b3J5LmJhY2soKTtcbiAgICB9XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb250cm9sbGVyKCdVc2Vyc0NvbnRyb2xsZXInLCBVc2Vyc0NvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gVXNlcnNDb250cm9sbGVyKCRjb250cm9sbGVyLCBVc2Vyc1NlcnZpY2UsIFByVG9hc3QsICRtZERpYWxvZywgJHRyYW5zbGF0ZSkge1xuXG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIHZtLm9uQWN0aXZhdGUgPSBvbkFjdGl2YXRlO1xuICAgIC8vIGluc3RhbnRpYXRlIGJhc2UgY29udHJvbGxlclxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHsgdm06IHZtLCBtb2RlbFNlcnZpY2U6IFVzZXJzU2VydmljZSwgb3B0aW9uczoge30gfSk7XG5cbiAgICBmdW5jdGlvbiBvbkFjdGl2YXRlKCkge1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0ge307XG4gICAgfVxuXG4gICAgdm0uaGlkZURpYWxvZyA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICRtZERpYWxvZy5oaWRlKCk7XG4gICAgfTtcblxuICAgIHZtLnNhdmVOZXdVc2VyID0gZnVuY3Rpb24gKCkge1xuICAgICAgdm0ucmVzb3VyY2UuJHNhdmUoKS50aGVuKGZ1bmN0aW9uIChyZXNvdXJjZSkge1xuICAgICAgICB2bS5yZXNvdXJjZSA9IHJlc291cmNlO1xuICAgICAgICBQclRvYXN0LnN1Y2Nlc3MoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5zdWNjZXNzU2lnblVwJykpO1xuICAgICAgICAkbWREaWFsb2cuaGlkZSgpO1xuICAgICAgfSk7XG4gICAgfTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25maWcocm91dGVzKTtcblxuICAvKipcbiAgICogQXJxdWl2byBkZSBjb25maWd1cmHDp8OjbyBjb20gYXMgcm90YXMgZXNwZWPDrWZpY2FzIGRvIHJlY3Vyc28gdXNlclxuICAgKlxuICAgKiBAcGFyYW0ge2FueX0gJHN0YXRlUHJvdmlkZXJcbiAgICogQHBhcmFtIHthbnl9IEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdhcHAudXNlcicsIHtcbiAgICAgIHVybDogJy91c3VhcmlvJyxcbiAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvdXNlcnMvdXNlcnMuaHRtbCcsXG4gICAgICBjb250cm9sbGVyOiAnVXNlcnNDb250cm9sbGVyIGFzIHVzZXJzQ3RybCcsXG4gICAgICBkYXRhOiB7IG5lZWRBdXRoZW50aWNhdGlvbjogdHJ1ZSwgbmVlZFByb2ZpbGU6IFsnYWRtaW4nXSB9XG4gICAgfSkuc3RhdGUoJ2FwcC51c2VyLXByb2ZpbGUnLCB7XG4gICAgICB1cmw6ICcvdXN1YXJpby9wZXJmaWwnLFxuICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy91c2Vycy9wcm9maWxlLmh0bWwnLFxuICAgICAgY29udHJvbGxlcjogJ1Byb2ZpbGVDb250cm9sbGVyIGFzIHByb2ZpbGVDdHJsJyxcbiAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiB0cnVlIH1cbiAgICB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5mYWN0b3J5KCdVc2Vyc1NlcnZpY2UnLCBVc2Vyc1NlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gVXNlcnNTZXJ2aWNlKGxvZGFzaCwgR2xvYmFsLCBzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHJldHVybiBzZXJ2aWNlRmFjdG9yeSgndXNlcnMnLCB7XG4gICAgICAvL3F1YW5kbyBpbnN0YW5jaWEgdW0gdXN1w6FyaW8gc2VtIHBhc3NhciBwYXJhbWV0cm8sXG4gICAgICAvL28gbWVzbW8gdmFpIHRlciBvcyB2YWxvcmVzIGRlZmF1bHRzIGFiYWl4b1xuICAgICAgZGVmYXVsdHM6IHtcbiAgICAgICAgcm9sZXM6IFtdXG4gICAgICB9LFxuXG4gICAgICBhY3Rpb25zOiB7XG4gICAgICAgIC8qKlxuICAgICAgICAgKiBTZXJ2acOnbyBxdWUgYXR1YWxpemEgb3MgZGFkb3MgZG8gcGVyZmlsIGRvIHVzdcOhcmlvIGxvZ2Fkb1xuICAgICAgICAgKlxuICAgICAgICAgKiBAcGFyYW0ge29iamVjdH0gYXR0cmlidXRlc1xuICAgICAgICAgKiBAcmV0dXJucyB7cHJvbWlzZX0gVW1hIHByb21pc2UgY29tIG8gcmVzdWx0YWRvIGRvIGNoYW1hZGEgbm8gYmFja2VuZFxuICAgICAgICAgKi9cbiAgICAgICAgdXBkYXRlUHJvZmlsZToge1xuICAgICAgICAgIG1ldGhvZDogJ1BVVCcsXG4gICAgICAgICAgdXJsOiBHbG9iYWwuYXBpUGF0aCArICcvcHJvZmlsZScsXG4gICAgICAgICAgb3ZlcnJpZGU6IHRydWUsXG4gICAgICAgICAgd3JhcDogZmFsc2VcbiAgICAgICAgfVxuICAgICAgfSxcblxuICAgICAgaW5zdGFuY2U6IHtcbiAgICAgICAgLyoqXG4gICAgICAgICAqIFZlcmlmaWNhIHNlIG8gdXN1w6FyaW8gdGVtIG9zIHBlcmZpcyBpbmZvcm1hZG9zLlxuICAgICAgICAgKlxuICAgICAgICAgKiBAcGFyYW0ge2FueX0gcm9sZXMgcGVyZmlzIGEgc2VyZW0gdmVyaWZpY2Fkb3NcbiAgICAgICAgICogQHBhcmFtIHtib29sZWFufSBhbGwgZmxhZyBwYXJhIGluZGljYXIgc2UgdmFpIGNoZWdhciB0b2RvcyBvcyBwZXJmaXMgb3Ugc29tZW50ZSB1bSBkZWxlc1xuICAgICAgICAgKiBAcmV0dXJucyB7Ym9vbGVhbn1cbiAgICAgICAgICovXG4gICAgICAgIGhhc1Byb2ZpbGU6IGZ1bmN0aW9uIGhhc1Byb2ZpbGUocm9sZXMsIGFsbCkge1xuICAgICAgICAgIHJvbGVzID0gYW5ndWxhci5pc0FycmF5KHJvbGVzKSA/IHJvbGVzIDogW3JvbGVzXTtcblxuICAgICAgICAgIHZhciB1c2VyUm9sZXMgPSBsb2Rhc2gubWFwKHRoaXMucm9sZXMsICdzbHVnJyk7XG5cbiAgICAgICAgICBpZiAoYWxsKSB7XG4gICAgICAgICAgICByZXR1cm4gbG9kYXNoLmludGVyc2VjdGlvbih1c2VyUm9sZXMsIHJvbGVzKS5sZW5ndGggPT09IHJvbGVzLmxlbmd0aDtcbiAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgLy9yZXR1cm4gdGhlIGxlbmd0aCBiZWNhdXNlIDAgaXMgZmFsc2UgaW4ganNcbiAgICAgICAgICAgIHJldHVybiBsb2Rhc2guaW50ZXJzZWN0aW9uKHVzZXJSb2xlcywgcm9sZXMpLmxlbmd0aDtcbiAgICAgICAgICB9XG4gICAgICAgIH0sXG5cbiAgICAgICAgLyoqXG4gICAgICAgICAqIFZlcmlmaWNhIHNlIG8gdXN1w6FyaW8gdGVtIG8gcGVyZmlsIGFkbWluLlxuICAgICAgICAgKlxuICAgICAgICAgKiBAcmV0dXJucyB7Ym9vbGVhbn1cbiAgICAgICAgICovXG4gICAgICAgIGlzQWRtaW46IGZ1bmN0aW9uIGlzQWRtaW4oKSB7XG4gICAgICAgICAgcmV0dXJuIHRoaXMuaGFzUHJvZmlsZSgnYWRtaW4nKTtcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4vL3Rva2VuIGNhY2I5MTIzNTg3M2E4YzQ4NzVkMjM1NzhhYzlmMzI2ZWY4OTRiNjZcbi8vIE9BdHV0aCBodHRwczovL2dpdGh1Yi5jb20vbG9naW4vb2F1dGgvYXV0aG9yaXplP2NsaWVudF9pZD04Mjk0NjhlN2ZkZWU3OTQ0NWJhNiZzY29wZT11c2VyLHB1YmxpY19yZXBvJnJlZGlyZWN0X3VyaT1odHRwOi8vMC4wLjAuMDo1MDAwLyMhL2FwcC92Y3NcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5maWx0ZXIoJ2J5dGVzJywgZnVuY3Rpb24gKCkge1xuICAgIHJldHVybiBmdW5jdGlvbiAoYnl0ZXMsIHByZWNpc2lvbikge1xuICAgICAgaWYgKGlzTmFOKHBhcnNlRmxvYXQoYnl0ZXMpKSB8fCAhaXNGaW5pdGUoYnl0ZXMpKSByZXR1cm4gJy0nO1xuICAgICAgaWYgKHR5cGVvZiBwcmVjaXNpb24gPT09ICd1bmRlZmluZWQnKSBwcmVjaXNpb24gPSAxO1xuICAgICAgdmFyIHVuaXRzID0gWydieXRlcycsICdrQicsICdNQicsICdHQicsICdUQicsICdQQiddLFxuICAgICAgICAgIG51bWJlciA9IE1hdGguZmxvb3IoTWF0aC5sb2coYnl0ZXMpIC8gTWF0aC5sb2coMTAyNCkpO1xuXG4gICAgICByZXR1cm4gKGJ5dGVzIC8gTWF0aC5wb3coMTAyNCwgTWF0aC5mbG9vcihudW1iZXIpKSkudG9GaXhlZChwcmVjaXNpb24pICsgJyAnICsgdW5pdHNbbnVtYmVyXTtcbiAgICB9O1xuICB9KS5jb250cm9sbGVyKCdWY3NDb250cm9sbGVyJywgVmNzQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBWY3NDb250cm9sbGVyKCRjb250cm9sbGVyLCBWY3NTZXJ2aWNlLCAkd2luZG93LCBQcm9qZWN0c1NlcnZpY2UsIFByVG9hc3QsICR0cmFuc2xhdGUpIHtcbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0uaW5kZXggPSAwO1xuICAgIHZtLnBhdGhzID0gW107XG5cbiAgICAvL0F0dHJpYnV0ZXMgQmxvY2tcblxuICAgIC8vRnVuY3Rpb25zIEJsb2NrXG4gICAgdm0ub25BY3RpdmF0ZSA9IGZ1bmN0aW9uICgpIHtcbiAgICAgIHRvZ2dsZVNwbGFzaFNjcmVlbigpO1xuICAgICAgUHJvamVjdHNTZXJ2aWNlLnF1ZXJ5KHsgcHJvamVjdF9pZDogbG9jYWxTdG9yYWdlLmdldEl0ZW0oJ3Byb2plY3QnKSB9KS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICB2bS51c2VybmFtZSA9IHJlc3BvbnNlWzBdLnVzZXJuYW1lX2dpdGh1YjtcbiAgICAgICAgdm0ucmVwbyA9IHJlc3BvbnNlWzBdLnJlcG9fZ2l0aHViO1xuICAgICAgICBpZiAodm0udXNlcm5hbWUgJiYgdm0ucmVwbykge1xuICAgICAgICAgIHZtLnF1ZXJ5RmlsdGVycyA9IHtcbiAgICAgICAgICAgIHVzZXJuYW1lOiB2bS51c2VybmFtZSxcbiAgICAgICAgICAgIHJlcG86IHZtLnJlcG8sXG4gICAgICAgICAgICBwYXRoOiAnLidcbiAgICAgICAgICB9O1xuICAgICAgICAgIHZtLnBhdGhzLnB1c2godm0ucXVlcnlGaWx0ZXJzLnBhdGgpO1xuICAgICAgICAgIHZtLnNlYXJjaCgpO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICR3aW5kb3cubG9hZGluZ19zY3JlZW4uZmluaXNoKCk7XG4gICAgICAgIH1cbiAgICAgIH0pO1xuICAgIH07XG5cbiAgICB2bS5hcHBseUZpbHRlcnMgPSBmdW5jdGlvbiAoZGVmYXVsdFF1ZXJ5RmlsdGVycykge1xuICAgICAgcmV0dXJuIGFuZ3VsYXIuZXh0ZW5kKGRlZmF1bHRRdWVyeUZpbHRlcnMsIHZtLnF1ZXJ5RmlsdGVycyk7XG4gICAgfTtcblxuICAgIHZtLmFmdGVyU2VhcmNoID0gZnVuY3Rpb24gKCkge1xuICAgICAgc29ydFJlc291cmNlcygpO1xuICAgICAgJHdpbmRvdy5sb2FkaW5nX3NjcmVlbi5maW5pc2goKTtcbiAgICB9O1xuXG4gICAgZnVuY3Rpb24gc29ydFJlc291cmNlcygpIHtcbiAgICAgIGlmICh2bS5yZXNvdXJjZXMubGVuZ3RoID4gMCkge1xuICAgICAgICB2bS5yZXNvdXJjZXMuc29ydChmdW5jdGlvbiAoYSwgYikge1xuICAgICAgICAgIHJldHVybiBhLnR5cGUgPCBiLnR5cGUgPyAtMSA6IGEudHlwZSA+IGIudHlwZSA/IDEgOiAwO1xuICAgICAgICB9KTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICB2bS5vcGVuRmlsZU9yRGlyZWN0b3J5ID0gZnVuY3Rpb24gKHJlc291cmNlKSB7XG4gICAgICB0b2dnbGVTcGxhc2hTY3JlZW4oKTtcbiAgICAgIGlmIChyZXNvdXJjZSkge1xuICAgICAgICB2bS5xdWVyeUZpbHRlcnMucGF0aCA9IHJlc291cmNlLnBhdGg7XG4gICAgICAgIHZtLnBhdGhzLnB1c2godm0ucXVlcnlGaWx0ZXJzLnBhdGgpO1xuICAgICAgICB2bS5pbmRleCsrO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgdm0ucXVlcnlGaWx0ZXJzLnBhdGggPSB2bS5wYXRoc1t2bS5pbmRleCAtIDFdO1xuICAgICAgICB2bS5wYXRocy5zcGxpY2Uodm0uaW5kZXgsIDEpO1xuICAgICAgICB2bS5pbmRleC0tO1xuICAgICAgfVxuICAgICAgdm0uc2VhcmNoKCk7XG4gICAgfTtcblxuICAgIHZtLm9uU2VhcmNoRXJyb3IgPSBmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgIGlmIChyZXNwb25zZS5kYXRhLmVycm9yID09PSAnTm90IEZvdW5kJykge1xuICAgICAgICBQclRvYXN0LmluZm8oJHRyYW5zbGF0ZS5pbnN0YW50KCdSZXBvc2l0w7NyaW8gbsOjbyBlbmNvbnRyYWRvJykpO1xuICAgICAgICAkd2luZG93LmxvYWRpbmdfc2NyZWVuLmZpbmlzaCgpO1xuICAgICAgfVxuICAgIH07XG5cbiAgICAvKipcbiAgICAgKiBNw6l0b2RvIHBhcmEgbW9zdHJhciBhIHRlbGEgZGUgZXNwZXJhXG4gICAgICovXG4gICAgZnVuY3Rpb24gdG9nZ2xlU3BsYXNoU2NyZWVuKCkge1xuICAgICAgJHdpbmRvdy5sb2FkaW5nX3NjcmVlbiA9ICR3aW5kb3cucGxlYXNlV2FpdCh7XG4gICAgICAgIGxvZ286ICcnLFxuICAgICAgICBiYWNrZ3JvdW5kQ29sb3I6ICdyZ2JhKDI1NSwyNTUsMjU1LDAuNCknLFxuICAgICAgICBsb2FkaW5nSHRtbDogJzxkaXYgY2xhc3M9XCJzcGlubmVyXCI+ICcgKyAnICA8ZGl2IGNsYXNzPVwicmVjdDFcIj48L2Rpdj4gJyArICcgIDxkaXYgY2xhc3M9XCJyZWN0MlwiPjwvZGl2PiAnICsgJyAgPGRpdiBjbGFzcz1cInJlY3QzXCI+PC9kaXY+ICcgKyAnICA8ZGl2IGNsYXNzPVwicmVjdDRcIj48L2Rpdj4gJyArICcgIDxkaXYgY2xhc3M9XCJyZWN0NVwiPjwvZGl2PiAnICsgJyA8cCBjbGFzcz1cImxvYWRpbmctbWVzc2FnZVwiPkNhcnJlZ2FuZG88L3A+ICcgKyAnPC9kaXY+J1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLy8gaW5zdGFudGlhdGUgYmFzZSBjb250cm9sbGVyXG4gICAgJGNvbnRyb2xsZXIoJ0NSVURDb250cm9sbGVyJywgeyB2bTogdm0sIG1vZGVsU2VydmljZTogVmNzU2VydmljZSwgb3B0aW9uczogeyBza2lwUGFnaW5hdGlvbjogdHJ1ZSwgc2VhcmNoT25Jbml0OiBmYWxzZSB9IH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKlxuICAgKiBBcnF1aXZvIGRlIGNvbmZpZ3VyYcOnw6NvIGNvbSBhcyByb3RhcyBlc3BlY8OtZmljYXMgZG8gcmVjdXJzbyB2Y3NcbiAgICpcbiAgICogQHBhcmFtIHtvYmplY3R9ICRzdGF0ZVByb3ZpZGVyXG4gICAqIEBwYXJhbSB7b2JqZWN0fSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnYXBwLnZjcycsIHtcbiAgICAgIHVybDogJy92Y3MnLFxuICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy92Y3MvdmNzLmh0bWwnLFxuICAgICAgY29udHJvbGxlcjogJ1Zjc0NvbnRyb2xsZXIgYXMgdmNzQ3RybCcsXG4gICAgICBkYXRhOiB7fVxuICAgIH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZhY3RvcnkoJ1Zjc1NlcnZpY2UnLCBWY3NTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIFZjc1NlcnZpY2Uoc2VydmljZUZhY3RvcnkpIHtcbiAgICB2YXIgbW9kZWwgPSBzZXJ2aWNlRmFjdG9yeSgndmNzJywge1xuICAgICAgYWN0aW9uczoge30sXG4gICAgICBpbnN0YW5jZToge31cbiAgICB9KTtcblxuICAgIHJldHVybiBtb2RlbDtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29tcG9uZW50KCdib3gnLCB7XG4gICAgcmVwbGFjZTogdHJ1ZSxcbiAgICB0ZW1wbGF0ZVVybDogWydHbG9iYWwnLCBmdW5jdGlvbiAoR2xvYmFsKSB7XG4gICAgICByZXR1cm4gR2xvYmFsLmNsaWVudFBhdGggKyAnL3dpZGdldHMvYm94Lmh0bWwnO1xuICAgIH1dLFxuICAgIHRyYW5zY2x1ZGU6IHtcbiAgICAgIHRvb2xiYXJCdXR0b25zOiAnP2JveFRvb2xiYXJCdXR0b25zJyxcbiAgICAgIGZvb3RlckJ1dHRvbnM6ICc/Ym94Rm9vdGVyQnV0dG9ucydcbiAgICB9LFxuICAgIGJpbmRpbmdzOiB7XG4gICAgICBib3hUaXRsZTogJ0AnLFxuICAgICAgdG9vbGJhckNsYXNzOiAnQCcsXG4gICAgICB0b29sYmFyQmdDb2xvcjogJ0AnXG4gICAgfSxcbiAgICBjb250cm9sbGVyOiBbJyR0cmFuc2NsdWRlJywgZnVuY3Rpb24gKCR0cmFuc2NsdWRlKSB7XG4gICAgICB2YXIgY3RybCA9IHRoaXM7XG5cbiAgICAgIGN0cmwudHJhbnNjbHVkZSA9ICR0cmFuc2NsdWRlO1xuXG4gICAgICBjdHJsLiRvbkluaXQgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgIGlmIChhbmd1bGFyLmlzVW5kZWZpbmVkKGN0cmwudG9vbGJhckJnQ29sb3IpKSBjdHJsLnRvb2xiYXJCZ0NvbG9yID0gJ2RlZmF1bHQtcHJpbWFyeSc7XG4gICAgICB9O1xuICAgIH1dXG4gIH0pO1xufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29tcG9uZW50KCdjb250ZW50Qm9keScsIHtcbiAgICByZXBsYWNlOiB0cnVlLFxuICAgIHRyYW5zY2x1ZGU6IHRydWUsXG4gICAgdGVtcGxhdGVVcmw6IFsnR2xvYmFsJywgZnVuY3Rpb24gKEdsb2JhbCkge1xuICAgICAgcmV0dXJuIEdsb2JhbC5jbGllbnRQYXRoICsgJy93aWRnZXRzL2NvbnRlbnQtYm9keS5odG1sJztcbiAgICB9XSxcbiAgICBiaW5kaW5nczoge1xuICAgICAgbGF5b3V0QWxpZ246ICdAJ1xuICAgIH0sXG4gICAgY29udHJvbGxlcjogW2Z1bmN0aW9uICgpIHtcbiAgICAgIHZhciBjdHJsID0gdGhpcztcblxuICAgICAgY3RybC4kb25Jbml0ID0gZnVuY3Rpb24gKCkge1xuICAgICAgICAvLyBNYWtlIGEgY29weSBvZiB0aGUgaW5pdGlhbCB2YWx1ZSB0byBiZSBhYmxlIHRvIHJlc2V0IGl0IGxhdGVyXG4gICAgICAgIGN0cmwubGF5b3V0QWxpZ24gPSBhbmd1bGFyLmlzRGVmaW5lZChjdHJsLmxheW91dEFsaWduKSA/IGN0cmwubGF5b3V0QWxpZ24gOiAnY2VudGVyIHN0YXJ0JztcbiAgICAgIH07XG4gICAgfV1cbiAgfSk7XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb21wb25lbnQoJ2NvbnRlbnRIZWFkZXInLCB7XG4gICAgdGVtcGxhdGVVcmw6IFsnR2xvYmFsJywgZnVuY3Rpb24gKEdsb2JhbCkge1xuICAgICAgcmV0dXJuIEdsb2JhbC5jbGllbnRQYXRoICsgJy93aWRnZXRzL2NvbnRlbnQtaGVhZGVyLmh0bWwnO1xuICAgIH1dLFxuICAgIHJlcGxhY2U6IHRydWUsXG4gICAgYmluZGluZ3M6IHtcbiAgICAgIHRpdGxlOiAnQCcsXG4gICAgICBkZXNjcmlwdGlvbjogJ0AnXG4gICAgfVxuICB9KTtcbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5maWx0ZXIoJ2F1ZGl0RGV0YWlsVGl0bGUnLCBhdWRpdERldGFpbFRpdGxlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIGF1ZGl0RGV0YWlsVGl0bGUoJHRyYW5zbGF0ZSkge1xuICAgIHJldHVybiBmdW5jdGlvbiAoYXVkaXREZXRhaWwsIHN0YXR1cykge1xuICAgICAgaWYgKGF1ZGl0RGV0YWlsLnR5cGUgPT09ICd1cGRhdGVkJykge1xuICAgICAgICBpZiAoc3RhdHVzID09PSAnYmVmb3JlJykge1xuICAgICAgICAgIHJldHVybiAkdHJhbnNsYXRlLmluc3RhbnQoJ2RpYWxvZy5hdWRpdC51cGRhdGVkQmVmb3JlJyk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgcmV0dXJuICR0cmFuc2xhdGUuaW5zdGFudCgnZGlhbG9nLmF1ZGl0LnVwZGF0ZWRBZnRlcicpO1xuICAgICAgICB9XG4gICAgICB9IGVsc2Uge1xuICAgICAgICByZXR1cm4gJHRyYW5zbGF0ZS5pbnN0YW50KCdkaWFsb2cuYXVkaXQuJyArIGF1ZGl0RGV0YWlsLnR5cGUpO1xuICAgICAgfVxuICAgIH07XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5maWx0ZXIoJ2F1ZGl0TW9kZWwnLCBhdWRpdE1vZGVsKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIGF1ZGl0TW9kZWwoJHRyYW5zbGF0ZSkge1xuICAgIHJldHVybiBmdW5jdGlvbiAobW9kZWxJZCkge1xuICAgICAgbW9kZWxJZCA9IG1vZGVsSWQucmVwbGFjZSgnQXBwXFxcXCcsICcnKTtcbiAgICAgIHZhciBtb2RlbCA9ICR0cmFuc2xhdGUuaW5zdGFudCgnbW9kZWxzLicgKyBtb2RlbElkLnRvTG93ZXJDYXNlKCkpO1xuXG4gICAgICByZXR1cm4gbW9kZWwgPyBtb2RlbCA6IG1vZGVsSWQ7XG4gICAgfTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZpbHRlcignYXVkaXRUeXBlJywgYXVkaXRUeXBlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIGF1ZGl0VHlwZShsb2Rhc2gsIEF1ZGl0U2VydmljZSkge1xuICAgIHJldHVybiBmdW5jdGlvbiAodHlwZUlkKSB7XG4gICAgICB2YXIgdHlwZSA9IGxvZGFzaC5maW5kKEF1ZGl0U2VydmljZS5saXN0VHlwZXMoKSwgeyBpZDogdHlwZUlkIH0pO1xuXG4gICAgICByZXR1cm4gdHlwZSA/IHR5cGUubGFiZWwgOiB0eXBlO1xuICAgIH07XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5maWx0ZXIoJ2F1ZGl0VmFsdWUnLCBhdWRpdFZhbHVlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIGF1ZGl0VmFsdWUoJGZpbHRlciwgbG9kYXNoKSB7XG4gICAgcmV0dXJuIGZ1bmN0aW9uICh2YWx1ZSwga2V5KSB7XG4gICAgICBpZiAoYW5ndWxhci5pc0RhdGUodmFsdWUpIHx8IGxvZGFzaC5lbmRzV2l0aChrZXksICdfYXQnKSB8fCBsb2Rhc2guZW5kc1dpdGgoa2V5LCAnX3RvJykpIHtcbiAgICAgICAgcmV0dXJuICRmaWx0ZXIoJ3ByRGF0ZXRpbWUnKSh2YWx1ZSk7XG4gICAgICB9XG5cbiAgICAgIGlmICh0eXBlb2YgdmFsdWUgPT09ICdib29sZWFuJykge1xuICAgICAgICByZXR1cm4gJGZpbHRlcigndHJhbnNsYXRlJykodmFsdWUgPyAnZ2xvYmFsLnllcycgOiAnZ2xvYmFsLm5vJyk7XG4gICAgICB9XG5cbiAgICAgIC8vY2hlY2sgaXMgZmxvYXRcbiAgICAgIGlmIChOdW1iZXIodmFsdWUpID09PSB2YWx1ZSAmJiB2YWx1ZSAlIDEgIT09IDApIHtcbiAgICAgICAgcmV0dXJuICRmaWx0ZXIoJ3JlYWwnKSh2YWx1ZSk7XG4gICAgICB9XG5cbiAgICAgIHJldHVybiB2YWx1ZTtcbiAgICB9O1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4vKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCwgbm8tdW5kZWY6IDAqL1xuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25zdGFudCgncHQtQlIuaTE4bi5hdHRyaWJ1dGVzJywge1xuICAgIGVtYWlsOiAnRW1haWwnLFxuICAgIHBhc3N3b3JkOiAnU2VuaGEnLFxuICAgIG5hbWU6ICdOb21lJyxcbiAgICBpbWFnZTogJ0ltYWdlbScsXG4gICAgcm9sZXM6ICdQZXJmaXMnLFxuICAgIGRhdGU6ICdEYXRhJyxcbiAgICBpbml0aWFsRGF0ZTogJ0RhdGEgSW5pY2lhbCcsXG4gICAgZmluYWxEYXRlOiAnRGF0YSBGaW5hbCcsXG4gICAgYmlydGhkYXk6ICdEYXRhIGRlIE5hc2NpbWVudG8nLFxuICAgIHRhc2s6IHtcbiAgICAgIGRlc2NyaXB0aW9uOiAnRGVzY3Jpw6fDo28nLFxuICAgICAgZG9uZTogJ0ZlaXRvPycsXG4gICAgICBwcmlvcml0eTogJ1ByaW9yaWRhZGUnLFxuICAgICAgc2NoZWR1bGVkX3RvOiAnQWdlbmRhZG8gUGFyYT8nLFxuICAgICAgcHJvamVjdDogJ1Byb2pldG8nLFxuICAgICAgc3RhdHVzOiAnU3RhdHVzJyxcbiAgICAgIHRpdGxlOiAnVMOtdHVsbycsXG4gICAgICB0eXBlOiAnVGlwbycsXG4gICAgICBtaWxlc3RvbmU6ICdTcHJpbnQnLFxuICAgICAgZXN0aW1hdGVkX3RpbWU6ICdUZW1wbyBFc3RpbWFkbydcbiAgICB9LFxuICAgIG1pbGVzdG9uZToge1xuICAgICAgdGl0bGU6ICdUw610dWxvJyxcbiAgICAgIGRlc2NyaXB0aW9uOiAnRGVzY3Jpw6fDo28nLFxuICAgICAgZGF0ZV9zdGFydDogJ0RhdGEgRXN0aW1hZGEgcGFyYSBJbsOtY2lvJyxcbiAgICAgIGRhdGVfZW5kOiAnRGF0YSBFc3RpbWFkYSBwYXJhIEZpbScsXG4gICAgICBlc3RpbWF0ZWRfdGltZTogJ1RlbXBvIEVzdGltYWRvJyxcbiAgICAgIGVzdGltYXRlZF92YWx1ZTogJ1ZhbG9yIEVzdGltYWRvJ1xuICAgIH0sXG4gICAgcHJvamVjdDoge1xuICAgICAgY29zdDogJ0N1c3RvJyxcbiAgICAgIGhvdXJWYWx1ZURldmVsb3BlcjogJ1ZhbG9yIGRhIEhvcmEgRGVzZW52b2x2ZWRvcicsXG4gICAgICBob3VyVmFsdWVDbGllbnQ6ICdWYWxvciBkYSBIb3JhIENsaWVudGUnLFxuICAgICAgaG91clZhbHVlRmluYWw6ICdWYWxvciBkYSBIb3JhIFByb2pldG8nXG4gICAgfSxcbiAgICByZWxlYXNlOiB7XG4gICAgICB0aXRsZTogJ1TDrXR1bG8nLFxuICAgICAgZGVzY3JpcHRpb246ICdEZXNjcmnDp8OjbycsXG4gICAgICByZWxlYXNlX2RhdGU6ICdEYXRhIGRlIEVudHJlZ2EnLFxuICAgICAgbWlsZXN0b25lOiAnTWlsZXN0b25lJyxcbiAgICAgIHRhc2tzOiAnVGFyZWZhcydcbiAgICB9LFxuICAgIC8vw6kgY2FycmVnYWRvIGRvIHNlcnZpZG9yIGNhc28gZXN0ZWphIGRlZmluaWRvIG5vIG1lc21vXG4gICAgYXVkaXRNb2RlbDoge31cbiAgfSk7XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4vKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCwgbm8tdW5kZWY6IDAqL1xuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25zdGFudCgncHQtQlIuaTE4bi5kaWFsb2cnLCB7XG4gICAgY29uZmlybVRpdGxlOiAnQ29uZmlybWHDp8OjbycsXG4gICAgY29uZmlybURlc2NyaXB0aW9uOiAnQ29uZmlybWEgYSBhw6fDo28/JyxcbiAgICByZW1vdmVEZXNjcmlwdGlvbjogJ0Rlc2VqYSByZW1vdmVyIHBlcm1hbmVudGVtZW50ZSB7e25hbWV9fT8nLFxuICAgIGF1ZGl0OiB7XG4gICAgICBjcmVhdGVkOiAnSW5mb3JtYcOnw7VlcyBkbyBDYWRhc3RybycsXG4gICAgICB1cGRhdGVkQmVmb3JlOiAnQW50ZXMgZGEgQXR1YWxpemHDp8OjbycsXG4gICAgICB1cGRhdGVkQWZ0ZXI6ICdEZXBvaXMgZGEgQXR1YWxpemHDp8OjbycsXG4gICAgICBkZWxldGVkOiAnSW5mb3JtYcOnw7VlcyBhbnRlcyBkZSByZW1vdmVyJ1xuICAgIH0sXG4gICAgbG9naW46IHtcbiAgICAgIHJlc2V0UGFzc3dvcmQ6IHtcbiAgICAgICAgZGVzY3JpcHRpb246ICdEaWdpdGUgYWJhaXhvIG8gZW1haWwgY2FkYXN0cmFkbyBubyBzaXN0ZW1hLidcbiAgICAgIH1cbiAgICB9XG4gIH0pO1xufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuLyplc2xpbnQgYW5ndWxhci9maWxlLW5hbWU6IDAsIG5vLXVuZGVmOiAwKi9cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29uc3RhbnQoJ3B0LUJSLmkxOG4uZ2xvYmFsJywge1xuICAgIGxvYWRpbmc6ICdDYXJyZWdhbmRvLi4uJyxcbiAgICBwcm9jZXNzaW5nOiAnUHJvY2Vzc2FuZG8uLi4nLFxuICAgIHllczogJ1NpbScsXG4gICAgbm86ICdOw6NvJyxcbiAgICBhbGw6ICdUb2RvcydcbiAgfSk7XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4vKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCwgbm8tdW5kZWY6IDAqL1xuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25zdGFudCgncHQtQlIuaTE4bi5tZXNzYWdlcycsIHtcbiAgICBpbnRlcm5hbEVycm9yOiAnT2NvcnJldSB1bSBlcnJvIGludGVybm8sIGNvbnRhdGUgbyBhZG1pbmlzdHJhZG9yIGRvIHNpc3RlbWEnLFxuICAgIG5vdEZvdW5kOiAnTmVuaHVtIHJlZ2lzdHJvIGVuY29udHJhZG8nLFxuICAgIG5vdEF1dGhvcml6ZWQ6ICdWb2PDqiBuw6NvIHRlbSBhY2Vzc28gYSBlc3RhIGZ1bmNpb25hbGlkYWRlLicsXG4gICAgc2VhcmNoRXJyb3I6ICdOw6NvIGZvaSBwb3Nzw612ZWwgcmVhbGl6YXIgYSBidXNjYS4nLFxuICAgIHNhdmVTdWNjZXNzOiAnUmVnaXN0cm8gc2Fsdm8gY29tIHN1Y2Vzc28uJyxcbiAgICBvcGVyYXRpb25TdWNjZXNzOiAnT3BlcmHDp8OjbyByZWFsaXphZGEgY29tIHN1Y2Vzc28uJyxcbiAgICBvcGVyYXRpb25FcnJvcjogJ0Vycm8gYW8gcmVhbGl6YXIgYSBvcGVyYcOnw6NvJyxcbiAgICBzYXZlRXJyb3I6ICdFcnJvIGFvIHRlbnRhciBzYWx2YXIgbyByZWdpc3Ryby4nLFxuICAgIHJlbW92ZVN1Y2Nlc3M6ICdSZW1vw6fDo28gcmVhbGl6YWRhIGNvbSBzdWNlc3NvLicsXG4gICAgcmVtb3ZlRXJyb3I6ICdFcnJvIGFvIHRlbnRhciByZW1vdmVyIG8gcmVnaXN0cm8uJyxcbiAgICByZXNvdXJjZU5vdEZvdW5kRXJyb3I6ICdSZWN1cnNvIG7Do28gZW5jb250cmFkbycsXG4gICAgbm90TnVsbEVycm9yOiAnVG9kb3Mgb3MgY2FtcG9zIG9icmlnYXTDs3Jpb3MgZGV2ZW0gc2VyIHByZWVuY2hpZG9zLicsXG4gICAgZHVwbGljYXRlZFJlc291cmNlRXJyb3I6ICdKw6EgZXhpc3RlIHVtIHJlY3Vyc28gY29tIGVzc2FzIGluZm9ybWHDp8O1ZXMuJyxcbiAgICBzcHJpbnRFbmRlZFN1Y2Nlc3M6ICdTcHJpbnQgZmluYWxpemFkYSBjb20gc3VjZXNzbycsXG4gICAgc3ByaW50RW5kZWRFcnJvcjogJ0Vycm8gYW8gZmluYWxpemFyIGEgc3ByaW50JyxcbiAgICBzdWNjZXNzU2lnblVwOiAnQ2FkYXN0cm8gcmVhbGl6YWRvIGNvbSBzdWNlc3NvLiBVbSBlLW1haWwgZm9pIGVudmlhZG8gY29tIHNldXMgZGFkb3MgZGUgbG9naW4nLFxuICAgIGVycm9yc1NpZ25VcDogJ0hvdXZlIHVtIGVycm8gYW8gcmVhbGl6YXIgbyBzZXUgY2FkYXN0cm8uIFRlbnRlIG5vdmFtZW50ZSBtYWlzIHRhcmRlIScsXG4gICAgcmVsZWFzZXRFbmRlZFN1Y2Nlc3M6ICdSZWxlYXNlIGZpbmFsaXphZGEgY29tIHN1Y2Vzc28nLFxuICAgIHJlbGVhc2VFbmRlZEVycm9yOiAnRXJybyBhbyBmaW5hbGl6YXIgYSByZWxlYXNlJyxcbiAgICBwcm9qZWN0RW5kZWRTdWNjZXNzOiAnUHJvamV0byBmaW5hbGl6YWRvIGNvbSBzdWNlc3NvJyxcbiAgICBwcm9qZWN0RW5kZWRFcnJvcjogJ0Vycm8gYW8gZmluYWxpemFyIG8gcHJvamV0bycsXG4gICAgdmFsaWRhdGU6IHtcbiAgICAgIGZpZWxkUmVxdWlyZWQ6ICdPIGNhbXBvIHt7ZmllbGR9fSDDqSBvYnJpZ3JhdMOzcmlvLidcbiAgICB9LFxuICAgIGxheW91dDoge1xuICAgICAgZXJyb3I0MDQ6ICdQw6FnaW5hIG7Do28gZW5jb250cmFkYSdcbiAgICB9LFxuICAgIGxvZ2luOiB7XG4gICAgICBsb2dvdXRJbmFjdGl2ZTogJ1ZvY8OqIGZvaSBkZXNsb2dhZG8gZG8gc2lzdGVtYSBwb3IgaW5hdGl2aWRhZGUuIEZhdm9yIGVudHJhciBubyBzaXN0ZW1hIG5vdmFtZW50ZS4nLFxuICAgICAgaW52YWxpZENyZWRlbnRpYWxzOiAnQ3JlZGVuY2lhaXMgSW52w6FsaWRhcycsXG4gICAgICB1bmtub3duRXJyb3I6ICdOw6NvIGZvaSBwb3Nzw612ZWwgcmVhbGl6YXIgbyBsb2dpbi4gVGVudGUgbm92YW1lbnRlLiAnICsgJ0Nhc28gbsOjbyBjb25zaWdhIGZhdm9yIGVuY29udHJhciBlbSBjb250YXRvIGNvbSBvIGFkbWluaXN0cmFkb3IgZG8gc2lzdGVtYS4nLFxuICAgICAgdXNlck5vdEZvdW5kOiAnTsOjbyBmb2kgcG9zc8OtdmVsIGVuY29udHJhciBzZXVzIGRhZG9zJ1xuICAgIH0sXG4gICAgZGFzaGJvYXJkOiB7XG4gICAgICB3ZWxjb21lOiAnU2VqYSBiZW0gVmluZG8ge3t1c2VyTmFtZX19JyxcbiAgICAgIGRlc2NyaXB0aW9uOiAnVXRpbGl6ZSBvIG1lbnUgcGFyYSBuYXZlZ2HDp8Ojby4nXG4gICAgfSxcbiAgICBtYWlsOiB7XG4gICAgICBtYWlsRXJyb3JzOiAnT2NvcnJldSB1bSBlcnJvIG5vcyBzZWd1aW50ZXMgZW1haWxzIGFiYWl4bzpcXG4nLFxuICAgICAgc2VuZE1haWxTdWNjZXNzOiAnRW1haWwgZW52aWFkbyBjb20gc3VjZXNzbyEnLFxuICAgICAgc2VuZE1haWxFcnJvcjogJ07Do28gZm9pIHBvc3PDrXZlbCBlbnZpYXIgbyBlbWFpbC4nLFxuICAgICAgcGFzc3dvcmRTZW5kaW5nU3VjY2VzczogJ08gcHJvY2Vzc28gZGUgcmVjdXBlcmHDp8OjbyBkZSBzZW5oYSBmb2kgaW5pY2lhZG8uIENhc28gbyBlbWFpbCBuw6NvIGNoZWd1ZSBlbSAxMCBtaW51dG9zIHRlbnRlIG5vdmFtZW50ZS4nXG4gICAgfSxcbiAgICB1c2VyOiB7XG4gICAgICByZW1vdmVZb3VyU2VsZkVycm9yOiAnVm9jw6ogbsOjbyBwb2RlIHJlbW92ZXIgc2V1IHByw7NwcmlvIHVzdcOhcmlvJyxcbiAgICAgIHVzZXJFeGlzdHM6ICdVc3XDoXJpbyBqw6EgYWRpY2lvbmFkbyEnLFxuICAgICAgcHJvZmlsZToge1xuICAgICAgICB1cGRhdGVFcnJvcjogJ07Do28gZm9pIHBvc3PDrXZlbCBhdHVhbGl6YXIgc2V1IHByb2ZpbGUnXG4gICAgICB9XG4gICAgfSxcbiAgICBxdWVyeURpbmFtaWM6IHtcbiAgICAgIG5vRmlsdGVyOiAnTmVuaHVtIGZpbHRybyBhZGljaW9uYWRvJ1xuICAgIH1cbiAgfSk7XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4vKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCwgbm8tdW5kZWY6IDAqL1xuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25zdGFudCgncHQtQlIuaTE4bi5tb2RlbHMnLCB7XG4gICAgdXNlcjogJ1VzdcOhcmlvJyxcbiAgICB0YXNrOiAnVGFyZWZhJyxcbiAgICBwcm9qZWN0OiAnUHJvamV0bydcbiAgfSk7XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4vKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCwgbm8tdW5kZWY6IDAqL1xuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25zdGFudCgncHQtQlIuaTE4bi52aWV3cycsIHtcbiAgICBicmVhZGNydW1iczoge1xuICAgICAgdXNlcjogJ0FkbWluaXN0cmHDp8OjbyAtIFVzdcOhcmlvJyxcbiAgICAgICd1c2VyLXByb2ZpbGUnOiAnUGVyZmlsJyxcbiAgICAgIGRhc2hib2FyZDogJ0Rhc2hib2FyZCcsXG4gICAgICBhdWRpdDogJ0FkbWluaXN0cmHDp8OjbyAtIEF1ZGl0b3JpYScsXG4gICAgICBtYWlsOiAnQWRtaW5pc3RyYcOnw6NvIC0gRW52aW8gZGUgZS1tYWlsJyxcbiAgICAgIHByb2plY3RzOiAnUHJvamV0b3MnLFxuICAgICAgJ2RpbmFtaWMtcXVlcnknOiAnQWRtaW5pc3RyYcOnw6NvIC0gQ29uc3VsdGFzIERpbsOibWljYXMnLFxuICAgICAgJ25vdC1hdXRob3JpemVkJzogJ0FjZXNzbyBOZWdhZG8nLFxuICAgICAgdGFza3M6ICdUYXJlZmFzJyxcbiAgICAgIG1pbGVzdG9uZXM6ICdTcHJpbnRzJyxcbiAgICAgIGthbmJhbjogJ0thbmJhbiBCb2FyZCcsXG4gICAgICB2Y3M6ICdDb250cm9sZSBkZSBWZXJzw6NvJyxcbiAgICAgIHJlbGVhc2VzOiAnUmVsZWFzZXMnXG4gICAgfSxcbiAgICB0aXRsZXM6IHtcbiAgICAgIGRhc2hib2FyZDogJ0Rhc2hib2FyZCcsXG4gICAgICBtYWlsU2VuZDogJ0VudmlhciBlLW1haWwnLFxuICAgICAgdGFza0xpc3Q6ICdMaXN0YSBkZSBUYXJlZmFzJyxcbiAgICAgIHVzZXJMaXN0OiAnTGlzdGEgZGUgVXN1w6FyaW9zJyxcbiAgICAgIGF1ZGl0TGlzdDogJ0xpc3RhIGRlIExvZ3MnLFxuICAgICAgcmVnaXN0ZXI6ICdGb3JtdWzDoXJpbyBkZSBDYWRhc3RybycsXG4gICAgICByZXNldFBhc3N3b3JkOiAnUmVkZWZpbmlyIFNlbmhhJyxcbiAgICAgIHVwZGF0ZTogJ0Zvcm11bMOhcmlvIGRlIEF0dWFsaXphw6fDo28nLFxuICAgICAgdGFza3M6ICdUYXJlZmFzJyxcbiAgICAgIG1pbGVzdG9uZXM6ICdTcHJpbnRzJyxcbiAgICAgIGthbmJhbjogJ0thbmJhbiBCb2FyZCcsXG4gICAgICB2Y3M6ICdDb250cm9sZSBkZSBWZXJzw6NvJyxcbiAgICAgIHJlbGVhc2VzOiAnUmVsZWFzZXMnXG4gICAgfSxcbiAgICBhY3Rpb25zOiB7XG4gICAgICBzZW5kOiAnRW52aWFyJyxcbiAgICAgIHNhdmU6ICdTYWx2YXInLFxuICAgICAgY2xlYXI6ICdMaW1wYXInLFxuICAgICAgY2xlYXJBbGw6ICdMaW1wYXIgVHVkbycsXG4gICAgICByZXN0YXJ0OiAnUmVpbmljaWFyJyxcbiAgICAgIGZpbHRlcjogJ0ZpbHRyYXInLFxuICAgICAgc2VhcmNoOiAnUGVzcXVpc2FyJyxcbiAgICAgIGxpc3Q6ICdMaXN0YXInLFxuICAgICAgZWRpdDogJ0VkaXRhcicsXG4gICAgICBjYW5jZWw6ICdDYW5jZWxhcicsXG4gICAgICB1cGRhdGU6ICdBdHVhbGl6YXInLFxuICAgICAgcmVtb3ZlOiAnUmVtb3ZlcicsXG4gICAgICBnZXRPdXQ6ICdTYWlyJyxcbiAgICAgIGFkZDogJ0FkaWNpb25hcicsXG4gICAgICBpbjogJ0VudHJhcicsXG4gICAgICBsb2FkSW1hZ2U6ICdDYXJyZWdhciBJbWFnZW0nLFxuICAgICAgc2lnbnVwOiAnQ2FkYXN0cmFyJyxcbiAgICAgIGNyaWFyUHJvamV0bzogJ0NyaWFyIFByb2pldG8nLFxuICAgICAgcHJvamVjdExpc3Q6ICdMaXN0YSBkZSBQcm9qZXRvcycsXG4gICAgICB0YXNrc0xpc3Q6ICdMaXN0YSBkZSBUYXJlZmFzJyxcbiAgICAgIG1pbGVzdG9uZXNMaXN0OiAnTGlzdGEgZGUgU3ByaW50cycsXG4gICAgICBmaW5hbGl6ZTogJ0ZpbmFsaXphcicsXG4gICAgICByZXBseTogJ1Jlc3BvbmRlcidcbiAgICB9LFxuICAgIGZpZWxkczoge1xuICAgICAgZGF0ZTogJ0RhdGEnLFxuICAgICAgYWN0aW9uOiAnQcOnw6NvJyxcbiAgICAgIGFjdGlvbnM6ICdBw6fDtWVzJyxcbiAgICAgIGF1ZGl0OiB7XG4gICAgICAgIGRhdGVTdGFydDogJ0RhdGEgSW5pY2lhbCcsXG4gICAgICAgIGRhdGVFbmQ6ICdEYXRhIEZpbmFsJyxcbiAgICAgICAgcmVzb3VyY2U6ICdSZWN1cnNvJyxcbiAgICAgICAgYWxsUmVzb3VyY2VzOiAnVG9kb3MgUmVjdXJzb3MnLFxuICAgICAgICB0eXBlOiB7XG4gICAgICAgICAgY3JlYXRlZDogJ0NhZGFzdHJhZG8nLFxuICAgICAgICAgIHVwZGF0ZWQ6ICdBdHVhbGl6YWRvJyxcbiAgICAgICAgICBkZWxldGVkOiAnUmVtb3ZpZG8nXG4gICAgICAgIH1cbiAgICAgIH0sXG4gICAgICBsb2dpbjoge1xuICAgICAgICByZXNldFBhc3N3b3JkOiAnRXNxdWVjaSBtaW5oYSBzZW5oYScsXG4gICAgICAgIGNvbmZpcm1QYXNzd29yZDogJ0NvbmZpcm1hciBzZW5oYSdcbiAgICAgIH0sXG4gICAgICBtYWlsOiB7XG4gICAgICAgIHRvOiAnUGFyYScsXG4gICAgICAgIHN1YmplY3Q6ICdBc3N1bnRvJyxcbiAgICAgICAgbWVzc2FnZTogJ01lbnNhZ2VtJ1xuICAgICAgfSxcbiAgICAgIHF1ZXJ5RGluYW1pYzoge1xuICAgICAgICBmaWx0ZXJzOiAnRmlsdHJvcycsXG4gICAgICAgIHJlc3VsdHM6ICdSZXN1bHRhZG9zJyxcbiAgICAgICAgbW9kZWw6ICdNb2RlbCcsXG4gICAgICAgIGF0dHJpYnV0ZTogJ0F0cmlidXRvJyxcbiAgICAgICAgb3BlcmF0b3I6ICdPcGVyYWRvcicsXG4gICAgICAgIHJlc291cmNlOiAnUmVjdXJzbycsXG4gICAgICAgIHZhbHVlOiAnVmFsb3InLFxuICAgICAgICBvcGVyYXRvcnM6IHtcbiAgICAgICAgICBlcXVhbHM6ICdJZ3VhbCcsXG4gICAgICAgICAgZGlmZXJlbnQ6ICdEaWZlcmVudGUnLFxuICAgICAgICAgIGNvbnRlaW5zOiAnQ29udMOpbScsXG4gICAgICAgICAgc3RhcnRXaXRoOiAnSW5pY2lhIGNvbScsXG4gICAgICAgICAgZmluaXNoV2l0aDogJ0ZpbmFsaXphIGNvbScsXG4gICAgICAgICAgYmlnZ2VyVGhhbjogJ01haW9yJyxcbiAgICAgICAgICBlcXVhbHNPckJpZ2dlclRoYW46ICdNYWlvciBvdSBJZ3VhbCcsXG4gICAgICAgICAgbGVzc1RoYW46ICdNZW5vcicsXG4gICAgICAgICAgZXF1YWxzT3JMZXNzVGhhbjogJ01lbm9yIG91IElndWFsJ1xuICAgICAgICB9XG4gICAgICB9LFxuICAgICAgcHJvamVjdDoge1xuICAgICAgICBuYW1lOiAnTm9tZScsXG4gICAgICAgIHRvdGFsVGFzazogJ1RvdGFsIGRlIFRhcmVmYXMnXG4gICAgICB9LFxuICAgICAgdGFzazoge1xuICAgICAgICBkb25lOiAnTsOjbyBGZWl0byAvIEZlaXRvJ1xuICAgICAgfSxcbiAgICAgIHVzZXI6IHtcbiAgICAgICAgcGVyZmlsczogJ1BlcmZpcycsXG4gICAgICAgIG5hbWVPckVtYWlsOiAnTm9tZSBvdSBFbWFpbCdcbiAgICAgIH1cbiAgICB9LFxuICAgIGxheW91dDoge1xuICAgICAgbWVudToge1xuICAgICAgICBwcm9qZWN0czogJ1Byb2pldG9zJyxcbiAgICAgICAgZGFzaGJvYXJkOiAnRGFzaGJvYXJkJyxcbiAgICAgICAgbWlsZXN0b25lczogJ1NwcmludHMnLFxuICAgICAgICB0YXNrczogJ1RhcmVmYXMnLFxuICAgICAgICBrYW5iYW46ICdLYW5iYW4nLFxuICAgICAgICB2Y3M6ICdDb250cm9sZSBkZSBWZXJzw6NvJyxcbiAgICAgICAgcmVsZWFzZXM6ICdSZWxlYXNlcydcbiAgICAgIH1cbiAgICB9LFxuICAgIHRvb2x0aXBzOiB7XG4gICAgICBhdWRpdDoge1xuICAgICAgICB2aWV3RGV0YWlsOiAnVmlzdWFsaXphciBEZXRhbGhhbWVudG8nXG4gICAgICB9LFxuICAgICAgdXNlcjoge1xuICAgICAgICBwZXJmaWw6ICdQZXJmaWwnLFxuICAgICAgICB0cmFuc2ZlcjogJ1RyYW5zZmVyaXInXG4gICAgICB9LFxuICAgICAgdGFzazoge1xuICAgICAgICBsaXN0VGFzazogJ0xpc3RhciBUYXJlZmFzJ1xuICAgICAgfVxuICAgIH1cbiAgfSk7XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29udHJvbGxlcignVGFza0luZm9Db250cm9sbGVyJywgVGFza0luZm9Db250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIFRhc2tJbmZvQ29udHJvbGxlcigkY29udHJvbGxlciwgVGFza3NTZXJ2aWNlLCBsb2NhbHMpIHtcbiAgICAvL0F0dHJpYnV0ZXMgQmxvY2tcbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0uY2xvc2VEaWFsb2cgPSBjbG9zZURpYWxvZztcblxuICAgIHZtLm9uQWN0aXZhdGUgPSBmdW5jdGlvbiAoKSB7XG4gICAgICB2bS50YXNrID0gbG9jYWxzLnRhc2s7XG4gICAgICB2bS50YXNrLmVzdGltYXRlZF90aW1lID0gdm0udGFzay5lc3RpbWF0ZWRfdGltZS50b1N0cmluZygpICsgJyBob3Jhcyc7XG4gICAgfTtcblxuICAgIGZ1bmN0aW9uIGNsb3NlRGlhbG9nKCkge1xuICAgICAgdm0uY2xvc2UoKTtcbiAgICAgIGNvbnNvbGUubG9nKFwiZmVjaGFyXCIpO1xuICAgIH1cblxuICAgIC8vIGluc3RhbnRpYXRlIGJhc2UgY29udHJvbGxlclxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHsgdm06IHZtLCBtb2RlbFNlcnZpY2U6IFRhc2tzU2VydmljZSwgb3B0aW9uczoge30gfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb250cm9sbGVyKCdVc2Vyc0RpYWxvZ0NvbnRyb2xsZXInLCBVc2Vyc0RpYWxvZ0NvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gVXNlcnNEaWFsb2dDb250cm9sbGVyKCRjb250cm9sbGVyLCBVc2Vyc1NlcnZpY2UsIFByRGlhbG9nLCAvLyBOT1NPTkFSXG4gIHVzZXJEaWFsb2dJbnB1dCwgb25Jbml0KSB7XG5cbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0ub25BY3RpdmF0ZSA9IG9uQWN0aXZhdGU7XG4gICAgdm0uYXBwbHlGaWx0ZXJzID0gYXBwbHlGaWx0ZXJzO1xuICAgIHZtLmNsb3NlID0gY2xvc2U7XG5cbiAgICBpZiAoYW5ndWxhci5pc0RlZmluZWQodXNlckRpYWxvZ0lucHV0KSkge1xuICAgICAgdm0udHJhbnNmZXJVc2VyID0gdXNlckRpYWxvZ0lucHV0LnRyYW5zZmVyVXNlckZuO1xuICAgIH1cblxuICAgIC8vIGluc3RhbnRpYXRlIGJhc2UgY29udHJvbGxlclxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHtcbiAgICAgIHZtOiB2bSxcbiAgICAgIG1vZGVsU2VydmljZTogVXNlcnNTZXJ2aWNlLFxuICAgICAgc2VhcmNoT25Jbml0OiBvbkluaXQsXG4gICAgICBvcHRpb25zOiB7XG4gICAgICAgIHBlclBhZ2U6IDVcbiAgICAgIH1cbiAgICB9KTtcblxuICAgIGZ1bmN0aW9uIG9uQWN0aXZhdGUoKSB7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMgPSB7fTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBhcHBseUZpbHRlcnMoKSB7XG4gICAgICByZXR1cm4gYW5ndWxhci5leHRlbmQodm0uZGVmYXVsdFF1ZXJ5RmlsdGVycywgdm0ucXVlcnlGaWx0ZXJzKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBjbG9zZSgpIHtcbiAgICAgIFByRGlhbG9nLmNsb3NlKCk7XG4gICAgfVxuICB9XG59KSgpOyIsIi8qZXNsaW50IGFuZ3VsYXIvZmlsZS1uYW1lOiAwKi9cbihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnLCBbXG4gICAgJ25nQW5pbWF0ZScsXG4gICAgJ25nQXJpYScsXG4gICAgJ3VpLnJvdXRlcicsXG4gICAgJ25nUHJvZGViJyxcbiAgICAndWkudXRpbHMubWFza3MnLFxuICAgICd0ZXh0LW1hc2snLFxuICAgICduZ01hdGVyaWFsJyxcbiAgICAnbW9kZWxGYWN0b3J5JyxcbiAgICAnbWQuZGF0YS50YWJsZScsXG4gICAgJ25nTWF0ZXJpYWxEYXRlUGlja2VyJyxcbiAgICAncGFzY2FscHJlY2h0LnRyYW5zbGF0ZScsXG4gICAgJ2FuZ3VsYXJGaWxlVXBsb2FkJyxcbiAgICAnbmdNZXNzYWdlcycsXG4gICAgJ2pxd2lkZ2V0cycsXG4gICAgJ3VpLm1hc2snLFxuICAgICduZ1JvdXRlJyxcbiAgICAnbmdTYW5pdGl6ZSddKTtcbn0pKCk7XG4iLCIoZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbmZpZyhjb25maWcpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gY29uZmlnKEdsb2JhbCwgJG1kVGhlbWluZ1Byb3ZpZGVyLCAkbW9kZWxGYWN0b3J5UHJvdmlkZXIsICAvLyBOT1NPTkFSXG4gICAgJHRyYW5zbGF0ZVByb3ZpZGVyLCBtb21lbnQsICRtZEFyaWFQcm92aWRlciwgJG1kRGF0ZUxvY2FsZVByb3ZpZGVyKSB7XG5cbiAgICAkdHJhbnNsYXRlUHJvdmlkZXJcbiAgICAgIC51c2VMb2FkZXIoJ2xhbmd1YWdlTG9hZGVyJylcbiAgICAgIC51c2VTYW5pdGl6ZVZhbHVlU3RyYXRlZ3koJ2VzY2FwZScpO1xuXG4gICAgJHRyYW5zbGF0ZVByb3ZpZGVyLnVzZVBvc3RDb21waWxpbmcodHJ1ZSk7XG5cbiAgICBtb21lbnQubG9jYWxlKCdwdC1CUicpO1xuXG4gICAgLy9vcyBzZXJ2acOnb3MgcmVmZXJlbnRlIGFvcyBtb2RlbHMgdmFpIHV0aWxpemFyIGNvbW8gYmFzZSBuYXMgdXJsc1xuICAgICRtb2RlbEZhY3RvcnlQcm92aWRlci5kZWZhdWx0T3B0aW9ucy5wcmVmaXggPSBHbG9iYWwuYXBpUGF0aDtcblxuICAgIC8vIENvbmZpZ3VyYXRpb24gdGhlbWVcbiAgICAkbWRUaGVtaW5nUHJvdmlkZXIudGhlbWUoJ2RlZmF1bHQnKVxuICAgICAgLnByaW1hcnlQYWxldHRlKCdncmV5Jywge1xuICAgICAgICBkZWZhdWx0OiAnODAwJ1xuICAgICAgfSlcbiAgICAgIC5hY2NlbnRQYWxldHRlKCdhbWJlcicpXG4gICAgICAud2FyblBhbGV0dGUoJ2RlZXAtb3JhbmdlJyk7XG5cbiAgICAvLyBFbmFibGUgYnJvd3NlciBjb2xvclxuICAgICRtZFRoZW1pbmdQcm92aWRlci5lbmFibGVCcm93c2VyQ29sb3IoKTtcblxuICAgICRtZEFyaWFQcm92aWRlci5kaXNhYmxlV2FybmluZ3MoKTtcblxuICAgICRtZERhdGVMb2NhbGVQcm92aWRlci5mb3JtYXREYXRlID0gZnVuY3Rpb24oZGF0ZSkge1xuICAgICAgcmV0dXJuIGRhdGUgPyBtb21lbnQoZGF0ZSkuZm9ybWF0KCdERC9NTS9ZWVlZJykgOiAnJztcbiAgICB9O1xuICB9XG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29udHJvbGxlcignQXBwQ29udHJvbGxlcicsIEFwcENvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLyoqXG4gICAqIENvbnRyb2xhZG9yIHJlc3BvbnPDoXZlbCBwb3IgZnVuY2lvbmFsaWRhZGVzIHF1ZSBzw6NvIGFjaW9uYWRhcyBlbSBxdWFscXVlciB0ZWxhIGRvIHNpc3RlbWFcbiAgICpcbiAgICovXG4gIGZ1bmN0aW9uIEFwcENvbnRyb2xsZXIoJHN0YXRlLCBBdXRoLCBHbG9iYWwpIHtcbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgLy9hbm8gYXR1YWwgcGFyYSBzZXIgZXhpYmlkbyBubyByb2RhcMOpIGRvIHNpc3RlbWFcbiAgICB2bS5hbm9BdHVhbCA9IG51bGw7XG4gICAgdm0uYWN0aXZlUHJvamVjdCA9IG51bGw7XG5cbiAgICB2bS5sb2dvdXQgICAgID0gbG9nb3V0O1xuICAgIHZtLmdldEltYWdlUGVyZmlsID0gZ2V0SW1hZ2VQZXJmaWw7XG4gICAgdm0uZ2V0TG9nb01lbnUgPSBnZXRMb2dvTWVudTtcbiAgICB2bS5zZXRBY3RpdmVQcm9qZWN0ID0gc2V0QWN0aXZlUHJvamVjdDtcbiAgICB2bS5nZXRBY3RpdmVQcm9qZWN0ID0gZ2V0QWN0aXZlUHJvamVjdDtcbiAgICB2bS5yZW1vdmVBY3RpdmVQcm9qZWN0ID0gcmVtb3ZlQWN0aXZlUHJvamVjdDtcblxuICAgIGFjdGl2YXRlKCk7XG5cbiAgICBmdW5jdGlvbiBhY3RpdmF0ZSgpIHtcbiAgICAgIHZhciBkYXRlID0gbmV3IERhdGUoKTtcblxuICAgICAgdm0uYW5vQXR1YWwgPSBkYXRlLmdldEZ1bGxZZWFyKCk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gbG9nb3V0KCkge1xuICAgICAgQXV0aC5sb2dvdXQoKS50aGVuKGZ1bmN0aW9uKCkge1xuICAgICAgICAkc3RhdGUuZ28oR2xvYmFsLmxvZ2luU3RhdGUpO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gZ2V0SW1hZ2VQZXJmaWwoKSB7XG4gICAgICByZXR1cm4gKEF1dGguY3VycmVudFVzZXIgJiYgQXV0aC5jdXJyZW50VXNlci5pbWFnZSlcbiAgICAgICAgPyBBdXRoLmN1cnJlbnRVc2VyLmltYWdlXG4gICAgICAgIDogR2xvYmFsLmltYWdlUGF0aCArICcvbm9fYXZhdGFyLmdpZic7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gZ2V0TG9nb01lbnUoKSB7XG4gICAgICByZXR1cm4gR2xvYmFsLmltYWdlUGF0aCArICcvbG9nby12ZXJ0aWNhbC5wbmcnO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIHNldEFjdGl2ZVByb2plY3QocHJvamVjdCkge1xuICAgICAgbG9jYWxTdG9yYWdlLnNldEl0ZW0oJ3Byb2plY3QnLCBwcm9qZWN0KTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBnZXRBY3RpdmVQcm9qZWN0KCkge1xuICAgICAgcmV0dXJuIGxvY2FsU3RvcmFnZS5nZXRJdGVtKCdwcm9qZWN0Jyk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gcmVtb3ZlQWN0aXZlUHJvamVjdCgpIHtcbiAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKCdwcm9qZWN0Jyk7XG4gICAgfVxuXG4gIH1cblxufSkoKTtcbiIsIi8qZXNsaW50IGFuZ3VsYXIvZmlsZS1uYW1lOiAwLCBuby11bmRlZjogMCovXG4oZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICAvKipcbiAgICogVHJhbnNmb3JtYSBiaWJsaW90ZWNhcyBleHRlcm5hcyBlbSBzZXJ2acOnb3MgZG8gYW5ndWxhciBwYXJhIHNlciBwb3Nzw612ZWwgdXRpbGl6YXJcbiAgICogYXRyYXbDqXMgZGEgaW5qZcOnw6NvIGRlIGRlcGVuZMOqbmNpYVxuICAgKi9cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnN0YW50KCdsb2Rhc2gnLCBfKVxuICAgIC5jb25zdGFudCgnbW9tZW50JywgbW9tZW50KTtcblxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb25zdGFudCgnR2xvYmFsJywge1xuICAgICAgYXBwTmFtZTogJ0ZyZWVsYWdpbGUnLFxuICAgICAgaG9tZVN0YXRlOiAnYXBwLnByb2plY3RzJyxcbiAgICAgIGxvZ2luVXJsOiAnYXBwL2xvZ2luJyxcbiAgICAgIHJlc2V0UGFzc3dvcmRVcmw6ICdhcHAvcGFzc3dvcmQvcmVzZXQnLFxuICAgICAgbG9naW5TdGF0ZTogJ2FwcC5sb2dpbicsXG4gICAgICByZXNldFBhc3N3b3JkU3RhdGU6ICdhcHAucGFzc3dvcmQtcmVzZXQnLFxuICAgICAgbm90QXV0aG9yaXplZFN0YXRlOiAnYXBwLm5vdC1hdXRob3JpemVkJyxcbiAgICAgIHRva2VuS2V5OiAnc2VydmVyX3Rva2VuJyxcbiAgICAgIGNsaWVudFBhdGg6ICdjbGllbnQvYXBwJyxcbiAgICAgIGFwaVBhdGg6ICdhcGkvdjEnLFxuICAgICAgaW1hZ2VQYXRoOiAnY2xpZW50L2ltYWdlcydcbiAgICB9KTtcbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsICR1cmxSb3V0ZXJQcm92aWRlciwgR2xvYmFsKSB7XG4gICAgJHN0YXRlUHJvdmlkZXJcbiAgICAgIC5zdGF0ZSgnYXBwJywge1xuICAgICAgICB1cmw6ICcvYXBwJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9sYXlvdXQvYXBwLmh0bWwnLFxuICAgICAgICBhYnN0cmFjdDogdHJ1ZSxcbiAgICAgICAgcmVzb2x2ZTogeyAvL2Vuc3VyZSBsYW5ncyBpcyByZWFkeSBiZWZvcmUgcmVuZGVyIHZpZXdcbiAgICAgICAgICB0cmFuc2xhdGVSZWFkeTogWyckdHJhbnNsYXRlJywgJyRxJywgZnVuY3Rpb24oJHRyYW5zbGF0ZSwgJHEpIHtcbiAgICAgICAgICAgIHZhciBkZWZlcnJlZCA9ICRxLmRlZmVyKCk7XG5cbiAgICAgICAgICAgICR0cmFuc2xhdGUudXNlKCdwdC1CUicpLnRoZW4oZnVuY3Rpb24oKSB7XG4gICAgICAgICAgICAgIGRlZmVycmVkLnJlc29sdmUoKTtcbiAgICAgICAgICAgIH0pO1xuXG4gICAgICAgICAgICByZXR1cm4gZGVmZXJyZWQucHJvbWlzZTtcbiAgICAgICAgICB9XVxuICAgICAgICB9XG4gICAgICB9KVxuICAgICAgLnN0YXRlKEdsb2JhbC5ub3RBdXRob3JpemVkU3RhdGUsIHtcbiAgICAgICAgdXJsOiAnL2FjZXNzby1uZWdhZG8nLFxuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL2xheW91dC9ub3QtYXV0aG9yaXplZC5odG1sJyxcbiAgICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IGZhbHNlIH1cbiAgICAgIH0pO1xuXG4gICAgJHVybFJvdXRlclByb3ZpZGVyLndoZW4oJy9wYXNzd29yZC9yZXNldCcsIEdsb2JhbC5yZXNldFBhc3N3b3JkVXJsKTtcbiAgICAkdXJsUm91dGVyUHJvdmlkZXIud2hlbignL2FwcCcsIEdsb2JhbC5sb2dpblVybCk7XG4gICAgJHVybFJvdXRlclByb3ZpZGVyLm90aGVyd2lzZShHbG9iYWwubG9naW5VcmwpO1xuICB9XG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLnJ1bihydW4pO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gcnVuKCRyb290U2NvcGUsICRzdGF0ZSwgJHN0YXRlUGFyYW1zLCBBdXRoLCBHbG9iYWwpIHsgLy8gTk9TT05BUlxuICAgIC8vc2V0YWRvIG5vIHJvb3RTY29wZSBwYXJhIHBvZGVyIHNlciBhY2Vzc2FkbyBuYXMgdmlld3Mgc2VtIHByZWZpeG8gZGUgY29udHJvbGxlclxuICAgICRyb290U2NvcGUuJHN0YXRlID0gJHN0YXRlO1xuICAgICRyb290U2NvcGUuJHN0YXRlUGFyYW1zID0gJHN0YXRlUGFyYW1zO1xuICAgICRyb290U2NvcGUuYXV0aCA9IEF1dGg7XG4gICAgJHJvb3RTY29wZS5nbG9iYWwgPSBHbG9iYWw7XG5cbiAgICAvL25vIGluaWNpbyBjYXJyZWdhIG8gdXN1w6FyaW8gZG8gbG9jYWxzdG9yYWdlIGNhc28gbyB1c3XDoXJpbyBlc3RhamEgYWJyaW5kbyBvIG5hdmVnYWRvclxuICAgIC8vcGFyYSB2b2x0YXIgYXV0ZW50aWNhZG9cbiAgICBBdXRoLnJldHJpZXZlVXNlckZyb21Mb2NhbFN0b3JhZ2UoKTtcbiAgfVxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnRyb2xsZXIoJ0F1ZGl0Q29udHJvbGxlcicsIEF1ZGl0Q29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBBdWRpdENvbnRyb2xsZXIoJGNvbnRyb2xsZXIsIEF1ZGl0U2VydmljZSwgUHJEaWFsb2csIEdsb2JhbCwgJHRyYW5zbGF0ZSkgeyAvLyBOT1NPTkFSXG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIHZtLm9uQWN0aXZhdGUgPSBvbkFjdGl2YXRlO1xuICAgIHZtLmFwcGx5RmlsdGVycyA9IGFwcGx5RmlsdGVycztcbiAgICB2bS52aWV3RGV0YWlsID0gdmlld0RldGFpbDtcblxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHsgdm06IHZtLCBtb2RlbFNlcnZpY2U6IEF1ZGl0U2VydmljZSwgb3B0aW9uczoge30gfSk7XG5cbiAgICBmdW5jdGlvbiBvbkFjdGl2YXRlKCkge1xuICAgICAgdm0ubW9kZWxzID0gW107XG4gICAgICB2bS5xdWVyeUZpbHRlcnMgPSB7fTtcblxuICAgICAgLy9QZWdhIHRvZG9zIG9zIG1vZGVscyBkbyBzZXJ2ZXIgZSBtb250YSB1bWEgbGlzdGEgcHJvIENvbWJvQm94XG4gICAgICBBdWRpdFNlcnZpY2UuZ2V0QXVkaXRlZE1vZGVscygpLnRoZW4oZnVuY3Rpb24oZGF0YSkge1xuICAgICAgICB2YXIgbW9kZWxzID0gW3sgaWQ6ICcnLCBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KCdnbG9iYWwuYWxsJykgfV07XG5cbiAgICAgICAgZGF0YS5tb2RlbHMuc29ydCgpO1xuXG4gICAgICAgIGZvciAodmFyIGluZGV4ID0gMDsgaW5kZXggPCBkYXRhLm1vZGVscy5sZW5ndGg7IGluZGV4KyspIHtcbiAgICAgICAgICB2YXIgbW9kZWwgPSBkYXRhLm1vZGVsc1tpbmRleF07XG5cbiAgICAgICAgICBtb2RlbHMucHVzaCh7XG4gICAgICAgICAgICBpZDogbW9kZWwsXG4gICAgICAgICAgICBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KCdtb2RlbHMuJyArIG1vZGVsLnRvTG93ZXJDYXNlKCkpXG4gICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICB2bS5tb2RlbHMgPSBtb2RlbHM7XG4gICAgICAgIHZtLnF1ZXJ5RmlsdGVycy5tb2RlbCA9IHZtLm1vZGVsc1swXS5pZDtcbiAgICAgIH0pO1xuXG4gICAgICB2bS50eXBlcyA9IEF1ZGl0U2VydmljZS5saXN0VHlwZXMoKTtcbiAgICAgIHZtLnF1ZXJ5RmlsdGVycy50eXBlID0gdm0udHlwZXNbMF0uaWQ7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gYXBwbHlGaWx0ZXJzKGRlZmF1bHRRdWVyeUZpbHRlcnMpIHtcbiAgICAgIHJldHVybiBhbmd1bGFyLmV4dGVuZChkZWZhdWx0UXVlcnlGaWx0ZXJzLCB2bS5xdWVyeUZpbHRlcnMpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIHZpZXdEZXRhaWwoYXVkaXREZXRhaWwpIHtcbiAgICAgIHZhciBjb25maWcgPSB7XG4gICAgICAgIGxvY2FsczogeyBhdWRpdERldGFpbDogYXVkaXREZXRhaWwgfSxcbiAgICAgICAgLyoqIEBuZ0luamVjdCAqL1xuICAgICAgICBjb250cm9sbGVyOiBmdW5jdGlvbihhdWRpdERldGFpbCwgUHJEaWFsb2cpIHtcbiAgICAgICAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgICAgICAgdm0uY2xvc2UgPSBjbG9zZTtcblxuICAgICAgICAgIGFjdGl2YXRlKCk7XG5cbiAgICAgICAgICBmdW5jdGlvbiBhY3RpdmF0ZSgpIHtcbiAgICAgICAgICAgIGlmIChhbmd1bGFyLmlzQXJyYXkoYXVkaXREZXRhaWwub2xkKSAmJiBhdWRpdERldGFpbC5vbGQubGVuZ3RoID09PSAwKSBhdWRpdERldGFpbC5vbGQgPSBudWxsO1xuICAgICAgICAgICAgaWYgKGFuZ3VsYXIuaXNBcnJheShhdWRpdERldGFpbC5uZXcpICYmIGF1ZGl0RGV0YWlsLm5ldy5sZW5ndGggPT09IDApIGF1ZGl0RGV0YWlsLm5ldyA9IG51bGw7XG5cbiAgICAgICAgICAgIHZtLmF1ZGl0RGV0YWlsID0gYXVkaXREZXRhaWw7XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgZnVuY3Rpb24gY2xvc2UoKSB7XG4gICAgICAgICAgICBQckRpYWxvZy5jbG9zZSgpO1xuICAgICAgICAgIH1cblxuICAgICAgICB9LFxuICAgICAgICBjb250cm9sbGVyQXM6ICdhdWRpdERldGFpbEN0cmwnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL2F1ZGl0L2F1ZGl0LWRldGFpbC5odG1sJyxcbiAgICAgICAgaGFzQmFja2Ryb3A6IHRydWVcbiAgICAgIH07XG5cbiAgICAgIFByRGlhbG9nLmN1c3RvbShjb25maWcpO1xuICAgIH1cblxuICB9XG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqXG4gICAqIEFycXVpdm8gZGUgY29uZmlndXJhw6fDo28gY29tIGFzIHJvdGFzIGVzcGVjw61maWNhcyBkZSBhdWRpdG9yaWFcbiAgICpcbiAgICogQHBhcmFtIHthbnl9ICRzdGF0ZVByb3ZpZGVyXG4gICAqIEBwYXJhbSB7YW55fSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlclxuICAgICAgLnN0YXRlKCdhcHAuYXVkaXQnLCB7XG4gICAgICAgIHVybDogJy9hdWRpdG9yaWEnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL2F1ZGl0L2F1ZGl0Lmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnQXVkaXRDb250cm9sbGVyIGFzIGF1ZGl0Q3RybCcsXG4gICAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiB0cnVlLCBuZWVkUHJvZmlsZTogWydhZG1pbiddIH1cbiAgICAgIH0pO1xuXG4gIH1cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmFjdG9yeSgnQXVkaXRTZXJ2aWNlJywgQXVkaXRTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIEF1ZGl0U2VydmljZShzZXJ2aWNlRmFjdG9yeSwgJHRyYW5zbGF0ZSkge1xuICAgIHJldHVybiBzZXJ2aWNlRmFjdG9yeSgnYXVkaXQnLCB7XG4gICAgICBhY3Rpb25zOiB7XG4gICAgICAgIGdldEF1ZGl0ZWRNb2RlbHM6IHtcbiAgICAgICAgICBtZXRob2Q6ICdHRVQnLFxuICAgICAgICAgIHVybDogJ21vZGVscydcbiAgICAgICAgfVxuICAgICAgfSxcbiAgICAgIGluc3RhbmNlOiB7XG4gICAgICB9LFxuICAgICAgbGlzdFR5cGVzOiBmdW5jdGlvbigpIHtcbiAgICAgICAgdmFyIGF1ZGl0UGF0aCA9ICd2aWV3cy5maWVsZHMuYXVkaXQuJztcblxuICAgICAgICByZXR1cm4gW1xuICAgICAgICAgIHsgaWQ6ICcnLCBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KGF1ZGl0UGF0aCArICdhbGxSZXNvdXJjZXMnKSB9LFxuICAgICAgICAgIHsgaWQ6ICdjcmVhdGVkJywgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudChhdWRpdFBhdGggKyAndHlwZS5jcmVhdGVkJykgfSxcbiAgICAgICAgICB7IGlkOiAndXBkYXRlZCcsIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoYXVkaXRQYXRoICsgJ3R5cGUudXBkYXRlZCcpIH0sXG4gICAgICAgICAgeyBpZDogJ2RlbGV0ZWQnLCBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KGF1ZGl0UGF0aCArICd0eXBlLmRlbGV0ZWQnKSB9XG4gICAgICAgIF07XG4gICAgICB9XG4gICAgfSk7XG4gIH1cblxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb25maWcocm91dGVzKTtcblxuICAvKipcbiAgICogQXJxdWl2byBkZSBjb25maWd1cmHDp8OjbyBjb20gYXMgcm90YXMgZXNwZWPDrWZpY2FzIGRvIHJlY3Vyc28gdXNlclxuICAgKlxuICAgKiBAcGFyYW0ge2FueX0gJHN0YXRlUHJvdmlkZXJcbiAgICogQHBhcmFtIHthbnl9IEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyXG4gICAgICAuc3RhdGUoR2xvYmFsLnJlc2V0UGFzc3dvcmRTdGF0ZSwge1xuICAgICAgICB1cmw6ICcvcGFzc3dvcmQvcmVzZXQvOnRva2VuJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9hdXRoL3Jlc2V0LXBhc3MtZm9ybS5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ1Bhc3N3b3JkQ29udHJvbGxlciBhcyBwYXNzQ3RybCcsXG4gICAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiBmYWxzZSB9XG4gICAgICB9KVxuICAgICAgLnN0YXRlKEdsb2JhbC5sb2dpblN0YXRlLCB7XG4gICAgICAgIHVybDogJy9sb2dpbicsXG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvYXV0aC9sb2dpbi5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ0xvZ2luQ29udHJvbGxlciBhcyBsb2dpbkN0cmwnLFxuICAgICAgICBkYXRhOiB7IG5lZWRBdXRoZW50aWNhdGlvbjogZmFsc2UgfVxuICAgICAgfSk7XG5cbiAgfVxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5mYWN0b3J5KCdBdXRoJywgQXV0aCk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBBdXRoKCRodHRwLCAkcSwgR2xvYmFsLCBVc2Vyc1NlcnZpY2UpIHsgLy8gTk9TT05BUlxuICAgIHZhciBhdXRoID0ge1xuICAgICAgbG9naW46IGxvZ2luLFxuICAgICAgbG9nb3V0OiBsb2dvdXQsXG4gICAgICB1cGRhdGVDdXJyZW50VXNlcjogdXBkYXRlQ3VycmVudFVzZXIsXG4gICAgICByZXRyaWV2ZVVzZXJGcm9tTG9jYWxTdG9yYWdlOiByZXRyaWV2ZVVzZXJGcm9tTG9jYWxTdG9yYWdlLFxuICAgICAgYXV0aGVudGljYXRlZDogYXV0aGVudGljYXRlZCxcbiAgICAgIHNlbmRFbWFpbFJlc2V0UGFzc3dvcmQ6IHNlbmRFbWFpbFJlc2V0UGFzc3dvcmQsXG4gICAgICByZW1vdGVWYWxpZGF0ZVRva2VuOiByZW1vdGVWYWxpZGF0ZVRva2VuLFxuICAgICAgZ2V0VG9rZW46IGdldFRva2VuLFxuICAgICAgc2V0VG9rZW46IHNldFRva2VuLFxuICAgICAgY2xlYXJUb2tlbjogY2xlYXJUb2tlbixcbiAgICAgIGN1cnJlbnRVc2VyOiBudWxsXG4gICAgfTtcblxuICAgIGZ1bmN0aW9uIGNsZWFyVG9rZW4oKSB7XG4gICAgICBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbShHbG9iYWwudG9rZW5LZXkpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIHNldFRva2VuKHRva2VuKSB7XG4gICAgICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbShHbG9iYWwudG9rZW5LZXksIHRva2VuKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBnZXRUb2tlbigpIHtcbiAgICAgIHJldHVybiBsb2NhbFN0b3JhZ2UuZ2V0SXRlbShHbG9iYWwudG9rZW5LZXkpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIHJlbW90ZVZhbGlkYXRlVG9rZW4oKSB7XG4gICAgICB2YXIgZGVmZXJyZWQgPSAkcS5kZWZlcigpO1xuXG4gICAgICBpZiAoYXV0aC5hdXRoZW50aWNhdGVkKCkpIHtcbiAgICAgICAgJGh0dHAuZ2V0KEdsb2JhbC5hcGlQYXRoICsgJy9hdXRoZW50aWNhdGUvY2hlY2snKVxuICAgICAgICAgIC50aGVuKGZ1bmN0aW9uKCkge1xuICAgICAgICAgICAgZGVmZXJyZWQucmVzb2x2ZSh0cnVlKTtcbiAgICAgICAgICB9LCBmdW5jdGlvbigpIHtcbiAgICAgICAgICAgIGF1dGgubG9nb3V0KCk7XG5cbiAgICAgICAgICAgIGRlZmVycmVkLnJlamVjdChmYWxzZSk7XG4gICAgICAgICAgfSk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBhdXRoLmxvZ291dCgpO1xuXG4gICAgICAgIGRlZmVycmVkLnJlamVjdChmYWxzZSk7XG4gICAgICB9XG5cbiAgICAgIHJldHVybiBkZWZlcnJlZC5wcm9taXNlO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFZlcmlmaWNhIHNlIG8gdXN1w6FyaW8gZXN0w6EgYXV0ZW50aWNhZG9cbiAgICAgKlxuICAgICAqIEByZXR1cm5zIHtib29sZWFufVxuICAgICAqL1xuICAgIGZ1bmN0aW9uIGF1dGhlbnRpY2F0ZWQoKSB7XG4gICAgICByZXR1cm4gYXV0aC5nZXRUb2tlbigpICE9PSBudWxsXG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVjdXBlcmEgbyB1c3XDoXJpbyBkbyBsb2NhbFN0b3JhZ2VcbiAgICAgKi9cbiAgICBmdW5jdGlvbiByZXRyaWV2ZVVzZXJGcm9tTG9jYWxTdG9yYWdlKCkge1xuICAgICAgdmFyIHVzZXIgPSBsb2NhbFN0b3JhZ2UuZ2V0SXRlbSgndXNlcicpO1xuXG4gICAgICBpZiAodXNlcikge1xuICAgICAgICBhdXRoLmN1cnJlbnRVc2VyID0gYW5ndWxhci5tZXJnZShuZXcgVXNlcnNTZXJ2aWNlKCksIGFuZ3VsYXIuZnJvbUpzb24odXNlcikpO1xuICAgICAgfVxuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEd1YXJkYSBvIHVzdcOhcmlvIG5vIGxvY2FsU3RvcmFnZSBwYXJhIGNhc28gbyB1c3XDoXJpbyBmZWNoZSBlIGFicmEgbyBuYXZlZ2Fkb3JcbiAgICAgKiBkZW50cm8gZG8gdGVtcG8gZGUgc2Vzc8OjbyBzZWphIHBvc3PDrXZlbCByZWN1cGVyYXIgbyB0b2tlbiBhdXRlbnRpY2Fkby5cbiAgICAgKlxuICAgICAqIE1hbnTDqW0gYSB2YXJpw6F2ZWwgYXV0aC5jdXJyZW50VXNlciBwYXJhIGZhY2lsaXRhciBvIGFjZXNzbyBhbyB1c3XDoXJpbyBsb2dhZG8gZW0gdG9kYSBhIGFwbGljYcOnw6NvXG4gICAgICpcbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSB1c2VyIFVzdcOhcmlvIGEgc2VyIGF0dWFsaXphZG8uIENhc28gc2VqYSBwYXNzYWRvIG51bGwgbGltcGFcbiAgICAgKiB0b2RhcyBhcyBpbmZvcm1hw6fDtWVzIGRvIHVzdcOhcmlvIGNvcnJlbnRlLlxuICAgICAqL1xuICAgIGZ1bmN0aW9uIHVwZGF0ZUN1cnJlbnRVc2VyKHVzZXIpIHtcbiAgICAgIHZhciBkZWZlcnJlZCA9ICRxLmRlZmVyKCk7XG5cbiAgICAgIGlmICh1c2VyKSB7XG4gICAgICAgIHVzZXIgPSBhbmd1bGFyLm1lcmdlKG5ldyBVc2Vyc1NlcnZpY2UoKSwgdXNlcik7XG5cbiAgICAgICAgdmFyIGpzb25Vc2VyID0gYW5ndWxhci50b0pzb24odXNlcik7XG5cbiAgICAgICAgbG9jYWxTdG9yYWdlLnNldEl0ZW0oJ3VzZXInLCBqc29uVXNlcik7XG4gICAgICAgIGF1dGguY3VycmVudFVzZXIgPSB1c2VyO1xuXG4gICAgICAgIGRlZmVycmVkLnJlc29sdmUodXNlcik7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbSgndXNlcicpO1xuICAgICAgICBhdXRoLmN1cnJlbnRVc2VyID0gbnVsbDtcbiAgICAgICAgYXV0aC5jbGVhclRva2VuKCk7XG5cbiAgICAgICAgZGVmZXJyZWQucmVqZWN0KCk7XG4gICAgICB9XG5cbiAgICAgIHJldHVybiBkZWZlcnJlZC5wcm9taXNlO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWxpemEgbyBsb2dpbiBkbyB1c3XDoXJpb1xuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IGNyZWRlbnRpYWxzIEVtYWlsIGUgU2VuaGEgZG8gdXN1w6FyaW9cbiAgICAgKiBAcmV0dXJucyB7cHJvbWlzZX0gVW1hIHByb21pc2UgY29tIG8gcmVzdWx0YWRvIGRvIGNoYW1hZGEgbm8gYmFja2VuZFxuICAgICAqL1xuICAgIGZ1bmN0aW9uIGxvZ2luKGNyZWRlbnRpYWxzKSB7XG4gICAgICB2YXIgZGVmZXJyZWQgPSAkcS5kZWZlcigpO1xuXG4gICAgICAkaHR0cC5wb3N0KEdsb2JhbC5hcGlQYXRoICsgJy9hdXRoZW50aWNhdGUnLCBjcmVkZW50aWFscylcbiAgICAgICAgLnRoZW4oZnVuY3Rpb24ocmVzcG9uc2UpIHtcbiAgICAgICAgICBhdXRoLnNldFRva2VuKHJlc3BvbnNlLmRhdGEudG9rZW4pO1xuXG4gICAgICAgICAgcmV0dXJuICRodHRwLmdldChHbG9iYWwuYXBpUGF0aCArICcvYXV0aGVudGljYXRlL3VzZXInKTtcbiAgICAgICAgfSlcbiAgICAgICAgLnRoZW4oZnVuY3Rpb24ocmVzcG9uc2UpIHtcbiAgICAgICAgICBhdXRoLnVwZGF0ZUN1cnJlbnRVc2VyKHJlc3BvbnNlLmRhdGEudXNlcik7XG5cbiAgICAgICAgICBkZWZlcnJlZC5yZXNvbHZlKCk7XG4gICAgICAgIH0sIGZ1bmN0aW9uKGVycm9yKSB7XG4gICAgICAgICAgYXV0aC5sb2dvdXQoKTtcblxuICAgICAgICAgIGRlZmVycmVkLnJlamVjdChlcnJvcik7XG4gICAgICAgIH0pO1xuXG4gICAgICByZXR1cm4gZGVmZXJyZWQucHJvbWlzZTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBEZXNsb2dhIG9zIHVzdcOhcmlvcy4gQ29tbyBuw6NvIHRlbiBuZW5odW1hIGluZm9ybWHDp8OjbyBuYSBzZXNzw6NvIGRvIHNlcnZpZG9yXG4gICAgICogZSB1bSB0b2tlbiB1bWEgdmV6IGdlcmFkbyBuw6NvIHBvZGUsIHBvciBwYWRyw6NvLCBzZXIgaW52YWxpZGFkbyBhbnRlcyBkbyBzZXUgdGVtcG8gZGUgZXhwaXJhw6fDo28sXG4gICAgICogc29tZW50ZSBhcGFnYW1vcyBvcyBkYWRvcyBkbyB1c3XDoXJpbyBlIG8gdG9rZW4gZG8gbmF2ZWdhZG9yIHBhcmEgZWZldGl2YXIgbyBsb2dvdXQuXG4gICAgICpcbiAgICAgKiBAcmV0dXJucyB7cHJvbWlzZX0gVW1hIHByb21pc2UgY29tIG8gcmVzdWx0YWRvIGRhIG9wZXJhw6fDo29cbiAgICAgKi9cbiAgICBmdW5jdGlvbiBsb2dvdXQoKSB7XG4gICAgICB2YXIgZGVmZXJyZWQgPSAkcS5kZWZlcigpO1xuXG4gICAgICBhdXRoLnVwZGF0ZUN1cnJlbnRVc2VyKG51bGwpO1xuICAgICAgZGVmZXJyZWQucmVzb2x2ZSgpO1xuXG4gICAgICByZXR1cm4gZGVmZXJyZWQucHJvbWlzZTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBFbnZpYSB1bSBlbWFpbCBwYXJhIHJlY3VwZXJhw6fDo28gZGUgc2VuaGFcbiAgICAgKiBAcGFyYW0ge09iamVjdH0gcmVzZXREYXRhIC0gT2JqZXRvIGNvbnRlbmRvIG8gZW1haWxcbiAgICAgKiBAcmV0dXJuIHtQcm9taXNlfSAtIFJldG9ybmEgdW1hIHByb21pc2UgcGFyYSBzZXIgcmVzb2x2aWRhXG4gICAgICovXG4gICAgZnVuY3Rpb24gc2VuZEVtYWlsUmVzZXRQYXNzd29yZChyZXNldERhdGEpIHtcbiAgICAgIHZhciBkZWZlcnJlZCA9ICRxLmRlZmVyKCk7XG5cbiAgICAgICRodHRwLnBvc3QoR2xvYmFsLmFwaVBhdGggKyAnL3Bhc3N3b3JkL2VtYWlsJywgcmVzZXREYXRhKVxuICAgICAgICAudGhlbihmdW5jdGlvbihyZXNwb25zZSkge1xuICAgICAgICAgIGRlZmVycmVkLnJlc29sdmUocmVzcG9uc2UuZGF0YSk7XG4gICAgICAgIH0sIGZ1bmN0aW9uKGVycm9yKSB7XG4gICAgICAgICAgZGVmZXJyZWQucmVqZWN0KGVycm9yKTtcbiAgICAgICAgfSk7XG5cbiAgICAgIHJldHVybiBkZWZlcnJlZC5wcm9taXNlO1xuICAgIH1cblxuICAgIHJldHVybiBhdXRoO1xuICB9XG5cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb250cm9sbGVyKCdMb2dpbkNvbnRyb2xsZXInLCBMb2dpbkNvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gTG9naW5Db250cm9sbGVyKCRzdGF0ZSwgQXV0aCwgR2xvYmFsLCBQckRpYWxvZykge1xuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICB2bS5sb2dpbiA9IGxvZ2luO1xuICAgIHZtLm9wZW5EaWFsb2dSZXNldFBhc3MgPSBvcGVuRGlhbG9nUmVzZXRQYXNzO1xuICAgIHZtLm9wZW5EaWFsb2dTaWduVXAgPSBvcGVuRGlhbG9nU2lnblVwO1xuXG4gICAgYWN0aXZhdGUoKTtcblxuICAgIGZ1bmN0aW9uIGFjdGl2YXRlKCkge1xuICAgICAgdm0uY3JlZGVudGlhbHMgPSB7fTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBsb2dpbigpIHtcbiAgICAgIHZhciBjcmVkZW50aWFscyA9IHtcbiAgICAgICAgZW1haWw6IHZtLmNyZWRlbnRpYWxzLmVtYWlsLFxuICAgICAgICBwYXNzd29yZDogdm0uY3JlZGVudGlhbHMucGFzc3dvcmRcbiAgICAgIH07XG5cbiAgICAgIEF1dGgubG9naW4oY3JlZGVudGlhbHMpLnRoZW4oZnVuY3Rpb24oKSB7XG4gICAgICAgICRzdGF0ZS5nbyhHbG9iYWwuaG9tZVN0YXRlKTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEV4aWJlIG8gZGlhbG9nIHBhcmEgcmVjdXBlcmHDp8OjbyBkZSBzZW5oYVxuICAgICAqL1xuICAgIGZ1bmN0aW9uIG9wZW5EaWFsb2dSZXNldFBhc3MoKSB7XG4gICAgICB2YXIgY29uZmlnID0ge1xuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL2F1dGgvc2VuZC1yZXNldC1kaWFsb2cuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdQYXNzd29yZENvbnRyb2xsZXIgYXMgcGFzc0N0cmwnLFxuICAgICAgICBoYXNCYWNrZHJvcDogdHJ1ZVxuICAgICAgfVxuXG4gICAgICBQckRpYWxvZy5jdXN0b20oY29uZmlnKTtcbiAgICB9XG4gICAgLyoqXG4gICAgICogRXhpYmUgbyBkaWFsb2cgcGFyYSByZWN1cGVyYcOnw6NvIGRlIHNlbmhhXG4gICAgICovXG4gICAgZnVuY3Rpb24gb3BlbkRpYWxvZ1NpZ25VcCgpIHtcbiAgICAgIHZhciBjb25maWcgPSB7XG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvdXNlcnMvdXNlci1mb3JtLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnVXNlcnNDb250cm9sbGVyIGFzIHVzZXJzQ3RybCcsXG4gICAgICAgIGhhc0JhY2tkcm9wOiB0cnVlXG4gICAgICB9XG5cbiAgICAgIFByRGlhbG9nLmN1c3RvbShjb25maWcpO1xuICAgIH1cblxuICB9XG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29udHJvbGxlcignUGFzc3dvcmRDb250cm9sbGVyJywgUGFzc3dvcmRDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIFBhc3N3b3JkQ29udHJvbGxlcihHbG9iYWwsICRzdGF0ZVBhcmFtcywgJGh0dHAsICR0aW1lb3V0LCAkc3RhdGUsIC8vIE5PU09OQVJcbiAgICBQclRvYXN0LCBQckRpYWxvZywgQXV0aCwgJHRyYW5zbGF0ZSkge1xuXG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIHZtLnNlbmRSZXNldCA9IHNlbmRSZXNldDtcbiAgICB2bS5jbG9zZURpYWxvZyA9IGNsb3NlRGlhbG9nO1xuICAgIHZtLmNsZWFuRm9ybSA9IGNsZWFuRm9ybTtcbiAgICB2bS5zZW5kRW1haWxSZXNldFBhc3N3b3JkID0gc2VuZEVtYWlsUmVzZXRQYXNzd29yZDtcblxuICAgIGFjdGl2YXRlKCk7XG5cbiAgICBmdW5jdGlvbiBhY3RpdmF0ZSgpIHtcbiAgICAgIHZtLnJlc2V0ID0geyBlbWFpbDogJycsIHRva2VuOiAkc3RhdGVQYXJhbXMudG9rZW4gfTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFsaXphIGEgYWx0ZXJhw6fDo28gZGEgc2VuaGEgZG8gdXN1w6FyaW8gZSBvIHJlZGlyZWNpb25hIHBhcmEgYSB0ZWxhIGRlIGxvZ2luXG4gICAgICovXG4gICAgZnVuY3Rpb24gc2VuZFJlc2V0KCkge1xuICAgICAgJGh0dHAucG9zdChHbG9iYWwuYXBpUGF0aCArICcvcGFzc3dvcmQvcmVzZXQnLCB2bS5yZXNldClcbiAgICAgICAgLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICAgIFByVG9hc3Quc3VjY2VzcygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLm9wZXJhdGlvblN1Y2Nlc3MnKSk7XG4gICAgICAgICAgJHRpbWVvdXQoZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgJHN0YXRlLmdvKEdsb2JhbC5sb2dpblN0YXRlKTtcbiAgICAgICAgICB9LCAxNTAwKTtcbiAgICAgICAgfSwgZnVuY3Rpb24gKGVycm9yKSB7XG4gICAgICAgICAgaWYgKGVycm9yLnN0YXR1cyAhPT0gNDAwICYmIGVycm9yLnN0YXR1cyAhPT0gNTAwKSB7XG4gICAgICAgICAgICB2YXIgbXNnID0gJyc7XG5cbiAgICAgICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgZXJyb3IuZGF0YS5wYXNzd29yZC5sZW5ndGg7IGkrKykge1xuICAgICAgICAgICAgICBtc2cgKz0gZXJyb3IuZGF0YS5wYXNzd29yZFtpXSArICc8YnI+JztcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIFByVG9hc3QuZXJyb3IobXNnLnRvVXBwZXJDYXNlKCkpO1xuICAgICAgICAgIH1cbiAgICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogRW52aWEgdW0gZW1haWwgZGUgcmVjdXBlcmHDp8OjbyBkZSBzZW5oYSBjb20gbyB0b2tlbiBkbyB1c3XDoXJpb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIHNlbmRFbWFpbFJlc2V0UGFzc3dvcmQoKSB7XG5cbiAgICAgIGlmICh2bS5yZXNldC5lbWFpbCA9PT0gJycpIHtcbiAgICAgICAgUHJUb2FzdC5lcnJvcigkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnZhbGlkYXRlLmZpZWxkUmVxdWlyZWQnLCB7IGZpZWxkOiAnZW1haWwnIH0pKTtcbiAgICAgICAgcmV0dXJuO1xuICAgICAgfVxuXG4gICAgICBBdXRoLnNlbmRFbWFpbFJlc2V0UGFzc3dvcmQodm0ucmVzZXQpLnRoZW4oZnVuY3Rpb24gKGRhdGEpIHtcbiAgICAgICAgUHJUb2FzdC5zdWNjZXNzKGRhdGEubWVzc2FnZSk7XG5cbiAgICAgICAgdm0uY2xlYW5Gb3JtKCk7XG4gICAgICAgIHZtLmNsb3NlRGlhbG9nKCk7XG4gICAgICB9LCBmdW5jdGlvbiAoZXJyb3IpIHtcbiAgICAgICAgaWYgKGVycm9yLmRhdGEuZW1haWwgJiYgZXJyb3IuZGF0YS5lbWFpbC5sZW5ndGggPiAwKSB7XG4gICAgICAgICAgdmFyIG1zZyA9ICcnO1xuXG4gICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCBlcnJvci5kYXRhLmVtYWlsLmxlbmd0aDsgaSsrKSB7XG4gICAgICAgICAgICBtc2cgKz0gZXJyb3IuZGF0YS5lbWFpbFtpXSArICc8YnI+JztcbiAgICAgICAgICB9XG5cbiAgICAgICAgICBQclRvYXN0LmVycm9yKG1zZyk7XG4gICAgICAgIH1cbiAgICAgIH0pO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGNsb3NlRGlhbG9nKCkge1xuICAgICAgUHJEaWFsb2cuY2xvc2UoKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBjbGVhbkZvcm0oKSB7XG4gICAgICB2bS5yZXNldC5lbWFpbCA9ICcnO1xuICAgIH1cblxuICB9XG5cbn0pKCk7XG4iLCIvKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCovXG4oZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmFjdG9yeSgnc2VydmljZUZhY3RvcnknLCBzZXJ2aWNlRmFjdG9yeSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvKipcbiAgICogTWFpcyBpbmZvcm1hw6fDtWVzOlxuICAgKiBodHRwczovL2dpdGh1Yi5jb20vc3dpbWxhbmUvYW5ndWxhci1tb2RlbC1mYWN0b3J5L3dpa2kvQVBJXG4gICAqL1xuICBmdW5jdGlvbiBzZXJ2aWNlRmFjdG9yeSgkbW9kZWxGYWN0b3J5KSB7XG4gICAgcmV0dXJuIGZ1bmN0aW9uKHVybCwgb3B0aW9ucykge1xuICAgICAgdmFyIG1vZGVsO1xuICAgICAgdmFyIGRlZmF1bHRPcHRpb25zID0ge1xuICAgICAgICBhY3Rpb25zOiB7XG4gICAgICAgICAgLyoqXG4gICAgICAgICAgICogU2VydmnDp28gY29tdW0gcGFyYSByZWFsaXphciBidXNjYSBjb20gcGFnaW5hw6fDo29cbiAgICAgICAgICAgKiBPIG1lc21vIGVzcGVyYSBxdWUgc2VqYSByZXRvcm5hZG8gdW0gb2JqZXRvIGNvbSBpdGVtcyBlIHRvdGFsXG4gICAgICAgICAgICovXG4gICAgICAgICAgcGFnaW5hdGU6IHtcbiAgICAgICAgICAgIG1ldGhvZDogJ0dFVCcsXG4gICAgICAgICAgICBpc0FycmF5OiBmYWxzZSxcbiAgICAgICAgICAgIHdyYXA6IGZhbHNlLFxuICAgICAgICAgICAgYWZ0ZXJSZXF1ZXN0OiBmdW5jdGlvbihyZXNwb25zZSkge1xuICAgICAgICAgICAgICBpZiAocmVzcG9uc2VbJ2l0ZW1zJ10pIHtcbiAgICAgICAgICAgICAgICByZXNwb25zZVsnaXRlbXMnXSA9IG1vZGVsLkxpc3QocmVzcG9uc2VbJ2l0ZW1zJ10pO1xuICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgcmV0dXJuIHJlc3BvbnNlO1xuICAgICAgICAgICAgfVxuICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgfVxuXG4gICAgICBtb2RlbCA9ICRtb2RlbEZhY3RvcnkodXJsLCBhbmd1bGFyLm1lcmdlKGRlZmF1bHRPcHRpb25zLCBvcHRpb25zKSlcblxuICAgICAgcmV0dXJuIG1vZGVsO1xuICAgIH1cbiAgfVxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnRyb2xsZXIoJ0NSVURDb250cm9sbGVyJywgQ1JVRENvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLyoqXG4gICAqIENvbnRyb2xhZG9yIEJhc2UgcXVlIGltcGxlbWVudGEgdG9kYXMgYXMgZnVuw6fDtWVzIHBhZHLDtWVzIGRlIHVtIENSVURcbiAgICpcbiAgICogQcOnw7VlcyBpbXBsZW1lbnRhZGFzXG4gICAqIGFjdGl2YXRlKClcbiAgICogc2VhcmNoKHBhZ2UpXG4gICAqIGVkaXQocmVzb3VyY2UpXG4gICAqIHNhdmUoKVxuICAgKiByZW1vdmUocmVzb3VyY2UpXG4gICAqIGdvVG8odmlld05hbWUpXG4gICAqIGNsZWFuRm9ybSgpXG4gICAqXG4gICAqIEdhdGlsaG9zXG4gICAqXG4gICAqIG9uQWN0aXZhdGUoKVxuICAgKiBhcHBseUZpbHRlcnMoZGVmYXVsdFF1ZXJ5RmlsdGVycylcbiAgICogYmVmb3JlU2VhcmNoKHBhZ2UpIC8vcmV0b3JuYW5kbyBmYWxzZSBjYW5jZWxhIG8gZmx1eG9cbiAgICogYWZ0ZXJTZWFyY2gocmVzcG9uc2UpXG4gICAqIGJlZm9yZUNsZWFuIC8vcmV0b3JuYW5kbyBmYWxzZSBjYW5jZWxhIG8gZmx1eG9cbiAgICogYWZ0ZXJDbGVhbigpXG4gICAqIGJlZm9yZVNhdmUoKSAvL3JldG9ybmFuZG8gZmFsc2UgY2FuY2VsYSBvIGZsdXhvXG4gICAqIGFmdGVyU2F2ZShyZXNvdXJjZSlcbiAgICogb25TYXZlRXJyb3IoZXJyb3IpXG4gICAqIGJlZm9yZVJlbW92ZShyZXNvdXJjZSkgLy9yZXRvcm5hbmRvIGZhbHNlIGNhbmNlbGEgbyBmbHV4b1xuICAgKiBhZnRlclJlbW92ZShyZXNvdXJjZSlcbiAgICpcbiAgICogQHBhcmFtIHthbnl9IHZtIGluc3RhbmNpYSBkbyBjb250cm9sbGVyIGZpbGhvXG4gICAqIEBwYXJhbSB7YW55fSBtb2RlbFNlcnZpY2Ugc2VydmnDp28gZG8gbW9kZWwgcXVlIHZhaSBzZXIgdXRpbGl6YWRvXG4gICAqIEBwYXJhbSB7YW55fSBvcHRpb25zIG9ww6fDtWVzIHBhcmEgc29icmVlc2NyZXZlciBjb21wb3J0YW1lbnRvcyBwYWRyw7Vlc1xuICAgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gQ1JVRENvbnRyb2xsZXIodm0sIG1vZGVsU2VydmljZSwgb3B0aW9ucywgUHJUb2FzdCwgUHJQYWdpbmF0aW9uLCAvLyBOT1NPTkFSXG4gICAgUHJEaWFsb2csICR0cmFuc2xhdGUpIHtcblxuICAgIC8vRnVuY3Rpb25zIEJsb2NrXG4gICAgdm0uc2VhcmNoID0gc2VhcmNoO1xuICAgIHZtLnBhZ2luYXRlU2VhcmNoID0gcGFnaW5hdGVTZWFyY2g7XG4gICAgdm0ubm9ybWFsU2VhcmNoID0gbm9ybWFsU2VhcmNoO1xuICAgIHZtLmVkaXQgPSBlZGl0O1xuICAgIHZtLnNhdmUgPSBzYXZlO1xuICAgIHZtLnJlbW92ZSA9IHJlbW92ZTtcbiAgICB2bS5nb1RvID0gZ29UbztcbiAgICB2bS5jbGVhbkZvcm0gPSBjbGVhbkZvcm07XG5cbiAgICBhY3RpdmF0ZSgpO1xuXG4gICAgLyoqXG4gICAgICogUHJlcGFyYSBvIGNvbnRyb2xhZG9yXG4gICAgICogRmF6IG8gbWVyZ2UgZGFzIG9ww6fDtWVzXG4gICAgICogSW5pY2lhbGl6YSBvIHJlY3Vyc29cbiAgICAgKiBJbmljaWFsaXphIG8gb2JqZXRvIHBhZ2luYWRvciBlIHJlYWxpemEgYSBwZXNxdWlzYVxuICAgICAqL1xuICAgIGZ1bmN0aW9uIGFjdGl2YXRlKCkge1xuICAgICAgdm0uZGVmYXVsdE9wdGlvbnMgPSB7XG4gICAgICAgIHJlZGlyZWN0QWZ0ZXJTYXZlOiB0cnVlLFxuICAgICAgICBzZWFyY2hPbkluaXQ6IHRydWUsXG4gICAgICAgIHBlclBhZ2U6IDgsXG4gICAgICAgIHNraXBQYWdpbmF0aW9uOiBmYWxzZVxuICAgICAgfVxuXG4gICAgICBhbmd1bGFyLm1lcmdlKHZtLmRlZmF1bHRPcHRpb25zLCBvcHRpb25zKTtcblxuICAgICAgdm0udmlld0Zvcm0gPSBmYWxzZTtcbiAgICAgIHZtLnJlc291cmNlID0gbmV3IG1vZGVsU2VydmljZSgpO1xuXG4gICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLm9uQWN0aXZhdGUpKSB2bS5vbkFjdGl2YXRlKCk7XG5cbiAgICAgIHZtLnBhZ2luYXRvciA9IFByUGFnaW5hdGlvbi5nZXRJbnN0YW5jZSh2bS5zZWFyY2gsIHZtLmRlZmF1bHRPcHRpb25zLnBlclBhZ2UpO1xuXG4gICAgICBpZiAodm0uZGVmYXVsdE9wdGlvbnMuc2VhcmNoT25Jbml0KSB2bS5zZWFyY2goKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFsaXphIGEgcGVzcXVpc2FcbiAgICAgKiBWZXJpZmljYSBxdWFsIGRhcyBmdW7Dp8O1ZXMgZGUgcGVzcXVpc2EgZGV2ZSBzZXIgcmVhbGl6YWRhLlxuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IHBhZ2UgcMOhZ2luYSBxdWUgZGV2ZSBzZXIgY2FycmVnYWRhXG4gICAgICovXG4gICAgZnVuY3Rpb24gc2VhcmNoKHBhZ2UpIHtcbiAgICAgICh2bS5kZWZhdWx0T3B0aW9ucy5za2lwUGFnaW5hdGlvbikgPyBub3JtYWxTZWFyY2goKSA6IHBhZ2luYXRlU2VhcmNoKHBhZ2UpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWxpemEgYSBwZXNxdWlzYSBwYWdpbmFkYSBjb20gYmFzZSBub3MgZmlsdHJvcyBkZWZpbmlkb3NcbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSBwYWdlIHDDoWdpbmEgcXVlIGRldmUgc2VyIGNhcnJlZ2FkYVxuICAgICAqL1xuICAgIGZ1bmN0aW9uIHBhZ2luYXRlU2VhcmNoKHBhZ2UpIHtcbiAgICAgIHZtLnBhZ2luYXRvci5jdXJyZW50UGFnZSA9IChhbmd1bGFyLmlzRGVmaW5lZChwYWdlKSkgPyBwYWdlIDogMTtcbiAgICAgIHZtLmRlZmF1bHRRdWVyeUZpbHRlcnMgPSB7IHBhZ2U6IHZtLnBhZ2luYXRvci5jdXJyZW50UGFnZSwgcGVyUGFnZTogdm0ucGFnaW5hdG9yLnBlclBhZ2UgfTtcblxuICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5hcHBseUZpbHRlcnMpKSB2bS5kZWZhdWx0UXVlcnlGaWx0ZXJzID0gdm0uYXBwbHlGaWx0ZXJzKHZtLmRlZmF1bHRRdWVyeUZpbHRlcnMpO1xuICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5iZWZvcmVTZWFyY2gpICYmIHZtLmJlZm9yZVNlYXJjaChwYWdlKSA9PT0gZmFsc2UpIHJldHVybiBmYWxzZTtcblxuICAgICAgbW9kZWxTZXJ2aWNlLnBhZ2luYXRlKHZtLmRlZmF1bHRRdWVyeUZpbHRlcnMpLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgIHZtLnBhZ2luYXRvci5jYWxjTnVtYmVyT2ZQYWdlcyhyZXNwb25zZS50b3RhbCk7XG4gICAgICAgIHZtLnJlc291cmNlcyA9IHJlc3BvbnNlLml0ZW1zO1xuXG4gICAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYWZ0ZXJTZWFyY2gpKSB2bS5hZnRlclNlYXJjaChyZXNwb25zZSk7XG4gICAgICB9LCBmdW5jdGlvbiAocmVzcG9uc2VEYXRhKSB7XG4gICAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0ub25TZWFyY2hFcnJvcikpIHZtLm9uU2VhcmNoRXJyb3IocmVzcG9uc2VEYXRhKTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWxpemEgYSBwZXNxdWlzYSBjb20gYmFzZSBub3MgZmlsdHJvcyBkZWZpbmlkb3NcbiAgICAgKlxuICAgICAqL1xuICAgIGZ1bmN0aW9uIG5vcm1hbFNlYXJjaCgpIHtcbiAgICAgIHZtLmRlZmF1bHRRdWVyeUZpbHRlcnMgPSB7IH07XG5cbiAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYXBwbHlGaWx0ZXJzKSkgdm0uZGVmYXVsdFF1ZXJ5RmlsdGVycyA9IHZtLmFwcGx5RmlsdGVycyh2bS5kZWZhdWx0UXVlcnlGaWx0ZXJzKTtcbiAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYmVmb3JlU2VhcmNoKSAmJiB2bS5iZWZvcmVTZWFyY2goKSA9PT0gZmFsc2UpIHJldHVybiBmYWxzZTtcblxuICAgICAgbW9kZWxTZXJ2aWNlLnF1ZXJ5KHZtLmRlZmF1bHRRdWVyeUZpbHRlcnMpLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgIHZtLnJlc291cmNlcyA9IHJlc3BvbnNlO1xuXG4gICAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYWZ0ZXJTZWFyY2gpKSB2bS5hZnRlclNlYXJjaChyZXNwb25zZSk7XG4gICAgICB9LCBmdW5jdGlvbiAocmVzcG9uc2VEYXRhKSB7XG4gICAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0ub25TZWFyY2hFcnJvcikpIHZtLm9uU2VhcmNoRXJyb3IocmVzcG9uc2VEYXRhKTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIExpbXBhIG8gZm9ybXVsw6FyaW9cbiAgICAgKi9cbiAgICBmdW5jdGlvbiBjbGVhbkZvcm0oZm9ybSkge1xuICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5iZWZvcmVDbGVhbikgJiYgdm0uYmVmb3JlQ2xlYW4oKSA9PT0gZmFsc2UpIHJldHVybiBmYWxzZTtcblxuICAgICAgdm0ucmVzb3VyY2UgPSBuZXcgbW9kZWxTZXJ2aWNlKCk7XG5cbiAgICAgIGlmIChhbmd1bGFyLmlzRGVmaW5lZChmb3JtKSkge1xuICAgICAgICBmb3JtLiRzZXRQcmlzdGluZSgpO1xuICAgICAgICBmb3JtLiRzZXRVbnRvdWNoZWQoKTtcbiAgICAgIH1cblxuICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5hZnRlckNsZWFuKSkgdm0uYWZ0ZXJDbGVhbigpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENhcnJlZ2Egbm8gZm9ybXVsw6FyaW8gbyByZWN1cnNvIHNlbGVjaW9uYWRvIHBhcmEgZWRpw6fDo29cbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSByZXNvdXJjZSByZWN1cnNvIHNlbGVjaW9uYWRvXG4gICAgICovXG4gICAgZnVuY3Rpb24gZWRpdChyZXNvdXJjZSkge1xuICAgICAgdm0uZ29UbygnZm9ybScpO1xuICAgICAgdm0ucmVzb3VyY2UgPSBuZXcgYW5ndWxhci5jb3B5KHJlc291cmNlKTtcblxuICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5hZnRlckVkaXQpKSB2bS5hZnRlckVkaXQoKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBTYWx2YSBvdSBhdHVhbGl6YSBvIHJlY3Vyc28gY29ycmVudGUgbm8gZm9ybXVsw6FyaW9cbiAgICAgKiBObyBjb21wb3J0YW1lbnRvIHBhZHLDo28gcmVkaXJlY2lvbmEgbyB1c3XDoXJpbyBwYXJhIHZpZXcgZGUgbGlzdGFnZW1cbiAgICAgKiBkZXBvaXMgZGEgZXhlY3XDp8Ojb1xuICAgICAqXG4gICAgICogQHJldHVybnNcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBzYXZlKGZvcm0pIHtcbiAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYmVmb3JlU2F2ZSkgJiYgdm0uYmVmb3JlU2F2ZSgpID09PSBmYWxzZSkgcmV0dXJuIGZhbHNlO1xuXG4gICAgICB2bS5yZXNvdXJjZS4kc2F2ZSgpLnRoZW4oZnVuY3Rpb24gKHJlc291cmNlKSB7XG4gICAgICAgIHZtLnJlc291cmNlID0gcmVzb3VyY2U7XG5cbiAgICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5hZnRlclNhdmUpKSB2bS5hZnRlclNhdmUocmVzb3VyY2UpO1xuXG4gICAgICAgIGlmICh2bS5kZWZhdWx0T3B0aW9ucy5yZWRpcmVjdEFmdGVyU2F2ZSkge1xuICAgICAgICAgIHZtLmNsZWFuRm9ybShmb3JtKTtcbiAgICAgICAgICB2bS5zZWFyY2godm0ucGFnaW5hdG9yLmN1cnJlbnRQYWdlKTtcbiAgICAgICAgICB2bS5nb1RvKCdsaXN0Jyk7XG4gICAgICAgIH1cblxuICAgICAgICBQclRvYXN0LnN1Y2Nlc3MoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5zYXZlU3VjY2VzcycpKTtcblxuICAgICAgfSwgZnVuY3Rpb24gKHJlc3BvbnNlRGF0YSkge1xuICAgICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLm9uU2F2ZUVycm9yKSkgdm0ub25TYXZlRXJyb3IocmVzcG9uc2VEYXRhKTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlbW92ZSBvIHJlY3Vyc28gaW5mb3JtYWRvLlxuICAgICAqIEFudGVzIGV4aWJlIHVtIGRpYWxvZ28gZGUgY29uZmlybWHDp8Ojb1xuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IHJlc291cmNlIHJlY3Vyc28gZXNjb2xoaWRvXG4gICAgICovXG4gICAgZnVuY3Rpb24gcmVtb3ZlKHJlc291cmNlKSB7XG4gICAgICB2YXIgY29uZmlnID0ge1xuICAgICAgICB0aXRsZTogJHRyYW5zbGF0ZS5pbnN0YW50KCdkaWFsb2cuY29uZmlybVRpdGxlJyksXG4gICAgICAgIGRlc2NyaXB0aW9uOiAkdHJhbnNsYXRlLmluc3RhbnQoJ2RpYWxvZy5jb25maXJtRGVzY3JpcHRpb24nKVxuICAgICAgfVxuXG4gICAgICBQckRpYWxvZy5jb25maXJtKGNvbmZpZykudGhlbihmdW5jdGlvbigpIHtcbiAgICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5iZWZvcmVSZW1vdmUpICYmIHZtLmJlZm9yZVJlbW92ZShyZXNvdXJjZSkgPT09IGZhbHNlKSByZXR1cm4gZmFsc2U7XG5cbiAgICAgICAgcmVzb3VyY2UuJGRlc3Ryb3koKS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmFmdGVyUmVtb3ZlKSkgdm0uYWZ0ZXJSZW1vdmUocmVzb3VyY2UpO1xuXG4gICAgICAgICAgdm0uc2VhcmNoKCk7XG4gICAgICAgICAgUHJUb2FzdC5pbmZvKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMucmVtb3ZlU3VjY2VzcycpKTtcbiAgICAgICAgfSk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBBbHRlcm5hIGVudHJlIGEgdmlldyBkbyBmb3JtdWzDoXJpbyBlIGxpc3RhZ2VtXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gdmlld05hbWUgbm9tZSBkYSB2aWV3XG4gICAgICovXG4gICAgZnVuY3Rpb24gZ29Ubyh2aWV3TmFtZSkge1xuICAgICAgdm0udmlld0Zvcm0gPSBmYWxzZTtcbiAgICAgIHZtLm9uVmlldyA9IGZhbHNlO1xuICAgICAgaWYgKHZpZXdOYW1lID09PSAnZm9ybScpIHtcbiAgICAgICAgdm0uY2xlYW5Gb3JtKCk7XG4gICAgICAgIHZtLnZpZXdGb3JtID0gdHJ1ZTtcbiAgICAgIH1cbiAgICB9XG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZpbHRlcignZWxhcHNlZCcsIGZ1bmN0aW9uKCkge1xuICAgICAgcmV0dXJuIGZ1bmN0aW9uKGRhdGUpIHtcbiAgICAgICAgaWYgKCFkYXRlKSByZXR1cm47XG4gICAgICAgIHZhciB0aW1lID0gRGF0ZS5wYXJzZShkYXRlKSxcbiAgICAgICAgICB0aW1lTm93ID0gbmV3IERhdGUoKS5nZXRUaW1lKCksXG4gICAgICAgICAgZGlmZmVyZW5jZSA9IHRpbWVOb3cgLSB0aW1lLFxuICAgICAgICAgIHNlY29uZHMgPSBNYXRoLmZsb29yKGRpZmZlcmVuY2UgLyAxMDAwKSxcbiAgICAgICAgICBtaW51dGVzID0gTWF0aC5mbG9vcihzZWNvbmRzIC8gNjApLFxuICAgICAgICAgIGhvdXJzID0gTWF0aC5mbG9vcihtaW51dGVzIC8gNjApLFxuICAgICAgICAgIGRheXMgPSBNYXRoLmZsb29yKGhvdXJzIC8gMjQpLFxuICAgICAgICAgIG1vbnRocyA9IE1hdGguZmxvb3IoZGF5cyAvIDMwKTtcblxuICAgICAgICBpZiAobW9udGhzID4gMSkge1xuICAgICAgICAgIHJldHVybiBtb250aHMgKyAnIG1lc2VzIGF0csOhcyc7XG4gICAgICAgIH0gZWxzZSBpZiAobW9udGhzID09PSAxKSB7XG4gICAgICAgICAgcmV0dXJuICcxIG3DqnMgYXRyw6FzJztcbiAgICAgICAgfSBlbHNlIGlmIChkYXlzID4gMSkge1xuICAgICAgICAgIHJldHVybiBkYXlzICsgJyBkaWFzIGF0csOhcyc7XG4gICAgICAgIH0gZWxzZSBpZiAoZGF5cyA9PT0gMSkge1xuICAgICAgICAgIHJldHVybiAnMSBkaWEgYXRyw6FzJ1xuICAgICAgICB9IGVsc2UgaWYgKGhvdXJzID4gMSkge1xuICAgICAgICAgIHJldHVybiBob3VycyArICcgaG9yYXMgYXRyw6FzJztcbiAgICAgICAgfSBlbHNlIGlmIChob3VycyA9PT0gMSkge1xuICAgICAgICAgIHJldHVybiAndW1hIGhvcmEgYXRyw6FzJztcbiAgICAgICAgfSBlbHNlIGlmIChtaW51dGVzID4gMSkge1xuICAgICAgICAgIHJldHVybiBtaW51dGVzICsgJyBtaW51dG9zIGF0csOhcyc7XG4gICAgICAgIH0gZWxzZSBpZiAobWludXRlcyA9PT0gMSkge1xuICAgICAgICAgIHJldHVybiAndW0gbWludXRvIGF0csOhcyc7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgcmV0dXJuICdow6EgcG91Y29zIHNlZ3VuZG9zJztcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pXG4gICAgLmNvbnRyb2xsZXIoJ0Rhc2hib2FyZENvbnRyb2xsZXInLCBEYXNoYm9hcmRDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIERhc2hib2FyZENvbnRyb2xsZXIoJGNvbnRyb2xsZXIsXG4gICAgJHN0YXRlLFxuICAgICRtZERpYWxvZyxcbiAgICAkdHJhbnNsYXRlLFxuICAgIERhc2hib2FyZHNTZXJ2aWNlLFxuICAgIFByb2plY3RzU2VydmljZSxcbiAgICBtb21lbnQsXG4gICAgUHJUb2FzdCxcbiAgICBBdXRoLFxuICAgIEdsb2JhbCkge1xuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICAvL0F0dHJpYnV0ZXMgQmxvY2tcblxuICAgIC8vRnVuY3Rpb25zIEJsb2NrXG4gICAgdm0ub25BY3RpdmF0ZSA9IG9uQWN0aXZhdGU7XG4gICAgdm0uYXBwbHlGaWx0ZXJzID0gYXBwbHlGaWx0ZXJzO1xuICAgIHZtLmZpeERhdGUgPSBmaXhEYXRlO1xuXG4gICAgZnVuY3Rpb24gb25BY3RpdmF0ZSgpIHtcbiAgICAgIHZhciBwcm9qZWN0ID0gbG9jYWxTdG9yYWdlLmdldEl0ZW0oJ3Byb2plY3QnKTtcblxuICAgICAgdm0uaW1hZ2VQYXRoID0gR2xvYmFsLmltYWdlUGF0aCArICcvbm9fYXZhdGFyLmdpZic7XG4gICAgICB2bS5jdXJyZW50VXNlciA9IEF1dGguY3VycmVudFVzZXI7XG4gICAgICBQcm9qZWN0c1NlcnZpY2UucXVlcnkoeyBwcm9qZWN0X2lkOiBwcm9qZWN0IH0pLnRoZW4oZnVuY3Rpb24ocmVzcG9uc2UpIHtcbiAgICAgICAgdm0uYWN0dWFsUHJvamVjdCA9IHJlc3BvbnNlWzBdO1xuICAgICAgfSlcbiAgICAgIHZtLnF1ZXJ5RmlsdGVycyA9IHsgcHJvamVjdF9pZDogcHJvamVjdCB9O1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGFwcGx5RmlsdGVycyhkZWZhdWx0UXVlcnlGaWx0ZXJzKSB7XG4gICAgICByZXR1cm4gYW5ndWxhci5leHRlbmQoZGVmYXVsdFF1ZXJ5RmlsdGVycywgdm0ucXVlcnlGaWx0ZXJzKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBmaXhEYXRlKGRhdGVTdHJpbmcpIHtcbiAgICAgIHJldHVybiBtb21lbnQoZGF0ZVN0cmluZyk7XG4gICAgfVxuXG4gICAgdm0uZ29Ub1Byb2plY3QgPSBmdW5jdGlvbigpIHtcbiAgICAgICRzdGF0ZS5nbygnYXBwLnByb2plY3RzJywgeyBvYmo6ICdlZGl0JywgcmVzb3VyY2U6IHZtLmFjdHVhbFByb2plY3QgfSk7XG4gICAgfVxuXG4gICAgdm0udG90YWxDb3N0ID0gZnVuY3Rpb24oKSB7XG4gICAgICB2YXIgZXN0aW1hdGVkX2Nvc3QgPSAwO1xuXG4gICAgICBpZiAodm0uYWN0dWFsUHJvamVjdC5ob3VyX3ZhbHVlX2ZpbmFsKSB7XG4gICAgICAgIHZtLmFjdHVhbFByb2plY3QudGFza3MuZm9yRWFjaChmdW5jdGlvbih0YXNrKSB7XG4gICAgICAgICAgaWYgKHRhc2suZXN0aW1hdGVkX3RpbWUgPiAwKSB7XG4gICAgICAgICAgICBlc3RpbWF0ZWRfY29zdCArPSAocGFyc2VGbG9hdCh2bS5hY3R1YWxQcm9qZWN0LmhvdXJfdmFsdWVfZmluYWwpICogdGFzay5lc3RpbWF0ZWRfdGltZSk7XG4gICAgICAgICAgfVxuICAgICAgICB9KTtcbiAgICAgIH1cbiAgICAgIHJldHVybiBlc3RpbWF0ZWRfY29zdC50b0xvY2FsZVN0cmluZygnUHQtYnInLCB7IG1pbmltdW1GcmFjdGlvbkRpZ2l0czogMiB9KTtcbiAgICB9XG5cbiAgICB2bS5maW5hbGl6ZVByb2plY3QgPSBmdW5jdGlvbigpIHtcbiAgICAgIFByb2plY3RzU2VydmljZS52ZXJpZnlSZWxlYXNlcyh7IHByb2plY3RfaWQ6IHZtLmFjdHVhbFByb2plY3QuaWQgfSkudGhlbihmdW5jdGlvbihyZXNwb25zZSkge1xuICAgICAgICBpZiAocmVzcG9uc2Uuc3VjY2Vzcykge1xuICAgICAgICAgIHZhciBjb25maXJtID0gJG1kRGlhbG9nLmNvbmZpcm0oKVxuICAgICAgICAgIC50aXRsZSgnRmluYWxpemFyIFByb2pldG8nKVxuICAgICAgICAgIC5odG1sQ29udGVudCgnVGVtIGNlcnRlemEgcXVlIGRlc2VqYSBmaW5hbGl6YXIgbyBwcm9qZXRvICcgKyB2bS5hY3R1YWxQcm9qZWN0Lm5hbWUgKyAnPzxiciAvPiBBaW5kYSBleGlzdGVtIHJlbGVhc2VzIG7Do28gZmluYWxpemFkYXMuJylcbiAgICAgICAgICAub2soJ1NpbScpXG4gICAgICAgICAgLmNhbmNlbCgnTsOjbycpO1xuXG4gICAgICAgICAgJG1kRGlhbG9nLnNob3coY29uZmlybSkudGhlbihmdW5jdGlvbigpIHtcbiAgICAgICAgICAgIHZhciByZWFzb24gPSAkbWREaWFsb2cucHJvbXB0KClcbiAgICAgICAgICAgIC50aXRsZSgnRmluYWxpemFyIFByb2pldG8nKVxuICAgICAgICAgICAgLnRleHRDb250ZW50KCdRdWFsIG8gbW90aXZvIHBhcmEgYSBmaW5hbGl6YcOnw6NvIGRvIHByb2pldG8/JylcbiAgICAgICAgICAgIC5wbGFjZWhvbGRlcignTW90aXZvJylcbiAgICAgICAgICAgIC5pbml0aWFsVmFsdWUoJycpXG4gICAgICAgICAgICAucmVxdWlyZWQodHJ1ZSlcbiAgICAgICAgICAgIC5vaygnQ29uZmlybWFyJylcbiAgICAgICAgICAgIC5jYW5jZWwoJ0NhbmNlbGFyJyk7XG5cbiAgICAgICAgICAgICRtZERpYWxvZy5zaG93KHJlYXNvbikudGhlbihmdW5jdGlvbihyZWFzb25UZXh0KSB7XG4gICAgICAgICAgICAgIFByb2plY3RzU2VydmljZS5maW5hbGl6ZSh7IHByb2plY3RfaWQ6IHZtLmFjdHVhbFByb2plY3QuaWQsIHJlYXNvbjogcmVhc29uVGV4dCB9KS50aGVuKGZ1bmN0aW9uKCkge1xuICAgICAgICAgICAgICAgIFByVG9hc3Quc3VjY2VzcygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnByb2plY3RFbmRlZFN1Y2Nlc3MnKSk7XG4gICAgICAgICAgICAgICAgb25BY3RpdmF0ZSgpO1xuICAgICAgICAgICAgICAgIHZtLnNlYXJjaCgpO1xuICAgICAgICAgICAgICB9LCBmdW5jdGlvbigpIHtcbiAgICAgICAgICAgICAgICBQclRvYXN0LkVycm9yKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMucHJvamVjdEVuZGVkRXJyb3InKSk7XG4gICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgfSk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgdmFyIGNvbmZpcm0gPSAkbWREaWFsb2cuY29uZmlybSgpXG4gICAgICAgICAgLnRpdGxlKCdGaW5hbGl6YXIgUHJvamV0bycpXG4gICAgICAgICAgLnRleHRDb250ZW50KCdUZW0gY2VydGV6YSBxdWUgZGVzZWphIGZpbmFsaXphciBvIHByb2pldG8gJyArIHZtLmFjdHVhbFByb2plY3QubmFtZSArICc/JylcbiAgICAgICAgICAub2soJ1NpbScpXG4gICAgICAgICAgLmNhbmNlbCgnTsOjbycpO1xuXG4gICAgICAgICAgJG1kRGlhbG9nLnNob3coY29uZmlybSkudGhlbihmdW5jdGlvbigpIHtcbiAgICAgICAgICAgIFByb2plY3RzU2VydmljZS5maW5hbGl6ZSh7IHByb2plY3RfaWQ6IHZtLmFjdHVhbFByb2plY3QuaWQgfSkudGhlbihmdW5jdGlvbigpIHtcbiAgICAgICAgICAgICAgUHJUb2FzdC5zdWNjZXNzKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMucHJvamVjdEVuZGVkU3VjY2VzcycpKTtcbiAgICAgICAgICAgICAgb25BY3RpdmF0ZSgpO1xuICAgICAgICAgICAgICB2bS5zZWFyY2goKTtcbiAgICAgICAgICAgIH0sIGZ1bmN0aW9uKCkge1xuICAgICAgICAgICAgICBQclRvYXN0LkVycm9yKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMucHJvamVjdEVuZGVkRXJyb3InKSk7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgICB9KTtcbiAgICAgICAgfVxuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLy8gaW5zdGFudGlhdGUgYmFzZSBjb250cm9sbGVyXG4gICAgJGNvbnRyb2xsZXIoJ0NSVURDb250cm9sbGVyJywgeyB2bTogdm0sIG1vZGVsU2VydmljZTogRGFzaGJvYXJkc1NlcnZpY2UsIG9wdGlvbnM6IHt9IH0pO1xuICB9XG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqXG4gICAqIEFycXVpdm8gZGUgY29uZmlndXJhw6fDo28gY29tIGFzIHJvdGFzIGVzcGVjw61maWNhcyBkbyByZWN1cnNvIHByb2plY3RcbiAgICpcbiAgICogQHBhcmFtIHthbnl9ICRzdGF0ZVByb3ZpZGVyXG4gICAqIEBwYXJhbSB7YW55fSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlclxuICAgICAgLnN0YXRlKCdhcHAuZGFzaGJvYXJkJywge1xuICAgICAgICB1cmw6ICcvZGFzaGJvYXJkcycsXG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvZGFzaGJvYXJkL2Rhc2hib2FyZC5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ0Rhc2hib2FyZENvbnRyb2xsZXIgYXMgZGFzaGJvYXJkQ3RybCcsXG4gICAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiB0cnVlIH0sXG4gICAgICAgIG9iajogeyByZXNvdXJjZTogbnVsbCB9XG4gICAgICB9KTtcbiAgfVxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5mYWN0b3J5KCdEYXNoYm9hcmRzU2VydmljZScsIERhc2hib2FyZHNTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIERhc2hib2FyZHNTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCdkYXNoYm9hcmRzJywge1xuICAgICAgYWN0aW9uczogeyB9LFxuICAgICAgaW5zdGFuY2U6IHsgfVxuICAgIH0pO1xuICB9XG5cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqXG4gICAqIEFycXVpdm8gZGUgY29uZmlndXJhw6fDo28gY29tIGFzIHJvdGFzIGVzcGVjw61maWNhcyBkbyByZWN1cnNvIHVzZXJcbiAgICpcbiAgICogQHBhcmFtIHthbnl9ICRzdGF0ZVByb3ZpZGVyXG4gICAqIEBwYXJhbSB7YW55fSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlclxuICAgICAgLnN0YXRlKCdhcHAuZGluYW1pYy1xdWVyeScsIHtcbiAgICAgICAgdXJsOiAnL2NvbnN1bHRhcy1kaW5hbWljYXMnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL2RpbmFtaWMtcXVlcnlzL2RpbmFtaWMtcXVlcnlzLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnRGluYW1pY1F1ZXJ5c0NvbnRyb2xsZXIgYXMgZGluYW1pY1F1ZXJ5Q3RybCcsXG4gICAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiB0cnVlLCBuZWVkUHJvZmlsZTogWydhZG1pbiddIH1cbiAgICAgIH0pO1xuXG4gIH1cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmFjdG9yeSgnRGluYW1pY1F1ZXJ5U2VydmljZScsIERpbmFtaWNRdWVyeVNlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gRGluYW1pY1F1ZXJ5U2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHJldHVybiBzZXJ2aWNlRmFjdG9yeSgnZGluYW1pY1F1ZXJ5Jywge1xuICAgICAgLyoqXG4gICAgICAgKiBhw6fDo28gYWRpY2lvbmFkYSBwYXJhIHBlZ2FyIHVtYSBsaXN0YSBkZSBtb2RlbHMgZXhpc3RlbnRlcyBubyBzZXJ2aWRvclxuICAgICAgICovXG4gICAgICBhY3Rpb25zOiB7XG4gICAgICAgIGdldE1vZGVsczoge1xuICAgICAgICAgIG1ldGhvZDogJ0dFVCcsXG4gICAgICAgICAgdXJsOiAnbW9kZWxzJ1xuICAgICAgICB9XG4gICAgICB9LFxuICAgICAgaW5zdGFuY2U6IHtcbiAgICAgIH1cbiAgICB9KTtcbiAgfVxuXG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29udHJvbGxlcignRGluYW1pY1F1ZXJ5c0NvbnRyb2xsZXInLCBEaW5hbWljUXVlcnlzQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBEaW5hbWljUXVlcnlzQ29udHJvbGxlcigkY29udHJvbGxlciwgRGluYW1pY1F1ZXJ5U2VydmljZSwgbG9kYXNoLCBQclRvYXN0LCAvLyBOT1NPTkFSXG4gICAgJHRyYW5zbGF0ZSkge1xuXG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIC8vYWN0aW9uc1xuICAgIHZtLm9uQWN0aXZhdGUgPSBvbkFjdGl2YXRlO1xuICAgIHZtLmFwcGx5RmlsdGVycyA9IGFwcGx5RmlsdGVycztcbiAgICB2bS5sb2FkQXR0cmlidXRlcyA9IGxvYWRBdHRyaWJ1dGVzO1xuICAgIHZtLmxvYWRPcGVyYXRvcnMgPSBsb2FkT3BlcmF0b3JzO1xuICAgIHZtLmFkZEZpbHRlciA9IGFkZEZpbHRlcjtcbiAgICB2bS5hZnRlclNlYXJjaCA9IGFmdGVyU2VhcmNoO1xuICAgIHZtLnJ1bkZpbHRlciA9IHJ1bkZpbHRlcjtcbiAgICB2bS5lZGl0RmlsdGVyID0gZWRpdEZpbHRlcjtcbiAgICB2bS5sb2FkTW9kZWxzID0gbG9hZE1vZGVscztcbiAgICB2bS5yZW1vdmVGaWx0ZXIgPSByZW1vdmVGaWx0ZXI7XG4gICAgdm0uY2xlYXIgPSBjbGVhcjtcbiAgICB2bS5yZXN0YXJ0ID0gcmVzdGFydDtcblxuICAgIC8vaGVyZGEgbyBjb21wb3J0YW1lbnRvIGJhc2UgZG8gQ1JVRFxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHsgdm06IHZtLCBtb2RlbFNlcnZpY2U6IERpbmFtaWNRdWVyeVNlcnZpY2UsIG9wdGlvbnM6IHtcbiAgICAgIHNlYXJjaE9uSW5pdDogZmFsc2VcbiAgICB9IH0pO1xuXG4gICAgZnVuY3Rpb24gb25BY3RpdmF0ZSgpIHtcbiAgICAgIHZtLnJlc3RhcnQoKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBQcmVwYXJhIGUgYXBsaWNhIG9zIGZpbHRybyBxdWUgdsOjbyBzZXIgZW52aWFkb3MgcGFyYSBvIHNlcnZpw6dvXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gZGVmYXVsdFF1ZXJ5RmlsdGVyc1xuICAgICAqIEByZXR1cm5zXG4gICAgICovXG4gICAgZnVuY3Rpb24gYXBwbHlGaWx0ZXJzKGRlZmF1bHRRdWVyeUZpbHRlcnMpIHtcbiAgICAgIHZhciB3aGVyZSA9IHt9O1xuXG4gICAgICAvKipcbiAgICAgICAqIG8gc2VydmnDp28gZXNwZXJhIHVtIG9iamV0byBjb206XG4gICAgICAgKiAgbyBub21lIGRlIHVtIG1vZGVsXG4gICAgICAgKiAgdW1hIGxpc3RhIGRlIGZpbHRyb3NcbiAgICAgICAqL1xuICAgICAgaWYgKHZtLmFkZGVkRmlsdGVycy5sZW5ndGggPiAwKSB7XG4gICAgICAgIHZhciBhZGRlZEZpbHRlcnMgPSBhbmd1bGFyLmNvcHkodm0uYWRkZWRGaWx0ZXJzKTtcblxuICAgICAgICB3aGVyZS5tb2RlbCA9IHZtLmFkZGVkRmlsdGVyc1swXS5tb2RlbC5uYW1lO1xuXG4gICAgICAgIGZvciAodmFyIGluZGV4ID0gMDsgaW5kZXggPCBhZGRlZEZpbHRlcnMubGVuZ3RoOyBpbmRleCsrKSB7XG4gICAgICAgICAgdmFyIGZpbHRlciA9IGFkZGVkRmlsdGVyc1tpbmRleF07XG5cbiAgICAgICAgICBmaWx0ZXIubW9kZWwgPSBudWxsO1xuICAgICAgICAgIGZpbHRlci5hdHRyaWJ1dGUgPSBmaWx0ZXIuYXR0cmlidXRlLm5hbWU7XG4gICAgICAgICAgZmlsdGVyLm9wZXJhdG9yID0gZmlsdGVyLm9wZXJhdG9yLnZhbHVlO1xuICAgICAgICB9XG5cbiAgICAgICAgd2hlcmUuZmlsdGVycyA9IGFuZ3VsYXIudG9Kc29uKGFkZGVkRmlsdGVycyk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICB3aGVyZS5tb2RlbCA9IHZtLnF1ZXJ5RmlsdGVycy5tb2RlbC5uYW1lO1xuICAgICAgfVxuXG4gICAgICByZXR1cm4gYW5ndWxhci5leHRlbmQoZGVmYXVsdFF1ZXJ5RmlsdGVycywgd2hlcmUpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENhcnJlZ2EgdG9kb3Mgb3MgbW9kZWxzIGNyaWFkb3Mgbm8gc2Vydmlkb3IgY29tIHNldXMgYXRyaWJ1dG9zXG4gICAgICovXG4gICAgZnVuY3Rpb24gbG9hZE1vZGVscygpIHtcbiAgICAgIC8vUGVnYSB0b2RvcyBvcyBtb2RlbHMgZG8gc2VydmVyIGUgbW9udGEgdW1hIGxpc3RhIHBybyBDb21ib0JveFxuICAgICAgRGluYW1pY1F1ZXJ5U2VydmljZS5nZXRNb2RlbHMoKS50aGVuKGZ1bmN0aW9uKGRhdGEpIHtcbiAgICAgICAgdm0ubW9kZWxzID0gZGF0YTtcbiAgICAgICAgdm0ucXVlcnlGaWx0ZXJzLm1vZGVsID0gdm0ubW9kZWxzWzBdO1xuICAgICAgICB2bS5sb2FkQXR0cmlidXRlcygpO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ2FycmVnYSBvcyBhdHRyaWJ1dG9zIGRvIG1vZGVsIGVzY29saGlkb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGxvYWRBdHRyaWJ1dGVzKCkge1xuICAgICAgdm0uYXR0cmlidXRlcyA9IHZtLnF1ZXJ5RmlsdGVycy5tb2RlbC5hdHRyaWJ1dGVzO1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzLmF0dHJpYnV0ZSA9IHZtLmF0dHJpYnV0ZXNbMF07XG5cbiAgICAgIHZtLmxvYWRPcGVyYXRvcnMoKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDYXJyZWdhIG9zIG9wZXJhZG9yZXMgZXNwZWNpZmljb3MgcGFyYSBvIHRpcG8gZG8gYXRyaWJ1dG9cbiAgICAgKi9cbiAgICBmdW5jdGlvbiBsb2FkT3BlcmF0b3JzKCkge1xuICAgICAgdmFyIG9wZXJhdG9ycyA9IFtcbiAgICAgICAgeyB2YWx1ZTogJz0nLCBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KCd2aWV3cy5maWVsZHMucXVlcnlEaW5hbWljLm9wZXJhdG9ycy5lcXVhbHMnKSB9LFxuICAgICAgICB7IHZhbHVlOiAnPD4nLCBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KCd2aWV3cy5maWVsZHMucXVlcnlEaW5hbWljLm9wZXJhdG9ycy5kaWZlcmVudCcpIH1cbiAgICAgIF1cblxuICAgICAgaWYgKHZtLnF1ZXJ5RmlsdGVycy5hdHRyaWJ1dGUudHlwZS5pbmRleE9mKCd2YXJ5aW5nJykgIT09IC0xKSB7XG4gICAgICAgIG9wZXJhdG9ycy5wdXNoKHsgdmFsdWU6ICdoYXMnLFxuICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLmNvbnRlaW5zJykgfSk7XG4gICAgICAgIG9wZXJhdG9ycy5wdXNoKHsgdmFsdWU6ICdzdGFydFdpdGgnLFxuICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLnN0YXJ0V2l0aCcpIH0pO1xuICAgICAgICBvcGVyYXRvcnMucHVzaCh7IHZhbHVlOiAnZW5kV2l0aCcsXG4gICAgICAgICAgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudCgndmlld3MuZmllbGRzLnF1ZXJ5RGluYW1pYy5vcGVyYXRvcnMuZmluaXNoV2l0aCcpIH0pO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgb3BlcmF0b3JzLnB1c2goeyB2YWx1ZTogJz4nLFxuICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLmJpZ2dlclRoYW4nKSB9KTtcbiAgICAgICAgb3BlcmF0b3JzLnB1c2goeyB2YWx1ZTogJz49JyxcbiAgICAgICAgICBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KCd2aWV3cy5maWVsZHMucXVlcnlEaW5hbWljLm9wZXJhdG9ycy5lcXVhbHNPckJpZ2dlclRoYW4nKSB9KTtcbiAgICAgICAgb3BlcmF0b3JzLnB1c2goeyB2YWx1ZTogJzwnLFxuICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLmxlc3NUaGFuJykgfSk7XG4gICAgICAgIG9wZXJhdG9ycy5wdXNoKHsgdmFsdWU6ICc8PScsXG4gICAgICAgICAgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudCgndmlld3MuZmllbGRzLnF1ZXJ5RGluYW1pYy5vcGVyYXRvcnMuZXF1YWxzT3JMZXNzVGhhbicpIH0pO1xuICAgICAgfVxuXG4gICAgICB2bS5vcGVyYXRvcnMgPSBvcGVyYXRvcnM7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMub3BlcmF0b3IgPSB2bS5vcGVyYXRvcnNbMF07XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQWRpY2lvbmEvZWRpdGEgdW0gZmlsdHJvXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gZm9ybSBlbGVtZW50byBodG1sIGRvIGZvcm11bMOhcmlvIHBhcmEgdmFsaWRhw6fDtWVzXG4gICAgICovXG4gICAgZnVuY3Rpb24gYWRkRmlsdGVyKGZvcm0pIHtcbiAgICAgIGlmIChhbmd1bGFyLmlzVW5kZWZpbmVkKHZtLnF1ZXJ5RmlsdGVycy52YWx1ZSkgfHwgdm0ucXVlcnlGaWx0ZXJzLnZhbHVlID09PSAnJykge1xuICAgICAgICBQclRvYXN0LmVycm9yKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMudmFsaWRhdGUuZmllbGRSZXF1aXJlZCcsIHsgZmllbGQ6ICd2YWxvcicgfSkpO1xuICAgICAgICByZXR1cm47XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBpZiAodm0uaW5kZXggPCAwKSB7XG4gICAgICAgICAgdm0uYWRkZWRGaWx0ZXJzLnB1c2goYW5ndWxhci5jb3B5KHZtLnF1ZXJ5RmlsdGVycykpO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIHZtLmFkZGVkRmlsdGVyc1t2bS5pbmRleF0gPSBhbmd1bGFyLmNvcHkodm0ucXVlcnlGaWx0ZXJzKTtcbiAgICAgICAgICB2bS5pbmRleCA9IC0xO1xuICAgICAgICB9XG5cbiAgICAgICAgLy9yZWluaWNpYSBvIGZvcm11bMOhcmlvIGUgYXMgdmFsaWRhw6fDtWVzIGV4aXN0ZW50ZXNcbiAgICAgICAgdm0ucXVlcnlGaWx0ZXJzID0ge307XG4gICAgICAgIGZvcm0uJHNldFByaXN0aW5lKCk7XG4gICAgICAgIGZvcm0uJHNldFVudG91Y2hlZCgpO1xuICAgICAgfVxuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWxpemEgYSBwZXNxdWlzYSB0ZW5kbyBvcyBmaWx0cm9zIGNvbW8gcGFyw6JtZXRyb3NcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBydW5GaWx0ZXIoKSB7XG4gICAgICB2bS5zZWFyY2godm0ucGFnaW5hdG9yLmN1cnJlbnRQYWdlKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBHYXRpbGhvIGFjaW9uYWRvIGRlcG9pcyBkYSBwZXNxdWlzYSByZXNwb25zw6F2ZWwgcG9yIGlkZW50aWZpY2FyIG9zIGF0cmlidXRvc1xuICAgICAqIGNvbnRpZG9zIG5vcyBlbGVtZW50b3MgcmVzdWx0YW50ZXMgZGEgYnVzY2FcbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSBkYXRhIGRhZG9zIHJlZmVyZW50ZSBhbyByZXRvcm5vIGRhIHJlcXVpc2nDp8Ojb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGFmdGVyU2VhcmNoKGRhdGEpIHtcbiAgICAgIHZhciBrZXlzID0gKGRhdGEuaXRlbXMubGVuZ3RoID4gMCkgPyBPYmplY3Qua2V5cyhkYXRhLml0ZW1zWzBdKSA6IFtdO1xuXG4gICAgICAvL3JldGlyYSB0b2RvcyBvcyBhdHJpYnV0b3MgcXVlIGNvbWXDp2FtIGNvbSAkLlxuICAgICAgLy9Fc3NlcyBhdHJpYnV0b3Mgc8OjbyBhZGljaW9uYWRvcyBwZWxvIHNlcnZpw6dvIGUgbsOjbyBkZXZlIGFwYXJlY2VyIG5hIGxpc3RhZ2VtXG4gICAgICB2bS5rZXlzID0gbG9kYXNoLmZpbHRlcihrZXlzLCBmdW5jdGlvbihrZXkpIHtcbiAgICAgICAgcmV0dXJuICFsb2Rhc2guc3RhcnRzV2l0aChrZXksICckJyk7XG4gICAgICB9KVxuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENvbG9hY2Egbm8gZm9ybXVsw6FyaW8gbyBmaWx0cm8gZXNjb2xoaWRvIHBhcmEgZWRpw6fDo29cbiAgICAgKiBAcGFyYW0ge2FueX0gJGluZGV4IGluZGljZSBubyBhcnJheSBkbyBmaWx0cm8gZXNjb2xoaWRvXG4gICAgICovXG4gICAgZnVuY3Rpb24gZWRpdEZpbHRlcigkaW5kZXgpIHtcbiAgICAgIHZtLmluZGV4ID0gJGluZGV4O1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0gdm0uYWRkZWRGaWx0ZXJzWyRpbmRleF07XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVtb3ZlIG8gZmlsdHJvIGVzY29saGlkb1xuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9ICRpbmRleCBpbmRpY2Ugbm8gYXJyYXkgZG8gZmlsdHJvIGVzY29saGlkb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIHJlbW92ZUZpbHRlcigkaW5kZXgpIHtcbiAgICAgIHZtLmFkZGVkRmlsdGVycy5zcGxpY2UoJGluZGV4KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBMaW1wYSBvIGZvcm11bMOhcmlvIGNvcnJlbnRlXG4gICAgICovXG4gICAgZnVuY3Rpb24gY2xlYXIoKSB7XG4gICAgICAvL2d1YXJkYSBvIGluZGljZSBkbyByZWdpc3RybyBxdWUgZXN0w6Egc2VuZG8gZWRpdGFkb1xuICAgICAgdm0uaW5kZXggPSAtMTtcbiAgICAgIC8vdmluY3VsYWRvIGFvcyBjYW1wb3MgZG8gZm9ybXVsw6FyaW9cbiAgICAgIHZtLnF1ZXJ5RmlsdGVycyA9IHtcbiAgICAgIH07XG5cbiAgICAgIGlmICh2bS5tb2RlbHMpIHZtLnF1ZXJ5RmlsdGVycy5tb2RlbCA9IHZtLm1vZGVsc1swXTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWluaWNpYSBhIGNvbnN0cnXDp8OjbyBkYSBxdWVyeSBsaW1wYW5kbyB0dWRvXG4gICAgICpcbiAgICAgKi9cbiAgICBmdW5jdGlvbiByZXN0YXJ0KCkge1xuICAgICAgLy9ndWFyZGEgYXRyaWJ1dG9zIGRvIHJlc3VsdGFkbyBkYSBidXNjYSBjb3JyZW50ZVxuICAgICAgdm0ua2V5cyA9IFtdO1xuXG4gICAgICAvL2d1YXJkYSBvcyBmaWx0cm9zIGFkaWNpb25hZG9zXG4gICAgICB2bS5hZGRlZEZpbHRlcnMgPSBbXTtcbiAgICAgIHZtLmNsZWFyKCk7XG4gICAgICB2bS5sb2FkTW9kZWxzKCk7XG4gICAgfVxuXG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZhY3RvcnkoJ2xhbmd1YWdlTG9hZGVyJywgTGFuZ3VhZ2VMb2FkZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gTGFuZ3VhZ2VMb2FkZXIoJHEsIFN1cHBvcnRTZXJ2aWNlLCAkbG9nLCAkaW5qZWN0b3IpIHtcbiAgICB2YXIgc2VydmljZSA9IHRoaXM7XG5cbiAgICBzZXJ2aWNlLnRyYW5zbGF0ZSA9IGZ1bmN0aW9uKGxvY2FsZSkge1xuICAgICAgcmV0dXJuIHtcbiAgICAgICAgZ2xvYmFsOiAkaW5qZWN0b3IuZ2V0KGxvY2FsZSArICcuaTE4bi5nbG9iYWwnKSxcbiAgICAgICAgdmlld3M6ICRpbmplY3Rvci5nZXQobG9jYWxlICsgJy5pMThuLnZpZXdzJyksXG4gICAgICAgIGF0dHJpYnV0ZXM6ICRpbmplY3Rvci5nZXQobG9jYWxlICsgJy5pMThuLmF0dHJpYnV0ZXMnKSxcbiAgICAgICAgZGlhbG9nOiAkaW5qZWN0b3IuZ2V0KGxvY2FsZSArICcuaTE4bi5kaWFsb2cnKSxcbiAgICAgICAgbWVzc2FnZXM6ICRpbmplY3Rvci5nZXQobG9jYWxlICsgJy5pMThuLm1lc3NhZ2VzJyksXG4gICAgICAgIG1vZGVsczogJGluamVjdG9yLmdldChsb2NhbGUgKyAnLmkxOG4ubW9kZWxzJylcbiAgICAgIH07XG4gICAgfVxuXG4gICAgLy8gcmV0dXJuIGxvYWRlckZuXG4gICAgcmV0dXJuIGZ1bmN0aW9uKG9wdGlvbnMpIHtcbiAgICAgICRsb2cuaW5mbygnQ2FycmVnYW5kbyBvIGNvbnRldWRvIGRhIGxpbmd1YWdlbSAnICsgb3B0aW9ucy5rZXkpO1xuXG4gICAgICB2YXIgZGVmZXJyZWQgPSAkcS5kZWZlcigpO1xuXG4gICAgICAvL0NhcnJlZ2EgYXMgbGFuZ3MgcXVlIHByZWNpc2FtIGUgZXN0w6NvIG5vIHNlcnZpZG9yIHBhcmEgbsOjbyBwcmVjaXNhciByZXBldGlyIGFxdWlcbiAgICAgIFN1cHBvcnRTZXJ2aWNlLmxhbmdzKCkudGhlbihmdW5jdGlvbihsYW5ncykge1xuICAgICAgICAvL01lcmdlIGNvbSBvcyBsYW5ncyBkZWZpbmlkb3Mgbm8gc2Vydmlkb3JcbiAgICAgICAgdmFyIGRhdGEgPSBhbmd1bGFyLm1lcmdlKHNlcnZpY2UudHJhbnNsYXRlKG9wdGlvbnMua2V5KSwgbGFuZ3MpO1xuXG4gICAgICAgIHJldHVybiBkZWZlcnJlZC5yZXNvbHZlKGRhdGEpO1xuICAgICAgfSwgZnVuY3Rpb24oKSB7XG4gICAgICAgIHJldHVybiBkZWZlcnJlZC5yZXNvbHZlKHNlcnZpY2UudHJhbnNsYXRlKG9wdGlvbnMua2V5KSk7XG4gICAgICB9KTtcblxuICAgICAgcmV0dXJuIGRlZmVycmVkLnByb21pc2U7XG4gICAgfVxuICB9XG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5maWx0ZXIoJ3RBdHRyJywgdEF0dHIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gdEF0dHIoJGZpbHRlcikge1xuICAgIC8qKlxuICAgICAqIEZpbHRybyBwYXJhIHRyYWR1w6fDo28gZGUgdW0gYXRyaWJ1dG8gZGUgdW0gbW9kZWxcbiAgICAgKiBcbiAgICAgKiBAcGFyYW0ge2FueX0gbmFtZSBub21lIGRvIGF0cmlidXRvXG4gICAgICogQHJldHVybnMgbyBub21lIGRvIGF0cmlidXRvIHRyYWR1emlkbyBjYXNvIGVuY29udHJlIHNlIG7Do28gbyBub21lIHBhc3NhZG8gcG9yIHBhcmFtZXRyb1xuICAgICAqLyAgICBcbiAgICByZXR1cm4gZnVuY3Rpb24obmFtZSkge1xuICAgICAgdmFyIGtleSA9ICdhdHRyaWJ1dGVzLicgKyBuYW1lO1xuICAgICAgdmFyIHRyYW5zbGF0ZSA9ICRmaWx0ZXIoJ3RyYW5zbGF0ZScpKGtleSk7XG5cbiAgICAgIHJldHVybiAodHJhbnNsYXRlID09PSBrZXkpID8gbmFtZSA6IHRyYW5zbGF0ZTtcbiAgICB9XG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZpbHRlcigndEJyZWFkY3J1bWInLCB0QnJlYWRjcnVtYik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiB0QnJlYWRjcnVtYigkZmlsdGVyKSB7XG4gICAgLyoqXG4gICAgICogRmlsdHJvIHBhcmEgdHJhZHXDp8OjbyBkbyBicmVhZGNydW1iICh0aXR1bG8gZGEgdGVsYSBjb20gcmFzdHJlaW8pXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gaWQgY2hhdmUgY29tIG8gbm9tZSBkbyBzdGF0ZSByZWZlcmVudGUgdGVsYVxuICAgICAqIEByZXR1cm5zIGEgdHJhZHXDp8OjbyBjYXNvIGVuY29udHJlIHNlIG7Do28gbyBpZCBwYXNzYWRvIHBvciBwYXJhbWV0cm9cbiAgICAgKi9cbiAgICByZXR1cm4gZnVuY3Rpb24oaWQpIHtcbiAgICAgIC8vcGVnYSBhIHNlZ3VuZGEgcGFydGUgZG8gbm9tZSBkbyBzdGF0ZSwgcmV0aXJhbmRvIGEgcGFydGUgYWJzdHJhdGEgKGFwcC4pXG4gICAgICB2YXIga2V5ID0gJ3ZpZXdzLmJyZWFkY3J1bWJzLicgKyBpZC5zcGxpdCgnLicpWzFdO1xuICAgICAgdmFyIHRyYW5zbGF0ZSA9ICRmaWx0ZXIoJ3RyYW5zbGF0ZScpKGtleSk7XG5cbiAgICAgIHJldHVybiAodHJhbnNsYXRlID09PSBrZXkpID8gaWQgOiB0cmFuc2xhdGU7XG4gICAgfVxuICB9XG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5maWx0ZXIoJ3RNb2RlbCcsIHRNb2RlbCk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiB0TW9kZWwoJGZpbHRlcikge1xuICAgIC8qKlxuICAgICAqIEZpbHRybyBwYXJhIHRyYWR1w6fDo28gZGUgdW0gYXRyaWJ1dG8gZGUgdW0gbW9kZWxcbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSBuYW1lIG5vbWUgZG8gYXRyaWJ1dG9cbiAgICAgKiBAcmV0dXJucyBvIG5vbWUgZG8gYXRyaWJ1dG8gdHJhZHV6aWRvIGNhc28gZW5jb250cmUgc2UgbsOjbyBvIG5vbWUgcGFzc2FkbyBwb3IgcGFyYW1ldHJvXG4gICAgICovXG4gICAgcmV0dXJuIGZ1bmN0aW9uKG5hbWUpIHtcbiAgICAgIHZhciBrZXkgPSAnbW9kZWxzLicgKyBuYW1lLnRvTG93ZXJDYXNlKCk7XG4gICAgICB2YXIgdHJhbnNsYXRlID0gJGZpbHRlcigndHJhbnNsYXRlJykoa2V5KTtcblxuICAgICAgcmV0dXJuICh0cmFuc2xhdGUgPT09IGtleSkgPyBuYW1lIDogdHJhbnNsYXRlO1xuICAgIH1cbiAgfVxuXG59KSgpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLnJ1bihhdXRoZW50aWNhdGlvbkxpc3RlbmVyKTtcblxuICAvKipcbiAgICogTGlzdGVuIGFsbCBzdGF0ZSAocGFnZSkgY2hhbmdlcy4gRXZlcnkgdGltZSBhIHN0YXRlIGNoYW5nZSBuZWVkIHRvIHZlcmlmeSB0aGUgdXNlciBpcyBhdXRoZW50aWNhdGVkIG9yIG5vdCB0b1xuICAgKiByZWRpcmVjdCB0byBjb3JyZWN0IHBhZ2UuIFdoZW4gYSB1c2VyIGNsb3NlIHRoZSBicm93c2VyIHdpdGhvdXQgbG9nb3V0LCB3aGVuIGhpbSByZW9wZW4gdGhlIGJyb3dzZXIgdGhpcyBldmVudFxuICAgKiByZWF1dGhlbnRpY2F0ZSB0aGUgdXNlciB3aXRoIHRoZSBwZXJzaXN0ZW50IHRva2VuIG9mIHRoZSBsb2NhbCBzdG9yYWdlLlxuICAgKlxuICAgKiBXZSBkb24ndCBjaGVjayBpZiB0aGUgdG9rZW4gaXMgZXhwaXJlZCBvciBub3QgaW4gdGhlIHBhZ2UgY2hhbmdlLCBiZWNhdXNlIGlzIGdlbmVyYXRlIGFuIHVuZWNlc3Nhcnkgb3ZlcmhlYWQuXG4gICAqIElmIHRoZSB0b2tlbiBpcyBleHBpcmVkIHdoZW4gdGhlIHVzZXIgdHJ5IHRvIGNhbGwgdGhlIGZpcnN0IGFwaSB0byBnZXQgZGF0YSwgaGltIHdpbGwgYmUgbG9nb2ZmIGFuZCByZWRpcmVjdFxuICAgKiB0byBsb2dpbiBwYWdlLlxuICAgKlxuICAgKiBAcGFyYW0gJHJvb3RTY29wZVxuICAgKiBAcGFyYW0gJHN0YXRlXG4gICAqIEBwYXJhbSAkc3RhdGVQYXJhbXNcbiAgICogQHBhcmFtIEF1dGhcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gYXV0aGVudGljYXRpb25MaXN0ZW5lcigkcm9vdFNjb3BlLCAkc3RhdGUsIEdsb2JhbCwgQXV0aCwgUHJUb2FzdCwgLy8gTk9TT05BUlxuICAgICR0cmFuc2xhdGUpIHtcblxuICAgIC8vb25seSB3aGVuIGFwcGxpY2F0aW9uIHN0YXJ0IGNoZWNrIGlmIHRoZSBleGlzdGVudCB0b2tlbiBzdGlsbCB2YWxpZFxuICAgIEF1dGgucmVtb3RlVmFsaWRhdGVUb2tlbigpLnRoZW4oZnVuY3Rpb24oKSB7XG4gICAgICAvL2lmIHRoZSB0b2tlbiBpcyB2YWxpZCBjaGVjayBpZiBleGlzdHMgdGhlIHVzZXIgYmVjYXVzZSB0aGUgYnJvd3NlciBjb3VsZCBiZSBjbG9zZWRcbiAgICAgIC8vYW5kIHRoZSB1c2VyIGRhdGEgaXNuJ3QgaW4gbWVtb3J5XG4gICAgICBpZiAoQXV0aC5jdXJyZW50VXNlciA9PT0gbnVsbCkge1xuICAgICAgICBBdXRoLnVwZGF0ZUN1cnJlbnRVc2VyKGFuZ3VsYXIuZnJvbUpzb24obG9jYWxTdG9yYWdlLmdldEl0ZW0oJ3VzZXInKSkpO1xuICAgICAgfVxuICAgIH0pO1xuXG4gICAgLy9DaGVjayBpZiB0aGUgdG9rZW4gc3RpbGwgdmFsaWQuXG4gICAgJHJvb3RTY29wZS4kb24oJyRzdGF0ZUNoYW5nZVN0YXJ0JywgZnVuY3Rpb24oZXZlbnQsIHRvU3RhdGUpIHtcbiAgICAgIGlmICh0b1N0YXRlLmRhdGEubmVlZEF1dGhlbnRpY2F0aW9uIHx8IHRvU3RhdGUuZGF0YS5uZWVkUHJvZmlsZSkge1xuICAgICAgICAvL2RvbnQgdHJhaXQgdGhlIHN1Y2Nlc3MgYmxvY2sgYmVjYXVzZSBhbHJlYWR5IGRpZCBieSB0b2tlbiBpbnRlcmNlcHRvclxuICAgICAgICBBdXRoLnJlbW90ZVZhbGlkYXRlVG9rZW4oKS5jYXRjaChmdW5jdGlvbigpIHtcbiAgICAgICAgICBQclRvYXN0Lndhcm4oJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5sb2dpbi5sb2dvdXRJbmFjdGl2ZScpKTtcblxuICAgICAgICAgIGlmICh0b1N0YXRlLm5hbWUgIT09IEdsb2JhbC5sb2dpblN0YXRlKSB7XG4gICAgICAgICAgICAkc3RhdGUuZ28oR2xvYmFsLmxvZ2luU3RhdGUpO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIGV2ZW50LnByZXZlbnREZWZhdWx0KCk7XG4gICAgICAgIH0pO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgLy9pZiB0aGUgdXNlIGlzIGF1dGhlbnRpY2F0ZWQgYW5kIG5lZWQgdG8gZW50ZXIgaW4gbG9naW4gcGFnZVxuICAgICAgICAvL2hpbSB3aWxsIGJlIHJlZGlyZWN0ZWQgdG8gaG9tZSBwYWdlXG4gICAgICAgIGlmICh0b1N0YXRlLm5hbWUgPT09IEdsb2JhbC5sb2dpblN0YXRlICYmIEF1dGguYXV0aGVudGljYXRlZCgpKSB7XG4gICAgICAgICAgJHN0YXRlLmdvKEdsb2JhbC5ob21lU3RhdGUpO1xuICAgICAgICAgIGV2ZW50LnByZXZlbnREZWZhdWx0KCk7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9KTtcbiAgfVxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5ydW4oYXV0aG9yaXphdGlvbkxpc3RlbmVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIGF1dGhvcml6YXRpb25MaXN0ZW5lcigkcm9vdFNjb3BlLCAkc3RhdGUsIEdsb2JhbCwgQXV0aCkge1xuICAgIC8qKlxuICAgICAqIEEgY2FkYSBtdWRhbsOnYSBkZSBlc3RhZG8gKFwicMOhZ2luYVwiKSB2ZXJpZmljYSBzZSBvIHVzdcOhcmlvIHRlbSBvIHBlcmZpbFxuICAgICAqIG5lY2Vzc8OhcmlvIHBhcmEgbyBhY2Vzc28gYSBtZXNtYVxuICAgICAqL1xuICAgICRyb290U2NvcGUuJG9uKCckc3RhdGVDaGFuZ2VTdGFydCcsIGZ1bmN0aW9uKGV2ZW50LCB0b1N0YXRlKSB7XG4gICAgICBpZiAodG9TdGF0ZS5kYXRhICYmIHRvU3RhdGUuZGF0YS5uZWVkQXV0aGVudGljYXRpb24gJiZcbiAgICAgICAgdG9TdGF0ZS5kYXRhLm5lZWRQcm9maWxlICYmIEF1dGguYXV0aGVudGljYXRlZCgpICYmXG4gICAgICAgICFBdXRoLmN1cnJlbnRVc2VyLmhhc1Byb2ZpbGUodG9TdGF0ZS5kYXRhLm5lZWRQcm9maWxlLCB0b1N0YXRlLmRhdGEuYWxsUHJvZmlsZXMpKSB7XG5cbiAgICAgICAgJHN0YXRlLmdvKEdsb2JhbC5ub3RBdXRob3JpemVkU3RhdGUpO1xuICAgICAgICBldmVudC5wcmV2ZW50RGVmYXVsdCgpO1xuICAgICAgfVxuXG4gICAgfSk7XG4gIH1cbn0oKSk7XG4iLCIoZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbmZpZyhzcGlubmVySW50ZXJjZXB0b3IpO1xuXG4gIGZ1bmN0aW9uIHNwaW5uZXJJbnRlcmNlcHRvcigkaHR0cFByb3ZpZGVyLCAkcHJvdmlkZSkge1xuICAgIC8qKlxuICAgICAqIEVzdGUgaW50ZXJjZXB0b3Igw6kgcmVzcG9uc8OhdmVsIHBvciBtb3N0cmFyIGUgZXNjb25kZXIgb1xuICAgICAqIGNvbXBvbmVudGUgUHJTcGlubmVyIHNlbXByZSBxdWUgdW1hIHJlcXVpc2nDp8OjbyBhamF4XG4gICAgICogaW5pY2lhciBlIGZpbmFsaXphci5cbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSAkcVxuICAgICAqIEBwYXJhbSB7YW55fSAkaW5qZWN0b3JcbiAgICAgKiBAcmV0dXJuc1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIHNob3dIaWRlU3Bpbm5lcigkcSwgJGluamVjdG9yKSB7XG4gICAgICByZXR1cm4ge1xuICAgICAgICByZXF1ZXN0OiBmdW5jdGlvbiAoY29uZmlnKSB7XG4gICAgICAgICAgJGluamVjdG9yLmdldCgnUHJTcGlubmVyJykuc2hvdygpO1xuXG4gICAgICAgICAgcmV0dXJuIGNvbmZpZztcbiAgICAgICAgfSxcblxuICAgICAgICByZXNwb25zZTogZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgICAgJGluamVjdG9yLmdldCgnUHJTcGlubmVyJykuaGlkZSgpO1xuXG4gICAgICAgICAgcmV0dXJuIHJlc3BvbnNlO1xuICAgICAgICB9LFxuXG4gICAgICAgIHJlc3BvbnNlRXJyb3I6IGZ1bmN0aW9uIChyZWplY3Rpb24pIHtcbiAgICAgICAgICAkaW5qZWN0b3IuZ2V0KCdQclNwaW5uZXInKS5oaWRlKCk7XG5cbiAgICAgICAgICByZXR1cm4gJHEucmVqZWN0KHJlamVjdGlvbik7XG4gICAgICAgIH1cbiAgICAgIH07XG4gICAgfVxuXG4gICAgLy8gRGVmaW5lIHVtYSBmYWN0b3J5IHBhcmEgbyAkaHR0cEludGVyY2VwdG9yXG4gICAgJHByb3ZpZGUuZmFjdG9yeSgnc2hvd0hpZGVTcGlubmVyJywgc2hvd0hpZGVTcGlubmVyKTtcblxuICAgIC8vIEFkaWNpb25hIGEgZmFjdG9yeSBubyBhcnJheSBkZSBpbnRlcmNlcHRvcnMgZG8gJGh0dHBcbiAgICAkaHR0cFByb3ZpZGVyLmludGVyY2VwdG9ycy5wdXNoKCdzaG93SGlkZVNwaW5uZXInKTtcbiAgfVxufSgpKTtcbiIsIi8qZXNsaW50IGFuZ3VsYXIvbW9kdWxlLWdldHRlcjogMCovXG5cbihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb25maWcodG9rZW5JbnRlcmNlcHRvcik7XG5cbiAgLyoqXG4gICAqIEludGVyY2VwdCBhbGwgcmVzcG9uc2UgKHN1Y2Nlc3Mgb3IgZXJyb3IpIHRvIHZlcmlmeSB0aGUgcmV0dXJuZWQgdG9rZW5cbiAgICpcbiAgICogQHBhcmFtICRodHRwUHJvdmlkZXJcbiAgICogQHBhcmFtICRwcm92aWRlXG4gICAqIEBwYXJhbSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gdG9rZW5JbnRlcmNlcHRvcigkaHR0cFByb3ZpZGVyLCAkcHJvdmlkZSwgR2xvYmFsKSB7XG5cbiAgICBmdW5jdGlvbiByZWRpcmVjdFdoZW5TZXJ2ZXJMb2dnZWRPdXQoJHEsICRpbmplY3Rvcikge1xuICAgICAgcmV0dXJuIHtcbiAgICAgICAgcmVxdWVzdDogZnVuY3Rpb24oY29uZmlnKSB7XG4gICAgICAgICAgdmFyIHRva2VuID0gJGluamVjdG9yLmdldCgnQXV0aCcpLmdldFRva2VuKCk7XG5cbiAgICAgICAgICBpZiAodG9rZW4pIHtcbiAgICAgICAgICAgIGNvbmZpZy5oZWFkZXJzWydBdXRob3JpemF0aW9uJ10gPSAnQmVhcmVyICcgKyB0b2tlbjtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICByZXR1cm4gY29uZmlnO1xuICAgICAgICB9LFxuICAgICAgICByZXNwb25zZTogZnVuY3Rpb24ocmVzcG9uc2UpIHtcbiAgICAgICAgICAvLyBnZXQgYSBuZXcgcmVmcmVzaCB0b2tlbiB0byB1c2UgaW4gdGhlIG5leHQgcmVxdWVzdFxuICAgICAgICAgIHZhciB0b2tlbiA9IHJlc3BvbnNlLmhlYWRlcnMoJ0F1dGhvcml6YXRpb24nKTtcblxuICAgICAgICAgIGlmICh0b2tlbikge1xuICAgICAgICAgICAgJGluamVjdG9yLmdldCgnQXV0aCcpLnNldFRva2VuKHRva2VuLnNwbGl0KCcgJylbMV0pO1xuICAgICAgICAgIH1cbiAgICAgICAgICByZXR1cm4gcmVzcG9uc2U7XG4gICAgICAgIH0sXG4gICAgICAgIHJlc3BvbnNlRXJyb3I6IGZ1bmN0aW9uKHJlamVjdGlvbikge1xuICAgICAgICAgIC8vIEluc3RlYWQgb2YgY2hlY2tpbmcgZm9yIGEgc3RhdHVzIGNvZGUgb2YgNDAwIHdoaWNoIG1pZ2h0IGJlIHVzZWRcbiAgICAgICAgICAvLyBmb3Igb3RoZXIgcmVhc29ucyBpbiBMYXJhdmVsLCB3ZSBjaGVjayBmb3IgdGhlIHNwZWNpZmljIHJlamVjdGlvblxuICAgICAgICAgIC8vIHJlYXNvbnMgdG8gdGVsbCB1cyBpZiB3ZSBuZWVkIHRvIHJlZGlyZWN0IHRvIHRoZSBsb2dpbiBzdGF0ZVxuICAgICAgICAgIHZhciByZWplY3Rpb25SZWFzb25zID0gWyd0b2tlbl9ub3RfcHJvdmlkZWQnLCAndG9rZW5fZXhwaXJlZCcsICd0b2tlbl9hYnNlbnQnLCAndG9rZW5faW52YWxpZCddO1xuXG4gICAgICAgICAgdmFyIHRva2VuRXJyb3IgPSBmYWxzZTtcblxuICAgICAgICAgIGFuZ3VsYXIuZm9yRWFjaChyZWplY3Rpb25SZWFzb25zLCBmdW5jdGlvbih2YWx1ZSkge1xuICAgICAgICAgICAgaWYgKHJlamVjdGlvbi5kYXRhICYmIHJlamVjdGlvbi5kYXRhLmVycm9yID09PSB2YWx1ZSkge1xuICAgICAgICAgICAgICB0b2tlbkVycm9yID0gdHJ1ZTtcblxuICAgICAgICAgICAgICAkaW5qZWN0b3IuZ2V0KCdBdXRoJykubG9nb3V0KCkudGhlbihmdW5jdGlvbigpIHtcbiAgICAgICAgICAgICAgICB2YXIgJHN0YXRlID0gJGluamVjdG9yLmdldCgnJHN0YXRlJyk7XG5cbiAgICAgICAgICAgICAgICAvLyBpbiBjYXNlIG11bHRpcGxlIGFqYXggcmVxdWVzdCBmYWlsIGF0IHNhbWUgdGltZSBiZWNhdXNlIHRva2VuIHByb2JsZW1zLFxuICAgICAgICAgICAgICAgIC8vIG9ubHkgdGhlIGZpcnN0IHdpbGwgcmVkaXJlY3RcbiAgICAgICAgICAgICAgICBpZiAoISRzdGF0ZS5pcyhHbG9iYWwubG9naW5TdGF0ZSkpIHtcbiAgICAgICAgICAgICAgICAgICRzdGF0ZS5nbyhHbG9iYWwubG9naW5TdGF0ZSk7XG5cbiAgICAgICAgICAgICAgICAgIC8vY2xvc2UgYW55IGRpYWxvZyB0aGF0IGlzIG9wZW5lZFxuICAgICAgICAgICAgICAgICAgJGluamVjdG9yLmdldCgnUHJEaWFsb2cnKS5jbG9zZSgpO1xuXG4gICAgICAgICAgICAgICAgICBldmVudC5wcmV2ZW50RGVmYXVsdCgpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfSk7XG5cbiAgICAgICAgICAvL2RlZmluZSBkYXRhIHRvIGVtcHR5IGJlY2F1c2UgYWxyZWFkeSBzaG93IFByVG9hc3QgdG9rZW4gbWVzc2FnZVxuICAgICAgICAgIGlmICh0b2tlbkVycm9yKSB7XG4gICAgICAgICAgICByZWplY3Rpb24uZGF0YSA9IHt9O1xuICAgICAgICAgIH1cblxuICAgICAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24ocmVqZWN0aW9uLmhlYWRlcnMpKSB7XG4gICAgICAgICAgICAvLyBtYW55IHNlcnZlcnMgZXJyb3JzIChidXNpbmVzcykgYXJlIGludGVyY2VwdCBoZXJlIGJ1dCBnZW5lcmF0ZWQgYSBuZXcgcmVmcmVzaCB0b2tlblxuICAgICAgICAgICAgLy8gYW5kIG5lZWQgdXBkYXRlIGN1cnJlbnQgdG9rZW5cbiAgICAgICAgICAgIHZhciB0b2tlbiA9IHJlamVjdGlvbi5oZWFkZXJzKCdBdXRob3JpemF0aW9uJyk7XG5cbiAgICAgICAgICAgIGlmICh0b2tlbikge1xuICAgICAgICAgICAgICAkaW5qZWN0b3IuZ2V0KCdBdXRoJykuc2V0VG9rZW4odG9rZW4uc3BsaXQoJyAnKVsxXSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgcmV0dXJuICRxLnJlamVjdChyZWplY3Rpb24pO1xuICAgICAgICB9XG4gICAgICB9O1xuICAgIH1cblxuICAgIC8vIFNldHVwIGZvciB0aGUgJGh0dHBJbnRlcmNlcHRvclxuICAgICRwcm92aWRlLmZhY3RvcnkoJ3JlZGlyZWN0V2hlblNlcnZlckxvZ2dlZE91dCcsIHJlZGlyZWN0V2hlblNlcnZlckxvZ2dlZE91dCk7XG5cbiAgICAvLyBQdXNoIHRoZSBuZXcgZmFjdG9yeSBvbnRvIHRoZSAkaHR0cCBpbnRlcmNlcHRvciBhcnJheVxuICAgICRodHRwUHJvdmlkZXIuaW50ZXJjZXB0b3JzLnB1c2goJ3JlZGlyZWN0V2hlblNlcnZlckxvZ2dlZE91dCcpO1xuICB9XG5cbn0oKSk7XG4iLCIoZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbmZpZyh2YWxpZGF0aW9uSW50ZXJjZXB0b3IpO1xuXG4gIGZ1bmN0aW9uIHZhbGlkYXRpb25JbnRlcmNlcHRvcigkaHR0cFByb3ZpZGVyLCAkcHJvdmlkZSkge1xuICAgIC8qKlxuICAgICAqIEVzdGUgaW50ZXJjZXB0b3Igw6kgcmVzcG9uc8OhdmVsIHBvciBtb3N0cmFyIGFzXG4gICAgICogbWVuc2FnZW5zIGRlIGVycm8gcmVmZXJlbnRlIGFzIHZhbGlkYcOnw7VlcyBkbyBiYWNrLWVuZFxuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9ICRxXG4gICAgICogQHBhcmFtIHthbnl9ICRpbmplY3RvclxuICAgICAqIEByZXR1cm5zXG4gICAgICovXG4gICAgZnVuY3Rpb24gc2hvd0Vycm9yVmFsaWRhdGlvbigkcSwgJGluamVjdG9yKSB7XG4gICAgICByZXR1cm4ge1xuICAgICAgICByZXNwb25zZUVycm9yOiBmdW5jdGlvbiAocmVqZWN0aW9uKSB7XG4gICAgICAgICAgdmFyIFByVG9hc3QgPSAkaW5qZWN0b3IuZ2V0KCdQclRvYXN0Jyk7XG4gICAgICAgICAgdmFyICR0cmFuc2xhdGUgPSAkaW5qZWN0b3IuZ2V0KCckdHJhbnNsYXRlJyk7XG5cbiAgICAgICAgICBpZiAocmVqZWN0aW9uLmNvbmZpZy5kYXRhICYmICFyZWplY3Rpb24uY29uZmlnLmRhdGEuc2tpcFZhbGlkYXRpb24pIHtcbiAgICAgICAgICAgIGlmIChyZWplY3Rpb24uZGF0YSAmJiByZWplY3Rpb24uZGF0YS5lcnJvcikge1xuXG4gICAgICAgICAgICAgIC8vdmVyaWZpY2Egc2Ugb2NvcnJldSBhbGd1bSBlcnJvIHJlZmVyZW50ZSBhbyB0b2tlblxuICAgICAgICAgICAgICBpZiAocmVqZWN0aW9uLmRhdGEuZXJyb3Iuc3RhcnRzV2l0aCgndG9rZW5fJykpIHtcbiAgICAgICAgICAgICAgICBQclRvYXN0Lndhcm4oJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5sb2dpbi5sb2dvdXRJbmFjdGl2ZScpKTtcbiAgICAgICAgICAgICAgfSBlbHNlIGlmIChyZWplY3Rpb24uZGF0YS5lcnJvciAhPT0gJ05vdCBGb3VuZCcpIHtcbiAgICAgICAgICAgICAgICBQclRvYXN0LmVycm9yKCR0cmFuc2xhdGUuaW5zdGFudChyZWplY3Rpb24uZGF0YS5lcnJvcikpO1xuICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICBQclRvYXN0LmVycm9yVmFsaWRhdGlvbihyZWplY3Rpb24uZGF0YSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgcmV0dXJuICRxLnJlamVjdChyZWplY3Rpb24pO1xuICAgICAgICB9XG4gICAgICB9O1xuICAgIH1cblxuICAgIC8vIERlZmluZSB1bWEgZmFjdG9yeSBwYXJhIG8gJGh0dHBJbnRlcmNlcHRvclxuICAgICRwcm92aWRlLmZhY3RvcnkoJ3Nob3dFcnJvclZhbGlkYXRpb24nLCBzaG93RXJyb3JWYWxpZGF0aW9uKTtcblxuICAgIC8vIEFkaWNpb25hIGEgZmFjdG9yeSBubyBhcnJheSBkZSBpbnRlcmNlcHRvcnMgZG8gJGh0dHBcbiAgICAkaHR0cFByb3ZpZGVyLmludGVyY2VwdG9ycy5wdXNoKCdzaG93RXJyb3JWYWxpZGF0aW9uJyk7XG4gIH1cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb250cm9sbGVyKCdLYW5iYW5Db250cm9sbGVyJywgS2FuYmFuQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBLYW5iYW5Db250cm9sbGVyKCRjb250cm9sbGVyLFxuICAgIFRhc2tzU2VydmljZSxcbiAgICBTdGF0dXNTZXJ2aWNlLFxuICAgIFByVG9hc3QsXG4gICAgJG1kRGlhbG9nLFxuICAgICRkb2N1bWVudCxcbiAgICBBdXRoLFxuICAgIFByb2plY3RzU2VydmljZSkge1xuICAgIC8vQXR0cmlidXRlcyBCbG9ja1xuICAgIHZhciB2bSA9IHRoaXM7XG4gICAgdmFyIGZpZWxkcyA9IFtcbiAgICAgIHsgbmFtZTogJ2lkJywgdHlwZTogJ3N0cmluZycgfSxcbiAgICAgIHsgbmFtZTogJ3N0YXR1cycsIG1hcDogJ3N0YXRlJywgdHlwZTogJ3N0cmluZycgfSxcbiAgICAgIHsgbmFtZTogJ3RleHQnLCBtYXA6ICdsYWJlbCcsIHR5cGU6ICdzdHJpbmcnIH0sXG4gICAgICB7IG5hbWU6ICd0YWdzJywgdHlwZTogJ3N0cmluZycgfVxuICAgIF07XG5cbiAgICB2bS5vbkFjdGl2YXRlID0gZnVuY3Rpb24oKSB7XG4gICAgICB2bS5wcm9qZWN0ID0gbG9jYWxTdG9yYWdlLmdldEl0ZW0oJ3Byb2plY3QnKTtcbiAgICAgIFByb2plY3RzU2VydmljZS5xdWVyeSh7IHByb2plY3RfaWQ6IHZtLnByb2plY3QgfSkudGhlbihmdW5jdGlvbihyZXNwb25zZSkge1xuICAgICAgICB2bS5hY3R1YWxQcm9qZWN0ID0gcmVzcG9uc2VbMF07XG4gICAgICB9KVxuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0geyBwcm9qZWN0X2lkOiB2bS5wcm9qZWN0IH07XG4gICAgICB2bS5pc01vdmVkID0gZmFsc2U7XG4gICAgfVxuXG4gICAgdm0uYXBwbHlGaWx0ZXJzID0gZnVuY3Rpb24oZGVmYXVsdFF1ZXJ5RmlsdGVycykge1xuICAgICAgcmV0dXJuIGFuZ3VsYXIuZXh0ZW5kKGRlZmF1bHRRdWVyeUZpbHRlcnMsIHZtLnF1ZXJ5RmlsdGVycyk7XG4gICAgfVxuXG4gICAgdm0uYWZ0ZXJTZWFyY2ggPSBmdW5jdGlvbiAoKSB7XG4gICAgICB2YXIgY29sdW1ucyA9IFtdO1xuICAgICAgdmFyIHRhc2tzID0gW107XG5cbiAgICAgIFN0YXR1c1NlcnZpY2UucXVlcnkoKS50aGVuKGZ1bmN0aW9uKHJlc3BvbnNlKSB7XG4gICAgICAgIHJlc3BvbnNlLmZvckVhY2goZnVuY3Rpb24oc3RhdHVzKSB7XG4gICAgICAgICAgY29sdW1ucy5wdXNoKHsgdGV4dDogc3RhdHVzLm5hbWUsIGRhdGFGaWVsZDogc3RhdHVzLnNsdWcsIGNvbGxhcHNpYmxlOiBmYWxzZSB9KTtcbiAgICAgICAgfSk7XG5cbiAgICAgICAgaWYgKHZtLnJlc291cmNlcy5sZW5ndGggPiAwKSB7XG4gICAgICAgICAgdm0ucmVzb3VyY2VzLmZvckVhY2goZnVuY3Rpb24odGFzaykge1xuICAgICAgICAgICAgdGFza3MucHVzaCh7XG4gICAgICAgICAgICAgIGlkOiB0YXNrLmlkLFxuICAgICAgICAgICAgICBzdGF0ZTogdGFzay5zdGF0dXMuc2x1ZyxcbiAgICAgICAgICAgICAgbGFiZWw6IHRhc2sudGl0bGUsXG4gICAgICAgICAgICAgIHRhZ3M6IHRhc2sudHlwZS5uYW1lICsgJywgJyArIHRhc2sucHJpb3JpdHkubmFtZVxuICAgICAgICAgICAgfSlcbiAgICAgICAgICB9KTtcblxuICAgICAgICAgIHZhciBzb3VyY2UgPSB7XG4gICAgICAgICAgICBsb2NhbERhdGE6IHRhc2tzLFxuICAgICAgICAgICAgZGF0YVR5cGU6ICdhcnJheScsXG4gICAgICAgICAgICBkYXRhRmllbGRzOiBmaWVsZHNcbiAgICAgICAgICB9O1xuICAgICAgICAgIHZhciBkYXRhQWRhcHRlciA9IG5ldyAkLmpxeC5kYXRhQWRhcHRlcihzb3VyY2UpO1xuXG4gICAgICAgICAgdm0uc2V0dGluZ3MgPSB7XG4gICAgICAgICAgICBzb3VyY2U6IGRhdGFBZGFwdGVyLFxuICAgICAgICAgICAgY29sdW1uczogY29sdW1ucyxcbiAgICAgICAgICAgIHRoZW1lOiAnbGlnaHQnXG4gICAgICAgICAgfTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICB2bS5zZXR0aW5ncyA9IHtcbiAgICAgICAgICAgIHNvdXJjZTogW3t9XSxcbiAgICAgICAgICAgIGNvbHVtbnM6IGNvbHVtbnMsXG4gICAgICAgICAgICB0aGVtZTogJ2xpZ2h0J1xuICAgICAgICAgIH07XG4gICAgICAgIH1cbiAgICAgICAgdm0ua2FuYmFuUmVhZHkgPSB0cnVlO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgdm0ub25JdGVtTW92ZWQgPSBmdW5jdGlvbihldmVudCkge1xuICAgICAgaWYgKCF2bS5hY3R1YWxQcm9qZWN0LmRvbmUgJiYgQXV0aC5jdXJyZW50VXNlci5pZCA9PT0gdm0uYWN0dWFsUHJvamVjdC5vd25lcikge1xuICAgICAgICB2bS5pc01vdmVkID0gdHJ1ZTtcbiAgICAgICAgVGFza3NTZXJ2aWNlLnF1ZXJ5KHsgdGFza19pZDogZXZlbnQuYXJncy5pdGVtSWQgfSkudGhlbihmdW5jdGlvbihyZXNwb25zZSkge1xuICAgICAgICAgIGlmICgocmVzcG9uc2VbMF0ubWlsZXN0b25lICYmIHJlc3BvbnNlWzBdLm1pbGVzdG9uZS5kb25lKSB8fCByZXNwb25zZVswXS5wcm9qZWN0LmRvbmUpIHtcbiAgICAgICAgICAgIFByVG9hc3QuZXJyb3IoJ07Do28gw6kgcG9zc8OtdmVsIG1vZGlmaWNhciBvIHN0YXR1cyBkZSB1bWEgdGFyZWZhIGZpbmFsaXphZGEuJyk7XG4gICAgICAgICAgICB2bS5hZnRlclNlYXJjaCgpO1xuICAgICAgICAgICAgdm0uaXNNb3ZlZCA9IGZhbHNlO1xuICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICBUYXNrc1NlcnZpY2UudXBkYXRlVGFza0J5S2FuYmFuKHtcbiAgICAgICAgICAgICAgcHJvamVjdF9pZDogdm0ucHJvamVjdCxcbiAgICAgICAgICAgICAgaWQ6IGV2ZW50LmFyZ3MuaXRlbUlkLFxuICAgICAgICAgICAgICBvbGRDb2x1bW46IGV2ZW50LmFyZ3Mub2xkQ29sdW1uLFxuICAgICAgICAgICAgICBuZXdDb2x1bW46IGV2ZW50LmFyZ3MubmV3Q29sdW1uIH0pLnRoZW4oZnVuY3Rpb24oKSB7XG4gICAgICAgICAgICAgICAgdm0uaXNNb3ZlZCA9IGZhbHNlO1xuICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICB9XG4gICAgICAgIH0pO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgdm0uYWZ0ZXJTZWFyY2goKTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICB2bS5vbkl0ZW1DbGlja2VkID0gZnVuY3Rpb24oZXZlbnQpIHtcbiAgICAgIGlmICghdm0uaXNNb3ZlZCkge1xuICAgICAgICBUYXNrc1NlcnZpY2UucXVlcnkoeyB0YXNrX2lkOiBldmVudC5hcmdzLml0ZW1JZCB9KS50aGVuKGZ1bmN0aW9uKHJlc3BvbnNlKSB7XG4gICAgICAgICAgdm0udGFza0luZm8gPSByZXNwb25zZVswXTtcbiAgICAgICAgICAkbWREaWFsb2cuc2hvdyh7XG4gICAgICAgICAgICBwYXJlbnQ6IGFuZ3VsYXIuZWxlbWVudCgkZG9jdW1lbnQuYm9keSksXG4gICAgICAgICAgICB0ZW1wbGF0ZVVybDogJ2NsaWVudC9hcHAva2FuYmFuL3Rhc2staW5mby1kaWFsb2cvdGFza0luZm8uaHRtbCcsXG4gICAgICAgICAgICBjb250cm9sbGVyQXM6ICd0YXNrSW5mb0N0cmwnLFxuICAgICAgICAgICAgY29udHJvbGxlcjogJ1Rhc2tJbmZvQ29udHJvbGxlcicsXG4gICAgICAgICAgICBiaW5kVG9Db250cm9sbGVyOiB0cnVlLFxuICAgICAgICAgICAgbG9jYWxzOiB7XG4gICAgICAgICAgICAgIHRhc2s6IHZtLnRhc2tJbmZvLFxuICAgICAgICAgICAgICBjbG9zZTogY2xvc2VcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICBlc2NhcGVUb0Nsb3NlOiB0cnVlLFxuICAgICAgICAgICAgY2xpY2tPdXRzaWRlVG9DbG9zZTogdHJ1ZVxuICAgICAgICAgIH0pO1xuICAgICAgICB9KTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHZtLmlzTW92ZWQgPSBmYWxzZTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICBmdW5jdGlvbiBjbG9zZSgpIHtcbiAgICAgICRtZERpYWxvZy5oaWRlKCk7XG4gICAgfVxuXG4gICAgLy8gaW5zdGFudGlhdGUgYmFzZSBjb250cm9sbGVyXG4gICAgJGNvbnRyb2xsZXIoJ0NSVURDb250cm9sbGVyJywgeyB2bTogdm0sIG1vZGVsU2VydmljZTogVGFza3NTZXJ2aWNlLCBvcHRpb25zOiB7IH0gfSk7XG5cbiAgfVxuXG59KSgpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKlxuICAgKiBBcnF1aXZvIGRlIGNvbmZpZ3VyYcOnw6NvIGNvbSBhcyByb3RhcyBlc3BlY8OtZmljYXMgZG8gcmVjdXJzbyBrYW5iYW5cbiAgICpcbiAgICogQHBhcmFtIHtvYmplY3R9ICRzdGF0ZVByb3ZpZGVyXG4gICAqIEBwYXJhbSB7b2JqZWN0fSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlclxuICAgICAgLnN0YXRlKCdhcHAua2FuYmFuJywge1xuICAgICAgICB1cmw6ICcva2FuYmFuJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9rYW5iYW4va2FuYmFuLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnS2FuYmFuQ29udHJvbGxlciBhcyBrYW5iYW5DdHJsJyxcbiAgICAgICAgZGF0YTogeyB9XG4gICAgICB9KTtcbiAgfVxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5mYWN0b3J5KCdLYW5iYW5TZXJ2aWNlJywgS2FuYmFuU2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiBLYW5iYW5TZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgdmFyIG1vZGVsID0gc2VydmljZUZhY3RvcnkoJ2thbmJhbicsIHtcbiAgICAgIGFjdGlvbnM6IHsgfSxcbiAgICAgIGluc3RhbmNlOiB7IH1cbiAgICB9KTtcblxuICAgIHJldHVybiBtb2RlbDtcbiAgfVxuXG59KCkpO1xuIiwiLyplc2xpbnQtZW52IGVzNiovXG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb250cm9sbGVyKCdNZW51Q29udHJvbGxlcicsIE1lbnVDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIE1lbnVDb250cm9sbGVyKCRtZFNpZGVuYXYsICRzdGF0ZSwgJG1kQ29sb3JzKSB7XG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIC8vQmxvY28gZGUgZGVjbGFyYWNvZXMgZGUgZnVuY29lc1xuICAgIHZtLm9wZW4gPSBvcGVuO1xuICAgIHZtLm9wZW5NZW51T3JSZWRpcmVjdFRvU3RhdGUgPSBvcGVuTWVudU9yUmVkaXJlY3RUb1N0YXRlO1xuXG4gICAgYWN0aXZhdGUoKTtcblxuICAgIGZ1bmN0aW9uIGFjdGl2YXRlKCkge1xuICAgICAgdmFyIG1lbnVQcmVmaXggPSAndmlld3MubGF5b3V0Lm1lbnUuJztcblxuICAgICAgLy8gQXJyYXkgY29udGVuZG8gb3MgaXRlbnMgcXVlIHPDo28gbW9zdHJhZG9zIG5vIG1lbnUgbGF0ZXJhbFxuICAgICAgdm0uaXRlbnNNZW51ID0gW1xuICAgICAgICB7IHN0YXRlOiAnYXBwLnByb2plY3RzJywgdGl0bGU6IG1lbnVQcmVmaXggKyAncHJvamVjdHMnLCBpY29uOiAnd29yaycsIHN1Ykl0ZW5zOiBbXSB9LFxuICAgICAgICB7IHN0YXRlOiAnYXBwLmRhc2hib2FyZCcsIHRpdGxlOiBtZW51UHJlZml4ICsgJ2Rhc2hib2FyZCcsIGljb246ICdkYXNoYm9hcmQnLCBzdWJJdGVuczogW10gfSxcbiAgICAgICAgeyBzdGF0ZTogJ2FwcC50YXNrcycsIHRpdGxlOiBtZW51UHJlZml4ICsgJ3Rhc2tzJywgaWNvbjogJ3ZpZXdfbGlzdCcsIHN1Ykl0ZW5zOiBbXSB9LFxuICAgICAgICB7IHN0YXRlOiAnYXBwLm1pbGVzdG9uZXMnLCB0aXRsZTogbWVudVByZWZpeCArICdtaWxlc3RvbmVzJywgaWNvbjogJ3ZpZXdfbW9kdWxlJywgc3ViSXRlbnM6IFtdIH0sXG4gICAgICAgIHsgc3RhdGU6ICdhcHAucmVsZWFzZXMnLCB0aXRsZTogbWVudVByZWZpeCArICdyZWxlYXNlcycsIGljb246ICdzdWJzY3JpcHRpb25zJywgc3ViSXRlbnM6IFtdIH0sXG4gICAgICAgIHsgc3RhdGU6ICdhcHAua2FuYmFuJywgdGl0bGU6IG1lbnVQcmVmaXggKyAna2FuYmFuJywgaWNvbjogJ3ZpZXdfY29sdW1uJywgc3ViSXRlbnM6IFtdIH0sXG4gICAgICAgIHsgc3RhdGU6ICdhcHAudmNzJywgdGl0bGU6IG1lbnVQcmVmaXggKyAndmNzJywgaWNvbjogJ2dyb3VwX3dvcmsnLCBzdWJJdGVuczogW10gfVxuICAgICAgICAvLyBDb2xvcXVlIHNldXMgaXRlbnMgZGUgbWVudSBhIHBhcnRpciBkZXN0ZSBwb250b1xuICAgICAgICAvKiB7XG4gICAgICAgICAgc3RhdGU6ICcjJywgdGl0bGU6IG1lbnVQcmVmaXggKyAnYWRtaW4nLCBpY29uOiAnc2V0dGluZ3NfYXBwbGljYXRpb25zJywgcHJvZmlsZXM6IFsnYWRtaW4nXSxcbiAgICAgICAgICBzdWJJdGVuczogW1xuICAgICAgICAgICAgeyBzdGF0ZTogJ2FwcC51c2VyJywgdGl0bGU6IG1lbnVQcmVmaXggKyAndXNlcicsIGljb246ICdwZW9wbGUnIH0sXG4gICAgICAgICAgICB7IHN0YXRlOiAnYXBwLm1haWwnLCB0aXRsZTogbWVudVByZWZpeCArICdtYWlsJywgaWNvbjogJ21haWwnIH0sXG4gICAgICAgICAgICB7IHN0YXRlOiAnYXBwLmF1ZGl0JywgdGl0bGU6IG1lbnVQcmVmaXggKyAnYXVkaXQnLCBpY29uOiAnc3RvcmFnZScgfSxcbiAgICAgICAgICAgIHsgc3RhdGU6ICdhcHAuZGluYW1pYy1xdWVyeScsIHRpdGxlOiBtZW51UHJlZml4ICsgJ2RpbmFtaWNRdWVyeScsIGljb246ICdsb2NhdGlvbl9zZWFyY2hpbmcnIH1cbiAgICAgICAgICBdXG4gICAgICAgIH0gKi9cbiAgICAgIF07XG5cbiAgICAgIC8qKlxuICAgICAgICogT2JqZXRvIHF1ZSBwcmVlbmNoZSBvIG5nLXN0eWxlIGRvIG1lbnUgbGF0ZXJhbCB0cm9jYW5kbyBhcyBjb3Jlc1xuICAgICAgICovXG4gICAgICB2bS5zaWRlbmF2U3R5bGUgPSB7XG4gICAgICAgIHRvcDoge1xuICAgICAgICAgICdib3JkZXItYm90dG9tJzogJzFweCBzb2xpZCByZ2IoMjEwLCAyMTAsIDIxMCknLFxuICAgICAgICAgICdiYWNrZ3JvdW5kLWltYWdlJzogJy13ZWJraXQtbGluZWFyLWdyYWRpZW50KHRvcCwgcmdiKDE0NCwgMTQ0LCAxNDQpLCByZ2IoMjEwLCAyMTAsIDIxMCkpJ1xuICAgICAgICB9LFxuICAgICAgICBjb250ZW50OiB7XG4gICAgICAgICAgJ2JhY2tncm91bmQtY29sb3InOiAncmdiKDIxMCwgMjEwLCAyMTApJ1xuICAgICAgICB9LFxuICAgICAgICB0ZXh0Q29sb3I6IHtcbiAgICAgICAgICBjb2xvcjogJyNGRkYnXG4gICAgICAgIH0sXG4gICAgICAgIGxpbmVCb3R0b206IHtcbiAgICAgICAgICAnYm9yZGVyLWJvdHRvbSc6ICcxcHggc29saWQgJyArIGdldENvbG9yKCdwcmltYXJ5LTQwMCcpXG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9XG5cbiAgICBmdW5jdGlvbiBvcGVuKCkge1xuICAgICAgJG1kU2lkZW5hdignbGVmdCcpLnRvZ2dsZSgpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIE3DqXRvZG8gcXVlIGV4aWJlIG8gc3ViIG1lbnUgZG9zIGl0ZW5zIGRvIG1lbnUgbGF0ZXJhbCBjYXNvIHRlbmhhIHN1YiBpdGVuc1xuICAgICAqIGNhc28gY29udHLDoXJpbyByZWRpcmVjaW9uYSBwYXJhIG8gc3RhdGUgcGFzc2FkbyBjb21vIHBhcsODwqJtZXRyb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIG9wZW5NZW51T3JSZWRpcmVjdFRvU3RhdGUoJG1kTWVudSwgZXYsIGl0ZW0pIHtcbiAgICAgIGlmIChhbmd1bGFyLmlzRGVmaW5lZChpdGVtLnN1Ykl0ZW5zKSAmJiBpdGVtLnN1Ykl0ZW5zLmxlbmd0aCA+IDApIHtcbiAgICAgICAgJG1kTWVudS5vcGVuKGV2KTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgICRzdGF0ZS5nbyhpdGVtLnN0YXRlLCB7IG9iajogbnVsbCB9KTtcbiAgICAgICAgJG1kU2lkZW5hdignbGVmdCcpLmNsb3NlKCk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gZ2V0Q29sb3IoY29sb3JQYWxldHRlcykge1xuICAgICAgcmV0dXJuICRtZENvbG9ycy5nZXRUaGVtZUNvbG9yKGNvbG9yUGFsZXR0ZXMpO1xuICAgIH1cblxuICB9XG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb250cm9sbGVyKCdNYWlsc0NvbnRyb2xsZXInLCBNYWlsc0NvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gTWFpbHNDb250cm9sbGVyKE1haWxzU2VydmljZSwgVXNlcnNTZXJ2aWNlLCBQckRpYWxvZywgUHJUb2FzdCwgLy8gTk9TT05BUlxuICAgICRxLCBsb2Rhc2gsICR0cmFuc2xhdGUsIEdsb2JhbCkge1xuXG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIHZtLmZpbHRlclNlbGVjdGVkID0gZmFsc2U7XG4gICAgdm0ub3B0aW9ucyA9IHtcbiAgICAgIHNraW46ICdrYW1hJyxcbiAgICAgIGxhbmd1YWdlOiAncHQtYnInLFxuICAgICAgYWxsb3dlZENvbnRlbnQ6IHRydWUsXG4gICAgICBlbnRpdGllczogdHJ1ZSxcbiAgICAgIGhlaWdodDogMzAwLFxuICAgICAgZXh0cmFQbHVnaW5zOiAnZGlhbG9nLGZpbmQsY29sb3JkaWFsb2cscHJldmlldyxmb3JtcyxpZnJhbWUsZmxhc2gnXG4gICAgfTtcblxuICAgIHZtLmxvYWRVc2VycyA9IGxvYWRVc2VycztcbiAgICB2bS5vcGVuVXNlckRpYWxvZyA9IG9wZW5Vc2VyRGlhbG9nO1xuICAgIHZtLmFkZFVzZXJNYWlsID0gYWRkVXNlck1haWw7XG4gICAgdm0uY2xlYW5Gb3JtID0gY2xlYW5Gb3JtO1xuICAgIHZtLnNlbmQgPSBzZW5kO1xuXG4gICAgYWN0aXZhdGUoKTtcblxuICAgIGZ1bmN0aW9uIGFjdGl2YXRlKCkge1xuICAgICAgdm0uY2xlYW5Gb3JtKCk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhbGl6YSBhIGJ1c2NhIHBlbG8gdXN1w6FyaW8gcmVtb3RhbWVudGVcbiAgICAgKlxuICAgICAqIEBwYXJhbXMge3N0cmluZ30gLSBSZWNlYmUgbyB2YWxvciBwYXJhIHNlciBwZXNxdWlzYWRvXG4gICAgICogQHJldHVybiB7cHJvbWlzc2V9IC0gUmV0b3JuYSB1bWEgcHJvbWlzc2UgcXVlIG8gY29tcG9uZXRlIHJlc29sdmVcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBsb2FkVXNlcnMoY3JpdGVyaWEpIHtcbiAgICAgIHZhciBkZWZlcnJlZCA9ICRxLmRlZmVyKCk7XG5cbiAgICAgIFVzZXJzU2VydmljZS5xdWVyeSh7XG4gICAgICAgIG5hbWVPckVtYWlsOiBjcml0ZXJpYSxcbiAgICAgICAgbm90VXNlcnM6IGxvZGFzaC5tYXAodm0ubWFpbC51c2VycywgbG9kYXNoLnByb3BlcnR5KCdpZCcpKS50b1N0cmluZygpLFxuICAgICAgICBsaW1pdDogNVxuICAgICAgfSkudGhlbihmdW5jdGlvbihkYXRhKSB7XG5cbiAgICAgICAgLy8gdmVyaWZpY2Egc2UgbmEgbGlzdGEgZGUgdXN1YXJpb3MgasOhIGV4aXN0ZSBvIHVzdcOhcmlvIGNvbSBvIGVtYWlsIHBlc3F1aXNhZG9cbiAgICAgICAgZGF0YSA9IGxvZGFzaC5maWx0ZXIoZGF0YSwgZnVuY3Rpb24odXNlcikge1xuICAgICAgICAgIHJldHVybiAhbG9kYXNoLmZpbmQodm0ubWFpbC51c2VycywgeyBlbWFpbDogdXNlci5lbWFpbCB9KTtcbiAgICAgICAgfSk7XG5cbiAgICAgICAgZGVmZXJyZWQucmVzb2x2ZShkYXRhKTtcbiAgICAgIH0pO1xuXG4gICAgICByZXR1cm4gZGVmZXJyZWQucHJvbWlzZTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBBYnJlIG8gZGlhbG9nIHBhcmEgcGVzcXVpc2EgZGUgdXN1w6FyaW9zXG4gICAgICovXG4gICAgZnVuY3Rpb24gb3BlblVzZXJEaWFsb2coKSB7XG4gICAgICB2YXIgY29uZmlnID0ge1xuICAgICAgICBsb2NhbHM6IHtcbiAgICAgICAgICBvbkluaXQ6IHRydWUsXG4gICAgICAgICAgdXNlckRpYWxvZ0lucHV0OiB7XG4gICAgICAgICAgICB0cmFuc2ZlclVzZXJGbjogdm0uYWRkVXNlck1haWxcbiAgICAgICAgICB9XG4gICAgICAgIH0sXG4gICAgICAgIGNvbnRyb2xsZXI6ICdVc2Vyc0RpYWxvZ0NvbnRyb2xsZXInLFxuICAgICAgICBjb250cm9sbGVyQXM6ICdjdHJsJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy91c2Vycy9kaWFsb2cvdXNlcnMtZGlhbG9nLmh0bWwnLFxuICAgICAgICBoYXNCYWNrZHJvcDogdHJ1ZVxuICAgICAgfTtcblxuICAgICAgUHJEaWFsb2cuY3VzdG9tKGNvbmZpZyk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQWRpY2lvbmEgbyB1c3XDoXJpbyBzZWxlY2lvbmFkbyBuYSBsaXN0YSBwYXJhIHF1ZSBzZWphIGVudmlhZG8gbyBlbWFpbFxuICAgICAqL1xuICAgIGZ1bmN0aW9uIGFkZFVzZXJNYWlsKHVzZXIpIHtcbiAgICAgIHZhciB1c2VycyA9IGxvZGFzaC5maW5kKHZtLm1haWwudXNlcnMsIHsgZW1haWw6IHVzZXIuZW1haWwgfSk7XG5cbiAgICAgIGlmICh2bS5tYWlsLnVzZXJzLmxlbmd0aCA+IDAgJiYgYW5ndWxhci5pc0RlZmluZWQodXNlcnMpKSB7XG4gICAgICAgIFByVG9hc3Qud2FybigkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnVzZXIudXNlckV4aXN0cycpKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHZtLm1haWwudXNlcnMucHVzaCh7IG5hbWU6IHVzZXIubmFtZSwgZW1haWw6IHVzZXIuZW1haWwgfSlcbiAgICAgIH1cbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFsaXphIG8gZW52aW8gZG8gZW1haWwgcGFyYSBhIGxpc3RhIGRlIHVzdcOhcmlvcyBzZWxlY2lvbmFkb3NcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBzZW5kKCkge1xuXG4gICAgICB2bS5tYWlsLiRzYXZlKCkudGhlbihmdW5jdGlvbihyZXNwb25zZSkge1xuICAgICAgICBpZiAocmVzcG9uc2UubGVuZ3RoID4gMCkge1xuICAgICAgICAgIHZhciBtc2cgPSAkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLm1haWwubWFpbEVycm9ycycpO1xuXG4gICAgICAgICAgZm9yICh2YXIgaT0wOyBpIDwgcmVzcG9uc2UubGVuZ3RoOyBpKyspIHtcbiAgICAgICAgICAgIG1zZyArPSByZXNwb25zZSArICdcXG4nO1xuICAgICAgICAgIH1cbiAgICAgICAgICBQclRvYXN0LmVycm9yKG1zZyk7XG4gICAgICAgICAgdm0uY2xlYW5Gb3JtKCk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgUHJUb2FzdC5zdWNjZXNzKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMubWFpbC5zZW5kTWFpbFN1Y2Nlc3MnKSk7XG4gICAgICAgICAgdm0uY2xlYW5Gb3JtKCk7XG4gICAgICAgIH1cbiAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIExpbXBhIG8gZm9ybXVsw6FyaW8gZGUgZW1haWxcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBjbGVhbkZvcm0oKSB7XG4gICAgICB2bS5tYWlsID0gbmV3IE1haWxzU2VydmljZSgpO1xuICAgICAgdm0ubWFpbC51c2VycyA9IFtdO1xuICAgIH1cblxuICB9XG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqXG4gICAqIEFycXVpdm8gZGUgY29uZmlndXJhw6fDo28gY29tIGFzIHJvdGFzIGVzcGVjw61maWNhcyBkbyByZWN1cnNvIGVtIHF1ZXN0w6NvXG4gICAqXG4gICAqIEBwYXJhbSB7YW55fSAkc3RhdGVQcm92aWRlclxuICAgKiBAcGFyYW0ge2FueX0gR2xvYmFsXG4gICAqL1xuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvdXRlcygkc3RhdGVQcm92aWRlciwgR2xvYmFsKSB7XG4gICAgJHN0YXRlUHJvdmlkZXJcbiAgICAgIC5zdGF0ZSgnYXBwLm1haWwnLCB7XG4gICAgICAgIHVybDogJy9lbWFpbCcsXG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvbWFpbC9tYWlscy1zZW5kLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnTWFpbHNDb250cm9sbGVyIGFzIG1haWxzQ3RybCcsXG4gICAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiB0cnVlLCBuZWVkUHJvZmlsZTogWydhZG1pbiddIH1cbiAgICAgIH0pO1xuXG4gIH1cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmFjdG9yeSgnTWFpbHNTZXJ2aWNlJywgTWFpbHNTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIE1haWxzU2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHJldHVybiBzZXJ2aWNlRmFjdG9yeSgnbWFpbHMnLCB7fSk7XG4gIH1cblxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnRyb2xsZXIoJ01pbGVzdG9uZXNDb250cm9sbGVyJywgTWlsZXN0b25lc0NvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gTWlsZXN0b25lc0NvbnRyb2xsZXIoJGNvbnRyb2xsZXIsXG4gICAgTWlsZXN0b25lc1NlcnZpY2UsXG4gICAgbW9tZW50LFxuICAgIFRhc2tzU2VydmljZSxcbiAgICBQclRvYXN0LFxuICAgICR0cmFuc2xhdGUsXG4gICAgJG1kRGlhbG9nLFxuICAgIEF1dGgpIHtcblxuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICB2bS5lc3RpbWF0ZWRQcmljZSA9IGVzdGltYXRlZFByaWNlO1xuXG4gICAgdm0ub25BY3RpdmF0ZSA9IGZ1bmN0aW9uKCkge1xuICAgICAgdm0uY3VycmVudFVzZXIgPSBBdXRoLmN1cnJlbnRVc2VyO1xuICAgICAgdm0ucHJvamVjdCA9IGxvY2FsU3RvcmFnZS5nZXRJdGVtKCdwcm9qZWN0Jyk7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMgPSB7IHByb2plY3RfaWQ6IHZtLnByb2plY3QgfTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBlc3RpbWF0ZWRQcmljZShtaWxlc3RvbmUpIHtcbiAgICAgIG1pbGVzdG9uZS5lc3RpbWF0ZWRfdmFsdWUgPSAwO1xuICAgICAgaWYobWlsZXN0b25lLnRhc2tzLmxlbmd0aCA+IDAgJiYgbWlsZXN0b25lLnByb2plY3QuaG91cl92YWx1ZV9maW5hbCkge1xuICAgICAgICBtaWxlc3RvbmUudGFza3MuZm9yRWFjaChmdW5jdGlvbih0YXNrKSB7XG4gICAgICAgICAgbWlsZXN0b25lLmVzdGltYXRlZF92YWx1ZSArPSAocGFyc2VGbG9hdChtaWxlc3RvbmUucHJvamVjdC5ob3VyX3ZhbHVlX2ZpbmFsKSAqIHRhc2suZXN0aW1hdGVkX3RpbWUpO1xuICAgICAgICB9KTtcbiAgICAgIH1cbiAgICAgIHJldHVybiBtaWxlc3RvbmUuZXN0aW1hdGVkX3ZhbHVlLnRvTG9jYWxlU3RyaW5nKCdQdC1icicsIHsgbWluaW11bUZyYWN0aW9uRGlnaXRzOiAyIH0pO1xuICAgIH1cblxuICAgIHZtLmVzdGltYXRlZFRpbWUgPSBmdW5jdGlvbiAobWlsZXN0b25lKSB7XG4gICAgICBtaWxlc3RvbmUuZXN0aW1hdGVkX3RpbWUgPSAwO1xuICAgICAgaWYobWlsZXN0b25lLnRhc2tzLmxlbmd0aCA+IDApIHtcbiAgICAgICAgbWlsZXN0b25lLnRhc2tzLmZvckVhY2goZnVuY3Rpb24odGFzaykge1xuICAgICAgICAgIG1pbGVzdG9uZS5lc3RpbWF0ZWRfdGltZSArPSB0YXNrLmVzdGltYXRlZF90aW1lO1xuICAgICAgICB9KTtcbiAgICAgIH1cbiAgICAgIG1pbGVzdG9uZS5lc3RpbWF0ZWRfdGltZSA9IG1pbGVzdG9uZS5lc3RpbWF0ZWRfdGltZSAvIDg7XG4gICAgICB2YXIgZGF0ZUVuZCA9IG1vbWVudChtaWxlc3RvbmUuZGF0ZV9lbmQpO1xuICAgICAgdmFyIGRhdGVCZWdpbiA9IG1vbWVudChtaWxlc3RvbmUuZGF0ZV9iZWdpbik7XG5cbiAgICAgIGlmIChkYXRlRW5kLmRpZmYoZGF0ZUJlZ2luLCAnZGF5cycpIDw9IG1pbGVzdG9uZS5lc3RpbWF0ZWRfdGltZSkge1xuICAgICAgICBtaWxlc3RvbmUuY29sb3JfZXN0aW1hdGVkX3RpbWUgPSB7IGNvbG9yOiAncmVkJyB9O1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgbWlsZXN0b25lLmNvbG9yX2VzdGltYXRlZF90aW1lID0geyBjb2xvcjogJ2dyZWVuJyB9O1xuICAgICAgfVxuICAgICAgcmV0dXJuIG1pbGVzdG9uZS5lc3RpbWF0ZWRfdGltZTtcbiAgICB9XG5cbiAgICB2bS5hcHBseUZpbHRlcnMgPSBmdW5jdGlvbihkZWZhdWx0UXVlcnlGaWx0ZXJzKSB7XG4gICAgICByZXR1cm4gYW5ndWxhci5leHRlbmQoZGVmYXVsdFF1ZXJ5RmlsdGVycywgdm0ucXVlcnlGaWx0ZXJzKTtcbiAgICB9XG5cbiAgICB2bS5iZWZvcmVTYXZlID0gZnVuY3Rpb24oKSB7XG4gICAgICB2bS5yZXNvdXJjZS5wcm9qZWN0X2lkID0gdm0ucHJvamVjdDtcbiAgICB9XG5cbiAgICB2bS5iZWZvcmVSZW1vdmUgPSBmdW5jdGlvbigpIHtcbiAgICAgIHZtLnJlc291cmNlLnByb2plY3RfaWQgPSB2bS5wcm9qZWN0O1xuICAgIH1cblxuICAgIHZtLmZvcm1hdERhdGUgPSBmdW5jdGlvbihkYXRlKSB7XG4gICAgICByZXR1cm4gbW9tZW50KGRhdGUpLmZvcm1hdCgnREQvTU0vWVlZWScpO1xuICAgIH1cblxuICAgIHZtLmFmdGVyRWRpdCA9IGZ1bmN0aW9uKCkge1xuICAgICAgdm0ucmVzb3VyY2UuZGF0ZV9iZWdpbiA9IG1vbWVudCh2bS5yZXNvdXJjZS5kYXRlX2JlZ2luKTtcbiAgICAgIHZtLnJlc291cmNlLmRhdGVfZW5kID0gbW9tZW50KHZtLnJlc291cmNlLmRhdGVfZW5kKTtcbiAgICB9XG5cbiAgICB2bS52aWV3ID0gZnVuY3Rpb24gKHJlc291cmNlKSB7XG4gICAgICByZXNvdXJjZS5kYXRlX2JlZ2luID0gbW9tZW50KHJlc291cmNlLmRhdGVfYmVnaW4pO1xuICAgICAgcmVzb3VyY2UuZGF0ZV9lbmQgPSBtb21lbnQocmVzb3VyY2UuZGF0ZV9lbmQpO1xuICAgICAgdm0ucmVzb3VyY2UgPSByZXNvdXJjZTtcbiAgICAgIHZtLm9uVmlldyA9IHRydWU7XG4gICAgICB2bS52aWV3Rm9ybSA9IGZhbHNlO1xuICAgIH1cblxuICAgIHZtLnNlYXJjaFRhc2sgPSBmdW5jdGlvbiAodGFza1Rlcm0pIHtcbiAgICAgIHJldHVybiBUYXNrc1NlcnZpY2UucXVlcnkoe1xuICAgICAgICBtaWxlc3RvbmVTZWFyY2g6IHRydWUsXG4gICAgICAgIHByb2plY3RfaWQ6IHZtLnJlc291cmNlLnByb2plY3RfaWQsXG4gICAgICAgIHRpdGxlOiB0YXNrVGVybVxuICAgICAgfSk7XG4gICAgfVxuXG4gICAgdm0ub25UYXNrQ2hhbmdlID0gZnVuY3Rpb24oKSB7XG4gICAgICBpZiAodm0udGFzayAhPT0gbnVsbCAmJiB2bS5yZXNvdXJjZS50YXNrcy5maW5kSW5kZXgoaSA9PiBpLmlkID09PSB2bS50YXNrLmlkKSA9PT0gLTEpIHtcbiAgICAgICAgdm0ucmVzb3VyY2UudGFza3MucHVzaCh2bS50YXNrKTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICB2bS5yZW1vdmVUYXNrID0gZnVuY3Rpb24odGFzaykge1xuICAgICAgdm0ucmVzb3VyY2UudGFza3Muc2xpY2UoMCkuZm9yRWFjaChmdW5jdGlvbihlbGVtZW50KSB7XG4gICAgICAgIGlmKGVsZW1lbnQuaWQgPT09IHRhc2suaWQpIHtcbiAgICAgICAgICB2bS5yZXNvdXJjZS50YXNrcy5zcGxpY2Uodm0ucmVzb3VyY2UudGFza3MuaW5kZXhPZihlbGVtZW50KSwgMSk7XG4gICAgICAgIH1cbiAgICAgIH0pO1xuICAgIH1cblxuICAgIHZtLnNhdmVUYXNrcyA9IGZ1bmN0aW9uKCkge1xuICAgICAgVGFza3NTZXJ2aWNlLnVwZGF0ZU1pbGVzdG9uZSh7cHJvamVjdF9pZDogdm0ucmVzb3VyY2UucHJvamVjdF9pZCwgbWlsZXN0b25lX2lkOiB2bS5yZXNvdXJjZS5pZCwgdGFza3M6IHZtLnJlc291cmNlLnRhc2tzfSkudGhlbihmdW5jdGlvbigpe1xuICAgICAgICBQclRvYXN0LnN1Y2Nlc3MoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5zYXZlU3VjY2VzcycpKTtcbiAgICAgICAgdm0udmlld0Zvcm0gPSBmYWxzZTtcbiAgICAgICAgdm0ub25WaWV3ID0gZmFsc2U7XG4gICAgICB9LCBmdW5jdGlvbigpIHtcbiAgICAgICAgUHJUb2FzdC5lcnJvcigkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLm9wZXJhdGlvbkVycm9yJykpO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgdm0uZmluYWxpemUgPSBmdW5jdGlvbihtaWxlc3RvbmUpIHtcbiAgICAgIHZhciBjb25maXJtID0gJG1kRGlhbG9nLmNvbmZpcm0oKVxuICAgICAgICAgIC50aXRsZSgnRmluYWxpemFyIFNwcmludCcpXG4gICAgICAgICAgLnRleHRDb250ZW50KCdUZW0gY2VydGV6YSBxdWUgZGVzZWphIGZpbmFsaXphciBhIHNwcmludCAnICsgbWlsZXN0b25lLnRpdGxlICsgJz8nKVxuICAgICAgICAgIC5vaygnU2ltJylcbiAgICAgICAgICAuY2FuY2VsKCdOw6NvJyk7XG5cbiAgICAgICRtZERpYWxvZy5zaG93KGNvbmZpcm0pLnRoZW4oZnVuY3Rpb24oKSB7XG4gICAgICAgIE1pbGVzdG9uZXNTZXJ2aWNlLmZpbmFsaXplKHsgcHJvamVjdF9pZDogdm0ucHJvamVjdCwgbWlsZXN0b25lX2lkOiBtaWxlc3RvbmUuaWQgfSkudGhlbihmdW5jdGlvbigpIHtcbiAgICAgICAgICBQclRvYXN0LnN1Y2Nlc3MoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5zcHJpbnRFbmRlZFN1Y2Nlc3MnKSk7XG4gICAgICAgICAgdm0uc2VhcmNoKCk7XG4gICAgICAgIH0sIGZ1bmN0aW9uKCkge1xuICAgICAgICAgIFByVG9hc3QuRXJyb3IoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5zcHJpbnRFbmRlZEVycm9yJykpO1xuICAgICAgICB9KTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIC8vIGluc3RhbnRpYXRlIGJhc2UgY29udHJvbGxlclxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHsgdm06IHZtLCBtb2RlbFNlcnZpY2U6IE1pbGVzdG9uZXNTZXJ2aWNlLCBvcHRpb25zOiB7IH0gfSk7XG5cbiAgfVxuXG59KSgpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKlxuICAgKiBBcnF1aXZvIGRlIGNvbmZpZ3VyYcOnw6NvIGNvbSBhcyByb3RhcyBlc3BlY8OtZmljYXMgZG8gcmVjdXJzbyBtaWxlc3RvbmVzXG4gICAqXG4gICAqIEBwYXJhbSB7b2JqZWN0fSAkc3RhdGVQcm92aWRlclxuICAgKiBAcGFyYW0ge29iamVjdH0gR2xvYmFsXG4gICAqL1xuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvdXRlcygkc3RhdGVQcm92aWRlciwgR2xvYmFsKSB7XG4gICAgJHN0YXRlUHJvdmlkZXJcbiAgICAgIC5zdGF0ZSgnYXBwLm1pbGVzdG9uZXMnLCB7XG4gICAgICAgIHVybDogJy9taWxlc3RvbmVzJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9taWxlc3RvbmVzL21pbGVzdG9uZXMuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdNaWxlc3RvbmVzQ29udHJvbGxlciBhcyBtaWxlc3RvbmVzQ3RybCcsXG4gICAgICAgIGRhdGE6IHsgfVxuICAgICAgfSk7XG4gIH1cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmFjdG9yeSgnTWlsZXN0b25lc1NlcnZpY2UnLCBNaWxlc3RvbmVzU2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiBNaWxlc3RvbmVzU2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHZhciBtb2RlbCA9IHNlcnZpY2VGYWN0b3J5KCdtaWxlc3RvbmVzJywge1xuICAgICAgYWN0aW9uczoge1xuICAgICAgICBmaW5hbGl6ZToge1xuICAgICAgICAgIG1ldGhvZDogJ1BPU1QnLFxuICAgICAgICAgIHVybDogJ2ZpbmFsaXplJ1xuICAgICAgICB9LFxuICAgICAgICB1cGRhdGVSZWxlYXNlOiB7XG4gICAgICAgICAgbWV0aG9kOiAnUE9TVCcsXG4gICAgICAgICAgdXJsOiAndXBkYXRlUmVsZWFzZSdcbiAgICAgICAgfVxuICAgICAgfSxcbiAgICAgIGluc3RhbmNlOiB7IH1cbiAgICB9KTtcblxuICAgIHJldHVybiBtb2RlbDtcbiAgfVxuXG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZhY3RvcnkoJ1ByaW9yaXRpZXNTZXJ2aWNlJywgUHJpb3JpdGllc1NlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gUHJpb3JpdGllc1NlcnZpY2Uoc2VydmljZUZhY3RvcnkpIHtcbiAgICB2YXIgbW9kZWwgPSBzZXJ2aWNlRmFjdG9yeSgncHJpb3JpdGllcycsIHtcbiAgICAgIGFjdGlvbnM6IHsgfSxcbiAgICAgIGluc3RhbmNlOiB7IH1cbiAgICB9KTtcblxuICAgIHJldHVybiBtb2RlbDtcbiAgfVxuXG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29udHJvbGxlcignUHJvamVjdHNDb250cm9sbGVyJywgUHJvamVjdHNDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIFByb2plY3RzQ29udHJvbGxlcigkY29udHJvbGxlcixcbiAgICBQcm9qZWN0c1NlcnZpY2UsXG4gICAgQXV0aCxcbiAgICBSb2xlc1NlcnZpY2UsXG4gICAgVXNlcnNTZXJ2aWNlLFxuICAgICRzdGF0ZSxcbiAgICAkZmlsdGVyLFxuICAgICRzdGF0ZVBhcmFtcyxcbiAgICAkd2luZG93KSB7XG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIC8vQXR0cmlidXRlcyBCbG9ja1xuXG4gICAgLy9GdW5jdGlvbnMgQmxvY2tcbiAgICB2bS5vbkFjdGl2YXRlID0gb25BY3RpdmF0ZTtcbiAgICB2bS5hcHBseUZpbHRlcnMgPSBhcHBseUZpbHRlcnM7XG4gICAgdm0uYmVmb3JlU2F2ZSA9IGJlZm9yZVNhdmU7XG4gICAgdm0uc2VhcmNoVXNlciA9IHNlYXJjaFVzZXI7XG4gICAgdm0uYWRkVXNlciA9IGFkZFVzZXI7XG4gICAgdm0ucmVtb3ZlVXNlciA9IHJlbW92ZVVzZXI7XG4gICAgdm0udmlld1Byb2plY3QgPSB2aWV3UHJvamVjdDtcblxuICAgIHZtLnJvbGVzID0ge307XG4gICAgdm0udXNlcnMgPSBbXTtcblxuICAgIGZ1bmN0aW9uIG9uQWN0aXZhdGUoKSB7XG4gICAgICB2bS5jdXJyZW50VXNlciA9IEF1dGguY3VycmVudFVzZXI7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMgPSB7IHVzZXJfaWQ6IHZtLmN1cnJlbnRVc2VyLmlkIH07XG4gICAgICBSb2xlc1NlcnZpY2UucXVlcnkoKS50aGVuKGZ1bmN0aW9uKHJlc3BvbnNlKSB7XG4gICAgICAgIHZtLnJvbGVzID0gcmVzcG9uc2U7XG4gICAgICAgIGlmICgkc3RhdGVQYXJhbXMub2JqID09PSAnZWRpdCcpIHtcbiAgICAgICAgICB2bS5jbGVhbkZvcm0oKTtcbiAgICAgICAgICB2bS52aWV3Rm9ybSA9IHRydWU7XG4gICAgICAgICAgdm0ucmVzb3VyY2UgPSAkc3RhdGVQYXJhbXMucmVzb3VyY2U7XG4gICAgICAgICAgdXNlcnNBcnJheSh2bS5yZXNvdXJjZSk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oJ3Byb2plY3QnKTtcbiAgICAgICAgfVxuICAgICAgfSk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gYXBwbHlGaWx0ZXJzKGRlZmF1bHRRdWVyeUZpbHRlcnMpIHtcbiAgICAgIHJldHVybiBhbmd1bGFyLmV4dGVuZChkZWZhdWx0UXVlcnlGaWx0ZXJzLCB2bS5xdWVyeWx0ZXJzKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBiZWZvcmVTYXZlKCkge1xuICAgICAgaWYgKCF2bS5yZXNvdXJjZS5vd25lcikge1xuICAgICAgICB2bS5yZXNvdXJjZS5vd25lciA9IEF1dGguY3VycmVudFVzZXIuaWQ7XG4gICAgICB9XG4gICAgICB2bS5yZXNvdXJjZS51c2VyX2lkID0gQXV0aC5jdXJyZW50VXNlci5pZDtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBzZWFyY2hVc2VyKCkge1xuICAgICAgcmV0dXJuIFVzZXJzU2VydmljZS5xdWVyeSh7IG5hbWU6IHZtLnVzZXJOYW1lIH0pO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGFkZFVzZXIodXNlcikge1xuICAgICAgaWYgKHVzZXIpIHtcbiAgICAgICAgdm0ucmVzb3VyY2UudXNlcnMucHVzaCh1c2VyKTtcbiAgICAgICAgdm0udXNlck5hbWUgPSAnJztcbiAgICAgIH1cbiAgICB9XG5cbiAgICBmdW5jdGlvbiByZW1vdmVVc2VyKGluZGV4KSB7XG4gICAgICB2bS5yZXNvdXJjZS51c2Vycy5zcGxpY2UoaW5kZXgsIDEpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGFwcGx5RmlsdGVycyhkZWZhdWx0UXVlcnlGaWx0ZXJzKSB7XG4gICAgICByZXR1cm4gYW5ndWxhci5leHRlbmQoZGVmYXVsdFF1ZXJ5RmlsdGVycywgdm0ucXVlcnlGaWx0ZXJzKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiB2aWV3UHJvamVjdCgpIHtcbiAgICAgICRzdGF0ZS5nbygnYXBwLmRhc2hib2FyZCcpO1xuICAgIH1cblxuICAgIHZtLmFmdGVyU2VhcmNoID0gZnVuY3Rpb24oKSB7XG4gICAgICBpZiAodm0ucmVzb3VyY2VzLmxlbmd0aCA+IDApIHtcbiAgICAgICAgdm0ucmVzb3VyY2VzLmZvckVhY2goZnVuY3Rpb24ocHJvamVjdCkge1xuICAgICAgICAgIHVzZXJzQXJyYXkocHJvamVjdCk7XG4gICAgICAgIH0pO1xuICAgICAgfVxuICAgIH1cblxuICAgIGZ1bmN0aW9uIHVzZXJzQXJyYXkocHJvamVjdCkge1xuICAgICAgcHJvamVjdC51c2VycyA9IFtdO1xuICAgICAgaWYgKHByb2plY3QuY2xpZW50X2lkKSB7XG4gICAgICAgIHByb2plY3QuY2xpZW50LnJvbGUgPSAkZmlsdGVyKCdmaWx0ZXInKSh2bS5yb2xlcywgeyBzbHVnOiAnY2xpZW50JyB9KVswXTtcbiAgICAgICAgcHJvamVjdC51c2Vycy5wdXNoKHByb2plY3QuY2xpZW50KTtcbiAgICAgIH1cbiAgICAgIGlmIChwcm9qZWN0LmRldl9pZCkge1xuICAgICAgICBwcm9qZWN0LmRldmVsb3Blci5yb2xlID0gJGZpbHRlcignZmlsdGVyJykodm0ucm9sZXMsIHsgc2x1ZzogJ2RldicgfSlbMF07XG4gICAgICAgIHByb2plY3QudXNlcnMucHVzaChwcm9qZWN0LmRldmVsb3Blcik7XG4gICAgICB9XG4gICAgICBpZiAocHJvamVjdC5zdGFrZWhvbGRlcl9pZCkge1xuICAgICAgICBwcm9qZWN0LnN0YWtlaG9sZGVyLnJvbGUgPSAkZmlsdGVyKCdmaWx0ZXInKSh2bS5yb2xlcywgeyBzbHVnOiAnc3Rha2Vob2xkZXInIH0pWzBdO1xuICAgICAgICBwcm9qZWN0LnVzZXJzLnB1c2gocHJvamVjdC5zdGFrZWhvbGRlcik7XG4gICAgICB9XG4gICAgfVxuXG4gICAgdm0uaGlzdG9yeUJhY2sgPSBmdW5jdGlvbigpIHtcbiAgICAgICR3aW5kb3cuaGlzdG9yeS5iYWNrKCk7XG4gICAgfVxuXG4gICAgdm0uYWZ0ZXJTYXZlID0gZnVuY3Rpb24ocmVzb3VyY2UpIHtcbiAgICAgIGxvY2FsU3RvcmFnZS5zZXRJdGVtKCdwcm9qZWN0JywgcmVzb3VyY2UuaWQpO1xuICAgICAgJHN0YXRlLmdvKCdhcHAuZGFzaGJvYXJkJyk7XG4gICAgfVxuXG4gICAgLy8gaW5zdGFudGlhdGUgYmFzZSBjb250cm9sbGVyXG4gICAgJGNvbnRyb2xsZXIoJ0NSVURDb250cm9sbGVyJywgeyB2bTogdm0sIG1vZGVsU2VydmljZTogUHJvamVjdHNTZXJ2aWNlLCBvcHRpb25zOiB7IHJlZGlyZWN0QWZ0ZXJTYXZlOiBmYWxzZSB9IH0pO1xuICB9XG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqXG4gICAqIEFycXVpdm8gZGUgY29uZmlndXJhw6fDo28gY29tIGFzIHJvdGFzIGVzcGVjw61maWNhcyBkbyByZWN1cnNvIHByb2plY3RcbiAgICpcbiAgICogQHBhcmFtIHthbnl9ICRzdGF0ZVByb3ZpZGVyXG4gICAqIEBwYXJhbSB7YW55fSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlclxuICAgICAgLnN0YXRlKCdhcHAucHJvamVjdHMnLCB7XG4gICAgICAgIHVybDogJy9wcm9qZWN0cycsXG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvcHJvamVjdHMvcHJvamVjdHMuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdQcm9qZWN0c0NvbnRyb2xsZXIgYXMgcHJvamVjdHNDdHJsJyxcbiAgICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IHRydWUgfSxcbiAgICAgICAgcGFyYW1zOiB7IG9iajogbnVsbCwgcmVzb3VyY2U6IG51bGwgfVxuICAgICAgfSk7XG4gIH1cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmFjdG9yeSgnUHJvamVjdHNTZXJ2aWNlJywgUHJvamVjdHNTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIFByb2plY3RzU2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHJldHVybiBzZXJ2aWNlRmFjdG9yeSgncHJvamVjdHMnLCB7XG4gICAgICBhY3Rpb25zOiB7XG4gICAgICAgIGZpbmFsaXplOiB7XG4gICAgICAgICAgbWV0aG9kOiAnUE9TVCcsXG4gICAgICAgICAgdXJsOiAnZmluYWxpemUnXG4gICAgICAgIH0sXG4gICAgICAgIHZlcmlmeVJlbGVhc2VzOiB7XG4gICAgICAgICAgbWV0aG9kOiAnUE9TVCcsXG4gICAgICAgICAgdXJsOiAndmVyaWZ5UmVsZWFzZXMnXG4gICAgICAgIH1cbiAgICAgIH0sXG4gICAgICBpbnN0YW5jZTogeyB9XG4gICAgfSk7XG4gIH1cblxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnRyb2xsZXIoJ1JlbGVhc2VzQ29udHJvbGxlcicsIFJlbGVhc2VzQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBSZWxlYXNlc0NvbnRyb2xsZXIoJGNvbnRyb2xsZXIsXG4gICAgUmVsZWFzZXNTZXJ2aWNlLFxuICAgIE1pbGVzdG9uZXNTZXJ2aWNlLFxuICAgIEF1dGgsXG4gICAgUHJUb2FzdCxcbiAgICBtb21lbnQsXG4gICAgJG1kRGlhbG9nLFxuICAgICR0cmFuc2xhdGUpIHtcbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgLy9BdHRyaWJ1dGVzIEJsb2NrXG5cbiAgICAvL0Z1bmN0aW9ucyBCbG9ja1xuICAgIHZtLm9uQWN0aXZhdGUgPSBmdW5jdGlvbigpIHtcbiAgICAgIHZtLmN1cnJlbnRVc2VyID0gQXV0aC5jdXJyZW50VXNlcjtcbiAgICAgIHZtLnByb2plY3QgPSBsb2NhbFN0b3JhZ2UuZ2V0SXRlbSgncHJvamVjdCcpO1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0geyBwcm9qZWN0X2lkOiB2bS5wcm9qZWN0IH07XG4gICAgfVxuXG4gICAgdm0uYmVmb3JlU2F2ZSA9IGZ1bmN0aW9uKCkge1xuICAgICAgdm0ucmVzb3VyY2UucHJvamVjdF9pZCA9IHZtLnByb2plY3Q7XG4gICAgfVxuXG4gICAgdm0uYmVmb3JlUmVtb3ZlID0gZnVuY3Rpb24oKSB7XG4gICAgICB2bS5yZXNvdXJjZS5wcm9qZWN0X2lkID0gdm0ucHJvamVjdDtcbiAgICB9XG5cbiAgICB2bS52aWV3ID0gZnVuY3Rpb24gKHJlc291cmNlKSB7XG4gICAgICB2bS5yZXNvdXJjZSA9IHJlc291cmNlO1xuICAgICAgdm0ub25WaWV3ID0gdHJ1ZTtcbiAgICAgIHZtLnZpZXdGb3JtID0gZmFsc2U7XG4gICAgfVxuXG4gICAgdm0uZmluYWxpemUgPSBmdW5jdGlvbihyZWxlYXNlKSB7XG4gICAgICB2YXIgY29uZmlybSA9ICRtZERpYWxvZy5jb25maXJtKClcbiAgICAgICAgICAudGl0bGUoJ0ZpbmFsaXphciBSZWxlYXNlJylcbiAgICAgICAgICAudGV4dENvbnRlbnQoJ1RlbSBjZXJ0ZXphIHF1ZSBkZXNlamEgZmluYWxpemFyIGEgcmVsZWFzZSAnICsgcmVsZWFzZS50aXRsZSArICc/JylcbiAgICAgICAgICAub2soJ1NpbScpXG4gICAgICAgICAgLmNhbmNlbCgnTsOjbycpO1xuXG4gICAgICAkbWREaWFsb2cuc2hvdyhjb25maXJtKS50aGVuKGZ1bmN0aW9uKCkge1xuICAgICAgICBSZWxlYXNlc1NlcnZpY2UuZmluYWxpemUoeyBwcm9qZWN0X2lkOiB2bS5wcm9qZWN0LCByZWxlYXNlX2lkOiByZWxlYXNlLmlkIH0pLnRoZW4oZnVuY3Rpb24oKSB7XG4gICAgICAgICAgUHJUb2FzdC5zdWNjZXNzKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMucmVsZWFzZUVuZGVkU3VjY2VzcycpKTtcbiAgICAgICAgICB2bS5zZWFyY2goKTtcbiAgICAgICAgfSwgZnVuY3Rpb24oKSB7XG4gICAgICAgICAgUHJUb2FzdC5FcnJvcigkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnJlbGVhc2VFbmRlZEVycm9yJykpO1xuICAgICAgICB9KTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIHZtLmZvcm1hdERhdGUgPSBmdW5jdGlvbihkYXRlKSB7XG4gICAgICByZXR1cm4gbW9tZW50KGRhdGUpLmZvcm1hdCgnREQvTU0vWVlZWScpO1xuICAgIH1cblxuICAgIHZtLnNlYXJjaE1pbGVzdG9uZSA9IGZ1bmN0aW9uIChtaWxlc3RvbmVUZXJtKSB7XG4gICAgICByZXR1cm4gTWlsZXN0b25lc1NlcnZpY2UucXVlcnkoe1xuICAgICAgICByZWxlYXNlU2VhcmNoOiB0cnVlLFxuICAgICAgICBwcm9qZWN0X2lkOiB2bS5yZXNvdXJjZS5wcm9qZWN0X2lkLFxuICAgICAgICB0aXRsZTogbWlsZXN0b25lVGVybVxuICAgICAgfSk7XG4gICAgfVxuXG4gICAgdm0ub25NaWxlc3RvbmVDaGFuZ2UgPSBmdW5jdGlvbigpIHtcbiAgICAgIGlmICh2bS5taWxlc3RvbmUgIT09IG51bGwgJiYgdm0ucmVzb3VyY2UubWlsZXN0b25lcy5maW5kSW5kZXgoaSA9PiBpLmlkID09PSB2bS5taWxlc3RvbmUuaWQpID09PSAtMSkge1xuICAgICAgICB2bS5yZXNvdXJjZS5taWxlc3RvbmVzLnB1c2godm0ubWlsZXN0b25lKTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICB2bS5yZW1vdmVNaWxlc3RvbmUgPSBmdW5jdGlvbihtaWxlc3RvbmUpIHtcbiAgICAgIHZtLnJlc291cmNlLm1pbGVzdG9uZXMuc2xpY2UoMCkuZm9yRWFjaChmdW5jdGlvbihlbGVtZW50KSB7XG4gICAgICAgIGlmKGVsZW1lbnQuaWQgPT09IG1pbGVzdG9uZS5pZCkge1xuICAgICAgICAgIHZtLnJlc291cmNlLm1pbGVzdG9uZXMuc3BsaWNlKHZtLnJlc291cmNlLm1pbGVzdG9uZXMuaW5kZXhPZihlbGVtZW50KSwgMSk7XG4gICAgICAgIH1cbiAgICAgIH0pO1xuICAgIH1cblxuICAgIHZtLnNhdmVNaWxlc3RvbmVzID0gZnVuY3Rpb24oKSB7XG4gICAgICBNaWxlc3RvbmVzU2VydmljZS51cGRhdGVSZWxlYXNlKHtwcm9qZWN0X2lkOiB2bS5yZXNvdXJjZS5wcm9qZWN0X2lkLCByZWxlYXNlX2lkOiB2bS5yZXNvdXJjZS5pZCwgbWlsZXN0b25lczogdm0ucmVzb3VyY2UubWlsZXN0b25lc30pLnRoZW4oZnVuY3Rpb24oKXtcbiAgICAgICAgUHJUb2FzdC5zdWNjZXNzKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMuc2F2ZVN1Y2Nlc3MnKSk7XG4gICAgICAgIHZtLnZpZXdGb3JtID0gZmFsc2U7XG4gICAgICAgIHZtLm9uVmlldyA9IGZhbHNlO1xuICAgICAgfSwgZnVuY3Rpb24oKSB7XG4gICAgICAgIFByVG9hc3QuZXJyb3IoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5vcGVyYXRpb25FcnJvcicpKTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIHZtLmVzdGltYXRlZFRpbWUgPSBmdW5jdGlvbiAobWlsZXN0b25lKSB7XG4gICAgICBtaWxlc3RvbmUuZXN0aW1hdGVkX3RpbWUgPSAwO1xuICAgICAgaWYobWlsZXN0b25lLnRhc2tzLmxlbmd0aCA+IDApIHtcbiAgICAgICAgbWlsZXN0b25lLnRhc2tzLmZvckVhY2goZnVuY3Rpb24odGFzaykge1xuICAgICAgICAgIG1pbGVzdG9uZS5lc3RpbWF0ZWRfdGltZSArPSB0YXNrLmVzdGltYXRlZF90aW1lO1xuICAgICAgICB9KTtcbiAgICAgIH1cbiAgICAgIHJldHVybiBtaWxlc3RvbmUuZXN0aW1hdGVkX3RpbWUgLyA4O1xuICAgIH1cblxuICAgIC8vIGluc3RhbnRpYXRlIGJhc2UgY29udHJvbGxlclxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHsgdm06IHZtLCBtb2RlbFNlcnZpY2U6IFJlbGVhc2VzU2VydmljZSwgb3B0aW9uczogeyB9IH0pO1xuXG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb25maWcocm91dGVzKTtcblxuICAvKipcbiAgICogQXJxdWl2byBkZSBjb25maWd1cmHDp8OjbyBjb20gYXMgcm90YXMgZXNwZWPDrWZpY2FzIGRvIHJlY3Vyc28gcmVsZWFzZXNcbiAgICpcbiAgICogQHBhcmFtIHtvYmplY3R9ICRzdGF0ZVByb3ZpZGVyXG4gICAqIEBwYXJhbSB7b2JqZWN0fSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlclxuICAgICAgLnN0YXRlKCdhcHAucmVsZWFzZXMnLCB7XG4gICAgICAgIHVybDogJy9yZWxlYXNlcycsXG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvcmVsZWFzZXMvcmVsZWFzZXMuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdSZWxlYXNlc0NvbnRyb2xsZXIgYXMgcmVsZWFzZXNDdHJsJyxcbiAgICAgICAgZGF0YTogeyB9XG4gICAgICB9KTtcbiAgfVxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5mYWN0b3J5KCdSZWxlYXNlc1NlcnZpY2UnLCBSZWxlYXNlc1NlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gUmVsZWFzZXNTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgdmFyIG1vZGVsID0gc2VydmljZUZhY3RvcnkoJ3JlbGVhc2VzJywge1xuICAgICAgYWN0aW9uczoge1xuICAgICAgICBmaW5hbGl6ZToge1xuICAgICAgICAgIG1ldGhvZDogJ1BPU1QnLFxuICAgICAgICAgIHVybDogJ2ZpbmFsaXplJ1xuICAgICAgICB9XG4gICAgICB9LFxuICAgICAgaW5zdGFuY2U6IHsgfVxuICAgIH0pO1xuXG4gICAgcmV0dXJuIG1vZGVsO1xuICB9XG5cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5maWx0ZXIoJ3JvbGVzU3RyJywgcm9sZXNTdHIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm9sZXNTdHIobG9kYXNoKSB7XG4gICAgLyoqXG4gICAgICogQHBhcmFtIHthcnJheX0gcm9sZXMgbGlzdGEgZGUgcGVyZmlzXG4gICAgICogQHJldHVybiB7c3RyaW5nfSBwZXJmaXMgc2VwYXJhZG9zIHBvciAnLCAnICBcbiAgICAgKi9cbiAgICByZXR1cm4gZnVuY3Rpb24ocm9sZXMpIHtcbiAgICAgIHJldHVybiBsb2Rhc2gubWFwKHJvbGVzLCAnc2x1ZycpLmpvaW4oJywgJyk7XG4gICAgfTtcbiAgfVxuXG59KSgpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZhY3RvcnkoJ1JvbGVzU2VydmljZScsIFJvbGVzU2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiBSb2xlc1NlcnZpY2Uoc2VydmljZUZhY3RvcnkpIHtcbiAgICByZXR1cm4gc2VydmljZUZhY3RvcnkoJ3JvbGVzJyk7XG4gIH1cblxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5mYWN0b3J5KCdTdGF0dXNTZXJ2aWNlJywgU3RhdHVzU2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiBTdGF0dXNTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgdmFyIG1vZGVsID0gc2VydmljZUZhY3RvcnkoJ3N0YXR1cycsIHtcbiAgICAgIGFjdGlvbnM6IHsgfSxcbiAgICAgIGluc3RhbmNlOiB7IH1cbiAgICB9KTtcblxuICAgIHJldHVybiBtb2RlbDtcbiAgfVxuXG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZhY3RvcnkoJ1N1cHBvcnRTZXJ2aWNlJywgU3VwcG9ydFNlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gU3VwcG9ydFNlcnZpY2Uoc2VydmljZUZhY3RvcnkpIHtcbiAgICByZXR1cm4gc2VydmljZUZhY3RvcnkoJ3N1cHBvcnQnLCB7XG4gICAgICBhY3Rpb25zOiB7XG4gICAgICAvKipcbiAgICAgICAqIFBlZ2EgYXMgdHJhZHXDp8O1ZXMgcXVlIGVzdMOjbyBubyBzZXJ2aWRvclxuICAgICAgICpcbiAgICAgICAqIEByZXR1cm5zIHtwcm9taXNlfSBVbWEgcHJvbWlzZSBjb20gbyByZXN1bHRhZG8gZG8gY2hhbWFkYSBubyBiYWNrZW5kXG4gICAgICAgKi9cbiAgICAgICAgbGFuZ3M6IHtcbiAgICAgICAgICBtZXRob2Q6ICdHRVQnLFxuICAgICAgICAgIHVybDogJ2xhbmdzJyxcbiAgICAgICAgICB3cmFwOiBmYWxzZSxcbiAgICAgICAgICBjYWNoZTogdHJ1ZVxuICAgICAgICB9XG4gICAgICB9XG4gICAgfSk7XG4gIH1cblxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5mYWN0b3J5KCdUYXNrQ29tbWVudHNTZXJ2aWNlJywgVGFza0NvbW1lbnRzU2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiBUYXNrQ29tbWVudHNTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgdmFyIG1vZGVsID0gc2VydmljZUZhY3RvcnkoJ3Rhc2stY29tbWVudHMnLCB7XG4gICAgICBhY3Rpb25zOiB7XG4gICAgICAgIHNhdmVUYXNrQ29tbWVudDoge1xuICAgICAgICAgIG1ldGhvZDogJ1BPU1QnLFxuICAgICAgICAgIHVybDogJ3NhdmVUYXNrQ29tbWVudCdcbiAgICAgICAgfSxcbiAgICAgICAgcmVtb3ZlVGFza0NvbW1lbnQ6IHtcbiAgICAgICAgICBtZXRob2Q6ICdQT1NUJyxcbiAgICAgICAgICB1cmw6ICdyZW1vdmVUYXNrQ29tbWVudCdcbiAgICAgICAgfVxuICAgICAgfSxcbiAgICAgIGluc3RhbmNlOiB7IH1cbiAgICB9KTtcblxuICAgIHJldHVybiBtb2RlbDtcbiAgfVxuXG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmlsdGVyKCdlbGFwc2VkJywgZnVuY3Rpb24oKSB7XG4gICAgICByZXR1cm4gZnVuY3Rpb24oZGF0ZSkge1xuICAgICAgICBpZiAoIWRhdGUpIHJldHVybjtcbiAgICAgICAgdmFyIHRpbWUgPSBEYXRlLnBhcnNlKGRhdGUpLFxuICAgICAgICAgIHRpbWVOb3cgPSBuZXcgRGF0ZSgpLmdldFRpbWUoKSxcbiAgICAgICAgICBkaWZmZXJlbmNlID0gdGltZU5vdyAtIHRpbWUsXG4gICAgICAgICAgc2Vjb25kcyA9IE1hdGguZmxvb3IoZGlmZmVyZW5jZSAvIDEwMDApLFxuICAgICAgICAgIG1pbnV0ZXMgPSBNYXRoLmZsb29yKHNlY29uZHMgLyA2MCksXG4gICAgICAgICAgaG91cnMgPSBNYXRoLmZsb29yKG1pbnV0ZXMgLyA2MCksXG4gICAgICAgICAgZGF5cyA9IE1hdGguZmxvb3IoaG91cnMgLyAyNCksXG4gICAgICAgICAgbW9udGhzID0gTWF0aC5mbG9vcihkYXlzIC8gMzApO1xuXG4gICAgICAgIGlmIChtb250aHMgPiAxKSB7XG4gICAgICAgICAgcmV0dXJuIG1vbnRocyArICcgbWVzZXMgYXRyw6FzJztcbiAgICAgICAgfSBlbHNlIGlmIChtb250aHMgPT09IDEpIHtcbiAgICAgICAgICByZXR1cm4gJzEgbcOqcyBhdHLDoXMnO1xuICAgICAgICB9IGVsc2UgaWYgKGRheXMgPiAxKSB7XG4gICAgICAgICAgcmV0dXJuIGRheXMgKyAnIGRpYXMgYXRyw6FzJztcbiAgICAgICAgfSBlbHNlIGlmIChkYXlzID09PSAxKSB7XG4gICAgICAgICAgcmV0dXJuICcxIGRpYSBhdHLDoXMnXG4gICAgICAgIH0gZWxzZSBpZiAoaG91cnMgPiAxKSB7XG4gICAgICAgICAgcmV0dXJuIGhvdXJzICsgJyBob3JhcyBhdHLDoXMnO1xuICAgICAgICB9IGVsc2UgaWYgKGhvdXJzID09PSAxKSB7XG4gICAgICAgICAgcmV0dXJuICd1bWEgaG9yYSBhdHLDoXMnO1xuICAgICAgICB9IGVsc2UgaWYgKG1pbnV0ZXMgPiAxKSB7XG4gICAgICAgICAgcmV0dXJuIG1pbnV0ZXMgKyAnIG1pbnV0b3MgYXRyw6FzJztcbiAgICAgICAgfSBlbHNlIGlmIChtaW51dGVzID09PSAxKSB7XG4gICAgICAgICAgcmV0dXJuICd1bSBtaW51dG8gYXRyw6FzJztcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICByZXR1cm4gJ2jDoSBwb3Vjb3Mgc2VndW5kb3MnO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfSlcbiAgICAuY29udHJvbGxlcignVGFza3NDb250cm9sbGVyJywgVGFza3NDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIFRhc2tzQ29udHJvbGxlcigkY29udHJvbGxlcixcbiAgICBUYXNrc1NlcnZpY2UsXG4gICAgU3RhdHVzU2VydmljZSxcbiAgICBQcmlvcml0aWVzU2VydmljZSxcbiAgICBUeXBlc1NlcnZpY2UsXG4gICAgVGFza0NvbW1lbnRzU2VydmljZSxcbiAgICBtb21lbnQsXG4gICAgQXV0aCxcbiAgICBQclRvYXN0LFxuICAgICR0cmFuc2xhdGUsXG4gICAgJGZpbHRlcixcbiAgICBHbG9iYWwpIHtcbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgLy9BdHRyaWJ1dGVzIEJsb2NrXG5cbiAgICAvL0Z1bmN0aW9ucyBCbG9ja1xuICAgIHZtLm9uQWN0aXZhdGUgPSBvbkFjdGl2YXRlO1xuICAgIHZtLmFwcGx5RmlsdGVycyA9IGFwcGx5RmlsdGVycztcbiAgICB2bS5iZWZvcmVTYXZlID0gYmVmb3JlU2F2ZTtcbiAgICB2bS5iZWZvcmVSZW1vdmUgPSBiZWZvcmVSZW1vdmU7XG5cbiAgICBmdW5jdGlvbiBvbkFjdGl2YXRlKCkge1xuICAgICAgdm0uY3VycmVudFVzZXIgPSBBdXRoLmN1cnJlbnRVc2VyO1xuICAgICAgdm0uaW1hZ2VQYXRoID0gR2xvYmFsLmltYWdlUGF0aCArICcvbm9fYXZhdGFyLmdpZic7XG4gICAgICB2bS5wcm9qZWN0ID0gbG9jYWxTdG9yYWdlLmdldEl0ZW0oJ3Byb2plY3QnKTtcbiAgICAgIHZtLnF1ZXJ5RmlsdGVycyA9IHsgcHJvamVjdF9pZDogdm0ucHJvamVjdCB9O1xuXG4gICAgICBTdGF0dXNTZXJ2aWNlLnF1ZXJ5KCkudGhlbihmdW5jdGlvbihyZXNwb25zZSkge1xuICAgICAgICB2bS5zdGF0dXMgPSByZXNwb25zZTtcbiAgICAgIH0pO1xuXG4gICAgICBQcmlvcml0aWVzU2VydmljZS5xdWVyeSgpLnRoZW4oZnVuY3Rpb24ocmVzcG9uc2UpIHtcbiAgICAgICAgdm0ucHJpb3JpdGllcyA9IHJlc3BvbnNlO1xuICAgICAgfSk7XG5cbiAgICAgIFR5cGVzU2VydmljZS5xdWVyeSgpLnRoZW4oZnVuY3Rpb24ocmVzcG9uc2UpIHtcbiAgICAgICAgdm0udHlwZXMgPSByZXNwb25zZTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGFwcGx5RmlsdGVycyhkZWZhdWx0UXVlcnlGaWx0ZXJzKSB7XG4gICAgICByZXR1cm4gYW5ndWxhci5leHRlbmQoZGVmYXVsdFF1ZXJ5RmlsdGVycywgdm0ucXVlcnlGaWx0ZXJzKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBiZWZvcmVTYXZlKCkge1xuICAgICAgdm0ucmVzb3VyY2UucHJvamVjdF9pZCA9IHZtLnByb2plY3Q7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gYmVmb3JlUmVtb3ZlKCkge1xuICAgICAgdm0ucmVzb3VyY2UucHJvamVjdF9pZCA9IHZtLnByb2plY3Q7XG4gICAgfVxuXG4gICAgdm0udmlldyA9IGZ1bmN0aW9uIChyZXNvdXJjZSkge1xuICAgICAgdm0ucmVzb3VyY2UgPSByZXNvdXJjZTtcbiAgICAgIHZtLm9uVmlldyA9IHRydWU7XG4gICAgICB2bS52aWV3Rm9ybSA9IGZhbHNlO1xuICAgIH1cblxuICAgIHZtLnNhdmVDb21tZW50ID0gZnVuY3Rpb24oY29tbWVudCkge1xuICAgICAgdmFyIGRlc2NyaXB0aW9uID0gJyc7XG4gICAgICB2YXIgY29tbWVudF9pZCA9IG51bGw7XG5cbiAgICAgIGlmIChjb21tZW50KSB7XG4gICAgICAgIGRlc2NyaXB0aW9uID0gdm0uYW5zd2VyXG4gICAgICAgIGNvbW1lbnRfaWQgPSBjb21tZW50LmlkO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgZGVzY3JpcHRpb24gPSB2bS5jb21tZW50O1xuICAgICAgfVxuICAgICAgVGFza0NvbW1lbnRzU2VydmljZS5zYXZlVGFza0NvbW1lbnQoeyBwcm9qZWN0X2lkOiB2bS5wcm9qZWN0LCB0YXNrX2lkOiB2bS5yZXNvdXJjZS5pZCwgY29tbWVudF90ZXh0OiBkZXNjcmlwdGlvbiwgY29tbWVudF9pZDogY29tbWVudF9pZCB9KS50aGVuKGZ1bmN0aW9uKCkge1xuICAgICAgICB2bS5jb21tZW50ID0gJyc7XG4gICAgICAgIHZtLmFuc3dlciA9ICcnO1xuICAgICAgICB2bS5zZWFyY2goKTtcbiAgICAgICAgUHJUb2FzdC5zdWNjZXNzKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMuc2F2ZVN1Y2Nlc3MnKSk7XG4gICAgICB9LCBmdW5jdGlvbigpIHtcbiAgICAgICAgUHJUb2FzdC5lcnJvcigkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLm9wZXJhdGlvbkVycm9yJykpO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgdm0ucmVtb3ZlQ29tbWVudCA9IGZ1bmN0aW9uKGNvbW1lbnQpIHtcbiAgICAgIFRhc2tDb21tZW50c1NlcnZpY2UucmVtb3ZlVGFza0NvbW1lbnQoeyBjb21tZW50X2lkOiBjb21tZW50LmlkIH0pLnRoZW4oZnVuY3Rpb24oKSB7XG4gICAgICAgIHZtLnNlYXJjaCgpO1xuICAgICAgICBQclRvYXN0LnN1Y2Nlc3MoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5yZW1vdmVTdWNjZXNzJykpO1xuICAgICAgfSwgZnVuY3Rpb24oKSB7XG4gICAgICAgIFByVG9hc3QuZXJyb3IoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5vcGVyYXRpb25FcnJvcicpKTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIHZtLmFmdGVyU2VhcmNoID0gZnVuY3Rpb24oKSB7XG4gICAgICBpZiAodm0ucmVzb3VyY2UuaWQpIHtcbiAgICAgICAgdm0ucmVzb3VyY2UgPSAkZmlsdGVyKCdmaWx0ZXInKSh2bS5yZXNvdXJjZXMsIHsgaWQ6IHZtLnJlc291cmNlLmlkIH0pWzBdO1xuICAgICAgfVxuICAgIH1cblxuICAgIHZtLmZpeERhdGUgPSBmdW5jdGlvbihkYXRlU3RyaW5nKSB7XG4gICAgICByZXR1cm4gbW9tZW50KGRhdGVTdHJpbmcpO1xuICAgIH1cblxuICAgIC8vIGluc3RhbnRpYXRlIGJhc2UgY29udHJvbGxlclxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHsgdm06IHZtLCBtb2RlbFNlcnZpY2U6IFRhc2tzU2VydmljZSwgb3B0aW9uczogeyBza2lwUGFnaW5hdGlvbjogdHJ1ZSB9IH0pO1xuICB9XG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqXG4gICAqIEFycXVpdm8gZGUgY29uZmlndXJhw6fDo28gY29tIGFzIHJvdGFzIGVzcGVjw61maWNhcyBkbyByZWN1cnNvIHByb2plY3RcbiAgICpcbiAgICogQHBhcmFtIHthbnl9ICRzdGF0ZVByb3ZpZGVyXG4gICAqIEBwYXJhbSB7YW55fSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlclxuICAgICAgLnN0YXRlKCdhcHAudGFza3MnLCB7XG4gICAgICAgIHVybDogJy90YXNrcycsXG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvdGFza3MvdGFza3MuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdUYXNrc0NvbnRyb2xsZXIgYXMgdGFza3NDdHJsJyxcbiAgICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IHRydWV9XG4gICAgICB9KTtcbiAgfVxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5mYWN0b3J5KCdUYXNrc1NlcnZpY2UnLCBUYXNrc1NlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gVGFza3NTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCd0YXNrcycsIHtcbiAgICAgIGFjdGlvbnM6IHtcbiAgICAgICAgdXBkYXRlTWlsZXN0b25lOiB7XG4gICAgICAgICAgbWV0aG9kOiAnUE9TVCcsXG4gICAgICAgICAgdXJsOiAndXBkYXRlTWlsZXN0b25lJ1xuICAgICAgICB9LFxuICAgICAgICB1cGRhdGVUYXNrQnlLYW5iYW46IHtcbiAgICAgICAgICBtZXRob2Q6ICdQT1NUJyxcbiAgICAgICAgICB1cmw6ICd1cGRhdGVUYXNrQnlLYW5iYW4nXG4gICAgICAgIH1cbiAgICAgIH0sXG4gICAgICBpbnN0YW5jZTogeyB9XG4gICAgfSk7XG4gIH1cblxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5mYWN0b3J5KCdUeXBlc1NlcnZpY2UnLCBUeXBlc1NlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gVHlwZXNTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgdmFyIG1vZGVsID0gc2VydmljZUZhY3RvcnkoJ3R5cGVzJywge1xuICAgICAgYWN0aW9uczogeyB9LFxuICAgICAgaW5zdGFuY2U6IHsgfVxuICAgIH0pO1xuXG4gICAgcmV0dXJuIG1vZGVsO1xuICB9XG5cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb250cm9sbGVyKCdQcm9maWxlQ29udHJvbGxlcicsIFByb2ZpbGVDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIFByb2ZpbGVDb250cm9sbGVyKFVzZXJzU2VydmljZSwgQXV0aCwgUHJUb2FzdCwgJHRyYW5zbGF0ZSwgJHdpbmRvdywgbW9tZW50KSB7XG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIHZtLnVwZGF0ZSA9IHVwZGF0ZTtcbiAgICB2bS5oaXN0b3J5QmFjayA9IGhpc3RvcnlCYWNrO1xuXG4gICAgYWN0aXZhdGUoKTtcblxuICAgIGZ1bmN0aW9uIGFjdGl2YXRlKCkge1xuICAgICAgdm0udXNlciA9IGFuZ3VsYXIuY29weShBdXRoLmN1cnJlbnRVc2VyKTtcbiAgICAgIGlmICh2bS51c2VyLmJpcnRoZGF5KSB7XG4gICAgICAgIHZtLnVzZXIuYmlydGhkYXkgPSBtb21lbnQodm0udXNlci5iaXJ0aGRheSkuZm9ybWF0KCdERC9NTS9ZWVlZJyk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gdXBkYXRlKCkge1xuICAgICAgaWYgKHZtLnVzZXIuYmlydGhkYXkpIHtcbiAgICAgICAgdm0udXNlci5iaXJ0aGRheSA9IG1vbWVudCh2bS51c2VyLmJpcnRoZGF5KTtcbiAgICAgIH1cbiAgICAgIFVzZXJzU2VydmljZS51cGRhdGVQcm9maWxlKHZtLnVzZXIpLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgIC8vYXR1YWxpemEgbyB1c3XDoXJpbyBjb3JyZW50ZSBjb20gYXMgbm92YXMgaW5mb3JtYcOnw7Vlc1xuICAgICAgICBBdXRoLnVwZGF0ZUN1cnJlbnRVc2VyKHJlc3BvbnNlKTtcbiAgICAgICAgUHJUb2FzdC5zdWNjZXNzKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMuc2F2ZVN1Y2Nlc3MnKSk7XG4gICAgICAgIGhpc3RvcnlCYWNrKCk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBoaXN0b3J5QmFjaygpIHtcbiAgICAgICR3aW5kb3cuaGlzdG9yeS5iYWNrKCk7XG4gICAgfVxuXG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnRyb2xsZXIoJ1VzZXJzQ29udHJvbGxlcicsIFVzZXJzQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBVc2Vyc0NvbnRyb2xsZXIoJGNvbnRyb2xsZXIsIFVzZXJzU2VydmljZSwgUHJUb2FzdCwgJG1kRGlhbG9nLCAkdHJhbnNsYXRlKSB7XG5cbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0ub25BY3RpdmF0ZSA9IG9uQWN0aXZhdGU7XG4gICAgLy8gaW5zdGFudGlhdGUgYmFzZSBjb250cm9sbGVyXG4gICAgJGNvbnRyb2xsZXIoJ0NSVURDb250cm9sbGVyJywgeyB2bTogdm0sIG1vZGVsU2VydmljZTogVXNlcnNTZXJ2aWNlLCBvcHRpb25zOiB7fSB9KTtcblxuICAgIGZ1bmN0aW9uIG9uQWN0aXZhdGUoKSB7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMgPSB7fTtcbiAgICB9XG5cbiAgICB2bS5oaWRlRGlhbG9nID0gZnVuY3Rpb24oKSB7XG4gICAgICAkbWREaWFsb2cuaGlkZSgpO1xuICAgIH1cblxuICAgIHZtLnNhdmVOZXdVc2VyID0gZnVuY3Rpb24oKSB7XG4gICAgICB2bS5yZXNvdXJjZS4kc2F2ZSgpLnRoZW4oZnVuY3Rpb24gKHJlc291cmNlKSB7XG4gICAgICAgIHZtLnJlc291cmNlID0gcmVzb3VyY2U7XG4gICAgICAgIFByVG9hc3Quc3VjY2VzcygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnN1Y2Nlc3NTaWduVXAnKSk7XG4gICAgICAgICRtZERpYWxvZy5oaWRlKCk7XG4gICAgICB9KTtcbiAgICB9XG4gIH1cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqXG4gICAqIEFycXVpdm8gZGUgY29uZmlndXJhw6fDo28gY29tIGFzIHJvdGFzIGVzcGVjw61maWNhcyBkbyByZWN1cnNvIHVzZXJcbiAgICpcbiAgICogQHBhcmFtIHthbnl9ICRzdGF0ZVByb3ZpZGVyXG4gICAqIEBwYXJhbSB7YW55fSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlclxuICAgICAgLnN0YXRlKCdhcHAudXNlcicsIHtcbiAgICAgICAgdXJsOiAnL3VzdWFyaW8nLFxuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL3VzZXJzL3VzZXJzLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnVXNlcnNDb250cm9sbGVyIGFzIHVzZXJzQ3RybCcsXG4gICAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiB0cnVlLCBuZWVkUHJvZmlsZTogWydhZG1pbiddIH1cbiAgICAgIH0pXG4gICAgICAuc3RhdGUoJ2FwcC51c2VyLXByb2ZpbGUnLCB7XG4gICAgICAgIHVybDogJy91c3VhcmlvL3BlcmZpbCcsXG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvdXNlcnMvcHJvZmlsZS5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ1Byb2ZpbGVDb250cm9sbGVyIGFzIHByb2ZpbGVDdHJsJyxcbiAgICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IHRydWUgfVxuICAgICAgfSk7XG5cbiAgfVxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5mYWN0b3J5KCdVc2Vyc1NlcnZpY2UnLCBVc2Vyc1NlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gVXNlcnNTZXJ2aWNlKGxvZGFzaCwgR2xvYmFsLCBzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHJldHVybiBzZXJ2aWNlRmFjdG9yeSgndXNlcnMnLCB7XG4gICAgICAvL3F1YW5kbyBpbnN0YW5jaWEgdW0gdXN1w6FyaW8gc2VtIHBhc3NhciBwYXJhbWV0cm8sXG4gICAgICAvL28gbWVzbW8gdmFpIHRlciBvcyB2YWxvcmVzIGRlZmF1bHRzIGFiYWl4b1xuICAgICAgZGVmYXVsdHM6IHtcbiAgICAgICAgcm9sZXM6IFtdXG4gICAgICB9LFxuXG4gICAgICBhY3Rpb25zOiB7XG4gICAgICAgIC8qKlxuICAgICAgICAgKiBTZXJ2acOnbyBxdWUgYXR1YWxpemEgb3MgZGFkb3MgZG8gcGVyZmlsIGRvIHVzdcOhcmlvIGxvZ2Fkb1xuICAgICAgICAgKlxuICAgICAgICAgKiBAcGFyYW0ge29iamVjdH0gYXR0cmlidXRlc1xuICAgICAgICAgKiBAcmV0dXJucyB7cHJvbWlzZX0gVW1hIHByb21pc2UgY29tIG8gcmVzdWx0YWRvIGRvIGNoYW1hZGEgbm8gYmFja2VuZFxuICAgICAgICAgKi9cbiAgICAgICAgdXBkYXRlUHJvZmlsZToge1xuICAgICAgICAgIG1ldGhvZDogJ1BVVCcsXG4gICAgICAgICAgdXJsOiBHbG9iYWwuYXBpUGF0aCArICcvcHJvZmlsZScsXG4gICAgICAgICAgb3ZlcnJpZGU6IHRydWUsXG4gICAgICAgICAgd3JhcDogZmFsc2VcbiAgICAgICAgfVxuICAgICAgfSxcblxuICAgICAgaW5zdGFuY2U6IHtcbiAgICAgICAgLyoqXG4gICAgICAgICAqIFZlcmlmaWNhIHNlIG8gdXN1w6FyaW8gdGVtIG9zIHBlcmZpcyBpbmZvcm1hZG9zLlxuICAgICAgICAgKlxuICAgICAgICAgKiBAcGFyYW0ge2FueX0gcm9sZXMgcGVyZmlzIGEgc2VyZW0gdmVyaWZpY2Fkb3NcbiAgICAgICAgICogQHBhcmFtIHtib29sZWFufSBhbGwgZmxhZyBwYXJhIGluZGljYXIgc2UgdmFpIGNoZWdhciB0b2RvcyBvcyBwZXJmaXMgb3Ugc29tZW50ZSB1bSBkZWxlc1xuICAgICAgICAgKiBAcmV0dXJucyB7Ym9vbGVhbn1cbiAgICAgICAgICovXG4gICAgICAgIGhhc1Byb2ZpbGU6IGZ1bmN0aW9uKHJvbGVzLCBhbGwpIHtcbiAgICAgICAgICByb2xlcyA9IGFuZ3VsYXIuaXNBcnJheShyb2xlcykgPyByb2xlcyA6IFtyb2xlc107XG5cbiAgICAgICAgICB2YXIgdXNlclJvbGVzID0gbG9kYXNoLm1hcCh0aGlzLnJvbGVzLCAnc2x1ZycpO1xuXG4gICAgICAgICAgaWYgKGFsbCkge1xuICAgICAgICAgICAgcmV0dXJuIGxvZGFzaC5pbnRlcnNlY3Rpb24odXNlclJvbGVzLCByb2xlcykubGVuZ3RoID09PSByb2xlcy5sZW5ndGg7XG4gICAgICAgICAgfSBlbHNlIHsgLy9yZXR1cm4gdGhlIGxlbmd0aCBiZWNhdXNlIDAgaXMgZmFsc2UgaW4ganNcbiAgICAgICAgICAgIHJldHVybiBsb2Rhc2guaW50ZXJzZWN0aW9uKHVzZXJSb2xlcywgcm9sZXMpLmxlbmd0aDtcbiAgICAgICAgICB9XG4gICAgICAgIH0sXG5cbiAgICAgICAgLyoqXG4gICAgICAgICAqIFZlcmlmaWNhIHNlIG8gdXN1w6FyaW8gdGVtIG8gcGVyZmlsIGFkbWluLlxuICAgICAgICAgKlxuICAgICAgICAgKiBAcmV0dXJucyB7Ym9vbGVhbn1cbiAgICAgICAgICovXG4gICAgICAgIGlzQWRtaW46IGZ1bmN0aW9uKCkge1xuICAgICAgICAgIHJldHVybiB0aGlzLmhhc1Byb2ZpbGUoJ2FkbWluJyk7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9KTtcbiAgfVxuXG59KCkpO1xuIiwiLy90b2tlbiBjYWNiOTEyMzU4NzNhOGM0ODc1ZDIzNTc4YWM5ZjMyNmVmODk0YjY2XG4vLyBPQXR1dGggaHR0cHM6Ly9naXRodWIuY29tL2xvZ2luL29hdXRoL2F1dGhvcml6ZT9jbGllbnRfaWQ9ODI5NDY4ZTdmZGVlNzk0NDViYTYmc2NvcGU9dXNlcixwdWJsaWNfcmVwbyZyZWRpcmVjdF91cmk9aHR0cDovLzAuMC4wLjA6NTAwMC8jIS9hcHAvdmNzXG5cbihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmlsdGVyKCdieXRlcycsIGZ1bmN0aW9uKCkge1xuICAgICAgcmV0dXJuIGZ1bmN0aW9uKGJ5dGVzLCBwcmVjaXNpb24pIHtcbiAgICAgICAgaWYgKGlzTmFOKHBhcnNlRmxvYXQoYnl0ZXMpKSB8fCAhaXNGaW5pdGUoYnl0ZXMpKSByZXR1cm4gJy0nO1xuICAgICAgICBpZiAodHlwZW9mIHByZWNpc2lvbiA9PT0gJ3VuZGVmaW5lZCcpIHByZWNpc2lvbiA9IDE7XG4gICAgICAgIHZhciB1bml0cyA9IFsnYnl0ZXMnLCAna0InLCAnTUInLCAnR0InLCAnVEInLCAnUEInXSxcbiAgICAgICAgICBudW1iZXIgPSBNYXRoLmZsb29yKE1hdGgubG9nKGJ5dGVzKSAvIE1hdGgubG9nKDEwMjQpKTtcblxuICAgICAgICByZXR1cm4gKGJ5dGVzIC8gTWF0aC5wb3coMTAyNCwgTWF0aC5mbG9vcihudW1iZXIpKSkudG9GaXhlZChwcmVjaXNpb24pICsgICcgJyArIHVuaXRzW251bWJlcl07XG4gICAgICB9XG4gICAgfSlcbiAgICAuY29udHJvbGxlcignVmNzQ29udHJvbGxlcicsIFZjc0NvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gVmNzQ29udHJvbGxlcigkY29udHJvbGxlciwgVmNzU2VydmljZSwgJHdpbmRvdywgUHJvamVjdHNTZXJ2aWNlLCBQclRvYXN0LCAkdHJhbnNsYXRlKSB7XG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIHZtLmluZGV4ID0gMDtcbiAgICB2bS5wYXRocyA9IFtdO1xuXG4gICAgLy9BdHRyaWJ1dGVzIEJsb2NrXG5cbiAgICAvL0Z1bmN0aW9ucyBCbG9ja1xuICAgIHZtLm9uQWN0aXZhdGUgPSAgZnVuY3Rpb24oKSB7XG4gICAgICB0b2dnbGVTcGxhc2hTY3JlZW4oKTtcbiAgICAgIFByb2plY3RzU2VydmljZS5xdWVyeSh7IHByb2plY3RfaWQ6IGxvY2FsU3RvcmFnZS5nZXRJdGVtKCdwcm9qZWN0JykgfSkudGhlbihmdW5jdGlvbihyZXNwb25zZSkge1xuICAgICAgICB2bS51c2VybmFtZSA9IHJlc3BvbnNlWzBdLnVzZXJuYW1lX2dpdGh1YjtcbiAgICAgICAgdm0ucmVwbyA9IHJlc3BvbnNlWzBdLnJlcG9fZ2l0aHViO1xuICAgICAgICBpZiAodm0udXNlcm5hbWUgJiYgdm0ucmVwbykge1xuICAgICAgICAgIHZtLnF1ZXJ5RmlsdGVycyA9IHtcbiAgICAgICAgICAgIHVzZXJuYW1lOiB2bS51c2VybmFtZSxcbiAgICAgICAgICAgIHJlcG86IHZtLnJlcG8sXG4gICAgICAgICAgICBwYXRoOiAnLidcbiAgICAgICAgICB9XG4gICAgICAgICAgdm0ucGF0aHMucHVzaCh2bS5xdWVyeUZpbHRlcnMucGF0aCk7XG4gICAgICAgICAgdm0uc2VhcmNoKCk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgJHdpbmRvdy5sb2FkaW5nX3NjcmVlbi5maW5pc2goKTtcbiAgICAgICAgfVxuICAgICAgfSk7XG4gICAgfVxuXG4gICAgdm0uYXBwbHlGaWx0ZXJzID0gZnVuY3Rpb24oZGVmYXVsdFF1ZXJ5RmlsdGVycykge1xuICAgICAgcmV0dXJuIGFuZ3VsYXIuZXh0ZW5kKGRlZmF1bHRRdWVyeUZpbHRlcnMsIHZtLnF1ZXJ5RmlsdGVycyk7XG4gICAgfVxuXG4gICAgdm0uYWZ0ZXJTZWFyY2ggPSBmdW5jdGlvbigpIHtcbiAgICAgIHNvcnRSZXNvdXJjZXMoKTtcbiAgICAgICR3aW5kb3cubG9hZGluZ19zY3JlZW4uZmluaXNoKCk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gc29ydFJlc291cmNlcygpIHtcbiAgICAgIGlmICh2bS5yZXNvdXJjZXMubGVuZ3RoID4gMCkge1xuICAgICAgICB2bS5yZXNvdXJjZXMuc29ydChmdW5jdGlvbihhLCBiKSB7XG4gICAgICAgICAgcmV0dXJuIGEudHlwZSA8IGIudHlwZSA/IC0xIDogYS50eXBlID4gYi50eXBlID8gMSA6IDA7XG4gICAgICAgIH0pO1xuICAgICAgfVxuICAgIH1cblxuICAgIHZtLm9wZW5GaWxlT3JEaXJlY3RvcnkgPSBmdW5jdGlvbihyZXNvdXJjZSkge1xuICAgICAgdG9nZ2xlU3BsYXNoU2NyZWVuKCk7XG4gICAgICBpZiAocmVzb3VyY2UpIHtcbiAgICAgICAgdm0ucXVlcnlGaWx0ZXJzLnBhdGggPSByZXNvdXJjZS5wYXRoO1xuICAgICAgICB2bS5wYXRocy5wdXNoKHZtLnF1ZXJ5RmlsdGVycy5wYXRoKTtcbiAgICAgICAgdm0uaW5kZXgrKztcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHZtLnF1ZXJ5RmlsdGVycy5wYXRoID0gdm0ucGF0aHNbdm0uaW5kZXggLSAxXTtcbiAgICAgICAgdm0ucGF0aHMuc3BsaWNlKHZtLmluZGV4LCAxKTtcbiAgICAgICAgdm0uaW5kZXgtLTtcbiAgICAgIH1cbiAgICAgIHZtLnNlYXJjaCgpO1xuICAgIH1cblxuICAgIHZtLm9uU2VhcmNoRXJyb3IgPSBmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgIGlmIChyZXNwb25zZS5kYXRhLmVycm9yID09PSAnTm90IEZvdW5kJykge1xuICAgICAgICBQclRvYXN0LmluZm8oJHRyYW5zbGF0ZS5pbnN0YW50KCdSZXBvc2l0w7NyaW8gbsOjbyBlbmNvbnRyYWRvJykpO1xuICAgICAgICAkd2luZG93LmxvYWRpbmdfc2NyZWVuLmZpbmlzaCgpO1xuICAgICAgfVxuICAgIH1cblxuICAgIC8qKlxuICAgICAqIE3DqXRvZG8gcGFyYSBtb3N0cmFyIGEgdGVsYSBkZSBlc3BlcmFcbiAgICAgKi9cbiAgICBmdW5jdGlvbiB0b2dnbGVTcGxhc2hTY3JlZW4oKSB7XG4gICAgICAkd2luZG93LmxvYWRpbmdfc2NyZWVuID0gJHdpbmRvdy5wbGVhc2VXYWl0KHtcbiAgICAgICAgbG9nbzogJycsXG4gICAgICAgIGJhY2tncm91bmRDb2xvcjogJ3JnYmEoMjU1LDI1NSwyNTUsMC40KScsXG4gICAgICAgIGxvYWRpbmdIdG1sOlxuICAgICAgICAgICc8ZGl2IGNsYXNzPVwic3Bpbm5lclwiPiAnICtcbiAgICAgICAgICAnICA8ZGl2IGNsYXNzPVwicmVjdDFcIj48L2Rpdj4gJyArXG4gICAgICAgICAgJyAgPGRpdiBjbGFzcz1cInJlY3QyXCI+PC9kaXY+ICcgK1xuICAgICAgICAgICcgIDxkaXYgY2xhc3M9XCJyZWN0M1wiPjwvZGl2PiAnICtcbiAgICAgICAgICAnICA8ZGl2IGNsYXNzPVwicmVjdDRcIj48L2Rpdj4gJyArXG4gICAgICAgICAgJyAgPGRpdiBjbGFzcz1cInJlY3Q1XCI+PC9kaXY+ICcgK1xuICAgICAgICAgICcgPHAgY2xhc3M9XCJsb2FkaW5nLW1lc3NhZ2VcIj5DYXJyZWdhbmRvPC9wPiAnICtcbiAgICAgICAgICAnPC9kaXY+J1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLy8gaW5zdGFudGlhdGUgYmFzZSBjb250cm9sbGVyXG4gICAgJGNvbnRyb2xsZXIoJ0NSVURDb250cm9sbGVyJywgeyB2bTogdm0sIG1vZGVsU2VydmljZTogVmNzU2VydmljZSwgb3B0aW9uczogeyBza2lwUGFnaW5hdGlvbjogdHJ1ZSwgc2VhcmNoT25Jbml0OiBmYWxzZSB9IH0pO1xuXG4gIH1cblxuXG59KSgpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKlxuICAgKiBBcnF1aXZvIGRlIGNvbmZpZ3VyYcOnw6NvIGNvbSBhcyByb3RhcyBlc3BlY8OtZmljYXMgZG8gcmVjdXJzbyB2Y3NcbiAgICpcbiAgICogQHBhcmFtIHtvYmplY3R9ICRzdGF0ZVByb3ZpZGVyXG4gICAqIEBwYXJhbSB7b2JqZWN0fSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlclxuICAgICAgLnN0YXRlKCdhcHAudmNzJywge1xuICAgICAgICB1cmw6ICcvdmNzJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy92Y3MvdmNzLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnVmNzQ29udHJvbGxlciBhcyB2Y3NDdHJsJyxcbiAgICAgICAgZGF0YTogeyB9XG4gICAgICB9KTtcbiAgfVxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5mYWN0b3J5KCdWY3NTZXJ2aWNlJywgVmNzU2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiBWY3NTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgdmFyIG1vZGVsID0gc2VydmljZUZhY3RvcnkoJ3ZjcycsIHtcbiAgICAgIGFjdGlvbnM6IHsgfSxcbiAgICAgIGluc3RhbmNlOiB7IH1cbiAgICB9KTtcblxuICAgIHJldHVybiBtb2RlbDtcbiAgfVxuXG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgIC8qKiBAbmdJbmplY3QgKi9cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbXBvbmVudCgnYm94Jywge1xuICAgICAgcmVwbGFjZTogdHJ1ZSxcbiAgICAgIHRlbXBsYXRlVXJsOiBbJ0dsb2JhbCcsIGZ1bmN0aW9uKEdsb2JhbCkge1xuICAgICAgICByZXR1cm4gR2xvYmFsLmNsaWVudFBhdGggKyAnL3dpZGdldHMvYm94Lmh0bWwnXG4gICAgICB9XSxcbiAgICAgIHRyYW5zY2x1ZGU6IHtcbiAgICAgICAgdG9vbGJhckJ1dHRvbnM6ICc/Ym94VG9vbGJhckJ1dHRvbnMnLFxuICAgICAgICBmb290ZXJCdXR0b25zOiAnP2JveEZvb3RlckJ1dHRvbnMnXG4gICAgICB9LFxuICAgICAgYmluZGluZ3M6IHtcbiAgICAgICAgYm94VGl0bGU6ICdAJyxcbiAgICAgICAgdG9vbGJhckNsYXNzOiAnQCcsXG4gICAgICAgIHRvb2xiYXJCZ0NvbG9yOiAnQCdcbiAgICAgIH0sXG4gICAgICBjb250cm9sbGVyOiBbJyR0cmFuc2NsdWRlJywgZnVuY3Rpb24oJHRyYW5zY2x1ZGUpIHtcbiAgICAgICAgdmFyIGN0cmwgPSB0aGlzO1xuXG4gICAgICAgIGN0cmwudHJhbnNjbHVkZSA9ICR0cmFuc2NsdWRlO1xuXG4gICAgICAgIGN0cmwuJG9uSW5pdCA9IGZ1bmN0aW9uKCkge1xuICAgICAgICAgIGlmIChhbmd1bGFyLmlzVW5kZWZpbmVkKGN0cmwudG9vbGJhckJnQ29sb3IpKSBjdHJsLnRvb2xiYXJCZ0NvbG9yID0gJ2RlZmF1bHQtcHJpbWFyeSc7XG4gICAgICAgIH07XG4gICAgICB9XVxuICAgIH0pO1xufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbXBvbmVudCgnY29udGVudEJvZHknLCB7XG4gICAgICByZXBsYWNlOiB0cnVlLFxuICAgICAgdHJhbnNjbHVkZTogdHJ1ZSxcbiAgICAgIHRlbXBsYXRlVXJsOiBbJ0dsb2JhbCcsIGZ1bmN0aW9uKEdsb2JhbCkge1xuICAgICAgICByZXR1cm4gR2xvYmFsLmNsaWVudFBhdGggKyAnL3dpZGdldHMvY29udGVudC1ib2R5Lmh0bWwnXG4gICAgICB9XSxcbiAgICAgIGJpbmRpbmdzOiB7XG4gICAgICAgIGxheW91dEFsaWduOiAnQCdcbiAgICAgIH0sXG4gICAgICBjb250cm9sbGVyOiBbZnVuY3Rpb24oKSB7XG4gICAgICAgIHZhciBjdHJsID0gdGhpcztcblxuICAgICAgICBjdHJsLiRvbkluaXQgPSBmdW5jdGlvbigpIHtcbiAgICAgICAgICAvLyBNYWtlIGEgY29weSBvZiB0aGUgaW5pdGlhbCB2YWx1ZSB0byBiZSBhYmxlIHRvIHJlc2V0IGl0IGxhdGVyXG4gICAgICAgICAgY3RybC5sYXlvdXRBbGlnbiA9IGFuZ3VsYXIuaXNEZWZpbmVkKGN0cmwubGF5b3V0QWxpZ24pID8gY3RybC5sYXlvdXRBbGlnbiA6ICdjZW50ZXIgc3RhcnQnO1xuICAgICAgICB9O1xuICAgICAgfV1cbiAgICB9KTtcblxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbXBvbmVudCgnY29udGVudEhlYWRlcicsIHtcbiAgICAgIHRlbXBsYXRlVXJsOiBbJ0dsb2JhbCcsIGZ1bmN0aW9uKEdsb2JhbCkge1xuICAgICAgICByZXR1cm4gR2xvYmFsLmNsaWVudFBhdGggKyAnL3dpZGdldHMvY29udGVudC1oZWFkZXIuaHRtbCdcbiAgICAgIH1dLFxuICAgICAgcmVwbGFjZTogdHJ1ZSxcbiAgICAgIGJpbmRpbmdzOiB7XG4gICAgICAgIHRpdGxlOiAnQCcsXG4gICAgICAgIGRlc2NyaXB0aW9uOiAnQCdcbiAgICAgIH1cbiAgICB9KTtcblxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZpbHRlcignYXVkaXREZXRhaWxUaXRsZScsIGF1ZGl0RGV0YWlsVGl0bGUpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gYXVkaXREZXRhaWxUaXRsZSgkdHJhbnNsYXRlKSB7XG4gICAgcmV0dXJuIGZ1bmN0aW9uKGF1ZGl0RGV0YWlsLCBzdGF0dXMpIHtcbiAgICAgIGlmIChhdWRpdERldGFpbC50eXBlID09PSAndXBkYXRlZCcpIHtcbiAgICAgICAgaWYgKHN0YXR1cyA9PT0gJ2JlZm9yZScpIHtcbiAgICAgICAgICByZXR1cm4gJHRyYW5zbGF0ZS5pbnN0YW50KCdkaWFsb2cuYXVkaXQudXBkYXRlZEJlZm9yZScpO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIHJldHVybiAkdHJhbnNsYXRlLmluc3RhbnQoJ2RpYWxvZy5hdWRpdC51cGRhdGVkQWZ0ZXInKTtcbiAgICAgICAgfVxuICAgICAgfSBlbHNlIHtcbiAgICAgICAgcmV0dXJuICR0cmFuc2xhdGUuaW5zdGFudCgnZGlhbG9nLmF1ZGl0LicgKyBhdWRpdERldGFpbC50eXBlKTtcbiAgICAgIH1cbiAgICB9XG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZpbHRlcignYXVkaXRNb2RlbCcsIGF1ZGl0TW9kZWwpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gYXVkaXRNb2RlbCgkdHJhbnNsYXRlKSB7XG4gICAgcmV0dXJuIGZ1bmN0aW9uKG1vZGVsSWQpIHtcbiAgICAgIG1vZGVsSWQgPSBtb2RlbElkLnJlcGxhY2UoJ0FwcFxcXFwnLCAnJyk7XG4gICAgICB2YXIgbW9kZWwgPSAkdHJhbnNsYXRlLmluc3RhbnQoJ21vZGVscy4nICsgbW9kZWxJZC50b0xvd2VyQ2FzZSgpKTtcblxuICAgICAgcmV0dXJuIChtb2RlbCkgPyBtb2RlbCA6IG1vZGVsSWQ7XG4gICAgfVxuICB9XG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5maWx0ZXIoJ2F1ZGl0VHlwZScsIGF1ZGl0VHlwZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBhdWRpdFR5cGUobG9kYXNoLCBBdWRpdFNlcnZpY2UpIHtcbiAgICByZXR1cm4gZnVuY3Rpb24odHlwZUlkKSB7XG4gICAgICB2YXIgdHlwZSA9IGxvZGFzaC5maW5kKEF1ZGl0U2VydmljZS5saXN0VHlwZXMoKSwgeyBpZDogdHlwZUlkIH0pO1xuXG4gICAgICByZXR1cm4gKHR5cGUpID8gdHlwZS5sYWJlbCA6IHR5cGU7XG4gICAgfVxuICB9XG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5maWx0ZXIoJ2F1ZGl0VmFsdWUnLCBhdWRpdFZhbHVlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIGF1ZGl0VmFsdWUoJGZpbHRlciwgbG9kYXNoKSB7XG4gICAgcmV0dXJuIGZ1bmN0aW9uKHZhbHVlLCBrZXkpIHtcbiAgICAgIGlmIChhbmd1bGFyLmlzRGF0ZSh2YWx1ZSkgfHwgbG9kYXNoLmVuZHNXaXRoKGtleSwgJ19hdCcpIHx8ICBsb2Rhc2guZW5kc1dpdGgoa2V5LCAnX3RvJykpIHtcbiAgICAgICAgcmV0dXJuICRmaWx0ZXIoJ3ByRGF0ZXRpbWUnKSh2YWx1ZSk7XG4gICAgICB9XG5cbiAgICAgIGlmICh0eXBlb2YgdmFsdWUgPT09ICdib29sZWFuJykge1xuICAgICAgICByZXR1cm4gJGZpbHRlcigndHJhbnNsYXRlJykoKHZhbHVlKSA/ICdnbG9iYWwueWVzJyA6ICdnbG9iYWwubm8nKTtcbiAgICAgIH1cblxuICAgICAgLy9jaGVjayBpcyBmbG9hdFxuICAgICAgaWYgKE51bWJlcih2YWx1ZSkgPT09IHZhbHVlICYmIHZhbHVlICUgMSAhPT0gMCkge1xuICAgICAgICByZXR1cm4gJGZpbHRlcigncmVhbCcpKHZhbHVlKTtcbiAgICAgIH1cblxuICAgICAgcmV0dXJuIHZhbHVlO1xuICAgIH1cbiAgfVxuXG59KSgpO1xuIiwiLyplc2xpbnQgYW5ndWxhci9maWxlLW5hbWU6IDAsIG5vLXVuZGVmOiAwKi9cbihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb25zdGFudCgncHQtQlIuaTE4bi5hdHRyaWJ1dGVzJywge1xuICAgICAgZW1haWw6ICdFbWFpbCcsXG4gICAgICBwYXNzd29yZDogJ1NlbmhhJyxcbiAgICAgIG5hbWU6ICdOb21lJyxcbiAgICAgIGltYWdlOiAnSW1hZ2VtJyxcbiAgICAgIHJvbGVzOiAnUGVyZmlzJyxcbiAgICAgIGRhdGU6ICdEYXRhJyxcbiAgICAgIGluaXRpYWxEYXRlOiAnRGF0YSBJbmljaWFsJyxcbiAgICAgIGZpbmFsRGF0ZTogJ0RhdGEgRmluYWwnLFxuICAgICAgYmlydGhkYXk6ICdEYXRhIGRlIE5hc2NpbWVudG8nLFxuICAgICAgdGFzazoge1xuICAgICAgICBkZXNjcmlwdGlvbjogJ0Rlc2NyacOnw6NvJyxcbiAgICAgICAgZG9uZTogJ0ZlaXRvPycsXG4gICAgICAgIHByaW9yaXR5OiAnUHJpb3JpZGFkZScsXG4gICAgICAgIHNjaGVkdWxlZF90bzogJ0FnZW5kYWRvIFBhcmE/JyxcbiAgICAgICAgcHJvamVjdDogJ1Byb2pldG8nLFxuICAgICAgICBzdGF0dXM6ICdTdGF0dXMnLFxuICAgICAgICB0aXRsZTogJ1TDrXR1bG8nLFxuICAgICAgICB0eXBlOiAnVGlwbycsXG4gICAgICAgIG1pbGVzdG9uZTogJ1NwcmludCcsXG4gICAgICAgIGVzdGltYXRlZF90aW1lOiAnVGVtcG8gRXN0aW1hZG8nXG4gICAgICB9LFxuICAgICAgbWlsZXN0b25lOiB7XG4gICAgICAgIHRpdGxlOiAnVMOtdHVsbycsXG4gICAgICAgIGRlc2NyaXB0aW9uOiAnRGVzY3Jpw6fDo28nLFxuICAgICAgICBkYXRlX3N0YXJ0OiAnRGF0YSBFc3RpbWFkYSBwYXJhIEluw61jaW8nLFxuICAgICAgICBkYXRlX2VuZDogJ0RhdGEgRXN0aW1hZGEgcGFyYSBGaW0nLFxuICAgICAgICBlc3RpbWF0ZWRfdGltZTogJ1RlbXBvIEVzdGltYWRvJyxcbiAgICAgICAgZXN0aW1hdGVkX3ZhbHVlOiAnVmFsb3IgRXN0aW1hZG8nXG4gICAgICB9LFxuICAgICAgcHJvamVjdDoge1xuICAgICAgICBjb3N0OiAnQ3VzdG8nLFxuICAgICAgICBob3VyVmFsdWVEZXZlbG9wZXI6ICdWYWxvciBkYSBIb3JhIERlc2Vudm9sdmVkb3InLFxuICAgICAgICBob3VyVmFsdWVDbGllbnQ6ICdWYWxvciBkYSBIb3JhIENsaWVudGUnLFxuICAgICAgICBob3VyVmFsdWVGaW5hbDogJ1ZhbG9yIGRhIEhvcmEgUHJvamV0bydcbiAgICAgIH0sXG4gICAgICByZWxlYXNlOiB7XG4gICAgICAgIHRpdGxlOiAnVMOtdHVsbycsXG4gICAgICAgIGRlc2NyaXB0aW9uOiAnRGVzY3Jpw6fDo28nLFxuICAgICAgICByZWxlYXNlX2RhdGU6ICdEYXRhIGRlIEVudHJlZ2EnLFxuICAgICAgICBtaWxlc3RvbmU6ICdNaWxlc3RvbmUnLFxuICAgICAgICB0YXNrczogJ1RhcmVmYXMnXG4gICAgICB9LFxuICAgICAgLy/DqSBjYXJyZWdhZG8gZG8gc2Vydmlkb3IgY2FzbyBlc3RlamEgZGVmaW5pZG8gbm8gbWVzbW9cbiAgICAgIGF1ZGl0TW9kZWw6IHtcbiAgICAgIH1cbiAgICB9KVxuXG59KCkpO1xuIiwiLyplc2xpbnQgYW5ndWxhci9maWxlLW5hbWU6IDAsIG5vLXVuZGVmOiAwKi9cbihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb25zdGFudCgncHQtQlIuaTE4bi5kaWFsb2cnLCB7XG4gICAgICBjb25maXJtVGl0bGU6ICdDb25maXJtYcOnw6NvJyxcbiAgICAgIGNvbmZpcm1EZXNjcmlwdGlvbjogJ0NvbmZpcm1hIGEgYcOnw6NvPycsXG4gICAgICByZW1vdmVEZXNjcmlwdGlvbjogJ0Rlc2VqYSByZW1vdmVyIHBlcm1hbmVudGVtZW50ZSB7e25hbWV9fT8nLFxuICAgICAgYXVkaXQ6IHtcbiAgICAgICAgY3JlYXRlZDogJ0luZm9ybWHDp8O1ZXMgZG8gQ2FkYXN0cm8nLFxuICAgICAgICB1cGRhdGVkQmVmb3JlOiAnQW50ZXMgZGEgQXR1YWxpemHDp8OjbycsXG4gICAgICAgIHVwZGF0ZWRBZnRlcjogJ0RlcG9pcyBkYSBBdHVhbGl6YcOnw6NvJyxcbiAgICAgICAgZGVsZXRlZDogJ0luZm9ybWHDp8O1ZXMgYW50ZXMgZGUgcmVtb3ZlcidcbiAgICAgIH0sXG4gICAgICBsb2dpbjoge1xuICAgICAgICByZXNldFBhc3N3b3JkOiB7XG4gICAgICAgICAgZGVzY3JpcHRpb246ICdEaWdpdGUgYWJhaXhvIG8gZW1haWwgY2FkYXN0cmFkbyBubyBzaXN0ZW1hLidcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pXG5cbn0oKSk7XG4iLCIvKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCwgbm8tdW5kZWY6IDAqL1xuKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnN0YW50KCdwdC1CUi5pMThuLmdsb2JhbCcsIHtcbiAgICAgIGxvYWRpbmc6ICdDYXJyZWdhbmRvLi4uJyxcbiAgICAgIHByb2Nlc3Npbmc6ICdQcm9jZXNzYW5kby4uLicsXG4gICAgICB5ZXM6ICdTaW0nLFxuICAgICAgbm86ICdOw6NvJyxcbiAgICAgIGFsbDogJ1RvZG9zJ1xuICAgIH0pXG5cbn0oKSk7XG4iLCIvKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCwgbm8tdW5kZWY6IDAqL1xuKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnN0YW50KCdwdC1CUi5pMThuLm1lc3NhZ2VzJywge1xuICAgICAgaW50ZXJuYWxFcnJvcjogJ09jb3JyZXUgdW0gZXJybyBpbnRlcm5vLCBjb250YXRlIG8gYWRtaW5pc3RyYWRvciBkbyBzaXN0ZW1hJyxcbiAgICAgIG5vdEZvdW5kOiAnTmVuaHVtIHJlZ2lzdHJvIGVuY29udHJhZG8nLFxuICAgICAgbm90QXV0aG9yaXplZDogJ1ZvY8OqIG7Do28gdGVtIGFjZXNzbyBhIGVzdGEgZnVuY2lvbmFsaWRhZGUuJyxcbiAgICAgIHNlYXJjaEVycm9yOiAnTsOjbyBmb2kgcG9zc8OtdmVsIHJlYWxpemFyIGEgYnVzY2EuJyxcbiAgICAgIHNhdmVTdWNjZXNzOiAnUmVnaXN0cm8gc2Fsdm8gY29tIHN1Y2Vzc28uJyxcbiAgICAgIG9wZXJhdGlvblN1Y2Nlc3M6ICdPcGVyYcOnw6NvIHJlYWxpemFkYSBjb20gc3VjZXNzby4nLFxuICAgICAgb3BlcmF0aW9uRXJyb3I6ICdFcnJvIGFvIHJlYWxpemFyIGEgb3BlcmHDp8OjbycsXG4gICAgICBzYXZlRXJyb3I6ICdFcnJvIGFvIHRlbnRhciBzYWx2YXIgbyByZWdpc3Ryby4nLFxuICAgICAgcmVtb3ZlU3VjY2VzczogJ1JlbW/Dp8OjbyByZWFsaXphZGEgY29tIHN1Y2Vzc28uJyxcbiAgICAgIHJlbW92ZUVycm9yOiAnRXJybyBhbyB0ZW50YXIgcmVtb3ZlciBvIHJlZ2lzdHJvLicsXG4gICAgICByZXNvdXJjZU5vdEZvdW5kRXJyb3I6ICdSZWN1cnNvIG7Do28gZW5jb250cmFkbycsXG4gICAgICBub3ROdWxsRXJyb3I6ICdUb2RvcyBvcyBjYW1wb3Mgb2JyaWdhdMOzcmlvcyBkZXZlbSBzZXIgcHJlZW5jaGlkb3MuJyxcbiAgICAgIGR1cGxpY2F0ZWRSZXNvdXJjZUVycm9yOiAnSsOhIGV4aXN0ZSB1bSByZWN1cnNvIGNvbSBlc3NhcyBpbmZvcm1hw6fDtWVzLicsXG4gICAgICBzcHJpbnRFbmRlZFN1Y2Nlc3M6ICdTcHJpbnQgZmluYWxpemFkYSBjb20gc3VjZXNzbycsXG4gICAgICBzcHJpbnRFbmRlZEVycm9yOiAnRXJybyBhbyBmaW5hbGl6YXIgYSBzcHJpbnQnLFxuICAgICAgc3VjY2Vzc1NpZ25VcDogJ0NhZGFzdHJvIHJlYWxpemFkbyBjb20gc3VjZXNzby4gVW0gZS1tYWlsIGZvaSBlbnZpYWRvIGNvbSBzZXVzIGRhZG9zIGRlIGxvZ2luJyxcbiAgICAgIGVycm9yc1NpZ25VcDogJ0hvdXZlIHVtIGVycm8gYW8gcmVhbGl6YXIgbyBzZXUgY2FkYXN0cm8uIFRlbnRlIG5vdmFtZW50ZSBtYWlzIHRhcmRlIScsXG4gICAgICByZWxlYXNldEVuZGVkU3VjY2VzczogJ1JlbGVhc2UgZmluYWxpemFkYSBjb20gc3VjZXNzbycsXG4gICAgICByZWxlYXNlRW5kZWRFcnJvcjogJ0Vycm8gYW8gZmluYWxpemFyIGEgcmVsZWFzZScsXG4gICAgICBwcm9qZWN0RW5kZWRTdWNjZXNzOiAnUHJvamV0byBmaW5hbGl6YWRvIGNvbSBzdWNlc3NvJyxcbiAgICAgIHByb2plY3RFbmRlZEVycm9yOiAnRXJybyBhbyBmaW5hbGl6YXIgbyBwcm9qZXRvJyxcbiAgICAgIHZhbGlkYXRlOiB7XG4gICAgICAgIGZpZWxkUmVxdWlyZWQ6ICdPIGNhbXBvIHt7ZmllbGR9fSDDqSBvYnJpZ3JhdMOzcmlvLidcbiAgICAgIH0sXG4gICAgICBsYXlvdXQ6IHtcbiAgICAgICAgZXJyb3I0MDQ6ICdQw6FnaW5hIG7Do28gZW5jb250cmFkYSdcbiAgICAgIH0sXG4gICAgICBsb2dpbjoge1xuICAgICAgICBsb2dvdXRJbmFjdGl2ZTogJ1ZvY8OqIGZvaSBkZXNsb2dhZG8gZG8gc2lzdGVtYSBwb3IgaW5hdGl2aWRhZGUuIEZhdm9yIGVudHJhciBubyBzaXN0ZW1hIG5vdmFtZW50ZS4nLFxuICAgICAgICBpbnZhbGlkQ3JlZGVudGlhbHM6ICdDcmVkZW5jaWFpcyBJbnbDoWxpZGFzJyxcbiAgICAgICAgdW5rbm93bkVycm9yOiAnTsOjbyBmb2kgcG9zc8OtdmVsIHJlYWxpemFyIG8gbG9naW4uIFRlbnRlIG5vdmFtZW50ZS4gJyArXG4gICAgICAgICAgJ0Nhc28gbsOjbyBjb25zaWdhIGZhdm9yIGVuY29udHJhciBlbSBjb250YXRvIGNvbSBvIGFkbWluaXN0cmFkb3IgZG8gc2lzdGVtYS4nLFxuICAgICAgICB1c2VyTm90Rm91bmQ6ICdOw6NvIGZvaSBwb3Nzw612ZWwgZW5jb250cmFyIHNldXMgZGFkb3MnXG4gICAgICB9LFxuICAgICAgZGFzaGJvYXJkOiB7XG4gICAgICAgIHdlbGNvbWU6ICdTZWphIGJlbSBWaW5kbyB7e3VzZXJOYW1lfX0nLFxuICAgICAgICBkZXNjcmlwdGlvbjogJ1V0aWxpemUgbyBtZW51IHBhcmEgbmF2ZWdhw6fDo28uJ1xuICAgICAgfSxcbiAgICAgIG1haWw6IHtcbiAgICAgICAgbWFpbEVycm9yczogJ09jb3JyZXUgdW0gZXJybyBub3Mgc2VndWludGVzIGVtYWlscyBhYmFpeG86XFxuJyxcbiAgICAgICAgc2VuZE1haWxTdWNjZXNzOiAnRW1haWwgZW52aWFkbyBjb20gc3VjZXNzbyEnLFxuICAgICAgICBzZW5kTWFpbEVycm9yOiAnTsOjbyBmb2kgcG9zc8OtdmVsIGVudmlhciBvIGVtYWlsLicsXG4gICAgICAgIHBhc3N3b3JkU2VuZGluZ1N1Y2Nlc3M6ICdPIHByb2Nlc3NvIGRlIHJlY3VwZXJhw6fDo28gZGUgc2VuaGEgZm9pIGluaWNpYWRvLiBDYXNvIG8gZW1haWwgbsOjbyBjaGVndWUgZW0gMTAgbWludXRvcyB0ZW50ZSBub3ZhbWVudGUuJ1xuICAgICAgfSxcbiAgICAgIHVzZXI6IHtcbiAgICAgICAgcmVtb3ZlWW91clNlbGZFcnJvcjogJ1ZvY8OqIG7Do28gcG9kZSByZW1vdmVyIHNldSBwcsOzcHJpbyB1c3XDoXJpbycsXG4gICAgICAgIHVzZXJFeGlzdHM6ICdVc3XDoXJpbyBqw6EgYWRpY2lvbmFkbyEnLFxuICAgICAgICBwcm9maWxlOiB7XG4gICAgICAgICAgdXBkYXRlRXJyb3I6ICdOw6NvIGZvaSBwb3Nzw612ZWwgYXR1YWxpemFyIHNldSBwcm9maWxlJ1xuICAgICAgICB9XG4gICAgICB9LFxuICAgICAgcXVlcnlEaW5hbWljOiB7XG4gICAgICAgIG5vRmlsdGVyOiAnTmVuaHVtIGZpbHRybyBhZGljaW9uYWRvJ1xuICAgICAgfVxuICAgIH0pXG5cbn0oKSk7XG4iLCIvKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCwgbm8tdW5kZWY6IDAqL1xuKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnN0YW50KCdwdC1CUi5pMThuLm1vZGVscycsIHtcbiAgICAgIHVzZXI6ICdVc3XDoXJpbycsXG4gICAgICB0YXNrOiAnVGFyZWZhJyxcbiAgICAgIHByb2plY3Q6ICdQcm9qZXRvJ1xuICAgIH0pXG5cbn0oKSk7XG4iLCIvKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCwgbm8tdW5kZWY6IDAqL1xuKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnN0YW50KCdwdC1CUi5pMThuLnZpZXdzJywge1xuICAgICAgYnJlYWRjcnVtYnM6IHtcbiAgICAgICAgdXNlcjogJ0FkbWluaXN0cmHDp8OjbyAtIFVzdcOhcmlvJyxcbiAgICAgICAgJ3VzZXItcHJvZmlsZSc6ICdQZXJmaWwnLFxuICAgICAgICBkYXNoYm9hcmQ6ICdEYXNoYm9hcmQnLFxuICAgICAgICBhdWRpdDogJ0FkbWluaXN0cmHDp8OjbyAtIEF1ZGl0b3JpYScsXG4gICAgICAgIG1haWw6ICdBZG1pbmlzdHJhw6fDo28gLSBFbnZpbyBkZSBlLW1haWwnLFxuICAgICAgICBwcm9qZWN0czogJ1Byb2pldG9zJyxcbiAgICAgICAgJ2RpbmFtaWMtcXVlcnknOiAnQWRtaW5pc3RyYcOnw6NvIC0gQ29uc3VsdGFzIERpbsOibWljYXMnLFxuICAgICAgICAnbm90LWF1dGhvcml6ZWQnOiAnQWNlc3NvIE5lZ2FkbycsXG4gICAgICAgIHRhc2tzOiAnVGFyZWZhcycsXG4gICAgICAgIG1pbGVzdG9uZXM6ICdTcHJpbnRzJyxcbiAgICAgICAga2FuYmFuOiAnS2FuYmFuIEJvYXJkJyxcbiAgICAgICAgdmNzOiAnQ29udHJvbGUgZGUgVmVyc8OjbycsXG4gICAgICAgIHJlbGVhc2VzOiAnUmVsZWFzZXMnXG4gICAgICB9LFxuICAgICAgdGl0bGVzOiB7XG4gICAgICAgIGRhc2hib2FyZDogJ0Rhc2hib2FyZCcsXG4gICAgICAgIG1haWxTZW5kOiAnRW52aWFyIGUtbWFpbCcsXG4gICAgICAgIHRhc2tMaXN0OiAnTGlzdGEgZGUgVGFyZWZhcycsXG4gICAgICAgIHVzZXJMaXN0OiAnTGlzdGEgZGUgVXN1w6FyaW9zJyxcbiAgICAgICAgYXVkaXRMaXN0OiAnTGlzdGEgZGUgTG9ncycsXG4gICAgICAgIHJlZ2lzdGVyOiAnRm9ybXVsw6FyaW8gZGUgQ2FkYXN0cm8nLFxuICAgICAgICByZXNldFBhc3N3b3JkOiAnUmVkZWZpbmlyIFNlbmhhJyxcbiAgICAgICAgdXBkYXRlOiAnRm9ybXVsw6FyaW8gZGUgQXR1YWxpemHDp8OjbycsXG4gICAgICAgIHRhc2tzOiAnVGFyZWZhcycsXG4gICAgICAgIG1pbGVzdG9uZXM6ICdTcHJpbnRzJyxcbiAgICAgICAga2FuYmFuOiAnS2FuYmFuIEJvYXJkJyxcbiAgICAgICAgdmNzOiAnQ29udHJvbGUgZGUgVmVyc8OjbycsXG4gICAgICAgIHJlbGVhc2VzOiAnUmVsZWFzZXMnXG4gICAgICB9LFxuICAgICAgYWN0aW9uczoge1xuICAgICAgICBzZW5kOiAnRW52aWFyJyxcbiAgICAgICAgc2F2ZTogJ1NhbHZhcicsXG4gICAgICAgIGNsZWFyOiAnTGltcGFyJyxcbiAgICAgICAgY2xlYXJBbGw6ICdMaW1wYXIgVHVkbycsXG4gICAgICAgIHJlc3RhcnQ6ICdSZWluaWNpYXInLFxuICAgICAgICBmaWx0ZXI6ICdGaWx0cmFyJyxcbiAgICAgICAgc2VhcmNoOiAnUGVzcXVpc2FyJyxcbiAgICAgICAgbGlzdDogJ0xpc3RhcicsXG4gICAgICAgIGVkaXQ6ICdFZGl0YXInLFxuICAgICAgICBjYW5jZWw6ICdDYW5jZWxhcicsXG4gICAgICAgIHVwZGF0ZTogJ0F0dWFsaXphcicsXG4gICAgICAgIHJlbW92ZTogJ1JlbW92ZXInLFxuICAgICAgICBnZXRPdXQ6ICdTYWlyJyxcbiAgICAgICAgYWRkOiAnQWRpY2lvbmFyJyxcbiAgICAgICAgaW46ICdFbnRyYXInLFxuICAgICAgICBsb2FkSW1hZ2U6ICdDYXJyZWdhciBJbWFnZW0nLFxuICAgICAgICBzaWdudXA6ICdDYWRhc3RyYXInLFxuICAgICAgICBjcmlhclByb2pldG86ICdDcmlhciBQcm9qZXRvJyxcbiAgICAgICAgcHJvamVjdExpc3Q6ICdMaXN0YSBkZSBQcm9qZXRvcycsXG4gICAgICAgIHRhc2tzTGlzdDogJ0xpc3RhIGRlIFRhcmVmYXMnLFxuICAgICAgICBtaWxlc3RvbmVzTGlzdDogJ0xpc3RhIGRlIFNwcmludHMnLFxuICAgICAgICBmaW5hbGl6ZTogJ0ZpbmFsaXphcicsXG4gICAgICAgIHJlcGx5OiAnUmVzcG9uZGVyJ1xuICAgICAgfSxcbiAgICAgIGZpZWxkczoge1xuICAgICAgICBkYXRlOiAnRGF0YScsXG4gICAgICAgIGFjdGlvbjogJ0HDp8OjbycsXG4gICAgICAgIGFjdGlvbnM6ICdBw6fDtWVzJyxcbiAgICAgICAgYXVkaXQ6IHtcbiAgICAgICAgICBkYXRlU3RhcnQ6ICdEYXRhIEluaWNpYWwnLFxuICAgICAgICAgIGRhdGVFbmQ6ICdEYXRhIEZpbmFsJyxcbiAgICAgICAgICByZXNvdXJjZTogJ1JlY3Vyc28nLFxuICAgICAgICAgIGFsbFJlc291cmNlczogJ1RvZG9zIFJlY3Vyc29zJyxcbiAgICAgICAgICB0eXBlOiB7XG4gICAgICAgICAgICBjcmVhdGVkOiAnQ2FkYXN0cmFkbycsXG4gICAgICAgICAgICB1cGRhdGVkOiAnQXR1YWxpemFkbycsXG4gICAgICAgICAgICBkZWxldGVkOiAnUmVtb3ZpZG8nXG4gICAgICAgICAgfVxuICAgICAgICB9LFxuICAgICAgICBsb2dpbjoge1xuICAgICAgICAgIHJlc2V0UGFzc3dvcmQ6ICdFc3F1ZWNpIG1pbmhhIHNlbmhhJyxcbiAgICAgICAgICBjb25maXJtUGFzc3dvcmQ6ICdDb25maXJtYXIgc2VuaGEnXG4gICAgICAgIH0sXG4gICAgICAgIG1haWw6IHtcbiAgICAgICAgICB0bzogJ1BhcmEnLFxuICAgICAgICAgIHN1YmplY3Q6ICdBc3N1bnRvJyxcbiAgICAgICAgICBtZXNzYWdlOiAnTWVuc2FnZW0nXG4gICAgICAgIH0sXG4gICAgICAgIHF1ZXJ5RGluYW1pYzoge1xuICAgICAgICAgIGZpbHRlcnM6ICdGaWx0cm9zJyxcbiAgICAgICAgICByZXN1bHRzOiAnUmVzdWx0YWRvcycsXG4gICAgICAgICAgbW9kZWw6ICdNb2RlbCcsXG4gICAgICAgICAgYXR0cmlidXRlOiAnQXRyaWJ1dG8nLFxuICAgICAgICAgIG9wZXJhdG9yOiAnT3BlcmFkb3InLFxuICAgICAgICAgIHJlc291cmNlOiAnUmVjdXJzbycsXG4gICAgICAgICAgdmFsdWU6ICdWYWxvcicsXG4gICAgICAgICAgb3BlcmF0b3JzOiB7XG4gICAgICAgICAgICBlcXVhbHM6ICdJZ3VhbCcsXG4gICAgICAgICAgICBkaWZlcmVudDogJ0RpZmVyZW50ZScsXG4gICAgICAgICAgICBjb250ZWluczogJ0NvbnTDqW0nLFxuICAgICAgICAgICAgc3RhcnRXaXRoOiAnSW5pY2lhIGNvbScsXG4gICAgICAgICAgICBmaW5pc2hXaXRoOiAnRmluYWxpemEgY29tJyxcbiAgICAgICAgICAgIGJpZ2dlclRoYW46ICdNYWlvcicsXG4gICAgICAgICAgICBlcXVhbHNPckJpZ2dlclRoYW46ICdNYWlvciBvdSBJZ3VhbCcsXG4gICAgICAgICAgICBsZXNzVGhhbjogJ01lbm9yJyxcbiAgICAgICAgICAgIGVxdWFsc09yTGVzc1RoYW46ICdNZW5vciBvdSBJZ3VhbCdcbiAgICAgICAgICB9XG4gICAgICAgIH0sXG4gICAgICAgIHByb2plY3Q6IHtcbiAgICAgICAgICBuYW1lOiAnTm9tZScsXG4gICAgICAgICAgdG90YWxUYXNrOiAnVG90YWwgZGUgVGFyZWZhcydcbiAgICAgICAgfSxcbiAgICAgICAgdGFzazoge1xuICAgICAgICAgIGRvbmU6ICdOw6NvIEZlaXRvIC8gRmVpdG8nXG4gICAgICAgIH0sXG4gICAgICAgIHVzZXI6IHtcbiAgICAgICAgICBwZXJmaWxzOiAnUGVyZmlzJyxcbiAgICAgICAgICBuYW1lT3JFbWFpbDogJ05vbWUgb3UgRW1haWwnXG4gICAgICAgIH1cbiAgICAgIH0sXG4gICAgICBsYXlvdXQ6IHtcbiAgICAgICAgbWVudToge1xuICAgICAgICAgIHByb2plY3RzOiAnUHJvamV0b3MnLFxuICAgICAgICAgIGRhc2hib2FyZDogJ0Rhc2hib2FyZCcsXG4gICAgICAgICAgbWlsZXN0b25lczogJ1NwcmludHMnLFxuICAgICAgICAgIHRhc2tzOiAnVGFyZWZhcycsXG4gICAgICAgICAga2FuYmFuOiAnS2FuYmFuJyxcbiAgICAgICAgICB2Y3M6ICdDb250cm9sZSBkZSBWZXJzw6NvJyxcbiAgICAgICAgICByZWxlYXNlczogJ1JlbGVhc2VzJ1xuICAgICAgICB9XG4gICAgICB9LFxuICAgICAgdG9vbHRpcHM6IHtcbiAgICAgICAgYXVkaXQ6IHtcbiAgICAgICAgICB2aWV3RGV0YWlsOiAnVmlzdWFsaXphciBEZXRhbGhhbWVudG8nXG4gICAgICAgIH0sXG4gICAgICAgIHVzZXI6IHtcbiAgICAgICAgICBwZXJmaWw6ICdQZXJmaWwnLFxuICAgICAgICAgIHRyYW5zZmVyOiAnVHJhbnNmZXJpcidcbiAgICAgICAgfSxcbiAgICAgICAgdGFzazoge1xuICAgICAgICAgIGxpc3RUYXNrOiAnTGlzdGFyIFRhcmVmYXMnXG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9KVxuXG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29udHJvbGxlcignVGFza0luZm9Db250cm9sbGVyJywgVGFza0luZm9Db250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIFRhc2tJbmZvQ29udHJvbGxlcigkY29udHJvbGxlciwgVGFza3NTZXJ2aWNlLCBsb2NhbHMpIHtcbiAgICAvL0F0dHJpYnV0ZXMgQmxvY2tcbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0uY2xvc2VEaWFsb2cgPSBjbG9zZURpYWxvZztcblxuICAgIHZtLm9uQWN0aXZhdGUgPSBmdW5jdGlvbigpIHtcbiAgICAgIHZtLnRhc2sgPSBsb2NhbHMudGFzaztcbiAgICAgIHZtLnRhc2suZXN0aW1hdGVkX3RpbWUgPSB2bS50YXNrLmVzdGltYXRlZF90aW1lLnRvU3RyaW5nKCkgKyAnIGhvcmFzJztcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBjbG9zZURpYWxvZygpIHtcbiAgICAgIHZtLmNsb3NlKCk7XG4gICAgICBjb25zb2xlLmxvZyhcImZlY2hhclwiKTtcbiAgICB9XG5cbiAgICAvLyBpbnN0YW50aWF0ZSBiYXNlIGNvbnRyb2xsZXJcbiAgICAkY29udHJvbGxlcignQ1JVRENvbnRyb2xsZXInLCB7IHZtOiB2bSwgbW9kZWxTZXJ2aWNlOiBUYXNrc1NlcnZpY2UsIG9wdGlvbnM6IHsgfSB9KTtcbiAgfVxuXG59KSgpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29udHJvbGxlcignVXNlcnNEaWFsb2dDb250cm9sbGVyJywgVXNlcnNEaWFsb2dDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIFVzZXJzRGlhbG9nQ29udHJvbGxlcigkY29udHJvbGxlciwgVXNlcnNTZXJ2aWNlLCBQckRpYWxvZywgIC8vIE5PU09OQVJcbiAgICB1c2VyRGlhbG9nSW5wdXQsIG9uSW5pdCkge1xuXG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIHZtLm9uQWN0aXZhdGUgPSBvbkFjdGl2YXRlO1xuICAgIHZtLmFwcGx5RmlsdGVycyA9IGFwcGx5RmlsdGVycztcbiAgICB2bS5jbG9zZSA9IGNsb3NlO1xuXG4gICAgaWYgKGFuZ3VsYXIuaXNEZWZpbmVkKHVzZXJEaWFsb2dJbnB1dCkpIHtcbiAgICAgIHZtLnRyYW5zZmVyVXNlciA9IHVzZXJEaWFsb2dJbnB1dC50cmFuc2ZlclVzZXJGbjtcbiAgICB9XG5cbiAgICAvLyBpbnN0YW50aWF0ZSBiYXNlIGNvbnRyb2xsZXJcbiAgICAkY29udHJvbGxlcignQ1JVRENvbnRyb2xsZXInLCB7XG4gICAgICB2bTogdm0sXG4gICAgICBtb2RlbFNlcnZpY2U6IFVzZXJzU2VydmljZSxcbiAgICAgIHNlYXJjaE9uSW5pdDogb25Jbml0LFxuICAgICAgb3B0aW9uczoge1xuICAgICAgICBwZXJQYWdlOiA1XG4gICAgICB9XG4gICAgfSk7XG5cbiAgICBmdW5jdGlvbiBvbkFjdGl2YXRlKCkge1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0ge307XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gYXBwbHlGaWx0ZXJzKCkge1xuICAgICAgcmV0dXJuIGFuZ3VsYXIuZXh0ZW5kKHZtLmRlZmF1bHRRdWVyeUZpbHRlcnMsIHZtLnF1ZXJ5RmlsdGVycyk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gY2xvc2UoKSB7XG4gICAgICBQckRpYWxvZy5jbG9zZSgpO1xuICAgIH1cblxuICB9XG5cbn0pKCk7XG4iXSwic291cmNlUm9vdCI6Ii9zb3VyY2UvIn0=
