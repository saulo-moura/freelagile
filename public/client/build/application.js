'use strict';

/*eslint angular/file-name: 0*/
(function () {
  'use strict';

  angular.module('app', ['ngAnimate', 'ngAria', 'ui.router', 'ngProdeb', 'ui.utils.masks', 'text-mask', 'ngMaterial', 'modelFactory', 'md.data.table', 'ngMaterialDatePicker', 'pascalprecht.translate', 'angularFileUpload', 'ngMessages', 'jqwidgets', 'ui.mask', 'ngRoute']);
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

      vm.actualProject.tasks.forEach(function (task) {
        estimated_cost += parseFloat(vm.actualProject.hour_value_final) * task.estimated_time;
      });
      return estimated_cost.toLocaleString('Pt-br', { minimumFractionDigits: 2 });
    };

    vm.finalizeProject = function () {
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
      if (Auth.currentUser.id === vm.actualProject.owner) {
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
      vm.resource = resource;
      vm.onView = true;
      vm.viewForm = false;
      console.log(resource.project);
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
        } },
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
      vm.currentUser = Auth.cuurrentUser;
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImFwcGxpY2F0aW9uLmpzIiwiYXBwLmpzIiwiYXBwLmNvbmZpZy5qcyIsImFwcC5jb250cm9sbGVyLmpzIiwiYXBwLmV4dGVybmFsLmpzIiwiYXBwLmdsb2JhbC5qcyIsImFwcC5yb3V0ZXMuanMiLCJhcHAucnVuLmpzIiwiYXVkaXQvYXVkaXQuY29udHJvbGxlci5qcyIsImF1ZGl0L2F1ZGl0LnJvdXRlLmpzIiwiYXVkaXQvYXVkaXQuc2VydmljZS5qcyIsImF1dGgvYXV0aC5yb3V0ZS5qcyIsImF1dGgvYXV0aC5zZXJ2aWNlLmpzIiwiYXV0aC9sb2dpbi5jb250cm9sbGVyLmpzIiwiYXV0aC9wYXNzd29yZC5jb250cm9sbGVyLmpzIiwiY29yZS9iYXNlLnNlcnZpY2UuanMiLCJjb3JlL2NydWQuY29udHJvbGxlci5qcyIsImRhc2hib2FyZC9kYXNoYm9hcmQuY29udHJvbGxlci5qcyIsImRhc2hib2FyZC9kYXNoYm9hcmQucm91dGUuanMiLCJkYXNoYm9hcmQvZGFzaGJvYXJkLnNlcnZpY2UuanMiLCJkaW5hbWljLXF1ZXJ5cy9kaW5hbWljLXF1ZXJ5LnJvdXRlLmpzIiwiZGluYW1pYy1xdWVyeXMvZGluYW1pYy1xdWVyeS5zZXJ2aWNlLmpzIiwiZGluYW1pYy1xdWVyeXMvZGluYW1pYy1xdWVyeXMuY29udHJvbGxlci5qcyIsImkxOG4vbGFuZ3VhZ2UtbG9hZGVyLnNlcnZpY2UuanMiLCJpMThuL3QtYXR0ci5maWx0ZXIuanMiLCJpMThuL3QtYnJlYWRjcnVtYi5maWx0ZXIuanMiLCJpMThuL3QtbW9kZWwuZmlsdGVyLmpzIiwiaW50ZXJjZXB0b3JzL2F1dGhlbnRpY2F0aW9uLmxpc3RlbmVyLmpzIiwiaW50ZXJjZXB0b3JzL2F1dGhvcml6YXRpb24ubGlzdGVuZXIuanMiLCJpbnRlcmNlcHRvcnMvc3Bpbm5lci5pbnRlcmNlcHRvci5qcyIsImludGVyY2VwdG9ycy90b2tlbi5pbnRlcmNlcHRvci5qcyIsImludGVyY2VwdG9ycy92YWxpZGF0aW9uLmludGVyY2VwdG9yLmpzIiwia2FuYmFuL2thbmJhbi5jb250cm9sbGVyLmpzIiwia2FuYmFuL2thbmJhbi5yb3V0ZS5qcyIsImthbmJhbi9rYW5iYW4uc2VydmljZS5qcyIsImxheW91dC9tZW51LmNvbnRyb2xsZXIuanMiLCJtYWlsL21haWxzLmNvbnRyb2xsZXIuanMiLCJtYWlsL21haWxzLnJvdXRlLmpzIiwibWFpbC9tYWlscy5zZXJ2aWNlLmpzIiwibWlsZXN0b25lcy9taWxlc3RvbmVzLmNvbnRyb2xsZXIuanMiLCJtaWxlc3RvbmVzL21pbGVzdG9uZXMucm91dGUuanMiLCJtaWxlc3RvbmVzL21pbGVzdG9uZXMuc2VydmljZS5qcyIsInByaW9yaXRpZXMvcHJpb3JpdGllcy5zZXJ2aWNlLmpzIiwicHJvamVjdHMvcHJvamVjdHMuY29udHJvbGxlci5qcyIsInByb2plY3RzL3Byb2plY3RzLnJvdXRlLmpzIiwicHJvamVjdHMvcHJvamVjdHMuc2VydmljZS5qcyIsInJlbGVhc2VzL3JlbGVhc2VzLmNvbnRyb2xsZXIuanMiLCJyZWxlYXNlcy9yZWxlYXNlcy5yb3V0ZS5qcyIsInJlbGVhc2VzL3JlbGVhc2VzLnNlcnZpY2UuanMiLCJyb2xlcy9yb2xlcy1zdHIuZmlsdGVyLmpzIiwicm9sZXMvcm9sZXMuc2VydmljZS5qcyIsInN0YXR1cy9zdGF0dXMuc2VydmljZS5qcyIsInN1cHBvcnQvc3VwcG9ydC5zZXJ2aWNlLmpzIiwidGFzay1jb21tZW50cy90YXNrLWNvbW1lbnRzLnNlcnZpY2UuanMiLCJ0YXNrcy90YXNrcy5jb250cm9sbGVyLmpzIiwidGFza3MvdGFza3Mucm91dGUuanMiLCJ0YXNrcy90YXNrcy5zZXJ2aWNlLmpzIiwidHlwZXMvdHlwZXMuc2VydmljZS5qcyIsInVzZXJzL3Byb2ZpbGUuY29udHJvbGxlci5qcyIsInVzZXJzL3VzZXJzLmNvbnRyb2xsZXIuanMiLCJ1c2Vycy91c2Vycy5yb3V0ZS5qcyIsInVzZXJzL3VzZXJzLnNlcnZpY2UuanMiLCJ2Y3MvdmNzLmNvbnRyb2xsZXIuanMiLCJ2Y3MvdmNzLnJvdXRlLmpzIiwidmNzL3Zjcy5zZXJ2aWNlLmpzIiwid2lkZ2V0cy9ib3guY29tcG9uZW50LmpzIiwid2lkZ2V0cy9jb250ZW50LWJvZHkuY29tcG9uZW50LmpzIiwid2lkZ2V0cy9jb250ZW50LWhlYWRlci5jb21wb25lbnQuanMiLCJhdWRpdC9maWx0ZXJzL2F1ZGl0LWRldGFpbC10aXRsZS5maWx0ZXIuanMiLCJhdWRpdC9maWx0ZXJzL2F1ZGl0LW1vZGVsLmZpbHRlci5qcyIsImF1ZGl0L2ZpbHRlcnMvYXVkaXQtdHlwZS5maWx0ZXIuanMiLCJhdWRpdC9maWx0ZXJzL2F1ZGl0LXZhbHVlLmZpbHRlci5qcyIsImkxOG4vcHQtQlIvYXR0cmlidXRlcy5qcyIsImkxOG4vcHQtQlIvZGlhbG9nLmpzIiwiaTE4bi9wdC1CUi9nbG9iYWwuanMiLCJpMThuL3B0LUJSL21lc3NhZ2VzLmpzIiwiaTE4bi9wdC1CUi9tb2RlbHMuanMiLCJpMThuL3B0LUJSL3ZpZXdzLmpzIiwia2FuYmFuL3Rhc2staW5mby1kaWFsb2cvdGFzay1pbmZvLmNvbnRyb2xsZXIuanMiLCJ1c2Vycy9kaWFsb2cvdXNlcnMtZGlhbG9nLmNvbnRyb2xsZXIuanMiXSwibmFtZXMiOlsiYW5ndWxhciIsIm1vZHVsZSIsImNvbmZpZyIsIkdsb2JhbCIsIiRtZFRoZW1pbmdQcm92aWRlciIsIiRtb2RlbEZhY3RvcnlQcm92aWRlciIsIiR0cmFuc2xhdGVQcm92aWRlciIsIm1vbWVudCIsIiRtZEFyaWFQcm92aWRlciIsIiRtZERhdGVMb2NhbGVQcm92aWRlciIsInVzZUxvYWRlciIsInVzZVNhbml0aXplVmFsdWVTdHJhdGVneSIsInVzZVBvc3RDb21waWxpbmciLCJsb2NhbGUiLCJkZWZhdWx0T3B0aW9ucyIsInByZWZpeCIsImFwaVBhdGgiLCJ0aGVtZSIsInByaW1hcnlQYWxldHRlIiwiZGVmYXVsdCIsImFjY2VudFBhbGV0dGUiLCJ3YXJuUGFsZXR0ZSIsImVuYWJsZUJyb3dzZXJDb2xvciIsImRpc2FibGVXYXJuaW5ncyIsImZvcm1hdERhdGUiLCJkYXRlIiwiZm9ybWF0IiwiY29udHJvbGxlciIsIkFwcENvbnRyb2xsZXIiLCIkc3RhdGUiLCJBdXRoIiwidm0iLCJhbm9BdHVhbCIsImFjdGl2ZVByb2plY3QiLCJsb2dvdXQiLCJnZXRJbWFnZVBlcmZpbCIsImdldExvZ29NZW51Iiwic2V0QWN0aXZlUHJvamVjdCIsImdldEFjdGl2ZVByb2plY3QiLCJyZW1vdmVBY3RpdmVQcm9qZWN0IiwiYWN0aXZhdGUiLCJEYXRlIiwiZ2V0RnVsbFllYXIiLCJ0aGVuIiwiZ28iLCJsb2dpblN0YXRlIiwiY3VycmVudFVzZXIiLCJpbWFnZSIsImltYWdlUGF0aCIsInByb2plY3QiLCJsb2NhbFN0b3JhZ2UiLCJzZXRJdGVtIiwiZ2V0SXRlbSIsInJlbW92ZUl0ZW0iLCJjb25zdGFudCIsIl8iLCJhcHBOYW1lIiwiaG9tZVN0YXRlIiwibG9naW5VcmwiLCJyZXNldFBhc3N3b3JkVXJsIiwicmVzZXRQYXNzd29yZFN0YXRlIiwibm90QXV0aG9yaXplZFN0YXRlIiwidG9rZW5LZXkiLCJjbGllbnRQYXRoIiwicm91dGVzIiwiJHN0YXRlUHJvdmlkZXIiLCIkdXJsUm91dGVyUHJvdmlkZXIiLCJzdGF0ZSIsInVybCIsInRlbXBsYXRlVXJsIiwiYWJzdHJhY3QiLCJyZXNvbHZlIiwidHJhbnNsYXRlUmVhZHkiLCIkdHJhbnNsYXRlIiwiJHEiLCJkZWZlcnJlZCIsImRlZmVyIiwidXNlIiwicHJvbWlzZSIsImRhdGEiLCJuZWVkQXV0aGVudGljYXRpb24iLCJ3aGVuIiwib3RoZXJ3aXNlIiwicnVuIiwiJHJvb3RTY29wZSIsIiRzdGF0ZVBhcmFtcyIsImF1dGgiLCJnbG9iYWwiLCJyZXRyaWV2ZVVzZXJGcm9tTG9jYWxTdG9yYWdlIiwiQXVkaXRDb250cm9sbGVyIiwiJGNvbnRyb2xsZXIiLCJBdWRpdFNlcnZpY2UiLCJQckRpYWxvZyIsIm9uQWN0aXZhdGUiLCJhcHBseUZpbHRlcnMiLCJ2aWV3RGV0YWlsIiwibW9kZWxTZXJ2aWNlIiwib3B0aW9ucyIsIm1vZGVscyIsInF1ZXJ5RmlsdGVycyIsImdldEF1ZGl0ZWRNb2RlbHMiLCJpZCIsImxhYmVsIiwiaW5zdGFudCIsInNvcnQiLCJpbmRleCIsImxlbmd0aCIsIm1vZGVsIiwicHVzaCIsInRvTG93ZXJDYXNlIiwidHlwZXMiLCJsaXN0VHlwZXMiLCJ0eXBlIiwiZGVmYXVsdFF1ZXJ5RmlsdGVycyIsImV4dGVuZCIsImF1ZGl0RGV0YWlsIiwibG9jYWxzIiwiY2xvc2UiLCJpc0FycmF5Iiwib2xkIiwibmV3IiwiY29udHJvbGxlckFzIiwiaGFzQmFja2Ryb3AiLCJjdXN0b20iLCJuZWVkUHJvZmlsZSIsImZhY3RvcnkiLCJzZXJ2aWNlRmFjdG9yeSIsImFjdGlvbnMiLCJtZXRob2QiLCJpbnN0YW5jZSIsImF1ZGl0UGF0aCIsIiRodHRwIiwiVXNlcnNTZXJ2aWNlIiwibG9naW4iLCJ1cGRhdGVDdXJyZW50VXNlciIsImF1dGhlbnRpY2F0ZWQiLCJzZW5kRW1haWxSZXNldFBhc3N3b3JkIiwicmVtb3RlVmFsaWRhdGVUb2tlbiIsImdldFRva2VuIiwic2V0VG9rZW4iLCJjbGVhclRva2VuIiwidG9rZW4iLCJnZXQiLCJyZWplY3QiLCJ1c2VyIiwibWVyZ2UiLCJmcm9tSnNvbiIsImpzb25Vc2VyIiwidG9Kc29uIiwiY3JlZGVudGlhbHMiLCJwb3N0IiwicmVzcG9uc2UiLCJlcnJvciIsInJlc2V0RGF0YSIsIkxvZ2luQ29udHJvbGxlciIsIm9wZW5EaWFsb2dSZXNldFBhc3MiLCJvcGVuRGlhbG9nU2lnblVwIiwiZW1haWwiLCJwYXNzd29yZCIsIlBhc3N3b3JkQ29udHJvbGxlciIsIiR0aW1lb3V0IiwiUHJUb2FzdCIsInNlbmRSZXNldCIsImNsb3NlRGlhbG9nIiwiY2xlYW5Gb3JtIiwicmVzZXQiLCJzdWNjZXNzIiwic3RhdHVzIiwibXNnIiwiaSIsInRvVXBwZXJDYXNlIiwiZmllbGQiLCJtZXNzYWdlIiwiJG1vZGVsRmFjdG9yeSIsInBhZ2luYXRlIiwid3JhcCIsImFmdGVyUmVxdWVzdCIsIkxpc3QiLCJDUlVEQ29udHJvbGxlciIsIlByUGFnaW5hdGlvbiIsInNlYXJjaCIsInBhZ2luYXRlU2VhcmNoIiwibm9ybWFsU2VhcmNoIiwiZWRpdCIsInNhdmUiLCJyZW1vdmUiLCJnb1RvIiwicmVkaXJlY3RBZnRlclNhdmUiLCJzZWFyY2hPbkluaXQiLCJwZXJQYWdlIiwic2tpcFBhZ2luYXRpb24iLCJ2aWV3Rm9ybSIsInJlc291cmNlIiwiaXNGdW5jdGlvbiIsInBhZ2luYXRvciIsImdldEluc3RhbmNlIiwicGFnZSIsImN1cnJlbnRQYWdlIiwiaXNEZWZpbmVkIiwiYmVmb3JlU2VhcmNoIiwiY2FsY051bWJlck9mUGFnZXMiLCJ0b3RhbCIsInJlc291cmNlcyIsIml0ZW1zIiwiYWZ0ZXJTZWFyY2giLCJyZXNwb25zZURhdGEiLCJvblNlYXJjaEVycm9yIiwicXVlcnkiLCJmb3JtIiwiYmVmb3JlQ2xlYW4iLCIkc2V0UHJpc3RpbmUiLCIkc2V0VW50b3VjaGVkIiwiYWZ0ZXJDbGVhbiIsImNvcHkiLCJhZnRlckVkaXQiLCJiZWZvcmVTYXZlIiwiJHNhdmUiLCJhZnRlclNhdmUiLCJvblNhdmVFcnJvciIsInRpdGxlIiwiZGVzY3JpcHRpb24iLCJjb25maXJtIiwiYmVmb3JlUmVtb3ZlIiwiJGRlc3Ryb3kiLCJhZnRlclJlbW92ZSIsImluZm8iLCJ2aWV3TmFtZSIsIm9uVmlldyIsImZpbHRlciIsInRpbWUiLCJwYXJzZSIsInRpbWVOb3ciLCJnZXRUaW1lIiwiZGlmZmVyZW5jZSIsInNlY29uZHMiLCJNYXRoIiwiZmxvb3IiLCJtaW51dGVzIiwiaG91cnMiLCJkYXlzIiwibW9udGhzIiwiRGFzaGJvYXJkQ29udHJvbGxlciIsIiRtZERpYWxvZyIsIkRhc2hib2FyZHNTZXJ2aWNlIiwiUHJvamVjdHNTZXJ2aWNlIiwiZml4RGF0ZSIsInByb2plY3RfaWQiLCJhY3R1YWxQcm9qZWN0IiwiZGF0ZVN0cmluZyIsImdvVG9Qcm9qZWN0Iiwib2JqIiwidG90YWxDb3N0IiwiZXN0aW1hdGVkX2Nvc3QiLCJ0YXNrcyIsImZvckVhY2giLCJ0YXNrIiwicGFyc2VGbG9hdCIsImhvdXJfdmFsdWVfZmluYWwiLCJlc3RpbWF0ZWRfdGltZSIsInRvTG9jYWxlU3RyaW5nIiwibWluaW11bUZyYWN0aW9uRGlnaXRzIiwiZmluYWxpemVQcm9qZWN0IiwidGV4dENvbnRlbnQiLCJuYW1lIiwib2siLCJjYW5jZWwiLCJzaG93IiwiZmluYWxpemUiLCJFcnJvciIsIkRpbmFtaWNRdWVyeVNlcnZpY2UiLCJnZXRNb2RlbHMiLCJEaW5hbWljUXVlcnlzQ29udHJvbGxlciIsImxvZGFzaCIsImxvYWRBdHRyaWJ1dGVzIiwibG9hZE9wZXJhdG9ycyIsImFkZEZpbHRlciIsInJ1bkZpbHRlciIsImVkaXRGaWx0ZXIiLCJsb2FkTW9kZWxzIiwicmVtb3ZlRmlsdGVyIiwiY2xlYXIiLCJyZXN0YXJ0Iiwid2hlcmUiLCJhZGRlZEZpbHRlcnMiLCJhdHRyaWJ1dGUiLCJvcGVyYXRvciIsInZhbHVlIiwiZmlsdGVycyIsImF0dHJpYnV0ZXMiLCJvcGVyYXRvcnMiLCJpbmRleE9mIiwiaXNVbmRlZmluZWQiLCJrZXlzIiwiT2JqZWN0Iiwia2V5Iiwic3RhcnRzV2l0aCIsIiRpbmRleCIsInNwbGljZSIsIkxhbmd1YWdlTG9hZGVyIiwiU3VwcG9ydFNlcnZpY2UiLCIkbG9nIiwiJGluamVjdG9yIiwic2VydmljZSIsInRyYW5zbGF0ZSIsInZpZXdzIiwiZGlhbG9nIiwibWVzc2FnZXMiLCJsYW5ncyIsInRBdHRyIiwiJGZpbHRlciIsInRCcmVhZGNydW1iIiwic3BsaXQiLCJ0TW9kZWwiLCJhdXRoZW50aWNhdGlvbkxpc3RlbmVyIiwiJG9uIiwiZXZlbnQiLCJ0b1N0YXRlIiwiY2F0Y2giLCJ3YXJuIiwicHJldmVudERlZmF1bHQiLCJhdXRob3JpemF0aW9uTGlzdGVuZXIiLCJoYXNQcm9maWxlIiwiYWxsUHJvZmlsZXMiLCJzcGlubmVySW50ZXJjZXB0b3IiLCIkaHR0cFByb3ZpZGVyIiwiJHByb3ZpZGUiLCJzaG93SGlkZVNwaW5uZXIiLCJyZXF1ZXN0IiwiaGlkZSIsInJlc3BvbnNlRXJyb3IiLCJyZWplY3Rpb24iLCJpbnRlcmNlcHRvcnMiLCJ0b2tlbkludGVyY2VwdG9yIiwicmVkaXJlY3RXaGVuU2VydmVyTG9nZ2VkT3V0IiwiaGVhZGVycyIsInJlamVjdGlvblJlYXNvbnMiLCJ0b2tlbkVycm9yIiwiaXMiLCJ2YWxpZGF0aW9uSW50ZXJjZXB0b3IiLCJzaG93RXJyb3JWYWxpZGF0aW9uIiwic2tpcFZhbGlkYXRpb24iLCJlcnJvclZhbGlkYXRpb24iLCJLYW5iYW5Db250cm9sbGVyIiwiVGFza3NTZXJ2aWNlIiwiU3RhdHVzU2VydmljZSIsIiRkb2N1bWVudCIsImZpZWxkcyIsIm1hcCIsImlzTW92ZWQiLCJjb2x1bW5zIiwidGV4dCIsImRhdGFGaWVsZCIsInNsdWciLCJjb2xsYXBzaWJsZSIsInRhZ3MiLCJwcmlvcml0eSIsInNvdXJjZSIsImxvY2FsRGF0YSIsImRhdGFUeXBlIiwiZGF0YUZpZWxkcyIsImRhdGFBZGFwdGVyIiwiJCIsImpxeCIsInNldHRpbmdzIiwia2FuYmFuUmVhZHkiLCJvbkl0ZW1Nb3ZlZCIsIm93bmVyIiwidGFza19pZCIsImFyZ3MiLCJpdGVtSWQiLCJtaWxlc3RvbmUiLCJkb25lIiwidXBkYXRlVGFza0J5S2FuYmFuIiwib2xkQ29sdW1uIiwibmV3Q29sdW1uIiwib25JdGVtQ2xpY2tlZCIsInRhc2tJbmZvIiwicGFyZW50IiwiZWxlbWVudCIsImJvZHkiLCJiaW5kVG9Db250cm9sbGVyIiwiZXNjYXBlVG9DbG9zZSIsImNsaWNrT3V0c2lkZVRvQ2xvc2UiLCJLYW5iYW5TZXJ2aWNlIiwiTWVudUNvbnRyb2xsZXIiLCIkbWRTaWRlbmF2IiwiJG1kQ29sb3JzIiwib3BlbiIsIm9wZW5NZW51T3JSZWRpcmVjdFRvU3RhdGUiLCJtZW51UHJlZml4IiwiaXRlbnNNZW51IiwiaWNvbiIsInN1Ykl0ZW5zIiwic2lkZW5hdlN0eWxlIiwidG9wIiwiY29udGVudCIsInRleHRDb2xvciIsImNvbG9yIiwibGluZUJvdHRvbSIsImdldENvbG9yIiwidG9nZ2xlIiwiJG1kTWVudSIsImV2IiwiaXRlbSIsImNvbG9yUGFsZXR0ZXMiLCJnZXRUaGVtZUNvbG9yIiwiTWFpbHNDb250cm9sbGVyIiwiTWFpbHNTZXJ2aWNlIiwiZmlsdGVyU2VsZWN0ZWQiLCJza2luIiwibGFuZ3VhZ2UiLCJhbGxvd2VkQ29udGVudCIsImVudGl0aWVzIiwiaGVpZ2h0IiwiZXh0cmFQbHVnaW5zIiwibG9hZFVzZXJzIiwib3BlblVzZXJEaWFsb2ciLCJhZGRVc2VyTWFpbCIsInNlbmQiLCJjcml0ZXJpYSIsIm5hbWVPckVtYWlsIiwibm90VXNlcnMiLCJtYWlsIiwidXNlcnMiLCJwcm9wZXJ0eSIsInRvU3RyaW5nIiwibGltaXQiLCJmaW5kIiwib25Jbml0IiwidXNlckRpYWxvZ0lucHV0IiwidHJhbnNmZXJVc2VyRm4iLCJNaWxlc3RvbmVzQ29udHJvbGxlciIsIk1pbGVzdG9uZXNTZXJ2aWNlIiwiZXN0aW1hdGVkUHJpY2UiLCJlc3RpbWF0ZWRfdmFsdWUiLCJlc3RpbWF0ZWRUaW1lIiwiZGF0ZUVuZCIsImRhdGVfZW5kIiwiZGF0ZUJlZ2luIiwiZGF0ZV9iZWdpbiIsImRpZmYiLCJjb2xvcl9lc3RpbWF0ZWRfdGltZSIsInZpZXciLCJjb25zb2xlIiwibG9nIiwic2VhcmNoVGFzayIsInRhc2tUZXJtIiwibWlsZXN0b25lU2VhcmNoIiwib25UYXNrQ2hhbmdlIiwiZmluZEluZGV4IiwicmVtb3ZlVGFzayIsInNsaWNlIiwic2F2ZVRhc2tzIiwidXBkYXRlTWlsZXN0b25lIiwibWlsZXN0b25lX2lkIiwidXBkYXRlUmVsZWFzZSIsIlByaW9yaXRpZXNTZXJ2aWNlIiwiUHJvamVjdHNDb250cm9sbGVyIiwiUm9sZXNTZXJ2aWNlIiwiJHdpbmRvdyIsInNlYXJjaFVzZXIiLCJhZGRVc2VyIiwicmVtb3ZlVXNlciIsInZpZXdQcm9qZWN0Iiwicm9sZXMiLCJ1c2VyX2lkIiwidXNlcnNBcnJheSIsInF1ZXJ5bHRlcnMiLCJ1c2VyTmFtZSIsImNsaWVudF9pZCIsImNsaWVudCIsInJvbGUiLCJkZXZfaWQiLCJkZXZlbG9wZXIiLCJzdGFrZWhvbGRlcl9pZCIsInN0YWtlaG9sZGVyIiwiaGlzdG9yeUJhY2siLCJoaXN0b3J5IiwiYmFjayIsInBhcmFtcyIsIlJlbGVhc2VzQ29udHJvbGxlciIsIlJlbGVhc2VzU2VydmljZSIsImN1dXJyZW50VXNlciIsInJlbGVhc2UiLCJyZWxlYXNlX2lkIiwic2VhcmNoTWlsZXN0b25lIiwibWlsZXN0b25lVGVybSIsInJlbGVhc2VTZWFyY2giLCJvbk1pbGVzdG9uZUNoYW5nZSIsIm1pbGVzdG9uZXMiLCJyZW1vdmVNaWxlc3RvbmUiLCJzYXZlTWlsZXN0b25lcyIsInJvbGVzU3RyIiwiam9pbiIsImNhY2hlIiwiVGFza0NvbW1lbnRzU2VydmljZSIsInNhdmVUYXNrQ29tbWVudCIsInJlbW92ZVRhc2tDb21tZW50IiwiVGFza3NDb250cm9sbGVyIiwiVHlwZXNTZXJ2aWNlIiwicHJpb3JpdGllcyIsInNhdmVDb21tZW50IiwiY29tbWVudCIsImNvbW1lbnRfaWQiLCJhbnN3ZXIiLCJjb21tZW50X3RleHQiLCJyZW1vdmVDb21tZW50IiwiUHJvZmlsZUNvbnRyb2xsZXIiLCJ1cGRhdGUiLCJiaXJ0aGRheSIsInVwZGF0ZVByb2ZpbGUiLCJVc2Vyc0NvbnRyb2xsZXIiLCJoaWRlRGlhbG9nIiwic2F2ZU5ld1VzZXIiLCJkZWZhdWx0cyIsIm92ZXJyaWRlIiwiYWxsIiwidXNlclJvbGVzIiwiaW50ZXJzZWN0aW9uIiwiaXNBZG1pbiIsImJ5dGVzIiwicHJlY2lzaW9uIiwiaXNOYU4iLCJpc0Zpbml0ZSIsInVuaXRzIiwibnVtYmVyIiwicG93IiwidG9GaXhlZCIsIlZjc0NvbnRyb2xsZXIiLCJWY3NTZXJ2aWNlIiwicGF0aHMiLCJ0b2dnbGVTcGxhc2hTY3JlZW4iLCJ1c2VybmFtZSIsInVzZXJuYW1lX2dpdGh1YiIsInJlcG8iLCJyZXBvX2dpdGh1YiIsInBhdGgiLCJsb2FkaW5nX3NjcmVlbiIsImZpbmlzaCIsInNvcnRSZXNvdXJjZXMiLCJhIiwiYiIsIm9wZW5GaWxlT3JEaXJlY3RvcnkiLCJwbGVhc2VXYWl0IiwibG9nbyIsImJhY2tncm91bmRDb2xvciIsImxvYWRpbmdIdG1sIiwiY29tcG9uZW50IiwicmVwbGFjZSIsInRyYW5zY2x1ZGUiLCJ0b29sYmFyQnV0dG9ucyIsImZvb3RlckJ1dHRvbnMiLCJiaW5kaW5ncyIsImJveFRpdGxlIiwidG9vbGJhckNsYXNzIiwidG9vbGJhckJnQ29sb3IiLCIkdHJhbnNjbHVkZSIsImN0cmwiLCIkb25Jbml0IiwibGF5b3V0QWxpZ24iLCJhdWRpdERldGFpbFRpdGxlIiwiYXVkaXRNb2RlbCIsIm1vZGVsSWQiLCJhdWRpdFR5cGUiLCJ0eXBlSWQiLCJhdWRpdFZhbHVlIiwiaXNEYXRlIiwiZW5kc1dpdGgiLCJOdW1iZXIiLCJpbml0aWFsRGF0ZSIsImZpbmFsRGF0ZSIsInNjaGVkdWxlZF90byIsImRhdGVfc3RhcnQiLCJjb3N0IiwiaG91clZhbHVlRGV2ZWxvcGVyIiwiaG91clZhbHVlQ2xpZW50IiwiaG91clZhbHVlRmluYWwiLCJyZWxlYXNlX2RhdGUiLCJjb25maXJtVGl0bGUiLCJjb25maXJtRGVzY3JpcHRpb24iLCJyZW1vdmVEZXNjcmlwdGlvbiIsImF1ZGl0IiwiY3JlYXRlZCIsInVwZGF0ZWRCZWZvcmUiLCJ1cGRhdGVkQWZ0ZXIiLCJkZWxldGVkIiwicmVzZXRQYXNzd29yZCIsImxvYWRpbmciLCJwcm9jZXNzaW5nIiwieWVzIiwibm8iLCJpbnRlcm5hbEVycm9yIiwibm90Rm91bmQiLCJub3RBdXRob3JpemVkIiwic2VhcmNoRXJyb3IiLCJzYXZlU3VjY2VzcyIsIm9wZXJhdGlvblN1Y2Nlc3MiLCJvcGVyYXRpb25FcnJvciIsInNhdmVFcnJvciIsInJlbW92ZVN1Y2Nlc3MiLCJyZW1vdmVFcnJvciIsInJlc291cmNlTm90Rm91bmRFcnJvciIsIm5vdE51bGxFcnJvciIsImR1cGxpY2F0ZWRSZXNvdXJjZUVycm9yIiwic3ByaW50RW5kZWRTdWNjZXNzIiwic3ByaW50RW5kZWRFcnJvciIsInN1Y2Nlc3NTaWduVXAiLCJlcnJvcnNTaWduVXAiLCJyZWxlYXNldEVuZGVkU3VjY2VzcyIsInJlbGVhc2VFbmRlZEVycm9yIiwicHJvamVjdEVuZGVkU3VjY2VzcyIsInByb2plY3RFbmRlZEVycm9yIiwidmFsaWRhdGUiLCJmaWVsZFJlcXVpcmVkIiwibGF5b3V0IiwiZXJyb3I0MDQiLCJsb2dvdXRJbmFjdGl2ZSIsImludmFsaWRDcmVkZW50aWFscyIsInVua25vd25FcnJvciIsInVzZXJOb3RGb3VuZCIsImRhc2hib2FyZCIsIndlbGNvbWUiLCJtYWlsRXJyb3JzIiwic2VuZE1haWxTdWNjZXNzIiwic2VuZE1haWxFcnJvciIsInBhc3N3b3JkU2VuZGluZ1N1Y2Nlc3MiLCJyZW1vdmVZb3VyU2VsZkVycm9yIiwidXNlckV4aXN0cyIsInByb2ZpbGUiLCJ1cGRhdGVFcnJvciIsInF1ZXJ5RGluYW1pYyIsIm5vRmlsdGVyIiwiYnJlYWRjcnVtYnMiLCJwcm9qZWN0cyIsImthbmJhbiIsInZjcyIsInJlbGVhc2VzIiwidGl0bGVzIiwibWFpbFNlbmQiLCJ0YXNrTGlzdCIsInVzZXJMaXN0IiwiYXVkaXRMaXN0IiwicmVnaXN0ZXIiLCJjbGVhckFsbCIsImxpc3QiLCJnZXRPdXQiLCJhZGQiLCJpbiIsImxvYWRJbWFnZSIsInNpZ251cCIsImNyaWFyUHJvamV0byIsInByb2plY3RMaXN0IiwidGFza3NMaXN0IiwibWlsZXN0b25lc0xpc3QiLCJyZXBseSIsImFjdGlvbiIsImRhdGVTdGFydCIsImFsbFJlc291cmNlcyIsInVwZGF0ZWQiLCJjb25maXJtUGFzc3dvcmQiLCJ0byIsInN1YmplY3QiLCJyZXN1bHRzIiwiZXF1YWxzIiwiZGlmZXJlbnQiLCJjb250ZWlucyIsInN0YXJ0V2l0aCIsImZpbmlzaFdpdGgiLCJiaWdnZXJUaGFuIiwiZXF1YWxzT3JCaWdnZXJUaGFuIiwibGVzc1RoYW4iLCJlcXVhbHNPckxlc3NUaGFuIiwidG90YWxUYXNrIiwicGVyZmlscyIsIm1lbnUiLCJ0b29sdGlwcyIsInBlcmZpbCIsInRyYW5zZmVyIiwibGlzdFRhc2siLCJUYXNrSW5mb0NvbnRyb2xsZXIiLCJVc2Vyc0RpYWxvZ0NvbnRyb2xsZXIiLCJ0cmFuc2ZlclVzZXIiXSwibWFwcGluZ3MiOiJBQUFBOzs7QUNDQSxDQUFDLFlBQVc7RUFDVjs7RUFFQUEsUUFBUUMsT0FBTyxPQUFPLENBQ3BCLGFBQ0EsVUFDQSxhQUNBLFlBQ0Esa0JBQ0EsYUFDQSxjQUNBLGdCQUNBLGlCQUNBLHdCQUNBLDBCQUNBLHFCQUNBLGNBQ0EsYUFDQSxXQUNBOztBRFpKOztBRVJDLENBQUEsWUFBWTtFQUNYOzs7RUFFQUQsUUFDR0MsT0FBTyxPQUNQQyxPQUFPQTs7OztFQUlWLFNBQVNBLE9BQU9DLFFBQVFDLG9CQUFvQkM7RUFDMUNDLG9CQUFvQkMsUUFBUUMsaUJBQWlCQyx1QkFBdUI7O0lBRXBFSCxtQkFDR0ksVUFBVSxrQkFDVkMseUJBQXlCOztJQUU1QkwsbUJBQW1CTSxpQkFBaUI7O0lBRXBDTCxPQUFPTSxPQUFPOzs7SUFHZFIsc0JBQXNCUyxlQUFlQyxTQUFTWixPQUFPYTs7O0lBR3JEWixtQkFBbUJhLE1BQU0sV0FDdEJDLGVBQWUsUUFBUTtNQUN0QkMsU0FBUztPQUVWQyxjQUFjLFNBQ2RDLFlBQVk7OztJQUdmakIsbUJBQW1Ca0I7O0lBRW5CZCxnQkFBZ0JlOztJQUVoQmQsc0JBQXNCZSxhQUFhLFVBQVNDLE1BQU07TUFDaEQsT0FBT0EsT0FBT2xCLE9BQU9rQixNQUFNQyxPQUFPLGdCQUFnQjs7OztBRk94RDs7QUc1Q0EsQ0FBQyxZQUFXOztFQUVWOzs7RUFFQTFCLFFBQ0dDLE9BQU8sT0FDUDBCLFdBQVcsaUJBQWlCQzs7Ozs7OztFQU8vQixTQUFTQSxjQUFjQyxRQUFRQyxNQUFNM0IsUUFBUTtJQUMzQyxJQUFJNEIsS0FBSzs7O0lBR1RBLEdBQUdDLFdBQVc7SUFDZEQsR0FBR0UsZ0JBQWdCOztJQUVuQkYsR0FBR0csU0FBYUE7SUFDaEJI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QUVWOzs7RUFFQWpHLFFBQ0dDLE9BQU8sT0FDUDBCLFdBQVcseUJBQXlCNm9COzs7O0VBSXZDLFNBQVNBLHNCQUFzQjlrQixhQUFhMEMsY0FBY3hDO0VBQ3hEaVYsaUJBQWlCRCxRQUFROztJQUV6QixJQUFJN1ksS0FBSzs7SUFFVEEsR0FBRzhELGFBQWFBO0lBQ2hCOUQsR0FBRytELGVBQWVBO0lBQ2xCL0QsR0FBR3NGLFFBQVFBOztJQUVYLElBQUlySCxRQUFRc00sVUFBVXVPLGtCQUFrQjtNQUN0QzlZLEdBQUcwb0IsZUFBZTVQLGdCQUFnQkM7Ozs7SUFJcENwVixZQUFZLGtCQUFrQjtNQUM1QjNELElBQUlBO01BQ0ppRSxjQUFjb0M7TUFDZHdELGNBQWNnUDtNQUNkM1UsU0FBUztRQUNQNEYsU0FBUzs7OztJQUliLFNBQVNoRyxhQUFhO01BQ3BCOUQsR0FBR29FLGVBQWU7OztJQUdwQixTQUFTTCxlQUFlO01BQ3RCLE9BQU85RixRQUFRa0gsT0FBT25GLEdBQUdrRixxQkFBcUJsRixHQUFHb0U7OztJQUduRCxTQUFTa0IsUUFBUTtNQUNmekIsU0FBU3lCOzs7S0ExQ2YiLCJmaWxlIjoiYXBwbGljYXRpb24uanMiLCJzb3VyY2VzQ29udGVudCI6WyIndXNlIHN0cmljdCc7XG5cbi8qZXNsaW50IGFuZ3VsYXIvZmlsZS1uYW1lOiAwKi9cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJywgWyduZ0FuaW1hdGUnLCAnbmdBcmlhJywgJ3VpLnJvdXRlcicsICduZ1Byb2RlYicsICd1aS51dGlscy5tYXNrcycsICd0ZXh0LW1hc2snLCAnbmdNYXRlcmlhbCcsICdtb2RlbEZhY3RvcnknLCAnbWQuZGF0YS50YWJsZScsICduZ01hdGVyaWFsRGF0ZVBpY2tlcicsICdwYXNjYWxwcmVjaHQudHJhbnNsYXRlJywgJ2FuZ3VsYXJGaWxlVXBsb2FkJywgJ25nTWVzc2FnZXMnLCAnanF3aWRnZXRzJywgJ3VpLm1hc2snLCAnbmdSb3V0ZSddKTtcbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29uZmlnKGNvbmZpZyk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBjb25maWcoR2xvYmFsLCAkbWRUaGVtaW5nUHJvdmlkZXIsICRtb2RlbEZhY3RvcnlQcm92aWRlciwgLy8gTk9TT05BUlxuICAkdHJhbnNsYXRlUHJvdmlkZXIsIG1vbWVudCwgJG1kQXJpYVByb3ZpZGVyLCAkbWREYXRlTG9jYWxlUHJvdmlkZXIpIHtcblxuICAgICR0cmFuc2xhdGVQcm92aWRlci51c2VMb2FkZXIoJ2xhbmd1YWdlTG9hZGVyJykudXNlU2FuaXRpemVWYWx1ZVN0cmF0ZWd5KCdlc2NhcGUnKTtcblxuICAgICR0cmFuc2xhdGVQcm92aWRlci51c2VQb3N0Q29tcGlsaW5nKHRydWUpO1xuXG4gICAgbW9tZW50LmxvY2FsZSgncHQtQlInKTtcblxuICAgIC8vb3Mgc2VydmnDp29zIHJlZmVyZW50ZSBhb3MgbW9kZWxzIHZhaSB1dGlsaXphciBjb21vIGJhc2UgbmFzIHVybHNcbiAgICAkbW9kZWxGYWN0b3J5UHJvdmlkZXIuZGVmYXVsdE9wdGlvbnMucHJlZml4ID0gR2xvYmFsLmFwaVBhdGg7XG5cbiAgICAvLyBDb25maWd1cmF0aW9uIHRoZW1lXG4gICAgJG1kVGhlbWluZ1Byb3ZpZGVyLnRoZW1lKCdkZWZhdWx0JykucHJpbWFyeVBhbGV0dGUoJ2dyZXknLCB7XG4gICAgICBkZWZhdWx0OiAnODAwJ1xuICAgIH0pLmFjY2VudFBhbGV0dGUoJ2FtYmVyJykud2FyblBhbGV0dGUoJ2RlZXAtb3JhbmdlJyk7XG5cbiAgICAvLyBFbmFibGUgYnJvd3NlciBjb2xvclxuICAgICRtZFRoZW1pbmdQcm92aWRlci5lbmFibGVCcm93c2VyQ29sb3IoKTtcblxuICAgICRtZEFyaWFQcm92aWRlci5kaXNhYmxlV2FybmluZ3MoKTtcblxuICAgICRtZERhdGVMb2NhbGVQcm92aWRlci5mb3JtYXREYXRlID0gZnVuY3Rpb24gKGRhdGUpIHtcbiAgICAgIHJldHVybiBkYXRlID8gbW9tZW50KGRhdGUpLmZvcm1hdCgnREQvTU0vWVlZWScpIDogJyc7XG4gICAgfTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbnRyb2xsZXIoJ0FwcENvbnRyb2xsZXInLCBBcHBDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8qKlxuICAgKiBDb250cm9sYWRvciByZXNwb25zw6F2ZWwgcG9yIGZ1bmNpb25hbGlkYWRlcyBxdWUgc8OjbyBhY2lvbmFkYXMgZW0gcXVhbHF1ZXIgdGVsYSBkbyBzaXN0ZW1hXG4gICAqXG4gICAqL1xuICBmdW5jdGlvbiBBcHBDb250cm9sbGVyKCRzdGF0ZSwgQXV0aCwgR2xvYmFsKSB7XG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIC8vYW5vIGF0dWFsIHBhcmEgc2VyIGV4aWJpZG8gbm8gcm9kYXDDqSBkbyBzaXN0ZW1hXG4gICAgdm0uYW5vQXR1YWwgPSBudWxsO1xuICAgIHZtLmFjdGl2ZVByb2plY3QgPSBudWxsO1xuXG4gICAgdm0ubG9nb3V0ID0gbG9nb3V0O1xuICAgIHZtLmdldEltYWdlUGVyZmlsID0gZ2V0SW1hZ2VQZXJmaWw7XG4gICAgdm0uZ2V0TG9nb01lbnUgPSBnZXRMb2dvTWVudTtcbiAgICB2bS5zZXRBY3RpdmVQcm9qZWN0ID0gc2V0QWN0aXZlUHJvamVjdDtcbiAgICB2bS5nZXRBY3RpdmVQcm9qZWN0ID0gZ2V0QWN0aXZlUHJvamVjdDtcbiAgICB2bS5yZW1vdmVBY3RpdmVQcm9qZWN0ID0gcmVtb3ZlQWN0aXZlUHJvamVjdDtcblxuICAgIGFjdGl2YXRlKCk7XG5cbiAgICBmdW5jdGlvbiBhY3RpdmF0ZSgpIHtcbiAgICAgIHZhciBkYXRlID0gbmV3IERhdGUoKTtcblxuICAgICAgdm0uYW5vQXR1YWwgPSBkYXRlLmdldEZ1bGxZZWFyKCk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gbG9nb3V0KCkge1xuICAgICAgQXV0aC5sb2dvdXQoKS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgJHN0YXRlLmdvKEdsb2JhbC5sb2dpblN0YXRlKTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGdldEltYWdlUGVyZmlsKCkge1xuICAgICAgcmV0dXJuIEF1dGguY3VycmVudFVzZXIgJiYgQXV0aC5jdXJyZW50VXNlci5pbWFnZSA/IEF1dGguY3VycmVudFVzZXIuaW1hZ2UgOiBHbG9iYWwuaW1hZ2VQYXRoICsgJy9ub19hdmF0YXIuZ2lmJztcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBnZXRMb2dvTWVudSgpIHtcbiAgICAgIHJldHVybiBHbG9iYWwuaW1hZ2VQYXRoICsgJy9sb2dvLXZlcnRpY2FsLnBuZyc7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gc2V0QWN0aXZlUHJvamVjdChwcm9qZWN0KSB7XG4gICAgICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbSgncHJvamVjdCcsIHByb2plY3QpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGdldEFjdGl2ZVByb2plY3QoKSB7XG4gICAgICByZXR1cm4gbG9jYWxTdG9yYWdlLmdldEl0ZW0oJ3Byb2plY3QnKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiByZW1vdmVBY3RpdmVQcm9qZWN0KCkge1xuICAgICAgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oJ3Byb2plY3QnKTtcbiAgICB9XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbi8qZXNsaW50IGFuZ3VsYXIvZmlsZS1uYW1lOiAwLCBuby11bmRlZjogMCovXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgLyoqXG4gICAqIFRyYW5zZm9ybWEgYmlibGlvdGVjYXMgZXh0ZXJuYXMgZW0gc2VydmnDp29zIGRvIGFuZ3VsYXIgcGFyYSBzZXIgcG9zc8OtdmVsIHV0aWxpemFyXG4gICAqIGF0cmF2w6lzIGRhIGluamXDp8OjbyBkZSBkZXBlbmTDqm5jaWFcbiAgICovXG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbnN0YW50KCdsb2Rhc2gnLCBfKS5jb25zdGFudCgnbW9tZW50JywgbW9tZW50KTtcbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29uc3RhbnQoJ0dsb2JhbCcsIHtcbiAgICBhcHBOYW1lOiAnRnJlZWxhZ2lsZScsXG4gICAgaG9tZVN0YXRlOiAnYXBwLnByb2plY3RzJyxcbiAgICBsb2dpblVybDogJ2FwcC9sb2dpbicsXG4gICAgcmVzZXRQYXNzd29yZFVybDogJ2FwcC9wYXNzd29yZC9yZXNldCcsXG4gICAgbG9naW5TdGF0ZTogJ2FwcC5sb2dpbicsXG4gICAgcmVzZXRQYXNzd29yZFN0YXRlOiAnYXBwLnBhc3N3b3JkLXJlc2V0JyxcbiAgICBub3RBdXRob3JpemVkU3RhdGU6ICdhcHAubm90LWF1dGhvcml6ZWQnLFxuICAgIHRva2VuS2V5OiAnc2VydmVyX3Rva2VuJyxcbiAgICBjbGllbnRQYXRoOiAnY2xpZW50L2FwcCcsXG4gICAgYXBpUGF0aDogJ2FwaS92MScsXG4gICAgaW1hZ2VQYXRoOiAnY2xpZW50L2ltYWdlcydcbiAgfSk7XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCAkdXJsUm91dGVyUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdhcHAnLCB7XG4gICAgICB1cmw6ICcvYXBwJyxcbiAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvbGF5b3V0L2FwcC5odG1sJyxcbiAgICAgIGFic3RyYWN0OiB0cnVlLFxuICAgICAgcmVzb2x2ZTogeyAvL2Vuc3VyZSBsYW5ncyBpcyByZWFkeSBiZWZvcmUgcmVuZGVyIHZpZXdcbiAgICAgICAgdHJhbnNsYXRlUmVhZHk6IFsnJHRyYW5zbGF0ZScsICckcScsIGZ1bmN0aW9uICgkdHJhbnNsYXRlLCAkcSkge1xuICAgICAgICAgIHZhciBkZWZlcnJlZCA9ICRxLmRlZmVyKCk7XG5cbiAgICAgICAgICAkdHJhbnNsYXRlLnVzZSgncHQtQlInKS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIGRlZmVycmVkLnJlc29sdmUoKTtcbiAgICAgICAgICB9KTtcblxuICAgICAgICAgIHJldHVybiBkZWZlcnJlZC5wcm9taXNlO1xuICAgICAgICB9XVxuICAgICAgfVxuICAgIH0pLnN0YXRlKEdsb2JhbC5ub3RBdXRob3JpemVkU3RhdGUsIHtcbiAgICAgIHVybDogJy9hY2Vzc28tbmVnYWRvJyxcbiAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvbGF5b3V0L25vdC1hdXRob3JpemVkLmh0bWwnLFxuICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IGZhbHNlIH1cbiAgICB9KTtcblxuICAgICR1cmxSb3V0ZXJQcm92aWRlci53aGVuKCcvcGFzc3dvcmQvcmVzZXQnLCBHbG9iYWwucmVzZXRQYXNzd29yZFVybCk7XG4gICAgJHVybFJvdXRlclByb3ZpZGVyLndoZW4oJy9hcHAnLCBHbG9iYWwubG9naW5VcmwpO1xuICAgICR1cmxSb3V0ZXJQcm92aWRlci5vdGhlcndpc2UoR2xvYmFsLmxvZ2luVXJsKTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5ydW4ocnVuKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIHJ1bigkcm9vdFNjb3BlLCAkc3RhdGUsICRzdGF0ZVBhcmFtcywgQXV0aCwgR2xvYmFsKSB7XG4gICAgLy8gTk9TT05BUlxuICAgIC8vc2V0YWRvIG5vIHJvb3RTY29wZSBwYXJhIHBvZGVyIHNlciBhY2Vzc2FkbyBuYXMgdmlld3Mgc2VtIHByZWZpeG8gZGUgY29udHJvbGxlclxuICAgICRyb290U2NvcGUuJHN0YXRlID0gJHN0YXRlO1xuICAgICRyb290U2NvcGUuJHN0YXRlUGFyYW1zID0gJHN0YXRlUGFyYW1zO1xuICAgICRyb290U2NvcGUuYXV0aCA9IEF1dGg7XG4gICAgJHJvb3RTY29wZS5nbG9iYWwgPSBHbG9iYWw7XG5cbiAgICAvL25vIGluaWNpbyBjYXJyZWdhIG8gdXN1w6FyaW8gZG8gbG9jYWxzdG9yYWdlIGNhc28gbyB1c3XDoXJpbyBlc3RhamEgYWJyaW5kbyBvIG5hdmVnYWRvclxuICAgIC8vcGFyYSB2b2x0YXIgYXV0ZW50aWNhZG9cbiAgICBBdXRoLnJldHJpZXZlVXNlckZyb21Mb2NhbFN0b3JhZ2UoKTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbnRyb2xsZXIoJ0F1ZGl0Q29udHJvbGxlcicsIEF1ZGl0Q29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBBdWRpdENvbnRyb2xsZXIoJGNvbnRyb2xsZXIsIEF1ZGl0U2VydmljZSwgUHJEaWFsb2csIEdsb2JhbCwgJHRyYW5zbGF0ZSkge1xuICAgIC8vIE5PU09OQVJcbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0ub25BY3RpdmF0ZSA9IG9uQWN0aXZhdGU7XG4gICAgdm0uYXBwbHlGaWx0ZXJzID0gYXBwbHlGaWx0ZXJzO1xuICAgIHZtLnZpZXdEZXRhaWwgPSB2aWV3RGV0YWlsO1xuXG4gICAgJGNvbnRyb2xsZXIoJ0NSVURDb250cm9sbGVyJywgeyB2bTogdm0sIG1vZGVsU2VydmljZTogQXVkaXRTZXJ2aWNlLCBvcHRpb25zOiB7fSB9KTtcblxuICAgIGZ1bmN0aW9uIG9uQWN0aXZhdGUoKSB7XG4gICAgICB2bS5tb2RlbHMgPSBbXTtcbiAgICAgIHZtLnF1ZXJ5RmlsdGVycyA9IHt9O1xuXG4gICAgICAvL1BlZ2EgdG9kb3Mgb3MgbW9kZWxzIGRvIHNlcnZlciBlIG1vbnRhIHVtYSBsaXN0YSBwcm8gQ29tYm9Cb3hcbiAgICAgIEF1ZGl0U2VydmljZS5nZXRBdWRpdGVkTW9kZWxzKCkudGhlbihmdW5jdGlvbiAoZGF0YSkge1xuICAgICAgICB2YXIgbW9kZWxzID0gW3sgaWQ6ICcnLCBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KCdnbG9iYWwuYWxsJykgfV07XG5cbiAgICAgICAgZGF0YS5tb2RlbHMuc29ydCgpO1xuXG4gICAgICAgIGZvciAodmFyIGluZGV4ID0gMDsgaW5kZXggPCBkYXRhLm1vZGVscy5sZW5ndGg7IGluZGV4KyspIHtcbiAgICAgICAgICB2YXIgbW9kZWwgPSBkYXRhLm1vZGVsc1tpbmRleF07XG5cbiAgICAgICAgICBtb2RlbHMucHVzaCh7XG4gICAgICAgICAgICBpZDogbW9kZWwsXG4gICAgICAgICAgICBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KCdtb2RlbHMuJyArIG1vZGVsLnRvTG93ZXJDYXNlKCkpXG4gICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICB2bS5tb2RlbHMgPSBtb2RlbHM7XG4gICAgICAgIHZtLnF1ZXJ5RmlsdGVycy5tb2RlbCA9IHZtLm1vZGVsc1swXS5pZDtcbiAgICAgIH0pO1xuXG4gICAgICB2bS50eXBlcyA9IEF1ZGl0U2VydmljZS5saXN0VHlwZXMoKTtcbiAgICAgIHZtLnF1ZXJ5RmlsdGVycy50eXBlID0gdm0udHlwZXNbMF0uaWQ7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gYXBwbHlGaWx0ZXJzKGRlZmF1bHRRdWVyeUZpbHRlcnMpIHtcbiAgICAgIHJldHVybiBhbmd1bGFyLmV4dGVuZChkZWZhdWx0UXVlcnlGaWx0ZXJzLCB2bS5xdWVyeUZpbHRlcnMpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIHZpZXdEZXRhaWwoYXVkaXREZXRhaWwpIHtcbiAgICAgIHZhciBjb25maWcgPSB7XG4gICAgICAgIGxvY2FsczogeyBhdWRpdERldGFpbDogYXVkaXREZXRhaWwgfSxcbiAgICAgICAgLyoqIEBuZ0luamVjdCAqL1xuICAgICAgICBjb250cm9sbGVyOiBmdW5jdGlvbiBjb250cm9sbGVyKGF1ZGl0RGV0YWlsLCBQckRpYWxvZykge1xuICAgICAgICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICAgICAgICB2bS5jbG9zZSA9IGNsb3NlO1xuXG4gICAgICAgICAgYWN0aXZhdGUoKTtcblxuICAgICAgICAgIGZ1bmN0aW9uIGFjdGl2YXRlKCkge1xuICAgICAgICAgICAgaWYgKGFuZ3VsYXIuaXNBcnJheShhdWRpdERldGFpbC5vbGQpICYmIGF1ZGl0RGV0YWlsLm9sZC5sZW5ndGggPT09IDApIGF1ZGl0RGV0YWlsLm9sZCA9IG51bGw7XG4gICAgICAgICAgICBpZiAoYW5ndWxhci5pc0FycmF5KGF1ZGl0RGV0YWlsLm5ldykgJiYgYXVkaXREZXRhaWwubmV3Lmxlbmd0aCA9PT0gMCkgYXVkaXREZXRhaWwubmV3ID0gbnVsbDtcblxuICAgICAgICAgICAgdm0uYXVkaXREZXRhaWwgPSBhdWRpdERldGFpbDtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICBmdW5jdGlvbiBjbG9zZSgpIHtcbiAgICAgICAgICAgIFByRGlhbG9nLmNsb3NlKCk7XG4gICAgICAgICAgfVxuICAgICAgICB9LFxuICAgICAgICBjb250cm9sbGVyQXM6ICdhdWRpdERldGFpbEN0cmwnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL2F1ZGl0L2F1ZGl0LWRldGFpbC5odG1sJyxcbiAgICAgICAgaGFzQmFja2Ryb3A6IHRydWVcbiAgICAgIH07XG5cbiAgICAgIFByRGlhbG9nLmN1c3RvbShjb25maWcpO1xuICAgIH1cbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25maWcocm91dGVzKTtcblxuICAvKipcbiAgICogQXJxdWl2byBkZSBjb25maWd1cmHDp8OjbyBjb20gYXMgcm90YXMgZXNwZWPDrWZpY2FzIGRlIGF1ZGl0b3JpYVxuICAgKlxuICAgKiBAcGFyYW0ge2FueX0gJHN0YXRlUHJvdmlkZXJcbiAgICogQHBhcmFtIHthbnl9IEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdhcHAuYXVkaXQnLCB7XG4gICAgICB1cmw6ICcvYXVkaXRvcmlhJyxcbiAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvYXVkaXQvYXVkaXQuaHRtbCcsXG4gICAgICBjb250cm9sbGVyOiAnQXVkaXRDb250cm9sbGVyIGFzIGF1ZGl0Q3RybCcsXG4gICAgICBkYXRhOiB7IG5lZWRBdXRoZW50aWNhdGlvbjogdHJ1ZSwgbmVlZFByb2ZpbGU6IFsnYWRtaW4nXSB9XG4gICAgfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmFjdG9yeSgnQXVkaXRTZXJ2aWNlJywgQXVkaXRTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIEF1ZGl0U2VydmljZShzZXJ2aWNlRmFjdG9yeSwgJHRyYW5zbGF0ZSkge1xuICAgIHJldHVybiBzZXJ2aWNlRmFjdG9yeSgnYXVkaXQnLCB7XG4gICAgICBhY3Rpb25zOiB7XG4gICAgICAgIGdldEF1ZGl0ZWRNb2RlbHM6IHtcbiAgICAgICAgICBtZXRob2Q6ICdHRVQnLFxuICAgICAgICAgIHVybDogJ21vZGVscydcbiAgICAgICAgfVxuICAgICAgfSxcbiAgICAgIGluc3RhbmNlOiB7fSxcbiAgICAgIGxpc3RUeXBlczogZnVuY3Rpb24gbGlzdFR5cGVzKCkge1xuICAgICAgICB2YXIgYXVkaXRQYXRoID0gJ3ZpZXdzLmZpZWxkcy5hdWRpdC4nO1xuXG4gICAgICAgIHJldHVybiBbeyBpZDogJycsIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoYXVkaXRQYXRoICsgJ2FsbFJlc291cmNlcycpIH0sIHsgaWQ6ICdjcmVhdGVkJywgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudChhdWRpdFBhdGggKyAndHlwZS5jcmVhdGVkJykgfSwgeyBpZDogJ3VwZGF0ZWQnLCBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KGF1ZGl0UGF0aCArICd0eXBlLnVwZGF0ZWQnKSB9LCB7IGlkOiAnZGVsZXRlZCcsIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoYXVkaXRQYXRoICsgJ3R5cGUuZGVsZXRlZCcpIH1dO1xuICAgICAgfVxuICAgIH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKlxuICAgKiBBcnF1aXZvIGRlIGNvbmZpZ3VyYcOnw6NvIGNvbSBhcyByb3RhcyBlc3BlY8OtZmljYXMgZG8gcmVjdXJzbyB1c2VyXG4gICAqXG4gICAqIEBwYXJhbSB7YW55fSAkc3RhdGVQcm92aWRlclxuICAgKiBAcGFyYW0ge2FueX0gR2xvYmFsXG4gICAqL1xuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvdXRlcygkc3RhdGVQcm92aWRlciwgR2xvYmFsKSB7XG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoR2xvYmFsLnJlc2V0UGFzc3dvcmRTdGF0ZSwge1xuICAgICAgdXJsOiAnL3Bhc3N3b3JkL3Jlc2V0Lzp0b2tlbicsXG4gICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL2F1dGgvcmVzZXQtcGFzcy1mb3JtLmh0bWwnLFxuICAgICAgY29udHJvbGxlcjogJ1Bhc3N3b3JkQ29udHJvbGxlciBhcyBwYXNzQ3RybCcsXG4gICAgICBkYXRhOiB7IG5lZWRBdXRoZW50aWNhdGlvbjogZmFsc2UgfVxuICAgIH0pLnN0YXRlKEdsb2JhbC5sb2dpblN0YXRlLCB7XG4gICAgICB1cmw6ICcvbG9naW4nLFxuICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9hdXRoL2xvZ2luLmh0bWwnLFxuICAgICAgY29udHJvbGxlcjogJ0xvZ2luQ29udHJvbGxlciBhcyBsb2dpbkN0cmwnLFxuICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IGZhbHNlIH1cbiAgICB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5mYWN0b3J5KCdBdXRoJywgQXV0aCk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBBdXRoKCRodHRwLCAkcSwgR2xvYmFsLCBVc2Vyc1NlcnZpY2UpIHtcbiAgICAvLyBOT1NPTkFSXG4gICAgdmFyIGF1dGggPSB7XG4gICAgICBsb2dpbjogbG9naW4sXG4gICAgICBsb2dvdXQ6IGxvZ291dCxcbiAgICAgIHVwZGF0ZUN1cnJlbnRVc2VyOiB1cGRhdGVDdXJyZW50VXNlcixcbiAgICAgIHJldHJpZXZlVXNlckZyb21Mb2NhbFN0b3JhZ2U6IHJldHJpZXZlVXNlckZyb21Mb2NhbFN0b3JhZ2UsXG4gICAgICBhdXRoZW50aWNhdGVkOiBhdXRoZW50aWNhdGVkLFxuICAgICAgc2VuZEVtYWlsUmVzZXRQYXNzd29yZDogc2VuZEVtYWlsUmVzZXRQYXNzd29yZCxcbiAgICAgIHJlbW90ZVZhbGlkYXRlVG9rZW46IHJlbW90ZVZhbGlkYXRlVG9rZW4sXG4gICAgICBnZXRUb2tlbjogZ2V0VG9rZW4sXG4gICAgICBzZXRUb2tlbjogc2V0VG9rZW4sXG4gICAgICBjbGVhclRva2VuOiBjbGVhclRva2VuLFxuICAgICAgY3VycmVudFVzZXI6IG51bGxcbiAgICB9O1xuXG4gICAgZnVuY3Rpb24gY2xlYXJUb2tlbigpIHtcbiAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKEdsb2JhbC50b2tlbktleSk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gc2V0VG9rZW4odG9rZW4pIHtcbiAgICAgIGxvY2FsU3RvcmFnZS5zZXRJdGVtKEdsb2JhbC50b2tlbktleSwgdG9rZW4pO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGdldFRva2VuKCkge1xuICAgICAgcmV0dXJuIGxvY2FsU3RvcmFnZS5nZXRJdGVtKEdsb2JhbC50b2tlbktleSk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gcmVtb3RlVmFsaWRhdGVUb2tlbigpIHtcbiAgICAgIHZhciBkZWZlcnJlZCA9ICRxLmRlZmVyKCk7XG5cbiAgICAgIGlmIChhdXRoLmF1dGhlbnRpY2F0ZWQoKSkge1xuICAgICAgICAkaHR0cC5nZXQoR2xvYmFsLmFwaVBhdGggKyAnL2F1dGhlbnRpY2F0ZS9jaGVjaycpLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICAgIGRlZmVycmVkLnJlc29sdmUodHJ1ZSk7XG4gICAgICAgIH0sIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICBhdXRoLmxvZ291dCgpO1xuXG4gICAgICAgICAgZGVmZXJyZWQucmVqZWN0KGZhbHNlKTtcbiAgICAgICAgfSk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBhdXRoLmxvZ291dCgpO1xuXG4gICAgICAgIGRlZmVycmVkLnJlamVjdChmYWxzZSk7XG4gICAgICB9XG5cbiAgICAgIHJldHVybiBkZWZlcnJlZC5wcm9taXNlO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFZlcmlmaWNhIHNlIG8gdXN1w6FyaW8gZXN0w6EgYXV0ZW50aWNhZG9cbiAgICAgKlxuICAgICAqIEByZXR1cm5zIHtib29sZWFufVxuICAgICAqL1xuICAgIGZ1bmN0aW9uIGF1dGhlbnRpY2F0ZWQoKSB7XG4gICAgICByZXR1cm4gYXV0aC5nZXRUb2tlbigpICE9PSBudWxsO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlY3VwZXJhIG8gdXN1w6FyaW8gZG8gbG9jYWxTdG9yYWdlXG4gICAgICovXG4gICAgZnVuY3Rpb24gcmV0cmlldmVVc2VyRnJvbUxvY2FsU3RvcmFnZSgpIHtcbiAgICAgIHZhciB1c2VyID0gbG9jYWxTdG9yYWdlLmdldEl0ZW0oJ3VzZXInKTtcblxuICAgICAgaWYgKHVzZXIpIHtcbiAgICAgICAgYXV0aC5jdXJyZW50VXNlciA9IGFuZ3VsYXIubWVyZ2UobmV3IFVzZXJzU2VydmljZSgpLCBhbmd1bGFyLmZyb21Kc29uKHVzZXIpKTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBHdWFyZGEgbyB1c3XDoXJpbyBubyBsb2NhbFN0b3JhZ2UgcGFyYSBjYXNvIG8gdXN1w6FyaW8gZmVjaGUgZSBhYnJhIG8gbmF2ZWdhZG9yXG4gICAgICogZGVudHJvIGRvIHRlbXBvIGRlIHNlc3PDo28gc2VqYSBwb3Nzw612ZWwgcmVjdXBlcmFyIG8gdG9rZW4gYXV0ZW50aWNhZG8uXG4gICAgICpcbiAgICAgKiBNYW50w6ltIGEgdmFyacOhdmVsIGF1dGguY3VycmVudFVzZXIgcGFyYSBmYWNpbGl0YXIgbyBhY2Vzc28gYW8gdXN1w6FyaW8gbG9nYWRvIGVtIHRvZGEgYSBhcGxpY2HDp8Ojb1xuICAgICAqXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gdXNlciBVc3XDoXJpbyBhIHNlciBhdHVhbGl6YWRvLiBDYXNvIHNlamEgcGFzc2FkbyBudWxsIGxpbXBhXG4gICAgICogdG9kYXMgYXMgaW5mb3JtYcOnw7VlcyBkbyB1c3XDoXJpbyBjb3JyZW50ZS5cbiAgICAgKi9cbiAgICBmdW5jdGlvbiB1cGRhdGVDdXJyZW50VXNlcih1c2VyKSB7XG4gICAgICB2YXIgZGVmZXJyZWQgPSAkcS5kZWZlcigpO1xuXG4gICAgICBpZiAodXNlcikge1xuICAgICAgICB1c2VyID0gYW5ndWxhci5tZXJnZShuZXcgVXNlcnNTZXJ2aWNlKCksIHVzZXIpO1xuXG4gICAgICAgIHZhciBqc29uVXNlciA9IGFuZ3VsYXIudG9Kc29uKHVzZXIpO1xuXG4gICAgICAgIGxvY2FsU3RvcmFnZS5zZXRJdGVtKCd1c2VyJywganNvblVzZXIpO1xuICAgICAgICBhdXRoLmN1cnJlbnRVc2VyID0gdXNlcjtcblxuICAgICAgICBkZWZlcnJlZC5yZXNvbHZlKHVzZXIpO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oJ3VzZXInKTtcbiAgICAgICAgYXV0aC5jdXJyZW50VXNlciA9IG51bGw7XG4gICAgICAgIGF1dGguY2xlYXJUb2tlbigpO1xuXG4gICAgICAgIGRlZmVycmVkLnJlamVjdCgpO1xuICAgICAgfVxuXG4gICAgICByZXR1cm4gZGVmZXJyZWQucHJvbWlzZTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFsaXphIG8gbG9naW4gZG8gdXN1w6FyaW9cbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSBjcmVkZW50aWFscyBFbWFpbCBlIFNlbmhhIGRvIHVzdcOhcmlvXG4gICAgICogQHJldHVybnMge3Byb21pc2V9IFVtYSBwcm9taXNlIGNvbSBvIHJlc3VsdGFkbyBkbyBjaGFtYWRhIG5vIGJhY2tlbmRcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBsb2dpbihjcmVkZW50aWFscykge1xuICAgICAgdmFyIGRlZmVycmVkID0gJHEuZGVmZXIoKTtcblxuICAgICAgJGh0dHAucG9zdChHbG9iYWwuYXBpUGF0aCArICcvYXV0aGVudGljYXRlJywgY3JlZGVudGlhbHMpLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgIGF1dGguc2V0VG9rZW4ocmVzcG9uc2UuZGF0YS50b2tlbik7XG5cbiAgICAgICAgcmV0dXJuICRodHRwLmdldChHbG9iYWwuYXBpUGF0aCArICcvYXV0aGVudGljYXRlL3VzZXInKTtcbiAgICAgIH0pLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgIGF1dGgudXBkYXRlQ3VycmVudFVzZXIocmVzcG9uc2UuZGF0YS51c2VyKTtcblxuICAgICAgICBkZWZlcnJlZC5yZXNvbHZlKCk7XG4gICAgICB9LCBmdW5jdGlvbiAoZXJyb3IpIHtcbiAgICAgICAgYXV0aC5sb2dvdXQoKTtcblxuICAgICAgICBkZWZlcnJlZC5yZWplY3QoZXJyb3IpO1xuICAgICAgfSk7XG5cbiAgICAgIHJldHVybiBkZWZlcnJlZC5wcm9taXNlO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIERlc2xvZ2Egb3MgdXN1w6FyaW9zLiBDb21vIG7Do28gdGVuIG5lbmh1bWEgaW5mb3JtYcOnw6NvIG5hIHNlc3PDo28gZG8gc2Vydmlkb3JcbiAgICAgKiBlIHVtIHRva2VuIHVtYSB2ZXogZ2VyYWRvIG7Do28gcG9kZSwgcG9yIHBhZHLDo28sIHNlciBpbnZhbGlkYWRvIGFudGVzIGRvIHNldSB0ZW1wbyBkZSBleHBpcmHDp8OjbyxcbiAgICAgKiBzb21lbnRlIGFwYWdhbW9zIG9zIGRhZG9zIGRvIHVzdcOhcmlvIGUgbyB0b2tlbiBkbyBuYXZlZ2Fkb3IgcGFyYSBlZmV0aXZhciBvIGxvZ291dC5cbiAgICAgKlxuICAgICAqIEByZXR1cm5zIHtwcm9taXNlfSBVbWEgcHJvbWlzZSBjb20gbyByZXN1bHRhZG8gZGEgb3BlcmHDp8Ojb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGxvZ291dCgpIHtcbiAgICAgIHZhciBkZWZlcnJlZCA9ICRxLmRlZmVyKCk7XG5cbiAgICAgIGF1dGgudXBkYXRlQ3VycmVudFVzZXIobnVsbCk7XG4gICAgICBkZWZlcnJlZC5yZXNvbHZlKCk7XG5cbiAgICAgIHJldHVybiBkZWZlcnJlZC5wcm9taXNlO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEVudmlhIHVtIGVtYWlsIHBhcmEgcmVjdXBlcmHDp8OjbyBkZSBzZW5oYVxuICAgICAqIEBwYXJhbSB7T2JqZWN0fSByZXNldERhdGEgLSBPYmpldG8gY29udGVuZG8gbyBlbWFpbFxuICAgICAqIEByZXR1cm4ge1Byb21pc2V9IC0gUmV0b3JuYSB1bWEgcHJvbWlzZSBwYXJhIHNlciByZXNvbHZpZGFcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBzZW5kRW1haWxSZXNldFBhc3N3b3JkKHJlc2V0RGF0YSkge1xuICAgICAgdmFyIGRlZmVycmVkID0gJHEuZGVmZXIoKTtcblxuICAgICAgJGh0dHAucG9zdChHbG9iYWwuYXBpUGF0aCArICcvcGFzc3dvcmQvZW1haWwnLCByZXNldERhdGEpLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgIGRlZmVycmVkLnJlc29sdmUocmVzcG9uc2UuZGF0YSk7XG4gICAgICB9LCBmdW5jdGlvbiAoZXJyb3IpIHtcbiAgICAgICAgZGVmZXJyZWQucmVqZWN0KGVycm9yKTtcbiAgICAgIH0pO1xuXG4gICAgICByZXR1cm4gZGVmZXJyZWQucHJvbWlzZTtcbiAgICB9XG5cbiAgICByZXR1cm4gYXV0aDtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbnRyb2xsZXIoJ0xvZ2luQ29udHJvbGxlcicsIExvZ2luQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBMb2dpbkNvbnRyb2xsZXIoJHN0YXRlLCBBdXRoLCBHbG9iYWwsIFByRGlhbG9nKSB7XG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIHZtLmxvZ2luID0gbG9naW47XG4gICAgdm0ub3BlbkRpYWxvZ1Jlc2V0UGFzcyA9IG9wZW5EaWFsb2dSZXNldFBhc3M7XG4gICAgdm0ub3BlbkRpYWxvZ1NpZ25VcCA9IG9wZW5EaWFsb2dTaWduVXA7XG5cbiAgICBhY3RpdmF0ZSgpO1xuXG4gICAgZnVuY3Rpb24gYWN0aXZhdGUoKSB7XG4gICAgICB2bS5jcmVkZW50aWFscyA9IHt9O1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGxvZ2luKCkge1xuICAgICAgdmFyIGNyZWRlbnRpYWxzID0ge1xuICAgICAgICBlbWFpbDogdm0uY3JlZGVudGlhbHMuZW1haWwsXG4gICAgICAgIHBhc3N3b3JkOiB2bS5jcmVkZW50aWFscy5wYXNzd29yZFxuICAgICAgfTtcblxuICAgICAgQXV0aC5sb2dpbihjcmVkZW50aWFscykudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgICRzdGF0ZS5nbyhHbG9iYWwuaG9tZVN0YXRlKTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEV4aWJlIG8gZGlhbG9nIHBhcmEgcmVjdXBlcmHDp8OjbyBkZSBzZW5oYVxuICAgICAqL1xuICAgIGZ1bmN0aW9uIG9wZW5EaWFsb2dSZXNldFBhc3MoKSB7XG4gICAgICB2YXIgY29uZmlnID0ge1xuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL2F1dGgvc2VuZC1yZXNldC1kaWFsb2cuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdQYXNzd29yZENvbnRyb2xsZXIgYXMgcGFzc0N0cmwnLFxuICAgICAgICBoYXNCYWNrZHJvcDogdHJ1ZVxuICAgICAgfTtcblxuICAgICAgUHJEaWFsb2cuY3VzdG9tKGNvbmZpZyk7XG4gICAgfVxuICAgIC8qKlxuICAgICAqIEV4aWJlIG8gZGlhbG9nIHBhcmEgcmVjdXBlcmHDp8OjbyBkZSBzZW5oYVxuICAgICAqL1xuICAgIGZ1bmN0aW9uIG9wZW5EaWFsb2dTaWduVXAoKSB7XG4gICAgICB2YXIgY29uZmlnID0ge1xuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL3VzZXJzL3VzZXItZm9ybS5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ1VzZXJzQ29udHJvbGxlciBhcyB1c2Vyc0N0cmwnLFxuICAgICAgICBoYXNCYWNrZHJvcDogdHJ1ZVxuICAgICAgfTtcblxuICAgICAgUHJEaWFsb2cuY3VzdG9tKGNvbmZpZyk7XG4gICAgfVxuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29udHJvbGxlcignUGFzc3dvcmRDb250cm9sbGVyJywgUGFzc3dvcmRDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIFBhc3N3b3JkQ29udHJvbGxlcihHbG9iYWwsICRzdGF0ZVBhcmFtcywgJGh0dHAsICR0aW1lb3V0LCAkc3RhdGUsIC8vIE5PU09OQVJcbiAgUHJUb2FzdCwgUHJEaWFsb2csIEF1dGgsICR0cmFuc2xhdGUpIHtcblxuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICB2bS5zZW5kUmVzZXQgPSBzZW5kUmVzZXQ7XG4gICAgdm0uY2xvc2VEaWFsb2cgPSBjbG9zZURpYWxvZztcbiAgICB2bS5jbGVhbkZvcm0gPSBjbGVhbkZvcm07XG4gICAgdm0uc2VuZEVtYWlsUmVzZXRQYXNzd29yZCA9IHNlbmRFbWFpbFJlc2V0UGFzc3dvcmQ7XG5cbiAgICBhY3RpdmF0ZSgpO1xuXG4gICAgZnVuY3Rpb24gYWN0aXZhdGUoKSB7XG4gICAgICB2bS5yZXNldCA9IHsgZW1haWw6ICcnLCB0b2tlbjogJHN0YXRlUGFyYW1zLnRva2VuIH07XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhbGl6YSBhIGFsdGVyYcOnw6NvIGRhIHNlbmhhIGRvIHVzdcOhcmlvIGUgbyByZWRpcmVjaW9uYSBwYXJhIGEgdGVsYSBkZSBsb2dpblxuICAgICAqL1xuICAgIGZ1bmN0aW9uIHNlbmRSZXNldCgpIHtcbiAgICAgICRodHRwLnBvc3QoR2xvYmFsLmFwaVBhdGggKyAnL3Bhc3N3b3JkL3Jlc2V0Jywgdm0ucmVzZXQpLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICBQclRvYXN0LnN1Y2Nlc3MoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5vcGVyYXRpb25TdWNjZXNzJykpO1xuICAgICAgICAkdGltZW91dChmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgJHN0YXRlLmdvKEdsb2JhbC5sb2dpblN0YXRlKTtcbiAgICAgICAgfSwgMTUwMCk7XG4gICAgICB9LCBmdW5jdGlvbiAoZXJyb3IpIHtcbiAgICAgICAgaWYgKGVycm9yLnN0YXR1cyAhPT0gNDAwICYmIGVycm9yLnN0YXR1cyAhPT0gNTAwKSB7XG4gICAgICAgICAgdmFyIG1zZyA9ICcnO1xuXG4gICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCBlcnJvci5kYXRhLnBhc3N3b3JkLmxlbmd0aDsgaSsrKSB7XG4gICAgICAgICAgICBtc2cgKz0gZXJyb3IuZGF0YS5wYXNzd29yZFtpXSArICc8YnI+JztcbiAgICAgICAgICB9XG4gICAgICAgICAgUHJUb2FzdC5lcnJvcihtc2cudG9VcHBlckNhc2UoKSk7XG4gICAgICAgIH1cbiAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEVudmlhIHVtIGVtYWlsIGRlIHJlY3VwZXJhw6fDo28gZGUgc2VuaGEgY29tIG8gdG9rZW4gZG8gdXN1w6FyaW9cbiAgICAgKi9cbiAgICBmdW5jdGlvbiBzZW5kRW1haWxSZXNldFBhc3N3b3JkKCkge1xuXG4gICAgICBpZiAodm0ucmVzZXQuZW1haWwgPT09ICcnKSB7XG4gICAgICAgIFByVG9hc3QuZXJyb3IoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy52YWxpZGF0ZS5maWVsZFJlcXVpcmVkJywgeyBmaWVsZDogJ2VtYWlsJyB9KSk7XG4gICAgICAgIHJldHVybjtcbiAgICAgIH1cblxuICAgICAgQXV0aC5zZW5kRW1haWxSZXNldFBhc3N3b3JkKHZtLnJlc2V0KS50aGVuKGZ1bmN0aW9uIChkYXRhKSB7XG4gICAgICAgIFByVG9hc3Quc3VjY2VzcyhkYXRhLm1lc3NhZ2UpO1xuXG4gICAgICAgIHZtLmNsZWFuRm9ybSgpO1xuICAgICAgICB2bS5jbG9zZURpYWxvZygpO1xuICAgICAgfSwgZnVuY3Rpb24gKGVycm9yKSB7XG4gICAgICAgIGlmIChlcnJvci5kYXRhLmVtYWlsICYmIGVycm9yLmRhdGEuZW1haWwubGVuZ3RoID4gMCkge1xuICAgICAgICAgIHZhciBtc2cgPSAnJztcblxuICAgICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgZXJyb3IuZGF0YS5lbWFpbC5sZW5ndGg7IGkrKykge1xuICAgICAgICAgICAgbXNnICs9IGVycm9yLmRhdGEuZW1haWxbaV0gKyAnPGJyPic7XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgUHJUb2FzdC5lcnJvcihtc2cpO1xuICAgICAgICB9XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBjbG9zZURpYWxvZygpIHtcbiAgICAgIFByRGlhbG9nLmNsb3NlKCk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gY2xlYW5Gb3JtKCkge1xuICAgICAgdm0ucmVzZXQuZW1haWwgPSAnJztcbiAgICB9XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbi8qZXNsaW50IGFuZ3VsYXIvZmlsZS1uYW1lOiAwKi9cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmFjdG9yeSgnc2VydmljZUZhY3RvcnknLCBzZXJ2aWNlRmFjdG9yeSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvKipcbiAgICogTWFpcyBpbmZvcm1hw6fDtWVzOlxuICAgKiBodHRwczovL2dpdGh1Yi5jb20vc3dpbWxhbmUvYW5ndWxhci1tb2RlbC1mYWN0b3J5L3dpa2kvQVBJXG4gICAqL1xuICBmdW5jdGlvbiBzZXJ2aWNlRmFjdG9yeSgkbW9kZWxGYWN0b3J5KSB7XG4gICAgcmV0dXJuIGZ1bmN0aW9uICh1cmwsIG9wdGlvbnMpIHtcbiAgICAgIHZhciBtb2RlbDtcbiAgICAgIHZhciBkZWZhdWx0T3B0aW9ucyA9IHtcbiAgICAgICAgYWN0aW9uczoge1xuICAgICAgICAgIC8qKlxuICAgICAgICAgICAqIFNlcnZpw6dvIGNvbXVtIHBhcmEgcmVhbGl6YXIgYnVzY2EgY29tIHBhZ2luYcOnw6NvXG4gICAgICAgICAgICogTyBtZXNtbyBlc3BlcmEgcXVlIHNlamEgcmV0b3JuYWRvIHVtIG9iamV0byBjb20gaXRlbXMgZSB0b3RhbFxuICAgICAgICAgICAqL1xuICAgICAgICAgIHBhZ2luYXRlOiB7XG4gICAgICAgICAgICBtZXRob2Q6ICdHRVQnLFxuICAgICAgICAgICAgaXNBcnJheTogZmFsc2UsXG4gICAgICAgICAgICB3cmFwOiBmYWxzZSxcbiAgICAgICAgICAgIGFmdGVyUmVxdWVzdDogZnVuY3Rpb24gYWZ0ZXJSZXF1ZXN0KHJlc3BvbnNlKSB7XG4gICAgICAgICAgICAgIGlmIChyZXNwb25zZVsnaXRlbXMnXSkge1xuICAgICAgICAgICAgICAgIHJlc3BvbnNlWydpdGVtcyddID0gbW9kZWwuTGlzdChyZXNwb25zZVsnaXRlbXMnXSk7XG4gICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICByZXR1cm4gcmVzcG9uc2U7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICB9O1xuXG4gICAgICBtb2RlbCA9ICRtb2RlbEZhY3RvcnkodXJsLCBhbmd1bGFyLm1lcmdlKGRlZmF1bHRPcHRpb25zLCBvcHRpb25zKSk7XG5cbiAgICAgIHJldHVybiBtb2RlbDtcbiAgICB9O1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29udHJvbGxlcignQ1JVRENvbnRyb2xsZXInLCBDUlVEQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvKipcbiAgICogQ29udHJvbGFkb3IgQmFzZSBxdWUgaW1wbGVtZW50YSB0b2RhcyBhcyBmdW7Dp8O1ZXMgcGFkcsO1ZXMgZGUgdW0gQ1JVRFxuICAgKlxuICAgKiBBw6fDtWVzIGltcGxlbWVudGFkYXNcbiAgICogYWN0aXZhdGUoKVxuICAgKiBzZWFyY2gocGFnZSlcbiAgICogZWRpdChyZXNvdXJjZSlcbiAgICogc2F2ZSgpXG4gICAqIHJlbW92ZShyZXNvdXJjZSlcbiAgICogZ29Ubyh2aWV3TmFtZSlcbiAgICogY2xlYW5Gb3JtKClcbiAgICpcbiAgICogR2F0aWxob3NcbiAgICpcbiAgICogb25BY3RpdmF0ZSgpXG4gICAqIGFwcGx5RmlsdGVycyhkZWZhdWx0UXVlcnlGaWx0ZXJzKVxuICAgKiBiZWZvcmVTZWFyY2gocGFnZSkgLy9yZXRvcm5hbmRvIGZhbHNlIGNhbmNlbGEgbyBmbHV4b1xuICAgKiBhZnRlclNlYXJjaChyZXNwb25zZSlcbiAgICogYmVmb3JlQ2xlYW4gLy9yZXRvcm5hbmRvIGZhbHNlIGNhbmNlbGEgbyBmbHV4b1xuICAgKiBhZnRlckNsZWFuKClcbiAgICogYmVmb3JlU2F2ZSgpIC8vcmV0b3JuYW5kbyBmYWxzZSBjYW5jZWxhIG8gZmx1eG9cbiAgICogYWZ0ZXJTYXZlKHJlc291cmNlKVxuICAgKiBvblNhdmVFcnJvcihlcnJvcilcbiAgICogYmVmb3JlUmVtb3ZlKHJlc291cmNlKSAvL3JldG9ybmFuZG8gZmFsc2UgY2FuY2VsYSBvIGZsdXhvXG4gICAqIGFmdGVyUmVtb3ZlKHJlc291cmNlKVxuICAgKlxuICAgKiBAcGFyYW0ge2FueX0gdm0gaW5zdGFuY2lhIGRvIGNvbnRyb2xsZXIgZmlsaG9cbiAgICogQHBhcmFtIHthbnl9IG1vZGVsU2VydmljZSBzZXJ2acOnbyBkbyBtb2RlbCBxdWUgdmFpIHNlciB1dGlsaXphZG9cbiAgICogQHBhcmFtIHthbnl9IG9wdGlvbnMgb3DDp8O1ZXMgcGFyYSBzb2JyZWVzY3JldmVyIGNvbXBvcnRhbWVudG9zIHBhZHLDtWVzXG4gICAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBDUlVEQ29udHJvbGxlcih2bSwgbW9kZWxTZXJ2aWNlLCBvcHRpb25zLCBQclRvYXN0LCBQclBhZ2luYXRpb24sIC8vIE5PU09OQVJcbiAgUHJEaWFsb2csICR0cmFuc2xhdGUpIHtcblxuICAgIC8vRnVuY3Rpb25zIEJsb2NrXG4gICAgdm0uc2VhcmNoID0gc2VhcmNoO1xuICAgIHZtLnBhZ2luYXRlU2VhcmNoID0gcGFnaW5hdGVTZWFyY2g7XG4gICAgdm0ubm9ybWFsU2VhcmNoID0gbm9ybWFsU2VhcmNoO1xuICAgIHZtLmVkaXQgPSBlZGl0O1xuICAgIHZtLnNhdmUgPSBzYXZlO1xuICAgIHZtLnJlbW92ZSA9IHJlbW92ZTtcbiAgICB2bS5nb1RvID0gZ29UbztcbiAgICB2bS5jbGVhbkZvcm0gPSBjbGVhbkZvcm07XG5cbiAgICBhY3RpdmF0ZSgpO1xuXG4gICAgLyoqXG4gICAgICogUHJlcGFyYSBvIGNvbnRyb2xhZG9yXG4gICAgICogRmF6IG8gbWVyZ2UgZGFzIG9ww6fDtWVzXG4gICAgICogSW5pY2lhbGl6YSBvIHJlY3Vyc29cbiAgICAgKiBJbmljaWFsaXphIG8gb2JqZXRvIHBhZ2luYWRvciBlIHJlYWxpemEgYSBwZXNxdWlzYVxuICAgICAqL1xuICAgIGZ1bmN0aW9uIGFjdGl2YXRlKCkge1xuICAgICAgdm0uZGVmYXVsdE9wdGlvbnMgPSB7XG4gICAgICAgIHJlZGlyZWN0QWZ0ZXJTYXZlOiB0cnVlLFxuICAgICAgICBzZWFyY2hPbkluaXQ6IHRydWUsXG4gICAgICAgIHBlclBhZ2U6IDgsXG4gICAgICAgIHNraXBQYWdpbmF0aW9uOiBmYWxzZVxuICAgICAgfTtcblxuICAgICAgYW5ndWxhci5tZXJnZSh2bS5kZWZhdWx0T3B0aW9ucywgb3B0aW9ucyk7XG5cbiAgICAgIHZtLnZpZXdGb3JtID0gZmFsc2U7XG4gICAgICB2bS5yZXNvdXJjZSA9IG5ldyBtb2RlbFNlcnZpY2UoKTtcblxuICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5vbkFjdGl2YXRlKSkgdm0ub25BY3RpdmF0ZSgpO1xuXG4gICAgICB2bS5wYWdpbmF0b3IgPSBQclBhZ2luYXRpb24uZ2V0SW5zdGFuY2Uodm0uc2VhcmNoLCB2bS5kZWZhdWx0T3B0aW9ucy5wZXJQYWdlKTtcblxuICAgICAgaWYgKHZtLmRlZmF1bHRPcHRpb25zLnNlYXJjaE9uSW5pdCkgdm0uc2VhcmNoKCk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhbGl6YSBhIHBlc3F1aXNhXG4gICAgICogVmVyaWZpY2EgcXVhbCBkYXMgZnVuw6fDtWVzIGRlIHBlc3F1aXNhIGRldmUgc2VyIHJlYWxpemFkYS5cbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSBwYWdlIHDDoWdpbmEgcXVlIGRldmUgc2VyIGNhcnJlZ2FkYVxuICAgICAqL1xuICAgIGZ1bmN0aW9uIHNlYXJjaChwYWdlKSB7XG4gICAgICB2bS5kZWZhdWx0T3B0aW9ucy5za2lwUGFnaW5hdGlvbiA/IG5vcm1hbFNlYXJjaCgpIDogcGFnaW5hdGVTZWFyY2gocGFnZSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhbGl6YSBhIHBlc3F1aXNhIHBhZ2luYWRhIGNvbSBiYXNlIG5vcyBmaWx0cm9zIGRlZmluaWRvc1xuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IHBhZ2UgcMOhZ2luYSBxdWUgZGV2ZSBzZXIgY2FycmVnYWRhXG4gICAgICovXG4gICAgZnVuY3Rpb24gcGFnaW5hdGVTZWFyY2gocGFnZSkge1xuICAgICAgdm0ucGFnaW5hdG9yLmN1cnJlbnRQYWdlID0gYW5ndWxhci5pc0RlZmluZWQocGFnZSkgPyBwYWdlIDogMTtcbiAgICAgIHZtLmRlZmF1bHRRdWVyeUZpbHRlcnMgPSB7IHBhZ2U6IHZtLnBhZ2luYXRvci5jdXJyZW50UGFnZSwgcGVyUGFnZTogdm0ucGFnaW5hdG9yLnBlclBhZ2UgfTtcblxuICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5hcHBseUZpbHRlcnMpKSB2bS5kZWZhdWx0UXVlcnlGaWx0ZXJzID0gdm0uYXBwbHlGaWx0ZXJzKHZtLmRlZmF1bHRRdWVyeUZpbHRlcnMpO1xuICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5iZWZvcmVTZWFyY2gpICYmIHZtLmJlZm9yZVNlYXJjaChwYWdlKSA9PT0gZmFsc2UpIHJldHVybiBmYWxzZTtcblxuICAgICAgbW9kZWxTZXJ2aWNlLnBhZ2luYXRlKHZtLmRlZmF1bHRRdWVyeUZpbHRlcnMpLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgIHZtLnBhZ2luYXRvci5jYWxjTnVtYmVyT2ZQYWdlcyhyZXNwb25zZS50b3RhbCk7XG4gICAgICAgIHZtLnJlc291cmNlcyA9IHJlc3BvbnNlLml0ZW1zO1xuXG4gICAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYWZ0ZXJTZWFyY2gpKSB2bS5hZnRlclNlYXJjaChyZXNwb25zZSk7XG4gICAgICB9LCBmdW5jdGlvbiAocmVzcG9uc2VEYXRhKSB7XG4gICAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0ub25TZWFyY2hFcnJvcikpIHZtLm9uU2VhcmNoRXJyb3IocmVzcG9uc2VEYXRhKTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWxpemEgYSBwZXNxdWlzYSBjb20gYmFzZSBub3MgZmlsdHJvcyBkZWZpbmlkb3NcbiAgICAgKlxuICAgICAqL1xuICAgIGZ1bmN0aW9uIG5vcm1hbFNlYXJjaCgpIHtcbiAgICAgIHZtLmRlZmF1bHRRdWVyeUZpbHRlcnMgPSB7fTtcblxuICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5hcHBseUZpbHRlcnMpKSB2bS5kZWZhdWx0UXVlcnlGaWx0ZXJzID0gdm0uYXBwbHlGaWx0ZXJzKHZtLmRlZmF1bHRRdWVyeUZpbHRlcnMpO1xuICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5iZWZvcmVTZWFyY2gpICYmIHZtLmJlZm9yZVNlYXJjaCgpID09PSBmYWxzZSkgcmV0dXJuIGZhbHNlO1xuXG4gICAgICBtb2RlbFNlcnZpY2UucXVlcnkodm0uZGVmYXVsdFF1ZXJ5RmlsdGVycykudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgdm0ucmVzb3VyY2VzID0gcmVzcG9uc2U7XG5cbiAgICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5hZnRlclNlYXJjaCkpIHZtLmFmdGVyU2VhcmNoKHJlc3BvbnNlKTtcbiAgICAgIH0sIGZ1bmN0aW9uIChyZXNwb25zZURhdGEpIHtcbiAgICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5vblNlYXJjaEVycm9yKSkgdm0ub25TZWFyY2hFcnJvcihyZXNwb25zZURhdGEpO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogTGltcGEgbyBmb3JtdWzDoXJpb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGNsZWFuRm9ybShmb3JtKSB7XG4gICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmJlZm9yZUNsZWFuKSAmJiB2bS5iZWZvcmVDbGVhbigpID09PSBmYWxzZSkgcmV0dXJuIGZhbHNlO1xuXG4gICAgICB2bS5yZXNvdXJjZSA9IG5ldyBtb2RlbFNlcnZpY2UoKTtcblxuICAgICAgaWYgKGFuZ3VsYXIuaXNEZWZpbmVkKGZvcm0pKSB7XG4gICAgICAgIGZvcm0uJHNldFByaXN0aW5lKCk7XG4gICAgICAgIGZvcm0uJHNldFVudG91Y2hlZCgpO1xuICAgICAgfVxuXG4gICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmFmdGVyQ2xlYW4pKSB2bS5hZnRlckNsZWFuKCk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ2FycmVnYSBubyBmb3JtdWzDoXJpbyBvIHJlY3Vyc28gc2VsZWNpb25hZG8gcGFyYSBlZGnDp8Ojb1xuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IHJlc291cmNlIHJlY3Vyc28gc2VsZWNpb25hZG9cbiAgICAgKi9cbiAgICBmdW5jdGlvbiBlZGl0KHJlc291cmNlKSB7XG4gICAgICB2bS5nb1RvKCdmb3JtJyk7XG4gICAgICB2bS5yZXNvdXJjZSA9IG5ldyBhbmd1bGFyLmNvcHkocmVzb3VyY2UpO1xuXG4gICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmFmdGVyRWRpdCkpIHZtLmFmdGVyRWRpdCgpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFNhbHZhIG91IGF0dWFsaXphIG8gcmVjdXJzbyBjb3JyZW50ZSBubyBmb3JtdWzDoXJpb1xuICAgICAqIE5vIGNvbXBvcnRhbWVudG8gcGFkcsOjbyByZWRpcmVjaW9uYSBvIHVzdcOhcmlvIHBhcmEgdmlldyBkZSBsaXN0YWdlbVxuICAgICAqIGRlcG9pcyBkYSBleGVjdcOnw6NvXG4gICAgICpcbiAgICAgKiBAcmV0dXJuc1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIHNhdmUoZm9ybSkge1xuICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5iZWZvcmVTYXZlKSAmJiB2bS5iZWZvcmVTYXZlKCkgPT09IGZhbHNlKSByZXR1cm4gZmFsc2U7XG5cbiAgICAgIHZtLnJlc291cmNlLiRzYXZlKCkudGhlbihmdW5jdGlvbiAocmVzb3VyY2UpIHtcbiAgICAgICAgdm0ucmVzb3VyY2UgPSByZXNvdXJjZTtcblxuICAgICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmFmdGVyU2F2ZSkpIHZtLmFmdGVyU2F2ZShyZXNvdXJjZSk7XG5cbiAgICAgICAgaWYgKHZtLmRlZmF1bHRPcHRpb25zLnJlZGlyZWN0QWZ0ZXJTYXZlKSB7XG4gICAgICAgICAgdm0uY2xlYW5Gb3JtKGZvcm0pO1xuICAgICAgICAgIHZtLnNlYXJjaCh2bS5wYWdpbmF0b3IuY3VycmVudFBhZ2UpO1xuICAgICAgICAgIHZtLmdvVG8oJ2xpc3QnKTtcbiAgICAgICAgfVxuXG4gICAgICAgIFByVG9hc3Quc3VjY2VzcygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnNhdmVTdWNjZXNzJykpO1xuICAgICAgfSwgZnVuY3Rpb24gKHJlc3BvbnNlRGF0YSkge1xuICAgICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLm9uU2F2ZUVycm9yKSkgdm0ub25TYXZlRXJyb3IocmVzcG9uc2VEYXRhKTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlbW92ZSBvIHJlY3Vyc28gaW5mb3JtYWRvLlxuICAgICAqIEFudGVzIGV4aWJlIHVtIGRpYWxvZ28gZGUgY29uZmlybWHDp8Ojb1xuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IHJlc291cmNlIHJlY3Vyc28gZXNjb2xoaWRvXG4gICAgICovXG4gICAgZnVuY3Rpb24gcmVtb3ZlKHJlc291cmNlKSB7XG4gICAgICB2YXIgY29uZmlnID0ge1xuICAgICAgICB0aXRsZTogJHRyYW5zbGF0ZS5pbnN0YW50KCdkaWFsb2cuY29uZmlybVRpdGxlJyksXG4gICAgICAgIGRlc2NyaXB0aW9uOiAkdHJhbnNsYXRlLmluc3RhbnQoJ2RpYWxvZy5jb25maXJtRGVzY3JpcHRpb24nKVxuICAgICAgfTtcblxuICAgICAgUHJEaWFsb2cuY29uZmlybShjb25maWcpLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmJlZm9yZVJlbW92ZSkgJiYgdm0uYmVmb3JlUmVtb3ZlKHJlc291cmNlKSA9PT0gZmFsc2UpIHJldHVybiBmYWxzZTtcblxuICAgICAgICByZXNvdXJjZS4kZGVzdHJveSgpLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYWZ0ZXJSZW1vdmUpKSB2bS5hZnRlclJlbW92ZShyZXNvdXJjZSk7XG5cbiAgICAgICAgICB2bS5zZWFyY2goKTtcbiAgICAgICAgICBQclRvYXN0LmluZm8oJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5yZW1vdmVTdWNjZXNzJykpO1xuICAgICAgICB9KTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEFsdGVybmEgZW50cmUgYSB2aWV3IGRvIGZvcm11bMOhcmlvIGUgbGlzdGFnZW1cbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSB2aWV3TmFtZSBub21lIGRhIHZpZXdcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBnb1RvKHZpZXdOYW1lKSB7XG4gICAgICB2bS52aWV3Rm9ybSA9IGZhbHNlO1xuICAgICAgdm0ub25WaWV3ID0gZmFsc2U7XG4gICAgICBpZiAodmlld05hbWUgPT09ICdmb3JtJykge1xuICAgICAgICB2bS5jbGVhbkZvcm0oKTtcbiAgICAgICAgdm0udmlld0Zvcm0gPSB0cnVlO1xuICAgICAgfVxuICAgIH1cbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZpbHRlcignZWxhcHNlZCcsIGZ1bmN0aW9uICgpIHtcbiAgICByZXR1cm4gZnVuY3Rpb24gKGRhdGUpIHtcbiAgICAgIGlmICghZGF0ZSkgcmV0dXJuO1xuICAgICAgdmFyIHRpbWUgPSBEYXRlLnBhcnNlKGRhdGUpLFxuICAgICAgICAgIHRpbWVOb3cgPSBuZXcgRGF0ZSgpLmdldFRpbWUoKSxcbiAgICAgICAgICBkaWZmZXJlbmNlID0gdGltZU5vdyAtIHRpbWUsXG4gICAgICAgICAgc2Vjb25kcyA9IE1hdGguZmxvb3IoZGlmZmVyZW5jZSAvIDEwMDApLFxuICAgICAgICAgIG1pbnV0ZXMgPSBNYXRoLmZsb29yKHNlY29uZHMgLyA2MCksXG4gICAgICAgICAgaG91cnMgPSBNYXRoLmZsb29yKG1pbnV0ZXMgLyA2MCksXG4gICAgICAgICAgZGF5cyA9IE1hdGguZmxvb3IoaG91cnMgLyAyNCksXG4gICAgICAgICAgbW9udGhzID0gTWF0aC5mbG9vcihkYXlzIC8gMzApO1xuXG4gICAgICBpZiAobW9udGhzID4gMSkge1xuICAgICAgICByZXR1cm4gbW9udGhzICsgJyBtZXNlcyBhdHLDoXMnO1xuICAgICAgfSBlbHNlIGlmIChtb250aHMgPT09IDEpIHtcbiAgICAgICAgcmV0dXJuICcxIG3DqnMgYXRyw6FzJztcbiAgICAgIH0gZWxzZSBpZiAoZGF5cyA+IDEpIHtcbiAgICAgICAgcmV0dXJuIGRheXMgKyAnIGRpYXMgYXRyw6FzJztcbiAgICAgIH0gZWxzZSBpZiAoZGF5cyA9PT0gMSkge1xuICAgICAgICByZXR1cm4gJzEgZGlhIGF0csOhcyc7XG4gICAgICB9IGVsc2UgaWYgKGhvdXJzID4gMSkge1xuICAgICAgICByZXR1cm4gaG91cnMgKyAnIGhvcmFzIGF0csOhcyc7XG4gICAgICB9IGVsc2UgaWYgKGhvdXJzID09PSAxKSB7XG4gICAgICAgIHJldHVybiAndW1hIGhvcmEgYXRyw6FzJztcbiAgICAgIH0gZWxzZSBpZiAobWludXRlcyA+IDEpIHtcbiAgICAgICAgcmV0dXJuIG1pbnV0ZXMgKyAnIG1pbnV0b3MgYXRyw6FzJztcbiAgICAgIH0gZWxzZSBpZiAobWludXRlcyA9PT0gMSkge1xuICAgICAgICByZXR1cm4gJ3VtIG1pbnV0byBhdHLDoXMnO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgcmV0dXJuICdow6EgcG91Y29zIHNlZ3VuZG9zJztcbiAgICAgIH1cbiAgICB9O1xuICB9KS5jb250cm9sbGVyKCdEYXNoYm9hcmRDb250cm9sbGVyJywgRGFzaGJvYXJkQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBEYXNoYm9hcmRDb250cm9sbGVyKCRjb250cm9sbGVyLCAkc3RhdGUsICRtZERpYWxvZywgJHRyYW5zbGF0ZSwgRGFzaGJvYXJkc1NlcnZpY2UsIFByb2plY3RzU2VydmljZSwgbW9tZW50LCBQclRvYXN0LCBBdXRoLCBHbG9iYWwpIHtcbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgLy9BdHRyaWJ1dGVzIEJsb2NrXG5cbiAgICAvL0Z1bmN0aW9ucyBCbG9ja1xuICAgIHZtLm9uQWN0aXZhdGUgPSBvbkFjdGl2YXRlO1xuICAgIHZtLmFwcGx5RmlsdGVycyA9IGFwcGx5RmlsdGVycztcbiAgICB2bS5maXhEYXRlID0gZml4RGF0ZTtcblxuICAgIGZ1bmN0aW9uIG9uQWN0aXZhdGUoKSB7XG4gICAgICB2YXIgcHJvamVjdCA9IGxvY2FsU3RvcmFnZS5nZXRJdGVtKCdwcm9qZWN0Jyk7XG5cbiAgICAgIHZtLmltYWdlUGF0aCA9IEdsb2JhbC5pbWFnZVBhdGggKyAnL25vX2F2YXRhci5naWYnO1xuICAgICAgdm0uY3VycmVudFVzZXIgPSBBdXRoLmN1cnJlbnRVc2VyO1xuICAgICAgUHJvamVjdHNTZXJ2aWNlLnF1ZXJ5KHsgcHJvamVjdF9pZDogcHJvamVjdCB9KS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICB2bS5hY3R1YWxQcm9qZWN0ID0gcmVzcG9uc2VbMF07XG4gICAgICB9KTtcbiAgICAgIHZtLnF1ZXJ5RmlsdGVycyA9IHsgcHJvamVjdF9pZDogcHJvamVjdCB9O1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGFwcGx5RmlsdGVycyhkZWZhdWx0UXVlcnlGaWx0ZXJzKSB7XG4gICAgICByZXR1cm4gYW5ndWxhci5leHRlbmQoZGVmYXVsdFF1ZXJ5RmlsdGVycywgdm0ucXVlcnlGaWx0ZXJzKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBmaXhEYXRlKGRhdGVTdHJpbmcpIHtcbiAgICAgIHJldHVybiBtb21lbnQoZGF0ZVN0cmluZyk7XG4gICAgfVxuXG4gICAgdm0uZ29Ub1Byb2plY3QgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAkc3RhdGUuZ28oJ2FwcC5wcm9qZWN0cycsIHsgb2JqOiAnZWRpdCcsIHJlc291cmNlOiB2bS5hY3R1YWxQcm9qZWN0IH0pO1xuICAgIH07XG5cbiAgICB2bS50b3RhbENvc3QgPSBmdW5jdGlvbiAoKSB7XG4gICAgICB2YXIgZXN0aW1hdGVkX2Nvc3QgPSAwO1xuXG4gICAgICB2bS5hY3R1YWxQcm9qZWN0LnRhc2tzLmZvckVhY2goZnVuY3Rpb24gKHRhc2spIHtcbiAgICAgICAgZXN0aW1hdGVkX2Nvc3QgKz0gcGFyc2VGbG9hdCh2bS5hY3R1YWxQcm9qZWN0LmhvdXJfdmFsdWVfZmluYWwpICogdGFzay5lc3RpbWF0ZWRfdGltZTtcbiAgICAgIH0pO1xuICAgICAgcmV0dXJuIGVzdGltYXRlZF9jb3N0LnRvTG9jYWxlU3RyaW5nKCdQdC1icicsIHsgbWluaW11bUZyYWN0aW9uRGlnaXRzOiAyIH0pO1xuICAgIH07XG5cbiAgICB2bS5maW5hbGl6ZVByb2plY3QgPSBmdW5jdGlvbiAoKSB7XG4gICAgICB2YXIgY29uZmlybSA9ICRtZERpYWxvZy5jb25maXJtKCkudGl0bGUoJ0ZpbmFsaXphciBQcm9qZXRvJykudGV4dENvbnRlbnQoJ1RlbSBjZXJ0ZXphIHF1ZSBkZXNlamEgZmluYWxpemFyIG8gcHJvamV0byAnICsgdm0uYWN0dWFsUHJvamVjdC5uYW1lICsgJz8nKS5vaygnU2ltJykuY2FuY2VsKCdOw6NvJyk7XG5cbiAgICAgICRtZERpYWxvZy5zaG93KGNvbmZpcm0pLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICBQcm9qZWN0c1NlcnZpY2UuZmluYWxpemUoeyBwcm9qZWN0X2lkOiB2bS5hY3R1YWxQcm9qZWN0LmlkIH0pLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICAgIFByVG9hc3Quc3VjY2VzcygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnByb2plY3RFbmRlZFN1Y2Nlc3MnKSk7XG4gICAgICAgICAgb25BY3RpdmF0ZSgpO1xuICAgICAgICAgIHZtLnNlYXJjaCgpO1xuICAgICAgICB9LCBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgUHJUb2FzdC5FcnJvcigkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnByb2plY3RFbmRlZEVycm9yJykpO1xuICAgICAgICB9KTtcbiAgICAgIH0pO1xuICAgIH07XG5cbiAgICAvLyBpbnN0YW50aWF0ZSBiYXNlIGNvbnRyb2xsZXJcbiAgICAkY29udHJvbGxlcignQ1JVRENvbnRyb2xsZXInLCB7IHZtOiB2bSwgbW9kZWxTZXJ2aWNlOiBEYXNoYm9hcmRzU2VydmljZSwgb3B0aW9uczoge30gfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqXG4gICAqIEFycXVpdm8gZGUgY29uZmlndXJhw6fDo28gY29tIGFzIHJvdGFzIGVzcGVjw61maWNhcyBkbyByZWN1cnNvIHByb2plY3RcbiAgICpcbiAgICogQHBhcmFtIHthbnl9ICRzdGF0ZVByb3ZpZGVyXG4gICAqIEBwYXJhbSB7YW55fSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnYXBwLmRhc2hib2FyZCcsIHtcbiAgICAgIHVybDogJy9kYXNoYm9hcmRzJyxcbiAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvZGFzaGJvYXJkL2Rhc2hib2FyZC5odG1sJyxcbiAgICAgIGNvbnRyb2xsZXI6ICdEYXNoYm9hcmRDb250cm9sbGVyIGFzIGRhc2hib2FyZEN0cmwnLFxuICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IHRydWUgfSxcbiAgICAgIG9iajogeyByZXNvdXJjZTogbnVsbCB9XG4gICAgfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmFjdG9yeSgnRGFzaGJvYXJkc1NlcnZpY2UnLCBEYXNoYm9hcmRzU2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiBEYXNoYm9hcmRzU2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHJldHVybiBzZXJ2aWNlRmFjdG9yeSgnZGFzaGJvYXJkcycsIHtcbiAgICAgIGFjdGlvbnM6IHt9LFxuICAgICAgaW5zdGFuY2U6IHt9XG4gICAgfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqXG4gICAqIEFycXVpdm8gZGUgY29uZmlndXJhw6fDo28gY29tIGFzIHJvdGFzIGVzcGVjw61maWNhcyBkbyByZWN1cnNvIHVzZXJcbiAgICpcbiAgICogQHBhcmFtIHthbnl9ICRzdGF0ZVByb3ZpZGVyXG4gICAqIEBwYXJhbSB7YW55fSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnYXBwLmRpbmFtaWMtcXVlcnknLCB7XG4gICAgICB1cmw6ICcvY29uc3VsdGFzLWRpbmFtaWNhcycsXG4gICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL2RpbmFtaWMtcXVlcnlzL2RpbmFtaWMtcXVlcnlzLmh0bWwnLFxuICAgICAgY29udHJvbGxlcjogJ0RpbmFtaWNRdWVyeXNDb250cm9sbGVyIGFzIGRpbmFtaWNRdWVyeUN0cmwnLFxuICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IHRydWUsIG5lZWRQcm9maWxlOiBbJ2FkbWluJ10gfVxuICAgIH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZhY3RvcnkoJ0RpbmFtaWNRdWVyeVNlcnZpY2UnLCBEaW5hbWljUXVlcnlTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIERpbmFtaWNRdWVyeVNlcnZpY2Uoc2VydmljZUZhY3RvcnkpIHtcbiAgICByZXR1cm4gc2VydmljZUZhY3RvcnkoJ2RpbmFtaWNRdWVyeScsIHtcbiAgICAgIC8qKlxuICAgICAgICogYcOnw6NvIGFkaWNpb25hZGEgcGFyYSBwZWdhciB1bWEgbGlzdGEgZGUgbW9kZWxzIGV4aXN0ZW50ZXMgbm8gc2Vydmlkb3JcbiAgICAgICAqL1xuICAgICAgYWN0aW9uczoge1xuICAgICAgICBnZXRNb2RlbHM6IHtcbiAgICAgICAgICBtZXRob2Q6ICdHRVQnLFxuICAgICAgICAgIHVybDogJ21vZGVscydcbiAgICAgICAgfVxuICAgICAgfSxcbiAgICAgIGluc3RhbmNlOiB7fVxuICAgIH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29udHJvbGxlcignRGluYW1pY1F1ZXJ5c0NvbnRyb2xsZXInLCBEaW5hbWljUXVlcnlzQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBEaW5hbWljUXVlcnlzQ29udHJvbGxlcigkY29udHJvbGxlciwgRGluYW1pY1F1ZXJ5U2VydmljZSwgbG9kYXNoLCBQclRvYXN0LCAvLyBOT1NPTkFSXG4gICR0cmFuc2xhdGUpIHtcblxuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICAvL2FjdGlvbnNcbiAgICB2bS5vbkFjdGl2YXRlID0gb25BY3RpdmF0ZTtcbiAgICB2bS5hcHBseUZpbHRlcnMgPSBhcHBseUZpbHRlcnM7XG4gICAgdm0ubG9hZEF0dHJpYnV0ZXMgPSBsb2FkQXR0cmlidXRlcztcbiAgICB2bS5sb2FkT3BlcmF0b3JzID0gbG9hZE9wZXJhdG9ycztcbiAgICB2bS5hZGRGaWx0ZXIgPSBhZGRGaWx0ZXI7XG4gICAgdm0uYWZ0ZXJTZWFyY2ggPSBhZnRlclNlYXJjaDtcbiAgICB2bS5ydW5GaWx0ZXIgPSBydW5GaWx0ZXI7XG4gICAgdm0uZWRpdEZpbHRlciA9IGVkaXRGaWx0ZXI7XG4gICAgdm0ubG9hZE1vZGVscyA9IGxvYWRNb2RlbHM7XG4gICAgdm0ucmVtb3ZlRmlsdGVyID0gcmVtb3ZlRmlsdGVyO1xuICAgIHZtLmNsZWFyID0gY2xlYXI7XG4gICAgdm0ucmVzdGFydCA9IHJlc3RhcnQ7XG5cbiAgICAvL2hlcmRhIG8gY29tcG9ydGFtZW50byBiYXNlIGRvIENSVURcbiAgICAkY29udHJvbGxlcignQ1JVRENvbnRyb2xsZXInLCB7IHZtOiB2bSwgbW9kZWxTZXJ2aWNlOiBEaW5hbWljUXVlcnlTZXJ2aWNlLCBvcHRpb25zOiB7XG4gICAgICAgIHNlYXJjaE9uSW5pdDogZmFsc2VcbiAgICAgIH0gfSk7XG5cbiAgICBmdW5jdGlvbiBvbkFjdGl2YXRlKCkge1xuICAgICAgdm0ucmVzdGFydCgpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFByZXBhcmEgZSBhcGxpY2Egb3MgZmlsdHJvIHF1ZSB2w6NvIHNlciBlbnZpYWRvcyBwYXJhIG8gc2VydmnDp29cbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSBkZWZhdWx0UXVlcnlGaWx0ZXJzXG4gICAgICogQHJldHVybnNcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBhcHBseUZpbHRlcnMoZGVmYXVsdFF1ZXJ5RmlsdGVycykge1xuICAgICAgdmFyIHdoZXJlID0ge307XG5cbiAgICAgIC8qKlxuICAgICAgICogbyBzZXJ2acOnbyBlc3BlcmEgdW0gb2JqZXRvIGNvbTpcbiAgICAgICAqICBvIG5vbWUgZGUgdW0gbW9kZWxcbiAgICAgICAqICB1bWEgbGlzdGEgZGUgZmlsdHJvc1xuICAgICAgICovXG4gICAgICBpZiAodm0uYWRkZWRGaWx0ZXJzLmxlbmd0aCA+IDApIHtcbiAgICAgICAgdmFyIGFkZGVkRmlsdGVycyA9IGFuZ3VsYXIuY29weSh2bS5hZGRlZEZpbHRlcnMpO1xuXG4gICAgICAgIHdoZXJlLm1vZGVsID0gdm0uYWRkZWRGaWx0ZXJzWzBdLm1vZGVsLm5hbWU7XG5cbiAgICAgICAgZm9yICh2YXIgaW5kZXggPSAwOyBpbmRleCA8IGFkZGVkRmlsdGVycy5sZW5ndGg7IGluZGV4KyspIHtcbiAgICAgICAgICB2YXIgZmlsdGVyID0gYWRkZWRGaWx0ZXJzW2luZGV4XTtcblxuICAgICAgICAgIGZpbHRlci5tb2RlbCA9IG51bGw7XG4gICAgICAgICAgZmlsdGVyLmF0dHJpYnV0ZSA9IGZpbHRlci5hdHRyaWJ1dGUubmFtZTtcbiAgICAgICAgICBmaWx0ZXIub3BlcmF0b3IgPSBmaWx0ZXIub3BlcmF0b3IudmFsdWU7XG4gICAgICAgIH1cblxuICAgICAgICB3aGVyZS5maWx0ZXJzID0gYW5ndWxhci50b0pzb24oYWRkZWRGaWx0ZXJzKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHdoZXJlLm1vZGVsID0gdm0ucXVlcnlGaWx0ZXJzLm1vZGVsLm5hbWU7XG4gICAgICB9XG5cbiAgICAgIHJldHVybiBhbmd1bGFyLmV4dGVuZChkZWZhdWx0UXVlcnlGaWx0ZXJzLCB3aGVyZSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ2FycmVnYSB0b2RvcyBvcyBtb2RlbHMgY3JpYWRvcyBubyBzZXJ2aWRvciBjb20gc2V1cyBhdHJpYnV0b3NcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBsb2FkTW9kZWxzKCkge1xuICAgICAgLy9QZWdhIHRvZG9zIG9zIG1vZGVscyBkbyBzZXJ2ZXIgZSBtb250YSB1bWEgbGlzdGEgcHJvIENvbWJvQm94XG4gICAgICBEaW5hbWljUXVlcnlTZXJ2aWNlLmdldE1vZGVscygpLnRoZW4oZnVuY3Rpb24gKGRhdGEpIHtcbiAgICAgICAgdm0ubW9kZWxzID0gZGF0YTtcbiAgICAgICAgdm0ucXVlcnlGaWx0ZXJzLm1vZGVsID0gdm0ubW9kZWxzWzBdO1xuICAgICAgICB2bS5sb2FkQXR0cmlidXRlcygpO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ2FycmVnYSBvcyBhdHRyaWJ1dG9zIGRvIG1vZGVsIGVzY29saGlkb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGxvYWRBdHRyaWJ1dGVzKCkge1xuICAgICAgdm0uYXR0cmlidXRlcyA9IHZtLnF1ZXJ5RmlsdGVycy5tb2RlbC5hdHRyaWJ1dGVzO1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzLmF0dHJpYnV0ZSA9IHZtLmF0dHJpYnV0ZXNbMF07XG5cbiAgICAgIHZtLmxvYWRPcGVyYXRvcnMoKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDYXJyZWdhIG9zIG9wZXJhZG9yZXMgZXNwZWNpZmljb3MgcGFyYSBvIHRpcG8gZG8gYXRyaWJ1dG9cbiAgICAgKi9cbiAgICBmdW5jdGlvbiBsb2FkT3BlcmF0b3JzKCkge1xuICAgICAgdmFyIG9wZXJhdG9ycyA9IFt7IHZhbHVlOiAnPScsIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLmVxdWFscycpIH0sIHsgdmFsdWU6ICc8PicsIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLmRpZmVyZW50JykgfV07XG5cbiAgICAgIGlmICh2bS5xdWVyeUZpbHRlcnMuYXR0cmlidXRlLnR5cGUuaW5kZXhPZigndmFyeWluZycpICE9PSAtMSkge1xuICAgICAgICBvcGVyYXRvcnMucHVzaCh7IHZhbHVlOiAnaGFzJyxcbiAgICAgICAgICBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KCd2aWV3cy5maWVsZHMucXVlcnlEaW5hbWljLm9wZXJhdG9ycy5jb250ZWlucycpIH0pO1xuICAgICAgICBvcGVyYXRvcnMucHVzaCh7IHZhbHVlOiAnc3RhcnRXaXRoJyxcbiAgICAgICAgICBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KCd2aWV3cy5maWVsZHMucXVlcnlEaW5hbWljLm9wZXJhdG9ycy5zdGFydFdpdGgnKSB9KTtcbiAgICAgICAgb3BlcmF0b3JzLnB1c2goeyB2YWx1ZTogJ2VuZFdpdGgnLFxuICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLmZpbmlzaFdpdGgnKSB9KTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIG9wZXJhdG9ycy5wdXNoKHsgdmFsdWU6ICc+JyxcbiAgICAgICAgICBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KCd2aWV3cy5maWVsZHMucXVlcnlEaW5hbWljLm9wZXJhdG9ycy5iaWdnZXJUaGFuJykgfSk7XG4gICAgICAgIG9wZXJhdG9ycy5wdXNoKHsgdmFsdWU6ICc+PScsXG4gICAgICAgICAgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudCgndmlld3MuZmllbGRzLnF1ZXJ5RGluYW1pYy5vcGVyYXRvcnMuZXF1YWxzT3JCaWdnZXJUaGFuJykgfSk7XG4gICAgICAgIG9wZXJhdG9ycy5wdXNoKHsgdmFsdWU6ICc8JyxcbiAgICAgICAgICBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KCd2aWV3cy5maWVsZHMucXVlcnlEaW5hbWljLm9wZXJhdG9ycy5sZXNzVGhhbicpIH0pO1xuICAgICAgICBvcGVyYXRvcnMucHVzaCh7IHZhbHVlOiAnPD0nLFxuICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLmVxdWFsc09yTGVzc1RoYW4nKSB9KTtcbiAgICAgIH1cblxuICAgICAgdm0ub3BlcmF0b3JzID0gb3BlcmF0b3JzO1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzLm9wZXJhdG9yID0gdm0ub3BlcmF0b3JzWzBdO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEFkaWNpb25hL2VkaXRhIHVtIGZpbHRyb1xuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IGZvcm0gZWxlbWVudG8gaHRtbCBkbyBmb3JtdWzDoXJpbyBwYXJhIHZhbGlkYcOnw7Vlc1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGFkZEZpbHRlcihmb3JtKSB7XG4gICAgICBpZiAoYW5ndWxhci5pc1VuZGVmaW5lZCh2bS5xdWVyeUZpbHRlcnMudmFsdWUpIHx8IHZtLnF1ZXJ5RmlsdGVycy52YWx1ZSA9PT0gJycpIHtcbiAgICAgICAgUHJUb2FzdC5lcnJvcigkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnZhbGlkYXRlLmZpZWxkUmVxdWlyZWQnLCB7IGZpZWxkOiAndmFsb3InIH0pKTtcbiAgICAgICAgcmV0dXJuO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgaWYgKHZtLmluZGV4IDwgMCkge1xuICAgICAgICAgIHZtLmFkZGVkRmlsdGVycy5wdXNoKGFuZ3VsYXIuY29weSh2bS5xdWVyeUZpbHRlcnMpKTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICB2bS5hZGRlZEZpbHRlcnNbdm0uaW5kZXhdID0gYW5ndWxhci5jb3B5KHZtLnF1ZXJ5RmlsdGVycyk7XG4gICAgICAgICAgdm0uaW5kZXggPSAtMTtcbiAgICAgICAgfVxuXG4gICAgICAgIC8vcmVpbmljaWEgbyBmb3JtdWzDoXJpbyBlIGFzIHZhbGlkYcOnw7VlcyBleGlzdGVudGVzXG4gICAgICAgIHZtLnF1ZXJ5RmlsdGVycyA9IHt9O1xuICAgICAgICBmb3JtLiRzZXRQcmlzdGluZSgpO1xuICAgICAgICBmb3JtLiRzZXRVbnRvdWNoZWQoKTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFsaXphIGEgcGVzcXVpc2EgdGVuZG8gb3MgZmlsdHJvcyBjb21vIHBhcsOibWV0cm9zXG4gICAgICovXG4gICAgZnVuY3Rpb24gcnVuRmlsdGVyKCkge1xuICAgICAgdm0uc2VhcmNoKHZtLnBhZ2luYXRvci5jdXJyZW50UGFnZSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogR2F0aWxobyBhY2lvbmFkbyBkZXBvaXMgZGEgcGVzcXVpc2EgcmVzcG9uc8OhdmVsIHBvciBpZGVudGlmaWNhciBvcyBhdHJpYnV0b3NcbiAgICAgKiBjb250aWRvcyBub3MgZWxlbWVudG9zIHJlc3VsdGFudGVzIGRhIGJ1c2NhXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gZGF0YSBkYWRvcyByZWZlcmVudGUgYW8gcmV0b3JubyBkYSByZXF1aXNpw6fDo29cbiAgICAgKi9cbiAgICBmdW5jdGlvbiBhZnRlclNlYXJjaChkYXRhKSB7XG4gICAgICB2YXIga2V5cyA9IGRhdGEuaXRlbXMubGVuZ3RoID4gMCA/IE9iamVjdC5rZXlzKGRhdGEuaXRlbXNbMF0pIDogW107XG5cbiAgICAgIC8vcmV0aXJhIHRvZG9zIG9zIGF0cmlidXRvcyBxdWUgY29tZcOnYW0gY29tICQuXG4gICAgICAvL0Vzc2VzIGF0cmlidXRvcyBzw6NvIGFkaWNpb25hZG9zIHBlbG8gc2VydmnDp28gZSBuw6NvIGRldmUgYXBhcmVjZXIgbmEgbGlzdGFnZW1cbiAgICAgIHZtLmtleXMgPSBsb2Rhc2guZmlsdGVyKGtleXMsIGZ1bmN0aW9uIChrZXkpIHtcbiAgICAgICAgcmV0dXJuICFsb2Rhc2guc3RhcnRzV2l0aChrZXksICckJyk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDb2xvYWNhIG5vIGZvcm11bMOhcmlvIG8gZmlsdHJvIGVzY29saGlkbyBwYXJhIGVkacOnw6NvXG4gICAgICogQHBhcmFtIHthbnl9ICRpbmRleCBpbmRpY2Ugbm8gYXJyYXkgZG8gZmlsdHJvIGVzY29saGlkb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGVkaXRGaWx0ZXIoJGluZGV4KSB7XG4gICAgICB2bS5pbmRleCA9ICRpbmRleDtcbiAgICAgIHZtLnF1ZXJ5RmlsdGVycyA9IHZtLmFkZGVkRmlsdGVyc1skaW5kZXhdO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlbW92ZSBvIGZpbHRybyBlc2NvbGhpZG9cbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSAkaW5kZXggaW5kaWNlIG5vIGFycmF5IGRvIGZpbHRybyBlc2NvbGhpZG9cbiAgICAgKi9cbiAgICBmdW5jdGlvbiByZW1vdmVGaWx0ZXIoJGluZGV4KSB7XG4gICAgICB2bS5hZGRlZEZpbHRlcnMuc3BsaWNlKCRpbmRleCk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogTGltcGEgbyBmb3JtdWzDoXJpbyBjb3JyZW50ZVxuICAgICAqL1xuICAgIGZ1bmN0aW9uIGNsZWFyKCkge1xuICAgICAgLy9ndWFyZGEgbyBpbmRpY2UgZG8gcmVnaXN0cm8gcXVlIGVzdMOhIHNlbmRvIGVkaXRhZG9cbiAgICAgIHZtLmluZGV4ID0gLTE7XG4gICAgICAvL3ZpbmN1bGFkbyBhb3MgY2FtcG9zIGRvIGZvcm11bMOhcmlvXG4gICAgICB2bS5xdWVyeUZpbHRlcnMgPSB7fTtcblxuICAgICAgaWYgKHZtLm1vZGVscykgdm0ucXVlcnlGaWx0ZXJzLm1vZGVsID0gdm0ubW9kZWxzWzBdO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlaW5pY2lhIGEgY29uc3RydcOnw6NvIGRhIHF1ZXJ5IGxpbXBhbmRvIHR1ZG9cbiAgICAgKlxuICAgICAqL1xuICAgIGZ1bmN0aW9uIHJlc3RhcnQoKSB7XG4gICAgICAvL2d1YXJkYSBhdHJpYnV0b3MgZG8gcmVzdWx0YWRvIGRhIGJ1c2NhIGNvcnJlbnRlXG4gICAgICB2bS5rZXlzID0gW107XG5cbiAgICAgIC8vZ3VhcmRhIG9zIGZpbHRyb3MgYWRpY2lvbmFkb3NcbiAgICAgIHZtLmFkZGVkRmlsdGVycyA9IFtdO1xuICAgICAgdm0uY2xlYXIoKTtcbiAgICAgIHZtLmxvYWRNb2RlbHMoKTtcbiAgICB9XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5mYWN0b3J5KCdsYW5ndWFnZUxvYWRlcicsIExhbmd1YWdlTG9hZGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIExhbmd1YWdlTG9hZGVyKCRxLCBTdXBwb3J0U2VydmljZSwgJGxvZywgJGluamVjdG9yKSB7XG4gICAgdmFyIHNlcnZpY2UgPSB0aGlzO1xuXG4gICAgc2VydmljZS50cmFuc2xhdGUgPSBmdW5jdGlvbiAobG9jYWxlKSB7XG4gICAgICByZXR1cm4ge1xuICAgICAgICBnbG9iYWw6ICRpbmplY3Rvci5nZXQobG9jYWxlICsgJy5pMThuLmdsb2JhbCcpLFxuICAgICAgICB2aWV3czogJGluamVjdG9yLmdldChsb2NhbGUgKyAnLmkxOG4udmlld3MnKSxcbiAgICAgICAgYXR0cmlidXRlczogJGluamVjdG9yLmdldChsb2NhbGUgKyAnLmkxOG4uYXR0cmlidXRlcycpLFxuICAgICAgICBkaWFsb2c6ICRpbmplY3Rvci5nZXQobG9jYWxlICsgJy5pMThuLmRpYWxvZycpLFxuICAgICAgICBtZXNzYWdlczogJGluamVjdG9yLmdldChsb2NhbGUgKyAnLmkxOG4ubWVzc2FnZXMnKSxcbiAgICAgICAgbW9kZWxzOiAkaW5qZWN0b3IuZ2V0KGxvY2FsZSArICcuaTE4bi5tb2RlbHMnKVxuICAgICAgfTtcbiAgICB9O1xuXG4gICAgLy8gcmV0dXJuIGxvYWRlckZuXG4gICAgcmV0dXJuIGZ1bmN0aW9uIChvcHRpb25zKSB7XG4gICAgICAkbG9nLmluZm8oJ0NhcnJlZ2FuZG8gbyBjb250ZXVkbyBkYSBsaW5ndWFnZW0gJyArIG9wdGlvbnMua2V5KTtcblxuICAgICAgdmFyIGRlZmVycmVkID0gJHEuZGVmZXIoKTtcblxuICAgICAgLy9DYXJyZWdhIGFzIGxhbmdzIHF1ZSBwcmVjaXNhbSBlIGVzdMOjbyBubyBzZXJ2aWRvciBwYXJhIG7Do28gcHJlY2lzYXIgcmVwZXRpciBhcXVpXG4gICAgICBTdXBwb3J0U2VydmljZS5sYW5ncygpLnRoZW4oZnVuY3Rpb24gKGxhbmdzKSB7XG4gICAgICAgIC8vTWVyZ2UgY29tIG9zIGxhbmdzIGRlZmluaWRvcyBubyBzZXJ2aWRvclxuICAgICAgICB2YXIgZGF0YSA9IGFuZ3VsYXIubWVyZ2Uoc2VydmljZS50cmFuc2xhdGUob3B0aW9ucy5rZXkpLCBsYW5ncyk7XG5cbiAgICAgICAgcmV0dXJuIGRlZmVycmVkLnJlc29sdmUoZGF0YSk7XG4gICAgICB9LCBmdW5jdGlvbiAoKSB7XG4gICAgICAgIHJldHVybiBkZWZlcnJlZC5yZXNvbHZlKHNlcnZpY2UudHJhbnNsYXRlKG9wdGlvbnMua2V5KSk7XG4gICAgICB9KTtcblxuICAgICAgcmV0dXJuIGRlZmVycmVkLnByb21pc2U7XG4gICAgfTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZpbHRlcigndEF0dHInLCB0QXR0cik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiB0QXR0cigkZmlsdGVyKSB7XG4gICAgLyoqXG4gICAgICogRmlsdHJvIHBhcmEgdHJhZHXDp8OjbyBkZSB1bSBhdHJpYnV0byBkZSB1bSBtb2RlbFxuICAgICAqIFxuICAgICAqIEBwYXJhbSB7YW55fSBuYW1lIG5vbWUgZG8gYXRyaWJ1dG9cbiAgICAgKiBAcmV0dXJucyBvIG5vbWUgZG8gYXRyaWJ1dG8gdHJhZHV6aWRvIGNhc28gZW5jb250cmUgc2UgbsOjbyBvIG5vbWUgcGFzc2FkbyBwb3IgcGFyYW1ldHJvXG4gICAgICovXG4gICAgcmV0dXJuIGZ1bmN0aW9uIChuYW1lKSB7XG4gICAgICB2YXIga2V5ID0gJ2F0dHJpYnV0ZXMuJyArIG5hbWU7XG4gICAgICB2YXIgdHJhbnNsYXRlID0gJGZpbHRlcigndHJhbnNsYXRlJykoa2V5KTtcblxuICAgICAgcmV0dXJuIHRyYW5zbGF0ZSA9PT0ga2V5ID8gbmFtZSA6IHRyYW5zbGF0ZTtcbiAgICB9O1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmlsdGVyKCd0QnJlYWRjcnVtYicsIHRCcmVhZGNydW1iKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIHRCcmVhZGNydW1iKCRmaWx0ZXIpIHtcbiAgICAvKipcbiAgICAgKiBGaWx0cm8gcGFyYSB0cmFkdcOnw6NvIGRvIGJyZWFkY3J1bWIgKHRpdHVsbyBkYSB0ZWxhIGNvbSByYXN0cmVpbylcbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSBpZCBjaGF2ZSBjb20gbyBub21lIGRvIHN0YXRlIHJlZmVyZW50ZSB0ZWxhXG4gICAgICogQHJldHVybnMgYSB0cmFkdcOnw6NvIGNhc28gZW5jb250cmUgc2UgbsOjbyBvIGlkIHBhc3NhZG8gcG9yIHBhcmFtZXRyb1xuICAgICAqL1xuICAgIHJldHVybiBmdW5jdGlvbiAoaWQpIHtcbiAgICAgIC8vcGVnYSBhIHNlZ3VuZGEgcGFydGUgZG8gbm9tZSBkbyBzdGF0ZSwgcmV0aXJhbmRvIGEgcGFydGUgYWJzdHJhdGEgKGFwcC4pXG4gICAgICB2YXIga2V5ID0gJ3ZpZXdzLmJyZWFkY3J1bWJzLicgKyBpZC5zcGxpdCgnLicpWzFdO1xuICAgICAgdmFyIHRyYW5zbGF0ZSA9ICRmaWx0ZXIoJ3RyYW5zbGF0ZScpKGtleSk7XG5cbiAgICAgIHJldHVybiB0cmFuc2xhdGUgPT09IGtleSA/IGlkIDogdHJhbnNsYXRlO1xuICAgIH07XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5maWx0ZXIoJ3RNb2RlbCcsIHRNb2RlbCk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiB0TW9kZWwoJGZpbHRlcikge1xuICAgIC8qKlxuICAgICAqIEZpbHRybyBwYXJhIHRyYWR1w6fDo28gZGUgdW0gYXRyaWJ1dG8gZGUgdW0gbW9kZWxcbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSBuYW1lIG5vbWUgZG8gYXRyaWJ1dG9cbiAgICAgKiBAcmV0dXJucyBvIG5vbWUgZG8gYXRyaWJ1dG8gdHJhZHV6aWRvIGNhc28gZW5jb250cmUgc2UgbsOjbyBvIG5vbWUgcGFzc2FkbyBwb3IgcGFyYW1ldHJvXG4gICAgICovXG4gICAgcmV0dXJuIGZ1bmN0aW9uIChuYW1lKSB7XG4gICAgICB2YXIga2V5ID0gJ21vZGVscy4nICsgbmFtZS50b0xvd2VyQ2FzZSgpO1xuICAgICAgdmFyIHRyYW5zbGF0ZSA9ICRmaWx0ZXIoJ3RyYW5zbGF0ZScpKGtleSk7XG5cbiAgICAgIHJldHVybiB0cmFuc2xhdGUgPT09IGtleSA/IG5hbWUgOiB0cmFuc2xhdGU7XG4gICAgfTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5ydW4oYXV0aGVudGljYXRpb25MaXN0ZW5lcik7XG5cbiAgLyoqXG4gICAqIExpc3RlbiBhbGwgc3RhdGUgKHBhZ2UpIGNoYW5nZXMuIEV2ZXJ5IHRpbWUgYSBzdGF0ZSBjaGFuZ2UgbmVlZCB0byB2ZXJpZnkgdGhlIHVzZXIgaXMgYXV0aGVudGljYXRlZCBvciBub3QgdG9cbiAgICogcmVkaXJlY3QgdG8gY29ycmVjdCBwYWdlLiBXaGVuIGEgdXNlciBjbG9zZSB0aGUgYnJvd3NlciB3aXRob3V0IGxvZ291dCwgd2hlbiBoaW0gcmVvcGVuIHRoZSBicm93c2VyIHRoaXMgZXZlbnRcbiAgICogcmVhdXRoZW50aWNhdGUgdGhlIHVzZXIgd2l0aCB0aGUgcGVyc2lzdGVudCB0b2tlbiBvZiB0aGUgbG9jYWwgc3RvcmFnZS5cbiAgICpcbiAgICogV2UgZG9uJ3QgY2hlY2sgaWYgdGhlIHRva2VuIGlzIGV4cGlyZWQgb3Igbm90IGluIHRoZSBwYWdlIGNoYW5nZSwgYmVjYXVzZSBpcyBnZW5lcmF0ZSBhbiB1bmVjZXNzYXJ5IG92ZXJoZWFkLlxuICAgKiBJZiB0aGUgdG9rZW4gaXMgZXhwaXJlZCB3aGVuIHRoZSB1c2VyIHRyeSB0byBjYWxsIHRoZSBmaXJzdCBhcGkgdG8gZ2V0IGRhdGEsIGhpbSB3aWxsIGJlIGxvZ29mZiBhbmQgcmVkaXJlY3RcbiAgICogdG8gbG9naW4gcGFnZS5cbiAgICpcbiAgICogQHBhcmFtICRyb290U2NvcGVcbiAgICogQHBhcmFtICRzdGF0ZVxuICAgKiBAcGFyYW0gJHN0YXRlUGFyYW1zXG4gICAqIEBwYXJhbSBBdXRoXG4gICAqL1xuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIGF1dGhlbnRpY2F0aW9uTGlzdGVuZXIoJHJvb3RTY29wZSwgJHN0YXRlLCBHbG9iYWwsIEF1dGgsIFByVG9hc3QsIC8vIE5PU09OQVJcbiAgJHRyYW5zbGF0ZSkge1xuXG4gICAgLy9vbmx5IHdoZW4gYXBwbGljYXRpb24gc3RhcnQgY2hlY2sgaWYgdGhlIGV4aXN0ZW50IHRva2VuIHN0aWxsIHZhbGlkXG4gICAgQXV0aC5yZW1vdGVWYWxpZGF0ZVRva2VuKCkudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAvL2lmIHRoZSB0b2tlbiBpcyB2YWxpZCBjaGVjayBpZiBleGlzdHMgdGhlIHVzZXIgYmVjYXVzZSB0aGUgYnJvd3NlciBjb3VsZCBiZSBjbG9zZWRcbiAgICAgIC8vYW5kIHRoZSB1c2VyIGRhdGEgaXNuJ3QgaW4gbWVtb3J5XG4gICAgICBpZiAoQXV0aC5jdXJyZW50VXNlciA9PT0gbnVsbCkge1xuICAgICAgICBBdXRoLnVwZGF0ZUN1cnJlbnRVc2VyKGFuZ3VsYXIuZnJvbUpzb24obG9jYWxTdG9yYWdlLmdldEl0ZW0oJ3VzZXInKSkpO1xuICAgICAgfVxuICAgIH0pO1xuXG4gICAgLy9DaGVjayBpZiB0aGUgdG9rZW4gc3RpbGwgdmFsaWQuXG4gICAgJHJvb3RTY29wZS4kb24oJyRzdGF0ZUNoYW5nZVN0YXJ0JywgZnVuY3Rpb24gKGV2ZW50LCB0b1N0YXRlKSB7XG4gICAgICBpZiAodG9TdGF0ZS5kYXRhLm5lZWRBdXRoZW50aWNhdGlvbiB8fCB0b1N0YXRlLmRhdGEubmVlZFByb2ZpbGUpIHtcbiAgICAgICAgLy9kb250IHRyYWl0IHRoZSBzdWNjZXNzIGJsb2NrIGJlY2F1c2UgYWxyZWFkeSBkaWQgYnkgdG9rZW4gaW50ZXJjZXB0b3JcbiAgICAgICAgQXV0aC5yZW1vdGVWYWxpZGF0ZVRva2VuKCkuY2F0Y2goZnVuY3Rpb24gKCkge1xuICAgICAgICAgIFByVG9hc3Qud2FybigkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLmxvZ2luLmxvZ291dEluYWN0aXZlJykpO1xuXG4gICAgICAgICAgaWYgKHRvU3RhdGUubmFtZSAhPT0gR2xvYmFsLmxvZ2luU3RhdGUpIHtcbiAgICAgICAgICAgICRzdGF0ZS5nbyhHbG9iYWwubG9naW5TdGF0ZSk7XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgZXZlbnQucHJldmVudERlZmF1bHQoKTtcbiAgICAgICAgfSk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICAvL2lmIHRoZSB1c2UgaXMgYXV0aGVudGljYXRlZCBhbmQgbmVlZCB0byBlbnRlciBpbiBsb2dpbiBwYWdlXG4gICAgICAgIC8vaGltIHdpbGwgYmUgcmVkaXJlY3RlZCB0byBob21lIHBhZ2VcbiAgICAgICAgaWYgKHRvU3RhdGUubmFtZSA9PT0gR2xvYmFsLmxvZ2luU3RhdGUgJiYgQXV0aC5hdXRoZW50aWNhdGVkKCkpIHtcbiAgICAgICAgICAkc3RhdGUuZ28oR2xvYmFsLmhvbWVTdGF0ZSk7XG4gICAgICAgICAgZXZlbnQucHJldmVudERlZmF1bHQoKTtcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLnJ1bihhdXRob3JpemF0aW9uTGlzdGVuZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gYXV0aG9yaXphdGlvbkxpc3RlbmVyKCRyb290U2NvcGUsICRzdGF0ZSwgR2xvYmFsLCBBdXRoKSB7XG4gICAgLyoqXG4gICAgICogQSBjYWRhIG11ZGFuw6dhIGRlIGVzdGFkbyAoXCJww6FnaW5hXCIpIHZlcmlmaWNhIHNlIG8gdXN1w6FyaW8gdGVtIG8gcGVyZmlsXG4gICAgICogbmVjZXNzw6FyaW8gcGFyYSBvIGFjZXNzbyBhIG1lc21hXG4gICAgICovXG4gICAgJHJvb3RTY29wZS4kb24oJyRzdGF0ZUNoYW5nZVN0YXJ0JywgZnVuY3Rpb24gKGV2ZW50LCB0b1N0YXRlKSB7XG4gICAgICBpZiAodG9TdGF0ZS5kYXRhICYmIHRvU3RhdGUuZGF0YS5uZWVkQXV0aGVudGljYXRpb24gJiYgdG9TdGF0ZS5kYXRhLm5lZWRQcm9maWxlICYmIEF1dGguYXV0aGVudGljYXRlZCgpICYmICFBdXRoLmN1cnJlbnRVc2VyLmhhc1Byb2ZpbGUodG9TdGF0ZS5kYXRhLm5lZWRQcm9maWxlLCB0b1N0YXRlLmRhdGEuYWxsUHJvZmlsZXMpKSB7XG5cbiAgICAgICAgJHN0YXRlLmdvKEdsb2JhbC5ub3RBdXRob3JpemVkU3RhdGUpO1xuICAgICAgICBldmVudC5wcmV2ZW50RGVmYXVsdCgpO1xuICAgICAgfVxuICAgIH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbmZpZyhzcGlubmVySW50ZXJjZXB0b3IpO1xuXG4gIGZ1bmN0aW9uIHNwaW5uZXJJbnRlcmNlcHRvcigkaHR0cFByb3ZpZGVyLCAkcHJvdmlkZSkge1xuICAgIC8qKlxuICAgICAqIEVzdGUgaW50ZXJjZXB0b3Igw6kgcmVzcG9uc8OhdmVsIHBvciBtb3N0cmFyIGUgZXNjb25kZXIgb1xuICAgICAqIGNvbXBvbmVudGUgUHJTcGlubmVyIHNlbXByZSBxdWUgdW1hIHJlcXVpc2nDp8OjbyBhamF4XG4gICAgICogaW5pY2lhciBlIGZpbmFsaXphci5cbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSAkcVxuICAgICAqIEBwYXJhbSB7YW55fSAkaW5qZWN0b3JcbiAgICAgKiBAcmV0dXJuc1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIHNob3dIaWRlU3Bpbm5lcigkcSwgJGluamVjdG9yKSB7XG4gICAgICByZXR1cm4ge1xuICAgICAgICByZXF1ZXN0OiBmdW5jdGlvbiByZXF1ZXN0KGNvbmZpZykge1xuICAgICAgICAgICRpbmplY3Rvci5nZXQoJ1ByU3Bpbm5lcicpLnNob3coKTtcblxuICAgICAgICAgIHJldHVybiBjb25maWc7XG4gICAgICAgIH0sXG5cbiAgICAgICAgcmVzcG9uc2U6IGZ1bmN0aW9uIHJlc3BvbnNlKF9yZXNwb25zZSkge1xuICAgICAgICAgICRpbmplY3Rvci5nZXQoJ1ByU3Bpbm5lcicpLmhpZGUoKTtcblxuICAgICAgICAgIHJldHVybiBfcmVzcG9uc2U7XG4gICAgICAgIH0sXG5cbiAgICAgICAgcmVzcG9uc2VFcnJvcjogZnVuY3Rpb24gcmVzcG9uc2VFcnJvcihyZWplY3Rpb24pIHtcbiAgICAgICAgICAkaW5qZWN0b3IuZ2V0KCdQclNwaW5uZXInKS5oaWRlKCk7XG5cbiAgICAgICAgICByZXR1cm4gJHEucmVqZWN0KHJlamVjdGlvbik7XG4gICAgICAgIH1cbiAgICAgIH07XG4gICAgfVxuXG4gICAgLy8gRGVmaW5lIHVtYSBmYWN0b3J5IHBhcmEgbyAkaHR0cEludGVyY2VwdG9yXG4gICAgJHByb3ZpZGUuZmFjdG9yeSgnc2hvd0hpZGVTcGlubmVyJywgc2hvd0hpZGVTcGlubmVyKTtcblxuICAgIC8vIEFkaWNpb25hIGEgZmFjdG9yeSBubyBhcnJheSBkZSBpbnRlcmNlcHRvcnMgZG8gJGh0dHBcbiAgICAkaHR0cFByb3ZpZGVyLmludGVyY2VwdG9ycy5wdXNoKCdzaG93SGlkZVNwaW5uZXInKTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuLyplc2xpbnQgYW5ndWxhci9tb2R1bGUtZ2V0dGVyOiAwKi9cblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25maWcodG9rZW5JbnRlcmNlcHRvcik7XG5cbiAgLyoqXG4gICAqIEludGVyY2VwdCBhbGwgcmVzcG9uc2UgKHN1Y2Nlc3Mgb3IgZXJyb3IpIHRvIHZlcmlmeSB0aGUgcmV0dXJuZWQgdG9rZW5cbiAgICpcbiAgICogQHBhcmFtICRodHRwUHJvdmlkZXJcbiAgICogQHBhcmFtICRwcm92aWRlXG4gICAqIEBwYXJhbSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gdG9rZW5JbnRlcmNlcHRvcigkaHR0cFByb3ZpZGVyLCAkcHJvdmlkZSwgR2xvYmFsKSB7XG5cbiAgICBmdW5jdGlvbiByZWRpcmVjdFdoZW5TZXJ2ZXJMb2dnZWRPdXQoJHEsICRpbmplY3Rvcikge1xuICAgICAgcmV0dXJuIHtcbiAgICAgICAgcmVxdWVzdDogZnVuY3Rpb24gcmVxdWVzdChjb25maWcpIHtcbiAgICAgICAgICB2YXIgdG9rZW4gPSAkaW5qZWN0b3IuZ2V0KCdBdXRoJykuZ2V0VG9rZW4oKTtcblxuICAgICAgICAgIGlmICh0b2tlbikge1xuICAgICAgICAgICAgY29uZmlnLmhlYWRlcnNbJ0F1dGhvcml6YXRpb24nXSA9ICdCZWFyZXIgJyArIHRva2VuO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIHJldHVybiBjb25maWc7XG4gICAgICAgIH0sXG4gICAgICAgIHJlc3BvbnNlOiBmdW5jdGlvbiByZXNwb25zZShfcmVzcG9uc2UpIHtcbiAgICAgICAgICAvLyBnZXQgYSBuZXcgcmVmcmVzaCB0b2tlbiB0byB1c2UgaW4gdGhlIG5leHQgcmVxdWVzdFxuICAgICAgICAgIHZhciB0b2tlbiA9IF9yZXNwb25zZS5oZWFkZXJzKCdBdXRob3JpemF0aW9uJyk7XG5cbiAgICAgICAgICBpZiAodG9rZW4pIHtcbiAgICAgICAgICAgICRpbmplY3Rvci5nZXQoJ0F1dGgnKS5zZXRUb2tlbih0b2tlbi5zcGxpdCgnICcpWzFdKTtcbiAgICAgICAgICB9XG4gICAgICAgICAgcmV0dXJuIF9yZXNwb25zZTtcbiAgICAgICAgfSxcbiAgICAgICAgcmVzcG9uc2VFcnJvcjogZnVuY3Rpb24gcmVzcG9uc2VFcnJvcihyZWplY3Rpb24pIHtcbiAgICAgICAgICAvLyBJbnN0ZWFkIG9mIGNoZWNraW5nIGZvciBhIHN0YXR1cyBjb2RlIG9mIDQwMCB3aGljaCBtaWdodCBiZSB1c2VkXG4gICAgICAgICAgLy8gZm9yIG90aGVyIHJlYXNvbnMgaW4gTGFyYXZlbCwgd2UgY2hlY2sgZm9yIHRoZSBzcGVjaWZpYyByZWplY3Rpb25cbiAgICAgICAgICAvLyByZWFzb25zIHRvIHRlbGwgdXMgaWYgd2UgbmVlZCB0byByZWRpcmVjdCB0byB0aGUgbG9naW4gc3RhdGVcbiAgICAgICAgICB2YXIgcmVqZWN0aW9uUmVhc29ucyA9IFsndG9rZW5fbm90X3Byb3ZpZGVkJywgJ3Rva2VuX2V4cGlyZWQnLCAndG9rZW5fYWJzZW50JywgJ3Rva2VuX2ludmFsaWQnXTtcblxuICAgICAgICAgIHZhciB0b2tlbkVycm9yID0gZmFsc2U7XG5cbiAgICAgICAgICBhbmd1bGFyLmZvckVhY2gocmVqZWN0aW9uUmVhc29ucywgZnVuY3Rpb24gKHZhbHVlKSB7XG4gICAgICAgICAgICBpZiAocmVqZWN0aW9uLmRhdGEgJiYgcmVqZWN0aW9uLmRhdGEuZXJyb3IgPT09IHZhbHVlKSB7XG4gICAgICAgICAgICAgIHRva2VuRXJyb3IgPSB0cnVlO1xuXG4gICAgICAgICAgICAgICRpbmplY3Rvci5nZXQoJ0F1dGgnKS5sb2dvdXQoKS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICB2YXIgJHN0YXRlID0gJGluamVjdG9yLmdldCgnJHN0YXRlJyk7XG5cbiAgICAgICAgICAgICAgICAvLyBpbiBjYXNlIG11bHRpcGxlIGFqYXggcmVxdWVzdCBmYWlsIGF0IHNhbWUgdGltZSBiZWNhdXNlIHRva2VuIHByb2JsZW1zLFxuICAgICAgICAgICAgICAgIC8vIG9ubHkgdGhlIGZpcnN0IHdpbGwgcmVkaXJlY3RcbiAgICAgICAgICAgICAgICBpZiAoISRzdGF0ZS5pcyhHbG9iYWwubG9naW5TdGF0ZSkpIHtcbiAgICAgICAgICAgICAgICAgICRzdGF0ZS5nbyhHbG9iYWwubG9naW5TdGF0ZSk7XG5cbiAgICAgICAgICAgICAgICAgIC8vY2xvc2UgYW55IGRpYWxvZyB0aGF0IGlzIG9wZW5lZFxuICAgICAgICAgICAgICAgICAgJGluamVjdG9yLmdldCgnUHJEaWFsb2cnKS5jbG9zZSgpO1xuXG4gICAgICAgICAgICAgICAgICBldmVudC5wcmV2ZW50RGVmYXVsdCgpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfSk7XG5cbiAgICAgICAgICAvL2RlZmluZSBkYXRhIHRvIGVtcHR5IGJlY2F1c2UgYWxyZWFkeSBzaG93IFByVG9hc3QgdG9rZW4gbWVzc2FnZVxuICAgICAgICAgIGlmICh0b2tlbkVycm9yKSB7XG4gICAgICAgICAgICByZWplY3Rpb24uZGF0YSA9IHt9O1xuICAgICAgICAgIH1cblxuICAgICAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24ocmVqZWN0aW9uLmhlYWRlcnMpKSB7XG4gICAgICAgICAgICAvLyBtYW55IHNlcnZlcnMgZXJyb3JzIChidXNpbmVzcykgYXJlIGludGVyY2VwdCBoZXJlIGJ1dCBnZW5lcmF0ZWQgYSBuZXcgcmVmcmVzaCB0b2tlblxuICAgICAgICAgICAgLy8gYW5kIG5lZWQgdXBkYXRlIGN1cnJlbnQgdG9rZW5cbiAgICAgICAgICAgIHZhciB0b2tlbiA9IHJlamVjdGlvbi5oZWFkZXJzKCdBdXRob3JpemF0aW9uJyk7XG5cbiAgICAgICAgICAgIGlmICh0b2tlbikge1xuICAgICAgICAgICAgICAkaW5qZWN0b3IuZ2V0KCdBdXRoJykuc2V0VG9rZW4odG9rZW4uc3BsaXQoJyAnKVsxXSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgcmV0dXJuICRxLnJlamVjdChyZWplY3Rpb24pO1xuICAgICAgICB9XG4gICAgICB9O1xuICAgIH1cblxuICAgIC8vIFNldHVwIGZvciB0aGUgJGh0dHBJbnRlcmNlcHRvclxuICAgICRwcm92aWRlLmZhY3RvcnkoJ3JlZGlyZWN0V2hlblNlcnZlckxvZ2dlZE91dCcsIHJlZGlyZWN0V2hlblNlcnZlckxvZ2dlZE91dCk7XG5cbiAgICAvLyBQdXNoIHRoZSBuZXcgZmFjdG9yeSBvbnRvIHRoZSAkaHR0cCBpbnRlcmNlcHRvciBhcnJheVxuICAgICRodHRwUHJvdmlkZXIuaW50ZXJjZXB0b3JzLnB1c2goJ3JlZGlyZWN0V2hlblNlcnZlckxvZ2dlZE91dCcpO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbmZpZyh2YWxpZGF0aW9uSW50ZXJjZXB0b3IpO1xuXG4gIGZ1bmN0aW9uIHZhbGlkYXRpb25JbnRlcmNlcHRvcigkaHR0cFByb3ZpZGVyLCAkcHJvdmlkZSkge1xuICAgIC8qKlxuICAgICAqIEVzdGUgaW50ZXJjZXB0b3Igw6kgcmVzcG9uc8OhdmVsIHBvciBtb3N0cmFyIGFzXG4gICAgICogbWVuc2FnZW5zIGRlIGVycm8gcmVmZXJlbnRlIGFzIHZhbGlkYcOnw7VlcyBkbyBiYWNrLWVuZFxuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9ICRxXG4gICAgICogQHBhcmFtIHthbnl9ICRpbmplY3RvclxuICAgICAqIEByZXR1cm5zXG4gICAgICovXG4gICAgZnVuY3Rpb24gc2hvd0Vycm9yVmFsaWRhdGlvbigkcSwgJGluamVjdG9yKSB7XG4gICAgICByZXR1cm4ge1xuICAgICAgICByZXNwb25zZUVycm9yOiBmdW5jdGlvbiByZXNwb25zZUVycm9yKHJlamVjdGlvbikge1xuICAgICAgICAgIHZhciBQclRvYXN0ID0gJGluamVjdG9yLmdldCgnUHJUb2FzdCcpO1xuICAgICAgICAgIHZhciAkdHJhbnNsYXRlID0gJGluamVjdG9yLmdldCgnJHRyYW5zbGF0ZScpO1xuXG4gICAgICAgICAgaWYgKHJlamVjdGlvbi5jb25maWcuZGF0YSAmJiAhcmVqZWN0aW9uLmNvbmZpZy5kYXRhLnNraXBWYWxpZGF0aW9uKSB7XG4gICAgICAgICAgICBpZiAocmVqZWN0aW9uLmRhdGEgJiYgcmVqZWN0aW9uLmRhdGEuZXJyb3IpIHtcblxuICAgICAgICAgICAgICAvL3ZlcmlmaWNhIHNlIG9jb3JyZXUgYWxndW0gZXJybyByZWZlcmVudGUgYW8gdG9rZW5cbiAgICAgICAgICAgICAgaWYgKHJlamVjdGlvbi5kYXRhLmVycm9yLnN0YXJ0c1dpdGgoJ3Rva2VuXycpKSB7XG4gICAgICAgICAgICAgICAgUHJUb2FzdC53YXJuKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMubG9naW4ubG9nb3V0SW5hY3RpdmUnKSk7XG4gICAgICAgICAgICAgIH0gZWxzZSBpZiAocmVqZWN0aW9uLmRhdGEuZXJyb3IgIT09ICdOb3QgRm91bmQnKSB7XG4gICAgICAgICAgICAgICAgUHJUb2FzdC5lcnJvcigkdHJhbnNsYXRlLmluc3RhbnQocmVqZWN0aW9uLmRhdGEuZXJyb3IpKTtcbiAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgUHJUb2FzdC5lcnJvclZhbGlkYXRpb24ocmVqZWN0aW9uLmRhdGEpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgIH1cblxuICAgICAgICAgIHJldHVybiAkcS5yZWplY3QocmVqZWN0aW9uKTtcbiAgICAgICAgfVxuICAgICAgfTtcbiAgICB9XG5cbiAgICAvLyBEZWZpbmUgdW1hIGZhY3RvcnkgcGFyYSBvICRodHRwSW50ZXJjZXB0b3JcbiAgICAkcHJvdmlkZS5mYWN0b3J5KCdzaG93RXJyb3JWYWxpZGF0aW9uJywgc2hvd0Vycm9yVmFsaWRhdGlvbik7XG5cbiAgICAvLyBBZGljaW9uYSBhIGZhY3Rvcnkgbm8gYXJyYXkgZGUgaW50ZXJjZXB0b3JzIGRvICRodHRwXG4gICAgJGh0dHBQcm92aWRlci5pbnRlcmNlcHRvcnMucHVzaCgnc2hvd0Vycm9yVmFsaWRhdGlvbicpO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29udHJvbGxlcignS2FuYmFuQ29udHJvbGxlcicsIEthbmJhbkNvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gS2FuYmFuQ29udHJvbGxlcigkY29udHJvbGxlciwgVGFza3NTZXJ2aWNlLCBTdGF0dXNTZXJ2aWNlLCBQclRvYXN0LCAkbWREaWFsb2csICRkb2N1bWVudCwgQXV0aCwgUHJvamVjdHNTZXJ2aWNlKSB7XG4gICAgLy9BdHRyaWJ1dGVzIEJsb2NrXG4gICAgdmFyIHZtID0gdGhpcztcbiAgICB2YXIgZmllbGRzID0gW3sgbmFtZTogJ2lkJywgdHlwZTogJ3N0cmluZycgfSwgeyBuYW1lOiAnc3RhdHVzJywgbWFwOiAnc3RhdGUnLCB0eXBlOiAnc3RyaW5nJyB9LCB7IG5hbWU6ICd0ZXh0JywgbWFwOiAnbGFiZWwnLCB0eXBlOiAnc3RyaW5nJyB9LCB7IG5hbWU6ICd0YWdzJywgdHlwZTogJ3N0cmluZycgfV07XG5cbiAgICB2bS5vbkFjdGl2YXRlID0gZnVuY3Rpb24gKCkge1xuICAgICAgdm0ucHJvamVjdCA9IGxvY2FsU3RvcmFnZS5nZXRJdGVtKCdwcm9qZWN0Jyk7XG4gICAgICBQcm9qZWN0c1NlcnZpY2UucXVlcnkoeyBwcm9qZWN0X2lkOiB2bS5wcm9qZWN0IH0pLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgIHZtLmFjdHVhbFByb2plY3QgPSByZXNwb25zZVswXTtcbiAgICAgIH0pO1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0geyBwcm9qZWN0X2lkOiB2bS5wcm9qZWN0IH07XG4gICAgICB2bS5pc01vdmVkID0gZmFsc2U7XG4gICAgfTtcblxuICAgIHZtLmFwcGx5RmlsdGVycyA9IGZ1bmN0aW9uIChkZWZhdWx0UXVlcnlGaWx0ZXJzKSB7XG4gICAgICByZXR1cm4gYW5ndWxhci5leHRlbmQoZGVmYXVsdFF1ZXJ5RmlsdGVycywgdm0ucXVlcnlGaWx0ZXJzKTtcbiAgICB9O1xuXG4gICAgdm0uYWZ0ZXJTZWFyY2ggPSBmdW5jdGlvbiAoKSB7XG4gICAgICB2YXIgY29sdW1ucyA9IFtdO1xuICAgICAgdmFyIHRhc2tzID0gW107XG5cbiAgICAgIFN0YXR1c1NlcnZpY2UucXVlcnkoKS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICByZXNwb25zZS5mb3JFYWNoKGZ1bmN0aW9uIChzdGF0dXMpIHtcbiAgICAgICAgICBjb2x1bW5zLnB1c2goeyB0ZXh0OiBzdGF0dXMubmFtZSwgZGF0YUZpZWxkOiBzdGF0dXMuc2x1ZywgY29sbGFwc2libGU6IGZhbHNlIH0pO1xuICAgICAgICB9KTtcblxuICAgICAgICBpZiAodm0ucmVzb3VyY2VzLmxlbmd0aCA+IDApIHtcbiAgICAgICAgICB2bS5yZXNvdXJjZXMuZm9yRWFjaChmdW5jdGlvbiAodGFzaykge1xuICAgICAgICAgICAgdGFza3MucHVzaCh7XG4gICAgICAgICAgICAgIGlkOiB0YXNrLmlkLFxuICAgICAgICAgICAgICBzdGF0ZTogdGFzay5zdGF0dXMuc2x1ZyxcbiAgICAgICAgICAgICAgbGFiZWw6IHRhc2sudGl0bGUsXG4gICAgICAgICAgICAgIHRhZ3M6IHRhc2sudHlwZS5uYW1lICsgJywgJyArIHRhc2sucHJpb3JpdHkubmFtZVxuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgfSk7XG5cbiAgICAgICAgICB2YXIgc291cmNlID0ge1xuICAgICAgICAgICAgbG9jYWxEYXRhOiB0YXNrcyxcbiAgICAgICAgICAgIGRhdGFUeXBlOiAnYXJyYXknLFxuICAgICAgICAgICAgZGF0YUZpZWxkczogZmllbGRzXG4gICAgICAgICAgfTtcbiAgICAgICAgICB2YXIgZGF0YUFkYXB0ZXIgPSBuZXcgJC5qcXguZGF0YUFkYXB0ZXIoc291cmNlKTtcblxuICAgICAgICAgIHZtLnNldHRpbmdzID0ge1xuICAgICAgICAgICAgc291cmNlOiBkYXRhQWRhcHRlcixcbiAgICAgICAgICAgIGNvbHVtbnM6IGNvbHVtbnMsXG4gICAgICAgICAgICB0aGVtZTogJ2xpZ2h0J1xuICAgICAgICAgIH07XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgdm0uc2V0dGluZ3MgPSB7XG4gICAgICAgICAgICBzb3VyY2U6IFt7fV0sXG4gICAgICAgICAgICBjb2x1bW5zOiBjb2x1bW5zLFxuICAgICAgICAgICAgdGhlbWU6ICdsaWdodCdcbiAgICAgICAgICB9O1xuICAgICAgICB9XG4gICAgICAgIHZtLmthbmJhblJlYWR5ID0gdHJ1ZTtcbiAgICAgIH0pO1xuICAgIH07XG5cbiAgICB2bS5vbkl0ZW1Nb3ZlZCA9IGZ1bmN0aW9uIChldmVudCkge1xuICAgICAgaWYgKEF1dGguY3VycmVudFVzZXIuaWQgPT09IHZtLmFjdHVhbFByb2plY3Qub3duZXIpIHtcbiAgICAgICAgdm0uaXNNb3ZlZCA9IHRydWU7XG4gICAgICAgIFRhc2tzU2VydmljZS5xdWVyeSh7IHRhc2tfaWQ6IGV2ZW50LmFyZ3MuaXRlbUlkIH0pLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgICAgaWYgKHJlc3BvbnNlWzBdLm1pbGVzdG9uZSAmJiByZXNwb25zZVswXS5taWxlc3RvbmUuZG9uZSB8fCByZXNwb25zZVswXS5wcm9qZWN0LmRvbmUpIHtcbiAgICAgICAgICAgIFByVG9hc3QuZXJyb3IoJ07Do28gw6kgcG9zc8OtdmVsIG1vZGlmaWNhciBvIHN0YXR1cyBkZSB1bWEgdGFyZWZhIGZpbmFsaXphZGEuJyk7XG4gICAgICAgICAgICB2bS5hZnRlclNlYXJjaCgpO1xuICAgICAgICAgICAgdm0uaXNNb3ZlZCA9IGZhbHNlO1xuICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICBUYXNrc1NlcnZpY2UudXBkYXRlVGFza0J5S2FuYmFuKHtcbiAgICAgICAgICAgICAgcHJvamVjdF9pZDogdm0ucHJvamVjdCxcbiAgICAgICAgICAgICAgaWQ6IGV2ZW50LmFyZ3MuaXRlbUlkLFxuICAgICAgICAgICAgICBvbGRDb2x1bW46IGV2ZW50LmFyZ3Mub2xkQ29sdW1uLFxuICAgICAgICAgICAgICBuZXdDb2x1bW46IGV2ZW50LmFyZ3MubmV3Q29sdW1uIH0pLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICB2bS5pc01vdmVkID0gZmFsc2U7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgICB9XG4gICAgICAgIH0pO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgdm0uYWZ0ZXJTZWFyY2goKTtcbiAgICAgIH1cbiAgICB9O1xuXG4gICAgdm0ub25JdGVtQ2xpY2tlZCA9IGZ1bmN0aW9uIChldmVudCkge1xuICAgICAgaWYgKCF2bS5pc01vdmVkKSB7XG4gICAgICAgIFRhc2tzU2VydmljZS5xdWVyeSh7IHRhc2tfaWQ6IGV2ZW50LmFyZ3MuaXRlbUlkIH0pLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgICAgdm0udGFza0luZm8gPSByZXNwb25zZVswXTtcbiAgICAgICAgICAkbWREaWFsb2cuc2hvdyh7XG4gICAgICAgICAgICBwYXJlbnQ6IGFuZ3VsYXIuZWxlbWVudCgkZG9jdW1lbnQuYm9keSksXG4gICAgICAgICAgICB0ZW1wbGF0ZVVybDogJ2NsaWVudC9hcHAva2FuYmFuL3Rhc2staW5mby1kaWFsb2cvdGFza0luZm8uaHRtbCcsXG4gICAgICAgICAgICBjb250cm9sbGVyQXM6ICd0YXNrSW5mb0N0cmwnLFxuICAgICAgICAgICAgY29udHJvbGxlcjogJ1Rhc2tJbmZvQ29udHJvbGxlcicsXG4gICAgICAgICAgICBiaW5kVG9Db250cm9sbGVyOiB0cnVlLFxuICAgICAgICAgICAgbG9jYWxzOiB7XG4gICAgICAgICAgICAgIHRhc2s6IHZtLnRhc2tJbmZvLFxuICAgICAgICAgICAgICBjbG9zZTogY2xvc2VcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICBlc2NhcGVUb0Nsb3NlOiB0cnVlLFxuICAgICAgICAgICAgY2xpY2tPdXRzaWRlVG9DbG9zZTogdHJ1ZVxuICAgICAgICAgIH0pO1xuICAgICAgICB9KTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHZtLmlzTW92ZWQgPSBmYWxzZTtcbiAgICAgIH1cbiAgICB9O1xuXG4gICAgZnVuY3Rpb24gY2xvc2UoKSB7XG4gICAgICAkbWREaWFsb2cuaGlkZSgpO1xuICAgIH1cblxuICAgIC8vIGluc3RhbnRpYXRlIGJhc2UgY29udHJvbGxlclxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHsgdm06IHZtLCBtb2RlbFNlcnZpY2U6IFRhc2tzU2VydmljZSwgb3B0aW9uczoge30gfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqXG4gICAqIEFycXVpdm8gZGUgY29uZmlndXJhw6fDo28gY29tIGFzIHJvdGFzIGVzcGVjw61maWNhcyBkbyByZWN1cnNvIGthbmJhblxuICAgKlxuICAgKiBAcGFyYW0ge29iamVjdH0gJHN0YXRlUHJvdmlkZXJcbiAgICogQHBhcmFtIHtvYmplY3R9IEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdhcHAua2FuYmFuJywge1xuICAgICAgdXJsOiAnL2thbmJhbicsXG4gICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL2thbmJhbi9rYW5iYW4uaHRtbCcsXG4gICAgICBjb250cm9sbGVyOiAnS2FuYmFuQ29udHJvbGxlciBhcyBrYW5iYW5DdHJsJyxcbiAgICAgIGRhdGE6IHt9XG4gICAgfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmFjdG9yeSgnS2FuYmFuU2VydmljZScsIEthbmJhblNlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gS2FuYmFuU2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHZhciBtb2RlbCA9IHNlcnZpY2VGYWN0b3J5KCdrYW5iYW4nLCB7XG4gICAgICBhY3Rpb25zOiB7fSxcbiAgICAgIGluc3RhbmNlOiB7fVxuICAgIH0pO1xuXG4gICAgcmV0dXJuIG1vZGVsO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4vKmVzbGludC1lbnYgZXM2Ki9cblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbnRyb2xsZXIoJ01lbnVDb250cm9sbGVyJywgTWVudUNvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gTWVudUNvbnRyb2xsZXIoJG1kU2lkZW5hdiwgJHN0YXRlLCAkbWRDb2xvcnMpIHtcbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgLy9CbG9jbyBkZSBkZWNsYXJhY29lcyBkZSBmdW5jb2VzXG4gICAgdm0ub3BlbiA9IG9wZW47XG4gICAgdm0ub3Blbk1lbnVPclJlZGlyZWN0VG9TdGF0ZSA9IG9wZW5NZW51T3JSZWRpcmVjdFRvU3RhdGU7XG5cbiAgICBhY3RpdmF0ZSgpO1xuXG4gICAgZnVuY3Rpb24gYWN0aXZhdGUoKSB7XG4gICAgICB2YXIgbWVudVByZWZpeCA9ICd2aWV3cy5sYXlvdXQubWVudS4nO1xuXG4gICAgICAvLyBBcnJheSBjb250ZW5kbyBvcyBpdGVucyBxdWUgc8OjbyBtb3N0cmFkb3Mgbm8gbWVudSBsYXRlcmFsXG4gICAgICB2bS5pdGVuc01lbnUgPSBbeyBzdGF0ZTogJ2FwcC5wcm9qZWN0cycsIHRpdGxlOiBtZW51UHJlZml4ICsgJ3Byb2plY3RzJywgaWNvbjogJ3dvcmsnLCBzdWJJdGVuczogW10gfSwgeyBzdGF0ZTogJ2FwcC5kYXNoYm9hcmQnLCB0aXRsZTogbWVudVByZWZpeCArICdkYXNoYm9hcmQnLCBpY29uOiAnZGFzaGJvYXJkJywgc3ViSXRlbnM6IFtdIH0sIHsgc3RhdGU6ICdhcHAudGFza3MnLCB0aXRsZTogbWVudVByZWZpeCArICd0YXNrcycsIGljb246ICd2aWV3X2xpc3QnLCBzdWJJdGVuczogW10gfSwgeyBzdGF0ZTogJ2FwcC5taWxlc3RvbmVzJywgdGl0bGU6IG1lbnVQcmVmaXggKyAnbWlsZXN0b25lcycsIGljb246ICd2aWV3X21vZHVsZScsIHN1Ykl0ZW5zOiBbXSB9LCB7IHN0YXRlOiAnYXBwLnJlbGVhc2VzJywgdGl0bGU6IG1lbnVQcmVmaXggKyAncmVsZWFzZXMnLCBpY29uOiAnc3Vic2NyaXB0aW9ucycsIHN1Ykl0ZW5zOiBbXSB9LCB7IHN0YXRlOiAnYXBwLmthbmJhbicsIHRpdGxlOiBtZW51UHJlZml4ICsgJ2thbmJhbicsIGljb246ICd2aWV3X2NvbHVtbicsIHN1Ykl0ZW5zOiBbXSB9LCB7IHN0YXRlOiAnYXBwLnZjcycsIHRpdGxlOiBtZW51UHJlZml4ICsgJ3ZjcycsIGljb246ICdncm91cF93b3JrJywgc3ViSXRlbnM6IFtdXG4gICAgICAgIC8vIENvbG9xdWUgc2V1cyBpdGVucyBkZSBtZW51IGEgcGFydGlyIGRlc3RlIHBvbnRvXG4gICAgICAgIC8qIHtcbiAgICAgICAgICBzdGF0ZTogJyMnLCB0aXRsZTogbWVudVByZWZpeCArICdhZG1pbicsIGljb246ICdzZXR0aW5nc19hcHBsaWNhdGlvbnMnLCBwcm9maWxlczogWydhZG1pbiddLFxuICAgICAgICAgIHN1Ykl0ZW5zOiBbXG4gICAgICAgICAgICB7IHN0YXRlOiAnYXBwLnVzZXInLCB0aXRsZTogbWVudVByZWZpeCArICd1c2VyJywgaWNvbjogJ3Blb3BsZScgfSxcbiAgICAgICAgICAgIHsgc3RhdGU6ICdhcHAubWFpbCcsIHRpdGxlOiBtZW51UHJlZml4ICsgJ21haWwnLCBpY29uOiAnbWFpbCcgfSxcbiAgICAgICAgICAgIHsgc3RhdGU6ICdhcHAuYXVkaXQnLCB0aXRsZTogbWVudVByZWZpeCArICdhdWRpdCcsIGljb246ICdzdG9yYWdlJyB9LFxuICAgICAgICAgICAgeyBzdGF0ZTogJ2FwcC5kaW5hbWljLXF1ZXJ5JywgdGl0bGU6IG1lbnVQcmVmaXggKyAnZGluYW1pY1F1ZXJ5JywgaWNvbjogJ2xvY2F0aW9uX3NlYXJjaGluZycgfVxuICAgICAgICAgIF1cbiAgICAgICAgfSAqL1xuICAgICAgfV07XG5cbiAgICAgIC8qKlxuICAgICAgICogT2JqZXRvIHF1ZSBwcmVlbmNoZSBvIG5nLXN0eWxlIGRvIG1lbnUgbGF0ZXJhbCB0cm9jYW5kbyBhcyBjb3Jlc1xuICAgICAgICovXG4gICAgICB2bS5zaWRlbmF2U3R5bGUgPSB7XG4gICAgICAgIHRvcDoge1xuICAgICAgICAgICdib3JkZXItYm90dG9tJzogJzFweCBzb2xpZCByZ2IoMjEwLCAyMTAsIDIxMCknLFxuICAgICAgICAgICdiYWNrZ3JvdW5kLWltYWdlJzogJy13ZWJraXQtbGluZWFyLWdyYWRpZW50KHRvcCwgcmdiKDE0NCwgMTQ0LCAxNDQpLCByZ2IoMjEwLCAyMTAsIDIxMCkpJ1xuICAgICAgICB9LFxuICAgICAgICBjb250ZW50OiB7XG4gICAgICAgICAgJ2JhY2tncm91bmQtY29sb3InOiAncmdiKDIxMCwgMjEwLCAyMTApJ1xuICAgICAgICB9LFxuICAgICAgICB0ZXh0Q29sb3I6IHtcbiAgICAgICAgICBjb2xvcjogJyNGRkYnXG4gICAgICAgIH0sXG4gICAgICAgIGxpbmVCb3R0b206IHtcbiAgICAgICAgICAnYm9yZGVyLWJvdHRvbSc6ICcxcHggc29saWQgJyArIGdldENvbG9yKCdwcmltYXJ5LTQwMCcpXG4gICAgICAgIH1cbiAgICAgIH07XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gb3BlbigpIHtcbiAgICAgICRtZFNpZGVuYXYoJ2xlZnQnKS50b2dnbGUoKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBNw6l0b2RvIHF1ZSBleGliZSBvIHN1YiBtZW51IGRvcyBpdGVucyBkbyBtZW51IGxhdGVyYWwgY2FzbyB0ZW5oYSBzdWIgaXRlbnNcbiAgICAgKiBjYXNvIGNvbnRyw6FyaW8gcmVkaXJlY2lvbmEgcGFyYSBvIHN0YXRlIHBhc3NhZG8gY29tbyBwYXLDg8KibWV0cm9cbiAgICAgKi9cbiAgICBmdW5jdGlvbiBvcGVuTWVudU9yUmVkaXJlY3RUb1N0YXRlKCRtZE1lbnUsIGV2LCBpdGVtKSB7XG4gICAgICBpZiAoYW5ndWxhci5pc0RlZmluZWQoaXRlbS5zdWJJdGVucykgJiYgaXRlbS5zdWJJdGVucy5sZW5ndGggPiAwKSB7XG4gICAgICAgICRtZE1lbnUub3Blbihldik7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICAkc3RhdGUuZ28oaXRlbS5zdGF0ZSwgeyBvYmo6IG51bGwgfSk7XG4gICAgICAgICRtZFNpZGVuYXYoJ2xlZnQnKS5jbG9zZSgpO1xuICAgICAgfVxuICAgIH1cblxuICAgIGZ1bmN0aW9uIGdldENvbG9yKGNvbG9yUGFsZXR0ZXMpIHtcbiAgICAgIHJldHVybiAkbWRDb2xvcnMuZ2V0VGhlbWVDb2xvcihjb2xvclBhbGV0dGVzKTtcbiAgICB9XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb250cm9sbGVyKCdNYWlsc0NvbnRyb2xsZXInLCBNYWlsc0NvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gTWFpbHNDb250cm9sbGVyKE1haWxzU2VydmljZSwgVXNlcnNTZXJ2aWNlLCBQckRpYWxvZywgUHJUb2FzdCwgLy8gTk9TT05BUlxuICAkcSwgbG9kYXNoLCAkdHJhbnNsYXRlLCBHbG9iYWwpIHtcblxuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICB2bS5maWx0ZXJTZWxlY3RlZCA9IGZhbHNlO1xuICAgIHZtLm9wdGlvbnMgPSB7XG4gICAgICBza2luOiAna2FtYScsXG4gICAgICBsYW5ndWFnZTogJ3B0LWJyJyxcbiAgICAgIGFsbG93ZWRDb250ZW50OiB0cnVlLFxuICAgICAgZW50aXRpZXM6IHRydWUsXG4gICAgICBoZWlnaHQ6IDMwMCxcbiAgICAgIGV4dHJhUGx1Z2luczogJ2RpYWxvZyxmaW5kLGNvbG9yZGlhbG9nLHByZXZpZXcsZm9ybXMsaWZyYW1lLGZsYXNoJ1xuICAgIH07XG5cbiAgICB2bS5sb2FkVXNlcnMgPSBsb2FkVXNlcnM7XG4gICAgdm0ub3BlblVzZXJEaWFsb2cgPSBvcGVuVXNlckRpYWxvZztcbiAgICB2bS5hZGRVc2VyTWFpbCA9IGFkZFVzZXJNYWlsO1xuICAgIHZtLmNsZWFuRm9ybSA9IGNsZWFuRm9ybTtcbiAgICB2bS5zZW5kID0gc2VuZDtcblxuICAgIGFjdGl2YXRlKCk7XG5cbiAgICBmdW5jdGlvbiBhY3RpdmF0ZSgpIHtcbiAgICAgIHZtLmNsZWFuRm9ybSgpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWxpemEgYSBidXNjYSBwZWxvIHVzdcOhcmlvIHJlbW90YW1lbnRlXG4gICAgICpcbiAgICAgKiBAcGFyYW1zIHtzdHJpbmd9IC0gUmVjZWJlIG8gdmFsb3IgcGFyYSBzZXIgcGVzcXVpc2Fkb1xuICAgICAqIEByZXR1cm4ge3Byb21pc3NlfSAtIFJldG9ybmEgdW1hIHByb21pc3NlIHF1ZSBvIGNvbXBvbmV0ZSByZXNvbHZlXG4gICAgICovXG4gICAgZnVuY3Rpb24gbG9hZFVzZXJzKGNyaXRlcmlhKSB7XG4gICAgICB2YXIgZGVmZXJyZWQgPSAkcS5kZWZlcigpO1xuXG4gICAgICBVc2Vyc1NlcnZpY2UucXVlcnkoe1xuICAgICAgICBuYW1lT3JFbWFpbDogY3JpdGVyaWEsXG4gICAgICAgIG5vdFVzZXJzOiBsb2Rhc2gubWFwKHZtLm1haWwudXNlcnMsIGxvZGFzaC5wcm9wZXJ0eSgnaWQnKSkudG9TdHJpbmcoKSxcbiAgICAgICAgbGltaXQ6IDVcbiAgICAgIH0pLnRoZW4oZnVuY3Rpb24gKGRhdGEpIHtcblxuICAgICAgICAvLyB2ZXJpZmljYSBzZSBuYSBsaXN0YSBkZSB1c3VhcmlvcyBqw6EgZXhpc3RlIG8gdXN1w6FyaW8gY29tIG8gZW1haWwgcGVzcXVpc2Fkb1xuICAgICAgICBkYXRhID0gbG9kYXNoLmZpbHRlcihkYXRhLCBmdW5jdGlvbiAodXNlcikge1xuICAgICAgICAgIHJldHVybiAhbG9kYXNoLmZpbmQodm0ubWFpbC51c2VycywgeyBlbWFpbDogdXNlci5lbWFpbCB9KTtcbiAgICAgICAgfSk7XG5cbiAgICAgICAgZGVmZXJyZWQucmVzb2x2ZShkYXRhKTtcbiAgICAgIH0pO1xuXG4gICAgICByZXR1cm4gZGVmZXJyZWQucHJvbWlzZTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBBYnJlIG8gZGlhbG9nIHBhcmEgcGVzcXVpc2EgZGUgdXN1w6FyaW9zXG4gICAgICovXG4gICAgZnVuY3Rpb24gb3BlblVzZXJEaWFsb2coKSB7XG4gICAgICB2YXIgY29uZmlnID0ge1xuICAgICAgICBsb2NhbHM6IHtcbiAgICAgICAgICBvbkluaXQ6IHRydWUsXG4gICAgICAgICAgdXNlckRpYWxvZ0lucHV0OiB7XG4gICAgICAgICAgICB0cmFuc2ZlclVzZXJGbjogdm0uYWRkVXNlck1haWxcbiAgICAgICAgICB9XG4gICAgICAgIH0sXG4gICAgICAgIGNvbnRyb2xsZXI6ICdVc2Vyc0RpYWxvZ0NvbnRyb2xsZXInLFxuICAgICAgICBjb250cm9sbGVyQXM6ICdjdHJsJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy91c2Vycy9kaWFsb2cvdXNlcnMtZGlhbG9nLmh0bWwnLFxuICAgICAgICBoYXNCYWNrZHJvcDogdHJ1ZVxuICAgICAgfTtcblxuICAgICAgUHJEaWFsb2cuY3VzdG9tKGNvbmZpZyk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQWRpY2lvbmEgbyB1c3XDoXJpbyBzZWxlY2lvbmFkbyBuYSBsaXN0YSBwYXJhIHF1ZSBzZWphIGVudmlhZG8gbyBlbWFpbFxuICAgICAqL1xuICAgIGZ1bmN0aW9uIGFkZFVzZXJNYWlsKHVzZXIpIHtcbiAgICAgIHZhciB1c2VycyA9IGxvZGFzaC5maW5kKHZtLm1haWwudXNlcnMsIHsgZW1haWw6IHVzZXIuZW1haWwgfSk7XG5cbiAgICAgIGlmICh2bS5tYWlsLnVzZXJzLmxlbmd0aCA+IDAgJiYgYW5ndWxhci5pc0RlZmluZWQodXNlcnMpKSB7XG4gICAgICAgIFByVG9hc3Qud2FybigkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnVzZXIudXNlckV4aXN0cycpKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHZtLm1haWwudXNlcnMucHVzaCh7IG5hbWU6IHVzZXIubmFtZSwgZW1haWw6IHVzZXIuZW1haWwgfSk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhbGl6YSBvIGVudmlvIGRvIGVtYWlsIHBhcmEgYSBsaXN0YSBkZSB1c3XDoXJpb3Mgc2VsZWNpb25hZG9zXG4gICAgICovXG4gICAgZnVuY3Rpb24gc2VuZCgpIHtcblxuICAgICAgdm0ubWFpbC4kc2F2ZSgpLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgIGlmIChyZXNwb25zZS5sZW5ndGggPiAwKSB7XG4gICAgICAgICAgdmFyIG1zZyA9ICR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMubWFpbC5tYWlsRXJyb3JzJyk7XG5cbiAgICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IHJlc3BvbnNlLmxlbmd0aDsgaSsrKSB7XG4gICAgICAgICAgICBtc2cgKz0gcmVzcG9uc2UgKyAnXFxuJztcbiAgICAgICAgICB9XG4gICAgICAgICAgUHJUb2FzdC5lcnJvcihtc2cpO1xuICAgICAgICAgIHZtLmNsZWFuRm9ybSgpO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIFByVG9hc3Quc3VjY2VzcygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLm1haWwuc2VuZE1haWxTdWNjZXNzJykpO1xuICAgICAgICAgIHZtLmNsZWFuRm9ybSgpO1xuICAgICAgICB9XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBMaW1wYSBvIGZvcm11bMOhcmlvIGRlIGVtYWlsXG4gICAgICovXG4gICAgZnVuY3Rpb24gY2xlYW5Gb3JtKCkge1xuICAgICAgdm0ubWFpbCA9IG5ldyBNYWlsc1NlcnZpY2UoKTtcbiAgICAgIHZtLm1haWwudXNlcnMgPSBbXTtcbiAgICB9XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqXG4gICAqIEFycXVpdm8gZGUgY29uZmlndXJhw6fDo28gY29tIGFzIHJvdGFzIGVzcGVjw61maWNhcyBkbyByZWN1cnNvIGVtIHF1ZXN0w6NvXG4gICAqXG4gICAqIEBwYXJhbSB7YW55fSAkc3RhdGVQcm92aWRlclxuICAgKiBAcGFyYW0ge2FueX0gR2xvYmFsXG4gICAqL1xuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvdXRlcygkc3RhdGVQcm92aWRlciwgR2xvYmFsKSB7XG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ2FwcC5tYWlsJywge1xuICAgICAgdXJsOiAnL2VtYWlsJyxcbiAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvbWFpbC9tYWlscy1zZW5kLmh0bWwnLFxuICAgICAgY29udHJvbGxlcjogJ01haWxzQ29udHJvbGxlciBhcyBtYWlsc0N0cmwnLFxuICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IHRydWUsIG5lZWRQcm9maWxlOiBbJ2FkbWluJ10gfVxuICAgIH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZhY3RvcnkoJ01haWxzU2VydmljZScsIE1haWxzU2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBNYWlsc1NlcnZpY2Uoc2VydmljZUZhY3RvcnkpIHtcbiAgICByZXR1cm4gc2VydmljZUZhY3RvcnkoJ21haWxzJywge30pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29udHJvbGxlcignTWlsZXN0b25lc0NvbnRyb2xsZXInLCBNaWxlc3RvbmVzQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBNaWxlc3RvbmVzQ29udHJvbGxlcigkY29udHJvbGxlciwgTWlsZXN0b25lc1NlcnZpY2UsIG1vbWVudCwgVGFza3NTZXJ2aWNlLCBQclRvYXN0LCAkdHJhbnNsYXRlLCAkbWREaWFsb2csIEF1dGgpIHtcblxuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICB2bS5lc3RpbWF0ZWRQcmljZSA9IGVzdGltYXRlZFByaWNlO1xuXG4gICAgdm0ub25BY3RpdmF0ZSA9IGZ1bmN0aW9uICgpIHtcbiAgICAgIHZtLmN1cnJlbnRVc2VyID0gQXV0aC5jdXJyZW50VXNlcjtcbiAgICAgIHZtLnByb2plY3QgPSBsb2NhbFN0b3JhZ2UuZ2V0SXRlbSgncHJvamVjdCcpO1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0geyBwcm9qZWN0X2lkOiB2bS5wcm9qZWN0IH07XG4gICAgfTtcblxuICAgIGZ1bmN0aW9uIGVzdGltYXRlZFByaWNlKG1pbGVzdG9uZSkge1xuICAgICAgbWlsZXN0b25lLmVzdGltYXRlZF92YWx1ZSA9IDA7XG4gICAgICBpZiAobWlsZXN0b25lLnRhc2tzLmxlbmd0aCA+IDAgJiYgbWlsZXN0b25lLnByb2plY3QuaG91cl92YWx1ZV9maW5hbCkge1xuICAgICAgICBtaWxlc3RvbmUudGFza3MuZm9yRWFjaChmdW5jdGlvbiAodGFzaykge1xuICAgICAgICAgIG1pbGVzdG9uZS5lc3RpbWF0ZWRfdmFsdWUgKz0gcGFyc2VGbG9hdChtaWxlc3RvbmUucHJvamVjdC5ob3VyX3ZhbHVlX2ZpbmFsKSAqIHRhc2suZXN0aW1hdGVkX3RpbWU7XG4gICAgICAgIH0pO1xuICAgICAgfVxuICAgICAgcmV0dXJuIG1pbGVzdG9uZS5lc3RpbWF0ZWRfdmFsdWUudG9Mb2NhbGVTdHJpbmcoJ1B0LWJyJywgeyBtaW5pbXVtRnJhY3Rpb25EaWdpdHM6IDIgfSk7XG4gICAgfVxuXG4gICAgdm0uZXN0aW1hdGVkVGltZSA9IGZ1bmN0aW9uIChtaWxlc3RvbmUpIHtcbiAgICAgIG1pbGVzdG9uZS5lc3RpbWF0ZWRfdGltZSA9IDA7XG4gICAgICBpZiAobWlsZXN0b25lLnRhc2tzLmxlbmd0aCA+IDApIHtcbiAgICAgICAgbWlsZXN0b25lLnRhc2tzLmZvckVhY2goZnVuY3Rpb24gKHRhc2spIHtcbiAgICAgICAgICBtaWxlc3RvbmUuZXN0aW1hdGVkX3RpbWUgKz0gdGFzay5lc3RpbWF0ZWRfdGltZTtcbiAgICAgICAgfSk7XG4gICAgICB9XG4gICAgICBtaWxlc3RvbmUuZXN0aW1hdGVkX3RpbWUgPSBtaWxlc3RvbmUuZXN0aW1hdGVkX3RpbWUgLyA4O1xuICAgICAgdmFyIGRhdGVFbmQgPSBtb21lbnQobWlsZXN0b25lLmRhdGVfZW5kKTtcbiAgICAgIHZhciBkYXRlQmVnaW4gPSBtb21lbnQobWlsZXN0b25lLmRhdGVfYmVnaW4pO1xuXG4gICAgICBpZiAoZGF0ZUVuZC5kaWZmKGRhdGVCZWdpbiwgJ2RheXMnKSA8PSBtaWxlc3RvbmUuZXN0aW1hdGVkX3RpbWUpIHtcbiAgICAgICAgbWlsZXN0b25lLmNvbG9yX2VzdGltYXRlZF90aW1lID0geyBjb2xvcjogJ3JlZCcgfTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIG1pbGVzdG9uZS5jb2xvcl9lc3RpbWF0ZWRfdGltZSA9IHsgY29sb3I6ICdncmVlbicgfTtcbiAgICAgIH1cbiAgICAgIHJldHVybiBtaWxlc3RvbmUuZXN0aW1hdGVkX3RpbWU7XG4gICAgfTtcblxuICAgIHZtLmFwcGx5RmlsdGVycyA9IGZ1bmN0aW9uIChkZWZhdWx0UXVlcnlGaWx0ZXJzKSB7XG4gICAgICByZXR1cm4gYW5ndWxhci5leHRlbmQoZGVmYXVsdFF1ZXJ5RmlsdGVycywgdm0ucXVlcnlGaWx0ZXJzKTtcbiAgICB9O1xuXG4gICAgdm0uYmVmb3JlU2F2ZSA9IGZ1bmN0aW9uICgpIHtcbiAgICAgIHZtLnJlc291cmNlLnByb2plY3RfaWQgPSB2bS5wcm9qZWN0O1xuICAgIH07XG5cbiAgICB2bS5iZWZvcmVSZW1vdmUgPSBmdW5jdGlvbiAoKSB7XG4gICAgICB2bS5yZXNvdXJjZS5wcm9qZWN0X2lkID0gdm0ucHJvamVjdDtcbiAgICB9O1xuXG4gICAgdm0uZm9ybWF0RGF0ZSA9IGZ1bmN0aW9uIChkYXRlKSB7XG4gICAgICByZXR1cm4gbW9tZW50KGRhdGUpLmZvcm1hdCgnREQvTU0vWVlZWScpO1xuICAgIH07XG5cbiAgICB2bS5hZnRlckVkaXQgPSBmdW5jdGlvbiAoKSB7XG4gICAgICB2bS5yZXNvdXJjZS5kYXRlX2JlZ2luID0gbW9tZW50KHZtLnJlc291cmNlLmRhdGVfYmVnaW4pO1xuICAgICAgdm0ucmVzb3VyY2UuZGF0ZV9lbmQgPSBtb21lbnQodm0ucmVzb3VyY2UuZGF0ZV9lbmQpO1xuICAgIH07XG5cbiAgICB2bS52aWV3ID0gZnVuY3Rpb24gKHJlc291cmNlKSB7XG4gICAgICB2bS5yZXNvdXJjZSA9IHJlc291cmNlO1xuICAgICAgdm0ub25WaWV3ID0gdHJ1ZTtcbiAgICAgIHZtLnZpZXdGb3JtID0gZmFsc2U7XG4gICAgICBjb25zb2xlLmxvZyhyZXNvdXJjZS5wcm9qZWN0KTtcbiAgICB9O1xuXG4gICAgdm0uc2VhcmNoVGFzayA9IGZ1bmN0aW9uICh0YXNrVGVybSkge1xuICAgICAgcmV0dXJuIFRhc2tzU2VydmljZS5xdWVyeSh7XG4gICAgICAgIG1pbGVzdG9uZVNlYXJjaDogdHJ1ZSxcbiAgICAgICAgcHJvamVjdF9pZDogdm0ucmVzb3VyY2UucHJvamVjdF9pZCxcbiAgICAgICAgdGl0bGU6IHRhc2tUZXJtXG4gICAgICB9KTtcbiAgICB9O1xuXG4gICAgdm0ub25UYXNrQ2hhbmdlID0gZnVuY3Rpb24gKCkge1xuICAgICAgaWYgKHZtLnRhc2sgIT09IG51bGwgJiYgdm0ucmVzb3VyY2UudGFza3MuZmluZEluZGV4KGZ1bmN0aW9uIChpKSB7XG4gICAgICAgIHJldHVybiBpLmlkID09PSB2bS50YXNrLmlkO1xuICAgICAgfSkgPT09IC0xKSB7XG4gICAgICAgIHZtLnJlc291cmNlLnRhc2tzLnB1c2godm0udGFzayk7XG4gICAgICB9XG4gICAgfTtcblxuICAgIHZtLnJlbW92ZVRhc2sgPSBmdW5jdGlvbiAodGFzaykge1xuICAgICAgdm0ucmVzb3VyY2UudGFza3Muc2xpY2UoMCkuZm9yRWFjaChmdW5jdGlvbiAoZWxlbWVudCkge1xuICAgICAgICBpZiAoZWxlbWVudC5pZCA9PT0gdGFzay5pZCkge1xuICAgICAgICAgIHZtLnJlc291cmNlLnRhc2tzLnNwbGljZSh2bS5yZXNvdXJjZS50YXNrcy5pbmRleE9mKGVsZW1lbnQpLCAxKTtcbiAgICAgICAgfVxuICAgICAgfSk7XG4gICAgfTtcblxuICAgIHZtLnNhdmVUYXNrcyA9IGZ1bmN0aW9uICgpIHtcbiAgICAgIFRhc2tzU2VydmljZS51cGRhdGVNaWxlc3RvbmUoeyBwcm9qZWN0X2lkOiB2bS5yZXNvdXJjZS5wcm9qZWN0X2lkLCBtaWxlc3RvbmVfaWQ6IHZtLnJlc291cmNlLmlkLCB0YXNrczogdm0ucmVzb3VyY2UudGFza3MgfSkudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgIFByVG9hc3Quc3VjY2VzcygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnNhdmVTdWNjZXNzJykpO1xuICAgICAgICB2bS52aWV3Rm9ybSA9IGZhbHNlO1xuICAgICAgICB2bS5vblZpZXcgPSBmYWxzZTtcbiAgICAgIH0sIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgUHJUb2FzdC5lcnJvcigkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLm9wZXJhdGlvbkVycm9yJykpO1xuICAgICAgfSk7XG4gICAgfTtcblxuICAgIHZtLmZpbmFsaXplID0gZnVuY3Rpb24gKG1pbGVzdG9uZSkge1xuICAgICAgdmFyIGNvbmZpcm0gPSAkbWREaWFsb2cuY29uZmlybSgpLnRpdGxlKCdGaW5hbGl6YXIgU3ByaW50JykudGV4dENvbnRlbnQoJ1RlbSBjZXJ0ZXphIHF1ZSBkZXNlamEgZmluYWxpemFyIGEgc3ByaW50ICcgKyBtaWxlc3RvbmUudGl0bGUgKyAnPycpLm9rKCdTaW0nKS5jYW5jZWwoJ07Do28nKTtcblxuICAgICAgJG1kRGlhbG9nLnNob3coY29uZmlybSkudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgIE1pbGVzdG9uZXNTZXJ2aWNlLmZpbmFsaXplKHsgcHJvamVjdF9pZDogdm0ucHJvamVjdCwgbWlsZXN0b25lX2lkOiBtaWxlc3RvbmUuaWQgfSkudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgUHJUb2FzdC5zdWNjZXNzKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMuc3ByaW50RW5kZWRTdWNjZXNzJykpO1xuICAgICAgICAgIHZtLnNlYXJjaCgpO1xuICAgICAgICB9LCBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgUHJUb2FzdC5FcnJvcigkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnNwcmludEVuZGVkRXJyb3InKSk7XG4gICAgICAgIH0pO1xuICAgICAgfSk7XG4gICAgfTtcblxuICAgIC8vIGluc3RhbnRpYXRlIGJhc2UgY29udHJvbGxlclxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHsgdm06IHZtLCBtb2RlbFNlcnZpY2U6IE1pbGVzdG9uZXNTZXJ2aWNlLCBvcHRpb25zOiB7fSB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25maWcocm91dGVzKTtcblxuICAvKipcbiAgICogQXJxdWl2byBkZSBjb25maWd1cmHDp8OjbyBjb20gYXMgcm90YXMgZXNwZWPDrWZpY2FzIGRvIHJlY3Vyc28gbWlsZXN0b25lc1xuICAgKlxuICAgKiBAcGFyYW0ge29iamVjdH0gJHN0YXRlUHJvdmlkZXJcbiAgICogQHBhcmFtIHtvYmplY3R9IEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdhcHAubWlsZXN0b25lcycsIHtcbiAgICAgIHVybDogJy9taWxlc3RvbmVzJyxcbiAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvbWlsZXN0b25lcy9taWxlc3RvbmVzLmh0bWwnLFxuICAgICAgY29udHJvbGxlcjogJ01pbGVzdG9uZXNDb250cm9sbGVyIGFzIG1pbGVzdG9uZXNDdHJsJyxcbiAgICAgIGRhdGE6IHt9XG4gICAgfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmFjdG9yeSgnTWlsZXN0b25lc1NlcnZpY2UnLCBNaWxlc3RvbmVzU2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiBNaWxlc3RvbmVzU2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHZhciBtb2RlbCA9IHNlcnZpY2VGYWN0b3J5KCdtaWxlc3RvbmVzJywge1xuICAgICAgYWN0aW9uczoge1xuICAgICAgICBmaW5hbGl6ZToge1xuICAgICAgICAgIG1ldGhvZDogJ1BPU1QnLFxuICAgICAgICAgIHVybDogJ2ZpbmFsaXplJ1xuICAgICAgICB9LFxuICAgICAgICB1cGRhdGVSZWxlYXNlOiB7XG4gICAgICAgICAgbWV0aG9kOiAnUE9TVCcsXG4gICAgICAgICAgdXJsOiAndXBkYXRlUmVsZWFzZSdcbiAgICAgICAgfVxuICAgICAgfSxcbiAgICAgIGluc3RhbmNlOiB7fVxuICAgIH0pO1xuXG4gICAgcmV0dXJuIG1vZGVsO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZhY3RvcnkoJ1ByaW9yaXRpZXNTZXJ2aWNlJywgUHJpb3JpdGllc1NlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gUHJpb3JpdGllc1NlcnZpY2Uoc2VydmljZUZhY3RvcnkpIHtcbiAgICB2YXIgbW9kZWwgPSBzZXJ2aWNlRmFjdG9yeSgncHJpb3JpdGllcycsIHtcbiAgICAgIGFjdGlvbnM6IHt9LFxuICAgICAgaW5zdGFuY2U6IHt9XG4gICAgfSk7XG5cbiAgICByZXR1cm4gbW9kZWw7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb250cm9sbGVyKCdQcm9qZWN0c0NvbnRyb2xsZXInLCBQcm9qZWN0c0NvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gUHJvamVjdHNDb250cm9sbGVyKCRjb250cm9sbGVyLCBQcm9qZWN0c1NlcnZpY2UsIEF1dGgsIFJvbGVzU2VydmljZSwgVXNlcnNTZXJ2aWNlLCAkc3RhdGUsICRmaWx0ZXIsICRzdGF0ZVBhcmFtcywgJHdpbmRvdykge1xuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICAvL0F0dHJpYnV0ZXMgQmxvY2tcblxuICAgIC8vRnVuY3Rpb25zIEJsb2NrXG4gICAgdm0ub25BY3RpdmF0ZSA9IG9uQWN0aXZhdGU7XG4gICAgdm0uYXBwbHlGaWx0ZXJzID0gYXBwbHlGaWx0ZXJzO1xuICAgIHZtLmJlZm9yZVNhdmUgPSBiZWZvcmVTYXZlO1xuICAgIHZtLnNlYXJjaFVzZXIgPSBzZWFyY2hVc2VyO1xuICAgIHZtLmFkZFVzZXIgPSBhZGRVc2VyO1xuICAgIHZtLnJlbW92ZVVzZXIgPSByZW1vdmVVc2VyO1xuICAgIHZtLnZpZXdQcm9qZWN0ID0gdmlld1Byb2plY3Q7XG5cbiAgICB2bS5yb2xlcyA9IHt9O1xuICAgIHZtLnVzZXJzID0gW107XG5cbiAgICBmdW5jdGlvbiBvbkFjdGl2YXRlKCkge1xuICAgICAgdm0uY3VycmVudFVzZXIgPSBBdXRoLmN1cnJlbnRVc2VyO1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0geyB1c2VyX2lkOiB2bS5jdXJyZW50VXNlci5pZCB9O1xuICAgICAgUm9sZXNTZXJ2aWNlLnF1ZXJ5KCkudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgdm0ucm9sZXMgPSByZXNwb25zZTtcbiAgICAgICAgaWYgKCRzdGF0ZVBhcmFtcy5vYmogPT09ICdlZGl0Jykge1xuICAgICAgICAgIHZtLmNsZWFuRm9ybSgpO1xuICAgICAgICAgIHZtLnZpZXdGb3JtID0gdHJ1ZTtcbiAgICAgICAgICB2bS5yZXNvdXJjZSA9ICRzdGF0ZVBhcmFtcy5yZXNvdXJjZTtcbiAgICAgICAgICB1c2Vyc0FycmF5KHZtLnJlc291cmNlKTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbSgncHJvamVjdCcpO1xuICAgICAgICB9XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBhcHBseUZpbHRlcnMoZGVmYXVsdFF1ZXJ5RmlsdGVycykge1xuICAgICAgcmV0dXJuIGFuZ3VsYXIuZXh0ZW5kKGRlZmF1bHRRdWVyeUZpbHRlcnMsIHZtLnF1ZXJ5bHRlcnMpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGJlZm9yZVNhdmUoKSB7XG4gICAgICBpZiAoIXZtLnJlc291cmNlLm93bmVyKSB7XG4gICAgICAgIHZtLnJlc291cmNlLm93bmVyID0gQXV0aC5jdXJyZW50VXNlci5pZDtcbiAgICAgIH1cbiAgICAgIHZtLnJlc291cmNlLnVzZXJfaWQgPSBBdXRoLmN1cnJlbnRVc2VyLmlkO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIHNlYXJjaFVzZXIoKSB7XG4gICAgICByZXR1cm4gVXNlcnNTZXJ2aWNlLnF1ZXJ5KHsgbmFtZTogdm0udXNlck5hbWUgfSk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gYWRkVXNlcih1c2VyKSB7XG4gICAgICBpZiAodXNlcikge1xuICAgICAgICB2bS5yZXNvdXJjZS51c2Vycy5wdXNoKHVzZXIpO1xuICAgICAgICB2bS51c2VyTmFtZSA9ICcnO1xuICAgICAgfVxuICAgIH1cblxuICAgIGZ1bmN0aW9uIHJlbW92ZVVzZXIoaW5kZXgpIHtcbiAgICAgIHZtLnJlc291cmNlLnVzZXJzLnNwbGljZShpbmRleCwgMSk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gYXBwbHlGaWx0ZXJzKGRlZmF1bHRRdWVyeUZpbHRlcnMpIHtcbiAgICAgIHJldHVybiBhbmd1bGFyLmV4dGVuZChkZWZhdWx0UXVlcnlGaWx0ZXJzLCB2bS5xdWVyeUZpbHRlcnMpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIHZpZXdQcm9qZWN0KCkge1xuICAgICAgJHN0YXRlLmdvKCdhcHAuZGFzaGJvYXJkJyk7XG4gICAgfVxuXG4gICAgdm0uYWZ0ZXJTZWFyY2ggPSBmdW5jdGlvbiAoKSB7XG4gICAgICBpZiAodm0ucmVzb3VyY2VzLmxlbmd0aCA+IDApIHtcbiAgICAgICAgdm0ucmVzb3VyY2VzLmZvckVhY2goZnVuY3Rpb24gKHByb2plY3QpIHtcbiAgICAgICAgICB1c2Vyc0FycmF5KHByb2plY3QpO1xuICAgICAgICB9KTtcbiAgICAgIH1cbiAgICB9O1xuXG4gICAgZnVuY3Rpb24gdXNlcnNBcnJheShwcm9qZWN0KSB7XG4gICAgICBwcm9qZWN0LnVzZXJzID0gW107XG4gICAgICBpZiAocHJvamVjdC5jbGllbnRfaWQpIHtcbiAgICAgICAgcHJvamVjdC5jbGllbnQucm9sZSA9ICRmaWx0ZXIoJ2ZpbHRlcicpKHZtLnJvbGVzLCB7IHNsdWc6ICdjbGllbnQnIH0pWzBdO1xuICAgICAgICBwcm9qZWN0LnVzZXJzLnB1c2gocHJvamVjdC5jbGllbnQpO1xuICAgICAgfVxuICAgICAgaWYgKHByb2plY3QuZGV2X2lkKSB7XG4gICAgICAgIHByb2plY3QuZGV2ZWxvcGVyLnJvbGUgPSAkZmlsdGVyKCdmaWx0ZXInKSh2bS5yb2xlcywgeyBzbHVnOiAnZGV2JyB9KVswXTtcbiAgICAgICAgcHJvamVjdC51c2Vycy5wdXNoKHByb2plY3QuZGV2ZWxvcGVyKTtcbiAgICAgIH1cbiAgICAgIGlmIChwcm9qZWN0LnN0YWtlaG9sZGVyX2lkKSB7XG4gICAgICAgIHByb2plY3Quc3Rha2Vob2xkZXIucm9sZSA9ICRmaWx0ZXIoJ2ZpbHRlcicpKHZtLnJvbGVzLCB7IHNsdWc6ICdzdGFrZWhvbGRlcicgfSlbMF07XG4gICAgICAgIHByb2plY3QudXNlcnMucHVzaChwcm9qZWN0LnN0YWtlaG9sZGVyKTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICB2bS5oaXN0b3J5QmFjayA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICR3aW5kb3cuaGlzdG9yeS5iYWNrKCk7XG4gICAgfTtcblxuICAgIHZtLmFmdGVyU2F2ZSA9IGZ1bmN0aW9uIChyZXNvdXJjZSkge1xuICAgICAgbG9jYWxTdG9yYWdlLnNldEl0ZW0oJ3Byb2plY3QnLCByZXNvdXJjZS5pZCk7XG4gICAgICAkc3RhdGUuZ28oJ2FwcC5kYXNoYm9hcmQnKTtcbiAgICB9O1xuXG4gICAgLy8gaW5zdGFudGlhdGUgYmFzZSBjb250cm9sbGVyXG4gICAgJGNvbnRyb2xsZXIoJ0NSVURDb250cm9sbGVyJywgeyB2bTogdm0sIG1vZGVsU2VydmljZTogUHJvamVjdHNTZXJ2aWNlLCBvcHRpb25zOiB7IHJlZGlyZWN0QWZ0ZXJTYXZlOiBmYWxzZSB9IH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKlxuICAgKiBBcnF1aXZvIGRlIGNvbmZpZ3VyYcOnw6NvIGNvbSBhcyByb3RhcyBlc3BlY8OtZmljYXMgZG8gcmVjdXJzbyBwcm9qZWN0XG4gICAqXG4gICAqIEBwYXJhbSB7YW55fSAkc3RhdGVQcm92aWRlclxuICAgKiBAcGFyYW0ge2FueX0gR2xvYmFsXG4gICAqL1xuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvdXRlcygkc3RhdGVQcm92aWRlciwgR2xvYmFsKSB7XG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ2FwcC5wcm9qZWN0cycsIHtcbiAgICAgIHVybDogJy9wcm9qZWN0cycsXG4gICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL3Byb2plY3RzL3Byb2plY3RzLmh0bWwnLFxuICAgICAgY29udHJvbGxlcjogJ1Byb2plY3RzQ29udHJvbGxlciBhcyBwcm9qZWN0c0N0cmwnLFxuICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IHRydWUgfSxcbiAgICAgIHBhcmFtczogeyBvYmo6IG51bGwsIHJlc291cmNlOiBudWxsIH1cbiAgICB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5mYWN0b3J5KCdQcm9qZWN0c1NlcnZpY2UnLCBQcm9qZWN0c1NlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gUHJvamVjdHNTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCdwcm9qZWN0cycsIHtcbiAgICAgIGFjdGlvbnM6IHtcbiAgICAgICAgZmluYWxpemU6IHtcbiAgICAgICAgICBtZXRob2Q6ICdQT1NUJyxcbiAgICAgICAgICB1cmw6ICdmaW5hbGl6ZSdcbiAgICAgICAgfSB9LFxuICAgICAgaW5zdGFuY2U6IHt9XG4gICAgfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb250cm9sbGVyKCdSZWxlYXNlc0NvbnRyb2xsZXInLCBSZWxlYXNlc0NvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gUmVsZWFzZXNDb250cm9sbGVyKCRjb250cm9sbGVyLCBSZWxlYXNlc1NlcnZpY2UsIE1pbGVzdG9uZXNTZXJ2aWNlLCBBdXRoLCBQclRvYXN0LCBtb21lbnQsICRtZERpYWxvZywgJHRyYW5zbGF0ZSkge1xuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICAvL0F0dHJpYnV0ZXMgQmxvY2tcblxuICAgIC8vRnVuY3Rpb25zIEJsb2NrXG4gICAgdm0ub25BY3RpdmF0ZSA9IGZ1bmN0aW9uICgpIHtcbiAgICAgIHZtLmN1cnJlbnRVc2VyID0gQXV0aC5jdXVycmVudFVzZXI7XG4gICAgICB2bS5wcm9qZWN0ID0gbG9jYWxTdG9yYWdlLmdldEl0ZW0oJ3Byb2plY3QnKTtcbiAgICAgIHZtLnF1ZXJ5RmlsdGVycyA9IHsgcHJvamVjdF9pZDogdm0ucHJvamVjdCB9O1xuICAgIH07XG5cbiAgICB2bS5iZWZvcmVTYXZlID0gZnVuY3Rpb24gKCkge1xuICAgICAgdm0ucmVzb3VyY2UucHJvamVjdF9pZCA9IHZtLnByb2plY3Q7XG4gICAgfTtcblxuICAgIHZtLmJlZm9yZVJlbW92ZSA9IGZ1bmN0aW9uICgpIHtcbiAgICAgIHZtLnJlc291cmNlLnByb2plY3RfaWQgPSB2bS5wcm9qZWN0O1xuICAgIH07XG5cbiAgICB2bS52aWV3ID0gZnVuY3Rpb24gKHJlc291cmNlKSB7XG4gICAgICB2bS5yZXNvdXJjZSA9IHJlc291cmNlO1xuICAgICAgdm0ub25WaWV3ID0gdHJ1ZTtcbiAgICAgIHZtLnZpZXdGb3JtID0gZmFsc2U7XG4gICAgfTtcblxuICAgIHZtLmZpbmFsaXplID0gZnVuY3Rpb24gKHJlbGVhc2UpIHtcbiAgICAgIHZhciBjb25maXJtID0gJG1kRGlhbG9nLmNvbmZpcm0oKS50aXRsZSgnRmluYWxpemFyIFJlbGVhc2UnKS50ZXh0Q29udGVudCgnVGVtIGNlcnRlemEgcXVlIGRlc2VqYSBmaW5hbGl6YXIgYSByZWxlYXNlICcgKyByZWxlYXNlLnRpdGxlICsgJz8nKS5vaygnU2ltJykuY2FuY2VsKCdOw6NvJyk7XG5cbiAgICAgICRtZERpYWxvZy5zaG93KGNvbmZpcm0pLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICBSZWxlYXNlc1NlcnZpY2UuZmluYWxpemUoeyBwcm9qZWN0X2lkOiB2bS5wcm9qZWN0LCByZWxlYXNlX2lkOiByZWxlYXNlLmlkIH0pLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICAgIFByVG9hc3Quc3VjY2VzcygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnJlbGVhc2VFbmRlZFN1Y2Nlc3MnKSk7XG4gICAgICAgICAgdm0uc2VhcmNoKCk7XG4gICAgICAgIH0sIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICBQclRvYXN0LkVycm9yKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMucmVsZWFzZUVuZGVkRXJyb3InKSk7XG4gICAgICAgIH0pO1xuICAgICAgfSk7XG4gICAgfTtcblxuICAgIHZtLmZvcm1hdERhdGUgPSBmdW5jdGlvbiAoZGF0ZSkge1xuICAgICAgcmV0dXJuIG1vbWVudChkYXRlKS5mb3JtYXQoJ0REL01NL1lZWVknKTtcbiAgICB9O1xuXG4gICAgdm0uc2VhcmNoTWlsZXN0b25lID0gZnVuY3Rpb24gKG1pbGVzdG9uZVRlcm0pIHtcbiAgICAgIHJldHVybiBNaWxlc3RvbmVzU2VydmljZS5xdWVyeSh7XG4gICAgICAgIHJlbGVhc2VTZWFyY2g6IHRydWUsXG4gICAgICAgIHByb2plY3RfaWQ6IHZtLnJlc291cmNlLnByb2plY3RfaWQsXG4gICAgICAgIHRpdGxlOiBtaWxlc3RvbmVUZXJtXG4gICAgICB9KTtcbiAgICB9O1xuXG4gICAgdm0ub25NaWxlc3RvbmVDaGFuZ2UgPSBmdW5jdGlvbiAoKSB7XG4gICAgICBpZiAodm0ubWlsZXN0b25lICE9PSBudWxsICYmIHZtLnJlc291cmNlLm1pbGVzdG9uZXMuZmluZEluZGV4KGZ1bmN0aW9uIChpKSB7XG4gICAgICAgIHJldHVybiBpLmlkID09PSB2bS5taWxlc3RvbmUuaWQ7XG4gICAgICB9KSA9PT0gLTEpIHtcbiAgICAgICAgdm0ucmVzb3VyY2UubWlsZXN0b25lcy5wdXNoKHZtLm1pbGVzdG9uZSk7XG4gICAgICB9XG4gICAgfTtcblxuICAgIHZtLnJlbW92ZU1pbGVzdG9uZSA9IGZ1bmN0aW9uIChtaWxlc3RvbmUpIHtcbiAgICAgIHZtLnJlc291cmNlLm1pbGVzdG9uZXMuc2xpY2UoMCkuZm9yRWFjaChmdW5jdGlvbiAoZWxlbWVudCkge1xuICAgICAgICBpZiAoZWxlbWVudC5pZCA9PT0gbWlsZXN0b25lLmlkKSB7XG4gICAgICAgICAgdm0ucmVzb3VyY2UubWlsZXN0b25lcy5zcGxpY2Uodm0ucmVzb3VyY2UubWlsZXN0b25lcy5pbmRleE9mKGVsZW1lbnQpLCAxKTtcbiAgICAgICAgfVxuICAgICAgfSk7XG4gICAgfTtcblxuICAgIHZtLnNhdmVNaWxlc3RvbmVzID0gZnVuY3Rpb24gKCkge1xuICAgICAgTWlsZXN0b25lc1NlcnZpY2UudXBkYXRlUmVsZWFzZSh7IHByb2plY3RfaWQ6IHZtLnJlc291cmNlLnByb2plY3RfaWQsIHJlbGVhc2VfaWQ6IHZtLnJlc291cmNlLmlkLCBtaWxlc3RvbmVzOiB2bS5yZXNvdXJjZS5taWxlc3RvbmVzIH0pLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICBQclRvYXN0LnN1Y2Nlc3MoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5zYXZlU3VjY2VzcycpKTtcbiAgICAgICAgdm0udmlld0Zvcm0gPSBmYWxzZTtcbiAgICAgICAgdm0ub25WaWV3ID0gZmFsc2U7XG4gICAgICB9LCBmdW5jdGlvbiAoKSB7XG4gICAgICAgIFByVG9hc3QuZXJyb3IoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5vcGVyYXRpb25FcnJvcicpKTtcbiAgICAgIH0pO1xuICAgIH07XG5cbiAgICB2bS5lc3RpbWF0ZWRUaW1lID0gZnVuY3Rpb24gKG1pbGVzdG9uZSkge1xuICAgICAgbWlsZXN0b25lLmVzdGltYXRlZF90aW1lID0gMDtcbiAgICAgIGlmIChtaWxlc3RvbmUudGFza3MubGVuZ3RoID4gMCkge1xuICAgICAgICBtaWxlc3RvbmUudGFza3MuZm9yRWFjaChmdW5jdGlvbiAodGFzaykge1xuICAgICAgICAgIG1pbGVzdG9uZS5lc3RpbWF0ZWRfdGltZSArPSB0YXNrLmVzdGltYXRlZF90aW1lO1xuICAgICAgICB9KTtcbiAgICAgIH1cbiAgICAgIHJldHVybiBtaWxlc3RvbmUuZXN0aW1hdGVkX3RpbWUgLyA4O1xuICAgIH07XG5cbiAgICAvLyBpbnN0YW50aWF0ZSBiYXNlIGNvbnRyb2xsZXJcbiAgICAkY29udHJvbGxlcignQ1JVRENvbnRyb2xsZXInLCB7IHZtOiB2bSwgbW9kZWxTZXJ2aWNlOiBSZWxlYXNlc1NlcnZpY2UsIG9wdGlvbnM6IHt9IH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKlxuICAgKiBBcnF1aXZvIGRlIGNvbmZpZ3VyYcOnw6NvIGNvbSBhcyByb3RhcyBlc3BlY8OtZmljYXMgZG8gcmVjdXJzbyByZWxlYXNlc1xuICAgKlxuICAgKiBAcGFyYW0ge29iamVjdH0gJHN0YXRlUHJvdmlkZXJcbiAgICogQHBhcmFtIHtvYmplY3R9IEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdhcHAucmVsZWFzZXMnLCB7XG4gICAgICB1cmw6ICcvcmVsZWFzZXMnLFxuICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9yZWxlYXNlcy9yZWxlYXNlcy5odG1sJyxcbiAgICAgIGNvbnRyb2xsZXI6ICdSZWxlYXNlc0NvbnRyb2xsZXIgYXMgcmVsZWFzZXNDdHJsJyxcbiAgICAgIGRhdGE6IHt9XG4gICAgfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmFjdG9yeSgnUmVsZWFzZXNTZXJ2aWNlJywgUmVsZWFzZXNTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIFJlbGVhc2VzU2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHZhciBtb2RlbCA9IHNlcnZpY2VGYWN0b3J5KCdyZWxlYXNlcycsIHtcbiAgICAgIGFjdGlvbnM6IHtcbiAgICAgICAgZmluYWxpemU6IHtcbiAgICAgICAgICBtZXRob2Q6ICdQT1NUJyxcbiAgICAgICAgICB1cmw6ICdmaW5hbGl6ZSdcbiAgICAgICAgfVxuICAgICAgfSxcbiAgICAgIGluc3RhbmNlOiB7fVxuICAgIH0pO1xuXG4gICAgcmV0dXJuIG1vZGVsO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmlsdGVyKCdyb2xlc1N0cicsIHJvbGVzU3RyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvbGVzU3RyKGxvZGFzaCkge1xuICAgIC8qKlxuICAgICAqIEBwYXJhbSB7YXJyYXl9IHJvbGVzIGxpc3RhIGRlIHBlcmZpc1xuICAgICAqIEByZXR1cm4ge3N0cmluZ30gcGVyZmlzIHNlcGFyYWRvcyBwb3IgJywgJyAgXG4gICAgICovXG4gICAgcmV0dXJuIGZ1bmN0aW9uIChyb2xlcykge1xuICAgICAgcmV0dXJuIGxvZGFzaC5tYXAocm9sZXMsICdzbHVnJykuam9pbignLCAnKTtcbiAgICB9O1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZhY3RvcnkoJ1JvbGVzU2VydmljZScsIFJvbGVzU2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiBSb2xlc1NlcnZpY2Uoc2VydmljZUZhY3RvcnkpIHtcbiAgICByZXR1cm4gc2VydmljZUZhY3RvcnkoJ3JvbGVzJyk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmFjdG9yeSgnU3RhdHVzU2VydmljZScsIFN0YXR1c1NlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gU3RhdHVzU2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHZhciBtb2RlbCA9IHNlcnZpY2VGYWN0b3J5KCdzdGF0dXMnLCB7XG4gICAgICBhY3Rpb25zOiB7fSxcbiAgICAgIGluc3RhbmNlOiB7fVxuICAgIH0pO1xuXG4gICAgcmV0dXJuIG1vZGVsO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZhY3RvcnkoJ1N1cHBvcnRTZXJ2aWNlJywgU3VwcG9ydFNlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gU3VwcG9ydFNlcnZpY2Uoc2VydmljZUZhY3RvcnkpIHtcbiAgICByZXR1cm4gc2VydmljZUZhY3RvcnkoJ3N1cHBvcnQnLCB7XG4gICAgICBhY3Rpb25zOiB7XG4gICAgICAgIC8qKlxuICAgICAgICAgKiBQZWdhIGFzIHRyYWR1w6fDtWVzIHF1ZSBlc3TDo28gbm8gc2Vydmlkb3JcbiAgICAgICAgICpcbiAgICAgICAgICogQHJldHVybnMge3Byb21pc2V9IFVtYSBwcm9taXNlIGNvbSBvIHJlc3VsdGFkbyBkbyBjaGFtYWRhIG5vIGJhY2tlbmRcbiAgICAgICAgICovXG4gICAgICAgIGxhbmdzOiB7XG4gICAgICAgICAgbWV0aG9kOiAnR0VUJyxcbiAgICAgICAgICB1cmw6ICdsYW5ncycsXG4gICAgICAgICAgd3JhcDogZmFsc2UsXG4gICAgICAgICAgY2FjaGU6IHRydWVcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZhY3RvcnkoJ1Rhc2tDb21tZW50c1NlcnZpY2UnLCBUYXNrQ29tbWVudHNTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIFRhc2tDb21tZW50c1NlcnZpY2Uoc2VydmljZUZhY3RvcnkpIHtcbiAgICB2YXIgbW9kZWwgPSBzZXJ2aWNlRmFjdG9yeSgndGFzay1jb21tZW50cycsIHtcbiAgICAgIGFjdGlvbnM6IHtcbiAgICAgICAgc2F2ZVRhc2tDb21tZW50OiB7XG4gICAgICAgICAgbWV0aG9kOiAnUE9TVCcsXG4gICAgICAgICAgdXJsOiAnc2F2ZVRhc2tDb21tZW50J1xuICAgICAgICB9LFxuICAgICAgICByZW1vdmVUYXNrQ29tbWVudDoge1xuICAgICAgICAgIG1ldGhvZDogJ1BPU1QnLFxuICAgICAgICAgIHVybDogJ3JlbW92ZVRhc2tDb21tZW50J1xuICAgICAgICB9XG4gICAgICB9LFxuICAgICAgaW5zdGFuY2U6IHt9XG4gICAgfSk7XG5cbiAgICByZXR1cm4gbW9kZWw7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5maWx0ZXIoJ2VsYXBzZWQnLCBmdW5jdGlvbiAoKSB7XG4gICAgcmV0dXJuIGZ1bmN0aW9uIChkYXRlKSB7XG4gICAgICBpZiAoIWRhdGUpIHJldHVybjtcbiAgICAgIHZhciB0aW1lID0gRGF0ZS5wYXJzZShkYXRlKSxcbiAgICAgICAgICB0aW1lTm93ID0gbmV3IERhdGUoKS5nZXRUaW1lKCksXG4gICAgICAgICAgZGlmZmVyZW5jZSA9IHRpbWVOb3cgLSB0aW1lLFxuICAgICAgICAgIHNlY29uZHMgPSBNYXRoLmZsb29yKGRpZmZlcmVuY2UgLyAxMDAwKSxcbiAgICAgICAgICBtaW51dGVzID0gTWF0aC5mbG9vcihzZWNvbmRzIC8gNjApLFxuICAgICAgICAgIGhvdXJzID0gTWF0aC5mbG9vcihtaW51dGVzIC8gNjApLFxuICAgICAgICAgIGRheXMgPSBNYXRoLmZsb29yKGhvdXJzIC8gMjQpLFxuICAgICAgICAgIG1vbnRocyA9IE1hdGguZmxvb3IoZGF5cyAvIDMwKTtcblxuICAgICAgaWYgKG1vbnRocyA+IDEpIHtcbiAgICAgICAgcmV0dXJuIG1vbnRocyArICcgbWVzZXMgYXRyw6FzJztcbiAgICAgIH0gZWxzZSBpZiAobW9udGhzID09PSAxKSB7XG4gICAgICAgIHJldHVybiAnMSBtw6pzIGF0csOhcyc7XG4gICAgICB9IGVsc2UgaWYgKGRheXMgPiAxKSB7XG4gICAgICAgIHJldHVybiBkYXlzICsgJyBkaWFzIGF0csOhcyc7XG4gICAgICB9IGVsc2UgaWYgKGRheXMgPT09IDEpIHtcbiAgICAgICAgcmV0dXJuICcxIGRpYSBhdHLDoXMnO1xuICAgICAgfSBlbHNlIGlmIChob3VycyA+IDEpIHtcbiAgICAgICAgcmV0dXJuIGhvdXJzICsgJyBob3JhcyBhdHLDoXMnO1xuICAgICAgfSBlbHNlIGlmIChob3VycyA9PT0gMSkge1xuICAgICAgICByZXR1cm4gJ3VtYSBob3JhIGF0csOhcyc7XG4gICAgICB9IGVsc2UgaWYgKG1pbnV0ZXMgPiAxKSB7XG4gICAgICAgIHJldHVybiBtaW51dGVzICsgJyBtaW51dG9zIGF0csOhcyc7XG4gICAgICB9IGVsc2UgaWYgKG1pbnV0ZXMgPT09IDEpIHtcbiAgICAgICAgcmV0dXJuICd1bSBtaW51dG8gYXRyw6FzJztcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHJldHVybiAnaMOhIHBvdWNvcyBzZWd1bmRvcyc7XG4gICAgICB9XG4gICAgfTtcbiAgfSkuY29udHJvbGxlcignVGFza3NDb250cm9sbGVyJywgVGFza3NDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIFRhc2tzQ29udHJvbGxlcigkY29udHJvbGxlciwgVGFza3NTZXJ2aWNlLCBTdGF0dXNTZXJ2aWNlLCBQcmlvcml0aWVzU2VydmljZSwgVHlwZXNTZXJ2aWNlLCBUYXNrQ29tbWVudHNTZXJ2aWNlLCBtb21lbnQsIEF1dGgsIFByVG9hc3QsICR0cmFuc2xhdGUsICRmaWx0ZXIsIEdsb2JhbCkge1xuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICAvL0F0dHJpYnV0ZXMgQmxvY2tcblxuICAgIC8vRnVuY3Rpb25zIEJsb2NrXG4gICAgdm0ub25BY3RpdmF0ZSA9IG9uQWN0aXZhdGU7XG4gICAgdm0uYXBwbHlGaWx0ZXJzID0gYXBwbHlGaWx0ZXJzO1xuICAgIHZtLmJlZm9yZVNhdmUgPSBiZWZvcmVTYXZlO1xuICAgIHZtLmJlZm9yZVJlbW92ZSA9IGJlZm9yZVJlbW92ZTtcblxuICAgIGZ1bmN0aW9uIG9uQWN0aXZhdGUoKSB7XG4gICAgICB2bS5jdXJyZW50VXNlciA9IEF1dGguY3VycmVudFVzZXI7XG4gICAgICB2bS5pbWFnZVBhdGggPSBHbG9iYWwuaW1hZ2VQYXRoICsgJy9ub19hdmF0YXIuZ2lmJztcbiAgICAgIHZtLnByb2plY3QgPSBsb2NhbFN0b3JhZ2UuZ2V0SXRlbSgncHJvamVjdCcpO1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0geyBwcm9qZWN0X2lkOiB2bS5wcm9qZWN0IH07XG5cbiAgICAgIFN0YXR1c1NlcnZpY2UucXVlcnkoKS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICB2bS5zdGF0dXMgPSByZXNwb25zZTtcbiAgICAgIH0pO1xuXG4gICAgICBQcmlvcml0aWVzU2VydmljZS5xdWVyeSgpLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgIHZtLnByaW9yaXRpZXMgPSByZXNwb25zZTtcbiAgICAgIH0pO1xuXG4gICAgICBUeXBlc1NlcnZpY2UucXVlcnkoKS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICB2bS50eXBlcyA9IHJlc3BvbnNlO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gYXBwbHlGaWx0ZXJzKGRlZmF1bHRRdWVyeUZpbHRlcnMpIHtcbiAgICAgIHJldHVybiBhbmd1bGFyLmV4dGVuZChkZWZhdWx0UXVlcnlGaWx0ZXJzLCB2bS5xdWVyeUZpbHRlcnMpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGJlZm9yZVNhdmUoKSB7XG4gICAgICB2bS5yZXNvdXJjZS5wcm9qZWN0X2lkID0gdm0ucHJvamVjdDtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBiZWZvcmVSZW1vdmUoKSB7XG4gICAgICB2bS5yZXNvdXJjZS5wcm9qZWN0X2lkID0gdm0ucHJvamVjdDtcbiAgICB9XG5cbiAgICB2bS52aWV3ID0gZnVuY3Rpb24gKHJlc291cmNlKSB7XG4gICAgICB2bS5yZXNvdXJjZSA9IHJlc291cmNlO1xuICAgICAgdm0ub25WaWV3ID0gdHJ1ZTtcbiAgICAgIHZtLnZpZXdGb3JtID0gZmFsc2U7XG4gICAgfTtcblxuICAgIHZtLnNhdmVDb21tZW50ID0gZnVuY3Rpb24gKGNvbW1lbnQpIHtcbiAgICAgIHZhciBkZXNjcmlwdGlvbiA9ICcnO1xuICAgICAgdmFyIGNvbW1lbnRfaWQgPSBudWxsO1xuXG4gICAgICBpZiAoY29tbWVudCkge1xuICAgICAgICBkZXNjcmlwdGlvbiA9IHZtLmFuc3dlcjtcbiAgICAgICAgY29tbWVudF9pZCA9IGNvbW1lbnQuaWQ7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBkZXNjcmlwdGlvbiA9IHZtLmNvbW1lbnQ7XG4gICAgICB9XG4gICAgICBUYXNrQ29tbWVudHNTZXJ2aWNlLnNhdmVUYXNrQ29tbWVudCh7IHByb2plY3RfaWQ6IHZtLnByb2plY3QsIHRhc2tfaWQ6IHZtLnJlc291cmNlLmlkLCBjb21tZW50X3RleHQ6IGRlc2NyaXB0aW9uLCBjb21tZW50X2lkOiBjb21tZW50X2lkIH0pLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICB2bS5jb21tZW50ID0gJyc7XG4gICAgICAgIHZtLmFuc3dlciA9ICcnO1xuICAgICAgICB2bS5zZWFyY2goKTtcbiAgICAgICAgUHJUb2FzdC5zdWNjZXNzKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMuc2F2ZVN1Y2Nlc3MnKSk7XG4gICAgICB9LCBmdW5jdGlvbiAoKSB7XG4gICAgICAgIFByVG9hc3QuZXJyb3IoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5vcGVyYXRpb25FcnJvcicpKTtcbiAgICAgIH0pO1xuICAgIH07XG5cbiAgICB2bS5yZW1vdmVDb21tZW50ID0gZnVuY3Rpb24gKGNvbW1lbnQpIHtcbiAgICAgIFRhc2tDb21tZW50c1NlcnZpY2UucmVtb3ZlVGFza0NvbW1lbnQoeyBjb21tZW50X2lkOiBjb21tZW50LmlkIH0pLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICB2bS5zZWFyY2goKTtcbiAgICAgICAgUHJUb2FzdC5zdWNjZXNzKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMucmVtb3ZlU3VjY2VzcycpKTtcbiAgICAgIH0sIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgUHJUb2FzdC5lcnJvcigkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLm9wZXJhdGlvbkVycm9yJykpO1xuICAgICAgfSk7XG4gICAgfTtcblxuICAgIHZtLmFmdGVyU2VhcmNoID0gZnVuY3Rpb24gKCkge1xuICAgICAgaWYgKHZtLnJlc291cmNlLmlkKSB7XG4gICAgICAgIHZtLnJlc291cmNlID0gJGZpbHRlcignZmlsdGVyJykodm0ucmVzb3VyY2VzLCB7IGlkOiB2bS5yZXNvdXJjZS5pZCB9KVswXTtcbiAgICAgIH1cbiAgICB9O1xuXG4gICAgdm0uZml4RGF0ZSA9IGZ1bmN0aW9uIChkYXRlU3RyaW5nKSB7XG4gICAgICByZXR1cm4gbW9tZW50KGRhdGVTdHJpbmcpO1xuICAgIH07XG5cbiAgICAvLyBpbnN0YW50aWF0ZSBiYXNlIGNvbnRyb2xsZXJcbiAgICAkY29udHJvbGxlcignQ1JVRENvbnRyb2xsZXInLCB7IHZtOiB2bSwgbW9kZWxTZXJ2aWNlOiBUYXNrc1NlcnZpY2UsIG9wdGlvbnM6IHsgc2tpcFBhZ2luYXRpb246IHRydWUgfSB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25maWcocm91dGVzKTtcblxuICAvKipcbiAgICogQXJxdWl2byBkZSBjb25maWd1cmHDp8OjbyBjb20gYXMgcm90YXMgZXNwZWPDrWZpY2FzIGRvIHJlY3Vyc28gcHJvamVjdFxuICAgKlxuICAgKiBAcGFyYW0ge2FueX0gJHN0YXRlUHJvdmlkZXJcbiAgICogQHBhcmFtIHthbnl9IEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdhcHAudGFza3MnLCB7XG4gICAgICB1cmw6ICcvdGFza3MnLFxuICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy90YXNrcy90YXNrcy5odG1sJyxcbiAgICAgIGNvbnRyb2xsZXI6ICdUYXNrc0NvbnRyb2xsZXIgYXMgdGFza3NDdHJsJyxcbiAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiB0cnVlIH1cbiAgICB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5mYWN0b3J5KCdUYXNrc1NlcnZpY2UnLCBUYXNrc1NlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gVGFza3NTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCd0YXNrcycsIHtcbiAgICAgIGFjdGlvbnM6IHtcbiAgICAgICAgdXBkYXRlTWlsZXN0b25lOiB7XG4gICAgICAgICAgbWV0aG9kOiAnUE9TVCcsXG4gICAgICAgICAgdXJsOiAndXBkYXRlTWlsZXN0b25lJ1xuICAgICAgICB9LFxuICAgICAgICB1cGRhdGVUYXNrQnlLYW5iYW46IHtcbiAgICAgICAgICBtZXRob2Q6ICdQT1NUJyxcbiAgICAgICAgICB1cmw6ICd1cGRhdGVUYXNrQnlLYW5iYW4nXG4gICAgICAgIH1cbiAgICAgIH0sXG4gICAgICBpbnN0YW5jZToge31cbiAgICB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5mYWN0b3J5KCdUeXBlc1NlcnZpY2UnLCBUeXBlc1NlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gVHlwZXNTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgdmFyIG1vZGVsID0gc2VydmljZUZhY3RvcnkoJ3R5cGVzJywge1xuICAgICAgYWN0aW9uczoge30sXG4gICAgICBpbnN0YW5jZToge31cbiAgICB9KTtcblxuICAgIHJldHVybiBtb2RlbDtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbnRyb2xsZXIoJ1Byb2ZpbGVDb250cm9sbGVyJywgUHJvZmlsZUNvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gUHJvZmlsZUNvbnRyb2xsZXIoVXNlcnNTZXJ2aWNlLCBBdXRoLCBQclRvYXN0LCAkdHJhbnNsYXRlLCAkd2luZG93LCBtb21lbnQpIHtcbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0udXBkYXRlID0gdXBkYXRlO1xuICAgIHZtLmhpc3RvcnlCYWNrID0gaGlzdG9yeUJhY2s7XG5cbiAgICBhY3RpdmF0ZSgpO1xuXG4gICAgZnVuY3Rpb24gYWN0aXZhdGUoKSB7XG4gICAgICB2bS51c2VyID0gYW5ndWxhci5jb3B5KEF1dGguY3VycmVudFVzZXIpO1xuICAgICAgaWYgKHZtLnVzZXIuYmlydGhkYXkpIHtcbiAgICAgICAgdm0udXNlci5iaXJ0aGRheSA9IG1vbWVudCh2bS51c2VyLmJpcnRoZGF5KS5mb3JtYXQoJ0REL01NL1lZWVknKTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICBmdW5jdGlvbiB1cGRhdGUoKSB7XG4gICAgICBpZiAodm0udXNlci5iaXJ0aGRheSkge1xuICAgICAgICB2bS51c2VyLmJpcnRoZGF5ID0gbW9tZW50KHZtLnVzZXIuYmlydGhkYXkpO1xuICAgICAgfVxuICAgICAgVXNlcnNTZXJ2aWNlLnVwZGF0ZVByb2ZpbGUodm0udXNlcikudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgLy9hdHVhbGl6YSBvIHVzdcOhcmlvIGNvcnJlbnRlIGNvbSBhcyBub3ZhcyBpbmZvcm1hw6fDtWVzXG4gICAgICAgIEF1dGgudXBkYXRlQ3VycmVudFVzZXIocmVzcG9uc2UpO1xuICAgICAgICBQclRvYXN0LnN1Y2Nlc3MoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5zYXZlU3VjY2VzcycpKTtcbiAgICAgICAgaGlzdG9yeUJhY2soKTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGhpc3RvcnlCYWNrKCkge1xuICAgICAgJHdpbmRvdy5oaXN0b3J5LmJhY2soKTtcbiAgICB9XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb250cm9sbGVyKCdVc2Vyc0NvbnRyb2xsZXInLCBVc2Vyc0NvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gVXNlcnNDb250cm9sbGVyKCRjb250cm9sbGVyLCBVc2Vyc1NlcnZpY2UsIFByVG9hc3QsICRtZERpYWxvZywgJHRyYW5zbGF0ZSkge1xuXG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIHZtLm9uQWN0aXZhdGUgPSBvbkFjdGl2YXRlO1xuICAgIC8vIGluc3RhbnRpYXRlIGJhc2UgY29udHJvbGxlclxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHsgdm06IHZtLCBtb2RlbFNlcnZpY2U6IFVzZXJzU2VydmljZSwgb3B0aW9uczoge30gfSk7XG5cbiAgICBmdW5jdGlvbiBvbkFjdGl2YXRlKCkge1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0ge307XG4gICAgfVxuXG4gICAgdm0uaGlkZURpYWxvZyA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICRtZERpYWxvZy5oaWRlKCk7XG4gICAgfTtcblxuICAgIHZtLnNhdmVOZXdVc2VyID0gZnVuY3Rpb24gKCkge1xuICAgICAgdm0ucmVzb3VyY2UuJHNhdmUoKS50aGVuKGZ1bmN0aW9uIChyZXNvdXJjZSkge1xuICAgICAgICB2bS5yZXNvdXJjZSA9IHJlc291cmNlO1xuICAgICAgICBQclRvYXN0LnN1Y2Nlc3MoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5zdWNjZXNzU2lnblVwJykpO1xuICAgICAgICAkbWREaWFsb2cuaGlkZSgpO1xuICAgICAgfSk7XG4gICAgfTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25maWcocm91dGVzKTtcblxuICAvKipcbiAgICogQXJxdWl2byBkZSBjb25maWd1cmHDp8OjbyBjb20gYXMgcm90YXMgZXNwZWPDrWZpY2FzIGRvIHJlY3Vyc28gdXNlclxuICAgKlxuICAgKiBAcGFyYW0ge2FueX0gJHN0YXRlUHJvdmlkZXJcbiAgICogQHBhcmFtIHthbnl9IEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdhcHAudXNlcicsIHtcbiAgICAgIHVybDogJy91c3VhcmlvJyxcbiAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvdXNlcnMvdXNlcnMuaHRtbCcsXG4gICAgICBjb250cm9sbGVyOiAnVXNlcnNDb250cm9sbGVyIGFzIHVzZXJzQ3RybCcsXG4gICAgICBkYXRhOiB7IG5lZWRBdXRoZW50aWNhdGlvbjogdHJ1ZSwgbmVlZFByb2ZpbGU6IFsnYWRtaW4nXSB9XG4gICAgfSkuc3RhdGUoJ2FwcC51c2VyLXByb2ZpbGUnLCB7XG4gICAgICB1cmw6ICcvdXN1YXJpby9wZXJmaWwnLFxuICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy91c2Vycy9wcm9maWxlLmh0bWwnLFxuICAgICAgY29udHJvbGxlcjogJ1Byb2ZpbGVDb250cm9sbGVyIGFzIHByb2ZpbGVDdHJsJyxcbiAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiB0cnVlIH1cbiAgICB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5mYWN0b3J5KCdVc2Vyc1NlcnZpY2UnLCBVc2Vyc1NlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gVXNlcnNTZXJ2aWNlKGxvZGFzaCwgR2xvYmFsLCBzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHJldHVybiBzZXJ2aWNlRmFjdG9yeSgndXNlcnMnLCB7XG4gICAgICAvL3F1YW5kbyBpbnN0YW5jaWEgdW0gdXN1w6FyaW8gc2VtIHBhc3NhciBwYXJhbWV0cm8sXG4gICAgICAvL28gbWVzbW8gdmFpIHRlciBvcyB2YWxvcmVzIGRlZmF1bHRzIGFiYWl4b1xuICAgICAgZGVmYXVsdHM6IHtcbiAgICAgICAgcm9sZXM6IFtdXG4gICAgICB9LFxuXG4gICAgICBhY3Rpb25zOiB7XG4gICAgICAgIC8qKlxuICAgICAgICAgKiBTZXJ2acOnbyBxdWUgYXR1YWxpemEgb3MgZGFkb3MgZG8gcGVyZmlsIGRvIHVzdcOhcmlvIGxvZ2Fkb1xuICAgICAgICAgKlxuICAgICAgICAgKiBAcGFyYW0ge29iamVjdH0gYXR0cmlidXRlc1xuICAgICAgICAgKiBAcmV0dXJucyB7cHJvbWlzZX0gVW1hIHByb21pc2UgY29tIG8gcmVzdWx0YWRvIGRvIGNoYW1hZGEgbm8gYmFja2VuZFxuICAgICAgICAgKi9cbiAgICAgICAgdXBkYXRlUHJvZmlsZToge1xuICAgICAgICAgIG1ldGhvZDogJ1BVVCcsXG4gICAgICAgICAgdXJsOiBHbG9iYWwuYXBpUGF0aCArICcvcHJvZmlsZScsXG4gICAgICAgICAgb3ZlcnJpZGU6IHRydWUsXG4gICAgICAgICAgd3JhcDogZmFsc2VcbiAgICAgICAgfVxuICAgICAgfSxcblxuICAgICAgaW5zdGFuY2U6IHtcbiAgICAgICAgLyoqXG4gICAgICAgICAqIFZlcmlmaWNhIHNlIG8gdXN1w6FyaW8gdGVtIG9zIHBlcmZpcyBpbmZvcm1hZG9zLlxuICAgICAgICAgKlxuICAgICAgICAgKiBAcGFyYW0ge2FueX0gcm9sZXMgcGVyZmlzIGEgc2VyZW0gdmVyaWZpY2Fkb3NcbiAgICAgICAgICogQHBhcmFtIHtib29sZWFufSBhbGwgZmxhZyBwYXJhIGluZGljYXIgc2UgdmFpIGNoZWdhciB0b2RvcyBvcyBwZXJmaXMgb3Ugc29tZW50ZSB1bSBkZWxlc1xuICAgICAgICAgKiBAcmV0dXJucyB7Ym9vbGVhbn1cbiAgICAgICAgICovXG4gICAgICAgIGhhc1Byb2ZpbGU6IGZ1bmN0aW9uIGhhc1Byb2ZpbGUocm9sZXMsIGFsbCkge1xuICAgICAgICAgIHJvbGVzID0gYW5ndWxhci5pc0FycmF5KHJvbGVzKSA/IHJvbGVzIDogW3JvbGVzXTtcblxuICAgICAgICAgIHZhciB1c2VyUm9sZXMgPSBsb2Rhc2gubWFwKHRoaXMucm9sZXMsICdzbHVnJyk7XG5cbiAgICAgICAgICBpZiAoYWxsKSB7XG4gICAgICAgICAgICByZXR1cm4gbG9kYXNoLmludGVyc2VjdGlvbih1c2VyUm9sZXMsIHJvbGVzKS5sZW5ndGggPT09IHJvbGVzLmxlbmd0aDtcbiAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgLy9yZXR1cm4gdGhlIGxlbmd0aCBiZWNhdXNlIDAgaXMgZmFsc2UgaW4ganNcbiAgICAgICAgICAgIHJldHVybiBsb2Rhc2guaW50ZXJzZWN0aW9uKHVzZXJSb2xlcywgcm9sZXMpLmxlbmd0aDtcbiAgICAgICAgICB9XG4gICAgICAgIH0sXG5cbiAgICAgICAgLyoqXG4gICAgICAgICAqIFZlcmlmaWNhIHNlIG8gdXN1w6FyaW8gdGVtIG8gcGVyZmlsIGFkbWluLlxuICAgICAgICAgKlxuICAgICAgICAgKiBAcmV0dXJucyB7Ym9vbGVhbn1cbiAgICAgICAgICovXG4gICAgICAgIGlzQWRtaW46IGZ1bmN0aW9uIGlzQWRtaW4oKSB7XG4gICAgICAgICAgcmV0dXJuIHRoaXMuaGFzUHJvZmlsZSgnYWRtaW4nKTtcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4vL3Rva2VuIGNhY2I5MTIzNTg3M2E4YzQ4NzVkMjM1NzhhYzlmMzI2ZWY4OTRiNjZcbi8vIE9BdHV0aCBodHRwczovL2dpdGh1Yi5jb20vbG9naW4vb2F1dGgvYXV0aG9yaXplP2NsaWVudF9pZD04Mjk0NjhlN2ZkZWU3OTQ0NWJhNiZzY29wZT11c2VyLHB1YmxpY19yZXBvJnJlZGlyZWN0X3VyaT1odHRwOi8vMC4wLjAuMDo1MDAwLyMhL2FwcC92Y3NcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5maWx0ZXIoJ2J5dGVzJywgZnVuY3Rpb24gKCkge1xuICAgIHJldHVybiBmdW5jdGlvbiAoYnl0ZXMsIHByZWNpc2lvbikge1xuICAgICAgaWYgKGlzTmFOKHBhcnNlRmxvYXQoYnl0ZXMpKSB8fCAhaXNGaW5pdGUoYnl0ZXMpKSByZXR1cm4gJy0nO1xuICAgICAgaWYgKHR5cGVvZiBwcmVjaXNpb24gPT09ICd1bmRlZmluZWQnKSBwcmVjaXNpb24gPSAxO1xuICAgICAgdmFyIHVuaXRzID0gWydieXRlcycsICdrQicsICdNQicsICdHQicsICdUQicsICdQQiddLFxuICAgICAgICAgIG51bWJlciA9IE1hdGguZmxvb3IoTWF0aC5sb2coYnl0ZXMpIC8gTWF0aC5sb2coMTAyNCkpO1xuXG4gICAgICByZXR1cm4gKGJ5dGVzIC8gTWF0aC5wb3coMTAyNCwgTWF0aC5mbG9vcihudW1iZXIpKSkudG9GaXhlZChwcmVjaXNpb24pICsgJyAnICsgdW5pdHNbbnVtYmVyXTtcbiAgICB9O1xuICB9KS5jb250cm9sbGVyKCdWY3NDb250cm9sbGVyJywgVmNzQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBWY3NDb250cm9sbGVyKCRjb250cm9sbGVyLCBWY3NTZXJ2aWNlLCAkd2luZG93LCBQcm9qZWN0c1NlcnZpY2UsIFByVG9hc3QsICR0cmFuc2xhdGUpIHtcbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0uaW5kZXggPSAwO1xuICAgIHZtLnBhdGhzID0gW107XG5cbiAgICAvL0F0dHJpYnV0ZXMgQmxvY2tcblxuICAgIC8vRnVuY3Rpb25zIEJsb2NrXG4gICAgdm0ub25BY3RpdmF0ZSA9IGZ1bmN0aW9uICgpIHtcbiAgICAgIHRvZ2dsZVNwbGFzaFNjcmVlbigpO1xuICAgICAgUHJvamVjdHNTZXJ2aWNlLnF1ZXJ5KHsgcHJvamVjdF9pZDogbG9jYWxTdG9yYWdlLmdldEl0ZW0oJ3Byb2plY3QnKSB9KS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICB2bS51c2VybmFtZSA9IHJlc3BvbnNlWzBdLnVzZXJuYW1lX2dpdGh1YjtcbiAgICAgICAgdm0ucmVwbyA9IHJlc3BvbnNlWzBdLnJlcG9fZ2l0aHViO1xuICAgICAgICBpZiAodm0udXNlcm5hbWUgJiYgdm0ucmVwbykge1xuICAgICAgICAgIHZtLnF1ZXJ5RmlsdGVycyA9IHtcbiAgICAgICAgICAgIHVzZXJuYW1lOiB2bS51c2VybmFtZSxcbiAgICAgICAgICAgIHJlcG86IHZtLnJlcG8sXG4gICAgICAgICAgICBwYXRoOiAnLidcbiAgICAgICAgICB9O1xuICAgICAgICAgIHZtLnBhdGhzLnB1c2godm0ucXVlcnlGaWx0ZXJzLnBhdGgpO1xuICAgICAgICAgIHZtLnNlYXJjaCgpO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICR3aW5kb3cubG9hZGluZ19zY3JlZW4uZmluaXNoKCk7XG4gICAgICAgIH1cbiAgICAgIH0pO1xuICAgIH07XG5cbiAgICB2bS5hcHBseUZpbHRlcnMgPSBmdW5jdGlvbiAoZGVmYXVsdFF1ZXJ5RmlsdGVycykge1xuICAgICAgcmV0dXJuIGFuZ3VsYXIuZXh0ZW5kKGRlZmF1bHRRdWVyeUZpbHRlcnMsIHZtLnF1ZXJ5RmlsdGVycyk7XG4gICAgfTtcblxuICAgIHZtLmFmdGVyU2VhcmNoID0gZnVuY3Rpb24gKCkge1xuICAgICAgc29ydFJlc291cmNlcygpO1xuICAgICAgJHdpbmRvdy5sb2FkaW5nX3NjcmVlbi5maW5pc2goKTtcbiAgICB9O1xuXG4gICAgZnVuY3Rpb24gc29ydFJlc291cmNlcygpIHtcbiAgICAgIGlmICh2bS5yZXNvdXJjZXMubGVuZ3RoID4gMCkge1xuICAgICAgICB2bS5yZXNvdXJjZXMuc29ydChmdW5jdGlvbiAoYSwgYikge1xuICAgICAgICAgIHJldHVybiBhLnR5cGUgPCBiLnR5cGUgPyAtMSA6IGEudHlwZSA+IGIudHlwZSA/IDEgOiAwO1xuICAgICAgICB9KTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICB2bS5vcGVuRmlsZU9yRGlyZWN0b3J5ID0gZnVuY3Rpb24gKHJlc291cmNlKSB7XG4gICAgICB0b2dnbGVTcGxhc2hTY3JlZW4oKTtcbiAgICAgIGlmIChyZXNvdXJjZSkge1xuICAgICAgICB2bS5xdWVyeUZpbHRlcnMucGF0aCA9IHJlc291cmNlLnBhdGg7XG4gICAgICAgIHZtLnBhdGhzLnB1c2godm0ucXVlcnlGaWx0ZXJzLnBhdGgpO1xuICAgICAgICB2bS5pbmRleCsrO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgdm0ucXVlcnlGaWx0ZXJzLnBhdGggPSB2bS5wYXRoc1t2bS5pbmRleCAtIDFdO1xuICAgICAgICB2bS5wYXRocy5zcGxpY2Uodm0uaW5kZXgsIDEpO1xuICAgICAgICB2bS5pbmRleC0tO1xuICAgICAgfVxuICAgICAgdm0uc2VhcmNoKCk7XG4gICAgfTtcblxuICAgIHZtLm9uU2VhcmNoRXJyb3IgPSBmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgIGlmIChyZXNwb25zZS5kYXRhLmVycm9yID09PSAnTm90IEZvdW5kJykge1xuICAgICAgICBQclRvYXN0LmluZm8oJHRyYW5zbGF0ZS5pbnN0YW50KCdSZXBvc2l0w7NyaW8gbsOjbyBlbmNvbnRyYWRvJykpO1xuICAgICAgICAkd2luZG93LmxvYWRpbmdfc2NyZWVuLmZpbmlzaCgpO1xuICAgICAgfVxuICAgIH07XG5cbiAgICAvKipcbiAgICAgKiBNw6l0b2RvIHBhcmEgbW9zdHJhciBhIHRlbGEgZGUgZXNwZXJhXG4gICAgICovXG4gICAgZnVuY3Rpb24gdG9nZ2xlU3BsYXNoU2NyZWVuKCkge1xuICAgICAgJHdpbmRvdy5sb2FkaW5nX3NjcmVlbiA9ICR3aW5kb3cucGxlYXNlV2FpdCh7XG4gICAgICAgIGxvZ286ICcnLFxuICAgICAgICBiYWNrZ3JvdW5kQ29sb3I6ICdyZ2JhKDI1NSwyNTUsMjU1LDAuNCknLFxuICAgICAgICBsb2FkaW5nSHRtbDogJzxkaXYgY2xhc3M9XCJzcGlubmVyXCI+ICcgKyAnICA8ZGl2IGNsYXNzPVwicmVjdDFcIj48L2Rpdj4gJyArICcgIDxkaXYgY2xhc3M9XCJyZWN0MlwiPjwvZGl2PiAnICsgJyAgPGRpdiBjbGFzcz1cInJlY3QzXCI+PC9kaXY+ICcgKyAnICA8ZGl2IGNsYXNzPVwicmVjdDRcIj48L2Rpdj4gJyArICcgIDxkaXYgY2xhc3M9XCJyZWN0NVwiPjwvZGl2PiAnICsgJyA8cCBjbGFzcz1cImxvYWRpbmctbWVzc2FnZVwiPkNhcnJlZ2FuZG88L3A+ICcgKyAnPC9kaXY+J1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLy8gaW5zdGFudGlhdGUgYmFzZSBjb250cm9sbGVyXG4gICAgJGNvbnRyb2xsZXIoJ0NSVURDb250cm9sbGVyJywgeyB2bTogdm0sIG1vZGVsU2VydmljZTogVmNzU2VydmljZSwgb3B0aW9uczogeyBza2lwUGFnaW5hdGlvbjogdHJ1ZSwgc2VhcmNoT25Jbml0OiBmYWxzZSB9IH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKlxuICAgKiBBcnF1aXZvIGRlIGNvbmZpZ3VyYcOnw6NvIGNvbSBhcyByb3RhcyBlc3BlY8OtZmljYXMgZG8gcmVjdXJzbyB2Y3NcbiAgICpcbiAgICogQHBhcmFtIHtvYmplY3R9ICRzdGF0ZVByb3ZpZGVyXG4gICAqIEBwYXJhbSB7b2JqZWN0fSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnYXBwLnZjcycsIHtcbiAgICAgIHVybDogJy92Y3MnLFxuICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy92Y3MvdmNzLmh0bWwnLFxuICAgICAgY29udHJvbGxlcjogJ1Zjc0NvbnRyb2xsZXIgYXMgdmNzQ3RybCcsXG4gICAgICBkYXRhOiB7fVxuICAgIH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZhY3RvcnkoJ1Zjc1NlcnZpY2UnLCBWY3NTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIFZjc1NlcnZpY2Uoc2VydmljZUZhY3RvcnkpIHtcbiAgICB2YXIgbW9kZWwgPSBzZXJ2aWNlRmFjdG9yeSgndmNzJywge1xuICAgICAgYWN0aW9uczoge30sXG4gICAgICBpbnN0YW5jZToge31cbiAgICB9KTtcblxuICAgIHJldHVybiBtb2RlbDtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29tcG9uZW50KCdib3gnLCB7XG4gICAgcmVwbGFjZTogdHJ1ZSxcbiAgICB0ZW1wbGF0ZVVybDogWydHbG9iYWwnLCBmdW5jdGlvbiAoR2xvYmFsKSB7XG4gICAgICByZXR1cm4gR2xvYmFsLmNsaWVudFBhdGggKyAnL3dpZGdldHMvYm94Lmh0bWwnO1xuICAgIH1dLFxuICAgIHRyYW5zY2x1ZGU6IHtcbiAgICAgIHRvb2xiYXJCdXR0b25zOiAnP2JveFRvb2xiYXJCdXR0b25zJyxcbiAgICAgIGZvb3RlckJ1dHRvbnM6ICc/Ym94Rm9vdGVyQnV0dG9ucydcbiAgICB9LFxuICAgIGJpbmRpbmdzOiB7XG4gICAgICBib3hUaXRsZTogJ0AnLFxuICAgICAgdG9vbGJhckNsYXNzOiAnQCcsXG4gICAgICB0b29sYmFyQmdDb2xvcjogJ0AnXG4gICAgfSxcbiAgICBjb250cm9sbGVyOiBbJyR0cmFuc2NsdWRlJywgZnVuY3Rpb24gKCR0cmFuc2NsdWRlKSB7XG4gICAgICB2YXIgY3RybCA9IHRoaXM7XG5cbiAgICAgIGN0cmwudHJhbnNjbHVkZSA9ICR0cmFuc2NsdWRlO1xuXG4gICAgICBjdHJsLiRvbkluaXQgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgIGlmIChhbmd1bGFyLmlzVW5kZWZpbmVkKGN0cmwudG9vbGJhckJnQ29sb3IpKSBjdHJsLnRvb2xiYXJCZ0NvbG9yID0gJ2RlZmF1bHQtcHJpbWFyeSc7XG4gICAgICB9O1xuICAgIH1dXG4gIH0pO1xufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29tcG9uZW50KCdjb250ZW50Qm9keScsIHtcbiAgICByZXBsYWNlOiB0cnVlLFxuICAgIHRyYW5zY2x1ZGU6IHRydWUsXG4gICAgdGVtcGxhdGVVcmw6IFsnR2xvYmFsJywgZnVuY3Rpb24gKEdsb2JhbCkge1xuICAgICAgcmV0dXJuIEdsb2JhbC5jbGllbnRQYXRoICsgJy93aWRnZXRzL2NvbnRlbnQtYm9keS5odG1sJztcbiAgICB9XSxcbiAgICBiaW5kaW5nczoge1xuICAgICAgbGF5b3V0QWxpZ246ICdAJ1xuICAgIH0sXG4gICAgY29udHJvbGxlcjogW2Z1bmN0aW9uICgpIHtcbiAgICAgIHZhciBjdHJsID0gdGhpcztcblxuICAgICAgY3RybC4kb25Jbml0ID0gZnVuY3Rpb24gKCkge1xuICAgICAgICAvLyBNYWtlIGEgY29weSBvZiB0aGUgaW5pdGlhbCB2YWx1ZSB0byBiZSBhYmxlIHRvIHJlc2V0IGl0IGxhdGVyXG4gICAgICAgIGN0cmwubGF5b3V0QWxpZ24gPSBhbmd1bGFyLmlzRGVmaW5lZChjdHJsLmxheW91dEFsaWduKSA/IGN0cmwubGF5b3V0QWxpZ24gOiAnY2VudGVyIHN0YXJ0JztcbiAgICAgIH07XG4gICAgfV1cbiAgfSk7XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb21wb25lbnQoJ2NvbnRlbnRIZWFkZXInLCB7XG4gICAgdGVtcGxhdGVVcmw6IFsnR2xvYmFsJywgZnVuY3Rpb24gKEdsb2JhbCkge1xuICAgICAgcmV0dXJuIEdsb2JhbC5jbGllbnRQYXRoICsgJy93aWRnZXRzL2NvbnRlbnQtaGVhZGVyLmh0bWwnO1xuICAgIH1dLFxuICAgIHJlcGxhY2U6IHRydWUsXG4gICAgYmluZGluZ3M6IHtcbiAgICAgIHRpdGxlOiAnQCcsXG4gICAgICBkZXNjcmlwdGlvbjogJ0AnXG4gICAgfVxuICB9KTtcbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5maWx0ZXIoJ2F1ZGl0RGV0YWlsVGl0bGUnLCBhdWRpdERldGFpbFRpdGxlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIGF1ZGl0RGV0YWlsVGl0bGUoJHRyYW5zbGF0ZSkge1xuICAgIHJldHVybiBmdW5jdGlvbiAoYXVkaXREZXRhaWwsIHN0YXR1cykge1xuICAgICAgaWYgKGF1ZGl0RGV0YWlsLnR5cGUgPT09ICd1cGRhdGVkJykge1xuICAgICAgICBpZiAoc3RhdHVzID09PSAnYmVmb3JlJykge1xuICAgICAgICAgIHJldHVybiAkdHJhbnNsYXRlLmluc3RhbnQoJ2RpYWxvZy5hdWRpdC51cGRhdGVkQmVmb3JlJyk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgcmV0dXJuICR0cmFuc2xhdGUuaW5zdGFudCgnZGlhbG9nLmF1ZGl0LnVwZGF0ZWRBZnRlcicpO1xuICAgICAgICB9XG4gICAgICB9IGVsc2Uge1xuICAgICAgICByZXR1cm4gJHRyYW5zbGF0ZS5pbnN0YW50KCdkaWFsb2cuYXVkaXQuJyArIGF1ZGl0RGV0YWlsLnR5cGUpO1xuICAgICAgfVxuICAgIH07XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5maWx0ZXIoJ2F1ZGl0TW9kZWwnLCBhdWRpdE1vZGVsKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIGF1ZGl0TW9kZWwoJHRyYW5zbGF0ZSkge1xuICAgIHJldHVybiBmdW5jdGlvbiAobW9kZWxJZCkge1xuICAgICAgbW9kZWxJZCA9IG1vZGVsSWQucmVwbGFjZSgnQXBwXFxcXCcsICcnKTtcbiAgICAgIHZhciBtb2RlbCA9ICR0cmFuc2xhdGUuaW5zdGFudCgnbW9kZWxzLicgKyBtb2RlbElkLnRvTG93ZXJDYXNlKCkpO1xuXG4gICAgICByZXR1cm4gbW9kZWwgPyBtb2RlbCA6IG1vZGVsSWQ7XG4gICAgfTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZpbHRlcignYXVkaXRUeXBlJywgYXVkaXRUeXBlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIGF1ZGl0VHlwZShsb2Rhc2gsIEF1ZGl0U2VydmljZSkge1xuICAgIHJldHVybiBmdW5jdGlvbiAodHlwZUlkKSB7XG4gICAgICB2YXIgdHlwZSA9IGxvZGFzaC5maW5kKEF1ZGl0U2VydmljZS5saXN0VHlwZXMoKSwgeyBpZDogdHlwZUlkIH0pO1xuXG4gICAgICByZXR1cm4gdHlwZSA/IHR5cGUubGFiZWwgOiB0eXBlO1xuICAgIH07XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5maWx0ZXIoJ2F1ZGl0VmFsdWUnLCBhdWRpdFZhbHVlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIGF1ZGl0VmFsdWUoJGZpbHRlciwgbG9kYXNoKSB7XG4gICAgcmV0dXJuIGZ1bmN0aW9uICh2YWx1ZSwga2V5KSB7XG4gICAgICBpZiAoYW5ndWxhci5pc0RhdGUodmFsdWUpIHx8IGxvZGFzaC5lbmRzV2l0aChrZXksICdfYXQnKSB8fCBsb2Rhc2guZW5kc1dpdGgoa2V5LCAnX3RvJykpIHtcbiAgICAgICAgcmV0dXJuICRmaWx0ZXIoJ3ByRGF0ZXRpbWUnKSh2YWx1ZSk7XG4gICAgICB9XG5cbiAgICAgIGlmICh0eXBlb2YgdmFsdWUgPT09ICdib29sZWFuJykge1xuICAgICAgICByZXR1cm4gJGZpbHRlcigndHJhbnNsYXRlJykodmFsdWUgPyAnZ2xvYmFsLnllcycgOiAnZ2xvYmFsLm5vJyk7XG4gICAgICB9XG5cbiAgICAgIC8vY2hlY2sgaXMgZmxvYXRcbiAgICAgIGlmIChOdW1iZXIodmFsdWUpID09PSB2YWx1ZSAmJiB2YWx1ZSAlIDEgIT09IDApIHtcbiAgICAgICAgcmV0dXJuICRmaWx0ZXIoJ3JlYWwnKSh2YWx1ZSk7XG4gICAgICB9XG5cbiAgICAgIHJldHVybiB2YWx1ZTtcbiAgICB9O1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4vKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCwgbm8tdW5kZWY6IDAqL1xuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25zdGFudCgncHQtQlIuaTE4bi5hdHRyaWJ1dGVzJywge1xuICAgIGVtYWlsOiAnRW1haWwnLFxuICAgIHBhc3N3b3JkOiAnU2VuaGEnLFxuICAgIG5hbWU6ICdOb21lJyxcbiAgICBpbWFnZTogJ0ltYWdlbScsXG4gICAgcm9sZXM6ICdQZXJmaXMnLFxuICAgIGRhdGU6ICdEYXRhJyxcbiAgICBpbml0aWFsRGF0ZTogJ0RhdGEgSW5pY2lhbCcsXG4gICAgZmluYWxEYXRlOiAnRGF0YSBGaW5hbCcsXG4gICAgYmlydGhkYXk6ICdEYXRhIGRlIE5hc2NpbWVudG8nLFxuICAgIHRhc2s6IHtcbiAgICAgIGRlc2NyaXB0aW9uOiAnRGVzY3Jpw6fDo28nLFxuICAgICAgZG9uZTogJ0ZlaXRvPycsXG4gICAgICBwcmlvcml0eTogJ1ByaW9yaWRhZGUnLFxuICAgICAgc2NoZWR1bGVkX3RvOiAnQWdlbmRhZG8gUGFyYT8nLFxuICAgICAgcHJvamVjdDogJ1Byb2pldG8nLFxuICAgICAgc3RhdHVzOiAnU3RhdHVzJyxcbiAgICAgIHRpdGxlOiAnVMOtdHVsbycsXG4gICAgICB0eXBlOiAnVGlwbycsXG4gICAgICBtaWxlc3RvbmU6ICdTcHJpbnQnLFxuICAgICAgZXN0aW1hdGVkX3RpbWU6ICdUZW1wbyBFc3RpbWFkbydcbiAgICB9LFxuICAgIG1pbGVzdG9uZToge1xuICAgICAgdGl0bGU6ICdUw610dWxvJyxcbiAgICAgIGRlc2NyaXB0aW9uOiAnRGVzY3Jpw6fDo28nLFxuICAgICAgZGF0ZV9zdGFydDogJ0RhdGEgRXN0aW1hZGEgcGFyYSBJbsOtY2lvJyxcbiAgICAgIGRhdGVfZW5kOiAnRGF0YSBFc3RpbWFkYSBwYXJhIEZpbScsXG4gICAgICBlc3RpbWF0ZWRfdGltZTogJ1RlbXBvIEVzdGltYWRvJyxcbiAgICAgIGVzdGltYXRlZF92YWx1ZTogJ1ZhbG9yIEVzdGltYWRvJ1xuICAgIH0sXG4gICAgcHJvamVjdDoge1xuICAgICAgY29zdDogJ0N1c3RvJyxcbiAgICAgIGhvdXJWYWx1ZURldmVsb3BlcjogJ1ZhbG9yIGRhIEhvcmEgRGVzZW52b2x2ZWRvcicsXG4gICAgICBob3VyVmFsdWVDbGllbnQ6ICdWYWxvciBkYSBIb3JhIENsaWVudGUnLFxuICAgICAgaG91clZhbHVlRmluYWw6ICdWYWxvciBkYSBIb3JhIFByb2pldG8nXG4gICAgfSxcbiAgICByZWxlYXNlOiB7XG4gICAgICB0aXRsZTogJ1TDrXR1bG8nLFxuICAgICAgZGVzY3JpcHRpb246ICdEZXNjcmnDp8OjbycsXG4gICAgICByZWxlYXNlX2RhdGU6ICdEYXRhIGRlIEVudHJlZ2EnLFxuICAgICAgbWlsZXN0b25lOiAnTWlsZXN0b25lJyxcbiAgICAgIHRhc2tzOiAnVGFyZWZhcydcbiAgICB9LFxuICAgIC8vw6kgY2FycmVnYWRvIGRvIHNlcnZpZG9yIGNhc28gZXN0ZWphIGRlZmluaWRvIG5vIG1lc21vXG4gICAgYXVkaXRNb2RlbDoge31cbiAgfSk7XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4vKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCwgbm8tdW5kZWY6IDAqL1xuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25zdGFudCgncHQtQlIuaTE4bi5kaWFsb2cnLCB7XG4gICAgY29uZmlybVRpdGxlOiAnQ29uZmlybWHDp8OjbycsXG4gICAgY29uZmlybURlc2NyaXB0aW9uOiAnQ29uZmlybWEgYSBhw6fDo28/JyxcbiAgICByZW1vdmVEZXNjcmlwdGlvbjogJ0Rlc2VqYSByZW1vdmVyIHBlcm1hbmVudGVtZW50ZSB7e25hbWV9fT8nLFxuICAgIGF1ZGl0OiB7XG4gICAgICBjcmVhdGVkOiAnSW5mb3JtYcOnw7VlcyBkbyBDYWRhc3RybycsXG4gICAgICB1cGRhdGVkQmVmb3JlOiAnQW50ZXMgZGEgQXR1YWxpemHDp8OjbycsXG4gICAgICB1cGRhdGVkQWZ0ZXI6ICdEZXBvaXMgZGEgQXR1YWxpemHDp8OjbycsXG4gICAgICBkZWxldGVkOiAnSW5mb3JtYcOnw7VlcyBhbnRlcyBkZSByZW1vdmVyJ1xuICAgIH0sXG4gICAgbG9naW46IHtcbiAgICAgIHJlc2V0UGFzc3dvcmQ6IHtcbiAgICAgICAgZGVzY3JpcHRpb246ICdEaWdpdGUgYWJhaXhvIG8gZW1haWwgY2FkYXN0cmFkbyBubyBzaXN0ZW1hLidcbiAgICAgIH1cbiAgICB9XG4gIH0pO1xufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuLyplc2xpbnQgYW5ndWxhci9maWxlLW5hbWU6IDAsIG5vLXVuZGVmOiAwKi9cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29uc3RhbnQoJ3B0LUJSLmkxOG4uZ2xvYmFsJywge1xuICAgIGxvYWRpbmc6ICdDYXJyZWdhbmRvLi4uJyxcbiAgICBwcm9jZXNzaW5nOiAnUHJvY2Vzc2FuZG8uLi4nLFxuICAgIHllczogJ1NpbScsXG4gICAgbm86ICdOw6NvJyxcbiAgICBhbGw6ICdUb2RvcydcbiAgfSk7XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4vKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCwgbm8tdW5kZWY6IDAqL1xuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25zdGFudCgncHQtQlIuaTE4bi5tZXNzYWdlcycsIHtcbiAgICBpbnRlcm5hbEVycm9yOiAnT2NvcnJldSB1bSBlcnJvIGludGVybm8sIGNvbnRhdGUgbyBhZG1pbmlzdHJhZG9yIGRvIHNpc3RlbWEnLFxuICAgIG5vdEZvdW5kOiAnTmVuaHVtIHJlZ2lzdHJvIGVuY29udHJhZG8nLFxuICAgIG5vdEF1dGhvcml6ZWQ6ICdWb2PDqiBuw6NvIHRlbSBhY2Vzc28gYSBlc3RhIGZ1bmNpb25hbGlkYWRlLicsXG4gICAgc2VhcmNoRXJyb3I6ICdOw6NvIGZvaSBwb3Nzw612ZWwgcmVhbGl6YXIgYSBidXNjYS4nLFxuICAgIHNhdmVTdWNjZXNzOiAnUmVnaXN0cm8gc2Fsdm8gY29tIHN1Y2Vzc28uJyxcbiAgICBvcGVyYXRpb25TdWNjZXNzOiAnT3BlcmHDp8OjbyByZWFsaXphZGEgY29tIHN1Y2Vzc28uJyxcbiAgICBvcGVyYXRpb25FcnJvcjogJ0Vycm8gYW8gcmVhbGl6YXIgYSBvcGVyYcOnw6NvJyxcbiAgICBzYXZlRXJyb3I6ICdFcnJvIGFvIHRlbnRhciBzYWx2YXIgbyByZWdpc3Ryby4nLFxuICAgIHJlbW92ZVN1Y2Nlc3M6ICdSZW1vw6fDo28gcmVhbGl6YWRhIGNvbSBzdWNlc3NvLicsXG4gICAgcmVtb3ZlRXJyb3I6ICdFcnJvIGFvIHRlbnRhciByZW1vdmVyIG8gcmVnaXN0cm8uJyxcbiAgICByZXNvdXJjZU5vdEZvdW5kRXJyb3I6ICdSZWN1cnNvIG7Do28gZW5jb250cmFkbycsXG4gICAgbm90TnVsbEVycm9yOiAnVG9kb3Mgb3MgY2FtcG9zIG9icmlnYXTDs3Jpb3MgZGV2ZW0gc2VyIHByZWVuY2hpZG9zLicsXG4gICAgZHVwbGljYXRlZFJlc291cmNlRXJyb3I6ICdKw6EgZXhpc3RlIHVtIHJlY3Vyc28gY29tIGVzc2FzIGluZm9ybWHDp8O1ZXMuJyxcbiAgICBzcHJpbnRFbmRlZFN1Y2Nlc3M6ICdTcHJpbnQgZmluYWxpemFkYSBjb20gc3VjZXNzbycsXG4gICAgc3ByaW50RW5kZWRFcnJvcjogJ0Vycm8gYW8gZmluYWxpemFyIGEgc3ByaW50JyxcbiAgICBzdWNjZXNzU2lnblVwOiAnQ2FkYXN0cm8gcmVhbGl6YWRvIGNvbSBzdWNlc3NvLiBVbSBlLW1haWwgZm9pIGVudmlhZG8gY29tIHNldXMgZGFkb3MgZGUgbG9naW4nLFxuICAgIGVycm9yc1NpZ25VcDogJ0hvdXZlIHVtIGVycm8gYW8gcmVhbGl6YXIgbyBzZXUgY2FkYXN0cm8uIFRlbnRlIG5vdmFtZW50ZSBtYWlzIHRhcmRlIScsXG4gICAgcmVsZWFzZXRFbmRlZFN1Y2Nlc3M6ICdSZWxlYXNlIGZpbmFsaXphZGEgY29tIHN1Y2Vzc28nLFxuICAgIHJlbGVhc2VFbmRlZEVycm9yOiAnRXJybyBhbyBmaW5hbGl6YXIgYSByZWxlYXNlJyxcbiAgICBwcm9qZWN0RW5kZWRTdWNjZXNzOiAnUHJvamV0byBmaW5hbGl6YWRvIGNvbSBzdWNlc3NvJyxcbiAgICBwcm9qZWN0RW5kZWRFcnJvcjogJ0Vycm8gYW8gZmluYWxpemFyIG8gcHJvamV0bycsXG4gICAgdmFsaWRhdGU6IHtcbiAgICAgIGZpZWxkUmVxdWlyZWQ6ICdPIGNhbXBvIHt7ZmllbGR9fSDDqSBvYnJpZ3JhdMOzcmlvLidcbiAgICB9LFxuICAgIGxheW91dDoge1xuICAgICAgZXJyb3I0MDQ6ICdQw6FnaW5hIG7Do28gZW5jb250cmFkYSdcbiAgICB9LFxuICAgIGxvZ2luOiB7XG4gICAgICBsb2dvdXRJbmFjdGl2ZTogJ1ZvY8OqIGZvaSBkZXNsb2dhZG8gZG8gc2lzdGVtYSBwb3IgaW5hdGl2aWRhZGUuIEZhdm9yIGVudHJhciBubyBzaXN0ZW1hIG5vdmFtZW50ZS4nLFxuICAgICAgaW52YWxpZENyZWRlbnRpYWxzOiAnQ3JlZGVuY2lhaXMgSW52w6FsaWRhcycsXG4gICAgICB1bmtub3duRXJyb3I6ICdOw6NvIGZvaSBwb3Nzw612ZWwgcmVhbGl6YXIgbyBsb2dpbi4gVGVudGUgbm92YW1lbnRlLiAnICsgJ0Nhc28gbsOjbyBjb25zaWdhIGZhdm9yIGVuY29udHJhciBlbSBjb250YXRvIGNvbSBvIGFkbWluaXN0cmFkb3IgZG8gc2lzdGVtYS4nLFxuICAgICAgdXNlck5vdEZvdW5kOiAnTsOjbyBmb2kgcG9zc8OtdmVsIGVuY29udHJhciBzZXVzIGRhZG9zJ1xuICAgIH0sXG4gICAgZGFzaGJvYXJkOiB7XG4gICAgICB3ZWxjb21lOiAnU2VqYSBiZW0gVmluZG8ge3t1c2VyTmFtZX19JyxcbiAgICAgIGRlc2NyaXB0aW9uOiAnVXRpbGl6ZSBvIG1lbnUgcGFyYSBuYXZlZ2HDp8Ojby4nXG4gICAgfSxcbiAgICBtYWlsOiB7XG4gICAgICBtYWlsRXJyb3JzOiAnT2NvcnJldSB1bSBlcnJvIG5vcyBzZWd1aW50ZXMgZW1haWxzIGFiYWl4bzpcXG4nLFxuICAgICAgc2VuZE1haWxTdWNjZXNzOiAnRW1haWwgZW52aWFkbyBjb20gc3VjZXNzbyEnLFxuICAgICAgc2VuZE1haWxFcnJvcjogJ07Do28gZm9pIHBvc3PDrXZlbCBlbnZpYXIgbyBlbWFpbC4nLFxuICAgICAgcGFzc3dvcmRTZW5kaW5nU3VjY2VzczogJ08gcHJvY2Vzc28gZGUgcmVjdXBlcmHDp8OjbyBkZSBzZW5oYSBmb2kgaW5pY2lhZG8uIENhc28gbyBlbWFpbCBuw6NvIGNoZWd1ZSBlbSAxMCBtaW51dG9zIHRlbnRlIG5vdmFtZW50ZS4nXG4gICAgfSxcbiAgICB1c2VyOiB7XG4gICAgICByZW1vdmVZb3VyU2VsZkVycm9yOiAnVm9jw6ogbsOjbyBwb2RlIHJlbW92ZXIgc2V1IHByw7NwcmlvIHVzdcOhcmlvJyxcbiAgICAgIHVzZXJFeGlzdHM6ICdVc3XDoXJpbyBqw6EgYWRpY2lvbmFkbyEnLFxuICAgICAgcHJvZmlsZToge1xuICAgICAgICB1cGRhdGVFcnJvcjogJ07Do28gZm9pIHBvc3PDrXZlbCBhdHVhbGl6YXIgc2V1IHByb2ZpbGUnXG4gICAgICB9XG4gICAgfSxcbiAgICBxdWVyeURpbmFtaWM6IHtcbiAgICAgIG5vRmlsdGVyOiAnTmVuaHVtIGZpbHRybyBhZGljaW9uYWRvJ1xuICAgIH1cbiAgfSk7XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4vKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCwgbm8tdW5kZWY6IDAqL1xuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25zdGFudCgncHQtQlIuaTE4bi5tb2RlbHMnLCB7XG4gICAgdXNlcjogJ1VzdcOhcmlvJyxcbiAgICB0YXNrOiAnVGFyZWZhJyxcbiAgICBwcm9qZWN0OiAnUHJvamV0bydcbiAgfSk7XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4vKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCwgbm8tdW5kZWY6IDAqL1xuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25zdGFudCgncHQtQlIuaTE4bi52aWV3cycsIHtcbiAgICBicmVhZGNydW1iczoge1xuICAgICAgdXNlcjogJ0FkbWluaXN0cmHDp8OjbyAtIFVzdcOhcmlvJyxcbiAgICAgICd1c2VyLXByb2ZpbGUnOiAnUGVyZmlsJyxcbiAgICAgIGRhc2hib2FyZDogJ0Rhc2hib2FyZCcsXG4gICAgICBhdWRpdDogJ0FkbWluaXN0cmHDp8OjbyAtIEF1ZGl0b3JpYScsXG4gICAgICBtYWlsOiAnQWRtaW5pc3RyYcOnw6NvIC0gRW52aW8gZGUgZS1tYWlsJyxcbiAgICAgIHByb2plY3RzOiAnUHJvamV0b3MnLFxuICAgICAgJ2RpbmFtaWMtcXVlcnknOiAnQWRtaW5pc3RyYcOnw6NvIC0gQ29uc3VsdGFzIERpbsOibWljYXMnLFxuICAgICAgJ25vdC1hdXRob3JpemVkJzogJ0FjZXNzbyBOZWdhZG8nLFxuICAgICAgdGFza3M6ICdUYXJlZmFzJyxcbiAgICAgIG1pbGVzdG9uZXM6ICdTcHJpbnRzJyxcbiAgICAgIGthbmJhbjogJ0thbmJhbiBCb2FyZCcsXG4gICAgICB2Y3M6ICdDb250cm9sZSBkZSBWZXJzw6NvJyxcbiAgICAgIHJlbGVhc2VzOiAnUmVsZWFzZXMnXG4gICAgfSxcbiAgICB0aXRsZXM6IHtcbiAgICAgIGRhc2hib2FyZDogJ0Rhc2hib2FyZCcsXG4gICAgICBtYWlsU2VuZDogJ0VudmlhciBlLW1haWwnLFxuICAgICAgdGFza0xpc3Q6ICdMaXN0YSBkZSBUYXJlZmFzJyxcbiAgICAgIHVzZXJMaXN0OiAnTGlzdGEgZGUgVXN1w6FyaW9zJyxcbiAgICAgIGF1ZGl0TGlzdDogJ0xpc3RhIGRlIExvZ3MnLFxuICAgICAgcmVnaXN0ZXI6ICdGb3JtdWzDoXJpbyBkZSBDYWRhc3RybycsXG4gICAgICByZXNldFBhc3N3b3JkOiAnUmVkZWZpbmlyIFNlbmhhJyxcbiAgICAgIHVwZGF0ZTogJ0Zvcm11bMOhcmlvIGRlIEF0dWFsaXphw6fDo28nLFxuICAgICAgdGFza3M6ICdUYXJlZmFzJyxcbiAgICAgIG1pbGVzdG9uZXM6ICdTcHJpbnRzJyxcbiAgICAgIGthbmJhbjogJ0thbmJhbiBCb2FyZCcsXG4gICAgICB2Y3M6ICdDb250cm9sZSBkZSBWZXJzw6NvJyxcbiAgICAgIHJlbGVhc2VzOiAnUmVsZWFzZXMnXG4gICAgfSxcbiAgICBhY3Rpb25zOiB7XG4gICAgICBzZW5kOiAnRW52aWFyJyxcbiAgICAgIHNhdmU6ICdTYWx2YXInLFxuICAgICAgY2xlYXI6ICdMaW1wYXInLFxuICAgICAgY2xlYXJBbGw6ICdMaW1wYXIgVHVkbycsXG4gICAgICByZXN0YXJ0OiAnUmVpbmljaWFyJyxcbiAgICAgIGZpbHRlcjogJ0ZpbHRyYXInLFxuICAgICAgc2VhcmNoOiAnUGVzcXVpc2FyJyxcbiAgICAgIGxpc3Q6ICdMaXN0YXInLFxuICAgICAgZWRpdDogJ0VkaXRhcicsXG4gICAgICBjYW5jZWw6ICdDYW5jZWxhcicsXG4gICAgICB1cGRhdGU6ICdBdHVhbGl6YXInLFxuICAgICAgcmVtb3ZlOiAnUmVtb3ZlcicsXG4gICAgICBnZXRPdXQ6ICdTYWlyJyxcbiAgICAgIGFkZDogJ0FkaWNpb25hcicsXG4gICAgICBpbjogJ0VudHJhcicsXG4gICAgICBsb2FkSW1hZ2U6ICdDYXJyZWdhciBJbWFnZW0nLFxuICAgICAgc2lnbnVwOiAnQ2FkYXN0cmFyJyxcbiAgICAgIGNyaWFyUHJvamV0bzogJ0NyaWFyIFByb2pldG8nLFxuICAgICAgcHJvamVjdExpc3Q6ICdMaXN0YSBkZSBQcm9qZXRvcycsXG4gICAgICB0YXNrc0xpc3Q6ICdMaXN0YSBkZSBUYXJlZmFzJyxcbiAgICAgIG1pbGVzdG9uZXNMaXN0OiAnTGlzdGEgZGUgU3ByaW50cycsXG4gICAgICBmaW5hbGl6ZTogJ0ZpbmFsaXphcicsXG4gICAgICByZXBseTogJ1Jlc3BvbmRlcidcbiAgICB9LFxuICAgIGZpZWxkczoge1xuICAgICAgZGF0ZTogJ0RhdGEnLFxuICAgICAgYWN0aW9uOiAnQcOnw6NvJyxcbiAgICAgIGFjdGlvbnM6ICdBw6fDtWVzJyxcbiAgICAgIGF1ZGl0OiB7XG4gICAgICAgIGRhdGVTdGFydDogJ0RhdGEgSW5pY2lhbCcsXG4gICAgICAgIGRhdGVFbmQ6ICdEYXRhIEZpbmFsJyxcbiAgICAgICAgcmVzb3VyY2U6ICdSZWN1cnNvJyxcbiAgICAgICAgYWxsUmVzb3VyY2VzOiAnVG9kb3MgUmVjdXJzb3MnLFxuICAgICAgICB0eXBlOiB7XG4gICAgICAgICAgY3JlYXRlZDogJ0NhZGFzdHJhZG8nLFxuICAgICAgICAgIHVwZGF0ZWQ6ICdBdHVhbGl6YWRvJyxcbiAgICAgICAgICBkZWxldGVkOiAnUmVtb3ZpZG8nXG4gICAgICAgIH1cbiAgICAgIH0sXG4gICAgICBsb2dpbjoge1xuICAgICAgICByZXNldFBhc3N3b3JkOiAnRXNxdWVjaSBtaW5oYSBzZW5oYScsXG4gICAgICAgIGNvbmZpcm1QYXNzd29yZDogJ0NvbmZpcm1hciBzZW5oYSdcbiAgICAgIH0sXG4gICAgICBtYWlsOiB7XG4gICAgICAgIHRvOiAnUGFyYScsXG4gICAgICAgIHN1YmplY3Q6ICdBc3N1bnRvJyxcbiAgICAgICAgbWVzc2FnZTogJ01lbnNhZ2VtJ1xuICAgICAgfSxcbiAgICAgIHF1ZXJ5RGluYW1pYzoge1xuICAgICAgICBmaWx0ZXJzOiAnRmlsdHJvcycsXG4gICAgICAgIHJlc3VsdHM6ICdSZXN1bHRhZG9zJyxcbiAgICAgICAgbW9kZWw6ICdNb2RlbCcsXG4gICAgICAgIGF0dHJpYnV0ZTogJ0F0cmlidXRvJyxcbiAgICAgICAgb3BlcmF0b3I6ICdPcGVyYWRvcicsXG4gICAgICAgIHJlc291cmNlOiAnUmVjdXJzbycsXG4gICAgICAgIHZhbHVlOiAnVmFsb3InLFxuICAgICAgICBvcGVyYXRvcnM6IHtcbiAgICAgICAgICBlcXVhbHM6ICdJZ3VhbCcsXG4gICAgICAgICAgZGlmZXJlbnQ6ICdEaWZlcmVudGUnLFxuICAgICAgICAgIGNvbnRlaW5zOiAnQ29udMOpbScsXG4gICAgICAgICAgc3RhcnRXaXRoOiAnSW5pY2lhIGNvbScsXG4gICAgICAgICAgZmluaXNoV2l0aDogJ0ZpbmFsaXphIGNvbScsXG4gICAgICAgICAgYmlnZ2VyVGhhbjogJ01haW9yJyxcbiAgICAgICAgICBlcXVhbHNPckJpZ2dlclRoYW46ICdNYWlvciBvdSBJZ3VhbCcsXG4gICAgICAgICAgbGVzc1RoYW46ICdNZW5vcicsXG4gICAgICAgICAgZXF1YWxzT3JMZXNzVGhhbjogJ01lbm9yIG91IElndWFsJ1xuICAgICAgICB9XG4gICAgICB9LFxuICAgICAgcHJvamVjdDoge1xuICAgICAgICBuYW1lOiAnTm9tZScsXG4gICAgICAgIHRvdGFsVGFzazogJ1RvdGFsIGRlIFRhcmVmYXMnXG4gICAgICB9LFxuICAgICAgdGFzazoge1xuICAgICAgICBkb25lOiAnTsOjbyBGZWl0byAvIEZlaXRvJ1xuICAgICAgfSxcbiAgICAgIHVzZXI6IHtcbiAgICAgICAgcGVyZmlsczogJ1BlcmZpcycsXG4gICAgICAgIG5hbWVPckVtYWlsOiAnTm9tZSBvdSBFbWFpbCdcbiAgICAgIH1cbiAgICB9LFxuICAgIGxheW91dDoge1xuICAgICAgbWVudToge1xuICAgICAgICBwcm9qZWN0czogJ1Byb2pldG9zJyxcbiAgICAgICAgZGFzaGJvYXJkOiAnRGFzaGJvYXJkJyxcbiAgICAgICAgbWlsZXN0b25lczogJ1NwcmludHMnLFxuICAgICAgICB0YXNrczogJ1RhcmVmYXMnLFxuICAgICAgICBrYW5iYW46ICdLYW5iYW4nLFxuICAgICAgICB2Y3M6ICdDb250cm9sZSBkZSBWZXJzw6NvJyxcbiAgICAgICAgcmVsZWFzZXM6ICdSZWxlYXNlcydcbiAgICAgIH1cbiAgICB9LFxuICAgIHRvb2x0aXBzOiB7XG4gICAgICBhdWRpdDoge1xuICAgICAgICB2aWV3RGV0YWlsOiAnVmlzdWFsaXphciBEZXRhbGhhbWVudG8nXG4gICAgICB9LFxuICAgICAgdXNlcjoge1xuICAgICAgICBwZXJmaWw6ICdQZXJmaWwnLFxuICAgICAgICB0cmFuc2ZlcjogJ1RyYW5zZmVyaXInXG4gICAgICB9LFxuICAgICAgdGFzazoge1xuICAgICAgICBsaXN0VGFzazogJ0xpc3RhciBUYXJlZmFzJ1xuICAgICAgfVxuICAgIH1cbiAgfSk7XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29udHJvbGxlcignVGFza0luZm9Db250cm9sbGVyJywgVGFza0luZm9Db250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIFRhc2tJbmZvQ29udHJvbGxlcigkY29udHJvbGxlciwgVGFza3NTZXJ2aWNlLCBsb2NhbHMpIHtcbiAgICAvL0F0dHJpYnV0ZXMgQmxvY2tcbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0uY2xvc2VEaWFsb2cgPSBjbG9zZURpYWxvZztcblxuICAgIHZtLm9uQWN0aXZhdGUgPSBmdW5jdGlvbiAoKSB7XG4gICAgICB2bS50YXNrID0gbG9jYWxzLnRhc2s7XG4gICAgICB2bS50YXNrLmVzdGltYXRlZF90aW1lID0gdm0udGFzay5lc3RpbWF0ZWRfdGltZS50b1N0cmluZygpICsgJyBob3Jhcyc7XG4gICAgfTtcblxuICAgIGZ1bmN0aW9uIGNsb3NlRGlhbG9nKCkge1xuICAgICAgdm0uY2xvc2UoKTtcbiAgICAgIGNvbnNvbGUubG9nKFwiZmVjaGFyXCIpO1xuICAgIH1cblxuICAgIC8vIGluc3RhbnRpYXRlIGJhc2UgY29udHJvbGxlclxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHsgdm06IHZtLCBtb2RlbFNlcnZpY2U6IFRhc2tzU2VydmljZSwgb3B0aW9uczoge30gfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb250cm9sbGVyKCdVc2Vyc0RpYWxvZ0NvbnRyb2xsZXInLCBVc2Vyc0RpYWxvZ0NvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gVXNlcnNEaWFsb2dDb250cm9sbGVyKCRjb250cm9sbGVyLCBVc2Vyc1NlcnZpY2UsIFByRGlhbG9nLCAvLyBOT1NPTkFSXG4gIHVzZXJEaWFsb2dJbnB1dCwgb25Jbml0KSB7XG5cbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0ub25BY3RpdmF0ZSA9IG9uQWN0aXZhdGU7XG4gICAgdm0uYXBwbHlGaWx0ZXJzID0gYXBwbHlGaWx0ZXJzO1xuICAgIHZtLmNsb3NlID0gY2xvc2U7XG5cbiAgICBpZiAoYW5ndWxhci5pc0RlZmluZWQodXNlckRpYWxvZ0lucHV0KSkge1xuICAgICAgdm0udHJhbnNmZXJVc2VyID0gdXNlckRpYWxvZ0lucHV0LnRyYW5zZmVyVXNlckZuO1xuICAgIH1cblxuICAgIC8vIGluc3RhbnRpYXRlIGJhc2UgY29udHJvbGxlclxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHtcbiAgICAgIHZtOiB2bSxcbiAgICAgIG1vZGVsU2VydmljZTogVXNlcnNTZXJ2aWNlLFxuICAgICAgc2VhcmNoT25Jbml0OiBvbkluaXQsXG4gICAgICBvcHRpb25zOiB7XG4gICAgICAgIHBlclBhZ2U6IDVcbiAgICAgIH1cbiAgICB9KTtcblxuICAgIGZ1bmN0aW9uIG9uQWN0aXZhdGUoKSB7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMgPSB7fTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBhcHBseUZpbHRlcnMoKSB7XG4gICAgICByZXR1cm4gYW5ndWxhci5leHRlbmQodm0uZGVmYXVsdFF1ZXJ5RmlsdGVycywgdm0ucXVlcnlGaWx0ZXJzKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBjbG9zZSgpIHtcbiAgICAgIFByRGlhbG9nLmNsb3NlKCk7XG4gICAgfVxuICB9XG59KSgpOyIsIi8qZXNsaW50IGFuZ3VsYXIvZmlsZS1uYW1lOiAwKi9cbihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnLCBbXG4gICAgJ25nQW5pbWF0ZScsXG4gICAgJ25nQXJpYScsXG4gICAgJ3VpLnJvdXRlcicsXG4gICAgJ25nUHJvZGViJyxcbiAgICAndWkudXRpbHMubWFza3MnLFxuICAgICd0ZXh0LW1hc2snLFxuICAgICduZ01hdGVyaWFsJyxcbiAgICAnbW9kZWxGYWN0b3J5JyxcbiAgICAnbWQuZGF0YS50YWJsZScsXG4gICAgJ25nTWF0ZXJpYWxEYXRlUGlja2VyJyxcbiAgICAncGFzY2FscHJlY2h0LnRyYW5zbGF0ZScsXG4gICAgJ2FuZ3VsYXJGaWxlVXBsb2FkJyxcbiAgICAnbmdNZXNzYWdlcycsXG4gICAgJ2pxd2lkZ2V0cycsXG4gICAgJ3VpLm1hc2snLFxuICAgICduZ1JvdXRlJ10pO1xufSkoKTtcbiIsIihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uZmlnKGNvbmZpZyk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBjb25maWcoR2xvYmFsLCAkbWRUaGVtaW5nUHJvdmlkZXIsICRtb2RlbEZhY3RvcnlQcm92aWRlciwgIC8vIE5PU09OQVJcbiAgICAkdHJhbnNsYXRlUHJvdmlkZXIsIG1vbWVudCwgJG1kQXJpYVByb3ZpZGVyLCAkbWREYXRlTG9jYWxlUHJvdmlkZXIpIHtcblxuICAgICR0cmFuc2xhdGVQcm92aWRlclxuICAgICAgLnVzZUxvYWRlcignbGFuZ3VhZ2VMb2FkZXInKVxuICAgICAgLnVzZVNhbml0aXplVmFsdWVTdHJhdGVneSgnZXNjYXBlJyk7XG5cbiAgICAkdHJhbnNsYXRlUHJvdmlkZXIudXNlUG9zdENvbXBpbGluZyh0cnVlKTtcblxuICAgIG1vbWVudC5sb2NhbGUoJ3B0LUJSJyk7XG5cbiAgICAvL29zIHNlcnZpw6dvcyByZWZlcmVudGUgYW9zIG1vZGVscyB2YWkgdXRpbGl6YXIgY29tbyBiYXNlIG5hcyB1cmxzXG4gICAgJG1vZGVsRmFjdG9yeVByb3ZpZGVyLmRlZmF1bHRPcHRpb25zLnByZWZpeCA9IEdsb2JhbC5hcGlQYXRoO1xuXG4gICAgLy8gQ29uZmlndXJhdGlvbiB0aGVtZVxuICAgICRtZFRoZW1pbmdQcm92aWRlci50aGVtZSgnZGVmYXVsdCcpXG4gICAgICAucHJpbWFyeVBhbGV0dGUoJ2dyZXknLCB7XG4gICAgICAgIGRlZmF1bHQ6ICc4MDAnXG4gICAgICB9KVxuICAgICAgLmFjY2VudFBhbGV0dGUoJ2FtYmVyJylcbiAgICAgIC53YXJuUGFsZXR0ZSgnZGVlcC1vcmFuZ2UnKTtcblxuICAgIC8vIEVuYWJsZSBicm93c2VyIGNvbG9yXG4gICAgJG1kVGhlbWluZ1Byb3ZpZGVyLmVuYWJsZUJyb3dzZXJDb2xvcigpO1xuXG4gICAgJG1kQXJpYVByb3ZpZGVyLmRpc2FibGVXYXJuaW5ncygpO1xuXG4gICAgJG1kRGF0ZUxvY2FsZVByb3ZpZGVyLmZvcm1hdERhdGUgPSBmdW5jdGlvbihkYXRlKSB7XG4gICAgICByZXR1cm4gZGF0ZSA/IG1vbWVudChkYXRlKS5mb3JtYXQoJ0REL01NL1lZWVknKSA6ICcnO1xuICAgIH07XG4gIH1cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb250cm9sbGVyKCdBcHBDb250cm9sbGVyJywgQXBwQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvKipcbiAgICogQ29udHJvbGFkb3IgcmVzcG9uc8OhdmVsIHBvciBmdW5jaW9uYWxpZGFkZXMgcXVlIHPDo28gYWNpb25hZGFzIGVtIHF1YWxxdWVyIHRlbGEgZG8gc2lzdGVtYVxuICAgKlxuICAgKi9cbiAgZnVuY3Rpb24gQXBwQ29udHJvbGxlcigkc3RhdGUsIEF1dGgsIEdsb2JhbCkge1xuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICAvL2FubyBhdHVhbCBwYXJhIHNlciBleGliaWRvIG5vIHJvZGFww6kgZG8gc2lzdGVtYVxuICAgIHZtLmFub0F0dWFsID0gbnVsbDtcbiAgICB2bS5hY3RpdmVQcm9qZWN0ID0gbnVsbDtcblxuICAgIHZtLmxvZ291dCAgICAgPSBsb2dvdXQ7XG4gICAgdm0uZ2V0SW1hZ2VQZXJmaWwgPSBnZXRJbWFnZVBlcmZpbDtcbiAgICB2bS5nZXRMb2dvTWVudSA9IGdldExvZ29NZW51O1xuICAgIHZtLnNldEFjdGl2ZVByb2plY3QgPSBzZXRBY3RpdmVQcm9qZWN0O1xuICAgIHZtLmdldEFjdGl2ZVByb2plY3QgPSBnZXRBY3RpdmVQcm9qZWN0O1xuICAgIHZtLnJlbW92ZUFjdGl2ZVByb2plY3QgPSByZW1vdmVBY3RpdmVQcm9qZWN0O1xuXG4gICAgYWN0aXZhdGUoKTtcblxuICAgIGZ1bmN0aW9uIGFjdGl2YXRlKCkge1xuICAgICAgdmFyIGRhdGUgPSBuZXcgRGF0ZSgpO1xuXG4gICAgICB2bS5hbm9BdHVhbCA9IGRhdGUuZ2V0RnVsbFllYXIoKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBsb2dvdXQoKSB7XG4gICAgICBBdXRoLmxvZ291dCgpLnRoZW4oZnVuY3Rpb24oKSB7XG4gICAgICAgICRzdGF0ZS5nbyhHbG9iYWwubG9naW5TdGF0ZSk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBnZXRJbWFnZVBlcmZpbCgpIHtcbiAgICAgIHJldHVybiAoQXV0aC5jdXJyZW50VXNlciAmJiBBdXRoLmN1cnJlbnRVc2VyLmltYWdlKVxuICAgICAgICA/IEF1dGguY3VycmVudFVzZXIuaW1hZ2VcbiAgICAgICAgOiBHbG9iYWwuaW1hZ2VQYXRoICsgJy9ub19hdmF0YXIuZ2lmJztcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBnZXRMb2dvTWVudSgpIHtcbiAgICAgIHJldHVybiBHbG9iYWwuaW1hZ2VQYXRoICsgJy9sb2dvLXZlcnRpY2FsLnBuZyc7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gc2V0QWN0aXZlUHJvamVjdChwcm9qZWN0KSB7XG4gICAgICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbSgncHJvamVjdCcsIHByb2plY3QpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGdldEFjdGl2ZVByb2plY3QoKSB7XG4gICAgICByZXR1cm4gbG9jYWxTdG9yYWdlLmdldEl0ZW0oJ3Byb2plY3QnKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiByZW1vdmVBY3RpdmVQcm9qZWN0KCkge1xuICAgICAgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oJ3Byb2plY3QnKTtcbiAgICB9XG5cbiAgfVxuXG59KSgpO1xuIiwiLyplc2xpbnQgYW5ndWxhci9maWxlLW5hbWU6IDAsIG5vLXVuZGVmOiAwKi9cbihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIC8qKlxuICAgKiBUcmFuc2Zvcm1hIGJpYmxpb3RlY2FzIGV4dGVybmFzIGVtIHNlcnZpw6dvcyBkbyBhbmd1bGFyIHBhcmEgc2VyIHBvc3PDrXZlbCB1dGlsaXphclxuICAgKiBhdHJhdsOpcyBkYSBpbmplw6fDo28gZGUgZGVwZW5kw6puY2lhXG4gICAqL1xuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uc3RhbnQoJ2xvZGFzaCcsIF8pXG4gICAgLmNvbnN0YW50KCdtb21lbnQnLCBtb21lbnQpO1xuXG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnN0YW50KCdHbG9iYWwnLCB7XG4gICAgICBhcHBOYW1lOiAnRnJlZWxhZ2lsZScsXG4gICAgICBob21lU3RhdGU6ICdhcHAucHJvamVjdHMnLFxuICAgICAgbG9naW5Vcmw6ICdhcHAvbG9naW4nLFxuICAgICAgcmVzZXRQYXNzd29yZFVybDogJ2FwcC9wYXNzd29yZC9yZXNldCcsXG4gICAgICBsb2dpblN0YXRlOiAnYXBwLmxvZ2luJyxcbiAgICAgIHJlc2V0UGFzc3dvcmRTdGF0ZTogJ2FwcC5wYXNzd29yZC1yZXNldCcsXG4gICAgICBub3RBdXRob3JpemVkU3RhdGU6ICdhcHAubm90LWF1dGhvcml6ZWQnLFxuICAgICAgdG9rZW5LZXk6ICdzZXJ2ZXJfdG9rZW4nLFxuICAgICAgY2xpZW50UGF0aDogJ2NsaWVudC9hcHAnLFxuICAgICAgYXBpUGF0aDogJ2FwaS92MScsXG4gICAgICBpbWFnZVBhdGg6ICdjbGllbnQvaW1hZ2VzJ1xuICAgIH0pO1xufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb25maWcocm91dGVzKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvdXRlcygkc3RhdGVQcm92aWRlciwgJHVybFJvdXRlclByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlclxuICAgICAgLnN0YXRlKCdhcHAnLCB7XG4gICAgICAgIHVybDogJy9hcHAnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL2xheW91dC9hcHAuaHRtbCcsXG4gICAgICAgIGFic3RyYWN0OiB0cnVlLFxuICAgICAgICByZXNvbHZlOiB7IC8vZW5zdXJlIGxhbmdzIGlzIHJlYWR5IGJlZm9yZSByZW5kZXIgdmlld1xuICAgICAgICAgIHRyYW5zbGF0ZVJlYWR5OiBbJyR0cmFuc2xhdGUnLCAnJHEnLCBmdW5jdGlvbigkdHJhbnNsYXRlLCAkcSkge1xuICAgICAgICAgICAgdmFyIGRlZmVycmVkID0gJHEuZGVmZXIoKTtcblxuICAgICAgICAgICAgJHRyYW5zbGF0ZS51c2UoJ3B0LUJSJykudGhlbihmdW5jdGlvbigpIHtcbiAgICAgICAgICAgICAgZGVmZXJyZWQucmVzb2x2ZSgpO1xuICAgICAgICAgICAgfSk7XG5cbiAgICAgICAgICAgIHJldHVybiBkZWZlcnJlZC5wcm9taXNlO1xuICAgICAgICAgIH1dXG4gICAgICAgIH1cbiAgICAgIH0pXG4gICAgICAuc3RhdGUoR2xvYmFsLm5vdEF1dGhvcml6ZWRTdGF0ZSwge1xuICAgICAgICB1cmw6ICcvYWNlc3NvLW5lZ2FkbycsXG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvbGF5b3V0L25vdC1hdXRob3JpemVkLmh0bWwnLFxuICAgICAgICBkYXRhOiB7IG5lZWRBdXRoZW50aWNhdGlvbjogZmFsc2UgfVxuICAgICAgfSk7XG5cbiAgICAkdXJsUm91dGVyUHJvdmlkZXIud2hlbignL3Bhc3N3b3JkL3Jlc2V0JywgR2xvYmFsLnJlc2V0UGFzc3dvcmRVcmwpO1xuICAgICR1cmxSb3V0ZXJQcm92aWRlci53aGVuKCcvYXBwJywgR2xvYmFsLmxvZ2luVXJsKTtcbiAgICAkdXJsUm91dGVyUHJvdmlkZXIub3RoZXJ3aXNlKEdsb2JhbC5sb2dpblVybCk7XG4gIH1cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAucnVuKHJ1bik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBydW4oJHJvb3RTY29wZSwgJHN0YXRlLCAkc3RhdGVQYXJhbXMsIEF1dGgsIEdsb2JhbCkgeyAvLyBOT1NPTkFSXG4gICAgLy9zZXRhZG8gbm8gcm9vdFNjb3BlIHBhcmEgcG9kZXIgc2VyIGFjZXNzYWRvIG5hcyB2aWV3cyBzZW0gcHJlZml4byBkZSBjb250cm9sbGVyXG4gICAgJHJvb3RTY29wZS4kc3RhdGUgPSAkc3RhdGU7XG4gICAgJHJvb3RTY29wZS4kc3RhdGVQYXJhbXMgPSAkc3RhdGVQYXJhbXM7XG4gICAgJHJvb3RTY29wZS5hdXRoID0gQXV0aDtcbiAgICAkcm9vdFNjb3BlLmdsb2JhbCA9IEdsb2JhbDtcblxuICAgIC8vbm8gaW5pY2lvIGNhcnJlZ2EgbyB1c3XDoXJpbyBkbyBsb2NhbHN0b3JhZ2UgY2FzbyBvIHVzdcOhcmlvIGVzdGFqYSBhYnJpbmRvIG8gbmF2ZWdhZG9yXG4gICAgLy9wYXJhIHZvbHRhciBhdXRlbnRpY2Fkb1xuICAgIEF1dGgucmV0cmlldmVVc2VyRnJvbUxvY2FsU3RvcmFnZSgpO1xuICB9XG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29udHJvbGxlcignQXVkaXRDb250cm9sbGVyJywgQXVkaXRDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIEF1ZGl0Q29udHJvbGxlcigkY29udHJvbGxlciwgQXVkaXRTZXJ2aWNlLCBQckRpYWxvZywgR2xvYmFsLCAkdHJhbnNsYXRlKSB7IC8vIE5PU09OQVJcbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0ub25BY3RpdmF0ZSA9IG9uQWN0aXZhdGU7XG4gICAgdm0uYXBwbHlGaWx0ZXJzID0gYXBwbHlGaWx0ZXJzO1xuICAgIHZtLnZpZXdEZXRhaWwgPSB2aWV3RGV0YWlsO1xuXG4gICAgJGNvbnRyb2xsZXIoJ0NSVURDb250cm9sbGVyJywgeyB2bTogdm0sIG1vZGVsU2VydmljZTogQXVkaXRTZXJ2aWNlLCBvcHRpb25zOiB7fSB9KTtcblxuICAgIGZ1bmN0aW9uIG9uQWN0aXZhdGUoKSB7XG4gICAgICB2bS5tb2RlbHMgPSBbXTtcbiAgICAgIHZtLnF1ZXJ5RmlsdGVycyA9IHt9O1xuXG4gICAgICAvL1BlZ2EgdG9kb3Mgb3MgbW9kZWxzIGRvIHNlcnZlciBlIG1vbnRhIHVtYSBsaXN0YSBwcm8gQ29tYm9Cb3hcbiAgICAgIEF1ZGl0U2VydmljZS5nZXRBdWRpdGVkTW9kZWxzKCkudGhlbihmdW5jdGlvbihkYXRhKSB7XG4gICAgICAgIHZhciBtb2RlbHMgPSBbeyBpZDogJycsIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ2dsb2JhbC5hbGwnKSB9XTtcblxuICAgICAgICBkYXRhLm1vZGVscy5zb3J0KCk7XG5cbiAgICAgICAgZm9yICh2YXIgaW5kZXggPSAwOyBpbmRleCA8IGRhdGEubW9kZWxzLmxlbmd0aDsgaW5kZXgrKykge1xuICAgICAgICAgIHZhciBtb2RlbCA9IGRhdGEubW9kZWxzW2luZGV4XTtcblxuICAgICAgICAgIG1vZGVscy5wdXNoKHtcbiAgICAgICAgICAgIGlkOiBtb2RlbCxcbiAgICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ21vZGVscy4nICsgbW9kZWwudG9Mb3dlckNhc2UoKSlcbiAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHZtLm1vZGVscyA9IG1vZGVscztcbiAgICAgICAgdm0ucXVlcnlGaWx0ZXJzLm1vZGVsID0gdm0ubW9kZWxzWzBdLmlkO1xuICAgICAgfSk7XG5cbiAgICAgIHZtLnR5cGVzID0gQXVkaXRTZXJ2aWNlLmxpc3RUeXBlcygpO1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzLnR5cGUgPSB2bS50eXBlc1swXS5pZDtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBhcHBseUZpbHRlcnMoZGVmYXVsdFF1ZXJ5RmlsdGVycykge1xuICAgICAgcmV0dXJuIGFuZ3VsYXIuZXh0ZW5kKGRlZmF1bHRRdWVyeUZpbHRlcnMsIHZtLnF1ZXJ5RmlsdGVycyk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gdmlld0RldGFpbChhdWRpdERldGFpbCkge1xuICAgICAgdmFyIGNvbmZpZyA9IHtcbiAgICAgICAgbG9jYWxzOiB7IGF1ZGl0RGV0YWlsOiBhdWRpdERldGFpbCB9LFxuICAgICAgICAvKiogQG5nSW5qZWN0ICovXG4gICAgICAgIGNvbnRyb2xsZXI6IGZ1bmN0aW9uKGF1ZGl0RGV0YWlsLCBQckRpYWxvZykge1xuICAgICAgICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICAgICAgICB2bS5jbG9zZSA9IGNsb3NlO1xuXG4gICAgICAgICAgYWN0aXZhdGUoKTtcblxuICAgICAgICAgIGZ1bmN0aW9uIGFjdGl2YXRlKCkge1xuICAgICAgICAgICAgaWYgKGFuZ3VsYXIuaXNBcnJheShhdWRpdERldGFpbC5vbGQpICYmIGF1ZGl0RGV0YWlsLm9sZC5sZW5ndGggPT09IDApIGF1ZGl0RGV0YWlsLm9sZCA9IG51bGw7XG4gICAgICAgICAgICBpZiAoYW5ndWxhci5pc0FycmF5KGF1ZGl0RGV0YWlsLm5ldykgJiYgYXVkaXREZXRhaWwubmV3Lmxlbmd0aCA9PT0gMCkgYXVkaXREZXRhaWwubmV3ID0gbnVsbDtcblxuICAgICAgICAgICAgdm0uYXVkaXREZXRhaWwgPSBhdWRpdERldGFpbDtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICBmdW5jdGlvbiBjbG9zZSgpIHtcbiAgICAgICAgICAgIFByRGlhbG9nLmNsb3NlKCk7XG4gICAgICAgICAgfVxuXG4gICAgICAgIH0sXG4gICAgICAgIGNvbnRyb2xsZXJBczogJ2F1ZGl0RGV0YWlsQ3RybCcsXG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvYXVkaXQvYXVkaXQtZGV0YWlsLmh0bWwnLFxuICAgICAgICBoYXNCYWNrZHJvcDogdHJ1ZVxuICAgICAgfTtcblxuICAgICAgUHJEaWFsb2cuY3VzdG9tKGNvbmZpZyk7XG4gICAgfVxuXG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb25maWcocm91dGVzKTtcblxuICAvKipcbiAgICogQXJxdWl2byBkZSBjb25maWd1cmHDp8OjbyBjb20gYXMgcm90YXMgZXNwZWPDrWZpY2FzIGRlIGF1ZGl0b3JpYVxuICAgKlxuICAgKiBAcGFyYW0ge2FueX0gJHN0YXRlUHJvdmlkZXJcbiAgICogQHBhcmFtIHthbnl9IEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyXG4gICAgICAuc3RhdGUoJ2FwcC5hdWRpdCcsIHtcbiAgICAgICAgdXJsOiAnL2F1ZGl0b3JpYScsXG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvYXVkaXQvYXVkaXQuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdBdWRpdENvbnRyb2xsZXIgYXMgYXVkaXRDdHJsJyxcbiAgICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IHRydWUsIG5lZWRQcm9maWxlOiBbJ2FkbWluJ10gfVxuICAgICAgfSk7XG5cbiAgfVxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5mYWN0b3J5KCdBdWRpdFNlcnZpY2UnLCBBdWRpdFNlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gQXVkaXRTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5LCAkdHJhbnNsYXRlKSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCdhdWRpdCcsIHtcbiAgICAgIGFjdGlvbnM6IHtcbiAgICAgICAgZ2V0QXVkaXRlZE1vZGVsczoge1xuICAgICAgICAgIG1ldGhvZDogJ0dFVCcsXG4gICAgICAgICAgdXJsOiAnbW9kZWxzJ1xuICAgICAgICB9XG4gICAgICB9LFxuICAgICAgaW5zdGFuY2U6IHtcbiAgICAgIH0sXG4gICAgICBsaXN0VHlwZXM6IGZ1bmN0aW9uKCkge1xuICAgICAgICB2YXIgYXVkaXRQYXRoID0gJ3ZpZXdzLmZpZWxkcy5hdWRpdC4nO1xuXG4gICAgICAgIHJldHVybiBbXG4gICAgICAgICAgeyBpZDogJycsIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoYXVkaXRQYXRoICsgJ2FsbFJlc291cmNlcycpIH0sXG4gICAgICAgICAgeyBpZDogJ2NyZWF0ZWQnLCBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KGF1ZGl0UGF0aCArICd0eXBlLmNyZWF0ZWQnKSB9LFxuICAgICAgICAgIHsgaWQ6ICd1cGRhdGVkJywgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudChhdWRpdFBhdGggKyAndHlwZS51cGRhdGVkJykgfSxcbiAgICAgICAgICB7IGlkOiAnZGVsZXRlZCcsIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoYXVkaXRQYXRoICsgJ3R5cGUuZGVsZXRlZCcpIH1cbiAgICAgICAgXTtcbiAgICAgIH1cbiAgICB9KTtcbiAgfVxuXG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKlxuICAgKiBBcnF1aXZvIGRlIGNvbmZpZ3VyYcOnw6NvIGNvbSBhcyByb3RhcyBlc3BlY8OtZmljYXMgZG8gcmVjdXJzbyB1c2VyXG4gICAqXG4gICAqIEBwYXJhbSB7YW55fSAkc3RhdGVQcm92aWRlclxuICAgKiBAcGFyYW0ge2FueX0gR2xvYmFsXG4gICAqL1xuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvdXRlcygkc3RhdGVQcm92aWRlciwgR2xvYmFsKSB7XG4gICAgJHN0YXRlUHJvdmlkZXJcbiAgICAgIC5zdGF0ZShHbG9iYWwucmVzZXRQYXNzd29yZFN0YXRlLCB7XG4gICAgICAgIHVybDogJy9wYXNzd29yZC9yZXNldC86dG9rZW4nLFxuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL2F1dGgvcmVzZXQtcGFzcy1mb3JtLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnUGFzc3dvcmRDb250cm9sbGVyIGFzIHBhc3NDdHJsJyxcbiAgICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IGZhbHNlIH1cbiAgICAgIH0pXG4gICAgICAuc3RhdGUoR2xvYmFsLmxvZ2luU3RhdGUsIHtcbiAgICAgICAgdXJsOiAnL2xvZ2luJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9hdXRoL2xvZ2luLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnTG9naW5Db250cm9sbGVyIGFzIGxvZ2luQ3RybCcsXG4gICAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiBmYWxzZSB9XG4gICAgICB9KTtcblxuICB9XG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZhY3RvcnkoJ0F1dGgnLCBBdXRoKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIEF1dGgoJGh0dHAsICRxLCBHbG9iYWwsIFVzZXJzU2VydmljZSkgeyAvLyBOT1NPTkFSXG4gICAgdmFyIGF1dGggPSB7XG4gICAgICBsb2dpbjogbG9naW4sXG4gICAgICBsb2dvdXQ6IGxvZ291dCxcbiAgICAgIHVwZGF0ZUN1cnJlbnRVc2VyOiB1cGRhdGVDdXJyZW50VXNlcixcbiAgICAgIHJldHJpZXZlVXNlckZyb21Mb2NhbFN0b3JhZ2U6IHJldHJpZXZlVXNlckZyb21Mb2NhbFN0b3JhZ2UsXG4gICAgICBhdXRoZW50aWNhdGVkOiBhdXRoZW50aWNhdGVkLFxuICAgICAgc2VuZEVtYWlsUmVzZXRQYXNzd29yZDogc2VuZEVtYWlsUmVzZXRQYXNzd29yZCxcbiAgICAgIHJlbW90ZVZhbGlkYXRlVG9rZW46IHJlbW90ZVZhbGlkYXRlVG9rZW4sXG4gICAgICBnZXRUb2tlbjogZ2V0VG9rZW4sXG4gICAgICBzZXRUb2tlbjogc2V0VG9rZW4sXG4gICAgICBjbGVhclRva2VuOiBjbGVhclRva2VuLFxuICAgICAgY3VycmVudFVzZXI6IG51bGxcbiAgICB9O1xuXG4gICAgZnVuY3Rpb24gY2xlYXJUb2tlbigpIHtcbiAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKEdsb2JhbC50b2tlbktleSk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gc2V0VG9rZW4odG9rZW4pIHtcbiAgICAgIGxvY2FsU3RvcmFnZS5zZXRJdGVtKEdsb2JhbC50b2tlbktleSwgdG9rZW4pO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGdldFRva2VuKCkge1xuICAgICAgcmV0dXJuIGxvY2FsU3RvcmFnZS5nZXRJdGVtKEdsb2JhbC50b2tlbktleSk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gcmVtb3RlVmFsaWRhdGVUb2tlbigpIHtcbiAgICAgIHZhciBkZWZlcnJlZCA9ICRxLmRlZmVyKCk7XG5cbiAgICAgIGlmIChhdXRoLmF1dGhlbnRpY2F0ZWQoKSkge1xuICAgICAgICAkaHR0cC5nZXQoR2xvYmFsLmFwaVBhdGggKyAnL2F1dGhlbnRpY2F0ZS9jaGVjaycpXG4gICAgICAgICAgLnRoZW4oZnVuY3Rpb24oKSB7XG4gICAgICAgICAgICBkZWZlcnJlZC5yZXNvbHZlKHRydWUpO1xuICAgICAgICAgIH0sIGZ1bmN0aW9uKCkge1xuICAgICAgICAgICAgYXV0aC5sb2dvdXQoKTtcblxuICAgICAgICAgICAgZGVmZXJyZWQucmVqZWN0KGZhbHNlKTtcbiAgICAgICAgICB9KTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIGF1dGgubG9nb3V0KCk7XG5cbiAgICAgICAgZGVmZXJyZWQucmVqZWN0KGZhbHNlKTtcbiAgICAgIH1cblxuICAgICAgcmV0dXJuIGRlZmVycmVkLnByb21pc2U7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogVmVyaWZpY2Egc2UgbyB1c3XDoXJpbyBlc3TDoSBhdXRlbnRpY2Fkb1xuICAgICAqXG4gICAgICogQHJldHVybnMge2Jvb2xlYW59XG4gICAgICovXG4gICAgZnVuY3Rpb24gYXV0aGVudGljYXRlZCgpIHtcbiAgICAgIHJldHVybiBhdXRoLmdldFRva2VuKCkgIT09IG51bGxcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWN1cGVyYSBvIHVzdcOhcmlvIGRvIGxvY2FsU3RvcmFnZVxuICAgICAqL1xuICAgIGZ1bmN0aW9uIHJldHJpZXZlVXNlckZyb21Mb2NhbFN0b3JhZ2UoKSB7XG4gICAgICB2YXIgdXNlciA9IGxvY2FsU3RvcmFnZS5nZXRJdGVtKCd1c2VyJyk7XG5cbiAgICAgIGlmICh1c2VyKSB7XG4gICAgICAgIGF1dGguY3VycmVudFVzZXIgPSBhbmd1bGFyLm1lcmdlKG5ldyBVc2Vyc1NlcnZpY2UoKSwgYW5ndWxhci5mcm9tSnNvbih1c2VyKSk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogR3VhcmRhIG8gdXN1w6FyaW8gbm8gbG9jYWxTdG9yYWdlIHBhcmEgY2FzbyBvIHVzdcOhcmlvIGZlY2hlIGUgYWJyYSBvIG5hdmVnYWRvclxuICAgICAqIGRlbnRybyBkbyB0ZW1wbyBkZSBzZXNzw6NvIHNlamEgcG9zc8OtdmVsIHJlY3VwZXJhciBvIHRva2VuIGF1dGVudGljYWRvLlxuICAgICAqXG4gICAgICogTWFudMOpbSBhIHZhcmnDoXZlbCBhdXRoLmN1cnJlbnRVc2VyIHBhcmEgZmFjaWxpdGFyIG8gYWNlc3NvIGFvIHVzdcOhcmlvIGxvZ2FkbyBlbSB0b2RhIGEgYXBsaWNhw6fDo29cbiAgICAgKlxuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IHVzZXIgVXN1w6FyaW8gYSBzZXIgYXR1YWxpemFkby4gQ2FzbyBzZWphIHBhc3NhZG8gbnVsbCBsaW1wYVxuICAgICAqIHRvZGFzIGFzIGluZm9ybWHDp8O1ZXMgZG8gdXN1w6FyaW8gY29ycmVudGUuXG4gICAgICovXG4gICAgZnVuY3Rpb24gdXBkYXRlQ3VycmVudFVzZXIodXNlcikge1xuICAgICAgdmFyIGRlZmVycmVkID0gJHEuZGVmZXIoKTtcblxuICAgICAgaWYgKHVzZXIpIHtcbiAgICAgICAgdXNlciA9IGFuZ3VsYXIubWVyZ2UobmV3IFVzZXJzU2VydmljZSgpLCB1c2VyKTtcblxuICAgICAgICB2YXIganNvblVzZXIgPSBhbmd1bGFyLnRvSnNvbih1c2VyKTtcblxuICAgICAgICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbSgndXNlcicsIGpzb25Vc2VyKTtcbiAgICAgICAgYXV0aC5jdXJyZW50VXNlciA9IHVzZXI7XG5cbiAgICAgICAgZGVmZXJyZWQucmVzb2x2ZSh1c2VyKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKCd1c2VyJyk7XG4gICAgICAgIGF1dGguY3VycmVudFVzZXIgPSBudWxsO1xuICAgICAgICBhdXRoLmNsZWFyVG9rZW4oKTtcblxuICAgICAgICBkZWZlcnJlZC5yZWplY3QoKTtcbiAgICAgIH1cblxuICAgICAgcmV0dXJuIGRlZmVycmVkLnByb21pc2U7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhbGl6YSBvIGxvZ2luIGRvIHVzdcOhcmlvXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gY3JlZGVudGlhbHMgRW1haWwgZSBTZW5oYSBkbyB1c3XDoXJpb1xuICAgICAqIEByZXR1cm5zIHtwcm9taXNlfSBVbWEgcHJvbWlzZSBjb20gbyByZXN1bHRhZG8gZG8gY2hhbWFkYSBubyBiYWNrZW5kXG4gICAgICovXG4gICAgZnVuY3Rpb24gbG9naW4oY3JlZGVudGlhbHMpIHtcbiAgICAgIHZhciBkZWZlcnJlZCA9ICRxLmRlZmVyKCk7XG5cbiAgICAgICRodHRwLnBvc3QoR2xvYmFsLmFwaVBhdGggKyAnL2F1dGhlbnRpY2F0ZScsIGNyZWRlbnRpYWxzKVxuICAgICAgICAudGhlbihmdW5jdGlvbihyZXNwb25zZSkge1xuICAgICAgICAgIGF1dGguc2V0VG9rZW4ocmVzcG9uc2UuZGF0YS50b2tlbik7XG5cbiAgICAgICAgICByZXR1cm4gJGh0dHAuZ2V0KEdsb2JhbC5hcGlQYXRoICsgJy9hdXRoZW50aWNhdGUvdXNlcicpO1xuICAgICAgICB9KVxuICAgICAgICAudGhlbihmdW5jdGlvbihyZXNwb25zZSkge1xuICAgICAgICAgIGF1dGgudXBkYXRlQ3VycmVudFVzZXIocmVzcG9uc2UuZGF0YS51c2VyKTtcblxuICAgICAgICAgIGRlZmVycmVkLnJlc29sdmUoKTtcbiAgICAgICAgfSwgZnVuY3Rpb24oZXJyb3IpIHtcbiAgICAgICAgICBhdXRoLmxvZ291dCgpO1xuXG4gICAgICAgICAgZGVmZXJyZWQucmVqZWN0KGVycm9yKTtcbiAgICAgICAgfSk7XG5cbiAgICAgIHJldHVybiBkZWZlcnJlZC5wcm9taXNlO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIERlc2xvZ2Egb3MgdXN1w6FyaW9zLiBDb21vIG7Do28gdGVuIG5lbmh1bWEgaW5mb3JtYcOnw6NvIG5hIHNlc3PDo28gZG8gc2Vydmlkb3JcbiAgICAgKiBlIHVtIHRva2VuIHVtYSB2ZXogZ2VyYWRvIG7Do28gcG9kZSwgcG9yIHBhZHLDo28sIHNlciBpbnZhbGlkYWRvIGFudGVzIGRvIHNldSB0ZW1wbyBkZSBleHBpcmHDp8OjbyxcbiAgICAgKiBzb21lbnRlIGFwYWdhbW9zIG9zIGRhZG9zIGRvIHVzdcOhcmlvIGUgbyB0b2tlbiBkbyBuYXZlZ2Fkb3IgcGFyYSBlZmV0aXZhciBvIGxvZ291dC5cbiAgICAgKlxuICAgICAqIEByZXR1cm5zIHtwcm9taXNlfSBVbWEgcHJvbWlzZSBjb20gbyByZXN1bHRhZG8gZGEgb3BlcmHDp8Ojb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGxvZ291dCgpIHtcbiAgICAgIHZhciBkZWZlcnJlZCA9ICRxLmRlZmVyKCk7XG5cbiAgICAgIGF1dGgudXBkYXRlQ3VycmVudFVzZXIobnVsbCk7XG4gICAgICBkZWZlcnJlZC5yZXNvbHZlKCk7XG5cbiAgICAgIHJldHVybiBkZWZlcnJlZC5wcm9taXNlO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEVudmlhIHVtIGVtYWlsIHBhcmEgcmVjdXBlcmHDp8OjbyBkZSBzZW5oYVxuICAgICAqIEBwYXJhbSB7T2JqZWN0fSByZXNldERhdGEgLSBPYmpldG8gY29udGVuZG8gbyBlbWFpbFxuICAgICAqIEByZXR1cm4ge1Byb21pc2V9IC0gUmV0b3JuYSB1bWEgcHJvbWlzZSBwYXJhIHNlciByZXNvbHZpZGFcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBzZW5kRW1haWxSZXNldFBhc3N3b3JkKHJlc2V0RGF0YSkge1xuICAgICAgdmFyIGRlZmVycmVkID0gJHEuZGVmZXIoKTtcblxuICAgICAgJGh0dHAucG9zdChHbG9iYWwuYXBpUGF0aCArICcvcGFzc3dvcmQvZW1haWwnLCByZXNldERhdGEpXG4gICAgICAgIC50aGVuKGZ1bmN0aW9uKHJlc3BvbnNlKSB7XG4gICAgICAgICAgZGVmZXJyZWQucmVzb2x2ZShyZXNwb25zZS5kYXRhKTtcbiAgICAgICAgfSwgZnVuY3Rpb24oZXJyb3IpIHtcbiAgICAgICAgICBkZWZlcnJlZC5yZWplY3QoZXJyb3IpO1xuICAgICAgICB9KTtcblxuICAgICAgcmV0dXJuIGRlZmVycmVkLnByb21pc2U7XG4gICAgfVxuXG4gICAgcmV0dXJuIGF1dGg7XG4gIH1cblxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnRyb2xsZXIoJ0xvZ2luQ29udHJvbGxlcicsIExvZ2luQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBMb2dpbkNvbnRyb2xsZXIoJHN0YXRlLCBBdXRoLCBHbG9iYWwsIFByRGlhbG9nKSB7XG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIHZtLmxvZ2luID0gbG9naW47XG4gICAgdm0ub3BlbkRpYWxvZ1Jlc2V0UGFzcyA9IG9wZW5EaWFsb2dSZXNldFBhc3M7XG4gICAgdm0ub3BlbkRpYWxvZ1NpZ25VcCA9IG9wZW5EaWFsb2dTaWduVXA7XG5cbiAgICBhY3RpdmF0ZSgpO1xuXG4gICAgZnVuY3Rpb24gYWN0aXZhdGUoKSB7XG4gICAgICB2bS5jcmVkZW50aWFscyA9IHt9O1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGxvZ2luKCkge1xuICAgICAgdmFyIGNyZWRlbnRpYWxzID0ge1xuICAgICAgICBlbWFpbDogdm0uY3JlZGVudGlhbHMuZW1haWwsXG4gICAgICAgIHBhc3N3b3JkOiB2bS5jcmVkZW50aWFscy5wYXNzd29yZFxuICAgICAgfTtcblxuICAgICAgQXV0aC5sb2dpbihjcmVkZW50aWFscykudGhlbihmdW5jdGlvbigpIHtcbiAgICAgICAgJHN0YXRlLmdvKEdsb2JhbC5ob21lU3RhdGUpO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogRXhpYmUgbyBkaWFsb2cgcGFyYSByZWN1cGVyYcOnw6NvIGRlIHNlbmhhXG4gICAgICovXG4gICAgZnVuY3Rpb24gb3BlbkRpYWxvZ1Jlc2V0UGFzcygpIHtcbiAgICAgIHZhciBjb25maWcgPSB7XG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvYXV0aC9zZW5kLXJlc2V0LWRpYWxvZy5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ1Bhc3N3b3JkQ29udHJvbGxlciBhcyBwYXNzQ3RybCcsXG4gICAgICAgIGhhc0JhY2tkcm9wOiB0cnVlXG4gICAgICB9XG5cbiAgICAgIFByRGlhbG9nLmN1c3RvbShjb25maWcpO1xuICAgIH1cbiAgICAvKipcbiAgICAgKiBFeGliZSBvIGRpYWxvZyBwYXJhIHJlY3VwZXJhw6fDo28gZGUgc2VuaGFcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBvcGVuRGlhbG9nU2lnblVwKCkge1xuICAgICAgdmFyIGNvbmZpZyA9IHtcbiAgICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy91c2Vycy91c2VyLWZvcm0uaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdVc2Vyc0NvbnRyb2xsZXIgYXMgdXNlcnNDdHJsJyxcbiAgICAgICAgaGFzQmFja2Ryb3A6IHRydWVcbiAgICAgIH1cblxuICAgICAgUHJEaWFsb2cuY3VzdG9tKGNvbmZpZyk7XG4gICAgfVxuXG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb250cm9sbGVyKCdQYXNzd29yZENvbnRyb2xsZXInLCBQYXNzd29yZENvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gUGFzc3dvcmRDb250cm9sbGVyKEdsb2JhbCwgJHN0YXRlUGFyYW1zLCAkaHR0cCwgJHRpbWVvdXQsICRzdGF0ZSwgLy8gTk9TT05BUlxuICAgIFByVG9hc3QsIFByRGlhbG9nLCBBdXRoLCAkdHJhbnNsYXRlKSB7XG5cbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0uc2VuZFJlc2V0ID0gc2VuZFJlc2V0O1xuICAgIHZtLmNsb3NlRGlhbG9nID0gY2xvc2VEaWFsb2c7XG4gICAgdm0uY2xlYW5Gb3JtID0gY2xlYW5Gb3JtO1xuICAgIHZtLnNlbmRFbWFpbFJlc2V0UGFzc3dvcmQgPSBzZW5kRW1haWxSZXNldFBhc3N3b3JkO1xuXG4gICAgYWN0aXZhdGUoKTtcblxuICAgIGZ1bmN0aW9uIGFjdGl2YXRlKCkge1xuICAgICAgdm0ucmVzZXQgPSB7IGVtYWlsOiAnJywgdG9rZW46ICRzdGF0ZVBhcmFtcy50b2tlbiB9O1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWxpemEgYSBhbHRlcmHDp8OjbyBkYSBzZW5oYSBkbyB1c3XDoXJpbyBlIG8gcmVkaXJlY2lvbmEgcGFyYSBhIHRlbGEgZGUgbG9naW5cbiAgICAgKi9cbiAgICBmdW5jdGlvbiBzZW5kUmVzZXQoKSB7XG4gICAgICAkaHR0cC5wb3N0KEdsb2JhbC5hcGlQYXRoICsgJy9wYXNzd29yZC9yZXNldCcsIHZtLnJlc2V0KVxuICAgICAgICAudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgUHJUb2FzdC5zdWNjZXNzKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMub3BlcmF0aW9uU3VjY2VzcycpKTtcbiAgICAgICAgICAkdGltZW91dChmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAkc3RhdGUuZ28oR2xvYmFsLmxvZ2luU3RhdGUpO1xuICAgICAgICAgIH0sIDE1MDApO1xuICAgICAgICB9LCBmdW5jdGlvbiAoZXJyb3IpIHtcbiAgICAgICAgICBpZiAoZXJyb3Iuc3RhdHVzICE9PSA0MDAgJiYgZXJyb3Iuc3RhdHVzICE9PSA1MDApIHtcbiAgICAgICAgICAgIHZhciBtc2cgPSAnJztcblxuICAgICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCBlcnJvci5kYXRhLnBhc3N3b3JkLmxlbmd0aDsgaSsrKSB7XG4gICAgICAgICAgICAgIG1zZyArPSBlcnJvci5kYXRhLnBhc3N3b3JkW2ldICsgJzxicj4nO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgUHJUb2FzdC5lcnJvcihtc2cudG9VcHBlckNhc2UoKSk7XG4gICAgICAgICAgfVxuICAgICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBFbnZpYSB1bSBlbWFpbCBkZSByZWN1cGVyYcOnw6NvIGRlIHNlbmhhIGNvbSBvIHRva2VuIGRvIHVzdcOhcmlvXG4gICAgICovXG4gICAgZnVuY3Rpb24gc2VuZEVtYWlsUmVzZXRQYXNzd29yZCgpIHtcblxuICAgICAgaWYgKHZtLnJlc2V0LmVtYWlsID09PSAnJykge1xuICAgICAgICBQclRvYXN0LmVycm9yKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMudmFsaWRhdGUuZmllbGRSZXF1aXJlZCcsIHsgZmllbGQ6ICdlbWFpbCcgfSkpO1xuICAgICAgICByZXR1cm47XG4gICAgICB9XG5cbiAgICAgIEF1dGguc2VuZEVtYWlsUmVzZXRQYXNzd29yZCh2bS5yZXNldCkudGhlbihmdW5jdGlvbiAoZGF0YSkge1xuICAgICAgICBQclRvYXN0LnN1Y2Nlc3MoZGF0YS5tZXNzYWdlKTtcblxuICAgICAgICB2bS5jbGVhbkZvcm0oKTtcbiAgICAgICAgdm0uY2xvc2VEaWFsb2coKTtcbiAgICAgIH0sIGZ1bmN0aW9uIChlcnJvcikge1xuICAgICAgICBpZiAoZXJyb3IuZGF0YS5lbWFpbCAmJiBlcnJvci5kYXRhLmVtYWlsLmxlbmd0aCA+IDApIHtcbiAgICAgICAgICB2YXIgbXNnID0gJyc7XG5cbiAgICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IGVycm9yLmRhdGEuZW1haWwubGVuZ3RoOyBpKyspIHtcbiAgICAgICAgICAgIG1zZyArPSBlcnJvci5kYXRhLmVtYWlsW2ldICsgJzxicj4nO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIFByVG9hc3QuZXJyb3IobXNnKTtcbiAgICAgICAgfVxuICAgICAgfSk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gY2xvc2VEaWFsb2coKSB7XG4gICAgICBQckRpYWxvZy5jbG9zZSgpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGNsZWFuRm9ybSgpIHtcbiAgICAgIHZtLnJlc2V0LmVtYWlsID0gJyc7XG4gICAgfVxuXG4gIH1cblxufSkoKTtcbiIsIi8qZXNsaW50IGFuZ3VsYXIvZmlsZS1uYW1lOiAwKi9cbihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5mYWN0b3J5KCdzZXJ2aWNlRmFjdG9yeScsIHNlcnZpY2VGYWN0b3J5KTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8qKlxuICAgKiBNYWlzIGluZm9ybWHDp8O1ZXM6XG4gICAqIGh0dHBzOi8vZ2l0aHViLmNvbS9zd2ltbGFuZS9hbmd1bGFyLW1vZGVsLWZhY3Rvcnkvd2lraS9BUElcbiAgICovXG4gIGZ1bmN0aW9uIHNlcnZpY2VGYWN0b3J5KCRtb2RlbEZhY3RvcnkpIHtcbiAgICByZXR1cm4gZnVuY3Rpb24odXJsLCBvcHRpb25zKSB7XG4gICAgICB2YXIgbW9kZWw7XG4gICAgICB2YXIgZGVmYXVsdE9wdGlvbnMgPSB7XG4gICAgICAgIGFjdGlvbnM6IHtcbiAgICAgICAgICAvKipcbiAgICAgICAgICAgKiBTZXJ2acOnbyBjb211bSBwYXJhIHJlYWxpemFyIGJ1c2NhIGNvbSBwYWdpbmHDp8Ojb1xuICAgICAgICAgICAqIE8gbWVzbW8gZXNwZXJhIHF1ZSBzZWphIHJldG9ybmFkbyB1bSBvYmpldG8gY29tIGl0ZW1zIGUgdG90YWxcbiAgICAgICAgICAgKi9cbiAgICAgICAgICBwYWdpbmF0ZToge1xuICAgICAgICAgICAgbWV0aG9kOiAnR0VUJyxcbiAgICAgICAgICAgIGlzQXJyYXk6IGZhbHNlLFxuICAgICAgICAgICAgd3JhcDogZmFsc2UsXG4gICAgICAgICAgICBhZnRlclJlcXVlc3Q6IGZ1bmN0aW9uKHJlc3BvbnNlKSB7XG4gICAgICAgICAgICAgIGlmIChyZXNwb25zZVsnaXRlbXMnXSkge1xuICAgICAgICAgICAgICAgIHJlc3BvbnNlWydpdGVtcyddID0gbW9kZWwuTGlzdChyZXNwb25zZVsnaXRlbXMnXSk7XG4gICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICByZXR1cm4gcmVzcG9uc2U7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICB9XG5cbiAgICAgIG1vZGVsID0gJG1vZGVsRmFjdG9yeSh1cmwsIGFuZ3VsYXIubWVyZ2UoZGVmYXVsdE9wdGlvbnMsIG9wdGlvbnMpKVxuXG4gICAgICByZXR1cm4gbW9kZWw7XG4gICAgfVxuICB9XG59KSgpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29udHJvbGxlcignQ1JVRENvbnRyb2xsZXInLCBDUlVEQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvKipcbiAgICogQ29udHJvbGFkb3IgQmFzZSBxdWUgaW1wbGVtZW50YSB0b2RhcyBhcyBmdW7Dp8O1ZXMgcGFkcsO1ZXMgZGUgdW0gQ1JVRFxuICAgKlxuICAgKiBBw6fDtWVzIGltcGxlbWVudGFkYXNcbiAgICogYWN0aXZhdGUoKVxuICAgKiBzZWFyY2gocGFnZSlcbiAgICogZWRpdChyZXNvdXJjZSlcbiAgICogc2F2ZSgpXG4gICAqIHJlbW92ZShyZXNvdXJjZSlcbiAgICogZ29Ubyh2aWV3TmFtZSlcbiAgICogY2xlYW5Gb3JtKClcbiAgICpcbiAgICogR2F0aWxob3NcbiAgICpcbiAgICogb25BY3RpdmF0ZSgpXG4gICAqIGFwcGx5RmlsdGVycyhkZWZhdWx0UXVlcnlGaWx0ZXJzKVxuICAgKiBiZWZvcmVTZWFyY2gocGFnZSkgLy9yZXRvcm5hbmRvIGZhbHNlIGNhbmNlbGEgbyBmbHV4b1xuICAgKiBhZnRlclNlYXJjaChyZXNwb25zZSlcbiAgICogYmVmb3JlQ2xlYW4gLy9yZXRvcm5hbmRvIGZhbHNlIGNhbmNlbGEgbyBmbHV4b1xuICAgKiBhZnRlckNsZWFuKClcbiAgICogYmVmb3JlU2F2ZSgpIC8vcmV0b3JuYW5kbyBmYWxzZSBjYW5jZWxhIG8gZmx1eG9cbiAgICogYWZ0ZXJTYXZlKHJlc291cmNlKVxuICAgKiBvblNhdmVFcnJvcihlcnJvcilcbiAgICogYmVmb3JlUmVtb3ZlKHJlc291cmNlKSAvL3JldG9ybmFuZG8gZmFsc2UgY2FuY2VsYSBvIGZsdXhvXG4gICAqIGFmdGVyUmVtb3ZlKHJlc291cmNlKVxuICAgKlxuICAgKiBAcGFyYW0ge2FueX0gdm0gaW5zdGFuY2lhIGRvIGNvbnRyb2xsZXIgZmlsaG9cbiAgICogQHBhcmFtIHthbnl9IG1vZGVsU2VydmljZSBzZXJ2acOnbyBkbyBtb2RlbCBxdWUgdmFpIHNlciB1dGlsaXphZG9cbiAgICogQHBhcmFtIHthbnl9IG9wdGlvbnMgb3DDp8O1ZXMgcGFyYSBzb2JyZWVzY3JldmVyIGNvbXBvcnRhbWVudG9zIHBhZHLDtWVzXG4gICAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBDUlVEQ29udHJvbGxlcih2bSwgbW9kZWxTZXJ2aWNlLCBvcHRpb25zLCBQclRvYXN0LCBQclBhZ2luYXRpb24sIC8vIE5PU09OQVJcbiAgICBQckRpYWxvZywgJHRyYW5zbGF0ZSkge1xuXG4gICAgLy9GdW5jdGlvbnMgQmxvY2tcbiAgICB2bS5zZWFyY2ggPSBzZWFyY2g7XG4gICAgdm0ucGFnaW5hdGVTZWFyY2ggPSBwYWdpbmF0ZVNlYXJjaDtcbiAgICB2bS5ub3JtYWxTZWFyY2ggPSBub3JtYWxTZWFyY2g7XG4gICAgdm0uZWRpdCA9IGVkaXQ7XG4gICAgdm0uc2F2ZSA9IHNhdmU7XG4gICAgdm0ucmVtb3ZlID0gcmVtb3ZlO1xuICAgIHZtLmdvVG8gPSBnb1RvO1xuICAgIHZtLmNsZWFuRm9ybSA9IGNsZWFuRm9ybTtcblxuICAgIGFjdGl2YXRlKCk7XG5cbiAgICAvKipcbiAgICAgKiBQcmVwYXJhIG8gY29udHJvbGFkb3JcbiAgICAgKiBGYXogbyBtZXJnZSBkYXMgb3DDp8O1ZXNcbiAgICAgKiBJbmljaWFsaXphIG8gcmVjdXJzb1xuICAgICAqIEluaWNpYWxpemEgbyBvYmpldG8gcGFnaW5hZG9yIGUgcmVhbGl6YSBhIHBlc3F1aXNhXG4gICAgICovXG4gICAgZnVuY3Rpb24gYWN0aXZhdGUoKSB7XG4gICAgICB2bS5kZWZhdWx0T3B0aW9ucyA9IHtcbiAgICAgICAgcmVkaXJlY3RBZnRlclNhdmU6IHRydWUsXG4gICAgICAgIHNlYXJjaE9uSW5pdDogdHJ1ZSxcbiAgICAgICAgcGVyUGFnZTogOCxcbiAgICAgICAgc2tpcFBhZ2luYXRpb246IGZhbHNlXG4gICAgICB9XG5cbiAgICAgIGFuZ3VsYXIubWVyZ2Uodm0uZGVmYXVsdE9wdGlvbnMsIG9wdGlvbnMpO1xuXG4gICAgICB2bS52aWV3Rm9ybSA9IGZhbHNlO1xuICAgICAgdm0ucmVzb3VyY2UgPSBuZXcgbW9kZWxTZXJ2aWNlKCk7XG5cbiAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0ub25BY3RpdmF0ZSkpIHZtLm9uQWN0aXZhdGUoKTtcblxuICAgICAgdm0ucGFnaW5hdG9yID0gUHJQYWdpbmF0aW9uLmdldEluc3RhbmNlKHZtLnNlYXJjaCwgdm0uZGVmYXVsdE9wdGlvbnMucGVyUGFnZSk7XG5cbiAgICAgIGlmICh2bS5kZWZhdWx0T3B0aW9ucy5zZWFyY2hPbkluaXQpIHZtLnNlYXJjaCgpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWxpemEgYSBwZXNxdWlzYVxuICAgICAqIFZlcmlmaWNhIHF1YWwgZGFzIGZ1bsOnw7VlcyBkZSBwZXNxdWlzYSBkZXZlIHNlciByZWFsaXphZGEuXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gcGFnZSBww6FnaW5hIHF1ZSBkZXZlIHNlciBjYXJyZWdhZGFcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBzZWFyY2gocGFnZSkge1xuICAgICAgKHZtLmRlZmF1bHRPcHRpb25zLnNraXBQYWdpbmF0aW9uKSA/IG5vcm1hbFNlYXJjaCgpIDogcGFnaW5hdGVTZWFyY2gocGFnZSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhbGl6YSBhIHBlc3F1aXNhIHBhZ2luYWRhIGNvbSBiYXNlIG5vcyBmaWx0cm9zIGRlZmluaWRvc1xuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IHBhZ2UgcMOhZ2luYSBxdWUgZGV2ZSBzZXIgY2FycmVnYWRhXG4gICAgICovXG4gICAgZnVuY3Rpb24gcGFnaW5hdGVTZWFyY2gocGFnZSkge1xuICAgICAgdm0ucGFnaW5hdG9yLmN1cnJlbnRQYWdlID0gKGFuZ3VsYXIuaXNEZWZpbmVkKHBhZ2UpKSA/IHBhZ2UgOiAxO1xuICAgICAgdm0uZGVmYXVsdFF1ZXJ5RmlsdGVycyA9IHsgcGFnZTogdm0ucGFnaW5hdG9yLmN1cnJlbnRQYWdlLCBwZXJQYWdlOiB2bS5wYWdpbmF0b3IucGVyUGFnZSB9O1xuXG4gICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmFwcGx5RmlsdGVycykpIHZtLmRlZmF1bHRRdWVyeUZpbHRlcnMgPSB2bS5hcHBseUZpbHRlcnModm0uZGVmYXVsdFF1ZXJ5RmlsdGVycyk7XG4gICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmJlZm9yZVNlYXJjaCkgJiYgdm0uYmVmb3JlU2VhcmNoKHBhZ2UpID09PSBmYWxzZSkgcmV0dXJuIGZhbHNlO1xuXG4gICAgICBtb2RlbFNlcnZpY2UucGFnaW5hdGUodm0uZGVmYXVsdFF1ZXJ5RmlsdGVycykudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgdm0ucGFnaW5hdG9yLmNhbGNOdW1iZXJPZlBhZ2VzKHJlc3BvbnNlLnRvdGFsKTtcbiAgICAgICAgdm0ucmVzb3VyY2VzID0gcmVzcG9uc2UuaXRlbXM7XG5cbiAgICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5hZnRlclNlYXJjaCkpIHZtLmFmdGVyU2VhcmNoKHJlc3BvbnNlKTtcbiAgICAgIH0sIGZ1bmN0aW9uIChyZXNwb25zZURhdGEpIHtcbiAgICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5vblNlYXJjaEVycm9yKSkgdm0ub25TZWFyY2hFcnJvcihyZXNwb25zZURhdGEpO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhbGl6YSBhIHBlc3F1aXNhIGNvbSBiYXNlIG5vcyBmaWx0cm9zIGRlZmluaWRvc1xuICAgICAqXG4gICAgICovXG4gICAgZnVuY3Rpb24gbm9ybWFsU2VhcmNoKCkge1xuICAgICAgdm0uZGVmYXVsdFF1ZXJ5RmlsdGVycyA9IHsgfTtcblxuICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5hcHBseUZpbHRlcnMpKSB2bS5kZWZhdWx0UXVlcnlGaWx0ZXJzID0gdm0uYXBwbHlGaWx0ZXJzKHZtLmRlZmF1bHRRdWVyeUZpbHRlcnMpO1xuICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5iZWZvcmVTZWFyY2gpICYmIHZtLmJlZm9yZVNlYXJjaCgpID09PSBmYWxzZSkgcmV0dXJuIGZhbHNlO1xuXG4gICAgICBtb2RlbFNlcnZpY2UucXVlcnkodm0uZGVmYXVsdFF1ZXJ5RmlsdGVycykudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgdm0ucmVzb3VyY2VzID0gcmVzcG9uc2U7XG5cbiAgICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5hZnRlclNlYXJjaCkpIHZtLmFmdGVyU2VhcmNoKHJlc3BvbnNlKTtcbiAgICAgIH0sIGZ1bmN0aW9uIChyZXNwb25zZURhdGEpIHtcbiAgICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5vblNlYXJjaEVycm9yKSkgdm0ub25TZWFyY2hFcnJvcihyZXNwb25zZURhdGEpO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogTGltcGEgbyBmb3JtdWzDoXJpb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGNsZWFuRm9ybShmb3JtKSB7XG4gICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmJlZm9yZUNsZWFuKSAmJiB2bS5iZWZvcmVDbGVhbigpID09PSBmYWxzZSkgcmV0dXJuIGZhbHNlO1xuXG4gICAgICB2bS5yZXNvdXJjZSA9IG5ldyBtb2RlbFNlcnZpY2UoKTtcblxuICAgICAgaWYgKGFuZ3VsYXIuaXNEZWZpbmVkKGZvcm0pKSB7XG4gICAgICAgIGZvcm0uJHNldFByaXN0aW5lKCk7XG4gICAgICAgIGZvcm0uJHNldFVudG91Y2hlZCgpO1xuICAgICAgfVxuXG4gICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmFmdGVyQ2xlYW4pKSB2bS5hZnRlckNsZWFuKCk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ2FycmVnYSBubyBmb3JtdWzDoXJpbyBvIHJlY3Vyc28gc2VsZWNpb25hZG8gcGFyYSBlZGnDp8Ojb1xuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IHJlc291cmNlIHJlY3Vyc28gc2VsZWNpb25hZG9cbiAgICAgKi9cbiAgICBmdW5jdGlvbiBlZGl0KHJlc291cmNlKSB7XG4gICAgICB2bS5nb1RvKCdmb3JtJyk7XG4gICAgICB2bS5yZXNvdXJjZSA9IG5ldyBhbmd1bGFyLmNvcHkocmVzb3VyY2UpO1xuXG4gICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmFmdGVyRWRpdCkpIHZtLmFmdGVyRWRpdCgpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFNhbHZhIG91IGF0dWFsaXphIG8gcmVjdXJzbyBjb3JyZW50ZSBubyBmb3JtdWzDoXJpb1xuICAgICAqIE5vIGNvbXBvcnRhbWVudG8gcGFkcsOjbyByZWRpcmVjaW9uYSBvIHVzdcOhcmlvIHBhcmEgdmlldyBkZSBsaXN0YWdlbVxuICAgICAqIGRlcG9pcyBkYSBleGVjdcOnw6NvXG4gICAgICpcbiAgICAgKiBAcmV0dXJuc1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIHNhdmUoZm9ybSkge1xuICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5iZWZvcmVTYXZlKSAmJiB2bS5iZWZvcmVTYXZlKCkgPT09IGZhbHNlKSByZXR1cm4gZmFsc2U7XG5cbiAgICAgIHZtLnJlc291cmNlLiRzYXZlKCkudGhlbihmdW5jdGlvbiAocmVzb3VyY2UpIHtcbiAgICAgICAgdm0ucmVzb3VyY2UgPSByZXNvdXJjZTtcblxuICAgICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmFmdGVyU2F2ZSkpIHZtLmFmdGVyU2F2ZShyZXNvdXJjZSk7XG5cbiAgICAgICAgaWYgKHZtLmRlZmF1bHRPcHRpb25zLnJlZGlyZWN0QWZ0ZXJTYXZlKSB7XG4gICAgICAgICAgdm0uY2xlYW5Gb3JtKGZvcm0pO1xuICAgICAgICAgIHZtLnNlYXJjaCh2bS5wYWdpbmF0b3IuY3VycmVudFBhZ2UpO1xuICAgICAgICAgIHZtLmdvVG8oJ2xpc3QnKTtcbiAgICAgICAgfVxuXG4gICAgICAgIFByVG9hc3Quc3VjY2VzcygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnNhdmVTdWNjZXNzJykpO1xuXG4gICAgICB9LCBmdW5jdGlvbiAocmVzcG9uc2VEYXRhKSB7XG4gICAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0ub25TYXZlRXJyb3IpKSB2bS5vblNhdmVFcnJvcihyZXNwb25zZURhdGEpO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVtb3ZlIG8gcmVjdXJzbyBpbmZvcm1hZG8uXG4gICAgICogQW50ZXMgZXhpYmUgdW0gZGlhbG9nbyBkZSBjb25maXJtYcOnw6NvXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gcmVzb3VyY2UgcmVjdXJzbyBlc2NvbGhpZG9cbiAgICAgKi9cbiAgICBmdW5jdGlvbiByZW1vdmUocmVzb3VyY2UpIHtcbiAgICAgIHZhciBjb25maWcgPSB7XG4gICAgICAgIHRpdGxlOiAkdHJhbnNsYXRlLmluc3RhbnQoJ2RpYWxvZy5jb25maXJtVGl0bGUnKSxcbiAgICAgICAgZGVzY3JpcHRpb246ICR0cmFuc2xhdGUuaW5zdGFudCgnZGlhbG9nLmNvbmZpcm1EZXNjcmlwdGlvbicpXG4gICAgICB9XG5cbiAgICAgIFByRGlhbG9nLmNvbmZpcm0oY29uZmlnKS50aGVuKGZ1bmN0aW9uKCkge1xuICAgICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmJlZm9yZVJlbW92ZSkgJiYgdm0uYmVmb3JlUmVtb3ZlKHJlc291cmNlKSA9PT0gZmFsc2UpIHJldHVybiBmYWxzZTtcblxuICAgICAgICByZXNvdXJjZS4kZGVzdHJveSgpLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYWZ0ZXJSZW1vdmUpKSB2bS5hZnRlclJlbW92ZShyZXNvdXJjZSk7XG5cbiAgICAgICAgICB2bS5zZWFyY2goKTtcbiAgICAgICAgICBQclRvYXN0LmluZm8oJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5yZW1vdmVTdWNjZXNzJykpO1xuICAgICAgICB9KTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEFsdGVybmEgZW50cmUgYSB2aWV3IGRvIGZvcm11bMOhcmlvIGUgbGlzdGFnZW1cbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSB2aWV3TmFtZSBub21lIGRhIHZpZXdcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBnb1RvKHZpZXdOYW1lKSB7XG4gICAgICB2bS52aWV3Rm9ybSA9IGZhbHNlO1xuICAgICAgdm0ub25WaWV3ID0gZmFsc2U7XG4gICAgICBpZiAodmlld05hbWUgPT09ICdmb3JtJykge1xuICAgICAgICB2bS5jbGVhbkZvcm0oKTtcbiAgICAgICAgdm0udmlld0Zvcm0gPSB0cnVlO1xuICAgICAgfVxuICAgIH1cbiAgfVxuXG59KSgpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmlsdGVyKCdlbGFwc2VkJywgZnVuY3Rpb24oKSB7XG4gICAgICByZXR1cm4gZnVuY3Rpb24oZGF0ZSkge1xuICAgICAgICBpZiAoIWRhdGUpIHJldHVybjtcbiAgICAgICAgdmFyIHRpbWUgPSBEYXRlLnBhcnNlKGRhdGUpLFxuICAgICAgICAgIHRpbWVOb3cgPSBuZXcgRGF0ZSgpLmdldFRpbWUoKSxcbiAgICAgICAgICBkaWZmZXJlbmNlID0gdGltZU5vdyAtIHRpbWUsXG4gICAgICAgICAgc2Vjb25kcyA9IE1hdGguZmxvb3IoZGlmZmVyZW5jZSAvIDEwMDApLFxuICAgICAgICAgIG1pbnV0ZXMgPSBNYXRoLmZsb29yKHNlY29uZHMgLyA2MCksXG4gICAgICAgICAgaG91cnMgPSBNYXRoLmZsb29yKG1pbnV0ZXMgLyA2MCksXG4gICAgICAgICAgZGF5cyA9IE1hdGguZmxvb3IoaG91cnMgLyAyNCksXG4gICAgICAgICAgbW9udGhzID0gTWF0aC5mbG9vcihkYXlzIC8gMzApO1xuXG4gICAgICAgIGlmIChtb250aHMgPiAxKSB7XG4gICAgICAgICAgcmV0dXJuIG1vbnRocyArICcgbWVzZXMgYXRyw6FzJztcbiAgICAgICAgfSBlbHNlIGlmIChtb250aHMgPT09IDEpIHtcbiAgICAgICAgICByZXR1cm4gJzEgbcOqcyBhdHLDoXMnO1xuICAgICAgICB9IGVsc2UgaWYgKGRheXMgPiAxKSB7XG4gICAgICAgICAgcmV0dXJuIGRheXMgKyAnIGRpYXMgYXRyw6FzJztcbiAgICAgICAgfSBlbHNlIGlmIChkYXlzID09PSAxKSB7XG4gICAgICAgICAgcmV0dXJuICcxIGRpYSBhdHLDoXMnXG4gICAgICAgIH0gZWxzZSBpZiAoaG91cnMgPiAxKSB7XG4gICAgICAgICAgcmV0dXJuIGhvdXJzICsgJyBob3JhcyBhdHLDoXMnO1xuICAgICAgICB9IGVsc2UgaWYgKGhvdXJzID09PSAxKSB7XG4gICAgICAgICAgcmV0dXJuICd1bWEgaG9yYSBhdHLDoXMnO1xuICAgICAgICB9IGVsc2UgaWYgKG1pbnV0ZXMgPiAxKSB7XG4gICAgICAgICAgcmV0dXJuIG1pbnV0ZXMgKyAnIG1pbnV0b3MgYXRyw6FzJztcbiAgICAgICAgfSBlbHNlIGlmIChtaW51dGVzID09PSAxKSB7XG4gICAgICAgICAgcmV0dXJuICd1bSBtaW51dG8gYXRyw6FzJztcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICByZXR1cm4gJ2jDoSBwb3Vjb3Mgc2VndW5kb3MnO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfSlcbiAgICAuY29udHJvbGxlcignRGFzaGJvYXJkQ29udHJvbGxlcicsIERhc2hib2FyZENvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gRGFzaGJvYXJkQ29udHJvbGxlcigkY29udHJvbGxlcixcbiAgICAkc3RhdGUsXG4gICAgJG1kRGlhbG9nLFxuICAgICR0cmFuc2xhdGUsXG4gICAgRGFzaGJvYXJkc1NlcnZpY2UsXG4gICAgUHJvamVjdHNTZXJ2aWNlLFxuICAgIG1vbWVudCxcbiAgICBQclRvYXN0LFxuICAgIEF1dGgsXG4gICAgR2xvYmFsKSB7XG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIC8vQXR0cmlidXRlcyBCbG9ja1xuXG4gICAgLy9GdW5jdGlvbnMgQmxvY2tcbiAgICB2bS5vbkFjdGl2YXRlID0gb25BY3RpdmF0ZTtcbiAgICB2bS5hcHBseUZpbHRlcnMgPSBhcHBseUZpbHRlcnM7XG4gICAgdm0uZml4RGF0ZSA9IGZpeERhdGU7XG5cbiAgICBmdW5jdGlvbiBvbkFjdGl2YXRlKCkge1xuICAgICAgdmFyIHByb2plY3QgPSBsb2NhbFN0b3JhZ2UuZ2V0SXRlbSgncHJvamVjdCcpO1xuXG4gICAgICB2bS5pbWFnZVBhdGggPSBHbG9iYWwuaW1hZ2VQYXRoICsgJy9ub19hdmF0YXIuZ2lmJztcbiAgICAgIHZtLmN1cnJlbnRVc2VyID0gQXV0aC5jdXJyZW50VXNlcjtcbiAgICAgIFByb2plY3RzU2VydmljZS5xdWVyeSh7IHByb2plY3RfaWQ6IHByb2plY3QgfSkudGhlbihmdW5jdGlvbihyZXNwb25zZSkge1xuICAgICAgICB2bS5hY3R1YWxQcm9qZWN0ID0gcmVzcG9uc2VbMF07XG4gICAgICB9KVxuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0geyBwcm9qZWN0X2lkOiBwcm9qZWN0IH07XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gYXBwbHlGaWx0ZXJzKGRlZmF1bHRRdWVyeUZpbHRlcnMpIHtcbiAgICAgIHJldHVybiBhbmd1bGFyLmV4dGVuZChkZWZhdWx0UXVlcnlGaWx0ZXJzLCB2bS5xdWVyeUZpbHRlcnMpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGZpeERhdGUoZGF0ZVN0cmluZykge1xuICAgICAgcmV0dXJuIG1vbWVudChkYXRlU3RyaW5nKTtcbiAgICB9XG5cbiAgICB2bS5nb1RvUHJvamVjdCA9IGZ1bmN0aW9uKCkge1xuICAgICAgJHN0YXRlLmdvKCdhcHAucHJvamVjdHMnLCB7IG9iajogJ2VkaXQnLCByZXNvdXJjZTogdm0uYWN0dWFsUHJvamVjdCB9KTtcbiAgICB9XG5cbiAgICB2bS50b3RhbENvc3QgPSBmdW5jdGlvbigpIHtcbiAgICAgIHZhciBlc3RpbWF0ZWRfY29zdCA9IDA7XG5cbiAgICAgIHZtLmFjdHVhbFByb2plY3QudGFza3MuZm9yRWFjaChmdW5jdGlvbih0YXNrKSB7XG4gICAgICAgIGVzdGltYXRlZF9jb3N0ICs9IChwYXJzZUZsb2F0KHZtLmFjdHVhbFByb2plY3QuaG91cl92YWx1ZV9maW5hbCkgKiB0YXNrLmVzdGltYXRlZF90aW1lKTtcbiAgICAgIH0pO1xuICAgICAgcmV0dXJuIGVzdGltYXRlZF9jb3N0LnRvTG9jYWxlU3RyaW5nKCdQdC1icicsIHsgbWluaW11bUZyYWN0aW9uRGlnaXRzOiAyIH0pO1xuICAgIH1cblxuICAgIHZtLmZpbmFsaXplUHJvamVjdCA9IGZ1bmN0aW9uKCkge1xuICAgICAgdmFyIGNvbmZpcm0gPSAkbWREaWFsb2cuY29uZmlybSgpXG4gICAgICAgICAgLnRpdGxlKCdGaW5hbGl6YXIgUHJvamV0bycpXG4gICAgICAgICAgLnRleHRDb250ZW50KCdUZW0gY2VydGV6YSBxdWUgZGVzZWphIGZpbmFsaXphciBvIHByb2pldG8gJyArIHZtLmFjdHVhbFByb2plY3QubmFtZSArICc/JylcbiAgICAgICAgICAub2soJ1NpbScpXG4gICAgICAgICAgLmNhbmNlbCgnTsOjbycpO1xuXG4gICAgICAkbWREaWFsb2cuc2hvdyhjb25maXJtKS50aGVuKGZ1bmN0aW9uKCkge1xuICAgICAgICBQcm9qZWN0c1NlcnZpY2UuZmluYWxpemUoeyBwcm9qZWN0X2lkOiB2bS5hY3R1YWxQcm9qZWN0LmlkIH0pLnRoZW4oZnVuY3Rpb24oKSB7XG4gICAgICAgICAgUHJUb2FzdC5zdWNjZXNzKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMucHJvamVjdEVuZGVkU3VjY2VzcycpKTtcbiAgICAgICAgICBvbkFjdGl2YXRlKCk7XG4gICAgICAgICAgdm0uc2VhcmNoKCk7XG4gICAgICAgIH0sIGZ1bmN0aW9uKCkge1xuICAgICAgICAgIFByVG9hc3QuRXJyb3IoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5wcm9qZWN0RW5kZWRFcnJvcicpKTtcbiAgICAgICAgfSk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICAvLyBpbnN0YW50aWF0ZSBiYXNlIGNvbnRyb2xsZXJcbiAgICAkY29udHJvbGxlcignQ1JVRENvbnRyb2xsZXInLCB7IHZtOiB2bSwgbW9kZWxTZXJ2aWNlOiBEYXNoYm9hcmRzU2VydmljZSwgb3B0aW9uczoge30gfSk7XG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb25maWcocm91dGVzKTtcblxuICAvKipcbiAgICogQXJxdWl2byBkZSBjb25maWd1cmHDp8OjbyBjb20gYXMgcm90YXMgZXNwZWPDrWZpY2FzIGRvIHJlY3Vyc28gcHJvamVjdFxuICAgKlxuICAgKiBAcGFyYW0ge2FueX0gJHN0YXRlUHJvdmlkZXJcbiAgICogQHBhcmFtIHthbnl9IEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyXG4gICAgICAuc3RhdGUoJ2FwcC5kYXNoYm9hcmQnLCB7XG4gICAgICAgIHVybDogJy9kYXNoYm9hcmRzJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9kYXNoYm9hcmQvZGFzaGJvYXJkLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnRGFzaGJvYXJkQ29udHJvbGxlciBhcyBkYXNoYm9hcmRDdHJsJyxcbiAgICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IHRydWUgfSxcbiAgICAgICAgb2JqOiB7IHJlc291cmNlOiBudWxsIH1cbiAgICAgIH0pO1xuICB9XG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZhY3RvcnkoJ0Rhc2hib2FyZHNTZXJ2aWNlJywgRGFzaGJvYXJkc1NlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gRGFzaGJvYXJkc1NlcnZpY2Uoc2VydmljZUZhY3RvcnkpIHtcbiAgICByZXR1cm4gc2VydmljZUZhY3RvcnkoJ2Rhc2hib2FyZHMnLCB7XG4gICAgICBhY3Rpb25zOiB7IH0sXG4gICAgICBpbnN0YW5jZTogeyB9XG4gICAgfSk7XG4gIH1cblxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb25maWcocm91dGVzKTtcblxuICAvKipcbiAgICogQXJxdWl2byBkZSBjb25maWd1cmHDp8OjbyBjb20gYXMgcm90YXMgZXNwZWPDrWZpY2FzIGRvIHJlY3Vyc28gdXNlclxuICAgKlxuICAgKiBAcGFyYW0ge2FueX0gJHN0YXRlUHJvdmlkZXJcbiAgICogQHBhcmFtIHthbnl9IEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyXG4gICAgICAuc3RhdGUoJ2FwcC5kaW5hbWljLXF1ZXJ5Jywge1xuICAgICAgICB1cmw6ICcvY29uc3VsdGFzLWRpbmFtaWNhcycsXG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvZGluYW1pYy1xdWVyeXMvZGluYW1pYy1xdWVyeXMuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdEaW5hbWljUXVlcnlzQ29udHJvbGxlciBhcyBkaW5hbWljUXVlcnlDdHJsJyxcbiAgICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IHRydWUsIG5lZWRQcm9maWxlOiBbJ2FkbWluJ10gfVxuICAgICAgfSk7XG5cbiAgfVxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5mYWN0b3J5KCdEaW5hbWljUXVlcnlTZXJ2aWNlJywgRGluYW1pY1F1ZXJ5U2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBEaW5hbWljUXVlcnlTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCdkaW5hbWljUXVlcnknLCB7XG4gICAgICAvKipcbiAgICAgICAqIGHDp8OjbyBhZGljaW9uYWRhIHBhcmEgcGVnYXIgdW1hIGxpc3RhIGRlIG1vZGVscyBleGlzdGVudGVzIG5vIHNlcnZpZG9yXG4gICAgICAgKi9cbiAgICAgIGFjdGlvbnM6IHtcbiAgICAgICAgZ2V0TW9kZWxzOiB7XG4gICAgICAgICAgbWV0aG9kOiAnR0VUJyxcbiAgICAgICAgICB1cmw6ICdtb2RlbHMnXG4gICAgICAgIH1cbiAgICAgIH0sXG4gICAgICBpbnN0YW5jZToge1xuICAgICAgfVxuICAgIH0pO1xuICB9XG5cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb250cm9sbGVyKCdEaW5hbWljUXVlcnlzQ29udHJvbGxlcicsIERpbmFtaWNRdWVyeXNDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIERpbmFtaWNRdWVyeXNDb250cm9sbGVyKCRjb250cm9sbGVyLCBEaW5hbWljUXVlcnlTZXJ2aWNlLCBsb2Rhc2gsIFByVG9hc3QsIC8vIE5PU09OQVJcbiAgICAkdHJhbnNsYXRlKSB7XG5cbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgLy9hY3Rpb25zXG4gICAgdm0ub25BY3RpdmF0ZSA9IG9uQWN0aXZhdGU7XG4gICAgdm0uYXBwbHlGaWx0ZXJzID0gYXBwbHlGaWx0ZXJzO1xuICAgIHZtLmxvYWRBdHRyaWJ1dGVzID0gbG9hZEF0dHJpYnV0ZXM7XG4gICAgdm0ubG9hZE9wZXJhdG9ycyA9IGxvYWRPcGVyYXRvcnM7XG4gICAgdm0uYWRkRmlsdGVyID0gYWRkRmlsdGVyO1xuICAgIHZtLmFmdGVyU2VhcmNoID0gYWZ0ZXJTZWFyY2g7XG4gICAgdm0ucnVuRmlsdGVyID0gcnVuRmlsdGVyO1xuICAgIHZtLmVkaXRGaWx0ZXIgPSBlZGl0RmlsdGVyO1xuICAgIHZtLmxvYWRNb2RlbHMgPSBsb2FkTW9kZWxzO1xuICAgIHZtLnJlbW92ZUZpbHRlciA9IHJlbW92ZUZpbHRlcjtcbiAgICB2bS5jbGVhciA9IGNsZWFyO1xuICAgIHZtLnJlc3RhcnQgPSByZXN0YXJ0O1xuXG4gICAgLy9oZXJkYSBvIGNvbXBvcnRhbWVudG8gYmFzZSBkbyBDUlVEXG4gICAgJGNvbnRyb2xsZXIoJ0NSVURDb250cm9sbGVyJywgeyB2bTogdm0sIG1vZGVsU2VydmljZTogRGluYW1pY1F1ZXJ5U2VydmljZSwgb3B0aW9uczoge1xuICAgICAgc2VhcmNoT25Jbml0OiBmYWxzZVxuICAgIH0gfSk7XG5cbiAgICBmdW5jdGlvbiBvbkFjdGl2YXRlKCkge1xuICAgICAgdm0ucmVzdGFydCgpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFByZXBhcmEgZSBhcGxpY2Egb3MgZmlsdHJvIHF1ZSB2w6NvIHNlciBlbnZpYWRvcyBwYXJhIG8gc2VydmnDp29cbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSBkZWZhdWx0UXVlcnlGaWx0ZXJzXG4gICAgICogQHJldHVybnNcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBhcHBseUZpbHRlcnMoZGVmYXVsdFF1ZXJ5RmlsdGVycykge1xuICAgICAgdmFyIHdoZXJlID0ge307XG5cbiAgICAgIC8qKlxuICAgICAgICogbyBzZXJ2acOnbyBlc3BlcmEgdW0gb2JqZXRvIGNvbTpcbiAgICAgICAqICBvIG5vbWUgZGUgdW0gbW9kZWxcbiAgICAgICAqICB1bWEgbGlzdGEgZGUgZmlsdHJvc1xuICAgICAgICovXG4gICAgICBpZiAodm0uYWRkZWRGaWx0ZXJzLmxlbmd0aCA+IDApIHtcbiAgICAgICAgdmFyIGFkZGVkRmlsdGVycyA9IGFuZ3VsYXIuY29weSh2bS5hZGRlZEZpbHRlcnMpO1xuXG4gICAgICAgIHdoZXJlLm1vZGVsID0gdm0uYWRkZWRGaWx0ZXJzWzBdLm1vZGVsLm5hbWU7XG5cbiAgICAgICAgZm9yICh2YXIgaW5kZXggPSAwOyBpbmRleCA8IGFkZGVkRmlsdGVycy5sZW5ndGg7IGluZGV4KyspIHtcbiAgICAgICAgICB2YXIgZmlsdGVyID0gYWRkZWRGaWx0ZXJzW2luZGV4XTtcblxuICAgICAgICAgIGZpbHRlci5tb2RlbCA9IG51bGw7XG4gICAgICAgICAgZmlsdGVyLmF0dHJpYnV0ZSA9IGZpbHRlci5hdHRyaWJ1dGUubmFtZTtcbiAgICAgICAgICBmaWx0ZXIub3BlcmF0b3IgPSBmaWx0ZXIub3BlcmF0b3IudmFsdWU7XG4gICAgICAgIH1cblxuICAgICAgICB3aGVyZS5maWx0ZXJzID0gYW5ndWxhci50b0pzb24oYWRkZWRGaWx0ZXJzKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHdoZXJlLm1vZGVsID0gdm0ucXVlcnlGaWx0ZXJzLm1vZGVsLm5hbWU7XG4gICAgICB9XG5cbiAgICAgIHJldHVybiBhbmd1bGFyLmV4dGVuZChkZWZhdWx0UXVlcnlGaWx0ZXJzLCB3aGVyZSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ2FycmVnYSB0b2RvcyBvcyBtb2RlbHMgY3JpYWRvcyBubyBzZXJ2aWRvciBjb20gc2V1cyBhdHJpYnV0b3NcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBsb2FkTW9kZWxzKCkge1xuICAgICAgLy9QZWdhIHRvZG9zIG9zIG1vZGVscyBkbyBzZXJ2ZXIgZSBtb250YSB1bWEgbGlzdGEgcHJvIENvbWJvQm94XG4gICAgICBEaW5hbWljUXVlcnlTZXJ2aWNlLmdldE1vZGVscygpLnRoZW4oZnVuY3Rpb24oZGF0YSkge1xuICAgICAgICB2bS5tb2RlbHMgPSBkYXRhO1xuICAgICAgICB2bS5xdWVyeUZpbHRlcnMubW9kZWwgPSB2bS5tb2RlbHNbMF07XG4gICAgICAgIHZtLmxvYWRBdHRyaWJ1dGVzKCk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDYXJyZWdhIG9zIGF0dHJpYnV0b3MgZG8gbW9kZWwgZXNjb2xoaWRvXG4gICAgICovXG4gICAgZnVuY3Rpb24gbG9hZEF0dHJpYnV0ZXMoKSB7XG4gICAgICB2bS5hdHRyaWJ1dGVzID0gdm0ucXVlcnlGaWx0ZXJzLm1vZGVsLmF0dHJpYnV0ZXM7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMuYXR0cmlidXRlID0gdm0uYXR0cmlidXRlc1swXTtcblxuICAgICAgdm0ubG9hZE9wZXJhdG9ycygpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENhcnJlZ2Egb3Mgb3BlcmFkb3JlcyBlc3BlY2lmaWNvcyBwYXJhIG8gdGlwbyBkbyBhdHJpYnV0b1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGxvYWRPcGVyYXRvcnMoKSB7XG4gICAgICB2YXIgb3BlcmF0b3JzID0gW1xuICAgICAgICB7IHZhbHVlOiAnPScsIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLmVxdWFscycpIH0sXG4gICAgICAgIHsgdmFsdWU6ICc8PicsIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLmRpZmVyZW50JykgfVxuICAgICAgXVxuXG4gICAgICBpZiAodm0ucXVlcnlGaWx0ZXJzLmF0dHJpYnV0ZS50eXBlLmluZGV4T2YoJ3ZhcnlpbmcnKSAhPT0gLTEpIHtcbiAgICAgICAgb3BlcmF0b3JzLnB1c2goeyB2YWx1ZTogJ2hhcycsXG4gICAgICAgICAgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudCgndmlld3MuZmllbGRzLnF1ZXJ5RGluYW1pYy5vcGVyYXRvcnMuY29udGVpbnMnKSB9KTtcbiAgICAgICAgb3BlcmF0b3JzLnB1c2goeyB2YWx1ZTogJ3N0YXJ0V2l0aCcsXG4gICAgICAgICAgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudCgndmlld3MuZmllbGRzLnF1ZXJ5RGluYW1pYy5vcGVyYXRvcnMuc3RhcnRXaXRoJykgfSk7XG4gICAgICAgIG9wZXJhdG9ycy5wdXNoKHsgdmFsdWU6ICdlbmRXaXRoJyxcbiAgICAgICAgICBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KCd2aWV3cy5maWVsZHMucXVlcnlEaW5hbWljLm9wZXJhdG9ycy5maW5pc2hXaXRoJykgfSk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBvcGVyYXRvcnMucHVzaCh7IHZhbHVlOiAnPicsXG4gICAgICAgICAgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudCgndmlld3MuZmllbGRzLnF1ZXJ5RGluYW1pYy5vcGVyYXRvcnMuYmlnZ2VyVGhhbicpIH0pO1xuICAgICAgICBvcGVyYXRvcnMucHVzaCh7IHZhbHVlOiAnPj0nLFxuICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLmVxdWFsc09yQmlnZ2VyVGhhbicpIH0pO1xuICAgICAgICBvcGVyYXRvcnMucHVzaCh7IHZhbHVlOiAnPCcsXG4gICAgICAgICAgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudCgndmlld3MuZmllbGRzLnF1ZXJ5RGluYW1pYy5vcGVyYXRvcnMubGVzc1RoYW4nKSB9KTtcbiAgICAgICAgb3BlcmF0b3JzLnB1c2goeyB2YWx1ZTogJzw9JyxcbiAgICAgICAgICBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KCd2aWV3cy5maWVsZHMucXVlcnlEaW5hbWljLm9wZXJhdG9ycy5lcXVhbHNPckxlc3NUaGFuJykgfSk7XG4gICAgICB9XG5cbiAgICAgIHZtLm9wZXJhdG9ycyA9IG9wZXJhdG9ycztcbiAgICAgIHZtLnF1ZXJ5RmlsdGVycy5vcGVyYXRvciA9IHZtLm9wZXJhdG9yc1swXTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBBZGljaW9uYS9lZGl0YSB1bSBmaWx0cm9cbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSBmb3JtIGVsZW1lbnRvIGh0bWwgZG8gZm9ybXVsw6FyaW8gcGFyYSB2YWxpZGHDp8O1ZXNcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBhZGRGaWx0ZXIoZm9ybSkge1xuICAgICAgaWYgKGFuZ3VsYXIuaXNVbmRlZmluZWQodm0ucXVlcnlGaWx0ZXJzLnZhbHVlKSB8fCB2bS5xdWVyeUZpbHRlcnMudmFsdWUgPT09ICcnKSB7XG4gICAgICAgIFByVG9hc3QuZXJyb3IoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy52YWxpZGF0ZS5maWVsZFJlcXVpcmVkJywgeyBmaWVsZDogJ3ZhbG9yJyB9KSk7XG4gICAgICAgIHJldHVybjtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIGlmICh2bS5pbmRleCA8IDApIHtcbiAgICAgICAgICB2bS5hZGRlZEZpbHRlcnMucHVzaChhbmd1bGFyLmNvcHkodm0ucXVlcnlGaWx0ZXJzKSk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgdm0uYWRkZWRGaWx0ZXJzW3ZtLmluZGV4XSA9IGFuZ3VsYXIuY29weSh2bS5xdWVyeUZpbHRlcnMpO1xuICAgICAgICAgIHZtLmluZGV4ID0gLTE7XG4gICAgICAgIH1cblxuICAgICAgICAvL3JlaW5pY2lhIG8gZm9ybXVsw6FyaW8gZSBhcyB2YWxpZGHDp8O1ZXMgZXhpc3RlbnRlc1xuICAgICAgICB2bS5xdWVyeUZpbHRlcnMgPSB7fTtcbiAgICAgICAgZm9ybS4kc2V0UHJpc3RpbmUoKTtcbiAgICAgICAgZm9ybS4kc2V0VW50b3VjaGVkKCk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhbGl6YSBhIHBlc3F1aXNhIHRlbmRvIG9zIGZpbHRyb3MgY29tbyBwYXLDom1ldHJvc1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIHJ1bkZpbHRlcigpIHtcbiAgICAgIHZtLnNlYXJjaCh2bS5wYWdpbmF0b3IuY3VycmVudFBhZ2UpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEdhdGlsaG8gYWNpb25hZG8gZGVwb2lzIGRhIHBlc3F1aXNhIHJlc3BvbnPDoXZlbCBwb3IgaWRlbnRpZmljYXIgb3MgYXRyaWJ1dG9zXG4gICAgICogY29udGlkb3Mgbm9zIGVsZW1lbnRvcyByZXN1bHRhbnRlcyBkYSBidXNjYVxuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IGRhdGEgZGFkb3MgcmVmZXJlbnRlIGFvIHJldG9ybm8gZGEgcmVxdWlzacOnw6NvXG4gICAgICovXG4gICAgZnVuY3Rpb24gYWZ0ZXJTZWFyY2goZGF0YSkge1xuICAgICAgdmFyIGtleXMgPSAoZGF0YS5pdGVtcy5sZW5ndGggPiAwKSA/IE9iamVjdC5rZXlzKGRhdGEuaXRlbXNbMF0pIDogW107XG5cbiAgICAgIC8vcmV0aXJhIHRvZG9zIG9zIGF0cmlidXRvcyBxdWUgY29tZcOnYW0gY29tICQuXG4gICAgICAvL0Vzc2VzIGF0cmlidXRvcyBzw6NvIGFkaWNpb25hZG9zIHBlbG8gc2VydmnDp28gZSBuw6NvIGRldmUgYXBhcmVjZXIgbmEgbGlzdGFnZW1cbiAgICAgIHZtLmtleXMgPSBsb2Rhc2guZmlsdGVyKGtleXMsIGZ1bmN0aW9uKGtleSkge1xuICAgICAgICByZXR1cm4gIWxvZGFzaC5zdGFydHNXaXRoKGtleSwgJyQnKTtcbiAgICAgIH0pXG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ29sb2FjYSBubyBmb3JtdWzDoXJpbyBvIGZpbHRybyBlc2NvbGhpZG8gcGFyYSBlZGnDp8Ojb1xuICAgICAqIEBwYXJhbSB7YW55fSAkaW5kZXggaW5kaWNlIG5vIGFycmF5IGRvIGZpbHRybyBlc2NvbGhpZG9cbiAgICAgKi9cbiAgICBmdW5jdGlvbiBlZGl0RmlsdGVyKCRpbmRleCkge1xuICAgICAgdm0uaW5kZXggPSAkaW5kZXg7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMgPSB2bS5hZGRlZEZpbHRlcnNbJGluZGV4XTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZW1vdmUgbyBmaWx0cm8gZXNjb2xoaWRvXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gJGluZGV4IGluZGljZSBubyBhcnJheSBkbyBmaWx0cm8gZXNjb2xoaWRvXG4gICAgICovXG4gICAgZnVuY3Rpb24gcmVtb3ZlRmlsdGVyKCRpbmRleCkge1xuICAgICAgdm0uYWRkZWRGaWx0ZXJzLnNwbGljZSgkaW5kZXgpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIExpbXBhIG8gZm9ybXVsw6FyaW8gY29ycmVudGVcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBjbGVhcigpIHtcbiAgICAgIC8vZ3VhcmRhIG8gaW5kaWNlIGRvIHJlZ2lzdHJvIHF1ZSBlc3TDoSBzZW5kbyBlZGl0YWRvXG4gICAgICB2bS5pbmRleCA9IC0xO1xuICAgICAgLy92aW5jdWxhZG8gYW9zIGNhbXBvcyBkbyBmb3JtdWzDoXJpb1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0ge1xuICAgICAgfTtcblxuICAgICAgaWYgKHZtLm1vZGVscykgdm0ucXVlcnlGaWx0ZXJzLm1vZGVsID0gdm0ubW9kZWxzWzBdO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlaW5pY2lhIGEgY29uc3RydcOnw6NvIGRhIHF1ZXJ5IGxpbXBhbmRvIHR1ZG9cbiAgICAgKlxuICAgICAqL1xuICAgIGZ1bmN0aW9uIHJlc3RhcnQoKSB7XG4gICAgICAvL2d1YXJkYSBhdHJpYnV0b3MgZG8gcmVzdWx0YWRvIGRhIGJ1c2NhIGNvcnJlbnRlXG4gICAgICB2bS5rZXlzID0gW107XG5cbiAgICAgIC8vZ3VhcmRhIG9zIGZpbHRyb3MgYWRpY2lvbmFkb3NcbiAgICAgIHZtLmFkZGVkRmlsdGVycyA9IFtdO1xuICAgICAgdm0uY2xlYXIoKTtcbiAgICAgIHZtLmxvYWRNb2RlbHMoKTtcbiAgICB9XG5cbiAgfVxuXG59KSgpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmFjdG9yeSgnbGFuZ3VhZ2VMb2FkZXInLCBMYW5ndWFnZUxvYWRlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBMYW5ndWFnZUxvYWRlcigkcSwgU3VwcG9ydFNlcnZpY2UsICRsb2csICRpbmplY3Rvcikge1xuICAgIHZhciBzZXJ2aWNlID0gdGhpcztcblxuICAgIHNlcnZpY2UudHJhbnNsYXRlID0gZnVuY3Rpb24obG9jYWxlKSB7XG4gICAgICByZXR1cm4ge1xuICAgICAgICBnbG9iYWw6ICRpbmplY3Rvci5nZXQobG9jYWxlICsgJy5pMThuLmdsb2JhbCcpLFxuICAgICAgICB2aWV3czogJGluamVjdG9yLmdldChsb2NhbGUgKyAnLmkxOG4udmlld3MnKSxcbiAgICAgICAgYXR0cmlidXRlczogJGluamVjdG9yLmdldChsb2NhbGUgKyAnLmkxOG4uYXR0cmlidXRlcycpLFxuICAgICAgICBkaWFsb2c6ICRpbmplY3Rvci5nZXQobG9jYWxlICsgJy5pMThuLmRpYWxvZycpLFxuICAgICAgICBtZXNzYWdlczogJGluamVjdG9yLmdldChsb2NhbGUgKyAnLmkxOG4ubWVzc2FnZXMnKSxcbiAgICAgICAgbW9kZWxzOiAkaW5qZWN0b3IuZ2V0KGxvY2FsZSArICcuaTE4bi5tb2RlbHMnKVxuICAgICAgfTtcbiAgICB9XG5cbiAgICAvLyByZXR1cm4gbG9hZGVyRm5cbiAgICByZXR1cm4gZnVuY3Rpb24ob3B0aW9ucykge1xuICAgICAgJGxvZy5pbmZvKCdDYXJyZWdhbmRvIG8gY29udGV1ZG8gZGEgbGluZ3VhZ2VtICcgKyBvcHRpb25zLmtleSk7XG5cbiAgICAgIHZhciBkZWZlcnJlZCA9ICRxLmRlZmVyKCk7XG5cbiAgICAgIC8vQ2FycmVnYSBhcyBsYW5ncyBxdWUgcHJlY2lzYW0gZSBlc3TDo28gbm8gc2Vydmlkb3IgcGFyYSBuw6NvIHByZWNpc2FyIHJlcGV0aXIgYXF1aVxuICAgICAgU3VwcG9ydFNlcnZpY2UubGFuZ3MoKS50aGVuKGZ1bmN0aW9uKGxhbmdzKSB7XG4gICAgICAgIC8vTWVyZ2UgY29tIG9zIGxhbmdzIGRlZmluaWRvcyBubyBzZXJ2aWRvclxuICAgICAgICB2YXIgZGF0YSA9IGFuZ3VsYXIubWVyZ2Uoc2VydmljZS50cmFuc2xhdGUob3B0aW9ucy5rZXkpLCBsYW5ncyk7XG5cbiAgICAgICAgcmV0dXJuIGRlZmVycmVkLnJlc29sdmUoZGF0YSk7XG4gICAgICB9LCBmdW5jdGlvbigpIHtcbiAgICAgICAgcmV0dXJuIGRlZmVycmVkLnJlc29sdmUoc2VydmljZS50cmFuc2xhdGUob3B0aW9ucy5rZXkpKTtcbiAgICAgIH0pO1xuXG4gICAgICByZXR1cm4gZGVmZXJyZWQucHJvbWlzZTtcbiAgICB9XG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZpbHRlcigndEF0dHInLCB0QXR0cik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiB0QXR0cigkZmlsdGVyKSB7XG4gICAgLyoqXG4gICAgICogRmlsdHJvIHBhcmEgdHJhZHXDp8OjbyBkZSB1bSBhdHJpYnV0byBkZSB1bSBtb2RlbFxuICAgICAqIFxuICAgICAqIEBwYXJhbSB7YW55fSBuYW1lIG5vbWUgZG8gYXRyaWJ1dG9cbiAgICAgKiBAcmV0dXJucyBvIG5vbWUgZG8gYXRyaWJ1dG8gdHJhZHV6aWRvIGNhc28gZW5jb250cmUgc2UgbsOjbyBvIG5vbWUgcGFzc2FkbyBwb3IgcGFyYW1ldHJvXG4gICAgICovICAgIFxuICAgIHJldHVybiBmdW5jdGlvbihuYW1lKSB7XG4gICAgICB2YXIga2V5ID0gJ2F0dHJpYnV0ZXMuJyArIG5hbWU7XG4gICAgICB2YXIgdHJhbnNsYXRlID0gJGZpbHRlcigndHJhbnNsYXRlJykoa2V5KTtcblxuICAgICAgcmV0dXJuICh0cmFuc2xhdGUgPT09IGtleSkgPyBuYW1lIDogdHJhbnNsYXRlO1xuICAgIH1cbiAgfVxuXG59KSgpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmlsdGVyKCd0QnJlYWRjcnVtYicsIHRCcmVhZGNydW1iKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIHRCcmVhZGNydW1iKCRmaWx0ZXIpIHtcbiAgICAvKipcbiAgICAgKiBGaWx0cm8gcGFyYSB0cmFkdcOnw6NvIGRvIGJyZWFkY3J1bWIgKHRpdHVsbyBkYSB0ZWxhIGNvbSByYXN0cmVpbylcbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSBpZCBjaGF2ZSBjb20gbyBub21lIGRvIHN0YXRlIHJlZmVyZW50ZSB0ZWxhXG4gICAgICogQHJldHVybnMgYSB0cmFkdcOnw6NvIGNhc28gZW5jb250cmUgc2UgbsOjbyBvIGlkIHBhc3NhZG8gcG9yIHBhcmFtZXRyb1xuICAgICAqL1xuICAgIHJldHVybiBmdW5jdGlvbihpZCkge1xuICAgICAgLy9wZWdhIGEgc2VndW5kYSBwYXJ0ZSBkbyBub21lIGRvIHN0YXRlLCByZXRpcmFuZG8gYSBwYXJ0ZSBhYnN0cmF0YSAoYXBwLilcbiAgICAgIHZhciBrZXkgPSAndmlld3MuYnJlYWRjcnVtYnMuJyArIGlkLnNwbGl0KCcuJylbMV07XG4gICAgICB2YXIgdHJhbnNsYXRlID0gJGZpbHRlcigndHJhbnNsYXRlJykoa2V5KTtcblxuICAgICAgcmV0dXJuICh0cmFuc2xhdGUgPT09IGtleSkgPyBpZCA6IHRyYW5zbGF0ZTtcbiAgICB9XG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZpbHRlcigndE1vZGVsJywgdE1vZGVsKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIHRNb2RlbCgkZmlsdGVyKSB7XG4gICAgLyoqXG4gICAgICogRmlsdHJvIHBhcmEgdHJhZHXDp8OjbyBkZSB1bSBhdHJpYnV0byBkZSB1bSBtb2RlbFxuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IG5hbWUgbm9tZSBkbyBhdHJpYnV0b1xuICAgICAqIEByZXR1cm5zIG8gbm9tZSBkbyBhdHJpYnV0byB0cmFkdXppZG8gY2FzbyBlbmNvbnRyZSBzZSBuw6NvIG8gbm9tZSBwYXNzYWRvIHBvciBwYXJhbWV0cm9cbiAgICAgKi9cbiAgICByZXR1cm4gZnVuY3Rpb24obmFtZSkge1xuICAgICAgdmFyIGtleSA9ICdtb2RlbHMuJyArIG5hbWUudG9Mb3dlckNhc2UoKTtcbiAgICAgIHZhciB0cmFuc2xhdGUgPSAkZmlsdGVyKCd0cmFuc2xhdGUnKShrZXkpO1xuXG4gICAgICByZXR1cm4gKHRyYW5zbGF0ZSA9PT0ga2V5KSA/IG5hbWUgOiB0cmFuc2xhdGU7XG4gICAgfVxuICB9XG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAucnVuKGF1dGhlbnRpY2F0aW9uTGlzdGVuZXIpO1xuXG4gIC8qKlxuICAgKiBMaXN0ZW4gYWxsIHN0YXRlIChwYWdlKSBjaGFuZ2VzLiBFdmVyeSB0aW1lIGEgc3RhdGUgY2hhbmdlIG5lZWQgdG8gdmVyaWZ5IHRoZSB1c2VyIGlzIGF1dGhlbnRpY2F0ZWQgb3Igbm90IHRvXG4gICAqIHJlZGlyZWN0IHRvIGNvcnJlY3QgcGFnZS4gV2hlbiBhIHVzZXIgY2xvc2UgdGhlIGJyb3dzZXIgd2l0aG91dCBsb2dvdXQsIHdoZW4gaGltIHJlb3BlbiB0aGUgYnJvd3NlciB0aGlzIGV2ZW50XG4gICAqIHJlYXV0aGVudGljYXRlIHRoZSB1c2VyIHdpdGggdGhlIHBlcnNpc3RlbnQgdG9rZW4gb2YgdGhlIGxvY2FsIHN0b3JhZ2UuXG4gICAqXG4gICAqIFdlIGRvbid0IGNoZWNrIGlmIHRoZSB0b2tlbiBpcyBleHBpcmVkIG9yIG5vdCBpbiB0aGUgcGFnZSBjaGFuZ2UsIGJlY2F1c2UgaXMgZ2VuZXJhdGUgYW4gdW5lY2Vzc2FyeSBvdmVyaGVhZC5cbiAgICogSWYgdGhlIHRva2VuIGlzIGV4cGlyZWQgd2hlbiB0aGUgdXNlciB0cnkgdG8gY2FsbCB0aGUgZmlyc3QgYXBpIHRvIGdldCBkYXRhLCBoaW0gd2lsbCBiZSBsb2dvZmYgYW5kIHJlZGlyZWN0XG4gICAqIHRvIGxvZ2luIHBhZ2UuXG4gICAqXG4gICAqIEBwYXJhbSAkcm9vdFNjb3BlXG4gICAqIEBwYXJhbSAkc3RhdGVcbiAgICogQHBhcmFtICRzdGF0ZVBhcmFtc1xuICAgKiBAcGFyYW0gQXV0aFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBhdXRoZW50aWNhdGlvbkxpc3RlbmVyKCRyb290U2NvcGUsICRzdGF0ZSwgR2xvYmFsLCBBdXRoLCBQclRvYXN0LCAvLyBOT1NPTkFSXG4gICAgJHRyYW5zbGF0ZSkge1xuXG4gICAgLy9vbmx5IHdoZW4gYXBwbGljYXRpb24gc3RhcnQgY2hlY2sgaWYgdGhlIGV4aXN0ZW50IHRva2VuIHN0aWxsIHZhbGlkXG4gICAgQXV0aC5yZW1vdGVWYWxpZGF0ZVRva2VuKCkudGhlbihmdW5jdGlvbigpIHtcbiAgICAgIC8vaWYgdGhlIHRva2VuIGlzIHZhbGlkIGNoZWNrIGlmIGV4aXN0cyB0aGUgdXNlciBiZWNhdXNlIHRoZSBicm93c2VyIGNvdWxkIGJlIGNsb3NlZFxuICAgICAgLy9hbmQgdGhlIHVzZXIgZGF0YSBpc24ndCBpbiBtZW1vcnlcbiAgICAgIGlmIChBdXRoLmN1cnJlbnRVc2VyID09PSBudWxsKSB7XG4gICAgICAgIEF1dGgudXBkYXRlQ3VycmVudFVzZXIoYW5ndWxhci5mcm9tSnNvbihsb2NhbFN0b3JhZ2UuZ2V0SXRlbSgndXNlcicpKSk7XG4gICAgICB9XG4gICAgfSk7XG5cbiAgICAvL0NoZWNrIGlmIHRoZSB0b2tlbiBzdGlsbCB2YWxpZC5cbiAgICAkcm9vdFNjb3BlLiRvbignJHN0YXRlQ2hhbmdlU3RhcnQnLCBmdW5jdGlvbihldmVudCwgdG9TdGF0ZSkge1xuICAgICAgaWYgKHRvU3RhdGUuZGF0YS5uZWVkQXV0aGVudGljYXRpb24gfHwgdG9TdGF0ZS5kYXRhLm5lZWRQcm9maWxlKSB7XG4gICAgICAgIC8vZG9udCB0cmFpdCB0aGUgc3VjY2VzcyBibG9jayBiZWNhdXNlIGFscmVhZHkgZGlkIGJ5IHRva2VuIGludGVyY2VwdG9yXG4gICAgICAgIEF1dGgucmVtb3RlVmFsaWRhdGVUb2tlbigpLmNhdGNoKGZ1bmN0aW9uKCkge1xuICAgICAgICAgIFByVG9hc3Qud2FybigkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLmxvZ2luLmxvZ291dEluYWN0aXZlJykpO1xuXG4gICAgICAgICAgaWYgKHRvU3RhdGUubmFtZSAhPT0gR2xvYmFsLmxvZ2luU3RhdGUpIHtcbiAgICAgICAgICAgICRzdGF0ZS5nbyhHbG9iYWwubG9naW5TdGF0ZSk7XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgZXZlbnQucHJldmVudERlZmF1bHQoKTtcbiAgICAgICAgfSk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICAvL2lmIHRoZSB1c2UgaXMgYXV0aGVudGljYXRlZCBhbmQgbmVlZCB0byBlbnRlciBpbiBsb2dpbiBwYWdlXG4gICAgICAgIC8vaGltIHdpbGwgYmUgcmVkaXJlY3RlZCB0byBob21lIHBhZ2VcbiAgICAgICAgaWYgKHRvU3RhdGUubmFtZSA9PT0gR2xvYmFsLmxvZ2luU3RhdGUgJiYgQXV0aC5hdXRoZW50aWNhdGVkKCkpIHtcbiAgICAgICAgICAkc3RhdGUuZ28oR2xvYmFsLmhvbWVTdGF0ZSk7XG4gICAgICAgICAgZXZlbnQucHJldmVudERlZmF1bHQoKTtcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pO1xuICB9XG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLnJ1bihhdXRob3JpemF0aW9uTGlzdGVuZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gYXV0aG9yaXphdGlvbkxpc3RlbmVyKCRyb290U2NvcGUsICRzdGF0ZSwgR2xvYmFsLCBBdXRoKSB7XG4gICAgLyoqXG4gICAgICogQSBjYWRhIG11ZGFuw6dhIGRlIGVzdGFkbyAoXCJww6FnaW5hXCIpIHZlcmlmaWNhIHNlIG8gdXN1w6FyaW8gdGVtIG8gcGVyZmlsXG4gICAgICogbmVjZXNzw6FyaW8gcGFyYSBvIGFjZXNzbyBhIG1lc21hXG4gICAgICovXG4gICAgJHJvb3RTY29wZS4kb24oJyRzdGF0ZUNoYW5nZVN0YXJ0JywgZnVuY3Rpb24oZXZlbnQsIHRvU3RhdGUpIHtcbiAgICAgIGlmICh0b1N0YXRlLmRhdGEgJiYgdG9TdGF0ZS5kYXRhLm5lZWRBdXRoZW50aWNhdGlvbiAmJlxuICAgICAgICB0b1N0YXRlLmRhdGEubmVlZFByb2ZpbGUgJiYgQXV0aC5hdXRoZW50aWNhdGVkKCkgJiZcbiAgICAgICAgIUF1dGguY3VycmVudFVzZXIuaGFzUHJvZmlsZSh0b1N0YXRlLmRhdGEubmVlZFByb2ZpbGUsIHRvU3RhdGUuZGF0YS5hbGxQcm9maWxlcykpIHtcblxuICAgICAgICAkc3RhdGUuZ28oR2xvYmFsLm5vdEF1dGhvcml6ZWRTdGF0ZSk7XG4gICAgICAgIGV2ZW50LnByZXZlbnREZWZhdWx0KCk7XG4gICAgICB9XG5cbiAgICB9KTtcbiAgfVxufSgpKTtcbiIsIihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uZmlnKHNwaW5uZXJJbnRlcmNlcHRvcik7XG5cbiAgZnVuY3Rpb24gc3Bpbm5lckludGVyY2VwdG9yKCRodHRwUHJvdmlkZXIsICRwcm92aWRlKSB7XG4gICAgLyoqXG4gICAgICogRXN0ZSBpbnRlcmNlcHRvciDDqSByZXNwb25zw6F2ZWwgcG9yIG1vc3RyYXIgZSBlc2NvbmRlciBvXG4gICAgICogY29tcG9uZW50ZSBQclNwaW5uZXIgc2VtcHJlIHF1ZSB1bWEgcmVxdWlzacOnw6NvIGFqYXhcbiAgICAgKiBpbmljaWFyIGUgZmluYWxpemFyLlxuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9ICRxXG4gICAgICogQHBhcmFtIHthbnl9ICRpbmplY3RvclxuICAgICAqIEByZXR1cm5zXG4gICAgICovXG4gICAgZnVuY3Rpb24gc2hvd0hpZGVTcGlubmVyKCRxLCAkaW5qZWN0b3IpIHtcbiAgICAgIHJldHVybiB7XG4gICAgICAgIHJlcXVlc3Q6IGZ1bmN0aW9uIChjb25maWcpIHtcbiAgICAgICAgICAkaW5qZWN0b3IuZ2V0KCdQclNwaW5uZXInKS5zaG93KCk7XG5cbiAgICAgICAgICByZXR1cm4gY29uZmlnO1xuICAgICAgICB9LFxuXG4gICAgICAgIHJlc3BvbnNlOiBmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgICAkaW5qZWN0b3IuZ2V0KCdQclNwaW5uZXInKS5oaWRlKCk7XG5cbiAgICAgICAgICByZXR1cm4gcmVzcG9uc2U7XG4gICAgICAgIH0sXG5cbiAgICAgICAgcmVzcG9uc2VFcnJvcjogZnVuY3Rpb24gKHJlamVjdGlvbikge1xuICAgICAgICAgICRpbmplY3Rvci5nZXQoJ1ByU3Bpbm5lcicpLmhpZGUoKTtcblxuICAgICAgICAgIHJldHVybiAkcS5yZWplY3QocmVqZWN0aW9uKTtcbiAgICAgICAgfVxuICAgICAgfTtcbiAgICB9XG5cbiAgICAvLyBEZWZpbmUgdW1hIGZhY3RvcnkgcGFyYSBvICRodHRwSW50ZXJjZXB0b3JcbiAgICAkcHJvdmlkZS5mYWN0b3J5KCdzaG93SGlkZVNwaW5uZXInLCBzaG93SGlkZVNwaW5uZXIpO1xuXG4gICAgLy8gQWRpY2lvbmEgYSBmYWN0b3J5IG5vIGFycmF5IGRlIGludGVyY2VwdG9ycyBkbyAkaHR0cFxuICAgICRodHRwUHJvdmlkZXIuaW50ZXJjZXB0b3JzLnB1c2goJ3Nob3dIaWRlU3Bpbm5lcicpO1xuICB9XG59KCkpO1xuIiwiLyplc2xpbnQgYW5ndWxhci9tb2R1bGUtZ2V0dGVyOiAwKi9cblxuKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbmZpZyh0b2tlbkludGVyY2VwdG9yKTtcblxuICAvKipcbiAgICogSW50ZXJjZXB0IGFsbCByZXNwb25zZSAoc3VjY2VzcyBvciBlcnJvcikgdG8gdmVyaWZ5IHRoZSByZXR1cm5lZCB0b2tlblxuICAgKlxuICAgKiBAcGFyYW0gJGh0dHBQcm92aWRlclxuICAgKiBAcGFyYW0gJHByb3ZpZGVcbiAgICogQHBhcmFtIEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiB0b2tlbkludGVyY2VwdG9yKCRodHRwUHJvdmlkZXIsICRwcm92aWRlLCBHbG9iYWwpIHtcblxuICAgIGZ1bmN0aW9uIHJlZGlyZWN0V2hlblNlcnZlckxvZ2dlZE91dCgkcSwgJGluamVjdG9yKSB7XG4gICAgICByZXR1cm4ge1xuICAgICAgICByZXF1ZXN0OiBmdW5jdGlvbihjb25maWcpIHtcbiAgICAgICAgICB2YXIgdG9rZW4gPSAkaW5qZWN0b3IuZ2V0KCdBdXRoJykuZ2V0VG9rZW4oKTtcblxuICAgICAgICAgIGlmICh0b2tlbikge1xuICAgICAgICAgICAgY29uZmlnLmhlYWRlcnNbJ0F1dGhvcml6YXRpb24nXSA9ICdCZWFyZXIgJyArIHRva2VuO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIHJldHVybiBjb25maWc7XG4gICAgICAgIH0sXG4gICAgICAgIHJlc3BvbnNlOiBmdW5jdGlvbihyZXNwb25zZSkge1xuICAgICAgICAgIC8vIGdldCBhIG5ldyByZWZyZXNoIHRva2VuIHRvIHVzZSBpbiB0aGUgbmV4dCByZXF1ZXN0XG4gICAgICAgICAgdmFyIHRva2VuID0gcmVzcG9uc2UuaGVhZGVycygnQXV0aG9yaXphdGlvbicpO1xuXG4gICAgICAgICAgaWYgKHRva2VuKSB7XG4gICAgICAgICAgICAkaW5qZWN0b3IuZ2V0KCdBdXRoJykuc2V0VG9rZW4odG9rZW4uc3BsaXQoJyAnKVsxXSk7XG4gICAgICAgICAgfVxuICAgICAgICAgIHJldHVybiByZXNwb25zZTtcbiAgICAgICAgfSxcbiAgICAgICAgcmVzcG9uc2VFcnJvcjogZnVuY3Rpb24ocmVqZWN0aW9uKSB7XG4gICAgICAgICAgLy8gSW5zdGVhZCBvZiBjaGVja2luZyBmb3IgYSBzdGF0dXMgY29kZSBvZiA0MDAgd2hpY2ggbWlnaHQgYmUgdXNlZFxuICAgICAgICAgIC8vIGZvciBvdGhlciByZWFzb25zIGluIExhcmF2ZWwsIHdlIGNoZWNrIGZvciB0aGUgc3BlY2lmaWMgcmVqZWN0aW9uXG4gICAgICAgICAgLy8gcmVhc29ucyB0byB0ZWxsIHVzIGlmIHdlIG5lZWQgdG8gcmVkaXJlY3QgdG8gdGhlIGxvZ2luIHN0YXRlXG4gICAgICAgICAgdmFyIHJlamVjdGlvblJlYXNvbnMgPSBbJ3Rva2VuX25vdF9wcm92aWRlZCcsICd0b2tlbl9leHBpcmVkJywgJ3Rva2VuX2Fic2VudCcsICd0b2tlbl9pbnZhbGlkJ107XG5cbiAgICAgICAgICB2YXIgdG9rZW5FcnJvciA9IGZhbHNlO1xuXG4gICAgICAgICAgYW5ndWxhci5mb3JFYWNoKHJlamVjdGlvblJlYXNvbnMsIGZ1bmN0aW9uKHZhbHVlKSB7XG4gICAgICAgICAgICBpZiAocmVqZWN0aW9uLmRhdGEgJiYgcmVqZWN0aW9uLmRhdGEuZXJyb3IgPT09IHZhbHVlKSB7XG4gICAgICAgICAgICAgIHRva2VuRXJyb3IgPSB0cnVlO1xuXG4gICAgICAgICAgICAgICRpbmplY3Rvci5nZXQoJ0F1dGgnKS5sb2dvdXQoKS50aGVuKGZ1bmN0aW9uKCkge1xuICAgICAgICAgICAgICAgIHZhciAkc3RhdGUgPSAkaW5qZWN0b3IuZ2V0KCckc3RhdGUnKTtcblxuICAgICAgICAgICAgICAgIC8vIGluIGNhc2UgbXVsdGlwbGUgYWpheCByZXF1ZXN0IGZhaWwgYXQgc2FtZSB0aW1lIGJlY2F1c2UgdG9rZW4gcHJvYmxlbXMsXG4gICAgICAgICAgICAgICAgLy8gb25seSB0aGUgZmlyc3Qgd2lsbCByZWRpcmVjdFxuICAgICAgICAgICAgICAgIGlmICghJHN0YXRlLmlzKEdsb2JhbC5sb2dpblN0YXRlKSkge1xuICAgICAgICAgICAgICAgICAgJHN0YXRlLmdvKEdsb2JhbC5sb2dpblN0YXRlKTtcblxuICAgICAgICAgICAgICAgICAgLy9jbG9zZSBhbnkgZGlhbG9nIHRoYXQgaXMgb3BlbmVkXG4gICAgICAgICAgICAgICAgICAkaW5qZWN0b3IuZ2V0KCdQckRpYWxvZycpLmNsb3NlKCk7XG5cbiAgICAgICAgICAgICAgICAgIGV2ZW50LnByZXZlbnREZWZhdWx0KCk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9KTtcblxuICAgICAgICAgIC8vZGVmaW5lIGRhdGEgdG8gZW1wdHkgYmVjYXVzZSBhbHJlYWR5IHNob3cgUHJUb2FzdCB0b2tlbiBtZXNzYWdlXG4gICAgICAgICAgaWYgKHRva2VuRXJyb3IpIHtcbiAgICAgICAgICAgIHJlamVjdGlvbi5kYXRhID0ge307XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbihyZWplY3Rpb24uaGVhZGVycykpIHtcbiAgICAgICAgICAgIC8vIG1hbnkgc2VydmVycyBlcnJvcnMgKGJ1c2luZXNzKSBhcmUgaW50ZXJjZXB0IGhlcmUgYnV0IGdlbmVyYXRlZCBhIG5ldyByZWZyZXNoIHRva2VuXG4gICAgICAgICAgICAvLyBhbmQgbmVlZCB1cGRhdGUgY3VycmVudCB0b2tlblxuICAgICAgICAgICAgdmFyIHRva2VuID0gcmVqZWN0aW9uLmhlYWRlcnMoJ0F1dGhvcml6YXRpb24nKTtcblxuICAgICAgICAgICAgaWYgKHRva2VuKSB7XG4gICAgICAgICAgICAgICRpbmplY3Rvci5nZXQoJ0F1dGgnKS5zZXRUb2tlbih0b2tlbi5zcGxpdCgnICcpWzFdKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9XG5cbiAgICAgICAgICByZXR1cm4gJHEucmVqZWN0KHJlamVjdGlvbik7XG4gICAgICAgIH1cbiAgICAgIH07XG4gICAgfVxuXG4gICAgLy8gU2V0dXAgZm9yIHRoZSAkaHR0cEludGVyY2VwdG9yXG4gICAgJHByb3ZpZGUuZmFjdG9yeSgncmVkaXJlY3RXaGVuU2VydmVyTG9nZ2VkT3V0JywgcmVkaXJlY3RXaGVuU2VydmVyTG9nZ2VkT3V0KTtcblxuICAgIC8vIFB1c2ggdGhlIG5ldyBmYWN0b3J5IG9udG8gdGhlICRodHRwIGludGVyY2VwdG9yIGFycmF5XG4gICAgJGh0dHBQcm92aWRlci5pbnRlcmNlcHRvcnMucHVzaCgncmVkaXJlY3RXaGVuU2VydmVyTG9nZ2VkT3V0Jyk7XG4gIH1cblxufSgpKTtcbiIsIihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uZmlnKHZhbGlkYXRpb25JbnRlcmNlcHRvcik7XG5cbiAgZnVuY3Rpb24gdmFsaWRhdGlvbkludGVyY2VwdG9yKCRodHRwUHJvdmlkZXIsICRwcm92aWRlKSB7XG4gICAgLyoqXG4gICAgICogRXN0ZSBpbnRlcmNlcHRvciDDqSByZXNwb25zw6F2ZWwgcG9yIG1vc3RyYXIgYXNcbiAgICAgKiBtZW5zYWdlbnMgZGUgZXJybyByZWZlcmVudGUgYXMgdmFsaWRhw6fDtWVzIGRvIGJhY2stZW5kXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gJHFcbiAgICAgKiBAcGFyYW0ge2FueX0gJGluamVjdG9yXG4gICAgICogQHJldHVybnNcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBzaG93RXJyb3JWYWxpZGF0aW9uKCRxLCAkaW5qZWN0b3IpIHtcbiAgICAgIHJldHVybiB7XG4gICAgICAgIHJlc3BvbnNlRXJyb3I6IGZ1bmN0aW9uIChyZWplY3Rpb24pIHtcbiAgICAgICAgICB2YXIgUHJUb2FzdCA9ICRpbmplY3Rvci5nZXQoJ1ByVG9hc3QnKTtcbiAgICAgICAgICB2YXIgJHRyYW5zbGF0ZSA9ICRpbmplY3Rvci5nZXQoJyR0cmFuc2xhdGUnKTtcblxuICAgICAgICAgIGlmIChyZWplY3Rpb24uY29uZmlnLmRhdGEgJiYgIXJlamVjdGlvbi5jb25maWcuZGF0YS5za2lwVmFsaWRhdGlvbikge1xuICAgICAgICAgICAgaWYgKHJlamVjdGlvbi5kYXRhICYmIHJlamVjdGlvbi5kYXRhLmVycm9yKSB7XG5cbiAgICAgICAgICAgICAgLy92ZXJpZmljYSBzZSBvY29ycmV1IGFsZ3VtIGVycm8gcmVmZXJlbnRlIGFvIHRva2VuXG4gICAgICAgICAgICAgIGlmIChyZWplY3Rpb24uZGF0YS5lcnJvci5zdGFydHNXaXRoKCd0b2tlbl8nKSkge1xuICAgICAgICAgICAgICAgIFByVG9hc3Qud2FybigkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLmxvZ2luLmxvZ291dEluYWN0aXZlJykpO1xuICAgICAgICAgICAgICB9IGVsc2UgaWYgKHJlamVjdGlvbi5kYXRhLmVycm9yICE9PSAnTm90IEZvdW5kJykge1xuICAgICAgICAgICAgICAgIFByVG9hc3QuZXJyb3IoJHRyYW5zbGF0ZS5pbnN0YW50KHJlamVjdGlvbi5kYXRhLmVycm9yKSk7XG4gICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgIFByVG9hc3QuZXJyb3JWYWxpZGF0aW9uKHJlamVjdGlvbi5kYXRhKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9XG5cbiAgICAgICAgICByZXR1cm4gJHEucmVqZWN0KHJlamVjdGlvbik7XG4gICAgICAgIH1cbiAgICAgIH07XG4gICAgfVxuXG4gICAgLy8gRGVmaW5lIHVtYSBmYWN0b3J5IHBhcmEgbyAkaHR0cEludGVyY2VwdG9yXG4gICAgJHByb3ZpZGUuZmFjdG9yeSgnc2hvd0Vycm9yVmFsaWRhdGlvbicsIHNob3dFcnJvclZhbGlkYXRpb24pO1xuXG4gICAgLy8gQWRpY2lvbmEgYSBmYWN0b3J5IG5vIGFycmF5IGRlIGludGVyY2VwdG9ycyBkbyAkaHR0cFxuICAgICRodHRwUHJvdmlkZXIuaW50ZXJjZXB0b3JzLnB1c2goJ3Nob3dFcnJvclZhbGlkYXRpb24nKTtcbiAgfVxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnRyb2xsZXIoJ0thbmJhbkNvbnRyb2xsZXInLCBLYW5iYW5Db250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIEthbmJhbkNvbnRyb2xsZXIoJGNvbnRyb2xsZXIsXG4gICAgVGFza3NTZXJ2aWNlLFxuICAgIFN0YXR1c1NlcnZpY2UsXG4gICAgUHJUb2FzdCxcbiAgICAkbWREaWFsb2csXG4gICAgJGRvY3VtZW50LFxuICAgIEF1dGgsXG4gICAgUHJvamVjdHNTZXJ2aWNlKSB7XG4gICAgLy9BdHRyaWJ1dGVzIEJsb2NrXG4gICAgdmFyIHZtID0gdGhpcztcbiAgICB2YXIgZmllbGRzID0gW1xuICAgICAgeyBuYW1lOiAnaWQnLCB0eXBlOiAnc3RyaW5nJyB9LFxuICAgICAgeyBuYW1lOiAnc3RhdHVzJywgbWFwOiAnc3RhdGUnLCB0eXBlOiAnc3RyaW5nJyB9LFxuICAgICAgeyBuYW1lOiAndGV4dCcsIG1hcDogJ2xhYmVsJywgdHlwZTogJ3N0cmluZycgfSxcbiAgICAgIHsgbmFtZTogJ3RhZ3MnLCB0eXBlOiAnc3RyaW5nJyB9XG4gICAgXTtcblxuICAgIHZtLm9uQWN0aXZhdGUgPSBmdW5jdGlvbigpIHtcbiAgICAgIHZtLnByb2plY3QgPSBsb2NhbFN0b3JhZ2UuZ2V0SXRlbSgncHJvamVjdCcpO1xuICAgICAgUHJvamVjdHNTZXJ2aWNlLnF1ZXJ5KHsgcHJvamVjdF9pZDogdm0ucHJvamVjdCB9KS50aGVuKGZ1bmN0aW9uKHJlc3BvbnNlKSB7XG4gICAgICAgIHZtLmFjdHVhbFByb2plY3QgPSByZXNwb25zZVswXTtcbiAgICAgIH0pXG4gICAgICB2bS5xdWVyeUZpbHRlcnMgPSB7IHByb2plY3RfaWQ6IHZtLnByb2plY3QgfTtcbiAgICAgIHZtLmlzTW92ZWQgPSBmYWxzZTtcbiAgICB9XG5cbiAgICB2bS5hcHBseUZpbHRlcnMgPSBmdW5jdGlvbihkZWZhdWx0UXVlcnlGaWx0ZXJzKSB7XG4gICAgICByZXR1cm4gYW5ndWxhci5leHRlbmQoZGVmYXVsdFF1ZXJ5RmlsdGVycywgdm0ucXVlcnlGaWx0ZXJzKTtcbiAgICB9XG5cbiAgICB2bS5hZnRlclNlYXJjaCA9IGZ1bmN0aW9uICgpIHtcbiAgICAgIHZhciBjb2x1bW5zID0gW107XG4gICAgICB2YXIgdGFza3MgPSBbXTtcblxuICAgICAgU3RhdHVzU2VydmljZS5xdWVyeSgpLnRoZW4oZnVuY3Rpb24ocmVzcG9uc2UpIHtcbiAgICAgICAgcmVzcG9uc2UuZm9yRWFjaChmdW5jdGlvbihzdGF0dXMpIHtcbiAgICAgICAgICBjb2x1bW5zLnB1c2goeyB0ZXh0OiBzdGF0dXMubmFtZSwgZGF0YUZpZWxkOiBzdGF0dXMuc2x1ZywgY29sbGFwc2libGU6IGZhbHNlIH0pO1xuICAgICAgICB9KTtcblxuICAgICAgICBpZiAodm0ucmVzb3VyY2VzLmxlbmd0aCA+IDApIHtcbiAgICAgICAgICB2bS5yZXNvdXJjZXMuZm9yRWFjaChmdW5jdGlvbih0YXNrKSB7XG4gICAgICAgICAgICB0YXNrcy5wdXNoKHtcbiAgICAgICAgICAgICAgaWQ6IHRhc2suaWQsXG4gICAgICAgICAgICAgIHN0YXRlOiB0YXNrLnN0YXR1cy5zbHVnLFxuICAgICAgICAgICAgICBsYWJlbDogdGFzay50aXRsZSxcbiAgICAgICAgICAgICAgdGFnczogdGFzay50eXBlLm5hbWUgKyAnLCAnICsgdGFzay5wcmlvcml0eS5uYW1lXG4gICAgICAgICAgICB9KVxuICAgICAgICAgIH0pO1xuXG4gICAgICAgICAgdmFyIHNvdXJjZSA9IHtcbiAgICAgICAgICAgIGxvY2FsRGF0YTogdGFza3MsXG4gICAgICAgICAgICBkYXRhVHlwZTogJ2FycmF5JyxcbiAgICAgICAgICAgIGRhdGFGaWVsZHM6IGZpZWxkc1xuICAgICAgICAgIH07XG4gICAgICAgICAgdmFyIGRhdGFBZGFwdGVyID0gbmV3ICQuanF4LmRhdGFBZGFwdGVyKHNvdXJjZSk7XG5cbiAgICAgICAgICB2bS5zZXR0aW5ncyA9IHtcbiAgICAgICAgICAgIHNvdXJjZTogZGF0YUFkYXB0ZXIsXG4gICAgICAgICAgICBjb2x1bW5zOiBjb2x1bW5zLFxuICAgICAgICAgICAgdGhlbWU6ICdsaWdodCdcbiAgICAgICAgICB9O1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIHZtLnNldHRpbmdzID0ge1xuICAgICAgICAgICAgc291cmNlOiBbe31dLFxuICAgICAgICAgICAgY29sdW1uczogY29sdW1ucyxcbiAgICAgICAgICAgIHRoZW1lOiAnbGlnaHQnXG4gICAgICAgICAgfTtcbiAgICAgICAgfVxuICAgICAgICB2bS5rYW5iYW5SZWFkeSA9IHRydWU7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICB2bS5vbkl0ZW1Nb3ZlZCA9IGZ1bmN0aW9uKGV2ZW50KSB7XG4gICAgICBpZiAoQXV0aC5jdXJyZW50VXNlci5pZCA9PT0gdm0uYWN0dWFsUHJvamVjdC5vd25lcikge1xuICAgICAgICB2bS5pc01vdmVkID0gdHJ1ZTtcbiAgICAgICAgVGFza3NTZXJ2aWNlLnF1ZXJ5KHsgdGFza19pZDogZXZlbnQuYXJncy5pdGVtSWQgfSkudGhlbihmdW5jdGlvbihyZXNwb25zZSkge1xuICAgICAgICAgIGlmICgocmVzcG9uc2VbMF0ubWlsZXN0b25lICYmIHJlc3BvbnNlWzBdLm1pbGVzdG9uZS5kb25lKSB8fCByZXNwb25zZVswXS5wcm9qZWN0LmRvbmUpIHtcbiAgICAgICAgICAgIFByVG9hc3QuZXJyb3IoJ07Do28gw6kgcG9zc8OtdmVsIG1vZGlmaWNhciBvIHN0YXR1cyBkZSB1bWEgdGFyZWZhIGZpbmFsaXphZGEuJyk7XG4gICAgICAgICAgICB2bS5hZnRlclNlYXJjaCgpO1xuICAgICAgICAgICAgdm0uaXNNb3ZlZCA9IGZhbHNlO1xuICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICBUYXNrc1NlcnZpY2UudXBkYXRlVGFza0J5S2FuYmFuKHtcbiAgICAgICAgICAgICAgcHJvamVjdF9pZDogdm0ucHJvamVjdCxcbiAgICAgICAgICAgICAgaWQ6IGV2ZW50LmFyZ3MuaXRlbUlkLFxuICAgICAgICAgICAgICBvbGRDb2x1bW46IGV2ZW50LmFyZ3Mub2xkQ29sdW1uLFxuICAgICAgICAgICAgICBuZXdDb2x1bW46IGV2ZW50LmFyZ3MubmV3Q29sdW1uIH0pLnRoZW4oZnVuY3Rpb24oKSB7XG4gICAgICAgICAgICAgICAgdm0uaXNNb3ZlZCA9IGZhbHNlO1xuICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICB9XG4gICAgICAgIH0pO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgdm0uYWZ0ZXJTZWFyY2goKTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICB2bS5vbkl0ZW1DbGlja2VkID0gZnVuY3Rpb24oZXZlbnQpIHtcbiAgICAgIGlmICghdm0uaXNNb3ZlZCkge1xuICAgICAgICBUYXNrc1NlcnZpY2UucXVlcnkoeyB0YXNrX2lkOiBldmVudC5hcmdzLml0ZW1JZCB9KS50aGVuKGZ1bmN0aW9uKHJlc3BvbnNlKSB7XG4gICAgICAgICAgdm0udGFza0luZm8gPSByZXNwb25zZVswXTtcbiAgICAgICAgICAkbWREaWFsb2cuc2hvdyh7XG4gICAgICAgICAgICBwYXJlbnQ6IGFuZ3VsYXIuZWxlbWVudCgkZG9jdW1lbnQuYm9keSksXG4gICAgICAgICAgICB0ZW1wbGF0ZVVybDogJ2NsaWVudC9hcHAva2FuYmFuL3Rhc2staW5mby1kaWFsb2cvdGFza0luZm8uaHRtbCcsXG4gICAgICAgICAgICBjb250cm9sbGVyQXM6ICd0YXNrSW5mb0N0cmwnLFxuICAgICAgICAgICAgY29udHJvbGxlcjogJ1Rhc2tJbmZvQ29udHJvbGxlcicsXG4gICAgICAgICAgICBiaW5kVG9Db250cm9sbGVyOiB0cnVlLFxuICAgICAgICAgICAgbG9jYWxzOiB7XG4gICAgICAgICAgICAgIHRhc2s6IHZtLnRhc2tJbmZvLFxuICAgICAgICAgICAgICBjbG9zZTogY2xvc2VcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICBlc2NhcGVUb0Nsb3NlOiB0cnVlLFxuICAgICAgICAgICAgY2xpY2tPdXRzaWRlVG9DbG9zZTogdHJ1ZVxuICAgICAgICAgIH0pO1xuICAgICAgICB9KTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHZtLmlzTW92ZWQgPSBmYWxzZTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICBmdW5jdGlvbiBjbG9zZSgpIHtcbiAgICAgICRtZERpYWxvZy5oaWRlKCk7XG4gICAgfVxuXG4gICAgLy8gaW5zdGFudGlhdGUgYmFzZSBjb250cm9sbGVyXG4gICAgJGNvbnRyb2xsZXIoJ0NSVURDb250cm9sbGVyJywgeyB2bTogdm0sIG1vZGVsU2VydmljZTogVGFza3NTZXJ2aWNlLCBvcHRpb25zOiB7IH0gfSk7XG5cbiAgfVxuXG59KSgpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKlxuICAgKiBBcnF1aXZvIGRlIGNvbmZpZ3VyYcOnw6NvIGNvbSBhcyByb3RhcyBlc3BlY8OtZmljYXMgZG8gcmVjdXJzbyBrYW5iYW5cbiAgICpcbiAgICogQHBhcmFtIHtvYmplY3R9ICRzdGF0ZVByb3ZpZGVyXG4gICAqIEBwYXJhbSB7b2JqZWN0fSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlclxuICAgICAgLnN0YXRlKCdhcHAua2FuYmFuJywge1xuICAgICAgICB1cmw6ICcva2FuYmFuJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9rYW5iYW4va2FuYmFuLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnS2FuYmFuQ29udHJvbGxlciBhcyBrYW5iYW5DdHJsJyxcbiAgICAgICAgZGF0YTogeyB9XG4gICAgICB9KTtcbiAgfVxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5mYWN0b3J5KCdLYW5iYW5TZXJ2aWNlJywgS2FuYmFuU2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiBLYW5iYW5TZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgdmFyIG1vZGVsID0gc2VydmljZUZhY3RvcnkoJ2thbmJhbicsIHtcbiAgICAgIGFjdGlvbnM6IHsgfSxcbiAgICAgIGluc3RhbmNlOiB7IH1cbiAgICB9KTtcblxuICAgIHJldHVybiBtb2RlbDtcbiAgfVxuXG59KCkpO1xuIiwiLyplc2xpbnQtZW52IGVzNiovXG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb250cm9sbGVyKCdNZW51Q29udHJvbGxlcicsIE1lbnVDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIE1lbnVDb250cm9sbGVyKCRtZFNpZGVuYXYsICRzdGF0ZSwgJG1kQ29sb3JzKSB7XG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIC8vQmxvY28gZGUgZGVjbGFyYWNvZXMgZGUgZnVuY29lc1xuICAgIHZtLm9wZW4gPSBvcGVuO1xuICAgIHZtLm9wZW5NZW51T3JSZWRpcmVjdFRvU3RhdGUgPSBvcGVuTWVudU9yUmVkaXJlY3RUb1N0YXRlO1xuXG4gICAgYWN0aXZhdGUoKTtcblxuICAgIGZ1bmN0aW9uIGFjdGl2YXRlKCkge1xuICAgICAgdmFyIG1lbnVQcmVmaXggPSAndmlld3MubGF5b3V0Lm1lbnUuJztcblxuICAgICAgLy8gQXJyYXkgY29udGVuZG8gb3MgaXRlbnMgcXVlIHPDo28gbW9zdHJhZG9zIG5vIG1lbnUgbGF0ZXJhbFxuICAgICAgdm0uaXRlbnNNZW51ID0gW1xuICAgICAgICB7IHN0YXRlOiAnYXBwLnByb2plY3RzJywgdGl0bGU6IG1lbnVQcmVmaXggKyAncHJvamVjdHMnLCBpY29uOiAnd29yaycsIHN1Ykl0ZW5zOiBbXSB9LFxuICAgICAgICB7IHN0YXRlOiAnYXBwLmRhc2hib2FyZCcsIHRpdGxlOiBtZW51UHJlZml4ICsgJ2Rhc2hib2FyZCcsIGljb246ICdkYXNoYm9hcmQnLCBzdWJJdGVuczogW10gfSxcbiAgICAgICAgeyBzdGF0ZTogJ2FwcC50YXNrcycsIHRpdGxlOiBtZW51UHJlZml4ICsgJ3Rhc2tzJywgaWNvbjogJ3ZpZXdfbGlzdCcsIHN1Ykl0ZW5zOiBbXSB9LFxuICAgICAgICB7IHN0YXRlOiAnYXBwLm1pbGVzdG9uZXMnLCB0aXRsZTogbWVudVByZWZpeCArICdtaWxlc3RvbmVzJywgaWNvbjogJ3ZpZXdfbW9kdWxlJywgc3ViSXRlbnM6IFtdIH0sXG4gICAgICAgIHsgc3RhdGU6ICdhcHAucmVsZWFzZXMnLCB0aXRsZTogbWVudVByZWZpeCArICdyZWxlYXNlcycsIGljb246ICdzdWJzY3JpcHRpb25zJywgc3ViSXRlbnM6IFtdIH0sXG4gICAgICAgIHsgc3RhdGU6ICdhcHAua2FuYmFuJywgdGl0bGU6IG1lbnVQcmVmaXggKyAna2FuYmFuJywgaWNvbjogJ3ZpZXdfY29sdW1uJywgc3ViSXRlbnM6IFtdIH0sXG4gICAgICAgIHsgc3RhdGU6ICdhcHAudmNzJywgdGl0bGU6IG1lbnVQcmVmaXggKyAndmNzJywgaWNvbjogJ2dyb3VwX3dvcmsnLCBzdWJJdGVuczogW10gfVxuICAgICAgICAvLyBDb2xvcXVlIHNldXMgaXRlbnMgZGUgbWVudSBhIHBhcnRpciBkZXN0ZSBwb250b1xuICAgICAgICAvKiB7XG4gICAgICAgICAgc3RhdGU6ICcjJywgdGl0bGU6IG1lbnVQcmVmaXggKyAnYWRtaW4nLCBpY29uOiAnc2V0dGluZ3NfYXBwbGljYXRpb25zJywgcHJvZmlsZXM6IFsnYWRtaW4nXSxcbiAgICAgICAgICBzdWJJdGVuczogW1xuICAgICAgICAgICAgeyBzdGF0ZTogJ2FwcC51c2VyJywgdGl0bGU6IG1lbnVQcmVmaXggKyAndXNlcicsIGljb246ICdwZW9wbGUnIH0sXG4gICAgICAgICAgICB7IHN0YXRlOiAnYXBwLm1haWwnLCB0aXRsZTogbWVudVByZWZpeCArICdtYWlsJywgaWNvbjogJ21haWwnIH0sXG4gICAgICAgICAgICB7IHN0YXRlOiAnYXBwLmF1ZGl0JywgdGl0bGU6IG1lbnVQcmVmaXggKyAnYXVkaXQnLCBpY29uOiAnc3RvcmFnZScgfSxcbiAgICAgICAgICAgIHsgc3RhdGU6ICdhcHAuZGluYW1pYy1xdWVyeScsIHRpdGxlOiBtZW51UHJlZml4ICsgJ2RpbmFtaWNRdWVyeScsIGljb246ICdsb2NhdGlvbl9zZWFyY2hpbmcnIH1cbiAgICAgICAgICBdXG4gICAgICAgIH0gKi9cbiAgICAgIF07XG5cbiAgICAgIC8qKlxuICAgICAgICogT2JqZXRvIHF1ZSBwcmVlbmNoZSBvIG5nLXN0eWxlIGRvIG1lbnUgbGF0ZXJhbCB0cm9jYW5kbyBhcyBjb3Jlc1xuICAgICAgICovXG4gICAgICB2bS5zaWRlbmF2U3R5bGUgPSB7XG4gICAgICAgIHRvcDoge1xuICAgICAgICAgICdib3JkZXItYm90dG9tJzogJzFweCBzb2xpZCByZ2IoMjEwLCAyMTAsIDIxMCknLFxuICAgICAgICAgICdiYWNrZ3JvdW5kLWltYWdlJzogJy13ZWJraXQtbGluZWFyLWdyYWRpZW50KHRvcCwgcmdiKDE0NCwgMTQ0LCAxNDQpLCByZ2IoMjEwLCAyMTAsIDIxMCkpJ1xuICAgICAgICB9LFxuICAgICAgICBjb250ZW50OiB7XG4gICAgICAgICAgJ2JhY2tncm91bmQtY29sb3InOiAncmdiKDIxMCwgMjEwLCAyMTApJ1xuICAgICAgICB9LFxuICAgICAgICB0ZXh0Q29sb3I6IHtcbiAgICAgICAgICBjb2xvcjogJyNGRkYnXG4gICAgICAgIH0sXG4gICAgICAgIGxpbmVCb3R0b206IHtcbiAgICAgICAgICAnYm9yZGVyLWJvdHRvbSc6ICcxcHggc29saWQgJyArIGdldENvbG9yKCdwcmltYXJ5LTQwMCcpXG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9XG5cbiAgICBmdW5jdGlvbiBvcGVuKCkge1xuICAgICAgJG1kU2lkZW5hdignbGVmdCcpLnRvZ2dsZSgpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIE3DqXRvZG8gcXVlIGV4aWJlIG8gc3ViIG1lbnUgZG9zIGl0ZW5zIGRvIG1lbnUgbGF0ZXJhbCBjYXNvIHRlbmhhIHN1YiBpdGVuc1xuICAgICAqIGNhc28gY29udHLDoXJpbyByZWRpcmVjaW9uYSBwYXJhIG8gc3RhdGUgcGFzc2FkbyBjb21vIHBhcsODwqJtZXRyb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIG9wZW5NZW51T3JSZWRpcmVjdFRvU3RhdGUoJG1kTWVudSwgZXYsIGl0ZW0pIHtcbiAgICAgIGlmIChhbmd1bGFyLmlzRGVmaW5lZChpdGVtLnN1Ykl0ZW5zKSAmJiBpdGVtLnN1Ykl0ZW5zLmxlbmd0aCA+IDApIHtcbiAgICAgICAgJG1kTWVudS5vcGVuKGV2KTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgICRzdGF0ZS5nbyhpdGVtLnN0YXRlLCB7IG9iajogbnVsbCB9KTtcbiAgICAgICAgJG1kU2lkZW5hdignbGVmdCcpLmNsb3NlKCk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gZ2V0Q29sb3IoY29sb3JQYWxldHRlcykge1xuICAgICAgcmV0dXJuICRtZENvbG9ycy5nZXRUaGVtZUNvbG9yKGNvbG9yUGFsZXR0ZXMpO1xuICAgIH1cblxuICB9XG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb250cm9sbGVyKCdNYWlsc0NvbnRyb2xsZXInLCBNYWlsc0NvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gTWFpbHNDb250cm9sbGVyKE1haWxzU2VydmljZSwgVXNlcnNTZXJ2aWNlLCBQckRpYWxvZywgUHJUb2FzdCwgLy8gTk9TT05BUlxuICAgICRxLCBsb2Rhc2gsICR0cmFuc2xhdGUsIEdsb2JhbCkge1xuXG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIHZtLmZpbHRlclNlbGVjdGVkID0gZmFsc2U7XG4gICAgdm0ub3B0aW9ucyA9IHtcbiAgICAgIHNraW46ICdrYW1hJyxcbiAgICAgIGxhbmd1YWdlOiAncHQtYnInLFxuICAgICAgYWxsb3dlZENvbnRlbnQ6IHRydWUsXG4gICAgICBlbnRpdGllczogdHJ1ZSxcbiAgICAgIGhlaWdodDogMzAwLFxuICAgICAgZXh0cmFQbHVnaW5zOiAnZGlhbG9nLGZpbmQsY29sb3JkaWFsb2cscHJldmlldyxmb3JtcyxpZnJhbWUsZmxhc2gnXG4gICAgfTtcblxuICAgIHZtLmxvYWRVc2VycyA9IGxvYWRVc2VycztcbiAgICB2bS5vcGVuVXNlckRpYWxvZyA9IG9wZW5Vc2VyRGlhbG9nO1xuICAgIHZtLmFkZFVzZXJNYWlsID0gYWRkVXNlck1haWw7XG4gICAgdm0uY2xlYW5Gb3JtID0gY2xlYW5Gb3JtO1xuICAgIHZtLnNlbmQgPSBzZW5kO1xuXG4gICAgYWN0aXZhdGUoKTtcblxuICAgIGZ1bmN0aW9uIGFjdGl2YXRlKCkge1xuICAgICAgdm0uY2xlYW5Gb3JtKCk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhbGl6YSBhIGJ1c2NhIHBlbG8gdXN1w6FyaW8gcmVtb3RhbWVudGVcbiAgICAgKlxuICAgICAqIEBwYXJhbXMge3N0cmluZ30gLSBSZWNlYmUgbyB2YWxvciBwYXJhIHNlciBwZXNxdWlzYWRvXG4gICAgICogQHJldHVybiB7cHJvbWlzc2V9IC0gUmV0b3JuYSB1bWEgcHJvbWlzc2UgcXVlIG8gY29tcG9uZXRlIHJlc29sdmVcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBsb2FkVXNlcnMoY3JpdGVyaWEpIHtcbiAgICAgIHZhciBkZWZlcnJlZCA9ICRxLmRlZmVyKCk7XG5cbiAgICAgIFVzZXJzU2VydmljZS5xdWVyeSh7XG4gICAgICAgIG5hbWVPckVtYWlsOiBjcml0ZXJpYSxcbiAgICAgICAgbm90VXNlcnM6IGxvZGFzaC5tYXAodm0ubWFpbC51c2VycywgbG9kYXNoLnByb3BlcnR5KCdpZCcpKS50b1N0cmluZygpLFxuICAgICAgICBsaW1pdDogNVxuICAgICAgfSkudGhlbihmdW5jdGlvbihkYXRhKSB7XG5cbiAgICAgICAgLy8gdmVyaWZpY2Egc2UgbmEgbGlzdGEgZGUgdXN1YXJpb3MgasOhIGV4aXN0ZSBvIHVzdcOhcmlvIGNvbSBvIGVtYWlsIHBlc3F1aXNhZG9cbiAgICAgICAgZGF0YSA9IGxvZGFzaC5maWx0ZXIoZGF0YSwgZnVuY3Rpb24odXNlcikge1xuICAgICAgICAgIHJldHVybiAhbG9kYXNoLmZpbmQodm0ubWFpbC51c2VycywgeyBlbWFpbDogdXNlci5lbWFpbCB9KTtcbiAgICAgICAgfSk7XG5cbiAgICAgICAgZGVmZXJyZWQucmVzb2x2ZShkYXRhKTtcbiAgICAgIH0pO1xuXG4gICAgICByZXR1cm4gZGVmZXJyZWQucHJvbWlzZTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBBYnJlIG8gZGlhbG9nIHBhcmEgcGVzcXVpc2EgZGUgdXN1w6FyaW9zXG4gICAgICovXG4gICAgZnVuY3Rpb24gb3BlblVzZXJEaWFsb2coKSB7XG4gICAgICB2YXIgY29uZmlnID0ge1xuICAgICAgICBsb2NhbHM6IHtcbiAgICAgICAgICBvbkluaXQ6IHRydWUsXG4gICAgICAgICAgdXNlckRpYWxvZ0lucHV0OiB7XG4gICAgICAgICAgICB0cmFuc2ZlclVzZXJGbjogdm0uYWRkVXNlck1haWxcbiAgICAgICAgICB9XG4gICAgICAgIH0sXG4gICAgICAgIGNvbnRyb2xsZXI6ICdVc2Vyc0RpYWxvZ0NvbnRyb2xsZXInLFxuICAgICAgICBjb250cm9sbGVyQXM6ICdjdHJsJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy91c2Vycy9kaWFsb2cvdXNlcnMtZGlhbG9nLmh0bWwnLFxuICAgICAgICBoYXNCYWNrZHJvcDogdHJ1ZVxuICAgICAgfTtcblxuICAgICAgUHJEaWFsb2cuY3VzdG9tKGNvbmZpZyk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQWRpY2lvbmEgbyB1c3XDoXJpbyBzZWxlY2lvbmFkbyBuYSBsaXN0YSBwYXJhIHF1ZSBzZWphIGVudmlhZG8gbyBlbWFpbFxuICAgICAqL1xuICAgIGZ1bmN0aW9uIGFkZFVzZXJNYWlsKHVzZXIpIHtcbiAgICAgIHZhciB1c2VycyA9IGxvZGFzaC5maW5kKHZtLm1haWwudXNlcnMsIHsgZW1haWw6IHVzZXIuZW1haWwgfSk7XG5cbiAgICAgIGlmICh2bS5tYWlsLnVzZXJzLmxlbmd0aCA+IDAgJiYgYW5ndWxhci5pc0RlZmluZWQodXNlcnMpKSB7XG4gICAgICAgIFByVG9hc3Qud2FybigkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnVzZXIudXNlckV4aXN0cycpKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHZtLm1haWwudXNlcnMucHVzaCh7IG5hbWU6IHVzZXIubmFtZSwgZW1haWw6IHVzZXIuZW1haWwgfSlcbiAgICAgIH1cbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFsaXphIG8gZW52aW8gZG8gZW1haWwgcGFyYSBhIGxpc3RhIGRlIHVzdcOhcmlvcyBzZWxlY2lvbmFkb3NcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBzZW5kKCkge1xuXG4gICAgICB2bS5tYWlsLiRzYXZlKCkudGhlbihmdW5jdGlvbihyZXNwb25zZSkge1xuICAgICAgICBpZiAocmVzcG9uc2UubGVuZ3RoID4gMCkge1xuICAgICAgICAgIHZhciBtc2cgPSAkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLm1haWwubWFpbEVycm9ycycpO1xuXG4gICAgICAgICAgZm9yICh2YXIgaT0wOyBpIDwgcmVzcG9uc2UubGVuZ3RoOyBpKyspIHtcbiAgICAgICAgICAgIG1zZyArPSByZXNwb25zZSArICdcXG4nO1xuICAgICAgICAgIH1cbiAgICAgICAgICBQclRvYXN0LmVycm9yKG1zZyk7XG4gICAgICAgICAgdm0uY2xlYW5Gb3JtKCk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgUHJUb2FzdC5zdWNjZXNzKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMubWFpbC5zZW5kTWFpbFN1Y2Nlc3MnKSk7XG4gICAgICAgICAgdm0uY2xlYW5Gb3JtKCk7XG4gICAgICAgIH1cbiAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIExpbXBhIG8gZm9ybXVsw6FyaW8gZGUgZW1haWxcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBjbGVhbkZvcm0oKSB7XG4gICAgICB2bS5tYWlsID0gbmV3IE1haWxzU2VydmljZSgpO1xuICAgICAgdm0ubWFpbC51c2VycyA9IFtdO1xuICAgIH1cblxuICB9XG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqXG4gICAqIEFycXVpdm8gZGUgY29uZmlndXJhw6fDo28gY29tIGFzIHJvdGFzIGVzcGVjw61maWNhcyBkbyByZWN1cnNvIGVtIHF1ZXN0w6NvXG4gICAqXG4gICAqIEBwYXJhbSB7YW55fSAkc3RhdGVQcm92aWRlclxuICAgKiBAcGFyYW0ge2FueX0gR2xvYmFsXG4gICAqL1xuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvdXRlcygkc3RhdGVQcm92aWRlciwgR2xvYmFsKSB7XG4gICAgJHN0YXRlUHJvdmlkZXJcbiAgICAgIC5zdGF0ZSgnYXBwLm1haWwnLCB7XG4gICAgICAgIHVybDogJy9lbWFpbCcsXG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvbWFpbC9tYWlscy1zZW5kLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnTWFpbHNDb250cm9sbGVyIGFzIG1haWxzQ3RybCcsXG4gICAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiB0cnVlLCBuZWVkUHJvZmlsZTogWydhZG1pbiddIH1cbiAgICAgIH0pO1xuXG4gIH1cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmFjdG9yeSgnTWFpbHNTZXJ2aWNlJywgTWFpbHNTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIE1haWxzU2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHJldHVybiBzZXJ2aWNlRmFjdG9yeSgnbWFpbHMnLCB7fSk7XG4gIH1cblxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnRyb2xsZXIoJ01pbGVzdG9uZXNDb250cm9sbGVyJywgTWlsZXN0b25lc0NvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gTWlsZXN0b25lc0NvbnRyb2xsZXIoJGNvbnRyb2xsZXIsXG4gICAgTWlsZXN0b25lc1NlcnZpY2UsXG4gICAgbW9tZW50LFxuICAgIFRhc2tzU2VydmljZSxcbiAgICBQclRvYXN0LFxuICAgICR0cmFuc2xhdGUsXG4gICAgJG1kRGlhbG9nLFxuICAgIEF1dGgpIHtcblxuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICB2bS5lc3RpbWF0ZWRQcmljZSA9IGVzdGltYXRlZFByaWNlO1xuXG4gICAgdm0ub25BY3RpdmF0ZSA9IGZ1bmN0aW9uKCkge1xuICAgICAgdm0uY3VycmVudFVzZXIgPSBBdXRoLmN1cnJlbnRVc2VyO1xuICAgICAgdm0ucHJvamVjdCA9IGxvY2FsU3RvcmFnZS5nZXRJdGVtKCdwcm9qZWN0Jyk7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMgPSB7IHByb2plY3RfaWQ6IHZtLnByb2plY3QgfTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBlc3RpbWF0ZWRQcmljZShtaWxlc3RvbmUpIHtcbiAgICAgIG1pbGVzdG9uZS5lc3RpbWF0ZWRfdmFsdWUgPSAwO1xuICAgICAgaWYobWlsZXN0b25lLnRhc2tzLmxlbmd0aCA+IDAgJiYgbWlsZXN0b25lLnByb2plY3QuaG91cl92YWx1ZV9maW5hbCkge1xuICAgICAgICBtaWxlc3RvbmUudGFza3MuZm9yRWFjaChmdW5jdGlvbih0YXNrKSB7XG4gICAgICAgICAgbWlsZXN0b25lLmVzdGltYXRlZF92YWx1ZSArPSAocGFyc2VGbG9hdChtaWxlc3RvbmUucHJvamVjdC5ob3VyX3ZhbHVlX2ZpbmFsKSAqIHRhc2suZXN0aW1hdGVkX3RpbWUpO1xuICAgICAgICB9KTtcbiAgICAgIH1cbiAgICAgIHJldHVybiBtaWxlc3RvbmUuZXN0aW1hdGVkX3ZhbHVlLnRvTG9jYWxlU3RyaW5nKCdQdC1icicsIHsgbWluaW11bUZyYWN0aW9uRGlnaXRzOiAyIH0pO1xuICAgIH1cblxuICAgIHZtLmVzdGltYXRlZFRpbWUgPSBmdW5jdGlvbiAobWlsZXN0b25lKSB7XG4gICAgICBtaWxlc3RvbmUuZXN0aW1hdGVkX3RpbWUgPSAwO1xuICAgICAgaWYobWlsZXN0b25lLnRhc2tzLmxlbmd0aCA+IDApIHtcbiAgICAgICAgbWlsZXN0b25lLnRhc2tzLmZvckVhY2goZnVuY3Rpb24odGFzaykge1xuICAgICAgICAgIG1pbGVzdG9uZS5lc3RpbWF0ZWRfdGltZSArPSB0YXNrLmVzdGltYXRlZF90aW1lO1xuICAgICAgICB9KTtcbiAgICAgIH1cbiAgICAgIG1pbGVzdG9uZS5lc3RpbWF0ZWRfdGltZSA9IG1pbGVzdG9uZS5lc3RpbWF0ZWRfdGltZSAvIDg7XG4gICAgICB2YXIgZGF0ZUVuZCA9IG1vbWVudChtaWxlc3RvbmUuZGF0ZV9lbmQpO1xuICAgICAgdmFyIGRhdGVCZWdpbiA9IG1vbWVudChtaWxlc3RvbmUuZGF0ZV9iZWdpbik7XG5cbiAgICAgIGlmIChkYXRlRW5kLmRpZmYoZGF0ZUJlZ2luLCAnZGF5cycpIDw9IG1pbGVzdG9uZS5lc3RpbWF0ZWRfdGltZSkge1xuICAgICAgICBtaWxlc3RvbmUuY29sb3JfZXN0aW1hdGVkX3RpbWUgPSB7IGNvbG9yOiAncmVkJyB9O1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgbWlsZXN0b25lLmNvbG9yX2VzdGltYXRlZF90aW1lID0geyBjb2xvcjogJ2dyZWVuJyB9O1xuICAgICAgfVxuICAgICAgcmV0dXJuIG1pbGVzdG9uZS5lc3RpbWF0ZWRfdGltZTtcbiAgICB9XG5cbiAgICB2bS5hcHBseUZpbHRlcnMgPSBmdW5jdGlvbihkZWZhdWx0UXVlcnlGaWx0ZXJzKSB7XG4gICAgICByZXR1cm4gYW5ndWxhci5leHRlbmQoZGVmYXVsdFF1ZXJ5RmlsdGVycywgdm0ucXVlcnlGaWx0ZXJzKTtcbiAgICB9XG5cbiAgICB2bS5iZWZvcmVTYXZlID0gZnVuY3Rpb24oKSB7XG4gICAgICB2bS5yZXNvdXJjZS5wcm9qZWN0X2lkID0gdm0ucHJvamVjdDtcbiAgICB9XG5cbiAgICB2bS5iZWZvcmVSZW1vdmUgPSBmdW5jdGlvbigpIHtcbiAgICAgIHZtLnJlc291cmNlLnByb2plY3RfaWQgPSB2bS5wcm9qZWN0O1xuICAgIH1cblxuICAgIHZtLmZvcm1hdERhdGUgPSBmdW5jdGlvbihkYXRlKSB7XG4gICAgICByZXR1cm4gbW9tZW50KGRhdGUpLmZvcm1hdCgnREQvTU0vWVlZWScpO1xuICAgIH1cblxuICAgIHZtLmFmdGVyRWRpdCA9IGZ1bmN0aW9uKCkge1xuICAgICAgdm0ucmVzb3VyY2UuZGF0ZV9iZWdpbiA9IG1vbWVudCh2bS5yZXNvdXJjZS5kYXRlX2JlZ2luKTtcbiAgICAgIHZtLnJlc291cmNlLmRhdGVfZW5kID0gbW9tZW50KHZtLnJlc291cmNlLmRhdGVfZW5kKTtcbiAgICB9XG5cbiAgICB2bS52aWV3ID0gZnVuY3Rpb24gKHJlc291cmNlKSB7XG4gICAgICB2bS5yZXNvdXJjZSA9IHJlc291cmNlO1xuICAgICAgdm0ub25WaWV3ID0gdHJ1ZTtcbiAgICAgIHZtLnZpZXdGb3JtID0gZmFsc2U7XG4gICAgICBjb25zb2xlLmxvZyhyZXNvdXJjZS5wcm9qZWN0KTtcbiAgICB9XG5cbiAgICB2bS5zZWFyY2hUYXNrID0gZnVuY3Rpb24gKHRhc2tUZXJtKSB7XG4gICAgICByZXR1cm4gVGFza3NTZXJ2aWNlLnF1ZXJ5KHtcbiAgICAgICAgbWlsZXN0b25lU2VhcmNoOiB0cnVlLFxuICAgICAgICBwcm9qZWN0X2lkOiB2bS5yZXNvdXJjZS5wcm9qZWN0X2lkLFxuICAgICAgICB0aXRsZTogdGFza1Rlcm1cbiAgICAgIH0pO1xuICAgIH1cblxuICAgIHZtLm9uVGFza0NoYW5nZSA9IGZ1bmN0aW9uKCkge1xuICAgICAgaWYgKHZtLnRhc2sgIT09IG51bGwgJiYgdm0ucmVzb3VyY2UudGFza3MuZmluZEluZGV4KGkgPT4gaS5pZCA9PT0gdm0udGFzay5pZCkgPT09IC0xKSB7XG4gICAgICAgIHZtLnJlc291cmNlLnRhc2tzLnB1c2godm0udGFzayk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgdm0ucmVtb3ZlVGFzayA9IGZ1bmN0aW9uKHRhc2spIHtcbiAgICAgIHZtLnJlc291cmNlLnRhc2tzLnNsaWNlKDApLmZvckVhY2goZnVuY3Rpb24oZWxlbWVudCkge1xuICAgICAgICBpZihlbGVtZW50LmlkID09PSB0YXNrLmlkKSB7XG4gICAgICAgICAgdm0ucmVzb3VyY2UudGFza3Muc3BsaWNlKHZtLnJlc291cmNlLnRhc2tzLmluZGV4T2YoZWxlbWVudCksIDEpO1xuICAgICAgICB9XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICB2bS5zYXZlVGFza3MgPSBmdW5jdGlvbigpIHtcbiAgICAgIFRhc2tzU2VydmljZS51cGRhdGVNaWxlc3RvbmUoe3Byb2plY3RfaWQ6IHZtLnJlc291cmNlLnByb2plY3RfaWQsIG1pbGVzdG9uZV9pZDogdm0ucmVzb3VyY2UuaWQsIHRhc2tzOiB2bS5yZXNvdXJjZS50YXNrc30pLnRoZW4oZnVuY3Rpb24oKXtcbiAgICAgICAgUHJUb2FzdC5zdWNjZXNzKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMuc2F2ZVN1Y2Nlc3MnKSk7XG4gICAgICAgIHZtLnZpZXdGb3JtID0gZmFsc2U7XG4gICAgICAgIHZtLm9uVmlldyA9IGZhbHNlO1xuICAgICAgfSwgZnVuY3Rpb24oKSB7XG4gICAgICAgIFByVG9hc3QuZXJyb3IoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5vcGVyYXRpb25FcnJvcicpKTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIHZtLmZpbmFsaXplID0gZnVuY3Rpb24obWlsZXN0b25lKSB7XG4gICAgICB2YXIgY29uZmlybSA9ICRtZERpYWxvZy5jb25maXJtKClcbiAgICAgICAgICAudGl0bGUoJ0ZpbmFsaXphciBTcHJpbnQnKVxuICAgICAgICAgIC50ZXh0Q29udGVudCgnVGVtIGNlcnRlemEgcXVlIGRlc2VqYSBmaW5hbGl6YXIgYSBzcHJpbnQgJyArIG1pbGVzdG9uZS50aXRsZSArICc/JylcbiAgICAgICAgICAub2soJ1NpbScpXG4gICAgICAgICAgLmNhbmNlbCgnTsOjbycpO1xuXG4gICAgICAkbWREaWFsb2cuc2hvdyhjb25maXJtKS50aGVuKGZ1bmN0aW9uKCkge1xuICAgICAgICBNaWxlc3RvbmVzU2VydmljZS5maW5hbGl6ZSh7IHByb2plY3RfaWQ6IHZtLnByb2plY3QsIG1pbGVzdG9uZV9pZDogbWlsZXN0b25lLmlkIH0pLnRoZW4oZnVuY3Rpb24oKSB7XG4gICAgICAgICAgUHJUb2FzdC5zdWNjZXNzKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMuc3ByaW50RW5kZWRTdWNjZXNzJykpO1xuICAgICAgICAgIHZtLnNlYXJjaCgpO1xuICAgICAgICB9LCBmdW5jdGlvbigpIHtcbiAgICAgICAgICBQclRvYXN0LkVycm9yKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMuc3ByaW50RW5kZWRFcnJvcicpKTtcbiAgICAgICAgfSk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICAvLyBpbnN0YW50aWF0ZSBiYXNlIGNvbnRyb2xsZXJcbiAgICAkY29udHJvbGxlcignQ1JVRENvbnRyb2xsZXInLCB7IHZtOiB2bSwgbW9kZWxTZXJ2aWNlOiBNaWxlc3RvbmVzU2VydmljZSwgb3B0aW9uczogeyB9IH0pO1xuXG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb25maWcocm91dGVzKTtcblxuICAvKipcbiAgICogQXJxdWl2byBkZSBjb25maWd1cmHDp8OjbyBjb20gYXMgcm90YXMgZXNwZWPDrWZpY2FzIGRvIHJlY3Vyc28gbWlsZXN0b25lc1xuICAgKlxuICAgKiBAcGFyYW0ge29iamVjdH0gJHN0YXRlUHJvdmlkZXJcbiAgICogQHBhcmFtIHtvYmplY3R9IEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyXG4gICAgICAuc3RhdGUoJ2FwcC5taWxlc3RvbmVzJywge1xuICAgICAgICB1cmw6ICcvbWlsZXN0b25lcycsXG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvbWlsZXN0b25lcy9taWxlc3RvbmVzLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnTWlsZXN0b25lc0NvbnRyb2xsZXIgYXMgbWlsZXN0b25lc0N0cmwnLFxuICAgICAgICBkYXRhOiB7IH1cbiAgICAgIH0pO1xuICB9XG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZhY3RvcnkoJ01pbGVzdG9uZXNTZXJ2aWNlJywgTWlsZXN0b25lc1NlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gTWlsZXN0b25lc1NlcnZpY2Uoc2VydmljZUZhY3RvcnkpIHtcbiAgICB2YXIgbW9kZWwgPSBzZXJ2aWNlRmFjdG9yeSgnbWlsZXN0b25lcycsIHtcbiAgICAgIGFjdGlvbnM6IHtcbiAgICAgICAgZmluYWxpemU6IHtcbiAgICAgICAgICBtZXRob2Q6ICdQT1NUJyxcbiAgICAgICAgICB1cmw6ICdmaW5hbGl6ZSdcbiAgICAgICAgfSxcbiAgICAgICAgdXBkYXRlUmVsZWFzZToge1xuICAgICAgICAgIG1ldGhvZDogJ1BPU1QnLFxuICAgICAgICAgIHVybDogJ3VwZGF0ZVJlbGVhc2UnXG4gICAgICAgIH1cbiAgICAgIH0sXG4gICAgICBpbnN0YW5jZTogeyB9XG4gICAgfSk7XG5cbiAgICByZXR1cm4gbW9kZWw7XG4gIH1cblxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5mYWN0b3J5KCdQcmlvcml0aWVzU2VydmljZScsIFByaW9yaXRpZXNTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIFByaW9yaXRpZXNTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgdmFyIG1vZGVsID0gc2VydmljZUZhY3RvcnkoJ3ByaW9yaXRpZXMnLCB7XG4gICAgICBhY3Rpb25zOiB7IH0sXG4gICAgICBpbnN0YW5jZTogeyB9XG4gICAgfSk7XG5cbiAgICByZXR1cm4gbW9kZWw7XG4gIH1cblxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnRyb2xsZXIoJ1Byb2plY3RzQ29udHJvbGxlcicsIFByb2plY3RzQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBQcm9qZWN0c0NvbnRyb2xsZXIoJGNvbnRyb2xsZXIsXG4gICAgUHJvamVjdHNTZXJ2aWNlLFxuICAgIEF1dGgsXG4gICAgUm9sZXNTZXJ2aWNlLFxuICAgIFVzZXJzU2VydmljZSxcbiAgICAkc3RhdGUsXG4gICAgJGZpbHRlcixcbiAgICAkc3RhdGVQYXJhbXMsXG4gICAgJHdpbmRvdykge1xuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICAvL0F0dHJpYnV0ZXMgQmxvY2tcblxuICAgIC8vRnVuY3Rpb25zIEJsb2NrXG4gICAgdm0ub25BY3RpdmF0ZSA9IG9uQWN0aXZhdGU7XG4gICAgdm0uYXBwbHlGaWx0ZXJzID0gYXBwbHlGaWx0ZXJzO1xuICAgIHZtLmJlZm9yZVNhdmUgPSBiZWZvcmVTYXZlO1xuICAgIHZtLnNlYXJjaFVzZXIgPSBzZWFyY2hVc2VyO1xuICAgIHZtLmFkZFVzZXIgPSBhZGRVc2VyO1xuICAgIHZtLnJlbW92ZVVzZXIgPSByZW1vdmVVc2VyO1xuICAgIHZtLnZpZXdQcm9qZWN0ID0gdmlld1Byb2plY3Q7XG5cbiAgICB2bS5yb2xlcyA9IHt9O1xuICAgIHZtLnVzZXJzID0gW107XG5cbiAgICBmdW5jdGlvbiBvbkFjdGl2YXRlKCkge1xuICAgICAgdm0uY3VycmVudFVzZXIgPSBBdXRoLmN1cnJlbnRVc2VyO1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0geyB1c2VyX2lkOiB2bS5jdXJyZW50VXNlci5pZCB9O1xuICAgICAgUm9sZXNTZXJ2aWNlLnF1ZXJ5KCkudGhlbihmdW5jdGlvbihyZXNwb25zZSkge1xuICAgICAgICB2bS5yb2xlcyA9IHJlc3BvbnNlO1xuICAgICAgICBpZiAoJHN0YXRlUGFyYW1zLm9iaiA9PT0gJ2VkaXQnKSB7XG4gICAgICAgICAgdm0uY2xlYW5Gb3JtKCk7XG4gICAgICAgICAgdm0udmlld0Zvcm0gPSB0cnVlO1xuICAgICAgICAgIHZtLnJlc291cmNlID0gJHN0YXRlUGFyYW1zLnJlc291cmNlO1xuICAgICAgICAgIHVzZXJzQXJyYXkodm0ucmVzb3VyY2UpO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKCdwcm9qZWN0Jyk7XG4gICAgICAgIH1cbiAgICAgIH0pO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGFwcGx5RmlsdGVycyhkZWZhdWx0UXVlcnlGaWx0ZXJzKSB7XG4gICAgICByZXR1cm4gYW5ndWxhci5leHRlbmQoZGVmYXVsdFF1ZXJ5RmlsdGVycywgdm0ucXVlcnlsdGVycyk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gYmVmb3JlU2F2ZSgpIHtcbiAgICAgIGlmICghdm0ucmVzb3VyY2Uub3duZXIpIHtcbiAgICAgICAgdm0ucmVzb3VyY2Uub3duZXIgPSBBdXRoLmN1cnJlbnRVc2VyLmlkO1xuICAgICAgfVxuICAgICAgdm0ucmVzb3VyY2UudXNlcl9pZCA9IEF1dGguY3VycmVudFVzZXIuaWQ7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gc2VhcmNoVXNlcigpIHtcbiAgICAgIHJldHVybiBVc2Vyc1NlcnZpY2UucXVlcnkoeyBuYW1lOiB2bS51c2VyTmFtZSB9KTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBhZGRVc2VyKHVzZXIpIHtcbiAgICAgIGlmICh1c2VyKSB7XG4gICAgICAgIHZtLnJlc291cmNlLnVzZXJzLnB1c2godXNlcik7XG4gICAgICAgIHZtLnVzZXJOYW1lID0gJyc7XG4gICAgICB9XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gcmVtb3ZlVXNlcihpbmRleCkge1xuICAgICAgdm0ucmVzb3VyY2UudXNlcnMuc3BsaWNlKGluZGV4LCAxKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBhcHBseUZpbHRlcnMoZGVmYXVsdFF1ZXJ5RmlsdGVycykge1xuICAgICAgcmV0dXJuIGFuZ3VsYXIuZXh0ZW5kKGRlZmF1bHRRdWVyeUZpbHRlcnMsIHZtLnF1ZXJ5RmlsdGVycyk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gdmlld1Byb2plY3QoKSB7XG4gICAgICAkc3RhdGUuZ28oJ2FwcC5kYXNoYm9hcmQnKTtcbiAgICB9XG5cbiAgICB2bS5hZnRlclNlYXJjaCA9IGZ1bmN0aW9uKCkge1xuICAgICAgaWYgKHZtLnJlc291cmNlcy5sZW5ndGggPiAwKSB7XG4gICAgICAgIHZtLnJlc291cmNlcy5mb3JFYWNoKGZ1bmN0aW9uKHByb2plY3QpIHtcbiAgICAgICAgICB1c2Vyc0FycmF5KHByb2plY3QpO1xuICAgICAgICB9KTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICBmdW5jdGlvbiB1c2Vyc0FycmF5KHByb2plY3QpIHtcbiAgICAgIHByb2plY3QudXNlcnMgPSBbXTtcbiAgICAgIGlmIChwcm9qZWN0LmNsaWVudF9pZCkge1xuICAgICAgICBwcm9qZWN0LmNsaWVudC5yb2xlID0gJGZpbHRlcignZmlsdGVyJykodm0ucm9sZXMsIHsgc2x1ZzogJ2NsaWVudCcgfSlbMF07XG4gICAgICAgIHByb2plY3QudXNlcnMucHVzaChwcm9qZWN0LmNsaWVudCk7XG4gICAgICB9XG4gICAgICBpZiAocHJvamVjdC5kZXZfaWQpIHtcbiAgICAgICAgcHJvamVjdC5kZXZlbG9wZXIucm9sZSA9ICRmaWx0ZXIoJ2ZpbHRlcicpKHZtLnJvbGVzLCB7IHNsdWc6ICdkZXYnIH0pWzBdO1xuICAgICAgICBwcm9qZWN0LnVzZXJzLnB1c2gocHJvamVjdC5kZXZlbG9wZXIpO1xuICAgICAgfVxuICAgICAgaWYgKHByb2plY3Quc3Rha2Vob2xkZXJfaWQpIHtcbiAgICAgICAgcHJvamVjdC5zdGFrZWhvbGRlci5yb2xlID0gJGZpbHRlcignZmlsdGVyJykodm0ucm9sZXMsIHsgc2x1ZzogJ3N0YWtlaG9sZGVyJyB9KVswXTtcbiAgICAgICAgcHJvamVjdC51c2Vycy5wdXNoKHByb2plY3Quc3Rha2Vob2xkZXIpO1xuICAgICAgfVxuICAgIH1cblxuICAgIHZtLmhpc3RvcnlCYWNrID0gZnVuY3Rpb24oKSB7XG4gICAgICAkd2luZG93Lmhpc3RvcnkuYmFjaygpO1xuICAgIH1cblxuICAgIHZtLmFmdGVyU2F2ZSA9IGZ1bmN0aW9uKHJlc291cmNlKSB7XG4gICAgICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbSgncHJvamVjdCcsIHJlc291cmNlLmlkKTtcbiAgICAgICRzdGF0ZS5nbygnYXBwLmRhc2hib2FyZCcpO1xuICAgIH1cblxuICAgIC8vIGluc3RhbnRpYXRlIGJhc2UgY29udHJvbGxlclxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHsgdm06IHZtLCBtb2RlbFNlcnZpY2U6IFByb2plY3RzU2VydmljZSwgb3B0aW9uczogeyByZWRpcmVjdEFmdGVyU2F2ZTogZmFsc2UgfSB9KTtcbiAgfVxuXG59KSgpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKlxuICAgKiBBcnF1aXZvIGRlIGNvbmZpZ3VyYcOnw6NvIGNvbSBhcyByb3RhcyBlc3BlY8OtZmljYXMgZG8gcmVjdXJzbyBwcm9qZWN0XG4gICAqXG4gICAqIEBwYXJhbSB7YW55fSAkc3RhdGVQcm92aWRlclxuICAgKiBAcGFyYW0ge2FueX0gR2xvYmFsXG4gICAqL1xuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvdXRlcygkc3RhdGVQcm92aWRlciwgR2xvYmFsKSB7XG4gICAgJHN0YXRlUHJvdmlkZXJcbiAgICAgIC5zdGF0ZSgnYXBwLnByb2plY3RzJywge1xuICAgICAgICB1cmw6ICcvcHJvamVjdHMnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL3Byb2plY3RzL3Byb2plY3RzLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnUHJvamVjdHNDb250cm9sbGVyIGFzIHByb2plY3RzQ3RybCcsXG4gICAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiB0cnVlIH0sXG4gICAgICAgIHBhcmFtczogeyBvYmo6IG51bGwsIHJlc291cmNlOiBudWxsIH1cbiAgICAgIH0pO1xuICB9XG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZhY3RvcnkoJ1Byb2plY3RzU2VydmljZScsIFByb2plY3RzU2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiBQcm9qZWN0c1NlcnZpY2Uoc2VydmljZUZhY3RvcnkpIHtcbiAgICByZXR1cm4gc2VydmljZUZhY3RvcnkoJ3Byb2plY3RzJywge1xuICAgICAgYWN0aW9uczoge1xuICAgICAgICBmaW5hbGl6ZToge1xuICAgICAgICAgIG1ldGhvZDogJ1BPU1QnLFxuICAgICAgICAgIHVybDogJ2ZpbmFsaXplJ1xuICAgICAgICB9IH0sXG4gICAgICBpbnN0YW5jZTogeyB9XG4gICAgfSk7XG4gIH1cblxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnRyb2xsZXIoJ1JlbGVhc2VzQ29udHJvbGxlcicsIFJlbGVhc2VzQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBSZWxlYXNlc0NvbnRyb2xsZXIoJGNvbnRyb2xsZXIsXG4gICAgUmVsZWFzZXNTZXJ2aWNlLFxuICAgIE1pbGVzdG9uZXNTZXJ2aWNlLFxuICAgIEF1dGgsXG4gICAgUHJUb2FzdCxcbiAgICBtb21lbnQsXG4gICAgJG1kRGlhbG9nLFxuICAgICR0cmFuc2xhdGUpIHtcbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgLy9BdHRyaWJ1dGVzIEJsb2NrXG5cbiAgICAvL0Z1bmN0aW9ucyBCbG9ja1xuICAgIHZtLm9uQWN0aXZhdGUgPSBmdW5jdGlvbigpIHtcbiAgICAgIHZtLmN1cnJlbnRVc2VyID0gQXV0aC5jdXVycmVudFVzZXI7XG4gICAgICB2bS5wcm9qZWN0ID0gbG9jYWxTdG9yYWdlLmdldEl0ZW0oJ3Byb2plY3QnKTtcbiAgICAgIHZtLnF1ZXJ5RmlsdGVycyA9IHsgcHJvamVjdF9pZDogdm0ucHJvamVjdCB9O1xuICAgIH1cblxuICAgIHZtLmJlZm9yZVNhdmUgPSBmdW5jdGlvbigpIHtcbiAgICAgIHZtLnJlc291cmNlLnByb2plY3RfaWQgPSB2bS5wcm9qZWN0O1xuICAgIH1cblxuICAgIHZtLmJlZm9yZVJlbW92ZSA9IGZ1bmN0aW9uKCkge1xuICAgICAgdm0ucmVzb3VyY2UucHJvamVjdF9pZCA9IHZtLnByb2plY3Q7XG4gICAgfVxuXG4gICAgdm0udmlldyA9IGZ1bmN0aW9uIChyZXNvdXJjZSkge1xuICAgICAgdm0ucmVzb3VyY2UgPSByZXNvdXJjZTtcbiAgICAgIHZtLm9uVmlldyA9IHRydWU7XG4gICAgICB2bS52aWV3Rm9ybSA9IGZhbHNlO1xuICAgIH1cblxuICAgIHZtLmZpbmFsaXplID0gZnVuY3Rpb24ocmVsZWFzZSkge1xuICAgICAgdmFyIGNvbmZpcm0gPSAkbWREaWFsb2cuY29uZmlybSgpXG4gICAgICAgICAgLnRpdGxlKCdGaW5hbGl6YXIgUmVsZWFzZScpXG4gICAgICAgICAgLnRleHRDb250ZW50KCdUZW0gY2VydGV6YSBxdWUgZGVzZWphIGZpbmFsaXphciBhIHJlbGVhc2UgJyArIHJlbGVhc2UudGl0bGUgKyAnPycpXG4gICAgICAgICAgLm9rKCdTaW0nKVxuICAgICAgICAgIC5jYW5jZWwoJ07Do28nKTtcblxuICAgICAgJG1kRGlhbG9nLnNob3coY29uZmlybSkudGhlbihmdW5jdGlvbigpIHtcbiAgICAgICAgUmVsZWFzZXNTZXJ2aWNlLmZpbmFsaXplKHsgcHJvamVjdF9pZDogdm0ucHJvamVjdCwgcmVsZWFzZV9pZDogcmVsZWFzZS5pZCB9KS50aGVuKGZ1bmN0aW9uKCkge1xuICAgICAgICAgIFByVG9hc3Quc3VjY2VzcygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnJlbGVhc2VFbmRlZFN1Y2Nlc3MnKSk7XG4gICAgICAgICAgdm0uc2VhcmNoKCk7XG4gICAgICAgIH0sIGZ1bmN0aW9uKCkge1xuICAgICAgICAgIFByVG9hc3QuRXJyb3IoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5yZWxlYXNlRW5kZWRFcnJvcicpKTtcbiAgICAgICAgfSk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICB2bS5mb3JtYXREYXRlID0gZnVuY3Rpb24oZGF0ZSkge1xuICAgICAgcmV0dXJuIG1vbWVudChkYXRlKS5mb3JtYXQoJ0REL01NL1lZWVknKTtcbiAgICB9XG5cbiAgICB2bS5zZWFyY2hNaWxlc3RvbmUgPSBmdW5jdGlvbiAobWlsZXN0b25lVGVybSkge1xuICAgICAgcmV0dXJuIE1pbGVzdG9uZXNTZXJ2aWNlLnF1ZXJ5KHtcbiAgICAgICAgcmVsZWFzZVNlYXJjaDogdHJ1ZSxcbiAgICAgICAgcHJvamVjdF9pZDogdm0ucmVzb3VyY2UucHJvamVjdF9pZCxcbiAgICAgICAgdGl0bGU6IG1pbGVzdG9uZVRlcm1cbiAgICAgIH0pO1xuICAgIH1cblxuICAgIHZtLm9uTWlsZXN0b25lQ2hhbmdlID0gZnVuY3Rpb24oKSB7XG4gICAgICBpZiAodm0ubWlsZXN0b25lICE9PSBudWxsICYmIHZtLnJlc291cmNlLm1pbGVzdG9uZXMuZmluZEluZGV4KGkgPT4gaS5pZCA9PT0gdm0ubWlsZXN0b25lLmlkKSA9PT0gLTEpIHtcbiAgICAgICAgdm0ucmVzb3VyY2UubWlsZXN0b25lcy5wdXNoKHZtLm1pbGVzdG9uZSk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgdm0ucmVtb3ZlTWlsZXN0b25lID0gZnVuY3Rpb24obWlsZXN0b25lKSB7XG4gICAgICB2bS5yZXNvdXJjZS5taWxlc3RvbmVzLnNsaWNlKDApLmZvckVhY2goZnVuY3Rpb24oZWxlbWVudCkge1xuICAgICAgICBpZihlbGVtZW50LmlkID09PSBtaWxlc3RvbmUuaWQpIHtcbiAgICAgICAgICB2bS5yZXNvdXJjZS5taWxlc3RvbmVzLnNwbGljZSh2bS5yZXNvdXJjZS5taWxlc3RvbmVzLmluZGV4T2YoZWxlbWVudCksIDEpO1xuICAgICAgICB9XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICB2bS5zYXZlTWlsZXN0b25lcyA9IGZ1bmN0aW9uKCkge1xuICAgICAgTWlsZXN0b25lc1NlcnZpY2UudXBkYXRlUmVsZWFzZSh7cHJvamVjdF9pZDogdm0ucmVzb3VyY2UucHJvamVjdF9pZCwgcmVsZWFzZV9pZDogdm0ucmVzb3VyY2UuaWQsIG1pbGVzdG9uZXM6IHZtLnJlc291cmNlLm1pbGVzdG9uZXN9KS50aGVuKGZ1bmN0aW9uKCl7XG4gICAgICAgIFByVG9hc3Quc3VjY2VzcygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnNhdmVTdWNjZXNzJykpO1xuICAgICAgICB2bS52aWV3Rm9ybSA9IGZhbHNlO1xuICAgICAgICB2bS5vblZpZXcgPSBmYWxzZTtcbiAgICAgIH0sIGZ1bmN0aW9uKCkge1xuICAgICAgICBQclRvYXN0LmVycm9yKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMub3BlcmF0aW9uRXJyb3InKSk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICB2bS5lc3RpbWF0ZWRUaW1lID0gZnVuY3Rpb24gKG1pbGVzdG9uZSkge1xuICAgICAgbWlsZXN0b25lLmVzdGltYXRlZF90aW1lID0gMDtcbiAgICAgIGlmKG1pbGVzdG9uZS50YXNrcy5sZW5ndGggPiAwKSB7XG4gICAgICAgIG1pbGVzdG9uZS50YXNrcy5mb3JFYWNoKGZ1bmN0aW9uKHRhc2spIHtcbiAgICAgICAgICBtaWxlc3RvbmUuZXN0aW1hdGVkX3RpbWUgKz0gdGFzay5lc3RpbWF0ZWRfdGltZTtcbiAgICAgICAgfSk7XG4gICAgICB9XG4gICAgICByZXR1cm4gbWlsZXN0b25lLmVzdGltYXRlZF90aW1lIC8gODtcbiAgICB9XG5cbiAgICAvLyBpbnN0YW50aWF0ZSBiYXNlIGNvbnRyb2xsZXJcbiAgICAkY29udHJvbGxlcignQ1JVRENvbnRyb2xsZXInLCB7IHZtOiB2bSwgbW9kZWxTZXJ2aWNlOiBSZWxlYXNlc1NlcnZpY2UsIG9wdGlvbnM6IHsgfSB9KTtcblxuICB9XG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqXG4gICAqIEFycXVpdm8gZGUgY29uZmlndXJhw6fDo28gY29tIGFzIHJvdGFzIGVzcGVjw61maWNhcyBkbyByZWN1cnNvIHJlbGVhc2VzXG4gICAqXG4gICAqIEBwYXJhbSB7b2JqZWN0fSAkc3RhdGVQcm92aWRlclxuICAgKiBAcGFyYW0ge29iamVjdH0gR2xvYmFsXG4gICAqL1xuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvdXRlcygkc3RhdGVQcm92aWRlciwgR2xvYmFsKSB7XG4gICAgJHN0YXRlUHJvdmlkZXJcbiAgICAgIC5zdGF0ZSgnYXBwLnJlbGVhc2VzJywge1xuICAgICAgICB1cmw6ICcvcmVsZWFzZXMnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL3JlbGVhc2VzL3JlbGVhc2VzLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnUmVsZWFzZXNDb250cm9sbGVyIGFzIHJlbGVhc2VzQ3RybCcsXG4gICAgICAgIGRhdGE6IHsgfVxuICAgICAgfSk7XG4gIH1cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmFjdG9yeSgnUmVsZWFzZXNTZXJ2aWNlJywgUmVsZWFzZXNTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIFJlbGVhc2VzU2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHZhciBtb2RlbCA9IHNlcnZpY2VGYWN0b3J5KCdyZWxlYXNlcycsIHtcbiAgICAgIGFjdGlvbnM6IHtcbiAgICAgICAgZmluYWxpemU6IHtcbiAgICAgICAgICBtZXRob2Q6ICdQT1NUJyxcbiAgICAgICAgICB1cmw6ICdmaW5hbGl6ZSdcbiAgICAgICAgfVxuICAgICAgfSxcbiAgICAgIGluc3RhbmNlOiB7IH1cbiAgICB9KTtcblxuICAgIHJldHVybiBtb2RlbDtcbiAgfVxuXG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmlsdGVyKCdyb2xlc1N0cicsIHJvbGVzU3RyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvbGVzU3RyKGxvZGFzaCkge1xuICAgIC8qKlxuICAgICAqIEBwYXJhbSB7YXJyYXl9IHJvbGVzIGxpc3RhIGRlIHBlcmZpc1xuICAgICAqIEByZXR1cm4ge3N0cmluZ30gcGVyZmlzIHNlcGFyYWRvcyBwb3IgJywgJyAgXG4gICAgICovXG4gICAgcmV0dXJuIGZ1bmN0aW9uKHJvbGVzKSB7XG4gICAgICByZXR1cm4gbG9kYXNoLm1hcChyb2xlcywgJ3NsdWcnKS5qb2luKCcsICcpO1xuICAgIH07XG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5mYWN0b3J5KCdSb2xlc1NlcnZpY2UnLCBSb2xlc1NlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gUm9sZXNTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCdyb2xlcycpO1xuICB9XG5cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmFjdG9yeSgnU3RhdHVzU2VydmljZScsIFN0YXR1c1NlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gU3RhdHVzU2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHZhciBtb2RlbCA9IHNlcnZpY2VGYWN0b3J5KCdzdGF0dXMnLCB7XG4gICAgICBhY3Rpb25zOiB7IH0sXG4gICAgICBpbnN0YW5jZTogeyB9XG4gICAgfSk7XG5cbiAgICByZXR1cm4gbW9kZWw7XG4gIH1cblxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5mYWN0b3J5KCdTdXBwb3J0U2VydmljZScsIFN1cHBvcnRTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIFN1cHBvcnRTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCdzdXBwb3J0Jywge1xuICAgICAgYWN0aW9uczoge1xuICAgICAgLyoqXG4gICAgICAgKiBQZWdhIGFzIHRyYWR1w6fDtWVzIHF1ZSBlc3TDo28gbm8gc2Vydmlkb3JcbiAgICAgICAqXG4gICAgICAgKiBAcmV0dXJucyB7cHJvbWlzZX0gVW1hIHByb21pc2UgY29tIG8gcmVzdWx0YWRvIGRvIGNoYW1hZGEgbm8gYmFja2VuZFxuICAgICAgICovXG4gICAgICAgIGxhbmdzOiB7XG4gICAgICAgICAgbWV0aG9kOiAnR0VUJyxcbiAgICAgICAgICB1cmw6ICdsYW5ncycsXG4gICAgICAgICAgd3JhcDogZmFsc2UsXG4gICAgICAgICAgY2FjaGU6IHRydWVcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pO1xuICB9XG5cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmFjdG9yeSgnVGFza0NvbW1lbnRzU2VydmljZScsIFRhc2tDb21tZW50c1NlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gVGFza0NvbW1lbnRzU2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHZhciBtb2RlbCA9IHNlcnZpY2VGYWN0b3J5KCd0YXNrLWNvbW1lbnRzJywge1xuICAgICAgYWN0aW9uczoge1xuICAgICAgICBzYXZlVGFza0NvbW1lbnQ6IHtcbiAgICAgICAgICBtZXRob2Q6ICdQT1NUJyxcbiAgICAgICAgICB1cmw6ICdzYXZlVGFza0NvbW1lbnQnXG4gICAgICAgIH0sXG4gICAgICAgIHJlbW92ZVRhc2tDb21tZW50OiB7XG4gICAgICAgICAgbWV0aG9kOiAnUE9TVCcsXG4gICAgICAgICAgdXJsOiAncmVtb3ZlVGFza0NvbW1lbnQnXG4gICAgICAgIH1cbiAgICAgIH0sXG4gICAgICBpbnN0YW5jZTogeyB9XG4gICAgfSk7XG5cbiAgICByZXR1cm4gbW9kZWw7XG4gIH1cblxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZpbHRlcignZWxhcHNlZCcsIGZ1bmN0aW9uKCkge1xuICAgICAgcmV0dXJuIGZ1bmN0aW9uKGRhdGUpIHtcbiAgICAgICAgaWYgKCFkYXRlKSByZXR1cm47XG4gICAgICAgIHZhciB0aW1lID0gRGF0ZS5wYXJzZShkYXRlKSxcbiAgICAgICAgICB0aW1lTm93ID0gbmV3IERhdGUoKS5nZXRUaW1lKCksXG4gICAgICAgICAgZGlmZmVyZW5jZSA9IHRpbWVOb3cgLSB0aW1lLFxuICAgICAgICAgIHNlY29uZHMgPSBNYXRoLmZsb29yKGRpZmZlcmVuY2UgLyAxMDAwKSxcbiAgICAgICAgICBtaW51dGVzID0gTWF0aC5mbG9vcihzZWNvbmRzIC8gNjApLFxuICAgICAgICAgIGhvdXJzID0gTWF0aC5mbG9vcihtaW51dGVzIC8gNjApLFxuICAgICAgICAgIGRheXMgPSBNYXRoLmZsb29yKGhvdXJzIC8gMjQpLFxuICAgICAgICAgIG1vbnRocyA9IE1hdGguZmxvb3IoZGF5cyAvIDMwKTtcblxuICAgICAgICBpZiAobW9udGhzID4gMSkge1xuICAgICAgICAgIHJldHVybiBtb250aHMgKyAnIG1lc2VzIGF0csOhcyc7XG4gICAgICAgIH0gZWxzZSBpZiAobW9udGhzID09PSAxKSB7XG4gICAgICAgICAgcmV0dXJuICcxIG3DqnMgYXRyw6FzJztcbiAgICAgICAgfSBlbHNlIGlmIChkYXlzID4gMSkge1xuICAgICAgICAgIHJldHVybiBkYXlzICsgJyBkaWFzIGF0csOhcyc7XG4gICAgICAgIH0gZWxzZSBpZiAoZGF5cyA9PT0gMSkge1xuICAgICAgICAgIHJldHVybiAnMSBkaWEgYXRyw6FzJ1xuICAgICAgICB9IGVsc2UgaWYgKGhvdXJzID4gMSkge1xuICAgICAgICAgIHJldHVybiBob3VycyArICcgaG9yYXMgYXRyw6FzJztcbiAgICAgICAgfSBlbHNlIGlmIChob3VycyA9PT0gMSkge1xuICAgICAgICAgIHJldHVybiAndW1hIGhvcmEgYXRyw6FzJztcbiAgICAgICAgfSBlbHNlIGlmIChtaW51dGVzID4gMSkge1xuICAgICAgICAgIHJldHVybiBtaW51dGVzICsgJyBtaW51dG9zIGF0csOhcyc7XG4gICAgICAgIH0gZWxzZSBpZiAobWludXRlcyA9PT0gMSkge1xuICAgICAgICAgIHJldHVybiAndW0gbWludXRvIGF0csOhcyc7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgcmV0dXJuICdow6EgcG91Y29zIHNlZ3VuZG9zJztcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pXG4gICAgLmNvbnRyb2xsZXIoJ1Rhc2tzQ29udHJvbGxlcicsIFRhc2tzQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBUYXNrc0NvbnRyb2xsZXIoJGNvbnRyb2xsZXIsXG4gICAgVGFza3NTZXJ2aWNlLFxuICAgIFN0YXR1c1NlcnZpY2UsXG4gICAgUHJpb3JpdGllc1NlcnZpY2UsXG4gICAgVHlwZXNTZXJ2aWNlLFxuICAgIFRhc2tDb21tZW50c1NlcnZpY2UsXG4gICAgbW9tZW50LFxuICAgIEF1dGgsXG4gICAgUHJUb2FzdCxcbiAgICAkdHJhbnNsYXRlLFxuICAgICRmaWx0ZXIsXG4gICAgR2xvYmFsKSB7XG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIC8vQXR0cmlidXRlcyBCbG9ja1xuXG4gICAgLy9GdW5jdGlvbnMgQmxvY2tcbiAgICB2bS5vbkFjdGl2YXRlID0gb25BY3RpdmF0ZTtcbiAgICB2bS5hcHBseUZpbHRlcnMgPSBhcHBseUZpbHRlcnM7XG4gICAgdm0uYmVmb3JlU2F2ZSA9IGJlZm9yZVNhdmU7XG4gICAgdm0uYmVmb3JlUmVtb3ZlID0gYmVmb3JlUmVtb3ZlO1xuXG4gICAgZnVuY3Rpb24gb25BY3RpdmF0ZSgpIHtcbiAgICAgIHZtLmN1cnJlbnRVc2VyID0gQXV0aC5jdXJyZW50VXNlcjtcbiAgICAgIHZtLmltYWdlUGF0aCA9IEdsb2JhbC5pbWFnZVBhdGggKyAnL25vX2F2YXRhci5naWYnO1xuICAgICAgdm0ucHJvamVjdCA9IGxvY2FsU3RvcmFnZS5nZXRJdGVtKCdwcm9qZWN0Jyk7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMgPSB7IHByb2plY3RfaWQ6IHZtLnByb2plY3QgfTtcblxuICAgICAgU3RhdHVzU2VydmljZS5xdWVyeSgpLnRoZW4oZnVuY3Rpb24ocmVzcG9uc2UpIHtcbiAgICAgICAgdm0uc3RhdHVzID0gcmVzcG9uc2U7XG4gICAgICB9KTtcblxuICAgICAgUHJpb3JpdGllc1NlcnZpY2UucXVlcnkoKS50aGVuKGZ1bmN0aW9uKHJlc3BvbnNlKSB7XG4gICAgICAgIHZtLnByaW9yaXRpZXMgPSByZXNwb25zZTtcbiAgICAgIH0pO1xuXG4gICAgICBUeXBlc1NlcnZpY2UucXVlcnkoKS50aGVuKGZ1bmN0aW9uKHJlc3BvbnNlKSB7XG4gICAgICAgIHZtLnR5cGVzID0gcmVzcG9uc2U7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBhcHBseUZpbHRlcnMoZGVmYXVsdFF1ZXJ5RmlsdGVycykge1xuICAgICAgcmV0dXJuIGFuZ3VsYXIuZXh0ZW5kKGRlZmF1bHRRdWVyeUZpbHRlcnMsIHZtLnF1ZXJ5RmlsdGVycyk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gYmVmb3JlU2F2ZSgpIHtcbiAgICAgIHZtLnJlc291cmNlLnByb2plY3RfaWQgPSB2bS5wcm9qZWN0O1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGJlZm9yZVJlbW92ZSgpIHtcbiAgICAgIHZtLnJlc291cmNlLnByb2plY3RfaWQgPSB2bS5wcm9qZWN0O1xuICAgIH1cblxuICAgIHZtLnZpZXcgPSBmdW5jdGlvbiAocmVzb3VyY2UpIHtcbiAgICAgIHZtLnJlc291cmNlID0gcmVzb3VyY2U7XG4gICAgICB2bS5vblZpZXcgPSB0cnVlO1xuICAgICAgdm0udmlld0Zvcm0gPSBmYWxzZTtcbiAgICB9XG5cbiAgICB2bS5zYXZlQ29tbWVudCA9IGZ1bmN0aW9uKGNvbW1lbnQpIHtcbiAgICAgIHZhciBkZXNjcmlwdGlvbiA9ICcnO1xuICAgICAgdmFyIGNvbW1lbnRfaWQgPSBudWxsO1xuXG4gICAgICBpZiAoY29tbWVudCkge1xuICAgICAgICBkZXNjcmlwdGlvbiA9IHZtLmFuc3dlclxuICAgICAgICBjb21tZW50X2lkID0gY29tbWVudC5pZDtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIGRlc2NyaXB0aW9uID0gdm0uY29tbWVudDtcbiAgICAgIH1cbiAgICAgIFRhc2tDb21tZW50c1NlcnZpY2Uuc2F2ZVRhc2tDb21tZW50KHsgcHJvamVjdF9pZDogdm0ucHJvamVjdCwgdGFza19pZDogdm0ucmVzb3VyY2UuaWQsIGNvbW1lbnRfdGV4dDogZGVzY3JpcHRpb24sIGNvbW1lbnRfaWQ6IGNvbW1lbnRfaWQgfSkudGhlbihmdW5jdGlvbigpIHtcbiAgICAgICAgdm0uY29tbWVudCA9ICcnO1xuICAgICAgICB2bS5hbnN3ZXIgPSAnJztcbiAgICAgICAgdm0uc2VhcmNoKCk7XG4gICAgICAgIFByVG9hc3Quc3VjY2VzcygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnNhdmVTdWNjZXNzJykpO1xuICAgICAgfSwgZnVuY3Rpb24oKSB7XG4gICAgICAgIFByVG9hc3QuZXJyb3IoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5vcGVyYXRpb25FcnJvcicpKTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIHZtLnJlbW92ZUNvbW1lbnQgPSBmdW5jdGlvbihjb21tZW50KSB7XG4gICAgICBUYXNrQ29tbWVudHNTZXJ2aWNlLnJlbW92ZVRhc2tDb21tZW50KHsgY29tbWVudF9pZDogY29tbWVudC5pZCB9KS50aGVuKGZ1bmN0aW9uKCkge1xuICAgICAgICB2bS5zZWFyY2goKTtcbiAgICAgICAgUHJUb2FzdC5zdWNjZXNzKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMucmVtb3ZlU3VjY2VzcycpKTtcbiAgICAgIH0sIGZ1bmN0aW9uKCkge1xuICAgICAgICBQclRvYXN0LmVycm9yKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMub3BlcmF0aW9uRXJyb3InKSk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICB2bS5hZnRlclNlYXJjaCA9IGZ1bmN0aW9uKCkge1xuICAgICAgaWYgKHZtLnJlc291cmNlLmlkKSB7XG4gICAgICAgIHZtLnJlc291cmNlID0gJGZpbHRlcignZmlsdGVyJykodm0ucmVzb3VyY2VzLCB7IGlkOiB2bS5yZXNvdXJjZS5pZCB9KVswXTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICB2bS5maXhEYXRlID0gZnVuY3Rpb24oZGF0ZVN0cmluZykge1xuICAgICAgcmV0dXJuIG1vbWVudChkYXRlU3RyaW5nKTtcbiAgICB9XG5cbiAgICAvLyBpbnN0YW50aWF0ZSBiYXNlIGNvbnRyb2xsZXJcbiAgICAkY29udHJvbGxlcignQ1JVRENvbnRyb2xsZXInLCB7IHZtOiB2bSwgbW9kZWxTZXJ2aWNlOiBUYXNrc1NlcnZpY2UsIG9wdGlvbnM6IHsgc2tpcFBhZ2luYXRpb246IHRydWUgfSB9KTtcbiAgfVxuXG59KSgpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKlxuICAgKiBBcnF1aXZvIGRlIGNvbmZpZ3VyYcOnw6NvIGNvbSBhcyByb3RhcyBlc3BlY8OtZmljYXMgZG8gcmVjdXJzbyBwcm9qZWN0XG4gICAqXG4gICAqIEBwYXJhbSB7YW55fSAkc3RhdGVQcm92aWRlclxuICAgKiBAcGFyYW0ge2FueX0gR2xvYmFsXG4gICAqL1xuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvdXRlcygkc3RhdGVQcm92aWRlciwgR2xvYmFsKSB7XG4gICAgJHN0YXRlUHJvdmlkZXJcbiAgICAgIC5zdGF0ZSgnYXBwLnRhc2tzJywge1xuICAgICAgICB1cmw6ICcvdGFza3MnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL3Rhc2tzL3Rhc2tzLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnVGFza3NDb250cm9sbGVyIGFzIHRhc2tzQ3RybCcsXG4gICAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiB0cnVlfVxuICAgICAgfSk7XG4gIH1cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmFjdG9yeSgnVGFza3NTZXJ2aWNlJywgVGFza3NTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIFRhc2tzU2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHJldHVybiBzZXJ2aWNlRmFjdG9yeSgndGFza3MnLCB7XG4gICAgICBhY3Rpb25zOiB7XG4gICAgICAgIHVwZGF0ZU1pbGVzdG9uZToge1xuICAgICAgICAgIG1ldGhvZDogJ1BPU1QnLFxuICAgICAgICAgIHVybDogJ3VwZGF0ZU1pbGVzdG9uZSdcbiAgICAgICAgfSxcbiAgICAgICAgdXBkYXRlVGFza0J5S2FuYmFuOiB7XG4gICAgICAgICAgbWV0aG9kOiAnUE9TVCcsXG4gICAgICAgICAgdXJsOiAndXBkYXRlVGFza0J5S2FuYmFuJ1xuICAgICAgICB9XG4gICAgICB9LFxuICAgICAgaW5zdGFuY2U6IHsgfVxuICAgIH0pO1xuICB9XG5cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmFjdG9yeSgnVHlwZXNTZXJ2aWNlJywgVHlwZXNTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIFR5cGVzU2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHZhciBtb2RlbCA9IHNlcnZpY2VGYWN0b3J5KCd0eXBlcycsIHtcbiAgICAgIGFjdGlvbnM6IHsgfSxcbiAgICAgIGluc3RhbmNlOiB7IH1cbiAgICB9KTtcblxuICAgIHJldHVybiBtb2RlbDtcbiAgfVxuXG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29udHJvbGxlcignUHJvZmlsZUNvbnRyb2xsZXInLCBQcm9maWxlQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBQcm9maWxlQ29udHJvbGxlcihVc2Vyc1NlcnZpY2UsIEF1dGgsIFByVG9hc3QsICR0cmFuc2xhdGUsICR3aW5kb3csIG1vbWVudCkge1xuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICB2bS51cGRhdGUgPSB1cGRhdGU7XG4gICAgdm0uaGlzdG9yeUJhY2sgPSBoaXN0b3J5QmFjaztcblxuICAgIGFjdGl2YXRlKCk7XG5cbiAgICBmdW5jdGlvbiBhY3RpdmF0ZSgpIHtcbiAgICAgIHZtLnVzZXIgPSBhbmd1bGFyLmNvcHkoQXV0aC5jdXJyZW50VXNlcik7XG4gICAgICBpZiAodm0udXNlci5iaXJ0aGRheSkge1xuICAgICAgICB2bS51c2VyLmJpcnRoZGF5ID0gbW9tZW50KHZtLnVzZXIuYmlydGhkYXkpLmZvcm1hdCgnREQvTU0vWVlZWScpO1xuICAgICAgfVxuICAgIH1cblxuICAgIGZ1bmN0aW9uIHVwZGF0ZSgpIHtcbiAgICAgIGlmICh2bS51c2VyLmJpcnRoZGF5KSB7XG4gICAgICAgIHZtLnVzZXIuYmlydGhkYXkgPSBtb21lbnQodm0udXNlci5iaXJ0aGRheSk7XG4gICAgICB9XG4gICAgICBVc2Vyc1NlcnZpY2UudXBkYXRlUHJvZmlsZSh2bS51c2VyKS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICAvL2F0dWFsaXphIG8gdXN1w6FyaW8gY29ycmVudGUgY29tIGFzIG5vdmFzIGluZm9ybWHDp8O1ZXNcbiAgICAgICAgQXV0aC51cGRhdGVDdXJyZW50VXNlcihyZXNwb25zZSk7XG4gICAgICAgIFByVG9hc3Quc3VjY2VzcygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnNhdmVTdWNjZXNzJykpO1xuICAgICAgICBoaXN0b3J5QmFjaygpO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gaGlzdG9yeUJhY2soKSB7XG4gICAgICAkd2luZG93Lmhpc3RvcnkuYmFjaygpO1xuICAgIH1cblxuICB9XG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb250cm9sbGVyKCdVc2Vyc0NvbnRyb2xsZXInLCBVc2Vyc0NvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gVXNlcnNDb250cm9sbGVyKCRjb250cm9sbGVyLCBVc2Vyc1NlcnZpY2UsIFByVG9hc3QsICRtZERpYWxvZywgJHRyYW5zbGF0ZSkge1xuXG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIHZtLm9uQWN0aXZhdGUgPSBvbkFjdGl2YXRlO1xuICAgIC8vIGluc3RhbnRpYXRlIGJhc2UgY29udHJvbGxlclxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHsgdm06IHZtLCBtb2RlbFNlcnZpY2U6IFVzZXJzU2VydmljZSwgb3B0aW9uczoge30gfSk7XG5cbiAgICBmdW5jdGlvbiBvbkFjdGl2YXRlKCkge1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0ge307XG4gICAgfVxuXG4gICAgdm0uaGlkZURpYWxvZyA9IGZ1bmN0aW9uKCkge1xuICAgICAgJG1kRGlhbG9nLmhpZGUoKTtcbiAgICB9XG5cbiAgICB2bS5zYXZlTmV3VXNlciA9IGZ1bmN0aW9uKCkge1xuICAgICAgdm0ucmVzb3VyY2UuJHNhdmUoKS50aGVuKGZ1bmN0aW9uIChyZXNvdXJjZSkge1xuICAgICAgICB2bS5yZXNvdXJjZSA9IHJlc291cmNlO1xuICAgICAgICBQclRvYXN0LnN1Y2Nlc3MoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5zdWNjZXNzU2lnblVwJykpO1xuICAgICAgICAkbWREaWFsb2cuaGlkZSgpO1xuICAgICAgfSk7XG4gICAgfVxuICB9XG59KSgpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKlxuICAgKiBBcnF1aXZvIGRlIGNvbmZpZ3VyYcOnw6NvIGNvbSBhcyByb3RhcyBlc3BlY8OtZmljYXMgZG8gcmVjdXJzbyB1c2VyXG4gICAqXG4gICAqIEBwYXJhbSB7YW55fSAkc3RhdGVQcm92aWRlclxuICAgKiBAcGFyYW0ge2FueX0gR2xvYmFsXG4gICAqL1xuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvdXRlcygkc3RhdGVQcm92aWRlciwgR2xvYmFsKSB7XG4gICAgJHN0YXRlUHJvdmlkZXJcbiAgICAgIC5zdGF0ZSgnYXBwLnVzZXInLCB7XG4gICAgICAgIHVybDogJy91c3VhcmlvJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy91c2Vycy91c2Vycy5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ1VzZXJzQ29udHJvbGxlciBhcyB1c2Vyc0N0cmwnLFxuICAgICAgICBkYXRhOiB7IG5lZWRBdXRoZW50aWNhdGlvbjogdHJ1ZSwgbmVlZFByb2ZpbGU6IFsnYWRtaW4nXSB9XG4gICAgICB9KVxuICAgICAgLnN0YXRlKCdhcHAudXNlci1wcm9maWxlJywge1xuICAgICAgICB1cmw6ICcvdXN1YXJpby9wZXJmaWwnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL3VzZXJzL3Byb2ZpbGUuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdQcm9maWxlQ29udHJvbGxlciBhcyBwcm9maWxlQ3RybCcsXG4gICAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiB0cnVlIH1cbiAgICAgIH0pO1xuXG4gIH1cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmFjdG9yeSgnVXNlcnNTZXJ2aWNlJywgVXNlcnNTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIFVzZXJzU2VydmljZShsb2Rhc2gsIEdsb2JhbCwgc2VydmljZUZhY3RvcnkpIHtcbiAgICByZXR1cm4gc2VydmljZUZhY3RvcnkoJ3VzZXJzJywge1xuICAgICAgLy9xdWFuZG8gaW5zdGFuY2lhIHVtIHVzdcOhcmlvIHNlbSBwYXNzYXIgcGFyYW1ldHJvLFxuICAgICAgLy9vIG1lc21vIHZhaSB0ZXIgb3MgdmFsb3JlcyBkZWZhdWx0cyBhYmFpeG9cbiAgICAgIGRlZmF1bHRzOiB7XG4gICAgICAgIHJvbGVzOiBbXVxuICAgICAgfSxcblxuICAgICAgYWN0aW9uczoge1xuICAgICAgICAvKipcbiAgICAgICAgICogU2VydmnDp28gcXVlIGF0dWFsaXphIG9zIGRhZG9zIGRvIHBlcmZpbCBkbyB1c3XDoXJpbyBsb2dhZG9cbiAgICAgICAgICpcbiAgICAgICAgICogQHBhcmFtIHtvYmplY3R9IGF0dHJpYnV0ZXNcbiAgICAgICAgICogQHJldHVybnMge3Byb21pc2V9IFVtYSBwcm9taXNlIGNvbSBvIHJlc3VsdGFkbyBkbyBjaGFtYWRhIG5vIGJhY2tlbmRcbiAgICAgICAgICovXG4gICAgICAgIHVwZGF0ZVByb2ZpbGU6IHtcbiAgICAgICAgICBtZXRob2Q6ICdQVVQnLFxuICAgICAgICAgIHVybDogR2xvYmFsLmFwaVBhdGggKyAnL3Byb2ZpbGUnLFxuICAgICAgICAgIG92ZXJyaWRlOiB0cnVlLFxuICAgICAgICAgIHdyYXA6IGZhbHNlXG4gICAgICAgIH1cbiAgICAgIH0sXG5cbiAgICAgIGluc3RhbmNlOiB7XG4gICAgICAgIC8qKlxuICAgICAgICAgKiBWZXJpZmljYSBzZSBvIHVzdcOhcmlvIHRlbSBvcyBwZXJmaXMgaW5mb3JtYWRvcy5cbiAgICAgICAgICpcbiAgICAgICAgICogQHBhcmFtIHthbnl9IHJvbGVzIHBlcmZpcyBhIHNlcmVtIHZlcmlmaWNhZG9zXG4gICAgICAgICAqIEBwYXJhbSB7Ym9vbGVhbn0gYWxsIGZsYWcgcGFyYSBpbmRpY2FyIHNlIHZhaSBjaGVnYXIgdG9kb3Mgb3MgcGVyZmlzIG91IHNvbWVudGUgdW0gZGVsZXNcbiAgICAgICAgICogQHJldHVybnMge2Jvb2xlYW59XG4gICAgICAgICAqL1xuICAgICAgICBoYXNQcm9maWxlOiBmdW5jdGlvbihyb2xlcywgYWxsKSB7XG4gICAgICAgICAgcm9sZXMgPSBhbmd1bGFyLmlzQXJyYXkocm9sZXMpID8gcm9sZXMgOiBbcm9sZXNdO1xuXG4gICAgICAgICAgdmFyIHVzZXJSb2xlcyA9IGxvZGFzaC5tYXAodGhpcy5yb2xlcywgJ3NsdWcnKTtcblxuICAgICAgICAgIGlmIChhbGwpIHtcbiAgICAgICAgICAgIHJldHVybiBsb2Rhc2guaW50ZXJzZWN0aW9uKHVzZXJSb2xlcywgcm9sZXMpLmxlbmd0aCA9PT0gcm9sZXMubGVuZ3RoO1xuICAgICAgICAgIH0gZWxzZSB7IC8vcmV0dXJuIHRoZSBsZW5ndGggYmVjYXVzZSAwIGlzIGZhbHNlIGluIGpzXG4gICAgICAgICAgICByZXR1cm4gbG9kYXNoLmludGVyc2VjdGlvbih1c2VyUm9sZXMsIHJvbGVzKS5sZW5ndGg7XG4gICAgICAgICAgfVxuICAgICAgICB9LFxuXG4gICAgICAgIC8qKlxuICAgICAgICAgKiBWZXJpZmljYSBzZSBvIHVzdcOhcmlvIHRlbSBvIHBlcmZpbCBhZG1pbi5cbiAgICAgICAgICpcbiAgICAgICAgICogQHJldHVybnMge2Jvb2xlYW59XG4gICAgICAgICAqL1xuICAgICAgICBpc0FkbWluOiBmdW5jdGlvbigpIHtcbiAgICAgICAgICByZXR1cm4gdGhpcy5oYXNQcm9maWxlKCdhZG1pbicpO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfSk7XG4gIH1cblxufSgpKTtcbiIsIi8vdG9rZW4gY2FjYjkxMjM1ODczYThjNDg3NWQyMzU3OGFjOWYzMjZlZjg5NGI2NlxuLy8gT0F0dXRoIGh0dHBzOi8vZ2l0aHViLmNvbS9sb2dpbi9vYXV0aC9hdXRob3JpemU/Y2xpZW50X2lkPTgyOTQ2OGU3ZmRlZTc5NDQ1YmE2JnNjb3BlPXVzZXIscHVibGljX3JlcG8mcmVkaXJlY3RfdXJpPWh0dHA6Ly8wLjAuMC4wOjUwMDAvIyEvYXBwL3Zjc1xuXG4oZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZpbHRlcignYnl0ZXMnLCBmdW5jdGlvbigpIHtcbiAgICAgIHJldHVybiBmdW5jdGlvbihieXRlcywgcHJlY2lzaW9uKSB7XG4gICAgICAgIGlmIChpc05hTihwYXJzZUZsb2F0KGJ5dGVzKSkgfHwgIWlzRmluaXRlKGJ5dGVzKSkgcmV0dXJuICctJztcbiAgICAgICAgaWYgKHR5cGVvZiBwcmVjaXNpb24gPT09ICd1bmRlZmluZWQnKSBwcmVjaXNpb24gPSAxO1xuICAgICAgICB2YXIgdW5pdHMgPSBbJ2J5dGVzJywgJ2tCJywgJ01CJywgJ0dCJywgJ1RCJywgJ1BCJ10sXG4gICAgICAgICAgbnVtYmVyID0gTWF0aC5mbG9vcihNYXRoLmxvZyhieXRlcykgLyBNYXRoLmxvZygxMDI0KSk7XG5cbiAgICAgICAgcmV0dXJuIChieXRlcyAvIE1hdGgucG93KDEwMjQsIE1hdGguZmxvb3IobnVtYmVyKSkpLnRvRml4ZWQocHJlY2lzaW9uKSArICAnICcgKyB1bml0c1tudW1iZXJdO1xuICAgICAgfVxuICAgIH0pXG4gICAgLmNvbnRyb2xsZXIoJ1Zjc0NvbnRyb2xsZXInLCBWY3NDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIFZjc0NvbnRyb2xsZXIoJGNvbnRyb2xsZXIsIFZjc1NlcnZpY2UsICR3aW5kb3csIFByb2plY3RzU2VydmljZSwgUHJUb2FzdCwgJHRyYW5zbGF0ZSkge1xuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICB2bS5pbmRleCA9IDA7XG4gICAgdm0ucGF0aHMgPSBbXTtcblxuICAgIC8vQXR0cmlidXRlcyBCbG9ja1xuXG4gICAgLy9GdW5jdGlvbnMgQmxvY2tcbiAgICB2bS5vbkFjdGl2YXRlID0gIGZ1bmN0aW9uKCkge1xuICAgICAgdG9nZ2xlU3BsYXNoU2NyZWVuKCk7XG4gICAgICBQcm9qZWN0c1NlcnZpY2UucXVlcnkoeyBwcm9qZWN0X2lkOiBsb2NhbFN0b3JhZ2UuZ2V0SXRlbSgncHJvamVjdCcpIH0pLnRoZW4oZnVuY3Rpb24ocmVzcG9uc2UpIHtcbiAgICAgICAgdm0udXNlcm5hbWUgPSByZXNwb25zZVswXS51c2VybmFtZV9naXRodWI7XG4gICAgICAgIHZtLnJlcG8gPSByZXNwb25zZVswXS5yZXBvX2dpdGh1YjtcbiAgICAgICAgaWYgKHZtLnVzZXJuYW1lICYmIHZtLnJlcG8pIHtcbiAgICAgICAgICB2bS5xdWVyeUZpbHRlcnMgPSB7XG4gICAgICAgICAgICB1c2VybmFtZTogdm0udXNlcm5hbWUsXG4gICAgICAgICAgICByZXBvOiB2bS5yZXBvLFxuICAgICAgICAgICAgcGF0aDogJy4nXG4gICAgICAgICAgfVxuICAgICAgICAgIHZtLnBhdGhzLnB1c2godm0ucXVlcnlGaWx0ZXJzLnBhdGgpO1xuICAgICAgICAgIHZtLnNlYXJjaCgpO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICR3aW5kb3cubG9hZGluZ19zY3JlZW4uZmluaXNoKCk7XG4gICAgICAgIH1cbiAgICAgIH0pO1xuICAgIH1cblxuICAgIHZtLmFwcGx5RmlsdGVycyA9IGZ1bmN0aW9uKGRlZmF1bHRRdWVyeUZpbHRlcnMpIHtcbiAgICAgIHJldHVybiBhbmd1bGFyLmV4dGVuZChkZWZhdWx0UXVlcnlGaWx0ZXJzLCB2bS5xdWVyeUZpbHRlcnMpO1xuICAgIH1cblxuICAgIHZtLmFmdGVyU2VhcmNoID0gZnVuY3Rpb24oKSB7XG4gICAgICBzb3J0UmVzb3VyY2VzKCk7XG4gICAgICAkd2luZG93LmxvYWRpbmdfc2NyZWVuLmZpbmlzaCgpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIHNvcnRSZXNvdXJjZXMoKSB7XG4gICAgICBpZiAodm0ucmVzb3VyY2VzLmxlbmd0aCA+IDApIHtcbiAgICAgICAgdm0ucmVzb3VyY2VzLnNvcnQoZnVuY3Rpb24oYSwgYikge1xuICAgICAgICAgIHJldHVybiBhLnR5cGUgPCBiLnR5cGUgPyAtMSA6IGEudHlwZSA+IGIudHlwZSA/IDEgOiAwO1xuICAgICAgICB9KTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICB2bS5vcGVuRmlsZU9yRGlyZWN0b3J5ID0gZnVuY3Rpb24ocmVzb3VyY2UpIHtcbiAgICAgIHRvZ2dsZVNwbGFzaFNjcmVlbigpO1xuICAgICAgaWYgKHJlc291cmNlKSB7XG4gICAgICAgIHZtLnF1ZXJ5RmlsdGVycy5wYXRoID0gcmVzb3VyY2UucGF0aDtcbiAgICAgICAgdm0ucGF0aHMucHVzaCh2bS5xdWVyeUZpbHRlcnMucGF0aCk7XG4gICAgICAgIHZtLmluZGV4Kys7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICB2bS5xdWVyeUZpbHRlcnMucGF0aCA9IHZtLnBhdGhzW3ZtLmluZGV4IC0gMV07XG4gICAgICAgIHZtLnBhdGhzLnNwbGljZSh2bS5pbmRleCwgMSk7XG4gICAgICAgIHZtLmluZGV4LS07XG4gICAgICB9XG4gICAgICB2bS5zZWFyY2goKTtcbiAgICB9XG5cbiAgICB2bS5vblNlYXJjaEVycm9yID0gZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICBpZiAocmVzcG9uc2UuZGF0YS5lcnJvciA9PT0gJ05vdCBGb3VuZCcpIHtcbiAgICAgICAgUHJUb2FzdC5pbmZvKCR0cmFuc2xhdGUuaW5zdGFudCgnUmVwb3NpdMOzcmlvIG7Do28gZW5jb250cmFkbycpKTtcbiAgICAgICAgJHdpbmRvdy5sb2FkaW5nX3NjcmVlbi5maW5pc2goKTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBNw6l0b2RvIHBhcmEgbW9zdHJhciBhIHRlbGEgZGUgZXNwZXJhXG4gICAgICovXG4gICAgZnVuY3Rpb24gdG9nZ2xlU3BsYXNoU2NyZWVuKCkge1xuICAgICAgJHdpbmRvdy5sb2FkaW5nX3NjcmVlbiA9ICR3aW5kb3cucGxlYXNlV2FpdCh7XG4gICAgICAgIGxvZ286ICcnLFxuICAgICAgICBiYWNrZ3JvdW5kQ29sb3I6ICdyZ2JhKDI1NSwyNTUsMjU1LDAuNCknLFxuICAgICAgICBsb2FkaW5nSHRtbDpcbiAgICAgICAgICAnPGRpdiBjbGFzcz1cInNwaW5uZXJcIj4gJyArXG4gICAgICAgICAgJyAgPGRpdiBjbGFzcz1cInJlY3QxXCI+PC9kaXY+ICcgK1xuICAgICAgICAgICcgIDxkaXYgY2xhc3M9XCJyZWN0MlwiPjwvZGl2PiAnICtcbiAgICAgICAgICAnICA8ZGl2IGNsYXNzPVwicmVjdDNcIj48L2Rpdj4gJyArXG4gICAgICAgICAgJyAgPGRpdiBjbGFzcz1cInJlY3Q0XCI+PC9kaXY+ICcgK1xuICAgICAgICAgICcgIDxkaXYgY2xhc3M9XCJyZWN0NVwiPjwvZGl2PiAnICtcbiAgICAgICAgICAnIDxwIGNsYXNzPVwibG9hZGluZy1tZXNzYWdlXCI+Q2FycmVnYW5kbzwvcD4gJyArXG4gICAgICAgICAgJzwvZGl2PidcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIC8vIGluc3RhbnRpYXRlIGJhc2UgY29udHJvbGxlclxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHsgdm06IHZtLCBtb2RlbFNlcnZpY2U6IFZjc1NlcnZpY2UsIG9wdGlvbnM6IHsgc2tpcFBhZ2luYXRpb246IHRydWUsIHNlYXJjaE9uSW5pdDogZmFsc2UgfSB9KTtcblxuICB9XG5cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb25maWcocm91dGVzKTtcblxuICAvKipcbiAgICogQXJxdWl2byBkZSBjb25maWd1cmHDp8OjbyBjb20gYXMgcm90YXMgZXNwZWPDrWZpY2FzIGRvIHJlY3Vyc28gdmNzXG4gICAqXG4gICAqIEBwYXJhbSB7b2JqZWN0fSAkc3RhdGVQcm92aWRlclxuICAgKiBAcGFyYW0ge29iamVjdH0gR2xvYmFsXG4gICAqL1xuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvdXRlcygkc3RhdGVQcm92aWRlciwgR2xvYmFsKSB7XG4gICAgJHN0YXRlUHJvdmlkZXJcbiAgICAgIC5zdGF0ZSgnYXBwLnZjcycsIHtcbiAgICAgICAgdXJsOiAnL3ZjcycsXG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvdmNzL3Zjcy5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ1Zjc0NvbnRyb2xsZXIgYXMgdmNzQ3RybCcsXG4gICAgICAgIGRhdGE6IHsgfVxuICAgICAgfSk7XG4gIH1cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmFjdG9yeSgnVmNzU2VydmljZScsIFZjc1NlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gVmNzU2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHZhciBtb2RlbCA9IHNlcnZpY2VGYWN0b3J5KCd2Y3MnLCB7XG4gICAgICBhY3Rpb25zOiB7IH0sXG4gICAgICBpbnN0YW5jZTogeyB9XG4gICAgfSk7XG5cbiAgICByZXR1cm4gbW9kZWw7XG4gIH1cblxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gICAvKiogQG5nSW5qZWN0ICovXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb21wb25lbnQoJ2JveCcsIHtcbiAgICAgIHJlcGxhY2U6IHRydWUsXG4gICAgICB0ZW1wbGF0ZVVybDogWydHbG9iYWwnLCBmdW5jdGlvbihHbG9iYWwpIHtcbiAgICAgICAgcmV0dXJuIEdsb2JhbC5jbGllbnRQYXRoICsgJy93aWRnZXRzL2JveC5odG1sJ1xuICAgICAgfV0sXG4gICAgICB0cmFuc2NsdWRlOiB7XG4gICAgICAgIHRvb2xiYXJCdXR0b25zOiAnP2JveFRvb2xiYXJCdXR0b25zJyxcbiAgICAgICAgZm9vdGVyQnV0dG9uczogJz9ib3hGb290ZXJCdXR0b25zJ1xuICAgICAgfSxcbiAgICAgIGJpbmRpbmdzOiB7XG4gICAgICAgIGJveFRpdGxlOiAnQCcsXG4gICAgICAgIHRvb2xiYXJDbGFzczogJ0AnLFxuICAgICAgICB0b29sYmFyQmdDb2xvcjogJ0AnXG4gICAgICB9LFxuICAgICAgY29udHJvbGxlcjogWyckdHJhbnNjbHVkZScsIGZ1bmN0aW9uKCR0cmFuc2NsdWRlKSB7XG4gICAgICAgIHZhciBjdHJsID0gdGhpcztcblxuICAgICAgICBjdHJsLnRyYW5zY2x1ZGUgPSAkdHJhbnNjbHVkZTtcblxuICAgICAgICBjdHJsLiRvbkluaXQgPSBmdW5jdGlvbigpIHtcbiAgICAgICAgICBpZiAoYW5ndWxhci5pc1VuZGVmaW5lZChjdHJsLnRvb2xiYXJCZ0NvbG9yKSkgY3RybC50b29sYmFyQmdDb2xvciA9ICdkZWZhdWx0LXByaW1hcnknO1xuICAgICAgICB9O1xuICAgICAgfV1cbiAgICB9KTtcbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb21wb25lbnQoJ2NvbnRlbnRCb2R5Jywge1xuICAgICAgcmVwbGFjZTogdHJ1ZSxcbiAgICAgIHRyYW5zY2x1ZGU6IHRydWUsXG4gICAgICB0ZW1wbGF0ZVVybDogWydHbG9iYWwnLCBmdW5jdGlvbihHbG9iYWwpIHtcbiAgICAgICAgcmV0dXJuIEdsb2JhbC5jbGllbnRQYXRoICsgJy93aWRnZXRzL2NvbnRlbnQtYm9keS5odG1sJ1xuICAgICAgfV0sXG4gICAgICBiaW5kaW5nczoge1xuICAgICAgICBsYXlvdXRBbGlnbjogJ0AnXG4gICAgICB9LFxuICAgICAgY29udHJvbGxlcjogW2Z1bmN0aW9uKCkge1xuICAgICAgICB2YXIgY3RybCA9IHRoaXM7XG5cbiAgICAgICAgY3RybC4kb25Jbml0ID0gZnVuY3Rpb24oKSB7XG4gICAgICAgICAgLy8gTWFrZSBhIGNvcHkgb2YgdGhlIGluaXRpYWwgdmFsdWUgdG8gYmUgYWJsZSB0byByZXNldCBpdCBsYXRlclxuICAgICAgICAgIGN0cmwubGF5b3V0QWxpZ24gPSBhbmd1bGFyLmlzRGVmaW5lZChjdHJsLmxheW91dEFsaWduKSA/IGN0cmwubGF5b3V0QWxpZ24gOiAnY2VudGVyIHN0YXJ0JztcbiAgICAgICAgfTtcbiAgICAgIH1dXG4gICAgfSk7XG5cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb21wb25lbnQoJ2NvbnRlbnRIZWFkZXInLCB7XG4gICAgICB0ZW1wbGF0ZVVybDogWydHbG9iYWwnLCBmdW5jdGlvbihHbG9iYWwpIHtcbiAgICAgICAgcmV0dXJuIEdsb2JhbC5jbGllbnRQYXRoICsgJy93aWRnZXRzL2NvbnRlbnQtaGVhZGVyLmh0bWwnXG4gICAgICB9XSxcbiAgICAgIHJlcGxhY2U6IHRydWUsXG4gICAgICBiaW5kaW5nczoge1xuICAgICAgICB0aXRsZTogJ0AnLFxuICAgICAgICBkZXNjcmlwdGlvbjogJ0AnXG4gICAgICB9XG4gICAgfSk7XG5cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5maWx0ZXIoJ2F1ZGl0RGV0YWlsVGl0bGUnLCBhdWRpdERldGFpbFRpdGxlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIGF1ZGl0RGV0YWlsVGl0bGUoJHRyYW5zbGF0ZSkge1xuICAgIHJldHVybiBmdW5jdGlvbihhdWRpdERldGFpbCwgc3RhdHVzKSB7XG4gICAgICBpZiAoYXVkaXREZXRhaWwudHlwZSA9PT0gJ3VwZGF0ZWQnKSB7XG4gICAgICAgIGlmIChzdGF0dXMgPT09ICdiZWZvcmUnKSB7XG4gICAgICAgICAgcmV0dXJuICR0cmFuc2xhdGUuaW5zdGFudCgnZGlhbG9nLmF1ZGl0LnVwZGF0ZWRCZWZvcmUnKTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICByZXR1cm4gJHRyYW5zbGF0ZS5pbnN0YW50KCdkaWFsb2cuYXVkaXQudXBkYXRlZEFmdGVyJyk7XG4gICAgICAgIH1cbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHJldHVybiAkdHJhbnNsYXRlLmluc3RhbnQoJ2RpYWxvZy5hdWRpdC4nICsgYXVkaXREZXRhaWwudHlwZSk7XG4gICAgICB9XG4gICAgfVxuICB9XG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5maWx0ZXIoJ2F1ZGl0TW9kZWwnLCBhdWRpdE1vZGVsKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIGF1ZGl0TW9kZWwoJHRyYW5zbGF0ZSkge1xuICAgIHJldHVybiBmdW5jdGlvbihtb2RlbElkKSB7XG4gICAgICBtb2RlbElkID0gbW9kZWxJZC5yZXBsYWNlKCdBcHBcXFxcJywgJycpO1xuICAgICAgdmFyIG1vZGVsID0gJHRyYW5zbGF0ZS5pbnN0YW50KCdtb2RlbHMuJyArIG1vZGVsSWQudG9Mb3dlckNhc2UoKSk7XG5cbiAgICAgIHJldHVybiAobW9kZWwpID8gbW9kZWwgOiBtb2RlbElkO1xuICAgIH1cbiAgfVxuXG59KSgpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmlsdGVyKCdhdWRpdFR5cGUnLCBhdWRpdFR5cGUpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gYXVkaXRUeXBlKGxvZGFzaCwgQXVkaXRTZXJ2aWNlKSB7XG4gICAgcmV0dXJuIGZ1bmN0aW9uKHR5cGVJZCkge1xuICAgICAgdmFyIHR5cGUgPSBsb2Rhc2guZmluZChBdWRpdFNlcnZpY2UubGlzdFR5cGVzKCksIHsgaWQ6IHR5cGVJZCB9KTtcblxuICAgICAgcmV0dXJuICh0eXBlKSA/IHR5cGUubGFiZWwgOiB0eXBlO1xuICAgIH1cbiAgfVxuXG59KSgpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmlsdGVyKCdhdWRpdFZhbHVlJywgYXVkaXRWYWx1ZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBhdWRpdFZhbHVlKCRmaWx0ZXIsIGxvZGFzaCkge1xuICAgIHJldHVybiBmdW5jdGlvbih2YWx1ZSwga2V5KSB7XG4gICAgICBpZiAoYW5ndWxhci5pc0RhdGUodmFsdWUpIHx8IGxvZGFzaC5lbmRzV2l0aChrZXksICdfYXQnKSB8fCAgbG9kYXNoLmVuZHNXaXRoKGtleSwgJ190bycpKSB7XG4gICAgICAgIHJldHVybiAkZmlsdGVyKCdwckRhdGV0aW1lJykodmFsdWUpO1xuICAgICAgfVxuXG4gICAgICBpZiAodHlwZW9mIHZhbHVlID09PSAnYm9vbGVhbicpIHtcbiAgICAgICAgcmV0dXJuICRmaWx0ZXIoJ3RyYW5zbGF0ZScpKCh2YWx1ZSkgPyAnZ2xvYmFsLnllcycgOiAnZ2xvYmFsLm5vJyk7XG4gICAgICB9XG5cbiAgICAgIC8vY2hlY2sgaXMgZmxvYXRcbiAgICAgIGlmIChOdW1iZXIodmFsdWUpID09PSB2YWx1ZSAmJiB2YWx1ZSAlIDEgIT09IDApIHtcbiAgICAgICAgcmV0dXJuICRmaWx0ZXIoJ3JlYWwnKSh2YWx1ZSk7XG4gICAgICB9XG5cbiAgICAgIHJldHVybiB2YWx1ZTtcbiAgICB9XG4gIH1cblxufSkoKTtcbiIsIi8qZXNsaW50IGFuZ3VsYXIvZmlsZS1uYW1lOiAwLCBuby11bmRlZjogMCovXG4oZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uc3RhbnQoJ3B0LUJSLmkxOG4uYXR0cmlidXRlcycsIHtcbiAgICAgIGVtYWlsOiAnRW1haWwnLFxuICAgICAgcGFzc3dvcmQ6ICdTZW5oYScsXG4gICAgICBuYW1lOiAnTm9tZScsXG4gICAgICBpbWFnZTogJ0ltYWdlbScsXG4gICAgICByb2xlczogJ1BlcmZpcycsXG4gICAgICBkYXRlOiAnRGF0YScsXG4gICAgICBpbml0aWFsRGF0ZTogJ0RhdGEgSW5pY2lhbCcsXG4gICAgICBmaW5hbERhdGU6ICdEYXRhIEZpbmFsJyxcbiAgICAgIGJpcnRoZGF5OiAnRGF0YSBkZSBOYXNjaW1lbnRvJyxcbiAgICAgIHRhc2s6IHtcbiAgICAgICAgZGVzY3JpcHRpb246ICdEZXNjcmnDp8OjbycsXG4gICAgICAgIGRvbmU6ICdGZWl0bz8nLFxuICAgICAgICBwcmlvcml0eTogJ1ByaW9yaWRhZGUnLFxuICAgICAgICBzY2hlZHVsZWRfdG86ICdBZ2VuZGFkbyBQYXJhPycsXG4gICAgICAgIHByb2plY3Q6ICdQcm9qZXRvJyxcbiAgICAgICAgc3RhdHVzOiAnU3RhdHVzJyxcbiAgICAgICAgdGl0bGU6ICdUw610dWxvJyxcbiAgICAgICAgdHlwZTogJ1RpcG8nLFxuICAgICAgICBtaWxlc3RvbmU6ICdTcHJpbnQnLFxuICAgICAgICBlc3RpbWF0ZWRfdGltZTogJ1RlbXBvIEVzdGltYWRvJ1xuICAgICAgfSxcbiAgICAgIG1pbGVzdG9uZToge1xuICAgICAgICB0aXRsZTogJ1TDrXR1bG8nLFxuICAgICAgICBkZXNjcmlwdGlvbjogJ0Rlc2NyacOnw6NvJyxcbiAgICAgICAgZGF0ZV9zdGFydDogJ0RhdGEgRXN0aW1hZGEgcGFyYSBJbsOtY2lvJyxcbiAgICAgICAgZGF0ZV9lbmQ6ICdEYXRhIEVzdGltYWRhIHBhcmEgRmltJyxcbiAgICAgICAgZXN0aW1hdGVkX3RpbWU6ICdUZW1wbyBFc3RpbWFkbycsXG4gICAgICAgIGVzdGltYXRlZF92YWx1ZTogJ1ZhbG9yIEVzdGltYWRvJ1xuICAgICAgfSxcbiAgICAgIHByb2plY3Q6IHtcbiAgICAgICAgY29zdDogJ0N1c3RvJyxcbiAgICAgICAgaG91clZhbHVlRGV2ZWxvcGVyOiAnVmFsb3IgZGEgSG9yYSBEZXNlbnZvbHZlZG9yJyxcbiAgICAgICAgaG91clZhbHVlQ2xpZW50OiAnVmFsb3IgZGEgSG9yYSBDbGllbnRlJyxcbiAgICAgICAgaG91clZhbHVlRmluYWw6ICdWYWxvciBkYSBIb3JhIFByb2pldG8nXG4gICAgICB9LFxuICAgICAgcmVsZWFzZToge1xuICAgICAgICB0aXRsZTogJ1TDrXR1bG8nLFxuICAgICAgICBkZXNjcmlwdGlvbjogJ0Rlc2NyacOnw6NvJyxcbiAgICAgICAgcmVsZWFzZV9kYXRlOiAnRGF0YSBkZSBFbnRyZWdhJyxcbiAgICAgICAgbWlsZXN0b25lOiAnTWlsZXN0b25lJyxcbiAgICAgICAgdGFza3M6ICdUYXJlZmFzJ1xuICAgICAgfSxcbiAgICAgIC8vw6kgY2FycmVnYWRvIGRvIHNlcnZpZG9yIGNhc28gZXN0ZWphIGRlZmluaWRvIG5vIG1lc21vXG4gICAgICBhdWRpdE1vZGVsOiB7XG4gICAgICB9XG4gICAgfSlcblxufSgpKTtcbiIsIi8qZXNsaW50IGFuZ3VsYXIvZmlsZS1uYW1lOiAwLCBuby11bmRlZjogMCovXG4oZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uc3RhbnQoJ3B0LUJSLmkxOG4uZGlhbG9nJywge1xuICAgICAgY29uZmlybVRpdGxlOiAnQ29uZmlybWHDp8OjbycsXG4gICAgICBjb25maXJtRGVzY3JpcHRpb246ICdDb25maXJtYSBhIGHDp8Ojbz8nLFxuICAgICAgcmVtb3ZlRGVzY3JpcHRpb246ICdEZXNlamEgcmVtb3ZlciBwZXJtYW5lbnRlbWVudGUge3tuYW1lfX0/JyxcbiAgICAgIGF1ZGl0OiB7XG4gICAgICAgIGNyZWF0ZWQ6ICdJbmZvcm1hw6fDtWVzIGRvIENhZGFzdHJvJyxcbiAgICAgICAgdXBkYXRlZEJlZm9yZTogJ0FudGVzIGRhIEF0dWFsaXphw6fDo28nLFxuICAgICAgICB1cGRhdGVkQWZ0ZXI6ICdEZXBvaXMgZGEgQXR1YWxpemHDp8OjbycsXG4gICAgICAgIGRlbGV0ZWQ6ICdJbmZvcm1hw6fDtWVzIGFudGVzIGRlIHJlbW92ZXInXG4gICAgICB9LFxuICAgICAgbG9naW46IHtcbiAgICAgICAgcmVzZXRQYXNzd29yZDoge1xuICAgICAgICAgIGRlc2NyaXB0aW9uOiAnRGlnaXRlIGFiYWl4byBvIGVtYWlsIGNhZGFzdHJhZG8gbm8gc2lzdGVtYS4nXG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9KVxuXG59KCkpO1xuIiwiLyplc2xpbnQgYW5ndWxhci9maWxlLW5hbWU6IDAsIG5vLXVuZGVmOiAwKi9cbihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb25zdGFudCgncHQtQlIuaTE4bi5nbG9iYWwnLCB7XG4gICAgICBsb2FkaW5nOiAnQ2FycmVnYW5kby4uLicsXG4gICAgICBwcm9jZXNzaW5nOiAnUHJvY2Vzc2FuZG8uLi4nLFxuICAgICAgeWVzOiAnU2ltJyxcbiAgICAgIG5vOiAnTsOjbycsXG4gICAgICBhbGw6ICdUb2RvcydcbiAgICB9KVxuXG59KCkpO1xuIiwiLyplc2xpbnQgYW5ndWxhci9maWxlLW5hbWU6IDAsIG5vLXVuZGVmOiAwKi9cbihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb25zdGFudCgncHQtQlIuaTE4bi5tZXNzYWdlcycsIHtcbiAgICAgIGludGVybmFsRXJyb3I6ICdPY29ycmV1IHVtIGVycm8gaW50ZXJubywgY29udGF0ZSBvIGFkbWluaXN0cmFkb3IgZG8gc2lzdGVtYScsXG4gICAgICBub3RGb3VuZDogJ05lbmh1bSByZWdpc3RybyBlbmNvbnRyYWRvJyxcbiAgICAgIG5vdEF1dGhvcml6ZWQ6ICdWb2PDqiBuw6NvIHRlbSBhY2Vzc28gYSBlc3RhIGZ1bmNpb25hbGlkYWRlLicsXG4gICAgICBzZWFyY2hFcnJvcjogJ07Do28gZm9pIHBvc3PDrXZlbCByZWFsaXphciBhIGJ1c2NhLicsXG4gICAgICBzYXZlU3VjY2VzczogJ1JlZ2lzdHJvIHNhbHZvIGNvbSBzdWNlc3NvLicsXG4gICAgICBvcGVyYXRpb25TdWNjZXNzOiAnT3BlcmHDp8OjbyByZWFsaXphZGEgY29tIHN1Y2Vzc28uJyxcbiAgICAgIG9wZXJhdGlvbkVycm9yOiAnRXJybyBhbyByZWFsaXphciBhIG9wZXJhw6fDo28nLFxuICAgICAgc2F2ZUVycm9yOiAnRXJybyBhbyB0ZW50YXIgc2FsdmFyIG8gcmVnaXN0cm8uJyxcbiAgICAgIHJlbW92ZVN1Y2Nlc3M6ICdSZW1vw6fDo28gcmVhbGl6YWRhIGNvbSBzdWNlc3NvLicsXG4gICAgICByZW1vdmVFcnJvcjogJ0Vycm8gYW8gdGVudGFyIHJlbW92ZXIgbyByZWdpc3Ryby4nLFxuICAgICAgcmVzb3VyY2VOb3RGb3VuZEVycm9yOiAnUmVjdXJzbyBuw6NvIGVuY29udHJhZG8nLFxuICAgICAgbm90TnVsbEVycm9yOiAnVG9kb3Mgb3MgY2FtcG9zIG9icmlnYXTDs3Jpb3MgZGV2ZW0gc2VyIHByZWVuY2hpZG9zLicsXG4gICAgICBkdXBsaWNhdGVkUmVzb3VyY2VFcnJvcjogJ0rDoSBleGlzdGUgdW0gcmVjdXJzbyBjb20gZXNzYXMgaW5mb3JtYcOnw7Vlcy4nLFxuICAgICAgc3ByaW50RW5kZWRTdWNjZXNzOiAnU3ByaW50IGZpbmFsaXphZGEgY29tIHN1Y2Vzc28nLFxuICAgICAgc3ByaW50RW5kZWRFcnJvcjogJ0Vycm8gYW8gZmluYWxpemFyIGEgc3ByaW50JyxcbiAgICAgIHN1Y2Nlc3NTaWduVXA6ICdDYWRhc3RybyByZWFsaXphZG8gY29tIHN1Y2Vzc28uIFVtIGUtbWFpbCBmb2kgZW52aWFkbyBjb20gc2V1cyBkYWRvcyBkZSBsb2dpbicsXG4gICAgICBlcnJvcnNTaWduVXA6ICdIb3V2ZSB1bSBlcnJvIGFvIHJlYWxpemFyIG8gc2V1IGNhZGFzdHJvLiBUZW50ZSBub3ZhbWVudGUgbWFpcyB0YXJkZSEnLFxuICAgICAgcmVsZWFzZXRFbmRlZFN1Y2Nlc3M6ICdSZWxlYXNlIGZpbmFsaXphZGEgY29tIHN1Y2Vzc28nLFxuICAgICAgcmVsZWFzZUVuZGVkRXJyb3I6ICdFcnJvIGFvIGZpbmFsaXphciBhIHJlbGVhc2UnLFxuICAgICAgcHJvamVjdEVuZGVkU3VjY2VzczogJ1Byb2pldG8gZmluYWxpemFkbyBjb20gc3VjZXNzbycsXG4gICAgICBwcm9qZWN0RW5kZWRFcnJvcjogJ0Vycm8gYW8gZmluYWxpemFyIG8gcHJvamV0bycsXG4gICAgICB2YWxpZGF0ZToge1xuICAgICAgICBmaWVsZFJlcXVpcmVkOiAnTyBjYW1wbyB7e2ZpZWxkfX0gw6kgb2JyaWdyYXTDs3Jpby4nXG4gICAgICB9LFxuICAgICAgbGF5b3V0OiB7XG4gICAgICAgIGVycm9yNDA0OiAnUMOhZ2luYSBuw6NvIGVuY29udHJhZGEnXG4gICAgICB9LFxuICAgICAgbG9naW46IHtcbiAgICAgICAgbG9nb3V0SW5hY3RpdmU6ICdWb2PDqiBmb2kgZGVzbG9nYWRvIGRvIHNpc3RlbWEgcG9yIGluYXRpdmlkYWRlLiBGYXZvciBlbnRyYXIgbm8gc2lzdGVtYSBub3ZhbWVudGUuJyxcbiAgICAgICAgaW52YWxpZENyZWRlbnRpYWxzOiAnQ3JlZGVuY2lhaXMgSW52w6FsaWRhcycsXG4gICAgICAgIHVua25vd25FcnJvcjogJ07Do28gZm9pIHBvc3PDrXZlbCByZWFsaXphciBvIGxvZ2luLiBUZW50ZSBub3ZhbWVudGUuICcgK1xuICAgICAgICAgICdDYXNvIG7Do28gY29uc2lnYSBmYXZvciBlbmNvbnRyYXIgZW0gY29udGF0byBjb20gbyBhZG1pbmlzdHJhZG9yIGRvIHNpc3RlbWEuJyxcbiAgICAgICAgdXNlck5vdEZvdW5kOiAnTsOjbyBmb2kgcG9zc8OtdmVsIGVuY29udHJhciBzZXVzIGRhZG9zJ1xuICAgICAgfSxcbiAgICAgIGRhc2hib2FyZDoge1xuICAgICAgICB3ZWxjb21lOiAnU2VqYSBiZW0gVmluZG8ge3t1c2VyTmFtZX19JyxcbiAgICAgICAgZGVzY3JpcHRpb246ICdVdGlsaXplIG8gbWVudSBwYXJhIG5hdmVnYcOnw6NvLidcbiAgICAgIH0sXG4gICAgICBtYWlsOiB7XG4gICAgICAgIG1haWxFcnJvcnM6ICdPY29ycmV1IHVtIGVycm8gbm9zIHNlZ3VpbnRlcyBlbWFpbHMgYWJhaXhvOlxcbicsXG4gICAgICAgIHNlbmRNYWlsU3VjY2VzczogJ0VtYWlsIGVudmlhZG8gY29tIHN1Y2Vzc28hJyxcbiAgICAgICAgc2VuZE1haWxFcnJvcjogJ07Do28gZm9pIHBvc3PDrXZlbCBlbnZpYXIgbyBlbWFpbC4nLFxuICAgICAgICBwYXNzd29yZFNlbmRpbmdTdWNjZXNzOiAnTyBwcm9jZXNzbyBkZSByZWN1cGVyYcOnw6NvIGRlIHNlbmhhIGZvaSBpbmljaWFkby4gQ2FzbyBvIGVtYWlsIG7Do28gY2hlZ3VlIGVtIDEwIG1pbnV0b3MgdGVudGUgbm92YW1lbnRlLidcbiAgICAgIH0sXG4gICAgICB1c2VyOiB7XG4gICAgICAgIHJlbW92ZVlvdXJTZWxmRXJyb3I6ICdWb2PDqiBuw6NvIHBvZGUgcmVtb3ZlciBzZXUgcHLDs3ByaW8gdXN1w6FyaW8nLFxuICAgICAgICB1c2VyRXhpc3RzOiAnVXN1w6FyaW8gasOhIGFkaWNpb25hZG8hJyxcbiAgICAgICAgcHJvZmlsZToge1xuICAgICAgICAgIHVwZGF0ZUVycm9yOiAnTsOjbyBmb2kgcG9zc8OtdmVsIGF0dWFsaXphciBzZXUgcHJvZmlsZSdcbiAgICAgICAgfVxuICAgICAgfSxcbiAgICAgIHF1ZXJ5RGluYW1pYzoge1xuICAgICAgICBub0ZpbHRlcjogJ05lbmh1bSBmaWx0cm8gYWRpY2lvbmFkbydcbiAgICAgIH1cbiAgICB9KVxuXG59KCkpO1xuIiwiLyplc2xpbnQgYW5ndWxhci9maWxlLW5hbWU6IDAsIG5vLXVuZGVmOiAwKi9cbihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb25zdGFudCgncHQtQlIuaTE4bi5tb2RlbHMnLCB7XG4gICAgICB1c2VyOiAnVXN1w6FyaW8nLFxuICAgICAgdGFzazogJ1RhcmVmYScsXG4gICAgICBwcm9qZWN0OiAnUHJvamV0bydcbiAgICB9KVxuXG59KCkpO1xuIiwiLyplc2xpbnQgYW5ndWxhci9maWxlLW5hbWU6IDAsIG5vLXVuZGVmOiAwKi9cbihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb25zdGFudCgncHQtQlIuaTE4bi52aWV3cycsIHtcbiAgICAgIGJyZWFkY3J1bWJzOiB7XG4gICAgICAgIHVzZXI6ICdBZG1pbmlzdHJhw6fDo28gLSBVc3XDoXJpbycsXG4gICAgICAgICd1c2VyLXByb2ZpbGUnOiAnUGVyZmlsJyxcbiAgICAgICAgZGFzaGJvYXJkOiAnRGFzaGJvYXJkJyxcbiAgICAgICAgYXVkaXQ6ICdBZG1pbmlzdHJhw6fDo28gLSBBdWRpdG9yaWEnLFxuICAgICAgICBtYWlsOiAnQWRtaW5pc3RyYcOnw6NvIC0gRW52aW8gZGUgZS1tYWlsJyxcbiAgICAgICAgcHJvamVjdHM6ICdQcm9qZXRvcycsXG4gICAgICAgICdkaW5hbWljLXF1ZXJ5JzogJ0FkbWluaXN0cmHDp8OjbyAtIENvbnN1bHRhcyBEaW7Dom1pY2FzJyxcbiAgICAgICAgJ25vdC1hdXRob3JpemVkJzogJ0FjZXNzbyBOZWdhZG8nLFxuICAgICAgICB0YXNrczogJ1RhcmVmYXMnLFxuICAgICAgICBtaWxlc3RvbmVzOiAnU3ByaW50cycsXG4gICAgICAgIGthbmJhbjogJ0thbmJhbiBCb2FyZCcsXG4gICAgICAgIHZjczogJ0NvbnRyb2xlIGRlIFZlcnPDo28nLFxuICAgICAgICByZWxlYXNlczogJ1JlbGVhc2VzJ1xuICAgICAgfSxcbiAgICAgIHRpdGxlczoge1xuICAgICAgICBkYXNoYm9hcmQ6ICdEYXNoYm9hcmQnLFxuICAgICAgICBtYWlsU2VuZDogJ0VudmlhciBlLW1haWwnLFxuICAgICAgICB0YXNrTGlzdDogJ0xpc3RhIGRlIFRhcmVmYXMnLFxuICAgICAgICB1c2VyTGlzdDogJ0xpc3RhIGRlIFVzdcOhcmlvcycsXG4gICAgICAgIGF1ZGl0TGlzdDogJ0xpc3RhIGRlIExvZ3MnLFxuICAgICAgICByZWdpc3RlcjogJ0Zvcm11bMOhcmlvIGRlIENhZGFzdHJvJyxcbiAgICAgICAgcmVzZXRQYXNzd29yZDogJ1JlZGVmaW5pciBTZW5oYScsXG4gICAgICAgIHVwZGF0ZTogJ0Zvcm11bMOhcmlvIGRlIEF0dWFsaXphw6fDo28nLFxuICAgICAgICB0YXNrczogJ1RhcmVmYXMnLFxuICAgICAgICBtaWxlc3RvbmVzOiAnU3ByaW50cycsXG4gICAgICAgIGthbmJhbjogJ0thbmJhbiBCb2FyZCcsXG4gICAgICAgIHZjczogJ0NvbnRyb2xlIGRlIFZlcnPDo28nLFxuICAgICAgICByZWxlYXNlczogJ1JlbGVhc2VzJ1xuICAgICAgfSxcbiAgICAgIGFjdGlvbnM6IHtcbiAgICAgICAgc2VuZDogJ0VudmlhcicsXG4gICAgICAgIHNhdmU6ICdTYWx2YXInLFxuICAgICAgICBjbGVhcjogJ0xpbXBhcicsXG4gICAgICAgIGNsZWFyQWxsOiAnTGltcGFyIFR1ZG8nLFxuICAgICAgICByZXN0YXJ0OiAnUmVpbmljaWFyJyxcbiAgICAgICAgZmlsdGVyOiAnRmlsdHJhcicsXG4gICAgICAgIHNlYXJjaDogJ1Blc3F1aXNhcicsXG4gICAgICAgIGxpc3Q6ICdMaXN0YXInLFxuICAgICAgICBlZGl0OiAnRWRpdGFyJyxcbiAgICAgICAgY2FuY2VsOiAnQ2FuY2VsYXInLFxuICAgICAgICB1cGRhdGU6ICdBdHVhbGl6YXInLFxuICAgICAgICByZW1vdmU6ICdSZW1vdmVyJyxcbiAgICAgICAgZ2V0T3V0OiAnU2FpcicsXG4gICAgICAgIGFkZDogJ0FkaWNpb25hcicsXG4gICAgICAgIGluOiAnRW50cmFyJyxcbiAgICAgICAgbG9hZEltYWdlOiAnQ2FycmVnYXIgSW1hZ2VtJyxcbiAgICAgICAgc2lnbnVwOiAnQ2FkYXN0cmFyJyxcbiAgICAgICAgY3JpYXJQcm9qZXRvOiAnQ3JpYXIgUHJvamV0bycsXG4gICAgICAgIHByb2plY3RMaXN0OiAnTGlzdGEgZGUgUHJvamV0b3MnLFxuICAgICAgICB0YXNrc0xpc3Q6ICdMaXN0YSBkZSBUYXJlZmFzJyxcbiAgICAgICAgbWlsZXN0b25lc0xpc3Q6ICdMaXN0YSBkZSBTcHJpbnRzJyxcbiAgICAgICAgZmluYWxpemU6ICdGaW5hbGl6YXInLFxuICAgICAgICByZXBseTogJ1Jlc3BvbmRlcidcbiAgICAgIH0sXG4gICAgICBmaWVsZHM6IHtcbiAgICAgICAgZGF0ZTogJ0RhdGEnLFxuICAgICAgICBhY3Rpb246ICdBw6fDo28nLFxuICAgICAgICBhY3Rpb25zOiAnQcOnw7VlcycsXG4gICAgICAgIGF1ZGl0OiB7XG4gICAgICAgICAgZGF0ZVN0YXJ0OiAnRGF0YSBJbmljaWFsJyxcbiAgICAgICAgICBkYXRlRW5kOiAnRGF0YSBGaW5hbCcsXG4gICAgICAgICAgcmVzb3VyY2U6ICdSZWN1cnNvJyxcbiAgICAgICAgICBhbGxSZXNvdXJjZXM6ICdUb2RvcyBSZWN1cnNvcycsXG4gICAgICAgICAgdHlwZToge1xuICAgICAgICAgICAgY3JlYXRlZDogJ0NhZGFzdHJhZG8nLFxuICAgICAgICAgICAgdXBkYXRlZDogJ0F0dWFsaXphZG8nLFxuICAgICAgICAgICAgZGVsZXRlZDogJ1JlbW92aWRvJ1xuICAgICAgICAgIH1cbiAgICAgICAgfSxcbiAgICAgICAgbG9naW46IHtcbiAgICAgICAgICByZXNldFBhc3N3b3JkOiAnRXNxdWVjaSBtaW5oYSBzZW5oYScsXG4gICAgICAgICAgY29uZmlybVBhc3N3b3JkOiAnQ29uZmlybWFyIHNlbmhhJ1xuICAgICAgICB9LFxuICAgICAgICBtYWlsOiB7XG4gICAgICAgICAgdG86ICdQYXJhJyxcbiAgICAgICAgICBzdWJqZWN0OiAnQXNzdW50bycsXG4gICAgICAgICAgbWVzc2FnZTogJ01lbnNhZ2VtJ1xuICAgICAgICB9LFxuICAgICAgICBxdWVyeURpbmFtaWM6IHtcbiAgICAgICAgICBmaWx0ZXJzOiAnRmlsdHJvcycsXG4gICAgICAgICAgcmVzdWx0czogJ1Jlc3VsdGFkb3MnLFxuICAgICAgICAgIG1vZGVsOiAnTW9kZWwnLFxuICAgICAgICAgIGF0dHJpYnV0ZTogJ0F0cmlidXRvJyxcbiAgICAgICAgICBvcGVyYXRvcjogJ09wZXJhZG9yJyxcbiAgICAgICAgICByZXNvdXJjZTogJ1JlY3Vyc28nLFxuICAgICAgICAgIHZhbHVlOiAnVmFsb3InLFxuICAgICAgICAgIG9wZXJhdG9yczoge1xuICAgICAgICAgICAgZXF1YWxzOiAnSWd1YWwnLFxuICAgICAgICAgICAgZGlmZXJlbnQ6ICdEaWZlcmVudGUnLFxuICAgICAgICAgICAgY29udGVpbnM6ICdDb250w6ltJyxcbiAgICAgICAgICAgIHN0YXJ0V2l0aDogJ0luaWNpYSBjb20nLFxuICAgICAgICAgICAgZmluaXNoV2l0aDogJ0ZpbmFsaXphIGNvbScsXG4gICAgICAgICAgICBiaWdnZXJUaGFuOiAnTWFpb3InLFxuICAgICAgICAgICAgZXF1YWxzT3JCaWdnZXJUaGFuOiAnTWFpb3Igb3UgSWd1YWwnLFxuICAgICAgICAgICAgbGVzc1RoYW46ICdNZW5vcicsXG4gICAgICAgICAgICBlcXVhbHNPckxlc3NUaGFuOiAnTWVub3Igb3UgSWd1YWwnXG4gICAgICAgICAgfVxuICAgICAgICB9LFxuICAgICAgICBwcm9qZWN0OiB7XG4gICAgICAgICAgbmFtZTogJ05vbWUnLFxuICAgICAgICAgIHRvdGFsVGFzazogJ1RvdGFsIGRlIFRhcmVmYXMnXG4gICAgICAgIH0sXG4gICAgICAgIHRhc2s6IHtcbiAgICAgICAgICBkb25lOiAnTsOjbyBGZWl0byAvIEZlaXRvJ1xuICAgICAgICB9LFxuICAgICAgICB1c2VyOiB7XG4gICAgICAgICAgcGVyZmlsczogJ1BlcmZpcycsXG4gICAgICAgICAgbmFtZU9yRW1haWw6ICdOb21lIG91IEVtYWlsJ1xuICAgICAgICB9XG4gICAgICB9LFxuICAgICAgbGF5b3V0OiB7XG4gICAgICAgIG1lbnU6IHtcbiAgICAgICAgICBwcm9qZWN0czogJ1Byb2pldG9zJyxcbiAgICAgICAgICBkYXNoYm9hcmQ6ICdEYXNoYm9hcmQnLFxuICAgICAgICAgIG1pbGVzdG9uZXM6ICdTcHJpbnRzJyxcbiAgICAgICAgICB0YXNrczogJ1RhcmVmYXMnLFxuICAgICAgICAgIGthbmJhbjogJ0thbmJhbicsXG4gICAgICAgICAgdmNzOiAnQ29udHJvbGUgZGUgVmVyc8OjbycsXG4gICAgICAgICAgcmVsZWFzZXM6ICdSZWxlYXNlcydcbiAgICAgICAgfVxuICAgICAgfSxcbiAgICAgIHRvb2x0aXBzOiB7XG4gICAgICAgIGF1ZGl0OiB7XG4gICAgICAgICAgdmlld0RldGFpbDogJ1Zpc3VhbGl6YXIgRGV0YWxoYW1lbnRvJ1xuICAgICAgICB9LFxuICAgICAgICB1c2VyOiB7XG4gICAgICAgICAgcGVyZmlsOiAnUGVyZmlsJyxcbiAgICAgICAgICB0cmFuc2ZlcjogJ1RyYW5zZmVyaXInXG4gICAgICAgIH0sXG4gICAgICAgIHRhc2s6IHtcbiAgICAgICAgICBsaXN0VGFzazogJ0xpc3RhciBUYXJlZmFzJ1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfSlcblxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnRyb2xsZXIoJ1Rhc2tJbmZvQ29udHJvbGxlcicsIFRhc2tJbmZvQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBUYXNrSW5mb0NvbnRyb2xsZXIoJGNvbnRyb2xsZXIsIFRhc2tzU2VydmljZSwgbG9jYWxzKSB7XG4gICAgLy9BdHRyaWJ1dGVzIEJsb2NrXG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIHZtLmNsb3NlRGlhbG9nID0gY2xvc2VEaWFsb2c7XG5cbiAgICB2bS5vbkFjdGl2YXRlID0gZnVuY3Rpb24oKSB7XG4gICAgICB2bS50YXNrID0gbG9jYWxzLnRhc2s7XG4gICAgICB2bS50YXNrLmVzdGltYXRlZF90aW1lID0gdm0udGFzay5lc3RpbWF0ZWRfdGltZS50b1N0cmluZygpICsgJyBob3Jhcyc7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gY2xvc2VEaWFsb2coKSB7XG4gICAgICB2bS5jbG9zZSgpO1xuICAgICAgY29uc29sZS5sb2coXCJmZWNoYXJcIik7XG4gICAgfVxuXG4gICAgLy8gaW5zdGFudGlhdGUgYmFzZSBjb250cm9sbGVyXG4gICAgJGNvbnRyb2xsZXIoJ0NSVURDb250cm9sbGVyJywgeyB2bTogdm0sIG1vZGVsU2VydmljZTogVGFza3NTZXJ2aWNlLCBvcHRpb25zOiB7IH0gfSk7XG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnRyb2xsZXIoJ1VzZXJzRGlhbG9nQ29udHJvbGxlcicsIFVzZXJzRGlhbG9nQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBVc2Vyc0RpYWxvZ0NvbnRyb2xsZXIoJGNvbnRyb2xsZXIsIFVzZXJzU2VydmljZSwgUHJEaWFsb2csICAvLyBOT1NPTkFSXG4gICAgdXNlckRpYWxvZ0lucHV0LCBvbkluaXQpIHtcblxuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICB2bS5vbkFjdGl2YXRlID0gb25BY3RpdmF0ZTtcbiAgICB2bS5hcHBseUZpbHRlcnMgPSBhcHBseUZpbHRlcnM7XG4gICAgdm0uY2xvc2UgPSBjbG9zZTtcblxuICAgIGlmIChhbmd1bGFyLmlzRGVmaW5lZCh1c2VyRGlhbG9nSW5wdXQpKSB7XG4gICAgICB2bS50cmFuc2ZlclVzZXIgPSB1c2VyRGlhbG9nSW5wdXQudHJhbnNmZXJVc2VyRm47XG4gICAgfVxuXG4gICAgLy8gaW5zdGFudGlhdGUgYmFzZSBjb250cm9sbGVyXG4gICAgJGNvbnRyb2xsZXIoJ0NSVURDb250cm9sbGVyJywge1xuICAgICAgdm06IHZtLFxuICAgICAgbW9kZWxTZXJ2aWNlOiBVc2Vyc1NlcnZpY2UsXG4gICAgICBzZWFyY2hPbkluaXQ6IG9uSW5pdCxcbiAgICAgIG9wdGlvbnM6IHtcbiAgICAgICAgcGVyUGFnZTogNVxuICAgICAgfVxuICAgIH0pO1xuXG4gICAgZnVuY3Rpb24gb25BY3RpdmF0ZSgpIHtcbiAgICAgIHZtLnF1ZXJ5RmlsdGVycyA9IHt9O1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGFwcGx5RmlsdGVycygpIHtcbiAgICAgIHJldHVybiBhbmd1bGFyLmV4dGVuZCh2bS5kZWZhdWx0UXVlcnlGaWx0ZXJzLCB2bS5xdWVyeUZpbHRlcnMpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGNsb3NlKCkge1xuICAgICAgUHJEaWFsb2cuY2xvc2UoKTtcbiAgICB9XG5cbiAgfVxuXG59KSgpO1xuIl0sInNvdXJjZVJvb3QiOiIvc291cmNlLyJ9
