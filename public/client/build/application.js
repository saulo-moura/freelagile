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
      RolesService.query().then(function (response) {
        vm.roles = response;
        //vm.roles = $filter('filter')(vm.roles, { slug: 'client' });
        if ($stateParams.obj === 'edit') {
          vm.cleanForm();
          vm.viewForm = true;
          vm.resource = $stateParams.resource;
          usersArray(vm.resource);
        } else {
          localStorage.removeItem('project');
          vm.queryFilters = { user_id: vm.currentUser.id };
        }
      });
    }

    function applyFilters(defaultQueryFilters) {
      return angular.extend(defaultQueryFilters, vm.querylters);
    }

    function beforeSave() {
      vm.resource.owner = Auth.currentUser.id;
      vm.resource.user_id = Auth.currentUser.id;
      vm.resource.dev_id = Auth.currentUser.id;
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
        vm.queryFilters = {
          username: vm.username,
          repo: vm.repo,
          path: '.'
        };
        vm.paths.push(vm.queryFilters.path);
        vm.search();
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
      vm.resources.sort(function (a, b) {
        return a.type < b.type ? -1 : a.type > b.type ? 1 : 0;
      });
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImFwcGxpY2F0aW9uLmpzIiwiYXBwLmpzIiwiYXBwLmNvbmZpZy5qcyIsImFwcC5jb250cm9sbGVyLmpzIiwiYXBwLmV4dGVybmFsLmpzIiwiYXBwLmdsb2JhbC5qcyIsImFwcC5yb3V0ZXMuanMiLCJhcHAucnVuLmpzIiwiYXVkaXQvYXVkaXQuY29udHJvbGxlci5qcyIsImF1ZGl0L2F1ZGl0LnJvdXRlLmpzIiwiYXVkaXQvYXVkaXQuc2VydmljZS5qcyIsImF1dGgvYXV0aC5yb3V0ZS5qcyIsImF1dGgvYXV0aC5zZXJ2aWNlLmpzIiwiYXV0aC9sb2dpbi5jb250cm9sbGVyLmpzIiwiYXV0aC9wYXNzd29yZC5jb250cm9sbGVyLmpzIiwiY29yZS9iYXNlLnNlcnZpY2UuanMiLCJjb3JlL2NydWQuY29udHJvbGxlci5qcyIsImRhc2hib2FyZC9kYXNoYm9hcmQuY29udHJvbGxlci5qcyIsImRhc2hib2FyZC9kYXNoYm9hcmQucm91dGUuanMiLCJkYXNoYm9hcmQvZGFzaGJvYXJkLnNlcnZpY2UuanMiLCJkaW5hbWljLXF1ZXJ5cy9kaW5hbWljLXF1ZXJ5LnJvdXRlLmpzIiwiZGluYW1pYy1xdWVyeXMvZGluYW1pYy1xdWVyeS5zZXJ2aWNlLmpzIiwiZGluYW1pYy1xdWVyeXMvZGluYW1pYy1xdWVyeXMuY29udHJvbGxlci5qcyIsImkxOG4vbGFuZ3VhZ2UtbG9hZGVyLnNlcnZpY2UuanMiLCJpMThuL3QtYXR0ci5maWx0ZXIuanMiLCJpMThuL3QtYnJlYWRjcnVtYi5maWx0ZXIuanMiLCJpMThuL3QtbW9kZWwuZmlsdGVyLmpzIiwiaW50ZXJjZXB0b3JzL2F1dGhlbnRpY2F0aW9uLmxpc3RlbmVyLmpzIiwiaW50ZXJjZXB0b3JzL2F1dGhvcml6YXRpb24ubGlzdGVuZXIuanMiLCJpbnRlcmNlcHRvcnMvc3Bpbm5lci5pbnRlcmNlcHRvci5qcyIsImludGVyY2VwdG9ycy90b2tlbi5pbnRlcmNlcHRvci5qcyIsImludGVyY2VwdG9ycy92YWxpZGF0aW9uLmludGVyY2VwdG9yLmpzIiwia2FuYmFuL2thbmJhbi5jb250cm9sbGVyLmpzIiwia2FuYmFuL2thbmJhbi5yb3V0ZS5qcyIsImthbmJhbi9rYW5iYW4uc2VydmljZS5qcyIsImxheW91dC9tZW51LmNvbnRyb2xsZXIuanMiLCJtYWlsL21haWxzLmNvbnRyb2xsZXIuanMiLCJtYWlsL21haWxzLnJvdXRlLmpzIiwibWFpbC9tYWlscy5zZXJ2aWNlLmpzIiwibWlsZXN0b25lcy9taWxlc3RvbmVzLmNvbnRyb2xsZXIuanMiLCJtaWxlc3RvbmVzL21pbGVzdG9uZXMucm91dGUuanMiLCJtaWxlc3RvbmVzL21pbGVzdG9uZXMuc2VydmljZS5qcyIsInByaW9yaXRpZXMvcHJpb3JpdGllcy5zZXJ2aWNlLmpzIiwicHJvamVjdHMvcHJvamVjdHMuY29udHJvbGxlci5qcyIsInByb2plY3RzL3Byb2plY3RzLnJvdXRlLmpzIiwicHJvamVjdHMvcHJvamVjdHMuc2VydmljZS5qcyIsInJlbGVhc2VzL3JlbGVhc2VzLmNvbnRyb2xsZXIuanMiLCJyZWxlYXNlcy9yZWxlYXNlcy5yb3V0ZS5qcyIsInJlbGVhc2VzL3JlbGVhc2VzLnNlcnZpY2UuanMiLCJyb2xlcy9yb2xlcy1zdHIuZmlsdGVyLmpzIiwicm9sZXMvcm9sZXMuc2VydmljZS5qcyIsInN0YXR1cy9zdGF0dXMuc2VydmljZS5qcyIsInN1cHBvcnQvc3VwcG9ydC5zZXJ2aWNlLmpzIiwidGFzay1jb21tZW50cy90YXNrLWNvbW1lbnRzLnNlcnZpY2UuanMiLCJ0YXNrcy90YXNrcy5jb250cm9sbGVyLmpzIiwidGFza3MvdGFza3Mucm91dGUuanMiLCJ0YXNrcy90YXNrcy5zZXJ2aWNlLmpzIiwidHlwZXMvdHlwZXMuc2VydmljZS5qcyIsInVzZXJzL3Byb2ZpbGUuY29udHJvbGxlci5qcyIsInVzZXJzL3VzZXJzLmNvbnRyb2xsZXIuanMiLCJ1c2Vycy91c2Vycy5yb3V0ZS5qcyIsInVzZXJzL3VzZXJzLnNlcnZpY2UuanMiLCJ2Y3MvdmNzLmNvbnRyb2xsZXIuanMiLCJ2Y3MvdmNzLnJvdXRlLmpzIiwidmNzL3Zjcy5zZXJ2aWNlLmpzIiwid2lkZ2V0cy9ib3guY29tcG9uZW50LmpzIiwid2lkZ2V0cy9jb250ZW50LWJvZHkuY29tcG9uZW50LmpzIiwid2lkZ2V0cy9jb250ZW50LWhlYWRlci5jb21wb25lbnQuanMiLCJhdWRpdC9maWx0ZXJzL2F1ZGl0LWRldGFpbC10aXRsZS5maWx0ZXIuanMiLCJhdWRpdC9maWx0ZXJzL2F1ZGl0LW1vZGVsLmZpbHRlci5qcyIsImF1ZGl0L2ZpbHRlcnMvYXVkaXQtdHlwZS5maWx0ZXIuanMiLCJhdWRpdC9maWx0ZXJzL2F1ZGl0LXZhbHVlLmZpbHRlci5qcyIsImkxOG4vcHQtQlIvYXR0cmlidXRlcy5qcyIsImkxOG4vcHQtQlIvZGlhbG9nLmpzIiwiaTE4bi9wdC1CUi9nbG9iYWwuanMiLCJpMThuL3B0LUJSL21lc3NhZ2VzLmpzIiwiaTE4bi9wdC1CUi9tb2RlbHMuanMiLCJpMThuL3B0LUJSL3ZpZXdzLmpzIiwia2FuYmFuL3Rhc2staW5mby1kaWFsb2cvdGFzay1pbmZvLmNvbnRyb2xsZXIuanMiLCJ1c2Vycy9kaWFsb2cvdXNlcnMtZGlhbG9nLmNvbnRyb2xsZXIuanMiXSwibmFtZXMiOlsiYW5ndWxhciIsIm1vZHVsZSIsImNvbmZpZyIsIkdsb2JhbCIsIiRtZFRoZW1pbmdQcm92aWRlciIsIiRtb2RlbEZhY3RvcnlQcm92aWRlciIsIiR0cmFuc2xhdGVQcm92aWRlciIsIm1vbWVudCIsIiRtZEFyaWFQcm92aWRlciIsIiRtZERhdGVMb2NhbGVQcm92aWRlciIsInVzZUxvYWRlciIsInVzZVNhbml0aXplVmFsdWVTdHJhdGVneSIsInVzZVBvc3RDb21waWxpbmciLCJsb2NhbGUiLCJkZWZhdWx0T3B0aW9ucyIsInByZWZpeCIsImFwaVBhdGgiLCJ0aGVtZSIsInByaW1hcnlQYWxldHRlIiwiZGVmYXVsdCIsImFjY2VudFBhbGV0dGUiLCJ3YXJuUGFsZXR0ZSIsImVuYWJsZUJyb3dzZXJDb2xvciIsImRpc2FibGVXYXJuaW5ncyIsImZvcm1hdERhdGUiLCJkYXRlIiwiZm9ybWF0IiwiY29udHJvbGxlciIsIkFwcENvbnRyb2xsZXIiLCIkc3RhdGUiLCJBdXRoIiwidm0iLCJhbm9BdHVhbCIsImFjdGl2ZVByb2plY3QiLCJsb2dvdXQiLCJnZXRJbWFnZVBlcmZpbCIsImdldExvZ29NZW51Iiwic2V0QWN0aXZlUHJvamVjdCIsImdldEFjdGl2ZVByb2plY3QiLCJyZW1vdmVBY3RpdmVQcm9qZWN0IiwiYWN0aXZhdGUiLCJEYXRlIiwiZ2V0RnVsbFllYXIiLCJ0aGVuIiwiZ28iLCJsb2dpblN0YXRlIiwiY3VycmVudFVzZXIiLCJpbWFnZSIsImltYWdlUGF0aCIsInByb2plY3QiLCJsb2NhbFN0b3JhZ2UiLCJzZXRJdGVtIiwiZ2V0SXRlbSIsInJlbW92ZUl0ZW0iLCJjb25zdGFudCIsIl8iLCJhcHBOYW1lIiwiaG9tZVN0YXRlIiwibG9naW5VcmwiLCJyZXNldFBhc3N3b3JkU3RhdGUiLCJub3RBdXRob3JpemVkU3RhdGUiLCJ0b2tlbktleSIsImNsaWVudFBhdGgiLCJyb3V0ZXMiLCIkc3RhdGVQcm92aWRlciIsIiR1cmxSb3V0ZXJQcm92aWRlciIsInN0YXRlIiwidXJsIiwidGVtcGxhdGVVcmwiLCJhYnN0cmFjdCIsInJlc29sdmUiLCJ0cmFuc2xhdGVSZWFkeSIsIiR0cmFuc2xhdGUiLCIkcSIsImRlZmVycmVkIiwiZGVmZXIiLCJ1c2UiLCJwcm9taXNlIiwiZGF0YSIsIm5lZWRBdXRoZW50aWNhdGlvbiIsIndoZW4iLCJvdGhlcndpc2UiLCJydW4iLCIkcm9vdFNjb3BlIiwiJHN0YXRlUGFyYW1zIiwiYXV0aCIsImdsb2JhbCIsInJldHJpZXZlVXNlckZyb21Mb2NhbFN0b3JhZ2UiLCJBdWRpdENvbnRyb2xsZXIiLCIkY29udHJvbGxlciIsIkF1ZGl0U2VydmljZSIsIlByRGlhbG9nIiwib25BY3RpdmF0ZSIsImFwcGx5RmlsdGVycyIsInZpZXdEZXRhaWwiLCJtb2RlbFNlcnZpY2UiLCJvcHRpb25zIiwibW9kZWxzIiwicXVlcnlGaWx0ZXJzIiwiZ2V0QXVkaXRlZE1vZGVscyIsImlkIiwibGFiZWwiLCJpbnN0YW50Iiwic29ydCIsImluZGV4IiwibGVuZ3RoIiwibW9kZWwiLCJwdXNoIiwidG9Mb3dlckNhc2UiLCJ0eXBlcyIsImxpc3RUeXBlcyIsInR5cGUiLCJkZWZhdWx0UXVlcnlGaWx0ZXJzIiwiZXh0ZW5kIiwiYXVkaXREZXRhaWwiLCJsb2NhbHMiLCJjbG9zZSIsImlzQXJyYXkiLCJvbGQiLCJuZXciLCJjb250cm9sbGVyQXMiLCJoYXNCYWNrZHJvcCIsImN1c3RvbSIsIm5lZWRQcm9maWxlIiwiZmFjdG9yeSIsInNlcnZpY2VGYWN0b3J5IiwiYWN0aW9ucyIsIm1ldGhvZCIsImluc3RhbmNlIiwiYXVkaXRQYXRoIiwiJGh0dHAiLCJVc2Vyc1NlcnZpY2UiLCJsb2dpbiIsInVwZGF0ZUN1cnJlbnRVc2VyIiwiYXV0aGVudGljYXRlZCIsInNlbmRFbWFpbFJlc2V0UGFzc3dvcmQiLCJyZW1vdGVWYWxpZGF0ZVRva2VuIiwiZ2V0VG9rZW4iLCJzZXRUb2tlbiIsImNsZWFyVG9rZW4iLCJ0b2tlbiIsImdldCIsInJlamVjdCIsInVzZXIiLCJtZXJnZSIsImZyb21Kc29uIiwianNvblVzZXIiLCJ0b0pzb24iLCJjcmVkZW50aWFscyIsInBvc3QiLCJyZXNwb25zZSIsImVycm9yIiwicmVzZXREYXRhIiwiTG9naW5Db250cm9sbGVyIiwib3BlbkRpYWxvZ1Jlc2V0UGFzcyIsIm9wZW5EaWFsb2dTaWduVXAiLCJlbWFpbCIsInBhc3N3b3JkIiwiUGFzc3dvcmRDb250cm9sbGVyIiwiJHRpbWVvdXQiLCJQclRvYXN0Iiwic2VuZFJlc2V0IiwiY2xvc2VEaWFsb2ciLCJjbGVhbkZvcm0iLCJyZXNldCIsInN1Y2Nlc3MiLCJzdGF0dXMiLCJtc2ciLCJpIiwidG9VcHBlckNhc2UiLCJmaWVsZCIsIm1lc3NhZ2UiLCIkbW9kZWxGYWN0b3J5IiwicGFnaW5hdGUiLCJ3cmFwIiwiYWZ0ZXJSZXF1ZXN0IiwiTGlzdCIsIkNSVURDb250cm9sbGVyIiwiUHJQYWdpbmF0aW9uIiwic2VhcmNoIiwicGFnaW5hdGVTZWFyY2giLCJub3JtYWxTZWFyY2giLCJlZGl0Iiwic2F2ZSIsInJlbW92ZSIsImdvVG8iLCJyZWRpcmVjdEFmdGVyU2F2ZSIsInNlYXJjaE9uSW5pdCIsInBlclBhZ2UiLCJza2lwUGFnaW5hdGlvbiIsInZpZXdGb3JtIiwicmVzb3VyY2UiLCJpc0Z1bmN0aW9uIiwicGFnaW5hdG9yIiwiZ2V0SW5zdGFuY2UiLCJwYWdlIiwiY3VycmVudFBhZ2UiLCJpc0RlZmluZWQiLCJiZWZvcmVTZWFyY2giLCJjYWxjTnVtYmVyT2ZQYWdlcyIsInRvdGFsIiwicmVzb3VyY2VzIiwiaXRlbXMiLCJhZnRlclNlYXJjaCIsInJlc3BvbnNlRGF0YSIsIm9uU2VhcmNoRXJyb3IiLCJxdWVyeSIsImZvcm0iLCJiZWZvcmVDbGVhbiIsIiRzZXRQcmlzdGluZSIsIiRzZXRVbnRvdWNoZWQiLCJhZnRlckNsZWFuIiwiY29weSIsImFmdGVyRWRpdCIsImJlZm9yZVNhdmUiLCIkc2F2ZSIsImFmdGVyU2F2ZSIsIm9uU2F2ZUVycm9yIiwidGl0bGUiLCJkZXNjcmlwdGlvbiIsImNvbmZpcm0iLCJiZWZvcmVSZW1vdmUiLCIkZGVzdHJveSIsImFmdGVyUmVtb3ZlIiwiaW5mbyIsInZpZXdOYW1lIiwib25WaWV3IiwiZmlsdGVyIiwidGltZSIsInBhcnNlIiwidGltZU5vdyIsImdldFRpbWUiLCJkaWZmZXJlbmNlIiwic2Vjb25kcyIsIk1hdGgiLCJmbG9vciIsIm1pbnV0ZXMiLCJob3VycyIsImRheXMiLCJtb250aHMiLCJEYXNoYm9hcmRDb250cm9sbGVyIiwiJG1kRGlhbG9nIiwiRGFzaGJvYXJkc1NlcnZpY2UiLCJQcm9qZWN0c1NlcnZpY2UiLCJmaXhEYXRlIiwicHJvamVjdF9pZCIsImFjdHVhbFByb2plY3QiLCJkYXRlU3RyaW5nIiwiZ29Ub1Byb2plY3QiLCJvYmoiLCJ0b3RhbENvc3QiLCJlc3RpbWF0ZWRfY29zdCIsInRhc2tzIiwiZm9yRWFjaCIsInRhc2siLCJwYXJzZUZsb2F0IiwiaG91cl92YWx1ZV9maW5hbCIsImVzdGltYXRlZF90aW1lIiwidG9Mb2NhbGVTdHJpbmciLCJtaW5pbXVtRnJhY3Rpb25EaWdpdHMiLCJmaW5hbGl6ZVByb2plY3QiLCJ0ZXh0Q29udGVudCIsIm5hbWUiLCJvayIsImNhbmNlbCIsInNob3ciLCJmaW5hbGl6ZSIsIkVycm9yIiwiRGluYW1pY1F1ZXJ5U2VydmljZSIsImdldE1vZGVscyIsIkRpbmFtaWNRdWVyeXNDb250cm9sbGVyIiwibG9kYXNoIiwibG9hZEF0dHJpYnV0ZXMiLCJsb2FkT3BlcmF0b3JzIiwiYWRkRmlsdGVyIiwicnVuRmlsdGVyIiwiZWRpdEZpbHRlciIsImxvYWRNb2RlbHMiLCJyZW1vdmVGaWx0ZXIiLCJjbGVhciIsInJlc3RhcnQiLCJ3aGVyZSIsImFkZGVkRmlsdGVycyIsImF0dHJpYnV0ZSIsIm9wZXJhdG9yIiwidmFsdWUiLCJmaWx0ZXJzIiwiYXR0cmlidXRlcyIsIm9wZXJhdG9ycyIsImluZGV4T2YiLCJpc1VuZGVmaW5lZCIsImtleXMiLCJPYmplY3QiLCJrZXkiLCJzdGFydHNXaXRoIiwiJGluZGV4Iiwic3BsaWNlIiwiTGFuZ3VhZ2VMb2FkZXIiLCJTdXBwb3J0U2VydmljZSIsIiRsb2ciLCIkaW5qZWN0b3IiLCJzZXJ2aWNlIiwidHJhbnNsYXRlIiwidmlld3MiLCJkaWFsb2ciLCJtZXNzYWdlcyIsImxhbmdzIiwidEF0dHIiLCIkZmlsdGVyIiwidEJyZWFkY3J1bWIiLCJzcGxpdCIsInRNb2RlbCIsImF1dGhlbnRpY2F0aW9uTGlzdGVuZXIiLCIkb24iLCJldmVudCIsInRvU3RhdGUiLCJjYXRjaCIsIndhcm4iLCJwcmV2ZW50RGVmYXVsdCIsImF1dGhvcml6YXRpb25MaXN0ZW5lciIsImhhc1Byb2ZpbGUiLCJhbGxQcm9maWxlcyIsInNwaW5uZXJJbnRlcmNlcHRvciIsIiRodHRwUHJvdmlkZXIiLCIkcHJvdmlkZSIsInNob3dIaWRlU3Bpbm5lciIsInJlcXVlc3QiLCJoaWRlIiwicmVzcG9uc2VFcnJvciIsInJlamVjdGlvbiIsImludGVyY2VwdG9ycyIsInRva2VuSW50ZXJjZXB0b3IiLCJyZWRpcmVjdFdoZW5TZXJ2ZXJMb2dnZWRPdXQiLCJoZWFkZXJzIiwicmVqZWN0aW9uUmVhc29ucyIsInRva2VuRXJyb3IiLCJpcyIsInZhbGlkYXRpb25JbnRlcmNlcHRvciIsInNob3dFcnJvclZhbGlkYXRpb24iLCJza2lwVmFsaWRhdGlvbiIsImVycm9yVmFsaWRhdGlvbiIsIkthbmJhbkNvbnRyb2xsZXIiLCJUYXNrc1NlcnZpY2UiLCJTdGF0dXNTZXJ2aWNlIiwiJGRvY3VtZW50IiwiZmllbGRzIiwibWFwIiwiaXNNb3ZlZCIsImNvbHVtbnMiLCJ0ZXh0IiwiZGF0YUZpZWxkIiwic2x1ZyIsImNvbGxhcHNpYmxlIiwidGFncyIsInByaW9yaXR5Iiwic291cmNlIiwibG9jYWxEYXRhIiwiZGF0YVR5cGUiLCJkYXRhRmllbGRzIiwiZGF0YUFkYXB0ZXIiLCIkIiwianF4Iiwic2V0dGluZ3MiLCJrYW5iYW5SZWFkeSIsIm9uSXRlbU1vdmVkIiwib3duZXIiLCJ0YXNrX2lkIiwiYXJncyIsIml0ZW1JZCIsIm1pbGVzdG9uZSIsImRvbmUiLCJ1cGRhdGVUYXNrQnlLYW5iYW4iLCJvbGRDb2x1bW4iLCJuZXdDb2x1bW4iLCJvbkl0ZW1DbGlja2VkIiwidGFza0luZm8iLCJwYXJlbnQiLCJlbGVtZW50IiwiYm9keSIsImJpbmRUb0NvbnRyb2xsZXIiLCJlc2NhcGVUb0Nsb3NlIiwiY2xpY2tPdXRzaWRlVG9DbG9zZSIsIkthbmJhblNlcnZpY2UiLCJNZW51Q29udHJvbGxlciIsIiRtZFNpZGVuYXYiLCIkbWRDb2xvcnMiLCJvcGVuIiwib3Blbk1lbnVPclJlZGlyZWN0VG9TdGF0ZSIsIm1lbnVQcmVmaXgiLCJpdGVuc01lbnUiLCJpY29uIiwic3ViSXRlbnMiLCJzaWRlbmF2U3R5bGUiLCJ0b3AiLCJjb250ZW50IiwidGV4dENvbG9yIiwiY29sb3IiLCJsaW5lQm90dG9tIiwiZ2V0Q29sb3IiLCJ0b2dnbGUiLCIkbWRNZW51IiwiZXYiLCJpdGVtIiwiY29sb3JQYWxldHRlcyIsImdldFRoZW1lQ29sb3IiLCJNYWlsc0NvbnRyb2xsZXIiLCJNYWlsc1NlcnZpY2UiLCJmaWx0ZXJTZWxlY3RlZCIsInNraW4iLCJsYW5ndWFnZSIsImFsbG93ZWRDb250ZW50IiwiZW50aXRpZXMiLCJoZWlnaHQiLCJleHRyYVBsdWdpbnMiLCJsb2FkVXNlcnMiLCJvcGVuVXNlckRpYWxvZyIsImFkZFVzZXJNYWlsIiwic2VuZCIsImNyaXRlcmlhIiwibmFtZU9yRW1haWwiLCJub3RVc2VycyIsIm1haWwiLCJ1c2VycyIsInByb3BlcnR5IiwidG9TdHJpbmciLCJsaW1pdCIsImZpbmQiLCJvbkluaXQiLCJ1c2VyRGlhbG9nSW5wdXQiLCJ0cmFuc2ZlclVzZXJGbiIsIk1pbGVzdG9uZXNDb250cm9sbGVyIiwiTWlsZXN0b25lc1NlcnZpY2UiLCJlc3RpbWF0ZWRQcmljZSIsImVzdGltYXRlZF92YWx1ZSIsImVzdGltYXRlZFRpbWUiLCJkYXRlRW5kIiwiZGF0ZV9lbmQiLCJkYXRlQmVnaW4iLCJkYXRlX2JlZ2luIiwiZGlmZiIsImNvbG9yX2VzdGltYXRlZF90aW1lIiwidmlldyIsImNvbnNvbGUiLCJsb2ciLCJzZWFyY2hUYXNrIiwidGFza1Rlcm0iLCJtaWxlc3RvbmVTZWFyY2giLCJvblRhc2tDaGFuZ2UiLCJmaW5kSW5kZXgiLCJyZW1vdmVUYXNrIiwic2xpY2UiLCJzYXZlVGFza3MiLCJ1cGRhdGVNaWxlc3RvbmUiLCJtaWxlc3RvbmVfaWQiLCJ1cGRhdGVSZWxlYXNlIiwiUHJpb3JpdGllc1NlcnZpY2UiLCJQcm9qZWN0c0NvbnRyb2xsZXIiLCJSb2xlc1NlcnZpY2UiLCIkd2luZG93Iiwic2VhcmNoVXNlciIsImFkZFVzZXIiLCJyZW1vdmVVc2VyIiwidmlld1Byb2plY3QiLCJyb2xlcyIsInVzZXJzQXJyYXkiLCJ1c2VyX2lkIiwicXVlcnlsdGVycyIsImRldl9pZCIsInVzZXJOYW1lIiwiY2xpZW50X2lkIiwiY2xpZW50Iiwicm9sZSIsImRldmVsb3BlciIsInN0YWtlaG9sZGVyX2lkIiwic3Rha2Vob2xkZXIiLCJoaXN0b3J5QmFjayIsImhpc3RvcnkiLCJiYWNrIiwicGFyYW1zIiwiUmVsZWFzZXNDb250cm9sbGVyIiwiUmVsZWFzZXNTZXJ2aWNlIiwiY3V1cnJlbnRVc2VyIiwicmVsZWFzZSIsInJlbGVhc2VfaWQiLCJzZWFyY2hNaWxlc3RvbmUiLCJtaWxlc3RvbmVUZXJtIiwicmVsZWFzZVNlYXJjaCIsIm9uTWlsZXN0b25lQ2hhbmdlIiwibWlsZXN0b25lcyIsInJlbW92ZU1pbGVzdG9uZSIsInNhdmVNaWxlc3RvbmVzIiwicm9sZXNTdHIiLCJqb2luIiwiY2FjaGUiLCJUYXNrQ29tbWVudHNTZXJ2aWNlIiwic2F2ZVRhc2tDb21tZW50IiwicmVtb3ZlVGFza0NvbW1lbnQiLCJUYXNrc0NvbnRyb2xsZXIiLCJUeXBlc1NlcnZpY2UiLCJwcmlvcml0aWVzIiwic2F2ZUNvbW1lbnQiLCJjb21tZW50IiwiY29tbWVudF9pZCIsImFuc3dlciIsImNvbW1lbnRfdGV4dCIsInJlbW92ZUNvbW1lbnQiLCJQcm9maWxlQ29udHJvbGxlciIsInVwZGF0ZSIsImJpcnRoZGF5IiwidXBkYXRlUHJvZmlsZSIsIlVzZXJzQ29udHJvbGxlciIsImhpZGVEaWFsb2ciLCJzYXZlTmV3VXNlciIsImRlZmF1bHRzIiwib3ZlcnJpZGUiLCJhbGwiLCJ1c2VyUm9sZXMiLCJpbnRlcnNlY3Rpb24iLCJpc0FkbWluIiwiYnl0ZXMiLCJwcmVjaXNpb24iLCJpc05hTiIsImlzRmluaXRlIiwidW5pdHMiLCJudW1iZXIiLCJwb3ciLCJ0b0ZpeGVkIiwiVmNzQ29udHJvbGxlciIsIlZjc1NlcnZpY2UiLCJwYXRocyIsInRvZ2dsZVNwbGFzaFNjcmVlbiIsInVzZXJuYW1lIiwidXNlcm5hbWVfZ2l0aHViIiwicmVwbyIsInJlcG9fZ2l0aHViIiwicGF0aCIsInNvcnRSZXNvdXJjZXMiLCJsb2FkaW5nX3NjcmVlbiIsImZpbmlzaCIsImEiLCJiIiwib3BlbkZpbGVPckRpcmVjdG9yeSIsInBsZWFzZVdhaXQiLCJsb2dvIiwiYmFja2dyb3VuZENvbG9yIiwibG9hZGluZ0h0bWwiLCJjb21wb25lbnQiLCJyZXBsYWNlIiwidHJhbnNjbHVkZSIsInRvb2xiYXJCdXR0b25zIiwiZm9vdGVyQnV0dG9ucyIsImJpbmRpbmdzIiwiYm94VGl0bGUiLCJ0b29sYmFyQ2xhc3MiLCJ0b29sYmFyQmdDb2xvciIsIiR0cmFuc2NsdWRlIiwiY3RybCIsIiRvbkluaXQiLCJsYXlvdXRBbGlnbiIsImF1ZGl0RGV0YWlsVGl0bGUiLCJhdWRpdE1vZGVsIiwibW9kZWxJZCIsImF1ZGl0VHlwZSIsInR5cGVJZCIsImF1ZGl0VmFsdWUiLCJpc0RhdGUiLCJlbmRzV2l0aCIsIk51bWJlciIsImluaXRpYWxEYXRlIiwiZmluYWxEYXRlIiwic2NoZWR1bGVkX3RvIiwiZGF0ZV9zdGFydCIsImNvc3QiLCJob3VyVmFsdWVEZXZlbG9wZXIiLCJob3VyVmFsdWVDbGllbnQiLCJob3VyVmFsdWVGaW5hbCIsInJlbGVhc2VfZGF0ZSIsImNvbmZpcm1UaXRsZSIsImNvbmZpcm1EZXNjcmlwdGlvbiIsInJlbW92ZURlc2NyaXB0aW9uIiwiYXVkaXQiLCJjcmVhdGVkIiwidXBkYXRlZEJlZm9yZSIsInVwZGF0ZWRBZnRlciIsImRlbGV0ZWQiLCJyZXNldFBhc3N3b3JkIiwibG9hZGluZyIsInByb2Nlc3NpbmciLCJ5ZXMiLCJubyIsImludGVybmFsRXJyb3IiLCJub3RGb3VuZCIsIm5vdEF1dGhvcml6ZWQiLCJzZWFyY2hFcnJvciIsInNhdmVTdWNjZXNzIiwib3BlcmF0aW9uU3VjY2VzcyIsIm9wZXJhdGlvbkVycm9yIiwic2F2ZUVycm9yIiwicmVtb3ZlU3VjY2VzcyIsInJlbW92ZUVycm9yIiwicmVzb3VyY2VOb3RGb3VuZEVycm9yIiwibm90TnVsbEVycm9yIiwiZHVwbGljYXRlZFJlc291cmNlRXJyb3IiLCJzcHJpbnRFbmRlZFN1Y2Nlc3MiLCJzcHJpbnRFbmRlZEVycm9yIiwic3VjY2Vzc1NpZ25VcCIsImVycm9yc1NpZ25VcCIsInJlbGVhc2V0RW5kZWRTdWNjZXNzIiwicmVsZWFzZUVuZGVkRXJyb3IiLCJwcm9qZWN0RW5kZWRTdWNjZXNzIiwicHJvamVjdEVuZGVkRXJyb3IiLCJ2YWxpZGF0ZSIsImZpZWxkUmVxdWlyZWQiLCJsYXlvdXQiLCJlcnJvcjQwNCIsImxvZ291dEluYWN0aXZlIiwiaW52YWxpZENyZWRlbnRpYWxzIiwidW5rbm93bkVycm9yIiwidXNlck5vdEZvdW5kIiwiZGFzaGJvYXJkIiwid2VsY29tZSIsIm1haWxFcnJvcnMiLCJzZW5kTWFpbFN1Y2Nlc3MiLCJzZW5kTWFpbEVycm9yIiwicGFzc3dvcmRTZW5kaW5nU3VjY2VzcyIsInJlbW92ZVlvdXJTZWxmRXJyb3IiLCJ1c2VyRXhpc3RzIiwicHJvZmlsZSIsInVwZGF0ZUVycm9yIiwicXVlcnlEaW5hbWljIiwibm9GaWx0ZXIiLCJicmVhZGNydW1icyIsInByb2plY3RzIiwia2FuYmFuIiwidmNzIiwicmVsZWFzZXMiLCJ0aXRsZXMiLCJtYWlsU2VuZCIsInRhc2tMaXN0IiwidXNlckxpc3QiLCJhdWRpdExpc3QiLCJyZWdpc3RlciIsImNsZWFyQWxsIiwibGlzdCIsImdldE91dCIsImFkZCIsImluIiwibG9hZEltYWdlIiwic2lnbnVwIiwiY3JpYXJQcm9qZXRvIiwicHJvamVjdExpc3QiLCJ0YXNrc0xpc3QiLCJtaWxlc3RvbmVzTGlzdCIsInJlcGx5IiwiYWN0aW9uIiwiZGF0ZVN0YXJ0IiwiYWxsUmVzb3VyY2VzIiwidXBkYXRlZCIsImNvbmZpcm1QYXNzd29yZCIsInRvIiwic3ViamVjdCIsInJlc3VsdHMiLCJlcXVhbHMiLCJkaWZlcmVudCIsImNvbnRlaW5zIiwic3RhcnRXaXRoIiwiZmluaXNoV2l0aCIsImJpZ2dlclRoYW4iLCJlcXVhbHNPckJpZ2dlclRoYW4iLCJsZXNzVGhhbiIsImVxdWFsc09yTGVzc1RoYW4iLCJ0b3RhbFRhc2siLCJwZXJmaWxzIiwibWVudSIsInRvb2x0aXBzIiwicGVyZmlsIiwidHJhbnNmZXIiLCJsaXN0VGFzayIsIlRhc2tJbmZvQ29udHJvbGxlciIsIlVzZXJzRGlhbG9nQ29udHJvbGxlciIsInRyYW5zZmVyVXNlciJdLCJtYXBwaW5ncyI6IkFBQUE7OztBQ0NBLENBQUMsWUFBVztFQUNWOztFQUVBQSxRQUFRQyxPQUFPLE9BQU8sQ0FDcEIsYUFDQSxVQUNBLGFBQ0EsWUFDQSxrQkFDQSxhQUNBLGNBQ0EsZ0JBQ0EsaUJBQ0Esd0JBQ0EsMEJBQ0EscUJBQ0EsY0FDQSxhQUNBLFdBQ0E7O0FEWko7O0FFUkMsQ0FBQSxZQUFZO0VBQ1g7OztFQUVBRCxRQUNHQyxPQUFPLE9BQ1BDLE9BQU9BOzs7O0VBSVYsU0FBU0EsT0FBT0MsUUFBUUMsb0JBQW9CQztFQUMxQ0Msb0JBQW9CQyxRQUFRQyxpQkFBaUJDLHVCQUF1Qjs7SUFFcEVILG1CQUNHSSxVQUFVLGtCQUNWQyx5QkFBeUI7O0lBRTVCTCxtQkFBbUJNLGlCQUFpQjs7SUFFcENMLE9BQU9NLE9BQU87OztJQUdkUixzQkFBc0JTLGVBQWVDLFNBQVNaLE9BQU9hOzs7SUFHckRaLG1CQUFtQmEsTUFBTSxXQUN0QkMsZUFBZSxRQUFRO01BQ3RCQyxTQUFTO09BRVZDLGNBQWMsU0FDZEMsWUFBWTs7O0lBR2ZqQixtQkFBbUJrQjs7SUFFbkJkLGdCQUFnQmU7O0lBRWhCZCxzQkFBc0JlLGFBQWEsVUFBU0MsTUFBTTtNQUNoRCxPQUFPQSxPQUFPbEIsT0FBT2tCLE1BQU1DLE9BQU8sZ0JBQWdCOzs7O0FGT3hEOztBRzVDQSxDQUFDLFlBQVc7O0VBRVY7OztFQUVBMUIsUUFDR0MsT0FBTyxPQUNQMEIsV0FBVyxpQkFBaUJDOzs7Ozs7O0VBTy9CLFNBQVNBLGNBQWNDLFFBQVFDLE1BQU0zQixRQUFRO0lBQzNDLElBQUk0QixLQUFLOzs7SUFHVEEsR0FBR0MsV0FBVztJQUNkRCxHQUFHRSxnQkFBZ0I7O0lBRW5CRixHQUFHRyxTQUFhQTtJQUNoQkgsR0FBR0ksaUJBQWlCQTtJQUNw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QUNsQjlELEdBQUdxRixRQUFRQTs7SUFFWCxJQUFJcEgsUUFBUXFNLFVBQVV1TyxrQkFBa0I7TUFDdEM3WSxHQUFHeW9CLGVBQWU1UCxnQkFBZ0JDOzs7O0lBSXBDcFYsWUFBWSxrQkFBa0I7TUFDNUIxRCxJQUFJQTtNQUNKZ0UsY0FBY29DO01BQ2R3RCxjQUFjZ1A7TUFDZDNVLFNBQVM7UUFDUDRGLFNBQVM7Ozs7SUFJYixTQUFTaEcsYUFBYTtNQUNwQjdELEdBQUdtRSxlQUFlOzs7SUFHcEIsU0FBU0wsZUFBZTtNQUN0QixPQUFPN0YsUUFBUWlILE9BQU9sRixHQUFHaUYscUJBQXFCakYsR0FBR21FOzs7SUFHbkQsU0FBU2tCLFFBQVE7TUFDZnpCLFNBQVN5Qjs7O0tBMUNmIiwiZmlsZSI6ImFwcGxpY2F0aW9uLmpzIiwic291cmNlc0NvbnRlbnQiOlsiJ3VzZSBzdHJpY3QnO1xuXG4vKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCovXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcsIFsnbmdBbmltYXRlJywgJ25nQXJpYScsICd1aS5yb3V0ZXInLCAnbmdQcm9kZWInLCAndWkudXRpbHMubWFza3MnLCAndGV4dC1tYXNrJywgJ25nTWF0ZXJpYWwnLCAnbW9kZWxGYWN0b3J5JywgJ21kLmRhdGEudGFibGUnLCAnbmdNYXRlcmlhbERhdGVQaWNrZXInLCAncGFzY2FscHJlY2h0LnRyYW5zbGF0ZScsICdhbmd1bGFyRmlsZVVwbG9hZCcsICduZ01lc3NhZ2VzJywgJ2pxd2lkZ2V0cycsICd1aS5tYXNrJywgJ25nUm91dGUnXSk7XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbmZpZyhjb25maWcpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gY29uZmlnKEdsb2JhbCwgJG1kVGhlbWluZ1Byb3ZpZGVyLCAkbW9kZWxGYWN0b3J5UHJvdmlkZXIsIC8vIE5PU09OQVJcbiAgJHRyYW5zbGF0ZVByb3ZpZGVyLCBtb21lbnQsICRtZEFyaWFQcm92aWRlciwgJG1kRGF0ZUxvY2FsZVByb3ZpZGVyKSB7XG5cbiAgICAkdHJhbnNsYXRlUHJvdmlkZXIudXNlTG9hZGVyKCdsYW5ndWFnZUxvYWRlcicpLnVzZVNhbml0aXplVmFsdWVTdHJhdGVneSgnZXNjYXBlJyk7XG5cbiAgICAkdHJhbnNsYXRlUHJvdmlkZXIudXNlUG9zdENvbXBpbGluZyh0cnVlKTtcblxuICAgIG1vbWVudC5sb2NhbGUoJ3B0LUJSJyk7XG5cbiAgICAvL29zIHNlcnZpw6dvcyByZWZlcmVudGUgYW9zIG1vZGVscyB2YWkgdXRpbGl6YXIgY29tbyBiYXNlIG5hcyB1cmxzXG4gICAgJG1vZGVsRmFjdG9yeVByb3ZpZGVyLmRlZmF1bHRPcHRpb25zLnByZWZpeCA9IEdsb2JhbC5hcGlQYXRoO1xuXG4gICAgLy8gQ29uZmlndXJhdGlvbiB0aGVtZVxuICAgICRtZFRoZW1pbmdQcm92aWRlci50aGVtZSgnZGVmYXVsdCcpLnByaW1hcnlQYWxldHRlKCdncmV5Jywge1xuICAgICAgZGVmYXVsdDogJzgwMCdcbiAgICB9KS5hY2NlbnRQYWxldHRlKCdhbWJlcicpLndhcm5QYWxldHRlKCdkZWVwLW9yYW5nZScpO1xuXG4gICAgLy8gRW5hYmxlIGJyb3dzZXIgY29sb3JcbiAgICAkbWRUaGVtaW5nUHJvdmlkZXIuZW5hYmxlQnJvd3NlckNvbG9yKCk7XG5cbiAgICAkbWRBcmlhUHJvdmlkZXIuZGlzYWJsZVdhcm5pbmdzKCk7XG5cbiAgICAkbWREYXRlTG9jYWxlUHJvdmlkZXIuZm9ybWF0RGF0ZSA9IGZ1bmN0aW9uIChkYXRlKSB7XG4gICAgICByZXR1cm4gZGF0ZSA/IG1vbWVudChkYXRlKS5mb3JtYXQoJ0REL01NL1lZWVknKSA6ICcnO1xuICAgIH07XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb250cm9sbGVyKCdBcHBDb250cm9sbGVyJywgQXBwQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvKipcbiAgICogQ29udHJvbGFkb3IgcmVzcG9uc8OhdmVsIHBvciBmdW5jaW9uYWxpZGFkZXMgcXVlIHPDo28gYWNpb25hZGFzIGVtIHF1YWxxdWVyIHRlbGEgZG8gc2lzdGVtYVxuICAgKlxuICAgKi9cbiAgZnVuY3Rpb24gQXBwQ29udHJvbGxlcigkc3RhdGUsIEF1dGgsIEdsb2JhbCkge1xuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICAvL2FubyBhdHVhbCBwYXJhIHNlciBleGliaWRvIG5vIHJvZGFww6kgZG8gc2lzdGVtYVxuICAgIHZtLmFub0F0dWFsID0gbnVsbDtcbiAgICB2bS5hY3RpdmVQcm9qZWN0ID0gbnVsbDtcblxuICAgIHZtLmxvZ291dCA9IGxvZ291dDtcbiAgICB2bS5nZXRJbWFnZVBlcmZpbCA9IGdldEltYWdlUGVyZmlsO1xuICAgIHZtLmdldExvZ29NZW51ID0gZ2V0TG9nb01lbnU7XG4gICAgdm0uc2V0QWN0aXZlUHJvamVjdCA9IHNldEFjdGl2ZVByb2plY3Q7XG4gICAgdm0uZ2V0QWN0aXZlUHJvamVjdCA9IGdldEFjdGl2ZVByb2plY3Q7XG4gICAgdm0ucmVtb3ZlQWN0aXZlUHJvamVjdCA9IHJlbW92ZUFjdGl2ZVByb2plY3Q7XG5cbiAgICBhY3RpdmF0ZSgpO1xuXG4gICAgZnVuY3Rpb24gYWN0aXZhdGUoKSB7XG4gICAgICB2YXIgZGF0ZSA9IG5ldyBEYXRlKCk7XG5cbiAgICAgIHZtLmFub0F0dWFsID0gZGF0ZS5nZXRGdWxsWWVhcigpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGxvZ291dCgpIHtcbiAgICAgIEF1dGgubG9nb3V0KCkudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgICRzdGF0ZS5nbyhHbG9iYWwubG9naW5TdGF0ZSk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBnZXRJbWFnZVBlcmZpbCgpIHtcbiAgICAgIHJldHVybiBBdXRoLmN1cnJlbnRVc2VyICYmIEF1dGguY3VycmVudFVzZXIuaW1hZ2UgPyBBdXRoLmN1cnJlbnRVc2VyLmltYWdlIDogR2xvYmFsLmltYWdlUGF0aCArICcvbm9fYXZhdGFyLmdpZic7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gZ2V0TG9nb01lbnUoKSB7XG4gICAgICByZXR1cm4gR2xvYmFsLmltYWdlUGF0aCArICcvbG9nby12ZXJ0aWNhbC5wbmcnO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIHNldEFjdGl2ZVByb2plY3QocHJvamVjdCkge1xuICAgICAgbG9jYWxTdG9yYWdlLnNldEl0ZW0oJ3Byb2plY3QnLCBwcm9qZWN0KTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBnZXRBY3RpdmVQcm9qZWN0KCkge1xuICAgICAgcmV0dXJuIGxvY2FsU3RvcmFnZS5nZXRJdGVtKCdwcm9qZWN0Jyk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gcmVtb3ZlQWN0aXZlUHJvamVjdCgpIHtcbiAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKCdwcm9qZWN0Jyk7XG4gICAgfVxuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4vKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCwgbm8tdW5kZWY6IDAqL1xuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIC8qKlxuICAgKiBUcmFuc2Zvcm1hIGJpYmxpb3RlY2FzIGV4dGVybmFzIGVtIHNlcnZpw6dvcyBkbyBhbmd1bGFyIHBhcmEgc2VyIHBvc3PDrXZlbCB1dGlsaXphclxuICAgKiBhdHJhdsOpcyBkYSBpbmplw6fDo28gZGUgZGVwZW5kw6puY2lhXG4gICAqL1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25zdGFudCgnbG9kYXNoJywgXykuY29uc3RhbnQoJ21vbWVudCcsIG1vbWVudCk7XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbnN0YW50KCdHbG9iYWwnLCB7XG4gICAgYXBwTmFtZTogJ0ZyZWVsYWdpbGUnLFxuICAgIGhvbWVTdGF0ZTogJ2FwcC5wcm9qZWN0cycsXG4gICAgbG9naW5Vcmw6ICdhcHAvbG9naW4nLFxuICAgIGxvZ2luU3RhdGU6ICdhcHAubG9naW4nLFxuICAgIHJlc2V0UGFzc3dvcmRTdGF0ZTogJ2FwcC5wYXNzd29yZC1yZXNldCcsXG4gICAgbm90QXV0aG9yaXplZFN0YXRlOiAnYXBwLm5vdC1hdXRob3JpemVkJyxcbiAgICB0b2tlbktleTogJ3NlcnZlcl90b2tlbicsXG4gICAgY2xpZW50UGF0aDogJ2NsaWVudC9hcHAnLFxuICAgIGFwaVBhdGg6ICdhcGkvdjEnLFxuICAgIGltYWdlUGF0aDogJ2NsaWVudC9pbWFnZXMnXG4gIH0pO1xufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25maWcocm91dGVzKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvdXRlcygkc3RhdGVQcm92aWRlciwgJHVybFJvdXRlclByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnYXBwJywge1xuICAgICAgdXJsOiAnL2FwcCcsXG4gICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL2xheW91dC9hcHAuaHRtbCcsXG4gICAgICBhYnN0cmFjdDogdHJ1ZSxcbiAgICAgIHJlc29sdmU6IHsgLy9lbnN1cmUgbGFuZ3MgaXMgcmVhZHkgYmVmb3JlIHJlbmRlciB2aWV3XG4gICAgICAgIHRyYW5zbGF0ZVJlYWR5OiBbJyR0cmFuc2xhdGUnLCAnJHEnLCBmdW5jdGlvbiAoJHRyYW5zbGF0ZSwgJHEpIHtcbiAgICAgICAgICB2YXIgZGVmZXJyZWQgPSAkcS5kZWZlcigpO1xuXG4gICAgICAgICAgJHRyYW5zbGF0ZS51c2UoJ3B0LUJSJykudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICBkZWZlcnJlZC5yZXNvbHZlKCk7XG4gICAgICAgICAgfSk7XG5cbiAgICAgICAgICByZXR1cm4gZGVmZXJyZWQucHJvbWlzZTtcbiAgICAgICAgfV1cbiAgICAgIH1cbiAgICB9KS5zdGF0ZShHbG9iYWwubm90QXV0aG9yaXplZFN0YXRlLCB7XG4gICAgICB1cmw6ICcvYWNlc3NvLW5lZ2FkbycsXG4gICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL2xheW91dC9ub3QtYXV0aG9yaXplZC5odG1sJyxcbiAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiBmYWxzZSB9XG4gICAgfSk7XG5cbiAgICAkdXJsUm91dGVyUHJvdmlkZXIud2hlbignL2FwcCcsIEdsb2JhbC5sb2dpblVybCk7XG4gICAgJHVybFJvdXRlclByb3ZpZGVyLm90aGVyd2lzZShHbG9iYWwubG9naW5VcmwpO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLnJ1bihydW4pO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gcnVuKCRyb290U2NvcGUsICRzdGF0ZSwgJHN0YXRlUGFyYW1zLCBBdXRoLCBHbG9iYWwpIHtcbiAgICAvLyBOT1NPTkFSXG4gICAgLy9zZXRhZG8gbm8gcm9vdFNjb3BlIHBhcmEgcG9kZXIgc2VyIGFjZXNzYWRvIG5hcyB2aWV3cyBzZW0gcHJlZml4byBkZSBjb250cm9sbGVyXG4gICAgJHJvb3RTY29wZS4kc3RhdGUgPSAkc3RhdGU7XG4gICAgJHJvb3RTY29wZS4kc3RhdGVQYXJhbXMgPSAkc3RhdGVQYXJhbXM7XG4gICAgJHJvb3RTY29wZS5hdXRoID0gQXV0aDtcbiAgICAkcm9vdFNjb3BlLmdsb2JhbCA9IEdsb2JhbDtcblxuICAgIC8vbm8gaW5pY2lvIGNhcnJlZ2EgbyB1c3XDoXJpbyBkbyBsb2NhbHN0b3JhZ2UgY2FzbyBvIHVzdcOhcmlvIGVzdGFqYSBhYnJpbmRvIG8gbmF2ZWdhZG9yXG4gICAgLy9wYXJhIHZvbHRhciBhdXRlbnRpY2Fkb1xuICAgIEF1dGgucmV0cmlldmVVc2VyRnJvbUxvY2FsU3RvcmFnZSgpO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29udHJvbGxlcignQXVkaXRDb250cm9sbGVyJywgQXVkaXRDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIEF1ZGl0Q29udHJvbGxlcigkY29udHJvbGxlciwgQXVkaXRTZXJ2aWNlLCBQckRpYWxvZywgR2xvYmFsLCAkdHJhbnNsYXRlKSB7XG4gICAgLy8gTk9TT05BUlxuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICB2bS5vbkFjdGl2YXRlID0gb25BY3RpdmF0ZTtcbiAgICB2bS5hcHBseUZpbHRlcnMgPSBhcHBseUZpbHRlcnM7XG4gICAgdm0udmlld0RldGFpbCA9IHZpZXdEZXRhaWw7XG5cbiAgICAkY29udHJvbGxlcignQ1JVRENvbnRyb2xsZXInLCB7IHZtOiB2bSwgbW9kZWxTZXJ2aWNlOiBBdWRpdFNlcnZpY2UsIG9wdGlvbnM6IHt9IH0pO1xuXG4gICAgZnVuY3Rpb24gb25BY3RpdmF0ZSgpIHtcbiAgICAgIHZtLm1vZGVscyA9IFtdO1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0ge307XG5cbiAgICAgIC8vUGVnYSB0b2RvcyBvcyBtb2RlbHMgZG8gc2VydmVyIGUgbW9udGEgdW1hIGxpc3RhIHBybyBDb21ib0JveFxuICAgICAgQXVkaXRTZXJ2aWNlLmdldEF1ZGl0ZWRNb2RlbHMoKS50aGVuKGZ1bmN0aW9uIChkYXRhKSB7XG4gICAgICAgIHZhciBtb2RlbHMgPSBbeyBpZDogJycsIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ2dsb2JhbC5hbGwnKSB9XTtcblxuICAgICAgICBkYXRhLm1vZGVscy5zb3J0KCk7XG5cbiAgICAgICAgZm9yICh2YXIgaW5kZXggPSAwOyBpbmRleCA8IGRhdGEubW9kZWxzLmxlbmd0aDsgaW5kZXgrKykge1xuICAgICAgICAgIHZhciBtb2RlbCA9IGRhdGEubW9kZWxzW2luZGV4XTtcblxuICAgICAgICAgIG1vZGVscy5wdXNoKHtcbiAgICAgICAgICAgIGlkOiBtb2RlbCxcbiAgICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ21vZGVscy4nICsgbW9kZWwudG9Mb3dlckNhc2UoKSlcbiAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHZtLm1vZGVscyA9IG1vZGVscztcbiAgICAgICAgdm0ucXVlcnlGaWx0ZXJzLm1vZGVsID0gdm0ubW9kZWxzWzBdLmlkO1xuICAgICAgfSk7XG5cbiAgICAgIHZtLnR5cGVzID0gQXVkaXRTZXJ2aWNlLmxpc3RUeXBlcygpO1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzLnR5cGUgPSB2bS50eXBlc1swXS5pZDtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBhcHBseUZpbHRlcnMoZGVmYXVsdFF1ZXJ5RmlsdGVycykge1xuICAgICAgcmV0dXJuIGFuZ3VsYXIuZXh0ZW5kKGRlZmF1bHRRdWVyeUZpbHRlcnMsIHZtLnF1ZXJ5RmlsdGVycyk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gdmlld0RldGFpbChhdWRpdERldGFpbCkge1xuICAgICAgdmFyIGNvbmZpZyA9IHtcbiAgICAgICAgbG9jYWxzOiB7IGF1ZGl0RGV0YWlsOiBhdWRpdERldGFpbCB9LFxuICAgICAgICAvKiogQG5nSW5qZWN0ICovXG4gICAgICAgIGNvbnRyb2xsZXI6IGZ1bmN0aW9uIGNvbnRyb2xsZXIoYXVkaXREZXRhaWwsIFByRGlhbG9nKSB7XG4gICAgICAgICAgdmFyIHZtID0gdGhpcztcblxuICAgICAgICAgIHZtLmNsb3NlID0gY2xvc2U7XG5cbiAgICAgICAgICBhY3RpdmF0ZSgpO1xuXG4gICAgICAgICAgZnVuY3Rpb24gYWN0aXZhdGUoKSB7XG4gICAgICAgICAgICBpZiAoYW5ndWxhci5pc0FycmF5KGF1ZGl0RGV0YWlsLm9sZCkgJiYgYXVkaXREZXRhaWwub2xkLmxlbmd0aCA9PT0gMCkgYXVkaXREZXRhaWwub2xkID0gbnVsbDtcbiAgICAgICAgICAgIGlmIChhbmd1bGFyLmlzQXJyYXkoYXVkaXREZXRhaWwubmV3KSAmJiBhdWRpdERldGFpbC5uZXcubGVuZ3RoID09PSAwKSBhdWRpdERldGFpbC5uZXcgPSBudWxsO1xuXG4gICAgICAgICAgICB2bS5hdWRpdERldGFpbCA9IGF1ZGl0RGV0YWlsO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIGZ1bmN0aW9uIGNsb3NlKCkge1xuICAgICAgICAgICAgUHJEaWFsb2cuY2xvc2UoKTtcbiAgICAgICAgICB9XG4gICAgICAgIH0sXG4gICAgICAgIGNvbnRyb2xsZXJBczogJ2F1ZGl0RGV0YWlsQ3RybCcsXG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvYXVkaXQvYXVkaXQtZGV0YWlsLmh0bWwnLFxuICAgICAgICBoYXNCYWNrZHJvcDogdHJ1ZVxuICAgICAgfTtcblxuICAgICAgUHJEaWFsb2cuY3VzdG9tKGNvbmZpZyk7XG4gICAgfVxuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKlxuICAgKiBBcnF1aXZvIGRlIGNvbmZpZ3VyYcOnw6NvIGNvbSBhcyByb3RhcyBlc3BlY8OtZmljYXMgZGUgYXVkaXRvcmlhXG4gICAqXG4gICAqIEBwYXJhbSB7YW55fSAkc3RhdGVQcm92aWRlclxuICAgKiBAcGFyYW0ge2FueX0gR2xvYmFsXG4gICAqL1xuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvdXRlcygkc3RhdGVQcm92aWRlciwgR2xvYmFsKSB7XG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ2FwcC5hdWRpdCcsIHtcbiAgICAgIHVybDogJy9hdWRpdG9yaWEnLFxuICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9hdWRpdC9hdWRpdC5odG1sJyxcbiAgICAgIGNvbnRyb2xsZXI6ICdBdWRpdENvbnRyb2xsZXIgYXMgYXVkaXRDdHJsJyxcbiAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiB0cnVlLCBuZWVkUHJvZmlsZTogWydhZG1pbiddIH1cbiAgICB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5mYWN0b3J5KCdBdWRpdFNlcnZpY2UnLCBBdWRpdFNlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gQXVkaXRTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5LCAkdHJhbnNsYXRlKSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCdhdWRpdCcsIHtcbiAgICAgIGFjdGlvbnM6IHtcbiAgICAgICAgZ2V0QXVkaXRlZE1vZGVsczoge1xuICAgICAgICAgIG1ldGhvZDogJ0dFVCcsXG4gICAgICAgICAgdXJsOiAnbW9kZWxzJ1xuICAgICAgICB9XG4gICAgICB9LFxuICAgICAgaW5zdGFuY2U6IHt9LFxuICAgICAgbGlzdFR5cGVzOiBmdW5jdGlvbiBsaXN0VHlwZXMoKSB7XG4gICAgICAgIHZhciBhdWRpdFBhdGggPSAndmlld3MuZmllbGRzLmF1ZGl0Lic7XG5cbiAgICAgICAgcmV0dXJuIFt7IGlkOiAnJywgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudChhdWRpdFBhdGggKyAnYWxsUmVzb3VyY2VzJykgfSwgeyBpZDogJ2NyZWF0ZWQnLCBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KGF1ZGl0UGF0aCArICd0eXBlLmNyZWF0ZWQnKSB9LCB7IGlkOiAndXBkYXRlZCcsIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoYXVkaXRQYXRoICsgJ3R5cGUudXBkYXRlZCcpIH0sIHsgaWQ6ICdkZWxldGVkJywgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudChhdWRpdFBhdGggKyAndHlwZS5kZWxldGVkJykgfV07XG4gICAgICB9XG4gICAgfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqXG4gICAqIEFycXVpdm8gZGUgY29uZmlndXJhw6fDo28gY29tIGFzIHJvdGFzIGVzcGVjw61maWNhcyBkbyByZWN1cnNvIHVzZXJcbiAgICpcbiAgICogQHBhcmFtIHthbnl9ICRzdGF0ZVByb3ZpZGVyXG4gICAqIEBwYXJhbSB7YW55fSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZShHbG9iYWwucmVzZXRQYXNzd29yZFN0YXRlLCB7XG4gICAgICB1cmw6ICcvcGFzc3dvcmQvcmVzZXQvOnRva2VuJyxcbiAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvYXV0aC9yZXNldC1wYXNzLWZvcm0uaHRtbCcsXG4gICAgICBjb250cm9sbGVyOiAnUGFzc3dvcmRDb250cm9sbGVyIGFzIHBhc3NDdHJsJyxcbiAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiBmYWxzZSB9XG4gICAgfSkuc3RhdGUoR2xvYmFsLmxvZ2luU3RhdGUsIHtcbiAgICAgIHVybDogJy9sb2dpbicsXG4gICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL2F1dGgvbG9naW4uaHRtbCcsXG4gICAgICBjb250cm9sbGVyOiAnTG9naW5Db250cm9sbGVyIGFzIGxvZ2luQ3RybCcsXG4gICAgICBkYXRhOiB7IG5lZWRBdXRoZW50aWNhdGlvbjogZmFsc2UgfVxuICAgIH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZhY3RvcnkoJ0F1dGgnLCBBdXRoKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIEF1dGgoJGh0dHAsICRxLCBHbG9iYWwsIFVzZXJzU2VydmljZSkge1xuICAgIC8vIE5PU09OQVJcbiAgICB2YXIgYXV0aCA9IHtcbiAgICAgIGxvZ2luOiBsb2dpbixcbiAgICAgIGxvZ291dDogbG9nb3V0LFxuICAgICAgdXBkYXRlQ3VycmVudFVzZXI6IHVwZGF0ZUN1cnJlbnRVc2VyLFxuICAgICAgcmV0cmlldmVVc2VyRnJvbUxvY2FsU3RvcmFnZTogcmV0cmlldmVVc2VyRnJvbUxvY2FsU3RvcmFnZSxcbiAgICAgIGF1dGhlbnRpY2F0ZWQ6IGF1dGhlbnRpY2F0ZWQsXG4gICAgICBzZW5kRW1haWxSZXNldFBhc3N3b3JkOiBzZW5kRW1haWxSZXNldFBhc3N3b3JkLFxuICAgICAgcmVtb3RlVmFsaWRhdGVUb2tlbjogcmVtb3RlVmFsaWRhdGVUb2tlbixcbiAgICAgIGdldFRva2VuOiBnZXRUb2tlbixcbiAgICAgIHNldFRva2VuOiBzZXRUb2tlbixcbiAgICAgIGNsZWFyVG9rZW46IGNsZWFyVG9rZW4sXG4gICAgICBjdXJyZW50VXNlcjogbnVsbFxuICAgIH07XG5cbiAgICBmdW5jdGlvbiBjbGVhclRva2VuKCkge1xuICAgICAgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oR2xvYmFsLnRva2VuS2V5KTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBzZXRUb2tlbih0b2tlbikge1xuICAgICAgbG9jYWxTdG9yYWdlLnNldEl0ZW0oR2xvYmFsLnRva2VuS2V5LCB0b2tlbik7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gZ2V0VG9rZW4oKSB7XG4gICAgICByZXR1cm4gbG9jYWxTdG9yYWdlLmdldEl0ZW0oR2xvYmFsLnRva2VuS2V5KTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiByZW1vdGVWYWxpZGF0ZVRva2VuKCkge1xuICAgICAgdmFyIGRlZmVycmVkID0gJHEuZGVmZXIoKTtcblxuICAgICAgaWYgKGF1dGguYXV0aGVudGljYXRlZCgpKSB7XG4gICAgICAgICRodHRwLmdldChHbG9iYWwuYXBpUGF0aCArICcvYXV0aGVudGljYXRlL2NoZWNrJykudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgZGVmZXJyZWQucmVzb2x2ZSh0cnVlKTtcbiAgICAgICAgfSwgZnVuY3Rpb24gKCkge1xuICAgICAgICAgIGF1dGgubG9nb3V0KCk7XG5cbiAgICAgICAgICBkZWZlcnJlZC5yZWplY3QoZmFsc2UpO1xuICAgICAgICB9KTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIGF1dGgubG9nb3V0KCk7XG5cbiAgICAgICAgZGVmZXJyZWQucmVqZWN0KGZhbHNlKTtcbiAgICAgIH1cblxuICAgICAgcmV0dXJuIGRlZmVycmVkLnByb21pc2U7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogVmVyaWZpY2Egc2UgbyB1c3XDoXJpbyBlc3TDoSBhdXRlbnRpY2Fkb1xuICAgICAqXG4gICAgICogQHJldHVybnMge2Jvb2xlYW59XG4gICAgICovXG4gICAgZnVuY3Rpb24gYXV0aGVudGljYXRlZCgpIHtcbiAgICAgIHJldHVybiBhdXRoLmdldFRva2VuKCkgIT09IG51bGw7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVjdXBlcmEgbyB1c3XDoXJpbyBkbyBsb2NhbFN0b3JhZ2VcbiAgICAgKi9cbiAgICBmdW5jdGlvbiByZXRyaWV2ZVVzZXJGcm9tTG9jYWxTdG9yYWdlKCkge1xuICAgICAgdmFyIHVzZXIgPSBsb2NhbFN0b3JhZ2UuZ2V0SXRlbSgndXNlcicpO1xuXG4gICAgICBpZiAodXNlcikge1xuICAgICAgICBhdXRoLmN1cnJlbnRVc2VyID0gYW5ndWxhci5tZXJnZShuZXcgVXNlcnNTZXJ2aWNlKCksIGFuZ3VsYXIuZnJvbUpzb24odXNlcikpO1xuICAgICAgfVxuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEd1YXJkYSBvIHVzdcOhcmlvIG5vIGxvY2FsU3RvcmFnZSBwYXJhIGNhc28gbyB1c3XDoXJpbyBmZWNoZSBlIGFicmEgbyBuYXZlZ2Fkb3JcbiAgICAgKiBkZW50cm8gZG8gdGVtcG8gZGUgc2Vzc8OjbyBzZWphIHBvc3PDrXZlbCByZWN1cGVyYXIgbyB0b2tlbiBhdXRlbnRpY2Fkby5cbiAgICAgKlxuICAgICAqIE1hbnTDqW0gYSB2YXJpw6F2ZWwgYXV0aC5jdXJyZW50VXNlciBwYXJhIGZhY2lsaXRhciBvIGFjZXNzbyBhbyB1c3XDoXJpbyBsb2dhZG8gZW0gdG9kYSBhIGFwbGljYcOnw6NvXG4gICAgICpcbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSB1c2VyIFVzdcOhcmlvIGEgc2VyIGF0dWFsaXphZG8uIENhc28gc2VqYSBwYXNzYWRvIG51bGwgbGltcGFcbiAgICAgKiB0b2RhcyBhcyBpbmZvcm1hw6fDtWVzIGRvIHVzdcOhcmlvIGNvcnJlbnRlLlxuICAgICAqL1xuICAgIGZ1bmN0aW9uIHVwZGF0ZUN1cnJlbnRVc2VyKHVzZXIpIHtcbiAgICAgIHZhciBkZWZlcnJlZCA9ICRxLmRlZmVyKCk7XG5cbiAgICAgIGlmICh1c2VyKSB7XG4gICAgICAgIHVzZXIgPSBhbmd1bGFyLm1lcmdlKG5ldyBVc2Vyc1NlcnZpY2UoKSwgdXNlcik7XG5cbiAgICAgICAgdmFyIGpzb25Vc2VyID0gYW5ndWxhci50b0pzb24odXNlcik7XG5cbiAgICAgICAgbG9jYWxTdG9yYWdlLnNldEl0ZW0oJ3VzZXInLCBqc29uVXNlcik7XG4gICAgICAgIGF1dGguY3VycmVudFVzZXIgPSB1c2VyO1xuXG4gICAgICAgIGRlZmVycmVkLnJlc29sdmUodXNlcik7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbSgndXNlcicpO1xuICAgICAgICBhdXRoLmN1cnJlbnRVc2VyID0gbnVsbDtcbiAgICAgICAgYXV0aC5jbGVhclRva2VuKCk7XG5cbiAgICAgICAgZGVmZXJyZWQucmVqZWN0KCk7XG4gICAgICB9XG5cbiAgICAgIHJldHVybiBkZWZlcnJlZC5wcm9taXNlO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWxpemEgbyBsb2dpbiBkbyB1c3XDoXJpb1xuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IGNyZWRlbnRpYWxzIEVtYWlsIGUgU2VuaGEgZG8gdXN1w6FyaW9cbiAgICAgKiBAcmV0dXJucyB7cHJvbWlzZX0gVW1hIHByb21pc2UgY29tIG8gcmVzdWx0YWRvIGRvIGNoYW1hZGEgbm8gYmFja2VuZFxuICAgICAqL1xuICAgIGZ1bmN0aW9uIGxvZ2luKGNyZWRlbnRpYWxzKSB7XG4gICAgICB2YXIgZGVmZXJyZWQgPSAkcS5kZWZlcigpO1xuXG4gICAgICAkaHR0cC5wb3N0KEdsb2JhbC5hcGlQYXRoICsgJy9hdXRoZW50aWNhdGUnLCBjcmVkZW50aWFscykudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgYXV0aC5zZXRUb2tlbihyZXNwb25zZS5kYXRhLnRva2VuKTtcblxuICAgICAgICByZXR1cm4gJGh0dHAuZ2V0KEdsb2JhbC5hcGlQYXRoICsgJy9hdXRoZW50aWNhdGUvdXNlcicpO1xuICAgICAgfSkudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgYXV0aC51cGRhdGVDdXJyZW50VXNlcihyZXNwb25zZS5kYXRhLnVzZXIpO1xuXG4gICAgICAgIGRlZmVycmVkLnJlc29sdmUoKTtcbiAgICAgIH0sIGZ1bmN0aW9uIChlcnJvcikge1xuICAgICAgICBhdXRoLmxvZ291dCgpO1xuXG4gICAgICAgIGRlZmVycmVkLnJlamVjdChlcnJvcik7XG4gICAgICB9KTtcblxuICAgICAgcmV0dXJuIGRlZmVycmVkLnByb21pc2U7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogRGVzbG9nYSBvcyB1c3XDoXJpb3MuIENvbW8gbsOjbyB0ZW4gbmVuaHVtYSBpbmZvcm1hw6fDo28gbmEgc2Vzc8OjbyBkbyBzZXJ2aWRvclxuICAgICAqIGUgdW0gdG9rZW4gdW1hIHZleiBnZXJhZG8gbsOjbyBwb2RlLCBwb3IgcGFkcsOjbywgc2VyIGludmFsaWRhZG8gYW50ZXMgZG8gc2V1IHRlbXBvIGRlIGV4cGlyYcOnw6NvLFxuICAgICAqIHNvbWVudGUgYXBhZ2Ftb3Mgb3MgZGFkb3MgZG8gdXN1w6FyaW8gZSBvIHRva2VuIGRvIG5hdmVnYWRvciBwYXJhIGVmZXRpdmFyIG8gbG9nb3V0LlxuICAgICAqXG4gICAgICogQHJldHVybnMge3Byb21pc2V9IFVtYSBwcm9taXNlIGNvbSBvIHJlc3VsdGFkbyBkYSBvcGVyYcOnw6NvXG4gICAgICovXG4gICAgZnVuY3Rpb24gbG9nb3V0KCkge1xuICAgICAgdmFyIGRlZmVycmVkID0gJHEuZGVmZXIoKTtcblxuICAgICAgYXV0aC51cGRhdGVDdXJyZW50VXNlcihudWxsKTtcbiAgICAgIGRlZmVycmVkLnJlc29sdmUoKTtcblxuICAgICAgcmV0dXJuIGRlZmVycmVkLnByb21pc2U7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogRW52aWEgdW0gZW1haWwgcGFyYSByZWN1cGVyYcOnw6NvIGRlIHNlbmhhXG4gICAgICogQHBhcmFtIHtPYmplY3R9IHJlc2V0RGF0YSAtIE9iamV0byBjb250ZW5kbyBvIGVtYWlsXG4gICAgICogQHJldHVybiB7UHJvbWlzZX0gLSBSZXRvcm5hIHVtYSBwcm9taXNlIHBhcmEgc2VyIHJlc29sdmlkYVxuICAgICAqL1xuICAgIGZ1bmN0aW9uIHNlbmRFbWFpbFJlc2V0UGFzc3dvcmQocmVzZXREYXRhKSB7XG4gICAgICB2YXIgZGVmZXJyZWQgPSAkcS5kZWZlcigpO1xuXG4gICAgICAkaHR0cC5wb3N0KEdsb2JhbC5hcGlQYXRoICsgJy9wYXNzd29yZC9lbWFpbCcsIHJlc2V0RGF0YSkudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgZGVmZXJyZWQucmVzb2x2ZShyZXNwb25zZS5kYXRhKTtcbiAgICAgIH0sIGZ1bmN0aW9uIChlcnJvcikge1xuICAgICAgICBkZWZlcnJlZC5yZWplY3QoZXJyb3IpO1xuICAgICAgfSk7XG5cbiAgICAgIHJldHVybiBkZWZlcnJlZC5wcm9taXNlO1xuICAgIH1cblxuICAgIHJldHVybiBhdXRoO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29udHJvbGxlcignTG9naW5Db250cm9sbGVyJywgTG9naW5Db250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIExvZ2luQ29udHJvbGxlcigkc3RhdGUsIEF1dGgsIEdsb2JhbCwgUHJEaWFsb2cpIHtcbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0ubG9naW4gPSBsb2dpbjtcbiAgICB2bS5vcGVuRGlhbG9nUmVzZXRQYXNzID0gb3BlbkRpYWxvZ1Jlc2V0UGFzcztcbiAgICB2bS5vcGVuRGlhbG9nU2lnblVwID0gb3BlbkRpYWxvZ1NpZ25VcDtcblxuICAgIGFjdGl2YXRlKCk7XG5cbiAgICBmdW5jdGlvbiBhY3RpdmF0ZSgpIHtcbiAgICAgIHZtLmNyZWRlbnRpYWxzID0ge307XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gbG9naW4oKSB7XG4gICAgICB2YXIgY3JlZGVudGlhbHMgPSB7XG4gICAgICAgIGVtYWlsOiB2bS5jcmVkZW50aWFscy5lbWFpbCxcbiAgICAgICAgcGFzc3dvcmQ6IHZtLmNyZWRlbnRpYWxzLnBhc3N3b3JkXG4gICAgICB9O1xuXG4gICAgICBBdXRoLmxvZ2luKGNyZWRlbnRpYWxzKS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgJHN0YXRlLmdvKEdsb2JhbC5ob21lU3RhdGUpO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogRXhpYmUgbyBkaWFsb2cgcGFyYSByZWN1cGVyYcOnw6NvIGRlIHNlbmhhXG4gICAgICovXG4gICAgZnVuY3Rpb24gb3BlbkRpYWxvZ1Jlc2V0UGFzcygpIHtcbiAgICAgIHZhciBjb25maWcgPSB7XG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvYXV0aC9zZW5kLXJlc2V0LWRpYWxvZy5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ1Bhc3N3b3JkQ29udHJvbGxlciBhcyBwYXNzQ3RybCcsXG4gICAgICAgIGhhc0JhY2tkcm9wOiB0cnVlXG4gICAgICB9O1xuXG4gICAgICBQckRpYWxvZy5jdXN0b20oY29uZmlnKTtcbiAgICB9XG4gICAgLyoqXG4gICAgICogRXhpYmUgbyBkaWFsb2cgcGFyYSByZWN1cGVyYcOnw6NvIGRlIHNlbmhhXG4gICAgICovXG4gICAgZnVuY3Rpb24gb3BlbkRpYWxvZ1NpZ25VcCgpIHtcbiAgICAgIHZhciBjb25maWcgPSB7XG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvdXNlcnMvdXNlci1mb3JtLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnVXNlcnNDb250cm9sbGVyIGFzIHVzZXJzQ3RybCcsXG4gICAgICAgIGhhc0JhY2tkcm9wOiB0cnVlXG4gICAgICB9O1xuXG4gICAgICBQckRpYWxvZy5jdXN0b20oY29uZmlnKTtcbiAgICB9XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb250cm9sbGVyKCdQYXNzd29yZENvbnRyb2xsZXInLCBQYXNzd29yZENvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gUGFzc3dvcmRDb250cm9sbGVyKEdsb2JhbCwgJHN0YXRlUGFyYW1zLCAkaHR0cCwgJHRpbWVvdXQsICRzdGF0ZSwgLy8gTk9TT05BUlxuICBQclRvYXN0LCBQckRpYWxvZywgQXV0aCwgJHRyYW5zbGF0ZSkge1xuXG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIHZtLnNlbmRSZXNldCA9IHNlbmRSZXNldDtcbiAgICB2bS5jbG9zZURpYWxvZyA9IGNsb3NlRGlhbG9nO1xuICAgIHZtLmNsZWFuRm9ybSA9IGNsZWFuRm9ybTtcbiAgICB2bS5zZW5kRW1haWxSZXNldFBhc3N3b3JkID0gc2VuZEVtYWlsUmVzZXRQYXNzd29yZDtcblxuICAgIGFjdGl2YXRlKCk7XG5cbiAgICBmdW5jdGlvbiBhY3RpdmF0ZSgpIHtcbiAgICAgIHZtLnJlc2V0ID0geyBlbWFpbDogJycsIHRva2VuOiAkc3RhdGVQYXJhbXMudG9rZW4gfTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFsaXphIGEgYWx0ZXJhw6fDo28gZGEgc2VuaGEgZG8gdXN1w6FyaW8gZSBvIHJlZGlyZWNpb25hIHBhcmEgYSB0ZWxhIGRlIGxvZ2luXG4gICAgICovXG4gICAgZnVuY3Rpb24gc2VuZFJlc2V0KCkge1xuICAgICAgJGh0dHAucG9zdChHbG9iYWwuYXBpUGF0aCArICcvcGFzc3dvcmQvcmVzZXQnLCB2bS5yZXNldCkudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgIFByVG9hc3Quc3VjY2VzcygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLm9wZXJhdGlvblN1Y2Nlc3MnKSk7XG4gICAgICAgICR0aW1lb3V0KGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAkc3RhdGUuZ28oR2xvYmFsLmxvZ2luU3RhdGUpO1xuICAgICAgICB9LCAxNTAwKTtcbiAgICAgIH0sIGZ1bmN0aW9uIChlcnJvcikge1xuICAgICAgICBpZiAoZXJyb3Iuc3RhdHVzICE9PSA0MDAgJiYgZXJyb3Iuc3RhdHVzICE9PSA1MDApIHtcbiAgICAgICAgICB2YXIgbXNnID0gJyc7XG5cbiAgICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IGVycm9yLmRhdGEucGFzc3dvcmQubGVuZ3RoOyBpKyspIHtcbiAgICAgICAgICAgIG1zZyArPSBlcnJvci5kYXRhLnBhc3N3b3JkW2ldICsgJzxicj4nO1xuICAgICAgICAgIH1cbiAgICAgICAgICBQclRvYXN0LmVycm9yKG1zZy50b1VwcGVyQ2FzZSgpKTtcbiAgICAgICAgfVxuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogRW52aWEgdW0gZW1haWwgZGUgcmVjdXBlcmHDp8OjbyBkZSBzZW5oYSBjb20gbyB0b2tlbiBkbyB1c3XDoXJpb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIHNlbmRFbWFpbFJlc2V0UGFzc3dvcmQoKSB7XG5cbiAgICAgIGlmICh2bS5yZXNldC5lbWFpbCA9PT0gJycpIHtcbiAgICAgICAgUHJUb2FzdC5lcnJvcigkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnZhbGlkYXRlLmZpZWxkUmVxdWlyZWQnLCB7IGZpZWxkOiAnZW1haWwnIH0pKTtcbiAgICAgICAgcmV0dXJuO1xuICAgICAgfVxuXG4gICAgICBBdXRoLnNlbmRFbWFpbFJlc2V0UGFzc3dvcmQodm0ucmVzZXQpLnRoZW4oZnVuY3Rpb24gKGRhdGEpIHtcbiAgICAgICAgUHJUb2FzdC5zdWNjZXNzKGRhdGEubWVzc2FnZSk7XG5cbiAgICAgICAgdm0uY2xlYW5Gb3JtKCk7XG4gICAgICAgIHZtLmNsb3NlRGlhbG9nKCk7XG4gICAgICB9LCBmdW5jdGlvbiAoZXJyb3IpIHtcbiAgICAgICAgaWYgKGVycm9yLmRhdGEuZW1haWwgJiYgZXJyb3IuZGF0YS5lbWFpbC5sZW5ndGggPiAwKSB7XG4gICAgICAgICAgdmFyIG1zZyA9ICcnO1xuXG4gICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCBlcnJvci5kYXRhLmVtYWlsLmxlbmd0aDsgaSsrKSB7XG4gICAgICAgICAgICBtc2cgKz0gZXJyb3IuZGF0YS5lbWFpbFtpXSArICc8YnI+JztcbiAgICAgICAgICB9XG5cbiAgICAgICAgICBQclRvYXN0LmVycm9yKG1zZyk7XG4gICAgICAgIH1cbiAgICAgIH0pO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGNsb3NlRGlhbG9nKCkge1xuICAgICAgUHJEaWFsb2cuY2xvc2UoKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBjbGVhbkZvcm0oKSB7XG4gICAgICB2bS5yZXNldC5lbWFpbCA9ICcnO1xuICAgIH1cbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuLyplc2xpbnQgYW5ndWxhci9maWxlLW5hbWU6IDAqL1xuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5mYWN0b3J5KCdzZXJ2aWNlRmFjdG9yeScsIHNlcnZpY2VGYWN0b3J5KTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8qKlxuICAgKiBNYWlzIGluZm9ybWHDp8O1ZXM6XG4gICAqIGh0dHBzOi8vZ2l0aHViLmNvbS9zd2ltbGFuZS9hbmd1bGFyLW1vZGVsLWZhY3Rvcnkvd2lraS9BUElcbiAgICovXG4gIGZ1bmN0aW9uIHNlcnZpY2VGYWN0b3J5KCRtb2RlbEZhY3RvcnkpIHtcbiAgICByZXR1cm4gZnVuY3Rpb24gKHVybCwgb3B0aW9ucykge1xuICAgICAgdmFyIG1vZGVsO1xuICAgICAgdmFyIGRlZmF1bHRPcHRpb25zID0ge1xuICAgICAgICBhY3Rpb25zOiB7XG4gICAgICAgICAgLyoqXG4gICAgICAgICAgICogU2VydmnDp28gY29tdW0gcGFyYSByZWFsaXphciBidXNjYSBjb20gcGFnaW5hw6fDo29cbiAgICAgICAgICAgKiBPIG1lc21vIGVzcGVyYSBxdWUgc2VqYSByZXRvcm5hZG8gdW0gb2JqZXRvIGNvbSBpdGVtcyBlIHRvdGFsXG4gICAgICAgICAgICovXG4gICAgICAgICAgcGFnaW5hdGU6IHtcbiAgICAgICAgICAgIG1ldGhvZDogJ0dFVCcsXG4gICAgICAgICAgICBpc0FycmF5OiBmYWxzZSxcbiAgICAgICAgICAgIHdyYXA6IGZhbHNlLFxuICAgICAgICAgICAgYWZ0ZXJSZXF1ZXN0OiBmdW5jdGlvbiBhZnRlclJlcXVlc3QocmVzcG9uc2UpIHtcbiAgICAgICAgICAgICAgaWYgKHJlc3BvbnNlWydpdGVtcyddKSB7XG4gICAgICAgICAgICAgICAgcmVzcG9uc2VbJ2l0ZW1zJ10gPSBtb2RlbC5MaXN0KHJlc3BvbnNlWydpdGVtcyddKTtcbiAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgIHJldHVybiByZXNwb25zZTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgIH07XG5cbiAgICAgIG1vZGVsID0gJG1vZGVsRmFjdG9yeSh1cmwsIGFuZ3VsYXIubWVyZ2UoZGVmYXVsdE9wdGlvbnMsIG9wdGlvbnMpKTtcblxuICAgICAgcmV0dXJuIG1vZGVsO1xuICAgIH07XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIENSVURDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8qKlxuICAgKiBDb250cm9sYWRvciBCYXNlIHF1ZSBpbXBsZW1lbnRhIHRvZGFzIGFzIGZ1bsOnw7VlcyBwYWRyw7VlcyBkZSB1bSBDUlVEXG4gICAqXG4gICAqIEHDp8O1ZXMgaW1wbGVtZW50YWRhc1xuICAgKiBhY3RpdmF0ZSgpXG4gICAqIHNlYXJjaChwYWdlKVxuICAgKiBlZGl0KHJlc291cmNlKVxuICAgKiBzYXZlKClcbiAgICogcmVtb3ZlKHJlc291cmNlKVxuICAgKiBnb1RvKHZpZXdOYW1lKVxuICAgKiBjbGVhbkZvcm0oKVxuICAgKlxuICAgKiBHYXRpbGhvc1xuICAgKlxuICAgKiBvbkFjdGl2YXRlKClcbiAgICogYXBwbHlGaWx0ZXJzKGRlZmF1bHRRdWVyeUZpbHRlcnMpXG4gICAqIGJlZm9yZVNlYXJjaChwYWdlKSAvL3JldG9ybmFuZG8gZmFsc2UgY2FuY2VsYSBvIGZsdXhvXG4gICAqIGFmdGVyU2VhcmNoKHJlc3BvbnNlKVxuICAgKiBiZWZvcmVDbGVhbiAvL3JldG9ybmFuZG8gZmFsc2UgY2FuY2VsYSBvIGZsdXhvXG4gICAqIGFmdGVyQ2xlYW4oKVxuICAgKiBiZWZvcmVTYXZlKCkgLy9yZXRvcm5hbmRvIGZhbHNlIGNhbmNlbGEgbyBmbHV4b1xuICAgKiBhZnRlclNhdmUocmVzb3VyY2UpXG4gICAqIG9uU2F2ZUVycm9yKGVycm9yKVxuICAgKiBiZWZvcmVSZW1vdmUocmVzb3VyY2UpIC8vcmV0b3JuYW5kbyBmYWxzZSBjYW5jZWxhIG8gZmx1eG9cbiAgICogYWZ0ZXJSZW1vdmUocmVzb3VyY2UpXG4gICAqXG4gICAqIEBwYXJhbSB7YW55fSB2bSBpbnN0YW5jaWEgZG8gY29udHJvbGxlciBmaWxob1xuICAgKiBAcGFyYW0ge2FueX0gbW9kZWxTZXJ2aWNlIHNlcnZpw6dvIGRvIG1vZGVsIHF1ZSB2YWkgc2VyIHV0aWxpemFkb1xuICAgKiBAcGFyYW0ge2FueX0gb3B0aW9ucyBvcMOnw7VlcyBwYXJhIHNvYnJlZXNjcmV2ZXIgY29tcG9ydGFtZW50b3MgcGFkcsO1ZXNcbiAgICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIENSVURDb250cm9sbGVyKHZtLCBtb2RlbFNlcnZpY2UsIG9wdGlvbnMsIFByVG9hc3QsIFByUGFnaW5hdGlvbiwgLy8gTk9TT05BUlxuICBQckRpYWxvZywgJHRyYW5zbGF0ZSkge1xuXG4gICAgLy9GdW5jdGlvbnMgQmxvY2tcbiAgICB2bS5zZWFyY2ggPSBzZWFyY2g7XG4gICAgdm0ucGFnaW5hdGVTZWFyY2ggPSBwYWdpbmF0ZVNlYXJjaDtcbiAgICB2bS5ub3JtYWxTZWFyY2ggPSBub3JtYWxTZWFyY2g7XG4gICAgdm0uZWRpdCA9IGVkaXQ7XG4gICAgdm0uc2F2ZSA9IHNhdmU7XG4gICAgdm0ucmVtb3ZlID0gcmVtb3ZlO1xuICAgIHZtLmdvVG8gPSBnb1RvO1xuICAgIHZtLmNsZWFuRm9ybSA9IGNsZWFuRm9ybTtcblxuICAgIGFjdGl2YXRlKCk7XG5cbiAgICAvKipcbiAgICAgKiBQcmVwYXJhIG8gY29udHJvbGFkb3JcbiAgICAgKiBGYXogbyBtZXJnZSBkYXMgb3DDp8O1ZXNcbiAgICAgKiBJbmljaWFsaXphIG8gcmVjdXJzb1xuICAgICAqIEluaWNpYWxpemEgbyBvYmpldG8gcGFnaW5hZG9yIGUgcmVhbGl6YSBhIHBlc3F1aXNhXG4gICAgICovXG4gICAgZnVuY3Rpb24gYWN0aXZhdGUoKSB7XG4gICAgICB2bS5kZWZhdWx0T3B0aW9ucyA9IHtcbiAgICAgICAgcmVkaXJlY3RBZnRlclNhdmU6IHRydWUsXG4gICAgICAgIHNlYXJjaE9uSW5pdDogdHJ1ZSxcbiAgICAgICAgcGVyUGFnZTogOCxcbiAgICAgICAgc2tpcFBhZ2luYXRpb246IGZhbHNlXG4gICAgICB9O1xuXG4gICAgICBhbmd1bGFyLm1lcmdlKHZtLmRlZmF1bHRPcHRpb25zLCBvcHRpb25zKTtcblxuICAgICAgdm0udmlld0Zvcm0gPSBmYWxzZTtcbiAgICAgIHZtLnJlc291cmNlID0gbmV3IG1vZGVsU2VydmljZSgpO1xuXG4gICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLm9uQWN0aXZhdGUpKSB2bS5vbkFjdGl2YXRlKCk7XG5cbiAgICAgIHZtLnBhZ2luYXRvciA9IFByUGFnaW5hdGlvbi5nZXRJbnN0YW5jZSh2bS5zZWFyY2gsIHZtLmRlZmF1bHRPcHRpb25zLnBlclBhZ2UpO1xuXG4gICAgICBpZiAodm0uZGVmYXVsdE9wdGlvbnMuc2VhcmNoT25Jbml0KSB2bS5zZWFyY2goKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFsaXphIGEgcGVzcXVpc2FcbiAgICAgKiBWZXJpZmljYSBxdWFsIGRhcyBmdW7Dp8O1ZXMgZGUgcGVzcXVpc2EgZGV2ZSBzZXIgcmVhbGl6YWRhLlxuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IHBhZ2UgcMOhZ2luYSBxdWUgZGV2ZSBzZXIgY2FycmVnYWRhXG4gICAgICovXG4gICAgZnVuY3Rpb24gc2VhcmNoKHBhZ2UpIHtcbiAgICAgIHZtLmRlZmF1bHRPcHRpb25zLnNraXBQYWdpbmF0aW9uID8gbm9ybWFsU2VhcmNoKCkgOiBwYWdpbmF0ZVNlYXJjaChwYWdlKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFsaXphIGEgcGVzcXVpc2EgcGFnaW5hZGEgY29tIGJhc2Ugbm9zIGZpbHRyb3MgZGVmaW5pZG9zXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gcGFnZSBww6FnaW5hIHF1ZSBkZXZlIHNlciBjYXJyZWdhZGFcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBwYWdpbmF0ZVNlYXJjaChwYWdlKSB7XG4gICAgICB2bS5wYWdpbmF0b3IuY3VycmVudFBhZ2UgPSBhbmd1bGFyLmlzRGVmaW5lZChwYWdlKSA/IHBhZ2UgOiAxO1xuICAgICAgdm0uZGVmYXVsdFF1ZXJ5RmlsdGVycyA9IHsgcGFnZTogdm0ucGFnaW5hdG9yLmN1cnJlbnRQYWdlLCBwZXJQYWdlOiB2bS5wYWdpbmF0b3IucGVyUGFnZSB9O1xuXG4gICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmFwcGx5RmlsdGVycykpIHZtLmRlZmF1bHRRdWVyeUZpbHRlcnMgPSB2bS5hcHBseUZpbHRlcnModm0uZGVmYXVsdFF1ZXJ5RmlsdGVycyk7XG4gICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmJlZm9yZVNlYXJjaCkgJiYgdm0uYmVmb3JlU2VhcmNoKHBhZ2UpID09PSBmYWxzZSkgcmV0dXJuIGZhbHNlO1xuXG4gICAgICBtb2RlbFNlcnZpY2UucGFnaW5hdGUodm0uZGVmYXVsdFF1ZXJ5RmlsdGVycykudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgdm0ucGFnaW5hdG9yLmNhbGNOdW1iZXJPZlBhZ2VzKHJlc3BvbnNlLnRvdGFsKTtcbiAgICAgICAgdm0ucmVzb3VyY2VzID0gcmVzcG9uc2UuaXRlbXM7XG5cbiAgICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5hZnRlclNlYXJjaCkpIHZtLmFmdGVyU2VhcmNoKHJlc3BvbnNlKTtcbiAgICAgIH0sIGZ1bmN0aW9uIChyZXNwb25zZURhdGEpIHtcbiAgICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5vblNlYXJjaEVycm9yKSkgdm0ub25TZWFyY2hFcnJvcihyZXNwb25zZURhdGEpO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhbGl6YSBhIHBlc3F1aXNhIGNvbSBiYXNlIG5vcyBmaWx0cm9zIGRlZmluaWRvc1xuICAgICAqXG4gICAgICovXG4gICAgZnVuY3Rpb24gbm9ybWFsU2VhcmNoKCkge1xuICAgICAgdm0uZGVmYXVsdFF1ZXJ5RmlsdGVycyA9IHt9O1xuXG4gICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmFwcGx5RmlsdGVycykpIHZtLmRlZmF1bHRRdWVyeUZpbHRlcnMgPSB2bS5hcHBseUZpbHRlcnModm0uZGVmYXVsdFF1ZXJ5RmlsdGVycyk7XG4gICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmJlZm9yZVNlYXJjaCkgJiYgdm0uYmVmb3JlU2VhcmNoKCkgPT09IGZhbHNlKSByZXR1cm4gZmFsc2U7XG5cbiAgICAgIG1vZGVsU2VydmljZS5xdWVyeSh2bS5kZWZhdWx0UXVlcnlGaWx0ZXJzKS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICB2bS5yZXNvdXJjZXMgPSByZXNwb25zZTtcblxuICAgICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmFmdGVyU2VhcmNoKSkgdm0uYWZ0ZXJTZWFyY2gocmVzcG9uc2UpO1xuICAgICAgfSwgZnVuY3Rpb24gKHJlc3BvbnNlRGF0YSkge1xuICAgICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLm9uU2VhcmNoRXJyb3IpKSB2bS5vblNlYXJjaEVycm9yKHJlc3BvbnNlRGF0YSk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBMaW1wYSBvIGZvcm11bMOhcmlvXG4gICAgICovXG4gICAgZnVuY3Rpb24gY2xlYW5Gb3JtKGZvcm0pIHtcbiAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYmVmb3JlQ2xlYW4pICYmIHZtLmJlZm9yZUNsZWFuKCkgPT09IGZhbHNlKSByZXR1cm4gZmFsc2U7XG5cbiAgICAgIHZtLnJlc291cmNlID0gbmV3IG1vZGVsU2VydmljZSgpO1xuXG4gICAgICBpZiAoYW5ndWxhci5pc0RlZmluZWQoZm9ybSkpIHtcbiAgICAgICAgZm9ybS4kc2V0UHJpc3RpbmUoKTtcbiAgICAgICAgZm9ybS4kc2V0VW50b3VjaGVkKCk7XG4gICAgICB9XG5cbiAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYWZ0ZXJDbGVhbikpIHZtLmFmdGVyQ2xlYW4oKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDYXJyZWdhIG5vIGZvcm11bMOhcmlvIG8gcmVjdXJzbyBzZWxlY2lvbmFkbyBwYXJhIGVkacOnw6NvXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gcmVzb3VyY2UgcmVjdXJzbyBzZWxlY2lvbmFkb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGVkaXQocmVzb3VyY2UpIHtcbiAgICAgIHZtLmdvVG8oJ2Zvcm0nKTtcbiAgICAgIHZtLnJlc291cmNlID0gbmV3IGFuZ3VsYXIuY29weShyZXNvdXJjZSk7XG5cbiAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYWZ0ZXJFZGl0KSkgdm0uYWZ0ZXJFZGl0KCk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogU2FsdmEgb3UgYXR1YWxpemEgbyByZWN1cnNvIGNvcnJlbnRlIG5vIGZvcm11bMOhcmlvXG4gICAgICogTm8gY29tcG9ydGFtZW50byBwYWRyw6NvIHJlZGlyZWNpb25hIG8gdXN1w6FyaW8gcGFyYSB2aWV3IGRlIGxpc3RhZ2VtXG4gICAgICogZGVwb2lzIGRhIGV4ZWN1w6fDo29cbiAgICAgKlxuICAgICAqIEByZXR1cm5zXG4gICAgICovXG4gICAgZnVuY3Rpb24gc2F2ZShmb3JtKSB7XG4gICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmJlZm9yZVNhdmUpICYmIHZtLmJlZm9yZVNhdmUoKSA9PT0gZmFsc2UpIHJldHVybiBmYWxzZTtcblxuICAgICAgdm0ucmVzb3VyY2UuJHNhdmUoKS50aGVuKGZ1bmN0aW9uIChyZXNvdXJjZSkge1xuICAgICAgICB2bS5yZXNvdXJjZSA9IHJlc291cmNlO1xuXG4gICAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYWZ0ZXJTYXZlKSkgdm0uYWZ0ZXJTYXZlKHJlc291cmNlKTtcblxuICAgICAgICBpZiAodm0uZGVmYXVsdE9wdGlvbnMucmVkaXJlY3RBZnRlclNhdmUpIHtcbiAgICAgICAgICB2bS5jbGVhbkZvcm0oZm9ybSk7XG4gICAgICAgICAgdm0uc2VhcmNoKHZtLnBhZ2luYXRvci5jdXJyZW50UGFnZSk7XG4gICAgICAgICAgdm0uZ29UbygnbGlzdCcpO1xuICAgICAgICB9XG5cbiAgICAgICAgUHJUb2FzdC5zdWNjZXNzKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMuc2F2ZVN1Y2Nlc3MnKSk7XG4gICAgICB9LCBmdW5jdGlvbiAocmVzcG9uc2VEYXRhKSB7XG4gICAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0ub25TYXZlRXJyb3IpKSB2bS5vblNhdmVFcnJvcihyZXNwb25zZURhdGEpO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVtb3ZlIG8gcmVjdXJzbyBpbmZvcm1hZG8uXG4gICAgICogQW50ZXMgZXhpYmUgdW0gZGlhbG9nbyBkZSBjb25maXJtYcOnw6NvXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gcmVzb3VyY2UgcmVjdXJzbyBlc2NvbGhpZG9cbiAgICAgKi9cbiAgICBmdW5jdGlvbiByZW1vdmUocmVzb3VyY2UpIHtcbiAgICAgIHZhciBjb25maWcgPSB7XG4gICAgICAgIHRpdGxlOiAkdHJhbnNsYXRlLmluc3RhbnQoJ2RpYWxvZy5jb25maXJtVGl0bGUnKSxcbiAgICAgICAgZGVzY3JpcHRpb246ICR0cmFuc2xhdGUuaW5zdGFudCgnZGlhbG9nLmNvbmZpcm1EZXNjcmlwdGlvbicpXG4gICAgICB9O1xuXG4gICAgICBQckRpYWxvZy5jb25maXJtKGNvbmZpZykudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYmVmb3JlUmVtb3ZlKSAmJiB2bS5iZWZvcmVSZW1vdmUocmVzb3VyY2UpID09PSBmYWxzZSkgcmV0dXJuIGZhbHNlO1xuXG4gICAgICAgIHJlc291cmNlLiRkZXN0cm95KCkudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5hZnRlclJlbW92ZSkpIHZtLmFmdGVyUmVtb3ZlKHJlc291cmNlKTtcblxuICAgICAgICAgIHZtLnNlYXJjaCgpO1xuICAgICAgICAgIFByVG9hc3QuaW5mbygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnJlbW92ZVN1Y2Nlc3MnKSk7XG4gICAgICAgIH0pO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQWx0ZXJuYSBlbnRyZSBhIHZpZXcgZG8gZm9ybXVsw6FyaW8gZSBsaXN0YWdlbVxuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IHZpZXdOYW1lIG5vbWUgZGEgdmlld1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGdvVG8odmlld05hbWUpIHtcbiAgICAgIHZtLnZpZXdGb3JtID0gZmFsc2U7XG4gICAgICB2bS5vblZpZXcgPSBmYWxzZTtcbiAgICAgIGlmICh2aWV3TmFtZSA9PT0gJ2Zvcm0nKSB7XG4gICAgICAgIHZtLmNsZWFuRm9ybSgpO1xuICAgICAgICB2bS52aWV3Rm9ybSA9IHRydWU7XG4gICAgICB9XG4gICAgfVxuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmlsdGVyKCdlbGFwc2VkJywgZnVuY3Rpb24gKCkge1xuICAgIHJldHVybiBmdW5jdGlvbiAoZGF0ZSkge1xuICAgICAgaWYgKCFkYXRlKSByZXR1cm47XG4gICAgICB2YXIgdGltZSA9IERhdGUucGFyc2UoZGF0ZSksXG4gICAgICAgICAgdGltZU5vdyA9IG5ldyBEYXRlKCkuZ2V0VGltZSgpLFxuICAgICAgICAgIGRpZmZlcmVuY2UgPSB0aW1lTm93IC0gdGltZSxcbiAgICAgICAgICBzZWNvbmRzID0gTWF0aC5mbG9vcihkaWZmZXJlbmNlIC8gMTAwMCksXG4gICAgICAgICAgbWludXRlcyA9IE1hdGguZmxvb3Ioc2Vjb25kcyAvIDYwKSxcbiAgICAgICAgICBob3VycyA9IE1hdGguZmxvb3IobWludXRlcyAvIDYwKSxcbiAgICAgICAgICBkYXlzID0gTWF0aC5mbG9vcihob3VycyAvIDI0KSxcbiAgICAgICAgICBtb250aHMgPSBNYXRoLmZsb29yKGRheXMgLyAzMCk7XG5cbiAgICAgIGlmIChtb250aHMgPiAxKSB7XG4gICAgICAgIHJldHVybiBtb250aHMgKyAnIG1lc2VzIGF0csOhcyc7XG4gICAgICB9IGVsc2UgaWYgKG1vbnRocyA9PT0gMSkge1xuICAgICAgICByZXR1cm4gJzEgbcOqcyBhdHLDoXMnO1xuICAgICAgfSBlbHNlIGlmIChkYXlzID4gMSkge1xuICAgICAgICByZXR1cm4gZGF5cyArICcgZGlhcyBhdHLDoXMnO1xuICAgICAgfSBlbHNlIGlmIChkYXlzID09PSAxKSB7XG4gICAgICAgIHJldHVybiAnMSBkaWEgYXRyw6FzJztcbiAgICAgIH0gZWxzZSBpZiAoaG91cnMgPiAxKSB7XG4gICAgICAgIHJldHVybiBob3VycyArICcgaG9yYXMgYXRyw6FzJztcbiAgICAgIH0gZWxzZSBpZiAoaG91cnMgPT09IDEpIHtcbiAgICAgICAgcmV0dXJuICd1bWEgaG9yYSBhdHLDoXMnO1xuICAgICAgfSBlbHNlIGlmIChtaW51dGVzID4gMSkge1xuICAgICAgICByZXR1cm4gbWludXRlcyArICcgbWludXRvcyBhdHLDoXMnO1xuICAgICAgfSBlbHNlIGlmIChtaW51dGVzID09PSAxKSB7XG4gICAgICAgIHJldHVybiAndW0gbWludXRvIGF0csOhcyc7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICByZXR1cm4gJ2jDoSBwb3Vjb3Mgc2VndW5kb3MnO1xuICAgICAgfVxuICAgIH07XG4gIH0pLmNvbnRyb2xsZXIoJ0Rhc2hib2FyZENvbnRyb2xsZXInLCBEYXNoYm9hcmRDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIERhc2hib2FyZENvbnRyb2xsZXIoJGNvbnRyb2xsZXIsICRzdGF0ZSwgJG1kRGlhbG9nLCAkdHJhbnNsYXRlLCBEYXNoYm9hcmRzU2VydmljZSwgUHJvamVjdHNTZXJ2aWNlLCBtb21lbnQsIFByVG9hc3QsIEF1dGgsIEdsb2JhbCkge1xuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICAvL0F0dHJpYnV0ZXMgQmxvY2tcblxuICAgIC8vRnVuY3Rpb25zIEJsb2NrXG4gICAgdm0ub25BY3RpdmF0ZSA9IG9uQWN0aXZhdGU7XG4gICAgdm0uYXBwbHlGaWx0ZXJzID0gYXBwbHlGaWx0ZXJzO1xuICAgIHZtLmZpeERhdGUgPSBmaXhEYXRlO1xuXG4gICAgZnVuY3Rpb24gb25BY3RpdmF0ZSgpIHtcbiAgICAgIHZhciBwcm9qZWN0ID0gbG9jYWxTdG9yYWdlLmdldEl0ZW0oJ3Byb2plY3QnKTtcblxuICAgICAgdm0uaW1hZ2VQYXRoID0gR2xvYmFsLmltYWdlUGF0aCArICcvbm9fYXZhdGFyLmdpZic7XG4gICAgICB2bS5jdXJyZW50VXNlciA9IEF1dGguY3VycmVudFVzZXI7XG4gICAgICBQcm9qZWN0c1NlcnZpY2UucXVlcnkoeyBwcm9qZWN0X2lkOiBwcm9qZWN0IH0pLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgIHZtLmFjdHVhbFByb2plY3QgPSByZXNwb25zZVswXTtcbiAgICAgIH0pO1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0geyBwcm9qZWN0X2lkOiBwcm9qZWN0IH07XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gYXBwbHlGaWx0ZXJzKGRlZmF1bHRRdWVyeUZpbHRlcnMpIHtcbiAgICAgIHJldHVybiBhbmd1bGFyLmV4dGVuZChkZWZhdWx0UXVlcnlGaWx0ZXJzLCB2bS5xdWVyeUZpbHRlcnMpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGZpeERhdGUoZGF0ZVN0cmluZykge1xuICAgICAgcmV0dXJuIG1vbWVudChkYXRlU3RyaW5nKTtcbiAgICB9XG5cbiAgICB2bS5nb1RvUHJvamVjdCA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICRzdGF0ZS5nbygnYXBwLnByb2plY3RzJywgeyBvYmo6ICdlZGl0JywgcmVzb3VyY2U6IHZtLmFjdHVhbFByb2plY3QgfSk7XG4gICAgfTtcblxuICAgIHZtLnRvdGFsQ29zdCA9IGZ1bmN0aW9uICgpIHtcbiAgICAgIHZhciBlc3RpbWF0ZWRfY29zdCA9IDA7XG5cbiAgICAgIHZtLmFjdHVhbFByb2plY3QudGFza3MuZm9yRWFjaChmdW5jdGlvbiAodGFzaykge1xuICAgICAgICBlc3RpbWF0ZWRfY29zdCArPSBwYXJzZUZsb2F0KHZtLmFjdHVhbFByb2plY3QuaG91cl92YWx1ZV9maW5hbCkgKiB0YXNrLmVzdGltYXRlZF90aW1lO1xuICAgICAgfSk7XG4gICAgICByZXR1cm4gZXN0aW1hdGVkX2Nvc3QudG9Mb2NhbGVTdHJpbmcoJ1B0LWJyJywgeyBtaW5pbXVtRnJhY3Rpb25EaWdpdHM6IDIgfSk7XG4gICAgfTtcblxuICAgIHZtLmZpbmFsaXplUHJvamVjdCA9IGZ1bmN0aW9uICgpIHtcbiAgICAgIHZhciBjb25maXJtID0gJG1kRGlhbG9nLmNvbmZpcm0oKS50aXRsZSgnRmluYWxpemFyIFByb2pldG8nKS50ZXh0Q29udGVudCgnVGVtIGNlcnRlemEgcXVlIGRlc2VqYSBmaW5hbGl6YXIgbyBwcm9qZXRvICcgKyB2bS5hY3R1YWxQcm9qZWN0Lm5hbWUgKyAnPycpLm9rKCdTaW0nKS5jYW5jZWwoJ07Do28nKTtcblxuICAgICAgJG1kRGlhbG9nLnNob3coY29uZmlybSkudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgIFByb2plY3RzU2VydmljZS5maW5hbGl6ZSh7IHByb2plY3RfaWQ6IHZtLmFjdHVhbFByb2plY3QuaWQgfSkudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgUHJUb2FzdC5zdWNjZXNzKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMucHJvamVjdEVuZGVkU3VjY2VzcycpKTtcbiAgICAgICAgICBvbkFjdGl2YXRlKCk7XG4gICAgICAgICAgdm0uc2VhcmNoKCk7XG4gICAgICAgIH0sIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICBQclRvYXN0LkVycm9yKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMucHJvamVjdEVuZGVkRXJyb3InKSk7XG4gICAgICAgIH0pO1xuICAgICAgfSk7XG4gICAgfTtcblxuICAgIC8vIGluc3RhbnRpYXRlIGJhc2UgY29udHJvbGxlclxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHsgdm06IHZtLCBtb2RlbFNlcnZpY2U6IERhc2hib2FyZHNTZXJ2aWNlLCBvcHRpb25zOiB7fSB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25maWcocm91dGVzKTtcblxuICAvKipcbiAgICogQXJxdWl2byBkZSBjb25maWd1cmHDp8OjbyBjb20gYXMgcm90YXMgZXNwZWPDrWZpY2FzIGRvIHJlY3Vyc28gcHJvamVjdFxuICAgKlxuICAgKiBAcGFyYW0ge2FueX0gJHN0YXRlUHJvdmlkZXJcbiAgICogQHBhcmFtIHthbnl9IEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdhcHAuZGFzaGJvYXJkJywge1xuICAgICAgdXJsOiAnL2Rhc2hib2FyZHMnLFxuICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9kYXNoYm9hcmQvZGFzaGJvYXJkLmh0bWwnLFxuICAgICAgY29udHJvbGxlcjogJ0Rhc2hib2FyZENvbnRyb2xsZXIgYXMgZGFzaGJvYXJkQ3RybCcsXG4gICAgICBkYXRhOiB7IG5lZWRBdXRoZW50aWNhdGlvbjogdHJ1ZSB9LFxuICAgICAgb2JqOiB7IHJlc291cmNlOiBudWxsIH1cbiAgICB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5mYWN0b3J5KCdEYXNoYm9hcmRzU2VydmljZScsIERhc2hib2FyZHNTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIERhc2hib2FyZHNTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCdkYXNoYm9hcmRzJywge1xuICAgICAgYWN0aW9uczoge30sXG4gICAgICBpbnN0YW5jZToge31cbiAgICB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25maWcocm91dGVzKTtcblxuICAvKipcbiAgICogQXJxdWl2byBkZSBjb25maWd1cmHDp8OjbyBjb20gYXMgcm90YXMgZXNwZWPDrWZpY2FzIGRvIHJlY3Vyc28gdXNlclxuICAgKlxuICAgKiBAcGFyYW0ge2FueX0gJHN0YXRlUHJvdmlkZXJcbiAgICogQHBhcmFtIHthbnl9IEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdhcHAuZGluYW1pYy1xdWVyeScsIHtcbiAgICAgIHVybDogJy9jb25zdWx0YXMtZGluYW1pY2FzJyxcbiAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvZGluYW1pYy1xdWVyeXMvZGluYW1pYy1xdWVyeXMuaHRtbCcsXG4gICAgICBjb250cm9sbGVyOiAnRGluYW1pY1F1ZXJ5c0NvbnRyb2xsZXIgYXMgZGluYW1pY1F1ZXJ5Q3RybCcsXG4gICAgICBkYXRhOiB7IG5lZWRBdXRoZW50aWNhdGlvbjogdHJ1ZSwgbmVlZFByb2ZpbGU6IFsnYWRtaW4nXSB9XG4gICAgfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmFjdG9yeSgnRGluYW1pY1F1ZXJ5U2VydmljZScsIERpbmFtaWNRdWVyeVNlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gRGluYW1pY1F1ZXJ5U2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHJldHVybiBzZXJ2aWNlRmFjdG9yeSgnZGluYW1pY1F1ZXJ5Jywge1xuICAgICAgLyoqXG4gICAgICAgKiBhw6fDo28gYWRpY2lvbmFkYSBwYXJhIHBlZ2FyIHVtYSBsaXN0YSBkZSBtb2RlbHMgZXhpc3RlbnRlcyBubyBzZXJ2aWRvclxuICAgICAgICovXG4gICAgICBhY3Rpb25zOiB7XG4gICAgICAgIGdldE1vZGVsczoge1xuICAgICAgICAgIG1ldGhvZDogJ0dFVCcsXG4gICAgICAgICAgdXJsOiAnbW9kZWxzJ1xuICAgICAgICB9XG4gICAgICB9LFxuICAgICAgaW5zdGFuY2U6IHt9XG4gICAgfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb250cm9sbGVyKCdEaW5hbWljUXVlcnlzQ29udHJvbGxlcicsIERpbmFtaWNRdWVyeXNDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIERpbmFtaWNRdWVyeXNDb250cm9sbGVyKCRjb250cm9sbGVyLCBEaW5hbWljUXVlcnlTZXJ2aWNlLCBsb2Rhc2gsIFByVG9hc3QsIC8vIE5PU09OQVJcbiAgJHRyYW5zbGF0ZSkge1xuXG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIC8vYWN0aW9uc1xuICAgIHZtLm9uQWN0aXZhdGUgPSBvbkFjdGl2YXRlO1xuICAgIHZtLmFwcGx5RmlsdGVycyA9IGFwcGx5RmlsdGVycztcbiAgICB2bS5sb2FkQXR0cmlidXRlcyA9IGxvYWRBdHRyaWJ1dGVzO1xuICAgIHZtLmxvYWRPcGVyYXRvcnMgPSBsb2FkT3BlcmF0b3JzO1xuICAgIHZtLmFkZEZpbHRlciA9IGFkZEZpbHRlcjtcbiAgICB2bS5hZnRlclNlYXJjaCA9IGFmdGVyU2VhcmNoO1xuICAgIHZtLnJ1bkZpbHRlciA9IHJ1bkZpbHRlcjtcbiAgICB2bS5lZGl0RmlsdGVyID0gZWRpdEZpbHRlcjtcbiAgICB2bS5sb2FkTW9kZWxzID0gbG9hZE1vZGVscztcbiAgICB2bS5yZW1vdmVGaWx0ZXIgPSByZW1vdmVGaWx0ZXI7XG4gICAgdm0uY2xlYXIgPSBjbGVhcjtcbiAgICB2bS5yZXN0YXJ0ID0gcmVzdGFydDtcblxuICAgIC8vaGVyZGEgbyBjb21wb3J0YW1lbnRvIGJhc2UgZG8gQ1JVRFxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHsgdm06IHZtLCBtb2RlbFNlcnZpY2U6IERpbmFtaWNRdWVyeVNlcnZpY2UsIG9wdGlvbnM6IHtcbiAgICAgICAgc2VhcmNoT25Jbml0OiBmYWxzZVxuICAgICAgfSB9KTtcblxuICAgIGZ1bmN0aW9uIG9uQWN0aXZhdGUoKSB7XG4gICAgICB2bS5yZXN0YXJ0KCk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUHJlcGFyYSBlIGFwbGljYSBvcyBmaWx0cm8gcXVlIHbDo28gc2VyIGVudmlhZG9zIHBhcmEgbyBzZXJ2acOnb1xuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IGRlZmF1bHRRdWVyeUZpbHRlcnNcbiAgICAgKiBAcmV0dXJuc1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGFwcGx5RmlsdGVycyhkZWZhdWx0UXVlcnlGaWx0ZXJzKSB7XG4gICAgICB2YXIgd2hlcmUgPSB7fTtcblxuICAgICAgLyoqXG4gICAgICAgKiBvIHNlcnZpw6dvIGVzcGVyYSB1bSBvYmpldG8gY29tOlxuICAgICAgICogIG8gbm9tZSBkZSB1bSBtb2RlbFxuICAgICAgICogIHVtYSBsaXN0YSBkZSBmaWx0cm9zXG4gICAgICAgKi9cbiAgICAgIGlmICh2bS5hZGRlZEZpbHRlcnMubGVuZ3RoID4gMCkge1xuICAgICAgICB2YXIgYWRkZWRGaWx0ZXJzID0gYW5ndWxhci5jb3B5KHZtLmFkZGVkRmlsdGVycyk7XG5cbiAgICAgICAgd2hlcmUubW9kZWwgPSB2bS5hZGRlZEZpbHRlcnNbMF0ubW9kZWwubmFtZTtcblxuICAgICAgICBmb3IgKHZhciBpbmRleCA9IDA7IGluZGV4IDwgYWRkZWRGaWx0ZXJzLmxlbmd0aDsgaW5kZXgrKykge1xuICAgICAgICAgIHZhciBmaWx0ZXIgPSBhZGRlZEZpbHRlcnNbaW5kZXhdO1xuXG4gICAgICAgICAgZmlsdGVyLm1vZGVsID0gbnVsbDtcbiAgICAgICAgICBmaWx0ZXIuYXR0cmlidXRlID0gZmlsdGVyLmF0dHJpYnV0ZS5uYW1lO1xuICAgICAgICAgIGZpbHRlci5vcGVyYXRvciA9IGZpbHRlci5vcGVyYXRvci52YWx1ZTtcbiAgICAgICAgfVxuXG4gICAgICAgIHdoZXJlLmZpbHRlcnMgPSBhbmd1bGFyLnRvSnNvbihhZGRlZEZpbHRlcnMpO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgd2hlcmUubW9kZWwgPSB2bS5xdWVyeUZpbHRlcnMubW9kZWwubmFtZTtcbiAgICAgIH1cblxuICAgICAgcmV0dXJuIGFuZ3VsYXIuZXh0ZW5kKGRlZmF1bHRRdWVyeUZpbHRlcnMsIHdoZXJlKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDYXJyZWdhIHRvZG9zIG9zIG1vZGVscyBjcmlhZG9zIG5vIHNlcnZpZG9yIGNvbSBzZXVzIGF0cmlidXRvc1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGxvYWRNb2RlbHMoKSB7XG4gICAgICAvL1BlZ2EgdG9kb3Mgb3MgbW9kZWxzIGRvIHNlcnZlciBlIG1vbnRhIHVtYSBsaXN0YSBwcm8gQ29tYm9Cb3hcbiAgICAgIERpbmFtaWNRdWVyeVNlcnZpY2UuZ2V0TW9kZWxzKCkudGhlbihmdW5jdGlvbiAoZGF0YSkge1xuICAgICAgICB2bS5tb2RlbHMgPSBkYXRhO1xuICAgICAgICB2bS5xdWVyeUZpbHRlcnMubW9kZWwgPSB2bS5tb2RlbHNbMF07XG4gICAgICAgIHZtLmxvYWRBdHRyaWJ1dGVzKCk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDYXJyZWdhIG9zIGF0dHJpYnV0b3MgZG8gbW9kZWwgZXNjb2xoaWRvXG4gICAgICovXG4gICAgZnVuY3Rpb24gbG9hZEF0dHJpYnV0ZXMoKSB7XG4gICAgICB2bS5hdHRyaWJ1dGVzID0gdm0ucXVlcnlGaWx0ZXJzLm1vZGVsLmF0dHJpYnV0ZXM7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMuYXR0cmlidXRlID0gdm0uYXR0cmlidXRlc1swXTtcblxuICAgICAgdm0ubG9hZE9wZXJhdG9ycygpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENhcnJlZ2Egb3Mgb3BlcmFkb3JlcyBlc3BlY2lmaWNvcyBwYXJhIG8gdGlwbyBkbyBhdHJpYnV0b1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGxvYWRPcGVyYXRvcnMoKSB7XG4gICAgICB2YXIgb3BlcmF0b3JzID0gW3sgdmFsdWU6ICc9JywgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudCgndmlld3MuZmllbGRzLnF1ZXJ5RGluYW1pYy5vcGVyYXRvcnMuZXF1YWxzJykgfSwgeyB2YWx1ZTogJzw+JywgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudCgndmlld3MuZmllbGRzLnF1ZXJ5RGluYW1pYy5vcGVyYXRvcnMuZGlmZXJlbnQnKSB9XTtcblxuICAgICAgaWYgKHZtLnF1ZXJ5RmlsdGVycy5hdHRyaWJ1dGUudHlwZS5pbmRleE9mKCd2YXJ5aW5nJykgIT09IC0xKSB7XG4gICAgICAgIG9wZXJhdG9ycy5wdXNoKHsgdmFsdWU6ICdoYXMnLFxuICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLmNvbnRlaW5zJykgfSk7XG4gICAgICAgIG9wZXJhdG9ycy5wdXNoKHsgdmFsdWU6ICdzdGFydFdpdGgnLFxuICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLnN0YXJ0V2l0aCcpIH0pO1xuICAgICAgICBvcGVyYXRvcnMucHVzaCh7IHZhbHVlOiAnZW5kV2l0aCcsXG4gICAgICAgICAgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudCgndmlld3MuZmllbGRzLnF1ZXJ5RGluYW1pYy5vcGVyYXRvcnMuZmluaXNoV2l0aCcpIH0pO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgb3BlcmF0b3JzLnB1c2goeyB2YWx1ZTogJz4nLFxuICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLmJpZ2dlclRoYW4nKSB9KTtcbiAgICAgICAgb3BlcmF0b3JzLnB1c2goeyB2YWx1ZTogJz49JyxcbiAgICAgICAgICBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KCd2aWV3cy5maWVsZHMucXVlcnlEaW5hbWljLm9wZXJhdG9ycy5lcXVhbHNPckJpZ2dlclRoYW4nKSB9KTtcbiAgICAgICAgb3BlcmF0b3JzLnB1c2goeyB2YWx1ZTogJzwnLFxuICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLmxlc3NUaGFuJykgfSk7XG4gICAgICAgIG9wZXJhdG9ycy5wdXNoKHsgdmFsdWU6ICc8PScsXG4gICAgICAgICAgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudCgndmlld3MuZmllbGRzLnF1ZXJ5RGluYW1pYy5vcGVyYXRvcnMuZXF1YWxzT3JMZXNzVGhhbicpIH0pO1xuICAgICAgfVxuXG4gICAgICB2bS5vcGVyYXRvcnMgPSBvcGVyYXRvcnM7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMub3BlcmF0b3IgPSB2bS5vcGVyYXRvcnNbMF07XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQWRpY2lvbmEvZWRpdGEgdW0gZmlsdHJvXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gZm9ybSBlbGVtZW50byBodG1sIGRvIGZvcm11bMOhcmlvIHBhcmEgdmFsaWRhw6fDtWVzXG4gICAgICovXG4gICAgZnVuY3Rpb24gYWRkRmlsdGVyKGZvcm0pIHtcbiAgICAgIGlmIChhbmd1bGFyLmlzVW5kZWZpbmVkKHZtLnF1ZXJ5RmlsdGVycy52YWx1ZSkgfHwgdm0ucXVlcnlGaWx0ZXJzLnZhbHVlID09PSAnJykge1xuICAgICAgICBQclRvYXN0LmVycm9yKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMudmFsaWRhdGUuZmllbGRSZXF1aXJlZCcsIHsgZmllbGQ6ICd2YWxvcicgfSkpO1xuICAgICAgICByZXR1cm47XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBpZiAodm0uaW5kZXggPCAwKSB7XG4gICAgICAgICAgdm0uYWRkZWRGaWx0ZXJzLnB1c2goYW5ndWxhci5jb3B5KHZtLnF1ZXJ5RmlsdGVycykpO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIHZtLmFkZGVkRmlsdGVyc1t2bS5pbmRleF0gPSBhbmd1bGFyLmNvcHkodm0ucXVlcnlGaWx0ZXJzKTtcbiAgICAgICAgICB2bS5pbmRleCA9IC0xO1xuICAgICAgICB9XG5cbiAgICAgICAgLy9yZWluaWNpYSBvIGZvcm11bMOhcmlvIGUgYXMgdmFsaWRhw6fDtWVzIGV4aXN0ZW50ZXNcbiAgICAgICAgdm0ucXVlcnlGaWx0ZXJzID0ge307XG4gICAgICAgIGZvcm0uJHNldFByaXN0aW5lKCk7XG4gICAgICAgIGZvcm0uJHNldFVudG91Y2hlZCgpO1xuICAgICAgfVxuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWxpemEgYSBwZXNxdWlzYSB0ZW5kbyBvcyBmaWx0cm9zIGNvbW8gcGFyw6JtZXRyb3NcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBydW5GaWx0ZXIoKSB7XG4gICAgICB2bS5zZWFyY2godm0ucGFnaW5hdG9yLmN1cnJlbnRQYWdlKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBHYXRpbGhvIGFjaW9uYWRvIGRlcG9pcyBkYSBwZXNxdWlzYSByZXNwb25zw6F2ZWwgcG9yIGlkZW50aWZpY2FyIG9zIGF0cmlidXRvc1xuICAgICAqIGNvbnRpZG9zIG5vcyBlbGVtZW50b3MgcmVzdWx0YW50ZXMgZGEgYnVzY2FcbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSBkYXRhIGRhZG9zIHJlZmVyZW50ZSBhbyByZXRvcm5vIGRhIHJlcXVpc2nDp8Ojb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGFmdGVyU2VhcmNoKGRhdGEpIHtcbiAgICAgIHZhciBrZXlzID0gZGF0YS5pdGVtcy5sZW5ndGggPiAwID8gT2JqZWN0LmtleXMoZGF0YS5pdGVtc1swXSkgOiBbXTtcblxuICAgICAgLy9yZXRpcmEgdG9kb3Mgb3MgYXRyaWJ1dG9zIHF1ZSBjb21lw6dhbSBjb20gJC5cbiAgICAgIC8vRXNzZXMgYXRyaWJ1dG9zIHPDo28gYWRpY2lvbmFkb3MgcGVsbyBzZXJ2acOnbyBlIG7Do28gZGV2ZSBhcGFyZWNlciBuYSBsaXN0YWdlbVxuICAgICAgdm0ua2V5cyA9IGxvZGFzaC5maWx0ZXIoa2V5cywgZnVuY3Rpb24gKGtleSkge1xuICAgICAgICByZXR1cm4gIWxvZGFzaC5zdGFydHNXaXRoKGtleSwgJyQnKTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENvbG9hY2Egbm8gZm9ybXVsw6FyaW8gbyBmaWx0cm8gZXNjb2xoaWRvIHBhcmEgZWRpw6fDo29cbiAgICAgKiBAcGFyYW0ge2FueX0gJGluZGV4IGluZGljZSBubyBhcnJheSBkbyBmaWx0cm8gZXNjb2xoaWRvXG4gICAgICovXG4gICAgZnVuY3Rpb24gZWRpdEZpbHRlcigkaW5kZXgpIHtcbiAgICAgIHZtLmluZGV4ID0gJGluZGV4O1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0gdm0uYWRkZWRGaWx0ZXJzWyRpbmRleF07XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVtb3ZlIG8gZmlsdHJvIGVzY29saGlkb1xuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9ICRpbmRleCBpbmRpY2Ugbm8gYXJyYXkgZG8gZmlsdHJvIGVzY29saGlkb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIHJlbW92ZUZpbHRlcigkaW5kZXgpIHtcbiAgICAgIHZtLmFkZGVkRmlsdGVycy5zcGxpY2UoJGluZGV4KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBMaW1wYSBvIGZvcm11bMOhcmlvIGNvcnJlbnRlXG4gICAgICovXG4gICAgZnVuY3Rpb24gY2xlYXIoKSB7XG4gICAgICAvL2d1YXJkYSBvIGluZGljZSBkbyByZWdpc3RybyBxdWUgZXN0w6Egc2VuZG8gZWRpdGFkb1xuICAgICAgdm0uaW5kZXggPSAtMTtcbiAgICAgIC8vdmluY3VsYWRvIGFvcyBjYW1wb3MgZG8gZm9ybXVsw6FyaW9cbiAgICAgIHZtLnF1ZXJ5RmlsdGVycyA9IHt9O1xuXG4gICAgICBpZiAodm0ubW9kZWxzKSB2bS5xdWVyeUZpbHRlcnMubW9kZWwgPSB2bS5tb2RlbHNbMF07XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVpbmljaWEgYSBjb25zdHJ1w6fDo28gZGEgcXVlcnkgbGltcGFuZG8gdHVkb1xuICAgICAqXG4gICAgICovXG4gICAgZnVuY3Rpb24gcmVzdGFydCgpIHtcbiAgICAgIC8vZ3VhcmRhIGF0cmlidXRvcyBkbyByZXN1bHRhZG8gZGEgYnVzY2EgY29ycmVudGVcbiAgICAgIHZtLmtleXMgPSBbXTtcblxuICAgICAgLy9ndWFyZGEgb3MgZmlsdHJvcyBhZGljaW9uYWRvc1xuICAgICAgdm0uYWRkZWRGaWx0ZXJzID0gW107XG4gICAgICB2bS5jbGVhcigpO1xuICAgICAgdm0ubG9hZE1vZGVscygpO1xuICAgIH1cbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZhY3RvcnkoJ2xhbmd1YWdlTG9hZGVyJywgTGFuZ3VhZ2VMb2FkZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gTGFuZ3VhZ2VMb2FkZXIoJHEsIFN1cHBvcnRTZXJ2aWNlLCAkbG9nLCAkaW5qZWN0b3IpIHtcbiAgICB2YXIgc2VydmljZSA9IHRoaXM7XG5cbiAgICBzZXJ2aWNlLnRyYW5zbGF0ZSA9IGZ1bmN0aW9uIChsb2NhbGUpIHtcbiAgICAgIHJldHVybiB7XG4gICAgICAgIGdsb2JhbDogJGluamVjdG9yLmdldChsb2NhbGUgKyAnLmkxOG4uZ2xvYmFsJyksXG4gICAgICAgIHZpZXdzOiAkaW5qZWN0b3IuZ2V0KGxvY2FsZSArICcuaTE4bi52aWV3cycpLFxuICAgICAgICBhdHRyaWJ1dGVzOiAkaW5qZWN0b3IuZ2V0KGxvY2FsZSArICcuaTE4bi5hdHRyaWJ1dGVzJyksXG4gICAgICAgIGRpYWxvZzogJGluamVjdG9yLmdldChsb2NhbGUgKyAnLmkxOG4uZGlhbG9nJyksXG4gICAgICAgIG1lc3NhZ2VzOiAkaW5qZWN0b3IuZ2V0KGxvY2FsZSArICcuaTE4bi5tZXNzYWdlcycpLFxuICAgICAgICBtb2RlbHM6ICRpbmplY3Rvci5nZXQobG9jYWxlICsgJy5pMThuLm1vZGVscycpXG4gICAgICB9O1xuICAgIH07XG5cbiAgICAvLyByZXR1cm4gbG9hZGVyRm5cbiAgICByZXR1cm4gZnVuY3Rpb24gKG9wdGlvbnMpIHtcbiAgICAgICRsb2cuaW5mbygnQ2FycmVnYW5kbyBvIGNvbnRldWRvIGRhIGxpbmd1YWdlbSAnICsgb3B0aW9ucy5rZXkpO1xuXG4gICAgICB2YXIgZGVmZXJyZWQgPSAkcS5kZWZlcigpO1xuXG4gICAgICAvL0NhcnJlZ2EgYXMgbGFuZ3MgcXVlIHByZWNpc2FtIGUgZXN0w6NvIG5vIHNlcnZpZG9yIHBhcmEgbsOjbyBwcmVjaXNhciByZXBldGlyIGFxdWlcbiAgICAgIFN1cHBvcnRTZXJ2aWNlLmxhbmdzKCkudGhlbihmdW5jdGlvbiAobGFuZ3MpIHtcbiAgICAgICAgLy9NZXJnZSBjb20gb3MgbGFuZ3MgZGVmaW5pZG9zIG5vIHNlcnZpZG9yXG4gICAgICAgIHZhciBkYXRhID0gYW5ndWxhci5tZXJnZShzZXJ2aWNlLnRyYW5zbGF0ZShvcHRpb25zLmtleSksIGxhbmdzKTtcblxuICAgICAgICByZXR1cm4gZGVmZXJyZWQucmVzb2x2ZShkYXRhKTtcbiAgICAgIH0sIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgcmV0dXJuIGRlZmVycmVkLnJlc29sdmUoc2VydmljZS50cmFuc2xhdGUob3B0aW9ucy5rZXkpKTtcbiAgICAgIH0pO1xuXG4gICAgICByZXR1cm4gZGVmZXJyZWQucHJvbWlzZTtcbiAgICB9O1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmlsdGVyKCd0QXR0cicsIHRBdHRyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIHRBdHRyKCRmaWx0ZXIpIHtcbiAgICAvKipcbiAgICAgKiBGaWx0cm8gcGFyYSB0cmFkdcOnw6NvIGRlIHVtIGF0cmlidXRvIGRlIHVtIG1vZGVsXG4gICAgICogXG4gICAgICogQHBhcmFtIHthbnl9IG5hbWUgbm9tZSBkbyBhdHJpYnV0b1xuICAgICAqIEByZXR1cm5zIG8gbm9tZSBkbyBhdHJpYnV0byB0cmFkdXppZG8gY2FzbyBlbmNvbnRyZSBzZSBuw6NvIG8gbm9tZSBwYXNzYWRvIHBvciBwYXJhbWV0cm9cbiAgICAgKi9cbiAgICByZXR1cm4gZnVuY3Rpb24gKG5hbWUpIHtcbiAgICAgIHZhciBrZXkgPSAnYXR0cmlidXRlcy4nICsgbmFtZTtcbiAgICAgIHZhciB0cmFuc2xhdGUgPSAkZmlsdGVyKCd0cmFuc2xhdGUnKShrZXkpO1xuXG4gICAgICByZXR1cm4gdHJhbnNsYXRlID09PSBrZXkgPyBuYW1lIDogdHJhbnNsYXRlO1xuICAgIH07XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5maWx0ZXIoJ3RCcmVhZGNydW1iJywgdEJyZWFkY3J1bWIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gdEJyZWFkY3J1bWIoJGZpbHRlcikge1xuICAgIC8qKlxuICAgICAqIEZpbHRybyBwYXJhIHRyYWR1w6fDo28gZG8gYnJlYWRjcnVtYiAodGl0dWxvIGRhIHRlbGEgY29tIHJhc3RyZWlvKVxuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IGlkIGNoYXZlIGNvbSBvIG5vbWUgZG8gc3RhdGUgcmVmZXJlbnRlIHRlbGFcbiAgICAgKiBAcmV0dXJucyBhIHRyYWR1w6fDo28gY2FzbyBlbmNvbnRyZSBzZSBuw6NvIG8gaWQgcGFzc2FkbyBwb3IgcGFyYW1ldHJvXG4gICAgICovXG4gICAgcmV0dXJuIGZ1bmN0aW9uIChpZCkge1xuICAgICAgLy9wZWdhIGEgc2VndW5kYSBwYXJ0ZSBkbyBub21lIGRvIHN0YXRlLCByZXRpcmFuZG8gYSBwYXJ0ZSBhYnN0cmF0YSAoYXBwLilcbiAgICAgIHZhciBrZXkgPSAndmlld3MuYnJlYWRjcnVtYnMuJyArIGlkLnNwbGl0KCcuJylbMV07XG4gICAgICB2YXIgdHJhbnNsYXRlID0gJGZpbHRlcigndHJhbnNsYXRlJykoa2V5KTtcblxuICAgICAgcmV0dXJuIHRyYW5zbGF0ZSA9PT0ga2V5ID8gaWQgOiB0cmFuc2xhdGU7XG4gICAgfTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZpbHRlcigndE1vZGVsJywgdE1vZGVsKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIHRNb2RlbCgkZmlsdGVyKSB7XG4gICAgLyoqXG4gICAgICogRmlsdHJvIHBhcmEgdHJhZHXDp8OjbyBkZSB1bSBhdHJpYnV0byBkZSB1bSBtb2RlbFxuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IG5hbWUgbm9tZSBkbyBhdHJpYnV0b1xuICAgICAqIEByZXR1cm5zIG8gbm9tZSBkbyBhdHJpYnV0byB0cmFkdXppZG8gY2FzbyBlbmNvbnRyZSBzZSBuw6NvIG8gbm9tZSBwYXNzYWRvIHBvciBwYXJhbWV0cm9cbiAgICAgKi9cbiAgICByZXR1cm4gZnVuY3Rpb24gKG5hbWUpIHtcbiAgICAgIHZhciBrZXkgPSAnbW9kZWxzLicgKyBuYW1lLnRvTG93ZXJDYXNlKCk7XG4gICAgICB2YXIgdHJhbnNsYXRlID0gJGZpbHRlcigndHJhbnNsYXRlJykoa2V5KTtcblxuICAgICAgcmV0dXJuIHRyYW5zbGF0ZSA9PT0ga2V5ID8gbmFtZSA6IHRyYW5zbGF0ZTtcbiAgICB9O1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLnJ1bihhdXRoZW50aWNhdGlvbkxpc3RlbmVyKTtcblxuICAvKipcbiAgICogTGlzdGVuIGFsbCBzdGF0ZSAocGFnZSkgY2hhbmdlcy4gRXZlcnkgdGltZSBhIHN0YXRlIGNoYW5nZSBuZWVkIHRvIHZlcmlmeSB0aGUgdXNlciBpcyBhdXRoZW50aWNhdGVkIG9yIG5vdCB0b1xuICAgKiByZWRpcmVjdCB0byBjb3JyZWN0IHBhZ2UuIFdoZW4gYSB1c2VyIGNsb3NlIHRoZSBicm93c2VyIHdpdGhvdXQgbG9nb3V0LCB3aGVuIGhpbSByZW9wZW4gdGhlIGJyb3dzZXIgdGhpcyBldmVudFxuICAgKiByZWF1dGhlbnRpY2F0ZSB0aGUgdXNlciB3aXRoIHRoZSBwZXJzaXN0ZW50IHRva2VuIG9mIHRoZSBsb2NhbCBzdG9yYWdlLlxuICAgKlxuICAgKiBXZSBkb24ndCBjaGVjayBpZiB0aGUgdG9rZW4gaXMgZXhwaXJlZCBvciBub3QgaW4gdGhlIHBhZ2UgY2hhbmdlLCBiZWNhdXNlIGlzIGdlbmVyYXRlIGFuIHVuZWNlc3Nhcnkgb3ZlcmhlYWQuXG4gICAqIElmIHRoZSB0b2tlbiBpcyBleHBpcmVkIHdoZW4gdGhlIHVzZXIgdHJ5IHRvIGNhbGwgdGhlIGZpcnN0IGFwaSB0byBnZXQgZGF0YSwgaGltIHdpbGwgYmUgbG9nb2ZmIGFuZCByZWRpcmVjdFxuICAgKiB0byBsb2dpbiBwYWdlLlxuICAgKlxuICAgKiBAcGFyYW0gJHJvb3RTY29wZVxuICAgKiBAcGFyYW0gJHN0YXRlXG4gICAqIEBwYXJhbSAkc3RhdGVQYXJhbXNcbiAgICogQHBhcmFtIEF1dGhcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gYXV0aGVudGljYXRpb25MaXN0ZW5lcigkcm9vdFNjb3BlLCAkc3RhdGUsIEdsb2JhbCwgQXV0aCwgUHJUb2FzdCwgLy8gTk9TT05BUlxuICAkdHJhbnNsYXRlKSB7XG5cbiAgICAvL29ubHkgd2hlbiBhcHBsaWNhdGlvbiBzdGFydCBjaGVjayBpZiB0aGUgZXhpc3RlbnQgdG9rZW4gc3RpbGwgdmFsaWRcbiAgICBBdXRoLnJlbW90ZVZhbGlkYXRlVG9rZW4oKS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgIC8vaWYgdGhlIHRva2VuIGlzIHZhbGlkIGNoZWNrIGlmIGV4aXN0cyB0aGUgdXNlciBiZWNhdXNlIHRoZSBicm93c2VyIGNvdWxkIGJlIGNsb3NlZFxuICAgICAgLy9hbmQgdGhlIHVzZXIgZGF0YSBpc24ndCBpbiBtZW1vcnlcbiAgICAgIGlmIChBdXRoLmN1cnJlbnRVc2VyID09PSBudWxsKSB7XG4gICAgICAgIEF1dGgudXBkYXRlQ3VycmVudFVzZXIoYW5ndWxhci5mcm9tSnNvbihsb2NhbFN0b3JhZ2UuZ2V0SXRlbSgndXNlcicpKSk7XG4gICAgICB9XG4gICAgfSk7XG5cbiAgICAvL0NoZWNrIGlmIHRoZSB0b2tlbiBzdGlsbCB2YWxpZC5cbiAgICAkcm9vdFNjb3BlLiRvbignJHN0YXRlQ2hhbmdlU3RhcnQnLCBmdW5jdGlvbiAoZXZlbnQsIHRvU3RhdGUpIHtcbiAgICAgIGlmICh0b1N0YXRlLmRhdGEubmVlZEF1dGhlbnRpY2F0aW9uIHx8IHRvU3RhdGUuZGF0YS5uZWVkUHJvZmlsZSkge1xuICAgICAgICAvL2RvbnQgdHJhaXQgdGhlIHN1Y2Nlc3MgYmxvY2sgYmVjYXVzZSBhbHJlYWR5IGRpZCBieSB0b2tlbiBpbnRlcmNlcHRvclxuICAgICAgICBBdXRoLnJlbW90ZVZhbGlkYXRlVG9rZW4oKS5jYXRjaChmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgUHJUb2FzdC53YXJuKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMubG9naW4ubG9nb3V0SW5hY3RpdmUnKSk7XG5cbiAgICAgICAgICBpZiAodG9TdGF0ZS5uYW1lICE9PSBHbG9iYWwubG9naW5TdGF0ZSkge1xuICAgICAgICAgICAgJHN0YXRlLmdvKEdsb2JhbC5sb2dpblN0YXRlKTtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICBldmVudC5wcmV2ZW50RGVmYXVsdCgpO1xuICAgICAgICB9KTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIC8vaWYgdGhlIHVzZSBpcyBhdXRoZW50aWNhdGVkIGFuZCBuZWVkIHRvIGVudGVyIGluIGxvZ2luIHBhZ2VcbiAgICAgICAgLy9oaW0gd2lsbCBiZSByZWRpcmVjdGVkIHRvIGhvbWUgcGFnZVxuICAgICAgICBpZiAodG9TdGF0ZS5uYW1lID09PSBHbG9iYWwubG9naW5TdGF0ZSAmJiBBdXRoLmF1dGhlbnRpY2F0ZWQoKSkge1xuICAgICAgICAgICRzdGF0ZS5nbyhHbG9iYWwuaG9tZVN0YXRlKTtcbiAgICAgICAgICBldmVudC5wcmV2ZW50RGVmYXVsdCgpO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykucnVuKGF1dGhvcml6YXRpb25MaXN0ZW5lcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiBhdXRob3JpemF0aW9uTGlzdGVuZXIoJHJvb3RTY29wZSwgJHN0YXRlLCBHbG9iYWwsIEF1dGgpIHtcbiAgICAvKipcbiAgICAgKiBBIGNhZGEgbXVkYW7Dp2EgZGUgZXN0YWRvIChcInDDoWdpbmFcIikgdmVyaWZpY2Egc2UgbyB1c3XDoXJpbyB0ZW0gbyBwZXJmaWxcbiAgICAgKiBuZWNlc3PDoXJpbyBwYXJhIG8gYWNlc3NvIGEgbWVzbWFcbiAgICAgKi9cbiAgICAkcm9vdFNjb3BlLiRvbignJHN0YXRlQ2hhbmdlU3RhcnQnLCBmdW5jdGlvbiAoZXZlbnQsIHRvU3RhdGUpIHtcbiAgICAgIGlmICh0b1N0YXRlLmRhdGEgJiYgdG9TdGF0ZS5kYXRhLm5lZWRBdXRoZW50aWNhdGlvbiAmJiB0b1N0YXRlLmRhdGEubmVlZFByb2ZpbGUgJiYgQXV0aC5hdXRoZW50aWNhdGVkKCkgJiYgIUF1dGguY3VycmVudFVzZXIuaGFzUHJvZmlsZSh0b1N0YXRlLmRhdGEubmVlZFByb2ZpbGUsIHRvU3RhdGUuZGF0YS5hbGxQcm9maWxlcykpIHtcblxuICAgICAgICAkc3RhdGUuZ28oR2xvYmFsLm5vdEF1dGhvcml6ZWRTdGF0ZSk7XG4gICAgICAgIGV2ZW50LnByZXZlbnREZWZhdWx0KCk7XG4gICAgICB9XG4gICAgfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29uZmlnKHNwaW5uZXJJbnRlcmNlcHRvcik7XG5cbiAgZnVuY3Rpb24gc3Bpbm5lckludGVyY2VwdG9yKCRodHRwUHJvdmlkZXIsICRwcm92aWRlKSB7XG4gICAgLyoqXG4gICAgICogRXN0ZSBpbnRlcmNlcHRvciDDqSByZXNwb25zw6F2ZWwgcG9yIG1vc3RyYXIgZSBlc2NvbmRlciBvXG4gICAgICogY29tcG9uZW50ZSBQclNwaW5uZXIgc2VtcHJlIHF1ZSB1bWEgcmVxdWlzacOnw6NvIGFqYXhcbiAgICAgKiBpbmljaWFyIGUgZmluYWxpemFyLlxuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9ICRxXG4gICAgICogQHBhcmFtIHthbnl9ICRpbmplY3RvclxuICAgICAqIEByZXR1cm5zXG4gICAgICovXG4gICAgZnVuY3Rpb24gc2hvd0hpZGVTcGlubmVyKCRxLCAkaW5qZWN0b3IpIHtcbiAgICAgIHJldHVybiB7XG4gICAgICAgIHJlcXVlc3Q6IGZ1bmN0aW9uIHJlcXVlc3QoY29uZmlnKSB7XG4gICAgICAgICAgJGluamVjdG9yLmdldCgnUHJTcGlubmVyJykuc2hvdygpO1xuXG4gICAgICAgICAgcmV0dXJuIGNvbmZpZztcbiAgICAgICAgfSxcblxuICAgICAgICByZXNwb25zZTogZnVuY3Rpb24gcmVzcG9uc2UoX3Jlc3BvbnNlKSB7XG4gICAgICAgICAgJGluamVjdG9yLmdldCgnUHJTcGlubmVyJykuaGlkZSgpO1xuXG4gICAgICAgICAgcmV0dXJuIF9yZXNwb25zZTtcbiAgICAgICAgfSxcblxuICAgICAgICByZXNwb25zZUVycm9yOiBmdW5jdGlvbiByZXNwb25zZUVycm9yKHJlamVjdGlvbikge1xuICAgICAgICAgICRpbmplY3Rvci5nZXQoJ1ByU3Bpbm5lcicpLmhpZGUoKTtcblxuICAgICAgICAgIHJldHVybiAkcS5yZWplY3QocmVqZWN0aW9uKTtcbiAgICAgICAgfVxuICAgICAgfTtcbiAgICB9XG5cbiAgICAvLyBEZWZpbmUgdW1hIGZhY3RvcnkgcGFyYSBvICRodHRwSW50ZXJjZXB0b3JcbiAgICAkcHJvdmlkZS5mYWN0b3J5KCdzaG93SGlkZVNwaW5uZXInLCBzaG93SGlkZVNwaW5uZXIpO1xuXG4gICAgLy8gQWRpY2lvbmEgYSBmYWN0b3J5IG5vIGFycmF5IGRlIGludGVyY2VwdG9ycyBkbyAkaHR0cFxuICAgICRodHRwUHJvdmlkZXIuaW50ZXJjZXB0b3JzLnB1c2goJ3Nob3dIaWRlU3Bpbm5lcicpO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4vKmVzbGludCBhbmd1bGFyL21vZHVsZS1nZXR0ZXI6IDAqL1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbmZpZyh0b2tlbkludGVyY2VwdG9yKTtcblxuICAvKipcbiAgICogSW50ZXJjZXB0IGFsbCByZXNwb25zZSAoc3VjY2VzcyBvciBlcnJvcikgdG8gdmVyaWZ5IHRoZSByZXR1cm5lZCB0b2tlblxuICAgKlxuICAgKiBAcGFyYW0gJGh0dHBQcm92aWRlclxuICAgKiBAcGFyYW0gJHByb3ZpZGVcbiAgICogQHBhcmFtIEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiB0b2tlbkludGVyY2VwdG9yKCRodHRwUHJvdmlkZXIsICRwcm92aWRlLCBHbG9iYWwpIHtcblxuICAgIGZ1bmN0aW9uIHJlZGlyZWN0V2hlblNlcnZlckxvZ2dlZE91dCgkcSwgJGluamVjdG9yKSB7XG4gICAgICByZXR1cm4ge1xuICAgICAgICByZXF1ZXN0OiBmdW5jdGlvbiByZXF1ZXN0KGNvbmZpZykge1xuICAgICAgICAgIHZhciB0b2tlbiA9ICRpbmplY3Rvci5nZXQoJ0F1dGgnKS5nZXRUb2tlbigpO1xuXG4gICAgICAgICAgaWYgKHRva2VuKSB7XG4gICAgICAgICAgICBjb25maWcuaGVhZGVyc1snQXV0aG9yaXphdGlvbiddID0gJ0JlYXJlciAnICsgdG9rZW47XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgcmV0dXJuIGNvbmZpZztcbiAgICAgICAgfSxcbiAgICAgICAgcmVzcG9uc2U6IGZ1bmN0aW9uIHJlc3BvbnNlKF9yZXNwb25zZSkge1xuICAgICAgICAgIC8vIGdldCBhIG5ldyByZWZyZXNoIHRva2VuIHRvIHVzZSBpbiB0aGUgbmV4dCByZXF1ZXN0XG4gICAgICAgICAgdmFyIHRva2VuID0gX3Jlc3BvbnNlLmhlYWRlcnMoJ0F1dGhvcml6YXRpb24nKTtcblxuICAgICAgICAgIGlmICh0b2tlbikge1xuICAgICAgICAgICAgJGluamVjdG9yLmdldCgnQXV0aCcpLnNldFRva2VuKHRva2VuLnNwbGl0KCcgJylbMV0pO1xuICAgICAgICAgIH1cbiAgICAgICAgICByZXR1cm4gX3Jlc3BvbnNlO1xuICAgICAgICB9LFxuICAgICAgICByZXNwb25zZUVycm9yOiBmdW5jdGlvbiByZXNwb25zZUVycm9yKHJlamVjdGlvbikge1xuICAgICAgICAgIC8vIEluc3RlYWQgb2YgY2hlY2tpbmcgZm9yIGEgc3RhdHVzIGNvZGUgb2YgNDAwIHdoaWNoIG1pZ2h0IGJlIHVzZWRcbiAgICAgICAgICAvLyBmb3Igb3RoZXIgcmVhc29ucyBpbiBMYXJhdmVsLCB3ZSBjaGVjayBmb3IgdGhlIHNwZWNpZmljIHJlamVjdGlvblxuICAgICAgICAgIC8vIHJlYXNvbnMgdG8gdGVsbCB1cyBpZiB3ZSBuZWVkIHRvIHJlZGlyZWN0IHRvIHRoZSBsb2dpbiBzdGF0ZVxuICAgICAgICAgIHZhciByZWplY3Rpb25SZWFzb25zID0gWyd0b2tlbl9ub3RfcHJvdmlkZWQnLCAndG9rZW5fZXhwaXJlZCcsICd0b2tlbl9hYnNlbnQnLCAndG9rZW5faW52YWxpZCddO1xuXG4gICAgICAgICAgdmFyIHRva2VuRXJyb3IgPSBmYWxzZTtcblxuICAgICAgICAgIGFuZ3VsYXIuZm9yRWFjaChyZWplY3Rpb25SZWFzb25zLCBmdW5jdGlvbiAodmFsdWUpIHtcbiAgICAgICAgICAgIGlmIChyZWplY3Rpb24uZGF0YSAmJiByZWplY3Rpb24uZGF0YS5lcnJvciA9PT0gdmFsdWUpIHtcbiAgICAgICAgICAgICAgdG9rZW5FcnJvciA9IHRydWU7XG5cbiAgICAgICAgICAgICAgJGluamVjdG9yLmdldCgnQXV0aCcpLmxvZ291dCgpLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgIHZhciAkc3RhdGUgPSAkaW5qZWN0b3IuZ2V0KCckc3RhdGUnKTtcblxuICAgICAgICAgICAgICAgIC8vIGluIGNhc2UgbXVsdGlwbGUgYWpheCByZXF1ZXN0IGZhaWwgYXQgc2FtZSB0aW1lIGJlY2F1c2UgdG9rZW4gcHJvYmxlbXMsXG4gICAgICAgICAgICAgICAgLy8gb25seSB0aGUgZmlyc3Qgd2lsbCByZWRpcmVjdFxuICAgICAgICAgICAgICAgIGlmICghJHN0YXRlLmlzKEdsb2JhbC5sb2dpblN0YXRlKSkge1xuICAgICAgICAgICAgICAgICAgJHN0YXRlLmdvKEdsb2JhbC5sb2dpblN0YXRlKTtcblxuICAgICAgICAgICAgICAgICAgLy9jbG9zZSBhbnkgZGlhbG9nIHRoYXQgaXMgb3BlbmVkXG4gICAgICAgICAgICAgICAgICAkaW5qZWN0b3IuZ2V0KCdQckRpYWxvZycpLmNsb3NlKCk7XG5cbiAgICAgICAgICAgICAgICAgIGV2ZW50LnByZXZlbnREZWZhdWx0KCk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9KTtcblxuICAgICAgICAgIC8vZGVmaW5lIGRhdGEgdG8gZW1wdHkgYmVjYXVzZSBhbHJlYWR5IHNob3cgUHJUb2FzdCB0b2tlbiBtZXNzYWdlXG4gICAgICAgICAgaWYgKHRva2VuRXJyb3IpIHtcbiAgICAgICAgICAgIHJlamVjdGlvbi5kYXRhID0ge307XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbihyZWplY3Rpb24uaGVhZGVycykpIHtcbiAgICAgICAgICAgIC8vIG1hbnkgc2VydmVycyBlcnJvcnMgKGJ1c2luZXNzKSBhcmUgaW50ZXJjZXB0IGhlcmUgYnV0IGdlbmVyYXRlZCBhIG5ldyByZWZyZXNoIHRva2VuXG4gICAgICAgICAgICAvLyBhbmQgbmVlZCB1cGRhdGUgY3VycmVudCB0b2tlblxuICAgICAgICAgICAgdmFyIHRva2VuID0gcmVqZWN0aW9uLmhlYWRlcnMoJ0F1dGhvcml6YXRpb24nKTtcblxuICAgICAgICAgICAgaWYgKHRva2VuKSB7XG4gICAgICAgICAgICAgICRpbmplY3Rvci5nZXQoJ0F1dGgnKS5zZXRUb2tlbih0b2tlbi5zcGxpdCgnICcpWzFdKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9XG5cbiAgICAgICAgICByZXR1cm4gJHEucmVqZWN0KHJlamVjdGlvbik7XG4gICAgICAgIH1cbiAgICAgIH07XG4gICAgfVxuXG4gICAgLy8gU2V0dXAgZm9yIHRoZSAkaHR0cEludGVyY2VwdG9yXG4gICAgJHByb3ZpZGUuZmFjdG9yeSgncmVkaXJlY3RXaGVuU2VydmVyTG9nZ2VkT3V0JywgcmVkaXJlY3RXaGVuU2VydmVyTG9nZ2VkT3V0KTtcblxuICAgIC8vIFB1c2ggdGhlIG5ldyBmYWN0b3J5IG9udG8gdGhlICRodHRwIGludGVyY2VwdG9yIGFycmF5XG4gICAgJGh0dHBQcm92aWRlci5pbnRlcmNlcHRvcnMucHVzaCgncmVkaXJlY3RXaGVuU2VydmVyTG9nZ2VkT3V0Jyk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29uZmlnKHZhbGlkYXRpb25JbnRlcmNlcHRvcik7XG5cbiAgZnVuY3Rpb24gdmFsaWRhdGlvbkludGVyY2VwdG9yKCRodHRwUHJvdmlkZXIsICRwcm92aWRlKSB7XG4gICAgLyoqXG4gICAgICogRXN0ZSBpbnRlcmNlcHRvciDDqSByZXNwb25zw6F2ZWwgcG9yIG1vc3RyYXIgYXNcbiAgICAgKiBtZW5zYWdlbnMgZGUgZXJybyByZWZlcmVudGUgYXMgdmFsaWRhw6fDtWVzIGRvIGJhY2stZW5kXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gJHFcbiAgICAgKiBAcGFyYW0ge2FueX0gJGluamVjdG9yXG4gICAgICogQHJldHVybnNcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBzaG93RXJyb3JWYWxpZGF0aW9uKCRxLCAkaW5qZWN0b3IpIHtcbiAgICAgIHJldHVybiB7XG4gICAgICAgIHJlc3BvbnNlRXJyb3I6IGZ1bmN0aW9uIHJlc3BvbnNlRXJyb3IocmVqZWN0aW9uKSB7XG4gICAgICAgICAgdmFyIFByVG9hc3QgPSAkaW5qZWN0b3IuZ2V0KCdQclRvYXN0Jyk7XG4gICAgICAgICAgdmFyICR0cmFuc2xhdGUgPSAkaW5qZWN0b3IuZ2V0KCckdHJhbnNsYXRlJyk7XG5cbiAgICAgICAgICBpZiAocmVqZWN0aW9uLmNvbmZpZy5kYXRhICYmICFyZWplY3Rpb24uY29uZmlnLmRhdGEuc2tpcFZhbGlkYXRpb24pIHtcbiAgICAgICAgICAgIGlmIChyZWplY3Rpb24uZGF0YSAmJiByZWplY3Rpb24uZGF0YS5lcnJvcikge1xuXG4gICAgICAgICAgICAgIC8vdmVyaWZpY2Egc2Ugb2NvcnJldSBhbGd1bSBlcnJvIHJlZmVyZW50ZSBhbyB0b2tlblxuICAgICAgICAgICAgICBpZiAocmVqZWN0aW9uLmRhdGEuZXJyb3Iuc3RhcnRzV2l0aCgndG9rZW5fJykpIHtcbiAgICAgICAgICAgICAgICBQclRvYXN0Lndhcm4oJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5sb2dpbi5sb2dvdXRJbmFjdGl2ZScpKTtcbiAgICAgICAgICAgICAgfSBlbHNlIGlmIChyZWplY3Rpb24uZGF0YS5lcnJvciAhPT0gJ05vdCBGb3VuZCcpIHtcbiAgICAgICAgICAgICAgICBQclRvYXN0LmVycm9yKCR0cmFuc2xhdGUuaW5zdGFudChyZWplY3Rpb24uZGF0YS5lcnJvcikpO1xuICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICBQclRvYXN0LmVycm9yVmFsaWRhdGlvbihyZWplY3Rpb24uZGF0YSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgcmV0dXJuICRxLnJlamVjdChyZWplY3Rpb24pO1xuICAgICAgICB9XG4gICAgICB9O1xuICAgIH1cblxuICAgIC8vIERlZmluZSB1bWEgZmFjdG9yeSBwYXJhIG8gJGh0dHBJbnRlcmNlcHRvclxuICAgICRwcm92aWRlLmZhY3RvcnkoJ3Nob3dFcnJvclZhbGlkYXRpb24nLCBzaG93RXJyb3JWYWxpZGF0aW9uKTtcblxuICAgIC8vIEFkaWNpb25hIGEgZmFjdG9yeSBubyBhcnJheSBkZSBpbnRlcmNlcHRvcnMgZG8gJGh0dHBcbiAgICAkaHR0cFByb3ZpZGVyLmludGVyY2VwdG9ycy5wdXNoKCdzaG93RXJyb3JWYWxpZGF0aW9uJyk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb250cm9sbGVyKCdLYW5iYW5Db250cm9sbGVyJywgS2FuYmFuQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBLYW5iYW5Db250cm9sbGVyKCRjb250cm9sbGVyLCBUYXNrc1NlcnZpY2UsIFN0YXR1c1NlcnZpY2UsIFByVG9hc3QsICRtZERpYWxvZywgJGRvY3VtZW50LCBBdXRoLCBQcm9qZWN0c1NlcnZpY2UpIHtcbiAgICAvL0F0dHJpYnV0ZXMgQmxvY2tcbiAgICB2YXIgdm0gPSB0aGlzO1xuICAgIHZhciBmaWVsZHMgPSBbeyBuYW1lOiAnaWQnLCB0eXBlOiAnc3RyaW5nJyB9LCB7IG5hbWU6ICdzdGF0dXMnLCBtYXA6ICdzdGF0ZScsIHR5cGU6ICdzdHJpbmcnIH0sIHsgbmFtZTogJ3RleHQnLCBtYXA6ICdsYWJlbCcsIHR5cGU6ICdzdHJpbmcnIH0sIHsgbmFtZTogJ3RhZ3MnLCB0eXBlOiAnc3RyaW5nJyB9XTtcblxuICAgIHZtLm9uQWN0aXZhdGUgPSBmdW5jdGlvbiAoKSB7XG4gICAgICB2bS5wcm9qZWN0ID0gbG9jYWxTdG9yYWdlLmdldEl0ZW0oJ3Byb2plY3QnKTtcbiAgICAgIFByb2plY3RzU2VydmljZS5xdWVyeSh7IHByb2plY3RfaWQ6IHZtLnByb2plY3QgfSkudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgdm0uYWN0dWFsUHJvamVjdCA9IHJlc3BvbnNlWzBdO1xuICAgICAgfSk7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMgPSB7IHByb2plY3RfaWQ6IHZtLnByb2plY3QgfTtcbiAgICAgIHZtLmlzTW92ZWQgPSBmYWxzZTtcbiAgICB9O1xuXG4gICAgdm0uYXBwbHlGaWx0ZXJzID0gZnVuY3Rpb24gKGRlZmF1bHRRdWVyeUZpbHRlcnMpIHtcbiAgICAgIHJldHVybiBhbmd1bGFyLmV4dGVuZChkZWZhdWx0UXVlcnlGaWx0ZXJzLCB2bS5xdWVyeUZpbHRlcnMpO1xuICAgIH07XG5cbiAgICB2bS5hZnRlclNlYXJjaCA9IGZ1bmN0aW9uICgpIHtcbiAgICAgIHZhciBjb2x1bW5zID0gW107XG4gICAgICB2YXIgdGFza3MgPSBbXTtcblxuICAgICAgU3RhdHVzU2VydmljZS5xdWVyeSgpLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgIHJlc3BvbnNlLmZvckVhY2goZnVuY3Rpb24gKHN0YXR1cykge1xuICAgICAgICAgIGNvbHVtbnMucHVzaCh7IHRleHQ6IHN0YXR1cy5uYW1lLCBkYXRhRmllbGQ6IHN0YXR1cy5zbHVnLCBjb2xsYXBzaWJsZTogZmFsc2UgfSk7XG4gICAgICAgIH0pO1xuXG4gICAgICAgIGlmICh2bS5yZXNvdXJjZXMubGVuZ3RoID4gMCkge1xuICAgICAgICAgIHZtLnJlc291cmNlcy5mb3JFYWNoKGZ1bmN0aW9uICh0YXNrKSB7XG4gICAgICAgICAgICB0YXNrcy5wdXNoKHtcbiAgICAgICAgICAgICAgaWQ6IHRhc2suaWQsXG4gICAgICAgICAgICAgIHN0YXRlOiB0YXNrLnN0YXR1cy5zbHVnLFxuICAgICAgICAgICAgICBsYWJlbDogdGFzay50aXRsZSxcbiAgICAgICAgICAgICAgdGFnczogdGFzay50eXBlLm5hbWUgKyAnLCAnICsgdGFzay5wcmlvcml0eS5uYW1lXG4gICAgICAgICAgICB9KTtcbiAgICAgICAgICB9KTtcblxuICAgICAgICAgIHZhciBzb3VyY2UgPSB7XG4gICAgICAgICAgICBsb2NhbERhdGE6IHRhc2tzLFxuICAgICAgICAgICAgZGF0YVR5cGU6ICdhcnJheScsXG4gICAgICAgICAgICBkYXRhRmllbGRzOiBmaWVsZHNcbiAgICAgICAgICB9O1xuICAgICAgICAgIHZhciBkYXRhQWRhcHRlciA9IG5ldyAkLmpxeC5kYXRhQWRhcHRlcihzb3VyY2UpO1xuXG4gICAgICAgICAgdm0uc2V0dGluZ3MgPSB7XG4gICAgICAgICAgICBzb3VyY2U6IGRhdGFBZGFwdGVyLFxuICAgICAgICAgICAgY29sdW1uczogY29sdW1ucyxcbiAgICAgICAgICAgIHRoZW1lOiAnbGlnaHQnXG4gICAgICAgICAgfTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICB2bS5zZXR0aW5ncyA9IHtcbiAgICAgICAgICAgIHNvdXJjZTogW3t9XSxcbiAgICAgICAgICAgIGNvbHVtbnM6IGNvbHVtbnMsXG4gICAgICAgICAgICB0aGVtZTogJ2xpZ2h0J1xuICAgICAgICAgIH07XG4gICAgICAgIH1cbiAgICAgICAgdm0ua2FuYmFuUmVhZHkgPSB0cnVlO1xuICAgICAgfSk7XG4gICAgfTtcblxuICAgIHZtLm9uSXRlbU1vdmVkID0gZnVuY3Rpb24gKGV2ZW50KSB7XG4gICAgICBpZiAoQXV0aC5jdXJyZW50VXNlci5pZCA9PT0gdm0uYWN0dWFsUHJvamVjdC5vd25lcikge1xuICAgICAgICB2bS5pc01vdmVkID0gdHJ1ZTtcbiAgICAgICAgVGFza3NTZXJ2aWNlLnF1ZXJ5KHsgdGFza19pZDogZXZlbnQuYXJncy5pdGVtSWQgfSkudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgICBpZiAocmVzcG9uc2VbMF0ubWlsZXN0b25lICYmIHJlc3BvbnNlWzBdLm1pbGVzdG9uZS5kb25lIHx8IHJlc3BvbnNlWzBdLnByb2plY3QuZG9uZSkge1xuICAgICAgICAgICAgUHJUb2FzdC5lcnJvcignTsOjbyDDqSBwb3Nzw612ZWwgbW9kaWZpY2FyIG8gc3RhdHVzIGRlIHVtYSB0YXJlZmEgZmluYWxpemFkYS4nKTtcbiAgICAgICAgICAgIHZtLmFmdGVyU2VhcmNoKCk7XG4gICAgICAgICAgICB2bS5pc01vdmVkID0gZmFsc2U7XG4gICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIFRhc2tzU2VydmljZS51cGRhdGVUYXNrQnlLYW5iYW4oe1xuICAgICAgICAgICAgICBwcm9qZWN0X2lkOiB2bS5wcm9qZWN0LFxuICAgICAgICAgICAgICBpZDogZXZlbnQuYXJncy5pdGVtSWQsXG4gICAgICAgICAgICAgIG9sZENvbHVtbjogZXZlbnQuYXJncy5vbGRDb2x1bW4sXG4gICAgICAgICAgICAgIG5ld0NvbHVtbjogZXZlbnQuYXJncy5uZXdDb2x1bW4gfSkudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgIHZtLmlzTW92ZWQgPSBmYWxzZTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICAgIH1cbiAgICAgICAgfSk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICB2bS5hZnRlclNlYXJjaCgpO1xuICAgICAgfVxuICAgIH07XG5cbiAgICB2bS5vbkl0ZW1DbGlja2VkID0gZnVuY3Rpb24gKGV2ZW50KSB7XG4gICAgICBpZiAoIXZtLmlzTW92ZWQpIHtcbiAgICAgICAgVGFza3NTZXJ2aWNlLnF1ZXJ5KHsgdGFza19pZDogZXZlbnQuYXJncy5pdGVtSWQgfSkudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgICB2bS50YXNrSW5mbyA9IHJlc3BvbnNlWzBdO1xuICAgICAgICAgICRtZERpYWxvZy5zaG93KHtcbiAgICAgICAgICAgIHBhcmVudDogYW5ndWxhci5lbGVtZW50KCRkb2N1bWVudC5ib2R5KSxcbiAgICAgICAgICAgIHRlbXBsYXRlVXJsOiAnY2xpZW50L2FwcC9rYW5iYW4vdGFzay1pbmZvLWRpYWxvZy90YXNrSW5mby5odG1sJyxcbiAgICAgICAgICAgIGNvbnRyb2xsZXJBczogJ3Rhc2tJbmZvQ3RybCcsXG4gICAgICAgICAgICBjb250cm9sbGVyOiAnVGFza0luZm9Db250cm9sbGVyJyxcbiAgICAgICAgICAgIGJpbmRUb0NvbnRyb2xsZXI6IHRydWUsXG4gICAgICAgICAgICBsb2NhbHM6IHtcbiAgICAgICAgICAgICAgdGFzazogdm0udGFza0luZm8sXG4gICAgICAgICAgICAgIGNsb3NlOiBjbG9zZVxuICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIGVzY2FwZVRvQ2xvc2U6IHRydWUsXG4gICAgICAgICAgICBjbGlja091dHNpZGVUb0Nsb3NlOiB0cnVlXG4gICAgICAgICAgfSk7XG4gICAgICAgIH0pO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgdm0uaXNNb3ZlZCA9IGZhbHNlO1xuICAgICAgfVxuICAgIH07XG5cbiAgICBmdW5jdGlvbiBjbG9zZSgpIHtcbiAgICAgICRtZERpYWxvZy5oaWRlKCk7XG4gICAgfVxuXG4gICAgLy8gaW5zdGFudGlhdGUgYmFzZSBjb250cm9sbGVyXG4gICAgJGNvbnRyb2xsZXIoJ0NSVURDb250cm9sbGVyJywgeyB2bTogdm0sIG1vZGVsU2VydmljZTogVGFza3NTZXJ2aWNlLCBvcHRpb25zOiB7fSB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25maWcocm91dGVzKTtcblxuICAvKipcbiAgICogQXJxdWl2byBkZSBjb25maWd1cmHDp8OjbyBjb20gYXMgcm90YXMgZXNwZWPDrWZpY2FzIGRvIHJlY3Vyc28ga2FuYmFuXG4gICAqXG4gICAqIEBwYXJhbSB7b2JqZWN0fSAkc3RhdGVQcm92aWRlclxuICAgKiBAcGFyYW0ge29iamVjdH0gR2xvYmFsXG4gICAqL1xuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvdXRlcygkc3RhdGVQcm92aWRlciwgR2xvYmFsKSB7XG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ2FwcC5rYW5iYW4nLCB7XG4gICAgICB1cmw6ICcva2FuYmFuJyxcbiAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcva2FuYmFuL2thbmJhbi5odG1sJyxcbiAgICAgIGNvbnRyb2xsZXI6ICdLYW5iYW5Db250cm9sbGVyIGFzIGthbmJhbkN0cmwnLFxuICAgICAgZGF0YToge31cbiAgICB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5mYWN0b3J5KCdLYW5iYW5TZXJ2aWNlJywgS2FuYmFuU2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiBLYW5iYW5TZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgdmFyIG1vZGVsID0gc2VydmljZUZhY3RvcnkoJ2thbmJhbicsIHtcbiAgICAgIGFjdGlvbnM6IHt9LFxuICAgICAgaW5zdGFuY2U6IHt9XG4gICAgfSk7XG5cbiAgICByZXR1cm4gbW9kZWw7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbi8qZXNsaW50LWVudiBlczYqL1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29udHJvbGxlcignTWVudUNvbnRyb2xsZXInLCBNZW51Q29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiBNZW51Q29udHJvbGxlcigkbWRTaWRlbmF2LCAkc3RhdGUsICRtZENvbG9ycykge1xuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICAvL0Jsb2NvIGRlIGRlY2xhcmFjb2VzIGRlIGZ1bmNvZXNcbiAgICB2bS5vcGVuID0gb3BlbjtcbiAgICB2bS5vcGVuTWVudU9yUmVkaXJlY3RUb1N0YXRlID0gb3Blbk1lbnVPclJlZGlyZWN0VG9TdGF0ZTtcblxuICAgIGFjdGl2YXRlKCk7XG5cbiAgICBmdW5jdGlvbiBhY3RpdmF0ZSgpIHtcbiAgICAgIHZhciBtZW51UHJlZml4ID0gJ3ZpZXdzLmxheW91dC5tZW51Lic7XG5cbiAgICAgIC8vIEFycmF5IGNvbnRlbmRvIG9zIGl0ZW5zIHF1ZSBzw6NvIG1vc3RyYWRvcyBubyBtZW51IGxhdGVyYWxcbiAgICAgIHZtLml0ZW5zTWVudSA9IFt7IHN0YXRlOiAnYXBwLnByb2plY3RzJywgdGl0bGU6IG1lbnVQcmVmaXggKyAncHJvamVjdHMnLCBpY29uOiAnd29yaycsIHN1Ykl0ZW5zOiBbXSB9LCB7IHN0YXRlOiAnYXBwLmRhc2hib2FyZCcsIHRpdGxlOiBtZW51UHJlZml4ICsgJ2Rhc2hib2FyZCcsIGljb246ICdkYXNoYm9hcmQnLCBzdWJJdGVuczogW10gfSwgeyBzdGF0ZTogJ2FwcC50YXNrcycsIHRpdGxlOiBtZW51UHJlZml4ICsgJ3Rhc2tzJywgaWNvbjogJ3ZpZXdfbGlzdCcsIHN1Ykl0ZW5zOiBbXSB9LCB7IHN0YXRlOiAnYXBwLm1pbGVzdG9uZXMnLCB0aXRsZTogbWVudVByZWZpeCArICdtaWxlc3RvbmVzJywgaWNvbjogJ3ZpZXdfbW9kdWxlJywgc3ViSXRlbnM6IFtdIH0sIHsgc3RhdGU6ICdhcHAucmVsZWFzZXMnLCB0aXRsZTogbWVudVByZWZpeCArICdyZWxlYXNlcycsIGljb246ICdzdWJzY3JpcHRpb25zJywgc3ViSXRlbnM6IFtdIH0sIHsgc3RhdGU6ICdhcHAua2FuYmFuJywgdGl0bGU6IG1lbnVQcmVmaXggKyAna2FuYmFuJywgaWNvbjogJ3ZpZXdfY29sdW1uJywgc3ViSXRlbnM6IFtdIH0sIHsgc3RhdGU6ICdhcHAudmNzJywgdGl0bGU6IG1lbnVQcmVmaXggKyAndmNzJywgaWNvbjogJ2dyb3VwX3dvcmsnLCBzdWJJdGVuczogW11cbiAgICAgICAgLy8gQ29sb3F1ZSBzZXVzIGl0ZW5zIGRlIG1lbnUgYSBwYXJ0aXIgZGVzdGUgcG9udG9cbiAgICAgICAgLyoge1xuICAgICAgICAgIHN0YXRlOiAnIycsIHRpdGxlOiBtZW51UHJlZml4ICsgJ2FkbWluJywgaWNvbjogJ3NldHRpbmdzX2FwcGxpY2F0aW9ucycsIHByb2ZpbGVzOiBbJ2FkbWluJ10sXG4gICAgICAgICAgc3ViSXRlbnM6IFtcbiAgICAgICAgICAgIHsgc3RhdGU6ICdhcHAudXNlcicsIHRpdGxlOiBtZW51UHJlZml4ICsgJ3VzZXInLCBpY29uOiAncGVvcGxlJyB9LFxuICAgICAgICAgICAgeyBzdGF0ZTogJ2FwcC5tYWlsJywgdGl0bGU6IG1lbnVQcmVmaXggKyAnbWFpbCcsIGljb246ICdtYWlsJyB9LFxuICAgICAgICAgICAgeyBzdGF0ZTogJ2FwcC5hdWRpdCcsIHRpdGxlOiBtZW51UHJlZml4ICsgJ2F1ZGl0JywgaWNvbjogJ3N0b3JhZ2UnIH0sXG4gICAgICAgICAgICB7IHN0YXRlOiAnYXBwLmRpbmFtaWMtcXVlcnknLCB0aXRsZTogbWVudVByZWZpeCArICdkaW5hbWljUXVlcnknLCBpY29uOiAnbG9jYXRpb25fc2VhcmNoaW5nJyB9XG4gICAgICAgICAgXVxuICAgICAgICB9ICovXG4gICAgICB9XTtcblxuICAgICAgLyoqXG4gICAgICAgKiBPYmpldG8gcXVlIHByZWVuY2hlIG8gbmctc3R5bGUgZG8gbWVudSBsYXRlcmFsIHRyb2NhbmRvIGFzIGNvcmVzXG4gICAgICAgKi9cbiAgICAgIHZtLnNpZGVuYXZTdHlsZSA9IHtcbiAgICAgICAgdG9wOiB7XG4gICAgICAgICAgJ2JvcmRlci1ib3R0b20nOiAnMXB4IHNvbGlkIHJnYigyMTAsIDIxMCwgMjEwKScsXG4gICAgICAgICAgJ2JhY2tncm91bmQtaW1hZ2UnOiAnLXdlYmtpdC1saW5lYXItZ3JhZGllbnQodG9wLCByZ2IoMTQ0LCAxNDQsIDE0NCksIHJnYigyMTAsIDIxMCwgMjEwKSknXG4gICAgICAgIH0sXG4gICAgICAgIGNvbnRlbnQ6IHtcbiAgICAgICAgICAnYmFja2dyb3VuZC1jb2xvcic6ICdyZ2IoMjEwLCAyMTAsIDIxMCknXG4gICAgICAgIH0sXG4gICAgICAgIHRleHRDb2xvcjoge1xuICAgICAgICAgIGNvbG9yOiAnI0ZGRidcbiAgICAgICAgfSxcbiAgICAgICAgbGluZUJvdHRvbToge1xuICAgICAgICAgICdib3JkZXItYm90dG9tJzogJzFweCBzb2xpZCAnICsgZ2V0Q29sb3IoJ3ByaW1hcnktNDAwJylcbiAgICAgICAgfVxuICAgICAgfTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBvcGVuKCkge1xuICAgICAgJG1kU2lkZW5hdignbGVmdCcpLnRvZ2dsZSgpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIE3DqXRvZG8gcXVlIGV4aWJlIG8gc3ViIG1lbnUgZG9zIGl0ZW5zIGRvIG1lbnUgbGF0ZXJhbCBjYXNvIHRlbmhhIHN1YiBpdGVuc1xuICAgICAqIGNhc28gY29udHLDoXJpbyByZWRpcmVjaW9uYSBwYXJhIG8gc3RhdGUgcGFzc2FkbyBjb21vIHBhcsODwqJtZXRyb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIG9wZW5NZW51T3JSZWRpcmVjdFRvU3RhdGUoJG1kTWVudSwgZXYsIGl0ZW0pIHtcbiAgICAgIGlmIChhbmd1bGFyLmlzRGVmaW5lZChpdGVtLnN1Ykl0ZW5zKSAmJiBpdGVtLnN1Ykl0ZW5zLmxlbmd0aCA+IDApIHtcbiAgICAgICAgJG1kTWVudS5vcGVuKGV2KTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgICRzdGF0ZS5nbyhpdGVtLnN0YXRlLCB7IG9iajogbnVsbCB9KTtcbiAgICAgICAgJG1kU2lkZW5hdignbGVmdCcpLmNsb3NlKCk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gZ2V0Q29sb3IoY29sb3JQYWxldHRlcykge1xuICAgICAgcmV0dXJuICRtZENvbG9ycy5nZXRUaGVtZUNvbG9yKGNvbG9yUGFsZXR0ZXMpO1xuICAgIH1cbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbnRyb2xsZXIoJ01haWxzQ29udHJvbGxlcicsIE1haWxzQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBNYWlsc0NvbnRyb2xsZXIoTWFpbHNTZXJ2aWNlLCBVc2Vyc1NlcnZpY2UsIFByRGlhbG9nLCBQclRvYXN0LCAvLyBOT1NPTkFSXG4gICRxLCBsb2Rhc2gsICR0cmFuc2xhdGUsIEdsb2JhbCkge1xuXG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIHZtLmZpbHRlclNlbGVjdGVkID0gZmFsc2U7XG4gICAgdm0ub3B0aW9ucyA9IHtcbiAgICAgIHNraW46ICdrYW1hJyxcbiAgICAgIGxhbmd1YWdlOiAncHQtYnInLFxuICAgICAgYWxsb3dlZENvbnRlbnQ6IHRydWUsXG4gICAgICBlbnRpdGllczogdHJ1ZSxcbiAgICAgIGhlaWdodDogMzAwLFxuICAgICAgZXh0cmFQbHVnaW5zOiAnZGlhbG9nLGZpbmQsY29sb3JkaWFsb2cscHJldmlldyxmb3JtcyxpZnJhbWUsZmxhc2gnXG4gICAgfTtcblxuICAgIHZtLmxvYWRVc2VycyA9IGxvYWRVc2VycztcbiAgICB2bS5vcGVuVXNlckRpYWxvZyA9IG9wZW5Vc2VyRGlhbG9nO1xuICAgIHZtLmFkZFVzZXJNYWlsID0gYWRkVXNlck1haWw7XG4gICAgdm0uY2xlYW5Gb3JtID0gY2xlYW5Gb3JtO1xuICAgIHZtLnNlbmQgPSBzZW5kO1xuXG4gICAgYWN0aXZhdGUoKTtcblxuICAgIGZ1bmN0aW9uIGFjdGl2YXRlKCkge1xuICAgICAgdm0uY2xlYW5Gb3JtKCk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhbGl6YSBhIGJ1c2NhIHBlbG8gdXN1w6FyaW8gcmVtb3RhbWVudGVcbiAgICAgKlxuICAgICAqIEBwYXJhbXMge3N0cmluZ30gLSBSZWNlYmUgbyB2YWxvciBwYXJhIHNlciBwZXNxdWlzYWRvXG4gICAgICogQHJldHVybiB7cHJvbWlzc2V9IC0gUmV0b3JuYSB1bWEgcHJvbWlzc2UgcXVlIG8gY29tcG9uZXRlIHJlc29sdmVcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBsb2FkVXNlcnMoY3JpdGVyaWEpIHtcbiAgICAgIHZhciBkZWZlcnJlZCA9ICRxLmRlZmVyKCk7XG5cbiAgICAgIFVzZXJzU2VydmljZS5xdWVyeSh7XG4gICAgICAgIG5hbWVPckVtYWlsOiBjcml0ZXJpYSxcbiAgICAgICAgbm90VXNlcnM6IGxvZGFzaC5tYXAodm0ubWFpbC51c2VycywgbG9kYXNoLnByb3BlcnR5KCdpZCcpKS50b1N0cmluZygpLFxuICAgICAgICBsaW1pdDogNVxuICAgICAgfSkudGhlbihmdW5jdGlvbiAoZGF0YSkge1xuXG4gICAgICAgIC8vIHZlcmlmaWNhIHNlIG5hIGxpc3RhIGRlIHVzdWFyaW9zIGrDoSBleGlzdGUgbyB1c3XDoXJpbyBjb20gbyBlbWFpbCBwZXNxdWlzYWRvXG4gICAgICAgIGRhdGEgPSBsb2Rhc2guZmlsdGVyKGRhdGEsIGZ1bmN0aW9uICh1c2VyKSB7XG4gICAgICAgICAgcmV0dXJuICFsb2Rhc2guZmluZCh2bS5tYWlsLnVzZXJzLCB7IGVtYWlsOiB1c2VyLmVtYWlsIH0pO1xuICAgICAgICB9KTtcblxuICAgICAgICBkZWZlcnJlZC5yZXNvbHZlKGRhdGEpO1xuICAgICAgfSk7XG5cbiAgICAgIHJldHVybiBkZWZlcnJlZC5wcm9taXNlO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEFicmUgbyBkaWFsb2cgcGFyYSBwZXNxdWlzYSBkZSB1c3XDoXJpb3NcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBvcGVuVXNlckRpYWxvZygpIHtcbiAgICAgIHZhciBjb25maWcgPSB7XG4gICAgICAgIGxvY2Fsczoge1xuICAgICAgICAgIG9uSW5pdDogdHJ1ZSxcbiAgICAgICAgICB1c2VyRGlhbG9nSW5wdXQ6IHtcbiAgICAgICAgICAgIHRyYW5zZmVyVXNlckZuOiB2bS5hZGRVc2VyTWFpbFxuICAgICAgICAgIH1cbiAgICAgICAgfSxcbiAgICAgICAgY29udHJvbGxlcjogJ1VzZXJzRGlhbG9nQ29udHJvbGxlcicsXG4gICAgICAgIGNvbnRyb2xsZXJBczogJ2N0cmwnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL3VzZXJzL2RpYWxvZy91c2Vycy1kaWFsb2cuaHRtbCcsXG4gICAgICAgIGhhc0JhY2tkcm9wOiB0cnVlXG4gICAgICB9O1xuXG4gICAgICBQckRpYWxvZy5jdXN0b20oY29uZmlnKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBBZGljaW9uYSBvIHVzdcOhcmlvIHNlbGVjaW9uYWRvIG5hIGxpc3RhIHBhcmEgcXVlIHNlamEgZW52aWFkbyBvIGVtYWlsXG4gICAgICovXG4gICAgZnVuY3Rpb24gYWRkVXNlck1haWwodXNlcikge1xuICAgICAgdmFyIHVzZXJzID0gbG9kYXNoLmZpbmQodm0ubWFpbC51c2VycywgeyBlbWFpbDogdXNlci5lbWFpbCB9KTtcblxuICAgICAgaWYgKHZtLm1haWwudXNlcnMubGVuZ3RoID4gMCAmJiBhbmd1bGFyLmlzRGVmaW5lZCh1c2VycykpIHtcbiAgICAgICAgUHJUb2FzdC53YXJuKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMudXNlci51c2VyRXhpc3RzJykpO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgdm0ubWFpbC51c2Vycy5wdXNoKHsgbmFtZTogdXNlci5uYW1lLCBlbWFpbDogdXNlci5lbWFpbCB9KTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFsaXphIG8gZW52aW8gZG8gZW1haWwgcGFyYSBhIGxpc3RhIGRlIHVzdcOhcmlvcyBzZWxlY2lvbmFkb3NcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBzZW5kKCkge1xuXG4gICAgICB2bS5tYWlsLiRzYXZlKCkudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgaWYgKHJlc3BvbnNlLmxlbmd0aCA+IDApIHtcbiAgICAgICAgICB2YXIgbXNnID0gJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5tYWlsLm1haWxFcnJvcnMnKTtcblxuICAgICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgcmVzcG9uc2UubGVuZ3RoOyBpKyspIHtcbiAgICAgICAgICAgIG1zZyArPSByZXNwb25zZSArICdcXG4nO1xuICAgICAgICAgIH1cbiAgICAgICAgICBQclRvYXN0LmVycm9yKG1zZyk7XG4gICAgICAgICAgdm0uY2xlYW5Gb3JtKCk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgUHJUb2FzdC5zdWNjZXNzKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMubWFpbC5zZW5kTWFpbFN1Y2Nlc3MnKSk7XG4gICAgICAgICAgdm0uY2xlYW5Gb3JtKCk7XG4gICAgICAgIH1cbiAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIExpbXBhIG8gZm9ybXVsw6FyaW8gZGUgZW1haWxcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBjbGVhbkZvcm0oKSB7XG4gICAgICB2bS5tYWlsID0gbmV3IE1haWxzU2VydmljZSgpO1xuICAgICAgdm0ubWFpbC51c2VycyA9IFtdO1xuICAgIH1cbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25maWcocm91dGVzKTtcblxuICAvKipcbiAgICogQXJxdWl2byBkZSBjb25maWd1cmHDp8OjbyBjb20gYXMgcm90YXMgZXNwZWPDrWZpY2FzIGRvIHJlY3Vyc28gZW0gcXVlc3TDo29cbiAgICpcbiAgICogQHBhcmFtIHthbnl9ICRzdGF0ZVByb3ZpZGVyXG4gICAqIEBwYXJhbSB7YW55fSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnYXBwLm1haWwnLCB7XG4gICAgICB1cmw6ICcvZW1haWwnLFxuICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9tYWlsL21haWxzLXNlbmQuaHRtbCcsXG4gICAgICBjb250cm9sbGVyOiAnTWFpbHNDb250cm9sbGVyIGFzIG1haWxzQ3RybCcsXG4gICAgICBkYXRhOiB7IG5lZWRBdXRoZW50aWNhdGlvbjogdHJ1ZSwgbmVlZFByb2ZpbGU6IFsnYWRtaW4nXSB9XG4gICAgfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmFjdG9yeSgnTWFpbHNTZXJ2aWNlJywgTWFpbHNTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIE1haWxzU2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHJldHVybiBzZXJ2aWNlRmFjdG9yeSgnbWFpbHMnLCB7fSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb250cm9sbGVyKCdNaWxlc3RvbmVzQ29udHJvbGxlcicsIE1pbGVzdG9uZXNDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIE1pbGVzdG9uZXNDb250cm9sbGVyKCRjb250cm9sbGVyLCBNaWxlc3RvbmVzU2VydmljZSwgbW9tZW50LCBUYXNrc1NlcnZpY2UsIFByVG9hc3QsICR0cmFuc2xhdGUsICRtZERpYWxvZywgQXV0aCkge1xuXG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIHZtLmVzdGltYXRlZFByaWNlID0gZXN0aW1hdGVkUHJpY2U7XG5cbiAgICB2bS5vbkFjdGl2YXRlID0gZnVuY3Rpb24gKCkge1xuICAgICAgdm0uY3VycmVudFVzZXIgPSBBdXRoLmN1cnJlbnRVc2VyO1xuICAgICAgdm0ucHJvamVjdCA9IGxvY2FsU3RvcmFnZS5nZXRJdGVtKCdwcm9qZWN0Jyk7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMgPSB7IHByb2plY3RfaWQ6IHZtLnByb2plY3QgfTtcbiAgICB9O1xuXG4gICAgZnVuY3Rpb24gZXN0aW1hdGVkUHJpY2UobWlsZXN0b25lKSB7XG4gICAgICBtaWxlc3RvbmUuZXN0aW1hdGVkX3ZhbHVlID0gMDtcbiAgICAgIGlmIChtaWxlc3RvbmUudGFza3MubGVuZ3RoID4gMCAmJiBtaWxlc3RvbmUucHJvamVjdC5ob3VyX3ZhbHVlX2ZpbmFsKSB7XG4gICAgICAgIG1pbGVzdG9uZS50YXNrcy5mb3JFYWNoKGZ1bmN0aW9uICh0YXNrKSB7XG4gICAgICAgICAgbWlsZXN0b25lLmVzdGltYXRlZF92YWx1ZSArPSBwYXJzZUZsb2F0KG1pbGVzdG9uZS5wcm9qZWN0LmhvdXJfdmFsdWVfZmluYWwpICogdGFzay5lc3RpbWF0ZWRfdGltZTtcbiAgICAgICAgfSk7XG4gICAgICB9XG4gICAgICByZXR1cm4gbWlsZXN0b25lLmVzdGltYXRlZF92YWx1ZS50b0xvY2FsZVN0cmluZygnUHQtYnInLCB7IG1pbmltdW1GcmFjdGlvbkRpZ2l0czogMiB9KTtcbiAgICB9XG5cbiAgICB2bS5lc3RpbWF0ZWRUaW1lID0gZnVuY3Rpb24gKG1pbGVzdG9uZSkge1xuICAgICAgbWlsZXN0b25lLmVzdGltYXRlZF90aW1lID0gMDtcbiAgICAgIGlmIChtaWxlc3RvbmUudGFza3MubGVuZ3RoID4gMCkge1xuICAgICAgICBtaWxlc3RvbmUudGFza3MuZm9yRWFjaChmdW5jdGlvbiAodGFzaykge1xuICAgICAgICAgIG1pbGVzdG9uZS5lc3RpbWF0ZWRfdGltZSArPSB0YXNrLmVzdGltYXRlZF90aW1lO1xuICAgICAgICB9KTtcbiAgICAgIH1cbiAgICAgIG1pbGVzdG9uZS5lc3RpbWF0ZWRfdGltZSA9IG1pbGVzdG9uZS5lc3RpbWF0ZWRfdGltZSAvIDg7XG4gICAgICB2YXIgZGF0ZUVuZCA9IG1vbWVudChtaWxlc3RvbmUuZGF0ZV9lbmQpO1xuICAgICAgdmFyIGRhdGVCZWdpbiA9IG1vbWVudChtaWxlc3RvbmUuZGF0ZV9iZWdpbik7XG5cbiAgICAgIGlmIChkYXRlRW5kLmRpZmYoZGF0ZUJlZ2luLCAnZGF5cycpIDw9IG1pbGVzdG9uZS5lc3RpbWF0ZWRfdGltZSkge1xuICAgICAgICBtaWxlc3RvbmUuY29sb3JfZXN0aW1hdGVkX3RpbWUgPSB7IGNvbG9yOiAncmVkJyB9O1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgbWlsZXN0b25lLmNvbG9yX2VzdGltYXRlZF90aW1lID0geyBjb2xvcjogJ2dyZWVuJyB9O1xuICAgICAgfVxuICAgICAgcmV0dXJuIG1pbGVzdG9uZS5lc3RpbWF0ZWRfdGltZTtcbiAgICB9O1xuXG4gICAgdm0uYXBwbHlGaWx0ZXJzID0gZnVuY3Rpb24gKGRlZmF1bHRRdWVyeUZpbHRlcnMpIHtcbiAgICAgIHJldHVybiBhbmd1bGFyLmV4dGVuZChkZWZhdWx0UXVlcnlGaWx0ZXJzLCB2bS5xdWVyeUZpbHRlcnMpO1xuICAgIH07XG5cbiAgICB2bS5iZWZvcmVTYXZlID0gZnVuY3Rpb24gKCkge1xuICAgICAgdm0ucmVzb3VyY2UucHJvamVjdF9pZCA9IHZtLnByb2plY3Q7XG4gICAgfTtcblxuICAgIHZtLmJlZm9yZVJlbW92ZSA9IGZ1bmN0aW9uICgpIHtcbiAgICAgIHZtLnJlc291cmNlLnByb2plY3RfaWQgPSB2bS5wcm9qZWN0O1xuICAgIH07XG5cbiAgICB2bS5mb3JtYXREYXRlID0gZnVuY3Rpb24gKGRhdGUpIHtcbiAgICAgIHJldHVybiBtb21lbnQoZGF0ZSkuZm9ybWF0KCdERC9NTS9ZWVlZJyk7XG4gICAgfTtcblxuICAgIHZtLmFmdGVyRWRpdCA9IGZ1bmN0aW9uICgpIHtcbiAgICAgIHZtLnJlc291cmNlLmRhdGVfYmVnaW4gPSBtb21lbnQodm0ucmVzb3VyY2UuZGF0ZV9iZWdpbik7XG4gICAgICB2bS5yZXNvdXJjZS5kYXRlX2VuZCA9IG1vbWVudCh2bS5yZXNvdXJjZS5kYXRlX2VuZCk7XG4gICAgfTtcblxuICAgIHZtLnZpZXcgPSBmdW5jdGlvbiAocmVzb3VyY2UpIHtcbiAgICAgIHZtLnJlc291cmNlID0gcmVzb3VyY2U7XG4gICAgICB2bS5vblZpZXcgPSB0cnVlO1xuICAgICAgdm0udmlld0Zvcm0gPSBmYWxzZTtcbiAgICAgIGNvbnNvbGUubG9nKHJlc291cmNlLnByb2plY3QpO1xuICAgIH07XG5cbiAgICB2bS5zZWFyY2hUYXNrID0gZnVuY3Rpb24gKHRhc2tUZXJtKSB7XG4gICAgICByZXR1cm4gVGFza3NTZXJ2aWNlLnF1ZXJ5KHtcbiAgICAgICAgbWlsZXN0b25lU2VhcmNoOiB0cnVlLFxuICAgICAgICBwcm9qZWN0X2lkOiB2bS5yZXNvdXJjZS5wcm9qZWN0X2lkLFxuICAgICAgICB0aXRsZTogdGFza1Rlcm1cbiAgICAgIH0pO1xuICAgIH07XG5cbiAgICB2bS5vblRhc2tDaGFuZ2UgPSBmdW5jdGlvbiAoKSB7XG4gICAgICBpZiAodm0udGFzayAhPT0gbnVsbCAmJiB2bS5yZXNvdXJjZS50YXNrcy5maW5kSW5kZXgoZnVuY3Rpb24gKGkpIHtcbiAgICAgICAgcmV0dXJuIGkuaWQgPT09IHZtLnRhc2suaWQ7XG4gICAgICB9KSA9PT0gLTEpIHtcbiAgICAgICAgdm0ucmVzb3VyY2UudGFza3MucHVzaCh2bS50YXNrKTtcbiAgICAgIH1cbiAgICB9O1xuXG4gICAgdm0ucmVtb3ZlVGFzayA9IGZ1bmN0aW9uICh0YXNrKSB7XG4gICAgICB2bS5yZXNvdXJjZS50YXNrcy5zbGljZSgwKS5mb3JFYWNoKGZ1bmN0aW9uIChlbGVtZW50KSB7XG4gICAgICAgIGlmIChlbGVtZW50LmlkID09PSB0YXNrLmlkKSB7XG4gICAgICAgICAgdm0ucmVzb3VyY2UudGFza3Muc3BsaWNlKHZtLnJlc291cmNlLnRhc2tzLmluZGV4T2YoZWxlbWVudCksIDEpO1xuICAgICAgICB9XG4gICAgICB9KTtcbiAgICB9O1xuXG4gICAgdm0uc2F2ZVRhc2tzID0gZnVuY3Rpb24gKCkge1xuICAgICAgVGFza3NTZXJ2aWNlLnVwZGF0ZU1pbGVzdG9uZSh7IHByb2plY3RfaWQ6IHZtLnJlc291cmNlLnByb2plY3RfaWQsIG1pbGVzdG9uZV9pZDogdm0ucmVzb3VyY2UuaWQsIHRhc2tzOiB2bS5yZXNvdXJjZS50YXNrcyB9KS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgUHJUb2FzdC5zdWNjZXNzKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMuc2F2ZVN1Y2Nlc3MnKSk7XG4gICAgICAgIHZtLnZpZXdGb3JtID0gZmFsc2U7XG4gICAgICAgIHZtLm9uVmlldyA9IGZhbHNlO1xuICAgICAgfSwgZnVuY3Rpb24gKCkge1xuICAgICAgICBQclRvYXN0LmVycm9yKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMub3BlcmF0aW9uRXJyb3InKSk7XG4gICAgICB9KTtcbiAgICB9O1xuXG4gICAgdm0uZmluYWxpemUgPSBmdW5jdGlvbiAobWlsZXN0b25lKSB7XG4gICAgICB2YXIgY29uZmlybSA9ICRtZERpYWxvZy5jb25maXJtKCkudGl0bGUoJ0ZpbmFsaXphciBTcHJpbnQnKS50ZXh0Q29udGVudCgnVGVtIGNlcnRlemEgcXVlIGRlc2VqYSBmaW5hbGl6YXIgYSBzcHJpbnQgJyArIG1pbGVzdG9uZS50aXRsZSArICc/Jykub2soJ1NpbScpLmNhbmNlbCgnTsOjbycpO1xuXG4gICAgICAkbWREaWFsb2cuc2hvdyhjb25maXJtKS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgTWlsZXN0b25lc1NlcnZpY2UuZmluYWxpemUoeyBwcm9qZWN0X2lkOiB2bS5wcm9qZWN0LCBtaWxlc3RvbmVfaWQ6IG1pbGVzdG9uZS5pZCB9KS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICBQclRvYXN0LnN1Y2Nlc3MoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5zcHJpbnRFbmRlZFN1Y2Nlc3MnKSk7XG4gICAgICAgICAgdm0uc2VhcmNoKCk7XG4gICAgICAgIH0sIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICBQclRvYXN0LkVycm9yKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMuc3ByaW50RW5kZWRFcnJvcicpKTtcbiAgICAgICAgfSk7XG4gICAgICB9KTtcbiAgICB9O1xuXG4gICAgLy8gaW5zdGFudGlhdGUgYmFzZSBjb250cm9sbGVyXG4gICAgJGNvbnRyb2xsZXIoJ0NSVURDb250cm9sbGVyJywgeyB2bTogdm0sIG1vZGVsU2VydmljZTogTWlsZXN0b25lc1NlcnZpY2UsIG9wdGlvbnM6IHt9IH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKlxuICAgKiBBcnF1aXZvIGRlIGNvbmZpZ3VyYcOnw6NvIGNvbSBhcyByb3RhcyBlc3BlY8OtZmljYXMgZG8gcmVjdXJzbyBtaWxlc3RvbmVzXG4gICAqXG4gICAqIEBwYXJhbSB7b2JqZWN0fSAkc3RhdGVQcm92aWRlclxuICAgKiBAcGFyYW0ge29iamVjdH0gR2xvYmFsXG4gICAqL1xuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvdXRlcygkc3RhdGVQcm92aWRlciwgR2xvYmFsKSB7XG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ2FwcC5taWxlc3RvbmVzJywge1xuICAgICAgdXJsOiAnL21pbGVzdG9uZXMnLFxuICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9taWxlc3RvbmVzL21pbGVzdG9uZXMuaHRtbCcsXG4gICAgICBjb250cm9sbGVyOiAnTWlsZXN0b25lc0NvbnRyb2xsZXIgYXMgbWlsZXN0b25lc0N0cmwnLFxuICAgICAgZGF0YToge31cbiAgICB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5mYWN0b3J5KCdNaWxlc3RvbmVzU2VydmljZScsIE1pbGVzdG9uZXNTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIE1pbGVzdG9uZXNTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgdmFyIG1vZGVsID0gc2VydmljZUZhY3RvcnkoJ21pbGVzdG9uZXMnLCB7XG4gICAgICBhY3Rpb25zOiB7XG4gICAgICAgIGZpbmFsaXplOiB7XG4gICAgICAgICAgbWV0aG9kOiAnUE9TVCcsXG4gICAgICAgICAgdXJsOiAnZmluYWxpemUnXG4gICAgICAgIH0sXG4gICAgICAgIHVwZGF0ZVJlbGVhc2U6IHtcbiAgICAgICAgICBtZXRob2Q6ICdQT1NUJyxcbiAgICAgICAgICB1cmw6ICd1cGRhdGVSZWxlYXNlJ1xuICAgICAgICB9XG4gICAgICB9LFxuICAgICAgaW5zdGFuY2U6IHt9XG4gICAgfSk7XG5cbiAgICByZXR1cm4gbW9kZWw7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmFjdG9yeSgnUHJpb3JpdGllc1NlcnZpY2UnLCBQcmlvcml0aWVzU2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiBQcmlvcml0aWVzU2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHZhciBtb2RlbCA9IHNlcnZpY2VGYWN0b3J5KCdwcmlvcml0aWVzJywge1xuICAgICAgYWN0aW9uczoge30sXG4gICAgICBpbnN0YW5jZToge31cbiAgICB9KTtcblxuICAgIHJldHVybiBtb2RlbDtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbnRyb2xsZXIoJ1Byb2plY3RzQ29udHJvbGxlcicsIFByb2plY3RzQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBQcm9qZWN0c0NvbnRyb2xsZXIoJGNvbnRyb2xsZXIsIFByb2plY3RzU2VydmljZSwgQXV0aCwgUm9sZXNTZXJ2aWNlLCBVc2Vyc1NlcnZpY2UsICRzdGF0ZSwgJGZpbHRlciwgJHN0YXRlUGFyYW1zLCAkd2luZG93KSB7XG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIC8vQXR0cmlidXRlcyBCbG9ja1xuXG4gICAgLy9GdW5jdGlvbnMgQmxvY2tcbiAgICB2bS5vbkFjdGl2YXRlID0gb25BY3RpdmF0ZTtcbiAgICB2bS5hcHBseUZpbHRlcnMgPSBhcHBseUZpbHRlcnM7XG4gICAgdm0uYmVmb3JlU2F2ZSA9IGJlZm9yZVNhdmU7XG4gICAgdm0uc2VhcmNoVXNlciA9IHNlYXJjaFVzZXI7XG4gICAgdm0uYWRkVXNlciA9IGFkZFVzZXI7XG4gICAgdm0ucmVtb3ZlVXNlciA9IHJlbW92ZVVzZXI7XG4gICAgdm0udmlld1Byb2plY3QgPSB2aWV3UHJvamVjdDtcblxuICAgIHZtLnJvbGVzID0ge307XG4gICAgdm0udXNlcnMgPSBbXTtcblxuICAgIGZ1bmN0aW9uIG9uQWN0aXZhdGUoKSB7XG4gICAgICB2bS5jdXJyZW50VXNlciA9IEF1dGguY3VycmVudFVzZXI7XG4gICAgICBSb2xlc1NlcnZpY2UucXVlcnkoKS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICB2bS5yb2xlcyA9IHJlc3BvbnNlO1xuICAgICAgICAvL3ZtLnJvbGVzID0gJGZpbHRlcignZmlsdGVyJykodm0ucm9sZXMsIHsgc2x1ZzogJ2NsaWVudCcgfSk7XG4gICAgICAgIGlmICgkc3RhdGVQYXJhbXMub2JqID09PSAnZWRpdCcpIHtcbiAgICAgICAgICB2bS5jbGVhbkZvcm0oKTtcbiAgICAgICAgICB2bS52aWV3Rm9ybSA9IHRydWU7XG4gICAgICAgICAgdm0ucmVzb3VyY2UgPSAkc3RhdGVQYXJhbXMucmVzb3VyY2U7XG4gICAgICAgICAgdXNlcnNBcnJheSh2bS5yZXNvdXJjZSk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oJ3Byb2plY3QnKTtcbiAgICAgICAgICB2bS5xdWVyeUZpbHRlcnMgPSB7IHVzZXJfaWQ6IHZtLmN1cnJlbnRVc2VyLmlkIH07XG4gICAgICAgIH1cbiAgICAgIH0pO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGFwcGx5RmlsdGVycyhkZWZhdWx0UXVlcnlGaWx0ZXJzKSB7XG4gICAgICByZXR1cm4gYW5ndWxhci5leHRlbmQoZGVmYXVsdFF1ZXJ5RmlsdGVycywgdm0ucXVlcnlsdGVycyk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gYmVmb3JlU2F2ZSgpIHtcbiAgICAgIHZtLnJlc291cmNlLm93bmVyID0gQXV0aC5jdXJyZW50VXNlci5pZDtcbiAgICAgIHZtLnJlc291cmNlLnVzZXJfaWQgPSBBdXRoLmN1cnJlbnRVc2VyLmlkO1xuICAgICAgdm0ucmVzb3VyY2UuZGV2X2lkID0gQXV0aC5jdXJyZW50VXNlci5pZDtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBzZWFyY2hVc2VyKCkge1xuICAgICAgcmV0dXJuIFVzZXJzU2VydmljZS5xdWVyeSh7IG5hbWU6IHZtLnVzZXJOYW1lIH0pO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGFkZFVzZXIodXNlcikge1xuICAgICAgaWYgKHVzZXIpIHtcbiAgICAgICAgdm0ucmVzb3VyY2UudXNlcnMucHVzaCh1c2VyKTtcbiAgICAgICAgdm0udXNlck5hbWUgPSAnJztcbiAgICAgIH1cbiAgICB9XG5cbiAgICBmdW5jdGlvbiByZW1vdmVVc2VyKGluZGV4KSB7XG4gICAgICB2bS5yZXNvdXJjZS51c2Vycy5zcGxpY2UoaW5kZXgsIDEpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGFwcGx5RmlsdGVycyhkZWZhdWx0UXVlcnlGaWx0ZXJzKSB7XG4gICAgICByZXR1cm4gYW5ndWxhci5leHRlbmQoZGVmYXVsdFF1ZXJ5RmlsdGVycywgdm0ucXVlcnlGaWx0ZXJzKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiB2aWV3UHJvamVjdCgpIHtcbiAgICAgICRzdGF0ZS5nbygnYXBwLmRhc2hib2FyZCcpO1xuICAgIH1cblxuICAgIHZtLmFmdGVyU2VhcmNoID0gZnVuY3Rpb24gKCkge1xuICAgICAgaWYgKHZtLnJlc291cmNlcy5sZW5ndGggPiAwKSB7XG4gICAgICAgIHZtLnJlc291cmNlcy5mb3JFYWNoKGZ1bmN0aW9uIChwcm9qZWN0KSB7XG4gICAgICAgICAgdXNlcnNBcnJheShwcm9qZWN0KTtcbiAgICAgICAgfSk7XG4gICAgICB9XG4gICAgfTtcblxuICAgIGZ1bmN0aW9uIHVzZXJzQXJyYXkocHJvamVjdCkge1xuICAgICAgcHJvamVjdC51c2VycyA9IFtdO1xuICAgICAgaWYgKHByb2plY3QuY2xpZW50X2lkKSB7XG4gICAgICAgIHByb2plY3QuY2xpZW50LnJvbGUgPSAkZmlsdGVyKCdmaWx0ZXInKSh2bS5yb2xlcywgeyBzbHVnOiAnY2xpZW50JyB9KVswXTtcbiAgICAgICAgcHJvamVjdC51c2Vycy5wdXNoKHByb2plY3QuY2xpZW50KTtcbiAgICAgIH1cbiAgICAgIGlmIChwcm9qZWN0LmRldl9pZCkge1xuICAgICAgICBwcm9qZWN0LmRldmVsb3Blci5yb2xlID0gJGZpbHRlcignZmlsdGVyJykodm0ucm9sZXMsIHsgc2x1ZzogJ2RldicgfSlbMF07XG4gICAgICAgIHByb2plY3QudXNlcnMucHVzaChwcm9qZWN0LmRldmVsb3Blcik7XG4gICAgICB9XG4gICAgICBpZiAocHJvamVjdC5zdGFrZWhvbGRlcl9pZCkge1xuICAgICAgICBwcm9qZWN0LnN0YWtlaG9sZGVyLnJvbGUgPSAkZmlsdGVyKCdmaWx0ZXInKSh2bS5yb2xlcywgeyBzbHVnOiAnc3Rha2Vob2xkZXInIH0pWzBdO1xuICAgICAgICBwcm9qZWN0LnVzZXJzLnB1c2gocHJvamVjdC5zdGFrZWhvbGRlcik7XG4gICAgICB9XG4gICAgfVxuXG4gICAgdm0uaGlzdG9yeUJhY2sgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAkd2luZG93Lmhpc3RvcnkuYmFjaygpO1xuICAgIH07XG5cbiAgICB2bS5hZnRlclNhdmUgPSBmdW5jdGlvbiAocmVzb3VyY2UpIHtcbiAgICAgIGxvY2FsU3RvcmFnZS5zZXRJdGVtKCdwcm9qZWN0JywgcmVzb3VyY2UuaWQpO1xuICAgICAgJHN0YXRlLmdvKCdhcHAuZGFzaGJvYXJkJyk7XG4gICAgfTtcblxuICAgIC8vIGluc3RhbnRpYXRlIGJhc2UgY29udHJvbGxlclxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHsgdm06IHZtLCBtb2RlbFNlcnZpY2U6IFByb2plY3RzU2VydmljZSwgb3B0aW9uczogeyByZWRpcmVjdEFmdGVyU2F2ZTogZmFsc2UgfSB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25maWcocm91dGVzKTtcblxuICAvKipcbiAgICogQXJxdWl2byBkZSBjb25maWd1cmHDp8OjbyBjb20gYXMgcm90YXMgZXNwZWPDrWZpY2FzIGRvIHJlY3Vyc28gcHJvamVjdFxuICAgKlxuICAgKiBAcGFyYW0ge2FueX0gJHN0YXRlUHJvdmlkZXJcbiAgICogQHBhcmFtIHthbnl9IEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdhcHAucHJvamVjdHMnLCB7XG4gICAgICB1cmw6ICcvcHJvamVjdHMnLFxuICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9wcm9qZWN0cy9wcm9qZWN0cy5odG1sJyxcbiAgICAgIGNvbnRyb2xsZXI6ICdQcm9qZWN0c0NvbnRyb2xsZXIgYXMgcHJvamVjdHNDdHJsJyxcbiAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiB0cnVlIH0sXG4gICAgICBwYXJhbXM6IHsgb2JqOiBudWxsLCByZXNvdXJjZTogbnVsbCB9XG4gICAgfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmFjdG9yeSgnUHJvamVjdHNTZXJ2aWNlJywgUHJvamVjdHNTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIFByb2plY3RzU2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHJldHVybiBzZXJ2aWNlRmFjdG9yeSgncHJvamVjdHMnLCB7XG4gICAgICBhY3Rpb25zOiB7XG4gICAgICAgIGZpbmFsaXplOiB7XG4gICAgICAgICAgbWV0aG9kOiAnUE9TVCcsXG4gICAgICAgICAgdXJsOiAnZmluYWxpemUnXG4gICAgICAgIH0gfSxcbiAgICAgIGluc3RhbmNlOiB7fVxuICAgIH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29udHJvbGxlcignUmVsZWFzZXNDb250cm9sbGVyJywgUmVsZWFzZXNDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIFJlbGVhc2VzQ29udHJvbGxlcigkY29udHJvbGxlciwgUmVsZWFzZXNTZXJ2aWNlLCBNaWxlc3RvbmVzU2VydmljZSwgQXV0aCwgUHJUb2FzdCwgbW9tZW50LCAkbWREaWFsb2csICR0cmFuc2xhdGUpIHtcbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgLy9BdHRyaWJ1dGVzIEJsb2NrXG5cbiAgICAvL0Z1bmN0aW9ucyBCbG9ja1xuICAgIHZtLm9uQWN0aXZhdGUgPSBmdW5jdGlvbiAoKSB7XG4gICAgICB2bS5jdXJyZW50VXNlciA9IEF1dGguY3V1cnJlbnRVc2VyO1xuICAgICAgdm0ucHJvamVjdCA9IGxvY2FsU3RvcmFnZS5nZXRJdGVtKCdwcm9qZWN0Jyk7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMgPSB7IHByb2plY3RfaWQ6IHZtLnByb2plY3QgfTtcbiAgICB9O1xuXG4gICAgdm0uYmVmb3JlU2F2ZSA9IGZ1bmN0aW9uICgpIHtcbiAgICAgIHZtLnJlc291cmNlLnByb2plY3RfaWQgPSB2bS5wcm9qZWN0O1xuICAgIH07XG5cbiAgICB2bS5iZWZvcmVSZW1vdmUgPSBmdW5jdGlvbiAoKSB7XG4gICAgICB2bS5yZXNvdXJjZS5wcm9qZWN0X2lkID0gdm0ucHJvamVjdDtcbiAgICB9O1xuXG4gICAgdm0udmlldyA9IGZ1bmN0aW9uIChyZXNvdXJjZSkge1xuICAgICAgdm0ucmVzb3VyY2UgPSByZXNvdXJjZTtcbiAgICAgIHZtLm9uVmlldyA9IHRydWU7XG4gICAgICB2bS52aWV3Rm9ybSA9IGZhbHNlO1xuICAgIH07XG5cbiAgICB2bS5maW5hbGl6ZSA9IGZ1bmN0aW9uIChyZWxlYXNlKSB7XG4gICAgICB2YXIgY29uZmlybSA9ICRtZERpYWxvZy5jb25maXJtKCkudGl0bGUoJ0ZpbmFsaXphciBSZWxlYXNlJykudGV4dENvbnRlbnQoJ1RlbSBjZXJ0ZXphIHF1ZSBkZXNlamEgZmluYWxpemFyIGEgcmVsZWFzZSAnICsgcmVsZWFzZS50aXRsZSArICc/Jykub2soJ1NpbScpLmNhbmNlbCgnTsOjbycpO1xuXG4gICAgICAkbWREaWFsb2cuc2hvdyhjb25maXJtKS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgUmVsZWFzZXNTZXJ2aWNlLmZpbmFsaXplKHsgcHJvamVjdF9pZDogdm0ucHJvamVjdCwgcmVsZWFzZV9pZDogcmVsZWFzZS5pZCB9KS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICBQclRvYXN0LnN1Y2Nlc3MoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5yZWxlYXNlRW5kZWRTdWNjZXNzJykpO1xuICAgICAgICAgIHZtLnNlYXJjaCgpO1xuICAgICAgICB9LCBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgUHJUb2FzdC5FcnJvcigkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnJlbGVhc2VFbmRlZEVycm9yJykpO1xuICAgICAgICB9KTtcbiAgICAgIH0pO1xuICAgIH07XG5cbiAgICB2bS5mb3JtYXREYXRlID0gZnVuY3Rpb24gKGRhdGUpIHtcbiAgICAgIHJldHVybiBtb21lbnQoZGF0ZSkuZm9ybWF0KCdERC9NTS9ZWVlZJyk7XG4gICAgfTtcblxuICAgIHZtLnNlYXJjaE1pbGVzdG9uZSA9IGZ1bmN0aW9uIChtaWxlc3RvbmVUZXJtKSB7XG4gICAgICByZXR1cm4gTWlsZXN0b25lc1NlcnZpY2UucXVlcnkoe1xuICAgICAgICByZWxlYXNlU2VhcmNoOiB0cnVlLFxuICAgICAgICBwcm9qZWN0X2lkOiB2bS5yZXNvdXJjZS5wcm9qZWN0X2lkLFxuICAgICAgICB0aXRsZTogbWlsZXN0b25lVGVybVxuICAgICAgfSk7XG4gICAgfTtcblxuICAgIHZtLm9uTWlsZXN0b25lQ2hhbmdlID0gZnVuY3Rpb24gKCkge1xuICAgICAgaWYgKHZtLm1pbGVzdG9uZSAhPT0gbnVsbCAmJiB2bS5yZXNvdXJjZS5taWxlc3RvbmVzLmZpbmRJbmRleChmdW5jdGlvbiAoaSkge1xuICAgICAgICByZXR1cm4gaS5pZCA9PT0gdm0ubWlsZXN0b25lLmlkO1xuICAgICAgfSkgPT09IC0xKSB7XG4gICAgICAgIHZtLnJlc291cmNlLm1pbGVzdG9uZXMucHVzaCh2bS5taWxlc3RvbmUpO1xuICAgICAgfVxuICAgIH07XG5cbiAgICB2bS5yZW1vdmVNaWxlc3RvbmUgPSBmdW5jdGlvbiAobWlsZXN0b25lKSB7XG4gICAgICB2bS5yZXNvdXJjZS5taWxlc3RvbmVzLnNsaWNlKDApLmZvckVhY2goZnVuY3Rpb24gKGVsZW1lbnQpIHtcbiAgICAgICAgaWYgKGVsZW1lbnQuaWQgPT09IG1pbGVzdG9uZS5pZCkge1xuICAgICAgICAgIHZtLnJlc291cmNlLm1pbGVzdG9uZXMuc3BsaWNlKHZtLnJlc291cmNlLm1pbGVzdG9uZXMuaW5kZXhPZihlbGVtZW50KSwgMSk7XG4gICAgICAgIH1cbiAgICAgIH0pO1xuICAgIH07XG5cbiAgICB2bS5zYXZlTWlsZXN0b25lcyA9IGZ1bmN0aW9uICgpIHtcbiAgICAgIE1pbGVzdG9uZXNTZXJ2aWNlLnVwZGF0ZVJlbGVhc2UoeyBwcm9qZWN0X2lkOiB2bS5yZXNvdXJjZS5wcm9qZWN0X2lkLCByZWxlYXNlX2lkOiB2bS5yZXNvdXJjZS5pZCwgbWlsZXN0b25lczogdm0ucmVzb3VyY2UubWlsZXN0b25lcyB9KS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgUHJUb2FzdC5zdWNjZXNzKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMuc2F2ZVN1Y2Nlc3MnKSk7XG4gICAgICAgIHZtLnZpZXdGb3JtID0gZmFsc2U7XG4gICAgICAgIHZtLm9uVmlldyA9IGZhbHNlO1xuICAgICAgfSwgZnVuY3Rpb24gKCkge1xuICAgICAgICBQclRvYXN0LmVycm9yKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMub3BlcmF0aW9uRXJyb3InKSk7XG4gICAgICB9KTtcbiAgICB9O1xuXG4gICAgdm0uZXN0aW1hdGVkVGltZSA9IGZ1bmN0aW9uIChtaWxlc3RvbmUpIHtcbiAgICAgIG1pbGVzdG9uZS5lc3RpbWF0ZWRfdGltZSA9IDA7XG4gICAgICBpZiAobWlsZXN0b25lLnRhc2tzLmxlbmd0aCA+IDApIHtcbiAgICAgICAgbWlsZXN0b25lLnRhc2tzLmZvckVhY2goZnVuY3Rpb24gKHRhc2spIHtcbiAgICAgICAgICBtaWxlc3RvbmUuZXN0aW1hdGVkX3RpbWUgKz0gdGFzay5lc3RpbWF0ZWRfdGltZTtcbiAgICAgICAgfSk7XG4gICAgICB9XG4gICAgICByZXR1cm4gbWlsZXN0b25lLmVzdGltYXRlZF90aW1lIC8gODtcbiAgICB9O1xuXG4gICAgLy8gaW5zdGFudGlhdGUgYmFzZSBjb250cm9sbGVyXG4gICAgJGNvbnRyb2xsZXIoJ0NSVURDb250cm9sbGVyJywgeyB2bTogdm0sIG1vZGVsU2VydmljZTogUmVsZWFzZXNTZXJ2aWNlLCBvcHRpb25zOiB7fSB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25maWcocm91dGVzKTtcblxuICAvKipcbiAgICogQXJxdWl2byBkZSBjb25maWd1cmHDp8OjbyBjb20gYXMgcm90YXMgZXNwZWPDrWZpY2FzIGRvIHJlY3Vyc28gcmVsZWFzZXNcbiAgICpcbiAgICogQHBhcmFtIHtvYmplY3R9ICRzdGF0ZVByb3ZpZGVyXG4gICAqIEBwYXJhbSB7b2JqZWN0fSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnYXBwLnJlbGVhc2VzJywge1xuICAgICAgdXJsOiAnL3JlbGVhc2VzJyxcbiAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvcmVsZWFzZXMvcmVsZWFzZXMuaHRtbCcsXG4gICAgICBjb250cm9sbGVyOiAnUmVsZWFzZXNDb250cm9sbGVyIGFzIHJlbGVhc2VzQ3RybCcsXG4gICAgICBkYXRhOiB7fVxuICAgIH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZhY3RvcnkoJ1JlbGVhc2VzU2VydmljZScsIFJlbGVhc2VzU2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiBSZWxlYXNlc1NlcnZpY2Uoc2VydmljZUZhY3RvcnkpIHtcbiAgICB2YXIgbW9kZWwgPSBzZXJ2aWNlRmFjdG9yeSgncmVsZWFzZXMnLCB7XG4gICAgICBhY3Rpb25zOiB7XG4gICAgICAgIGZpbmFsaXplOiB7XG4gICAgICAgICAgbWV0aG9kOiAnUE9TVCcsXG4gICAgICAgICAgdXJsOiAnZmluYWxpemUnXG4gICAgICAgIH1cbiAgICAgIH0sXG4gICAgICBpbnN0YW5jZToge31cbiAgICB9KTtcblxuICAgIHJldHVybiBtb2RlbDtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZpbHRlcigncm9sZXNTdHInLCByb2xlc1N0cik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb2xlc1N0cihsb2Rhc2gpIHtcbiAgICAvKipcbiAgICAgKiBAcGFyYW0ge2FycmF5fSByb2xlcyBsaXN0YSBkZSBwZXJmaXNcbiAgICAgKiBAcmV0dXJuIHtzdHJpbmd9IHBlcmZpcyBzZXBhcmFkb3MgcG9yICcsICcgIFxuICAgICAqL1xuICAgIHJldHVybiBmdW5jdGlvbiAocm9sZXMpIHtcbiAgICAgIHJldHVybiBsb2Rhc2gubWFwKHJvbGVzLCAnc2x1ZycpLmpvaW4oJywgJyk7XG4gICAgfTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5mYWN0b3J5KCdSb2xlc1NlcnZpY2UnLCBSb2xlc1NlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gUm9sZXNTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCdyb2xlcycpO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZhY3RvcnkoJ1N0YXR1c1NlcnZpY2UnLCBTdGF0dXNTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIFN0YXR1c1NlcnZpY2Uoc2VydmljZUZhY3RvcnkpIHtcbiAgICB2YXIgbW9kZWwgPSBzZXJ2aWNlRmFjdG9yeSgnc3RhdHVzJywge1xuICAgICAgYWN0aW9uczoge30sXG4gICAgICBpbnN0YW5jZToge31cbiAgICB9KTtcblxuICAgIHJldHVybiBtb2RlbDtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5mYWN0b3J5KCdTdXBwb3J0U2VydmljZScsIFN1cHBvcnRTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIFN1cHBvcnRTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCdzdXBwb3J0Jywge1xuICAgICAgYWN0aW9uczoge1xuICAgICAgICAvKipcbiAgICAgICAgICogUGVnYSBhcyB0cmFkdcOnw7VlcyBxdWUgZXN0w6NvIG5vIHNlcnZpZG9yXG4gICAgICAgICAqXG4gICAgICAgICAqIEByZXR1cm5zIHtwcm9taXNlfSBVbWEgcHJvbWlzZSBjb20gbyByZXN1bHRhZG8gZG8gY2hhbWFkYSBubyBiYWNrZW5kXG4gICAgICAgICAqL1xuICAgICAgICBsYW5nczoge1xuICAgICAgICAgIG1ldGhvZDogJ0dFVCcsXG4gICAgICAgICAgdXJsOiAnbGFuZ3MnLFxuICAgICAgICAgIHdyYXA6IGZhbHNlLFxuICAgICAgICAgIGNhY2hlOiB0cnVlXG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5mYWN0b3J5KCdUYXNrQ29tbWVudHNTZXJ2aWNlJywgVGFza0NvbW1lbnRzU2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiBUYXNrQ29tbWVudHNTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgdmFyIG1vZGVsID0gc2VydmljZUZhY3RvcnkoJ3Rhc2stY29tbWVudHMnLCB7XG4gICAgICBhY3Rpb25zOiB7XG4gICAgICAgIHNhdmVUYXNrQ29tbWVudDoge1xuICAgICAgICAgIG1ldGhvZDogJ1BPU1QnLFxuICAgICAgICAgIHVybDogJ3NhdmVUYXNrQ29tbWVudCdcbiAgICAgICAgfSxcbiAgICAgICAgcmVtb3ZlVGFza0NvbW1lbnQ6IHtcbiAgICAgICAgICBtZXRob2Q6ICdQT1NUJyxcbiAgICAgICAgICB1cmw6ICdyZW1vdmVUYXNrQ29tbWVudCdcbiAgICAgICAgfVxuICAgICAgfSxcbiAgICAgIGluc3RhbmNlOiB7fVxuICAgIH0pO1xuXG4gICAgcmV0dXJuIG1vZGVsO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmlsdGVyKCdlbGFwc2VkJywgZnVuY3Rpb24gKCkge1xuICAgIHJldHVybiBmdW5jdGlvbiAoZGF0ZSkge1xuICAgICAgaWYgKCFkYXRlKSByZXR1cm47XG4gICAgICB2YXIgdGltZSA9IERhdGUucGFyc2UoZGF0ZSksXG4gICAgICAgICAgdGltZU5vdyA9IG5ldyBEYXRlKCkuZ2V0VGltZSgpLFxuICAgICAgICAgIGRpZmZlcmVuY2UgPSB0aW1lTm93IC0gdGltZSxcbiAgICAgICAgICBzZWNvbmRzID0gTWF0aC5mbG9vcihkaWZmZXJlbmNlIC8gMTAwMCksXG4gICAgICAgICAgbWludXRlcyA9IE1hdGguZmxvb3Ioc2Vjb25kcyAvIDYwKSxcbiAgICAgICAgICBob3VycyA9IE1hdGguZmxvb3IobWludXRlcyAvIDYwKSxcbiAgICAgICAgICBkYXlzID0gTWF0aC5mbG9vcihob3VycyAvIDI0KSxcbiAgICAgICAgICBtb250aHMgPSBNYXRoLmZsb29yKGRheXMgLyAzMCk7XG5cbiAgICAgIGlmIChtb250aHMgPiAxKSB7XG4gICAgICAgIHJldHVybiBtb250aHMgKyAnIG1lc2VzIGF0csOhcyc7XG4gICAgICB9IGVsc2UgaWYgKG1vbnRocyA9PT0gMSkge1xuICAgICAgICByZXR1cm4gJzEgbcOqcyBhdHLDoXMnO1xuICAgICAgfSBlbHNlIGlmIChkYXlzID4gMSkge1xuICAgICAgICByZXR1cm4gZGF5cyArICcgZGlhcyBhdHLDoXMnO1xuICAgICAgfSBlbHNlIGlmIChkYXlzID09PSAxKSB7XG4gICAgICAgIHJldHVybiAnMSBkaWEgYXRyw6FzJztcbiAgICAgIH0gZWxzZSBpZiAoaG91cnMgPiAxKSB7XG4gICAgICAgIHJldHVybiBob3VycyArICcgaG9yYXMgYXRyw6FzJztcbiAgICAgIH0gZWxzZSBpZiAoaG91cnMgPT09IDEpIHtcbiAgICAgICAgcmV0dXJuICd1bWEgaG9yYSBhdHLDoXMnO1xuICAgICAgfSBlbHNlIGlmIChtaW51dGVzID4gMSkge1xuICAgICAgICByZXR1cm4gbWludXRlcyArICcgbWludXRvcyBhdHLDoXMnO1xuICAgICAgfSBlbHNlIGlmIChtaW51dGVzID09PSAxKSB7XG4gICAgICAgIHJldHVybiAndW0gbWludXRvIGF0csOhcyc7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICByZXR1cm4gJ2jDoSBwb3Vjb3Mgc2VndW5kb3MnO1xuICAgICAgfVxuICAgIH07XG4gIH0pLmNvbnRyb2xsZXIoJ1Rhc2tzQ29udHJvbGxlcicsIFRhc2tzQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBUYXNrc0NvbnRyb2xsZXIoJGNvbnRyb2xsZXIsIFRhc2tzU2VydmljZSwgU3RhdHVzU2VydmljZSwgUHJpb3JpdGllc1NlcnZpY2UsIFR5cGVzU2VydmljZSwgVGFza0NvbW1lbnRzU2VydmljZSwgbW9tZW50LCBBdXRoLCBQclRvYXN0LCAkdHJhbnNsYXRlLCAkZmlsdGVyLCBHbG9iYWwpIHtcbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgLy9BdHRyaWJ1dGVzIEJsb2NrXG5cbiAgICAvL0Z1bmN0aW9ucyBCbG9ja1xuICAgIHZtLm9uQWN0aXZhdGUgPSBvbkFjdGl2YXRlO1xuICAgIHZtLmFwcGx5RmlsdGVycyA9IGFwcGx5RmlsdGVycztcbiAgICB2bS5iZWZvcmVTYXZlID0gYmVmb3JlU2F2ZTtcbiAgICB2bS5iZWZvcmVSZW1vdmUgPSBiZWZvcmVSZW1vdmU7XG5cbiAgICBmdW5jdGlvbiBvbkFjdGl2YXRlKCkge1xuICAgICAgdm0uY3VycmVudFVzZXIgPSBBdXRoLmN1cnJlbnRVc2VyO1xuICAgICAgdm0uaW1hZ2VQYXRoID0gR2xvYmFsLmltYWdlUGF0aCArICcvbm9fYXZhdGFyLmdpZic7XG4gICAgICB2bS5wcm9qZWN0ID0gbG9jYWxTdG9yYWdlLmdldEl0ZW0oJ3Byb2plY3QnKTtcbiAgICAgIHZtLnF1ZXJ5RmlsdGVycyA9IHsgcHJvamVjdF9pZDogdm0ucHJvamVjdCB9O1xuXG4gICAgICBTdGF0dXNTZXJ2aWNlLnF1ZXJ5KCkudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgdm0uc3RhdHVzID0gcmVzcG9uc2U7XG4gICAgICB9KTtcblxuICAgICAgUHJpb3JpdGllc1NlcnZpY2UucXVlcnkoKS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICB2bS5wcmlvcml0aWVzID0gcmVzcG9uc2U7XG4gICAgICB9KTtcblxuICAgICAgVHlwZXNTZXJ2aWNlLnF1ZXJ5KCkudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgdm0udHlwZXMgPSByZXNwb25zZTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGFwcGx5RmlsdGVycyhkZWZhdWx0UXVlcnlGaWx0ZXJzKSB7XG4gICAgICByZXR1cm4gYW5ndWxhci5leHRlbmQoZGVmYXVsdFF1ZXJ5RmlsdGVycywgdm0ucXVlcnlGaWx0ZXJzKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBiZWZvcmVTYXZlKCkge1xuICAgICAgdm0ucmVzb3VyY2UucHJvamVjdF9pZCA9IHZtLnByb2plY3Q7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gYmVmb3JlUmVtb3ZlKCkge1xuICAgICAgdm0ucmVzb3VyY2UucHJvamVjdF9pZCA9IHZtLnByb2plY3Q7XG4gICAgfVxuXG4gICAgdm0udmlldyA9IGZ1bmN0aW9uIChyZXNvdXJjZSkge1xuICAgICAgdm0ucmVzb3VyY2UgPSByZXNvdXJjZTtcbiAgICAgIHZtLm9uVmlldyA9IHRydWU7XG4gICAgICB2bS52aWV3Rm9ybSA9IGZhbHNlO1xuICAgIH07XG5cbiAgICB2bS5zYXZlQ29tbWVudCA9IGZ1bmN0aW9uIChjb21tZW50KSB7XG4gICAgICB2YXIgZGVzY3JpcHRpb24gPSAnJztcbiAgICAgIHZhciBjb21tZW50X2lkID0gbnVsbDtcblxuICAgICAgaWYgKGNvbW1lbnQpIHtcbiAgICAgICAgZGVzY3JpcHRpb24gPSB2bS5hbnN3ZXI7XG4gICAgICAgIGNvbW1lbnRfaWQgPSBjb21tZW50LmlkO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgZGVzY3JpcHRpb24gPSB2bS5jb21tZW50O1xuICAgICAgfVxuICAgICAgVGFza0NvbW1lbnRzU2VydmljZS5zYXZlVGFza0NvbW1lbnQoeyBwcm9qZWN0X2lkOiB2bS5wcm9qZWN0LCB0YXNrX2lkOiB2bS5yZXNvdXJjZS5pZCwgY29tbWVudF90ZXh0OiBkZXNjcmlwdGlvbiwgY29tbWVudF9pZDogY29tbWVudF9pZCB9KS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgdm0uY29tbWVudCA9ICcnO1xuICAgICAgICB2bS5hbnN3ZXIgPSAnJztcbiAgICAgICAgdm0uc2VhcmNoKCk7XG4gICAgICAgIFByVG9hc3Quc3VjY2VzcygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnNhdmVTdWNjZXNzJykpO1xuICAgICAgfSwgZnVuY3Rpb24gKCkge1xuICAgICAgICBQclRvYXN0LmVycm9yKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMub3BlcmF0aW9uRXJyb3InKSk7XG4gICAgICB9KTtcbiAgICB9O1xuXG4gICAgdm0ucmVtb3ZlQ29tbWVudCA9IGZ1bmN0aW9uIChjb21tZW50KSB7XG4gICAgICBUYXNrQ29tbWVudHNTZXJ2aWNlLnJlbW92ZVRhc2tDb21tZW50KHsgY29tbWVudF9pZDogY29tbWVudC5pZCB9KS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgdm0uc2VhcmNoKCk7XG4gICAgICAgIFByVG9hc3Quc3VjY2VzcygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnJlbW92ZVN1Y2Nlc3MnKSk7XG4gICAgICB9LCBmdW5jdGlvbiAoKSB7XG4gICAgICAgIFByVG9hc3QuZXJyb3IoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5vcGVyYXRpb25FcnJvcicpKTtcbiAgICAgIH0pO1xuICAgIH07XG5cbiAgICB2bS5hZnRlclNlYXJjaCA9IGZ1bmN0aW9uICgpIHtcbiAgICAgIGlmICh2bS5yZXNvdXJjZS5pZCkge1xuICAgICAgICB2bS5yZXNvdXJjZSA9ICRmaWx0ZXIoJ2ZpbHRlcicpKHZtLnJlc291cmNlcywgeyBpZDogdm0ucmVzb3VyY2UuaWQgfSlbMF07XG4gICAgICB9XG4gICAgfTtcblxuICAgIHZtLmZpeERhdGUgPSBmdW5jdGlvbiAoZGF0ZVN0cmluZykge1xuICAgICAgcmV0dXJuIG1vbWVudChkYXRlU3RyaW5nKTtcbiAgICB9O1xuXG4gICAgLy8gaW5zdGFudGlhdGUgYmFzZSBjb250cm9sbGVyXG4gICAgJGNvbnRyb2xsZXIoJ0NSVURDb250cm9sbGVyJywgeyB2bTogdm0sIG1vZGVsU2VydmljZTogVGFza3NTZXJ2aWNlLCBvcHRpb25zOiB7IHNraXBQYWdpbmF0aW9uOiB0cnVlIH0gfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqXG4gICAqIEFycXVpdm8gZGUgY29uZmlndXJhw6fDo28gY29tIGFzIHJvdGFzIGVzcGVjw61maWNhcyBkbyByZWN1cnNvIHByb2plY3RcbiAgICpcbiAgICogQHBhcmFtIHthbnl9ICRzdGF0ZVByb3ZpZGVyXG4gICAqIEBwYXJhbSB7YW55fSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnYXBwLnRhc2tzJywge1xuICAgICAgdXJsOiAnL3Rhc2tzJyxcbiAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvdGFza3MvdGFza3MuaHRtbCcsXG4gICAgICBjb250cm9sbGVyOiAnVGFza3NDb250cm9sbGVyIGFzIHRhc2tzQ3RybCcsXG4gICAgICBkYXRhOiB7IG5lZWRBdXRoZW50aWNhdGlvbjogdHJ1ZSB9XG4gICAgfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmFjdG9yeSgnVGFza3NTZXJ2aWNlJywgVGFza3NTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIFRhc2tzU2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHJldHVybiBzZXJ2aWNlRmFjdG9yeSgndGFza3MnLCB7XG4gICAgICBhY3Rpb25zOiB7XG4gICAgICAgIHVwZGF0ZU1pbGVzdG9uZToge1xuICAgICAgICAgIG1ldGhvZDogJ1BPU1QnLFxuICAgICAgICAgIHVybDogJ3VwZGF0ZU1pbGVzdG9uZSdcbiAgICAgICAgfSxcbiAgICAgICAgdXBkYXRlVGFza0J5S2FuYmFuOiB7XG4gICAgICAgICAgbWV0aG9kOiAnUE9TVCcsXG4gICAgICAgICAgdXJsOiAndXBkYXRlVGFza0J5S2FuYmFuJ1xuICAgICAgICB9XG4gICAgICB9LFxuICAgICAgaW5zdGFuY2U6IHt9XG4gICAgfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmFjdG9yeSgnVHlwZXNTZXJ2aWNlJywgVHlwZXNTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIFR5cGVzU2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHZhciBtb2RlbCA9IHNlcnZpY2VGYWN0b3J5KCd0eXBlcycsIHtcbiAgICAgIGFjdGlvbnM6IHt9LFxuICAgICAgaW5zdGFuY2U6IHt9XG4gICAgfSk7XG5cbiAgICByZXR1cm4gbW9kZWw7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb250cm9sbGVyKCdQcm9maWxlQ29udHJvbGxlcicsIFByb2ZpbGVDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIFByb2ZpbGVDb250cm9sbGVyKFVzZXJzU2VydmljZSwgQXV0aCwgUHJUb2FzdCwgJHRyYW5zbGF0ZSwgJHdpbmRvdywgbW9tZW50KSB7XG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIHZtLnVwZGF0ZSA9IHVwZGF0ZTtcbiAgICB2bS5oaXN0b3J5QmFjayA9IGhpc3RvcnlCYWNrO1xuXG4gICAgYWN0aXZhdGUoKTtcblxuICAgIGZ1bmN0aW9uIGFjdGl2YXRlKCkge1xuICAgICAgdm0udXNlciA9IGFuZ3VsYXIuY29weShBdXRoLmN1cnJlbnRVc2VyKTtcbiAgICAgIGlmICh2bS51c2VyLmJpcnRoZGF5KSB7XG4gICAgICAgIHZtLnVzZXIuYmlydGhkYXkgPSBtb21lbnQodm0udXNlci5iaXJ0aGRheSkuZm9ybWF0KCdERC9NTS9ZWVlZJyk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gdXBkYXRlKCkge1xuICAgICAgaWYgKHZtLnVzZXIuYmlydGhkYXkpIHtcbiAgICAgICAgdm0udXNlci5iaXJ0aGRheSA9IG1vbWVudCh2bS51c2VyLmJpcnRoZGF5KTtcbiAgICAgIH1cbiAgICAgIFVzZXJzU2VydmljZS51cGRhdGVQcm9maWxlKHZtLnVzZXIpLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgIC8vYXR1YWxpemEgbyB1c3XDoXJpbyBjb3JyZW50ZSBjb20gYXMgbm92YXMgaW5mb3JtYcOnw7Vlc1xuICAgICAgICBBdXRoLnVwZGF0ZUN1cnJlbnRVc2VyKHJlc3BvbnNlKTtcbiAgICAgICAgUHJUb2FzdC5zdWNjZXNzKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMuc2F2ZVN1Y2Nlc3MnKSk7XG4gICAgICAgIGhpc3RvcnlCYWNrKCk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBoaXN0b3J5QmFjaygpIHtcbiAgICAgICR3aW5kb3cuaGlzdG9yeS5iYWNrKCk7XG4gICAgfVxuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29udHJvbGxlcignVXNlcnNDb250cm9sbGVyJywgVXNlcnNDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIFVzZXJzQ29udHJvbGxlcigkY29udHJvbGxlciwgVXNlcnNTZXJ2aWNlLCBQclRvYXN0LCAkbWREaWFsb2csICR0cmFuc2xhdGUpIHtcblxuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICB2bS5vbkFjdGl2YXRlID0gb25BY3RpdmF0ZTtcbiAgICAvLyBpbnN0YW50aWF0ZSBiYXNlIGNvbnRyb2xsZXJcbiAgICAkY29udHJvbGxlcignQ1JVRENvbnRyb2xsZXInLCB7IHZtOiB2bSwgbW9kZWxTZXJ2aWNlOiBVc2Vyc1NlcnZpY2UsIG9wdGlvbnM6IHt9IH0pO1xuXG4gICAgZnVuY3Rpb24gb25BY3RpdmF0ZSgpIHtcbiAgICAgIHZtLnF1ZXJ5RmlsdGVycyA9IHt9O1xuICAgIH1cblxuICAgIHZtLmhpZGVEaWFsb2cgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAkbWREaWFsb2cuaGlkZSgpO1xuICAgIH07XG5cbiAgICB2bS5zYXZlTmV3VXNlciA9IGZ1bmN0aW9uICgpIHtcbiAgICAgIHZtLnJlc291cmNlLiRzYXZlKCkudGhlbihmdW5jdGlvbiAocmVzb3VyY2UpIHtcbiAgICAgICAgdm0ucmVzb3VyY2UgPSByZXNvdXJjZTtcbiAgICAgICAgUHJUb2FzdC5zdWNjZXNzKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMuc3VjY2Vzc1NpZ25VcCcpKTtcbiAgICAgICAgJG1kRGlhbG9nLmhpZGUoKTtcbiAgICAgIH0pO1xuICAgIH07XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqXG4gICAqIEFycXVpdm8gZGUgY29uZmlndXJhw6fDo28gY29tIGFzIHJvdGFzIGVzcGVjw61maWNhcyBkbyByZWN1cnNvIHVzZXJcbiAgICpcbiAgICogQHBhcmFtIHthbnl9ICRzdGF0ZVByb3ZpZGVyXG4gICAqIEBwYXJhbSB7YW55fSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnYXBwLnVzZXInLCB7XG4gICAgICB1cmw6ICcvdXN1YXJpbycsXG4gICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL3VzZXJzL3VzZXJzLmh0bWwnLFxuICAgICAgY29udHJvbGxlcjogJ1VzZXJzQ29udHJvbGxlciBhcyB1c2Vyc0N0cmwnLFxuICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IHRydWUsIG5lZWRQcm9maWxlOiBbJ2FkbWluJ10gfVxuICAgIH0pLnN0YXRlKCdhcHAudXNlci1wcm9maWxlJywge1xuICAgICAgdXJsOiAnL3VzdWFyaW8vcGVyZmlsJyxcbiAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvdXNlcnMvcHJvZmlsZS5odG1sJyxcbiAgICAgIGNvbnRyb2xsZXI6ICdQcm9maWxlQ29udHJvbGxlciBhcyBwcm9maWxlQ3RybCcsXG4gICAgICBkYXRhOiB7IG5lZWRBdXRoZW50aWNhdGlvbjogdHJ1ZSB9XG4gICAgfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmFjdG9yeSgnVXNlcnNTZXJ2aWNlJywgVXNlcnNTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIFVzZXJzU2VydmljZShsb2Rhc2gsIEdsb2JhbCwgc2VydmljZUZhY3RvcnkpIHtcbiAgICByZXR1cm4gc2VydmljZUZhY3RvcnkoJ3VzZXJzJywge1xuICAgICAgLy9xdWFuZG8gaW5zdGFuY2lhIHVtIHVzdcOhcmlvIHNlbSBwYXNzYXIgcGFyYW1ldHJvLFxuICAgICAgLy9vIG1lc21vIHZhaSB0ZXIgb3MgdmFsb3JlcyBkZWZhdWx0cyBhYmFpeG9cbiAgICAgIGRlZmF1bHRzOiB7XG4gICAgICAgIHJvbGVzOiBbXVxuICAgICAgfSxcblxuICAgICAgYWN0aW9uczoge1xuICAgICAgICAvKipcbiAgICAgICAgICogU2VydmnDp28gcXVlIGF0dWFsaXphIG9zIGRhZG9zIGRvIHBlcmZpbCBkbyB1c3XDoXJpbyBsb2dhZG9cbiAgICAgICAgICpcbiAgICAgICAgICogQHBhcmFtIHtvYmplY3R9IGF0dHJpYnV0ZXNcbiAgICAgICAgICogQHJldHVybnMge3Byb21pc2V9IFVtYSBwcm9taXNlIGNvbSBvIHJlc3VsdGFkbyBkbyBjaGFtYWRhIG5vIGJhY2tlbmRcbiAgICAgICAgICovXG4gICAgICAgIHVwZGF0ZVByb2ZpbGU6IHtcbiAgICAgICAgICBtZXRob2Q6ICdQVVQnLFxuICAgICAgICAgIHVybDogR2xvYmFsLmFwaVBhdGggKyAnL3Byb2ZpbGUnLFxuICAgICAgICAgIG92ZXJyaWRlOiB0cnVlLFxuICAgICAgICAgIHdyYXA6IGZhbHNlXG4gICAgICAgIH1cbiAgICAgIH0sXG5cbiAgICAgIGluc3RhbmNlOiB7XG4gICAgICAgIC8qKlxuICAgICAgICAgKiBWZXJpZmljYSBzZSBvIHVzdcOhcmlvIHRlbSBvcyBwZXJmaXMgaW5mb3JtYWRvcy5cbiAgICAgICAgICpcbiAgICAgICAgICogQHBhcmFtIHthbnl9IHJvbGVzIHBlcmZpcyBhIHNlcmVtIHZlcmlmaWNhZG9zXG4gICAgICAgICAqIEBwYXJhbSB7Ym9vbGVhbn0gYWxsIGZsYWcgcGFyYSBpbmRpY2FyIHNlIHZhaSBjaGVnYXIgdG9kb3Mgb3MgcGVyZmlzIG91IHNvbWVudGUgdW0gZGVsZXNcbiAgICAgICAgICogQHJldHVybnMge2Jvb2xlYW59XG4gICAgICAgICAqL1xuICAgICAgICBoYXNQcm9maWxlOiBmdW5jdGlvbiBoYXNQcm9maWxlKHJvbGVzLCBhbGwpIHtcbiAgICAgICAgICByb2xlcyA9IGFuZ3VsYXIuaXNBcnJheShyb2xlcykgPyByb2xlcyA6IFtyb2xlc107XG5cbiAgICAgICAgICB2YXIgdXNlclJvbGVzID0gbG9kYXNoLm1hcCh0aGlzLnJvbGVzLCAnc2x1ZycpO1xuXG4gICAgICAgICAgaWYgKGFsbCkge1xuICAgICAgICAgICAgcmV0dXJuIGxvZGFzaC5pbnRlcnNlY3Rpb24odXNlclJvbGVzLCByb2xlcykubGVuZ3RoID09PSByb2xlcy5sZW5ndGg7XG4gICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIC8vcmV0dXJuIHRoZSBsZW5ndGggYmVjYXVzZSAwIGlzIGZhbHNlIGluIGpzXG4gICAgICAgICAgICByZXR1cm4gbG9kYXNoLmludGVyc2VjdGlvbih1c2VyUm9sZXMsIHJvbGVzKS5sZW5ndGg7XG4gICAgICAgICAgfVxuICAgICAgICB9LFxuXG4gICAgICAgIC8qKlxuICAgICAgICAgKiBWZXJpZmljYSBzZSBvIHVzdcOhcmlvIHRlbSBvIHBlcmZpbCBhZG1pbi5cbiAgICAgICAgICpcbiAgICAgICAgICogQHJldHVybnMge2Jvb2xlYW59XG4gICAgICAgICAqL1xuICAgICAgICBpc0FkbWluOiBmdW5jdGlvbiBpc0FkbWluKCkge1xuICAgICAgICAgIHJldHVybiB0aGlzLmhhc1Byb2ZpbGUoJ2FkbWluJyk7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuLy90b2tlbiBjYWNiOTEyMzU4NzNhOGM0ODc1ZDIzNTc4YWM5ZjMyNmVmODk0YjY2XG4vLyBPQXR1dGggaHR0cHM6Ly9naXRodWIuY29tL2xvZ2luL29hdXRoL2F1dGhvcml6ZT9jbGllbnRfaWQ9ODI5NDY4ZTdmZGVlNzk0NDViYTYmc2NvcGU9dXNlcixwdWJsaWNfcmVwbyZyZWRpcmVjdF91cmk9aHR0cDovLzAuMC4wLjA6NTAwMC8jIS9hcHAvdmNzXG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmlsdGVyKCdieXRlcycsIGZ1bmN0aW9uICgpIHtcbiAgICByZXR1cm4gZnVuY3Rpb24gKGJ5dGVzLCBwcmVjaXNpb24pIHtcbiAgICAgIGlmIChpc05hTihwYXJzZUZsb2F0KGJ5dGVzKSkgfHwgIWlzRmluaXRlKGJ5dGVzKSkgcmV0dXJuICctJztcbiAgICAgIGlmICh0eXBlb2YgcHJlY2lzaW9uID09PSAndW5kZWZpbmVkJykgcHJlY2lzaW9uID0gMTtcbiAgICAgIHZhciB1bml0cyA9IFsnYnl0ZXMnLCAna0InLCAnTUInLCAnR0InLCAnVEInLCAnUEInXSxcbiAgICAgICAgICBudW1iZXIgPSBNYXRoLmZsb29yKE1hdGgubG9nKGJ5dGVzKSAvIE1hdGgubG9nKDEwMjQpKTtcblxuICAgICAgcmV0dXJuIChieXRlcyAvIE1hdGgucG93KDEwMjQsIE1hdGguZmxvb3IobnVtYmVyKSkpLnRvRml4ZWQocHJlY2lzaW9uKSArICcgJyArIHVuaXRzW251bWJlcl07XG4gICAgfTtcbiAgfSkuY29udHJvbGxlcignVmNzQ29udHJvbGxlcicsIFZjc0NvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gVmNzQ29udHJvbGxlcigkY29udHJvbGxlciwgVmNzU2VydmljZSwgJHdpbmRvdywgUHJvamVjdHNTZXJ2aWNlLCBQclRvYXN0LCAkdHJhbnNsYXRlKSB7XG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIHZtLmluZGV4ID0gMDtcbiAgICB2bS5wYXRocyA9IFtdO1xuXG4gICAgLy9BdHRyaWJ1dGVzIEJsb2NrXG5cbiAgICAvL0Z1bmN0aW9ucyBCbG9ja1xuICAgIHZtLm9uQWN0aXZhdGUgPSBmdW5jdGlvbiAoKSB7XG4gICAgICB0b2dnbGVTcGxhc2hTY3JlZW4oKTtcbiAgICAgIFByb2plY3RzU2VydmljZS5xdWVyeSh7IHByb2plY3RfaWQ6IGxvY2FsU3RvcmFnZS5nZXRJdGVtKCdwcm9qZWN0JykgfSkudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgdm0udXNlcm5hbWUgPSByZXNwb25zZVswXS51c2VybmFtZV9naXRodWI7XG4gICAgICAgIHZtLnJlcG8gPSByZXNwb25zZVswXS5yZXBvX2dpdGh1YjtcbiAgICAgICAgdm0ucXVlcnlGaWx0ZXJzID0ge1xuICAgICAgICAgIHVzZXJuYW1lOiB2bS51c2VybmFtZSxcbiAgICAgICAgICByZXBvOiB2bS5yZXBvLFxuICAgICAgICAgIHBhdGg6ICcuJ1xuICAgICAgICB9O1xuICAgICAgICB2bS5wYXRocy5wdXNoKHZtLnF1ZXJ5RmlsdGVycy5wYXRoKTtcbiAgICAgICAgdm0uc2VhcmNoKCk7XG4gICAgICB9KTtcbiAgICB9O1xuXG4gICAgdm0uYXBwbHlGaWx0ZXJzID0gZnVuY3Rpb24gKGRlZmF1bHRRdWVyeUZpbHRlcnMpIHtcbiAgICAgIHJldHVybiBhbmd1bGFyLmV4dGVuZChkZWZhdWx0UXVlcnlGaWx0ZXJzLCB2bS5xdWVyeUZpbHRlcnMpO1xuICAgIH07XG5cbiAgICB2bS5hZnRlclNlYXJjaCA9IGZ1bmN0aW9uICgpIHtcbiAgICAgIHNvcnRSZXNvdXJjZXMoKTtcbiAgICAgICR3aW5kb3cubG9hZGluZ19zY3JlZW4uZmluaXNoKCk7XG4gICAgfTtcblxuICAgIGZ1bmN0aW9uIHNvcnRSZXNvdXJjZXMoKSB7XG4gICAgICB2bS5yZXNvdXJjZXMuc29ydChmdW5jdGlvbiAoYSwgYikge1xuICAgICAgICByZXR1cm4gYS50eXBlIDwgYi50eXBlID8gLTEgOiBhLnR5cGUgPiBiLnR5cGUgPyAxIDogMDtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIHZtLm9wZW5GaWxlT3JEaXJlY3RvcnkgPSBmdW5jdGlvbiAocmVzb3VyY2UpIHtcbiAgICAgIHRvZ2dsZVNwbGFzaFNjcmVlbigpO1xuICAgICAgaWYgKHJlc291cmNlKSB7XG4gICAgICAgIHZtLnF1ZXJ5RmlsdGVycy5wYXRoID0gcmVzb3VyY2UucGF0aDtcbiAgICAgICAgdm0ucGF0aHMucHVzaCh2bS5xdWVyeUZpbHRlcnMucGF0aCk7XG4gICAgICAgIHZtLmluZGV4Kys7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICB2bS5xdWVyeUZpbHRlcnMucGF0aCA9IHZtLnBhdGhzW3ZtLmluZGV4IC0gMV07XG4gICAgICAgIHZtLnBhdGhzLnNwbGljZSh2bS5pbmRleCwgMSk7XG4gICAgICAgIHZtLmluZGV4LS07XG4gICAgICB9XG4gICAgICB2bS5zZWFyY2goKTtcbiAgICB9O1xuXG4gICAgdm0ub25TZWFyY2hFcnJvciA9IGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgaWYgKHJlc3BvbnNlLmRhdGEuZXJyb3IgPT09ICdOb3QgRm91bmQnKSB7XG4gICAgICAgIFByVG9hc3QuaW5mbygkdHJhbnNsYXRlLmluc3RhbnQoJ1JlcG9zaXTDs3JpbyBuw6NvIGVuY29udHJhZG8nKSk7XG4gICAgICAgICR3aW5kb3cubG9hZGluZ19zY3JlZW4uZmluaXNoKCk7XG4gICAgICB9XG4gICAgfTtcblxuICAgIC8qKlxuICAgICAqIE3DqXRvZG8gcGFyYSBtb3N0cmFyIGEgdGVsYSBkZSBlc3BlcmFcbiAgICAgKi9cbiAgICBmdW5jdGlvbiB0b2dnbGVTcGxhc2hTY3JlZW4oKSB7XG4gICAgICAkd2luZG93LmxvYWRpbmdfc2NyZWVuID0gJHdpbmRvdy5wbGVhc2VXYWl0KHtcbiAgICAgICAgbG9nbzogJycsXG4gICAgICAgIGJhY2tncm91bmRDb2xvcjogJ3JnYmEoMjU1LDI1NSwyNTUsMC40KScsXG4gICAgICAgIGxvYWRpbmdIdG1sOiAnPGRpdiBjbGFzcz1cInNwaW5uZXJcIj4gJyArICcgIDxkaXYgY2xhc3M9XCJyZWN0MVwiPjwvZGl2PiAnICsgJyAgPGRpdiBjbGFzcz1cInJlY3QyXCI+PC9kaXY+ICcgKyAnICA8ZGl2IGNsYXNzPVwicmVjdDNcIj48L2Rpdj4gJyArICcgIDxkaXYgY2xhc3M9XCJyZWN0NFwiPjwvZGl2PiAnICsgJyAgPGRpdiBjbGFzcz1cInJlY3Q1XCI+PC9kaXY+ICcgKyAnIDxwIGNsYXNzPVwibG9hZGluZy1tZXNzYWdlXCI+Q2FycmVnYW5kbzwvcD4gJyArICc8L2Rpdj4nXG4gICAgICB9KTtcbiAgICB9XG5cbiAgICAvLyBpbnN0YW50aWF0ZSBiYXNlIGNvbnRyb2xsZXJcbiAgICAkY29udHJvbGxlcignQ1JVRENvbnRyb2xsZXInLCB7IHZtOiB2bSwgbW9kZWxTZXJ2aWNlOiBWY3NTZXJ2aWNlLCBvcHRpb25zOiB7IHNraXBQYWdpbmF0aW9uOiB0cnVlLCBzZWFyY2hPbkluaXQ6IGZhbHNlIH0gfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqXG4gICAqIEFycXVpdm8gZGUgY29uZmlndXJhw6fDo28gY29tIGFzIHJvdGFzIGVzcGVjw61maWNhcyBkbyByZWN1cnNvIHZjc1xuICAgKlxuICAgKiBAcGFyYW0ge29iamVjdH0gJHN0YXRlUHJvdmlkZXJcbiAgICogQHBhcmFtIHtvYmplY3R9IEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdhcHAudmNzJywge1xuICAgICAgdXJsOiAnL3ZjcycsXG4gICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL3Zjcy92Y3MuaHRtbCcsXG4gICAgICBjb250cm9sbGVyOiAnVmNzQ29udHJvbGxlciBhcyB2Y3NDdHJsJyxcbiAgICAgIGRhdGE6IHt9XG4gICAgfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmFjdG9yeSgnVmNzU2VydmljZScsIFZjc1NlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gVmNzU2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHZhciBtb2RlbCA9IHNlcnZpY2VGYWN0b3J5KCd2Y3MnLCB7XG4gICAgICBhY3Rpb25zOiB7fSxcbiAgICAgIGluc3RhbmNlOiB7fVxuICAgIH0pO1xuXG4gICAgcmV0dXJuIG1vZGVsO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb21wb25lbnQoJ2JveCcsIHtcbiAgICByZXBsYWNlOiB0cnVlLFxuICAgIHRlbXBsYXRlVXJsOiBbJ0dsb2JhbCcsIGZ1bmN0aW9uIChHbG9iYWwpIHtcbiAgICAgIHJldHVybiBHbG9iYWwuY2xpZW50UGF0aCArICcvd2lkZ2V0cy9ib3guaHRtbCc7XG4gICAgfV0sXG4gICAgdHJhbnNjbHVkZToge1xuICAgICAgdG9vbGJhckJ1dHRvbnM6ICc/Ym94VG9vbGJhckJ1dHRvbnMnLFxuICAgICAgZm9vdGVyQnV0dG9uczogJz9ib3hGb290ZXJCdXR0b25zJ1xuICAgIH0sXG4gICAgYmluZGluZ3M6IHtcbiAgICAgIGJveFRpdGxlOiAnQCcsXG4gICAgICB0b29sYmFyQ2xhc3M6ICdAJyxcbiAgICAgIHRvb2xiYXJCZ0NvbG9yOiAnQCdcbiAgICB9LFxuICAgIGNvbnRyb2xsZXI6IFsnJHRyYW5zY2x1ZGUnLCBmdW5jdGlvbiAoJHRyYW5zY2x1ZGUpIHtcbiAgICAgIHZhciBjdHJsID0gdGhpcztcblxuICAgICAgY3RybC50cmFuc2NsdWRlID0gJHRyYW5zY2x1ZGU7XG5cbiAgICAgIGN0cmwuJG9uSW5pdCA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgaWYgKGFuZ3VsYXIuaXNVbmRlZmluZWQoY3RybC50b29sYmFyQmdDb2xvcikpIGN0cmwudG9vbGJhckJnQ29sb3IgPSAnZGVmYXVsdC1wcmltYXJ5JztcbiAgICAgIH07XG4gICAgfV1cbiAgfSk7XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb21wb25lbnQoJ2NvbnRlbnRCb2R5Jywge1xuICAgIHJlcGxhY2U6IHRydWUsXG4gICAgdHJhbnNjbHVkZTogdHJ1ZSxcbiAgICB0ZW1wbGF0ZVVybDogWydHbG9iYWwnLCBmdW5jdGlvbiAoR2xvYmFsKSB7XG4gICAgICByZXR1cm4gR2xvYmFsLmNsaWVudFBhdGggKyAnL3dpZGdldHMvY29udGVudC1ib2R5Lmh0bWwnO1xuICAgIH1dLFxuICAgIGJpbmRpbmdzOiB7XG4gICAgICBsYXlvdXRBbGlnbjogJ0AnXG4gICAgfSxcbiAgICBjb250cm9sbGVyOiBbZnVuY3Rpb24gKCkge1xuICAgICAgdmFyIGN0cmwgPSB0aGlzO1xuXG4gICAgICBjdHJsLiRvbkluaXQgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgIC8vIE1ha2UgYSBjb3B5IG9mIHRoZSBpbml0aWFsIHZhbHVlIHRvIGJlIGFibGUgdG8gcmVzZXQgaXQgbGF0ZXJcbiAgICAgICAgY3RybC5sYXlvdXRBbGlnbiA9IGFuZ3VsYXIuaXNEZWZpbmVkKGN0cmwubGF5b3V0QWxpZ24pID8gY3RybC5sYXlvdXRBbGlnbiA6ICdjZW50ZXIgc3RhcnQnO1xuICAgICAgfTtcbiAgICB9XVxuICB9KTtcbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICAvKiogQG5nSW5qZWN0ICovXG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbXBvbmVudCgnY29udGVudEhlYWRlcicsIHtcbiAgICB0ZW1wbGF0ZVVybDogWydHbG9iYWwnLCBmdW5jdGlvbiAoR2xvYmFsKSB7XG4gICAgICByZXR1cm4gR2xvYmFsLmNsaWVudFBhdGggKyAnL3dpZGdldHMvY29udGVudC1oZWFkZXIuaHRtbCc7XG4gICAgfV0sXG4gICAgcmVwbGFjZTogdHJ1ZSxcbiAgICBiaW5kaW5nczoge1xuICAgICAgdGl0bGU6ICdAJyxcbiAgICAgIGRlc2NyaXB0aW9uOiAnQCdcbiAgICB9XG4gIH0pO1xufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZpbHRlcignYXVkaXREZXRhaWxUaXRsZScsIGF1ZGl0RGV0YWlsVGl0bGUpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gYXVkaXREZXRhaWxUaXRsZSgkdHJhbnNsYXRlKSB7XG4gICAgcmV0dXJuIGZ1bmN0aW9uIChhdWRpdERldGFpbCwgc3RhdHVzKSB7XG4gICAgICBpZiAoYXVkaXREZXRhaWwudHlwZSA9PT0gJ3VwZGF0ZWQnKSB7XG4gICAgICAgIGlmIChzdGF0dXMgPT09ICdiZWZvcmUnKSB7XG4gICAgICAgICAgcmV0dXJuICR0cmFuc2xhdGUuaW5zdGFudCgnZGlhbG9nLmF1ZGl0LnVwZGF0ZWRCZWZvcmUnKTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICByZXR1cm4gJHRyYW5zbGF0ZS5pbnN0YW50KCdkaWFsb2cuYXVkaXQudXBkYXRlZEFmdGVyJyk7XG4gICAgICAgIH1cbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHJldHVybiAkdHJhbnNsYXRlLmluc3RhbnQoJ2RpYWxvZy5hdWRpdC4nICsgYXVkaXREZXRhaWwudHlwZSk7XG4gICAgICB9XG4gICAgfTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZpbHRlcignYXVkaXRNb2RlbCcsIGF1ZGl0TW9kZWwpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gYXVkaXRNb2RlbCgkdHJhbnNsYXRlKSB7XG4gICAgcmV0dXJuIGZ1bmN0aW9uIChtb2RlbElkKSB7XG4gICAgICBtb2RlbElkID0gbW9kZWxJZC5yZXBsYWNlKCdBcHBcXFxcJywgJycpO1xuICAgICAgdmFyIG1vZGVsID0gJHRyYW5zbGF0ZS5pbnN0YW50KCdtb2RlbHMuJyArIG1vZGVsSWQudG9Mb3dlckNhc2UoKSk7XG5cbiAgICAgIHJldHVybiBtb2RlbCA/IG1vZGVsIDogbW9kZWxJZDtcbiAgICB9O1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmlsdGVyKCdhdWRpdFR5cGUnLCBhdWRpdFR5cGUpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gYXVkaXRUeXBlKGxvZGFzaCwgQXVkaXRTZXJ2aWNlKSB7XG4gICAgcmV0dXJuIGZ1bmN0aW9uICh0eXBlSWQpIHtcbiAgICAgIHZhciB0eXBlID0gbG9kYXNoLmZpbmQoQXVkaXRTZXJ2aWNlLmxpc3RUeXBlcygpLCB7IGlkOiB0eXBlSWQgfSk7XG5cbiAgICAgIHJldHVybiB0eXBlID8gdHlwZS5sYWJlbCA6IHR5cGU7XG4gICAgfTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZpbHRlcignYXVkaXRWYWx1ZScsIGF1ZGl0VmFsdWUpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gYXVkaXRWYWx1ZSgkZmlsdGVyLCBsb2Rhc2gpIHtcbiAgICByZXR1cm4gZnVuY3Rpb24gKHZhbHVlLCBrZXkpIHtcbiAgICAgIGlmIChhbmd1bGFyLmlzRGF0ZSh2YWx1ZSkgfHwgbG9kYXNoLmVuZHNXaXRoKGtleSwgJ19hdCcpIHx8IGxvZGFzaC5lbmRzV2l0aChrZXksICdfdG8nKSkge1xuICAgICAgICByZXR1cm4gJGZpbHRlcigncHJEYXRldGltZScpKHZhbHVlKTtcbiAgICAgIH1cblxuICAgICAgaWYgKHR5cGVvZiB2YWx1ZSA9PT0gJ2Jvb2xlYW4nKSB7XG4gICAgICAgIHJldHVybiAkZmlsdGVyKCd0cmFuc2xhdGUnKSh2YWx1ZSA/ICdnbG9iYWwueWVzJyA6ICdnbG9iYWwubm8nKTtcbiAgICAgIH1cblxuICAgICAgLy9jaGVjayBpcyBmbG9hdFxuICAgICAgaWYgKE51bWJlcih2YWx1ZSkgPT09IHZhbHVlICYmIHZhbHVlICUgMSAhPT0gMCkge1xuICAgICAgICByZXR1cm4gJGZpbHRlcigncmVhbCcpKHZhbHVlKTtcbiAgICAgIH1cblxuICAgICAgcmV0dXJuIHZhbHVlO1xuICAgIH07XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbi8qZXNsaW50IGFuZ3VsYXIvZmlsZS1uYW1lOiAwLCBuby11bmRlZjogMCovXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbnN0YW50KCdwdC1CUi5pMThuLmF0dHJpYnV0ZXMnLCB7XG4gICAgZW1haWw6ICdFbWFpbCcsXG4gICAgcGFzc3dvcmQ6ICdTZW5oYScsXG4gICAgbmFtZTogJ05vbWUnLFxuICAgIGltYWdlOiAnSW1hZ2VtJyxcbiAgICByb2xlczogJ1BlcmZpcycsXG4gICAgZGF0ZTogJ0RhdGEnLFxuICAgIGluaXRpYWxEYXRlOiAnRGF0YSBJbmljaWFsJyxcbiAgICBmaW5hbERhdGU6ICdEYXRhIEZpbmFsJyxcbiAgICBiaXJ0aGRheTogJ0RhdGEgZGUgTmFzY2ltZW50bycsXG4gICAgdGFzazoge1xuICAgICAgZGVzY3JpcHRpb246ICdEZXNjcmnDp8OjbycsXG4gICAgICBkb25lOiAnRmVpdG8/JyxcbiAgICAgIHByaW9yaXR5OiAnUHJpb3JpZGFkZScsXG4gICAgICBzY2hlZHVsZWRfdG86ICdBZ2VuZGFkbyBQYXJhPycsXG4gICAgICBwcm9qZWN0OiAnUHJvamV0bycsXG4gICAgICBzdGF0dXM6ICdTdGF0dXMnLFxuICAgICAgdGl0bGU6ICdUw610dWxvJyxcbiAgICAgIHR5cGU6ICdUaXBvJyxcbiAgICAgIG1pbGVzdG9uZTogJ1NwcmludCcsXG4gICAgICBlc3RpbWF0ZWRfdGltZTogJ1RlbXBvIEVzdGltYWRvJ1xuICAgIH0sXG4gICAgbWlsZXN0b25lOiB7XG4gICAgICB0aXRsZTogJ1TDrXR1bG8nLFxuICAgICAgZGVzY3JpcHRpb246ICdEZXNjcmnDp8OjbycsXG4gICAgICBkYXRlX3N0YXJ0OiAnRGF0YSBFc3RpbWFkYSBwYXJhIEluw61jaW8nLFxuICAgICAgZGF0ZV9lbmQ6ICdEYXRhIEVzdGltYWRhIHBhcmEgRmltJyxcbiAgICAgIGVzdGltYXRlZF90aW1lOiAnVGVtcG8gRXN0aW1hZG8nLFxuICAgICAgZXN0aW1hdGVkX3ZhbHVlOiAnVmFsb3IgRXN0aW1hZG8nXG4gICAgfSxcbiAgICBwcm9qZWN0OiB7XG4gICAgICBjb3N0OiAnQ3VzdG8nLFxuICAgICAgaG91clZhbHVlRGV2ZWxvcGVyOiAnVmFsb3IgZGEgSG9yYSBEZXNlbnZvbHZlZG9yJyxcbiAgICAgIGhvdXJWYWx1ZUNsaWVudDogJ1ZhbG9yIGRhIEhvcmEgQ2xpZW50ZScsXG4gICAgICBob3VyVmFsdWVGaW5hbDogJ1ZhbG9yIGRhIEhvcmEgUHJvamV0bydcbiAgICB9LFxuICAgIHJlbGVhc2U6IHtcbiAgICAgIHRpdGxlOiAnVMOtdHVsbycsXG4gICAgICBkZXNjcmlwdGlvbjogJ0Rlc2NyacOnw6NvJyxcbiAgICAgIHJlbGVhc2VfZGF0ZTogJ0RhdGEgZGUgRW50cmVnYScsXG4gICAgICBtaWxlc3RvbmU6ICdNaWxlc3RvbmUnLFxuICAgICAgdGFza3M6ICdUYXJlZmFzJ1xuICAgIH0sXG4gICAgLy/DqSBjYXJyZWdhZG8gZG8gc2Vydmlkb3IgY2FzbyBlc3RlamEgZGVmaW5pZG8gbm8gbWVzbW9cbiAgICBhdWRpdE1vZGVsOiB7fVxuICB9KTtcbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbi8qZXNsaW50IGFuZ3VsYXIvZmlsZS1uYW1lOiAwLCBuby11bmRlZjogMCovXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbnN0YW50KCdwdC1CUi5pMThuLmRpYWxvZycsIHtcbiAgICBjb25maXJtVGl0bGU6ICdDb25maXJtYcOnw6NvJyxcbiAgICBjb25maXJtRGVzY3JpcHRpb246ICdDb25maXJtYSBhIGHDp8Ojbz8nLFxuICAgIHJlbW92ZURlc2NyaXB0aW9uOiAnRGVzZWphIHJlbW92ZXIgcGVybWFuZW50ZW1lbnRlIHt7bmFtZX19PycsXG4gICAgYXVkaXQ6IHtcbiAgICAgIGNyZWF0ZWQ6ICdJbmZvcm1hw6fDtWVzIGRvIENhZGFzdHJvJyxcbiAgICAgIHVwZGF0ZWRCZWZvcmU6ICdBbnRlcyBkYSBBdHVhbGl6YcOnw6NvJyxcbiAgICAgIHVwZGF0ZWRBZnRlcjogJ0RlcG9pcyBkYSBBdHVhbGl6YcOnw6NvJyxcbiAgICAgIGRlbGV0ZWQ6ICdJbmZvcm1hw6fDtWVzIGFudGVzIGRlIHJlbW92ZXInXG4gICAgfSxcbiAgICBsb2dpbjoge1xuICAgICAgcmVzZXRQYXNzd29yZDoge1xuICAgICAgICBkZXNjcmlwdGlvbjogJ0RpZ2l0ZSBhYmFpeG8gbyBlbWFpbCBjYWRhc3RyYWRvIG5vIHNpc3RlbWEuJ1xuICAgICAgfVxuICAgIH1cbiAgfSk7XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4vKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCwgbm8tdW5kZWY6IDAqL1xuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25zdGFudCgncHQtQlIuaTE4bi5nbG9iYWwnLCB7XG4gICAgbG9hZGluZzogJ0NhcnJlZ2FuZG8uLi4nLFxuICAgIHByb2Nlc3Npbmc6ICdQcm9jZXNzYW5kby4uLicsXG4gICAgeWVzOiAnU2ltJyxcbiAgICBubzogJ07Do28nLFxuICAgIGFsbDogJ1RvZG9zJ1xuICB9KTtcbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbi8qZXNsaW50IGFuZ3VsYXIvZmlsZS1uYW1lOiAwLCBuby11bmRlZjogMCovXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbnN0YW50KCdwdC1CUi5pMThuLm1lc3NhZ2VzJywge1xuICAgIGludGVybmFsRXJyb3I6ICdPY29ycmV1IHVtIGVycm8gaW50ZXJubywgY29udGF0ZSBvIGFkbWluaXN0cmFkb3IgZG8gc2lzdGVtYScsXG4gICAgbm90Rm91bmQ6ICdOZW5odW0gcmVnaXN0cm8gZW5jb250cmFkbycsXG4gICAgbm90QXV0aG9yaXplZDogJ1ZvY8OqIG7Do28gdGVtIGFjZXNzbyBhIGVzdGEgZnVuY2lvbmFsaWRhZGUuJyxcbiAgICBzZWFyY2hFcnJvcjogJ07Do28gZm9pIHBvc3PDrXZlbCByZWFsaXphciBhIGJ1c2NhLicsXG4gICAgc2F2ZVN1Y2Nlc3M6ICdSZWdpc3RybyBzYWx2byBjb20gc3VjZXNzby4nLFxuICAgIG9wZXJhdGlvblN1Y2Nlc3M6ICdPcGVyYcOnw6NvIHJlYWxpemFkYSBjb20gc3VjZXNzby4nLFxuICAgIG9wZXJhdGlvbkVycm9yOiAnRXJybyBhbyByZWFsaXphciBhIG9wZXJhw6fDo28nLFxuICAgIHNhdmVFcnJvcjogJ0Vycm8gYW8gdGVudGFyIHNhbHZhciBvIHJlZ2lzdHJvLicsXG4gICAgcmVtb3ZlU3VjY2VzczogJ1JlbW/Dp8OjbyByZWFsaXphZGEgY29tIHN1Y2Vzc28uJyxcbiAgICByZW1vdmVFcnJvcjogJ0Vycm8gYW8gdGVudGFyIHJlbW92ZXIgbyByZWdpc3Ryby4nLFxuICAgIHJlc291cmNlTm90Rm91bmRFcnJvcjogJ1JlY3Vyc28gbsOjbyBlbmNvbnRyYWRvJyxcbiAgICBub3ROdWxsRXJyb3I6ICdUb2RvcyBvcyBjYW1wb3Mgb2JyaWdhdMOzcmlvcyBkZXZlbSBzZXIgcHJlZW5jaGlkb3MuJyxcbiAgICBkdXBsaWNhdGVkUmVzb3VyY2VFcnJvcjogJ0rDoSBleGlzdGUgdW0gcmVjdXJzbyBjb20gZXNzYXMgaW5mb3JtYcOnw7Vlcy4nLFxuICAgIHNwcmludEVuZGVkU3VjY2VzczogJ1NwcmludCBmaW5hbGl6YWRhIGNvbSBzdWNlc3NvJyxcbiAgICBzcHJpbnRFbmRlZEVycm9yOiAnRXJybyBhbyBmaW5hbGl6YXIgYSBzcHJpbnQnLFxuICAgIHN1Y2Nlc3NTaWduVXA6ICdDYWRhc3RybyByZWFsaXphZG8gY29tIHN1Y2Vzc28uIFVtIGUtbWFpbCBmb2kgZW52aWFkbyBjb20gc2V1cyBkYWRvcyBkZSBsb2dpbicsXG4gICAgZXJyb3JzU2lnblVwOiAnSG91dmUgdW0gZXJybyBhbyByZWFsaXphciBvIHNldSBjYWRhc3Ryby4gVGVudGUgbm92YW1lbnRlIG1haXMgdGFyZGUhJyxcbiAgICByZWxlYXNldEVuZGVkU3VjY2VzczogJ1JlbGVhc2UgZmluYWxpemFkYSBjb20gc3VjZXNzbycsXG4gICAgcmVsZWFzZUVuZGVkRXJyb3I6ICdFcnJvIGFvIGZpbmFsaXphciBhIHJlbGVhc2UnLFxuICAgIHByb2plY3RFbmRlZFN1Y2Nlc3M6ICdQcm9qZXRvIGZpbmFsaXphZG8gY29tIHN1Y2Vzc28nLFxuICAgIHByb2plY3RFbmRlZEVycm9yOiAnRXJybyBhbyBmaW5hbGl6YXIgbyBwcm9qZXRvJyxcbiAgICB2YWxpZGF0ZToge1xuICAgICAgZmllbGRSZXF1aXJlZDogJ08gY2FtcG8ge3tmaWVsZH19IMOpIG9icmlncmF0w7NyaW8uJ1xuICAgIH0sXG4gICAgbGF5b3V0OiB7XG4gICAgICBlcnJvcjQwNDogJ1DDoWdpbmEgbsOjbyBlbmNvbnRyYWRhJ1xuICAgIH0sXG4gICAgbG9naW46IHtcbiAgICAgIGxvZ291dEluYWN0aXZlOiAnVm9jw6ogZm9pIGRlc2xvZ2FkbyBkbyBzaXN0ZW1hIHBvciBpbmF0aXZpZGFkZS4gRmF2b3IgZW50cmFyIG5vIHNpc3RlbWEgbm92YW1lbnRlLicsXG4gICAgICBpbnZhbGlkQ3JlZGVudGlhbHM6ICdDcmVkZW5jaWFpcyBJbnbDoWxpZGFzJyxcbiAgICAgIHVua25vd25FcnJvcjogJ07Do28gZm9pIHBvc3PDrXZlbCByZWFsaXphciBvIGxvZ2luLiBUZW50ZSBub3ZhbWVudGUuICcgKyAnQ2FzbyBuw6NvIGNvbnNpZ2EgZmF2b3IgZW5jb250cmFyIGVtIGNvbnRhdG8gY29tIG8gYWRtaW5pc3RyYWRvciBkbyBzaXN0ZW1hLicsXG4gICAgICB1c2VyTm90Rm91bmQ6ICdOw6NvIGZvaSBwb3Nzw612ZWwgZW5jb250cmFyIHNldXMgZGFkb3MnXG4gICAgfSxcbiAgICBkYXNoYm9hcmQ6IHtcbiAgICAgIHdlbGNvbWU6ICdTZWphIGJlbSBWaW5kbyB7e3VzZXJOYW1lfX0nLFxuICAgICAgZGVzY3JpcHRpb246ICdVdGlsaXplIG8gbWVudSBwYXJhIG5hdmVnYcOnw6NvLidcbiAgICB9LFxuICAgIG1haWw6IHtcbiAgICAgIG1haWxFcnJvcnM6ICdPY29ycmV1IHVtIGVycm8gbm9zIHNlZ3VpbnRlcyBlbWFpbHMgYWJhaXhvOlxcbicsXG4gICAgICBzZW5kTWFpbFN1Y2Nlc3M6ICdFbWFpbCBlbnZpYWRvIGNvbSBzdWNlc3NvIScsXG4gICAgICBzZW5kTWFpbEVycm9yOiAnTsOjbyBmb2kgcG9zc8OtdmVsIGVudmlhciBvIGVtYWlsLicsXG4gICAgICBwYXNzd29yZFNlbmRpbmdTdWNjZXNzOiAnTyBwcm9jZXNzbyBkZSByZWN1cGVyYcOnw6NvIGRlIHNlbmhhIGZvaSBpbmljaWFkby4gQ2FzbyBvIGVtYWlsIG7Do28gY2hlZ3VlIGVtIDEwIG1pbnV0b3MgdGVudGUgbm92YW1lbnRlLidcbiAgICB9LFxuICAgIHVzZXI6IHtcbiAgICAgIHJlbW92ZVlvdXJTZWxmRXJyb3I6ICdWb2PDqiBuw6NvIHBvZGUgcmVtb3ZlciBzZXUgcHLDs3ByaW8gdXN1w6FyaW8nLFxuICAgICAgdXNlckV4aXN0czogJ1VzdcOhcmlvIGrDoSBhZGljaW9uYWRvIScsXG4gICAgICBwcm9maWxlOiB7XG4gICAgICAgIHVwZGF0ZUVycm9yOiAnTsOjbyBmb2kgcG9zc8OtdmVsIGF0dWFsaXphciBzZXUgcHJvZmlsZSdcbiAgICAgIH1cbiAgICB9LFxuICAgIHF1ZXJ5RGluYW1pYzoge1xuICAgICAgbm9GaWx0ZXI6ICdOZW5odW0gZmlsdHJvIGFkaWNpb25hZG8nXG4gICAgfVxuICB9KTtcbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbi8qZXNsaW50IGFuZ3VsYXIvZmlsZS1uYW1lOiAwLCBuby11bmRlZjogMCovXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbnN0YW50KCdwdC1CUi5pMThuLm1vZGVscycsIHtcbiAgICB1c2VyOiAnVXN1w6FyaW8nLFxuICAgIHRhc2s6ICdUYXJlZmEnLFxuICAgIHByb2plY3Q6ICdQcm9qZXRvJ1xuICB9KTtcbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbi8qZXNsaW50IGFuZ3VsYXIvZmlsZS1uYW1lOiAwLCBuby11bmRlZjogMCovXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbnN0YW50KCdwdC1CUi5pMThuLnZpZXdzJywge1xuICAgIGJyZWFkY3J1bWJzOiB7XG4gICAgICB1c2VyOiAnQWRtaW5pc3RyYcOnw6NvIC0gVXN1w6FyaW8nLFxuICAgICAgJ3VzZXItcHJvZmlsZSc6ICdQZXJmaWwnLFxuICAgICAgZGFzaGJvYXJkOiAnRGFzaGJvYXJkJyxcbiAgICAgIGF1ZGl0OiAnQWRtaW5pc3RyYcOnw6NvIC0gQXVkaXRvcmlhJyxcbiAgICAgIG1haWw6ICdBZG1pbmlzdHJhw6fDo28gLSBFbnZpbyBkZSBlLW1haWwnLFxuICAgICAgcHJvamVjdHM6ICdQcm9qZXRvcycsXG4gICAgICAnZGluYW1pYy1xdWVyeSc6ICdBZG1pbmlzdHJhw6fDo28gLSBDb25zdWx0YXMgRGluw6JtaWNhcycsXG4gICAgICAnbm90LWF1dGhvcml6ZWQnOiAnQWNlc3NvIE5lZ2FkbycsXG4gICAgICB0YXNrczogJ1RhcmVmYXMnLFxuICAgICAgbWlsZXN0b25lczogJ1NwcmludHMnLFxuICAgICAga2FuYmFuOiAnS2FuYmFuIEJvYXJkJyxcbiAgICAgIHZjczogJ0NvbnRyb2xlIGRlIFZlcnPDo28nLFxuICAgICAgcmVsZWFzZXM6ICdSZWxlYXNlcydcbiAgICB9LFxuICAgIHRpdGxlczoge1xuICAgICAgZGFzaGJvYXJkOiAnRGFzaGJvYXJkJyxcbiAgICAgIG1haWxTZW5kOiAnRW52aWFyIGUtbWFpbCcsXG4gICAgICB0YXNrTGlzdDogJ0xpc3RhIGRlIFRhcmVmYXMnLFxuICAgICAgdXNlckxpc3Q6ICdMaXN0YSBkZSBVc3XDoXJpb3MnLFxuICAgICAgYXVkaXRMaXN0OiAnTGlzdGEgZGUgTG9ncycsXG4gICAgICByZWdpc3RlcjogJ0Zvcm11bMOhcmlvIGRlIENhZGFzdHJvJyxcbiAgICAgIHJlc2V0UGFzc3dvcmQ6ICdSZWRlZmluaXIgU2VuaGEnLFxuICAgICAgdXBkYXRlOiAnRm9ybXVsw6FyaW8gZGUgQXR1YWxpemHDp8OjbycsXG4gICAgICB0YXNrczogJ1RhcmVmYXMnLFxuICAgICAgbWlsZXN0b25lczogJ1NwcmludHMnLFxuICAgICAga2FuYmFuOiAnS2FuYmFuIEJvYXJkJyxcbiAgICAgIHZjczogJ0NvbnRyb2xlIGRlIFZlcnPDo28nLFxuICAgICAgcmVsZWFzZXM6ICdSZWxlYXNlcydcbiAgICB9LFxuICAgIGFjdGlvbnM6IHtcbiAgICAgIHNlbmQ6ICdFbnZpYXInLFxuICAgICAgc2F2ZTogJ1NhbHZhcicsXG4gICAgICBjbGVhcjogJ0xpbXBhcicsXG4gICAgICBjbGVhckFsbDogJ0xpbXBhciBUdWRvJyxcbiAgICAgIHJlc3RhcnQ6ICdSZWluaWNpYXInLFxuICAgICAgZmlsdGVyOiAnRmlsdHJhcicsXG4gICAgICBzZWFyY2g6ICdQZXNxdWlzYXInLFxuICAgICAgbGlzdDogJ0xpc3RhcicsXG4gICAgICBlZGl0OiAnRWRpdGFyJyxcbiAgICAgIGNhbmNlbDogJ0NhbmNlbGFyJyxcbiAgICAgIHVwZGF0ZTogJ0F0dWFsaXphcicsXG4gICAgICByZW1vdmU6ICdSZW1vdmVyJyxcbiAgICAgIGdldE91dDogJ1NhaXInLFxuICAgICAgYWRkOiAnQWRpY2lvbmFyJyxcbiAgICAgIGluOiAnRW50cmFyJyxcbiAgICAgIGxvYWRJbWFnZTogJ0NhcnJlZ2FyIEltYWdlbScsXG4gICAgICBzaWdudXA6ICdDYWRhc3RyYXInLFxuICAgICAgY3JpYXJQcm9qZXRvOiAnQ3JpYXIgUHJvamV0bycsXG4gICAgICBwcm9qZWN0TGlzdDogJ0xpc3RhIGRlIFByb2pldG9zJyxcbiAgICAgIHRhc2tzTGlzdDogJ0xpc3RhIGRlIFRhcmVmYXMnLFxuICAgICAgbWlsZXN0b25lc0xpc3Q6ICdMaXN0YSBkZSBTcHJpbnRzJyxcbiAgICAgIGZpbmFsaXplOiAnRmluYWxpemFyJyxcbiAgICAgIHJlcGx5OiAnUmVzcG9uZGVyJ1xuICAgIH0sXG4gICAgZmllbGRzOiB7XG4gICAgICBkYXRlOiAnRGF0YScsXG4gICAgICBhY3Rpb246ICdBw6fDo28nLFxuICAgICAgYWN0aW9uczogJ0HDp8O1ZXMnLFxuICAgICAgYXVkaXQ6IHtcbiAgICAgICAgZGF0ZVN0YXJ0OiAnRGF0YSBJbmljaWFsJyxcbiAgICAgICAgZGF0ZUVuZDogJ0RhdGEgRmluYWwnLFxuICAgICAgICByZXNvdXJjZTogJ1JlY3Vyc28nLFxuICAgICAgICBhbGxSZXNvdXJjZXM6ICdUb2RvcyBSZWN1cnNvcycsXG4gICAgICAgIHR5cGU6IHtcbiAgICAgICAgICBjcmVhdGVkOiAnQ2FkYXN0cmFkbycsXG4gICAgICAgICAgdXBkYXRlZDogJ0F0dWFsaXphZG8nLFxuICAgICAgICAgIGRlbGV0ZWQ6ICdSZW1vdmlkbydcbiAgICAgICAgfVxuICAgICAgfSxcbiAgICAgIGxvZ2luOiB7XG4gICAgICAgIHJlc2V0UGFzc3dvcmQ6ICdFc3F1ZWNpIG1pbmhhIHNlbmhhJyxcbiAgICAgICAgY29uZmlybVBhc3N3b3JkOiAnQ29uZmlybWFyIHNlbmhhJ1xuICAgICAgfSxcbiAgICAgIG1haWw6IHtcbiAgICAgICAgdG86ICdQYXJhJyxcbiAgICAgICAgc3ViamVjdDogJ0Fzc3VudG8nLFxuICAgICAgICBtZXNzYWdlOiAnTWVuc2FnZW0nXG4gICAgICB9LFxuICAgICAgcXVlcnlEaW5hbWljOiB7XG4gICAgICAgIGZpbHRlcnM6ICdGaWx0cm9zJyxcbiAgICAgICAgcmVzdWx0czogJ1Jlc3VsdGFkb3MnLFxuICAgICAgICBtb2RlbDogJ01vZGVsJyxcbiAgICAgICAgYXR0cmlidXRlOiAnQXRyaWJ1dG8nLFxuICAgICAgICBvcGVyYXRvcjogJ09wZXJhZG9yJyxcbiAgICAgICAgcmVzb3VyY2U6ICdSZWN1cnNvJyxcbiAgICAgICAgdmFsdWU6ICdWYWxvcicsXG4gICAgICAgIG9wZXJhdG9yczoge1xuICAgICAgICAgIGVxdWFsczogJ0lndWFsJyxcbiAgICAgICAgICBkaWZlcmVudDogJ0RpZmVyZW50ZScsXG4gICAgICAgICAgY29udGVpbnM6ICdDb250w6ltJyxcbiAgICAgICAgICBzdGFydFdpdGg6ICdJbmljaWEgY29tJyxcbiAgICAgICAgICBmaW5pc2hXaXRoOiAnRmluYWxpemEgY29tJyxcbiAgICAgICAgICBiaWdnZXJUaGFuOiAnTWFpb3InLFxuICAgICAgICAgIGVxdWFsc09yQmlnZ2VyVGhhbjogJ01haW9yIG91IElndWFsJyxcbiAgICAgICAgICBsZXNzVGhhbjogJ01lbm9yJyxcbiAgICAgICAgICBlcXVhbHNPckxlc3NUaGFuOiAnTWVub3Igb3UgSWd1YWwnXG4gICAgICAgIH1cbiAgICAgIH0sXG4gICAgICBwcm9qZWN0OiB7XG4gICAgICAgIG5hbWU6ICdOb21lJyxcbiAgICAgICAgdG90YWxUYXNrOiAnVG90YWwgZGUgVGFyZWZhcydcbiAgICAgIH0sXG4gICAgICB0YXNrOiB7XG4gICAgICAgIGRvbmU6ICdOw6NvIEZlaXRvIC8gRmVpdG8nXG4gICAgICB9LFxuICAgICAgdXNlcjoge1xuICAgICAgICBwZXJmaWxzOiAnUGVyZmlzJyxcbiAgICAgICAgbmFtZU9yRW1haWw6ICdOb21lIG91IEVtYWlsJ1xuICAgICAgfVxuICAgIH0sXG4gICAgbGF5b3V0OiB7XG4gICAgICBtZW51OiB7XG4gICAgICAgIHByb2plY3RzOiAnUHJvamV0b3MnLFxuICAgICAgICBkYXNoYm9hcmQ6ICdEYXNoYm9hcmQnLFxuICAgICAgICBtaWxlc3RvbmVzOiAnU3ByaW50cycsXG4gICAgICAgIHRhc2tzOiAnVGFyZWZhcycsXG4gICAgICAgIGthbmJhbjogJ0thbmJhbicsXG4gICAgICAgIHZjczogJ0NvbnRyb2xlIGRlIFZlcnPDo28nLFxuICAgICAgICByZWxlYXNlczogJ1JlbGVhc2VzJ1xuICAgICAgfVxuICAgIH0sXG4gICAgdG9vbHRpcHM6IHtcbiAgICAgIGF1ZGl0OiB7XG4gICAgICAgIHZpZXdEZXRhaWw6ICdWaXN1YWxpemFyIERldGFsaGFtZW50bydcbiAgICAgIH0sXG4gICAgICB1c2VyOiB7XG4gICAgICAgIHBlcmZpbDogJ1BlcmZpbCcsXG4gICAgICAgIHRyYW5zZmVyOiAnVHJhbnNmZXJpcidcbiAgICAgIH0sXG4gICAgICB0YXNrOiB7XG4gICAgICAgIGxpc3RUYXNrOiAnTGlzdGFyIFRhcmVmYXMnXG4gICAgICB9XG4gICAgfVxuICB9KTtcbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb250cm9sbGVyKCdUYXNrSW5mb0NvbnRyb2xsZXInLCBUYXNrSW5mb0NvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gVGFza0luZm9Db250cm9sbGVyKCRjb250cm9sbGVyLCBUYXNrc1NlcnZpY2UsIGxvY2Fscykge1xuICAgIC8vQXR0cmlidXRlcyBCbG9ja1xuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICB2bS5jbG9zZURpYWxvZyA9IGNsb3NlRGlhbG9nO1xuXG4gICAgdm0ub25BY3RpdmF0ZSA9IGZ1bmN0aW9uICgpIHtcbiAgICAgIHZtLnRhc2sgPSBsb2NhbHMudGFzaztcbiAgICAgIHZtLnRhc2suZXN0aW1hdGVkX3RpbWUgPSB2bS50YXNrLmVzdGltYXRlZF90aW1lLnRvU3RyaW5nKCkgKyAnIGhvcmFzJztcbiAgICB9O1xuXG4gICAgZnVuY3Rpb24gY2xvc2VEaWFsb2coKSB7XG4gICAgICB2bS5jbG9zZSgpO1xuICAgICAgY29uc29sZS5sb2coXCJmZWNoYXJcIik7XG4gICAgfVxuXG4gICAgLy8gaW5zdGFudGlhdGUgYmFzZSBjb250cm9sbGVyXG4gICAgJGNvbnRyb2xsZXIoJ0NSVURDb250cm9sbGVyJywgeyB2bTogdm0sIG1vZGVsU2VydmljZTogVGFza3NTZXJ2aWNlLCBvcHRpb25zOiB7fSB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbnRyb2xsZXIoJ1VzZXJzRGlhbG9nQ29udHJvbGxlcicsIFVzZXJzRGlhbG9nQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBVc2Vyc0RpYWxvZ0NvbnRyb2xsZXIoJGNvbnRyb2xsZXIsIFVzZXJzU2VydmljZSwgUHJEaWFsb2csIC8vIE5PU09OQVJcbiAgdXNlckRpYWxvZ0lucHV0LCBvbkluaXQpIHtcblxuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICB2bS5vbkFjdGl2YXRlID0gb25BY3RpdmF0ZTtcbiAgICB2bS5hcHBseUZpbHRlcnMgPSBhcHBseUZpbHRlcnM7XG4gICAgdm0uY2xvc2UgPSBjbG9zZTtcblxuICAgIGlmIChhbmd1bGFyLmlzRGVmaW5lZCh1c2VyRGlhbG9nSW5wdXQpKSB7XG4gICAgICB2bS50cmFuc2ZlclVzZXIgPSB1c2VyRGlhbG9nSW5wdXQudHJhbnNmZXJVc2VyRm47XG4gICAgfVxuXG4gICAgLy8gaW5zdGFudGlhdGUgYmFzZSBjb250cm9sbGVyXG4gICAgJGNvbnRyb2xsZXIoJ0NSVURDb250cm9sbGVyJywge1xuICAgICAgdm06IHZtLFxuICAgICAgbW9kZWxTZXJ2aWNlOiBVc2Vyc1NlcnZpY2UsXG4gICAgICBzZWFyY2hPbkluaXQ6IG9uSW5pdCxcbiAgICAgIG9wdGlvbnM6IHtcbiAgICAgICAgcGVyUGFnZTogNVxuICAgICAgfVxuICAgIH0pO1xuXG4gICAgZnVuY3Rpb24gb25BY3RpdmF0ZSgpIHtcbiAgICAgIHZtLnF1ZXJ5RmlsdGVycyA9IHt9O1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGFwcGx5RmlsdGVycygpIHtcbiAgICAgIHJldHVybiBhbmd1bGFyLmV4dGVuZCh2bS5kZWZhdWx0UXVlcnlGaWx0ZXJzLCB2bS5xdWVyeUZpbHRlcnMpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGNsb3NlKCkge1xuICAgICAgUHJEaWFsb2cuY2xvc2UoKTtcbiAgICB9XG4gIH1cbn0pKCk7IiwiLyplc2xpbnQgYW5ndWxhci9maWxlLW5hbWU6IDAqL1xuKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcsIFtcbiAgICAnbmdBbmltYXRlJyxcbiAgICAnbmdBcmlhJyxcbiAgICAndWkucm91dGVyJyxcbiAgICAnbmdQcm9kZWInLFxuICAgICd1aS51dGlscy5tYXNrcycsXG4gICAgJ3RleHQtbWFzaycsXG4gICAgJ25nTWF0ZXJpYWwnLFxuICAgICdtb2RlbEZhY3RvcnknLFxuICAgICdtZC5kYXRhLnRhYmxlJyxcbiAgICAnbmdNYXRlcmlhbERhdGVQaWNrZXInLFxuICAgICdwYXNjYWxwcmVjaHQudHJhbnNsYXRlJyxcbiAgICAnYW5ndWxhckZpbGVVcGxvYWQnLFxuICAgICduZ01lc3NhZ2VzJyxcbiAgICAnanF3aWRnZXRzJyxcbiAgICAndWkubWFzaycsXG4gICAgJ25nUm91dGUnXSk7XG59KSgpO1xuIiwiKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb25maWcoY29uZmlnKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIGNvbmZpZyhHbG9iYWwsICRtZFRoZW1pbmdQcm92aWRlciwgJG1vZGVsRmFjdG9yeVByb3ZpZGVyLCAgLy8gTk9TT05BUlxuICAgICR0cmFuc2xhdGVQcm92aWRlciwgbW9tZW50LCAkbWRBcmlhUHJvdmlkZXIsICRtZERhdGVMb2NhbGVQcm92aWRlcikge1xuXG4gICAgJHRyYW5zbGF0ZVByb3ZpZGVyXG4gICAgICAudXNlTG9hZGVyKCdsYW5ndWFnZUxvYWRlcicpXG4gICAgICAudXNlU2FuaXRpemVWYWx1ZVN0cmF0ZWd5KCdlc2NhcGUnKTtcblxuICAgICR0cmFuc2xhdGVQcm92aWRlci51c2VQb3N0Q29tcGlsaW5nKHRydWUpO1xuXG4gICAgbW9tZW50LmxvY2FsZSgncHQtQlInKTtcblxuICAgIC8vb3Mgc2VydmnDp29zIHJlZmVyZW50ZSBhb3MgbW9kZWxzIHZhaSB1dGlsaXphciBjb21vIGJhc2UgbmFzIHVybHNcbiAgICAkbW9kZWxGYWN0b3J5UHJvdmlkZXIuZGVmYXVsdE9wdGlvbnMucHJlZml4ID0gR2xvYmFsLmFwaVBhdGg7XG5cbiAgICAvLyBDb25maWd1cmF0aW9uIHRoZW1lXG4gICAgJG1kVGhlbWluZ1Byb3ZpZGVyLnRoZW1lKCdkZWZhdWx0JylcbiAgICAgIC5wcmltYXJ5UGFsZXR0ZSgnZ3JleScsIHtcbiAgICAgICAgZGVmYXVsdDogJzgwMCdcbiAgICAgIH0pXG4gICAgICAuYWNjZW50UGFsZXR0ZSgnYW1iZXInKVxuICAgICAgLndhcm5QYWxldHRlKCdkZWVwLW9yYW5nZScpO1xuXG4gICAgLy8gRW5hYmxlIGJyb3dzZXIgY29sb3JcbiAgICAkbWRUaGVtaW5nUHJvdmlkZXIuZW5hYmxlQnJvd3NlckNvbG9yKCk7XG5cbiAgICAkbWRBcmlhUHJvdmlkZXIuZGlzYWJsZVdhcm5pbmdzKCk7XG5cbiAgICAkbWREYXRlTG9jYWxlUHJvdmlkZXIuZm9ybWF0RGF0ZSA9IGZ1bmN0aW9uKGRhdGUpIHtcbiAgICAgIHJldHVybiBkYXRlID8gbW9tZW50KGRhdGUpLmZvcm1hdCgnREQvTU0vWVlZWScpIDogJyc7XG4gICAgfTtcbiAgfVxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnRyb2xsZXIoJ0FwcENvbnRyb2xsZXInLCBBcHBDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8qKlxuICAgKiBDb250cm9sYWRvciByZXNwb25zw6F2ZWwgcG9yIGZ1bmNpb25hbGlkYWRlcyBxdWUgc8OjbyBhY2lvbmFkYXMgZW0gcXVhbHF1ZXIgdGVsYSBkbyBzaXN0ZW1hXG4gICAqXG4gICAqL1xuICBmdW5jdGlvbiBBcHBDb250cm9sbGVyKCRzdGF0ZSwgQXV0aCwgR2xvYmFsKSB7XG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIC8vYW5vIGF0dWFsIHBhcmEgc2VyIGV4aWJpZG8gbm8gcm9kYXDDqSBkbyBzaXN0ZW1hXG4gICAgdm0uYW5vQXR1YWwgPSBudWxsO1xuICAgIHZtLmFjdGl2ZVByb2plY3QgPSBudWxsO1xuXG4gICAgdm0ubG9nb3V0ICAgICA9IGxvZ291dDtcbiAgICB2bS5nZXRJbWFnZVBlcmZpbCA9IGdldEltYWdlUGVyZmlsO1xuICAgIHZtLmdldExvZ29NZW51ID0gZ2V0TG9nb01lbnU7XG4gICAgdm0uc2V0QWN0aXZlUHJvamVjdCA9IHNldEFjdGl2ZVByb2plY3Q7XG4gICAgdm0uZ2V0QWN0aXZlUHJvamVjdCA9IGdldEFjdGl2ZVByb2plY3Q7XG4gICAgdm0ucmVtb3ZlQWN0aXZlUHJvamVjdCA9IHJlbW92ZUFjdGl2ZVByb2plY3Q7XG5cbiAgICBhY3RpdmF0ZSgpO1xuXG4gICAgZnVuY3Rpb24gYWN0aXZhdGUoKSB7XG4gICAgICB2YXIgZGF0ZSA9IG5ldyBEYXRlKCk7XG5cbiAgICAgIHZtLmFub0F0dWFsID0gZGF0ZS5nZXRGdWxsWWVhcigpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGxvZ291dCgpIHtcbiAgICAgIEF1dGgubG9nb3V0KCkudGhlbihmdW5jdGlvbigpIHtcbiAgICAgICAgJHN0YXRlLmdvKEdsb2JhbC5sb2dpblN0YXRlKTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGdldEltYWdlUGVyZmlsKCkge1xuICAgICAgcmV0dXJuIChBdXRoLmN1cnJlbnRVc2VyICYmIEF1dGguY3VycmVudFVzZXIuaW1hZ2UpXG4gICAgICAgID8gQXV0aC5jdXJyZW50VXNlci5pbWFnZVxuICAgICAgICA6IEdsb2JhbC5pbWFnZVBhdGggKyAnL25vX2F2YXRhci5naWYnO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGdldExvZ29NZW51KCkge1xuICAgICAgcmV0dXJuIEdsb2JhbC5pbWFnZVBhdGggKyAnL2xvZ28tdmVydGljYWwucG5nJztcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBzZXRBY3RpdmVQcm9qZWN0KHByb2plY3QpIHtcbiAgICAgIGxvY2FsU3RvcmFnZS5zZXRJdGVtKCdwcm9qZWN0JywgcHJvamVjdCk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gZ2V0QWN0aXZlUHJvamVjdCgpIHtcbiAgICAgIHJldHVybiBsb2NhbFN0b3JhZ2UuZ2V0SXRlbSgncHJvamVjdCcpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIHJlbW92ZUFjdGl2ZVByb2plY3QoKSB7XG4gICAgICBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbSgncHJvamVjdCcpO1xuICAgIH1cblxuICB9XG5cbn0pKCk7XG4iLCIvKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCwgbm8tdW5kZWY6IDAqL1xuKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgLyoqXG4gICAqIFRyYW5zZm9ybWEgYmlibGlvdGVjYXMgZXh0ZXJuYXMgZW0gc2VydmnDp29zIGRvIGFuZ3VsYXIgcGFyYSBzZXIgcG9zc8OtdmVsIHV0aWxpemFyXG4gICAqIGF0cmF2w6lzIGRhIGluamXDp8OjbyBkZSBkZXBlbmTDqm5jaWFcbiAgICovXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb25zdGFudCgnbG9kYXNoJywgXylcbiAgICAuY29uc3RhbnQoJ21vbWVudCcsIG1vbWVudCk7XG5cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uc3RhbnQoJ0dsb2JhbCcsIHtcbiAgICAgIGFwcE5hbWU6ICdGcmVlbGFnaWxlJyxcbiAgICAgIGhvbWVTdGF0ZTogJ2FwcC5wcm9qZWN0cycsXG4gICAgICBsb2dpblVybDogJ2FwcC9sb2dpbicsXG4gICAgICBsb2dpblN0YXRlOiAnYXBwLmxvZ2luJyxcbiAgICAgIHJlc2V0UGFzc3dvcmRTdGF0ZTogJ2FwcC5wYXNzd29yZC1yZXNldCcsXG4gICAgICBub3RBdXRob3JpemVkU3RhdGU6ICdhcHAubm90LWF1dGhvcml6ZWQnLFxuICAgICAgdG9rZW5LZXk6ICdzZXJ2ZXJfdG9rZW4nLFxuICAgICAgY2xpZW50UGF0aDogJ2NsaWVudC9hcHAnLFxuICAgICAgYXBpUGF0aDogJ2FwaS92MScsXG4gICAgICBpbWFnZVBhdGg6ICdjbGllbnQvaW1hZ2VzJ1xuICAgIH0pO1xufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb25maWcocm91dGVzKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvdXRlcygkc3RhdGVQcm92aWRlciwgJHVybFJvdXRlclByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlclxuICAgICAgLnN0YXRlKCdhcHAnLCB7XG4gICAgICAgIHVybDogJy9hcHAnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL2xheW91dC9hcHAuaHRtbCcsXG4gICAgICAgIGFic3RyYWN0OiB0cnVlLFxuICAgICAgICByZXNvbHZlOiB7IC8vZW5zdXJlIGxhbmdzIGlzIHJlYWR5IGJlZm9yZSByZW5kZXIgdmlld1xuICAgICAgICAgIHRyYW5zbGF0ZVJlYWR5OiBbJyR0cmFuc2xhdGUnLCAnJHEnLCBmdW5jdGlvbigkdHJhbnNsYXRlLCAkcSkge1xuICAgICAgICAgICAgdmFyIGRlZmVycmVkID0gJHEuZGVmZXIoKTtcblxuICAgICAgICAgICAgJHRyYW5zbGF0ZS51c2UoJ3B0LUJSJykudGhlbihmdW5jdGlvbigpIHtcbiAgICAgICAgICAgICAgZGVmZXJyZWQucmVzb2x2ZSgpO1xuICAgICAgICAgICAgfSk7XG5cbiAgICAgICAgICAgIHJldHVybiBkZWZlcnJlZC5wcm9taXNlO1xuICAgICAgICAgIH1dXG4gICAgICAgIH1cbiAgICAgIH0pXG4gICAgICAuc3RhdGUoR2xvYmFsLm5vdEF1dGhvcml6ZWRTdGF0ZSwge1xuICAgICAgICB1cmw6ICcvYWNlc3NvLW5lZ2FkbycsXG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvbGF5b3V0L25vdC1hdXRob3JpemVkLmh0bWwnLFxuICAgICAgICBkYXRhOiB7IG5lZWRBdXRoZW50aWNhdGlvbjogZmFsc2UgfVxuICAgICAgfSk7XG5cbiAgICAkdXJsUm91dGVyUHJvdmlkZXIud2hlbignL2FwcCcsIEdsb2JhbC5sb2dpblVybCk7XG4gICAgJHVybFJvdXRlclByb3ZpZGVyLm90aGVyd2lzZShHbG9iYWwubG9naW5VcmwpO1xuICB9XG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLnJ1bihydW4pO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gcnVuKCRyb290U2NvcGUsICRzdGF0ZSwgJHN0YXRlUGFyYW1zLCBBdXRoLCBHbG9iYWwpIHsgLy8gTk9TT05BUlxuICAgIC8vc2V0YWRvIG5vIHJvb3RTY29wZSBwYXJhIHBvZGVyIHNlciBhY2Vzc2FkbyBuYXMgdmlld3Mgc2VtIHByZWZpeG8gZGUgY29udHJvbGxlclxuICAgICRyb290U2NvcGUuJHN0YXRlID0gJHN0YXRlO1xuICAgICRyb290U2NvcGUuJHN0YXRlUGFyYW1zID0gJHN0YXRlUGFyYW1zO1xuICAgICRyb290U2NvcGUuYXV0aCA9IEF1dGg7XG4gICAgJHJvb3RTY29wZS5nbG9iYWwgPSBHbG9iYWw7XG5cbiAgICAvL25vIGluaWNpbyBjYXJyZWdhIG8gdXN1w6FyaW8gZG8gbG9jYWxzdG9yYWdlIGNhc28gbyB1c3XDoXJpbyBlc3RhamEgYWJyaW5kbyBvIG5hdmVnYWRvclxuICAgIC8vcGFyYSB2b2x0YXIgYXV0ZW50aWNhZG9cbiAgICBBdXRoLnJldHJpZXZlVXNlckZyb21Mb2NhbFN0b3JhZ2UoKTtcbiAgfVxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnRyb2xsZXIoJ0F1ZGl0Q29udHJvbGxlcicsIEF1ZGl0Q29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBBdWRpdENvbnRyb2xsZXIoJGNvbnRyb2xsZXIsIEF1ZGl0U2VydmljZSwgUHJEaWFsb2csIEdsb2JhbCwgJHRyYW5zbGF0ZSkgeyAvLyBOT1NPTkFSXG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIHZtLm9uQWN0aXZhdGUgPSBvbkFjdGl2YXRlO1xuICAgIHZtLmFwcGx5RmlsdGVycyA9IGFwcGx5RmlsdGVycztcbiAgICB2bS52aWV3RGV0YWlsID0gdmlld0RldGFpbDtcblxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHsgdm06IHZtLCBtb2RlbFNlcnZpY2U6IEF1ZGl0U2VydmljZSwgb3B0aW9uczoge30gfSk7XG5cbiAgICBmdW5jdGlvbiBvbkFjdGl2YXRlKCkge1xuICAgICAgdm0ubW9kZWxzID0gW107XG4gICAgICB2bS5xdWVyeUZpbHRlcnMgPSB7fTtcblxuICAgICAgLy9QZWdhIHRvZG9zIG9zIG1vZGVscyBkbyBzZXJ2ZXIgZSBtb250YSB1bWEgbGlzdGEgcHJvIENvbWJvQm94XG4gICAgICBBdWRpdFNlcnZpY2UuZ2V0QXVkaXRlZE1vZGVscygpLnRoZW4oZnVuY3Rpb24oZGF0YSkge1xuICAgICAgICB2YXIgbW9kZWxzID0gW3sgaWQ6ICcnLCBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KCdnbG9iYWwuYWxsJykgfV07XG5cbiAgICAgICAgZGF0YS5tb2RlbHMuc29ydCgpO1xuXG4gICAgICAgIGZvciAodmFyIGluZGV4ID0gMDsgaW5kZXggPCBkYXRhLm1vZGVscy5sZW5ndGg7IGluZGV4KyspIHtcbiAgICAgICAgICB2YXIgbW9kZWwgPSBkYXRhLm1vZGVsc1tpbmRleF07XG5cbiAgICAgICAgICBtb2RlbHMucHVzaCh7XG4gICAgICAgICAgICBpZDogbW9kZWwsXG4gICAgICAgICAgICBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KCdtb2RlbHMuJyArIG1vZGVsLnRvTG93ZXJDYXNlKCkpXG4gICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICB2bS5tb2RlbHMgPSBtb2RlbHM7XG4gICAgICAgIHZtLnF1ZXJ5RmlsdGVycy5tb2RlbCA9IHZtLm1vZGVsc1swXS5pZDtcbiAgICAgIH0pO1xuXG4gICAgICB2bS50eXBlcyA9IEF1ZGl0U2VydmljZS5saXN0VHlwZXMoKTtcbiAgICAgIHZtLnF1ZXJ5RmlsdGVycy50eXBlID0gdm0udHlwZXNbMF0uaWQ7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gYXBwbHlGaWx0ZXJzKGRlZmF1bHRRdWVyeUZpbHRlcnMpIHtcbiAgICAgIHJldHVybiBhbmd1bGFyLmV4dGVuZChkZWZhdWx0UXVlcnlGaWx0ZXJzLCB2bS5xdWVyeUZpbHRlcnMpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIHZpZXdEZXRhaWwoYXVkaXREZXRhaWwpIHtcbiAgICAgIHZhciBjb25maWcgPSB7XG4gICAgICAgIGxvY2FsczogeyBhdWRpdERldGFpbDogYXVkaXREZXRhaWwgfSxcbiAgICAgICAgLyoqIEBuZ0luamVjdCAqL1xuICAgICAgICBjb250cm9sbGVyOiBmdW5jdGlvbihhdWRpdERldGFpbCwgUHJEaWFsb2cpIHtcbiAgICAgICAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgICAgICAgdm0uY2xvc2UgPSBjbG9zZTtcblxuICAgICAgICAgIGFjdGl2YXRlKCk7XG5cbiAgICAgICAgICBmdW5jdGlvbiBhY3RpdmF0ZSgpIHtcbiAgICAgICAgICAgIGlmIChhbmd1bGFyLmlzQXJyYXkoYXVkaXREZXRhaWwub2xkKSAmJiBhdWRpdERldGFpbC5vbGQubGVuZ3RoID09PSAwKSBhdWRpdERldGFpbC5vbGQgPSBudWxsO1xuICAgICAgICAgICAgaWYgKGFuZ3VsYXIuaXNBcnJheShhdWRpdERldGFpbC5uZXcpICYmIGF1ZGl0RGV0YWlsLm5ldy5sZW5ndGggPT09IDApIGF1ZGl0RGV0YWlsLm5ldyA9IG51bGw7XG5cbiAgICAgICAgICAgIHZtLmF1ZGl0RGV0YWlsID0gYXVkaXREZXRhaWw7XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgZnVuY3Rpb24gY2xvc2UoKSB7XG4gICAgICAgICAgICBQckRpYWxvZy5jbG9zZSgpO1xuICAgICAgICAgIH1cblxuICAgICAgICB9LFxuICAgICAgICBjb250cm9sbGVyQXM6ICdhdWRpdERldGFpbEN0cmwnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL2F1ZGl0L2F1ZGl0LWRldGFpbC5odG1sJyxcbiAgICAgICAgaGFzQmFja2Ryb3A6IHRydWVcbiAgICAgIH07XG5cbiAgICAgIFByRGlhbG9nLmN1c3RvbShjb25maWcpO1xuICAgIH1cblxuICB9XG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqXG4gICAqIEFycXVpdm8gZGUgY29uZmlndXJhw6fDo28gY29tIGFzIHJvdGFzIGVzcGVjw61maWNhcyBkZSBhdWRpdG9yaWFcbiAgICpcbiAgICogQHBhcmFtIHthbnl9ICRzdGF0ZVByb3ZpZGVyXG4gICAqIEBwYXJhbSB7YW55fSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlclxuICAgICAgLnN0YXRlKCdhcHAuYXVkaXQnLCB7XG4gICAgICAgIHVybDogJy9hdWRpdG9yaWEnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL2F1ZGl0L2F1ZGl0Lmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnQXVkaXRDb250cm9sbGVyIGFzIGF1ZGl0Q3RybCcsXG4gICAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiB0cnVlLCBuZWVkUHJvZmlsZTogWydhZG1pbiddIH1cbiAgICAgIH0pO1xuXG4gIH1cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmFjdG9yeSgnQXVkaXRTZXJ2aWNlJywgQXVkaXRTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIEF1ZGl0U2VydmljZShzZXJ2aWNlRmFjdG9yeSwgJHRyYW5zbGF0ZSkge1xuICAgIHJldHVybiBzZXJ2aWNlRmFjdG9yeSgnYXVkaXQnLCB7XG4gICAgICBhY3Rpb25zOiB7XG4gICAgICAgIGdldEF1ZGl0ZWRNb2RlbHM6IHtcbiAgICAgICAgICBtZXRob2Q6ICdHRVQnLFxuICAgICAgICAgIHVybDogJ21vZGVscydcbiAgICAgICAgfVxuICAgICAgfSxcbiAgICAgIGluc3RhbmNlOiB7XG4gICAgICB9LFxuICAgICAgbGlzdFR5cGVzOiBmdW5jdGlvbigpIHtcbiAgICAgICAgdmFyIGF1ZGl0UGF0aCA9ICd2aWV3cy5maWVsZHMuYXVkaXQuJztcblxuICAgICAgICByZXR1cm4gW1xuICAgICAgICAgIHsgaWQ6ICcnLCBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KGF1ZGl0UGF0aCArICdhbGxSZXNvdXJjZXMnKSB9LFxuICAgICAgICAgIHsgaWQ6ICdjcmVhdGVkJywgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudChhdWRpdFBhdGggKyAndHlwZS5jcmVhdGVkJykgfSxcbiAgICAgICAgICB7IGlkOiAndXBkYXRlZCcsIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoYXVkaXRQYXRoICsgJ3R5cGUudXBkYXRlZCcpIH0sXG4gICAgICAgICAgeyBpZDogJ2RlbGV0ZWQnLCBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KGF1ZGl0UGF0aCArICd0eXBlLmRlbGV0ZWQnKSB9XG4gICAgICAgIF07XG4gICAgICB9XG4gICAgfSk7XG4gIH1cblxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb25maWcocm91dGVzKTtcblxuICAvKipcbiAgICogQXJxdWl2byBkZSBjb25maWd1cmHDp8OjbyBjb20gYXMgcm90YXMgZXNwZWPDrWZpY2FzIGRvIHJlY3Vyc28gdXNlclxuICAgKlxuICAgKiBAcGFyYW0ge2FueX0gJHN0YXRlUHJvdmlkZXJcbiAgICogQHBhcmFtIHthbnl9IEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyXG4gICAgICAuc3RhdGUoR2xvYmFsLnJlc2V0UGFzc3dvcmRTdGF0ZSwge1xuICAgICAgICB1cmw6ICcvcGFzc3dvcmQvcmVzZXQvOnRva2VuJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9hdXRoL3Jlc2V0LXBhc3MtZm9ybS5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ1Bhc3N3b3JkQ29udHJvbGxlciBhcyBwYXNzQ3RybCcsXG4gICAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiBmYWxzZSB9XG4gICAgICB9KVxuICAgICAgLnN0YXRlKEdsb2JhbC5sb2dpblN0YXRlLCB7XG4gICAgICAgIHVybDogJy9sb2dpbicsXG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvYXV0aC9sb2dpbi5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ0xvZ2luQ29udHJvbGxlciBhcyBsb2dpbkN0cmwnLFxuICAgICAgICBkYXRhOiB7IG5lZWRBdXRoZW50aWNhdGlvbjogZmFsc2UgfVxuICAgICAgfSk7XG5cbiAgfVxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5mYWN0b3J5KCdBdXRoJywgQXV0aCk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBBdXRoKCRodHRwLCAkcSwgR2xvYmFsLCBVc2Vyc1NlcnZpY2UpIHsgLy8gTk9TT05BUlxuICAgIHZhciBhdXRoID0ge1xuICAgICAgbG9naW46IGxvZ2luLFxuICAgICAgbG9nb3V0OiBsb2dvdXQsXG4gICAgICB1cGRhdGVDdXJyZW50VXNlcjogdXBkYXRlQ3VycmVudFVzZXIsXG4gICAgICByZXRyaWV2ZVVzZXJGcm9tTG9jYWxTdG9yYWdlOiByZXRyaWV2ZVVzZXJGcm9tTG9jYWxTdG9yYWdlLFxuICAgICAgYXV0aGVudGljYXRlZDogYXV0aGVudGljYXRlZCxcbiAgICAgIHNlbmRFbWFpbFJlc2V0UGFzc3dvcmQ6IHNlbmRFbWFpbFJlc2V0UGFzc3dvcmQsXG4gICAgICByZW1vdGVWYWxpZGF0ZVRva2VuOiByZW1vdGVWYWxpZGF0ZVRva2VuLFxuICAgICAgZ2V0VG9rZW46IGdldFRva2VuLFxuICAgICAgc2V0VG9rZW46IHNldFRva2VuLFxuICAgICAgY2xlYXJUb2tlbjogY2xlYXJUb2tlbixcbiAgICAgIGN1cnJlbnRVc2VyOiBudWxsXG4gICAgfTtcblxuICAgIGZ1bmN0aW9uIGNsZWFyVG9rZW4oKSB7XG4gICAgICBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbShHbG9iYWwudG9rZW5LZXkpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIHNldFRva2VuKHRva2VuKSB7XG4gICAgICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbShHbG9iYWwudG9rZW5LZXksIHRva2VuKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBnZXRUb2tlbigpIHtcbiAgICAgIHJldHVybiBsb2NhbFN0b3JhZ2UuZ2V0SXRlbShHbG9iYWwudG9rZW5LZXkpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIHJlbW90ZVZhbGlkYXRlVG9rZW4oKSB7XG4gICAgICB2YXIgZGVmZXJyZWQgPSAkcS5kZWZlcigpO1xuXG4gICAgICBpZiAoYXV0aC5hdXRoZW50aWNhdGVkKCkpIHtcbiAgICAgICAgJGh0dHAuZ2V0KEdsb2JhbC5hcGlQYXRoICsgJy9hdXRoZW50aWNhdGUvY2hlY2snKVxuICAgICAgICAgIC50aGVuKGZ1bmN0aW9uKCkge1xuICAgICAgICAgICAgZGVmZXJyZWQucmVzb2x2ZSh0cnVlKTtcbiAgICAgICAgICB9LCBmdW5jdGlvbigpIHtcbiAgICAgICAgICAgIGF1dGgubG9nb3V0KCk7XG5cbiAgICAgICAgICAgIGRlZmVycmVkLnJlamVjdChmYWxzZSk7XG4gICAgICAgICAgfSk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBhdXRoLmxvZ291dCgpO1xuXG4gICAgICAgIGRlZmVycmVkLnJlamVjdChmYWxzZSk7XG4gICAgICB9XG5cbiAgICAgIHJldHVybiBkZWZlcnJlZC5wcm9taXNlO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFZlcmlmaWNhIHNlIG8gdXN1w6FyaW8gZXN0w6EgYXV0ZW50aWNhZG9cbiAgICAgKlxuICAgICAqIEByZXR1cm5zIHtib29sZWFufVxuICAgICAqL1xuICAgIGZ1bmN0aW9uIGF1dGhlbnRpY2F0ZWQoKSB7XG4gICAgICByZXR1cm4gYXV0aC5nZXRUb2tlbigpICE9PSBudWxsXG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVjdXBlcmEgbyB1c3XDoXJpbyBkbyBsb2NhbFN0b3JhZ2VcbiAgICAgKi9cbiAgICBmdW5jdGlvbiByZXRyaWV2ZVVzZXJGcm9tTG9jYWxTdG9yYWdlKCkge1xuICAgICAgdmFyIHVzZXIgPSBsb2NhbFN0b3JhZ2UuZ2V0SXRlbSgndXNlcicpO1xuXG4gICAgICBpZiAodXNlcikge1xuICAgICAgICBhdXRoLmN1cnJlbnRVc2VyID0gYW5ndWxhci5tZXJnZShuZXcgVXNlcnNTZXJ2aWNlKCksIGFuZ3VsYXIuZnJvbUpzb24odXNlcikpO1xuICAgICAgfVxuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEd1YXJkYSBvIHVzdcOhcmlvIG5vIGxvY2FsU3RvcmFnZSBwYXJhIGNhc28gbyB1c3XDoXJpbyBmZWNoZSBlIGFicmEgbyBuYXZlZ2Fkb3JcbiAgICAgKiBkZW50cm8gZG8gdGVtcG8gZGUgc2Vzc8OjbyBzZWphIHBvc3PDrXZlbCByZWN1cGVyYXIgbyB0b2tlbiBhdXRlbnRpY2Fkby5cbiAgICAgKlxuICAgICAqIE1hbnTDqW0gYSB2YXJpw6F2ZWwgYXV0aC5jdXJyZW50VXNlciBwYXJhIGZhY2lsaXRhciBvIGFjZXNzbyBhbyB1c3XDoXJpbyBsb2dhZG8gZW0gdG9kYSBhIGFwbGljYcOnw6NvXG4gICAgICpcbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSB1c2VyIFVzdcOhcmlvIGEgc2VyIGF0dWFsaXphZG8uIENhc28gc2VqYSBwYXNzYWRvIG51bGwgbGltcGFcbiAgICAgKiB0b2RhcyBhcyBpbmZvcm1hw6fDtWVzIGRvIHVzdcOhcmlvIGNvcnJlbnRlLlxuICAgICAqL1xuICAgIGZ1bmN0aW9uIHVwZGF0ZUN1cnJlbnRVc2VyKHVzZXIpIHtcbiAgICAgIHZhciBkZWZlcnJlZCA9ICRxLmRlZmVyKCk7XG5cbiAgICAgIGlmICh1c2VyKSB7XG4gICAgICAgIHVzZXIgPSBhbmd1bGFyLm1lcmdlKG5ldyBVc2Vyc1NlcnZpY2UoKSwgdXNlcik7XG5cbiAgICAgICAgdmFyIGpzb25Vc2VyID0gYW5ndWxhci50b0pzb24odXNlcik7XG5cbiAgICAgICAgbG9jYWxTdG9yYWdlLnNldEl0ZW0oJ3VzZXInLCBqc29uVXNlcik7XG4gICAgICAgIGF1dGguY3VycmVudFVzZXIgPSB1c2VyO1xuXG4gICAgICAgIGRlZmVycmVkLnJlc29sdmUodXNlcik7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbSgndXNlcicpO1xuICAgICAgICBhdXRoLmN1cnJlbnRVc2VyID0gbnVsbDtcbiAgICAgICAgYXV0aC5jbGVhclRva2VuKCk7XG5cbiAgICAgICAgZGVmZXJyZWQucmVqZWN0KCk7XG4gICAgICB9XG5cbiAgICAgIHJldHVybiBkZWZlcnJlZC5wcm9taXNlO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWxpemEgbyBsb2dpbiBkbyB1c3XDoXJpb1xuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IGNyZWRlbnRpYWxzIEVtYWlsIGUgU2VuaGEgZG8gdXN1w6FyaW9cbiAgICAgKiBAcmV0dXJucyB7cHJvbWlzZX0gVW1hIHByb21pc2UgY29tIG8gcmVzdWx0YWRvIGRvIGNoYW1hZGEgbm8gYmFja2VuZFxuICAgICAqL1xuICAgIGZ1bmN0aW9uIGxvZ2luKGNyZWRlbnRpYWxzKSB7XG4gICAgICB2YXIgZGVmZXJyZWQgPSAkcS5kZWZlcigpO1xuXG4gICAgICAkaHR0cC5wb3N0KEdsb2JhbC5hcGlQYXRoICsgJy9hdXRoZW50aWNhdGUnLCBjcmVkZW50aWFscylcbiAgICAgICAgLnRoZW4oZnVuY3Rpb24ocmVzcG9uc2UpIHtcbiAgICAgICAgICBhdXRoLnNldFRva2VuKHJlc3BvbnNlLmRhdGEudG9rZW4pO1xuXG4gICAgICAgICAgcmV0dXJuICRodHRwLmdldChHbG9iYWwuYXBpUGF0aCArICcvYXV0aGVudGljYXRlL3VzZXInKTtcbiAgICAgICAgfSlcbiAgICAgICAgLnRoZW4oZnVuY3Rpb24ocmVzcG9uc2UpIHtcbiAgICAgICAgICBhdXRoLnVwZGF0ZUN1cnJlbnRVc2VyKHJlc3BvbnNlLmRhdGEudXNlcik7XG5cbiAgICAgICAgICBkZWZlcnJlZC5yZXNvbHZlKCk7XG4gICAgICAgIH0sIGZ1bmN0aW9uKGVycm9yKSB7XG4gICAgICAgICAgYXV0aC5sb2dvdXQoKTtcblxuICAgICAgICAgIGRlZmVycmVkLnJlamVjdChlcnJvcik7XG4gICAgICAgIH0pO1xuXG4gICAgICByZXR1cm4gZGVmZXJyZWQucHJvbWlzZTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBEZXNsb2dhIG9zIHVzdcOhcmlvcy4gQ29tbyBuw6NvIHRlbiBuZW5odW1hIGluZm9ybWHDp8OjbyBuYSBzZXNzw6NvIGRvIHNlcnZpZG9yXG4gICAgICogZSB1bSB0b2tlbiB1bWEgdmV6IGdlcmFkbyBuw6NvIHBvZGUsIHBvciBwYWRyw6NvLCBzZXIgaW52YWxpZGFkbyBhbnRlcyBkbyBzZXUgdGVtcG8gZGUgZXhwaXJhw6fDo28sXG4gICAgICogc29tZW50ZSBhcGFnYW1vcyBvcyBkYWRvcyBkbyB1c3XDoXJpbyBlIG8gdG9rZW4gZG8gbmF2ZWdhZG9yIHBhcmEgZWZldGl2YXIgbyBsb2dvdXQuXG4gICAgICpcbiAgICAgKiBAcmV0dXJucyB7cHJvbWlzZX0gVW1hIHByb21pc2UgY29tIG8gcmVzdWx0YWRvIGRhIG9wZXJhw6fDo29cbiAgICAgKi9cbiAgICBmdW5jdGlvbiBsb2dvdXQoKSB7XG4gICAgICB2YXIgZGVmZXJyZWQgPSAkcS5kZWZlcigpO1xuXG4gICAgICBhdXRoLnVwZGF0ZUN1cnJlbnRVc2VyKG51bGwpO1xuICAgICAgZGVmZXJyZWQucmVzb2x2ZSgpO1xuXG4gICAgICByZXR1cm4gZGVmZXJyZWQucHJvbWlzZTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBFbnZpYSB1bSBlbWFpbCBwYXJhIHJlY3VwZXJhw6fDo28gZGUgc2VuaGFcbiAgICAgKiBAcGFyYW0ge09iamVjdH0gcmVzZXREYXRhIC0gT2JqZXRvIGNvbnRlbmRvIG8gZW1haWxcbiAgICAgKiBAcmV0dXJuIHtQcm9taXNlfSAtIFJldG9ybmEgdW1hIHByb21pc2UgcGFyYSBzZXIgcmVzb2x2aWRhXG4gICAgICovXG4gICAgZnVuY3Rpb24gc2VuZEVtYWlsUmVzZXRQYXNzd29yZChyZXNldERhdGEpIHtcbiAgICAgIHZhciBkZWZlcnJlZCA9ICRxLmRlZmVyKCk7XG5cbiAgICAgICRodHRwLnBvc3QoR2xvYmFsLmFwaVBhdGggKyAnL3Bhc3N3b3JkL2VtYWlsJywgcmVzZXREYXRhKVxuICAgICAgICAudGhlbihmdW5jdGlvbihyZXNwb25zZSkge1xuICAgICAgICAgIGRlZmVycmVkLnJlc29sdmUocmVzcG9uc2UuZGF0YSk7XG4gICAgICAgIH0sIGZ1bmN0aW9uKGVycm9yKSB7XG4gICAgICAgICAgZGVmZXJyZWQucmVqZWN0KGVycm9yKTtcbiAgICAgICAgfSk7XG5cbiAgICAgIHJldHVybiBkZWZlcnJlZC5wcm9taXNlO1xuICAgIH1cblxuICAgIHJldHVybiBhdXRoO1xuICB9XG5cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb250cm9sbGVyKCdMb2dpbkNvbnRyb2xsZXInLCBMb2dpbkNvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gTG9naW5Db250cm9sbGVyKCRzdGF0ZSwgQXV0aCwgR2xvYmFsLCBQckRpYWxvZykge1xuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICB2bS5sb2dpbiA9IGxvZ2luO1xuICAgIHZtLm9wZW5EaWFsb2dSZXNldFBhc3MgPSBvcGVuRGlhbG9nUmVzZXRQYXNzO1xuICAgIHZtLm9wZW5EaWFsb2dTaWduVXAgPSBvcGVuRGlhbG9nU2lnblVwO1xuXG4gICAgYWN0aXZhdGUoKTtcblxuICAgIGZ1bmN0aW9uIGFjdGl2YXRlKCkge1xuICAgICAgdm0uY3JlZGVudGlhbHMgPSB7fTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBsb2dpbigpIHtcbiAgICAgIHZhciBjcmVkZW50aWFscyA9IHtcbiAgICAgICAgZW1haWw6IHZtLmNyZWRlbnRpYWxzLmVtYWlsLFxuICAgICAgICBwYXNzd29yZDogdm0uY3JlZGVudGlhbHMucGFzc3dvcmRcbiAgICAgIH07XG5cbiAgICAgIEF1dGgubG9naW4oY3JlZGVudGlhbHMpLnRoZW4oZnVuY3Rpb24oKSB7XG4gICAgICAgICRzdGF0ZS5nbyhHbG9iYWwuaG9tZVN0YXRlKTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEV4aWJlIG8gZGlhbG9nIHBhcmEgcmVjdXBlcmHDp8OjbyBkZSBzZW5oYVxuICAgICAqL1xuICAgIGZ1bmN0aW9uIG9wZW5EaWFsb2dSZXNldFBhc3MoKSB7XG4gICAgICB2YXIgY29uZmlnID0ge1xuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL2F1dGgvc2VuZC1yZXNldC1kaWFsb2cuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdQYXNzd29yZENvbnRyb2xsZXIgYXMgcGFzc0N0cmwnLFxuICAgICAgICBoYXNCYWNrZHJvcDogdHJ1ZVxuICAgICAgfVxuXG4gICAgICBQckRpYWxvZy5jdXN0b20oY29uZmlnKTtcbiAgICB9XG4gICAgLyoqXG4gICAgICogRXhpYmUgbyBkaWFsb2cgcGFyYSByZWN1cGVyYcOnw6NvIGRlIHNlbmhhXG4gICAgICovXG4gICAgZnVuY3Rpb24gb3BlbkRpYWxvZ1NpZ25VcCgpIHtcbiAgICAgIHZhciBjb25maWcgPSB7XG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvdXNlcnMvdXNlci1mb3JtLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnVXNlcnNDb250cm9sbGVyIGFzIHVzZXJzQ3RybCcsXG4gICAgICAgIGhhc0JhY2tkcm9wOiB0cnVlXG4gICAgICB9XG5cbiAgICAgIFByRGlhbG9nLmN1c3RvbShjb25maWcpO1xuICAgIH1cblxuICB9XG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29udHJvbGxlcignUGFzc3dvcmRDb250cm9sbGVyJywgUGFzc3dvcmRDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIFBhc3N3b3JkQ29udHJvbGxlcihHbG9iYWwsICRzdGF0ZVBhcmFtcywgJGh0dHAsICR0aW1lb3V0LCAkc3RhdGUsIC8vIE5PU09OQVJcbiAgICBQclRvYXN0LCBQckRpYWxvZywgQXV0aCwgJHRyYW5zbGF0ZSkge1xuXG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIHZtLnNlbmRSZXNldCA9IHNlbmRSZXNldDtcbiAgICB2bS5jbG9zZURpYWxvZyA9IGNsb3NlRGlhbG9nO1xuICAgIHZtLmNsZWFuRm9ybSA9IGNsZWFuRm9ybTtcbiAgICB2bS5zZW5kRW1haWxSZXNldFBhc3N3b3JkID0gc2VuZEVtYWlsUmVzZXRQYXNzd29yZDtcblxuICAgIGFjdGl2YXRlKCk7XG5cbiAgICBmdW5jdGlvbiBhY3RpdmF0ZSgpIHtcbiAgICAgIHZtLnJlc2V0ID0geyBlbWFpbDogJycsIHRva2VuOiAkc3RhdGVQYXJhbXMudG9rZW4gfTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFsaXphIGEgYWx0ZXJhw6fDo28gZGEgc2VuaGEgZG8gdXN1w6FyaW8gZSBvIHJlZGlyZWNpb25hIHBhcmEgYSB0ZWxhIGRlIGxvZ2luXG4gICAgICovXG4gICAgZnVuY3Rpb24gc2VuZFJlc2V0KCkge1xuICAgICAgJGh0dHAucG9zdChHbG9iYWwuYXBpUGF0aCArICcvcGFzc3dvcmQvcmVzZXQnLCB2bS5yZXNldClcbiAgICAgICAgLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICAgIFByVG9hc3Quc3VjY2VzcygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLm9wZXJhdGlvblN1Y2Nlc3MnKSk7XG4gICAgICAgICAgJHRpbWVvdXQoZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgJHN0YXRlLmdvKEdsb2JhbC5sb2dpblN0YXRlKTtcbiAgICAgICAgICB9LCAxNTAwKTtcbiAgICAgICAgfSwgZnVuY3Rpb24gKGVycm9yKSB7XG4gICAgICAgICAgaWYgKGVycm9yLnN0YXR1cyAhPT0gNDAwICYmIGVycm9yLnN0YXR1cyAhPT0gNTAwKSB7XG4gICAgICAgICAgICB2YXIgbXNnID0gJyc7XG5cbiAgICAgICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgZXJyb3IuZGF0YS5wYXNzd29yZC5sZW5ndGg7IGkrKykge1xuICAgICAgICAgICAgICBtc2cgKz0gZXJyb3IuZGF0YS5wYXNzd29yZFtpXSArICc8YnI+JztcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIFByVG9hc3QuZXJyb3IobXNnLnRvVXBwZXJDYXNlKCkpO1xuICAgICAgICAgIH1cbiAgICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogRW52aWEgdW0gZW1haWwgZGUgcmVjdXBlcmHDp8OjbyBkZSBzZW5oYSBjb20gbyB0b2tlbiBkbyB1c3XDoXJpb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIHNlbmRFbWFpbFJlc2V0UGFzc3dvcmQoKSB7XG5cbiAgICAgIGlmICh2bS5yZXNldC5lbWFpbCA9PT0gJycpIHtcbiAgICAgICAgUHJUb2FzdC5lcnJvcigkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnZhbGlkYXRlLmZpZWxkUmVxdWlyZWQnLCB7IGZpZWxkOiAnZW1haWwnIH0pKTtcbiAgICAgICAgcmV0dXJuO1xuICAgICAgfVxuXG4gICAgICBBdXRoLnNlbmRFbWFpbFJlc2V0UGFzc3dvcmQodm0ucmVzZXQpLnRoZW4oZnVuY3Rpb24gKGRhdGEpIHtcbiAgICAgICAgUHJUb2FzdC5zdWNjZXNzKGRhdGEubWVzc2FnZSk7XG5cbiAgICAgICAgdm0uY2xlYW5Gb3JtKCk7XG4gICAgICAgIHZtLmNsb3NlRGlhbG9nKCk7XG4gICAgICB9LCBmdW5jdGlvbiAoZXJyb3IpIHtcbiAgICAgICAgaWYgKGVycm9yLmRhdGEuZW1haWwgJiYgZXJyb3IuZGF0YS5lbWFpbC5sZW5ndGggPiAwKSB7XG4gICAgICAgICAgdmFyIG1zZyA9ICcnO1xuXG4gICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCBlcnJvci5kYXRhLmVtYWlsLmxlbmd0aDsgaSsrKSB7XG4gICAgICAgICAgICBtc2cgKz0gZXJyb3IuZGF0YS5lbWFpbFtpXSArICc8YnI+JztcbiAgICAgICAgICB9XG5cbiAgICAgICAgICBQclRvYXN0LmVycm9yKG1zZyk7XG4gICAgICAgIH1cbiAgICAgIH0pO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGNsb3NlRGlhbG9nKCkge1xuICAgICAgUHJEaWFsb2cuY2xvc2UoKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBjbGVhbkZvcm0oKSB7XG4gICAgICB2bS5yZXNldC5lbWFpbCA9ICcnO1xuICAgIH1cblxuICB9XG5cbn0pKCk7XG4iLCIvKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCovXG4oZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmFjdG9yeSgnc2VydmljZUZhY3RvcnknLCBzZXJ2aWNlRmFjdG9yeSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvKipcbiAgICogTWFpcyBpbmZvcm1hw6fDtWVzOlxuICAgKiBodHRwczovL2dpdGh1Yi5jb20vc3dpbWxhbmUvYW5ndWxhci1tb2RlbC1mYWN0b3J5L3dpa2kvQVBJXG4gICAqL1xuICBmdW5jdGlvbiBzZXJ2aWNlRmFjdG9yeSgkbW9kZWxGYWN0b3J5KSB7XG4gICAgcmV0dXJuIGZ1bmN0aW9uKHVybCwgb3B0aW9ucykge1xuICAgICAgdmFyIG1vZGVsO1xuICAgICAgdmFyIGRlZmF1bHRPcHRpb25zID0ge1xuICAgICAgICBhY3Rpb25zOiB7XG4gICAgICAgICAgLyoqXG4gICAgICAgICAgICogU2VydmnDp28gY29tdW0gcGFyYSByZWFsaXphciBidXNjYSBjb20gcGFnaW5hw6fDo29cbiAgICAgICAgICAgKiBPIG1lc21vIGVzcGVyYSBxdWUgc2VqYSByZXRvcm5hZG8gdW0gb2JqZXRvIGNvbSBpdGVtcyBlIHRvdGFsXG4gICAgICAgICAgICovXG4gICAgICAgICAgcGFnaW5hdGU6IHtcbiAgICAgICAgICAgIG1ldGhvZDogJ0dFVCcsXG4gICAgICAgICAgICBpc0FycmF5OiBmYWxzZSxcbiAgICAgICAgICAgIHdyYXA6IGZhbHNlLFxuICAgICAgICAgICAgYWZ0ZXJSZXF1ZXN0OiBmdW5jdGlvbihyZXNwb25zZSkge1xuICAgICAgICAgICAgICBpZiAocmVzcG9uc2VbJ2l0ZW1zJ10pIHtcbiAgICAgICAgICAgICAgICByZXNwb25zZVsnaXRlbXMnXSA9IG1vZGVsLkxpc3QocmVzcG9uc2VbJ2l0ZW1zJ10pO1xuICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgcmV0dXJuIHJlc3BvbnNlO1xuICAgICAgICAgICAgfVxuICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgfVxuXG4gICAgICBtb2RlbCA9ICRtb2RlbEZhY3RvcnkodXJsLCBhbmd1bGFyLm1lcmdlKGRlZmF1bHRPcHRpb25zLCBvcHRpb25zKSlcblxuICAgICAgcmV0dXJuIG1vZGVsO1xuICAgIH1cbiAgfVxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnRyb2xsZXIoJ0NSVURDb250cm9sbGVyJywgQ1JVRENvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLyoqXG4gICAqIENvbnRyb2xhZG9yIEJhc2UgcXVlIGltcGxlbWVudGEgdG9kYXMgYXMgZnVuw6fDtWVzIHBhZHLDtWVzIGRlIHVtIENSVURcbiAgICpcbiAgICogQcOnw7VlcyBpbXBsZW1lbnRhZGFzXG4gICAqIGFjdGl2YXRlKClcbiAgICogc2VhcmNoKHBhZ2UpXG4gICAqIGVkaXQocmVzb3VyY2UpXG4gICAqIHNhdmUoKVxuICAgKiByZW1vdmUocmVzb3VyY2UpXG4gICAqIGdvVG8odmlld05hbWUpXG4gICAqIGNsZWFuRm9ybSgpXG4gICAqXG4gICAqIEdhdGlsaG9zXG4gICAqXG4gICAqIG9uQWN0aXZhdGUoKVxuICAgKiBhcHBseUZpbHRlcnMoZGVmYXVsdFF1ZXJ5RmlsdGVycylcbiAgICogYmVmb3JlU2VhcmNoKHBhZ2UpIC8vcmV0b3JuYW5kbyBmYWxzZSBjYW5jZWxhIG8gZmx1eG9cbiAgICogYWZ0ZXJTZWFyY2gocmVzcG9uc2UpXG4gICAqIGJlZm9yZUNsZWFuIC8vcmV0b3JuYW5kbyBmYWxzZSBjYW5jZWxhIG8gZmx1eG9cbiAgICogYWZ0ZXJDbGVhbigpXG4gICAqIGJlZm9yZVNhdmUoKSAvL3JldG9ybmFuZG8gZmFsc2UgY2FuY2VsYSBvIGZsdXhvXG4gICAqIGFmdGVyU2F2ZShyZXNvdXJjZSlcbiAgICogb25TYXZlRXJyb3IoZXJyb3IpXG4gICAqIGJlZm9yZVJlbW92ZShyZXNvdXJjZSkgLy9yZXRvcm5hbmRvIGZhbHNlIGNhbmNlbGEgbyBmbHV4b1xuICAgKiBhZnRlclJlbW92ZShyZXNvdXJjZSlcbiAgICpcbiAgICogQHBhcmFtIHthbnl9IHZtIGluc3RhbmNpYSBkbyBjb250cm9sbGVyIGZpbGhvXG4gICAqIEBwYXJhbSB7YW55fSBtb2RlbFNlcnZpY2Ugc2VydmnDp28gZG8gbW9kZWwgcXVlIHZhaSBzZXIgdXRpbGl6YWRvXG4gICAqIEBwYXJhbSB7YW55fSBvcHRpb25zIG9ww6fDtWVzIHBhcmEgc29icmVlc2NyZXZlciBjb21wb3J0YW1lbnRvcyBwYWRyw7Vlc1xuICAgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gQ1JVRENvbnRyb2xsZXIodm0sIG1vZGVsU2VydmljZSwgb3B0aW9ucywgUHJUb2FzdCwgUHJQYWdpbmF0aW9uLCAvLyBOT1NPTkFSXG4gICAgUHJEaWFsb2csICR0cmFuc2xhdGUpIHtcblxuICAgIC8vRnVuY3Rpb25zIEJsb2NrXG4gICAgdm0uc2VhcmNoID0gc2VhcmNoO1xuICAgIHZtLnBhZ2luYXRlU2VhcmNoID0gcGFnaW5hdGVTZWFyY2g7XG4gICAgdm0ubm9ybWFsU2VhcmNoID0gbm9ybWFsU2VhcmNoO1xuICAgIHZtLmVkaXQgPSBlZGl0O1xuICAgIHZtLnNhdmUgPSBzYXZlO1xuICAgIHZtLnJlbW92ZSA9IHJlbW92ZTtcbiAgICB2bS5nb1RvID0gZ29UbztcbiAgICB2bS5jbGVhbkZvcm0gPSBjbGVhbkZvcm07XG5cbiAgICBhY3RpdmF0ZSgpO1xuXG4gICAgLyoqXG4gICAgICogUHJlcGFyYSBvIGNvbnRyb2xhZG9yXG4gICAgICogRmF6IG8gbWVyZ2UgZGFzIG9ww6fDtWVzXG4gICAgICogSW5pY2lhbGl6YSBvIHJlY3Vyc29cbiAgICAgKiBJbmljaWFsaXphIG8gb2JqZXRvIHBhZ2luYWRvciBlIHJlYWxpemEgYSBwZXNxdWlzYVxuICAgICAqL1xuICAgIGZ1bmN0aW9uIGFjdGl2YXRlKCkge1xuICAgICAgdm0uZGVmYXVsdE9wdGlvbnMgPSB7XG4gICAgICAgIHJlZGlyZWN0QWZ0ZXJTYXZlOiB0cnVlLFxuICAgICAgICBzZWFyY2hPbkluaXQ6IHRydWUsXG4gICAgICAgIHBlclBhZ2U6IDgsXG4gICAgICAgIHNraXBQYWdpbmF0aW9uOiBmYWxzZVxuICAgICAgfVxuXG4gICAgICBhbmd1bGFyLm1lcmdlKHZtLmRlZmF1bHRPcHRpb25zLCBvcHRpb25zKTtcblxuICAgICAgdm0udmlld0Zvcm0gPSBmYWxzZTtcbiAgICAgIHZtLnJlc291cmNlID0gbmV3IG1vZGVsU2VydmljZSgpO1xuXG4gICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLm9uQWN0aXZhdGUpKSB2bS5vbkFjdGl2YXRlKCk7XG5cbiAgICAgIHZtLnBhZ2luYXRvciA9IFByUGFnaW5hdGlvbi5nZXRJbnN0YW5jZSh2bS5zZWFyY2gsIHZtLmRlZmF1bHRPcHRpb25zLnBlclBhZ2UpO1xuXG4gICAgICBpZiAodm0uZGVmYXVsdE9wdGlvbnMuc2VhcmNoT25Jbml0KSB2bS5zZWFyY2goKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFsaXphIGEgcGVzcXVpc2FcbiAgICAgKiBWZXJpZmljYSBxdWFsIGRhcyBmdW7Dp8O1ZXMgZGUgcGVzcXVpc2EgZGV2ZSBzZXIgcmVhbGl6YWRhLlxuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IHBhZ2UgcMOhZ2luYSBxdWUgZGV2ZSBzZXIgY2FycmVnYWRhXG4gICAgICovXG4gICAgZnVuY3Rpb24gc2VhcmNoKHBhZ2UpIHtcbiAgICAgICh2bS5kZWZhdWx0T3B0aW9ucy5za2lwUGFnaW5hdGlvbikgPyBub3JtYWxTZWFyY2goKSA6IHBhZ2luYXRlU2VhcmNoKHBhZ2UpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWxpemEgYSBwZXNxdWlzYSBwYWdpbmFkYSBjb20gYmFzZSBub3MgZmlsdHJvcyBkZWZpbmlkb3NcbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSBwYWdlIHDDoWdpbmEgcXVlIGRldmUgc2VyIGNhcnJlZ2FkYVxuICAgICAqL1xuICAgIGZ1bmN0aW9uIHBhZ2luYXRlU2VhcmNoKHBhZ2UpIHtcbiAgICAgIHZtLnBhZ2luYXRvci5jdXJyZW50UGFnZSA9IChhbmd1bGFyLmlzRGVmaW5lZChwYWdlKSkgPyBwYWdlIDogMTtcbiAgICAgIHZtLmRlZmF1bHRRdWVyeUZpbHRlcnMgPSB7IHBhZ2U6IHZtLnBhZ2luYXRvci5jdXJyZW50UGFnZSwgcGVyUGFnZTogdm0ucGFnaW5hdG9yLnBlclBhZ2UgfTtcblxuICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5hcHBseUZpbHRlcnMpKSB2bS5kZWZhdWx0UXVlcnlGaWx0ZXJzID0gdm0uYXBwbHlGaWx0ZXJzKHZtLmRlZmF1bHRRdWVyeUZpbHRlcnMpO1xuICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5iZWZvcmVTZWFyY2gpICYmIHZtLmJlZm9yZVNlYXJjaChwYWdlKSA9PT0gZmFsc2UpIHJldHVybiBmYWxzZTtcblxuICAgICAgbW9kZWxTZXJ2aWNlLnBhZ2luYXRlKHZtLmRlZmF1bHRRdWVyeUZpbHRlcnMpLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgIHZtLnBhZ2luYXRvci5jYWxjTnVtYmVyT2ZQYWdlcyhyZXNwb25zZS50b3RhbCk7XG4gICAgICAgIHZtLnJlc291cmNlcyA9IHJlc3BvbnNlLml0ZW1zO1xuXG4gICAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYWZ0ZXJTZWFyY2gpKSB2bS5hZnRlclNlYXJjaChyZXNwb25zZSk7XG4gICAgICB9LCBmdW5jdGlvbiAocmVzcG9uc2VEYXRhKSB7XG4gICAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0ub25TZWFyY2hFcnJvcikpIHZtLm9uU2VhcmNoRXJyb3IocmVzcG9uc2VEYXRhKTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWxpemEgYSBwZXNxdWlzYSBjb20gYmFzZSBub3MgZmlsdHJvcyBkZWZpbmlkb3NcbiAgICAgKlxuICAgICAqL1xuICAgIGZ1bmN0aW9uIG5vcm1hbFNlYXJjaCgpIHtcbiAgICAgIHZtLmRlZmF1bHRRdWVyeUZpbHRlcnMgPSB7IH07XG5cbiAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYXBwbHlGaWx0ZXJzKSkgdm0uZGVmYXVsdFF1ZXJ5RmlsdGVycyA9IHZtLmFwcGx5RmlsdGVycyh2bS5kZWZhdWx0UXVlcnlGaWx0ZXJzKTtcbiAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYmVmb3JlU2VhcmNoKSAmJiB2bS5iZWZvcmVTZWFyY2goKSA9PT0gZmFsc2UpIHJldHVybiBmYWxzZTtcblxuICAgICAgbW9kZWxTZXJ2aWNlLnF1ZXJ5KHZtLmRlZmF1bHRRdWVyeUZpbHRlcnMpLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgIHZtLnJlc291cmNlcyA9IHJlc3BvbnNlO1xuXG4gICAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYWZ0ZXJTZWFyY2gpKSB2bS5hZnRlclNlYXJjaChyZXNwb25zZSk7XG4gICAgICB9LCBmdW5jdGlvbiAocmVzcG9uc2VEYXRhKSB7XG4gICAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0ub25TZWFyY2hFcnJvcikpIHZtLm9uU2VhcmNoRXJyb3IocmVzcG9uc2VEYXRhKTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIExpbXBhIG8gZm9ybXVsw6FyaW9cbiAgICAgKi9cbiAgICBmdW5jdGlvbiBjbGVhbkZvcm0oZm9ybSkge1xuICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5iZWZvcmVDbGVhbikgJiYgdm0uYmVmb3JlQ2xlYW4oKSA9PT0gZmFsc2UpIHJldHVybiBmYWxzZTtcblxuICAgICAgdm0ucmVzb3VyY2UgPSBuZXcgbW9kZWxTZXJ2aWNlKCk7XG5cbiAgICAgIGlmIChhbmd1bGFyLmlzRGVmaW5lZChmb3JtKSkge1xuICAgICAgICBmb3JtLiRzZXRQcmlzdGluZSgpO1xuICAgICAgICBmb3JtLiRzZXRVbnRvdWNoZWQoKTtcbiAgICAgIH1cblxuICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5hZnRlckNsZWFuKSkgdm0uYWZ0ZXJDbGVhbigpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENhcnJlZ2Egbm8gZm9ybXVsw6FyaW8gbyByZWN1cnNvIHNlbGVjaW9uYWRvIHBhcmEgZWRpw6fDo29cbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSByZXNvdXJjZSByZWN1cnNvIHNlbGVjaW9uYWRvXG4gICAgICovXG4gICAgZnVuY3Rpb24gZWRpdChyZXNvdXJjZSkge1xuICAgICAgdm0uZ29UbygnZm9ybScpO1xuICAgICAgdm0ucmVzb3VyY2UgPSBuZXcgYW5ndWxhci5jb3B5KHJlc291cmNlKTtcblxuICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5hZnRlckVkaXQpKSB2bS5hZnRlckVkaXQoKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBTYWx2YSBvdSBhdHVhbGl6YSBvIHJlY3Vyc28gY29ycmVudGUgbm8gZm9ybXVsw6FyaW9cbiAgICAgKiBObyBjb21wb3J0YW1lbnRvIHBhZHLDo28gcmVkaXJlY2lvbmEgbyB1c3XDoXJpbyBwYXJhIHZpZXcgZGUgbGlzdGFnZW1cbiAgICAgKiBkZXBvaXMgZGEgZXhlY3XDp8Ojb1xuICAgICAqXG4gICAgICogQHJldHVybnNcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBzYXZlKGZvcm0pIHtcbiAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYmVmb3JlU2F2ZSkgJiYgdm0uYmVmb3JlU2F2ZSgpID09PSBmYWxzZSkgcmV0dXJuIGZhbHNlO1xuXG4gICAgICB2bS5yZXNvdXJjZS4kc2F2ZSgpLnRoZW4oZnVuY3Rpb24gKHJlc291cmNlKSB7XG4gICAgICAgIHZtLnJlc291cmNlID0gcmVzb3VyY2U7XG5cbiAgICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5hZnRlclNhdmUpKSB2bS5hZnRlclNhdmUocmVzb3VyY2UpO1xuXG4gICAgICAgIGlmICh2bS5kZWZhdWx0T3B0aW9ucy5yZWRpcmVjdEFmdGVyU2F2ZSkge1xuICAgICAgICAgIHZtLmNsZWFuRm9ybShmb3JtKTtcbiAgICAgICAgICB2bS5zZWFyY2godm0ucGFnaW5hdG9yLmN1cnJlbnRQYWdlKTtcbiAgICAgICAgICB2bS5nb1RvKCdsaXN0Jyk7XG4gICAgICAgIH1cblxuICAgICAgICBQclRvYXN0LnN1Y2Nlc3MoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5zYXZlU3VjY2VzcycpKTtcblxuICAgICAgfSwgZnVuY3Rpb24gKHJlc3BvbnNlRGF0YSkge1xuICAgICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLm9uU2F2ZUVycm9yKSkgdm0ub25TYXZlRXJyb3IocmVzcG9uc2VEYXRhKTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlbW92ZSBvIHJlY3Vyc28gaW5mb3JtYWRvLlxuICAgICAqIEFudGVzIGV4aWJlIHVtIGRpYWxvZ28gZGUgY29uZmlybWHDp8Ojb1xuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IHJlc291cmNlIHJlY3Vyc28gZXNjb2xoaWRvXG4gICAgICovXG4gICAgZnVuY3Rpb24gcmVtb3ZlKHJlc291cmNlKSB7XG4gICAgICB2YXIgY29uZmlnID0ge1xuICAgICAgICB0aXRsZTogJHRyYW5zbGF0ZS5pbnN0YW50KCdkaWFsb2cuY29uZmlybVRpdGxlJyksXG4gICAgICAgIGRlc2NyaXB0aW9uOiAkdHJhbnNsYXRlLmluc3RhbnQoJ2RpYWxvZy5jb25maXJtRGVzY3JpcHRpb24nKVxuICAgICAgfVxuXG4gICAgICBQckRpYWxvZy5jb25maXJtKGNvbmZpZykudGhlbihmdW5jdGlvbigpIHtcbiAgICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5iZWZvcmVSZW1vdmUpICYmIHZtLmJlZm9yZVJlbW92ZShyZXNvdXJjZSkgPT09IGZhbHNlKSByZXR1cm4gZmFsc2U7XG5cbiAgICAgICAgcmVzb3VyY2UuJGRlc3Ryb3koKS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmFmdGVyUmVtb3ZlKSkgdm0uYWZ0ZXJSZW1vdmUocmVzb3VyY2UpO1xuXG4gICAgICAgICAgdm0uc2VhcmNoKCk7XG4gICAgICAgICAgUHJUb2FzdC5pbmZvKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMucmVtb3ZlU3VjY2VzcycpKTtcbiAgICAgICAgfSk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBBbHRlcm5hIGVudHJlIGEgdmlldyBkbyBmb3JtdWzDoXJpbyBlIGxpc3RhZ2VtXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gdmlld05hbWUgbm9tZSBkYSB2aWV3XG4gICAgICovXG4gICAgZnVuY3Rpb24gZ29Ubyh2aWV3TmFtZSkge1xuICAgICAgdm0udmlld0Zvcm0gPSBmYWxzZTtcbiAgICAgIHZtLm9uVmlldyA9IGZhbHNlO1xuICAgICAgaWYgKHZpZXdOYW1lID09PSAnZm9ybScpIHtcbiAgICAgICAgdm0uY2xlYW5Gb3JtKCk7XG4gICAgICAgIHZtLnZpZXdGb3JtID0gdHJ1ZTtcbiAgICAgIH1cbiAgICB9XG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZpbHRlcignZWxhcHNlZCcsIGZ1bmN0aW9uKCkge1xuICAgICAgcmV0dXJuIGZ1bmN0aW9uKGRhdGUpIHtcbiAgICAgICAgaWYgKCFkYXRlKSByZXR1cm47XG4gICAgICAgIHZhciB0aW1lID0gRGF0ZS5wYXJzZShkYXRlKSxcbiAgICAgICAgICB0aW1lTm93ID0gbmV3IERhdGUoKS5nZXRUaW1lKCksXG4gICAgICAgICAgZGlmZmVyZW5jZSA9IHRpbWVOb3cgLSB0aW1lLFxuICAgICAgICAgIHNlY29uZHMgPSBNYXRoLmZsb29yKGRpZmZlcmVuY2UgLyAxMDAwKSxcbiAgICAgICAgICBtaW51dGVzID0gTWF0aC5mbG9vcihzZWNvbmRzIC8gNjApLFxuICAgICAgICAgIGhvdXJzID0gTWF0aC5mbG9vcihtaW51dGVzIC8gNjApLFxuICAgICAgICAgIGRheXMgPSBNYXRoLmZsb29yKGhvdXJzIC8gMjQpLFxuICAgICAgICAgIG1vbnRocyA9IE1hdGguZmxvb3IoZGF5cyAvIDMwKTtcblxuICAgICAgICBpZiAobW9udGhzID4gMSkge1xuICAgICAgICAgIHJldHVybiBtb250aHMgKyAnIG1lc2VzIGF0csOhcyc7XG4gICAgICAgIH0gZWxzZSBpZiAobW9udGhzID09PSAxKSB7XG4gICAgICAgICAgcmV0dXJuICcxIG3DqnMgYXRyw6FzJztcbiAgICAgICAgfSBlbHNlIGlmIChkYXlzID4gMSkge1xuICAgICAgICAgIHJldHVybiBkYXlzICsgJyBkaWFzIGF0csOhcyc7XG4gICAgICAgIH0gZWxzZSBpZiAoZGF5cyA9PT0gMSkge1xuICAgICAgICAgIHJldHVybiAnMSBkaWEgYXRyw6FzJ1xuICAgICAgICB9IGVsc2UgaWYgKGhvdXJzID4gMSkge1xuICAgICAgICAgIHJldHVybiBob3VycyArICcgaG9yYXMgYXRyw6FzJztcbiAgICAgICAgfSBlbHNlIGlmIChob3VycyA9PT0gMSkge1xuICAgICAgICAgIHJldHVybiAndW1hIGhvcmEgYXRyw6FzJztcbiAgICAgICAgfSBlbHNlIGlmIChtaW51dGVzID4gMSkge1xuICAgICAgICAgIHJldHVybiBtaW51dGVzICsgJyBtaW51dG9zIGF0csOhcyc7XG4gICAgICAgIH0gZWxzZSBpZiAobWludXRlcyA9PT0gMSkge1xuICAgICAgICAgIHJldHVybiAndW0gbWludXRvIGF0csOhcyc7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgcmV0dXJuICdow6EgcG91Y29zIHNlZ3VuZG9zJztcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pXG4gICAgLmNvbnRyb2xsZXIoJ0Rhc2hib2FyZENvbnRyb2xsZXInLCBEYXNoYm9hcmRDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIERhc2hib2FyZENvbnRyb2xsZXIoJGNvbnRyb2xsZXIsXG4gICAgJHN0YXRlLFxuICAgICRtZERpYWxvZyxcbiAgICAkdHJhbnNsYXRlLFxuICAgIERhc2hib2FyZHNTZXJ2aWNlLFxuICAgIFByb2plY3RzU2VydmljZSxcbiAgICBtb21lbnQsXG4gICAgUHJUb2FzdCxcbiAgICBBdXRoLFxuICAgIEdsb2JhbCkge1xuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICAvL0F0dHJpYnV0ZXMgQmxvY2tcblxuICAgIC8vRnVuY3Rpb25zIEJsb2NrXG4gICAgdm0ub25BY3RpdmF0ZSA9IG9uQWN0aXZhdGU7XG4gICAgdm0uYXBwbHlGaWx0ZXJzID0gYXBwbHlGaWx0ZXJzO1xuICAgIHZtLmZpeERhdGUgPSBmaXhEYXRlO1xuXG4gICAgZnVuY3Rpb24gb25BY3RpdmF0ZSgpIHtcbiAgICAgIHZhciBwcm9qZWN0ID0gbG9jYWxTdG9yYWdlLmdldEl0ZW0oJ3Byb2plY3QnKTtcblxuICAgICAgdm0uaW1hZ2VQYXRoID0gR2xvYmFsLmltYWdlUGF0aCArICcvbm9fYXZhdGFyLmdpZic7XG4gICAgICB2bS5jdXJyZW50VXNlciA9IEF1dGguY3VycmVudFVzZXI7XG4gICAgICBQcm9qZWN0c1NlcnZpY2UucXVlcnkoeyBwcm9qZWN0X2lkOiBwcm9qZWN0IH0pLnRoZW4oZnVuY3Rpb24ocmVzcG9uc2UpIHtcbiAgICAgICAgdm0uYWN0dWFsUHJvamVjdCA9IHJlc3BvbnNlWzBdO1xuICAgICAgfSlcbiAgICAgIHZtLnF1ZXJ5RmlsdGVycyA9IHsgcHJvamVjdF9pZDogcHJvamVjdCB9O1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGFwcGx5RmlsdGVycyhkZWZhdWx0UXVlcnlGaWx0ZXJzKSB7XG4gICAgICByZXR1cm4gYW5ndWxhci5leHRlbmQoZGVmYXVsdFF1ZXJ5RmlsdGVycywgdm0ucXVlcnlGaWx0ZXJzKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBmaXhEYXRlKGRhdGVTdHJpbmcpIHtcbiAgICAgIHJldHVybiBtb21lbnQoZGF0ZVN0cmluZyk7XG4gICAgfVxuXG4gICAgdm0uZ29Ub1Byb2plY3QgPSBmdW5jdGlvbigpIHtcbiAgICAgICRzdGF0ZS5nbygnYXBwLnByb2plY3RzJywgeyBvYmo6ICdlZGl0JywgcmVzb3VyY2U6IHZtLmFjdHVhbFByb2plY3QgfSk7XG4gICAgfVxuXG4gICAgdm0udG90YWxDb3N0ID0gZnVuY3Rpb24oKSB7XG4gICAgICB2YXIgZXN0aW1hdGVkX2Nvc3QgPSAwO1xuXG4gICAgICB2bS5hY3R1YWxQcm9qZWN0LnRhc2tzLmZvckVhY2goZnVuY3Rpb24odGFzaykge1xuICAgICAgICBlc3RpbWF0ZWRfY29zdCArPSAocGFyc2VGbG9hdCh2bS5hY3R1YWxQcm9qZWN0LmhvdXJfdmFsdWVfZmluYWwpICogdGFzay5lc3RpbWF0ZWRfdGltZSk7XG4gICAgICB9KTtcbiAgICAgIHJldHVybiBlc3RpbWF0ZWRfY29zdC50b0xvY2FsZVN0cmluZygnUHQtYnInLCB7IG1pbmltdW1GcmFjdGlvbkRpZ2l0czogMiB9KTtcbiAgICB9XG5cbiAgICB2bS5maW5hbGl6ZVByb2plY3QgPSBmdW5jdGlvbigpIHtcbiAgICAgIHZhciBjb25maXJtID0gJG1kRGlhbG9nLmNvbmZpcm0oKVxuICAgICAgICAgIC50aXRsZSgnRmluYWxpemFyIFByb2pldG8nKVxuICAgICAgICAgIC50ZXh0Q29udGVudCgnVGVtIGNlcnRlemEgcXVlIGRlc2VqYSBmaW5hbGl6YXIgbyBwcm9qZXRvICcgKyB2bS5hY3R1YWxQcm9qZWN0Lm5hbWUgKyAnPycpXG4gICAgICAgICAgLm9rKCdTaW0nKVxuICAgICAgICAgIC5jYW5jZWwoJ07Do28nKTtcblxuICAgICAgJG1kRGlhbG9nLnNob3coY29uZmlybSkudGhlbihmdW5jdGlvbigpIHtcbiAgICAgICAgUHJvamVjdHNTZXJ2aWNlLmZpbmFsaXplKHsgcHJvamVjdF9pZDogdm0uYWN0dWFsUHJvamVjdC5pZCB9KS50aGVuKGZ1bmN0aW9uKCkge1xuICAgICAgICAgIFByVG9hc3Quc3VjY2VzcygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnByb2plY3RFbmRlZFN1Y2Nlc3MnKSk7XG4gICAgICAgICAgb25BY3RpdmF0ZSgpO1xuICAgICAgICAgIHZtLnNlYXJjaCgpO1xuICAgICAgICB9LCBmdW5jdGlvbigpIHtcbiAgICAgICAgICBQclRvYXN0LkVycm9yKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMucHJvamVjdEVuZGVkRXJyb3InKSk7XG4gICAgICAgIH0pO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLy8gaW5zdGFudGlhdGUgYmFzZSBjb250cm9sbGVyXG4gICAgJGNvbnRyb2xsZXIoJ0NSVURDb250cm9sbGVyJywgeyB2bTogdm0sIG1vZGVsU2VydmljZTogRGFzaGJvYXJkc1NlcnZpY2UsIG9wdGlvbnM6IHt9IH0pO1xuICB9XG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqXG4gICAqIEFycXVpdm8gZGUgY29uZmlndXJhw6fDo28gY29tIGFzIHJvdGFzIGVzcGVjw61maWNhcyBkbyByZWN1cnNvIHByb2plY3RcbiAgICpcbiAgICogQHBhcmFtIHthbnl9ICRzdGF0ZVByb3ZpZGVyXG4gICAqIEBwYXJhbSB7YW55fSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlclxuICAgICAgLnN0YXRlKCdhcHAuZGFzaGJvYXJkJywge1xuICAgICAgICB1cmw6ICcvZGFzaGJvYXJkcycsXG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvZGFzaGJvYXJkL2Rhc2hib2FyZC5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ0Rhc2hib2FyZENvbnRyb2xsZXIgYXMgZGFzaGJvYXJkQ3RybCcsXG4gICAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiB0cnVlIH0sXG4gICAgICAgIG9iajogeyByZXNvdXJjZTogbnVsbCB9XG4gICAgICB9KTtcbiAgfVxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5mYWN0b3J5KCdEYXNoYm9hcmRzU2VydmljZScsIERhc2hib2FyZHNTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIERhc2hib2FyZHNTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCdkYXNoYm9hcmRzJywge1xuICAgICAgYWN0aW9uczogeyB9LFxuICAgICAgaW5zdGFuY2U6IHsgfVxuICAgIH0pO1xuICB9XG5cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqXG4gICAqIEFycXVpdm8gZGUgY29uZmlndXJhw6fDo28gY29tIGFzIHJvdGFzIGVzcGVjw61maWNhcyBkbyByZWN1cnNvIHVzZXJcbiAgICpcbiAgICogQHBhcmFtIHthbnl9ICRzdGF0ZVByb3ZpZGVyXG4gICAqIEBwYXJhbSB7YW55fSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlclxuICAgICAgLnN0YXRlKCdhcHAuZGluYW1pYy1xdWVyeScsIHtcbiAgICAgICAgdXJsOiAnL2NvbnN1bHRhcy1kaW5hbWljYXMnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL2RpbmFtaWMtcXVlcnlzL2RpbmFtaWMtcXVlcnlzLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnRGluYW1pY1F1ZXJ5c0NvbnRyb2xsZXIgYXMgZGluYW1pY1F1ZXJ5Q3RybCcsXG4gICAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiB0cnVlLCBuZWVkUHJvZmlsZTogWydhZG1pbiddIH1cbiAgICAgIH0pO1xuXG4gIH1cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmFjdG9yeSgnRGluYW1pY1F1ZXJ5U2VydmljZScsIERpbmFtaWNRdWVyeVNlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gRGluYW1pY1F1ZXJ5U2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHJldHVybiBzZXJ2aWNlRmFjdG9yeSgnZGluYW1pY1F1ZXJ5Jywge1xuICAgICAgLyoqXG4gICAgICAgKiBhw6fDo28gYWRpY2lvbmFkYSBwYXJhIHBlZ2FyIHVtYSBsaXN0YSBkZSBtb2RlbHMgZXhpc3RlbnRlcyBubyBzZXJ2aWRvclxuICAgICAgICovXG4gICAgICBhY3Rpb25zOiB7XG4gICAgICAgIGdldE1vZGVsczoge1xuICAgICAgICAgIG1ldGhvZDogJ0dFVCcsXG4gICAgICAgICAgdXJsOiAnbW9kZWxzJ1xuICAgICAgICB9XG4gICAgICB9LFxuICAgICAgaW5zdGFuY2U6IHtcbiAgICAgIH1cbiAgICB9KTtcbiAgfVxuXG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29udHJvbGxlcignRGluYW1pY1F1ZXJ5c0NvbnRyb2xsZXInLCBEaW5hbWljUXVlcnlzQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBEaW5hbWljUXVlcnlzQ29udHJvbGxlcigkY29udHJvbGxlciwgRGluYW1pY1F1ZXJ5U2VydmljZSwgbG9kYXNoLCBQclRvYXN0LCAvLyBOT1NPTkFSXG4gICAgJHRyYW5zbGF0ZSkge1xuXG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIC8vYWN0aW9uc1xuICAgIHZtLm9uQWN0aXZhdGUgPSBvbkFjdGl2YXRlO1xuICAgIHZtLmFwcGx5RmlsdGVycyA9IGFwcGx5RmlsdGVycztcbiAgICB2bS5sb2FkQXR0cmlidXRlcyA9IGxvYWRBdHRyaWJ1dGVzO1xuICAgIHZtLmxvYWRPcGVyYXRvcnMgPSBsb2FkT3BlcmF0b3JzO1xuICAgIHZtLmFkZEZpbHRlciA9IGFkZEZpbHRlcjtcbiAgICB2bS5hZnRlclNlYXJjaCA9IGFmdGVyU2VhcmNoO1xuICAgIHZtLnJ1bkZpbHRlciA9IHJ1bkZpbHRlcjtcbiAgICB2bS5lZGl0RmlsdGVyID0gZWRpdEZpbHRlcjtcbiAgICB2bS5sb2FkTW9kZWxzID0gbG9hZE1vZGVscztcbiAgICB2bS5yZW1vdmVGaWx0ZXIgPSByZW1vdmVGaWx0ZXI7XG4gICAgdm0uY2xlYXIgPSBjbGVhcjtcbiAgICB2bS5yZXN0YXJ0ID0gcmVzdGFydDtcblxuICAgIC8vaGVyZGEgbyBjb21wb3J0YW1lbnRvIGJhc2UgZG8gQ1JVRFxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHsgdm06IHZtLCBtb2RlbFNlcnZpY2U6IERpbmFtaWNRdWVyeVNlcnZpY2UsIG9wdGlvbnM6IHtcbiAgICAgIHNlYXJjaE9uSW5pdDogZmFsc2VcbiAgICB9IH0pO1xuXG4gICAgZnVuY3Rpb24gb25BY3RpdmF0ZSgpIHtcbiAgICAgIHZtLnJlc3RhcnQoKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBQcmVwYXJhIGUgYXBsaWNhIG9zIGZpbHRybyBxdWUgdsOjbyBzZXIgZW52aWFkb3MgcGFyYSBvIHNlcnZpw6dvXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gZGVmYXVsdFF1ZXJ5RmlsdGVyc1xuICAgICAqIEByZXR1cm5zXG4gICAgICovXG4gICAgZnVuY3Rpb24gYXBwbHlGaWx0ZXJzKGRlZmF1bHRRdWVyeUZpbHRlcnMpIHtcbiAgICAgIHZhciB3aGVyZSA9IHt9O1xuXG4gICAgICAvKipcbiAgICAgICAqIG8gc2VydmnDp28gZXNwZXJhIHVtIG9iamV0byBjb206XG4gICAgICAgKiAgbyBub21lIGRlIHVtIG1vZGVsXG4gICAgICAgKiAgdW1hIGxpc3RhIGRlIGZpbHRyb3NcbiAgICAgICAqL1xuICAgICAgaWYgKHZtLmFkZGVkRmlsdGVycy5sZW5ndGggPiAwKSB7XG4gICAgICAgIHZhciBhZGRlZEZpbHRlcnMgPSBhbmd1bGFyLmNvcHkodm0uYWRkZWRGaWx0ZXJzKTtcblxuICAgICAgICB3aGVyZS5tb2RlbCA9IHZtLmFkZGVkRmlsdGVyc1swXS5tb2RlbC5uYW1lO1xuXG4gICAgICAgIGZvciAodmFyIGluZGV4ID0gMDsgaW5kZXggPCBhZGRlZEZpbHRlcnMubGVuZ3RoOyBpbmRleCsrKSB7XG4gICAgICAgICAgdmFyIGZpbHRlciA9IGFkZGVkRmlsdGVyc1tpbmRleF07XG5cbiAgICAgICAgICBmaWx0ZXIubW9kZWwgPSBudWxsO1xuICAgICAgICAgIGZpbHRlci5hdHRyaWJ1dGUgPSBmaWx0ZXIuYXR0cmlidXRlLm5hbWU7XG4gICAgICAgICAgZmlsdGVyLm9wZXJhdG9yID0gZmlsdGVyLm9wZXJhdG9yLnZhbHVlO1xuICAgICAgICB9XG5cbiAgICAgICAgd2hlcmUuZmlsdGVycyA9IGFuZ3VsYXIudG9Kc29uKGFkZGVkRmlsdGVycyk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICB3aGVyZS5tb2RlbCA9IHZtLnF1ZXJ5RmlsdGVycy5tb2RlbC5uYW1lO1xuICAgICAgfVxuXG4gICAgICByZXR1cm4gYW5ndWxhci5leHRlbmQoZGVmYXVsdFF1ZXJ5RmlsdGVycywgd2hlcmUpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENhcnJlZ2EgdG9kb3Mgb3MgbW9kZWxzIGNyaWFkb3Mgbm8gc2Vydmlkb3IgY29tIHNldXMgYXRyaWJ1dG9zXG4gICAgICovXG4gICAgZnVuY3Rpb24gbG9hZE1vZGVscygpIHtcbiAgICAgIC8vUGVnYSB0b2RvcyBvcyBtb2RlbHMgZG8gc2VydmVyIGUgbW9udGEgdW1hIGxpc3RhIHBybyBDb21ib0JveFxuICAgICAgRGluYW1pY1F1ZXJ5U2VydmljZS5nZXRNb2RlbHMoKS50aGVuKGZ1bmN0aW9uKGRhdGEpIHtcbiAgICAgICAgdm0ubW9kZWxzID0gZGF0YTtcbiAgICAgICAgdm0ucXVlcnlGaWx0ZXJzLm1vZGVsID0gdm0ubW9kZWxzWzBdO1xuICAgICAgICB2bS5sb2FkQXR0cmlidXRlcygpO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ2FycmVnYSBvcyBhdHRyaWJ1dG9zIGRvIG1vZGVsIGVzY29saGlkb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGxvYWRBdHRyaWJ1dGVzKCkge1xuICAgICAgdm0uYXR0cmlidXRlcyA9IHZtLnF1ZXJ5RmlsdGVycy5tb2RlbC5hdHRyaWJ1dGVzO1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzLmF0dHJpYnV0ZSA9IHZtLmF0dHJpYnV0ZXNbMF07XG5cbiAgICAgIHZtLmxvYWRPcGVyYXRvcnMoKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDYXJyZWdhIG9zIG9wZXJhZG9yZXMgZXNwZWNpZmljb3MgcGFyYSBvIHRpcG8gZG8gYXRyaWJ1dG9cbiAgICAgKi9cbiAgICBmdW5jdGlvbiBsb2FkT3BlcmF0b3JzKCkge1xuICAgICAgdmFyIG9wZXJhdG9ycyA9IFtcbiAgICAgICAgeyB2YWx1ZTogJz0nLCBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KCd2aWV3cy5maWVsZHMucXVlcnlEaW5hbWljLm9wZXJhdG9ycy5lcXVhbHMnKSB9LFxuICAgICAgICB7IHZhbHVlOiAnPD4nLCBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KCd2aWV3cy5maWVsZHMucXVlcnlEaW5hbWljLm9wZXJhdG9ycy5kaWZlcmVudCcpIH1cbiAgICAgIF1cblxuICAgICAgaWYgKHZtLnF1ZXJ5RmlsdGVycy5hdHRyaWJ1dGUudHlwZS5pbmRleE9mKCd2YXJ5aW5nJykgIT09IC0xKSB7XG4gICAgICAgIG9wZXJhdG9ycy5wdXNoKHsgdmFsdWU6ICdoYXMnLFxuICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLmNvbnRlaW5zJykgfSk7XG4gICAgICAgIG9wZXJhdG9ycy5wdXNoKHsgdmFsdWU6ICdzdGFydFdpdGgnLFxuICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLnN0YXJ0V2l0aCcpIH0pO1xuICAgICAgICBvcGVyYXRvcnMucHVzaCh7IHZhbHVlOiAnZW5kV2l0aCcsXG4gICAgICAgICAgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudCgndmlld3MuZmllbGRzLnF1ZXJ5RGluYW1pYy5vcGVyYXRvcnMuZmluaXNoV2l0aCcpIH0pO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgb3BlcmF0b3JzLnB1c2goeyB2YWx1ZTogJz4nLFxuICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLmJpZ2dlclRoYW4nKSB9KTtcbiAgICAgICAgb3BlcmF0b3JzLnB1c2goeyB2YWx1ZTogJz49JyxcbiAgICAgICAgICBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KCd2aWV3cy5maWVsZHMucXVlcnlEaW5hbWljLm9wZXJhdG9ycy5lcXVhbHNPckJpZ2dlclRoYW4nKSB9KTtcbiAgICAgICAgb3BlcmF0b3JzLnB1c2goeyB2YWx1ZTogJzwnLFxuICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLmxlc3NUaGFuJykgfSk7XG4gICAgICAgIG9wZXJhdG9ycy5wdXNoKHsgdmFsdWU6ICc8PScsXG4gICAgICAgICAgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudCgndmlld3MuZmllbGRzLnF1ZXJ5RGluYW1pYy5vcGVyYXRvcnMuZXF1YWxzT3JMZXNzVGhhbicpIH0pO1xuICAgICAgfVxuXG4gICAgICB2bS5vcGVyYXRvcnMgPSBvcGVyYXRvcnM7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMub3BlcmF0b3IgPSB2bS5vcGVyYXRvcnNbMF07XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQWRpY2lvbmEvZWRpdGEgdW0gZmlsdHJvXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gZm9ybSBlbGVtZW50byBodG1sIGRvIGZvcm11bMOhcmlvIHBhcmEgdmFsaWRhw6fDtWVzXG4gICAgICovXG4gICAgZnVuY3Rpb24gYWRkRmlsdGVyKGZvcm0pIHtcbiAgICAgIGlmIChhbmd1bGFyLmlzVW5kZWZpbmVkKHZtLnF1ZXJ5RmlsdGVycy52YWx1ZSkgfHwgdm0ucXVlcnlGaWx0ZXJzLnZhbHVlID09PSAnJykge1xuICAgICAgICBQclRvYXN0LmVycm9yKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMudmFsaWRhdGUuZmllbGRSZXF1aXJlZCcsIHsgZmllbGQ6ICd2YWxvcicgfSkpO1xuICAgICAgICByZXR1cm47XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBpZiAodm0uaW5kZXggPCAwKSB7XG4gICAgICAgICAgdm0uYWRkZWRGaWx0ZXJzLnB1c2goYW5ndWxhci5jb3B5KHZtLnF1ZXJ5RmlsdGVycykpO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIHZtLmFkZGVkRmlsdGVyc1t2bS5pbmRleF0gPSBhbmd1bGFyLmNvcHkodm0ucXVlcnlGaWx0ZXJzKTtcbiAgICAgICAgICB2bS5pbmRleCA9IC0xO1xuICAgICAgICB9XG5cbiAgICAgICAgLy9yZWluaWNpYSBvIGZvcm11bMOhcmlvIGUgYXMgdmFsaWRhw6fDtWVzIGV4aXN0ZW50ZXNcbiAgICAgICAgdm0ucXVlcnlGaWx0ZXJzID0ge307XG4gICAgICAgIGZvcm0uJHNldFByaXN0aW5lKCk7XG4gICAgICAgIGZvcm0uJHNldFVudG91Y2hlZCgpO1xuICAgICAgfVxuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWxpemEgYSBwZXNxdWlzYSB0ZW5kbyBvcyBmaWx0cm9zIGNvbW8gcGFyw6JtZXRyb3NcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBydW5GaWx0ZXIoKSB7XG4gICAgICB2bS5zZWFyY2godm0ucGFnaW5hdG9yLmN1cnJlbnRQYWdlKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBHYXRpbGhvIGFjaW9uYWRvIGRlcG9pcyBkYSBwZXNxdWlzYSByZXNwb25zw6F2ZWwgcG9yIGlkZW50aWZpY2FyIG9zIGF0cmlidXRvc1xuICAgICAqIGNvbnRpZG9zIG5vcyBlbGVtZW50b3MgcmVzdWx0YW50ZXMgZGEgYnVzY2FcbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSBkYXRhIGRhZG9zIHJlZmVyZW50ZSBhbyByZXRvcm5vIGRhIHJlcXVpc2nDp8Ojb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGFmdGVyU2VhcmNoKGRhdGEpIHtcbiAgICAgIHZhciBrZXlzID0gKGRhdGEuaXRlbXMubGVuZ3RoID4gMCkgPyBPYmplY3Qua2V5cyhkYXRhLml0ZW1zWzBdKSA6IFtdO1xuXG4gICAgICAvL3JldGlyYSB0b2RvcyBvcyBhdHJpYnV0b3MgcXVlIGNvbWXDp2FtIGNvbSAkLlxuICAgICAgLy9Fc3NlcyBhdHJpYnV0b3Mgc8OjbyBhZGljaW9uYWRvcyBwZWxvIHNlcnZpw6dvIGUgbsOjbyBkZXZlIGFwYXJlY2VyIG5hIGxpc3RhZ2VtXG4gICAgICB2bS5rZXlzID0gbG9kYXNoLmZpbHRlcihrZXlzLCBmdW5jdGlvbihrZXkpIHtcbiAgICAgICAgcmV0dXJuICFsb2Rhc2guc3RhcnRzV2l0aChrZXksICckJyk7XG4gICAgICB9KVxuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENvbG9hY2Egbm8gZm9ybXVsw6FyaW8gbyBmaWx0cm8gZXNjb2xoaWRvIHBhcmEgZWRpw6fDo29cbiAgICAgKiBAcGFyYW0ge2FueX0gJGluZGV4IGluZGljZSBubyBhcnJheSBkbyBmaWx0cm8gZXNjb2xoaWRvXG4gICAgICovXG4gICAgZnVuY3Rpb24gZWRpdEZpbHRlcigkaW5kZXgpIHtcbiAgICAgIHZtLmluZGV4ID0gJGluZGV4O1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0gdm0uYWRkZWRGaWx0ZXJzWyRpbmRleF07XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVtb3ZlIG8gZmlsdHJvIGVzY29saGlkb1xuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9ICRpbmRleCBpbmRpY2Ugbm8gYXJyYXkgZG8gZmlsdHJvIGVzY29saGlkb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIHJlbW92ZUZpbHRlcigkaW5kZXgpIHtcbiAgICAgIHZtLmFkZGVkRmlsdGVycy5zcGxpY2UoJGluZGV4KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBMaW1wYSBvIGZvcm11bMOhcmlvIGNvcnJlbnRlXG4gICAgICovXG4gICAgZnVuY3Rpb24gY2xlYXIoKSB7XG4gICAgICAvL2d1YXJkYSBvIGluZGljZSBkbyByZWdpc3RybyBxdWUgZXN0w6Egc2VuZG8gZWRpdGFkb1xuICAgICAgdm0uaW5kZXggPSAtMTtcbiAgICAgIC8vdmluY3VsYWRvIGFvcyBjYW1wb3MgZG8gZm9ybXVsw6FyaW9cbiAgICAgIHZtLnF1ZXJ5RmlsdGVycyA9IHtcbiAgICAgIH07XG5cbiAgICAgIGlmICh2bS5tb2RlbHMpIHZtLnF1ZXJ5RmlsdGVycy5tb2RlbCA9IHZtLm1vZGVsc1swXTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWluaWNpYSBhIGNvbnN0cnXDp8OjbyBkYSBxdWVyeSBsaW1wYW5kbyB0dWRvXG4gICAgICpcbiAgICAgKi9cbiAgICBmdW5jdGlvbiByZXN0YXJ0KCkge1xuICAgICAgLy9ndWFyZGEgYXRyaWJ1dG9zIGRvIHJlc3VsdGFkbyBkYSBidXNjYSBjb3JyZW50ZVxuICAgICAgdm0ua2V5cyA9IFtdO1xuXG4gICAgICAvL2d1YXJkYSBvcyBmaWx0cm9zIGFkaWNpb25hZG9zXG4gICAgICB2bS5hZGRlZEZpbHRlcnMgPSBbXTtcbiAgICAgIHZtLmNsZWFyKCk7XG4gICAgICB2bS5sb2FkTW9kZWxzKCk7XG4gICAgfVxuXG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZhY3RvcnkoJ2xhbmd1YWdlTG9hZGVyJywgTGFuZ3VhZ2VMb2FkZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gTGFuZ3VhZ2VMb2FkZXIoJHEsIFN1cHBvcnRTZXJ2aWNlLCAkbG9nLCAkaW5qZWN0b3IpIHtcbiAgICB2YXIgc2VydmljZSA9IHRoaXM7XG5cbiAgICBzZXJ2aWNlLnRyYW5zbGF0ZSA9IGZ1bmN0aW9uKGxvY2FsZSkge1xuICAgICAgcmV0dXJuIHtcbiAgICAgICAgZ2xvYmFsOiAkaW5qZWN0b3IuZ2V0KGxvY2FsZSArICcuaTE4bi5nbG9iYWwnKSxcbiAgICAgICAgdmlld3M6ICRpbmplY3Rvci5nZXQobG9jYWxlICsgJy5pMThuLnZpZXdzJyksXG4gICAgICAgIGF0dHJpYnV0ZXM6ICRpbmplY3Rvci5nZXQobG9jYWxlICsgJy5pMThuLmF0dHJpYnV0ZXMnKSxcbiAgICAgICAgZGlhbG9nOiAkaW5qZWN0b3IuZ2V0KGxvY2FsZSArICcuaTE4bi5kaWFsb2cnKSxcbiAgICAgICAgbWVzc2FnZXM6ICRpbmplY3Rvci5nZXQobG9jYWxlICsgJy5pMThuLm1lc3NhZ2VzJyksXG4gICAgICAgIG1vZGVsczogJGluamVjdG9yLmdldChsb2NhbGUgKyAnLmkxOG4ubW9kZWxzJylcbiAgICAgIH07XG4gICAgfVxuXG4gICAgLy8gcmV0dXJuIGxvYWRlckZuXG4gICAgcmV0dXJuIGZ1bmN0aW9uKG9wdGlvbnMpIHtcbiAgICAgICRsb2cuaW5mbygnQ2FycmVnYW5kbyBvIGNvbnRldWRvIGRhIGxpbmd1YWdlbSAnICsgb3B0aW9ucy5rZXkpO1xuXG4gICAgICB2YXIgZGVmZXJyZWQgPSAkcS5kZWZlcigpO1xuXG4gICAgICAvL0NhcnJlZ2EgYXMgbGFuZ3MgcXVlIHByZWNpc2FtIGUgZXN0w6NvIG5vIHNlcnZpZG9yIHBhcmEgbsOjbyBwcmVjaXNhciByZXBldGlyIGFxdWlcbiAgICAgIFN1cHBvcnRTZXJ2aWNlLmxhbmdzKCkudGhlbihmdW5jdGlvbihsYW5ncykge1xuICAgICAgICAvL01lcmdlIGNvbSBvcyBsYW5ncyBkZWZpbmlkb3Mgbm8gc2Vydmlkb3JcbiAgICAgICAgdmFyIGRhdGEgPSBhbmd1bGFyLm1lcmdlKHNlcnZpY2UudHJhbnNsYXRlKG9wdGlvbnMua2V5KSwgbGFuZ3MpO1xuXG4gICAgICAgIHJldHVybiBkZWZlcnJlZC5yZXNvbHZlKGRhdGEpO1xuICAgICAgfSwgZnVuY3Rpb24oKSB7XG4gICAgICAgIHJldHVybiBkZWZlcnJlZC5yZXNvbHZlKHNlcnZpY2UudHJhbnNsYXRlKG9wdGlvbnMua2V5KSk7XG4gICAgICB9KTtcblxuICAgICAgcmV0dXJuIGRlZmVycmVkLnByb21pc2U7XG4gICAgfVxuICB9XG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5maWx0ZXIoJ3RBdHRyJywgdEF0dHIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gdEF0dHIoJGZpbHRlcikge1xuICAgIC8qKlxuICAgICAqIEZpbHRybyBwYXJhIHRyYWR1w6fDo28gZGUgdW0gYXRyaWJ1dG8gZGUgdW0gbW9kZWxcbiAgICAgKiBcbiAgICAgKiBAcGFyYW0ge2FueX0gbmFtZSBub21lIGRvIGF0cmlidXRvXG4gICAgICogQHJldHVybnMgbyBub21lIGRvIGF0cmlidXRvIHRyYWR1emlkbyBjYXNvIGVuY29udHJlIHNlIG7Do28gbyBub21lIHBhc3NhZG8gcG9yIHBhcmFtZXRyb1xuICAgICAqLyAgICBcbiAgICByZXR1cm4gZnVuY3Rpb24obmFtZSkge1xuICAgICAgdmFyIGtleSA9ICdhdHRyaWJ1dGVzLicgKyBuYW1lO1xuICAgICAgdmFyIHRyYW5zbGF0ZSA9ICRmaWx0ZXIoJ3RyYW5zbGF0ZScpKGtleSk7XG5cbiAgICAgIHJldHVybiAodHJhbnNsYXRlID09PSBrZXkpID8gbmFtZSA6IHRyYW5zbGF0ZTtcbiAgICB9XG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZpbHRlcigndEJyZWFkY3J1bWInLCB0QnJlYWRjcnVtYik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiB0QnJlYWRjcnVtYigkZmlsdGVyKSB7XG4gICAgLyoqXG4gICAgICogRmlsdHJvIHBhcmEgdHJhZHXDp8OjbyBkbyBicmVhZGNydW1iICh0aXR1bG8gZGEgdGVsYSBjb20gcmFzdHJlaW8pXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gaWQgY2hhdmUgY29tIG8gbm9tZSBkbyBzdGF0ZSByZWZlcmVudGUgdGVsYVxuICAgICAqIEByZXR1cm5zIGEgdHJhZHXDp8OjbyBjYXNvIGVuY29udHJlIHNlIG7Do28gbyBpZCBwYXNzYWRvIHBvciBwYXJhbWV0cm9cbiAgICAgKi9cbiAgICByZXR1cm4gZnVuY3Rpb24oaWQpIHtcbiAgICAgIC8vcGVnYSBhIHNlZ3VuZGEgcGFydGUgZG8gbm9tZSBkbyBzdGF0ZSwgcmV0aXJhbmRvIGEgcGFydGUgYWJzdHJhdGEgKGFwcC4pXG4gICAgICB2YXIga2V5ID0gJ3ZpZXdzLmJyZWFkY3J1bWJzLicgKyBpZC5zcGxpdCgnLicpWzFdO1xuICAgICAgdmFyIHRyYW5zbGF0ZSA9ICRmaWx0ZXIoJ3RyYW5zbGF0ZScpKGtleSk7XG5cbiAgICAgIHJldHVybiAodHJhbnNsYXRlID09PSBrZXkpID8gaWQgOiB0cmFuc2xhdGU7XG4gICAgfVxuICB9XG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5maWx0ZXIoJ3RNb2RlbCcsIHRNb2RlbCk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiB0TW9kZWwoJGZpbHRlcikge1xuICAgIC8qKlxuICAgICAqIEZpbHRybyBwYXJhIHRyYWR1w6fDo28gZGUgdW0gYXRyaWJ1dG8gZGUgdW0gbW9kZWxcbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSBuYW1lIG5vbWUgZG8gYXRyaWJ1dG9cbiAgICAgKiBAcmV0dXJucyBvIG5vbWUgZG8gYXRyaWJ1dG8gdHJhZHV6aWRvIGNhc28gZW5jb250cmUgc2UgbsOjbyBvIG5vbWUgcGFzc2FkbyBwb3IgcGFyYW1ldHJvXG4gICAgICovXG4gICAgcmV0dXJuIGZ1bmN0aW9uKG5hbWUpIHtcbiAgICAgIHZhciBrZXkgPSAnbW9kZWxzLicgKyBuYW1lLnRvTG93ZXJDYXNlKCk7XG4gICAgICB2YXIgdHJhbnNsYXRlID0gJGZpbHRlcigndHJhbnNsYXRlJykoa2V5KTtcblxuICAgICAgcmV0dXJuICh0cmFuc2xhdGUgPT09IGtleSkgPyBuYW1lIDogdHJhbnNsYXRlO1xuICAgIH1cbiAgfVxuXG59KSgpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLnJ1bihhdXRoZW50aWNhdGlvbkxpc3RlbmVyKTtcblxuICAvKipcbiAgICogTGlzdGVuIGFsbCBzdGF0ZSAocGFnZSkgY2hhbmdlcy4gRXZlcnkgdGltZSBhIHN0YXRlIGNoYW5nZSBuZWVkIHRvIHZlcmlmeSB0aGUgdXNlciBpcyBhdXRoZW50aWNhdGVkIG9yIG5vdCB0b1xuICAgKiByZWRpcmVjdCB0byBjb3JyZWN0IHBhZ2UuIFdoZW4gYSB1c2VyIGNsb3NlIHRoZSBicm93c2VyIHdpdGhvdXQgbG9nb3V0LCB3aGVuIGhpbSByZW9wZW4gdGhlIGJyb3dzZXIgdGhpcyBldmVudFxuICAgKiByZWF1dGhlbnRpY2F0ZSB0aGUgdXNlciB3aXRoIHRoZSBwZXJzaXN0ZW50IHRva2VuIG9mIHRoZSBsb2NhbCBzdG9yYWdlLlxuICAgKlxuICAgKiBXZSBkb24ndCBjaGVjayBpZiB0aGUgdG9rZW4gaXMgZXhwaXJlZCBvciBub3QgaW4gdGhlIHBhZ2UgY2hhbmdlLCBiZWNhdXNlIGlzIGdlbmVyYXRlIGFuIHVuZWNlc3Nhcnkgb3ZlcmhlYWQuXG4gICAqIElmIHRoZSB0b2tlbiBpcyBleHBpcmVkIHdoZW4gdGhlIHVzZXIgdHJ5IHRvIGNhbGwgdGhlIGZpcnN0IGFwaSB0byBnZXQgZGF0YSwgaGltIHdpbGwgYmUgbG9nb2ZmIGFuZCByZWRpcmVjdFxuICAgKiB0byBsb2dpbiBwYWdlLlxuICAgKlxuICAgKiBAcGFyYW0gJHJvb3RTY29wZVxuICAgKiBAcGFyYW0gJHN0YXRlXG4gICAqIEBwYXJhbSAkc3RhdGVQYXJhbXNcbiAgICogQHBhcmFtIEF1dGhcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gYXV0aGVudGljYXRpb25MaXN0ZW5lcigkcm9vdFNjb3BlLCAkc3RhdGUsIEdsb2JhbCwgQXV0aCwgUHJUb2FzdCwgLy8gTk9TT05BUlxuICAgICR0cmFuc2xhdGUpIHtcblxuICAgIC8vb25seSB3aGVuIGFwcGxpY2F0aW9uIHN0YXJ0IGNoZWNrIGlmIHRoZSBleGlzdGVudCB0b2tlbiBzdGlsbCB2YWxpZFxuICAgIEF1dGgucmVtb3RlVmFsaWRhdGVUb2tlbigpLnRoZW4oZnVuY3Rpb24oKSB7XG4gICAgICAvL2lmIHRoZSB0b2tlbiBpcyB2YWxpZCBjaGVjayBpZiBleGlzdHMgdGhlIHVzZXIgYmVjYXVzZSB0aGUgYnJvd3NlciBjb3VsZCBiZSBjbG9zZWRcbiAgICAgIC8vYW5kIHRoZSB1c2VyIGRhdGEgaXNuJ3QgaW4gbWVtb3J5XG4gICAgICBpZiAoQXV0aC5jdXJyZW50VXNlciA9PT0gbnVsbCkge1xuICAgICAgICBBdXRoLnVwZGF0ZUN1cnJlbnRVc2VyKGFuZ3VsYXIuZnJvbUpzb24obG9jYWxTdG9yYWdlLmdldEl0ZW0oJ3VzZXInKSkpO1xuICAgICAgfVxuICAgIH0pO1xuXG4gICAgLy9DaGVjayBpZiB0aGUgdG9rZW4gc3RpbGwgdmFsaWQuXG4gICAgJHJvb3RTY29wZS4kb24oJyRzdGF0ZUNoYW5nZVN0YXJ0JywgZnVuY3Rpb24oZXZlbnQsIHRvU3RhdGUpIHtcbiAgICAgIGlmICh0b1N0YXRlLmRhdGEubmVlZEF1dGhlbnRpY2F0aW9uIHx8IHRvU3RhdGUuZGF0YS5uZWVkUHJvZmlsZSkge1xuICAgICAgICAvL2RvbnQgdHJhaXQgdGhlIHN1Y2Nlc3MgYmxvY2sgYmVjYXVzZSBhbHJlYWR5IGRpZCBieSB0b2tlbiBpbnRlcmNlcHRvclxuICAgICAgICBBdXRoLnJlbW90ZVZhbGlkYXRlVG9rZW4oKS5jYXRjaChmdW5jdGlvbigpIHtcbiAgICAgICAgICBQclRvYXN0Lndhcm4oJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5sb2dpbi5sb2dvdXRJbmFjdGl2ZScpKTtcblxuICAgICAgICAgIGlmICh0b1N0YXRlLm5hbWUgIT09IEdsb2JhbC5sb2dpblN0YXRlKSB7XG4gICAgICAgICAgICAkc3RhdGUuZ28oR2xvYmFsLmxvZ2luU3RhdGUpO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIGV2ZW50LnByZXZlbnREZWZhdWx0KCk7XG4gICAgICAgIH0pO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgLy9pZiB0aGUgdXNlIGlzIGF1dGhlbnRpY2F0ZWQgYW5kIG5lZWQgdG8gZW50ZXIgaW4gbG9naW4gcGFnZVxuICAgICAgICAvL2hpbSB3aWxsIGJlIHJlZGlyZWN0ZWQgdG8gaG9tZSBwYWdlXG4gICAgICAgIGlmICh0b1N0YXRlLm5hbWUgPT09IEdsb2JhbC5sb2dpblN0YXRlICYmIEF1dGguYXV0aGVudGljYXRlZCgpKSB7XG4gICAgICAgICAgJHN0YXRlLmdvKEdsb2JhbC5ob21lU3RhdGUpO1xuICAgICAgICAgIGV2ZW50LnByZXZlbnREZWZhdWx0KCk7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9KTtcbiAgfVxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5ydW4oYXV0aG9yaXphdGlvbkxpc3RlbmVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIGF1dGhvcml6YXRpb25MaXN0ZW5lcigkcm9vdFNjb3BlLCAkc3RhdGUsIEdsb2JhbCwgQXV0aCkge1xuICAgIC8qKlxuICAgICAqIEEgY2FkYSBtdWRhbsOnYSBkZSBlc3RhZG8gKFwicMOhZ2luYVwiKSB2ZXJpZmljYSBzZSBvIHVzdcOhcmlvIHRlbSBvIHBlcmZpbFxuICAgICAqIG5lY2Vzc8OhcmlvIHBhcmEgbyBhY2Vzc28gYSBtZXNtYVxuICAgICAqL1xuICAgICRyb290U2NvcGUuJG9uKCckc3RhdGVDaGFuZ2VTdGFydCcsIGZ1bmN0aW9uKGV2ZW50LCB0b1N0YXRlKSB7XG4gICAgICBpZiAodG9TdGF0ZS5kYXRhICYmIHRvU3RhdGUuZGF0YS5uZWVkQXV0aGVudGljYXRpb24gJiZcbiAgICAgICAgdG9TdGF0ZS5kYXRhLm5lZWRQcm9maWxlICYmIEF1dGguYXV0aGVudGljYXRlZCgpICYmXG4gICAgICAgICFBdXRoLmN1cnJlbnRVc2VyLmhhc1Byb2ZpbGUodG9TdGF0ZS5kYXRhLm5lZWRQcm9maWxlLCB0b1N0YXRlLmRhdGEuYWxsUHJvZmlsZXMpKSB7XG5cbiAgICAgICAgJHN0YXRlLmdvKEdsb2JhbC5ub3RBdXRob3JpemVkU3RhdGUpO1xuICAgICAgICBldmVudC5wcmV2ZW50RGVmYXVsdCgpO1xuICAgICAgfVxuXG4gICAgfSk7XG4gIH1cbn0oKSk7XG4iLCIoZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbmZpZyhzcGlubmVySW50ZXJjZXB0b3IpO1xuXG4gIGZ1bmN0aW9uIHNwaW5uZXJJbnRlcmNlcHRvcigkaHR0cFByb3ZpZGVyLCAkcHJvdmlkZSkge1xuICAgIC8qKlxuICAgICAqIEVzdGUgaW50ZXJjZXB0b3Igw6kgcmVzcG9uc8OhdmVsIHBvciBtb3N0cmFyIGUgZXNjb25kZXIgb1xuICAgICAqIGNvbXBvbmVudGUgUHJTcGlubmVyIHNlbXByZSBxdWUgdW1hIHJlcXVpc2nDp8OjbyBhamF4XG4gICAgICogaW5pY2lhciBlIGZpbmFsaXphci5cbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSAkcVxuICAgICAqIEBwYXJhbSB7YW55fSAkaW5qZWN0b3JcbiAgICAgKiBAcmV0dXJuc1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIHNob3dIaWRlU3Bpbm5lcigkcSwgJGluamVjdG9yKSB7XG4gICAgICByZXR1cm4ge1xuICAgICAgICByZXF1ZXN0OiBmdW5jdGlvbiAoY29uZmlnKSB7XG4gICAgICAgICAgJGluamVjdG9yLmdldCgnUHJTcGlubmVyJykuc2hvdygpO1xuXG4gICAgICAgICAgcmV0dXJuIGNvbmZpZztcbiAgICAgICAgfSxcblxuICAgICAgICByZXNwb25zZTogZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgICAgJGluamVjdG9yLmdldCgnUHJTcGlubmVyJykuaGlkZSgpO1xuXG4gICAgICAgICAgcmV0dXJuIHJlc3BvbnNlO1xuICAgICAgICB9LFxuXG4gICAgICAgIHJlc3BvbnNlRXJyb3I6IGZ1bmN0aW9uIChyZWplY3Rpb24pIHtcbiAgICAgICAgICAkaW5qZWN0b3IuZ2V0KCdQclNwaW5uZXInKS5oaWRlKCk7XG5cbiAgICAgICAgICByZXR1cm4gJHEucmVqZWN0KHJlamVjdGlvbik7XG4gICAgICAgIH1cbiAgICAgIH07XG4gICAgfVxuXG4gICAgLy8gRGVmaW5lIHVtYSBmYWN0b3J5IHBhcmEgbyAkaHR0cEludGVyY2VwdG9yXG4gICAgJHByb3ZpZGUuZmFjdG9yeSgnc2hvd0hpZGVTcGlubmVyJywgc2hvd0hpZGVTcGlubmVyKTtcblxuICAgIC8vIEFkaWNpb25hIGEgZmFjdG9yeSBubyBhcnJheSBkZSBpbnRlcmNlcHRvcnMgZG8gJGh0dHBcbiAgICAkaHR0cFByb3ZpZGVyLmludGVyY2VwdG9ycy5wdXNoKCdzaG93SGlkZVNwaW5uZXInKTtcbiAgfVxufSgpKTtcbiIsIi8qZXNsaW50IGFuZ3VsYXIvbW9kdWxlLWdldHRlcjogMCovXG5cbihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb25maWcodG9rZW5JbnRlcmNlcHRvcik7XG5cbiAgLyoqXG4gICAqIEludGVyY2VwdCBhbGwgcmVzcG9uc2UgKHN1Y2Nlc3Mgb3IgZXJyb3IpIHRvIHZlcmlmeSB0aGUgcmV0dXJuZWQgdG9rZW5cbiAgICpcbiAgICogQHBhcmFtICRodHRwUHJvdmlkZXJcbiAgICogQHBhcmFtICRwcm92aWRlXG4gICAqIEBwYXJhbSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gdG9rZW5JbnRlcmNlcHRvcigkaHR0cFByb3ZpZGVyLCAkcHJvdmlkZSwgR2xvYmFsKSB7XG5cbiAgICBmdW5jdGlvbiByZWRpcmVjdFdoZW5TZXJ2ZXJMb2dnZWRPdXQoJHEsICRpbmplY3Rvcikge1xuICAgICAgcmV0dXJuIHtcbiAgICAgICAgcmVxdWVzdDogZnVuY3Rpb24oY29uZmlnKSB7XG4gICAgICAgICAgdmFyIHRva2VuID0gJGluamVjdG9yLmdldCgnQXV0aCcpLmdldFRva2VuKCk7XG5cbiAgICAgICAgICBpZiAodG9rZW4pIHtcbiAgICAgICAgICAgIGNvbmZpZy5oZWFkZXJzWydBdXRob3JpemF0aW9uJ10gPSAnQmVhcmVyICcgKyB0b2tlbjtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICByZXR1cm4gY29uZmlnO1xuICAgICAgICB9LFxuICAgICAgICByZXNwb25zZTogZnVuY3Rpb24ocmVzcG9uc2UpIHtcbiAgICAgICAgICAvLyBnZXQgYSBuZXcgcmVmcmVzaCB0b2tlbiB0byB1c2UgaW4gdGhlIG5leHQgcmVxdWVzdFxuICAgICAgICAgIHZhciB0b2tlbiA9IHJlc3BvbnNlLmhlYWRlcnMoJ0F1dGhvcml6YXRpb24nKTtcblxuICAgICAgICAgIGlmICh0b2tlbikge1xuICAgICAgICAgICAgJGluamVjdG9yLmdldCgnQXV0aCcpLnNldFRva2VuKHRva2VuLnNwbGl0KCcgJylbMV0pO1xuICAgICAgICAgIH1cbiAgICAgICAgICByZXR1cm4gcmVzcG9uc2U7XG4gICAgICAgIH0sXG4gICAgICAgIHJlc3BvbnNlRXJyb3I6IGZ1bmN0aW9uKHJlamVjdGlvbikge1xuICAgICAgICAgIC8vIEluc3RlYWQgb2YgY2hlY2tpbmcgZm9yIGEgc3RhdHVzIGNvZGUgb2YgNDAwIHdoaWNoIG1pZ2h0IGJlIHVzZWRcbiAgICAgICAgICAvLyBmb3Igb3RoZXIgcmVhc29ucyBpbiBMYXJhdmVsLCB3ZSBjaGVjayBmb3IgdGhlIHNwZWNpZmljIHJlamVjdGlvblxuICAgICAgICAgIC8vIHJlYXNvbnMgdG8gdGVsbCB1cyBpZiB3ZSBuZWVkIHRvIHJlZGlyZWN0IHRvIHRoZSBsb2dpbiBzdGF0ZVxuICAgICAgICAgIHZhciByZWplY3Rpb25SZWFzb25zID0gWyd0b2tlbl9ub3RfcHJvdmlkZWQnLCAndG9rZW5fZXhwaXJlZCcsICd0b2tlbl9hYnNlbnQnLCAndG9rZW5faW52YWxpZCddO1xuXG4gICAgICAgICAgdmFyIHRva2VuRXJyb3IgPSBmYWxzZTtcblxuICAgICAgICAgIGFuZ3VsYXIuZm9yRWFjaChyZWplY3Rpb25SZWFzb25zLCBmdW5jdGlvbih2YWx1ZSkge1xuICAgICAgICAgICAgaWYgKHJlamVjdGlvbi5kYXRhICYmIHJlamVjdGlvbi5kYXRhLmVycm9yID09PSB2YWx1ZSkge1xuICAgICAgICAgICAgICB0b2tlbkVycm9yID0gdHJ1ZTtcblxuICAgICAgICAgICAgICAkaW5qZWN0b3IuZ2V0KCdBdXRoJykubG9nb3V0KCkudGhlbihmdW5jdGlvbigpIHtcbiAgICAgICAgICAgICAgICB2YXIgJHN0YXRlID0gJGluamVjdG9yLmdldCgnJHN0YXRlJyk7XG5cbiAgICAgICAgICAgICAgICAvLyBpbiBjYXNlIG11bHRpcGxlIGFqYXggcmVxdWVzdCBmYWlsIGF0IHNhbWUgdGltZSBiZWNhdXNlIHRva2VuIHByb2JsZW1zLFxuICAgICAgICAgICAgICAgIC8vIG9ubHkgdGhlIGZpcnN0IHdpbGwgcmVkaXJlY3RcbiAgICAgICAgICAgICAgICBpZiAoISRzdGF0ZS5pcyhHbG9iYWwubG9naW5TdGF0ZSkpIHtcbiAgICAgICAgICAgICAgICAgICRzdGF0ZS5nbyhHbG9iYWwubG9naW5TdGF0ZSk7XG5cbiAgICAgICAgICAgICAgICAgIC8vY2xvc2UgYW55IGRpYWxvZyB0aGF0IGlzIG9wZW5lZFxuICAgICAgICAgICAgICAgICAgJGluamVjdG9yLmdldCgnUHJEaWFsb2cnKS5jbG9zZSgpO1xuXG4gICAgICAgICAgICAgICAgICBldmVudC5wcmV2ZW50RGVmYXVsdCgpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfSk7XG5cbiAgICAgICAgICAvL2RlZmluZSBkYXRhIHRvIGVtcHR5IGJlY2F1c2UgYWxyZWFkeSBzaG93IFByVG9hc3QgdG9rZW4gbWVzc2FnZVxuICAgICAgICAgIGlmICh0b2tlbkVycm9yKSB7XG4gICAgICAgICAgICByZWplY3Rpb24uZGF0YSA9IHt9O1xuICAgICAgICAgIH1cblxuICAgICAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24ocmVqZWN0aW9uLmhlYWRlcnMpKSB7XG4gICAgICAgICAgICAvLyBtYW55IHNlcnZlcnMgZXJyb3JzIChidXNpbmVzcykgYXJlIGludGVyY2VwdCBoZXJlIGJ1dCBnZW5lcmF0ZWQgYSBuZXcgcmVmcmVzaCB0b2tlblxuICAgICAgICAgICAgLy8gYW5kIG5lZWQgdXBkYXRlIGN1cnJlbnQgdG9rZW5cbiAgICAgICAgICAgIHZhciB0b2tlbiA9IHJlamVjdGlvbi5oZWFkZXJzKCdBdXRob3JpemF0aW9uJyk7XG5cbiAgICAgICAgICAgIGlmICh0b2tlbikge1xuICAgICAgICAgICAgICAkaW5qZWN0b3IuZ2V0KCdBdXRoJykuc2V0VG9rZW4odG9rZW4uc3BsaXQoJyAnKVsxXSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgcmV0dXJuICRxLnJlamVjdChyZWplY3Rpb24pO1xuICAgICAgICB9XG4gICAgICB9O1xuICAgIH1cblxuICAgIC8vIFNldHVwIGZvciB0aGUgJGh0dHBJbnRlcmNlcHRvclxuICAgICRwcm92aWRlLmZhY3RvcnkoJ3JlZGlyZWN0V2hlblNlcnZlckxvZ2dlZE91dCcsIHJlZGlyZWN0V2hlblNlcnZlckxvZ2dlZE91dCk7XG5cbiAgICAvLyBQdXNoIHRoZSBuZXcgZmFjdG9yeSBvbnRvIHRoZSAkaHR0cCBpbnRlcmNlcHRvciBhcnJheVxuICAgICRodHRwUHJvdmlkZXIuaW50ZXJjZXB0b3JzLnB1c2goJ3JlZGlyZWN0V2hlblNlcnZlckxvZ2dlZE91dCcpO1xuICB9XG5cbn0oKSk7XG4iLCIoZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbmZpZyh2YWxpZGF0aW9uSW50ZXJjZXB0b3IpO1xuXG4gIGZ1bmN0aW9uIHZhbGlkYXRpb25JbnRlcmNlcHRvcigkaHR0cFByb3ZpZGVyLCAkcHJvdmlkZSkge1xuICAgIC8qKlxuICAgICAqIEVzdGUgaW50ZXJjZXB0b3Igw6kgcmVzcG9uc8OhdmVsIHBvciBtb3N0cmFyIGFzXG4gICAgICogbWVuc2FnZW5zIGRlIGVycm8gcmVmZXJlbnRlIGFzIHZhbGlkYcOnw7VlcyBkbyBiYWNrLWVuZFxuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9ICRxXG4gICAgICogQHBhcmFtIHthbnl9ICRpbmplY3RvclxuICAgICAqIEByZXR1cm5zXG4gICAgICovXG4gICAgZnVuY3Rpb24gc2hvd0Vycm9yVmFsaWRhdGlvbigkcSwgJGluamVjdG9yKSB7XG4gICAgICByZXR1cm4ge1xuICAgICAgICByZXNwb25zZUVycm9yOiBmdW5jdGlvbiAocmVqZWN0aW9uKSB7XG4gICAgICAgICAgdmFyIFByVG9hc3QgPSAkaW5qZWN0b3IuZ2V0KCdQclRvYXN0Jyk7XG4gICAgICAgICAgdmFyICR0cmFuc2xhdGUgPSAkaW5qZWN0b3IuZ2V0KCckdHJhbnNsYXRlJyk7XG5cbiAgICAgICAgICBpZiAocmVqZWN0aW9uLmNvbmZpZy5kYXRhICYmICFyZWplY3Rpb24uY29uZmlnLmRhdGEuc2tpcFZhbGlkYXRpb24pIHtcbiAgICAgICAgICAgIGlmIChyZWplY3Rpb24uZGF0YSAmJiByZWplY3Rpb24uZGF0YS5lcnJvcikge1xuXG4gICAgICAgICAgICAgIC8vdmVyaWZpY2Egc2Ugb2NvcnJldSBhbGd1bSBlcnJvIHJlZmVyZW50ZSBhbyB0b2tlblxuICAgICAgICAgICAgICBpZiAocmVqZWN0aW9uLmRhdGEuZXJyb3Iuc3RhcnRzV2l0aCgndG9rZW5fJykpIHtcbiAgICAgICAgICAgICAgICBQclRvYXN0Lndhcm4oJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5sb2dpbi5sb2dvdXRJbmFjdGl2ZScpKTtcbiAgICAgICAgICAgICAgfSBlbHNlIGlmIChyZWplY3Rpb24uZGF0YS5lcnJvciAhPT0gJ05vdCBGb3VuZCcpIHtcbiAgICAgICAgICAgICAgICBQclRvYXN0LmVycm9yKCR0cmFuc2xhdGUuaW5zdGFudChyZWplY3Rpb24uZGF0YS5lcnJvcikpO1xuICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICBQclRvYXN0LmVycm9yVmFsaWRhdGlvbihyZWplY3Rpb24uZGF0YSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgcmV0dXJuICRxLnJlamVjdChyZWplY3Rpb24pO1xuICAgICAgICB9XG4gICAgICB9O1xuICAgIH1cblxuICAgIC8vIERlZmluZSB1bWEgZmFjdG9yeSBwYXJhIG8gJGh0dHBJbnRlcmNlcHRvclxuICAgICRwcm92aWRlLmZhY3RvcnkoJ3Nob3dFcnJvclZhbGlkYXRpb24nLCBzaG93RXJyb3JWYWxpZGF0aW9uKTtcblxuICAgIC8vIEFkaWNpb25hIGEgZmFjdG9yeSBubyBhcnJheSBkZSBpbnRlcmNlcHRvcnMgZG8gJGh0dHBcbiAgICAkaHR0cFByb3ZpZGVyLmludGVyY2VwdG9ycy5wdXNoKCdzaG93RXJyb3JWYWxpZGF0aW9uJyk7XG4gIH1cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb250cm9sbGVyKCdLYW5iYW5Db250cm9sbGVyJywgS2FuYmFuQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBLYW5iYW5Db250cm9sbGVyKCRjb250cm9sbGVyLFxuICAgIFRhc2tzU2VydmljZSxcbiAgICBTdGF0dXNTZXJ2aWNlLFxuICAgIFByVG9hc3QsXG4gICAgJG1kRGlhbG9nLFxuICAgICRkb2N1bWVudCxcbiAgICBBdXRoLFxuICAgIFByb2plY3RzU2VydmljZSkge1xuICAgIC8vQXR0cmlidXRlcyBCbG9ja1xuICAgIHZhciB2bSA9IHRoaXM7XG4gICAgdmFyIGZpZWxkcyA9IFtcbiAgICAgIHsgbmFtZTogJ2lkJywgdHlwZTogJ3N0cmluZycgfSxcbiAgICAgIHsgbmFtZTogJ3N0YXR1cycsIG1hcDogJ3N0YXRlJywgdHlwZTogJ3N0cmluZycgfSxcbiAgICAgIHsgbmFtZTogJ3RleHQnLCBtYXA6ICdsYWJlbCcsIHR5cGU6ICdzdHJpbmcnIH0sXG4gICAgICB7IG5hbWU6ICd0YWdzJywgdHlwZTogJ3N0cmluZycgfVxuICAgIF07XG5cbiAgICB2bS5vbkFjdGl2YXRlID0gZnVuY3Rpb24oKSB7XG4gICAgICB2bS5wcm9qZWN0ID0gbG9jYWxTdG9yYWdlLmdldEl0ZW0oJ3Byb2plY3QnKTtcbiAgICAgIFByb2plY3RzU2VydmljZS5xdWVyeSh7IHByb2plY3RfaWQ6IHZtLnByb2plY3QgfSkudGhlbihmdW5jdGlvbihyZXNwb25zZSkge1xuICAgICAgICB2bS5hY3R1YWxQcm9qZWN0ID0gcmVzcG9uc2VbMF07XG4gICAgICB9KVxuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0geyBwcm9qZWN0X2lkOiB2bS5wcm9qZWN0IH07XG4gICAgICB2bS5pc01vdmVkID0gZmFsc2U7XG4gICAgfVxuXG4gICAgdm0uYXBwbHlGaWx0ZXJzID0gZnVuY3Rpb24oZGVmYXVsdFF1ZXJ5RmlsdGVycykge1xuICAgICAgcmV0dXJuIGFuZ3VsYXIuZXh0ZW5kKGRlZmF1bHRRdWVyeUZpbHRlcnMsIHZtLnF1ZXJ5RmlsdGVycyk7XG4gICAgfVxuXG4gICAgdm0uYWZ0ZXJTZWFyY2ggPSBmdW5jdGlvbiAoKSB7XG4gICAgICB2YXIgY29sdW1ucyA9IFtdO1xuICAgICAgdmFyIHRhc2tzID0gW107XG5cbiAgICAgIFN0YXR1c1NlcnZpY2UucXVlcnkoKS50aGVuKGZ1bmN0aW9uKHJlc3BvbnNlKSB7XG4gICAgICAgIHJlc3BvbnNlLmZvckVhY2goZnVuY3Rpb24oc3RhdHVzKSB7XG4gICAgICAgICAgY29sdW1ucy5wdXNoKHsgdGV4dDogc3RhdHVzLm5hbWUsIGRhdGFGaWVsZDogc3RhdHVzLnNsdWcsIGNvbGxhcHNpYmxlOiBmYWxzZSB9KTtcbiAgICAgICAgfSk7XG5cbiAgICAgICAgaWYgKHZtLnJlc291cmNlcy5sZW5ndGggPiAwKSB7XG4gICAgICAgICAgdm0ucmVzb3VyY2VzLmZvckVhY2goZnVuY3Rpb24odGFzaykge1xuICAgICAgICAgICAgdGFza3MucHVzaCh7XG4gICAgICAgICAgICAgIGlkOiB0YXNrLmlkLFxuICAgICAgICAgICAgICBzdGF0ZTogdGFzay5zdGF0dXMuc2x1ZyxcbiAgICAgICAgICAgICAgbGFiZWw6IHRhc2sudGl0bGUsXG4gICAgICAgICAgICAgIHRhZ3M6IHRhc2sudHlwZS5uYW1lICsgJywgJyArIHRhc2sucHJpb3JpdHkubmFtZVxuICAgICAgICAgICAgfSlcbiAgICAgICAgICB9KTtcblxuICAgICAgICAgIHZhciBzb3VyY2UgPSB7XG4gICAgICAgICAgICBsb2NhbERhdGE6IHRhc2tzLFxuICAgICAgICAgICAgZGF0YVR5cGU6ICdhcnJheScsXG4gICAgICAgICAgICBkYXRhRmllbGRzOiBmaWVsZHNcbiAgICAgICAgICB9O1xuICAgICAgICAgIHZhciBkYXRhQWRhcHRlciA9IG5ldyAkLmpxeC5kYXRhQWRhcHRlcihzb3VyY2UpO1xuXG4gICAgICAgICAgdm0uc2V0dGluZ3MgPSB7XG4gICAgICAgICAgICBzb3VyY2U6IGRhdGFBZGFwdGVyLFxuICAgICAgICAgICAgY29sdW1uczogY29sdW1ucyxcbiAgICAgICAgICAgIHRoZW1lOiAnbGlnaHQnXG4gICAgICAgICAgfTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICB2bS5zZXR0aW5ncyA9IHtcbiAgICAgICAgICAgIHNvdXJjZTogW3t9XSxcbiAgICAgICAgICAgIGNvbHVtbnM6IGNvbHVtbnMsXG4gICAgICAgICAgICB0aGVtZTogJ2xpZ2h0J1xuICAgICAgICAgIH07XG4gICAgICAgIH1cbiAgICAgICAgdm0ua2FuYmFuUmVhZHkgPSB0cnVlO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgdm0ub25JdGVtTW92ZWQgPSBmdW5jdGlvbihldmVudCkge1xuICAgICAgaWYgKEF1dGguY3VycmVudFVzZXIuaWQgPT09IHZtLmFjdHVhbFByb2plY3Qub3duZXIpIHtcbiAgICAgICAgdm0uaXNNb3ZlZCA9IHRydWU7XG4gICAgICAgIFRhc2tzU2VydmljZS5xdWVyeSh7IHRhc2tfaWQ6IGV2ZW50LmFyZ3MuaXRlbUlkIH0pLnRoZW4oZnVuY3Rpb24ocmVzcG9uc2UpIHtcbiAgICAgICAgICBpZiAoKHJlc3BvbnNlWzBdLm1pbGVzdG9uZSAmJiByZXNwb25zZVswXS5taWxlc3RvbmUuZG9uZSkgfHwgcmVzcG9uc2VbMF0ucHJvamVjdC5kb25lKSB7XG4gICAgICAgICAgICBQclRvYXN0LmVycm9yKCdOw6NvIMOpIHBvc3PDrXZlbCBtb2RpZmljYXIgbyBzdGF0dXMgZGUgdW1hIHRhcmVmYSBmaW5hbGl6YWRhLicpO1xuICAgICAgICAgICAgdm0uYWZ0ZXJTZWFyY2goKTtcbiAgICAgICAgICAgIHZtLmlzTW92ZWQgPSBmYWxzZTtcbiAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgVGFza3NTZXJ2aWNlLnVwZGF0ZVRhc2tCeUthbmJhbih7XG4gICAgICAgICAgICAgIHByb2plY3RfaWQ6IHZtLnByb2plY3QsXG4gICAgICAgICAgICAgIGlkOiBldmVudC5hcmdzLml0ZW1JZCxcbiAgICAgICAgICAgICAgb2xkQ29sdW1uOiBldmVudC5hcmdzLm9sZENvbHVtbixcbiAgICAgICAgICAgICAgbmV3Q29sdW1uOiBldmVudC5hcmdzLm5ld0NvbHVtbiB9KS50aGVuKGZ1bmN0aW9uKCkge1xuICAgICAgICAgICAgICAgIHZtLmlzTW92ZWQgPSBmYWxzZTtcbiAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgfVxuICAgICAgICB9KTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHZtLmFmdGVyU2VhcmNoKCk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgdm0ub25JdGVtQ2xpY2tlZCA9IGZ1bmN0aW9uKGV2ZW50KSB7XG4gICAgICBpZiAoIXZtLmlzTW92ZWQpIHtcbiAgICAgICAgVGFza3NTZXJ2aWNlLnF1ZXJ5KHsgdGFza19pZDogZXZlbnQuYXJncy5pdGVtSWQgfSkudGhlbihmdW5jdGlvbihyZXNwb25zZSkge1xuICAgICAgICAgIHZtLnRhc2tJbmZvID0gcmVzcG9uc2VbMF07XG4gICAgICAgICAgJG1kRGlhbG9nLnNob3coe1xuICAgICAgICAgICAgcGFyZW50OiBhbmd1bGFyLmVsZW1lbnQoJGRvY3VtZW50LmJvZHkpLFxuICAgICAgICAgICAgdGVtcGxhdGVVcmw6ICdjbGllbnQvYXBwL2thbmJhbi90YXNrLWluZm8tZGlhbG9nL3Rhc2tJbmZvLmh0bWwnLFxuICAgICAgICAgICAgY29udHJvbGxlckFzOiAndGFza0luZm9DdHJsJyxcbiAgICAgICAgICAgIGNvbnRyb2xsZXI6ICdUYXNrSW5mb0NvbnRyb2xsZXInLFxuICAgICAgICAgICAgYmluZFRvQ29udHJvbGxlcjogdHJ1ZSxcbiAgICAgICAgICAgIGxvY2Fsczoge1xuICAgICAgICAgICAgICB0YXNrOiB2bS50YXNrSW5mbyxcbiAgICAgICAgICAgICAgY2xvc2U6IGNsb3NlXG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgZXNjYXBlVG9DbG9zZTogdHJ1ZSxcbiAgICAgICAgICAgIGNsaWNrT3V0c2lkZVRvQ2xvc2U6IHRydWVcbiAgICAgICAgICB9KTtcbiAgICAgICAgfSk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICB2bS5pc01vdmVkID0gZmFsc2U7XG4gICAgICB9XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gY2xvc2UoKSB7XG4gICAgICAkbWREaWFsb2cuaGlkZSgpO1xuICAgIH1cblxuICAgIC8vIGluc3RhbnRpYXRlIGJhc2UgY29udHJvbGxlclxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHsgdm06IHZtLCBtb2RlbFNlcnZpY2U6IFRhc2tzU2VydmljZSwgb3B0aW9uczogeyB9IH0pO1xuXG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb25maWcocm91dGVzKTtcblxuICAvKipcbiAgICogQXJxdWl2byBkZSBjb25maWd1cmHDp8OjbyBjb20gYXMgcm90YXMgZXNwZWPDrWZpY2FzIGRvIHJlY3Vyc28ga2FuYmFuXG4gICAqXG4gICAqIEBwYXJhbSB7b2JqZWN0fSAkc3RhdGVQcm92aWRlclxuICAgKiBAcGFyYW0ge29iamVjdH0gR2xvYmFsXG4gICAqL1xuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvdXRlcygkc3RhdGVQcm92aWRlciwgR2xvYmFsKSB7XG4gICAgJHN0YXRlUHJvdmlkZXJcbiAgICAgIC5zdGF0ZSgnYXBwLmthbmJhbicsIHtcbiAgICAgICAgdXJsOiAnL2thbmJhbicsXG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcva2FuYmFuL2thbmJhbi5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ0thbmJhbkNvbnRyb2xsZXIgYXMga2FuYmFuQ3RybCcsXG4gICAgICAgIGRhdGE6IHsgfVxuICAgICAgfSk7XG4gIH1cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmFjdG9yeSgnS2FuYmFuU2VydmljZScsIEthbmJhblNlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gS2FuYmFuU2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHZhciBtb2RlbCA9IHNlcnZpY2VGYWN0b3J5KCdrYW5iYW4nLCB7XG4gICAgICBhY3Rpb25zOiB7IH0sXG4gICAgICBpbnN0YW5jZTogeyB9XG4gICAgfSk7XG5cbiAgICByZXR1cm4gbW9kZWw7XG4gIH1cblxufSgpKTtcbiIsIi8qZXNsaW50LWVudiBlczYqL1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29udHJvbGxlcignTWVudUNvbnRyb2xsZXInLCBNZW51Q29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiBNZW51Q29udHJvbGxlcigkbWRTaWRlbmF2LCAkc3RhdGUsICRtZENvbG9ycykge1xuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICAvL0Jsb2NvIGRlIGRlY2xhcmFjb2VzIGRlIGZ1bmNvZXNcbiAgICB2bS5vcGVuID0gb3BlbjtcbiAgICB2bS5vcGVuTWVudU9yUmVkaXJlY3RUb1N0YXRlID0gb3Blbk1lbnVPclJlZGlyZWN0VG9TdGF0ZTtcblxuICAgIGFjdGl2YXRlKCk7XG5cbiAgICBmdW5jdGlvbiBhY3RpdmF0ZSgpIHtcbiAgICAgIHZhciBtZW51UHJlZml4ID0gJ3ZpZXdzLmxheW91dC5tZW51Lic7XG5cbiAgICAgIC8vIEFycmF5IGNvbnRlbmRvIG9zIGl0ZW5zIHF1ZSBzw6NvIG1vc3RyYWRvcyBubyBtZW51IGxhdGVyYWxcbiAgICAgIHZtLml0ZW5zTWVudSA9IFtcbiAgICAgICAgeyBzdGF0ZTogJ2FwcC5wcm9qZWN0cycsIHRpdGxlOiBtZW51UHJlZml4ICsgJ3Byb2plY3RzJywgaWNvbjogJ3dvcmsnLCBzdWJJdGVuczogW10gfSxcbiAgICAgICAgeyBzdGF0ZTogJ2FwcC5kYXNoYm9hcmQnLCB0aXRsZTogbWVudVByZWZpeCArICdkYXNoYm9hcmQnLCBpY29uOiAnZGFzaGJvYXJkJywgc3ViSXRlbnM6IFtdIH0sXG4gICAgICAgIHsgc3RhdGU6ICdhcHAudGFza3MnLCB0aXRsZTogbWVudVByZWZpeCArICd0YXNrcycsIGljb246ICd2aWV3X2xpc3QnLCBzdWJJdGVuczogW10gfSxcbiAgICAgICAgeyBzdGF0ZTogJ2FwcC5taWxlc3RvbmVzJywgdGl0bGU6IG1lbnVQcmVmaXggKyAnbWlsZXN0b25lcycsIGljb246ICd2aWV3X21vZHVsZScsIHN1Ykl0ZW5zOiBbXSB9LFxuICAgICAgICB7IHN0YXRlOiAnYXBwLnJlbGVhc2VzJywgdGl0bGU6IG1lbnVQcmVmaXggKyAncmVsZWFzZXMnLCBpY29uOiAnc3Vic2NyaXB0aW9ucycsIHN1Ykl0ZW5zOiBbXSB9LFxuICAgICAgICB7IHN0YXRlOiAnYXBwLmthbmJhbicsIHRpdGxlOiBtZW51UHJlZml4ICsgJ2thbmJhbicsIGljb246ICd2aWV3X2NvbHVtbicsIHN1Ykl0ZW5zOiBbXSB9LFxuICAgICAgICB7IHN0YXRlOiAnYXBwLnZjcycsIHRpdGxlOiBtZW51UHJlZml4ICsgJ3ZjcycsIGljb246ICdncm91cF93b3JrJywgc3ViSXRlbnM6IFtdIH1cbiAgICAgICAgLy8gQ29sb3F1ZSBzZXVzIGl0ZW5zIGRlIG1lbnUgYSBwYXJ0aXIgZGVzdGUgcG9udG9cbiAgICAgICAgLyoge1xuICAgICAgICAgIHN0YXRlOiAnIycsIHRpdGxlOiBtZW51UHJlZml4ICsgJ2FkbWluJywgaWNvbjogJ3NldHRpbmdzX2FwcGxpY2F0aW9ucycsIHByb2ZpbGVzOiBbJ2FkbWluJ10sXG4gICAgICAgICAgc3ViSXRlbnM6IFtcbiAgICAgICAgICAgIHsgc3RhdGU6ICdhcHAudXNlcicsIHRpdGxlOiBtZW51UHJlZml4ICsgJ3VzZXInLCBpY29uOiAncGVvcGxlJyB9LFxuICAgICAgICAgICAgeyBzdGF0ZTogJ2FwcC5tYWlsJywgdGl0bGU6IG1lbnVQcmVmaXggKyAnbWFpbCcsIGljb246ICdtYWlsJyB9LFxuICAgICAgICAgICAgeyBzdGF0ZTogJ2FwcC5hdWRpdCcsIHRpdGxlOiBtZW51UHJlZml4ICsgJ2F1ZGl0JywgaWNvbjogJ3N0b3JhZ2UnIH0sXG4gICAgICAgICAgICB7IHN0YXRlOiAnYXBwLmRpbmFtaWMtcXVlcnknLCB0aXRsZTogbWVudVByZWZpeCArICdkaW5hbWljUXVlcnknLCBpY29uOiAnbG9jYXRpb25fc2VhcmNoaW5nJyB9XG4gICAgICAgICAgXVxuICAgICAgICB9ICovXG4gICAgICBdO1xuXG4gICAgICAvKipcbiAgICAgICAqIE9iamV0byBxdWUgcHJlZW5jaGUgbyBuZy1zdHlsZSBkbyBtZW51IGxhdGVyYWwgdHJvY2FuZG8gYXMgY29yZXNcbiAgICAgICAqL1xuICAgICAgdm0uc2lkZW5hdlN0eWxlID0ge1xuICAgICAgICB0b3A6IHtcbiAgICAgICAgICAnYm9yZGVyLWJvdHRvbSc6ICcxcHggc29saWQgcmdiKDIxMCwgMjEwLCAyMTApJyxcbiAgICAgICAgICAnYmFja2dyb3VuZC1pbWFnZSc6ICctd2Via2l0LWxpbmVhci1ncmFkaWVudCh0b3AsIHJnYigxNDQsIDE0NCwgMTQ0KSwgcmdiKDIxMCwgMjEwLCAyMTApKSdcbiAgICAgICAgfSxcbiAgICAgICAgY29udGVudDoge1xuICAgICAgICAgICdiYWNrZ3JvdW5kLWNvbG9yJzogJ3JnYigyMTAsIDIxMCwgMjEwKSdcbiAgICAgICAgfSxcbiAgICAgICAgdGV4dENvbG9yOiB7XG4gICAgICAgICAgY29sb3I6ICcjRkZGJ1xuICAgICAgICB9LFxuICAgICAgICBsaW5lQm90dG9tOiB7XG4gICAgICAgICAgJ2JvcmRlci1ib3R0b20nOiAnMXB4IHNvbGlkICcgKyBnZXRDb2xvcigncHJpbWFyeS00MDAnKVxuICAgICAgICB9XG4gICAgICB9XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gb3BlbigpIHtcbiAgICAgICRtZFNpZGVuYXYoJ2xlZnQnKS50b2dnbGUoKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBNw6l0b2RvIHF1ZSBleGliZSBvIHN1YiBtZW51IGRvcyBpdGVucyBkbyBtZW51IGxhdGVyYWwgY2FzbyB0ZW5oYSBzdWIgaXRlbnNcbiAgICAgKiBjYXNvIGNvbnRyw6FyaW8gcmVkaXJlY2lvbmEgcGFyYSBvIHN0YXRlIHBhc3NhZG8gY29tbyBwYXLDg8KibWV0cm9cbiAgICAgKi9cbiAgICBmdW5jdGlvbiBvcGVuTWVudU9yUmVkaXJlY3RUb1N0YXRlKCRtZE1lbnUsIGV2LCBpdGVtKSB7XG4gICAgICBpZiAoYW5ndWxhci5pc0RlZmluZWQoaXRlbS5zdWJJdGVucykgJiYgaXRlbS5zdWJJdGVucy5sZW5ndGggPiAwKSB7XG4gICAgICAgICRtZE1lbnUub3Blbihldik7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICAkc3RhdGUuZ28oaXRlbS5zdGF0ZSwgeyBvYmo6IG51bGwgfSk7XG4gICAgICAgICRtZFNpZGVuYXYoJ2xlZnQnKS5jbG9zZSgpO1xuICAgICAgfVxuICAgIH1cblxuICAgIGZ1bmN0aW9uIGdldENvbG9yKGNvbG9yUGFsZXR0ZXMpIHtcbiAgICAgIHJldHVybiAkbWRDb2xvcnMuZ2V0VGhlbWVDb2xvcihjb2xvclBhbGV0dGVzKTtcbiAgICB9XG5cbiAgfVxuXG59KSgpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29udHJvbGxlcignTWFpbHNDb250cm9sbGVyJywgTWFpbHNDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIE1haWxzQ29udHJvbGxlcihNYWlsc1NlcnZpY2UsIFVzZXJzU2VydmljZSwgUHJEaWFsb2csIFByVG9hc3QsIC8vIE5PU09OQVJcbiAgICAkcSwgbG9kYXNoLCAkdHJhbnNsYXRlLCBHbG9iYWwpIHtcblxuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICB2bS5maWx0ZXJTZWxlY3RlZCA9IGZhbHNlO1xuICAgIHZtLm9wdGlvbnMgPSB7XG4gICAgICBza2luOiAna2FtYScsXG4gICAgICBsYW5ndWFnZTogJ3B0LWJyJyxcbiAgICAgIGFsbG93ZWRDb250ZW50OiB0cnVlLFxuICAgICAgZW50aXRpZXM6IHRydWUsXG4gICAgICBoZWlnaHQ6IDMwMCxcbiAgICAgIGV4dHJhUGx1Z2luczogJ2RpYWxvZyxmaW5kLGNvbG9yZGlhbG9nLHByZXZpZXcsZm9ybXMsaWZyYW1lLGZsYXNoJ1xuICAgIH07XG5cbiAgICB2bS5sb2FkVXNlcnMgPSBsb2FkVXNlcnM7XG4gICAgdm0ub3BlblVzZXJEaWFsb2cgPSBvcGVuVXNlckRpYWxvZztcbiAgICB2bS5hZGRVc2VyTWFpbCA9IGFkZFVzZXJNYWlsO1xuICAgIHZtLmNsZWFuRm9ybSA9IGNsZWFuRm9ybTtcbiAgICB2bS5zZW5kID0gc2VuZDtcblxuICAgIGFjdGl2YXRlKCk7XG5cbiAgICBmdW5jdGlvbiBhY3RpdmF0ZSgpIHtcbiAgICAgIHZtLmNsZWFuRm9ybSgpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWxpemEgYSBidXNjYSBwZWxvIHVzdcOhcmlvIHJlbW90YW1lbnRlXG4gICAgICpcbiAgICAgKiBAcGFyYW1zIHtzdHJpbmd9IC0gUmVjZWJlIG8gdmFsb3IgcGFyYSBzZXIgcGVzcXVpc2Fkb1xuICAgICAqIEByZXR1cm4ge3Byb21pc3NlfSAtIFJldG9ybmEgdW1hIHByb21pc3NlIHF1ZSBvIGNvbXBvbmV0ZSByZXNvbHZlXG4gICAgICovXG4gICAgZnVuY3Rpb24gbG9hZFVzZXJzKGNyaXRlcmlhKSB7XG4gICAgICB2YXIgZGVmZXJyZWQgPSAkcS5kZWZlcigpO1xuXG4gICAgICBVc2Vyc1NlcnZpY2UucXVlcnkoe1xuICAgICAgICBuYW1lT3JFbWFpbDogY3JpdGVyaWEsXG4gICAgICAgIG5vdFVzZXJzOiBsb2Rhc2gubWFwKHZtLm1haWwudXNlcnMsIGxvZGFzaC5wcm9wZXJ0eSgnaWQnKSkudG9TdHJpbmcoKSxcbiAgICAgICAgbGltaXQ6IDVcbiAgICAgIH0pLnRoZW4oZnVuY3Rpb24oZGF0YSkge1xuXG4gICAgICAgIC8vIHZlcmlmaWNhIHNlIG5hIGxpc3RhIGRlIHVzdWFyaW9zIGrDoSBleGlzdGUgbyB1c3XDoXJpbyBjb20gbyBlbWFpbCBwZXNxdWlzYWRvXG4gICAgICAgIGRhdGEgPSBsb2Rhc2guZmlsdGVyKGRhdGEsIGZ1bmN0aW9uKHVzZXIpIHtcbiAgICAgICAgICByZXR1cm4gIWxvZGFzaC5maW5kKHZtLm1haWwudXNlcnMsIHsgZW1haWw6IHVzZXIuZW1haWwgfSk7XG4gICAgICAgIH0pO1xuXG4gICAgICAgIGRlZmVycmVkLnJlc29sdmUoZGF0YSk7XG4gICAgICB9KTtcblxuICAgICAgcmV0dXJuIGRlZmVycmVkLnByb21pc2U7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQWJyZSBvIGRpYWxvZyBwYXJhIHBlc3F1aXNhIGRlIHVzdcOhcmlvc1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIG9wZW5Vc2VyRGlhbG9nKCkge1xuICAgICAgdmFyIGNvbmZpZyA9IHtcbiAgICAgICAgbG9jYWxzOiB7XG4gICAgICAgICAgb25Jbml0OiB0cnVlLFxuICAgICAgICAgIHVzZXJEaWFsb2dJbnB1dDoge1xuICAgICAgICAgICAgdHJhbnNmZXJVc2VyRm46IHZtLmFkZFVzZXJNYWlsXG4gICAgICAgICAgfVxuICAgICAgICB9LFxuICAgICAgICBjb250cm9sbGVyOiAnVXNlcnNEaWFsb2dDb250cm9sbGVyJyxcbiAgICAgICAgY29udHJvbGxlckFzOiAnY3RybCcsXG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvdXNlcnMvZGlhbG9nL3VzZXJzLWRpYWxvZy5odG1sJyxcbiAgICAgICAgaGFzQmFja2Ryb3A6IHRydWVcbiAgICAgIH07XG5cbiAgICAgIFByRGlhbG9nLmN1c3RvbShjb25maWcpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEFkaWNpb25hIG8gdXN1w6FyaW8gc2VsZWNpb25hZG8gbmEgbGlzdGEgcGFyYSBxdWUgc2VqYSBlbnZpYWRvIG8gZW1haWxcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBhZGRVc2VyTWFpbCh1c2VyKSB7XG4gICAgICB2YXIgdXNlcnMgPSBsb2Rhc2guZmluZCh2bS5tYWlsLnVzZXJzLCB7IGVtYWlsOiB1c2VyLmVtYWlsIH0pO1xuXG4gICAgICBpZiAodm0ubWFpbC51c2Vycy5sZW5ndGggPiAwICYmIGFuZ3VsYXIuaXNEZWZpbmVkKHVzZXJzKSkge1xuICAgICAgICBQclRvYXN0Lndhcm4oJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy51c2VyLnVzZXJFeGlzdHMnKSk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICB2bS5tYWlsLnVzZXJzLnB1c2goeyBuYW1lOiB1c2VyLm5hbWUsIGVtYWlsOiB1c2VyLmVtYWlsIH0pXG4gICAgICB9XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhbGl6YSBvIGVudmlvIGRvIGVtYWlsIHBhcmEgYSBsaXN0YSBkZSB1c3XDoXJpb3Mgc2VsZWNpb25hZG9zXG4gICAgICovXG4gICAgZnVuY3Rpb24gc2VuZCgpIHtcblxuICAgICAgdm0ubWFpbC4kc2F2ZSgpLnRoZW4oZnVuY3Rpb24ocmVzcG9uc2UpIHtcbiAgICAgICAgaWYgKHJlc3BvbnNlLmxlbmd0aCA+IDApIHtcbiAgICAgICAgICB2YXIgbXNnID0gJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5tYWlsLm1haWxFcnJvcnMnKTtcblxuICAgICAgICAgIGZvciAodmFyIGk9MDsgaSA8IHJlc3BvbnNlLmxlbmd0aDsgaSsrKSB7XG4gICAgICAgICAgICBtc2cgKz0gcmVzcG9uc2UgKyAnXFxuJztcbiAgICAgICAgICB9XG4gICAgICAgICAgUHJUb2FzdC5lcnJvcihtc2cpO1xuICAgICAgICAgIHZtLmNsZWFuRm9ybSgpO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIFByVG9hc3Quc3VjY2VzcygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLm1haWwuc2VuZE1haWxTdWNjZXNzJykpO1xuICAgICAgICAgIHZtLmNsZWFuRm9ybSgpO1xuICAgICAgICB9XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBMaW1wYSBvIGZvcm11bMOhcmlvIGRlIGVtYWlsXG4gICAgICovXG4gICAgZnVuY3Rpb24gY2xlYW5Gb3JtKCkge1xuICAgICAgdm0ubWFpbCA9IG5ldyBNYWlsc1NlcnZpY2UoKTtcbiAgICAgIHZtLm1haWwudXNlcnMgPSBbXTtcbiAgICB9XG5cbiAgfVxuXG59KSgpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKlxuICAgKiBBcnF1aXZvIGRlIGNvbmZpZ3VyYcOnw6NvIGNvbSBhcyByb3RhcyBlc3BlY8OtZmljYXMgZG8gcmVjdXJzbyBlbSBxdWVzdMOjb1xuICAgKlxuICAgKiBAcGFyYW0ge2FueX0gJHN0YXRlUHJvdmlkZXJcbiAgICogQHBhcmFtIHthbnl9IEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyXG4gICAgICAuc3RhdGUoJ2FwcC5tYWlsJywge1xuICAgICAgICB1cmw6ICcvZW1haWwnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL21haWwvbWFpbHMtc2VuZC5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ01haWxzQ29udHJvbGxlciBhcyBtYWlsc0N0cmwnLFxuICAgICAgICBkYXRhOiB7IG5lZWRBdXRoZW50aWNhdGlvbjogdHJ1ZSwgbmVlZFByb2ZpbGU6IFsnYWRtaW4nXSB9XG4gICAgICB9KTtcblxuICB9XG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZhY3RvcnkoJ01haWxzU2VydmljZScsIE1haWxzU2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBNYWlsc1NlcnZpY2Uoc2VydmljZUZhY3RvcnkpIHtcbiAgICByZXR1cm4gc2VydmljZUZhY3RvcnkoJ21haWxzJywge30pO1xuICB9XG5cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb250cm9sbGVyKCdNaWxlc3RvbmVzQ29udHJvbGxlcicsIE1pbGVzdG9uZXNDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIE1pbGVzdG9uZXNDb250cm9sbGVyKCRjb250cm9sbGVyLFxuICAgIE1pbGVzdG9uZXNTZXJ2aWNlLFxuICAgIG1vbWVudCxcbiAgICBUYXNrc1NlcnZpY2UsXG4gICAgUHJUb2FzdCxcbiAgICAkdHJhbnNsYXRlLFxuICAgICRtZERpYWxvZyxcbiAgICBBdXRoKSB7XG5cbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0uZXN0aW1hdGVkUHJpY2UgPSBlc3RpbWF0ZWRQcmljZTtcblxuICAgIHZtLm9uQWN0aXZhdGUgPSBmdW5jdGlvbigpIHtcbiAgICAgIHZtLmN1cnJlbnRVc2VyID0gQXV0aC5jdXJyZW50VXNlcjtcbiAgICAgIHZtLnByb2plY3QgPSBsb2NhbFN0b3JhZ2UuZ2V0SXRlbSgncHJvamVjdCcpO1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0geyBwcm9qZWN0X2lkOiB2bS5wcm9qZWN0IH07XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gZXN0aW1hdGVkUHJpY2UobWlsZXN0b25lKSB7XG4gICAgICBtaWxlc3RvbmUuZXN0aW1hdGVkX3ZhbHVlID0gMDtcbiAgICAgIGlmKG1pbGVzdG9uZS50YXNrcy5sZW5ndGggPiAwICYmIG1pbGVzdG9uZS5wcm9qZWN0LmhvdXJfdmFsdWVfZmluYWwpIHtcbiAgICAgICAgbWlsZXN0b25lLnRhc2tzLmZvckVhY2goZnVuY3Rpb24odGFzaykge1xuICAgICAgICAgIG1pbGVzdG9uZS5lc3RpbWF0ZWRfdmFsdWUgKz0gKHBhcnNlRmxvYXQobWlsZXN0b25lLnByb2plY3QuaG91cl92YWx1ZV9maW5hbCkgKiB0YXNrLmVzdGltYXRlZF90aW1lKTtcbiAgICAgICAgfSk7XG4gICAgICB9XG4gICAgICByZXR1cm4gbWlsZXN0b25lLmVzdGltYXRlZF92YWx1ZS50b0xvY2FsZVN0cmluZygnUHQtYnInLCB7IG1pbmltdW1GcmFjdGlvbkRpZ2l0czogMiB9KTtcbiAgICB9XG5cbiAgICB2bS5lc3RpbWF0ZWRUaW1lID0gZnVuY3Rpb24gKG1pbGVzdG9uZSkge1xuICAgICAgbWlsZXN0b25lLmVzdGltYXRlZF90aW1lID0gMDtcbiAgICAgIGlmKG1pbGVzdG9uZS50YXNrcy5sZW5ndGggPiAwKSB7XG4gICAgICAgIG1pbGVzdG9uZS50YXNrcy5mb3JFYWNoKGZ1bmN0aW9uKHRhc2spIHtcbiAgICAgICAgICBtaWxlc3RvbmUuZXN0aW1hdGVkX3RpbWUgKz0gdGFzay5lc3RpbWF0ZWRfdGltZTtcbiAgICAgICAgfSk7XG4gICAgICB9XG4gICAgICBtaWxlc3RvbmUuZXN0aW1hdGVkX3RpbWUgPSBtaWxlc3RvbmUuZXN0aW1hdGVkX3RpbWUgLyA4O1xuICAgICAgdmFyIGRhdGVFbmQgPSBtb21lbnQobWlsZXN0b25lLmRhdGVfZW5kKTtcbiAgICAgIHZhciBkYXRlQmVnaW4gPSBtb21lbnQobWlsZXN0b25lLmRhdGVfYmVnaW4pO1xuXG4gICAgICBpZiAoZGF0ZUVuZC5kaWZmKGRhdGVCZWdpbiwgJ2RheXMnKSA8PSBtaWxlc3RvbmUuZXN0aW1hdGVkX3RpbWUpIHtcbiAgICAgICAgbWlsZXN0b25lLmNvbG9yX2VzdGltYXRlZF90aW1lID0geyBjb2xvcjogJ3JlZCcgfTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIG1pbGVzdG9uZS5jb2xvcl9lc3RpbWF0ZWRfdGltZSA9IHsgY29sb3I6ICdncmVlbicgfTtcbiAgICAgIH1cbiAgICAgIHJldHVybiBtaWxlc3RvbmUuZXN0aW1hdGVkX3RpbWU7XG4gICAgfVxuXG4gICAgdm0uYXBwbHlGaWx0ZXJzID0gZnVuY3Rpb24oZGVmYXVsdFF1ZXJ5RmlsdGVycykge1xuICAgICAgcmV0dXJuIGFuZ3VsYXIuZXh0ZW5kKGRlZmF1bHRRdWVyeUZpbHRlcnMsIHZtLnF1ZXJ5RmlsdGVycyk7XG4gICAgfVxuXG4gICAgdm0uYmVmb3JlU2F2ZSA9IGZ1bmN0aW9uKCkge1xuICAgICAgdm0ucmVzb3VyY2UucHJvamVjdF9pZCA9IHZtLnByb2plY3Q7XG4gICAgfVxuXG4gICAgdm0uYmVmb3JlUmVtb3ZlID0gZnVuY3Rpb24oKSB7XG4gICAgICB2bS5yZXNvdXJjZS5wcm9qZWN0X2lkID0gdm0ucHJvamVjdDtcbiAgICB9XG5cbiAgICB2bS5mb3JtYXREYXRlID0gZnVuY3Rpb24oZGF0ZSkge1xuICAgICAgcmV0dXJuIG1vbWVudChkYXRlKS5mb3JtYXQoJ0REL01NL1lZWVknKTtcbiAgICB9XG5cbiAgICB2bS5hZnRlckVkaXQgPSBmdW5jdGlvbigpIHtcbiAgICAgIHZtLnJlc291cmNlLmRhdGVfYmVnaW4gPSBtb21lbnQodm0ucmVzb3VyY2UuZGF0ZV9iZWdpbik7XG4gICAgICB2bS5yZXNvdXJjZS5kYXRlX2VuZCA9IG1vbWVudCh2bS5yZXNvdXJjZS5kYXRlX2VuZCk7XG4gICAgfVxuXG4gICAgdm0udmlldyA9IGZ1bmN0aW9uIChyZXNvdXJjZSkge1xuICAgICAgdm0ucmVzb3VyY2UgPSByZXNvdXJjZTtcbiAgICAgIHZtLm9uVmlldyA9IHRydWU7XG4gICAgICB2bS52aWV3Rm9ybSA9IGZhbHNlO1xuICAgICAgY29uc29sZS5sb2cocmVzb3VyY2UucHJvamVjdCk7XG4gICAgfVxuXG4gICAgdm0uc2VhcmNoVGFzayA9IGZ1bmN0aW9uICh0YXNrVGVybSkge1xuICAgICAgcmV0dXJuIFRhc2tzU2VydmljZS5xdWVyeSh7XG4gICAgICAgIG1pbGVzdG9uZVNlYXJjaDogdHJ1ZSxcbiAgICAgICAgcHJvamVjdF9pZDogdm0ucmVzb3VyY2UucHJvamVjdF9pZCxcbiAgICAgICAgdGl0bGU6IHRhc2tUZXJtXG4gICAgICB9KTtcbiAgICB9XG5cbiAgICB2bS5vblRhc2tDaGFuZ2UgPSBmdW5jdGlvbigpIHtcbiAgICAgIGlmICh2bS50YXNrICE9PSBudWxsICYmIHZtLnJlc291cmNlLnRhc2tzLmZpbmRJbmRleChpID0+IGkuaWQgPT09IHZtLnRhc2suaWQpID09PSAtMSkge1xuICAgICAgICB2bS5yZXNvdXJjZS50YXNrcy5wdXNoKHZtLnRhc2spO1xuICAgICAgfVxuICAgIH1cblxuICAgIHZtLnJlbW92ZVRhc2sgPSBmdW5jdGlvbih0YXNrKSB7XG4gICAgICB2bS5yZXNvdXJjZS50YXNrcy5zbGljZSgwKS5mb3JFYWNoKGZ1bmN0aW9uKGVsZW1lbnQpIHtcbiAgICAgICAgaWYoZWxlbWVudC5pZCA9PT0gdGFzay5pZCkge1xuICAgICAgICAgIHZtLnJlc291cmNlLnRhc2tzLnNwbGljZSh2bS5yZXNvdXJjZS50YXNrcy5pbmRleE9mKGVsZW1lbnQpLCAxKTtcbiAgICAgICAgfVxuICAgICAgfSk7XG4gICAgfVxuXG4gICAgdm0uc2F2ZVRhc2tzID0gZnVuY3Rpb24oKSB7XG4gICAgICBUYXNrc1NlcnZpY2UudXBkYXRlTWlsZXN0b25lKHtwcm9qZWN0X2lkOiB2bS5yZXNvdXJjZS5wcm9qZWN0X2lkLCBtaWxlc3RvbmVfaWQ6IHZtLnJlc291cmNlLmlkLCB0YXNrczogdm0ucmVzb3VyY2UudGFza3N9KS50aGVuKGZ1bmN0aW9uKCl7XG4gICAgICAgIFByVG9hc3Quc3VjY2VzcygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnNhdmVTdWNjZXNzJykpO1xuICAgICAgICB2bS52aWV3Rm9ybSA9IGZhbHNlO1xuICAgICAgICB2bS5vblZpZXcgPSBmYWxzZTtcbiAgICAgIH0sIGZ1bmN0aW9uKCkge1xuICAgICAgICBQclRvYXN0LmVycm9yKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMub3BlcmF0aW9uRXJyb3InKSk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICB2bS5maW5hbGl6ZSA9IGZ1bmN0aW9uKG1pbGVzdG9uZSkge1xuICAgICAgdmFyIGNvbmZpcm0gPSAkbWREaWFsb2cuY29uZmlybSgpXG4gICAgICAgICAgLnRpdGxlKCdGaW5hbGl6YXIgU3ByaW50JylcbiAgICAgICAgICAudGV4dENvbnRlbnQoJ1RlbSBjZXJ0ZXphIHF1ZSBkZXNlamEgZmluYWxpemFyIGEgc3ByaW50ICcgKyBtaWxlc3RvbmUudGl0bGUgKyAnPycpXG4gICAgICAgICAgLm9rKCdTaW0nKVxuICAgICAgICAgIC5jYW5jZWwoJ07Do28nKTtcblxuICAgICAgJG1kRGlhbG9nLnNob3coY29uZmlybSkudGhlbihmdW5jdGlvbigpIHtcbiAgICAgICAgTWlsZXN0b25lc1NlcnZpY2UuZmluYWxpemUoeyBwcm9qZWN0X2lkOiB2bS5wcm9qZWN0LCBtaWxlc3RvbmVfaWQ6IG1pbGVzdG9uZS5pZCB9KS50aGVuKGZ1bmN0aW9uKCkge1xuICAgICAgICAgIFByVG9hc3Quc3VjY2VzcygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnNwcmludEVuZGVkU3VjY2VzcycpKTtcbiAgICAgICAgICB2bS5zZWFyY2goKTtcbiAgICAgICAgfSwgZnVuY3Rpb24oKSB7XG4gICAgICAgICAgUHJUb2FzdC5FcnJvcigkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnNwcmludEVuZGVkRXJyb3InKSk7XG4gICAgICAgIH0pO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLy8gaW5zdGFudGlhdGUgYmFzZSBjb250cm9sbGVyXG4gICAgJGNvbnRyb2xsZXIoJ0NSVURDb250cm9sbGVyJywgeyB2bTogdm0sIG1vZGVsU2VydmljZTogTWlsZXN0b25lc1NlcnZpY2UsIG9wdGlvbnM6IHsgfSB9KTtcblxuICB9XG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqXG4gICAqIEFycXVpdm8gZGUgY29uZmlndXJhw6fDo28gY29tIGFzIHJvdGFzIGVzcGVjw61maWNhcyBkbyByZWN1cnNvIG1pbGVzdG9uZXNcbiAgICpcbiAgICogQHBhcmFtIHtvYmplY3R9ICRzdGF0ZVByb3ZpZGVyXG4gICAqIEBwYXJhbSB7b2JqZWN0fSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlclxuICAgICAgLnN0YXRlKCdhcHAubWlsZXN0b25lcycsIHtcbiAgICAgICAgdXJsOiAnL21pbGVzdG9uZXMnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL21pbGVzdG9uZXMvbWlsZXN0b25lcy5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ01pbGVzdG9uZXNDb250cm9sbGVyIGFzIG1pbGVzdG9uZXNDdHJsJyxcbiAgICAgICAgZGF0YTogeyB9XG4gICAgICB9KTtcbiAgfVxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5mYWN0b3J5KCdNaWxlc3RvbmVzU2VydmljZScsIE1pbGVzdG9uZXNTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIE1pbGVzdG9uZXNTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgdmFyIG1vZGVsID0gc2VydmljZUZhY3RvcnkoJ21pbGVzdG9uZXMnLCB7XG4gICAgICBhY3Rpb25zOiB7XG4gICAgICAgIGZpbmFsaXplOiB7XG4gICAgICAgICAgbWV0aG9kOiAnUE9TVCcsXG4gICAgICAgICAgdXJsOiAnZmluYWxpemUnXG4gICAgICAgIH0sXG4gICAgICAgIHVwZGF0ZVJlbGVhc2U6IHtcbiAgICAgICAgICBtZXRob2Q6ICdQT1NUJyxcbiAgICAgICAgICB1cmw6ICd1cGRhdGVSZWxlYXNlJ1xuICAgICAgICB9XG4gICAgICB9LFxuICAgICAgaW5zdGFuY2U6IHsgfVxuICAgIH0pO1xuXG4gICAgcmV0dXJuIG1vZGVsO1xuICB9XG5cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmFjdG9yeSgnUHJpb3JpdGllc1NlcnZpY2UnLCBQcmlvcml0aWVzU2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiBQcmlvcml0aWVzU2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHZhciBtb2RlbCA9IHNlcnZpY2VGYWN0b3J5KCdwcmlvcml0aWVzJywge1xuICAgICAgYWN0aW9uczogeyB9LFxuICAgICAgaW5zdGFuY2U6IHsgfVxuICAgIH0pO1xuXG4gICAgcmV0dXJuIG1vZGVsO1xuICB9XG5cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb250cm9sbGVyKCdQcm9qZWN0c0NvbnRyb2xsZXInLCBQcm9qZWN0c0NvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gUHJvamVjdHNDb250cm9sbGVyKCRjb250cm9sbGVyLFxuICAgIFByb2plY3RzU2VydmljZSxcbiAgICBBdXRoLFxuICAgIFJvbGVzU2VydmljZSxcbiAgICBVc2Vyc1NlcnZpY2UsXG4gICAgJHN0YXRlLFxuICAgICRmaWx0ZXIsXG4gICAgJHN0YXRlUGFyYW1zLFxuICAgICR3aW5kb3cpIHtcbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgLy9BdHRyaWJ1dGVzIEJsb2NrXG5cbiAgICAvL0Z1bmN0aW9ucyBCbG9ja1xuICAgIHZtLm9uQWN0aXZhdGUgPSBvbkFjdGl2YXRlO1xuICAgIHZtLmFwcGx5RmlsdGVycyA9IGFwcGx5RmlsdGVycztcbiAgICB2bS5iZWZvcmVTYXZlID0gYmVmb3JlU2F2ZTtcbiAgICB2bS5zZWFyY2hVc2VyID0gc2VhcmNoVXNlcjtcbiAgICB2bS5hZGRVc2VyID0gYWRkVXNlcjtcbiAgICB2bS5yZW1vdmVVc2VyID0gcmVtb3ZlVXNlcjtcbiAgICB2bS52aWV3UHJvamVjdCA9IHZpZXdQcm9qZWN0O1xuXG4gICAgdm0ucm9sZXMgPSB7fTtcbiAgICB2bS51c2VycyA9IFtdO1xuXG4gICAgZnVuY3Rpb24gb25BY3RpdmF0ZSgpIHtcbiAgICAgIHZtLmN1cnJlbnRVc2VyID0gQXV0aC5jdXJyZW50VXNlcjtcbiAgICAgIFJvbGVzU2VydmljZS5xdWVyeSgpLnRoZW4oZnVuY3Rpb24ocmVzcG9uc2UpIHtcbiAgICAgICAgdm0ucm9sZXMgPSByZXNwb25zZTtcbiAgICAgICAgLy92bS5yb2xlcyA9ICRmaWx0ZXIoJ2ZpbHRlcicpKHZtLnJvbGVzLCB7IHNsdWc6ICdjbGllbnQnIH0pO1xuICAgICAgICBpZiAoJHN0YXRlUGFyYW1zLm9iaiA9PT0gJ2VkaXQnKSB7XG4gICAgICAgICAgdm0uY2xlYW5Gb3JtKCk7XG4gICAgICAgICAgdm0udmlld0Zvcm0gPSB0cnVlO1xuICAgICAgICAgIHZtLnJlc291cmNlID0gJHN0YXRlUGFyYW1zLnJlc291cmNlO1xuICAgICAgICAgIHVzZXJzQXJyYXkodm0ucmVzb3VyY2UpO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKCdwcm9qZWN0Jyk7XG4gICAgICAgICAgdm0ucXVlcnlGaWx0ZXJzID0geyB1c2VyX2lkOiB2bS5jdXJyZW50VXNlci5pZCB9O1xuICAgICAgICB9XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBhcHBseUZpbHRlcnMoZGVmYXVsdFF1ZXJ5RmlsdGVycykge1xuICAgICAgcmV0dXJuIGFuZ3VsYXIuZXh0ZW5kKGRlZmF1bHRRdWVyeUZpbHRlcnMsIHZtLnF1ZXJ5bHRlcnMpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGJlZm9yZVNhdmUoKSB7XG4gICAgICB2bS5yZXNvdXJjZS5vd25lciA9IEF1dGguY3VycmVudFVzZXIuaWQ7XG4gICAgICB2bS5yZXNvdXJjZS51c2VyX2lkID0gQXV0aC5jdXJyZW50VXNlci5pZDtcbiAgICAgIHZtLnJlc291cmNlLmRldl9pZCA9IEF1dGguY3VycmVudFVzZXIuaWQ7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gc2VhcmNoVXNlcigpIHtcbiAgICAgIHJldHVybiBVc2Vyc1NlcnZpY2UucXVlcnkoeyBuYW1lOiB2bS51c2VyTmFtZSB9KTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBhZGRVc2VyKHVzZXIpIHtcbiAgICAgIGlmICh1c2VyKSB7XG4gICAgICAgIHZtLnJlc291cmNlLnVzZXJzLnB1c2godXNlcik7XG4gICAgICAgIHZtLnVzZXJOYW1lID0gJyc7XG4gICAgICB9XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gcmVtb3ZlVXNlcihpbmRleCkge1xuICAgICAgdm0ucmVzb3VyY2UudXNlcnMuc3BsaWNlKGluZGV4LCAxKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBhcHBseUZpbHRlcnMoZGVmYXVsdFF1ZXJ5RmlsdGVycykge1xuICAgICAgcmV0dXJuIGFuZ3VsYXIuZXh0ZW5kKGRlZmF1bHRRdWVyeUZpbHRlcnMsIHZtLnF1ZXJ5RmlsdGVycyk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gdmlld1Byb2plY3QoKSB7XG4gICAgICAkc3RhdGUuZ28oJ2FwcC5kYXNoYm9hcmQnKTtcbiAgICB9XG5cbiAgICB2bS5hZnRlclNlYXJjaCA9IGZ1bmN0aW9uKCkge1xuICAgICAgaWYgKHZtLnJlc291cmNlcy5sZW5ndGggPiAwKSB7XG4gICAgICAgIHZtLnJlc291cmNlcy5mb3JFYWNoKGZ1bmN0aW9uKHByb2plY3QpIHtcbiAgICAgICAgICB1c2Vyc0FycmF5KHByb2plY3QpO1xuICAgICAgICB9KTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICBmdW5jdGlvbiB1c2Vyc0FycmF5KHByb2plY3QpIHtcbiAgICAgIHByb2plY3QudXNlcnMgPSBbXTtcbiAgICAgIGlmIChwcm9qZWN0LmNsaWVudF9pZCkge1xuICAgICAgICBwcm9qZWN0LmNsaWVudC5yb2xlID0gJGZpbHRlcignZmlsdGVyJykodm0ucm9sZXMsIHsgc2x1ZzogJ2NsaWVudCcgfSlbMF07XG4gICAgICAgIHByb2plY3QudXNlcnMucHVzaChwcm9qZWN0LmNsaWVudCk7XG4gICAgICB9XG4gICAgICBpZiAocHJvamVjdC5kZXZfaWQpIHtcbiAgICAgICAgcHJvamVjdC5kZXZlbG9wZXIucm9sZSA9ICRmaWx0ZXIoJ2ZpbHRlcicpKHZtLnJvbGVzLCB7IHNsdWc6ICdkZXYnIH0pWzBdO1xuICAgICAgICBwcm9qZWN0LnVzZXJzLnB1c2gocHJvamVjdC5kZXZlbG9wZXIpO1xuICAgICAgfVxuICAgICAgaWYgKHByb2plY3Quc3Rha2Vob2xkZXJfaWQpIHtcbiAgICAgICAgcHJvamVjdC5zdGFrZWhvbGRlci5yb2xlID0gJGZpbHRlcignZmlsdGVyJykodm0ucm9sZXMsIHsgc2x1ZzogJ3N0YWtlaG9sZGVyJyB9KVswXTtcbiAgICAgICAgcHJvamVjdC51c2Vycy5wdXNoKHByb2plY3Quc3Rha2Vob2xkZXIpO1xuICAgICAgfVxuICAgIH1cblxuICAgIHZtLmhpc3RvcnlCYWNrID0gZnVuY3Rpb24oKSB7XG4gICAgICAkd2luZG93Lmhpc3RvcnkuYmFjaygpO1xuICAgIH1cblxuICAgIHZtLmFmdGVyU2F2ZSA9IGZ1bmN0aW9uKHJlc291cmNlKSB7XG4gICAgICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbSgncHJvamVjdCcsIHJlc291cmNlLmlkKTtcbiAgICAgICRzdGF0ZS5nbygnYXBwLmRhc2hib2FyZCcpO1xuICAgIH1cblxuICAgIC8vIGluc3RhbnRpYXRlIGJhc2UgY29udHJvbGxlclxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHsgdm06IHZtLCBtb2RlbFNlcnZpY2U6IFByb2plY3RzU2VydmljZSwgb3B0aW9uczogeyByZWRpcmVjdEFmdGVyU2F2ZTogZmFsc2UgfSB9KTtcbiAgfVxuXG59KSgpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKlxuICAgKiBBcnF1aXZvIGRlIGNvbmZpZ3VyYcOnw6NvIGNvbSBhcyByb3RhcyBlc3BlY8OtZmljYXMgZG8gcmVjdXJzbyBwcm9qZWN0XG4gICAqXG4gICAqIEBwYXJhbSB7YW55fSAkc3RhdGVQcm92aWRlclxuICAgKiBAcGFyYW0ge2FueX0gR2xvYmFsXG4gICAqL1xuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvdXRlcygkc3RhdGVQcm92aWRlciwgR2xvYmFsKSB7XG4gICAgJHN0YXRlUHJvdmlkZXJcbiAgICAgIC5zdGF0ZSgnYXBwLnByb2plY3RzJywge1xuICAgICAgICB1cmw6ICcvcHJvamVjdHMnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL3Byb2plY3RzL3Byb2plY3RzLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnUHJvamVjdHNDb250cm9sbGVyIGFzIHByb2plY3RzQ3RybCcsXG4gICAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiB0cnVlIH0sXG4gICAgICAgIHBhcmFtczogeyBvYmo6IG51bGwsIHJlc291cmNlOiBudWxsIH1cbiAgICAgIH0pO1xuICB9XG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZhY3RvcnkoJ1Byb2plY3RzU2VydmljZScsIFByb2plY3RzU2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiBQcm9qZWN0c1NlcnZpY2Uoc2VydmljZUZhY3RvcnkpIHtcbiAgICByZXR1cm4gc2VydmljZUZhY3RvcnkoJ3Byb2plY3RzJywge1xuICAgICAgYWN0aW9uczoge1xuICAgICAgICBmaW5hbGl6ZToge1xuICAgICAgICAgIG1ldGhvZDogJ1BPU1QnLFxuICAgICAgICAgIHVybDogJ2ZpbmFsaXplJ1xuICAgICAgICB9IH0sXG4gICAgICBpbnN0YW5jZTogeyB9XG4gICAgfSk7XG4gIH1cblxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnRyb2xsZXIoJ1JlbGVhc2VzQ29udHJvbGxlcicsIFJlbGVhc2VzQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBSZWxlYXNlc0NvbnRyb2xsZXIoJGNvbnRyb2xsZXIsXG4gICAgUmVsZWFzZXNTZXJ2aWNlLFxuICAgIE1pbGVzdG9uZXNTZXJ2aWNlLFxuICAgIEF1dGgsXG4gICAgUHJUb2FzdCxcbiAgICBtb21lbnQsXG4gICAgJG1kRGlhbG9nLFxuICAgICR0cmFuc2xhdGUpIHtcbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgLy9BdHRyaWJ1dGVzIEJsb2NrXG5cbiAgICAvL0Z1bmN0aW9ucyBCbG9ja1xuICAgIHZtLm9uQWN0aXZhdGUgPSBmdW5jdGlvbigpIHtcbiAgICAgIHZtLmN1cnJlbnRVc2VyID0gQXV0aC5jdXVycmVudFVzZXI7XG4gICAgICB2bS5wcm9qZWN0ID0gbG9jYWxTdG9yYWdlLmdldEl0ZW0oJ3Byb2plY3QnKTtcbiAgICAgIHZtLnF1ZXJ5RmlsdGVycyA9IHsgcHJvamVjdF9pZDogdm0ucHJvamVjdCB9O1xuICAgIH1cblxuICAgIHZtLmJlZm9yZVNhdmUgPSBmdW5jdGlvbigpIHtcbiAgICAgIHZtLnJlc291cmNlLnByb2plY3RfaWQgPSB2bS5wcm9qZWN0O1xuICAgIH1cblxuICAgIHZtLmJlZm9yZVJlbW92ZSA9IGZ1bmN0aW9uKCkge1xuICAgICAgdm0ucmVzb3VyY2UucHJvamVjdF9pZCA9IHZtLnByb2plY3Q7XG4gICAgfVxuXG4gICAgdm0udmlldyA9IGZ1bmN0aW9uIChyZXNvdXJjZSkge1xuICAgICAgdm0ucmVzb3VyY2UgPSByZXNvdXJjZTtcbiAgICAgIHZtLm9uVmlldyA9IHRydWU7XG4gICAgICB2bS52aWV3Rm9ybSA9IGZhbHNlO1xuICAgIH1cblxuICAgIHZtLmZpbmFsaXplID0gZnVuY3Rpb24ocmVsZWFzZSkge1xuICAgICAgdmFyIGNvbmZpcm0gPSAkbWREaWFsb2cuY29uZmlybSgpXG4gICAgICAgICAgLnRpdGxlKCdGaW5hbGl6YXIgUmVsZWFzZScpXG4gICAgICAgICAgLnRleHRDb250ZW50KCdUZW0gY2VydGV6YSBxdWUgZGVzZWphIGZpbmFsaXphciBhIHJlbGVhc2UgJyArIHJlbGVhc2UudGl0bGUgKyAnPycpXG4gICAgICAgICAgLm9rKCdTaW0nKVxuICAgICAgICAgIC5jYW5jZWwoJ07Do28nKTtcblxuICAgICAgJG1kRGlhbG9nLnNob3coY29uZmlybSkudGhlbihmdW5jdGlvbigpIHtcbiAgICAgICAgUmVsZWFzZXNTZXJ2aWNlLmZpbmFsaXplKHsgcHJvamVjdF9pZDogdm0ucHJvamVjdCwgcmVsZWFzZV9pZDogcmVsZWFzZS5pZCB9KS50aGVuKGZ1bmN0aW9uKCkge1xuICAgICAgICAgIFByVG9hc3Quc3VjY2VzcygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnJlbGVhc2VFbmRlZFN1Y2Nlc3MnKSk7XG4gICAgICAgICAgdm0uc2VhcmNoKCk7XG4gICAgICAgIH0sIGZ1bmN0aW9uKCkge1xuICAgICAgICAgIFByVG9hc3QuRXJyb3IoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5yZWxlYXNlRW5kZWRFcnJvcicpKTtcbiAgICAgICAgfSk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICB2bS5mb3JtYXREYXRlID0gZnVuY3Rpb24oZGF0ZSkge1xuICAgICAgcmV0dXJuIG1vbWVudChkYXRlKS5mb3JtYXQoJ0REL01NL1lZWVknKTtcbiAgICB9XG5cbiAgICB2bS5zZWFyY2hNaWxlc3RvbmUgPSBmdW5jdGlvbiAobWlsZXN0b25lVGVybSkge1xuICAgICAgcmV0dXJuIE1pbGVzdG9uZXNTZXJ2aWNlLnF1ZXJ5KHtcbiAgICAgICAgcmVsZWFzZVNlYXJjaDogdHJ1ZSxcbiAgICAgICAgcHJvamVjdF9pZDogdm0ucmVzb3VyY2UucHJvamVjdF9pZCxcbiAgICAgICAgdGl0bGU6IG1pbGVzdG9uZVRlcm1cbiAgICAgIH0pO1xuICAgIH1cblxuICAgIHZtLm9uTWlsZXN0b25lQ2hhbmdlID0gZnVuY3Rpb24oKSB7XG4gICAgICBpZiAodm0ubWlsZXN0b25lICE9PSBudWxsICYmIHZtLnJlc291cmNlLm1pbGVzdG9uZXMuZmluZEluZGV4KGkgPT4gaS5pZCA9PT0gdm0ubWlsZXN0b25lLmlkKSA9PT0gLTEpIHtcbiAgICAgICAgdm0ucmVzb3VyY2UubWlsZXN0b25lcy5wdXNoKHZtLm1pbGVzdG9uZSk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgdm0ucmVtb3ZlTWlsZXN0b25lID0gZnVuY3Rpb24obWlsZXN0b25lKSB7XG4gICAgICB2bS5yZXNvdXJjZS5taWxlc3RvbmVzLnNsaWNlKDApLmZvckVhY2goZnVuY3Rpb24oZWxlbWVudCkge1xuICAgICAgICBpZihlbGVtZW50LmlkID09PSBtaWxlc3RvbmUuaWQpIHtcbiAgICAgICAgICB2bS5yZXNvdXJjZS5taWxlc3RvbmVzLnNwbGljZSh2bS5yZXNvdXJjZS5taWxlc3RvbmVzLmluZGV4T2YoZWxlbWVudCksIDEpO1xuICAgICAgICB9XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICB2bS5zYXZlTWlsZXN0b25lcyA9IGZ1bmN0aW9uKCkge1xuICAgICAgTWlsZXN0b25lc1NlcnZpY2UudXBkYXRlUmVsZWFzZSh7cHJvamVjdF9pZDogdm0ucmVzb3VyY2UucHJvamVjdF9pZCwgcmVsZWFzZV9pZDogdm0ucmVzb3VyY2UuaWQsIG1pbGVzdG9uZXM6IHZtLnJlc291cmNlLm1pbGVzdG9uZXN9KS50aGVuKGZ1bmN0aW9uKCl7XG4gICAgICAgIFByVG9hc3Quc3VjY2VzcygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnNhdmVTdWNjZXNzJykpO1xuICAgICAgICB2bS52aWV3Rm9ybSA9IGZhbHNlO1xuICAgICAgICB2bS5vblZpZXcgPSBmYWxzZTtcbiAgICAgIH0sIGZ1bmN0aW9uKCkge1xuICAgICAgICBQclRvYXN0LmVycm9yKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMub3BlcmF0aW9uRXJyb3InKSk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICB2bS5lc3RpbWF0ZWRUaW1lID0gZnVuY3Rpb24gKG1pbGVzdG9uZSkge1xuICAgICAgbWlsZXN0b25lLmVzdGltYXRlZF90aW1lID0gMDtcbiAgICAgIGlmKG1pbGVzdG9uZS50YXNrcy5sZW5ndGggPiAwKSB7XG4gICAgICAgIG1pbGVzdG9uZS50YXNrcy5mb3JFYWNoKGZ1bmN0aW9uKHRhc2spIHtcbiAgICAgICAgICBtaWxlc3RvbmUuZXN0aW1hdGVkX3RpbWUgKz0gdGFzay5lc3RpbWF0ZWRfdGltZTtcbiAgICAgICAgfSk7XG4gICAgICB9XG4gICAgICByZXR1cm4gbWlsZXN0b25lLmVzdGltYXRlZF90aW1lIC8gODtcbiAgICB9XG5cbiAgICAvLyBpbnN0YW50aWF0ZSBiYXNlIGNvbnRyb2xsZXJcbiAgICAkY29udHJvbGxlcignQ1JVRENvbnRyb2xsZXInLCB7IHZtOiB2bSwgbW9kZWxTZXJ2aWNlOiBSZWxlYXNlc1NlcnZpY2UsIG9wdGlvbnM6IHsgfSB9KTtcblxuICB9XG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqXG4gICAqIEFycXVpdm8gZGUgY29uZmlndXJhw6fDo28gY29tIGFzIHJvdGFzIGVzcGVjw61maWNhcyBkbyByZWN1cnNvIHJlbGVhc2VzXG4gICAqXG4gICAqIEBwYXJhbSB7b2JqZWN0fSAkc3RhdGVQcm92aWRlclxuICAgKiBAcGFyYW0ge29iamVjdH0gR2xvYmFsXG4gICAqL1xuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvdXRlcygkc3RhdGVQcm92aWRlciwgR2xvYmFsKSB7XG4gICAgJHN0YXRlUHJvdmlkZXJcbiAgICAgIC5zdGF0ZSgnYXBwLnJlbGVhc2VzJywge1xuICAgICAgICB1cmw6ICcvcmVsZWFzZXMnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL3JlbGVhc2VzL3JlbGVhc2VzLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnUmVsZWFzZXNDb250cm9sbGVyIGFzIHJlbGVhc2VzQ3RybCcsXG4gICAgICAgIGRhdGE6IHsgfVxuICAgICAgfSk7XG4gIH1cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmFjdG9yeSgnUmVsZWFzZXNTZXJ2aWNlJywgUmVsZWFzZXNTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIFJlbGVhc2VzU2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHZhciBtb2RlbCA9IHNlcnZpY2VGYWN0b3J5KCdyZWxlYXNlcycsIHtcbiAgICAgIGFjdGlvbnM6IHtcbiAgICAgICAgZmluYWxpemU6IHtcbiAgICAgICAgICBtZXRob2Q6ICdQT1NUJyxcbiAgICAgICAgICB1cmw6ICdmaW5hbGl6ZSdcbiAgICAgICAgfVxuICAgICAgfSxcbiAgICAgIGluc3RhbmNlOiB7IH1cbiAgICB9KTtcblxuICAgIHJldHVybiBtb2RlbDtcbiAgfVxuXG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmlsdGVyKCdyb2xlc1N0cicsIHJvbGVzU3RyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvbGVzU3RyKGxvZGFzaCkge1xuICAgIC8qKlxuICAgICAqIEBwYXJhbSB7YXJyYXl9IHJvbGVzIGxpc3RhIGRlIHBlcmZpc1xuICAgICAqIEByZXR1cm4ge3N0cmluZ30gcGVyZmlzIHNlcGFyYWRvcyBwb3IgJywgJyAgXG4gICAgICovXG4gICAgcmV0dXJuIGZ1bmN0aW9uKHJvbGVzKSB7XG4gICAgICByZXR1cm4gbG9kYXNoLm1hcChyb2xlcywgJ3NsdWcnKS5qb2luKCcsICcpO1xuICAgIH07XG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5mYWN0b3J5KCdSb2xlc1NlcnZpY2UnLCBSb2xlc1NlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gUm9sZXNTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCdyb2xlcycpO1xuICB9XG5cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmFjdG9yeSgnU3RhdHVzU2VydmljZScsIFN0YXR1c1NlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gU3RhdHVzU2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHZhciBtb2RlbCA9IHNlcnZpY2VGYWN0b3J5KCdzdGF0dXMnLCB7XG4gICAgICBhY3Rpb25zOiB7IH0sXG4gICAgICBpbnN0YW5jZTogeyB9XG4gICAgfSk7XG5cbiAgICByZXR1cm4gbW9kZWw7XG4gIH1cblxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5mYWN0b3J5KCdTdXBwb3J0U2VydmljZScsIFN1cHBvcnRTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIFN1cHBvcnRTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCdzdXBwb3J0Jywge1xuICAgICAgYWN0aW9uczoge1xuICAgICAgLyoqXG4gICAgICAgKiBQZWdhIGFzIHRyYWR1w6fDtWVzIHF1ZSBlc3TDo28gbm8gc2Vydmlkb3JcbiAgICAgICAqXG4gICAgICAgKiBAcmV0dXJucyB7cHJvbWlzZX0gVW1hIHByb21pc2UgY29tIG8gcmVzdWx0YWRvIGRvIGNoYW1hZGEgbm8gYmFja2VuZFxuICAgICAgICovXG4gICAgICAgIGxhbmdzOiB7XG4gICAgICAgICAgbWV0aG9kOiAnR0VUJyxcbiAgICAgICAgICB1cmw6ICdsYW5ncycsXG4gICAgICAgICAgd3JhcDogZmFsc2UsXG4gICAgICAgICAgY2FjaGU6IHRydWVcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pO1xuICB9XG5cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmFjdG9yeSgnVGFza0NvbW1lbnRzU2VydmljZScsIFRhc2tDb21tZW50c1NlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gVGFza0NvbW1lbnRzU2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHZhciBtb2RlbCA9IHNlcnZpY2VGYWN0b3J5KCd0YXNrLWNvbW1lbnRzJywge1xuICAgICAgYWN0aW9uczoge1xuICAgICAgICBzYXZlVGFza0NvbW1lbnQ6IHtcbiAgICAgICAgICBtZXRob2Q6ICdQT1NUJyxcbiAgICAgICAgICB1cmw6ICdzYXZlVGFza0NvbW1lbnQnXG4gICAgICAgIH0sXG4gICAgICAgIHJlbW92ZVRhc2tDb21tZW50OiB7XG4gICAgICAgICAgbWV0aG9kOiAnUE9TVCcsXG4gICAgICAgICAgdXJsOiAncmVtb3ZlVGFza0NvbW1lbnQnXG4gICAgICAgIH1cbiAgICAgIH0sXG4gICAgICBpbnN0YW5jZTogeyB9XG4gICAgfSk7XG5cbiAgICByZXR1cm4gbW9kZWw7XG4gIH1cblxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZpbHRlcignZWxhcHNlZCcsIGZ1bmN0aW9uKCkge1xuICAgICAgcmV0dXJuIGZ1bmN0aW9uKGRhdGUpIHtcbiAgICAgICAgaWYgKCFkYXRlKSByZXR1cm47XG4gICAgICAgIHZhciB0aW1lID0gRGF0ZS5wYXJzZShkYXRlKSxcbiAgICAgICAgICB0aW1lTm93ID0gbmV3IERhdGUoKS5nZXRUaW1lKCksXG4gICAgICAgICAgZGlmZmVyZW5jZSA9IHRpbWVOb3cgLSB0aW1lLFxuICAgICAgICAgIHNlY29uZHMgPSBNYXRoLmZsb29yKGRpZmZlcmVuY2UgLyAxMDAwKSxcbiAgICAgICAgICBtaW51dGVzID0gTWF0aC5mbG9vcihzZWNvbmRzIC8gNjApLFxuICAgICAgICAgIGhvdXJzID0gTWF0aC5mbG9vcihtaW51dGVzIC8gNjApLFxuICAgICAgICAgIGRheXMgPSBNYXRoLmZsb29yKGhvdXJzIC8gMjQpLFxuICAgICAgICAgIG1vbnRocyA9IE1hdGguZmxvb3IoZGF5cyAvIDMwKTtcblxuICAgICAgICBpZiAobW9udGhzID4gMSkge1xuICAgICAgICAgIHJldHVybiBtb250aHMgKyAnIG1lc2VzIGF0csOhcyc7XG4gICAgICAgIH0gZWxzZSBpZiAobW9udGhzID09PSAxKSB7XG4gICAgICAgICAgcmV0dXJuICcxIG3DqnMgYXRyw6FzJztcbiAgICAgICAgfSBlbHNlIGlmIChkYXlzID4gMSkge1xuICAgICAgICAgIHJldHVybiBkYXlzICsgJyBkaWFzIGF0csOhcyc7XG4gICAgICAgIH0gZWxzZSBpZiAoZGF5cyA9PT0gMSkge1xuICAgICAgICAgIHJldHVybiAnMSBkaWEgYXRyw6FzJ1xuICAgICAgICB9IGVsc2UgaWYgKGhvdXJzID4gMSkge1xuICAgICAgICAgIHJldHVybiBob3VycyArICcgaG9yYXMgYXRyw6FzJztcbiAgICAgICAgfSBlbHNlIGlmIChob3VycyA9PT0gMSkge1xuICAgICAgICAgIHJldHVybiAndW1hIGhvcmEgYXRyw6FzJztcbiAgICAgICAgfSBlbHNlIGlmIChtaW51dGVzID4gMSkge1xuICAgICAgICAgIHJldHVybiBtaW51dGVzICsgJyBtaW51dG9zIGF0csOhcyc7XG4gICAgICAgIH0gZWxzZSBpZiAobWludXRlcyA9PT0gMSkge1xuICAgICAgICAgIHJldHVybiAndW0gbWludXRvIGF0csOhcyc7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgcmV0dXJuICdow6EgcG91Y29zIHNlZ3VuZG9zJztcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pXG4gICAgLmNvbnRyb2xsZXIoJ1Rhc2tzQ29udHJvbGxlcicsIFRhc2tzQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBUYXNrc0NvbnRyb2xsZXIoJGNvbnRyb2xsZXIsXG4gICAgVGFza3NTZXJ2aWNlLFxuICAgIFN0YXR1c1NlcnZpY2UsXG4gICAgUHJpb3JpdGllc1NlcnZpY2UsXG4gICAgVHlwZXNTZXJ2aWNlLFxuICAgIFRhc2tDb21tZW50c1NlcnZpY2UsXG4gICAgbW9tZW50LFxuICAgIEF1dGgsXG4gICAgUHJUb2FzdCxcbiAgICAkdHJhbnNsYXRlLFxuICAgICRmaWx0ZXIsXG4gICAgR2xvYmFsKSB7XG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIC8vQXR0cmlidXRlcyBCbG9ja1xuXG4gICAgLy9GdW5jdGlvbnMgQmxvY2tcbiAgICB2bS5vbkFjdGl2YXRlID0gb25BY3RpdmF0ZTtcbiAgICB2bS5hcHBseUZpbHRlcnMgPSBhcHBseUZpbHRlcnM7XG4gICAgdm0uYmVmb3JlU2F2ZSA9IGJlZm9yZVNhdmU7XG4gICAgdm0uYmVmb3JlUmVtb3ZlID0gYmVmb3JlUmVtb3ZlO1xuXG4gICAgZnVuY3Rpb24gb25BY3RpdmF0ZSgpIHtcbiAgICAgIHZtLmN1cnJlbnRVc2VyID0gQXV0aC5jdXJyZW50VXNlcjtcbiAgICAgIHZtLmltYWdlUGF0aCA9IEdsb2JhbC5pbWFnZVBhdGggKyAnL25vX2F2YXRhci5naWYnO1xuICAgICAgdm0ucHJvamVjdCA9IGxvY2FsU3RvcmFnZS5nZXRJdGVtKCdwcm9qZWN0Jyk7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMgPSB7IHByb2plY3RfaWQ6IHZtLnByb2plY3QgfTtcblxuICAgICAgU3RhdHVzU2VydmljZS5xdWVyeSgpLnRoZW4oZnVuY3Rpb24ocmVzcG9uc2UpIHtcbiAgICAgICAgdm0uc3RhdHVzID0gcmVzcG9uc2U7XG4gICAgICB9KTtcblxuICAgICAgUHJpb3JpdGllc1NlcnZpY2UucXVlcnkoKS50aGVuKGZ1bmN0aW9uKHJlc3BvbnNlKSB7XG4gICAgICAgIHZtLnByaW9yaXRpZXMgPSByZXNwb25zZTtcbiAgICAgIH0pO1xuXG4gICAgICBUeXBlc1NlcnZpY2UucXVlcnkoKS50aGVuKGZ1bmN0aW9uKHJlc3BvbnNlKSB7XG4gICAgICAgIHZtLnR5cGVzID0gcmVzcG9uc2U7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBhcHBseUZpbHRlcnMoZGVmYXVsdFF1ZXJ5RmlsdGVycykge1xuICAgICAgcmV0dXJuIGFuZ3VsYXIuZXh0ZW5kKGRlZmF1bHRRdWVyeUZpbHRlcnMsIHZtLnF1ZXJ5RmlsdGVycyk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gYmVmb3JlU2F2ZSgpIHtcbiAgICAgIHZtLnJlc291cmNlLnByb2plY3RfaWQgPSB2bS5wcm9qZWN0O1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGJlZm9yZVJlbW92ZSgpIHtcbiAgICAgIHZtLnJlc291cmNlLnByb2plY3RfaWQgPSB2bS5wcm9qZWN0O1xuICAgIH1cblxuICAgIHZtLnZpZXcgPSBmdW5jdGlvbiAocmVzb3VyY2UpIHtcbiAgICAgIHZtLnJlc291cmNlID0gcmVzb3VyY2U7XG4gICAgICB2bS5vblZpZXcgPSB0cnVlO1xuICAgICAgdm0udmlld0Zvcm0gPSBmYWxzZTtcbiAgICB9XG5cbiAgICB2bS5zYXZlQ29tbWVudCA9IGZ1bmN0aW9uKGNvbW1lbnQpIHtcbiAgICAgIHZhciBkZXNjcmlwdGlvbiA9ICcnO1xuICAgICAgdmFyIGNvbW1lbnRfaWQgPSBudWxsO1xuXG4gICAgICBpZiAoY29tbWVudCkge1xuICAgICAgICBkZXNjcmlwdGlvbiA9IHZtLmFuc3dlclxuICAgICAgICBjb21tZW50X2lkID0gY29tbWVudC5pZDtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIGRlc2NyaXB0aW9uID0gdm0uY29tbWVudDtcbiAgICAgIH1cbiAgICAgIFRhc2tDb21tZW50c1NlcnZpY2Uuc2F2ZVRhc2tDb21tZW50KHsgcHJvamVjdF9pZDogdm0ucHJvamVjdCwgdGFza19pZDogdm0ucmVzb3VyY2UuaWQsIGNvbW1lbnRfdGV4dDogZGVzY3JpcHRpb24sIGNvbW1lbnRfaWQ6IGNvbW1lbnRfaWQgfSkudGhlbihmdW5jdGlvbigpIHtcbiAgICAgICAgdm0uY29tbWVudCA9ICcnO1xuICAgICAgICB2bS5hbnN3ZXIgPSAnJztcbiAgICAgICAgdm0uc2VhcmNoKCk7XG4gICAgICAgIFByVG9hc3Quc3VjY2VzcygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnNhdmVTdWNjZXNzJykpO1xuICAgICAgfSwgZnVuY3Rpb24oKSB7XG4gICAgICAgIFByVG9hc3QuZXJyb3IoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5vcGVyYXRpb25FcnJvcicpKTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIHZtLnJlbW92ZUNvbW1lbnQgPSBmdW5jdGlvbihjb21tZW50KSB7XG4gICAgICBUYXNrQ29tbWVudHNTZXJ2aWNlLnJlbW92ZVRhc2tDb21tZW50KHsgY29tbWVudF9pZDogY29tbWVudC5pZCB9KS50aGVuKGZ1bmN0aW9uKCkge1xuICAgICAgICB2bS5zZWFyY2goKTtcbiAgICAgICAgUHJUb2FzdC5zdWNjZXNzKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMucmVtb3ZlU3VjY2VzcycpKTtcbiAgICAgIH0sIGZ1bmN0aW9uKCkge1xuICAgICAgICBQclRvYXN0LmVycm9yKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMub3BlcmF0aW9uRXJyb3InKSk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICB2bS5hZnRlclNlYXJjaCA9IGZ1bmN0aW9uKCkge1xuICAgICAgaWYgKHZtLnJlc291cmNlLmlkKSB7XG4gICAgICAgIHZtLnJlc291cmNlID0gJGZpbHRlcignZmlsdGVyJykodm0ucmVzb3VyY2VzLCB7IGlkOiB2bS5yZXNvdXJjZS5pZCB9KVswXTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICB2bS5maXhEYXRlID0gZnVuY3Rpb24oZGF0ZVN0cmluZykge1xuICAgICAgcmV0dXJuIG1vbWVudChkYXRlU3RyaW5nKTtcbiAgICB9XG5cbiAgICAvLyBpbnN0YW50aWF0ZSBiYXNlIGNvbnRyb2xsZXJcbiAgICAkY29udHJvbGxlcignQ1JVRENvbnRyb2xsZXInLCB7IHZtOiB2bSwgbW9kZWxTZXJ2aWNlOiBUYXNrc1NlcnZpY2UsIG9wdGlvbnM6IHsgc2tpcFBhZ2luYXRpb246IHRydWUgfSB9KTtcbiAgfVxuXG59KSgpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKlxuICAgKiBBcnF1aXZvIGRlIGNvbmZpZ3VyYcOnw6NvIGNvbSBhcyByb3RhcyBlc3BlY8OtZmljYXMgZG8gcmVjdXJzbyBwcm9qZWN0XG4gICAqXG4gICAqIEBwYXJhbSB7YW55fSAkc3RhdGVQcm92aWRlclxuICAgKiBAcGFyYW0ge2FueX0gR2xvYmFsXG4gICAqL1xuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvdXRlcygkc3RhdGVQcm92aWRlciwgR2xvYmFsKSB7XG4gICAgJHN0YXRlUHJvdmlkZXJcbiAgICAgIC5zdGF0ZSgnYXBwLnRhc2tzJywge1xuICAgICAgICB1cmw6ICcvdGFza3MnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL3Rhc2tzL3Rhc2tzLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnVGFza3NDb250cm9sbGVyIGFzIHRhc2tzQ3RybCcsXG4gICAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiB0cnVlfVxuICAgICAgfSk7XG4gIH1cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmFjdG9yeSgnVGFza3NTZXJ2aWNlJywgVGFza3NTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIFRhc2tzU2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHJldHVybiBzZXJ2aWNlRmFjdG9yeSgndGFza3MnLCB7XG4gICAgICBhY3Rpb25zOiB7XG4gICAgICAgIHVwZGF0ZU1pbGVzdG9uZToge1xuICAgICAgICAgIG1ldGhvZDogJ1BPU1QnLFxuICAgICAgICAgIHVybDogJ3VwZGF0ZU1pbGVzdG9uZSdcbiAgICAgICAgfSxcbiAgICAgICAgdXBkYXRlVGFza0J5S2FuYmFuOiB7XG4gICAgICAgICAgbWV0aG9kOiAnUE9TVCcsXG4gICAgICAgICAgdXJsOiAndXBkYXRlVGFza0J5S2FuYmFuJ1xuICAgICAgICB9XG4gICAgICB9LFxuICAgICAgaW5zdGFuY2U6IHsgfVxuICAgIH0pO1xuICB9XG5cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmFjdG9yeSgnVHlwZXNTZXJ2aWNlJywgVHlwZXNTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIFR5cGVzU2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHZhciBtb2RlbCA9IHNlcnZpY2VGYWN0b3J5KCd0eXBlcycsIHtcbiAgICAgIGFjdGlvbnM6IHsgfSxcbiAgICAgIGluc3RhbmNlOiB7IH1cbiAgICB9KTtcblxuICAgIHJldHVybiBtb2RlbDtcbiAgfVxuXG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29udHJvbGxlcignUHJvZmlsZUNvbnRyb2xsZXInLCBQcm9maWxlQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBQcm9maWxlQ29udHJvbGxlcihVc2Vyc1NlcnZpY2UsIEF1dGgsIFByVG9hc3QsICR0cmFuc2xhdGUsICR3aW5kb3csIG1vbWVudCkge1xuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICB2bS51cGRhdGUgPSB1cGRhdGU7XG4gICAgdm0uaGlzdG9yeUJhY2sgPSBoaXN0b3J5QmFjaztcblxuICAgIGFjdGl2YXRlKCk7XG5cbiAgICBmdW5jdGlvbiBhY3RpdmF0ZSgpIHtcbiAgICAgIHZtLnVzZXIgPSBhbmd1bGFyLmNvcHkoQXV0aC5jdXJyZW50VXNlcik7XG4gICAgICBpZiAodm0udXNlci5iaXJ0aGRheSkge1xuICAgICAgICB2bS51c2VyLmJpcnRoZGF5ID0gbW9tZW50KHZtLnVzZXIuYmlydGhkYXkpLmZvcm1hdCgnREQvTU0vWVlZWScpO1xuICAgICAgfVxuICAgIH1cblxuICAgIGZ1bmN0aW9uIHVwZGF0ZSgpIHtcbiAgICAgIGlmICh2bS51c2VyLmJpcnRoZGF5KSB7XG4gICAgICAgIHZtLnVzZXIuYmlydGhkYXkgPSBtb21lbnQodm0udXNlci5iaXJ0aGRheSk7XG4gICAgICB9XG4gICAgICBVc2Vyc1NlcnZpY2UudXBkYXRlUHJvZmlsZSh2bS51c2VyKS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICAvL2F0dWFsaXphIG8gdXN1w6FyaW8gY29ycmVudGUgY29tIGFzIG5vdmFzIGluZm9ybWHDp8O1ZXNcbiAgICAgICAgQXV0aC51cGRhdGVDdXJyZW50VXNlcihyZXNwb25zZSk7XG4gICAgICAgIFByVG9hc3Quc3VjY2VzcygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnNhdmVTdWNjZXNzJykpO1xuICAgICAgICBoaXN0b3J5QmFjaygpO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gaGlzdG9yeUJhY2soKSB7XG4gICAgICAkd2luZG93Lmhpc3RvcnkuYmFjaygpO1xuICAgIH1cblxuICB9XG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb250cm9sbGVyKCdVc2Vyc0NvbnRyb2xsZXInLCBVc2Vyc0NvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gVXNlcnNDb250cm9sbGVyKCRjb250cm9sbGVyLCBVc2Vyc1NlcnZpY2UsIFByVG9hc3QsICRtZERpYWxvZywgJHRyYW5zbGF0ZSkge1xuXG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIHZtLm9uQWN0aXZhdGUgPSBvbkFjdGl2YXRlO1xuICAgIC8vIGluc3RhbnRpYXRlIGJhc2UgY29udHJvbGxlclxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHsgdm06IHZtLCBtb2RlbFNlcnZpY2U6IFVzZXJzU2VydmljZSwgb3B0aW9uczoge30gfSk7XG5cbiAgICBmdW5jdGlvbiBvbkFjdGl2YXRlKCkge1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0ge307XG4gICAgfVxuXG4gICAgdm0uaGlkZURpYWxvZyA9IGZ1bmN0aW9uKCkge1xuICAgICAgJG1kRGlhbG9nLmhpZGUoKTtcbiAgICB9XG5cbiAgICB2bS5zYXZlTmV3VXNlciA9IGZ1bmN0aW9uKCkge1xuICAgICAgdm0ucmVzb3VyY2UuJHNhdmUoKS50aGVuKGZ1bmN0aW9uIChyZXNvdXJjZSkge1xuICAgICAgICB2bS5yZXNvdXJjZSA9IHJlc291cmNlO1xuICAgICAgICBQclRvYXN0LnN1Y2Nlc3MoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5zdWNjZXNzU2lnblVwJykpO1xuICAgICAgICAkbWREaWFsb2cuaGlkZSgpO1xuICAgICAgfSk7XG4gICAgfVxuICB9XG59KSgpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKlxuICAgKiBBcnF1aXZvIGRlIGNvbmZpZ3VyYcOnw6NvIGNvbSBhcyByb3RhcyBlc3BlY8OtZmljYXMgZG8gcmVjdXJzbyB1c2VyXG4gICAqXG4gICAqIEBwYXJhbSB7YW55fSAkc3RhdGVQcm92aWRlclxuICAgKiBAcGFyYW0ge2FueX0gR2xvYmFsXG4gICAqL1xuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvdXRlcygkc3RhdGVQcm92aWRlciwgR2xvYmFsKSB7XG4gICAgJHN0YXRlUHJvdmlkZXJcbiAgICAgIC5zdGF0ZSgnYXBwLnVzZXInLCB7XG4gICAgICAgIHVybDogJy91c3VhcmlvJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy91c2Vycy91c2Vycy5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ1VzZXJzQ29udHJvbGxlciBhcyB1c2Vyc0N0cmwnLFxuICAgICAgICBkYXRhOiB7IG5lZWRBdXRoZW50aWNhdGlvbjogdHJ1ZSwgbmVlZFByb2ZpbGU6IFsnYWRtaW4nXSB9XG4gICAgICB9KVxuICAgICAgLnN0YXRlKCdhcHAudXNlci1wcm9maWxlJywge1xuICAgICAgICB1cmw6ICcvdXN1YXJpby9wZXJmaWwnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL3VzZXJzL3Byb2ZpbGUuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdQcm9maWxlQ29udHJvbGxlciBhcyBwcm9maWxlQ3RybCcsXG4gICAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiB0cnVlIH1cbiAgICAgIH0pO1xuXG4gIH1cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmFjdG9yeSgnVXNlcnNTZXJ2aWNlJywgVXNlcnNTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIFVzZXJzU2VydmljZShsb2Rhc2gsIEdsb2JhbCwgc2VydmljZUZhY3RvcnkpIHtcbiAgICByZXR1cm4gc2VydmljZUZhY3RvcnkoJ3VzZXJzJywge1xuICAgICAgLy9xdWFuZG8gaW5zdGFuY2lhIHVtIHVzdcOhcmlvIHNlbSBwYXNzYXIgcGFyYW1ldHJvLFxuICAgICAgLy9vIG1lc21vIHZhaSB0ZXIgb3MgdmFsb3JlcyBkZWZhdWx0cyBhYmFpeG9cbiAgICAgIGRlZmF1bHRzOiB7XG4gICAgICAgIHJvbGVzOiBbXVxuICAgICAgfSxcblxuICAgICAgYWN0aW9uczoge1xuICAgICAgICAvKipcbiAgICAgICAgICogU2VydmnDp28gcXVlIGF0dWFsaXphIG9zIGRhZG9zIGRvIHBlcmZpbCBkbyB1c3XDoXJpbyBsb2dhZG9cbiAgICAgICAgICpcbiAgICAgICAgICogQHBhcmFtIHtvYmplY3R9IGF0dHJpYnV0ZXNcbiAgICAgICAgICogQHJldHVybnMge3Byb21pc2V9IFVtYSBwcm9taXNlIGNvbSBvIHJlc3VsdGFkbyBkbyBjaGFtYWRhIG5vIGJhY2tlbmRcbiAgICAgICAgICovXG4gICAgICAgIHVwZGF0ZVByb2ZpbGU6IHtcbiAgICAgICAgICBtZXRob2Q6ICdQVVQnLFxuICAgICAgICAgIHVybDogR2xvYmFsLmFwaVBhdGggKyAnL3Byb2ZpbGUnLFxuICAgICAgICAgIG92ZXJyaWRlOiB0cnVlLFxuICAgICAgICAgIHdyYXA6IGZhbHNlXG4gICAgICAgIH1cbiAgICAgIH0sXG5cbiAgICAgIGluc3RhbmNlOiB7XG4gICAgICAgIC8qKlxuICAgICAgICAgKiBWZXJpZmljYSBzZSBvIHVzdcOhcmlvIHRlbSBvcyBwZXJmaXMgaW5mb3JtYWRvcy5cbiAgICAgICAgICpcbiAgICAgICAgICogQHBhcmFtIHthbnl9IHJvbGVzIHBlcmZpcyBhIHNlcmVtIHZlcmlmaWNhZG9zXG4gICAgICAgICAqIEBwYXJhbSB7Ym9vbGVhbn0gYWxsIGZsYWcgcGFyYSBpbmRpY2FyIHNlIHZhaSBjaGVnYXIgdG9kb3Mgb3MgcGVyZmlzIG91IHNvbWVudGUgdW0gZGVsZXNcbiAgICAgICAgICogQHJldHVybnMge2Jvb2xlYW59XG4gICAgICAgICAqL1xuICAgICAgICBoYXNQcm9maWxlOiBmdW5jdGlvbihyb2xlcywgYWxsKSB7XG4gICAgICAgICAgcm9sZXMgPSBhbmd1bGFyLmlzQXJyYXkocm9sZXMpID8gcm9sZXMgOiBbcm9sZXNdO1xuXG4gICAgICAgICAgdmFyIHVzZXJSb2xlcyA9IGxvZGFzaC5tYXAodGhpcy5yb2xlcywgJ3NsdWcnKTtcblxuICAgICAgICAgIGlmIChhbGwpIHtcbiAgICAgICAgICAgIHJldHVybiBsb2Rhc2guaW50ZXJzZWN0aW9uKHVzZXJSb2xlcywgcm9sZXMpLmxlbmd0aCA9PT0gcm9sZXMubGVuZ3RoO1xuICAgICAgICAgIH0gZWxzZSB7IC8vcmV0dXJuIHRoZSBsZW5ndGggYmVjYXVzZSAwIGlzIGZhbHNlIGluIGpzXG4gICAgICAgICAgICByZXR1cm4gbG9kYXNoLmludGVyc2VjdGlvbih1c2VyUm9sZXMsIHJvbGVzKS5sZW5ndGg7XG4gICAgICAgICAgfVxuICAgICAgICB9LFxuXG4gICAgICAgIC8qKlxuICAgICAgICAgKiBWZXJpZmljYSBzZSBvIHVzdcOhcmlvIHRlbSBvIHBlcmZpbCBhZG1pbi5cbiAgICAgICAgICpcbiAgICAgICAgICogQHJldHVybnMge2Jvb2xlYW59XG4gICAgICAgICAqL1xuICAgICAgICBpc0FkbWluOiBmdW5jdGlvbigpIHtcbiAgICAgICAgICByZXR1cm4gdGhpcy5oYXNQcm9maWxlKCdhZG1pbicpO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfSk7XG4gIH1cblxufSgpKTtcbiIsIi8vdG9rZW4gY2FjYjkxMjM1ODczYThjNDg3NWQyMzU3OGFjOWYzMjZlZjg5NGI2NlxuLy8gT0F0dXRoIGh0dHBzOi8vZ2l0aHViLmNvbS9sb2dpbi9vYXV0aC9hdXRob3JpemU/Y2xpZW50X2lkPTgyOTQ2OGU3ZmRlZTc5NDQ1YmE2JnNjb3BlPXVzZXIscHVibGljX3JlcG8mcmVkaXJlY3RfdXJpPWh0dHA6Ly8wLjAuMC4wOjUwMDAvIyEvYXBwL3Zjc1xuXG4oZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZpbHRlcignYnl0ZXMnLCBmdW5jdGlvbigpIHtcbiAgICAgIHJldHVybiBmdW5jdGlvbihieXRlcywgcHJlY2lzaW9uKSB7XG4gICAgICAgIGlmIChpc05hTihwYXJzZUZsb2F0KGJ5dGVzKSkgfHwgIWlzRmluaXRlKGJ5dGVzKSkgcmV0dXJuICctJztcbiAgICAgICAgaWYgKHR5cGVvZiBwcmVjaXNpb24gPT09ICd1bmRlZmluZWQnKSBwcmVjaXNpb24gPSAxO1xuICAgICAgICB2YXIgdW5pdHMgPSBbJ2J5dGVzJywgJ2tCJywgJ01CJywgJ0dCJywgJ1RCJywgJ1BCJ10sXG4gICAgICAgICAgbnVtYmVyID0gTWF0aC5mbG9vcihNYXRoLmxvZyhieXRlcykgLyBNYXRoLmxvZygxMDI0KSk7XG5cbiAgICAgICAgcmV0dXJuIChieXRlcyAvIE1hdGgucG93KDEwMjQsIE1hdGguZmxvb3IobnVtYmVyKSkpLnRvRml4ZWQocHJlY2lzaW9uKSArICAnICcgKyB1bml0c1tudW1iZXJdO1xuICAgICAgfVxuICAgIH0pXG4gICAgLmNvbnRyb2xsZXIoJ1Zjc0NvbnRyb2xsZXInLCBWY3NDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIFZjc0NvbnRyb2xsZXIoJGNvbnRyb2xsZXIsIFZjc1NlcnZpY2UsICR3aW5kb3csIFByb2plY3RzU2VydmljZSwgUHJUb2FzdCwgJHRyYW5zbGF0ZSkge1xuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICB2bS5pbmRleCA9IDA7XG4gICAgdm0ucGF0aHMgPSBbXTtcblxuICAgIC8vQXR0cmlidXRlcyBCbG9ja1xuXG4gICAgLy9GdW5jdGlvbnMgQmxvY2tcbiAgICB2bS5vbkFjdGl2YXRlID0gIGZ1bmN0aW9uKCkge1xuICAgICAgdG9nZ2xlU3BsYXNoU2NyZWVuKCk7XG4gICAgICBQcm9qZWN0c1NlcnZpY2UucXVlcnkoeyBwcm9qZWN0X2lkOiBsb2NhbFN0b3JhZ2UuZ2V0SXRlbSgncHJvamVjdCcpIH0pLnRoZW4oZnVuY3Rpb24ocmVzcG9uc2UpIHtcbiAgICAgICAgdm0udXNlcm5hbWUgPSByZXNwb25zZVswXS51c2VybmFtZV9naXRodWI7XG4gICAgICAgIHZtLnJlcG8gPSByZXNwb25zZVswXS5yZXBvX2dpdGh1YjtcbiAgICAgICAgdm0ucXVlcnlGaWx0ZXJzID0ge1xuICAgICAgICAgIHVzZXJuYW1lOiB2bS51c2VybmFtZSxcbiAgICAgICAgICByZXBvOiB2bS5yZXBvLFxuICAgICAgICAgIHBhdGg6ICcuJ1xuICAgICAgICB9XG4gICAgICAgIHZtLnBhdGhzLnB1c2godm0ucXVlcnlGaWx0ZXJzLnBhdGgpO1xuICAgICAgICB2bS5zZWFyY2goKTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIHZtLmFwcGx5RmlsdGVycyA9IGZ1bmN0aW9uKGRlZmF1bHRRdWVyeUZpbHRlcnMpIHtcbiAgICAgIHJldHVybiBhbmd1bGFyLmV4dGVuZChkZWZhdWx0UXVlcnlGaWx0ZXJzLCB2bS5xdWVyeUZpbHRlcnMpO1xuICAgIH1cblxuICAgIHZtLmFmdGVyU2VhcmNoID0gZnVuY3Rpb24oKSB7XG4gICAgICBzb3J0UmVzb3VyY2VzKCk7XG4gICAgICAkd2luZG93LmxvYWRpbmdfc2NyZWVuLmZpbmlzaCgpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIHNvcnRSZXNvdXJjZXMoKSB7XG4gICAgICB2bS5yZXNvdXJjZXMuc29ydChmdW5jdGlvbihhLCBiKSB7XG4gICAgICAgIHJldHVybiBhLnR5cGUgPCBiLnR5cGUgPyAtMSA6IGEudHlwZSA+IGIudHlwZSA/IDEgOiAwO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgdm0ub3BlbkZpbGVPckRpcmVjdG9yeSA9IGZ1bmN0aW9uKHJlc291cmNlKSB7XG4gICAgICB0b2dnbGVTcGxhc2hTY3JlZW4oKTtcbiAgICAgIGlmIChyZXNvdXJjZSkge1xuICAgICAgICB2bS5xdWVyeUZpbHRlcnMucGF0aCA9IHJlc291cmNlLnBhdGg7XG4gICAgICAgIHZtLnBhdGhzLnB1c2godm0ucXVlcnlGaWx0ZXJzLnBhdGgpO1xuICAgICAgICB2bS5pbmRleCsrO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgdm0ucXVlcnlGaWx0ZXJzLnBhdGggPSB2bS5wYXRoc1t2bS5pbmRleCAtIDFdO1xuICAgICAgICB2bS5wYXRocy5zcGxpY2Uodm0uaW5kZXgsIDEpO1xuICAgICAgICB2bS5pbmRleC0tO1xuICAgICAgfVxuICAgICAgdm0uc2VhcmNoKCk7XG4gICAgfVxuXG4gICAgdm0ub25TZWFyY2hFcnJvciA9IGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgaWYgKHJlc3BvbnNlLmRhdGEuZXJyb3IgPT09ICdOb3QgRm91bmQnKSB7XG4gICAgICAgIFByVG9hc3QuaW5mbygkdHJhbnNsYXRlLmluc3RhbnQoJ1JlcG9zaXTDs3JpbyBuw6NvIGVuY29udHJhZG8nKSk7XG4gICAgICAgICR3aW5kb3cubG9hZGluZ19zY3JlZW4uZmluaXNoKCk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogTcOpdG9kbyBwYXJhIG1vc3RyYXIgYSB0ZWxhIGRlIGVzcGVyYVxuICAgICAqL1xuICAgIGZ1bmN0aW9uIHRvZ2dsZVNwbGFzaFNjcmVlbigpIHtcbiAgICAgICR3aW5kb3cubG9hZGluZ19zY3JlZW4gPSAkd2luZG93LnBsZWFzZVdhaXQoe1xuICAgICAgICBsb2dvOiAnJyxcbiAgICAgICAgYmFja2dyb3VuZENvbG9yOiAncmdiYSgyNTUsMjU1LDI1NSwwLjQpJyxcbiAgICAgICAgbG9hZGluZ0h0bWw6XG4gICAgICAgICAgJzxkaXYgY2xhc3M9XCJzcGlubmVyXCI+ICcgK1xuICAgICAgICAgICcgIDxkaXYgY2xhc3M9XCJyZWN0MVwiPjwvZGl2PiAnICtcbiAgICAgICAgICAnICA8ZGl2IGNsYXNzPVwicmVjdDJcIj48L2Rpdj4gJyArXG4gICAgICAgICAgJyAgPGRpdiBjbGFzcz1cInJlY3QzXCI+PC9kaXY+ICcgK1xuICAgICAgICAgICcgIDxkaXYgY2xhc3M9XCJyZWN0NFwiPjwvZGl2PiAnICtcbiAgICAgICAgICAnICA8ZGl2IGNsYXNzPVwicmVjdDVcIj48L2Rpdj4gJyArXG4gICAgICAgICAgJyA8cCBjbGFzcz1cImxvYWRpbmctbWVzc2FnZVwiPkNhcnJlZ2FuZG88L3A+ICcgK1xuICAgICAgICAgICc8L2Rpdj4nXG4gICAgICB9KTtcbiAgICB9XG5cbiAgICAvLyBpbnN0YW50aWF0ZSBiYXNlIGNvbnRyb2xsZXJcbiAgICAkY29udHJvbGxlcignQ1JVRENvbnRyb2xsZXInLCB7IHZtOiB2bSwgbW9kZWxTZXJ2aWNlOiBWY3NTZXJ2aWNlLCBvcHRpb25zOiB7IHNraXBQYWdpbmF0aW9uOiB0cnVlLCBzZWFyY2hPbkluaXQ6IGZhbHNlIH0gfSk7XG5cbiAgfVxuXG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqXG4gICAqIEFycXVpdm8gZGUgY29uZmlndXJhw6fDo28gY29tIGFzIHJvdGFzIGVzcGVjw61maWNhcyBkbyByZWN1cnNvIHZjc1xuICAgKlxuICAgKiBAcGFyYW0ge29iamVjdH0gJHN0YXRlUHJvdmlkZXJcbiAgICogQHBhcmFtIHtvYmplY3R9IEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyXG4gICAgICAuc3RhdGUoJ2FwcC52Y3MnLCB7XG4gICAgICAgIHVybDogJy92Y3MnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL3Zjcy92Y3MuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdWY3NDb250cm9sbGVyIGFzIHZjc0N0cmwnLFxuICAgICAgICBkYXRhOiB7IH1cbiAgICAgIH0pO1xuICB9XG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZhY3RvcnkoJ1Zjc1NlcnZpY2UnLCBWY3NTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIFZjc1NlcnZpY2Uoc2VydmljZUZhY3RvcnkpIHtcbiAgICB2YXIgbW9kZWwgPSBzZXJ2aWNlRmFjdG9yeSgndmNzJywge1xuICAgICAgYWN0aW9uczogeyB9LFxuICAgICAgaW5zdGFuY2U6IHsgfVxuICAgIH0pO1xuXG4gICAgcmV0dXJuIG1vZGVsO1xuICB9XG5cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICAgLyoqIEBuZ0luamVjdCAqL1xuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29tcG9uZW50KCdib3gnLCB7XG4gICAgICByZXBsYWNlOiB0cnVlLFxuICAgICAgdGVtcGxhdGVVcmw6IFsnR2xvYmFsJywgZnVuY3Rpb24oR2xvYmFsKSB7XG4gICAgICAgIHJldHVybiBHbG9iYWwuY2xpZW50UGF0aCArICcvd2lkZ2V0cy9ib3guaHRtbCdcbiAgICAgIH1dLFxuICAgICAgdHJhbnNjbHVkZToge1xuICAgICAgICB0b29sYmFyQnV0dG9uczogJz9ib3hUb29sYmFyQnV0dG9ucycsXG4gICAgICAgIGZvb3RlckJ1dHRvbnM6ICc/Ym94Rm9vdGVyQnV0dG9ucydcbiAgICAgIH0sXG4gICAgICBiaW5kaW5nczoge1xuICAgICAgICBib3hUaXRsZTogJ0AnLFxuICAgICAgICB0b29sYmFyQ2xhc3M6ICdAJyxcbiAgICAgICAgdG9vbGJhckJnQ29sb3I6ICdAJ1xuICAgICAgfSxcbiAgICAgIGNvbnRyb2xsZXI6IFsnJHRyYW5zY2x1ZGUnLCBmdW5jdGlvbigkdHJhbnNjbHVkZSkge1xuICAgICAgICB2YXIgY3RybCA9IHRoaXM7XG5cbiAgICAgICAgY3RybC50cmFuc2NsdWRlID0gJHRyYW5zY2x1ZGU7XG5cbiAgICAgICAgY3RybC4kb25Jbml0ID0gZnVuY3Rpb24oKSB7XG4gICAgICAgICAgaWYgKGFuZ3VsYXIuaXNVbmRlZmluZWQoY3RybC50b29sYmFyQmdDb2xvcikpIGN0cmwudG9vbGJhckJnQ29sb3IgPSAnZGVmYXVsdC1wcmltYXJ5JztcbiAgICAgICAgfTtcbiAgICAgIH1dXG4gICAgfSk7XG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29tcG9uZW50KCdjb250ZW50Qm9keScsIHtcbiAgICAgIHJlcGxhY2U6IHRydWUsXG4gICAgICB0cmFuc2NsdWRlOiB0cnVlLFxuICAgICAgdGVtcGxhdGVVcmw6IFsnR2xvYmFsJywgZnVuY3Rpb24oR2xvYmFsKSB7XG4gICAgICAgIHJldHVybiBHbG9iYWwuY2xpZW50UGF0aCArICcvd2lkZ2V0cy9jb250ZW50LWJvZHkuaHRtbCdcbiAgICAgIH1dLFxuICAgICAgYmluZGluZ3M6IHtcbiAgICAgICAgbGF5b3V0QWxpZ246ICdAJ1xuICAgICAgfSxcbiAgICAgIGNvbnRyb2xsZXI6IFtmdW5jdGlvbigpIHtcbiAgICAgICAgdmFyIGN0cmwgPSB0aGlzO1xuXG4gICAgICAgIGN0cmwuJG9uSW5pdCA9IGZ1bmN0aW9uKCkge1xuICAgICAgICAgIC8vIE1ha2UgYSBjb3B5IG9mIHRoZSBpbml0aWFsIHZhbHVlIHRvIGJlIGFibGUgdG8gcmVzZXQgaXQgbGF0ZXJcbiAgICAgICAgICBjdHJsLmxheW91dEFsaWduID0gYW5ndWxhci5pc0RlZmluZWQoY3RybC5sYXlvdXRBbGlnbikgPyBjdHJsLmxheW91dEFsaWduIDogJ2NlbnRlciBzdGFydCc7XG4gICAgICAgIH07XG4gICAgICB9XVxuICAgIH0pO1xuXG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29tcG9uZW50KCdjb250ZW50SGVhZGVyJywge1xuICAgICAgdGVtcGxhdGVVcmw6IFsnR2xvYmFsJywgZnVuY3Rpb24oR2xvYmFsKSB7XG4gICAgICAgIHJldHVybiBHbG9iYWwuY2xpZW50UGF0aCArICcvd2lkZ2V0cy9jb250ZW50LWhlYWRlci5odG1sJ1xuICAgICAgfV0sXG4gICAgICByZXBsYWNlOiB0cnVlLFxuICAgICAgYmluZGluZ3M6IHtcbiAgICAgICAgdGl0bGU6ICdAJyxcbiAgICAgICAgZGVzY3JpcHRpb246ICdAJ1xuICAgICAgfVxuICAgIH0pO1xuXG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmlsdGVyKCdhdWRpdERldGFpbFRpdGxlJywgYXVkaXREZXRhaWxUaXRsZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBhdWRpdERldGFpbFRpdGxlKCR0cmFuc2xhdGUpIHtcbiAgICByZXR1cm4gZnVuY3Rpb24oYXVkaXREZXRhaWwsIHN0YXR1cykge1xuICAgICAgaWYgKGF1ZGl0RGV0YWlsLnR5cGUgPT09ICd1cGRhdGVkJykge1xuICAgICAgICBpZiAoc3RhdHVzID09PSAnYmVmb3JlJykge1xuICAgICAgICAgIHJldHVybiAkdHJhbnNsYXRlLmluc3RhbnQoJ2RpYWxvZy5hdWRpdC51cGRhdGVkQmVmb3JlJyk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgcmV0dXJuICR0cmFuc2xhdGUuaW5zdGFudCgnZGlhbG9nLmF1ZGl0LnVwZGF0ZWRBZnRlcicpO1xuICAgICAgICB9XG4gICAgICB9IGVsc2Uge1xuICAgICAgICByZXR1cm4gJHRyYW5zbGF0ZS5pbnN0YW50KCdkaWFsb2cuYXVkaXQuJyArIGF1ZGl0RGV0YWlsLnR5cGUpO1xuICAgICAgfVxuICAgIH1cbiAgfVxuXG59KSgpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmlsdGVyKCdhdWRpdE1vZGVsJywgYXVkaXRNb2RlbCk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBhdWRpdE1vZGVsKCR0cmFuc2xhdGUpIHtcbiAgICByZXR1cm4gZnVuY3Rpb24obW9kZWxJZCkge1xuICAgICAgbW9kZWxJZCA9IG1vZGVsSWQucmVwbGFjZSgnQXBwXFxcXCcsICcnKTtcbiAgICAgIHZhciBtb2RlbCA9ICR0cmFuc2xhdGUuaW5zdGFudCgnbW9kZWxzLicgKyBtb2RlbElkLnRvTG93ZXJDYXNlKCkpO1xuXG4gICAgICByZXR1cm4gKG1vZGVsKSA/IG1vZGVsIDogbW9kZWxJZDtcbiAgICB9XG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZpbHRlcignYXVkaXRUeXBlJywgYXVkaXRUeXBlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIGF1ZGl0VHlwZShsb2Rhc2gsIEF1ZGl0U2VydmljZSkge1xuICAgIHJldHVybiBmdW5jdGlvbih0eXBlSWQpIHtcbiAgICAgIHZhciB0eXBlID0gbG9kYXNoLmZpbmQoQXVkaXRTZXJ2aWNlLmxpc3RUeXBlcygpLCB7IGlkOiB0eXBlSWQgfSk7XG5cbiAgICAgIHJldHVybiAodHlwZSkgPyB0eXBlLmxhYmVsIDogdHlwZTtcbiAgICB9XG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZpbHRlcignYXVkaXRWYWx1ZScsIGF1ZGl0VmFsdWUpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gYXVkaXRWYWx1ZSgkZmlsdGVyLCBsb2Rhc2gpIHtcbiAgICByZXR1cm4gZnVuY3Rpb24odmFsdWUsIGtleSkge1xuICAgICAgaWYgKGFuZ3VsYXIuaXNEYXRlKHZhbHVlKSB8fCBsb2Rhc2guZW5kc1dpdGgoa2V5LCAnX2F0JykgfHwgIGxvZGFzaC5lbmRzV2l0aChrZXksICdfdG8nKSkge1xuICAgICAgICByZXR1cm4gJGZpbHRlcigncHJEYXRldGltZScpKHZhbHVlKTtcbiAgICAgIH1cblxuICAgICAgaWYgKHR5cGVvZiB2YWx1ZSA9PT0gJ2Jvb2xlYW4nKSB7XG4gICAgICAgIHJldHVybiAkZmlsdGVyKCd0cmFuc2xhdGUnKSgodmFsdWUpID8gJ2dsb2JhbC55ZXMnIDogJ2dsb2JhbC5ubycpO1xuICAgICAgfVxuXG4gICAgICAvL2NoZWNrIGlzIGZsb2F0XG4gICAgICBpZiAoTnVtYmVyKHZhbHVlKSA9PT0gdmFsdWUgJiYgdmFsdWUgJSAxICE9PSAwKSB7XG4gICAgICAgIHJldHVybiAkZmlsdGVyKCdyZWFsJykodmFsdWUpO1xuICAgICAgfVxuXG4gICAgICByZXR1cm4gdmFsdWU7XG4gICAgfVxuICB9XG5cbn0pKCk7XG4iLCIvKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCwgbm8tdW5kZWY6IDAqL1xuKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnN0YW50KCdwdC1CUi5pMThuLmF0dHJpYnV0ZXMnLCB7XG4gICAgICBlbWFpbDogJ0VtYWlsJyxcbiAgICAgIHBhc3N3b3JkOiAnU2VuaGEnLFxuICAgICAgbmFtZTogJ05vbWUnLFxuICAgICAgaW1hZ2U6ICdJbWFnZW0nLFxuICAgICAgcm9sZXM6ICdQZXJmaXMnLFxuICAgICAgZGF0ZTogJ0RhdGEnLFxuICAgICAgaW5pdGlhbERhdGU6ICdEYXRhIEluaWNpYWwnLFxuICAgICAgZmluYWxEYXRlOiAnRGF0YSBGaW5hbCcsXG4gICAgICBiaXJ0aGRheTogJ0RhdGEgZGUgTmFzY2ltZW50bycsXG4gICAgICB0YXNrOiB7XG4gICAgICAgIGRlc2NyaXB0aW9uOiAnRGVzY3Jpw6fDo28nLFxuICAgICAgICBkb25lOiAnRmVpdG8/JyxcbiAgICAgICAgcHJpb3JpdHk6ICdQcmlvcmlkYWRlJyxcbiAgICAgICAgc2NoZWR1bGVkX3RvOiAnQWdlbmRhZG8gUGFyYT8nLFxuICAgICAgICBwcm9qZWN0OiAnUHJvamV0bycsXG4gICAgICAgIHN0YXR1czogJ1N0YXR1cycsXG4gICAgICAgIHRpdGxlOiAnVMOtdHVsbycsXG4gICAgICAgIHR5cGU6ICdUaXBvJyxcbiAgICAgICAgbWlsZXN0b25lOiAnU3ByaW50JyxcbiAgICAgICAgZXN0aW1hdGVkX3RpbWU6ICdUZW1wbyBFc3RpbWFkbydcbiAgICAgIH0sXG4gICAgICBtaWxlc3RvbmU6IHtcbiAgICAgICAgdGl0bGU6ICdUw610dWxvJyxcbiAgICAgICAgZGVzY3JpcHRpb246ICdEZXNjcmnDp8OjbycsXG4gICAgICAgIGRhdGVfc3RhcnQ6ICdEYXRhIEVzdGltYWRhIHBhcmEgSW7DrWNpbycsXG4gICAgICAgIGRhdGVfZW5kOiAnRGF0YSBFc3RpbWFkYSBwYXJhIEZpbScsXG4gICAgICAgIGVzdGltYXRlZF90aW1lOiAnVGVtcG8gRXN0aW1hZG8nLFxuICAgICAgICBlc3RpbWF0ZWRfdmFsdWU6ICdWYWxvciBFc3RpbWFkbydcbiAgICAgIH0sXG4gICAgICBwcm9qZWN0OiB7XG4gICAgICAgIGNvc3Q6ICdDdXN0bycsXG4gICAgICAgIGhvdXJWYWx1ZURldmVsb3BlcjogJ1ZhbG9yIGRhIEhvcmEgRGVzZW52b2x2ZWRvcicsXG4gICAgICAgIGhvdXJWYWx1ZUNsaWVudDogJ1ZhbG9yIGRhIEhvcmEgQ2xpZW50ZScsXG4gICAgICAgIGhvdXJWYWx1ZUZpbmFsOiAnVmFsb3IgZGEgSG9yYSBQcm9qZXRvJ1xuICAgICAgfSxcbiAgICAgIHJlbGVhc2U6IHtcbiAgICAgICAgdGl0bGU6ICdUw610dWxvJyxcbiAgICAgICAgZGVzY3JpcHRpb246ICdEZXNjcmnDp8OjbycsXG4gICAgICAgIHJlbGVhc2VfZGF0ZTogJ0RhdGEgZGUgRW50cmVnYScsXG4gICAgICAgIG1pbGVzdG9uZTogJ01pbGVzdG9uZScsXG4gICAgICAgIHRhc2tzOiAnVGFyZWZhcydcbiAgICAgIH0sXG4gICAgICAvL8OpIGNhcnJlZ2FkbyBkbyBzZXJ2aWRvciBjYXNvIGVzdGVqYSBkZWZpbmlkbyBubyBtZXNtb1xuICAgICAgYXVkaXRNb2RlbDoge1xuICAgICAgfVxuICAgIH0pXG5cbn0oKSk7XG4iLCIvKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCwgbm8tdW5kZWY6IDAqL1xuKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnN0YW50KCdwdC1CUi5pMThuLmRpYWxvZycsIHtcbiAgICAgIGNvbmZpcm1UaXRsZTogJ0NvbmZpcm1hw6fDo28nLFxuICAgICAgY29uZmlybURlc2NyaXB0aW9uOiAnQ29uZmlybWEgYSBhw6fDo28/JyxcbiAgICAgIHJlbW92ZURlc2NyaXB0aW9uOiAnRGVzZWphIHJlbW92ZXIgcGVybWFuZW50ZW1lbnRlIHt7bmFtZX19PycsXG4gICAgICBhdWRpdDoge1xuICAgICAgICBjcmVhdGVkOiAnSW5mb3JtYcOnw7VlcyBkbyBDYWRhc3RybycsXG4gICAgICAgIHVwZGF0ZWRCZWZvcmU6ICdBbnRlcyBkYSBBdHVhbGl6YcOnw6NvJyxcbiAgICAgICAgdXBkYXRlZEFmdGVyOiAnRGVwb2lzIGRhIEF0dWFsaXphw6fDo28nLFxuICAgICAgICBkZWxldGVkOiAnSW5mb3JtYcOnw7VlcyBhbnRlcyBkZSByZW1vdmVyJ1xuICAgICAgfSxcbiAgICAgIGxvZ2luOiB7XG4gICAgICAgIHJlc2V0UGFzc3dvcmQ6IHtcbiAgICAgICAgICBkZXNjcmlwdGlvbjogJ0RpZ2l0ZSBhYmFpeG8gbyBlbWFpbCBjYWRhc3RyYWRvIG5vIHNpc3RlbWEuJ1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfSlcblxufSgpKTtcbiIsIi8qZXNsaW50IGFuZ3VsYXIvZmlsZS1uYW1lOiAwLCBuby11bmRlZjogMCovXG4oZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uc3RhbnQoJ3B0LUJSLmkxOG4uZ2xvYmFsJywge1xuICAgICAgbG9hZGluZzogJ0NhcnJlZ2FuZG8uLi4nLFxuICAgICAgcHJvY2Vzc2luZzogJ1Byb2Nlc3NhbmRvLi4uJyxcbiAgICAgIHllczogJ1NpbScsXG4gICAgICBubzogJ07Do28nLFxuICAgICAgYWxsOiAnVG9kb3MnXG4gICAgfSlcblxufSgpKTtcbiIsIi8qZXNsaW50IGFuZ3VsYXIvZmlsZS1uYW1lOiAwLCBuby11bmRlZjogMCovXG4oZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uc3RhbnQoJ3B0LUJSLmkxOG4ubWVzc2FnZXMnLCB7XG4gICAgICBpbnRlcm5hbEVycm9yOiAnT2NvcnJldSB1bSBlcnJvIGludGVybm8sIGNvbnRhdGUgbyBhZG1pbmlzdHJhZG9yIGRvIHNpc3RlbWEnLFxuICAgICAgbm90Rm91bmQ6ICdOZW5odW0gcmVnaXN0cm8gZW5jb250cmFkbycsXG4gICAgICBub3RBdXRob3JpemVkOiAnVm9jw6ogbsOjbyB0ZW0gYWNlc3NvIGEgZXN0YSBmdW5jaW9uYWxpZGFkZS4nLFxuICAgICAgc2VhcmNoRXJyb3I6ICdOw6NvIGZvaSBwb3Nzw612ZWwgcmVhbGl6YXIgYSBidXNjYS4nLFxuICAgICAgc2F2ZVN1Y2Nlc3M6ICdSZWdpc3RybyBzYWx2byBjb20gc3VjZXNzby4nLFxuICAgICAgb3BlcmF0aW9uU3VjY2VzczogJ09wZXJhw6fDo28gcmVhbGl6YWRhIGNvbSBzdWNlc3NvLicsXG4gICAgICBvcGVyYXRpb25FcnJvcjogJ0Vycm8gYW8gcmVhbGl6YXIgYSBvcGVyYcOnw6NvJyxcbiAgICAgIHNhdmVFcnJvcjogJ0Vycm8gYW8gdGVudGFyIHNhbHZhciBvIHJlZ2lzdHJvLicsXG4gICAgICByZW1vdmVTdWNjZXNzOiAnUmVtb8Onw6NvIHJlYWxpemFkYSBjb20gc3VjZXNzby4nLFxuICAgICAgcmVtb3ZlRXJyb3I6ICdFcnJvIGFvIHRlbnRhciByZW1vdmVyIG8gcmVnaXN0cm8uJyxcbiAgICAgIHJlc291cmNlTm90Rm91bmRFcnJvcjogJ1JlY3Vyc28gbsOjbyBlbmNvbnRyYWRvJyxcbiAgICAgIG5vdE51bGxFcnJvcjogJ1RvZG9zIG9zIGNhbXBvcyBvYnJpZ2F0w7NyaW9zIGRldmVtIHNlciBwcmVlbmNoaWRvcy4nLFxuICAgICAgZHVwbGljYXRlZFJlc291cmNlRXJyb3I6ICdKw6EgZXhpc3RlIHVtIHJlY3Vyc28gY29tIGVzc2FzIGluZm9ybWHDp8O1ZXMuJyxcbiAgICAgIHNwcmludEVuZGVkU3VjY2VzczogJ1NwcmludCBmaW5hbGl6YWRhIGNvbSBzdWNlc3NvJyxcbiAgICAgIHNwcmludEVuZGVkRXJyb3I6ICdFcnJvIGFvIGZpbmFsaXphciBhIHNwcmludCcsXG4gICAgICBzdWNjZXNzU2lnblVwOiAnQ2FkYXN0cm8gcmVhbGl6YWRvIGNvbSBzdWNlc3NvLiBVbSBlLW1haWwgZm9pIGVudmlhZG8gY29tIHNldXMgZGFkb3MgZGUgbG9naW4nLFxuICAgICAgZXJyb3JzU2lnblVwOiAnSG91dmUgdW0gZXJybyBhbyByZWFsaXphciBvIHNldSBjYWRhc3Ryby4gVGVudGUgbm92YW1lbnRlIG1haXMgdGFyZGUhJyxcbiAgICAgIHJlbGVhc2V0RW5kZWRTdWNjZXNzOiAnUmVsZWFzZSBmaW5hbGl6YWRhIGNvbSBzdWNlc3NvJyxcbiAgICAgIHJlbGVhc2VFbmRlZEVycm9yOiAnRXJybyBhbyBmaW5hbGl6YXIgYSByZWxlYXNlJyxcbiAgICAgIHByb2plY3RFbmRlZFN1Y2Nlc3M6ICdQcm9qZXRvIGZpbmFsaXphZG8gY29tIHN1Y2Vzc28nLFxuICAgICAgcHJvamVjdEVuZGVkRXJyb3I6ICdFcnJvIGFvIGZpbmFsaXphciBvIHByb2pldG8nLFxuICAgICAgdmFsaWRhdGU6IHtcbiAgICAgICAgZmllbGRSZXF1aXJlZDogJ08gY2FtcG8ge3tmaWVsZH19IMOpIG9icmlncmF0w7NyaW8uJ1xuICAgICAgfSxcbiAgICAgIGxheW91dDoge1xuICAgICAgICBlcnJvcjQwNDogJ1DDoWdpbmEgbsOjbyBlbmNvbnRyYWRhJ1xuICAgICAgfSxcbiAgICAgIGxvZ2luOiB7XG4gICAgICAgIGxvZ291dEluYWN0aXZlOiAnVm9jw6ogZm9pIGRlc2xvZ2FkbyBkbyBzaXN0ZW1hIHBvciBpbmF0aXZpZGFkZS4gRmF2b3IgZW50cmFyIG5vIHNpc3RlbWEgbm92YW1lbnRlLicsXG4gICAgICAgIGludmFsaWRDcmVkZW50aWFsczogJ0NyZWRlbmNpYWlzIEludsOhbGlkYXMnLFxuICAgICAgICB1bmtub3duRXJyb3I6ICdOw6NvIGZvaSBwb3Nzw612ZWwgcmVhbGl6YXIgbyBsb2dpbi4gVGVudGUgbm92YW1lbnRlLiAnICtcbiAgICAgICAgICAnQ2FzbyBuw6NvIGNvbnNpZ2EgZmF2b3IgZW5jb250cmFyIGVtIGNvbnRhdG8gY29tIG8gYWRtaW5pc3RyYWRvciBkbyBzaXN0ZW1hLicsXG4gICAgICAgIHVzZXJOb3RGb3VuZDogJ07Do28gZm9pIHBvc3PDrXZlbCBlbmNvbnRyYXIgc2V1cyBkYWRvcydcbiAgICAgIH0sXG4gICAgICBkYXNoYm9hcmQ6IHtcbiAgICAgICAgd2VsY29tZTogJ1NlamEgYmVtIFZpbmRvIHt7dXNlck5hbWV9fScsXG4gICAgICAgIGRlc2NyaXB0aW9uOiAnVXRpbGl6ZSBvIG1lbnUgcGFyYSBuYXZlZ2HDp8Ojby4nXG4gICAgICB9LFxuICAgICAgbWFpbDoge1xuICAgICAgICBtYWlsRXJyb3JzOiAnT2NvcnJldSB1bSBlcnJvIG5vcyBzZWd1aW50ZXMgZW1haWxzIGFiYWl4bzpcXG4nLFxuICAgICAgICBzZW5kTWFpbFN1Y2Nlc3M6ICdFbWFpbCBlbnZpYWRvIGNvbSBzdWNlc3NvIScsXG4gICAgICAgIHNlbmRNYWlsRXJyb3I6ICdOw6NvIGZvaSBwb3Nzw612ZWwgZW52aWFyIG8gZW1haWwuJyxcbiAgICAgICAgcGFzc3dvcmRTZW5kaW5nU3VjY2VzczogJ08gcHJvY2Vzc28gZGUgcmVjdXBlcmHDp8OjbyBkZSBzZW5oYSBmb2kgaW5pY2lhZG8uIENhc28gbyBlbWFpbCBuw6NvIGNoZWd1ZSBlbSAxMCBtaW51dG9zIHRlbnRlIG5vdmFtZW50ZS4nXG4gICAgICB9LFxuICAgICAgdXNlcjoge1xuICAgICAgICByZW1vdmVZb3VyU2VsZkVycm9yOiAnVm9jw6ogbsOjbyBwb2RlIHJlbW92ZXIgc2V1IHByw7NwcmlvIHVzdcOhcmlvJyxcbiAgICAgICAgdXNlckV4aXN0czogJ1VzdcOhcmlvIGrDoSBhZGljaW9uYWRvIScsXG4gICAgICAgIHByb2ZpbGU6IHtcbiAgICAgICAgICB1cGRhdGVFcnJvcjogJ07Do28gZm9pIHBvc3PDrXZlbCBhdHVhbGl6YXIgc2V1IHByb2ZpbGUnXG4gICAgICAgIH1cbiAgICAgIH0sXG4gICAgICBxdWVyeURpbmFtaWM6IHtcbiAgICAgICAgbm9GaWx0ZXI6ICdOZW5odW0gZmlsdHJvIGFkaWNpb25hZG8nXG4gICAgICB9XG4gICAgfSlcblxufSgpKTtcbiIsIi8qZXNsaW50IGFuZ3VsYXIvZmlsZS1uYW1lOiAwLCBuby11bmRlZjogMCovXG4oZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uc3RhbnQoJ3B0LUJSLmkxOG4ubW9kZWxzJywge1xuICAgICAgdXNlcjogJ1VzdcOhcmlvJyxcbiAgICAgIHRhc2s6ICdUYXJlZmEnLFxuICAgICAgcHJvamVjdDogJ1Byb2pldG8nXG4gICAgfSlcblxufSgpKTtcbiIsIi8qZXNsaW50IGFuZ3VsYXIvZmlsZS1uYW1lOiAwLCBuby11bmRlZjogMCovXG4oZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uc3RhbnQoJ3B0LUJSLmkxOG4udmlld3MnLCB7XG4gICAgICBicmVhZGNydW1iczoge1xuICAgICAgICB1c2VyOiAnQWRtaW5pc3RyYcOnw6NvIC0gVXN1w6FyaW8nLFxuICAgICAgICAndXNlci1wcm9maWxlJzogJ1BlcmZpbCcsXG4gICAgICAgIGRhc2hib2FyZDogJ0Rhc2hib2FyZCcsXG4gICAgICAgIGF1ZGl0OiAnQWRtaW5pc3RyYcOnw6NvIC0gQXVkaXRvcmlhJyxcbiAgICAgICAgbWFpbDogJ0FkbWluaXN0cmHDp8OjbyAtIEVudmlvIGRlIGUtbWFpbCcsXG4gICAgICAgIHByb2plY3RzOiAnUHJvamV0b3MnLFxuICAgICAgICAnZGluYW1pYy1xdWVyeSc6ICdBZG1pbmlzdHJhw6fDo28gLSBDb25zdWx0YXMgRGluw6JtaWNhcycsXG4gICAgICAgICdub3QtYXV0aG9yaXplZCc6ICdBY2Vzc28gTmVnYWRvJyxcbiAgICAgICAgdGFza3M6ICdUYXJlZmFzJyxcbiAgICAgICAgbWlsZXN0b25lczogJ1NwcmludHMnLFxuICAgICAgICBrYW5iYW46ICdLYW5iYW4gQm9hcmQnLFxuICAgICAgICB2Y3M6ICdDb250cm9sZSBkZSBWZXJzw6NvJyxcbiAgICAgICAgcmVsZWFzZXM6ICdSZWxlYXNlcydcbiAgICAgIH0sXG4gICAgICB0aXRsZXM6IHtcbiAgICAgICAgZGFzaGJvYXJkOiAnRGFzaGJvYXJkJyxcbiAgICAgICAgbWFpbFNlbmQ6ICdFbnZpYXIgZS1tYWlsJyxcbiAgICAgICAgdGFza0xpc3Q6ICdMaXN0YSBkZSBUYXJlZmFzJyxcbiAgICAgICAgdXNlckxpc3Q6ICdMaXN0YSBkZSBVc3XDoXJpb3MnLFxuICAgICAgICBhdWRpdExpc3Q6ICdMaXN0YSBkZSBMb2dzJyxcbiAgICAgICAgcmVnaXN0ZXI6ICdGb3JtdWzDoXJpbyBkZSBDYWRhc3RybycsXG4gICAgICAgIHJlc2V0UGFzc3dvcmQ6ICdSZWRlZmluaXIgU2VuaGEnLFxuICAgICAgICB1cGRhdGU6ICdGb3JtdWzDoXJpbyBkZSBBdHVhbGl6YcOnw6NvJyxcbiAgICAgICAgdGFza3M6ICdUYXJlZmFzJyxcbiAgICAgICAgbWlsZXN0b25lczogJ1NwcmludHMnLFxuICAgICAgICBrYW5iYW46ICdLYW5iYW4gQm9hcmQnLFxuICAgICAgICB2Y3M6ICdDb250cm9sZSBkZSBWZXJzw6NvJyxcbiAgICAgICAgcmVsZWFzZXM6ICdSZWxlYXNlcydcbiAgICAgIH0sXG4gICAgICBhY3Rpb25zOiB7XG4gICAgICAgIHNlbmQ6ICdFbnZpYXInLFxuICAgICAgICBzYXZlOiAnU2FsdmFyJyxcbiAgICAgICAgY2xlYXI6ICdMaW1wYXInLFxuICAgICAgICBjbGVhckFsbDogJ0xpbXBhciBUdWRvJyxcbiAgICAgICAgcmVzdGFydDogJ1JlaW5pY2lhcicsXG4gICAgICAgIGZpbHRlcjogJ0ZpbHRyYXInLFxuICAgICAgICBzZWFyY2g6ICdQZXNxdWlzYXInLFxuICAgICAgICBsaXN0OiAnTGlzdGFyJyxcbiAgICAgICAgZWRpdDogJ0VkaXRhcicsXG4gICAgICAgIGNhbmNlbDogJ0NhbmNlbGFyJyxcbiAgICAgICAgdXBkYXRlOiAnQXR1YWxpemFyJyxcbiAgICAgICAgcmVtb3ZlOiAnUmVtb3ZlcicsXG4gICAgICAgIGdldE91dDogJ1NhaXInLFxuICAgICAgICBhZGQ6ICdBZGljaW9uYXInLFxuICAgICAgICBpbjogJ0VudHJhcicsXG4gICAgICAgIGxvYWRJbWFnZTogJ0NhcnJlZ2FyIEltYWdlbScsXG4gICAgICAgIHNpZ251cDogJ0NhZGFzdHJhcicsXG4gICAgICAgIGNyaWFyUHJvamV0bzogJ0NyaWFyIFByb2pldG8nLFxuICAgICAgICBwcm9qZWN0TGlzdDogJ0xpc3RhIGRlIFByb2pldG9zJyxcbiAgICAgICAgdGFza3NMaXN0OiAnTGlzdGEgZGUgVGFyZWZhcycsXG4gICAgICAgIG1pbGVzdG9uZXNMaXN0OiAnTGlzdGEgZGUgU3ByaW50cycsXG4gICAgICAgIGZpbmFsaXplOiAnRmluYWxpemFyJyxcbiAgICAgICAgcmVwbHk6ICdSZXNwb25kZXInXG4gICAgICB9LFxuICAgICAgZmllbGRzOiB7XG4gICAgICAgIGRhdGU6ICdEYXRhJyxcbiAgICAgICAgYWN0aW9uOiAnQcOnw6NvJyxcbiAgICAgICAgYWN0aW9uczogJ0HDp8O1ZXMnLFxuICAgICAgICBhdWRpdDoge1xuICAgICAgICAgIGRhdGVTdGFydDogJ0RhdGEgSW5pY2lhbCcsXG4gICAgICAgICAgZGF0ZUVuZDogJ0RhdGEgRmluYWwnLFxuICAgICAgICAgIHJlc291cmNlOiAnUmVjdXJzbycsXG4gICAgICAgICAgYWxsUmVzb3VyY2VzOiAnVG9kb3MgUmVjdXJzb3MnLFxuICAgICAgICAgIHR5cGU6IHtcbiAgICAgICAgICAgIGNyZWF0ZWQ6ICdDYWRhc3RyYWRvJyxcbiAgICAgICAgICAgIHVwZGF0ZWQ6ICdBdHVhbGl6YWRvJyxcbiAgICAgICAgICAgIGRlbGV0ZWQ6ICdSZW1vdmlkbydcbiAgICAgICAgICB9XG4gICAgICAgIH0sXG4gICAgICAgIGxvZ2luOiB7XG4gICAgICAgICAgcmVzZXRQYXNzd29yZDogJ0VzcXVlY2kgbWluaGEgc2VuaGEnLFxuICAgICAgICAgIGNvbmZpcm1QYXNzd29yZDogJ0NvbmZpcm1hciBzZW5oYSdcbiAgICAgICAgfSxcbiAgICAgICAgbWFpbDoge1xuICAgICAgICAgIHRvOiAnUGFyYScsXG4gICAgICAgICAgc3ViamVjdDogJ0Fzc3VudG8nLFxuICAgICAgICAgIG1lc3NhZ2U6ICdNZW5zYWdlbSdcbiAgICAgICAgfSxcbiAgICAgICAgcXVlcnlEaW5hbWljOiB7XG4gICAgICAgICAgZmlsdGVyczogJ0ZpbHRyb3MnLFxuICAgICAgICAgIHJlc3VsdHM6ICdSZXN1bHRhZG9zJyxcbiAgICAgICAgICBtb2RlbDogJ01vZGVsJyxcbiAgICAgICAgICBhdHRyaWJ1dGU6ICdBdHJpYnV0bycsXG4gICAgICAgICAgb3BlcmF0b3I6ICdPcGVyYWRvcicsXG4gICAgICAgICAgcmVzb3VyY2U6ICdSZWN1cnNvJyxcbiAgICAgICAgICB2YWx1ZTogJ1ZhbG9yJyxcbiAgICAgICAgICBvcGVyYXRvcnM6IHtcbiAgICAgICAgICAgIGVxdWFsczogJ0lndWFsJyxcbiAgICAgICAgICAgIGRpZmVyZW50OiAnRGlmZXJlbnRlJyxcbiAgICAgICAgICAgIGNvbnRlaW5zOiAnQ29udMOpbScsXG4gICAgICAgICAgICBzdGFydFdpdGg6ICdJbmljaWEgY29tJyxcbiAgICAgICAgICAgIGZpbmlzaFdpdGg6ICdGaW5hbGl6YSBjb20nLFxuICAgICAgICAgICAgYmlnZ2VyVGhhbjogJ01haW9yJyxcbiAgICAgICAgICAgIGVxdWFsc09yQmlnZ2VyVGhhbjogJ01haW9yIG91IElndWFsJyxcbiAgICAgICAgICAgIGxlc3NUaGFuOiAnTWVub3InLFxuICAgICAgICAgICAgZXF1YWxzT3JMZXNzVGhhbjogJ01lbm9yIG91IElndWFsJ1xuICAgICAgICAgIH1cbiAgICAgICAgfSxcbiAgICAgICAgcHJvamVjdDoge1xuICAgICAgICAgIG5hbWU6ICdOb21lJyxcbiAgICAgICAgICB0b3RhbFRhc2s6ICdUb3RhbCBkZSBUYXJlZmFzJ1xuICAgICAgICB9LFxuICAgICAgICB0YXNrOiB7XG4gICAgICAgICAgZG9uZTogJ07Do28gRmVpdG8gLyBGZWl0bydcbiAgICAgICAgfSxcbiAgICAgICAgdXNlcjoge1xuICAgICAgICAgIHBlcmZpbHM6ICdQZXJmaXMnLFxuICAgICAgICAgIG5hbWVPckVtYWlsOiAnTm9tZSBvdSBFbWFpbCdcbiAgICAgICAgfVxuICAgICAgfSxcbiAgICAgIGxheW91dDoge1xuICAgICAgICBtZW51OiB7XG4gICAgICAgICAgcHJvamVjdHM6ICdQcm9qZXRvcycsXG4gICAgICAgICAgZGFzaGJvYXJkOiAnRGFzaGJvYXJkJyxcbiAgICAgICAgICBtaWxlc3RvbmVzOiAnU3ByaW50cycsXG4gICAgICAgICAgdGFza3M6ICdUYXJlZmFzJyxcbiAgICAgICAgICBrYW5iYW46ICdLYW5iYW4nLFxuICAgICAgICAgIHZjczogJ0NvbnRyb2xlIGRlIFZlcnPDo28nLFxuICAgICAgICAgIHJlbGVhc2VzOiAnUmVsZWFzZXMnXG4gICAgICAgIH1cbiAgICAgIH0sXG4gICAgICB0b29sdGlwczoge1xuICAgICAgICBhdWRpdDoge1xuICAgICAgICAgIHZpZXdEZXRhaWw6ICdWaXN1YWxpemFyIERldGFsaGFtZW50bydcbiAgICAgICAgfSxcbiAgICAgICAgdXNlcjoge1xuICAgICAgICAgIHBlcmZpbDogJ1BlcmZpbCcsXG4gICAgICAgICAgdHJhbnNmZXI6ICdUcmFuc2ZlcmlyJ1xuICAgICAgICB9LFxuICAgICAgICB0YXNrOiB7XG4gICAgICAgICAgbGlzdFRhc2s6ICdMaXN0YXIgVGFyZWZhcydcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pXG5cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb250cm9sbGVyKCdUYXNrSW5mb0NvbnRyb2xsZXInLCBUYXNrSW5mb0NvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gVGFza0luZm9Db250cm9sbGVyKCRjb250cm9sbGVyLCBUYXNrc1NlcnZpY2UsIGxvY2Fscykge1xuICAgIC8vQXR0cmlidXRlcyBCbG9ja1xuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICB2bS5jbG9zZURpYWxvZyA9IGNsb3NlRGlhbG9nO1xuXG4gICAgdm0ub25BY3RpdmF0ZSA9IGZ1bmN0aW9uKCkge1xuICAgICAgdm0udGFzayA9IGxvY2Fscy50YXNrO1xuICAgICAgdm0udGFzay5lc3RpbWF0ZWRfdGltZSA9IHZtLnRhc2suZXN0aW1hdGVkX3RpbWUudG9TdHJpbmcoKSArICcgaG9yYXMnO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGNsb3NlRGlhbG9nKCkge1xuICAgICAgdm0uY2xvc2UoKTtcbiAgICAgIGNvbnNvbGUubG9nKFwiZmVjaGFyXCIpO1xuICAgIH1cblxuICAgIC8vIGluc3RhbnRpYXRlIGJhc2UgY29udHJvbGxlclxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHsgdm06IHZtLCBtb2RlbFNlcnZpY2U6IFRhc2tzU2VydmljZSwgb3B0aW9uczogeyB9IH0pO1xuICB9XG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb250cm9sbGVyKCdVc2Vyc0RpYWxvZ0NvbnRyb2xsZXInLCBVc2Vyc0RpYWxvZ0NvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gVXNlcnNEaWFsb2dDb250cm9sbGVyKCRjb250cm9sbGVyLCBVc2Vyc1NlcnZpY2UsIFByRGlhbG9nLCAgLy8gTk9TT05BUlxuICAgIHVzZXJEaWFsb2dJbnB1dCwgb25Jbml0KSB7XG5cbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0ub25BY3RpdmF0ZSA9IG9uQWN0aXZhdGU7XG4gICAgdm0uYXBwbHlGaWx0ZXJzID0gYXBwbHlGaWx0ZXJzO1xuICAgIHZtLmNsb3NlID0gY2xvc2U7XG5cbiAgICBpZiAoYW5ndWxhci5pc0RlZmluZWQodXNlckRpYWxvZ0lucHV0KSkge1xuICAgICAgdm0udHJhbnNmZXJVc2VyID0gdXNlckRpYWxvZ0lucHV0LnRyYW5zZmVyVXNlckZuO1xuICAgIH1cblxuICAgIC8vIGluc3RhbnRpYXRlIGJhc2UgY29udHJvbGxlclxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHtcbiAgICAgIHZtOiB2bSxcbiAgICAgIG1vZGVsU2VydmljZTogVXNlcnNTZXJ2aWNlLFxuICAgICAgc2VhcmNoT25Jbml0OiBvbkluaXQsXG4gICAgICBvcHRpb25zOiB7XG4gICAgICAgIHBlclBhZ2U6IDVcbiAgICAgIH1cbiAgICB9KTtcblxuICAgIGZ1bmN0aW9uIG9uQWN0aXZhdGUoKSB7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMgPSB7fTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBhcHBseUZpbHRlcnMoKSB7XG4gICAgICByZXR1cm4gYW5ndWxhci5leHRlbmQodm0uZGVmYXVsdFF1ZXJ5RmlsdGVycywgdm0ucXVlcnlGaWx0ZXJzKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBjbG9zZSgpIHtcbiAgICAgIFByRGlhbG9nLmNsb3NlKCk7XG4gICAgfVxuXG4gIH1cblxufSkoKTtcbiJdLCJzb3VyY2VSb290IjoiL3NvdXJjZS8ifQ==
