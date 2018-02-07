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

  DashboardController.$inject = ["$controller", "$state", "DashboardsService", "ProjectsService", "moment"];
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
  function DashboardController($controller, $state, DashboardsService, ProjectsService, moment) {
    var vm = this;

    //Attributes Block

    //Functions Block
    vm.onActivate = onActivate;
    vm.applyFilters = applyFilters;
    vm.fixDate = fixDate;

    function onActivate() {
      var project = localStorage.getItem('project');

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

  KanbanController.$inject = ["$controller", "TasksService", "StatusService", "$mdDialog", "$document"];
  angular.module('app').controller('KanbanController', KanbanController);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function KanbanController($controller, TasksService, StatusService, $mdDialog, $document) {
    //Attributes Block
    var vm = this;
    var fields = [{ name: 'id', type: 'string' }, { name: 'status', map: 'state', type: 'string' }, { name: 'text', map: 'label', type: 'string' }, { name: 'tags', type: 'string' }];

    vm.onActivate = function () {
      vm.project = localStorage.getItem('project');
      vm.queryFilters = { project_id: vm.project };
    };

    vm.applyFilters = function (defaultQueryFilters) {
      return angular.extend(defaultQueryFilters, vm.queryFilters);
    };

    vm.afterSearch = function () {
      var columns = [];
      var tasks = [];

      StatusService.query().then(function (response) {
        response.forEach(function (status) {
          columns.push({ text: status.name, dataField: status.slug });
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
      TasksService.updateTaskByKanban({
        project_id: vm.project,
        id: event.args.itemId,
        oldColumn: event.args.oldColumn,
        newColumn: event.args.newColumn }).then(function () {});
    };

    vm.onItemClicked = function (event) {
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

  MilestonesController.$inject = ["$controller", "MilestonesService", "moment", "TasksService", "PrToast", "$translate", "$mdDialog"];
  angular.module('app').controller('MilestonesController', MilestonesController);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function MilestonesController($controller, MilestonesService, moment, TasksService, PrToast, $translate, $mdDialog) {

    var vm = this;

    vm.estimatedPrice = estimatedPrice;

    vm.onActivate = function () {
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
      RolesService.query().then(function (response) {
        vm.roles = response;
        if ($stateParams.obj === 'edit') {
          vm.cleanForm();
          vm.viewForm = true;
          vm.resource = $stateParams.resource;
          usersArray(vm.resource);
        } else {
          localStorage.removeItem('project');
          vm.queryFilters = { user_id: Auth.currentUser.id };
        }
      });
    }

    function applyFilters(defaultQueryFilters) {
      return angular.extend(defaultQueryFilters, vm.querylters);
    }

    function beforeSave() {
      vm.resource.owner = Auth.currentUser.id;
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

  ReleasesController.$inject = ["$controller", "ReleasesService", "MilestonesService", "PrToast", "moment", "$mdDialog", "$translate"];
  angular.module('app').controller('ReleasesController', ReleasesController);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function ReleasesController($controller, ReleasesService, MilestonesService, PrToast, moment, $mdDialog, $translate) {
    var vm = this;

    //Attributes Block

    //Functions Block
    vm.onActivate = function () {
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
          PrToast.success($translate.instant('messages.sprintEndedSuccess'));
          vm.search();
        }, function () {
          PrToast.Error($translate.instant('messages.sprintEndedError'));
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

  TasksController.$inject = ["$controller", "TasksService", "StatusService", "PrioritiesService", "TypesService", "TaskCommentsService", "moment", "Auth", "PrToast", "$translate", "$filter"];
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
  function TasksController($controller, TasksService, StatusService, PrioritiesService, TypesService, TaskCommentsService, moment, Auth, PrToast, $translate, $filter) {
    var vm = this;

    //Attributes Block

    //Functions Block
    vm.onActivate = onActivate;
    vm.applyFilters = applyFilters;
    vm.beforeSave = beforeSave;
    vm.beforeRemove = beforeRemove;

    function onActivate() {
      vm.currentUser = Auth.currentUser;
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImFwcGxpY2F0aW9uLmpzIiwiYXBwLmpzIiwiYXBwLmNvbmZpZy5qcyIsImFwcC5jb250cm9sbGVyLmpzIiwiYXBwLmV4dGVybmFsLmpzIiwiYXBwLmdsb2JhbC5qcyIsImFwcC5yb3V0ZXMuanMiLCJhcHAucnVuLmpzIiwiYXVkaXQvYXVkaXQuY29udHJvbGxlci5qcyIsImF1ZGl0L2F1ZGl0LnJvdXRlLmpzIiwiYXVkaXQvYXVkaXQuc2VydmljZS5qcyIsImF1dGgvYXV0aC5yb3V0ZS5qcyIsImF1dGgvYXV0aC5zZXJ2aWNlLmpzIiwiYXV0aC9sb2dpbi5jb250cm9sbGVyLmpzIiwiYXV0aC9wYXNzd29yZC5jb250cm9sbGVyLmpzIiwiY29yZS9iYXNlLnNlcnZpY2UuanMiLCJjb3JlL2NydWQuY29udHJvbGxlci5qcyIsImRhc2hib2FyZC9kYXNoYm9hcmQuY29udHJvbGxlci5qcyIsImRhc2hib2FyZC9kYXNoYm9hcmQucm91dGUuanMiLCJkYXNoYm9hcmQvZGFzaGJvYXJkLnNlcnZpY2UuanMiLCJkaW5hbWljLXF1ZXJ5cy9kaW5hbWljLXF1ZXJ5LnJvdXRlLmpzIiwiZGluYW1pYy1xdWVyeXMvZGluYW1pYy1xdWVyeS5zZXJ2aWNlLmpzIiwiZGluYW1pYy1xdWVyeXMvZGluYW1pYy1xdWVyeXMuY29udHJvbGxlci5qcyIsImkxOG4vbGFuZ3VhZ2UtbG9hZGVyLnNlcnZpY2UuanMiLCJpMThuL3QtYXR0ci5maWx0ZXIuanMiLCJpMThuL3QtYnJlYWRjcnVtYi5maWx0ZXIuanMiLCJpMThuL3QtbW9kZWwuZmlsdGVyLmpzIiwiaW50ZXJjZXB0b3JzL2F1dGhlbnRpY2F0aW9uLmxpc3RlbmVyLmpzIiwiaW50ZXJjZXB0b3JzL2F1dGhvcml6YXRpb24ubGlzdGVuZXIuanMiLCJpbnRlcmNlcHRvcnMvc3Bpbm5lci5pbnRlcmNlcHRvci5qcyIsImludGVyY2VwdG9ycy90b2tlbi5pbnRlcmNlcHRvci5qcyIsImludGVyY2VwdG9ycy92YWxpZGF0aW9uLmludGVyY2VwdG9yLmpzIiwia2FuYmFuL2thbmJhbi5jb250cm9sbGVyLmpzIiwia2FuYmFuL2thbmJhbi5yb3V0ZS5qcyIsImthbmJhbi9rYW5iYW4uc2VydmljZS5qcyIsImxheW91dC9tZW51LmNvbnRyb2xsZXIuanMiLCJtYWlsL21haWxzLmNvbnRyb2xsZXIuanMiLCJtYWlsL21haWxzLnJvdXRlLmpzIiwibWFpbC9tYWlscy5zZXJ2aWNlLmpzIiwibWlsZXN0b25lcy9taWxlc3RvbmVzLmNvbnRyb2xsZXIuanMiLCJtaWxlc3RvbmVzL21pbGVzdG9uZXMucm91dGUuanMiLCJtaWxlc3RvbmVzL21pbGVzdG9uZXMuc2VydmljZS5qcyIsInByaW9yaXRpZXMvcHJpb3JpdGllcy5zZXJ2aWNlLmpzIiwicHJvamVjdHMvcHJvamVjdHMuY29udHJvbGxlci5qcyIsInByb2plY3RzL3Byb2plY3RzLnJvdXRlLmpzIiwicHJvamVjdHMvcHJvamVjdHMuc2VydmljZS5qcyIsInJvbGVzL3JvbGVzLXN0ci5maWx0ZXIuanMiLCJyb2xlcy9yb2xlcy5zZXJ2aWNlLmpzIiwicmVsZWFzZXMvcmVsZWFzZXMuY29udHJvbGxlci5qcyIsInJlbGVhc2VzL3JlbGVhc2VzLnJvdXRlLmpzIiwicmVsZWFzZXMvcmVsZWFzZXMuc2VydmljZS5qcyIsInN0YXR1cy9zdGF0dXMuc2VydmljZS5qcyIsInN1cHBvcnQvc3VwcG9ydC5zZXJ2aWNlLmpzIiwidGFzay1jb21tZW50cy90YXNrLWNvbW1lbnRzLnNlcnZpY2UuanMiLCJ0YXNrcy90YXNrcy5jb250cm9sbGVyLmpzIiwidGFza3MvdGFza3Mucm91dGUuanMiLCJ0YXNrcy90YXNrcy5zZXJ2aWNlLmpzIiwidHlwZXMvdHlwZXMuc2VydmljZS5qcyIsInVzZXJzL3Byb2ZpbGUuY29udHJvbGxlci5qcyIsInVzZXJzL3VzZXJzLmNvbnRyb2xsZXIuanMiLCJ1c2Vycy91c2Vycy5yb3V0ZS5qcyIsInVzZXJzL3VzZXJzLnNlcnZpY2UuanMiLCJ2Y3MvdmNzLmNvbnRyb2xsZXIuanMiLCJ2Y3MvdmNzLnJvdXRlLmpzIiwidmNzL3Zjcy5zZXJ2aWNlLmpzIiwid2lkZ2V0cy9ib3guY29tcG9uZW50LmpzIiwid2lkZ2V0cy9jb250ZW50LWJvZHkuY29tcG9uZW50LmpzIiwid2lkZ2V0cy9jb250ZW50LWhlYWRlci5jb21wb25lbnQuanMiLCJhdWRpdC9maWx0ZXJzL2F1ZGl0LWRldGFpbC10aXRsZS5maWx0ZXIuanMiLCJhdWRpdC9maWx0ZXJzL2F1ZGl0LW1vZGVsLmZpbHRlci5qcyIsImF1ZGl0L2ZpbHRlcnMvYXVkaXQtdHlwZS5maWx0ZXIuanMiLCJhdWRpdC9maWx0ZXJzL2F1ZGl0LXZhbHVlLmZpbHRlci5qcyIsImkxOG4vcHQtQlIvYXR0cmlidXRlcy5qcyIsImkxOG4vcHQtQlIvZGlhbG9nLmpzIiwiaTE4bi9wdC1CUi9nbG9iYWwuanMiLCJpMThuL3B0LUJSL21lc3NhZ2VzLmpzIiwiaTE4bi9wdC1CUi9tb2RlbHMuanMiLCJpMThuL3B0LUJSL3ZpZXdzLmpzIiwia2FuYmFuL3Rhc2staW5mby1kaWFsb2cvdGFzay1pbmZvLmNvbnRyb2xsZXIuanMiLCJ1c2Vycy9kaWFsb2cvdXNlcnMtZGlhbG9nLmNvbnRyb2xsZXIuanMiXSwibmFtZXMiOlsiYW5ndWxhciIsIm1vZHVsZSIsImNvbmZpZyIsIkdsb2JhbCIsIiRtZFRoZW1pbmdQcm92aWRlciIsIiRtb2RlbEZhY3RvcnlQcm92aWRlciIsIiR0cmFuc2xhdGVQcm92aWRlciIsIm1vbWVudCIsIiRtZEFyaWFQcm92aWRlciIsIiRtZERhdGVMb2NhbGVQcm92aWRlciIsInVzZUxvYWRlciIsInVzZVNhbml0aXplVmFsdWVTdHJhdGVneSIsInVzZVBvc3RDb21waWxpbmciLCJsb2NhbGUiLCJkZWZhdWx0T3B0aW9ucyIsInByZWZpeCIsImFwaVBhdGgiLCJ0aGVtZSIsInByaW1hcnlQYWxldHRlIiwiZGVmYXVsdCIsImFjY2VudFBhbGV0dGUiLCJ3YXJuUGFsZXR0ZSIsImVuYWJsZUJyb3dzZXJDb2xvciIsImRpc2FibGVXYXJuaW5ncyIsImZvcm1hdERhdGUiLCJkYXRlIiwiZm9ybWF0IiwiY29udHJvbGxlciIsIkFwcENvbnRyb2xsZXIiLCIkc3RhdGUiLCJBdXRoIiwidm0iLCJhbm9BdHVhbCIsImFjdGl2ZVByb2plY3QiLCJsb2dvdXQiLCJnZXRJbWFnZVBlcmZpbCIsImdldExvZ29NZW51Iiwic2V0QWN0aXZlUHJvamVjdCIsImdldEFjdGl2ZVByb2plY3QiLCJyZW1vdmVBY3RpdmVQcm9qZWN0IiwiYWN0aXZhdGUiLCJEYXRlIiwiZ2V0RnVsbFllYXIiLCJ0aGVuIiwiZ28iLCJsb2dpblN0YXRlIiwiY3VycmVudFVzZXIiLCJpbWFnZSIsImltYWdlUGF0aCIsInByb2plY3QiLCJsb2NhbFN0b3JhZ2UiLCJzZXRJdGVtIiwiZ2V0SXRlbSIsInJlbW92ZUl0ZW0iLCJjb25zdGFudCIsIl8iLCJhcHBOYW1lIiwiaG9tZVN0YXRlIiwibG9naW5VcmwiLCJyZXNldFBhc3N3b3JkU3RhdGUiLCJub3RBdXRob3JpemVkU3RhdGUiLCJ0b2tlbktleSIsImNsaWVudFBhdGgiLCJyb3V0ZXMiLCIkc3RhdGVQcm92aWRlciIsIiR1cmxSb3V0ZXJQcm92aWRlciIsInN0YXRlIiwidXJsIiwidGVtcGxhdGVVcmwiLCJhYnN0cmFjdCIsInJlc29sdmUiLCJ0cmFuc2xhdGVSZWFkeSIsIiR0cmFuc2xhdGUiLCIkcSIsImRlZmVycmVkIiwiZGVmZXIiLCJ1c2UiLCJwcm9taXNlIiwiZGF0YSIsIm5lZWRBdXRoZW50aWNhdGlvbiIsIndoZW4iLCJvdGhlcndpc2UiLCJydW4iLCIkcm9vdFNjb3BlIiwiJHN0YXRlUGFyYW1zIiwiYXV0aCIsImdsb2JhbCIsInJldHJpZXZlVXNlckZyb21Mb2NhbFN0b3JhZ2UiLCJBdWRpdENvbnRyb2xsZXIiLCIkY29udHJvbGxlciIsIkF1ZGl0U2VydmljZSIsIlByRGlhbG9nIiwib25BY3RpdmF0ZSIsImFwcGx5RmlsdGVycyIsInZpZXdEZXRhaWwiLCJtb2RlbFNlcnZpY2UiLCJvcHRpb25zIiwibW9kZWxzIiwicXVlcnlGaWx0ZXJzIiwiZ2V0QXVkaXRlZE1vZGVscyIsImlkIiwibGFiZWwiLCJpbnN0YW50Iiwic29ydCIsImluZGV4IiwibGVuZ3RoIiwibW9kZWwiLCJwdXNoIiwidG9Mb3dlckNhc2UiLCJ0eXBlcyIsImxpc3RUeXBlcyIsInR5cGUiLCJkZWZhdWx0UXVlcnlGaWx0ZXJzIiwiZXh0ZW5kIiwiYXVkaXREZXRhaWwiLCJsb2NhbHMiLCJjbG9zZSIsImlzQXJyYXkiLCJvbGQiLCJuZXciLCJjb250cm9sbGVyQXMiLCJoYXNCYWNrZHJvcCIsImN1c3RvbSIsIm5lZWRQcm9maWxlIiwiZmFjdG9yeSIsInNlcnZpY2VGYWN0b3J5IiwiYWN0aW9ucyIsIm1ldGhvZCIsImluc3RhbmNlIiwiYXVkaXRQYXRoIiwiJGh0dHAiLCJVc2Vyc1NlcnZpY2UiLCJsb2dpbiIsInVwZGF0ZUN1cnJlbnRVc2VyIiwiYXV0aGVudGljYXRlZCIsInNlbmRFbWFpbFJlc2V0UGFzc3dvcmQiLCJyZW1vdGVWYWxpZGF0ZVRva2VuIiwiZ2V0VG9rZW4iLCJzZXRUb2tlbiIsImNsZWFyVG9rZW4iLCJ0b2tlbiIsImdldCIsInJlamVjdCIsInVzZXIiLCJtZXJnZSIsImZyb21Kc29uIiwianNvblVzZXIiLCJ0b0pzb24iLCJjcmVkZW50aWFscyIsInBvc3QiLCJyZXNwb25zZSIsImVycm9yIiwicmVzZXREYXRhIiwiTG9naW5Db250cm9sbGVyIiwib3BlbkRpYWxvZ1Jlc2V0UGFzcyIsIm9wZW5EaWFsb2dTaWduVXAiLCJlbWFpbCIsInBhc3N3b3JkIiwiUGFzc3dvcmRDb250cm9sbGVyIiwiJHRpbWVvdXQiLCJQclRvYXN0Iiwic2VuZFJlc2V0IiwiY2xvc2VEaWFsb2ciLCJjbGVhbkZvcm0iLCJyZXNldCIsInN1Y2Nlc3MiLCJzdGF0dXMiLCJtc2ciLCJpIiwidG9VcHBlckNhc2UiLCJmaWVsZCIsIm1lc3NhZ2UiLCIkbW9kZWxGYWN0b3J5IiwicGFnaW5hdGUiLCJ3cmFwIiwiYWZ0ZXJSZXF1ZXN0IiwiTGlzdCIsIkNSVURDb250cm9sbGVyIiwiUHJQYWdpbmF0aW9uIiwic2VhcmNoIiwicGFnaW5hdGVTZWFyY2giLCJub3JtYWxTZWFyY2giLCJlZGl0Iiwic2F2ZSIsInJlbW92ZSIsImdvVG8iLCJyZWRpcmVjdEFmdGVyU2F2ZSIsInNlYXJjaE9uSW5pdCIsInBlclBhZ2UiLCJza2lwUGFnaW5hdGlvbiIsInZpZXdGb3JtIiwicmVzb3VyY2UiLCJpc0Z1bmN0aW9uIiwicGFnaW5hdG9yIiwiZ2V0SW5zdGFuY2UiLCJwYWdlIiwiY3VycmVudFBhZ2UiLCJpc0RlZmluZWQiLCJiZWZvcmVTZWFyY2giLCJjYWxjTnVtYmVyT2ZQYWdlcyIsInRvdGFsIiwicmVzb3VyY2VzIiwiaXRlbXMiLCJhZnRlclNlYXJjaCIsInJlc3BvbnNlRGF0YSIsIm9uU2VhcmNoRXJyb3IiLCJxdWVyeSIsImZvcm0iLCJiZWZvcmVDbGVhbiIsIiRzZXRQcmlzdGluZSIsIiRzZXRVbnRvdWNoZWQiLCJhZnRlckNsZWFuIiwiY29weSIsImFmdGVyRWRpdCIsImJlZm9yZVNhdmUiLCIkc2F2ZSIsImFmdGVyU2F2ZSIsIm9uU2F2ZUVycm9yIiwidGl0bGUiLCJkZXNjcmlwdGlvbiIsImNvbmZpcm0iLCJiZWZvcmVSZW1vdmUiLCIkZGVzdHJveSIsImFmdGVyUmVtb3ZlIiwiaW5mbyIsInZpZXdOYW1lIiwib25WaWV3IiwiZmlsdGVyIiwidGltZSIsInBhcnNlIiwidGltZU5vdyIsImdldFRpbWUiLCJkaWZmZXJlbmNlIiwic2Vjb25kcyIsIk1hdGgiLCJmbG9vciIsIm1pbnV0ZXMiLCJob3VycyIsImRheXMiLCJtb250aHMiLCJEYXNoYm9hcmRDb250cm9sbGVyIiwiRGFzaGJvYXJkc1NlcnZpY2UiLCJQcm9qZWN0c1NlcnZpY2UiLCJmaXhEYXRlIiwicHJvamVjdF9pZCIsImFjdHVhbFByb2plY3QiLCJkYXRlU3RyaW5nIiwiZ29Ub1Byb2plY3QiLCJvYmoiLCJ0b3RhbENvc3QiLCJlc3RpbWF0ZWRfY29zdCIsInRhc2tzIiwiZm9yRWFjaCIsInRhc2siLCJwYXJzZUZsb2F0IiwiaG91cl92YWx1ZV9maW5hbCIsImVzdGltYXRlZF90aW1lIiwidG9Mb2NhbGVTdHJpbmciLCJtaW5pbXVtRnJhY3Rpb25EaWdpdHMiLCJEaW5hbWljUXVlcnlTZXJ2aWNlIiwiZ2V0TW9kZWxzIiwiRGluYW1pY1F1ZXJ5c0NvbnRyb2xsZXIiLCJsb2Rhc2giLCJsb2FkQXR0cmlidXRlcyIsImxvYWRPcGVyYXRvcnMiLCJhZGRGaWx0ZXIiLCJydW5GaWx0ZXIiLCJlZGl0RmlsdGVyIiwibG9hZE1vZGVscyIsInJlbW92ZUZpbHRlciIsImNsZWFyIiwicmVzdGFydCIsIndoZXJlIiwiYWRkZWRGaWx0ZXJzIiwibmFtZSIsImF0dHJpYnV0ZSIsIm9wZXJhdG9yIiwidmFsdWUiLCJmaWx0ZXJzIiwiYXR0cmlidXRlcyIsIm9wZXJhdG9ycyIsImluZGV4T2YiLCJpc1VuZGVmaW5lZCIsImtleXMiLCJPYmplY3QiLCJrZXkiLCJzdGFydHNXaXRoIiwiJGluZGV4Iiwic3BsaWNlIiwiTGFuZ3VhZ2VMb2FkZXIiLCJTdXBwb3J0U2VydmljZSIsIiRsb2ciLCIkaW5qZWN0b3IiLCJzZXJ2aWNlIiwidHJhbnNsYXRlIiwidmlld3MiLCJkaWFsb2ciLCJtZXNzYWdlcyIsImxhbmdzIiwidEF0dHIiLCIkZmlsdGVyIiwidEJyZWFkY3J1bWIiLCJzcGxpdCIsInRNb2RlbCIsImF1dGhlbnRpY2F0aW9uTGlzdGVuZXIiLCIkb24iLCJldmVudCIsInRvU3RhdGUiLCJjYXRjaCIsIndhcm4iLCJwcmV2ZW50RGVmYXVsdCIsImF1dGhvcml6YXRpb25MaXN0ZW5lciIsImhhc1Byb2ZpbGUiLCJhbGxQcm9maWxlcyIsInNwaW5uZXJJbnRlcmNlcHRvciIsIiRodHRwUHJvdmlkZXIiLCIkcHJvdmlkZSIsInNob3dIaWRlU3Bpbm5lciIsInJlcXVlc3QiLCJzaG93IiwiaGlkZSIsInJlc3BvbnNlRXJyb3IiLCJyZWplY3Rpb24iLCJpbnRlcmNlcHRvcnMiLCJ0b2tlbkludGVyY2VwdG9yIiwicmVkaXJlY3RXaGVuU2VydmVyTG9nZ2VkT3V0IiwiaGVhZGVycyIsInJlamVjdGlvblJlYXNvbnMiLCJ0b2tlbkVycm9yIiwiaXMiLCJ2YWxpZGF0aW9uSW50ZXJjZXB0b3IiLCJzaG93RXJyb3JWYWxpZGF0aW9uIiwic2tpcFZhbGlkYXRpb24iLCJlcnJvclZhbGlkYXRpb24iLCJLYW5iYW5Db250cm9sbGVyIiwiVGFza3NTZXJ2aWNlIiwiU3RhdHVzU2VydmljZSIsIiRtZERpYWxvZyIsIiRkb2N1bWVudCIsImZpZWxkcyIsIm1hcCIsImNvbHVtbnMiLCJ0ZXh0IiwiZGF0YUZpZWxkIiwic2x1ZyIsInRhZ3MiLCJwcmlvcml0eSIsInNvdXJjZSIsImxvY2FsRGF0YSIsImRhdGFUeXBlIiwiZGF0YUZpZWxkcyIsImRhdGFBZGFwdGVyIiwiJCIsImpxeCIsInNldHRpbmdzIiwia2FuYmFuUmVhZHkiLCJvbkl0ZW1Nb3ZlZCIsInVwZGF0ZVRhc2tCeUthbmJhbiIsImFyZ3MiLCJpdGVtSWQiLCJvbGRDb2x1bW4iLCJuZXdDb2x1bW4iLCJvbkl0ZW1DbGlja2VkIiwidGFza19pZCIsInRhc2tJbmZvIiwicGFyZW50IiwiZWxlbWVudCIsImJvZHkiLCJiaW5kVG9Db250cm9sbGVyIiwiZXNjYXBlVG9DbG9zZSIsImNsaWNrT3V0c2lkZVRvQ2xvc2UiLCJLYW5iYW5TZXJ2aWNlIiwiTWVudUNvbnRyb2xsZXIiLCIkbWRTaWRlbmF2IiwiJG1kQ29sb3JzIiwib3BlbiIsIm9wZW5NZW51T3JSZWRpcmVjdFRvU3RhdGUiLCJtZW51UHJlZml4IiwiaXRlbnNNZW51IiwiaWNvbiIsInN1Ykl0ZW5zIiwic2lkZW5hdlN0eWxlIiwidG9wIiwiY29udGVudCIsInRleHRDb2xvciIsImNvbG9yIiwibGluZUJvdHRvbSIsImdldENvbG9yIiwidG9nZ2xlIiwiJG1kTWVudSIsImV2IiwiaXRlbSIsImNvbG9yUGFsZXR0ZXMiLCJnZXRUaGVtZUNvbG9yIiwiTWFpbHNDb250cm9sbGVyIiwiTWFpbHNTZXJ2aWNlIiwiZmlsdGVyU2VsZWN0ZWQiLCJza2luIiwibGFuZ3VhZ2UiLCJhbGxvd2VkQ29udGVudCIsImVudGl0aWVzIiwiaGVpZ2h0IiwiZXh0cmFQbHVnaW5zIiwibG9hZFVzZXJzIiwib3BlblVzZXJEaWFsb2ciLCJhZGRVc2VyTWFpbCIsInNlbmQiLCJjcml0ZXJpYSIsIm5hbWVPckVtYWlsIiwibm90VXNlcnMiLCJtYWlsIiwidXNlcnMiLCJwcm9wZXJ0eSIsInRvU3RyaW5nIiwibGltaXQiLCJmaW5kIiwib25Jbml0IiwidXNlckRpYWxvZ0lucHV0IiwidHJhbnNmZXJVc2VyRm4iLCJNaWxlc3RvbmVzQ29udHJvbGxlciIsIk1pbGVzdG9uZXNTZXJ2aWNlIiwiZXN0aW1hdGVkUHJpY2UiLCJtaWxlc3RvbmUiLCJlc3RpbWF0ZWRfdmFsdWUiLCJlc3RpbWF0ZWRUaW1lIiwiZGF0ZUVuZCIsImRhdGVfZW5kIiwiZGF0ZUJlZ2luIiwiZGF0ZV9iZWdpbiIsImRpZmYiLCJjb2xvcl9lc3RpbWF0ZWRfdGltZSIsInZpZXciLCJjb25zb2xlIiwibG9nIiwic2VhcmNoVGFzayIsInRhc2tUZXJtIiwibWlsZXN0b25lU2VhcmNoIiwib25UYXNrQ2hhbmdlIiwiZmluZEluZGV4IiwicmVtb3ZlVGFzayIsInNsaWNlIiwic2F2ZVRhc2tzIiwidXBkYXRlTWlsZXN0b25lIiwibWlsZXN0b25lX2lkIiwiZmluYWxpemUiLCJ0ZXh0Q29udGVudCIsIm9rIiwiY2FuY2VsIiwiRXJyb3IiLCJ1cGRhdGVSZWxlYXNlIiwiUHJpb3JpdGllc1NlcnZpY2UiLCJQcm9qZWN0c0NvbnRyb2xsZXIiLCJSb2xlc1NlcnZpY2UiLCIkd2luZG93Iiwic2VhcmNoVXNlciIsImFkZFVzZXIiLCJyZW1vdmVVc2VyIiwidmlld1Byb2plY3QiLCJyb2xlcyIsInVzZXJzQXJyYXkiLCJ1c2VyX2lkIiwicXVlcnlsdGVycyIsIm93bmVyIiwidXNlck5hbWUiLCJjbGllbnRfaWQiLCJjbGllbnQiLCJyb2xlIiwiZGV2X2lkIiwiZGV2ZWxvcGVyIiwic3Rha2Vob2xkZXJfaWQiLCJzdGFrZWhvbGRlciIsImhpc3RvcnlCYWNrIiwiaGlzdG9yeSIsImJhY2siLCJwYXJhbXMiLCJyb2xlc1N0ciIsImpvaW4iLCJSZWxlYXNlc0NvbnRyb2xsZXIiLCJSZWxlYXNlc1NlcnZpY2UiLCJyZWxlYXNlIiwicmVsZWFzZV9pZCIsInNlYXJjaE1pbGVzdG9uZSIsIm1pbGVzdG9uZVRlcm0iLCJyZWxlYXNlU2VhcmNoIiwib25NaWxlc3RvbmVDaGFuZ2UiLCJtaWxlc3RvbmVzIiwicmVtb3ZlTWlsZXN0b25lIiwic2F2ZU1pbGVzdG9uZXMiLCJjYWNoZSIsIlRhc2tDb21tZW50c1NlcnZpY2UiLCJzYXZlVGFza0NvbW1lbnQiLCJyZW1vdmVUYXNrQ29tbWVudCIsIlRhc2tzQ29udHJvbGxlciIsIlR5cGVzU2VydmljZSIsInByaW9yaXRpZXMiLCJzYXZlQ29tbWVudCIsImNvbW1lbnQiLCJjb21tZW50X2lkIiwiYW5zd2VyIiwiY29tbWVudF90ZXh0IiwicmVtb3ZlQ29tbWVudCIsIlByb2ZpbGVDb250cm9sbGVyIiwidXBkYXRlIiwiYmlydGhkYXkiLCJ1cGRhdGVQcm9maWxlIiwiVXNlcnNDb250cm9sbGVyIiwiaGlkZURpYWxvZyIsInNhdmVOZXdVc2VyIiwiZGVmYXVsdHMiLCJvdmVycmlkZSIsImFsbCIsInVzZXJSb2xlcyIsImludGVyc2VjdGlvbiIsImlzQWRtaW4iLCJieXRlcyIsInByZWNpc2lvbiIsImlzTmFOIiwiaXNGaW5pdGUiLCJ1bml0cyIsIm51bWJlciIsInBvdyIsInRvRml4ZWQiLCJWY3NDb250cm9sbGVyIiwiVmNzU2VydmljZSIsInBhdGhzIiwidG9nZ2xlU3BsYXNoU2NyZWVuIiwidXNlcm5hbWUiLCJ1c2VybmFtZV9naXRodWIiLCJyZXBvIiwicmVwb19naXRodWIiLCJwYXRoIiwic29ydFJlc291cmNlcyIsImxvYWRpbmdfc2NyZWVuIiwiZmluaXNoIiwiYSIsImIiLCJvcGVuRmlsZU9yRGlyZWN0b3J5IiwicGxlYXNlV2FpdCIsImxvZ28iLCJiYWNrZ3JvdW5kQ29sb3IiLCJsb2FkaW5nSHRtbCIsImNvbXBvbmVudCIsInJlcGxhY2UiLCJ0cmFuc2NsdWRlIiwidG9vbGJhckJ1dHRvbnMiLCJmb290ZXJCdXR0b25zIiwiYmluZGluZ3MiLCJib3hUaXRsZSIsInRvb2xiYXJDbGFzcyIsInRvb2xiYXJCZ0NvbG9yIiwiJHRyYW5zY2x1ZGUiLCJjdHJsIiwiJG9uSW5pdCIsImxheW91dEFsaWduIiwiYXVkaXREZXRhaWxUaXRsZSIsImF1ZGl0TW9kZWwiLCJtb2RlbElkIiwiYXVkaXRUeXBlIiwidHlwZUlkIiwiYXVkaXRWYWx1ZSIsImlzRGF0ZSIsImVuZHNXaXRoIiwiTnVtYmVyIiwiaW5pdGlhbERhdGUiLCJmaW5hbERhdGUiLCJkb25lIiwic2NoZWR1bGVkX3RvIiwiZGF0ZV9zdGFydCIsImNvc3QiLCJob3VyVmFsdWVEZXZlbG9wZXIiLCJob3VyVmFsdWVDbGllbnQiLCJob3VyVmFsdWVGaW5hbCIsInJlbGVhc2VfZGF0ZSIsImNvbmZpcm1UaXRsZSIsImNvbmZpcm1EZXNjcmlwdGlvbiIsInJlbW92ZURlc2NyaXB0aW9uIiwiYXVkaXQiLCJjcmVhdGVkIiwidXBkYXRlZEJlZm9yZSIsInVwZGF0ZWRBZnRlciIsImRlbGV0ZWQiLCJyZXNldFBhc3N3b3JkIiwibG9hZGluZyIsInByb2Nlc3NpbmciLCJ5ZXMiLCJubyIsImludGVybmFsRXJyb3IiLCJub3RGb3VuZCIsIm5vdEF1dGhvcml6ZWQiLCJzZWFyY2hFcnJvciIsInNhdmVTdWNjZXNzIiwib3BlcmF0aW9uU3VjY2VzcyIsIm9wZXJhdGlvbkVycm9yIiwic2F2ZUVycm9yIiwicmVtb3ZlU3VjY2VzcyIsInJlbW92ZUVycm9yIiwicmVzb3VyY2VOb3RGb3VuZEVycm9yIiwibm90TnVsbEVycm9yIiwiZHVwbGljYXRlZFJlc291cmNlRXJyb3IiLCJzcHJpbnRFbmRlZFN1Y2Nlc3MiLCJzcHJpbnRFbmRlZEVycm9yIiwic3VjY2Vzc1NpZ25VcCIsImVycm9yc1NpZ25VcCIsInZhbGlkYXRlIiwiZmllbGRSZXF1aXJlZCIsImxheW91dCIsImVycm9yNDA0IiwibG9nb3V0SW5hY3RpdmUiLCJpbnZhbGlkQ3JlZGVudGlhbHMiLCJ1bmtub3duRXJyb3IiLCJ1c2VyTm90Rm91bmQiLCJkYXNoYm9hcmQiLCJ3ZWxjb21lIiwibWFpbEVycm9ycyIsInNlbmRNYWlsU3VjY2VzcyIsInNlbmRNYWlsRXJyb3IiLCJwYXNzd29yZFNlbmRpbmdTdWNjZXNzIiwicmVtb3ZlWW91clNlbGZFcnJvciIsInVzZXJFeGlzdHMiLCJwcm9maWxlIiwidXBkYXRlRXJyb3IiLCJxdWVyeURpbmFtaWMiLCJub0ZpbHRlciIsImJyZWFkY3J1bWJzIiwicHJvamVjdHMiLCJrYW5iYW4iLCJ2Y3MiLCJyZWxlYXNlcyIsInRpdGxlcyIsIm1haWxTZW5kIiwidGFza0xpc3QiLCJ1c2VyTGlzdCIsImF1ZGl0TGlzdCIsInJlZ2lzdGVyIiwiY2xlYXJBbGwiLCJsaXN0IiwiZ2V0T3V0IiwiYWRkIiwiaW4iLCJsb2FkSW1hZ2UiLCJzaWdudXAiLCJjcmlhclByb2pldG8iLCJwcm9qZWN0TGlzdCIsInRhc2tzTGlzdCIsIm1pbGVzdG9uZXNMaXN0IiwicmVwbHkiLCJhY3Rpb24iLCJkYXRlU3RhcnQiLCJhbGxSZXNvdXJjZXMiLCJ1cGRhdGVkIiwiY29uZmlybVBhc3N3b3JkIiwidG8iLCJzdWJqZWN0IiwicmVzdWx0cyIsImVxdWFscyIsImRpZmVyZW50IiwiY29udGVpbnMiLCJzdGFydFdpdGgiLCJmaW5pc2hXaXRoIiwiYmlnZ2VyVGhhbiIsImVxdWFsc09yQmlnZ2VyVGhhbiIsImxlc3NUaGFuIiwiZXF1YWxzT3JMZXNzVGhhbiIsInRvdGFsVGFzayIsInBlcmZpbHMiLCJtZW51IiwidG9vbHRpcHMiLCJwZXJmaWwiLCJ0cmFuc2ZlciIsImxpc3RUYXNrIiwiVGFza0luZm9Db250cm9sbGVyIiwiVXNlcnNEaWFsb2dDb250cm9sbGVyIiwidHJhbnNmZXJVc2VyIl0sIm1hcHBpbmdzIjoiQUFBQTs7O0FDQ0EsQ0FB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RzZELGFBQWEsWUFBVztNQUN6QjdELEdBQUc4TixPQUFPMUksT0FBTzBJO01BQ2pCOU4sR0FBRzhOLEtBQUtHLGlCQUFpQmpPLEdBQUc4TixLQUFLRyxlQUFlNkosYUFBYTs7O0lBRy9ELFNBQVMzUCxjQUFjO01BQ3JCbkksR0FBR3FGO01BQ0g0VCxRQUFRQyxJQUFJOzs7O0lBSWR4VixZQUFZLGtCQUFrQixFQUFFMUQsSUFBSUEsSUFBSWdFLGNBQWNnUCxjQUFjL08sU0FBUzs7O0E5RTRrSGpGOztBK0V2bUhBLENBQUMsWUFBVzs7RUFFVjs7O0VBRUFoRyxRQUNHQyxPQUFPLE9BQ1AwQixXQUFXLHlCQUF5Qm9vQjs7OztFQUl2QyxTQUFTQSxzQkFBc0J0a0IsYUFBYTBDLGNBQWN4QztFQUN4RHNVLGlCQUFpQkQsUUFBUTs7SUFFekIsSUFBSWpZLEtBQUs7O0lBRVRBLEdBQUc2RCxhQUFhQTtJQUNoQjdELEdBQUc4RCxlQUFlQTtJQUNsQjlELEdBQUdxRixRQUFRQTs7SUFFWCxJQUFJcEgsUUFBUXFNLFVBQVU0TixrQkFBa0I7TUFDdENsWSxHQUFHaW9CLGVBQWUvUCxnQkFBZ0JDOzs7O0lBSXBDelUsWUFBWSxrQkFBa0I7TUFDNUIxRCxJQUFJQTtNQUNKZ0UsY0FBY29DO01BQ2R3RCxjQUFjcU87TUFDZGhVLFNBQVM7UUFDUDRGLFNBQVM7Ozs7SUFJYixTQUFTaEcsYUFBYTtNQUNwQjdELEdBQUdtRSxlQUFlOzs7SUFHcEIsU0FBU0wsZUFBZTtNQUN0QixPQUFPN0YsUUFBUWlILE9BQU9sRixHQUFHaUYscUJBQXFCakYsR0FBR21FOzs7SUFHbkQsU0FBU2tCLFFBQVE7TUFDZnpCLFNBQVN5Qjs7O0tBMUNmIiwiZmlsZSI6ImFwcGxpY2F0aW9uLmpzIiwic291cmNlc0NvbnRlbnQiOlsiJ3VzZSBzdHJpY3QnO1xuXG4vKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCovXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcsIFsnbmdBbmltYXRlJywgJ25nQXJpYScsICd1aS5yb3V0ZXInLCAnbmdQcm9kZWInLCAndWkudXRpbHMubWFza3MnLCAndGV4dC1tYXNrJywgJ25nTWF0ZXJpYWwnLCAnbW9kZWxGYWN0b3J5JywgJ21kLmRhdGEudGFibGUnLCAnbmdNYXRlcmlhbERhdGVQaWNrZXInLCAncGFzY2FscHJlY2h0LnRyYW5zbGF0ZScsICdhbmd1bGFyRmlsZVVwbG9hZCcsICduZ01lc3NhZ2VzJywgJ2pxd2lkZ2V0cycsICd1aS5tYXNrJywgJ25nUm91dGUnXSk7XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbmZpZyhjb25maWcpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gY29uZmlnKEdsb2JhbCwgJG1kVGhlbWluZ1Byb3ZpZGVyLCAkbW9kZWxGYWN0b3J5UHJvdmlkZXIsIC8vIE5PU09OQVJcbiAgJHRyYW5zbGF0ZVByb3ZpZGVyLCBtb21lbnQsICRtZEFyaWFQcm92aWRlciwgJG1kRGF0ZUxvY2FsZVByb3ZpZGVyKSB7XG5cbiAgICAkdHJhbnNsYXRlUHJvdmlkZXIudXNlTG9hZGVyKCdsYW5ndWFnZUxvYWRlcicpLnVzZVNhbml0aXplVmFsdWVTdHJhdGVneSgnZXNjYXBlJyk7XG5cbiAgICAkdHJhbnNsYXRlUHJvdmlkZXIudXNlUG9zdENvbXBpbGluZyh0cnVlKTtcblxuICAgIG1vbWVudC5sb2NhbGUoJ3B0LUJSJyk7XG5cbiAgICAvL29zIHNlcnZpw6dvcyByZWZlcmVudGUgYW9zIG1vZGVscyB2YWkgdXRpbGl6YXIgY29tbyBiYXNlIG5hcyB1cmxzXG4gICAgJG1vZGVsRmFjdG9yeVByb3ZpZGVyLmRlZmF1bHRPcHRpb25zLnByZWZpeCA9IEdsb2JhbC5hcGlQYXRoO1xuXG4gICAgLy8gQ29uZmlndXJhdGlvbiB0aGVtZVxuICAgICRtZFRoZW1pbmdQcm92aWRlci50aGVtZSgnZGVmYXVsdCcpLnByaW1hcnlQYWxldHRlKCdncmV5Jywge1xuICAgICAgZGVmYXVsdDogJzgwMCdcbiAgICB9KS5hY2NlbnRQYWxldHRlKCdhbWJlcicpLndhcm5QYWxldHRlKCdkZWVwLW9yYW5nZScpO1xuXG4gICAgLy8gRW5hYmxlIGJyb3dzZXIgY29sb3JcbiAgICAkbWRUaGVtaW5nUHJvdmlkZXIuZW5hYmxlQnJvd3NlckNvbG9yKCk7XG5cbiAgICAkbWRBcmlhUHJvdmlkZXIuZGlzYWJsZVdhcm5pbmdzKCk7XG5cbiAgICAkbWREYXRlTG9jYWxlUHJvdmlkZXIuZm9ybWF0RGF0ZSA9IGZ1bmN0aW9uIChkYXRlKSB7XG4gICAgICByZXR1cm4gZGF0ZSA/IG1vbWVudChkYXRlKS5mb3JtYXQoJ0REL01NL1lZWVknKSA6ICcnO1xuICAgIH07XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb250cm9sbGVyKCdBcHBDb250cm9sbGVyJywgQXBwQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvKipcbiAgICogQ29udHJvbGFkb3IgcmVzcG9uc8OhdmVsIHBvciBmdW5jaW9uYWxpZGFkZXMgcXVlIHPDo28gYWNpb25hZGFzIGVtIHF1YWxxdWVyIHRlbGEgZG8gc2lzdGVtYVxuICAgKlxuICAgKi9cbiAgZnVuY3Rpb24gQXBwQ29udHJvbGxlcigkc3RhdGUsIEF1dGgsIEdsb2JhbCkge1xuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICAvL2FubyBhdHVhbCBwYXJhIHNlciBleGliaWRvIG5vIHJvZGFww6kgZG8gc2lzdGVtYVxuICAgIHZtLmFub0F0dWFsID0gbnVsbDtcbiAgICB2bS5hY3RpdmVQcm9qZWN0ID0gbnVsbDtcblxuICAgIHZtLmxvZ291dCA9IGxvZ291dDtcbiAgICB2bS5nZXRJbWFnZVBlcmZpbCA9IGdldEltYWdlUGVyZmlsO1xuICAgIHZtLmdldExvZ29NZW51ID0gZ2V0TG9nb01lbnU7XG4gICAgdm0uc2V0QWN0aXZlUHJvamVjdCA9IHNldEFjdGl2ZVByb2plY3Q7XG4gICAgdm0uZ2V0QWN0aXZlUHJvamVjdCA9IGdldEFjdGl2ZVByb2plY3Q7XG4gICAgdm0ucmVtb3ZlQWN0aXZlUHJvamVjdCA9IHJlbW92ZUFjdGl2ZVByb2plY3Q7XG5cbiAgICBhY3RpdmF0ZSgpO1xuXG4gICAgZnVuY3Rpb24gYWN0aXZhdGUoKSB7XG4gICAgICB2YXIgZGF0ZSA9IG5ldyBEYXRlKCk7XG5cbiAgICAgIHZtLmFub0F0dWFsID0gZGF0ZS5nZXRGdWxsWWVhcigpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGxvZ291dCgpIHtcbiAgICAgIEF1dGgubG9nb3V0KCkudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgICRzdGF0ZS5nbyhHbG9iYWwubG9naW5TdGF0ZSk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBnZXRJbWFnZVBlcmZpbCgpIHtcbiAgICAgIHJldHVybiBBdXRoLmN1cnJlbnRVc2VyICYmIEF1dGguY3VycmVudFVzZXIuaW1hZ2UgPyBBdXRoLmN1cnJlbnRVc2VyLmltYWdlIDogR2xvYmFsLmltYWdlUGF0aCArICcvbm9fYXZhdGFyLmdpZic7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gZ2V0TG9nb01lbnUoKSB7XG4gICAgICByZXR1cm4gR2xvYmFsLmltYWdlUGF0aCArICcvbG9nby12ZXJ0aWNhbC5wbmcnO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIHNldEFjdGl2ZVByb2plY3QocHJvamVjdCkge1xuICAgICAgbG9jYWxTdG9yYWdlLnNldEl0ZW0oJ3Byb2plY3QnLCBwcm9qZWN0KTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBnZXRBY3RpdmVQcm9qZWN0KCkge1xuICAgICAgcmV0dXJuIGxvY2FsU3RvcmFnZS5nZXRJdGVtKCdwcm9qZWN0Jyk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gcmVtb3ZlQWN0aXZlUHJvamVjdCgpIHtcbiAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKCdwcm9qZWN0Jyk7XG4gICAgfVxuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4vKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCwgbm8tdW5kZWY6IDAqL1xuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIC8qKlxuICAgKiBUcmFuc2Zvcm1hIGJpYmxpb3RlY2FzIGV4dGVybmFzIGVtIHNlcnZpw6dvcyBkbyBhbmd1bGFyIHBhcmEgc2VyIHBvc3PDrXZlbCB1dGlsaXphclxuICAgKiBhdHJhdsOpcyBkYSBpbmplw6fDo28gZGUgZGVwZW5kw6puY2lhXG4gICAqL1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25zdGFudCgnbG9kYXNoJywgXykuY29uc3RhbnQoJ21vbWVudCcsIG1vbWVudCk7XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbnN0YW50KCdHbG9iYWwnLCB7XG4gICAgYXBwTmFtZTogJ0ZyZWVsYWdpbGUnLFxuICAgIGhvbWVTdGF0ZTogJ2FwcC5wcm9qZWN0cycsXG4gICAgbG9naW5Vcmw6ICdhcHAvbG9naW4nLFxuICAgIGxvZ2luU3RhdGU6ICdhcHAubG9naW4nLFxuICAgIHJlc2V0UGFzc3dvcmRTdGF0ZTogJ2FwcC5wYXNzd29yZC1yZXNldCcsXG4gICAgbm90QXV0aG9yaXplZFN0YXRlOiAnYXBwLm5vdC1hdXRob3JpemVkJyxcbiAgICB0b2tlbktleTogJ3NlcnZlcl90b2tlbicsXG4gICAgY2xpZW50UGF0aDogJ2NsaWVudC9hcHAnLFxuICAgIGFwaVBhdGg6ICdhcGkvdjEnLFxuICAgIGltYWdlUGF0aDogJ2NsaWVudC9pbWFnZXMnXG4gIH0pO1xufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25maWcocm91dGVzKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvdXRlcygkc3RhdGVQcm92aWRlciwgJHVybFJvdXRlclByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnYXBwJywge1xuICAgICAgdXJsOiAnL2FwcCcsXG4gICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL2xheW91dC9hcHAuaHRtbCcsXG4gICAgICBhYnN0cmFjdDogdHJ1ZSxcbiAgICAgIHJlc29sdmU6IHsgLy9lbnN1cmUgbGFuZ3MgaXMgcmVhZHkgYmVmb3JlIHJlbmRlciB2aWV3XG4gICAgICAgIHRyYW5zbGF0ZVJlYWR5OiBbJyR0cmFuc2xhdGUnLCAnJHEnLCBmdW5jdGlvbiAoJHRyYW5zbGF0ZSwgJHEpIHtcbiAgICAgICAgICB2YXIgZGVmZXJyZWQgPSAkcS5kZWZlcigpO1xuXG4gICAgICAgICAgJHRyYW5zbGF0ZS51c2UoJ3B0LUJSJykudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICBkZWZlcnJlZC5yZXNvbHZlKCk7XG4gICAgICAgICAgfSk7XG5cbiAgICAgICAgICByZXR1cm4gZGVmZXJyZWQucHJvbWlzZTtcbiAgICAgICAgfV1cbiAgICAgIH1cbiAgICB9KS5zdGF0ZShHbG9iYWwubm90QXV0aG9yaXplZFN0YXRlLCB7XG4gICAgICB1cmw6ICcvYWNlc3NvLW5lZ2FkbycsXG4gICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL2xheW91dC9ub3QtYXV0aG9yaXplZC5odG1sJyxcbiAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiBmYWxzZSB9XG4gICAgfSk7XG5cbiAgICAkdXJsUm91dGVyUHJvdmlkZXIud2hlbignL2FwcCcsIEdsb2JhbC5sb2dpblVybCk7XG4gICAgJHVybFJvdXRlclByb3ZpZGVyLm90aGVyd2lzZShHbG9iYWwubG9naW5VcmwpO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLnJ1bihydW4pO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gcnVuKCRyb290U2NvcGUsICRzdGF0ZSwgJHN0YXRlUGFyYW1zLCBBdXRoLCBHbG9iYWwpIHtcbiAgICAvLyBOT1NPTkFSXG4gICAgLy9zZXRhZG8gbm8gcm9vdFNjb3BlIHBhcmEgcG9kZXIgc2VyIGFjZXNzYWRvIG5hcyB2aWV3cyBzZW0gcHJlZml4byBkZSBjb250cm9sbGVyXG4gICAgJHJvb3RTY29wZS4kc3RhdGUgPSAkc3RhdGU7XG4gICAgJHJvb3RTY29wZS4kc3RhdGVQYXJhbXMgPSAkc3RhdGVQYXJhbXM7XG4gICAgJHJvb3RTY29wZS5hdXRoID0gQXV0aDtcbiAgICAkcm9vdFNjb3BlLmdsb2JhbCA9IEdsb2JhbDtcblxuICAgIC8vbm8gaW5pY2lvIGNhcnJlZ2EgbyB1c3XDoXJpbyBkbyBsb2NhbHN0b3JhZ2UgY2FzbyBvIHVzdcOhcmlvIGVzdGFqYSBhYnJpbmRvIG8gbmF2ZWdhZG9yXG4gICAgLy9wYXJhIHZvbHRhciBhdXRlbnRpY2Fkb1xuICAgIEF1dGgucmV0cmlldmVVc2VyRnJvbUxvY2FsU3RvcmFnZSgpO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29udHJvbGxlcignQXVkaXRDb250cm9sbGVyJywgQXVkaXRDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIEF1ZGl0Q29udHJvbGxlcigkY29udHJvbGxlciwgQXVkaXRTZXJ2aWNlLCBQckRpYWxvZywgR2xvYmFsLCAkdHJhbnNsYXRlKSB7XG4gICAgLy8gTk9TT05BUlxuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICB2bS5vbkFjdGl2YXRlID0gb25BY3RpdmF0ZTtcbiAgICB2bS5hcHBseUZpbHRlcnMgPSBhcHBseUZpbHRlcnM7XG4gICAgdm0udmlld0RldGFpbCA9IHZpZXdEZXRhaWw7XG5cbiAgICAkY29udHJvbGxlcignQ1JVRENvbnRyb2xsZXInLCB7IHZtOiB2bSwgbW9kZWxTZXJ2aWNlOiBBdWRpdFNlcnZpY2UsIG9wdGlvbnM6IHt9IH0pO1xuXG4gICAgZnVuY3Rpb24gb25BY3RpdmF0ZSgpIHtcbiAgICAgIHZtLm1vZGVscyA9IFtdO1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0ge307XG5cbiAgICAgIC8vUGVnYSB0b2RvcyBvcyBtb2RlbHMgZG8gc2VydmVyIGUgbW9udGEgdW1hIGxpc3RhIHBybyBDb21ib0JveFxuICAgICAgQXVkaXRTZXJ2aWNlLmdldEF1ZGl0ZWRNb2RlbHMoKS50aGVuKGZ1bmN0aW9uIChkYXRhKSB7XG4gICAgICAgIHZhciBtb2RlbHMgPSBbeyBpZDogJycsIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ2dsb2JhbC5hbGwnKSB9XTtcblxuICAgICAgICBkYXRhLm1vZGVscy5zb3J0KCk7XG5cbiAgICAgICAgZm9yICh2YXIgaW5kZXggPSAwOyBpbmRleCA8IGRhdGEubW9kZWxzLmxlbmd0aDsgaW5kZXgrKykge1xuICAgICAgICAgIHZhciBtb2RlbCA9IGRhdGEubW9kZWxzW2luZGV4XTtcblxuICAgICAgICAgIG1vZGVscy5wdXNoKHtcbiAgICAgICAgICAgIGlkOiBtb2RlbCxcbiAgICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ21vZGVscy4nICsgbW9kZWwudG9Mb3dlckNhc2UoKSlcbiAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHZtLm1vZGVscyA9IG1vZGVscztcbiAgICAgICAgdm0ucXVlcnlGaWx0ZXJzLm1vZGVsID0gdm0ubW9kZWxzWzBdLmlkO1xuICAgICAgfSk7XG5cbiAgICAgIHZtLnR5cGVzID0gQXVkaXRTZXJ2aWNlLmxpc3RUeXBlcygpO1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzLnR5cGUgPSB2bS50eXBlc1swXS5pZDtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBhcHBseUZpbHRlcnMoZGVmYXVsdFF1ZXJ5RmlsdGVycykge1xuICAgICAgcmV0dXJuIGFuZ3VsYXIuZXh0ZW5kKGRlZmF1bHRRdWVyeUZpbHRlcnMsIHZtLnF1ZXJ5RmlsdGVycyk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gdmlld0RldGFpbChhdWRpdERldGFpbCkge1xuICAgICAgdmFyIGNvbmZpZyA9IHtcbiAgICAgICAgbG9jYWxzOiB7IGF1ZGl0RGV0YWlsOiBhdWRpdERldGFpbCB9LFxuICAgICAgICAvKiogQG5nSW5qZWN0ICovXG4gICAgICAgIGNvbnRyb2xsZXI6IGZ1bmN0aW9uIGNvbnRyb2xsZXIoYXVkaXREZXRhaWwsIFByRGlhbG9nKSB7XG4gICAgICAgICAgdmFyIHZtID0gdGhpcztcblxuICAgICAgICAgIHZtLmNsb3NlID0gY2xvc2U7XG5cbiAgICAgICAgICBhY3RpdmF0ZSgpO1xuXG4gICAgICAgICAgZnVuY3Rpb24gYWN0aXZhdGUoKSB7XG4gICAgICAgICAgICBpZiAoYW5ndWxhci5pc0FycmF5KGF1ZGl0RGV0YWlsLm9sZCkgJiYgYXVkaXREZXRhaWwub2xkLmxlbmd0aCA9PT0gMCkgYXVkaXREZXRhaWwub2xkID0gbnVsbDtcbiAgICAgICAgICAgIGlmIChhbmd1bGFyLmlzQXJyYXkoYXVkaXREZXRhaWwubmV3KSAmJiBhdWRpdERldGFpbC5uZXcubGVuZ3RoID09PSAwKSBhdWRpdERldGFpbC5uZXcgPSBudWxsO1xuXG4gICAgICAgICAgICB2bS5hdWRpdERldGFpbCA9IGF1ZGl0RGV0YWlsO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIGZ1bmN0aW9uIGNsb3NlKCkge1xuICAgICAgICAgICAgUHJEaWFsb2cuY2xvc2UoKTtcbiAgICAgICAgICB9XG4gICAgICAgIH0sXG4gICAgICAgIGNvbnRyb2xsZXJBczogJ2F1ZGl0RGV0YWlsQ3RybCcsXG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvYXVkaXQvYXVkaXQtZGV0YWlsLmh0bWwnLFxuICAgICAgICBoYXNCYWNrZHJvcDogdHJ1ZVxuICAgICAgfTtcblxuICAgICAgUHJEaWFsb2cuY3VzdG9tKGNvbmZpZyk7XG4gICAgfVxuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKlxuICAgKiBBcnF1aXZvIGRlIGNvbmZpZ3VyYcOnw6NvIGNvbSBhcyByb3RhcyBlc3BlY8OtZmljYXMgZGUgYXVkaXRvcmlhXG4gICAqXG4gICAqIEBwYXJhbSB7YW55fSAkc3RhdGVQcm92aWRlclxuICAgKiBAcGFyYW0ge2FueX0gR2xvYmFsXG4gICAqL1xuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvdXRlcygkc3RhdGVQcm92aWRlciwgR2xvYmFsKSB7XG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ2FwcC5hdWRpdCcsIHtcbiAgICAgIHVybDogJy9hdWRpdG9yaWEnLFxuICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9hdWRpdC9hdWRpdC5odG1sJyxcbiAgICAgIGNvbnRyb2xsZXI6ICdBdWRpdENvbnRyb2xsZXIgYXMgYXVkaXRDdHJsJyxcbiAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiB0cnVlLCBuZWVkUHJvZmlsZTogWydhZG1pbiddIH1cbiAgICB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5mYWN0b3J5KCdBdWRpdFNlcnZpY2UnLCBBdWRpdFNlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gQXVkaXRTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5LCAkdHJhbnNsYXRlKSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCdhdWRpdCcsIHtcbiAgICAgIGFjdGlvbnM6IHtcbiAgICAgICAgZ2V0QXVkaXRlZE1vZGVsczoge1xuICAgICAgICAgIG1ldGhvZDogJ0dFVCcsXG4gICAgICAgICAgdXJsOiAnbW9kZWxzJ1xuICAgICAgICB9XG4gICAgICB9LFxuICAgICAgaW5zdGFuY2U6IHt9LFxuICAgICAgbGlzdFR5cGVzOiBmdW5jdGlvbiBsaXN0VHlwZXMoKSB7XG4gICAgICAgIHZhciBhdWRpdFBhdGggPSAndmlld3MuZmllbGRzLmF1ZGl0Lic7XG5cbiAgICAgICAgcmV0dXJuIFt7IGlkOiAnJywgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudChhdWRpdFBhdGggKyAnYWxsUmVzb3VyY2VzJykgfSwgeyBpZDogJ2NyZWF0ZWQnLCBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KGF1ZGl0UGF0aCArICd0eXBlLmNyZWF0ZWQnKSB9LCB7IGlkOiAndXBkYXRlZCcsIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoYXVkaXRQYXRoICsgJ3R5cGUudXBkYXRlZCcpIH0sIHsgaWQ6ICdkZWxldGVkJywgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudChhdWRpdFBhdGggKyAndHlwZS5kZWxldGVkJykgfV07XG4gICAgICB9XG4gICAgfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqXG4gICAqIEFycXVpdm8gZGUgY29uZmlndXJhw6fDo28gY29tIGFzIHJvdGFzIGVzcGVjw61maWNhcyBkbyByZWN1cnNvIHVzZXJcbiAgICpcbiAgICogQHBhcmFtIHthbnl9ICRzdGF0ZVByb3ZpZGVyXG4gICAqIEBwYXJhbSB7YW55fSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZShHbG9iYWwucmVzZXRQYXNzd29yZFN0YXRlLCB7XG4gICAgICB1cmw6ICcvcGFzc3dvcmQvcmVzZXQvOnRva2VuJyxcbiAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvYXV0aC9yZXNldC1wYXNzLWZvcm0uaHRtbCcsXG4gICAgICBjb250cm9sbGVyOiAnUGFzc3dvcmRDb250cm9sbGVyIGFzIHBhc3NDdHJsJyxcbiAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiBmYWxzZSB9XG4gICAgfSkuc3RhdGUoR2xvYmFsLmxvZ2luU3RhdGUsIHtcbiAgICAgIHVybDogJy9sb2dpbicsXG4gICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL2F1dGgvbG9naW4uaHRtbCcsXG4gICAgICBjb250cm9sbGVyOiAnTG9naW5Db250cm9sbGVyIGFzIGxvZ2luQ3RybCcsXG4gICAgICBkYXRhOiB7IG5lZWRBdXRoZW50aWNhdGlvbjogZmFsc2UgfVxuICAgIH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZhY3RvcnkoJ0F1dGgnLCBBdXRoKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIEF1dGgoJGh0dHAsICRxLCBHbG9iYWwsIFVzZXJzU2VydmljZSkge1xuICAgIC8vIE5PU09OQVJcbiAgICB2YXIgYXV0aCA9IHtcbiAgICAgIGxvZ2luOiBsb2dpbixcbiAgICAgIGxvZ291dDogbG9nb3V0LFxuICAgICAgdXBkYXRlQ3VycmVudFVzZXI6IHVwZGF0ZUN1cnJlbnRVc2VyLFxuICAgICAgcmV0cmlldmVVc2VyRnJvbUxvY2FsU3RvcmFnZTogcmV0cmlldmVVc2VyRnJvbUxvY2FsU3RvcmFnZSxcbiAgICAgIGF1dGhlbnRpY2F0ZWQ6IGF1dGhlbnRpY2F0ZWQsXG4gICAgICBzZW5kRW1haWxSZXNldFBhc3N3b3JkOiBzZW5kRW1haWxSZXNldFBhc3N3b3JkLFxuICAgICAgcmVtb3RlVmFsaWRhdGVUb2tlbjogcmVtb3RlVmFsaWRhdGVUb2tlbixcbiAgICAgIGdldFRva2VuOiBnZXRUb2tlbixcbiAgICAgIHNldFRva2VuOiBzZXRUb2tlbixcbiAgICAgIGNsZWFyVG9rZW46IGNsZWFyVG9rZW4sXG4gICAgICBjdXJyZW50VXNlcjogbnVsbFxuICAgIH07XG5cbiAgICBmdW5jdGlvbiBjbGVhclRva2VuKCkge1xuICAgICAgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oR2xvYmFsLnRva2VuS2V5KTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBzZXRUb2tlbih0b2tlbikge1xuICAgICAgbG9jYWxTdG9yYWdlLnNldEl0ZW0oR2xvYmFsLnRva2VuS2V5LCB0b2tlbik7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gZ2V0VG9rZW4oKSB7XG4gICAgICByZXR1cm4gbG9jYWxTdG9yYWdlLmdldEl0ZW0oR2xvYmFsLnRva2VuS2V5KTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiByZW1vdGVWYWxpZGF0ZVRva2VuKCkge1xuICAgICAgdmFyIGRlZmVycmVkID0gJHEuZGVmZXIoKTtcblxuICAgICAgaWYgKGF1dGguYXV0aGVudGljYXRlZCgpKSB7XG4gICAgICAgICRodHRwLmdldChHbG9iYWwuYXBpUGF0aCArICcvYXV0aGVudGljYXRlL2NoZWNrJykudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgZGVmZXJyZWQucmVzb2x2ZSh0cnVlKTtcbiAgICAgICAgfSwgZnVuY3Rpb24gKCkge1xuICAgICAgICAgIGF1dGgubG9nb3V0KCk7XG5cbiAgICAgICAgICBkZWZlcnJlZC5yZWplY3QoZmFsc2UpO1xuICAgICAgICB9KTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIGF1dGgubG9nb3V0KCk7XG5cbiAgICAgICAgZGVmZXJyZWQucmVqZWN0KGZhbHNlKTtcbiAgICAgIH1cblxuICAgICAgcmV0dXJuIGRlZmVycmVkLnByb21pc2U7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogVmVyaWZpY2Egc2UgbyB1c3XDoXJpbyBlc3TDoSBhdXRlbnRpY2Fkb1xuICAgICAqXG4gICAgICogQHJldHVybnMge2Jvb2xlYW59XG4gICAgICovXG4gICAgZnVuY3Rpb24gYXV0aGVudGljYXRlZCgpIHtcbiAgICAgIHJldHVybiBhdXRoLmdldFRva2VuKCkgIT09IG51bGw7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVjdXBlcmEgbyB1c3XDoXJpbyBkbyBsb2NhbFN0b3JhZ2VcbiAgICAgKi9cbiAgICBmdW5jdGlvbiByZXRyaWV2ZVVzZXJGcm9tTG9jYWxTdG9yYWdlKCkge1xuICAgICAgdmFyIHVzZXIgPSBsb2NhbFN0b3JhZ2UuZ2V0SXRlbSgndXNlcicpO1xuXG4gICAgICBpZiAodXNlcikge1xuICAgICAgICBhdXRoLmN1cnJlbnRVc2VyID0gYW5ndWxhci5tZXJnZShuZXcgVXNlcnNTZXJ2aWNlKCksIGFuZ3VsYXIuZnJvbUpzb24odXNlcikpO1xuICAgICAgfVxuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEd1YXJkYSBvIHVzdcOhcmlvIG5vIGxvY2FsU3RvcmFnZSBwYXJhIGNhc28gbyB1c3XDoXJpbyBmZWNoZSBlIGFicmEgbyBuYXZlZ2Fkb3JcbiAgICAgKiBkZW50cm8gZG8gdGVtcG8gZGUgc2Vzc8OjbyBzZWphIHBvc3PDrXZlbCByZWN1cGVyYXIgbyB0b2tlbiBhdXRlbnRpY2Fkby5cbiAgICAgKlxuICAgICAqIE1hbnTDqW0gYSB2YXJpw6F2ZWwgYXV0aC5jdXJyZW50VXNlciBwYXJhIGZhY2lsaXRhciBvIGFjZXNzbyBhbyB1c3XDoXJpbyBsb2dhZG8gZW0gdG9kYSBhIGFwbGljYcOnw6NvXG4gICAgICpcbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSB1c2VyIFVzdcOhcmlvIGEgc2VyIGF0dWFsaXphZG8uIENhc28gc2VqYSBwYXNzYWRvIG51bGwgbGltcGFcbiAgICAgKiB0b2RhcyBhcyBpbmZvcm1hw6fDtWVzIGRvIHVzdcOhcmlvIGNvcnJlbnRlLlxuICAgICAqL1xuICAgIGZ1bmN0aW9uIHVwZGF0ZUN1cnJlbnRVc2VyKHVzZXIpIHtcbiAgICAgIHZhciBkZWZlcnJlZCA9ICRxLmRlZmVyKCk7XG5cbiAgICAgIGlmICh1c2VyKSB7XG4gICAgICAgIHVzZXIgPSBhbmd1bGFyLm1lcmdlKG5ldyBVc2Vyc1NlcnZpY2UoKSwgdXNlcik7XG5cbiAgICAgICAgdmFyIGpzb25Vc2VyID0gYW5ndWxhci50b0pzb24odXNlcik7XG5cbiAgICAgICAgbG9jYWxTdG9yYWdlLnNldEl0ZW0oJ3VzZXInLCBqc29uVXNlcik7XG4gICAgICAgIGF1dGguY3VycmVudFVzZXIgPSB1c2VyO1xuXG4gICAgICAgIGRlZmVycmVkLnJlc29sdmUodXNlcik7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbSgndXNlcicpO1xuICAgICAgICBhdXRoLmN1cnJlbnRVc2VyID0gbnVsbDtcbiAgICAgICAgYXV0aC5jbGVhclRva2VuKCk7XG5cbiAgICAgICAgZGVmZXJyZWQucmVqZWN0KCk7XG4gICAgICB9XG5cbiAgICAgIHJldHVybiBkZWZlcnJlZC5wcm9taXNlO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWxpemEgbyBsb2dpbiBkbyB1c3XDoXJpb1xuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IGNyZWRlbnRpYWxzIEVtYWlsIGUgU2VuaGEgZG8gdXN1w6FyaW9cbiAgICAgKiBAcmV0dXJucyB7cHJvbWlzZX0gVW1hIHByb21pc2UgY29tIG8gcmVzdWx0YWRvIGRvIGNoYW1hZGEgbm8gYmFja2VuZFxuICAgICAqL1xuICAgIGZ1bmN0aW9uIGxvZ2luKGNyZWRlbnRpYWxzKSB7XG4gICAgICB2YXIgZGVmZXJyZWQgPSAkcS5kZWZlcigpO1xuXG4gICAgICAkaHR0cC5wb3N0KEdsb2JhbC5hcGlQYXRoICsgJy9hdXRoZW50aWNhdGUnLCBjcmVkZW50aWFscykudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgYXV0aC5zZXRUb2tlbihyZXNwb25zZS5kYXRhLnRva2VuKTtcblxuICAgICAgICByZXR1cm4gJGh0dHAuZ2V0KEdsb2JhbC5hcGlQYXRoICsgJy9hdXRoZW50aWNhdGUvdXNlcicpO1xuICAgICAgfSkudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgYXV0aC51cGRhdGVDdXJyZW50VXNlcihyZXNwb25zZS5kYXRhLnVzZXIpO1xuXG4gICAgICAgIGRlZmVycmVkLnJlc29sdmUoKTtcbiAgICAgIH0sIGZ1bmN0aW9uIChlcnJvcikge1xuICAgICAgICBhdXRoLmxvZ291dCgpO1xuXG4gICAgICAgIGRlZmVycmVkLnJlamVjdChlcnJvcik7XG4gICAgICB9KTtcblxuICAgICAgcmV0dXJuIGRlZmVycmVkLnByb21pc2U7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogRGVzbG9nYSBvcyB1c3XDoXJpb3MuIENvbW8gbsOjbyB0ZW4gbmVuaHVtYSBpbmZvcm1hw6fDo28gbmEgc2Vzc8OjbyBkbyBzZXJ2aWRvclxuICAgICAqIGUgdW0gdG9rZW4gdW1hIHZleiBnZXJhZG8gbsOjbyBwb2RlLCBwb3IgcGFkcsOjbywgc2VyIGludmFsaWRhZG8gYW50ZXMgZG8gc2V1IHRlbXBvIGRlIGV4cGlyYcOnw6NvLFxuICAgICAqIHNvbWVudGUgYXBhZ2Ftb3Mgb3MgZGFkb3MgZG8gdXN1w6FyaW8gZSBvIHRva2VuIGRvIG5hdmVnYWRvciBwYXJhIGVmZXRpdmFyIG8gbG9nb3V0LlxuICAgICAqXG4gICAgICogQHJldHVybnMge3Byb21pc2V9IFVtYSBwcm9taXNlIGNvbSBvIHJlc3VsdGFkbyBkYSBvcGVyYcOnw6NvXG4gICAgICovXG4gICAgZnVuY3Rpb24gbG9nb3V0KCkge1xuICAgICAgdmFyIGRlZmVycmVkID0gJHEuZGVmZXIoKTtcblxuICAgICAgYXV0aC51cGRhdGVDdXJyZW50VXNlcihudWxsKTtcbiAgICAgIGRlZmVycmVkLnJlc29sdmUoKTtcblxuICAgICAgcmV0dXJuIGRlZmVycmVkLnByb21pc2U7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogRW52aWEgdW0gZW1haWwgcGFyYSByZWN1cGVyYcOnw6NvIGRlIHNlbmhhXG4gICAgICogQHBhcmFtIHtPYmplY3R9IHJlc2V0RGF0YSAtIE9iamV0byBjb250ZW5kbyBvIGVtYWlsXG4gICAgICogQHJldHVybiB7UHJvbWlzZX0gLSBSZXRvcm5hIHVtYSBwcm9taXNlIHBhcmEgc2VyIHJlc29sdmlkYVxuICAgICAqL1xuICAgIGZ1bmN0aW9uIHNlbmRFbWFpbFJlc2V0UGFzc3dvcmQocmVzZXREYXRhKSB7XG4gICAgICB2YXIgZGVmZXJyZWQgPSAkcS5kZWZlcigpO1xuXG4gICAgICAkaHR0cC5wb3N0KEdsb2JhbC5hcGlQYXRoICsgJy9wYXNzd29yZC9lbWFpbCcsIHJlc2V0RGF0YSkudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgZGVmZXJyZWQucmVzb2x2ZShyZXNwb25zZS5kYXRhKTtcbiAgICAgIH0sIGZ1bmN0aW9uIChlcnJvcikge1xuICAgICAgICBkZWZlcnJlZC5yZWplY3QoZXJyb3IpO1xuICAgICAgfSk7XG5cbiAgICAgIHJldHVybiBkZWZlcnJlZC5wcm9taXNlO1xuICAgIH1cblxuICAgIHJldHVybiBhdXRoO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29udHJvbGxlcignTG9naW5Db250cm9sbGVyJywgTG9naW5Db250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIExvZ2luQ29udHJvbGxlcigkc3RhdGUsIEF1dGgsIEdsb2JhbCwgUHJEaWFsb2cpIHtcbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0ubG9naW4gPSBsb2dpbjtcbiAgICB2bS5vcGVuRGlhbG9nUmVzZXRQYXNzID0gb3BlbkRpYWxvZ1Jlc2V0UGFzcztcbiAgICB2bS5vcGVuRGlhbG9nU2lnblVwID0gb3BlbkRpYWxvZ1NpZ25VcDtcblxuICAgIGFjdGl2YXRlKCk7XG5cbiAgICBmdW5jdGlvbiBhY3RpdmF0ZSgpIHtcbiAgICAgIHZtLmNyZWRlbnRpYWxzID0ge307XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gbG9naW4oKSB7XG4gICAgICB2YXIgY3JlZGVudGlhbHMgPSB7XG4gICAgICAgIGVtYWlsOiB2bS5jcmVkZW50aWFscy5lbWFpbCxcbiAgICAgICAgcGFzc3dvcmQ6IHZtLmNyZWRlbnRpYWxzLnBhc3N3b3JkXG4gICAgICB9O1xuXG4gICAgICBBdXRoLmxvZ2luKGNyZWRlbnRpYWxzKS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgJHN0YXRlLmdvKEdsb2JhbC5ob21lU3RhdGUpO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogRXhpYmUgbyBkaWFsb2cgcGFyYSByZWN1cGVyYcOnw6NvIGRlIHNlbmhhXG4gICAgICovXG4gICAgZnVuY3Rpb24gb3BlbkRpYWxvZ1Jlc2V0UGFzcygpIHtcbiAgICAgIHZhciBjb25maWcgPSB7XG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvYXV0aC9zZW5kLXJlc2V0LWRpYWxvZy5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ1Bhc3N3b3JkQ29udHJvbGxlciBhcyBwYXNzQ3RybCcsXG4gICAgICAgIGhhc0JhY2tkcm9wOiB0cnVlXG4gICAgICB9O1xuXG4gICAgICBQckRpYWxvZy5jdXN0b20oY29uZmlnKTtcbiAgICB9XG4gICAgLyoqXG4gICAgICogRXhpYmUgbyBkaWFsb2cgcGFyYSByZWN1cGVyYcOnw6NvIGRlIHNlbmhhXG4gICAgICovXG4gICAgZnVuY3Rpb24gb3BlbkRpYWxvZ1NpZ25VcCgpIHtcbiAgICAgIHZhciBjb25maWcgPSB7XG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvdXNlcnMvdXNlci1mb3JtLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnVXNlcnNDb250cm9sbGVyIGFzIHVzZXJzQ3RybCcsXG4gICAgICAgIGhhc0JhY2tkcm9wOiB0cnVlXG4gICAgICB9O1xuXG4gICAgICBQckRpYWxvZy5jdXN0b20oY29uZmlnKTtcbiAgICB9XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb250cm9sbGVyKCdQYXNzd29yZENvbnRyb2xsZXInLCBQYXNzd29yZENvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gUGFzc3dvcmRDb250cm9sbGVyKEdsb2JhbCwgJHN0YXRlUGFyYW1zLCAkaHR0cCwgJHRpbWVvdXQsICRzdGF0ZSwgLy8gTk9TT05BUlxuICBQclRvYXN0LCBQckRpYWxvZywgQXV0aCwgJHRyYW5zbGF0ZSkge1xuXG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIHZtLnNlbmRSZXNldCA9IHNlbmRSZXNldDtcbiAgICB2bS5jbG9zZURpYWxvZyA9IGNsb3NlRGlhbG9nO1xuICAgIHZtLmNsZWFuRm9ybSA9IGNsZWFuRm9ybTtcbiAgICB2bS5zZW5kRW1haWxSZXNldFBhc3N3b3JkID0gc2VuZEVtYWlsUmVzZXRQYXNzd29yZDtcblxuICAgIGFjdGl2YXRlKCk7XG5cbiAgICBmdW5jdGlvbiBhY3RpdmF0ZSgpIHtcbiAgICAgIHZtLnJlc2V0ID0geyBlbWFpbDogJycsIHRva2VuOiAkc3RhdGVQYXJhbXMudG9rZW4gfTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFsaXphIGEgYWx0ZXJhw6fDo28gZGEgc2VuaGEgZG8gdXN1w6FyaW8gZSBvIHJlZGlyZWNpb25hIHBhcmEgYSB0ZWxhIGRlIGxvZ2luXG4gICAgICovXG4gICAgZnVuY3Rpb24gc2VuZFJlc2V0KCkge1xuICAgICAgJGh0dHAucG9zdChHbG9iYWwuYXBpUGF0aCArICcvcGFzc3dvcmQvcmVzZXQnLCB2bS5yZXNldCkudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgIFByVG9hc3Quc3VjY2VzcygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLm9wZXJhdGlvblN1Y2Nlc3MnKSk7XG4gICAgICAgICR0aW1lb3V0KGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAkc3RhdGUuZ28oR2xvYmFsLmxvZ2luU3RhdGUpO1xuICAgICAgICB9LCAxNTAwKTtcbiAgICAgIH0sIGZ1bmN0aW9uIChlcnJvcikge1xuICAgICAgICBpZiAoZXJyb3Iuc3RhdHVzICE9PSA0MDAgJiYgZXJyb3Iuc3RhdHVzICE9PSA1MDApIHtcbiAgICAgICAgICB2YXIgbXNnID0gJyc7XG5cbiAgICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IGVycm9yLmRhdGEucGFzc3dvcmQubGVuZ3RoOyBpKyspIHtcbiAgICAgICAgICAgIG1zZyArPSBlcnJvci5kYXRhLnBhc3N3b3JkW2ldICsgJzxicj4nO1xuICAgICAgICAgIH1cbiAgICAgICAgICBQclRvYXN0LmVycm9yKG1zZy50b1VwcGVyQ2FzZSgpKTtcbiAgICAgICAgfVxuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogRW52aWEgdW0gZW1haWwgZGUgcmVjdXBlcmHDp8OjbyBkZSBzZW5oYSBjb20gbyB0b2tlbiBkbyB1c3XDoXJpb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIHNlbmRFbWFpbFJlc2V0UGFzc3dvcmQoKSB7XG5cbiAgICAgIGlmICh2bS5yZXNldC5lbWFpbCA9PT0gJycpIHtcbiAgICAgICAgUHJUb2FzdC5lcnJvcigkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnZhbGlkYXRlLmZpZWxkUmVxdWlyZWQnLCB7IGZpZWxkOiAnZW1haWwnIH0pKTtcbiAgICAgICAgcmV0dXJuO1xuICAgICAgfVxuXG4gICAgICBBdXRoLnNlbmRFbWFpbFJlc2V0UGFzc3dvcmQodm0ucmVzZXQpLnRoZW4oZnVuY3Rpb24gKGRhdGEpIHtcbiAgICAgICAgUHJUb2FzdC5zdWNjZXNzKGRhdGEubWVzc2FnZSk7XG5cbiAgICAgICAgdm0uY2xlYW5Gb3JtKCk7XG4gICAgICAgIHZtLmNsb3NlRGlhbG9nKCk7XG4gICAgICB9LCBmdW5jdGlvbiAoZXJyb3IpIHtcbiAgICAgICAgaWYgKGVycm9yLmRhdGEuZW1haWwgJiYgZXJyb3IuZGF0YS5lbWFpbC5sZW5ndGggPiAwKSB7XG4gICAgICAgICAgdmFyIG1zZyA9ICcnO1xuXG4gICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCBlcnJvci5kYXRhLmVtYWlsLmxlbmd0aDsgaSsrKSB7XG4gICAgICAgICAgICBtc2cgKz0gZXJyb3IuZGF0YS5lbWFpbFtpXSArICc8YnI+JztcbiAgICAgICAgICB9XG5cbiAgICAgICAgICBQclRvYXN0LmVycm9yKG1zZyk7XG4gICAgICAgIH1cbiAgICAgIH0pO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGNsb3NlRGlhbG9nKCkge1xuICAgICAgUHJEaWFsb2cuY2xvc2UoKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBjbGVhbkZvcm0oKSB7XG4gICAgICB2bS5yZXNldC5lbWFpbCA9ICcnO1xuICAgIH1cbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuLyplc2xpbnQgYW5ndWxhci9maWxlLW5hbWU6IDAqL1xuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5mYWN0b3J5KCdzZXJ2aWNlRmFjdG9yeScsIHNlcnZpY2VGYWN0b3J5KTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8qKlxuICAgKiBNYWlzIGluZm9ybWHDp8O1ZXM6XG4gICAqIGh0dHBzOi8vZ2l0aHViLmNvbS9zd2ltbGFuZS9hbmd1bGFyLW1vZGVsLWZhY3Rvcnkvd2lraS9BUElcbiAgICovXG4gIGZ1bmN0aW9uIHNlcnZpY2VGYWN0b3J5KCRtb2RlbEZhY3RvcnkpIHtcbiAgICByZXR1cm4gZnVuY3Rpb24gKHVybCwgb3B0aW9ucykge1xuICAgICAgdmFyIG1vZGVsO1xuICAgICAgdmFyIGRlZmF1bHRPcHRpb25zID0ge1xuICAgICAgICBhY3Rpb25zOiB7XG4gICAgICAgICAgLyoqXG4gICAgICAgICAgICogU2VydmnDp28gY29tdW0gcGFyYSByZWFsaXphciBidXNjYSBjb20gcGFnaW5hw6fDo29cbiAgICAgICAgICAgKiBPIG1lc21vIGVzcGVyYSBxdWUgc2VqYSByZXRvcm5hZG8gdW0gb2JqZXRvIGNvbSBpdGVtcyBlIHRvdGFsXG4gICAgICAgICAgICovXG4gICAgICAgICAgcGFnaW5hdGU6IHtcbiAgICAgICAgICAgIG1ldGhvZDogJ0dFVCcsXG4gICAgICAgICAgICBpc0FycmF5OiBmYWxzZSxcbiAgICAgICAgICAgIHdyYXA6IGZhbHNlLFxuICAgICAgICAgICAgYWZ0ZXJSZXF1ZXN0OiBmdW5jdGlvbiBhZnRlclJlcXVlc3QocmVzcG9uc2UpIHtcbiAgICAgICAgICAgICAgaWYgKHJlc3BvbnNlWydpdGVtcyddKSB7XG4gICAgICAgICAgICAgICAgcmVzcG9uc2VbJ2l0ZW1zJ10gPSBtb2RlbC5MaXN0KHJlc3BvbnNlWydpdGVtcyddKTtcbiAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgIHJldHVybiByZXNwb25zZTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgIH07XG5cbiAgICAgIG1vZGVsID0gJG1vZGVsRmFjdG9yeSh1cmwsIGFuZ3VsYXIubWVyZ2UoZGVmYXVsdE9wdGlvbnMsIG9wdGlvbnMpKTtcblxuICAgICAgcmV0dXJuIG1vZGVsO1xuICAgIH07XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIENSVURDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8qKlxuICAgKiBDb250cm9sYWRvciBCYXNlIHF1ZSBpbXBsZW1lbnRhIHRvZGFzIGFzIGZ1bsOnw7VlcyBwYWRyw7VlcyBkZSB1bSBDUlVEXG4gICAqXG4gICAqIEHDp8O1ZXMgaW1wbGVtZW50YWRhc1xuICAgKiBhY3RpdmF0ZSgpXG4gICAqIHNlYXJjaChwYWdlKVxuICAgKiBlZGl0KHJlc291cmNlKVxuICAgKiBzYXZlKClcbiAgICogcmVtb3ZlKHJlc291cmNlKVxuICAgKiBnb1RvKHZpZXdOYW1lKVxuICAgKiBjbGVhbkZvcm0oKVxuICAgKlxuICAgKiBHYXRpbGhvc1xuICAgKlxuICAgKiBvbkFjdGl2YXRlKClcbiAgICogYXBwbHlGaWx0ZXJzKGRlZmF1bHRRdWVyeUZpbHRlcnMpXG4gICAqIGJlZm9yZVNlYXJjaChwYWdlKSAvL3JldG9ybmFuZG8gZmFsc2UgY2FuY2VsYSBvIGZsdXhvXG4gICAqIGFmdGVyU2VhcmNoKHJlc3BvbnNlKVxuICAgKiBiZWZvcmVDbGVhbiAvL3JldG9ybmFuZG8gZmFsc2UgY2FuY2VsYSBvIGZsdXhvXG4gICAqIGFmdGVyQ2xlYW4oKVxuICAgKiBiZWZvcmVTYXZlKCkgLy9yZXRvcm5hbmRvIGZhbHNlIGNhbmNlbGEgbyBmbHV4b1xuICAgKiBhZnRlclNhdmUocmVzb3VyY2UpXG4gICAqIG9uU2F2ZUVycm9yKGVycm9yKVxuICAgKiBiZWZvcmVSZW1vdmUocmVzb3VyY2UpIC8vcmV0b3JuYW5kbyBmYWxzZSBjYW5jZWxhIG8gZmx1eG9cbiAgICogYWZ0ZXJSZW1vdmUocmVzb3VyY2UpXG4gICAqXG4gICAqIEBwYXJhbSB7YW55fSB2bSBpbnN0YW5jaWEgZG8gY29udHJvbGxlciBmaWxob1xuICAgKiBAcGFyYW0ge2FueX0gbW9kZWxTZXJ2aWNlIHNlcnZpw6dvIGRvIG1vZGVsIHF1ZSB2YWkgc2VyIHV0aWxpemFkb1xuICAgKiBAcGFyYW0ge2FueX0gb3B0aW9ucyBvcMOnw7VlcyBwYXJhIHNvYnJlZXNjcmV2ZXIgY29tcG9ydGFtZW50b3MgcGFkcsO1ZXNcbiAgICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIENSVURDb250cm9sbGVyKHZtLCBtb2RlbFNlcnZpY2UsIG9wdGlvbnMsIFByVG9hc3QsIFByUGFnaW5hdGlvbiwgLy8gTk9TT05BUlxuICBQckRpYWxvZywgJHRyYW5zbGF0ZSkge1xuXG4gICAgLy9GdW5jdGlvbnMgQmxvY2tcbiAgICB2bS5zZWFyY2ggPSBzZWFyY2g7XG4gICAgdm0ucGFnaW5hdGVTZWFyY2ggPSBwYWdpbmF0ZVNlYXJjaDtcbiAgICB2bS5ub3JtYWxTZWFyY2ggPSBub3JtYWxTZWFyY2g7XG4gICAgdm0uZWRpdCA9IGVkaXQ7XG4gICAgdm0uc2F2ZSA9IHNhdmU7XG4gICAgdm0ucmVtb3ZlID0gcmVtb3ZlO1xuICAgIHZtLmdvVG8gPSBnb1RvO1xuICAgIHZtLmNsZWFuRm9ybSA9IGNsZWFuRm9ybTtcblxuICAgIGFjdGl2YXRlKCk7XG5cbiAgICAvKipcbiAgICAgKiBQcmVwYXJhIG8gY29udHJvbGFkb3JcbiAgICAgKiBGYXogbyBtZXJnZSBkYXMgb3DDp8O1ZXNcbiAgICAgKiBJbmljaWFsaXphIG8gcmVjdXJzb1xuICAgICAqIEluaWNpYWxpemEgbyBvYmpldG8gcGFnaW5hZG9yIGUgcmVhbGl6YSBhIHBlc3F1aXNhXG4gICAgICovXG4gICAgZnVuY3Rpb24gYWN0aXZhdGUoKSB7XG4gICAgICB2bS5kZWZhdWx0T3B0aW9ucyA9IHtcbiAgICAgICAgcmVkaXJlY3RBZnRlclNhdmU6IHRydWUsXG4gICAgICAgIHNlYXJjaE9uSW5pdDogdHJ1ZSxcbiAgICAgICAgcGVyUGFnZTogOCxcbiAgICAgICAgc2tpcFBhZ2luYXRpb246IGZhbHNlXG4gICAgICB9O1xuXG4gICAgICBhbmd1bGFyLm1lcmdlKHZtLmRlZmF1bHRPcHRpb25zLCBvcHRpb25zKTtcblxuICAgICAgdm0udmlld0Zvcm0gPSBmYWxzZTtcbiAgICAgIHZtLnJlc291cmNlID0gbmV3IG1vZGVsU2VydmljZSgpO1xuXG4gICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLm9uQWN0aXZhdGUpKSB2bS5vbkFjdGl2YXRlKCk7XG5cbiAgICAgIHZtLnBhZ2luYXRvciA9IFByUGFnaW5hdGlvbi5nZXRJbnN0YW5jZSh2bS5zZWFyY2gsIHZtLmRlZmF1bHRPcHRpb25zLnBlclBhZ2UpO1xuXG4gICAgICBpZiAodm0uZGVmYXVsdE9wdGlvbnMuc2VhcmNoT25Jbml0KSB2bS5zZWFyY2goKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFsaXphIGEgcGVzcXVpc2FcbiAgICAgKiBWZXJpZmljYSBxdWFsIGRhcyBmdW7Dp8O1ZXMgZGUgcGVzcXVpc2EgZGV2ZSBzZXIgcmVhbGl6YWRhLlxuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IHBhZ2UgcMOhZ2luYSBxdWUgZGV2ZSBzZXIgY2FycmVnYWRhXG4gICAgICovXG4gICAgZnVuY3Rpb24gc2VhcmNoKHBhZ2UpIHtcbiAgICAgIHZtLmRlZmF1bHRPcHRpb25zLnNraXBQYWdpbmF0aW9uID8gbm9ybWFsU2VhcmNoKCkgOiBwYWdpbmF0ZVNlYXJjaChwYWdlKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFsaXphIGEgcGVzcXVpc2EgcGFnaW5hZGEgY29tIGJhc2Ugbm9zIGZpbHRyb3MgZGVmaW5pZG9zXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gcGFnZSBww6FnaW5hIHF1ZSBkZXZlIHNlciBjYXJyZWdhZGFcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBwYWdpbmF0ZVNlYXJjaChwYWdlKSB7XG4gICAgICB2bS5wYWdpbmF0b3IuY3VycmVudFBhZ2UgPSBhbmd1bGFyLmlzRGVmaW5lZChwYWdlKSA/IHBhZ2UgOiAxO1xuICAgICAgdm0uZGVmYXVsdFF1ZXJ5RmlsdGVycyA9IHsgcGFnZTogdm0ucGFnaW5hdG9yLmN1cnJlbnRQYWdlLCBwZXJQYWdlOiB2bS5wYWdpbmF0b3IucGVyUGFnZSB9O1xuXG4gICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmFwcGx5RmlsdGVycykpIHZtLmRlZmF1bHRRdWVyeUZpbHRlcnMgPSB2bS5hcHBseUZpbHRlcnModm0uZGVmYXVsdFF1ZXJ5RmlsdGVycyk7XG4gICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmJlZm9yZVNlYXJjaCkgJiYgdm0uYmVmb3JlU2VhcmNoKHBhZ2UpID09PSBmYWxzZSkgcmV0dXJuIGZhbHNlO1xuXG4gICAgICBtb2RlbFNlcnZpY2UucGFnaW5hdGUodm0uZGVmYXVsdFF1ZXJ5RmlsdGVycykudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgdm0ucGFnaW5hdG9yLmNhbGNOdW1iZXJPZlBhZ2VzKHJlc3BvbnNlLnRvdGFsKTtcbiAgICAgICAgdm0ucmVzb3VyY2VzID0gcmVzcG9uc2UuaXRlbXM7XG5cbiAgICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5hZnRlclNlYXJjaCkpIHZtLmFmdGVyU2VhcmNoKHJlc3BvbnNlKTtcbiAgICAgIH0sIGZ1bmN0aW9uIChyZXNwb25zZURhdGEpIHtcbiAgICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5vblNlYXJjaEVycm9yKSkgdm0ub25TZWFyY2hFcnJvcihyZXNwb25zZURhdGEpO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhbGl6YSBhIHBlc3F1aXNhIGNvbSBiYXNlIG5vcyBmaWx0cm9zIGRlZmluaWRvc1xuICAgICAqXG4gICAgICovXG4gICAgZnVuY3Rpb24gbm9ybWFsU2VhcmNoKCkge1xuICAgICAgdm0uZGVmYXVsdFF1ZXJ5RmlsdGVycyA9IHt9O1xuXG4gICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmFwcGx5RmlsdGVycykpIHZtLmRlZmF1bHRRdWVyeUZpbHRlcnMgPSB2bS5hcHBseUZpbHRlcnModm0uZGVmYXVsdFF1ZXJ5RmlsdGVycyk7XG4gICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmJlZm9yZVNlYXJjaCkgJiYgdm0uYmVmb3JlU2VhcmNoKCkgPT09IGZhbHNlKSByZXR1cm4gZmFsc2U7XG5cbiAgICAgIG1vZGVsU2VydmljZS5xdWVyeSh2bS5kZWZhdWx0UXVlcnlGaWx0ZXJzKS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICB2bS5yZXNvdXJjZXMgPSByZXNwb25zZTtcblxuICAgICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmFmdGVyU2VhcmNoKSkgdm0uYWZ0ZXJTZWFyY2gocmVzcG9uc2UpO1xuICAgICAgfSwgZnVuY3Rpb24gKHJlc3BvbnNlRGF0YSkge1xuICAgICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLm9uU2VhcmNoRXJyb3IpKSB2bS5vblNlYXJjaEVycm9yKHJlc3BvbnNlRGF0YSk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBMaW1wYSBvIGZvcm11bMOhcmlvXG4gICAgICovXG4gICAgZnVuY3Rpb24gY2xlYW5Gb3JtKGZvcm0pIHtcbiAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYmVmb3JlQ2xlYW4pICYmIHZtLmJlZm9yZUNsZWFuKCkgPT09IGZhbHNlKSByZXR1cm4gZmFsc2U7XG5cbiAgICAgIHZtLnJlc291cmNlID0gbmV3IG1vZGVsU2VydmljZSgpO1xuXG4gICAgICBpZiAoYW5ndWxhci5pc0RlZmluZWQoZm9ybSkpIHtcbiAgICAgICAgZm9ybS4kc2V0UHJpc3RpbmUoKTtcbiAgICAgICAgZm9ybS4kc2V0VW50b3VjaGVkKCk7XG4gICAgICB9XG5cbiAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYWZ0ZXJDbGVhbikpIHZtLmFmdGVyQ2xlYW4oKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDYXJyZWdhIG5vIGZvcm11bMOhcmlvIG8gcmVjdXJzbyBzZWxlY2lvbmFkbyBwYXJhIGVkacOnw6NvXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gcmVzb3VyY2UgcmVjdXJzbyBzZWxlY2lvbmFkb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGVkaXQocmVzb3VyY2UpIHtcbiAgICAgIHZtLmdvVG8oJ2Zvcm0nKTtcbiAgICAgIHZtLnJlc291cmNlID0gbmV3IGFuZ3VsYXIuY29weShyZXNvdXJjZSk7XG5cbiAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYWZ0ZXJFZGl0KSkgdm0uYWZ0ZXJFZGl0KCk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogU2FsdmEgb3UgYXR1YWxpemEgbyByZWN1cnNvIGNvcnJlbnRlIG5vIGZvcm11bMOhcmlvXG4gICAgICogTm8gY29tcG9ydGFtZW50byBwYWRyw6NvIHJlZGlyZWNpb25hIG8gdXN1w6FyaW8gcGFyYSB2aWV3IGRlIGxpc3RhZ2VtXG4gICAgICogZGVwb2lzIGRhIGV4ZWN1w6fDo29cbiAgICAgKlxuICAgICAqIEByZXR1cm5zXG4gICAgICovXG4gICAgZnVuY3Rpb24gc2F2ZShmb3JtKSB7XG4gICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmJlZm9yZVNhdmUpICYmIHZtLmJlZm9yZVNhdmUoKSA9PT0gZmFsc2UpIHJldHVybiBmYWxzZTtcblxuICAgICAgdm0ucmVzb3VyY2UuJHNhdmUoKS50aGVuKGZ1bmN0aW9uIChyZXNvdXJjZSkge1xuICAgICAgICB2bS5yZXNvdXJjZSA9IHJlc291cmNlO1xuXG4gICAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYWZ0ZXJTYXZlKSkgdm0uYWZ0ZXJTYXZlKHJlc291cmNlKTtcblxuICAgICAgICBpZiAodm0uZGVmYXVsdE9wdGlvbnMucmVkaXJlY3RBZnRlclNhdmUpIHtcbiAgICAgICAgICB2bS5jbGVhbkZvcm0oZm9ybSk7XG4gICAgICAgICAgdm0uc2VhcmNoKHZtLnBhZ2luYXRvci5jdXJyZW50UGFnZSk7XG4gICAgICAgICAgdm0uZ29UbygnbGlzdCcpO1xuICAgICAgICB9XG5cbiAgICAgICAgUHJUb2FzdC5zdWNjZXNzKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMuc2F2ZVN1Y2Nlc3MnKSk7XG4gICAgICB9LCBmdW5jdGlvbiAocmVzcG9uc2VEYXRhKSB7XG4gICAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0ub25TYXZlRXJyb3IpKSB2bS5vblNhdmVFcnJvcihyZXNwb25zZURhdGEpO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVtb3ZlIG8gcmVjdXJzbyBpbmZvcm1hZG8uXG4gICAgICogQW50ZXMgZXhpYmUgdW0gZGlhbG9nbyBkZSBjb25maXJtYcOnw6NvXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gcmVzb3VyY2UgcmVjdXJzbyBlc2NvbGhpZG9cbiAgICAgKi9cbiAgICBmdW5jdGlvbiByZW1vdmUocmVzb3VyY2UpIHtcbiAgICAgIHZhciBjb25maWcgPSB7XG4gICAgICAgIHRpdGxlOiAkdHJhbnNsYXRlLmluc3RhbnQoJ2RpYWxvZy5jb25maXJtVGl0bGUnKSxcbiAgICAgICAgZGVzY3JpcHRpb246ICR0cmFuc2xhdGUuaW5zdGFudCgnZGlhbG9nLmNvbmZpcm1EZXNjcmlwdGlvbicpXG4gICAgICB9O1xuXG4gICAgICBQckRpYWxvZy5jb25maXJtKGNvbmZpZykudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYmVmb3JlUmVtb3ZlKSAmJiB2bS5iZWZvcmVSZW1vdmUocmVzb3VyY2UpID09PSBmYWxzZSkgcmV0dXJuIGZhbHNlO1xuXG4gICAgICAgIHJlc291cmNlLiRkZXN0cm95KCkudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5hZnRlclJlbW92ZSkpIHZtLmFmdGVyUmVtb3ZlKHJlc291cmNlKTtcblxuICAgICAgICAgIHZtLnNlYXJjaCgpO1xuICAgICAgICAgIFByVG9hc3QuaW5mbygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnJlbW92ZVN1Y2Nlc3MnKSk7XG4gICAgICAgIH0pO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQWx0ZXJuYSBlbnRyZSBhIHZpZXcgZG8gZm9ybXVsw6FyaW8gZSBsaXN0YWdlbVxuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IHZpZXdOYW1lIG5vbWUgZGEgdmlld1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGdvVG8odmlld05hbWUpIHtcbiAgICAgIHZtLnZpZXdGb3JtID0gZmFsc2U7XG4gICAgICB2bS5vblZpZXcgPSBmYWxzZTtcbiAgICAgIGlmICh2aWV3TmFtZSA9PT0gJ2Zvcm0nKSB7XG4gICAgICAgIHZtLmNsZWFuRm9ybSgpO1xuICAgICAgICB2bS52aWV3Rm9ybSA9IHRydWU7XG4gICAgICB9XG4gICAgfVxuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmlsdGVyKCdlbGFwc2VkJywgZnVuY3Rpb24gKCkge1xuICAgIHJldHVybiBmdW5jdGlvbiAoZGF0ZSkge1xuICAgICAgaWYgKCFkYXRlKSByZXR1cm47XG4gICAgICB2YXIgdGltZSA9IERhdGUucGFyc2UoZGF0ZSksXG4gICAgICAgICAgdGltZU5vdyA9IG5ldyBEYXRlKCkuZ2V0VGltZSgpLFxuICAgICAgICAgIGRpZmZlcmVuY2UgPSB0aW1lTm93IC0gdGltZSxcbiAgICAgICAgICBzZWNvbmRzID0gTWF0aC5mbG9vcihkaWZmZXJlbmNlIC8gMTAwMCksXG4gICAgICAgICAgbWludXRlcyA9IE1hdGguZmxvb3Ioc2Vjb25kcyAvIDYwKSxcbiAgICAgICAgICBob3VycyA9IE1hdGguZmxvb3IobWludXRlcyAvIDYwKSxcbiAgICAgICAgICBkYXlzID0gTWF0aC5mbG9vcihob3VycyAvIDI0KSxcbiAgICAgICAgICBtb250aHMgPSBNYXRoLmZsb29yKGRheXMgLyAzMCk7XG5cbiAgICAgIGlmIChtb250aHMgPiAxKSB7XG4gICAgICAgIHJldHVybiBtb250aHMgKyAnIG1lc2VzIGF0csOhcyc7XG4gICAgICB9IGVsc2UgaWYgKG1vbnRocyA9PT0gMSkge1xuICAgICAgICByZXR1cm4gJzEgbcOqcyBhdHLDoXMnO1xuICAgICAgfSBlbHNlIGlmIChkYXlzID4gMSkge1xuICAgICAgICByZXR1cm4gZGF5cyArICcgZGlhcyBhdHLDoXMnO1xuICAgICAgfSBlbHNlIGlmIChkYXlzID09PSAxKSB7XG4gICAgICAgIHJldHVybiAnMSBkaWEgYXRyw6FzJztcbiAgICAgIH0gZWxzZSBpZiAoaG91cnMgPiAxKSB7XG4gICAgICAgIHJldHVybiBob3VycyArICcgaG9yYXMgYXRyw6FzJztcbiAgICAgIH0gZWxzZSBpZiAoaG91cnMgPT09IDEpIHtcbiAgICAgICAgcmV0dXJuICd1bWEgaG9yYSBhdHLDoXMnO1xuICAgICAgfSBlbHNlIGlmIChtaW51dGVzID4gMSkge1xuICAgICAgICByZXR1cm4gbWludXRlcyArICcgbWludXRvcyBhdHLDoXMnO1xuICAgICAgfSBlbHNlIGlmIChtaW51dGVzID09PSAxKSB7XG4gICAgICAgIHJldHVybiAndW0gbWludXRvIGF0csOhcyc7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICByZXR1cm4gJ2jDoSBwb3Vjb3Mgc2VndW5kb3MnO1xuICAgICAgfVxuICAgIH07XG4gIH0pLmNvbnRyb2xsZXIoJ0Rhc2hib2FyZENvbnRyb2xsZXInLCBEYXNoYm9hcmRDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIERhc2hib2FyZENvbnRyb2xsZXIoJGNvbnRyb2xsZXIsICRzdGF0ZSwgRGFzaGJvYXJkc1NlcnZpY2UsIFByb2plY3RzU2VydmljZSwgbW9tZW50KSB7XG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIC8vQXR0cmlidXRlcyBCbG9ja1xuXG4gICAgLy9GdW5jdGlvbnMgQmxvY2tcbiAgICB2bS5vbkFjdGl2YXRlID0gb25BY3RpdmF0ZTtcbiAgICB2bS5hcHBseUZpbHRlcnMgPSBhcHBseUZpbHRlcnM7XG4gICAgdm0uZml4RGF0ZSA9IGZpeERhdGU7XG5cbiAgICBmdW5jdGlvbiBvbkFjdGl2YXRlKCkge1xuICAgICAgdmFyIHByb2plY3QgPSBsb2NhbFN0b3JhZ2UuZ2V0SXRlbSgncHJvamVjdCcpO1xuXG4gICAgICBQcm9qZWN0c1NlcnZpY2UucXVlcnkoeyBwcm9qZWN0X2lkOiBwcm9qZWN0IH0pLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgIHZtLmFjdHVhbFByb2plY3QgPSByZXNwb25zZVswXTtcbiAgICAgIH0pO1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0geyBwcm9qZWN0X2lkOiBwcm9qZWN0IH07XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gYXBwbHlGaWx0ZXJzKGRlZmF1bHRRdWVyeUZpbHRlcnMpIHtcbiAgICAgIHJldHVybiBhbmd1bGFyLmV4dGVuZChkZWZhdWx0UXVlcnlGaWx0ZXJzLCB2bS5xdWVyeUZpbHRlcnMpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGZpeERhdGUoZGF0ZVN0cmluZykge1xuICAgICAgcmV0dXJuIG1vbWVudChkYXRlU3RyaW5nKTtcbiAgICB9XG5cbiAgICB2bS5nb1RvUHJvamVjdCA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICRzdGF0ZS5nbygnYXBwLnByb2plY3RzJywgeyBvYmo6ICdlZGl0JywgcmVzb3VyY2U6IHZtLmFjdHVhbFByb2plY3QgfSk7XG4gICAgfTtcblxuICAgIHZtLnRvdGFsQ29zdCA9IGZ1bmN0aW9uICgpIHtcbiAgICAgIHZhciBlc3RpbWF0ZWRfY29zdCA9IDA7XG5cbiAgICAgIHZtLmFjdHVhbFByb2plY3QudGFza3MuZm9yRWFjaChmdW5jdGlvbiAodGFzaykge1xuICAgICAgICBlc3RpbWF0ZWRfY29zdCArPSBwYXJzZUZsb2F0KHZtLmFjdHVhbFByb2plY3QuaG91cl92YWx1ZV9maW5hbCkgKiB0YXNrLmVzdGltYXRlZF90aW1lO1xuICAgICAgfSk7XG4gICAgICByZXR1cm4gZXN0aW1hdGVkX2Nvc3QudG9Mb2NhbGVTdHJpbmcoJ1B0LWJyJywgeyBtaW5pbXVtRnJhY3Rpb25EaWdpdHM6IDIgfSk7XG4gICAgfTtcblxuICAgIC8vIGluc3RhbnRpYXRlIGJhc2UgY29udHJvbGxlclxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHsgdm06IHZtLCBtb2RlbFNlcnZpY2U6IERhc2hib2FyZHNTZXJ2aWNlLCBvcHRpb25zOiB7fSB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25maWcocm91dGVzKTtcblxuICAvKipcbiAgICogQXJxdWl2byBkZSBjb25maWd1cmHDp8OjbyBjb20gYXMgcm90YXMgZXNwZWPDrWZpY2FzIGRvIHJlY3Vyc28gcHJvamVjdFxuICAgKlxuICAgKiBAcGFyYW0ge2FueX0gJHN0YXRlUHJvdmlkZXJcbiAgICogQHBhcmFtIHthbnl9IEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdhcHAuZGFzaGJvYXJkJywge1xuICAgICAgdXJsOiAnL2Rhc2hib2FyZHMnLFxuICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9kYXNoYm9hcmQvZGFzaGJvYXJkLmh0bWwnLFxuICAgICAgY29udHJvbGxlcjogJ0Rhc2hib2FyZENvbnRyb2xsZXIgYXMgZGFzaGJvYXJkQ3RybCcsXG4gICAgICBkYXRhOiB7IG5lZWRBdXRoZW50aWNhdGlvbjogdHJ1ZSB9LFxuICAgICAgb2JqOiB7IHJlc291cmNlOiBudWxsIH1cbiAgICB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5mYWN0b3J5KCdEYXNoYm9hcmRzU2VydmljZScsIERhc2hib2FyZHNTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIERhc2hib2FyZHNTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCdkYXNoYm9hcmRzJywge1xuICAgICAgYWN0aW9uczoge30sXG4gICAgICBpbnN0YW5jZToge31cbiAgICB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25maWcocm91dGVzKTtcblxuICAvKipcbiAgICogQXJxdWl2byBkZSBjb25maWd1cmHDp8OjbyBjb20gYXMgcm90YXMgZXNwZWPDrWZpY2FzIGRvIHJlY3Vyc28gdXNlclxuICAgKlxuICAgKiBAcGFyYW0ge2FueX0gJHN0YXRlUHJvdmlkZXJcbiAgICogQHBhcmFtIHthbnl9IEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdhcHAuZGluYW1pYy1xdWVyeScsIHtcbiAgICAgIHVybDogJy9jb25zdWx0YXMtZGluYW1pY2FzJyxcbiAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvZGluYW1pYy1xdWVyeXMvZGluYW1pYy1xdWVyeXMuaHRtbCcsXG4gICAgICBjb250cm9sbGVyOiAnRGluYW1pY1F1ZXJ5c0NvbnRyb2xsZXIgYXMgZGluYW1pY1F1ZXJ5Q3RybCcsXG4gICAgICBkYXRhOiB7IG5lZWRBdXRoZW50aWNhdGlvbjogdHJ1ZSwgbmVlZFByb2ZpbGU6IFsnYWRtaW4nXSB9XG4gICAgfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmFjdG9yeSgnRGluYW1pY1F1ZXJ5U2VydmljZScsIERpbmFtaWNRdWVyeVNlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gRGluYW1pY1F1ZXJ5U2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHJldHVybiBzZXJ2aWNlRmFjdG9yeSgnZGluYW1pY1F1ZXJ5Jywge1xuICAgICAgLyoqXG4gICAgICAgKiBhw6fDo28gYWRpY2lvbmFkYSBwYXJhIHBlZ2FyIHVtYSBsaXN0YSBkZSBtb2RlbHMgZXhpc3RlbnRlcyBubyBzZXJ2aWRvclxuICAgICAgICovXG4gICAgICBhY3Rpb25zOiB7XG4gICAgICAgIGdldE1vZGVsczoge1xuICAgICAgICAgIG1ldGhvZDogJ0dFVCcsXG4gICAgICAgICAgdXJsOiAnbW9kZWxzJ1xuICAgICAgICB9XG4gICAgICB9LFxuICAgICAgaW5zdGFuY2U6IHt9XG4gICAgfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb250cm9sbGVyKCdEaW5hbWljUXVlcnlzQ29udHJvbGxlcicsIERpbmFtaWNRdWVyeXNDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIERpbmFtaWNRdWVyeXNDb250cm9sbGVyKCRjb250cm9sbGVyLCBEaW5hbWljUXVlcnlTZXJ2aWNlLCBsb2Rhc2gsIFByVG9hc3QsIC8vIE5PU09OQVJcbiAgJHRyYW5zbGF0ZSkge1xuXG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIC8vYWN0aW9uc1xuICAgIHZtLm9uQWN0aXZhdGUgPSBvbkFjdGl2YXRlO1xuICAgIHZtLmFwcGx5RmlsdGVycyA9IGFwcGx5RmlsdGVycztcbiAgICB2bS5sb2FkQXR0cmlidXRlcyA9IGxvYWRBdHRyaWJ1dGVzO1xuICAgIHZtLmxvYWRPcGVyYXRvcnMgPSBsb2FkT3BlcmF0b3JzO1xuICAgIHZtLmFkZEZpbHRlciA9IGFkZEZpbHRlcjtcbiAgICB2bS5hZnRlclNlYXJjaCA9IGFmdGVyU2VhcmNoO1xuICAgIHZtLnJ1bkZpbHRlciA9IHJ1bkZpbHRlcjtcbiAgICB2bS5lZGl0RmlsdGVyID0gZWRpdEZpbHRlcjtcbiAgICB2bS5sb2FkTW9kZWxzID0gbG9hZE1vZGVscztcbiAgICB2bS5yZW1vdmVGaWx0ZXIgPSByZW1vdmVGaWx0ZXI7XG4gICAgdm0uY2xlYXIgPSBjbGVhcjtcbiAgICB2bS5yZXN0YXJ0ID0gcmVzdGFydDtcblxuICAgIC8vaGVyZGEgbyBjb21wb3J0YW1lbnRvIGJhc2UgZG8gQ1JVRFxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHsgdm06IHZtLCBtb2RlbFNlcnZpY2U6IERpbmFtaWNRdWVyeVNlcnZpY2UsIG9wdGlvbnM6IHtcbiAgICAgICAgc2VhcmNoT25Jbml0OiBmYWxzZVxuICAgICAgfSB9KTtcblxuICAgIGZ1bmN0aW9uIG9uQWN0aXZhdGUoKSB7XG4gICAgICB2bS5yZXN0YXJ0KCk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUHJlcGFyYSBlIGFwbGljYSBvcyBmaWx0cm8gcXVlIHbDo28gc2VyIGVudmlhZG9zIHBhcmEgbyBzZXJ2acOnb1xuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IGRlZmF1bHRRdWVyeUZpbHRlcnNcbiAgICAgKiBAcmV0dXJuc1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGFwcGx5RmlsdGVycyhkZWZhdWx0UXVlcnlGaWx0ZXJzKSB7XG4gICAgICB2YXIgd2hlcmUgPSB7fTtcblxuICAgICAgLyoqXG4gICAgICAgKiBvIHNlcnZpw6dvIGVzcGVyYSB1bSBvYmpldG8gY29tOlxuICAgICAgICogIG8gbm9tZSBkZSB1bSBtb2RlbFxuICAgICAgICogIHVtYSBsaXN0YSBkZSBmaWx0cm9zXG4gICAgICAgKi9cbiAgICAgIGlmICh2bS5hZGRlZEZpbHRlcnMubGVuZ3RoID4gMCkge1xuICAgICAgICB2YXIgYWRkZWRGaWx0ZXJzID0gYW5ndWxhci5jb3B5KHZtLmFkZGVkRmlsdGVycyk7XG5cbiAgICAgICAgd2hlcmUubW9kZWwgPSB2bS5hZGRlZEZpbHRlcnNbMF0ubW9kZWwubmFtZTtcblxuICAgICAgICBmb3IgKHZhciBpbmRleCA9IDA7IGluZGV4IDwgYWRkZWRGaWx0ZXJzLmxlbmd0aDsgaW5kZXgrKykge1xuICAgICAgICAgIHZhciBmaWx0ZXIgPSBhZGRlZEZpbHRlcnNbaW5kZXhdO1xuXG4gICAgICAgICAgZmlsdGVyLm1vZGVsID0gbnVsbDtcbiAgICAgICAgICBmaWx0ZXIuYXR0cmlidXRlID0gZmlsdGVyLmF0dHJpYnV0ZS5uYW1lO1xuICAgICAgICAgIGZpbHRlci5vcGVyYXRvciA9IGZpbHRlci5vcGVyYXRvci52YWx1ZTtcbiAgICAgICAgfVxuXG4gICAgICAgIHdoZXJlLmZpbHRlcnMgPSBhbmd1bGFyLnRvSnNvbihhZGRlZEZpbHRlcnMpO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgd2hlcmUubW9kZWwgPSB2bS5xdWVyeUZpbHRlcnMubW9kZWwubmFtZTtcbiAgICAgIH1cblxuICAgICAgcmV0dXJuIGFuZ3VsYXIuZXh0ZW5kKGRlZmF1bHRRdWVyeUZpbHRlcnMsIHdoZXJlKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDYXJyZWdhIHRvZG9zIG9zIG1vZGVscyBjcmlhZG9zIG5vIHNlcnZpZG9yIGNvbSBzZXVzIGF0cmlidXRvc1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGxvYWRNb2RlbHMoKSB7XG4gICAgICAvL1BlZ2EgdG9kb3Mgb3MgbW9kZWxzIGRvIHNlcnZlciBlIG1vbnRhIHVtYSBsaXN0YSBwcm8gQ29tYm9Cb3hcbiAgICAgIERpbmFtaWNRdWVyeVNlcnZpY2UuZ2V0TW9kZWxzKCkudGhlbihmdW5jdGlvbiAoZGF0YSkge1xuICAgICAgICB2bS5tb2RlbHMgPSBkYXRhO1xuICAgICAgICB2bS5xdWVyeUZpbHRlcnMubW9kZWwgPSB2bS5tb2RlbHNbMF07XG4gICAgICAgIHZtLmxvYWRBdHRyaWJ1dGVzKCk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDYXJyZWdhIG9zIGF0dHJpYnV0b3MgZG8gbW9kZWwgZXNjb2xoaWRvXG4gICAgICovXG4gICAgZnVuY3Rpb24gbG9hZEF0dHJpYnV0ZXMoKSB7XG4gICAgICB2bS5hdHRyaWJ1dGVzID0gdm0ucXVlcnlGaWx0ZXJzLm1vZGVsLmF0dHJpYnV0ZXM7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMuYXR0cmlidXRlID0gdm0uYXR0cmlidXRlc1swXTtcblxuICAgICAgdm0ubG9hZE9wZXJhdG9ycygpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENhcnJlZ2Egb3Mgb3BlcmFkb3JlcyBlc3BlY2lmaWNvcyBwYXJhIG8gdGlwbyBkbyBhdHJpYnV0b1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGxvYWRPcGVyYXRvcnMoKSB7XG4gICAgICB2YXIgb3BlcmF0b3JzID0gW3sgdmFsdWU6ICc9JywgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudCgndmlld3MuZmllbGRzLnF1ZXJ5RGluYW1pYy5vcGVyYXRvcnMuZXF1YWxzJykgfSwgeyB2YWx1ZTogJzw+JywgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudCgndmlld3MuZmllbGRzLnF1ZXJ5RGluYW1pYy5vcGVyYXRvcnMuZGlmZXJlbnQnKSB9XTtcblxuICAgICAgaWYgKHZtLnF1ZXJ5RmlsdGVycy5hdHRyaWJ1dGUudHlwZS5pbmRleE9mKCd2YXJ5aW5nJykgIT09IC0xKSB7XG4gICAgICAgIG9wZXJhdG9ycy5wdXNoKHsgdmFsdWU6ICdoYXMnLFxuICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLmNvbnRlaW5zJykgfSk7XG4gICAgICAgIG9wZXJhdG9ycy5wdXNoKHsgdmFsdWU6ICdzdGFydFdpdGgnLFxuICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLnN0YXJ0V2l0aCcpIH0pO1xuICAgICAgICBvcGVyYXRvcnMucHVzaCh7IHZhbHVlOiAnZW5kV2l0aCcsXG4gICAgICAgICAgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudCgndmlld3MuZmllbGRzLnF1ZXJ5RGluYW1pYy5vcGVyYXRvcnMuZmluaXNoV2l0aCcpIH0pO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgb3BlcmF0b3JzLnB1c2goeyB2YWx1ZTogJz4nLFxuICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLmJpZ2dlclRoYW4nKSB9KTtcbiAgICAgICAgb3BlcmF0b3JzLnB1c2goeyB2YWx1ZTogJz49JyxcbiAgICAgICAgICBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KCd2aWV3cy5maWVsZHMucXVlcnlEaW5hbWljLm9wZXJhdG9ycy5lcXVhbHNPckJpZ2dlclRoYW4nKSB9KTtcbiAgICAgICAgb3BlcmF0b3JzLnB1c2goeyB2YWx1ZTogJzwnLFxuICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLmxlc3NUaGFuJykgfSk7XG4gICAgICAgIG9wZXJhdG9ycy5wdXNoKHsgdmFsdWU6ICc8PScsXG4gICAgICAgICAgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudCgndmlld3MuZmllbGRzLnF1ZXJ5RGluYW1pYy5vcGVyYXRvcnMuZXF1YWxzT3JMZXNzVGhhbicpIH0pO1xuICAgICAgfVxuXG4gICAgICB2bS5vcGVyYXRvcnMgPSBvcGVyYXRvcnM7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMub3BlcmF0b3IgPSB2bS5vcGVyYXRvcnNbMF07XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQWRpY2lvbmEvZWRpdGEgdW0gZmlsdHJvXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gZm9ybSBlbGVtZW50byBodG1sIGRvIGZvcm11bMOhcmlvIHBhcmEgdmFsaWRhw6fDtWVzXG4gICAgICovXG4gICAgZnVuY3Rpb24gYWRkRmlsdGVyKGZvcm0pIHtcbiAgICAgIGlmIChhbmd1bGFyLmlzVW5kZWZpbmVkKHZtLnF1ZXJ5RmlsdGVycy52YWx1ZSkgfHwgdm0ucXVlcnlGaWx0ZXJzLnZhbHVlID09PSAnJykge1xuICAgICAgICBQclRvYXN0LmVycm9yKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMudmFsaWRhdGUuZmllbGRSZXF1aXJlZCcsIHsgZmllbGQ6ICd2YWxvcicgfSkpO1xuICAgICAgICByZXR1cm47XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBpZiAodm0uaW5kZXggPCAwKSB7XG4gICAgICAgICAgdm0uYWRkZWRGaWx0ZXJzLnB1c2goYW5ndWxhci5jb3B5KHZtLnF1ZXJ5RmlsdGVycykpO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIHZtLmFkZGVkRmlsdGVyc1t2bS5pbmRleF0gPSBhbmd1bGFyLmNvcHkodm0ucXVlcnlGaWx0ZXJzKTtcbiAgICAgICAgICB2bS5pbmRleCA9IC0xO1xuICAgICAgICB9XG5cbiAgICAgICAgLy9yZWluaWNpYSBvIGZvcm11bMOhcmlvIGUgYXMgdmFsaWRhw6fDtWVzIGV4aXN0ZW50ZXNcbiAgICAgICAgdm0ucXVlcnlGaWx0ZXJzID0ge307XG4gICAgICAgIGZvcm0uJHNldFByaXN0aW5lKCk7XG4gICAgICAgIGZvcm0uJHNldFVudG91Y2hlZCgpO1xuICAgICAgfVxuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWxpemEgYSBwZXNxdWlzYSB0ZW5kbyBvcyBmaWx0cm9zIGNvbW8gcGFyw6JtZXRyb3NcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBydW5GaWx0ZXIoKSB7XG4gICAgICB2bS5zZWFyY2godm0ucGFnaW5hdG9yLmN1cnJlbnRQYWdlKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBHYXRpbGhvIGFjaW9uYWRvIGRlcG9pcyBkYSBwZXNxdWlzYSByZXNwb25zw6F2ZWwgcG9yIGlkZW50aWZpY2FyIG9zIGF0cmlidXRvc1xuICAgICAqIGNvbnRpZG9zIG5vcyBlbGVtZW50b3MgcmVzdWx0YW50ZXMgZGEgYnVzY2FcbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSBkYXRhIGRhZG9zIHJlZmVyZW50ZSBhbyByZXRvcm5vIGRhIHJlcXVpc2nDp8Ojb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGFmdGVyU2VhcmNoKGRhdGEpIHtcbiAgICAgIHZhciBrZXlzID0gZGF0YS5pdGVtcy5sZW5ndGggPiAwID8gT2JqZWN0LmtleXMoZGF0YS5pdGVtc1swXSkgOiBbXTtcblxuICAgICAgLy9yZXRpcmEgdG9kb3Mgb3MgYXRyaWJ1dG9zIHF1ZSBjb21lw6dhbSBjb20gJC5cbiAgICAgIC8vRXNzZXMgYXRyaWJ1dG9zIHPDo28gYWRpY2lvbmFkb3MgcGVsbyBzZXJ2acOnbyBlIG7Do28gZGV2ZSBhcGFyZWNlciBuYSBsaXN0YWdlbVxuICAgICAgdm0ua2V5cyA9IGxvZGFzaC5maWx0ZXIoa2V5cywgZnVuY3Rpb24gKGtleSkge1xuICAgICAgICByZXR1cm4gIWxvZGFzaC5zdGFydHNXaXRoKGtleSwgJyQnKTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENvbG9hY2Egbm8gZm9ybXVsw6FyaW8gbyBmaWx0cm8gZXNjb2xoaWRvIHBhcmEgZWRpw6fDo29cbiAgICAgKiBAcGFyYW0ge2FueX0gJGluZGV4IGluZGljZSBubyBhcnJheSBkbyBmaWx0cm8gZXNjb2xoaWRvXG4gICAgICovXG4gICAgZnVuY3Rpb24gZWRpdEZpbHRlcigkaW5kZXgpIHtcbiAgICAgIHZtLmluZGV4ID0gJGluZGV4O1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0gdm0uYWRkZWRGaWx0ZXJzWyRpbmRleF07XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVtb3ZlIG8gZmlsdHJvIGVzY29saGlkb1xuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9ICRpbmRleCBpbmRpY2Ugbm8gYXJyYXkgZG8gZmlsdHJvIGVzY29saGlkb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIHJlbW92ZUZpbHRlcigkaW5kZXgpIHtcbiAgICAgIHZtLmFkZGVkRmlsdGVycy5zcGxpY2UoJGluZGV4KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBMaW1wYSBvIGZvcm11bMOhcmlvIGNvcnJlbnRlXG4gICAgICovXG4gICAgZnVuY3Rpb24gY2xlYXIoKSB7XG4gICAgICAvL2d1YXJkYSBvIGluZGljZSBkbyByZWdpc3RybyBxdWUgZXN0w6Egc2VuZG8gZWRpdGFkb1xuICAgICAgdm0uaW5kZXggPSAtMTtcbiAgICAgIC8vdmluY3VsYWRvIGFvcyBjYW1wb3MgZG8gZm9ybXVsw6FyaW9cbiAgICAgIHZtLnF1ZXJ5RmlsdGVycyA9IHt9O1xuXG4gICAgICBpZiAodm0ubW9kZWxzKSB2bS5xdWVyeUZpbHRlcnMubW9kZWwgPSB2bS5tb2RlbHNbMF07XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVpbmljaWEgYSBjb25zdHJ1w6fDo28gZGEgcXVlcnkgbGltcGFuZG8gdHVkb1xuICAgICAqXG4gICAgICovXG4gICAgZnVuY3Rpb24gcmVzdGFydCgpIHtcbiAgICAgIC8vZ3VhcmRhIGF0cmlidXRvcyBkbyByZXN1bHRhZG8gZGEgYnVzY2EgY29ycmVudGVcbiAgICAgIHZtLmtleXMgPSBbXTtcblxuICAgICAgLy9ndWFyZGEgb3MgZmlsdHJvcyBhZGljaW9uYWRvc1xuICAgICAgdm0uYWRkZWRGaWx0ZXJzID0gW107XG4gICAgICB2bS5jbGVhcigpO1xuICAgICAgdm0ubG9hZE1vZGVscygpO1xuICAgIH1cbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZhY3RvcnkoJ2xhbmd1YWdlTG9hZGVyJywgTGFuZ3VhZ2VMb2FkZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gTGFuZ3VhZ2VMb2FkZXIoJHEsIFN1cHBvcnRTZXJ2aWNlLCAkbG9nLCAkaW5qZWN0b3IpIHtcbiAgICB2YXIgc2VydmljZSA9IHRoaXM7XG5cbiAgICBzZXJ2aWNlLnRyYW5zbGF0ZSA9IGZ1bmN0aW9uIChsb2NhbGUpIHtcbiAgICAgIHJldHVybiB7XG4gICAgICAgIGdsb2JhbDogJGluamVjdG9yLmdldChsb2NhbGUgKyAnLmkxOG4uZ2xvYmFsJyksXG4gICAgICAgIHZpZXdzOiAkaW5qZWN0b3IuZ2V0KGxvY2FsZSArICcuaTE4bi52aWV3cycpLFxuICAgICAgICBhdHRyaWJ1dGVzOiAkaW5qZWN0b3IuZ2V0KGxvY2FsZSArICcuaTE4bi5hdHRyaWJ1dGVzJyksXG4gICAgICAgIGRpYWxvZzogJGluamVjdG9yLmdldChsb2NhbGUgKyAnLmkxOG4uZGlhbG9nJyksXG4gICAgICAgIG1lc3NhZ2VzOiAkaW5qZWN0b3IuZ2V0KGxvY2FsZSArICcuaTE4bi5tZXNzYWdlcycpLFxuICAgICAgICBtb2RlbHM6ICRpbmplY3Rvci5nZXQobG9jYWxlICsgJy5pMThuLm1vZGVscycpXG4gICAgICB9O1xuICAgIH07XG5cbiAgICAvLyByZXR1cm4gbG9hZGVyRm5cbiAgICByZXR1cm4gZnVuY3Rpb24gKG9wdGlvbnMpIHtcbiAgICAgICRsb2cuaW5mbygnQ2FycmVnYW5kbyBvIGNvbnRldWRvIGRhIGxpbmd1YWdlbSAnICsgb3B0aW9ucy5rZXkpO1xuXG4gICAgICB2YXIgZGVmZXJyZWQgPSAkcS5kZWZlcigpO1xuXG4gICAgICAvL0NhcnJlZ2EgYXMgbGFuZ3MgcXVlIHByZWNpc2FtIGUgZXN0w6NvIG5vIHNlcnZpZG9yIHBhcmEgbsOjbyBwcmVjaXNhciByZXBldGlyIGFxdWlcbiAgICAgIFN1cHBvcnRTZXJ2aWNlLmxhbmdzKCkudGhlbihmdW5jdGlvbiAobGFuZ3MpIHtcbiAgICAgICAgLy9NZXJnZSBjb20gb3MgbGFuZ3MgZGVmaW5pZG9zIG5vIHNlcnZpZG9yXG4gICAgICAgIHZhciBkYXRhID0gYW5ndWxhci5tZXJnZShzZXJ2aWNlLnRyYW5zbGF0ZShvcHRpb25zLmtleSksIGxhbmdzKTtcblxuICAgICAgICByZXR1cm4gZGVmZXJyZWQucmVzb2x2ZShkYXRhKTtcbiAgICAgIH0sIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgcmV0dXJuIGRlZmVycmVkLnJlc29sdmUoc2VydmljZS50cmFuc2xhdGUob3B0aW9ucy5rZXkpKTtcbiAgICAgIH0pO1xuXG4gICAgICByZXR1cm4gZGVmZXJyZWQucHJvbWlzZTtcbiAgICB9O1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmlsdGVyKCd0QXR0cicsIHRBdHRyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIHRBdHRyKCRmaWx0ZXIpIHtcbiAgICAvKipcbiAgICAgKiBGaWx0cm8gcGFyYSB0cmFkdcOnw6NvIGRlIHVtIGF0cmlidXRvIGRlIHVtIG1vZGVsXG4gICAgICogXG4gICAgICogQHBhcmFtIHthbnl9IG5hbWUgbm9tZSBkbyBhdHJpYnV0b1xuICAgICAqIEByZXR1cm5zIG8gbm9tZSBkbyBhdHJpYnV0byB0cmFkdXppZG8gY2FzbyBlbmNvbnRyZSBzZSBuw6NvIG8gbm9tZSBwYXNzYWRvIHBvciBwYXJhbWV0cm9cbiAgICAgKi9cbiAgICByZXR1cm4gZnVuY3Rpb24gKG5hbWUpIHtcbiAgICAgIHZhciBrZXkgPSAnYXR0cmlidXRlcy4nICsgbmFtZTtcbiAgICAgIHZhciB0cmFuc2xhdGUgPSAkZmlsdGVyKCd0cmFuc2xhdGUnKShrZXkpO1xuXG4gICAgICByZXR1cm4gdHJhbnNsYXRlID09PSBrZXkgPyBuYW1lIDogdHJhbnNsYXRlO1xuICAgIH07XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5maWx0ZXIoJ3RCcmVhZGNydW1iJywgdEJyZWFkY3J1bWIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gdEJyZWFkY3J1bWIoJGZpbHRlcikge1xuICAgIC8qKlxuICAgICAqIEZpbHRybyBwYXJhIHRyYWR1w6fDo28gZG8gYnJlYWRjcnVtYiAodGl0dWxvIGRhIHRlbGEgY29tIHJhc3RyZWlvKVxuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IGlkIGNoYXZlIGNvbSBvIG5vbWUgZG8gc3RhdGUgcmVmZXJlbnRlIHRlbGFcbiAgICAgKiBAcmV0dXJucyBhIHRyYWR1w6fDo28gY2FzbyBlbmNvbnRyZSBzZSBuw6NvIG8gaWQgcGFzc2FkbyBwb3IgcGFyYW1ldHJvXG4gICAgICovXG4gICAgcmV0dXJuIGZ1bmN0aW9uIChpZCkge1xuICAgICAgLy9wZWdhIGEgc2VndW5kYSBwYXJ0ZSBkbyBub21lIGRvIHN0YXRlLCByZXRpcmFuZG8gYSBwYXJ0ZSBhYnN0cmF0YSAoYXBwLilcbiAgICAgIHZhciBrZXkgPSAndmlld3MuYnJlYWRjcnVtYnMuJyArIGlkLnNwbGl0KCcuJylbMV07XG4gICAgICB2YXIgdHJhbnNsYXRlID0gJGZpbHRlcigndHJhbnNsYXRlJykoa2V5KTtcblxuICAgICAgcmV0dXJuIHRyYW5zbGF0ZSA9PT0ga2V5ID8gaWQgOiB0cmFuc2xhdGU7XG4gICAgfTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZpbHRlcigndE1vZGVsJywgdE1vZGVsKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIHRNb2RlbCgkZmlsdGVyKSB7XG4gICAgLyoqXG4gICAgICogRmlsdHJvIHBhcmEgdHJhZHXDp8OjbyBkZSB1bSBhdHJpYnV0byBkZSB1bSBtb2RlbFxuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IG5hbWUgbm9tZSBkbyBhdHJpYnV0b1xuICAgICAqIEByZXR1cm5zIG8gbm9tZSBkbyBhdHJpYnV0byB0cmFkdXppZG8gY2FzbyBlbmNvbnRyZSBzZSBuw6NvIG8gbm9tZSBwYXNzYWRvIHBvciBwYXJhbWV0cm9cbiAgICAgKi9cbiAgICByZXR1cm4gZnVuY3Rpb24gKG5hbWUpIHtcbiAgICAgIHZhciBrZXkgPSAnbW9kZWxzLicgKyBuYW1lLnRvTG93ZXJDYXNlKCk7XG4gICAgICB2YXIgdHJhbnNsYXRlID0gJGZpbHRlcigndHJhbnNsYXRlJykoa2V5KTtcblxuICAgICAgcmV0dXJuIHRyYW5zbGF0ZSA9PT0ga2V5ID8gbmFtZSA6IHRyYW5zbGF0ZTtcbiAgICB9O1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLnJ1bihhdXRoZW50aWNhdGlvbkxpc3RlbmVyKTtcblxuICAvKipcbiAgICogTGlzdGVuIGFsbCBzdGF0ZSAocGFnZSkgY2hhbmdlcy4gRXZlcnkgdGltZSBhIHN0YXRlIGNoYW5nZSBuZWVkIHRvIHZlcmlmeSB0aGUgdXNlciBpcyBhdXRoZW50aWNhdGVkIG9yIG5vdCB0b1xuICAgKiByZWRpcmVjdCB0byBjb3JyZWN0IHBhZ2UuIFdoZW4gYSB1c2VyIGNsb3NlIHRoZSBicm93c2VyIHdpdGhvdXQgbG9nb3V0LCB3aGVuIGhpbSByZW9wZW4gdGhlIGJyb3dzZXIgdGhpcyBldmVudFxuICAgKiByZWF1dGhlbnRpY2F0ZSB0aGUgdXNlciB3aXRoIHRoZSBwZXJzaXN0ZW50IHRva2VuIG9mIHRoZSBsb2NhbCBzdG9yYWdlLlxuICAgKlxuICAgKiBXZSBkb24ndCBjaGVjayBpZiB0aGUgdG9rZW4gaXMgZXhwaXJlZCBvciBub3QgaW4gdGhlIHBhZ2UgY2hhbmdlLCBiZWNhdXNlIGlzIGdlbmVyYXRlIGFuIHVuZWNlc3Nhcnkgb3ZlcmhlYWQuXG4gICAqIElmIHRoZSB0b2tlbiBpcyBleHBpcmVkIHdoZW4gdGhlIHVzZXIgdHJ5IHRvIGNhbGwgdGhlIGZpcnN0IGFwaSB0byBnZXQgZGF0YSwgaGltIHdpbGwgYmUgbG9nb2ZmIGFuZCByZWRpcmVjdFxuICAgKiB0byBsb2dpbiBwYWdlLlxuICAgKlxuICAgKiBAcGFyYW0gJHJvb3RTY29wZVxuICAgKiBAcGFyYW0gJHN0YXRlXG4gICAqIEBwYXJhbSAkc3RhdGVQYXJhbXNcbiAgICogQHBhcmFtIEF1dGhcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gYXV0aGVudGljYXRpb25MaXN0ZW5lcigkcm9vdFNjb3BlLCAkc3RhdGUsIEdsb2JhbCwgQXV0aCwgUHJUb2FzdCwgLy8gTk9TT05BUlxuICAkdHJhbnNsYXRlKSB7XG5cbiAgICAvL29ubHkgd2hlbiBhcHBsaWNhdGlvbiBzdGFydCBjaGVjayBpZiB0aGUgZXhpc3RlbnQgdG9rZW4gc3RpbGwgdmFsaWRcbiAgICBBdXRoLnJlbW90ZVZhbGlkYXRlVG9rZW4oKS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgIC8vaWYgdGhlIHRva2VuIGlzIHZhbGlkIGNoZWNrIGlmIGV4aXN0cyB0aGUgdXNlciBiZWNhdXNlIHRoZSBicm93c2VyIGNvdWxkIGJlIGNsb3NlZFxuICAgICAgLy9hbmQgdGhlIHVzZXIgZGF0YSBpc24ndCBpbiBtZW1vcnlcbiAgICAgIGlmIChBdXRoLmN1cnJlbnRVc2VyID09PSBudWxsKSB7XG4gICAgICAgIEF1dGgudXBkYXRlQ3VycmVudFVzZXIoYW5ndWxhci5mcm9tSnNvbihsb2NhbFN0b3JhZ2UuZ2V0SXRlbSgndXNlcicpKSk7XG4gICAgICB9XG4gICAgfSk7XG5cbiAgICAvL0NoZWNrIGlmIHRoZSB0b2tlbiBzdGlsbCB2YWxpZC5cbiAgICAkcm9vdFNjb3BlLiRvbignJHN0YXRlQ2hhbmdlU3RhcnQnLCBmdW5jdGlvbiAoZXZlbnQsIHRvU3RhdGUpIHtcbiAgICAgIGlmICh0b1N0YXRlLmRhdGEubmVlZEF1dGhlbnRpY2F0aW9uIHx8IHRvU3RhdGUuZGF0YS5uZWVkUHJvZmlsZSkge1xuICAgICAgICAvL2RvbnQgdHJhaXQgdGhlIHN1Y2Nlc3MgYmxvY2sgYmVjYXVzZSBhbHJlYWR5IGRpZCBieSB0b2tlbiBpbnRlcmNlcHRvclxuICAgICAgICBBdXRoLnJlbW90ZVZhbGlkYXRlVG9rZW4oKS5jYXRjaChmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgUHJUb2FzdC53YXJuKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMubG9naW4ubG9nb3V0SW5hY3RpdmUnKSk7XG5cbiAgICAgICAgICBpZiAodG9TdGF0ZS5uYW1lICE9PSBHbG9iYWwubG9naW5TdGF0ZSkge1xuICAgICAgICAgICAgJHN0YXRlLmdvKEdsb2JhbC5sb2dpblN0YXRlKTtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICBldmVudC5wcmV2ZW50RGVmYXVsdCgpO1xuICAgICAgICB9KTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIC8vaWYgdGhlIHVzZSBpcyBhdXRoZW50aWNhdGVkIGFuZCBuZWVkIHRvIGVudGVyIGluIGxvZ2luIHBhZ2VcbiAgICAgICAgLy9oaW0gd2lsbCBiZSByZWRpcmVjdGVkIHRvIGhvbWUgcGFnZVxuICAgICAgICBpZiAodG9TdGF0ZS5uYW1lID09PSBHbG9iYWwubG9naW5TdGF0ZSAmJiBBdXRoLmF1dGhlbnRpY2F0ZWQoKSkge1xuICAgICAgICAgICRzdGF0ZS5nbyhHbG9iYWwuaG9tZVN0YXRlKTtcbiAgICAgICAgICBldmVudC5wcmV2ZW50RGVmYXVsdCgpO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykucnVuKGF1dGhvcml6YXRpb25MaXN0ZW5lcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiBhdXRob3JpemF0aW9uTGlzdGVuZXIoJHJvb3RTY29wZSwgJHN0YXRlLCBHbG9iYWwsIEF1dGgpIHtcbiAgICAvKipcbiAgICAgKiBBIGNhZGEgbXVkYW7Dp2EgZGUgZXN0YWRvIChcInDDoWdpbmFcIikgdmVyaWZpY2Egc2UgbyB1c3XDoXJpbyB0ZW0gbyBwZXJmaWxcbiAgICAgKiBuZWNlc3PDoXJpbyBwYXJhIG8gYWNlc3NvIGEgbWVzbWFcbiAgICAgKi9cbiAgICAkcm9vdFNjb3BlLiRvbignJHN0YXRlQ2hhbmdlU3RhcnQnLCBmdW5jdGlvbiAoZXZlbnQsIHRvU3RhdGUpIHtcbiAgICAgIGlmICh0b1N0YXRlLmRhdGEgJiYgdG9TdGF0ZS5kYXRhLm5lZWRBdXRoZW50aWNhdGlvbiAmJiB0b1N0YXRlLmRhdGEubmVlZFByb2ZpbGUgJiYgQXV0aC5hdXRoZW50aWNhdGVkKCkgJiYgIUF1dGguY3VycmVudFVzZXIuaGFzUHJvZmlsZSh0b1N0YXRlLmRhdGEubmVlZFByb2ZpbGUsIHRvU3RhdGUuZGF0YS5hbGxQcm9maWxlcykpIHtcblxuICAgICAgICAkc3RhdGUuZ28oR2xvYmFsLm5vdEF1dGhvcml6ZWRTdGF0ZSk7XG4gICAgICAgIGV2ZW50LnByZXZlbnREZWZhdWx0KCk7XG4gICAgICB9XG4gICAgfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29uZmlnKHNwaW5uZXJJbnRlcmNlcHRvcik7XG5cbiAgZnVuY3Rpb24gc3Bpbm5lckludGVyY2VwdG9yKCRodHRwUHJvdmlkZXIsICRwcm92aWRlKSB7XG4gICAgLyoqXG4gICAgICogRXN0ZSBpbnRlcmNlcHRvciDDqSByZXNwb25zw6F2ZWwgcG9yIG1vc3RyYXIgZSBlc2NvbmRlciBvXG4gICAgICogY29tcG9uZW50ZSBQclNwaW5uZXIgc2VtcHJlIHF1ZSB1bWEgcmVxdWlzacOnw6NvIGFqYXhcbiAgICAgKiBpbmljaWFyIGUgZmluYWxpemFyLlxuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9ICRxXG4gICAgICogQHBhcmFtIHthbnl9ICRpbmplY3RvclxuICAgICAqIEByZXR1cm5zXG4gICAgICovXG4gICAgZnVuY3Rpb24gc2hvd0hpZGVTcGlubmVyKCRxLCAkaW5qZWN0b3IpIHtcbiAgICAgIHJldHVybiB7XG4gICAgICAgIHJlcXVlc3Q6IGZ1bmN0aW9uIHJlcXVlc3QoY29uZmlnKSB7XG4gICAgICAgICAgJGluamVjdG9yLmdldCgnUHJTcGlubmVyJykuc2hvdygpO1xuXG4gICAgICAgICAgcmV0dXJuIGNvbmZpZztcbiAgICAgICAgfSxcblxuICAgICAgICByZXNwb25zZTogZnVuY3Rpb24gcmVzcG9uc2UoX3Jlc3BvbnNlKSB7XG4gICAgICAgICAgJGluamVjdG9yLmdldCgnUHJTcGlubmVyJykuaGlkZSgpO1xuXG4gICAgICAgICAgcmV0dXJuIF9yZXNwb25zZTtcbiAgICAgICAgfSxcblxuICAgICAgICByZXNwb25zZUVycm9yOiBmdW5jdGlvbiByZXNwb25zZUVycm9yKHJlamVjdGlvbikge1xuICAgICAgICAgICRpbmplY3Rvci5nZXQoJ1ByU3Bpbm5lcicpLmhpZGUoKTtcblxuICAgICAgICAgIHJldHVybiAkcS5yZWplY3QocmVqZWN0aW9uKTtcbiAgICAgICAgfVxuICAgICAgfTtcbiAgICB9XG5cbiAgICAvLyBEZWZpbmUgdW1hIGZhY3RvcnkgcGFyYSBvICRodHRwSW50ZXJjZXB0b3JcbiAgICAkcHJvdmlkZS5mYWN0b3J5KCdzaG93SGlkZVNwaW5uZXInLCBzaG93SGlkZVNwaW5uZXIpO1xuXG4gICAgLy8gQWRpY2lvbmEgYSBmYWN0b3J5IG5vIGFycmF5IGRlIGludGVyY2VwdG9ycyBkbyAkaHR0cFxuICAgICRodHRwUHJvdmlkZXIuaW50ZXJjZXB0b3JzLnB1c2goJ3Nob3dIaWRlU3Bpbm5lcicpO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4vKmVzbGludCBhbmd1bGFyL21vZHVsZS1nZXR0ZXI6IDAqL1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbmZpZyh0b2tlbkludGVyY2VwdG9yKTtcblxuICAvKipcbiAgICogSW50ZXJjZXB0IGFsbCByZXNwb25zZSAoc3VjY2VzcyBvciBlcnJvcikgdG8gdmVyaWZ5IHRoZSByZXR1cm5lZCB0b2tlblxuICAgKlxuICAgKiBAcGFyYW0gJGh0dHBQcm92aWRlclxuICAgKiBAcGFyYW0gJHByb3ZpZGVcbiAgICogQHBhcmFtIEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiB0b2tlbkludGVyY2VwdG9yKCRodHRwUHJvdmlkZXIsICRwcm92aWRlLCBHbG9iYWwpIHtcblxuICAgIGZ1bmN0aW9uIHJlZGlyZWN0V2hlblNlcnZlckxvZ2dlZE91dCgkcSwgJGluamVjdG9yKSB7XG4gICAgICByZXR1cm4ge1xuICAgICAgICByZXF1ZXN0OiBmdW5jdGlvbiByZXF1ZXN0KGNvbmZpZykge1xuICAgICAgICAgIHZhciB0b2tlbiA9ICRpbmplY3Rvci5nZXQoJ0F1dGgnKS5nZXRUb2tlbigpO1xuXG4gICAgICAgICAgaWYgKHRva2VuKSB7XG4gICAgICAgICAgICBjb25maWcuaGVhZGVyc1snQXV0aG9yaXphdGlvbiddID0gJ0JlYXJlciAnICsgdG9rZW47XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgcmV0dXJuIGNvbmZpZztcbiAgICAgICAgfSxcbiAgICAgICAgcmVzcG9uc2U6IGZ1bmN0aW9uIHJlc3BvbnNlKF9yZXNwb25zZSkge1xuICAgICAgICAgIC8vIGdldCBhIG5ldyByZWZyZXNoIHRva2VuIHRvIHVzZSBpbiB0aGUgbmV4dCByZXF1ZXN0XG4gICAgICAgICAgdmFyIHRva2VuID0gX3Jlc3BvbnNlLmhlYWRlcnMoJ0F1dGhvcml6YXRpb24nKTtcblxuICAgICAgICAgIGlmICh0b2tlbikge1xuICAgICAgICAgICAgJGluamVjdG9yLmdldCgnQXV0aCcpLnNldFRva2VuKHRva2VuLnNwbGl0KCcgJylbMV0pO1xuICAgICAgICAgIH1cbiAgICAgICAgICByZXR1cm4gX3Jlc3BvbnNlO1xuICAgICAgICB9LFxuICAgICAgICByZXNwb25zZUVycm9yOiBmdW5jdGlvbiByZXNwb25zZUVycm9yKHJlamVjdGlvbikge1xuICAgICAgICAgIC8vIEluc3RlYWQgb2YgY2hlY2tpbmcgZm9yIGEgc3RhdHVzIGNvZGUgb2YgNDAwIHdoaWNoIG1pZ2h0IGJlIHVzZWRcbiAgICAgICAgICAvLyBmb3Igb3RoZXIgcmVhc29ucyBpbiBMYXJhdmVsLCB3ZSBjaGVjayBmb3IgdGhlIHNwZWNpZmljIHJlamVjdGlvblxuICAgICAgICAgIC8vIHJlYXNvbnMgdG8gdGVsbCB1cyBpZiB3ZSBuZWVkIHRvIHJlZGlyZWN0IHRvIHRoZSBsb2dpbiBzdGF0ZVxuICAgICAgICAgIHZhciByZWplY3Rpb25SZWFzb25zID0gWyd0b2tlbl9ub3RfcHJvdmlkZWQnLCAndG9rZW5fZXhwaXJlZCcsICd0b2tlbl9hYnNlbnQnLCAndG9rZW5faW52YWxpZCddO1xuXG4gICAgICAgICAgdmFyIHRva2VuRXJyb3IgPSBmYWxzZTtcblxuICAgICAgICAgIGFuZ3VsYXIuZm9yRWFjaChyZWplY3Rpb25SZWFzb25zLCBmdW5jdGlvbiAodmFsdWUpIHtcbiAgICAgICAgICAgIGlmIChyZWplY3Rpb24uZGF0YSAmJiByZWplY3Rpb24uZGF0YS5lcnJvciA9PT0gdmFsdWUpIHtcbiAgICAgICAgICAgICAgdG9rZW5FcnJvciA9IHRydWU7XG5cbiAgICAgICAgICAgICAgJGluamVjdG9yLmdldCgnQXV0aCcpLmxvZ291dCgpLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgIHZhciAkc3RhdGUgPSAkaW5qZWN0b3IuZ2V0KCckc3RhdGUnKTtcblxuICAgICAgICAgICAgICAgIC8vIGluIGNhc2UgbXVsdGlwbGUgYWpheCByZXF1ZXN0IGZhaWwgYXQgc2FtZSB0aW1lIGJlY2F1c2UgdG9rZW4gcHJvYmxlbXMsXG4gICAgICAgICAgICAgICAgLy8gb25seSB0aGUgZmlyc3Qgd2lsbCByZWRpcmVjdFxuICAgICAgICAgICAgICAgIGlmICghJHN0YXRlLmlzKEdsb2JhbC5sb2dpblN0YXRlKSkge1xuICAgICAgICAgICAgICAgICAgJHN0YXRlLmdvKEdsb2JhbC5sb2dpblN0YXRlKTtcblxuICAgICAgICAgICAgICAgICAgLy9jbG9zZSBhbnkgZGlhbG9nIHRoYXQgaXMgb3BlbmVkXG4gICAgICAgICAgICAgICAgICAkaW5qZWN0b3IuZ2V0KCdQckRpYWxvZycpLmNsb3NlKCk7XG5cbiAgICAgICAgICAgICAgICAgIGV2ZW50LnByZXZlbnREZWZhdWx0KCk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9KTtcblxuICAgICAgICAgIC8vZGVmaW5lIGRhdGEgdG8gZW1wdHkgYmVjYXVzZSBhbHJlYWR5IHNob3cgUHJUb2FzdCB0b2tlbiBtZXNzYWdlXG4gICAgICAgICAgaWYgKHRva2VuRXJyb3IpIHtcbiAgICAgICAgICAgIHJlamVjdGlvbi5kYXRhID0ge307XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbihyZWplY3Rpb24uaGVhZGVycykpIHtcbiAgICAgICAgICAgIC8vIG1hbnkgc2VydmVycyBlcnJvcnMgKGJ1c2luZXNzKSBhcmUgaW50ZXJjZXB0IGhlcmUgYnV0IGdlbmVyYXRlZCBhIG5ldyByZWZyZXNoIHRva2VuXG4gICAgICAgICAgICAvLyBhbmQgbmVlZCB1cGRhdGUgY3VycmVudCB0b2tlblxuICAgICAgICAgICAgdmFyIHRva2VuID0gcmVqZWN0aW9uLmhlYWRlcnMoJ0F1dGhvcml6YXRpb24nKTtcblxuICAgICAgICAgICAgaWYgKHRva2VuKSB7XG4gICAgICAgICAgICAgICRpbmplY3Rvci5nZXQoJ0F1dGgnKS5zZXRUb2tlbih0b2tlbi5zcGxpdCgnICcpWzFdKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9XG5cbiAgICAgICAgICByZXR1cm4gJHEucmVqZWN0KHJlamVjdGlvbik7XG4gICAgICAgIH1cbiAgICAgIH07XG4gICAgfVxuXG4gICAgLy8gU2V0dXAgZm9yIHRoZSAkaHR0cEludGVyY2VwdG9yXG4gICAgJHByb3ZpZGUuZmFjdG9yeSgncmVkaXJlY3RXaGVuU2VydmVyTG9nZ2VkT3V0JywgcmVkaXJlY3RXaGVuU2VydmVyTG9nZ2VkT3V0KTtcblxuICAgIC8vIFB1c2ggdGhlIG5ldyBmYWN0b3J5IG9udG8gdGhlICRodHRwIGludGVyY2VwdG9yIGFycmF5XG4gICAgJGh0dHBQcm92aWRlci5pbnRlcmNlcHRvcnMucHVzaCgncmVkaXJlY3RXaGVuU2VydmVyTG9nZ2VkT3V0Jyk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29uZmlnKHZhbGlkYXRpb25JbnRlcmNlcHRvcik7XG5cbiAgZnVuY3Rpb24gdmFsaWRhdGlvbkludGVyY2VwdG9yKCRodHRwUHJvdmlkZXIsICRwcm92aWRlKSB7XG4gICAgLyoqXG4gICAgICogRXN0ZSBpbnRlcmNlcHRvciDDqSByZXNwb25zw6F2ZWwgcG9yIG1vc3RyYXIgYXNcbiAgICAgKiBtZW5zYWdlbnMgZGUgZXJybyByZWZlcmVudGUgYXMgdmFsaWRhw6fDtWVzIGRvIGJhY2stZW5kXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gJHFcbiAgICAgKiBAcGFyYW0ge2FueX0gJGluamVjdG9yXG4gICAgICogQHJldHVybnNcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBzaG93RXJyb3JWYWxpZGF0aW9uKCRxLCAkaW5qZWN0b3IpIHtcbiAgICAgIHJldHVybiB7XG4gICAgICAgIHJlc3BvbnNlRXJyb3I6IGZ1bmN0aW9uIHJlc3BvbnNlRXJyb3IocmVqZWN0aW9uKSB7XG4gICAgICAgICAgdmFyIFByVG9hc3QgPSAkaW5qZWN0b3IuZ2V0KCdQclRvYXN0Jyk7XG4gICAgICAgICAgdmFyICR0cmFuc2xhdGUgPSAkaW5qZWN0b3IuZ2V0KCckdHJhbnNsYXRlJyk7XG5cbiAgICAgICAgICBpZiAocmVqZWN0aW9uLmNvbmZpZy5kYXRhICYmICFyZWplY3Rpb24uY29uZmlnLmRhdGEuc2tpcFZhbGlkYXRpb24pIHtcbiAgICAgICAgICAgIGlmIChyZWplY3Rpb24uZGF0YSAmJiByZWplY3Rpb24uZGF0YS5lcnJvcikge1xuXG4gICAgICAgICAgICAgIC8vdmVyaWZpY2Egc2Ugb2NvcnJldSBhbGd1bSBlcnJvIHJlZmVyZW50ZSBhbyB0b2tlblxuICAgICAgICAgICAgICBpZiAocmVqZWN0aW9uLmRhdGEuZXJyb3Iuc3RhcnRzV2l0aCgndG9rZW5fJykpIHtcbiAgICAgICAgICAgICAgICBQclRvYXN0Lndhcm4oJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5sb2dpbi5sb2dvdXRJbmFjdGl2ZScpKTtcbiAgICAgICAgICAgICAgfSBlbHNlIGlmIChyZWplY3Rpb24uZGF0YS5lcnJvciAhPT0gJ05vdCBGb3VuZCcpIHtcbiAgICAgICAgICAgICAgICBQclRvYXN0LmVycm9yKCR0cmFuc2xhdGUuaW5zdGFudChyZWplY3Rpb24uZGF0YS5lcnJvcikpO1xuICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICBQclRvYXN0LmVycm9yVmFsaWRhdGlvbihyZWplY3Rpb24uZGF0YSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgcmV0dXJuICRxLnJlamVjdChyZWplY3Rpb24pO1xuICAgICAgICB9XG4gICAgICB9O1xuICAgIH1cblxuICAgIC8vIERlZmluZSB1bWEgZmFjdG9yeSBwYXJhIG8gJGh0dHBJbnRlcmNlcHRvclxuICAgICRwcm92aWRlLmZhY3RvcnkoJ3Nob3dFcnJvclZhbGlkYXRpb24nLCBzaG93RXJyb3JWYWxpZGF0aW9uKTtcblxuICAgIC8vIEFkaWNpb25hIGEgZmFjdG9yeSBubyBhcnJheSBkZSBpbnRlcmNlcHRvcnMgZG8gJGh0dHBcbiAgICAkaHR0cFByb3ZpZGVyLmludGVyY2VwdG9ycy5wdXNoKCdzaG93RXJyb3JWYWxpZGF0aW9uJyk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb250cm9sbGVyKCdLYW5iYW5Db250cm9sbGVyJywgS2FuYmFuQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBLYW5iYW5Db250cm9sbGVyKCRjb250cm9sbGVyLCBUYXNrc1NlcnZpY2UsIFN0YXR1c1NlcnZpY2UsICRtZERpYWxvZywgJGRvY3VtZW50KSB7XG4gICAgLy9BdHRyaWJ1dGVzIEJsb2NrXG4gICAgdmFyIHZtID0gdGhpcztcbiAgICB2YXIgZmllbGRzID0gW3sgbmFtZTogJ2lkJywgdHlwZTogJ3N0cmluZycgfSwgeyBuYW1lOiAnc3RhdHVzJywgbWFwOiAnc3RhdGUnLCB0eXBlOiAnc3RyaW5nJyB9LCB7IG5hbWU6ICd0ZXh0JywgbWFwOiAnbGFiZWwnLCB0eXBlOiAnc3RyaW5nJyB9LCB7IG5hbWU6ICd0YWdzJywgdHlwZTogJ3N0cmluZycgfV07XG5cbiAgICB2bS5vbkFjdGl2YXRlID0gZnVuY3Rpb24gKCkge1xuICAgICAgdm0ucHJvamVjdCA9IGxvY2FsU3RvcmFnZS5nZXRJdGVtKCdwcm9qZWN0Jyk7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMgPSB7IHByb2plY3RfaWQ6IHZtLnByb2plY3QgfTtcbiAgICB9O1xuXG4gICAgdm0uYXBwbHlGaWx0ZXJzID0gZnVuY3Rpb24gKGRlZmF1bHRRdWVyeUZpbHRlcnMpIHtcbiAgICAgIHJldHVybiBhbmd1bGFyLmV4dGVuZChkZWZhdWx0UXVlcnlGaWx0ZXJzLCB2bS5xdWVyeUZpbHRlcnMpO1xuICAgIH07XG5cbiAgICB2bS5hZnRlclNlYXJjaCA9IGZ1bmN0aW9uICgpIHtcbiAgICAgIHZhciBjb2x1bW5zID0gW107XG4gICAgICB2YXIgdGFza3MgPSBbXTtcblxuICAgICAgU3RhdHVzU2VydmljZS5xdWVyeSgpLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgIHJlc3BvbnNlLmZvckVhY2goZnVuY3Rpb24gKHN0YXR1cykge1xuICAgICAgICAgIGNvbHVtbnMucHVzaCh7IHRleHQ6IHN0YXR1cy5uYW1lLCBkYXRhRmllbGQ6IHN0YXR1cy5zbHVnIH0pO1xuICAgICAgICB9KTtcblxuICAgICAgICBpZiAodm0ucmVzb3VyY2VzLmxlbmd0aCA+IDApIHtcbiAgICAgICAgICB2bS5yZXNvdXJjZXMuZm9yRWFjaChmdW5jdGlvbiAodGFzaykge1xuICAgICAgICAgICAgdGFza3MucHVzaCh7XG4gICAgICAgICAgICAgIGlkOiB0YXNrLmlkLFxuICAgICAgICAgICAgICBzdGF0ZTogdGFzay5zdGF0dXMuc2x1ZyxcbiAgICAgICAgICAgICAgbGFiZWw6IHRhc2sudGl0bGUsXG4gICAgICAgICAgICAgIHRhZ3M6IHRhc2sudHlwZS5uYW1lICsgJywgJyArIHRhc2sucHJpb3JpdHkubmFtZVxuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgfSk7XG5cbiAgICAgICAgICB2YXIgc291cmNlID0ge1xuICAgICAgICAgICAgbG9jYWxEYXRhOiB0YXNrcyxcbiAgICAgICAgICAgIGRhdGFUeXBlOiAnYXJyYXknLFxuICAgICAgICAgICAgZGF0YUZpZWxkczogZmllbGRzXG4gICAgICAgICAgfTtcbiAgICAgICAgICB2YXIgZGF0YUFkYXB0ZXIgPSBuZXcgJC5qcXguZGF0YUFkYXB0ZXIoc291cmNlKTtcblxuICAgICAgICAgIHZtLnNldHRpbmdzID0ge1xuICAgICAgICAgICAgc291cmNlOiBkYXRhQWRhcHRlcixcbiAgICAgICAgICAgIGNvbHVtbnM6IGNvbHVtbnMsXG4gICAgICAgICAgICB0aGVtZTogJ2xpZ2h0J1xuICAgICAgICAgIH07XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgdm0uc2V0dGluZ3MgPSB7XG4gICAgICAgICAgICBzb3VyY2U6IFt7fV0sXG4gICAgICAgICAgICBjb2x1bW5zOiBjb2x1bW5zLFxuICAgICAgICAgICAgdGhlbWU6ICdsaWdodCdcbiAgICAgICAgICB9O1xuICAgICAgICB9XG4gICAgICAgIHZtLmthbmJhblJlYWR5ID0gdHJ1ZTtcbiAgICAgIH0pO1xuICAgIH07XG5cbiAgICB2bS5vbkl0ZW1Nb3ZlZCA9IGZ1bmN0aW9uIChldmVudCkge1xuICAgICAgVGFza3NTZXJ2aWNlLnVwZGF0ZVRhc2tCeUthbmJhbih7XG4gICAgICAgIHByb2plY3RfaWQ6IHZtLnByb2plY3QsXG4gICAgICAgIGlkOiBldmVudC5hcmdzLml0ZW1JZCxcbiAgICAgICAgb2xkQ29sdW1uOiBldmVudC5hcmdzLm9sZENvbHVtbixcbiAgICAgICAgbmV3Q29sdW1uOiBldmVudC5hcmdzLm5ld0NvbHVtbiB9KS50aGVuKGZ1bmN0aW9uICgpIHt9KTtcbiAgICB9O1xuXG4gICAgdm0ub25JdGVtQ2xpY2tlZCA9IGZ1bmN0aW9uIChldmVudCkge1xuICAgICAgVGFza3NTZXJ2aWNlLnF1ZXJ5KHsgdGFza19pZDogZXZlbnQuYXJncy5pdGVtSWQgfSkudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgdm0udGFza0luZm8gPSByZXNwb25zZVswXTtcbiAgICAgICAgJG1kRGlhbG9nLnNob3coe1xuICAgICAgICAgIHBhcmVudDogYW5ndWxhci5lbGVtZW50KCRkb2N1bWVudC5ib2R5KSxcbiAgICAgICAgICB0ZW1wbGF0ZVVybDogJ2NsaWVudC9hcHAva2FuYmFuL3Rhc2staW5mby1kaWFsb2cvdGFza0luZm8uaHRtbCcsXG4gICAgICAgICAgY29udHJvbGxlckFzOiAndGFza0luZm9DdHJsJyxcbiAgICAgICAgICBjb250cm9sbGVyOiAnVGFza0luZm9Db250cm9sbGVyJyxcbiAgICAgICAgICBiaW5kVG9Db250cm9sbGVyOiB0cnVlLFxuICAgICAgICAgIGxvY2Fsczoge1xuICAgICAgICAgICAgdGFzazogdm0udGFza0luZm8sXG4gICAgICAgICAgICBjbG9zZTogY2xvc2VcbiAgICAgICAgICB9LFxuICAgICAgICAgIGVzY2FwZVRvQ2xvc2U6IHRydWUsXG4gICAgICAgICAgY2xpY2tPdXRzaWRlVG9DbG9zZTogdHJ1ZVxuICAgICAgICB9KTtcbiAgICAgIH0pO1xuICAgIH07XG5cbiAgICBmdW5jdGlvbiBjbG9zZSgpIHtcbiAgICAgICRtZERpYWxvZy5oaWRlKCk7XG4gICAgfVxuXG4gICAgLy8gaW5zdGFudGlhdGUgYmFzZSBjb250cm9sbGVyXG4gICAgJGNvbnRyb2xsZXIoJ0NSVURDb250cm9sbGVyJywgeyB2bTogdm0sIG1vZGVsU2VydmljZTogVGFza3NTZXJ2aWNlLCBvcHRpb25zOiB7fSB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25maWcocm91dGVzKTtcblxuICAvKipcbiAgICogQXJxdWl2byBkZSBjb25maWd1cmHDp8OjbyBjb20gYXMgcm90YXMgZXNwZWPDrWZpY2FzIGRvIHJlY3Vyc28ga2FuYmFuXG4gICAqXG4gICAqIEBwYXJhbSB7b2JqZWN0fSAkc3RhdGVQcm92aWRlclxuICAgKiBAcGFyYW0ge29iamVjdH0gR2xvYmFsXG4gICAqL1xuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvdXRlcygkc3RhdGVQcm92aWRlciwgR2xvYmFsKSB7XG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ2FwcC5rYW5iYW4nLCB7XG4gICAgICB1cmw6ICcva2FuYmFuJyxcbiAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcva2FuYmFuL2thbmJhbi5odG1sJyxcbiAgICAgIGNvbnRyb2xsZXI6ICdLYW5iYW5Db250cm9sbGVyIGFzIGthbmJhbkN0cmwnLFxuICAgICAgZGF0YToge31cbiAgICB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5mYWN0b3J5KCdLYW5iYW5TZXJ2aWNlJywgS2FuYmFuU2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiBLYW5iYW5TZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgdmFyIG1vZGVsID0gc2VydmljZUZhY3RvcnkoJ2thbmJhbicsIHtcbiAgICAgIGFjdGlvbnM6IHt9LFxuICAgICAgaW5zdGFuY2U6IHt9XG4gICAgfSk7XG5cbiAgICByZXR1cm4gbW9kZWw7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbi8qZXNsaW50LWVudiBlczYqL1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29udHJvbGxlcignTWVudUNvbnRyb2xsZXInLCBNZW51Q29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiBNZW51Q29udHJvbGxlcigkbWRTaWRlbmF2LCAkc3RhdGUsICRtZENvbG9ycykge1xuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICAvL0Jsb2NvIGRlIGRlY2xhcmFjb2VzIGRlIGZ1bmNvZXNcbiAgICB2bS5vcGVuID0gb3BlbjtcbiAgICB2bS5vcGVuTWVudU9yUmVkaXJlY3RUb1N0YXRlID0gb3Blbk1lbnVPclJlZGlyZWN0VG9TdGF0ZTtcblxuICAgIGFjdGl2YXRlKCk7XG5cbiAgICBmdW5jdGlvbiBhY3RpdmF0ZSgpIHtcbiAgICAgIHZhciBtZW51UHJlZml4ID0gJ3ZpZXdzLmxheW91dC5tZW51Lic7XG5cbiAgICAgIC8vIEFycmF5IGNvbnRlbmRvIG9zIGl0ZW5zIHF1ZSBzw6NvIG1vc3RyYWRvcyBubyBtZW51IGxhdGVyYWxcbiAgICAgIHZtLml0ZW5zTWVudSA9IFt7IHN0YXRlOiAnYXBwLnByb2plY3RzJywgdGl0bGU6IG1lbnVQcmVmaXggKyAncHJvamVjdHMnLCBpY29uOiAnd29yaycsIHN1Ykl0ZW5zOiBbXSB9LCB7IHN0YXRlOiAnYXBwLmRhc2hib2FyZCcsIHRpdGxlOiBtZW51UHJlZml4ICsgJ2Rhc2hib2FyZCcsIGljb246ICdkYXNoYm9hcmQnLCBzdWJJdGVuczogW10gfSwgeyBzdGF0ZTogJ2FwcC50YXNrcycsIHRpdGxlOiBtZW51UHJlZml4ICsgJ3Rhc2tzJywgaWNvbjogJ3ZpZXdfbGlzdCcsIHN1Ykl0ZW5zOiBbXSB9LCB7IHN0YXRlOiAnYXBwLm1pbGVzdG9uZXMnLCB0aXRsZTogbWVudVByZWZpeCArICdtaWxlc3RvbmVzJywgaWNvbjogJ3ZpZXdfbW9kdWxlJywgc3ViSXRlbnM6IFtdIH0sIHsgc3RhdGU6ICdhcHAucmVsZWFzZXMnLCB0aXRsZTogbWVudVByZWZpeCArICdyZWxlYXNlcycsIGljb246ICdzdWJzY3JpcHRpb25zJywgc3ViSXRlbnM6IFtdIH0sIHsgc3RhdGU6ICdhcHAua2FuYmFuJywgdGl0bGU6IG1lbnVQcmVmaXggKyAna2FuYmFuJywgaWNvbjogJ3ZpZXdfY29sdW1uJywgc3ViSXRlbnM6IFtdIH0sIHsgc3RhdGU6ICdhcHAudmNzJywgdGl0bGU6IG1lbnVQcmVmaXggKyAndmNzJywgaWNvbjogJ2dyb3VwX3dvcmsnLCBzdWJJdGVuczogW11cbiAgICAgICAgLy8gQ29sb3F1ZSBzZXVzIGl0ZW5zIGRlIG1lbnUgYSBwYXJ0aXIgZGVzdGUgcG9udG9cbiAgICAgICAgLyoge1xuICAgICAgICAgIHN0YXRlOiAnIycsIHRpdGxlOiBtZW51UHJlZml4ICsgJ2FkbWluJywgaWNvbjogJ3NldHRpbmdzX2FwcGxpY2F0aW9ucycsIHByb2ZpbGVzOiBbJ2FkbWluJ10sXG4gICAgICAgICAgc3ViSXRlbnM6IFtcbiAgICAgICAgICAgIHsgc3RhdGU6ICdhcHAudXNlcicsIHRpdGxlOiBtZW51UHJlZml4ICsgJ3VzZXInLCBpY29uOiAncGVvcGxlJyB9LFxuICAgICAgICAgICAgeyBzdGF0ZTogJ2FwcC5tYWlsJywgdGl0bGU6IG1lbnVQcmVmaXggKyAnbWFpbCcsIGljb246ICdtYWlsJyB9LFxuICAgICAgICAgICAgeyBzdGF0ZTogJ2FwcC5hdWRpdCcsIHRpdGxlOiBtZW51UHJlZml4ICsgJ2F1ZGl0JywgaWNvbjogJ3N0b3JhZ2UnIH0sXG4gICAgICAgICAgICB7IHN0YXRlOiAnYXBwLmRpbmFtaWMtcXVlcnknLCB0aXRsZTogbWVudVByZWZpeCArICdkaW5hbWljUXVlcnknLCBpY29uOiAnbG9jYXRpb25fc2VhcmNoaW5nJyB9XG4gICAgICAgICAgXVxuICAgICAgICB9ICovXG4gICAgICB9XTtcblxuICAgICAgLyoqXG4gICAgICAgKiBPYmpldG8gcXVlIHByZWVuY2hlIG8gbmctc3R5bGUgZG8gbWVudSBsYXRlcmFsIHRyb2NhbmRvIGFzIGNvcmVzXG4gICAgICAgKi9cbiAgICAgIHZtLnNpZGVuYXZTdHlsZSA9IHtcbiAgICAgICAgdG9wOiB7XG4gICAgICAgICAgJ2JvcmRlci1ib3R0b20nOiAnMXB4IHNvbGlkIHJnYigyMTAsIDIxMCwgMjEwKScsXG4gICAgICAgICAgJ2JhY2tncm91bmQtaW1hZ2UnOiAnLXdlYmtpdC1saW5lYXItZ3JhZGllbnQodG9wLCByZ2IoMTQ0LCAxNDQsIDE0NCksIHJnYigyMTAsIDIxMCwgMjEwKSknXG4gICAgICAgIH0sXG4gICAgICAgIGNvbnRlbnQ6IHtcbiAgICAgICAgICAnYmFja2dyb3VuZC1jb2xvcic6ICdyZ2IoMjEwLCAyMTAsIDIxMCknXG4gICAgICAgIH0sXG4gICAgICAgIHRleHRDb2xvcjoge1xuICAgICAgICAgIGNvbG9yOiAnI0ZGRidcbiAgICAgICAgfSxcbiAgICAgICAgbGluZUJvdHRvbToge1xuICAgICAgICAgICdib3JkZXItYm90dG9tJzogJzFweCBzb2xpZCAnICsgZ2V0Q29sb3IoJ3ByaW1hcnktNDAwJylcbiAgICAgICAgfVxuICAgICAgfTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBvcGVuKCkge1xuICAgICAgJG1kU2lkZW5hdignbGVmdCcpLnRvZ2dsZSgpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIE3DqXRvZG8gcXVlIGV4aWJlIG8gc3ViIG1lbnUgZG9zIGl0ZW5zIGRvIG1lbnUgbGF0ZXJhbCBjYXNvIHRlbmhhIHN1YiBpdGVuc1xuICAgICAqIGNhc28gY29udHLDoXJpbyByZWRpcmVjaW9uYSBwYXJhIG8gc3RhdGUgcGFzc2FkbyBjb21vIHBhcsODwqJtZXRyb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIG9wZW5NZW51T3JSZWRpcmVjdFRvU3RhdGUoJG1kTWVudSwgZXYsIGl0ZW0pIHtcbiAgICAgIGlmIChhbmd1bGFyLmlzRGVmaW5lZChpdGVtLnN1Ykl0ZW5zKSAmJiBpdGVtLnN1Ykl0ZW5zLmxlbmd0aCA+IDApIHtcbiAgICAgICAgJG1kTWVudS5vcGVuKGV2KTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgICRzdGF0ZS5nbyhpdGVtLnN0YXRlLCB7IG9iajogbnVsbCB9KTtcbiAgICAgICAgJG1kU2lkZW5hdignbGVmdCcpLmNsb3NlKCk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gZ2V0Q29sb3IoY29sb3JQYWxldHRlcykge1xuICAgICAgcmV0dXJuICRtZENvbG9ycy5nZXRUaGVtZUNvbG9yKGNvbG9yUGFsZXR0ZXMpO1xuICAgIH1cbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbnRyb2xsZXIoJ01haWxzQ29udHJvbGxlcicsIE1haWxzQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBNYWlsc0NvbnRyb2xsZXIoTWFpbHNTZXJ2aWNlLCBVc2Vyc1NlcnZpY2UsIFByRGlhbG9nLCBQclRvYXN0LCAvLyBOT1NPTkFSXG4gICRxLCBsb2Rhc2gsICR0cmFuc2xhdGUsIEdsb2JhbCkge1xuXG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIHZtLmZpbHRlclNlbGVjdGVkID0gZmFsc2U7XG4gICAgdm0ub3B0aW9ucyA9IHtcbiAgICAgIHNraW46ICdrYW1hJyxcbiAgICAgIGxhbmd1YWdlOiAncHQtYnInLFxuICAgICAgYWxsb3dlZENvbnRlbnQ6IHRydWUsXG4gICAgICBlbnRpdGllczogdHJ1ZSxcbiAgICAgIGhlaWdodDogMzAwLFxuICAgICAgZXh0cmFQbHVnaW5zOiAnZGlhbG9nLGZpbmQsY29sb3JkaWFsb2cscHJldmlldyxmb3JtcyxpZnJhbWUsZmxhc2gnXG4gICAgfTtcblxuICAgIHZtLmxvYWRVc2VycyA9IGxvYWRVc2VycztcbiAgICB2bS5vcGVuVXNlckRpYWxvZyA9IG9wZW5Vc2VyRGlhbG9nO1xuICAgIHZtLmFkZFVzZXJNYWlsID0gYWRkVXNlck1haWw7XG4gICAgdm0uY2xlYW5Gb3JtID0gY2xlYW5Gb3JtO1xuICAgIHZtLnNlbmQgPSBzZW5kO1xuXG4gICAgYWN0aXZhdGUoKTtcblxuICAgIGZ1bmN0aW9uIGFjdGl2YXRlKCkge1xuICAgICAgdm0uY2xlYW5Gb3JtKCk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhbGl6YSBhIGJ1c2NhIHBlbG8gdXN1w6FyaW8gcmVtb3RhbWVudGVcbiAgICAgKlxuICAgICAqIEBwYXJhbXMge3N0cmluZ30gLSBSZWNlYmUgbyB2YWxvciBwYXJhIHNlciBwZXNxdWlzYWRvXG4gICAgICogQHJldHVybiB7cHJvbWlzc2V9IC0gUmV0b3JuYSB1bWEgcHJvbWlzc2UgcXVlIG8gY29tcG9uZXRlIHJlc29sdmVcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBsb2FkVXNlcnMoY3JpdGVyaWEpIHtcbiAgICAgIHZhciBkZWZlcnJlZCA9ICRxLmRlZmVyKCk7XG5cbiAgICAgIFVzZXJzU2VydmljZS5xdWVyeSh7XG4gICAgICAgIG5hbWVPckVtYWlsOiBjcml0ZXJpYSxcbiAgICAgICAgbm90VXNlcnM6IGxvZGFzaC5tYXAodm0ubWFpbC51c2VycywgbG9kYXNoLnByb3BlcnR5KCdpZCcpKS50b1N0cmluZygpLFxuICAgICAgICBsaW1pdDogNVxuICAgICAgfSkudGhlbihmdW5jdGlvbiAoZGF0YSkge1xuXG4gICAgICAgIC8vIHZlcmlmaWNhIHNlIG5hIGxpc3RhIGRlIHVzdWFyaW9zIGrDoSBleGlzdGUgbyB1c3XDoXJpbyBjb20gbyBlbWFpbCBwZXNxdWlzYWRvXG4gICAgICAgIGRhdGEgPSBsb2Rhc2guZmlsdGVyKGRhdGEsIGZ1bmN0aW9uICh1c2VyKSB7XG4gICAgICAgICAgcmV0dXJuICFsb2Rhc2guZmluZCh2bS5tYWlsLnVzZXJzLCB7IGVtYWlsOiB1c2VyLmVtYWlsIH0pO1xuICAgICAgICB9KTtcblxuICAgICAgICBkZWZlcnJlZC5yZXNvbHZlKGRhdGEpO1xuICAgICAgfSk7XG5cbiAgICAgIHJldHVybiBkZWZlcnJlZC5wcm9taXNlO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEFicmUgbyBkaWFsb2cgcGFyYSBwZXNxdWlzYSBkZSB1c3XDoXJpb3NcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBvcGVuVXNlckRpYWxvZygpIHtcbiAgICAgIHZhciBjb25maWcgPSB7XG4gICAgICAgIGxvY2Fsczoge1xuICAgICAgICAgIG9uSW5pdDogdHJ1ZSxcbiAgICAgICAgICB1c2VyRGlhbG9nSW5wdXQ6IHtcbiAgICAgICAgICAgIHRyYW5zZmVyVXNlckZuOiB2bS5hZGRVc2VyTWFpbFxuICAgICAgICAgIH1cbiAgICAgICAgfSxcbiAgICAgICAgY29udHJvbGxlcjogJ1VzZXJzRGlhbG9nQ29udHJvbGxlcicsXG4gICAgICAgIGNvbnRyb2xsZXJBczogJ2N0cmwnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL3VzZXJzL2RpYWxvZy91c2Vycy1kaWFsb2cuaHRtbCcsXG4gICAgICAgIGhhc0JhY2tkcm9wOiB0cnVlXG4gICAgICB9O1xuXG4gICAgICBQckRpYWxvZy5jdXN0b20oY29uZmlnKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBBZGljaW9uYSBvIHVzdcOhcmlvIHNlbGVjaW9uYWRvIG5hIGxpc3RhIHBhcmEgcXVlIHNlamEgZW52aWFkbyBvIGVtYWlsXG4gICAgICovXG4gICAgZnVuY3Rpb24gYWRkVXNlck1haWwodXNlcikge1xuICAgICAgdmFyIHVzZXJzID0gbG9kYXNoLmZpbmQodm0ubWFpbC51c2VycywgeyBlbWFpbDogdXNlci5lbWFpbCB9KTtcblxuICAgICAgaWYgKHZtLm1haWwudXNlcnMubGVuZ3RoID4gMCAmJiBhbmd1bGFyLmlzRGVmaW5lZCh1c2VycykpIHtcbiAgICAgICAgUHJUb2FzdC53YXJuKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMudXNlci51c2VyRXhpc3RzJykpO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgdm0ubWFpbC51c2Vycy5wdXNoKHsgbmFtZTogdXNlci5uYW1lLCBlbWFpbDogdXNlci5lbWFpbCB9KTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFsaXphIG8gZW52aW8gZG8gZW1haWwgcGFyYSBhIGxpc3RhIGRlIHVzdcOhcmlvcyBzZWxlY2lvbmFkb3NcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBzZW5kKCkge1xuXG4gICAgICB2bS5tYWlsLiRzYXZlKCkudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgaWYgKHJlc3BvbnNlLmxlbmd0aCA+IDApIHtcbiAgICAgICAgICB2YXIgbXNnID0gJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5tYWlsLm1haWxFcnJvcnMnKTtcblxuICAgICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgcmVzcG9uc2UubGVuZ3RoOyBpKyspIHtcbiAgICAgICAgICAgIG1zZyArPSByZXNwb25zZSArICdcXG4nO1xuICAgICAgICAgIH1cbiAgICAgICAgICBQclRvYXN0LmVycm9yKG1zZyk7XG4gICAgICAgICAgdm0uY2xlYW5Gb3JtKCk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgUHJUb2FzdC5zdWNjZXNzKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMubWFpbC5zZW5kTWFpbFN1Y2Nlc3MnKSk7XG4gICAgICAgICAgdm0uY2xlYW5Gb3JtKCk7XG4gICAgICAgIH1cbiAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIExpbXBhIG8gZm9ybXVsw6FyaW8gZGUgZW1haWxcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBjbGVhbkZvcm0oKSB7XG4gICAgICB2bS5tYWlsID0gbmV3IE1haWxzU2VydmljZSgpO1xuICAgICAgdm0ubWFpbC51c2VycyA9IFtdO1xuICAgIH1cbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25maWcocm91dGVzKTtcblxuICAvKipcbiAgICogQXJxdWl2byBkZSBjb25maWd1cmHDp8OjbyBjb20gYXMgcm90YXMgZXNwZWPDrWZpY2FzIGRvIHJlY3Vyc28gZW0gcXVlc3TDo29cbiAgICpcbiAgICogQHBhcmFtIHthbnl9ICRzdGF0ZVByb3ZpZGVyXG4gICAqIEBwYXJhbSB7YW55fSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnYXBwLm1haWwnLCB7XG4gICAgICB1cmw6ICcvZW1haWwnLFxuICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9tYWlsL21haWxzLXNlbmQuaHRtbCcsXG4gICAgICBjb250cm9sbGVyOiAnTWFpbHNDb250cm9sbGVyIGFzIG1haWxzQ3RybCcsXG4gICAgICBkYXRhOiB7IG5lZWRBdXRoZW50aWNhdGlvbjogdHJ1ZSwgbmVlZFByb2ZpbGU6IFsnYWRtaW4nXSB9XG4gICAgfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmFjdG9yeSgnTWFpbHNTZXJ2aWNlJywgTWFpbHNTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIE1haWxzU2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHJldHVybiBzZXJ2aWNlRmFjdG9yeSgnbWFpbHMnLCB7fSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb250cm9sbGVyKCdNaWxlc3RvbmVzQ29udHJvbGxlcicsIE1pbGVzdG9uZXNDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIE1pbGVzdG9uZXNDb250cm9sbGVyKCRjb250cm9sbGVyLCBNaWxlc3RvbmVzU2VydmljZSwgbW9tZW50LCBUYXNrc1NlcnZpY2UsIFByVG9hc3QsICR0cmFuc2xhdGUsICRtZERpYWxvZykge1xuXG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIHZtLmVzdGltYXRlZFByaWNlID0gZXN0aW1hdGVkUHJpY2U7XG5cbiAgICB2bS5vbkFjdGl2YXRlID0gZnVuY3Rpb24gKCkge1xuICAgICAgdm0ucHJvamVjdCA9IGxvY2FsU3RvcmFnZS5nZXRJdGVtKCdwcm9qZWN0Jyk7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMgPSB7IHByb2plY3RfaWQ6IHZtLnByb2plY3QgfTtcbiAgICB9O1xuXG4gICAgZnVuY3Rpb24gZXN0aW1hdGVkUHJpY2UobWlsZXN0b25lKSB7XG4gICAgICBtaWxlc3RvbmUuZXN0aW1hdGVkX3ZhbHVlID0gMDtcbiAgICAgIGlmIChtaWxlc3RvbmUudGFza3MubGVuZ3RoID4gMCAmJiBtaWxlc3RvbmUucHJvamVjdC5ob3VyX3ZhbHVlX2ZpbmFsKSB7XG4gICAgICAgIG1pbGVzdG9uZS50YXNrcy5mb3JFYWNoKGZ1bmN0aW9uICh0YXNrKSB7XG4gICAgICAgICAgbWlsZXN0b25lLmVzdGltYXRlZF92YWx1ZSArPSBwYXJzZUZsb2F0KG1pbGVzdG9uZS5wcm9qZWN0LmhvdXJfdmFsdWVfZmluYWwpICogdGFzay5lc3RpbWF0ZWRfdGltZTtcbiAgICAgICAgfSk7XG4gICAgICB9XG4gICAgICByZXR1cm4gbWlsZXN0b25lLmVzdGltYXRlZF92YWx1ZS50b0xvY2FsZVN0cmluZygnUHQtYnInLCB7IG1pbmltdW1GcmFjdGlvbkRpZ2l0czogMiB9KTtcbiAgICB9XG5cbiAgICB2bS5lc3RpbWF0ZWRUaW1lID0gZnVuY3Rpb24gKG1pbGVzdG9uZSkge1xuICAgICAgbWlsZXN0b25lLmVzdGltYXRlZF90aW1lID0gMDtcbiAgICAgIGlmIChtaWxlc3RvbmUudGFza3MubGVuZ3RoID4gMCkge1xuICAgICAgICBtaWxlc3RvbmUudGFza3MuZm9yRWFjaChmdW5jdGlvbiAodGFzaykge1xuICAgICAgICAgIG1pbGVzdG9uZS5lc3RpbWF0ZWRfdGltZSArPSB0YXNrLmVzdGltYXRlZF90aW1lO1xuICAgICAgICB9KTtcbiAgICAgIH1cbiAgICAgIG1pbGVzdG9uZS5lc3RpbWF0ZWRfdGltZSA9IG1pbGVzdG9uZS5lc3RpbWF0ZWRfdGltZSAvIDg7XG4gICAgICB2YXIgZGF0ZUVuZCA9IG1vbWVudChtaWxlc3RvbmUuZGF0ZV9lbmQpO1xuICAgICAgdmFyIGRhdGVCZWdpbiA9IG1vbWVudChtaWxlc3RvbmUuZGF0ZV9iZWdpbik7XG5cbiAgICAgIGlmIChkYXRlRW5kLmRpZmYoZGF0ZUJlZ2luLCAnZGF5cycpIDw9IG1pbGVzdG9uZS5lc3RpbWF0ZWRfdGltZSkge1xuICAgICAgICBtaWxlc3RvbmUuY29sb3JfZXN0aW1hdGVkX3RpbWUgPSB7IGNvbG9yOiAncmVkJyB9O1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgbWlsZXN0b25lLmNvbG9yX2VzdGltYXRlZF90aW1lID0geyBjb2xvcjogJ2dyZWVuJyB9O1xuICAgICAgfVxuICAgICAgcmV0dXJuIG1pbGVzdG9uZS5lc3RpbWF0ZWRfdGltZTtcbiAgICB9O1xuXG4gICAgdm0uYXBwbHlGaWx0ZXJzID0gZnVuY3Rpb24gKGRlZmF1bHRRdWVyeUZpbHRlcnMpIHtcbiAgICAgIHJldHVybiBhbmd1bGFyLmV4dGVuZChkZWZhdWx0UXVlcnlGaWx0ZXJzLCB2bS5xdWVyeUZpbHRlcnMpO1xuICAgIH07XG5cbiAgICB2bS5iZWZvcmVTYXZlID0gZnVuY3Rpb24gKCkge1xuICAgICAgdm0ucmVzb3VyY2UucHJvamVjdF9pZCA9IHZtLnByb2plY3Q7XG4gICAgfTtcblxuICAgIHZtLmJlZm9yZVJlbW92ZSA9IGZ1bmN0aW9uICgpIHtcbiAgICAgIHZtLnJlc291cmNlLnByb2plY3RfaWQgPSB2bS5wcm9qZWN0O1xuICAgIH07XG5cbiAgICB2bS5mb3JtYXREYXRlID0gZnVuY3Rpb24gKGRhdGUpIHtcbiAgICAgIHJldHVybiBtb21lbnQoZGF0ZSkuZm9ybWF0KCdERC9NTS9ZWVlZJyk7XG4gICAgfTtcblxuICAgIHZtLmFmdGVyRWRpdCA9IGZ1bmN0aW9uICgpIHtcbiAgICAgIHZtLnJlc291cmNlLmRhdGVfYmVnaW4gPSBtb21lbnQodm0ucmVzb3VyY2UuZGF0ZV9iZWdpbik7XG4gICAgICB2bS5yZXNvdXJjZS5kYXRlX2VuZCA9IG1vbWVudCh2bS5yZXNvdXJjZS5kYXRlX2VuZCk7XG4gICAgfTtcblxuICAgIHZtLnZpZXcgPSBmdW5jdGlvbiAocmVzb3VyY2UpIHtcbiAgICAgIHZtLnJlc291cmNlID0gcmVzb3VyY2U7XG4gICAgICB2bS5vblZpZXcgPSB0cnVlO1xuICAgICAgdm0udmlld0Zvcm0gPSBmYWxzZTtcbiAgICAgIGNvbnNvbGUubG9nKHJlc291cmNlLnByb2plY3QpO1xuICAgIH07XG5cbiAgICB2bS5zZWFyY2hUYXNrID0gZnVuY3Rpb24gKHRhc2tUZXJtKSB7XG4gICAgICByZXR1cm4gVGFza3NTZXJ2aWNlLnF1ZXJ5KHtcbiAgICAgICAgbWlsZXN0b25lU2VhcmNoOiB0cnVlLFxuICAgICAgICBwcm9qZWN0X2lkOiB2bS5yZXNvdXJjZS5wcm9qZWN0X2lkLFxuICAgICAgICB0aXRsZTogdGFza1Rlcm1cbiAgICAgIH0pO1xuICAgIH07XG5cbiAgICB2bS5vblRhc2tDaGFuZ2UgPSBmdW5jdGlvbiAoKSB7XG4gICAgICBpZiAodm0udGFzayAhPT0gbnVsbCAmJiB2bS5yZXNvdXJjZS50YXNrcy5maW5kSW5kZXgoZnVuY3Rpb24gKGkpIHtcbiAgICAgICAgcmV0dXJuIGkuaWQgPT09IHZtLnRhc2suaWQ7XG4gICAgICB9KSA9PT0gLTEpIHtcbiAgICAgICAgdm0ucmVzb3VyY2UudGFza3MucHVzaCh2bS50YXNrKTtcbiAgICAgIH1cbiAgICB9O1xuXG4gICAgdm0ucmVtb3ZlVGFzayA9IGZ1bmN0aW9uICh0YXNrKSB7XG4gICAgICB2bS5yZXNvdXJjZS50YXNrcy5zbGljZSgwKS5mb3JFYWNoKGZ1bmN0aW9uIChlbGVtZW50KSB7XG4gICAgICAgIGlmIChlbGVtZW50LmlkID09PSB0YXNrLmlkKSB7XG4gICAgICAgICAgdm0ucmVzb3VyY2UudGFza3Muc3BsaWNlKHZtLnJlc291cmNlLnRhc2tzLmluZGV4T2YoZWxlbWVudCksIDEpO1xuICAgICAgICB9XG4gICAgICB9KTtcbiAgICB9O1xuXG4gICAgdm0uc2F2ZVRhc2tzID0gZnVuY3Rpb24gKCkge1xuICAgICAgVGFza3NTZXJ2aWNlLnVwZGF0ZU1pbGVzdG9uZSh7IHByb2plY3RfaWQ6IHZtLnJlc291cmNlLnByb2plY3RfaWQsIG1pbGVzdG9uZV9pZDogdm0ucmVzb3VyY2UuaWQsIHRhc2tzOiB2bS5yZXNvdXJjZS50YXNrcyB9KS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgUHJUb2FzdC5zdWNjZXNzKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMuc2F2ZVN1Y2Nlc3MnKSk7XG4gICAgICAgIHZtLnZpZXdGb3JtID0gZmFsc2U7XG4gICAgICAgIHZtLm9uVmlldyA9IGZhbHNlO1xuICAgICAgfSwgZnVuY3Rpb24gKCkge1xuICAgICAgICBQclRvYXN0LmVycm9yKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMub3BlcmF0aW9uRXJyb3InKSk7XG4gICAgICB9KTtcbiAgICB9O1xuXG4gICAgdm0uZmluYWxpemUgPSBmdW5jdGlvbiAobWlsZXN0b25lKSB7XG4gICAgICB2YXIgY29uZmlybSA9ICRtZERpYWxvZy5jb25maXJtKCkudGl0bGUoJ0ZpbmFsaXphciBTcHJpbnQnKS50ZXh0Q29udGVudCgnVGVtIGNlcnRlemEgcXVlIGRlc2VqYSBmaW5hbGl6YXIgYSBzcHJpbnQgJyArIG1pbGVzdG9uZS50aXRsZSArICc/Jykub2soJ1NpbScpLmNhbmNlbCgnTsOjbycpO1xuXG4gICAgICAkbWREaWFsb2cuc2hvdyhjb25maXJtKS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgTWlsZXN0b25lc1NlcnZpY2UuZmluYWxpemUoeyBwcm9qZWN0X2lkOiB2bS5wcm9qZWN0LCBtaWxlc3RvbmVfaWQ6IG1pbGVzdG9uZS5pZCB9KS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICBQclRvYXN0LnN1Y2Nlc3MoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5zcHJpbnRFbmRlZFN1Y2Nlc3MnKSk7XG4gICAgICAgICAgdm0uc2VhcmNoKCk7XG4gICAgICAgIH0sIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICBQclRvYXN0LkVycm9yKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMuc3ByaW50RW5kZWRFcnJvcicpKTtcbiAgICAgICAgfSk7XG4gICAgICB9KTtcbiAgICB9O1xuXG4gICAgLy8gaW5zdGFudGlhdGUgYmFzZSBjb250cm9sbGVyXG4gICAgJGNvbnRyb2xsZXIoJ0NSVURDb250cm9sbGVyJywgeyB2bTogdm0sIG1vZGVsU2VydmljZTogTWlsZXN0b25lc1NlcnZpY2UsIG9wdGlvbnM6IHt9IH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKlxuICAgKiBBcnF1aXZvIGRlIGNvbmZpZ3VyYcOnw6NvIGNvbSBhcyByb3RhcyBlc3BlY8OtZmljYXMgZG8gcmVjdXJzbyBtaWxlc3RvbmVzXG4gICAqXG4gICAqIEBwYXJhbSB7b2JqZWN0fSAkc3RhdGVQcm92aWRlclxuICAgKiBAcGFyYW0ge29iamVjdH0gR2xvYmFsXG4gICAqL1xuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvdXRlcygkc3RhdGVQcm92aWRlciwgR2xvYmFsKSB7XG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ2FwcC5taWxlc3RvbmVzJywge1xuICAgICAgdXJsOiAnL21pbGVzdG9uZXMnLFxuICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9taWxlc3RvbmVzL21pbGVzdG9uZXMuaHRtbCcsXG4gICAgICBjb250cm9sbGVyOiAnTWlsZXN0b25lc0NvbnRyb2xsZXIgYXMgbWlsZXN0b25lc0N0cmwnLFxuICAgICAgZGF0YToge31cbiAgICB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5mYWN0b3J5KCdNaWxlc3RvbmVzU2VydmljZScsIE1pbGVzdG9uZXNTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIE1pbGVzdG9uZXNTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgdmFyIG1vZGVsID0gc2VydmljZUZhY3RvcnkoJ21pbGVzdG9uZXMnLCB7XG4gICAgICBhY3Rpb25zOiB7XG4gICAgICAgIGZpbmFsaXplOiB7XG4gICAgICAgICAgbWV0aG9kOiAnUE9TVCcsXG4gICAgICAgICAgdXJsOiAnZmluYWxpemUnXG4gICAgICAgIH0sXG4gICAgICAgIHVwZGF0ZVJlbGVhc2U6IHtcbiAgICAgICAgICBtZXRob2Q6ICdQT1NUJyxcbiAgICAgICAgICB1cmw6ICd1cGRhdGVSZWxlYXNlJ1xuICAgICAgICB9XG4gICAgICB9LFxuICAgICAgaW5zdGFuY2U6IHt9XG4gICAgfSk7XG5cbiAgICByZXR1cm4gbW9kZWw7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmFjdG9yeSgnUHJpb3JpdGllc1NlcnZpY2UnLCBQcmlvcml0aWVzU2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiBQcmlvcml0aWVzU2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHZhciBtb2RlbCA9IHNlcnZpY2VGYWN0b3J5KCdwcmlvcml0aWVzJywge1xuICAgICAgYWN0aW9uczoge30sXG4gICAgICBpbnN0YW5jZToge31cbiAgICB9KTtcblxuICAgIHJldHVybiBtb2RlbDtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbnRyb2xsZXIoJ1Byb2plY3RzQ29udHJvbGxlcicsIFByb2plY3RzQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBQcm9qZWN0c0NvbnRyb2xsZXIoJGNvbnRyb2xsZXIsIFByb2plY3RzU2VydmljZSwgQXV0aCwgUm9sZXNTZXJ2aWNlLCBVc2Vyc1NlcnZpY2UsICRzdGF0ZSwgJGZpbHRlciwgJHN0YXRlUGFyYW1zLCAkd2luZG93KSB7XG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIC8vQXR0cmlidXRlcyBCbG9ja1xuXG4gICAgLy9GdW5jdGlvbnMgQmxvY2tcbiAgICB2bS5vbkFjdGl2YXRlID0gb25BY3RpdmF0ZTtcbiAgICB2bS5hcHBseUZpbHRlcnMgPSBhcHBseUZpbHRlcnM7XG4gICAgdm0uYmVmb3JlU2F2ZSA9IGJlZm9yZVNhdmU7XG4gICAgdm0uc2VhcmNoVXNlciA9IHNlYXJjaFVzZXI7XG4gICAgdm0uYWRkVXNlciA9IGFkZFVzZXI7XG4gICAgdm0ucmVtb3ZlVXNlciA9IHJlbW92ZVVzZXI7XG4gICAgdm0udmlld1Byb2plY3QgPSB2aWV3UHJvamVjdDtcblxuICAgIHZtLnJvbGVzID0ge307XG4gICAgdm0udXNlcnMgPSBbXTtcblxuICAgIGZ1bmN0aW9uIG9uQWN0aXZhdGUoKSB7XG4gICAgICBSb2xlc1NlcnZpY2UucXVlcnkoKS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICB2bS5yb2xlcyA9IHJlc3BvbnNlO1xuICAgICAgICBpZiAoJHN0YXRlUGFyYW1zLm9iaiA9PT0gJ2VkaXQnKSB7XG4gICAgICAgICAgdm0uY2xlYW5Gb3JtKCk7XG4gICAgICAgICAgdm0udmlld0Zvcm0gPSB0cnVlO1xuICAgICAgICAgIHZtLnJlc291cmNlID0gJHN0YXRlUGFyYW1zLnJlc291cmNlO1xuICAgICAgICAgIHVzZXJzQXJyYXkodm0ucmVzb3VyY2UpO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKCdwcm9qZWN0Jyk7XG4gICAgICAgICAgdm0ucXVlcnlGaWx0ZXJzID0geyB1c2VyX2lkOiBBdXRoLmN1cnJlbnRVc2VyLmlkIH07XG4gICAgICAgIH1cbiAgICAgIH0pO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGFwcGx5RmlsdGVycyhkZWZhdWx0UXVlcnlGaWx0ZXJzKSB7XG4gICAgICByZXR1cm4gYW5ndWxhci5leHRlbmQoZGVmYXVsdFF1ZXJ5RmlsdGVycywgdm0ucXVlcnlsdGVycyk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gYmVmb3JlU2F2ZSgpIHtcbiAgICAgIHZtLnJlc291cmNlLm93bmVyID0gQXV0aC5jdXJyZW50VXNlci5pZDtcbiAgICAgIHZtLnJlc291cmNlLnVzZXJfaWQgPSBBdXRoLmN1cnJlbnRVc2VyLmlkO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIHNlYXJjaFVzZXIoKSB7XG4gICAgICByZXR1cm4gVXNlcnNTZXJ2aWNlLnF1ZXJ5KHsgbmFtZTogdm0udXNlck5hbWUgfSk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gYWRkVXNlcih1c2VyKSB7XG4gICAgICBpZiAodXNlcikge1xuICAgICAgICB2bS5yZXNvdXJjZS51c2Vycy5wdXNoKHVzZXIpO1xuICAgICAgICB2bS51c2VyTmFtZSA9ICcnO1xuICAgICAgfVxuICAgIH1cblxuICAgIGZ1bmN0aW9uIHJlbW92ZVVzZXIoaW5kZXgpIHtcbiAgICAgIHZtLnJlc291cmNlLnVzZXJzLnNwbGljZShpbmRleCwgMSk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gYXBwbHlGaWx0ZXJzKGRlZmF1bHRRdWVyeUZpbHRlcnMpIHtcbiAgICAgIHJldHVybiBhbmd1bGFyLmV4dGVuZChkZWZhdWx0UXVlcnlGaWx0ZXJzLCB2bS5xdWVyeUZpbHRlcnMpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIHZpZXdQcm9qZWN0KCkge1xuICAgICAgJHN0YXRlLmdvKCdhcHAuZGFzaGJvYXJkJyk7XG4gICAgfVxuXG4gICAgdm0uYWZ0ZXJTZWFyY2ggPSBmdW5jdGlvbiAoKSB7XG4gICAgICBpZiAodm0ucmVzb3VyY2VzLmxlbmd0aCA+IDApIHtcbiAgICAgICAgdm0ucmVzb3VyY2VzLmZvckVhY2goZnVuY3Rpb24gKHByb2plY3QpIHtcbiAgICAgICAgICB1c2Vyc0FycmF5KHByb2plY3QpO1xuICAgICAgICB9KTtcbiAgICAgIH1cbiAgICB9O1xuXG4gICAgZnVuY3Rpb24gdXNlcnNBcnJheShwcm9qZWN0KSB7XG4gICAgICBwcm9qZWN0LnVzZXJzID0gW107XG4gICAgICBpZiAocHJvamVjdC5jbGllbnRfaWQpIHtcbiAgICAgICAgcHJvamVjdC5jbGllbnQucm9sZSA9ICRmaWx0ZXIoJ2ZpbHRlcicpKHZtLnJvbGVzLCB7IHNsdWc6ICdjbGllbnQnIH0pWzBdO1xuICAgICAgICBwcm9qZWN0LnVzZXJzLnB1c2gocHJvamVjdC5jbGllbnQpO1xuICAgICAgfVxuICAgICAgaWYgKHByb2plY3QuZGV2X2lkKSB7XG4gICAgICAgIHByb2plY3QuZGV2ZWxvcGVyLnJvbGUgPSAkZmlsdGVyKCdmaWx0ZXInKSh2bS5yb2xlcywgeyBzbHVnOiAnZGV2JyB9KVswXTtcbiAgICAgICAgcHJvamVjdC51c2Vycy5wdXNoKHByb2plY3QuZGV2ZWxvcGVyKTtcbiAgICAgIH1cbiAgICAgIGlmIChwcm9qZWN0LnN0YWtlaG9sZGVyX2lkKSB7XG4gICAgICAgIHByb2plY3Quc3Rha2Vob2xkZXIucm9sZSA9ICRmaWx0ZXIoJ2ZpbHRlcicpKHZtLnJvbGVzLCB7IHNsdWc6ICdzdGFrZWhvbGRlcicgfSlbMF07XG4gICAgICAgIHByb2plY3QudXNlcnMucHVzaChwcm9qZWN0LnN0YWtlaG9sZGVyKTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICB2bS5oaXN0b3J5QmFjayA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICR3aW5kb3cuaGlzdG9yeS5iYWNrKCk7XG4gICAgfTtcblxuICAgIHZtLmFmdGVyU2F2ZSA9IGZ1bmN0aW9uIChyZXNvdXJjZSkge1xuICAgICAgbG9jYWxTdG9yYWdlLnNldEl0ZW0oJ3Byb2plY3QnLCByZXNvdXJjZS5pZCk7XG4gICAgICAkc3RhdGUuZ28oJ2FwcC5kYXNoYm9hcmQnKTtcbiAgICB9O1xuXG4gICAgLy8gaW5zdGFudGlhdGUgYmFzZSBjb250cm9sbGVyXG4gICAgJGNvbnRyb2xsZXIoJ0NSVURDb250cm9sbGVyJywgeyB2bTogdm0sIG1vZGVsU2VydmljZTogUHJvamVjdHNTZXJ2aWNlLCBvcHRpb25zOiB7IHJlZGlyZWN0QWZ0ZXJTYXZlOiBmYWxzZSB9IH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKlxuICAgKiBBcnF1aXZvIGRlIGNvbmZpZ3VyYcOnw6NvIGNvbSBhcyByb3RhcyBlc3BlY8OtZmljYXMgZG8gcmVjdXJzbyBwcm9qZWN0XG4gICAqXG4gICAqIEBwYXJhbSB7YW55fSAkc3RhdGVQcm92aWRlclxuICAgKiBAcGFyYW0ge2FueX0gR2xvYmFsXG4gICAqL1xuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvdXRlcygkc3RhdGVQcm92aWRlciwgR2xvYmFsKSB7XG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ2FwcC5wcm9qZWN0cycsIHtcbiAgICAgIHVybDogJy9wcm9qZWN0cycsXG4gICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL3Byb2plY3RzL3Byb2plY3RzLmh0bWwnLFxuICAgICAgY29udHJvbGxlcjogJ1Byb2plY3RzQ29udHJvbGxlciBhcyBwcm9qZWN0c0N0cmwnLFxuICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IHRydWUgfSxcbiAgICAgIHBhcmFtczogeyBvYmo6IG51bGwsIHJlc291cmNlOiBudWxsIH1cbiAgICB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5mYWN0b3J5KCdQcm9qZWN0c1NlcnZpY2UnLCBQcm9qZWN0c1NlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gUHJvamVjdHNTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCdwcm9qZWN0cycsIHtcbiAgICAgIGFjdGlvbnM6IHt9LFxuICAgICAgaW5zdGFuY2U6IHt9XG4gICAgfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5maWx0ZXIoJ3JvbGVzU3RyJywgcm9sZXNTdHIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm9sZXNTdHIobG9kYXNoKSB7XG4gICAgLyoqXG4gICAgICogQHBhcmFtIHthcnJheX0gcm9sZXMgbGlzdGEgZGUgcGVyZmlzXG4gICAgICogQHJldHVybiB7c3RyaW5nfSBwZXJmaXMgc2VwYXJhZG9zIHBvciAnLCAnICBcbiAgICAgKi9cbiAgICByZXR1cm4gZnVuY3Rpb24gKHJvbGVzKSB7XG4gICAgICByZXR1cm4gbG9kYXNoLm1hcChyb2xlcywgJ3NsdWcnKS5qb2luKCcsICcpO1xuICAgIH07XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmFjdG9yeSgnUm9sZXNTZXJ2aWNlJywgUm9sZXNTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIFJvbGVzU2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHJldHVybiBzZXJ2aWNlRmFjdG9yeSgncm9sZXMnKTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbnRyb2xsZXIoJ1JlbGVhc2VzQ29udHJvbGxlcicsIFJlbGVhc2VzQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBSZWxlYXNlc0NvbnRyb2xsZXIoJGNvbnRyb2xsZXIsIFJlbGVhc2VzU2VydmljZSwgTWlsZXN0b25lc1NlcnZpY2UsIFByVG9hc3QsIG1vbWVudCwgJG1kRGlhbG9nLCAkdHJhbnNsYXRlKSB7XG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIC8vQXR0cmlidXRlcyBCbG9ja1xuXG4gICAgLy9GdW5jdGlvbnMgQmxvY2tcbiAgICB2bS5vbkFjdGl2YXRlID0gZnVuY3Rpb24gKCkge1xuICAgICAgdm0ucHJvamVjdCA9IGxvY2FsU3RvcmFnZS5nZXRJdGVtKCdwcm9qZWN0Jyk7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMgPSB7IHByb2plY3RfaWQ6IHZtLnByb2plY3QgfTtcbiAgICB9O1xuXG4gICAgdm0uYmVmb3JlU2F2ZSA9IGZ1bmN0aW9uICgpIHtcbiAgICAgIHZtLnJlc291cmNlLnByb2plY3RfaWQgPSB2bS5wcm9qZWN0O1xuICAgIH07XG5cbiAgICB2bS5iZWZvcmVSZW1vdmUgPSBmdW5jdGlvbiAoKSB7XG4gICAgICB2bS5yZXNvdXJjZS5wcm9qZWN0X2lkID0gdm0ucHJvamVjdDtcbiAgICB9O1xuXG4gICAgdm0udmlldyA9IGZ1bmN0aW9uIChyZXNvdXJjZSkge1xuICAgICAgdm0ucmVzb3VyY2UgPSByZXNvdXJjZTtcbiAgICAgIHZtLm9uVmlldyA9IHRydWU7XG4gICAgICB2bS52aWV3Rm9ybSA9IGZhbHNlO1xuICAgIH07XG5cbiAgICB2bS5maW5hbGl6ZSA9IGZ1bmN0aW9uIChyZWxlYXNlKSB7XG4gICAgICB2YXIgY29uZmlybSA9ICRtZERpYWxvZy5jb25maXJtKCkudGl0bGUoJ0ZpbmFsaXphciBSZWxlYXNlJykudGV4dENvbnRlbnQoJ1RlbSBjZXJ0ZXphIHF1ZSBkZXNlamEgZmluYWxpemFyIGEgcmVsZWFzZSAnICsgcmVsZWFzZS50aXRsZSArICc/Jykub2soJ1NpbScpLmNhbmNlbCgnTsOjbycpO1xuXG4gICAgICAkbWREaWFsb2cuc2hvdyhjb25maXJtKS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgUmVsZWFzZXNTZXJ2aWNlLmZpbmFsaXplKHsgcHJvamVjdF9pZDogdm0ucHJvamVjdCwgcmVsZWFzZV9pZDogcmVsZWFzZS5pZCB9KS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICBQclRvYXN0LnN1Y2Nlc3MoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5zcHJpbnRFbmRlZFN1Y2Nlc3MnKSk7XG4gICAgICAgICAgdm0uc2VhcmNoKCk7XG4gICAgICAgIH0sIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICBQclRvYXN0LkVycm9yKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMuc3ByaW50RW5kZWRFcnJvcicpKTtcbiAgICAgICAgfSk7XG4gICAgICB9KTtcbiAgICB9O1xuXG4gICAgdm0uZm9ybWF0RGF0ZSA9IGZ1bmN0aW9uIChkYXRlKSB7XG4gICAgICByZXR1cm4gbW9tZW50KGRhdGUpLmZvcm1hdCgnREQvTU0vWVlZWScpO1xuICAgIH07XG5cbiAgICB2bS5zZWFyY2hNaWxlc3RvbmUgPSBmdW5jdGlvbiAobWlsZXN0b25lVGVybSkge1xuICAgICAgcmV0dXJuIE1pbGVzdG9uZXNTZXJ2aWNlLnF1ZXJ5KHtcbiAgICAgICAgcmVsZWFzZVNlYXJjaDogdHJ1ZSxcbiAgICAgICAgcHJvamVjdF9pZDogdm0ucmVzb3VyY2UucHJvamVjdF9pZCxcbiAgICAgICAgdGl0bGU6IG1pbGVzdG9uZVRlcm1cbiAgICAgIH0pO1xuICAgIH07XG5cbiAgICB2bS5vbk1pbGVzdG9uZUNoYW5nZSA9IGZ1bmN0aW9uICgpIHtcbiAgICAgIGlmICh2bS5taWxlc3RvbmUgIT09IG51bGwgJiYgdm0ucmVzb3VyY2UubWlsZXN0b25lcy5maW5kSW5kZXgoZnVuY3Rpb24gKGkpIHtcbiAgICAgICAgcmV0dXJuIGkuaWQgPT09IHZtLm1pbGVzdG9uZS5pZDtcbiAgICAgIH0pID09PSAtMSkge1xuICAgICAgICB2bS5yZXNvdXJjZS5taWxlc3RvbmVzLnB1c2godm0ubWlsZXN0b25lKTtcbiAgICAgIH1cbiAgICB9O1xuXG4gICAgdm0ucmVtb3ZlTWlsZXN0b25lID0gZnVuY3Rpb24gKG1pbGVzdG9uZSkge1xuICAgICAgdm0ucmVzb3VyY2UubWlsZXN0b25lcy5zbGljZSgwKS5mb3JFYWNoKGZ1bmN0aW9uIChlbGVtZW50KSB7XG4gICAgICAgIGlmIChlbGVtZW50LmlkID09PSBtaWxlc3RvbmUuaWQpIHtcbiAgICAgICAgICB2bS5yZXNvdXJjZS5taWxlc3RvbmVzLnNwbGljZSh2bS5yZXNvdXJjZS5taWxlc3RvbmVzLmluZGV4T2YoZWxlbWVudCksIDEpO1xuICAgICAgICB9XG4gICAgICB9KTtcbiAgICB9O1xuXG4gICAgdm0uc2F2ZU1pbGVzdG9uZXMgPSBmdW5jdGlvbiAoKSB7XG4gICAgICBNaWxlc3RvbmVzU2VydmljZS51cGRhdGVSZWxlYXNlKHsgcHJvamVjdF9pZDogdm0ucmVzb3VyY2UucHJvamVjdF9pZCwgcmVsZWFzZV9pZDogdm0ucmVzb3VyY2UuaWQsIG1pbGVzdG9uZXM6IHZtLnJlc291cmNlLm1pbGVzdG9uZXMgfSkudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgIFByVG9hc3Quc3VjY2VzcygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnNhdmVTdWNjZXNzJykpO1xuICAgICAgICB2bS52aWV3Rm9ybSA9IGZhbHNlO1xuICAgICAgICB2bS5vblZpZXcgPSBmYWxzZTtcbiAgICAgIH0sIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgUHJUb2FzdC5lcnJvcigkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLm9wZXJhdGlvbkVycm9yJykpO1xuICAgICAgfSk7XG4gICAgfTtcblxuICAgIHZtLmVzdGltYXRlZFRpbWUgPSBmdW5jdGlvbiAobWlsZXN0b25lKSB7XG4gICAgICBtaWxlc3RvbmUuZXN0aW1hdGVkX3RpbWUgPSAwO1xuICAgICAgaWYgKG1pbGVzdG9uZS50YXNrcy5sZW5ndGggPiAwKSB7XG4gICAgICAgIG1pbGVzdG9uZS50YXNrcy5mb3JFYWNoKGZ1bmN0aW9uICh0YXNrKSB7XG4gICAgICAgICAgbWlsZXN0b25lLmVzdGltYXRlZF90aW1lICs9IHRhc2suZXN0aW1hdGVkX3RpbWU7XG4gICAgICAgIH0pO1xuICAgICAgfVxuICAgICAgcmV0dXJuIG1pbGVzdG9uZS5lc3RpbWF0ZWRfdGltZSAvIDg7XG4gICAgfTtcblxuICAgIC8vIGluc3RhbnRpYXRlIGJhc2UgY29udHJvbGxlclxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHsgdm06IHZtLCBtb2RlbFNlcnZpY2U6IFJlbGVhc2VzU2VydmljZSwgb3B0aW9uczoge30gfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqXG4gICAqIEFycXVpdm8gZGUgY29uZmlndXJhw6fDo28gY29tIGFzIHJvdGFzIGVzcGVjw61maWNhcyBkbyByZWN1cnNvIHJlbGVhc2VzXG4gICAqXG4gICAqIEBwYXJhbSB7b2JqZWN0fSAkc3RhdGVQcm92aWRlclxuICAgKiBAcGFyYW0ge29iamVjdH0gR2xvYmFsXG4gICAqL1xuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvdXRlcygkc3RhdGVQcm92aWRlciwgR2xvYmFsKSB7XG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ2FwcC5yZWxlYXNlcycsIHtcbiAgICAgIHVybDogJy9yZWxlYXNlcycsXG4gICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL3JlbGVhc2VzL3JlbGVhc2VzLmh0bWwnLFxuICAgICAgY29udHJvbGxlcjogJ1JlbGVhc2VzQ29udHJvbGxlciBhcyByZWxlYXNlc0N0cmwnLFxuICAgICAgZGF0YToge31cbiAgICB9KTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5mYWN0b3J5KCdSZWxlYXNlc1NlcnZpY2UnLCBSZWxlYXNlc1NlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gUmVsZWFzZXNTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgdmFyIG1vZGVsID0gc2VydmljZUZhY3RvcnkoJ3JlbGVhc2VzJywge1xuICAgICAgYWN0aW9uczoge1xuICAgICAgICBmaW5hbGl6ZToge1xuICAgICAgICAgIG1ldGhvZDogJ1BPU1QnLFxuICAgICAgICAgIHVybDogJ2ZpbmFsaXplJ1xuICAgICAgICB9XG4gICAgICB9LFxuICAgICAgaW5zdGFuY2U6IHt9XG4gICAgfSk7XG5cbiAgICByZXR1cm4gbW9kZWw7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuZmFjdG9yeSgnU3RhdHVzU2VydmljZScsIFN0YXR1c1NlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gU3RhdHVzU2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHZhciBtb2RlbCA9IHNlcnZpY2VGYWN0b3J5KCdzdGF0dXMnLCB7XG4gICAgICBhY3Rpb25zOiB7fSxcbiAgICAgIGluc3RhbmNlOiB7fVxuICAgIH0pO1xuXG4gICAgcmV0dXJuIG1vZGVsO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZhY3RvcnkoJ1N1cHBvcnRTZXJ2aWNlJywgU3VwcG9ydFNlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gU3VwcG9ydFNlcnZpY2Uoc2VydmljZUZhY3RvcnkpIHtcbiAgICByZXR1cm4gc2VydmljZUZhY3RvcnkoJ3N1cHBvcnQnLCB7XG4gICAgICBhY3Rpb25zOiB7XG4gICAgICAgIC8qKlxuICAgICAgICAgKiBQZWdhIGFzIHRyYWR1w6fDtWVzIHF1ZSBlc3TDo28gbm8gc2Vydmlkb3JcbiAgICAgICAgICpcbiAgICAgICAgICogQHJldHVybnMge3Byb21pc2V9IFVtYSBwcm9taXNlIGNvbSBvIHJlc3VsdGFkbyBkbyBjaGFtYWRhIG5vIGJhY2tlbmRcbiAgICAgICAgICovXG4gICAgICAgIGxhbmdzOiB7XG4gICAgICAgICAgbWV0aG9kOiAnR0VUJyxcbiAgICAgICAgICB1cmw6ICdsYW5ncycsXG4gICAgICAgICAgd3JhcDogZmFsc2UsXG4gICAgICAgICAgY2FjaGU6IHRydWVcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZhY3RvcnkoJ1Rhc2tDb21tZW50c1NlcnZpY2UnLCBUYXNrQ29tbWVudHNTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIFRhc2tDb21tZW50c1NlcnZpY2Uoc2VydmljZUZhY3RvcnkpIHtcbiAgICB2YXIgbW9kZWwgPSBzZXJ2aWNlRmFjdG9yeSgndGFzay1jb21tZW50cycsIHtcbiAgICAgIGFjdGlvbnM6IHtcbiAgICAgICAgc2F2ZVRhc2tDb21tZW50OiB7XG4gICAgICAgICAgbWV0aG9kOiAnUE9TVCcsXG4gICAgICAgICAgdXJsOiAnc2F2ZVRhc2tDb21tZW50J1xuICAgICAgICB9LFxuICAgICAgICByZW1vdmVUYXNrQ29tbWVudDoge1xuICAgICAgICAgIG1ldGhvZDogJ1BPU1QnLFxuICAgICAgICAgIHVybDogJ3JlbW92ZVRhc2tDb21tZW50J1xuICAgICAgICB9XG4gICAgICB9LFxuICAgICAgaW5zdGFuY2U6IHt9XG4gICAgfSk7XG5cbiAgICByZXR1cm4gbW9kZWw7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5maWx0ZXIoJ2VsYXBzZWQnLCBmdW5jdGlvbiAoKSB7XG4gICAgcmV0dXJuIGZ1bmN0aW9uIChkYXRlKSB7XG4gICAgICBpZiAoIWRhdGUpIHJldHVybjtcbiAgICAgIHZhciB0aW1lID0gRGF0ZS5wYXJzZShkYXRlKSxcbiAgICAgICAgICB0aW1lTm93ID0gbmV3IERhdGUoKS5nZXRUaW1lKCksXG4gICAgICAgICAgZGlmZmVyZW5jZSA9IHRpbWVOb3cgLSB0aW1lLFxuICAgICAgICAgIHNlY29uZHMgPSBNYXRoLmZsb29yKGRpZmZlcmVuY2UgLyAxMDAwKSxcbiAgICAgICAgICBtaW51dGVzID0gTWF0aC5mbG9vcihzZWNvbmRzIC8gNjApLFxuICAgICAgICAgIGhvdXJzID0gTWF0aC5mbG9vcihtaW51dGVzIC8gNjApLFxuICAgICAgICAgIGRheXMgPSBNYXRoLmZsb29yKGhvdXJzIC8gMjQpLFxuICAgICAgICAgIG1vbnRocyA9IE1hdGguZmxvb3IoZGF5cyAvIDMwKTtcblxuICAgICAgaWYgKG1vbnRocyA+IDEpIHtcbiAgICAgICAgcmV0dXJuIG1vbnRocyArICcgbWVzZXMgYXRyw6FzJztcbiAgICAgIH0gZWxzZSBpZiAobW9udGhzID09PSAxKSB7XG4gICAgICAgIHJldHVybiAnMSBtw6pzIGF0csOhcyc7XG4gICAgICB9IGVsc2UgaWYgKGRheXMgPiAxKSB7XG4gICAgICAgIHJldHVybiBkYXlzICsgJyBkaWFzIGF0csOhcyc7XG4gICAgICB9IGVsc2UgaWYgKGRheXMgPT09IDEpIHtcbiAgICAgICAgcmV0dXJuICcxIGRpYSBhdHLDoXMnO1xuICAgICAgfSBlbHNlIGlmIChob3VycyA+IDEpIHtcbiAgICAgICAgcmV0dXJuIGhvdXJzICsgJyBob3JhcyBhdHLDoXMnO1xuICAgICAgfSBlbHNlIGlmIChob3VycyA9PT0gMSkge1xuICAgICAgICByZXR1cm4gJ3VtYSBob3JhIGF0csOhcyc7XG4gICAgICB9IGVsc2UgaWYgKG1pbnV0ZXMgPiAxKSB7XG4gICAgICAgIHJldHVybiBtaW51dGVzICsgJyBtaW51dG9zIGF0csOhcyc7XG4gICAgICB9IGVsc2UgaWYgKG1pbnV0ZXMgPT09IDEpIHtcbiAgICAgICAgcmV0dXJuICd1bSBtaW51dG8gYXRyw6FzJztcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHJldHVybiAnaMOhIHBvdWNvcyBzZWd1bmRvcyc7XG4gICAgICB9XG4gICAgfTtcbiAgfSkuY29udHJvbGxlcignVGFza3NDb250cm9sbGVyJywgVGFza3NDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIFRhc2tzQ29udHJvbGxlcigkY29udHJvbGxlciwgVGFza3NTZXJ2aWNlLCBTdGF0dXNTZXJ2aWNlLCBQcmlvcml0aWVzU2VydmljZSwgVHlwZXNTZXJ2aWNlLCBUYXNrQ29tbWVudHNTZXJ2aWNlLCBtb21lbnQsIEF1dGgsIFByVG9hc3QsICR0cmFuc2xhdGUsICRmaWx0ZXIpIHtcbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgLy9BdHRyaWJ1dGVzIEJsb2NrXG5cbiAgICAvL0Z1bmN0aW9ucyBCbG9ja1xuICAgIHZtLm9uQWN0aXZhdGUgPSBvbkFjdGl2YXRlO1xuICAgIHZtLmFwcGx5RmlsdGVycyA9IGFwcGx5RmlsdGVycztcbiAgICB2bS5iZWZvcmVTYXZlID0gYmVmb3JlU2F2ZTtcbiAgICB2bS5iZWZvcmVSZW1vdmUgPSBiZWZvcmVSZW1vdmU7XG5cbiAgICBmdW5jdGlvbiBvbkFjdGl2YXRlKCkge1xuICAgICAgdm0uY3VycmVudFVzZXIgPSBBdXRoLmN1cnJlbnRVc2VyO1xuICAgICAgdm0ucHJvamVjdCA9IGxvY2FsU3RvcmFnZS5nZXRJdGVtKCdwcm9qZWN0Jyk7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMgPSB7IHByb2plY3RfaWQ6IHZtLnByb2plY3QgfTtcblxuICAgICAgU3RhdHVzU2VydmljZS5xdWVyeSgpLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgIHZtLnN0YXR1cyA9IHJlc3BvbnNlO1xuICAgICAgfSk7XG5cbiAgICAgIFByaW9yaXRpZXNTZXJ2aWNlLnF1ZXJ5KCkudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgdm0ucHJpb3JpdGllcyA9IHJlc3BvbnNlO1xuICAgICAgfSk7XG5cbiAgICAgIFR5cGVzU2VydmljZS5xdWVyeSgpLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgIHZtLnR5cGVzID0gcmVzcG9uc2U7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBhcHBseUZpbHRlcnMoZGVmYXVsdFF1ZXJ5RmlsdGVycykge1xuICAgICAgcmV0dXJuIGFuZ3VsYXIuZXh0ZW5kKGRlZmF1bHRRdWVyeUZpbHRlcnMsIHZtLnF1ZXJ5RmlsdGVycyk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gYmVmb3JlU2F2ZSgpIHtcbiAgICAgIHZtLnJlc291cmNlLnByb2plY3RfaWQgPSB2bS5wcm9qZWN0O1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGJlZm9yZVJlbW92ZSgpIHtcbiAgICAgIHZtLnJlc291cmNlLnByb2plY3RfaWQgPSB2bS5wcm9qZWN0O1xuICAgIH1cblxuICAgIHZtLnZpZXcgPSBmdW5jdGlvbiAocmVzb3VyY2UpIHtcbiAgICAgIHZtLnJlc291cmNlID0gcmVzb3VyY2U7XG4gICAgICB2bS5vblZpZXcgPSB0cnVlO1xuICAgICAgdm0udmlld0Zvcm0gPSBmYWxzZTtcbiAgICB9O1xuXG4gICAgdm0uc2F2ZUNvbW1lbnQgPSBmdW5jdGlvbiAoY29tbWVudCkge1xuICAgICAgdmFyIGRlc2NyaXB0aW9uID0gJyc7XG4gICAgICB2YXIgY29tbWVudF9pZCA9IG51bGw7XG5cbiAgICAgIGlmIChjb21tZW50KSB7XG4gICAgICAgIGRlc2NyaXB0aW9uID0gdm0uYW5zd2VyO1xuICAgICAgICBjb21tZW50X2lkID0gY29tbWVudC5pZDtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIGRlc2NyaXB0aW9uID0gdm0uY29tbWVudDtcbiAgICAgIH1cbiAgICAgIFRhc2tDb21tZW50c1NlcnZpY2Uuc2F2ZVRhc2tDb21tZW50KHsgcHJvamVjdF9pZDogdm0ucHJvamVjdCwgdGFza19pZDogdm0ucmVzb3VyY2UuaWQsIGNvbW1lbnRfdGV4dDogZGVzY3JpcHRpb24sIGNvbW1lbnRfaWQ6IGNvbW1lbnRfaWQgfSkudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgIHZtLmNvbW1lbnQgPSAnJztcbiAgICAgICAgdm0uYW5zd2VyID0gJyc7XG4gICAgICAgIHZtLnNlYXJjaCgpO1xuICAgICAgICBQclRvYXN0LnN1Y2Nlc3MoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5zYXZlU3VjY2VzcycpKTtcbiAgICAgIH0sIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgUHJUb2FzdC5lcnJvcigkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLm9wZXJhdGlvbkVycm9yJykpO1xuICAgICAgfSk7XG4gICAgfTtcblxuICAgIHZtLnJlbW92ZUNvbW1lbnQgPSBmdW5jdGlvbiAoY29tbWVudCkge1xuICAgICAgVGFza0NvbW1lbnRzU2VydmljZS5yZW1vdmVUYXNrQ29tbWVudCh7IGNvbW1lbnRfaWQ6IGNvbW1lbnQuaWQgfSkudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgIHZtLnNlYXJjaCgpO1xuICAgICAgICBQclRvYXN0LnN1Y2Nlc3MoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5yZW1vdmVTdWNjZXNzJykpO1xuICAgICAgfSwgZnVuY3Rpb24gKCkge1xuICAgICAgICBQclRvYXN0LmVycm9yKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMub3BlcmF0aW9uRXJyb3InKSk7XG4gICAgICB9KTtcbiAgICB9O1xuXG4gICAgdm0uYWZ0ZXJTZWFyY2ggPSBmdW5jdGlvbiAoKSB7XG4gICAgICBpZiAodm0ucmVzb3VyY2UuaWQpIHtcbiAgICAgICAgdm0ucmVzb3VyY2UgPSAkZmlsdGVyKCdmaWx0ZXInKSh2bS5yZXNvdXJjZXMsIHsgaWQ6IHZtLnJlc291cmNlLmlkIH0pWzBdO1xuICAgICAgfVxuICAgIH07XG5cbiAgICB2bS5maXhEYXRlID0gZnVuY3Rpb24gKGRhdGVTdHJpbmcpIHtcbiAgICAgIHJldHVybiBtb21lbnQoZGF0ZVN0cmluZyk7XG4gICAgfTtcblxuICAgIC8vIGluc3RhbnRpYXRlIGJhc2UgY29udHJvbGxlclxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHsgdm06IHZtLCBtb2RlbFNlcnZpY2U6IFRhc2tzU2VydmljZSwgb3B0aW9uczogeyBza2lwUGFnaW5hdGlvbjogdHJ1ZSB9IH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKlxuICAgKiBBcnF1aXZvIGRlIGNvbmZpZ3VyYcOnw6NvIGNvbSBhcyByb3RhcyBlc3BlY8OtZmljYXMgZG8gcmVjdXJzbyBwcm9qZWN0XG4gICAqXG4gICAqIEBwYXJhbSB7YW55fSAkc3RhdGVQcm92aWRlclxuICAgKiBAcGFyYW0ge2FueX0gR2xvYmFsXG4gICAqL1xuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvdXRlcygkc3RhdGVQcm92aWRlciwgR2xvYmFsKSB7XG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ2FwcC50YXNrcycsIHtcbiAgICAgIHVybDogJy90YXNrcycsXG4gICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL3Rhc2tzL3Rhc2tzLmh0bWwnLFxuICAgICAgY29udHJvbGxlcjogJ1Rhc2tzQ29udHJvbGxlciBhcyB0YXNrc0N0cmwnLFxuICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IHRydWUgfVxuICAgIH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZhY3RvcnkoJ1Rhc2tzU2VydmljZScsIFRhc2tzU2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiBUYXNrc1NlcnZpY2Uoc2VydmljZUZhY3RvcnkpIHtcbiAgICByZXR1cm4gc2VydmljZUZhY3RvcnkoJ3Rhc2tzJywge1xuICAgICAgYWN0aW9uczoge1xuICAgICAgICB1cGRhdGVNaWxlc3RvbmU6IHtcbiAgICAgICAgICBtZXRob2Q6ICdQT1NUJyxcbiAgICAgICAgICB1cmw6ICd1cGRhdGVNaWxlc3RvbmUnXG4gICAgICAgIH0sXG4gICAgICAgIHVwZGF0ZVRhc2tCeUthbmJhbjoge1xuICAgICAgICAgIG1ldGhvZDogJ1BPU1QnLFxuICAgICAgICAgIHVybDogJ3VwZGF0ZVRhc2tCeUthbmJhbidcbiAgICAgICAgfVxuICAgICAgfSxcbiAgICAgIGluc3RhbmNlOiB7fVxuICAgIH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZhY3RvcnkoJ1R5cGVzU2VydmljZScsIFR5cGVzU2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiBUeXBlc1NlcnZpY2Uoc2VydmljZUZhY3RvcnkpIHtcbiAgICB2YXIgbW9kZWwgPSBzZXJ2aWNlRmFjdG9yeSgndHlwZXMnLCB7XG4gICAgICBhY3Rpb25zOiB7fSxcbiAgICAgIGluc3RhbmNlOiB7fVxuICAgIH0pO1xuXG4gICAgcmV0dXJuIG1vZGVsO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29udHJvbGxlcignUHJvZmlsZUNvbnRyb2xsZXInLCBQcm9maWxlQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBQcm9maWxlQ29udHJvbGxlcihVc2Vyc1NlcnZpY2UsIEF1dGgsIFByVG9hc3QsICR0cmFuc2xhdGUsICR3aW5kb3csIG1vbWVudCkge1xuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICB2bS51cGRhdGUgPSB1cGRhdGU7XG4gICAgdm0uaGlzdG9yeUJhY2sgPSBoaXN0b3J5QmFjaztcblxuICAgIGFjdGl2YXRlKCk7XG5cbiAgICBmdW5jdGlvbiBhY3RpdmF0ZSgpIHtcbiAgICAgIHZtLnVzZXIgPSBhbmd1bGFyLmNvcHkoQXV0aC5jdXJyZW50VXNlcik7XG4gICAgICBpZiAodm0udXNlci5iaXJ0aGRheSkge1xuICAgICAgICB2bS51c2VyLmJpcnRoZGF5ID0gbW9tZW50KHZtLnVzZXIuYmlydGhkYXkpLmZvcm1hdCgnREQvTU0vWVlZWScpO1xuICAgICAgfVxuICAgIH1cblxuICAgIGZ1bmN0aW9uIHVwZGF0ZSgpIHtcbiAgICAgIGlmICh2bS51c2VyLmJpcnRoZGF5KSB7XG4gICAgICAgIHZtLnVzZXIuYmlydGhkYXkgPSBtb21lbnQodm0udXNlci5iaXJ0aGRheSk7XG4gICAgICB9XG4gICAgICBVc2Vyc1NlcnZpY2UudXBkYXRlUHJvZmlsZSh2bS51c2VyKS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICAvL2F0dWFsaXphIG8gdXN1w6FyaW8gY29ycmVudGUgY29tIGFzIG5vdmFzIGluZm9ybWHDp8O1ZXNcbiAgICAgICAgQXV0aC51cGRhdGVDdXJyZW50VXNlcihyZXNwb25zZSk7XG4gICAgICAgIFByVG9hc3Quc3VjY2VzcygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnNhdmVTdWNjZXNzJykpO1xuICAgICAgICBoaXN0b3J5QmFjaygpO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gaGlzdG9yeUJhY2soKSB7XG4gICAgICAkd2luZG93Lmhpc3RvcnkuYmFjaygpO1xuICAgIH1cbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbnRyb2xsZXIoJ1VzZXJzQ29udHJvbGxlcicsIFVzZXJzQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBVc2Vyc0NvbnRyb2xsZXIoJGNvbnRyb2xsZXIsIFVzZXJzU2VydmljZSwgUHJUb2FzdCwgJG1kRGlhbG9nLCAkdHJhbnNsYXRlKSB7XG5cbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0ub25BY3RpdmF0ZSA9IG9uQWN0aXZhdGU7XG4gICAgLy8gaW5zdGFudGlhdGUgYmFzZSBjb250cm9sbGVyXG4gICAgJGNvbnRyb2xsZXIoJ0NSVURDb250cm9sbGVyJywgeyB2bTogdm0sIG1vZGVsU2VydmljZTogVXNlcnNTZXJ2aWNlLCBvcHRpb25zOiB7fSB9KTtcblxuICAgIGZ1bmN0aW9uIG9uQWN0aXZhdGUoKSB7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMgPSB7fTtcbiAgICB9XG5cbiAgICB2bS5oaWRlRGlhbG9nID0gZnVuY3Rpb24gKCkge1xuICAgICAgJG1kRGlhbG9nLmhpZGUoKTtcbiAgICB9O1xuXG4gICAgdm0uc2F2ZU5ld1VzZXIgPSBmdW5jdGlvbiAoKSB7XG4gICAgICB2bS5yZXNvdXJjZS4kc2F2ZSgpLnRoZW4oZnVuY3Rpb24gKHJlc291cmNlKSB7XG4gICAgICAgIHZtLnJlc291cmNlID0gcmVzb3VyY2U7XG4gICAgICAgIFByVG9hc3Quc3VjY2VzcygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnN1Y2Nlc3NTaWduVXAnKSk7XG4gICAgICAgICRtZERpYWxvZy5oaWRlKCk7XG4gICAgICB9KTtcbiAgICB9O1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKlxuICAgKiBBcnF1aXZvIGRlIGNvbmZpZ3VyYcOnw6NvIGNvbSBhcyByb3RhcyBlc3BlY8OtZmljYXMgZG8gcmVjdXJzbyB1c2VyXG4gICAqXG4gICAqIEBwYXJhbSB7YW55fSAkc3RhdGVQcm92aWRlclxuICAgKiBAcGFyYW0ge2FueX0gR2xvYmFsXG4gICAqL1xuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvdXRlcygkc3RhdGVQcm92aWRlciwgR2xvYmFsKSB7XG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ2FwcC51c2VyJywge1xuICAgICAgdXJsOiAnL3VzdWFyaW8nLFxuICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy91c2Vycy91c2Vycy5odG1sJyxcbiAgICAgIGNvbnRyb2xsZXI6ICdVc2Vyc0NvbnRyb2xsZXIgYXMgdXNlcnNDdHJsJyxcbiAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiB0cnVlLCBuZWVkUHJvZmlsZTogWydhZG1pbiddIH1cbiAgICB9KS5zdGF0ZSgnYXBwLnVzZXItcHJvZmlsZScsIHtcbiAgICAgIHVybDogJy91c3VhcmlvL3BlcmZpbCcsXG4gICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL3VzZXJzL3Byb2ZpbGUuaHRtbCcsXG4gICAgICBjb250cm9sbGVyOiAnUHJvZmlsZUNvbnRyb2xsZXIgYXMgcHJvZmlsZUN0cmwnLFxuICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IHRydWUgfVxuICAgIH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZhY3RvcnkoJ1VzZXJzU2VydmljZScsIFVzZXJzU2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBVc2Vyc1NlcnZpY2UobG9kYXNoLCBHbG9iYWwsIHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCd1c2VycycsIHtcbiAgICAgIC8vcXVhbmRvIGluc3RhbmNpYSB1bSB1c3XDoXJpbyBzZW0gcGFzc2FyIHBhcmFtZXRybyxcbiAgICAgIC8vbyBtZXNtbyB2YWkgdGVyIG9zIHZhbG9yZXMgZGVmYXVsdHMgYWJhaXhvXG4gICAgICBkZWZhdWx0czoge1xuICAgICAgICByb2xlczogW11cbiAgICAgIH0sXG5cbiAgICAgIGFjdGlvbnM6IHtcbiAgICAgICAgLyoqXG4gICAgICAgICAqIFNlcnZpw6dvIHF1ZSBhdHVhbGl6YSBvcyBkYWRvcyBkbyBwZXJmaWwgZG8gdXN1w6FyaW8gbG9nYWRvXG4gICAgICAgICAqXG4gICAgICAgICAqIEBwYXJhbSB7b2JqZWN0fSBhdHRyaWJ1dGVzXG4gICAgICAgICAqIEByZXR1cm5zIHtwcm9taXNlfSBVbWEgcHJvbWlzZSBjb20gbyByZXN1bHRhZG8gZG8gY2hhbWFkYSBubyBiYWNrZW5kXG4gICAgICAgICAqL1xuICAgICAgICB1cGRhdGVQcm9maWxlOiB7XG4gICAgICAgICAgbWV0aG9kOiAnUFVUJyxcbiAgICAgICAgICB1cmw6IEdsb2JhbC5hcGlQYXRoICsgJy9wcm9maWxlJyxcbiAgICAgICAgICBvdmVycmlkZTogdHJ1ZSxcbiAgICAgICAgICB3cmFwOiBmYWxzZVxuICAgICAgICB9XG4gICAgICB9LFxuXG4gICAgICBpbnN0YW5jZToge1xuICAgICAgICAvKipcbiAgICAgICAgICogVmVyaWZpY2Egc2UgbyB1c3XDoXJpbyB0ZW0gb3MgcGVyZmlzIGluZm9ybWFkb3MuXG4gICAgICAgICAqXG4gICAgICAgICAqIEBwYXJhbSB7YW55fSByb2xlcyBwZXJmaXMgYSBzZXJlbSB2ZXJpZmljYWRvc1xuICAgICAgICAgKiBAcGFyYW0ge2Jvb2xlYW59IGFsbCBmbGFnIHBhcmEgaW5kaWNhciBzZSB2YWkgY2hlZ2FyIHRvZG9zIG9zIHBlcmZpcyBvdSBzb21lbnRlIHVtIGRlbGVzXG4gICAgICAgICAqIEByZXR1cm5zIHtib29sZWFufVxuICAgICAgICAgKi9cbiAgICAgICAgaGFzUHJvZmlsZTogZnVuY3Rpb24gaGFzUHJvZmlsZShyb2xlcywgYWxsKSB7XG4gICAgICAgICAgcm9sZXMgPSBhbmd1bGFyLmlzQXJyYXkocm9sZXMpID8gcm9sZXMgOiBbcm9sZXNdO1xuXG4gICAgICAgICAgdmFyIHVzZXJSb2xlcyA9IGxvZGFzaC5tYXAodGhpcy5yb2xlcywgJ3NsdWcnKTtcblxuICAgICAgICAgIGlmIChhbGwpIHtcbiAgICAgICAgICAgIHJldHVybiBsb2Rhc2guaW50ZXJzZWN0aW9uKHVzZXJSb2xlcywgcm9sZXMpLmxlbmd0aCA9PT0gcm9sZXMubGVuZ3RoO1xuICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAvL3JldHVybiB0aGUgbGVuZ3RoIGJlY2F1c2UgMCBpcyBmYWxzZSBpbiBqc1xuICAgICAgICAgICAgcmV0dXJuIGxvZGFzaC5pbnRlcnNlY3Rpb24odXNlclJvbGVzLCByb2xlcykubGVuZ3RoO1xuICAgICAgICAgIH1cbiAgICAgICAgfSxcblxuICAgICAgICAvKipcbiAgICAgICAgICogVmVyaWZpY2Egc2UgbyB1c3XDoXJpbyB0ZW0gbyBwZXJmaWwgYWRtaW4uXG4gICAgICAgICAqXG4gICAgICAgICAqIEByZXR1cm5zIHtib29sZWFufVxuICAgICAgICAgKi9cbiAgICAgICAgaXNBZG1pbjogZnVuY3Rpb24gaXNBZG1pbigpIHtcbiAgICAgICAgICByZXR1cm4gdGhpcy5oYXNQcm9maWxlKCdhZG1pbicpO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbi8vdG9rZW4gY2FjYjkxMjM1ODczYThjNDg3NWQyMzU3OGFjOWYzMjZlZjg5NGI2NlxuLy8gT0F0dXRoIGh0dHBzOi8vZ2l0aHViLmNvbS9sb2dpbi9vYXV0aC9hdXRob3JpemU/Y2xpZW50X2lkPTgyOTQ2OGU3ZmRlZTc5NDQ1YmE2JnNjb3BlPXVzZXIscHVibGljX3JlcG8mcmVkaXJlY3RfdXJpPWh0dHA6Ly8wLjAuMC4wOjUwMDAvIyEvYXBwL3Zjc1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZpbHRlcignYnl0ZXMnLCBmdW5jdGlvbiAoKSB7XG4gICAgcmV0dXJuIGZ1bmN0aW9uIChieXRlcywgcHJlY2lzaW9uKSB7XG4gICAgICBpZiAoaXNOYU4ocGFyc2VGbG9hdChieXRlcykpIHx8ICFpc0Zpbml0ZShieXRlcykpIHJldHVybiAnLSc7XG4gICAgICBpZiAodHlwZW9mIHByZWNpc2lvbiA9PT0gJ3VuZGVmaW5lZCcpIHByZWNpc2lvbiA9IDE7XG4gICAgICB2YXIgdW5pdHMgPSBbJ2J5dGVzJywgJ2tCJywgJ01CJywgJ0dCJywgJ1RCJywgJ1BCJ10sXG4gICAgICAgICAgbnVtYmVyID0gTWF0aC5mbG9vcihNYXRoLmxvZyhieXRlcykgLyBNYXRoLmxvZygxMDI0KSk7XG5cbiAgICAgIHJldHVybiAoYnl0ZXMgLyBNYXRoLnBvdygxMDI0LCBNYXRoLmZsb29yKG51bWJlcikpKS50b0ZpeGVkKHByZWNpc2lvbikgKyAnICcgKyB1bml0c1tudW1iZXJdO1xuICAgIH07XG4gIH0pLmNvbnRyb2xsZXIoJ1Zjc0NvbnRyb2xsZXInLCBWY3NDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIFZjc0NvbnRyb2xsZXIoJGNvbnRyb2xsZXIsIFZjc1NlcnZpY2UsICR3aW5kb3csIFByb2plY3RzU2VydmljZSwgUHJUb2FzdCwgJHRyYW5zbGF0ZSkge1xuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICB2bS5pbmRleCA9IDA7XG4gICAgdm0ucGF0aHMgPSBbXTtcblxuICAgIC8vQXR0cmlidXRlcyBCbG9ja1xuXG4gICAgLy9GdW5jdGlvbnMgQmxvY2tcbiAgICB2bS5vbkFjdGl2YXRlID0gZnVuY3Rpb24gKCkge1xuICAgICAgdG9nZ2xlU3BsYXNoU2NyZWVuKCk7XG4gICAgICBQcm9qZWN0c1NlcnZpY2UucXVlcnkoeyBwcm9qZWN0X2lkOiBsb2NhbFN0b3JhZ2UuZ2V0SXRlbSgncHJvamVjdCcpIH0pLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgIHZtLnVzZXJuYW1lID0gcmVzcG9uc2VbMF0udXNlcm5hbWVfZ2l0aHViO1xuICAgICAgICB2bS5yZXBvID0gcmVzcG9uc2VbMF0ucmVwb19naXRodWI7XG4gICAgICAgIHZtLnF1ZXJ5RmlsdGVycyA9IHtcbiAgICAgICAgICB1c2VybmFtZTogdm0udXNlcm5hbWUsXG4gICAgICAgICAgcmVwbzogdm0ucmVwbyxcbiAgICAgICAgICBwYXRoOiAnLidcbiAgICAgICAgfTtcbiAgICAgICAgdm0ucGF0aHMucHVzaCh2bS5xdWVyeUZpbHRlcnMucGF0aCk7XG4gICAgICAgIHZtLnNlYXJjaCgpO1xuICAgICAgfSk7XG4gICAgfTtcblxuICAgIHZtLmFwcGx5RmlsdGVycyA9IGZ1bmN0aW9uIChkZWZhdWx0UXVlcnlGaWx0ZXJzKSB7XG4gICAgICByZXR1cm4gYW5ndWxhci5leHRlbmQoZGVmYXVsdFF1ZXJ5RmlsdGVycywgdm0ucXVlcnlGaWx0ZXJzKTtcbiAgICB9O1xuXG4gICAgdm0uYWZ0ZXJTZWFyY2ggPSBmdW5jdGlvbiAoKSB7XG4gICAgICBzb3J0UmVzb3VyY2VzKCk7XG4gICAgICAkd2luZG93LmxvYWRpbmdfc2NyZWVuLmZpbmlzaCgpO1xuICAgIH07XG5cbiAgICBmdW5jdGlvbiBzb3J0UmVzb3VyY2VzKCkge1xuICAgICAgdm0ucmVzb3VyY2VzLnNvcnQoZnVuY3Rpb24gKGEsIGIpIHtcbiAgICAgICAgcmV0dXJuIGEudHlwZSA8IGIudHlwZSA/IC0xIDogYS50eXBlID4gYi50eXBlID8gMSA6IDA7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICB2bS5vcGVuRmlsZU9yRGlyZWN0b3J5ID0gZnVuY3Rpb24gKHJlc291cmNlKSB7XG4gICAgICB0b2dnbGVTcGxhc2hTY3JlZW4oKTtcbiAgICAgIGlmIChyZXNvdXJjZSkge1xuICAgICAgICB2bS5xdWVyeUZpbHRlcnMucGF0aCA9IHJlc291cmNlLnBhdGg7XG4gICAgICAgIHZtLnBhdGhzLnB1c2godm0ucXVlcnlGaWx0ZXJzLnBhdGgpO1xuICAgICAgICB2bS5pbmRleCsrO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgdm0ucXVlcnlGaWx0ZXJzLnBhdGggPSB2bS5wYXRoc1t2bS5pbmRleCAtIDFdO1xuICAgICAgICB2bS5wYXRocy5zcGxpY2Uodm0uaW5kZXgsIDEpO1xuICAgICAgICB2bS5pbmRleC0tO1xuICAgICAgfVxuICAgICAgdm0uc2VhcmNoKCk7XG4gICAgfTtcblxuICAgIHZtLm9uU2VhcmNoRXJyb3IgPSBmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgIGlmIChyZXNwb25zZS5kYXRhLmVycm9yID09PSAnTm90IEZvdW5kJykge1xuICAgICAgICBQclRvYXN0LmluZm8oJHRyYW5zbGF0ZS5pbnN0YW50KCdSZXBvc2l0w7NyaW8gbsOjbyBlbmNvbnRyYWRvJykpO1xuICAgICAgICAkd2luZG93LmxvYWRpbmdfc2NyZWVuLmZpbmlzaCgpO1xuICAgICAgfVxuICAgIH07XG5cbiAgICAvKipcbiAgICAgKiBNw6l0b2RvIHBhcmEgbW9zdHJhciBhIHRlbGEgZGUgZXNwZXJhXG4gICAgICovXG4gICAgZnVuY3Rpb24gdG9nZ2xlU3BsYXNoU2NyZWVuKCkge1xuICAgICAgJHdpbmRvdy5sb2FkaW5nX3NjcmVlbiA9ICR3aW5kb3cucGxlYXNlV2FpdCh7XG4gICAgICAgIGxvZ286ICcnLFxuICAgICAgICBiYWNrZ3JvdW5kQ29sb3I6ICdyZ2JhKDI1NSwyNTUsMjU1LDAuNCknLFxuICAgICAgICBsb2FkaW5nSHRtbDogJzxkaXYgY2xhc3M9XCJzcGlubmVyXCI+ICcgKyAnICA8ZGl2IGNsYXNzPVwicmVjdDFcIj48L2Rpdj4gJyArICcgIDxkaXYgY2xhc3M9XCJyZWN0MlwiPjwvZGl2PiAnICsgJyAgPGRpdiBjbGFzcz1cInJlY3QzXCI+PC9kaXY+ICcgKyAnICA8ZGl2IGNsYXNzPVwicmVjdDRcIj48L2Rpdj4gJyArICcgIDxkaXYgY2xhc3M9XCJyZWN0NVwiPjwvZGl2PiAnICsgJyA8cCBjbGFzcz1cImxvYWRpbmctbWVzc2FnZVwiPkNhcnJlZ2FuZG88L3A+ICcgKyAnPC9kaXY+J1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLy8gaW5zdGFudGlhdGUgYmFzZSBjb250cm9sbGVyXG4gICAgJGNvbnRyb2xsZXIoJ0NSVURDb250cm9sbGVyJywgeyB2bTogdm0sIG1vZGVsU2VydmljZTogVmNzU2VydmljZSwgb3B0aW9uczogeyBza2lwUGFnaW5hdGlvbjogdHJ1ZSwgc2VhcmNoT25Jbml0OiBmYWxzZSB9IH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKlxuICAgKiBBcnF1aXZvIGRlIGNvbmZpZ3VyYcOnw6NvIGNvbSBhcyByb3RhcyBlc3BlY8OtZmljYXMgZG8gcmVjdXJzbyB2Y3NcbiAgICpcbiAgICogQHBhcmFtIHtvYmplY3R9ICRzdGF0ZVByb3ZpZGVyXG4gICAqIEBwYXJhbSB7b2JqZWN0fSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnYXBwLnZjcycsIHtcbiAgICAgIHVybDogJy92Y3MnLFxuICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy92Y3MvdmNzLmh0bWwnLFxuICAgICAgY29udHJvbGxlcjogJ1Zjc0NvbnRyb2xsZXIgYXMgdmNzQ3RybCcsXG4gICAgICBkYXRhOiB7fVxuICAgIH0pO1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZhY3RvcnkoJ1Zjc1NlcnZpY2UnLCBWY3NTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIFZjc1NlcnZpY2Uoc2VydmljZUZhY3RvcnkpIHtcbiAgICB2YXIgbW9kZWwgPSBzZXJ2aWNlRmFjdG9yeSgndmNzJywge1xuICAgICAgYWN0aW9uczoge30sXG4gICAgICBpbnN0YW5jZToge31cbiAgICB9KTtcblxuICAgIHJldHVybiBtb2RlbDtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29tcG9uZW50KCdib3gnLCB7XG4gICAgcmVwbGFjZTogdHJ1ZSxcbiAgICB0ZW1wbGF0ZVVybDogWydHbG9iYWwnLCBmdW5jdGlvbiAoR2xvYmFsKSB7XG4gICAgICByZXR1cm4gR2xvYmFsLmNsaWVudFBhdGggKyAnL3dpZGdldHMvYm94Lmh0bWwnO1xuICAgIH1dLFxuICAgIHRyYW5zY2x1ZGU6IHtcbiAgICAgIHRvb2xiYXJCdXR0b25zOiAnP2JveFRvb2xiYXJCdXR0b25zJyxcbiAgICAgIGZvb3RlckJ1dHRvbnM6ICc/Ym94Rm9vdGVyQnV0dG9ucydcbiAgICB9LFxuICAgIGJpbmRpbmdzOiB7XG4gICAgICBib3hUaXRsZTogJ0AnLFxuICAgICAgdG9vbGJhckNsYXNzOiAnQCcsXG4gICAgICB0b29sYmFyQmdDb2xvcjogJ0AnXG4gICAgfSxcbiAgICBjb250cm9sbGVyOiBbJyR0cmFuc2NsdWRlJywgZnVuY3Rpb24gKCR0cmFuc2NsdWRlKSB7XG4gICAgICB2YXIgY3RybCA9IHRoaXM7XG5cbiAgICAgIGN0cmwudHJhbnNjbHVkZSA9ICR0cmFuc2NsdWRlO1xuXG4gICAgICBjdHJsLiRvbkluaXQgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgIGlmIChhbmd1bGFyLmlzVW5kZWZpbmVkKGN0cmwudG9vbGJhckJnQ29sb3IpKSBjdHJsLnRvb2xiYXJCZ0NvbG9yID0gJ2RlZmF1bHQtcHJpbWFyeSc7XG4gICAgICB9O1xuICAgIH1dXG4gIH0pO1xufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29tcG9uZW50KCdjb250ZW50Qm9keScsIHtcbiAgICByZXBsYWNlOiB0cnVlLFxuICAgIHRyYW5zY2x1ZGU6IHRydWUsXG4gICAgdGVtcGxhdGVVcmw6IFsnR2xvYmFsJywgZnVuY3Rpb24gKEdsb2JhbCkge1xuICAgICAgcmV0dXJuIEdsb2JhbC5jbGllbnRQYXRoICsgJy93aWRnZXRzL2NvbnRlbnQtYm9keS5odG1sJztcbiAgICB9XSxcbiAgICBiaW5kaW5nczoge1xuICAgICAgbGF5b3V0QWxpZ246ICdAJ1xuICAgIH0sXG4gICAgY29udHJvbGxlcjogW2Z1bmN0aW9uICgpIHtcbiAgICAgIHZhciBjdHJsID0gdGhpcztcblxuICAgICAgY3RybC4kb25Jbml0ID0gZnVuY3Rpb24gKCkge1xuICAgICAgICAvLyBNYWtlIGEgY29weSBvZiB0aGUgaW5pdGlhbCB2YWx1ZSB0byBiZSBhYmxlIHRvIHJlc2V0IGl0IGxhdGVyXG4gICAgICAgIGN0cmwubGF5b3V0QWxpZ24gPSBhbmd1bGFyLmlzRGVmaW5lZChjdHJsLmxheW91dEFsaWduKSA/IGN0cmwubGF5b3V0QWxpZ24gOiAnY2VudGVyIHN0YXJ0JztcbiAgICAgIH07XG4gICAgfV1cbiAgfSk7XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb21wb25lbnQoJ2NvbnRlbnRIZWFkZXInLCB7XG4gICAgdGVtcGxhdGVVcmw6IFsnR2xvYmFsJywgZnVuY3Rpb24gKEdsb2JhbCkge1xuICAgICAgcmV0dXJuIEdsb2JhbC5jbGllbnRQYXRoICsgJy93aWRnZXRzL2NvbnRlbnQtaGVhZGVyLmh0bWwnO1xuICAgIH1dLFxuICAgIHJlcGxhY2U6IHRydWUsXG4gICAgYmluZGluZ3M6IHtcbiAgICAgIHRpdGxlOiAnQCcsXG4gICAgICBkZXNjcmlwdGlvbjogJ0AnXG4gICAgfVxuICB9KTtcbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5maWx0ZXIoJ2F1ZGl0RGV0YWlsVGl0bGUnLCBhdWRpdERldGFpbFRpdGxlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIGF1ZGl0RGV0YWlsVGl0bGUoJHRyYW5zbGF0ZSkge1xuICAgIHJldHVybiBmdW5jdGlvbiAoYXVkaXREZXRhaWwsIHN0YXR1cykge1xuICAgICAgaWYgKGF1ZGl0RGV0YWlsLnR5cGUgPT09ICd1cGRhdGVkJykge1xuICAgICAgICBpZiAoc3RhdHVzID09PSAnYmVmb3JlJykge1xuICAgICAgICAgIHJldHVybiAkdHJhbnNsYXRlLmluc3RhbnQoJ2RpYWxvZy5hdWRpdC51cGRhdGVkQmVmb3JlJyk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgcmV0dXJuICR0cmFuc2xhdGUuaW5zdGFudCgnZGlhbG9nLmF1ZGl0LnVwZGF0ZWRBZnRlcicpO1xuICAgICAgICB9XG4gICAgICB9IGVsc2Uge1xuICAgICAgICByZXR1cm4gJHRyYW5zbGF0ZS5pbnN0YW50KCdkaWFsb2cuYXVkaXQuJyArIGF1ZGl0RGV0YWlsLnR5cGUpO1xuICAgICAgfVxuICAgIH07XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5maWx0ZXIoJ2F1ZGl0TW9kZWwnLCBhdWRpdE1vZGVsKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIGF1ZGl0TW9kZWwoJHRyYW5zbGF0ZSkge1xuICAgIHJldHVybiBmdW5jdGlvbiAobW9kZWxJZCkge1xuICAgICAgbW9kZWxJZCA9IG1vZGVsSWQucmVwbGFjZSgnQXBwXFxcXCcsICcnKTtcbiAgICAgIHZhciBtb2RlbCA9ICR0cmFuc2xhdGUuaW5zdGFudCgnbW9kZWxzLicgKyBtb2RlbElkLnRvTG93ZXJDYXNlKCkpO1xuXG4gICAgICByZXR1cm4gbW9kZWwgPyBtb2RlbCA6IG1vZGVsSWQ7XG4gICAgfTtcbiAgfVxufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhci5tb2R1bGUoJ2FwcCcpLmZpbHRlcignYXVkaXRUeXBlJywgYXVkaXRUeXBlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIGF1ZGl0VHlwZShsb2Rhc2gsIEF1ZGl0U2VydmljZSkge1xuICAgIHJldHVybiBmdW5jdGlvbiAodHlwZUlkKSB7XG4gICAgICB2YXIgdHlwZSA9IGxvZGFzaC5maW5kKEF1ZGl0U2VydmljZS5saXN0VHlwZXMoKSwgeyBpZDogdHlwZUlkIH0pO1xuXG4gICAgICByZXR1cm4gdHlwZSA/IHR5cGUubGFiZWwgOiB0eXBlO1xuICAgIH07XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5maWx0ZXIoJ2F1ZGl0VmFsdWUnLCBhdWRpdFZhbHVlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIGF1ZGl0VmFsdWUoJGZpbHRlciwgbG9kYXNoKSB7XG4gICAgcmV0dXJuIGZ1bmN0aW9uICh2YWx1ZSwga2V5KSB7XG4gICAgICBpZiAoYW5ndWxhci5pc0RhdGUodmFsdWUpIHx8IGxvZGFzaC5lbmRzV2l0aChrZXksICdfYXQnKSB8fCBsb2Rhc2guZW5kc1dpdGgoa2V5LCAnX3RvJykpIHtcbiAgICAgICAgcmV0dXJuICRmaWx0ZXIoJ3ByRGF0ZXRpbWUnKSh2YWx1ZSk7XG4gICAgICB9XG5cbiAgICAgIGlmICh0eXBlb2YgdmFsdWUgPT09ICdib29sZWFuJykge1xuICAgICAgICByZXR1cm4gJGZpbHRlcigndHJhbnNsYXRlJykodmFsdWUgPyAnZ2xvYmFsLnllcycgOiAnZ2xvYmFsLm5vJyk7XG4gICAgICB9XG5cbiAgICAgIC8vY2hlY2sgaXMgZmxvYXRcbiAgICAgIGlmIChOdW1iZXIodmFsdWUpID09PSB2YWx1ZSAmJiB2YWx1ZSAlIDEgIT09IDApIHtcbiAgICAgICAgcmV0dXJuICRmaWx0ZXIoJ3JlYWwnKSh2YWx1ZSk7XG4gICAgICB9XG5cbiAgICAgIHJldHVybiB2YWx1ZTtcbiAgICB9O1xuICB9XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4vKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCwgbm8tdW5kZWY6IDAqL1xuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25zdGFudCgncHQtQlIuaTE4bi5hdHRyaWJ1dGVzJywge1xuICAgIGVtYWlsOiAnRW1haWwnLFxuICAgIHBhc3N3b3JkOiAnU2VuaGEnLFxuICAgIG5hbWU6ICdOb21lJyxcbiAgICBpbWFnZTogJ0ltYWdlbScsXG4gICAgcm9sZXM6ICdQZXJmaXMnLFxuICAgIGRhdGU6ICdEYXRhJyxcbiAgICBpbml0aWFsRGF0ZTogJ0RhdGEgSW5pY2lhbCcsXG4gICAgZmluYWxEYXRlOiAnRGF0YSBGaW5hbCcsXG4gICAgYmlydGhkYXk6ICdEYXRhIGRlIE5hc2NpbWVudG8nLFxuICAgIHRhc2s6IHtcbiAgICAgIGRlc2NyaXB0aW9uOiAnRGVzY3Jpw6fDo28nLFxuICAgICAgZG9uZTogJ0ZlaXRvPycsXG4gICAgICBwcmlvcml0eTogJ1ByaW9yaWRhZGUnLFxuICAgICAgc2NoZWR1bGVkX3RvOiAnQWdlbmRhZG8gUGFyYT8nLFxuICAgICAgcHJvamVjdDogJ1Byb2pldG8nLFxuICAgICAgc3RhdHVzOiAnU3RhdHVzJyxcbiAgICAgIHRpdGxlOiAnVMOtdHVsbycsXG4gICAgICB0eXBlOiAnVGlwbycsXG4gICAgICBtaWxlc3RvbmU6ICdTcHJpbnQnLFxuICAgICAgZXN0aW1hdGVkX3RpbWU6ICdUZW1wbyBFc3RpbWFkbydcbiAgICB9LFxuICAgIG1pbGVzdG9uZToge1xuICAgICAgdGl0bGU6ICdUw610dWxvJyxcbiAgICAgIGRlc2NyaXB0aW9uOiAnRGVzY3Jpw6fDo28nLFxuICAgICAgZGF0ZV9zdGFydDogJ0RhdGEgRXN0aW1hZGEgcGFyYSBJbsOtY2lvJyxcbiAgICAgIGRhdGVfZW5kOiAnRGF0YSBFc3RpbWFkYSBwYXJhIEZpbScsXG4gICAgICBlc3RpbWF0ZWRfdGltZTogJ1RlbXBvIEVzdGltYWRvJyxcbiAgICAgIGVzdGltYXRlZF92YWx1ZTogJ1ZhbG9yIEVzdGltYWRvJ1xuICAgIH0sXG4gICAgcHJvamVjdDoge1xuICAgICAgY29zdDogJ0N1c3RvJyxcbiAgICAgIGhvdXJWYWx1ZURldmVsb3BlcjogJ1ZhbG9yIGRhIEhvcmEgRGVzZW52b2x2ZWRvcicsXG4gICAgICBob3VyVmFsdWVDbGllbnQ6ICdWYWxvciBkYSBIb3JhIENsaWVudGUnLFxuICAgICAgaG91clZhbHVlRmluYWw6ICdWYWxvciBkYSBIb3JhIFByb2pldG8nXG4gICAgfSxcbiAgICByZWxlYXNlOiB7XG4gICAgICB0aXRsZTogJ1TDrXR1bG8nLFxuICAgICAgZGVzY3JpcHRpb246ICdEZXNjcmnDp8OjbycsXG4gICAgICByZWxlYXNlX2RhdGU6ICdEYXRhIGRlIEVudHJlZ2EnLFxuICAgICAgbWlsZXN0b25lOiAnTWlsZXN0b25lJyxcbiAgICAgIHRhc2tzOiAnVGFyZWZhcydcbiAgICB9LFxuICAgIC8vw6kgY2FycmVnYWRvIGRvIHNlcnZpZG9yIGNhc28gZXN0ZWphIGRlZmluaWRvIG5vIG1lc21vXG4gICAgYXVkaXRNb2RlbDoge31cbiAgfSk7XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4vKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCwgbm8tdW5kZWY6IDAqL1xuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25zdGFudCgncHQtQlIuaTE4bi5kaWFsb2cnLCB7XG4gICAgY29uZmlybVRpdGxlOiAnQ29uZmlybWHDp8OjbycsXG4gICAgY29uZmlybURlc2NyaXB0aW9uOiAnQ29uZmlybWEgYSBhw6fDo28/JyxcbiAgICByZW1vdmVEZXNjcmlwdGlvbjogJ0Rlc2VqYSByZW1vdmVyIHBlcm1hbmVudGVtZW50ZSB7e25hbWV9fT8nLFxuICAgIGF1ZGl0OiB7XG4gICAgICBjcmVhdGVkOiAnSW5mb3JtYcOnw7VlcyBkbyBDYWRhc3RybycsXG4gICAgICB1cGRhdGVkQmVmb3JlOiAnQW50ZXMgZGEgQXR1YWxpemHDp8OjbycsXG4gICAgICB1cGRhdGVkQWZ0ZXI6ICdEZXBvaXMgZGEgQXR1YWxpemHDp8OjbycsXG4gICAgICBkZWxldGVkOiAnSW5mb3JtYcOnw7VlcyBhbnRlcyBkZSByZW1vdmVyJ1xuICAgIH0sXG4gICAgbG9naW46IHtcbiAgICAgIHJlc2V0UGFzc3dvcmQ6IHtcbiAgICAgICAgZGVzY3JpcHRpb246ICdEaWdpdGUgYWJhaXhvIG8gZW1haWwgY2FkYXN0cmFkbyBubyBzaXN0ZW1hLidcbiAgICAgIH1cbiAgICB9XG4gIH0pO1xufSkoKTtcbid1c2Ugc3RyaWN0JztcblxuLyplc2xpbnQgYW5ndWxhci9maWxlLW5hbWU6IDAsIG5vLXVuZGVmOiAwKi9cbihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29uc3RhbnQoJ3B0LUJSLmkxOG4uZ2xvYmFsJywge1xuICAgIGxvYWRpbmc6ICdDYXJyZWdhbmRvLi4uJyxcbiAgICBwcm9jZXNzaW5nOiAnUHJvY2Vzc2FuZG8uLi4nLFxuICAgIHllczogJ1NpbScsXG4gICAgbm86ICdOw6NvJyxcbiAgICBhbGw6ICdUb2RvcydcbiAgfSk7XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4vKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCwgbm8tdW5kZWY6IDAqL1xuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25zdGFudCgncHQtQlIuaTE4bi5tZXNzYWdlcycsIHtcbiAgICBpbnRlcm5hbEVycm9yOiAnT2NvcnJldSB1bSBlcnJvIGludGVybm8sIGNvbnRhdGUgbyBhZG1pbmlzdHJhZG9yIGRvIHNpc3RlbWEnLFxuICAgIG5vdEZvdW5kOiAnTmVuaHVtIHJlZ2lzdHJvIGVuY29udHJhZG8nLFxuICAgIG5vdEF1dGhvcml6ZWQ6ICdWb2PDqiBuw6NvIHRlbSBhY2Vzc28gYSBlc3RhIGZ1bmNpb25hbGlkYWRlLicsXG4gICAgc2VhcmNoRXJyb3I6ICdOw6NvIGZvaSBwb3Nzw612ZWwgcmVhbGl6YXIgYSBidXNjYS4nLFxuICAgIHNhdmVTdWNjZXNzOiAnUmVnaXN0cm8gc2Fsdm8gY29tIHN1Y2Vzc28uJyxcbiAgICBvcGVyYXRpb25TdWNjZXNzOiAnT3BlcmHDp8OjbyByZWFsaXphZGEgY29tIHN1Y2Vzc28uJyxcbiAgICBvcGVyYXRpb25FcnJvcjogJ0Vycm8gYW8gcmVhbGl6YXIgYSBvcGVyYcOnw6NvJyxcbiAgICBzYXZlRXJyb3I6ICdFcnJvIGFvIHRlbnRhciBzYWx2YXIgbyByZWdpc3Ryby4nLFxuICAgIHJlbW92ZVN1Y2Nlc3M6ICdSZW1vw6fDo28gcmVhbGl6YWRhIGNvbSBzdWNlc3NvLicsXG4gICAgcmVtb3ZlRXJyb3I6ICdFcnJvIGFvIHRlbnRhciByZW1vdmVyIG8gcmVnaXN0cm8uJyxcbiAgICByZXNvdXJjZU5vdEZvdW5kRXJyb3I6ICdSZWN1cnNvIG7Do28gZW5jb250cmFkbycsXG4gICAgbm90TnVsbEVycm9yOiAnVG9kb3Mgb3MgY2FtcG9zIG9icmlnYXTDs3Jpb3MgZGV2ZW0gc2VyIHByZWVuY2hpZG9zLicsXG4gICAgZHVwbGljYXRlZFJlc291cmNlRXJyb3I6ICdKw6EgZXhpc3RlIHVtIHJlY3Vyc28gY29tIGVzc2FzIGluZm9ybWHDp8O1ZXMuJyxcbiAgICBzcHJpbnRFbmRlZFN1Y2Nlc3M6ICdTcHJpbnQgZmluYWxpemFkYSBjb20gc3VjZXNzbycsXG4gICAgc3ByaW50RW5kZWRFcnJvcjogJ0Vycm8gYW8gZmluYWxpemFyIGEgc3ByaW50JyxcbiAgICBzdWNjZXNzU2lnblVwOiAnQ2FkYXN0cm8gcmVhbGl6YWRvIGNvbSBzdWNlc3NvLiBVbSBlLW1haWwgZm9pIGVudmlhZG8gY29tIHNldXMgZGFkb3MgZGUgbG9naW4nLFxuICAgIGVycm9yc1NpZ25VcDogJ0hvdXZlIHVtIGVycm8gYW8gcmVhbGl6YXIgbyBzZXUgY2FkYXN0cm8uIFRlbnRlIG5vdmFtZW50ZSBtYWlzIHRhcmRlIScsXG4gICAgdmFsaWRhdGU6IHtcbiAgICAgIGZpZWxkUmVxdWlyZWQ6ICdPIGNhbXBvIHt7ZmllbGR9fSDDqSBvYnJpZ3JhdMOzcmlvLidcbiAgICB9LFxuICAgIGxheW91dDoge1xuICAgICAgZXJyb3I0MDQ6ICdQw6FnaW5hIG7Do28gZW5jb250cmFkYSdcbiAgICB9LFxuICAgIGxvZ2luOiB7XG4gICAgICBsb2dvdXRJbmFjdGl2ZTogJ1ZvY8OqIGZvaSBkZXNsb2dhZG8gZG8gc2lzdGVtYSBwb3IgaW5hdGl2aWRhZGUuIEZhdm9yIGVudHJhciBubyBzaXN0ZW1hIG5vdmFtZW50ZS4nLFxuICAgICAgaW52YWxpZENyZWRlbnRpYWxzOiAnQ3JlZGVuY2lhaXMgSW52w6FsaWRhcycsXG4gICAgICB1bmtub3duRXJyb3I6ICdOw6NvIGZvaSBwb3Nzw612ZWwgcmVhbGl6YXIgbyBsb2dpbi4gVGVudGUgbm92YW1lbnRlLiAnICsgJ0Nhc28gbsOjbyBjb25zaWdhIGZhdm9yIGVuY29udHJhciBlbSBjb250YXRvIGNvbSBvIGFkbWluaXN0cmFkb3IgZG8gc2lzdGVtYS4nLFxuICAgICAgdXNlck5vdEZvdW5kOiAnTsOjbyBmb2kgcG9zc8OtdmVsIGVuY29udHJhciBzZXVzIGRhZG9zJ1xuICAgIH0sXG4gICAgZGFzaGJvYXJkOiB7XG4gICAgICB3ZWxjb21lOiAnU2VqYSBiZW0gVmluZG8ge3t1c2VyTmFtZX19JyxcbiAgICAgIGRlc2NyaXB0aW9uOiAnVXRpbGl6ZSBvIG1lbnUgcGFyYSBuYXZlZ2HDp8Ojby4nXG4gICAgfSxcbiAgICBtYWlsOiB7XG4gICAgICBtYWlsRXJyb3JzOiAnT2NvcnJldSB1bSBlcnJvIG5vcyBzZWd1aW50ZXMgZW1haWxzIGFiYWl4bzpcXG4nLFxuICAgICAgc2VuZE1haWxTdWNjZXNzOiAnRW1haWwgZW52aWFkbyBjb20gc3VjZXNzbyEnLFxuICAgICAgc2VuZE1haWxFcnJvcjogJ07Do28gZm9pIHBvc3PDrXZlbCBlbnZpYXIgbyBlbWFpbC4nLFxuICAgICAgcGFzc3dvcmRTZW5kaW5nU3VjY2VzczogJ08gcHJvY2Vzc28gZGUgcmVjdXBlcmHDp8OjbyBkZSBzZW5oYSBmb2kgaW5pY2lhZG8uIENhc28gbyBlbWFpbCBuw6NvIGNoZWd1ZSBlbSAxMCBtaW51dG9zIHRlbnRlIG5vdmFtZW50ZS4nXG4gICAgfSxcbiAgICB1c2VyOiB7XG4gICAgICByZW1vdmVZb3VyU2VsZkVycm9yOiAnVm9jw6ogbsOjbyBwb2RlIHJlbW92ZXIgc2V1IHByw7NwcmlvIHVzdcOhcmlvJyxcbiAgICAgIHVzZXJFeGlzdHM6ICdVc3XDoXJpbyBqw6EgYWRpY2lvbmFkbyEnLFxuICAgICAgcHJvZmlsZToge1xuICAgICAgICB1cGRhdGVFcnJvcjogJ07Do28gZm9pIHBvc3PDrXZlbCBhdHVhbGl6YXIgc2V1IHByb2ZpbGUnXG4gICAgICB9XG4gICAgfSxcbiAgICBxdWVyeURpbmFtaWM6IHtcbiAgICAgIG5vRmlsdGVyOiAnTmVuaHVtIGZpbHRybyBhZGljaW9uYWRvJ1xuICAgIH1cbiAgfSk7XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4vKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCwgbm8tdW5kZWY6IDAqL1xuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25zdGFudCgncHQtQlIuaTE4bi5tb2RlbHMnLCB7XG4gICAgdXNlcjogJ1VzdcOhcmlvJyxcbiAgICB0YXNrOiAnVGFyZWZhJyxcbiAgICBwcm9qZWN0OiAnUHJvamV0bydcbiAgfSk7XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4vKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCwgbm8tdW5kZWY6IDAqL1xuKGZ1bmN0aW9uICgpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb25zdGFudCgncHQtQlIuaTE4bi52aWV3cycsIHtcbiAgICBicmVhZGNydW1iczoge1xuICAgICAgdXNlcjogJ0FkbWluaXN0cmHDp8OjbyAtIFVzdcOhcmlvJyxcbiAgICAgICd1c2VyLXByb2ZpbGUnOiAnUGVyZmlsJyxcbiAgICAgIGRhc2hib2FyZDogJ0Rhc2hib2FyZCcsXG4gICAgICBhdWRpdDogJ0FkbWluaXN0cmHDp8OjbyAtIEF1ZGl0b3JpYScsXG4gICAgICBtYWlsOiAnQWRtaW5pc3RyYcOnw6NvIC0gRW52aW8gZGUgZS1tYWlsJyxcbiAgICAgIHByb2plY3RzOiAnUHJvamV0b3MnLFxuICAgICAgJ2RpbmFtaWMtcXVlcnknOiAnQWRtaW5pc3RyYcOnw6NvIC0gQ29uc3VsdGFzIERpbsOibWljYXMnLFxuICAgICAgJ25vdC1hdXRob3JpemVkJzogJ0FjZXNzbyBOZWdhZG8nLFxuICAgICAgdGFza3M6ICdUYXJlZmFzJyxcbiAgICAgIG1pbGVzdG9uZXM6ICdTcHJpbnRzJyxcbiAgICAgIGthbmJhbjogJ0thbmJhbiBCb2FyZCcsXG4gICAgICB2Y3M6ICdDb250cm9sZSBkZSBWZXJzw6NvJyxcbiAgICAgIHJlbGVhc2VzOiAnUmVsZWFzZXMnXG4gICAgfSxcbiAgICB0aXRsZXM6IHtcbiAgICAgIGRhc2hib2FyZDogJ0Rhc2hib2FyZCcsXG4gICAgICBtYWlsU2VuZDogJ0VudmlhciBlLW1haWwnLFxuICAgICAgdGFza0xpc3Q6ICdMaXN0YSBkZSBUYXJlZmFzJyxcbiAgICAgIHVzZXJMaXN0OiAnTGlzdGEgZGUgVXN1w6FyaW9zJyxcbiAgICAgIGF1ZGl0TGlzdDogJ0xpc3RhIGRlIExvZ3MnLFxuICAgICAgcmVnaXN0ZXI6ICdGb3JtdWzDoXJpbyBkZSBDYWRhc3RybycsXG4gICAgICByZXNldFBhc3N3b3JkOiAnUmVkZWZpbmlyIFNlbmhhJyxcbiAgICAgIHVwZGF0ZTogJ0Zvcm11bMOhcmlvIGRlIEF0dWFsaXphw6fDo28nLFxuICAgICAgdGFza3M6ICdUYXJlZmFzJyxcbiAgICAgIG1pbGVzdG9uZXM6ICdTcHJpbnRzJyxcbiAgICAgIGthbmJhbjogJ0thbmJhbiBCb2FyZCcsXG4gICAgICB2Y3M6ICdDb250cm9sZSBkZSBWZXJzw6NvJyxcbiAgICAgIHJlbGVhc2VzOiAnUmVsZWFzZXMnXG4gICAgfSxcbiAgICBhY3Rpb25zOiB7XG4gICAgICBzZW5kOiAnRW52aWFyJyxcbiAgICAgIHNhdmU6ICdTYWx2YXInLFxuICAgICAgY2xlYXI6ICdMaW1wYXInLFxuICAgICAgY2xlYXJBbGw6ICdMaW1wYXIgVHVkbycsXG4gICAgICByZXN0YXJ0OiAnUmVpbmljaWFyJyxcbiAgICAgIGZpbHRlcjogJ0ZpbHRyYXInLFxuICAgICAgc2VhcmNoOiAnUGVzcXVpc2FyJyxcbiAgICAgIGxpc3Q6ICdMaXN0YXInLFxuICAgICAgZWRpdDogJ0VkaXRhcicsXG4gICAgICBjYW5jZWw6ICdDYW5jZWxhcicsXG4gICAgICB1cGRhdGU6ICdBdHVhbGl6YXInLFxuICAgICAgcmVtb3ZlOiAnUmVtb3ZlcicsXG4gICAgICBnZXRPdXQ6ICdTYWlyJyxcbiAgICAgIGFkZDogJ0FkaWNpb25hcicsXG4gICAgICBpbjogJ0VudHJhcicsXG4gICAgICBsb2FkSW1hZ2U6ICdDYXJyZWdhciBJbWFnZW0nLFxuICAgICAgc2lnbnVwOiAnQ2FkYXN0cmFyJyxcbiAgICAgIGNyaWFyUHJvamV0bzogJ0NyaWFyIFByb2pldG8nLFxuICAgICAgcHJvamVjdExpc3Q6ICdMaXN0YSBkZSBQcm9qZXRvcycsXG4gICAgICB0YXNrc0xpc3Q6ICdMaXN0YSBkZSBUYXJlZmFzJyxcbiAgICAgIG1pbGVzdG9uZXNMaXN0OiAnTGlzdGEgZGUgU3ByaW50cycsXG4gICAgICBmaW5hbGl6ZTogJ0ZpbmFsaXphcicsXG4gICAgICByZXBseTogJ1Jlc3BvbmRlcidcbiAgICB9LFxuICAgIGZpZWxkczoge1xuICAgICAgZGF0ZTogJ0RhdGEnLFxuICAgICAgYWN0aW9uOiAnQcOnw6NvJyxcbiAgICAgIGFjdGlvbnM6ICdBw6fDtWVzJyxcbiAgICAgIGF1ZGl0OiB7XG4gICAgICAgIGRhdGVTdGFydDogJ0RhdGEgSW5pY2lhbCcsXG4gICAgICAgIGRhdGVFbmQ6ICdEYXRhIEZpbmFsJyxcbiAgICAgICAgcmVzb3VyY2U6ICdSZWN1cnNvJyxcbiAgICAgICAgYWxsUmVzb3VyY2VzOiAnVG9kb3MgUmVjdXJzb3MnLFxuICAgICAgICB0eXBlOiB7XG4gICAgICAgICAgY3JlYXRlZDogJ0NhZGFzdHJhZG8nLFxuICAgICAgICAgIHVwZGF0ZWQ6ICdBdHVhbGl6YWRvJyxcbiAgICAgICAgICBkZWxldGVkOiAnUmVtb3ZpZG8nXG4gICAgICAgIH1cbiAgICAgIH0sXG4gICAgICBsb2dpbjoge1xuICAgICAgICByZXNldFBhc3N3b3JkOiAnRXNxdWVjaSBtaW5oYSBzZW5oYScsXG4gICAgICAgIGNvbmZpcm1QYXNzd29yZDogJ0NvbmZpcm1hciBzZW5oYSdcbiAgICAgIH0sXG4gICAgICBtYWlsOiB7XG4gICAgICAgIHRvOiAnUGFyYScsXG4gICAgICAgIHN1YmplY3Q6ICdBc3N1bnRvJyxcbiAgICAgICAgbWVzc2FnZTogJ01lbnNhZ2VtJ1xuICAgICAgfSxcbiAgICAgIHF1ZXJ5RGluYW1pYzoge1xuICAgICAgICBmaWx0ZXJzOiAnRmlsdHJvcycsXG4gICAgICAgIHJlc3VsdHM6ICdSZXN1bHRhZG9zJyxcbiAgICAgICAgbW9kZWw6ICdNb2RlbCcsXG4gICAgICAgIGF0dHJpYnV0ZTogJ0F0cmlidXRvJyxcbiAgICAgICAgb3BlcmF0b3I6ICdPcGVyYWRvcicsXG4gICAgICAgIHJlc291cmNlOiAnUmVjdXJzbycsXG4gICAgICAgIHZhbHVlOiAnVmFsb3InLFxuICAgICAgICBvcGVyYXRvcnM6IHtcbiAgICAgICAgICBlcXVhbHM6ICdJZ3VhbCcsXG4gICAgICAgICAgZGlmZXJlbnQ6ICdEaWZlcmVudGUnLFxuICAgICAgICAgIGNvbnRlaW5zOiAnQ29udMOpbScsXG4gICAgICAgICAgc3RhcnRXaXRoOiAnSW5pY2lhIGNvbScsXG4gICAgICAgICAgZmluaXNoV2l0aDogJ0ZpbmFsaXphIGNvbScsXG4gICAgICAgICAgYmlnZ2VyVGhhbjogJ01haW9yJyxcbiAgICAgICAgICBlcXVhbHNPckJpZ2dlclRoYW46ICdNYWlvciBvdSBJZ3VhbCcsXG4gICAgICAgICAgbGVzc1RoYW46ICdNZW5vcicsXG4gICAgICAgICAgZXF1YWxzT3JMZXNzVGhhbjogJ01lbm9yIG91IElndWFsJ1xuICAgICAgICB9XG4gICAgICB9LFxuICAgICAgcHJvamVjdDoge1xuICAgICAgICBuYW1lOiAnTm9tZScsXG4gICAgICAgIHRvdGFsVGFzazogJ1RvdGFsIGRlIFRhcmVmYXMnXG4gICAgICB9LFxuICAgICAgdGFzazoge1xuICAgICAgICBkb25lOiAnTsOjbyBGZWl0byAvIEZlaXRvJ1xuICAgICAgfSxcbiAgICAgIHVzZXI6IHtcbiAgICAgICAgcGVyZmlsczogJ1BlcmZpcycsXG4gICAgICAgIG5hbWVPckVtYWlsOiAnTm9tZSBvdSBFbWFpbCdcbiAgICAgIH1cbiAgICB9LFxuICAgIGxheW91dDoge1xuICAgICAgbWVudToge1xuICAgICAgICBwcm9qZWN0czogJ1Byb2pldG9zJyxcbiAgICAgICAgZGFzaGJvYXJkOiAnRGFzaGJvYXJkJyxcbiAgICAgICAgbWlsZXN0b25lczogJ1NwcmludHMnLFxuICAgICAgICB0YXNrczogJ1RhcmVmYXMnLFxuICAgICAgICBrYW5iYW46ICdLYW5iYW4nLFxuICAgICAgICB2Y3M6ICdDb250cm9sZSBkZSBWZXJzw6NvJyxcbiAgICAgICAgcmVsZWFzZXM6ICdSZWxlYXNlcydcbiAgICAgIH1cbiAgICB9LFxuICAgIHRvb2x0aXBzOiB7XG4gICAgICBhdWRpdDoge1xuICAgICAgICB2aWV3RGV0YWlsOiAnVmlzdWFsaXphciBEZXRhbGhhbWVudG8nXG4gICAgICB9LFxuICAgICAgdXNlcjoge1xuICAgICAgICBwZXJmaWw6ICdQZXJmaWwnLFxuICAgICAgICB0cmFuc2ZlcjogJ1RyYW5zZmVyaXInXG4gICAgICB9LFxuICAgICAgdGFzazoge1xuICAgICAgICBsaXN0VGFzazogJ0xpc3RhciBUYXJlZmFzJ1xuICAgICAgfVxuICAgIH1cbiAgfSk7XG59KSgpO1xuJ3VzZSBzdHJpY3QnO1xuXG4oZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyLm1vZHVsZSgnYXBwJykuY29udHJvbGxlcignVGFza0luZm9Db250cm9sbGVyJywgVGFza0luZm9Db250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIFRhc2tJbmZvQ29udHJvbGxlcigkY29udHJvbGxlciwgVGFza3NTZXJ2aWNlLCBsb2NhbHMpIHtcbiAgICAvL0F0dHJpYnV0ZXMgQmxvY2tcbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0uY2xvc2VEaWFsb2cgPSBjbG9zZURpYWxvZztcblxuICAgIHZtLm9uQWN0aXZhdGUgPSBmdW5jdGlvbiAoKSB7XG4gICAgICB2bS50YXNrID0gbG9jYWxzLnRhc2s7XG4gICAgICB2bS50YXNrLmVzdGltYXRlZF90aW1lID0gdm0udGFzay5lc3RpbWF0ZWRfdGltZS50b1N0cmluZygpICsgJyBob3Jhcyc7XG4gICAgfTtcblxuICAgIGZ1bmN0aW9uIGNsb3NlRGlhbG9nKCkge1xuICAgICAgdm0uY2xvc2UoKTtcbiAgICAgIGNvbnNvbGUubG9nKFwiZmVjaGFyXCIpO1xuICAgIH1cblxuICAgIC8vIGluc3RhbnRpYXRlIGJhc2UgY29udHJvbGxlclxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHsgdm06IHZtLCBtb2RlbFNlcnZpY2U6IFRhc2tzU2VydmljZSwgb3B0aW9uczoge30gfSk7XG4gIH1cbn0pKCk7XG4ndXNlIHN0cmljdCc7XG5cbihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnKS5jb250cm9sbGVyKCdVc2Vyc0RpYWxvZ0NvbnRyb2xsZXInLCBVc2Vyc0RpYWxvZ0NvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gVXNlcnNEaWFsb2dDb250cm9sbGVyKCRjb250cm9sbGVyLCBVc2Vyc1NlcnZpY2UsIFByRGlhbG9nLCAvLyBOT1NPTkFSXG4gIHVzZXJEaWFsb2dJbnB1dCwgb25Jbml0KSB7XG5cbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0ub25BY3RpdmF0ZSA9IG9uQWN0aXZhdGU7XG4gICAgdm0uYXBwbHlGaWx0ZXJzID0gYXBwbHlGaWx0ZXJzO1xuICAgIHZtLmNsb3NlID0gY2xvc2U7XG5cbiAgICBpZiAoYW5ndWxhci5pc0RlZmluZWQodXNlckRpYWxvZ0lucHV0KSkge1xuICAgICAgdm0udHJhbnNmZXJVc2VyID0gdXNlckRpYWxvZ0lucHV0LnRyYW5zZmVyVXNlckZuO1xuICAgIH1cblxuICAgIC8vIGluc3RhbnRpYXRlIGJhc2UgY29udHJvbGxlclxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHtcbiAgICAgIHZtOiB2bSxcbiAgICAgIG1vZGVsU2VydmljZTogVXNlcnNTZXJ2aWNlLFxuICAgICAgc2VhcmNoT25Jbml0OiBvbkluaXQsXG4gICAgICBvcHRpb25zOiB7XG4gICAgICAgIHBlclBhZ2U6IDVcbiAgICAgIH1cbiAgICB9KTtcblxuICAgIGZ1bmN0aW9uIG9uQWN0aXZhdGUoKSB7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMgPSB7fTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBhcHBseUZpbHRlcnMoKSB7XG4gICAgICByZXR1cm4gYW5ndWxhci5leHRlbmQodm0uZGVmYXVsdFF1ZXJ5RmlsdGVycywgdm0ucXVlcnlGaWx0ZXJzKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBjbG9zZSgpIHtcbiAgICAgIFByRGlhbG9nLmNsb3NlKCk7XG4gICAgfVxuICB9XG59KSgpOyIsIi8qZXNsaW50IGFuZ3VsYXIvZmlsZS1uYW1lOiAwKi9cbihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXIubW9kdWxlKCdhcHAnLCBbXG4gICAgJ25nQW5pbWF0ZScsXG4gICAgJ25nQXJpYScsXG4gICAgJ3VpLnJvdXRlcicsXG4gICAgJ25nUHJvZGViJyxcbiAgICAndWkudXRpbHMubWFza3MnLFxuICAgICd0ZXh0LW1hc2snLFxuICAgICduZ01hdGVyaWFsJyxcbiAgICAnbW9kZWxGYWN0b3J5JyxcbiAgICAnbWQuZGF0YS50YWJsZScsXG4gICAgJ25nTWF0ZXJpYWxEYXRlUGlja2VyJyxcbiAgICAncGFzY2FscHJlY2h0LnRyYW5zbGF0ZScsXG4gICAgJ2FuZ3VsYXJGaWxlVXBsb2FkJyxcbiAgICAnbmdNZXNzYWdlcycsXG4gICAgJ2pxd2lkZ2V0cycsXG4gICAgJ3VpLm1hc2snLFxuICAgICduZ1JvdXRlJ10pO1xufSkoKTtcbiIsIihmdW5jdGlvbiAoKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uZmlnKGNvbmZpZyk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBjb25maWcoR2xvYmFsLCAkbWRUaGVtaW5nUHJvdmlkZXIsICRtb2RlbEZhY3RvcnlQcm92aWRlciwgIC8vIE5PU09OQVJcbiAgICAkdHJhbnNsYXRlUHJvdmlkZXIsIG1vbWVudCwgJG1kQXJpYVByb3ZpZGVyLCAkbWREYXRlTG9jYWxlUHJvdmlkZXIpIHtcblxuICAgICR0cmFuc2xhdGVQcm92aWRlclxuICAgICAgLnVzZUxvYWRlcignbGFuZ3VhZ2VMb2FkZXInKVxuICAgICAgLnVzZVNhbml0aXplVmFsdWVTdHJhdGVneSgnZXNjYXBlJyk7XG5cbiAgICAkdHJhbnNsYXRlUHJvdmlkZXIudXNlUG9zdENvbXBpbGluZyh0cnVlKTtcblxuICAgIG1vbWVudC5sb2NhbGUoJ3B0LUJSJyk7XG5cbiAgICAvL29zIHNlcnZpw6dvcyByZWZlcmVudGUgYW9zIG1vZGVscyB2YWkgdXRpbGl6YXIgY29tbyBiYXNlIG5hcyB1cmxzXG4gICAgJG1vZGVsRmFjdG9yeVByb3ZpZGVyLmRlZmF1bHRPcHRpb25zLnByZWZpeCA9IEdsb2JhbC5hcGlQYXRoO1xuXG4gICAgLy8gQ29uZmlndXJhdGlvbiB0aGVtZVxuICAgICRtZFRoZW1pbmdQcm92aWRlci50aGVtZSgnZGVmYXVsdCcpXG4gICAgICAucHJpbWFyeVBhbGV0dGUoJ2dyZXknLCB7XG4gICAgICAgIGRlZmF1bHQ6ICc4MDAnXG4gICAgICB9KVxuICAgICAgLmFjY2VudFBhbGV0dGUoJ2FtYmVyJylcbiAgICAgIC53YXJuUGFsZXR0ZSgnZGVlcC1vcmFuZ2UnKTtcblxuICAgIC8vIEVuYWJsZSBicm93c2VyIGNvbG9yXG4gICAgJG1kVGhlbWluZ1Byb3ZpZGVyLmVuYWJsZUJyb3dzZXJDb2xvcigpO1xuXG4gICAgJG1kQXJpYVByb3ZpZGVyLmRpc2FibGVXYXJuaW5ncygpO1xuXG4gICAgJG1kRGF0ZUxvY2FsZVByb3ZpZGVyLmZvcm1hdERhdGUgPSBmdW5jdGlvbihkYXRlKSB7XG4gICAgICByZXR1cm4gZGF0ZSA/IG1vbWVudChkYXRlKS5mb3JtYXQoJ0REL01NL1lZWVknKSA6ICcnO1xuICAgIH07XG4gIH1cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb250cm9sbGVyKCdBcHBDb250cm9sbGVyJywgQXBwQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvKipcbiAgICogQ29udHJvbGFkb3IgcmVzcG9uc8OhdmVsIHBvciBmdW5jaW9uYWxpZGFkZXMgcXVlIHPDo28gYWNpb25hZGFzIGVtIHF1YWxxdWVyIHRlbGEgZG8gc2lzdGVtYVxuICAgKlxuICAgKi9cbiAgZnVuY3Rpb24gQXBwQ29udHJvbGxlcigkc3RhdGUsIEF1dGgsIEdsb2JhbCkge1xuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICAvL2FubyBhdHVhbCBwYXJhIHNlciBleGliaWRvIG5vIHJvZGFww6kgZG8gc2lzdGVtYVxuICAgIHZtLmFub0F0dWFsID0gbnVsbDtcbiAgICB2bS5hY3RpdmVQcm9qZWN0ID0gbnVsbDtcblxuICAgIHZtLmxvZ291dCAgICAgPSBsb2dvdXQ7XG4gICAgdm0uZ2V0SW1hZ2VQZXJmaWwgPSBnZXRJbWFnZVBlcmZpbDtcbiAgICB2bS5nZXRMb2dvTWVudSA9IGdldExvZ29NZW51O1xuICAgIHZtLnNldEFjdGl2ZVByb2plY3QgPSBzZXRBY3RpdmVQcm9qZWN0O1xuICAgIHZtLmdldEFjdGl2ZVByb2plY3QgPSBnZXRBY3RpdmVQcm9qZWN0O1xuICAgIHZtLnJlbW92ZUFjdGl2ZVByb2plY3QgPSByZW1vdmVBY3RpdmVQcm9qZWN0O1xuXG4gICAgYWN0aXZhdGUoKTtcblxuICAgIGZ1bmN0aW9uIGFjdGl2YXRlKCkge1xuICAgICAgdmFyIGRhdGUgPSBuZXcgRGF0ZSgpO1xuXG4gICAgICB2bS5hbm9BdHVhbCA9IGRhdGUuZ2V0RnVsbFllYXIoKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBsb2dvdXQoKSB7XG4gICAgICBBdXRoLmxvZ291dCgpLnRoZW4oZnVuY3Rpb24oKSB7XG4gICAgICAgICRzdGF0ZS5nbyhHbG9iYWwubG9naW5TdGF0ZSk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBnZXRJbWFnZVBlcmZpbCgpIHtcbiAgICAgIHJldHVybiAoQXV0aC5jdXJyZW50VXNlciAmJiBBdXRoLmN1cnJlbnRVc2VyLmltYWdlKVxuICAgICAgICA/IEF1dGguY3VycmVudFVzZXIuaW1hZ2VcbiAgICAgICAgOiBHbG9iYWwuaW1hZ2VQYXRoICsgJy9ub19hdmF0YXIuZ2lmJztcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBnZXRMb2dvTWVudSgpIHtcbiAgICAgIHJldHVybiBHbG9iYWwuaW1hZ2VQYXRoICsgJy9sb2dvLXZlcnRpY2FsLnBuZyc7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gc2V0QWN0aXZlUHJvamVjdChwcm9qZWN0KSB7XG4gICAgICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbSgncHJvamVjdCcsIHByb2plY3QpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGdldEFjdGl2ZVByb2plY3QoKSB7XG4gICAgICByZXR1cm4gbG9jYWxTdG9yYWdlLmdldEl0ZW0oJ3Byb2plY3QnKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiByZW1vdmVBY3RpdmVQcm9qZWN0KCkge1xuICAgICAgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oJ3Byb2plY3QnKTtcbiAgICB9XG5cbiAgfVxuXG59KSgpO1xuIiwiLyplc2xpbnQgYW5ndWxhci9maWxlLW5hbWU6IDAsIG5vLXVuZGVmOiAwKi9cbihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIC8qKlxuICAgKiBUcmFuc2Zvcm1hIGJpYmxpb3RlY2FzIGV4dGVybmFzIGVtIHNlcnZpw6dvcyBkbyBhbmd1bGFyIHBhcmEgc2VyIHBvc3PDrXZlbCB1dGlsaXphclxuICAgKiBhdHJhdsOpcyBkYSBpbmplw6fDo28gZGUgZGVwZW5kw6puY2lhXG4gICAqL1xuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uc3RhbnQoJ2xvZGFzaCcsIF8pXG4gICAgLmNvbnN0YW50KCdtb21lbnQnLCBtb21lbnQpO1xuXG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnN0YW50KCdHbG9iYWwnLCB7XG4gICAgICBhcHBOYW1lOiAnRnJlZWxhZ2lsZScsXG4gICAgICBob21lU3RhdGU6ICdhcHAucHJvamVjdHMnLFxuICAgICAgbG9naW5Vcmw6ICdhcHAvbG9naW4nLFxuICAgICAgbG9naW5TdGF0ZTogJ2FwcC5sb2dpbicsXG4gICAgICByZXNldFBhc3N3b3JkU3RhdGU6ICdhcHAucGFzc3dvcmQtcmVzZXQnLFxuICAgICAgbm90QXV0aG9yaXplZFN0YXRlOiAnYXBwLm5vdC1hdXRob3JpemVkJyxcbiAgICAgIHRva2VuS2V5OiAnc2VydmVyX3Rva2VuJyxcbiAgICAgIGNsaWVudFBhdGg6ICdjbGllbnQvYXBwJyxcbiAgICAgIGFwaVBhdGg6ICdhcGkvdjEnLFxuICAgICAgaW1hZ2VQYXRoOiAnY2xpZW50L2ltYWdlcydcbiAgICB9KTtcbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsICR1cmxSb3V0ZXJQcm92aWRlciwgR2xvYmFsKSB7XG4gICAgJHN0YXRlUHJvdmlkZXJcbiAgICAgIC5zdGF0ZSgnYXBwJywge1xuICAgICAgICB1cmw6ICcvYXBwJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9sYXlvdXQvYXBwLmh0bWwnLFxuICAgICAgICBhYnN0cmFjdDogdHJ1ZSxcbiAgICAgICAgcmVzb2x2ZTogeyAvL2Vuc3VyZSBsYW5ncyBpcyByZWFkeSBiZWZvcmUgcmVuZGVyIHZpZXdcbiAgICAgICAgICB0cmFuc2xhdGVSZWFkeTogWyckdHJhbnNsYXRlJywgJyRxJywgZnVuY3Rpb24oJHRyYW5zbGF0ZSwgJHEpIHtcbiAgICAgICAgICAgIHZhciBkZWZlcnJlZCA9ICRxLmRlZmVyKCk7XG5cbiAgICAgICAgICAgICR0cmFuc2xhdGUudXNlKCdwdC1CUicpLnRoZW4oZnVuY3Rpb24oKSB7XG4gICAgICAgICAgICAgIGRlZmVycmVkLnJlc29sdmUoKTtcbiAgICAgICAgICAgIH0pO1xuXG4gICAgICAgICAgICByZXR1cm4gZGVmZXJyZWQucHJvbWlzZTtcbiAgICAgICAgICB9XVxuICAgICAgICB9XG4gICAgICB9KVxuICAgICAgLnN0YXRlKEdsb2JhbC5ub3RBdXRob3JpemVkU3RhdGUsIHtcbiAgICAgICAgdXJsOiAnL2FjZXNzby1uZWdhZG8nLFxuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL2xheW91dC9ub3QtYXV0aG9yaXplZC5odG1sJyxcbiAgICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IGZhbHNlIH1cbiAgICAgIH0pO1xuXG4gICAgJHVybFJvdXRlclByb3ZpZGVyLndoZW4oJy9hcHAnLCBHbG9iYWwubG9naW5VcmwpO1xuICAgICR1cmxSb3V0ZXJQcm92aWRlci5vdGhlcndpc2UoR2xvYmFsLmxvZ2luVXJsKTtcbiAgfVxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5ydW4ocnVuKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIHJ1bigkcm9vdFNjb3BlLCAkc3RhdGUsICRzdGF0ZVBhcmFtcywgQXV0aCwgR2xvYmFsKSB7IC8vIE5PU09OQVJcbiAgICAvL3NldGFkbyBubyByb290U2NvcGUgcGFyYSBwb2RlciBzZXIgYWNlc3NhZG8gbmFzIHZpZXdzIHNlbSBwcmVmaXhvIGRlIGNvbnRyb2xsZXJcbiAgICAkcm9vdFNjb3BlLiRzdGF0ZSA9ICRzdGF0ZTtcbiAgICAkcm9vdFNjb3BlLiRzdGF0ZVBhcmFtcyA9ICRzdGF0ZVBhcmFtcztcbiAgICAkcm9vdFNjb3BlLmF1dGggPSBBdXRoO1xuICAgICRyb290U2NvcGUuZ2xvYmFsID0gR2xvYmFsO1xuXG4gICAgLy9ubyBpbmljaW8gY2FycmVnYSBvIHVzdcOhcmlvIGRvIGxvY2Fsc3RvcmFnZSBjYXNvIG8gdXN1w6FyaW8gZXN0YWphIGFicmluZG8gbyBuYXZlZ2Fkb3JcbiAgICAvL3BhcmEgdm9sdGFyIGF1dGVudGljYWRvXG4gICAgQXV0aC5yZXRyaWV2ZVVzZXJGcm9tTG9jYWxTdG9yYWdlKCk7XG4gIH1cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb250cm9sbGVyKCdBdWRpdENvbnRyb2xsZXInLCBBdWRpdENvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gQXVkaXRDb250cm9sbGVyKCRjb250cm9sbGVyLCBBdWRpdFNlcnZpY2UsIFByRGlhbG9nLCBHbG9iYWwsICR0cmFuc2xhdGUpIHsgLy8gTk9TT05BUlxuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICB2bS5vbkFjdGl2YXRlID0gb25BY3RpdmF0ZTtcbiAgICB2bS5hcHBseUZpbHRlcnMgPSBhcHBseUZpbHRlcnM7XG4gICAgdm0udmlld0RldGFpbCA9IHZpZXdEZXRhaWw7XG5cbiAgICAkY29udHJvbGxlcignQ1JVRENvbnRyb2xsZXInLCB7IHZtOiB2bSwgbW9kZWxTZXJ2aWNlOiBBdWRpdFNlcnZpY2UsIG9wdGlvbnM6IHt9IH0pO1xuXG4gICAgZnVuY3Rpb24gb25BY3RpdmF0ZSgpIHtcbiAgICAgIHZtLm1vZGVscyA9IFtdO1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0ge307XG5cbiAgICAgIC8vUGVnYSB0b2RvcyBvcyBtb2RlbHMgZG8gc2VydmVyIGUgbW9udGEgdW1hIGxpc3RhIHBybyBDb21ib0JveFxuICAgICAgQXVkaXRTZXJ2aWNlLmdldEF1ZGl0ZWRNb2RlbHMoKS50aGVuKGZ1bmN0aW9uKGRhdGEpIHtcbiAgICAgICAgdmFyIG1vZGVscyA9IFt7IGlkOiAnJywgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudCgnZ2xvYmFsLmFsbCcpIH1dO1xuXG4gICAgICAgIGRhdGEubW9kZWxzLnNvcnQoKTtcblxuICAgICAgICBmb3IgKHZhciBpbmRleCA9IDA7IGluZGV4IDwgZGF0YS5tb2RlbHMubGVuZ3RoOyBpbmRleCsrKSB7XG4gICAgICAgICAgdmFyIG1vZGVsID0gZGF0YS5tb2RlbHNbaW5kZXhdO1xuXG4gICAgICAgICAgbW9kZWxzLnB1c2goe1xuICAgICAgICAgICAgaWQ6IG1vZGVsLFxuICAgICAgICAgICAgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudCgnbW9kZWxzLicgKyBtb2RlbC50b0xvd2VyQ2FzZSgpKVxuICAgICAgICAgIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgdm0ubW9kZWxzID0gbW9kZWxzO1xuICAgICAgICB2bS5xdWVyeUZpbHRlcnMubW9kZWwgPSB2bS5tb2RlbHNbMF0uaWQ7XG4gICAgICB9KTtcblxuICAgICAgdm0udHlwZXMgPSBBdWRpdFNlcnZpY2UubGlzdFR5cGVzKCk7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMudHlwZSA9IHZtLnR5cGVzWzBdLmlkO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGFwcGx5RmlsdGVycyhkZWZhdWx0UXVlcnlGaWx0ZXJzKSB7XG4gICAgICByZXR1cm4gYW5ndWxhci5leHRlbmQoZGVmYXVsdFF1ZXJ5RmlsdGVycywgdm0ucXVlcnlGaWx0ZXJzKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiB2aWV3RGV0YWlsKGF1ZGl0RGV0YWlsKSB7XG4gICAgICB2YXIgY29uZmlnID0ge1xuICAgICAgICBsb2NhbHM6IHsgYXVkaXREZXRhaWw6IGF1ZGl0RGV0YWlsIH0sXG4gICAgICAgIC8qKiBAbmdJbmplY3QgKi9cbiAgICAgICAgY29udHJvbGxlcjogZnVuY3Rpb24oYXVkaXREZXRhaWwsIFByRGlhbG9nKSB7XG4gICAgICAgICAgdmFyIHZtID0gdGhpcztcblxuICAgICAgICAgIHZtLmNsb3NlID0gY2xvc2U7XG5cbiAgICAgICAgICBhY3RpdmF0ZSgpO1xuXG4gICAgICAgICAgZnVuY3Rpb24gYWN0aXZhdGUoKSB7XG4gICAgICAgICAgICBpZiAoYW5ndWxhci5pc0FycmF5KGF1ZGl0RGV0YWlsLm9sZCkgJiYgYXVkaXREZXRhaWwub2xkLmxlbmd0aCA9PT0gMCkgYXVkaXREZXRhaWwub2xkID0gbnVsbDtcbiAgICAgICAgICAgIGlmIChhbmd1bGFyLmlzQXJyYXkoYXVkaXREZXRhaWwubmV3KSAmJiBhdWRpdERldGFpbC5uZXcubGVuZ3RoID09PSAwKSBhdWRpdERldGFpbC5uZXcgPSBudWxsO1xuXG4gICAgICAgICAgICB2bS5hdWRpdERldGFpbCA9IGF1ZGl0RGV0YWlsO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIGZ1bmN0aW9uIGNsb3NlKCkge1xuICAgICAgICAgICAgUHJEaWFsb2cuY2xvc2UoKTtcbiAgICAgICAgICB9XG5cbiAgICAgICAgfSxcbiAgICAgICAgY29udHJvbGxlckFzOiAnYXVkaXREZXRhaWxDdHJsJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9hdWRpdC9hdWRpdC1kZXRhaWwuaHRtbCcsXG4gICAgICAgIGhhc0JhY2tkcm9wOiB0cnVlXG4gICAgICB9O1xuXG4gICAgICBQckRpYWxvZy5jdXN0b20oY29uZmlnKTtcbiAgICB9XG5cbiAgfVxuXG59KSgpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKlxuICAgKiBBcnF1aXZvIGRlIGNvbmZpZ3VyYcOnw6NvIGNvbSBhcyByb3RhcyBlc3BlY8OtZmljYXMgZGUgYXVkaXRvcmlhXG4gICAqXG4gICAqIEBwYXJhbSB7YW55fSAkc3RhdGVQcm92aWRlclxuICAgKiBAcGFyYW0ge2FueX0gR2xvYmFsXG4gICAqL1xuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvdXRlcygkc3RhdGVQcm92aWRlciwgR2xvYmFsKSB7XG4gICAgJHN0YXRlUHJvdmlkZXJcbiAgICAgIC5zdGF0ZSgnYXBwLmF1ZGl0Jywge1xuICAgICAgICB1cmw6ICcvYXVkaXRvcmlhJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9hdWRpdC9hdWRpdC5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ0F1ZGl0Q29udHJvbGxlciBhcyBhdWRpdEN0cmwnLFxuICAgICAgICBkYXRhOiB7IG5lZWRBdXRoZW50aWNhdGlvbjogdHJ1ZSwgbmVlZFByb2ZpbGU6IFsnYWRtaW4nXSB9XG4gICAgICB9KTtcblxuICB9XG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZhY3RvcnkoJ0F1ZGl0U2VydmljZScsIEF1ZGl0U2VydmljZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBBdWRpdFNlcnZpY2Uoc2VydmljZUZhY3RvcnksICR0cmFuc2xhdGUpIHtcbiAgICByZXR1cm4gc2VydmljZUZhY3RvcnkoJ2F1ZGl0Jywge1xuICAgICAgYWN0aW9uczoge1xuICAgICAgICBnZXRBdWRpdGVkTW9kZWxzOiB7XG4gICAgICAgICAgbWV0aG9kOiAnR0VUJyxcbiAgICAgICAgICB1cmw6ICdtb2RlbHMnXG4gICAgICAgIH1cbiAgICAgIH0sXG4gICAgICBpbnN0YW5jZToge1xuICAgICAgfSxcbiAgICAgIGxpc3RUeXBlczogZnVuY3Rpb24oKSB7XG4gICAgICAgIHZhciBhdWRpdFBhdGggPSAndmlld3MuZmllbGRzLmF1ZGl0Lic7XG5cbiAgICAgICAgcmV0dXJuIFtcbiAgICAgICAgICB7IGlkOiAnJywgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudChhdWRpdFBhdGggKyAnYWxsUmVzb3VyY2VzJykgfSxcbiAgICAgICAgICB7IGlkOiAnY3JlYXRlZCcsIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoYXVkaXRQYXRoICsgJ3R5cGUuY3JlYXRlZCcpIH0sXG4gICAgICAgICAgeyBpZDogJ3VwZGF0ZWQnLCBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KGF1ZGl0UGF0aCArICd0eXBlLnVwZGF0ZWQnKSB9LFxuICAgICAgICAgIHsgaWQ6ICdkZWxldGVkJywgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudChhdWRpdFBhdGggKyAndHlwZS5kZWxldGVkJykgfVxuICAgICAgICBdO1xuICAgICAgfVxuICAgIH0pO1xuICB9XG5cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqXG4gICAqIEFycXVpdm8gZGUgY29uZmlndXJhw6fDo28gY29tIGFzIHJvdGFzIGVzcGVjw61maWNhcyBkbyByZWN1cnNvIHVzZXJcbiAgICpcbiAgICogQHBhcmFtIHthbnl9ICRzdGF0ZVByb3ZpZGVyXG4gICAqIEBwYXJhbSB7YW55fSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlclxuICAgICAgLnN0YXRlKEdsb2JhbC5yZXNldFBhc3N3b3JkU3RhdGUsIHtcbiAgICAgICAgdXJsOiAnL3Bhc3N3b3JkL3Jlc2V0Lzp0b2tlbicsXG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvYXV0aC9yZXNldC1wYXNzLWZvcm0uaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdQYXNzd29yZENvbnRyb2xsZXIgYXMgcGFzc0N0cmwnLFxuICAgICAgICBkYXRhOiB7IG5lZWRBdXRoZW50aWNhdGlvbjogZmFsc2UgfVxuICAgICAgfSlcbiAgICAgIC5zdGF0ZShHbG9iYWwubG9naW5TdGF0ZSwge1xuICAgICAgICB1cmw6ICcvbG9naW4nLFxuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL2F1dGgvbG9naW4uaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdMb2dpbkNvbnRyb2xsZXIgYXMgbG9naW5DdHJsJyxcbiAgICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IGZhbHNlIH1cbiAgICAgIH0pO1xuXG4gIH1cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmFjdG9yeSgnQXV0aCcsIEF1dGgpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gQXV0aCgkaHR0cCwgJHEsIEdsb2JhbCwgVXNlcnNTZXJ2aWNlKSB7IC8vIE5PU09OQVJcbiAgICB2YXIgYXV0aCA9IHtcbiAgICAgIGxvZ2luOiBsb2dpbixcbiAgICAgIGxvZ291dDogbG9nb3V0LFxuICAgICAgdXBkYXRlQ3VycmVudFVzZXI6IHVwZGF0ZUN1cnJlbnRVc2VyLFxuICAgICAgcmV0cmlldmVVc2VyRnJvbUxvY2FsU3RvcmFnZTogcmV0cmlldmVVc2VyRnJvbUxvY2FsU3RvcmFnZSxcbiAgICAgIGF1dGhlbnRpY2F0ZWQ6IGF1dGhlbnRpY2F0ZWQsXG4gICAgICBzZW5kRW1haWxSZXNldFBhc3N3b3JkOiBzZW5kRW1haWxSZXNldFBhc3N3b3JkLFxuICAgICAgcmVtb3RlVmFsaWRhdGVUb2tlbjogcmVtb3RlVmFsaWRhdGVUb2tlbixcbiAgICAgIGdldFRva2VuOiBnZXRUb2tlbixcbiAgICAgIHNldFRva2VuOiBzZXRUb2tlbixcbiAgICAgIGNsZWFyVG9rZW46IGNsZWFyVG9rZW4sXG4gICAgICBjdXJyZW50VXNlcjogbnVsbFxuICAgIH07XG5cbiAgICBmdW5jdGlvbiBjbGVhclRva2VuKCkge1xuICAgICAgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oR2xvYmFsLnRva2VuS2V5KTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBzZXRUb2tlbih0b2tlbikge1xuICAgICAgbG9jYWxTdG9yYWdlLnNldEl0ZW0oR2xvYmFsLnRva2VuS2V5LCB0b2tlbik7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gZ2V0VG9rZW4oKSB7XG4gICAgICByZXR1cm4gbG9jYWxTdG9yYWdlLmdldEl0ZW0oR2xvYmFsLnRva2VuS2V5KTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiByZW1vdGVWYWxpZGF0ZVRva2VuKCkge1xuICAgICAgdmFyIGRlZmVycmVkID0gJHEuZGVmZXIoKTtcblxuICAgICAgaWYgKGF1dGguYXV0aGVudGljYXRlZCgpKSB7XG4gICAgICAgICRodHRwLmdldChHbG9iYWwuYXBpUGF0aCArICcvYXV0aGVudGljYXRlL2NoZWNrJylcbiAgICAgICAgICAudGhlbihmdW5jdGlvbigpIHtcbiAgICAgICAgICAgIGRlZmVycmVkLnJlc29sdmUodHJ1ZSk7XG4gICAgICAgICAgfSwgZnVuY3Rpb24oKSB7XG4gICAgICAgICAgICBhdXRoLmxvZ291dCgpO1xuXG4gICAgICAgICAgICBkZWZlcnJlZC5yZWplY3QoZmFsc2UpO1xuICAgICAgICAgIH0pO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgYXV0aC5sb2dvdXQoKTtcblxuICAgICAgICBkZWZlcnJlZC5yZWplY3QoZmFsc2UpO1xuICAgICAgfVxuXG4gICAgICByZXR1cm4gZGVmZXJyZWQucHJvbWlzZTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBWZXJpZmljYSBzZSBvIHVzdcOhcmlvIGVzdMOhIGF1dGVudGljYWRvXG4gICAgICpcbiAgICAgKiBAcmV0dXJucyB7Ym9vbGVhbn1cbiAgICAgKi9cbiAgICBmdW5jdGlvbiBhdXRoZW50aWNhdGVkKCkge1xuICAgICAgcmV0dXJuIGF1dGguZ2V0VG9rZW4oKSAhPT0gbnVsbFxuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlY3VwZXJhIG8gdXN1w6FyaW8gZG8gbG9jYWxTdG9yYWdlXG4gICAgICovXG4gICAgZnVuY3Rpb24gcmV0cmlldmVVc2VyRnJvbUxvY2FsU3RvcmFnZSgpIHtcbiAgICAgIHZhciB1c2VyID0gbG9jYWxTdG9yYWdlLmdldEl0ZW0oJ3VzZXInKTtcblxuICAgICAgaWYgKHVzZXIpIHtcbiAgICAgICAgYXV0aC5jdXJyZW50VXNlciA9IGFuZ3VsYXIubWVyZ2UobmV3IFVzZXJzU2VydmljZSgpLCBhbmd1bGFyLmZyb21Kc29uKHVzZXIpKTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBHdWFyZGEgbyB1c3XDoXJpbyBubyBsb2NhbFN0b3JhZ2UgcGFyYSBjYXNvIG8gdXN1w6FyaW8gZmVjaGUgZSBhYnJhIG8gbmF2ZWdhZG9yXG4gICAgICogZGVudHJvIGRvIHRlbXBvIGRlIHNlc3PDo28gc2VqYSBwb3Nzw612ZWwgcmVjdXBlcmFyIG8gdG9rZW4gYXV0ZW50aWNhZG8uXG4gICAgICpcbiAgICAgKiBNYW50w6ltIGEgdmFyacOhdmVsIGF1dGguY3VycmVudFVzZXIgcGFyYSBmYWNpbGl0YXIgbyBhY2Vzc28gYW8gdXN1w6FyaW8gbG9nYWRvIGVtIHRvZGEgYSBhcGxpY2HDp8Ojb1xuICAgICAqXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gdXNlciBVc3XDoXJpbyBhIHNlciBhdHVhbGl6YWRvLiBDYXNvIHNlamEgcGFzc2FkbyBudWxsIGxpbXBhXG4gICAgICogdG9kYXMgYXMgaW5mb3JtYcOnw7VlcyBkbyB1c3XDoXJpbyBjb3JyZW50ZS5cbiAgICAgKi9cbiAgICBmdW5jdGlvbiB1cGRhdGVDdXJyZW50VXNlcih1c2VyKSB7XG4gICAgICB2YXIgZGVmZXJyZWQgPSAkcS5kZWZlcigpO1xuXG4gICAgICBpZiAodXNlcikge1xuICAgICAgICB1c2VyID0gYW5ndWxhci5tZXJnZShuZXcgVXNlcnNTZXJ2aWNlKCksIHVzZXIpO1xuXG4gICAgICAgIHZhciBqc29uVXNlciA9IGFuZ3VsYXIudG9Kc29uKHVzZXIpO1xuXG4gICAgICAgIGxvY2FsU3RvcmFnZS5zZXRJdGVtKCd1c2VyJywganNvblVzZXIpO1xuICAgICAgICBhdXRoLmN1cnJlbnRVc2VyID0gdXNlcjtcblxuICAgICAgICBkZWZlcnJlZC5yZXNvbHZlKHVzZXIpO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oJ3VzZXInKTtcbiAgICAgICAgYXV0aC5jdXJyZW50VXNlciA9IG51bGw7XG4gICAgICAgIGF1dGguY2xlYXJUb2tlbigpO1xuXG4gICAgICAgIGRlZmVycmVkLnJlamVjdCgpO1xuICAgICAgfVxuXG4gICAgICByZXR1cm4gZGVmZXJyZWQucHJvbWlzZTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFsaXphIG8gbG9naW4gZG8gdXN1w6FyaW9cbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSBjcmVkZW50aWFscyBFbWFpbCBlIFNlbmhhIGRvIHVzdcOhcmlvXG4gICAgICogQHJldHVybnMge3Byb21pc2V9IFVtYSBwcm9taXNlIGNvbSBvIHJlc3VsdGFkbyBkbyBjaGFtYWRhIG5vIGJhY2tlbmRcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBsb2dpbihjcmVkZW50aWFscykge1xuICAgICAgdmFyIGRlZmVycmVkID0gJHEuZGVmZXIoKTtcblxuICAgICAgJGh0dHAucG9zdChHbG9iYWwuYXBpUGF0aCArICcvYXV0aGVudGljYXRlJywgY3JlZGVudGlhbHMpXG4gICAgICAgIC50aGVuKGZ1bmN0aW9uKHJlc3BvbnNlKSB7XG4gICAgICAgICAgYXV0aC5zZXRUb2tlbihyZXNwb25zZS5kYXRhLnRva2VuKTtcblxuICAgICAgICAgIHJldHVybiAkaHR0cC5nZXQoR2xvYmFsLmFwaVBhdGggKyAnL2F1dGhlbnRpY2F0ZS91c2VyJyk7XG4gICAgICAgIH0pXG4gICAgICAgIC50aGVuKGZ1bmN0aW9uKHJlc3BvbnNlKSB7XG4gICAgICAgICAgYXV0aC51cGRhdGVDdXJyZW50VXNlcihyZXNwb25zZS5kYXRhLnVzZXIpO1xuXG4gICAgICAgICAgZGVmZXJyZWQucmVzb2x2ZSgpO1xuICAgICAgICB9LCBmdW5jdGlvbihlcnJvcikge1xuICAgICAgICAgIGF1dGgubG9nb3V0KCk7XG5cbiAgICAgICAgICBkZWZlcnJlZC5yZWplY3QoZXJyb3IpO1xuICAgICAgICB9KTtcblxuICAgICAgcmV0dXJuIGRlZmVycmVkLnByb21pc2U7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogRGVzbG9nYSBvcyB1c3XDoXJpb3MuIENvbW8gbsOjbyB0ZW4gbmVuaHVtYSBpbmZvcm1hw6fDo28gbmEgc2Vzc8OjbyBkbyBzZXJ2aWRvclxuICAgICAqIGUgdW0gdG9rZW4gdW1hIHZleiBnZXJhZG8gbsOjbyBwb2RlLCBwb3IgcGFkcsOjbywgc2VyIGludmFsaWRhZG8gYW50ZXMgZG8gc2V1IHRlbXBvIGRlIGV4cGlyYcOnw6NvLFxuICAgICAqIHNvbWVudGUgYXBhZ2Ftb3Mgb3MgZGFkb3MgZG8gdXN1w6FyaW8gZSBvIHRva2VuIGRvIG5hdmVnYWRvciBwYXJhIGVmZXRpdmFyIG8gbG9nb3V0LlxuICAgICAqXG4gICAgICogQHJldHVybnMge3Byb21pc2V9IFVtYSBwcm9taXNlIGNvbSBvIHJlc3VsdGFkbyBkYSBvcGVyYcOnw6NvXG4gICAgICovXG4gICAgZnVuY3Rpb24gbG9nb3V0KCkge1xuICAgICAgdmFyIGRlZmVycmVkID0gJHEuZGVmZXIoKTtcblxuICAgICAgYXV0aC51cGRhdGVDdXJyZW50VXNlcihudWxsKTtcbiAgICAgIGRlZmVycmVkLnJlc29sdmUoKTtcblxuICAgICAgcmV0dXJuIGRlZmVycmVkLnByb21pc2U7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogRW52aWEgdW0gZW1haWwgcGFyYSByZWN1cGVyYcOnw6NvIGRlIHNlbmhhXG4gICAgICogQHBhcmFtIHtPYmplY3R9IHJlc2V0RGF0YSAtIE9iamV0byBjb250ZW5kbyBvIGVtYWlsXG4gICAgICogQHJldHVybiB7UHJvbWlzZX0gLSBSZXRvcm5hIHVtYSBwcm9taXNlIHBhcmEgc2VyIHJlc29sdmlkYVxuICAgICAqL1xuICAgIGZ1bmN0aW9uIHNlbmRFbWFpbFJlc2V0UGFzc3dvcmQocmVzZXREYXRhKSB7XG4gICAgICB2YXIgZGVmZXJyZWQgPSAkcS5kZWZlcigpO1xuXG4gICAgICAkaHR0cC5wb3N0KEdsb2JhbC5hcGlQYXRoICsgJy9wYXNzd29yZC9lbWFpbCcsIHJlc2V0RGF0YSlcbiAgICAgICAgLnRoZW4oZnVuY3Rpb24ocmVzcG9uc2UpIHtcbiAgICAgICAgICBkZWZlcnJlZC5yZXNvbHZlKHJlc3BvbnNlLmRhdGEpO1xuICAgICAgICB9LCBmdW5jdGlvbihlcnJvcikge1xuICAgICAgICAgIGRlZmVycmVkLnJlamVjdChlcnJvcik7XG4gICAgICAgIH0pO1xuXG4gICAgICByZXR1cm4gZGVmZXJyZWQucHJvbWlzZTtcbiAgICB9XG5cbiAgICByZXR1cm4gYXV0aDtcbiAgfVxuXG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29udHJvbGxlcignTG9naW5Db250cm9sbGVyJywgTG9naW5Db250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIExvZ2luQ29udHJvbGxlcigkc3RhdGUsIEF1dGgsIEdsb2JhbCwgUHJEaWFsb2cpIHtcbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0ubG9naW4gPSBsb2dpbjtcbiAgICB2bS5vcGVuRGlhbG9nUmVzZXRQYXNzID0gb3BlbkRpYWxvZ1Jlc2V0UGFzcztcbiAgICB2bS5vcGVuRGlhbG9nU2lnblVwID0gb3BlbkRpYWxvZ1NpZ25VcDtcblxuICAgIGFjdGl2YXRlKCk7XG5cbiAgICBmdW5jdGlvbiBhY3RpdmF0ZSgpIHtcbiAgICAgIHZtLmNyZWRlbnRpYWxzID0ge307XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gbG9naW4oKSB7XG4gICAgICB2YXIgY3JlZGVudGlhbHMgPSB7XG4gICAgICAgIGVtYWlsOiB2bS5jcmVkZW50aWFscy5lbWFpbCxcbiAgICAgICAgcGFzc3dvcmQ6IHZtLmNyZWRlbnRpYWxzLnBhc3N3b3JkXG4gICAgICB9O1xuXG4gICAgICBBdXRoLmxvZ2luKGNyZWRlbnRpYWxzKS50aGVuKGZ1bmN0aW9uKCkge1xuICAgICAgICAkc3RhdGUuZ28oR2xvYmFsLmhvbWVTdGF0ZSk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBFeGliZSBvIGRpYWxvZyBwYXJhIHJlY3VwZXJhw6fDo28gZGUgc2VuaGFcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBvcGVuRGlhbG9nUmVzZXRQYXNzKCkge1xuICAgICAgdmFyIGNvbmZpZyA9IHtcbiAgICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9hdXRoL3NlbmQtcmVzZXQtZGlhbG9nLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnUGFzc3dvcmRDb250cm9sbGVyIGFzIHBhc3NDdHJsJyxcbiAgICAgICAgaGFzQmFja2Ryb3A6IHRydWVcbiAgICAgIH1cblxuICAgICAgUHJEaWFsb2cuY3VzdG9tKGNvbmZpZyk7XG4gICAgfVxuICAgIC8qKlxuICAgICAqIEV4aWJlIG8gZGlhbG9nIHBhcmEgcmVjdXBlcmHDp8OjbyBkZSBzZW5oYVxuICAgICAqL1xuICAgIGZ1bmN0aW9uIG9wZW5EaWFsb2dTaWduVXAoKSB7XG4gICAgICB2YXIgY29uZmlnID0ge1xuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL3VzZXJzL3VzZXItZm9ybS5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ1VzZXJzQ29udHJvbGxlciBhcyB1c2Vyc0N0cmwnLFxuICAgICAgICBoYXNCYWNrZHJvcDogdHJ1ZVxuICAgICAgfVxuXG4gICAgICBQckRpYWxvZy5jdXN0b20oY29uZmlnKTtcbiAgICB9XG5cbiAgfVxuXG59KSgpO1xuIiwiKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnRyb2xsZXIoJ1Bhc3N3b3JkQ29udHJvbGxlcicsIFBhc3N3b3JkQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBQYXNzd29yZENvbnRyb2xsZXIoR2xvYmFsLCAkc3RhdGVQYXJhbXMsICRodHRwLCAkdGltZW91dCwgJHN0YXRlLCAvLyBOT1NPTkFSXG4gICAgUHJUb2FzdCwgUHJEaWFsb2csIEF1dGgsICR0cmFuc2xhdGUpIHtcblxuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICB2bS5zZW5kUmVzZXQgPSBzZW5kUmVzZXQ7XG4gICAgdm0uY2xvc2VEaWFsb2cgPSBjbG9zZURpYWxvZztcbiAgICB2bS5jbGVhbkZvcm0gPSBjbGVhbkZvcm07XG4gICAgdm0uc2VuZEVtYWlsUmVzZXRQYXNzd29yZCA9IHNlbmRFbWFpbFJlc2V0UGFzc3dvcmQ7XG5cbiAgICBhY3RpdmF0ZSgpO1xuXG4gICAgZnVuY3Rpb24gYWN0aXZhdGUoKSB7XG4gICAgICB2bS5yZXNldCA9IHsgZW1haWw6ICcnLCB0b2tlbjogJHN0YXRlUGFyYW1zLnRva2VuIH07XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhbGl6YSBhIGFsdGVyYcOnw6NvIGRhIHNlbmhhIGRvIHVzdcOhcmlvIGUgbyByZWRpcmVjaW9uYSBwYXJhIGEgdGVsYSBkZSBsb2dpblxuICAgICAqL1xuICAgIGZ1bmN0aW9uIHNlbmRSZXNldCgpIHtcbiAgICAgICRodHRwLnBvc3QoR2xvYmFsLmFwaVBhdGggKyAnL3Bhc3N3b3JkL3Jlc2V0Jywgdm0ucmVzZXQpXG4gICAgICAgIC50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICBQclRvYXN0LnN1Y2Nlc3MoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5vcGVyYXRpb25TdWNjZXNzJykpO1xuICAgICAgICAgICR0aW1lb3V0KGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICRzdGF0ZS5nbyhHbG9iYWwubG9naW5TdGF0ZSk7XG4gICAgICAgICAgfSwgMTUwMCk7XG4gICAgICAgIH0sIGZ1bmN0aW9uIChlcnJvcikge1xuICAgICAgICAgIGlmIChlcnJvci5zdGF0dXMgIT09IDQwMCAmJiBlcnJvci5zdGF0dXMgIT09IDUwMCkge1xuICAgICAgICAgICAgdmFyIG1zZyA9ICcnO1xuXG4gICAgICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IGVycm9yLmRhdGEucGFzc3dvcmQubGVuZ3RoOyBpKyspIHtcbiAgICAgICAgICAgICAgbXNnICs9IGVycm9yLmRhdGEucGFzc3dvcmRbaV0gKyAnPGJyPic7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBQclRvYXN0LmVycm9yKG1zZy50b1VwcGVyQ2FzZSgpKTtcbiAgICAgICAgICB9XG4gICAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEVudmlhIHVtIGVtYWlsIGRlIHJlY3VwZXJhw6fDo28gZGUgc2VuaGEgY29tIG8gdG9rZW4gZG8gdXN1w6FyaW9cbiAgICAgKi9cbiAgICBmdW5jdGlvbiBzZW5kRW1haWxSZXNldFBhc3N3b3JkKCkge1xuXG4gICAgICBpZiAodm0ucmVzZXQuZW1haWwgPT09ICcnKSB7XG4gICAgICAgIFByVG9hc3QuZXJyb3IoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy52YWxpZGF0ZS5maWVsZFJlcXVpcmVkJywgeyBmaWVsZDogJ2VtYWlsJyB9KSk7XG4gICAgICAgIHJldHVybjtcbiAgICAgIH1cblxuICAgICAgQXV0aC5zZW5kRW1haWxSZXNldFBhc3N3b3JkKHZtLnJlc2V0KS50aGVuKGZ1bmN0aW9uIChkYXRhKSB7XG4gICAgICAgIFByVG9hc3Quc3VjY2VzcyhkYXRhLm1lc3NhZ2UpO1xuXG4gICAgICAgIHZtLmNsZWFuRm9ybSgpO1xuICAgICAgICB2bS5jbG9zZURpYWxvZygpO1xuICAgICAgfSwgZnVuY3Rpb24gKGVycm9yKSB7XG4gICAgICAgIGlmIChlcnJvci5kYXRhLmVtYWlsICYmIGVycm9yLmRhdGEuZW1haWwubGVuZ3RoID4gMCkge1xuICAgICAgICAgIHZhciBtc2cgPSAnJztcblxuICAgICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgZXJyb3IuZGF0YS5lbWFpbC5sZW5ndGg7IGkrKykge1xuICAgICAgICAgICAgbXNnICs9IGVycm9yLmRhdGEuZW1haWxbaV0gKyAnPGJyPic7XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgUHJUb2FzdC5lcnJvcihtc2cpO1xuICAgICAgICB9XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBjbG9zZURpYWxvZygpIHtcbiAgICAgIFByRGlhbG9nLmNsb3NlKCk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gY2xlYW5Gb3JtKCkge1xuICAgICAgdm0ucmVzZXQuZW1haWwgPSAnJztcbiAgICB9XG5cbiAgfVxuXG59KSgpO1xuIiwiLyplc2xpbnQgYW5ndWxhci9maWxlLW5hbWU6IDAqL1xuKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZhY3RvcnkoJ3NlcnZpY2VGYWN0b3J5Jywgc2VydmljZUZhY3RvcnkpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLyoqXG4gICAqIE1haXMgaW5mb3JtYcOnw7VlczpcbiAgICogaHR0cHM6Ly9naXRodWIuY29tL3N3aW1sYW5lL2FuZ3VsYXItbW9kZWwtZmFjdG9yeS93aWtpL0FQSVxuICAgKi9cbiAgZnVuY3Rpb24gc2VydmljZUZhY3RvcnkoJG1vZGVsRmFjdG9yeSkge1xuICAgIHJldHVybiBmdW5jdGlvbih1cmwsIG9wdGlvbnMpIHtcbiAgICAgIHZhciBtb2RlbDtcbiAgICAgIHZhciBkZWZhdWx0T3B0aW9ucyA9IHtcbiAgICAgICAgYWN0aW9uczoge1xuICAgICAgICAgIC8qKlxuICAgICAgICAgICAqIFNlcnZpw6dvIGNvbXVtIHBhcmEgcmVhbGl6YXIgYnVzY2EgY29tIHBhZ2luYcOnw6NvXG4gICAgICAgICAgICogTyBtZXNtbyBlc3BlcmEgcXVlIHNlamEgcmV0b3JuYWRvIHVtIG9iamV0byBjb20gaXRlbXMgZSB0b3RhbFxuICAgICAgICAgICAqL1xuICAgICAgICAgIHBhZ2luYXRlOiB7XG4gICAgICAgICAgICBtZXRob2Q6ICdHRVQnLFxuICAgICAgICAgICAgaXNBcnJheTogZmFsc2UsXG4gICAgICAgICAgICB3cmFwOiBmYWxzZSxcbiAgICAgICAgICAgIGFmdGVyUmVxdWVzdDogZnVuY3Rpb24ocmVzcG9uc2UpIHtcbiAgICAgICAgICAgICAgaWYgKHJlc3BvbnNlWydpdGVtcyddKSB7XG4gICAgICAgICAgICAgICAgcmVzcG9uc2VbJ2l0ZW1zJ10gPSBtb2RlbC5MaXN0KHJlc3BvbnNlWydpdGVtcyddKTtcbiAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgIHJldHVybiByZXNwb25zZTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgIH1cblxuICAgICAgbW9kZWwgPSAkbW9kZWxGYWN0b3J5KHVybCwgYW5ndWxhci5tZXJnZShkZWZhdWx0T3B0aW9ucywgb3B0aW9ucykpXG5cbiAgICAgIHJldHVybiBtb2RlbDtcbiAgICB9XG4gIH1cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIENSVURDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8qKlxuICAgKiBDb250cm9sYWRvciBCYXNlIHF1ZSBpbXBsZW1lbnRhIHRvZGFzIGFzIGZ1bsOnw7VlcyBwYWRyw7VlcyBkZSB1bSBDUlVEXG4gICAqXG4gICAqIEHDp8O1ZXMgaW1wbGVtZW50YWRhc1xuICAgKiBhY3RpdmF0ZSgpXG4gICAqIHNlYXJjaChwYWdlKVxuICAgKiBlZGl0KHJlc291cmNlKVxuICAgKiBzYXZlKClcbiAgICogcmVtb3ZlKHJlc291cmNlKVxuICAgKiBnb1RvKHZpZXdOYW1lKVxuICAgKiBjbGVhbkZvcm0oKVxuICAgKlxuICAgKiBHYXRpbGhvc1xuICAgKlxuICAgKiBvbkFjdGl2YXRlKClcbiAgICogYXBwbHlGaWx0ZXJzKGRlZmF1bHRRdWVyeUZpbHRlcnMpXG4gICAqIGJlZm9yZVNlYXJjaChwYWdlKSAvL3JldG9ybmFuZG8gZmFsc2UgY2FuY2VsYSBvIGZsdXhvXG4gICAqIGFmdGVyU2VhcmNoKHJlc3BvbnNlKVxuICAgKiBiZWZvcmVDbGVhbiAvL3JldG9ybmFuZG8gZmFsc2UgY2FuY2VsYSBvIGZsdXhvXG4gICAqIGFmdGVyQ2xlYW4oKVxuICAgKiBiZWZvcmVTYXZlKCkgLy9yZXRvcm5hbmRvIGZhbHNlIGNhbmNlbGEgbyBmbHV4b1xuICAgKiBhZnRlclNhdmUocmVzb3VyY2UpXG4gICAqIG9uU2F2ZUVycm9yKGVycm9yKVxuICAgKiBiZWZvcmVSZW1vdmUocmVzb3VyY2UpIC8vcmV0b3JuYW5kbyBmYWxzZSBjYW5jZWxhIG8gZmx1eG9cbiAgICogYWZ0ZXJSZW1vdmUocmVzb3VyY2UpXG4gICAqXG4gICAqIEBwYXJhbSB7YW55fSB2bSBpbnN0YW5jaWEgZG8gY29udHJvbGxlciBmaWxob1xuICAgKiBAcGFyYW0ge2FueX0gbW9kZWxTZXJ2aWNlIHNlcnZpw6dvIGRvIG1vZGVsIHF1ZSB2YWkgc2VyIHV0aWxpemFkb1xuICAgKiBAcGFyYW0ge2FueX0gb3B0aW9ucyBvcMOnw7VlcyBwYXJhIHNvYnJlZXNjcmV2ZXIgY29tcG9ydGFtZW50b3MgcGFkcsO1ZXNcbiAgICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIENSVURDb250cm9sbGVyKHZtLCBtb2RlbFNlcnZpY2UsIG9wdGlvbnMsIFByVG9hc3QsIFByUGFnaW5hdGlvbiwgLy8gTk9TT05BUlxuICAgIFByRGlhbG9nLCAkdHJhbnNsYXRlKSB7XG5cbiAgICAvL0Z1bmN0aW9ucyBCbG9ja1xuICAgIHZtLnNlYXJjaCA9IHNlYXJjaDtcbiAgICB2bS5wYWdpbmF0ZVNlYXJjaCA9IHBhZ2luYXRlU2VhcmNoO1xuICAgIHZtLm5vcm1hbFNlYXJjaCA9IG5vcm1hbFNlYXJjaDtcbiAgICB2bS5lZGl0ID0gZWRpdDtcbiAgICB2bS5zYXZlID0gc2F2ZTtcbiAgICB2bS5yZW1vdmUgPSByZW1vdmU7XG4gICAgdm0uZ29UbyA9IGdvVG87XG4gICAgdm0uY2xlYW5Gb3JtID0gY2xlYW5Gb3JtO1xuXG4gICAgYWN0aXZhdGUoKTtcblxuICAgIC8qKlxuICAgICAqIFByZXBhcmEgbyBjb250cm9sYWRvclxuICAgICAqIEZheiBvIG1lcmdlIGRhcyBvcMOnw7Vlc1xuICAgICAqIEluaWNpYWxpemEgbyByZWN1cnNvXG4gICAgICogSW5pY2lhbGl6YSBvIG9iamV0byBwYWdpbmFkb3IgZSByZWFsaXphIGEgcGVzcXVpc2FcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBhY3RpdmF0ZSgpIHtcbiAgICAgIHZtLmRlZmF1bHRPcHRpb25zID0ge1xuICAgICAgICByZWRpcmVjdEFmdGVyU2F2ZTogdHJ1ZSxcbiAgICAgICAgc2VhcmNoT25Jbml0OiB0cnVlLFxuICAgICAgICBwZXJQYWdlOiA4LFxuICAgICAgICBza2lwUGFnaW5hdGlvbjogZmFsc2VcbiAgICAgIH1cblxuICAgICAgYW5ndWxhci5tZXJnZSh2bS5kZWZhdWx0T3B0aW9ucywgb3B0aW9ucyk7XG5cbiAgICAgIHZtLnZpZXdGb3JtID0gZmFsc2U7XG4gICAgICB2bS5yZXNvdXJjZSA9IG5ldyBtb2RlbFNlcnZpY2UoKTtcblxuICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5vbkFjdGl2YXRlKSkgdm0ub25BY3RpdmF0ZSgpO1xuXG4gICAgICB2bS5wYWdpbmF0b3IgPSBQclBhZ2luYXRpb24uZ2V0SW5zdGFuY2Uodm0uc2VhcmNoLCB2bS5kZWZhdWx0T3B0aW9ucy5wZXJQYWdlKTtcblxuICAgICAgaWYgKHZtLmRlZmF1bHRPcHRpb25zLnNlYXJjaE9uSW5pdCkgdm0uc2VhcmNoKCk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhbGl6YSBhIHBlc3F1aXNhXG4gICAgICogVmVyaWZpY2EgcXVhbCBkYXMgZnVuw6fDtWVzIGRlIHBlc3F1aXNhIGRldmUgc2VyIHJlYWxpemFkYS5cbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSBwYWdlIHDDoWdpbmEgcXVlIGRldmUgc2VyIGNhcnJlZ2FkYVxuICAgICAqL1xuICAgIGZ1bmN0aW9uIHNlYXJjaChwYWdlKSB7XG4gICAgICAodm0uZGVmYXVsdE9wdGlvbnMuc2tpcFBhZ2luYXRpb24pID8gbm9ybWFsU2VhcmNoKCkgOiBwYWdpbmF0ZVNlYXJjaChwYWdlKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFsaXphIGEgcGVzcXVpc2EgcGFnaW5hZGEgY29tIGJhc2Ugbm9zIGZpbHRyb3MgZGVmaW5pZG9zXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gcGFnZSBww6FnaW5hIHF1ZSBkZXZlIHNlciBjYXJyZWdhZGFcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBwYWdpbmF0ZVNlYXJjaChwYWdlKSB7XG4gICAgICB2bS5wYWdpbmF0b3IuY3VycmVudFBhZ2UgPSAoYW5ndWxhci5pc0RlZmluZWQocGFnZSkpID8gcGFnZSA6IDE7XG4gICAgICB2bS5kZWZhdWx0UXVlcnlGaWx0ZXJzID0geyBwYWdlOiB2bS5wYWdpbmF0b3IuY3VycmVudFBhZ2UsIHBlclBhZ2U6IHZtLnBhZ2luYXRvci5wZXJQYWdlIH07XG5cbiAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYXBwbHlGaWx0ZXJzKSkgdm0uZGVmYXVsdFF1ZXJ5RmlsdGVycyA9IHZtLmFwcGx5RmlsdGVycyh2bS5kZWZhdWx0UXVlcnlGaWx0ZXJzKTtcbiAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYmVmb3JlU2VhcmNoKSAmJiB2bS5iZWZvcmVTZWFyY2gocGFnZSkgPT09IGZhbHNlKSByZXR1cm4gZmFsc2U7XG5cbiAgICAgIG1vZGVsU2VydmljZS5wYWdpbmF0ZSh2bS5kZWZhdWx0UXVlcnlGaWx0ZXJzKS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICB2bS5wYWdpbmF0b3IuY2FsY051bWJlck9mUGFnZXMocmVzcG9uc2UudG90YWwpO1xuICAgICAgICB2bS5yZXNvdXJjZXMgPSByZXNwb25zZS5pdGVtcztcblxuICAgICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmFmdGVyU2VhcmNoKSkgdm0uYWZ0ZXJTZWFyY2gocmVzcG9uc2UpO1xuICAgICAgfSwgZnVuY3Rpb24gKHJlc3BvbnNlRGF0YSkge1xuICAgICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLm9uU2VhcmNoRXJyb3IpKSB2bS5vblNlYXJjaEVycm9yKHJlc3BvbnNlRGF0YSk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFsaXphIGEgcGVzcXVpc2EgY29tIGJhc2Ugbm9zIGZpbHRyb3MgZGVmaW5pZG9zXG4gICAgICpcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBub3JtYWxTZWFyY2goKSB7XG4gICAgICB2bS5kZWZhdWx0UXVlcnlGaWx0ZXJzID0geyB9O1xuXG4gICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmFwcGx5RmlsdGVycykpIHZtLmRlZmF1bHRRdWVyeUZpbHRlcnMgPSB2bS5hcHBseUZpbHRlcnModm0uZGVmYXVsdFF1ZXJ5RmlsdGVycyk7XG4gICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmJlZm9yZVNlYXJjaCkgJiYgdm0uYmVmb3JlU2VhcmNoKCkgPT09IGZhbHNlKSByZXR1cm4gZmFsc2U7XG5cbiAgICAgIG1vZGVsU2VydmljZS5xdWVyeSh2bS5kZWZhdWx0UXVlcnlGaWx0ZXJzKS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICB2bS5yZXNvdXJjZXMgPSByZXNwb25zZTtcblxuICAgICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmFmdGVyU2VhcmNoKSkgdm0uYWZ0ZXJTZWFyY2gocmVzcG9uc2UpO1xuICAgICAgfSwgZnVuY3Rpb24gKHJlc3BvbnNlRGF0YSkge1xuICAgICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLm9uU2VhcmNoRXJyb3IpKSB2bS5vblNlYXJjaEVycm9yKHJlc3BvbnNlRGF0YSk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBMaW1wYSBvIGZvcm11bMOhcmlvXG4gICAgICovXG4gICAgZnVuY3Rpb24gY2xlYW5Gb3JtKGZvcm0pIHtcbiAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYmVmb3JlQ2xlYW4pICYmIHZtLmJlZm9yZUNsZWFuKCkgPT09IGZhbHNlKSByZXR1cm4gZmFsc2U7XG5cbiAgICAgIHZtLnJlc291cmNlID0gbmV3IG1vZGVsU2VydmljZSgpO1xuXG4gICAgICBpZiAoYW5ndWxhci5pc0RlZmluZWQoZm9ybSkpIHtcbiAgICAgICAgZm9ybS4kc2V0UHJpc3RpbmUoKTtcbiAgICAgICAgZm9ybS4kc2V0VW50b3VjaGVkKCk7XG4gICAgICB9XG5cbiAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYWZ0ZXJDbGVhbikpIHZtLmFmdGVyQ2xlYW4oKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDYXJyZWdhIG5vIGZvcm11bMOhcmlvIG8gcmVjdXJzbyBzZWxlY2lvbmFkbyBwYXJhIGVkacOnw6NvXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gcmVzb3VyY2UgcmVjdXJzbyBzZWxlY2lvbmFkb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGVkaXQocmVzb3VyY2UpIHtcbiAgICAgIHZtLmdvVG8oJ2Zvcm0nKTtcbiAgICAgIHZtLnJlc291cmNlID0gbmV3IGFuZ3VsYXIuY29weShyZXNvdXJjZSk7XG5cbiAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYWZ0ZXJFZGl0KSkgdm0uYWZ0ZXJFZGl0KCk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogU2FsdmEgb3UgYXR1YWxpemEgbyByZWN1cnNvIGNvcnJlbnRlIG5vIGZvcm11bMOhcmlvXG4gICAgICogTm8gY29tcG9ydGFtZW50byBwYWRyw6NvIHJlZGlyZWNpb25hIG8gdXN1w6FyaW8gcGFyYSB2aWV3IGRlIGxpc3RhZ2VtXG4gICAgICogZGVwb2lzIGRhIGV4ZWN1w6fDo29cbiAgICAgKlxuICAgICAqIEByZXR1cm5zXG4gICAgICovXG4gICAgZnVuY3Rpb24gc2F2ZShmb3JtKSB7XG4gICAgICBpZiAoYW5ndWxhci5pc0Z1bmN0aW9uKHZtLmJlZm9yZVNhdmUpICYmIHZtLmJlZm9yZVNhdmUoKSA9PT0gZmFsc2UpIHJldHVybiBmYWxzZTtcblxuICAgICAgdm0ucmVzb3VyY2UuJHNhdmUoKS50aGVuKGZ1bmN0aW9uIChyZXNvdXJjZSkge1xuICAgICAgICB2bS5yZXNvdXJjZSA9IHJlc291cmNlO1xuXG4gICAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYWZ0ZXJTYXZlKSkgdm0uYWZ0ZXJTYXZlKHJlc291cmNlKTtcblxuICAgICAgICBpZiAodm0uZGVmYXVsdE9wdGlvbnMucmVkaXJlY3RBZnRlclNhdmUpIHtcbiAgICAgICAgICB2bS5jbGVhbkZvcm0oZm9ybSk7XG4gICAgICAgICAgdm0uc2VhcmNoKHZtLnBhZ2luYXRvci5jdXJyZW50UGFnZSk7XG4gICAgICAgICAgdm0uZ29UbygnbGlzdCcpO1xuICAgICAgICB9XG5cbiAgICAgICAgUHJUb2FzdC5zdWNjZXNzKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMuc2F2ZVN1Y2Nlc3MnKSk7XG5cbiAgICAgIH0sIGZ1bmN0aW9uIChyZXNwb25zZURhdGEpIHtcbiAgICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5vblNhdmVFcnJvcikpIHZtLm9uU2F2ZUVycm9yKHJlc3BvbnNlRGF0YSk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZW1vdmUgbyByZWN1cnNvIGluZm9ybWFkby5cbiAgICAgKiBBbnRlcyBleGliZSB1bSBkaWFsb2dvIGRlIGNvbmZpcm1hw6fDo29cbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSByZXNvdXJjZSByZWN1cnNvIGVzY29saGlkb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIHJlbW92ZShyZXNvdXJjZSkge1xuICAgICAgdmFyIGNvbmZpZyA9IHtcbiAgICAgICAgdGl0bGU6ICR0cmFuc2xhdGUuaW5zdGFudCgnZGlhbG9nLmNvbmZpcm1UaXRsZScpLFxuICAgICAgICBkZXNjcmlwdGlvbjogJHRyYW5zbGF0ZS5pbnN0YW50KCdkaWFsb2cuY29uZmlybURlc2NyaXB0aW9uJylcbiAgICAgIH1cblxuICAgICAgUHJEaWFsb2cuY29uZmlybShjb25maWcpLnRoZW4oZnVuY3Rpb24oKSB7XG4gICAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24odm0uYmVmb3JlUmVtb3ZlKSAmJiB2bS5iZWZvcmVSZW1vdmUocmVzb3VyY2UpID09PSBmYWxzZSkgcmV0dXJuIGZhbHNlO1xuXG4gICAgICAgIHJlc291cmNlLiRkZXN0cm95KCkudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgaWYgKGFuZ3VsYXIuaXNGdW5jdGlvbih2bS5hZnRlclJlbW92ZSkpIHZtLmFmdGVyUmVtb3ZlKHJlc291cmNlKTtcblxuICAgICAgICAgIHZtLnNlYXJjaCgpO1xuICAgICAgICAgIFByVG9hc3QuaW5mbygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnJlbW92ZVN1Y2Nlc3MnKSk7XG4gICAgICAgIH0pO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQWx0ZXJuYSBlbnRyZSBhIHZpZXcgZG8gZm9ybXVsw6FyaW8gZSBsaXN0YWdlbVxuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9IHZpZXdOYW1lIG5vbWUgZGEgdmlld1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGdvVG8odmlld05hbWUpIHtcbiAgICAgIHZtLnZpZXdGb3JtID0gZmFsc2U7XG4gICAgICB2bS5vblZpZXcgPSBmYWxzZTtcbiAgICAgIGlmICh2aWV3TmFtZSA9PT0gJ2Zvcm0nKSB7XG4gICAgICAgIHZtLmNsZWFuRm9ybSgpO1xuICAgICAgICB2bS52aWV3Rm9ybSA9IHRydWU7XG4gICAgICB9XG4gICAgfVxuICB9XG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5maWx0ZXIoJ2VsYXBzZWQnLCBmdW5jdGlvbigpIHtcbiAgICAgIHJldHVybiBmdW5jdGlvbihkYXRlKSB7XG4gICAgICAgIGlmICghZGF0ZSkgcmV0dXJuO1xuICAgICAgICB2YXIgdGltZSA9IERhdGUucGFyc2UoZGF0ZSksXG4gICAgICAgICAgdGltZU5vdyA9IG5ldyBEYXRlKCkuZ2V0VGltZSgpLFxuICAgICAgICAgIGRpZmZlcmVuY2UgPSB0aW1lTm93IC0gdGltZSxcbiAgICAgICAgICBzZWNvbmRzID0gTWF0aC5mbG9vcihkaWZmZXJlbmNlIC8gMTAwMCksXG4gICAgICAgICAgbWludXRlcyA9IE1hdGguZmxvb3Ioc2Vjb25kcyAvIDYwKSxcbiAgICAgICAgICBob3VycyA9IE1hdGguZmxvb3IobWludXRlcyAvIDYwKSxcbiAgICAgICAgICBkYXlzID0gTWF0aC5mbG9vcihob3VycyAvIDI0KSxcbiAgICAgICAgICBtb250aHMgPSBNYXRoLmZsb29yKGRheXMgLyAzMCk7XG5cbiAgICAgICAgaWYgKG1vbnRocyA+IDEpIHtcbiAgICAgICAgICByZXR1cm4gbW9udGhzICsgJyBtZXNlcyBhdHLDoXMnO1xuICAgICAgICB9IGVsc2UgaWYgKG1vbnRocyA9PT0gMSkge1xuICAgICAgICAgIHJldHVybiAnMSBtw6pzIGF0csOhcyc7XG4gICAgICAgIH0gZWxzZSBpZiAoZGF5cyA+IDEpIHtcbiAgICAgICAgICByZXR1cm4gZGF5cyArICcgZGlhcyBhdHLDoXMnO1xuICAgICAgICB9IGVsc2UgaWYgKGRheXMgPT09IDEpIHtcbiAgICAgICAgICByZXR1cm4gJzEgZGlhIGF0csOhcydcbiAgICAgICAgfSBlbHNlIGlmIChob3VycyA+IDEpIHtcbiAgICAgICAgICByZXR1cm4gaG91cnMgKyAnIGhvcmFzIGF0csOhcyc7XG4gICAgICAgIH0gZWxzZSBpZiAoaG91cnMgPT09IDEpIHtcbiAgICAgICAgICByZXR1cm4gJ3VtYSBob3JhIGF0csOhcyc7XG4gICAgICAgIH0gZWxzZSBpZiAobWludXRlcyA+IDEpIHtcbiAgICAgICAgICByZXR1cm4gbWludXRlcyArICcgbWludXRvcyBhdHLDoXMnO1xuICAgICAgICB9IGVsc2UgaWYgKG1pbnV0ZXMgPT09IDEpIHtcbiAgICAgICAgICByZXR1cm4gJ3VtIG1pbnV0byBhdHLDoXMnO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIHJldHVybiAnaMOhIHBvdWNvcyBzZWd1bmRvcyc7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9KVxuICAgIC5jb250cm9sbGVyKCdEYXNoYm9hcmRDb250cm9sbGVyJywgRGFzaGJvYXJkQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBEYXNoYm9hcmRDb250cm9sbGVyKCRjb250cm9sbGVyLCAkc3RhdGUsIERhc2hib2FyZHNTZXJ2aWNlLCBQcm9qZWN0c1NlcnZpY2UsIG1vbWVudCkge1xuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICAvL0F0dHJpYnV0ZXMgQmxvY2tcblxuICAgIC8vRnVuY3Rpb25zIEJsb2NrXG4gICAgdm0ub25BY3RpdmF0ZSA9IG9uQWN0aXZhdGU7XG4gICAgdm0uYXBwbHlGaWx0ZXJzID0gYXBwbHlGaWx0ZXJzO1xuICAgIHZtLmZpeERhdGUgPSBmaXhEYXRlO1xuXG4gICAgZnVuY3Rpb24gb25BY3RpdmF0ZSgpIHtcbiAgICAgIHZhciBwcm9qZWN0ID0gbG9jYWxTdG9yYWdlLmdldEl0ZW0oJ3Byb2plY3QnKTtcblxuICAgICAgUHJvamVjdHNTZXJ2aWNlLnF1ZXJ5KHsgcHJvamVjdF9pZDogcHJvamVjdCB9KS50aGVuKGZ1bmN0aW9uKHJlc3BvbnNlKSB7XG4gICAgICAgIHZtLmFjdHVhbFByb2plY3QgPSByZXNwb25zZVswXTtcbiAgICAgIH0pXG4gICAgICB2bS5xdWVyeUZpbHRlcnMgPSB7IHByb2plY3RfaWQ6IHByb2plY3QgfTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBhcHBseUZpbHRlcnMoZGVmYXVsdFF1ZXJ5RmlsdGVycykge1xuICAgICAgcmV0dXJuIGFuZ3VsYXIuZXh0ZW5kKGRlZmF1bHRRdWVyeUZpbHRlcnMsIHZtLnF1ZXJ5RmlsdGVycyk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gZml4RGF0ZShkYXRlU3RyaW5nKSB7XG4gICAgICByZXR1cm4gbW9tZW50KGRhdGVTdHJpbmcpO1xuICAgIH1cblxuICAgIHZtLmdvVG9Qcm9qZWN0ID0gZnVuY3Rpb24oKSB7XG4gICAgICAkc3RhdGUuZ28oJ2FwcC5wcm9qZWN0cycsIHsgb2JqOiAnZWRpdCcsIHJlc291cmNlOiB2bS5hY3R1YWxQcm9qZWN0IH0pO1xuICAgIH1cblxuICAgIHZtLnRvdGFsQ29zdCA9IGZ1bmN0aW9uKCkge1xuICAgICAgdmFyIGVzdGltYXRlZF9jb3N0ID0gMDtcblxuICAgICAgdm0uYWN0dWFsUHJvamVjdC50YXNrcy5mb3JFYWNoKGZ1bmN0aW9uKHRhc2spIHtcbiAgICAgICAgZXN0aW1hdGVkX2Nvc3QgKz0gKHBhcnNlRmxvYXQodm0uYWN0dWFsUHJvamVjdC5ob3VyX3ZhbHVlX2ZpbmFsKSAqIHRhc2suZXN0aW1hdGVkX3RpbWUpO1xuICAgICAgfSk7XG4gICAgICByZXR1cm4gZXN0aW1hdGVkX2Nvc3QudG9Mb2NhbGVTdHJpbmcoJ1B0LWJyJywgeyBtaW5pbXVtRnJhY3Rpb25EaWdpdHM6IDIgfSk7XG4gICAgfVxuXG4gICAgLy8gaW5zdGFudGlhdGUgYmFzZSBjb250cm9sbGVyXG4gICAgJGNvbnRyb2xsZXIoJ0NSVURDb250cm9sbGVyJywgeyB2bTogdm0sIG1vZGVsU2VydmljZTogRGFzaGJvYXJkc1NlcnZpY2UsIG9wdGlvbnM6IHt9IH0pO1xuICB9XG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqXG4gICAqIEFycXVpdm8gZGUgY29uZmlndXJhw6fDo28gY29tIGFzIHJvdGFzIGVzcGVjw61maWNhcyBkbyByZWN1cnNvIHByb2plY3RcbiAgICpcbiAgICogQHBhcmFtIHthbnl9ICRzdGF0ZVByb3ZpZGVyXG4gICAqIEBwYXJhbSB7YW55fSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlclxuICAgICAgLnN0YXRlKCdhcHAuZGFzaGJvYXJkJywge1xuICAgICAgICB1cmw6ICcvZGFzaGJvYXJkcycsXG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvZGFzaGJvYXJkL2Rhc2hib2FyZC5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ0Rhc2hib2FyZENvbnRyb2xsZXIgYXMgZGFzaGJvYXJkQ3RybCcsXG4gICAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiB0cnVlIH0sXG4gICAgICAgIG9iajogeyByZXNvdXJjZTogbnVsbCB9XG4gICAgICB9KTtcbiAgfVxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5mYWN0b3J5KCdEYXNoYm9hcmRzU2VydmljZScsIERhc2hib2FyZHNTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIERhc2hib2FyZHNTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCdkYXNoYm9hcmRzJywge1xuICAgICAgYWN0aW9uczogeyB9LFxuICAgICAgaW5zdGFuY2U6IHsgfVxuICAgIH0pO1xuICB9XG5cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqXG4gICAqIEFycXVpdm8gZGUgY29uZmlndXJhw6fDo28gY29tIGFzIHJvdGFzIGVzcGVjw61maWNhcyBkbyByZWN1cnNvIHVzZXJcbiAgICpcbiAgICogQHBhcmFtIHthbnl9ICRzdGF0ZVByb3ZpZGVyXG4gICAqIEBwYXJhbSB7YW55fSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlclxuICAgICAgLnN0YXRlKCdhcHAuZGluYW1pYy1xdWVyeScsIHtcbiAgICAgICAgdXJsOiAnL2NvbnN1bHRhcy1kaW5hbWljYXMnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL2RpbmFtaWMtcXVlcnlzL2RpbmFtaWMtcXVlcnlzLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnRGluYW1pY1F1ZXJ5c0NvbnRyb2xsZXIgYXMgZGluYW1pY1F1ZXJ5Q3RybCcsXG4gICAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiB0cnVlLCBuZWVkUHJvZmlsZTogWydhZG1pbiddIH1cbiAgICAgIH0pO1xuXG4gIH1cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmFjdG9yeSgnRGluYW1pY1F1ZXJ5U2VydmljZScsIERpbmFtaWNRdWVyeVNlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gRGluYW1pY1F1ZXJ5U2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHJldHVybiBzZXJ2aWNlRmFjdG9yeSgnZGluYW1pY1F1ZXJ5Jywge1xuICAgICAgLyoqXG4gICAgICAgKiBhw6fDo28gYWRpY2lvbmFkYSBwYXJhIHBlZ2FyIHVtYSBsaXN0YSBkZSBtb2RlbHMgZXhpc3RlbnRlcyBubyBzZXJ2aWRvclxuICAgICAgICovXG4gICAgICBhY3Rpb25zOiB7XG4gICAgICAgIGdldE1vZGVsczoge1xuICAgICAgICAgIG1ldGhvZDogJ0dFVCcsXG4gICAgICAgICAgdXJsOiAnbW9kZWxzJ1xuICAgICAgICB9XG4gICAgICB9LFxuICAgICAgaW5zdGFuY2U6IHtcbiAgICAgIH1cbiAgICB9KTtcbiAgfVxuXG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29udHJvbGxlcignRGluYW1pY1F1ZXJ5c0NvbnRyb2xsZXInLCBEaW5hbWljUXVlcnlzQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBEaW5hbWljUXVlcnlzQ29udHJvbGxlcigkY29udHJvbGxlciwgRGluYW1pY1F1ZXJ5U2VydmljZSwgbG9kYXNoLCBQclRvYXN0LCAvLyBOT1NPTkFSXG4gICAgJHRyYW5zbGF0ZSkge1xuXG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIC8vYWN0aW9uc1xuICAgIHZtLm9uQWN0aXZhdGUgPSBvbkFjdGl2YXRlO1xuICAgIHZtLmFwcGx5RmlsdGVycyA9IGFwcGx5RmlsdGVycztcbiAgICB2bS5sb2FkQXR0cmlidXRlcyA9IGxvYWRBdHRyaWJ1dGVzO1xuICAgIHZtLmxvYWRPcGVyYXRvcnMgPSBsb2FkT3BlcmF0b3JzO1xuICAgIHZtLmFkZEZpbHRlciA9IGFkZEZpbHRlcjtcbiAgICB2bS5hZnRlclNlYXJjaCA9IGFmdGVyU2VhcmNoO1xuICAgIHZtLnJ1bkZpbHRlciA9IHJ1bkZpbHRlcjtcbiAgICB2bS5lZGl0RmlsdGVyID0gZWRpdEZpbHRlcjtcbiAgICB2bS5sb2FkTW9kZWxzID0gbG9hZE1vZGVscztcbiAgICB2bS5yZW1vdmVGaWx0ZXIgPSByZW1vdmVGaWx0ZXI7XG4gICAgdm0uY2xlYXIgPSBjbGVhcjtcbiAgICB2bS5yZXN0YXJ0ID0gcmVzdGFydDtcblxuICAgIC8vaGVyZGEgbyBjb21wb3J0YW1lbnRvIGJhc2UgZG8gQ1JVRFxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHsgdm06IHZtLCBtb2RlbFNlcnZpY2U6IERpbmFtaWNRdWVyeVNlcnZpY2UsIG9wdGlvbnM6IHtcbiAgICAgIHNlYXJjaE9uSW5pdDogZmFsc2VcbiAgICB9IH0pO1xuXG4gICAgZnVuY3Rpb24gb25BY3RpdmF0ZSgpIHtcbiAgICAgIHZtLnJlc3RhcnQoKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBQcmVwYXJhIGUgYXBsaWNhIG9zIGZpbHRybyBxdWUgdsOjbyBzZXIgZW52aWFkb3MgcGFyYSBvIHNlcnZpw6dvXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gZGVmYXVsdFF1ZXJ5RmlsdGVyc1xuICAgICAqIEByZXR1cm5zXG4gICAgICovXG4gICAgZnVuY3Rpb24gYXBwbHlGaWx0ZXJzKGRlZmF1bHRRdWVyeUZpbHRlcnMpIHtcbiAgICAgIHZhciB3aGVyZSA9IHt9O1xuXG4gICAgICAvKipcbiAgICAgICAqIG8gc2VydmnDp28gZXNwZXJhIHVtIG9iamV0byBjb206XG4gICAgICAgKiAgbyBub21lIGRlIHVtIG1vZGVsXG4gICAgICAgKiAgdW1hIGxpc3RhIGRlIGZpbHRyb3NcbiAgICAgICAqL1xuICAgICAgaWYgKHZtLmFkZGVkRmlsdGVycy5sZW5ndGggPiAwKSB7XG4gICAgICAgIHZhciBhZGRlZEZpbHRlcnMgPSBhbmd1bGFyLmNvcHkodm0uYWRkZWRGaWx0ZXJzKTtcblxuICAgICAgICB3aGVyZS5tb2RlbCA9IHZtLmFkZGVkRmlsdGVyc1swXS5tb2RlbC5uYW1lO1xuXG4gICAgICAgIGZvciAodmFyIGluZGV4ID0gMDsgaW5kZXggPCBhZGRlZEZpbHRlcnMubGVuZ3RoOyBpbmRleCsrKSB7XG4gICAgICAgICAgdmFyIGZpbHRlciA9IGFkZGVkRmlsdGVyc1tpbmRleF07XG5cbiAgICAgICAgICBmaWx0ZXIubW9kZWwgPSBudWxsO1xuICAgICAgICAgIGZpbHRlci5hdHRyaWJ1dGUgPSBmaWx0ZXIuYXR0cmlidXRlLm5hbWU7XG4gICAgICAgICAgZmlsdGVyLm9wZXJhdG9yID0gZmlsdGVyLm9wZXJhdG9yLnZhbHVlO1xuICAgICAgICB9XG5cbiAgICAgICAgd2hlcmUuZmlsdGVycyA9IGFuZ3VsYXIudG9Kc29uKGFkZGVkRmlsdGVycyk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICB3aGVyZS5tb2RlbCA9IHZtLnF1ZXJ5RmlsdGVycy5tb2RlbC5uYW1lO1xuICAgICAgfVxuXG4gICAgICByZXR1cm4gYW5ndWxhci5leHRlbmQoZGVmYXVsdFF1ZXJ5RmlsdGVycywgd2hlcmUpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENhcnJlZ2EgdG9kb3Mgb3MgbW9kZWxzIGNyaWFkb3Mgbm8gc2Vydmlkb3IgY29tIHNldXMgYXRyaWJ1dG9zXG4gICAgICovXG4gICAgZnVuY3Rpb24gbG9hZE1vZGVscygpIHtcbiAgICAgIC8vUGVnYSB0b2RvcyBvcyBtb2RlbHMgZG8gc2VydmVyIGUgbW9udGEgdW1hIGxpc3RhIHBybyBDb21ib0JveFxuICAgICAgRGluYW1pY1F1ZXJ5U2VydmljZS5nZXRNb2RlbHMoKS50aGVuKGZ1bmN0aW9uKGRhdGEpIHtcbiAgICAgICAgdm0ubW9kZWxzID0gZGF0YTtcbiAgICAgICAgdm0ucXVlcnlGaWx0ZXJzLm1vZGVsID0gdm0ubW9kZWxzWzBdO1xuICAgICAgICB2bS5sb2FkQXR0cmlidXRlcygpO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ2FycmVnYSBvcyBhdHRyaWJ1dG9zIGRvIG1vZGVsIGVzY29saGlkb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGxvYWRBdHRyaWJ1dGVzKCkge1xuICAgICAgdm0uYXR0cmlidXRlcyA9IHZtLnF1ZXJ5RmlsdGVycy5tb2RlbC5hdHRyaWJ1dGVzO1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzLmF0dHJpYnV0ZSA9IHZtLmF0dHJpYnV0ZXNbMF07XG5cbiAgICAgIHZtLmxvYWRPcGVyYXRvcnMoKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDYXJyZWdhIG9zIG9wZXJhZG9yZXMgZXNwZWNpZmljb3MgcGFyYSBvIHRpcG8gZG8gYXRyaWJ1dG9cbiAgICAgKi9cbiAgICBmdW5jdGlvbiBsb2FkT3BlcmF0b3JzKCkge1xuICAgICAgdmFyIG9wZXJhdG9ycyA9IFtcbiAgICAgICAgeyB2YWx1ZTogJz0nLCBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KCd2aWV3cy5maWVsZHMucXVlcnlEaW5hbWljLm9wZXJhdG9ycy5lcXVhbHMnKSB9LFxuICAgICAgICB7IHZhbHVlOiAnPD4nLCBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KCd2aWV3cy5maWVsZHMucXVlcnlEaW5hbWljLm9wZXJhdG9ycy5kaWZlcmVudCcpIH1cbiAgICAgIF1cblxuICAgICAgaWYgKHZtLnF1ZXJ5RmlsdGVycy5hdHRyaWJ1dGUudHlwZS5pbmRleE9mKCd2YXJ5aW5nJykgIT09IC0xKSB7XG4gICAgICAgIG9wZXJhdG9ycy5wdXNoKHsgdmFsdWU6ICdoYXMnLFxuICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLmNvbnRlaW5zJykgfSk7XG4gICAgICAgIG9wZXJhdG9ycy5wdXNoKHsgdmFsdWU6ICdzdGFydFdpdGgnLFxuICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLnN0YXJ0V2l0aCcpIH0pO1xuICAgICAgICBvcGVyYXRvcnMucHVzaCh7IHZhbHVlOiAnZW5kV2l0aCcsXG4gICAgICAgICAgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudCgndmlld3MuZmllbGRzLnF1ZXJ5RGluYW1pYy5vcGVyYXRvcnMuZmluaXNoV2l0aCcpIH0pO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgb3BlcmF0b3JzLnB1c2goeyB2YWx1ZTogJz4nLFxuICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLmJpZ2dlclRoYW4nKSB9KTtcbiAgICAgICAgb3BlcmF0b3JzLnB1c2goeyB2YWx1ZTogJz49JyxcbiAgICAgICAgICBsYWJlbDogJHRyYW5zbGF0ZS5pbnN0YW50KCd2aWV3cy5maWVsZHMucXVlcnlEaW5hbWljLm9wZXJhdG9ycy5lcXVhbHNPckJpZ2dlclRoYW4nKSB9KTtcbiAgICAgICAgb3BlcmF0b3JzLnB1c2goeyB2YWx1ZTogJzwnLFxuICAgICAgICAgIGxhYmVsOiAkdHJhbnNsYXRlLmluc3RhbnQoJ3ZpZXdzLmZpZWxkcy5xdWVyeURpbmFtaWMub3BlcmF0b3JzLmxlc3NUaGFuJykgfSk7XG4gICAgICAgIG9wZXJhdG9ycy5wdXNoKHsgdmFsdWU6ICc8PScsXG4gICAgICAgICAgbGFiZWw6ICR0cmFuc2xhdGUuaW5zdGFudCgndmlld3MuZmllbGRzLnF1ZXJ5RGluYW1pYy5vcGVyYXRvcnMuZXF1YWxzT3JMZXNzVGhhbicpIH0pO1xuICAgICAgfVxuXG4gICAgICB2bS5vcGVyYXRvcnMgPSBvcGVyYXRvcnM7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMub3BlcmF0b3IgPSB2bS5vcGVyYXRvcnNbMF07XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQWRpY2lvbmEvZWRpdGEgdW0gZmlsdHJvXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gZm9ybSBlbGVtZW50byBodG1sIGRvIGZvcm11bMOhcmlvIHBhcmEgdmFsaWRhw6fDtWVzXG4gICAgICovXG4gICAgZnVuY3Rpb24gYWRkRmlsdGVyKGZvcm0pIHtcbiAgICAgIGlmIChhbmd1bGFyLmlzVW5kZWZpbmVkKHZtLnF1ZXJ5RmlsdGVycy52YWx1ZSkgfHwgdm0ucXVlcnlGaWx0ZXJzLnZhbHVlID09PSAnJykge1xuICAgICAgICBQclRvYXN0LmVycm9yKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMudmFsaWRhdGUuZmllbGRSZXF1aXJlZCcsIHsgZmllbGQ6ICd2YWxvcicgfSkpO1xuICAgICAgICByZXR1cm47XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBpZiAodm0uaW5kZXggPCAwKSB7XG4gICAgICAgICAgdm0uYWRkZWRGaWx0ZXJzLnB1c2goYW5ndWxhci5jb3B5KHZtLnF1ZXJ5RmlsdGVycykpO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIHZtLmFkZGVkRmlsdGVyc1t2bS5pbmRleF0gPSBhbmd1bGFyLmNvcHkodm0ucXVlcnlGaWx0ZXJzKTtcbiAgICAgICAgICB2bS5pbmRleCA9IC0xO1xuICAgICAgICB9XG5cbiAgICAgICAgLy9yZWluaWNpYSBvIGZvcm11bMOhcmlvIGUgYXMgdmFsaWRhw6fDtWVzIGV4aXN0ZW50ZXNcbiAgICAgICAgdm0ucXVlcnlGaWx0ZXJzID0ge307XG4gICAgICAgIGZvcm0uJHNldFByaXN0aW5lKCk7XG4gICAgICAgIGZvcm0uJHNldFVudG91Y2hlZCgpO1xuICAgICAgfVxuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWxpemEgYSBwZXNxdWlzYSB0ZW5kbyBvcyBmaWx0cm9zIGNvbW8gcGFyw6JtZXRyb3NcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBydW5GaWx0ZXIoKSB7XG4gICAgICB2bS5zZWFyY2godm0ucGFnaW5hdG9yLmN1cnJlbnRQYWdlKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBHYXRpbGhvIGFjaW9uYWRvIGRlcG9pcyBkYSBwZXNxdWlzYSByZXNwb25zw6F2ZWwgcG9yIGlkZW50aWZpY2FyIG9zIGF0cmlidXRvc1xuICAgICAqIGNvbnRpZG9zIG5vcyBlbGVtZW50b3MgcmVzdWx0YW50ZXMgZGEgYnVzY2FcbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSBkYXRhIGRhZG9zIHJlZmVyZW50ZSBhbyByZXRvcm5vIGRhIHJlcXVpc2nDp8Ojb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIGFmdGVyU2VhcmNoKGRhdGEpIHtcbiAgICAgIHZhciBrZXlzID0gKGRhdGEuaXRlbXMubGVuZ3RoID4gMCkgPyBPYmplY3Qua2V5cyhkYXRhLml0ZW1zWzBdKSA6IFtdO1xuXG4gICAgICAvL3JldGlyYSB0b2RvcyBvcyBhdHJpYnV0b3MgcXVlIGNvbWXDp2FtIGNvbSAkLlxuICAgICAgLy9Fc3NlcyBhdHJpYnV0b3Mgc8OjbyBhZGljaW9uYWRvcyBwZWxvIHNlcnZpw6dvIGUgbsOjbyBkZXZlIGFwYXJlY2VyIG5hIGxpc3RhZ2VtXG4gICAgICB2bS5rZXlzID0gbG9kYXNoLmZpbHRlcihrZXlzLCBmdW5jdGlvbihrZXkpIHtcbiAgICAgICAgcmV0dXJuICFsb2Rhc2guc3RhcnRzV2l0aChrZXksICckJyk7XG4gICAgICB9KVxuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENvbG9hY2Egbm8gZm9ybXVsw6FyaW8gbyBmaWx0cm8gZXNjb2xoaWRvIHBhcmEgZWRpw6fDo29cbiAgICAgKiBAcGFyYW0ge2FueX0gJGluZGV4IGluZGljZSBubyBhcnJheSBkbyBmaWx0cm8gZXNjb2xoaWRvXG4gICAgICovXG4gICAgZnVuY3Rpb24gZWRpdEZpbHRlcigkaW5kZXgpIHtcbiAgICAgIHZtLmluZGV4ID0gJGluZGV4O1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0gdm0uYWRkZWRGaWx0ZXJzWyRpbmRleF07XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVtb3ZlIG8gZmlsdHJvIGVzY29saGlkb1xuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9ICRpbmRleCBpbmRpY2Ugbm8gYXJyYXkgZG8gZmlsdHJvIGVzY29saGlkb1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIHJlbW92ZUZpbHRlcigkaW5kZXgpIHtcbiAgICAgIHZtLmFkZGVkRmlsdGVycy5zcGxpY2UoJGluZGV4KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBMaW1wYSBvIGZvcm11bMOhcmlvIGNvcnJlbnRlXG4gICAgICovXG4gICAgZnVuY3Rpb24gY2xlYXIoKSB7XG4gICAgICAvL2d1YXJkYSBvIGluZGljZSBkbyByZWdpc3RybyBxdWUgZXN0w6Egc2VuZG8gZWRpdGFkb1xuICAgICAgdm0uaW5kZXggPSAtMTtcbiAgICAgIC8vdmluY3VsYWRvIGFvcyBjYW1wb3MgZG8gZm9ybXVsw6FyaW9cbiAgICAgIHZtLnF1ZXJ5RmlsdGVycyA9IHtcbiAgICAgIH07XG5cbiAgICAgIGlmICh2bS5tb2RlbHMpIHZtLnF1ZXJ5RmlsdGVycy5tb2RlbCA9IHZtLm1vZGVsc1swXTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWluaWNpYSBhIGNvbnN0cnXDp8OjbyBkYSBxdWVyeSBsaW1wYW5kbyB0dWRvXG4gICAgICpcbiAgICAgKi9cbiAgICBmdW5jdGlvbiByZXN0YXJ0KCkge1xuICAgICAgLy9ndWFyZGEgYXRyaWJ1dG9zIGRvIHJlc3VsdGFkbyBkYSBidXNjYSBjb3JyZW50ZVxuICAgICAgdm0ua2V5cyA9IFtdO1xuXG4gICAgICAvL2d1YXJkYSBvcyBmaWx0cm9zIGFkaWNpb25hZG9zXG4gICAgICB2bS5hZGRlZEZpbHRlcnMgPSBbXTtcbiAgICAgIHZtLmNsZWFyKCk7XG4gICAgICB2bS5sb2FkTW9kZWxzKCk7XG4gICAgfVxuXG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZhY3RvcnkoJ2xhbmd1YWdlTG9hZGVyJywgTGFuZ3VhZ2VMb2FkZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gTGFuZ3VhZ2VMb2FkZXIoJHEsIFN1cHBvcnRTZXJ2aWNlLCAkbG9nLCAkaW5qZWN0b3IpIHtcbiAgICB2YXIgc2VydmljZSA9IHRoaXM7XG5cbiAgICBzZXJ2aWNlLnRyYW5zbGF0ZSA9IGZ1bmN0aW9uKGxvY2FsZSkge1xuICAgICAgcmV0dXJuIHtcbiAgICAgICAgZ2xvYmFsOiAkaW5qZWN0b3IuZ2V0KGxvY2FsZSArICcuaTE4bi5nbG9iYWwnKSxcbiAgICAgICAgdmlld3M6ICRpbmplY3Rvci5nZXQobG9jYWxlICsgJy5pMThuLnZpZXdzJyksXG4gICAgICAgIGF0dHJpYnV0ZXM6ICRpbmplY3Rvci5nZXQobG9jYWxlICsgJy5pMThuLmF0dHJpYnV0ZXMnKSxcbiAgICAgICAgZGlhbG9nOiAkaW5qZWN0b3IuZ2V0KGxvY2FsZSArICcuaTE4bi5kaWFsb2cnKSxcbiAgICAgICAgbWVzc2FnZXM6ICRpbmplY3Rvci5nZXQobG9jYWxlICsgJy5pMThuLm1lc3NhZ2VzJyksXG4gICAgICAgIG1vZGVsczogJGluamVjdG9yLmdldChsb2NhbGUgKyAnLmkxOG4ubW9kZWxzJylcbiAgICAgIH07XG4gICAgfVxuXG4gICAgLy8gcmV0dXJuIGxvYWRlckZuXG4gICAgcmV0dXJuIGZ1bmN0aW9uKG9wdGlvbnMpIHtcbiAgICAgICRsb2cuaW5mbygnQ2FycmVnYW5kbyBvIGNvbnRldWRvIGRhIGxpbmd1YWdlbSAnICsgb3B0aW9ucy5rZXkpO1xuXG4gICAgICB2YXIgZGVmZXJyZWQgPSAkcS5kZWZlcigpO1xuXG4gICAgICAvL0NhcnJlZ2EgYXMgbGFuZ3MgcXVlIHByZWNpc2FtIGUgZXN0w6NvIG5vIHNlcnZpZG9yIHBhcmEgbsOjbyBwcmVjaXNhciByZXBldGlyIGFxdWlcbiAgICAgIFN1cHBvcnRTZXJ2aWNlLmxhbmdzKCkudGhlbihmdW5jdGlvbihsYW5ncykge1xuICAgICAgICAvL01lcmdlIGNvbSBvcyBsYW5ncyBkZWZpbmlkb3Mgbm8gc2Vydmlkb3JcbiAgICAgICAgdmFyIGRhdGEgPSBhbmd1bGFyLm1lcmdlKHNlcnZpY2UudHJhbnNsYXRlKG9wdGlvbnMua2V5KSwgbGFuZ3MpO1xuXG4gICAgICAgIHJldHVybiBkZWZlcnJlZC5yZXNvbHZlKGRhdGEpO1xuICAgICAgfSwgZnVuY3Rpb24oKSB7XG4gICAgICAgIHJldHVybiBkZWZlcnJlZC5yZXNvbHZlKHNlcnZpY2UudHJhbnNsYXRlKG9wdGlvbnMua2V5KSk7XG4gICAgICB9KTtcblxuICAgICAgcmV0dXJuIGRlZmVycmVkLnByb21pc2U7XG4gICAgfVxuICB9XG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5maWx0ZXIoJ3RBdHRyJywgdEF0dHIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gdEF0dHIoJGZpbHRlcikge1xuICAgIC8qKlxuICAgICAqIEZpbHRybyBwYXJhIHRyYWR1w6fDo28gZGUgdW0gYXRyaWJ1dG8gZGUgdW0gbW9kZWxcbiAgICAgKiBcbiAgICAgKiBAcGFyYW0ge2FueX0gbmFtZSBub21lIGRvIGF0cmlidXRvXG4gICAgICogQHJldHVybnMgbyBub21lIGRvIGF0cmlidXRvIHRyYWR1emlkbyBjYXNvIGVuY29udHJlIHNlIG7Do28gbyBub21lIHBhc3NhZG8gcG9yIHBhcmFtZXRyb1xuICAgICAqLyAgICBcbiAgICByZXR1cm4gZnVuY3Rpb24obmFtZSkge1xuICAgICAgdmFyIGtleSA9ICdhdHRyaWJ1dGVzLicgKyBuYW1lO1xuICAgICAgdmFyIHRyYW5zbGF0ZSA9ICRmaWx0ZXIoJ3RyYW5zbGF0ZScpKGtleSk7XG5cbiAgICAgIHJldHVybiAodHJhbnNsYXRlID09PSBrZXkpID8gbmFtZSA6IHRyYW5zbGF0ZTtcbiAgICB9XG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZpbHRlcigndEJyZWFkY3J1bWInLCB0QnJlYWRjcnVtYik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiB0QnJlYWRjcnVtYigkZmlsdGVyKSB7XG4gICAgLyoqXG4gICAgICogRmlsdHJvIHBhcmEgdHJhZHXDp8OjbyBkbyBicmVhZGNydW1iICh0aXR1bG8gZGEgdGVsYSBjb20gcmFzdHJlaW8pXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2FueX0gaWQgY2hhdmUgY29tIG8gbm9tZSBkbyBzdGF0ZSByZWZlcmVudGUgdGVsYVxuICAgICAqIEByZXR1cm5zIGEgdHJhZHXDp8OjbyBjYXNvIGVuY29udHJlIHNlIG7Do28gbyBpZCBwYXNzYWRvIHBvciBwYXJhbWV0cm9cbiAgICAgKi9cbiAgICByZXR1cm4gZnVuY3Rpb24oaWQpIHtcbiAgICAgIC8vcGVnYSBhIHNlZ3VuZGEgcGFydGUgZG8gbm9tZSBkbyBzdGF0ZSwgcmV0aXJhbmRvIGEgcGFydGUgYWJzdHJhdGEgKGFwcC4pXG4gICAgICB2YXIga2V5ID0gJ3ZpZXdzLmJyZWFkY3J1bWJzLicgKyBpZC5zcGxpdCgnLicpWzFdO1xuICAgICAgdmFyIHRyYW5zbGF0ZSA9ICRmaWx0ZXIoJ3RyYW5zbGF0ZScpKGtleSk7XG5cbiAgICAgIHJldHVybiAodHJhbnNsYXRlID09PSBrZXkpID8gaWQgOiB0cmFuc2xhdGU7XG4gICAgfVxuICB9XG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5maWx0ZXIoJ3RNb2RlbCcsIHRNb2RlbCk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiB0TW9kZWwoJGZpbHRlcikge1xuICAgIC8qKlxuICAgICAqIEZpbHRybyBwYXJhIHRyYWR1w6fDo28gZGUgdW0gYXRyaWJ1dG8gZGUgdW0gbW9kZWxcbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSBuYW1lIG5vbWUgZG8gYXRyaWJ1dG9cbiAgICAgKiBAcmV0dXJucyBvIG5vbWUgZG8gYXRyaWJ1dG8gdHJhZHV6aWRvIGNhc28gZW5jb250cmUgc2UgbsOjbyBvIG5vbWUgcGFzc2FkbyBwb3IgcGFyYW1ldHJvXG4gICAgICovXG4gICAgcmV0dXJuIGZ1bmN0aW9uKG5hbWUpIHtcbiAgICAgIHZhciBrZXkgPSAnbW9kZWxzLicgKyBuYW1lLnRvTG93ZXJDYXNlKCk7XG4gICAgICB2YXIgdHJhbnNsYXRlID0gJGZpbHRlcigndHJhbnNsYXRlJykoa2V5KTtcblxuICAgICAgcmV0dXJuICh0cmFuc2xhdGUgPT09IGtleSkgPyBuYW1lIDogdHJhbnNsYXRlO1xuICAgIH1cbiAgfVxuXG59KSgpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLnJ1bihhdXRoZW50aWNhdGlvbkxpc3RlbmVyKTtcblxuICAvKipcbiAgICogTGlzdGVuIGFsbCBzdGF0ZSAocGFnZSkgY2hhbmdlcy4gRXZlcnkgdGltZSBhIHN0YXRlIGNoYW5nZSBuZWVkIHRvIHZlcmlmeSB0aGUgdXNlciBpcyBhdXRoZW50aWNhdGVkIG9yIG5vdCB0b1xuICAgKiByZWRpcmVjdCB0byBjb3JyZWN0IHBhZ2UuIFdoZW4gYSB1c2VyIGNsb3NlIHRoZSBicm93c2VyIHdpdGhvdXQgbG9nb3V0LCB3aGVuIGhpbSByZW9wZW4gdGhlIGJyb3dzZXIgdGhpcyBldmVudFxuICAgKiByZWF1dGhlbnRpY2F0ZSB0aGUgdXNlciB3aXRoIHRoZSBwZXJzaXN0ZW50IHRva2VuIG9mIHRoZSBsb2NhbCBzdG9yYWdlLlxuICAgKlxuICAgKiBXZSBkb24ndCBjaGVjayBpZiB0aGUgdG9rZW4gaXMgZXhwaXJlZCBvciBub3QgaW4gdGhlIHBhZ2UgY2hhbmdlLCBiZWNhdXNlIGlzIGdlbmVyYXRlIGFuIHVuZWNlc3Nhcnkgb3ZlcmhlYWQuXG4gICAqIElmIHRoZSB0b2tlbiBpcyBleHBpcmVkIHdoZW4gdGhlIHVzZXIgdHJ5IHRvIGNhbGwgdGhlIGZpcnN0IGFwaSB0byBnZXQgZGF0YSwgaGltIHdpbGwgYmUgbG9nb2ZmIGFuZCByZWRpcmVjdFxuICAgKiB0byBsb2dpbiBwYWdlLlxuICAgKlxuICAgKiBAcGFyYW0gJHJvb3RTY29wZVxuICAgKiBAcGFyYW0gJHN0YXRlXG4gICAqIEBwYXJhbSAkc3RhdGVQYXJhbXNcbiAgICogQHBhcmFtIEF1dGhcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gYXV0aGVudGljYXRpb25MaXN0ZW5lcigkcm9vdFNjb3BlLCAkc3RhdGUsIEdsb2JhbCwgQXV0aCwgUHJUb2FzdCwgLy8gTk9TT05BUlxuICAgICR0cmFuc2xhdGUpIHtcblxuICAgIC8vb25seSB3aGVuIGFwcGxpY2F0aW9uIHN0YXJ0IGNoZWNrIGlmIHRoZSBleGlzdGVudCB0b2tlbiBzdGlsbCB2YWxpZFxuICAgIEF1dGgucmVtb3RlVmFsaWRhdGVUb2tlbigpLnRoZW4oZnVuY3Rpb24oKSB7XG4gICAgICAvL2lmIHRoZSB0b2tlbiBpcyB2YWxpZCBjaGVjayBpZiBleGlzdHMgdGhlIHVzZXIgYmVjYXVzZSB0aGUgYnJvd3NlciBjb3VsZCBiZSBjbG9zZWRcbiAgICAgIC8vYW5kIHRoZSB1c2VyIGRhdGEgaXNuJ3QgaW4gbWVtb3J5XG4gICAgICBpZiAoQXV0aC5jdXJyZW50VXNlciA9PT0gbnVsbCkge1xuICAgICAgICBBdXRoLnVwZGF0ZUN1cnJlbnRVc2VyKGFuZ3VsYXIuZnJvbUpzb24obG9jYWxTdG9yYWdlLmdldEl0ZW0oJ3VzZXInKSkpO1xuICAgICAgfVxuICAgIH0pO1xuXG4gICAgLy9DaGVjayBpZiB0aGUgdG9rZW4gc3RpbGwgdmFsaWQuXG4gICAgJHJvb3RTY29wZS4kb24oJyRzdGF0ZUNoYW5nZVN0YXJ0JywgZnVuY3Rpb24oZXZlbnQsIHRvU3RhdGUpIHtcbiAgICAgIGlmICh0b1N0YXRlLmRhdGEubmVlZEF1dGhlbnRpY2F0aW9uIHx8IHRvU3RhdGUuZGF0YS5uZWVkUHJvZmlsZSkge1xuICAgICAgICAvL2RvbnQgdHJhaXQgdGhlIHN1Y2Nlc3MgYmxvY2sgYmVjYXVzZSBhbHJlYWR5IGRpZCBieSB0b2tlbiBpbnRlcmNlcHRvclxuICAgICAgICBBdXRoLnJlbW90ZVZhbGlkYXRlVG9rZW4oKS5jYXRjaChmdW5jdGlvbigpIHtcbiAgICAgICAgICBQclRvYXN0Lndhcm4oJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5sb2dpbi5sb2dvdXRJbmFjdGl2ZScpKTtcblxuICAgICAgICAgIGlmICh0b1N0YXRlLm5hbWUgIT09IEdsb2JhbC5sb2dpblN0YXRlKSB7XG4gICAgICAgICAgICAkc3RhdGUuZ28oR2xvYmFsLmxvZ2luU3RhdGUpO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIGV2ZW50LnByZXZlbnREZWZhdWx0KCk7XG4gICAgICAgIH0pO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgLy9pZiB0aGUgdXNlIGlzIGF1dGhlbnRpY2F0ZWQgYW5kIG5lZWQgdG8gZW50ZXIgaW4gbG9naW4gcGFnZVxuICAgICAgICAvL2hpbSB3aWxsIGJlIHJlZGlyZWN0ZWQgdG8gaG9tZSBwYWdlXG4gICAgICAgIGlmICh0b1N0YXRlLm5hbWUgPT09IEdsb2JhbC5sb2dpblN0YXRlICYmIEF1dGguYXV0aGVudGljYXRlZCgpKSB7XG4gICAgICAgICAgJHN0YXRlLmdvKEdsb2JhbC5ob21lU3RhdGUpO1xuICAgICAgICAgIGV2ZW50LnByZXZlbnREZWZhdWx0KCk7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9KTtcbiAgfVxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5ydW4oYXV0aG9yaXphdGlvbkxpc3RlbmVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIGF1dGhvcml6YXRpb25MaXN0ZW5lcigkcm9vdFNjb3BlLCAkc3RhdGUsIEdsb2JhbCwgQXV0aCkge1xuICAgIC8qKlxuICAgICAqIEEgY2FkYSBtdWRhbsOnYSBkZSBlc3RhZG8gKFwicMOhZ2luYVwiKSB2ZXJpZmljYSBzZSBvIHVzdcOhcmlvIHRlbSBvIHBlcmZpbFxuICAgICAqIG5lY2Vzc8OhcmlvIHBhcmEgbyBhY2Vzc28gYSBtZXNtYVxuICAgICAqL1xuICAgICRyb290U2NvcGUuJG9uKCckc3RhdGVDaGFuZ2VTdGFydCcsIGZ1bmN0aW9uKGV2ZW50LCB0b1N0YXRlKSB7XG4gICAgICBpZiAodG9TdGF0ZS5kYXRhICYmIHRvU3RhdGUuZGF0YS5uZWVkQXV0aGVudGljYXRpb24gJiZcbiAgICAgICAgdG9TdGF0ZS5kYXRhLm5lZWRQcm9maWxlICYmIEF1dGguYXV0aGVudGljYXRlZCgpICYmXG4gICAgICAgICFBdXRoLmN1cnJlbnRVc2VyLmhhc1Byb2ZpbGUodG9TdGF0ZS5kYXRhLm5lZWRQcm9maWxlLCB0b1N0YXRlLmRhdGEuYWxsUHJvZmlsZXMpKSB7XG5cbiAgICAgICAgJHN0YXRlLmdvKEdsb2JhbC5ub3RBdXRob3JpemVkU3RhdGUpO1xuICAgICAgICBldmVudC5wcmV2ZW50RGVmYXVsdCgpO1xuICAgICAgfVxuXG4gICAgfSk7XG4gIH1cbn0oKSk7XG4iLCIoZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbmZpZyhzcGlubmVySW50ZXJjZXB0b3IpO1xuXG4gIGZ1bmN0aW9uIHNwaW5uZXJJbnRlcmNlcHRvcigkaHR0cFByb3ZpZGVyLCAkcHJvdmlkZSkge1xuICAgIC8qKlxuICAgICAqIEVzdGUgaW50ZXJjZXB0b3Igw6kgcmVzcG9uc8OhdmVsIHBvciBtb3N0cmFyIGUgZXNjb25kZXIgb1xuICAgICAqIGNvbXBvbmVudGUgUHJTcGlubmVyIHNlbXByZSBxdWUgdW1hIHJlcXVpc2nDp8OjbyBhamF4XG4gICAgICogaW5pY2lhciBlIGZpbmFsaXphci5cbiAgICAgKlxuICAgICAqIEBwYXJhbSB7YW55fSAkcVxuICAgICAqIEBwYXJhbSB7YW55fSAkaW5qZWN0b3JcbiAgICAgKiBAcmV0dXJuc1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIHNob3dIaWRlU3Bpbm5lcigkcSwgJGluamVjdG9yKSB7XG4gICAgICByZXR1cm4ge1xuICAgICAgICByZXF1ZXN0OiBmdW5jdGlvbiAoY29uZmlnKSB7XG4gICAgICAgICAgJGluamVjdG9yLmdldCgnUHJTcGlubmVyJykuc2hvdygpO1xuXG4gICAgICAgICAgcmV0dXJuIGNvbmZpZztcbiAgICAgICAgfSxcblxuICAgICAgICByZXNwb25zZTogZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgICAgJGluamVjdG9yLmdldCgnUHJTcGlubmVyJykuaGlkZSgpO1xuXG4gICAgICAgICAgcmV0dXJuIHJlc3BvbnNlO1xuICAgICAgICB9LFxuXG4gICAgICAgIHJlc3BvbnNlRXJyb3I6IGZ1bmN0aW9uIChyZWplY3Rpb24pIHtcbiAgICAgICAgICAkaW5qZWN0b3IuZ2V0KCdQclNwaW5uZXInKS5oaWRlKCk7XG5cbiAgICAgICAgICByZXR1cm4gJHEucmVqZWN0KHJlamVjdGlvbik7XG4gICAgICAgIH1cbiAgICAgIH07XG4gICAgfVxuXG4gICAgLy8gRGVmaW5lIHVtYSBmYWN0b3J5IHBhcmEgbyAkaHR0cEludGVyY2VwdG9yXG4gICAgJHByb3ZpZGUuZmFjdG9yeSgnc2hvd0hpZGVTcGlubmVyJywgc2hvd0hpZGVTcGlubmVyKTtcblxuICAgIC8vIEFkaWNpb25hIGEgZmFjdG9yeSBubyBhcnJheSBkZSBpbnRlcmNlcHRvcnMgZG8gJGh0dHBcbiAgICAkaHR0cFByb3ZpZGVyLmludGVyY2VwdG9ycy5wdXNoKCdzaG93SGlkZVNwaW5uZXInKTtcbiAgfVxufSgpKTtcbiIsIi8qZXNsaW50IGFuZ3VsYXIvbW9kdWxlLWdldHRlcjogMCovXG5cbihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb25maWcodG9rZW5JbnRlcmNlcHRvcik7XG5cbiAgLyoqXG4gICAqIEludGVyY2VwdCBhbGwgcmVzcG9uc2UgKHN1Y2Nlc3Mgb3IgZXJyb3IpIHRvIHZlcmlmeSB0aGUgcmV0dXJuZWQgdG9rZW5cbiAgICpcbiAgICogQHBhcmFtICRodHRwUHJvdmlkZXJcbiAgICogQHBhcmFtICRwcm92aWRlXG4gICAqIEBwYXJhbSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gdG9rZW5JbnRlcmNlcHRvcigkaHR0cFByb3ZpZGVyLCAkcHJvdmlkZSwgR2xvYmFsKSB7XG5cbiAgICBmdW5jdGlvbiByZWRpcmVjdFdoZW5TZXJ2ZXJMb2dnZWRPdXQoJHEsICRpbmplY3Rvcikge1xuICAgICAgcmV0dXJuIHtcbiAgICAgICAgcmVxdWVzdDogZnVuY3Rpb24oY29uZmlnKSB7XG4gICAgICAgICAgdmFyIHRva2VuID0gJGluamVjdG9yLmdldCgnQXV0aCcpLmdldFRva2VuKCk7XG5cbiAgICAgICAgICBpZiAodG9rZW4pIHtcbiAgICAgICAgICAgIGNvbmZpZy5oZWFkZXJzWydBdXRob3JpemF0aW9uJ10gPSAnQmVhcmVyICcgKyB0b2tlbjtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICByZXR1cm4gY29uZmlnO1xuICAgICAgICB9LFxuICAgICAgICByZXNwb25zZTogZnVuY3Rpb24ocmVzcG9uc2UpIHtcbiAgICAgICAgICAvLyBnZXQgYSBuZXcgcmVmcmVzaCB0b2tlbiB0byB1c2UgaW4gdGhlIG5leHQgcmVxdWVzdFxuICAgICAgICAgIHZhciB0b2tlbiA9IHJlc3BvbnNlLmhlYWRlcnMoJ0F1dGhvcml6YXRpb24nKTtcblxuICAgICAgICAgIGlmICh0b2tlbikge1xuICAgICAgICAgICAgJGluamVjdG9yLmdldCgnQXV0aCcpLnNldFRva2VuKHRva2VuLnNwbGl0KCcgJylbMV0pO1xuICAgICAgICAgIH1cbiAgICAgICAgICByZXR1cm4gcmVzcG9uc2U7XG4gICAgICAgIH0sXG4gICAgICAgIHJlc3BvbnNlRXJyb3I6IGZ1bmN0aW9uKHJlamVjdGlvbikge1xuICAgICAgICAgIC8vIEluc3RlYWQgb2YgY2hlY2tpbmcgZm9yIGEgc3RhdHVzIGNvZGUgb2YgNDAwIHdoaWNoIG1pZ2h0IGJlIHVzZWRcbiAgICAgICAgICAvLyBmb3Igb3RoZXIgcmVhc29ucyBpbiBMYXJhdmVsLCB3ZSBjaGVjayBmb3IgdGhlIHNwZWNpZmljIHJlamVjdGlvblxuICAgICAgICAgIC8vIHJlYXNvbnMgdG8gdGVsbCB1cyBpZiB3ZSBuZWVkIHRvIHJlZGlyZWN0IHRvIHRoZSBsb2dpbiBzdGF0ZVxuICAgICAgICAgIHZhciByZWplY3Rpb25SZWFzb25zID0gWyd0b2tlbl9ub3RfcHJvdmlkZWQnLCAndG9rZW5fZXhwaXJlZCcsICd0b2tlbl9hYnNlbnQnLCAndG9rZW5faW52YWxpZCddO1xuXG4gICAgICAgICAgdmFyIHRva2VuRXJyb3IgPSBmYWxzZTtcblxuICAgICAgICAgIGFuZ3VsYXIuZm9yRWFjaChyZWplY3Rpb25SZWFzb25zLCBmdW5jdGlvbih2YWx1ZSkge1xuICAgICAgICAgICAgaWYgKHJlamVjdGlvbi5kYXRhICYmIHJlamVjdGlvbi5kYXRhLmVycm9yID09PSB2YWx1ZSkge1xuICAgICAgICAgICAgICB0b2tlbkVycm9yID0gdHJ1ZTtcblxuICAgICAgICAgICAgICAkaW5qZWN0b3IuZ2V0KCdBdXRoJykubG9nb3V0KCkudGhlbihmdW5jdGlvbigpIHtcbiAgICAgICAgICAgICAgICB2YXIgJHN0YXRlID0gJGluamVjdG9yLmdldCgnJHN0YXRlJyk7XG5cbiAgICAgICAgICAgICAgICAvLyBpbiBjYXNlIG11bHRpcGxlIGFqYXggcmVxdWVzdCBmYWlsIGF0IHNhbWUgdGltZSBiZWNhdXNlIHRva2VuIHByb2JsZW1zLFxuICAgICAgICAgICAgICAgIC8vIG9ubHkgdGhlIGZpcnN0IHdpbGwgcmVkaXJlY3RcbiAgICAgICAgICAgICAgICBpZiAoISRzdGF0ZS5pcyhHbG9iYWwubG9naW5TdGF0ZSkpIHtcbiAgICAgICAgICAgICAgICAgICRzdGF0ZS5nbyhHbG9iYWwubG9naW5TdGF0ZSk7XG5cbiAgICAgICAgICAgICAgICAgIC8vY2xvc2UgYW55IGRpYWxvZyB0aGF0IGlzIG9wZW5lZFxuICAgICAgICAgICAgICAgICAgJGluamVjdG9yLmdldCgnUHJEaWFsb2cnKS5jbG9zZSgpO1xuXG4gICAgICAgICAgICAgICAgICBldmVudC5wcmV2ZW50RGVmYXVsdCgpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfSk7XG5cbiAgICAgICAgICAvL2RlZmluZSBkYXRhIHRvIGVtcHR5IGJlY2F1c2UgYWxyZWFkeSBzaG93IFByVG9hc3QgdG9rZW4gbWVzc2FnZVxuICAgICAgICAgIGlmICh0b2tlbkVycm9yKSB7XG4gICAgICAgICAgICByZWplY3Rpb24uZGF0YSA9IHt9O1xuICAgICAgICAgIH1cblxuICAgICAgICAgIGlmIChhbmd1bGFyLmlzRnVuY3Rpb24ocmVqZWN0aW9uLmhlYWRlcnMpKSB7XG4gICAgICAgICAgICAvLyBtYW55IHNlcnZlcnMgZXJyb3JzIChidXNpbmVzcykgYXJlIGludGVyY2VwdCBoZXJlIGJ1dCBnZW5lcmF0ZWQgYSBuZXcgcmVmcmVzaCB0b2tlblxuICAgICAgICAgICAgLy8gYW5kIG5lZWQgdXBkYXRlIGN1cnJlbnQgdG9rZW5cbiAgICAgICAgICAgIHZhciB0b2tlbiA9IHJlamVjdGlvbi5oZWFkZXJzKCdBdXRob3JpemF0aW9uJyk7XG5cbiAgICAgICAgICAgIGlmICh0b2tlbikge1xuICAgICAgICAgICAgICAkaW5qZWN0b3IuZ2V0KCdBdXRoJykuc2V0VG9rZW4odG9rZW4uc3BsaXQoJyAnKVsxXSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgcmV0dXJuICRxLnJlamVjdChyZWplY3Rpb24pO1xuICAgICAgICB9XG4gICAgICB9O1xuICAgIH1cblxuICAgIC8vIFNldHVwIGZvciB0aGUgJGh0dHBJbnRlcmNlcHRvclxuICAgICRwcm92aWRlLmZhY3RvcnkoJ3JlZGlyZWN0V2hlblNlcnZlckxvZ2dlZE91dCcsIHJlZGlyZWN0V2hlblNlcnZlckxvZ2dlZE91dCk7XG5cbiAgICAvLyBQdXNoIHRoZSBuZXcgZmFjdG9yeSBvbnRvIHRoZSAkaHR0cCBpbnRlcmNlcHRvciBhcnJheVxuICAgICRodHRwUHJvdmlkZXIuaW50ZXJjZXB0b3JzLnB1c2goJ3JlZGlyZWN0V2hlblNlcnZlckxvZ2dlZE91dCcpO1xuICB9XG5cbn0oKSk7XG4iLCIoZnVuY3Rpb24gKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbmZpZyh2YWxpZGF0aW9uSW50ZXJjZXB0b3IpO1xuXG4gIGZ1bmN0aW9uIHZhbGlkYXRpb25JbnRlcmNlcHRvcigkaHR0cFByb3ZpZGVyLCAkcHJvdmlkZSkge1xuICAgIC8qKlxuICAgICAqIEVzdGUgaW50ZXJjZXB0b3Igw6kgcmVzcG9uc8OhdmVsIHBvciBtb3N0cmFyIGFzXG4gICAgICogbWVuc2FnZW5zIGRlIGVycm8gcmVmZXJlbnRlIGFzIHZhbGlkYcOnw7VlcyBkbyBiYWNrLWVuZFxuICAgICAqXG4gICAgICogQHBhcmFtIHthbnl9ICRxXG4gICAgICogQHBhcmFtIHthbnl9ICRpbmplY3RvclxuICAgICAqIEByZXR1cm5zXG4gICAgICovXG4gICAgZnVuY3Rpb24gc2hvd0Vycm9yVmFsaWRhdGlvbigkcSwgJGluamVjdG9yKSB7XG4gICAgICByZXR1cm4ge1xuICAgICAgICByZXNwb25zZUVycm9yOiBmdW5jdGlvbiAocmVqZWN0aW9uKSB7XG4gICAgICAgICAgdmFyIFByVG9hc3QgPSAkaW5qZWN0b3IuZ2V0KCdQclRvYXN0Jyk7XG4gICAgICAgICAgdmFyICR0cmFuc2xhdGUgPSAkaW5qZWN0b3IuZ2V0KCckdHJhbnNsYXRlJyk7XG5cbiAgICAgICAgICBpZiAocmVqZWN0aW9uLmNvbmZpZy5kYXRhICYmICFyZWplY3Rpb24uY29uZmlnLmRhdGEuc2tpcFZhbGlkYXRpb24pIHtcbiAgICAgICAgICAgIGlmIChyZWplY3Rpb24uZGF0YSAmJiByZWplY3Rpb24uZGF0YS5lcnJvcikge1xuXG4gICAgICAgICAgICAgIC8vdmVyaWZpY2Egc2Ugb2NvcnJldSBhbGd1bSBlcnJvIHJlZmVyZW50ZSBhbyB0b2tlblxuICAgICAgICAgICAgICBpZiAocmVqZWN0aW9uLmRhdGEuZXJyb3Iuc3RhcnRzV2l0aCgndG9rZW5fJykpIHtcbiAgICAgICAgICAgICAgICBQclRvYXN0Lndhcm4oJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5sb2dpbi5sb2dvdXRJbmFjdGl2ZScpKTtcbiAgICAgICAgICAgICAgfSBlbHNlIGlmIChyZWplY3Rpb24uZGF0YS5lcnJvciAhPT0gJ05vdCBGb3VuZCcpIHtcbiAgICAgICAgICAgICAgICBQclRvYXN0LmVycm9yKCR0cmFuc2xhdGUuaW5zdGFudChyZWplY3Rpb24uZGF0YS5lcnJvcikpO1xuICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICBQclRvYXN0LmVycm9yVmFsaWRhdGlvbihyZWplY3Rpb24uZGF0YSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgcmV0dXJuICRxLnJlamVjdChyZWplY3Rpb24pO1xuICAgICAgICB9XG4gICAgICB9O1xuICAgIH1cblxuICAgIC8vIERlZmluZSB1bWEgZmFjdG9yeSBwYXJhIG8gJGh0dHBJbnRlcmNlcHRvclxuICAgICRwcm92aWRlLmZhY3RvcnkoJ3Nob3dFcnJvclZhbGlkYXRpb24nLCBzaG93RXJyb3JWYWxpZGF0aW9uKTtcblxuICAgIC8vIEFkaWNpb25hIGEgZmFjdG9yeSBubyBhcnJheSBkZSBpbnRlcmNlcHRvcnMgZG8gJGh0dHBcbiAgICAkaHR0cFByb3ZpZGVyLmludGVyY2VwdG9ycy5wdXNoKCdzaG93RXJyb3JWYWxpZGF0aW9uJyk7XG4gIH1cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb250cm9sbGVyKCdLYW5iYW5Db250cm9sbGVyJywgS2FuYmFuQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBLYW5iYW5Db250cm9sbGVyKCRjb250cm9sbGVyLCBUYXNrc1NlcnZpY2UsIFN0YXR1c1NlcnZpY2UsICRtZERpYWxvZywgJGRvY3VtZW50KSB7XG4gICAgLy9BdHRyaWJ1dGVzIEJsb2NrXG4gICAgdmFyIHZtID0gdGhpcztcbiAgICB2YXIgZmllbGRzID0gW1xuICAgICAgeyBuYW1lOiAnaWQnLCB0eXBlOiAnc3RyaW5nJyB9LFxuICAgICAgeyBuYW1lOiAnc3RhdHVzJywgbWFwOiAnc3RhdGUnLCB0eXBlOiAnc3RyaW5nJyB9LFxuICAgICAgeyBuYW1lOiAndGV4dCcsIG1hcDogJ2xhYmVsJywgdHlwZTogJ3N0cmluZycgfSxcbiAgICAgIHsgbmFtZTogJ3RhZ3MnLCB0eXBlOiAnc3RyaW5nJyB9XG4gICAgXTtcblxuICAgIHZtLm9uQWN0aXZhdGUgPSBmdW5jdGlvbigpIHtcbiAgICAgIHZtLnByb2plY3QgPSBsb2NhbFN0b3JhZ2UuZ2V0SXRlbSgncHJvamVjdCcpO1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0geyBwcm9qZWN0X2lkOiB2bS5wcm9qZWN0IH07XG4gICAgfVxuXG4gICAgdm0uYXBwbHlGaWx0ZXJzID0gZnVuY3Rpb24oZGVmYXVsdFF1ZXJ5RmlsdGVycykge1xuICAgICAgcmV0dXJuIGFuZ3VsYXIuZXh0ZW5kKGRlZmF1bHRRdWVyeUZpbHRlcnMsIHZtLnF1ZXJ5RmlsdGVycyk7XG4gICAgfVxuXG4gICAgdm0uYWZ0ZXJTZWFyY2ggPSBmdW5jdGlvbiAoKSB7XG4gICAgICB2YXIgY29sdW1ucyA9IFtdO1xuICAgICAgdmFyIHRhc2tzID0gW107XG5cbiAgICAgIFN0YXR1c1NlcnZpY2UucXVlcnkoKS50aGVuKGZ1bmN0aW9uKHJlc3BvbnNlKSB7XG4gICAgICAgIHJlc3BvbnNlLmZvckVhY2goZnVuY3Rpb24oc3RhdHVzKSB7XG4gICAgICAgICAgY29sdW1ucy5wdXNoKHsgdGV4dDogc3RhdHVzLm5hbWUsIGRhdGFGaWVsZDogc3RhdHVzLnNsdWcgfSk7XG4gICAgICAgIH0pO1xuXG4gICAgICAgIGlmICh2bS5yZXNvdXJjZXMubGVuZ3RoID4gMCkge1xuICAgICAgICAgIHZtLnJlc291cmNlcy5mb3JFYWNoKGZ1bmN0aW9uKHRhc2spIHtcbiAgICAgICAgICAgIHRhc2tzLnB1c2goe1xuICAgICAgICAgICAgICBpZDogdGFzay5pZCxcbiAgICAgICAgICAgICAgc3RhdGU6IHRhc2suc3RhdHVzLnNsdWcsXG4gICAgICAgICAgICAgIGxhYmVsOiB0YXNrLnRpdGxlLFxuICAgICAgICAgICAgICB0YWdzOiB0YXNrLnR5cGUubmFtZSArICcsICcgKyB0YXNrLnByaW9yaXR5Lm5hbWVcbiAgICAgICAgICAgIH0pXG4gICAgICAgICAgfSk7XG5cbiAgICAgICAgICB2YXIgc291cmNlID0ge1xuICAgICAgICAgICAgbG9jYWxEYXRhOiB0YXNrcyxcbiAgICAgICAgICAgIGRhdGFUeXBlOiAnYXJyYXknLFxuICAgICAgICAgICAgZGF0YUZpZWxkczogZmllbGRzXG4gICAgICAgICAgfTtcbiAgICAgICAgICB2YXIgZGF0YUFkYXB0ZXIgPSBuZXcgJC5qcXguZGF0YUFkYXB0ZXIoc291cmNlKTtcblxuICAgICAgICAgIHZtLnNldHRpbmdzID0ge1xuICAgICAgICAgICAgc291cmNlOiBkYXRhQWRhcHRlcixcbiAgICAgICAgICAgIGNvbHVtbnM6IGNvbHVtbnMsXG4gICAgICAgICAgICB0aGVtZTogJ2xpZ2h0J1xuICAgICAgICAgIH07XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgdm0uc2V0dGluZ3MgPSB7XG4gICAgICAgICAgICBzb3VyY2U6IFt7fV0sXG4gICAgICAgICAgICBjb2x1bW5zOiBjb2x1bW5zLFxuICAgICAgICAgICAgdGhlbWU6ICdsaWdodCdcbiAgICAgICAgICB9O1xuICAgICAgICB9XG4gICAgICAgIHZtLmthbmJhblJlYWR5ID0gdHJ1ZTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIHZtLm9uSXRlbU1vdmVkID0gZnVuY3Rpb24oZXZlbnQpIHtcbiAgICAgIFRhc2tzU2VydmljZS51cGRhdGVUYXNrQnlLYW5iYW4oe1xuICAgICAgICBwcm9qZWN0X2lkOiB2bS5wcm9qZWN0LFxuICAgICAgICBpZDogZXZlbnQuYXJncy5pdGVtSWQsXG4gICAgICAgIG9sZENvbHVtbjogZXZlbnQuYXJncy5vbGRDb2x1bW4sXG4gICAgICAgIG5ld0NvbHVtbjogZXZlbnQuYXJncy5uZXdDb2x1bW4gfSkudGhlbihmdW5jdGlvbigpIHtcblxuICAgICAgICB9KTtcbiAgICB9XG5cbiAgICB2bS5vbkl0ZW1DbGlja2VkID0gZnVuY3Rpb24oZXZlbnQpIHtcbiAgICAgIFRhc2tzU2VydmljZS5xdWVyeSh7IHRhc2tfaWQ6IGV2ZW50LmFyZ3MuaXRlbUlkIH0pLnRoZW4oZnVuY3Rpb24ocmVzcG9uc2UpIHtcbiAgICAgICAgdm0udGFza0luZm8gPSByZXNwb25zZVswXTtcbiAgICAgICAgJG1kRGlhbG9nLnNob3coe1xuICAgICAgICAgIHBhcmVudDogYW5ndWxhci5lbGVtZW50KCRkb2N1bWVudC5ib2R5KSxcbiAgICAgICAgICB0ZW1wbGF0ZVVybDogJ2NsaWVudC9hcHAva2FuYmFuL3Rhc2staW5mby1kaWFsb2cvdGFza0luZm8uaHRtbCcsXG4gICAgICAgICAgY29udHJvbGxlckFzOiAndGFza0luZm9DdHJsJyxcbiAgICAgICAgICBjb250cm9sbGVyOiAnVGFza0luZm9Db250cm9sbGVyJyxcbiAgICAgICAgICBiaW5kVG9Db250cm9sbGVyOiB0cnVlLFxuICAgICAgICAgIGxvY2Fsczoge1xuICAgICAgICAgICAgdGFzazogdm0udGFza0luZm8sXG4gICAgICAgICAgICBjbG9zZTogY2xvc2VcbiAgICAgICAgICB9LFxuICAgICAgICAgIGVzY2FwZVRvQ2xvc2U6IHRydWUsXG4gICAgICAgICAgY2xpY2tPdXRzaWRlVG9DbG9zZTogdHJ1ZVxuICAgICAgICB9KTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGNsb3NlKCkge1xuICAgICAgJG1kRGlhbG9nLmhpZGUoKTtcbiAgICB9XG5cbiAgICAvLyBpbnN0YW50aWF0ZSBiYXNlIGNvbnRyb2xsZXJcbiAgICAkY29udHJvbGxlcignQ1JVRENvbnRyb2xsZXInLCB7IHZtOiB2bSwgbW9kZWxTZXJ2aWNlOiBUYXNrc1NlcnZpY2UsIG9wdGlvbnM6IHsgfSB9KTtcblxuICB9XG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqXG4gICAqIEFycXVpdm8gZGUgY29uZmlndXJhw6fDo28gY29tIGFzIHJvdGFzIGVzcGVjw61maWNhcyBkbyByZWN1cnNvIGthbmJhblxuICAgKlxuICAgKiBAcGFyYW0ge29iamVjdH0gJHN0YXRlUHJvdmlkZXJcbiAgICogQHBhcmFtIHtvYmplY3R9IEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyXG4gICAgICAuc3RhdGUoJ2FwcC5rYW5iYW4nLCB7XG4gICAgICAgIHVybDogJy9rYW5iYW4nLFxuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL2thbmJhbi9rYW5iYW4uaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdLYW5iYW5Db250cm9sbGVyIGFzIGthbmJhbkN0cmwnLFxuICAgICAgICBkYXRhOiB7IH1cbiAgICAgIH0pO1xuICB9XG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZhY3RvcnkoJ0thbmJhblNlcnZpY2UnLCBLYW5iYW5TZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIEthbmJhblNlcnZpY2Uoc2VydmljZUZhY3RvcnkpIHtcbiAgICB2YXIgbW9kZWwgPSBzZXJ2aWNlRmFjdG9yeSgna2FuYmFuJywge1xuICAgICAgYWN0aW9uczogeyB9LFxuICAgICAgaW5zdGFuY2U6IHsgfVxuICAgIH0pO1xuXG4gICAgcmV0dXJuIG1vZGVsO1xuICB9XG5cbn0oKSk7XG4iLCIvKmVzbGludC1lbnYgZXM2Ki9cblxuKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnRyb2xsZXIoJ01lbnVDb250cm9sbGVyJywgTWVudUNvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gTWVudUNvbnRyb2xsZXIoJG1kU2lkZW5hdiwgJHN0YXRlLCAkbWRDb2xvcnMpIHtcbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgLy9CbG9jbyBkZSBkZWNsYXJhY29lcyBkZSBmdW5jb2VzXG4gICAgdm0ub3BlbiA9IG9wZW47XG4gICAgdm0ub3Blbk1lbnVPclJlZGlyZWN0VG9TdGF0ZSA9IG9wZW5NZW51T3JSZWRpcmVjdFRvU3RhdGU7XG5cbiAgICBhY3RpdmF0ZSgpO1xuXG4gICAgZnVuY3Rpb24gYWN0aXZhdGUoKSB7XG4gICAgICB2YXIgbWVudVByZWZpeCA9ICd2aWV3cy5sYXlvdXQubWVudS4nO1xuXG4gICAgICAvLyBBcnJheSBjb250ZW5kbyBvcyBpdGVucyBxdWUgc8OjbyBtb3N0cmFkb3Mgbm8gbWVudSBsYXRlcmFsXG4gICAgICB2bS5pdGVuc01lbnUgPSBbXG4gICAgICAgIHsgc3RhdGU6ICdhcHAucHJvamVjdHMnLCB0aXRsZTogbWVudVByZWZpeCArICdwcm9qZWN0cycsIGljb246ICd3b3JrJywgc3ViSXRlbnM6IFtdIH0sXG4gICAgICAgIHsgc3RhdGU6ICdhcHAuZGFzaGJvYXJkJywgdGl0bGU6IG1lbnVQcmVmaXggKyAnZGFzaGJvYXJkJywgaWNvbjogJ2Rhc2hib2FyZCcsIHN1Ykl0ZW5zOiBbXSB9LFxuICAgICAgICB7IHN0YXRlOiAnYXBwLnRhc2tzJywgdGl0bGU6IG1lbnVQcmVmaXggKyAndGFza3MnLCBpY29uOiAndmlld19saXN0Jywgc3ViSXRlbnM6IFtdIH0sXG4gICAgICAgIHsgc3RhdGU6ICdhcHAubWlsZXN0b25lcycsIHRpdGxlOiBtZW51UHJlZml4ICsgJ21pbGVzdG9uZXMnLCBpY29uOiAndmlld19tb2R1bGUnLCBzdWJJdGVuczogW10gfSxcbiAgICAgICAgeyBzdGF0ZTogJ2FwcC5yZWxlYXNlcycsIHRpdGxlOiBtZW51UHJlZml4ICsgJ3JlbGVhc2VzJywgaWNvbjogJ3N1YnNjcmlwdGlvbnMnLCBzdWJJdGVuczogW10gfSxcbiAgICAgICAgeyBzdGF0ZTogJ2FwcC5rYW5iYW4nLCB0aXRsZTogbWVudVByZWZpeCArICdrYW5iYW4nLCBpY29uOiAndmlld19jb2x1bW4nLCBzdWJJdGVuczogW10gfSxcbiAgICAgICAgeyBzdGF0ZTogJ2FwcC52Y3MnLCB0aXRsZTogbWVudVByZWZpeCArICd2Y3MnLCBpY29uOiAnZ3JvdXBfd29yaycsIHN1Ykl0ZW5zOiBbXSB9XG4gICAgICAgIC8vIENvbG9xdWUgc2V1cyBpdGVucyBkZSBtZW51IGEgcGFydGlyIGRlc3RlIHBvbnRvXG4gICAgICAgIC8qIHtcbiAgICAgICAgICBzdGF0ZTogJyMnLCB0aXRsZTogbWVudVByZWZpeCArICdhZG1pbicsIGljb246ICdzZXR0aW5nc19hcHBsaWNhdGlvbnMnLCBwcm9maWxlczogWydhZG1pbiddLFxuICAgICAgICAgIHN1Ykl0ZW5zOiBbXG4gICAgICAgICAgICB7IHN0YXRlOiAnYXBwLnVzZXInLCB0aXRsZTogbWVudVByZWZpeCArICd1c2VyJywgaWNvbjogJ3Blb3BsZScgfSxcbiAgICAgICAgICAgIHsgc3RhdGU6ICdhcHAubWFpbCcsIHRpdGxlOiBtZW51UHJlZml4ICsgJ21haWwnLCBpY29uOiAnbWFpbCcgfSxcbiAgICAgICAgICAgIHsgc3RhdGU6ICdhcHAuYXVkaXQnLCB0aXRsZTogbWVudVByZWZpeCArICdhdWRpdCcsIGljb246ICdzdG9yYWdlJyB9LFxuICAgICAgICAgICAgeyBzdGF0ZTogJ2FwcC5kaW5hbWljLXF1ZXJ5JywgdGl0bGU6IG1lbnVQcmVmaXggKyAnZGluYW1pY1F1ZXJ5JywgaWNvbjogJ2xvY2F0aW9uX3NlYXJjaGluZycgfVxuICAgICAgICAgIF1cbiAgICAgICAgfSAqL1xuICAgICAgXTtcblxuICAgICAgLyoqXG4gICAgICAgKiBPYmpldG8gcXVlIHByZWVuY2hlIG8gbmctc3R5bGUgZG8gbWVudSBsYXRlcmFsIHRyb2NhbmRvIGFzIGNvcmVzXG4gICAgICAgKi9cbiAgICAgIHZtLnNpZGVuYXZTdHlsZSA9IHtcbiAgICAgICAgdG9wOiB7XG4gICAgICAgICAgJ2JvcmRlci1ib3R0b20nOiAnMXB4IHNvbGlkIHJnYigyMTAsIDIxMCwgMjEwKScsXG4gICAgICAgICAgJ2JhY2tncm91bmQtaW1hZ2UnOiAnLXdlYmtpdC1saW5lYXItZ3JhZGllbnQodG9wLCByZ2IoMTQ0LCAxNDQsIDE0NCksIHJnYigyMTAsIDIxMCwgMjEwKSknXG4gICAgICAgIH0sXG4gICAgICAgIGNvbnRlbnQ6IHtcbiAgICAgICAgICAnYmFja2dyb3VuZC1jb2xvcic6ICdyZ2IoMjEwLCAyMTAsIDIxMCknXG4gICAgICAgIH0sXG4gICAgICAgIHRleHRDb2xvcjoge1xuICAgICAgICAgIGNvbG9yOiAnI0ZGRidcbiAgICAgICAgfSxcbiAgICAgICAgbGluZUJvdHRvbToge1xuICAgICAgICAgICdib3JkZXItYm90dG9tJzogJzFweCBzb2xpZCAnICsgZ2V0Q29sb3IoJ3ByaW1hcnktNDAwJylcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH1cblxuICAgIGZ1bmN0aW9uIG9wZW4oKSB7XG4gICAgICAkbWRTaWRlbmF2KCdsZWZ0JykudG9nZ2xlKCk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogTcOpdG9kbyBxdWUgZXhpYmUgbyBzdWIgbWVudSBkb3MgaXRlbnMgZG8gbWVudSBsYXRlcmFsIGNhc28gdGVuaGEgc3ViIGl0ZW5zXG4gICAgICogY2FzbyBjb250csOhcmlvIHJlZGlyZWNpb25hIHBhcmEgbyBzdGF0ZSBwYXNzYWRvIGNvbW8gcGFyw4PCom1ldHJvXG4gICAgICovXG4gICAgZnVuY3Rpb24gb3Blbk1lbnVPclJlZGlyZWN0VG9TdGF0ZSgkbWRNZW51LCBldiwgaXRlbSkge1xuICAgICAgaWYgKGFuZ3VsYXIuaXNEZWZpbmVkKGl0ZW0uc3ViSXRlbnMpICYmIGl0ZW0uc3ViSXRlbnMubGVuZ3RoID4gMCkge1xuICAgICAgICAkbWRNZW51Lm9wZW4oZXYpO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgJHN0YXRlLmdvKGl0ZW0uc3RhdGUsIHsgb2JqOiBudWxsIH0pO1xuICAgICAgICAkbWRTaWRlbmF2KCdsZWZ0JykuY2xvc2UoKTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICBmdW5jdGlvbiBnZXRDb2xvcihjb2xvclBhbGV0dGVzKSB7XG4gICAgICByZXR1cm4gJG1kQ29sb3JzLmdldFRoZW1lQ29sb3IoY29sb3JQYWxldHRlcyk7XG4gICAgfVxuXG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnRyb2xsZXIoJ01haWxzQ29udHJvbGxlcicsIE1haWxzQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBNYWlsc0NvbnRyb2xsZXIoTWFpbHNTZXJ2aWNlLCBVc2Vyc1NlcnZpY2UsIFByRGlhbG9nLCBQclRvYXN0LCAvLyBOT1NPTkFSXG4gICAgJHEsIGxvZGFzaCwgJHRyYW5zbGF0ZSwgR2xvYmFsKSB7XG5cbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0uZmlsdGVyU2VsZWN0ZWQgPSBmYWxzZTtcbiAgICB2bS5vcHRpb25zID0ge1xuICAgICAgc2tpbjogJ2thbWEnLFxuICAgICAgbGFuZ3VhZ2U6ICdwdC1icicsXG4gICAgICBhbGxvd2VkQ29udGVudDogdHJ1ZSxcbiAgICAgIGVudGl0aWVzOiB0cnVlLFxuICAgICAgaGVpZ2h0OiAzMDAsXG4gICAgICBleHRyYVBsdWdpbnM6ICdkaWFsb2csZmluZCxjb2xvcmRpYWxvZyxwcmV2aWV3LGZvcm1zLGlmcmFtZSxmbGFzaCdcbiAgICB9O1xuXG4gICAgdm0ubG9hZFVzZXJzID0gbG9hZFVzZXJzO1xuICAgIHZtLm9wZW5Vc2VyRGlhbG9nID0gb3BlblVzZXJEaWFsb2c7XG4gICAgdm0uYWRkVXNlck1haWwgPSBhZGRVc2VyTWFpbDtcbiAgICB2bS5jbGVhbkZvcm0gPSBjbGVhbkZvcm07XG4gICAgdm0uc2VuZCA9IHNlbmQ7XG5cbiAgICBhY3RpdmF0ZSgpO1xuXG4gICAgZnVuY3Rpb24gYWN0aXZhdGUoKSB7XG4gICAgICB2bS5jbGVhbkZvcm0oKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFsaXphIGEgYnVzY2EgcGVsbyB1c3XDoXJpbyByZW1vdGFtZW50ZVxuICAgICAqXG4gICAgICogQHBhcmFtcyB7c3RyaW5nfSAtIFJlY2ViZSBvIHZhbG9yIHBhcmEgc2VyIHBlc3F1aXNhZG9cbiAgICAgKiBAcmV0dXJuIHtwcm9taXNzZX0gLSBSZXRvcm5hIHVtYSBwcm9taXNzZSBxdWUgbyBjb21wb25ldGUgcmVzb2x2ZVxuICAgICAqL1xuICAgIGZ1bmN0aW9uIGxvYWRVc2Vycyhjcml0ZXJpYSkge1xuICAgICAgdmFyIGRlZmVycmVkID0gJHEuZGVmZXIoKTtcblxuICAgICAgVXNlcnNTZXJ2aWNlLnF1ZXJ5KHtcbiAgICAgICAgbmFtZU9yRW1haWw6IGNyaXRlcmlhLFxuICAgICAgICBub3RVc2VyczogbG9kYXNoLm1hcCh2bS5tYWlsLnVzZXJzLCBsb2Rhc2gucHJvcGVydHkoJ2lkJykpLnRvU3RyaW5nKCksXG4gICAgICAgIGxpbWl0OiA1XG4gICAgICB9KS50aGVuKGZ1bmN0aW9uKGRhdGEpIHtcblxuICAgICAgICAvLyB2ZXJpZmljYSBzZSBuYSBsaXN0YSBkZSB1c3VhcmlvcyBqw6EgZXhpc3RlIG8gdXN1w6FyaW8gY29tIG8gZW1haWwgcGVzcXVpc2Fkb1xuICAgICAgICBkYXRhID0gbG9kYXNoLmZpbHRlcihkYXRhLCBmdW5jdGlvbih1c2VyKSB7XG4gICAgICAgICAgcmV0dXJuICFsb2Rhc2guZmluZCh2bS5tYWlsLnVzZXJzLCB7IGVtYWlsOiB1c2VyLmVtYWlsIH0pO1xuICAgICAgICB9KTtcblxuICAgICAgICBkZWZlcnJlZC5yZXNvbHZlKGRhdGEpO1xuICAgICAgfSk7XG5cbiAgICAgIHJldHVybiBkZWZlcnJlZC5wcm9taXNlO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEFicmUgbyBkaWFsb2cgcGFyYSBwZXNxdWlzYSBkZSB1c3XDoXJpb3NcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBvcGVuVXNlckRpYWxvZygpIHtcbiAgICAgIHZhciBjb25maWcgPSB7XG4gICAgICAgIGxvY2Fsczoge1xuICAgICAgICAgIG9uSW5pdDogdHJ1ZSxcbiAgICAgICAgICB1c2VyRGlhbG9nSW5wdXQ6IHtcbiAgICAgICAgICAgIHRyYW5zZmVyVXNlckZuOiB2bS5hZGRVc2VyTWFpbFxuICAgICAgICAgIH1cbiAgICAgICAgfSxcbiAgICAgICAgY29udHJvbGxlcjogJ1VzZXJzRGlhbG9nQ29udHJvbGxlcicsXG4gICAgICAgIGNvbnRyb2xsZXJBczogJ2N0cmwnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL3VzZXJzL2RpYWxvZy91c2Vycy1kaWFsb2cuaHRtbCcsXG4gICAgICAgIGhhc0JhY2tkcm9wOiB0cnVlXG4gICAgICB9O1xuXG4gICAgICBQckRpYWxvZy5jdXN0b20oY29uZmlnKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBBZGljaW9uYSBvIHVzdcOhcmlvIHNlbGVjaW9uYWRvIG5hIGxpc3RhIHBhcmEgcXVlIHNlamEgZW52aWFkbyBvIGVtYWlsXG4gICAgICovXG4gICAgZnVuY3Rpb24gYWRkVXNlck1haWwodXNlcikge1xuICAgICAgdmFyIHVzZXJzID0gbG9kYXNoLmZpbmQodm0ubWFpbC51c2VycywgeyBlbWFpbDogdXNlci5lbWFpbCB9KTtcblxuICAgICAgaWYgKHZtLm1haWwudXNlcnMubGVuZ3RoID4gMCAmJiBhbmd1bGFyLmlzRGVmaW5lZCh1c2VycykpIHtcbiAgICAgICAgUHJUb2FzdC53YXJuKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMudXNlci51c2VyRXhpc3RzJykpO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgdm0ubWFpbC51c2Vycy5wdXNoKHsgbmFtZTogdXNlci5uYW1lLCBlbWFpbDogdXNlci5lbWFpbCB9KVxuICAgICAgfVxuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWxpemEgbyBlbnZpbyBkbyBlbWFpbCBwYXJhIGEgbGlzdGEgZGUgdXN1w6FyaW9zIHNlbGVjaW9uYWRvc1xuICAgICAqL1xuICAgIGZ1bmN0aW9uIHNlbmQoKSB7XG5cbiAgICAgIHZtLm1haWwuJHNhdmUoKS50aGVuKGZ1bmN0aW9uKHJlc3BvbnNlKSB7XG4gICAgICAgIGlmIChyZXNwb25zZS5sZW5ndGggPiAwKSB7XG4gICAgICAgICAgdmFyIG1zZyA9ICR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMubWFpbC5tYWlsRXJyb3JzJyk7XG5cbiAgICAgICAgICBmb3IgKHZhciBpPTA7IGkgPCByZXNwb25zZS5sZW5ndGg7IGkrKykge1xuICAgICAgICAgICAgbXNnICs9IHJlc3BvbnNlICsgJ1xcbic7XG4gICAgICAgICAgfVxuICAgICAgICAgIFByVG9hc3QuZXJyb3IobXNnKTtcbiAgICAgICAgICB2bS5jbGVhbkZvcm0oKTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICBQclRvYXN0LnN1Y2Nlc3MoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5tYWlsLnNlbmRNYWlsU3VjY2VzcycpKTtcbiAgICAgICAgICB2bS5jbGVhbkZvcm0oKTtcbiAgICAgICAgfVxuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogTGltcGEgbyBmb3JtdWzDoXJpbyBkZSBlbWFpbFxuICAgICAqL1xuICAgIGZ1bmN0aW9uIGNsZWFuRm9ybSgpIHtcbiAgICAgIHZtLm1haWwgPSBuZXcgTWFpbHNTZXJ2aWNlKCk7XG4gICAgICB2bS5tYWlsLnVzZXJzID0gW107XG4gICAgfVxuXG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb25maWcocm91dGVzKTtcblxuICAvKipcbiAgICogQXJxdWl2byBkZSBjb25maWd1cmHDp8OjbyBjb20gYXMgcm90YXMgZXNwZWPDrWZpY2FzIGRvIHJlY3Vyc28gZW0gcXVlc3TDo29cbiAgICpcbiAgICogQHBhcmFtIHthbnl9ICRzdGF0ZVByb3ZpZGVyXG4gICAqIEBwYXJhbSB7YW55fSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlclxuICAgICAgLnN0YXRlKCdhcHAubWFpbCcsIHtcbiAgICAgICAgdXJsOiAnL2VtYWlsJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9tYWlsL21haWxzLXNlbmQuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdNYWlsc0NvbnRyb2xsZXIgYXMgbWFpbHNDdHJsJyxcbiAgICAgICAgZGF0YTogeyBuZWVkQXV0aGVudGljYXRpb246IHRydWUsIG5lZWRQcm9maWxlOiBbJ2FkbWluJ10gfVxuICAgICAgfSk7XG5cbiAgfVxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5mYWN0b3J5KCdNYWlsc1NlcnZpY2UnLCBNYWlsc1NlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gTWFpbHNTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCdtYWlscycsIHt9KTtcbiAgfVxuXG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29udHJvbGxlcignTWlsZXN0b25lc0NvbnRyb2xsZXInLCBNaWxlc3RvbmVzQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBNaWxlc3RvbmVzQ29udHJvbGxlcigkY29udHJvbGxlcixcbiAgICBNaWxlc3RvbmVzU2VydmljZSxcbiAgICBtb21lbnQsXG4gICAgVGFza3NTZXJ2aWNlLFxuICAgIFByVG9hc3QsXG4gICAgJHRyYW5zbGF0ZSxcbiAgICAkbWREaWFsb2cpIHtcblxuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICB2bS5lc3RpbWF0ZWRQcmljZSA9IGVzdGltYXRlZFByaWNlO1xuXG4gICAgdm0ub25BY3RpdmF0ZSA9IGZ1bmN0aW9uKCkge1xuICAgICAgdm0ucHJvamVjdCA9IGxvY2FsU3RvcmFnZS5nZXRJdGVtKCdwcm9qZWN0Jyk7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMgPSB7IHByb2plY3RfaWQ6IHZtLnByb2plY3QgfTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBlc3RpbWF0ZWRQcmljZShtaWxlc3RvbmUpIHtcbiAgICAgIG1pbGVzdG9uZS5lc3RpbWF0ZWRfdmFsdWUgPSAwO1xuICAgICAgaWYobWlsZXN0b25lLnRhc2tzLmxlbmd0aCA+IDAgJiYgbWlsZXN0b25lLnByb2plY3QuaG91cl92YWx1ZV9maW5hbCkge1xuICAgICAgICBtaWxlc3RvbmUudGFza3MuZm9yRWFjaChmdW5jdGlvbih0YXNrKSB7XG4gICAgICAgICAgbWlsZXN0b25lLmVzdGltYXRlZF92YWx1ZSArPSAocGFyc2VGbG9hdChtaWxlc3RvbmUucHJvamVjdC5ob3VyX3ZhbHVlX2ZpbmFsKSAqIHRhc2suZXN0aW1hdGVkX3RpbWUpO1xuICAgICAgICB9KTtcbiAgICAgIH1cbiAgICAgIHJldHVybiBtaWxlc3RvbmUuZXN0aW1hdGVkX3ZhbHVlLnRvTG9jYWxlU3RyaW5nKCdQdC1icicsIHsgbWluaW11bUZyYWN0aW9uRGlnaXRzOiAyIH0pO1xuICAgIH1cblxuICAgIHZtLmVzdGltYXRlZFRpbWUgPSBmdW5jdGlvbiAobWlsZXN0b25lKSB7XG4gICAgICBtaWxlc3RvbmUuZXN0aW1hdGVkX3RpbWUgPSAwO1xuICAgICAgaWYobWlsZXN0b25lLnRhc2tzLmxlbmd0aCA+IDApIHtcbiAgICAgICAgbWlsZXN0b25lLnRhc2tzLmZvckVhY2goZnVuY3Rpb24odGFzaykge1xuICAgICAgICAgIG1pbGVzdG9uZS5lc3RpbWF0ZWRfdGltZSArPSB0YXNrLmVzdGltYXRlZF90aW1lO1xuICAgICAgICB9KTtcbiAgICAgIH1cbiAgICAgIG1pbGVzdG9uZS5lc3RpbWF0ZWRfdGltZSA9IG1pbGVzdG9uZS5lc3RpbWF0ZWRfdGltZSAvIDg7XG4gICAgICB2YXIgZGF0ZUVuZCA9IG1vbWVudChtaWxlc3RvbmUuZGF0ZV9lbmQpO1xuICAgICAgdmFyIGRhdGVCZWdpbiA9IG1vbWVudChtaWxlc3RvbmUuZGF0ZV9iZWdpbik7XG5cbiAgICAgIGlmIChkYXRlRW5kLmRpZmYoZGF0ZUJlZ2luLCAnZGF5cycpIDw9IG1pbGVzdG9uZS5lc3RpbWF0ZWRfdGltZSkge1xuICAgICAgICBtaWxlc3RvbmUuY29sb3JfZXN0aW1hdGVkX3RpbWUgPSB7IGNvbG9yOiAncmVkJyB9O1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgbWlsZXN0b25lLmNvbG9yX2VzdGltYXRlZF90aW1lID0geyBjb2xvcjogJ2dyZWVuJyB9O1xuICAgICAgfVxuICAgICAgcmV0dXJuIG1pbGVzdG9uZS5lc3RpbWF0ZWRfdGltZTtcbiAgICB9XG5cbiAgICB2bS5hcHBseUZpbHRlcnMgPSBmdW5jdGlvbihkZWZhdWx0UXVlcnlGaWx0ZXJzKSB7XG4gICAgICByZXR1cm4gYW5ndWxhci5leHRlbmQoZGVmYXVsdFF1ZXJ5RmlsdGVycywgdm0ucXVlcnlGaWx0ZXJzKTtcbiAgICB9XG5cbiAgICB2bS5iZWZvcmVTYXZlID0gZnVuY3Rpb24oKSB7XG4gICAgICB2bS5yZXNvdXJjZS5wcm9qZWN0X2lkID0gdm0ucHJvamVjdDtcbiAgICB9XG5cbiAgICB2bS5iZWZvcmVSZW1vdmUgPSBmdW5jdGlvbigpIHtcbiAgICAgIHZtLnJlc291cmNlLnByb2plY3RfaWQgPSB2bS5wcm9qZWN0O1xuICAgIH1cblxuICAgIHZtLmZvcm1hdERhdGUgPSBmdW5jdGlvbihkYXRlKSB7XG4gICAgICByZXR1cm4gbW9tZW50KGRhdGUpLmZvcm1hdCgnREQvTU0vWVlZWScpO1xuICAgIH1cblxuICAgIHZtLmFmdGVyRWRpdCA9IGZ1bmN0aW9uKCkge1xuICAgICAgdm0ucmVzb3VyY2UuZGF0ZV9iZWdpbiA9IG1vbWVudCh2bS5yZXNvdXJjZS5kYXRlX2JlZ2luKTtcbiAgICAgIHZtLnJlc291cmNlLmRhdGVfZW5kID0gbW9tZW50KHZtLnJlc291cmNlLmRhdGVfZW5kKTtcbiAgICB9XG5cbiAgICB2bS52aWV3ID0gZnVuY3Rpb24gKHJlc291cmNlKSB7XG4gICAgICB2bS5yZXNvdXJjZSA9IHJlc291cmNlO1xuICAgICAgdm0ub25WaWV3ID0gdHJ1ZTtcbiAgICAgIHZtLnZpZXdGb3JtID0gZmFsc2U7XG4gICAgICBjb25zb2xlLmxvZyhyZXNvdXJjZS5wcm9qZWN0KTtcbiAgICB9XG5cbiAgICB2bS5zZWFyY2hUYXNrID0gZnVuY3Rpb24gKHRhc2tUZXJtKSB7XG4gICAgICByZXR1cm4gVGFza3NTZXJ2aWNlLnF1ZXJ5KHtcbiAgICAgICAgbWlsZXN0b25lU2VhcmNoOiB0cnVlLFxuICAgICAgICBwcm9qZWN0X2lkOiB2bS5yZXNvdXJjZS5wcm9qZWN0X2lkLFxuICAgICAgICB0aXRsZTogdGFza1Rlcm1cbiAgICAgIH0pO1xuICAgIH1cblxuICAgIHZtLm9uVGFza0NoYW5nZSA9IGZ1bmN0aW9uKCkge1xuICAgICAgaWYgKHZtLnRhc2sgIT09IG51bGwgJiYgdm0ucmVzb3VyY2UudGFza3MuZmluZEluZGV4KGkgPT4gaS5pZCA9PT0gdm0udGFzay5pZCkgPT09IC0xKSB7XG4gICAgICAgIHZtLnJlc291cmNlLnRhc2tzLnB1c2godm0udGFzayk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgdm0ucmVtb3ZlVGFzayA9IGZ1bmN0aW9uKHRhc2spIHtcbiAgICAgIHZtLnJlc291cmNlLnRhc2tzLnNsaWNlKDApLmZvckVhY2goZnVuY3Rpb24oZWxlbWVudCkge1xuICAgICAgICBpZihlbGVtZW50LmlkID09PSB0YXNrLmlkKSB7XG4gICAgICAgICAgdm0ucmVzb3VyY2UudGFza3Muc3BsaWNlKHZtLnJlc291cmNlLnRhc2tzLmluZGV4T2YoZWxlbWVudCksIDEpO1xuICAgICAgICB9XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICB2bS5zYXZlVGFza3MgPSBmdW5jdGlvbigpIHtcbiAgICAgIFRhc2tzU2VydmljZS51cGRhdGVNaWxlc3RvbmUoe3Byb2plY3RfaWQ6IHZtLnJlc291cmNlLnByb2plY3RfaWQsIG1pbGVzdG9uZV9pZDogdm0ucmVzb3VyY2UuaWQsIHRhc2tzOiB2bS5yZXNvdXJjZS50YXNrc30pLnRoZW4oZnVuY3Rpb24oKXtcbiAgICAgICAgUHJUb2FzdC5zdWNjZXNzKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMuc2F2ZVN1Y2Nlc3MnKSk7XG4gICAgICAgIHZtLnZpZXdGb3JtID0gZmFsc2U7XG4gICAgICAgIHZtLm9uVmlldyA9IGZhbHNlO1xuICAgICAgfSwgZnVuY3Rpb24oKSB7XG4gICAgICAgIFByVG9hc3QuZXJyb3IoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5vcGVyYXRpb25FcnJvcicpKTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIHZtLmZpbmFsaXplID0gZnVuY3Rpb24obWlsZXN0b25lKSB7XG4gICAgICB2YXIgY29uZmlybSA9ICRtZERpYWxvZy5jb25maXJtKClcbiAgICAgICAgICAudGl0bGUoJ0ZpbmFsaXphciBTcHJpbnQnKVxuICAgICAgICAgIC50ZXh0Q29udGVudCgnVGVtIGNlcnRlemEgcXVlIGRlc2VqYSBmaW5hbGl6YXIgYSBzcHJpbnQgJyArIG1pbGVzdG9uZS50aXRsZSArICc/JylcbiAgICAgICAgICAub2soJ1NpbScpXG4gICAgICAgICAgLmNhbmNlbCgnTsOjbycpO1xuXG4gICAgICAkbWREaWFsb2cuc2hvdyhjb25maXJtKS50aGVuKGZ1bmN0aW9uKCkge1xuICAgICAgICBNaWxlc3RvbmVzU2VydmljZS5maW5hbGl6ZSh7IHByb2plY3RfaWQ6IHZtLnByb2plY3QsIG1pbGVzdG9uZV9pZDogbWlsZXN0b25lLmlkIH0pLnRoZW4oZnVuY3Rpb24oKSB7XG4gICAgICAgICAgUHJUb2FzdC5zdWNjZXNzKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMuc3ByaW50RW5kZWRTdWNjZXNzJykpO1xuICAgICAgICAgIHZtLnNlYXJjaCgpO1xuICAgICAgICB9LCBmdW5jdGlvbigpIHtcbiAgICAgICAgICBQclRvYXN0LkVycm9yKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMuc3ByaW50RW5kZWRFcnJvcicpKTtcbiAgICAgICAgfSk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICAvLyBpbnN0YW50aWF0ZSBiYXNlIGNvbnRyb2xsZXJcbiAgICAkY29udHJvbGxlcignQ1JVRENvbnRyb2xsZXInLCB7IHZtOiB2bSwgbW9kZWxTZXJ2aWNlOiBNaWxlc3RvbmVzU2VydmljZSwgb3B0aW9uczogeyB9IH0pO1xuXG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb25maWcocm91dGVzKTtcblxuICAvKipcbiAgICogQXJxdWl2byBkZSBjb25maWd1cmHDp8OjbyBjb20gYXMgcm90YXMgZXNwZWPDrWZpY2FzIGRvIHJlY3Vyc28gbWlsZXN0b25lc1xuICAgKlxuICAgKiBAcGFyYW0ge29iamVjdH0gJHN0YXRlUHJvdmlkZXJcbiAgICogQHBhcmFtIHtvYmplY3R9IEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyXG4gICAgICAuc3RhdGUoJ2FwcC5taWxlc3RvbmVzJywge1xuICAgICAgICB1cmw6ICcvbWlsZXN0b25lcycsXG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvbWlsZXN0b25lcy9taWxlc3RvbmVzLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnTWlsZXN0b25lc0NvbnRyb2xsZXIgYXMgbWlsZXN0b25lc0N0cmwnLFxuICAgICAgICBkYXRhOiB7IH1cbiAgICAgIH0pO1xuICB9XG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZhY3RvcnkoJ01pbGVzdG9uZXNTZXJ2aWNlJywgTWlsZXN0b25lc1NlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gTWlsZXN0b25lc1NlcnZpY2Uoc2VydmljZUZhY3RvcnkpIHtcbiAgICB2YXIgbW9kZWwgPSBzZXJ2aWNlRmFjdG9yeSgnbWlsZXN0b25lcycsIHtcbiAgICAgIGFjdGlvbnM6IHtcbiAgICAgICAgZmluYWxpemU6IHtcbiAgICAgICAgICBtZXRob2Q6ICdQT1NUJyxcbiAgICAgICAgICB1cmw6ICdmaW5hbGl6ZSdcbiAgICAgICAgfSxcbiAgICAgICAgdXBkYXRlUmVsZWFzZToge1xuICAgICAgICAgIG1ldGhvZDogJ1BPU1QnLFxuICAgICAgICAgIHVybDogJ3VwZGF0ZVJlbGVhc2UnXG4gICAgICAgIH1cbiAgICAgIH0sXG4gICAgICBpbnN0YW5jZTogeyB9XG4gICAgfSk7XG5cbiAgICByZXR1cm4gbW9kZWw7XG4gIH1cblxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5mYWN0b3J5KCdQcmlvcml0aWVzU2VydmljZScsIFByaW9yaXRpZXNTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIFByaW9yaXRpZXNTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgdmFyIG1vZGVsID0gc2VydmljZUZhY3RvcnkoJ3ByaW9yaXRpZXMnLCB7XG4gICAgICBhY3Rpb25zOiB7IH0sXG4gICAgICBpbnN0YW5jZTogeyB9XG4gICAgfSk7XG5cbiAgICByZXR1cm4gbW9kZWw7XG4gIH1cblxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnRyb2xsZXIoJ1Byb2plY3RzQ29udHJvbGxlcicsIFByb2plY3RzQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBQcm9qZWN0c0NvbnRyb2xsZXIoJGNvbnRyb2xsZXIsXG4gICAgUHJvamVjdHNTZXJ2aWNlLFxuICAgIEF1dGgsXG4gICAgUm9sZXNTZXJ2aWNlLFxuICAgIFVzZXJzU2VydmljZSxcbiAgICAkc3RhdGUsXG4gICAgJGZpbHRlcixcbiAgICAkc3RhdGVQYXJhbXMsXG4gICAgJHdpbmRvdykge1xuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICAvL0F0dHJpYnV0ZXMgQmxvY2tcblxuICAgIC8vRnVuY3Rpb25zIEJsb2NrXG4gICAgdm0ub25BY3RpdmF0ZSA9IG9uQWN0aXZhdGU7XG4gICAgdm0uYXBwbHlGaWx0ZXJzID0gYXBwbHlGaWx0ZXJzO1xuICAgIHZtLmJlZm9yZVNhdmUgPSBiZWZvcmVTYXZlO1xuICAgIHZtLnNlYXJjaFVzZXIgPSBzZWFyY2hVc2VyO1xuICAgIHZtLmFkZFVzZXIgPSBhZGRVc2VyO1xuICAgIHZtLnJlbW92ZVVzZXIgPSByZW1vdmVVc2VyO1xuICAgIHZtLnZpZXdQcm9qZWN0ID0gdmlld1Byb2plY3Q7XG5cbiAgICB2bS5yb2xlcyA9IHt9O1xuICAgIHZtLnVzZXJzID0gW107XG5cbiAgICBmdW5jdGlvbiBvbkFjdGl2YXRlKCkge1xuICAgICAgUm9sZXNTZXJ2aWNlLnF1ZXJ5KCkudGhlbihmdW5jdGlvbihyZXNwb25zZSkge1xuICAgICAgICB2bS5yb2xlcyA9IHJlc3BvbnNlO1xuICAgICAgICBpZiAoJHN0YXRlUGFyYW1zLm9iaiA9PT0gJ2VkaXQnKSB7XG4gICAgICAgICAgdm0uY2xlYW5Gb3JtKCk7XG4gICAgICAgICAgdm0udmlld0Zvcm0gPSB0cnVlO1xuICAgICAgICAgIHZtLnJlc291cmNlID0gJHN0YXRlUGFyYW1zLnJlc291cmNlO1xuICAgICAgICAgIHVzZXJzQXJyYXkodm0ucmVzb3VyY2UpO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKCdwcm9qZWN0Jyk7XG4gICAgICAgICAgdm0ucXVlcnlGaWx0ZXJzID0geyB1c2VyX2lkOiBBdXRoLmN1cnJlbnRVc2VyLmlkIH07XG4gICAgICAgIH1cbiAgICAgIH0pO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGFwcGx5RmlsdGVycyhkZWZhdWx0UXVlcnlGaWx0ZXJzKSB7XG4gICAgICByZXR1cm4gYW5ndWxhci5leHRlbmQoZGVmYXVsdFF1ZXJ5RmlsdGVycywgdm0ucXVlcnlsdGVycyk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gYmVmb3JlU2F2ZSgpIHtcbiAgICAgIHZtLnJlc291cmNlLm93bmVyID0gQXV0aC5jdXJyZW50VXNlci5pZDtcbiAgICAgIHZtLnJlc291cmNlLnVzZXJfaWQgPSBBdXRoLmN1cnJlbnRVc2VyLmlkO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIHNlYXJjaFVzZXIoKSB7XG4gICAgICByZXR1cm4gVXNlcnNTZXJ2aWNlLnF1ZXJ5KHsgbmFtZTogdm0udXNlck5hbWUgfSk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gYWRkVXNlcih1c2VyKSB7XG4gICAgICBpZiAodXNlcikge1xuICAgICAgICB2bS5yZXNvdXJjZS51c2Vycy5wdXNoKHVzZXIpO1xuICAgICAgICB2bS51c2VyTmFtZSA9ICcnO1xuICAgICAgfVxuICAgIH1cblxuICAgIGZ1bmN0aW9uIHJlbW92ZVVzZXIoaW5kZXgpIHtcbiAgICAgIHZtLnJlc291cmNlLnVzZXJzLnNwbGljZShpbmRleCwgMSk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gYXBwbHlGaWx0ZXJzKGRlZmF1bHRRdWVyeUZpbHRlcnMpIHtcbiAgICAgIHJldHVybiBhbmd1bGFyLmV4dGVuZChkZWZhdWx0UXVlcnlGaWx0ZXJzLCB2bS5xdWVyeUZpbHRlcnMpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIHZpZXdQcm9qZWN0KCkge1xuICAgICAgJHN0YXRlLmdvKCdhcHAuZGFzaGJvYXJkJyk7XG4gICAgfVxuXG4gICAgdm0uYWZ0ZXJTZWFyY2ggPSBmdW5jdGlvbigpIHtcbiAgICAgIGlmICh2bS5yZXNvdXJjZXMubGVuZ3RoID4gMCkge1xuICAgICAgICB2bS5yZXNvdXJjZXMuZm9yRWFjaChmdW5jdGlvbihwcm9qZWN0KSB7XG4gICAgICAgICAgdXNlcnNBcnJheShwcm9qZWN0KTtcbiAgICAgICAgfSk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gdXNlcnNBcnJheShwcm9qZWN0KSB7XG4gICAgICBwcm9qZWN0LnVzZXJzID0gW107XG4gICAgICBpZiAocHJvamVjdC5jbGllbnRfaWQpIHtcbiAgICAgICAgcHJvamVjdC5jbGllbnQucm9sZSA9ICRmaWx0ZXIoJ2ZpbHRlcicpKHZtLnJvbGVzLCB7IHNsdWc6ICdjbGllbnQnIH0pWzBdO1xuICAgICAgICBwcm9qZWN0LnVzZXJzLnB1c2gocHJvamVjdC5jbGllbnQpO1xuICAgICAgfVxuICAgICAgaWYgKHByb2plY3QuZGV2X2lkKSB7XG4gICAgICAgIHByb2plY3QuZGV2ZWxvcGVyLnJvbGUgPSAkZmlsdGVyKCdmaWx0ZXInKSh2bS5yb2xlcywgeyBzbHVnOiAnZGV2JyB9KVswXTtcbiAgICAgICAgcHJvamVjdC51c2Vycy5wdXNoKHByb2plY3QuZGV2ZWxvcGVyKTtcbiAgICAgIH1cbiAgICAgIGlmIChwcm9qZWN0LnN0YWtlaG9sZGVyX2lkKSB7XG4gICAgICAgIHByb2plY3Quc3Rha2Vob2xkZXIucm9sZSA9ICRmaWx0ZXIoJ2ZpbHRlcicpKHZtLnJvbGVzLCB7IHNsdWc6ICdzdGFrZWhvbGRlcicgfSlbMF07XG4gICAgICAgIHByb2plY3QudXNlcnMucHVzaChwcm9qZWN0LnN0YWtlaG9sZGVyKTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICB2bS5oaXN0b3J5QmFjayA9IGZ1bmN0aW9uKCkge1xuICAgICAgJHdpbmRvdy5oaXN0b3J5LmJhY2soKTtcbiAgICB9XG5cbiAgICB2bS5hZnRlclNhdmUgPSBmdW5jdGlvbihyZXNvdXJjZSkge1xuICAgICAgbG9jYWxTdG9yYWdlLnNldEl0ZW0oJ3Byb2plY3QnLCByZXNvdXJjZS5pZCk7XG4gICAgICAkc3RhdGUuZ28oJ2FwcC5kYXNoYm9hcmQnKTtcbiAgICB9XG5cbiAgICAvLyBpbnN0YW50aWF0ZSBiYXNlIGNvbnRyb2xsZXJcbiAgICAkY29udHJvbGxlcignQ1JVRENvbnRyb2xsZXInLCB7IHZtOiB2bSwgbW9kZWxTZXJ2aWNlOiBQcm9qZWN0c1NlcnZpY2UsIG9wdGlvbnM6IHsgcmVkaXJlY3RBZnRlclNhdmU6IGZhbHNlIH0gfSk7XG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb25maWcocm91dGVzKTtcblxuICAvKipcbiAgICogQXJxdWl2byBkZSBjb25maWd1cmHDp8OjbyBjb20gYXMgcm90YXMgZXNwZWPDrWZpY2FzIGRvIHJlY3Vyc28gcHJvamVjdFxuICAgKlxuICAgKiBAcGFyYW0ge2FueX0gJHN0YXRlUHJvdmlkZXJcbiAgICogQHBhcmFtIHthbnl9IEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyXG4gICAgICAuc3RhdGUoJ2FwcC5wcm9qZWN0cycsIHtcbiAgICAgICAgdXJsOiAnL3Byb2plY3RzJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy9wcm9qZWN0cy9wcm9qZWN0cy5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ1Byb2plY3RzQ29udHJvbGxlciBhcyBwcm9qZWN0c0N0cmwnLFxuICAgICAgICBkYXRhOiB7IG5lZWRBdXRoZW50aWNhdGlvbjogdHJ1ZSB9LFxuICAgICAgICBwYXJhbXM6IHsgb2JqOiBudWxsLCByZXNvdXJjZTogbnVsbCB9XG4gICAgICB9KTtcbiAgfVxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5mYWN0b3J5KCdQcm9qZWN0c1NlcnZpY2UnLCBQcm9qZWN0c1NlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gUHJvamVjdHNTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCdwcm9qZWN0cycsIHtcbiAgICAgIGFjdGlvbnM6IHsgfSxcbiAgICAgIGluc3RhbmNlOiB7IH1cbiAgICB9KTtcbiAgfVxuXG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmlsdGVyKCdyb2xlc1N0cicsIHJvbGVzU3RyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvbGVzU3RyKGxvZGFzaCkge1xuICAgIC8qKlxuICAgICAqIEBwYXJhbSB7YXJyYXl9IHJvbGVzIGxpc3RhIGRlIHBlcmZpc1xuICAgICAqIEByZXR1cm4ge3N0cmluZ30gcGVyZmlzIHNlcGFyYWRvcyBwb3IgJywgJyAgXG4gICAgICovXG4gICAgcmV0dXJuIGZ1bmN0aW9uKHJvbGVzKSB7XG4gICAgICByZXR1cm4gbG9kYXNoLm1hcChyb2xlcywgJ3NsdWcnKS5qb2luKCcsICcpO1xuICAgIH07XG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5mYWN0b3J5KCdSb2xlc1NlcnZpY2UnLCBSb2xlc1NlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gUm9sZXNTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCdyb2xlcycpO1xuICB9XG5cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb250cm9sbGVyKCdSZWxlYXNlc0NvbnRyb2xsZXInLCBSZWxlYXNlc0NvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gUmVsZWFzZXNDb250cm9sbGVyKCRjb250cm9sbGVyLCBSZWxlYXNlc1NlcnZpY2UsIE1pbGVzdG9uZXNTZXJ2aWNlLCBQclRvYXN0LCBtb21lbnQsICRtZERpYWxvZywgJHRyYW5zbGF0ZSkge1xuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICAvL0F0dHJpYnV0ZXMgQmxvY2tcblxuICAgIC8vRnVuY3Rpb25zIEJsb2NrXG4gICAgdm0ub25BY3RpdmF0ZSA9IGZ1bmN0aW9uKCkge1xuICAgICAgdm0ucHJvamVjdCA9IGxvY2FsU3RvcmFnZS5nZXRJdGVtKCdwcm9qZWN0Jyk7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMgPSB7IHByb2plY3RfaWQ6IHZtLnByb2plY3QgfTtcbiAgICB9XG5cbiAgICB2bS5iZWZvcmVTYXZlID0gZnVuY3Rpb24oKSB7XG4gICAgICB2bS5yZXNvdXJjZS5wcm9qZWN0X2lkID0gdm0ucHJvamVjdDtcbiAgICB9XG5cbiAgICB2bS5iZWZvcmVSZW1vdmUgPSBmdW5jdGlvbigpIHtcbiAgICAgIHZtLnJlc291cmNlLnByb2plY3RfaWQgPSB2bS5wcm9qZWN0O1xuICAgIH1cblxuICAgIHZtLnZpZXcgPSBmdW5jdGlvbiAocmVzb3VyY2UpIHtcbiAgICAgIHZtLnJlc291cmNlID0gcmVzb3VyY2U7XG4gICAgICB2bS5vblZpZXcgPSB0cnVlO1xuICAgICAgdm0udmlld0Zvcm0gPSBmYWxzZTtcbiAgICB9XG5cbiAgICB2bS5maW5hbGl6ZSA9IGZ1bmN0aW9uKHJlbGVhc2UpIHtcbiAgICAgIHZhciBjb25maXJtID0gJG1kRGlhbG9nLmNvbmZpcm0oKVxuICAgICAgICAgIC50aXRsZSgnRmluYWxpemFyIFJlbGVhc2UnKVxuICAgICAgICAgIC50ZXh0Q29udGVudCgnVGVtIGNlcnRlemEgcXVlIGRlc2VqYSBmaW5hbGl6YXIgYSByZWxlYXNlICcgKyByZWxlYXNlLnRpdGxlICsgJz8nKVxuICAgICAgICAgIC5vaygnU2ltJylcbiAgICAgICAgICAuY2FuY2VsKCdOw6NvJyk7XG5cbiAgICAgICRtZERpYWxvZy5zaG93KGNvbmZpcm0pLnRoZW4oZnVuY3Rpb24oKSB7XG4gICAgICAgIFJlbGVhc2VzU2VydmljZS5maW5hbGl6ZSh7IHByb2plY3RfaWQ6IHZtLnByb2plY3QsIHJlbGVhc2VfaWQ6IHJlbGVhc2UuaWQgfSkudGhlbihmdW5jdGlvbigpIHtcbiAgICAgICAgICBQclRvYXN0LnN1Y2Nlc3MoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5zcHJpbnRFbmRlZFN1Y2Nlc3MnKSk7XG4gICAgICAgICAgdm0uc2VhcmNoKCk7XG4gICAgICAgIH0sIGZ1bmN0aW9uKCkge1xuICAgICAgICAgIFByVG9hc3QuRXJyb3IoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5zcHJpbnRFbmRlZEVycm9yJykpO1xuICAgICAgICB9KTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIHZtLmZvcm1hdERhdGUgPSBmdW5jdGlvbihkYXRlKSB7XG4gICAgICByZXR1cm4gbW9tZW50KGRhdGUpLmZvcm1hdCgnREQvTU0vWVlZWScpO1xuICAgIH1cblxuICAgIHZtLnNlYXJjaE1pbGVzdG9uZSA9IGZ1bmN0aW9uIChtaWxlc3RvbmVUZXJtKSB7XG4gICAgICByZXR1cm4gTWlsZXN0b25lc1NlcnZpY2UucXVlcnkoe1xuICAgICAgICByZWxlYXNlU2VhcmNoOiB0cnVlLFxuICAgICAgICBwcm9qZWN0X2lkOiB2bS5yZXNvdXJjZS5wcm9qZWN0X2lkLFxuICAgICAgICB0aXRsZTogbWlsZXN0b25lVGVybVxuICAgICAgfSk7XG4gICAgfVxuXG4gICAgdm0ub25NaWxlc3RvbmVDaGFuZ2UgPSBmdW5jdGlvbigpIHtcbiAgICAgIGlmICh2bS5taWxlc3RvbmUgIT09IG51bGwgJiYgdm0ucmVzb3VyY2UubWlsZXN0b25lcy5maW5kSW5kZXgoaSA9PiBpLmlkID09PSB2bS5taWxlc3RvbmUuaWQpID09PSAtMSkge1xuICAgICAgICB2bS5yZXNvdXJjZS5taWxlc3RvbmVzLnB1c2godm0ubWlsZXN0b25lKTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICB2bS5yZW1vdmVNaWxlc3RvbmUgPSBmdW5jdGlvbihtaWxlc3RvbmUpIHtcbiAgICAgIHZtLnJlc291cmNlLm1pbGVzdG9uZXMuc2xpY2UoMCkuZm9yRWFjaChmdW5jdGlvbihlbGVtZW50KSB7XG4gICAgICAgIGlmKGVsZW1lbnQuaWQgPT09IG1pbGVzdG9uZS5pZCkge1xuICAgICAgICAgIHZtLnJlc291cmNlLm1pbGVzdG9uZXMuc3BsaWNlKHZtLnJlc291cmNlLm1pbGVzdG9uZXMuaW5kZXhPZihlbGVtZW50KSwgMSk7XG4gICAgICAgIH1cbiAgICAgIH0pO1xuICAgIH1cblxuICAgIHZtLnNhdmVNaWxlc3RvbmVzID0gZnVuY3Rpb24oKSB7XG4gICAgICBNaWxlc3RvbmVzU2VydmljZS51cGRhdGVSZWxlYXNlKHtwcm9qZWN0X2lkOiB2bS5yZXNvdXJjZS5wcm9qZWN0X2lkLCByZWxlYXNlX2lkOiB2bS5yZXNvdXJjZS5pZCwgbWlsZXN0b25lczogdm0ucmVzb3VyY2UubWlsZXN0b25lc30pLnRoZW4oZnVuY3Rpb24oKXtcbiAgICAgICAgUHJUb2FzdC5zdWNjZXNzKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMuc2F2ZVN1Y2Nlc3MnKSk7XG4gICAgICAgIHZtLnZpZXdGb3JtID0gZmFsc2U7XG4gICAgICAgIHZtLm9uVmlldyA9IGZhbHNlO1xuICAgICAgfSwgZnVuY3Rpb24oKSB7XG4gICAgICAgIFByVG9hc3QuZXJyb3IoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5vcGVyYXRpb25FcnJvcicpKTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIHZtLmVzdGltYXRlZFRpbWUgPSBmdW5jdGlvbiAobWlsZXN0b25lKSB7XG4gICAgICBtaWxlc3RvbmUuZXN0aW1hdGVkX3RpbWUgPSAwO1xuICAgICAgaWYobWlsZXN0b25lLnRhc2tzLmxlbmd0aCA+IDApIHtcbiAgICAgICAgbWlsZXN0b25lLnRhc2tzLmZvckVhY2goZnVuY3Rpb24odGFzaykge1xuICAgICAgICAgIG1pbGVzdG9uZS5lc3RpbWF0ZWRfdGltZSArPSB0YXNrLmVzdGltYXRlZF90aW1lO1xuICAgICAgICB9KTtcbiAgICAgIH1cbiAgICAgIHJldHVybiBtaWxlc3RvbmUuZXN0aW1hdGVkX3RpbWUgLyA4O1xuICAgIH1cblxuICAgIC8vIGluc3RhbnRpYXRlIGJhc2UgY29udHJvbGxlclxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHsgdm06IHZtLCBtb2RlbFNlcnZpY2U6IFJlbGVhc2VzU2VydmljZSwgb3B0aW9uczogeyB9IH0pO1xuXG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb25maWcocm91dGVzKTtcblxuICAvKipcbiAgICogQXJxdWl2byBkZSBjb25maWd1cmHDp8OjbyBjb20gYXMgcm90YXMgZXNwZWPDrWZpY2FzIGRvIHJlY3Vyc28gcmVsZWFzZXNcbiAgICpcbiAgICogQHBhcmFtIHtvYmplY3R9ICRzdGF0ZVByb3ZpZGVyXG4gICAqIEBwYXJhbSB7b2JqZWN0fSBHbG9iYWxcbiAgICovXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gcm91dGVzKCRzdGF0ZVByb3ZpZGVyLCBHbG9iYWwpIHtcbiAgICAkc3RhdGVQcm92aWRlclxuICAgICAgLnN0YXRlKCdhcHAucmVsZWFzZXMnLCB7XG4gICAgICAgIHVybDogJy9yZWxlYXNlcycsXG4gICAgICAgIHRlbXBsYXRlVXJsOiBHbG9iYWwuY2xpZW50UGF0aCArICcvcmVsZWFzZXMvcmVsZWFzZXMuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdSZWxlYXNlc0NvbnRyb2xsZXIgYXMgcmVsZWFzZXNDdHJsJyxcbiAgICAgICAgZGF0YTogeyB9XG4gICAgICB9KTtcbiAgfVxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5mYWN0b3J5KCdSZWxlYXNlc1NlcnZpY2UnLCBSZWxlYXNlc1NlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gUmVsZWFzZXNTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgdmFyIG1vZGVsID0gc2VydmljZUZhY3RvcnkoJ3JlbGVhc2VzJywge1xuICAgICAgYWN0aW9uczoge1xuICAgICAgICBmaW5hbGl6ZToge1xuICAgICAgICAgIG1ldGhvZDogJ1BPU1QnLFxuICAgICAgICAgIHVybDogJ2ZpbmFsaXplJ1xuICAgICAgICB9XG4gICAgICB9LFxuICAgICAgaW5zdGFuY2U6IHsgfVxuICAgIH0pO1xuXG4gICAgcmV0dXJuIG1vZGVsO1xuICB9XG5cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmFjdG9yeSgnU3RhdHVzU2VydmljZScsIFN0YXR1c1NlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gU3RhdHVzU2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHZhciBtb2RlbCA9IHNlcnZpY2VGYWN0b3J5KCdzdGF0dXMnLCB7XG4gICAgICBhY3Rpb25zOiB7IH0sXG4gICAgICBpbnN0YW5jZTogeyB9XG4gICAgfSk7XG5cbiAgICByZXR1cm4gbW9kZWw7XG4gIH1cblxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5mYWN0b3J5KCdTdXBwb3J0U2VydmljZScsIFN1cHBvcnRTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIFN1cHBvcnRTZXJ2aWNlKHNlcnZpY2VGYWN0b3J5KSB7XG4gICAgcmV0dXJuIHNlcnZpY2VGYWN0b3J5KCdzdXBwb3J0Jywge1xuICAgICAgYWN0aW9uczoge1xuICAgICAgLyoqXG4gICAgICAgKiBQZWdhIGFzIHRyYWR1w6fDtWVzIHF1ZSBlc3TDo28gbm8gc2Vydmlkb3JcbiAgICAgICAqXG4gICAgICAgKiBAcmV0dXJucyB7cHJvbWlzZX0gVW1hIHByb21pc2UgY29tIG8gcmVzdWx0YWRvIGRvIGNoYW1hZGEgbm8gYmFja2VuZFxuICAgICAgICovXG4gICAgICAgIGxhbmdzOiB7XG4gICAgICAgICAgbWV0aG9kOiAnR0VUJyxcbiAgICAgICAgICB1cmw6ICdsYW5ncycsXG4gICAgICAgICAgd3JhcDogZmFsc2UsXG4gICAgICAgICAgY2FjaGU6IHRydWVcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pO1xuICB9XG5cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmFjdG9yeSgnVGFza0NvbW1lbnRzU2VydmljZScsIFRhc2tDb21tZW50c1NlcnZpY2UpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgZnVuY3Rpb24gVGFza0NvbW1lbnRzU2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHZhciBtb2RlbCA9IHNlcnZpY2VGYWN0b3J5KCd0YXNrLWNvbW1lbnRzJywge1xuICAgICAgYWN0aW9uczoge1xuICAgICAgICBzYXZlVGFza0NvbW1lbnQ6IHtcbiAgICAgICAgICBtZXRob2Q6ICdQT1NUJyxcbiAgICAgICAgICB1cmw6ICdzYXZlVGFza0NvbW1lbnQnXG4gICAgICAgIH0sXG4gICAgICAgIHJlbW92ZVRhc2tDb21tZW50OiB7XG4gICAgICAgICAgbWV0aG9kOiAnUE9TVCcsXG4gICAgICAgICAgdXJsOiAncmVtb3ZlVGFza0NvbW1lbnQnXG4gICAgICAgIH1cbiAgICAgIH0sXG4gICAgICBpbnN0YW5jZTogeyB9XG4gICAgfSk7XG5cbiAgICByZXR1cm4gbW9kZWw7XG4gIH1cblxufSgpKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZpbHRlcignZWxhcHNlZCcsIGZ1bmN0aW9uKCkge1xuICAgICAgcmV0dXJuIGZ1bmN0aW9uKGRhdGUpIHtcbiAgICAgICAgaWYgKCFkYXRlKSByZXR1cm47XG4gICAgICAgIHZhciB0aW1lID0gRGF0ZS5wYXJzZShkYXRlKSxcbiAgICAgICAgICB0aW1lTm93ID0gbmV3IERhdGUoKS5nZXRUaW1lKCksXG4gICAgICAgICAgZGlmZmVyZW5jZSA9IHRpbWVOb3cgLSB0aW1lLFxuICAgICAgICAgIHNlY29uZHMgPSBNYXRoLmZsb29yKGRpZmZlcmVuY2UgLyAxMDAwKSxcbiAgICAgICAgICBtaW51dGVzID0gTWF0aC5mbG9vcihzZWNvbmRzIC8gNjApLFxuICAgICAgICAgIGhvdXJzID0gTWF0aC5mbG9vcihtaW51dGVzIC8gNjApLFxuICAgICAgICAgIGRheXMgPSBNYXRoLmZsb29yKGhvdXJzIC8gMjQpLFxuICAgICAgICAgIG1vbnRocyA9IE1hdGguZmxvb3IoZGF5cyAvIDMwKTtcblxuICAgICAgICBpZiAobW9udGhzID4gMSkge1xuICAgICAgICAgIHJldHVybiBtb250aHMgKyAnIG1lc2VzIGF0csOhcyc7XG4gICAgICAgIH0gZWxzZSBpZiAobW9udGhzID09PSAxKSB7XG4gICAgICAgICAgcmV0dXJuICcxIG3DqnMgYXRyw6FzJztcbiAgICAgICAgfSBlbHNlIGlmIChkYXlzID4gMSkge1xuICAgICAgICAgIHJldHVybiBkYXlzICsgJyBkaWFzIGF0csOhcyc7XG4gICAgICAgIH0gZWxzZSBpZiAoZGF5cyA9PT0gMSkge1xuICAgICAgICAgIHJldHVybiAnMSBkaWEgYXRyw6FzJ1xuICAgICAgICB9IGVsc2UgaWYgKGhvdXJzID4gMSkge1xuICAgICAgICAgIHJldHVybiBob3VycyArICcgaG9yYXMgYXRyw6FzJztcbiAgICAgICAgfSBlbHNlIGlmIChob3VycyA9PT0gMSkge1xuICAgICAgICAgIHJldHVybiAndW1hIGhvcmEgYXRyw6FzJztcbiAgICAgICAgfSBlbHNlIGlmIChtaW51dGVzID4gMSkge1xuICAgICAgICAgIHJldHVybiBtaW51dGVzICsgJyBtaW51dG9zIGF0csOhcyc7XG4gICAgICAgIH0gZWxzZSBpZiAobWludXRlcyA9PT0gMSkge1xuICAgICAgICAgIHJldHVybiAndW0gbWludXRvIGF0csOhcyc7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgcmV0dXJuICdow6EgcG91Y29zIHNlZ3VuZG9zJztcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pXG4gICAgLmNvbnRyb2xsZXIoJ1Rhc2tzQ29udHJvbGxlcicsIFRhc2tzQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBUYXNrc0NvbnRyb2xsZXIoJGNvbnRyb2xsZXIsXG4gICAgVGFza3NTZXJ2aWNlLFxuICAgIFN0YXR1c1NlcnZpY2UsXG4gICAgUHJpb3JpdGllc1NlcnZpY2UsXG4gICAgVHlwZXNTZXJ2aWNlLFxuICAgIFRhc2tDb21tZW50c1NlcnZpY2UsXG4gICAgbW9tZW50LFxuICAgIEF1dGgsXG4gICAgUHJUb2FzdCxcbiAgICAkdHJhbnNsYXRlLFxuICAgICRmaWx0ZXIpIHtcbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgLy9BdHRyaWJ1dGVzIEJsb2NrXG5cbiAgICAvL0Z1bmN0aW9ucyBCbG9ja1xuICAgIHZtLm9uQWN0aXZhdGUgPSBvbkFjdGl2YXRlO1xuICAgIHZtLmFwcGx5RmlsdGVycyA9IGFwcGx5RmlsdGVycztcbiAgICB2bS5iZWZvcmVTYXZlID0gYmVmb3JlU2F2ZTtcbiAgICB2bS5iZWZvcmVSZW1vdmUgPSBiZWZvcmVSZW1vdmU7XG5cbiAgICBmdW5jdGlvbiBvbkFjdGl2YXRlKCkge1xuICAgICAgdm0uY3VycmVudFVzZXIgPSBBdXRoLmN1cnJlbnRVc2VyO1xuICAgICAgdm0ucHJvamVjdCA9IGxvY2FsU3RvcmFnZS5nZXRJdGVtKCdwcm9qZWN0Jyk7XG4gICAgICB2bS5xdWVyeUZpbHRlcnMgPSB7IHByb2plY3RfaWQ6IHZtLnByb2plY3QgfTtcblxuICAgICAgU3RhdHVzU2VydmljZS5xdWVyeSgpLnRoZW4oZnVuY3Rpb24ocmVzcG9uc2UpIHtcbiAgICAgICAgdm0uc3RhdHVzID0gcmVzcG9uc2U7XG4gICAgICB9KTtcblxuICAgICAgUHJpb3JpdGllc1NlcnZpY2UucXVlcnkoKS50aGVuKGZ1bmN0aW9uKHJlc3BvbnNlKSB7XG4gICAgICAgIHZtLnByaW9yaXRpZXMgPSByZXNwb25zZTtcbiAgICAgIH0pO1xuXG4gICAgICBUeXBlc1NlcnZpY2UucXVlcnkoKS50aGVuKGZ1bmN0aW9uKHJlc3BvbnNlKSB7XG4gICAgICAgIHZtLnR5cGVzID0gcmVzcG9uc2U7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBhcHBseUZpbHRlcnMoZGVmYXVsdFF1ZXJ5RmlsdGVycykge1xuICAgICAgcmV0dXJuIGFuZ3VsYXIuZXh0ZW5kKGRlZmF1bHRRdWVyeUZpbHRlcnMsIHZtLnF1ZXJ5RmlsdGVycyk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gYmVmb3JlU2F2ZSgpIHtcbiAgICAgIHZtLnJlc291cmNlLnByb2plY3RfaWQgPSB2bS5wcm9qZWN0O1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGJlZm9yZVJlbW92ZSgpIHtcbiAgICAgIHZtLnJlc291cmNlLnByb2plY3RfaWQgPSB2bS5wcm9qZWN0O1xuICAgIH1cblxuICAgIHZtLnZpZXcgPSBmdW5jdGlvbiAocmVzb3VyY2UpIHtcbiAgICAgIHZtLnJlc291cmNlID0gcmVzb3VyY2U7XG4gICAgICB2bS5vblZpZXcgPSB0cnVlO1xuICAgICAgdm0udmlld0Zvcm0gPSBmYWxzZTtcbiAgICB9XG5cbiAgICB2bS5zYXZlQ29tbWVudCA9IGZ1bmN0aW9uKGNvbW1lbnQpIHtcbiAgICAgIHZhciBkZXNjcmlwdGlvbiA9ICcnO1xuICAgICAgdmFyIGNvbW1lbnRfaWQgPSBudWxsO1xuXG4gICAgICBpZiAoY29tbWVudCkge1xuICAgICAgICBkZXNjcmlwdGlvbiA9IHZtLmFuc3dlclxuICAgICAgICBjb21tZW50X2lkID0gY29tbWVudC5pZDtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIGRlc2NyaXB0aW9uID0gdm0uY29tbWVudDtcbiAgICAgIH1cbiAgICAgIFRhc2tDb21tZW50c1NlcnZpY2Uuc2F2ZVRhc2tDb21tZW50KHsgcHJvamVjdF9pZDogdm0ucHJvamVjdCwgdGFza19pZDogdm0ucmVzb3VyY2UuaWQsIGNvbW1lbnRfdGV4dDogZGVzY3JpcHRpb24sIGNvbW1lbnRfaWQ6IGNvbW1lbnRfaWQgfSkudGhlbihmdW5jdGlvbigpIHtcbiAgICAgICAgdm0uY29tbWVudCA9ICcnO1xuICAgICAgICB2bS5hbnN3ZXIgPSAnJztcbiAgICAgICAgdm0uc2VhcmNoKCk7XG4gICAgICAgIFByVG9hc3Quc3VjY2VzcygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnNhdmVTdWNjZXNzJykpO1xuICAgICAgfSwgZnVuY3Rpb24oKSB7XG4gICAgICAgIFByVG9hc3QuZXJyb3IoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5vcGVyYXRpb25FcnJvcicpKTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIHZtLnJlbW92ZUNvbW1lbnQgPSBmdW5jdGlvbihjb21tZW50KSB7XG4gICAgICBUYXNrQ29tbWVudHNTZXJ2aWNlLnJlbW92ZVRhc2tDb21tZW50KHsgY29tbWVudF9pZDogY29tbWVudC5pZCB9KS50aGVuKGZ1bmN0aW9uKCkge1xuICAgICAgICB2bS5zZWFyY2goKTtcbiAgICAgICAgUHJUb2FzdC5zdWNjZXNzKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMucmVtb3ZlU3VjY2VzcycpKTtcbiAgICAgIH0sIGZ1bmN0aW9uKCkge1xuICAgICAgICBQclRvYXN0LmVycm9yKCR0cmFuc2xhdGUuaW5zdGFudCgnbWVzc2FnZXMub3BlcmF0aW9uRXJyb3InKSk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICB2bS5hZnRlclNlYXJjaCA9IGZ1bmN0aW9uKCkge1xuICAgICAgaWYgKHZtLnJlc291cmNlLmlkKSB7XG4gICAgICAgIHZtLnJlc291cmNlID0gJGZpbHRlcignZmlsdGVyJykodm0ucmVzb3VyY2VzLCB7IGlkOiB2bS5yZXNvdXJjZS5pZCB9KVswXTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICB2bS5maXhEYXRlID0gZnVuY3Rpb24oZGF0ZVN0cmluZykge1xuICAgICAgcmV0dXJuIG1vbWVudChkYXRlU3RyaW5nKTtcbiAgICB9XG5cbiAgICAvLyBpbnN0YW50aWF0ZSBiYXNlIGNvbnRyb2xsZXJcbiAgICAkY29udHJvbGxlcignQ1JVRENvbnRyb2xsZXInLCB7IHZtOiB2bSwgbW9kZWxTZXJ2aWNlOiBUYXNrc1NlcnZpY2UsIG9wdGlvbnM6IHsgc2tpcFBhZ2luYXRpb246IHRydWUgfSB9KTtcbiAgfVxuXG59KSgpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKlxuICAgKiBBcnF1aXZvIGRlIGNvbmZpZ3VyYcOnw6NvIGNvbSBhcyByb3RhcyBlc3BlY8OtZmljYXMgZG8gcmVjdXJzbyBwcm9qZWN0XG4gICAqXG4gICAqIEBwYXJhbSB7YW55fSAkc3RhdGVQcm92aWRlclxuICAgKiBAcGFyYW0ge2FueX0gR2xvYmFsXG4gICAqL1xuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvdXRlcygkc3RhdGVQcm92aWRlciwgR2xvYmFsKSB7XG4gICAgJHN0YXRlUHJvdmlkZXJcbiAgICAgIC5zdGF0ZSgnYXBwLnRhc2tzJywge1xuICAgICAgICB1cmw6ICcvdGFza3MnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL3Rhc2tzL3Rhc2tzLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnVGFza3NDb250cm9sbGVyIGFzIHRhc2tzQ3RybCcsXG4gICAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiB0cnVlfVxuICAgICAgfSk7XG4gIH1cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmFjdG9yeSgnVGFza3NTZXJ2aWNlJywgVGFza3NTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIFRhc2tzU2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHJldHVybiBzZXJ2aWNlRmFjdG9yeSgndGFza3MnLCB7XG4gICAgICBhY3Rpb25zOiB7XG4gICAgICAgIHVwZGF0ZU1pbGVzdG9uZToge1xuICAgICAgICAgIG1ldGhvZDogJ1BPU1QnLFxuICAgICAgICAgIHVybDogJ3VwZGF0ZU1pbGVzdG9uZSdcbiAgICAgICAgfSxcbiAgICAgICAgdXBkYXRlVGFza0J5S2FuYmFuOiB7XG4gICAgICAgICAgbWV0aG9kOiAnUE9TVCcsXG4gICAgICAgICAgdXJsOiAndXBkYXRlVGFza0J5S2FuYmFuJ1xuICAgICAgICB9XG4gICAgICB9LFxuICAgICAgaW5zdGFuY2U6IHsgfVxuICAgIH0pO1xuICB9XG5cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmFjdG9yeSgnVHlwZXNTZXJ2aWNlJywgVHlwZXNTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIFR5cGVzU2VydmljZShzZXJ2aWNlRmFjdG9yeSkge1xuICAgIHZhciBtb2RlbCA9IHNlcnZpY2VGYWN0b3J5KCd0eXBlcycsIHtcbiAgICAgIGFjdGlvbnM6IHsgfSxcbiAgICAgIGluc3RhbmNlOiB7IH1cbiAgICB9KTtcblxuICAgIHJldHVybiBtb2RlbDtcbiAgfVxuXG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29udHJvbGxlcignUHJvZmlsZUNvbnRyb2xsZXInLCBQcm9maWxlQ29udHJvbGxlcik7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBQcm9maWxlQ29udHJvbGxlcihVc2Vyc1NlcnZpY2UsIEF1dGgsIFByVG9hc3QsICR0cmFuc2xhdGUsICR3aW5kb3csIG1vbWVudCkge1xuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICB2bS51cGRhdGUgPSB1cGRhdGU7XG4gICAgdm0uaGlzdG9yeUJhY2sgPSBoaXN0b3J5QmFjaztcblxuICAgIGFjdGl2YXRlKCk7XG5cbiAgICBmdW5jdGlvbiBhY3RpdmF0ZSgpIHtcbiAgICAgIHZtLnVzZXIgPSBhbmd1bGFyLmNvcHkoQXV0aC5jdXJyZW50VXNlcik7XG4gICAgICBpZiAodm0udXNlci5iaXJ0aGRheSkge1xuICAgICAgICB2bS51c2VyLmJpcnRoZGF5ID0gbW9tZW50KHZtLnVzZXIuYmlydGhkYXkpLmZvcm1hdCgnREQvTU0vWVlZWScpO1xuICAgICAgfVxuICAgIH1cblxuICAgIGZ1bmN0aW9uIHVwZGF0ZSgpIHtcbiAgICAgIGlmICh2bS51c2VyLmJpcnRoZGF5KSB7XG4gICAgICAgIHZtLnVzZXIuYmlydGhkYXkgPSBtb21lbnQodm0udXNlci5iaXJ0aGRheSk7XG4gICAgICB9XG4gICAgICBVc2Vyc1NlcnZpY2UudXBkYXRlUHJvZmlsZSh2bS51c2VyKS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICAvL2F0dWFsaXphIG8gdXN1w6FyaW8gY29ycmVudGUgY29tIGFzIG5vdmFzIGluZm9ybWHDp8O1ZXNcbiAgICAgICAgQXV0aC51cGRhdGVDdXJyZW50VXNlcihyZXNwb25zZSk7XG4gICAgICAgIFByVG9hc3Quc3VjY2VzcygkdHJhbnNsYXRlLmluc3RhbnQoJ21lc3NhZ2VzLnNhdmVTdWNjZXNzJykpO1xuICAgICAgICBoaXN0b3J5QmFjaygpO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gaGlzdG9yeUJhY2soKSB7XG4gICAgICAkd2luZG93Lmhpc3RvcnkuYmFjaygpO1xuICAgIH1cblxuICB9XG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIGFuZ3VsYXJcbiAgICAubW9kdWxlKCdhcHAnKVxuICAgIC5jb250cm9sbGVyKCdVc2Vyc0NvbnRyb2xsZXInLCBVc2Vyc0NvbnRyb2xsZXIpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gVXNlcnNDb250cm9sbGVyKCRjb250cm9sbGVyLCBVc2Vyc1NlcnZpY2UsIFByVG9hc3QsICRtZERpYWxvZywgJHRyYW5zbGF0ZSkge1xuXG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIHZtLm9uQWN0aXZhdGUgPSBvbkFjdGl2YXRlO1xuICAgIC8vIGluc3RhbnRpYXRlIGJhc2UgY29udHJvbGxlclxuICAgICRjb250cm9sbGVyKCdDUlVEQ29udHJvbGxlcicsIHsgdm06IHZtLCBtb2RlbFNlcnZpY2U6IFVzZXJzU2VydmljZSwgb3B0aW9uczoge30gfSk7XG5cbiAgICBmdW5jdGlvbiBvbkFjdGl2YXRlKCkge1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0ge307XG4gICAgfVxuXG4gICAgdm0uaGlkZURpYWxvZyA9IGZ1bmN0aW9uKCkge1xuICAgICAgJG1kRGlhbG9nLmhpZGUoKTtcbiAgICB9XG5cbiAgICB2bS5zYXZlTmV3VXNlciA9IGZ1bmN0aW9uKCkge1xuICAgICAgdm0ucmVzb3VyY2UuJHNhdmUoKS50aGVuKGZ1bmN0aW9uIChyZXNvdXJjZSkge1xuICAgICAgICB2bS5yZXNvdXJjZSA9IHJlc291cmNlO1xuICAgICAgICBQclRvYXN0LnN1Y2Nlc3MoJHRyYW5zbGF0ZS5pbnN0YW50KCdtZXNzYWdlcy5zdWNjZXNzU2lnblVwJykpO1xuICAgICAgICAkbWREaWFsb2cuaGlkZSgpO1xuICAgICAgfSk7XG4gICAgfVxuICB9XG59KSgpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbmZpZyhyb3V0ZXMpO1xuXG4gIC8qKlxuICAgKiBBcnF1aXZvIGRlIGNvbmZpZ3VyYcOnw6NvIGNvbSBhcyByb3RhcyBlc3BlY8OtZmljYXMgZG8gcmVjdXJzbyB1c2VyXG4gICAqXG4gICAqIEBwYXJhbSB7YW55fSAkc3RhdGVQcm92aWRlclxuICAgKiBAcGFyYW0ge2FueX0gR2xvYmFsXG4gICAqL1xuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIHJvdXRlcygkc3RhdGVQcm92aWRlciwgR2xvYmFsKSB7XG4gICAgJHN0YXRlUHJvdmlkZXJcbiAgICAgIC5zdGF0ZSgnYXBwLnVzZXInLCB7XG4gICAgICAgIHVybDogJy91c3VhcmlvJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6IEdsb2JhbC5jbGllbnRQYXRoICsgJy91c2Vycy91c2Vycy5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ1VzZXJzQ29udHJvbGxlciBhcyB1c2Vyc0N0cmwnLFxuICAgICAgICBkYXRhOiB7IG5lZWRBdXRoZW50aWNhdGlvbjogdHJ1ZSwgbmVlZFByb2ZpbGU6IFsnYWRtaW4nXSB9XG4gICAgICB9KVxuICAgICAgLnN0YXRlKCdhcHAudXNlci1wcm9maWxlJywge1xuICAgICAgICB1cmw6ICcvdXN1YXJpby9wZXJmaWwnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL3VzZXJzL3Byb2ZpbGUuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdQcm9maWxlQ29udHJvbGxlciBhcyBwcm9maWxlQ3RybCcsXG4gICAgICAgIGRhdGE6IHsgbmVlZEF1dGhlbnRpY2F0aW9uOiB0cnVlIH1cbiAgICAgIH0pO1xuXG4gIH1cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmFjdG9yeSgnVXNlcnNTZXJ2aWNlJywgVXNlcnNTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIFVzZXJzU2VydmljZShsb2Rhc2gsIEdsb2JhbCwgc2VydmljZUZhY3RvcnkpIHtcbiAgICByZXR1cm4gc2VydmljZUZhY3RvcnkoJ3VzZXJzJywge1xuICAgICAgLy9xdWFuZG8gaW5zdGFuY2lhIHVtIHVzdcOhcmlvIHNlbSBwYXNzYXIgcGFyYW1ldHJvLFxuICAgICAgLy9vIG1lc21vIHZhaSB0ZXIgb3MgdmFsb3JlcyBkZWZhdWx0cyBhYmFpeG9cbiAgICAgIGRlZmF1bHRzOiB7XG4gICAgICAgIHJvbGVzOiBbXVxuICAgICAgfSxcblxuICAgICAgYWN0aW9uczoge1xuICAgICAgICAvKipcbiAgICAgICAgICogU2VydmnDp28gcXVlIGF0dWFsaXphIG9zIGRhZG9zIGRvIHBlcmZpbCBkbyB1c3XDoXJpbyBsb2dhZG9cbiAgICAgICAgICpcbiAgICAgICAgICogQHBhcmFtIHtvYmplY3R9IGF0dHJpYnV0ZXNcbiAgICAgICAgICogQHJldHVybnMge3Byb21pc2V9IFVtYSBwcm9taXNlIGNvbSBvIHJlc3VsdGFkbyBkbyBjaGFtYWRhIG5vIGJhY2tlbmRcbiAgICAgICAgICovXG4gICAgICAgIHVwZGF0ZVByb2ZpbGU6IHtcbiAgICAgICAgICBtZXRob2Q6ICdQVVQnLFxuICAgICAgICAgIHVybDogR2xvYmFsLmFwaVBhdGggKyAnL3Byb2ZpbGUnLFxuICAgICAgICAgIG92ZXJyaWRlOiB0cnVlLFxuICAgICAgICAgIHdyYXA6IGZhbHNlXG4gICAgICAgIH1cbiAgICAgIH0sXG5cbiAgICAgIGluc3RhbmNlOiB7XG4gICAgICAgIC8qKlxuICAgICAgICAgKiBWZXJpZmljYSBzZSBvIHVzdcOhcmlvIHRlbSBvcyBwZXJmaXMgaW5mb3JtYWRvcy5cbiAgICAgICAgICpcbiAgICAgICAgICogQHBhcmFtIHthbnl9IHJvbGVzIHBlcmZpcyBhIHNlcmVtIHZlcmlmaWNhZG9zXG4gICAgICAgICAqIEBwYXJhbSB7Ym9vbGVhbn0gYWxsIGZsYWcgcGFyYSBpbmRpY2FyIHNlIHZhaSBjaGVnYXIgdG9kb3Mgb3MgcGVyZmlzIG91IHNvbWVudGUgdW0gZGVsZXNcbiAgICAgICAgICogQHJldHVybnMge2Jvb2xlYW59XG4gICAgICAgICAqL1xuICAgICAgICBoYXNQcm9maWxlOiBmdW5jdGlvbihyb2xlcywgYWxsKSB7XG4gICAgICAgICAgcm9sZXMgPSBhbmd1bGFyLmlzQXJyYXkocm9sZXMpID8gcm9sZXMgOiBbcm9sZXNdO1xuXG4gICAgICAgICAgdmFyIHVzZXJSb2xlcyA9IGxvZGFzaC5tYXAodGhpcy5yb2xlcywgJ3NsdWcnKTtcblxuICAgICAgICAgIGlmIChhbGwpIHtcbiAgICAgICAgICAgIHJldHVybiBsb2Rhc2guaW50ZXJzZWN0aW9uKHVzZXJSb2xlcywgcm9sZXMpLmxlbmd0aCA9PT0gcm9sZXMubGVuZ3RoO1xuICAgICAgICAgIH0gZWxzZSB7IC8vcmV0dXJuIHRoZSBsZW5ndGggYmVjYXVzZSAwIGlzIGZhbHNlIGluIGpzXG4gICAgICAgICAgICByZXR1cm4gbG9kYXNoLmludGVyc2VjdGlvbih1c2VyUm9sZXMsIHJvbGVzKS5sZW5ndGg7XG4gICAgICAgICAgfVxuICAgICAgICB9LFxuXG4gICAgICAgIC8qKlxuICAgICAgICAgKiBWZXJpZmljYSBzZSBvIHVzdcOhcmlvIHRlbSBvIHBlcmZpbCBhZG1pbi5cbiAgICAgICAgICpcbiAgICAgICAgICogQHJldHVybnMge2Jvb2xlYW59XG4gICAgICAgICAqL1xuICAgICAgICBpc0FkbWluOiBmdW5jdGlvbigpIHtcbiAgICAgICAgICByZXR1cm4gdGhpcy5oYXNQcm9maWxlKCdhZG1pbicpO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfSk7XG4gIH1cblxufSgpKTtcbiIsIi8vdG9rZW4gY2FjYjkxMjM1ODczYThjNDg3NWQyMzU3OGFjOWYzMjZlZjg5NGI2NlxuLy8gT0F0dXRoIGh0dHBzOi8vZ2l0aHViLmNvbS9sb2dpbi9vYXV0aC9hdXRob3JpemU/Y2xpZW50X2lkPTgyOTQ2OGU3ZmRlZTc5NDQ1YmE2JnNjb3BlPXVzZXIscHVibGljX3JlcG8mcmVkaXJlY3RfdXJpPWh0dHA6Ly8wLjAuMC4wOjUwMDAvIyEvYXBwL3Zjc1xuXG4oZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZpbHRlcignYnl0ZXMnLCBmdW5jdGlvbigpIHtcbiAgICAgIHJldHVybiBmdW5jdGlvbihieXRlcywgcHJlY2lzaW9uKSB7XG4gICAgICAgIGlmIChpc05hTihwYXJzZUZsb2F0KGJ5dGVzKSkgfHwgIWlzRmluaXRlKGJ5dGVzKSkgcmV0dXJuICctJztcbiAgICAgICAgaWYgKHR5cGVvZiBwcmVjaXNpb24gPT09ICd1bmRlZmluZWQnKSBwcmVjaXNpb24gPSAxO1xuICAgICAgICB2YXIgdW5pdHMgPSBbJ2J5dGVzJywgJ2tCJywgJ01CJywgJ0dCJywgJ1RCJywgJ1BCJ10sXG4gICAgICAgICAgbnVtYmVyID0gTWF0aC5mbG9vcihNYXRoLmxvZyhieXRlcykgLyBNYXRoLmxvZygxMDI0KSk7XG5cbiAgICAgICAgcmV0dXJuIChieXRlcyAvIE1hdGgucG93KDEwMjQsIE1hdGguZmxvb3IobnVtYmVyKSkpLnRvRml4ZWQocHJlY2lzaW9uKSArICAnICcgKyB1bml0c1tudW1iZXJdO1xuICAgICAgfVxuICAgIH0pXG4gICAgLmNvbnRyb2xsZXIoJ1Zjc0NvbnRyb2xsZXInLCBWY3NDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIFZjc0NvbnRyb2xsZXIoJGNvbnRyb2xsZXIsIFZjc1NlcnZpY2UsICR3aW5kb3csIFByb2plY3RzU2VydmljZSwgUHJUb2FzdCwgJHRyYW5zbGF0ZSkge1xuICAgIHZhciB2bSA9IHRoaXM7XG5cbiAgICB2bS5pbmRleCA9IDA7XG4gICAgdm0ucGF0aHMgPSBbXTtcblxuICAgIC8vQXR0cmlidXRlcyBCbG9ja1xuXG4gICAgLy9GdW5jdGlvbnMgQmxvY2tcbiAgICB2bS5vbkFjdGl2YXRlID0gIGZ1bmN0aW9uKCkge1xuICAgICAgdG9nZ2xlU3BsYXNoU2NyZWVuKCk7XG4gICAgICBQcm9qZWN0c1NlcnZpY2UucXVlcnkoeyBwcm9qZWN0X2lkOiBsb2NhbFN0b3JhZ2UuZ2V0SXRlbSgncHJvamVjdCcpIH0pLnRoZW4oZnVuY3Rpb24ocmVzcG9uc2UpIHtcbiAgICAgICAgdm0udXNlcm5hbWUgPSByZXNwb25zZVswXS51c2VybmFtZV9naXRodWI7XG4gICAgICAgIHZtLnJlcG8gPSByZXNwb25zZVswXS5yZXBvX2dpdGh1YjtcbiAgICAgICAgdm0ucXVlcnlGaWx0ZXJzID0ge1xuICAgICAgICAgIHVzZXJuYW1lOiB2bS51c2VybmFtZSxcbiAgICAgICAgICByZXBvOiB2bS5yZXBvLFxuICAgICAgICAgIHBhdGg6ICcuJ1xuICAgICAgICB9XG4gICAgICAgIHZtLnBhdGhzLnB1c2godm0ucXVlcnlGaWx0ZXJzLnBhdGgpO1xuICAgICAgICB2bS5zZWFyY2goKTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIHZtLmFwcGx5RmlsdGVycyA9IGZ1bmN0aW9uKGRlZmF1bHRRdWVyeUZpbHRlcnMpIHtcbiAgICAgIHJldHVybiBhbmd1bGFyLmV4dGVuZChkZWZhdWx0UXVlcnlGaWx0ZXJzLCB2bS5xdWVyeUZpbHRlcnMpO1xuICAgIH1cblxuICAgIHZtLmFmdGVyU2VhcmNoID0gZnVuY3Rpb24oKSB7XG4gICAgICBzb3J0UmVzb3VyY2VzKCk7XG4gICAgICAkd2luZG93LmxvYWRpbmdfc2NyZWVuLmZpbmlzaCgpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIHNvcnRSZXNvdXJjZXMoKSB7XG4gICAgICB2bS5yZXNvdXJjZXMuc29ydChmdW5jdGlvbihhLCBiKSB7XG4gICAgICAgIHJldHVybiBhLnR5cGUgPCBiLnR5cGUgPyAtMSA6IGEudHlwZSA+IGIudHlwZSA/IDEgOiAwO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgdm0ub3BlbkZpbGVPckRpcmVjdG9yeSA9IGZ1bmN0aW9uKHJlc291cmNlKSB7XG4gICAgICB0b2dnbGVTcGxhc2hTY3JlZW4oKTtcbiAgICAgIGlmIChyZXNvdXJjZSkge1xuICAgICAgICB2bS5xdWVyeUZpbHRlcnMucGF0aCA9IHJlc291cmNlLnBhdGg7XG4gICAgICAgIHZtLnBhdGhzLnB1c2godm0ucXVlcnlGaWx0ZXJzLnBhdGgpO1xuICAgICAgICB2bS5pbmRleCsrO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgdm0ucXVlcnlGaWx0ZXJzLnBhdGggPSB2bS5wYXRoc1t2bS5pbmRleCAtIDFdO1xuICAgICAgICB2bS5wYXRocy5zcGxpY2Uodm0uaW5kZXgsIDEpO1xuICAgICAgICB2bS5pbmRleC0tO1xuICAgICAgfVxuICAgICAgdm0uc2VhcmNoKCk7XG4gICAgfVxuXG4gICAgdm0ub25TZWFyY2hFcnJvciA9IGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgaWYgKHJlc3BvbnNlLmRhdGEuZXJyb3IgPT09ICdOb3QgRm91bmQnKSB7XG4gICAgICAgIFByVG9hc3QuaW5mbygkdHJhbnNsYXRlLmluc3RhbnQoJ1JlcG9zaXTDs3JpbyBuw6NvIGVuY29udHJhZG8nKSk7XG4gICAgICAgICR3aW5kb3cubG9hZGluZ19zY3JlZW4uZmluaXNoKCk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogTcOpdG9kbyBwYXJhIG1vc3RyYXIgYSB0ZWxhIGRlIGVzcGVyYVxuICAgICAqL1xuICAgIGZ1bmN0aW9uIHRvZ2dsZVNwbGFzaFNjcmVlbigpIHtcbiAgICAgICR3aW5kb3cubG9hZGluZ19zY3JlZW4gPSAkd2luZG93LnBsZWFzZVdhaXQoe1xuICAgICAgICBsb2dvOiAnJyxcbiAgICAgICAgYmFja2dyb3VuZENvbG9yOiAncmdiYSgyNTUsMjU1LDI1NSwwLjQpJyxcbiAgICAgICAgbG9hZGluZ0h0bWw6XG4gICAgICAgICAgJzxkaXYgY2xhc3M9XCJzcGlubmVyXCI+ICcgK1xuICAgICAgICAgICcgIDxkaXYgY2xhc3M9XCJyZWN0MVwiPjwvZGl2PiAnICtcbiAgICAgICAgICAnICA8ZGl2IGNsYXNzPVwicmVjdDJcIj48L2Rpdj4gJyArXG4gICAgICAgICAgJyAgPGRpdiBjbGFzcz1cInJlY3QzXCI+PC9kaXY+ICcgK1xuICAgICAgICAgICcgIDxkaXYgY2xhc3M9XCJyZWN0NFwiPjwvZGl2PiAnICtcbiAgICAgICAgICAnICA8ZGl2IGNsYXNzPVwicmVjdDVcIj48L2Rpdj4gJyArXG4gICAgICAgICAgJyA8cCBjbGFzcz1cImxvYWRpbmctbWVzc2FnZVwiPkNhcnJlZ2FuZG88L3A+ICcgK1xuICAgICAgICAgICc8L2Rpdj4nXG4gICAgICB9KTtcbiAgICB9XG5cbiAgICAvLyBpbnN0YW50aWF0ZSBiYXNlIGNvbnRyb2xsZXJcbiAgICAkY29udHJvbGxlcignQ1JVRENvbnRyb2xsZXInLCB7IHZtOiB2bSwgbW9kZWxTZXJ2aWNlOiBWY3NTZXJ2aWNlLCBvcHRpb25zOiB7IHNraXBQYWdpbmF0aW9uOiB0cnVlLCBzZWFyY2hPbkluaXQ6IGZhbHNlIH0gfSk7XG5cbiAgfVxuXG5cbn0pKCk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uZmlnKHJvdXRlcyk7XG5cbiAgLyoqXG4gICAqIEFycXVpdm8gZGUgY29uZmlndXJhw6fDo28gY29tIGFzIHJvdGFzIGVzcGVjw61maWNhcyBkbyByZWN1cnNvIHZjc1xuICAgKlxuICAgKiBAcGFyYW0ge29iamVjdH0gJHN0YXRlUHJvdmlkZXJcbiAgICogQHBhcmFtIHtvYmplY3R9IEdsb2JhbFxuICAgKi9cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBmdW5jdGlvbiByb3V0ZXMoJHN0YXRlUHJvdmlkZXIsIEdsb2JhbCkge1xuICAgICRzdGF0ZVByb3ZpZGVyXG4gICAgICAuc3RhdGUoJ2FwcC52Y3MnLCB7XG4gICAgICAgIHVybDogJy92Y3MnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogR2xvYmFsLmNsaWVudFBhdGggKyAnL3Zjcy92Y3MuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdWY3NDb250cm9sbGVyIGFzIHZjc0N0cmwnLFxuICAgICAgICBkYXRhOiB7IH1cbiAgICAgIH0pO1xuICB9XG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZhY3RvcnkoJ1Zjc1NlcnZpY2UnLCBWY3NTZXJ2aWNlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIGZ1bmN0aW9uIFZjc1NlcnZpY2Uoc2VydmljZUZhY3RvcnkpIHtcbiAgICB2YXIgbW9kZWwgPSBzZXJ2aWNlRmFjdG9yeSgndmNzJywge1xuICAgICAgYWN0aW9uczogeyB9LFxuICAgICAgaW5zdGFuY2U6IHsgfVxuICAgIH0pO1xuXG4gICAgcmV0dXJuIG1vZGVsO1xuICB9XG5cbn0oKSk7XG4iLCIoZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICAgLyoqIEBuZ0luamVjdCAqL1xuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29tcG9uZW50KCdib3gnLCB7XG4gICAgICByZXBsYWNlOiB0cnVlLFxuICAgICAgdGVtcGxhdGVVcmw6IFsnR2xvYmFsJywgZnVuY3Rpb24oR2xvYmFsKSB7XG4gICAgICAgIHJldHVybiBHbG9iYWwuY2xpZW50UGF0aCArICcvd2lkZ2V0cy9ib3guaHRtbCdcbiAgICAgIH1dLFxuICAgICAgdHJhbnNjbHVkZToge1xuICAgICAgICB0b29sYmFyQnV0dG9uczogJz9ib3hUb29sYmFyQnV0dG9ucycsXG4gICAgICAgIGZvb3RlckJ1dHRvbnM6ICc/Ym94Rm9vdGVyQnV0dG9ucydcbiAgICAgIH0sXG4gICAgICBiaW5kaW5nczoge1xuICAgICAgICBib3hUaXRsZTogJ0AnLFxuICAgICAgICB0b29sYmFyQ2xhc3M6ICdAJyxcbiAgICAgICAgdG9vbGJhckJnQ29sb3I6ICdAJ1xuICAgICAgfSxcbiAgICAgIGNvbnRyb2xsZXI6IFsnJHRyYW5zY2x1ZGUnLCBmdW5jdGlvbigkdHJhbnNjbHVkZSkge1xuICAgICAgICB2YXIgY3RybCA9IHRoaXM7XG5cbiAgICAgICAgY3RybC50cmFuc2NsdWRlID0gJHRyYW5zY2x1ZGU7XG5cbiAgICAgICAgY3RybC4kb25Jbml0ID0gZnVuY3Rpb24oKSB7XG4gICAgICAgICAgaWYgKGFuZ3VsYXIuaXNVbmRlZmluZWQoY3RybC50b29sYmFyQmdDb2xvcikpIGN0cmwudG9vbGJhckJnQ29sb3IgPSAnZGVmYXVsdC1wcmltYXJ5JztcbiAgICAgICAgfTtcbiAgICAgIH1dXG4gICAgfSk7XG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29tcG9uZW50KCdjb250ZW50Qm9keScsIHtcbiAgICAgIHJlcGxhY2U6IHRydWUsXG4gICAgICB0cmFuc2NsdWRlOiB0cnVlLFxuICAgICAgdGVtcGxhdGVVcmw6IFsnR2xvYmFsJywgZnVuY3Rpb24oR2xvYmFsKSB7XG4gICAgICAgIHJldHVybiBHbG9iYWwuY2xpZW50UGF0aCArICcvd2lkZ2V0cy9jb250ZW50LWJvZHkuaHRtbCdcbiAgICAgIH1dLFxuICAgICAgYmluZGluZ3M6IHtcbiAgICAgICAgbGF5b3V0QWxpZ246ICdAJ1xuICAgICAgfSxcbiAgICAgIGNvbnRyb2xsZXI6IFtmdW5jdGlvbigpIHtcbiAgICAgICAgdmFyIGN0cmwgPSB0aGlzO1xuXG4gICAgICAgIGN0cmwuJG9uSW5pdCA9IGZ1bmN0aW9uKCkge1xuICAgICAgICAgIC8vIE1ha2UgYSBjb3B5IG9mIHRoZSBpbml0aWFsIHZhbHVlIHRvIGJlIGFibGUgdG8gcmVzZXQgaXQgbGF0ZXJcbiAgICAgICAgICBjdHJsLmxheW91dEFsaWduID0gYW5ndWxhci5pc0RlZmluZWQoY3RybC5sYXlvdXRBbGlnbikgPyBjdHJsLmxheW91dEFsaWduIDogJ2NlbnRlciBzdGFydCc7XG4gICAgICAgIH07XG4gICAgICB9XVxuICAgIH0pO1xuXG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29tcG9uZW50KCdjb250ZW50SGVhZGVyJywge1xuICAgICAgdGVtcGxhdGVVcmw6IFsnR2xvYmFsJywgZnVuY3Rpb24oR2xvYmFsKSB7XG4gICAgICAgIHJldHVybiBHbG9iYWwuY2xpZW50UGF0aCArICcvd2lkZ2V0cy9jb250ZW50LWhlYWRlci5odG1sJ1xuICAgICAgfV0sXG4gICAgICByZXBsYWNlOiB0cnVlLFxuICAgICAgYmluZGluZ3M6IHtcbiAgICAgICAgdGl0bGU6ICdAJyxcbiAgICAgICAgZGVzY3JpcHRpb246ICdAJ1xuICAgICAgfVxuICAgIH0pO1xuXG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmlsdGVyKCdhdWRpdERldGFpbFRpdGxlJywgYXVkaXREZXRhaWxUaXRsZSk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBhdWRpdERldGFpbFRpdGxlKCR0cmFuc2xhdGUpIHtcbiAgICByZXR1cm4gZnVuY3Rpb24oYXVkaXREZXRhaWwsIHN0YXR1cykge1xuICAgICAgaWYgKGF1ZGl0RGV0YWlsLnR5cGUgPT09ICd1cGRhdGVkJykge1xuICAgICAgICBpZiAoc3RhdHVzID09PSAnYmVmb3JlJykge1xuICAgICAgICAgIHJldHVybiAkdHJhbnNsYXRlLmluc3RhbnQoJ2RpYWxvZy5hdWRpdC51cGRhdGVkQmVmb3JlJyk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgcmV0dXJuICR0cmFuc2xhdGUuaW5zdGFudCgnZGlhbG9nLmF1ZGl0LnVwZGF0ZWRBZnRlcicpO1xuICAgICAgICB9XG4gICAgICB9IGVsc2Uge1xuICAgICAgICByZXR1cm4gJHRyYW5zbGF0ZS5pbnN0YW50KCdkaWFsb2cuYXVkaXQuJyArIGF1ZGl0RGV0YWlsLnR5cGUpO1xuICAgICAgfVxuICAgIH1cbiAgfVxuXG59KSgpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuZmlsdGVyKCdhdWRpdE1vZGVsJywgYXVkaXRNb2RlbCk7XG5cbiAgLyoqIEBuZ0luamVjdCAqL1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbWF4LXBhcmFtc1xuICBmdW5jdGlvbiBhdWRpdE1vZGVsKCR0cmFuc2xhdGUpIHtcbiAgICByZXR1cm4gZnVuY3Rpb24obW9kZWxJZCkge1xuICAgICAgbW9kZWxJZCA9IG1vZGVsSWQucmVwbGFjZSgnQXBwXFxcXCcsICcnKTtcbiAgICAgIHZhciBtb2RlbCA9ICR0cmFuc2xhdGUuaW5zdGFudCgnbW9kZWxzLicgKyBtb2RlbElkLnRvTG93ZXJDYXNlKCkpO1xuXG4gICAgICByZXR1cm4gKG1vZGVsKSA/IG1vZGVsIDogbW9kZWxJZDtcbiAgICB9XG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZpbHRlcignYXVkaXRUeXBlJywgYXVkaXRUeXBlKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIGF1ZGl0VHlwZShsb2Rhc2gsIEF1ZGl0U2VydmljZSkge1xuICAgIHJldHVybiBmdW5jdGlvbih0eXBlSWQpIHtcbiAgICAgIHZhciB0eXBlID0gbG9kYXNoLmZpbmQoQXVkaXRTZXJ2aWNlLmxpc3RUeXBlcygpLCB7IGlkOiB0eXBlSWQgfSk7XG5cbiAgICAgIHJldHVybiAodHlwZSkgPyB0eXBlLmxhYmVsIDogdHlwZTtcbiAgICB9XG4gIH1cblxufSkoKTtcbiIsIihmdW5jdGlvbigpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmZpbHRlcignYXVkaXRWYWx1ZScsIGF1ZGl0VmFsdWUpO1xuXG4gIC8qKiBAbmdJbmplY3QgKi9cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG1heC1wYXJhbXNcbiAgZnVuY3Rpb24gYXVkaXRWYWx1ZSgkZmlsdGVyLCBsb2Rhc2gpIHtcbiAgICByZXR1cm4gZnVuY3Rpb24odmFsdWUsIGtleSkge1xuICAgICAgaWYgKGFuZ3VsYXIuaXNEYXRlKHZhbHVlKSB8fCBsb2Rhc2guZW5kc1dpdGgoa2V5LCAnX2F0JykgfHwgIGxvZGFzaC5lbmRzV2l0aChrZXksICdfdG8nKSkge1xuICAgICAgICByZXR1cm4gJGZpbHRlcigncHJEYXRldGltZScpKHZhbHVlKTtcbiAgICAgIH1cblxuICAgICAgaWYgKHR5cGVvZiB2YWx1ZSA9PT0gJ2Jvb2xlYW4nKSB7XG4gICAgICAgIHJldHVybiAkZmlsdGVyKCd0cmFuc2xhdGUnKSgodmFsdWUpID8gJ2dsb2JhbC55ZXMnIDogJ2dsb2JhbC5ubycpO1xuICAgICAgfVxuXG4gICAgICAvL2NoZWNrIGlzIGZsb2F0XG4gICAgICBpZiAoTnVtYmVyKHZhbHVlKSA9PT0gdmFsdWUgJiYgdmFsdWUgJSAxICE9PSAwKSB7XG4gICAgICAgIHJldHVybiAkZmlsdGVyKCdyZWFsJykodmFsdWUpO1xuICAgICAgfVxuXG4gICAgICByZXR1cm4gdmFsdWU7XG4gICAgfVxuICB9XG5cbn0pKCk7XG4iLCIvKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCwgbm8tdW5kZWY6IDAqL1xuKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnN0YW50KCdwdC1CUi5pMThuLmF0dHJpYnV0ZXMnLCB7XG4gICAgICBlbWFpbDogJ0VtYWlsJyxcbiAgICAgIHBhc3N3b3JkOiAnU2VuaGEnLFxuICAgICAgbmFtZTogJ05vbWUnLFxuICAgICAgaW1hZ2U6ICdJbWFnZW0nLFxuICAgICAgcm9sZXM6ICdQZXJmaXMnLFxuICAgICAgZGF0ZTogJ0RhdGEnLFxuICAgICAgaW5pdGlhbERhdGU6ICdEYXRhIEluaWNpYWwnLFxuICAgICAgZmluYWxEYXRlOiAnRGF0YSBGaW5hbCcsXG4gICAgICBiaXJ0aGRheTogJ0RhdGEgZGUgTmFzY2ltZW50bycsXG4gICAgICB0YXNrOiB7XG4gICAgICAgIGRlc2NyaXB0aW9uOiAnRGVzY3Jpw6fDo28nLFxuICAgICAgICBkb25lOiAnRmVpdG8/JyxcbiAgICAgICAgcHJpb3JpdHk6ICdQcmlvcmlkYWRlJyxcbiAgICAgICAgc2NoZWR1bGVkX3RvOiAnQWdlbmRhZG8gUGFyYT8nLFxuICAgICAgICBwcm9qZWN0OiAnUHJvamV0bycsXG4gICAgICAgIHN0YXR1czogJ1N0YXR1cycsXG4gICAgICAgIHRpdGxlOiAnVMOtdHVsbycsXG4gICAgICAgIHR5cGU6ICdUaXBvJyxcbiAgICAgICAgbWlsZXN0b25lOiAnU3ByaW50JyxcbiAgICAgICAgZXN0aW1hdGVkX3RpbWU6ICdUZW1wbyBFc3RpbWFkbydcbiAgICAgIH0sXG4gICAgICBtaWxlc3RvbmU6IHtcbiAgICAgICAgdGl0bGU6ICdUw610dWxvJyxcbiAgICAgICAgZGVzY3JpcHRpb246ICdEZXNjcmnDp8OjbycsXG4gICAgICAgIGRhdGVfc3RhcnQ6ICdEYXRhIEVzdGltYWRhIHBhcmEgSW7DrWNpbycsXG4gICAgICAgIGRhdGVfZW5kOiAnRGF0YSBFc3RpbWFkYSBwYXJhIEZpbScsXG4gICAgICAgIGVzdGltYXRlZF90aW1lOiAnVGVtcG8gRXN0aW1hZG8nLFxuICAgICAgICBlc3RpbWF0ZWRfdmFsdWU6ICdWYWxvciBFc3RpbWFkbydcbiAgICAgIH0sXG4gICAgICBwcm9qZWN0OiB7XG4gICAgICAgIGNvc3Q6ICdDdXN0bycsXG4gICAgICAgIGhvdXJWYWx1ZURldmVsb3BlcjogJ1ZhbG9yIGRhIEhvcmEgRGVzZW52b2x2ZWRvcicsXG4gICAgICAgIGhvdXJWYWx1ZUNsaWVudDogJ1ZhbG9yIGRhIEhvcmEgQ2xpZW50ZScsXG4gICAgICAgIGhvdXJWYWx1ZUZpbmFsOiAnVmFsb3IgZGEgSG9yYSBQcm9qZXRvJ1xuICAgICAgfSxcbiAgICAgIHJlbGVhc2U6IHtcbiAgICAgICAgdGl0bGU6ICdUw610dWxvJyxcbiAgICAgICAgZGVzY3JpcHRpb246ICdEZXNjcmnDp8OjbycsXG4gICAgICAgIHJlbGVhc2VfZGF0ZTogJ0RhdGEgZGUgRW50cmVnYScsXG4gICAgICAgIG1pbGVzdG9uZTogJ01pbGVzdG9uZScsXG4gICAgICAgIHRhc2tzOiAnVGFyZWZhcydcbiAgICAgIH0sXG4gICAgICAvL8OpIGNhcnJlZ2FkbyBkbyBzZXJ2aWRvciBjYXNvIGVzdGVqYSBkZWZpbmlkbyBubyBtZXNtb1xuICAgICAgYXVkaXRNb2RlbDoge1xuICAgICAgfVxuICAgIH0pXG5cbn0oKSk7XG4iLCIvKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCwgbm8tdW5kZWY6IDAqL1xuKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnN0YW50KCdwdC1CUi5pMThuLmRpYWxvZycsIHtcbiAgICAgIGNvbmZpcm1UaXRsZTogJ0NvbmZpcm1hw6fDo28nLFxuICAgICAgY29uZmlybURlc2NyaXB0aW9uOiAnQ29uZmlybWEgYSBhw6fDo28/JyxcbiAgICAgIHJlbW92ZURlc2NyaXB0aW9uOiAnRGVzZWphIHJlbW92ZXIgcGVybWFuZW50ZW1lbnRlIHt7bmFtZX19PycsXG4gICAgICBhdWRpdDoge1xuICAgICAgICBjcmVhdGVkOiAnSW5mb3JtYcOnw7VlcyBkbyBDYWRhc3RybycsXG4gICAgICAgIHVwZGF0ZWRCZWZvcmU6ICdBbnRlcyBkYSBBdHVhbGl6YcOnw6NvJyxcbiAgICAgICAgdXBkYXRlZEFmdGVyOiAnRGVwb2lzIGRhIEF0dWFsaXphw6fDo28nLFxuICAgICAgICBkZWxldGVkOiAnSW5mb3JtYcOnw7VlcyBhbnRlcyBkZSByZW1vdmVyJ1xuICAgICAgfSxcbiAgICAgIGxvZ2luOiB7XG4gICAgICAgIHJlc2V0UGFzc3dvcmQ6IHtcbiAgICAgICAgICBkZXNjcmlwdGlvbjogJ0RpZ2l0ZSBhYmFpeG8gbyBlbWFpbCBjYWRhc3RyYWRvIG5vIHNpc3RlbWEuJ1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfSlcblxufSgpKTtcbiIsIi8qZXNsaW50IGFuZ3VsYXIvZmlsZS1uYW1lOiAwLCBuby11bmRlZjogMCovXG4oZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uc3RhbnQoJ3B0LUJSLmkxOG4uZ2xvYmFsJywge1xuICAgICAgbG9hZGluZzogJ0NhcnJlZ2FuZG8uLi4nLFxuICAgICAgcHJvY2Vzc2luZzogJ1Byb2Nlc3NhbmRvLi4uJyxcbiAgICAgIHllczogJ1NpbScsXG4gICAgICBubzogJ07Do28nLFxuICAgICAgYWxsOiAnVG9kb3MnXG4gICAgfSlcblxufSgpKTtcbiIsIi8qZXNsaW50IGFuZ3VsYXIvZmlsZS1uYW1lOiAwLCBuby11bmRlZjogMCovXG4oZnVuY3Rpb24oKSB7XG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29uc3RhbnQoJ3B0LUJSLmkxOG4ubWVzc2FnZXMnLCB7XG4gICAgICBpbnRlcm5hbEVycm9yOiAnT2NvcnJldSB1bSBlcnJvIGludGVybm8sIGNvbnRhdGUgbyBhZG1pbmlzdHJhZG9yIGRvIHNpc3RlbWEnLFxuICAgICAgbm90Rm91bmQ6ICdOZW5odW0gcmVnaXN0cm8gZW5jb250cmFkbycsXG4gICAgICBub3RBdXRob3JpemVkOiAnVm9jw6ogbsOjbyB0ZW0gYWNlc3NvIGEgZXN0YSBmdW5jaW9uYWxpZGFkZS4nLFxuICAgICAgc2VhcmNoRXJyb3I6ICdOw6NvIGZvaSBwb3Nzw612ZWwgcmVhbGl6YXIgYSBidXNjYS4nLFxuICAgICAgc2F2ZVN1Y2Nlc3M6ICdSZWdpc3RybyBzYWx2byBjb20gc3VjZXNzby4nLFxuICAgICAgb3BlcmF0aW9uU3VjY2VzczogJ09wZXJhw6fDo28gcmVhbGl6YWRhIGNvbSBzdWNlc3NvLicsXG4gICAgICBvcGVyYXRpb25FcnJvcjogJ0Vycm8gYW8gcmVhbGl6YXIgYSBvcGVyYcOnw6NvJyxcbiAgICAgIHNhdmVFcnJvcjogJ0Vycm8gYW8gdGVudGFyIHNhbHZhciBvIHJlZ2lzdHJvLicsXG4gICAgICByZW1vdmVTdWNjZXNzOiAnUmVtb8Onw6NvIHJlYWxpemFkYSBjb20gc3VjZXNzby4nLFxuICAgICAgcmVtb3ZlRXJyb3I6ICdFcnJvIGFvIHRlbnRhciByZW1vdmVyIG8gcmVnaXN0cm8uJyxcbiAgICAgIHJlc291cmNlTm90Rm91bmRFcnJvcjogJ1JlY3Vyc28gbsOjbyBlbmNvbnRyYWRvJyxcbiAgICAgIG5vdE51bGxFcnJvcjogJ1RvZG9zIG9zIGNhbXBvcyBvYnJpZ2F0w7NyaW9zIGRldmVtIHNlciBwcmVlbmNoaWRvcy4nLFxuICAgICAgZHVwbGljYXRlZFJlc291cmNlRXJyb3I6ICdKw6EgZXhpc3RlIHVtIHJlY3Vyc28gY29tIGVzc2FzIGluZm9ybWHDp8O1ZXMuJyxcbiAgICAgIHNwcmludEVuZGVkU3VjY2VzczogJ1NwcmludCBmaW5hbGl6YWRhIGNvbSBzdWNlc3NvJyxcbiAgICAgIHNwcmludEVuZGVkRXJyb3I6ICdFcnJvIGFvIGZpbmFsaXphciBhIHNwcmludCcsXG4gICAgICBzdWNjZXNzU2lnblVwOiAnQ2FkYXN0cm8gcmVhbGl6YWRvIGNvbSBzdWNlc3NvLiBVbSBlLW1haWwgZm9pIGVudmlhZG8gY29tIHNldXMgZGFkb3MgZGUgbG9naW4nLFxuICAgICAgZXJyb3JzU2lnblVwOiAnSG91dmUgdW0gZXJybyBhbyByZWFsaXphciBvIHNldSBjYWRhc3Ryby4gVGVudGUgbm92YW1lbnRlIG1haXMgdGFyZGUhJyxcbiAgICAgIHZhbGlkYXRlOiB7XG4gICAgICAgIGZpZWxkUmVxdWlyZWQ6ICdPIGNhbXBvIHt7ZmllbGR9fSDDqSBvYnJpZ3JhdMOzcmlvLidcbiAgICAgIH0sXG4gICAgICBsYXlvdXQ6IHtcbiAgICAgICAgZXJyb3I0MDQ6ICdQw6FnaW5hIG7Do28gZW5jb250cmFkYSdcbiAgICAgIH0sXG4gICAgICBsb2dpbjoge1xuICAgICAgICBsb2dvdXRJbmFjdGl2ZTogJ1ZvY8OqIGZvaSBkZXNsb2dhZG8gZG8gc2lzdGVtYSBwb3IgaW5hdGl2aWRhZGUuIEZhdm9yIGVudHJhciBubyBzaXN0ZW1hIG5vdmFtZW50ZS4nLFxuICAgICAgICBpbnZhbGlkQ3JlZGVudGlhbHM6ICdDcmVkZW5jaWFpcyBJbnbDoWxpZGFzJyxcbiAgICAgICAgdW5rbm93bkVycm9yOiAnTsOjbyBmb2kgcG9zc8OtdmVsIHJlYWxpemFyIG8gbG9naW4uIFRlbnRlIG5vdmFtZW50ZS4gJyArXG4gICAgICAgICAgJ0Nhc28gbsOjbyBjb25zaWdhIGZhdm9yIGVuY29udHJhciBlbSBjb250YXRvIGNvbSBvIGFkbWluaXN0cmFkb3IgZG8gc2lzdGVtYS4nLFxuICAgICAgICB1c2VyTm90Rm91bmQ6ICdOw6NvIGZvaSBwb3Nzw612ZWwgZW5jb250cmFyIHNldXMgZGFkb3MnXG4gICAgICB9LFxuICAgICAgZGFzaGJvYXJkOiB7XG4gICAgICAgIHdlbGNvbWU6ICdTZWphIGJlbSBWaW5kbyB7e3VzZXJOYW1lfX0nLFxuICAgICAgICBkZXNjcmlwdGlvbjogJ1V0aWxpemUgbyBtZW51IHBhcmEgbmF2ZWdhw6fDo28uJ1xuICAgICAgfSxcbiAgICAgIG1haWw6IHtcbiAgICAgICAgbWFpbEVycm9yczogJ09jb3JyZXUgdW0gZXJybyBub3Mgc2VndWludGVzIGVtYWlscyBhYmFpeG86XFxuJyxcbiAgICAgICAgc2VuZE1haWxTdWNjZXNzOiAnRW1haWwgZW52aWFkbyBjb20gc3VjZXNzbyEnLFxuICAgICAgICBzZW5kTWFpbEVycm9yOiAnTsOjbyBmb2kgcG9zc8OtdmVsIGVudmlhciBvIGVtYWlsLicsXG4gICAgICAgIHBhc3N3b3JkU2VuZGluZ1N1Y2Nlc3M6ICdPIHByb2Nlc3NvIGRlIHJlY3VwZXJhw6fDo28gZGUgc2VuaGEgZm9pIGluaWNpYWRvLiBDYXNvIG8gZW1haWwgbsOjbyBjaGVndWUgZW0gMTAgbWludXRvcyB0ZW50ZSBub3ZhbWVudGUuJ1xuICAgICAgfSxcbiAgICAgIHVzZXI6IHtcbiAgICAgICAgcmVtb3ZlWW91clNlbGZFcnJvcjogJ1ZvY8OqIG7Do28gcG9kZSByZW1vdmVyIHNldSBwcsOzcHJpbyB1c3XDoXJpbycsXG4gICAgICAgIHVzZXJFeGlzdHM6ICdVc3XDoXJpbyBqw6EgYWRpY2lvbmFkbyEnLFxuICAgICAgICBwcm9maWxlOiB7XG4gICAgICAgICAgdXBkYXRlRXJyb3I6ICdOw6NvIGZvaSBwb3Nzw612ZWwgYXR1YWxpemFyIHNldSBwcm9maWxlJ1xuICAgICAgICB9XG4gICAgICB9LFxuICAgICAgcXVlcnlEaW5hbWljOiB7XG4gICAgICAgIG5vRmlsdGVyOiAnTmVuaHVtIGZpbHRybyBhZGljaW9uYWRvJ1xuICAgICAgfVxuICAgIH0pXG5cbn0oKSk7XG4iLCIvKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCwgbm8tdW5kZWY6IDAqL1xuKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnN0YW50KCdwdC1CUi5pMThuLm1vZGVscycsIHtcbiAgICAgIHVzZXI6ICdVc3XDoXJpbycsXG4gICAgICB0YXNrOiAnVGFyZWZhJyxcbiAgICAgIHByb2plY3Q6ICdQcm9qZXRvJ1xuICAgIH0pXG5cbn0oKSk7XG4iLCIvKmVzbGludCBhbmd1bGFyL2ZpbGUtbmFtZTogMCwgbm8tdW5kZWY6IDAqL1xuKGZ1bmN0aW9uKCkge1xuICAndXNlIHN0cmljdCc7XG5cbiAgYW5ndWxhclxuICAgIC5tb2R1bGUoJ2FwcCcpXG4gICAgLmNvbnN0YW50KCdwdC1CUi5pMThuLnZpZXdzJywge1xuICAgICAgYnJlYWRjcnVtYnM6IHtcbiAgICAgICAgdXNlcjogJ0FkbWluaXN0cmHDp8OjbyAtIFVzdcOhcmlvJyxcbiAgICAgICAgJ3VzZXItcHJvZmlsZSc6ICdQZXJmaWwnLFxuICAgICAgICBkYXNoYm9hcmQ6ICdEYXNoYm9hcmQnLFxuICAgICAgICBhdWRpdDogJ0FkbWluaXN0cmHDp8OjbyAtIEF1ZGl0b3JpYScsXG4gICAgICAgIG1haWw6ICdBZG1pbmlzdHJhw6fDo28gLSBFbnZpbyBkZSBlLW1haWwnLFxuICAgICAgICBwcm9qZWN0czogJ1Byb2pldG9zJyxcbiAgICAgICAgJ2RpbmFtaWMtcXVlcnknOiAnQWRtaW5pc3RyYcOnw6NvIC0gQ29uc3VsdGFzIERpbsOibWljYXMnLFxuICAgICAgICAnbm90LWF1dGhvcml6ZWQnOiAnQWNlc3NvIE5lZ2FkbycsXG4gICAgICAgIHRhc2tzOiAnVGFyZWZhcycsXG4gICAgICAgIG1pbGVzdG9uZXM6ICdTcHJpbnRzJyxcbiAgICAgICAga2FuYmFuOiAnS2FuYmFuIEJvYXJkJyxcbiAgICAgICAgdmNzOiAnQ29udHJvbGUgZGUgVmVyc8OjbycsXG4gICAgICAgIHJlbGVhc2VzOiAnUmVsZWFzZXMnXG4gICAgICB9LFxuICAgICAgdGl0bGVzOiB7XG4gICAgICAgIGRhc2hib2FyZDogJ0Rhc2hib2FyZCcsXG4gICAgICAgIG1haWxTZW5kOiAnRW52aWFyIGUtbWFpbCcsXG4gICAgICAgIHRhc2tMaXN0OiAnTGlzdGEgZGUgVGFyZWZhcycsXG4gICAgICAgIHVzZXJMaXN0OiAnTGlzdGEgZGUgVXN1w6FyaW9zJyxcbiAgICAgICAgYXVkaXRMaXN0OiAnTGlzdGEgZGUgTG9ncycsXG4gICAgICAgIHJlZ2lzdGVyOiAnRm9ybXVsw6FyaW8gZGUgQ2FkYXN0cm8nLFxuICAgICAgICByZXNldFBhc3N3b3JkOiAnUmVkZWZpbmlyIFNlbmhhJyxcbiAgICAgICAgdXBkYXRlOiAnRm9ybXVsw6FyaW8gZGUgQXR1YWxpemHDp8OjbycsXG4gICAgICAgIHRhc2tzOiAnVGFyZWZhcycsXG4gICAgICAgIG1pbGVzdG9uZXM6ICdTcHJpbnRzJyxcbiAgICAgICAga2FuYmFuOiAnS2FuYmFuIEJvYXJkJyxcbiAgICAgICAgdmNzOiAnQ29udHJvbGUgZGUgVmVyc8OjbycsXG4gICAgICAgIHJlbGVhc2VzOiAnUmVsZWFzZXMnXG4gICAgICB9LFxuICAgICAgYWN0aW9uczoge1xuICAgICAgICBzZW5kOiAnRW52aWFyJyxcbiAgICAgICAgc2F2ZTogJ1NhbHZhcicsXG4gICAgICAgIGNsZWFyOiAnTGltcGFyJyxcbiAgICAgICAgY2xlYXJBbGw6ICdMaW1wYXIgVHVkbycsXG4gICAgICAgIHJlc3RhcnQ6ICdSZWluaWNpYXInLFxuICAgICAgICBmaWx0ZXI6ICdGaWx0cmFyJyxcbiAgICAgICAgc2VhcmNoOiAnUGVzcXVpc2FyJyxcbiAgICAgICAgbGlzdDogJ0xpc3RhcicsXG4gICAgICAgIGVkaXQ6ICdFZGl0YXInLFxuICAgICAgICBjYW5jZWw6ICdDYW5jZWxhcicsXG4gICAgICAgIHVwZGF0ZTogJ0F0dWFsaXphcicsXG4gICAgICAgIHJlbW92ZTogJ1JlbW92ZXInLFxuICAgICAgICBnZXRPdXQ6ICdTYWlyJyxcbiAgICAgICAgYWRkOiAnQWRpY2lvbmFyJyxcbiAgICAgICAgaW46ICdFbnRyYXInLFxuICAgICAgICBsb2FkSW1hZ2U6ICdDYXJyZWdhciBJbWFnZW0nLFxuICAgICAgICBzaWdudXA6ICdDYWRhc3RyYXInLFxuICAgICAgICBjcmlhclByb2pldG86ICdDcmlhciBQcm9qZXRvJyxcbiAgICAgICAgcHJvamVjdExpc3Q6ICdMaXN0YSBkZSBQcm9qZXRvcycsXG4gICAgICAgIHRhc2tzTGlzdDogJ0xpc3RhIGRlIFRhcmVmYXMnLFxuICAgICAgICBtaWxlc3RvbmVzTGlzdDogJ0xpc3RhIGRlIFNwcmludHMnLFxuICAgICAgICBmaW5hbGl6ZTogJ0ZpbmFsaXphcicsXG4gICAgICAgIHJlcGx5OiAnUmVzcG9uZGVyJ1xuICAgICAgfSxcbiAgICAgIGZpZWxkczoge1xuICAgICAgICBkYXRlOiAnRGF0YScsXG4gICAgICAgIGFjdGlvbjogJ0HDp8OjbycsXG4gICAgICAgIGFjdGlvbnM6ICdBw6fDtWVzJyxcbiAgICAgICAgYXVkaXQ6IHtcbiAgICAgICAgICBkYXRlU3RhcnQ6ICdEYXRhIEluaWNpYWwnLFxuICAgICAgICAgIGRhdGVFbmQ6ICdEYXRhIEZpbmFsJyxcbiAgICAgICAgICByZXNvdXJjZTogJ1JlY3Vyc28nLFxuICAgICAgICAgIGFsbFJlc291cmNlczogJ1RvZG9zIFJlY3Vyc29zJyxcbiAgICAgICAgICB0eXBlOiB7XG4gICAgICAgICAgICBjcmVhdGVkOiAnQ2FkYXN0cmFkbycsXG4gICAgICAgICAgICB1cGRhdGVkOiAnQXR1YWxpemFkbycsXG4gICAgICAgICAgICBkZWxldGVkOiAnUmVtb3ZpZG8nXG4gICAgICAgICAgfVxuICAgICAgICB9LFxuICAgICAgICBsb2dpbjoge1xuICAgICAgICAgIHJlc2V0UGFzc3dvcmQ6ICdFc3F1ZWNpIG1pbmhhIHNlbmhhJyxcbiAgICAgICAgICBjb25maXJtUGFzc3dvcmQ6ICdDb25maXJtYXIgc2VuaGEnXG4gICAgICAgIH0sXG4gICAgICAgIG1haWw6IHtcbiAgICAgICAgICB0bzogJ1BhcmEnLFxuICAgICAgICAgIHN1YmplY3Q6ICdBc3N1bnRvJyxcbiAgICAgICAgICBtZXNzYWdlOiAnTWVuc2FnZW0nXG4gICAgICAgIH0sXG4gICAgICAgIHF1ZXJ5RGluYW1pYzoge1xuICAgICAgICAgIGZpbHRlcnM6ICdGaWx0cm9zJyxcbiAgICAgICAgICByZXN1bHRzOiAnUmVzdWx0YWRvcycsXG4gICAgICAgICAgbW9kZWw6ICdNb2RlbCcsXG4gICAgICAgICAgYXR0cmlidXRlOiAnQXRyaWJ1dG8nLFxuICAgICAgICAgIG9wZXJhdG9yOiAnT3BlcmFkb3InLFxuICAgICAgICAgIHJlc291cmNlOiAnUmVjdXJzbycsXG4gICAgICAgICAgdmFsdWU6ICdWYWxvcicsXG4gICAgICAgICAgb3BlcmF0b3JzOiB7XG4gICAgICAgICAgICBlcXVhbHM6ICdJZ3VhbCcsXG4gICAgICAgICAgICBkaWZlcmVudDogJ0RpZmVyZW50ZScsXG4gICAgICAgICAgICBjb250ZWluczogJ0NvbnTDqW0nLFxuICAgICAgICAgICAgc3RhcnRXaXRoOiAnSW5pY2lhIGNvbScsXG4gICAgICAgICAgICBmaW5pc2hXaXRoOiAnRmluYWxpemEgY29tJyxcbiAgICAgICAgICAgIGJpZ2dlclRoYW46ICdNYWlvcicsXG4gICAgICAgICAgICBlcXVhbHNPckJpZ2dlclRoYW46ICdNYWlvciBvdSBJZ3VhbCcsXG4gICAgICAgICAgICBsZXNzVGhhbjogJ01lbm9yJyxcbiAgICAgICAgICAgIGVxdWFsc09yTGVzc1RoYW46ICdNZW5vciBvdSBJZ3VhbCdcbiAgICAgICAgICB9XG4gICAgICAgIH0sXG4gICAgICAgIHByb2plY3Q6IHtcbiAgICAgICAgICBuYW1lOiAnTm9tZScsXG4gICAgICAgICAgdG90YWxUYXNrOiAnVG90YWwgZGUgVGFyZWZhcydcbiAgICAgICAgfSxcbiAgICAgICAgdGFzazoge1xuICAgICAgICAgIGRvbmU6ICdOw6NvIEZlaXRvIC8gRmVpdG8nXG4gICAgICAgIH0sXG4gICAgICAgIHVzZXI6IHtcbiAgICAgICAgICBwZXJmaWxzOiAnUGVyZmlzJyxcbiAgICAgICAgICBuYW1lT3JFbWFpbDogJ05vbWUgb3UgRW1haWwnXG4gICAgICAgIH1cbiAgICAgIH0sXG4gICAgICBsYXlvdXQ6IHtcbiAgICAgICAgbWVudToge1xuICAgICAgICAgIHByb2plY3RzOiAnUHJvamV0b3MnLFxuICAgICAgICAgIGRhc2hib2FyZDogJ0Rhc2hib2FyZCcsXG4gICAgICAgICAgbWlsZXN0b25lczogJ1NwcmludHMnLFxuICAgICAgICAgIHRhc2tzOiAnVGFyZWZhcycsXG4gICAgICAgICAga2FuYmFuOiAnS2FuYmFuJyxcbiAgICAgICAgICB2Y3M6ICdDb250cm9sZSBkZSBWZXJzw6NvJyxcbiAgICAgICAgICByZWxlYXNlczogJ1JlbGVhc2VzJ1xuICAgICAgICB9XG4gICAgICB9LFxuICAgICAgdG9vbHRpcHM6IHtcbiAgICAgICAgYXVkaXQ6IHtcbiAgICAgICAgICB2aWV3RGV0YWlsOiAnVmlzdWFsaXphciBEZXRhbGhhbWVudG8nXG4gICAgICAgIH0sXG4gICAgICAgIHVzZXI6IHtcbiAgICAgICAgICBwZXJmaWw6ICdQZXJmaWwnLFxuICAgICAgICAgIHRyYW5zZmVyOiAnVHJhbnNmZXJpcidcbiAgICAgICAgfSxcbiAgICAgICAgdGFzazoge1xuICAgICAgICAgIGxpc3RUYXNrOiAnTGlzdGFyIFRhcmVmYXMnXG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9KVxuXG59KCkpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29udHJvbGxlcignVGFza0luZm9Db250cm9sbGVyJywgVGFza0luZm9Db250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIFRhc2tJbmZvQ29udHJvbGxlcigkY29udHJvbGxlciwgVGFza3NTZXJ2aWNlLCBsb2NhbHMpIHtcbiAgICAvL0F0dHJpYnV0ZXMgQmxvY2tcbiAgICB2YXIgdm0gPSB0aGlzO1xuXG4gICAgdm0uY2xvc2VEaWFsb2cgPSBjbG9zZURpYWxvZztcblxuICAgIHZtLm9uQWN0aXZhdGUgPSBmdW5jdGlvbigpIHtcbiAgICAgIHZtLnRhc2sgPSBsb2NhbHMudGFzaztcbiAgICAgIHZtLnRhc2suZXN0aW1hdGVkX3RpbWUgPSB2bS50YXNrLmVzdGltYXRlZF90aW1lLnRvU3RyaW5nKCkgKyAnIGhvcmFzJztcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBjbG9zZURpYWxvZygpIHtcbiAgICAgIHZtLmNsb3NlKCk7XG4gICAgICBjb25zb2xlLmxvZyhcImZlY2hhclwiKTtcbiAgICB9XG5cbiAgICAvLyBpbnN0YW50aWF0ZSBiYXNlIGNvbnRyb2xsZXJcbiAgICAkY29udHJvbGxlcignQ1JVRENvbnRyb2xsZXInLCB7IHZtOiB2bSwgbW9kZWxTZXJ2aWNlOiBUYXNrc1NlcnZpY2UsIG9wdGlvbnM6IHsgfSB9KTtcbiAgfVxuXG59KSgpO1xuIiwiKGZ1bmN0aW9uKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICBhbmd1bGFyXG4gICAgLm1vZHVsZSgnYXBwJylcbiAgICAuY29udHJvbGxlcignVXNlcnNEaWFsb2dDb250cm9sbGVyJywgVXNlcnNEaWFsb2dDb250cm9sbGVyKTtcblxuICAvKiogQG5nSW5qZWN0ICovXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBtYXgtcGFyYW1zXG4gIGZ1bmN0aW9uIFVzZXJzRGlhbG9nQ29udHJvbGxlcigkY29udHJvbGxlciwgVXNlcnNTZXJ2aWNlLCBQckRpYWxvZywgIC8vIE5PU09OQVJcbiAgICB1c2VyRGlhbG9nSW5wdXQsIG9uSW5pdCkge1xuXG4gICAgdmFyIHZtID0gdGhpcztcblxuICAgIHZtLm9uQWN0aXZhdGUgPSBvbkFjdGl2YXRlO1xuICAgIHZtLmFwcGx5RmlsdGVycyA9IGFwcGx5RmlsdGVycztcbiAgICB2bS5jbG9zZSA9IGNsb3NlO1xuXG4gICAgaWYgKGFuZ3VsYXIuaXNEZWZpbmVkKHVzZXJEaWFsb2dJbnB1dCkpIHtcbiAgICAgIHZtLnRyYW5zZmVyVXNlciA9IHVzZXJEaWFsb2dJbnB1dC50cmFuc2ZlclVzZXJGbjtcbiAgICB9XG5cbiAgICAvLyBpbnN0YW50aWF0ZSBiYXNlIGNvbnRyb2xsZXJcbiAgICAkY29udHJvbGxlcignQ1JVRENvbnRyb2xsZXInLCB7XG4gICAgICB2bTogdm0sXG4gICAgICBtb2RlbFNlcnZpY2U6IFVzZXJzU2VydmljZSxcbiAgICAgIHNlYXJjaE9uSW5pdDogb25Jbml0LFxuICAgICAgb3B0aW9uczoge1xuICAgICAgICBwZXJQYWdlOiA1XG4gICAgICB9XG4gICAgfSk7XG5cbiAgICBmdW5jdGlvbiBvbkFjdGl2YXRlKCkge1xuICAgICAgdm0ucXVlcnlGaWx0ZXJzID0ge307XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gYXBwbHlGaWx0ZXJzKCkge1xuICAgICAgcmV0dXJuIGFuZ3VsYXIuZXh0ZW5kKHZtLmRlZmF1bHRRdWVyeUZpbHRlcnMsIHZtLnF1ZXJ5RmlsdGVycyk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gY2xvc2UoKSB7XG4gICAgICBQckRpYWxvZy5jbG9zZSgpO1xuICAgIH1cblxuICB9XG5cbn0pKCk7XG4iXSwic291cmNlUm9vdCI6Ii9zb3VyY2UvIn0=
