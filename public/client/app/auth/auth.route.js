(function() {
  'use strict';

  angular
    .module('app')
    .config(routes);

  /**
   * Arquivo de configuração com as rotas específicas do recurso user
   *
   * @param {any} $stateProvider
   * @param {any} Global
   */
  /** @ngInject */
  function routes($stateProvider, Global) {
    $stateProvider
      .state(Global.resetPasswordState, {
        url: '/password/reset/:token',
        templateUrl: Global.clientPath + '/auth/reset-pass-form.html',
        controller: 'PasswordController as passCtrl',
        data: { needAuthentication: false }
      })
      .state(Global.loginState, {
        url: '/login',
        templateUrl: Global.clientPath + '/auth/login.html',
        controller: 'LoginController as loginCtrl',
        data: { needAuthentication: false }
      });

  }
}());
