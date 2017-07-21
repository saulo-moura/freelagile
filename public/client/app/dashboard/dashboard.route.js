(function() {
  'use strict';

  angular
    .module('app')
    .config(routes);

  /**
   * Arquivo de configuração com as rotas específicas do dashboard
   *
   * @param {any} $stateProvider
   * @param {any} Global
   */
  /** @ngInject */
  function routes($stateProvider, Global) {
    $stateProvider
      .state(Global.homeState, {
        url: '/dashboard',
        templateUrl: Global.clientPath + '/dashboard/dashboard.html',
        controller: 'DashboardController as dashboardCtrl',
        data: { needAuthentication: true }
      })
  }
}());
