(function() {
  'use strict';

  angular
    .module('app')
    .config(routes);

  /**
   * Arquivo de configuração com as rotas específicas do recurso project
   *
   * @param {any} $stateProvider
   * @param {any} Global
   */
  /** @ngInject */
  function routes($stateProvider, Global) {
    $stateProvider
      .state('app.dashboard', {
        url: '/dashboards',
        templateUrl: Global.clientPath + '/dashboard/dashboard.html',
        controller: 'DashboardController as dashboardCtrl',
        data: { needAuthentication: true}
      });
  }
}());
