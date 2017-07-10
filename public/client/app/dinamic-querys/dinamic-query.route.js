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
      .state('app.dinamic-query', {
        url: '/consultas-dinamicas',
        templateUrl: Global.clientPath + '/dinamic-querys/dinamic-querys.html',
        controller: 'DinamicQuerysController as dinamicQueryCtrl',
        data: { needAuthentication: true, needPermission: { resource: 'dataInspection' } }
      });

  }
}());
