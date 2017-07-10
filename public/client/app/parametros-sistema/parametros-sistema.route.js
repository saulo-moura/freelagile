(function() {
  'use strict';

  angular
    .module('app')
    .config(routes);

  /**
   * Arquivo de configuração com as rotas específicas do recurso parametrossistema
   *
   * @param {object} $stateProvider
   * @param {object} Global
   */
  /** @ngInject */
  function routes($stateProvider, Global) {
    $stateProvider
      .state('app.parametros-sistema', {
        url: '/parametros-sistema',
        templateUrl: Global.clientPath + '/parametros-sistema/parametros-sistema.html',
        controller: 'ParametrossistemaController as parametrossistemaCtrl',
        data: { needAuthentication: true, needPermission: { resource: 'parametrosSistema' } }
      });
  }
}());
