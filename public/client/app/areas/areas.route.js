(function() {
  'use strict';

  angular
    .module('app')
    .config(routes);

  /**
   * Arquivo de configuração com as rotas específicas do recurso areas
   *
   * @param {object} $stateProvider
   * @param {object} Global
   */
  /** @ngInject */
  function routes($stateProvider, Global) {
    $stateProvider
      .state('app.areas', {
        url: '/areas',
        templateUrl: Global.clientPath + '/areas/areas.html',
        controller: 'AreasController as areasCtrl',
        data: { }
      });
  }
}());
