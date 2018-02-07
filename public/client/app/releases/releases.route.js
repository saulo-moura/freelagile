(function() {
  'use strict';

  angular
    .module('app')
    .config(routes);

  /**
   * Arquivo de configuração com as rotas específicas do recurso releases
   *
   * @param {object} $stateProvider
   * @param {object} Global
   */
  /** @ngInject */
  function routes($stateProvider, Global) {
    $stateProvider
      .state('app.releases', {
        url: '/releases',
        templateUrl: Global.clientPath + '/releases/releases.html',
        controller: 'ReleasesController as releasesCtrl',
        data: { }
      });
  }
}());
