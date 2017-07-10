(function() {
  'use strict';

  angular
    .module('app')
    .config(routes);

  /**
   * Arquivo de configuração com as rotas específicas do recurso setores
   *
   * @param {object} $stateProvider
   * @param {object} Global
   */
  /** @ngInject */
  function routes($stateProvider, Global) {
    $stateProvider
      .state('app.setores', {
        url: '/setores',
        templateUrl: Global.clientPath + '/setores/setores.html',
        controller: 'SetoresController as setoresCtrl',
        data: { needAuthentication: true, needPermission: { resource: 'setores' } }
      });
  }
}());
