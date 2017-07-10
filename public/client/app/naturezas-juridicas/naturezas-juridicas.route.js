(function() {
  'use strict';

  angular
    .module('app')
    .config(routes);

  /**
   * Arquivo de configuração com as rotas específicas do recurso naturezajuridica
   *
   * @param {object} $stateProvider
   * @param {object} Global
   */
  /** @ngInject */
  function routes($stateProvider, Global) {
    $stateProvider
      .state('app.naturezas-juridicas', {
        url: '/naturezas-juridicas',
        templateUrl: Global.clientPath + '/naturezas-juridicas/naturezas-juridicas.html',
        controller: 'NaturezasJuridicasController as naturezasJuridicasCtrl',
        data: { needAuthentication: true, needPermission: { resource: 'naturezasJuridicas' } }
      });
  }
}());
