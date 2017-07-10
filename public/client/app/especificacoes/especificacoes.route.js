(function() {
  'use strict';

  angular
    .module('app')
    .config(routes);

  /**
   * Arquivo de configuração com as rotas específicas do recurso especificacoes
   *
   * @param {object} $stateProvider
   * @param {object} Global
   */
  /** @ngInject */
  function routes($stateProvider, Global) {
    $stateProvider
      .state('app.especificacoes', {
        url: '/especificacoes',
        templateUrl: Global.clientPath + '/especificacoes/especificacoes.html',
        controller: 'EspecificacoesController as especificacoesCtrl',
        data: { }
      });
  }
}());
