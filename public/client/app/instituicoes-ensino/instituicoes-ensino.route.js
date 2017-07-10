(function() {
  'use strict';

  angular
    .module('app')
    .config(routes);

  /**
   * Arquivo de configuração com as rotas específicas do recurso instituicaoensino
   *
   * @param {object} $stateProvider
   * @param {object} Global
   */
  /** @ngInject */
  function routes($stateProvider, Global) {
    $stateProvider
      .state('app.instituicoes-ensino', {
        url: '/instituicoes-ensino',
        templateUrl: Global.clientPath + '/instituicoes-ensino/instituicoes-ensino.html',
        controller: 'InstituicoesEnsinoController as iesCtrl',
        data: { }
      });
  }
}());
