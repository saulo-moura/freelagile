(function() {
  'use strict';

  angular
    .module('app')
    .config(routes);

  /**
   * Arquivo de configuração com as rotas específicas do recurso relatorioDisponibilidadeVagas
   *
   * @param {object} $stateProvider
   * @param {object} Global
   */
  /** @ngInject */
  function routes($stateProvider, Global) {
    $stateProvider
      .state('app.relatorio-disponibilidade-vagas', {
        url: '/relatorio-disponibilidade-vagas',
        templateUrl: Global.clientPath + '/relatorio-disponibilidade-vagas/relatorio-disponibilidade-vagas.html',
        controller: 'RelatorioDisponibilidadeVagasController as relatorioDisponibilidadeVagasCtrl',
        data: { }
      });
  }
}());
