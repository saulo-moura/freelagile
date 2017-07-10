(function() {
  'use strict';

  angular
    .module('app')
    .config(routes);

  /**
   * Arquivo de configuração com as rotas específicas do recurso vagas
   *
   * @param {object} $stateProvider
   * @param {object} Global
   */
  /** @ngInject */
  function routes($stateProvider, Global) {
    $stateProvider
      .state('app.vagas', {
        url: '/vagas',
        templateUrl: Global.clientPath + '/vagas/vagas.html',
        controller: 'VagasController as vagasCtrl',
        data: { needAuthentication: true, needPermission: { resource: 'vagas' } }
      })
      .state('app.vagas-agenda-impressao', {
        url: '/vagas/agenda-impressao/:id',
        templateUrl: Global.clientPath + '/vagas/agenda-impressao/agenda-impressao.html',
        controller: 'AgendaImpressaoController as agendaImpressaoCtrl',
        data: { needAuthentication: true, needPermission: { resource: 'vagas' }  }
      });
  }
}());
