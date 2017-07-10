(function() {
  'use strict';

  angular
    .module('app')
    .config(routes);

  /**
   * Arquivo de configuração com as rotas específicas do recurso relatorio-estabelecimentos-saude
   *
   * @param {object} $stateProvider
   * @param {object} Global
   */
  /** @ngInject */
  function routes($stateProvider, Global) {
    $stateProvider
      .state('app.relatorio-estabelecimentos-saude', {
        url: '/relatorio-estabelecimentos-saude',
        templateUrl: Global.clientPath + '/relatorio-estabelecimentos-saude/relatorio-estabelecimentos-saude.html',
        controller: 'RelatorioEstabelecimentosSaudeController as relatorioEstabelecimentosSaudeCtrl',
        data: { needAuthentication: true, needPermission: { resource: 'estabelecimentosSaude' } }
      });
  }
}());
