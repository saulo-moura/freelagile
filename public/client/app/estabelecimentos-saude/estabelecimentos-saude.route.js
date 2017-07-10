(function() {
  'use strict';

  angular
    .module('app')
    .config(routes);

  /**
   * Arquivo de configuração com as rotas específicas do recurso estabelecimentos-saude
   *
   * @param {object} $stateProvider
   * @param {object} Global
   */
  /** @ngInject */
  function routes($stateProvider, Global) {
    $stateProvider
      .state('app.estabelecimentos-saude', {
        url: '/estabelecimentos-saude',
        templateUrl: Global.clientPath + '/estabelecimentos-saude/estabelecimentos-saude.html',
        controller: 'EstabelecimentosSaudeController as estabelecimentosSaudeCtrl',
        data: { needAuthentication: true, needPermission: { resource: 'estabelecimentosSaude' } }
      });
  }
}());
