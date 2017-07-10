(function() {
  'use strict';

  angular
    .module('app')
    .config(routes);

  /**
   * Arquivo de configuração com as rotas específicas do recurso tiposestabelecimentosaude
   *
   * @param {object} $stateProvider
   * @param {object} Global
   */
  /** @ngInject */
  function routes($stateProvider, Global) {
    $stateProvider
      .state('app.tipos-estabelecimento-saude', {
        url: '/tipos-estabelecimento-saude',
        templateUrl: Global.clientPath + '/tipos-estabelecimento-saude/tipos-estabelecimento-saude.html',
        controller: 'TiposEstabelecimentoSaudeController as tiposEstabelecimentoSaudeCtrl',
        data: { }
      });
  }
}());
