(function() {
  'use strict';

  angular
    .module('app')
    .factory('RelatorioEstabelecimentosSaudeService', RelatorioEstabelecimentosSaudeService);

  /** @ngInject */
  function RelatorioEstabelecimentosSaudeService(serviceFactory) {
    var model = serviceFactory('relatorio-estabelecimentos-saude', {
      actions: { },
      instance: { }
    });

    return model;
  }

}());
