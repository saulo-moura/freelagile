(function() {
  'use strict';

  angular
    .module('app')
    .factory('TiposEstabelecimentoSaudeService', TiposEstabelecimentoSaudeService);

  /** @ngInject */
  function TiposEstabelecimentoSaudeService(serviceFactory) {
    var model = serviceFactory('tipos-estabelecimento-saude', {
      actions: { },
      instance: { }
    });

    return model;
  }

}());
