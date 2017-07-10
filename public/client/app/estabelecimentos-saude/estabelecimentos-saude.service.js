(function() {
  'use strict';

  angular
    .module('app')
    .factory('EstabelecimentosSaudeService', EstabelecimentosSaudeService);

  /** @ngInject */
  function EstabelecimentosSaudeService(serviceFactory) {
    var model =  serviceFactory('estabelecimentos-saude', {
      actions: { },
      instance: { }
    });

    return model;
  }

}());
