(function() {
  'use strict';

  angular
    .module('app')
    .factory('InsituicoesEnsinoCursosService', InsituicoesEnsinoCursosService);

  /** @ngInject */
  function InsituicoesEnsinoCursosService(serviceFactory) {
    var model = serviceFactory('insituicoes-ensino-cursos', {
      actions: { },
      instance: { }
    });

    return model;
  }

}());
