(function() {
  'use strict';

  angular
    .module('app')
    .factory('EspecificacoesService', EspecificacoesService);

  /** @ngInject */
  function EspecificacoesService(serviceFactory) {
    var model = serviceFactory('especificacoes', {
      actions: { },
      instance: { }
    });

    return model;
  }

}());
