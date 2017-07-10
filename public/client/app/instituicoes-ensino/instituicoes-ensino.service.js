(function() {
  'use strict';

  angular
    .module('app')
    .factory('InstituicoesEnsinoService', InstituicoesEnsinoService);

  /** @ngInject */
  function InstituicoesEnsinoService(serviceFactory, Global) {
    return serviceFactory('instituicoes-ensino');
  }

}());
