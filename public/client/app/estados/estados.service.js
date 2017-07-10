(function() {
  'use strict';

  angular
    .module('app')
    .factory('EstadosService', EstadosService);

  /** @ngInject */
  function EstadosService(serviceFactory) {
    return serviceFactory('estados');
  }

}());
