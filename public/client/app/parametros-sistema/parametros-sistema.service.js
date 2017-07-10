(function() {
  'use strict';

  angular
    .module('app')
    .factory('ParametrossistemaService', ParametrossistemaService);

  /** @ngInject */
  function ParametrossistemaService(serviceFactory) {
    var model = serviceFactory('parametros-sistema', {
      actions: { },
      instance: { }
    });

    return model;
  }

}());
