(function() {
  'use strict';

  angular
    .module('app')
    .factory('ModalidadesService', ModalidadesService);

  /** @ngInject */
  function ModalidadesService(serviceFactory) {
    var model = serviceFactory('modalidades', {
      actions: { },
      instance: { }
    });

    return model;
  }

}());
