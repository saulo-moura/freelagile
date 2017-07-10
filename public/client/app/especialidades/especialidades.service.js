(function() {
  'use strict';

  angular
    .module('app')
    .factory('EspecialidadesService', EspecialidadesService);

  /** @ngInject */
  function EspecialidadesService(serviceFactory) {
    var model = serviceFactory('especialidades', {
      actions: { },
      instance: { }
    });

    return model;
  }

}());
