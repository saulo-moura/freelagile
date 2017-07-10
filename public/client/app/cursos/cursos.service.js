(function() {
  'use strict';

  angular
    .module('app')
    .factory('CursosService', CursosService);

  /** @ngInject */
  function CursosService(serviceFactory) {
    var model = serviceFactory('cursos', {
      actions: { },
      instance: { }
    });

    return model;
  }

}());
