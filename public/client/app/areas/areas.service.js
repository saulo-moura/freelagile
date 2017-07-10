(function() {
  'use strict';

  angular
    .module('app')
    .factory('AreasService', AreasService);

  /** @ngInject */
  function AreasService(serviceFactory) {
    var model = serviceFactory('areas', {
      actions: { },
      instance: { }
    });

    return model;
  }

}());
