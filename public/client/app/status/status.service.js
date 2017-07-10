(function() {
  'use strict';

  angular
    .module('app')
    .factory('StatusService', StatusService);

  /** @ngInject */
  function StatusService(serviceFactory) {
    var model = serviceFactory('status', {
      actions: { },
      instance: { }
    });

    return model;
  }

}());
