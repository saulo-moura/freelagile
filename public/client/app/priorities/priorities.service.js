(function() {
  'use strict';

  angular
    .module('app')
    .factory('PrioritiesService', PrioritiesService);

  /** @ngInject */
  function PrioritiesService(serviceFactory) {
    var model = serviceFactory('priorities', {
      actions: { },
      instance: { }
    });

    return model;
  }

}());
