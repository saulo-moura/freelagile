(function() {
  'use strict';

  angular
    .module('app')
    .factory('ReleasesService', ReleasesService);

  /** @ngInject */
  function ReleasesService(serviceFactory) {
    var model = serviceFactory('releases', {
      actions: {
        finalize: {
          method: 'POST',
          url: 'finalize'
        }
      },
      instance: { }
    });

    return model;
  }

}());
