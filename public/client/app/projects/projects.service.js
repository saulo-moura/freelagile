(function() {
  'use strict';

  angular
    .module('app')
    .factory('ProjectsService', ProjectsService);

  /** @ngInject */
  function ProjectsService(serviceFactory) {
    return serviceFactory('projects', {
      actions: {
        finalize: {
          method: 'POST',
          url: 'finalize'
        },
        verifyReleases: {
          method: 'POST',
          url: 'verifyReleases'
        }
      },
      instance: { }
    });
  }

}());
