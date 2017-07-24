(function() {
  'use strict';

  angular
    .module('app')
    .factory('ProjectsService', ProjectsService);

  /** @ngInject */
  function ProjectsService(serviceFactory) {
    return serviceFactory('projects', {
      actions: { },
      instance: { }
    });
  }

}());
