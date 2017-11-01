(function() {
  'use strict';

  angular
    .module('app')
    .factory('TasksService', TasksService);

  /** @ngInject */
  function TasksService(serviceFactory) {
    return serviceFactory('tasks', {
      actions: { },
      instance: { }
    });
  }

}());
