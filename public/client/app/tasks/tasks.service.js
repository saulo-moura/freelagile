(function() {
  'use strict';

  angular
    .module('app')
    .factory('TasksService', TasksService);

  /** @ngInject */
  function TasksService(serviceFactory) {
    return serviceFactory('tasks', {
      actions: {
        updateMilestone: {
          method: 'POST',
          url: 'updateMilestone'
        },
        updateTaskByKanban: {
          method: 'POST',
          url: 'updateTaskByKanban'
        }
      },
      instance: { }
    });
  }

}());
