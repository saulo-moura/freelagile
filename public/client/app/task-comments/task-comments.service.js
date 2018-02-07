(function() {
  'use strict';

  angular
    .module('app')
    .factory('TaskCommentsService', TaskCommentsService);

  /** @ngInject */
  function TaskCommentsService(serviceFactory) {
    var model = serviceFactory('task-comments', {
      actions: {
        saveTaskComment: {
          method: 'POST',
          url: 'saveTaskComment'
        },
        removeTaskComment: {
          method: 'POST',
          url: 'removeTaskComment'
        }
      },
      instance: { }
    });

    return model;
  }

}());
