(function() {
  'use strict';

  angular
    .module('app')
    .factory('KanbanService', KanbanService);

  /** @ngInject */
  function KanbanService(serviceFactory) {
    var model = serviceFactory('kanban', {
      actions: { },
      instance: { }
    });

    return model;
  }

}());
