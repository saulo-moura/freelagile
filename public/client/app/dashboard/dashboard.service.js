(function() {
  'use strict';

  angular
    .module('app')
    .factory('DashboardsService', DashboardsService);

  /** @ngInject */
  function DashboardsService(serviceFactory) {
    return serviceFactory('dashboards', {
      actions: { },
      instance: { }
    });
  }

}());
