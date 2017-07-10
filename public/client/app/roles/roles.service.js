(function() {
  'use strict';

  angular
    .module('app')
    .factory('RolesService', RolesService);

  /** @ngInject */
  function RolesService(serviceFactory) {
    return serviceFactory('roles');
  }

}());
