(function() {
  'use strict';

  angular
    .module('app')
    .factory('CampusService', CampusService);

  /** @ngInject */
  function CampusService(serviceFactory) {
    var model = serviceFactory('campus', {
      actions: { },
      instance: { }
    });

    return model;
  }

}());
