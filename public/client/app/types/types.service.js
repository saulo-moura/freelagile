(function() {
  'use strict';

  angular
    .module('app')
    .factory('TypesService', TypesService);

  /** @ngInject */
  function TypesService(serviceFactory) {
    var model = serviceFactory('types', {
      actions: { },
      instance: { }
    });

    return model;
  }

}());
