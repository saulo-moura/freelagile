(function() {
  'use strict';

  angular
    .module('app')
    .factory('SetoresService', SetoresService);

  /** @ngInject */
  function SetoresService(serviceFactory) {
    var model = serviceFactory('setores', {
      actions: { },
      instance: { }
    });

    return model;
  }

}());
