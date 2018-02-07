(function() {
  'use strict';

  angular
    .module('app')
    .factory('VcsService', VcsService);

  /** @ngInject */
  function VcsService(serviceFactory) {
    var model = serviceFactory('vcs', {
      actions: { },
      instance: { }
    });

    return model;
  }

}());
