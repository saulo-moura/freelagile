(function() {
  'use strict';

  angular
    .module('app')
    .factory('ResourceAuthorizationService', ResourceAuthorizationService);

  /** @ngInject */
  function ResourceAuthorizationService(serviceFactory, PrToast) {
    var model = serviceFactory('authorization/resources', {
      actions: { base: { afterRequest: afterRequest } },
      instance: { },
      afterRequest: afterRequest
    });

    function afterRequest(response) {
      if (response.permissionError) {
        PrToast.error(response.error);
      }
      return response.items;
    }

    return model;
  }

}());
