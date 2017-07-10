(function() {
  'use strict';

  angular
    .module('app')
    .factory('NucleosRegionaisService', NucleosRegionaisService);

  /** @ngInject */
  function NucleosRegionaisService(serviceFactory) {
    return serviceFactory('nucleos-regionais');
  }

}());
