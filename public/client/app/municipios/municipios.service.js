(function() {
  'use strict';

  angular
    .module('app')
    .factory('MunicipiosService', MunicipiosService);

  /** @ngInject */
  function MunicipiosService(serviceFactory) {
    return serviceFactory('municipios');
  }

}());
