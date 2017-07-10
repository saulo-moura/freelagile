(function () {
  'use strict';

  angular
    .module('app')
    .factory('CepService', CepService);

  /** @ngInject */
  function CepService($http) {

    return {
      getCEP: function (cep) {
        return $http({
          method: 'GET', url: 'http://correiosapi.apphb.com/cep/' + cep, headers: {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, X-Requested-With',
          }
        });
      }
    }
  }

}());
