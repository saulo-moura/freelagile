(function() {
  'use strict';

  angular
    .module('app')
    .factory('VagasService', VagasService);

  /** @ngInject */
  function VagasService(serviceFactory) {
    var model = serviceFactory('vagas', {
      actions: { 
        getHistorico: {
          method: 'GET',
          url: 'historico'
        }
      },
      instance: { }
    });

    return model;
  }

}());
