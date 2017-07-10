(function() {
  'use strict';

  angular
    .module('app')
    .factory('NaturezasJuridicasService', NaturezasJuridicasService);

  /** @ngInject */
  function NaturezasJuridicasService(serviceFactory) {
    var model = serviceFactory('naturezas-juridicas', {
      actions: { },
      instance: { }
    });

    return model;
  }

}());
