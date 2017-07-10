(function() {
  'use strict';

  angular
    .module('app')
    .factory('RelatorioDisponibilidadeVagasService', RelatorioDisponibilidadeVagasService);

  /** @ngInject */
  function RelatorioDisponibilidadeVagasService(serviceFactory) {
    var model = serviceFactory('relatorio-disponibilidade-vagas', {
      actions: { },
      instance: { }
    });

    return model;
  }

}());
