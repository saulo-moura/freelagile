(function() {
  'use strict';

  angular
    .module('app')
    .config(routes);

  /**
   * Arquivo de configuração com as rotas específicas do recurso especialidades
   *
   * @param {object} $stateProvider
   * @param {object} Global
   */
  /** @ngInject */
  function routes($stateProvider, Global) {
    $stateProvider
      .state('app.especialidades', {
        url: '/especialidades',
        templateUrl: Global.clientPath + '/especialidades/especialidades.html',
        controller: 'EspecialidadesController as especialidadesCtrl',
        data: { }
      });
  }
}());
