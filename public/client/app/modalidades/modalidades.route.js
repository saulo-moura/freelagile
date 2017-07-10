(function() {
  'use strict';

  angular
    .module('app')
    .config(routes);

  /**
   * Arquivo de configuração com as rotas específicas do recurso modalidades
   *
   * @param {object} $stateProvider
   * @param {object} Global
   */
  /** @ngInject */
  function routes($stateProvider, Global) {
    $stateProvider
      .state('app.modalidades', {
        url: '/modalidades',
        templateUrl: Global.clientPath + '/modalidades/modalidades.html',
        controller: 'ModalidadesController as modalidadesCtrl',
        data: { }
      });
  }
}());
