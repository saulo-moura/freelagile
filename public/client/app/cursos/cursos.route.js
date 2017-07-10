(function() {
  'use strict';

  angular
    .module('app')
    .config(routes);

  /**
   * Arquivo de configuração com as rotas específicas do recurso cursos
   *
   * @param {object} $stateProvider
   * @param {object} Global
   */
  /** @ngInject */
  function routes($stateProvider, Global) {
    $stateProvider
      .state('app.cursos', {
        url: '/cursos',
        templateUrl: Global.clientPath + '/cursos/cursos.html',
        controller: 'CursosController as cursosCtrl',
        data: { }
      });
  }
}());
