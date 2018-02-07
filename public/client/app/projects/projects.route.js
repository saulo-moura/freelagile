(function() {
  'use strict';

  angular
    .module('app')
    .config(routes);

  /**
   * Arquivo de configuração com as rotas específicas do recurso project
   *
   * @param {any} $stateProvider
   * @param {any} Global
   */
  /** @ngInject */
  function routes($stateProvider, Global) {
    $stateProvider
      .state('app.projects', {
        url: '/projects',
        templateUrl: Global.clientPath + '/projects/projects.html',
        controller: 'ProjectsController as projectsCtrl',
        data: { needAuthentication: true },
        params: { obj: null, resource: null }
      });
  }
}());
