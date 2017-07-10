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
      .state('app.project', {
        url: '/projetos',
        templateUrl: Global.clientPath + '/samples/projects/projects.html',
        controller: 'ProjectsController as projectsCtrl',
        data: { needAuthentication: true, needPermission: { resource: 'users' } }
      });
  }
}());
