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
      .state('app.tasks', {
        url: '/tasks',
        templateUrl: Global.clientPath + '/tasks/tasks.html',
        controller: 'TasksController as tasksCtrl',
        data: { needAuthentication: true}
      });
  }
}());
