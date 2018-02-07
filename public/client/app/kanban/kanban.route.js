(function() {
  'use strict';

  angular
    .module('app')
    .config(routes);

  /**
   * Arquivo de configuração com as rotas específicas do recurso kanban
   *
   * @param {object} $stateProvider
   * @param {object} Global
   */
  /** @ngInject */
  function routes($stateProvider, Global) {
    $stateProvider
      .state('app.kanban', {
        url: '/kanban',
        templateUrl: Global.clientPath + '/kanban/kanban.html',
        controller: 'KanbanController as kanbanCtrl',
        data: { }
      });
  }
}());
