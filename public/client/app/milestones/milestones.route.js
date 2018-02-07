(function() {
  'use strict';

  angular
    .module('app')
    .config(routes);

  /**
   * Arquivo de configuração com as rotas específicas do recurso milestones
   *
   * @param {object} $stateProvider
   * @param {object} Global
   */
  /** @ngInject */
  function routes($stateProvider, Global) {
    $stateProvider
      .state('app.milestones', {
        url: '/milestones',
        templateUrl: Global.clientPath + '/milestones/milestones.html',
        controller: 'MilestonesController as milestonesCtrl',
        data: { }
      });
  }
}());
