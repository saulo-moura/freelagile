(function() {
  'use strict';

  angular
    .module('app')
    .config(routes);

  /**
   * Arquivo de configuração com as rotas específicas do recurso vcs
   *
   * @param {object} $stateProvider
   * @param {object} Global
   */
  /** @ngInject */
  function routes($stateProvider, Global) {
    $stateProvider
      .state('app.vcs', {
        url: '/vcs',
        templateUrl: Global.clientPath + '/vcs/vcs.html',
        controller: 'VcsController as vcsCtrl',
        data: { }
      });
  }
}());
