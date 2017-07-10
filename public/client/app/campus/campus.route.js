(function() {
  'use strict';

  angular
    .module('app')
    .config(routes);

  /**
   * Arquivo de configuração com as rotas específicas do recurso campus
   *
   * @param {object} $stateProvider
   * @param {object} Global
   */
  /** @ngInject */
  function routes($stateProvider, Global) {
    $stateProvider
      .state('app.campus', {
        url: '/campus',
        templateUrl: Global.clientPath + '/campus/campus.html',
        controller: 'CampusController as campusCtrl',
        data: { }
      });
  }
}());
