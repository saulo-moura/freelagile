(function() {
  'use strict';

  angular
    .module('app')
    .config(routes);

  /**
   * Arquivo de configuração com as rotas específicas do recurso roles
   *
   * @param {object} $stateProvider
   * @param {object} Global
   */
  /** @ngInject */
  function routes($stateProvider, Global) {
    $stateProvider
      .state('app.roles', {
        url: '/perfil',
        templateUrl: Global.clientPath + '/roles/roles.html',
        controller: 'RolesController as rolesCtrl',
        data: { needAuthentication: true, needPermission: { resource: 'roles' } }
      });
  }
}());
