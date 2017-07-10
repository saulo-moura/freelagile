(function() {
  'use strict';

  angular
    .module('app')
    .config(routes);

  /**
   * Arquivo de configuração com as rotas específicas de auditoria
   *
   * @param {any} $stateProvider
   * @param {any} Global
   */
  /** @ngInject */
  function routes($stateProvider, Global) {
    $stateProvider
      .state('app.audit', {
        url: '/auditoria',
        templateUrl: Global.clientPath + '/audit/audit.html',
        controller: 'AuditController as auditCtrl',
        data: { needAuthentication: true, needPermission: { resource: 'audit' } }
      });

  }
}());
