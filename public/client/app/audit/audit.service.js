(function() {
  'use strict';

  angular
    .module('app')
    .factory('AuditService', AuditService);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function AuditService(serviceFactory, $translate) {
    return serviceFactory('audit', {
      actions: {
        getAuditedModels: {
          method: 'GET',
          url: 'models'
        }
      },
      instance: {
      },
      listTypes: function() {
        var auditPath = 'views.fields.audit.';

        return [
          { id: '', label: $translate.instant(auditPath + 'allResources') },
          { id: 'created', label: $translate.instant(auditPath + 'type.created') },
          { id: 'updated', label: $translate.instant(auditPath + 'type.updated') },
          { id: 'deleted', label: $translate.instant(auditPath + 'type.deleted') }
        ];
      }
    });
  }

}());
