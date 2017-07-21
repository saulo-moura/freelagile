(function() {

  'use strict';

  angular
    .module('app')
    .filter('auditType', auditType);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function auditType(lodash, AuditService) {
    return function(typeId) {
      var type = lodash.find(AuditService.listTypes(), { id: typeId });

      return (type) ? type.label : type;
    }
  }

})();
