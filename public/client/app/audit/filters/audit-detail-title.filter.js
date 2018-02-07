(function() {

  'use strict';

  angular
    .module('app')
    .filter('auditDetailTitle', auditDetailTitle);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function auditDetailTitle($translate) {
    return function(auditDetail, status) {
      if (auditDetail.type === 'updated') {
        if (status === 'before') {
          return $translate.instant('dialog.audit.updatedBefore');
        } else {
          return $translate.instant('dialog.audit.updatedAfter');
        }
      } else {
        return $translate.instant('dialog.audit.' + auditDetail.type);
      }
    }
  }

})();
