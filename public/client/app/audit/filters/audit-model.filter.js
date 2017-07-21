(function() {

  'use strict';

  angular
    .module('app')
    .filter('auditModel', auditModel);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function auditModel($translate) {
    return function(modelId) {
      modelId = modelId.replace('App\\', '');
      var model = $translate.instant('models.' + modelId.toLowerCase());

      return (model) ? model : modelId;
    }
  }

})();
