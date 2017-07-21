(function() {

  'use strict';

  angular
    .module('ngProdeb')
    .filter('prDate', prDate);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function prDate(moment) {
    /**
     * Formata uma data no padrão brasileiro
     */
    return function(value, inputFormat) {
      var outputFormat = 'DD/MM/YYYY';

      if (angular.isDefined(inputFormat)) {
        return moment(value, inputFormat).format(outputFormat);
      } else {
        return moment(value).format(outputFormat);
      }
    }
  }

})();
