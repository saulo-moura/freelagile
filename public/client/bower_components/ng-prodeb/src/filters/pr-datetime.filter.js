(function() {

  'use strict';

  angular
    .module('ngProdeb')
    .filter('prDatetime', prDatetime);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function prDatetime(moment) {
    /**
     * Formata uma data com horário no padrão brasileiro
     */
    return function(value) {
      return moment(value).format('DD/MM/YYYY HH:mm');
    }
  }

})();
