(function() {

  'use strict';

  angular
    .module('ngProdeb')
    .filter('real', real);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function real($filter) {
    /**
     * Formata um valor para o padrão brasileiro
     */
    return function(value) {
      return $filter('currency')(value, 'R$ ');
    }
  }

})();
