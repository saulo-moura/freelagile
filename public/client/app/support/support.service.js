(function() {
  'use strict';

  angular
    .module('app')
    .factory('SupportService', SupportService);

  /** @ngInject */
  function SupportService(serviceFactory) {
    return serviceFactory('support', {
      actions: {
      /**
       * Pega as traduções que estão no servidor
       *
       * @returns {promise} Uma promise com o resultado do chamada no backend
       */
        langs: {
          method: 'GET',
          url: 'langs',
          wrap: false,
          cache: true
        }
      }
    });
  }

}());
