(function() {
  'use strict';

  angular.module('ngProdeb')
    .factory('PrSpinner', spinnerService);

  /** @ngInject */
  function spinnerService($rootScope) {
    return {
      show: show,
      hide: hide
    };

    /**
     * Exibe o spinner
     */
    function show() {
      //emite o sinal para a diretiva informando que o componente spinner deve ser exibido
      $rootScope.$broadcast('show-spinner');
    }


    /**
     * Esconde o spinner
     */
    function hide() {
      $rootScope.$broadcast('hide-spinner');
    }
  }

})();
