(function() {

  'use strict';

  angular
    .module('app')
    .controller('NaturezasJuridicasController', NaturezasJuridicasController);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function NaturezasJuridicasController($controller, $translate, PrToast, NaturezasJuridicasService) {
    var vm = this;

    vm.onRemoveError = onRemoveError;

    //Attributes Block
    vm.applyFilters = applyFilters;

    //Functions Block
    function applyFilters(defaultQueryFilters) {
      return angular.extend(defaultQueryFilters, vm.filters);
    }

    function onRemoveError(data) {
      var erro = data.error.split('|');

      PrToast.error($translate.instant(erro[0], { entidade: erro[1] }));
    }

    // instantiate base controller
    $controller('CRUDController', { vm: vm, modelService: NaturezasJuridicasService, options: { } });

  }

})();
