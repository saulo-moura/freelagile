(function() {

  'use strict';

  angular
    .module('app')
    .controller('AdicionarCampusController', AdicionarCampusController);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function AdicionarCampusController(locals) {
    var vm = this;

    //Attributes Block
    vm.resource = locals.resource;
    vm.onMunicipioChange = locals.onMunicipioChange;
    vm.buscarCEP = locals.buscarCEP;
    vm.closeDialog = locals.closeDialog;
    vm.municipios = locals.municipios;
    vm.nucleosRegionais = locals.nucleosRegionais;

    vm.save = locals.save;
    vm.cleanForm = locals.cleanForm;
    //Functions Block

  }

})();
