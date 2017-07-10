(function() {

  'use strict';

  angular
    .module('app')
    .controller('EditarCampusController', EditarCampusController);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function EditarCampusController(locals) {
    var vm = this;

    vm.resource = locals.resource;
    vm.onMunicipioChange = locals.onMunicipioChange;
    vm.buscarCEP = locals.buscarCEP;
    vm.closeDialog = locals.closeDialog;
    vm.municipios = locals.municipios;

    vm.resource.nucleo_regional_id = vm.resource.municipio.nucleo_regional_id;
    vm.nucleosRegionais = locals.nucleosRegionais;

    vm.save = locals.save;
    vm.cleanForm = locals.cleanForm;
  }

})();
