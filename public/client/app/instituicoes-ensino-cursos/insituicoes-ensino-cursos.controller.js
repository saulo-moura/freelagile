(function () {

  'use strict';

  angular
    .module('app')
    .controller('InsituicoesEnsinoCursosController', InsituicoesEnsinoCursosController);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function InsituicoesEnsinoCursosController($controller, locals, InsituicoesEnsinoCursosService, $mdDialog, CursosService, CampusService) {
    var vm = this;
    vm.closeDialog = closeDialog;
    vm.beforeSearch = beforeSearch;
    vm.onActivate = onActivate;

    //Attributes Block
    vm.resource = locals.resource;

    //Functions Block
    function onActivate() {

      vm.cursos = CursosService.query().then(function (response) {
        vm.cursos = response;
      });
      vm.campus = CampusService.query({instituicao_ensino_id : locals.instituicao_ensino_id}).then(function (response) {
        vm.campi = response;
        console.log(response);
        console.log(vm.campi);
      });
    }
    // Fechar modal
    function closeDialog() {
      $mdDialog.cancel();
    }

    function beforeSearch() {
      return false;
    }
    // instantiate base controller
    $controller('CRUDController', { vm: vm, modelService: InsituicoesEnsinoCursosService, options: {} });

  }

})();
