(function () {

  'use strict';

  angular
    .module('app')
    .controller('EstabelecimentosSaudeController', EstabelecimentosSaudeController);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function EstabelecimentosSaudeController($controller, $state, EstabelecimentosSaudeService, TiposEstabelecimentoSaudeService,
    MunicipiosService, EstadosService, NucleosRegionaisService, NaturezasJuridicasService, Auth) {
    var vm = this;
    vm.onActivate = onActivate;
    vm.onMunicipioChange = onMunicipioChange;
    vm.afterClean = afterClean;
    vm.afterEdit = afterEdit;
    vm.applyFilters = applyFilters;
    vm.listarPendencia = listarPendencia;

    //Attributes Block
    vm.GESTOES = {
      GESTAO_DIRETA: 1,
      GESTAO_INDIRETA: 2
    };
    vm.ESTADO = { BAHIA: 1 };

    // instantiate base controller
    $controller('CRUDController', { vm: vm, modelService: EstabelecimentosSaudeService, options: {} });

    //Functions Block
    function onActivate() {
      var user = Auth.currentUser;

      if(user.estabelecimento_saude_id !== null && user.estabelecimento_saude_id !== "" && user.estabelecimento_saude_id !== undefined){
        vm.filters = { estabelecimento_saude_id: user.estabelecimento_saude_id };
      }
      vm.tiposEstabelecimento = TiposEstabelecimentoSaudeService.query().then(function (response) {
        vm.tiposEstabelecimento = response;
      });

      vm.municipios = MunicipiosService.query().then(function (response) {
        vm.municipios = response;
      });

      vm.nucleosRegionais = NucleosRegionaisService.query().then(function (response) {
        vm.nucleosRegionais = response;
      });

      vm.estados = EstadosService.query().then(function (response) {
        vm.estados = response;
      });

      vm.naturezasJuridicas = NaturezasJuridicasService.query().then(function (response) {
        vm.naturezasJuridicas = response;
      });
    }

    function onMunicipioChange() {
      vm.resource.municipio_id = vm.resource.municipio.id;
      vm.resource.nucleo_regional_id = vm.resource.municipio.nucleo_regional_id;
    }

    function afterClean() {
      vm.editando = false;
      vm.resource.estado_id = vm.ESTADO.BAHIA;
    }

    function afterEdit() {
      vm.editando = true;

      angular.forEach(vm.municipios, function (municipio, key) {
        if (vm.resource.municipio_id === municipio.id) {
          vm.resource.municipio = municipio;
          vm.resource.nucleo_regional_id = municipio.nucleo_regional_id;
        }
      });

    }

    function applyFilters(defaultQueryFilters) {
      return angular.extend(defaultQueryFilters, vm.filters);
    }

    function listarPendencia() {
      $state.go('app.relatorio-estabelecimentos-saude');
    }
  }

})();
