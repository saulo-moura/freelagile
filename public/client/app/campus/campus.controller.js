(function() {

  'use strict';
  angular
    .module('app')
    .controller('CampusController', CampusController);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function CampusController($controller, CampusService, MunicipiosService, NucleosRegionaisService,
  CepService, Auth, $mdDialog, $document, PrToast, $translate, $rootScope) {
    var vm = this;

    vm.onMunicipioChange = onMunicipioChange;
    vm.buscarCEP = buscarCEP;
    vm.beforeSave = beforeSave;
    vm.afterSave = afterSave;
    vm.closeDialog = closeDialog;
    vm.editarCampus = editarCampus;
    vm.onSaveError = onSaveError;
    vm.cadastrarCampus = cadastrarCampus;
    vm.onActivate = onActivate;

    //Attributes Block

    // Configurações do dialog para a alteração do campus
    vm.editarCampusDialog = {
      parent: angular.element($document.body),
      templateUrl: 'client/app/campus/campus-form.html',
      controllerAs: 'campusCtrl',
      controller: 'EditarCampusController',
      escapeToClose: true,
      locals: {
      }
    }

    // Configurações do dialog para o cadastro do campus
    vm.cadastrarCampusDialog = {
      parent: angular.element($document.body),
      templateUrl: 'client/app/campus/campus-form.html',
      controllerAs: 'campusCtrl',
      controller: 'AdicionarCampusController',
      escapeToClose: true,
      locals: {
      }
    }

     // abrir modal editar campus
    function editarCampus(resource) {
      vm.resource = resource;
      vm.editarCampusDialog.locals = vm;
      $mdDialog.show(vm.editarCampusDialog);
    }

    //Functions Block
    function onActivate() {
      vm.municipios = MunicipiosService.query().then(function (response) {
        vm.municipios = response;
      });

      vm.nucleosRegionais = NucleosRegionaisService.query().then(function (response) {
        vm.nucleosRegionais = response;
      });
    }

    function onMunicipioChange() {
      vm.resource.municipio_id = vm.resource.municipio.id;
      vm.resource.nucleo_regional_id = vm.resource.municipio.nucleo_regional_id;
    }

    function buscarCEP() {
      CepService.getCEP(vm.resource.cep).then(function(response) {
        vm.resource.endereco = response.data.tipoDeLogradouro + ' ' + response.data.logradouro;
        vm.resource.bairro = response.data.bairro;
      });
    }

    function beforeSave() {
      vm.resource.instituicao_ensino_id = $rootScope.instituicao_ensino_id;
    }

    // Fechar modal
    function closeDialog() {
      $mdDialog.cancel();
    }

    function onSaveError(data) {
      PrToast.error($translate.instant(data.error));
    }

    function afterSave() {
      closeDialog();
    }

    // Modal de cadastro de campus
    function cadastrarCampus() {
      vm.cleanForm();
      vm.cadastrarCampusDialog.locals = vm;
      $mdDialog.show(vm.cadastrarCampusDialog);
    }

    // instantiate base controller
    $controller('CRUDController', { vm: vm, modelService: CampusService, options: { } });
  }

})();
