(function () {

  'use strict';

  angular
    .module('app')
    .controller('InstituicoesEnsinoController', InstituicoesEnsinoController);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function InstituicoesEnsinoController($controller, InstituicoesEnsinoService, MunicipiosService,
  NucleosRegionaisService, UploadService, $document, $mdDialog, PrToast, Auth, $rootScope) {
    var vm = this;

    vm.onActivate = onActivate;
    vm.afterEdit = afterEdit;
    vm.applyFilters = applyFilters;
    vm.onMunicipioChange = onMunicipioChange;
    vm.uploadArquivosIES = uploadArquivosIES;
    vm.excluirArquivosIES = excluirArquivosIES;
    vm.cadastrarCampus = cadastrarCampus;
    vm.cadastrarCurso = cadastrarCurso;

    //Attributes Block
    vm.naturezasJuridicas = [
      { id: 3, nome: "Pública Federal" },
      { id: 4, nome: "Pública Estadual" },
      { id: 5, nome: "Privada com Fins Lucrativos" },
      { id: 6, nome: "Privada sem Fins Lucrativos" }
    ];
    vm.cursoLocals = {};
    // Configurações do dialog para o cadastro do campus
    vm.cadastrarCampusDialog = {
      parent: angular.element($document.body),
      templateUrl: 'client/app/campus/campus-form.html',
      controllerAs: 'campusCtrl',
      controller: 'CampusController',
      escapeToClose: true
    }

    // Configurações do dialog para o cadastro do cursos
    vm.cadastrarCursosDialog = {
      parent: angular.element($document.body),
      templateUrl: 'client/app/instituicoes-ensino-cursos/instituicoes-ensino-cursos-form.html',
      controllerAs: 'iesCursosCtrl',
      controller: 'InsituicoesEnsinoCursosController',
      locals: vm.cursoLocals,
      escapeToClose: true
    }

    //Functions Block
    function onActivate() {
      var user = Auth.currentUser;

      if(user.instituicao_ensino_id !== null && user.instituicao_ensino_id !== "" && user.instituicao_ensino_id !== undefined){
        vm.filters = { instituicao_ensino_id: user.instituicao_ensino_id };
      }
      vm.municipios = MunicipiosService.query().then(function (response) {
        vm.municipios = response;
      });

      vm.nucleosRegionais = NucleosRegionaisService.query().then(function (response) {
        vm.nucleosRegionais = response;
      });

    }

    function afterEdit() {
      //PREPARA OS CAMPOS DE UPLOAD
      delete vm.diarioOficialUniao;
      delete vm.alvaraFuncionamento;
      delete vm.atestadoFuncionamentoRegular;
      vm.diarioOficialUniao = [];
      vm.alvaraFuncionamento = [];
      vm.atestadoFuncionamentoRegular = [];

      //Carrega municipio
      if (vm.resource.municipio_id) {
        angular.forEach(vm.municipios, function (municipio) {
          if (municipio.id === vm.resource.municipio_id) {
            vm.resource.municipio = municipio;
          }
        });
      }

      $rootScope.instituicao_ensino_id = vm.resource.id;
    }

    function onMunicipioChange() {
      vm.resource.municipio_id = vm.resource.municipio.id;
      vm.resource.nucleo_regional_id = vm.resource.municipio.nucleo_regional_id;
    }

    function uploadArquivosIES(tipoArquivo) {
      var formData = new FormData();
      var arquivos = [];
      formData.append('tipoArquivo', tipoArquivo);
      switch (tipoArquivo) {
        case 'diario_oficial_uniao':
          arquivos = vm.diarioOficialUniao;
          break;
        case 'alvara_funcionamento':
          arquivos = vm.alvaraFuncionamento;
          break;
        case 'atestado_funcionamento_regular':
          arquivos = vm.atestadoFuncionamentoRegular;
          break;
      }
      formData.append('arquivo', arquivos[0].lfFile);

      UploadService.uploadArquivosIES(vm.resource.id, formData).then(function (result) {
        vm.resource[tipoArquivo] = result.data.nomeArquivo;
        removeArquivoPreUpload(tipoArquivo);
      });
    }

    function excluirArquivosIES(tipoArquivo) {
      var formData = new FormData();
      formData.append('tipoArquivo', tipoArquivo);
      UploadService.excluirArquivosIES(vm.resource.id, formData).then(function (result) {
        delete vm.resource[tipoArquivo];
      }, function () {
          PrToast.error('Houve um erro ao realizar a exclusão do arquivo.');
      });
    }



    function removeArquivoPreUpload(tipoArquivo) {
      switch (tipoArquivo) {
        case 'diario_oficial_uniao':
          vm.diarioOficialUniao = [];
          break;
        case 'alvara_funcionamento':
          vm.alvaraFuncionamento = [];
          break;
        case 'atestado_funcionamento_regular':
          vm.atestadoFuncionamentoRegular = [];
          break;
      }
    }


    // Modal de cadastro de campus
    function cadastrarCampus() {
      $mdDialog.show(vm.cadastrarCampusDialog);
    }

    // Modal de cadastro de curso
    function cadastrarCurso() {
      vm.cursoLocals.instituicao_ensino_id = vm.resource.id;
      $mdDialog.show(vm.cadastrarCursosDialog);
    }

    //FILTROS
    function applyFilters(defaultQueryFilters) {
      return angular.extend(defaultQueryFilters, vm.filters);
    }




    // instantiate base controller
    $controller('CRUDController', { vm: vm, modelService: InstituicoesEnsinoService, options: {} });

  }

})();
