(function() {

  'use strict';

  angular
    .module('app')
    .controller('RelatorioDisponibilidadeVagasController', RelatorioDisponibilidadeVagasController);

  function RelatorioDisponibilidadeVagasController($controller, $window, $translate, PrToast, RelatorioDisponibilidadeVagasService, VagasService, CursosService, ModalidadesService, SetoresService, EspecificacoesService, EspecialidadesService) {
    var vm = this;

    vm.onActivate = onActivate;
    vm.applyFilters = applyFilters;
    vm.formatDate = formatDate;
    vm.modoImpressaoOuPesquisa = modoImpressaoOuPesquisa;
    vm.limparFiltros = limparFiltros;
    vm.imprimir = imprimir;
    vm.beforeSearch = beforeSearch;


    //Attributes Block
    vm.vagas = [];


    //Functions Block
    /**
     * Adiciona filtros a busca de vagas.
     */
    function applyFilters(defaultQueryFilters) {
      vm.vagas = VagasService
        .query({
          periodoInicialFormatado: vm.queryFilters.periodoInicialFormatado,
          periodoFinalFormatado: vm.queryFilters.periodoFinalFormatado,
          estabelecimentoSaude: vm.queryFilters.estabelecimentoSaude,
          curso_id: vm.queryFilters.curso_id,
          modalidade_id: vm.queryFilters.modalidade_id,
          setor_id: vm.queryFilters.setor_id,
          especificacao_id: vm.queryFilters.especificacao_id,
          especialidade_id: vm.queryFilters.especialidade_id
        })
        .then(function (response) {
          vm.vagas = response;
        }
      );
      return angular.extend(defaultQueryFilters, vm.queryFilters);
    }
    /**
     * Função disparada ao ativar a tela.
     */
    function onActivate() {
      vm.queryFilters = {};
      //Carrega combos
      vm.cursos = CursosService.query().then(function (response) {
        vm.cursos = response;
      });

      vm.modalidades = ModalidadesService.query().then(function (response) {
        vm.modalidades = response;
      });

      vm.setores = SetoresService.query().then(function (response) {
        vm.setores = response;
      });

      vm.especialidades = EspecialidadesService.query().then(function (response) {
        vm.especialidades = response;
      });

      vm.especificacoes = EspecificacoesService.query().then(function (response) {
        vm.especificacoes = response;
      });
    }

    function modoImpressaoOuPesquisa() {
      vm.viewForm = vm.viewForm ? false : true;
    }

    function formatDate(data) {
      return moment(data).format('YYYY-MM-DD');
    }

    function limparFiltros() {
      vm.queryFilters = {};
    }

    function imprimir(){
      $window.print();
    }

    function beforeSearch() {
      if (vm.queryFilters.periodoInicial > vm.queryFilters.periodoFinal) {
        PrToast.error($translate.instant('messages.periodoFinalInferiorAoInicial'));
        return false;
      }
    }

    // instantiate base controller
    $controller('CRUDController', { vm: vm, modelService: RelatorioDisponibilidadeVagasService, options: { } });

  }

})();
