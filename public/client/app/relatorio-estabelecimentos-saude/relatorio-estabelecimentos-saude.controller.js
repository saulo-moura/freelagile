(function() {

  'use strict';

  angular
    .module('app')
    .controller('RelatorioEstabelecimentosSaudeController', RelatorioEstabelecimentosSaudeController);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function RelatorioEstabelecimentosSaudeController($controller, $state, $window, RelatorioEstabelecimentosSaudeService, EstabelecimentosSaudeService) {
    var vm = this;

    vm.onActivate = onActivate;
    vm.applyFilters = applyFilters;
    vm.voltarParaEs = voltarParaEs;
    vm.imprimirPendencia = imprimirPendencia;

    //Attributes Block
    vm.estabelecimentosSaudePendente = [];

    //Functions Block

    /**
     * Função disparada ao ativar a tela.
     */
    function onActivate() {
      vm.estabelecimentosSaudePendente = EstabelecimentosSaudeService.query({ validado: 'false' }).then(function (response) {
        vm.estabelecimentosSaudePendente = response;
      });
    }

    /**
     * Adiciona filtros a busca de vagas.
     */
    function applyFilters(defaultQueryFilters) {
      return angular.extend(defaultQueryFilters, vm.queryFilters);
    }

    function voltarParaEs() {
      $state.go('app.estabelecimentos-saude');
    }

    function imprimirPendencia() {
      $window.print();
    }

    // instantiate base controller
    $controller('CRUDController', { vm: vm, modelService: RelatorioEstabelecimentosSaudeService, options: { } });

  }

})();
