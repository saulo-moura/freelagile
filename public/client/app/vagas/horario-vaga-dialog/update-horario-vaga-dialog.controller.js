(function () {

  'use strict';

  angular
    .module('app')
    .controller('UpdateHorarioVagaDialogController', UpdateHorarioVagaDialogController);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function UpdateHorarioVagaDialogController(locals, moment, PrToast) {

    var vm = this;
    vm.escolher = escolher;
    vm.excluir = excluir;
    vm.horario = locals.horarioAtual;

    function escolher() {
      if (angular.isDefined(vm.horario.qtdVagas) && vm.horario.qtdVagas !== null) {
        vm.updateHorario(vm.horario);
      }else{
        PrToast.error('É necessário preencher os campos.');
      }
    }

    function excluir() {
      vm.excluirHorario(locals.horarioAtual);
    }
  }
})();
