(function () {

  'use strict';

  angular
    .module('app')
    .controller('AddHorarioVagaDialogController', AddHorarioVagaDialogController);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function AddHorarioVagaDialogController(locals, moment, PrToast) {

    var vm = this;
    vm.escolher = escolher;

    vm.diasDaSemana = [
      { id: 0, nome: 'Segunda' },
      { id: 1, nome: 'Terça' },
      { id: 2, nome: 'Quarta' },
      { id: 3, nome: 'Quinta' },
      { id: 4, nome: 'Sexta' },
      { id: 5, nome: 'Sábado' },
      { id: 6, nome: 'Domingo' }
    ];
    function escolher() {
      if (angular.isDefined(vm.diaDaSemana) && angular.isDefined(vm.qtdVagas)) {
        vm.getHorarioInfo(vm.diaDaSemana, vm.qtdVagas, locals.horario);
      }else{
        PrToast.error('É necessário preencher os campos.');
      }
    }
  }
})();