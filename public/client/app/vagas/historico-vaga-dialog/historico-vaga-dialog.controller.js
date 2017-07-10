(function() {

  'use strict';

  angular
    .module('app')    
    .controller('HistoricoVagaDialogController', HistoricoVagaDialogController);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function HistoricoVagaDialogController(locals, moment) {

    var vm = this;

    vm.historico = locals.historico;
    
    vm.ajustaData = function(data) {
      return moment(data).format('DD/MM/YYYY [às] H:mm ')
    }
  }
})();