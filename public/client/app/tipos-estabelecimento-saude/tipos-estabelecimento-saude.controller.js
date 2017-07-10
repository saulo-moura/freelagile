(function() {

  'use strict';

  angular
    .module('app')
    .controller('TiposEstabelecimentoSaudeController', TiposEstabelecimentoSaudeController);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function TiposEstabelecimentoSaudeController($controller, $translate, PrToast, TiposEstabelecimentoSaudeService ) {
    var vm = this;

    vm.onRemoveError = onRemoveError;

    //Attributes Block

    //Functions Block
    function onRemoveError(data) {
      var erro = data.error.split('|');
      PrToast.error($translate.instant(erro[0], { entidade: erro[1] }));
    }

    // instantiate base controller
    $controller('CRUDController', { vm: vm, modelService: TiposEstabelecimentoSaudeService, options: { } });

  }

})();
