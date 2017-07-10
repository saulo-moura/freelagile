(function() {

  'use strict';

  angular
    .module('app')
    .controller('SetoresController', SetoresController);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function SetoresController($controller, $translate, PrToast, SetoresService, TiposEstabelecimentoSaudeService) {
    var vm = this;

    vm.onActivate = onActivate;
    vm.beforeRemove = beforeRemove;
    vm.afterEdit = afterEdit;
    vm.onRemoveError = onRemoveError;

    //Functions Block
    function onActivate() {
      vm.tiposEstabelecimento = TiposEstabelecimentoSaudeService.query().then(function (response) {
        vm.tiposEstabelecimento = response;
      });
    }

    function beforeRemove(resource) {
      vm.resource.tipo_estabelecimento_saude_id = resource.setor_tipo_estabelecimento_saude[0].id;
    }

    /**
     * Disparada após entrar em modo de edição.
     */
    function afterEdit() {

    }

    function onRemoveError(data) {
      var erro = data.error.split('|');

      PrToast.error($translate.instant(erro[0], { entidade: erro[1] }));
    }

    // instantiate base controller
    $controller('CRUDController', { vm: vm, modelService: SetoresService, options: { } });

  }

})();
