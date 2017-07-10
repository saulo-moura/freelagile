(function() {

  'use strict';

  angular
    .module('app')
    .controller('ParametrossistemaController', ParametrossistemaController);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function ParametrossistemaController(Auth, $controller, ParametrossistemaService) {
    var vm = this;

    //Attributes Block

    vm.mostrarCampoChave = false; 

    //Functions Block
    vm.onActivate = function () {
      var usuarioLogado = Auth.currentUser;

      for (var i=0;i < usuarioLogado.roles.length;i++)
          vm.mostrarCampoChave = true;
    }

    // instantiate base controller
    $controller('CRUDController', { vm: vm, modelService: ParametrossistemaService, options: { } });

  }

})();
