(function() {

  'use strict';

  angular
    .module('app')
    .controller('AppController', AppController);

  /** @ngInject */
  /**
   * Controlador responsável por funcionalidades que são acionadas em qualquer tela do sistema
   *
   */
  function AppController($state, Auth, Global) {
    var vm = this;

    //ano atual para ser exibido no rodapé do sistema
    vm.anoAtual = null;

    vm.logout     = logout;
    vm.getImagePerfil = getImagePerfil;

    activate();

    function activate() {
      var date = new Date();

      vm.anoAtual = date.getFullYear();
    }

    function logout() {
      Auth.logout().then(function() {
        $state.go(Global.loginState);
      });
    }

    function getImagePerfil() {
      return (Auth.currentUser && Auth.currentUser.image)
        ? Auth.currentUser.image
        : Global.imagePath + '/no_avatar.gif';
    }

  }

})();
