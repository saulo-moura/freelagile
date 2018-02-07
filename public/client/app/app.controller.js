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
    vm.activeProject = null;

    vm.logout     = logout;
    vm.getImagePerfil = getImagePerfil;
    vm.getLogoMenu = getLogoMenu;
    vm.setActiveProject = setActiveProject;
    vm.getActiveProject = getActiveProject;
    vm.removeActiveProject = removeActiveProject;

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

    function getLogoMenu() {
      return Global.imagePath + '/logo-vertical.png';
    }

    function setActiveProject(project) {
      localStorage.setItem('project', project);
    }

    function getActiveProject() {
      return localStorage.getItem('project');
    }

    function removeActiveProject() {
      localStorage.removeItem('project');
    }

  }

})();
