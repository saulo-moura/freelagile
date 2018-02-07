/*eslint-env es6*/

(function () {

  'use strict';

  angular
    .module('app')
    .controller('MenuController', MenuController);

  /** @ngInject */
  function MenuController($mdSidenav, $state, $mdColors) {
    var vm = this;

    //Bloco de declaracoes de funcoes
    vm.open = open;
    vm.openMenuOrRedirectToState = openMenuOrRedirectToState;

    activate();

    function activate() {
      var menuPrefix = 'views.layout.menu.';

      // Array contendo os itens que são mostrados no menu lateral
      vm.itensMenu = [
        { state: 'app.projects', title: menuPrefix + 'projects', icon: 'work', subItens: [] },
        { state: 'app.dashboard', title: menuPrefix + 'dashboard', icon: 'dashboard', subItens: [] },
        { state: 'app.tasks', title: menuPrefix + 'tasks', icon: 'view_list', subItens: [] },
        { state: 'app.milestones', title: menuPrefix + 'milestones', icon: 'view_module', subItens: [] },
        { state: 'app.releases', title: menuPrefix + 'releases', icon: 'subscriptions', subItens: [] },
        { state: 'app.kanban', title: menuPrefix + 'kanban', icon: 'view_column', subItens: [] },
        { state: 'app.vcs', title: menuPrefix + 'vcs', icon: 'group_work', subItens: [] }
        // Coloque seus itens de menu a partir deste ponto
        /* {
          state: '#', title: menuPrefix + 'admin', icon: 'settings_applications', profiles: ['admin'],
          subItens: [
            { state: 'app.user', title: menuPrefix + 'user', icon: 'people' },
            { state: 'app.mail', title: menuPrefix + 'mail', icon: 'mail' },
            { state: 'app.audit', title: menuPrefix + 'audit', icon: 'storage' },
            { state: 'app.dinamic-query', title: menuPrefix + 'dinamicQuery', icon: 'location_searching' }
          ]
        } */
      ];

      /**
       * Objeto que preenche o ng-style do menu lateral trocando as cores
       */
      vm.sidenavStyle = {
        top: {
          'border-bottom': '1px solid rgb(210, 210, 210)',
          'background-image': '-webkit-linear-gradient(top, rgb(144, 144, 144), rgb(210, 210, 210))'
        },
        content: {
          'background-color': 'rgb(210, 210, 210)'
        },
        textColor: {
          color: '#FFF'
        },
        lineBottom: {
          'border-bottom': '1px solid ' + getColor('primary-400')
        }
      }
    }

    function open() {
      $mdSidenav('left').toggle();
    }

    /**
     * Método que exibe o sub menu dos itens do menu lateral caso tenha sub itens
     * caso contrário redireciona para o state passado como parÃ¢metro
     */
    function openMenuOrRedirectToState($mdMenu, ev, item) {
      if (angular.isDefined(item.subItens) && item.subItens.length > 0) {
        $mdMenu.open(ev);
      } else {
        $state.go(item.state, { obj: null });
        $mdSidenav('left').close();
      }
    }

    function getColor(colorPalettes) {
      return $mdColors.getThemeColor(colorPalettes);
    }

  }

})();
