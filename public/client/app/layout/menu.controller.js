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
        // Coloque seus itens de menu a partir deste ponto
        { state: '#', title: menuPrefix + 'cadastrosBasicos', icon: 'input',
          subItens: [
            { state: 'app.areas', title: menuPrefix + 'areas', icon: 'border_all',
              needPermission: { resource: 'areas' }
            },
            { state: 'app.cursos', title: menuPrefix + 'cursos', icon: 'book',
              needPermission: { resource: 'cursos' }
            },
            { state: 'app.especialidades', title: menuPrefix + 'especialidades', icon: 'pie_chart_outlined',
              needPermission: { resource: 'especialidades' }
            },
            { state: 'app.especificacoes', title: menuPrefix + 'especificacoes', icon: 'toys',
              needPermission: { resource: 'especificacoes' }
            },
            { state: 'app.modalidades', title: menuPrefix + 'modalidades', icon: 'compare',
              needPermission: { resource: 'modalidades' }
            },
            { state: 'app.naturezas-juridicas', title: menuPrefix + 'naturezasJuridicas', icon: 'nature',
              needPermission: { resource: 'naturezasJuridicas' }
            },
            { state: 'app.setores', title: menuPrefix + 'setores', icon: 'dashboard',
              needPermission: { resource: 'setores' }
            },
            { state: 'app.tipos-estabelecimento-saude', title: menuPrefix + 'tiposEstabelecimentoSaude', icon: 'playlist_add',
              needPermission: { resource: 'tiposEstabelecimentoSaude' }
            }
          ]
        },
        { state: '#', title: menuPrefix + 'estabelecimentosSaude', icon: 'local_hospital',
          subItens: [
            { state: 'app.estabelecimentos-saude', title: menuPrefix + 'cadastroes',
              icon: 'format_list_bulleted', needPermission: { resource: 'estabelecimentosSaude' }
            },
            { state: 'app.vagas', title: menuPrefix + 'vagas', icon: 'event_note',
              needPermission: { resource: 'vagas' }
            }
          ]
        },
        { state: 'app.instituicoes-ensino', title: menuPrefix + 'instituicoesEnsino', icon: 'school',
          needPermission: { resource: 'instituicoesEnsino' },
          subItens: [
          ]
        },
        { state: '#', title: menuPrefix + 'admin', icon: 'settings_applications',
          subItens: [
            { state: 'app.user', title: menuPrefix + 'user', icon: 'people',
              needPermission: { resource: 'users' }
            },
            { state: 'app.roles', title: menuPrefix + 'roles', icon: 'perm_contact_calendar',
              needPermission: { resource: 'roles' }
            },
            { state: 'app.parametros-sistema', title: menuPrefix + 'painelcontrole', icon: 'extension',
              needPermission: { resource: 'parametrosSistema' }
            }
          ]
        }
      ];

      /**
       * Objeto que preenche o ng-style do menu lateral trocando as cores
       */
      vm.sidenavStyle = {
        top: {
          'border-bottom': '1px solid ' + getColor('primary'),
          'background-image': '-webkit-linear-gradient(top, '+getColor('primary-500')+', '+getColor('primary-800')+')'
        },
        content: {
          'background-color': getColor('primary-800')
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
     * caso contrário redireciona para o state passado como parâmetro
     */
    function openMenuOrRedirectToState($mdOpenMenu, ev, item) {
      if (angular.isDefined(item.subItens) && item.subItens.length > 0) {
        $mdOpenMenu(ev);
      } else {
        $state.go(item.state);
        $mdSidenav('left').close();
      }
    }

    function getColor(colorPalettes) {
      return $mdColors.getThemeColor(colorPalettes);
    }

  }

})();
