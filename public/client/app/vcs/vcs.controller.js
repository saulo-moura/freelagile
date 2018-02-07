//token cacb91235873a8c4875d23578ac9f326ef894b66
// OAtuth https://github.com/login/oauth/authorize?client_id=829468e7fdee79445ba6&scope=user,public_repo&redirect_uri=http://0.0.0.0:5000/#!/app/vcs

(function() {
  'use strict';
  angular
    .module('app')
    .filter('bytes', function() {
      return function(bytes, precision) {
        if (isNaN(parseFloat(bytes)) || !isFinite(bytes)) return '-';
        if (typeof precision === 'undefined') precision = 1;
        var units = ['bytes', 'kB', 'MB', 'GB', 'TB', 'PB'],
          number = Math.floor(Math.log(bytes) / Math.log(1024));

        return (bytes / Math.pow(1024, Math.floor(number))).toFixed(precision) +  ' ' + units[number];
      }
    })
    .controller('VcsController', VcsController);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function VcsController($controller, VcsService, $window, ProjectsService, PrToast, $translate) {
    var vm = this;

    vm.index = 0;
    vm.paths = [];

    //Attributes Block

    //Functions Block
    vm.onActivate =  function() {
      toggleSplashScreen();
      ProjectsService.query({ project_id: localStorage.getItem('project') }).then(function(response) {
        vm.username = response[0].username_github;
        vm.repo = response[0].repo_github;
        vm.queryFilters = {
          username: vm.username,
          repo: vm.repo,
          path: '.'
        }
        vm.paths.push(vm.queryFilters.path);
        vm.search();
      });
    }

    vm.applyFilters = function(defaultQueryFilters) {
      return angular.extend(defaultQueryFilters, vm.queryFilters);
    }

    vm.afterSearch = function() {
      sortResources();
      $window.loading_screen.finish();
    }

    function sortResources() {
      vm.resources.sort(function(a, b) {
        return a.type < b.type ? -1 : a.type > b.type ? 1 : 0;
      });
    }

    vm.openFileOrDirectory = function(resource) {
      toggleSplashScreen();
      if (resource) {
        vm.queryFilters.path = resource.path;
        vm.paths.push(vm.queryFilters.path);
        vm.index++;
      } else {
        vm.queryFilters.path = vm.paths[vm.index - 1];
        vm.paths.splice(vm.index, 1);
        vm.index--;
      }
      vm.search();
    }

    vm.onSearchError = function (response) {
      if (response.data.error === 'Not Found') {
        PrToast.info($translate.instant('Repositório não encontrado'));
        $window.loading_screen.finish();
      }
    }

    /**
     * Método para mostrar a tela de espera
     */
    function toggleSplashScreen() {
      $window.loading_screen = $window.pleaseWait({
        logo: '',
        backgroundColor: 'rgba(255,255,255,0.4)',
        loadingHtml:
          '<div class="spinner"> ' +
          '  <div class="rect1"></div> ' +
          '  <div class="rect2"></div> ' +
          '  <div class="rect3"></div> ' +
          '  <div class="rect4"></div> ' +
          '  <div class="rect5"></div> ' +
          ' <p class="loading-message">Carregando</p> ' +
          '</div>'
      });
    }

    // instantiate base controller
    $controller('CRUDController', { vm: vm, modelService: VcsService, options: { skipPagination: true, searchOnInit: false } });

  }


})();
