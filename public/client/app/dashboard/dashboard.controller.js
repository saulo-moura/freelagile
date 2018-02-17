(function() {

  'use strict';

  angular
    .module('app')
    .filter('elapsed', function() {
      return function(date) {
        if (!date) return;
        var time = Date.parse(date),
          timeNow = new Date().getTime(),
          difference = timeNow - time,
          seconds = Math.floor(difference / 1000),
          minutes = Math.floor(seconds / 60),
          hours = Math.floor(minutes / 60),
          days = Math.floor(hours / 24),
          months = Math.floor(days / 30);

        if (months > 1) {
          return months + ' meses atrás';
        } else if (months === 1) {
          return '1 mês atrás';
        } else if (days > 1) {
          return days + ' dias atrás';
        } else if (days === 1) {
          return '1 dia atrás'
        } else if (hours > 1) {
          return hours + ' horas atrás';
        } else if (hours === 1) {
          return 'uma hora atrás';
        } else if (minutes > 1) {
          return minutes + ' minutos atrás';
        } else if (minutes === 1) {
          return 'um minuto atrás';
        } else {
          return 'há poucos segundos';
        }
      }
    })
    .controller('DashboardController', DashboardController);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function DashboardController($controller,
    $state,
    $mdDialog,
    $translate,
    DashboardsService,
    ProjectsService,
    moment,
    PrToast,
    Auth,
    Global) {
    var vm = this;

    //Attributes Block

    //Functions Block
    vm.onActivate = onActivate;
    vm.applyFilters = applyFilters;
    vm.fixDate = fixDate;

    function onActivate() {
      var project = localStorage.getItem('project');

      vm.imagePath = Global.imagePath + '/no_avatar.gif';
      vm.currentUser = Auth.currentUser;
      ProjectsService.query({ project_id: project }).then(function(response) {
        vm.actualProject = response[0];
      })
      vm.queryFilters = { project_id: project };
    }

    function applyFilters(defaultQueryFilters) {
      return angular.extend(defaultQueryFilters, vm.queryFilters);
    }

    function fixDate(dateString) {
      return moment(dateString);
    }

    vm.goToProject = function() {
      $state.go('app.projects', { obj: 'edit', resource: vm.actualProject });
    }

    vm.totalCost = function() {
      var estimated_cost = 0;

      vm.actualProject.tasks.forEach(function(task) {
        estimated_cost += (parseFloat(vm.actualProject.hour_value_final) * task.estimated_time);
      });
      return estimated_cost.toLocaleString('Pt-br', { minimumFractionDigits: 2 });
    }

    vm.finalizeProject = function() {
      var confirm = $mdDialog.confirm()
          .title('Finalizar Projeto')
          .textContent('Tem certeza que deseja finalizar o projeto ' + vm.actualProject.name + '?')
          .ok('Sim')
          .cancel('Não');

      $mdDialog.show(confirm).then(function() {
        ProjectsService.finalize({ project_id: vm.actualProject.id }).then(function() {
          PrToast.success($translate.instant('messages.projectEndedSuccess'));
          onActivate();
          vm.search();
        }, function() {
          PrToast.Error($translate.instant('messages.projectEndedError'));
        });
      });
    }

    // instantiate base controller
    $controller('CRUDController', { vm: vm, modelService: DashboardsService, options: {} });
  }

})();
