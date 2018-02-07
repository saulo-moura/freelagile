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
  function DashboardController($controller, $state, DashboardsService, ProjectsService, moment) {
    var vm = this;

    //Attributes Block

    //Functions Block
    vm.onActivate = onActivate;
    vm.applyFilters = applyFilters;
    vm.fixDate = fixDate;

    function onActivate() {
      var project = localStorage.getItem('project');

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

    // instantiate base controller
    $controller('CRUDController', { vm: vm, modelService: DashboardsService, options: {} });
  }

})();
