(function() {

  'use strict';

  angular
    .module('app')
    .controller('MilestonesController', MilestonesController);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function MilestonesController($controller,
    MilestonesService,
    moment,
    TasksService,
    PrToast,
    $translate,
    $mdDialog) {

    var vm = this;

    vm.estimatedPrice = estimatedPrice;

    vm.onActivate = function() {
      vm.project = localStorage.getItem('project');
      vm.queryFilters = { project_id: vm.project };
    }

    function estimatedPrice(milestone) {
      milestone.estimated_value = 0;
      if(milestone.tasks.length > 0 && milestone.project.hour_value_final) {
        milestone.tasks.forEach(function(task) {
          milestone.estimated_value += (parseFloat(milestone.project.hour_value_final) * task.estimated_time);
        });
      }
      return milestone.estimated_value.toLocaleString('Pt-br', { minimumFractionDigits: 2 });
    }

    vm.estimatedTime = function (milestone) {
      milestone.estimated_time = 0;
      if(milestone.tasks.length > 0) {
        milestone.tasks.forEach(function(task) {
          milestone.estimated_time += task.estimated_time;
        });
      }
      milestone.estimated_time = milestone.estimated_time / 8;
      var dateEnd = moment(milestone.date_end);
      var dateBegin = moment(milestone.date_begin);

      if (dateEnd.diff(dateBegin, 'days') <= milestone.estimated_time) {
        milestone.color_estimated_time = { color: 'red' };
      } else {
        milestone.color_estimated_time = { color: 'green' };
      }
      return milestone.estimated_time;
    }

    vm.applyFilters = function(defaultQueryFilters) {
      return angular.extend(defaultQueryFilters, vm.queryFilters);
    }

    vm.beforeSave = function() {
      vm.resource.project_id = vm.project;
    }

    vm.beforeRemove = function() {
      vm.resource.project_id = vm.project;
    }

    vm.formatDate = function(date) {
      return moment(date).format('DD/MM/YYYY');
    }

    vm.afterEdit = function() {
      vm.resource.date_begin = moment(vm.resource.date_begin);
      vm.resource.date_end = moment(vm.resource.date_end);
    }

    vm.view = function (resource) {
      vm.resource = resource;
      vm.onView = true;
      vm.viewForm = false;
      console.log(resource.project);
    }

    vm.searchTask = function (taskTerm) {
      return TasksService.query({
        milestoneSearch: true,
        project_id: vm.resource.project_id,
        title: taskTerm
      });
    }

    vm.onTaskChange = function() {
      if (vm.task !== null && vm.resource.tasks.findIndex(i => i.id === vm.task.id) === -1) {
        vm.resource.tasks.push(vm.task);
      }
    }

    vm.removeTask = function(task) {
      vm.resource.tasks.slice(0).forEach(function(element) {
        if(element.id === task.id) {
          vm.resource.tasks.splice(vm.resource.tasks.indexOf(element), 1);
        }
      });
    }

    vm.saveTasks = function() {
      TasksService.updateMilestone({project_id: vm.resource.project_id, milestone_id: vm.resource.id, tasks: vm.resource.tasks}).then(function(){
        PrToast.success($translate.instant('messages.saveSuccess'));
        vm.viewForm = false;
        vm.onView = false;
      }, function() {
        PrToast.error($translate.instant('messages.operationError'));
      });
    }

    vm.finalize = function(milestone) {
      var confirm = $mdDialog.confirm()
          .title('Finalizar Sprint')
          .textContent('Tem certeza que deseja finalizar a sprint ' + milestone.title + '?')
          .ok('Sim')
          .cancel('Não');

      $mdDialog.show(confirm).then(function() {
        MilestonesService.finalize({ project_id: vm.project, milestone_id: milestone.id }).then(function() {
          PrToast.success($translate.instant('messages.sprintEndedSuccess'));
          vm.search();
        }, function() {
          PrToast.Error($translate.instant('messages.sprintEndedError'));
        });
      });
    }

    // instantiate base controller
    $controller('CRUDController', { vm: vm, modelService: MilestonesService, options: { } });

  }

})();
