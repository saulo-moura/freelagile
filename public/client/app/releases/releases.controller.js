(function() {

  'use strict';

  angular
    .module('app')
    .controller('ReleasesController', ReleasesController);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function ReleasesController($controller, ReleasesService, MilestonesService, PrToast, moment, $mdDialog, $translate) {
    var vm = this;

    //Attributes Block

    //Functions Block
    vm.onActivate = function() {
      vm.project = localStorage.getItem('project');
      vm.queryFilters = { project_id: vm.project };
    }

    vm.beforeSave = function() {
      vm.resource.project_id = vm.project;
    }

    vm.beforeRemove = function() {
      vm.resource.project_id = vm.project;
    }

    vm.view = function (resource) {
      vm.resource = resource;
      vm.onView = true;
      vm.viewForm = false;
    }

    vm.finalize = function(release) {
      var confirm = $mdDialog.confirm()
          .title('Finalizar Release')
          .textContent('Tem certeza que deseja finalizar a release ' + release.title + '?')
          .ok('Sim')
          .cancel('Não');

      $mdDialog.show(confirm).then(function() {
        ReleasesService.finalize({ project_id: vm.project, release_id: release.id }).then(function() {
          PrToast.success($translate.instant('messages.sprintEndedSuccess'));
          vm.search();
        }, function() {
          PrToast.Error($translate.instant('messages.sprintEndedError'));
        });
      });
    }

    vm.formatDate = function(date) {
      return moment(date).format('DD/MM/YYYY');
    }

    vm.searchMilestone = function (milestoneTerm) {
      return MilestonesService.query({
        releaseSearch: true,
        project_id: vm.resource.project_id,
        title: milestoneTerm
      });
    }

    vm.onMilestoneChange = function() {
      if (vm.milestone !== null && vm.resource.milestones.findIndex(i => i.id === vm.milestone.id) === -1) {
        vm.resource.milestones.push(vm.milestone);
      }
    }

    vm.removeMilestone = function(milestone) {
      vm.resource.milestones.slice(0).forEach(function(element) {
        if(element.id === milestone.id) {
          vm.resource.milestones.splice(vm.resource.milestones.indexOf(element), 1);
        }
      });
    }

    vm.saveMilestones = function() {
      MilestonesService.updateRelease({project_id: vm.resource.project_id, release_id: vm.resource.id, milestones: vm.resource.milestones}).then(function(){
        PrToast.success($translate.instant('messages.saveSuccess'));
        vm.viewForm = false;
        vm.onView = false;
      }, function() {
        PrToast.error($translate.instant('messages.operationError'));
      });
    }

    vm.estimatedTime = function (milestone) {
      milestone.estimated_time = 0;
      if(milestone.tasks.length > 0) {
        milestone.tasks.forEach(function(task) {
          milestone.estimated_time += task.estimated_time;
        });
      }
      return milestone.estimated_time / 8;
    }

    // instantiate base controller
    $controller('CRUDController', { vm: vm, modelService: ReleasesService, options: { } });

  }

})();
