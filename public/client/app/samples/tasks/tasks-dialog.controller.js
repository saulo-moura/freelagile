(function() {

  'use strict';

  angular
    .module('app')
    .controller('TasksDialogController', TasksDialogController);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function TasksDialogController($controller, TasksService, projectId, PrToast, // NOSONAR
    PrDialog, $translate, Global, moment) {

    var vm = this;

    //Functions Block
    vm.onActivate   = onActivate;
    vm.close        = close;
    vm.applyFilters = applyFilters;
    vm.beforeSave   = beforeSave;
    vm.afterSave    = afterSave;
    vm.toggleDone   = toggleDone;

    // instantiate base controller
    $controller('CRUDController', { vm: vm, modelService: TasksService, options: {
      perPage: 5
    } });

    function onActivate() {
      vm.global = Global;
      vm.resource.scheduled_to = moment().add(30, 'minutes');
      vm.queryFilters = { projectId: projectId };
    }

    function applyFilters(defaultQueryFilters) {
      return angular.extend(defaultQueryFilters, vm.queryFilters);
    }

    function beforeSave() {
      vm.resource.project_id = vm.queryFilters.projectId;
      vm.resource.project = null;
    }

    function afterSave() {
      vm.cleanForm();
      vm.search(vm.paginator.currentPage);
    }

    function close() {
      vm.cleanForm();
      PrDialog.close();
    }

    function toggleDone(resource) {
      TasksService.toggleDone({ id: resource.id, done: resource.done }).then(function() {
        PrToast.success($translate.instant('messages.saveSuccess'));
        vm.search(vm.paginator.currentPage);
      }, function(error) {
        PrToast.errorValidation(error.data, $translate.instant('messages.operationError'));
      });
    }

  }

})();
