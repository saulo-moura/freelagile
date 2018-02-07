(function() {

  'use strict';

  angular
    .module('app')
    .controller('TaskInfoController', TaskInfoController);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function TaskInfoController($controller, TasksService, locals) {
    //Attributes Block
    var vm = this;

    vm.closeDialog = closeDialog;

    vm.onActivate = function() {
      vm.task = locals.task;
      vm.task.estimated_time = vm.task.estimated_time.toString() + ' horas';
    }

    function closeDialog() {
      vm.close();
      console.log("fechar");
    }

    // instantiate base controller
    $controller('CRUDController', { vm: vm, modelService: TasksService, options: { } });
  }

})();
