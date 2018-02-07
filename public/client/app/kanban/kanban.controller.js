(function() {

  'use strict';

  angular
    .module('app')
    .controller('KanbanController', KanbanController);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function KanbanController($controller, TasksService, StatusService, $mdDialog, $document) {
    //Attributes Block
    var vm = this;
    var fields = [
      { name: 'id', type: 'string' },
      { name: 'status', map: 'state', type: 'string' },
      { name: 'text', map: 'label', type: 'string' },
      { name: 'tags', type: 'string' }
    ];

    vm.onActivate = function() {
      vm.project = localStorage.getItem('project');
      vm.queryFilters = { project_id: vm.project };
    }

    vm.applyFilters = function(defaultQueryFilters) {
      return angular.extend(defaultQueryFilters, vm.queryFilters);
    }

    vm.afterSearch = function () {
      var columns = [];
      var tasks = [];

      StatusService.query().then(function(response) {
        response.forEach(function(status) {
          columns.push({ text: status.name, dataField: status.slug });
        });

        if (vm.resources.length > 0) {
          vm.resources.forEach(function(task) {
            tasks.push({
              id: task.id,
              state: task.status.slug,
              label: task.title,
              tags: task.type.name + ', ' + task.priority.name
            })
          });

          var source = {
            localData: tasks,
            dataType: 'array',
            dataFields: fields
          };
          var dataAdapter = new $.jqx.dataAdapter(source);

          vm.settings = {
            source: dataAdapter,
            columns: columns,
            theme: 'light'
          };
        } else {
          vm.settings = {
            source: [{}],
            columns: columns,
            theme: 'light'
          };
        }
        vm.kanbanReady = true;
      });
    }

    vm.onItemMoved = function(event) {
      TasksService.updateTaskByKanban({
        project_id: vm.project,
        id: event.args.itemId,
        oldColumn: event.args.oldColumn,
        newColumn: event.args.newColumn }).then(function() {

        });
    }

    vm.onItemClicked = function(event) {
      TasksService.query({ task_id: event.args.itemId }).then(function(response) {
        vm.taskInfo = response[0];
        $mdDialog.show({
          parent: angular.element($document.body),
          templateUrl: 'client/app/kanban/task-info-dialog/taskInfo.html',
          controllerAs: 'taskInfoCtrl',
          controller: 'TaskInfoController',
          bindToController: true,
          locals: {
            task: vm.taskInfo,
            close: close
          },
          escapeToClose: true,
          clickOutsideToClose: true
        });
      });
    }

    function close() {
      $mdDialog.hide();
    }

    // instantiate base controller
    $controller('CRUDController', { vm: vm, modelService: TasksService, options: { } });

  }

})();
