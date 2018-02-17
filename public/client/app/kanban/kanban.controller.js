(function() {

  'use strict';

  angular
    .module('app')
    .controller('KanbanController', KanbanController);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function KanbanController($controller,
    TasksService,
    StatusService,
    PrToast,
    $mdDialog,
    $document,
    Auth,
    ProjectsService) {
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
      ProjectsService.query({ project_id: vm.project }).then(function(response) {
        vm.actualProject = response[0];
      })
      vm.queryFilters = { project_id: vm.project };
      vm.isMoved = false;
    }

    vm.applyFilters = function(defaultQueryFilters) {
      return angular.extend(defaultQueryFilters, vm.queryFilters);
    }

    vm.afterSearch = function () {
      var columns = [];
      var tasks = [];

      StatusService.query().then(function(response) {
        response.forEach(function(status) {
          columns.push({ text: status.name, dataField: status.slug, collapsible: false });
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
      if (Auth.currentUser.id === vm.actualProject.owner) {
        vm.isMoved = true;
        TasksService.query({ task_id: event.args.itemId }).then(function(response) {
          if ((response[0].milestone && response[0].milestone.done) || response[0].project.done) {
            PrToast.error('Não é possível modificar o status de uma tarefa finalizada.');
            vm.afterSearch();
            vm.isMoved = false;
          } else {
            TasksService.updateTaskByKanban({
              project_id: vm.project,
              id: event.args.itemId,
              oldColumn: event.args.oldColumn,
              newColumn: event.args.newColumn }).then(function() {
                vm.isMoved = false;
              });
          }
        });
      } else {
        vm.afterSearch();
      }
    }

    vm.onItemClicked = function(event) {
      if (!vm.isMoved) {
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
      } else {
        vm.isMoved = false;
      }
    }

    function close() {
      $mdDialog.hide();
    }

    // instantiate base controller
    $controller('CRUDController', { vm: vm, modelService: TasksService, options: { } });

  }

})();
