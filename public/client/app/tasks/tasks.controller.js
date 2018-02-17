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
    .controller('TasksController', TasksController);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function TasksController($controller,
    TasksService,
    StatusService,
    PrioritiesService,
    TypesService,
    TaskCommentsService,
    moment,
    Auth,
    PrToast,
    $translate,
    $filter,
    Global) {
    var vm = this;

    //Attributes Block

    //Functions Block
    vm.onActivate = onActivate;
    vm.applyFilters = applyFilters;
    vm.beforeSave = beforeSave;
    vm.beforeRemove = beforeRemove;

    function onActivate() {
      vm.currentUser = Auth.currentUser;
      vm.imagePath = Global.imagePath + '/no_avatar.gif';
      vm.project = localStorage.getItem('project');
      vm.queryFilters = { project_id: vm.project };

      StatusService.query().then(function(response) {
        vm.status = response;
      });

      PrioritiesService.query().then(function(response) {
        vm.priorities = response;
      });

      TypesService.query().then(function(response) {
        vm.types = response;
      });
    }

    function applyFilters(defaultQueryFilters) {
      return angular.extend(defaultQueryFilters, vm.queryFilters);
    }

    function beforeSave() {
      vm.resource.project_id = vm.project;
    }

    function beforeRemove() {
      vm.resource.project_id = vm.project;
    }

    vm.view = function (resource) {
      vm.resource = resource;
      vm.onView = true;
      vm.viewForm = false;
    }

    vm.saveComment = function(comment) {
      var description = '';
      var comment_id = null;

      if (comment) {
        description = vm.answer
        comment_id = comment.id;
      } else {
        description = vm.comment;
      }
      TaskCommentsService.saveTaskComment({ project_id: vm.project, task_id: vm.resource.id, comment_text: description, comment_id: comment_id }).then(function() {
        vm.comment = '';
        vm.answer = '';
        vm.search();
        PrToast.success($translate.instant('messages.saveSuccess'));
      }, function() {
        PrToast.error($translate.instant('messages.operationError'));
      });
    }

    vm.removeComment = function(comment) {
      TaskCommentsService.removeTaskComment({ comment_id: comment.id }).then(function() {
        vm.search();
        PrToast.success($translate.instant('messages.removeSuccess'));
      }, function() {
        PrToast.error($translate.instant('messages.operationError'));
      });
    }

    vm.afterSearch = function() {
      if (vm.resource.id) {
        vm.resource = $filter('filter')(vm.resources, { id: vm.resource.id })[0];
      }
    }

    vm.fixDate = function(dateString) {
      return moment(dateString);
    }

    // instantiate base controller
    $controller('CRUDController', { vm: vm, modelService: TasksService, options: { skipPagination: true } });
  }

})();
