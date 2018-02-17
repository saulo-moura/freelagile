(function() {

  'use strict';

  angular
    .module('app')
    .controller('ProjectsController', ProjectsController);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function ProjectsController($controller,
    ProjectsService,
    Auth,
    RolesService,
    UsersService,
    $state,
    $filter,
    $stateParams,
    $window) {
    var vm = this;

    //Attributes Block

    //Functions Block
    vm.onActivate = onActivate;
    vm.applyFilters = applyFilters;
    vm.beforeSave = beforeSave;
    vm.searchUser = searchUser;
    vm.addUser = addUser;
    vm.removeUser = removeUser;
    vm.viewProject = viewProject;

    vm.roles = {};
    vm.users = [];

    function onActivate() {
      vm.currentUser = Auth.currentUser;
      RolesService.query().then(function(response) {
        vm.roles = response;
        //vm.roles = $filter('filter')(vm.roles, { slug: 'client' });
        if ($stateParams.obj === 'edit') {
          vm.cleanForm();
          vm.viewForm = true;
          vm.resource = $stateParams.resource;
          usersArray(vm.resource);
        } else {
          localStorage.removeItem('project');
          vm.queryFilters = { user_id: vm.currentUser.id };
        }
      });
    }

    function applyFilters(defaultQueryFilters) {
      return angular.extend(defaultQueryFilters, vm.querylters);
    }

    function beforeSave() {
      vm.resource.owner = Auth.currentUser.id;
      vm.resource.user_id = Auth.currentUser.id;
      vm.resource.dev_id = Auth.currentUser.id;
    }

    function searchUser() {
      return UsersService.query({ name: vm.userName });
    }

    function addUser(user) {
      if (user) {
        vm.resource.users.push(user);
        vm.userName = '';
      }
    }

    function removeUser(index) {
      vm.resource.users.splice(index, 1);
    }

    function applyFilters(defaultQueryFilters) {
      return angular.extend(defaultQueryFilters, vm.queryFilters);
    }

    function viewProject() {
      $state.go('app.dashboard');
    }

    vm.afterSearch = function() {
      if (vm.resources.length > 0) {
        vm.resources.forEach(function(project) {
          usersArray(project);
        });
      }
    }

    function usersArray(project) {
      project.users = [];
      if (project.client_id) {
        project.client.role = $filter('filter')(vm.roles, { slug: 'client' })[0];
        project.users.push(project.client);
      }
      if (project.dev_id) {
        project.developer.role = $filter('filter')(vm.roles, { slug: 'dev' })[0];
        project.users.push(project.developer);
      }
      if (project.stakeholder_id) {
        project.stakeholder.role = $filter('filter')(vm.roles, { slug: 'stakeholder' })[0];
        project.users.push(project.stakeholder);
      }
    }

    vm.historyBack = function() {
      $window.history.back();
    }

    vm.afterSave = function(resource) {
      localStorage.setItem('project', resource.id);
      $state.go('app.dashboard');
    }

    // instantiate base controller
    $controller('CRUDController', { vm: vm, modelService: ProjectsService, options: { redirectAfterSave: false } });
  }

})();
