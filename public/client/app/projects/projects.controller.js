(function() {

  'use strict';

  angular
    .module('app')
    .controller('ProjectsController', ProjectsController);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function ProjectsController(Global, 
    $controller, 
    ProjectsService, 
    Auth, 
    RolesService, 
    UsersService,
    $state) {
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

    function onActivate() { 
      localStorage.removeItem('project');
      vm.queryFilters = {user_id: Auth.currentUser.id};
  		RolesService.query().then(function(response){
  			vm.roles = response;
  		});
    }

    function applyFilters(defaultQueryFilters) {
      return angular.extend(defaultQueryFilters, vm.querylters);
    }
    
    function beforeSave() {
  		vm.resource.owner = Auth.currentUser.id;
  		vm.resource.user_id = Auth.currentUser.id;
  	}

    function searchUser(text) {
      return UsersService.query({name: vm.userName});
    }

    function addUser(user) {
      if(user) {
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
    
    function viewProject(project) {
      $state.go('app.dashboard');
		}

    // instantiate base controller
    $controller('CRUDController', { vm: vm, modelService: ProjectsService, options: {} });
  }

})();
