(function() {

  'use strict';

  angular
    .module('app')
    .controller('ProjectsController', ProjectsController);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function ProjectsController(Global, $controller, ProjectsService, Auth, RolesService) {
    var vm = this;

    //Attributes Block

    //Functions Block
    vm.onActivate = onActivate;
    vm.applyFilters = applyFilters;
    vm.beforeSave = beforeSave;
    vm.afterSearch = afterSearch;
    
    vm.roles = {};

    // instantiate base controller
    $controller('CRUDController', { vm: vm, modelService: ProjectsService, options: {} });

    function onActivate() {
		RolesService.query().then(function(response){
			vm.roles = response;
		});
		vm.queryFilters = {};
    }
    
    function afterSearch() {
		console.log(vm.resources);
	}

    function applyFilters(defaultQueryFilters) {
      return angular.extend(defaultQueryFilters, vm.querylters);
    }
    
    function beforeSave() {
		vm.resource.owner = Auth.currentUser.id;
		vm.resource.user_id = Auth.currentUser.id;
	}

  }

})();
