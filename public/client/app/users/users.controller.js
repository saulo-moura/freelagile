(function() {

  'use strict';

  angular
    .module('app')
    .controller('UsersController', UsersController);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function UsersController($controller, UsersService) {

    var vm = this;

    vm.onActivate = onActivate;
    // instantiate base controller
    $controller('CRUDController', { vm: vm, modelService: UsersService, options: {} });

    function onActivate() {
      vm.queryFilters = {};
    }
  }
})();
