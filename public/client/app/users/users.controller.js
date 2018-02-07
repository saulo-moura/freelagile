(function() {

  'use strict';

  angular
    .module('app')
    .controller('UsersController', UsersController);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function UsersController($controller, UsersService, PrToast, $mdDialog, $translate) {

    var vm = this;

    vm.onActivate = onActivate;
    // instantiate base controller
    $controller('CRUDController', { vm: vm, modelService: UsersService, options: {} });

    function onActivate() {
      vm.queryFilters = {};
    }

    vm.hideDialog = function() {
      $mdDialog.hide();
    }

    vm.saveNewUser = function() {
      vm.resource.$save().then(function (resource) {
        vm.resource = resource;
        PrToast.success($translate.instant('messages.successSignUp'));
        $mdDialog.hide();
      });
    }
  }
})();
