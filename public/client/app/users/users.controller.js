(function() {

  'use strict';

  angular
    .module('app')
    .controller('UsersController', UsersController);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function UsersController($controller, lodash, UsersService, RolesService, // NOSONAR
    PrToast, Auth, $translate) {

    var vm = this;

    vm.onActivate = onActivate;
    vm.applyFilters = applyFilters;
    vm.afterEdit = afterEdit;
    vm.afterClean = afterClean;
    vm.beforeSave = beforeSave;
    vm.afterSave = afterSave;
    vm.beforeRemove = beforeRemove;

    // instantiate base controller
    $controller('CRUDController', { vm: vm, modelService: UsersService, options: {} });

    function onActivate() {
      vm.queryFilters = {};

      vm.roles = RolesService.query().then(function (response) {
        vm.roles = response;
      });
    }

    function applyFilters(defaultQueryFilters) {
      return angular.extend(defaultQueryFilters, vm.queryFilters);
    }

    function afterClean() {
      vm.roles.forEach(function(role) {
        role.selected = false;
      });
    }

    function afterEdit() {
      vm.roles.forEach(function(role) {
        vm.resource.roles.forEach(function(roleUser) {
          if (role.id === roleUser.id) {
            role.selected = true;
          }
        });
      });
    }

    function beforeSave() {
      //filtra o array de roles para extrair somente os ids
      vm.resource.roles = lodash.map(lodash.filter(angular.copy(vm.roles), { selected: true }), function(role) {
        return { id: role.id };
      });
    }

    function afterSave(resource) {
      if (vm.resource.id === Auth.currentUser.id) {
        Auth.updateCurrentUser(resource);
      }
    }

    function beforeRemove(resource) {
      if (resource.id === Auth.currentUser.id) {
        PrToast.error($translate.instant('messages.user.removeYourSelfError'));
        return false;
      }
    }
  }
})();
