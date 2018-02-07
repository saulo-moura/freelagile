(function() {

  'use strict';

  angular
    .module('app')
    .controller('ProfileController', ProfileController);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function ProfileController(UsersService, Auth, PrToast, $translate, $window, moment) {
    var vm = this;

    vm.update = update;
    vm.historyBack = historyBack;

    activate();

    function activate() {
      vm.user = angular.copy(Auth.currentUser);
      if (vm.user.birthday) {
        vm.user.birthday = moment(vm.user.birthday).format('DD/MM/YYYY');
      }
    }

    function update() {
      if (vm.user.birthday) {
        vm.user.birthday = moment(vm.user.birthday);
      }
      UsersService.updateProfile(vm.user).then(function (response) {
        //atualiza o usuário corrente com as novas informações
        Auth.updateCurrentUser(response);
        PrToast.success($translate.instant('messages.saveSuccess'));
        historyBack();
      });
    }

    function historyBack() {
      $window.history.back();
    }

  }

})();
