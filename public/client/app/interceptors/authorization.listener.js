(function() {
  'use strict';

  angular
    .module('app')
    .run(authorizationListener);

  /** @ngInject */
  function authorizationListener($rootScope, $state, Global, Auth) {
    /**
     * A cada mudança de estado ("página") verifica se o usuário tem o perfil
     * necessário para o acesso a mesma
     */
    $rootScope.$on('$stateChangeStart', function(event, toState) {
      if (toState.data && toState.data.needAuthentication &&
        toState.data.needPermission && Auth.authenticated() &&
        !Auth.currentUser.hasPermission(toState.data.needPermission.resource, toState.data.needPermission.action)) {

        $state.go(Global.notAuthorizedState);
        event.preventDefault();
      }

    });
  }
}());
