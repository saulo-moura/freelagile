(function() {
  'use strict';

  angular
    .module('app')
    .constant('Global', {
      appName: 'Freelagile',
      homeState: 'app.projects',
      loginUrl: 'app/login',
      loginState: 'app.login',
      resetPasswordState: 'app.password-reset',
      notAuthorizedState: 'app.not-authorized',
      tokenKey: 'server_token',
      clientPath: 'client/app',
      apiPath: 'api/v1',
      imagePath: 'client/images'
    });
}());
