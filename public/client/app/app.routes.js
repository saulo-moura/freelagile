(function() {
  'use strict';

  angular
    .module('app')
    .config(routes);

  /** @ngInject */
  function routes($stateProvider, $urlRouterProvider, Global) {
    $stateProvider
      .state('app', {
        url: '/app',
        templateUrl: Global.clientPath + '/layout/app.html',
        abstract: true,
        resolve: { //ensure langs is ready before render view
          translateReady: ['$translate', '$q', function($translate, $q) {
            var deferred = $q.defer();

            $translate.use('pt-BR').then(function() {
              deferred.resolve();
            });

            return deferred.promise;
          }]
        }
      })
      .state(Global.notAuthorizedState, {
        url: '/acesso-negado',
        templateUrl: Global.clientPath + '/layout/not-authorized.html',
        data: { needAuthentication: false }
      });

    $urlRouterProvider.when('/password/reset', Global.resetPasswordUrl);
    $urlRouterProvider.when('/app', Global.loginUrl);
    $urlRouterProvider.otherwise(Global.loginUrl);
  }
}());
