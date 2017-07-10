(function() {
  'use strict';

  /** @ngInject */
  angular
    .module('app')
    .component('contentHeader', {
      templateUrl: ['Global', function(Global) {
        return Global.clientPath + '/widgets/content-header.html'
      }],
      replace: true,
      bindings: {
        title: '@',
        description: '@'
      }
    });

}());
