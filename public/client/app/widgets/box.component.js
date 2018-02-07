(function() {
  'use strict';

   /** @ngInject */
  angular
    .module('app')
    .component('box', {
      replace: true,
      templateUrl: ['Global', function(Global) {
        return Global.clientPath + '/widgets/box.html'
      }],
      transclude: {
        toolbarButtons: '?boxToolbarButtons',
        footerButtons: '?boxFooterButtons'
      },
      bindings: {
        boxTitle: '@',
        toolbarClass: '@',
        toolbarBgColor: '@'
      },
      controller: ['$transclude', function($transclude) {
        var ctrl = this;

        ctrl.transclude = $transclude;

        ctrl.$onInit = function() {
          if (angular.isUndefined(ctrl.toolbarBgColor)) ctrl.toolbarBgColor = 'default-primary';
        };
      }]
    });
}());
