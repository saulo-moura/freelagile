(function() {
  'use strict';

  /** @ngInject */
  angular
    .module('app')
    .component('contentBody', {
      replace: true,
      transclude: true,
      templateUrl: ['Global', function(Global) {
        return Global.clientPath + '/widgets/content-body.html'
      }],
      bindings: {
        layoutAlign: '@'
      },
      controller: [function() {
        var ctrl = this;

        ctrl.$onInit = function() {
          // Make a copy of the initial value to be able to reset it later
          ctrl.layoutAlign = angular.isDefined(ctrl.layoutAlign) ? ctrl.layoutAlign : 'center start';
        };
      }]
    });

}());
