/*eslint-env es6*/

(function() {
  'use strict';

  /**
   * Diretiva que exibe um spinner sempre que um broadcast, manualmente, é disparado
   */
  /** @ngInject */
  angular
    .module('ngProdeb')
    .component('prSpinner', {
      template: `
        <md-progress-linear class="spin-label-component {{::$ctrl.color}}"
          ng-style="$ctrl.style"
          md-mode="indeterminate"
          ng-show="$ctrl.spinner && $ctrl.spinner.show"></md-progress-linear>
        `,
      bindings: {
        position: '@',
        color: '@'
      },
      controller: ['$scope', function($scope) {
        var ctrl = this;

        ctrl.$onInit = function() {
          //Define a posição
          ctrl.style = { position: angular.isDefined(ctrl.position) ? ctrl.position : 'fixed' };
          if (angular.isUndefined(ctrl.color)) ctrl.color = 'md-primary';
        };
        //comportamento padrão
        ctrl.spinner = {
          show: false
        };

        //Escuta o canal emitido via broadcast
        //para exibir/esconder o componente
        $scope.$on('show-spinner', function() {
          ctrl.spinner = {
            show: true
          };
        });

        $scope.$on('hide-spinner', function() {
          ctrl.spinner = {
            show: false
          };
        });
      }]
    });

})();
