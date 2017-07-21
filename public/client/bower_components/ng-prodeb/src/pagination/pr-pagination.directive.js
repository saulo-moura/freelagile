/*eslint-env es6*/

(function() {
  'use strict';

  angular.module('ngProdeb')
    .directive('prPagination', paginationDirective);

  /**
   * Diretiva que exibe uma paginação.
   * Adota o estilo de paginação da Busca do Google.
   * Utiliza os estilos do bootstrap
   */
  /** @ngInject */
  function paginationDirective() {
    return {
      restrict: 'AE',
      scope: {
        paginator: '='
      },
      template: `
        <section class="pr-pagination" layout="row">
          <section layout="row" layout-align="center center" layout-wrap
            style="margin-right: 10px"
            ng-show="paginator.numberOfPages > 1">
              <md-button class="md-raised"
                ng-disabled="paginator.currentPage === 1"
                ng-click="paginator.goToPage(1)">{{paginator.options.labels.first}}</md-button>
              <md-button class="md-raised"
                ng-disabled="paginator.currentPage === 1"
                ng-click="paginator.previousPage()">{{paginator.options.labels.previous}}</md-button>
              <md-button class="md-raised"
                ng-repeat="n in paginator.pages(s)"
                ng-class="{'md-primary': n == paginator.currentPage}"
                ng-click="paginator.goToPage(n)"
                ng-bind="n">1</md-button>
            <md-button class="md-raised"
              ng-disabled="paginator.currentPage == paginator.numberOfPages"
              ng-click="paginator.nextPage()">{{paginator.options.labels.next}}</md-button>
            <md-button class="md-raised"
              ng-disabled="paginator.currentPage == paginator.numberOfPages"
              ng-click="paginator.goToPage(paginator.numberOfPages)">{{paginator.options.labels.last}}</md-button>
          </section>
          <section layout="row" layout-align="center center"
            ng-show="paginator.total > 0">
            <md-button class="md-raised" style="cursor: default;"
              ng-disabled="true" md-colors="::{background:'accent'}">Total: {{paginator.total}} registro(s)</md-button>
          </section>
        </section>`
    };
  }

})();
