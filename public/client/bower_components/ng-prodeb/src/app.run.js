(function () {
  'use strict';

  angular
    .module('ngProdeb')
    .run(run);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function run($templateCache, PrIcons) {
    angular.forEach(PrIcons, function(icon) {
      $templateCache.put(icon.url, icon.svg);
    });
  }
}());


