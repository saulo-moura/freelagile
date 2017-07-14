(function () {
  'use strict';

  angular
    .module('ngProdeb')
    .config(config);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function config($mdThemingProvider, $mdIconProvider,
    moment, PrIcons, $qProvider) {
    //configurações padrões das bibliotecas que são utilizadas
    $mdThemingProvider.theme('default')
      .primaryPalette('indigo')
      .accentPalette('amber');

    moment.locale('pt-BR');

    moment.createFromInputFallback = function(config) {
      // unreliable string magic, or
      config._d = new Date(config._i);
    };

    $qProvider.errorOnUnhandledRejections(false);

    angular.forEach(PrIcons, function(icon) {
      $mdIconProvider.icon(icon.id, icon.url);
    });
  }
}());
