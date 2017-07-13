(function () {
  'use strict';

  angular
    .module('app')
    .config(config);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function config(Global, $mdThemingProvider, $modelFactoryProvider,  // NOSONAR
    $translateProvider, moment, $mdAriaProvider) {

    $translateProvider
      .useLoader('languageLoader')
      .useSanitizeValueStrategy('escape');

    $translateProvider.usePostCompiling(true);

    moment.locale('pt-BR');

    //os serviços referente aos models vai utilizar como base nas urls
    $modelFactoryProvider.defaultOptions.prefix = Global.apiPath;

    // Configuration theme
    $mdThemingProvider.theme('default')
      .primaryPalette('brown', {
        default: '700'
      })
      .accentPalette('amber')
      .warnPalette('deep-orange');

    // Enable browser color
    $mdThemingProvider.enableBrowserColor();

    $mdAriaProvider.disableWarnings();

  }
}());
