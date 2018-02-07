(function () {
  'use strict';

  angular
    .module('app')
    .config(config);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function config(Global, $mdThemingProvider, $modelFactoryProvider,  // NOSONAR
    $translateProvider, moment, $mdAriaProvider, $mdDateLocaleProvider) {

    $translateProvider
      .useLoader('languageLoader')
      .useSanitizeValueStrategy('escape');

    $translateProvider.usePostCompiling(true);

    moment.locale('pt-BR');

    //os serviços referente aos models vai utilizar como base nas urls
    $modelFactoryProvider.defaultOptions.prefix = Global.apiPath;

    // Configuration theme
    $mdThemingProvider.theme('default')
      .primaryPalette('grey', {
        default: '800'
      })
      .accentPalette('amber')
      .warnPalette('deep-orange');

    // Enable browser color
    $mdThemingProvider.enableBrowserColor();

    $mdAriaProvider.disableWarnings();

    $mdDateLocaleProvider.formatDate = function(date) {
      return date ? moment(date).format('DD/MM/YYYY') : '';
    };
  }
}());
