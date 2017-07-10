/*eslint angular/file-name: 0*/
(function() {
  'use strict';

  angular
    .module('app')
    .factory('serviceFactory', serviceFactory);

  /** @ngInject */
  /**
   * Mais informações:
   * https://github.com/swimlane/angular-model-factory/wiki/API
   */
  function serviceFactory($modelFactory, PrToast) {
    var service = function(url, options) {
      var model;
      var defaultOptions = {
        actions: {
          /**
           * Serviço comum para realizar busca com paginação
           * O mesmo espera que seja retornado um objeto com items e total
           */
          paginate: {
            method: 'GET',
            isArray: false,
            wrap: false,
            afterRequest: function(response) {
              if (response.permissionError) {
                PrToast.error(response['error']);
              } else if (response['items']) {
                response['items'] = model.List(response['items']);
              }

              return response;
            }
          }
        }
      }

      model = $modelFactory(url, angular.merge(defaultOptions, options))

      return model;
    }

    return service;
  };
})();
