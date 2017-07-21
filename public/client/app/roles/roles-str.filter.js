(function() {

  'use strict';

  angular
    .module('app')
    .filter('rolesStr', rolesStr);

  /** @ngInject */
  function rolesStr(lodash) {
    /**
     * @param {array} roles lista de perfis
     * @return {string} perfis separados por ', '  
     */
    return function(roles) {
      return lodash.map(roles, 'slug').join(', ');
    };
  }

})();
