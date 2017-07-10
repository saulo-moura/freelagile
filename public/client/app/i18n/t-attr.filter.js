(function() {

  'use strict';

  angular
    .module('app')
    .filter('tAttr', tAttr);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function tAttr($filter) {
    /**
     * Filtro para tradução de um atributo de um model
     * 
     * @param {any} name nome do atributo
     * @returns o nome do atributo traduzido caso encontre se não o nome passado por parametro
     */    
    return function(name) {
      var key = 'attributes.' + name;
      var translate = $filter('translate')(key);

      return (translate === key) ? name : translate;
    }
  }

})();
