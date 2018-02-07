/*eslint angular/file-name: 0, no-undef: 0*/

(function() {
  'use strict';

  //encapsula as bibliotecas externas para serem carregadas como uma dependência
  //do angular.
  angular
    .module('ngProdeb')
    .constant('lodash', _)
    .constant('_', _)
    .constant('alasql', alasql)
    .constant('moment', moment);
})();
