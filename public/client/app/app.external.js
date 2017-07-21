/*eslint angular/file-name: 0, no-undef: 0*/
(function() {
  'use strict';

  /**
   * Transforma bibliotecas externas em serviços do angular para ser possível utilizar
   * através da injeção de dependência
   */
  angular
    .module('app')
    .constant('lodash', _)
    .constant('moment', moment);

}());
