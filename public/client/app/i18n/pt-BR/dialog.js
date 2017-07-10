/*eslint angular/file-name: 0, no-undef: 0*/
(function() {
  'use strict';

  angular
    .module('app')
    .constant('pt-BR.i18n.dialog', {
      confirmTitle: 'Confirmação',
      confirmDescription: 'Confirma a ação?',
      removeDescription: 'Deseja remover permanentemente {{name}}?',
      audit: {
        created: 'Informações do Cadastro',
        updatedBefore: 'Antes da Atualização',
        updatedAfter: 'Depois da Atualização',
        deleted: 'Informações antes de remover'
      },
      login: {
        resetPassword: {
          description: 'Digite abaixo o email cadastrado no sistema.'
        }
      }
    })

}());
