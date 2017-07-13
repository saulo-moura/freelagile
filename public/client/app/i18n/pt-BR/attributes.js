/*eslint angular/file-name: 0, no-undef: 0*/
(function() {
  'use strict';

  angular
    .module('app')
    .constant('pt-BR.i18n.attributes', {
      email: 'Email',
      password: 'Senha',
      name: 'Nome',
      image: 'Imagem',
      roles: 'Perfis',
      date: 'Data',
      initialDate: 'Data Inicial',
      finalDate: 'Data Final',
      task: {
        description: 'Descrição',
        done: 'Feito?',
        priority: 'Prioridade',
        scheduled_to: 'Agendado Para?',
        project: 'Projeto'
      },
      project: {
        cost: 'Custo'
      },
      //é carregado do servidor caso esteja definido no mesmo
      auditModel: {
      }
    })

}());
