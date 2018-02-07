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
      birthday: 'Data de Nascimento',
      task: {
        description: 'Descrição',
        done: 'Feito?',
        priority: 'Prioridade',
        scheduled_to: 'Agendado Para?',
        project: 'Projeto',
        status: 'Status',
        title: 'Título',
        type: 'Tipo',
        milestone: 'Sprint',
        estimated_time: 'Tempo Estimado'
      },
      milestone: {
        title: 'Título',
        description: 'Descrição',
        date_start: 'Data Estimada para Início',
        date_end: 'Data Estimada para Fim',
        estimated_time: 'Tempo Estimado',
        estimated_value: 'Valor Estimado'
      },
      project: {
        cost: 'Custo',
        hourValueDeveloper: 'Valor da Hora Desenvolvedor',
        hourValueClient: 'Valor da Hora Cliente',
        hourValueFinal: 'Valor da Hora Projeto'
      },
      release: {
        title: 'Título',
        description: 'Descrição',
        release_date: 'Data de Entrega',
        milestone: 'Milestone',
        tasks: 'Tarefas'
      },
      //é carregado do servidor caso esteja definido no mesmo
      auditModel: {
      }
    })

}());
