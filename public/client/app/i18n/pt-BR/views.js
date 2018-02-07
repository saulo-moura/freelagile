/*eslint angular/file-name: 0, no-undef: 0*/
(function() {
  'use strict';

  angular
    .module('app')
    .constant('pt-BR.i18n.views', {
      breadcrumbs: {
        user: 'Administração - Usuário',
        'user-profile': 'Perfil',
        dashboard: 'Dashboard',
        audit: 'Administração - Auditoria',
        mail: 'Administração - Envio de e-mail',
        projects: 'Projetos',
        'dinamic-query': 'Administração - Consultas Dinâmicas',
        'not-authorized': 'Acesso Negado',
        tasks: 'Tarefas',
        milestones: 'Sprints',
        kanban: 'Kanban Board',
        vcs: 'Controle de Versão',
        releases: 'Releases'
      },
      titles: {
        dashboard: 'Dashboard',
        mailSend: 'Enviar e-mail',
        taskList: 'Lista de Tarefas',
        userList: 'Lista de Usuários',
        auditList: 'Lista de Logs',
        register: 'Formulário de Cadastro',
        resetPassword: 'Redefinir Senha',
        update: 'Formulário de Atualização',
        tasks: 'Tarefas',
        milestones: 'Sprints',
        kanban: 'Kanban Board',
        vcs: 'Controle de Versão',
        releases: 'Releases'
      },
      actions: {
        send: 'Enviar',
        save: 'Salvar',
        clear: 'Limpar',
        clearAll: 'Limpar Tudo',
        restart: 'Reiniciar',
        filter: 'Filtrar',
        search: 'Pesquisar',
        list: 'Listar',
        edit: 'Editar',
        cancel: 'Cancelar',
        update: 'Atualizar',
        remove: 'Remover',
        getOut: 'Sair',
        add: 'Adicionar',
        in: 'Entrar',
        loadImage: 'Carregar Imagem',
        signup: 'Cadastrar',
        criarProjeto: 'Criar Projeto',
        projectList: 'Lista de Projetos',
        tasksList: 'Lista de Tarefas',
        milestonesList: 'Lista de Sprints',
        finalize: 'Finalizar',
        reply: 'Responder'
      },
      fields: {
        date: 'Data',
        action: 'Ação',
        actions: 'Ações',
        audit: {
          dateStart: 'Data Inicial',
          dateEnd: 'Data Final',
          resource: 'Recurso',
          allResources: 'Todos Recursos',
          type: {
            created: 'Cadastrado',
            updated: 'Atualizado',
            deleted: 'Removido'
          }
        },
        login: {
          resetPassword: 'Esqueci minha senha',
          confirmPassword: 'Confirmar senha'
        },
        mail: {
          to: 'Para',
          subject: 'Assunto',
          message: 'Mensagem'
        },
        queryDinamic: {
          filters: 'Filtros',
          results: 'Resultados',
          model: 'Model',
          attribute: 'Atributo',
          operator: 'Operador',
          resource: 'Recurso',
          value: 'Valor',
          operators: {
            equals: 'Igual',
            diferent: 'Diferente',
            conteins: 'Contém',
            startWith: 'Inicia com',
            finishWith: 'Finaliza com',
            biggerThan: 'Maior',
            equalsOrBiggerThan: 'Maior ou Igual',
            lessThan: 'Menor',
            equalsOrLessThan: 'Menor ou Igual'
          }
        },
        project: {
          name: 'Nome',
          totalTask: 'Total de Tarefas'
        },
        task: {
          done: 'Não Feito / Feito'
        },
        user: {
          perfils: 'Perfis',
          nameOrEmail: 'Nome ou Email'
        }
      },
      layout: {
        menu: {
          projects: 'Projetos',
          dashboard: 'Dashboard',
          milestones: 'Sprints',
          tasks: 'Tarefas',
          kanban: 'Kanban',
          vcs: 'Controle de Versão',
          releases: 'Releases'
        }
      },
      tooltips: {
        audit: {
          viewDetail: 'Visualizar Detalhamento'
        },
        user: {
          perfil: 'Perfil',
          transfer: 'Transferir'
        },
        task: {
          listTask: 'Listar Tarefas'
        }
      }
    })

}());
