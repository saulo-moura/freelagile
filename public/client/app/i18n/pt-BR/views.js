/*eslint angular/file-name: 0, no-undef: 0*/
(function () {
  'use strict';

  angular
    .module('app')
    .constant('pt-BR.i18n.views', {
      breadcrumbs: {
        user: 'Administração - Usuário',
        'user-profile': 'Perfil',
        dashboard: 'SGEO - Sistema de Gestão de Estágio Obrigatório',
        audit: 'Administração - Auditoria',
        mail: 'Administração - Envio de e-mail',
        roles: 'Administração - Perfis',
        project: 'Exemplos - Projetos',
        'dinamic-query': 'Administração - Consultas Dinâmicas',
        'not-authorized': 'Acesso Negado',
        'estabelecimentos-saude': 'Estabelecimento de Saúde',
        'vagas': 'Disponibilidade de Vagas',
        'parametros-sistema': 'Administração - Painel de Controle',
        'relatorio-estabelecimentos-saude': 'Relatório de Estabelecimentos de Saúde Pendentes',
        'relatorio-disponibilidade-vagas': 'Relatório de Disponibilidade de Vagas',
        'tipos-estabelecimento-saude': 'Tipos de Estabelecimento de Saúde',
        areas: 'Áreas',
        setores: 'Setores',
        'naturezas-juridicas': 'Naturezas Jurídicas',
        cursos: 'Cursos',
        especialidades: 'Especialidades',
        especificacoes: 'Especificações',
        'instituicoes-ensino': 'Instituições de Ensino Superior',
        modalidades: 'Modalidades'
      },
      titles: {
        dashboard: 'Página inicial',
        mailSend: 'Enviar e-mail',
        taskList: 'Lista de Tarefas',
        userList: 'Lista de Usuários',
        auditList: 'Lista de Logs',
        register: 'Formulário de Cadastro',
        resetPassword: 'Redefinir Senha',
        update: 'Formulário de Atualização',
        'relatorio-estabelecimentos-saude': 'Relatório de Estabelecimentos de Saúde Pendentes',
        'relatorio-disponibilidade-vagas': 'Relatório de Disponibilidade de Vagas',
        especialidades: 'Especialidades',
        especificacoes: 'Especificações',
        cursos: 'Cursos',
        modalidades: 'Modalidades'
      },
      actions: {
        send: 'Enviar',
        save: 'Salvar',
        finalize: 'Finalizar',
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
        cantRemove: 'Não é possível remover',
        approval: 'Aprovação',
        approve: 'Aprovar',
        reject: 'Rejeitar',
        historico: 'Histórico',
        view: 'Visualizar',
        back: 'Voltar',
        disable: 'Desativar',
        reactivate: 'Reativar',
        imprimir: 'Imprimir',
        download: 'Download'
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
        },
        estabelecimentoSaude: {
          nome: 'Estabelecimento de Saúde',
          tipo: 'Tipo',
          naturezaJuridica: 'Natureza Jurídica'
        },
        vaga: {
          estabelecimentoSaude: 'Estabelecimento de Saúde',
          curso: 'Curso',
          modalidade: 'Modalidade',
          area: 'Área',
          setor: 'Setor',
          status: 'Status'
        }
      },
      layout: {
        menu: {
          dashboard: 'Dashboard',
          project: 'Projetos',
          admin: 'Administração',
          examples: 'Exemplos',
          user: 'Usuários',
          roles: 'Perfis',
          mail: 'Enviar e-mail',
          audit: 'Auditoria',
          dinamicQuery: 'Consultas Dinamicas',
          estabelecimentosSaude: 'Estabelecimento de Saúde',
          cadastroes: 'Cadastro de ES',
          vagas: 'Disponibilidade de Vagas',
          painelcontrole: 'Painel de Controle',
          instituicoesEnsino: 'Instituições de Ensino',
          especialidades: 'Especialidades',
          especificacoes: 'Especificações',
          cadastrosBasicos: 'Cadastros Básicos',
          tiposEstabelecimentoSaude: 'Tipos de Estabelecimento de Saúde',
          naturezasJuridicas: 'Naturezas Jurídicas',
          areas: 'Áreas',
          setores: 'Setores',
          cursos: 'Cursos',
          modalidades: 'Modalidades'
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
        },
        estabelecimentoSaude: {
          listaDeEstabeleicmentosDeSaudePendentes: 'Lista de Estabelecimentos de Saúde Pendentes'
        },
        vagas: {
          listaDeDisponibilidadeDeVagasParaImpressao: 'Lista de Disponibilidade de Vagas Para Impressão',
          gerarRelatorioDeDisponibilidadeDeVagas: 'Gerar Relatório de Disponibilidade de Vagas'
        }
      }
    })

}());
