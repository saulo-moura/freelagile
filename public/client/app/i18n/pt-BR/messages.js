/*eslint angular/file-name: 0, no-undef: 0*/
(function() {
  'use strict';

  angular
    .module('app')
    .constant('pt-BR.i18n.messages', {
      internalError: 'Ocorreu um erro interno, contate o administrador do sistema',
      notFound: 'Nenhum registro encontrado',
      notAuthorized: 'Você não tem acesso a esta funcionalidade.',
      searchError: 'Não foi possível realizar a busca.',
      saveSuccess: 'Registro salvo com sucesso.',
      operationSuccess: 'Operação realizada com sucesso.',
      operationError: 'Erro ao realizar a operação',
      saveError: 'Erro ao tentar salvar o registro.',
      removeSuccess: 'Remoção realizada com sucesso.',
      removeError: 'Erro ao tentar remover o registro.',
      resourceNotFoundError: 'Recurso não encontrado',
      notNullError: 'Todos os campos obrigatórios devem ser preenchidos.',
      duplicatedResourceError: 'Já existe um recurso com essas informações.',
      periodoFinalInferiorAoInicial: 'O Período Final não deve ser inferior ao Período Inicial.',
      removerAssociado: 'Este registro não pode ser removido enquanto estiver associado à(s) entidade(s): {{entidade}}',
      validate: {
        fieldRequired: 'O campo {{field}} é obrigratório.'
      },
      layout: {
        error404: 'Página não encontrada'
      },
      login: {
        logoutInactive: 'Você foi deslogado do sistema por inatividade. Favor entrar no sistema novamente.',
        invalidCredentials: 'Credenciais Inválidas',
        unknownError: 'Não foi possível realizar o login. Tente novamente. ' +
          'Caso não consiga favor encontrar em contato com o administrador do sistema.',
        userNotFound: 'Não foi possível encontrar seus dados'
      },
      dashboard: {
        welcome: 'Seja bem Vindo {{userName}}',
        description: 'Utilize o menu para navegação.'
      },
      mail: {
        mailErrors: 'Ocorreu um erro nos seguintes emails abaixo:\n',
        sendMailSuccess: 'Email enviado com sucesso!',
        sendMailError: 'Não foi possível enviar o email.',
        passwordSendingSuccess: 'O processo de recuperação de senha foi iniciado. Caso o email não chegue em 10 minutos tente novamente.'
      },
      user: {
        removeYourSelfError: 'Você não pode remover seu próprio usuário',
        userExists: 'Usuário já adicionado!',
        profile: {
          updateError: 'Não foi possível atualizar seu profile'
        },
        missingEstabelecimentoSaude: "É necessário definir o Estabelecimento de Saúde.",
        missingInstituicaoEnsino: "É necessário definir a Instituição de Ensino",
        activeSuccess: "Usuário ativado com sucesso"
      },
      vagas:{
        dataInicioJaneiro: "A data de início deve ser do mês de Janeiro.",
        dataFimDezembro: "A data do fim deve ser do mês de Dezembro.",
        validarEstabelecimento: "O cadastro do Estabelecimento de Saúde ainda não foi finalizado."
      },
      role: {
        actionDependenciesAutoSelected: 'Permissões adicionais necessárias para a ação {{action}} foram selecionadas automaticamente',
        emptyActions: 'Um perfil tem que permitir acesso a, pelo menos, um recurso (funcionalidade/ação) do sistema.'
      },
      queryDinamic: {
        noFilter: 'Nenhum filtro adicionado'
      }
    })

}());
