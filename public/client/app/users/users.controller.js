(function () {

  'use strict';

  angular
    .module('app')
    .controller('UsersController', UsersController);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function UsersController($controller, lodash, UsersService, RolesService, // NOSONAR
    EstabelecimentosSaudeService, InstituicoesEnsinoService, PrToast, Auth, $translate, PrDialog) {

    var vm = this;

    vm.onActivate = onActivate;
    vm.applyFilters = applyFilters;
    vm.afterEdit = afterEdit;
    vm.afterClean = afterClean;
    vm.afterSave = afterSave;
    vm.beforeRemove = beforeRemove;
    vm.beforeSave = beforeSave;
    vm.onRoleChange = onRoleChange;
    vm.onEstabelecimentoChange = onEstabelecimentoChange;
    vm.onInstituicaoChange = onInstituicaoChange;
    vm.printSigla = printSigla;
    vm.searchEstabelecimentoAutoComplete = searchEstabelecimentoAutoComplete;
    vm.searchInstituicaoAutoComplete = searchInstituicaoAutoComplete;
    vm.ativar = ativar;

    //Constante Pública
    vm.PERFIL = {
      ADM_SISTEMA: 1,
      GESTOR_SISTEMA: 2,
      GESTOR_ENSINO: 3,
      GESTOR_SAUDE: 4,
      ASSISTENTE_SAUDE: 5,
    };

    // instantiate base controller
    $controller('CRUDController', { vm: vm, modelService: UsersService, options: {} });

    function onActivate() {
      vm.queryFilters = {};

      vm.roles = RolesService.query().then(function (response) {
        vm.roles = response;
      });
    }

    function applyFilters(defaultQueryFilters) {
      return angular.extend(defaultQueryFilters, vm.queryFilters);
    }

    function afterClean() {
      vm.roles.forEach(function (role) {
        role.selected = false;
      });
      resetaPerfil();
    }

    function afterEdit() {
      vm.gestorEnsino = false;
      vm.gestorSaude = false;
      if (vm.resource.roles[0] != null) {
        vm.resource.role = vm.resource.roles[0].id;
      }

      if (vm.resource.instituicao_ensino_id !== undefined && vm.resource.instituicao_ensino_id !== null) {
        vm.gestorEnsino = true;
        vm.instituicaoEnsino = vm.resource.instituicao_ensino;
        delete vm.resource.estabelecimento_saude_id;
      }

      if (vm.resource.estabelecimento_saude_id !== undefined && vm.resource.estabelecimento_saude_id !== null) {
        vm.gestorSaude = true;
        vm.estabelecimentoSaude = vm.resource.estabelecimento_saude;
        delete vm.resource.instituicao_ensino_id;
      }

    }

    /**
     * Ao mudar o combo de perfil
     */
    function onRoleChange() {
      //Reseta as configurações
      resetaPerfil();
      vm.resource.roles = [];
      if (vm.resource.role !== "" && vm.resource.role !== undefined) {
        vm.resource.roles.push({ id: vm.resource.role });
        switch (vm.resource.role) {
          case vm.PERFIL.GESTOR_ENSINO:
            vm.gestorEnsino = true;
            break;
          case vm.PERFIL.GESTOR_SAUDE:
            vm.gestorSaude = true;
            break;
          case vm.PERFIL.ASSISTENTE_SAUDE:
            vm.gestorSaude = true;
            break;
        }
      }
    }

    /**
     * Ao mudar o autocomplete de estabelecimento
     */
    function onEstabelecimentoChange(){
      if(vm.estabelecimentoSaude){
        vm.resource.estabelecimento_saude_id = vm.estabelecimentoSaude.id;
      }
    }

    /**
     * Ao mudar o autocomplete de instituição
     */
    function onInstituicaoChange(){
      vm.instituicaoEnsinoTerm = vm.instituicaoEnsinoTerm.toUpperCase()
      if(vm.instituicaoEnsino){
        vm.resource.instituicao_ensino_id = vm.instituicaoEnsino.id;
      }
    }

    /**
     * Executada antes de salvar um registro.
     * Se retornar false o fluxo é interrompido.
     */
    function beforeSave() {
      if (vm.gestorSaude === true) {
        if (!verificaGestorSaude()) {
          PrToast.error($translate.instant('messages.user.missingEstabelecimentoSaude'));
          return false;
        }
      }
      if (vm.gestorEnsino === true) {
        if (!verificaGestorEnsino()) {
          PrToast.error($translate.instant('messages.user.missingInstituicaoEnsino'));
          return false;
        }
      }
    }

    /**
     * Executada depois de salvar um registro.
     */
    function afterSave(resource) {
      if (vm.resource.id === Auth.currentUser.id) {
        Auth.updateCurrentUser(resource);
      }
      resetaPerfil();
    }

    /**
     * Executada antes de remover um registro
     */
    function beforeRemove(resource) {
      if (resource.id === Auth.currentUser.id) {
        PrToast.error($translate.instant('messages.user.removeYourSelfError'));
        return false;
      }
    }

    /**
     * Printa prepara a sigla de um estabelecimento para ser exibida na tela caso ela exista.
     */
    function printSigla(sigla) {
      if (sigla !== "" && sigla !== undefined && sigla !== null) {
        return sigla + " - ";
      } else {
        return "";
      }
    }

    /**
     * Remove configurações relacionadas ao tipo de perfil que foi selecionado.
     */
    function resetaPerfil() {
      vm.gestorSaude = false;
      vm.gestorEnsino = false;
      delete vm.resource.instituicao_ensino_id;
      delete vm.instituicaoEnsino;
      delete vm.resource.estabelecimento_saude_id;
      delete vm.estabelecimentoSaude;
    }

    /**
     * Retorna true caso seja gestor de saude e tenha selecionado um Estabelecimento.
     */
    function verificaGestorSaude() {
      var gestorSaude = false;
      if (vm.gestorSaude === true) {
        if (vm.resource.estabelecimento_saude_id !== null && vm.resource.estabelecimento_saude_id !== "" && vm.resource.estabelecimento_saude_id !== undefined) {
          gestorSaude = true;
        }
      }
      return gestorSaude;
    }

    /**
     * Retorna true caso seja gestor de ensino e tenha selecionado uma Instituição.
     */
    function verificaGestorEnsino() {
      var gestorEnsino = false;
      if (vm.gestorEnsino === true) {
        if (vm.resource.instituicao_ensino_id !== null && vm.resource.instituicao_ensino_id !== "" && vm.resource.instituicao_ensino_id !== undefined) {
          gestorEnsino = true;
        }
      }
      return gestorEnsino;
    }

    /**
     * Busca estabelecimentos para o autocomplete
     */
    function searchEstabelecimentoAutoComplete(estabelecimentoSaudeTerm) {
      return EstabelecimentosSaudeService.query({ nome: estabelecimentoSaudeTerm });
    }

    /**
     * Busca instituições para o autocomplete
     */
    function searchInstituicaoAutoComplete(instituicaoEnsinoTerm) {
      return InstituicoesEnsinoService.query({ nome: instituicaoEnsinoTerm });
    }

    function ativar(resource) {
      var config = {
        title: $translate.instant('dialog.confirmTitle'),
        description: $translate.instant('dialog.confirmDescription')
      }

      PrDialog.confirm(config).then(function() {
        UsersService.ativarUsuario({ user_id: resource.id })
        .then(function () {
          vm.search();
          PrToast.info($translate.instant('messages.user.activeSuccess'));
        });
      });
    }
  }
})();
