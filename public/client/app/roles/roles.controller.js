/*
 * This file is part of the Starter Pack Dynamic Authorization
 *
 * @author Amon Santana <amoncaldas@gmail.com>
 */

(function () {
  'use strict'

  angular
    .module('app')
    .controller('RolesController', RolesController)

  /** @ngInject */
  // eslint-disable-next-line max-params
  function RolesController (
    $controller,
    RolesService,
    ResourceAuthorizationService,
    lodash,
    PrToast,
    $translate) {
    var vm = this

    // Attributes Block

    // Functions Block

    vm.onActivate = function () {
      vm.actionsBeforeChange = []
      ResourceAuthorizationService.query().then(function (results) {
        vm.availableResources = results;
      })
    }

    /**
     * Lida com o evento de seleção de ação em um recurso
     * Caso 1: Quando o recurso é um coringa (recurso All) e a ação é um coringa (ação All)
     * seleciona todas as ações de todos os recursos
     * Caso 2: Quando o recuso é um coringa é selecioanda uma das ações possíveis (exceto a all )
     * seleciona a ação do mesmo tipo em todos os outros recursos
     * Caso 3: Quando o recuso não é um coringa, mas a ação é um coringa (ação all disponível em cada recurso)
     * seleciona todas as ações desse recurso
     * @param {object} currentResource recurso no qual houve mudança na seleção de ações
     */
    vm.actionsSelectionChanged = function (currentResource) {

      // Aqui recuperamos a action modificada (adicionada ou removida)
      var actionChanged = getActionChanged()

      // Aqui recuperamos o recurso coringa 'All' da lista de recursos disponíveis
      var wildcardResource = lodash.find(vm.availableResources, function (ar) {
        return ar.slug === 'all'
      })


      // Aqui verificamos se o recurso  que foi modificado é o recurso coringa (All)
      // Se sim, aplicamos as ações do coringa aos outros recursos
      if (wildcardResource.slug === currentResource.slug) {
        triggerAllSelectionForResource(currentResource, actionChanged)
        triggerAllSelectionForResources(wildcardResource, actionChanged)
      } else {
        // Não sendo o recurso coringa, disparamos a trigger que vai verificar
        // se foi selecionada a ação coringa de um recurso marcamos então todas as ações deste recurso
        triggerAllSelectionForResource(currentResource, actionChanged)
      }

      // Aqui disparamos a trigger que vai verificar se há ações dependentes (no próprio recurso ou em outro)
      // para cada ação selecinada do recurso. Se houver, a função seleciona as ações dependentes
      triggerActionDependenciesSelection(currentResource)


      // verifica se deve ser desmarcado (e demarca) o coringa all (do recurso coringa ou da ação coringa)
      // este caso ocorre quando all estava selecionado e é deselecionao um item
      // nesse caso não faz sentido manter o all selecionado, por que representaria uma inconssistência
      adjustTheAllSelection(currentResource, wildcardResource, actionChanged)

      // Após todos os tratamentos copiamos a atual lista de ações seleciondas como sendo
      // a lista anterior (na próxima mudança, ela será usada)
      vm.actionsBeforeChange = angular.copy(vm.resource.actions);

    }

    /**
     * Verifica se deve ser deselecionada (e deseleciona) a ação all de cada recurso
     * esta situação ocorre quando 'all' estava selecionado e é deselecionao um item da coleção.
     * Nesse caso não faz sentido manter o all selecionado, por que representaria uma inconssistência
     * @param {object} wildcardResource recurso coringa que serve para propagação de permissões
     * @param {object} currentResource recurso no qual deve ser deselecionada a ação 'all'
     * @param {object} actionChanged ação que foi modificada (selecionada ou deselecionada)
     */
    function adjustTheAllSelection(currentResource, wildcardResource, actionChanged) {
      //caso desmarque a opção todas

      if (actionChanged.action_type_slug === 'all' &&  actionChanged.wasAdded === false) {

        for (var i=0;i<currentResource.actions.length;i++) {
          var index = vm.resource.actions.indexOf(currentResource.actions[i]);

          vm.resource.actions.splice(index, 1);
        }
        return;
      }

      // Caso 1: se tudo, menos 'all' está selecionado então podemos tentar remover, nenhum efeito colateral.
      // Não precisamos de uma condição específica para tratar isso

      // Caso 2: se há itens não selecionados, além do 'all', então então podemos tentar remover, nenhum efeito colateral.

      // Caso 3: se tudo está selecionado e um item foi modificado, então está ocorrendo uma remoção.

      // Logo, podemos tentar remover o 'all' em todos os casos :-). Vale lembrar que essa tentativa não gera erro. Se houver, é removido
      // Conclusão: não há fluxo no qual precisemos checar se é adição ou remoção para remover o 'all'.
      // O código abaixo funciona para todos os casos e tratamos somente o caso de remoção de uma ação de um recurso específico

      if (actionChanged.action_type_slug !== 'all') {
        // no primeiro caso estamos lidando com a alteração de seleção no recurso coringa 'all'
        if (wildcardResource.slug === currentResource.slug) {
          //Tenta recuperar a ação coringa (all) do recurso coringa (all)
          var actionAllInWildcardResource = lodash.find(vm.resource.actions, function (a) {
            return a.action_type_slug === 'all' && a.resource_slug === wildcardResource.slug
          })

          // Se estiver marcado, o deseleciona.
          if (actionAllInWildcardResource) {
            lodash.remove(vm.resource.actions, function (a) {
              return a.id === actionAllInWildcardResource.id
            })
          }
        } else { // neste caso estamos lidando com a ação 'all' de um recuso específico
          lodash.remove(vm.resource.actions, function (a) {
            return a.action_type_slug === 'all' && a.resource_slug === currentResource.slug
          })
          lodash.remove(vm.resource.actions, function (a) {
            return a.action_type_slug === 'all' && a.resource_slug === wildcardResource.slug
          })

          // Aqui tratamos o caso de ser removido uma ação diferente de 'all' de um recurso específico.
          // Quando isso ocorre, tentamos remover essa ação do recurso coringa 'all', pois seria inconssistênte mantê-la selecionada
          // se um dos recursos não estiver com essa ação selecionada
          if (!actionChanged.wasAdded) {
            lodash.remove(vm.resource.actions, function (a) {
              return a.action_type_slug === actionChanged.action_type_slug && a.resource_slug === wildcardResource.slug
            })
          }
        }
      }
    }



    /**
     * Recupera a ação modificada
     */
    function getActionChanged() {
      // Aqui recuperamos as actions diff - o diferencial , XOR,
      // entre as ações que estavam marcadas antes dessa interação e as que estão maracadas agora
      var actionsDiff = lodash.xorBy(vm.resource.actions, vm.actionsBeforeChange, 'id')
      var actionDiff = null;

      // As diferenças entre as duas coleções devem, em princípio, ser sempre de 1 ação.
      // Selecionamos o primeiro item e a propriedade 'wasAdded' é inicializada como false
      if (actionsDiff.length === 1) {
        actionDiff = actionsDiff[0]
        actionDiff.wasAdded = false;
      }
      // se houver um item de diferença, e se ele tiver sido adicionado (está na coleção de ações adicionadas vm.resource.actions)
      // a propriedade wasAdded é setada como true;
      if (actionDiff) {
        var added = lodash.filter(vm.resource.actions, function (a) {
          return a.id === actionDiff.id
        })

        if (added && added.length > 0) {
          actionDiff.wasAdded = true;
        }

      }
      return actionDiff
    }

    /**
    * Propaga as ações selecionadas no recurso coringa para todos os recursos
    * @param {object} wildcardResource recurso coringa que serve para propagação de permissões
    * @param {object} actionChanged ação que foi modificada (selecionada ou deselecionada)
    */
    function triggerAllSelectionForResources (wildcardResource, actionChanged) {
      if (actionChanged.wasAdded) {
        angular.forEach(vm.availableResources, function (availableResource, index) {
          // Devemos propagar as ações para outros recuros somente se o recurso omdificado for o coringa (All)
          if (availableResource.slug !== wildcardResource.slug) {
            // Aqui recuperamos as ações que devem ser propagadas
            var propagableActions = lodash.filter(vm.resource.actions, function (a) {
              return a.resource_slug === wildcardResource.slug
            })

            angular.forEach(propagableActions, function (action) {
              selectActions(vm.availableResources[index], action.action_type_slug)
            })
          }
        })
      }
    }

    /**
    * Executa a seleção de todas as ações de um determinado recurso quando a ação 'all' for marcada
    * @param {object} currentResource recurso no qual devem ser selecionadas todas as ações
    * @param {object} actionChanged ação que foi modificada (selecionada ou deselecionada)
    */
    function triggerAllSelectionForResource (currentResource, actionChanged) {
      if (actionChanged.wasAdded) {
        // Here we check if the action that is being applied the wildcard ACTION named 'All'.
        // If yes, this means that all actions must be applied to current resource
        var actionAllToCurrentResource = lodash.find(vm.resource.actions, function (a) {
          return a.action_type_slug === 'all' && a.resource_slug === currentResource.slug
        })

        // Se a ação coringa (All) estiver marcada, mandamos marcar todas as ações no recurso
        if (actionAllToCurrentResource && actionChanged.wasAdded) {
          selectActions(currentResource, 'all')
        }
      }
    }

    /**
    * Verifica se as dependências de cada uma das ações marcadas para um recurso e as adiciona como permissão
    * Ao selecionar as dependências, notifica o usuário com um toaster
    * @param {object} currentResource recurso a partir do qual devem ser selecionadas as ações dependentes
    */
    function triggerActionDependenciesSelection (currentResource) {
      // Aqui recuperamos as ações do recurso que foram selecionadas
      var resourceActionsSelected = lodash.intersectionBy(currentResource.actions, vm.resource.actions, 'id')

      // Aqui selecionamos, dentre as ações selecionadas, aquelas que têm ações como dependência
      var actionsWithDependencies = lodash.filter(resourceActionsSelected, function (a) {
        return a.dependencies.length > 0
      })

      // Se houver ações que tem dependências, as percorremos e selecionamos as ações que são dependẽncias de cada ação
      if (actionsWithDependencies.length > 0) {
        angular.forEach(actionsWithDependencies, function (action) {
          angular.forEach(action.dependencies, function (actionD) {
            var resourceDestinationIndex = lodash.findIndex(vm.availableResources, function (r) {
              return r.slug === actionD.resource_slug
            })

            selectActions(vm.availableResources[resourceDestinationIndex], actionD.action_type_slug)
          })

          // Notificamos na interface que as ações dependentes foram automaticmaente selecionadas
          notifyAutoDependenciesSelection(currentResource, action)
        })
      }
    }


    /**
    * Notifica que as ações dependentes foram automaticamente selecionadas
    * @param {object} resource resource com o qual a ação que tem dependências está vinculada
    * @param {object} action ação para a qual há dependências
    */
    function notifyAutoDependenciesSelection (resource, action) {
      var params = { action: action.action_type_name + ' ' + resource.name }
      PrToast.info($translate.instant('messages.role.actionDependenciesAutoSelected', params))
    }

    /**
    * Marca como selecionada uma ação num dado recurso
    * Se a ação passada for a coringa 'all', seleciona todas as ações do recurso
    * @param {object} resource recurso no qual devem ser selecionadas as ações
    * @param {string} actionSlug slug da action que deve ser selecionada no recurso
    */
    function selectActions (resource, actionSlug) {
      // Se a ação indicada é do tipo coringa (all), marcamos todas as ações do recurso
      if (actionSlug === 'all') {
        angular.forEach(resource.actions, function (action, index) {
          var currentActionAlreadyAdded = lodash.find(vm.resource.actions, function (a) { a.id === action.id })

          if (!currentActionAlreadyAdded) {
            vm.resource.actions.push(resource.actions[index])
          }
        })
      } else { // caso contrário aplicamos somente a ação indicada
        var actionIndex = lodash.findIndex(resource.actions, ['action_type_slug', actionSlug])

        if (actionIndex > 0) {
          vm.resource.actions.push(resource.actions[actionIndex])
        }
      }
      // Garantimos que não há action duplicadas na lista
      vm.resource.actions = lodash.uniqBy(vm.resource.actions, 'id');
    }

    // Ajusta dados do model depois de carregada a tela de edição
    vm.afterEdit = function() {
      vm.actionsBeforeChange = []
      if (vm.resource.actions) {
        vm.actionsBeforeChange = angular.copy(vm.resource.actions);
      }
    }

    vm.afterClean = function(){
      vm.resource.name = null
      vm.resource.actions = []
      vm.actionsBeforeChange = []
    }

    vm.beforeSave = function () {

      var defaultSelectedActions = lodash.filter(vm.availableResources, function (ar) {
        return ar.slug === 'authorization' ||  ar.slug === 'authentication'
      })

      if (!vm.resource.actions.length) {
        PrToast.error($translate.instant('messages.role.emptyActions'));
        return false;
      }

      angular.forEach(defaultSelectedActions, function(resource) {
        vm.resource.actions = vm.resource.actions.concat(resource.actions);
      })

      // Adicionando estrutura para permissão de alteração de senha
      var usersPermissions = lodash.filter(vm.availableResources, function (ar) {
        return ar.slug === 'users'
      })

      var updateProfilePermission = lodash.filter(usersPermissions[0].actions, function (ar) {
        return ar.action_type_slug === 'updateProfile';
      })

      vm.resource.actions = vm.resource.actions.concat(updateProfilePermission);
      // Fim dessa estrutura
    }

    vm.onRemoveError = function (data) {
      PrToast.error($translate.instant(data.error));
    }

    // instantiate base controller
    $controller('CRUDController', { vm: vm, modelService: RolesService, options: { } })
  }
})()
