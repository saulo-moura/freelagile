(function() {
  'use strict';

  angular
    .module('app')
    .factory('UsersService', UsersService);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function UsersService(lodash, Global, serviceFactory) {
    var model = serviceFactory('users', {
      //quando instancia um usuário sem passar parametro,
      //o mesmo vai ter os valores defaults abaixo
      defaults: {
        roles: []
      },

      actions: {
        /**
         * Serviço que atualiza os dados do perfil do usuário logado
         *
         * @param {object} attributes
         * @returns {promise} Uma promise com o resultado do chamada no backend
         */
        updateProfile: {
          method: 'PUT',
          url: Global.apiPath + '/profile',
          override: true,
          wrap: false
        },
        ativarUsuario: {
          method: 'PUT',
          url: 'ativar'
        }
      },

      instance: {
        /**
         * Verifica se o usuário tem os perfis informados.
         *
         * @param {any} roles perfis a serem verificados
         * @param {boolean} all flag para indicar se vai chegar todos os perfis ou somente um deles
         * @returns {boolean}
         */
        hasProfile: function(roles, all) {
          roles = angular.isArray(roles) ? roles : [roles];

          var userRoles = lodash.map(this.roles, 'slug');

          if (all) {
            return lodash.intersection(userRoles, roles).length === roles.length;
          } else { //return the length because 0 is false in js
            return lodash.intersection(userRoles, roles).length;
          }
        },

         /**
         * Verifica se o usuário tem uma determinada permissão de ação num determinado recurso
         *
         * @param {any} resource recurso a ser verificado
         * @param {any} action ação a ser verificada
         * @returns {boolean}
         */
        hasPermission: function(resource, action) {
          // Se não for passada uma ação, é verificado se o usuário tem a ação primária de listar (internamente chamada de index)
          action = action? action : 'index';

          var allowed = lodash.find(this.allowed_actions, function(a) {
            return a.action_type_slug === action && a.resource_slug === resource;
          })

          return allowed? true : false;
        },

        /**
         * Verifica se o usuário tem o perfil admin.
         *
         * @returns {boolean}
         */
        isAdmin: function() {
          return this.hasProfile('admin');
        },

        /**
         * Verifica se o usuário tem permissao para exibir um item com subitens
         *
         * @param {any} subItems recurso a ser verificado
         * @returns {boolean}
         */
        itemMenuPermitido: function(subItems) {
          var i = subItems.length;
          var permissao = true;
          while (i-- > 0) {
            if (angular.isUndefined(subItems[i].needPermission)) {
              return true;
            }
            permissao = this.hasPermission(subItems[i].needPermission.resource, subItems[i].needPermission.action)
            if (permissao) {
              return permissao;
            }
          }
          return permissao;
        }
      }
    });

    return model;
  }

}());
