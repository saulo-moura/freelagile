(function() {
  'use strict';

  angular
    .module('app')
    .factory('UsersService', UsersService);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function UsersService(lodash, Global, serviceFactory) {
    return serviceFactory('users', {
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
         * Verifica se o usuário tem o perfil admin.
         *
         * @returns {boolean}
         */
        isAdmin: function() {
          return this.hasProfile('admin');
        }
      }
    });
  }

}());
