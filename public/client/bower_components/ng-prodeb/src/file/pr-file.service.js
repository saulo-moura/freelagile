/*eslint-env es6*/

(function() {
  'use strict';

  angular
    .module('ngProdeb')
    .factory('PrFile', PrFile);

  /**
   * Service que encapsula os serviços
   * de exportação e importação de arquivos
   */
  /** @ngInject */
  function PrFile(alasql, lodash, $filter) {
    var obj = {
      exportToExcel: exportToExcel,
      exportToCSV: exportToCSV
    };

    //Defined filters

    alasql.fn.formatDate = function(date, format) {
      return $filter('prDate')(date, format);
    }

    /**
     * Exporta os dados enviados para o formato informado.
     *
     * @param {string|array} fields
     *  String contendo os campos separado por virgula
     *    ex: name, description
     *    ex: name as Nome, description as 'Descrição'
     *    ex: *  (para todos os campos)
     *  Array de objetos com os campos
     *    ex: [
     *      { name: 'name', label: 'Nome' },
     *      { name: 'description', label: 'Descrição' },
     *      { name: 'role.name', label: 'Perfil' },
     *      { name: 'formatDate(date)', label: 'Data' },*
     *    ]
     * @param {array} data - Array que vai servir como fonte de dados
     * @param {string} fileName - Nome do arquivo sem a extensão
     * @param {object} config
     * Configurações da documentação do alasql como:
     *  - (boolean) headers
     * mais as destacadas abaixo
     *  - (string) where
     *  - (string) orderBy
     *
     * filters definidos
     *
     * formatDate(campo, [formato])
     *
     * Exemplo:
     *
     * var cars = [
     *  { name: 'Stilo',  brand: 'Fiat', date: moment().subtract(1, 'years') },
     *  { name: 'Punto',  brand: 'Fiat', date: moment().subtract(3, 'years') },
     *  { name: 'Fiesta', brand: 'Ford', date: '04-01-2017' }
     * ]
     *
     * PrFile.exportToExcel([
     *  { name: 'brand', label: 'Marca' },
     *  { name: 'name', label: 'Nome' },
     *  { name: 'formatDate(date, \'DD-MM-YYYY\')', label: 'Comprado em?' }
     * ], cars, 'data-export', {
     *  orderBy: 'brand ASC, name ASC',
     *  where: 'brand like "%Fi%"'
     * });
     *
     * @returns {promisse} - Retorna uma promisse que pode ou não ser resolvida
     */
    function exportTo(fields, data, fileName, config) {
      var defaultConfig = {
        headers: true
      }

      if (angular.isObject(config)) angular.merge(defaultConfig, config);
      if (angular.isUndefined(fileName)) fileName = 'export'

      defaultConfig.where = (angular.isDefined(defaultConfig.where)) ? ' WHERE ' + defaultConfig.where : ' ';
      defaultConfig.orderBy = (angular.isDefined(defaultConfig.orderBy)) ? ' ORDER BY ' + defaultConfig.orderBy : ' ';

      fileName = fileName + '.' + defaultConfig.formatTo;

      return alasql.promise('SELECT ' + buildFields(fields)
        + ' INTO ' + defaultConfig.formatTo.toUpperCase() + '(?, ?) FROM ? '
        + defaultConfig.where
        + defaultConfig.orderBy, [fileName, defaultConfig, data]);
    }

    /**
     * Exporta os dados enviados para csv
     *
     * @see exportTo
     */
    function exportToCSV(fields, data, fileName, config) {
      if (angular.isUndefined(config)) config = {};

      config.formatTo = 'csv';

      return exportTo(fields, data, fileName, config);
    }

    /**
     * Exporta os dados enviados para excel
     *
     * @see exportTo
     */
    function exportToExcel(fields, data, fileName, config) {
      if (angular.isUndefined(config)) config = {};

      config.formatTo = 'xlsx';

      return exportTo(fields, data, fileName, config);
    }

    /**
     * Monta uma string contendo os campos para o SELECT da Query.
     */
    function buildFields(fields) {
      if (angular.isArray(fields)) {
        fields = lodash.map(fields, function(field) {
          return field.name + ' as [' + field.label + ']';
        }).join(', ');
      }

      return fields;
    }

    return obj;
  }

}());
