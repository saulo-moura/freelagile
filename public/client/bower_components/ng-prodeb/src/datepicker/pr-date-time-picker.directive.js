/*eslint-env es6*/

(function() {
  'use strict';

  /**
   * Diretiva que exibe um spinner sempre que um broadcast, manualmente, é disparado
   */
  /** @ngInject */
  angular
    .module('ngProdeb')
    .directive('prDateTimePicker', function(moment) {

      function buildDatePicker(attr) {
        var autoOk = (angular.isUndefined(attr.autoOk) || attr.autoOk === 'true');
        var withTime = (angular.isDefined(attr.withTime) && attr.withTime === 'true');
        var withMinutesPicker = (angular.isUndefined(attr.withMinutesPicker) || attr.withMinutesPicker === 'true');
        var format = attr.format || ((withTime) ? 'DD/MM/YYYY HH:mm' : 'DD/MM/YYYY');

        /**
         * Constroi o template do componente de escolha de data
         */
        return `
            <input
              id="${attr.id}"
              mdc-datetime-picker
              ng-model="ngModel"
              show-todays-date
              date="true"
              time="${withTime}"
              minutes="${withMinutesPicker}"
              cancel-text="Cancelar"
              today-text="Hoje"
              auto-ok="${autoOk}"
              format="${format}"
              min-date="${ angular.isDefined(attr.minDate) ? moment(attr.minDate).format(format) : '' }"
              max-date="'${ angular.isDefined(attr.maxDate) ? moment(attr.maxDate).format(format) : '' }'">
            </input>
        `
      }

      return {
        template: function(element, attr) {
          var template = buildDatePicker(attr);

          return template;
        },
        scope: {
          ngModel: '=',
          layout: '=',
          id: '=',
          withTime: '=?',
          withMinutesPicker: '=?',
          autoOk: '=?',
          format: '=?',
          minDate: '=?',
          maxDate: '=?'
        }
      }
    });
})();
