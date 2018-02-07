/*eslint-env es6*/

(function() {
  'use strict';

  /**
   * Diretiva que exibe um spinner sempre que um broadcast, manualmente, é disparado
   */
  /** @ngInject */
  angular
    .module('ngProdeb')
    .component('prDateTimePicker', {
      template: `
          <md-input-container class="md-block" flex="$ctrl.flex">
            <label for="$ctrl.id">{{$ctrl.label}}</label>
            <md-icon md-font-set="material-icons" class="md-warn"
              ng-style="$ctrl.style.label"
              ng-click="$ctrl.show(true)"
              md-colors="$ctrl.colors.icon">date_range</md-icon>
            <input
              id="$ctrl.id"
              ng-model="$ctrl.ngModel"
              ng-click="$ctrl.show(false)"
              ng-readonly="$ctrl.clickToShowInField"
              text-mask="$ctrl.maskConfig"
              type="text">
            </input>
          </md-input-container>
        `,
      controller: ['mdcDateTimeDialog', 'moment', function(mdcDateTimeDialog, moment) {
        var ctrl = this;

        ctrl.$onInit = function() {
          ctrl.style = {
            label: {
              cursor: 'pointer'
            }
          }

          ctrl.autoOk = setDefaultToTrue(ctrl.autoOk);
          ctrl.withMinutesPicker = setDefaultToTrue(ctrl.withMinutesPicker);
          ctrl.clickToShowInField = setDefaultToTrue(ctrl.clickToShowInField);
          ctrl.format = (ctrl.format || ((ctrl.withTime)) ? 'DD/MM/YYYY HH:mm' : 'DD/MM/YYYY');

          ctrl.defineMask();
          ctrl.defineColors();
        }

        ctrl.defineColors = function() {
          ctrl.colors = {
            icon: {
              color: (ctrl.iconColor) ? ctrl.iconColor : 'default-grey-900'
            }
          }

        }

        ctrl.defineMask = function() {
          if (angular.isUndefined(ctrl.mask)) {
            ctrl.mask = [/\d/, /\d/, '/', /\d/, /\d/, '/', /\d/, /\d/, /\d/, /\d/];

            if (ctrl.withTime) {
              ctrl.mask = ctrl.mask.concat([' ', /\d/, /\d/, ':', /\d/, /\d/]);
            }
          }

          ctrl.maskConfig = {
            mask: ctrl.mask,
            guide: false
          }
        }

        function setDefaultToTrue(value) {
          return (angular.isUndefined(value) || value);
        }

        ctrl.show = function(fromIcon) {
          if (ctrl.clickToShowInField || fromIcon) {
            mdcDateTimeDialog.show({
              maxDate: (angular.isUndefined(ctrl.maxDate)) ? null : ctrl.maxDate,
              format: ctrl.format,
              minutes: ctrl.withMinutesPicker,
              currentDate: ctrl.ngModel,
              autoOk: ctrl.autoOk,
              cancelText: 'Cancelar',
              todayText: 'Hoje',
              time: ctrl.withTime,
              date: true
            })
            .then(function (date) {
              ctrl.ngModel = moment(date).format(ctrl.format);
            });
          }
        }
      }],
      require: {
        ngModelCtrl: 'ngModel'
      },
      bindings: {
        label: '=',
        minDate: '=',
        maxDate: '=',
        ngModel: '<',
        id: '<',
        iconColor: '<',
        withTime: '<',
        withMask: '<',
        withMinutesPicker: '<',
        clickToShowInField: '<',
        autoOk: '<',
        format: '<',
        flex: '<',
        mask: '<'
      }
    });
})();

