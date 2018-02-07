/*eslint-env es6*/

(function () {
  'use strict';

  angular.module('ngProdeb')
    .factory('PrDialog', dialogService);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function dialogService($log, $mdDialog, $mdUtil, $rootScope, $animate, $document) {
    return {
      custom: custom,
      confirm: confirm,
      close: close,
      alert: alert
    };

    /**
     * Método que configura e realiza o merge do objeto recebido via parâmetro
     * com a configuração padrão para a exibição do dialog
     * @param {object} config - Objeto contendo as configurações
     * @returns {dialogService} - Retorna o service
     */
    function build(config) {

      if (!angular.isObject(config)) {
        $log.error('PrDialog: Parâmetro inválido, é esperando um objeto como parâmetro.');
        return;
      }

      var defaultOptions = {
        hasBackdrop: false,
        escapeToClose: false,
        bindToController: true,
        clickOutsideToClose: true,
        autoWrap: true,
        skipHide: true,
        locals: {},
        zIndex: 75,
        fullscreen: false
      };

      //não fazemos merge da propriedade locals para não estourar o limite de recursividade
      if (angular.isDefined(config.locals)) {
        defaultOptions.locals = config.locals;
        delete config.locals;
      }

      return angular.merge(defaultOptions, config);
    }

    /**
     * Método que exibe o dialog de confirmação na tela depois que o build e invocado
     * de uma determinada ação
     * @returns {promisse} - Retorna uma promisse que pode ou não ser resolvida
     */
    function alert(config) {

      var options = build(config);

      options.locals = {
        title: (angular.isDefined(options.title) ? options.title : 'Exception'),
        description: (angular.isDefined(options.description) ? options.description : ''),
        okBgColor: (angular.isDefined(options.okBgColor) ? options.okBgColor : 'red-A700'),
        toolbarBgColor: (angular.isDefined(options.toolbarBgColor) ? options.toolbarBgColor : 'red-A700')
      };

      options.template =
          ` <md-dialog flex=50 aria-label="${options.locals.title}">
              <md-toolbar md-scroll-shrink md-colors="::{background:'default-{{ctrl.toolbarBgColor}}'}">
                <div class="md-toolbar-tools">
                  <h3>
                    <span>${options.locals.title}</span>
                  </h3>
                </div>
              </md-toolbar>
              <md-dialog-content layout-margin>
                <p>${options.locals.description}</p>
              </md-dialog-content>
              <md-dialog-actions>
                <md-button class="md-raised"
                  md-colors="::{background:'default-{{ctrl.okBgColor}}'}"
                  ng-click="ctrl.okAction()">Ok</md-button>
              </md-dialog-actions>
            </md-dialog>
          `;

      options.controller = ['$mdDialog', function($mdDialog) {
        var vm = this;

        vm.okAction = okAction;

        function okAction() {
          $mdDialog.hide();
        }
      }];

      options.controllerAs = 'ctrl';
      options.clickOutsideToClose = false;
      options.hasBackdrop = true;

      return $mdDialog.show(options);
    }

    /**
     * Método que exibe o dialog de confirmação na tela depois que o build e invocado
     * de uma determinada ação
     * @returns {promisse} - Retorna uma promisse que pode ou não ser resolvida
     */
    function confirm(config) {

      var options = build(config);

      options.template =
          ` <md-dialog flex=50 aria-label="{{::ctrl.title}}">
              <md-toolbar md-scroll-shrink>
                <div class="md-toolbar-tools">
                  <h3>
                    <span>{{::ctrl.title}}</span>
                  </h3>
                </div>
              </md-toolbar>
              <md-dialog-content layout-margin>
                <p>{{::ctrl.description}}</p>
              </md-dialog-content>
              <md-dialog-actions>
                <md-button class="md-raised"
                  md-colors="::{background:'default-{{ctrl.yesBgColor}}'}"
                  ng-click="ctrl.yesAction()">Sim</md-button>
                <md-button class="md-raised"
                  md-colors="::{background:'default-{{ctrl.noBgColor}}'}"
                  ng-click="ctrl.noAction()">Não</md-button>
              </md-dialog-actions>
            </md-dialog>
          `;
      options.locals = {
        title: (angular.isDefined(options.title) ? options.title : ''),
        description: (angular.isDefined(options.description) ? options.description : ''),
        yesBgColor: (angular.isDefined(options.yesBgColor) ? options.yesBgColor : 'primary'),
        noBgColor: (angular.isDefined(options.noBgColor) ? options.noBgColor : 'accent')
      };

      options.controller = ['$mdDialog', function($mdDialog) {
        var vm = this;

        vm.noAction = noAction;
        vm.yesAction = yesAction;

        function noAction() {
          $mdDialog.cancel();
        }
        function yesAction() {
          $mdDialog.hide();
        }
      }];

      options.controllerAs = 'ctrl';
      options.clickOutsideToClose = false;
      options.hasBackdrop = true;

      return $mdDialog.show(options);
    }

    /**
     * Método que exibe o dialog customizado na tela depois que o build e invocado
     * @returns {promisse} - Retorna uma promisse que pode ou não ser resolvida
     */
    function custom(config) {

      var options = build(config);

      if (angular.isUndefined(options.templateUrl) && angular.isUndefined(options.template)) {
        $log.error(
          'PrDialog: templateUrl ou template indefinido, é esperando um templateUrl ou um template como atributo.');
        return;
      }

      //Criado o backdrop manualmente para diminuir o z-index através de uma classe css
      //o z-index tem que ficar menor devido ao dialog.confirm usar o z-index original de 80
      options = addBackdrop(options);

      options.hasBackdrop = false;

      return $mdDialog.show(options);
    }

    /**
     * Método que cria o backdrop e mostra na tela com o z-index configuravél
     * para sobrepor os elementos da tela
     */
    function addBackdrop(options) {
      if (options.hasBackdrop) {
        var backdrop = $mdUtil.createBackdrop($rootScope, 'md-dialog-backdrop md-opaque md-backdrop-custom');

        $animate.enter(backdrop, angular.element($document.find('body')));

        var originalOnRemoving = options.onRemoving;

        //Método executado quando a animação de fechamento do dialog termina
        options.onRemoving = function () {
          backdrop.remove();
          if (angular.isFunction(originalOnRemoving)) originalOnRemoving.call();
        }

        var originalOnComplete = options.onComplete;

        //Método executado quando a animação de abertura do dialog termina
        options.onComplete = function (scope, element) {
          var zIndex = parseInt(options.zIndex, 10);

          angular.element($document[0].querySelector('.md-backdrop-custom')).css('z-index', zIndex);
          element.css('z-index', zIndex + 1);
          if (angular.isFunction(originalOnComplete)) originalOnComplete.call();
        }
      }

      return options;
    }

    /**
     * Método que serve para fechar o dialog
     */
    function close() {
      $mdDialog.hide();
    }

  }

})();
