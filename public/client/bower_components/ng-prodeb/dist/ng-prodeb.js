'use strict';

/*eslint angular/file-name: 0*/

(function () {
  'use strict';

  //inicia o modulo da biblioteca e define as dependências

  angular.module('ngProdeb', ['ngMaterial', 'md.data.table', 'ngMaterialDatePicker', 'angularFileUpload']);
})();
'use strict';

(function () {
  'use strict';

  config.$inject = ["$mdThemingProvider", "$mdIconProvider", "moment", "PrIcons", "$qProvider"];
  angular.module('ngProdeb').config(config);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function config($mdThemingProvider, $mdIconProvider, moment, PrIcons, $qProvider) {
    //configurações padrões das bibliotecas que são utilizadas
    $mdThemingProvider.theme('default').primaryPalette('indigo').accentPalette('amber');

    moment.locale('pt-BR');

    moment.createFromInputFallback = function (config) {
      // unreliable string magic, or
      config._d = new Date(config._i);
    };

    $qProvider.errorOnUnhandledRejections(false);

    angular.forEach(PrIcons, function (icon) {
      $mdIconProvider.icon(icon.id, icon.url);
    });
  }
})();
'use strict';

/*eslint angular/file-name: 0, no-undef: 0*/

(function () {
  'use strict';

  //encapsula as bibliotecas externas para serem carregadas como uma dependência
  //do angular.

  angular.module('ngProdeb').constant('lodash', _).constant('alasql', alasql).constant('moment', moment);
})();
'use strict';

(function () {
  'use strict';

  run.$inject = ["$templateCache", "PrIcons"];
  angular.module('ngProdeb').run(run);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function run($templateCache, PrIcons) {
    angular.forEach(PrIcons, function (icon) {
      $templateCache.put(icon.url, icon.svg);
    });
  }
})();
'use strict';

/*eslint-env es6*/

(function () {
  'use strict';

  /**
   * Diretiva que exibe um spinner sempre que um broadcast, manualmente, é disparado
   */
  /** @ngInject */

  angular.module('ngProdeb').directive('prDateTimePicker', ["moment", function (moment) {

    function buildDatePicker(attr) {
      var autoOk = angular.isUndefined(attr.autoOk) || attr.autoOk === 'true';
      var withTime = angular.isDefined(attr.withTime) && attr.withTime === 'true';
      var withMinutesPicker = angular.isUndefined(attr.withMinutesPicker) || attr.withMinutesPicker === 'true';
      var format = attr.format || (withTime ? 'DD/MM/YYYY HH:mm' : 'DD/MM/YYYY');

      /**
       * Constroi o template do componente de escolha de data
       */
      return '\n            <input\n              id="' + attr.id + '"\n              mdc-datetime-picker\n              ng-model="ngModel"\n              show-todays-date\n              date="true"\n              time="' + withTime + '"\n              minutes="' + withMinutesPicker + '"\n              cancel-text="Cancelar"\n              today-text="Hoje"\n              auto-ok="' + autoOk + '"\n              format="' + format + '"\n              min-date="' + (angular.isDefined(attr.minDate) ? moment(attr.minDate).format(format) : '') + '"\n              max-date="\'' + (angular.isDefined(attr.maxDate) ? moment(attr.maxDate).format(format) : '') + '\'">\n            </input>\n        ';
    }

    return {
      template: function template(element, attr) {
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
    };
  }]);
})();
'use strict';

/*eslint-env es6*/

(function () {
  'use strict';

  dialogService.$inject = ["$log", "$mdDialog", "$mdUtil", "$rootScope", "$animate", "$document"];
  angular.module('ngProdeb').factory('PrDialog', dialogService);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function dialogService($log, $mdDialog, $mdUtil, $rootScope, $animate, $document) {
    return {
      custom: custom,
      confirm: confirm,
      close: close
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
    function confirm(config) {

      var options = build(config);

      options.template = ' <md-dialog flex=50 aria-label="{{::ctrl.title}}">\n              <md-toolbar md-scroll-shrink>\n                <div class="md-toolbar-tools">\n                  <h3>\n                    <span>{{::ctrl.title}}</span>\n                  </h3>\n                </div>\n              </md-toolbar>\n              <md-dialog-content layout-margin>\n                <p>{{::ctrl.description}}</p>\n              </md-dialog-content>\n              <md-dialog-actions>\n                <md-button class="md-raised"\n                  md-colors="::{background:\'default-{{ctrl.yesBgColor}}\'}"\n                  ng-click="ctrl.yesAction()">Sim</md-button>\n                <md-button class="md-raised"\n                  md-colors="::{background:\'default-{{ctrl.noBgColor}}\'}"\n                  ng-click="ctrl.noAction()">N\xE3o</md-button>\n              </md-dialog-actions>\n            </md-dialog>\n          ';
      options.locals = {
        title: angular.isDefined(options.title) ? options.title : '',
        description: angular.isDefined(options.description) ? options.description : '',
        yesBgColor: angular.isDefined(options.yesBgColor) ? options.yesBgColor : 'primary',
        noBgColor: angular.isDefined(options.noBgColor) ? options.noBgColor : 'accent'
      };

      options.controller = ['$mdDialog', function ($mdDialog) {
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
        $log.error('PrDialog: templateUrl ou template indefinido, é esperando um templateUrl ou um template como atributo.');
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
        };

        var originalOnComplete = options.onComplete;

        //Método executado quando a animação de abertura do dialog termina
        options.onComplete = function (scope, element) {
          var zIndex = parseInt(options.zIndex, 10);

          angular.element($document[0].querySelector('.md-backdrop-custom')).css('z-index', zIndex);
          element.css('z-index', zIndex + 1);
          if (angular.isFunction(originalOnComplete)) originalOnComplete.call();
        };
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
'use strict';

/*eslint-env es6*/

(function () {
  'use strict';

  PrFile.$inject = ["alasql", "lodash", "$filter"];
  angular.module('ngProdeb').factory('PrFile', PrFile);

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

    alasql.fn.formatDate = function (date, format) {
      return $filter('prDate')(date, format);
    };

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
      };

      if (angular.isObject(config)) angular.merge(defaultConfig, config);
      if (angular.isUndefined(fileName)) fileName = 'export';

      defaultConfig.where = angular.isDefined(defaultConfig.where) ? ' WHERE ' + defaultConfig.where : ' ';
      defaultConfig.orderBy = angular.isDefined(defaultConfig.orderBy) ? ' ORDER BY ' + defaultConfig.orderBy : ' ';

      fileName = fileName + '.' + defaultConfig.formatTo;

      return alasql.promise('SELECT ' + buildFields(fields) + ' INTO ' + defaultConfig.formatTo.toUpperCase() + '(?, ?) FROM ? ' + defaultConfig.where + defaultConfig.orderBy, [fileName, defaultConfig, data]);
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
        fields = lodash.map(fields, function (field) {
          return field.name + ' as [' + field.label + ']';
        }).join(', ');
      }

      return fields;
    }

    return obj;
  }
})();
'use strict';

(function () {

  'use strict';

  prDate.$inject = ["moment"];
  angular.module('ngProdeb').filter('prDate', prDate);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function prDate(moment) {
    /**
     * Formata uma data no padrão brasileiro
     */
    return function (value, inputFormat) {
      var outputFormat = 'DD/MM/YYYY';

      if (angular.isDefined(inputFormat)) {
        return moment(value, inputFormat).format(outputFormat);
      } else {
        return moment(value).format(outputFormat);
      }
    };
  }
})();
'use strict';

(function () {

  'use strict';

  prDatetime.$inject = ["moment"];
  angular.module('ngProdeb').filter('prDatetime', prDatetime);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function prDatetime(moment) {
    /**
     * Formata uma data com horário no padrão brasileiro
     */
    return function (value) {
      return moment(value).format('DD/MM/YYYY HH:mm');
    };
  }
})();
'use strict';

(function () {

  'use strict';

  real.$inject = ["$filter"];
  angular.module('ngProdeb').filter('real', real);

  /** @ngInject */
  // eslint-disable-next-line max-params
  function real($filter) {
    /**
     * Formata um valor para o padrão brasileiro
     */
    return function (value) {
      return $filter('currency')(value, 'R$ ');
    };
  }
})();
'use strict';

/*eslint-env es6*/

(function () {
  'use strict';

  /* eslint-disable max-len */

  angular.module('ngProdeb').constant('PrIcons', [{
    id: 'pr-excel',
    url: 'pr-excel.svg',
    svg: '<svg height="24" width="24" style="fill:#2E7D32" viewBox="0 0 24 24"><path d="M6,2H14L20,8V20A2,2 0 0,1 18,22H6A2,2 0 0,1 4,20V4A2,2 0 0,1 6,2M13,3.5V9H18.5L13,3.5M17,11H13V13H14L12,14.67L10,13H11V11H7V13H8L11,15.5L8,18H7V20H11V18H10L12,16.33L14,18H13V20H17V18H16L13,15.5L16,13H17V11Z" /></svg>'
  }]);
})();
'use strict';

/*eslint-env es6*/

(function () {
  'use strict';

  angular.module('ngProdeb').directive('prPagination', paginationDirective);

  /**
   * Diretiva que exibe uma paginação.
   * Adota o estilo de paginação da Busca do Google.
   * Utiliza os estilos do bootstrap
   */
  /** @ngInject */
  function paginationDirective() {
    return {
      restrict: 'AE',
      scope: {
        paginator: '='
      },
      template: '\n        <section class="pr-pagination" layout="row">\n          <section layout="row" layout-align="center center" layout-wrap\n            style="margin-right: 10px"\n            ng-show="paginator.numberOfPages > 1">\n              <md-button class="md-raised"\n                ng-disabled="paginator.currentPage === 1"\n                ng-click="paginator.goToPage(1)">{{paginator.options.labels.first}}</md-button>\n              <md-button class="md-raised"\n                ng-disabled="paginator.currentPage === 1"\n                ng-click="paginator.previousPage()">{{paginator.options.labels.previous}}</md-button>\n              <md-button class="md-raised"\n                ng-repeat="n in paginator.pages(s)"\n                ng-class="{\'md-primary\': n == paginator.currentPage}"\n                ng-click="paginator.goToPage(n)"\n                ng-bind="n">1</md-button>\n            <md-button class="md-raised"\n              ng-disabled="paginator.currentPage == paginator.numberOfPages"\n              ng-click="paginator.nextPage()">{{paginator.options.labels.next}}</md-button>\n            <md-button class="md-raised"\n              ng-disabled="paginator.currentPage == paginator.numberOfPages"\n              ng-click="paginator.goToPage(paginator.numberOfPages)">{{paginator.options.labels.last}}</md-button>\n          </section>\n          <section layout="row" layout-align="center center"\n            ng-show="paginator.total > 0">\n            <md-button class="md-raised" style="cursor: default;"\n              ng-disabled="true" md-colors="::{background:\'accent\'}">Total: {{paginator.total}} registro(s)</md-button>\n          </section>\n        </section>'
    };
  }
})();
'use strict';

/*eslint-env es6*/

(function () {
  'use strict';

  angular.module('ngProdeb').factory('PrPagination', paginationService);

  /** @ngInject */
  function paginationService() {

    /**
     * Cria e retorna uma instancia do objeto paginador.
     *
     * @constructor
     * @param {function} searchMethod - função responsável por carregar os dados
       e que vai ser chamada quando o usuário clicar em uma página
     * @param {int} perPage - Número de itens por página. Padrão é 10.
     * @param {object} _options - Objeto contendo as demais configurações
     */
    var PrPaginacao = function PrPaginacao(searchMethod, perPage, _options) {
      var options = {
        maxPages: 10,
        labels: {
          first: '««',
          previous: '«',
          next: '»',
          last: '»»'
        }
      };

      //sobreescreve os parametros padrões
      if (angular.isUndefined(perPage)) {
        perPage = 10;
      }

      if (angular.isDefined(_options)) {
        if (angular.isDefined(_options.maxPages)) {
          options.maxPages = _options.maxPages;
        }
        if (angular.isDefined(_options.labels)) {
          options.labels = _options.labels;
        }
      }

      //calcula quantas páginas vão ser exibidas na parte intermediaria da paginação
      options.maxPagesInner = Math.floor(options.maxPages / 2);

      //Cria o objeto paginador com os parametros iniciais
      this.searchMethod = searchMethod;
      this.numberOfPages = 1;
      this.total = 0;
      this.perPage = perPage;
      this.currentPage = 0;
      this.options = options;
    };

    /**
     * Calcula o número de páginas que vai ser exibida baseado no total de
     * itens com a perPage
     *
     * @param {int} total - total de itens
     */
    PrPaginacao.prototype.calcNumberOfPages = function (total) {
      this.total = total;

      if (total <= 0) {
        this.numberOfPages = 1;
      } else {
        this.numberOfPages = Math.floor(total / this.perPage) + (total % this.perPage > 0 ? 1 : 0);
      }
    };

    /**
     * Verifica as páginas que devem ser exibidas
     */
    PrPaginacao.prototype.pages = function () {
      var ret = [];

      for (var i = 1; i <= this.numberOfPages; i++) {
        if (this.currentPage === i) {
          ret.push(i);
        } else {
          if (this.currentPage <= this.options.maxPagesInner + 1) {
            if (i <= this.options.maxPages) {
              ret.push(i);
            }
          } else {
            if (i >= this.currentPage - this.options.maxPagesInner && i <= this.currentPage + this.options.maxPagesInner) {
              ret.push(i);
            }
          }
        }
      }
      return ret;
    };

    /**
     * Carrega os dados da página anterior
     */
    PrPaginacao.prototype.previousPage = function () {
      if (this.currentPage > 1) {
        this.searchMethod(this.currentPage - 1);
      }
    };

    /**
     * Carrega os dados da próxima página
     */
    PrPaginacao.prototype.nextPage = function () {
      if (this.currentPage < this.numberOfPages) {
        this.searchMethod(this.currentPage + 1);
      }
    };

    /**
     * Carrega os dados da página informada
     *
     * @param {int} page - pagina que deve ser carregada
     */
    PrPaginacao.prototype.goToPage = function (page) {
      if (page >= 1 && page <= this.numberOfPages) {
        this.searchMethod(page);
      }
    };

    return {
      getInstance: function getInstance(searchMethod, perPage, _options) {
        return new PrPaginacao(searchMethod, perPage, _options);
      }
    };
  }
})();
'use strict';

/*eslint-env es6*/

(function () {
  'use strict';

  /**
   * Diretiva que exibe um spinner sempre que um broadcast, manualmente, é disparado
   */
  /** @ngInject */

  angular.module('ngProdeb').component('prSpinner', {
    template: '\n        <md-progress-linear class="spin-label-component {{::$ctrl.color}}"\n          ng-style="$ctrl.style"\n          md-mode="indeterminate"\n          ng-show="$ctrl.spinner && $ctrl.spinner.show"></md-progress-linear>\n        ',
    bindings: {
      position: '@',
      color: '@'
    },
    controller: ['$scope', function ($scope) {
      var ctrl = this;

      ctrl.$onInit = function () {
        //Define a posição
        ctrl.style = { position: angular.isDefined(ctrl.position) ? ctrl.position : 'fixed' };
        if (angular.isUndefined(ctrl.color)) ctrl.color = 'md-primary';
      };
      //comportamento padrão
      ctrl.spinner = {
        show: false
      };

      //Escuta o canal emitido via broadcast
      //para exibir/esconder o componente
      $scope.$on('show-spinner', function () {
        ctrl.spinner = {
          show: true
        };
      });

      $scope.$on('hide-spinner', function () {
        ctrl.spinner = {
          show: false
        };
      });
    }]
  });
})();
'use strict';

(function () {
  'use strict';

  spinnerService.$inject = ["$rootScope"];
  angular.module('ngProdeb').factory('PrSpinner', spinnerService);

  /** @ngInject */
  function spinnerService($rootScope) {
    return {
      show: show,
      hide: hide
    };

    /**
     * Exibe o spinner
     */
    function show() {
      //emite o sinal para a diretiva informando que o componente spinner deve ser exibido
      $rootScope.$broadcast('show-spinner');
    }

    /**
     * Esconde o spinner
     */
    function hide() {
      $rootScope.$broadcast('hide-spinner');
    }
  }
})();
'use strict';

/*eslint-env es6*/

(function () {
  'use strict';

  Toast.$inject = ["$mdToast", "lodash", "$log"];
  angular.module('ngProdeb').factory('PrToast', Toast);

  /**
   * Serviço que encapsula e amplia os serviços do angular toastr
   */
  /** @ngInject */
  function Toast($mdToast, lodash, $log) {
    var obj = {
      success: success,
      error: error,
      errorValidation: errorValidation,
      info: info,
      warn: warn,
      hide: hide
    };

    /**
     * Exibe uma notificação
     *
     * @param {string} msg - Mensagem da notificação
     * @param {string} color - Cor de fundo da notificação
     *
      @returns {promisse} - Retorna uma promisse que pode ou não ser resolvida
     */
    function toast(msg, color, options) {
      if (msg) {
        var defaultOptions = {
          template: '\n            <md-toast>\n              <div class="md-toast-content" md-colors="::{background:\'' + color + '\'}">\n                <span class="md-toast-text" flex>' + msg + '</span>\n              </div>\n            </md-toast>\n          ',
          position: 'top right'
        };

        if (angular.isObject(options)) defaultOptions = angular.merge(defaultOptions, options);

        return $mdToast.show(defaultOptions);
      } else {
        $log.debug('Mensagem para ser exibida no Toast não foi informada');
      }
    }

    /**
     * Esconde uma notificação
     *
     * @param {object} object - Um argumento opcional para a promise a ser resolvida
     *
     * @returns {promisse} - Retorna uma promisse que é executada quando a notificação é removida do DOM
     */
    function hide(object) {
      return $mdToast.hide(object);
    }

    function success(msg, options) {
      return toast(msg, 'green', options);
    }

    function error(errors, options) {
      //se for um objeto contendo os erros, itera sobre os atributos do mesmo
      //para exibir a(s) mensagem(ns) de erro atribuidas
      if (angular.isObject(errors)) {
        var errorStr = '';

        // exibe as mensagem de erro contidas no objeto
        //  {
        //    "name": ["o campo nome é obrigatório"],
        //    "password": [
        //      "A confirmação de senha não confere.",
        //      "senha deve ter no mínimo 6 caracteres."
        //    ]
        //  }
        lodash.forIn(errors, function (keyErrors) {
          errorStr += buildArrayMessage(keyErrors);
        });

        errors = errorStr;
      } else {
        if (angular.isArray(errors)) {
          errors = buildArrayMessage(errors);
        }
      }

      return toast(errors, 'red-A700', options);
    }

    function buildArrayMessage(arrMsg) {
      var msg = '';

      if (angular.isArray(arrMsg)) {
        //itera sobre os erros de um atributo
        arrMsg.forEach(function (error) {
          msg += error + '<br/>';
        });
      } else {
        msg += arrMsg + '<br/>';
      }

      return msg;
    }

    /**
     * Exibe um toast com as mensagens de erro referente a validação.
     *
     * @param {object | array} errors - Objeto ou Array contendo as mensagens de erro. Deve estar
     * no seguinte formato.
     *   {
     *    "nome-do-atributo1": ["mensagem de erro 1", "mensagem de erro 2"],
     *    "nome-do-atributo2": ["mensagem de erro 1"]
     *   }
     * ou
     *   [
     *    'Mensagem 1',
     *    'Mensagem 2'
     *   ]
     * @param {string} msg - Opcional. Mensagem de erro.
     */
    function errorValidation(errors, msg, options) {
      obj.error(angular.isArray(errors) || angular.isObject(errors) ? errors : msg, options);
    }

    function info(msg, options) {
      return toast(msg, 'teal', options);
    }

    function warn(msg, options) {
      return toast(msg, 'warn', options);
    }

    return obj;
  }
})();
'use strict';

/*eslint-env es6*/

(function () {
  'use strict';

  angular.module('ngProdeb').directive('prUploaderBase64', ["$q", function ($q) {
    var slice = Array.prototype.slice;

    return {
      restrict: 'A',
      require: '?ngModel',
      link: function link(scope, element, attrs, ngModel) {
        if (!ngModel) return;

        ngModel.$render = function () {};

        element.bind('change', function (e) {
          var element = e.target;

          $q.all(slice.call(element.files, 0).map(readFile)).then(function (values) {
            if (element.multiple) ngModel.$setViewValue(values);else ngModel.$setViewValue(values.length ? values[0] : null);
          });

          function readFile(file) {
            var deferred = $q.defer();

            var reader = new FileReader();

            reader.onload = function (e) {
              deferred.resolve(e.target.result);
            };
            reader.onerror = function (e) {
              deferred.reject(e);
            };
            reader.readAsDataURL(file);

            return deferred.promise;
          }
        });
      }
    };
  }]);
})();