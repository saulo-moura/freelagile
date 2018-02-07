/*eslint-env es6*/

(function() {
  'use strict';

  angular
    .module('ngProdeb')
    .factory('PrToast', Toast);

  /**
   * Serviço que encapsula e amplia os serviços do angular toastr
   */
  /** @ngInject */
  function Toast($mdToast, lodash, $log, PrDialog) {
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
          template: `
            <md-toast>
              <div class="md-toast-content" md-colors="::{background:'${color}'}">
                <span class="md-toast-text" flex>${msg}</span>
              </div>
            </md-toast>
          `,
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

    /**
     * Exibe um toast com as mensagens de erro referente a validação.
     *
     * @param {string | object | array} errors - String, Objeto ou Array contendo as mensagens de erro.
     * Suporta diferente formatos:
     *
     * Para validações de atributos
     *   {
     *    "nome-do-atributo1": ["mensagem de erro 1", "mensagem de erro 2"],
     *    "nome-do-atributo2": ["mensagem de erro 1"]
     *   }
     *
     * ou - Para várias mensagens simples
     *   [
     *    'Mensagem 1',
     *    'Mensagem 2'
     *   ]
     *
     *  ou - Para 1 única mensagem
     *   "Mensagem 1"
     *
     *  ou - Para exceptions - Neste caso usa um PrDialog
     *   {
     *     message: 'Exception Desconhecida',
     *     source: 'StarterPack.Controllers.SupportController.langs()',
     *     line: 21,
     *     stacktrace: 'at StarterPack.Controllers.SupportController.langs() in /home/workspa...'
     *   }
     * @param {string} msg - Opcional. Mensagem de erro.
     */
    function error(errors, options = {}) {
      //se for um objeto contendo os erros, itera sobre os atributos do mesmo
      //para exibir a(s) mensagem(ns) de erro atribuidas
      if (angular.isObject(errors)) {
        var errorStr = '';

        if (checkErrorIsUnknownException(errors)) {
          errorStr += 'Message: ' + errors.message
            + '<br/>Source: ' + errors.source
            + '<br/>Line: ' + errors.line
            + '<br/><br/>StackTrace: ';

          var steps = errors.stacktrace.split(' at ');

          if (steps.length > 0) {
            steps.forEach(function(step, index) {
              errorStr +=  '<br/>Step ' + (index + 1) + ': ' + step;
            });
          } else {
            errorStr +=  errors.stacktrace;
          }

          return PrDialog.alert({
            title: 'Exception',
            description: errorStr
          });
        } else {
          // exibe as mensagem de erro contidas no objeto
          //  {
          //    "name": ["o campo nome é obrigatório"],
          //    "password": [
          //      "A confirmação de senha não confere.",
          //      "senha deve ter no mínimo 6 caracteres."
          //    ]
          //  }
          lodash.forIn(errors, function(keyErrors) {
            errorStr += buildArrayMessage(keyErrors);
          });
        }

        errors = errorStr;
      } else {
        if (angular.isArray(errors)) {
          errors = buildArrayMessage(errors);
        }
      }

      return toast(errors, 'red-A700', options);
    }

    function buildArrayMessage(arrMsg) {
      var msg =  '';

      if (angular.isArray(arrMsg)) {
        //itera sobre os erros de um atributo
        arrMsg.forEach(function(error) {
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
     * @param {object} options - Options da documentação do $mdToast
     */
    function errorValidation(errors, msg, options) {
      obj.error((angular.isArray(errors) || angular.isObject(errors)) ? errors : msg, options);
    }

    function info(msg, options) {
      return toast(msg, 'teal', options);
    }

    function warn(msg, options) {
      return toast(msg, 'warn', options);
    }

    function checkErrorIsUnknownException(errors) {
      return (angular.isObject(errors)
        && angular.isDefined(errors.line)
        && angular.isDefined(errors.source)
        && angular.isDefined(errors.stacktrace));
    }

    return obj;
  }

}());
