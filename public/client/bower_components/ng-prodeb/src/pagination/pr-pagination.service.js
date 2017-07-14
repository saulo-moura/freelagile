/*eslint-env es6*/

(function() {
  'use strict';

  angular.module('ngProdeb')
    .factory('PrPagination', paginationService);

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
    var PrPaginacao = function(searchMethod, perPage, _options) {
      var options = {
        maxPages: 10,
        labels: {
          first: '««',
          previous: '«',
          next: '»',
          last: '»»'
        }
      }

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
    }

    /**
     * Calcula o número de páginas que vai ser exibida baseado no total de
     * itens com a perPage
     *
     * @param {int} total - total de itens
     */
    PrPaginacao.prototype.calcNumberOfPages = function(total) {
      this.total = total;

      if (total <= 0) {
        this.numberOfPages = 1
      } else {
        this.numberOfPages = Math.floor(total / this.perPage) + (total % this.perPage > 0 ? 1 : 0);
      }
    };

    /**
     * Verifica as páginas que devem ser exibidas
     */
    PrPaginacao.prototype.pages = function() {
      var ret = [];

      for (var i = 1; i <= this.numberOfPages; i++) {
        if (this.currentPage === i) {
          ret.push(i);
        } else {
          if (this.currentPage <= (this.options.maxPagesInner + 1)) {
            if (i <= this.options.maxPages) {
              ret.push(i);
            }
          } else {
            if ((i >= this.currentPage - this.options.maxPagesInner) &&
              (i <= this.currentPage + this.options.maxPagesInner)) {
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
    PrPaginacao.prototype.previousPage = function() {
      if (this.currentPage > 1) {
        this.searchMethod(this.currentPage - 1);
      }
    };

    /**
     * Carrega os dados da próxima página
     */
    PrPaginacao.prototype.nextPage = function() {
      if (this.currentPage < this.numberOfPages) {
        this.searchMethod(this.currentPage + 1);
      }
    };

    /**
     * Carrega os dados da página informada
     *
     * @param {int} page - pagina que deve ser carregada
     */
    PrPaginacao.prototype.goToPage = function(page) {
      if (page >= 1 && page <= this.numberOfPages) {
        this.searchMethod(page);
      }
    };

    return {
      getInstance: function(searchMethod, perPage, _options) {
        return new PrPaginacao(searchMethod, perPage, _options);
      }
    };
  }

})();
