(function () {
  'use strict';

  angular
    .module('app')
    .factory('UploadService', UploadService);

  /** @ngInject */
  function UploadService($http, Global) {
    return {
      uploadArquivosIES: function (id, formData) {
        return $http.post(Global.apiPath + '/instituicoes-ensino/' + id + '/upload-arquivos', formData, {
          transformRequest: angular.identity,
          headers: { 'Content-Type': undefined }
        });
      },
      excluirArquivosIES: function (id, formData) {
        return $http.post(Global.apiPath + '/instituicoes-ensino/' + id + '/excluir-arquivos', formData, {
          transformRequest: angular.identity,
          headers: { 'Content-Type': undefined }
        });
      },
      downloadArquivosIES: function (id, formData) {
        return $http.post(Global.apiPath + '/instituicoes-ensino/' + id + '/download-arquivos', formData, {
          transformRequest: angular.identity,
          headers: { 'Content-Type': undefined }
        });
      },
    }
  }

}());
