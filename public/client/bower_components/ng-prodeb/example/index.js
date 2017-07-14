angular.module('app', ['ngProdeb'])
  .controller('GlobalController', GlobalController);

GlobalController.$inject = ['PrPagination', 'PrSpinner', 'PrToast', 'PrDialog', '$timeout', 'FileUploader', 'PrFile'];

function GlobalController(PrPagination, PrSpinner, PrToast, PrDialog, $timeout, FileUploader, PrFile) {
  var vm = this;

  vm.uploader = new FileUploader();

  vm.search = search;
  vm.exportToExcel = exportToExcel;
  vm.notification = notification;
  vm.hideNotification = hideNotification;
  vm.customDialog = customDialog;
  vm.confirmDialog = confirmDialog;
  vm.notificationArrayValidationErrors = notificationArrayValidationErrors;
  vm.notificationObjectValidationErrors = notificationObjectValidationErrors;

  activate();

  function activate() {

    vm.cars = [];
    vm.carsData = [{
      brand: 'Fiat',
      name: 'Stilo',
      date: moment()
    }, {
      brand: 'Fiat',
      name: 'Uno',
      date: moment("2015-12-25")
    }, {
      brand: 'GM',
      name: 'Onix',
      date: new Date()
    }, {
      brand: 'Ford',
      name: 'Fiesta',
      date: '04-01-2017'
    }, {
      brand: 'GM',
      name: 'Vectra',
      date: moment().subtract(7, 'days')
    }, {
      brand: 'GM',
      name: 'Cruze',
      date: moment().subtract(7, 'years')
    }, {
      brand: 'Ford',
      name: 'Ka',
      date: moment().subtract(1, 'years')
    }, {
      brand: 'Wolks',
      name: 'Fusca',
      date: moment().subtract(2, 'years')
    }, {
      brand: 'GM',
      name: 'Agile',
      date: moment().subtract(3, 'years')
    }, {
      brand: 'Fiat',
      name: 'Punto',
      date: moment().subtract(4, 'years')
    }, {
      brand: 'GM',
      name: 'S10',
      date: moment().subtract(1, 'years')
    }];

    vm.carsData.sort(function (previousCar, nextCar) {
      if (previousCar.name < nextCar.name)
        return -1;
      if (previousCar.name > nextCar.name)
        return 1;
      return 0;
    });

    //crie uma instancia e informe a
    //função responsável pela busca e quantidade por página a ser exibido
    vm.paginator = PrPagination.getInstance(search, 3);

    search(1);
  }

  function search(page) {
    vm.paginator.currentPage = page; //atualize a página atual
    PrSpinner.show();

    $timeout(function () {
      var offset = (page - 1) * vm.paginator.perPage;

      vm.cars = vm.carsData.slice(offset, offset + vm.paginator.perPage);
      //chame a função para calcular a quantidade de página
      vm.paginator.calcNumberOfPages(vm.carsData.length);

      PrSpinner.hide();
    }, 1000)
  }

  function exportToExcel() {
    PrFile.exportToExcel([
      { name: 'brand', label: 'Marca' },
      { name: 'name', label: 'Nome' },
      { name: 'formatDate(date, \'DD-MM-YYYY\')', label: 'Comprado em?' }
    ], vm.carsData, 'data-export', {
      orderBy: 'brand ASC, name ASC'
    });
  }

  function notification(type, message) {
    PrToast[type](message);
  }

  function hideNotification() {
    PrToast.hide();
  }

  function notificationArrayValidationErrors() {
    PrToast.errorValidation([
      'Atributo 1 é obrigatório',
      'Atributo 1 deve ter o formato 999.999.999-99',
      'Atributo 2 deve ter no máximo 10 caracteres'
    ]);
  }

  function notificationObjectValidationErrors() {
    PrToast.errorValidation({
     'Atributo 1': ['é obrigatório', 'deve ter o formato 999.999.999-99'],
     'Atributo 2': ['deve ter no máximo 10 caracteres']
    });
  }

  function customDialog() {
    var config = {
      controller: function () {
        var vm = this;

        vm.title = 'Título do dialog customizado';
        vm.description = 'Conteúdo do dialog customizado';

        vm.close = vm.close;

        vm.close = function () {
          PrDialog.close();
        }

      },
      controllerAs: 'ctrl',
      templateUrl: 'custom-dialog.html',
      hasBackdrop: true
    };

    PrDialog.custom(config);

  }

  function confirmDialog() {
    var config = {
      title: 'Dialog de Confirmação',
      description: 'Descrição do dialog de confirmação'
    };

    PrDialog.confirm(config).then(() => {
      console.log("Você clicou no botão sim.");
    });

  }

}
