(function () {

  'use strict';

  angular
    .module('app')
    .controller('VagasController', VagasController);

  function VagasController($controller, $scope, $state, $timeout, $window, VagasService, EstabelecimentosSaudeService, CursosService, EspecialidadesService, EspecificacoesService, Auth, PrToast, $translate,
    $mdDialog, ModalidadesService, AreasService, SetoresService, StatusService, $document, moment, uiCalendarConfig, $rootScope) {

    var vm = this;
    vm.onActivate = onActivate;
    vm.beforeSave = beforeSave;
    vm.afterClean = afterClean;
    vm.afterEdit = afterEdit;
    vm.finalize = finalize;
    vm.salvarPendente = salvarPendente;
    vm.aprovar = aprovar;
    vm.rejeitar = rejeitar;
    vm.view = view;
    vm.onEstabelecimentoChange = onEstabelecimentoChange;
    vm.searchEstabelecimentoAutoComplete = searchEstabelecimentoAutoComplete;
    vm.applyFilters = applyFilters;
    vm.afterSave = afterSave;
    vm.historico = historico;
    vm.addHorario = addHorario;
    vm.replicar = replicar;
    vm.onDataInicioChange = onDataInicioChange;
    vm.onDataFimChange = onDataFimChange;
    vm.onModalidadeOpen = onModalidadeOpen;
    vm.onModalidadeClose = onModalidadeClose;
    vm.abrirRelatorio = abrirRelatorio;
    vm.imprimirAgendaView = imprimirAgendaView;
    vm.imprimirAgenda = imprimirAgenda;
    vm.voltarImpressao = voltarImpressao;

    //Attributes Block
    vm.STATUS = {
      PENDENTE: 1,
      AGUARDANDO_APROVACAO: 2,
      APROVADO: 3,
      REJEITADO: 4
    };
    vm.MODALIDADE = {
      ESTAGIO: 1,
      PRATICA: 2,
      INTERNATO: 3
    };

    vm.TIPO = {
      HOSPITAL: 1,
      CENTRO_REFERENCIA: 3
    }

    vm.onView = false;
    vm.onImpressao = false;
    vm.tipoAtual = 0;
    //Calendário semanal
    $scope.calendarHorarios = [
      []
    ];
    vm.uiConfig = {
      calendar: {
        defaultView: 'agendaWeek',
        firstDay: 1,
        allDaySlot: false,
        slotLabelFormat: 'H:mm',
        timeFormat: 'H:mm',
        columnFormat: 'ddd',
        height: 400,
        editable: false,
        eventStartEditable: false,
        header: {
          left: '',
          center: '',
          right: ''
        },
        eventClick: onClickHorario
      },
      impressao: {
        defaultView: 'agendaWeek',
        firstDay: 1,
        allDaySlot: false,
        slotLabelFormat: 'H:mm',
        timeFormat: 'H:mm',
        columnFormat: 'ddd',
        height: 1270,
        editable: false,
        eventStartEditable: false,
        header: {
          left: '',
          center: 'Teste',
          right: ''
        }
      }
    };

    // Configurações do dialog que exibirá o histórico
    vm.historicoDialog = {
      parent: angular.element($document.body),
      templateUrl: 'client/app/vagas/historico-vaga-dialog/historico-vaga-dialog.html',
      controllerAs: 'historicoVagaCtrl',
      controller: 'HistoricoVagaDialogController',
      clickOutsideToClose: true,
      locals: {
        historico: {}
      }
    }
    // Configurações do dialog para criação de horários
    vm.horarioDialog = {
      parent: angular.element($document.body),
      templateUrl: 'client/app/vagas/horario-vaga-dialog/add-horario-vaga-dialog.html',
      controllerAs: 'addHorarioVagaCtrl',
      controller: 'AddHorarioVagaDialogController',
      clickOutsideToClose: true,
      bindToController: true,
      locals: {
        getHorarioInfo: getHorarioInfo
      }
    }

    // Configurações do dialog para atualização de horários
    vm.updateHorarioDialog = {
      parent: angular.element($document.body),
      templateUrl: 'client/app/vagas/horario-vaga-dialog/update-horario-vaga-dialog.html',
      controllerAs: 'updateHorarioVagaCtrl',
      controller: 'UpdateHorarioVagaDialogController',
      clickOutsideToClose: true,
      bindToController: true,
      locals: {
        updateHorario: updateHorario,
        excluirHorario: excluirHorario
      }
    }

    //Functions Block

    /**
     * Função disparada ao ativar a tela.
     */
    function onActivate() {
      vm.user = Auth.currentUser;

      vm.queryFilters = {};

      //Define que aquele estabelecimento de saúde está validado.
      vm.estabelecimentoSaudeValidado = true;

      if (vm.user.estabelecimento_saude_id !== null && vm.user.estabelecimento_saude_id !== ''
        && vm.user.estabelecimento_saude_id !== undefined) {
        vm.estabelecimentoSaudeValidado = EstabelecimentosSaudeService.query({
          estabelecimento_saude_id: vm.user.estabelecimento_saude_id
        }).then(function (response) {
          vm.estabelecimentoSaudeValidado = response[0].validado;
        });
        vm.queryFilters = { estabelecimento_saude_id: vm.user.estabelecimento_saude_id };
        vm.tipoAtual = vm.user.estabelecimento_saude.tipo_id;
        vm.setores = SetoresService.query({
          tipo_id: vm.tipoAtual
        }).then(function (response) {
          vm.setores = response;
        });
      } else {
        vm.setores = SetoresService.query().then(function (response) {
          vm.setores = response;
        });
      }

      //Carrega combos
      vm.cursos = CursosService.query().then(function (response) {
        vm.cursos = response;
      });

      vm.modalidades = ModalidadesService.query().then(function (response) {
        vm.modalidades = response;
      });

      vm.areas = AreasService.query().then(function (response) {
        vm.areas = response;
      });


      vm.status = StatusService.query().then(function (response) {
        vm.status = response;
      });

      vm.especialidades = EspecialidadesService.query().then(function (response) {
        vm.especialidades = response;
      });

      vm.especificacoes = EspecificacoesService.query().then(function (response) {
        vm.especificacoes = response;
      });

      var dataAtual = moment(new Date());
      vm.anoAtual = dataAtual.year();
      vm.mesJaneiroLabel = 'Janeiro';
      vm.mesDezembroLabel = 'Dezembro';

      vm.dias = [];
      for (var i = 1; i <= 31; i++) {
        vm.dias.push(i);
      }
    }

    /**
     * Chama a tela em modo de visualização.
     * @param resource
     */
    function view(resource) {
      vm.goTo('form');
      vm.resource = new angular.copy(resource);
      vm.resource.diaJaneiro = moment(vm.resource.data_inicio).date();
      vm.resource.diaDezembro = moment(vm.resource.data_fim).date();
      vm.estabelecimentoSaude = vm.resource.estabelecimento_saude;
      vm.onView = true;
      $timeout(function () {
        $scope.renderCalender('semana');
        //Reseta os Horários do Calendário.
        uiCalendarConfig.calendars['semana'].fullCalendar('removeEvents');
        angular.forEach(vm.resource.horarios, function (horario) {
          adicionaHorarioCalendario(horario.tipo_horario_id, horario.dia_semana, horario.qtd_vagas);
        });
        vm.pristineCalendar = true;
      }, 500);
    }

    /**
     * Disparada após limpar a resource e entrar no cadastro.
     */
    function afterClean() {
      vm.onView = false;
      vm.resource.total_vagas_ano = 0;
      delete vm.estabelecimentoSaude;
      vm.resource.status_id = vm.STATUS.PENDENTE;
      vm.gestorSaude = false;
      if (vm.user.estabelecimento_saude) {
        vm.gestorSaude = true;
        vm.estabelecimentoSaude = vm.user.estabelecimento_saude;
        vm.resource.estabelecimento_saude_id = vm.estabelecimentoSaude.id;
      }

      //Reseta os Horários do Calendário.
      uiCalendarConfig.calendars['semana'].fullCalendar('removeEvents');
      //$scope.calendarHorarios[0].splice(0, $scope.calendarHorarios[0].length);
      $timeout(function () {
        $scope.renderCalender('semana');
        vm.pristineCalendar = true;
      }, 500);

    }

    /**
     * Disparada após entrar em modo de edição.
     */
    function afterEdit() {
      vm.onView = false;
      vm.resource.diaJaneiro = moment(vm.resource.data_inicio).date();
      vm.resource.diaDezembro = moment(vm.resource.data_fim).date();
      if (vm.resource.estabelecimento_saude_id !== undefined && vm.resource.estabelecimento_saude_id !== null) {
        vm.gestorSaude = true;
        vm.estabelecimentoSaude = vm.resource.estabelecimento_saude;
      }

      $timeout(function () {
        $scope.renderCalender('semana');
        //Reseta os Horários do Calendário.
        uiCalendarConfig.calendars['semana'].fullCalendar('removeEvents');
        angular.forEach(vm.resource.horarios, function (horario) {
          adicionaHorarioCalendario(horario.tipo_horario_id, horario.dia_semana, horario.qtd_vagas);
        });
        vm.pristineCalendar = true;
      }, 500);


    }

    /**
     * Prepara a vaga para ser finalizada.
     */
    function finalize() {
      vm.resource.status_desejado_id = vm.STATUS.AGUARDANDO_APROVACAO;
      var horarios = uiCalendarConfig.calendars['semana'].fullCalendar('clientEvents');
      if (horarios.length === 0) {
        PrToast.error("Não é possível finalizar sem horários definidos.");
        return false;
      }
      if (vm.pristineCalendar === false) {
        PrToast.error("É necessário replicar antes de proceder.");
        return false;
      }
      vm.save();
    }

    /**
     * Prepara para salvar a vaga como pendente.
     */
    function salvarPendente() {
      vm.resource.status_desejado_id = vm.STATUS.PENDENTE;
      if (vm.pristineCalendar === false) {
        PrToast.error("É necessário replicar antes de proceder.");
        return false;
      }
      vm.save();
    }

    /**
     * Prepara a vaga para ser aprovada para ser disponibilizada.
     */
    function aprovar() {
      vm.resource.status_desejado_id = vm.STATUS.APROVADO;
      vm.save();
    }

    /**
     * Rejeita a disponibilização de uma vaga.
     */
    function rejeitar() {
      vm.resource.status_desejado_id = vm.STATUS.REJEITADO;
      vm.save();
    }

    /**
     * Antes de salvar.
     */
    function beforeSave() {
      vm.resource.user = vm.user;

      //Adiciona os horários definidos.
      vm.resource.horarios = uiCalendarConfig.calendars['semana'].fullCalendar('clientEvents');
    }

    /**
     * Após salvar.
     */
    function afterSave() {
      vm.resource.status_id = vm.resource.status_desejado_id;
    }

    /**
     * Ao abrir combo de modalidade
     */
    function onModalidadeOpen() {
      vm.modalidade_id_bkp = vm.resource.modalidade_id;
    }
    /**
     * Ao fechar combo de modalidade
     */
    function onModalidadeClose() {

      if (vm.modalidade_id_bkp) {
        if (vm.resource.modalidade_id !== vm.modalidade_id_bkp) {
          var confirm = $mdDialog.confirm()
            .title('Confirmação')
            .textContent('Ao mudar a modalidade, sua agenda será apagada. Deseja continuar?')
            .ok('Sim')
            .cancel('Não');
          $mdDialog.show(confirm).then(function () {
            uiCalendarConfig.calendars['semana'].fullCalendar('removeEvents');
          }, function (confirmou) {
            vm.resource.modalidade_id = vm.modalidade_id_bkp;
          });
        }
      }
    }
    /**
     * Ao mudar data inicio
     */
    function onDataInicioChange() {
      var diaJaneiro = (vm.resource.diaJaneiro.toString().length < 2) ? '0' + vm.resource.diaJaneiro : vm.resource.diaJaneiro;
      vm.resource.data_inicio = vm.anoAtual + '-' + '01' + '-' + diaJaneiro;
    }

    /**
     * Ao mudar data fim
     */

    function onDataFimChange() {
      var diaDezembro = (vm.resource.diaDezembro.toString().length < 2) ? '0' + vm.resource.diaDezembro : vm.resource.diaDezembro;
      vm.resource.data_fim = vm.anoAtual + '-' + '12' + '-' + diaDezembro;
    }

    /**
     * Ao mudar o autocomplete de estabelecimento
     */
    function onEstabelecimentoChange() {
      if (vm.estabelecimentoSaude) {
        vm.resource.estabelecimento_saude_id = vm.estabelecimentoSaude.id;
        vm.setores = SetoresService.query({
          estabelecimento_saude_id: vm.resource.estabelecimento_saude_id
        }).then(function (response) {
          vm.setores = response;
        });
      }
    }

    /**
     * Busca estabelecimentos para o autocomplete
     */
    function searchEstabelecimentoAutoComplete(estabelecimentoSaudeTerm) {
      vm.resource.especialidade_id = null;
      vm.resource.especificacao_id = null;
      return EstabelecimentosSaudeService.query({ nome: estabelecimentoSaudeTerm });
    }

    /**
     * Adiciona filtros a busca de vagas.
     */
    function applyFilters(defaultQueryFilters) {
      return angular.extend(defaultQueryFilters, vm.queryFilters);
    }

    /**
     * Abre o modal do histórico de status daquela vaga.
     */
    function historico() {
      VagasService.getHistorico({ vaga_id: vm.resource.id })
        .then(function (response) {
          vm.historicoDialog.locals.historico = {};
          vm.historicoDialog.locals.historico = response;
          $mdDialog.show(vm.historicoDialog);
        });
    }

    //AGENDA
    function addHorario(horario) {
      vm.horarioDialog.locals.horario = horario;
      $mdDialog.show(vm.horarioDialog);
    }

    /**
     * Recebe as informações de horário para a criação de um novo
     * horário no componente.
     *
     * @param {INT} diaDaSemana
     * @param {INT} qtdVagas
     * @param {INT} horario
     */
    function getHorarioInfo(diaDaSemana, qtdVagas, horario) {
      $mdDialog.hide();
      var horariosDoDia = horariosDaqueleDia(diaDaSemana);
      if (horariosDoDia) {
        if (!validaInsercao(horariosDoDia, diaDaSemana, horario)) {
          PrToast.error('Horários Conflitantes');
          return false;
        }
      }
      adicionaHorarioCalendario(horario, diaDaSemana, qtdVagas);
    }

    /**
     * Valida se horário pode ser inserido no na grade horários
     *
     * @param {Array} horariosDoDia
     * @param {Int} diaDaSemana
     * @param {int} horario
     */
    function validaInsercao(horariosDoDia, diaDaSemana, horario) {
      var valido = true;
      switch (horario) {
        case 1:
          angular.forEach(horariosDoDia, function (horario) {
            if (horario.tipoHorario === 1 || horario.tipoHorario === 3) {
              valido = false;
            }
          });
          break;
        case 2:
          angular.forEach(horariosDoDia, function (horario) {
            if (horario.tipoHorario === 2 || horario.tipoHorario === 3) {
              valido = false;
            }
          });
          break;
        case 3:
          angular.forEach(horariosDoDia, function (horario) {
            if (horario.tipoHorario === 3 || horario.tipoHorario === 1 || horario.tipoHorario === 2) {
              valido = false;
            }
          });
          break;
        case 4:
          angular.forEach(horariosDoDia, function (horario) {
            if (horario.tipoHorario === 4) {
              valido = false;
            }
          });
          break;
      }
      return valido;
    }

    /**
     *  Cria um horário matutino
     *
     * @param {INT} diaDaSemana
     * @param {INT} qtdVagas
     */
    function horarioManha(diaDaSemana, qtdVagas) {
      var d = inicioDaSemana();
      var start = new Date(d.year(), d.month(), d.date() + diaDaSemana, 8, 0, 0);
      var end = new Date(d.year(), d.month(), d.date() + diaDaSemana, 12, 0, 0);

      return montaHorario({
        title: qtdVagas + ' vagas',
        start: start,
        end: end,
        diaDaSemana: diaDaSemana,
        qtdVagas: qtdVagas,
        duracao: 4,
        tipoHorario: 1,
        allDay: false
      });
    }

    /**
     * Cria um horário Vespertino
     *
     * @param {INT} diaDaSemana
     * @param {INT} qtdVagas
     */
    function horarioTarde(diaDaSemana, qtdVagas) {
      var d = inicioDaSemana();
      var start = new Date(d.year(), d.month(), d.date() + diaDaSemana, 14, 0, 0);
      var end = new Date(d.year(), d.month(), d.date() + diaDaSemana, 18, 0, 0);

      return montaHorario({
        title: qtdVagas + ' vagas',
        start: start,
        end: end,
        diaDaSemana: diaDaSemana,
        qtdVagas: qtdVagas,
        duracao: 4,
        tipoHorario: 2,
        allDay: false
      });
    }

    /**
     * Cria um horário de plantão diurno
     *
     * @param {INT} diaDaSemana
     * @param {INT} qtdVagas
     */
    function horarioPlantaoDia(diaDaSemana, qtdVagas) {
      var d = inicioDaSemana();
      var start = new Date(d.year(), d.month(), d.date() + diaDaSemana, 7, 0, 0);
      var end = new Date(d.year(), d.month(), d.date() + diaDaSemana, 19, 0, 0);

      return montaHorario({
        title: qtdVagas + ' vagas',
        start: start,
        end: end,
        qtdVagas: qtdVagas,
        diaDaSemana: diaDaSemana,
        duracao: 12,
        tipoHorario: 3,
        allDay: false
      });
    }

    /**
     * Cria um horário de plantão noturno
     *
     * @param {INT} diaDaSemana
     * @param {INT} qtdVagas
     */
    function horarioPlantaoNoite(diaDaSemana, qtdVagas) {
      var d = inicioDaSemana();
      if (diaDaSemana !== 6) {
        //Se não for domingo, cria o evento normal
        var start = new Date(d.year(), d.month(), d.date() + diaDaSemana, 19, 0, 0);
        var end = new Date(d.year(), d.month(), d.date() + diaDaSemana + 1, 7, 0, 0);
      } else {
        //Caso seja domingo, cria mais um evento (fake) para exibir o horário na segunda
        var start = new Date(d.year(), d.month(), d.date() + diaDaSemana, 19, 0, 0);
        var end = new Date(d.year(), d.month(), d.date() + diaDaSemana, 23, 59, 59);
        $scope.calendarHorarios[0].push(montaHorario({
          title: qtdVagas + ' vagas',
          start: new Date(d.year(), d.month(), d.date(), 0, 0, 0),
          end: new Date(d.year(), d.month(), d.date(), 7, 0, 0),
          qtdVagas: qtdVagas,
          duracao: 12,
          allDay: false,
          fake: true
        }));
      }

      return montaHorario({
        title: qtdVagas + ' vagas',
        start: start,
        end: end,
        qtdVagas: qtdVagas,
        diaDaSemana: diaDaSemana,
        duracao: 12,
        tipoHorario: 4,
        allDay: false
      });
    }

    /**
     * Monta um horário a partir de um conjunto de configurações fornecidas
     *
     * @param {Obj} config
     */
    function montaHorario(config) {
      var horario = {
        title: config.title,
        start: config.start,
        end: config.end,
        qtdVagas: config.qtdVagas,
        diaDaSemana: angular.isDefined(config.diaDaSemana) ? config.diaDaSemana : false,
        duracao: config.duracao,
        tipoHorario: config.tipoHorario ? config.tipoHorario : false,
        allDay: false,
        fake: config.fake ? config.fake : false
      }
      return horario;
    }

    /**
     * Adiciona um horário no componente de calendário
     *
     * @param {INT} horario
     * @param {INT} diaDaSemana
     * @param {INT} qtdVagas
     */
    function adicionaHorarioCalendario(horario, diaDaSemana, qtdVagas) {
      switch (horario) {
        case 1:
          $scope.calendarHorarios[0].push(horarioManha(diaDaSemana, qtdVagas));
          break;
        case 2:
          $scope.calendarHorarios[0].push(horarioTarde(diaDaSemana, qtdVagas));
          break;
        case 3:
          $scope.calendarHorarios[0].push(horarioPlantaoDia(diaDaSemana, qtdVagas));
          break;
        case 4:
          $scope.calendarHorarios[0].push(horarioPlantaoNoite(diaDaSemana, qtdVagas));
          break;
      }
      vm.pristineCalendar = false;
    }

    /**
     * Resgata o primeiro dia da semana corrente.
     *
     * @param {Date} date
     */
    function inicioDaSemana(date) {
      // Copy date if provided, or use current date if not
      date = date ? new Date(+date) : new Date();
      date.setHours(0, 0, 0, 0);

      // Set date to previous Sunday
      date.setDate((date.getDate() + 1) - date.getDay());
      return moment(date);
    }

    /**
     * Retorna todos os horários que foram definidios para um dia de
     * semana específico.
     *
     * @param {INT} diaDaSemana
     */
    function horariosDaqueleDia(diaDaSemana) {
      var horarios = [];
      angular.forEach(uiCalendarConfig.calendars['semana'].fullCalendar('clientEvents'), function (horario) {
        var date = new Date(horario.start);
        if ((date.getDay() - 1) === diaDaSemana && !horario.fake) {
          horarios.push(horario);
        }
        if (date.getDay() === 0 && diaDaSemana === 6) {
          horarios.push(horario);
        }
      });
      return horarios;
    }

    /**
     * Disparada ao clicar em um evento do calendário.
     */
    function onClickHorario(calEvent) {
      if (!vm.onView && vm.resource.status_id !== vm.STATUS.AGUARDANDO_APROVACAO) {
        vm.updateHorarioDialog.locals.horarioAtual = calEvent;
        if (calEvent.fake === true) {
          for (var i = 0; i < $scope.calendarHorarios[0].length; i++) {
            if ($scope.calendarHorarios[0][i].diaDaSemana === 6 && $scope.calendarHorarios[0][i].duracao === 12) {
              vm.updateHorarioDialog.locals.horarioAtual = $scope.calendarHorarios[0][i];
            }
          }
        }
        $mdDialog.show(vm.updateHorarioDialog);
      }


    }

    /**
     * Atualiza um horário do componente
     *
     * @param {obj} horario
     */
    function updateHorario(horario) {
      excluirHorario(horario);
      adicionaHorarioCalendario(horario.tipoHorario, horario.diaDaSemana, horario.qtdVagas);
      $mdDialog.hide();
    }

    /**
     * Remove um horário do componente
     *
     * @param {obj} horario
     */
    function excluirHorario(horario) {
      vm.pristineCalendar = false;
      for (var i = 0; i < $scope.calendarHorarios[0].length; i++) {
        //Acha o horário atual
        if (horario.diaDaSemana === $scope.calendarHorarios[0][i].diaDaSemana
          && horario.tipoHorario === $scope.calendarHorarios[0][i].tipoHorario
        ) {
          $scope.calendarHorarios[0].splice(i, 1);
          //Caso seja domingo, será necessário excluir o fake também.
          if (horario.diaDaSemana === 6 && horario.tipoHorario === 4) {
            for (var j = 0; j < $scope.calendarHorarios[0].length; j++) {
              if (!$scope.calendarHorarios[0][j].diaDaSemana && $scope.calendarHorarios[0][j].duracao === 12) {
                $scope.calendarHorarios[0].splice(j, 1);
              }
            }
          }
        }
      }
      $mdDialog.hide();
    }

    /**
     * Replicar Horários
     */
    function replicar() {
      vm.resource.total_vagas_ano = 0;
      for (var i = 0; i <= 6; i++) {
        var horarios = horariosDaqueleDia(i);
        var diasDoPeriodo = calcularDiasSemanaPeriodo(vm.resource.data_inicio, vm.resource.data_fim, i);
        angular.forEach(horarios, function (horario) {
          if (horario.fake !== true) {
            vm.resource.total_vagas_ano += horario.qtdVagas * diasDoPeriodo;
          }
        });
      }
      vm.pristineCalendar = true;
    }

    /**
     * Devolve quantidade de vezes que um dia da semana ocorre dentro de um
     * período de datas.
     */
    function calcularDiasSemanaPeriodo(dataInicio, dataFim, diaDaSemana) {
      dataInicio = moment(dataInicio);
      dataFim = moment(dataFim);
      var data;
      var diasSemanaCount = 0;
      var qtdDias = 0;
      var achouDataSemana = false;

      while (achouDataSemana === false) {
        if (dataInicio.day() === diaDaSemana) {
          data = dataInicio;
          achouDataSemana = true;
        } else {
          dataInicio.add(1, 'days');
        }
      }

      while (data < dataFim) {
        qtdDias++;
        data.add(7, 'days');
      }
      return qtdDias;
    }

    /* Change View */
    $scope.renderCalender = function (calendar) {
      if (uiCalendarConfig.calendars[calendar]) {
        uiCalendarConfig.calendars[calendar].fullCalendar('render');
      }
    };

    function abrirRelatorio() {
      $state.go('app.relatorio-disponibilidade-vagas');
    }

    function imprimirAgendaView() {
      vm.onImpressao = true;
      vm.agendaImpressaoTitulo = preparaTituloAgendaImpressao();
      $timeout(function () {
        uiCalendarConfig.calendars.impressao.fullCalendar('removeEvents');
        uiCalendarConfig.calendars.impressao.fullCalendar('render');
        angular.forEach(uiCalendarConfig.calendars.semana.fullCalendar('clientEvents'), function (evento) {
          uiCalendarConfig.calendars.impressao.fullCalendar('renderEvent', evento);
        });
      }, 1000);
    }

    function voltarImpressao() {
      vm.onImpressao = false;
    }

    function imprimirAgenda() {
      $window.print();
    }

    function preparaTituloAgendaImpressao() {
      var titulo = '';
      if(vm.resource.id){
        if(vm.estabelecimentoSaude){
          titulo += (" " + vm.estabelecimentoSaude.nome);
        }
        if(vm.resource.curso_id){
          angular.forEach(vm.cursos, function(curso){
            if(curso.id === vm.resource.curso_id){
              titulo += (" - " + curso.nome);
            }
          });
        }
        if(vm.resource.modalidade_id){
          angular.forEach(vm.modalidades, function(modalidade){
            if(modalidade.id === vm.resource.modalidade_id){
              titulo += (" - " + modalidade.nome);
            }
          });
        }
        if(vm.resource.area_id){
          angular.forEach(vm.areas, function(area){
            if(area.id === vm.resource.area_id){
              titulo += (" - " + area.nome);
            }
          });
        }
        if(vm.resource.setor_id){
          angular.forEach(vm.setores, function(setor){
            if(setor.id === vm.resource.setor_id){
              titulo += (" - " + setor.nome);
            }
          });
        }
        if(vm.resource.especialidade_id){
          angular.forEach(vm.especialidades, function(especialidade){
            if(especialidade.id === vm.resource.especialidade_id){
              titulo += (" - " + especialidade.nome);
            }
          });
        }
        if(vm.resource.especificacao_id){
          angular.forEach(vm.especificacoes, function(especificacao){
            if(especificacao.id === vm.resource.especificacao_id){
              titulo += (" - " + especificacao.nome);
            }
          });
        }

      }
      return titulo;
    }

    // instantiate base controller
    $controller('CRUDController', { vm: vm, modelService: VagasService, options: {} });
  }

})();
