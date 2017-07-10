<?php

namespace App\Http\Controllers;

use App\EstabelecimentoSaude;
use App\Vaga;

use Log;

use Illuminate\Http\Request;

use App\Http\Requests;
use App\Http\Controllers\CrudController;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Input;
use App\Exceptions\BusinessException;
use Illuminate\Support\Facades\Config;
use Carbon\Carbon;
use DB;

class VagasController extends CrudController
{
    public function __construct()
    {
    }

    protected function getModel()
    {
        return Vaga::class;
    }

    protected function applyFilters(Request $request, $query)
    {

        /*
         * Se houver relacionamentos e caso queira incluir nos filtros
         * descomente a linha abaixo e informe o relacionamento
         * $query = $query->with('{modelRelacionado}');
         */
         $query = $query->with('estabelecimentoSaude', 'curso', 'setor', 'modalidade', 'area', 'status', 'historico', 'horarios', 'especialidades', 'especificacoes');

        /*
         * O bloco de código abaixo serve para verificar se o campo para filtragem está sendo passando
         * no request caso seja é inserido na query de de pesquisa.
         *if($request->has('{attribute}')) {
         *   $query = $query->where('{attribute}', 'like', '%'.$request->{attribute}.'%');
         *}
         */
         $query = $query->select('vagas.*');
         $query = $query->join('estabelecimentos_saude', 'estabelecimentos_saude.id', '=', 'estabelecimento_saude_id');
         $query = $query->join('cursos', 'cursos.id', '=', 'curso_id');
         $query = $query->join('modalidades', 'modalidades.id', '=', 'modalidade_id');
         $query = $query->join('areas', 'areas.id', '=', 'area_id');
         $query = $query->join('setores', 'setores.id', '=', 'setor_id');
         $query = $query->leftJoin('especialidades', 'especialidades.id', '=', 'especialidade_id');
         $query = $query->leftJoin('especificacoes', 'especificacoes.id', '=', 'especificacao_id');

        if ($request->has('estabelecimentoSaude')) {
            $query = $query->where('estabelecimentos_saude.nome', 'like', '%' . strtoupper($request->estabelecimentoSaude) . '%');
        }

        if ($request->has('curso_id')) {
            $query = $query->where('curso_id', '=', $request->curso_id);
        }

        if ($request->has('modalidade_id')) {
            $query = $query->where('modalidade_id', '=', $request->modalidade_id);
        }

        if ($request->has('area_id')) {
            $query = $query->where('area_id', '=', $request->area_id);
        }

        if ($request->has('setor_id')) {
            $query = $query->where('setor_id', '=', $request->setor_id);
        }

        if ($request->has('status_id')) {
            $query = $query->where('status_id', '=', $request->status_id);
        }

        if ($request->has('estabelecimento_saude_id')) {
            $query = $query->where('estabelecimento_saude_id', '=', $request->estabelecimento_saude_id);
        }

        if ($request->has('periodoInicialFormatado')) {
            $query = $query->where('data_inicio', '>=', $request->periodoInicialFormatado . ' 00:00:00');
        }

        if ($request->has('periodoFinalFormatado')) {
            $query = $query->where('data_fim', '<=', $request->periodoInicialFormatado . ' 00:00:00');
        }

        if ($request->has('especificacao_id')) {
            $query = $query->where('especificacao_id', '=', $request->especificacao_id);
        }

        if ($request->has('especialidade_id')) {
            $query = $query->where('especialidade_id', '=', $request->especialidade_id);
        }
    }

    /**
     * Antes de buscar.
     *
     * @param Request $request
     * @param Query $dataQuery
     * @param int $countQuery
     * @return void
     */
    protected function beforeSearch(Request $request, $dataQuery, $countQuery)
    {
        /*
         * A linha abaixo aplica o critério de ordenação antes da pesquisa
         * $dataQuery->orderBy('{{attribute}}', 'asc');
         */
         $dataQuery->orderBy('estabelecimentos_saude.nome', 'asc');
         $dataQuery->orderBy('cursos.nome', 'asc');
         $dataQuery->orderBy('modalidades.nome', 'asc');
         $dataQuery->orderBy('areas.nome', 'asc');
         $dataQuery->orderBy('setores.nome', 'asc');
         $dataQuery->orderBy('especialidades.nome', 'asc');
         $dataQuery->orderBy('especificacoes.nome', 'asc');
    }

    /**
     * Antes de salvar valida o fluxo verificando se aquela ação pode ser tomada.
     * Em caso positivo salva o status.
     *
     * @param Request $request
     * @param Model $model
     * @return void
     */
    protected function beforeSave(Request $request, Model $model)
    {
        if (!$this->validaVagaDuplicada($model)) {
                throw new BusinessException('Já existe uma vaga com essas especificações para esse ano.');
        }
        if (!isset($model->id)) {
            if (!$this->validaStatusInicial($request->status_desejado_id)) {
                throw new BusinessException('Ação não permitida nesse momento da abertura de vagas.');
            }
        } else {
            $modelAtual = $model->find($model->id);
            switch ($request->status_desejado_id) {
                case config('utils.vaga_status.PENDENTE'):
                    if (!$this->validaParaPendente($request->status_desejado_id, $modelAtual->status_id)) {
                        throw new BusinessException('Erro ao mudar para status para pendente.');
                    }
                    break;
                case config('utils.vaga_status.AGUARDANDO_APROVACAO'):
                    if (!$this->validaParaAguardando($request->status_desejado_id, $modelAtual->status_id)) {
                        throw new BusinessException('Erro ao mudar status para  Aguardando Aprovação.');
                    }
                    break;
                case config('utils.vaga_status.APROVADO'):
                    if (!$this->validaAprovacao($request->status_desejado_id, $modelAtual->status_id)) {
                        throw new BusinessException('Erro ao mudar status para Aprovado.');
                    }
                    break;
                case config('utils.vaga_status.REJEITADO'):
                    if (!$this->validaRejeicao($request->status_desejado_id, $modelAtual->status_id)) {
                        throw new BusinessException('Erro ao mudar status para Rejeitado.');
                    }
                    break;
                default:
                    throw new BusinessException('Houve um erro ao mudar o Status.');
            }

            //Exclui todos os horários, pois o front-end irá passar todos os novos que serão salvos no afterSave
             \App\Horario::where('vaga_id', $model->id)->delete();
        }
        $model->status_id = $request->status_desejado_id;
        $model->data_inicio = new Carbon($model->data_inicio);
        $dataFim = new Carbon($model->data_fim);
        $dataFim->hour(23)->minute(59)->second(59);
        $model->data_fim = $dataFim;
    }

    /**
     * Após salvar a vaga, cria um registro de histórico pra ela.
     *
     * @param Request $request
     * @param Model $model
     * @return void
     */
    protected function afterSave(Request $request, Model $model)
    {
        $usuario = \Auth::user();
        foreach ($request->horarios as $horario) {
            if ($horario['fake'] != true) {
                \App\Horario::create([
                'vaga_id' => $model->id,
                'qtd_vagas' => $horario['qtdVagas'],
                'titulo' => $horario['title'],
                'dia_semana' => $horario['diaDaSemana'],
                'tipo_horario_id' => $horario['tipoHorario']
                ]);
            }
        }
        \App\HistoricoVaga::create([
            'vaga_id' => $model->id,
            'status_id' => $model->status_id,
            'user_id' => $usuario->id
        ]);


    }

    /**
     * Antes de excluir destroi os relacionamentos.
     *
     * @param Request $request
     * @param Model $model
     * @return void
     */
    protected function beforeDestroy(Request $request, Model $model)
    {
        $model->historico()->delete();
        $model->horarios()->delete();
    }

    /**
     * Obtem Histórico de uma disponibilidade de vagas.
     *
     * @return HistoricoVagas
     */
    public function historico(Request $request)
    {
        $orderDirection = isset($request->orderDirection) ?  $request->orderDirection : 'desc';
        return \App\HistoricoVaga::where('vaga_id', $request->input('vaga_id'))
        ->with('usuario', 'status')
        ->orderBy('created_at', 'asc')
        ->get();
    }

    /**
     * Retorna as regras de validação
     *
     * @param Request $request
     * @param Model $obj
     * @return void
     */
    protected function getValidationRules(Request $request, Model $obj)
    {
        $rules = [
           'estabelecimento_saude_id' => 'required',
           'status_id' => 'required',
           'user' => 'required',
           'status_desejado_id' => 'required',
           'curso_id' => 'required',
           'modalidade_id' => 'required',
           'area_id' => 'required',
           'setor_id' => 'required',
           'data_inicio' => 'required',
           'data_fim' => 'required'
         ];

        return $rules;
    }

    /**
     * Valida se o status é um dos status iniciais permitidos para cadastro
     *
     * @param Int $status
     * @return Boolean
     */
    protected function validaStatusInicial($status)
    {
        if ($status == config('utils.vaga_status.PENDENTE') || $status == config('utils.vaga_status.AGUARDANDO_APROVACAO')) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * Valida se pode alterar status para rejeitado
     *
     * @param int $status
     * @param int $statusAtual
     * @return Boolean
     */
    protected function validaRejeicao($status, $statusAtual)
    {
        if ($statusAtual == config('utils.vaga_status.AGUARDANDO_APROVACAO') && $status == config('utils.vaga_status.REJEITADO')) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * Valida se pode alterar status para Aprovado
     *
     * @param int $status
     * @param int $statusAtual
     * @return Boolean
     */
    protected function validaAprovacao($status, $statusAtual)
    {
        if ($statusAtual == config('utils.vaga_status.AGUARDANDO_APROVACAO') && $status == config('utils.vaga_status.APROVADO')) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * Valida se pode alterar status para pendente
     *
     * @param int $status
     * @param int $statusAtual
     * @return Boolean
     */
    protected function validaParaPendente($status, $statusAtual)
    {
        if (($statusAtual == config('utils.vaga_status.REJEITADO') || $statusAtual == config('utils.vaga_status.PENDENTE') )
        && $status == config('utils.vaga_status.PENDENTE') ) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * Valida se pode alterar status para aguardando aprovação
     *
     * @param int $status
     * @param int $statusAtual
     * @return Boolean
     */
    protected function validaParaAguardando($status, $statusAtual)
    {
        if (($statusAtual == config('utils.vaga_status.REJEITADO') || $statusAtual == config('utils.vaga_status.PENDENTE'))
        && $status == config('utils.vaga_status.AGUARDANDO_APROVACAO')) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * Valida se as configurações da vaga já existem para aquele ano.
     *
     * @param VagaModel $model
     * @return Boolean
     */
    protected function validaVagaDuplicada($model)
    {

        $dataInicio = new Carbon($model->data_inicio);
        $vagaModel = new Vaga();
        $vaga = Vaga::where('curso_id', $model->curso_id)
                       ->where('area_id', $model->area_id)
                       ->where('setor_id', $model->setor_id)
                       ->where('estabelecimento_saude_id', $model->estabelecimento_saude_id)
                       ->where('modalidade_id', $model->modalidade_id)
                       ->where('especialidade_id', $model->especialidade_id)
                       ->where('especificacao_id', $model->especificacao_id)
                       ->whereYear('data_inicio', '=', $dataInicio->year)
                       ->whereNotIn('id', isset($model->id) ? [$model->id] : [])
                       ->first();
        if ($vaga) {
            //Já existe uma vaga nessas especificações para aquele ano
            return false;
        } else {
            return true;
        }
    }
}
