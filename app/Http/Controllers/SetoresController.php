<?php

namespace App\Http\Controllers;

use App\Setor;
use App\Vaga;

use Log;

use Illuminate\Http\Request;

use App\Exceptions\BusinessException;
use App\Http\Requests;
use App\Http\Controllers\CrudController;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Input;

use App\TipoEstabelecimentoSaude;

class SetoresController extends CrudController
{
    public function __construct()
    {
    }

    protected function getModel()
    {
        return Setor::class;
    }

    protected function applyFilters(Request $request, $query) {

        $query = $query->select('setores.*');
        $query = $query->with('setorTipoEstabelecimentoSaude');

        if ($request->has('tipo_id')) {
            $query = $query->join('setores_tipos_estabelecimento_saude', 'setores_tipos_estabelecimento_saude.setor_id', '=', 'setores.id');
            $query = $query->where('tipo_estabelecimento_saude_id', '=', $request->tipo_id);
        }

        if ($request->has('estabelecimento_saude_id')) {
            $query = $query->join('setores_tipos_estabelecimento_saude', 'setores_tipos_estabelecimento_saude.setor_id', '=', 'setores.id');
            $query = $query->join('estabelecimentos_saude', 'estabelecimentos_saude.tipo_id', '=', 'setores_tipos_estabelecimento_saude.tipo_estabelecimento_saude_id');
            $query = $query->where('estabelecimentos_saude.id', '=', $request->estabelecimento_saude_id);
        }
    }

    protected function beforeSearch(Request $request, $dataQuery, $countQuery) {
         $dataQuery->orderBy('nome', 'asc');
    }

    protected function getValidationRules(Request $request, Model $obj) {
        $id = 0;
        if (isset($obj->id)) $id = $obj->id;

        return [
            'nome' => 'required|unique:setores,nome,'.$id.'|max:50',
            'setor_tipo_estabelecimento_saude' => 'required'
        ];
    }

    /**
     * Após salvar a o setor cria a relação com o tipo de estabelecimento.
     *
     * @param Request $request
     * @param Model $model
     * @return void
     */
    protected function afterSave(Request $request, Model $model) {
        foreach($request->setor_tipo_estabelecimento_saude as $attach){
            $tipoEstabelecimento = TipoEstabelecimentoSaude::find($attach['id']);
            $model->setorTipoEstabelecimentoSaude()->withTimestamps()->save($tipoEstabelecimento);
        }
    }

    /**
     * Antes de deletar o setor, exclui o relacionamento com o tipo de estabelecimento.
     *
     * @param Request $request
     * @param Model $model
     * @return void
     */
    protected function beforeDestroy(Request $request, Model $model) {
        if (Vaga::where('setor_id', $model->id)->first()) {
            throw new BusinessException('messages.removerAssociado|Disponibilida de Vaga');
        }
        $model->setorTipoEstabelecimentoSaude()->detach();

    }

    /**
     * Antes de atualizar o setor, exclui o relacionamento com o tipo de estabelecimento.
     *
     * @param Request $request
     * @param Model $model
     * @return void
     */
    function beforeUpdate(Request $request, Model $model) {
        $model->setorTipoEstabelecimentoSaude()->detach();
    }
}
