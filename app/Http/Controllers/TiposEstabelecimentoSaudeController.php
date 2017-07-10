<?php

namespace App\Http\Controllers;

use App\EstabelecimentoSaude;
use App\TipoEstabelecimentoSaude;
use App\SetorTipoEstabelecimentoSaude;

use Log;

use Illuminate\Http\Request;

use App\Exceptions\BusinessException;
use App\Http\Requests;
use App\Http\Controllers\CrudController;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Input;


class TiposEstabelecimentoSaudeController extends CrudController
{
    public function __construct()
    {
    }

    protected function getModel()
    {
        return TipoEstabelecimentoSaude::class;
    }

    protected function applyFilters(Request $request, $query) {

        $query = $query->select('tipos_estabelecimento_saude.*');
        $query = $query->with('setorTipoEstabelecimentoSaude');
    }

    protected function beforeSearch(Request $request, $dataQuery, $countQuery) {
        /*
         * A linha abaixo aplica o critério de ordenação antes da pesquisa
         * $dataQuery->orderBy('{{attribute}}', 'asc');
         */
         $dataQuery->orderBy('nome', 'asc');
    }

    protected function getValidationRules(Request $request, Model $obj){
        $id = 0;
        if (isset($obj->id)) $id = $obj->id;

        return $rules = [
           'nome' => 'required|unique:tipos_estabelecimento_saude,nome,'.$id.'|max:255',
         ];
    }

    protected function beforeDestroy(Request $request, Model $obj) {
        $entidades = [];

        if (EstabelecimentoSaude::where('tipo_id', $obj->id)->first()) {
            $entidades[] = 'Estabelecimento de Saúde';
        }

        if (SetorTipoEstabelecimentoSaude::where('tipo_estabelecimento_saude_id', $obj->id)->first()) {
            $entidades[] = 'Setor';
        }

        if (!empty($entidades)) {
            throw new BusinessException('messages.removerAssociado|' . implode(", ", $entidades));
        }
    }
}
