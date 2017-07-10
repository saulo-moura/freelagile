<?php

namespace App\Http\Controllers;

use App\Modalidade;
use App\Vaga;

use Log;

use Illuminate\Http\Request;

use App\Exceptions\BusinessException;
use App\Http\Requests;
use App\Http\Controllers\CrudController;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Input;


class ModalidadesController extends CrudController
{
    public function __construct()
    {
    }

    protected function getModel()
    {
        return Modalidade::class;
    }

    protected function applyFilters(Request $request, $query) {
        if ($request->has('nome')) {
            $query = $query->where('nome', 'ilike', '%'.$request->nome.'%');
        }
    }

    protected function beforeSearch(Request $request, $dataQuery, $countQuery) {
        $dataQuery->orderBy('nome', 'asc');
    }

    protected function getValidationRules(Request $request, Model $obj)
    {
        $id = 0;
        if (isset($obj->id)) $id = $obj->id;

        return $rules = [
           'nome' => 'required|unique:modalidades,nome,'.$id,
         ];
    }

    protected function beforeDestroy(Request $request, Model $obj) {
        if (Vaga::where('modalidade_id', $obj->id)->first()) {
            throw new BusinessException('messages.removerAssociado|Disponibilida de Vaga');
        }
    }
}
