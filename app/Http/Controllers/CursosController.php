<?php

namespace App\Http\Controllers;

use App\Curso;
use App\Vaga;

use Log;

use Illuminate\Http\Request;

use App\Exceptions\BusinessException;
use App\Http\Requests;
use App\Http\Controllers\CrudController;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Input;


class CursosController extends CrudController
{
    public function __construct()
    {
    }

    protected function getModel()
    {
        return Curso::class;
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
           'nome' => 'required|unique:cursos,nome,'.$id,
         ];
    }

    protected function beforeDestroy(Request $request, Model $obj) {
        if (Vaga::where('curso_id', $obj->id)->first()) {
            throw new BusinessException('messages.removerAssociado|Disponibilidade de Vagas');
        }
    }
}
