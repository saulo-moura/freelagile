<?php

namespace App\Http\Controllers;

use App\Priority;

use Log;

use Illuminate\Http\Request;

use App\Http\Requests;
use App\Http\Controllers\CrudController;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Input;


class PrioritiesController extends CrudController
{
    public function __construct()
    {
    }

    protected function getModel()
    {
        return Priority::class;
    }

    protected function applyFilters(Request $request, $query) {
        /*
         * Se houver relacionamentos e caso queira incluir nos filtros
         * descomente a linha abaixo e informe o relacionamento
         * $query = $query->with('{modelRelacionado}');
         */

        /*
         * O bloco de código abaixo serve para verificar se o campo para filtragem está sendo passando
         * no request caso seja é inserido na query de de pesquisa.
         *if($request->has('{attribute}')) {
         *   $query = $query->where('{attribute}', 'like', '%'.$request->{attribute}.'%');
         *}
         */
    }

    protected function beforeSearch(Request $request, $dataQuery, $countQuery) {
        /*
         * A linha abaixo aplica o critério de ordenação antes da pesquisa
         * $dataQuery->orderBy('{{attribute}}', 'asc');
         */
    }

    protected function getValidationRules(Request $request, Model $obj)
    {
        /*
         * O bloco de código abaixo aplica as regras de validação dos campos
         * na requisição
         *$rules = [
         *  '{attribute}' => 'required|max:100',
         *];
         *
         *return $rules;
         */
    }
}