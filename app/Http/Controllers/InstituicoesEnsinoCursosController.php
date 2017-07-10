<?php

namespace App\Http\Controllers;

use App\InstituicaoEnsinoCurso;

use Log;

use Illuminate\Http\Request;

use App\Http\Requests;
use App\Http\Controllers\CrudController;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Input;
use App\Exceptions\BusinessException;
use Storage;

class InstituicoesEnsinoCursosController extends CrudController
{
    public function __construct()
    {
    }

    protected function getModel()
    {
        return InstituicaoEnsinoCurso::class;
    }

    protected function applyFilters(Request $request, $query)
    {
        if ($request->has('nome')) {
            $query = $query->where('nome', 'ilike', '%'.$request->nome.'%');
        }
    }

    protected function beforeSearch(Request $request, $dataQuery, $countQuery)
    {
        $dataQuery->orderBy('nome', 'asc');
    }

    protected function beforeSave(Request $request, Model $model)
    {
        
    }

    protected function getValidationRules(Request $request, Model $obj)
    {
        $rules = [
            'nome' => 'required',
            'sigla' => 'required'
        ];
        return $rules;
    }

}
