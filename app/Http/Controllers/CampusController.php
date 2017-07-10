<?php

namespace App\Http\Controllers;

use App\Campus;

use Log;

use Illuminate\Http\Request;

use App\Http\Requests;
use App\Http\Controllers\CrudController;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Input;
use App\Exceptions\BusinessException;

class CampusController extends CrudController
{
    public function __construct()
    {
    }

    protected function getModel()
    {
        return Campus::class;
    }

    protected function applyFilters(Request $request, $query) {
        $query = $query->with('municipio', 'instituicoesEnsinoSuperior');

        if ($request->has('instituicao_ensino_id')) {
            $query = $query->where('instituicao_ensino_id', '=', $request->instituicao_ensino_id);
        }
    }

    protected function beforeSearch(Request $request, $dataQuery, $countQuery)
    {
        $dataQuery->orderBy('nome', 'asc');
    }

    protected function beforeSave(Request $request, Model $model) {
        if(!isset($request->id)){
            $campus = Campus::where('bairro', $request->bairro)
                        ->where('municipio_id', $request->municipio['id'])
                        ->where('instituicao_ensino_id', $request->instituicao_ensino_id)
                        ->first();
            if($campus) {
                throw new BusinessException('messages.duplicatedResourceError');
            }
        }
    }

    protected function getValidationRules(Request $request, Model $obj) {

        return $rules = [
            'nome' => 'required|max:255',
            'cep' => 'required | max:8',
            'endereco' => 'required',
            'bairro' => 'required',
            'municipio_id' => 'required',
            'instituicao_ensino_id' => 'required'
        ];
    }
}
