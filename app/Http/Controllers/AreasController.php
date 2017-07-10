<?php

namespace App\Http\Controllers;

use App\Area;
use App\Vaga;

use Log;

use Illuminate\Http\Request;

use App\Exceptions\BusinessException;
use App\Http\Requests;
use App\Http\Controllers\CrudController;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Input;


class AreasController extends CrudController
{
    public function __construct()
    {
    }

    protected function getModel()
    {
        return Area::class;
    }

    protected function applyFilters(Request $request, $query) {

    }

    protected function beforeSearch(Request $request, $dataQuery, $countQuery) {
        $dataQuery->orderBy('nome', 'asc');
    }

    protected function getValidationRules(Request $request, Model $obj) {
        $id = 0;
        if (isset($obj->id)) $id = $obj->id;

        return $rules = [
           'nome' => 'required|unique:areas,nome,'.$id.'|max:255',
         ];
    }

    protected function beforeDestroy(Request $request, Model $obj) {
        if (Vaga::where('area_id', $obj->id)->first()) {
            throw new BusinessException('messages.removerAssociado|Disponibilidade de Vaga');
        }
    }
}
