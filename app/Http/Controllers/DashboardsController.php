<?php

namespace App\Http\Controllers;

use App\Dashboard;

use Log;

use Illuminate\Http\Request;

use App\Http\Requests;
use App\Http\Controllers\CrudController;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Input;


class DashboardsController extends CrudController
{
    public function __construct()
    {
    }

    protected function getModel()
    {
        return Dashboard::class;
    }

    protected function applyFilters(Request $request, $query) {
        $query = $query->with(['user']);
        
        if ($request->has('project_id')) {
            $query = $query->where('project_id', $request->project_id);
        }
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
