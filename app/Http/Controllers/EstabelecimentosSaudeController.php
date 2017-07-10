<?php

namespace App\Http\Controllers;

use App\EstabelecimentoSaude;

use Log;

use Illuminate\Http\Request;

use App\Http\Requests;
use App\Http\Controllers\CrudController;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Input;

class EstabelecimentosSaudeController extends CrudController
{
    public function __construct()
    {
    }

    protected function getModel()
    {
        return EstabelecimentoSaude::class;
    }

    protected function applyFilters(Request $request, $query)
    {
        $query = $query->with('tipoEstabelecimentoSaude');

        /*
         * O bloco de código abaixo serve para verificar se o campo para filtragem está sendo passando
         * no request caso seja é inserido na query de de pesquisa.
         */
        if ($request->has('estabelecimento_saude_id')) {
            $query = $query->where('id', '=', $request->estabelecimento_saude_id);
        }

        if ($request->has('nome')) {
            $query = $query->where('nome', 'ilike', '%'.$request->nome.'%');
        }

        if ($request->has('natureza_juridica_id')) {
            $query = $query->where('natureza_juridica_id', '=', $request->natureza_juridica_id);
        }

        if ($request->has('tipo_id')) {
            $query = $query->where('tipo_id', '=', $request->tipo_id);
        }

        if ($request->has('validado')) {
            $query = $query->where('validado', '=', $request->validado);
        }
    }

    protected function beforeSearch(Request $request, $dataQuery, $countQuery)
    {
	/*
         * A linha abaixo aplica o critério de ordenação antes da pesquisa
         * $dataQuery->orderBy('{{attribute}}', 'asc');
         */
        $dataQuery->orderBy('nome', 'asc');
    }

    protected function beforeSave(Request $request, Model $obj) {
        if ($obj->id) {
            $obj->validado = 1;
        }
    }

    protected function getValidationRules(Request $request, Model $obj)
    {
        if ($obj->id) {
            $rules = [
                'nome' => 'required|max:255',
                'sigla' => 'required | max:6',
                'cpf_cnpj' => 'required',
                'tipo_id' => 'required',
                'natureza_juridica_id' => 'required',
                'nome_diretor' => 'required',
                'email_diretor' => 'required',
                'telefone_diretor' => 'required',
                'nome_responsavel_estagio' => 'required',
                'email_responsavel_estagio' => 'required',
                'telefone_responsavel_estagio' => 'required',
                'endereco' => 'required',
                'bairro' => 'required',
                'cep' => 'required',
                'estado_id' => 'required',
                'municipio_id' => 'required',
                'nucleo_regional_id' => 'required',
                // 'email' => ( !isset($obj->id) ) ? 'required|email|max:255|unique:users,email' : 'required|email|max:255|unique:users,email,'.$obj->id,
                // 'cpf' => ( !isset($obj->id) ) ? 'required|max:255|unique:users,cpf' : 'required|max:255|unique:users,cpf,'.$obj->id,
            ];
        } else {
            $rules = [
                'cnes' => 'required|max:10',
                'nome' => 'required|max:255',
                'sigla' => 'required | max:6',
            ];
        }

        return $rules;
    }
}
