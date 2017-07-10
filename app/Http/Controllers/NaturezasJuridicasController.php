<?php

namespace App\Http\Controllers;

use App\EstabelecimentoSaude;
use App\InstituicaoEnsino;
use App\NaturezaJuridica;


use Log;

use Illuminate\Http\Request;

use App\Exceptions\BusinessException;
use App\Http\Requests;
use App\Http\Controllers\CrudController;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Input;

use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\DB;


class NaturezasJuridicasController extends CrudController
{
    public function __construct()
    {
    }

    protected function getModel()
    {
        return NaturezaJuridica::class;
    }

    protected function applyFilters(Request $request, $query) {
        if($request->has('tipo_natureza_juridica') && ($request->tipo_natureza_juridica == 0 || $request->tipo_natureza_juridica == 1)) {
            $query = $query->where('tipo_natureza_juridica', '=', $request->tipo_natureza_juridica);
        }
    }

    protected function beforeSearch(Request $request, $dataQuery, $countQuery) {
        $dataQuery->orderBy('nome', 'asc');
    }

    protected function getValidationRules(Request $request, Model $obj) {
        if (isset($obj->id) && ($request->nome === $obj->nome) && ($request->tipo_natureza_juridica === $obj->tipo_natureza_juridica)){
            $rules = [];
        }else if(isset($obj->id) && ($request->nome !== $obj->nome)) {
            $rules = [
                'nome' => 'required|max:255',
            ];
        }else{
            Validator::extend( 'composite_unique', function ( $attribute, $value, $parameters, $validator ) {

                // remove first parameter and assume it is the table name
                $table = array_shift( $parameters );

                // start building the conditions
                $fields = [ $attribute => $value ]; // current field, company_code in your case

                // iterates over the other parameters and build the conditions for all the required fields
                while ( $field = array_shift( $parameters ) ) {
                    $fields[ $field ] = \Request::get( $field );
                }

                // query the table with all the conditions
                $result = DB::table( $table )->select( DB::raw( 1 ) )->where( $fields )->first();

                return empty( $result ); // edited here
            }, ':attribute já está em uso.' );

            $rules = [
                'nome' => 'required|composite_unique:naturezas_juridicas,tipo_natureza_juridica|max:255',
                'tipo_natureza_juridica' => 'required'
            ];
        }
        return $rules;
    }

    protected function beforeDestroy(Request $request, Model $obj) {
        $entidades = [];

        if (EstabelecimentoSaude::where('natureza_juridica_id', $obj->id)->first()) {
            $entidades[] = 'Estabelecimento de Saúde';
        }

        if (InstituicaoEnsino::where('natureza_juridica_id', $obj->id)->first()) {
            $entidades[] = 'Instituição de Ensino';
        }

        if (!empty($entidades)) {
            throw new BusinessException('messages.removerAssociado|' . implode(", ", $entidades));
        }
    }
}
