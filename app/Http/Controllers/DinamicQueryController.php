<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

use OwenIt\Auditing\Log;

use App\Http\Requests;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Input;
use Carbon\Carbon;

class DinamicQueryController extends Controller
{
    public function __construct()
    {
    }


    public function index(Request $request)
    {
        $filters = json_decode($request->filters);

        //cria uma query baseado no nome da tabela
        //é preciso transformar o nome do modelo para o nome da tabela
        $baseQuery = \DB::table(str_plural(strtolower($request->model)));

        if ($filters !== null) {
            foreach ($filters as $filter) {
                if ($filter->operator === 'has') {
                    $filter->operator = 'ilike';
                    $filter->value = '%' . $filter->value . '%';
                }

                if ($filter->operator === 'startWith') {
                    $filter->operator = 'ilike';
                    $filter->value = $filter->value . '%';
                }

                if ($filter->operator === 'endWith') {
                    $filter->operator = 'ilike';
                    $filter->value = '%' . $filter->value;
                }

                $baseQuery = $baseQuery->where($filter->attribute, $filter->operator, $filter->value);
            }
        }

        $dataQuery = clone $baseQuery;
        $countQuery = clone $baseQuery;

        $data['items'] = $dataQuery
            ->skip(($request->page - 1) * $request->perPage)
            ->take($request->perPage)
            ->get();

        $data['total'] = $countQuery
            ->count();


        return $data;
    }

    /**
     * Serviço responsável por pegar todos os modelos juntamento com uma
     * lista dos atributos (contendo nome e tipo)
     *
     * @return array contendo uma lista de models com os seus atributos
     */
    public function models(Request $request)
    {
        $models = \Prodeb::modelNames(array("BaseModel.php", "Role.php"));
        $data = array();

        foreach ($models as $model) {
            //pluraliza o nome do model para conseguir achar o nome da tabela
            $tableName = str_plural(strtolower($model));
            //busca no banco (postgres) os nomes e tipo das colunas para cada tabela
            $columnWithTypes =  \DB::table('information_schema.columns')->select('column_name as name', 'data_type as type')
                ->where('table_name', $tableName)->get();

            $modelWithNamespace = 'App\\'.$model;

            $instance = new $modelWithNamespace;
            $dontFilterAttributesInDinamicQuery = collect($instance->getDontFilterAttributesInDinamicQuery());

            $columnWithTypes = $columnWithTypes->filter(function ($attribute) use ($dontFilterAttributesInDinamicQuery) {
                return !$dontFilterAttributesInDinamicQuery->contains($attribute->name);
            });

            array_push($data, [
                'name' => $model,
                'attributes' => $columnWithTypes
            ]);
        }

        return $data;
    }
}
