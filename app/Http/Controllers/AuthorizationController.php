<?php

namespace App\Http\Controllers;

use Log;
use Illuminate\Http\Request;
use App\Http\Requests;
use App\Http\Controllers\CrudController;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Input;
use Illuminate\Database\Eloquent\Builder;
use App\Http\Traits\GenericService;
use App\Authorization\Authorization;
use App\Authorization\Action;



class AuthorizationController extends Controller
{
    use GenericService;

    /**
    * Gets the classes
    * @param request inject the request data
    **/
    public function resources(Request $request)
    {
        // Coleção que vai ser retornada
        $resources_output = [];

        // Recursos mapeados em /config/authorization
        $resources = \App\Authorization\Authorization::getResources();

        // modificações necessárias do objeto
        foreach ($resources as $key => $value) {
            // Aqui nós substituímos as ações declaradas no config
            // com possíveis pelas correspondentes ações concretas armazenadas em banco
            // pois precisaremos dos ids delas para armazenar na tabela role_actions
            $concreteActions = Action::where('resource_slug',$key)->get();
            $resources[$key]['slug'] = $key;
            $resources[$key]['actions'] = $concreteActions;

            // convertemos o array chave valor em array índice valor. A view espera nesse formato
            $resources_output[] = $resources[$key];
        }
        return $resources_output;
    }

    /**
    * Gets the estado
    * @param request inject the request data
    **/
    public function actions(Request $request)
    {
        $query = \App\Authorization\Action::query();
        return $this->getResults($request, $query);
    }



}
