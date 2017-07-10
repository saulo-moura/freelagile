<?php
/*
 * This file is part of the Starter Pack Dynamic Authorization
 *
 * @author Amon Santana <amoncaldas@gmail.com>
 */

namespace App\Authorization;

use Illuminate\Support\Facades\Config;
use App\Authorization\Action;
use Illuminate\Support\Collection;


class Authorization
{
    /**
     * Get the resources that will be treated in the Dynamic Authorization.
     *
     * @return array
     */
    public static function getResources() {
        // TODO: validate resources declared
        return Config::get('authorization.resources');
    }

    /**
     * Get the resources that will be treated in the Dynamic Authorization.
     *
     * @return array
     */
    public static function getResource($slug) {
       $resources = Authorization::getResources();
       if(!empty($resources[$slug])) {
           return $resources[$slug];
       }
    }

    /**
     * Get the action types that will be treated in the Dynamic Authorization.
     *
     * @return array
     */
    public static function getActionTypes() {
        // TODO: validate action types declared
        return Config::get('authorization.actionTypes');
    }

    /**
     * Get the action types that will be treated in the Dynamic Authorization.
     *
     * @return array
     */
    public static function getActionType($slug) {
       $actionTypes = Authorization::getActionTypes();
       if(!empty($actionTypes[$slug])) {
           return $actionTypes[$slug];
       }
    }

    /**
     * Armazena em banco as ações possíveis de um dado recurso.
     * @param  array  $resources
     */
    public static function storeResourcesActions($resources) {

        \DB::table('actions_dependencies')->delete();
        \DB::table('role_actions')->delete();
        \DB::table('actions')->delete();

        foreach ($resources as $key => $value) {
            // Para cada ação declarada como possível para um dado recurso
            foreach ($value['actions'] as $action) {
                // A ação pode ter sido declarada como um string ou como um array (neste último caso por que tem dependências)
                // Para recuperar o identificador semântico (slug) fazemos essa verificação
                $actionslug = is_array($action)?  $action['slug'] : $action;

                // A chave do recurso $key é o slug, conforme declarado em /config/authorization
                $actionCreated = Action::create(['resource_slug' => $key,'action_type_slug'=>$actionslug]);

                // se é um array, então é por que tem dependências
                if(is_array($action) && isset($action['dependencies'])) {
                    $dependencies = $action['dependencies'];
                    foreach ($dependencies as $dependency) {
                        // Para cada dependência declarada para um dada ação, recuperamos a ação dependente já armazenada em banco
                        // Para a dependência funcionar, a ação da qual outra ação depende deve ser declara anteriormente
                        $resourceSlug = $dependency['resource_slug'];
                        $actionTypeSlug = $dependency['action_type_slug'];
                        $dependsOnAction = Action::where('resource_slug',$resourceSlug)->where('action_type_slug',$actionTypeSlug)->first();

                        // Aqui inserimos no banco a ação dependente e a ação alvo da dependência
                        \DB::table('actions_dependencies')->insert(
                            [
                                'dependent_action_id' => $actionCreated->id,
                                'depends_on_action_id'=>$dependsOnAction->id
                            ]
                        );
                    }
                }
            }
        }
    }

    /**
     * Recupera um recurso passível de autorização pelo nome do controller associado ao recurso.
     * @param  string  $controller - nome completo do controler, incluindo namespace
     */
    public static function getResourceByController($controller) {
        // Aqui recuperamos a coleção de recursos definidos em /config/authorization
        // já com mapeamentos necessário para a iteração abaixo
        $resourcesCollection = Authorization::getMapedResourceCollection();

        // A partir dessa coleção extraímos o recurso com base no nome do controller
        $filtered =  $resourcesCollection->first(function ($value, $key) use ($controller) {
            return $value['controller'] === $controller;
        });

        return $filtered;

    }

    /**
     * Recupera os recuros declarados em /config/authorization e mapeia dados com base em seus atributos
     * @return   Illuminate\Support\Collection  $mapped - Collection de recursos mapeados
     */
    protected static function getMapedResourceCollection() {
        // Recuperamos os recursos declarados em /config/authorization
        $resources = Authorization::getResources();

        // Este é o namespace padrão. Caso o recurso não tenha a propriedade namespace definida, este será usado
        $defaultControllerNamespace = "App\Http\Controllers\\";

        // Transforma o Illuminate\Support\Collectionarray de recursos em uma Illuminate\Support\Collection, facilitando a manipulação
        // O recurso coring 'all' é excluído, pois não é um recurso passível de validação
        $collection = collect($resources)->filter(function ($value, $key) {
            return $key !== 'all' && isset($value['controller_class']);
        });

        // Para facilitar o filtro de recursos com base no controller, definimos o controller com seu namespace completo aqui
        // Adicionamos também o identificador do recurso (slug) no objeto mapeado para facilitar os filtros na coleção
        $mapped =  $collection->map(function ($item, $key) use ($defaultControllerNamespace) {
            $item['controller'] = isset($item['namespace'])? $item['namespace']."\\".$item['controller_class'] : $defaultControllerNamespace.$item['controller_class'];
            $item['slug'] = $key;
            return $item;
        });

        return $mapped;
    }

    /**
     * Recupera as ações permitidas para um determinado usuário
     * @return  Sttsy $mapped - Collection de recursos mapeados
     * @param  \App\User  $user - instância de um usuário
     */
    public static function userAllowedActions($user)
    {
        $actions = [];
        $roles = $user->roles;
        foreach ($roles as $role) {
            $roleActions = is_array($role)? $role['actions']: $role->actions->toArray();
            $actions = array_merge($actions, $roleActions);
        }
        return $actions;
    }

    /**
     * Verifica se um usuário tem a pemisção de executar uma dada ação num dado controller
     * @param  string  $controller - nome do controller (incluindo namespace)
     * @param  string  $action - nome da ação
     * @param  \App\User|null  $user - instância de um usuário. Se não passado, será utilizado o usuário corrente (autenticado)
     * @return boolean - se tem a permissão ou não
     */
    public static function hasPermission($controller, $actionDesired, $user = null)
    {
        // Se a ação for no controller de Support, devemos permitir. Ele retorna dados (como lang strings) para a view
        if($controller === 'App\Http\Controllers\SupportController') {
            return true;
        }
        // Se um usuário não for passado, recupera o usuário corrente (autenticado)
        $user = $user? $user: \Auth::user();

        // Aqui recuperamos os ids dos roles atribuídos ao usuário
        $userRolesIds = [];
        foreach ($user->roles as $role) {
            $userRolesIds[] = $role->id;
        }

        // Recuperamos o resource pelo nome do controller
        $resource = Authorization::getResourceByController($controller);

        // Se o recurso não existir, então a permissão é negada (pode ser configurado o contrário)
        if(!$resource) {
            $allowNotListedControllers  = Config::get('authorization.allowNotListedControllers');
            $allowNotListedControllers = $allowNotListedControllers !== null ? $allowNotListedControllers : false;
            return $allowNotListedControllers;
        }

        // Recuperamos a instância da ação baseado no nome da ação passada
        $action = Action::where('resource_slug',$resource['slug'])->where('action_type_slug', $actionDesired)->first();

        // Se a ação não existir, então a permissão é negada (pode ser configurado o contrário)
        if(!$action){
            $allowNotListedActions = Config::get('authorization.allowNotListedActions');
            $allowNotListedActions = $allowNotListedActions !== null ? $allowNotListedActions : false;
            return $allowNotListedActions;
        }

        // Se conseguimos encontrar o recurso e a ação, verificamos no banco se um dos roles atribuídos ao usuário
        // possui a permição para executar tal ação
        $count = \DB::table('role_actions')->whereIn('role_id', $userRolesIds)->where('action_id',$action->id)->count();

        // Se sim, retorn true, se não false;
        return $count > 0;
    }

     /**
     * Contróia a mensagem de ação não permitda com base no identificador do recurso e da ação
     * @param  string  $controller - nome do controller (incluindo namespace)
     * @param  string  $action - nome da ação
     * @return string - mensagem com informação da ação não autorizada
     */
    public static function getDenialMessage($controller, $action) {
        // Mensagem padrão, caso não seja possível encontrar o recurso
        $msg = \Lang::get('auth.noAuthorizationForThisResource');

        // Recupera o recurso pelo nome do controller (incluindo namespace)
        $resource = Authorization::getResourceByController($controller);

        // Se não foi possível encontrar o recurso, devolve uma mensagem padrão
        if(!$resource) {
            return $msg;
        }

        // Recupera o tipo da ação pelo identificador da ação
        $actionType = Authorization::getActionType($action);

        // Se não foi possível encontrar o tipo da ação, devolve uma mensagem só com o nome do recurso
        if(!$actionType) {
            $msg = \Lang::get('auth.noAuthorizationForThisTypeOfActionInResource', ['resourceName' => $resource['name']]);
            return $msg;
        }

        // Controi a mensagem incluindo os nomes amigáveis do recurso e da ação
        $msg = \Lang::get('auth.noAuthorizationForActionInResource', ['actionName'=>$actionType['name'],'resourceName' => $resource['name']]);
        return $msg;
    }
}
