<?php

use Illuminate\Database\Seeder;
use App\Authorization\Authorization;
use App\Authorization\Action;
use App\Role;
use Carbon\Carbon;

class ActionsSeeder extends Seeder
{
    /**
     * Run the database seeds.
     *
     * @return void
     */
    public function run()
    {
        // Aqui recuperamos os recursos declaradosno arquivo /config/authorization.php
        $resourcesWithActions = Authorization::getResources();

        // Esses recursos, suas respectivas posśiveis ações e as ações de dependência de cada ação são inseridas
        // Como há algumas regras específicas a inserção é feita pela classe App\Authorization\Authorization
        Authorization::storeResourcesActions($resourcesWithActions);


        /* ------------------------------------------------------------------------------------------------
        |  Abaixo inserimos todas as permissões para o perfil Admin, que é criado por apdrão no sistema
        | ------------------------------------------------------------------------------------------------
        */

        // Recuperamos todas as ações inseridas no passo acima, o perfil Admin e a data corrente
        $actions = Action::all();
        $admin = Role::where('slug', 'admin')->first();
        $gestorDoSistema = Role::where('slug', 'gestorDoSistema')->first();
        $gestorDaIes = Role::where('slug', 'gestorDaIes')->first();
        $gestorDaEs = Role::where('slug', 'gestorDaEs')->first();
        $now = Carbon::now();
        $permissions = [];

       /* Para cada ação, criamos um array com os dados do id do admin, id da ação e datas correntes
        *
        * Esta rotina associa todas as permissões do sistema aos perfis criando admins.
        */
        foreach ($actions as $action) {
            if ($action->action_type_slug != 'all' && $action->resource_slug !== 'all') {
                $permissions[] = ['role_id'=>$admin->id, 'action_id'=>$action->id, 'created_at'=>$now, 'updated_at'=>$now];
                $permissions[] = ['role_id'=>$gestorDoSistema->id, 'action_id'=>$action->id, 'created_at'=>$now, 'updated_at'=>$now];
            }
        }

        // Esta rotina adiciona permissões de autenticação aos perfis base.
        foreach ($actions as $action) {
            if ($action->resource_slug == "authorization" || $action->resource_slug == "authentication") {
                $permissions[] = ['role_id'=>$gestorDaIes->id, 'action_id'=>$action->id, 'created_at'=>$now, 'updated_at'=>$now];
                $permissions[] = ['role_id'=>$gestorDaEs->id, 'action_id'=>$action->id, 'created_at'=>$now, 'updated_at'=>$now];
            }
        }

        // Inserimos as permissões para o perfil Admin
        \DB::table('role_actions')->insert($permissions);
    }
}
