<?php

use Illuminate\Database\Seeder;
use Illuminate\Database\Eloquent\Model;
use App\User;
use App\Role;
use App\Project;

class DatabaseSeeder extends Seeder
{
    /**
     * Run the database seeds.
     *
     * @return void
     */
    public function run()
    {
        Model::unguard();

        DB::table('users')->delete();
        DB::table('roles')->delete();
        DB::table('role_user')->delete();

        factory(\App\User::class)->states('admin')->create();
        factory(\App\User::class)->states('normal')->create();
        factory(\App\User::class, 5)->create();
        factory(\App\Task::class, 3)->create();

        factory(\App\Project::class)->create()
            ->tasks()->saveMany(factory(\App\Task::class, 2)->states('no-project')->make());

        factory(\App\Project::class)->create()
            ->tasks()->saveMany(factory(\App\Task::class, 5)->states('no-project')->make());


        $role = factory(\App\Role::class)->states('admin')->create();
        factory(\App\Role::class)->states('gestorDoSistema')->create();
        factory(\App\Role::class)->states('gestorDaIes')->create();
        factory(\App\Role::class)->states('gestorDaEs')->create();


        User::where('email', 'admin-base@prodeb.com')->first()->roles()->attach($role->id);
        $this->call(ActionsSeeder::class);
        $this->call(TiposEstabelecimentoSaudeTableSeeder::class);
        $this->call(NucleosRegionaisTableSeeder::class);
        $this->call(StatusTableSeeder::class);
        $this->call(CursosTableSeeder::class);
        $this->call(ModalidadesTableSeeder::class);
        $this->call(AreasTableSeeder::class);
        Model::reguard();
    }
}