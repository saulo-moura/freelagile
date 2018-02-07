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

        $role = factory(\App\Role::class)->states('admin')->create();

        User::where('email', 'admin@freelagile.com')->first()->roles()->attach($role->id);

        Model::reguard();
    }
}
