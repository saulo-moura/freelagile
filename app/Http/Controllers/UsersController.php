<?php

namespace App\Http\Controllers;

use App\User;

use Mail;
use Hash;
use Log;

use Illuminate\Http\Request;

use App\Mail\ConfirmNewUser;
use App\Http\Requests;
use App\Http\Controllers\CrudController;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Input;

use OwenIt\Auditing\Auditing;

class UsersController extends CrudController
{
    public function __construct()
    {
    }

    protected function getModel()
    {
        return User::class;
    }

    protected function applyFilters(Request $request, $query)
    {
        $query = $query->with('roles');

        if ($request->has('name')) {
            $query = $query->where('name', 'like', '%'.$request->name.'%');
        }

        if ($request->has('email')) {
            $query = $query->where('email', 'like', '%'.$request->email.'%');
        }

        if ($request->has('nameOrEmail')) {
            $query = $query
                ->where('name', 'like', '%'.$request->nameOrEmail.'%')
                ->orWhere('email', 'like', '%'.$request->nameOrEmail.'%');
        }

        if ($request->has('notUsers')) {
            $query = $query->whereNotIn('id', explode(',', $request->notUsers));
        }
    }

    protected function beforeSearch(Request $request, $dataQuery, $countQuery)
    {
        $dataQuery->orderBy('name', 'asc');
    }

    protected function getValidationRules(Request $request, Model $obj)
    {
        $rules = [
            'name' => 'required|max:255',
            'email' => 'required|email|max:255|unique:users'
        ];

        if (strpos($request->route()->getName(), 'users.update') !== false) {
            $rules['email'] = 'required|email|max:255|unique:users,email,'.$obj->id;
        }

        return $rules;
    }

    protected function afterShow(Request $request, Model $obj)
    {
        $obj->roles = $obj->roles()->get()->toArray();
    }

    protected function beforeStore(Request $request, Model $obj)
    {
        //coloca no container, sem criptografar, para poder emitir para o email do usuário
        $obj->setPasswordConteiner(str_random(10));
        $obj->password = bcrypt($obj->getPasswordConteiner());
    }

    protected function beforeUpdate(Request $request, Model $obj)
    {
        //adiciona no request os papeis antigos para depois ser possível auditar
        //pois por padrão a solução de auditar não audita relacionamentos 1 para muitos
        $request->merge(array('oldRoles' => array_pluck($obj->roles()->get()->toArray(), 'slug')));
    }

    //After Store and Update
    protected function afterSave(Request $request, Model $obj)
    {
        $obj->roles()->sync(array_pluck(Input::only('roles')["roles"], 'id'));

        $newRoles = $obj->roles()->get()->toArray();
        $this->auditRoles($obj, $request->oldRoles, array_pluck($newRoles, 'slug'));

        $obj->roles = $newRoles;
    }

    //after store (only new users)
    protected function afterStore(Request $request, Model $obj)
    {
        //Envia o email de confirmação para o usuário com o login e senha

        Mail::to($obj)->send(new ConfirmNewUser($obj));
    }

    /**
     * Audit os perfis do usuário
     * @param  \App\User $user usuário;
     * @param  $oldRoles array contendo os perfis antigos
     * @param  $newRoles array contendo os perfis novos
     */
    protected function auditRoles($user, $oldRoles, $newRoles)
    {
        if (!isset($oldRoles)) {
            $oldRoles = [];
        }

        sort($newRoles);
        sort($oldRoles);

        if ($oldRoles !== $newRoles) {
            $data = $user->toAudit();
            $data['new'] = [ 'roles' => $newRoles ];
            $data['old'] = [ 'roles' => $oldRoles ];
            $data['type'] = 'updated';

            if (config('app.env') === 'testing') {
                $data['user_id'] = Auth::id();
                $data['ip_address'] = null;
            }

            Auditing::create($data);
        }
    }

    /**
     * Atualiza os dados do usuário logado
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function updateProfile(Request $request)
    {
        $user = Auth::user();
        $this->validate($request, [
            'name' => 'required|max:255',
            'email' => 'required|email|max:255|unique:users,email,'.$user->id,
            'password' => 'confirmed|min:6',
        ]);

        $user->fill(Input::only('name', 'email'));

        if ($request->has('password')) {
            $user->password = Hash::make($request->password);
        }

        $user->save();

        //get the roles to return do view
        $user->roles = $user->roles()->get()->toArray();

        return $user;
    }
}
