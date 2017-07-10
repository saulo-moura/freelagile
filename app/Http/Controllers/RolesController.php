<?php

namespace App\Http\Controllers;

use App\Role;

use Illuminate\Http\Request;

use App\Http\Requests;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Input;
use Illuminate\Database\Eloquent\Model;
use App\Exceptions\BusinessException;
use App\Authorization\Action;
use Carbon\Carbon;
use App\Util\Prodeb;

class RolesController extends CrudController
{
    public function __construct()
    {
    }


    protected function getModel()
    {
        return Role::class;
    }

    protected function applyFilters(Request $request, $query) {

    }

    protected function beforeSearch(Request $request, $dataQuery, $countQuery)
    {
	/*
         * A linha abaixo aplica o critério de ordenação antes da pesquisa
         * $dataQuery->orderBy('{{attribute}}', 'asc');
         */
        $dataQuery->orderBy('title', 'asc');
    }

    protected function beforeValidation(Request $request, Model $obj) {
        $request->merge(array('slug'=>Prodeb::getSlug($request->title)));
    }

    protected function getValidationRules(Request $request, Model $obj)
    {
        $uniqueFilterAppend = isset($obj->id)?  ','.$obj->id : '';
        return ['title'=>'required|unique:roles,title'.$uniqueFilterAppend];
    }

    protected function beforeSave(Request $request, Model $obj) {
        $obj->title = strtoupper($obj->title);
        $obj->slug = Prodeb::getSlug($obj->title);
    }

    protected function beforeDestroy(Request $request, Model $obj) {
        if ($obj->users->count() > 0) {
            throw new BusinessException('messages.removeError');
        } if ($obj->slug === 'admin') {
            throw new BusinessException('messages.removeError');
        } else {
            \DB::table('role_actions')->where('role_id', '=', $obj->id)->delete();
        }
    }

    protected function afterSave(Request $request, Model $obj) {
        $addedActions = [];
        \DB::table('role_actions')->where('role_id', '=', $obj->id)->delete();
        $actions =  $request->actions;
        if ($request->has('actions') && count($request->actions) > 0) {
            $now = Carbon::now();
            foreach ($actions as $a) {
                if (!empty($a['id'])) {
                    $action = Action::find($a['id']);
                    if (isset($action) && $action['action_type_slug'] != 'all' && $action['resource_slug'] != 'all' && !in_array($action['id'], $addedActions)) {
                        $obj->actions()->save($action, ['created_at'=>$now, 'updated_at'=>$now]);
                        $addedActions[] = $action['id'];
                    }
                }
            }
        }
    }
}
