<?php

namespace App\Http\Controllers;

use App\Project;

use Hash;
use Log;

use Illuminate\Http\Request;

use App\Http\Requests;
use App\Http\Controllers\CrudController;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Input;
use Illuminate\Support\Facades\DB;

class ProjectsController extends CrudController {
    public function __construct() {
    }

    protected function getModel() {
        return Project::class;
    }

    protected function applyFilters(Request $request, $query) {
		$query = $query->with(['users.projectRoles', 'roles']);
    
        if ($request->has('user_id')) {
            $query = $query->whereHas('users', function($q) use ($request) {
                $q = $q->where('user_id', $request->user_id);
            });
        }

        if ($request->has('name')) {
                $query = $query->where('name', 'like', '%'.$request->name.'%');
        }
    }

    protected function beforeSearch(Request $request, $dataQuery, $countQuery) {
        $dataQuery->orderBy('name', 'asc');
    }
    
    protected function afterSave(Request $request, Model $model) { 
        $user_id = $request->user_id;
        $role_id = $request->role['id'];
        
        if($request->has('id')) {
            foreach($request->users as $user) {

            }
            $project_id = $request->id;
            DB::table('user_role_project')->where([
                ['project_id', $project_id],
                ['user_id', $user_id] 
            ])->update([
                'role_id'    => $role_id,
            ]);
        } else {
            $project_id = $model->id;
            DB::table('user_role_project')->insert([
                'user_id'    => $user_id,
                'role_id'    => $role_id,
                'project_id' => $project_id 
            ]);
        }
    }

    protected function beforeDestroy(Request $request, Model $model) { 
        DB::table('user_role_project')
            ->where('project_id', $model->id)
            ->delete();
    }

    protected function getValidationRules(Request $request, Model $obj) {
        $rules = [
            'name' => 'required|max:100',
            'description' => 'required|max:255',
            'owner' => 'required'
        ];

        return $rules;
    }
}
