<?php

namespace App\Http\Controllers;

use App\Project;

use Hash;
use Log;

use Illuminate\Http\Request;

use App\Http\Requests;
use App\Http\Controllers\CrudController;
use App\Exceptions\BusinessException;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Input;
use Illuminate\Support\Facades\DB;

class ProjectsController extends CrudController {

    protected function getModel() {
        return Project::class;
    }

    protected function applyFilters(Request $request, $query) {
		$query->with(['developer.projectRoles', 'client.projectRoles', 'stakeholder.projectRoles', 'releases']);

        if ($request->has('user_id')) {
            $query->where('dev_id', $request->user_id)
                ->orWhere('client_id', $request->user_id)
                ->orWhere('stakeholder_id', $request->user_id)
                ->orWhere('owner', $request->user_id);
        }

        if ($request->has('name')) {
            $query->where('name', 'like', '%'.$request->name.'%');
        }

        if ($request->has('project_id')) {
            $query->with(['tasks']);
            $query->where('id', $request->project_id);
        }
    }

    protected function beforeSearch(Request $request, $dataQuery, $countQuery) {
        $dataQuery->orderBy('name', 'asc');
    }

    protected function afterSave(Request $request, Model $model) {
        if(isset($request->role)) {
            $project_id = $model->id;
            $project = \App\Project::find($project_id);
            switch($request->role['slug']) {
                case 'client':
                    $project->client_id = $request->user_id;
                    break;
                case 'stakeholder':
                    $project->stakeholder_id = $request->user_id;
                    break;
            }
            $project->save();
        }
        if(isset($request->users)) {
            $project_id = $model->id;
            $project = \App\Project::find($project_id);
            $project->client_id = null;
            $project->stakeholder_id = null;

            $this->projectValidate($request);
            foreach($request->users as $user) {
                switch($user['role']['slug']) {
                    case 'client':
                        $project->client_id = $user['id'];
                        break;
                    case 'stakeholder':
                        $project->stakeholder_id = $user['id'];
                        break;
                }
            }
            $project->save();
        }
    }

    private function projectValidate($request) {
        $client = 0;
        $dev = 0;
        $stakeholder = 0;
        if(count($request->users) > 3) {
            throw new BusinessException('O projeto não pode ter mais que 3 membros');
        }
        foreach($request->users as $user) {
            switch($user['role']['slug']) {
                case 'client':
                    $client++;
                    break;
                case 'dev':
                    $dev++;
                    break;
                case 'stakeholder':
                    $stakeholder++;
                    break;
            }
        }
        if($client > 1 || $dev > 1 || $stakeholder > 1) {
            throw new BusinessException('Dois ou mais membros não podem exercer o mesmo papel no projeto');
        }
    }

    protected function afterStore(Request $request, Model $model) {
        if($request->has('id')) {
            $project_id = $request->id;
        } else {
            $project_id = $model->id;
        }
        $project = \App\Project::find($project_id);
        $project->dev_id = $model->owner;
        $project->save();

        $this->saveAction($project_id, 'Store', config('utils.dashboard.saveProject'));
    }

    protected function afterUpdate(Request $request, Model $model) {
        if($request->has('id')) {
            $project_id = $request->id;
        } else {
            $project_id = $model->id;
        }

        $this->saveAction($project_id, 'Update', config('utils.dashboard.updateProject'));
    }

    protected function beforeDestroy(Request $request, Model $model) {
        DB::table('user_role_project')
            ->where('project_id', $model->id)
            ->delete();
        DB::table('dashboard')
            ->where('project_id', $model->id)
            ->delete();
        DB::table('tasks')
            ->where('project_id', $model->id)
            ->delete();
        DB::table('milestones')
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

    public function finalize(Request $request) {
        $project = \App\Project::find($request->project_id);
        foreach ($project->releases as $release) {
            if(!$release->done) {
                throw new BusinessException("Não foi possível finalizar o projeto, existem releases não finalizadas");
            }
        }
        $this->saveAction($request->project_id, 'Update', config('utils.dashboard.finalizedProject'));
        return \App\Project::where('id', $request->project_id)->update(['done' => true]);
    }
}
