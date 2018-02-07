<?php

namespace App\Http\Controllers;

use App\Milestone;

use Log;
use DB;

use Illuminate\Http\Request;

use App\Http\Requests;
use App\Http\Controllers\CrudController;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Input;


class MilestonesController extends CrudController
{
    public function __construct()
    {
    }

    protected function getModel()
    {
        return Milestone::class;
    }

    protected function applyFilters(Request $request, $query) {
        $query = $query->with(['project.developer', 'project.client', 'project.stakeholder', 'tasks']);

        if ($request->has('project_id')) {
            $query = $query->where('project_id', $request->project_id);
        }
        if ($request->has('releaseSearch')) {
            $query = $query->whereNull('release_id');
        }
        if ($request->has('title')) {
            $query = $query->where('title', 'like', '%'.$request->title.'%');
        }
    }

    protected function beforeSearch(Request $request, $dataQuery, $countQuery) {
        /*
         * A linha abaixo aplica o critério de ordenação antes da pesquisa
         * $dataQuery->orderBy('{{attribute}}', 'asc');
         */
    }

    protected function getValidationRules(Request $request, Model $obj) {
        $rules = [
            'title' => 'required|max:256',
            'description' => 'required|max:256',
            'date_begin' => 'required|date',
            'date_end' => 'required|date',
            'project_id' => 'required'
        ];

        return $rules;
    }

    protected function afterStore(Request $request, Model $model) {
        $this->saveAction($request->project_id, 'Store', config('utils.dashboard.saveMilestone'));
    }

    protected function afterUpdate(Request $request, Model $model) {
        $this->saveAction($request->project_id, 'Update', config('utils.dashboard.updateMilestone'));
    }

    protected function afterDestroy(Request $request, Model $model) {
        $this->saveAction($request->project_id, 'Destroy', config('utils.dashboard.destroyMilestone'));
    }

    public function finalize(Request $request) {
        $this->saveAction($request->project_id, 'Update', config('utils.dashboard.finalizedMilestone'));
        return \App\Milestone::where('id', $request->milestone_id)->update(['done' => true]);
    }

    public function updateRelease(Request $request) {
        $milestones = \App\Milestone::where('release_id', $request->release_id)->update(['release_id' => null]);
        DB::transaction(function() use ($request) {
            foreach ($request->milestones as $sprint) {
                $milestone = \App\Milestone::find($sprint['id']);
                $milestone->release_id = $request->release_id;
                $milestone->save();
            }
            $this->saveAction($request->project_id, 'Update', config('utils.dashboard.updateReleaseMilestone'));
        });
    }
}
