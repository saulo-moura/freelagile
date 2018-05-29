<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

use App\Task;
use App\Project;
use App\Http\Requests;
use App\Http\Controllers\CrudController;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Input;

use DB;

class TasksController extends CrudController {

    public function __construct()
    {
    }

    protected function getModel()
    {
        return Task::class;
    }

    protected function applyFilters(Request $request, $query) {
        if ($request->has('project_id')) {
            $query = $query->where('project_id', $request->project_id);
        }
        if ($request->has('milestone_id')) {
            $query = $query->where('milestone_id', $request->milestone_id);
        }
        if ($request->has('title')) {
            $query = $query->where('title', 'like', '%'.$request->title.'%');
        }
        if ($request->has('milestoneSearch')) {
            $query = $query->whereNull('milestone_id');
        }
        if ($request->has('task_id')) {
            $query = $query->where('id', $request->task_id);
        }
    }

    protected function beforeSearch(Request $request, $dataQuery, $countQuery) {
        $dataQuery->orderBy('title', 'asc');
    }

    protected function getValidationRules(Request $request, Model $obj) {
        $rules = [
            'title' => 'required|max:256',
            'description' => 'required|max:256',
            'priority_id' => 'required',
            'status_id' => 'required'
        ];

        return $rules;
    }

    public function beforeStore(Request $request, Model $obj) {
        $obj->done = false;
    }

    protected function afterStore(Request $request, Model $model) {
        $this->saveAction($request->project_id, 'Store', config('utils.dashboard.saveTask'));
    }

    protected function afterUpdate(Request $request, Model $model) {
        $this->saveAction($request->project_id, 'Update', config('utils.dashboard.updateTask'));
    }

    protected function beforeDestroy(Request $request, Model $model) {
        DB::table('task_comments')
            ->where('task_id', $model->id)
            ->delete();
    }

    protected function afterDestroy(Request $request, Model $model) {
        $this->saveAction($model->project_id, 'Destroy', config('utils.dashboard.destroyTask'));
    }

    public function updateMilestone(Request $request) {
        $tasks = \App\Task::where('milestone_id', $request->milestone_id)->update(['milestone_id' => null]);
        DB::transaction(function() use ($request) {
            foreach ($request->tasks as $t) {
                $task = \App\Task::find($t['id']);
                $task->milestone_id = $request->milestone_id;
                $task->save();
            }
            $this->saveAction($request->project_id, 'Update', config('utils.dashboard.updateMilestoneTasks'));
        });
    }

    public function updateTaskByKanban(Request $request) {
        DB::transaction(function() use ($request) {
            $task = \App\Task::find($request->id);
            $status = \App\Status::where('slug', $request->newColumn['dataField'])->first();
            $task->status_id = $status->id;
            $task->save();
            $this->saveAction($request->project_id, 'Update', config('utils.dashboard.updateTask'));
        });
    }

}
