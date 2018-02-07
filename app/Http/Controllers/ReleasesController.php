<?php

namespace App\Http\Controllers;

use App\Release;

use Log;
use Carbon\Carbon;

use Illuminate\Http\Request;

use App\Http\Requests;
use App\Http\Controllers\CrudController;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Input;
use App\Exceptions\BusinessException;


class ReleasesController extends CrudController {

    public function __construct() {
    }

    protected function getModel() {
        return Release::class;
    }

    protected function applyFilters(Request $request, $query) {
        $query->with(['milestones.tasks', 'project']);
        if ($request->has('project_id')) {
            $query = $query->where('project_id', $request->project_id);
        }
    }

    protected function beforeSearch(Request $request, $dataQuery, $countQuery) {
        $dataQuery->orderBy('release_date', 'asc');
        $dataQuery->orderBy('id', 'asc');
    }

    protected function getValidationRules(Request $request, Model $obj) {
        $rules = [
            'title' => 'required|max:256',
            'description' => 'required|max:256'
        ];

        return $rules;
    }

    protected function afterStore(Request $request, Model $model) {
        $this->saveAction($request->project_id, 'Store', config('utils.dashboard.saveRelease'));
    }

    protected function afterUpdate(Request $request, Model $model) {
        $this->saveAction($request->project_id, 'Update', config('utils.dashboard.updateRelease'));
    }

    protected function afterDestroy(Request $request, Model $model) {
        $this->saveAction($request->project_id, 'Destroy', config('utils.dashboard.destroyRelease'));
    }

    public function finalize(Request $request) {
        $release = \App\Release::find($request->release_id);
        foreach ($release->milestones as $milestone) {
            if(!$milestone->done) {
                throw new BusinessException("Não foi possível finalizar a release, existem sprints não finalizadas");
            }
        }
        $this->saveAction($request->project_id, 'Update', config('utils.dashboard.finalizedRelease'));
        return \App\Release::where('id', $request->release_id)->update(['done' => true, 'release_date' => Carbon::now()]);
    }
}
