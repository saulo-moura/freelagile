<?php
/**
 * CrudController is a shared base controller that provides a CRUD basis for Laravel applications.
 *
 * @author Jamie Rumbelow <jamie@jamierumbelow.net>
 * @license http://opensource.org/licenses/MIT
 */

namespace App\Http\Traits;

use Illuminate\Http\Request;

/**
 * Actions are the core of the CRUD functionality; the methods accessed directly through the router.
 *
 * @internal
 * @uses \App\Http\Controllers\CrudController
 * @used-by \App\Http\Controllers\CrudController
 */
trait Actions
{
    public function index(Request $request)
    {
        $this->callback('beforeAll', $request);

        $klass = $this->getModel();

        $baseQuery = $klass::query();

        $this->callback('applyFilters', $request, $baseQuery);

        $dataQuery = clone $baseQuery;
        $countQuery = clone $baseQuery;

        $this->callback('beforeSearch', $request, $dataQuery, $countQuery);

        if ($request->has('perPage') && $request->has('page')) {
            $data['items'] = $dataQuery
                ->skip(($request->page - 1) * $request->perPage)
                ->take($request->perPage)
                ->get();

            $data['total'] = $countQuery
                ->count();
        } else {
            if ($request->has('limit')) {
                $data = $dataQuery->take($request->limit)->get();
            } else {
                $data = $dataQuery->get();
            }
        }

        return $data;
    }

    /**
     * Store a newly created resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function store(Request $request)
    {
        $this->callback('beforeAll', $request);

        $klass = $this->getModel();
        $obj = new $klass();

        return $this->saveOrUpdate($request, $obj, 'Store');
    }

    /**
     * Display the specified resource.
     *
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function show(Request $request, $id)
    {
        $this->callback('beforeAll', $request);

        $klass = $this->getModel();

        $obj = $klass::findOrFail($id);

        $this->callback('afterShow', $request, $obj);

        return $obj;
    }

    /**
     * Store a newly created resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function update(Request $request, $id)
    {
        $this->callback('beforeAll', $request);

        $klass = $this->getModel();
        $obj = $klass::find($id);

        return $this->saveOrUpdate($request, $obj, 'Update');
    }

    protected function saveOrUpdate(Request $request, $obj, $action)
    {
        $input = $request->all();

        $this->validate($input, $this->getValidationRules($request, $obj));

        $obj->fill($input);

        try {
            \DB::transaction(function () use ($request, $action, $obj) {
                $this->callback('before'.$action, $request, $obj);
                $this->callback('beforeSave', $request, $obj);

                $obj->save();

                $this->callback('after'.$action, $request, $obj);
                $this->callback('afterSave', $request, $obj);

                $this->dashboard($request, $obj, $action);
            });
        } catch (Exception $e) {
            return Response::json(['error' => 'messages.duplicatedResourceError'], HttpResponse::HTTP_CONFLICT);
        }

        return $obj;
    }

    public function destroy(Request $request, $id)
    {
        $this->callback('beforeAll', $request);

        $klass = $this->getModel();
        $obj = $klass::find($id);

        \DB::transaction(function () use ($request, $obj) {
            $this->callback('beforeDestroy', $request, $obj);

            $obj->delete();

            $this->callback('afterDestroy', $request, $obj);

            $this->dashboard($request, $obj, 'Destroy');
        });
    }

    protected function dashboard(Request $request, $obj, $action) {
        $user = \Auth::user();
        $query = \App\Dashboard::create([
            'user_id' => $user->id,
            'project_id' => isset($request->project_id) ? $request->project_id : $obj->id, 
            'action' => $action, 
            'description' => strcmp($action, 'Store') == 0 ? 'messages.dashboard.store' : (strcmp($action, 'Update') == 0 ? 'messages.dashboard.update' : 'messages.dashboard.destroy')
        ]);
    }
}
