<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

use OwenIt\Auditing\Auditing;

use App\Http\Requests;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Input;
use Illuminate\Support\Facades\DB;
use Carbon\Carbon;

class AuditController extends Controller
{
    public function __construct()
    {
    }

    /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function index(Request $request)
    {
        $baseQuery = Auditing::with('user');

        //filtra por atributos do relacionamento user
        $baseQuery = $baseQuery->whereHas('user', function ($query) use ($request) {
            if ($request->has('user')) {
                $query->where('name', 'ilike', '%'.$request->user.'%');
            }
        });

        if ($request->has('type')) {
            $baseQuery = $baseQuery->where('type', $request->type);
        }

        if ($request->has('auditable_id')) {
            $baseQuery = $baseQuery->where('auditable_id', $request->auditable_id);
        }

        if ($request->has('model')) {
            $baseQuery = $baseQuery->where('auditable_type', 'App\\' . $request->model);
        }

        if ($request->has('dateStart')) {
            $baseQuery = $baseQuery->where('created_at', '>=', $request->dateStart);
        }

        if ($request->has('dateEnd')) {
            $baseQuery = $baseQuery->where('created_at', '<=', \Prodeb::parseDate($request->dateEnd)->endOfDay());
        }

        $dataQuery = clone $baseQuery;
        $countQuery = clone $baseQuery;

        $data['items'] = $dataQuery
            ->orderBy('created_at', 'desc')
            ->skip(($request->page - 1) * $request->perPage)
            ->take($request->perPage)
            ->get();

        $data['total'] = $countQuery
            ->count();

        return $data;
    }

    /**
     * Serviço responsável por pegar todos os modelos
     *
     * @return array contendo uma lista de models
     */
    public function models(Request $request)
    {
        $models = \Prodeb::modelNames(array("BaseModel.php", "Role.php"));

        return [
            'models' => $models
        ];
    }
}
