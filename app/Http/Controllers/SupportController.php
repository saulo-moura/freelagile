<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

use OwenIt\Auditing\Log;

use App\Http\Requests;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Input;
use Carbon\Carbon;

class SupportController extends Controller
{
    public function __construct()
    {
    }

    /**
     * Serviço que retorna as traduções dos atributos
     * Estas traduções são utilizadas na view também
     */
    public function langs(Request $request)
    {
        return [
            'attributes' => trans('validation.attributes')
        ];
    }
}
