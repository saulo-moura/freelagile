<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Contracts\Auth\Guard;
use App\Authorization\Authorization;

class HasPermission
{
    protected $auth;
    /**
     * Creates a new instance of the middleware.
     *
     * @param Guard $auth
     */
    public function __construct(Guard $auth)
    {
        $this->auth = $auth;
    }

    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
        $actionData = $request->route()->getAction();

        if(isset($actionData['controller'])) {
            $actionParts = explode('@',$actionData['controller']);
            $controller = $actionParts[0];
            $action = $actionParts[1];

            //verificar se tem permissão a partir do controller_class e namespace
            $user = $request->user();
            if ($user && !$request->user()->hasPermission($controller, $action)) {
                $msg = Authorization::getDenialMessage($controller, $action);
                return response()->json(['error' =>$msg, 'permissionError'=>true, 'items'=>[] ], 403);
            }
        }

        return $next($request);
    }
}
