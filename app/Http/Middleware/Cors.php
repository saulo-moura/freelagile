<?php

namespace App\Http\Middleware;

use Closure;

class Cors
{
    /**
     * Middleware que trata o CORS.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
        $response = $next($request);

        // Pega todos os cabeçalhos necessários para o CORS
        $headers = \Prodeb::getCORSHeaders();

        //Adiciona os cabeçalhos na resposta
        foreach ($headers as $key => $value) {
            $response->headers->set($key, $value);
        }

        return $response;
    }
}
