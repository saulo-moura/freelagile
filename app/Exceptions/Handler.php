<?php

namespace App\Exceptions;

use Exception;
use Log;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use \Illuminate\Validation\ValidationException;
use Symfony\Component\HttpKernel\Exception\HttpException;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;
use Tymon\JWTAuth\Exceptions\Exceptions;
use App\Exceptions\BusinessException;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Exceptions\Handler as ExceptionHandler;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;

class Handler extends ExceptionHandler
{
    /**
     * A list of the exception types that should not be reported.
     *
     * @var array
     */
    protected $dontReport = [
        \Illuminate\Auth\AuthenticationException::class,
        \Illuminate\Auth\Access\AuthorizationException::class,
        \Symfony\Component\HttpKernel\Exception\HttpException::class,
        \Illuminate\Session\TokenMismatchException::class,
        ValidationException::class,
    ];

    protected $headers = [];

    protected $errorKey = 'error';


    /**
     * Render an exception into an HTTP response.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Exception  $e
     * @return \Illuminate\Http\Response
     */
    public function render($request, Exception $e)
    {
        $this->headers = \Prodeb::getCORSHeaders();

        //Exceptions relacionadas ao token
        $tokenResponse = $this->handlerTokenExceptions($e);

        if ($tokenResponse !== null) {
            return $tokenResponse;
        }

        //Exceptions especificas com tratamento especial
        $response = $this->handlerSpecialExceptions($e);

        // Para as demais exceptions sem tratamento especifico
        // é criado uma response de erro genérica
        if ($response === null) {
            $response = $this->buildGenericErrorResponse($e);
        }

        return $this->refreshTokenInResponse($response);
    }

    protected function handlerTokenExceptions(Exception $e)
    {
        $response = null;

        if ($e instanceof TokenExpiredException) {
            $response = response()->json([$this->errorKey =>'token_expired'], $e->getStatusCode(), $this->headers);
        }

        if ($e instanceof UnauthorizedHttpException) {
            $response = response()->json([$this->errorKey =>'token_expired'], $e->getStatusCode(), $this->headers);
        }

        if ($e instanceof TokenInvalidException) {
            $response = response()->json([$this->errorKey =>'token_invalid'], $e->getStatusCode(), $this->headers);
        }

        if ($e instanceof JWTException) {
            $response = response()->json([$this->errorKey =>'token_absent'], $e->getStatusCode(), $this->headers);
        }

        if ($e instanceof BadRequestHttpException && $e->getMessage() == "Token not provided") {
            $response = response()->json([$this->errorKey => 'token_not_provided'], $e->getStatusCode(), $this->headers);
        }

        return $response;
    }

    protected function handlerSpecialExceptions(Exception $e)
    {
        $response = null;

        if ($e instanceof ModelNotFoundException) {
            $response = response()->json([$this->errorKey =>'messages.resourceNotFoundError'], 404, $this->headers);
        }

        if ($e instanceof ValidationException) {
            $response = $e->response;
        }

        if ($e instanceof QueryException) {
            Log::debug('Erro no acesso ao bando de dados: '.$e->getMessage());

            if (strpos($e->getMessage(), 'not-null') !== false) {
                $response = response()->json([$this->errorKey => 'messages.notNullError'], 400, $this->headers);
            }
        }

        if ($e instanceof BusinessException) {
            $response = response()->json([$this->errorKey => $e->getMessage()], 400, $this->headers);
        }

        return $response;
    }

    protected function buildGenericErrorResponse(Exception $e)
    {
        $content = [$this->errorKey => 'messages.internalError'];

        if (config('app.debug')) {
            $content = [$this->errorKey => $e->getMessage()];
        }

        return response()
            ->json($content, method_exists($e, 'getStatusCode') ? $e->getStatusCode() : 500, $this->headers);
    }

    protected function refreshTokenInResponse($response)
    {
        //Dá um refresh no token caso o mesmo exista para anexar a resposta
        try {
            $token = \JWTAuth::parseToken()->refresh();

            if ($token !== null) {
                $response = $response->header('Authorization', 'Bearer '. $token);
            }
        } catch (Exception $ex) {
            Log::debug('Request without token');
        }

        return $response;
    }

    /**
     * Convert an authentication exception into an unauthenticated response.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Illuminate\Auth\AuthenticationException  $exception
     * @return \Illuminate\Http\Response
     */
    protected function unauthenticated($request, AuthenticationException $exception)
    {
        return response()->json(['error' => 'messages.notAuthorized'], 401);
    }
}
