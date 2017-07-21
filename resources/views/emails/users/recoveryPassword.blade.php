<!DOCTYPE html>
<html>
    <head>
        <title>Redefinição de senha</title>
        <link href="https://fonts.googleapis.com/css?family=Lato:100" rel="stylesheet" type="text/css">
    </head>
    <body>
        <div style="width: 100%; text-align:center; background-color:#fff; padding: 10px;">
            <img src="{{$message->embed(public_path().'/client/images/governo-do-estado-da-bahia.png')}}" alt="logo"
                style="max-width: 30%;">
            <hr>
            <div style="font-size: 12px;">
                <h2 style="text-transform: uppercase;">Prezado {{$user['name']}}, </h2>
                <p>Segue o link abaixo para redefinir sua senha no sistema {{$appName}}.</p>
                <p>Caso não tenha sido você quem solcitou a redefinição de senha favor desconsiderar este email.</p>
                <p>Este link tem validade de 1 hora.</p>
                <p>Clique ou copie o link para redefinir sua senha.</p>
                <p><a href="{{ url('/#/app/password/reset/'.$token) }}">{{ url('/#/password/reset/'.$token) }}</a></p>
            </div>
        </div>
    </body>
</html>
