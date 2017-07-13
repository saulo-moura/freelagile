<!DOCTYPE html>
<html>
    <head>
        <title>Confirmação de Registro</title>
        <link href="https://fonts.googleapis.com/css?family=Lato:100" rel="stylesheet" type="text/css">
    </head>
    <body>
        <div style="width: 100%; text-align:center; background-color:#fff; padding: 10px;">
            <img src="{{$message->embed(public_path().'/client/images/governo-do-estado-da-bahia.png')}}" alt="logo"
                style="max-width: 30%;">
            <hr>
            <div style="font-size: 20px;font-weight: bold;">
                <h2 style="text-transform: uppercase;">Prezado {{$user['name']}}, </h2>
                <p>Você foi cadastrado com êxito no sistema {{$appName}}.</p>
                <p>Segue seus dados de acesso abaixo:</p>
            </div>
            <hr>
            <table style="border: none">
                <tr>
                    <td><b>Login:</b></td>
                    <td>{{$user['email']}}</td>
                </tr>
                <tr>
                    <td><b>Senha:</b></td>
                    <td>{{$user->getPasswordConteiner()}}</td>
                </tr>
                <tr>
                    <td><a href="{{$url}}">Clique aqui para acessar o sistema</a></td>
                </tr>
            </table>
        </div>
    </body>
</html>
