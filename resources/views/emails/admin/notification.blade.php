<!DOCTYPE html>
<html>
    <head>
        <title>Email</title>
        <link href="https://fonts.googleapis.com/css?family=Lato:100" rel="stylesheet" type="text/css">
    </head>
    <body>
        <div style="width: 100%; text-align:center; background-color:#fff; padding: 10px;">
            <img src="http://secom.ba.gov.br/arquivos/File/marcagoverno2015.jpg" alt="logo"
                style="max-width: 30%;">
            <hr>
            <div style="font-size: 20px;font-weight: bold;">
                {{$mailData['subject']}}
            </div>
            <hr>
            <div>
                {{$mailData['message']}}
            </div>
        </div>
    </body>
</html>
