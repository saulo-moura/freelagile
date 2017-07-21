<?php

namespace App\Util;

class Prodeb
{

     /**
     * Função que retorna os cabeçalhos referente ao CORS
     *
     * @return Array com todos os cabeçalhos necessários referente ao CORS
     */
    public static function getCORSHeaders()
    {
        return [
            'Access-Control-Allow-Origin' => '*',
            'Access-Control-Allow-Methods' => 'POST, GET, OPTIONS, PUT, DELETE',
            'Access-Control-Allow-Headers' => 'Origin, Content-Type, Accept, Authorization, X-Requested-With',
            'Access-Control-Allow-CredentialsHeaders' => 'true'
        ];
    }

    /**
     * Transforma uma data string em um objeto Carbon
     *
     * @param $date data no formato de string
     * @return Objeto do Carbon com a data transformada
     */
    public static function parseDate($date)
    {
        return \Carbon::parse($date)->timezone(config('app.timezone'));
    }

    /**
     * Varre o diretório do aplicativo para encontrar os Models
     *
     * @param $ignoredModels Lista de modelos para serem ignorados da varredura
     * @return array contendo todos os models
     */
    public static function modelNames($ignoredModels = array())
    {
        $models = array();
        $path = app_path();
        $files = scandir($path);

        foreach ($files as $file) {
            //skip all dirs and ignoredModels
            if ($file === '.' || $file === '..' || is_dir($path . '/' . $file) || in_array($file, $ignoredModels)) {
                continue;
            }

            $models[] = preg_replace('/\.php$/', '', $file);
        }

        return $models;
    }
}
