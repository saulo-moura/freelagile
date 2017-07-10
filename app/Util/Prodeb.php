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
            'Access-Control-Allow-Headers' => 'Origin, Content-Type, Accept, Authorization, X-Requested-With, Application',
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

    public static function getSlug($string)
    {

         // Remove special accented characters - ie. sí.
        if (!isset($string)) {
            return $string;
        }

        $clean_name = strtr($string, array('Š' => 'S','Ž' => 'Z','š' => 's','ž' => 'z','Ÿ' => 'Y','À' => 'A','Á' => 'A','Â' => 'A','Ã' => 'A','Ä' => 'A','Å' => 'A','Ç' => 'C','È' => 'E','É' => 'E','Ê' => 'E','Ë' => 'E','Ì' => 'I','Í' => 'I','Î' => 'I','Ï' => 'I','Ñ' => 'N','Ò' => 'O','Ó' => 'O','Ô' => 'O','Õ' => 'O','Ö' => 'O','Ø' => 'O','Ù' => 'U','Ú' => 'U','Û' => 'U','Ü' => 'U','Ý' => 'Y','à' => 'a','á' => 'a','â' => 'a','ã' => 'a','ä' => 'a','å' => 'a','ç' => 'c','è' => 'e','é' => 'e','ê' => 'e','ë' => 'e','ì' => 'i','í' => 'i','î' => 'i','ï' => 'i','ñ' => 'n','ò' => 'o','ó' => 'o','ô' => 'o','õ' => 'o','ö' => 'o','ø' => 'o','ù' => 'u','ú' => 'u','û' => 'u','ü' => 'u','ý' => 'y','ÿ' => 'y'));

        $clean_name = strtr($clean_name, array('Þ' => 'TH', 'þ' => 'th', 'Ð' => 'DH', 'ð' => 'dh', 'ß' => 'ss', 'Œ' => 'OE', 'œ' => 'oe', 'Æ' => 'AE', 'æ' => 'ae', 'µ' => 'u'));

        $words = explode(" ", $clean_name);

        $slug = '';
        foreach ($words as $word) {
            $str = strtolower($word);
            if ($slug !== '') {
                $slug .= ucfirst($str);
            } else {
                $slug .= $str;
            }
        }

        return $slug;
    }
    
    /**
     * Substitui os acentos de uma string por caracteres normais
     *
     * @param $string
     * @return $string (com os caracteres removidos)
     */
    public static function removerAcentos($string)
    {
        return preg_replace(array("/(á|à|ã|â|ä)/","/(Á|À|Ã|Â|Ä)/","/(é|è|ê|ë)/","/(É|È|Ê|Ë)/","/(í|ì|î|ï)/","/(Í|Ì|Î|Ï)/","/(ó|ò|õ|ô|ö)/","/(Ó|Ò|Õ|Ô|Ö)/","/(ú|ù|û|ü)/","/(Ú|Ù|Û|Ü)/","/(ñ)/","/(Ñ)/"), explode(" ", "a A e E i I o O u U n N"), $string);
    }
}
