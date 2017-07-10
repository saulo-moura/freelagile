<?php

namespace App;

use App\BaseModel;

use Illuminate\Database\Eloquent\Model;

class Campus extends BaseModel
{
    /**
     * The database table used by the model.
     *
     * @var string
     */
    protected $table = 'campus';

    /**
     * Attributes that should be mass-assignable.
     *
     * @var array
     */

    protected $fillable = ['nome','endereco','bairro','cep','municipio_id','instituicao_ensino_id'];

    public function municipio(){
        return $this->hasOne('App\Municipio', 'id', 'municipio_id');
    }

    public function instituicoesEnsinoSuperior(){
        return $this->hasOne('App\InstituicaoEnsino', 'id', 'instituicao_ensino_id');
    }

}
