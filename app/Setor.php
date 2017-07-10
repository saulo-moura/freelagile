<?php

namespace App;

use App\BaseModel;

use Illuminate\Database\Eloquent\Model;

class Setor extends BaseModel
{
    /**
     * The database table used by the model.
     *
     * @var string
     */
    protected $table = 'setores';

    /**
     * Attributes that should be mass-assignable.
     *
     * @var array
     */
    protected $fillable = ['nome'];

    /*
    |--------------------------------------------------------------------------
    | Relationship Methods
    |--------------------------------------------------------------------------
    */
    public function setorTipoEstabelecimentoSaude() {
        return $this->belongsToMany('App\TipoEstabelecimentoSaude', 'setores_tipos_estabelecimento_saude', 'setor_id', 'tipo_estabelecimento_saude_id');
    }
}
