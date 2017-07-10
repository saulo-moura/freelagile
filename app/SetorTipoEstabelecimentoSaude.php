<?php

namespace App;

use App\BaseModel;

use Illuminate\Database\Eloquent\Model;

class SetorTipoEstabelecimentoSaude extends BaseModel
{
    /**
     * The database table used by the model.
     *
     * @var string
     */
    protected $table = 'setores_tipos_estabelecimento_saude';


    public function tipoEstabelecimentoSaude()
    {
        return $this->belongsTo('App\TipoEstabelecimentoSaude', 'tipo_estabelecimento_saude_id', 'id');
    }

}
