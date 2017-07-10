<?php

namespace App;

use App\BaseModel;

use Illuminate\Database\Eloquent\Model;

class ParametrosSistema extends BaseModel
{
    /**
     * The database table used by the model.
     *
     * @var string
     */
    protected $table = 'parametros_sistema';

    /**
     * Attributes that should be mass-assignable.
     *
     * @var array
     */

    protected $fillable = ['chave','valor','descricao'];

    
}
