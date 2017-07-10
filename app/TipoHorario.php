<?php

namespace App;

use App\BaseModel;

use Illuminate\Database\Eloquent\Model;

class TipoHorario extends BaseModel
{
    /**
     * The database table used by the model.
     *
     * @var string
     */
    protected $table = 'tipos_horario';

    /**
     * Attributes that should be mass-assignable.
     *
     * @var array
     */
    protected $fillable = [
        'descricao',
        'duracao'
    ];

    
}
