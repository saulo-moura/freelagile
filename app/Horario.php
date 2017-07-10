<?php

namespace App;

use App\BaseModel;

use Illuminate\Database\Eloquent\Model;

class Horario extends BaseModel
{
    /**
     * The database table used by the model.
     *
     * @var string
     */
    protected $table = 'horarios';

    /**
     * Attributes that should be mass-assignable.
     *
     * @var array
     */
    protected $fillable = [
        'qtd_vagas',
        'vaga_id',
        'titulo',
        'dia_semana',
        'tipo_horario_id'
    ];

    
}
