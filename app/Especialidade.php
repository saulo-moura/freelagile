<?php

namespace App;

use App\BaseModel;

use Illuminate\Database\Eloquent\Model;

class Especialidade extends BaseModel
{
    /**
     * The database table used by the model.
     *
     * @var string
     */
    protected $table = 'especialidades';

    /**
     * Attributes that should be mass-assignable.
     *
     * @var array
     */
    protected $fillable = ['nome'];

}
