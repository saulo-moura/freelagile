<?php

namespace App;

use App\BaseModel;

use Illuminate\Database\Eloquent\Model;

class Curso extends BaseModel
{
    /**
     * The database table used by the model.
     *
     * @var string
     */
    protected $table = 'cursos';

    /**
     * Attributes that should be mass-assignable.
     *
     * @var array
     */
    protected $fillable = ['nome'];    

}
