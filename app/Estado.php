<?php

namespace App;

use App\BaseModel;

use Illuminate\Database\Eloquent\Model;

class Estado extends BaseModel
{
    /**
     * The database table used by the model.
     *
     * @var string
     */
    protected $table = 'estados';

    /**
     * Attributes that should be mass-assignable.
     *
     * @var array
     */
    protected $fillable = ['nome'];

    
}