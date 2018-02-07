<?php

namespace App;

use App\BaseModel;

use Illuminate\Database\Eloquent\Model;

class Priority extends BaseModel
{
    /**
     * The database table used by the model.
     *
     * @var string
     */
    protected $table = 'priorities';

    /**
     * Attributes that should be mass-assignable.
     *
     * @var array
     */
    protected $fillable = [
        'name',
        'slug'
    ];


}
