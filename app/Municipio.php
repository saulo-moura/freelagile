<?php

namespace App;

use App\BaseModel;

use Illuminate\Database\Eloquent\Model;

class Municipio extends BaseModel
{
    /**
     * The database table used by the model.
     *
     * @var string
     */
    protected $table = 'municipios';

    /**
     * Attributes that should be mass-assignable.
     *
     * @var array
     */
    protected $fillable = ['nome', 'estado_id', 'nucleo_regional_id'];

    public function campus(){
        return $this->belongsTo('App\Campus', 'municipio_id', 'id');
    }

}
