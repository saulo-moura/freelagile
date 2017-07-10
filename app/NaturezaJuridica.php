<?php

namespace App;

use App\BaseModel;

use Illuminate\Database\Eloquent\Model;

class NaturezaJuridica extends BaseModel
{
    /**
     * The database table used by the model.
     *
     * @var string
     */
    protected $table = 'naturezas_juridicas';

    /**
     * Indicates if the model should be timestamped.
     *
     * @var bool
     */
    public $timestamps = false;

    /**
     * Attributes that should be mass-assignable.
     *
     * @var array
     */
    protected $fillable = [
        'nome',
        'tipo_natureza_juridica'
    ];


}
