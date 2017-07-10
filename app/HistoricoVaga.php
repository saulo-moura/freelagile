<?php

namespace App;

use App\BaseModel;

use Illuminate\Database\Eloquent\Model;

class HistoricoVaga extends BaseModel
{
    /**
     * The database table used by the model.
     *
     * @var string
     */
    protected $table = 'historico_vagas';

    /**
     * Attributes that should be mass-assignable.
     *
     * @var array
     */
    protected $fillable = ['status_id', 'vaga_id', 'user_id', 'created_at'];

    /*
    |--------------------------------------------------------------------------
    | Relationship Methods
    |--------------------------------------------------------------------------
    */
    public function usuario()
    {
        return $this->belongsTo('App\User', 'user_id', 'id')->withTrashed();
    }

    public function status()
    {
        return $this->belongsTo('App\Status', 'status_id', 'id');
    }
}
