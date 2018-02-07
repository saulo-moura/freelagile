<?php

namespace App;

use App\BaseModel;

use Illuminate\Database\Eloquent\Model;

class Dashboard extends BaseModel
{
    /**
     * The database table used by the model.
     *
     * @var string
     */
    protected $table = 'dashboard';

    /**
     * Attributes that should be mass-assignable.
     *
     * @var array
     */
    protected $fillable = [
        'user_id',
        'project_id',
        'action',
        'description'
    ];

    public function user() {
        return $this->belongsTo('App\User', 'user_id', 'id');
    }

}
