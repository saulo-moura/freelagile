<?php

namespace App;

use App\BaseModel;

use Illuminate\Database\Eloquent\Model;

class Release extends BaseModel
{
    /**
     * The database table used by the model.
     *
     * @var string
     */
    protected $table = 'releases';

    /**
     * Attributes that should be mass-assignable.
     *
     * @var array
     */
    protected $fillable = [
        'title',
        'description',
        'done',
        'project_id',
        'release_date'
    ];

    /**
    * Retorna o projeto de uma release
    */
    public function project() {
        return $this->belongsTo(Project::class);
    }

    /**
    * Retorna as milestones de uma release
    */
    public function milestones() {
        return $this->hasMany(Milestone::class);
    }

}
