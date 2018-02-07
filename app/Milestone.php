<?php

namespace App;

use App\BaseModel;

use Illuminate\Database\Eloquent\Model;

class Milestone extends BaseModel
{
    /**
     * The database table used by the model.
     *
     * @var string
     */
    protected $table = 'milestones';

    /**
     * Attributes that should be mass-assignable.
     *
     * @var array
     */
    protected $fillable = [
        'title',
        'description',
        'date_begin',
        'date_end',
        'project_id',
        'done',
        'release_id'
    ];

    /**
    * Retorna o projeto de um milestone
    */
    public function project() {
        return $this->belongsTo(Project::class);
    }

    /**
    * Retorna o projeto de um milestone
    */
    public function tasks() {
        return $this->hasMany(Task::class);
    }

    /**
    * Retorna a release de uma milestone
    */
    public function release() {
        return $this->belongsTo(Release::class);
    }

}
