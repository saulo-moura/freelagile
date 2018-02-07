<?php

namespace App;

use App\BaseModel;
use App\Task;

use Illuminate\Database\Eloquent\Model;
use OwenIt\Auditing\AuditingTrait;

/**
 * App\Project
**/

class Project extends BaseModel {

    protected $table = 'projects';

    protected $fillable = [
        'name',
        'description',
        'owner',
        'dev_id',
        'client_id',
        'stakeholder_id',
        'username_github',
        'repo_github',
        'hour_value_developer',
        'hour_value_client',
        'hour_value_final',
        'done'
    ];

    public function developer() {
        return $this->belongsTo('App\User', 'dev_id', 'id');
	}

    public function client() {
        return $this->belongsTo('App\User', 'client_id', 'id');
    }

    public function stakeholder() {
        return $this->belongsTo('App\User', 'stakeholder_id', 'id');
    }

    public function tasks() {
        return $this->hasMany(Task::class);
    }

    public function releases() {
        return $this->hasMany(Release::class);
	}
}
