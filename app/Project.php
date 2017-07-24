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
    protected $fillable = ['name', 'description', 'owner'];

    protected $dateFormat = "Y-m-d H:m:i";
    
    public function roles() {
        return $this->belongsToMany('App\Role', 'user_role_project', 'role_id', 'project_id');
	}

}
