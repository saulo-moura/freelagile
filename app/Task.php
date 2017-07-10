<?php

namespace App;

use App\Project;
use Illuminate\Database\Eloquent\Model;
use Carbon\Carbon;

/**
 * App\Task
 *
 * @property int $id
 * @property string $description
 * @property bool $done
 * @property int $priority
 * @property string $scheduled_to
 * @property int $project_id
 * @property \Carbon\Carbon $created_at
 * @property \Carbon\Carbon $updated_at
 * @property-read \App\Project $project
 * @property-read \Illuminate\Database\Eloquent\Collection|\OwenIt\Auditing\Log[] $logs
 * @method static \Illuminate\Database\Query\Builder|\App\Task whereId($value)
 * @method static \Illuminate\Database\Query\Builder|\App\Task whereDescription($value)
 * @method static \Illuminate\Database\Query\Builder|\App\Task whereDone($value)
 * @method static \Illuminate\Database\Query\Builder|\App\Task wherePriority($value)
 * @method static \Illuminate\Database\Query\Builder|\App\Task whereScheduledTo($value)
 * @method static \Illuminate\Database\Query\Builder|\App\Task whereProjectId($value)
 * @method static \Illuminate\Database\Query\Builder|\App\Task whereCreatedAt($value)
 * @method static \Illuminate\Database\Query\Builder|\App\Task whereUpdatedAt($value)
 */
class Task extends BaseModel
{
    protected $table = 'tasks';
    protected $fillable = [
        'description',
        'done',
        'priority',
        'scheduled_to',
        'project_id'
    ];

    /**
    * Retorna o projeto de um projeto
    */
    public function project()
    {
        return $this->belongsTo(Project::class);
    }
}
