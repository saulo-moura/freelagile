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
        'title',
        'description',
        'done',
        'milestone_id',
        'status_id',
        'priority_id',
        'estimated_time',
        'type_id',
        'project_id'
    ];

    protected $with = ['milestone', 'status', 'priority', 'type', 'project', 'comments'];

    /**
    * Retorna o milestone de um de uma tarefa
    */
    public function milestone() {
        return $this->belongsTo(Milestone::class);
    }

    /**
    * Retorna o milestone de um de uma tarefa
    */
    public function status() {
        return $this->belongsTo(Status::class);
    }

    /**
    * Retorna o milestone de um de uma tarefa
    */
    public function priority() {
        return $this->belongsTo(Priority::class);
    }

    /**
    * Retorna o tipo de um de uma tarefa
    */
    public function type() {
        return $this->belongsTo(Type::class);
    }

    /**
    * Retorna o projeto a qual a tarefa pertence
    */
    public function project() {
        return $this->belongsTo(Project::class);
    }

    /**
    * Retorna os comentários de uma tarefa
    */
    public function comments() {
        return $this->hasMany(Comment::class)->orderBy('created_at', 'desc');
    }

}
