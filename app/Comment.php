<?php

namespace App;

use App\BaseModel;

use Illuminate\Database\Eloquent\Model;

class Comment extends BaseModel
{
    /**
     * The database table used by the model.
     *
     * @var string
     */
    protected $table = 'task_comments';

    /**
     * Attributes that should be mass-assignable.
     *
     * @var array
     */
    protected $fillable = [
        'description',
        'task_id',
        'comment_id'
    ];

    protected $with = ['comments', 'user'];

    /**
    * Retorna a tarefa de um comentário
    */
    public function task() {
        return $this->belongsTo(Task::class);
    }

    /**
    * Retorna os comentários de um comentário
    */
    public function comments() {
        return $this->hasMany(Comment::class);
    }

    /**
    * Retorna o usuário que fez o comentário
    */
    public function user() {
        return $this->belongsTo(User::class);
    }
}
