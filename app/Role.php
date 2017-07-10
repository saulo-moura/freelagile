<?php
/*
 * This file is part of the Starter Pack Dynamic Authorization
 */


namespace App;

use App\User;
use App\BaseModel;
use Illuminate\Database\Eloquent\Model;

use App\Authorization\Action;
use App\Authorization\Resource;

/**
 * App\Role
 *
 * @property int $id
 * @property string $title
 * @property string $slug
 * @property-read \Illuminate\Database\Eloquent\Collection|\App\User[] $users
 * @property-read \Illuminate\Database\Eloquent\Collection|\App\Permission[] $permissions
 * @property-read \Illuminate\Database\Eloquent\Collection|\OwenIt\Auditing\Log[] $logs
 * @method static \Illuminate\Database\Query\Builder|\App\Role whereId($value)
 * @method static \Illuminate\Database\Query\Builder|\App\Role whereTitle($value)
 * @method static \Illuminate\Database\Query\Builder|\App\Role whereSlug($value)
 */
class Role extends BaseModel
{
    /**
     * The database table used by the model.
     *
     * @var string
     */
    protected $table = 'roles';
    public $timestamps = false;

    protected $fillable = ['title','slug'];

    /*
    |--------------------------------------------------------------------------
    | Relationship Methods
    |--------------------------------------------------------------------------
    */

    /**
     * many-to-many relationship method.
     *
     * @return QueryBuilder
     */
    public function users()
    {
        return $this->belongsToMany(User::class);
    }

    /**
     * many-to-many relationship method.
     *
     * @return QueryBuilder
     */
    public function actions()
    {
        return $this->belongsToMany('\App\Authorization\Action', 'role_actions', 'role_id', 'action_id');
    }


     /**
     * Overrrides toArray method
     *
     * @return Array
     */
    public function toArray() {
        $data = parent::toArray();
        $actions = $this->actions;
        $data['actions'] = $actions->toArray();
        $data['has_users'] = $this->users->count() > 0;
        return $data;
    }
}
