<?php

namespace App;

use App\BaseModel;
use App\Mail\RecoveryPassword;

use Illuminate\Auth\Authenticatable;
use Illuminate\Notifications\Notifiable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Auth\Passwords\CanResetPassword;
use Illuminate\Foundation\Auth\Access\Authorizable;
use Illuminate\Contracts\Auth\Authenticatable as AuthenticatableContract;
use Illuminate\Contracts\Auth\Access\Authorizable as AuthorizableContract;
use Illuminate\Contracts\Auth\CanResetPassword as CanResetPasswordContract;
use Tymon\JWTAuth\Contracts\JWTSubject as JWTSubject;
use Mail;

/**
 * App\User
 *
 * @property int $id
 * @property string $name
 * @property string $email
 * @property string $password
 * @property string $remember_token
 * @property string $image
 * @property \Carbon\Carbon $created_at
 * @property \Carbon\Carbon $updated_at
 * @property-read \Illuminate\Database\Eloquent\Collection|\App\Role[] $roles
 * @property-read \Illuminate\Database\Eloquent\Collection|\OwenIt\Auditing\Log[] $logs
 * @method static \Illuminate\Database\Query\Builder|\App\User whereId($value)
 * @method static \Illuminate\Database\Query\Builder|\App\User whereName($value)
 * @method static \Illuminate\Database\Query\Builder|\App\User whereEmail($value)
 * @method static \Illuminate\Database\Query\Builder|\App\User wherePassword($value)
 * @method static \Illuminate\Database\Query\Builder|\App\User whereRememberToken($value)
 * @method static \Illuminate\Database\Query\Builder|\App\User whereCreatedAt($value)
 * @method static \Illuminate\Database\Query\Builder|\App\User whereUpdatedAt($value)
 * @method static \Illuminate\Database\Query\Builder|\App\User whereImage($value)
 */
class User extends BaseModel implements AuthenticatableContract, CanResetPasswordContract, JWTSubject
{
    use Authenticatable, Authorizable, Notifiable, CanResetPassword;

    protected $dontFilterAttributesInDinamicQuery = ['password', 'image', 'remember_token'];

    /**
     * The database table used by the model.
     *
     * @var string
     */
    protected $table = 'users';

    /**
     * The attributes that are mass assignable.
     *
     * @var array
     */
    protected $fillable = ['name', 'email', 'image', 'birthday'];

    /**
     * The attributes excluded from the model's JSON form.
     *
     * @var array
     */
    protected $hidden = ['password', 'remember_token'];
    protected $dontKeepLogOf = ['password', 'remember_token'];

    /**
     * Atributo usado para amazenar temporáriamente a senha para envio no email
     *
     * @var string
     */
    private $passwordConteiner;

    public function getPasswordConteiner()
    {
        return $this->passwordConteiner;
    }

    public function setPasswordConteiner($passwordConteiner)
    {
        $this->passwordConteiner = $passwordConteiner;
    }

    public function getJWTIdentifier()
    {
        return $this->getKey();
    }

    public function getJWTCustomClaims()
    {
        return [];
    }

    /**
     * Checks a Role
     *
     * @param  String role Slug of a role
     * @return Boolean true if has role, otherwise false
     */
    public function hasRole($roles = null, $all = false)
    {
        return !is_null($roles) && $this->checkRole($roles, $all);
    }

    /**
     * Check if the roles matches with any role user has
     *
     * @param  String roles slug of a role
     * @return Boolean true if role exists, otherwise false
     */
    protected function checkRole($roles, $all)
    {
        $userRoles = array_pluck($this->roles()->get()->toArray(), 'slug');

        $roles = is_array($roles) ? $roles : [$roles];

        if ($all) {
            return count(array_intersect($userRoles, $roles)) == count($roles);
        } else {
            return count(array_intersect($userRoles, $roles));
        }
    }

    /**
    * Send the password reset notification.
    *
    * @param  string  $token
    * @return void
    */
    public function sendPasswordResetNotification($token)
    {
        Mail::to($this->email)->send(new RecoveryPassword($this, $token));
    }

    /*
    |--------------------------------------------------------------------------
    | Relationship Methods
    |--------------------------------------------------------------------------
    */

    /**
     * Many-To-Many Relationship Method for accessing the User->roles
     *
     * @return QueryBuilder Object
     */
    public function roles() {
        return $this->belongsToMany(Role::class);
    }

    public function projectRoles() {
        return $this->belongsToMany('App\Role', 'user_role_project', 'user_id', 'role_id');
    }
}
