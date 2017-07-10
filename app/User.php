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
use App\Authorization\Action;
use App\Authorization\Authorization;
use Illuminate\Database\Eloquent\SoftDeletes;

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

    use SoftDeletes;

    /**
     * The database table used by the model.
     *
     * @var string
     */
    protected $table = 'users';

    /**
     * Relation to be loaded
     *
     * @var array
     */
    protected $with = ['instituicaoEnsino', 'estabelecimentoSaude'];

    /**
     * The attributes that are mass assignable.
     *
     * @var array
     */
    protected $fillable = ['name', 'email', 'image', 'cpf', 'instituicao_ensino_id', 'estabelecimento_saude_id'];

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
    public function roles()
    {
        return $this->belongsToMany(Role::class);
    }
    /**
     * Belongs to Relationship Method for accessing the User->estabelecimentoSaude
     *
     * @return QueryBuilder Object
     */
    public function estabelecimentoSaude()
    {
        return $this->belongsTo('App\EstabelecimentoSaude', 'estabelecimento_saude_id', 'id');
    }

    /**
     * Belongs to Relationship Method for accessing the User->instituicaoEnsino
     *
     * @return QueryBuilder Object
     */
    public function instituicaoEnsino()
    {
        return $this->belongsTo('App\InstituicaoEnsino', 'instituicao_ensino_id', 'id');
    }

    /**
     * Verifica se o usuário corrent possui uma permissão
     *
     * @return boolean
     */
    public function hasPermission($controller, $action)
    {
        return Authorization::hasPermission($controller, $action, $this);
    }

    public function toArray() {
        $data = parent::toArray();
        $data['allowed_actions'] = Authorization::userAllowedActions($this);
        return $data;
    }
}
