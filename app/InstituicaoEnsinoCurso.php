<?php

namespace App;

use App\BaseModel;

use Illuminate\Database\Eloquent\Model;

class InstituicaoEnsinoCurso extends BaseModel
{
    /**
     * The database table used by the model.
     *
     * @var string
     */
    protected $table = 'cursos_ies';
    
    /**
     * Relações a serem carregadas com o model.
     *
     * @var string
     */
    protected $with = ['curso', 'instituicaoEnsino', 'campus', 'coordenador'];

    /**
     * Attributes that should be mass-assignable.
     *
     * @var array
     */
    protected $fillable = [
        'curso_id',
        'instituicao_ensino_id',
        'campus_id',
        'coordenador_id',
        'email',
        'telefone',
        'data_reconhecimento',
        'nota_enade',
        'autorizacao_funcionamento'
    ];

    //RELATIONS
    public function curso(){
        return $this->belongsTo('App\Curso', 'curso_id');
    }
    public function campus(){
        return $this->belongsTo('App\Campus', 'campus_id');
    }
    public function instituicaoEnsino(){
        return $this->belongsTo('App\InstituicaoEnsino', 'instituicao_ensino_id');
    }
    public function coordenador(){
        return $this->belongsTo('App\User', 'coordenador_id');
    }

    
}
