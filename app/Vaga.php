<?php

namespace App;

use App\BaseModel;

use Illuminate\Database\Eloquent\Model;

class Vaga extends BaseModel
{
    /**
     * The database table used by the model.
     *
     * @var string
     */
    protected $table = 'vagas';

    /**
     * Status desejado que virá da requisição
     *
     * @var int
     */
    protected $status_desejado_id;

    /**
     * Attributes that should be mass-assignable.
     *
     * @var array
     */
    protected $fillable = [
        'estabelecimento_saude_id' ,
        'status_id',
        'curso_id' ,
        'modalidade_id',
        'area_id' ,
        'setor_id',
        'data_inicio',
        'data_fim',
        'total_vagas_ano',
        'especificacao_id',
        'especialidade_id'
    ];

   /*
    |--------------------------------------------------------------------------
    | Relationship Methods
    |--------------------------------------------------------------------------
    */
    public function estabelecimentoSaude()
    {
        return $this->belongsTo('App\EstabelecimentoSaude', 'estabelecimento_saude_id', 'id');
    }

    public function curso()
    {
        return $this->belongsTo('App\Curso', 'curso_id', 'id');
    }

    public function area()
    {
        return $this->belongsTo('App\Area', 'area_id', 'id');
    }

    public function modalidade()
    {
        return $this->belongsTo('App\Modalidade', 'modalidade_id', 'id');
    }

    public function setor()
    {
        return $this->belongsTo('App\Setor', 'setor_id', 'id');
    }

    public function status()
    {
        return $this->belongsTo('App\Status', 'status_id', 'id');
    }

    public function historico()
    {
        return $this->hasMany('App\HistoricoVaga', 'vaga_id', 'id');
    }

    public function horarios()
    {
        return $this->hasMany('App\Horario', 'vaga_id', 'id');
    }

    public function especialidades()
    {
        return $this->belongsTo('App\Especialidade', 'especialidade_id', 'id');
    }

    public function especificacoes()
    {
        return $this->belongsTo('App\Especificacao', 'especificacao_id', 'id');
    }
}
