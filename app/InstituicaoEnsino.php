<?php

namespace App;

use App\BaseModel;

use Illuminate\Database\Eloquent\Model;

class InstituicaoEnsino extends BaseModel
{
    /**
     * The database table used by the model.
     *
     * @var string
     */
    protected $table = 'instituicoes_ensino_superior';

    /**
     * Attributes that should be mass-assignable.
     *
     * @var array
     */
    protected $fillable = [
        'nome',
        'sigla',
        'razao_social',
        'cnpj',
        'mantenedora',
        'cnpj_mantenedora',
        'natureza_juridica_id',
        'endereco',
        'numero',
        'complemento',
        'bairro',
        'cep',
        'municipio_id',
        'nucleo_regional_id',
        'telefone',
        'telefone2',
        'telefone3',
        'igc',
        'email',
        'email2',
        'email3',
        'nome_reitor',
        'telefone_reitor',
        'telefone_reitor2',
        'email_reitor',
        'cpf_reitor',
        'rg_reitor'
    ];

    //RELATIONS
    public function municipio(){
        return $this->belongsTo('App\Municipio', 'municipio_id');
    }
}
