<?php

namespace App;

use App\BaseModel;

use Illuminate\Database\Eloquent\Model;

class EstabelecimentoSaude extends BaseModel
{
    /**
     * The database table used by the model.
     *
     * @var string
     */
    protected $table = 'estabelecimentos_saude';

    /**
     * Attributes that should be mass-assignable.
     *
     * @var array
     */
    protected $fillable = [
        'nome',
        'sigla',
        'endereco',
        'bairro',
        'cep',
        'cnes',
        'cpf_cnpj',
        'estado_id',
        'municipio_id',
        'natureza_juridica_id',
        'tipo_id',
        'nome_diretor',
        'email_diretor',
        'telefone_diretor',
        'nome_responsavel_estagio',
        'email_responsavel_estagio',
        'telefone_responsavel_estagio',
        'email_alternativo_diretor',
        'telefone_alternativo_diretor',
        'email_alternativo_responsavel_estagio',
        'telefone_alternativo_responsavel_estagio'

    ];

    public function tipoEstabelecimentoSaude()
    {
        return $this->belongsTo('App\TipoEstabelecimentoSaude', 'tipo_id');
    }

    public function toArray() {
        $data = parent::toArray();

        if (isset($data['natureza_juridica_id'])) {
            if ($data['natureza_juridica_id'] == 1) {
                $data['natureza_juridica'] = 'Gestão Direta';
            } else {
                $data['natureza_juridica'] = 'Gestão Indireta';
            }
        }
        return $data;
    }
}
