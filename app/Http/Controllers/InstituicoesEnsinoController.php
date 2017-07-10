<?php

namespace App\Http\Controllers;

use App\InstituicaoEnsino;

use Log;

use Illuminate\Http\Request;

use App\Http\Requests;
use App\Http\Controllers\CrudController;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Input;
use App\Exceptions\BusinessException;
use Storage;

class InstituicoesEnsinoController extends CrudController
{
    public function __construct()
    {
    }

    protected function getModel()
    {
        return InstituicaoEnsino::class;
    }

    protected function applyFilters(Request $request, $query)
    {
         $query = $query->with('municipio');

        if ($request->has('instituicao_ensino_id')) {
            $query = $query->where('id', '=', $request->instituicao_ensino_id);
        }

        if ($request->has('nome')) {
            $query = $query->where('nome', 'ilike', '%'.$request->nome.'%');
        }

        if ($request->has('razao_social')) {
            $query = $query->where('razao_social', 'ilike', '%'.$request->razao_social.'%');
        }

        if ($request->has('cnpj_mantenedora')) {
            $query = $query->where('cnpj_mantenedora', '=', $request->cnpj_mantenedora);
        }

        if ($request->has('nome_reitor')) {
            $query = $query->where('nome_reitor', 'ilike', '%'.$request->nome_reitor.'%');
        }
        
        if ($request->has('municipio_id')) {
            $query = $query->where('municipio_id', '=', $request->municipio_id);
        }
    }

    protected function beforeSearch(Request $request, $dataQuery, $countQuery)
    {
        $dataQuery->orderBy('nome', 'asc');
    }

    protected function beforeSave(Request $request, Model $model)
    {
        if ($model->id) {
            $model->validado = 1;
        }
    }

    protected function getValidationRules(Request $request, Model $obj)
    {
        $rules = [
            'nome' => 'required',
            'sigla' => 'required'
        ];
        return $rules;
    }

    public function uploadArquivos(Request $request, $id)
    {
        if ($request->hasFile('arquivo')) {
            
            $extensions = ['doc', 'pdf'];
            
            $arquivo = $request->file('arquivo');
            if(!in_array($arquivo->getClientOriginalExtension(), $extensions)){
                throw new BusinessException('Apenas arquivos .doc e .pdf são permitidos.');
            }            
            $model = \App\InstituicaoEnsino::find($id);
            
            $caminho = 'instituicoes/' . $id;
            $nomeArquivo = $model->sigla . '_' . $request->tipoArquivo . '.' . $arquivo->getClientOriginalExtension();
            
            switch ($request->tipoArquivo) {
                case 'diario_oficial_uniao':
                    if ($model->diario_oficial_uniao) {
                        $this->removeArquivoIES($model->diario_oficial_uniao, $id);
                    }
                    $arquivo->storeAs($caminho, $nomeArquivo);
                    $model->diario_oficial_uniao = $nomeArquivo;
                    break;
                case 'alvara_funcionamento':
                    if ($model->alvara_funcionamento) {
                        $this->removeArquivoIES($model->alvara_funcionamento, $id);
                    }
                    $arquivo->storeAs($caminho, $nomeArquivo);
                    $model->alvara_funcionamento = $nomeArquivo;
                    break;
                case 'atestado_funcionamento_regular':
                    if ($model->atestado_funcionamento_regular) {
                        $this->removeArquivoIES($model->atestado_funcionamento_regular, $id);
                    }
                    $arquivo->storeAs($caminho, $nomeArquivo);
                    $model->atestado_funcionamento_regular = $nomeArquivo;
                    break;
            }
            $model->save();
            return [
                'success' => true,
                'nomeArquivo' => $nomeArquivo
            ];
        }
    }

    public function excluirArquivos(Request $request, $id)
    {
        if ($request->tipoArquivo) {
            $model = \App\InstituicaoEnsino::find($id);
            
            switch ($request->tipoArquivo) {
                case 'diario_oficial_uniao':
                    $this->removeArquivoIES($model->diario_oficial_uniao, $id);
                    $model->diario_oficial_uniao = null;
                    break;
                case 'alvara_funcionamento':
                    $this->removeArquivoIES($model->alvara_funcionamento, $id);
                    $model->alvara_funcionamento = null;
                    break;
                case 'atestado_funcionamento_regular':
                    $this->removeArquivoIES($model->atestado_funcionamento_regular, $id);
                    $model->atestado_funcionamento_regular = null;
                    break;
            }
            $model->save();
            return ['success' => true];
        }
    }

    protected function removeArquivoIES($nomeArquivo, $id)
    {
        $caminho = 'instituicoes/' . $id . '/';
        return Storage::delete($caminho . $nomeArquivo);
    }
}
