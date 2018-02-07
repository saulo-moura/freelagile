<?php

namespace App\Http\Controllers;

use App\Comment;

use Log;

use Illuminate\Http\Request;

use App\Http\Requests;
use App\Http\Controllers\CrudController;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Input;


class CommentsController extends CrudController {

    protected function getModel() {
        return Comment::class;
    }

    protected function applyFilters(Request $request, $query) {
        /*
         * Se houver relacionamentos e caso queira incluir nos filtros
         * descomente a linha abaixo e informe o relacionamento
         * $query = $query->with('{modelRelacionado}');
         */

        /*
         * O bloco de código abaixo serve para verificar se o campo para filtragem está sendo passando
         * no request caso seja é inserido na query de de pesquisa.
         *if($request->has('{attribute}')) {
         *   $query = $query->where('{attribute}', 'like', '%'.$request->{attribute}.'%');
         *}
         */
    }

    protected function beforeSearch(Request $request, $dataQuery, $countQuery) {
        $dataQuery->orderBy('created_at', 'asc');
    }

    protected function getValidationRules(Request $request, Model $obj)
    {
        /*
         * O bloco de código abaixo aplica as regras de validação dos campos
         * na requisição
         *$rules = [
         *  '{attribute}' => 'required|max:100',
         *];
         *
         *return $rules;
         */
    }

    public function saveTaskComment(Request $request) {
        $comment = new \App\Comment;
        $comment->description = $request->comment_text;
        $comment->task_id = $request->task_id;
        $comment->user_id = \Auth::user()->id;
        $comment->comment_id = $request->comment_id ? $request->comment_id : null;
        $comment->save();
        $this->saveAction($request->project_id, 'Update', config('utils.dashboard.addComment'));
        return $comment;
    }

    public function removeTaskComment(Request $request) {
        $replies = \App\Comment::where('comment_id', $request->comment_id)->delete();
        return \App\Comment::destroy($request->comment_id);
    }
}
