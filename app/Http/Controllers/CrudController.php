<?php
/**
 * CrudController is a shared base controller that provides a CRUD basis for Laravel applications.
 *
 * @author Jamie Rumbelow <jamie@jamierumbelow.net>
 * @license http://opensource.org/licenses/MIT
 */

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Database\Eloquent\Model;

use App\Http\Requests;
use App\Http\Controllers\Controller;

use App\Http\Traits\Callbacks;
use App\Http\Traits\Actions;

abstract class CrudController extends Controller
{
    use Callbacks, Actions;

    /**
     * Get the model class.
     *
     * @return string
     */
    abstract protected function getModel();

    /**
     * Get the model class.
     *
     * @return string
     */
    abstract protected function getValidationRules(Request $request, Model $obj);
}
