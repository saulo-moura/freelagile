<?php
/**
 * GenericService is a shared base service that provides out of the box request to models.
 *
 * @author Amon Caldas <amon.santana@prodeb.ba.gov.br>
 * @license http://opensource.org/licenses/MIT
 */

namespace App\Http\Traits;

use Illuminate\Http\Request;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Schema\Builder as SchemaBuilder;
use App\Exceptions\BusinessException;

/**
 * GenericService is the of the services provided by the applicatin.
 *
 * @internal
 * @used-by \App\Http\Controllers\DomainsController
 */
trait GenericService
{
    /**
     * Get the results for a given service request
     *
     * @param  \Illuminate\Http\Request $request
     * @param  Illuminate\Database\Eloquent\Builder $query
     * @throws BusinessException
     */
    public function getResults(Request $request, Builder $query){
        // Initialise defaults
        $take = 20; //the default page size (amount of items)
        $skip = $total = $itemsCount = 0; // the default offset (page), total of items (with no filters) and count of items (with filters)
        $items = []; // The initial collection of items returned is empty

        // Here we validate the filters to check if it has anyone invalid

        $this->validateFilters($request, $query);

        // If we do not have an invalid filter, we contine

        if($request->has('take')){
            $take = $request->input('take');
        }

        if($request->has('skip')){
            $skip = $request->input('skip');
        }

        // Here we add the filters comming from the request to the QueryBuilder.
        // $query is passed as reference (can me modified)
        $this->addFilters($request, $query);

        // Trys to get the results
        try{
            // get the data, using pagination
            $items =  $query->skip($skip)->take($take)->get();
            // get the total, not considering pagination
            $itemsCount =  $items->count();
            if($request->skipcount !== "true") {
                $total = $query->count();
            }
        }
        catch(\Exception $e){
            // if we had an error while executing the query, set the error message to be returned
            $error = $e->getMessage();
            $error .= ". ". $this->getEntityDesc($query);
            throw new BusinessException($error);
        }


        //we return an array with the values. In all cases we return this array
        return [
            'total'=>$total,
            'items_count'=>$itemsCount,
            'items'=>$items
        ];
    }

    /**
     * Add the filters comming from the request to the $query,
     * either from a collection (array of json object in url) either from a collection of three get parameters (prop;op;value)
     *
     * @param  \Illuminate\Http\Request $request
     * @param  Illuminate\Database\Eloquent\Builder $query
     */
    public function addFilters(Request $request, Builder &$query){
        //closure to prepare binding value
        //if the operator requires wrapers, we add them (like, ilike)
        $prepareBinding = function(&$filter, $query){
            if( in_array($filter->op, ['like','ilike'])){
                // whereRaw expects and array of parameters.
                // We only have one, so we put it in an array
                $filter->value = ['%'.strtolower($filter->value).'%'];

                // we set the whereRaw condition, but the left value (filter->value)
                // will be binded via parameter binding, replacing the ?
                $query = $query->whereRaw("lower($filter->prop) like ?");
            }
            else{
                $query = $query->where($filter->prop, $filter->op, '?');
            }
        };

        //closure to add where to query, applying the filters from the request
        //we add the filter and return the binding value (the parameter that will be passed to the db)
        $addFilter = function(&$filter) use (&$query, $prepareBinding){
            $prepareBinding($filter, $query);
            $bindings[] = $filter->value;
            return $bindings;
        };


        // here we get the filters from the rhttp://localhost:5000equest
        $filters = $this->getFilters($request);
        $bindings = [];
        foreach ($filters as $filter) {
            $bindings[] = $addFilter($filter);
        }
        //here we set the parameters array as bindings
        $query->setBindings($bindings);
    }

    /**
     * Validate the filters comming from the request.
     * It is used before adding the parameters to the $query
     * The validation compares the filters from the request with the table structure
     *
     * @param  \Illuminate\Http\Request $request
     * @param  Illuminate\Database\Eloquent\Builder $query
     * @throws BusinessException
     */
    public function validateFilters(Request $request, Builder $query){
        $error = null;// the default error string in null (no error)
        $filters = $this->getFilters($request);// get the filters

        // here we check if each filter prop exists as a column in the table
        // if not, we stop in the first fail http://localhost:5000and build a message telling that the filter is not valid
        // we also list the columns and data type of each colum that can be used as a filter

        $table = $query->getModel()->getTable(); // get the current QueryBuilder table name

        //$columns = \Schema::getColumnListing($table);
        $columns = $this->getSchema($query)->getColumnListing($table);

        // In some cases the schema does not return the columns list (sqlserver views, for example)
        // In these cases we can not validate the filters
        if(count($columns) > 0){
            foreach($filters as $filter) {
                if(!in_array($filter->prop,$columns)) {
                    $error = "Invalid property '$filter->prop' for entity $table. ";
                    $error .= $this->getEntityDesc($query);
                    break;
                }
            }
        }
        if(isset($error)){
            throw new BusinessException($error);
        }
    }

    /**
     * Get a text describing the entity properties and the type of each property
     * @param  Illuminate\Database\Eloquent\Builder $query
     * @param  string $prefix
     * @return string
     */
    function getEntityDesc(Builder $query, $prefix = null ){
        $desc = '';
        $prefix = isset($prefix)? $prefix : "The available properties are: ";
        $table = $query->getModel()->getTable(); // get the current QueryBuilder table name

        // Build a string with the table's <column-name> (datatype) list
        $columnsDesc = '';
        $schemaManager  =  $query->getConnection()->getDoctrineSchemaManager();
        $columns = $schemaManager->listTableColumns($table);

        // In some cases the schema does not return the columns list (sqlserver views, for example)
        // In these cases we can not validate the filters
        if(count($columns) > 0){
            foreach ($columns as $column) {
                $name = $column->getName();
                $type = $column->getType()->getName();
                if($columnsDesc != ''){
                    $columnsDesc .= ', ';
                }
                $columnsDesc .= "$name ($type)";
            }
        }

        $desc = $columnsDesc;
        // return the prefix and the columns description
        if($desc != ''){
            $desc = $prefix.' '.$desc;
        }
        else{
           $desc = 'It was not possible to retrive the entity properties' ;
        }
        return  $desc;
    }

    /**
     * Get the filter from the request
     * It is usedto extract the the collection of filters ffrom the request
     * It looks for two types of filters: a collection of filters as a json get parameter or a collection of three get parameters (prop;op;value)
     *
     * @param  \Illuminate\Http\Request $request
     * @return array $filters
     */
    public function getFilters(Request $request){
        $filters = [];
        $defaultOperator = "=";

        //handles a filter collection
        //example url: v1/domain/<resource>?filters=[{"prop":"cnes","op":"=","value":"4032136"}, {"prop":"cnes","op":"=","value":"4032136"}]
        if($request->has('filters')) {
            $filters = $request->input('filters');
            if(!is_object($filters)){
                $filters = json_decode(($filters));
                foreach ($filters as $filter) {
                    if(!isset($filter->op)){
                        $filter->op = $defaultOperator; // set default operator, if not set
                    }
                }
            }
        }
        //handles a unique filter parameters
        //example url: v1/domain/<resource>?prop=cnes&op==&value=4032136
        elseif($request->has('prop') && $request->has('value')) {
            $filter = new \stdClass();
            $filter->op = $defaultOperator; // default operator

            $filter->value = $request->input('value');
            $filter->prop = $request->input('prop');
            if($request->has('op') ){
                $filter->op = $request->input('op');// override the default operator, if available
            }

            $filters = array($filter);
        }
        return $filters;
    }

    /**
    * This route maps the request to the appropriated controller method
    * for example: /domain/health-units will be routed to the method DomainsController@healthUnits
    * @param request inject the request data
    * @param domainName the domain name that will be converted to a controller method
    **/
    public function getDomainData(Request $request, $domainName)
    {
        $domainMethod = camel_case($domainName);
        if(method_exists($this, $domainMethod)){
            return $this->$domainMethod($request);
        }
        else{
            abort(404, 'Resource not found.');
        }
    }

    /**
    * Get the db schema for the $query
    * @param QueryBuilder
    * @return Illuminate\Database\Schema\Builder $schemaBuilder
    **/
    public function getSchema($query){
        $conn = $query->getModel()->getConnection();
        $conn->getSchemaBuilder();
        $schemaBuilder = new SchemaBuilder($conn);
        return $schemaBuilder;
    }

}
