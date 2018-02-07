<?php

namespace App;

use Illuminate\Database\Eloquent\Model;
use OwenIt\Auditing\Auditable;

use Carbon\Carbon;

class BaseModel extends Model
{
    use Auditable;

    protected $auditEnabled  = true;
    // Clear the oldest audits after 50 records.
    protected $auditLimit = 50;
    // Specify what actions you want to audit.
    protected $auditableTypes = ['created', 'updated', 'deleted', 'saved', 'restored'];
    // Fields that you do NOT want to audit.
    protected $dontKeepAuditOf = ['password'];

    protected $casts = [];

    protected $dateFormat = "Y-m-d H:i:s";

    protected $dontFilterAttributesInDinamicQuery = ['password'];

    protected function addCast($moreAttributes = [])
    {
        $this->casts = array_merge($this->casts, $moreAttributes);
    }

    public function setAttribute($key, $value)
    {
        if (in_array($key, $this->dates) && is_string($value)) {
            $this->attributes[$key] = \Prodeb::parseDate($value);
        } else {
            parent::setAttribute($key, $value);
        }
    }

    public function getDontFilterAttributesInDinamicQuery()
    {
        return $this->dontFilterAttributesInDinamicQuery;
    }
}
