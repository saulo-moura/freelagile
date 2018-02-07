<?php

/*
 * This file is part of laravel-auditing.
 *
 * @author Antério Vieira <anteriovieira@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

return [

    // Authentication Model
    'model' => App\User::class,

    // Database Connection
    'connection' => null,

    // Table Name
    'table' => 'audits',

    'queue' => false,

    // Whether we should audit queries run through console (eg. php artisan db:seed).
    'audit_console' => true,

    // Default auditor
    'default_auditor' => 'database',
];
