<?php

declare(strict_types=1);

namespace AdGo\Cluster\Controllers;

use CodeIgniter\Controller;
use CodeIgniter\HTTP\ResponseInterface;

/**
 * Server side of clock-drift measurement (Cristian's algorithm) - see
 * AdGo\Cluster\Commands\TimeDriftCommand's own docblock for the client-
 * side math this feeds into. Just echoes this node's current time back;
 * the caller does all the actual estimation using its own before/after
 * timestamps around this one request.
 */
class TimeController extends Controller
{
    public function now(): ResponseInterface
    {
        return $this->response->setJSON(['time' => microtime(true)]);
    }
}
