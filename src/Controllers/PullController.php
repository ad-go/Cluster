<?php

declare(strict_types=1);

namespace AdGo\Cluster\Controllers;

use AdGo\Cluster\Cluster;
use AdGo\Cluster\DeletedFiles;
use AdGo\Cluster\SessionInvalidation;
use CodeIgniter\Controller;
use CodeIgniter\HTTP\ResponseInterface;

/**
 * Server side of cluster:pull (see AdGo\Cluster\Commands\PullCommand) - a
 * peer connects OUT to these three GET endpoints to catch up on
 * invalidations/files it may have missed, rather than waiting to be pushed
 * to. This is what closes the 'nat' gap the push-only mechanism always
 * had (a 'nat' node can push OUT fine, but nothing can push files/
 * invalidations IN to it - see this package's README "Not built yet"
 * before this command existed): a 'nat' node still can't be pushed to, but
 * it CAN pull, since pulling is a connection it initiates outbound itself.
 *
 * Auth is the ClusterAuthFilter (Bearer token), not Shield - this is
 * node-to-node traffic, never a logged-in user's browser request. GET
 * requests are exempt from CSRF by CodeIgniter's own Security::verify()
 * (only POST/PUT/DELETE/PATCH are checked), so unlike cluster/files and
 * cluster/invalidate, these routes need no CSRF except-list entry at all.
 */
class PullController extends Controller
{
    /**
     * @return ResponseInterface {"invalidations": {"email@x.com": 1723900000, ...}}
     */
    public function invalidations(): ResponseInterface
    {
        // 503, matching InvalidationController's own reasoning: a caller
        // (PullCommand) already treats a non-2xx as this peer failing,
        // not "nothing new" - a disabled node reads as temporarily
        // unavailable for this concern, not as having an empty dataset.
        if (! config('Cluster')->sessionSyncEnabled) {
            return $this->response->setStatusCode(503)->setJSON(['error' => 'session sync disabled on this node']);
        }

        $since = (int) $this->request->getGet('since');

        return $this->response->setJSON([
            'invalidations' => (new SessionInvalidation())->allSince($since),
        ]);
    }

    /**
     * @return ResponseInterface {"files": {"share/foo.txt": {"hash": "...", "mtime": 123, "size": 456}, ...}}
     */
    public function files(): ResponseInterface
    {
        if (! config('Cluster')->fileSyncEnabled) {
            return $this->response->setStatusCode(503)->setJSON(['error' => 'file sync disabled on this node']);
        }

        $since = (int) $this->request->getGet('since');

        return $this->response->setJSON([
            'files' => (new Cluster())->manifestSince($since),
        ]);
    }

    /**
     * @return ResponseInterface {"deletions": {"share/foo.txt": 1723900000, ...}}
     */
    public function deletedFiles(): ResponseInterface
    {
        if (! config('Cluster')->fileSyncEnabled) {
            return $this->response->setStatusCode(503)->setJSON(['error' => 'file sync disabled on this node']);
        }

        $since = (int) $this->request->getGet('since');

        return $this->response->setJSON([
            'deletions' => (new DeletedFiles())->allSince($since),
        ]);
    }

    /**
     * Streams one file's bytes back to the puller, alongside its real
     * mtime/hash as headers - PullCommand touches the local copy to
     * X-Cluster-Mtime and verifies X-Cluster-Hash the exact same way
     * PushFileJob's multipart fields already let FileReceiverController
     * do on the push side.
     */
    public function file(): ResponseInterface
    {
        if (! config('Cluster')->fileSyncEnabled) {
            return $this->response->setStatusCode(503)->setJSON(['error' => 'file sync disabled on this node']);
        }

        $relative  = (string) $this->request->getGet('path');
        $localPath = (new Cluster())->resolveExistingSyncPath($relative);
        if ($localPath === null) {
            return $this->response->setStatusCode(404)->setJSON(['error' => 'not found']);
        }

        $mtime = (string) filemtime($localPath);
        $hash  = (string) md5_file($localPath);

        // download() builds a FRESH DownloadResponse internally - headers
        // set on $this->response beforehand would be silently dropped, so
        // they're set on the object it actually returns instead.
        return $this->response->download($localPath, null)
            ->setHeader('X-Cluster-Mtime', $mtime)
            ->setHeader('X-Cluster-Hash', $hash);
    }
}
