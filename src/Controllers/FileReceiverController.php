<?php

declare(strict_types=1);

namespace AdGo\Cluster\Controllers;

use AdGo\Cluster\Cluster;
use AdGo\Cluster\SyncState;
use CodeIgniter\Controller;
use CodeIgniter\HTTP\ResponseInterface;

/**
 * Receives a pushed file from a peer (PushFileJob on the sending side).
 * Auth is the ClusterAuthFilter (Bearer token), not Shield - this is
 * node-to-node traffic, never a logged-in user's browser request. Excluded
 * from CSRF (see app/Config/Filters.php's csrf except list) - a
 * Bearer-token API has no session to forge.
 */
class FileReceiverController extends Controller
{
    public function receive(): ResponseInterface
    {
        // 503, not a silent 200 - a sender's PushFileJob treats any non-2xx
        // as a failure and retries on its own schedule (see BaseJob::
        // $tries/$retryAfter), so a temporarily-disabled node still ends up
        // with the file once cluster.fileSyncEnabled goes back to true,
        // instead of the push being silently dropped forever.
        if (! config('Cluster')->fileSyncEnabled) {
            return $this->response->setStatusCode(503)->setJSON(['error' => 'file sync disabled on this node']);
        }

        $cluster = new Cluster();

        $relativePath = (string) $this->request->getPost('path');
        $expectedHash = (string) $this->request->getPost('hash');
        $mtime        = (int) $this->request->getPost('mtime');
        $senderPeer   = (string) $this->request->getPost('peer');
        // Informational only - the sender (see Jobs\PushFileJob) is solely
        // responsible for drift correction on the push path. NEVER use
        // this to alter $mtime/detectConflict()/finalizeIncomingFile()
        // below - doing so would double-correct an already-corrected
        // value. Echoed back in the response purely so the sender's side
        // can confirm the receiver saw it as pre-corrected.
        $driftCorrected = $this->request->getPost('driftCorrected') === '1';

        $file = $this->request->getFile('file');
        if ($file === null || ! $file->isValid()) {
            return $this->response->setStatusCode(400)->setJSON(['error' => 'missing or invalid file upload']);
        }

        // Rejects "..", absolute paths, and anything resolving outside the
        // configured syncPaths - $relativePath is peer-supplied and must
        // never be trusted as-is (path traversal would let a compromised
        // peer write anywhere this PHP process can).
        $targetPath = $cluster->resolveIncomingPath($relativePath);
        if ($targetPath === null) {
            return $this->response->setStatusCode(400)->setJSON(['error' => 'path not allowed']);
        }

        // Computed from the actual uploaded bytes, not trusted from
        // $expectedHash - the same reasoning the post-move corruption
        // check below already applies, just earlier: a conflict decision
        // needs the real content, not a claim that could itself be
        // wrong/corrupted in transit.
        $incomingHash = (string) md5_file($file->getTempName());
        $resolution   = $cluster->detectConflict($relativePath, $targetPath, $incomingHash, $mtime);

        if ($resolution['conflict']) {
            // Archive the LOSER before anything overwrites it - whichever
            // side that is. See Cluster::detectConflict()'s own docblock
            // for the full LWW-by-mtime reasoning.
            $cluster->preserveConflictLoser(
                $relativePath,
                $resolution['incomingWins'] ? $targetPath : $file->getTempName(),
                $resolution['incomingWins'] ? 'local' : ($senderPeer !== '' ? $senderPeer : 'peer'),
                $resolution['incomingWins'] ? ($senderPeer !== '' ? $senderPeer : 'peer') : 'local'
            );
        }

        if (! $resolution['incomingWins']) {
            // Local wins - deliberately does NOT touch $targetPath or the
            // manifest. Leaving the manifest at its stale (pre-conflict)
            // value is what makes this self-correcting: this node's own
            // NEXT cluster:sync-files scan will see local's real hash no
            // longer matches the manifest and push the winning content
            // back out on its own, the same way any other local change
            // would be detected and propagated - no special-casing needed
            // here beyond just not recording this incoming write as
            // "known".
            return $this->response->setJSON([
                'ok'       => true,
                'conflict' => true,
                'winner'   => 'local',
                'path'     => $relativePath,
            ]);
        }

        try {
            $moved = $file->move(dirname($targetPath), basename($targetPath), true);
        } catch (\Throwable $e) {
            return $this->response->setStatusCode(500)->setJSON(['error' => 'move failed: ' . $e->getMessage()]);
        }
        if (! $moved) {
            return $this->response->setStatusCode(500)->setJSON(['error' => 'could not save file']);
        }

        // Sets mtime to match the sender's claim, then records the actual
        // on-disk hash/size as "known" - this is what prevents a re-push
        // storm: without it, this node's OWN next scan would see the
        // just-written file as "new" (not yet in its manifest) and
        // immediately queue it right back out to every peer, including
        // the one that just sent it. Shared with cluster:pull's own
        // download path - see Cluster::finalizeIncomingFile()'s docblock.
        $result     = $cluster->finalizeIncomingFile($relativePath, $targetPath, $mtime);
        $actualHash = $result['hash'];

        // Only recorded when the claimed sender is a node THIS receiver
        // actually has configured - stops a typo/garbage 'peer' value from
        // polluting the Dashboard's connections list. Not an authentication
        // check (see SyncState's docblock): the shared Bearer secret alone
        // can't prove which configured peer is calling.
        if ($senderPeer !== '' && $cluster->node($senderPeer) !== null) {
            (new SyncState())->recordIncoming($senderPeer, $relativePath);
        }

        if ($expectedHash !== '' && ! hash_equals($expectedHash, $actualHash)) {
            // Written, but corrupted in transit. The manifest now reflects
            // what actually landed on disk (not the sender's claim), so
            // the sender's OWN next scan will see this path's hash as
            // stale on ITS side too... no - the sender compares against
            // ITS OWN manifest, not this node's. Surfacing a 422 here is
            // what actually needs to trigger a retry: the queue job (see
            // PushFileJob) treats a non-2xx response as a failure, which
            // codeigniter4/queue retries on its own schedule.
            return $this->response->setStatusCode(422)->setJSON([
                'error'    => 'hash mismatch',
                'expected' => $expectedHash,
                'actual'   => $actualHash,
            ]);
        }

        return $this->response->setJSON([
            'ok'             => true,
            'path'           => $relativePath,
            'hash'           => $actualHash,
            'conflict'       => $resolution['conflict'],
            'driftCorrected' => $driftCorrected,
        ]);
    }

    /**
     * Receives a "this path was deleted" tombstone from a peer
     * (Jobs\DeleteFileJob on the sending side) - the delete-side
     * counterpart to receive() above, same auth/CSRF treatment.
     */
    public function deleteFile(): ResponseInterface
    {
        if (! config('Cluster')->fileSyncEnabled) {
            return $this->response->setStatusCode(503)->setJSON(['error' => 'file sync disabled on this node']);
        }

        $cluster       = new Cluster();
        $relativePath  = (string) $this->request->getPost('path');
        $deletedAt     = (int) $this->request->getPost('deletedAt');
        $senderPeer    = (string) $this->request->getPost('peer');

        $result = $cluster->applyIncomingDeletion($relativePath, $deletedAt);

        // A genuinely bad path (traversal, outside syncDirs) is a real
        // error worth surfacing as non-2xx, same as receive()'s own 400 for
        // the same case - it should never just look like a normal delivery
        // to the sending job. "local is newer" is the expected/valid
        // rejection outcome instead (mirrors receive()'s own "local wins"
        // conflict case, which is also a 200) - not an error, just this
        // node choosing not to apply a stale tombstone.
        if ($result['reason'] === 'path not allowed') {
            return $this->response->setStatusCode(400)->setJSON(['error' => 'path not allowed']);
        }

        // Same "self-reported, validated against the registry" convention
        // as receive() above - see SyncState's own docblock on why this is
        // a Dashboard label, not an authenticated identity.
        if ($senderPeer !== '' && $cluster->node($senderPeer) !== null) {
            (new SyncState())->recordIncoming($senderPeer, $relativePath);
        }

        return $this->response->setJSON([
            'ok'      => true,
            'path'    => $relativePath,
            'applied' => $result['applied'],
            'reason'  => $result['reason'],
        ]);
    }
}
