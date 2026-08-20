<?php

declare(strict_types=1);

namespace AdGo\Cluster\Controllers;

use AdGo\Cluster\Cluster;
use AdGo\Cluster\SsoTicketStore;
use CodeIgniter\Controller;
use CodeIgniter\HTTP\ResponseInterface;
use CodeIgniter\Shield\Models\UserModel;
use Throwable;

/**
 * Real cross-node SSO: a user already logged in on one node can land on
 * another node already logged in too, via a short-lived single-use ticket
 * handed off through a plain browser redirect - no shared cookies
 * (impossible across different domains, which is what every node in this
 * cluster is) and no shared session storage, just a server-to-server
 * confirmation over the same Bearer channel every other cluster/* route
 * already uses.
 *
 * Deliberately does NOT depend on account sync (not built yet - see this
 * package's README, "Not built yet"): a ticket only ever proves an EMAIL,
 * it never creates an account. If the target node has no local Shield
 * user for that email, the handoff fails gracefully back to that node's
 * own login page - this only actually completes end-to-end for an email
 * that already has a matching account on both nodes (today: just the
 * superadmin every node's own install bootstraps identically - see
 * CI4install.php's installSuperadminHere() - until DB sync exists).
 */
class SsoController extends Controller
{
    /**
     * Session-filtered (see this package's README) - only a user already
     * logged in HERE can request a handoff, since the ticket this issues
     * only ever proves whatever email THIS request is authenticated as.
     */
    public function start(): ResponseInterface
    {
        $user = auth()->user();
        if ($user === null) {
            return redirect()->to('/login');
        }

        $cluster = new Cluster();
        $node    = $cluster->node((string) $this->request->getGet('node'));
        if ($node === null) {
            return $this->response->setStatusCode(400)->setJSON(['error' => 'unknown node']);
        }

        $identity = $user->getEmailIdentity();
        $email    = $identity?->secret ?? '';
        if ($email === '') {
            return $this->response->setStatusCode(400)->setJSON(['error' => 'no email identity']);
        }

        // Self-supplied by this request (the "Switch server" link builds it
        // from the page it's clicked on - see cluster-ui's Layout/app.php),
        // not peer-supplied - the worst a user could do tampering with
        // their OWN request is pick a weird landing page for themselves.
        // Still validated (not just passed through) since it becomes a
        // same-node redirect target on the far end - see
        // safeReturnPath()'s own docblock.
        $returnPath = $this->safeReturnPath((string) $this->request->getGet('return'));
        $ticket     = (new SsoTicketStore())->issue($email, $returnPath);

        $target = rtrim($node['baseURL'], '/') . '/cluster/sso/consume'
            . '?ticket=' . urlencode($ticket)
            . '&from=' . urlencode($cluster->thisNodeName());

        return redirect()->to($target);
    }

    /**
     * NOT session-filtered - this is how a user arrives WITHOUT a local
     * session yet. Trust comes entirely from the live server-to-server
     * verify() call below, never from the query string alone: 'ticket' is
     * opaque and 'from' is only ever resolved against this node's OWN
     * cluster.nodes registry (never treated as a raw URL), the same
     * pattern every other peer-supplied identifier in this package
     * follows (see Cluster::resolveIncomingPath()'s own reasoning).
     */
    public function consume(): ResponseInterface
    {
        $ticket = (string) $this->request->getGet('ticket');
        $cluster = new Cluster();
        $node    = $cluster->node((string) $this->request->getGet('from'));

        if ($ticket === '' || $node === null) {
            return redirect()->to('/login')->with('error', $this->handoffFailedMessage());
        }

        try {
            $client   = service('curlrequest', ['baseURI' => $node['baseURL'], 'timeout' => 10], null, null, false);
            $response = $client->post('cluster/sso/verify', [
                'headers'     => ['Authorization' => $cluster->authHeader()],
                'form_params' => ['ticket' => $ticket],
            ]);
            $body = $response->getStatusCode() === 200 ? json_decode($response->getBody(), true) : null;
        } catch (Throwable $e) {
            return redirect()->to('/login')->with('error', $this->handoffFailedMessage());
        }

        $email = is_array($body) && ($body['ok'] ?? false) ? (string) ($body['email'] ?? '') : '';
        if ($email === '') {
            return redirect()->to('/login')->with('error', $this->handoffFailedMessage());
        }
        // Read back from the verified response, not the query string -
        // same trust boundary as $email itself (see this method's own
        // docblock on why 'from'/'ticket' alone are never enough).
        // Re-validated anyway (defense in depth - this ends up an actual
        // redirect target) rather than assuming the issuing node already
        // did it correctly.
        $returnPath = $this->safeReturnPath((string) ($body['return'] ?? '/'));

        $localUser = model(UserModel::class)->findByCredentials(['email' => $email]);
        if ($localUser === null) {
            // The "no account sync yet" case - expected, not an error,
            // until DB sync exists (see this package's README).
            return redirect()->to('/login')->with('error', $this->handoffFailedMessage());
        }

        // startLogin() throws if this session already has a logged-in
        // user - a stale/different local session on this node must never
        // block the handoff.
        if (auth()->loggedIn()) {
            auth()->logout();
        }
        auth()->login($localUser);

        return redirect()->to($returnPath);
    }

    /**
     * Peer-to-peer only (cluster-auth filter, same Bearer as every other
     * cluster/* route) - redeems a ticket THIS node issued and returns
     * the email it was issued for. Single-use: SsoTicketStore::consume()
     * deletes it from the store the moment it's read, so replaying the
     * same ticket a second time always answers {ok: false}.
     */
    public function verify(): ResponseInterface
    {
        $ticket = (string) $this->request->getPost('ticket');
        if ($ticket === '') {
            return $this->response->setJSON(['ok' => false]);
        }

        $redeemed = (new SsoTicketStore())->consume($ticket);

        return $redeemed !== null
            ? $this->response->setJSON(['ok' => true, 'email' => $redeemed['email'], 'return' => $redeemed['returnPath']])
            : $this->response->setJSON(['ok' => false]);
    }

    // Not a lang() call - this package ships no Language files of its own
    // (see this package's README - it's the mechanism layer, cluster-ui
    // owns human-facing text). One plain string is simpler than adding a
    // whole Language infrastructure for a single flash message.
    private function handoffFailedMessage(): string
    {
        return 'Single sign-on failed or expired - please log in.';
    }

    // A same-node-relative path only: must start with exactly one '/' -
    // '//evil.com/x' (protocol-relative) and 'https://evil.com/x' (a full
    // URL) both fail this and fall back to '/', since either would send
    // the browser to a different host entirely after a successful login,
    // the definition of an open redirect. No query string/fragment
    // stripped - those are harmless once the host itself is pinned down.
    private function safeReturnPath(string $path): string
    {
        if ($path === '' || $path[0] !== '/' || str_starts_with($path, '//') || str_contains($path, '://')) {
            return '/';
        }

        return $path;
    }
}
