<?php

declare(strict_types=1);

namespace AdGo\Cluster\Filters;

use AdGo\Cluster\Cluster;
use CodeIgniter\Filters\FilterInterface;
use CodeIgniter\HTTP\RequestInterface;
use CodeIgniter\HTTP\ResponseInterface;

/**
 * Guards every cluster/* route - each request signed with the CALLING
 * node's own RSA private key and verified against that node's public key
 * (see Cluster::authHeader()/verifyAuthHeader(), Config\Cluster::
 * $signingPrivateKey's own docblock for the full reasoning), falling back
 * to a legacy shared bearer token only for a peer that hasn't been given a
 * keypair yet. Per the spec's own security note (section 5) that the
 * inter-node sync routes are a real attack surface distinct from Shield's
 * per-user JWT auth - a stolen user session should never be enough to
 * write files onto another node.
 *
 * Registered as an app-level filter alias (see this package's README) -
 * not auto-applied, same reasoning as ad-go/cluster-ui's own filters:
 * a package can't safely assume it owns the app's whole Filters.php.
 */
class ClusterAuthFilter implements FilterInterface
{
    public function before(RequestInterface $request, $arguments = null)
    {
        // Apache renames Authorization to REDIRECT_HTTP_AUTHORIZATION on
        // its internal mod_rewrite redirect to index.php unless the host's
        // config explicitly opts out (CGIPassAuth On, Apache 2.4.13+) -
        // found live 2026-08-18 on beta (cPanel/Apache): $request's own
        // header parsing came back empty even though curl was sending the
        // header correctly, because PHP's own $_SERVER['HTTP_AUTHORIZATION']
        // was equally empty at that point, only REDIRECT_HTTP_AUTHORIZATION
        // carried it. Checking both here - instead of requiring every
        // Apache host's .htaccess to be edited, which may not even be
        // allowed by AllowOverride on a given shared-hosting account -
        // means this works regardless of whether that server-level
        // workaround was also applied.
        $header = $request->getHeaderLine('Authorization');
        if ($header === '') {
            $header = (string) ($_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '');
        }

        if (! (new Cluster())->verifyAuthHeader($header)) {
            return service('response')
                ->setStatusCode(403)
                ->setJSON(['error' => 'Forbidden']);
        }

        return null;
    }

    public function after(RequestInterface $request, ResponseInterface $response, $arguments = null)
    {
        // Nothing to do after - the route handlers below set their own response.
    }
}
