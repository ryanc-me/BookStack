<?php

namespace BookStack\Auth\Access\Guards;

use BookStack\Exceptions\AuthProxyException;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\IpUtils;
use BookStack\Auth\User;


class AuthProxyGuard implements Guard
{

    use GuardHelpers;

    /**
     * The request instance.
     */
    protected $request;

    /**
     * Auth proxy configuration options
     *
     * @var array
     */
    protected $config;

    /**
     * Either null, or a list of CDIR blocks describing
     * IP addresses that are allowed to authenticate
     * via header.
     *
     * @var array
     */
    protected $whitelist;

    /**
     * AuthProxyGuard constructor.
     */
    public function __construct(Request $request)
    {
        // The the auth-proxy technique works in a similar way to API
        // authorization via the `Authentication` header, except with
        // a different header, and fewer checks. Most of the API/Token
        // auth code can be re-used here.

        // Grab the auth proxy config
        $this->config = config('services.auth_proxy');

        //TODO: Ensure whitelist is valid. Ideally, we should check this
        // at app start time.
        $whitelist = $this->config['whitelist'];
        if (!is_null($whitelist)) {
            $this->whitelist = explode(',', $whitelist);
        }

        $this->request = $request;
    }
    
    /**
     * @inheritDoc
     */
    public function user()
    {
        // Return the user if we've already retrieved them.
        // Effectively a request-instance cache for this method.
        if (!is_null($this->user)) {
            return $this->user;
        }

        $user = null;
        try {
            $user = $this->getAuthorisedUserFromRequest();
        } catch (AuthProxyException $exception) {
            $this->lastAuthException = $exception;
        }

        $this->user = $user;
        return $user;
    }

    /**
     * Determine if current user is authenticated. If not, throw an exception.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable
     *
     * @throws ApiAuthException
     */
    public function authenticate()
    {
        if (! is_null($user = $this->user())) {
            return $user;
        }

        if ($this->lastAuthException) {
            throw $this->lastAuthException;
        }

        throw new AuthProxyException('Unauthorized', 401);
    }

    /**
     * Check the API token in the request and fetch a valid authorised user.
     * @throws ApiAuthException
     */
    protected function getAuthorisedUserFromRequest(): Authenticatable
    {
        if (!is_null($this->whitelist)) {
            // Ensure the requests' source IP matches one of the allowed CDIRs
            // from the whitelist option. Note that `REMOTE_ADDR` is checked,
            // rather than the `X-Forwarded-For` header. REMOTE_ADDR should
            // contain the upstream auth proxy's address, which is what we want
            // to filter on.

            $sourceIp = $this->request->server->get('REMOTE_ADDR');
            $matched = IpUtils::checkIp($sourceIp, $this->whitelist);

            if (!$matched) {
                throw new AuthProxyException('Invalid source IP', 403);
            }
        }

        $authHeader = $this->config['header_name'];
        $authProperty = $this->config['header_property'];

        $headerValue = trim($this->request->headers->get($authHeader, ''));

        if (is_null($headerValue)) {
            if ($this->config['allow_guest']) {
                //TODO: Login as guest
            }
            else {
                //TODO: return an authentication exception here (401?)
                throw new AuthProxyException('Unauthorized', 403);
            }
        }

        $user = $this->getUserFromProperty($authProperty, $headerValue);

        return $user;
    }

    protected function getUserFromProperty(string $property, string $email): Authenticatable
    {
        //TODO: How safe is it to query on arbitrary columns like this?
        $user = User::where($property, $email)->first();

        if (!is_null($user)) {
            //TODO: Will `is_null` work here? Possibly returns empty record (like Odoo)

            return $user;
        }
        else {
            //TODO: Throw access error
            throw new AuthProxyException('Unauthorized', 403);
        }
    }

    protected function getGuestUser(): Authenticatable
    {
        //TODO: Check
    }

    public function validate(array $credentials = [])
    {
        //TODO: Proper checks here...
        return true;
    }

    public function logout()
    {
        $this->user = null;
    }

    public function logoutRedirect()
    {
        $logoutUrl = $this->config['logout_url'];

        if (!is_null($logoutUrl)) {
            return redirect()->to($logoutUrl);
        }
    }
}