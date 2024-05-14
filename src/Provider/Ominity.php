<?php

namespace Ominity\OAuth2\Client\Provider;

use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use Psr\Http\Message\ResponseInterface;

class Ominity extends AbstractProvider
{
    use BearerAuthorizationTrait;

    /**
     * Version of this client.
     */
    const CLIENT_VERSION = "2.8.0";

    /**
     * The base url to the Omniity API.
     *
     * @const string
     */
    const OMINITY_API_URL = 'https://api.ominity.com';

    /**
     * The base url to the Ominity web application.
     *
     * @const string
     */
    const OMINITY_WEB_URL = 'https://app.ominity.com';

    /**
     * @var string HTTP method used to revoke tokens.
     */
    const METHOD_DELETE = 'DELETE';

    /**
     * @var string Token type hint for Ominity access tokens.
     */
    const TOKEN_TYPE_ACCESS = 'access_token';

    /**
     * @var string Token type hint for Ominity refresh tokens.
     */
    const TOKEN_TYPE_REFRESH = 'refresh_token';

    /**
     * Shortcuts to the available Ominity scopes.
     *
     * In order to access the Ominity API endpoints on behalf of your user, your
     * app should request the appropriate scope permissions.
     */
    const SCOPE_ADMINS_READ  = 'admins.read';
    const SCOPE_ADMINS_WRITE  = 'admins.write';
    const SCOPE_USERS_READ  = 'users.read';
    const SCOPE_USERS_WRITE = 'users.write';
    const SCOPE_ME_READ = 'me.read';
    
    /**
     * @var string
     */
    private $ominityApiUrl = self::OMINITY_API_URL;

    /**
     * @var string
     */
    private $ominityWebUrl = self::OMINITY_WEB_URL;

    public function __construct(array $options = [], array $collaborators = [])
    {
        parent::__construct($options, $collaborators);

        if (!isset($options["clientId"])) {
            throw new \DomainException("Ominity requires the client ID for authentication requests.");
        }
    }

    /**
     * Define Ominity api URL
     *
     * @param string $url
     * @return Ominity
     */
    public function setApiUrl($url): self
    {
        $this->ominityApiUrl = $url;

        return $this;
    }

    /**
     * Define Ominity web URL
     *
     * @param string $url
     * @return Ominity
     */
    public function setWebUrl($url): self
    {
        $this->ominityWebUrl = $url;

        return $this;
    }

    /**
     * Returns the base URL for authorizing a client.
     *
     * Eg. https://oauth.service.com/authorize
     *
     * @return string
     */
    public function getBaseAuthorizationUrl(): string
    {
        return $this->ominityWebUrl . '/oauth2/authorize';
    }

    /**
     * Returns the base URL for requesting or revoking an access token.
     *
     * Eg. https://oauth.service.com/token
     *
     * @param array $params
     * @return string
     */
    public function getBaseAccessTokenUrl(array $params): string
    {
        return $this->ominityApiUrl . '/oauth2/tokens';
    }

    /**
     * Returns the URL for requesting the user's details.
     *
     * @param AccessToken $token
     * @return string
     */
    public function getResourceOwnerDetailsUrl(AccessToken $token): string
    {
        return static::OMINITY_API_URL . '/v1/me';
    }

    /**
     * Revoke a Ominity access token.
     *
     * @param string $accessToken
     *
     * @return \Psr\Http\Message\ResponseInterface
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function revokeAccessToken($accessToken): ResponseInterface
    {
        return $this->revokeToken(self::TOKEN_TYPE_ACCESS, $accessToken);
    }

    /**
     * Revoke a Ominity refresh token.
     *
     * @param string $refreshToken
     *
     * @return \Psr\Http\Message\ResponseInterface
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function revokeRefreshToken($refreshToken): ResponseInterface
    {
        return $this->revokeToken(self::TOKEN_TYPE_REFRESH, $refreshToken);
    }

    /**
     * Revoke a Ominty access token or refresh token.
     *
     * @param string $type
     * @param string $token
     *
     * @return \Psr\Http\Message\ResponseInterface
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function revokeToken($type, $token): ResponseInterface
    {
        return $this->getRevokeTokenResponse([
            'token_type_hint' => $type,
            'token' => $token,
        ]);
    }

    /**
     * Sends a token revocation request and returns an response instance.
     *
     * @param array $params
     *
     * @return \Psr\Http\Message\ResponseInterface
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    protected function getRevokeTokenResponse(array $params): ResponseInterface
    {
        $params['client_id'] = $this->clientId;
        $params['client_secret'] = $this->clientSecret;
        $params['redirect_uri'] = $this->redirectUri;

        $options = ['headers' => ['content-type' => 'application/x-www-form-urlencoded']];
        $options['body'] = $this->buildQueryString($params);

        $request = $this->getRequest(
            self::METHOD_DELETE,
            $this->getBaseAccessTokenUrl([]),
            $options
        );

        return $this->getHttpClient()->send($request);
    }

    /**
     * The Ominity OAuth provider requests access to the me.read scope
     * by default to enable retrieving the profile's details.
     *
     * @return string[]
     */
    protected function getDefaultScopes(): array
    {
        return [
            self::SCOPE_ME_READ,
        ];
    }

    /**
     * Returns the string that should be used to separate scopes when building
     * the URL for requesting an access token.
     *
     * @return string Scope separator, defaults to ','
     */
    protected function getScopeSeparator(): string
    {
        return ' ';
    }

    /**
     * Checks a provider response for errors.
     *
     * @throws IdentityProviderException
     * @param  ResponseInterface $response
     * @param  array|string      $data Parsed response data
     * @return void
     */
    protected function checkResponse(ResponseInterface $response, $data): void
    {
        if ($response->getStatusCode() < 400) {
            return;
        }

        if (!isset($data['error'])) {
            throw new IdentityProviderException($response->getReasonPhrase(), $response->getStatusCode(), $response);
        }

        if (isset($data['error']['type']) && isset($data['error']['message'])) {
            $message = sprintf('[%s] %s', $data['error']['type'], $data['error']['message']);
        } else {
            $message = $data['error'];
        }

        if (isset($data['error']['field'])) {
            $message .= sprintf(' (field: %s)', $data['error']['field']);
        }

        throw new IdentityProviderException($message, $response->getStatusCode(), $response);
    }

    /**
     * Generates a resource owner object from a successful resource owner
     * details request.
     *
     * @param  array       $response
     * @param  AccessToken $token
     * @return OminityResourceOwner
     */
    protected function createResourceOwner(array $response, AccessToken $token): OminityResourceOwner
    {
        return new OminityResourceOwner($response);
    }

    /**
     * Returns the default headers used by this provider.
     *
     * Typically this is used to set 'Accept' or 'Content-Type' headers.
     *
     * @return array
     */
    protected function getDefaultHeaders()
    {
        return [
            'User-Agent' => implode(' ', [
                "OminityOAuth2PHP/" . self::CLIENT_VERSION,
                "PHP/" . phpversion(),
            ])
        ];
    }
}
