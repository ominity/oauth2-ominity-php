<?php

namespace Ominity\OAuth2\Client\Test\Provider;

use GuzzleHttp\ClientInterface;
use GuzzleHttp\Psr7\Utils;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use Mockery as m;
use Ominity\OAuth2\Client\Provider\Ominity;
use Ominity\OAuth2\Client\Provider\OminityResourceOwner;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;

class OminityTest extends TestCase
{
    const MOCK_CLIENT_ID = 'mock_client_id';
    const MOCK_SECRET = 'mock_secret';
    const REDIRECT_URI = 'none';

    const OPTIONS = [
        'clientId' => self::MOCK_CLIENT_ID,
        'clientSecret' => self::MOCK_SECRET,
        'redirectUri' => self::REDIRECT_URI,
    ];

    protected $provider;

    protected function setUp(): void
    {
        $this->provider = new Ominity(self::OPTIONS);
    }

    public function tearDown(): void
    {
        m::close();
        parent::tearDown();
    }

    public function testClientIdShouldThrowExceptionWhenNotPrefixed()
    {
        $this->expectException(\DomainException::class);
        $this->expectExceptionMessage("Ominity requires the client ID for authentication requests.");

        new Ominity([
            'clientSecret' => 'mock_secret',
            'redirectUri'  => 'none',
        ]);
    }

    public function testGetBaseAccessTokenUrl()
    {
        $params = [];

        $url = $this->provider->getBaseAccessTokenUrl($params);

        $this->assertEquals('https://api.ominity.com/oauth2/tokens', $url);
    }

    public function testAuthorizationUrl()
    {
        $authUrl = $this->provider->getAuthorizationUrl();

        list($url, $queryString) = explode('?', $authUrl);
        parse_str($queryString, $query);

        $this->assertEquals('https://app.ominity.com/oauth2/authorize', $url);
        $this->assertEquals([
            'state' => $this->provider->getState(),
            'client_id' => self::MOCK_CLIENT_ID,
            'redirect_uri' => self::REDIRECT_URI,
            'scope' => 'me.read',
            'response_type' => 'code',
            'approval_prompt' => 'auto',
        ], $query);
        $this->assertMatchesRegularExpression('/^[a-f0-9]{32}$/i', $this->provider->getState());
    }

    public function testResourceOwnerDetailsUrl()
    {
        $token = m::mock(AccessToken::class);

        $url = $this->provider->getResourceOwnerDetailsUrl($token);

        $this->assertEquals('https://api.ominity.com/v1/me', $url);
    }

    public function testGetAccessToken()
    {
        $response = m::mock(ResponseInterface::class);
        $response->shouldReceive('getBody')->andReturn(Utils::streamFor('{"access_token":"mock_access_token", "token_type":"bearer"}'));
        $response->shouldReceive('getHeader')->andReturn(['content-type' => 'json']);
        $response->shouldReceive('getStatusCode')->andReturn(200);

        $client = m::mock(ClientInterface::class);
        $client->shouldReceive('send')->times(1)->andReturn($response);

        $this->provider->setHttpClient($client);

        $token = $this->provider->getAccessToken('authorization_code', ['code' => 'mock_authorization_code']);

        $this->assertEquals('mock_access_token', $token->getToken());
        $this->assertNull($token->getExpires());
        $this->assertNull($token->getRefreshToken());
        $this->assertNull($token->getResourceOwnerId());
    }

    public function testRevokeToken()
    {
        $response = m::mock(ResponseInterface::class);
        $response->shouldReceive('getBody')->andReturn('{"client_id":' . self::MOCK_CLIENT_ID . ', "client_secret":' . self::MOCK_SECRET . ', "redirect_uri":' . self::REDIRECT_URI . ', "token_type_hint":"access_token":"mock_access_token"}');
        $response->shouldReceive('getHeader')->andReturn(['content-type' => 'application/x-www-form-urlencoded']);
        $response->shouldReceive('getStatusCode')->andReturn(204);

        $client = m::mock(ClientInterface::class);
        $client->shouldReceive('send')->times(1)->andReturn($response);

        $this->provider->setHttpClient($client);

        $result = $this->provider->revokeAccessToken('mock_access_token');

        $this->assertEquals($result->getStatusCode(), 204);
    }

    public function testRevokeAccessToken()
    {
        $response = m::mock(ResponseInterface::class);
        $response->shouldReceive('getBody')->andReturn('{"client_id":' . self::MOCK_CLIENT_ID . ', "client_secret":' . self::MOCK_SECRET . ', "redirect_uri":' . self::REDIRECT_URI . ', "token_type_hint":"access_token":"mock_access_token"}');
        $response->shouldReceive('getHeader')->andReturn(['content-type' => 'application/x-www-form-urlencoded']);
        $response->shouldReceive('getStatusCode')->andReturn(204);

        $client = m::mock(ClientInterface::class);
        $client->shouldReceive('send')->times(1)->andReturn($response);

        $this->provider->setHttpClient($client);

        $result = $this->provider->revokeAccessToken('mock_access_token');

        $this->assertEquals($result->getStatusCode(), 204);
    }

    public function testRevokeRefreshToken()
    {
        $response = m::mock(ResponseInterface::class);
        $response->shouldReceive('getBody')->andReturn('{"client_id":' . self::MOCK_CLIENT_ID . ', "client_secret":' . self::MOCK_SECRET . ', "redirect_uri":' . self::REDIRECT_URI . ', "token_type_hint":"refresh_token":"mock_refresh_token"}');
        $response->shouldReceive('getHeader')->andReturn(['content-type' => 'application/x-www-form-urlencoded']);
        $response->shouldReceive('getStatusCode')->andReturn(204);

        $client = m::mock(ClientInterface::class);
        $client->shouldReceive('send')->times(1)->andReturn($response);

        $this->provider->setHttpClient($client);

        $result = $this->provider->revokeRefreshToken('mock_refresh_token');

        $this->assertEquals($result->getStatusCode(), 204);
    }

    public function testExceptionThrownWhenErrorObjectReceived()
    {
        $message = uniqid();
        $status = rand(400, 600);

        $postResponse = m::mock(ResponseInterface::class);
        $postResponse->shouldReceive('getBody')->andReturn(Utils::streamFor('{"error":{"type":"request","message":"' . $message . '"}}'));
        $postResponse->shouldReceive('getHeader')->andReturn(['content-type' => 'json']);
        $postResponse->shouldReceive('getStatusCode')->andReturn($status);

        $client = m::mock(ClientInterface::class);
        $client->shouldReceive('send')
            ->times(1)
            ->andReturn($postResponse);

        $this->expectException(IdentityProviderException::class);

        $this->provider->setHttpClient($client);
        $this->provider->getAccessToken('authorization_code', ['code' => 'mock_authorization_code']);
    }

    public function testUserData()
    {
        $postResponse = m::mock(ResponseInterface::class);
        $postResponse->shouldReceive('getBody')->andReturn(Utils::streamFor(
            'access_token=mock_access_token&expires=3600&refresh_token=mock_refresh_token'
        ));
        $postResponse->shouldReceive('getHeader')->andReturn(['content-type' => 'application/x-www-form-urlencoded']);
        $postResponse->shouldReceive('getStatusCode')->andReturn(200);

        $accountResponse = m::mock(ResponseInterface::class);
        $accountResponse->shouldReceive('getBody')->andReturn(Utils::streamFor(
            '{
                "resource": "user",
                "id": 1,
                "firstName": "John",
                "lastName": "Doe",
                "email": "john.doe@ominity.com",
                "_links": {
                    "self": {
                        "href": "https://api.ominity.com/v1/users/1",
                        "type": "application/hal+json"
                    }
                }
            }'
        ));
        $accountResponse->shouldReceive('getHeader')->andReturn(['content-type' => 'json']);
        $accountResponse->shouldReceive('getStatusCode')->andReturn(200);

        $client = m::mock(ClientInterface::class);
        $client->shouldReceive('send')
            ->times(2)
            ->andReturn($postResponse, $accountResponse);

        $this->provider->setHttpClient($client);
        $token = $this->provider->getAccessToken('authorization_code', ['code' => 'mock_authorization_code']);
        $account = $this->provider->getResourceOwner($token);

        assert($account instanceof OminityResourceOwner);

        $array = $account->toArray();

        $this->assertEquals('user', $account->getResource());
        $this->assertEquals('user', $array['resource']);
        $this->assertEquals(1, $account->getId());
        $this->assertEquals(1, $array['id']);
        $this->assertEquals('John', $array['firstName']);
        $this->assertEquals('john.doe@ominity.com', $array['email']);
        $this->assertEquals('john.doe@ominity.com', $account->getEmail());
    }

    public function testWhenDefiningADifferentOminityApiUrlThenUseThisOnApiCalls()
    {
        $this->provider->setApiUrl('https://ominity.mycompany.com/api');

        $this->assertEquals('https://ominity.mycompany.com/api/oauth2/tokens', $this->provider->getBaseAccessTokenUrl([]));
    }

    public function testWhenDefiningADifferentOminityWebUrlThenUseThisForAuthorize()
    {
        $this->provider->setWebUrl('https://ominity.mycompany.com');

        list($url) = explode('?', $this->provider->getAuthorizationUrl());
        $this->assertEquals('https://ominity.mycompany.com/oauth2/authorize', $url);
    }
}
