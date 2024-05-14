# Ominity OAuth in PHP #

This package provides Ominity OAuth 2.0 support for the PHP League's [OAuth 2.0 Client](https://github.com/thephpleague/oauth2-client).

Use Ominity OAuth to easily connect Ominity User & Admin accounts to your application.

## Installation ##

By far the easiest way to install the Ominity API client is to require it with [Composer](http://getcomposer.org/doc/00-intro.md).

	$ composer require ominity/oauth2-ominity-php ^1.0

	    {
	        "require": {
	            "ominity/oauth2-ominity-php": "^1.0"
	        }
	    }


You may also git checkout or [download all the files](https://github.com/ominity/oauth2-ominity-php/archive/master.zip), and include the OAuth 2.0 provider manually.

## Usage

Usage is the same as The League's OAuth client, using `\Ominity\OAuth2\Client\Provider\Ominity` as the provider.

### Authorization Code Flow

```php
$provider = new \Ominity\OAuth2\Client\Provider\Ominity([
    'clientId'     => 'YOUR_CLIENT_ID',
    'clientSecret' => 'YOUR_CLIENT_SECRET',
    'redirectUri'  => 'https://your-redirect-uri',
]);

// If we don't have an authorization code then get one
if (!isset($_GET['code']))
{
    // Fetch the authorization URL from the provider; this returns the
    // urlAuthorize option and generates and applies any necessary parameters
    // (e.g. state).
    $authorizationUrl = $provider->getAuthorizationUrl([
        // Optional, only use this if you want to ask for scopes the user previously denied.
        'approval_prompt' => 'force',

        // Optional, a list of scopes. Defaults to only 'me.read'.
        'scope' => [
        \Ominity\OAuth2\Client\Provider\Ominity::SCOPE_ME_READ,
	    \Ominity\OAuth2\Client\Provider\Ominity::SCOPE_USERS_READ
	],
    ]);

    // Get the state generated for you and store it to the session.
    $_SESSION['oauth2state'] = $provider->getState();

    // Redirect the user to the authorization URL.
    header('Location: ' . $authorizationUrl);
    exit;
}

// Check given state against previously stored one to mitigate CSRF attack
elseif (empty($_GET['state']) || ($_GET['state'] !== $_SESSION['oauth2state']))
{
    unset($_SESSION['oauth2state']);
    exit('Invalid state');
}

else
{
    try
    {
        // Try to get an access token using the authorization code grant.
        $accessToken = $provider->getAccessToken('authorization_code', [
            'code' => $_GET['code']
        ]);

        // Using the access token, we may look up details about the resource owner.
        $resourceOwner = $provider->getResourceOwner($accessToken);

        print_r($resourceOwner->toArray());
    }
    catch (\League\OAuth2\Client\Provider\Exception\IdentityProviderException $e)
    {
        // Failed to get the access token or user details.
        exit($e->getMessage());
    }
}
```

### Refreshing A Token

```php
$provider = new \Ominity\OAuth2\Client\Provider\Ominity([
    'clientId'     => 'YOUR_CLIENT_ID',
    'clientSecret' => 'YOUR_CLIENT_SECRET',
    'redirectUri'  => 'https://your-redirect-uri',
]);

$grant = new \League\OAuth2\Client\Grant\RefreshToken();
$token = $provider->getAccessToken($grant, ['refresh_token' => $refreshToken]);
```


### Authenticating using the AccessToken (ominity-api-php example)

After refreshing an AccessToken, here's how to use it with the [ominity-api-php package](https://www.github.com/ominity/ominity-api-php). Note that the `getToken()` method is used to obtain the access token string.

```php
$ominity = new \Ominity\Api\OminityApiClient;
$ominity->setAccessToken($token->getToken());

// With the correct scopes, you can now interact with Ominity's API on behalf of the User
$orders = $ominity->commerce->orders->page(); // returns paginated user orders
```

> [!NOTE]
> In order to access the ominity api via `\Ominity\Api\OminityApiClient`, the [ominity/ominity-api-php](github.com/ominity/ominity-api-php) library is required!

### Revoking a token

Both AccessTokens and RefreshTokens are revokable. Here's how to revoke an AccessToken:

```php
$provider = new \Ominity\OAuth2\Client\Provider\Ominity([
    'clientId'     => 'YOUR_CLIENT_ID',
    'clientSecret' => 'YOUR_CLIENT_SECRET',
    'redirectUri'  => 'https://your-redirect-uri',
]);

$provider->revokeAccessToken($accessToken->getToken());
```

Similarly, here's how to revoke a RefreshToken:

**Note: When you revoke a refresh token, all access tokens based on the same authorization grant will be revoked as well.**

```php
$provider = new \Ominity\OAuth2\Client\Provider\Ominity([
    'clientId'     => 'YOUR_CLIENT_ID',
    'clientSecret' => 'YOUR_CLIENT_SECRET',
    'redirectUri'  => 'https://your-redirect-uri',
]);

$provider->revokeRefreshToken($refreshToken->getToken());
```


## Want to help us make our API client even better? ##

Want to help us make our API client even better? We take [pull requests](https://github.com/ominity/ominity-api-php/pulls?utf8=%E2%9C%93&q=is%3Apr).

## License ##
[BSD (Berkeley Software Distribution) License](http://www.opensource.org/licenses/bsd-license.php).
Copyright (c) 2024, Ominity.

## Support ##
Contact: [www.ominity.com](https://www.ominity.com) — info@ominity.com
