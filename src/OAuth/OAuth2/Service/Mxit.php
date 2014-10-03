<?php

namespace OAuth\OAuth2\Service;

use OAuth\Common\Exception\Exception;
use OAuth\OAuth2\Token\StdOAuth2Token;
use OAuth\Common\Http\Exception\TokenResponseException;
use OAuth\Common\Http\Uri\Uri;
use OAuth\Common\Consumer\CredentialsInterface;
use OAuth\Common\Http\Client\ClientInterface;
use OAuth\Common\Storage\TokenStorageInterface;
use OAuth\Common\Http\Uri\UriInterface;

class Mxit extends AbstractService
{
    /** 
    * @var UriInterface|null 
    */
    protected $baseApiUri = 'https://auth.mxit.com';

    /**
     * Defined scopes
     *
     * @link https://dev.mxit.com/docs/oauth-scopes     
     */
    const SCOPE_PROFILE_PUBLIC                = 'profile/public';
    const SCOPE_PROFILE_PRIVATE               = 'profile/private';
    const SCOPE_PROFILE_WRITE                 = 'profile/write';
    const SCOPE_CONTENT_READ                  = 'content/read';
    const SCOPE_CONTENT_WRITE                 = 'content/write';
    const SCOPE_GRAPH_READ                    = 'graph/read';
    const SCOPE_AVATAR_WRITE                  = 'avatar/write';
    const SCOPE_STATUS_WRITE                  = 'status/write';
    const SCOPE_CONTACT_INVITE                = 'contact/invite';
    const SCOPE_MESSAGE_SEND                  = 'message/send';
    const SCOPE_MESSAGE_USER                  = 'message/user';


    public function __construct(
        CredentialsInterface $credentials,
        ClientInterface $httpClient,
        TokenStorageInterface $storage,
        $scopes = array(),
        UriInterface $baseApiUri = null
    ) {
        parent::__construct($credentials, $httpClient, $storage, $scopes, $baseApiUri);

        if (null === $baseApiUri) {
            $this->baseApiUri = new Uri('https://auth.mxit.com/');
        }
    }


    public function getAuthorizationEndpoint()
    {
        return new Uri('https://auth.mxit.com/authorize');
    }


    /**
     * {@inheritdoc}
     */
    public function getAccessTokenEndpoint()
    {
        return new Uri('https://auth.mxit.com/token');
    }

    /**
     * {@inheritdoc}
     */
    protected function getAuthorizationMethod()
    {
        return static::AUTHORIZATION_METHOD_HEADER_BEARER;
    }

    /**
     *   Request the actual token from the OAuth2 server
     */
    public function requestAccessToken($code) {
        $url = "https://auth.mxit.com/token";

        $params = array('grant_type'   => 'authorization_code',
                        'code'         => $code,
                        'redirect_uri' => $this->credentials->getCallbackUrl());

        $this->_headers = array();
        $this->_headers[] = 'Authorization: Basic '. base64_encode($this->credentials->getConsumerId() .':'. $this->credentials->getConsumerSecret());
        $this->_headers[] = "Content-Type: application/x-www-form-urlencoded";

        $responseBody = $this->retrieveResponse($url, 'POST', $params);        
        
        $token = $this->parseAccessTokenResponse($responseBody);
        $this->storage->storeAccessToken($this->service(), $token);

        return $token;
    }

    private function retrieveResponse($url, $method='POST', $params='', $decode=TRUE) {
        $this->http_status = NULL;
        $this->content_type = NULL;
        $this->result = NULL;
        $this->error = FALSE;

        $fields = '';

        if (($method == 'POST' || $method == 'PUT' || $method == 'DELETE') && $params != '') {
            $fields = (is_array($params)) ? http_build_query($params) : $params;
        }

        if ($method == 'PUT' || $method == 'POST' || $method == 'DELETE') {
            $this->_headers[] = 'Content-Length: '. strlen($fields);
        }

        $opts = array(
                CURLOPT_CONNECTTIMEOUT => 10,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_VERBOSE        => false,
                CURLOPT_SSL_VERIFYPEER => false,
                CURLOPT_TIMEOUT        => 60,
                CURLOPT_USERAGENT      => 'PHPoAuthLib',
                CURLOPT_URL            => $url,
                CURLOPT_HTTPHEADER     => $this->_headers
                );

        if (($method == 'POST' || $method == 'PUT' || $method == 'DELETE') && $params != '') {
            $opts[CURLOPT_POSTFIELDS] = $fields; 
        }
        
        if ($method == 'POST' && is_array($params)) {
            $opts[CURLOPT_POST] = count($params);
        } elseif ($method == 'PUT') {
            $opts[CURLOPT_CUSTOMREQUEST] = 'PUT';
        } elseif ($method == 'DELETE') {
            $opts[CURLOPT_CUSTOMREQUEST] = 'DELETE';
        } elseif ($method == 'POST') {
            $opts[CURLOPT_POST] = TRUE;
        }

        $ch = curl_init();
        curl_setopt_array($ch, $opts);
        $result = curl_exec($ch);
        $this->http_status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $this->content_type = curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
        curl_close($ch);

        if ($this->http_status != 200) {
            // Problem with API call, we received an HTTP status code other than 200
            $this->error = TRUE;
        }

        return $result;
    }

    /**
     * {@inheritdoc}
     */
    protected function parseAccessTokenResponse($responseBody)
    {       

        if (!is_array($responseBody)){
            $data = json_decode($responseBody, true);
        } else {
            $data = $responseBody;
        }


        if (null === $data || !is_array($data)) {
            throw new TokenResponseException('Unable to parse response.');
        } elseif (isset($data['message'])) {
            throw new TokenResponseException('Error in retrieving token: "' . $data['message'] . '"');
        } elseif (isset($data['name'])) {
            throw new TokenResponseException('Error in retrieving token: "' . $data['name'] . '"');
        }

        $token = new StdOAuth2Token();
        $token->setAccessToken($data['access_token']);
        $token->setLifeTime($data['expires_in']);

        if (isset($data['refresh_token'])) {
            $token->setRefreshToken($data['refresh_token']);
            unset($data['refresh_token']);
        }

        unset($data['access_token']);
        unset($data['expires_in']);

        $token->setExtraParams($data);

        return $token;
    }

}
