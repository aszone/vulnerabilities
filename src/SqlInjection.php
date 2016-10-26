<?php

namespace Aszone\Vulnerabilities;

use GuzzleHttp\ClientInterface;
use Psr\Log\LoggerInterface;
use Aszone\Vulnerabilities\Log\Logger;

class SqlInjection implements VulnerabilityScanner
{
    const EXPLOIT = "'";

    private $errors;

    private $client;

    private $logger;

    public function __construct(ClientInterface $client, array $errors, LoggerInterface $logger = null)
    {
        $this->client = $client;
        $this->errors = $errors;

        if (empty($logger)) {
            $logger = new Logger;
        }

        $this->logger = $logger;
    }

    public function isVulnerable($target)
    {
        if ($this->isSqlInjectionPossible($target)) {
            return $this->verify($target);
        }

        return false;
    }

    protected function isSqlInjectionPossible($target)
    {
        return isset(parse_url($target)['query']);
    }

    protected function verify($target)
    {
        $urls = $this->generateUrlByExploit($target);

        foreach ($urls as $url) {
            $this->logger->info("\n url =>".$url."\n");

            if ($this->attack($url)) {
                $this->logger->info('Is Vull');

                return true;
            }
        }

        return false;
    }

    public function generateUrlByExploit($target)
    {
        $explodeUrl = parse_url($target);
        $explodeQuery = explode('&', $explodeUrl['query']);

        foreach ($explodeQuery as $keyQuery => $query) {
            $explodeQueryEqual = explode('=', $query);
            $wordsValue[$explodeQueryEqual[0]] = $explodeQueryEqual[1];
        }

        foreach ($wordsValue as $keyValue => $value) {
            $urls[] = str_replace($keyValue.'='.$value, $keyValue.'='.$value.static::EXPLOIT, $target);
        }

        return $urls;
    }

    public function attack($url)
    {
        try {
            $body = $this->client->get($url)->getBody()->getContents();

            if ($body) {
                if ($this->checkError($body)) {
                    return $url;
                }
            }
        } catch (\Exception $e) {
            if ($e->getCode() != '404' and $e->getCode() != '403') {
                return $url;
            }

            $this->logger->error('Error code => '.$e->getCode()."\n");
        }

        return false;
    }

    public function checkError($body)
    {
        foreach ($this->errors as $error) {
            $isValid = strpos($body, $error);

            if ($isValid !== false) {
                return true;
            }
        }

        return false;
    }
}
