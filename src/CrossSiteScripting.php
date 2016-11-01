<?php

namespace Aszone\Vulnerabilities;

use GuzzleHttp\ClientInterface;
use Psr\Log\LoggerInterface;
use Aszone\Vulnerabilities\Log\Logger;

class CrossSiteScripting implements VulnerabilityScanner
{
    const EXPLOIT1 = '<script>alert(aaabbbccc);</script>';
    const EXPLOIT2 = '<h1>aaabbbccc</h1>';
    const EXPLOIT1REGEX = "<script>alert\(aaabbbccc\);<\/script>";
    const EXPLOIT2REGEX = "<h1>aaabbbccc<\/h1>";

    private $compare;

    private $client;

    private $logger;

    public function __construct(ClientInterface $client, array $compare, LoggerInterface $logger = null)
    {
        $this->client = $client;
        $this->compare = $compare;

        if (empty($logger)) {
            $logger = new Logger;
        }

        $this->logger = $logger;


    }

    public function isVulnerable($target)
    {
        if ($this->isXssPossible($target)) {
            return $this->verify($target);
        }

        return false;
    }

    public function isXssPossible($target)
    {
        return (bool) preg_match("/\?|(.+?)\=/", (string) $target);
    }

    public function verify($target)
    {

        $urls = $this->generateUrls($target);

        $this->logger->info("\n");

        foreach ($urls as $url) {
            if ($this->attack($url)) {
                $this->logger->info('Is Vull');

                return true;
            }
        }

        return false;
    }

    public function attack($url)
    {
        $this->logger->info('.');

        try {
            $body = $this->client->get($url)->getBody()->getContents();
            if ($body && $this->checkSuccess($body) && $this->checkCompare($body)) {
                return true;
            }
        } catch (\Exception $e) {
            $this->logger->error('#');
        }

        return false;
    }

    public function checkSuccess($body)
    {
        return (bool) preg_match('/'.static::EXPLOIT1REGEX.'|'.static::EXPLOIT2REGEX.'/', $body);
    }

    public function generateUrls($target)
    {
        $this->logger->info("\n".$target);
        $urls1 = $this->generateUrlsByExploit($target, static::EXPLOIT1);
        $urls2 = $this->generateUrlsByExploit($target, static::EXPLOIT2);
        return array_merge($urls1, $urls2);
    }

    public function generateUrlsByExploit($target, $exploit)
    {
        $explodeUrl = parse_url($target);
        $explodeQuery = explode('&', $explodeUrl['query']);

        if (!isset($explodeUrl['query'])) {
            return [];
        }

        $wordsValue = [];

        foreach ($explodeQuery as $query) {
            $explodeQueryEqual = explode('=', $query);
            $wordsValue[$explodeQueryEqual[0]] = '';

            if (isset($explodeQueryEqual[1])) {
                $wordsValue[$explodeQueryEqual[0]] = $explodeQueryEqual[1];
            }
        }

        foreach ($wordsValue as $keyValue => $value) {
            $urls[] = str_replace($keyValue.'='.$value, $keyValue.'='.$exploit, $target);
        }

        return $urls;
    }

    public function checkCompare($body)
    {
        foreach ($this->compare as $compare) {

            $isValid = strpos($body, $compare);
            if ($isValid !== false) {
                return true;
            }
        }

        return false;
    }

}
