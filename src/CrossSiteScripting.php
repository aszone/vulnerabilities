<?php

namespace Aszone\Vulnerabilities;

use Aszone\FakeHeaders\FakeHeaders;
use GuzzleHttp\Client;

class CrossSiteScripting extends CommandDataConfig implements VulnerabilityScanner
{
    const EXPLOIT1 = '<script>alert(aaabbbccc);</script>';
    const EXPLOIT2 = '<h1>aaabbbccc</h1>';
    const EXPLOIT1REGEX = "<script>alert\(aaabbbccc\);<\/script>";
    const EXPLOIT2REGEX = "<h1>aaabbbccc<\/h1>";

    private $errors = [];

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

        $this->output("\n");

        foreach ($urls as $url) {
            if ($this->attack($url)) {
                $this->output('Is Vull');

                return $url;
            }
        }

        return false;
    }

    public function attack($url)
    {
        $this->output('.');

        $header = new FakeHeaders();
        $client = new Client(['defaults' => [
            'headers' => ['User-Agent' => $header->getUserAgent()],
            'proxy' => $this->commandData['tor'],
            'timeout' => 30,
        ]]);

        try {
            $body = $client->get($url)->getBody()->getContents();

            if ($body && $this->checkSuccess($body) && !$this->checkError($body)) {
                return true;
            }
        } catch (\Exception $e) {
            $this->output('#');
        }

        return false;
    }

    public function checkSuccess($body)
    {
        return (bool) preg_match('/'.static::EXPLOIT1REGEX.'|'.static::EXPLOIT2REGEX.'/', $body);
    }

    public function generateUrls($target)
    {
        $this->output("\n".$target);

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

    public function checkError($body)
    {
        $errors = $this->getErrors();

        foreach ($errors as $error) {
            $isValid = strpos($body, $error);

            if ($isValid !== false) {
                return true;
            }
        }

        return false;
    }

    protected function getErrors()
    {
        if (!$this->errors) {
            $this->loadErrors();
        }

        return $this->errors;
    }

    protected function loadErrors()
    {
        $errorsMysql = parse_ini_file(__DIR__.'/../resources/Errors/mysql.ini');
        $errorsMariaDb = parse_ini_file(__DIR__.'/../resources/Errors/mariadb.ini');
        $errorsOracle = parse_ini_file(__DIR__.'/../resources/Errors/oracle.ini');
        $errorssqlServer = parse_ini_file(__DIR__.'/../resources/Errors/sqlserver.ini');
        $errorsPostgreSql = parse_ini_file(__DIR__.'/../resources/Errors/postgresql.ini');
        $errorsAsp = parse_ini_file(__DIR__.'/../resources/Errors/asp.ini');
        $errorsPhp = parse_ini_file(__DIR__.'/../resources/Errors/php.ini');

        $this->errors = array_merge(
            $errorsMysql,
            $errorsMariaDb,
            $errorsOracle,
            $errorssqlServer,
            $errorsPostgreSql,
            $errorsAsp,
            $errorsPhp
        );
    }
}
