<?php

namespace Aszone\Vulnerabilities;

use Aszone\FakeHeaders\FakeHeaders;
use GuzzleHttp\Client;

class SqlInjection extends CommandDataConfig implements VulnerabilityScanner
{
    const EXPLOIT = "'";

    private $errors = [];

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
            $this->output("\n url =>".$url."\n");

            if ($this->attack($url)) {
                $this->output('Is Vull');

                return $url;
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
        $header = new FakeHeaders();
        $client = new Client(['defaults' => [
            'headers' => ['User-Agent' => $header->getUserAgent()],
            'proxy' => $this->commandData['tor'],
            'timeout' => 30,
        ]]);

        try {
            $body = $client->get($url)->getBody()->getContents();

            if ($body) {
                if ($this->checkError($body)) {
                    return $url;
                }
            }
        } catch (\Exception $e) {
            if ($e->getCode() != '404' and $e->getCode() != '403') {
                return $url;
            }

            $this->output('Error code => '.$e->getCode()."\n");
        }

        return false;
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

        $this->errors = array_merge(
            $errorsMysql,
            $errorsMariaDb,
            $errorsOracle,
            $errorssqlServer,
            $errorsPostgreSql
        );
    }
}
