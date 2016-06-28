<?php

namespace Aszone\Vulnerabilities;

use Respect\Validation\Validator as v;
use Aszone\FakeHeaders\FakeHeaders;
use GuzzleHttp\Client;

class CrossSiteScripting
{
    public $targets;

    public $target;

    public $tor;

    public $commandData;

    public $exploit1;

    public $exploit2;

    public $exploit1Regex;

    public $exploit2Regex;

    public function __construct($commandData, $targets)
    {
        //Check command of entered.
        $defaultEnterData = $this->defaultEnterData();
        $this->commandData = array_merge($defaultEnterData, $commandData);
        if ($this->commandData['torl']) {
            $this->commandData['tor'] = $this->commandData['torl'];
        }
        $this->targets = $targets;
        $this->exploit1= "<script>alert(aaabbbccc);</script>";
        $this->exploit2= "<h1>aaabbbccc</h1>";
        $this->exploit1Regex= "<script>alert\(aaabbbccc\);<\/script>";
        $this->exploit2Regex= "<h1>aaabbbccc<\/h1>";
    }

    private function defaultEnterData()
    {
        $dataDefault['dork'] = false;
        $dataDefault['pl'] = false;
        $dataDefault['tor'] = false;
        $dataDefault['torl'] = false;
        $dataDefault['virginProxies'] = false;
        $dataDefault['proxyOfSites'] = false;

        return $dataDefault;
    }

    public function check()
    {
        $result = [];
        foreach ($this->targets as $searchEngenier) {
            foreach ($searchEngenier as $keyTarget => $target) {
                $this->target = urldecode(urldecode($target));
                $resultCheck = $this->checkSuccess();
                if($resultCheck){
                    $result[]=$resultCheck;
                }
            }
        }

        return $result;
    }

    protected function getWordListInArray($wordlist)
    {
        $checkFileWordList = v::file()->notEmpty()->validate($wordlist);
        if ($checkFileWordList) {
            $targetResult = file($wordlist, FILE_IGNORE_NEW_LINES);

            return $targetResult;
        }

        return false;
    }

    protected function checkSuccess()
    {
        $isValidLfd = $this->isXss($this->target);
        if (!$isValidLfd) {
            return false;
        }

        return $this->setVull();
    }

    protected function isXss($target)
    {
        $validXss = preg_match("/\?|(.+?)\=/", $target, $m);
        if ($validXss) {
            return true;
        }

        return false;
    }

    protected function setVull()
    {
        //$ext=$this->getExtension($this->target);
        $urlsForAttack = $this->generatesUrlForAttack();
        $resultcheckAttack = [];
        echo "\n";
        foreach ($urlsForAttack as $urlAttack) {
            $resultcheckAttack = $this->setAttack($urlAttack);
            if (!empty($resultcheckAttack)) {
                echo 'Is Vull';
                return $urlAttack;
            }
        }

        return false;
    }


    protected function setAttack($url)
    {
        echo '.';
        $header = new FakeHeaders();
        $client = new Client(['defaults' => [
            'headers' => ['User-Agent' => $header->getUserAgent()],
            'proxy' => $this->commandData['tor'],
            'timeout' => 30,
        ],
        ]);
        try {
            $body= $client->get($url)->getBody()->getContents();
            if($body){
                if($this->checkExistValueGetInBody($body) AND !$this->checkError($body)){
                    return $url;
                }
            }

        } catch (\Exception $e) {
            //echo "Error code => ".$e->getCode()."\n";
            echo '#';
        }

        return false;
    }

    protected function checkExistValueGetInBody($body){

        //$valid=preg_match("/<script>alert\(aaabbbccc\);<\/script\>|<h1>aaabbbccc<\/h1>/",$body,$m);
        $valid=preg_match("/".$this->exploit1Regex."|".$this->exploit2Regex."/",$body,$m);
        if($valid){
            return true;
        }
        return false;

    }

    protected function generatesUrlForAttack()
    {
        echo "\n".$this->target;
        $urlsFinal = [];
        $urls1 = $this->generateUrlsByExploit($this->exploit1);
        $urls2 = $this->generateUrlsByExploit($this->exploit2);
        $urlsFinal = array_merge($urls1, $urls2);

        return $urlsFinal;
    }

    protected function generateUrlsByExploit($exploit)
    {
        $explodeUrl = parse_url($this->target);
        $explodeQuery = explode('&', $explodeUrl['query']);
        if(!isset($explodeUrl['query'])){
            return array();
        }
        $wordsValue=array();
        //Identify and sets urls of values of Get
        foreach ($explodeQuery as $keyQuery => $query) {
            $explodeQueryEqual = explode('=', $query);
            $wordsValue[$explodeQueryEqual[0]]="";
            if(isset($explodeQueryEqual[1])){
                $wordsValue[$explodeQueryEqual[0]] = $explodeQueryEqual[1];
            }

        }

        foreach($wordsValue as $keyValue => $value){
            $urls[]=str_replace($keyValue."=".$value,$keyValue."=??????????",$this->target);
        }

        $urlFinal = [];
        foreach ($urls as $url) {
            $urlFinal[] = str_replace('??????????', $exploit, $url);
        }
        return $urlFinal;
    }

    protected function getNameFileUrl()
    {
        $resultUrl = parse_url($this->target);

        return $resultUrl['path'];
    }

    protected function getExtension()
    {
        $url_parts = parse_url($this->target);
        $isValidExt = preg_match("/\.(.*)/", $url_parts['path'], $m);
        if ($isValidExt) {
            return $m[1];
        }

        return false;
    }

    protected function getKeysUrl($target)
    {
        $url_parts = parse_url($target);
        $parameters = explode('&', $url_parts['query']);
        $resultFinal = [];

        foreach ($parameters as $keyGet => $get) {
            $resultLine = explode('=', $get);
            $resultFinal[$keyGet][$resultLine[0]] = $resultLine[1];
        }

        return $resultFinal;
    }

    protected function sendMail($result)
    {
        //Send Mail with parcial results
        $mailer = new Mailer();
        if (empty($result)) {
            $mailer->sendMessage('you@example.com', 'Fail, not finder password in list. =\\');
        } else {
            $msg = 'PHP Avenger Informer, SUCCESS:<br><br>Link Vull is '.$result;

            $mailer->sendMessage('you@example.com', $msg);
        }
    }

    protected function createNameFile()
    {
        return $this->getName().'_'.date('m-d-Y_hia');
    }

    protected function saveTxt($data, $filename)
    {
        $file = __DIR__.'/../../../results/'.$filename.'.txt';
        $myfile = fopen($file, 'w') or die('Unable to open file!');
        if (is_array($data)) {
            foreach ($data as $dataType) {
                foreach ($dataType as $singleData) {
                    $txt = $singleData."\n";
                    fwrite($myfile, $txt);
                }
            }
        } else {
            $txt = $data;
            fwrite($myfile, $txt);
        }
        fclose($myfile);

        if (!file_exists($file)) {
            return false;
        }

        return true;
    }

    protected function checkError($body)
    {
        //echo $body;
        $errors = $this->getErrorsOfList();
        foreach ($errors as $error) {
            $isValid = strpos($body, $error);
            if ($isValid !== false) {
                return true;
            }
        }

        return false;
    }

    protected function getErrorsOfList()
    {
        $errorsMysql = parse_ini_file(__DIR__ . '/resource/Errors/mysql.ini');
        $errorsMariaDb = parse_ini_file(__DIR__ . '/resource/Errors/mariadb.ini');
        $errorsOracle = parse_ini_file(__DIR__ . '/resource/Errors/oracle.ini');
        $errorssqlServer = parse_ini_file(__DIR__ . '/resource/Errors/sqlserver.ini');
        $errorsPostgreSql = parse_ini_file(__DIR__ . '/resource/Errors/postgresql.ini');
        $errorsAsp = parse_ini_file(__DIR__ . '/resource/Errors/asp.ini');
        $errorsPhp = parse_ini_file(__DIR__ . '/resource/Errors/php.ini');

        return array_merge($errorsMysql, $errorsMariaDb, $errorsOracle, $errorssqlServer, $errorsPostgreSql,$errorsAsp,$errorsPhp );
    }
}
