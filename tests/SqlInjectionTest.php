<?php

namespace Aszone\Vulnerabilities\Test;

use Aszone\Vulnerabilities\SqlInjection;
use GuzzleHttp\ClientInterface;
use Psr\Log\LoggerInterface;
use GuzzleHttp\Message\ResponseInterface;
use GuzzleHttp\Stream\StreamInterface;

class SqlInjectionTest extends \PHPUnit_Framework_TestCase
{
    private $instance;

    private $stream;

    public function setUp()
    {
        $client = $this->createMock(ClientInterface::class);
        $logger = $this->createMock(LoggerInterface::class);
        $response = $this->createMock(ResponseInterface::class);
        $this->stream = $this->createMock(StreamInterface::class);
        $errors = ['mysql_'];

        $client->method('get')
               ->willReturn($response);

        $response->method('getBody')
                 ->willReturn($this->stream);

        $this->instance = new SqlInjection($client, $errors, $logger);
    }

    public function testIsVulnerable()
    {
        $target = 'http://example.com/index.html?test=a';

        $this->stream->method('getContents')
                     ->willReturn('mysql_');

        $this->assertTrue(
            $this->instance->isVulnerable($target)
        );
    }

    public function testIsNotVulnerable()
    {
        $target = 'http://example.com';

        $this->assertFalse($this->instance->isVulnerable($target));
    }

    public function testGenerateUrlByExploit()
    {
        $target = 'http://example.com?query=a&par1=a&par2=a';
        $urls[] = sprintf('http://example.com?query=a%s&par1=a&par2=a', SqlInjection::EXPLOIT);
        $urls[] = sprintf('http://example.com?query=a&par1=a%s&par2=a', SqlInjection::EXPLOIT);
        $urls[] = sprintf('http://example.com?query=a&par1=a&par2=a%s', SqlInjection::EXPLOIT);

        $generatedUrl = $this->instance->generateUrlByExploit($target);

        $this->assertEquals($generatedUrl, $urls);
    }

    public function testCheckError()
    {
        $body = 'lorem mysql_ ipsum';

        $this->assertTrue($this->instance->checkError($body));
    }

    public function testCheckNotError()
    {
        $body = 'lorem ipsum';

        $this->assertFalse($this->instance->checkError($body));
    }
}
