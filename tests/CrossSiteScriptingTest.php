<?php

namespace Aszone\Vulnerabilities\Test;

use Aszone\Vulnerabilities\CrossSiteScripting;
use GuzzleHttp\ClientInterface;
use Psr\Log\LoggerInterface;
use GuzzleHttp\Message\ResponseInterface;
use GuzzleHttp\Stream\StreamInterface;


class CrossSiteScriptingTest extends \PHPUnit_Framework_TestCase
{
    private $instance;

    private $stream;

    public function setUp()
    {
        $client = $this->createMock(ClientInterface::class);
        $logger = $this->createMock(LoggerInterface::class);
        $response = $this->createMock(ResponseInterface::class);
        $this->stream = $this->createMock(StreamInterface::class);
        $compare = [CrossSiteScripting::EXPLOIT2];

        $client->method('get')
            ->willReturn($response);

        $response->method('getBody')
            ->willReturn($this->stream);

        $this->instance = new CrossSiteScripting($client, $compare, $logger);
    }

    public function testIsVulnerable()
    {
        $target = 'http://www.example.com/index.html?query=a';

        $this->stream->method('getContents')
            ->willReturn('lorem '.CrossSiteScripting::EXPLOIT2.' ipsum');

        $this->assertTrue(
            $this->instance->isVulnerable($target)
        );
    }

    public function testIsNotVulnerable()
    {
        $target = 'http://www.example.com/';

        $this->assertFalse($this->instance->isVulnerable($target));

        $target = 'http://example.com/index.html?param=a';

        $this->stream->method('getContents')
            ->willReturn('lorem ipsum');

        $this->assertFalse($this->instance->isVulnerable($target));
    }

    public function testGenerateUrls()
    {
        $target = 'http://example.com?param=1&query=a';
        $url0 = sprintf('http://example.com?param=%s&query=a', CrossSiteScripting::EXPLOIT1);
        $url1 = sprintf('http://example.com?param=1&query=%s', CrossSiteScripting::EXPLOIT1);
        $url2 = sprintf('http://example.com?param=%s&query=a', CrossSiteScripting::EXPLOIT2);
        $url3 = sprintf('http://example.com?param=1&query=%s', CrossSiteScripting::EXPLOIT2);

        $urls = $this->instance->generateUrls($target);

        $this->assertTrue(count($urls) === 4);

        $this->assertEquals($urls[0], $url0);
        $this->assertEquals($urls[1], $url1);
        $this->assertEquals($urls[2], $url2);
        $this->assertEquals($urls[3], $url3);
    }

    public function testIsXssPossible()
    {
        $target = 'http://example.com?param=1&query=a';

        $isValid = $this->instance->isXssPossible($target);

        $this->assertTrue($isValid);
    }

    public function testIsXssNotPossible()
    {
        $target = 'http://example.com';

        $isValid = $this->instance->isXssPossible($target);

        $this->assertFalse($isValid);
    }

    public function testCheckSuccess()
    {
        $body = ' '.CrossSiteScripting::EXPLOIT1.' ';

        $this->assertTrue($this->instance->checkSuccess($body));
    }

    public function testCheckNotSuccess()
    {
        $body = ' ';

        $this->assertFalse($this->instance->checkSuccess($body));
    }

    public function testCheckCompare()
    {
        $body = 'lorem '.CrossSiteScripting::EXPLOIT2.' ipsum';

        $this->assertTrue($this->instance->checkCompare($body));
    }

    public function testCheckNotCompare()
    {
        $body = 'lorem ipsum';

        $this->assertFalse($this->instance->checkCompare($body));
    }
}
