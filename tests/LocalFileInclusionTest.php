<?php

namespace Aszone\Vulnerabilities\Test;

use Aszone\Vulnerabilities\LocalFileInclusion;
use GuzzleHttp\ClientInterface;
use Psr\Log\LoggerInterface;
use GuzzleHttp\Message\ResponseInterface;
use GuzzleHttp\Stream\StreamInterface;

class LocalFileInclusionTest extends \PHPUnit_Framework_TestCase
{
    private $instance;

    private $stream;

    public function setUp()
    {
        $client = $this->createMock(ClientInterface::class);
        $logger = $this->createMock(LoggerInterface::class);
        $response = $this->createMock(ResponseInterface::class);
        $this->stream = $this->createMock(StreamInterface::class);

        $client->method('get')
            ->willReturn($response);

        $response->method('getBody')
            ->willReturn($this->stream);

        $this->instance = new LocalFileInclusion($client, $logger);
    }

    public function testIsVulnerable()
    {
        $target = 'http://example.com/index.html?param=a';

        $url = sprintf('http://example.com/index.html?param=%s', LocalFileInclusion::EXPLOIT1);

        $this->stream->method('getContents')
            ->willReturn('lorem '.LocalFileInclusion::EXPLOIT1REGEX.' ipsum');

        $this->assertEquals($url,$this->instance->isVulnerable($target));
    }

    public function testIsNotVulnerable()
    {
        $target = 'http://example.com/index.html';

        $this->assertFalse($this->instance->isVulnerable($target));

        $target = 'http://example.com/index.html?param=a';

        $this->stream->method('getContents')
            ->willReturn('lorem ipsum');

        $this->assertFalse($this->instance->isVulnerable($target));
    }

    public function testGenerateUrls()
    {
        $target = 'http://example.com/index.html?param=1&query=a';
        $url0 = sprintf('http://example.com/index.html?param=%s&query=a', LocalFileInclusion::EXPLOIT1);

        $urls = $this->instance->generateUrls($target);

        $this->assertTrue(count($urls) === 44);

        $this->assertEquals($urls[0], $url0);
    }

    public function testIsLfiPossible()
    {
        $target = 'http://example.com/index.html?param=1&query=a';

        $isValid = $this->instance->isLfiPossible($target);

        $this->assertTrue($isValid);
    }

    public function testIsLfiNotPossible()
    {
        $target = 'http://example.com/index.html';

        $isValid = $this->instance->isLfiPossible($target);

        $this->assertFalse($isValid);
    }
}
