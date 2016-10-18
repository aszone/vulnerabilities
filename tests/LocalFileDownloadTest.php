<?php

namespace Aszone\Vulnerabilities\Test;

use Aszone\Vulnerabilities\LocalFileDownload;

class LocalFileDownloadTest extends \PHPUnit_Framework_TestCase
{
    private $instance;

    public function setUp()
    {
        $this->instance = new LocalFileDownload([]);
    }

    public function testIsNotVulnerable()
    {
        $target = "http://example.com/index.html?a=1";

        $this->assertFalse($this->instance->isVulnerable($target));
    }

    public function testGenerateUrls()
    {
        $target = "http://example.com/index.html?param=1&query=a";
        $url0 = sprintf("http://example.com/index.html?param=%s&query=a", "/index.html");

        $urls = $this->instance->generateUrls($target);

        $this->assertTrue(count($urls) === 44);

        $this->assertEquals($urls[0], $url0);
    }

    public function testIsLfdPossible()
    {
        $target = "http://example.com/index.html?param=1&query=a";
        
        $isValid = $this->instance->isLfdPossible($target);

        $this->assertTrue($isValid);
    }

    public function testIsLfdNotPossible()
    {
        $target = "http://example.com/index.html";
        
        $isValid = $this->instance->isLfdPossible($target);

        $this->assertFalse($isValid);
    }
}

