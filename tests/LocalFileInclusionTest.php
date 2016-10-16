<?php

namespace Aszone\Vulnerabilities\Test;

use Aszone\Vulnerabilities\LocalFileInclusion;

class LocalFileInclusionTest extends \PHPUnit_Framework_TestCase
{
    private $instance;

    public function setUp()
    {
        $this->instance = new LocalFileInclusion([]);
    }

    public function testIsNotVulnerable()
    {
        $target = "http://example.com/index.html?a=1";

        $this->assertFalse($this->instance->isVulnerable($target));
    }

    public function testGenerateUrls()
    {
        $target = "http://example.com/index.html?param=1&query=a";
        $url0 = sprintf("http://example.com/index.html?param=%s&query=a", LocalFileInclusion::EXPLOIT1);

        $urls = $this->instance->generateUrls($target);

        $this->assertTrue(count($urls) === 44);

        $this->assertEquals($urls[0], $url0);
    }

    public function testIsLfiPossible()
    {
        $target = "http://example.com/index.html?param=1&query=a";
        
        $isValid = $this->instance->isLfiPossible($target);

        $this->assertTrue($isValid);
    }

    public function testIsLfiNotPossible()
    {
        $target = "http://example.com/index.html";
        
        $isValid = $this->instance->isLfiPossible($target);

        $this->assertFalse($isValid);
    }
}

