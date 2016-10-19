<?php

namespace Aszone\Vulnerabilities\Test;

use Aszone\Vulnerabilities\CrossSiteScripting;

class CrossSiteScriptingTest extends \PHPUnit_Framework_TestCase
{
    private $instance;

    public function setUp()
    {
        $this->instance = new CrossSiteScripting([]);
    }

    public function testIsVulnerable()
    {
        $target = 'http://www.insecurelabs.org/task/Rule1?query=a';

        $this->assertEquals(
            substr($target, 0, -1).CrossSiteScripting::EXPLOIT2,
            $this->instance->isVulnerable($target)
        );
    }

    public function testIsNotVulnerable()
    {
        $target = 'http://www.insecurelabs.org';

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
