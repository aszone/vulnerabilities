<?php

namespace Aszone\Vulnerabilities\Test;

use Aszone\Vulnerabilities\SqlInjection;

class SqlInjectionTest extends \PHPUnit_Framework_TestCase
{
    private $instance;

    public function setUp()
    {
        $this->instance = new SqlInjection([]);
    }

    public function testIsVulnerable()
    {
        $target = 'http://testphp.vulnweb.com/search.php?test=a';

        $this->assertEquals(
            $target.SqlInjection::EXPLOIT,
            $this->instance->isVulnerable($target)
        );
    }

    public function testIsNotVulnerable()
    {
        $target = 'http://www.insecurelabs.org';

        $this->assertFalse($this->instance->isVulnerable($target));
    }

    public function testGenerateUrlByExploit()
    {
        $target = 'http://example.com?query=a';
        $url = sprintf('http://example.com?query=a%s', SqlInjection::EXPLOIT);

        $generatedUrl = $this->instance->generateUrlByExploit($target);

        $this->assertEquals($generatedUrl[0], $url);
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
