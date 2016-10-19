<?php

namespace Aszone\Vulnerabilities;

abstract class CommandDataConfig
{
    protected $commandData;

    protected $defaultCommandData = [
        'dork' => false,
        'pl' => false,
        'tor' => false,
        'torl' => false,
        'virginProxies' => false,
        'proxyOfSites' => false,
    ];

    public function __construct(array $commandData)
    {
        $this->commandData = array_merge($this->defaultCommandData, $commandData);

        if ($this->commandData['torl']) {
            $this->commandData['tor'] = $this->commandData['torl'];
        }
    }

    public function output($value)
    {
        echo $value;
    }
}
