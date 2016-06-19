# Avenger Vulnerabilities

> Avenger Vulnerabilities are methods and function for check possibles vulnerabilities

## Instalation 

The recommended way to install PHP Avenger is through
[Composer](http://getcomposer.org).

```bash
# Install Composer
curl -sS https://getcomposer.org/installer | php
```

Next, run the Composer command to install the latest beta version of Php Avenger SH:

```bash
php composer.phar require aszone/vulnerabilities
```

## Basic Usage

> Use command for init process, result will print in monitor and save in txt on folder results. 
> Var $result is array of urls for test

```bash
$sqli = new SqlInjection($commandData, $result);
$resultSqli['sqli'] = $sqli->check();
```
   
```bash
$lfd = new LocalFileDownload($commandData, $result);
$resultLFD['lfd'] = $lfd->check();
```

## Commands
```bash
$commandData = array(
    'tor' => $tor,
    'torl' => $torl,
    'virginProxies' => $vp,
);
```


## Details

#### Vulnerabilities Checked
* Sql Injection
* Local File Download


#### Future Vulnerabilities Checked
* Admin Page
* RFI
* Xss
* Sensitive Files
    * Dump Files
    * Config Files
    * Open Folders
    
## Help and docs
* [Documentation](http://phpavenger.aszone.com.br).
* [Examples](http://phpavenger.aszone.com.br/examples).
* [Videos](http://youtube.com/aszone).
* [Steakoverflow](http://phpavenger.aszone.com.br).

