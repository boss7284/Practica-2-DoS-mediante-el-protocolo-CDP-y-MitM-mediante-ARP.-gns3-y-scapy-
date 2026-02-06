# Practica-2-DoS-mediante-el-protocolo-CDP-y-MitM-mediante-ARP.-gns3-y-scapy-

**Asignatura:** Seguridad en Redes 

**Estudiante:** Roberto de Jesus

**Matrícula:** 2023-0348 

**Profesor:** Jonathan Esteban Rondón 

**Fecha:** Febrero 2026

**Link del video**: https://youtu.be/_wscGbKKHwc
---

# Herramientas de Auditoría de Seguridad en Redes

## Tabla de Contenidos
- [Descripción General](#-descripción-general)
- [Topología del Laboratorio](#-topología-del-laboratorio)
- [Script 1: CDP DoS Attack](#-script-1-cdp-dos-attack)
- [Script 2: ARP MitM Attack](#-script-2-arp-mitm-attack)
- [Requisitos del Sistema](#-requisitos-del-sistema)
- [Medidas de Mitigación](#-medidas-de-mitigación)


---

## Descripción General

Este proyecto contiene dos scripts de prueba seguridad desarrollados con Scapy para demostrar vulnerabilidades comunes en redes.

### Scripts utilizados
- **CDP DoS Attack**  
  Ataque de denegación de servicio mediante saturación del protocolo **Cisco Discovery Protocol (CDP)**.
- **ARP MitM Attack**  
  Ataque **Man-in-the-Middle** mediante **envenenamiento de tablas ARP**.

>  **ADVERTENCIA**  
> Estas herramientas están diseñadas **EXCLUSIVAMENTE** para fines educativos en laboratorios como **GNS3 o PNETLAB**.  
> Este codigo es Original en caso de yo me vea afectado por *PLAGIO* habra retaliacion.

---

## **Topología del Laboratorio** (EJEMPLO DEL VIDEO)

### Diagrama de Red

![image alt](https://github.com/boss7284/d.u.m.p2/blob/0febd2957c0c35be74dc9476fd039456b7783bc9/Screenshot%202026-02-06%20023647.png)

### Configuración de Red

#### Router R1
- IP: `192.168.10.1/24`
- Función: Gateway y DHCP Server
- Dominio: `laboratorio.local`
- DNS: `8.8.8.8`

#### Switch SW1
- Modelo: Cisco IOSv
- VLAN 10 (Datos)
- CDP: Habilitado (default)

#### Dispositivos Finales

| Dispositivo | IP | MAC | Gateway |
|------------|----|-----|--------|
| PC1 | 192.168.10.22 | 00:50:79:66:68:00 | 192.168.10.1 |
| PC2 | 192.168.10.21 | 00:50:79:66:68:01 | 192.168.10.1 |
| Kali | 192.168.10.23 | 00:0c:29:e6:e2:1b | 192.168.10.1 |

---

## Script 1: CDP DoS Attack

### Objetivo
Demostrar la vulnerabilidad del protocolo **CDP** ante ataques de **denegación de servicio** mediante la inyección masiva de anuncios falsos.

### Impacto esperado
- Saturación de la tabla CDP
- Alto uso de CPU (60–90%)
- Degradación del rendimiento del switch

### Parámetros principales
```python
INTERFACE = "eth0"
CDP_MULTICAST = "01:00:0c:cc:cc:cc"
PACKETS_PER_SECOND = 50
```
### Ejecucion
```
sudo python3 cdp_dos.py
```

### Verificación en el switch
```
show cdp neighbors
show cdp traffic
show processes cpu sorted
```

---

## Script 2: ARP MitM Attack

### Objetivo del Script

El script **arp_mitm.py** demuestra cómo un atacante puede interceptar tráfico de red mediante **ARP Spoofing (envenenamiento ARP)**, posicionándose como intermediario (**Man-in-the-Middle**) entre una víctima y el gateway.

---

### Funcionamiento

- Envía paquetes ARP falsos a la víctima haciéndose pasar por el gateway
- Envía paquetes ARP falsos al gateway haciéndose pasar por la víctima
- Habilita **IP Forwarding** para reenviar tráfico y evitar interrupciones
- Intercepta todo el tráfico entre víctima y router

---

### Capacidades del Ataque

-  Interceptar credenciales HTTP / FTP / Telnet
-  Capturar tráfico no cifrado
-  Modificar paquetes en tránsito (extensible)
-  Secuestro de sesiones (session hijacking)

---

### Parámetros del Script

#### Versión con argumentos

```
-t, --target   IP_VICTIMA
-g, --gateway  IP_GATEWAY
-i, --interface INTERFAZ (default: eth0)
```

### Ejecucion
```
sudo python3 arp_mitm.py -t 192.168.10.22 -g 192.168.10.1
```

### Verificación en PC1
```
sh arp
```

---

## Medidas de Mitigación

Las siguientes medidas reducen o eliminan la efectividad de ataques como **ARP Spoofing (MitM)** y **CDP Abuse**, aplicables en redes Cisco.

---

### Dynamic ARP Inspection (DAI)

Evita ataques de ARP Spoofing validando los mensajes ARP contra la base de datos de DHCP Snooping.

```cisco
ip arp inspection vlan 10

interface GigabitEthernet0/0
 ip arp inspection trust

interface range GigabitEthernet0/1-3
 no ip arp inspection trust
```

### DHCP Snooping

```
ip dhcp snooping
ip dhcp snooping vlan 10

interface GigabitEthernet0/0
 ip dhcp snooping trust
```

### Port Security

```
interface GigabitEthernet0/1
 switchport mode access
 switchport port-security
 switchport port-security maximum 2
 switchport port-security violation restrict
```

### IP Source Guard

```
interface GigabitEthernet0/1
 ip verify source
```

### Deshabilitar CDP en Puertos No Confiables

```
interface range GigabitEthernet0/1-24
 no cdp enable
```

---

## Requisitos

- Kali Linux

- Python 3

- Scapy

- GNS3

- Dispositivos Cisco IOS
