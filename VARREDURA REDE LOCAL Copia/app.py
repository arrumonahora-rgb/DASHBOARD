from flask import Flask, render_template, request, jsonify
import socket
from scapy.all import ARP, Ether, srp
from concurrent.futures import ThreadPoolExecutor

app = Flask(__name__)

def get_local_network():
    """Identifica a sub-rede local (ex: 192.168.1.0/24)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Tenta conectar a um IP externo para identificar a interface ativa
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        return ".".join(ip.split('.')[:-1]) + ".0/24"
    except Exception:
        return '127.0.0.1/24'
    finally:
        s.close()

def check_single_port(ip, port):
    """Verifica se uma porta TCP especifica esta aberta."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.3)
            if s.connect_ex((ip, port)) == 0:
                return port
    except:
        return None
    return None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan-network', methods=['POST'])
def scan_network():
    """Realiza varredura ARP na rede local."""
    subnet = get_local_network()
    try:
        # ARP Scan - Requer Npcap e Admin
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=subnet), timeout=2, verbose=False)
        devices = []
        for s, r in ans:
            devices.append({"ip": r.psrc, "mac": r.hwsrc.upper()})
        return jsonify({"status": "success", "devices": devices, "subnet": subnet})
    except Exception as e:
        return jsonify({"status": "error", "message": "Erro de Permissao ou Npcap ausente. Execute como ADMIN."}), 500

@app.route('/scan-ports', methods=['POST'])
def scan_ports():
    """Realiza varredura de portas comuns em um IP alvo."""
    data = request.json
    target = data.get('target')
    common_ports = [21, 22, 23, 25, 53, 80, 110, 443, 3306, 3389, 8080]
    
    open_ports = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        results = executor.map(lambda p: check_single_port(target, p), common_ports)
        open_ports = [p for p in results if p is not None]
    
    return jsonify({"ip": target, "open_ports": open_ports})

if __name__ == '__main__':
    print("--------------------------------------------------")
    print(" SERVIDOR INICIADO EM http://127.0.0.1:5000")
    print(" AVISO: Execute o terminal como ADMINISTRADOR.")
    print("--------------------------------------------------")
    app.run(debug=True)