import subprocess
import json
import os
import socket

def bloquear_dns_cliente(ip):    
    # Reglas para bloqueo absoluto: bloquear todo tráfico entrante y saliente
    reglas = [
        f"sudo iptables -I FORWARD 1 -d {ip} -j DROP", 
        f"sudo iptables -I FORWARD 1 -s {ip} -j DROP"
    ]
    
    for regla in reglas:
        subprocess.run(regla.split(), check=True)

    
def remover_bloqueo_dns_cliente(ip):    
    reglas = [
        f"sudo iptables -I FORWARD 1 -s {ip} -j ACCEPT",  
        f"sudo iptables -I FORWARD 1 -d {ip} -j ACCEPT"    
    ]
    
    for regla in reglas:
        subprocess.run(regla.split(), check=True)

def verificar_credenciales(username, password):
    """Verificar credenciales contra un archivo JSON (función de módulo)."""
    try:
        if os.path.exists('users.json'):
            with open('users.json', 'r', encoding='utf-8') as f:
                usuarios = json.load(f)

            for usuario in usuarios.get('usuarios', []):
                if (usuario.get('username') == username and 
                    usuario.get('password') == password):
                    print(f"✅ Login válido: {username}")
                    return True

            print(f"❌ Login fallido: {username}")
            return False
        else:
            print("⚠️  Archivo usuarios.json no encontrado")
            return False
    except Exception as e:
        print(f"❌ Error verificando credenciales: {e}")
        return False

def obtener_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip