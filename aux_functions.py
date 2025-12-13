import subprocess
import json
import os
import socket

def block_conections(ip):    
    reglas = [
        f"sudo iptables -I FORWARD 1 -d {ip} -j DROP", 
        f"sudo iptables -I FORWARD 1 -s {ip} -j DROP"
    ]
    
    for regla in reglas:
        subprocess.run(regla.split(), check=True)

    
def remove_block(ip):    
    reglas = [
        f"sudo iptables -I FORWARD 1 -s {ip} -j ACCEPT",  
        f"sudo iptables -I FORWARD 1 -d {ip} -j ACCEPT"    
    ]
    
    for regla in reglas:
        subprocess.run(regla.split(), check=True)

def check_credentials(username, password):
    try:
        if os.path.exists('users.json'):
            with open('users.json', 'r', encoding='utf-8') as f:
                usuarios = json.load(f)

            for usuario in usuarios.get('usuarios', []):
                if (usuario.get('username') == username and 
                    usuario.get('password') == password):
                    return True

            return False
        else:
            return False
    except Exception as e:
        return False

def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip