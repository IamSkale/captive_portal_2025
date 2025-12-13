import socket
import time
import threading
import signal
import sys
import urllib.parse
import json
import os
import errno
import subprocess

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


class ManualHTTPServer:
    def __init__(self, host='0.0.0.0', port=8443):
        self.host = host
        self.port = port
        self.sock = None
        self.running = False
        self.thread = None

    def start(self):
        subprocess.run("sudo iptables -F FORWARD 2>/dev/null", shell=True)
        subprocess.run("sudo iptables -P FORWARD DROP", shell=True)
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except Exception:
            pass

        try:
            self.sock.bind((self.host, self.port))
        except OSError as e:
            if e.errno == errno.EACCES:
                raise PermissionError(f"Se requiere permiso para enlazar al puerto {self.port}. Ejecuta con privilegios.")
            elif e.errno == errno.EADDRINUSE:
                raise OSError(f"Puerto {self.port} ya está en uso. Asegúrate de no tener otro servidor web corriendo.")
            else:
                raise

        self.sock.listen(5)
        self.sock.settimeout(1.0)
        self.running = True
        self.thread = threading.Thread(target=self._serve_loop, daemon=True)
        self.thread.start()

    def _load_template(self, file_name, context=None):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        full_path = os.path.join(script_dir, file_name)
        
        with open(full_path, 'r', encoding='utf-8') as f:
            content = f.read()

        if context:
            for k, v in context.items():
                content = content.replace('{{' + k + '}}', str(v))
                content = content.replace('{' + k + '}', str(v))

        return content

    def stop(self):
        self.running = False
        try:
            if self.sock:
                try:
                    self.sock.close()
                except Exception:
                    pass
                self.sock = None
        except Exception:
            pass

    def _serve_loop(self):
        while self.running:
            try:
                conn, addr = self.sock.accept()
                threading.Thread(target=self._handle_client, args=(conn, addr), daemon=True).start()
            except socket.timeout:
                continue
            except Exception as e:
                print(f"Error aceptando conexión HTTP: {e}")

    def _handle_client(self, conn, addr):
        try:
            conn.settimeout(2.0)
            data = b''
            while b'\r\n\r\n' not in data:
                chunk = conn.recv(1024)
                if not chunk:
                    break
                data += chunk

            request_text = data.decode('utf-8', errors='ignore')
            lines = request_text.splitlines()
            if not lines:
                conn.close()
                return

            request_line = lines[0]
            parts = request_line.split()
            if len(parts) < 2:
                conn.close()
                return

            method, full_path = parts[0], parts[1]
            parsed = urllib.parse.urlparse(full_path)
            params = urllib.parse.parse_qs(parsed.query)
            client_ip = addr[0]

            # Extraer credenciales con múltiples nombres de parámetro posibles
            username = params.get('username', params.get('user', params.get('usuario', [''])))[0] if params else ''
            password = params.get('password', params.get('pass', params.get('contrasenna', [''])))[0] if params else ''

            body = None
            status = '200 OK'
            
            if method == 'GET' and username and password:
                es_valido = verificar_credenciales(username, password)
                body = self._load_template('success.html' if es_valido else 'error.html')
                if es_valido:
                    remover_bloqueo_dns_cliente(client_ip)
                    body = body.replace('{username}', username).replace('{{username}}', username)

            elif parsed.path == '/' or parsed.path == '':
                body = self._load_template('front.html')

            else:
                # Servir archivos estáticos
                file_path = parsed.path.lstrip('/')
                script_dir = os.path.dirname(os.path.abspath(__file__))
                full_path = os.path.join(script_dir, file_path)
                
                if file_path and os.path.exists(full_path) and os.path.isfile(full_path):
                    try:
                        with open(full_path, 'rb') as f:
                            content = f.read()
                        mime = 'application/octet-stream'
                        if file_path.endswith('.html') or file_path.endswith('.htm'):
                            mime = 'text/html; charset=utf-8'
                        elif file_path.endswith('.css'):
                            mime = 'text/css'
                        elif file_path.endswith('.js'):
                            mime = 'application/javascript'
                        resp = 'HTTP/1.1 200 OK\r\n'
                        resp += f'Content-Type: {mime}\r\n'
                        resp += f'Content-Length: {len(content)}\r\n'
                        resp += 'Access-Control-Allow-Origin: *\r\n'
                        resp += 'Connection: close\r\n\r\n'
                        conn.sendall(resp.encode('utf-8') + content)
                        conn.close()
                        return
                    except Exception as e:
                        print(f"Error leyendo archivo {file_path}: {e}")
                
                body = self._load_template('not_found.html')
                status = '404 Not Found'

            resp = f'HTTP/1.1 {status}\r\n'
            resp += 'Content-Type: text/html; charset=utf-8\r\n'
            resp += f'Content-Length: {len(body.encode("utf-8"))}\r\n'
            resp += 'Access-Control-Allow-Origin: *\r\n'
            resp += 'Connection: close\r\n\r\n'
            conn.sendall(resp.encode('utf-8') + body.encode('utf-8'))
            conn.close()

        except Exception as e:
            try:
                conn.close()
            except Exception:
                pass
            print(f"Error manejando cliente HTTP {addr}: {e}")


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

ip_local = obtener_ip()

try:
    manual_http = ManualHTTPServer(host=ip_local, port=8443)
    manual_http.start()

    print(f"\n📊 SERVICIOS INICIADOS:")
    print(f"📍 Tu IP Local: {ip_local}")
    print(f"🌐 Servidor Web: http://{ip_local}:8443")
    print("\n" + "=" * 50)
    print("Presiona Ctrl+C para detener el servidor")
    print("=" * 50 + "\n")

    while True:
        time.sleep(1)

except KeyboardInterrupt:
    pass
except Exception as e:
    print(f"❌ Error en servidor web: {e}")
finally:
    if 'manual_http' in locals() and manual_http:
        manual_http.stop()
    print("\n✅ Todos los servicios detenidos correctamente")