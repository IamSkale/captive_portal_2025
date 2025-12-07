import socket
import time
import threading
import signal
import sys
import urllib.parse
import json
import os
import errno

class SmartDNS:
    def __init__(self, web_ip='127.0.0.1', port=53):
        self.web_ip = web_ip
        self.port = port
        self.sock = None
        self.running = False
        self.dispositivos_bloqueados = {}  # IP -> timestamp
        self.dispositivos_permitidos = set()  # IPs que ya hicieron login
        self.dns_real = "8.8.8.8"  # DNS de Google
        self.dns_alternativo = "1.1.1.1"  # DNS de Cloudflare
        self.lock = threading.Lock()
    
    def setup_socket(self):
        # Si ya existe un socket en esta instancia, cerrarlo antes de crear uno nuevo
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

        # Crear socket UDP para DNS
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except Exception:
            pass

        try:
            self.sock.bind(('', self.port))
        except OSError as e:
            if e.errno == errno.EACCES:
                raise PermissionError(f"Se requiere permiso para enlazar al puerto {self.port}. Ejecuta con privilegios (ej.: sudo).")
            elif e.errno == errno.EADDRINUSE:
                raise OSError(f"Puerto {self.port} ya está en uso. Asegúrate de no tener otro servidor DNS corriendo.")
            else:
                raise

        self.sock.settimeout(1.0)
    
    def manejar_dns_externo(self, data, addr):
        """Consultar a DNS real y reenviar respuesta"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as dns_socket:
                dns_socket.settimeout(2.0)
                dns_socket.sendto(data, (self.dns_real, 53))
                respuesta, _ = dns_socket.recvfrom(512)
                return respuesta
        except:
            return None
    
    def handle_dns_query(self, data, addr):
        """Manejar consulta DNS inteligentemente"""
        try:
            client_ip = addr[0]
            
            with self.lock:
                if client_ip in self.dispositivos_permitidos:
                    respuesta_real = self.manejar_dns_externo(data, addr)
                    if respuesta_real:
                        self.sock.sendto(respuesta_real, addr)
                        print(f"🌐 DNS Real para {client_ip}")
                    return
                else:
                    self.dispositivos_bloqueados[client_ip] = time.time()
                    # Construir respuesta DNS que redirige a nuestro servidor
                    response = data[:2] + b'\x81\x80'  # Copiar ID y marcar como respuesta
                    response += data[4:6] + data[4:6]  # Copiar counts de pregunta y respuesta
                    response += b'\x00\x00\x00\x00'  # Authority y Additional sections vacíos
                    response += data[12:]  # Copiar la pregunta original
                    response += b'\xc0\x0c'  # Puntero a la pregunta (compresión DNS)
                    response += b'\x00\x01\x00\x01'  # Tipo A (IPv4) y clase IN
                    response += b'\x00\x00\x00\x3c'  # TTL de 60 segundos
                    response += b'\x00\x04'  # Longitud de la dirección (4 bytes)
                    response += socket.inet_aton(self.web_ip)  # IP a la que redirigir
                    
                    self.sock.sendto(response, addr)
                    print(f"🔒 DNS Bloqueado para {client_ip}")
                    
        except Exception as e:
            print(f"Error DNS: {e}")
    
    def permitir_dispositivo(self, client_ip):
        """Permitir que un dispositivo use DNS real"""
        with self.lock:
            if client_ip in self.dispositivos_bloqueados:
                del self.dispositivos_bloqueados[client_ip]
            
            self.dispositivos_permitidos.add(client_ip)
            print(f"✅ Permitiendo DNS real para: {client_ip}")
    
    def run(self):
        try:
            self.setup_socket()
            self.running = True
            
            print(f"✅ DNS Inteligente en puerto {self.port}")
            print(f"   DNS Real: {self.dns_real}")
            print(f"   Portal: {self.web_ip}:8443")
            
            while self.running:
                try:
                    data, addr = self.sock.recvfrom(512)
                    if self.running:
                        threading.Thread(
                            target=self.handle_dns_query,
                            args=(data, addr),
                            daemon=True
                        ).start()
                except socket.timeout:
                    continue
        except Exception as e:
            print(f"❌ Error DNS: {e}")
    
    def stop(self):
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

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
    """Servidor HTTP simple hecho con sockets que maneja GET y login por querystring."""
    def __init__(self, host='0.0.0.0', port=8443, dns_server=None):
        self.host = host
        self.port = port
        self.dns_server = dns_server
        self.sock = None
        self.running = False
        self.thread = None

    def start(self):
        # Si ya existe un socket en esta instancia, cerrarlo antes de crear uno nuevo
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
        """Cargar template HTML y reemplazar variables {{key}} por valores del contexto"""
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
                if es_valido and self.dns_server:
                    self.dns_server.permitir_dispositivo(client_ip)
                body = self._load_template('success.html' if es_valido else 'error.html')
                if es_valido:
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
    """Obtener IP local conectando a DNS externo"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

def signal_handler(sig, frame):
    print("\n\n🔴 Señal Ctrl+C recibida. Deteniendo servidores...")
    
    if 'dns_server' in globals():
        dns_server.stop()
    print("👋 Programa terminado")
    sys.exit(0)

# Configurar manejador de señales para Ctrl+C
signal.signal(signal.SIGINT, signal_handler)

ip_local = obtener_ip()

print("=" * 50)
print("🌐 SISTEMA DE REDIRECCIÓN DNS")
print("=" * 50)

dns_server = SmartDNS(web_ip=ip_local, port=53)
# Nota: Para usar puerto 53, ejecutar con: sudo python main.py

dns_thread = threading.Thread(target=dns_server.run, daemon=True)
dns_thread.start()

time.sleep(0.5)  # Esperar a que DNS inicie

# Iniciar servidor web
try:
    manual_http = ManualHTTPServer(host=ip_local, port=8443, dns_server=dns_server)
    manual_http.start()
    print(f"\n📊 SERVICIOS INICIADOS:")
    print(f"📍 Tu IP Local: {ip_local}")
    print(f"🔐 DNS Bloqueador: {ip_local}:53")
    print(f"🌐 Servidor Web: http://{ip_local}:8443")
    print("\n" + "=" * 50)
    print("Para acceder desde otros dispositivos usa la IP de red")
    print("Presiona Ctrl+C para detener ambos servidores")
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
    if 'dns_server' in locals() or 'dns_server' in globals():
        dns_server.stop()
    print("\n✅ Todos los servicios detenidos correctamente")