import http.server
import socketserver
import socket
import threading
import signal
import sys
import urllib.parse
import json
import os

class SmartDNS:
    def __init__(self, web_ip='127.0.0.1', port=5353):
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
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('', self.port))
        self.sock.settimeout(1.0)
    
    def manejar_dns_externo(self, data, addr):
        """Consultar a DNS real y reenviar respuesta"""
        try:
            # Crear socket para consultar DNS real
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
                # Verificar si este dispositivo ya hizo login
                if client_ip in self.dispositivos_permitidos:
                    # CONSULTA DNS REAL
                    respuesta_real = self.manejar_dns_externo(data, addr)
                    if respuesta_real:
                        self.sock.sendto(respuesta_real, addr)
                        print(f"🌐 DNS Real para {client_ip}")
                    return
                else:
                    # BLOQUEAR - redirigir a portal de login
                    self.dispositivos_bloqueados[client_ip] = time.time()
                    
                    # Respuesta DNS que redirige todo a nuestro servidor web
                    response = data[:2] + b'\x81\x80'
                    response += data[4:6] + data[4:6]
                    response += b'\x00\x00\x00\x00'
                    response += data[12:]
                    response += b'\xc0\x0c'
                    response += b'\x00\x01\x00\x01'
                    response += b'\x00\x00\x00\x3c'
                    response += b'\x00\x04'
                    response += socket.inet_aton(self.web_ip)
                    
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
            self.sock.close()

class MyHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def send_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        super().send_headers()

    def do_GET(self):
        """Manejar solicitudes GET (incluyendo login por URL)"""
        # Verificar si la URL contiene credenciales (ej: /?user=juan&pass=123)
        if '?' in self.path:
            # Separar la ruta de los parámetros
            path, query_string = self.path.split('?', 1)
            
            # Parsear los parámetros de la URL
            params = urllib.parse.parse_qs(query_string)
            
            # Extraer credenciales (soportar diferentes nombres)
            username = params.get('username', params.get('user', params.get('usuario', [''])))[0]
            password = params.get('password', params.get('pass', params.get('contrasenna', [''])))[0]
            
            if username and password:
                # Verificar credenciales contra el JSON
                es_valido = self.verificar_credenciales(username, password)
                
                # Mostrar resultado
                self.send_response(200)
                self.send_header('Content-type', 'text/html; charset=utf-8')
                self.end_headers()
                client_ip = self.client_address[0]

                if es_valido:
                    dns_server.permitir_dispositivo(client_ip)
                    html = f'''
                    <!DOCTYPE html>
                    <html>
                    <head>
                        <title>Acceso Concedido</title>
                        <style>
                            body {{ font-family: Arial; text-align: center; padding: 50px; }}
                            .success {{ color: green; font-size: 24px; margin: 20px 0; }}
                            .info {{ background: #f0f0f0; padding: 20px; border-radius: 10px; }}
                        </style>
                    </head>
                    <body>
                        <div class="success">✅ ACCESO CONCEDIDO</div>
                        <div class="info">
                            <p>Bienvenido, <strong>{username}</strong></p>
                            <p>Tu dispositivo ahora tiene acceso a internet.</p>
                        </div>
                        <p><small>Esta sesión será monitoreada para seguridad de la red.</small></p>
                    </body>
                    </html>
                    '''
                else:
                    html = '''
                    <!DOCTYPE html>
                    <html>
                    <head>
                        <title>Acceso Denegado</title>
                        <style>
                            body { font-family: Arial; text-align: center; padding: 50px; }
                            .error { color: red; font-size: 24px; margin: 20px 0; }
                            .warning { background: #ffe6e6; padding: 20px; border-radius: 10px; }
                        </style>
                    </head>
                    <body>
                        <div class="error">❌ ACCESO DENEGADO</div>
                        <div class="warning">
                            <p>Usuario o contraseña incorrectos.</p>
                            <p>Por favor, verifica tus credenciales.</p>
                        </div>
                        <p><a href="/">Volver al login</a></p>
                    </body>
                    </html>
                    '''
                
                self.wfile.write(html.encode('utf-8'))
                return
        
        # Si no hay credenciales en la URL, servir archivos normalmente
        return super().do_GET()
    
    def verificar_credenciales(self, username, password):
        """Verificar credenciales contra un archivo JSON"""
        try:
            # Cargar archivo JSON de usuarios
            if os.path.exists('users.json'):
                with open('users.json', 'r', encoding='utf-8') as f:
                    usuarios = json.load(f)
                
                # Buscar usuario en la lista
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
    """Obtener la IP local de la máquina"""
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
    """Manejador para Ctrl+C"""
    print("\n\n🔴 Señal Ctrl+C recibida. Deteniendo servidores...")
    
    # Detener el servidor DNS si existe
    if 'dns_server' in globals():
        dns_server.stop()
    
    # Salir del programa
    print("👋 Programa terminado")
    sys.exit(0)

# Configurar el manejador de señales para Ctrl+C
signal.signal(signal.SIGINT, signal_handler)

# Obtener IP local
ip_local = obtener_ip()

print("=" * 50)
print("🌐 SISTEMA DE REDIRECCIÓN DNS")
print("=" * 50)

# Crear instancia del servidor DNS
dns_server = SmartDNS(web_ip=ip_local, port=5353)
# Nota: Si quieres usar puerto 53, ejecuta con: sudo python main.py

# Iniciar el servidor DNS en un hilo
dns_thread = threading.Thread(target=dns_server.run, daemon=True)
dns_thread.start()

# Esperar un momento para que el DNS inicie
import time
time.sleep(0.5)

# Iniciar el servidor web
try:
    with socketserver.TCPServer(("", 8443), MyHTTPRequestHandler) as httpd:
        print(f"\n📊 SERVICIOS INICIADOS:")
        print(f"📍 Tu IP Local: {ip_local}")
        print(f"🔐 DNS Bloqueador: {ip_local}:5353")
        print(f"🌐 Servidor Web: http://{ip_local}:8443")
        print("\n" + "=" * 50)
        print("Para acceder desde otros dispositivos usa la IP de red")
        print("Presiona Ctrl+C para detener ambos servidores")
        print("=" * 50 + "\n")
        
        httpd.serve_forever()
        
except KeyboardInterrupt:
    # Esto se ejecutará si hay KeyboardInterrupt dentro del serve_forever()
    pass
except Exception as e:
    print(f"❌ Error en servidor web: {e}")
finally:
    # Asegurarse de que el DNS se detenga incluso si hay errores
    if 'dns_server' in locals() or 'dns_server' in globals():
        dns_server.stop()
    print("\n✅ Todos los servicios detenidos correctamente")