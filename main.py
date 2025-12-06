import http.server
import socketserver
import socket
import threading
import signal
import sys
import urllib.parse
import json
import os


class SimpleDNS:
    def __init__(self, block_ip='127.0.0.1', port=53):
        self.block_ip = block_ip
        self.port = port
        self.sock = None
        self.running = False  # Bandera para controlar el bucle
        self.lock = threading.Lock()
    
    def setup_socket(self):
        """Configurar el socket DNS"""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('', self.port))
        self.sock.settimeout(1.0)  # Timeout para poder verificar self.running
    
    def handle_dns_query(self, data, addr):
        """Manejar una consulta DNS individual"""
        try:
            # Respuesta DNS simple que redirige todo a block_ip
            response = data[:2] + b'\x81\x80'  # Transaction ID + Flags
            response += data[4:6] + data[4:6]  # Questions + Answer RRs
            response += b'\x00\x00\x00\x00'    # Authority + Additional RRs
            response += data[12:]              # Original query
            response += b'\xc0\x0c'            # Pointer to domain name
            response += b'\x00\x01\x00\x01'    # Type A, Class IN
            response += b'\x00\x00\x00\x3c'    # TTL 60 seconds
            response += b'\x00\x04'            # Data length
            response += socket.inet_aton(self.block_ip)  # IP address
            
            with self.lock:
                if self.sock and self.running:
                    self.sock.sendto(response, addr)
        except Exception as e:
            if self.running:
                print(f"Error en consulta DNS: {e}")
    
    def run(self):
        """Método principal que se ejecuta en el hilo"""
        try:
            self.setup_socket()
            self.running = True
            print(f"✅ Servidor DNS bloqueador ejecutándose en puerto {self.port}")
            
            while self.running:
                try:
                    data, addr = self.sock.recvfrom(512)
                    if self.running:
                        # Procesar en un hilo separado
                        threading.Thread(
                            target=self.handle_dns_query, 
                            args=(data, addr),
                            daemon=True
                        ).start()
                except socket.timeout:
                    continue  # Timeout normal, verificar si seguimos running
                except Exception as e:
                    if self.running:
                        print(f"Error recibiendo datos DNS: {e}")
        except Exception as e:
            print(f"❌ Error iniciando servidor DNS: {e}")
            if self.port == 53:
                print("   Nota: El puerto 53 requiere permisos de administrador (sudo)")
    
    def stop(self):
        """Detener el servidor DNS de forma segura"""
        print("\n🛑 Deteniendo servidor DNS...")
        self.running = False
        
        # Cerrar el socket para desbloquear recvfrom()
        if self.sock:
            try:
                # Enviar un paquete dummy para desbloquear
                temp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                temp_sock.sendto(b'', ('127.0.0.1', self.port))
                temp_sock.close()
            except:
                pass
            
            # Cerrar el socket principal
            self.sock.close()
            self.sock = None
        
        print("✅ Servidor DNS detenido")

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
                
                if es_valido:
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
dns_server = SimpleDNS(ip_local, 5353)  # Cambiado a puerto 5353 para no requerir sudo
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