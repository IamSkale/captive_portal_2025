import http.server
import socketserver
import socket

class MyHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        super().end_headers()

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

with socketserver.TCPServer(("", 8443), MyHTTPRequestHandler) as httpd:
    ip_local = obtener_ip()
    print(f"Servidor ejecutándose en:")
    print(f"Local: http://localhost:{8443}")
    print(f"Red: http://{ip_local}:{8443}")
    print("Para acceder desde otros dispositivos usa la IP de red")
    print("Presiona Ctrl+C para detener el servidor")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nServidor detenido")