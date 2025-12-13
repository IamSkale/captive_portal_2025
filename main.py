import time
import aux_functions
import my_http_server

ip_local = aux_functions.get_ip()

try:
    manual_http = my_http_server.ManualHTTPServer(host=ip_local, port=8443)
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