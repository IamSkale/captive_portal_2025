#!/bin/bash

# Script para iniciar el portal cautivo completo
# Uso: sudo bash start_portal.sh <interfaz_wifi>

WIFI_INTERFACE=${1:-wlan0}
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "🚀 Iniciando Portal Cautivo..."
echo ""

# Cambiar a directorio del script
cd "$SCRIPT_DIR"

# Hacer scripts ejecutables
chmod +x firewall_portal.sh

# Obtener IP local
LOCAL_IP=$(hostname -I | awk '{print $1}')

if [ -z "$LOCAL_IP" ]; then
    echo "❌ No se puede obtener IP local"
    exit 1
fi

echo "📍 IP Local: $LOCAL_IP"
echo "📡 Interfaz WiFi: $WIFI_INTERFACE"
echo ""

# Configurar firewall
echo "🔒 Configurando firewall..."
sudo bash firewall_portal.sh start "$WIFI_INTERFACE" "$LOCAL_IP" 8443

echo ""
echo "⏳ Esperando 2 segundos..."
sleep 2

# Iniciar servidor Python
echo "🚀 Iniciando servidor Python..."
echo ""

python3 main.py
