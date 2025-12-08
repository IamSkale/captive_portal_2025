#!/bin/bash

# Script para bloquear TODO el tráfico excepto al portal de login
# Uso: sudo bash firewall_portal.sh start <interfaz_wifi> <ip_servidor> <puerto_portal>
# Ejemplo: sudo bash firewall_portal.sh start wlan0 192.168.1.100 8443

ACTION=$1
WIFI_INTERFACE=${2:-wlan0}
SERVER_IP=${3:-$(hostname -I | awk '{print $1}')}
PORTAL_PORT=${4:-8443}

case $ACTION in
    start)
        echo "🔒 Iniciando firewall bloqueador..."
        echo "📡 Interfaz: $WIFI_INTERFACE"
        echo "🔒 Servidor: $SERVER_IP:$PORTAL_PORT"
        echo ""
        
        # Limpiar reglas anteriores
        sudo iptables -F 2>/dev/null || true
        sudo iptables -t nat -F 2>/dev/null || true
        sudo iptables -t mangle -F 2>/dev/null || true
        
        # Habilitar IP forwarding
        sudo sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1
        
        # Establecer políticas por defecto
        sudo iptables -P INPUT ACCEPT
        sudo iptables -P OUTPUT ACCEPT
        sudo iptables -P FORWARD DROP  # ⭐ BLOQUEAMOS TODO POR DEFECTO
        
        # NAT masquerading
        sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE 2>/dev/null || true
        sudo iptables -t nat -A POSTROUTING -o en0 -j MASQUERADE 2>/dev/null || true
        
        # ========== REDIRECCIONAMIENTOS ==========
        # DNS (53) -> 5353
        sudo iptables -t nat -A PREROUTING -i $WIFI_INTERFACE -p udp --dport 53 -j REDIRECT --to-port 5353
        sudo iptables -t nat -A PREROUTING -i $WIFI_INTERFACE -p tcp --dport 53 -j REDIRECT --to-port 5353
        
        # HTTP (80) -> Puerto del portal
        sudo iptables -t nat -A PREROUTING -i $WIFI_INTERFACE -p tcp --dport 80 -j REDIRECT --to-port $PORTAL_PORT
        
        # HTTPS (443) -> Puerto del portal
        sudo iptables -t nat -A PREROUTING -i $WIFI_INTERFACE -p tcp --dport 443 -j REDIRECT --to-port $PORTAL_PORT
        
        # ========== PERMITIR SOLO PORTAL ==========
        # DNS
        sudo iptables -A FORWARD -i $WIFI_INTERFACE -p udp --dport 5353 -j ACCEPT
        sudo iptables -A FORWARD -i $WIFI_INTERFACE -p tcp --dport 5353 -j ACCEPT
        
        # HTTP/HTTPS (redirigidos al portal)
        sudo iptables -A FORWARD -i $WIFI_INTERFACE -p tcp --dport 80 -j ACCEPT
        sudo iptables -A FORWARD -i $WIFI_INTERFACE -p tcp --dport 443 -j ACCEPT
        sudo iptables -A FORWARD -i $WIFI_INTERFACE -p tcp --dport $PORTAL_PORT -j ACCEPT
        
        # Permitir respuestas de conexiones establecidas
        sudo iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
        
        echo "✅ Firewall iniciado:"
        echo "   ✓ Todo tráfico bloqueado excepto:"
        echo "   ✓ DNS (puerto 5353)"
        echo "   ✓ HTTP/HTTPS (puertos 80, 443 → $PORTAL_PORT)"
        echo ""
        echo "📋 Reglas NAT:"
        sudo iptables -t nat -L -n -v 2>/dev/null | grep -E "PREROUTING|5353|80|443"
        echo ""
        ;;
    
    allow)
        CLIENT_IP=$2
        echo "✅ Desbloqueando cliente: $CLIENT_IP"
        
        # Marcar tráfico del cliente
        sudo iptables -t mangle -A FORWARD -s $CLIENT_IP -j MARK --set-mark 1
        sudo iptables -t mangle -A FORWARD -d $CLIENT_IP -j MARK --set-mark 1
        
        # Permitir tráfico marcado
        sudo iptables -A FORWARD -m mark --mark 1 -j ACCEPT
        
        echo "✅ Cliente $CLIENT_IP desbloqueado"
        ;;
    
    stop)
        echo "🧹 Limpiando firewall..."
        sudo iptables -P INPUT ACCEPT
        sudo iptables -P FORWARD ACCEPT
        sudo iptables -P OUTPUT ACCEPT
        sudo iptables -F
        sudo iptables -t nat -F
        sudo iptables -t mangle -F
        sudo sysctl -w net.ipv4.ip_forward=0 > /dev/null 2>&1
        echo "✅ Firewall limpiado"
        ;;
    
    *)
        echo "❌ Uso: sudo bash firewall_portal.sh <start|allow|stop> [opciones]"
        echo ""
        echo "Ejemplos:"
        echo "  sudo bash firewall_portal.sh start wlan0 192.168.1.100 8443"
        echo "  sudo bash firewall_portal.sh allow 192.168.1.150"
        echo "  sudo bash firewall_portal.sh stop"
        ;;
esac
