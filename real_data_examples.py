"""
Real Data Integration Examples for LangGraph Cybersecurity Agents
Shows how to connect real data sources to the agents
"""

import json
import requests
import subprocess
import psutil
import time
from datetime import datetime
from typing import Dict, List, Any

# Import our agents
from cybersecurity_agents import create_cybersecurity_agent, create_iot_intrusion_agent
from langchain_core.messages import HumanMessage

# ============================================================================
# REAL NETWORK TRAFFIC DATA SOURCES
# ============================================================================

def get_network_stats_from_system():
    """Get real network statistics from the system"""
    try:
        # Get network I/O statistics
        net_io = psutil.net_io_counters()
        
        # Get network connections
        connections = psutil.net_connections()
        
        # Calculate traffic metrics
        traffic_data = {
            'bytes_sent': net_io.bytes_sent,
            'bytes_recv': net_io.bytes_recv,
            'packets_sent': net_io.packets_sent,
            'packets_recv': net_io.packets_recv,
            'active_connections': len(connections),
            'timestamp': datetime.now().isoformat()
        }
        
        return traffic_data
    except Exception as e:
        print(f"Error getting network stats: {e}")
        return None

def get_network_traffic_from_pcap(pcap_file: str):
    """Get network traffic from pcap file (requires pyshark)"""
    try:
        # This would require: pip install pyshark
        import pyshark
        
        cap = pyshark.FileCapture(pcap_file)
        traffic_data = []
        
        for packet in cap:
            if hasattr(packet, 'tcp'):
                packet_info = {
                    'protocol': 'TCP',
                    'src_port': packet.tcp.srcport,
                    'dst_port': packet.tcp.dstport,
                    'length': packet.length,
                    'timestamp': packet.sniff_timestamp
                }
                traffic_data.append(packet_info)
        
        cap.close()
        return traffic_data
    except ImportError:
        print("pyshark not installed. Install with: pip install pyshark")
        return None
    except Exception as e:
        print(f"Error reading pcap file: {e}")
        return None

def get_network_traffic_from_api(api_endpoint: str):
    """Get network traffic from monitoring API"""
    try:
        response = requests.get(api_endpoint, timeout=10)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"API request failed: {response.status_code}")
            return None
    except Exception as e:
        print(f"Error fetching from API: {e}")
        return None

# ============================================================================
# REAL IoT DEVICE DATA SOURCES
# ============================================================================

def get_iot_device_data_from_sensors():
    """Get real IoT device data from sensors"""
    try:
        # Example: Reading from temperature sensor
        # This would depend on your specific hardware
        import board
        import adafruit_dht
        
        dht = adafruit_dht.DHT22(board.D4)
        
        device_data = {
            'temperature': dht.temperature,
            'humidity': dht.humidity,
            'timestamp': datetime.now().isoformat()
        }
        
        return device_data
    except ImportError:
        print("adafruit_dht not installed. Install with: pip install adafruit-circuitpython-dht")
        return None
    except Exception as e:
        print(f"Error reading sensor data: {e}")
        return None

def get_iot_device_data_from_api(device_api_url: str):
    """Get IoT device data from device API"""
    try:
        response = requests.get(device_api_url, timeout=10)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Device API request failed: {response.status_code}")
            return None
    except Exception as e:
        print(f"Error fetching device data: {e}")
        return None

def get_iot_device_data_from_mqtt(mqtt_broker: str, topic: str):
    """Get IoT device data from MQTT broker"""
    try:
        # This would require: pip install paho-mqtt
        import paho.mqtt.client as mqtt
        
        client = mqtt.Client()
        client.connect(mqtt_broker, 1883, 60)
        
        # Subscribe to topic
        client.subscribe(topic)
        
        # This is a simplified example - you'd need proper async handling
        return {"message": "MQTT data received"}
    except ImportError:
        print("paho-mqtt not installed. Install with: pip install paho-mqtt")
        return None
    except Exception as e:
        print(f"Error connecting to MQTT: {e}")
        return None

# ============================================================================
# REAL SECURITY EVENTS DATA SOURCES
# ============================================================================

def get_security_events_from_logs(log_file_path: str):
    """Get security events from log files"""
    try:
        events = []
        with open(log_file_path, 'r') as f:
            for line in f:
                # Parse security events (example patterns)
                if any(keyword in line.lower() for keyword in ['ddos', 'attack', 'intrusion', 'malware']):
                    event = {
                        'timestamp': datetime.now().isoformat(),
                        'log_line': line.strip(),
                        'severity': 'HIGH' if 'attack' in line.lower() else 'MEDIUM'
                    }
                    events.append(event)
        return events
    except Exception as e:
        print(f"Error reading log file: {e}")
        return None

def get_security_events_from_siem(siem_api_url: str, api_key: str):
    """Get security events from SIEM system"""
    try:
        headers = {'Authorization': f'Bearer {api_key}'}
        response = requests.get(siem_api_url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            return response.json()
        else:
            print(f"SIEM API request failed: {response.status_code}")
            return None
    except Exception as e:
        print(f"Error fetching SIEM data: {e}")
        return None

def get_security_events_from_ids(ids_command: str):
    """Get security events from IDS system"""
    try:
        # Example: Running Snort or similar IDS
        result = subprocess.run(ids_command.split(), capture_output=True, text=True)
        
        if result.returncode == 0:
            # Parse IDS output
            events = []
            for line in result.stdout.split('\n'):
                if 'alert' in line.lower():
                    events.append({
                        'timestamp': datetime.now().isoformat(),
                        'alert': line.strip(),
                        'severity': 'HIGH'
                    })
            return events
        else:
            print(f"IDS command failed: {result.stderr}")
            return None
    except Exception as e:
        print(f"Error running IDS command: {e}")
        return None

# ============================================================================
# REAL-TIME MONITORING WITH AGENTS
# ============================================================================

def monitor_network_traffic_realtime(interval: int = 60):
    """Monitor network traffic in real-time using the cybersecurity agent"""
    
    # Create the agent
    security_agent = create_cybersecurity_agent()
    
    print(f"🔍 Starting real-time network monitoring (checking every {interval} seconds)...")
    
    try:
        while True:
            # Get real network data
            network_data = get_network_stats_from_system()
            
            if network_data:
                # Prepare data for agent
                traffic_summary = {
                    'packet_count': network_data['packets_recv'],
                    'flow_duration': 60,  # 1 minute interval
                    'bytes_transferred': network_data['bytes_recv']
                }
                
                # Send to agent for analysis
                query = f"Analyze this network traffic: {json.dumps(traffic_summary)}"
                result = security_agent.invoke({"messages": [HumanMessage(content=query)]})
                
                print(f"{datetime.now().strftime('%H:%M:%S')} - {result['messages'][-1].content}")
            
            # Wait for next check
            time.sleep(interval)
            
    except KeyboardInterrupt:
        print("\n🛑 Network monitoring stopped by user")

def monitor_iot_devices_realtime(device_urls: List[str], interval: int = 30):
    """Monitor IoT devices in real-time using the IoT agent"""
    
    # Create the agent
    iot_agent = create_iot_intrusion_agent()
    
    print(f"Starting real-time IoT device monitoring (checking every {interval} seconds)...")
    
    try:
        while True:
            for device_url in device_urls:
                # Get real IoT device data
                device_data = get_iot_device_data_from_api(device_url)
                
                if device_data:
                    # Send to agent for analysis
                    query = f"Analyze this IoT device: {json.dumps(device_data)}"
                    result = iot_agent.invoke({"messages": [HumanMessage(content=query)]})
                    
                    print(f"{datetime.now().strftime('%H:%M:%S')} - Device {device_url}: {result['messages'][-1].content}")
            
            # Wait for next check
            time.sleep(interval)
            
    except KeyboardInterrupt:
        print("\n🛑 IoT monitoring stopped by user")

# ============================================================================
# INTEGRATION EXAMPLES
# ============================================================================

def example_real_data_integration():
    """Example of integrating real data sources with the agents"""
    
    print("Real Data Integration Examples")
    print("=" * 50)
    
    # 1. Network Traffic Analysis
    print("\n1. Network Traffic Analysis:")
    network_data = get_network_stats_from_system()
    if network_data:
        print(f"   Real network data: {network_data}")
        
        # Use with agent
        security_agent = create_cybersecurity_agent()
        query = f"Analyze this network traffic: {json.dumps(network_data)}"
        result = security_agent.invoke({"messages": [HumanMessage(content=query)]})
        print(f"   Agent analysis: {result['messages'][-1].content}")
    
    # 2. Security Events from Logs
    print("\n2. Security Events from Logs:")
    # Example: Check system logs for security events
    log_events = get_security_events_from_logs('/var/log/system.log')
    if log_events:
        print(f"   Found {len(log_events)} security events in logs")
    
    # 3. IoT Device Monitoring
    print("\n3. IoT Device Monitoring:")
    # Example: Monitor a smart device
    device_data = {
        'power_consumption': 150,
        'network_packets': 500,
        'sensor_reading': 25.5,
        'timestamp': datetime.now().isoformat()
    }
    print(f"   Simulated IoT data: {device_data}")
    
    # Use with IoT agent
    iot_agent = create_iot_intrusion_agent()
    query = f"Analyze this IoT device: {json.dumps(device_data)}"
    result = iot_agent.invoke({"messages": [HumanMessage(content=query)]})
    print(f"   IoT agent analysis: {result['messages'][-1].content}")

if __name__ == "__main__":
    example_real_data_integration()
    
    # Uncomment to start real-time monitoring
    # monitor_network_traffic_realtime(30)  # Check every 30 seconds
    # monitor_iot_devices_realtime(['http://device1.local/api', 'http://device2.local/api'], 60) 