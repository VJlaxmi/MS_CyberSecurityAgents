#!/usr/bin/env python3
"""
Quick Start Guide: Connecting Real Data Sources to Cybersecurity Agents
"""

import json
import psutil
import requests
import time
from datetime import datetime
from cybersecurity_agents import create_cybersecurity_agent, create_iot_intrusion_agent
from langchain_core.messages import HumanMessage

def get_real_network_data():
    """Get real network data from your system"""
    try:
        # Get real network statistics
        net_io = psutil.net_io_counters()
        connections = psutil.net_connections()
        
        # Get real-time network data
        real_data = {
            'bytes_sent': net_io.bytes_sent,
            'bytes_recv': net_io.bytes_recv,
            'packets_sent': net_io.packets_sent,
            'packets_recv': net_io.packets_recv,
            'active_connections': len(connections),
            'timestamp': datetime.now().isoformat()
        }
        
        return real_data
    except Exception as e:
        print(f"Error getting network data: {e}")
        return None

def get_real_system_data():
    """Get real system performance data"""
    try:
        # Get CPU and memory usage
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        
        # Get disk usage
        disk = psutil.disk_usage('/')
        
        real_data = {
            'cpu_usage': cpu_percent,
            'memory_usage': memory.percent,
            'memory_available': memory.available,
            'disk_usage': disk.percent,
            'disk_free': disk.free,
            'timestamp': datetime.now().isoformat()
        }
        
        return real_data
    except Exception as e:
        print(f"Error getting system data: {e}")
        return None

def analyze_real_network_traffic():
    """Analyze real network traffic with the cybersecurity agent"""
    
    print("Analyzing Real Network Traffic")
    print("=" * 40)
    
    # Create the agent
    security_agent = create_cybersecurity_agent()
    
    # Get real network data
    network_data = get_real_network_data()
    
    if network_data:
        print(f"Real Network Data: {json.dumps(network_data, indent=2)}")
        
        # Prepare data for analysis
        traffic_summary = {
            'packet_count': network_data['packets_recv'],
            'flow_duration': 60,  # 1 minute interval
            'bytes_transferred': network_data['bytes_recv'],
            'active_connections': network_data['active_connections']
        }
        
        # Send to agent for analysis
        query = f"Analyze this network traffic: {json.dumps(traffic_summary)}"
        result = security_agent.invoke({"messages": [HumanMessage(content=query)]})
        
        print(f"\nAgent Analysis: {result['messages'][-1].content}")
    else:
        print("Could not get network data")

def analyze_real_system_behavior():
    """Analyze real system behavior as if it were an IoT device"""
    
    print("\nAnalyzing Real System Behavior (IoT Simulation)")
    print("=" * 50)
    
    # Create the IoT agent
    iot_agent = create_iot_intrusion_agent()
    
    # Get real system data
    system_data = get_real_system_data()
    
    if system_data:
        print(f"Real System Data: {json.dumps(system_data, indent=2)}")
        
        # Prepare data for IoT analysis
        device_summary = {
            'power_consumption': system_data['cpu_usage'],  # CPU as power consumption
            'network_packets': system_data['memory_usage'],  # Memory as network activity
            'sensor_reading': system_data['disk_usage'],  # Disk as sensor reading
            'timestamp': system_data['timestamp']
        }
        
        # Send to agent for analysis
        query = f"Analyze this IoT device: {json.dumps(device_summary)}"
        result = iot_agent.invoke({"messages": [HumanMessage(content=query)]})
        
        print(f"\nIoT Agent Analysis: {result['messages'][-1].content}")
    else:
        print("Could not get system data")

def monitor_realtime(interval=30):
    """Monitor real data in real-time"""
    
    print(f"\nReal-Time Monitoring (checking every {interval} seconds)")
    print("=" * 50)
    print("Press Ctrl+C to stop monitoring")
    
    security_agent = create_cybersecurity_agent()
    iot_agent = create_iot_intrusion_agent()
    
    try:
        while True:
            timestamp = datetime.now().strftime('%H:%M:%S')
            
            # Get real network data
            network_data = get_real_network_data()
            if network_data:
                traffic_summary = {
                    'packet_count': network_data['packets_recv'],
                    'flow_duration': interval,
                    'bytes_transferred': network_data['bytes_recv']
                }
                
                query = f"Analyze this network traffic: {json.dumps(traffic_summary)}"
                result = security_agent.invoke({"messages": [HumanMessage(content=query)]})
                
                print(f"[{timestamp}] Network: {result['messages'][-1].content}")
            
            # Get real system data
            system_data = get_real_system_data()
            if system_data:
                device_summary = {
                    'power_consumption': system_data['cpu_usage'],
                    'network_packets': system_data['memory_usage'],
                    'sensor_reading': system_data['disk_usage']
                }
                
                query = f"Analyze this IoT device: {json.dumps(device_summary)}"
                result = iot_agent.invoke({"messages": [HumanMessage(content=query)]})
                
                print(f"[{timestamp}] System: {result['messages'][-1].content}")
            
            print("-" * 50)
            time.sleep(interval)
            
    except KeyboardInterrupt:
        print("\nMonitoring stopped by user")

def test_external_apis():
    """Test connecting to external APIs (examples)"""
    
    print("\nTesting External API Connections")
    print("=" * 40)
    
    # Example: Test a public API
    try:
        # Test with a public API (replace with your actual API)
        response = requests.get('https://httpbin.org/json', timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"API Connection Test: {data.get('origin', 'Unknown')}")
            
            # Simulate network traffic analysis
            mock_traffic = {
                'packet_count': 1000,
                'flow_duration': 30,
                'source_ip': data.get('origin', 'unknown')
            }
            
            security_agent = create_cybersecurity_agent()
            query = f"Analyze this network traffic: {json.dumps(mock_traffic)}"
            result = security_agent.invoke({"messages": [HumanMessage(content=query)]})
            
            print(f"Analysis: {result['messages'][-1].content}")
        else:
            print(f"API test failed: {response.status_code}")
    except Exception as e:
        print(f"API connection error: {e}")

def main():
    """Main function to demonstrate real data integration"""
    
    print("Quick Start: Real Data Integration")
    print("=" * 50)
    print("This script shows how to connect real data sources to your cybersecurity agents")
    
    # 1. Analyze real network traffic
    analyze_real_network_traffic()
    
    # 2. Analyze real system behavior
    analyze_real_system_behavior()
    
    # 3. Test external APIs
    test_external_apis()
    
    # 4. Ask user if they want real-time monitoring
    print("\n" + "=" * 50)
    print("Next Steps:")
    print("1. Run real-time monitoring: python quick_start_real_data.py --monitor")
    print("2. Connect to your own APIs and data sources")
    print("3. Customize the agents for your specific use case")
    
    # Check if user wants real-time monitoring
    import sys
    if '--monitor' in sys.argv:
        monitor_realtime(30)

if __name__ == "__main__":
    main() 