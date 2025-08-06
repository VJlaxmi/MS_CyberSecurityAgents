#!/usr/bin/env python3
"""
Test Example Data with Cybersecurity Agents
Shows how to use the provided example data files
"""

import json
import os
from cybersecurity_agents import create_cybersecurity_agent, create_iot_intrusion_agent
from advanced_security_agents import create_advanced_security_graph
from langchain_core.messages import HumanMessage

def test_network_traffic_data():
    """Test network traffic data with cybersecurity agent"""
    
    print("Testing Network Traffic Data")
    print("=" * 40)
    
    # Load example network data
    try:
        with open('example_data/network_traffic.json', 'r') as f:
            network_data = json.load(f)
        
        print(f"Network Data: {json.dumps(network_data, indent=2)}")
        
        # Create agent and analyze
        security_agent = create_cybersecurity_agent()
        query = f"Analyze this network traffic: {json.dumps(network_data)}"
        result = security_agent.invoke({"messages": [HumanMessage(content=query)]})
        
        print(f"\nAnalysis: {result['messages'][-1].content}")
        
    except FileNotFoundError:
        print("Network traffic data file not found")
    except Exception as e:
        print(f"Error: {e}")

def test_iot_device_data():
    """Test IoT device data with IoT agent"""
    
    print("\nTesting IoT Device Data")
    print("=" * 40)
    
    # Load example IoT data
    try:
        with open('example_data/iot_device.json', 'r') as f:
            iot_data = json.load(f)
        
        print(f"IoT Device Data: {json.dumps(iot_data, indent=2)}")
        
        # Create agent and analyze
        iot_agent = create_iot_intrusion_agent()
        query = f"Analyze this IoT device: {json.dumps(iot_data)}"
        result = iot_agent.invoke({"messages": [HumanMessage(content=query)]})
        
        print(f"\nAnalysis: {result['messages'][-1].content}")
        
    except FileNotFoundError:
        print("IoT device data file not found")
    except Exception as e:
        print(f"Error: {e}")

def test_security_events_data():
    """Test security events data with advanced agent"""
    
    print("\nTesting Security Events Data")
    print("=" * 40)
    
    # Load example security events data
    try:
        with open('example_data/security_events.json', 'r') as f:
            security_data = json.load(f)
        
        print(f"Security Events: {len(security_data['security_events'])} events")
        print(f"IoT Devices: {len(security_data['iot_device_status'])} devices")
        print(f"Network Status: {security_data['network_status']['suspicious_connections']} suspicious connections")
        
        # Create advanced agent and analyze
        advanced_graph = create_advanced_security_graph()
        
        # Prepare initial state
        initial_state = {
            "messages": [],
            "security_events": security_data['security_events'],
            "threat_analysis": {},
            "iot_device_status": security_data['iot_device_status'],
            "network_status": security_data['network_status'],
            "recommendations": [],
            "session_id": f"test_session_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "timestamp": datetime.now().isoformat(),
            "agent_history": [],
            "confidence_scores": {}
        }
        
        # Run analysis
        result = advanced_graph.invoke(initial_state)
        
        print(f"\nAdvanced Analysis Results:")
        print(f"   Threat Level: {result['threat_analysis'].get('threat_level', 'UNKNOWN')}")
        print(f"   IoT Devices Online: {result['iot_device_status'].get('monitoring_results', {}).get('devices_online', 0)}")
        print(f"   Anomalies Detected: {result['iot_device_status'].get('monitoring_results', {}).get('anomalies_detected', 0)}")
        print(f"   Recommendations: {len(result['recommendations'])}")
        
        for i, rec in enumerate(result['recommendations'], 1):
            print(f"   {i}. {rec}")
        
    except FileNotFoundError:
        print("Security events data file not found")
    except Exception as e:
        print(f"Error: {e}")

def create_custom_data():
    """Show how to create custom data"""
    
    print("\nCreating Custom Data")
    print("=" * 40)
    
    # Example: Create custom network data
    custom_network_data = {
        "flow_duration": 30,
        "packet_count": 20000,  # High packet count - potential DDoS
        "port": 22,             # SSH port
        "bytes_transferred": 5000000,
        "source_ip": "10.0.0.100",
        "destination_ip": "192.168.1.50",
        "protocol": "TCP",
        "timestamp": "2025-08-05T17:00:00.000000"
    }
    
    print(f"Custom Network Data: {json.dumps(custom_network_data, indent=2)}")
    
    # Analyze custom data
    security_agent = create_cybersecurity_agent()
    query = f"Analyze this network traffic: {json.dumps(custom_network_data)}"
    result = security_agent.invoke({"messages": [HumanMessage(content=query)]})
    
    print(f"\nCustom Data Analysis: {result['messages'][-1].content}")
    
    # Example: Create custom IoT data
    custom_iot_data = {
        "power_consumption": 300,  # High power consumption
        "network_packets": 3000,   # High network activity
        "sensor_reading": 150.5,   # Abnormal sensor reading
        "device_type": "smart_camera",
        "ip_address": "192.168.1.200",
        "timestamp": "2025-08-05T17:00:00.000000"
    }
    
    print(f"\nCustom IoT Data: {json.dumps(custom_iot_data, indent=2)}")
    
    # Analyze custom IoT data
    iot_agent = create_iot_intrusion_agent()
    query = f"Analyze this IoT device: {json.dumps(custom_iot_data)}"
    result = iot_agent.invoke({"messages": [HumanMessage(content=query)]})
    
    print(f"\nCustom IoT Analysis: {result['messages'][-1].content}")

def main():
    """Main function to test all example data"""
    
    print("Testing Example Data with Cybersecurity Agents")
    print("=" * 60)
    
    # Check if example data directory exists
    if not os.path.exists('example_data'):
        print("Example data directory not found. Creating it...")
        os.makedirs('example_data', exist_ok=True)
        print("Created example_data directory")
        print("Please add your data files to the example_data directory")
        return
    
    # Test all example data
    test_network_traffic_data()
    test_iot_device_data()
    test_security_events_data()
    create_custom_data()
    
    print("\n" + "=" * 60)
    print("All tests completed!")
    print("\nSummary of Data You Can Provide:")
    print("1. Network Traffic: flow_duration, packet_count, port, etc.")
    print("2. IoT Devices: power_consumption, network_packets, sensor_reading, etc.")
    print("3. Security Events: DDoS, PortScan, Malware, etc.")
    print("\nNext Steps:")
    print("1. Modify the example data files with your real data")
    print("2. Create your own custom data files")
    print("3. Connect to real data sources using the provided examples")

if __name__ == "__main__":
    from datetime import datetime
    main() 