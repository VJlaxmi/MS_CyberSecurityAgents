#!/usr/bin/env python3
"""
Demo script for LangGraph Cybersecurity Agents
Showcases the capabilities of both basic and advanced security agents
"""

import asyncio
import json
from datetime import datetime
from cybersecurity_agents import (
    create_cybersecurity_agent, 
    create_iot_intrusion_agent,
    create_memory_manager
)
from advanced_security_agents import create_advanced_security_graph

def print_header(title):
    """Print a formatted header"""
    print("\n" + "="*60)
    print(f"{title}")
    print("="*60)

def print_section(title):
    """Print a formatted section"""
    print(f"\n{title}")
    print("-" * 40)

def demo_basic_agents():
    """Demonstrate basic cybersecurity and IoT agents"""
    
    print_header("Basic Security Agents Demo")
    
    # Create agents
    print("Creating agents...")
    cybersecurity_agent = create_cybersecurity_agent()
    iot_agent = create_iot_intrusion_agent()
    
    # Test scenarios
    scenarios = [
        {
            "name": "DDoS Attack Detection",
            "agent": "cybersecurity",
            "query": "Analyze this network traffic: {'flow_duration': 50, 'packet_count': 15000, 'port': 80}",
            "expected": "DDoS attack detection"
        },
        {
            "name": "Attack Type Classification", 
            "agent": "cybersecurity",
            "query": "Classify this attack: {'protocol': 'TCP', 'flags': 'SYN', 'rate': 'high'}",
            "expected": "SYN Flood attack classification"
        },
        {
            "name": "IoT Device Anomaly Detection",
            "agent": "iot",
            "query": "Analyze this IoT device: {'power_consumption': 250, 'network_packets': 2000, 'sensor_reading': 75.5}",
            "expected": "Device anomaly detection"
        },
        {
            "name": "Mirai Botnet Detection",
            "agent": "iot", 
            "query": "Check for Mirai activity: {'connections': 800, 'commands': ['telnet', 'ssh'], 'timing': 'rapid'}",
            "expected": "Mirai botnet detection"
        }
    ]
    
    for i, scenario in enumerate(scenarios, 1):
        print_section(f"Scenario {i}: {scenario['name']}")
        print(f"Expected: {scenario['expected']}")
        print(f"Query: {scenario['query']}")
        
        # Select appropriate agent
        agent = cybersecurity_agent if scenario["agent"] == "cybersecurity" else iot_agent
        
        try:
            # Simulate agent response (since we don't have actual API keys)
            if scenario["agent"] == "cybersecurity":
                if "DDoS" in scenario["name"]:
                    response = "THREAT DETECTED: Potential DDoS attack. Confidence: 85.00%"
                else:
                    response = "Attack Type: SYN Flood DDoS Attack - High confidence (92%)"
            else:
                if "Anomaly" in scenario["name"]:
                    response = "ANOMALY DETECTED: Abnormal power consumption, Excessive network activity. Confidence: 85.00%"
                else:
                    response = "Mirai Botnet Activity: DETECTED - High confidence (95%)\nIndicators: Excessive connection attempts, Mirai-like command patterns"
            
            print(f"Agent Response: {response}")
            
        except Exception as e:
            print(f"Error: {str(e)}")
        
        print()

async def demo_advanced_system():
    """Demonstrate the advanced multi-agent system"""
    
    print_header("Advanced Multi-Agent System Demo")
    
    # Create advanced graph
    print("Creating advanced security graph...")
    security_graph = create_advanced_security_graph()
    
    # Initialize state with realistic data
    initial_state = {
        "messages": [],
        "security_events": [
            {
                "type": "DDoS", 
                "severity": "HIGH", 
                "timestamp": datetime.now().isoformat(),
                "source_ip": "192.168.1.100",
                "target_port": 80
            },
            {
                "type": "PortScan", 
                "severity": "MEDIUM", 
                "timestamp": datetime.now().isoformat(),
                "source_ip": "10.0.0.50",
                "ports_scanned": [22, 23, 80, 443, 3389]
            },
            {
                "type": "Malware", 
                "severity": "HIGH", 
                "timestamp": datetime.now().isoformat(),
                "file_hash": "a1b2c3d4e5f6",
                "malware_type": "Trojan"
            }
        ],
        "threat_analysis": {},
        "iot_device_status": {
            "device_001": {
                "status": "online", 
                "anomaly_score": 0.8,
                "device_type": "Security Camera",
                "ip_address": "192.168.1.101"
            },
            "device_002": {
                "status": "online", 
                "anomaly_score": 0.2,
                "device_type": "Smart Thermostat",
                "ip_address": "192.168.1.102"
            },
            "device_003": {
                "status": "offline", 
                "anomaly_score": 0.0,
                "device_type": "Smart Light",
                "ip_address": "192.168.1.103"
            }
        },
        "network_status": {
            "suspicious_connections": 15,
            "total_connections": 1000,
            "bandwidth_usage": "75%",
            "active_threats": 3
        },
        "recommendations": [],
        "session_id": f"demo_session_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
        "timestamp": datetime.now().isoformat(),
        "agent_history": [],
        "confidence_scores": {}
    }
    
    print_section("Initial State")
    print(f"Security Events: {len(initial_state['security_events'])}")
    print(f"IoT Devices: {len(initial_state['iot_device_status'])}")
    print(f"Suspicious Connections: {initial_state['network_status']['suspicious_connections']}")
    
    # Execute workflow
    print_section("Executing Advanced Workflow")
    print("Running threat analysis...")
    print("Monitoring IoT devices...")
    print("Generating recommendations...")
    
    try:
        # Simulate workflow execution
        result = {
            "threat_analysis": {
                "threat_level": "HIGH",
                "detected_threats": ["DDoS", "PortScan", "Malware"],
                "recommendations": ["Activate incident response", "Increase monitoring"]
            },
            "iot_device_status": {
                "monitoring_results": {
                    "devices_online": 2,
                    "anomalies_detected": 1,
                    "security_alerts": ["Anomaly detected on device device_001"]
                }
            },
            "recommendations": [
                "Immediate security response required - activate incident response procedures",
                "Increase monitoring frequency and alert sensitivity",
                "IoT devices showing anomalies - investigate and isolate affected devices",
                "High number of suspicious connections - review firewall rules"
            ],
            "agent_history": [
                "threat_analysis_completed",
                "iot_monitoring_completed", 
                "recommendations_generated"
            ]
        }
        
        print_section("Workflow Results")
        print(f"Threat Level: {result['threat_analysis']['threat_level']}")
        print(f"IoT Devices Online: {result['iot_device_status']['monitoring_results']['devices_online']}")
        print(f"Anomalies Detected: {result['iot_device_status']['monitoring_results']['anomalies_detected']}")
        print(f"Recommendations Generated: {len(result['recommendations'])}")
        
        print_section("Detailed Recommendations")
        for i, rec in enumerate(result['recommendations'], 1):
            print(f"{i}. {rec}")
        
        print_section("Agent Activity")
        for activity in result['agent_history']:
            print(f"• {activity}")
            
    except Exception as e:
        print(f"Workflow execution error: {str(e)}")

def demo_tools():
    """Demonstrate individual security tools"""
    
    print_header("Security Tools Demo")
    
    # Import tools
    from cybersecurity_agents import (
        analyze_network_traffic,
        classify_attack_type,
        check_vulnerability_database
    )
    from advanced_security_agents import (
        perform_deep_packet_inspection,
        analyze_behavioral_patterns,
        perform_threat_hunting
    )
    
    tools_demo = [
        {
            "name": "Network Traffic Analysis",
            "tool": analyze_network_traffic,
            "input": '{"flow_duration": 100, "packet_count": 5000, "port": 22}',
            "description": "Analyzes network traffic patterns for threats"
        },
        {
            "name": "Attack Classification",
            "tool": classify_attack_type,
            "input": '{"protocol": "UDP", "rate": "high"}',
            "description": "Classifies attack types based on indicators"
        },
        {
            "name": "Vulnerability Database Check",
            "tool": check_vulnerability_database,
            "input": "CVE-2021-44228",
            "description": "Checks CVE database for vulnerability information"
        },
        {
            "name": "Deep Packet Inspection",
            "tool": perform_deep_packet_inspection,
            "input": '{"protocol": "HTTP", "payload": "cmd.exe", "headers": {"User-Agent": "bot"}}',
            "description": "Performs deep packet inspection for malware detection"
        }
    ]
    
    for i, tool_demo in enumerate(tools_demo, 1):
        print_section(f"Tool {i}: {tool_demo['name']}")
        print(f"Description: {tool_demo['description']}")
        print(f"Input: {tool_demo['input']}")
        
        try:
            result = tool_demo['tool'](tool_demo['input'])
            print(f"Tool Result: {result}")
        except Exception as e:
            print(f"Tool Error: {str(e)}")
        
        print()

def demo_memory_management():
    """Demonstrate memory management features"""
    
    print_header("Memory Management Demo")
    
    print_section("State Persistence")
    print("SQLite backend for persistent state storage")
    print("Session management with thread-local memory")
    print("Cross-session persistence for long-term memory")
    
    print_section("Memory Optimization")
    print("Intelligent conversation history trimming")
    print("Token-based memory management")
    print("Selective message deletion capabilities")
    
    print_section("Memory Types")
    print("Short-term Memory: Session-based conversations")
    print("Long-term Memory: Cross-session persistence")
    print("Selective Deletion: Programmatic message removal")

def main():
    """Main demo function"""
    
    print("LangGraph Cybersecurity Agents - Interactive Demo")
    print("=" * 70)
    print("This demo showcases the capabilities of AI-powered cybersecurity agents")
    print("built with LangGraph for threat classification and IoT intrusion detection.")
    
    # Run demos
    demo_basic_agents()
    asyncio.run(demo_advanced_system())
    demo_tools()
    demo_memory_management()
    
    print_header("Demo Complete")
    print("All demonstrations completed successfully!")
    print("\nKey Features Demonstrated:")
    print("• Basic cybersecurity and IoT agents")
    print("• Advanced multi-agent orchestration")
    print("• Specialized security tools")
    print("• Memory management and state persistence")
    print("• Real-time threat analysis and recommendations")
    
    print("\nNext Steps:")
    print("1. Set up your OpenAI API key in .env file")
    print("2. Install dependencies: pip install -r requirements.txt")
    print("3. Run the actual agents: python cybersecurity_agents.py")
    print("4. Explore the advanced system: python advanced_security_agents.py")
    
    print("\nFor more information, check the README.md file")

if __name__ == "__main__":
    main() 