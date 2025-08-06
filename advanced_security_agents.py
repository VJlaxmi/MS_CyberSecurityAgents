"""
Advanced Multi-Agent Security System with LangGraph
Featuring state management, visualization, and complex workflow orchestration
"""

import os
import json
import asyncio
from typing import TypedDict, List, Annotated, Dict, Any, Optional
from typing_extensions import Annotated
import operator
from datetime import datetime
import hashlib
import matplotlib.pyplot as plt
import networkx as nx
from IPython.display import Image, display

# LangGraph and LangChain imports
from langchain_core.messages import (
    HumanMessage, AIMessage, SystemMessage, ToolMessage, 
    BaseMessage, RemoveMessage
)
from langchain_openai import ChatOpenAI
from langchain_community.tools import tool
from langgraph.graph import StateGraph, START, END
from langgraph.prebuilt import create_react_agent
# Simplified imports - remove checkpoint dependencies for now
# We'll use session-only memory instead of persistent storage
from langchain_core.messages.utils import trim_messages, count_tokens_approximately
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# ============================================================================
# ADVANCED STATE DEFINITIONS
# ============================================================================

class MultiAgentSecurityState(TypedDict):
    """Advanced state for multi-agent security system"""
    messages: Annotated[List[BaseMessage], operator.add]
    security_events: List[Dict[str, Any]]
    threat_analysis: Dict[str, Any]
    iot_device_status: Dict[str, Any]
    network_status: Dict[str, Any]
    recommendations: List[str]
    session_id: str
    timestamp: str
    agent_history: List[str]
    confidence_scores: Dict[str, float]

# ============================================================================
# ADVANCED SECURITY TOOLS
# ============================================================================

@tool
def perform_deep_packet_inspection(packet_data: str) -> str:
    """
    Performs deep packet inspection to analyze packet contents and detect threats.
    
    Args:
        packet_data (str): JSON string containing packet information
            including headers, payload, protocols, etc.
    
    Returns:
        str: Deep packet inspection results with threat analysis
    """
    try:
        data = json.loads(packet_data)
        
        # Deep packet inspection logic
        protocol = data.get('protocol', '')
        payload = data.get('payload', '')
        headers = data.get('headers', {})
        
        threats = []
        confidence = 0.95
        
        # Malware signature detection
        malware_signatures = [
            'cmd.exe', 'powershell', 'wget', 'curl', 'nc ', 'netcat',
            'reverse shell', 'backdoor', 'trojan'
        ]
        
        for signature in malware_signatures:
            if signature.lower() in payload.lower():
                threats.append(f"Malware signature detected: {signature}")
                confidence = 0.90
        
        # Suspicious header analysis
        if 'User-Agent' in headers:
            ua = headers['User-Agent']
            if 'bot' in ua.lower() or 'scanner' in ua.lower():
                threats.append("Suspicious User-Agent detected")
                confidence = 0.85
        
        # Protocol anomaly detection
        if protocol == 'HTTP' and 'POST' in headers.get('method', ''):
            if len(payload) > 10000:
                threats.append("Large HTTP POST payload - potential data exfiltration")
                confidence = 0.88
        
        if threats:
            return f"DEEP PACKET INSPECTION - THREATS: {', '.join(threats)}. Confidence: {confidence:.2%}"
        else:
            return f"Deep packet inspection: No threats detected. Confidence: {confidence:.2%}"
            
    except Exception as e:
        return f"Error in deep packet inspection: {str(e)}"

@tool
def analyze_behavioral_patterns(behavior_data: str) -> str:
    """
    Analyzes behavioral patterns to detect advanced persistent threats (APTs).
    
    Args:
        behavior_data (str): JSON string containing behavioral metrics
            including user activity, system calls, network patterns, etc.
    
    Returns:
        str: Behavioral analysis results with APT detection
    """
    try:
        data = json.loads(behavior_data)
        
        # Behavioral analysis metrics
        user_activity = data.get('user_activity', {})
        system_calls = data.get('system_calls', [])
        network_patterns = data.get('network_patterns', {})
        
        apt_indicators = []
        confidence = 0.95
        
        # Lateral movement detection
        if len(system_calls) > 100 and 'net use' in str(system_calls).lower():
            apt_indicators.append("Potential lateral movement")
            confidence = 0.87
        
        # Data exfiltration patterns
        if network_patterns.get('outbound_volume', 0) > 1000000:
            apt_indicators.append("Large outbound data transfer - potential exfiltration")
            confidence = 0.92
        
        # Privilege escalation patterns
        if 'runas' in str(system_calls).lower() or 'sudo' in str(system_calls).lower():
            apt_indicators.append("Privilege escalation attempts detected")
            confidence = 0.89
        
        # Command and control patterns
        if network_patterns.get('unique_destinations', 0) > 50:
            apt_indicators.append("Multiple C&C connections detected")
            confidence = 0.91
        
        if apt_indicators:
            return f"APT DETECTION: {', '.join(apt_indicators)}. Confidence: {confidence:.2%}"
        else:
            return f"Behavioral analysis: No APT indicators detected. Confidence: {confidence:.2%}"
            
    except Exception as e:
        return f"Error in behavioral analysis: {str(e)}"

@tool
def perform_threat_hunting(threat_indicators: str) -> str:
    """
    Performs proactive threat hunting based on threat intelligence and indicators.
    
    Args:
        threat_indicators (str): JSON string containing threat indicators
            including IP addresses, domains, file hashes, etc.
    
    Returns:
        str: Threat hunting results with detailed findings
    """
    try:
        data = json.loads(threat_indicators)
        
        # Threat hunting logic
        ip_addresses = data.get('ip_addresses', [])
        domains = data.get('domains', [])
        file_hashes = data.get('file_hashes', [])
        
        findings = []
        confidence = 0.95
        
        # Known malicious IPs (simulated threat intelligence)
        malicious_ips = [
            '192.168.1.100', '10.0.0.50', '172.16.0.25'
        ]
        
        for ip in ip_addresses:
            if ip in malicious_ips:
                findings.append(f"Known malicious IP detected: {ip}")
                confidence = 0.98
        
        # Suspicious domain patterns
        for domain in domains:
            if 'malware' in domain.lower() or 'botnet' in domain.lower():
                findings.append(f"Suspicious domain detected: {domain}")
                confidence = 0.90
        
        # Known malicious file hashes
        malicious_hashes = [
            'a1b2c3d4e5f6', 'deadbeef1234', 'badcafe5678'
        ]
        
        for file_hash in file_hashes:
            if file_hash in malicious_hashes:
                findings.append(f"Known malicious file hash detected: {file_hash}")
                confidence = 0.99
        
        if findings:
            return f"THREAT HUNTING FINDINGS: {', '.join(findings)}. Confidence: {confidence:.2%}"
        else:
            return f"Threat hunting: No malicious indicators found. Confidence: {confidence:.2%}"
            
    except Exception as e:
        return f"Error in threat hunting: {str(e)}"

# ============================================================================
# ADVANCED IoT TOOLS
# ============================================================================

@tool
def analyze_iot_network_topology(topology_data: str) -> str:
    """
    Analyzes IoT network topology to identify security vulnerabilities.
    
    Args:
        topology_data (str): JSON string containing network topology information
            including device connections, protocols, routing, etc.
    
    Returns:
        str: Topology analysis with security assessment
    """
    try:
        data = json.loads(topology_data)
        
        # Topology analysis
        devices = data.get('devices', [])
        connections = data.get('connections', [])
        protocols = data.get('protocols', [])
        
        vulnerabilities = []
        confidence = 0.95
        
        # Device enumeration
        if len(devices) > 100:
            vulnerabilities.append("Large device network - potential attack surface")
            confidence = 0.85
        
        # Insecure protocols
        insecure_protocols = ['HTTP', 'FTP', 'Telnet', 'SNMPv1']
        for protocol in protocols:
            if protocol in insecure_protocols:
                vulnerabilities.append(f"Insecure protocol detected: {protocol}")
                confidence = 0.92
        
        # Direct internet connections
        internet_connected = data.get('internet_connected_devices', 0)
        if internet_connected > 10:
            vulnerabilities.append(f"Multiple devices directly connected to internet: {internet_connected}")
            confidence = 0.88
        
        if vulnerabilities:
            return f"TOPOLOGY VULNERABILITIES: {', '.join(vulnerabilities)}. Confidence: {confidence:.2%}"
        else:
            return f"Topology analysis: No major vulnerabilities detected. Confidence: {confidence:.2%}"
            
    except Exception as e:
        return f"Error in topology analysis: {str(e)}"

@tool
def detect_iot_firmware_vulnerabilities(firmware_data: str) -> str:
    """
    Detects vulnerabilities in IoT device firmware.
    
    Args:
        firmware_data (str): JSON string containing firmware information
            including version, vendor, known vulnerabilities, etc.
    
    Returns:
        str: Firmware vulnerability analysis
    """
    try:
        data = json.loads(firmware_data)
        
        # Firmware analysis
        vendor = data.get('vendor', '')
        version = data.get('version', '')
        last_update = data.get('last_update', '')
        
        vulnerabilities = []
        confidence = 0.95
        
        # Known vulnerable firmware versions
        vulnerable_firmware = {
            'router_vendor': {
                '1.0.0': ['CVE-2021-1234', 'CVE-2021-5678'],
                '2.0.0': ['CVE-2022-1234']
            },
            'camera_vendor': {
                '1.5.0': ['CVE-2021-9999'],
                '2.1.0': ['CVE-2022-5678']
            }
        }
        
        if vendor in vulnerable_firmware:
            if version in vulnerable_firmware[vendor]:
                vulns = vulnerable_firmware[vendor][version]
                vulnerabilities.extend(vulns)
                confidence = 0.98
        
        # Outdated firmware
        if last_update < '2023-01-01':
            vulnerabilities.append("Firmware outdated - security patches missing")
            confidence = 0.90
        
        if vulnerabilities:
            return f"FIRMWARE VULNERABILITIES: {', '.join(vulnerabilities)}. Confidence: {confidence:.2%}"
        else:
            return f"Firmware analysis: No vulnerabilities detected. Confidence: {confidence:.2%}"
            
    except Exception as e:
        return f"Error in firmware analysis: {str(e)}"

# ============================================================================
# ADVANCED AGENT NODES
# ============================================================================

def threat_analysis_node(state: MultiAgentSecurityState) -> MultiAgentSecurityState:
    """Node for comprehensive threat analysis"""
    
    llm = ChatOpenAI(model="gpt-4o", temperature=0.1)
    
    # Analyze current security events
    events = state.get('security_events', [])
    analysis = {
        'threat_level': 'LOW',
        'detected_threats': [],
        'recommendations': []
    }
    
    if events:
        # Determine threat level based on events
        high_severity_count = sum(1 for event in events if event.get('severity') == 'HIGH')
        
        if high_severity_count > 5:
            analysis['threat_level'] = 'CRITICAL'
        elif high_severity_count > 2:
            analysis['threat_level'] = 'HIGH'
        elif high_severity_count > 0:
            analysis['threat_level'] = 'MEDIUM'
    
    state['threat_analysis'] = analysis
    state['agent_history'].append('threat_analysis_completed')
    
    return state

def iot_monitoring_node(state: MultiAgentSecurityState) -> MultiAgentSecurityState:
    """Node for IoT device monitoring"""
    
    # Monitor IoT devices
    devices = state.get('iot_device_status', {})
    monitoring_results = {
        'devices_online': 0,
        'anomalies_detected': 0,
        'security_alerts': []
    }
    
    for device_id, device_info in devices.items():
        if device_info.get('status') == 'online':
            monitoring_results['devices_online'] += 1
            
            # Check for anomalies
            if device_info.get('anomaly_score', 0) > 0.7:
                monitoring_results['anomalies_detected'] += 1
                monitoring_results['security_alerts'].append(f"Anomaly detected on device {device_id}")
    
    state['iot_device_status']['monitoring_results'] = monitoring_results
    state['agent_history'].append('iot_monitoring_completed')
    
    return state

def recommendation_engine_node(state: MultiAgentSecurityState) -> MultiAgentSecurityState:
    """Node for generating security recommendations"""
    
    recommendations = []
    
    # Generate recommendations based on threat analysis
    threat_analysis = state.get('threat_analysis', {})
    if threat_analysis.get('threat_level') in ['HIGH', 'CRITICAL']:
        recommendations.append("Immediate security response required - activate incident response procedures")
        recommendations.append("Increase monitoring frequency and alert sensitivity")
    
    # IoT-specific recommendations
    iot_status = state.get('iot_device_status', {})
    if iot_status.get('monitoring_results', {}).get('anomalies_detected', 0) > 0:
        recommendations.append("IoT devices showing anomalies - investigate and isolate affected devices")
    
    # Network recommendations
    network_status = state.get('network_status', {})
    if network_status.get('suspicious_connections', 0) > 10:
        recommendations.append("High number of suspicious connections - review firewall rules")
    
    state['recommendations'] = recommendations
    state['agent_history'].append('recommendations_generated')
    
    return state

# ============================================================================
# ADVANCED GRAPH CONSTRUCTION
# ============================================================================

def create_advanced_security_graph():
    """Creates an advanced multi-agent security graph"""
    
    # Create the graph
    workflow = StateGraph(MultiAgentSecurityState)
    
    # Add nodes
    workflow.add_node("threat_analysis", threat_analysis_node)
    workflow.add_node("iot_monitoring", iot_monitoring_node)
    workflow.add_node("recommendation_engine", recommendation_engine_node)
    
    # Add edges
    workflow.add_edge(START, "threat_analysis")
    workflow.add_edge("threat_analysis", "iot_monitoring")
    workflow.add_edge("iot_monitoring", "recommendation_engine")
    workflow.add_edge("recommendation_engine", END)
    
    # Compile without memory for now (session-only)
    print("Info: Using session-only execution (no persistence)")
    graph = workflow.compile()
    
    return graph

# ============================================================================
# VISUALIZATION FUNCTIONS
# ============================================================================

def visualize_agent_workflow(graph):
    """Visualizes the agent workflow"""
    
    try:
        # Get the graph structure
        graph_structure = graph.get_graph()
        
        # Create visualization
        png_data = graph_structure.draw_mermaid_png()
        
        # Display the image
        display(Image(png_data))
        
    except Exception as e:
        print(f"Visualization error: {str(e)}")
        print("Creating simple text representation...")
        
        # Fallback text representation
        print("""
        Advanced Security Agent Workflow:
        
        START
          ↓
        Threat Analysis Node
          ↓
        IoT Monitoring Node
          ↓
        Recommendation Engine Node
          ↓
        END
        """)

def create_security_dashboard(state: MultiAgentSecurityState):
    """Creates a security dashboard visualization"""
    
    try:
        # Create dashboard data
        threat_level = state.get('threat_analysis', {}).get('threat_level', 'UNKNOWN')
        iot_devices = state.get('iot_device_status', {}).get('monitoring_results', {})
        recommendations = state.get('recommendations', [])
        
        # Create dashboard
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 10))
        
        # Threat Level
        threat_colors = {'LOW': 'green', 'MEDIUM': 'yellow', 'HIGH': 'orange', 'CRITICAL': 'red'}
        ax1.pie([1], colors=[threat_colors.get(threat_level, 'gray')], labels=[threat_level])
        ax1.set_title('Current Threat Level')
        
        # IoT Device Status
        if iot_devices:
            devices_online = iot_devices.get('devices_online', 0)
            anomalies = iot_devices.get('anomalies_detected', 0)
            ax2.bar(['Online Devices', 'Anomalies'], [devices_online, anomalies])
            ax2.set_title('IoT Device Status')
        
        # Agent History
        agent_history = state.get('agent_history', [])
        if agent_history:
            history_counts = {}
            for agent in agent_history:
                history_counts[agent] = history_counts.get(agent, 0) + 1
            
            ax3.bar(history_counts.keys(), history_counts.values())
            ax3.set_title('Agent Activity')
            plt.setp(ax3.xaxis.get_majorticklabels(), rotation=45)
        
        # Recommendations
        ax4.text(0.1, 0.9, 'Security Recommendations:', fontsize=12, fontweight='bold')
        for i, rec in enumerate(recommendations[:5]):  # Show first 5 recommendations
            ax4.text(0.1, 0.8 - i*0.15, f"• {rec}", fontsize=10, wrap=True)
        ax4.set_xlim(0, 1)
        ax4.set_ylim(0, 1)
        ax4.axis('off')
        ax4.set_title('Recommendations')
        
        plt.tight_layout()
        plt.show()
        
    except Exception as e:
        print(f"Dashboard creation error: {str(e)}")

# ============================================================================
# MAIN EXECUTION
# ============================================================================

async def main():
    """Main function to demonstrate the advanced security agents"""
    
    print("Advanced Multi-Agent Security System with LangGraph")
    print("=" * 70)
    
    # Create the advanced graph
    security_graph = create_advanced_security_graph()
    
    # Visualize the workflow
    print("\nAgent Workflow Visualization:")
    visualize_agent_workflow(security_graph)
    
    # Initialize state
    initial_state = {
        "messages": [],
        "security_events": [
            {"type": "DDoS", "severity": "HIGH", "timestamp": datetime.now().isoformat()},
            {"type": "PortScan", "severity": "MEDIUM", "timestamp": datetime.now().isoformat()},
            {"type": "Malware", "severity": "HIGH", "timestamp": datetime.now().isoformat()}
        ],
        "threat_analysis": {},
        "iot_device_status": {
            "device_001": {"status": "online", "anomaly_score": 0.8},
            "device_002": {"status": "online", "anomaly_score": 0.2},
            "device_003": {"status": "offline", "anomaly_score": 0.0}
        },
        "network_status": {
            "suspicious_connections": 15,
            "total_connections": 1000,
            "bandwidth_usage": "75%"
        },
        "recommendations": [],
        "session_id": f"advanced_session_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
        "timestamp": datetime.now().isoformat(),
        "agent_history": [],
        "confidence_scores": {}
    }
    
    # Execute the workflow
    print("\nExecuting Advanced Security Workflow:")
    print("-" * 50)
    
    try:
        result = await security_graph.ainvoke(initial_state)
        
        print("Workflow completed successfully!")
        print(f"Final State Summary:")
        print(f"   - Threat Level: {result['threat_analysis'].get('threat_level', 'UNKNOWN')}")
        print(f"   - IoT Devices Online: {result['iot_device_status'].get('monitoring_results', {}).get('devices_online', 0)}")
        print(f"   - Anomalies Detected: {result['iot_device_status'].get('monitoring_results', {}).get('anomalies_detected', 0)}")
        print(f"   - Recommendations Generated: {len(result['recommendations'])}")
        
        # Create security dashboard
        print("\nSecurity Dashboard:")
        create_security_dashboard(result)
        
        # Show detailed results
        print("\nDetailed Results:")
        print(f"Agent History: {result['agent_history']}")
        print(f"Recommendations: {result['recommendations']}")
        
    except Exception as e:
        print(f"Workflow execution error: {str(e)}")
    
    print("\nAdvanced security agent demonstration completed!")

if __name__ == "__main__":
    asyncio.run(main()) 