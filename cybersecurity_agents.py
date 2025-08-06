"""
Cybersecurity Threat Classification and IoT Intrusion Detection Agents
Using LangGraph for building specialized security agents with memory and tools
"""

import os
import json
import requests
import pandas as pd
import numpy as np
from typing import TypedDict, List, Annotated, Dict, Any
from typing_extensions import Annotated
import operator
from datetime import datetime
import hashlib

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
# STATE DEFINITIONS
# ============================================================================

class SecurityAgentState(TypedDict):
    """State for security agents with memory management"""
    messages: Annotated[List[BaseMessage], operator.add]
    threat_data: Dict[str, Any]
    analysis_results: Dict[str, Any]
    session_id: str
    timestamp: str

class IoTAgentState(TypedDict):
    """State for IoT intrusion detection agents"""
    messages: Annotated[List[BaseMessage], operator.add]
    iot_data: Dict[str, Any]
    intrusion_results: Dict[str, Any]
    device_info: Dict[str, Any]
    session_id: str
    timestamp: str

# ============================================================================
# CUSTOM TOOLS FOR CYBERSECURITY
# ============================================================================

@tool
def analyze_network_traffic(traffic_data: str) -> str:
    """
    Analyzes network traffic data to identify potential threats.
    
    Args:
        traffic_data (str): JSON string containing network traffic information
            including flow duration, packet counts, port information, etc.
    
    Returns:
        str: Analysis results with threat classification and confidence scores
    
    Example:
        >>> analyze_network_traffic('{"flow_duration": 100, "packet_count": 1000, "port": 80}')
        'Analysis complete: Normal traffic detected with 95% confidence'
    """
    try:
        data = json.loads(traffic_data)
        
        # Simulate threat analysis based on CIC-IDS-2017 patterns
        flow_duration = data.get('flow_duration', 0)
        packet_count = data.get('packet_count', 0)
        port = data.get('port', 0)
        
        # Threat detection logic
        threats = []
        confidence = 0.95
        
        # DDoS detection
        if packet_count > 10000 and flow_duration < 100:
            threats.append("Potential DDoS attack")
            confidence = 0.85
        
        # Port scan detection
        if port in [22, 23, 80, 443, 3389] and packet_count > 100:
            threats.append("Potential port scanning")
            confidence = 0.90
        
        # Brute force detection
        if flow_duration > 1000 and packet_count < 10:
            threats.append("Potential brute force attack")
            confidence = 0.88
        
        if threats:
            return f"THREAT DETECTED: {', '.join(threats)}. Confidence: {confidence:.2%}"
        else:
            return f"Normal traffic detected. Confidence: {confidence:.2%}"
            
    except Exception as e:
        return f"Error analyzing traffic: {str(e)}"

@tool
def classify_attack_type(attack_indicators: str) -> str:
    """
    Classifies the type of cyber attack based on provided indicators.
    
    Args:
        attack_indicators (str): JSON string containing attack indicators
            such as packet patterns, timing, protocols, etc.
    
    Returns:
        str: Attack classification with detailed analysis
    
    Example:
        >>> classify_attack_type('{"protocol": "TCP", "flags": "SYN", "rate": "high"}')
        'Attack Type: SYN Flood DDoS Attack - High confidence (92%)'
    """
    try:
        indicators = json.loads(attack_indicators)
        
        # Attack classification logic
        protocol = indicators.get('protocol', '').upper()
        flags = indicators.get('flags', '').upper()
        rate = indicators.get('rate', '').lower()
        
        attack_types = {
            'SYN_FLOOD': {
                'conditions': ['TCP' in protocol, 'SYN' in flags, 'high' in rate],
                'description': 'SYN Flood DDoS Attack',
                'confidence': 0.92
            },
            'UDP_FLOOD': {
                'conditions': ['UDP' in protocol, 'high' in rate],
                'description': 'UDP Flood Attack',
                'confidence': 0.89
            },
            'ICMP_FLOOD': {
                'conditions': ['ICMP' in protocol, 'high' in rate],
                'description': 'ICMP Flood Attack',
                'confidence': 0.87
            },
            'PORT_SCAN': {
                'conditions': ['TCP' in protocol, 'multiple' in indicators.get('ports', '')],
                'description': 'Port Scanning Attack',
                'confidence': 0.94
            },
            'BRUTE_FORCE': {
                'conditions': ['low' in rate, 'repeated' in indicators.get('pattern', '')],
                'description': 'Brute Force Attack',
                'confidence': 0.91
            }
        }
        
        # Determine attack type
        detected_attack = None
        for attack_name, attack_info in attack_types.items():
            if all(attack_info['conditions']):
                detected_attack = attack_name
                break
        
        if detected_attack:
            attack_info = attack_types[detected_attack]
            return f"Attack Type: {attack_info['description']} - High confidence ({attack_info['confidence']:.0%})"
        else:
            return "Attack Type: Unknown/Unclassified - Requires further analysis"
            
    except Exception as e:
        return f"Error classifying attack: {str(e)}"

@tool
def check_vulnerability_database(cve_id: str) -> str:
    """
    Checks vulnerability database for specific CVE information.
    
    Args:
        cve_id (str): CVE identifier (e.g., 'CVE-2021-44228')
    
    Returns:
        str: Vulnerability information and severity rating
    
    Example:
        >>> check_vulnerability_database('CVE-2021-44228')
        'CVE-2021-44228: Log4Shell vulnerability - Critical severity (9.8/10)'
    """
    try:
        # Simulate vulnerability database lookup
        # In production, this would connect to NVD, CVE databases, etc.
        
        # Mock vulnerability database
        vuln_db = {
            'CVE-2021-44228': {
                'title': 'Log4Shell vulnerability',
                'severity': 'Critical',
                'score': 9.8,
                'description': 'Remote code execution vulnerability in Apache Log4j'
            },
            'CVE-2021-34527': {
                'title': 'PrintNightmare vulnerability',
                'severity': 'Critical',
                'score': 9.0,
                'description': 'Remote code execution in Windows Print Spooler'
            },
            'CVE-2020-1472': {
                'title': 'Zerologon vulnerability',
                'severity': 'Critical',
                'score': 10.0,
                'description': 'Netlogon elevation of privilege vulnerability'
            }
        }
        
        if cve_id in vuln_db:
            vuln = vuln_db[cve_id]
            return f"{cve_id}: {vuln['title']} - {vuln['severity']} severity ({vuln['score']}/10)\nDescription: {vuln['description']}"
        else:
            return f"CVE {cve_id} not found in database or requires manual verification"
            
    except Exception as e:
        return f"Error checking vulnerability database: {str(e)}"

# ============================================================================
# CUSTOM TOOLS FOR IoT INTRUSION DETECTION
# ============================================================================

@tool
def analyze_iot_device_behavior(device_data: str) -> str:
    """
    Analyzes IoT device behavior patterns to detect anomalies.
    
    Args:
        device_data (str): JSON string containing IoT device metrics
            including power consumption, network activity, sensor readings, etc.
    
    Returns:
        str: Behavior analysis with anomaly detection results
    
    Example:
        >>> analyze_iot_device_behavior('{"power_consumption": 150, "network_packets": 500, "sensor_reading": 25.5}')
        'Device behavior: Normal - No anomalies detected (98% confidence)'
    """
    try:
        data = json.loads(device_data)
        
        # IoT device behavior analysis
        power_consumption = data.get('power_consumption', 0)
        network_packets = data.get('network_packets', 0)
        sensor_reading = data.get('sensor_reading', 0)
        
        anomalies = []
        confidence = 0.98
        
        # Power consumption anomaly
        if power_consumption > 200 or power_consumption < 50:
            anomalies.append("Abnormal power consumption")
            confidence = 0.85
        
        # Network activity anomaly
        if network_packets > 1000:
            anomalies.append("Excessive network activity")
            confidence = 0.90
        
        # Sensor reading anomaly
        if sensor_reading > 100 or sensor_reading < -50:
            anomalies.append("Sensor reading out of normal range")
            confidence = 0.88
        
        if anomalies:
            return f"ANOMALY DETECTED: {', '.join(anomalies)}. Confidence: {confidence:.2%}"
        else:
            return f"Device behavior: Normal - No anomalies detected ({confidence:.0%} confidence)"
            
    except Exception as e:
        return f"Error analyzing device behavior: {str(e)}"

@tool
def detect_mirai_botnet_activity(activity_data: str) -> str:
    """
    Detects Mirai botnet activity patterns in IoT devices.
    
    Args:
        activity_data (str): JSON string containing device activity patterns
            including connection attempts, command patterns, etc.
    
    Returns:
        str: Mirai botnet detection results
    
    Example:
        >>> detect_mirai_botnet_activity('{"connections": 1000, "commands": ["telnet", "ssh"], "timing": "rapid"}')
        'Mirai Botnet Activity: DETECTED - High confidence (95%)'
    """
    try:
        data = json.loads(activity_data)
        
        # Mirai botnet detection patterns
        connections = data.get('connections', 0)
        commands = data.get('commands', [])
        timing = data.get('timing', '')
        
        mirai_indicators = []
        confidence = 0.95
        
        # Connection pattern analysis
        if connections > 500:
            mirai_indicators.append("Excessive connection attempts")
        
        # Command pattern analysis
        mirai_commands = ['telnet', 'ssh', 'ftp', 'http']
        if any(cmd in commands for cmd in mirai_commands):
            mirai_indicators.append("Mirai-like command patterns")
        
        # Timing analysis
        if timing == 'rapid':
            mirai_indicators.append("Rapid scanning behavior")
        
        if mirai_indicators:
            return f"Mirai Botnet Activity: DETECTED - High confidence ({confidence:.0%})\nIndicators: {', '.join(mirai_indicators)}"
        else:
            return f"Mirai Botnet Activity: Not detected - Normal behavior ({confidence:.0%} confidence)"
            
    except Exception as e:
        return f"Error detecting Mirai activity: {str(e)}"

@tool
def analyze_iot_protocol_vulnerabilities(protocol_data: str) -> str:
    """
    Analyzes IoT protocol vulnerabilities and security weaknesses.
    
    Args:
        protocol_data (str): JSON string containing protocol information
            including protocol type, version, encryption status, etc.
    
    Returns:
        str: Protocol vulnerability analysis
    
    Example:
        >>> analyze_iot_protocol_vulnerabilities('{"protocol": "MQTT", "version": "3.1", "encryption": false}')
        'Protocol: MQTT v3.1 - VULNERABLE: No encryption detected'
    """
    try:
        data = json.loads(protocol_data)
        
        protocol = data.get('protocol', '').upper()
        version = data.get('version', '')
        encryption = data.get('encryption', False)
        
        # Protocol vulnerability database
        protocol_vulns = {
            'MQTT': {
                '3.1': ['No encryption by default', 'Weak authentication'],
                '3.1.1': ['Limited security features'],
                '5.0': ['Improved security but optional encryption']
            },
            'COAP': {
                'default': ['DTLS required for security', 'No encryption by default']
            },
            'HTTP': {
                '1.0': ['No encryption', 'Vulnerable to MITM'],
                '1.1': ['Requires HTTPS for security'],
                '2.0': ['Requires HTTPS for security']
            }
        }
        
        vulnerabilities = []
        
        if protocol in protocol_vulns:
            if version in protocol_vulns[protocol]:
                vulnerabilities.extend(protocol_vulns[protocol][version])
            elif 'default' in protocol_vulns[protocol]:
                vulnerabilities.extend(protocol_vulns[protocol]['default'])
        
        if not encryption:
            vulnerabilities.append("No encryption detected")
        
        if vulnerabilities:
            return f"Protocol: {protocol} v{version} - VULNERABLE: {', '.join(vulnerabilities)}"
        else:
            return f"Protocol: {protocol} v{version} - SECURE: No known vulnerabilities detected"
            
    except Exception as e:
        return f"Error analyzing protocol vulnerabilities: {str(e)}"

# ============================================================================
# AGENT BUILDERS
# ============================================================================

def create_cybersecurity_agent():
    """Creates a cybersecurity threat classification agent"""
    
    # Initialize LLM
    llm = ChatOpenAI(model="gpt-4o", temperature=0.1)
    
    # Define tools
    tools = [
        analyze_network_traffic,
        classify_attack_type,
        check_vulnerability_database
    ]
    
    # Create ReAct agent
    agent = create_react_agent(
        model=llm,
        tools=tools,
        name="cybersecurity_agent",
        prompt="""You are a specialized cybersecurity threat classification agent. 
        Your role is to analyze network traffic, classify attack types, and provide 
        detailed security assessments. Always use the available tools to perform 
        thorough analysis and provide actionable security recommendations.
        
        Key responsibilities:
        1. Analyze network traffic patterns for threats
        2. Classify attack types with confidence levels
        3. Check vulnerability databases for relevant CVEs
        4. Provide detailed security reports and recommendations
        
        Be thorough, accurate, and provide specific technical details in your analysis."""
    )
    
    return agent

def create_iot_intrusion_agent():
    """Creates an IoT intrusion detection agent"""
    
    # Initialize LLM
    llm = ChatOpenAI(model="gpt-4o", temperature=0.1)
    
    # Define tools
    tools = [
        analyze_iot_device_behavior,
        detect_mirai_botnet_activity,
        analyze_iot_protocol_vulnerabilities
    ]
    
    # Create ReAct agent
    agent = create_react_agent(
        model=llm,
        tools=tools,
        name="iot_intrusion_agent",
        prompt="""You are a specialized IoT intrusion detection agent. 
        Your role is to monitor IoT devices, detect anomalies, identify botnet 
        activity, and analyze protocol vulnerabilities.
        
        Key responsibilities:
        1. Analyze IoT device behavior patterns
        2. Detect Mirai and other botnet activities
        3. Identify protocol vulnerabilities and security weaknesses
        4. Provide IoT-specific security recommendations
        
        Focus on IoT-specific threats and provide detailed technical analysis."""
    )
    
    return agent

# ============================================================================
# MEMORY MANAGEMENT
# ============================================================================

def create_memory_manager():
    """Creates a memory manager for persistent state"""
    
    # For now, return None to use session-only memory
    # This avoids import issues with checkpoint modules
    print("Info: Using session-only memory (no persistence)")
    return None

def trim_conversation_history(state: Dict[str, Any], max_tokens: int = 1000) -> Dict[str, Any]:
    """Trims conversation history to manage memory"""
    
    if "messages" in state and len(state["messages"]) > 10:
        trimmed = trim_messages(
            messages=state["messages"],
            strategy="first",
            token_counter=count_tokens_approximately,
            max_tokens=max_tokens
        )
        state["messages"] = trimmed
    
    return state

# ============================================================================
# MAIN EXECUTION
# ============================================================================

def main():
    """Main function to demonstrate the cybersecurity agents"""
    
    print("Cybersecurity Threat Classification and IoT Intrusion Detection Agents")
    print("=" * 70)
    
    # Create agents
    cybersecurity_agent = create_cybersecurity_agent()
    iot_agent = create_iot_intrusion_agent()
    
    # Create memory manager
    memory = create_memory_manager()
    
    # Example usage scenarios
    scenarios = [
        {
            "agent": "cybersecurity",
            "query": "Analyze this network traffic: {'flow_duration': 50, 'packet_count': 15000, 'port': 80}",
            "description": "DDoS Attack Detection"
        },
        {
            "agent": "cybersecurity", 
            "query": "Classify this attack: {'protocol': 'TCP', 'flags': 'SYN', 'rate': 'high'}",
            "description": "Attack Type Classification"
        },
        {
            "agent": "iot",
            "query": "Analyze this IoT device: {'power_consumption': 250, 'network_packets': 2000, 'sensor_reading': 75.5}",
            "description": "IoT Device Anomaly Detection"
        },
        {
            "agent": "iot",
            "query": "Check for Mirai activity: {'connections': 800, 'commands': ['telnet', 'ssh'], 'timing': 'rapid'}",
            "description": "Mirai Botnet Detection"
        }
    ]
    
    for i, scenario in enumerate(scenarios, 1):
        print(f"\nScenario {i}: {scenario['description']}")
        print("-" * 50)
        
        # Select appropriate agent
        agent = cybersecurity_agent if scenario["agent"] == "cybersecurity" else iot_agent
        
        # Create session ID
        session_id = f"session_{i}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Invoke agent with memory
        try:
            result = agent.invoke(
                {"messages": [HumanMessage(content=scenario["query"])]},
                {"configurable": {"thread_id": session_id}}
            )
            
            print(f"Agent Response:")
            print(result["messages"][-1].content)
            
        except Exception as e:
            print(f"Error: {str(e)}")
    
    print("\nAgent demonstration completed!")

if __name__ == "__main__":
    main() 