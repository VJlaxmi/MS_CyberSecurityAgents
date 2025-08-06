# LangGraph Cybersecurity Agents

Advanced AI-powered cybersecurity threat classification and IoT intrusion detection agents built with LangGraph, featuring state management, memory persistence, and multi-agent orchestration.

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![LangGraph](https://img.shields.io/badge/LangGraph-0.6.2+-green.svg)](https://github.com/langchain-ai/langgraph)
[![OpenAI](https://img.shields.io/badge/OpenAI-GPT--4o-orange.svg)](https://openai.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Usage](#usage)
- [Agent Types](#agent-types)
- [Tools and Capabilities](#tools-and-capabilities)
- [Memory Management](#memory-management)
- [Visualization](#visualization)
- [Examples](#examples)
- [Configuration](#configuration)
- [Testing](#testing)
- [Performance](#performance)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgments](#acknowledgments)
- [Support](#support)

## Overview

This project implements sophisticated cybersecurity agents using LangGraph's graph-based framework for building AI agents. The system includes:

- **Cybersecurity Threat Classification Agent**: Detects and classifies network-based threats
- **IoT Intrusion Detection Agent**: Specialized for IoT device anomaly detection
- **Advanced Multi-Agent System**: Orchestrates multiple agents for complex security scenarios
- **Real-time Data Integration**: Connects to live data sources for continuous monitoring
- **Memory Management**: Persistent state across sessions with intelligent cleanup

The system leverages machine learning models from research projects on CIC-IDS2017 dataset, achieving 99.998% accuracy for IoT intrusion detection.

## Features

### Security Capabilities
- **Network Traffic Analysis**: Deep packet inspection and threat detection
- **Attack Classification**: Identifies DDoS, port scanning, brute force, and other attacks
- **IoT Device Monitoring**: Real-time anomaly detection for smart devices
- **Vulnerability Assessment**: CVE database integration and risk scoring
- **Threat Hunting**: Proactive threat intelligence and indicator analysis

### AI Agent Features
- **ReAct Pattern**: Reasoning and acting agents with tool integration
- **State Management**: Persistent memory across sessions
- **Multi-Agent Orchestration**: Complex workflows with specialized agents
- **Custom Tools**: Extensible tool ecosystem for security analysis
- **Memory Trimming**: Intelligent conversation history management

### Visualization & Monitoring
- **Real-time Dashboards**: Security status and threat levels
- **Workflow Visualization**: Agent interaction graphs
- **Performance Metrics**: Accuracy, precision, recall tracking
- **Session Tracking**: Persistent conversation history

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    LangGraph Framework                      │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐     │
│  │ Cybersecurity│    │   IoT Agent │    │ Advanced    │     │
│  │   Agent     │    │             │    │ Multi-Agent │     │
│  └─────────────┘    └─────────────┘    └─────────────┘     │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐     │
│  │ Network     │    │ Device      │    │ Threat      │     │
│  │ Analysis    │    │ Monitoring  │    │ Hunting     │     │
│  └─────────────┘    └─────────────┘    └─────────────┘     │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐     │
│  │ CIC-IDS2017 │    │ Real-time   │    │ Custom      │     │
│  │ Dataset     │    │ Data Sources│    │ Tools       │     │
│  └─────────────┘    └─────────────┘    └─────────────┘     │
└─────────────────────────────────────────────────────────────┘
```

## Installation

### Prerequisites
- Python 3.8 or higher
- OpenAI API key
- Git

### Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/VJlaxmi/MS_CyberSecurityAgents.git
   cd MS_CyberSecurityAgents
   ```

2. **Create virtual environment**
   ```bash
   python3 -m venv cybersecurity_env
   source cybersecurity_env/bin/activate  # On Windows: cybersecurity_env\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment variables**
   ```bash
   cp env_example.txt .env
   # Edit .env file with your OpenAI API key
   ```

## Usage

### Basic Usage

1. **Run the interactive demo**
   ```bash
   python demo.py
   ```

2. **Test with example data**
   ```bash
   python test_example_data.py
   ```

3. **Integrate with real data**
   ```bash
   python quick_start_real_data.py
   ```

### Advanced Usage

```python
from cybersecurity_agents import create_cybersecurity_agent, create_iot_intrusion_agent
from advanced_security_agents import create_advanced_security_graph

# Create basic agents
security_agent = create_cybersecurity_agent()
iot_agent = create_iot_intrusion_agent()

# Create advanced multi-agent system
advanced_graph = create_advanced_security_graph()

# Analyze network traffic
result = security_agent.invoke({
    "messages": [{"role": "user", "content": "Analyze this traffic: {...}"}]
})
```

## Agent Types

### 1. Cybersecurity Threat Classification Agent
- **Purpose**: General network threat detection and classification
- **Capabilities**: DDoS detection, port scanning, brute force attacks
- **Tools**: Network analysis, attack classification, vulnerability checks
- **Accuracy**: 99.85% (Random Forest), 99.00% (Neural Network)

### 2. IoT Intrusion Detection Agent
- **Purpose**: Specialized IoT device anomaly detection
- **Capabilities**: Device behavior analysis, Mirai botnet detection
- **Tools**: IoT protocol analysis, firmware vulnerability detection
- **Accuracy**: 99.998% (Random Forest)

### 3. Advanced Multi-Agent System
- **Purpose**: Orchestrated security workflow management
- **Capabilities**: Multi-stage threat analysis, recommendation generation
- **Components**: Threat analysis, IoT monitoring, recommendation engine
- **Features**: Real-time dashboard, workflow visualization

## Tools and Capabilities

| Tool | Purpose | Input | Output |
|------|---------|-------|--------|
| `analyze_network_traffic` | Network analysis | Traffic data | Threat assessment |
| `classify_attack_type` | Attack classification | Attack indicators | Attack type |
| `check_vulnerability_database` | CVE lookup | CVE ID | Vulnerability details |
| `analyze_iot_device_behavior` | IoT monitoring | Device data | Anomaly detection |
| `detect_mirai_botnet_activity` | Botnet detection | Activity data | Botnet indicators |
| `perform_deep_packet_inspection` | DPI analysis | Packet data | Malware detection |
| `analyze_behavioral_patterns` | Behavioral analysis | Behavior data | APT indicators |
| `perform_threat_hunting` | Threat hunting | Indicators | Threat intelligence |
| `analyze_iot_network_topology` | Topology analysis | Network data | Vulnerability assessment |
| `detect_iot_firmware_vulnerabilities` | Firmware analysis | Firmware data | Vulnerability detection |

## Memory Management

### State Persistence
- **SQLite Backend**: Persistent state storage across sessions
- **Session Management**: Thread-local memory for concurrent operations
- **Cross-session Persistence**: Long-term memory for context retention

### Memory Optimization
- **Intelligent Trimming**: Conversation history management
- **Token-based Management**: Efficient memory usage
- **Selective Deletion**: Programmatic message removal

### Memory Types
- **Short-term Memory**: Session-based conversations
- **Long-term Memory**: Cross-session persistence
- **Selective Deletion**: Programmatic message removal

## Visualization

### Workflow Visualization
```python
from advanced_security_agents import visualize_agent_workflow

# Visualize agent workflow
visualize_agent_workflow(security_graph)
```

### Security Dashboard
```python
from advanced_security_agents import create_security_dashboard

# Create real-time dashboard
create_security_dashboard(result)
```

## Examples

### Example 1: DDoS Attack Detection
```python
# Input
traffic_data = {
    "flow_duration": 50,
    "packet_count": 15000,
    "port": 80,
    "protocol": "HTTP"
}

# Analysis
result = security_agent.invoke({
    "messages": [{"role": "user", "content": f"Analyze: {traffic_data}"}]
})

# Output: "THREAT DETECTED: Potential DDoS attack. Confidence: 85.00%"
```

### Example 2: IoT Device Anomaly
```python
# Input
device_data = {
    "power_consumption": 250,
    "network_packets": 2000,
    "sensor_reading": 75.5,
    "device_type": "security_camera"
}

# Analysis
result = iot_agent.invoke({
    "messages": [{"role": "user", "content": f"Analyze: {device_data}"}]
})

# Output: "ANOMALY DETECTED: Abnormal power consumption. Confidence: 85.00%"
```

### Example 3: Advanced Multi-Agent Workflow
```python
# Initialize state
initial_state = {
    "security_events": [{"type": "DDoS", "severity": "HIGH"}],
    "iot_device_status": {"device_001": {"anomaly_score": 0.8}},
    "network_status": {"suspicious_connections": 15}
}

# Execute workflow
result = await advanced_graph.ainvoke(initial_state)

# Output: Comprehensive threat analysis with recommendations
```

## Configuration

### Environment Variables
```bash
# Required
OPENAI_API_KEY=your_openai_api_key_here

# Optional
LANGCHAIN_API_KEY=your_langchain_api_key_here
LANGCHAIN_TRACING_V2=true
LANGCHAIN_ENDPOINT=https://api.smith.langchain.com
```

### Model Configuration
```python
# Default: GPT-4o
llm = ChatOpenAI(model="gpt-4o", temperature=0.1)

# Alternative models
llm = ChatOpenAI(model="gpt-3.5-turbo", temperature=0.1)
llm = ChatAnthropic(model="claude-3-sonnet-20240229")
```

## Testing

### Run Basic Tests
```bash
# Test all example data
python test_example_data.py

# Test real data integration
python quick_start_real_data.py

# Run interactive demo
python demo.py
```

### Test Individual Components
```python
# Test cybersecurity agent
from cybersecurity_agents import create_cybersecurity_agent
agent = create_cybersecurity_agent()
result = agent.invoke({"messages": [{"role": "user", "content": "Test query"}]})

# Test IoT agent
from cybersecurity_agents import create_iot_intrusion_agent
iot_agent = create_iot_intrusion_agent()
result = iot_agent.invoke({"messages": [{"role": "user", "content": "Test query"}]})
```

## Performance

### Accuracy Metrics
- **IoT Intrusion Detection**: 99.998% (Random Forest)
- **General Threat Classification**: 99.85% (Random Forest)
- **Neural Network Performance**: 99.00% accuracy
- **Multi-class Classification**: Support for 15+ attack types

### Response Times
- **Basic Analysis**: < 1 second
- **Complex Workflows**: 2-5 seconds
- **Real-time Monitoring**: Continuous with 30-second intervals

### Scalability
- **Concurrent Sessions**: Multiple simultaneous agent instances
- **Memory Management**: Automatic cleanup and optimization
- **Tool Integration**: Extensible architecture for new capabilities

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines
- Follow PEP 8 style guidelines
- Add comprehensive docstrings
- Include unit tests for new features
- Update documentation for API changes

---

**Built with love for the cybersecurity community** 
