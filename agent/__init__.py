"""
MQTT Security Agent
UCLA ECE 202C - IoT Security Final Project

An agentic AI system that reads the MQTT protocol specification,
constructs a finite state machine of valid protocol behaviors,
and autonomously launches targeted fuzzing attacks against
software MQTT brokers to discover security vulnerabilities.

Architecture inspired by:
- MGPTFuzz: LLM-guided protocol spec parsing -> FSM extraction
- FUME: Stateful MQTT-specific fuzzing with response feedback
- Burglars' IoT Paradise: MQTT vulnerability taxonomy
- MQTTactic: Authorization logic flaw categories
- FirmAgent: Hybrid fuzzing + LLM agent reasoning loop
"""

__version__ = "0.1.0"
__author__ = "UCLA ECE 202C Final Project"
