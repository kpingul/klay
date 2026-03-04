An AI agent that performs SOC tier 1 level analysis in a Wazuh shop.  

## How it Works

1. **The Agent:** A Python-based **LangGraph** agent running in a Docker container
2. **The Outcome:** When Wazuh detects a threat, the Agent analyzes the alert, determines the risk, and pings a **Slack** channel with the detailed analysis.

## Tech Stack

* **AI Agent:** LangGraph, FastAPI, OpenAI (GPT-4o-mini)

## 🚀 Quick Start

### 1. Requirements

* Docker version v29+
* An OpenAI API Key and Slack Webhook URL.

### 2. Setup


1. Launch the AI Agent:
```bash
docker compose up -d --build

```


2. Configure Wazuh to forward alerts (Level 8+) to your AI Agent's IP on port `8000`.

## 🧪 The Goal

The primary objective of this project is to learn the mechanics of Agentic AI conducting tier 1 level analysis. By placing an agent in a live security environment, I can test how it handles multi-step reasoning, manages "memory" of past events, and interacts with external tools to solve real-world problems.