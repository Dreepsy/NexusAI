from transformers import AutoModelForCausalLM, AutoTokenizer, pipeline
import torch
import yaml
import os
import requests
from ..core.config import get_config, get_logger
from ..core.http_client import get_http_client

# Get configuration and logger
config = get_config()
logger = get_logger()
http_client = get_http_client()

# Security best practice: Load API key from environment variable first
API_KEY = config.get_api_key('deepseek')

# Get DeepSeek configuration
deepseek_cfg = config.get('deepseek', {})

# If the environment variable is not set, fall back to config (not recommended for production)
if not API_KEY:
    API_KEY = deepseek_cfg.get('api_key')
    if API_KEY:
        logger.warning("DeepSeek API key loaded from config. For better security, set it as the DEEPSEEK_API_KEY environment variable.")

API_MODEL = deepseek_cfg.get('model', 'deepseek-chat')
LOCAL_MODEL_NAME = "deepseek-ai/deepseek-llm-7b-chat"

def generate_vuln_summary(service, version, cve_list):
    """
    Developer Note:
    This function generates a vulnerability summary and exploitation guide for a given service/version and list of CVEs.
    If you have a DeepSeek API key as the DEEPSEEK_API_KEY environment variable, it will use the DeepSeek cloud API (fast, no GPU required).
    If not, it will try to run the model locally (requires a good GPU and the model weights).

    Args:
        service (str): The service name (e.g., 'apache')
        version (str): The service version (e.g., '2.4.49')
        cve_list (list of dict): Each dict should have 'id' and 'description' keys
    Returns:
        str: AI-generated summary and exploitation guide
    """
    prompt = (
        f"You are a cybersecurity expert. Given the following service and version:\n"
        f"Service: {service}\nVersion: {version}\n"
        f"Here are related CVEs:\n"
    )
    for cve in cve_list:
        prompt += f"- {cve['id']}: {cve['description']}\n"
    prompt += (
        "\nSummarize the main vulnerabilities, and provide a step-by-step exploitation guide if possible. "
        "Also, suggest remediation steps."
    )
    
    # If the user has set an API key, use the DeepSeek API (recommended for most devs)
    if API_KEY:
        headers = {"Authorization": f"Bearer {API_KEY}"}
        payload = {
            "model": API_MODEL,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 512,
            "temperature": 0.2
        }
        try:
            response = http_client.post(
                "https://api.deepseek.com/v1/chat/completions",
                data=payload,
                headers=headers
            )
            
            if response.get('error'):
                return f"[DeepSeek API Error] {response.get('message', 'Unknown error')}"
            
            data = response.get('data', {})
            if 'choices' in data and len(data['choices']) > 0:
                return data['choices'][0]['message']['content']
            else:
                return f"[DeepSeek API Error] Unexpected response format"
                
        except Exception as e:
            logger.error("DeepSeek API request failed", error=str(e))
            return f"[DeepSeek API Connection Error] {e}"
    
    # If no API key, provide a fallback summary instead of downloading large model
    logger.info("No DeepSeek API key provided, using fallback summary")
    
    # Generate a simple but informative fallback summary
    fallback_summary = f"""
🔍 VULNERABILITY ANALYSIS SUMMARY

Service: {service}
Version: {version}

📋 DETECTED VULNERABILITIES:
"""
    
    for cve in cve_list:
        fallback_summary += f"• {cve['id']}: {cve['description']}\n"
    
    fallback_summary += f"""
⚠️  RISK ASSESSMENT:
• Multiple critical vulnerabilities detected
• Immediate patching recommended
• Consider service isolation

🛡️  RECOMMENDED ACTIONS:
• Update {service} to latest version
• Apply security patches immediately
• Review access controls
• Monitor for suspicious activity
• Consider implementing additional security measures

💡 Note: For detailed AI-powered analysis, set the DEEPSEEK_API_KEY environment variable.
"""
    
    return fallback_summary

# Example usage for developers: run this file directly to test DeepSeek integration
if __name__ == "__main__":
    cve_list = [
        {"id": "CVE-2021-41773", "description": "Path traversal vulnerability in Apache HTTP Server 2.4.49."},
        {"id": "CVE-2021-42013", "description": "Remote code execution in Apache HTTP Server 2.4.50."}
    ]
    summary = generate_vuln_summary("apache", "2.4.49", cve_list)
    print(summary)