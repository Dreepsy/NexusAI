# NEXUS-AI Integration Modules

This directory contains AI-powered integration modules for enhanced vulnerability analysis and threat intelligence in the NEXUS-AI CLI tool.

## Overview

The AI integration modules provide:
- **DeepSeek AI Integration**: Dynamic vulnerability analysis and exploitation guidance
- **CVE Fetcher**: Real-time CVE data from NVD database
- **Threat Intelligence**: Exploit-DB integration and CISA KEV analysis
- **MITRE ATT&CK**: Framework mapping and threat actor analysis

## Modules

### 1. DeepSeek AI Integration (`deepseek_integration.py`)
Dynamic vulnerability analysis and exploitation guidance using DeepSeek AI models.

## 1. Requirements
- Python 3.8+
- A modern GPU (NVIDIA, 8GB+ VRAM recommended) for fast inference (if running locally)
- [transformers](https://pypi.org/project/transformers/) and [torch](https://pypi.org/project/torch/) Python packages
- (Optional) DeepSeek API key for cloud inference

## 2. Installation

```bash
pip install torch transformers requests pyyaml
```

## 3. Configure Your API Key

**Developer Note:**
- Put your DeepSeek API key in `config.yaml` under the `deepseek` section. Never hardcode it in your scripts!
- The integration will automatically load the key from config.yaml and use the DeepSeek API if it's present.

Example:
```yaml
deepseek:
  api_key: "sk-..."  # Your DeepSeek API key
  model: "deepseek-chat"
```

## 4. Usage Example

See `deepseek_integration.py` for a ready-to-use function that generates vulnerability summaries and exploitation guides from a list of CVEs and service info.

The CLI tool (`CLI_tools/cli.py`) will automatically use the DeepSeek API if the key is present in `config.yaml`.

## 5. Customization
- You can swap in any HuggingFace-compatible LLM by changing the `LOCAL_MODEL_NAME` in `deepseek_integration.py`.
- For CPU-only inference, add `device_map="cpu"` to the model loading code (but it will be slow).

## 6. Security Note
- Never hardcode your API key in code or share it publicly.
- Do not expose sensitive data to the LLM if your environment is not secure.