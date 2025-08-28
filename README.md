# plsaicheckyay

==WARNING: Vibe coded with Code Claude==

A secure wrapper for yay (Arch User Repository Helper) that uses AI to analyze PKGBUILDs before installation, helping detect potential security risks, malware, and suspicious code.

## Features

- 🔍 **AI-Powered Security Analysis**: Analyzes PKGBUILD files for potential security risks before installation
- 🌐 **Web Search Integration**: Uses SearXNG to verify package authenticity and reputation
- 🎯 **Direct URL Verification**: Pattern matching and direct access verification for known software
- 🤖 **Multiple AI Providers**: Support for OLLAMA (local), OpenAI, and OpenRouter
- 🛡️ **Security Scoring**: Provides confidence scores and safety recommendations
- 🔗 **Source Verification**: Checks source URLs and download locations for suspicious patterns
- ⚡ **yay Compatibility**: Full passthrough support for all yay commands
- 📊 **Detailed Reports**: Shows risks, warnings, and actionable recommendations
- 🌍 **Intelligent Fallback**: Works perfectly even when web search is unavailable

## How It Works

The security analysis combines multiple verification layers:

### 🔍 **AI Analysis**
- **Suspicious URLs**: Non-official domains, HTTP instead of HTTPS, unusual download sources
- **Dangerous Commands**: Potentially harmful commands in build(), package(), prepare() functions
- **Unverified Downloads**: Scripts or binaries downloaded without verification
- **System Modifications**: Changes to critical system files or configurations
- **Network Connections**: Unexpected network activity during build
- **Malware Indicators**: Patterns suggesting malware, botnet, or backdoor presence

### 🎯 **Direct URL Verification**
- **Pattern Matching**: Recognizes official domains for popular software (GitHub, Microsoft, Mozilla, etc.)
- **Direct Access**: Verifies URL accessibility and authenticity
- **Trusted Domains**: Built-in database of known safe and suspicious domains
- **Smart Detection**: Automatically identifies legitimate vs malicious sources

### 🌐 **Web Search Enhancement** (Optional)
- **SearXNG Integration**: Uses your local SearXNG instance for privacy-focused searches
- **Reputation Checking**: Searches for security reports and vulnerability information
- **Official Source Validation**: Confirms URLs match official project websites
- **Graceful Fallback**: Works without web search when unavailable

## Installation

### Prerequisites

- Arch Linux with `pacman`
- `yay` installed ([installation guide](https://github.com/Jguer/yay))
- Python 3.6+
- Internet connection for AI analysis

### Quick Install

```bash
git clone https://github.com/yourusername/plsaicheckyay.git
cd plsaicheckyay
./install.sh
```

### Manual Install

```bash
# Install Python dependencies
pip3 install --user -r requirements.txt

# Make executable
chmod +x plsaicheckyay.py

# Create symlink (optional)
ln -sf $(pwd)/plsaicheckyay.py ~/.local/bin/plsyay
```

## Configuration

Run the configuration script to set up your AI provider:

```bash
python3 config.py
```

### AI Providers

#### OLLAMA (Recommended - Local)
- **Pros**: Private, no API costs, works offline
- **Setup**: Install OLLAMA and pull a model (e.g., `ollama pull llama3.1`)
- **Config**: Default host is `http://localhost:11434`

#### OpenAI
- **Pros**: High-quality analysis, reliable
- **Setup**: Get API key from OpenAI
- **Config**: Set API key via config or `OPENAI_API_KEY` environment variable

#### OpenRouter
- **Pros**: Access to multiple models including Claude
- **Setup**: Get API key from OpenRouter
- **Config**: Set API key via config or `OPENROUTER_API_KEY` environment variable

## Usage

### Secure Package Installation

```bash
# Install with security check (AUR packages only)
plsyay -S discord

# Force installation even if flagged as unsafe
plsyay -S suspicious-package --force

# Auto-install if confidence >= 80%
plsyay -S package --auto-threshold 0.8

# Enable review mode (edit/diff PKGBUILD)
plsyay -S package --editmenu --diffmenu

# Force analysis even for official repo packages
plsyay -S firefox --analyze-official

# Install multiple packages
plsyay -S firefox chromium
```

### Regular yay Commands (Passthrough)

```bash
# Update all packages
plsyay -Syu

# Search packages
plsyay -Ss browser

# Remove package
plsyay -R old-package

# Clean cache
plsyay -Sc
```

### Configuration Options

```bash
# Use specific AI provider
plsyay -S package --ai-provider ollama

# Use custom model
plsyay -S package --ai-model llama3.1:70b

# Use custom OLLAMA host
plsyay -S package --ai-host http://192.168.1.100:11434

# Auto-install threshold (0.0-1.0)
plsyay -S package --auto-threshold 0.9

# Enable interactive review mode
plsyay -S package --editmenu --diffmenu
```

### Web Search Options

```bash
# Use custom SearXNG instance
plsyay -S package --searxng-url https://searx.mydomain.com/

# Skip web search entirely (faster, local verification only)
plsyay -S package --skip-web-search

# Skip URL verification (not recommended)
plsyay -S package --skip-url-verification

# Enable debug output
plsyay -S package --debug
```

### Environment Variables

```bash
# Set SearXNG URL globally
export SEARXNG_URL="https://searxng.lan/"

# Enable debug mode
export PLSYAY_DEBUG=1

# Skip web search globally
export PLSYAY_SKIP_WEB_SEARCH=1
```

## Latest Features

### 🌐 **Web Search Integration**
- **SearXNG Support**: Integrate with your local SearXNG instance for privacy-focused searches
- **Multi-Engine Search**: Combines results from Bing, Google, and other engines through SearXNG
- **Rate Limit Handling**: Automatic retry with exponential backoff for robust searching
- **SSL Support**: Works with self-signed certificates for local instances

### 🎯 **Direct URL Verification**
- **Pattern Database**: Pre-built recognition for popular software (VS Code, Discord, Chrome, etc.)
- **Smart Matching**: Automatically identifies official vs malicious domains
- **Direct Access**: Verifies URL accessibility without relying on search engines
- **Confidence Scoring**: Provides reliability scores for each verification method

### 🛡️ **Enhanced Security Analysis**
- **Multi-Layer Verification**: Combines AI analysis + web search + direct verification
- **Domain Classification**: Automatic trusted/suspicious domain detection
- **Graceful Fallback**: Full functionality even when web search is unavailable
- **Context-Rich Prompts**: AI receives comprehensive information for better analysis

### ⚡ **Performance & Reliability**
- **Intelligent Caching**: 1-hour cache for web search results
- **Reduced API Calls**: Optimized search queries to minimize rate limiting
- **Error Recovery**: Robust error handling with meaningful fallbacks
- **Debug Mode**: Comprehensive logging for troubleshooting

## Example Security Analysis

### AUR Package Analysis
```
🔍 Analyzing discord from AUR for security risks...
🔄 Downloading PKGBUILD for discord...

📊 Security Analysis Results (AUR):
Confidence: 85.0%
Recommendation: ✅ SAFE

💡 Recommendation: Package appears safe to install

🚀 Installing discord...
```

### Official Repository Package
```
🔍 Analyzing firefox from Official Repository for security risks...
✅ firefox is from official Arch repositories - installing directly
🚀 Installing firefox...
```

### Risky Package with Review Option
```
🔍 Analyzing suspicious-tool from AUR for security risks...

📊 Security Analysis Results (AUR):
Confidence: 25.0%
Recommendation: ⚠️ ATTENTION

🚨 Risks identified:
  • Downloads executable from unknown domain
  • Contains obfuscated code in build() function
  • Network connections to suspicious IPs

Options:
1. Cancel installation
2. Proceed with installation  
3. Review and edit PKGBUILD (--editmenu --diffmenu)
Choose (1/2/3): 3

📝 Review mode enabled - you'll be able to inspect/edit files
🚀 Installing suspicious-tool...
```

## Configuration File

Config location: `~/.config/plsaicheckyay/config.json`

Example configuration:

```json
{
  "ai_provider": "ollama",
  "ollama": {
    "host": "http://localhost:11434",
    "model": "llama3.1"
  },
  "security": {
    "min_confidence_threshold": 0.7,
    "auto_install_safe_packages": false,
    "always_ask_confirmation": true
  }
}
```

## Security Considerations

- This tool provides **additional security analysis** but is not foolproof
- **Always review flagged packages manually** before proceeding
- The AI analysis is based on **patterns and heuristics**, not formal verification
- **Keep your AI models updated** for better detection capabilities
- Consider using **local AI models** (OLLAMA) for privacy-sensitive environments

## Development

### Architecture

- `plsaicheckyay.py`: Main application with CLI interface
- `config.py`: Configuration management and setup
- `AIProvider` classes: Pluggable AI backends (OLLAMA, OpenAI, OpenRouter)
- `YayWrapper`: yay command integration and PKGBUILD analysis

### Adding New AI Providers

Extend the `AIProvider` base class:

```python
class NewAIProvider(AIProvider):
    def analyze_pkgbuild(self, pkgbuild_info: PKGBUILDInfo) -> SecurityAnalysis:
        # Implement your AI analysis logic
        pass
```

### Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

## Troubleshooting

### Common Issues

**OLLAMA connection failed**
- Ensure OLLAMA is running: `ollama serve`
- Check host configuration in config
- Verify model is available: `ollama list`

**yay -G fails**
- Package might not exist in AUR
- Check internet connection
- Verify package name spelling

**Permission errors**
- Ensure proper permissions for ~/.config directory
- Check Python package installation permissions

## License

MIT License - see LICENSE file for details.

## Disclaimer

This tool is provided as-is for educational and security research purposes. While it aims to detect security issues in PKGBUILDs, it cannot guarantee complete protection against all threats. Users should exercise their own judgment and conduct additional security reviews when necessary.# plsaicheckyay
# plsaicheckyay
