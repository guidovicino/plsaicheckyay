#!/usr/bin/env python3

"""
plsaicheckyay - A secure yay wrapper with AI-powered PKGBUILD analysis

This utility wraps yay commands and uses AI to analyze PKGBUILDs before
installation, checking for potential security risks.
"""

import argparse
import subprocess
import sys
import os
import tempfile
import shutil
import requests
import json
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
from pathlib import Path
import re
import urllib.parse
import time
import hashlib


@dataclass
class SecurityAnalysis:
    """Security analysis result for a PKGBUILD"""
    confidence_score: float
    risks: List[str]
    warnings: List[str]
    recommendation: str
    safe_to_install: bool


@dataclass
class URLVerificationResult:
    """Result of URL verification for a single URL"""
    url: str
    status: str  # "OFFICIAL", "LIKELY_OFFICIAL", "UNKNOWN", "SUSPICIOUS", "DANGEROUS"
    confidence: float  # 0.0-1.0
    official_url: Optional[str] = None  # The actual official URL if found
    reasoning: str = ""  # AI explanation


@dataclass
class URLsVerificationResult:
    """Results of URL verification for all URLs in a package"""
    package_url_result: Optional[URLVerificationResult] = None
    source_url_results: List[URLVerificationResult] = None
    overall_status: str = "UNKNOWN"  # Worst status among all URLs
    
    def __post_init__(self):
        """Initialize default values after dataclass creation"""
        if self.source_url_results is None:
            self.source_url_results = []


@dataclass
class PKGBUILDInfo:
    """Information extracted from a PKGBUILD"""
    pkgname: str
    pkgver: str
    source: List[str]
    url: Optional[str]
    content: str
    is_aur_package: bool = True  # Default to AUR since we analyze those


@dataclass
class WebSearchResult:
    """Result of a web search query"""
    query: str
    results: List[Dict[str, str]]  # List of {title, url, snippet}
    search_time: float
    success: bool
    error_message: Optional[str] = None


class DirectWebVerifier:
    """Direct web verification without search engines"""
    
    def __init__(self):
        """Initialize the direct URL verifier with a configured HTTP session"""
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        })
        
        # Known patterns for popular software
        self.known_patterns = {
            'visual-studio-code': {
                'official_urls': ['code.visualstudio.com', 'github.com/microsoft/vscode'],
                'download_patterns': ['update.code.visualstudio.com', 'az764295.vo.msecnd.net'],
            },
            'discord': {
                'official_urls': ['discord.com', 'discordapp.com'],
                'download_patterns': ['stable.dl.discord.gg'],
            },
            'chrome': {
                'official_urls': ['google.com/chrome', 'chrome.google.com'],
                'download_patterns': ['dl.google.com', 'edgedl.me.gvt1.com'],
            },
            'firefox': {
                'official_urls': ['mozilla.org', 'firefox.com'],
                'download_patterns': ['download.mozilla.org', 'ftp.mozilla.org'],
            }
        }
    
    def verify_url_directly(self, url: str, package_name: str) -> Dict[str, Any]:
        """Verify URL by direct access and pattern matching"""
        try:
            # Parse domain
            from urllib.parse import urlparse
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # Check against known patterns
            pkg_clean = package_name.lower().replace('-bin', '').replace('_', '-')
            if pkg_clean in self.known_patterns:
                patterns = self.known_patterns[pkg_clean]
                
                # Check if it's a known official domain
                for official in patterns['official_urls']:
                    if official in domain or domain in official:
                        return {
                            'status': 'OFFICIAL',
                            'confidence': 0.95,
                            'reasoning': f'Domain {domain} matches known official pattern for {package_name}',
                            'verified_by': 'pattern_match'
                        }
                
                # Check if it's a known download domain
                for download in patterns['download_patterns']:
                    if download in domain or domain in download:
                        return {
                            'status': 'LIKELY_OFFICIAL',
                            'confidence': 0.85,
                            'reasoning': f'Domain {domain} matches known download pattern for {package_name}',
                            'verified_by': 'pattern_match'
                        }
            
            # Try direct access
            try:
                response = self.session.head(url, timeout=10, allow_redirects=True)
                if response.status_code == 200:
                    return {
                        'status': 'ACCESSIBLE',
                        'confidence': 0.7,
                        'reasoning': f'URL is accessible (HTTP {response.status_code})',
                        'verified_by': 'direct_access'
                    }
                else:
                    return {
                        'status': 'UNKNOWN',
                        'confidence': 0.3,
                        'reasoning': f'URL returned HTTP {response.status_code}',
                        'verified_by': 'direct_access'
                    }
            except Exception:
                return {
                    'status': 'UNKNOWN',
                    'confidence': 0.2,
                    'reasoning': 'URL is not accessible for verification',
                    'verified_by': 'direct_access_failed'
                }
                
        except Exception as e:
            return {
                'status': 'ERROR',
                'confidence': 0.0,
                'reasoning': f'Verification failed: {str(e)}',
                'verified_by': 'error'
            }


class WebSearchProvider:
    """Base class for web search providers"""
    
    def __init__(self, cache_dir: Optional[Path] = None):
        """Initialize web search provider with caching support"""
        self.cache_dir = cache_dir or Path.home() / ".cache" / "plsaicheckyay"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_ttl = 3600  # 1 hour cache
    
    def search(self, query: str, max_results: int = 5) -> WebSearchResult:
        """Search the web for the given query"""
        # Check cache first
        cached_result = self._get_cached_result(query)
        if cached_result:
            return cached_result
        
        # Perform actual search
        result = self._perform_search(query, max_results)
        
        # Cache the result
        if result.success:
            self._cache_result(query, result)
        
        return result
    
    def _perform_search(self, query: str, max_results: int) -> WebSearchResult:
        """Override this method in subclasses"""
        raise NotImplementedError
    
    def _get_cached_result(self, query: str) -> Optional[WebSearchResult]:
        """Get cached search result if still valid"""
        cache_file = self.cache_dir / f"{self._hash_query(query)}.json"
        
        if not cache_file.exists():
            return None
        
        try:
            with open(cache_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Check if cache is still valid
            if time.time() - data['timestamp'] > self.cache_ttl:
                cache_file.unlink()  # Remove expired cache
                return None
            
            return WebSearchResult(
                query=data['query'],
                results=data['results'],
                search_time=data['search_time'],
                success=data['success'],
                error_message=data.get('error_message')
            )
        except Exception:
            return None
    
    def _cache_result(self, query: str, result: WebSearchResult):
        """Cache search result"""
        cache_file = self.cache_dir / f"{self._hash_query(query)}.json"
        
        try:
            data = {
                'timestamp': time.time(),
                'query': result.query,
                'results': result.results,
                'search_time': result.search_time,
                'success': result.success,
                'error_message': result.error_message
            }
            
            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception:
            pass  # Ignore cache failures
    
    def _hash_query(self, query: str) -> str:
        """Generate cache filename hash from query"""
        return hashlib.md5(query.encode('utf-8')).hexdigest()




class SearXNGSearchProvider(WebSearchProvider):
    """SearXNG search provider - much better than DuckDuckGo for automation"""
    
    def __init__(self, searxng_url: str = "https://searxng.lan/", cache_dir: Optional[Path] = None):
        """Initialize SearXNG search provider with SSL handling for local instances"""
        super().__init__(cache_dir)
        self.searxng_url = searxng_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'plsaicheckyay/1.0 (Security Analysis Tool)'
        })
        
        # Disable SSL verification for local/LAN instances
        if '.lan' in searxng_url or 'localhost' in searxng_url or '192.168.' in searxng_url or '10.' in searxng_url:
            self.session.verify = False
            # Disable SSL warnings for local instances
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    def _perform_search(self, query: str, max_results: int) -> WebSearchResult:
        """Search using SearXNG API with retry logic"""
        start_time = time.time()
        
        # Retry with exponential backoff for rate limits
        max_retries = 3
        base_delay = 1.0
        
        for attempt in range(max_retries):
            try:
                if attempt > 0:  # Wait before retry
                    delay = base_delay * (2 ** attempt)  # Exponential backoff
                    if os.getenv("PLSYAY_DEBUG"):
                        print(f"DEBUG: SearXNG retry {attempt + 1}/{max_retries} after {delay}s delay")
                    time.sleep(delay)
                
                # Use SearXNG JSON API with minimal parameters
                response = self.session.get(
                    f"{self.searxng_url}/search",
                    params={
                        'q': query,
                        'format': 'json',
                        'engines': 'bing',  # Single reliable engine
                        'safesearch': '0',
                    },
                    timeout=15
                )
                
                if response.status_code == 429:  # Too Many Requests
                    if attempt < max_retries - 1:
                        continue  # Retry with backoff
                    else:
                        return WebSearchResult(
                            query=query,
                            results=[],
                            search_time=time.time() - start_time,
                            success=False,
                            error_message="SearXNG rate limit exceeded (HTTP 429)"
                        )
                
                if response.status_code != 200:
                    return WebSearchResult(
                        query=query,
                        results=[],
                        search_time=time.time() - start_time,
                        success=False,
                        error_message=f"SearXNG returned HTTP {response.status_code}"
                    )
                
                data = response.json()
                results = []
                
                # Parse SearXNG results
                for item in data.get('results', [])[:max_results]:
                    results.append({
                        'title': item.get('title', ''),
                        'url': item.get('url', ''),
                        'snippet': item.get('content', '')[:300]
                    })
                
                return WebSearchResult(
                    query=query,
                    results=results,
                    search_time=time.time() - start_time,
                    success=len(results) > 0,
                    error_message=None if results else "No results found"
                )
                
            except Exception as e:
                if attempt == max_retries - 1:  # Last attempt
                    return WebSearchResult(
                        query=query,
                        results=[],
                        search_time=time.time() - start_time,
                        success=False,
                        error_message=f"SearXNG search failed: {str(e)}"
                    )
        
        # Should never reach here
        return WebSearchResult(
            query=query,
            results=[],
            search_time=time.time() - start_time,
            success=False,
            error_message="Unexpected error in search retry logic"
        )


class AIProvider:
    """Base class for AI providers"""
    
    # List of common suspicious domains (expandable)
    SUSPICIOUS_DOMAINS = [
        'bit.ly', 'tinyurl.com', 'goo.gl', 't.co',  # URL shorteners
        'discord.gg', 'cdn.discordapp.com',  # Discord files
        'dropbox.com', 'drive.google.com',  # File sharing (non sempre sospetti ma da verificare)
        'pastebin.com', 'paste.ee', 'hastebin.com',  # Paste services
        '*.tk', '*.ml', '*.ga', '*.cf',  # Domini gratuiti spesso usati per spam
    ]
    
    # Domains considered safe for open source software
    TRUSTED_DOMAINS = [
        'github.com', 'gitlab.com', 'bitbucket.org', 'codeberg.org',
        'sourceforge.net', 'launchpad.net',
        'archive.org', 'debian.org', 'ubuntu.com', 'archlinux.org',
        'gnu.org', 'kernel.org', 'python.org', 'nodejs.org',
        'mozilla.org', 'apache.org', 'gnu.org', 'fsf.org'
    ]
    
    def __init__(self, web_search_provider: Optional[WebSearchProvider] = None):
        """Initialize AI provider with optional web search and direct URL verification"""
        # Use SearXNG for web search (optional)
        if web_search_provider is None:
            searxng_url = os.getenv("SEARXNG_URL", "https://searxng.lan/")
            self.web_search_provider = SearXNGSearchProvider(searxng_url)
        else:
            self.web_search_provider = web_search_provider
        # Direct verification always available
        self.direct_verifier = DirectWebVerifier()
    
    def analyze_pkgbuild(self, pkgbuild_info: PKGBUILDInfo) -> SecurityAnalysis:
        """Analyze PKGBUILD for security risks (must be implemented by subclasses)"""
        raise NotImplementedError
    
    def verify_urls(self, pkgbuild_info: PKGBUILDInfo) -> URLsVerificationResult:
        """Verify if URLs in PKGBUILD are official using AI web search (must be implemented by subclasses)"""
        raise NotImplementedError
    
    def _perform_web_search_for_package(self, pkgbuild_info: PKGBUILDInfo) -> Dict[str, WebSearchResult]:
        """Perform web searches to gather information about the package"""
        searches = {}
        
        if not self.web_search_provider:
            if os.getenv("PLSYAY_DEBUG"):
                print("DEBUG: No web search provider available")
            return searches
        
        # Check if web search is disabled
        if os.getenv("PLSYAY_SKIP_WEB_SEARCH"):
            if os.getenv("PLSYAY_DEBUG"):
                print("DEBUG: Web search disabled via PLSYAY_SKIP_WEB_SEARCH")
            return searches
        
        search_attempts = 0
        successful_searches = 0
        
        # Define searches to perform with minimal queries for SearXNG
        search_queries = [
            ('package_info', f"{pkgbuild_info.pkgname} official site", 3),  # Reduced results
            ('security_info', f"{pkgbuild_info.pkgname} security vulnerability", 3),
        ]
        
        # Only add URL verification for non-GitHub sources
        if pkgbuild_info.url and 'github.com' not in pkgbuild_info.url.lower():
            search_queries.append(('url_verification', f"{pkgbuild_info.pkgname} {pkgbuild_info.url}", 2))
        
        # Skip domain-specific searches to reduce load on SearXNG
        # The direct verification handles this better anyway
        
        # Perform searches with error handling
        for search_key, query, max_results in search_queries:
            search_attempts += 1
            try:
                result = self.web_search_provider.search(query, max_results=max_results)
                searches[search_key] = result
                if result.success:
                    successful_searches += 1
                    if os.getenv("PLSYAY_DEBUG"):
                        print(f"DEBUG: Search '{search_key}' successful: {len(result.results)} results")
                else:
                    if os.getenv("PLSYAY_DEBUG"):
                        print(f"DEBUG: Search '{search_key}' failed: {result.error_message}")
                
                # Add small delay between searches to be respectful
                if search_attempts < len(search_queries):
                    time.sleep(2.0)  # Longer delay for SearXNG
                    
            except Exception as e:
                if os.getenv("PLSYAY_DEBUG"):
                    print(f"DEBUG: Search '{search_key}' exception: {e}")
                # Create failed result
                searches[search_key] = WebSearchResult(
                    query=query,
                    results=[],
                    search_time=0.0,
                    success=False,
                    error_message=f"Exception: {str(e)}"
                )
        
        if os.getenv("PLSYAY_DEBUG"):
            print(f"DEBUG: Web search summary: {successful_searches}/{search_attempts} successful")
        
        return searches
    
    def _perform_direct_url_verification(self, pkgbuild_info: PKGBUILDInfo) -> Dict[str, Any]:
        """Perform direct URL verification without search engines"""
        results = {}
        
        all_urls = []
        if pkgbuild_info.url:
            all_urls.append(("package_url", pkgbuild_info.url))
        for source in pkgbuild_info.source:
            if source.startswith(("http://", "https://", "ftp://", "ftps://")):
                all_urls.append(("source_url", source))
        
        if os.getenv("PLSYAY_DEBUG"):
            print(f"DEBUG: Direct verification of {len(all_urls)} URLs")
        
        for url_type, url in all_urls:
            verification = self.direct_verifier.verify_url_directly(url, pkgbuild_info.pkgname)
            results[f"{url_type}_{url}"] = verification
            
            if os.getenv("PLSYAY_DEBUG"):
                print(f"DEBUG: {url} -> {verification['status']} ({verification['confidence']:.2f}) via {verification['verified_by']}")
        
        return results
    
    def _check_domain_trust_level(self, domain: str) -> str:
        """Check if domain is trusted, suspicious, or unknown"""
        domain_lower = domain.lower()
        
        # Check trusted domains
        for trusted in self.TRUSTED_DOMAINS:
            if domain_lower == trusted or domain_lower.endswith('.' + trusted):
                return "TRUSTED"
        
        # Check suspicious domains
        for suspicious in self.SUSPICIOUS_DOMAINS:
            if suspicious.startswith('*.'):
                # Handle wildcard domains like *.tk
                tld = suspicious[2:]
                if domain_lower.endswith('.' + tld):
                    return "SUSPICIOUS"
            elif domain_lower == suspicious or domain_lower.endswith('.' + suspicious):
                return "SUSPICIOUS"
        
        # Check for common red flags
        red_flags = [
            len(domain_lower) > 50,  # Very long domains
            domain_lower.count('-') > 3,  # Too many hyphens
            any(char.isdigit() for char in domain_lower.replace('.', '').replace('-', '')) and len([c for c in domain_lower if c.isdigit()]) > 5,  # Too many numbers
            any(keyword in domain_lower for keyword in ['temp', 'tmp', 'test', 'random', 'generated'])
        ]
        
        if any(red_flags):
            return "SUSPICIOUS"
        
        return "UNKNOWN"


class OllamaProvider(AIProvider):
    """OLLAMA AI provider"""
    
    def __init__(self, model: str = "llama3.1", host: str = "http://localhost:11434", web_search_provider: Optional[WebSearchProvider] = None):
        """Initialize OLLAMA provider with model and host configuration"""
        super().__init__(web_search_provider)
        self.model = model
        self.host = host
    
    def analyze_pkgbuild(self, pkgbuild_info: PKGBUILDInfo) -> SecurityAnalysis:
        """Analyze PKGBUILD security using OLLAMA AI with web search context"""
        # Perform web searches to gather additional context
        web_search_results = self._perform_web_search_for_package(pkgbuild_info)
        
        prompt = self._create_security_prompt(pkgbuild_info, web_search_results)
        
        try:
            response = requests.post(
                f"{self.host}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False
                }
            )
            response.raise_for_status()
            
            result = response.json()
            return self._parse_ai_response(result["response"])
        
        except Exception as e:
            return SecurityAnalysis(
                confidence_score=0.0,
                risks=[f"AI analysis error: {str(e)}"],
                warnings=["Unable to analyze PKGBUILD"],
                recommendation="Do not proceed without manual analysis",
                safe_to_install=False
            )
    
    def _create_security_prompt(self, pkgbuild_info: PKGBUILDInfo, web_search_results: Dict[str, WebSearchResult] = None) -> str:
        # Build web search context
        web_context = ""
        domain_analysis = ""
        direct_verification = ""
        
        if web_search_results:
            web_context = "\n\n=== WEB SEARCH INFORMATION ===\n"
            
            for search_type, result in web_search_results.items():
                if result.success and result.results:
                    web_context += f"\n{search_type.upper().replace('_', ' ')}:\n"
                    for i, item in enumerate(result.results[:3], 1):  # Limit to 3 results per search
                        web_context += f"  {i}. {item['title']}\n"
                        web_context += f"     URL: {item['url']}\n"
                        if item['snippet']:
                            web_context += f"     Snippet: {item['snippet'][:200]}...\n"
                        web_context += "\n"
                elif not result.success:
                    web_context += f"\n{search_type.upper().replace('_', ' ')}: Search failed - {result.error_message}\n"
        
        # Perform direct URL verification
        direct_results = self._perform_direct_url_verification(pkgbuild_info)
        if direct_results:
            direct_verification = "\n\n=== DIRECT URL VERIFICATION ===\n"
            for url_key, verification in direct_results.items():
                url = url_key.split('_', 2)[-1]  # Extract URL from key
                direct_verification += f"{url}:\n"
                direct_verification += f"  Status: {verification['status']}\n"
                direct_verification += f"  Confidence: {verification['confidence']:.2f}\n"
                direct_verification += f"  Reasoning: {verification['reasoning']}\n"
                direct_verification += f"  Method: {verification['verified_by']}\n\n"
        
        # Analyze domains from PKGBUILD
        domain_analysis = "\n\n=== DOMAIN ANALYSIS ===\n"
        all_urls = []
        if pkgbuild_info.url:
            all_urls.append(pkgbuild_info.url)
        all_urls.extend([s for s in pkgbuild_info.source if s.startswith(('http://', 'https://', 'ftp://', 'ftps://'))])
        
        for url in all_urls:
            try:
                domain = urllib.parse.urlparse(url).netloc
                trust_level = self._check_domain_trust_level(domain)
                domain_analysis += f"{domain}: {trust_level}\n"
            except Exception:
                continue
        
        return f"""
Analyze this Arch Linux PKGBUILD for potential security risks.

Package: {pkgbuild_info.pkgname} v{pkgbuild_info.pkgver}
URL: {pkgbuild_info.url or 'N/A'}
Sources: {', '.join(pkgbuild_info.source)}

PKGBUILD Content:
{pkgbuild_info.content}
{web_context}
{direct_verification}
{domain_analysis}

Use the web search information, direct URL verification and domain analysis to:
1. Verify if URLs and sources are official and legitimate (TRUSTED = safe, SUSPICIOUS = suspicious, UNKNOWN = to verify)
2. Check software reputation and any known security issues
3. Validate that domains used match official project websites

Analyze specifically:
1. Suspicious URLs and sources (unofficial domains, HTTP instead of HTTPS, mismatch with official sites found)
2. Potentially dangerous commands in build(), package(), prepare() functions
3. Downloads of unverified scripts or binaries
4. System modifications or critical file changes
5. Unexpected network connections
6. Presence of malware, botnet or backdoor
7. Software reputation based on search results

Respond in JSON format with:
{{
    "confidence_score": (0.0-1.0, where 1.0 = maximum security, 0.0 = maximum risk),
    "risks": ["list of risks found"],
    "warnings": ["list of warnings"],
    "recommendation": "final recommendation",
    "safe_to_install": true/false
}}
"""

    def _parse_ai_response(self, response: str) -> SecurityAnalysis:
        """Parse AI response and extract security analysis from JSON"""
        try:
            # Look for JSON in response
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
                return SecurityAnalysis(
                    confidence_score=data.get("confidence_score", 0.5),
                    risks=data.get("risks", []),
                    warnings=data.get("warnings", []),
                    recommendation=data.get("recommendation", "Inconclusive analysis"),
                    safe_to_install=data.get("safe_to_install", False)
                )
        except:
            pass
        
        # Fallback if JSON parsing fails
        return SecurityAnalysis(
            confidence_score=0.3,
            risks=["Impossibile parsare la risposta AI"],
            warnings=["Analisi automatica fallita"],
            recommendation="Revisione manuale necessaria",
            safe_to_install=False
        )
    
    def verify_urls(self, pkgbuild_info: PKGBUILDInfo) -> URLsVerificationResult:
        """Verify if URLs in PKGBUILD are official using AI with real web search"""
        all_urls = []
        
        # Collect all URLs to verify
        if pkgbuild_info.url:
            all_urls.append(("package_url", pkgbuild_info.url))
        
        for source in pkgbuild_info.source:
            if source.startswith(("http://", "https://", "ftp://", "ftps://")):
                all_urls.append(("source", source))
        
        if not all_urls:
            return URLsVerificationResult(overall_status="NO_URLS")
        
        # Perform web searches to gather real data
        search_results = self._perform_web_search_for_package(pkgbuild_info)
        
        prompt = self._create_url_verification_prompt(pkgbuild_info, all_urls, search_results)
        
        try:
            response = requests.post(
                f"{self.host}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False
                }
            )
            response.raise_for_status()
            
            result = response.json()
            return self._parse_url_verification_response(result["response"], all_urls)
        
        except Exception as e:
            # Return error result
            error_result = URLsVerificationResult(overall_status="ERROR")
            for url_type, url in all_urls:
                verification = URLVerificationResult(
                    url=url,
                    status="ERROR",
                    confidence=0.0,
                    reasoning=f"Verification error: {str(e)}"
                )
                if url_type == "package_url":
                    error_result.package_url_result = verification
                else:
                    error_result.source_url_results.append(verification)
            
            return error_result
    
    def _create_url_verification_prompt(self, pkgbuild_info: PKGBUILDInfo, urls: List[Tuple[str, str]], search_results: Dict[str, WebSearchResult] = None) -> str:
        urls_text = "\n".join([f"- {url_type}: {url}" for url_type, url in urls])
        
        return f"""
Verify if this AUR package URLs are official using web search:

Package: {pkgbuild_info.pkgname} v{pkgbuild_info.pkgver}
URLs da verificare:
{urls_text}

Per ogni URL, cerca online e determina:
1. È l'URL ufficiale del progetto {pkgbuild_info.pkgname}?
2. Se no, qual è l'URL ufficiale reale del progetto?
3. Classifica il livello di sicurezza:
   - OFFICIAL: URL ufficiale confermato
   - LIKELY_OFFICIAL: Probabilmente ufficiale (es. mirror ufficiale)
   - UNKNOWN: Non si riesce a determinare
   - SUSPICIOUS: Suspicious but not dangerous URL
   - DANGEROUS: URL chiaramente malevolo o compromesso

Respond in JSON format with:
{{
    "verifications": [
        {{
            "url": "url_da_verificare",
            "status": "OFFICIAL|LIKELY_OFFICIAL|UNKNOWN|SUSPICIOUS|DANGEROUS",
            "confidence": 0.0-1.0,
            "official_url": "url_ufficiale_se_diverso_o_null",
            "reasoning": "spiegazione_della_verifica"
        }}
    ]
}}
"""
    
    def _parse_url_verification_response(self, response: str, urls: List[Tuple[str, str]]) -> URLsVerificationResult:
        # Debug output
        if os.getenv("PLSYAY_DEBUG"):
            print(f"DEBUG: URL Verification Response: {response[:300]}...")
        
        result = URLsVerificationResult()
        status_priority = {"DANGEROUS": 5, "SUSPICIOUS": 4, "UNKNOWN": 3, "LIKELY_OFFICIAL": 2, "OFFICIAL": 1}
        worst_status = "OFFICIAL"
        
        try:
            # Look for JSON in response
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
                verifications = data.get("verifications", [])
                
                for verification_data in verifications:
                    verification = URLVerificationResult(
                        url=verification_data.get("url", ""),
                        status=verification_data.get("status", "UNKNOWN"),
                        confidence=verification_data.get("confidence", 0.5),
                        official_url=verification_data.get("official_url"),
                        reasoning=verification_data.get("reasoning", "")
                    )
                    
                    # Track worst status
                    if status_priority.get(verification.status, 3) > status_priority.get(worst_status, 1):
                        worst_status = verification.status
                    
                    # Assign to appropriate result field
                    url_found = False
                    for url_type, url in urls:
                        if verification.url == url:
                            if url_type == "package_url":
                                result.package_url_result = verification
                            else:
                                result.source_url_results.append(verification)
                            url_found = True
                            break
                
        except Exception as e:
            if os.getenv("PLSYAY_DEBUG"):
                print(f"DEBUG: URL verification parsing error: {e}")
            worst_status = "ERROR"
        
        # Handle missing verifications with fallback
        for url_type, url in urls:
            found = False
            if url_type == "package_url" and result.package_url_result and result.package_url_result.url == url:
                found = True
            elif url_type == "source" and any(v.url == url for v in result.source_url_results):
                found = True
            
            if not found:
                fallback = URLVerificationResult(
                    url=url,
                    status="UNKNOWN",
                    confidence=0.3,
                    reasoning="Verifica fallita - impossibile parsare risposta AI"
                )
                if url_type == "package_url":
                    result.package_url_result = fallback
                else:
                    result.source_url_results.append(fallback)
                
                if status_priority.get("UNKNOWN", 3) > status_priority.get(worst_status, 1):
                    worst_status = "UNKNOWN"
        
        result.overall_status = worst_status
        return result


class OpenAIProvider(AIProvider):
    """OpenAI Provider"""
    
    def __init__(self, api_key: str, model: str = "gpt-4", web_search_provider: Optional[WebSearchProvider] = None):
        """Initialize OpenAI provider with API key and model configuration"""
        super().__init__(web_search_provider)
        self.api_key = api_key
        self.model = model
    
    def analyze_pkgbuild(self, pkgbuild_info: PKGBUILDInfo) -> SecurityAnalysis:
        """Analyze PKGBUILD security using OpenAI API (placeholder implementation)"""
        # Similar implementation to OLLAMA but with OpenAI API
        # Basic implementation for brevity
        return SecurityAnalysis(
            confidence_score=0.8,
            risks=["OpenAI provider not fully implemented"],
            warnings=[],
            recommendation="Usa OLLAMA per ora",
            safe_to_install=False
        )


class OpenRouterProvider(AIProvider):
    """OpenRouter Provider"""
    
    def __init__(self, api_key: str, model: str = "anthropic/claude-3.5-sonnet", web_search_provider: Optional[WebSearchProvider] = None):
        """Initialize OpenRouter provider with API key and model configuration"""
        super().__init__(web_search_provider)
        self.api_key = api_key
        self.model = model
        self.host = "https://openrouter.ai/api/v1"
    
    def analyze_pkgbuild(self, pkgbuild_info: PKGBUILDInfo) -> SecurityAnalysis:
        """Analyze PKGBUILD security using OpenRouter API with web search context"""
        # Perform web searches to gather additional context
        web_search_results = self._perform_web_search_for_package(pkgbuild_info)
        
        prompt = self._create_security_prompt(pkgbuild_info, web_search_results)
        
        try:
            response = requests.post(
                f"{self.host}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                    "HTTP-Referer": "https://github.com/your-username/plsaicheckyay",
                    "X-Title": "plsaicheckyay"
                },
                json={
                    "model": self.model,
                    "messages": [
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ],
                    "max_tokens": 1000,
                    "temperature": 0.1
                }
            )
            response.raise_for_status()
            
            result = response.json()
            ai_response = result["choices"][0]["message"]["content"]
            return self._parse_ai_response(ai_response)
        
        except Exception as e:
            return SecurityAnalysis(
                confidence_score=0.0,
                risks=[f"AI analysis error: {str(e)}"],
                warnings=["Unable to analyze PKGBUILD"],
                recommendation="Do not proceed without manual analysis",
                safe_to_install=False
            )
    
    def _create_security_prompt(self, pkgbuild_info: PKGBUILDInfo, web_search_results: Dict[str, WebSearchResult] = None) -> str:
        # Build web search context
        web_context = ""
        domain_analysis = ""
        direct_verification = ""
        
        if web_search_results:
            web_context = "\n\n=== WEB SEARCH INFORMATION ===\n"
            
            for search_type, result in web_search_results.items():
                if result.success and result.results:
                    web_context += f"\n{search_type.upper().replace('_', ' ')}:\n"
                    for i, item in enumerate(result.results[:3], 1):  # Limit to 3 results per search
                        web_context += f"  {i}. {item['title']}\n"
                        web_context += f"     URL: {item['url']}\n"
                        if item['snippet']:
                            web_context += f"     Snippet: {item['snippet'][:200]}...\n"
                        web_context += "\n"
                elif not result.success:
                    web_context += f"\n{search_type.upper().replace('_', ' ')}: Search failed - {result.error_message}\n"
        
        # Perform direct URL verification
        direct_results = self._perform_direct_url_verification(pkgbuild_info)
        if direct_results:
            direct_verification = "\n\n=== DIRECT URL VERIFICATION ===\n"
            for url_key, verification in direct_results.items():
                url = url_key.split('_', 2)[-1]  # Extract URL from key
                direct_verification += f"{url}:\n"
                direct_verification += f"  Status: {verification['status']}\n"
                direct_verification += f"  Confidence: {verification['confidence']:.2f}\n"
                direct_verification += f"  Reasoning: {verification['reasoning']}\n"
                direct_verification += f"  Method: {verification['verified_by']}\n\n"
        
        # Analyze domains from PKGBUILD
        domain_analysis = "\n\n=== DOMAIN ANALYSIS ===\n"
        all_urls = []
        if pkgbuild_info.url:
            all_urls.append(pkgbuild_info.url)
        all_urls.extend([s for s in pkgbuild_info.source if s.startswith(('http://', 'https://', 'ftp://', 'ftps://'))])
        
        for url in all_urls:
            try:
                domain = urllib.parse.urlparse(url).netloc
                trust_level = self._check_domain_trust_level(domain)
                domain_analysis += f"{domain}: {trust_level}\n"
            except Exception:
                continue
        
        return f"""
Analyze this Arch Linux PKGBUILD for potential security risks.

Package: {pkgbuild_info.pkgname} v{pkgbuild_info.pkgver}
URL: {pkgbuild_info.url or 'N/A'}
Sources: {', '.join(pkgbuild_info.source)}

PKGBUILD Content:
{pkgbuild_info.content}
{web_context}
{direct_verification}
{domain_analysis}

Use the web search information, direct URL verification and domain analysis to:
1. Verify if URLs and sources are official and legitimate (TRUSTED = safe, SUSPICIOUS = suspicious, UNKNOWN = to verify)
2. Check software reputation and any known security issues
3. Validate that domains used match official project websites

Analyze specifically:
1. Suspicious URLs and sources (unofficial domains, HTTP instead of HTTPS, mismatch with official sites found)
2. Potentially dangerous commands in build(), package(), prepare() functions
3. Downloads of unverified scripts or binaries
4. System modifications or critical file changes
5. Unexpected network connections
6. Presence of malware, botnet or backdoor
7. Software reputation based on search results

Respond in JSON format with:
{{
    "confidence_score": (0.0-1.0, where 1.0 = maximum security, 0.0 = maximum risk),
    "risks": ["list of risks found"],
    "warnings": ["list of warnings"],
    "recommendation": "final recommendation",
    "safe_to_install": true/false
}}
"""

    def _parse_ai_response(self, response: str) -> SecurityAnalysis:
        # Debug output
        if os.getenv("PLSYAY_DEBUG"):
            print(f"DEBUG: AI Response: {response[:500]}...")
        
        try:
            # Look for JSON in response
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                json_str = json_match.group()
                if os.getenv("PLSYAY_DEBUG"):
                    print(f"DEBUG: Extracted JSON: {json_str}")
                data = json.loads(json_str)
                return SecurityAnalysis(
                    confidence_score=data.get("confidence_score", 0.5),
                    risks=data.get("risks", []),
                    warnings=data.get("warnings", []),
                    recommendation=data.get("recommendation", "Inconclusive analysis"),
                    safe_to_install=data.get("safe_to_install", False)
                )
        except Exception as e:
            if os.getenv("PLSYAY_DEBUG"):
                print(f"DEBUG: JSON parsing error: {e}")
        
        # Fallback if JSON parsing fails
        return SecurityAnalysis(
            confidence_score=0.3,
            risks=[f"Impossibile parsare la risposta AI: {response[:100]}..."],
            warnings=["Analisi automatica fallita"],
            recommendation="Revisione manuale necessaria",
            safe_to_install=False
        )
    
    def verify_urls(self, pkgbuild_info: PKGBUILDInfo) -> URLsVerificationResult:
        """Verify if URLs in PKGBUILD are official using AI web search"""
        all_urls = []
        
        # Collect all URLs to verify
        if pkgbuild_info.url:
            all_urls.append(("package_url", pkgbuild_info.url))
        
        for source in pkgbuild_info.source:
            if source.startswith(("http://", "https://", "ftp://", "ftps://")):
                all_urls.append(("source", source))
        
        if not all_urls:
            return URLsVerificationResult(overall_status="NO_URLS")
        
        prompt = self._create_url_verification_prompt(pkgbuild_info, all_urls)
        
        try:
            response = requests.post(
                f"{self.host}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                    "HTTP-Referer": "https://github.com/your-username/plsaicheckyay",
                    "X-Title": "plsaicheckyay"
                },
                json={
                    "model": self.model,
                    "messages": [
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ],
                    "max_tokens": 1500,
                    "temperature": 0.1
                }
            )
            response.raise_for_status()
            
            result = response.json()
            ai_response = result["choices"][0]["message"]["content"]
            return self._parse_url_verification_response(ai_response, all_urls)
        
        except Exception as e:
            # Return error result
            error_result = URLsVerificationResult(overall_status="ERROR")
            for url_type, url in all_urls:
                verification = URLVerificationResult(
                    url=url,
                    status="ERROR",
                    confidence=0.0,
                    reasoning=f"Verification error: {str(e)}"
                )
                if url_type == "package_url":
                    error_result.package_url_result = verification
                else:
                    error_result.source_url_results.append(verification)
            
            return error_result
    
    def _create_url_verification_prompt(self, pkgbuild_info: PKGBUILDInfo, urls: List[Tuple[str, str]], search_results: Dict[str, WebSearchResult] = None) -> str:
        urls_text = "\n".join([f"- {url_type}: {url}" for url_type, url in urls])
        
        return f"""
Verify if this AUR package URLs are official using web search:

Package: {pkgbuild_info.pkgname} v{pkgbuild_info.pkgver}
URLs da verificare:
{urls_text}

Per ogni URL, cerca online e determina:
1. È l'URL ufficiale del progetto {pkgbuild_info.pkgname}?
2. Se no, qual è l'URL ufficiale reale del progetto?
3. Classifica il livello di sicurezza:
   - OFFICIAL: URL ufficiale confermato
   - LIKELY_OFFICIAL: Probabilmente ufficiale (es. mirror ufficiale)
   - UNKNOWN: Non si riesce a determinare
   - SUSPICIOUS: Suspicious but not dangerous URL
   - DANGEROUS: URL chiaramente malevolo o compromesso

Respond in JSON format with:
{{
    "verifications": [
        {{
            "url": "url_da_verificare",
            "status": "OFFICIAL|LIKELY_OFFICIAL|UNKNOWN|SUSPICIOUS|DANGEROUS",
            "confidence": 0.0-1.0,
            "official_url": "url_ufficiale_se_diverso_o_null",
            "reasoning": "spiegazione_della_verifica"
        }}
    ]
}}
"""
    
    def _parse_url_verification_response(self, response: str, urls: List[Tuple[str, str]]) -> URLsVerificationResult:
        # Debug output
        if os.getenv("PLSYAY_DEBUG"):
            print(f"DEBUG: URL Verification Response: {response[:300]}...")
        
        result = URLsVerificationResult()
        status_priority = {"DANGEROUS": 5, "SUSPICIOUS": 4, "UNKNOWN": 3, "LIKELY_OFFICIAL": 2, "OFFICIAL": 1}
        worst_status = "OFFICIAL"
        
        try:
            # Look for JSON in response
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
                verifications = data.get("verifications", [])
                
                for verification_data in verifications:
                    verification = URLVerificationResult(
                        url=verification_data.get("url", ""),
                        status=verification_data.get("status", "UNKNOWN"),
                        confidence=verification_data.get("confidence", 0.5),
                        official_url=verification_data.get("official_url"),
                        reasoning=verification_data.get("reasoning", "")
                    )
                    
                    # Track worst status
                    if status_priority.get(verification.status, 3) > status_priority.get(worst_status, 1):
                        worst_status = verification.status
                    
                    # Assign to appropriate result field
                    url_found = False
                    for url_type, url in urls:
                        if verification.url == url:
                            if url_type == "package_url":
                                result.package_url_result = verification
                            else:
                                result.source_url_results.append(verification)
                            url_found = True
                            break
                
        except Exception as e:
            if os.getenv("PLSYAY_DEBUG"):
                print(f"DEBUG: URL verification parsing error: {e}")
            worst_status = "ERROR"
        
        # Handle missing verifications with fallback
        for url_type, url in urls:
            found = False
            if url_type == "package_url" and result.package_url_result and result.package_url_result.url == url:
                found = True
            elif url_type == "source" and any(v.url == url for v in result.source_url_results):
                found = True
            
            if not found:
                fallback = URLVerificationResult(
                    url=url,
                    status="UNKNOWN",
                    confidence=0.3,
                    reasoning="Verifica fallita - impossibile parsare risposta AI"
                )
                if url_type == "package_url":
                    result.package_url_result = fallback
                else:
                    result.source_url_results.append(fallback)
                
                if status_priority.get("UNKNOWN", 3) > status_priority.get(worst_status, 1):
                    worst_status = "UNKNOWN"
        
        result.overall_status = worst_status
        return result


class YayWrapper:
    """Wrapper for yay commands with security analysis"""
    
    def __init__(self, ai_provider: AIProvider):
        """Initialize yay wrapper with an AI provider for security analysis"""
        self.ai_provider = ai_provider
    
    def install_package(self, package_name: str, force: bool = False, 
                       auto_threshold: Optional[float] = None,
                       use_editmenu: bool = False, use_diffmenu: bool = False) -> bool:
        """Install package with AI security analysis for AUR packages"""
        
        # Check if package is from official repos vs AUR
        is_aur = self._is_aur_package(package_name)
        repo_type = "AUR" if is_aur else "Official Repository"
        print(f"🔍 Analyzing {package_name} from {repo_type} for security risks...")
        
        # Debug info for troubleshooting
        if os.getenv("PLSYAY_DEBUG"):
            print(f"DEBUG: {package_name} detected as {'AUR' if is_aur else 'Official'}")
        
        # Skip analysis for official repo packages unless forced
        if not is_aur and not force:
            print(f"✅ {package_name} is from official Arch repositories - installing directly")
            return self._run_yay_install(package_name, use_editmenu, use_diffmenu)
        
        # Get PKGBUILD for AUR packages
        pkgbuild_info = self._get_pkgbuild_info(package_name)
        if not pkgbuild_info:
            print(f"❌ Unable to get PKGBUILD for {package_name}")
            return False
        
        pkgbuild_info.is_aur_package = is_aur
        
        # Analyze with AI
        analysis = self.ai_provider.analyze_pkgbuild(pkgbuild_info)
        
        # Verify URLs with AI (if enabled)
        url_verification = None
        if not os.getenv("PLSYAY_SKIP_URL_VERIFICATION"):
            print("🔍 Verifying URLs authenticity...")
            url_verification = self.ai_provider.verify_urls(pkgbuild_info)
        
        # Display results
        self._display_analysis(analysis, repo_type, pkgbuild_info, url_verification)
        
        # Auto-install if confidence is above threshold
        if auto_threshold and analysis.confidence_score >= auto_threshold:
            print(f"🤖 Auto-installing (confidence {analysis.confidence_score:.1%} >= threshold {auto_threshold:.1%})")
            return self._run_yay_install(package_name, use_editmenu, use_diffmenu)
        
        # Ask for confirmation if not safe and not forced
        if not analysis.safe_to_install and not force:
            choice = self._ask_user_confirmation_with_options()
            if choice == "cancel":
                print("❌ Installation cancelled by user")
                return False
            elif choice == "review":
                return self._run_yay_install(package_name, True, True)  # Force review mode
            # choice == "proceed" falls through to normal install
        
        # Proceed with installation
        return self._run_yay_install(package_name, use_editmenu, use_diffmenu)
    
    def _get_pkgbuild_info(self, package_name: str) -> Optional[PKGBUILDInfo]:
        """Downloads and analyzes a package's PKGBUILD using yay -G
        
        The process:
        1. Use 'yay -G package_name' to download PKGBUILD to ./package_name/ directory
        2. Read the PKGBUILD file from the downloaded directory
        3. Extract key security-relevant fields (source URLs, package info, etc.)
        4. Clean up the downloaded directory
        """
        temp_dir = None
        try:
            # Create temporary directory for download
            temp_dir = tempfile.mkdtemp(prefix="plsyay_")
            old_cwd = os.getcwd()
            os.chdir(temp_dir)
            
            print(f"🔄 Downloading PKGBUILD for {package_name}...")
            
            # Use yay -G to download PKGBUILD (Git download)
            result = subprocess.run(
                ["yay", "-G", package_name],
                capture_output=True,
                text=True,
                check=False
            )
            
            if result.returncode != 0:
                print(f"❌ Failed to download PKGBUILD: {result.stderr}")
                return None
            
            # Read the PKGBUILD from downloaded directory
            pkgbuild_path = Path(temp_dir) / package_name / "PKGBUILD"
            if not pkgbuild_path.exists():
                print(f"❌ PKGBUILD not found at {pkgbuild_path}")
                return None
            
            content = pkgbuild_path.read_text(encoding='utf-8')
            
            # Extract key information for security analysis
            pkgname = self._extract_field(content, "pkgname")
            pkgver = self._extract_field(content, "pkgver")
            url = self._extract_field(content, "url")
            source = self._extract_array_field(content, "source")
            
            return PKGBUILDInfo(
                pkgname=pkgname or package_name,
                pkgver=pkgver or "unknown",
                source=source,
                url=url,
                content=content,
                is_aur_package=True  # Always True since we use yay -G
            )
        
        except Exception as e:
            print(f"❌ Error getting PKGBUILD: {e}")
            return None
        
        finally:
            # Cleanup: restore directory and remove temp files
            try:
                os.chdir(old_cwd)
                if temp_dir and os.path.exists(temp_dir):
                    import shutil
                    shutil.rmtree(temp_dir)
            except Exception as e:
                print(f"⚠️  Warning: Failed to cleanup temp directory: {e}")
    
    def _is_aur_package(self, package_name: str) -> bool:
        """Check if package is from AUR vs official repositories"""
        try:
            # First try to get package info from pacman (more reliable)
            result = subprocess.run(
                ["pacman", "-Si", package_name],
                capture_output=True,
                text=True,
                check=False
            )
            
            # If pacman can get info about it, it's in official repos
            if result.returncode == 0:
                return False
            
            # If pacman doesn't know it, check if yay can find it
            result = subprocess.run(
                ["yay", "-Si", package_name],
                capture_output=True,
                text=True,
                check=False
            )
            
            # If yay can get info but pacman couldn't, it's AUR
            if result.returncode == 0:
                # Double-check by looking at the repository field in yay output
                output = result.stdout.lower()
                if "repository" in output and "aur" in output:
                    return True
                # If no repository info or it mentions official repos, it might be official
                if "repository" in output and any(repo in output for repo in ["core", "extra", "multilib", "community"]):
                    return False
                # Default to AUR if we can't determine from yay output
                return True
            
            # If neither can find it, assume it doesn't exist
            print(f"⚠️  Package {package_name} not found in repositories or AUR")
            return True
            
        except Exception as e:
            print(f"⚠️  Error detecting repository for {package_name}: {e}")
            # Default to AUR for safety (trigger analysis)
            return True
    
    def _extract_field(self, content: str, field: str) -> Optional[str]:
        """Extract a field from PKGBUILD"""
        pattern = rf'^{field}=(["\']?)([^"\'\n]*)\1'
        match = re.search(pattern, content, re.MULTILINE)
        return match.group(2) if match else None
    
    def _extract_array_field(self, content: str, field: str) -> List[str]:
        """Extract an array from PKGBUILD"""
        pattern = rf'^{field}=\((.*?)\)'
        match = re.search(pattern, content, re.MULTILINE | re.DOTALL)
        if not match:
            return []
        
        # Parse dell'array bash
        array_content = match.group(1)
        # Semplificato: split su spazi e rimuovi quotes
        items = []
        for item in array_content.split():
            item = item.strip().strip('"\'')
            if item:
                items.append(item)
        return items
    
    def _display_analysis(self, analysis: SecurityAnalysis, repo_type: str = "AUR", pkgbuild_info: Optional[PKGBUILDInfo] = None, url_verification: Optional[URLsVerificationResult] = None):
        """Display comprehensive security analysis results with color-coded output"""
        print(f"\n📊 Security Analysis Results ({repo_type}):")
        print(f"Confidence: {analysis.confidence_score:.1%}")
        print(f"Recommendation: {'✅ SAFE' if analysis.safe_to_install else '⚠️  ATTENTION'}")
        
        # Display package info with clickable links and URL verification
        if pkgbuild_info:
            print(f"\n📦 Package Info:")
            print(f"  Name: {pkgbuild_info.pkgname}")
            print(f"  Version: {pkgbuild_info.pkgver}")
            
            if pkgbuild_info.url:
                url_icon = "🔗" if pkgbuild_info.url.startswith("https://") else "⚠️🔗"
                verification_status = self._get_url_verification_icon(pkgbuild_info.url, url_verification)
                print(f"  URL: {verification_status}{url_icon} {pkgbuild_info.url}")
                
                # Show verification details if available
                if url_verification and url_verification.package_url_result:
                    result = url_verification.package_url_result
                    if result.reasoning and result.status != "OFFICIAL":
                        print(f"       📝 {result.reasoning}")
                    if result.official_url and result.official_url != pkgbuild_info.url:
                        print(f"       ✅ Official URL: {result.official_url}")
            
            if pkgbuild_info.source:
                print(f"  Sources:")
                for i, source in enumerate(pkgbuild_info.source, 1):
                    # Check if source is a URL
                    if source.startswith(("http://", "https://", "ftp://", "ftps://")):
                        source_icon = "🔗" if source.startswith("https://") else "⚠️🔗"
                        verification_status = self._get_url_verification_icon(source, url_verification)
                        print(f"    {i}. {verification_status}{source_icon} {source}")
                        
                        # Show verification details if available
                        if url_verification:
                            for result in url_verification.source_url_results:
                                if result.url == source:
                                    if result.reasoning and result.status != "OFFICIAL":
                                        print(f"         📝 {result.reasoning}")
                                    if result.official_url and result.official_url != source:
                                        print(f"         ✅ Official URL: {result.official_url}")
                                    break
                    else:
                        print(f"    {i}. 📄 {source}")
        
        # Display URL verification summary
        if url_verification and url_verification.overall_status not in ["NO_URLS", "ERROR"]:
            print(f"\n🛡️  URL Verification: {self._get_verification_status_display(url_verification.overall_status)}")
        
        if analysis.risks:
            print("\n🚨 Risks identified:")
            for risk in analysis.risks:
                print(f"  • {risk}")
        
        if analysis.warnings:
            print("\n⚠️  Warnings:")
            for warning in analysis.warnings:
                print(f"  • {warning}")
        
        print(f"\n💡 Recommendation: {analysis.recommendation}")
    
    def _get_url_verification_icon(self, url: str, verification: Optional[URLsVerificationResult]) -> str:
        """Get verification status icon for a URL based on verification results"""
        if not verification:
            return ""
        
        # Check package URL
        if verification.package_url_result and verification.package_url_result.url == url:
            return self._status_to_icon(verification.package_url_result.status)
        
        # Check source URLs
        for result in verification.source_url_results:
            if result.url == url:
                return self._status_to_icon(result.status)
        
        return ""
    
    def _status_to_icon(self, status: str) -> str:
        """Convert verification status string to display icon"""
        icons = {
            "OFFICIAL": "✅",
            "LIKELY_OFFICIAL": "✅",
            "UNKNOWN": "❓",
            "SUSPICIOUS": "⚠️",
            "DANGEROUS": "🚨",
            "ERROR": "❌"
        }
        return icons.get(status, "❓")
    
    def _get_verification_status_display(self, status: str) -> str:
        """Get human-readable display string for verification status"""
        displays = {
            "OFFICIAL": "✅ All URLs are official",
            "LIKELY_OFFICIAL": "✅ URLs are likely official", 
            "UNKNOWN": "❓ Could not verify URLs",
            "SUSPICIOUS": "⚠️ Some URLs are suspicious",
            "DANGEROUS": "🚨 DANGEROUS URLs detected",
            "ERROR": "❌ Verification failed"
        }
        return displays.get(status, "❓ Unknown status")
    
    def _ask_user_confirmation(self) -> bool:
        """Ask user for simple yes/no confirmation to proceed with installation"""
        response = input("\nDo you want to proceed with installation anyway? (y/N): ")
        return response.lower() in ['y', 'yes', 's', 'si']
    
    def _ask_user_confirmation_with_options(self) -> str:
        """Ask user for confirmation with additional review and edit options"""
        print("\nOptions:")
        print("1. Cancel installation")
        print("2. Proceed with installation")
        print("3. Review and edit PKGBUILD (--editmenu --diffmenu)")
        
        while True:
            response = input("Choose (1/2/3): ").strip()
            if response == "1":
                return "cancel"
            elif response == "2":
                return "proceed"
            elif response == "3":
                return "review"
            else:
                print("Invalid choice. Please enter 1, 2, or 3.")
    
    def _run_yay_install(self, package_name: str, use_editmenu: bool = False, 
                        use_diffmenu: bool = False) -> bool:
        """Execute package installation using yay with optional review menus"""
        try:
            cmd = ["yay", "-S", package_name]
            
            if use_editmenu:
                cmd.append("--editmenu")
            if use_diffmenu:
                cmd.append("--diffmenu")
                
            print(f"🚀 Installing {package_name}...")
            if use_editmenu or use_diffmenu:
                print("📝 Review mode enabled - you'll be able to inspect/edit files")
                
            result = subprocess.run(cmd, check=False)
            return result.returncode == 0
        except Exception as e:
            print(f"Installation error: {e}")
            return False
    
    def run_yay_command(self, args: List[str]) -> int:
        """Execute a yay command as passthrough without security analysis"""
        try:
            return subprocess.run(["yay"] + args).returncode
        except Exception as e:
            print(f"Error executing yay command: {e}")
            return 1


def main():
    """Main entry point for plsaicheckyay - parse arguments and execute commands"""
    parser = argparse.ArgumentParser(
        description="plsaicheckyay - Secure wrapper for yay with AI analysis"
    )
    
    # AI Configuration
    parser.add_argument("--ai-provider", choices=["ollama", "openai", "openrouter"],
                       default="ollama", help="AI Provider to use")
    parser.add_argument("--ai-model", help="Specific AI model")
    parser.add_argument("--ai-host", default="http://localhost:11434",
                       help="OLLAMA host")
    parser.add_argument("--api-key", help="API key for OpenAI/OpenRouter")
    
    # Commands
    parser.add_argument("-S", "--sync", metavar="PACKAGE", nargs="*",
                       help="Install packages with security analysis")
    parser.add_argument("--force", action="store_true",
                       help="Force installation even if flagged as unsafe")
    
    # Security options
    parser.add_argument("--auto-threshold", type=float, metavar="0.0-1.0",
                       help="Auto-install if confidence >= threshold (e.g., 0.8 for 80%%)")
    parser.add_argument("--editmenu", action="store_true",
                       help="Enable edit menu for PKGBUILD review (yay --editmenu)")
    parser.add_argument("--diffmenu", action="store_true", 
                       help="Enable diff menu for build file changes (yay --diffmenu)")
    parser.add_argument("--analyze-official", action="store_true",
                       help="Force analysis even for official repository packages")
    parser.add_argument("--debug", action="store_true",
                       help="Enable debug output for troubleshooting")
    parser.add_argument("--skip-url-verification", action="store_true",
                       help="Skip AI-powered URL verification (faster but less secure)")
    parser.add_argument("--skip-web-search", action="store_true",
                       help="Skip web search entirely (fallback mode)")
    parser.add_argument("--searxng-url", 
                       help="SearXNG instance URL (default: https://searxng.lan/)")
    
    # Passthrough per altri comandi yay
    parser.add_argument("yay_args", nargs="*", help="Argomenti da passare a yay")
    
    args = parser.parse_args()
    
    # Set SearXNG URL if provided
    if args.searxng_url:
        os.environ["SEARXNG_URL"] = args.searxng_url
    
    # Setup web search provider
    web_search_provider = None
    if not args.skip_web_search:
        searxng_url = args.searxng_url or os.getenv("SEARXNG_URL", "https://searxng.lan/")
        web_search_provider = SearXNGSearchProvider(searxng_url)
    
    # Configure AI provider
    if args.ai_provider == "ollama":
        ai_provider = OllamaProvider(
            model=args.ai_model or "llama3.1",
            host=args.ai_host,
            web_search_provider=web_search_provider
        )
    elif args.ai_provider == "openai":
        if not args.api_key:
            print("❌ API key richiesta per OpenAI")
            return 1
        ai_provider = OpenAIProvider(args.api_key, args.ai_model or "gpt-4", web_search_provider)
    elif args.ai_provider == "openrouter":
        if not args.api_key:
            print("❌ API key richiesta per OpenRouter")
            return 1
        ai_provider = OpenRouterProvider(args.api_key, args.ai_model, web_search_provider)
    
    wrapper = YayWrapper(ai_provider)
    
    # Set debug mode
    if args.debug:
        os.environ["PLSYAY_DEBUG"] = "1"
    
    # Set URL verification mode
    if args.skip_url_verification:
        os.environ["PLSYAY_SKIP_URL_VERIFICATION"] = "1"
    
    # Set web search mode
    if args.skip_web_search:
        os.environ["PLSYAY_SKIP_WEB_SEARCH"] = "1"
    
    # Validate auto-threshold
    if args.auto_threshold is not None:
        if not (0.0 <= args.auto_threshold <= 1.0):
            print("❌ --auto-threshold must be between 0.0 and 1.0")
            return 1
    
    # Handle commands
    if args.sync is not None:
        if not args.sync:
            print("❌ Specify at least one package to install")
            return 1
        
        success = True
        for package in args.sync:
            if not wrapper.install_package(
                package_name=package,
                force=args.force or args.analyze_official,
                auto_threshold=args.auto_threshold,
                use_editmenu=args.editmenu,
                use_diffmenu=args.diffmenu
            ):
                success = False
        
        return 0 if success else 1
    
    # Passthrough per altri comandi
    if args.yay_args:
        return wrapper.run_yay_command(args.yay_args)
    
    # Se non ci sono argomenti, mostra help
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())