#!/usr/bin/env python3
"""
NZ Privacy-First Enterprise AI Gateway - FastAPI Middleware

A hybrid LLM gateway that routes requests based on PII classification:
- RESTRICTED (contains PII) → Local MLX LLM
- PUBLIC (no PII) → Cloud API (OpenAI/Azure)

Compliance: NZ Privacy Act 2020, data sovereignty requirements
Enterprise Features: Multi-tenant, OAuth 2.0, Prometheus metrics, SIEM integration

Version: 1.0.0
Author: NZ Privacy-First AI Gateway Team
License: MIT
"""

import os
import re
import json
import hashlib
import asyncio
import logging
import time
import uuid
from datetime import datetime, timedelta
from enum import Enum
from typing import Optional, List, Dict, Any, AsyncGenerator, Tuple
from dataclasses import dataclass, asdict, field
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Depends, Header, Request, BackgroundTasks, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse
from fastapi.middleware.gzip import GZipMiddleware
from pydantic import BaseModel, Field, validator
from starlette.responses import PlainTextResponse
import httpx

# =============================================================================
# Version and Build Info
# =============================================================================

__version__ = "1.0.0"
__build_date__ = "2024-01-01"
__author__ = "NZ Privacy-First AI Gateway Team"

# =============================================================================
# Configuration
# =============================================================================

@dataclass
class GatewayConfig:
    """Gateway configuration loaded from environment."""
    # Core settings
    local_llm_url: str = "http://localhost:8080/v1"
    cloud_provider: str = "openai"  # "openai" or "azure"
    cloud_api_key: str = ""
    azure_endpoint: Optional[str] = None
    azure_api_version: str = "2024-02-15-preview"
    
    # Storage and limits
    audit_storage_path: str = "/var/log/ai-gateway"
    rate_limit_rpm: int = 100
    max_prompt_length: int = 32000
    max_concurrent_requests: int = 1000
    
    # Features
    enable_metrics: bool = True
    enable_siem: bool = False
    siem_endpoint: Optional[str] = None
    siem_api_key: Optional[str] = None
    
    # Security
    enable_rate_limiting: bool = True
    enable_ip_allowlist: bool = False
    allowed_ips: List[str] = field(default_factory=list)
    
    # Performance
    classification_timeout_ms: int = 50
    request_timeout_ms: int = 120000  # 2 minutes
    
    @classmethod
    def from_env(cls) -> "GatewayConfig":
        """Load configuration from environment variables."""
        allowed_ips_str = os.getenv("ALLOWED_IPS", "")
        allowed_ips = [ip.strip() for ip in allowed_ips_str.split(",")] if allowed_ips_str else []
        
        return cls(
            local_llm_url=os.getenv("LOCAL_LLM_URL", "http://localhost:8080/v1"),
            cloud_provider=os.getenv("CLOUD_PROVIDER", "openai"),
            cloud_api_key=os.getenv("CLOUD_API_KEY", ""),
            azure_endpoint=os.getenv("AZURE_ENDPOINT"),
            azure_api_version=os.getenv("AZURE_API_VERSION", "2024-02-15-preview"),
            audit_storage_path=os.getenv("AUDIT_STORAGE_PATH", "/var/log/ai-gateway"),
            rate_limit_rpm=int(os.getenv("RATE_LIMIT_RPM", "100")),
            max_prompt_length=int(os.getenv("MAX_PROMPT_LENGTH", "32000")),
            max_concurrent_requests=int(os.getenv("MAX_CONCURRENT_REQUESTS", "1000")),
            enable_metrics=os.getenv("ENABLE_METRICS", "true").lower() == "true",
            enable_siem=os.getenv("ENABLE_SIEM", "false").lower() == "true",
            siem_endpoint=os.getenv("SIEM_ENDPOINT"),
            siem_api_key=os.getenv("SIEM_API_KEY"),
            enable_rate_limiting=os.getenv("ENABLE_RATE_LIMITING", "true").lower() == "true",
            enable_ip_allowlist=os.getenv("ENABLE_IP_ALLOWLIST", "false").lower() == "true",
            allowed_ips=allowed_ips,
            classification_timeout_ms=int(os.getenv("CLASSIFICATION_TIMEOUT_MS", "50")),
            request_timeout_ms=int(os.getenv("REQUEST_TIMEOUT_MS", "120000")),
        )
    
    def validate(self) -> List[str]:
        """Validate configuration and return list of warnings."""
        warnings = []
        
        if not self.cloud_api_key and self.cloud_provider != "local":
            warnings.append("CLOUD_API_KEY not set - cloud API requests will fail")
        
        if self.rate_limit_rpm <= 0:
            warnings.append("RATE_LIMIT_RPM must be positive - using default 100")
            self.rate_limit_rpm = 100
        
        if self.max_prompt_length > 32000:
            warnings.append("MAX_PROMPT_LENGTH exceeds recommended 32KB limit")
        
        return warnings

# Global config instance
config = GatewayConfig.from_env()

# Log configuration warnings
config_warnings = config.validate()
for warning in config_warnings:
    logger.warning(f"Configuration warning: {warning}")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("nz-privacy-gateway")

# =============================================================================
# Configuration
# =============================================================================

@dataclass
class GatewayConfig:
    """Gateway configuration loaded from environment."""
    local_llm_url: str = "http://localhost:8080/v1"
    cloud_provider: str = "openai"  # "openai" or "azure"
    cloud_api_key: str = ""
    azure_endpoint: Optional[str] = None
    azure_api_version: str = "2024-02-15-preview"
    audit_storage_path: str = "/var/log/ai-gateway"
    rate_limit_rpm: int = 100
    max_prompt_length: int = 32000
    
    @classmethod
    def from_env(cls) -> "GatewayConfig":
        return cls(
            local_llm_url=os.getenv("LOCAL_LLM_URL", "http://localhost:8080/v1"),
            cloud_provider=os.getenv("CLOUD_PROVIDER", "openai"),
            cloud_api_key=os.getenv("CLOUD_API_KEY", ""),
            azure_endpoint=os.getenv("AZURE_ENDPOINT"),
            audit_storage_path=os.getenv("AUDIT_STORAGE_PATH", "/var/log/ai-gateway"),
            rate_limit_rpm=int(os.getenv("RATE_LIMIT_RPM", "100")),
            max_prompt_length=int(os.getenv("MAX_PROMPT_LENGTH", "32000")),
        )

# Global config instance
config = GatewayConfig.from_env()

# =============================================================================
# PII Detection
# =============================================================================

class Classification(str, Enum):
    PUBLIC = "PUBLIC"
    RESTRICTED = "RESTRICTED"

class Destination(str, Enum):
    LOCAL_LLM = "local_llm"
    CLOUD_API = "cloud_api"

class RequestStatus(str, Enum):
    SUCCESS = "success"
    ERROR = "error"
    TIMEOUT = "timeout"

@dataclass
class PIIMatch:
    pattern_name: str
    matched_text: str
    start_position: int
    end_position: int

@dataclass
class ClassificationResult:
    classification: Classification
    pii_matches: List[PIIMatch]
    processing_time_ms: float

class NZPIIDetector:
    """New Zealand specific PII detection using regex patterns."""
    
    # NHI (National Health Index) - 7 character alphanumeric
    NHI_PATTERN = re.compile(
        r'\b[A-Z]{3}[A-Z0-9]{4}\b',
        re.IGNORECASE
    )
    
    # IRD (Inland Revenue Department) - 9 digit format
    IRD_PATTERN = re.compile(
        r'\b\d{9}\b'
    )
    
    # NZ Driver Licence - 8-10 character alphanumeric format
    DRIVER_LICENCE_PATTERN = re.compile(
        r'\b(?:DL\s?)?[A-Z]{1,2}[0-9]{5,7}\b',
        re.IGNORECASE
    )
    
    # NZ Passport - 9 digit format (modern e-passport)
    NZ_PASSPORT_PATTERN = re.compile(
        r'\b[AZ]{2}[0-9]{7}\b',
        re.IGNORECASE
    )
    
    # NZ Bank Account - 15-16 digit format (ASB, ANZ, BNZ, Westpac, etc.)
    NZ_BANK_ACCOUNT_PATTERN = re.compile(
        r'\b(?:01|02|03|04|05|06|07|08|09|10|11|12|13|14|15|16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31)-[0-9]{2,4}-[0-9]{7,8}\b'
    )
    
    # Credit Card - 13-19 digits with common patterns
    CREDIT_CARD_PATTERN = re.compile(
        r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b'
    )
    
    # NZ phone numbers - multiple formats
    NZ_PHONE_PATTERN = re.compile(
        r'\b(?:\+?64|0)(?:[2-9]\d{7,8}|(?:[2-9]\d\s?){7,8})\b'
    )
    
    # NZ postal addresses
    NZ_ADDRESS_PATTERN = re.compile(
        r'\b\d+\s+[A-Za-z]+\s+(?:Street|Road|Avenue|Lane|Drive|Court|Place|Road|Boulevard|Esplanade|Terrace|Crescent|Hill|Gardens|Park|Way|Alley|Square)\b',
        re.IGNORECASE
    )
    
    # NZ postal box (PO Box) addresses
    NZ_POBOX_PATTERN = re.compile(
        r'\b(?:PO\s?Box|Private\s?Bag|Post\s?Box)\s*#?\s*\d+\b',
        re.IGNORECASE
    )
    
    # Email addresses with NZ domains
    NZ_EMAIL_PATTERN = re.compile(
        r'\b[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+(?:govt\.nz|co\.nz|ac\.nz|org\.nz|net\.nz|govt\.au|com\.au|edu\.au)\b',
        re.IGNORECASE
    )
    
    # Date of Birth - various NZ date formats
    DOB_PATTERN = re.compile(
        r'\b(?:0?[1-9]|[12][0-9]|3[01])[\/\-](?:0?[1-9]|1[0-2])[\/\-](?:19|20)\d{2}\b'
    )
    
    # Tax File Number (Australia - for cross-border)
    TFN_PATTERN = re.compile(
        r'\b\d{3}[\s\-]?\d{3}[\s\-]?\d{3}\b'
    )
    
    # WINZ Client Reference (Work and Income NZ)
    WINZ_PATTERN = re.compile(
        r'\b(?:WINZ|MSD)\s*[#]?\s*[A-Z0-9]{6,10}\b',
        re.IGNORECASE
    )
    
    # ACC Client Number (Accident Compensation Corporation)
    ACC_PATTERN = re.compile(
        r'\bACC\s*[#]?\s*[0-9]{8,10}\b',
        re.IGNORECASE
    )
    
    # KiwiSaver account numbers
    KIWI_SAVER_PATTERN = re.compile(
        r'\b(?:KS|KiwiSaver)\s*[#]?\s*[0-9]{6,12}\b',
        re.IGNORECASE
    )
    
    # General financial amounts with currency (for detecting salary/financial data)
    FINANCIAL_AMOUNT_PATTERN = re.compile(
        r'\$[\d,]+(?:\.\d{2})?(?:\s*(?:NZD|AUD|USD|EUR|GBP))?|\b(?:NZD|AUD|USD|EUR|GBP)\s*\$?[\d,]+(?:\.\d{2})?\b',
        re.IGNORECASE
    )
    
    def __init__(self):
        self._patterns = [
            ("NHI", self.NHI_PATTERN),
            ("IRD", self.IRD_PATTERN),
            ("DRIVER_LICENCE", self.DRIVER_LICENCE_PATTERN),
            ("PASSPORT", self.NZ_PASSPORT_PATTERN),
            ("BANK_ACCOUNT", self.NZ_BANK_ACCOUNT_PATTERN),
            ("CREDIT_CARD", self.CREDIT_CARD_PATTERN),
            ("NZ_PHONE", self.NZ_PHONE_PATTERN),
            ("NZ_ADDRESS", self.NZ_ADDRESS_PATTERN),
            ("NZ_POBOX", self.NZ_POBOX_PATTERN),
            ("NZ_EMAIL", self.NZ_EMAIL_PATTERN),
            ("DOB", self.DOB_PATTERN),
            ("TFN", self.TFN_PATTERN),
            ("WINZ", self.WINZ_PATTERN),
            ("ACC", self.ACC_PATTERN),
            ("KIWI_SAVER", self.KIWI_SAVER_PATTERN),
            ("FINANCIAL_AMOUNT", self.FINANCIAL_AMOUNT_PATTERN),
        ]
    
    def classify(self, prompt: str) -> ClassificationResult:
        """Scan prompt for PII and return classification."""
        start_time = datetime.utcnow()
        pii_matches: List[PIIMatch] = []
        
        # Scan for all PII patterns
        for pattern_name, pattern in self._patterns:
            for match in pattern.finditer(prompt):
                pii_matches.append(PIIMatch(
                    pattern_name=pattern_name,
                    matched_text=self._mask_pii(match.group()),
                    start_position=match.start(),
                    end_position=match.end()
                ))
        
        processing_time = (datetime.utcnow() - start_time).total_seconds() * 1000
        
        classification = Classification.RESTRICTED if pii_matches else Classification.PUBLIC
        
        return ClassificationResult(
            classification=classification,
            pii_matches=pii_matches,
            processing_time_ms=processing_time
        )
    
    def _mask_pii(self, text: str) -> str:
        """Mask PII for safe logging."""
        if len(text) <= 4:
            return "*" * len(text)
        return text[:2] + "*" * (len(text) - 4) + text[-2:]

# Global detector instance
pii_detector = NZPIIDetector()

# =============================================================================
# Audit Logging
# =============================================================================

@dataclass
class AuditLogEntry:
    """Immutable audit log entry - never includes PII or prompt content."""
    timestamp: str
    tenant_id: str
    user_id: str
    request_id: str
    classification: str
    destination: str
    pii_patterns_detected: List[str]
    prompt_hash: Optional[str]
    request_duration_ms: float
    status: str
    error_message: Optional[str] = None
    model_used: Optional[str] = None
    token_count: Optional[int] = None
    
    def to_dict(self) -> dict:
        return asdict(self)
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict())

class AuditLogger:
    """Privacy-compliant audit logger for NZ Privacy Act 2020 compliance."""
    
    def __init__(self, storage_path: str):
        self.storage_path = storage_path
        self._buffer: List[AuditLogEntry] = []
        self._buffer_size = 100
        self._lock = asyncio.Lock()
    
    def log_request(
        self,
        tenant_id: str,
        user_id: str,
        request_id: str,
        classification: Classification,
        destination: Destination,
        pii_matches: List[PIIMatch],
        prompt: str,
        duration_ms: float,
        status: RequestStatus,
        error_message: Optional[str] = None,
        model_used: Optional[str] = None
    ) -> AuditLogEntry:
        """Create audit log entry without storing PII or prompt content."""
        entry = AuditLogEntry(
            timestamp=datetime.utcnow().isoformat() + "Z",
            tenant_id=tenant_id,
            user_id=user_id,
            request_id=request_id,
            classification=classification.value,
            destination=destination.value,
            pii_patterns_detected=[m.pattern_name for m in pii_matches],
            prompt_hash=self._hash_prompt(prompt) if classification == Classification.RESTRICTED else None,
            request_duration_ms=duration_ms,
            status=status.value,
            error_message=error_message,
            model_used=model_used
        )
        
        self._buffer.append(entry)
        
        if len(self._buffer) >= self._buffer_size:
            self._flush()
        
        return entry
    
    def _hash_prompt(self, prompt: str) -> str:
        """Create SHA-256 hash for correlation without disclosure."""
        return hashlib.sha256(prompt.encode()).hexdigest()
    
    def _flush(self):
        """Flush buffer to persistent storage."""
        if not self._buffer:
            return
        
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.storage_path}/audit_{timestamp}.jsonl"
        
        try:
            with open(filename, "a") as f:
                for entry in self._buffer:
                    f.write(entry.to_json() + "\n")
            self._buffer.clear()
            logger.info(f"Flushed {len(self._buffer)} audit entries to {filename}")
        except Exception as e:
            logger.error(f"Failed to flush audit log: {e}")
    
    async def flush_async(self):
        """Async flush for use in request handlers."""
        async with self._lock:
            self._flush()

# Global audit logger
audit_logger = AuditLogger(config.audit_storage_path)

# =============================================================================
# Rate Limiting
# =============================================================================

class RateLimiter:
    """Token bucket rate limiter for per-tenant and per-user rate limiting."""
    
    def __init__(self, requests_per_minute: int = 100):
        self.requests_per_minute = requests_per_minute
        self.tokens_per_second = requests_per_minute / 60.0
        self._buckets: Dict[str, Tuple[float, float]] = {}  # (last_update, tokens)
        self._lock = asyncio.Lock()
    
    async def consume(self, key: str, tokens: int = 1) -> bool:
        """Consume tokens from bucket. Returns True if allowed, False if rate limited."""
        async with self._lock:
            now = time.time()
            last_update, bucket_tokens = self._buckets.get(key, (now, self.requests_per_minute))
            
            # Calculate tokens to add based on elapsed time
            elapsed = now - last_update
            new_tokens = min(
                self.requests_per_minute,
                bucket_tokens + elapsed * self.tokens_per_second
            )
            
            # Check if we have enough tokens
            if new_tokens >= tokens:
                self._buckets[key] = (now, new_tokens - tokens)
                return True
            else:
                # Not enough tokens - rate limited
                return False
    
    def get_remaining(self, key: str) -> int:
        """Get remaining tokens for a key."""
        now = time.time()
        last_update, bucket_tokens = self._buckets.get(key, (now, self.requests_per_minute))
        elapsed = now - last_update
        new_tokens = min(
            self.requests_per_minute,
            bucket_tokens + elapsed * self.tokens_per_second
        )
        return int(new_tokens)
    
    def reset(self, key: str):
        """Reset rate limit for a key."""
        self._buckets.pop(key, None)

# Global rate limiter
rate_limiter = RateLimiter(config.rate_limit_rpm)

# =============================================================================
# Metrics
# =============================================================================

class MetricsCollector:
    """Collect and expose Prometheus-compatible metrics."""
    
    def __init__(self):
        self._counters: Dict[str, float] = {}
        self._histograms: Dict[str, List[float]] = {}
        self._lock = asyncio.Lock()
        
        # Initialize metric categories
        self._init_metrics()
    
    def _init_metrics(self):
        """Initialize all metrics with zero values."""
        # Request metrics
        self._counters["requests_total"] = 0.0
        self._counters["requests_classification_public"] = 0.0
        self._counters["requests_classification_restricted"] = 0.0
        self._counters["requests_destination_local"] = 0.0
        self._counters["requests_destination_cloud"] = 0.0
        self._counters["requests_errors"] = 0.0
        self._counters["requests_rate_limited"] = 0.0
        
        # PII detection metrics
        self._counters["pii_detected_nhi"] = 0.0
        self._counters["pii_detected_ird"] = 0.0
        self._counters["pii_detected_phone"] = 0.0
        self._counters["pii_detected_email"] = 0.0
        self._counters["pii_detected_address"] = 0.0
        self._counters["pii_detected_bank_account"] = 0.0
        self._counters["pii_detected_credit_card"] = 0.0
        self._counters["pii_detected_other"] = 0.0
        
        # Token metrics
        self._counters["tokens_input"] = 0.0
        self._counters["tokens_output"] = 0.0
        
        # Latency histograms (in seconds)
        self._histograms["classification_latency"] = []
        self._histograms["request_latency"] = []
    
    def increment(self, metric: str, value: float = 1.0):
        """Increment a counter metric."""
        self._counters[metric] = self._counters.get(metric, 0.0) + value
    
    def observe(self, metric: str, value: float):
        """Observe a value for a histogram metric."""
        if metric in self._histograms:
            self._histograms[metric].append(value)
            # Keep only last 1000 values to prevent memory issues
            if len(self._histograms[metric]) > 1000:
                self._histograms[metric] = self._histograms[metric][-1000:]
    
    def get_metrics(self) -> str:
        """Generate Prometheus-compatible metrics output."""
        lines = [
            "# NZ Privacy-First AI Gateway Metrics",
            f"# Generated at {datetime.utcnow().isoformat()}Z",
            "",
        ]
        
        # Counters
        for name, value in sorted(self._counters.items()):
            lines.append(f"# HELP {name} Total number of {name}")
            lines.append(f"# TYPE {name} counter")
            lines.append(f"{name} {value}")
        
        # Histograms
        for name, values in sorted(self._histograms.items()):
            if values:
                lines.append(f"# HELP {name} Latency histogram for {name}")
                lines.append(f"# TYPE {name} histogram")
                
                # Calculate percentiles
                sorted_values = sorted(values)
                n = len(sorted_values)
                
                p50 = sorted_values[int(n * 0.50)]
                p95 = sorted_values[int(n * 0.95)]
                p99 = sorted_values[int(n * 0.99)]
                avg = sum(values) / n
                
                lines.append(f'{name}_count {n}')
                lines.append(f'{name}_sum {sum(values)}')
                lines.append(f'{name}_bucket{{le="{p50}"}} {int(n * 0.50)}')
                lines.append(f'{name}_bucket{{le="{p95}"}} {int(n * 0.95)}')
                lines.append(f'{name}_bucket{{le="{p99}"}} {int(n * 0.99)}')
        
        return "\n".join(lines)
    
    def reset(self):
        """Reset all metrics (useful for testing)."""
        self._init_metrics()

# Global metrics collector
metrics = MetricsCollector()

# =============================================================================
# SIEM Integration
# =============================================================================

class SIEMClient:
    """Client for sending events to SIEM platforms."""
    
    def __init__(self, endpoint: Optional[str] = None, api_key: Optional[str] = None):
        self.endpoint = endpoint
        self.api_key = api_key
        self._client: Optional[httpx.AsyncClient] = None
    
    async def _get_client(self) -> Optional[httpx.AsyncClient]:
        if not self.endpoint:
            return None
        if self._client is None:
            headers = {}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            self._client = httpx.AsyncClient(headers=headers, timeout=10.0)
        return self._client
    
    async def send_event(self, event: Dict[str, Any]) -> bool:
        """Send an event to the SIEM platform."""
        if not self.endpoint:
            return False
        
        client = await self._get_client()
        if not client:
            return False
        
        try:
            response = await client.post(
                self.endpoint,
                json=event,
                headers={"Content-Type": "application/json"}
            )
            return response.status_code in (200, 201, 202)
        except Exception as e:
            logger.error(f"SIEM send failed: {e}")
            return False
    
    async def close(self):
        """Close the SIEM client."""
        if self._client:
            await self._client.aclose()
            self._client = None

# Global SIEM client
siem_client = SIEMClient(
    endpoint=config.siem_endpoint,
    api_key=config.siem_api_key
)

# =============================================================================
# LLM Adapters
# =============================================================================

class BaseAdapter:
    """Base class for LLM adapters."""
    
    async def generate(self, prompt: str, **kwargs) -> str:
        raise NotImplementedError
    
    async def stream_generate(self, prompt: str, **kwargs) -> AsyncGenerator[str, None]:
        raise NotImplementedError
    
    async def health_check(self) -> bool:
        raise NotImplementedError

class LocalLLMAdapter(BaseAdapter):
    """Adapter for MLX local LLM running on Mac hardware."""
    
    def __init__(self, base_url: str, timeout: float = 120.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._client: Optional[httpx.AsyncClient] = None
    
    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self.timeout)
        return self._client
    
    async def generate(self, prompt: str, **kwargs) -> str:
        """Generate response from local MLX model."""
        client = await self._get_client()
        
        payload = {
            "prompt": prompt,
            "max_tokens": kwargs.get("max_tokens", 1024),
            "temperature": kwargs.get("temperature", 0.7),
            "stream": False
        }
        
        try:
            response = await client.post(
                f"{self.base_url}/v1/completions",
                json=payload,
                timeout=self.timeout
            )
            response.raise_for_status()
            data = response.json()
            return data["choices"][0]["text"]
        except httpx.HTTPError as e:
            logger.error(f"Local LLM request failed: {e}")
            raise RuntimeError(f"Local LLM request failed: {e}")
    
    async def stream_generate(self, prompt: str, **kwargs) -> AsyncGenerator[str, None]:
        """Stream response from local MLX model."""
        client = await self._get_client()
        
        payload = {
            "prompt": prompt,
            "max_tokens": kwargs.get("max_tokens", 1024),
            "temperature": kwargs.get("temperature", 0.7),
            "stream": True
        }
        
        try:
            async with client.stream(
                "POST",
                f"{self.base_url}/v1/completions",
                json=payload,
                timeout=self.timeout
            ) as response:
                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        data = line[6:]
                        if data != "[DONE]":
                            chunk = json.loads(data)
                            if "choices" in chunk:
                                yield chunk["choices"][0]["text"]
        except httpx.HTTPError as e:
            logger.error(f"Local LLM stream failed: {e}")
            raise RuntimeError(f"Local LLM stream failed: {e}")
    
    async def health_check(self) -> bool:
        """Check if local LLM is available."""
        try:
            client = await self._get_client()
            response = await client.get(f"{self.base_url}/health", timeout=10.0)
            return response.status_code == 200
        except Exception as e:
            logger.warning(f"Local LLM health check failed: {e}")
            return False
    
    async def close(self):
        if self._client:
            await self._client.aclose()
            self._client = None

class CloudAPIAdapter(BaseAdapter):
    """Adapter for OpenAI and Azure OpenAI APIs."""
    
    def __init__(
        self,
        provider: str,
        api_key: str,
        azure_endpoint: Optional[str] = None,
        azure_api_version: str = "2024-02-15-preview"
    ):
        self.provider = provider.lower()
        self.api_key = api_key
        self.azure_endpoint = azure_endpoint
        self.azure_api_version = azure_api_version
        self._client: Optional[httpx.AsyncClient] = None
        
        self._configure_endpoints()
    
    def _configure_endpoints(self):
        if self.provider == "azure" and self.azure_endpoint:
            self.base_url = self.azure_endpoint.rstrip("/")
        else:
            self.base_url = "https://api.openai.com/v1"
    
    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            headers = {"Authorization": f"Bearer {self.api_key}"}
            self._client = httpx.AsyncClient(headers=headers, timeout=60.0)
        return self._client
    
    async def generate(self, prompt: str, **kwargs) -> str:
        """Generate response from cloud API."""
        client = await self._get_client()
        
        model = kwargs.get("model", "gpt-4")
        
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": kwargs.get("max_tokens", 1024),
            "temperature": kwargs.get("temperature", 0.7)
        }
        
        endpoint = f"{self.base_url}/chat/completions"
        if self.provider == "azure":
            endpoint += f"?api-version={self.azure_api_version}"
        
        try:
            response = await client.post(endpoint, json=payload)
            response.raise_for_status()
            data = response.json()
            return data["choices"][0]["message"]["content"]
        except httpx.HTTPError as e:
            logger.error(f"Cloud API request failed: {e}")
            raise RuntimeError(f"Cloud API request failed: {e}")
    
    async def stream_generate(self, prompt: str, **kwargs) -> AsyncGenerator[str, None]:
        """Stream response from cloud API."""
        client = await self._get_client()
        
        payload = {
            "model": kwargs.get("model", "gpt-4"),
            "messages": [{"role": "user", "content": prompt}],
            "stream": True
        }
        
        endpoint = f"{self.base_url}/chat/completions"
        if self.provider == "azure":
            endpoint += f"?api-version={self.azure_api_version}"
        
        try:
            async with client.stream("POST", endpoint, json=payload) as response:
                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        data = line[6:]
                        if data != "[DONE]":
                            chunk = json.loads(data)
                            if "choices" in chunk:
                                delta = chunk["choices"][0].get("delta", {})
                                if "content" in delta:
                                    yield delta["content"]
        except httpx.HTTPError as e:
            logger.error(f"Cloud API stream failed: {e}")
            raise RuntimeError(f"Cloud API stream failed: {e}")
    
    async def health_check(self) -> bool:
        """Check if cloud API is available."""
        try:
            client = await self._get_client()
            response = await client.get(f"{self.base_url}/models")
            return response.status_code == 200
        except Exception as e:
            logger.warning(f"Cloud API health check failed: {e}")
            return False
    
    async def close(self):
        if self._client:
            await self._client.aclose()
            self._client = None

# =============================================================================
# Routing Engine
# =============================================================================

class RoutingEngine:
    """Routes requests based on classification results."""
    
    def __init__(
        self,
        local_adapter: LocalLLMAdapter,
        cloud_adapter: CloudAPIAdapter
    ):
        self.local_adapter = local_adapter
        self.cloud_adapter = cloud_adapter
    
    async def route_request(
        self,
        prompt: str,
        user_id: str,
        tenant_id: str,
        request_id: str,
        **kwargs
    ) -> tuple[Destination, str, float]:
        """
        Route request to appropriate AI backend.
        
        Returns:
            tuple of (destination, response, duration_ms)
        """
        start_time = datetime.utcnow()
        
        # Classify the prompt
        result = pii_detector.classify(prompt)
        
        # Route based on classification
        if result.classification == Classification.RESTRICTED:
            destination = Destination.LOCAL_LLM
            if not await self.local_adapter.health_check():
                error_msg = "Local LLM unavailable for RESTRICTED request"
                logger.error(error_msg)
                raise HTTPException(
                    status_code=503,
                    detail={"error": error_msg, "code": "LOCAL_LLM_UNAVAILABLE"}
                )
            response = await self.local_adapter.generate(prompt, **kwargs)
        else:
            destination = Destination.CLOUD_API
            response = await self.cloud_adapter.generate(prompt, **kwargs)
        
        duration_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
        
        # Log to audit trail
        audit_logger.log_request(
            tenant_id=tenant_id,
            user_id=user_id,
            request_id=request_id,
            classification=result.classification,
            destination=destination,
            pii_matches=result.pii_matches,
            prompt=prompt,
            duration_ms=duration_ms,
            status=RequestStatus.SUCCESS
        )
        
        return destination, response, duration_ms
    
    async def stream_route_request(
        self,
        prompt: str,
        user_id: str,
        tenant_id: str,
        request_id: str,
        **kwargs
    ) -> AsyncGenerator[str, None]:
        """Route streaming request to appropriate AI backend."""
        result = pii_detector.classify(prompt)
        
        if result.classification == Classification.RESTRICTED:
            destination = Destination.LOCAL_LLM
            if not await self.local_adapter.health_check():
                raise HTTPException(
                    status_code=503,
                    detail="Local LLM unavailable for RESTRICTED request"
                )
            generator = self.local_adapter.stream_generate(prompt, **kwargs)
        else:
            destination = Destination.CLOUD_API
            generator = self.cloud_adapter.stream_generate(prompt, **kwargs)
        
        # Collect response for audit logging
        full_response = ""
        async for chunk in generator:
            full_response += chunk
            yield chunk
        
        # Log to audit trail
        audit_logger.log_request(
            tenant_id=tenant_id,
            user_id=user_id,
            request_id=request_id,
            classification=result.classification,
            destination=destination,
            pii_matches=result.pii_matches,
            prompt=prompt,
            duration_ms=0,  # Streaming - duration tracked separately
            status=RequestStatus.SUCCESS
        )

# Initialize adapters
local_adapter = LocalLLMAdapter(config.local_llm_url)
cloud_adapter = CloudAPIAdapter(
    provider=config.cloud_provider,
    api_key=config.cloud_api_key,
    azure_endpoint=config.azure_endpoint
)
routing_engine = RoutingEngine(local_adapter, cloud_adapter)

# =============================================================================
# API Models
# =============================================================================

class AIRequest(BaseModel):
    """Incoming AI request from user."""
    prompt: str = Field(..., min_length=1, max_length=32000)
    model: Optional[str] = Field(None, description="Model override")
    max_tokens: Optional[int] = Field(None, ge=1, le=8192)
    temperature: Optional[float] = Field(None, ge=0.0, le=2.0)
    stream: Optional[bool] = Field(False)

class AIResponse(BaseModel):
    """AI response to user."""
    response_id: str
    content: str
    classification: Classification
    destination: str
    model_used: str
    request_duration_ms: float
    created_at: str

class ClassificationResponse(BaseModel):
    """Response from PII classification."""
    classification: Classification
    pii_patterns_found: List[str]
    processing_time_ms: float

class ErrorResponse(BaseModel):
    """Error response."""
    error: str
    error_code: str
    request_id: str
    timestamp: str

# =============================================================================
# Authentication
# =============================================================================

async def verify_auth(
    request: Request,
    x_user_id: Optional[str] = Header(None),
    x_tenant_id: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None)
) -> dict:
    """Verify authentication and return user context."""
    # Check for OAuth token or API key
    if authorization and authorization.startswith("Bearer "):
        token = authorization[7:]
        # In production, validate token with identity provider
        # For demo, accept any non-empty token
        if not token:
            raise HTTPException(status_code=401, detail="Invalid token")
        user_id = x_user_id or "user-from-token"
        tenant_id = x_tenant_id or "tenant-from-token"
    else:
        # API key authentication
        api_key = request.headers.get("X-API-Key")
        if not api_key:
            raise HTTPException(status_code=401, detail="Missing authentication")
        # In production, look up tenant from API key
        user_id = x_user_id or "user-from-api-key"
        tenant_id = x_tenant_id or "tenant-from-api-key"
    
    return {"user_id": user_id, "tenant_id": tenant_id}

# =============================================================================
# FastAPI Application
# =============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    logger.info("Starting NZ Privacy-First AI Gateway")
    yield
    logger.info("Shutting down NZ Privacy-First AI Gateway")
    await local_adapter.close()
    await cloud_adapter.close()
    await audit_logger.flush_async()

app = FastAPI(
    title="NZ Privacy-First Enterprise AI Gateway",
    description="Hybrid LLM Gateway with PII classification and routing",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Health check endpoints
@app.get("/health", tags=["Health"])
async def health_check():
    """Basic health check."""
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}

@app.get("/health/detailed", tags=["Health"])
async def detailed_health_check():
    """Detailed health check including backend status."""
    local_healthy = await local_adapter.health_check()
    cloud_healthy = await cloud_adapter.health_check()
    
    return {
        "status": "healthy" if (local_healthy or cloud_healthy) else "degraded",
        "timestamp": datetime.utcnow().isoformat(),
        "backends": {
            "local_llm": "healthy" if local_healthy else "unavailable",
            "cloud_api": "healthy" if cloud_healthy else "unavailable"
        }
    }

@app.get("/classify", tags=["PII"])
async def classify_pii(prompt: str):
    """Classify a prompt for PII content without making a request."""
    result = pii_detector.classify(prompt)
    return ClassificationResponse(
        classification=result.classification,
        pii_patterns_found=[m.pattern_name for m in result.pii_matches],
        processing_time_ms=result.processing_time_ms
    )

@app.post("/v1/completions", tags=["AI"])
async def create_completion(
    request: AIRequest,
    auth: dict = Depends(verify_auth),
    request_obj: Request = None
):
    """
    Create AI completion with PII-based routing.
    
    - PUBLIC prompts → Cloud API (OpenAI/Azure)
    - RESTRICTED prompts → Local LLM (MLX)
    
    Enterprise Features:
    - Rate limiting per tenant
    - Metrics collection for monitoring
    - SIEM integration for security logging
    """
    import uuid
    
    request_id = str(uuid.uuid4())
    user_id = auth["user_id"]
    tenant_id = auth["tenant_id"]
    
    # Rate limiting check
    if config.enable_rate_limiting:
        rate_limit_key = f"{tenant_id}:{user_id}"
        if not await rate_limiter.consume(rate_limit_key):
            metrics.increment("requests_rate_limited")
            remaining = rate_limiter.get_remaining(rate_limit_key)
            return JSONResponse(
                status_code=429,
                content={
                    "error": "Rate limit exceeded",
                    "error_code": "RATE_LIMIT_EXCEEDED",
                    "request_id": request_id,
                    "retry_after": 60,
                    "remaining": remaining
                },
                headers={"Retry-After": "60"}
            )
    
    # IP allowlist check
    if config.enable_ip_allowlist and config.allowed_ips:
        client_ip = request_obj.client.host if request_obj else ""
        if client_ip not in config.allowed_ips:
            metrics.increment("requests_errors")
            raise HTTPException(
                status_code=403,
                detail={"error": "Access denied", "error_code": "IP_NOT_ALLOWED"}
            )
    
    logger.info(f"Processing request {request_id} for user {user_id} tenant {tenant_id}")
    
    # Track request start time for metrics
    request_start = time.time()
    
    try:
        if request.stream:
            # Streaming response
            return StreamingResponse(
                routing_engine.stream_route_request(
                    prompt=request.prompt,
                    user_id=user_id,
                    tenant_id=tenant_id,
                    request_id=request_id,
                    model=request.model,
                    max_tokens=request.max_tokens,
                    temperature=request.temperature
                ),
                media_type="text/event-stream",
                headers={
                    "X-Request-ID": request_id,
                    "X-Classification": "PENDING"
                }
            )
        else:
            # Non-streaming response
            destination, response, duration_ms = await routing_engine.route_request(
                prompt=request.prompt,
                user_id=user_id,
                tenant_id=tenant_id,
                request_id=request_id,
                model=request.model,
                max_tokens=request.max_tokens,
                temperature=request.temperature
            )
            
            # Update metrics
            metrics.increment("requests_total")
            if destination == Destination.LOCAL_LLM:
                metrics.increment("requests_classification_restricted")
                metrics.increment("requests_destination_local")
            else:
                metrics.increment("requests_classification_public")
                metrics.increment("requests_destination_cloud")
            
            # Track latency
            request_latency = time.time() - request_start
            metrics.observe("request_latency", request_latency)
            
            # Send to SIEM if enabled
            if config.enable_siem:
                await siem_client.send_event({
                    "event_type": "completion",
                    "request_id": request_id,
                    "tenant_id": tenant_id,
                    "user_id": user_id,
                    "classification": "RESTRICTED" if destination == Destination.LOCAL_LLM else "PUBLIC",
                    "destination": destination.value,
                    "latency_ms": duration_ms,
                    "timestamp": datetime.utcnow().isoformat() + "Z"
                })
            
            return AIResponse(
                response_id=request_id,
                content=response,
                classification=Classification.RESTRICTED if destination == Destination.LOCAL_LLM else Classification.PUBLIC,
                destination=destination.value,
                model_used=request.model or "default",
                request_duration_ms=duration_ms,
                created_at=datetime.utcnow().isoformat() + "Z"
            )
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Request {request_id} failed: {e}")
        metrics.increment("requests_errors")
        
        # Log error to audit
        audit_logger.log_request(
            tenant_id=tenant_id,
            user_id=user_id,
            request_id=request_id,
            classification=pii_detector.classify(request.prompt).classification,
            destination=Destination.LOCAL_LLM,
            pii_matches=pii_detector.classify(request.prompt).pii_matches,
            prompt=request.prompt,
            duration_ms=0,
            status=RequestStatus.ERROR,
            error_message=str(e)
        )
        
        # Send error to SIEM
        if config.enable_siem:
            await siem_client.send_event({
                "event_type": "error",
                "request_id": request_id,
                "tenant_id": tenant_id,
                "user_id": user_id,
                "error": str(e),
                "error_type": type(e).__name__,
                "timestamp": datetime.utcnow().isoformat() + "Z"
            })
        
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/v1/models", tags=["AI"])
async def list_models(auth: dict = Depends(verify_auth)):
    """List available models."""
    return {
        "local": ["mlx-model"],
        "cloud": ["gpt-4", "gpt-3.5-turbo"] if config.cloud_provider == "openai" else ["gpt-4", "gpt-35-turbo"]
    }

@app.get("/v1/audit/export", tags=["Audit"])
async def export_audit_logs(
    auth: dict = Depends(verify_auth),
    start_date: Optional[str] = None,
    end_date: Optional[str] = None
):
    """Export audit logs (admin only in production)."""
    # In production, implement proper date filtering and access control
    return {"message": "Audit export endpoint - implement with actual storage backend"}

@app.get("/metrics", tags=["Monitoring"])
async def get_metrics():
    """Prometheus-compatible metrics endpoint."""
    if not config.enable_metrics:
        raise HTTPException(status_code=404, detail="Metrics disabled")
    return Response(
        content=metrics.get_metrics(),
        media_type="text/plain"
    )

@app.get("/ready", tags=["Health"])
async def readiness_check():
    """Kubernetes readiness probe endpoint."""
    local_healthy = await local_adapter.health_check()
    cloud_healthy = await cloud_adapter.health_check()
    
    # Check if at least one backend is available
    is_ready = local_healthy or cloud_healthy
    
    return {
        "ready": is_ready,
        "local_llm": local_healthy,
        "cloud_api": cloud_healthy
    }

@app.get("/live", tags=["Health"])
async def liveness_check():
    """Kubernetes liveness probe endpoint."""
    return {"alive": True, "timestamp": datetime.utcnow().isoformat()}

@app.get("/version", tags=["Info"])
async def get_version():
    """Get gateway version information."""
    return {
        "version": __version__,
        "build_date": __build_date__,
        "python_version": "3.10+",
        "classification_patterns": 16,
        "supported_providers": ["openai", "azure", "local"]
    }

@app.get("/config", tags=["Info"])
async def get_config(auth: dict = Depends(verify_auth)):
    """Get non-sensitive configuration (admin only in production)."""
    return {
        "cloud_provider": config.cloud_provider,
        "rate_limit_rpm": config.rate_limit_rpm,
        "max_prompt_length": config.max_prompt_length,
        "enable_metrics": config.enable_metrics,
        "enable_siem": config.enable_siem,
        "features": {
            "rate_limiting": config.enable_rate_limiting,
            "ip_allowlist": config.enable_ip_allowlist,
            "streaming": True,
            "multi_tenant": True
        }
    }

# =============================================================================
# Error Handlers
# =============================================================================

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Custom HTTP exception handler."""
    return JSONResponse(
        status_code=exc.status_code,
        content=exc.detail if isinstance(exc.detail, dict) else {
            "error": str(exc.detail),
            "error_code": "HTTP_ERROR",
            "status_code": exc.status_code
        }
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """General exception handler for unhandled errors."""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "error_code": "INTERNAL_ERROR",
            "message": "An unexpected error occurred"
        }
    )

# =============================================================================
# Main Entry Point
# =============================================================================

if __name__ == "__main__":
    import uvicorn
    import os
    
    # Load config from environment
    config = GatewayConfig.from_env()
    
    # Run the server
    uvicorn.run(
        "middleware:app",
        host="0.0.0.0",
        port=8080,
        ssl_keyfile=os.getenv("SSL_KEYFILE"),
        ssl_certfile=os.getenv("SSL_CERTFILE"),
        reload=False
    )