# NZ Privacy-First Enterprise AI Gateway

A hybrid LLM gateway that routes AI requests based on PII classification, ensuring compliance with New Zealand's Privacy Act 2020 and data sovereignty requirements.

## Overview

This gateway sits between enterprise users and AI models (local MLX or cloud APIs like OpenAI/Azure), automatically detecting sensitive data and routing it to appropriate backends:

- **RESTRICTED** (contains PII) → Local MLX LLM (data never leaves your network)
- **PUBLIC** (no PII) → Cloud API (cost-effective for non-sensitive requests)

## Features

### Comprehensive PII Detection
Detects 16 types of sensitive data:
- **Government**: NHI, IRD, Driver Licence, Passport
- **Financial**: Bank Accounts, Credit Cards, Financial Amounts
- **Contact**: Phone Numbers, Addresses, PO Boxes, Emails
- **Personal**: Dates of Birth
- **Cross-border**: Australian TFN
- **NZ Programs**: WINZ/MSD, ACC, KiwiSaver

### Privacy-Compliant Audit Trail
- Logs metadata without storing PII or prompt content
- Uses SHA-256 hashing for correlation without disclosure
- 7-year retention for NZ Privacy Act compliance

### Hybrid Routing
- Local MLX integration for sensitive data
- OpenAI/Azure integration for public data
- Automatic routing based on classification

### Enterprise Features
- Multi-tenant isolation
- OAuth 2.0 and API key authentication
- Rate limiting per tenant
- Comprehensive audit logging

## Project Structure

```
.kiro/
├── specs/
│   └── nz-privacy-first-ai-gateway/
│       ├── requirements.md      # Requirements document
│       ├── design.md            # Design document
│       ├── tasks.md             # Implementation tasks
│       └── middleware.py        # Working FastAPI implementation
```

## Quick Start

```bash
# Install dependencies
pip install fastapi uvicorn httpx pydantic

# Run the gateway
python .kiro/specs/nz-privacy-first-ai-gateway/middleware.py

# Test classification
curl "http://localhost:8080/classify?prompt=My%20NHI%20is%20ABC1234D"

# Make a completion request
curl -X POST "http://localhost:8080/v1/completions" \
  -H "Content-Type: application/json" \
  -H "X-User-Id: user123" \
  -H "X-Tenant-Id: tenant456" \
  -d '{"prompt": "What is the capital of New Zealand?"}'
```

## Environment Variables

- `LOCAL_LLM_URL` - MLX server URL (default: http://localhost:8080/v1)
- `CLOUD_PROVIDER` - openai or azure
- `CLOUD_API_KEY` - API key for cloud provider
- `AZURE_ENDPOINT` - Azure OpenAI endpoint (optional)
- `AUDIT_STORAGE_PATH` - Path for audit logs
- `RATE_LIMIT_RPM` - Requests per minute limit

## Documentation

See the `.kiro/specs/` directory for:
- `requirements.md` - Detailed requirements and acceptance criteria
- `design.md` - Architecture, components, and sequence diagrams
- `tasks.md` - Implementation roadmap with 102 tasks

## Compliance

Designed for compliance with:
- New Zealand Privacy Act 2020
- Data sovereignty requirements
- NZ government security standards

## License

MIT License