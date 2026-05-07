# Apollo

Disclaimer: This project is intended solely for practice and development purposes. Any use beyond that is up to the user’s discretion.

A URL security scanner that analyzes any given URL for SSL validity, DNS resolution, and missing HTTP security headers — returning a structured risk assessment via a REST API.

---

## Tech Stack

- **Backend** — Python, FastAPI, httpx, Pydantic
- **Frontend** — Vanilla HTML/CSS/JS, Tailwind CSS
- **Checks** — SSL (socket), DNS (socket), Security Headers (httpx)

---

## Project Structure

```
apollo/
├── app/
│   ├── main.py                  # FastAPI app entry point, CORS config
│   ├── core/
│   │   └── checks/
│   │       ├── ssl.py           # SSLChecker — validates cert and expiry
│   │       ├── osint.py         # OSINTChecker — Check the hostname for footprints
│   │       └── headers.py       # HeaderChecker — probes HTTP security headers
│   ├── core/
│   │   └── scanner.py           # ScannerFacade — orchestrates all checks
│   ├── models/
│   │   └── scan.py              # Pydantic models — ScanRequest, ScanResponse
│   └── api/
│       └── scans.py             # POST /scans/ route
└── frontend/
    └── static/ main.js          # All JS functions
    └── index.html               # Frontend UI
```

---

## Setup

### Prerequisites

- Python 3.10+
- pip

### Installation

```bash
# clone the repo
git clone https://github.com/d3mon1-0slo/Apollo
cd apollo

# create and activate a virtual environment
python -m venv venv
source venv/bin/activate        # windows: venv\Scripts\activate

# install dependencies
pip install -r requirements.txt
```

### Running the server

```bash
uvicorn app.main:app --reload
```

Server runs at `http://127.0.0.1:8000`

---

## API Docs

### `POST /scans/`

Scans a URL and returns a full security risk assessment.

**Request body**

```json
{
  "url": "https://example.com"
}
```

**Response**

```json
{
  "url": "https://example.com",
  "ssl": {
    "ssl_valid": true,
    "expires_in_days": 41,
    "expired": false,
    "error": null
  },
  "dns": {
    "dns_resolves": true,
    "ip": "93.184.216.34",
    "error": null
  },
  "headers": {
    "strict-transport-security": true,
    "content-security-policy": false,
    "x-frame-options": true,
    "x-content-type-options": true,
    "missing": ["content-security-policy"]
  },
  "risk_level": "medium",
  "scanned_at": "2026-05-05T00:00:00.000000"
  "osint": {
        "whois": {
            "ip": "93.184.216.34",
            "asn": "29802",
            "org": "LAX2-46-21-150-0-24",
            "country": "US",
            "creation_date": "None",
            "age_days": null,
            "risk_flag": false
        },
        "reputation": {
            "ip": "93.184.216.34",
            "country": "United States",
            "isp": "HIVELOCITY, Inc.",
            "org": "",
            "is_proxy": false,
            "risk_flag": false
        },
        "server_info": {
            "server": "nginx",
            "powered_by": "PHP/8.2.30",
            "risk_flag": true,
            "risk_reason": "Server info exposed — attackers can fingerprint your stack"
        }
    },
    "port_scans": [
        {
            "port": 53,
            "label": "DNS",
            "open": true
        },
        {
            "port": 80,
            "label": "HTTP",
            "open": true
        },
        {
            "port": 443,
            "label": "HTTPS",
            "open": true
        }
    ],
    "scanned_at": "2026-05-07T11:38:18.126700Z"
}
```

**Risk levels**

| Level    | Condition                           |
| -------- | ----------------------------------- |
| `high`   | SSL invalid or DNS fails to resolve |
| `medium` | 2 or more security headers missing  |
| `low`    | All checks pass                     |

**Security headers checked**

| Header                      | Purpose                                  |
| --------------------------- | ---------------------------------------- |
| `strict-transport-security` | Forces HTTPS, prevents downgrade attacks |
| `content-security-policy`   | Prevents XSS attacks                     |
| `x-frame-options`           | Prevents clickjacking                    |
| `x-content-type-options`    | Prevents MIME sniffing                   |

---

## How the Checks Work

### SSLChecker

Opens a raw socket connection to port 443 and wraps it with TLS. Reads the certificate's `notAfter` field to determine validity and days remaining. Runs in a thread executor to avoid blocking the async event loop.

### DNSChecker

Uses `socket.gethostbyname()` to resolve the hostname to an IP address. Also runs in a thread executor for the same reason.

### HeaderChecker

Makes a real HTTP request using `httpx.AsyncClient` and inspects the response headers. Natively async — no thread executor needed.

### ScannerFacade

Orchestrates all three checkers using `asyncio.gather()` so they run in parallel, then assembles the results into a `ScanResponse`.

---

## CORS

CORS is enabled for all origins by default for local development. Restrict this before deploying to production:

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://yourdomain.com"],
    allow_methods=["POST"],
    allow_headers=["Content-Type"],
)
```

---

## Interactive API Docs

FastAPI provides built-in docs at:

- Swagger UI — `http://127.0.0.1:8000/docs`
- ReDoc — `http://127.0.0.1:8000/redoc`
