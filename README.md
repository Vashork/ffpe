# ffpe (FortiGate Firewall Policy Exporter)

## Overview

`ffpe` is a CLI tool for exporting, filtering, and post-processing
FortiGate firewall policies via the FortiOS REST API.

It supports:

-   Exporting firewall policies from FortiGate
-   Client-side filtering of policies
-   CSV export
-   DNS / address object resolution
-   Service → port resolution (including port range compression)
-   Fully environment-driven configuration via `.env`

------------------------------------------------------------------------

## Requirements

-   Python 3.9+
-   FortiGate FortiOS 6.x / 7.x
-   REST API access enabled
-   API Token with CMDB read permissions (firewall policy, address,
    service)

------------------------------------------------------------------------

## Installation

### 1. Clone repository

``` bash
git clone <repo_url>
cd ffpe
```

### 2. Create virtual environment

``` bash
python -m venv .venv
source .venv/bin/activate        # Linux/macOS
.venv\Scripts\activate         # Windows
```

### 3. Install dependencies

``` bash
pip install -r requirements.txt
```
### 4. Export inventory data (addresses and services)
Before using name and port resolution, export required CMDB objects from FortiGate:
```bash
 python scripts/export_addresses.py 
```
```bash
 python scripts/export_services.py
```
After execution, copy or verify that the generated files are located in:
```
    inventory/ 
    ├── firewall_addresses.csv 
    ├── firewall_services_custom.csv 
    └── firewall_service_groups_with_ports.csv
```

These files are required for:
- DNS fallback resolution (resolve_name.py)
- DNS fallback resolution (resolve_name.py)
------------------------------------------------------------------------

## Configuration

Create your runtime config:

``` bash
cp .env.example .env
```

Edit `.env` and set required values:

``` dotenv
FGT_API_TOKEN=
FGT_API_BASE_URL=https://<fortigate>/api/v2
FGT_VDOM=
```

Optional:

``` dotenv
FGT_VERIFY_TLS=false
FGT_TIMEOUT_SECONDS=20
```

------------------------------------------------------------------------

## Main Export

Run:

``` bash
python main.py
```

Output:

-   CSV written to `OUTPUT_DIR`
-   Filename controlled by `CSV_FILENAME`

Example:

``` dotenv
EXPORT_CSV=true
CSV_FILENAME=firewall_policies.csv
OUTPUT_DIR=./output
```

------------------------------------------------------------------------

## Filtering

All filters are client-side unless using `FGT_SERVER_FILTER`.

### Exact filters

``` dotenv
FILTER_SRCINTF=
FILTER_DSTINTF=
FILTER_ACTION=
FILTER_STATUS=
FILTER_NAME=
FILTER_POLICYID=
FILTER_SRCADDR=
FILTER_DSTADDR=
FILTER_SERVICE=
```

### IN filters (comma-separated)

``` dotenv
FILTER_SRCINTF_IN=
FILTER_DSTINTF_IN=
```

### NOT IN filters

``` dotenv
FILTER_DSTINTF_NOT_IN=DMZ,Guest
FILTER_STATUS_NOT_IN=disable
```

### Server-side (FortiOS query)

``` dotenv
FGT_SERVER_FILTER=srcintf==port1
```

------------------------------------------------------------------------

## Name / DNS Resolution

Script: `scripts/resolve_name.py`

Resolves:

-   IP → hostname (PTR)
-   hostname → IP (A)
-   fallback via exported address objects

### Enable

``` dotenv
RESOLVE_ENABLED=true
RESOLVE_COLUMNS=srcaddr,dstaddr
RESOLVE_DISPLAY_MODE=full   # full | ip
```

Run:

``` bash
python scripts/resolve_name.py
```

Interactive mode (optional):

``` dotenv
RESOLVE_INTERACTIVE=true
```

------------------------------------------------------------------------

## Service / Port Resolution

Script: `scripts/resolve_ports.py`

Resolves service names into:

    service_name(port/proto)

Supports:

-   Custom services
-   Service groups
-   Automatic port range compression

Example:

    4001/tcp 4002/tcp 4003/tcp
    → 4001-4003/tcp

### Enable

``` dotenv
PORTS_RESOLVE_ENABLED=true
PORTS_RESOLVE_COLUMNS=service
```

Required truth tables:

``` dotenv
PORTS_SERVICES_CSV=./inventory/firewall_services_custom.csv
PORTS_SERVICE_GROUPS_CSV=./inventory/firewall_service_groups_with_ports.csv
```

Run:

``` bash
python scripts/resolve_ports.py
```

Interactive selection:

``` dotenv
PORTS_RESOLVE_INTERACTIVE=true
```

------------------------------------------------------------------------

## Debug

``` dotenv
DEBUG=true
DEBUG_RESPONSE_KEYS=true
DEBUG_RESULTS_TYPE=true
```

Displays:

-   Final request URL
-   HTTP status
-   Response structure
-   Result size

------------------------------------------------------------------------

## Project Structure

    ffpe/
    ├── main.py
    ├── fgpol/
    │   ├── config.py
    │   ├── client.py
    │   ├── filters.py
    │   ├── fields.py
    │   ├── fortios.py
    │   ├── exporters.py
    │   └── table.py
    ├── scripts/
    │   ├── resolve_name.py
    │   ├── resolve_ports.py
    │   └── export_*.py
    ├── inventory/
    ├── output/
    ├── .env.example
    └── requirements.txt

------------------------------------------------------------------------

## Typical Workflow

1.  Export policies:

``` bash
python main.py
```

2.  Resolve names:

``` bash
python scripts/resolve_name.py
```

3.  Resolve ports:

``` bash
python scripts/resolve_ports.py
```

Final result:

    firewall_policies_ports.csv

------------------------------------------------------------------------

## Version

Current: 1.6
