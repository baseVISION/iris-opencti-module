# IRIS OpenCTI Module

An [IRIS](https://github.com/dfir-iris/iris-web) processor module that pushes IOCs from IRIS cases to [OpenCTI](https://docs.opencti.io/) as STIX Cyber Observables and Indicators, linked to Case Incidents.

## Features

- Syncs IRIS IOCs to OpenCTI as STIX Cyber Observables + Indicators, grouped under a Case Incident — on create, update, delete, or manual trigger
- Skips re-push when nothing changed (hashes value, type, OpenCTI description, confidence override, and TLP)
- Writes an enrichment tab to each IOC with score, labels, indicators, ATT&CK context, sightings, and containers fetched from OpenCTI
- Maps 30+ IRIS IOC types to STIX observables; unsupported types are skipped and tagged `opencti:failed`
- Adds per-IOC custom fields (**OpenCTI Description**, **OpenCTI Confidence Score**) so analysts control exactly what is shared with OpenCTI
- Compatible with IRIS 2.4.x and 2.5.x case linkage models

## Requirements

| Component | Version |
|---|---|
| IRIS | ≥ 2.4.x |
| OpenCTI | 6.x |
| Python | ≥ 3.9 (container) |
| pycti | ≥ 6.0, < 7.0 |

## Installation

### Using the build script (recommended)

```bash
git clone https://github.com/baseVISION/iris-opencti-module.git
cd iris-opencti-module
bash buildnpush2iris.sh                      # installs into worker container and restarts it
bash buildnpush2iris.sh -a                   # also installs into app container (required on first install)
bash buildnpush2iris.sh -n <nginx-name>      # use a custom nginx container name
bash buildnpush2iris.sh -a -n <nginx-name>   # worker + app install, custom nginx name
```

The script builds the wheel, copies it into the running IRIS containers via Podman/Docker, installs `pycti` if not already present, and restarts the worker and nginx container.

### Manual installation

Clone the repo and run the following in one shell session — the wheel is built from source and then copied into the running containers:

```bash
git clone https://github.com/baseVISION/iris-opencti-module.git
cd iris-opencti-module

# Build the wheel from source
pip wheel . --no-deps -w dist/
WHL=$(ls dist/iris_opencti_module-*.whl | tail -1)
MODULE=$(basename "$WHL")

# Install pycti and the module into the app container
docker cp "$WHL" iriswebapp_app:/iriswebapp/dependencies/
docker exec iriswebapp_app pip3 install "pycti>=6.0,<7.0" --quiet
docker exec iriswebapp_app pip3 install "dependencies/$MODULE" --no-deps --force-reinstall

# Install pycti and the module into the worker container
docker cp "$WHL" iriswebapp_worker:/iriswebapp/dependencies/
docker exec iriswebapp_worker pip3 install "pycti>=6.0,<7.0" --quiet
docker exec iriswebapp_worker pip3 install "dependencies/$MODULE" --no-deps --force-reinstall

# Restart both containers
docker restart iriswebapp_app iriswebapp_worker
```

### Deployment on AKS (Kubernetes)

Copying files into pods is not persistent — installs are lost when pods restart. The correct approach is to build a custom Docker image with the module baked in, push it to Azure Container Registry, and update the AKS deployment.

**1. Create a `Dockerfile`** in your IRIS worker image build context:
```dockerfile
ARG BASE_IMAGE
FROM ${BASE_IMAGE}

# Installs the module and pycti (declared dependency) directly from GitHub
RUN pip3 install git+https://github.com/baseVISION/iris-opencti-module.git@v1.0.0
```

Replace `v1.0.0` with the desired tag or commit SHA for reproducible builds. `pycti` is installed automatically as a declared dependency — no separate step needed.

**2. Build and push via your Bicep/Azure Pipeline:**
```bash
az acr login --name <your-acr-name>

docker build \
  --build-arg BASE_IMAGE=<iris-worker-base-image> \
  -t <your-acr-name>.azurecr.io/iris-opencti-worker:1.0.0 .

docker push <your-acr-name>.azurecr.io/iris-opencti-worker:1.0.0
```

**3. Update the AKS worker deployment:**
```bash
kubectl set image deployment/<iris-worker-deployment> \
  <container-name>=<your-acr-name>.azurecr.io/iris-opencti-worker:1.0.0 \
  -n <namespace>

kubectl rollout status deployment/<iris-worker-deployment> -n <namespace>
```

**4. Register the module in IRIS** (one-time via the UI): Manage → Modules → Add module → `iris_opencti_module`

### Register in IRIS

Go to **Manage → Modules → Add module** and enter `iris_opencti_module`, then configure it under **Manage → Modules → IrisOpenCTI**.

## Configuration

All settings are in the IRIS UI under **Manage → Modules → IrisOpenCTI**.

### Connection

| Parameter | Description |
|---|---|
| OpenCTI URL | Base URL (e.g. `https://opencti.example.com`) |
| OpenCTI API Key | Token from OpenCTI: Settings → Security → API access |
| Verify SSL | Verify TLS certificates (default: `true`) |
| HTTP/HTTPS Proxy | Optional proxy URLs |

### Triggers

| Parameter | Default |
|---|---|
| Push on IOC create | `false` |
| Push on IOC update | `false` |
| Manual push button ("Sync to OpenCTI") | `true` |
| Push on IOC delete | `false` |

### Behavior

| Parameter | Default | Description |
|---|---|---|
| Create indicator | `true` | Create a detection Indicator alongside the Observable |
| Create Case Incident | `true` | Create/link an OpenCTI Case Incident per IRIS case |
| Default TLP | `amber` | Fallback TLP: `clear`, `green`, `amber`, `amber+strict`, `red` |
| Author organization | *(empty)* | "Created by" identity in OpenCTI |
| Default confidence | `50` | Confidence level 0–100 (can be overridden per-IOC via the **OpenCTI Confidence Score** custom field) |
| IRIS base URL | *(empty)* | Link back to IRIS IOC page on OpenCTI Case Incidents |

### IOC-level custom fields

On the first sync the module creates three editable custom fields directly on each IOC in the IRIS UI.

| Tab | Field | Purpose |
|---|---|---|
| **OpenCTI** | **OpenCTI Description** | Description pushed to OpenCTI as the observable description. Leave empty to create the observable without a description. |
| **OpenCTI** | **OpenCTI Confidence Score** | Integer 0–100. Overrides the module-level *Default confidence* for this individual IOC. Leave empty to use the module default. |

> **Why a separate description field?**  The IRIS `ioc_description` field often contains internal investigation notes that should not leave the platform.  The **OpenCTI Description** field lets analysts explicitly write a public-facing description when they want context to appear in OpenCTI.

### Case Naming

| Mode | OpenCTI case name |
|---|---|
| `case_name` | Full IRIS case name (e.g. `#3 - Phishing`) |
| `case_id` | `IRIS-Case-{id}` |
| `custom_prefix_id` | `{prefix}-{id}` |
| `custom_attribute` | Value of a custom case attribute (e.g. `CSIRT Case ID`) |

Additionally, **Include case description** (`true` by default) controls whether the IRIS case description is copied to the OpenCTI Case Incident.

## IOC Type Mapping

| IRIS type | OpenCTI observable |
|---|---|
| `ip-src`, `ip-dst` | IPv4-Addr / IPv6-Addr (auto-detected) |
| `ip-src\|port`, `ip-dst\|port` | IPv4-Addr (port discarded) |
| `domain`, `hostname` | Domain-Name / Hostname |
| `domain\|ip` | Domain-Name + IPv4-Addr |
| `url`, `uri`, `link` | Url |
| `md5`, `sha1`, `sha256`, `sha512`, `sha224`, `sha384` | File (with hash) |
| `ssdeep`, `tlsh`, `authentihash` | File (with hash) |
| `filename` | File.name |
| `filename\|md5`, `filename\|sha1`, `filename\|sha256`, `filename\|sha512` | File (name + hash) |
| `email`, `email-addr`, `email-src`, `email-dst` | Email-Addr |
| `mac-address` | Mac-Addr |
| `AS`, `as` | Autonomous-System |
| `registry-key` | Windows-Registry-Key |
| `user-agent` | User-Agent |
| `ja3-fingerprint-md5` | Text (raw JA3 value) |

Unsupported types are skipped, logged as a warning, and tagged `opencti:failed`.

## Tags

| Tag | Meaning |
|---|---|
| `opencti:pushed` | Successfully synced |
| `opencti:failed` | Sync failed (unsupported type or API error) |

## API Token Permissions

The token needs: Create/Update Observables, Indicators, Case Incidents; Read/List Case Incidents; Read Marking Definitions; Create Identities. The **Connector** role is sufficient.

## Development

```bash
pip install pytest
pytest iris_opencti_module/tests/ -v
```

When preparing a new release, update the version in `pyproject.toml` — `module_version` in `IrisOpenCTIConfig.py` is derived automatically from the installed package. Integration tests run automatically when pycti is installed and OpenCTI is reachable at `http://localhost:8080`. Override with env vars:

```bash
export OPENCTI_URL=http://localhost:8080
export OPENCTI_TOKEN=<your-api-key>
```

## License

[LGPL-3.0](LICENSE)
