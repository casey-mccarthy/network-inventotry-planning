# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## User Context

**You are working with an advanced systems engineer** with deep expertise in:
- **Active Directory** architecture, Group Policy, and enterprise Windows environments
- **Government networks** including security requirements, compliance frameworks, and air-gapped systems
- Enterprise-scale Windows deployments and infrastructure management

Assume high-level technical knowledge. Focus on advanced implementation details, security best practices for government environments, and enterprise-grade solutions.

## Project Overview

This repository contains planning documentation and implementation specifications for a **Windows Active Directory Inventory Management System**. The system is designed to automate hardware inventory collection across Windows 11 workstations in an enterprise environment.

**Key Objective:** Track hardware assets (computer names, serial numbers, disk info, IP addresses, user login history) across AD-joined Windows systems with real-time collection and centralized management.

## Architecture Overview

The system follows a **three-tier architecture**:

1. **Client Agent** (Windows 11 workstations): Collects inventory data on login events and scheduled intervals
2. **Collection Service** (Server): RESTful API for data ingestion with message queue processing
3. **Dashboard** (Web application): React-based UI for viewing, searching, and reporting on inventory data

**Data Flow:**
- Windows 11 agents collect system information via WMI queries
- Agents transmit data via HTTPS with certificate-based authentication
- Collection service validates and queues data in RabbitMQ/Redis
- Processing workers persist data to PostgreSQL
- Dashboard provides real-time search and reporting capabilities

## Implementation Options

Two complete implementation approaches are documented:

### Option 1: Compiled .NET Service (`option1_compiled_client.md`)
- **Technology:** C# .NET 6/7 Windows Service
- **Deployment:** MSI package via GPO or SCCM
- **Best for:** Large-scale deployments (10,000+ endpoints), high security requirements
- **Key files:** Service runs continuously, uses SQLite for offline queue, WMI data collection

### Option 2: PowerShell Scripts (`option2_powershell_solution.md`)
- **Technology:** Native PowerShell scripts with Task Scheduler
- **Deployment:** Script deployment via GPO startup scripts
- **Best for:** Small-medium deployments (<10,000 endpoints), easier maintenance
- **Key files:** Scheduled tasks trigger collection on logon and daily schedule

**Recommendation:** Start with Option 2 for easier implementation and transition to Option 1 if scale or security requirements demand it.

## Key System Components

### Client Agent Collection
- **System Info:** BIOS serial, manufacturer, model, processor, memory (via Win32_BIOS, Win32_ComputerSystem, Win32_Processor)
- **Disk Info:** Physical disk serials, partition layout (via Win32_DiskDrive, Win32_DiskPartition)
- **Network Info:** IP addresses, MAC addresses, adapter details (via Win32_NetworkAdapterConfiguration)
- **User Info:** Last logged-in user, login timestamp (via Event ID 4624, Win32_ComputerSystem)

### Server Architecture
- **API Layer:** ASP.NET Core Web API with certificate authentication
- **Message Queue:** RabbitMQ or Redis Streams for async processing
- **Database:** PostgreSQL 14+ with table partitioning for historical data
- **Caching:** Redis for frequently accessed data

### Dashboard
- **Frontend:** React 18 + TypeScript, Material-UI/Ant Design
- **State Management:** Redux Toolkit
- **Features:** Real-time search, historical timeline, export (CSV/JSON), compliance reports

## Development Workflow

### For Client Agent Development (Option 1 - .NET)
```bash
# Build the project
dotnet restore
dotnet build -c Release

# Publish for deployment
dotnet publish -c Release -r win-x64 --self-contained false -o ./publish

# Build installer (requires WiX Toolset)
candle.exe -arch x64 Installer/InventoryAgent.wxs
light.exe Installer/InventoryAgent.wixobj -o publish/InventoryAgent.msi
```

### For Client Agent Development (Option 2 - PowerShell)
```powershell
# Test collection script locally
powershell.exe -ExecutionPolicy Bypass -File Collect-Inventory.ps1 -TriggerType Manual

# Install scheduled tasks
Install-InventoryTasks.ps1 -Force

# Run diagnostics
Test-InventoryAgent.ps1 -FullDiagnostics
```

### For Server Components
```bash
# Database setup
psql -U postgres -f database-schema.sql

# Run API with Docker Compose
docker-compose up -d

# Run database migrations
dotnet ef database update
```

### For Dashboard Development
```bash
# Install dependencies
npm install

# Development server
npm run dev

# Build for production
npm run build

# Run tests
npm test
```

## Deployment Commands

### GPO Deployment (Option 1 - Compiled)
```powershell
# Deploy via Group Policy
.\Deploy-InventoryAgent.ps1 -MSIPath ".\InventoryAgent.msi" `
                            -ServerEndpoint "https://inventory.company.com" `
                            -GPOName "Deploy-InventoryAgent" `
                            -TargetOU "OU=Computers,DC=company,DC=com"
```

### GPO Deployment (Option 2 - PowerShell)
```powershell
# Deploy PowerShell scripts via GPO
.\Deploy-InventoryPowerShell.ps1 -ServerEndpoint "https://inventory.company.com" `
                                  -GPOName "Deploy-InventoryAgent-PowerShell" `
                                  -TargetOU "OU=Computers,DC=company,DC=com"
```

### Server Deployment
```bash
# Using Docker Compose
docker-compose -f docker-compose.yml up -d

# Using Kubernetes
kubectl apply -f k8s/inventory-api-deployment.yaml
kubectl apply -f k8s/inventory-db-statefulset.yaml
```

## Testing

### Client Agent Testing
```powershell
# PowerShell Option
Test-InventoryAgent.ps1 -TestCollection -TestConnection -CheckTasks -ViewLogs

# .NET Option - Unit tests
dotnet test InventoryAgent.Tests
```

### API Testing
```bash
# Health check
curl https://inventory.company.com/api/v1/health

# Submit inventory (with certificate)
curl -X POST https://inventory.company.com/api/v1/inventory \
     -H "Content-Type: application/json" \
     --cert client.crt --key client.key \
     -d @sample-inventory.json
```

### Load Testing
```bash
# Using k6 (see inventory_system_architecture.md:800-834)
k6 run load-test.js
```

## Database Schema

**Primary Tables:**
- `inventory` - Main system records (computer_name, serial_number, manufacturer, model, last_user)
- `inventory_disks` - Physical disk information (linked to inventory via foreign key)
- `inventory_network` - Network adapter details (IP addresses, MAC addresses)
- `inventory_history` - Change tracking for audit compliance
- `audit_log` - User action auditing

**Indexes:** See `inventory_system_architecture.md:197-258` for full schema with indexes on serial_number, last_user, ip_address, and updated_at.

## Security Considerations

### Authentication
- **Agent Auth:** Certificate-based mutual TLS (certificates deployed via GPO)
- **User Auth:** SAML 2.0 / OAuth 2.0 with AD FS, JWT tokens
- **RBAC:** Admin, Technician, Viewer roles (see `inventory_system_architecture.md:394-413`)

### Data Protection
- TLS 1.2+ for all communications
- AES-256 encryption for PII at rest
- Column-level encryption for sensitive data
- No storage of passwords or credentials

### Code Security
- **Always run Snyk code scans** for new first-party code in Snyk-supported languages
- Fix any security issues found and rescan until clean
- Sign all binaries with enterprise code signing certificate
- Whitelist agent executable in antivirus systems

## Configuration

### Agent Configuration (PowerShell)
Location: `C:\ProgramData\InventoryAgent\Config.json`
```json
{
  "ServerEndpoint": "https://inventory.company.com/api/v1",
  "CertificateThumbprint": "",
  "EnableDebounce": true,
  "DebounceMinutes": 60,
  "MaxRetryAttempts": 3,
  "QueueMaxSize": 1000
}
```

### Agent Configuration (.NET)
Location: `C:\Program Files\InventoryAgent\Config\appsettings.json`
```json
{
  "AgentSettings": {
    "ServerEndpoint": "https://inventory.company.com",
    "CollectionIntervalHours": 24,
    "EnableLoginDetection": true,
    "OfflineQueueSize": 1000
  }
}
```

### Server Configuration
Environment variables or `appsettings.json`:
- `DATABASE_URL`: PostgreSQL connection string
- `REDIS_URL`: Redis cache connection
- `RABBITMQ_URL`: Message queue connection

## Monitoring & Troubleshooting

### Client Agent Logs
- **PowerShell:** `C:\ProgramData\InventoryAgent\Logs\inventory_YYYYMMDD.log`
- **.NET Service:** Windows Event Log (Application log, source: "InventoryAgent")

### Server Logs
- Structured JSON logging to stdout (for Docker) or filesystem
- ELK Stack or Splunk for aggregation
- Prometheus metrics endpoint at `/metrics`

### Common Issues
| Issue | Solution |
|-------|----------|
| Agent not reporting | Check Event Log, verify network connectivity, validate certificate |
| High CPU usage | Adjust collection interval, check for WMI issues |
| Slow dashboard queries | Run `VACUUM ANALYZE`, check indexes, consider partitioning |
| Authentication failures | Verify AD connectivity, check certificate expiration |

### Health Checks
```bash
# API health
curl https://inventory.company.com/api/v1/health

# Database connection
psql -U postgres -c "SELECT COUNT(*) FROM inventory;"

# Queue status
rabbitmqctl list_queues
```

## Performance Requirements

- **Agent collection:** <5 seconds per system
- **API response:** <500ms for writes, <2 seconds for searches
- **Dashboard load:** <3 seconds
- **Support:** 50,000+ endpoints with horizontal scaling
- **Resource usage:** Agent <50MB RAM, <1% CPU (compiled) or ~100MB RAM during execution (PowerShell)

## Project Structure

```
/
├── inventory_system_prd.md              # Product requirements document
├── inventory_system_architecture.md     # Technical architecture specs
├── option1_compiled_client.md           # .NET Windows Service implementation
├── option2_powershell_solution.md       # PowerShell script implementation
├── deployment-tools/                    # Deployment automation scripts
├── option1-dotnet-compiled/             # .NET service source code
├── option2-powershell-native/           # PowerShell scripts
├── security-templates/                  # Security configs and certificates
└── shared-documentation/                # Shared docs and API specs
```

## API Endpoints

Base URL: `https://inventory.company.com/api/v1`

- `POST /inventory` - Submit inventory data (requires certificate auth)
- `GET /inventory/{id}` - Retrieve single record
- `GET /inventory/search?q={query}` - Search inventory (supports computer_name, serial, IP, username)
- `GET /inventory/history/{id}` - Get historical data for system
- `GET /reports/{type}` - Generate reports (CSV/JSON export)
- `GET /health` - Health check endpoint

Rate limit: 100 requests/minute per agent

## Success Metrics

- **Coverage:** 95%+ of AD-joined Windows 11 workstations
- **Data freshness:** <5 minutes for new logins
- **Availability:** 99.9% service uptime
- **Performance:** <2 second search response time
- **Efficiency:** 90% reduction in manual inventory effort

## Additional Resources

- **Full technical specs:** See `inventory_system_architecture.md` for database schema, API documentation, deployment configurations
- **Product requirements:** See `inventory_system_prd.md` for functional requirements, use cases, and success criteria
- **Implementation guides:** See `option1_compiled_client.md` and `option2_powershell_solution.md` for complete source code
