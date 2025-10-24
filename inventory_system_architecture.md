# Technical Architecture Document
## Windows Active Directory Inventory Management System

### 1. System Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         Windows 11 Clients                       │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│  │ Agent Service│  │ Agent Service│  │ Agent Service│  ...     │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘         │
└─────────┼──────────────────┼──────────────────┼─────────────────┘
          │                  │                  │
          └──────────────────┴──────────────────┘
                             │
                      HTTPS (Port 443)
                             │
                             ▼
        ┌────────────────────────────────────────┐
        │          Load Balancer (HA)            │
        └────────────────────┬───────────────────┘
                             │
        ┌────────────────────┴───────────────────┐
        │                                         │
        ▼                                         ▼
┌──────────────────┐                 ┌──────────────────┐
│ Collection API   │                 │ Collection API   │
│   Server #1      │                 │   Server #2      │
│ (Windows/Linux)  │                 │ (Windows/Linux)  │
└────────┬─────────┘                 └────────┬─────────┘
         │                                     │
         └──────────────┬──────────────────────┘
                        │
                        ▼
            ┌──────────────────────┐
            │   Message Queue       │
            │  (RabbitMQ/Redis)     │
            └──────────┬───────────┘
                       │
                       ▼
            ┌──────────────────────┐
            │  Processing Workers   │
            │   (Microservices)     │
            └──────────┬───────────┘
                       │
                       ▼
        ┌──────────────────────────────┐
        │      Database Cluster         │
        │  ┌──────────┐  ┌──────────┐ │
        │  │ Primary  │  │ Replica  │ │
        │  │PostgreSQL│  │PostgreSQL│ │
        │  └──────────┘  └──────────┘ │
        └──────────────┬───────────────┘
                       │
                       ▼
        ┌──────────────────────────────┐
        │    Web Application Layer      │
        │  ┌─────────┐   ┌─────────┐  │
        │  │Dashboard│   │   API    │  │
        │  │  Server │   │  Gateway │  │
        │  └─────────┘   └─────────┘  │
        └──────────────────────────────┘
                       │
                       ▼
                [HTTPS Users/Browsers]
```

### 2. Component Architecture

#### 2.1 Windows 11 Agent Architecture

**Technology Stack:**
- Language: C# (.NET 6/7)
- Service Type: Windows Service
- Local Storage: SQLite for queue
- Communication: HttpClient with Polly for resilience

**Component Design:**

```csharp
namespace InventoryAgent
{
    // Core Components
    ├── Service
    │   ├── InventoryAgentService.cs       // Windows Service entry
    │   ├── ServiceConfiguration.cs        // Config management
    │   └── ServiceInstaller.cs           // Installation logic
    │
    ├── Collectors
    │   ├── IDataCollector.cs             // Interface
    │   ├── SystemInfoCollector.cs        // WMI queries
    │   ├── DiskInfoCollector.cs          // Disk serial collection
    │   ├── NetworkInfoCollector.cs       // IP/MAC collection
    │   └── UserInfoCollector.cs          // Login information
    │
    ├── Communication
    │   ├── ApiClient.cs                  // HTTPS communication
    │   ├── AuthenticationHandler.cs      // Certificate auth
    │   ├── RetryPolicy.cs               // Polly retry logic
    │   └── QueueManager.cs              // Offline queue
    │
    ├── Scheduling
    │   ├── TaskScheduler.cs              // Quartz.NET scheduler
    │   └── EventWatcher.cs               // Login event monitor
    │
    └── Logging
        ├── EventLogWriter.cs             // Windows Event Log
        └── FileLogger.cs                 // Local file logging
}
```

**Data Collection Methods:**

```csharp
// System Information via WMI
SELECT SerialNumber, Manufacturer, Model FROM Win32_BIOS
SELECT Name, DNSHostName FROM Win32_ComputerSystem

// Disk Information
SELECT SerialNumber, MediaType FROM Win32_DiskDrive WHERE MediaType='Fixed hard disk media'

// Network Information  
SELECT IPAddress, MACAddress FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=TRUE

// User Information
SELECT LastLogon, UserName FROM Win32_ComputerSystem
Event ID 4624 (Logon) from Security Event Log
```

**Configuration (appsettings.json):**

```json
{
  "AgentSettings": {
    "ServiceEndpoint": "https://inventory.company.com/api/v1",
    "CollectionInterval": "86400",
    "LoginEventDetection": true,
    "CertificateThumbprint": "...",
    "RetryAttempts": 3,
    "RetryDelaySeconds": 30,
    "OfflineQueueSize": 1000,
    "LogLevel": "Information"
  }
}
```

#### 2.2 Collection Service Architecture

**Technology Stack:**
- Platform: .NET 6/7 Core (cross-platform)
- Framework: ASP.NET Core Web API
- Message Queue: RabbitMQ or Redis Streams
- Database: PostgreSQL 14+
- Caching: Redis

**API Architecture:**

```csharp
namespace InventoryAPI
{
    Controllers/
    ├── InventoryController.cs
    │   ├── POST   /api/v1/inventory
    │   ├── GET    /api/v1/inventory/{id}
    │   ├── GET    /api/v1/inventory/search
    │   └── DELETE /api/v1/inventory/{id}
    │
    Services/
    ├── IInventoryService.cs
    ├── InventoryService.cs
    ├── ValidationService.cs
    ├── QueueService.cs
    └── CacheService.cs
    │
    Models/
    ├── InventoryRecord.cs
    ├── InventoryRequest.cs
    └── InventoryResponse.cs
    │
    Middleware/
    ├── AuthenticationMiddleware.cs
    ├── RateLimitingMiddleware.cs
    ├── LoggingMiddleware.cs
    └── ExceptionHandlingMiddleware.cs
    │
    Data/
    ├── InventoryDbContext.cs
    ├── Repositories/
    │   ├── IInventoryRepository.cs
    │   └── InventoryRepository.cs
    └── Migrations/
}
```

**Database Schema:**

```sql
-- Main inventory table
CREATE TABLE inventory (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    computer_name VARCHAR(255) NOT NULL,
    fqdn VARCHAR(255),
    serial_number VARCHAR(100) NOT NULL,
    manufacturer VARCHAR(100),
    model VARCHAR(100),
    last_user VARCHAR(255),
    last_login TIMESTAMP,
    agent_version VARCHAR(20),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(computer_name),
    INDEX idx_serial (serial_number),
    INDEX idx_user (last_user),
    INDEX idx_updated (updated_at)
);

-- Disk information (one-to-many)
CREATE TABLE inventory_disks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    inventory_id UUID REFERENCES inventory(id) ON DELETE CASCADE,
    serial_number VARCHAR(100) NOT NULL,
    media_type VARCHAR(50),
    capacity_gb INTEGER,
    INDEX idx_disk_serial (serial_number)
);

-- Network information (one-to-many)
CREATE TABLE inventory_network (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    inventory_id UUID REFERENCES inventory(id) ON DELETE CASCADE,
    ip_address INET NOT NULL,
    mac_address MACADDR,
    adapter_name VARCHAR(255),
    INDEX idx_ip (ip_address)
);

-- Historical tracking
CREATE TABLE inventory_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    inventory_id UUID REFERENCES inventory(id),
    change_type VARCHAR(50),
    change_data JSONB,
    changed_by VARCHAR(255),
    changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_inventory_history (inventory_id, changed_at)
);

-- Audit log
CREATE TABLE audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id VARCHAR(255),
    action VARCHAR(100),
    resource VARCHAR(255),
    details JSONB,
    ip_address INET,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_audit_user (user_id, timestamp)
);
```

**Message Queue Configuration:**

```yaml
# RabbitMQ Configuration
rabbitmq:
  host: mq.company.com
  port: 5672
  vhost: /inventory
  queues:
    - name: inventory.ingestion
      durable: true
      arguments:
        x-message-ttl: 86400000
        x-max-length: 100000
    - name: inventory.processing
      durable: true
    - name: inventory.notifications
      durable: true
```

#### 2.3 Dashboard Architecture

**Technology Stack:**
- Frontend: React 18 with TypeScript
- UI Framework: Material-UI or Ant Design
- State Management: Redux Toolkit
- API Client: Axios with interceptors
- Charts: Recharts or Chart.js
- Build: Vite
- Testing: Jest + React Testing Library

**Frontend Structure:**

```typescript
src/
├── components/
│   ├── common/
│   │   ├── Layout/
│   │   ├── Navigation/
│   │   └── LoadingSpinner/
│   ├── dashboard/
│   │   ├── DashboardView.tsx
│   │   ├── StatsCards.tsx
│   │   └── RecentActivity.tsx
│   ├── inventory/
│   │   ├── InventoryTable.tsx
│   │   ├── InventoryDetails.tsx
│   │   └── InventorySearch.tsx
│   └── reports/
│       ├── ReportGenerator.tsx
│       └── ReportViewer.tsx
│
├── services/
│   ├── api.ts
│   ├── auth.ts
│   └── export.ts
│
├── store/
│   ├── store.ts
│   ├── slices/
│   │   ├── inventorySlice.ts
│   │   ├── authSlice.ts
│   │   └── uiSlice.ts
│
├── hooks/
│   ├── useInventory.ts
│   ├── useAuth.ts
│   └── useWebSocket.ts
│
└── utils/
    ├── formatters.ts
    ├── validators.ts
    └── constants.ts
```

**API Integration:**

```typescript
// API Service Layer
class InventoryAPI {
  private client: AxiosInstance;

  constructor() {
    this.client = axios.create({
      baseURL: process.env.REACT_APP_API_URL,
      timeout: 10000,
    });

    this.client.interceptors.request.use(
      config => {
        const token = localStorage.getItem('auth_token');
        if (token) {
          config.headers.Authorization = `Bearer ${token}`;
        }
        return config;
      }
    );
  }

  async searchInventory(params: SearchParams): Promise<InventoryResult[]> {
    const response = await this.client.get('/inventory/search', { params });
    return response.data;
  }

  async getInventoryDetails(id: string): Promise<InventoryDetail> {
    const response = await this.client.get(`/inventory/${id}`);
    return response.data;
  }

  async exportReport(format: 'csv' | 'json', filters: any): Promise<Blob> {
    const response = await this.client.post('/reports/export', 
      { format, filters },
      { responseType: 'blob' }
    );
    return response.data;
  }
}
```

### 3. Security Architecture

#### 3.1 Authentication & Authorization

**Agent Authentication:**
- Certificate-based mutual TLS
- Certificates deployed via GPO
- Certificate validation at API gateway

**User Authentication:**
- SAML 2.0 / OAuth 2.0 with AD FS
- JWT tokens for session management
- Role-based access control (RBAC)

```yaml
# RBAC Configuration
roles:
  admin:
    permissions:
      - inventory:read
      - inventory:write
      - inventory:delete
      - reports:generate
      - settings:manage
  
  technician:
    permissions:
      - inventory:read
      - reports:generate
  
  viewer:
    permissions:
      - inventory:read
```

#### 3.2 Data Protection

**Encryption:**
- TLS 1.2+ for data in transit
- AES-256 for sensitive data at rest
- Column-level encryption for PII

**Data Sanitization:**
```csharp
public class DataSanitizer
{
    public InventoryRecord Sanitize(InventoryRecord record)
    {
        record.SerialNumber = SanitizeString(record.SerialNumber);
        record.UserName = SanitizeUserName(record.UserName);
        record.IPAddresses = SanitizeIPList(record.IPAddresses);
        return record;
    }

    private string SanitizeString(string input)
    {
        // Remove special characters, validate length
        return Regex.Replace(input, @"[^\w\-\.]", "");
    }
}
```

### 4. Deployment Architecture

#### 4.1 Agent Deployment

**Group Policy Deployment:**

```xml
<!-- GPO Configuration -->
<GPO name="InventoryAgentDeployment">
  <ComputerConfiguration>
    <MSI>
      <Package>\\domain\sysvol\software\InventoryAgent.msi</Package>
      <Assignment>Required</Assignment>
    </MSI>
    <Registry>
      <Key>HKLM\SOFTWARE\CompanyName\InventoryAgent</Key>
      <Values>
        <Value name="ServerEndpoint">https://inventory.company.com</Value>
        <Value name="CollectionInterval">86400</Value>
      </Values>
    </Registry>
    <Service>
      <Name>InventoryAgent</Name>
      <StartupType>Automatic</StartupType>
      <Account>NT AUTHORITY\SYSTEM</Account>
    </Service>
  </ComputerConfiguration>
</GPO>
```

**SCCM/Intune Alternative:**

```powershell
# SCCM Detection Script
$service = Get-Service -Name "InventoryAgent" -ErrorAction SilentlyContinue
if ($service -and $service.Status -eq 'Running') {
    Write-Output "Installed"
    exit 0
} else {
    exit 1
}
```

#### 4.2 Server Deployment

**Docker Compose Configuration:**

```yaml
version: '3.8'

services:
  api:
    image: inventory-api:latest
    deploy:
      replicas: 2
    environment:
      - DATABASE_URL=postgresql://postgres@db/inventory
      - REDIS_URL=redis://redis:6379
      - RABBITMQ_URL=amqp://rabbitmq:5672
    ports:
      - "8080:80"
    depends_on:
      - db
      - redis
      - rabbitmq

  worker:
    image: inventory-worker:latest
    deploy:
      replicas: 3
    environment:
      - DATABASE_URL=postgresql://postgres@db/inventory
      - RABBITMQ_URL=amqp://rabbitmq:5672
    depends_on:
      - db
      - rabbitmq

  dashboard:
    image: inventory-dashboard:latest
    ports:
      - "3000:80"
    environment:
      - API_URL=http://api:80

  db:
    image: postgres:14
    volumes:
      - postgres_data:/var/lib/postgresql/data
    environment:
      - POSTGRES_DB=inventory
      - POSTGRES_PASSWORD=${DB_PASSWORD}

  redis:
    image: redis:7-alpine
    volumes:
      - redis_data:/data

  rabbitmq:
    image: rabbitmq:3-management
    ports:
      - "15672:15672"
    volumes:
      - rabbitmq_data:/var/lib/rabbitmq

  nginx:
    image: nginx:alpine
    ports:
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./certs:/etc/nginx/certs
    depends_on:
      - api
      - dashboard

volumes:
  postgres_data:
  redis_data:
  rabbitmq_data:
```

**Kubernetes Alternative:**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: inventory-api
spec:
  replicas: 3
  selector:
    matchLabels:
      app: inventory-api
  template:
    metadata:
      labels:
        app: inventory-api
    spec:
      containers:
      - name: api
        image: inventory-api:latest
        ports:
        - containerPort: 80
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: inventory-secrets
              key: database-url
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
---
apiVersion: v1
kind: Service
metadata:
  name: inventory-api-service
spec:
  selector:
    app: inventory-api
  ports:
  - port: 80
    targetPort: 80
  type: LoadBalancer
```

### 5. Monitoring and Observability

#### 5.1 Metrics Collection

**Application Metrics:**
- Prometheus metrics endpoint
- Custom metrics for business logic
- Performance counters

```csharp
// Metrics Implementation
public class MetricsService
{
    private readonly Counter _inventorySubmissions = Metrics
        .CreateCounter("inventory_submissions_total", "Total inventory submissions");
    
    private readonly Histogram _processingDuration = Metrics
        .CreateHistogram("inventory_processing_duration_seconds", "Processing duration");
    
    private readonly Gauge _activeAgents = Metrics
        .CreateGauge("inventory_active_agents", "Number of active agents");
}
```

#### 5.2 Logging Strategy

**Structured Logging:**

```json
{
  "timestamp": "2024-01-15T10:30:45Z",
  "level": "INFO",
  "service": "inventory-api",
  "trace_id": "abc123",
  "user": "john.doe",
  "action": "inventory.submit",
  "details": {
    "computer_name": "DESKTOP-ABC123",
    "serial": "SN123456",
    "processing_time_ms": 145
  }
}
```

**Log Aggregation:**
- ELK Stack (Elasticsearch, Logstash, Kibana)
- Or Splunk for enterprise environments

#### 5.3 Health Checks

```csharp
// Health Check Implementation
public class InventoryHealthCheck : IHealthCheck
{
    public async Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context,
        CancellationToken cancellationToken)
    {
        var isHealthy = await CheckDatabaseConnection();
        isHealthy &= await CheckMessageQueue();
        isHealthy &= await CheckRedisCache();
        
        if (isHealthy)
        {
            return HealthCheckResult.Healthy("All systems operational");
        }
        
        return HealthCheckResult.Unhealthy("Service degraded");
    }
}
```

### 6. Disaster Recovery

#### 6.1 Backup Strategy

```bash
#!/bin/bash
# Automated Backup Script

# Database backup
pg_dump -h $DB_HOST -U $DB_USER -d inventory \
  | gzip > /backup/inventory_$(date +%Y%m%d_%H%M%S).sql.gz

# Retain 30 days of backups
find /backup -name "inventory_*.sql.gz" -mtime +30 -delete

# Sync to offsite storage
aws s3 sync /backup s3://company-backups/inventory/
```

#### 6.2 High Availability Configuration

- Database: PostgreSQL with streaming replication
- API: Multiple instances behind load balancer
- Message Queue: RabbitMQ cluster with mirrored queues
- Cache: Redis Sentinel for automatic failover

### 7. Performance Optimization

#### 7.1 Database Optimization

```sql
-- Partitioning for historical data
CREATE TABLE inventory_history_2024 PARTITION OF inventory_history
FOR VALUES FROM ('2024-01-01') TO ('2025-01-01');

-- Indexing strategy
CREATE INDEX CONCURRENTLY idx_inventory_search 
ON inventory USING gin(
  to_tsvector('english', computer_name || ' ' || serial_number || ' ' || last_user)
);

-- Materialized view for dashboard
CREATE MATERIALIZED VIEW inventory_summary AS
SELECT 
  COUNT(*) as total_systems,
  COUNT(DISTINCT last_user) as unique_users,
  manufacturer,
  COUNT(*) as count
FROM inventory
GROUP BY manufacturer
WITH DATA;

-- Refresh every hour
CREATE OR REPLACE FUNCTION refresh_inventory_summary()
RETURNS void AS $$
BEGIN
  REFRESH MATERIALIZED VIEW CONCURRENTLY inventory_summary;
END;
$$ LANGUAGE plpgsql;
```

#### 7.2 Caching Strategy

```csharp
public class CachedInventoryService
{
    private readonly IMemoryCache _cache;
    private readonly IInventoryRepository _repository;
    
    public async Task<InventoryRecord> GetInventoryAsync(string id)
    {
        var cacheKey = $"inventory:{id}";
        
        if (!_cache.TryGetValue(cacheKey, out InventoryRecord inventory))
        {
            inventory = await _repository.GetByIdAsync(id);
            
            var cacheOptions = new MemoryCacheEntryOptions()
                .SetSlidingExpiration(TimeSpan.FromMinutes(5))
                .SetAbsoluteExpiration(TimeSpan.FromHours(1));
                
            _cache.Set(cacheKey, inventory, cacheOptions);
        }
        
        return inventory;
    }
}
```

### 8. Testing Strategy

#### 8.1 Agent Testing

```csharp
[TestClass]
public class InventoryCollectorTests
{
    [TestMethod]
    public async Task CollectSystemInfo_ReturnsValidData()
    {
        // Arrange
        var collector = new SystemInfoCollector();
        
        // Act
        var result = await collector.CollectAsync();
        
        // Assert
        Assert.IsNotNull(result.SerialNumber);
        Assert.IsTrue(result.SerialNumber.Length > 0);
        Assert.IsNotNull(result.Manufacturer);
    }
}
```

#### 8.2 Load Testing

```javascript
// K6 Load Test Script
import http from 'k6/http';
import { check } from 'k6';

export let options = {
  stages: [
    { duration: '5m', target: 100 },  // Ramp up
    { duration: '10m', target: 100 }, // Stay at 100 users
    { duration: '5m', target: 0 },    // Ramp down
  ],
};

export default function() {
  let payload = JSON.stringify({
    computerName: `TEST-${__VU}-${__ITER}`,
    serialNumber: `SN${Date.now()}`,
    // ... other fields
  });

  let params = {
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + __ENV.API_TOKEN,
    },
  };

  let res = http.post('https://inventory-api/api/v1/inventory', payload, params);
  
  check(res, {
    'status is 200': (r) => r.status === 200,
    'response time < 500ms': (r) => r.timings.duration < 500,
  });
}
```

### 9. Migration Strategy

#### 9.1 Phased Rollout Plan

**Phase 1: Pilot (Week 1-2)**
- Deploy to IT department (50 machines)
- Monitor performance and gather feedback
- Adjust configuration as needed

**Phase 2: Limited Rollout (Week 3-4)**
- Deploy to single business unit (500 machines)
- Validate scalability
- Refine deployment process

**Phase 3: Full Deployment (Week 5-8)**
- Deploy organization-wide in batches
- 2,500 machines per day
- Monitor system health continuously

#### 9.2 Rollback Plan

```powershell
# Emergency Agent Removal Script
$computers = Get-ADComputer -Filter * | Select-Object -ExpandProperty Name

Invoke-Command -ComputerName $computers -ScriptBlock {
    Stop-Service -Name "InventoryAgent" -Force
    & msiexec.exe /x "{PRODUCT-GUID}" /quiet
    Remove-Item "C:\Program Files\InventoryAgent" -Recurse -Force
}
```

### 10. Cost Estimation

**Infrastructure Costs (Annual):**

| Component | Specification | Cost |
|-----------|--------------|------|
| API Servers | 2x 8vCPU, 16GB RAM | $3,600 |
| Database Server | 1x 16vCPU, 64GB RAM, 1TB SSD | $4,800 |
| Load Balancer | Managed Service | $1,200 |
| Message Queue | 2x 4vCPU, 8GB RAM | $1,800 |
| Storage | 5TB for backups/archives | $600 |
| SSL Certificates | Wildcard cert | $300 |
| **Total Infrastructure** | | **$12,300** |

**Development Costs:**

| Phase | Duration | Resources | Cost |
|-------|----------|-----------|------|
| Development | 12 weeks | 2 developers | $60,000 |
| Testing | 4 weeks | 1 QA engineer | $10,000 |
| Deployment | 4 weeks | 1 DevOps engineer | $12,000 |
| Documentation | 2 weeks | 1 technical writer | $4,000 |
| **Total Development** | | | **$86,000** |

**Operational Costs (Annual):**

| Item | Cost |
|------|------|
| Maintenance (0.5 FTE) | $50,000 |
| Monitoring tools | $2,400 |
| Backup storage | $1,200 |
| **Total Operational** | **$53,600** |

### 11. Appendices

#### A. PowerShell Agent Installation Script

```powershell
# Install-InventoryAgent.ps1
param(
    [Parameter(Mandatory=$true)]
    [string]$ServerEndpoint,
    
    [string]$InstallPath = "C:\Program Files\InventoryAgent",
    [string]$LogPath = "C:\ProgramData\InventoryAgent\Logs"
)

function Install-InventoryAgent {
    # Check if running as administrator
    if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Error "This script must be run as Administrator."
        exit 1
    }

    # Create directories
    New-Item -ItemType Directory -Force -Path $InstallPath
    New-Item -ItemType Directory -Force -Path $LogPath

    # Download agent
    $downloadUrl = "$ServerEndpoint/downloads/InventoryAgent.msi"
    $msiPath = "$env:TEMP\InventoryAgent.msi"
    
    Invoke-WebRequest -Uri $downloadUrl -OutFile $msiPath

    # Install MSI
    $arguments = @(
        "/i"
        "`"$msiPath`""
        "/quiet"
        "/qn"
        "/norestart"
        "/log"
        "`"$LogPath\install.log`""
        "SERVERENDPOINT=$ServerEndpoint"
    )
    
    Start-Process "msiexec.exe" -ArgumentList $arguments -Wait -NoNewWindow

    # Configure service
    Set-Service -Name "InventoryAgent" -StartupType Automatic
    Start-Service -Name "InventoryAgent"

    # Verify installation
    $service = Get-Service -Name "InventoryAgent" -ErrorAction SilentlyContinue
    if ($service.Status -eq 'Running') {
        Write-Host "Inventory Agent installed successfully!" -ForegroundColor Green
    } else {
        Write-Error "Installation failed. Check logs at $LogPath\install.log"
    }
}

Install-InventoryAgent
```

#### B. API Documentation Sample

```yaml
openapi: 3.0.0
info:
  title: Inventory Management API
  version: 1.0.0
  
paths:
  /api/v1/inventory:
    post:
      summary: Submit inventory data
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/InventoryRecord'
      responses:
        '201':
          description: Inventory record created
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/InventoryResponse'
        '400':
          description: Bad request
        '401':
          description: Unauthorized
        '429':
          description: Too many requests
          
  /api/v1/inventory/search:
    get:
      summary: Search inventory records
      parameters:
        - in: query
          name: q
          schema:
            type: string
          description: Search query
        - in: query
          name: limit
          schema:
            type: integer
            default: 20
        - in: query
          name: offset
          schema:
            type: integer
            default: 0
      responses:
        '200':
          description: Search results
          content:
            application/json:
              schema:
                type: array
                items:
                  $ref: '#/components/schemas/InventoryRecord'

components:
  schemas:
    InventoryRecord:
      type: object
      required:
        - computerName
        - serialNumber
      properties:
        computerName:
          type: string
        serialNumber:
          type: string
        manufacturer:
          type: string
        model:
          type: string
        diskSerials:
          type: array
          items:
            type: string
        ipAddresses:
          type: array
          items:
            type: string
        lastUser:
          type: string
        lastLogin:
          type: string
          format: date-time
```

#### C. Troubleshooting Guide

**Common Issues and Solutions:**

| Issue | Symptoms | Solution |
|-------|----------|----------|
| Agent not reporting | No data in dashboard | Check Windows Event Log, verify network connectivity, validate certificate |
| High CPU usage | Agent consuming >5% CPU | Adjust collection interval, check for WMI issues |
| Database performance | Slow dashboard queries | Run VACUUM ANALYZE, check indexes, consider partitioning |
| Authentication failures | 401 errors in logs | Verify AD connectivity, check certificate expiration |
| Queue backlog | Delayed data processing | Scale worker instances, check message TTL |

This completes the comprehensive technical architecture document for your Windows AD Inventory Management System.
