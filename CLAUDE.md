# IRIS Web - IOC Enrichment Implementation

## Project Overview

**IRIS** (Incident Response Investigation System) is a collaborative web platform for incident responders to share technical details during investigations. This is version 2.4.22, built with Flask and deployed via Docker containers.

### Change control ###
- Every single change you make to the source code will be logged in a file called changes.md
- this is to document the changes so I can pull them into production

### Technology Stack
- **Backend**: Flask 2.3.2, SQLAlchemy, PostgreSQL
- **Task Queue**: Celery 5.2.7 with RabbitMQ
- **Frontend**: HTML/JavaScript with jQuery, Ace Editor
- **GraphQL**: Graphene 3.3 for API layer
- **Authentication**: Flask-Login, LDAP3 support
- **Deployment**: Docker Compose (5 services: app, db, rabbitmq, worker, nginx)

### Impport Docs ###
### ioc-enrichment-implementation.md
- contains the plan, guide, and steps to implement this feature into our IRIS application

### iris-module-documentation.md
- contains information about the structure of modules in IRIS for reference to create your own

### Project Structure
```
source/app/
├── blueprints/           # Flask blueprints (routes)
│   ├── case/            # Case management (IOCs, assets, notes, timeline)
│   ├── api/             # REST API endpoints
│   ├── graphql/         # GraphQL resolvers
│   └── manage/          # Admin management
├── models/              # SQLAlchemy models
├── business/            # Business logic layer
├── datamgmt/           # Data management utilities
├── iris_engine/        # Module system & task handling
├── static/             # Frontend assets (JS, CSS, images)
└── templates/          # Jinja2 templates
```

## Current IOC System

### Key Files
- **Backend Routes**: `source/app/blueprints/case/case_ioc_routes.py`
- **Frontend**: `source/app/static/assets/js/iris/case.ioc.js`
- **Template**: `source/app/blueprints/case/templates/case_ioc.html`
- **Business Logic**: `source/app/business/iocs.py`
- **Data Layer**: `source/app/datamgmt/case/case_iocs_db.py`
- **GraphQL**: `source/app/blueprints/graphql/iocs.py`
- **Models**: IOC models in `source/app/models/models.py`

### Current IOC Features
- Add/edit/delete IOCs with types (IP, domain, hash, etc.)
- IOC linking and relationships
- Comments on IOCs
- CSV bulk import
- TLP (Traffic Light Protocol) classifications
- Integration with external modules (VirusTotal, MISP, etc.)

## IOC Enrichment Implementation Plan

### Goal
Implement custom IOC enrichment profiles that allow SOC analysts to run one-click enrichment jobs directly from the IOC tab in case view, with results written to Notes and raw data stored as artifacts.

### Implementation Phases

#### Phase 1: Core Infrastructure
1. **Profile System** (`source/app/iris_engine/enrichment/`)
   - YAML-based profile definitions
   - Profile registry and loader
   - Support for IP-basic, Domain-basic, Hash-basic profiles

2. **Enrichment Sources** (`source/app/iris_engine/enrichment/sources/`)
   - Modular source implementations (AbuseIPDB, GreyNoise, Talos, etc.)
   - Standardized fetch interface
   - Error handling and timeouts

3. **Data Processing** (`source/app/iris_engine/enrichment/`)
   - Result normalization
   - Risk scoring algorithm
   - Markdown report generation

#### Phase 2: Celery Job System
1. **Enrichment Tasks** (`source/app/iris_engine/tasks/enrichment_tasks.py`)
   - Celery task for profile execution
   - Progress tracking
   - Result storage (Notes + Artifacts)

2. **Job Management**
   - Job status tracking
   - Error handling and retries
   - Idempotent note updates

#### Phase 3: API Layer
1. **GraphQL Extensions** (`source/app/blueprints/graphql/enrichment.py`)
   - `startIocJob` mutation
   - `jobStatus` query
   - Profile listing

2. **REST Endpoints** (if needed)
   - Profile management
   - Job monitoring

#### Phase 4: Frontend Integration
1. **IOC Table Enhancements** (`source/app/static/assets/js/iris/case.ioc.js`)
   - Right-click context menu with enrichment options
   - Bulk enrichment actions
   - Profile filtering by IOC type

2. **Job Status UI**
   - Job progress indicators
   - Toast notifications
   - "Open Note" links on completion

3. **Template Updates** (`source/app/blueprints/case/templates/case_ioc.html`)
   - Enrichment buttons/dropdowns
   - Status indicators

### Key Integration Points

#### Existing Module System
- Leverage `source/app/iris_engine/module_handler/` for consistency
- Use existing hook system for extensibility
- Follow current module patterns in dependencies/

#### Notes System
- Integrate with `source/app/blueprints/case/case_notes_routes.py`
- Use existing note upsert functionality
- Follow current note templating patterns

#### Artifacts System
- Store raw JSON in case artifacts
- Use existing artifact tagging system
- Integrate with `source/app/blueprints/case/case_assets_routes.py`

### Development Commands

```bash
# Start development environment
docker compose -f docker-compose.dev.yml up

# Run tests
python -m pytest tests/

# Database migrations
flask db migrate -m "Add enrichment tables"
flask db upgrade

# Lint/Format (if configured)
# Check project for existing tools
```

### File Locations for Implementation

1. **Core Enrichment Engine**:
   - `source/app/iris_engine/enrichment/profiles.py`
   - `source/app/iris_engine/enrichment/sources/`
   - `source/app/iris_engine/enrichment/normalizer.py`

2. **Database Models** (if new tables needed):
   - Add to `source/app/models/models.py`
   - Create migration in `source/app/alembic/versions/`

3. **API Layer**:
   - `source/app/blueprints/graphql/enrichment.py`
   - Extend `source/app/blueprints/case/case_ioc_routes.py`

4. **Frontend**:
   - Extend `source/app/static/assets/js/iris/case.ioc.js`
   - Update `source/app/blueprints/case/templates/case_ioc.html`

5. **Configuration**:
   - Profile YAML files in `source/app/iris_engine/enrichment/profiles/`
   - Environment variables for API keys

### Next Steps
1. Review the detailed implementation plan in `ioc-enrichment-implementation.md`
2. Set up development environment
3. Create core enrichment infrastructure
4. Implement first profile (IP-basic)
5. Add GraphQL API endpoints
6. Integrate frontend controls
7. Test end-to-end workflow

### Notes
- IRIS uses LGPL v3 license
- Follow existing code style and patterns
- Leverage current module system architecture
- Ensure RBAC compliance for profile access
- Consider caching for API quota management