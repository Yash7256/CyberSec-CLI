# PostgreSQL Migration Guide

This guide explains how to migrate from SQLite to PostgreSQL for the CyberSec-CLI application.

## Overview

The CyberSec-CLI application now supports PostgreSQL as a database backend with graceful fallback to SQLite if PostgreSQL is unavailable. This provides better concurrency, scalability, and performance for production deployments.

## Prerequisites

Ensure you have the following installed:
- PostgreSQL server (version 12 or higher)
- Python packages: `asyncpg`

## Architecture Changes

### New Database Schema

PostgreSQL uses a normalized schema with two tables:
1. `scans` - Stores scan metadata
2. `scan_results` - Stores detailed port scan results

This replaces the single-table approach used by SQLite.

### Database Abstraction Layer

A new database abstraction layer (`database/__init__.py`) allows the application to seamlessly switch between SQLite and PostgreSQL based on configuration.

## Configuration

### Environment Variables

The following environment variables can be used to configure PostgreSQL:

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | None | PostgreSQL connection URL |
| `DATABASE_TYPE` | `sqlite` | Database type (`sqlite` or `postgresql`) |

### Docker Configuration

If using Docker, the `docker-compose.yml` file includes a PostgreSQL service:

```yaml
postgres:
  image: postgres:15-alpine
  container_name: cybersec-postgres
  environment:
    POSTGRES_DB: cybersec
    POSTGRES_USER: cybersec
    POSTGRES_PASSWORD: cybersec123
  ports:
    - "5432:5432"
  restart: unless-stopped
  networks:
    - cybersec-network
  volumes:
    - postgres-data:/var/lib/postgresql/data
  healthcheck:
    test: ["CMD-SHELL", "pg_isready -U cybersec"]
    interval: 10s
    timeout: 5s
    retries: 5
```

## Migration Process

### 1. Install Dependencies

Ensure PostgreSQL dependencies are installed:

```bash
pip install asyncpg
```

Or if using the project's requirements:

```bash
pip install -r requirements.txt
```

### 2. Configure Environment

Set the appropriate environment variables in your `.env` file:

```bash
DATABASE_URL=postgresql://cybersec:cybersec123@localhost:5432/cybersec
DATABASE_TYPE=postgresql
```

### 3. Initialize Database Schema

Apply the PostgreSQL schema:

```bash
psql -U cybersec -d cybersec -f database/postgres_schema.sql
```

Or using Docker:

```bash
docker exec -i cybersec-postgres psql -U cybersec -d cybersec < database/postgres_schema.sql
```

### 4. Migrate Existing Data

Use the migration script to transfer data from SQLite to PostgreSQL:

```bash
# Dry run to see what would be migrated
python database/migrate_sqlite_to_postgres.py --dry-run

# Actual migration
python database/migrate_sqlite_to_postgres.py
```

### 5. Verify Migration

Run the verification script to ensure data was migrated correctly:

```bash
python database/migrate_sqlite_to_postgres.py --verify
```

## Performance Benefits

### Concurrency

PostgreSQL supports multiple concurrent connections, allowing:
- Multiple users to access the system simultaneously
- Parallel scan processing
- Better resource utilization

### Scalability

- Horizontal scaling through read replicas
- Vertical scaling through better hardware
- Partitioning for large datasets

### Advanced Features

- JSONB for flexible configuration storage
- Indexes for faster queries
- Transactions for data consistency
- Foreign key constraints for data integrity

## Rollback Procedure

To rollback to SQLite:

1. Set environment variables:
   ```bash
   DATABASE_URL=
   DATABASE_TYPE=sqlite
   ```

2. Restart the application

3. The application will automatically fall back to SQLite

## Troubleshooting

### Common Issues

1. **Connection Refused**: Ensure PostgreSQL server is running and accessible
2. **Authentication Failed**: Check `DATABASE_URL` environment variable
3. **Schema Not Found**: Verify the schema was applied correctly

### Logs

Check application logs for database-related messages:
- `INFO` level for successful connections
- `WARNING` level for fallbacks to SQLite
- `ERROR` level for connection failures

## Performance Comparison

Run the benchmark script to compare performance:

```bash
python database/performance_benchmark.py
```

Typical results show PostgreSQL outperforming SQLite for:
- Concurrent access
- Large dataset queries
- Complex operations

## Best Practices

1. Use connection pooling for efficient resource usage
2. Apply appropriate indexes for common query patterns
3. Monitor database performance and adjust configuration as needed
4. Regularly backup PostgreSQL data
5. Use transactions for data consistency

## Security Considerations

1. Use strong passwords for database access
2. Enable SSL/TLS encryption for network connections
3. Restrict database access to trusted sources
4. Regularly update PostgreSQL to latest security patches
5. Audit database access logs

## Monitoring and Maintenance

### Health Checks

The application includes database health checks:
```bash
curl http://localhost:8000/health/database
```

### Maintenance Scripts

Regular maintenance tasks:
```bash
# Vacuum and analyze (PostgreSQL)
docker exec cybersec-postgres vacuumdb -U cybersec -d cybersec

# Backup database
docker exec cybersec-postgres pg_dump -U cybersec -d cybersec > backup.sql
```

## Future Enhancements

Planned improvements:
1. Database connection retry logic
2. Enhanced query optimization
3. Caching layer for frequently accessed data
4. Automated backup and restore procedures
5. Database migration versioning