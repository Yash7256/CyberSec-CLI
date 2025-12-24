# CyberSec-CLI Test Suite

This directory contains the comprehensive test suite for the CyberSec-CLI project. The tests are organized to cover all core functionality with a focus on unit testing, integration testing, and coverage.

## Test Structure

### Unit Tests
- `test_cache.py` - Tests for the Redis-based caching system
- `test_rate_limiter.py` - Tests for the multi-layer rate limiting system
- `test_validators.py` - Tests for input validation and sanitization
- `test_scanner.py` - Tests for the port scanning functionality
- `test_redis_client.py` - Tests for the Redis client wrapper
- `test_service_probes.py` - Tests for service detection probes
- `test_port_priority.py` - Tests for port prioritization logic

### Integration Tests
- `integration/test_scan_workflow.py` - End-to-end integration tests for the complete scan workflow

### Test Fixtures
- `conftest.py` - Shared test fixtures and configurations

## Running Tests

### Basic Test Execution
```bash
# Run all tests
python -m pytest tests/

# Run tests with verbose output
python -m pytest tests/ -v

# Run tests with coverage
python -m pytest tests/ --cov=core --cov=src --cov-report=term-missing
```

### Specific Test Execution
```bash
# Run a specific test file
python -m pytest tests/test_cache.py

# Run a specific test class
python -m pytest tests/test_cache.py::TestCacheKeyGeneration

# Run a specific test method
python -m pytest tests/test_cache.py::TestCacheKeyGeneration::test_cache_key_generation_consistency
```

## Test Coverage

The test suite aims for 80%+ coverage of all core functionality. Current coverage includes:

- Redis-based caching with SHA256 key generation and compression/decompression
- Rate limiting with sliding window, exponential backoff, and abuse detection
- Input validation and sanitization with blocklist/whitelist functionality
- Port prioritization with critical, high, medium, and low priority tiers
- Adaptive concurrency control based on network conditions
- Service detection accuracy for common protocols
- End-to-end scan workflow integration

## Test Fixtures

The test suite uses several important fixtures:

- `mock_redis_client` - Mock Redis client for testing without requiring Redis server
- `mock_cache` - Mock ScanCache instance with mocked Redis client
- `mock_rate_limiter` - Mock rate limiter instance
- `mock_scanner` - Mock port scanner instance
- `mock_scan_result` - Mock scan result data

## Development Guidelines

When adding new functionality to the CyberSec-CLI project, please ensure:

1. All new features have corresponding unit tests
2. Integration tests cover the interaction between components
3. Test coverage remains above 80%
4. Tests follow the existing naming and organization conventions
5. Tests are focused and test one specific behavior at a time

## Requirements

To run the full test suite, you need:

- Python 3.7+
- pytest
- pytest-cov (for coverage reports)
- redis (for Redis client tests, though mocked in most cases)
- All dependencies listed in requirements-dev.txt