-- PostgreSQL Schema for CyberSec-CLI
-- This schema defines the tables and relationships for storing scan data

-- Enable UUID extension for generating unique identifiers
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Scans table: stores information about each scan job
CREATE TABLE scans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    target VARCHAR(255) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    user_id UUID,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE,
    config JSONB
);

-- Scan results table: stores detailed results for each scan
CREATE TABLE scan_results (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    port INTEGER NOT NULL,
    state VARCHAR(50) NOT NULL,
    service VARCHAR(100),
    version VARCHAR(100),
    banner TEXT,
    risk_level VARCHAR(50),
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance optimization
CREATE INDEX idx_scans_user_created ON scans(user_id, created_at);
CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_scan_results_scan_port ON scan_results(scan_id, port);
CREATE INDEX idx_scans_target ON scans(target);
CREATE INDEX idx_scan_results_port ON scan_results(port);
CREATE INDEX idx_scan_results_state ON scan_results(state);

-- Comments for documentation
COMMENT ON TABLE scans IS 'Stores information about each scan job';
COMMENT ON COLUMN scans.id IS 'Unique identifier for the scan';
COMMENT ON COLUMN scans.target IS 'Target hostname or IP address';
COMMENT ON COLUMN scans.status IS 'Current status of the scan (pending, running, completed, failed)';
COMMENT ON COLUMN scans.user_id IS 'Identifier for the user who initiated the scan';
COMMENT ON COLUMN scans.created_at IS 'Timestamp when the scan was created';
COMMENT ON COLUMN scans.completed_at IS 'Timestamp when the scan was completed';
COMMENT ON COLUMN scans.config IS 'JSON configuration for the scan';

COMMENT ON TABLE scan_results IS 'Stores detailed results for each scan';
COMMENT ON COLUMN scan_results.scan_id IS 'Reference to the scan this result belongs to';
COMMENT ON COLUMN scan_results.port IS 'Port number';
COMMENT ON COLUMN scan_results.state IS 'Port state (open, closed, filtered, etc.)';
COMMENT ON COLUMN scan_results.service IS 'Detected service name';
COMMENT ON COLUMN scan_results.version IS 'Service version';
COMMENT ON COLUMN scan_results.banner IS 'Service banner information';
COMMENT ON COLUMN scan_results.risk_level IS 'Risk level assessment';
COMMENT ON COLUMN scan_results.metadata IS 'Additional metadata as JSON';

-- Sample data for testing
-- INSERT INTO scans (target, user_id, config) VALUES 
-- ('example.com', '123e4567-e89b-12d3-a456-426614174000', '{"ports": "1-1000", "scan_type": "TCP"}');