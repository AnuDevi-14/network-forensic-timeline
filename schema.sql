-- ============================================================
-- Storage Layer Schema
-- Automated Network Forensic Analysis for Attack Timeline Reconstruction
-- Member 2 — Storage Layer
-- ============================================================
-- Run this against the "network_forensics" database.
-- In psql:
--   \c network_forensics
--   \i schema.sql
-- ============================================================

DROP TABLE IF EXISTS attack_timeline;

CREATE TABLE attack_timeline (
    event_order   INTEGER PRIMARY KEY,      -- sequence proxy for time (0 to 329,380)
    src_ip_dec    BIGINT NOT NULL,           -- source IP as decimal (up to ~4.29B, exceeds INT range)
    dst_ip_dec    BIGINT NOT NULL,           -- destination IP as decimal
    dst_port      INTEGER NOT NULL,          -- destination port (0-65535)
    attack_type   VARCHAR(20) NOT NULL,      -- 'DDoS', 'PortScan', 'PortScan+DDoS', 'Unknown'
    label         VARCHAR(20) NOT NULL       -- ground-truth label: 'BENIGN', 'DDoS', 'Portscan'
);

-- Helpful indexes for the Storage layer's own verification queries
-- (and useful later for Member 3's API layer, though that's not our job to build)
CREATE INDEX idx_attack_timeline_attack_type ON attack_timeline (attack_type);
CREATE INDEX idx_attack_timeline_label ON attack_timeline (label);
CREATE INDEX idx_attack_timeline_dst_port ON attack_timeline (dst_port);
