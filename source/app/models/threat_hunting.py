#  IRIS Source Code
#  Copyright (C) 2025 - DFIR-IRIS
#  contact@dfir-iris.org
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU Lesser General Public
#  License as published by the Free Software Foundation; either
#  version 3 of the License, or (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#  Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public License
#  along with this program; if not, write to the Free Software Foundation,
#  Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

from sqlalchemy import Boolean
from sqlalchemy import Column
from sqlalchemy import DateTime
from sqlalchemy import Integer
from sqlalchemy import String
from sqlalchemy import Text
from sqlalchemy import BigInteger
from sqlalchemy import ForeignKey
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from app import db


class ThreatHuntingQuery(db.Model):
    """
    Stores threat hunting query definitions and execution history
    """
    __tablename__ = 'threat_hunting_queries'

    query_id = Column(String(36), primary_key=True)  # UUID
    case_id = Column(Integer, ForeignKey('cases.case_id'), nullable=True)
    query_name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    category = Column(String(100), nullable=True)  # Email Compromise, Lateral Movement, etc.
    opensearch_query = Column(JSONB, nullable=False)  # OpenSearch Query DSL
    aggregation_config = Column(JSONB, nullable=True)  # Aggregation configuration
    threshold_config = Column(JSONB, nullable=True)  # Alert thresholds
    mitre_attack_ids = Column(JSONB, nullable=True)  # MITRE ATT&CK technique IDs
    severity = Column(String(20), nullable=True, default='medium')  # low, medium, high, critical
    default_time_range = Column(String(20), nullable=False, default='24h')
    is_active = Column(Boolean, nullable=False, default=True)
    is_favorite = Column(Boolean, nullable=False, default=False)
    saved_by = Column(Integer, ForeignKey('user.id'), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_executed_at = Column(DateTime(timezone=True), nullable=True)
    execution_count = Column(Integer, nullable=False, default=0)

    # Relationships
    case = relationship('Cases', foreign_keys=[case_id])
    creator = relationship('User', foreign_keys=[saved_by])
    results = relationship('ThreatHuntingResult', back_populates='query', cascade='all, delete-orphan')


class ThreatHuntingResult(db.Model):
    """
    Stores execution results for threat hunting queries
    """
    __tablename__ = 'threat_hunting_results'

    result_id = Column(String(36), primary_key=True)  # UUID
    query_id = Column(String(36), ForeignKey('threat_hunting_queries.query_id'), nullable=False)
    case_id = Column(Integer, ForeignKey('cases.case_id'), nullable=True)
    executed_by = Column(Integer, ForeignKey('user.id'), nullable=False)
    query_snapshot = Column(JSONB, nullable=False)  # Query used for this execution
    time_range_start = Column(DateTime(timezone=True), nullable=False)
    time_range_end = Column(DateTime(timezone=True), nullable=False)
    result_data = Column(JSONB, nullable=False)  # Query results from OpenSearch
    aggregation_results = Column(JSONB, nullable=True)  # Aggregation results
    hit_count = Column(Integer, nullable=False, default=0)
    execution_time_ms = Column(Integer, nullable=True)  # Execution time in milliseconds
    status = Column(String(20), nullable=False, default='completed')  # queued, running, completed, failed
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    note_id = Column(Integer, ForeignKey('case_notes.note_id'), nullable=True)  # If added to case notes

    # Relationships
    query = relationship('ThreatHuntingQuery', back_populates='results')
    case = relationship('Cases', foreign_keys=[case_id])
    executor = relationship('User', foreign_keys=[executed_by])
    artifacts = relationship('ThreatHuntingArtifact', back_populates='result', cascade='all, delete-orphan')


class ThreatHuntingArtifact(db.Model):
    """
    Stores artifacts generated from threat hunting results (exported files, etc.)
    """
    __tablename__ = 'threat_hunting_artifacts'

    artifact_id = Column(String(36), primary_key=True)  # UUID
    result_id = Column(String(36), ForeignKey('threat_hunting_results.result_id'), nullable=False)
    artifact_name = Column(String(255), nullable=False)
    artifact_type = Column(String(50), nullable=False)  # json, csv, pdf
    file_path = Column(String(500), nullable=False)
    file_size = Column(BigInteger, nullable=True)
    is_downloadable = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    # Relationships
    result = relationship('ThreatHuntingResult', back_populates='artifacts')


class ThreatHuntingSchedule(db.Model):
    """
    Stores scheduled threat hunting query executions
    """
    __tablename__ = 'threat_hunting_schedules'

    schedule_id = Column(String(36), primary_key=True)  # UUID
    query_id = Column(String(36), ForeignKey('threat_hunting_queries.query_id'), nullable=False)
    case_id = Column(Integer, ForeignKey('cases.case_id'), nullable=True)
    schedule_type = Column(String(20), nullable=False)  # hourly, daily, weekly
    schedule_params = Column(JSONB, nullable=True)  # Cron expression or schedule config
    is_enabled = Column(Boolean, nullable=False, default=True)
    alert_on_hits = Column(Boolean, nullable=False, default=True)
    alert_threshold = Column(Integer, nullable=True)  # Alert if hit count exceeds threshold
    notify_users = Column(JSONB, nullable=True)  # User IDs to notify
    created_by = Column(Integer, ForeignKey('user.id'), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_run_at = Column(DateTime(timezone=True), nullable=True)
    next_run_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    query = relationship('ThreatHuntingQuery', foreign_keys=[query_id])
    case = relationship('Cases', foreign_keys=[case_id])
    creator = relationship('User', foreign_keys=[created_by])
