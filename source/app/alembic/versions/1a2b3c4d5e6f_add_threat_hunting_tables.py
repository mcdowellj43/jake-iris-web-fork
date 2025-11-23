"""Add threat hunting tables

Revision ID: 1a2b3c4d5e6f
Revises: ff917e2ab02e
Create Date: 2025-01-20 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '1a2b3c4d5e6f'
down_revision = 'ff917e2ab02e'
branch_labels = None
depends_on = None


def upgrade():
    # Create threat_hunting_queries table
    op.create_table(
        'threat_hunting_queries',
        sa.Column('query_id', sa.String(length=36), nullable=False),
        sa.Column('case_id', sa.Integer(), nullable=True),
        sa.Column('query_name', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('category', sa.String(length=100), nullable=True),
        sa.Column('opensearch_query', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('aggregation_config', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('threshold_config', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('mitre_attack_ids', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('severity', sa.String(length=20), nullable=True, server_default='medium'),
        sa.Column('default_time_range', sa.String(length=20), nullable=False, server_default='24h'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.text('true')),
        sa.Column('is_favorite', sa.Boolean(), nullable=False, server_default=sa.text('false')),
        sa.Column('saved_by', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('last_executed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('execution_count', sa.Integer(), nullable=False, server_default='0'),
        sa.ForeignKeyConstraint(['case_id'], ['cases.case_id'], ),
        sa.ForeignKeyConstraint(['saved_by'], ['user.id'], ),
        sa.PrimaryKeyConstraint('query_id')
    )

    # Create threat_hunting_results table
    op.create_table(
        'threat_hunting_results',
        sa.Column('result_id', sa.String(length=36), nullable=False),
        sa.Column('query_id', sa.String(length=36), nullable=False),
        sa.Column('case_id', sa.Integer(), nullable=True),
        sa.Column('executed_by', sa.Integer(), nullable=False),
        sa.Column('query_snapshot', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('time_range_start', sa.DateTime(timezone=True), nullable=False),
        sa.Column('time_range_end', sa.DateTime(timezone=True), nullable=False),
        sa.Column('result_data', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('aggregation_results', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('hit_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('execution_time_ms', sa.Integer(), nullable=True),
        sa.Column('status', sa.String(length=20), nullable=False, server_default='completed'),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('note_id', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['case_id'], ['cases.case_id'], ),
        sa.ForeignKeyConstraint(['executed_by'], ['user.id'], ),
        sa.ForeignKeyConstraint(['note_id'], ['case_notes.note_id'], ),
        sa.ForeignKeyConstraint(['query_id'], ['threat_hunting_queries.query_id'], ),
        sa.PrimaryKeyConstraint('result_id')
    )

    # Create threat_hunting_artifacts table
    op.create_table(
        'threat_hunting_artifacts',
        sa.Column('artifact_id', sa.String(length=36), nullable=False),
        sa.Column('result_id', sa.String(length=36), nullable=False),
        sa.Column('artifact_name', sa.String(length=255), nullable=False),
        sa.Column('artifact_type', sa.String(length=50), nullable=False),
        sa.Column('file_path', sa.String(length=500), nullable=False),
        sa.Column('file_size', sa.BigInteger(), nullable=True),
        sa.Column('is_downloadable', sa.Boolean(), nullable=False, server_default=sa.text('true')),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['result_id'], ['threat_hunting_results.result_id'], ),
        sa.PrimaryKeyConstraint('artifact_id')
    )

    # Create threat_hunting_schedules table
    op.create_table(
        'threat_hunting_schedules',
        sa.Column('schedule_id', sa.String(length=36), nullable=False),
        sa.Column('query_id', sa.String(length=36), nullable=False),
        sa.Column('case_id', sa.Integer(), nullable=True),
        sa.Column('schedule_type', sa.String(length=20), nullable=False),
        sa.Column('schedule_params', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('is_enabled', sa.Boolean(), nullable=False, server_default=sa.text('true')),
        sa.Column('alert_on_hits', sa.Boolean(), nullable=False, server_default=sa.text('true')),
        sa.Column('alert_threshold', sa.Integer(), nullable=True),
        sa.Column('notify_users', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('created_by', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('last_run_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('next_run_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['case_id'], ['cases.case_id'], ),
        sa.ForeignKeyConstraint(['created_by'], ['user.id'], ),
        sa.ForeignKeyConstraint(['query_id'], ['threat_hunting_queries.query_id'], ),
        sa.PrimaryKeyConstraint('schedule_id')
    )

    # Create indices for better performance
    op.create_index('ix_threat_hunting_queries_category', 'threat_hunting_queries', ['category'])
    op.create_index('ix_threat_hunting_queries_severity', 'threat_hunting_queries', ['severity'])
    op.create_index('ix_threat_hunting_queries_saved_by', 'threat_hunting_queries', ['saved_by'])
    op.create_index('ix_threat_hunting_results_query_id', 'threat_hunting_results', ['query_id'])
    op.create_index('ix_threat_hunting_results_executed_by', 'threat_hunting_results', ['executed_by'])
    op.create_index('ix_threat_hunting_results_created_at', 'threat_hunting_results', ['created_at'])
    op.create_index('ix_threat_hunting_results_status', 'threat_hunting_results', ['status'])


def downgrade():
    # Drop indices
    op.drop_index('ix_threat_hunting_results_status', table_name='threat_hunting_results')
    op.drop_index('ix_threat_hunting_results_created_at', table_name='threat_hunting_results')
    op.drop_index('ix_threat_hunting_results_executed_by', table_name='threat_hunting_results')
    op.drop_index('ix_threat_hunting_results_query_id', table_name='threat_hunting_results')
    op.drop_index('ix_threat_hunting_queries_saved_by', table_name='threat_hunting_queries')
    op.drop_index('ix_threat_hunting_queries_severity', table_name='threat_hunting_queries')
    op.drop_index('ix_threat_hunting_queries_category', table_name='threat_hunting_queries')

    # Drop tables in reverse order (respecting foreign keys)
    op.drop_table('threat_hunting_schedules')
    op.drop_table('threat_hunting_artifacts')
    op.drop_table('threat_hunting_results')
    op.drop_table('threat_hunting_queries')
