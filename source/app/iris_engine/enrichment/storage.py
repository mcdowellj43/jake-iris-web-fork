"""
Enrichment Storage Management
Handles artifact creation and note management for enrichment results
"""

import logging
import json
from datetime import datetime
from typing import Dict, Any, List, Optional

from flask_login import current_user
from sqlalchemy import and_

from app import db
from app.models import CaseAssets, AssetsType, Notes
from app.datamgmt.case.case_notes_db import get_note, add_note, update_note
from app.datamgmt.case.case_assets_db import create_asset
from app.datamgmt.states import update_assets_state, update_notes_state

log = logging.getLogger(__name__)


class EnrichmentStorageManager:
    """Manages storage of enrichment artifacts and notes"""

    def __init__(self):
        self._default_asset_type_id = None

    @property
    def default_asset_type_id(self) -> int:
        """Get the default asset type ID, creating it if necessary"""
        if self._default_asset_type_id is None:
            self._default_asset_type_id = self._get_json_asset_type_id()
        return self._default_asset_type_id

    def _get_json_asset_type_id(self) -> int:
        """Get or create JSON asset type for enrichment data"""
        json_type = AssetsType.query.filter_by(asset_name="JSON Data").first()

        if not json_type:
            # Create JSON asset type if it doesn't exist
            json_type = AssetsType(
                asset_name="JSON Data",
                asset_description="JSON formatted data files",
                asset_icon_not_compromised="far fa-file-code",
                asset_icon_compromised="fas fa-file-code"
            )
            db.session.add(json_type)
            db.session.commit()
            log.info("Created JSON asset type for enrichment data")

        return json_type.asset_id

    def create_enrichment_artifact(self, case_id: int, source_name: str, ioc_value: str,
                                 source_data: Dict[str, Any], profile_name: str) -> Optional[int]:
        """
        Create an artifact containing enrichment source data

        Args:
            case_id: Case ID
            source_name: Name of the enrichment source
            ioc_value: IOC value that was enriched
            source_data: Raw source data
            profile_name: Profile used for enrichment

        Returns:
            Asset ID if successful, None otherwise
        """
        try:
            # Generate artifact name with timestamp
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            artifact_name = f"{source_name}_{ioc_value}_{timestamp}.json"

            # Prepare artifact content
            artifact_content = {
                "source": source_name,
                "ioc_value": ioc_value,
                "profile": profile_name,
                "timestamp": datetime.utcnow().isoformat(),
                "data": source_data
            }

            # Create case asset
            asset = CaseAssets(
                asset_name=artifact_name,
                asset_description=f"Enrichment data from {source_name} for IOC: {ioc_value}",
                asset_type_id=self.default_asset_type_id,
                asset_tags=f"ioc,enrichment,{source_name},{profile_name}",
                case_id=case_id,
                date_added=datetime.utcnow(),
                date_update=datetime.utcnow(),
                user_id=current_user.id if current_user and current_user.is_authenticated else 1
            )

            # Store JSON content as file content (this would need proper file storage in production)
            json_content = json.dumps(artifact_content, indent=2)
            # In a real implementation, this would save to file storage and store the path
            asset.asset_file_path = f"/enrichment_artifacts/{artifact_name}"
            asset.asset_file_size = len(json_content.encode('utf-8'))

            db.session.add(asset)
            db.session.commit()

            # Update asset state
            update_assets_state(caseid=case_id)

            log.info(f"Created enrichment artifact {asset.asset_id} for {source_name}/{ioc_value}")
            return asset.asset_id

        except Exception as e:
            log.error(f"Failed to create enrichment artifact for {source_name}/{ioc_value}: {str(e)}")
            db.session.rollback()
            return None

    def get_case_note_by_title(self, case_id: int, title: str) -> Optional[Notes]:
        """
        Find a case note by exact title match

        Args:
            case_id: Case ID
            title: Note title to search for

        Returns:
            Notes object if found, None otherwise
        """
        try:
            note = Notes.query.filter(and_(
                Notes.note_case_id == case_id,
                Notes.note_title == title
            )).first()

            return note

        except Exception as e:
            log.error(f"Error searching for note '{title}' in case {case_id}: {str(e)}")
            return None

    def create_enrichment_note(self, case_id: int, title: str, content: str,
                             directory_id: int = 1) -> Optional[int]:
        """
        Create a new enrichment note

        Args:
            case_id: Case ID
            title: Note title
            content: Markdown content
            directory_id: Directory ID (default to root)

        Returns:
            Note ID if successful, None otherwise
        """
        try:
            user_id = current_user.id if current_user and current_user.is_authenticated else 1

            note_id = add_note(
                note_title=title,
                creation_date=datetime.utcnow(),
                user_id=user_id,
                caseid=case_id,
                directory_id=directory_id,
                note_content=content
            )

            if note_id:
                # Update notes state
                update_notes_state(caseid=case_id)
                log.info(f"Created enrichment note {note_id} in case {case_id}")

            return note_id

        except Exception as e:
            log.error(f"Failed to create enrichment note '{title}' in case {case_id}: {str(e)}")
            return None

    def update_enrichment_note(self, note_id: int, case_id: int, new_content: str,
                             title: str = None) -> bool:
        """
        Update an existing enrichment note

        Args:
            note_id: Note ID
            case_id: Case ID
            new_content: New note content
            title: New title (optional)

        Returns:
            True if successful, False otherwise
        """
        try:
            # Get existing note
            existing_note = get_note(note_id, case_id)
            if not existing_note:
                log.warning(f"Note {note_id} not found in case {case_id}")
                return False

            user_id = current_user.id if current_user and current_user.is_authenticated else 1
            update_title = title or existing_note.note_title

            # Update the note
            success = update_note(
                note_content=new_content,
                note_title=update_title,
                update_date=datetime.utcnow(),
                user_id=user_id,
                note_id=note_id,
                caseid=case_id
            )

            if success:
                # Update notes state
                update_notes_state(caseid=case_id)
                log.info(f"Updated enrichment note {note_id} in case {case_id}")

            return success

        except Exception as e:
            log.error(f"Failed to update enrichment note {note_id} in case {case_id}: {str(e)}")
            return False

    def upsert_enrichment_note(self, case_id: int, title: str, content: str,
                             update_mode: str = "prepend") -> Optional[int]:
        """
        Create or update an enrichment note (upsert operation)

        Args:
            case_id: Case ID
            title: Note title
            content: New content to add
            update_mode: "prepend", "append", or "replace"

        Returns:
            Note ID if successful, None otherwise
        """
        try:
            # Check if note exists
            existing_note = self.get_case_note_by_title(case_id, title)

            if existing_note:
                # Update existing note
                if update_mode == "prepend":
                    new_content = f"{content}\n\n{existing_note.note_content}"
                elif update_mode == "append":
                    new_content = f"{existing_note.note_content}\n\n{content}"
                else:  # replace
                    new_content = content

                success = self.update_enrichment_note(
                    existing_note.note_id,
                    case_id,
                    new_content,
                    title
                )

                return existing_note.note_id if success else None

            else:
                # Create new note
                return self.create_enrichment_note(case_id, title, content)

        except Exception as e:
            log.error(f"Failed to upsert enrichment note '{title}' in case {case_id}: {str(e)}")
            return None

    def create_enrichment_artifacts_batch(self, case_id: int, enrichment_results: Dict[str, Dict[str, Any]],
                                        ioc_value: str, profile_name: str) -> List[int]:
        """
        Create multiple artifacts from enrichment results

        Args:
            case_id: Case ID
            enrichment_results: Dict of {source_name: source_data}
            ioc_value: IOC value
            profile_name: Profile name

        Returns:
            List of created artifact IDs
        """
        artifact_ids = []

        for source_name, source_data in enrichment_results.items():
            # Skip failed sources
            if "_error" in source_data:
                continue

            artifact_id = self.create_enrichment_artifact(
                case_id=case_id,
                source_name=source_name,
                ioc_value=ioc_value,
                source_data=source_data,
                profile_name=profile_name
            )

            if artifact_id:
                artifact_ids.append(artifact_id)

        log.info(f"Created {len(artifact_ids)} enrichment artifacts for {ioc_value}")
        return artifact_ids

    def get_enrichment_artifacts(self, case_id: int, ioc_value: str = None,
                               profile_name: str = None) -> List[Dict[str, Any]]:
        """
        Get enrichment artifacts for a case, optionally filtered

        Args:
            case_id: Case ID
            ioc_value: Filter by IOC value (optional)
            profile_name: Filter by profile name (optional)

        Returns:
            List of artifact metadata
        """
        try:
            query = CaseAssets.query.filter(and_(
                CaseAssets.case_id == case_id,
                CaseAssets.asset_tags.contains('enrichment')
            ))

            if ioc_value:
                query = query.filter(CaseAssets.asset_name.contains(ioc_value))

            if profile_name:
                query = query.filter(CaseAssets.asset_tags.contains(profile_name))

            assets = query.order_by(CaseAssets.date_added.desc()).all()

            artifact_list = []
            for asset in assets:
                artifact_list.append({
                    "asset_id": asset.asset_id,
                    "asset_name": asset.asset_name,
                    "asset_description": asset.asset_description,
                    "asset_tags": asset.asset_tags,
                    "date_added": asset.date_added.isoformat() if asset.date_added else None,
                    "file_size": asset.asset_file_size,
                    "file_path": asset.asset_file_path
                })

            return artifact_list

        except Exception as e:
            log.error(f"Failed to get enrichment artifacts for case {case_id}: {str(e)}")
            return []


# Global storage manager instance
_storage_manager = None


def get_storage_manager() -> EnrichmentStorageManager:
    """Get the global storage manager instance"""
    global _storage_manager
    if _storage_manager is None:
        _storage_manager = EnrichmentStorageManager()
    return _storage_manager