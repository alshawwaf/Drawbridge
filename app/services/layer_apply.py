"""Shared helpers for applying Dynamic Layer content and recording the result."""
import uuid

from ..models import DynamicLayer, LayerTask
from ..schemas.dynamic_layer import build_set_dynamic_content, evaluate_dynamic_content


def new_task_id() -> str:
    return str(uuid.uuid4())


def to_task_details(result: dict) -> dict:
    """Convert an evaluate_dynamic_content() result to the Gaia API show-task 'task-details' shape."""
    return {
        "change-summary": result.get("change_summary", {}),
        "validation-warnings": result.get("validation_warnings", []),
        "validation-errors": result.get("validation_errors", []),
        "dry-run": result.get("dry_run", False),
        "comments": result.get("comments", ""),
        "tags": result.get("tags", []),
    }


def apply_to_mock(db, layer: DynamicLayer, *, dry_run: bool = False) -> LayerTask:
    """Apply a layer against the built-in mock engine and record the task."""
    payload = build_set_dynamic_content(layer, dry_run=dry_run)
    result = evaluate_dynamic_content(payload)
    task = LayerTask(
        task_id=new_task_id(),
        layer_id=layer.id,
        target="mock",
        dry_run=dry_run,
        status=result["status"],
        status_code=result["status_code"],
        result=result,
    )
    db.add(task)
    db.commit()
    db.refresh(task)
    return task
