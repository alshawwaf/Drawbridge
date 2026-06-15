"""The apply trace captures each Gaia step's request/response and redacts secrets."""
from app.services import apply_runner

PAYLOAD = {
    "dry-run": False,
    "objects": {"hosts": [{"name": "h", "ip-address": "1.1.1.1"}]},
    "referenced-objects": {"access-layers": ["dl"]},
    "access-layers-content": [{"name": "dl", "operation": "replace", "rulebase": [
        {"name": "r", "action": "Accept", "source": "any", "destination": "any", "service": "any"}
    ]}],
}


def test_mock_trace_steps_and_redaction(monkeypatch):
    monkeypatch.setattr(apply_runner.time, "sleep", lambda *_a, **_k: None)
    pid = "t1"
    apply_runner._PROGRESS[pid] = {"stage": "queued", "status": "running", "done_stages": []}
    result, status, code, task_id = apply_runner._run_mock(pid, PAYLOAD, False)

    steps = [s["step"] for s in result["trace"]]
    assert steps == ["login", "set-dynamic-content", "show-task", "logout"]
    assert status == "succeeded"

    login = result["trace"][0]
    assert login["request"]["body"]["password"] == "***"          # password never recorded
    assert login["response"]["sid"] == apply_runner._MASK          # session token masked

    push = result["trace"][1]
    assert push["request"]["headers"]["X-chkp-sid"] == apply_runner._MASK
    assert push["request"]["body"]["objects"]["hosts"][0]["name"] == "h"  # real payload captured
    assert push["response"]["task-id"]                            # task-id returned

    show = result["trace"][2]
    assert show["response"]["tasks"][0]["status"] == "succeeded"


def test_mock_trace_present_for_failed_validation(monkeypatch):
    monkeypatch.setattr(apply_runner.time, "sleep", lambda *_a, **_k: None)
    bad = {**PAYLOAD, "access-layers-content": [{"name": "dl", "operation": "replace",
           "rulebase": [{"name": "noaction"}]}]}  # missing action -> validation error
    apply_runner._PROGRESS["t2"] = {"stage": "queued", "status": "running", "done_stages": []}
    result, status, code, _ = apply_runner._run_mock("t2", bad, False)
    assert status == "failed"
    assert len(result["trace"]) == 4  # still captures the full session
