# SPDX-License-Identifier: Apache-2.0
"""Run protection-removal controls in disposable copies, with no public service.

Usage: python3 scripts/check_artifact_controls.py NEW_OUTPUT_DIRECTORY
"""
from pathlib import Path
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
MODULE="driftcore/governance/artifact_channel.py"
CASES=[
    ("read_scope_promoted_to_publish",
     'required_scope=("artifact:" + op,), effects=[Effect.DATA_EGRESS],',
     'required_scope=("artifact:read",), effects=[Effect.DATA_EGRESS],',
     "test_read_scope_cannot_publish"),
    ("human_gate_requirement_removed",
     'type(broker._human_approval) is not HumanApprovalGate or not broker._enforce_effects',
     'not broker._enforce_effects',
     "test_install_requires_human_gate"),
    ("packet_hash_check_removed",
     '            if _sha(packet) != packet_sha256:',
     '            if False:',
     "test_even_signed_wrong_packet_hash_does_not_write"),
    ("exposure_history_disconnected",
     '            parents = {r[0] for r in db.execute("SELECT artifact FROM seen WHERE session=?", (session,))}',
     '            parents = set()',
     "test_three_agent_derivative_chain_keeps_original_roots"),
    ("retrieval_promotes_claim_status",
     '            provenance=provenance, roots=obj["manifest"]["roots"], source=source,\n            claim_status="UNVERIFIED", authority="NONE")',
     '            provenance=provenance, roots=obj["manifest"]["roots"], source=source,\n            claim_status="VERIFIED", authority="NONE")',
     "test_body_claiming_approval_never_becomes_authority"),
    ("write_ahead_reservation_removed",
     '            db.execute("INSERT INTO publications VALUES (?, \'PENDING\', NULL)", (publication_id,))',
     '            pass  # deliberately removed reservation',
     "test_uncertain_send_remains_blocked_after_restart"),
]


def run(tree,test,path):
    with tempfile.TemporaryDirectory() as logs:
        result=subprocess.run([sys.executable,"-m","unittest","test_artifact_channel.ArtifactChannelTests."+test],
            cwd=tree,capture_output=True,text=True,timeout=30,
            env={**os.environ,"PYTHONDONTWRITEBYTECODE":"1","DRIFTCORE_LOG_DIR":logs})
    output=result.stdout+result.stderr
    path.write_text(output)
    return result.returncode,output


def main():
    out=Path(sys.argv[1]).resolve()
    out.mkdir(parents=True,exist_ok=False)
    rows=[]
    for name,before,after,test in CASES:
        with tempfile.TemporaryDirectory(prefix="artifact-control-") as tmp:
            tree=Path(tmp)/"source"
            def ignore(directory,names):
                excluded=set(shutil.ignore_patterns("__pycache__","logs",".git","*.zip")(directory,names))
                if Path(directory)==ROOT:
                    excluded.add("verification")
                return excluded
            shutil.copytree(ROOT,tree,ignore=ignore)
            path=tree/MODULE
            original=path.read_text()
            if original.count(before)!=1:
                raise RuntimeError(name+": mutation anchor is not unique")
            healthy,_=run(tree,test,out/(name+"-healthy.log"))
            if healthy:
                raise RuntimeError(name+": healthy test failed")
            path.write_text(original.replace(before,after,1))
            removed,output=run(tree,test,out/(name+"-removed.log"))
            if not removed or "AssertionError" not in output or "ERROR:" in output:
                raise RuntimeError(name+": no qualifying assertion failure")
            path.write_text(original)
            restored,_=run(tree,test,out/(name+"-restored.log"))
            if restored:
                raise RuntimeError(name+": restored test failed")
            rows.append(dict(control=name,test=test,healthy_exit=healthy,removed_exit=removed,restored_exit=restored))
            print(name+": detected; restored test passed",flush=True)
    (out/"summary.json").write_text(json.dumps(rows,indent=2)+"\n")
    print(f"{len(rows)}/{len(CASES)} mutation controls detected")


if __name__=="__main__":
    main()
