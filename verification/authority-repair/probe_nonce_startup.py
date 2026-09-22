# SPDX-License-Identifier: Apache-2.0
"""Synchronize concurrent nonce-store startup and retain child errors. No external effects."""
from pathlib import Path
import json,os,subprocess,sys,tempfile,time

CHILD = r"""
import sys,time
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from driftcore.verification.nonce_store_sqlite import SqliteNonceStore
root=Path(sys.argv[2]); worker=sys.argv[3]
(root/(worker+".ready")).touch()
while not (root/"go").exists(): time.sleep(.001)
s=SqliteNonceStore(str(root/"nonces.db"),retention_seconds=3600,max_grant_ttl_seconds=300)
for i in range(50): s.add(worker+"-"+str(i))
s.prune();s.close()
print("DONE")
"""

def probe(tree,workers=20,synchronize=True):
    with tempfile.TemporaryDirectory() as temporary:
        root=Path(temporary)
        if not synchronize: (root/"go").touch()
        children=[subprocess.Popen([sys.executable,"-c",CHILD,str(tree),str(root),"w"+str(i)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True) for i in range(workers)]
        deadline=time.monotonic()+15
        while len(list(root.glob("*.ready")))!=workers and time.monotonic()<deadline: time.sleep(.002)
        ready=len(list(root.glob("*.ready")))
        (root/"go").touch()
        results=[]
        for child in children:
            stdout,stderr=child.communicate(timeout=30)
            results.append({"exit_code":child.returncode,"stdout":stdout.strip(),"stderr":stderr.strip()})
        return {"ready":ready,"workers":workers,"successful":sum(r["exit_code"]==0 for r in results),"children":results}

if __name__=="__main__":
    results={}
    for tree in sys.argv[1:]: results[tree]=probe(Path(tree).resolve())
    print(json.dumps(results,indent=2))
