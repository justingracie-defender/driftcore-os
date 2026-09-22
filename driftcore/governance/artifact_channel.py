# SPDX-License-Identifier: Apache-2.0
"""CLAIM artifacts-do-not-confer-authority: stored, signed, published and retrieved
artifacts retain UNVERIFIED claim status and NONE authority in this channel.

CLAIM lineage-follows-exposure: captures include every artifact delivered through
the bound session, including after restart; callers cannot choose their parents.

CLAIM publication-binds-the-artifact: publication uses the immutable stored packet
identified by the approved ID and matches its destination, audience and purpose.

CLAIM uncertain-publication-stays-pending: a write-ahead publication reservation
blocks another send of that artifact to that route after an uncertain result.

HONEST LIMITS
This is a trusted broker-side service, not protection from hostile Python in the
same process. All model inputs and outputs must traverse the bound host session.
Lineage records possible influence, not semantic dependence or independent truth.
The database, session bootstrap and HMAC key need OS protection. HMAC authenticates
this deployment's provenance, not a human approval or an independent fact check.
Public-only publishing; private audiences and declassification are out of scope.
Transport adapters and their actual network paths remain part of the trusted base.
"""
from contextlib import contextmanager
import hashlib
import hmac
import json
from pathlib import Path
import re
import sqlite3
import threading
import time
import uuid

from driftcore.governance.information_flow import Label, Level, PUBLIC
from driftcore.kernel.egress_guard import normalize_destination
from driftcore.verification.invariant_guard import Effect

MAX_BODY_BYTES = 262144
MAX_PACKET_BYTES = 1048576
MAX_SOURCES = 128
MAX_ARTIFACTS = 10000
SCHEMA = "driftcore-artifact-v1"
_DOMAIN = b"driftcore-artifact-provenance-v1\x00"


class ArtifactRefused(ValueError):
    pass


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False)


def _sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _text(value, name, limit=512):
    if type(value) is not str or not value or len(value.encode("utf-8")) > limit:
        raise ArtifactRefused(f"invalid {name}")
    return value


def _digest(value):
    if type(value) is not str or re.fullmatch("[0-9a-f]{64}", value) is None:
        raise ArtifactRefused("invalid artifact digest")
    return value


def _label(value):
    if type(value) is not Label or type(value.level) is not Level or type(value.compartments) is not frozenset:
        raise ArtifactRefused("a trusted sensitivity label is required")
    for name in value.compartments:
        _text(name, "compartment", 128)
    if len(value.compartments) > MAX_SOURCES:
        raise ArtifactRefused("too many compartments")
    return [value.level.name, sorted(value.compartments)]


def _unlabel(value):
    if type(value) is not list or len(value) != 2 or type(value[1]) is not list:
        raise ArtifactRefused("invalid sensitivity record")
    try:
        result = Label(Level[value[0]], frozenset(value[1]))
        if _label(result) != value:
            raise ArtifactRefused("noncanonical sensitivity record")
        return result
    except (KeyError, TypeError) as error:
        raise ArtifactRefused("invalid sensitivity record") from error


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ArtifactRefused("duplicate JSON field")
        result[key] = value
    return result


class ArtifactStore:
    def __init__(self, path, *, provenance_key, issuer):
        if type(provenance_key) is not bytes or len(provenance_key) < 32:
            raise ArtifactRefused("a separate operator-held provenance key of at least 32 bytes is required")
        self._key = provenance_key
        self.issuer = _text(issuer, "issuer")
        self._lock = threading.RLock()
        path = Path(path)
        if str(path) == ":memory:":
            raise ArtifactRefused("artifact state must have a persistent path")
        self._db = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
        self._db.execute("PRAGMA foreign_keys=ON")
        self._db.execute("PRAGMA synchronous=FULL")
        with self._transaction() as db:
            db.execute("CREATE TABLE IF NOT EXISTS metadata (id INTEGER PRIMARY KEY, identity TEXT NOT NULL)")
            identity = hmac.new(self._key, _DOMAIN + self.issuer.encode(), hashlib.sha256).hexdigest()
            row = db.execute("SELECT identity FROM metadata WHERE id=1").fetchone()
            if row is None:
                db.execute("INSERT INTO metadata VALUES (1,?)", (identity,))
            elif not hmac.compare_digest(row[0], identity):
                raise ArtifactRefused("store belongs to another provenance key or issuer")
            db.execute("CREATE TABLE IF NOT EXISTS artifacts (id TEXT PRIMARY KEY, packet TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, subject TEXT NOT NULL, creator TEXT NOT NULL, initial_label TEXT NOT NULL, current_label TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS seen (session TEXT REFERENCES sessions(id), artifact TEXT REFERENCES artifacts(id), PRIMARY KEY(session,artifact))")
            db.execute("CREATE TABLE IF NOT EXISTS publications (id TEXT PRIMARY KEY, state TEXT NOT NULL, receipt TEXT)")

    @contextmanager
    def _transaction(self):
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                yield self._db
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
            else:
                self._db.execute("COMMIT")

    def close(self):
        with self._lock:
            self._db.close()

    def open_session(self, context_id, *, subject, creator, initial_label):
        # Trusted host bootstrap only. Reopening preserves exposure and sensitivity.
        values = (_text(context_id, "context id"), _text(subject, "subject"),
                  _text(creator, "creator"), _json(_label(initial_label)))
        with self._transaction() as db:
            row = db.execute("SELECT subject,creator,initial_label FROM sessions WHERE id=?", (context_id,)).fetchone()
            if row is None:
                db.execute("INSERT INTO sessions VALUES (?,?,?,?,?)", (*values, values[-1]))
            elif row != values[1:]:
                raise ArtifactRefused("session identity or initial label cannot be replaced")
        return context_id

    def _session(self, db, session):
        row = db.execute("SELECT subject,creator,current_label FROM sessions WHERE id=?", (session,)).fetchone()
        if row is None:
            raise ArtifactRefused("unknown host session")
        return row[0], row[1], _unlabel(json.loads(row[2]))

    def observe_label(self, session, label):
        # Host must call this for non-artifact inputs too. No downgrade/reset API.
        _label(label)
        with self._transaction() as db:
            _, _, current = self._session(db, session)
            db.execute("UPDATE sessions SET current_label=? WHERE id=?", (_json(_label(current.join(label))), session))

    def _decode(self, packet):
        _text(packet, "packet", MAX_PACKET_BYTES)
        obj = json.loads(packet, object_pairs_hook=_unique_object)
        if type(obj) is not dict or set(obj) != {"artifact_id", "manifest", "provenance_sig"}:
            raise ArtifactRefused("not a provenance packet")
        manifest = obj["manifest"]
        if type(manifest) is not dict or manifest.get("schema") != SCHEMA:
            raise ArtifactRefused("unknown provenance schema")
        encoded = _json(manifest)
        signature = hmac.new(self._key, _DOMAIN + encoded.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(_digest(obj["provenance_sig"]), signature):
            raise ArtifactRefused("provenance signature rejected")
        if _digest(obj["artifact_id"]) != _sha(encoded) or manifest["issuer"] != self.issuer:
            raise ArtifactRefused("artifact identity mismatch")
        if manifest["claim_status"] != "UNVERIFIED" or manifest["authority"] != "NONE":
            raise ArtifactRefused("provenance is not permission or truth verification")
        if manifest["body_sha256"] != _sha(_text(manifest["body"], "body", MAX_BODY_BYTES)):
            raise ArtifactRefused("artifact body mismatch")
        _unlabel(manifest["sensitivity"])
        for name in ("parents", "roots"):
            values = manifest[name]
            if type(values) is not list or len(values) > MAX_SOURCES or values != sorted(set(values)):
                raise ArtifactRefused("invalid lineage")
            for item in values:
                _digest(item)
        if not manifest["roots"]:
            raise ArtifactRefused("missing origin")
        # One exact serialization is published, hashed and imported.
        if packet != _json(obj):
            raise ArtifactRefused("noncanonical artifact packet")
        return obj

    def _get(self, db, artifact_id):
        row = db.execute("SELECT packet FROM artifacts WHERE id=?", (_digest(artifact_id),)).fetchone()
        if row is None:
            raise ArtifactRefused("unknown artifact")
        obj = self._decode(row[0])
        if obj["artifact_id"] != artifact_id:
            raise ArtifactRefused("stored artifact identity changed")
        return obj, row[0]

    def _put(self, db, obj):
        packet = _json(obj)
        _text(packet, "packet", MAX_PACKET_BYTES)
        old = db.execute("SELECT packet FROM artifacts WHERE id=?", (obj["artifact_id"],)).fetchone()
        if old is not None:
            if old[0] != packet:
                raise ArtifactRefused("immutable artifact collision")
        else:
            if db.execute("SELECT 1 FROM artifacts LIMIT 1 OFFSET ?", (MAX_ARTIFACTS - 1,)).fetchone() is not None:
                raise ArtifactRefused("artifact capacity reached")
            db.execute("INSERT INTO artifacts VALUES (?,?)", (obj["artifact_id"], packet))

    def _new(self, body, *, creator, context, parents, roots, sensitivity, origin, release):
        manifest = dict(schema=SCHEMA, issuer=self.issuer, creator=creator,
            context_id=context, created_ns=time.time_ns(), origin=origin,
            body=_text(body, "body", MAX_BODY_BYTES), body_sha256=_sha(body),
            parents=sorted(parents), roots=sorted(roots), sensitivity=_label(sensitivity),
            release=release, claim_status="UNVERIFIED", authority="NONE")
        if len(manifest["roots"]) > MAX_SOURCES or len(manifest["parents"]) > MAX_SOURCES:
            raise ArtifactRefused("lineage capacity reached; no silent truncation")
        encoded = _json(manifest)
        return dict(artifact_id=_sha(encoded), manifest=manifest,
                    provenance_sig=hmac.new(self._key, _DOMAIN + encoded.encode(), hashlib.sha256).hexdigest())

    def capture(self, session, text, *, release):
        # Called by the trusted model host with the actual output of this session.
        # The model supplies text, never creator, roots, labels or verification status.
        with self._transaction() as db:
            _, creator, label = self._session(db, session)
            parents = {r[0] for r in db.execute("SELECT artifact FROM seen WHERE session=?", (session,))}
            roots = set()
            for parent in parents:
                obj, _ = self._get(db, parent)
                roots.update(obj["manifest"]["roots"])
                label = label.join(_unlabel(obj["manifest"]["sensitivity"]))
            if not roots:
                roots.add(_sha(self.issuer + ":" + uuid.uuid4().hex))
            obj = self._new(text, creator=creator, context=session, parents=parents,
                            roots=roots, sensitivity=label, origin="model-output", release=release)
            self._put(db, obj)
            self._expose(db, session, obj)
        return obj["artifact_id"]

    def _expose(self, db, session, obj):
        _, _, label = self._session(db, session)
        already = db.execute("SELECT 1 FROM seen WHERE session=? AND artifact=?", (session, obj["artifact_id"])).fetchone()
        if already is None and db.execute("SELECT 1 FROM seen WHERE session=? LIMIT 1 OFFSET ?", (session, MAX_SOURCES - 1)).fetchone() is not None:
            raise ArtifactRefused("session exposure capacity reached")
        db.execute("INSERT OR IGNORE INTO seen VALUES (?,?)", (session, obj["artifact_id"]))
        joined = label.join(_unlabel(obj["manifest"]["sensitivity"]))
        db.execute("UPDATE sessions SET current_label=? WHERE id=?", (_json(_label(joined)), session))

    def receive(self, session, text, *, source):
        _text(source, "source")
        _text(text, "retrieved data", MAX_PACKET_BYTES)
        try:
            obj = self._decode(text)
            provenance = "AUTHENTICATED_LOCAL_ORIGIN"
        except (ArtifactRefused, ValueError, KeyError, TypeError, RecursionError):
            # Claims inside a foreign/stripped/forged packet are plain content.
            obj = self._new(text, creator="unknown-external", context="external",
                parents=set(), roots={_sha("external-content:" + text)}, sensitivity=PUBLIC,
                origin=source, release=None)
            provenance = "UNVERIFIED_EXTERNAL"
        with self._transaction() as db:
            self._put(db, obj)
            self._expose(db, session, obj)  # Commit exposure BEFORE handing back content.
        return dict(artifact_id=obj["artifact_id"], content=obj["manifest"]["body"],
            provenance=provenance, roots=obj["manifest"]["roots"], source=source,
            claim_status="UNVERIFIED", authority="NONE")

    def review(self, artifact_id):
        # Operator-only: this includes the exact packet bytes whose hash is approved.
        with self._transaction() as db:
            obj, packet = self._get(db, artifact_id)
        return dict(artifact=obj, packet=packet, packet_sha256=_sha(packet))

    def publication_state(self, publication_id):
        with self._transaction() as db:
            row = db.execute("SELECT state FROM publications WHERE id=?", (publication_id,)).fetchone()
        return row[0] if row else None


class ArtifactChannel:
    def __init__(self, store, session, *, publishers, readers):
        if type(store) is not ArtifactStore:
            raise ArtifactRefused("a protected artifact store is required")
        self._store, self._session = store, _text(session, "session")
        self._publishers, self._readers = dict(publishers), dict(readers)
        for routes, size in ((self._publishers, 3), (self._readers, 2)):
            if not routes:
                raise ArtifactRefused("explicit nonempty routes are required")
            for route, fn in routes.items():
                if type(route) is not tuple or len(route) != size or not callable(fn):
                    raise ArtifactRefused("invalid artifact route")
                for item in route:
                    _text(item, "route")
                if normalize_destination(route[0])[0] != "https" or route[1] != "PUBLIC":
                    raise ArtifactRefused("this channel supports explicit HTTPS public routes only")

    def capture(self, text, *, destination, audience, purpose):
        route = (destination, audience, purpose)
        if route not in self._publishers:
            raise ArtifactRefused("publication route is not configured")
        return self._store.capture(self._session, text,
            release=dict(destination=destination, audience=audience, purpose=purpose))

    def publish(self, *, artifact_id, destination, audience, purpose, packet_sha256):
        route = (destination, audience, purpose)
        if route not in self._publishers:
            raise ArtifactRefused("publication route is not configured")
        store = self._store
        params = dict(artifact_id=artifact_id, destination=destination, audience=audience,
                      purpose=purpose, packet_sha256=_digest(packet_sha256))
        publication_id = _sha(_json(params))
        with store._transaction() as db:
            _, _, label = store._session(db, self._session)
            obj, packet = store._get(db, artifact_id)
            if db.execute("SELECT 1 FROM seen WHERE session=? AND artifact=?", (self._session, artifact_id)).fetchone() is None:
                raise ArtifactRefused("artifact was not delivered to this session")
            if not PUBLIC.dominates(label.join(_unlabel(obj["manifest"]["sensitivity"]))):
                raise ArtifactRefused("session or artifact is not cleared for public release")
            if obj["manifest"]["release"] != dict(destination=destination, audience=audience, purpose=purpose):
                raise ArtifactRefused("publication differs from the artifact's declared release")
            if _sha(packet) != packet_sha256:
                raise ArtifactRefused("approved publication bytes changed")
            if db.execute("SELECT 1 FROM publications WHERE id=?", (publication_id,)).fetchone():
                raise ArtifactRefused("publication already attempted; operator reconciliation required")
            db.execute("INSERT INTO publications VALUES (?, 'PENDING', NULL)", (publication_id,))
        # Real external effect; credentials and network live only in this adapter.
        receipt = self._publishers[route](packet)
        if type(receipt) is not dict or any(receipt.get(k) != v for k, v in (
                ("packet_sha256", packet_sha256), ("destination", destination), ("audience", audience))):
            raise ArtifactRefused("publication outcome is unconfirmed")
        reference = _text(receipt.get("reference"), "publication reference")
        with store._transaction() as db:
            db.execute("UPDATE publications SET state='COMMITTED', receipt=? WHERE id=?",
                       (_json(dict(reference=reference, packet_sha256=packet_sha256)), publication_id))
        return dict(executed_args=params, artifact_id=artifact_id, reference=reference,
                    publication_id=publication_id, publication_status="COMMITTED",
                    claim_status="UNVERIFIED", authority="NONE")

    def read(self, *, destination, audience, reference):
        route = (destination, audience)
        if route not in self._readers:
            raise ArtifactRefused("read route is not configured")
        _text(reference, "reference")
        text = self._readers[route](reference)
        view = self._store.receive(self._session, text, source=destination)
        return dict(executed_args=dict(destination=destination, audience=audience, reference=reference), **view)

    def install(self, broker, *, prefix):
        from driftcore.verification.human_authorization import HumanApprovalGate
        from driftcore.verification.mediated_actuation import ActuationBroker
        _text(prefix, "actuator prefix", 128)
        if not isinstance(broker, ActuationBroker):
            raise ArtifactRefused("an actuation broker is required")
        with self._store._transaction() as db:
            subject, _, _ = self._store._session(db, self._session)
        if (type(broker._human_approval) is not HumanApprovalGate or not broker._enforce_effects
                or not broker.is_effect_bound() or broker.policy_hash is None
                or not broker._broker_id or broker._expected_subject != subject):
            raise ArtifactRefused("artifact routes require human approval, effect binding, policy and a subject-bound broker")
        destinations = {r[0] for r in self._publishers} | {r[0] for r in self._readers}
        if broker._egress_guard is None or any(not broker._egress_guard.check(d).permitted for d in destinations):
            raise ArtifactRefused("artifact routes require the broker's egress allowlist")
        # Trusted bootstrap, before serving. Reserve the pair atomically against
        # duplicate registration; no agent-facing registration or policy setter.
        with broker._lock:
            if broker._thread is not None or any(prefix + "." + op in broker._actuators for op in ("publish", "read")):
                raise ArtifactRefused("install artifact routes once, before serving")
            for op, fn in (("publish", self.publish), ("read", self.read)):
                broker.register_actuator(prefix + "." + op, fn,
                    required_scope=("artifact:" + op,), effects=[Effect.DATA_EGRESS],
                    effect_declared_by="artifact-channel-bootstrap", destination_param="destination",
                    physical_resource="artifact-channel:" + prefix)
