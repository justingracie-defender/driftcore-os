# SPDX-License-Identifier: Apache-2.0
"""Standalone, standard-library-only client for an isolated operational agent.

Deploy this file and the published tool contract to the agent, not the broker
package. This client transports opaque grants issued elsewhere; it contains no
issuer, verifier, policy loader or actuator. Filesystem/OS separation is still a
deployment responsibility. A transport failure means completion may be unknown.
"""
import json
import math
import socket
import struct

MAX_FRAME_BYTES = 4_000_000


class ActionRefused(Exception):
    def __init__(self, response):
        self.response = response
        self.effect_status = response.get("effect_status", "UNKNOWN")
        super().__init__(response.get("detail", "Request refused; contact the operator."))


class OutcomeUnknown(Exception):
    """No reliable response; reconcile the effect before attempting a retry."""


def _receive_exactly(connection, size):
    chunks = bytearray()
    while len(chunks) < size:
        part = connection.recv(size - len(chunks))
        if not part:
            raise OutcomeUnknown("Incomplete broker response. Do not retry automatically.")
        chunks.extend(part)
    return bytes(chunks)


class DriftCoreClient:
    def __init__(self, socket_path, actuator_id, *, timeout=5.0):
        if type(socket_path) is not str or not socket_path:
            raise ValueError("socket_path must be a nonempty string")
        if type(actuator_id) is not str or not actuator_id:
            raise ValueError("actuator_id must be a nonempty string")
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be a positive finite number")
        self._socket_path = socket_path
        self.actuator_id = actuator_id
        self.timeout = timeout

    def execute(self, command, grant, *, params=None, attestation=None):
        """Submit once; return the public response, including completion information.

        Grants/attestations are JSON dictionaries supplied by a trusted issuer.
        This API does not decide whether they confer authority. The broker does.
        """
        if type(command) is not str or not command:
            raise ValueError("command must be a nonempty string")
        if type(grant) is not dict or (params is not None and type(params) is not dict):
            raise ValueError("grant and params must be JSON objects")
        request = {"op": "execute", "actuator_id": self.actuator_id, "command": command,
                   "grant": grant, "params": params if params is not None else {}}
        if attestation is not None:
            if type(attestation) is not dict:
                raise ValueError("attestation must be a JSON object")
            request["attestation"] = attestation
        body = json.dumps(request, separators=(",", ":"), allow_nan=False).encode("utf-8")
        if len(body) > MAX_FRAME_BYTES:
            raise ValueError("request exceeds the broker frame limit")
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(self.timeout)
                connection.connect(self._socket_path)
                connection.sendall(struct.pack("!I", len(body)) + body)
                length = struct.unpack("!I", _receive_exactly(connection, 4))[0]
                if length > MAX_FRAME_BYTES:
                    raise OutcomeUnknown("Oversized broker response. Do not retry automatically.")
                response = json.loads(_receive_exactly(connection, length).decode("utf-8"))
                # Covers literal NaN/Infinity and overflow such as 1e999.
                json.dumps(response, allow_nan=False)
        except (OSError, ValueError, TypeError, RecursionError) as error:
            raise OutcomeUnknown("Broker response unavailable. Do not retry automatically.") from error
        if type(response) is not dict or type(response.get("ok")) is not bool:
            raise OutcomeUnknown("Invalid broker response. Do not retry automatically.")
        if not response["ok"]:
            raise ActionRefused(response)
        return response
