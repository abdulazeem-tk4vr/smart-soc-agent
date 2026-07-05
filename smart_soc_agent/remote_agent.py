from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import requests


class RemoteAgentError(RuntimeError):
    pass


@dataclass
class RemoteSmartSocAgent:
    base_url: str
    timeout: float = 120.0
    token: str = ""
    session: requests.Session = field(default_factory=requests.Session)

    @property
    def name(self) -> str:
        return "RemoteSmartSocAgent"

    def reset(self, change_seed: bool = True) -> None:
        self._post("/reset", {"change_seed": bool(change_seed)})

    def act(self, observation: str) -> tuple[str, bool]:
        payload = self._post("/act", {"observation": str(observation)})
        action = str(payload.get("action") or "")
        submit = bool(payload.get("submit"))
        if not action:
            raise RemoteAgentError("remote agent returned an empty action")
        return action, submit

    def get_logging(self) -> dict[str, Any]:
        response = self.session.get(self._url("/logging"), headers=self._headers(), timeout=self.timeout)
        return self._decode_response(response)

    def health(self) -> dict[str, Any]:
        response = self.session.get(self._url("/health"), headers=self._headers(), timeout=self.timeout)
        return self._decode_response(response)

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        response = self.session.post(self._url(path), json=payload, headers=self._headers(), timeout=self.timeout)
        return self._decode_response(response)

    def _decode_response(self, response: requests.Response) -> dict[str, Any]:
        try:
            data = response.json()
        except ValueError as exc:
            raise RemoteAgentError(f"remote agent returned non-JSON response: HTTP {response.status_code}") from exc
        if response.status_code >= 400:
            message = data.get("error") if isinstance(data, dict) else None
            raise RemoteAgentError(f"remote agent error HTTP {response.status_code}: {message or data}")
        if not isinstance(data, dict):
            raise RemoteAgentError("remote agent response must be a JSON object")
        return data

    def _url(self, path: str) -> str:
        return f"{self.base_url.rstrip('/')}/{path.lstrip('/')}"

    def _headers(self) -> dict[str, str]:
        if not self.token:
            return {}
        return {"Authorization": f"Bearer {self.token}"}
