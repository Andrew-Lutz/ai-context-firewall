"""
API Client for the AI Context Firewall Streamlit frontend.
Wraps all backend API calls with error handling and auth headers.
"""
from __future__ import annotations

from typing import Any, BinaryIO, Dict, List, Optional
import requests
import structlog

logger = structlog.get_logger(__name__)


class FirewallAPIClient:
    """
    HTTP client for the AI Context Firewall backend API.
    All methods return parsed JSON dicts or raise on error.
    """

    def __init__(self, base_url: str = "http://localhost:8000", token: Optional[str] = None):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.session = requests.Session()
        if token:
            self.session.headers.update({"Authorization": f"Bearer {token}"})
        self.session.headers.update({"Content-Type": "application/json"})

    def _url(self, path: str) -> str:
        return f"{self.base_url}/api/v1{path}"

    def _handle(self, response: requests.Response) -> Dict:
        """Handle response, raising on HTTP errors."""
        try:
            response.raise_for_status()
            return response.json()
        except requests.HTTPError as e:
            logger.error("api_error", status=response.status_code, url=response.url)
            try:
                detail = response.json().get("detail", str(e))
            except Exception:
                detail = str(e)
            raise APIError(response.status_code, detail)
        except Exception as e:
            raise APIError(0, str(e))

    # --- Auth ---

    def login(self, email: str, password: str) -> Dict:
        """Authenticate and get JWT tokens."""
        resp = self.session.post(
            f"{self.base_url}/api/v1/auth/login/json",
            json={"email": email, "password": password},
            headers={"Content-Type": "application/json"},
        )
        result = self._handle(resp)
        if result.get("access_token"):
            self.token = result["access_token"]
            self.session.headers.update({"Authorization": f"Bearer {self.token}"})
        return result

    def get_current_user(self) -> Dict:
        return self._handle(self.session.get(self._url("/auth/me")))

    # --- Scanning ---

    def scan_prompt(
        self,
        text: str,
        content_type: str = "prompt",
        apply_redaction: bool = True,
        user_role: Optional[str] = None,
        model_name: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> Dict:
        """Scan a text prompt through the full inspection pipeline."""
        payload = {
            "text": text,
            "content_type": content_type,
            "apply_redaction": apply_redaction,
            "user_role": user_role,
            "model_name": model_name,
            "tenant_id": tenant_id,
        }
        resp = self.session.post(self._url("/scan/prompt"), json=payload)
        return self._handle(resp)

    def scan_file(
        self,
        file_bytes: bytes,
        filename: str,
        tenant_id: Optional[str] = None,
    ) -> Dict:
        """Scan an uploaded file."""
        resp = self.session.post(
            self._url("/scan/file"),
            files={"file": (filename, file_bytes)},
            data={"tenant_id": tenant_id or "default"},
            headers={},  # Remove Content-Type so requests sets multipart boundary
        )
        # Temporarily remove JSON content-type for file upload
        headers_backup = self.session.headers.copy()
        if "Content-Type" in self.session.headers:
            del self.session.headers["Content-Type"]
        resp = self.session.post(
            self._url("/scan/file"),
            files={"file": (filename, file_bytes)},
            data={"tenant_id": tenant_id or "default"},
        )
        self.session.headers.update(headers_backup)
        return self._handle(resp)

    # --- Policies ---

    def list_policies(self) -> List[Dict]:
        resp = self.session.get(self._url("/policies/"))
        return self._handle(resp)

    # --- Audit ---

    def get_audit_events(
        self,
        limit: int = 100,
        offset: int = 0,
        event_type: Optional[str] = None,
    ) -> Dict:
        params = {"limit": limit, "offset": offset}
        if event_type:
            params["event_type"] = event_type
        resp = self.session.get(self._url("/audit/"), params=params)
        return self._handle(resp)

    # --- Health ---

    def health_check(self) -> Dict:
        try:
            resp = requests.get(f"{self.base_url}/health", timeout=3)
            return resp.json()
        except Exception as e:
            return {"status": "unreachable", "error": str(e)}


class APIError(Exception):
    """Raised when the API returns an error response."""
    def __init__(self, status_code: int, detail: str):
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"API Error {status_code}: {detail}")
