import requests
from requests.exceptions import RequestException
from typing import Optional
from src.core.scope import Scope
from src.core.logging_setup import get_logger

logger = get_logger(__name__)


class ScannerSession:
    def __init__(self, cookie: str = None, bearer_token: str = None, scope: Optional[Scope] = None):
        self.session = requests.Session()

        # Set default headers
        self.session.headers.update({
            "User-Agent": "Omni-Auditor/1.0"
        })

        if cookie:
            self.session.headers.update({"Cookie": cookie})

        if bearer_token:
            self.session.headers.update({"Authorization": f"Bearer {bearer_token}"})

        self.timeout = 10
        # Bila scope diberikan, setiap request divalidasi terhadapnya (ScopeError
        # bila di luar scope). Tanpa scope -> tidak ada penegakan (backward compatible).
        self.scope = scope

    def _enforce_scope(self, url: str) -> None:
        if self.scope is not None:
            # Lempar ScopeError bila di luar scope (fail-loud, dicatat di pemanggil).
            self.scope.require(url)

    def get_request(self, url: str, **kwargs) -> Optional[requests.Response]:
        self._enforce_scope(url)
        try:
            response = self.session.get(url, timeout=self.timeout, **kwargs)
            return response
        except RequestException as e:
            logger.warning("GET request failed for %s: %s", url, e)
            return None

    def post_request(self, url: str, data: dict = None, json: dict = None, **kwargs) -> Optional[requests.Response]:
        self._enforce_scope(url)
        try:
            response = self.session.post(url, data=data, json=json, timeout=self.timeout, **kwargs)
            return response
        except RequestException as e:
            logger.warning("POST request failed for %s: %s", url, e)
            return None

    def request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """Request generik untuk method apa pun (GET/POST/PUT/PATCH/DELETE).

        Dipakai oleh pengujian injeksi berbasis endpoint (lihat endpoints-file).
        Tetap melewati satu jalur error-handling yang sama seperti get/post.
        """
        self._enforce_scope(url)
        try:
            response = self.session.request(
                method.upper(), url, timeout=self.timeout, **kwargs
            )
            return response
        except RequestException as e:
            logger.warning("%s request failed for %s: %s", method.upper(), url, e)
            return None
