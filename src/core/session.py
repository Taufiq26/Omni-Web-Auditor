import requests
from requests.exceptions import RequestException
from typing import Optional

class ScannerSession:
    def __init__(self, cookie: str = None, bearer_token: str = None):
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
        
    def get_request(self, url: str, **kwargs) -> Optional[requests.Response]:
        try:
            response = self.session.get(url, timeout=self.timeout, **kwargs)
            return response
        except RequestException as e:
            print(f"[!] GET request failed for {url}: {e}")
            return None
            
    def post_request(self, url: str, data: dict = None, json: dict = None, **kwargs) -> Optional[requests.Response]:
        try:
            response = self.session.post(url, data=data, json=json, timeout=self.timeout, **kwargs)
            return response
        except RequestException as e:
            print(f"[!] POST request failed for {url}: {e}")
            return None

    def request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """Request generik untuk method apa pun (GET/POST/PUT/PATCH/DELETE).

        Dipakai oleh pengujian injeksi berbasis endpoint (lihat endpoints-file).
        Tetap melewati satu jalur error-handling yang sama seperti get/post.
        """
        try:
            response = self.session.request(
                method.upper(), url, timeout=self.timeout, **kwargs
            )
            return response
        except RequestException as e:
            print(f"[!] {method.upper()} request failed for {url}: {e}")
            return None
