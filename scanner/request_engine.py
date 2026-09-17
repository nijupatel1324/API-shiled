import requests
import time
import logging
from urllib.parse import urlparse

logger = logging.getLogger('api-shield.request_engine')

class SafeRequestEngine:
    def __init__(self, allowed_hosts, timeout=10, max_redirects=3, max_size=5*1024*1024):
        """
        Initializes the Safe Request Engine.
        :param allowed_hosts: List of domains/IPs we are authorized to scan.
        :param timeout: Maximum seconds to wait for a response.
        :param max_redirects: Maximum HTTP redirects to follow.
        :param max_size: Maximum response body size to download (in bytes) to prevent DoS.
        """
        self.allowed_hosts = allowed_hosts
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.max_size = max_size
        self.session = requests.Session()
        
        # Configure the session
        self.session.max_redirects = self.max_redirects
        
        # Rate Limiting configuration
        self.last_request_time = 0
        self.min_delay_between_requests = 0.5 # Wait at least 0.5s between requests

    def _is_allowed(self, url):
        """Scope restriction: Ensure the target URL is in the allowlist."""
        parsed = urlparse(url)
        host = parsed.hostname
        if not host:
            return False
        
        # Exact match or subdomain match (simplified for this project)
        for allowed in self.allowed_hosts:
            if host == allowed or host.endswith('.' + allowed):
                return True
        return False

    def _enforce_rate_limit(self):
        """Ensure we don't bombard the target with unlimited requests."""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.min_delay_between_requests:
            time.sleep(self.min_delay_between_requests - elapsed)
        self.last_request_time = time.time()

    def send_request(self, method, url, headers=None, params=None, json_data=None):
        """
        Sends a safe, controlled HTTP request.
        """
        if not self._is_allowed(url):
            logger.warning(f"Target Out of Scope: {url}")
            return {"error": "Target not in allowlist (Out of Scope)", "status_code": 0}

        self._enforce_rate_limit()

        method = method.upper()
        if method not in ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD']:
            return {"error": f"Unsupported HTTP method: {method}", "status_code": 0}

        logger.debug(f"Sending {method} request to {url}")
        
        try:
            # We use stream=True so we can check the response size before fully downloading it
            response = self.session.request(
                method=method,
                url=url,
                headers=headers,
                params=params,
                json=json_data,
                timeout=self.timeout,
                allow_redirects=True,
                stream=True 
            )

            # Response Size Limiting
            content_length = response.headers.get('Content-Length')
            if content_length and int(content_length) > self.max_size:
                response.close() # Cancel the download
                logger.warning(f"Response too large from {url}. Terminating connection.")
                return {"error": "Response size exceeded limit", "status_code": response.status_code}

            # If no Content-Length is provided, we read it in chunks to enforce the size limit
            content = b""
            for chunk in response.iter_content(chunk_size=8192):
                content += chunk
                if len(content) > self.max_size:
                    response.close()
                    logger.warning(f"Response chunking too large from {url}. Terminating connection.")
                    return {"error": "Response size exceeded limit during stream", "status_code": response.status_code}

            return {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "text": content.decode('utf-8', errors='replace'), # Use replace to handle binary/weird chars safely
                "elapsed": response.elapsed.total_seconds(),
                "url": response.url
            }

        except requests.exceptions.Timeout:
            logger.error(f"Request timeout for {url}")
            return {"error": "Request timed out", "status_code": 0}
        except requests.exceptions.TooManyRedirects:
            logger.error(f"Too many redirects for {url}")
            return {"error": "Too many redirects", "status_code": 0}
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed for {url}: {str(e)}")
            return {"error": f"Request failed: {str(e)}", "status_code": 0}
