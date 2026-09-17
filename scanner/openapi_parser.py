import yaml
import json

class OpenAPIParser:
    def __init__(self, spec_string):
        self.spec_string = spec_string
        self.spec = self._parse_string()

    def _parse_string(self):
        try:
            return json.loads(self.spec_string)
        except json.JSONDecodeError:
            try:
                return yaml.safe_load(self.spec_string)
            except yaml.YAMLError:
                raise ValueError("Specification must be valid JSON or YAML.")

    def parse(self):
        if not self.spec:
            raise ValueError("Empty or invalid specification.")

        info = self.spec.get('info', {})
        servers = self.spec.get('servers', [])
        paths = self.spec.get('paths', {})
        components = self.spec.get('components', {})

        endpoints = []
        for path, path_obj in paths.items():
            for method, operation in path_obj.items():
                if method.lower() not in ['get', 'post', 'put', 'delete', 'patch', 'options', 'head']:
                    continue
                
                # Determine authentication requirements for this specific endpoint
                auth_required = False
                security = operation.get('security', self.spec.get('security', []))
                if security:
                    auth_required = True

                endpoints.append({
                    "path": path,
                    "method": method.upper(),
                    "summary": operation.get('summary', ''),
                    "auth_required": auth_required,
                    "parameters": len(operation.get('parameters', [])),
                    "has_body": 'requestBody' in operation
                })

        return {
            "title": info.get('title', 'Unknown API'),
            "version": info.get('version', 'Unknown'),
            "servers": [s.get('url') for s in servers],
            "endpoints": endpoints
        }
