class InvalidRoleARNError(Exception):
    def __init__(self, message: str):
        super().__init__(message)

class AssumeRoleError(Exception):
    def __init__(self, message: str):
        super().__init__(message)

class PermissionDeniedError(Exception):
    def __init__(self, message: str):
        super().__init__(message)

class ScannerError(Exception):
    """Scanner API failure that preserves resources discovered before failure."""
    def __init__(self, message: str, resources=None):
        super().__init__(message)
        self.resources = resources or []
