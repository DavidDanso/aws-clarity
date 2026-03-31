class InvalidRoleARNError(Exception):
    def __init__(self, message: str):
        super().__init__(message)

class AssumeRoleError(Exception):
    def __init__(self, message: str):
        super().__init__(message)

class PermissionDeniedError(Exception):
    def __init__(self, message: str):
        super().__init__(message)
