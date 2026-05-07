class IngestError(Exception):
    pass


class QuotaExceeded(IngestError):
    pass


class UnreadableFile(IngestError):
    pass


class PathTraversalAttempt(IngestError):
    pass
