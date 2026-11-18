"""Client error types. Messages are shown to the user as-is, so they must be
plain and must never contain secrets."""


class ClientError(Exception):
    """Any problem the CLI should report as a one-line error."""


class ApiError(ClientError):
    """The server answered with an error status.

    A 4xx answer is "definitive": the server understood and refused, so
    nothing was stored and it is safe to clean up local state.
    """

    def __init__(self, status: int, message: str, reason: str | None = None):
        super().__init__(message)
        self.status = status
        self.reason = reason  # machine-readable reject reason, when the server gives one

    @property
    def definitive(self) -> bool:
        return self.status >= 400 and self.status < 500


class NetworkError(ClientError):
    """No answer from the server: we do NOT know whether the request was applied."""
