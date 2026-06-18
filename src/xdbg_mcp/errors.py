from __future__ import annotations


class BridgeError(RuntimeError):
    def __init__(self, code: str, message: str, *, retriable: bool = False, details: object | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.retriable = retriable
        self.details = details

    def to_dict(self) -> dict[str, object]:
        data: dict[str, object] = {
            "code": self.code,
            "message": self.message,
            "retriable": self.retriable,
        }
        if self.details is not None:
            data["details"] = self.details
        return data
