class AlfaBankSBPClientError(Exception):
    """Исключение для ошибок клиента API СБП Альфа-Банка."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"API error {code}: {message}")