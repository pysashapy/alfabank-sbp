import base64
import json
import logging
import time
from typing import Dict, Optional, Any

import requests
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

from alfabank_sbp.exceptions import AlfaBankSBPClientError

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class AlfaBankSBPClient:
    """Клиент для взаимодействия с API СБП Альфа-Банка.

    Реализует методы для работы с динамическими QR-кодами: генерация, проверка статуса,
    возврат средств, получение истории возвратов и обработка уведомлений.
    Поддерживает MTLS-аутентификацию и подпись запросов SHA256.

    Attributes:
        base_url (str): Базовый URL API.
        term_no (str): Уникальный идентификатор терминала.
        cert_alias (str): Alias сертификата для подписи.
        session (requests.Session): Сессия для HTTP-запросов с MTLS.
        signing_key_path (str): Путь к приватному ключу для подписи.
    """

    def __init__(
            self,
            base_url: str,
            term_no: str,
            cert_path: str,
            key_path: str,
            ca_path: str,
            signing_cert_path: str,
            signing_key_path: str,
            cert_alias: str
    ) -> None:
        """Инициализация клиента.

        Args:
            base_url: Базовый URL API (например, 'https://217.12.103.132:2443/fsCryptoProxy').
            term_no: Уникальный идентификатор терминала (20 символов).
            cert_path: Путь к клиентскому сертификату для MTLS.
            key_path: Путь к приватному ключу для MTLS.
            ca_path: Путь к файлу CA (или объединённому CA bundle).
            signing_cert_path: Путь к сертификату для подписи.
            signing_key_path: Путь к приватному ключу для подписи.
            cert_alias: Alias сертификата для заголовка 'key-name'.
        """
        self.base_url = base_url.rstrip('/')
        self.term_no = term_no
        self.cert_alias = cert_alias
        self.session = requests.Session()
        self.session.cert = (cert_path, key_path)
        self.session.verify = False
        self.signing_key_path = signing_key_path
        self._private_key = self._load_private_key()

    def _load_private_key(self) -> Any:
        """Загружает приватный ключ для подписи запросов."""
        with open(self.signing_key_path, "rb") as key_file:
            return serialization.load_pem_private_key(key_file.read(), password=None)

    def _sign_data(self, data: bytes) -> bytes:
        """Подписывает данные SHA256 с использованием приватного ключа."""
        return base64.b64encode(self._private_key.sign(data, padding.PKCS1v15(), hashes.SHA256()))

    def _build_request_data(self, command: str, optional_params: Dict[str, Any]) -> Dict[str, Any]:
        """Формирует тело запроса с обязательными и опциональными параметрами."""
        return {"command": command, "TermNo": self.term_no, **optional_params}

    def _send_request(self, data: Dict[str, Any], endpoint: str = "") -> Dict[str, Any]:
        """Отправляет POST-запрос с MTLS и подписью."""
        data = json.dumps(data, ensure_ascii=False).encode('utf-8')
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": self._sign_data(data),
            "key-name": self.cert_alias
        }
        logger.debug(f"Запрос: URL={self.base_url}/{endpoint}, Тело={data}, Заголовки={headers}")

        response = self.session.post(
            f"{self.base_url}/{endpoint}",
            headers=headers,
            data=data,
        )
        response.raise_for_status()
        result = response.json()
        if result.get("ErrorCode") != 0:
            raise AlfaBankSBPClientError(result.get("ErrorCode"), result.get("message", "Неизвестная ошибка"))
        return result

    def get_qr_code(
            self,
            amount: int,
            currency: str = "RUB",
            qrc_type: str = "02",
            payment_purpose: Optional[str] = None,
            qr_ttl: Optional[str] = None,
            notification_url: Optional[str] = None,
            redirect_url: Optional[str] = None,
            width: Optional[str] = None,
            height: Optional[str] = None,
            order_number: Optional[str] = None,
            message_id: Optional[str] = None,
            sender_fio: Optional[str] = None,
            sender_id: Optional[str] = None,
            sender_bank_bic: Optional[str] = None,
            subscription_service_id: Optional[str] = None,
            subscription_service_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """Генерирует динамический QR-код для оплаты (GetQRCd).

        Args:
            amount: Сумма платежа в копейках (например, 10000 = 100 рублей).
            currency: Код валюты (по умолчанию "RUB").
            qrc_type: Тип QR-кода (по умолчанию "02" для динамического).
            payment_purpose: Назначение платежа (до 140 символов).
            qr_ttl: Срок жизни ссылки в минутах (1–129600, по умолчанию 4320).
            notification_url: URL для уведомлений о статусе оплаты.
            redirect_url: URL для возврата в приложение (ASCII, percent-encoded).
            width: Ширина изображения QR-кода (число).
            height: Высота изображения QR-кода (число).
            order_number: Номер заказа (до 1000 символов, латинские буквы, цифры, '_', '-').
            message_id: Уникальный идентификатор сообщения (GUID, латинские символы).
            sender_fio: ФИО плательщика (до 140 символов, формат 'Фамилия|Имя|Отчество').
            sender_id: Номер телефона плательщика (например, '0079123456789').
            sender_bank_bic: БИК банка плательщика (9 цифр).
            subscription_service_id: Идентификатор привязки (32 символа, требуется с subscription_service_name).
            subscription_service_name: Наименование привязки (70 символов, требуется с subscription_service_id).
        """
        params = {
            "qrcType": qrc_type,
            "amount": str(amount),
            "currency": currency,
            "paymentPurpose": payment_purpose,
            "qrTtl": qr_ttl,
            "redirectUrl": redirect_url,
            "width": width,
            "height": height,
            "orderNumber": order_number,
            "messageID": message_id,
            "subscriptionServiceId": subscription_service_id,
            "subscriptionServiceName": subscription_service_name
        }
        if any([notification_url, sender_fio, sender_id, sender_bank_bic]):
            params["queryData"] = {
                "notificationUrl": notification_url,
                "SenderFIO": sender_fio,
                "SenderID": sender_id,
                "SenderBankBIC": sender_bank_bic
            }
        return self._send_request(self._build_request_data("GetQRCd", params))

    def get_qr_status(
            self,
            qrc_id: Optional[str] = None,
            payrrn: Optional[str] = None,
            message_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Проверяет статус оплаты QR-кода (GetQRCstatus).

        Args:
            qrc_id: Идентификатор QR-кода (32 символа, требуется, если не указан payrrn).
            payrrn: Референсный идентификатор запроса (12 цифр, требуется, если не указан qrc_id).
            message_id: Уникальный идентификатор сообщения (GUID, до 1024 символов).
        """
        if not (qrc_id or payrrn):
            raise AlfaBankSBPClientError("Требуется qrcId или payrrn")
        params = {"qrcId": qrc_id, "payrrn": payrrn, "messageID": message_id}
        return self._send_request(self._build_request_data("GetQRCstatus", params))

    def get_reversal_data(
            self,
            qrc_id: Optional[str] = None,
            payrrn: Optional[str] = None,
            trx_id: Optional[str] = None,
            trx_dt: Optional[str] = None,
            amount: Optional[int] = None,
            currency: Optional[str] = None,
            message_id: Optional[str] = None,
            return_rest_amount: Optional[bool] = None
    ) -> Dict[str, Any]:
        """Проверяет возможность возврата средств (GetQRCreversalData).

        Args:
            qrc_id: Идентификатор QR-кода (32 символа, требуется, если не указаны payrrn или trx_id).
            payrrn: Референсный идентификатор запроса (12 цифр, требуется, если не указаны qrc_id или trx_id).
            trx_id: Идентификатор платежа в НСПК (32 символа, требуется, если не указаны qrc_id или payrrn).
            trx_dt: Дата и время платежа (ГГГГММДДччммсс).
            amount: Сумма возврата в копейках (по умолчанию полная сумма минус возвраты).
            currency: Код валюты (по умолчанию "RUB").
            message_id: Уникальный идентификатор сообщения (GUID, до 1024 символов).
            return_rest_amount: Проверка остатка для возврата (True/False).
        """
        if not (qrc_id or payrrn or trx_id):
            raise AlfaBankSBPClientError("Требуется qrcId, payrrn или trxId")
        params = {
            "qrcId": qrc_id,
            "payrrn": payrrn,
            "trxId": trx_id,
            "trxDT": trx_dt,
            "amount": str(amount) if amount is not None else None,
            "currency": currency,
            "messageID": message_id,
            "ReturnRestAmount": str(return_rest_amount).lower() if return_rest_amount is not None else None
        }
        return self._send_request(self._build_request_data("GetQRCreversalData", params))

    def perform_reversal(
            self,
            qrc_id: Optional[str] = None,
            payrrn: Optional[str] = None,
            trx_id: Optional[str] = None,
            trx_dt: Optional[str] = None,
            amount: Optional[int] = None,
            currency: Optional[str] = None,
            message_id: Optional[str] = None,
            notification_url: Optional[str] = None,
            return_rest_amount: Optional[bool] = None
    ) -> Dict[str, Any]:
        """Выполняет возврат средств по ранее оплаченному QR-коду (QRCreversal).

        Args:
            qrc_id: Идентификатор QR-кода (32 символа, требуется, если не указаны payrrn или trx_id).
            payrrn: Референсный идентификатор запроса (12 цифр, требуется, если не указаны qrc_id или trx_id).
            trx_id: Идентификатор платежа в НСПК (32 символа, требуется, если не указаны qrc_id или payrrn).
            trx_dt: Дата и время платежа (ГГГГММДДччммсс).
            amount: Сумма возврата в копейках (по умолчанию полная сумма минус возвраты).
            currency: Код валюты (по умолчанию "RUB").
            message_id: Уникальный идентификатор сообщения (GUID, из GetQRCreversalData).
            notification_url: URL для уведомлений о статусе возврата.
            return_rest_amount: Проверка остатка для возврата (True/False).
        """
        if not (qrc_id or payrrn or trx_id):
            raise AlfaBankSBPClientError("-1", "Требуется qrcId, payrrn или trxId")

        params = {
            "qrcId": qrc_id,
            "payrrn": payrrn,
            "trxId": trx_id,
            "trxDT": trx_dt,
            "amount": str(amount) if amount is not None else None,
            "currency": currency,
            "messageID": message_id,
            "ReturnRestAmount": str(return_rest_amount).lower() if return_rest_amount is not None else None,
            "queryData": {"notificationUrl": notification_url}
        }
        return self._send_request(self._build_request_data("QRCreversal", params))

    def get_reversal_status(
            self,
            payrrn: Optional[str] = None,
            original_trx_id: Optional[str] = None,
            trx_id: Optional[str] = None,
            message_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Проверяет статус возврата средств (GetQRCreversalStatus).

        Args:
            payrrn: Референсный идентификатор запроса (12 цифр, требуется, если не указан original_trx_id).
            original_trx_id: Идентификатор исходного платежа (32 символа, требуется, если не указан payrrn).
            trx_id: Идентификатор возврата (32 символа, требуется, если не указан message_id).
            message_id: Уникальный идентификатор сообщения (GUID, требуется, если не указан trx_id).
        """
        if not (payrrn or original_trx_id):
            raise AlfaBankSBPClientError("Требуется payrrn или originalTrxId")
        if not (trx_id or message_id):
            raise AlfaBankSBPClientError("Требуется trxId или messageID")

        return self._send_request(self._build_request_data(
            "GetQRCreversalStatus",
            {
                "payrrn": payrrn,
                "originalTrxId": original_trx_id,
                "trxId": trx_id,
                "messageID": message_id
            }))

    def get_reversal_history(self, payrrn: str) -> Dict[str, Any]:
        """Получает историю возвратов по транзакции СБП C2B (GetQRCreversalHistory).

        Args:
            payrrn: Референсный идентификатор запроса (12 цифр).
        """
        return self._send_request(self._build_request_data("GetQRCreversalHistory", {"payrrn": payrrn}))

    def poll_qr_status(
            self,
            qrc_id: Optional[str] = None,
            payrrn: Optional[str] = None,
            max_attempts: int = 10,
            interval_seconds: int = 10
    ) -> Dict[str, Any] | None:
        """Опрашивает статус QR-кода до получения финального состояния.

        Args:
            qrc_id: Идентификатор QR-кода (32 символа, требуется, если не указан payrrn).
            payrrn: Референсный идентификатор запроса (12 цифр, требуется, если не указан qrc_id).
            max_attempts: Максимальное количество попыток опроса (по умолчанию 10).
            interval_seconds: Интервал между попытками в секундах (не менее 10, по умолчанию 10).
        """
        if not (qrc_id or payrrn):
            raise AlfaBankSBPClientError("Требуется qrcId или payrrn")

        for attempt in range(max_attempts):
            try:
                result = self.get_qr_status(qrc_id, payrrn)
                status = result.get("status")
                if status in ["ACWP", "RJCT"]:
                    logger.debug(f"Финальный статус QR-кода: {status}")
                    return result
                logger.debug(f"Промежуточный статус: {status}, попытка {attempt + 1}")
                time.sleep(max(interval_seconds, 10))  # Минимум 10 секунд
            except AlfaBankSBPClientError as e:
                logger.debug(f"Попытка {attempt + 1} не удалась: {e}")
                time.sleep(max(interval_seconds, 10))
