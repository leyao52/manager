"""凭据加解密工具：使用 Fernet 对称加密存储实例账号密码。"""
import base64
import binascii
import hashlib

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings


class CredentialCipherError(ValueError):
    """解密失败：密钥变更或密文损坏。"""


def _fernet_key() -> bytes:
    """优先使用配置的 Fernet key，未配置时由 SECRET_KEY 派生（仅建议本地开发使用）。"""
    configured = (getattr(settings, "CREDENTIAL_ENCRYPTION_KEY", "") or "").strip()
    if configured:
        return configured.encode("ascii")
    digest = hashlib.sha256(settings.SECRET_KEY.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


def encrypt(plaintext: str) -> str:
    """加密明文，返回可直接入库的 base64 密文。"""
    return Fernet(_fernet_key()).encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt(ciphertext: str) -> str:
    """解密数据库中保存的密文。"""
    try:
        return Fernet(_fernet_key()).decrypt(ciphertext.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError, TypeError, binascii.Error) as exc:
        raise CredentialCipherError("无法解密凭据，请检查 CREDENTIAL_ENCRYPTION_KEY 配置") from exc


def generate_encryption_key() -> str:
    """生成一个新的 Fernet key，用于配置 CREDENTIAL_ENCRYPTION_KEY。"""
    return Fernet.generate_key().decode("ascii")
