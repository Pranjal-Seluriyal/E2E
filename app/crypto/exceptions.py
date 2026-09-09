class E2EError(Exception):
    """Base class for all E2EE exceptions."""
    pass

class DecryptionError(E2EError):
    """Raised when ciphertext decryption fails (e.g. invalid signature, corrupted payload, or bad key)."""
    pass

class SessionError(E2EError):
    """Raised when an active Double Ratchet session cannot be established or is missing."""
    pass

class InvalidSignatureError(E2EError):
    """Raised when signature verification on prekeys or payloads fails."""
    pass

class KeyRotationError(E2EError):
    """Raised when signed prekey rotation fails verification."""
    pass

class DeviceRevocationError(E2EError):
    """Raised when attempting cryptographic operations with a revoked device."""
    pass
