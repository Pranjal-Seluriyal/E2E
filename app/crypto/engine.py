import time
from typing import Dict, List, Optional, Tuple
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature
from app.crypto.exceptions import DecryptionError, InvalidSignatureError, SessionError

class ClientCryptoEngine:
    def __init__(self, device_id: str):
        self.device_id: str = device_id
        
        # 1. Long-term Identity Keys
        self.identity_private_dh = x25519.X25519PrivateKey.generate()
        self.identity_public_dh = self.identity_private_dh.public_key()
        
        self.identity_private_sign = ed25519.Ed25519PrivateKey.generate()
        self.identity_public_sign = self.identity_private_sign.public_key()
        
        # Combined 64-byte public identity key
        self.identity_public_bytes = (
            self.identity_public_dh.public_bytes_raw() + 
            self.identity_public_sign.public_bytes_raw()
        )
        
        # 2. Medium-term Signed Prekey (SPK)
        self.spk_id: int = 1
        self.spk_private = x25519.X25519PrivateKey.generate()
        self.spk_public = self.spk_private.public_key()
        
        # Sign public SPK using identity signing key
        spk_bytes = self.spk_public.public_bytes_raw()
        self.spk_signature = self.identity_private_sign.sign(spk_bytes)
        
        # Store initial SPK in history
        self.spk_history: Dict[int, x25519.X25519PrivateKey] = {self.spk_id: self.spk_private}
        
        # 3. One-Time Prekeys (OPKs)
        self.opk_store: Dict[int, x25519.X25519PrivateKey] = {}
        self.next_opk_id: int = 100
        
        # 4. Session Store: maps peer_device_id -> session_key (bytes)
        self.sessions: Dict[str, bytes] = {}
        self.seen_messages: Dict[str, List[bytes]] = {}  # Replay protection track
        self.session_ephemeral_keys: Dict[str, bytes] = {}
        self.peer_identity_keys: Dict[str, bytes] = {}

    def generate_one_time_prekeys(self, count: int) -> List[Tuple[int, bytes]]:
        """Generates a batch of one-time prekeys, stores the private parts, and returns public parts."""
        public_prekeys = []
        for _ in range(count):
            opk_id = self.next_opk_id
            self.next_opk_id += 1
            opk_priv = x25519.X25519PrivateKey.generate()
            self.opk_store[opk_id] = opk_priv
            public_prekeys.append((opk_id, opk_priv.public_key().public_bytes_raw()))
        return public_prekeys

    def verify_peer_signed_prekey(
        self,
        peer_identity_bytes: bytes,
        peer_spk_bytes: bytes,
        peer_spk_signature: bytes
    ) -> bool:
        """Verifies that a peer's signed prekey is signed by their identity signing key."""
        try:
            if len(peer_identity_bytes) == 64:
                signing_key_bytes = peer_identity_bytes[32:]
            else:
                signing_key_bytes = peer_identity_bytes
            peer_identity_sign = ed25519.Ed25519PublicKey.from_public_bytes(signing_key_bytes)
            peer_identity_sign.verify(peer_spk_signature, peer_spk_bytes)
            return True
        except InvalidSignature:
            return False

    def initiate_x3dh(
        self,
        peer_device_id: str,
        peer_identity_bytes: bytes,
        peer_spk_bytes: bytes,
        peer_spk_signature: bytes,
        peer_spk_id: int,
        peer_opk_bytes: Optional[bytes] = None,
        peer_opk_id: Optional[int] = None
    ) -> Tuple[bytes, bytes, bytes]:
        """Executes client-side X3DH key agreement.
        Returns: (session_key, local_ephemeral_public_bytes, peer_identity_dh_bytes)
        """
        # Detect key changes / rotations
        if peer_device_id in self.peer_identity_keys:
            if self.peer_identity_keys[peer_device_id] != peer_identity_bytes:
                raise SessionError(f"Peer identity key changed for device {peer_device_id}! Key rotation detected.")
        else:
            self.peer_identity_keys[peer_device_id] = peer_identity_bytes

        # 1. Verify Signed Prekey Signature
        if not self.verify_peer_signed_prekey(peer_identity_bytes, peer_spk_bytes, peer_spk_signature):
            raise InvalidSignatureError("Peer's signed prekey verification failed.")
            
        peer_identity_dh_bytes = peer_identity_bytes[:32]
        peer_identity_dh = x25519.X25519PublicKey.from_public_bytes(peer_identity_dh_bytes)
        peer_spk = x25519.X25519PublicKey.from_public_bytes(peer_spk_bytes)
        
        # 2. Generate local ephemeral key pair (EK)
        ek_private = x25519.X25519PrivateKey.generate()
        ek_public = ek_private.public_key()
        ek_public_bytes = ek_public.public_bytes_raw()
        
        # 3. Perform DH exchanges
        # DH1 = local_identity_private_dh * peer_spk
        dh1 = self.identity_private_dh.exchange(peer_spk)
        # DH2 = local_ephemeral_private_dh * peer_identity_dh
        dh2 = ek_private.exchange(peer_identity_dh)
        # DH3 = local_ephemeral_private_dh * peer_spk
        dh3 = ek_private.exchange(peer_spk)
        
        dh_concat = dh1 + dh2 + dh3
        
        # DH4 = local_ephemeral_private_dh * peer_opk (optional)
        if peer_opk_bytes is not None and peer_opk_id is not None:
            peer_opk = x25519.X25519PublicKey.from_public_bytes(peer_opk_bytes)
            dh4 = ek_private.exchange(peer_opk)
            dh_concat += dh4

        # 4. KDF (HKDF-SHA256) to derive 32-byte session key
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            salt=b"\x00" * 32,
            info=b"Reddit-Insta-E2EE-X3DH",
            length=32
        )
        session_key = hkdf.derive(dh_concat)
        
        # Save session key
        self.sessions[peer_device_id] = session_key
        self.session_ephemeral_keys[peer_device_id] = ek_public_bytes
        return session_key, ek_public_bytes, peer_identity_dh_bytes

    def receive_x3dh(
        self,
        peer_device_id: str,
        peer_identity_bytes: bytes,
        peer_ephemeral_key_bytes: bytes,
        signed_prekey_id: int,
        one_time_prekey_id: Optional[int] = None
    ) -> bytes:
        """Executes recipient-side X3DH key agreement using local stored private keys."""
        # Detect key changes / rotations
        if peer_device_id in self.peer_identity_keys:
            if self.peer_identity_keys[peer_device_id] != peer_identity_bytes:
                raise SessionError(f"Peer identity key changed for device {peer_device_id}! Key rotation detected.")
        else:
            self.peer_identity_keys[peer_device_id] = peer_identity_bytes

        peer_identity_dh_bytes = peer_identity_bytes[:32]
        peer_identity_dh = x25519.X25519PublicKey.from_public_bytes(peer_identity_dh_bytes)
        peer_ek = x25519.X25519PublicKey.from_public_bytes(peer_ephemeral_key_bytes)
        
        # 1. DH1 = local_spk_private * peer_identity_dh
        if signed_prekey_id == self.spk_id:
            spk_priv = self.spk_private
        elif signed_prekey_id in self.spk_history:
            spk_priv = self.spk_history[signed_prekey_id]
        else:
            raise SessionError("Local signed prekey ID mismatch or retired.")
            
        dh1 = spk_priv.exchange(peer_identity_dh)
        
        # 2. DH2 = local_identity_private_dh * peer_ek
        dh2 = self.identity_private_dh.exchange(peer_ek)
        
        # 3. DH3 = local_spk_private * peer_ek (using correct retired key)
        dh3 = spk_priv.exchange(peer_ek)
        
        dh_concat = dh1 + dh2 + dh3
        
        # 4. DH4 = local_opk_private * peer_ek (optional)
        if one_time_prekey_id is not None:
            if one_time_prekey_id not in self.opk_store:
                raise SessionError("One-time prekey not found or already consumed.")
            opk_private = self.opk_store.pop(one_time_prekey_id)  # Remove to prevent reuse
            dh4 = opk_private.exchange(peer_ek)
            dh_concat += dh4
            
        # 5. HKDF-SHA256 key derivation
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            salt=b"\x00" * 32,
            info=b"Reddit-Insta-E2EE-X3DH",
            length=32
        )
        session_key = hkdf.derive(dh_concat)
        
        self.sessions[peer_device_id] = session_key
        return session_key

    def encrypt(self, peer_device_id: str, plaintext: bytes) -> Tuple[bytes, bytes]:
        """Encrypts data using the active session key. Returns (ciphertext, iv)."""
        session_key = self.sessions.get(peer_device_id)
        if not session_key:
            raise SessionError(f"No active E2EE session with device {peer_device_id}")
            
        import os
        aesgcm = AESGCM(session_key)
        iv = os.urandom(12)
        assoc_data = f"{self.device_id}:{peer_device_id}".encode("utf-8")
        ciphertext = aesgcm.encrypt(iv, plaintext, assoc_data)
        return ciphertext, iv

    def decrypt(self, peer_device_id: str, ciphertext: bytes, iv: bytes) -> bytes:
        """Decrypts ciphertext using active session key, with integrity and replay checks."""
        session_key = self.sessions.get(peer_device_id)
        if not session_key:
            raise SessionError(f"No active E2EE session with device {peer_device_id}")
            
        # Replay/duplicate check
        if peer_device_id not in self.seen_messages:
            self.seen_messages[peer_device_id] = []
        if ciphertext in self.seen_messages[peer_device_id]:
            raise DecryptionError("Replay attack detected: ciphertext has already been decrypted.")
            
        aesgcm = AESGCM(session_key)
        assoc_data = f"{peer_device_id}:{self.device_id}".encode("utf-8")
        
        try:
            plaintext = aesgcm.decrypt(iv, ciphertext, assoc_data)
            self.seen_messages[peer_device_id].append(ciphertext)
            return plaintext
        except Exception as e:
            raise DecryptionError(f"Ciphertext decryption failed: {str(e)}")

    def rotate_signed_prekey(self) -> Tuple[int, bytes, bytes]:
        """Rotates the signed prekey. Returns (new_spk_id, public_bytes, signature)."""
        self.spk_id += 1
        self.spk_private = x25519.X25519PrivateKey.generate()
        self.spk_public = self.spk_private.public_key()
        
        # Store new key in history
        self.spk_history[self.spk_id] = self.spk_private
        
        spk_bytes = self.spk_public.public_bytes_raw()
        self.spk_signature = self.identity_private_sign.sign(spk_bytes)
        
        return self.spk_id, spk_bytes, self.spk_signature
