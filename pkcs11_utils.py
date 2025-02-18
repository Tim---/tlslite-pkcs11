#!/usr/bin/env python3

import contextlib
import getpass
from typing import Optional, TypeVar
from collections.abc import Iterator
import pkcs11
from pkcs11 import Attribute, Certificate, Mechanism, Object, PrivateKey, PublicKey
from tlslite import X509
from tlslite.utils.rsakey import RSAKey


class Pkcs11RsaKey(RSAKey):
    def __init__(self, priv_key: PrivateKey, pub_key: PublicKey):
        self.priv_key = priv_key
        self.pub_key = pub_key
        self.key_type = "rsa"

    def __len__(self) -> int:
        return self.priv_key.key_length

    def sign(
        self,
        bytes: bytes,
        padding: str = "pkcs1",
        hashAlg: None = None,
        saltLen: Optional[int] = None,
    ) -> bytes:
        assert padding == "pkcs1"
        assert hashAlg is None
        assert saltLen == 0
        result = self.priv_key.sign(bytes, mechanism=Mechanism.RSA_PKCS)
        print(bytes)
        print(self.priv_key)
        print(result)
        return result

    def verify(
        self,
        sigBytes: bytes,
        data: bytes,
        padding: str = "pkcs1",
        hashAlg: None = None,
        saltLen: Optional[int] = None,
    ) -> bool:
        assert padding == "pkcs1"
        assert hashAlg is None
        assert saltLen == 0
        result = self.pub_key.verify(data, sigBytes, mechanism=Mechanism.RSA_PKCS)
        return result


@contextlib.contextmanager
def get_cert(module: str, label: str) -> Iterator[tuple[Pkcs11RsaKey, X509]]:
    T = TypeVar("T", bound=Object)

    lib = pkcs11.lib(module)
    token = lib.get_token()

    with token.open(user_pin=getpass.getpass(f"pin for {label}: ")) as session:

        def get_obj(t: type[T]) -> T:
            (obj,) = session.get_objects(
                {Attribute.CLASS: t.object_class, Attribute.LABEL: label}
            )
            assert isinstance(obj, t)
            return obj

        priv_key = get_obj(PrivateKey)
        pub_key = get_obj(PublicKey)
        cert = get_obj(Certificate)

        raw_cert = cert[Attribute.VALUE]

        pkcs11_key = Pkcs11RsaKey(priv_key, pub_key)

        cert = X509()
        cert.parseBinary(raw_cert)

        yield pkcs11_key, cert
