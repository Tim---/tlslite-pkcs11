import asyncio
import argparse
from tlslite import X509CertChain, TLSConnection, HandshakeSettings

from async_utils import AsyncWrapper
from pkcs11_utils import get_cert


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("module")
    parser.add_argument("label")
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    args = parser.parse_args()

    with get_cert(args.module, args.label) as (key, cert):
        reader, writer = await asyncio.open_connection(args.host, args.port)

        wrapper = AsyncWrapper(reader, writer)
        conn = TLSConnection(wrapper)

        settings = HandshakeSettings()
        settings.minVersion = (3, 1)
        settings.maxVersion = (3, 1)
        settings.versions = [(3, 1)]

        h = conn.handshakeClientCert(
            X509CertChain([cert]),
            key,
            settings=settings,
            serverName=args.host,
            async_=True,
        )
        for x in h:
            assert x == 0
            await wrapper.recv_some()


asyncio.run(main())
