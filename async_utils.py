#!/usr/bin/env python3

import errno
import socket
import asyncio


class AsyncWrapper:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.reader = reader
        self.writer = writer
        self.buffer = bytearray()

    def send(self, data: bytes) -> int:
        self.writer.write(data)
        return len(data)

    def sendall(self, data: bytes) -> int:
        return self.send(data)

    def recv(self, size: int) -> bytes:
        assert size
        if not self.buffer:
            raise socket.error(errno.EWOULDBLOCK)
        else:
            chunk, self.buffer = self.buffer[:size], self.buffer[size:]
            return bytes(chunk)

    async def recv_some(self):
        chunk = await self.reader.read(8192)
        assert chunk
        self.buffer.extend(chunk)
