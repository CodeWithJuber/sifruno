#!/usr/bin/python3
# Dev VM only (proof.sh panel-shell): relay guest port 80, which QEMU forwards
# from a host loopback port, to the panel. The panel binds loopback only.
import asyncio
import sys

TARGET_PORT = int(sys.argv[1])


async def pipe(reader, writer):
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    except ConnectionError:
        pass
    finally:
        writer.close()


async def handle(client_reader, client_writer):
    try:
        upstream_reader, upstream_writer = await asyncio.open_connection("127.0.0.1", TARGET_PORT)
    except OSError:
        client_writer.close()
        return
    await asyncio.gather(pipe(client_reader, upstream_writer), pipe(upstream_reader, client_writer))


async def main():
    server = await asyncio.start_server(handle, "0.0.0.0", 80)
    async with server:
        await server.serve_forever()


asyncio.run(main())
