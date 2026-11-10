"""Bounded TCP/UDP client driving a single collection; no shell or target instrumentation."""
import socket
import time
import ipaddress

from tools.track.store import hexbytes


def validate(config):
    # DNS lookup has no portable stdlib timeout; require an explicit IP to honor the run deadline.
    ipaddress.ip_address(config.get("host", "127.0.0.1"))
    for exchange in config["exchanges"]:
        mode = exchange.get("receive_mode", "exact")
        if mode not in ("exact", "until_close", "idle"):
            raise ValueError("receive_mode 必须是 exact/until_close/idle")
        if config["transport"] == "udp" and (mode != "exact" or exchange.get("reconnect")):
            raise ValueError("UDP 不支持 receive_mode 或 reconnect 扩展")
        if mode != "exact" and "receive_bytes" in exchange:
            raise ValueError("非 exact 模式使用 max_receive_bytes，不使用 receive_bytes")
        if mode == "exact" and "max_receive_bytes" in exchange:
            raise ValueError("exact 模式使用 receive_bytes，不使用 max_receive_bytes")
        if mode != "idle" and "idle_timeout_ms" in exchange:
            raise ValueError("idle_timeout_ms 只适用于 idle 模式")
        if not 1 <= exchange.get("max_receive_bytes", 65536) <= 65536:
            raise ValueError("max_receive_bytes 必须在 1..65536")
        if not 1 <= exchange.get("idle_timeout_ms", 200) <= 30000:
            raise ValueError("idle_timeout_ms 必须在 1..30000")
        if ("send_hex" in exchange) == ("send_chunks" in exchange):
            raise ValueError("send_hex 与 send_chunks 必须且只能提供一个")
        if "send_chunks" in exchange and config["transport"] != "tcp":
            raise ValueError("send_chunks 仅支持 TCP；UDP 每个 exchange 发送一个完整数据报")
        chunks = exchange.get("send_chunks", [{"send_hex": exchange.get("send_hex", "")}])
        if not isinstance(chunks, list) or not 1 <= len(chunks) <= 64:
            raise ValueError("send_chunks 必须包含 1..64 段")
        for chunk in chunks:
            delay = chunk.get("delay_before_ms", 0)
            if type(delay) is not int or not 0 <= delay <= 30000:
                raise ValueError("delay_before_ms 必须在 0..30000")
        data = b"".join(hexbytes(c["send_hex"], "network.send_hex") for c in chunks)
        if len(data) > 65507:
            raise ValueError("每次网络发送最多 65507 字节")
    if "\x00" in config.get("host", "127.0.0.1"):
        raise ValueError("网络 host 包含 NUL")


def replay(config, deadline, check, transcript):
    def remaining():
        check()
        value = deadline - time.monotonic()
        if value <= 0:
            raise TimeoutError("采集总时限已到")
        return value

    delay_end = time.monotonic() + config.get("startup_delay_ms", 0) / 1000
    while time.monotonic() < delay_end:
        time.sleep(min(0.1, remaining(), delay_end - time.monotonic()))
    host, port = config.get("host", "127.0.0.1"), config["port"]
    transport = config["transport"]
    sock = None
    connection = -1

    def connect():
        if transport == "tcp":
            # The first successful connection is the experiment, not a probe.
            while True:
                try:
                    return socket.create_connection((host, port), timeout=min(0.5, remaining()))
                except (ConnectionRefusedError, TimeoutError):
                    time.sleep(min(0.1, remaining()))
        info = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)[0]
        result = socket.socket(info[0], socket.SOCK_DGRAM)
        try:
            result.connect(info[4])
            return result
        except BaseException:
            result.close()
            raise

    try:
        for index, exchange in enumerate(config["exchanges"]):
            if sock is None or exchange.get("reconnect", False):
                if sock is not None:
                    sock.close()
                sock = connect()
                connection += 1
            sock.settimeout(min(0.5, remaining()))
            chunks = exchange.get("send_chunks", [{"send_hex": exchange.get("send_hex", "")}])
            item = {"exchange": index, "send_hex": "".join(c["send_hex"] for c in chunks),
                    "received_hex": "", "complete": False, "connection": connection, "sent_bytes": 0,
                    "send_chunks": [], "receive_mode": exchange.get("receive_mode", "exact")}
            transcript.append(item)
            for chunk in chunks:
                part = {"send_bytes": len(chunk["send_hex"]) // 2, "sent_bytes": 0,
                        "delay_before_ms": chunk.get("delay_before_ms", 0)}
                item["send_chunks"].append(part)
                until = time.monotonic() + part["delay_before_ms"] / 1000
                while time.monotonic() < until:
                    time.sleep(max(0, min(0.05, remaining(), until - time.monotonic())))
                send = hexbytes(chunk["send_hex"], "network.send_hex")
                part["started_at_monotonic"] = time.monotonic()
                if transport == "tcp":
                    view = memoryview(send)
                    while view:
                        sock.settimeout(min(0.5, remaining()))
                        try:
                            sent = sock.send(view)
                        except socket.timeout:
                            continue
                        if not sent:
                            raise ConnectionError("发送时连接关闭")
                        view = view[sent:]
                        part["sent_bytes"] += sent
                        item["sent_bytes"] += sent
                else:
                    sock.settimeout(min(0.5, remaining()))
                    part["sent_bytes"] = sock.send(send)
                    item["sent_bytes"] += part["sent_bytes"]
            mode = exchange.get("receive_mode", "exact")
            wanted = exchange.get("receive_bytes", 0) if mode == "exact" else exchange.get("max_receive_bytes", 65536)
            received = bytearray()
            last_received = None
            item["receive_end"] = "length" if wanted else "no_receive"
            while mode != "exact" or len(received) < wanted:
                wait = min(0.5, remaining())
                if mode == "idle" and last_received is not None:
                    idle_left = exchange.get("idle_timeout_ms", 200) / 1000 - (time.monotonic() - last_received)
                    if idle_left <= 0:
                        item["receive_end"] = "idle"
                        break
                    wait = min(wait, idle_left)
                sock.settimeout(wait)
                try:
                    if transport == "udp":
                        chunk, _, flags, _ = sock.recvmsg(wanted)
                        if flags & socket.MSG_TRUNC:
                            item["response_truncated"] = True
                            item["received_hex"] = chunk.hex()
                            raise ValueError("UDP 响应大于 receive_bytes，已截断")
                    else:
                        # At the cap, read one byte to distinguish EOF from overflow.
                        chunk = sock.recv(max(1, wanted - len(received)))
                except socket.timeout:
                    continue
                if not chunk and transport == "tcp":
                    if mode == "exact":
                        raise ConnectionError("TCP 响应在 receive_bytes 之前结束")
                    item["receive_end"] = "eof"
                    break
                if len(received) + len(chunk) > wanted:
                    item["response_truncated"] = True
                    raise ValueError("TCP 响应超过 max_receive_bytes")
                received.extend(chunk)
                last_received = time.monotonic()
                item["received_hex"] = received.hex()
                if transport == "udp":
                    item["receive_end"] = "datagram"
                    break
            item["complete"] = True
    finally:
        if sock is not None:
            sock.close()
