#!/usr/bin/env python3
"""Minimal OpenAI-compatible SSE provider used by demo_phase15.sh.

Streams a slow text response chunk by chunk so the NetAgent Core can
demonstrate real-time agent.text.delta events and mid-turn cancellation.

Usage: python3 fake_llm_sse.py <port>
"""
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

CHUNKS = [
    "正在分析当前网络证据：已加载 15 条 flow 与 15 条 DNS 事件。",
    "规则 dns_nxdomain_spike 检测到 10.0.0.8 的 NXDOMAIN 比率 66.7%，",
    "规则 dns_nxdomain_enumeration 检测到 10 个不同的 NXDOMAIN 查询名。",
    "证据引用与报告已生成（artifact ref），未发现需要实时抓包的缺口。",
    "结论：当前网络存在 DNS 异常模式，建议结合防火墙提案（preview only）评审。",
    "此演示每秒输出一个 chunk，以便观察流式增量与取消行为。",
]


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        try:
            for chunk in CHUNKS:
                event = f"data: {json.dumps({'choices': [{'delta': {'content': chunk}}]})}\n\n"
                body = event.encode("utf-8")
                self.wfile.write(f"{len(body):x}\r\n".encode("utf-8"))
                self.wfile.write(body)
                self.wfile.write(b"\r\n")
                self.wfile.flush()
                time.sleep(0.5)
            self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            # The Core cancelled the turn mid-stream: this is the expected demo path.
            pass

    def log_message(self, *args):
        pass


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8790
    server = HTTPServer(("127.0.0.1", port), Handler)
    print(f"fake SSE provider listening on 127.0.0.1:{port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
