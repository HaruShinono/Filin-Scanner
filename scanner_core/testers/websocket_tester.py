import websocket
import json
import time
from typing import List
from urllib.parse import urlparse

from scanner_core.scanner import Vulnerability
from .base_tester import BaseTester


class WebsocketTester(BaseTester):
    def __init__(self, session, config: dict):
        super().__init__(session, config)
        self.payloads = [
            "<script>alert('WSXSS')</script>",
            "<img src=x onerror=alert('WSXSS')>"
        ]

    def test(self, url: str) -> List[Vulnerability]:
        vulns = []
        parsed = urlparse(url)

        # Chỉ chạy khi phát hiện endpoint socket.io
        if 'socket.io' not in url.lower():
            return vulns

        # Chuyển đổi HTTP URL thành WebSocket URL (ws:// hoặc wss://)
        ws_scheme = 'ws' if parsed.scheme == 'http' else 'wss'
        # Xây dựng URL bắt tay (handshake) mặc định của Socket.io v4
        ws_url = f"{ws_scheme}://{parsed.netloc}/socket.io/?EIO=4&transport=websocket"

        print(f"  [DEBUG-WS] Auditing WebSocket Endpoint: {ws_url}", flush=True)

        # --- TEST 1: Cross-Site WebSocket Hijacking (CSWSH) ---
        try:
            # Gửi request bắt tay với Origin độc hại (evil.com)
            ws = websocket.create_connection(
                ws_url,
                header=["Origin: http://evil-attacker.com"],
                timeout=5
            )
            # Nếu kết nối thành công (Switching Protocols 101) mà không bị từ chối
            ws.close()
            print("  [DEBUG-WS] !!! CSWSH VULNERABILITY CONFIRMED !!!", flush=True)
            vulns.append(Vulnerability(
                type='Broken Access Control',
                subcategory='Cross-Site WebSocket Hijacking (CSWSH)',
                url=url,
                details={
                    'evidence': 'WebSocket connection accepted with an arbitrary Origin header (http://evil-attacker.com).',
                    'mitigation': 'Implement origin validation in Socket.io configuration.'
                },
                severity='High',
                cwe='CWE-1385',
                cvss_score=7.5,
                cvss_vector='CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:R/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N'
            ))
        except Exception as e:
            print(f"  [DEBUG-WS] CSWSH test passed (Connection refused by server): {e}", flush=True)

        # --- TEST 2: WebSocket Reflected XSS ---
        try:
            # Kết nối bình thường
            ws = websocket.create_connection(ws_url, timeout=5)

            # Đọc gói tin chào mừng của Socket.io (thường là '0{"sid":"..."}')
            ws.recv()
            # Gửi gói tin ping-probe (chuẩn của Socket.io)
            ws.send("2probe")
            ws.recv()

            for payload in self.payloads:
                # Định dạng gói tin Socket.io gửi message: 42["message_name", "payload"]
                socket_io_payload = f'42["message", "{payload}"]'
                print(f"  [DEBUG-WS] Sending WebSocket payload: {socket_io_payload}", flush=True)

                ws.send(socket_io_payload)

                # Lắng nghe phản hồi từ server trong 2 giây xem có bị phản xạ nguyên văn không
                start_time = time.time()
                while time.time() - start_time < 2:
                    try:
                        response = ws.recv()
                        if payload in response:
                            print("  [DEBUG-WS] !!! WEBSOCKET XSS CONFIRMED !!!", flush=True)
                            vulns.append(Vulnerability(
                                type='Cross-Site Scripting (XSS)',
                                subcategory='WebSocket Reflected XSS',
                                url=url,
                                details={
                                    'payload': socket_io_payload,
                                    'evidence': f'Payload reflected unescaped in WebSocket frame response: {response}'
                                },
                                severity='High',
                                cwe='CWE-79',
                                cvss_score=6.1,
                                cvss_vector='CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:R/VC:N/VI:L/VA:N/SC:L/SI:L/SA:N'
                            ))
                            break
                    except websocket.SubprocessDoc:
                        break
            ws.close()
        except Exception as e:
            print(f"  [DEBUG-WS] WebSocket XSS test exception: {e}", flush=True)

        return vulns