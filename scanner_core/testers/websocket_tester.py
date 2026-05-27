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
            "<iframe src=\"javascript:alert(`xss`)\">",
            "<script>alert('WSXSS')</script>",
            "<img src=x onerror=alert('WSXSS')>"
        ]

    def test(self, url: str) -> List[Vulnerability]:
        vulns = []
        parsed = urlparse(url)

        if 'socket.io' not in url.lower():
            return vulns

        # Chuyển đổi HTTP protocol sang WS protocol
        ws_scheme = 'ws' if parsed.scheme == 'http' else 'wss'
        ws_url = f"{ws_scheme}://{parsed.netloc}/socket.io/?EIO=4&transport=websocket"

        print(f"  [DEBUG-WS] Connecting to Engine.IO / Socket.IO endpoint: {ws_url}", flush=True)

        # --- TEST 1: Cross-Site WebSocket Hijacking (CSWSH) ---
        try:
            # Sửa lỗi: Thêm bypass Ngrok vào Header bắt tay CSWSH
            ws_cswsh = websocket.create_connection(
                ws_url,
                header=[
                    "Origin: http://evil-attacker.com",
                    "ngrok-skip-browser-warning: true"
                ],
                timeout=5
            )
            initial_packet = ws_cswsh.recv()
            ws_cswsh.close()

            if initial_packet.startswith('0'):
                vulns.append(Vulnerability(
                    type='Broken Access Control',
                    subcategory='Cross-Site WebSocket Hijacking (CSWSH)',
                    url=url,
                    details={
                        'evidence': 'WebSocket connection accepted with an arbitrary Origin header (http://evil-attacker.com).',
                        'packet_received': initial_packet
                    },
                    severity='High',
                    cwe='CWE-1385',
                    cvss_score=7.5,
                    # Sửa UI:R thành UI:A cho đúng chuẩn CVSS v4.0
                    cvss_vector='CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N'
                ))
        except Exception as e:
            print(f"  [DEBUG-WS] CSWSH test finished (Connection refused/closed): {e}", flush=True)

        # --- TEST 2: Socket.IO Event Fuzzing (XSS) ---
        try:
            # Sửa lỗi: Thêm bypass Ngrok vào Header bắt tay XSS Fuzzing
            ws = websocket.create_connection(
                ws_url,
                header=["ngrok-skip-browser-warning: true"],
                timeout=5
            )

            # Step A: Handshake '0' packet
            handshake = ws.recv()

            # Step B: Connect to namespace
            ws.send("40")
            ns_ack = ws.recv()

            # Step C: Fuzzing
            for payload in self.payloads:
                event_packet = f'42["verifyLocalXssChallenge","{payload}"]'
                print(f"  [DEBUG-WS] Emitting packet: {event_packet}", flush=True)

                ws.send(event_packet)

                start_time = time.time()
                while time.time() - start_time < 3:
                    try:
                        response = ws.recv()
                        if payload in response:
                            print("  [DEBUG-WS] !!! WEBSOCKET XSS CONFIRMED !!!", flush=True)
                            vulns.append(Vulnerability(
                                type='Cross-Site Scripting (XSS)',
                                subcategory='WebSocket Reflected XSS',
                                url=url,
                                details={
                                    'event': 'verifyLocalXssChallenge',
                                    'payload': event_packet,
                                    'evidence': f'Payload reflected unescaped in Socket.IO response packet: {response}'
                                },
                                severity='High',
                                cwe='CWE-79',
                                cvss_score=6.1,
                                # Sửa UI:R thành UI:A cho đúng chuẩn CVSS v4.0
                                cvss_vector='CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:L/SI:L/SA:N'
                            ))
                            break
                    except Exception:
                        break
            ws.close()
        except Exception as e:
            print(f"  [DEBUG-WS] Socket.IO connection failed: {e}", flush=True)

        return vulns