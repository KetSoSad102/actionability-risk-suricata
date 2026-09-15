from __future__ import annotations

import argparse
from dataclasses import dataclass
from scapy.all import Ether, IP, TCP, wrpcap, Raw


@dataclass
class HttpFlow:
    name: str
    src: str
    dst: str
    sport: int
    dport: int
    host: str
    path: str
    user_agent: str = "curl/8.0"
    response_code: int = 200
    response_body: str = "OK"


def tcp_http_flow(flow: HttpFlow, seq_base: int) -> list:
    cseq = seq_base
    sseq = seq_base + 100000
    ether = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")

    syn = ether / IP(src=flow.src, dst=flow.dst) / TCP(sport=flow.sport, dport=flow.dport, flags="S", seq=cseq)
    synack = ether / IP(src=flow.dst, dst=flow.src) / TCP(sport=flow.dport, dport=flow.sport, flags="SA", seq=sseq, ack=cseq + 1)
    ack = ether / IP(src=flow.src, dst=flow.dst) / TCP(sport=flow.sport, dport=flow.dport, flags="A", seq=cseq + 1, ack=sseq + 1)

    req = (
        f"GET {flow.path} HTTP/1.1\r\n"
        f"Host: {flow.host}\r\n"
        f"User-Agent: {flow.user_agent}\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode()

    req_pkt = ether / IP(src=flow.src, dst=flow.dst) / TCP(
        sport=flow.sport, dport=flow.dport, flags="PA", seq=cseq + 1, ack=sseq + 1
    ) / Raw(req)

    body = flow.response_body.encode()
    resp = (
        f"HTTP/1.1 {flow.response_code} OK\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Content-Type: text/plain\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode() + body

    resp_pkt = ether / IP(src=flow.dst, dst=flow.src) / TCP(
        sport=flow.dport, dport=flow.sport, flags="PA", seq=sseq + 1, ack=cseq + 1 + len(req)
    ) / Raw(resp)

    fin1 = ether / IP(src=flow.dst, dst=flow.src) / TCP(sport=flow.dport, dport=flow.sport, flags="FA", seq=sseq + 1 + len(resp), ack=cseq + 1 + len(req))
    fin2 = ether / IP(src=flow.src, dst=flow.dst) / TCP(sport=flow.sport, dport=flow.dport, flags="FA", seq=cseq + 1 + len(req), ack=sseq + 2 + len(resp))

    return [syn, synack, ack, req_pkt, resp_pkt, fin1, fin2]


def build_flows() -> list[HttpFlow]:
    ext = "203.0.113.10"
    home_server = "10.0.0.20"
    internal_client = "10.0.0.10"
    external_server = "203.0.113.20"

    return [
        HttpFlow(
            name="OpenVAS RCE test string - SID 2012726",
            src=ext, dst=home_server, sport=41001, dport=80,
            host="victim.local",
            path="/scan?q=T3BlblZBU1ZUIFJDRSBUZXN0",
            response_body="openvas marker accepted",
        ),
        HttpFlow(
            name="ColdFusion admin access + 200 response - SID 2016185",
            src=ext, dst=home_server, sport=41002, dport=80,
            host="victim.local",
            path="/CFIDE/administrator/index.cfm",
            response_body="ColdFusion administrator login page",
        ),
        HttpFlow(
            name="D-Link cli command separator - SID 2025756",
            src=ext, dst=home_server, sport=41003, dport=80,
            host="victim.local",
            path="/login.cgi?cli=abc;id",
            response_body="D-Link login handler",
        ),
        HttpFlow(
            name="Nmap NSE UA + 200 response - SID 2009359",
            src=ext, dst=home_server, sport=41004, dport=80,
            host="victim.local",
            path="/",
            user_agent="Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
            response_body="web root",
        ),
        HttpFlow(
            name="SQLi information_schema + 200 response - SID 2017809",
            src=ext, dst=home_server, sport=41005, dport=80,
            host="victim.local",
            path="/search?q=information_schema",
            response_body="schema search result",
        ),
        HttpFlow(
            name="SQLi SELECT FROM + 200 response - SID 2006447",
            src=ext, dst=home_server, sport=41006, dport=80,
            host="victim.local",
            path="/search?q=SELECTFROMusers",
            response_body="user rows",
        ),
        HttpFlow(
            name="SQLi UNION SELECT + 200 response - SID 2006448",
            src=ext, dst=home_server, sport=41007, dport=80,
            host="victim.local",
            path="/search?q=UNIONSELECTpassword",
            response_body="joined rows",
        ),
        HttpFlow(
            name="XSS script tag + 200 response - SID 2009715",
            src=ext, dst=home_server, sport=41008, dport=80,
            host="victim.local",
            path="/comment?text=</script>",
            response_body="comment accepted",
        ),
        HttpFlow(
            name="Internal Go HTTP client UA - SID 2024897",
            src=internal_client, dst=external_server, sport=42001, dport=80,
            host="external.local",
            path="/api/v1/check",
            user_agent="Go-http-client/1.1",
            response_body="external api ok",
        ),
        HttpFlow(
            name="Internal Nmap UA - SID 2024364",
            src=internal_client, dst=external_server, sport=42002, dport=80,
            host="external.local",
            path="/",
            user_agent="Mozilla Nmap",
            response_body="external web ok",
        ),
    ]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    packets = []
    for i, flow in enumerate(build_flows()):
        packets.extend(tcp_http_flow(flow, seq_base=1000 + i * 10000))

    wrpcap(args.output, packets)
    print(f"[+] Wrote {len(packets)} packets to {args.output}")
    print("[+] Payload scenarios:")
    for flow in build_flows():
        print(f"    - {flow.name}: {flow.src}:{flow.sport} -> {flow.dst}:{flow.dport} {flow.path}")


if __name__ == "__main__":
    main()
