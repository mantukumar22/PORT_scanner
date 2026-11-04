
import ipaddress
import socket
import argparse
import sys
import logging
from datetime import datetime
from pathlib import Path

DEFAULT_PORTS = [22, 80, 443, 8080]
MAX_PORTS = 100
DEFAULT_TIMEOUT = 2.0
RESULTS_DIR = Path("results")
LOG_FILE = Path("scanner.log")

PRIVATE_NETWORKS = [
	ipaddress.ip_network("10.0.0.0/8"),
	ipaddress.ip_network("172.16.0.0/12"),
	ipaddress.ip_network("192.168.0.0/16"),
	ipaddress.ip_network("fc00::/7"),
]

log = logging.getLogger("scanner")
log.addHandler(logging.NullHandler()) # stay silent unless --log is used in cmd

# -- arguments --

def positive_float(text):
	
	try:
		value = float(text)
	except ValueError:
		raise argparse.ArgumentTypeError("must be a number") from None
	if not 0.1 <= value <= 30:
		raise argparse.ArgumentTypeError("must be between 0.1 & 30")
	return value


def parse_args(argv=None):
	parser = argparse.ArgumentParser(
		description="Small, safe TCP port checker",
		epilog="Only scan systems have permission to test."
	)
	parser.add_argument("target", help="IP address or hostname")
	parser.add_argument("--ports", help="comma separated ports.")
	parser.add_argument("--timeout", type=positive_float, default=DEFAULT_TIMEOUT, help="timeout")
	parser.add_argument("--log", action="store_true", help="logs")
	return parser.parse_args(argv)


# --target validation--

def classify(addr):
	if addr.version == 6 and addr.ipv4_mapped is not None:
		addr = addr.ipv4_mapped
	if addr.is_loopback:
		return "loopback"
	if any(addr in net for net in PRIVATE_NETWORKS if net.version == addr.version):
		return "private"
	return "refused"


def resolve_target(raw):
	raw = raw.strip()
	try:
		return [ipaddress.ip_address(raw)]
	except ValueError:
		pass
	try:
		infos = socket.getaddrinfo(raw, None, type=socket.SOCK_STREAM)
	except (socket.gaierror, UnicodeError):
		raise ValueError(
			"Target is not a valid IP or a resolveable hostname"
		) from None
	addrs = []
	for info in infos:
		addr = ipaddress.ip_address(info[4][0].split("%")[0])
		if addr not in addrs:
			addrs.append(addr)
	addrs.sort(key=lambda a: a.version)
	return addrs
	

def validate_target(raw):
	addrs = resolve_target(raw)
	kinds = {classify(a) for a in addrs}
	if "refused" in kinds:
		raise ValueError("refused: target is (or resolve to) a public or non-private address" )
	kind = "private" if "private" in kinds else "loopback"
	return addrs[0], kind

def confirm_authorization(addr):
	print(f"{addr} is a private address.")
	print("Only scan systems you own or have written permission to test.")
	try:
		answer = input("Type 'yes' to confirm you are authorized: ").strip().lower()
	except EDFError:
		return False
	return answer == "yes"


# -- ports --

def parse_ports(raw):
	if raw is None:
		return list(DEFAULT_PORTS)
	parts = [p.strip() for p in raw.split(",")]
	if any(p == "" for p in parts):
		raise ValueError("empty port in the list ")
	ports = set()
	for part in parts:
		if not (part.isascii() and part.isdigit()):
			raise ValueError(f"'{part}' is not a valid port number")
		port = int(part)
		if not 1 <= port <= 65535:
			raise ValueError(f"port {port} is out of range ")
		ports.add(port)
	if len(ports) > MAX_PORTS:
		raise ValueError(f"too many ports {MAX_PORTS}")
	return sorted(ports)


def check_port(addr, port, timeout):
	try:
		with socket.create_connection((str(addr), port), timeout=timeout):
			return "open"
	except ConnectionRefusedError:
		return "closed"
	except socket.timeout:
		return "Filtered/no response"
	except OSError as e:
		return f"error: {e.strerror or e}"

#-- saving--

def save_results(target, addr, kind, timeout, results):
	RESULTS_DIR.mkdir(exist_ok=True)
	now = datetime.now()
	path = RESULTS_DIR / f"scan_{now.strftime('%Y-%m-%d_%H%M%S')}.txt"
	lines = [
		"Port scan results ",
		f"Time: {now.isoformat(timespec='seconds')}",
		f"Target: {target} ({addr}, {kind})",
		f"Timeout: {timeout}s",	
		f"Ports: {', '.join(str(p) for p, _ in results)}",
		"",
	]
	lines += [f"{port}/tcp {state}" for port, state in results]
	path.write_text("\n".join(lines) + "\n", encoding="utf-8")
	return path

def setup_logging():
	logging.basicConfig(
		filename=LOG_FILE,
		level=logging.INFO,
		format="%(asctime)s %(levelname)s %(message)s"
	)


# -------Main------------


def main(argv=None):
	args = parse_args(argv)
	if args.log:
		setup_logging()

	try:
		addr, kind = validate_target(args.target)
		ports = parse_ports(args.ports)

		if kind == "private" and not confirm_authorization(addr):
			raise ValueError("authorization not confirmed; nothing was scanned")
		
		log.info("Scan started: target accepted (%s), %d ports", kind, len(ports))
		print(f"Scanning {args.target} ({kind}), {len(ports)} port(s), "
			f"timeout {args.timeout}s\n")
		
		results = []
		for port in ports:
			state = check_port(addr, port, args.timeout)
			print(f"{port:>5}/tcp {state}")
			log.info("port %d: %d: %s", port, state)
			results.append((port, state))
		
		path = save_results(args.target, addr, kind, args.timeout, results)
		print(f"\nSaved results to {path}")
		log.info("Results saved to %s", path)
		return 0

	except ValueError as e:
		print(f"Error: {e}", file=sys.stder)
		log.warning("Rejected: %s", e)
		return 2
	except KeyboardInterrupt:
		print("\nStopped by user.", file=sys.stderr)
		log.warning("Stopped by user")
		return 130
	except OSError as e:
		print(f"Network or file error: {e}", file=sys.stderr)
		log.error("Os error: %s", e)
		return 1

if __name__ == "__main__":
	sys.exit(main())




