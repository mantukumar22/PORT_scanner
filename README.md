# Day 7: My First Security Tool

A small, safe TCP port checker for learning.

## Safety rules

- Loopback targets (`127.0.0.1`, `::1`) are allowed.
- Private targets (`10.x.x.x`, `172.16-31.x.x`, `192.168.x.x`) need you to type `yes`.
- Public addresses are refused before any connection is made.
- Hostnames are resolved first, and every address they resolve to must be allowed.
- Only scan systems you own or have written permission to test.

## Usage

```bash
python3 scanner.py 127.0.0.1
python3 scanner.py 127.0.0.1 --ports 22,80,443
python3 scanner.py 192.168.x.x --ports 22,80 --timeout 1 --log
bash scan.sh 127.0.0.1 --ports 8000,9999   # or: chmod +x scan.sh && ./scan.sh ...
```

## States

| State | Meaning |
|---|---|
| `open` | A program accepted the connection |
| `closed` | The host answered "refused" (nothing is listening) |
| `filtered/no response` | No answer before the timeout (firewall, or host down) |
| `error: ...` | Another network problem, shown with the reason |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Scan finished |
| 1 | Network or file error |
| 2 | Bad input, refused target, or authorization not given |
| 130 | Stopped with Ctrl+C |

## Output

Results go to `results/scan_<date>_<time>.txt`. The `results/` folder and `*.log` files are in `.gitignore`. Never commit real IPs or hostnames. Use placeholders like `192.168.x.x` in docs.

## Limits

This only checks whether a port answers. It is not a vulnerability assessment.
