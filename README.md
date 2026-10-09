# Netmask Validator

A small, dependency-free Python library that checks whether an IPv4 address and prefix length form a legal network (i.e. the address has no host bits set for the given prefix) and reports the host bits that are set.

## Usage

```python
from netmask_validator import NetmaskValidator, ValidationResult

validator = NetmaskValidator()
result: ValidationResult = validator.validate("192.168.1.5", 24)

print(result.is_legal_network)  # False
print(result.host_bits)         # 5

result = validator.validate("192.168.1.0", 24)
print(result.is_legal_network)  # True
print(result.host_bits)         # 0
```

Exported names: `NetmaskValidator` (the validator class) and `ValidationResult` (an immutable dataclass with `address`, `prefix_length`, `is_legal_network`, and `host_bits` fields).

## Why this exists

Config parsers, firewall rule loaders, and DHCP config generators often receive an address plus a prefix length from a user and need to distinguish a genuine network address (e.g. `10.0.0.0/24`) from a host address inside that network (e.g. `10.0.0.5/24`). The standard library's `ipaddress` module can build a network object, but it silently masks off host bits by default, which hides the very mistake the caller made. This library makes the check explicit and returns the offending host bits as an integer so callers can report a precise error.

The trade-off: the library is IPv4-only and takes a prefix length as a bare integer (0-32), not a dotted netmask like `255.255.255.0`. Converting a dotted netmask to a prefix length is a separate concern; keeping it out avoids ambiguity around non-contiguous netmasks, which are legal on some platforms but not on others.

## Awkward edges

- `prefix_length=32` describes a host route. There are no host bits, so any valid IPv4 address is reported as a legal network with `host_bits == 0`. This is intentional: `/32` has no host portion to be wrong.
- `prefix_length=0` describes the default route. The entire 32-bit address is host bits, so the only legal network address is `0.0.0.0`.
- The library does not accept IPv6 addresses; passing one raises `ValueError`.
- Addresses with leading zeros (e.g. `192.168.001.001`) are rejected, matching the behavior of Python's `ipaddress` module.

## Performance

The window keeps a bounded buffer, so `push` is constant time and memory does not
grow with the length of the stream. `peak` and `trough` are linear in the window
size, which is the trade that keeps `push` cheap.

