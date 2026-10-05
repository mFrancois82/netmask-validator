from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ValidationResult:
    """Outcome of validating an address and prefix length as a network.

    Attributes:
        address: The dotted-decimal IPv4 address exactly as supplied.
        prefix_length: The prefix length (0-32) as supplied.
        is_legal_network: True iff no host bits are set for the given prefix.
        host_bits: The integer formed by the bits of the address strictly
            below the prefix length, i.e. the host portion interpreted as a
            non-negative integer. Zero for a legal network. Always defined,
            even when the prefix is 0 (whole host) or 32 (whole address).
    """
    address: str
    prefix_length: int
    is_legal_network: bool
    host_bits: int


class NetmaskValidator:
    """Validate that an IPv4 address and prefix length form a legal network.

    A "legal network" here means the address has zero in every host bit
    position, i.e. the address equals the network address for its prefix.
    For example, 192.168.1.0/24 is legal; 192.168.1.5/24 is not, because
    the last three octets carry host bits.

    Design choices (one interpretation, stated plainly):
      * IPv4 only. IPv6 is out of scope; callers should validate that
        elsewhere. Keeping the surface narrow means the code stays small
        and easy to audit.
      * Prefix length is a single integer 0-32, not a dotted netmask.
        Translating 255.255.255.0 -> 24 is a separate concern.
      * The address is parsed by stdlib ipaddress and then re-derived as
        a 32-bit unsigned int, so the host bits come from canonical bits
        rather than textual octets (which sidesteps leading-zero quirks
        like "192.168.001.001", which ipaddress rejects anyway).
      * prefix_length=0 denotes the default route; the whole address is
        host bits, but a legal network only if the address is 0.0.0.0.
      * prefix_length=32 denotes a host route; there are no host bits,
        and any legal address is trivially a "legal network" under this
        definition (host_bits == 0).
    """

    MAX_PREFIX = 32

    def validate(self, address: str, prefix_length: int) -> ValidationResult:
        """Validate an IPv4 address and prefix length.

        Args:
            address: Dotted-decimal IPv4 address (e.g. "10.0.0.0").
            prefix_length: Prefix length in the range [0, 32].

        Returns:
            A ValidationResult describing the network legality and host bits.

        Raises:
            TypeError: If the argument types are wrong.
            ValueError: If the prefix length is out of range, or if the
                address is not a valid IPv4 address in dotted-decimal form.
        """
        if not isinstance(address, str):
            raise TypeError(
                f"address must be str, got {type(address).__name__}"
            )
        if isinstance(prefix_length, bool) or not isinstance(prefix_length, int):
            raise TypeError(
                f"prefix_length must be int, got {type(prefix_length).__name__}"
            )
        if not 0 <= prefix_length <= self.MAX_PREFIX:
            raise ValueError(
                f"prefix_length must be in [0, 32], got {prefix_length}"
            )

        # ipaddress is stdlib and rejects malformed/IPv6/leading-zero forms.
        # We require IPv4Address specifically; IPv6Address is a different class
        # and would silently pass isinstance(ip_address, IPv4Address) == False,
        # so we raise explicitly to keep the contract narrow.
        import ipaddress

        try:
            ip = ipaddress.ip_address(address)
        except ValueError as exc:
            raise ValueError(f"invalid IPv4 address: {address!r}") from exc

        if not isinstance(ip, ipaddress.IPv4Address):
            raise ValueError(f"not an IPv4 address: {address!r}")

        value = int(ip)
        host_bits = self._extract_host_bits(value, prefix_length)

        return ValidationResult(
            address=address,
            prefix_length=prefix_length,
            is_legal_network=(host_bits == 0),
            host_bits=host_bits,
        )

    @staticmethod
    def _extract_host_bits(address_int: int, prefix_length: int) -> int:
        """Return the host portion of a 32-bit address integer.

        The host portion is the low (32 - prefix_length) bits of the address.
        For prefix_length == 32 this is zero bits -> 0. For prefix_length == 0
        this is all 32 bits -> the address itself.
        """
        if prefix_length == 0:
            return address_int
        # Shift right by the host width to drop host bits, then shift back
        # left and subtract from the original to isolate them. Equivalent to
        # address_int & ((1 << host_width) - 1), but expressed via shifts so
        # the prefix_length == 32 case (host width 0) needs no special casing
        # beyond the mask naturally becoming 0.
        host_width = 32 - prefix_length
        network_int = (address_int >> host_width) << host_width
        return address_int - network_int
