from micropython import const

from trezor import ui
from trezor.messages import ButtonRequestType
from trezor.ui.text import Text

from . import HARDENED
from .confirm import require_confirm

if False:
    from typing import (
        Any,
        Callable,
        Collection,
        List,
        Sequence,
        TypeVar,
    )
    from trezor import wire

    # XXX this is a circular import, but it's only for typing
    from .keychain import Keychain

    Bip32Path = Sequence[int]
    Slip21Path = Sequence[bytes]
    PathType = TypeVar("PathType", Bip32Path, Slip21Path)


class PathSchema:
    """General BIP-32 path schema.

    Loosely based on the BIP-32 path template proposal [1], with the following
    constants added from BIP-44 as possible wildcards:

    * `coin_type` is substituted with the coin's SLIP-44 identifier
    * `account` is substituted with [0-100], Trezor's default range of accounts
    * `change` is substituted with [0,1]
    * `address_index` is substituted with [0-1000000], Trezor's default range of addresses

    In addition, each path component is limited to either a constant (7), a range
    (0-19), or a list of values (1,2,3). Brackets are recommended but not enforced.

    Hardened flag is indicated by an apostrophe.

    See examples of valid path formats below and in `apps.bitcoin.keychain`.

    E.g. the following are equivalent definitions of a BIP-84 schema:

        m/84'/coin_type'/[0-100]'/[0,1]/[0-1000000]
        m/84'/coin_type'/0-100'/0,1/0-1000000
        m/84'/coin_type'/account'/change/address_index

    Adding an asterisk at the end of the pattern acts as a wildcard for zero or more
    non-hardened path components with any value.

    The following is a BIP-44 generic `GetPublicKey` schema:

        m/44'/coin_type'/account'/*

    The asterisk can only appear at end of pattern. Using hardened suffix (*') is not
    currently supported.

    [1] https://github.com/dgpv/bip32_template_parse_tplaplus_spec/blob/master/bip-path-templates.mediawiki
    """

    REPLACEMENTS = {
        "account": "0-100",
        "change": "0,1",
        "address_index": "0-1000000",
    }

    def __init__(self, pattern: str, slip44_id: int) -> None:
        if not pattern.startswith("m/"):
            raise ValueError  # unsupported path template
        components = pattern[2:].split("/")

        self.schema = []  # type: List[Collection[int]]
        self.trailing_components = ()  # type: Collection[int]

        for component in components:
            if component == "*":
                if len(self.schema) != len(components) - 1:
                    # every component should have resulted in extending self.schema
                    # so if self.schema does not have the appropriate length (yet),
                    # the asterisk is not the last item
                    raise ValueError  # asterisk is not last item of pattern
                self.trailing_components = range(HARDENED)
                break

            # figure out if the component is hardened
            if component[-1] == "'":
                component = component[:-1]
                parse = (
                    lambda s: int(s) | HARDENED
                )  # type: Callable[[Any], int]  # noqa: E731
            else:
                parse = int

            # strip brackets
            if component[0] == "[" and component[-1] == "]":
                component = component[1:-1]

            # optionally replace a keyword
            component = self.REPLACEMENTS.get(component, component)

            if "-" in component:
                # parse as a range
                a, b = [parse(s) for s in component.split("-", 1)]
                self.schema.append(range(a, b + 1))

            elif "," in component:
                # parse as a list of values
                self.schema.append(set(parse(s) for s in component.split(",")))

            elif component == "coin_type":
                # substitute SLIP-44 id
                self.schema.append((parse(slip44_id),))

            else:
                # plain constant
                self.schema.append((parse(component),))

    def match(self, path: Bip32Path) -> bool:
        # The path must not be _shorter_ than schema. It may be longer.
        if len(path) < len(self.schema):
            return False

        path_iter = iter(path)
        # iterate over length of schema, consuming path components
        for expected in self.schema:
            value = next(path_iter)
            if value not in expected:
                return False

        # iterate over remaining path components
        for value in path_iter:
            if value not in self.trailing_components:
                return False

        return True

    if __debug__:

        def __repr__(self) -> str:
            components = ["m"]

            def unharden(item: int) -> int:
                return item ^ HARDENED

            for component in self.schema:
                if isinstance(component, range):
                    a, b = component.start, component.stop - 1
                    components.append(
                        "[{}-{}]{}".format(
                            unharden(a), unharden(b), "'" if a & HARDENED else ""
                        )
                    )
                else:
                    component_str = ",".join(str(unharden(i)) for i in component)
                    if len(component) > 1:
                        component_str = "[" + component_str + "]"
                    if next(iter(component)) & HARDENED:
                        component_str += "'"
                    components.append(component_str)

            if self.trailing_components:
                components.append("*")

            return "<schema:" + "/".join(components) + ">"


class _AlwaysMatchingSchema:
    def match(self, path: Bip32Path) -> bool:
        return True

    if __debug__:

        def __repr__(self) -> str:
            return "<schema:always_match>"


class _NeverMatchingPathSchema:
    def match(self, path: Bip32Path) -> bool:
        return False

    if __debug__:

        def __repr__(self) -> str:
            return "<schema:never_match>"


PATTERN_BIP44 = "m/44'/coin_type'/account'/change/address_index"
PATTERN_BIP44_PUBKEY = "m/44'/coin_type'/account'/*"
PATTERN_SEP0005 = "m/44'/coin_type'/account'"
PATTERN_SEP0005_COMPAT = "m/44'/coin_type'/account'/0/0"

SCHEMA_ANY_PATH = _AlwaysMatchingSchema()
SCHEMA_NO_MATCH = _NeverMatchingPathSchema()


async def validate_path(
    ctx: wire.Context, keychain: Keychain, path: Bip32Path, *additional_checks: bool
) -> None:
    keychain.verify_path(path)
    if not keychain.is_in_keychain(path) or not all(additional_checks):
        await show_path_warning(ctx, path)


async def show_path_warning(ctx: wire.Context, path: Bip32Path) -> None:
    text = Text("Confirm path", ui.ICON_WRONG, ui.RED)
    text.normal("Path")
    text.mono(*break_address_n_to_lines(path))
    text.normal("is unknown.")
    text.normal("Are you sure?")
    await require_confirm(ctx, text, ButtonRequestType.UnknownDerivationPath)


def is_hardened(i: int) -> bool:
    return bool(i & HARDENED)


def path_is_hardened(address_n: Bip32Path) -> bool:
    return all(is_hardened(n) for n in address_n)


def break_address_n_to_lines(address_n: Bip32Path) -> List[str]:
    def path_item(i: int) -> str:
        if i & HARDENED:
            return str(i ^ HARDENED) + "'"
        else:
            return str(i)

    lines = []
    path_str = "m/" + "/".join([path_item(i) for i in address_n])

    per_line = const(17)
    while len(path_str) > per_line:
        i = path_str[:per_line].rfind("/")
        lines.append(path_str[:i])
        path_str = path_str[i:]
    lines.append(path_str)

    return lines
