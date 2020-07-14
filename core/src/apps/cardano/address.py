from trezor import log
from trezor.crypto import base58, crc, hashlib

from apps.cardano.protocol_magics import ProtocolMagics
from apps.common import HARDENED, cbor
from apps.common.seed import remove_ed25519_prefix

if False:
    from typing import Tuple
    from trezor.crypto import bip32
    from apps.cardano import seed


def _encode_address_raw(address_data_encoded: bytes) -> str:
    return base58.encode(
        cbor.encode(
            [cbor.Tagged(24, address_data_encoded), crc.crc32(address_data_encoded)]
        )
    )


def derive_address_and_node(
    keychain: seed.Keychain, path: list, protocol_magic: int
) -> Tuple[str, bip32.Node]:
    node = keychain.derive(path)

    address_attributes = get_address_attributes(protocol_magic)

    address_root = _get_address_root(node, address_attributes)
    address_type = 0
    address_data = [address_root, address_attributes, address_type]
    address_data_encoded = cbor.encode(address_data)

    return (_encode_address_raw(address_data_encoded), node)


def get_address_attributes(protocol_magic: int) -> dict:
    # protocol magic is included in Byron addresses only on testnets
    if protocol_magic == ProtocolMagics.MAINNET:
        address_attributes = {}
    else:
        address_attributes = {2: cbor.encode(protocol_magic)}

    return address_attributes


def is_safe_output_address(address: str) -> bool:
    """
    Determines whether it is safe to include the address as-is as
    a tx output, preventing unintended side effects (e.g. CBOR injection)
    """
    address_data_encoded = _get_address_data(address)
    if address_data_encoded is None:
        return False

    return _encode_address_raw(address_data_encoded) == address


def _get_address_data(address: str) -> bytes:
    try:
        address_hex = base58.decode(address)
        address_unpacked = cbor.decode(address_hex)
    except ValueError as e:
        if __debug__:
            log.exception(__name__, e)
        return None

    if not isinstance(address_unpacked, list) or len(address_unpacked) != 2:
        return None

    address_data_encoded = address_unpacked[0]
    if not isinstance(address_data_encoded, bytes):
        return None

    return address_data_encoded


def matches_with_protocol_magic(address: str, protocol_magic: int) -> bool:
    address_data_encoded = _get_address_data(address)
    if address_data_encoded is None:
        return False

    address_data = cbor.decode(address_data_encoded)
    if not isinstance(address_data, list) or len(address_data) < 2:
        return False

    address_attributes = address_data[1]

    if len(address_attributes) == 0:
        return protocol_magic == ProtocolMagics.MAINNET

    if 2 not in address_attributes:
        return False

    protocol_magic_cbor = address_attributes[2]
    address_protocol_magic = cbor.decode(protocol_magic_cbor)

    if not isinstance(address_protocol_magic, int):
        return False

    return address_protocol_magic == protocol_magic


def validate_full_path(path: list) -> bool:
    """
    Validates derivation path to fit 44'/1815'/a'/{0,1}/i,
    where `a` is an account number and i an address index.
    The max value for `a` is 20, 1 000 000 for `i`.
    The derivation scheme v1 allowed a'/0/i only,
    but in v2 it can be a'/1/i as well.
    """
    if len(path) != 5:
        return False
    if path[0] != 44 | HARDENED:
        return False
    if path[1] != 1815 | HARDENED:
        return False
    if path[2] < HARDENED or path[2] > 20 | HARDENED:
        return False
    if path[3] != 0 and path[3] != 1:
        return False
    if path[4] > 1000000:
        return False
    return True


def _address_hash(data: list) -> bytes:
    cbor_data = cbor.encode(data)
    sha_data_hash = hashlib.sha3_256(cbor_data).digest()
    res = hashlib.blake2b(data=sha_data_hash, outlen=28).digest()
    return res


def _get_address_root(node: bip32.Node, address_attributes: dict) -> bytes:
    extpubkey = remove_ed25519_prefix(node.public_key()) + node.chain_code()
    return _address_hash([0, [0, extpubkey], address_attributes])
