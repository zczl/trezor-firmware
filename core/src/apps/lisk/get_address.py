from trezor.messages.LiskAddress import LiskAddress

from apps.common import paths
from apps.common.keychain import with_slip44_keychain
from apps.common.layout import address_n_to_str, show_address, show_qr

from . import CURVE, PATTERN, SLIP44_ID
from .helpers import get_address_from_public_key


@with_slip44_keychain(PATTERN, slip44_id=SLIP44_ID, curve=CURVE)
async def get_address(ctx, msg, keychain):
    await paths.validate_path(ctx, keychain, msg.address_n)

    node = keychain.derive(msg.address_n)
    pubkey = node.public_key()
    pubkey = pubkey[1:]  # skip ed25519 pubkey marker
    address = get_address_from_public_key(pubkey)

    if msg.show_display:
        desc = address_n_to_str(msg.address_n)
        while True:
            if await show_address(ctx, address, desc=desc):
                break
            if await show_qr(ctx, address, desc=desc):
                break

    return LiskAddress(address=address)
