from trezor.messages.BinanceGetPublicKey import BinanceGetPublicKey
from trezor.messages.BinancePublicKey import BinancePublicKey

from apps.common import layout, paths
from apps.common.keychain import Keychain, with_slip44_keychain

from . import CURVE, PATTERN, SLIP44_ID


@with_slip44_keychain(PATTERN, slip44_id=SLIP44_ID, curve=CURVE)
async def get_public_key(ctx, msg: BinanceGetPublicKey, keychain: Keychain):
    await paths.validate_path(ctx, keychain, msg.address_n)
    node = keychain.derive(msg.address_n)
    pubkey = node.public_key()

    if msg.show_display:
        await layout.show_pubkey(ctx, pubkey)

    return BinancePublicKey(pubkey)
