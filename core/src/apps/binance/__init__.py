from trezor import wire
from trezor.messages import MessageType

from apps.common.paths import PATTERN_SEP0005_COMPAT

CURVE = "secp256k1"
SLIP44_ID = 714
PATTERN = PATTERN_SEP0005_COMPAT


def boot() -> None:
    wire.add(MessageType.BinanceGetAddress, __name__, "get_address")
    wire.add(MessageType.BinanceGetPublicKey, __name__, "get_public_key")
    wire.add(MessageType.BinanceSignTx, __name__, "sign_tx")
