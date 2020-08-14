from trezor import wire
from trezor.messages import MessageType

from apps.common.paths import PATTERN_SEP0005_COMPAT

CURVE = "secp256k1"
SLIP44_ID = 194
PATTERN = PATTERN_SEP0005_COMPAT


def boot() -> None:
    wire.add(MessageType.EosGetPublicKey, __name__, "get_public_key")
    wire.add(MessageType.EosSignTx, __name__, "sign_tx")
