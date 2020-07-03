# This file is part of the Trezor project.
#
# Copyright (C) 2012-2019 SatoshiLabs and contributors
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the License along with this library.
# If not, see <https://www.gnu.org/licenses/lgpl-3.0.html>.

import pytest

from trezorlib import cardano, messages
from trezorlib.cardano import PROTOCOL_MAGICS
from trezorlib.exceptions import TrezorFailure

SAMPLE_INPUT = {
    "path": "m/44'/1815'/0'/0/1",
    "prev_hash": "1af8fa0b754ff99253d983894e63a2b09cbb56c833ba18c3384210163f63dcfc",
    "prev_index": 0,
}

SAMPLE_OUTPUTS = {
    "simple_output": {
        "address": "Ae2tdPwUPEZCanmBz5g2GEwFqKTKpNJcGYPKfDxoNeKZ8bRHr8366kseiK2",
        "amount": "3003112",
    },
    "change_output": {"path": "m/44'/1815'/0'/0/1", "amount": "1000000"},
    "invalid_address": {
        "address": "jsK75PTH2esX8k4Wvxenyz83LJJWToBbVmGrWUer2CHFHanLseh7r3sW5X5q",
        "amount": "3003112",
    },
    "invalid_cbor": {
        "address": "5dnY6xgRcNUSLGa4gfqef2jGAMHb7koQs9EXErXLNC1LiMPUnhn8joXhvEJpWQtN3F4ysATcBvCn5tABgL3e4hPWapPHmcK5GJMSEaET5JafgAGwSrznzL1Mqa",
        "amount": "3003112",
    },
    "large_simple_output": {
        "address": "Ae2tdPwUPEZCanmBz5g2GEwFqKTKpNJcGYPKfDxoNeKZ8bRHr8366kseiK2",
        "amount": "449999999199999999",
    },
    "testnet_output": {
        "address": "2657WMsDfac7BteXkJq5Jzdog4h47fPbkwUM49isuWbYAr2cFRHa3rURP236h9PBe",
        "amount": "3003112",
    },
}

VALID_VECTORS = [
    # Mainnet transaction without change
    (
        # protocol magic
        PROTOCOL_MAGICS["mainnet"],
        # inputs
        [SAMPLE_INPUT],
        # outputs
        [SAMPLE_OUTPUTS["simple_output"]],
        # fee
        42,
        # ttl
        10,
        # tx hash
        "73e09bdebf98a9e0f17f86a2d11e0f14f4f8dae77cdf26ff1678e821f20c8db6",
        # serialized tx
        "83a400818258201af8fa0b754ff99253d983894e63a2b09cbb56c833ba18c3384210163f63dcfc00018182582b82d818582183581c9e1c71de652ec8b85fec296f0685ca3988781c94a2e1a5d89d92f45fa0001a0d0c25611a002dd2e802182a030aa1008182582089053545a6c254b0d9b1464e48d2b5fcf91d4e25c128afb1fcfc61d0843338ea5840600b3c21cc08389de4f151aaf8cfea4127b04c50a70ad427d5f2724f72ca9dbce0e8812947a5040393276bcbe0cb047ba231c5edd55f69181a5caec7e5139c0ef6",
    ),
    # Mainnet transaction with change
    (
        # protocol magic (mainnet)
        PROTOCOL_MAGICS["mainnet"],
        # inputs
        [SAMPLE_INPUT],
        # outputs
        [SAMPLE_OUTPUTS["simple_output"], SAMPLE_OUTPUTS["change_output"]],
        # fee
        42,
        # ttl
        10,
        # tx hash
        "81b14b7e62972127eb33c0b1198de6430540ad3a98eec621a3194f2baac43a43",
        # serialized tx
        "83a400818258201af8fa0b754ff99253d983894e63a2b09cbb56c833ba18c3384210163f63dcfc00018282582b82d818582183581c9e1c71de652ec8b85fec296f0685ca3988781c94a2e1a5d89d92f45fa0001a0d0c25611a002dd2e882582b82d818582183581cda4da43db3fca93695e71dab839e72271204d28b9d964d306b8800a8a0001a7a6916a51a000f424002182a030aa1008182582089053545a6c254b0d9b1464e48d2b5fcf91d4e25c128afb1fcfc61d0843338ea5840d97639e62463d312a3f98d8877e379dffbc9689e845ab7b1341b9c83eff40b1d26c85e42232027542d62edaeda8f84f9a0fc6232a8fa3e3c2536845fdbc6630ff6",
    ),
    # Testnet transaction
    (
        # protocol magic
        PROTOCOL_MAGICS["testnet"],
        # inputs
        [SAMPLE_INPUT],
        # outputs
        [SAMPLE_OUTPUTS["testnet_output"], SAMPLE_OUTPUTS["change_output"]],
        # fee
        42,
        # ttl
        10,
        # tx hash
        "1a624c5935fac3d0185e3900cc040f66442b40b29791cdbcb2803fb4c46ec8b4",
        # serialized tx
        "83a400818258201af8fa0b754ff99253d983894e63a2b09cbb56c833ba18c3384210163f63dcfc00018282582f82d818582583581cc817d85b524e3d073795819a25cdbb84cff6aa2bbb3a081980d248cba10242182a001a0fb6fc611a002dd2e882582f82d818582583581c90bf7d20a6e5351b6e1a47f8f236005044e2a36fbe648a33a2639127a10242182a001ab97eca181a000f424002182a030aa1008182582089053545a6c254b0d9b1464e48d2b5fcf91d4e25c128afb1fcfc61d0843338ea5840d8f79cf71ffcdbfa22e7c1761702b36fa70d640bff851cc5b5087b3748fc14e92a56c274a37209e602208096b2e9366483d25cff990552cf9e91501146138d01f6",
    ),
]

INVALID_VECTORS = [
    # Output address is a valid CBOR but invalid Cardano address
    (
        # protocol magic
        PROTOCOL_MAGICS["mainnet"],
        # inputs
        [SAMPLE_INPUT],
        # outputs
        [SAMPLE_OUTPUTS["invalid_address"]],
        # fee
        42,
        # ttl
        10,
        # error message
        "Invalid output address!",
    ),
    # Output address is invalid CBOR
    (
        # protocol magic (mainnet)
        PROTOCOL_MAGICS["mainnet"],
        # inputs
        [SAMPLE_INPUT],
        # outputs
        [SAMPLE_OUTPUTS["invalid_cbor"]],
        # fee
        42,
        # ttl
        10,
        # error message
        "Invalid output address!",
    ),
    # Fee is too high
    (
        # protocol magic (mainnet)
        PROTOCOL_MAGICS["mainnet"],
        # inputs
        [SAMPLE_INPUT],
        # outputs
        [SAMPLE_OUTPUTS["simple_output"]],
        # fee
        45000000000000001,
        # ttl
        10,
        # error message
        "Fee is out of range!",
    ),
    # Output total is too high
    (
        # protocol magic (mainnet)
        PROTOCOL_MAGICS["mainnet"],
        # inputs
        [SAMPLE_INPUT],
        # outputs
        [SAMPLE_OUTPUTS["large_simple_output"], SAMPLE_OUTPUTS["change_output"]],
        # fee
        42,
        # ttl
        10,
        # error message
        "Total transaction amount is out of range!",
    ),
    # Mainnet transaction with testnet output
    (
        # protocol magic
        PROTOCOL_MAGICS["mainnet"],
        # inputs
        [SAMPLE_INPUT],
        # outputs
        [SAMPLE_OUTPUTS["testnet_output"]],
        # fee
        42,
        # ttl
        10,
        # error message
        "Output address network mismatch!",
    ),
    # Testnet transaction with mainnet output
    (
        # protocol magic
        PROTOCOL_MAGICS["testnet"],
        # inputs
        [SAMPLE_INPUT],
        # outputs
        [SAMPLE_OUTPUTS["simple_output"]],
        # fee
        42,
        # ttl
        10,
        # error message
        "Output address network mismatch!",
    ),
]


@pytest.mark.altcoin
@pytest.mark.cardano
@pytest.mark.skip_t1  # T1 support is not planned
@pytest.mark.parametrize(
    "protocol_magic,inputs,outputs,fee,ttl,tx_hash,serialized_tx", VALID_VECTORS
)
def test_cardano_sign_tx(
    client, protocol_magic, inputs, outputs, fee, ttl, tx_hash, serialized_tx
):
    inputs = [cardano.create_input(i) for i in inputs]
    outputs = [cardano.create_output(o) for o in outputs]

    expected_responses = [
        messages.ButtonRequest(code=messages.ButtonRequestType.Other),
        messages.ButtonRequest(code=messages.ButtonRequestType.Other),
        messages.CardanoSignedTx(),
    ]

    def input_flow():
        yield
        client.debug.swipe_up()
        client.debug.press_yes()
        yield
        client.debug.swipe_up()
        client.debug.press_yes()

    with client:
        client.set_expected_responses(expected_responses)
        client.set_input_flow(input_flow)
        response = cardano.sign_tx(client, inputs, outputs, fee, ttl, protocol_magic)
        assert response.tx_hash.hex() == tx_hash
        assert response.serialized_tx.hex() == serialized_tx


@pytest.mark.altcoin
@pytest.mark.cardano
@pytest.mark.skip_t1  # T1 support is not planned
@pytest.mark.parametrize(
    "protocol_magic,inputs,outputs,fee,ttl,expected_error_message", INVALID_VECTORS
)
def test_cardano_sign_tx_validation(
    client, protocol_magic, inputs, outputs, fee, ttl, expected_error_message
):
    inputs = [cardano.create_input(i) for i in inputs]
    outputs = [cardano.create_output(o) for o in outputs]

    expected_responses = [messages.Failure()]

    with client:
        client.set_expected_responses(expected_responses)

        with pytest.raises(TrezorFailure, match=expected_error_message):
            cardano.sign_tx(client, inputs, outputs, fee, ttl, protocol_magic)
