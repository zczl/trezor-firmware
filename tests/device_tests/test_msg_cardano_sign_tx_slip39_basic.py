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

from ..common import MNEMONIC_SLIP39_BASIC_20_3of6

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
        "83a400818258201af8fa0b754ff99253d983894e63a2b09cbb56c833ba18c3384210163f63dcfc00018182582b82d818582183581c9e1c71de652ec8b85fec296f0685ca3988781c94a2e1a5d89d92f45fa0001a0d0c25611a002dd2e802182a030aa1008182582024c4fe188a39103db88818bc191fd8571eae7b284ebcbdf2462bde97b058a95c5840891702f10b3cea50bf32d3449d6dbd34cdeec5a282172e478421b6f1d84684a87fda755bc77d9095b96727f1f7648b670d2ff4c41bc10c612521344ccef7380ff6",
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
        "4c43ce4c72f145b145ae7add414722735e250d048f61c4585a5becafcbffa6ae",
        # serialized tx
        "83a400818258201af8fa0b754ff99253d983894e63a2b09cbb56c833ba18c3384210163f63dcfc00018282582b82d818582183581c9e1c71de652ec8b85fec296f0685ca3988781c94a2e1a5d89d92f45fa0001a0d0c25611a002dd2e882582b82d818582183581c2ea63b3db3a1865f59c11762a5aede800ed8f2dc0605d75df2ed7c9ca0001ae82668161a000f424002182a030aa1008182582024c4fe188a39103db88818bc191fd8571eae7b284ebcbdf2462bde97b058a95c5840fb62fe0fdd3f497f03148ffc1fef18f4b6e75efb21bc7207767740d8b64afebe53143f08221dfb3fcff780f811826ec95e4a37317aa6d6a0c69895da001da908f6",
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
        "b84b4805b9b24e37d83538e08a077fc82b72af1cdb54b1ef454491587d1cd53a",
        # serialized tx
        "83a400818258201af8fa0b754ff99253d983894e63a2b09cbb56c833ba18c3384210163f63dcfc00018282582f82d818582583581cc817d85b524e3d073795819a25cdbb84cff6aa2bbb3a081980d248cba10242182a001a0fb6fc611a002dd2e882582f82d818582583581c9207eb267885eb475deddf7d325b1ab7a8ad92a0fb18ba6291e050eda10242182a001aa01941361a000f424002182a030aa1008182582024c4fe188a39103db88818bc191fd8571eae7b284ebcbdf2462bde97b058a95c584036be1a2ed66125e683e12a210d1527d533acb0a105457122cbcd39c812c5cf79ada29a091065b94da21a31891e6b4cd53e6ee1a47c970f036741012b226f220cf6",
    ),
]


@pytest.mark.altcoin
@pytest.mark.cardano
@pytest.mark.skip_t1  # T1 support is not planned
@pytest.mark.setup_client(mnemonic=MNEMONIC_SLIP39_BASIC_20_3of6, passphrase=True)
@pytest.mark.parametrize(
    "protocol_magic,inputs,outputs,fee,ttl,tx_hash,serialized_tx", VALID_VECTORS
)
def test_cardano_sign_tx(
    client, protocol_magic, inputs, outputs, fee, ttl, tx_hash, serialized_tx
):
    inputs = [cardano.create_input(i) for i in inputs]
    outputs = [cardano.create_output(o) for o in outputs]

    expected_responses = [
        messages.PassphraseRequest(),
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

    client.use_passphrase("TREZOR")
    with client:
        client.set_expected_responses(expected_responses)
        client.set_input_flow(input_flow)
        response = cardano.sign_tx(client, inputs, outputs, fee, ttl, protocol_magic)
        assert response.tx_hash.hex() == tx_hash
        assert response.serialized_tx.hex() == serialized_tx
