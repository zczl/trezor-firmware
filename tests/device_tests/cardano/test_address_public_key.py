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

from trezorlib.cardano import (
    NETWORK_IDS,
    create_address_parameters,
    get_address,
    get_public_key,
)
from trezorlib.messages import CardanoAddressType
from trezorlib.tools import parse_path

from ...common import parametrize_using_common_fixtures

pytestmark = [
    pytest.mark.altcoin,
    pytest.mark.cardano,
    pytest.mark.skip_t1,
    pytest.mark.skip_ui,
]


@parametrize_using_common_fixtures(
    "cardano/get_address.json", "cardano/get_address.slip39.json"
)
def test_cardano_get_address(client, parameters, result):
    address = get_address(
        client,
        address_parameters=create_address_parameters(
            address_type=CardanoAddressType.BYRON,
            address_n=parse_path(parameters["path"]),
        ),
        protocol_magic=parameters["protocol_magic"],
        network_id=NETWORK_IDS["mainnet"],
    )
    assert address == result["expected_address"]


@parametrize_using_common_fixtures("cardano/get_base_address.json")
def test_cardano_get_base_address(client, parameters, result):
    address = get_address(
        client,
        address_parameters=create_address_parameters(
            address_type=CardanoAddressType.BASE,
            address_n=parse_path(parameters["path"]),
            address_n_staking=parse_path(parameters["staking_path"]),
        ),
        protocol_magic=parameters["protocol_magic"],
        network_id=parameters["network_id"],
    )
    assert address == result["expected_address"]


@parametrize_using_common_fixtures(
    "cardano/get_base_address_with_staking_key_hash.json"
)
def test_cardano_get_base_address_with_staking_key_hash(client, parameters, result):
    address = get_address(
        client,
        address_parameters=create_address_parameters(
            address_type=CardanoAddressType.BASE,
            address_n=parse_path(parameters["path"]),
            staking_key_hash=bytes.fromhex(parameters["staking_key_hash"]),
        ),
        protocol_magic=parameters["protocol_magic"],
        network_id=parameters["network_id"],
    )
    assert address == result["expected_address"]


@parametrize_using_common_fixtures("cardano/get_enterprise_address.json")
def test_cardano_get_enterprise_address(client, parameters, result):
    address = get_address(
        client,
        address_parameters=create_address_parameters(
            address_type=CardanoAddressType.ENTERPRISE,
            address_n=parse_path(parameters["path"]),
        ),
        protocol_magic=parameters["protocol_magic"],
        network_id=parameters["network_id"],
    )
    assert address == result["expected_address"]


@parametrize_using_common_fixtures("cardano/get_pointer_address.json")
def test_cardano_get_pointer_address(client, parameters, result):
    address = get_address(
        client,
        address_parameters=create_address_parameters(
            address_type=CardanoAddressType.POINTER,
            address_n=parse_path(parameters["path"]),
            block_index=parameters["block_index"],
            tx_index=parameters["tx_index"],
            certificate_index=parameters["certificate_index"],
        ),
        protocol_magic=parameters["protocol_magic"],
        network_id=parameters["network_id"],
    )
    assert address == result["expected_address"]


@parametrize_using_common_fixtures("cardano/get_reward_address.json")
def test_cardano_get_reward_address(client, parameters, result):
    address = get_address(
        client,
        address_parameters=create_address_parameters(
            address_type=CardanoAddressType.REWARD,
            address_n=parse_path(parameters["path"]),
        ),
        protocol_magic=parameters["protocol_magic"],
        network_id=parameters["network_id"],
    )
    assert address == result["expected_address"]


@parametrize_using_common_fixtures(
    "cardano/get_public_key.json", "cardano/get_public_key.slip39.json"
)
def test_cardano_get_public_key(client, parameters, result):
    key = get_public_key(client, parse_path(parameters["path"]))

    assert key.node.public_key.hex() == result["public_key"]
    assert key.node.chain_code.hex() == result["chain_code"]
    assert key.xpub == result["public_key"] + result["chain_code"]
