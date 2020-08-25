import configparser
import sys

from device.t1 import TrezorOne
from device.tt import TrezorT


def main(model: str, file: str = None, reboot: bool = False):
    config = configparser.ConfigParser()
    config.read_file(open("hardware.cfg"))
    if model == "t1":
        model = TrezorOne
        port = config["t1"]["port"]
    elif model == "tt":
        model = TrezorT
        port = config["tt"]["port"]
    else:
        raise ValueError("Unknown Trezor model.")

    device = model(
        config["uhub"]["location"],
        config["uhub"]["arduino_serial"],
        port,
    )
    device.update_firmware(file)


if __name__ == "__main__":
    model = sys.argv[1]
    if len(sys.argv) == 3:
        main(model, file=sys.argv[2])
    else:
        main(model)
