import configparser
import sys, os, time

from device.t1 import TrezorOne
from device.tt import TrezorT


def main(model: str, file: str = None):
    config = configparser.ConfigParser()
    config.read_file(open("hardware.cfg"))

    t1 = TrezorOne(
        config["uhub"]["location"],
        config["uhub"]["arduino_serial"],
        config["t1"]["port"],
    )
    tt = TrezorT(
        config["uhub"]["location"],
        config["uhub"]["arduino_serial"],
        config["tt"]["port"],
    )

    print("Turning off everything")
    turn_off_everything(config["uhub"]["location"])

    if model == "t1":
        print("Starting T1")
        t1.turn_on_arduino()
        t1.power_on()
        t1.update_firmware(file)
    elif model == "tt":
        print("Starting TT")
        tt.power_on()
        tt.update_firmware(file)
    else:
        raise ValueError("Unknown Trezor model.")


def turn_off_everything(uhub_location: str):
    for p in range(1, 5):
        os.system(
            "uhubctl -l {} -p {} -r 100 -a off".format(
                uhub_location, p
            )
        )


if __name__ == "__main__":
    model = sys.argv[1]
    if len(sys.argv) == 3:
        main(model, file=sys.argv[2])
    else:
        main(model)
