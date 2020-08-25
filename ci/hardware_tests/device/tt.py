from .device import Device


class TrezorT(Device):
    def update_firmware(self, file=None):
        if not file:
            raise ValueError("Uploading production firmware will replace the bootloader, it is not allowed!")

        # we need to reboot the device to get into the bootloader again
        self.reboot()

        self.wait(5)
        print("[software] Updating the firmware to {}".format(file))
        self.run_trezorctl("firmware-update -s -f {} &".format(file))

        # upgrading to 2.3.2 toook about 80s - let's give a bit extra to be sure
        self.wait(90)
        self.check_version()
