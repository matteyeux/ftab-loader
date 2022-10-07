import struct
from binaryninja.binaryview import (
    BinaryView,
    BinaryReader,
)
from binaryninja.enums import Endianness
from binaryninja import mainthread
from binaryninjaui import UIContext
from binaryninja import interaction


class RKOSView(BinaryView):
    name = "RKOS"
    long_name = "RKOS loader"

    def __init__(self, data):
        self.reader = BinaryReader(data, Endianness.LittleEndian)
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        self.data = data

    def init(self):
        tags = self.list_tags()

        print(f"Found {len(tags)} tags")

        choice = interaction.get_choice_input(
            "RKOS app", "choices", list(tags.keys())
        )
        if choice is not None:
            tag_name = list(tags.keys())[choice]
            fname = self.extract(tag_name, tags[tag_name])

            mainthread.execute_on_main_thread_and_wait(
                lambda: UIContext.allContexts()[0].openFilename(fname)
            )
            return True
        return False

    @classmethod
    def is_valid_for_data(self, data):
        if data.read(0x20, 8) == b"rkosftab":
            return True
        else:
            return False

    def list_tags(self) -> dict:
        tags = {}
        for i in range(0x30, len(self.data), 16):
            try:
                tag = self.data.read(i, 4).decode()
            except UnicodeDecodeError:
                break

            offset = struct.unpack('<i', self.data.read(i+4, 4))[0]
            sz = struct.unpack('<i', self.data.read(i+8, 4))[0]
            tags[tag] = {'offset': offset, 'size': sz}
            print(tag, hex(offset), hex(sz))

        return tags

    def extract(self, name, tag):
        filename = self.set_output_filename(name)
        open(filename, 'wb').write(self.data.read(tag['offset'], tag['size']))
        return filename

    def set_output_filename(self, out_name) -> str:
        """Get the path to save file."""
        filename = self.file.original_filename
        out = filename.replace(filename.split('/')[-1], out_name)
        return out
