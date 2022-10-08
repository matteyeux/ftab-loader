from binaryninja.binaryview import BinaryView
from binaryninja import mainthread
from binaryninjaui import UIContext
from binaryninja import interaction


class FtabView(BinaryView):
    name = "Ftab"
    long_name = "Ftab Loader"

    def __init__(self, data):
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        self.data = data

    def init(self) -> bool:
        tags = self.list_tags()
        print(f"Found {len(tags)} tags")

        choice = interaction.get_choice_input(
            "Ftab modules", "choices", list(tags.keys())
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
    def is_valid_for_data(self, data: BinaryView) -> bool:
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

            offset = self.data.read_int(i + 4, 4)
            sz = self.data.read_int(i + 8, 4)
            tags[tag] = {'offset': offset, 'size': sz}

            print(f"tag : {tag}\n\toffset : {offset:#x}\n\tsize : {sz:#x}")
        return tags

    def extract(self, name: str, tag: dict) -> str:
        filename = self.set_output_filename(name)
        open(filename, 'wb').write(self.data.read(tag['offset'], tag['size']))
        return filename

    def set_output_filename(self, out_name: str) -> str:
        """Get the path to save file."""
        filename = self.file.original_filename
        out = filename.replace(filename.split('/')[-1], out_name)
        return out

