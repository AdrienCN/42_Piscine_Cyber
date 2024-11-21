import argparse
import os
from PIL import Image, ExifTags
from pathlib import Path
from datetime import datetime


class Scorpion:
    def __init__(self, filepath_lst=[]):
        self.filepath_set = set()
        self.img_lst = []
        self.img_attr = [
            'filename',
            'format',
            'mode',
            'size',
            'width',
            'height',
            'palette',
            'is_animated']
        self.file_extension_set = (".jpg", ".jpeg", ".bmp", ".gif", ".png")

        self.attr_max_len = max(len(attr) for attr in self.img_attr)  # For pretty printing
        self.file_extension_check(filepath_lst)
        return

    def file_extension_check(self, filepath_lst=[]):
        for filepath in filepath_lst:
            filepath = Path(filepath)
            if filepath.suffix.lower() not in self.file_extension_set:
                print(f"File [{filepath.name}] not processed - File extension must be {self.file_extension_set}")
            else:
                self.filepath_set.add(filepath)
        return

    def extract_metadata(self):
        for filepath in self.filepath_set:
            try:
                img = Image.open(filepath)
                self.img_lst.append(img)
            except Exception as e:
                print(f"**Scorpion : Error : Exctracting {filepath} metadata\n{e}**")

        return

    def print_metadata(self):
        for img in self.img_lst:
            exif = img.getexif()

            print("---------------Img Info Start -----------------", end="")

            print("\n--Basic Attributes--")

            for attr in self.img_attr:
                value = getattr(img, attr, None)
                print(f"{attr.ljust(self.attr_max_len)}\t: {value}")

            print("\n--EXIF Attributes--")
            if exif:
                exif_max_length = max(len(ExifTags.TAGS.get(tag, tag)) for tag in exif.keys())
                for tag, value in exif.items():
                    tag_name = ExifTags.TAGS.get(tag, tag)  # Use human-readable tag names
                    print(f"{tag_name.ljust(exif_max_length)}\t: {value}")
            else:
                print("No EXIF found for this img")

            if getattr(exif, "DateTimeOriginal", None) is None:
                creation_time = os.path.getctime(img.filename)
                creation_time = datetime.fromtimestamp(creation_time).strftime('%Y-%m-%d %H:%M:%S')
                print(f"\nDateTimeOriginal : {creation_time}")
                print("---------------Img Info End  -----------------", end="\n\n")
        return


def main():

    parser = argparse.ArgumentParser(
         prog="scorpion",
         usage="python3 scorpion FILE_1 [FILE_N] ...",
         description="Process one or more image files. Outputs file EXIF & Metadata")
    parser.add_argument(
         "filepath",   # Name of the argument
         type=str,     # Expected type of each argusment
         nargs='+',    # Allows one or more values
         help="One or more paths to image files (.jpg, .jpeg, .bmp, .gif, .png)")
    args = parser.parse_args()

    scorpion = Scorpion(filepath_lst=args.filepath)
    scorpion.extract_metadata()
    scorpion.print_metadata()

    return


if __name__ == "__main__":
    main()
