#!/usr/bin/env python3

"""
stegosaurus.py
Encode hidden messages into image files.
"""

"""
todo:
    - encode into video frames
    --- encryption option
    - compression
    - use the green channel past 128 bits
    - split code up into different files
    - absolute vs relative image path
    - setup pyinstaller compilation for static binary
    - guess filetype of extracted file
    - optional encoded header with instructional message (?)
    - unit tests
"""

import argparse
import binascii
import hashlib
import logging
import mimetypes
import os
import zlib
from collections import Counter
from datetime import datetime

import coloredlogs
import magic
import numpy as np
from PIL import Image
from tqdm import tqdm

log = logging.getLogger(__name__)
coloredlogs.install(level="INFO", fmt="%(message)s", logger=log)

BOLD = "\033[1m"
GREEN = "\033[1;32m"
LIGHT_GRAY = "\033[32m"
ITALICS = "\033[3m"
YELLOW = "\033[1;33m"
RESET = "\033[0m"

ICON = "\
                ___     \n\
               / *_)    \n\
              / /       \n\
     _/\/\/\_/ /        \n\
   _|         /         \n\
 _|  (  | (  |          \n\
/__.-'|_|--|_|            \
"


def open_image(image_path: str) -> Image:
    """
    Open an image.
    :param image_path: path to the image to be opened
    :return: Image object from path
    """
    if not os.path.exists(image_path):
        log.error(f"Image '{args.source}' not found.")
        return

    log.info(f"{YELLOW}{ITALICS}Opening image '{image_path}'...{RESET}")
    try:
        image = Image.open(image_path, "r")

    except IOError:
        log.exception(f"Unable to open image at path '{image_path}'.")
        return

    log.debug(f"Image '{image_path}' opened successfully.")

    return image


def save_image(image: Image, image_path: str) -> None:
    """
    Save an image.
    :param image: image to be saved
    :param path: path to save the image to
    :return: None
    """
    log.info(f"{YELLOW}{ITALICS}Saving image to '{image_path}'...{RESET}")
    try:
        image.save(image_path, "PNG")

    except IOError:
        log.exception(f"Unable to save image to '{image_path}'.")
        return

    log.debug(f"Image saved to '{image_path}' successfully.")


def open_file(file_path:str) ->str:
    """
    Open a file at a given filepath.
    :param file_path: path to file
    :return: data read from input file as a string
    """
    if os.path.isfile(file_path):
            log.debug(f"Opening file at path {file_path}...")
            try:
                with open(file_path, "r") as f:
                    return f.read()

            except OSError as e:
                log.error(f"Error encountered opening '{file_path}'. Error output: {e}")

    else:
        log.error(f"'{file_path}' does not exist.")
        return


def save_file(data: str, file_path: str) -> None:
    """
    Save decoded data to a file.
    :param data: data to be written to the file
    :param file_path: name of the file to be created
    :return: None
    """
    log.debug(f"Writing output data to '{file_path}'...")
    try:
        with open(file_path, "w") as output_file:
            output_file.write(data)


    except OSError:
        log.error(f"Unable to write data to '{file_path}'")


def compress_data(data:str) -> str:
    """
    Compress a given data input, returning a binary representation.
    :param data: input data string
    :return: binary compressed data string
    """

    # first, encode the data into bytes
    try:
        encoded_data = data.encode()
    except UnicodeEncodeError:
        log.exception(f"Unable to encode {data}.")
        return

    # compress the encoded data into hex
    try:
        compressed = zlib.compress(encoded_data)
    except zlib.error as e:
        log.error(f"Error encountered compressing data. Error output: {e}")
        return

    # convert the hex data into a binary string
    try:
        bits = bin(int.from_bytes(compressed, byteorder="big"))[2:]
    except ValueError as e:
        log.error(f"ValueError hit converting bytes to binary. Error output: {e}")
        return

    return bits


def decompress_data(data:str) -> str:
    """
    Compress a given data input, returning a decoded representation.
    :param data: compressed binary data string
    :return: decoded data
    """

    # first convert the binary data into a byte array
    v = int(data, 2)
    b = bytearray()
    while v:
        b.append(v & 0xFF)
        v >>= 8

    byte_array = bytes(b[::-1])

    # now, decompress the byte array
    try:
        decompressed = zlib.decompress(byte_array)
    except zlib.error as e:
        log.error(f"Error encountered decompressing data. Error output: {e}")
        return

    # convert the decompressed data from hex to a UTF decoded string
    try:
        decompressed_data = decompressed.decode()
    except ValueError as e:
        log.error(f"ValueError hit decoding decompresseed data. Error output: {e}")
        return

    return decompressed_data


def get_target_reds(image: Image) -> list:
    """
    Get the n most common pixel values.
    :param image: An image to analyze for common pixel values.
    :return: list of n most common pixels 
    """
    log.debug("Determining target reds from source image...")
    colors = Image.Image.getcolors(image, maxcolors=image.size[0] * image.size[1])

    # getcolors will return a tuple where the first value is the count of the
    # number of times the pixel appears, and the second will be the pixel tuple
    # (R, G, B). we want to get the second value (pixel tuple), then
    # get the first val (red)
    reds = [pixel[1][0] for pixel in colors]

    # find all of the red values from 0-255 that are not in our image
    not_in_reds = [r for r in range(0, 255) if r not in set(reds)]

    # we will use the top 1/3 of the most common pixel values in order
    # to encode our data
    target_count = int((len(set(reds)) - len(not_in_reds)) / 3)

    # sort the list by the most dominant reds
    most_common_reds = Counter(reds).most_common(target_count)

    # extract the raw red value (0-255)
    reds = [item[0] for item in most_common_reds]

    # calculate the total number of pixels we have to encode data into
    total_pixel_ct = 0
    for color in colors:
        if color[1][0] in reds:
            total_pixel_ct += color[0]

    log.debug(f"Total available pixels: {total_pixel_ct}")

    return reds, total_pixel_ct


def get_bitstream(datastream: str, is_file: bool = False):
    """
    Convert a datastream (either a file, or raw text) into a binary string
    of bits.
    :param datastream: data source, either a filepath or raw text
    :param is_file: specification of whether datastream represents a file
        or raw text
    :return: raw string of binary data (ex. 1010110101001010)
    """
    bitstream = ""

    if is_file:
        if os.path.isfile(datastream):
            with open(datastream, "rb") as f:
                try:
                    for byte in iter(lambda: f.read(1), b""):
                        bitstream += "{0:08b}".format(ord(byte))

                except:
                    log.error("Unable to decode datastream to binary.")
                    return

        else:
            log.error(f"'{datastream}' does not exist.")

    else:
        bitstream = "".join(format(ord(i),'b').zfill(8) for i in datastream)

    return bitstream


def bin_to_str(bits: str) -> str:
    """
    Convert a binary string to a UTF8 string.
    :param bits: binary string to convert
    :return: UTF8 encoded string (e.g. "hello")
    """
    log.debug(f"Attempting to convert extracted binary to UTF8...")
    n = int(bits, 2)
    try:
        data = (
            n.to_bytes((n.bit_length() + 7) // 8, "big").decode("utf8", "surrogatepass")
            or "\0"
        )

    except UnicodeDecodeError:
        log.error(f"Unable to convert data to a UTF8 string.")
        return

    return data


def hash_str(data: str) -> str:
    """
    Generate a binary representation of an MD5 hash of a string.
    :param data: data to be hashed
    :return: binary MD5 hash
    """
    # encode our data into a byte representation
    try:
        encoded_data = data.encode()

    except UnicodeEncodeError:
        log.exception(f"Unable to encode '{data}'.")
        return

    # get the MD5 hash of our data, which will be in hex
    try:
        hex_hash = hashlib.md5(encoded_data).hexdigest()

    except:
        log.exception(f"Unable to calculate the hash of '{data}'.")
        return

    # convert our hex hash into binary
    binary_of_hash = bin(int(hex_hash, 16))[2:]

    # pad the right with zeroes if we are not at 128 bits
    while len(binary_of_hash) != 128:
        binary_of_hash += "0"

    return str(binary_of_hash)


def encode_message(
    image: Image, data: str, target_reds: list, total_pixel_ct: int
) -> Image:
    """
    Encode a message into an image.
    :param image: image to be encoded into
    :param data: string data to be encoded into the image
    :param target_reds: most common red values that will serve as the indexes
        for data encoding
    :param total_pixel_ct: total number of pixels in the image that we have
        for data encoding
    :return: new image with data encoded inside
    """
    log.info(f"{YELLOW}{ITALICS}Encoding data...{RESET}")
    log.debug(f"Target reds are {target_reds}...")

    # calculate the hash of the total data length
    hash_of_length = hash_str(str(len(data)))
    log.debug(
        f"Total data length: {len(data)} bits, hash: {hash_of_length} ({len(hash_of_length)} bits)"
    )

    # calculate the hash of the data
    hash_of_data = hash_str(data)
    log.debug(f"Data hash: {hash_of_data} ({len(hash_of_data)} bits)")

    # encode the total size hash as well as the data hash into the first
    # 256 bits of the green channel
    header = hash_of_length + hash_of_data

    # create new image & pixel map
    new_image = image.copy()

    width, height = image.size
    data_index = 0
    header_index = 0

    # show a progress bar equivalent to all of the data we need to write
    with tqdm(total=len(data) + len(header), leave=False) as pbar:

        for x in range(width):
            for y in range(height):

                # extract the pixel tuple (R, G, B)
                pixel = list(image.getpixel((x, y)))

                # if the R is in our target reds
                if pixel[0] in target_reds:

                    # if we still have data to encode, then encode the current
                    # data bit into the LSB of the blue channel
                    if data_index < len(data):

                        # if the data bit is 1, set the image bit to 1
                        # if the data bit is 0, keep it at 0
                        pixel[2] = pixel[2] & ~1 | int(data[data_index])
                        data_index += 1
                        pbar.update(1)

                    # if we still have some of our header to encode, then encode
                    # the current header bit into the LSB of the green channel
                    if header_index < len(header):
                        pixel[1] = pixel[1] & ~1 | int(header[header_index])
                        header_index += 1
                        pbar.update(1)

                    # set pixel in new image
                    new_image.putpixel((x, y), tuple(pixel))

                    # if we have written our header and our data, then we are done
                    if data_index == len(data) and header_index == len(header):
                        return new_image

    # if we still have data to write, then we didn't have enough pixels
    # in the image to encode our data
    if data_index < len(data) or header_index < len(header):
        log.error("Not enough bits to encode data within the image.")
        return


def decode_message(image: Image, target_reds: list, total_pixel_ct: int) -> str:
    """
    Extract a message from an encoded image.
    :param image: image to have message extracted from
    :param target_reds: red values that will serve as the indexes for data 
        decoding, in order of dominance
    :param total_pixel_ct: total number of pixels in the image that we have
        for data encoding
    :return: binary data extracted from the image
    """
    log.info(f"{YELLOW}{ITALICS}Decoding data...{RESET}")
    log.debug(f"Target reds are {target_reds}...")

    width, height = image.size

    # first, extract the header. the header will be encoded into the LSB
    # of the green channels for each pixel in the reds, in order of dominance
    header = ""
    for x in range(0, width):
        for y in range(0, height):

            if len(header) < 256:

                # extract the pixel tuple (R, G, B)
                pixel = list(image.getpixel((x, y)))

                # if the R is in our target reds, extract the LSB
                if pixel[0] in target_reds:
                    extracted_bit = pixel[1] & 1
                    header += str(extracted_bit)

            # we have our full header, so we can break
            else:
                break

        if len(header) == 256:
            break

    size_hash = header[:128]
    data_hash = header[128:]

    log.debug(f"Extracted size: {size_hash} (length: {len(size_hash)} bits)")
    log.debug(f"Extracted data hash: {data_hash} (length: {len(data_hash)} bits)")

    # iterate a counter, calculating the hash of the counter until the hash
    # of the counter matches the hash of the data length. once it matches,
    # we will know exactly how many bits we have to extract from the image
    # until we have our complete message.
    total_data_length = 0
    index_hash = hash_str(str(total_data_length))

    while index_hash != size_hash:
        total_data_length += 1
        index_hash = hash_str(str(total_data_length))

    log.debug(f"Total encoded data length: {total_data_length} bits")

    extracted_bin = ""

    # show a progress bar equivalent to total encoded data length
    with tqdm(total=total_data_length, leave=False) as pbar:

        for x in range(0, width):
            for y in range(0, height):

                # if the length of our extracted binary matches,
                # then we're done
                if len(extracted_bin) >= total_data_length:

                    # ensure that the final extracted data matches the hash
                    # we extracted from the header
                    hash_of_extracted_binary = hash_str(extracted_bin)
                    log.debug("Performing data validation checks...")

                    if hash_of_extracted_binary == data_hash:
                        log.debug("Data passed all verification checks.")
                        return extracted_bin

                    else:
                        log.error("Extracted data failed verification checks.")
                        return None

                # extract the pixel tuple (R, G, B)
                pixel = list(image.getpixel((x, y)))

                # if the R is in our target reds, extract the LSB
                if pixel[0] in target_reds:

                    extracted_bit = pixel[2] & 1
                    extracted_bin += str(extracted_bit)
                    pbar.update(1)

    # if we got this far, we didnt find data equivalent to our hash
    log.error("No data found.")
    return None


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Hide messages within image files.")
    group = parser.add_mutually_exclusive_group()

    group.add_argument("-e", "--encode", action="store_true", help="Encode a string.")
    group.add_argument("-d", "--decode", action="store_true", help="Decode an image.")
    parser.add_argument(
        "-c",
        "--compress",
        action="store_true",
        default=False,
        help="Compress input data before encoding.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=False,
        help="Enable verbose logging.",
    )

    parser.add_argument(
        "-s",
        "--source",
        type=str,
        metavar="SOURCE IMAGE",
        required=True,
        help="Source image.",
    )
    parser.add_argument(
        "-o",
        "--out",
        type=str,
        metavar="OUTPUT FILE",
        default=None,
        help="Destination file.",
    )
    parser.add_argument(
        "-f", "--file", type=str, metavar="INPUT FILE", help="Filepath of data to hide."
    )
    parser.add_argument(
        "--input", type=str, metavar="INPUT STRING", help="String to hide."
    )

    args = parser.parse_args()

    if not args.encode and not args.decode:
        log.error("You must choose to encode or decode an image. Exiting...")
        parser.print_help()
        exit(1)

    # if we threw the verbose flag, then enable debug logging
    if args.verbose:
        coloredlogs.install(
            level="DEBUG", fmt="[%(asctime)s] [%(levelname)-8s] %(message)s", logger=log
        )

    start_time = datetime.now()

    image = open_image(args.source)
    if not image:
        exit(1)

    # we will use the reds in the image to encode our message, in order of
    # most dominant red value in the image (from 0-255)
    target_reds, total_pixel_ct = get_target_reds(image)

    if args.encode:

        # if we are encoding, we can either use an input file or a raw string
        if args.file:
            data = open_file(args.file)

        elif args.input:
            data = args.input

        else:
            log.error("You must provide a string or file to encode. Exiting...")
            exit(1)

        
        compressed_data = compress_data(data)

        # we can only encode as many bits as there are pixels, so ensure we
        # can pull this shindig off with what we have
        if len(compressed_data) > total_pixel_ct:
            log.error(
                f"Not enough pixels to encode inputted data into '{args.source}'. "
            )
            log.error(
                f"Total data length is {len(compressed_data)} bits, but only "
                f"{total_pixel_ct} encodable bits are available. Try a larger image."
            )
            exit(1)

        # encode the message in the image
        new_image = encode_message(image, compressed_data, target_reds, total_pixel_ct)

        # if we were able to actually encode everything, then save the image
        if new_image:
            outfile = args.out or "encoded." + os.path.basename(args.source)
            save_image(new_image, outfile)

    elif args.decode:

        # extract the raw binary from the image
        extracted_binary = decode_message(image, target_reds, total_pixel_ct)

        if extracted_binary:

            decompressed_data = decompress_data(extracted_binary)

            if decompressed_data:

                # if we specified an out file, then just save it
                if args.out:
                    save_file(decompressed_data, args.out)

                else:
                    log.info(
                        f"{BOLD}{LIGHT_GRAY}Decoded message:{RESET}\n\n {decompressed_data}"
                    )


    print(f"{GREEN}\n\n{ICON}{RESET}")
    log.debug(f"Total elapsed time: {datetime.now() - start_time}")
    log.info(f"{GREEN}All steps completed.{RESET}")
