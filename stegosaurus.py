#!/usr/bin/env python3

import argparse
import hashlib
import logging
import os
from collections import Counter

import coloredlogs
import numpy as np
from tqdm import tqdm
from PIL import Image

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
    except:
        log.exception(f"Unable to open image at path '{image_path}'.")
        return
    log.debug(f"Image '{image_path}' opened successfully.")

    return image


def open_file(file_path: str) -> str:
    if not os.path.exists(file_path):
        log.error(f"File '{file_path}' not found.")
        return

    log.info(f"{YELLOW}{ITALICS}Opening file '{file_path}'...{RESET}")

    try:
        with open(file_path, "r") as data_file:
            data = data_file.read()
    except:
        log.exception(f"Unable to parse data file '{file_path}'.")
        return

    log.debug(f"Data read from '{file_path}': {data}")
    return data


def save_image(image: Image, path: str) -> None:
    """
    Save an image.
    :param image: image to be saved
    :param path: path to save the image to
    :return: None
    """
    log.info(f"{YELLOW}{ITALICS}Saving image to '{path}'...{RESET}")
    try:
        image.save(path, "PNG")
    except:
        log.exception(f"Unable to save image to '{path}'.")
        return

    log.debug(f"Image saved to '{path}' successfully.")


def get_target_reds(image: Image, n=5) -> list:
    """
    Get the n most common pixel values.
    :param image: An image to analyze for common pixel values.
    :return: list of n most common pixels 
    """
    log.debug("Extracting reds from source image...")
    colors = Image.Image.getcolors(image, maxcolors=image.size[0] * image.size[1])

    # getcolors will return a tuple where the first value is the count of the
    # number of times the pixel appears, and the second will be the pixel tuple
    # (R, G, B). we want to get the second value (pixel tuple), then
    # get the first val (red)
    reds = [pixel[1][0] for pixel in colors]

    # sort the list by the most dominant reds
    most_common_reds = Counter(reds).most_common(n)

    # extract the raw red value (0-255)
    reds = [item[0] for item in most_common_reds]

    return reds


def str_to_bin(data: str) -> str:
    """
    Convert a UTF8 string to binary.
    :param data: string to convert
    :return: binary string (e.g. "10010001100101110110011011001101111")
    """
    log.debug(f"Attempting to convert {data} to binary...")
    try:
        bits = bin(int.from_bytes(data.encode("utf-8", "surrogatepass"), "big"))[2:]
        binary = bits.zfill(8 * ((len(bits) + 7) // 8))
    except:
        log.exception(f"Unable to convert {data}.")
        return

    log.debug(f"{data} = {binary}")
    return binary


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
    except:
        log.exception(f"Unable to convert {bits}.")
        return

    log.debug(f"{bits} = {data}")
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
    except UnicodeDecodeError:
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


def encode_message(image: Image, data: str, target_reds: list) -> Image:
    """
    Encode a message into an image.
    :param image: image to be encoded into
    :param data: string data to be encoded into the image
    :param target_reds: most common red values that will serve as the indexes
        for data encoding
    :return: new image with data encoded inside
    """
    log.info(f"{YELLOW}{ITALICS}Encoding data...{RESET}")

    # get an MD5 hash of our data
    data_hash = hash_str(data)
    log.debug(f"Hash of '{data}' is {data_hash} (length: {len(data_hash)})")

    # create new image & pixel map
    new_image = image.copy()

    width, height = image.size
    log.debug(f"Target reds are {target_reds}...")

    data_index = 0
    hash_index = 0

    # show a progress bar equivalent to all of the data we need to write
    # (128 bits for the hash + number of bits in our data)
    with tqdm(total=len(data) + 128, leave=False) as pbar:

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

                    # if we still have some of our hash to encode, then encode
                    # the current hash bit into the LSB of the green channel
                    if hash_index < len(data_hash):
                        pixel[1] = pixel[1] & ~1 | int(data_hash[hash_index])
                        hash_index += 1
                        pbar.update(1)

                    # set pixel in new image
                    new_image.putpixel((x, y), tuple(pixel))

                    # if we have written our hash and our data, then we are done
                    if data_index == len(data) and hash_index == len(data_hash):
                        return new_image

    # if we still have data to write, then we didn't have enough pixels
    # in the image to encode our data
    if data_index < len(data):
        log.error("Not enough bits to encode data within the image.")
        return


def decode_message(image: Image, target_reds: list) -> str:
    """
    Extract a message from an encoded image.
    :param image: image to have message extracted from
    :param target_reds: red values that will serve as the indexes for data 
        decoding, in order of dominance
    :return: binary data extracted from the image
    """
    log.info(f"{YELLOW}{ITALICS}Decoding data...{RESET}")

    extracted_bin = ""

    width, height = image.size

    # first, extract the hash. the hash will be encoded into the LSB
    # of the green channels for each pixel in the reds, in order of dominance
    data_hash = ""
    for x in range(0, width):
        for y in range(0, height):

            # an MD5 hash is 128 bits, so keep going until we get all 128
            if len(data_hash) < 128:

                # extract the pixel tuple (R, G, B)
                pixel = list(image.getpixel((x, y)))

                # if the R is in our target reds, extract the LSB
                if pixel[0] in target_reds:
                    extracted_bit = pixel[1] & 1
                    data_hash += str(extracted_bit)

            # we have our full hash, so we can break
            else:
                break

    log.debug(f"Extracted hash: {data_hash} (length: {len(data_hash)})")

    # show a progress bar equivalent to all of the pixels in the image
    # (worse case, we would have to check everything)
    with tqdm(total=width * height, leave=False) as pbar:

        for x in range(0, width):
            for y in range(0, height):

                # extract the pixel tuple (R, G, B)
                pixel = list(image.getpixel((x, y)))

                # if the R is in our target reds, extract the LSB
                if pixel[0] in target_reds:

                    extracted_bit = pixel[2] & 1
                    extracted_bin += str(extracted_bit)

                    # calculate the hash of the bit string we have extracted
                    # thus far. if it is equal to the hash we extracted earlier
                    # from the green channel, we have our full message
                    hash_of_extracted = hash_str(extracted_bin)

                    if str(hash_of_extracted) == str(data_hash):
                        log.debug(f"Found hash! Extracted binary is {extracted_bin}")
                        return extracted_bin

                pbar.update(1)
            pbar.update(1)

    # if we got this far, we didnt find data equivalent to our hash
    log.error("No data found.")
    return None


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Hide messages within image files.")
    group = parser.add_mutually_exclusive_group()

    group.add_argument("-e", "--encode", action="store_true", help="Encode a string.")
    group.add_argument("-d", "--decode", action="store_true", help="Decode an image.")

    parser.add_argument("-s", "--source", type=str, required=True, help="Source image.")
    parser.add_argument(
        "-o", "--out", type=str, default=None, help="Destination image."
    )
    parser.add_argument("-f", "--file", type=str, help="Filepath of data to hide.")
    parser.add_argument("--data", type=str, help="String to hide.")
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=False,
        help="Enable verbose logging.",
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

    image = open_image(args.source)
    if not image:
        exit(1)

    # we will use the reds in the image to encode our message, in order of
    # most dominant red value in the image (from 0-255)
    target_reds = get_target_reds(image, n=20)

    if args.encode:

        # if we are encoding, we can either use an input file or a raw string
        if args.file:
            data = open_file(args.file)

        elif args.data:
            data = args.data

        else:
            log.error("You must provide a string or file to encode. Exiting...")
            exit(1)

        # convert the raw message data to binary
        binary_data = str_to_bin(data)

        # encode the message in the image
        new_image = encode_message(image, binary_data, target_reds)

        # if we were able to actually encode everything, then save the image
        if new_image:

            save_image(new_image, args.out or f"new.{args.source}")

    elif args.decode:
        # extract the raw binary from the image
        decoded_binary = decode_message(image, target_reds)

        # convert the extracted binary to a UTF8 decoded string, if we pulled it
        if decoded_binary:
            decoded_message = bin_to_str(decoded_binary)

            log.info(f"{BOLD}{LIGHT_GRAY}Decoded message:{RESET} {decoded_message}")

    print(f"{GREEN}\n\n{ICON}{RESET}")
    log.info(f"{GREEN}All steps completed.{RESET}")
