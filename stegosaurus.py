#!/usr/bin/env python3

import argparse
import binascii
import logging
import os

import hashlib
import coloredlogs
import numpy as np
from PIL import Image
import matplotlib.pyplot as plt
from skimage import feature
from skimage.color import rgb2gray
import time
from collections import Counter, deque

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

    log.info(f"{YELLOW}{ITALICS}Opening image '{image_path}'...'{RESET}")
    try:
        image = Image.open(image_path, "r")
    except:
        log.exception(f"Unable to open image at path '{image_path}'.")
        return
    log.debug(f"Image '{image_path}' opened successfully.")

    return image


def save_image(image: Image, path: str) -> None:
    """
    Save an image.
    :param image: image to be saved
    :param path: path to save the image to
    :return: None
    """
    log.info(f"Saving image to '{path}'...")
    try:
        image.save(path, "png")
    except:
        log.exception(f"Unable to save image to '{path}'.")
        return

    log.debug(f"Image saved to '{path}' successfully. ")


def create_image(x: int, y: int) -> Image:
    """
    Create a new image with the given size.
    :param x: image width
    :param y: image height
    :return: new image with dimensions x * y
    """
    log.debug(f"Creating new image of size {x} x {y}...")
    try:
        image = Image.new("RGB", (x, y))
    except:
        log.exception("Unable to create new image.")
        return

    return image


def get_pixel(image: Image, x: int, y: int) -> tuple:
    """
    Get a given pixel from an image.
    :param image: an image to get a pixel from
    :param x: x coordinate
    :param y: y coordinate
    :return: A string tuple (e.g. ("00101010", "11101011", "00010110"))
    """
    width, height = image.size
    if x > width or y > height:
        log.debug(f"Pixel coordinates {x}, {y} out of bounds ({width}, {height}).")
        return None

    pixel = image.getpixel((x, y))
    log.debug(f"Pixel at {x}, {y} is {pixel}.")
    return pixel


def get_common_reds(image: Image, n: int = 5) -> list:
    """
    Get the n most common pixel values.
    :param image: An image to analyze for common pixel values.
    :param n: the number of common pixels to scan for (default 5)
    :return: list of n most common pixels 
    """
    colors = Image.Image.getcolors(image, maxcolors=image.size[0] * image.size[1])

    # get the first value (pixel tuple), then get the first val (red)
    reds = [pixel[1][0] for pixel in colors]

    occ_count = Counter(reds)
    most_common_reds = occ_count.most_common(n)
    reds = [item[0] for item in most_common_reds]
    log.debug(f"Most common reds: {reds}")

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


def hash_str(data):
    hash_object = hashlib.md5(data.encode())
    hex_hash = hash_object.hexdigest()
    binary_of_hash = bin(int(hex_hash, 16))[2:]

    #log.debug(f"hash of '{data}': {binary_of_hash} (length: {len(binary_of_hash)})")
    while len(binary_of_hash) != 128:
        binary_of_hash += "0"

    return str(binary_of_hash)


def encode_message(image: Image, data: str, target_reds) -> Image:
    """
    Encode a message into an image.
    :param image: image to be encoded into
    :param data: string data to be encoded into the image
    :return: new image with data encoded inside
    """
    data_hash = hash_str(data)
    log.debug(f"Hash of '{data}' is {data_hash} (length: {len(data_hash)})")

    # create new image & pixel map
    new_image = image.copy()

    width, height = image.size
    log.debug(f"Target reds are {target_reds}...")

    data_index = 0
    hash_index = 0
    for x in range(width):
        for y in range(height):
            # start in the top left and work through the image
            pixel = list(image.getpixel((x, y)))

            if pixel[0] in target_reds:

                # if we still have data to encode
                if data_index < len(data):

                    # if the data bit is 1, set the image bit to 1
                    # if the data bit is 0, keep it at 0
                    pixel[2] = pixel[2] & ~1 | int(data[data_index])
                    data_index += 1

                # if we still have some of our hash to encode
                if hash_index < len(data_hash):
                    pixel[1] = pixel[1] & ~1 | int(data_hash[hash_index])
                    hash_index += 1

                # set pixel in new image
                new_image.putpixel((x, y), tuple(pixel))

    return new_image


def decode_message(image: Image, target_reds) -> str:
    """
    Extract a message from an encoded image.
    :param image: image to have message extracted from
    :return: string extracted from the image
    """
    extracted_bin = ""
    log.debug(f"Target reds are {target_reds}...")

    width, height = image.size

    # first, extract the hash
    data_hash = ""
    for x in range(0, width):
        for y in range(0, height):

            if len(data_hash) < 128:

                pixel = list(image.getpixel((x,y)))

                if pixel[0] in target_reds:
                    extracted_bit = pixel[1] & 1
                    data_hash += str(extracted_bit)
            else:
                break

    log.debug(f"Extracted hash: {data_hash}, length: {len(data_hash)}")

    for x in range(0, width):
        for y in range(0, height):
            # go through each pixel of the image
            pixel = list(image.getpixel((x, y)))

            if pixel[0] in target_reds:
                extracted_bit = pixel[2] & 1
                extracted_bin += str(extracted_bit)

                hash_of_extracted = hash_str(extracted_bin)
                
                if str(hash_of_extracted) == str(data_hash):
                    log.debug(f"Found hash!")
                    return extracted_bin

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

    if args.verbose:
        coloredlogs.install(
            level="DEBUG", fmt="[%(asctime)s] [%(levelname)-8s] %(message)s", logger=log
        )

    image = open_image(args.source)
    if not image:
        exit(1)

    common_reds = get_common_reds(image)

    if args.encode:
        if not args.data:
            log.error("You must provide a string to encode. Exiting...")
            exit(1)

        # convert the raw message data to binary
        binary_data = str_to_bin(args.data)

        # encode the message in the image
        new_image = encode_message(image, binary_data, common_reds)

        # save the new image to disk
        save_image(new_image, args.out or f"new.{args.source}")

    elif args.decode:
        # extract the raw binary from the image
        decoded_binary = decode_message(image, common_reds)

        # convert the extracted binary to a UTF8 decoded string
        if decoded_binary:
            decoded_message = bin_to_str(decoded_binary)

            log.info(f"{BOLD}{LIGHT_GRAY}Decoded message:{RESET} {decoded_message}")

    print(f"\n\n{ICON}")
    log.info(f"{GREEN}All steps completed.{RESET}")
