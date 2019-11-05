#!/usr/bin/env python3

import argparse
import binascii
import logging
import os

import coloredlogs
import numpy as np
from PIL import Image

log = logging.getLogger(__name__)
coloredlogs.install(level="INFO", fmt="%(message)s", logger=log)

BOLD = '\033[1m'
GREEN = "\033[1;32m"
LIGHT_GRAY = '\033[32m'
ITALICS = '\033[3m'
YELLOW = '\033[1;33m'
RESET = '\033[0m'

ICON = "                ___ \n\
               / *_) \n\
              / / \n\
     _/\/\/\_/ / \n\
   _|         / \n\
 _|  (  | (  | \n\
/__.-'|_|--|_|" 

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


def get_common_pixels(image: Image, n: int = 5) -> list:
    """
    Get the n most common pixel values.
    :param image: An image to analyze for common pixel values.
    :param n: the number of common pixels to scan for (default 5)
    :return: list of n most common pixels 
    """
    colors = Image.Image.getcolors(image, maxcolors=image.size[0] * image.size[1])

    # frequency: pixel value (0-255)
    top_five = sorted(colors, key=lambda t: t[0], reverse=True)[:n]
    log.debug(f"Top {n} most common pixel values: {top_five}")
    return top_five


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
    log.debug(f"Attempting to convert {bits} to UTF8...")
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


def encode_message(image: Image, data: str) -> Image:
    """
    Encode a message into an image.
    :param image: image to be encoded into
    :param data: string data to be encoded into the image
    :return: new image with data encoded inside
    """
    width, height = image.size

    # create new image & pixel map
    new_image = create_image(width, height)

    i = 0
    for x in range(width):
        for y in range(height):
            # start in the top left and work through the image
            pixel = list(image.getpixel((x, y)))

            # for each RGB value of the pixel
            for n in range(0, 3):

                # if we still have data to encode
                if i < len(data):

                    # if the data bit is 1, set the image bit to 1
                    # if the data bit is 0, keep it at 0
                    pixel[n] = pixel[n] & ~1 | int(data[i])
                    i += 1

            # set pixel in new image
            new_image.putpixel((x, y), tuple(pixel))

    # write the data length to the index pixel of the image
    log.debug(f"Writing data length {len(data)} to pixel (0,0)...")
    new_image.putpixel((image.width - 1, image.height - 1), tuple([len(data), 0, 0]))
    return new_image


def decode_message(image: Image) -> str:
    """
    Extract a message from an encoded image.
    :param image: image to have message extracted from
    :return: string extracted from the image
    """
    extracted_bin = []

    # get the index pixel that contains the length of the encoded message
    index_pixel = list(image.getpixel((image.width - 1, image.height - 1)))
    data_length = index_pixel[0]
    log.debug(f"Data length recorded at pixel (0, 0) is {data_length}.")

    width, height = image.size
    for x in range(0, width):
        for y in range(0, height):
            # go through each pixel of the image
            pixel = list(image.getpixel((x, y)))

            # for each RGB value of the pixel
            for n in range(0, 3):

                # if we still have data in the image, pull the LSB
                if len(extracted_bin) < data_length:
                    extracted_bin.append(pixel[n] & 1)

    data = "".join([str(x) for x in extracted_bin])
    log.debug(f"Extracted binary: {data}")

    return data


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Hide messages within image files.")
    group = parser.add_mutually_exclusive_group()

    group.add_argument("-e", "--encode", action="store_true", help="Encode a string.")
    group.add_argument("-d", "--decode", action="store_true", help="Decode an image.")

    parser.add_argument("-s", "--source", type=str, required=True, help="Source image.")
    parser.add_argument("-o", "--out", type=str, default=None, help="Destination image.")
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

    common_pixels = get_common_pixels(image)

    if args.encode:
        if not args.data:
            log.error("You must provide a string to encode. Exiting...")
            exit(1)

        # convert the raw message data to binary
        binary_data = str_to_bin(args.data)

        # encode the message in the image
        new_image = encode_message(image, binary_data)

        # save the new image to disk
        save_image(new_image, args.out or f"new.{args.source}")

    elif args.decode:
        # extract the raw binary from the image
        decoded_binary = decode_message(image)

        # convert the extracted binary to a UTF8 decoded string
        decoded_message = bin_to_str(decoded_binary)

        log.info(f"{BOLD}{LIGHT_GRAY}Decoded message:{RESET} {decoded_message}")
    
    print(f"\n\n{ICON}")
    log.info(f"{GREEN}All steps completed.{RESET}")
