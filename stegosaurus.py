#!/usr/bin/env python3

import argparse
import logging
import os

import coloredlogs
import numpy as np
from PIL import Image

log = logging.getLogger(__name__)
coloredlogs.install(
    level="INFO", fmt="%(message)s", logger=log
)


def open_image(image_path: str) -> Image:
    """
    Open an image.
    :param image_path: path to the image to be opened
    :return: Image object from path
    """
    if not os.path.exists(image_path):
        log.error(f"Image '{args.source}' not found.")
        return

    log.info(f"Opening image '{image_path}'...'")
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
    log.debug(f"Creating new image of size {x}, {y}...")
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


def int_to_bin(rgb: tuple) -> tuple:
    """
    Convert an integer tuple to a binary (string) tuple.
    :param rgb: An integer tuple (e.g. (220, 110, 96))
    :return: A string tuple (e.g. ("00101010", "11101011", "00010110"))
    """
    r, g, b = rgb
    return ('{0:08b}'.format(r),
            '{0:08b}'.format(g),
            '{0:08b}'.format(b))


def bin_to_int(rgb: tuple) -> tuple:
    """
    Convert a binary (string) tuple to an integer tuple.
    :param rgb: A string tuple (e.g. ("00101010", "11101011", "00010110"))
    :return: Return an int tuple (e.g. (220, 110, 96))
    """
    r, g, b = rgb
    return (int(r, 2),
            int(g, 2),
            int(b, 2))


def encode_message(image: Image, data:str) -> Image:
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
            pixel = list(image.getpixel((x, y)))

            for n in range(0, 3):
                if i < len(data):
                    pixel[n] = pixel[n] & ~1 | int(data[i])
                    i += 1

            # set pixel in new image
            new_image.putpixel((x,y), tuple(pixel))

    return new_image


def decode_message(image: Image) -> str:
    """
    Extract a message from an encoded image.
    :param image: image to have message extracted from
    :return: string extracted from the image
    """
    extracted_bin = []

    width, height = image.size
    for x in range(0, width):
        for y in range(0, height):
            pixel = list(image.getpixel((x, y)))

            for n in range(0,3):
                extracted_bin.append(pixel[n] & 1)

    data = "".join([str(x) for x in extracted_bin])
    return data


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Hide messages within image files.")
    group = parser.add_mutually_exclusive_group()
   
    group.add_argument("-e", "--encode", action="store_true", help="Encode a string.")
    group.add_argument("-d", "--decode", action="store_true", help="Decode an image.")
   
    parser.add_argument("-s", "--source", type=str, required=True, help="Source image")
    parser.add_argument(
        "-o", "--out", type=str, default=None, help="Destination image"
    )
    parser.add_argument(
        "--data", type=str, help="String to hide"
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=False,
        help="Enable verbose logging.",
    )

    args = parser.parse_args()

    if args.verbose:
        coloredlogs.install(
            level="DEBUG",
            fmt="[%(asctime)s] [%(levelname)-8s] %(message)s",
            logger=log,
        )

    image = open_image(args.source)
    if not image:
        exit(1)

    common_pixels = get_common_pixels(image)
    
    if args.encode:
        binary_data = ''.join(format(ord(x), 'b') for x in args.data)
        log.debug(f"Data: {args.data} = {binary_data}")

        new_image = encode_message(image, binary_data)

        save_image(new_image, args.destination or f"new.{args.source}")
    
    elif args.decode:
        decoded_message = decode_message(image)
        log.info(f"Decoded message: {decoded_message}")


    log.info("All steps completed.")
