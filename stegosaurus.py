#!/usr/bin/env python3

import argparse
import logging
import os

import coloredlogs
import numpy as np
import png
from PIL import Image

log = logging.getLogger(__name__)
coloredlogs.install(level="INFO", logger=log)


def open_image(path):
    """Open an Image."""
    log.debug(f"Opening image at path '{path}'...")
    try:
        newImage = Image.open(path, "r").convert("L")
    except:
        log.exception(f"Unable to open image at path '{path}'.")
        return

    return newImage


def save_image(image: Image, path: str):
    """Save an Image."""
    log.debug(f"Saving image to '{path}'...")
    try:
        image.save(path, "png")
    except:
        log.exception(f"Unable to save image to '{path}'.")


def create_image(x: int, y: int) -> Image:
    """Create a new image with the given size."""
    log.debug(f"Creating new image of size {x}, {y}...")
    try:
        image = Image.new("RGB", (x, y), "white")
    except:
        log.exception("Unable to create new image.")
        return

    return image


def get_pixel(image: Image, x: int, y: int) -> tuple:
    """Get a given pixel from an image."""
    width, height = image.size
    log.debug(f"Image width: {width}, height: {height}")
    if x > width or y > height:
        log.debug(f"Pixel coordinates {x}, {y} out of bounds.")
        return None

    pixel = image.getpixel((x, y))
    log.debug(f"Pixel at {x}, {y} is {pixel}.")
    return pixel


def get_common_pixels(image: Image, n: int = 5) -> list:
    """Get the n most common pixel values."""
    colors = Image.Image.getcolors(image)

    # frequency: pixel value (0-255)
    topfive = sorted(colors, key=lambda t: t[0], reverse=True)[:n]
    log.debug(f"Top {n} most common pixel values: {topfive}")
    return topfive


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Hide messages within image files.")
    parser.add_argument(
        "-s", 
        "--source", 
        type=str, 
        required=True, 
        help="Source image"
    )
    parser.add_argument(
        "-d",
        "--destination",
        type=str,
        default=None,
        help="Destination image"
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
        coloredlogs.install(level="DEBUG", logger=log)

    if not os.path.exists(args.source):
        log.error(f"Image '{args.source}' not found.")
        exit(1)

    image = open_image(args.source)

    common_pixels = get_common_pixels(image)

    save_image(image, args.destination or f"new.{args.source}")
