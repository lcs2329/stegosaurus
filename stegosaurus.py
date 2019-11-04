#!/usr/bin/env python3

import argparse
import logging
import os

import coloredlogs
import numpy as np
from PIL import Image

log = logging.getLogger(__name__)
coloredlogs.install(level="INFO", logger=log)


def get_image(image: str, resize:bool, resize_threshold: int = 150) -> Image:
    """Convert an image into a pillow image object."""
    log.debug(f"Opening '{image}'...")
    try:
        img = Image.open(image, "r").convert("L")
    except:
        log.exception(f"Unable to open {image}. Exiting...")
        return

    if resize:
        img = img.resize((resize_threshold, resize_threshold))

    return img


def get_pixel_map(image: Image) -> np.ndarray:
    """Get a pixel map from an image."""
    return np.asarray(image)


def rewrite_image(pixelmap:np.ndarray):
    for pixel in pixelmap:
        log.debug(f"Old pixel: {pixel}")
        for index, color in enumerate(pixel):
            pixel[index] = color + 10
        log.debug(f"New pixel: {pixel}")

    # arr[arr > 255] = new_pixel


def get_common_pixels(image: Image, n:int=5) -> list:
    """Get the n most common pixel values."""
    colors = Image.Image.getcolors(image)
    topfive = sorted(colors, key=lambda t: t[0], reverse=True)[:5]
    log.debug(f"Top 5 most common pixel values: {topfive}")
    return topfive


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Image Steganography tool")
    parser.add_argument("-i", "--image", type=str, required=True, help="Source image")
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=False,
        help="Enable verbose logging.",
    )
    parser.add_argument(
        "--resize",
        action="store_true",
        default=False,
        help="Resize image for faster processing.",
    )

    args = parser.parse_args()

    if args.verbose:
        coloredlogs.install(level="DEBUG", logger=log)

    if not os.path.exists(args.image):
        log.error(f"Image '{args.image}' not found.")
        exit(1)

    image = get_image(args.image, args.resize)
    if image is None:
        exit()

    pixelmap = get_pixel_map(image)
   
    common_pixels = get_common_pixels(image)

    for pixel in common_pixels:
        log.info(f"Most common pixels: {pixel}")
