#!/usr/bin/env python3

import argparse
import logging
import os

import coloredlogs
import numpy as np
from PIL import Image

log = logging.getLogger(__name__)
coloredlogs.install(
    level="INFO", fmt="[%(asctime)s] [%(levelname)-8s] %(message)s'", logger=log
)


def open_image(image_path: str) -> Image:
    """Open an image."""
    if not os.path.exists(image_path):
        log.error(f"Image '{args.source}' not found.")
        return

    log.debug(f"Opening image at path '{image_path}'...")
    try:
        image = Image.open(image_path, "r")
    except:
        log.exception(f"Unable to open image at path '{image_path}'.")
        return

    return image


def save_image(image: Image, path: str) -> None:
    """Save an image."""
    log.debug(f"Saving image to '{path}'...")
    try:
        image.save(path, "png")
    except:
        log.exception(f"Unable to save image to '{path}'.")


def create_image(x: int, y: int) -> Image:
    """Create a new image with the given size."""
    log.debug(f"Creating new image of size {x}, {y}...")
    try:
        image = Image.new("RGB", (x, y))
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
    colors = Image.Image.getcolors(image, maxcolors=image.size[0] * image.size[1])

    # frequency: pixel value (0-255)
    top_five = sorted(colors, key=lambda t: t[0], reverse=True)[:n]
    log.debug(f"Top {n} most common pixel values: {top_five}")
    return top_five


def transform_pixels(image: Image, pixel_value: tuple, shift: int) -> Image:
    """Modify a given image."""
    width, height = image.size

    # create new image & pixel map
    new_image = create_image(width, height)
    pixels = new_image.load()

    for x in range(width):
        for y in range(height):
            pixel = get_pixel(image, x, y)

            red = pixel[0]
            green = pixel[1]
            blue = pixel[2]

            if pixel == pixel_value:
                # if we have a match for our desired modified pixel, then
                # set the pixel in the new image accordingly
                red = red * shift // 255
                green = red * shift // 255
                blue = red * shift // 255
            
            # set pixel in new image
            pixels[x, y] = (int(red), int(green), int(blue))

    return new_image


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Hide messages within image files.")
    parser.add_argument("-s", "--source", type=str, required=True, help="Source image")
    parser.add_argument(
        "-d", "--destination", type=str, default=None, help="Destination image"
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
            fmt="[%(asctime)s] [%(levelname)-8s] %(message)s'",
            logger=log,
        )
    
    image = open_image(args.source)
    if not image:
        exit(1)

    common_pixels = get_common_pixels(image)

    new_image = transform_pixels(image, common_pixels[0][1], 2)

    save_image(new_image, args.destination or f"new.{args.source}")

    log.info("All steps completed.")
