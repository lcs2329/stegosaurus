#!/usr/bin/env python3

from __future__ import print_function

import argparse
import binascii
import logging
import os
import struct

import coloredlogs
import numpy as np
import scipy
import scipy.cluster
import scipy.misc
from matplotlib.image import imread
from PIL import Image

log = logging.getLogger(__name__)
coloredlogs.install(level="INFO", logger=log)


def get_pixel_map(image:str, resize, resize_threshold:int=150):
    """Get a pixel map from an image."""
    log.debug(f"Opening '{image}'...")
    try:
        img = Image.open(image, "r").convert("L")
    except:
        log.exception(f"Unable to open {image}. Exiting...")
        return
    if resize:
        img = img.resize((resize_threshold, resize_threshold))
    
    colors = Image.Image.getcolors(img)
    topfive = sorted(colors, key=lambda t: t[0], reverse=True)[:5]

    return np.asarray(img)


def rewrite_image(pixelmap):
    for pixel in pixelmap:
        log.debug(f"Old pixel: {pixel}")
        for index,color in enumerate(pixel):
            pixel[index] = color + 10
        log.debug(f"New pixel: {pixel}")

    # arr[arr > 255] = new_pixel


def get_common_pixels(pixelmap, n=5):
    """Get the n most common pixel values."""
    shape = pixelmap.shape
    pixelmap = pixelmap.reshape(scipy.product(shape[:2]), shape[2]).astype(float)

    log.debug("Finding common clusters...")
    codes, dist = scipy.cluster.vq.kmeans(pixelmap, n)
    log.debug(f"Cluster centers: \n{codes}")

    # assign codes
    vecs, dist = scipy.cluster.vq.vq(pixelmap, codes)  

    # count occurrences
    counts, bins = scipy.histogram(vecs, len(codes))

    # find most frequent    
    index_max = scipy.argmax(counts)
    peak = codes[index_max]

    # get hex value
    color = binascii.hexlify(bytearray(int(c) for c in peak)).decode("ascii")
    log.debug(f"Most frequent is {peak} (#{color})")
    return codes


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Image Steganography tool")
    parser.add_argument("-i", "--image", type=str, required=True, help="Source image")
    parser.add_argument("-v", "--verbose", action="store_true", default=False, help="Enable verbose logging.")
    parser.add_argument("--resize", action="store_true", default=False, help="Resize image for faster processing.")

    args = parser.parse_args()

    if args.verbose:
        coloredlogs.install(level="DEBUG", logger=log)

    if not os.path.exists(args.image):
        log.error(f"Image '{args.image}' not found.")
        exit(1)
    
    pixelmap = get_pixel_map(args.image, args.resize)
    if pixelmap is None:
        exit()

    common_pixels = get_common_pixels(pixelmap)
    
    for pixel in common_pixels:
        log.info(f"Most common pixels: {pixel}")
