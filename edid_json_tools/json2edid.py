#!/usr/bin/env python3 -i
# Copyright 2014 The Chromium OS Authors. All rights reserved.
# Copyright (c) 2019-2021 The EDID JSON Tools authors. All rights reserved.
#
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# SPDX-License-Identifier: BSD-3-Clause

# TODO(chromium:395947): Share strings and options with jsonedid
# TODO(chromium:395947): Add JSON validation


"""Create an EDID binary blob out of a Json representation of an EDID."""


import itertools
import json
from typing import Any, Dict, List, NewType, Tuple

from . import data_block
from . import edid as edid_module
from . import options as options_module
from .tools import PrintHexData
from .typing import BoolDict

BitMask = NewType("BitMask", int)


def _BuildBitsFromOptions(options: List[str], json_map: BoolDict) -> int:
    """Encode a list of options into bit form for an EDID binary blob.

    The order of the options determines the bit position in the EDID. The first
    option corresponds to the most significant bit in the result, the last option
    with the least significant bit, etc.

    Args:
      options: The list of options (strings).
      json_map: The json dictionary indicating whether each option is true or
          false (i.e., supported or not).

    Returns:
      An integer to be stored in the EDID that encodes these options.
    """
    bits = 0
    for option in options:
        bits = (bits << 1) + int(json_map[option])
    return bits


def _BuildBitsFromBitmaskList(
    options: List[Tuple[BitMask, str]], json_map: BoolDict
) -> int:
    """Encode a list of options into bit form for an EDID binary blob.

    Args:
      options: The list of options (bitmask, string pairs).
      json_map: The json dictionary indicating whether each option is true or
          false (i.e., supported or not).

    Returns:
      An integer to be stored in the EDID that encodes these options.
    """
    bits = 0
    for mask, option in options:
        if option in json_map:
            bits += mask * int(json_map[option])
    return bits


def BuildManufacturerInfo(edid: List[int], manu_json: Dict[str, Any]):
    """Add information from manufacturer info dictionary into the EDID list.

    Args:
      edid: The full list form of the EDID.
      manu_json: The dictionary of manufacturer info.
    """
    # Manufacturer Name
    manu_id = manu_json["Manufacturer ID"]

    m1 = (ord(manu_id[0]) - 64) << 10
    m2 = (ord(manu_id[1]) - 64) << 5
    m3 = ord(manu_id[2]) - 64

    m = m1 + m2 + m3
    edid[0x08] = m >> 8
    edid[0x09] = m & 0xFF

    # ID Product Code
    prod_code = manu_json["ID Product Code"]
    edid[0x0A] = prod_code & 0xFF
    edid[0x0B] = prod_code >> 8

    # Serial Number
    ser_num = manu_json["Serial number"]
    if ser_num:
        edid[0x0C] = ser_num & 0xFF
        edid[0x0D] = (ser_num >> 8) & 0xFF
        edid[0x0E] = (ser_num >> 16) & 0xFF
        edid[0x0F] = (ser_num >> 24) & 0xFF
    else:
        edid[0x0C:0x10] = [0x00] * 4

    # Manufacturer week and year
    if manu_json["Week of manufacture"]:
        edid[0x10] = manu_json["Week of manufacture"]
        edid[0x11] = manu_json["Year of manufacture"] - 1990
    else:
        if manu_json["Year of manufacture"]:
            edid[0x10] = 0x00
            edid[0x11] = manu_json["Year of manufacture"] - 1990
        else:
            edid[0x10] = 0xFF
            edid[0x11] = manu_json["Model year"] - 1990


def BuildBasicDisplay(edid: List[int], bd_json: Dict[str, Any]):
    """Add information from basic display info dictionary into the EDID list.

    Args:
      edid: The full list form of the EDID.
      bd_json: The dictionary of basic display info.
    """
    if bd_json["Video input type"] == "Digital":
        vid_input = 1

        if not bd_json["Color Bit Depth"]:
            cbd = 0x00
        elif "Reserved" in bd_json["Color Bit Depth"]:
            cbd = 0x07
        else:
            x, _ = bd_json["Color Bit Depth"].split(" Bits")
            cbd = int(x) // 2 - 2

        dig_supp = {
            None: 0x00,
            "DVI": 0x01,
            "HDMI-a": 0x02,
            "HDMI-b": 0x03,
            "MDDI": 0x04,
            "DisplayPort": 0x05,
        }

        supp = dig_supp[bd_json["Digital Video Interface Standard Support"]]

        edid[0x14] = (vid_input << 7) + (cbd << 4) + supp

    else:
        vid_input = 0
        sig_supp = {
            "+0.7/-0.3 V": 0x00,
            "+0.714/-0.286 V": 0x01,
            "+1.0/-0.4 V": 0x02,
            "+0.7/0 V": 0x03,
        }
        sig = sig_supp[bd_json["Video white and sync levels"]]

        vid_settings = [
            "Blank-to-black setup expected",
            "Separate sync supported",
            "Composite sync (on HSync) supported",
            "Sync on green supported",
            "VSync serrated when composite/sync-on-green used",
        ]

        sum_bits = _BuildBitsFromOptions(vid_settings, bd_json)
        edid[0x14] = (vid_input << 7) + (sig << 5) + sum_bits

    # Aspect Ratios or Maximum Dimensions
    arl = bd_json["Aspect ratio (landscape)"]
    arp = bd_json["Aspect ratio (portrait)"]
    md = bd_json["Maximum dimensions (cm)"]

    if arl:
        a, b = arl.split(" : ")
        edid[0x15] = int((float(a) * 100.0) - 99)

    if arp:
        a, b = arp.split(" : ")
        edid[0x16] = int((100.0 / float(a)) - 99)

    if md:
        edid[0x15] = md["x"]
        edid[0x16] = md["y"]

    # Gamma
    g = bd_json["Display gamma"]
    edid[0x17] = int((g * 100.0) - 100)

    # Feature Support
    dpm = ["DPM standby supported", "DPM suspend supported", "DPM active-off supported"]

    sum_dpm = _BuildBitsFromOptions(dpm, bd_json)

    sce = bd_json["Display color type"]

    if bd_json["Video input type"] == "Digital":
        a = 1 if "YCrCb 4:2:2" in sce else 0
        b = 1 if "YCrCb 4:4:4" in sce else 0
        color = (a << 1) + b

    else:
        color_types = {
            "Monochrome/Grayscale": 0x00,
            "RGB color": 0x01,
            "Non-RGB color": 0x02,
            "Undefined": 0x03,
        }
        color = color_types[sce]

    fsf = [
        "sRGB Standard is default colour space",
        "Preferred timing includes native timing pixel format and refresh rate",
        "Continuous frequency supported",
    ]

    sum_fsf = _BuildBitsFromOptions(fsf, bd_json)
    edid[0x18] = (sum_dpm << 5) + (color << 3) + sum_fsf


def BuildChromaticity(edid: List[int], chrom_json: Dict[str, Dict[str, int]]):
    """Add information from chromaticity info dictionary into the EDID list.

    Args:
      edid: The full list form of the EDID.
      chrom_json: The dictionary of chromaticity info.
    """
    rx = chrom_json["Red"]["x"] & 0x03
    ry = chrom_json["Red"]["y"] & 0x03
    gx = chrom_json["Green"]["x"] & 0x03
    gy = chrom_json["Green"]["y"] & 0x03
    bx = chrom_json["Blue"]["x"] & 0x03
    by = chrom_json["Blue"]["y"] & 0x03
    wx = chrom_json["White"]["x"] & 0x03
    wy = chrom_json["White"]["y"] & 0x03

    edid[0x19] = (rx << 6) + (ry << 4) + (gx << 2) + gy
    edid[0x1A] = (bx << 6) + (by << 4) + (wx << 2) + wy
    edid[0x1B] = chrom_json["Red"]["x"] >> 2
    edid[0x1C] = chrom_json["Red"]["y"] >> 2
    edid[0x1D] = chrom_json["Green"]["x"] >> 2
    edid[0x1E] = chrom_json["Green"]["y"] >> 2
    edid[0x1F] = chrom_json["Blue"]["x"] >> 2
    edid[0x20] = chrom_json["Blue"]["y"] >> 2
    edid[0x21] = chrom_json["White"]["x"] >> 2
    edid[0x22] = chrom_json["White"]["y"] >> 2


def BuildEstablishedTimings(edid: List[int], et_json):
    """Add information from established timings info dictionary into EDID list.

    Args:
      edid: The full list form of the EDID.
      et_json: The dictionary of established timings info.
    """
    sum_bits = _BuildBitsFromOptions(options_module.timings, et_json)

    edid[0x23] = sum_bits >> 16
    edid[0x24] = (sum_bits >> 8) & 0xFF
    edid[0x25] = sum_bits & 0xFF


def BuildStandardTimings(edid: List[int], sts_json):
    """Add information from standard timings info dictionary into the EDID list.

    Args:
      edid: The full list form of the EDID.
      sts_json: The list of dictionaries of standard timings info.
    """
    # First, set the standard timings that are defined
    num_st = len(sts_json)
    base = 0x26
    edid[base : (base + 16)] = [0x01] * 16

    for x in range(0, num_st):
        edid[base + (x * 2) : base + 2 + (x * 2)] = BuildSt(sts_json[x])


def BuildSt(one_st_json):
    """Create a list out of a single standard timing object's dictionary.

    Args:
      one_st_json: The dictionary of a single standard timing object info.

    Returns:
      A list of two bytes representing a single standard timing object.
    """
    x = (one_st_json["X resolution"] // 8) - 31

    ratios = {"1:1": 0x00, "16:10": 0x00, "4:3": 0x01, "5:4": 0x02, "16:9": 0x03}

    iar = ratios[one_st_json["Ratio"]]
    frr = one_st_json["Frequency"] - 60

    return [x, (iar << 6) + frr]


def BuildDescriptors(edid: List[int], descs_json):
    """Add information from descriptors info dictionary into the EDID list.

    Args:
      edid: The full list form of the EDID.
      descs_json: The list of dictionaries of descriptor info.
    """
    base = 0x36
    for x in range(0, 4):
        edid[base + (x * 18) : base + ((x + 1) * 18)] = BuildDescriptor(descs_json[x])


def BuildDtd(desc_json):
    """Create a list out of a single detailed timing descriptor dictionary.

    Args:
      desc_json: The dictionary of a single detailed timing descriptor info.

    Returns:
      A list of 18 bytes representing a single detailed timing descriptor.
    """
    d = [0] * 18

    # Set pixel clock
    pc = int(desc_json["Pixel clock (MHz)"] * 100)
    d[0] = pc & 0xFF
    d[1] = pc >> 8

    hav = desc_json["Addressable"]["x"]
    hb = desc_json["Blanking"]["x"]
    d[2] = hav & 0xFF
    d[3] = hb & 0xFF
    d[4] = ((hav >> 8) << 4) + (hb >> 8)

    vav = desc_json["Addressable"]["y"]
    hv = desc_json["Blanking"]["y"]
    d[5] = vav & 0xFF
    d[6] = hv & 0xFF
    d[7] = ((vav >> 8) << 4) + (hv >> 8)

    hfp = desc_json["Front porch"]["x"]
    hsp = desc_json["Sync pulse"]["x"]
    vfp = desc_json["Front porch"]["y"]
    vsp = desc_json["Sync pulse"]["y"]
    d[8] = hfp & 0xFF
    d[9] = hsp & 0xFF
    d[10] = ((vfp & 0x0F) << 4) + (vsp & 0x0F)
    d[11] = ((hfp >> 8) << 6) + ((hsp >> 8) << 4) + ((vfp >> 4) << 2) + (vsp >> 4)

    hav = desc_json["Image size (mm)"]["x"]
    vav = desc_json["Image size (mm)"]["y"]
    d[12] = hav & 0xFF
    d[13] = vav & 0xFF
    d[14] = ((hav >> 8) << 4) + (vav >> 8)

    d[15] = desc_json["Border"]["x"]
    d[16] = desc_json["Border"]["y"]

    # Byte 17
    stereo_map = {
        "No stereo": (0x0 << 5) + 0x0,  # Could be 0x00 or 0x01
        "Field sequential stereo, right image when stereo sync signal = 1": (0x1 << 5)
        + 0x0,
        "2-way interleaved stereo, right image on even lines": (0x1 << 5) + 0x1,
        "Field sequential stereo, left image when stereo sync signal = 1": (0x2 << 5)
        + 0x0,
        "2-way interleaved stereo, left image on even lines": (0x2 << 5) + 0x1,
        "4-way interleaved stereo": (0x3 << 5) + 0x0,
        "Side-by-side interleaved stereo": (0x3 << 5) + 0x1,
    }

    stereo = stereo_map[desc_json["Stereo viewing"]]

    sync_json = desc_json["Sync type"]
    if "Digital" in sync_json["Type"]:
        if "Separate" in sync_json["Type"]:
            x = 0x03
            y = int(sync_json["Vertical sync"] == "Positive")

        else:
            x = 0x02
            y = int(sync_json["Serrations"])

        z = int(sync_json["Horizontal sync (outside of V-sync)"] == "Positive")

    else:  # Analog
        x = int("Bipolar" in sync_json["Type"])
        y = int(sync_json["Serrations"])
        z = int(sync_json["Sync on RGB"])

    interlace = int(desc_json["Interlace"])
    sync_type = (x << 3) + (y << 2) + (z << 1)

    d[17] = (interlace << 7) + stereo + sync_type

    return d


def BuildDescriptor(desc_json):
    """Create a list out of a single descriptor object's dictionary.

    Args:
      desc_json: The dictionary of a single descriptor object info.

    Returns:
      A list of 18 bytes representing a single descriptor object.
    """
    d = [0] * 18
    atype = desc_json["Type"]

    if atype == "Detailed Timing Descriptor":

        return BuildDtd(desc_json)

    else:

        d[0] = d[1] = d[2] = 0x00
        types = {
            "Display Product Serial Number": 0xFF,
            "Alphanumeric Data String (ASCII)": 0xFE,
            "Display Range Limits Descriptor": 0xFD,
            "Display Product Name": 0xFC,
            "Color Point Data": 0xFB,
            "Standard Timing Identifiers": 0xFA,
            "Display Color Management (DCM) Data": 0xF9,
            "CVT 3 Byte Timing Codes": 0xF8,
            "Established Timings III": 0xF7,
            "Error: Reserved/undefined; do not use": 0x11,
            "Dummy descriptor": 0x10,
            "Manufacturer Specified Display Descriptor": 0x00,  # 0x00 to 0xF6
        }

        d[3] = types[atype]

        if d[3] in [0xFF, 0xFE, 0xFC]:  # Type of string descriptor

            d[5:18] = [0x20] * 13  # Padding with 0x20
            data = desc_json["Data string"]
            str_len = len(data)
            d[5 : (5 + str_len)] = list(map(ord, data))
            if str_len < 13:
                d[5 + str_len] = 0x0A

        elif atype == "Display Range Limits Descriptor":

            subtypes = {
                "Default GTF supported": 0x00,
                "Range Limits Only - no additional info": 0x01,
                "Secondary GTF supported - requires default too": 0x02,
                "CVT supported": 0x04,
                "Unknown": 0x03,  # Could be 0x03, 0x05+
            }

            asubtype = desc_json["Subtype"]
            d[10] = subtypes[asubtype]

            vmin = int(desc_json["Vertical rate (Hz)"]["Minimum"])
            vmax = int(desc_json["Vertical rate (Hz)"]["Maximum"])
            hmin = int(desc_json["Horizontal rate (kHz)"]["Minimum"])
            hmax = int(desc_json["Horizontal rate (kHz)"]["Maximum"])

            h = hmax // 256
            i = hmin // 256
            j = vmax // 256
            k = vmin // 256

            d[4] = (h << 3) + (i << 2) + (j << 1) + k
            d[5] = vmin % 256
            d[6] = vmax % 256
            d[7] = hmin % 256
            d[8] = hmax % 256

            d[9] = int(desc_json["Pixel clock (MHz)"] / 10)

            if asubtype == "Secondary GTF supported - requires default too":
                d[12] = desc_json["Start break frequency"] // 2
                d[13] = desc_json["C"] * 2
                d[14] = desc_json["M"] & 0xFF
                d[15] = desc_json["M"] >> 8
                d[16] = desc_json["K"]
                d[17] = desc_json["J"] * 2

            elif asubtype == "CVT supported":

                v, r = desc_json["CVT Version"].split(".")
                d[11] = (int(v) << 4) + int(r)
                apc = int(desc_json["Additional Pixel Clock (MHz)"] / 0.25)

                maxap = desc_json["Maximum active pixels"]
                maxap = int(maxap) // 8 if maxap else 0

                d[12] = (apc << 2) + (maxap >> 8)
                d[13] = maxap & 0xFF

                ratios = ["4:3 AR", "16:9 AR", "16:10 AR", "5:4 AR", "15:9 AR"]

                d[14] = (
                    _BuildBitsFromOptions(ratios, desc_json["Supported aspect ratios"])
                    << 3
                )

                par = ratios.index(desc_json["Preferred aspect ratio"])

                cvt_blank = desc_json["CVT blanking support"]
                rcvt = 1 if cvt_blank["Reduced CVT Blanking"] else 0
                scvt = 1 if cvt_blank["Standard CVT Blanking"] else 0
                d[15] = (par << 5) + (rcvt << 4) + (scvt << 3)

                scalings = [
                    "Horizontal Shrink",
                    "Horizontal Stretch",
                    "Vertical Shrink",
                    "Vertical Stretch",
                ]

                d[16] = (
                    _BuildBitsFromOptions(
                        scalings, desc_json["Display scaling support"]
                    )
                    << 4
                )
                d[17] = desc_json["Preferred vertical refresh (Hz)"]

            else:  # Not Secondary GTF or CVT supported
                d[11] = 0x0A
                d[12:18] = [0x20] * 6

        elif atype == "Manufacturer Specified Display Descriptor":
            d[5:18] = desc_json["Blob"]

        elif atype == "Established Timings III":

            est_timings = [
                [0x80000000000, "640 x 350 @ 85 Hz"],
                [0x40000000000, "640 x 400 @ 85 Hz"],
                [0x20000000000, "720 x 400 @ 85 Hz"],
                [0x10000000000, "640 x 480 @ 85 Hz"],
                [0x8000000000, "848 x 480 @ 60 Hz"],
                [0x4000000000, "800 x 600 @ 85 Hz"],
                [0x2000000000, "1024 x 768 @ 85 Hz"],
                [0x1000000000, "1152 x 864 @ 75 Hz"],
                [0x800000000, "1280 x 768 @ 60 Hz (RB)"],
                [0x400000000, "1280 x 768 @ 60 Hz"],
                [0x200000000, "1280 x 768 @ 75 Hz"],
                [0x100000000, "1280 x 768 @ 85 Hz"],
                [0x80000000, "1280 x 960 @ 60 Hz"],
                [0x40000000, "1280 x 960 @ 85 Hz"],
                [0x20000000, "1280 x 1024 @ 60 Hz"],
                [0x10000000, "1280 x 1024 @ 85 Hz"],
                [0x8000000, "1360 x 768 @ 60 Hz"],
                [0x4000000, "1440 x 900 @ 60 Hz (RB)"],
                [0x2000000, "1440 x 900 @ 60 Hz"],
                [0x1000000, "1440 x 900 @ 75 Hz"],
                [0x800000, "1440 x 900 @ 85 Hz"],
                [0x400000, "1400 x 1050 @ 60 Hz (RB)"],
                [0x200000, "1400 x 1050 @ 60 Hz"],
                [0x100000, "1400 x 1050 @ 75 Hz"],
                [0x80000, "1400 x 1050 @ 85 Hz"],
                [0x40000, "1680 x 1050 @ 60 Hz (RB)"],
                [0x20000, "1680 x 1050 @ 60 Hz"],
                [0x10000, "1680 x 1050 @ 75 Hz"],
                [0x8000, "1680 x 1050 @ 85 Hz"],
                [0x4000, "1600 x 1200 @ 60 Hz"],
                [0x2000, "1600 x 1200 @ 65 Hz"],
                [0x1000, "1600 x 1200 @ 70 Hz"],
                [0x800, "1600 x 1200 @ 75 Hz"],
                [0x400, "1600 x 1200 @ 85 Hz"],
                [0x200, "1792 x 1344 @ 60 Hz"],
                [0x100, "1792 x 1344 @ 75 Hz"],
                [0x80, "1856 x 1392 @ 60 Hz"],
                [0x40, "1856 x 1392 @ 75 Hz"],
                [0x20, "1920 x 1200 @ 60 Hz (RB)"],
                [0x10, "1920 x 1200 @ 60 Hz"],
                [0x8, "1920 x 1200 @ 75 Hz"],
                [0x4, "1920 x 1200 @ 85 Hz"],
                [0x2, "1920 x 1440 @ 60 Hz"],
                [0x1, "1920 x 1440 @ 75 Hz"],
            ]

            sum_bits = 0

            for x, s in est_timings:
                if desc_json["Established Timings"][s]:
                    sum_bits += x

            sum_bits <<= 4

            d[6] = sum_bits >> 40
            d[7] = (sum_bits >> 32) & 0xFF
            d[8] = (sum_bits >> 24) & 0xFF
            d[9] = (sum_bits >> 16) & 0xFF
            d[10] = (sum_bits >> 8) & 0xFF
            d[11] = sum_bits & 0xFF

        elif atype == "Color Point Data":

            cps = desc_json["Color Points"]  # List of dicts

            start = 5
            for cp in cps:
                d[start] = cp["Index number"]
                wx = cp["White point coordinates"]["x"]
                wy = cp["White point coordinates"]["y"]
                d[start + 1] = ((wx & 0x03) << 2) + (wy & 0x03)
                d[start + 2] = wx >> 2
                d[start + 3] = wy >> 2
                gamma = cp["Gamma"]
                d[start + 4] = int((gamma * 100) - 100) if gamma else 0xFF
                start += 5

            # If there's only one color point, the 2nd remains all 0x00

        elif atype == "Standard Timing Identifiers":

            sts = desc_json["Standard Timings"]
            for x in range(0, 6):
                d[5 + (x * 2) : 7 + (x * 2)] = BuildSt(sts[x])

            d[17] = 0x0A

        elif atype == "Display Color Management (DCM) Data":

            d[5] = 0x03
            d[6] = desc_json["Red a3"] & 0xFF
            d[7] = desc_json["Red a3"] >> 8
            d[8] = desc_json["Red a2"] & 0xFF
            d[9] = desc_json["Red a2"] >> 8
            d[10] = desc_json["Green a3"] & 0xFF
            d[11] = desc_json["Green a3"] >> 8
            d[12] = desc_json["Green a2"] & 0xFF
            d[13] = desc_json["Green a2"] >> 8
            d[14] = desc_json["Blue a3"] & 0xFF
            d[15] = desc_json["Blue a3"] >> 8
            d[16] = desc_json["Blue a2"] & 0xFF
            d[17] = desc_json["Blue a2"] >> 8

        elif atype == "CVT 3 Byte Timing Codes":

            d[5] = 0x01
            cvts = desc_json["Coordinated Video Timings"]
            for x in range(0, len(cvts)):  # Up to 4
                d[6 + (x * 3) : 9 + (x * 3)] = BuildCvt(cvts[x])

    return d


def BuildCvt(cvt_json):
    """Create a list out of a single CVT object's dictionary.

    Args:
      cvt_json: The dictionary of a single CVT object info.

    Returns:
      A list of bytes representing a single CVT object.
    """
    edid = [0] * 3
    avl = (cvt_json["Active vertical lines"] // 2) - 1
    edid[0] = avl & 0xFF

    ratios = {"4:3 AR": 0x00, "16:9 AR": 0x01, "16:10 AR": 0x02, "15:9 AR": 0x03}

    ar = ratios[cvt_json["Aspect ratio"]]

    edid[1] = ((avl >> 4) & 0xF0) + (ar << 2)

    vert_rate = {
        "50Hz": 0x00,
        "60Hz": 0x01,
        "60Hz (reduced blanking)": 0x01,
        "75Hz": 0x02,
        "85Hz": 0x03,
    }

    pref_vert = vert_rate[cvt_json["Preferred refresh rate"]]
    edid[2] = pref_vert << 5

    rates = ["50Hz", "60Hz", "75Hz", "85Hz", "60Hz (reduced blanking)"]

    edid[2] += _BuildBitsFromOptions(rates, cvt_json["Supported refresh rates"])
    return edid


def BuildExtensions(edid: List[int], exts_json):
    """Add information from extensions dictionary into the EDID list.

    Args:
      edid: The full list form of the EDID.
      exts_json: The dictionary of extensions info.
    """
    base = 0x80
    for ext_json in exts_json:
        edid[base : (base + 128)] = BuildExtension(ext_json)
        base += 128


def BuildExtension(ext_json):
    """Create a list out of a single extension object's dictionary.

    Args:
      ext_json: The dictionary of a single extension object info.

    Returns:
      A list of bytes representing a single extension object.
    """
    e = [0] * 128

    atype = ext_json["Type"]

    if atype == "Video Timing Block Extension (VTB-EXT)":
        e[0] = 0x10
        e[1] = ext_json["Version"]

        dtds = ext_json["Detailed Timing Descriptors"]
        cvts = ext_json["Coordinated Video Timings"]
        sts = ext_json["Standard Timings"]

        e[2] = len(dtds)
        e[3] = len(cvts)
        e[4] = len(sts)

        start = 5
        for dtd in dtds:
            e[start : (start + 0x12)] = BuildDtd(dtd)
            start += 0x12
        for cvt in cvts:
            e[start : (start + 0x03)] = BuildCvt(cvt)
            start += 0x03
        for st in sts:
            e[start : (start + 0x02)] = BuildSt(st)
            start += 0x02

    if atype == "DisplayID Extension":
        rev_map = {
                "v1.2": 0x12,
                "v1.3": 0x13,
                "v2.0": 0x20,
                "v2.1": 0x21,
            }
        use_cases = [
                "Extension Section",
                "Test Structure",
                "Generic",
                "Television",
                "Productivity",
                "Gaming",
                "Presentation",
                "Virtual Reality",
                "Augmented Reality",
            ]

        did_exts = ext_json["Extensions"]
        blocks: list[dict] = ext_json["Blocks"]

        e[0] = 0x70
        e[1] = rev_map[ext_json["Version"]]
        e[2] = ext_json["Length"]
        e[3] = use_cases.index(ext_json["Primary Use Case"])
        e[4] = len(did_exts)

        def BuildDIDBlock(blk):
            out = [0] * (3 + blk["len"])
            out[0] = blk["tag"]
            out[1] = blk["revision"]
            out[2] = blk["len"]
            out[3:] = blk["data"]
            return out

        start = 5
        for blk in blocks:
            length = 3 + blk["len"]
            e[start:start + length] = BuildDIDBlock(blk)
            start += length

        sum = 0
        for c in e[1:e[2] + 5]:
            sum += c

        e[126] = 256 - (sum % 256)

    elif atype == "CEA-861 Series Timing Extension":
        e[0] = 0x02
        e[1] = ext_json["Version"]

        supports = ["Underscan", "Basic audio", "YCbCr 4:4:4", "YCbCr 4:2:2"]

        supports_bits = _BuildBitsFromOptions(supports, ext_json)
        e[3] = (supports_bits << 4) + ext_json["Native DTD count"]

        index = 0x04
        for db in ext_json["Data blocks"]:
            blob = BuildDataBlock(db)
            length = len(blob)
            e[index : (index + length)] = blob
            index += length

        e[2] = index  # Where the DTDs start

        for dtd in ext_json["Descriptors"]:
            e[index : (index + 18)] = BuildDtd(dtd)
            index += 18

    elif atype == "Extension Block Map":

        tags = ext_json["Tags"]
        e[1 : (1 + len(tags))] = tags

    return e


def BuildDataBlock(db_json):
    """Create a list out of a single data block object's dictionary.

    Args:
      db_json: The dictionary of a single data block object info.

    Returns:
      A list of bytes representing a single data block object.
    """
    atype = db_json["Type"]
    extended_tag = None
    blob = []

    if atype == data_block.DB_TYPE_AUDIO:
        tag = 0x01

        sads = db_json["Short audio descriptors"]
        blob = list(itertools.chain(*[BuildSad(sad) for sad in sads]))

    elif atype in (data_block.DB_TYPE_VIDEO, data_block.DB_TYPE_YCBCR420_VIDEO):

        if atype == data_block.DB_TYPE_VIDEO:
            tag = 0x02

        else:  # YCbCr 4:2:0
            tag = 0x07
            extended_tag = 0x01

        blob = [BuildSvd(svd) for svd in db_json["Short video descriptors"]]

    elif "Vendor-Specific" in atype:

        if atype == data_block.DB_TYPE_VENDOR_SPECIFIC:
            tag = 0x03
        else:
            tag = 0x07
            extended_tag = 0x01 if "Video" in atype else 0x17  # Audio

        x, y, z = db_json["IEEE OUI"].split("-")
        blob = [int(z, 16), int(y, 16), int(x, 16)] + db_json["Data payload"]

    elif atype == data_block.DB_TYPE_SPEAKER_ALLOCATION:

        tag = 0x04

        speaker_bits = _BuildBitsFromBitmaskList(
            data_block.SPEAKERS, db_json["Speaker allocation"]
        )

        blob = [speaker_bits & 0xFF, speaker_bits >> 8, 0]

    elif atype == data_block.DB_TYPE_COLORIMETRY:

        tag = 0x07
        extended_tag = 0x05

        # TODO The previous values appeared reversed:
        # need to verify that we're round-tripping this right.

        blob = [
            _BuildBitsFromBitmaskList(data_block.COLORS, db_json["Colorimetry"]),
            db_json["Metadata"],
        ]

    elif atype == data_block.DB_TYPE_VIDEO_CAPABILITY:

        tag = 0x07
        extended_tag = 0x00

        qy = 1 if db_json["YCC Quantization range"] else 0
        qs = 1 if db_json["RGB Quantization range"] else 0

        ou = {
            "Undefined": 0x00,
            "Not supported": 0x00,
            "Overscan": 0x01,
            "Underscan": 0x02,
            "Both": 0x03,
            # the following are the entries as created by edid2json
            data_block.OU_UNDEFINED: 0x00,
            data_block.OU_NOT_SUPPORTED: 0x00,
            data_block.OU_OVERSCAN: 0x01,
            data_block.OU_UNDERSCAN: 0x02,
            data_block.OU_BOTH: 0x03,
        }

        pt = ou[db_json["PT behavior"]]
        it = ou[db_json["IT behavior"]]
        ce = ou[db_json["CE behavior"]]

        blob = [(qy << 7) + (qs << 6) + (pt << 4) + (it << 2) + ce]

    elif atype == data_block.DB_TYPE_INFO_FRAME:

        tag = 0x07
        extended_tag = 0x32

        if_proc = db_json["InfoFrame Processing Descriptor"]
        if_proc_payload = if_proc["Data payload"]
        vsifs = db_json["Vendor-Specific Info Frames"]
        blob = [len(if_proc_payload) << 5, len(vsifs)] + if_proc_payload

        for vsif in vsifs:
            blob += BuildVsif(vsif)

    elif atype == data_block.DB_TYPE_YCBCR420_CAPABILITY_MAP:

        tag = 0x07
        extended_tag = 0x15

        indices = db_json["Supported descriptor indices"]
        bit_map = 0
        for index in indices:
            bit_map |= 1 << index
        while bit_map:
            blob.append(bit_map & 0xFF)
            bit_map >>= 8

    elif atype == data_block.DB_TYPE_VIDEO_FORMAT_PREFERENCE:

        tag = 0x07
        extended_tag = 0x13

        prefs = db_json["Video preferences"]
        for pref in prefs:
            if pref["Type"] == "Video Preference VIC":
                blob.append(pref["VIC"])
            elif pref["Type"] == "Video Preference DTD":
                blob.append(pref["DTD index"] + 128)
            else:  # Reserved
                blob.append(pref["SVR"])

    elif atype == data_block.DB_TYPE_RESERVED:
        tag = db_json["Tag"]
        blob = db_json["Data payload"]

    else:
        raise RuntimeError("Got a data block we can't turn back into EDID")

    length = len(blob) if not extended_tag else len(blob) + 1
    header = [(tag << 5) + length]

    if extended_tag:
        header.append(extended_tag)

    return header + blob


def BuildVsif(vsif_json):
    """Create a list out of a single VSIF object's dictionary.

    Args:
      vsif_json: The dictionary of a single VSIF object info.

    Returns:
      A list of bytes representing a single VSIF object.
    """
    codes = {
        "Vendor Specific": 0x01,
        "Auxiliary Video Information": 0x02,
        "Source Product Description": 0x03,
        "Audio": 0x04,
        "MPEG Source": 0x05,
        "NTSC VBI": 0x06,
        "Unknown": 0x07,
    }
    vtype = vsif_json["Type"]
    payload = vsif_json["Data payload"]
    header = [(len(payload) << 5) + codes[vtype]]
    oui = []

    if vtype == "Vendor Specific":
        x, y, z = vsif_json["IEEE OUI"].split("-")
        oui = [int(z, 16), int(y, 16), int(x, 16)]

    return header + oui + payload


def BuildSad(sad_json):
    """Create a list out of a single SAD object's dictionary.

    Args:
      sad_json: The dictionary of a single SAD object info.

    Returns:
      A list of 3 bytes representing a single SAD object.
    """
    sad = [0] * 3

    sad_types = [
        "Linear Pulse Code Modulation (LPCM)",
        "AC-3",
        "MPEG1 (Layers 1 and 2)",
        "MP3 (MPEG1 Layer 3)",
        "MPEG2 (multichannel)",
        "AAC",
        "DTS",
        "ATRAC",
        "One-bit audio (aka SACD)",
        "E-AC-3",
        "DTS-HD",
        "MAT MLP/Dolby TrueHD",
        "DST Audio",
        "Microsoft WMA Pro",
        "MPEG-4 HE AAC",
        "MPEG-4 HE AAC v2",
        "MPEG-4 AAC LC",
        "DRA",
        "MPEG-4 HE AAC + MPEG Surround",
        "MPEG-4AAC LC + MPEG Surround",
        "Unknown",  # Necessary?
    ]

    tag = sad_types.index(sad_json["Type"]) + 1
    mcc = sad_json["Max channel count"] - 1
    sad[0] = (tag << 3) + mcc

    sad[1] = _BuildBitsFromBitmaskList(data_block.FREQS, sad_json["Supported sampling"])

    if sad_json["Type"] == "Linear Pulse Code Modulation (LPCM)":
        sad[2] = _BuildBitsFromBitmaskList(data_block.AUDIO_BITS, sad_json["Bit depth"])

    elif tag <= 0x08 and tag >= 0x02:
        sad[2] = int(sad_json["Max bit rate"].split()[0]) // 8

    elif tag <= 0x0E and tag <= 0x09:
        sad[2] = sad_json["Value"]

    elif sad_json["Type"] == "DRA":  # A type of extension SAD
        ext_code = 0x07
        sad[2] = (ext_code << 3) + sad_json["DRA value"]

    else:  # All other extension SAD types
        ext = sad_json["Extension code"]

        frame_len = {"1024": 0x02, "960": 0x01, "Undefined": 0x00}
        fl = frame_len[sad_json["Frame length"]]
        mps = int(sad_json.get("MPS support") == "MPS explicit")
        sad[2] = (ext << 3) + (fl << 1) + mps

    return sad


def BuildSvd(svd_json):
    """Create a list out of a single SVD object's dictionary.

    Args:
      svd_json: The dictionary of a single SVD object info.

    Returns:
      An 8-bit integer representing a single SVD object.
    """
    svd = svd_json["VIC"]
    if svd_json["Nativity"] == "Native":
        svd += 0x80

    return svd


def BuildEdid(edid_json):
    """Create an EDID (list of bytes) out of a dictionary.

    Args:
      edid_json: The dictionary of EDID info.

    Returns:
      A list of bytes representing the full EDID.
    """
    ext_count = len(edid_json["Extensions"])
    edid = [0] * ((ext_count + 1) * 128)

    base = edid_json["Base"]

    # Set up header
    edid[0x00:0x08] = [0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00]

    # Set version and revision
    version, revision = edid_json["Version"].split(".")
    edid[0x12] = int(version)
    edid[0x13] = int(revision)

    BuildManufacturerInfo(edid, base["Manufacturer Info"])
    BuildBasicDisplay(edid, base["Basic Display"])
    BuildChromaticity(edid, base["Chromaticity"])
    BuildEstablishedTimings(edid, base["Established Timing"])
    BuildStandardTimings(edid, base["Standard Timing"])
    BuildDescriptors(edid, base["Descriptors"])
    BuildExtensions(edid, edid_json["Extensions"])

    # Extension count
    edid[126] = ext_count
    assert len(edid) % 128 == 0, "Size {} is not a multiple of 128, was a block was filled past capacity?".format(len(edid))

    # Set checksums for each 128-byte block
    for x in range(0, len(edid), 128):
        current_sum = sum(edid[x : 127 + x])
        edid[127 + x] = 256 - (current_sum % 256)

    return edid


def JsonToBinary(in_file: str, out_file: str):
    """Read text file in as Json and convert information into binary blob.

    Args:
      in_file: The string name of the text file to read as Json input.
      out_file: The string name of the text file for binary output.
    """
    with open(in_file) as json_file:
        json_data = json.load(json_file)
        list_edid = BuildEdid(json_data)

        list_edid = list(map(int, list_edid))  # make sure every byte is an int
        PrintHexData(list_edid)

        invalid_bytes = [
            i
            for i in range(0, len(list_edid))
            if not 0 <= list_edid[i] and not list_edid[i] < 256
        ]
        if not invalid_bytes:
            edid_obj = edid_module.Edid(list_edid)
            if edid_obj.GetErrors():
                print(edid_obj.GetErrors())
            edid_obj.ConvertToBinary(out_file)
        else:
            for i in invalid_bytes:
                print("Invalid byte at 0x%02X: %s" % (i, list_edid[i]))
            print("Nothing is written to the output file due to errors")
