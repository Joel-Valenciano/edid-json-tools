#!/usr/bin/env python3

from sys import stdout
import click
from pathlib import Path
import subprocess
import json
import tempfile
import difflib
import copy
import queue
from typing import Union
from traceback import format_exc

EDID2JSON = "edid2json"
JSON2EDID = "json2edid"

"""
To run this program, you may have to install this package, some examples:
    python3 -m pip install --editable .[CLI]
    or
    pip install --editable .[CLI]
    or
    python3 ./setup.py install

Examples of how to run:

    patch_edid override 1 HDMI-A-1 -ymd

    patch_edid override 1 HDMI-A-1 --reset

    patch_edid override 1 HDMI-A-1 -ym

    patch_edid test a.edid -ymd

    patch_edid test a.edid -ymd out.edid

    patch_edid dump 1 HDMI-A-1

    patch_edid dump 1 HDMI-A-1 a.edid
"""

opt_yuv = click.option(
    "-y", "--apply-yuv-fix",
    is_flag=True,
    help="Remove YCbCr support flags from edid (Fixes black " +
        "screen issues on some headsets)"
)

opt_hmd = click.option(
    "-m", "--apply-hmd-fix",
    is_flag=True,
    help="Append a Microsoft HMD VSDB to edid (Allows some headsets " +
        "without the non-desktop quirk to be detected as non-desktop)"
)

opt_did = click.option(
    "-d", "--check-displayid",
    is_flag=True,
    help="Correct checksum in DisplayID block (Fix " +
    "for buggy EDIDs in some headsets)"
)

opt_debug = click.option(
    "--debug",
    is_flag=True,
    help="""Print output of edid2json and diff after processing"""
)

opt_dry_run = click.option(
    "--dry-run",
    is_flag=True,
    help="""Run commands, but don't apply output EDID"""
)


class OverrideOptions:
    def __init__(self, kwargs):
        self.apply_yuv_fix = kwargs.pop("apply_yuv_fix")
        self.apply_hmd_fix = kwargs.pop("apply_hmd_fix")
        self.check_displayid = kwargs.pop("check_displayid")
        self.debug = kwargs.pop("debug")
        self.dry_run = kwargs.pop("dry_run")

    def use_displayid(self):
        return self.check_displayid

    def use_cea861(self):
        return self.apply_yuv_fix or self.apply_hmd_fix


class FixCounter:
    def __init__(self):
        self.counter = 0

    def inc(self):
        self.counter += 1

    def __repr__(self) -> str:
        return str(self.counter)

    def __eq__(self, value: object, /) -> bool:
        return self.counter == value


def process_options(fn):
    """Intercept the options and adds override_options as kwarg"""
    @opt_yuv
    @opt_hmd
    @opt_did
    @opt_debug
    @opt_dry_run
    def wrapper(*args, **kwargs):
        opts = OverrideOptions(kwargs)
        return fn(*args, override_options=opts, **kwargs)

    wrapper.__name__ = fn.__name__
    return wrapper


@click.group()
def cli():
    pass


@cli.command(help="Make changes to the EDID of CONNECTOR")
@click.argument("card", type=int)
@click.argument("connector")
@click.option("--reset", is_flag=True, help="Reset edid override")
@click.option("output_path", "--output", type=click.Path(exists=False), help="Output to file instead of directly to connector")
@process_options
def override(card, connector, reset, override_options, output_path):
    print("Using card {}, connector '{}'".format(card, connector))

    sysfs_path = Path("/sys/class/drm/card{}-{}".format(card, connector))
    debugfs_path = Path("/sys/kernel/debug/dri/{}/{}".format(card, connector))

    edid_path = sysfs_path.joinpath("edid")
    edid_override_path = debugfs_path.joinpath("edid_override")
    trigger_hotplug_path = debugfs_path.joinpath("trigger_hotplug")

    try:
        if reset:
            print("Resetting...")
            edid_bin = b"reset"

        else:
            print("Overriding...")
            edid_bin = patch_edid(edid_path, override_options)

            if edid_bin is None:
                return

        if output_path is not None:
            with click.open_file(output_path, "wb") as output:
                output.write(edid_bin)
                output.flush()

            return

        if not override_options.dry_run:
            apply_edid(edid_bin, edid_override_path, trigger_hotplug_path)

    except PermissionError:
        print("Could not open debugfs files; please run this command as sudo.")
        pass

    print("Done.")
    pass


@cli.command(help="Test with an EDID file (CURRENTLY NO-OP)")
@click.argument("edid_input", type=click.Path())
@click.argument("edid_output", type=click.Path(), default="out.edid")
@process_options
def test(edid_input, edid_output, override_options: OverrideOptions):
    edid_output_path = Path(edid_output)
    print("Testing with EDID file at {} ..."
          .format("stdin" if edid_input == '-' else edid_input))

    edid_bin = patch_edid(edid_input, override_options)
    if not override_options.dry_run:
        if edid_bin is None:
            return

        apply_edid(edid_bin, edid_output_path)
    print("Done.")
    pass


@cli.command(help="Dump the EDID for a connector")
@click.argument("card", type=int)
@click.argument("connector")
@click.argument("output_path", type=click.File("wb"))
@click.option("--json", is_flag=True, default=False, help="Dump edid contents as json")
def dump(card, connector, output_path, json):
    edid_path = "/sys/class/drm/card{}-{}/edid".format(card, connector)
    edid_bin = None

    print("Using card {}, connector '{}'".format(card, connector))

    # Read the binary to see if edid is possibly valid, and to just write it
    # if not using json
    edid_bin = read_edid_bin(edid_path)
    if not edid_bin:
        return None

    if json:
        print("Dumping EDID to {} as JSON...".format(output_path.name))
        edid2json_path = "edid2json"

        print("Running edid2json.py...")
        p1 = subprocess.Popen(args=[edid2json_path, edid_path], stdout=subprocess.PIPE)
        p1.wait(5)
        if p1.returncode != 0:
            print("edid2json.py returned {}.".format(p1.returncode))
            return

        assert p1.stdout is not None
        output_path.write(p1.stdout.read())
    else:
        print("Dumping EDID to {}...".format(output_path.name))
        output_path.write(edid_bin)

    output_path.flush()
    print("Done.")


def read_edid_bin(edid_path: Union[str, Path]):
    edid_path_str = str(Path(edid_path).absolute())
    regular_file = not edid_path_str.startswith("/sys")

    try:
        with click.open_file(edid_path_str, "rb") as edid:
            edid_bin = edid.read()
            length = len(edid_bin)
            if length == 0 or length % 128 != 0:
                if regular_file:
                    print("File at {} is not an EDID file.".format(edid_path))
                else:
                    print("EDID Missing; is display plugged in?")
                return

            return edid_bin

    except Exception as e:
        print(e)
        return None


def patch_edid(edid_path: Union[str, Path], options: OverrideOptions):
    """This function handles most of the processing"""
    # Read edid to see if it is possibly valid
    edid_bin = read_edid_bin(edid_path)
    if not edid_bin:
        return None

    def run_e2j(edid_path):
        print("Running edid2json.py...")
        try:
            p = subprocess.Popen(args=[EDID2JSON, edid_path], stdout=subprocess.PIPE)
            ret = p.wait(5)
        except Exception as e:
            print(format_exc())

        print("json2edid.py returned {}".format(ret))
        return p.stdout.read().decode()

    j_orig = json.loads(run_e2j(edid_path))

    j = copy.deepcopy(j_orig)

    ext_cea861 = None
    ext_displayid = None
    fix_counter = FixCounter()

    TYPE_CEA861 = "CEA-861 Series Timing Extension"
    TYPE_DISPLAYID = "DisplayID Extension"
    for ext in j["Extensions"]:
        if "Type" in ext:
            if ext["Type"] == TYPE_CEA861:
                ext_cea861 = ext
            elif ext["Type"] == TYPE_DISPLAYID:
                ext_displayid = ext

    if options.use_cea861():
        if ext_cea861 is None:
            print("EDID doesn't contain CEA-861 Extension block, " +
            "skipping related fixes.")
        else:
            print("Checking CEA-861 Extension block...")
            apply_cea861_fixes(ext_cea861, options, fix_counter)

    if options.use_displayid():
        if ext_displayid is None:
            print("EDID does not contain DisplayID Extension block, " +
            "skipping related fixes.")
        else:
            print("Checking DisplayID Extension block...")
            apply_displayid_fixes(ext_displayid, options, fix_counter)

    if options.debug:
        show_diff(j_orig, j)

    if fix_counter == 0:
        print("No fixes applied, quitting.")
        return

    print("Applied {} {} to EDID"
          .format(fix_counter, "fix" if fix_counter == 1 else "fixes"))

    tmp_edid = tempfile.NamedTemporaryFile()
    tmp_json = tempfile.NamedTemporaryFile("w+")

    def run_json2edid(j):
        print("Running json2edid.py...")
        json.dump(j, tmp_json, indent=2)
        tmp_json.flush()
        ret = None
        out = None
        try:
            p = subprocess.Popen([JSON2EDID, tmp_json.name, tmp_edid.name], stdout=subprocess.PIPE)
            ret = p.wait(5)
        except Exception as e:
            print(format_exc())

        out = p.stdout.read().decode()
        print("json2edid.py returned {}, output:{}".format(ret, ("\n{}" + out) if len(out) > 0 else ""))
        print("=" * 40)
        return ret

    if run_json2edid(j) != 0:
        print("Error while patching edid, quitting...")
        return None

    edid_bin = tmp_edid.read()
    assert len(edid_bin) > 0 and len(edid_bin) % 128 == 0

    tmp_json.close()
    tmp_edid.close()
    return edid_bin


def apply_displayid_fixes(ext_displayid: dict, options: OverrideOptions, fix_counter):
    # This doesn't do anything explicitly, but it will count it as a fix so
    # it can write the edid, edid2json will fix it automatically (hopefully)
    if ext_displayid["Checksum"] != ext_displayid["Calculated"]:
        print("DisplayID checksum is {}, expected {}. Will correct."
              .format(ext_displayid["Checksum"], ext_displayid["Calculated"]))
        fix_counter.inc()
    pass


def apply_cea861_fixes(ext_cea861: dict, options: OverrideOptions,
                       fix_counter: FixCounter):
    found = False
    for blk in ext_cea861["Data blocks"]:
        if "IEEE OUI" in blk and blk["IEEE OUI"] == "ca-12-5c":
            found = True
            break

    if options.apply_hmd_fix:
        if found:
            print("Found existing HMD VSDB, skipping...")
        else:
            fix_counter.inc()
            print("Appending HMD VSDB...")
            # Taken from https://github.com/OSVR/OSVR-HDK-MCU-Firmware
            # HMD extension - see https://docs.microsoft.com/en-us/windows-hardware/drivers/display/specialized-monitors-edid-extension
            block = {
                "Type": "Vendor-Specific Data Block",
                "IEEE OUI": "ca-12-5c",
                "Data payload": [2, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
            }
            ext_cea861["Data blocks"].append(block)

    if options.apply_yuv_fix:
        fix_counter.inc()
        print("Applying YUV fix...")
        ext_cea861["YCbCr 4:2:2"] = False
        ext_cea861["YCbCr 4:4:4"] = False


def apply_edid(edid_bin, output_edid_path: Path, trigger_hotplug_path=None):
    print("Writing New EDID to {}...".format(output_edid_path))
    with open(output_edid_path, "wb") as output_edid:
        output_edid.write(edid_bin)
        output_edid.flush()

    if trigger_hotplug_path is None:
        return

    if trigger_hotplug_path.exists():
        print("Triggering Hotplug...")
        with open(trigger_hotplug_path, "w") as trigger_hotplug:
            trigger_hotplug.write("1\n")
    else:
        print("Could not Trigger Hotplug.")

    print("Please Re-Plug Headset.")


def show_diff(j_orig, j):
    sj_orig = json.dumps(j_orig, indent=2).splitlines()
    sj = json.dumps(j, indent=2).splitlines()

    # TODO: improve diff printing

    diff = difflib.ndiff(sj_orig, sj)
    print("Diff:")
    minus_i = 0
    plus_i = 0
    changes_plus = 0
    changes_minus = 0
    context = queue.Queue(maxsize=3)
    last_type = ' '
    for line in diff:
        if line[0] == '+':
            if last_type == ' ':
                while not context.empty():
                    i, cl = context.get(block=False)
                    print(i, cl)

            plus_i += 1
            changes_plus += 1
            print("{}:".format(plus_i), line)
        elif line[0] == '-':
            if last_type != line[0]:
                while not context.empty():
                    i, cl = context.get(block=False)
                    print(i, cl)

            changes_minus += 1
            minus_i += 1
            print("{}:".format(minus_i), line)
        elif line[0] == '?':
            pass
        else:
            if context.full():
                context.get(block=False)
            context.put((plus_i, line), block=False)
            plus_i += 1
            minus_i += 1

        last_type = line[0]

    print("lines: {}, changed: +{},-{}".format(len(sj), changes_plus, changes_minus))


if __name__ == "__main__":
    cli()
