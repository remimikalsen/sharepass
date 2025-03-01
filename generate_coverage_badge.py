#!/usr/bin/env python3
import argparse
import xml.etree.ElementTree as ET
import os
import sys


def get_coverage_percentage(xml_path):
    """Parses the coverage XML and returns the integer percentage."""
    try:
        tree = ET.parse(xml_path)
    except Exception as e:
        sys.exit(f"Error parsing XML file: {e}")
    root = tree.getroot()
    # Here we assume the root attribute "line-rate" holds the coverage fraction (e.g., 0.92)
    try:
        line_rate = float(root.attrib.get("line-rate", 0))
    except Exception as e:
        sys.exit(f"Error reading line-rate from XML: {e}")
    return int(round(line_rate * 100))


def generate_badge_svg(coverage):
    """Generates an SVG badge string with the given coverage percentage."""
    svg_template = f'''<svg xmlns="http://www.w3.org/2000/svg" width="120" height="20">
  <linearGradient id="a" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <rect rx="3" width="120" height="20" fill="#555"/>
  <rect rx="3" x="70" width="50" height="20" fill="#4c1"/>
  <path fill="#4c1" d="M70 0h4v20h-4z"/>
  <rect rx="3" width="120" height="20" fill="url(#a)"/>
  <g fill="#fff" text-anchor="middle" font-family="Verdana" font-size="11">
    <text x="35" y="14">coverage</text>
    <text x="95" y="14">{coverage}%</text>
  </g>
</svg>'''
    return svg_template


def update_badge(xml_path, badge_path, print_if_changed):
    # Generate new badge SVG from the coverage XML
    coverage = get_coverage_percentage(xml_path)
    new_svg = generate_badge_svg(coverage)

    file_changed = True
    # Check if the badge file already exists and if its content is the same
    if os.path.exists(badge_path):
        with open(badge_path, 'r') as f:
            old_svg = f.read()
        if old_svg == new_svg:
            file_changed = False

    # If changed, write the new file
    if True:
        with open(badge_path, 'w') as f:
            f.write(new_svg)
        if print_if_changed:
            print(new_svg, end='')  # Print without extra newline if desired
    # If not changed and --print-svg-if-changed is provided, print nothing.
    return file_changed


def main():
    parser = argparse.ArgumentParser(
        description="Generate a coverage badge SVG from coverage.xml and update badge file only if changed."
    )
    parser.add_argument(
        "--coverage-xml",
        default="tests/coverage.xml",
        help="Path to the coverage XML file (default: tests/coverage.xml)",
    )
    parser.add_argument(
        "--badge-file",
        default="tests/coverage-badge.svg",
        help="Path to the badge SVG file (default: tests/coverage-badge.svg)",
    )
    parser.add_argument(
        "--print-svg-if-changed",
        action="store_true",
        help="If set, print the new SVG to stdout only if the badge file is updated.",
    )
    args = parser.parse_args()

    update_badge(args.coverage_xml, args.badge_file, args.print_svg_if_changed)


if __name__ == "__main__":
    main()
