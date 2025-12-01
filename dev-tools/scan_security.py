#!/usr/bin/env python3
"""
Security scanning dev tool for Trivy and OpenGrep.
Run security scans locally before committing code.

Usage:
    python dev-tools/scan_security.py [--trivy-fs] [--trivy-image] [--opengrep] [--all]
    python dev-tools/scan_security.py --help
"""

import argparse
import subprocess
import sys
import os
from pathlib import Path
from typing import Optional, List, Tuple
from datetime import datetime


def run_command(
    cmd: List[str], 
    description: str, 
    check: bool = True,
    output_file: Optional[str] = None,
    quiet: bool = False
) -> Tuple[bool, str]:
    """
    Run a shell command and return success status and output.
    
    Returns:
        Tuple of (success: bool, output: str)
    """
    if not quiet:
        print(f"\n{'='*60}")
        print(f"Running: {description}")
        print(f"Command: {' '.join(cmd)}")
        if output_file:
            print(f"Output will be saved to: {output_file}")
        print(f"{'='*60}\n")
    
    try:
        result = subprocess.run(
            cmd,
            check=check,
            capture_output=True,
            text=True
        )
        
        output = result.stdout + result.stderr
        
        # Save output to file if specified
        if output_file:
            try:
                output_dir = os.path.dirname(output_file)
                if output_dir:
                    os.makedirs(output_dir, exist_ok=True)
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(f"# {description}\n")
                    f.write(f"# Command: {' '.join(cmd)}\n")
                    f.write(f"# Timestamp: {datetime.now().isoformat()}\n")
                    f.write(f"# Exit Code: {result.returncode}\n")
                    f.write("#" + "="*60 + "\n\n")
                    f.write(output)
                if not quiet:
                    print(f"✓ Results saved to: {output_file}")
            except Exception as e:
                if not quiet:
                    print(f"⚠ Warning: Could not save output to {output_file}: {e}")
        
        # Display output to console (unless quiet)
        if not quiet:
            print(output)
        
        if result.returncode == 0:
            if not quiet:
                print(f"\n✓ {description} completed successfully")
            return True, output
        else:
            if not quiet:
                print(f"\n✗ {description} failed with exit code {result.returncode}")
            return False, output
    except FileNotFoundError:
        error_msg = f"Error: Command not found. Please ensure the tool is installed.\n   Command: {cmd[0]}"
        if not quiet:
            print(f"\n✗ {error_msg}")
        return False, error_msg
    except Exception as e:
        error_msg = f"Error running {description}: {e}"
        if not quiet:
            print(f"\n✗ {error_msg}")
        return False, error_msg


def check_trivy_installed() -> bool:
    """Check if Trivy is installed."""
    try:
        subprocess.run(["trivy", "--version"], capture_output=True, check=True)
        return True
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False


def check_opengrep_installed() -> bool:
    """Check if OpenGrep is installed."""
    try:
        subprocess.run(["opengrep", "--version"], capture_output=True, check=True)
        return True
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False


def run_trivy_fs(
    trivyignore: Optional[str] = None,
    output_file: Optional[str] = None,
    json_output: bool = False,
    quiet: bool = False
) -> Tuple[bool, str]:
    """Run Trivy filesystem scan."""
    if not check_trivy_installed():
        error_msg = "✗ Trivy is not installed. Please install it first.\n  Windows: choco install trivy or download from https://github.com/aquasecurity/trivy"
        if not quiet:
            print(error_msg)
        return False, error_msg
    
    format_type = "json" if json_output else "table"
    cmd = [
        "trivy", "fs",
        "--scanners", "vuln,secret,misconfig",
        "--severity", "CRITICAL,HIGH",
        "--format", format_type,
        "."
    ]
    
    if trivyignore and os.path.exists(trivyignore):
        cmd.extend(["--ignorefile", trivyignore])
    
    return run_command(cmd, "Trivy Filesystem Scan", check=False, output_file=output_file, quiet=quiet)


def run_trivy_image(
    image_name: str,
    trivyignore: Optional[str] = None,
    output_file: Optional[str] = None,
    json_output: bool = False,
    quiet: bool = False
) -> Tuple[bool, str]:
    """Run Trivy image scan."""
    if not check_trivy_installed():
        error_msg = "✗ Trivy is not installed. Please install it first.\n  Windows: choco install trivy or download from https://github.com/aquasecurity/trivy"
        if not quiet:
            print(error_msg)
        return False, error_msg
    
    format_type = "json" if json_output else "table"
    cmd = [
        "trivy", "image",
        "--scanners", "vuln,secret,misconfig",
        "--severity", "CRITICAL,HIGH",
        "--format", format_type,
        image_name
    ]
    
    if trivyignore and os.path.exists(trivyignore):
        cmd.extend(["--ignorefile", trivyignore])
    
    return run_command(cmd, f"Trivy Image Scan: {image_name}", check=False, output_file=output_file, quiet=quiet)


def run_opengrep(
    output_file: Optional[str] = None,
    quiet: bool = False
) -> Tuple[bool, str]:
    """Run OpenGrep SAST scan."""
    if not check_opengrep_installed():
        error_msg = "✗ OpenGrep is not installed. Please install it first.\n  Download from: https://github.com/opengrep/opengrep/releases\n  Windows: Download the Windows binary and add to PATH"
        if not quiet:
            print(error_msg)
        return False, error_msg
    
    cmd = ["opengrep", "scan", "--config", "auto", "--verbose"]
    return run_command(cmd, "OpenGrep SAST Scan", check=False, output_file=output_file, quiet=quiet)


def main():
    parser = argparse.ArgumentParser(
        description="Run security scans locally using Trivy and OpenGrep",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python dev-tools/scan_security.py --all
  python dev-tools/scan_security.py --trivy-fs
  python dev-tools/scan_security.py --trivy-image credshare:build
  python dev-tools/scan_security.py --opengrep
  
  # With output files
  python dev-tools/scan_security.py --all --output-dir scan-results
  python dev-tools/scan_security.py --trivy-image credshare:build --json
  python dev-tools/scan_security.py --trivy-fs --output trivy-fs-report.txt
        """
    )
    
    parser.add_argument(
        "--trivy-fs",
        action="store_true",
        help="Run Trivy filesystem scan"
    )
    parser.add_argument(
        "--trivy-image",
        metavar="IMAGE",
        help="Run Trivy image scan on specified image"
    )
    parser.add_argument(
        "--opengrep",
        action="store_true",
        help="Run OpenGrep secret scan"
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Run all scans (filesystem, image, and opengrep)"
    )
    parser.add_argument(
        "--trivyignore",
        default=".trivyignore",
        help="Path to .trivyignore file (default: .trivyignore)"
    )
    parser.add_argument(
        "--output-dir",
        metavar="DIR",
        help="Directory to save scan results (creates timestamped subdirectory if not specified)"
    )
    parser.add_argument(
        "--output",
        metavar="FILE",
        help="Output file for single scan (overrides --output-dir for that scan)"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output Trivy results in JSON format (better for analysis)"
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress console output (results still saved to files if --output-dir or --output specified)"
    )
    
    args = parser.parse_args()
    
    # Change to project root directory
    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    os.chdir(project_root)
    
    # Setup output directory
    output_dir = None
    if args.output_dir:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = Path(args.output_dir) / f"scan_{timestamp}"
        output_dir.mkdir(parents=True, exist_ok=True)
        if not args.quiet:
            print(f"📁 Output directory: {output_dir}")
    
    results = []
    
    # Determine what to run
    run_fs = args.trivy_fs or args.all
    run_image = args.trivy_image is not None or args.all
    run_opengrep_scan = args.opengrep or args.all
    
    if not any([run_fs, run_image, run_opengrep_scan]):
        parser.print_help()
        print("\n✗ No scan type specified. Use --all or specify individual scans.")
        sys.exit(1)
    
    # Determine output files
    fs_output = args.output if args.output and run_fs and not (run_image or run_opengrep_scan) else None
    image_output = args.output if args.output and run_image and not (run_fs or run_opengrep_scan) else None
    opengrep_output = args.output if args.output and run_opengrep_scan and not (run_fs or run_image) else None
    
    if output_dir:
        if not fs_output and run_fs:
            ext = "json" if args.json else "txt"
            fs_output = str(output_dir / f"trivy-fs.{ext}")
        if not image_output and run_image:
            ext = "json" if args.json else "txt"
            image_name_safe = (args.trivy_image or "credshare-build").replace(":", "_").replace("/", "_")
            image_output = str(output_dir / f"trivy-image-{image_name_safe}.{ext}")
        if not opengrep_output and run_opengrep_scan:
            opengrep_output = str(output_dir / "opengrep.txt")
    
    # Run filesystem scan
    if run_fs:
        success, _ = run_trivy_fs(
            args.trivyignore,
            output_file=fs_output,
            json_output=args.json,
            quiet=args.quiet
        )
        results.append(("Trivy FS", success))
    
    # Run image scan
    if run_image:
        image_name = args.trivy_image or "credshare:build"
        success, _ = run_trivy_image(
            image_name,
            args.trivyignore,
            output_file=image_output,
            json_output=args.json,
            quiet=args.quiet
        )
        results.append(("Trivy Image", success))
    
    # Run OpenGrep scan
    if run_opengrep_scan:
        success, _ = run_opengrep(
            output_file=opengrep_output,
            quiet=args.quiet
        )
        results.append(("OpenGrep", success))
    
    # Summary
    if not args.quiet:
        print(f"\n{'='*60}")
        print("Scan Summary")
        print(f"{'='*60}")
        for name, success in results:
            status = "✓ PASSED" if success else "✗ FAILED"
            print(f"{name:20} {status}")
        
        if output_dir:
            print(f"\n📁 All results saved to: {output_dir}")
    
    # Exit with error if any scan failed
    if not all(result[1] for result in results):
        if not args.quiet:
            print("\n⚠ Some scans failed or found issues. Please review the output above.")
        sys.exit(1)
    else:
        if not args.quiet:
            print("\n✓ All scans completed successfully!")
        sys.exit(0)


if __name__ == "__main__":
    main()

