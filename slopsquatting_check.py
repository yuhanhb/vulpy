"""
=============================================================
SLOPSQUATTING DETECTION SCRIPT - slopsquatting_check.py
=============================================================
This script reads every package listed in requirements.txt
and checks each one against the PyPI registry (the official
Python package database).

It scores each package based on suspicion signals that are
known indicators of slopsquatting. If a package scores too
high, the build fails and a developer must review it.
=============================================================
"""

import sys
import json
import requests
from datetime import datetime, timezone
from dateutil.parser import parse as parse_date

# ─────────────────────────────────────────────
# CONFIGURATION
# How suspicious does a package need to be before
# we stop the build? Score of 60+ = block it.
# ─────────────────────────────────────────────
SUSPICION_THRESHOLD = 60

# How recent is "too new"? Packages registered within
# 30 days are more suspicious — attackers register them
# AFTER watching AI hallucinate the name repeatedly.
NEW_PACKAGE_DAYS = 30

# Packages with very few downloads haven't been vetted
# by the community at all. Real packages get used.
LOW_DOWNLOAD_THRESHOLD = 500


def read_requirements(filepath="requirements.txt"):
    """
    Read the requirements.txt file — this is the standard file
    where Python projects list all their dependencies (packages).
    Returns a clean list of package names, ignoring comments and
    version numbers (e.g. 'requests==2.28.0' becomes 'requests').
    """
    packages = []
    try:
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                # Skip blank lines and comments (lines starting with #)
                if not line or line.startswith("#"):
                    continue
                # Strip version specifiers like ==, >=, <=, ~=
                for sep in ["==", ">=", "<=", "~=", "!="]:
                    if sep in line:
                        line = line.split(sep)[0].strip()
                packages.append(line)
    except FileNotFoundError:
        print("⚠️  No requirements.txt found. Skipping check.")
        sys.exit(0)
    return packages


def query_pypi(package_name):
    """
    Hit the PyPI API (PyPI is the official Python package registry).
    This is publicly available — no login needed.
    Returns the package data if it exists, or None if it doesn't exist at all.

    A package that doesn't exist on PyPI = automatic red flag.
    An AI hallucinated it. An attacker may have already registered it.
    """
    url = f"https://pypi.org/pypi/{package_name}/json"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            return None  # Package doesn't exist
    except requests.RequestException:
        print(f"  ⚠️  Could not reach PyPI for {package_name}. Skipping.")
        return "network_error"


def get_download_count(package_name):
    """
    Query the PyPI Stats API to get the last 30 days of downloads.
    Low download counts are suspicious — real packages get used by
    many developers. A package with 12 downloads in 30 days that
    your AI just recommended is a red flag.
    """
    url = f"https://pypistats.org/api/packages/{package_name}/recent"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            return data.get("data", {}).get("last_month", 0)
    except requests.RequestException:
        pass
    return None  # Unknown


def score_package(package_name, pypi_data):
    """
    THE CORE DETECTION LOGIC.

    We assign a suspicion score based on known slopsquatting signals.
    Each signal adds points. Higher score = more suspicious.

    Signals are based on real research into how hallucinated packages
    behave differently from legitimate packages.
    """
    score = 0
    flags = []

    # ── SIGNAL 1: Package doesn't exist on PyPI ──────────────────
    # This is the most obvious signal. If the AI hallucinated a name
    # and an attacker already registered it, it WILL appear on PyPI.
    # But if it's not there yet, that's still a critical warning —
    # the developer is about to install something that doesn't exist.
    if pypi_data is None:
        score += 100  # Instant block — doesn't exist at all
        flags.append("❌ CRITICAL: Package does not exist on PyPI")
        return score, flags

    if pypi_data == "network_error":
        flags.append("⚠️  Could not verify — network error")
        return 0, flags

    info = pypi_data.get("info", {})

    # ── SIGNAL 2: Package was registered very recently ────────────
    # Attackers register packages AFTER watching LLMs hallucinate
    # the same name repeatedly. A brand new package that your AI
    # just suggested warrants immediate suspicion.
    releases = pypi_data.get("releases", {})
    if releases:
        # Find the earliest release date across all versions
        all_dates = []
        for version_files in releases.values():
            for f in version_files:
                upload_time = f.get("upload_time")
                if upload_time:
                    all_dates.append(parse_date(upload_time).replace(tzinfo=timezone.utc))

        if all_dates:
            first_published = min(all_dates)
            days_old = (datetime.now(timezone.utc) - first_published).days
            if days_old < NEW_PACKAGE_DAYS:
                score += 40
                flags.append(f"🆕 NEW: Package only {days_old} days old (registered {first_published.date()})")

    # ── SIGNAL 3: Very few downloads ─────────────────────────────
    # Legitimate packages get used. A package with almost no
    # downloads has not been vetted by the developer community.
    downloads = get_download_count(package_name)
    if downloads is not None and downloads < LOW_DOWNLOAD_THRESHOLD:
        score += 25
        flags.append(f"📉 LOW DOWNLOADS: Only {downloads} downloads in the last 30 days")

    # ── SIGNAL 4: No description or documentation ─────────────────
    # Real packages have READMEs and descriptions. Quickly registered
    # malicious packages often have nothing — they're hollow shells.
    description = info.get("summary", "") or ""
    if len(description.strip()) < 10:
        score += 15
        flags.append("📭 NO DESCRIPTION: Package has no meaningful summary")

    # ── SIGNAL 5: No maintainer information ───────────────────────
    # Anonymous or empty maintainer fields are common in quickly
    # spun-up malicious packages.
    author = info.get("author", "") or ""
    maintainer = info.get("maintainer", "") or ""
    if not author.strip() and not maintainer.strip():
        score += 10
        flags.append("👤 NO AUTHOR: No author or maintainer listed")

    # ── SIGNAL 6: No GitHub/source link ──────────────────────────
    # Legitimate open source packages almost always link to their
    # source code. No source link = no transparency.
    project_urls = info.get("project_urls") or {}
    source_keywords = ["github", "source", "repository", "code"]
    has_source = any(
        any(kw in (url or "").lower() for kw in source_keywords)
        for url in project_urls.values()
    )
    if not has_source:
        score += 10
        flags.append("🔗 NO SOURCE LINK: No repository or source code link found")

    return score, flags


def main():
    """
    Main runner. Reads packages, scores each one, prints a report,
    and exits with a failure code if anything is too suspicious.
    Exiting with code 1 tells GitHub Actions to FAIL the build.
    """
    print("=" * 60)
    print("  SLOPSQUATTING DETECTION — Package Trust Check")
    print("=" * 60)

    packages = read_requirements()
    if not packages:
        print("No packages found in requirements.txt.")
        sys.exit(0)

    print(f"\n🔍 Checking {len(packages)} package(s)...\n")

    blocked = []

    for pkg in packages:
        print(f"  Checking: {pkg}")
        pypi_data = query_pypi(pkg)
        score, flags = score_package(pkg, pypi_data)

        if flags:
            for flag in flags:
                print(f"    {flag}")

        if score >= SUSPICION_THRESHOLD:
            print(f"    🚨 SUSPICION SCORE: {score}/100 — BUILD BLOCKED\n")
            blocked.append((pkg, score, flags))
        else:
            print(f"    ✅ Score: {score}/100 — OK\n")

    print("=" * 60)

    if blocked:
        print(f"\n🚨 BUILD FAILED — {len(blocked)} suspicious package(s) detected:\n")
        for pkg, score, flags in blocked:
            print(f"  • {pkg} (score: {score})")
            for flag in flags:
                print(f"      {flag}")
        print("\n  → A developer must review these packages before merging.")
        print("  → Check if they were AI-generated suggestions.")
        print("  → Verify on PyPI manually: https://pypi.org/project/<name>/\n")
        sys.exit(1)  # Exit code 1 = failure = GitHub Actions blocks the build
    else:
        print("\n✅ All packages passed the slopsquatting check.\n")
        sys.exit(0)  # Exit code 0 = success = build continues


if __name__ == "__main__":
    main()
