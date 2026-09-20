# NetWatch Telnet-AttackPod - Improvements

This document describes the improvements made to the Telnet-AttackPod codebase.

## Changes Made

### 1. Fixed Missing Import
- Added missing `import random` to resolve error in line 393
- This ensures proper functioning of the randomized delay between login attempts

### 2. Enhanced Docker Multi-architecture Support
- Updated Dockerfile with `--platform=linux/amd64` to ensure correct base image selection
- Created `build.sh` script for building multi-architecture images (amd64 and arm64)
- Modified docker-compose.yml to properly reference the Dockerfile location

### 3. Improved API Communication
- Added User-Agent header to requests for better identification
- Maintained existing authentication approach with Authorization header

## Architecture Support

The updated build system now supports building images for:
- AMD64 (x86_64)
- ARM64 (arm64/aarch64)

This enables running the AttackPod on various hardware platforms including Raspberry Pi and servers.

## Build Instructions

1. **Normal Build:**
   ```bash
   docker compose build --no-cache
   ```

2. **Multi-architecture Build (Recommended):**
   ```bash
   ./build.sh
   ```
   
3. **Run the Container:**
   ```bash
   docker compose up --force-recreate -d && docker compose logs -tf
   ```