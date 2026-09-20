#!/bin/bash

# Multi-architecture Docker build script for NetWatch Telnet-AttackPod

echo "Building multi-architecture Docker image for Telnet-AttackPod..."

# Create a builder instance if it doesn't exist
if ! docker buildx ls | grep -q "multiarch"; then
    echo "Creating multi-architecture builder..."
    docker buildx create --name multiarch --use
fi

# Build for multiple platforms
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --tag netwatchteam/netwatch_telnet-attackpod:v0.2 \
  --output "type=image,push=false" \
  -f src/Dockerfile src/

echo "Multi-architecture build complete!"