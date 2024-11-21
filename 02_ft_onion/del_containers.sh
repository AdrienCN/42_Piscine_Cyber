#!/bin/bash

# Stop all running containers
echo "Stopping all running containers..."
docker ps -q | xargs -r docker stop

# Remove all containers (stopped and running)
echo "Removing all containers..."
docker ps -a -q | xargs -r docker rm

# Optional: Remove unused images, volumes, and networks
echo "Cleaning up unused Docker resources..."
docker system prune -f --volumes

echo "All containers stopped and removed. System cleaned!"
