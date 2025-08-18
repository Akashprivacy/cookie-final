FROM node:18-bullseye-slim

# Install Chrome dependencies and system packages
RUN apt-get update && apt-get install -y \
    libasound2 \
    libatk-bridge2.0-0 \
    libdrm2 \
    libxkbcommon0 \
    libxcomposite1 \
    libxdamage1 \
    libxrandr2 \
    libgbm1 \
    libxss1 \
    libgtk-3-0 \
    libnss3 \
    libxext6 \
    libxfixes3 \
    libxi6 \
    libxrender1 \
    libxtst6 \
    ca-certificates \
    fonts-liberation \
    lsb-release \
    xdg-utils \
    wget \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy package files first (for better caching)
COPY package*.json ./
COPY backend/package*.json ./backend/

# Install dependencies
RUN npm install
RUN cd backend && npm install

# Install additional frontend dependencies
RUN npm install jspdf html2canvas && \
    npm install --save-dev @types/html2canvas
    
# Copy all source code
COPY . .

# Build backend
RUN cd backend && npm run build

# Create start script for Docker
RUN echo '#!/bin/bash\necho "Starting Cookie Care in Docker..."\necho "Starting backend..."\ncd backend && npm run dev &\necho "Waiting for backend..."\nsleep 8\necho "Starting frontend..."\nnpm run dev -- --port $PORT --host 0.0.0.0\nwait' > docker-start.sh && chmod +x docker-start.sh

# Expose ports
EXPOSE 3001 5174

# Default command
CMD ["./docker-start.sh"]
