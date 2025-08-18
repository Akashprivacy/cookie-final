FROM node:18-bullseye-slim

# Install Chrome/system dependencies if you really need Puppeteer-like features
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

# Copy package files
COPY package*.json ./
COPY backend/package*.json ./backend/

# Install dependencies
RUN npm install
RUN cd backend && npm install

# Install any extra frontend libs
RUN npm install jspdf html2canvas && \
    npm install --save-dev @types/html2canvas

# Copy all source
COPY . .

# Build frontend (Vite → dist/)
RUN npm run build

# Environment variable for Cloud Run
ENV PORT=8080

# Switch to backend directory
WORKDIR /app/backend

# Start backend in production mode
CMD ["npm", "start"]
