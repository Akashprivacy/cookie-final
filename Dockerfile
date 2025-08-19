FROM node:18-bullseye-slim

# Install Chrome/system dependencies for Puppeteer
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

# Copy package files for both frontend (root) and backend
COPY package*.json ./
COPY backend/package*.json ./backend/

# Install dependencies
RUN npm install
RUN cd backend && npm install

# Copy frontend files (your actual structure)
COPY index.html index.tsx App.tsx types.ts ./
COPY vite.config.ts tailwind.config.js postcss.config.js tsconfig.json ./
COPY components/ ./components/
COPY styles/ ./styles/
COPY services/ ./services/

# Copy backend files
COPY backend/ ./backend/

# Build frontend using Vite (builds from root where your files are)
RUN npm run build

# Copy built frontend to backend's public directory
RUN mkdir -p /app/backend/public && \
    cp -r /app/dist/* /app/backend/public/

# Build backend TypeScript to dist/
RUN cd backend && npm run build

# Set environment variables
ENV NODE_ENV=production
ENV PORT=8080

# Switch to backend directory for runtime
WORKDIR /app/backend

# Expose port
EXPOSE 8080

# Start the compiled backend server (your exact start command)
CMD ["npm", "start"]
