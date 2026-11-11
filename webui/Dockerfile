# syntax=docker/dockerfile:1

########################
# Builder: build static
########################
FROM node:20-alpine AS builder
WORKDIR /app

# Install deps first for better cache
COPY package*.json ./
RUN npm ci --no-audit --no-fund

# Copy sources and build
COPY . .
RUN npm run build:static

########################
# Runtime: Nginx serve
########################
FROM nginx:alpine AS runtime

# Copy nginx config
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copy exported static site
COPY --from=builder /app/out /usr/share/nginx/html

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]


