# Build from the repo root:  docker build -f frontend/Dockerfile .   (docker-compose.yml does this)
FROM node:22-alpine AS build
WORKDIR /app
COPY frontend/dashboard-app/package*.json ./
RUN npm ci
COPY frontend/dashboard-app/ ./
# Baked into the JavaScript at build time. The dashboard's default data mode is "mock", so "real" is required
# here or it would show generated demo data instead of talking to the backend.
ARG VITE_API_BASE_URL=http://localhost:8000
ARG VITE_DATA_MODE=real
ENV VITE_API_BASE_URL=$VITE_API_BASE_URL VITE_DATA_MODE=$VITE_DATA_MODE
RUN npm run build

FROM nginx:1.27-alpine
COPY --from=build /app/dist /usr/share/nginx/html
RUN printf 'server { listen 80; root /usr/share/nginx/html; location / { try_files $uri /index.html; } }' > /etc/nginx/conf.d/default.conf
EXPOSE 80
