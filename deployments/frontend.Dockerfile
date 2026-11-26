# Build stage
FROM node:22.14.0-alpine AS builder

WORKDIR /app

COPY frontend/package*.json ./
RUN npm ci

COPY frontend/ ./

ARG VITE_API_BASE_URL=/api
ARG VITE_USE_MOCKS=false
ARG VITE_ROTATION_GRACE_SEC=30
ARG VITE_MAX_CLOCK_SKEW_SEC=30

ENV VITE_API_BASE_URL=${VITE_API_BASE_URL}
ENV VITE_USE_MOCKS=${VITE_USE_MOCKS}
ENV VITE_ROTATION_GRACE_SEC=${VITE_ROTATION_GRACE_SEC}
ENV VITE_MAX_CLOCK_SKEW_SEC=${VITE_MAX_CLOCK_SKEW_SEC}

RUN npm run build

# Runtime stage
FROM nginx:1.27.4-alpine AS runtime

COPY deployments/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=builder /app/dist /usr/share/nginx/html

EXPOSE 80

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -qO- http://127.0.0.1:80/healthz >/dev/null || exit 1
