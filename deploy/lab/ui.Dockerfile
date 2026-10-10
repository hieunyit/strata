# Lab UI: builds ui/ and serves it with the API proxied to the control plane.
FROM node:24.21.0-bookworm-slim AS build
WORKDIR /ui
COPY ui/package.json ui/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY ui/ ./
RUN npm run build

FROM nginx:1.30.5
COPY deploy/lab/ui/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /ui/dist /usr/share/nginx/html
