FROM oven/bun:1.3.14 AS builder

WORKDIR /app
COPY web/operator/package.json web/operator/bun.lock ./
RUN bun install --frozen-lockfile
COPY web/operator ./
RUN bun run build

FROM nginx:1.29-alpine

COPY web/operator/nginx.conf.template /etc/nginx/templates/default.conf.template
COPY --from=builder /app/dist /usr/share/nginx/html

EXPOSE 80