FROM node:24-alpine AS build

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . .

ARG VITE_API_URL=http://localhost:8000
ARG VITE_TEMPORAL_UI_URL=http://localhost:8081
ARG VITE_CLIENT_ID=oauth2-client
ARG VITE_AI_ENABLED=false
ENV VITE_API_URL=$VITE_API_URL \
	VITE_TEMPORAL_UI_URL=$VITE_TEMPORAL_UI_URL \
	VITE_CLIENT_ID=$VITE_CLIENT_ID \
	VITE_AI_ENABLED=$VITE_AI_ENABLED

RUN npm run build

FROM nginxinc/nginx-unprivileged:1.31-alpine

USER root
# Pull in patched Alpine packages to clear known OS-level CVEs.
RUN apk upgrade --no-cache
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
RUN chmod -R a+rX /usr/share/nginx/html
USER nginx

EXPOSE 3000