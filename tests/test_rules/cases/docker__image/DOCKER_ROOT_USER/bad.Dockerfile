FROM node:20.11-alpine
WORKDIR /app
COPY . .
USER root
CMD ["node", "server.js"]
