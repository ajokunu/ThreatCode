FROM node:20.11-alpine
WORKDIR /app
COPY . .
USER node
CMD ["node", "server.js"]
