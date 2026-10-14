FROM node:20.11-alpine
WORKDIR /app
COPY . .
CMD ["node", "server.js"]
