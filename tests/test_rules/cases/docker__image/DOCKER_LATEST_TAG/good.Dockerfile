FROM node:20.11-alpine
WORKDIR /app
USER node
CMD ["node", "server.js"]
