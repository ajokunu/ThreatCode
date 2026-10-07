FROM node:20.11-alpine
COPY . .
USER node
CMD ["node", "server.js"]
