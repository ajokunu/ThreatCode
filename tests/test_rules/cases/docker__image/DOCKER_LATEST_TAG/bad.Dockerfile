FROM node:latest
WORKDIR /app
USER node
CMD ["node", "server.js"]
