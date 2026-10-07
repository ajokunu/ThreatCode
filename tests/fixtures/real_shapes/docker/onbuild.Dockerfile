FROM node:20-alpine AS base
WORKDIR /usr/src/app
ONBUILD COPY package*.json ./
ONBUILD RUN npm ci --omit=dev
ONBUILD COPY . .
USER node
CMD ["node", "server.js"]
