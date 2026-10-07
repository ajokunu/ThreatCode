FROM node:20-alpine AS build
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci

FROM gcr.io/distroless/nodejs20-debian12:nonroot
COPY --from=build /src /app
USER 65532
CMD ["/app/server.js"]
