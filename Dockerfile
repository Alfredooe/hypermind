FROM node:18-alpine

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache python3 make g++ linux-headers git

COPY package*.json ./

# Install dependencies with build flags for udx-native
RUN npm install --production --build-from-source

COPY server.js ./

ENV PORT=3000
ENV NODE_ENV=production

EXPOSE 3000

CMD ["node", "server.js"]
