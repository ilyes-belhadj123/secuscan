# Benchmark : même image, configurée de façon sûre (aucune alerte attendue).
FROM node:22.11-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY . .
RUN chown -R node:node /app
USER node
EXPOSE 3000
CMD ["node", "server.js"]
