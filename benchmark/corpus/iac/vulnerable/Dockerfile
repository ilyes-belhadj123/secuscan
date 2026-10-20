# Benchmark : image Docker mal configurée (vulnérable).
FROM node:latest
WORKDIR /app
ENV DATABASE_PASSWORD=Bench-Docker-Pass-2024
ADD https://example.com/tools/agent.tar.gz /opt/agent.tar.gz
RUN curl -fsSL https://example.com/install.sh | sh
COPY . .
RUN npm install && chmod -R 777 /app
EXPOSE 3000
CMD ["node", "server.js"]
