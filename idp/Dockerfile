# Plain ESM JavaScript, no build step.
FROM node:24-alpine
WORKDIR /app
COPY --chown=node:node package.json package-lock.json ./
RUN npm ci --omit=dev
COPY --chown=node:node src ./src
USER node
CMD ["node", "src/index.js"]
