FROM node:22-bookworm

WORKDIR /app

COPY sdk/javascript/rulia-js /opt/rulia-js
RUN cd /opt/rulia-js && npm ci && npm run build

COPY examples/services/sdk-gateway/src ./src

ENV HOST=0.0.0.0
ENV PORT=8080
ENV RULIA_JS_PATH=/opt/rulia-js/dist/index.js

EXPOSE 8080
CMD ["node", "src/main.js"]
