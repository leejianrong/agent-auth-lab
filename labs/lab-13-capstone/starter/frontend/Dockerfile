FROM node:24-slim
WORKDIR /app
COPY --from=harness_frontend . /harness-frontend
COPY package.json package-lock.json ./
RUN npm install
COPY . .
ENV HARNESS_FRONTEND=/harness-frontend
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0", "--port", "5173", "--strictPort"]
