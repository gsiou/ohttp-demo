FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY tsconfig.json ./
# COPY src ./src
EXPOSE 3003
ENV PORT=3003
CMD ["npm", "run", "dev"]
