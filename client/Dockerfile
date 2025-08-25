FROM node:22-alpine AS dependencies
ENV NODE_ENV=development
WORKDIR /dependencies
COPY package.json package-lock.json* pnpm-lock.yaml* yarn.lock* ./
RUN npm install

FROM node:22-alpine AS development
ENV NODE_ENV=development
WORKDIR /app
COPY ./package.json .
COPY --from=dependencies /dependencies/node_modules /app/node_modules
# RUN npm install
# COPY . .
EXPOSE 5173
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]
