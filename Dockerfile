FROM node:18 AS build
WORKDIR /app
COPY package*.json ./

# Explicitly install dependencies including node-sass-chokidar
RUN npm install --legacy-peer-deps --force && \
    npm install node-sass-chokidar --legacy-peer-deps --force && \
    npm cache clean --force

COPY . .

# Ensure node-sass-chokidar runs before build
RUN npx node-sass-chokidar src/ -o src/ && npm run build

# Production stage
FROM nginx:1.25.3-alpine
COPY --from=build /app/build /usr/share/nginx/html
COPY nginx.conf /etc/nginx/nginx.conf
EXPOSE 8080
CMD ["nginx", "-g", "daemon off;"]