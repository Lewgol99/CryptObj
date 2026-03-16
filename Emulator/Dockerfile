FROM node:16
COPY start.sh /
WORKDIR /usr/src/app
COPY . .
WORKDIR /usr/src/app/frontend
RUN npm install
RUN npm install -D webpack-cli@4.9.1 webpack@5.14.0 ts-loader@8.0.14 typescript@4.1.3 @types/node@16.18.0
RUN ./node_modules/.bin/webpack --mode production
WORKDIR /usr/src/app/backend
RUN npm install
RUN npm install -D typescript
RUN ./node_modules/.bin/tsc
ENTRYPOINT ["sh", "/start.sh"]
