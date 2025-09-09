# Use official Node.js LTS image
FROM node:18

WORKDIR /app

COPY package*.json ./
RUN npm install --production

COPY . .

# Generate Prisma client
RUN npx prisma generate

ENV PORT=8080
EXPOSE 8080

CMD ["npm", "start"]