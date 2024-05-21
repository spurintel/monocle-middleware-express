# Use the official Node.js 16 image as base
FROM node:16

# Set the working directory in the Docker image
WORKDIR /usr/src/app

# Copy package.json and package-lock.json
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy the rest of the application
COPY . .

# Compile TypeScript files
RUN npm run build

# Expose the port your app runs on
EXPOSE 3000

# Start the application
CMD [ "npm", "start" ]