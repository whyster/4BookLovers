FROM node:18-alpine

WORKDIR /app

# Copy package.json and package-lock.json
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy the rest of the code
COPY . .

# Build the application for production
# RUN npm run build

# Expose port for React development server
EXPOSE 3000

# Start the React development server
CMD ["npm", "start"]