# Name the node stage "builder"
FROM node:16 AS builder

ARG PORT
ARG DB_CONNECTION_STRING

ENV PORT ${PORT}
ENV DB_CONNECTION_STRING ${DB_CONNECTION_STRING}

# Set working directory
WORKDIR /build
COPY package*.json yarn.lock ./

# install node modules
RUN yarn

# Copy all files from current directory to working dir in image
COPY . .
CMD [ "yarn", "start" ]
