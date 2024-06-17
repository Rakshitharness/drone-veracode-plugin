# Use Alpine Linux as the base image for the final stage
FROM alpine:latest

# # Install Gradle and Java using apk
RUN apk add --no-cache openjdk11-jre curl unzip

# Copy the built Go executable from the builder stage to the final stage
COPY release/linux/amd64/drone-veracode-plugin /bin/

# Set the entrypoint to the Go executable
ENTRYPOINT ["/bin/drone-veracode-plugin"]
