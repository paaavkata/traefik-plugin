FROM traefik:v3.1

# Copy the plugin source into the local plugins directory.
COPY . /plugins-local/src/github.com/fileconvert/traefik-gateway-plugin/
