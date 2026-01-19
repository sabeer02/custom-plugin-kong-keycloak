FROM kong:3.5

USER root

# Create plugin directory in the standard Kong plugins location
RUN mkdir -p /usr/local/share/lua/5.1/kong/plugins/keycloak-rate-limit

# Copy plugin files
COPY keycloak-rate-limit/handler.lua /usr/local/share/lua/5.1/kong/plugins/keycloak-rate-limit/
COPY keycloak-rate-limit/schema.lua /usr/local/share/lua/5.1/kong/plugins/keycloak-rate-limit/

# Set proper permissions
RUN chown -R kong:kong /usr/local/share/lua/5.1/kong/plugins/keycloak-rate-limit

USER kong
