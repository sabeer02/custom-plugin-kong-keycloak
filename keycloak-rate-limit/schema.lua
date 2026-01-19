-- schema.lua
local typedefs = require "kong.db.schema.typedefs"

return {
  name = "keycloak-rate-limit",
  fields = {
    { protocols = typedefs.protocols_http },
    { config = {
        type = "record",
        fields = {
          { keycloak_url = {
              type = "string",
              required = true,
              default = "http://192.168.181.75:8080",
              description = "Keycloak server URL"
          }},
          { realm = {
              type = "string",
              required = true,
              default = "sabeer",
              description = "Keycloak realm name"
          }},
          { client_id = {
              type = "string",
              required = true,
              description = "Client ID for introspection"
          }},
          { client_secret = {
              type = "string",
              required = true,
              description = "Client secret for introspection"
          }},
          { timeout = {
              type = "number",
              default = 10000,
              description = "Timeout for Keycloak requests in milliseconds"
          }},
        },
    }},
  },
}