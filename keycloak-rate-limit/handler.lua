-- handler.lua
local http = require "resty.http"
local cjson = require "cjson"

local KeycloakRateLimitHandler = {
  VERSION = "1.0.0",
  PRIORITY = 900, -- Execute before most plugins
}

-- Rate limit configurations
local RATE_LIMITS = {
  premium = { limit = nil, window = 60 },      -- No limit
  diamond = { limit = 10, window = 60 },       -- 10 per minute
  basic = { limit = 1, window = 60 },          -- 1 per minute
}

-- Function to extract bearer token from Authorization header
local function extract_token(authorization_header)
  if not authorization_header then
    return nil, "Missing Authorization header"
  end
  
  local token = authorization_header:match("^Bearer%s+(.+)$")
  if not token then
    return nil, "Invalid Authorization header format"
  end
  
  return token
end

-- Function to introspect token with Keycloak
local function introspect_token(conf, token)
  local httpc = http.new()
  httpc:set_timeout(conf.timeout)
  
  -- Prepare introspection request
  local introspect_url = conf.keycloak_url .. "/realms/" .. conf.realm .. "/protocol/openid-connect/token/introspect"
  
  local res, err = httpc:request_uri(introspect_url, {
    method = "POST",
    body = ngx.encode_args({
      token = token,
      client_id = conf.client_id,
      client_secret = conf.client_secret,
    }),
    headers = {
      ["Content-Type"] = "application/x-www-form-urlencoded",
    },
    ssl_verify = false,
  })
  
  if not res then
    kong.log.err("Failed to introspect token: ", err)
    return nil, "Token introspection failed"
  end
  
  if res.status ~= 200 then
    kong.log.err("Keycloak returned non-200 status: ", res.status)
    return nil, "Invalid token"
  end
  
  local body = cjson.decode(res.body)
  
  if not body.active then
    return nil, "Token is not active"
  end
  
  return body
end

-- Function to get rate limit tier from token claims
local function get_rate_limit_tier(token_data)
  -- First check if client has rate_limit_tier attribute
  if token_data.rate_limit_tier then
    return token_data.rate_limit_tier
  end
  
  -- Fallback: derive from client_id
  local client_id = token_data.client_id or token_data.azp
  
  if not client_id then
    kong.log.warn("No client_id found in token")
    return "basic" -- Default to most restrictive
  end
  
  if string.match(client_id, "premium") then
    return "premium"
  elseif string.match(client_id, "diamond") then
    return "diamond"
  else
    return "basic"
  end
end

-- Main access handler
function KeycloakRateLimitHandler:access(conf)
  kong.log.debug("KeycloakRateLimitHandler: access phase started")
  
  -- Extract token
  local authorization = kong.request.get_header("Authorization")
  local token, err = extract_token(authorization)
  
  if not token then
    kong.log.err("Token extraction failed: ", err)
    return kong.response.exit(401, { message = "Unauthorized: " .. err })
  end
  
  -- Introspect token
  local token_data, err = introspect_token(conf, token)
  
  if not token_data then
    kong.log.err("Token introspection failed: ", err)
    return kong.response.exit(401, { message = "Unauthorized: " .. err })
  end
  
  -- Get rate limit tier
  local tier = get_rate_limit_tier(token_data)
  kong.log.debug("Rate limit tier: ", tier)
  
  -- Get identifier (use client_id or sub)
  local identifier = token_data.client_id or token_data.sub or "unknown"
  
  local config = RATE_LIMITS[tier]
  
  -- Premium has no rate limit
  if not config.limit then
    kong.log.debug("Premium tier - no rate limit")
    kong.service.request.set_header("X-Client-Tier", tier)
    kong.service.request.set_header("X-Client-Id", identifier)
    return
  end
  
  -- Use shared dictionary for rate limiting
  local dict = ngx.shared.kong_rate_limiting_counters
  if not dict then
    kong.log.err("Shared dictionary 'kong_rate_limiting_counters' not found")
    return kong.response.exit(500, { message = "Rate limiting not configured" })
  end
  
  local current_time = ngx.now()
  local window_start = math.floor(current_time / config.window) * config.window
  local cache_key = string.format("rl:%s:%s:%d", tier, identifier, window_start)
  
  -- Atomic increment
  local current_count, err = dict:incr(cache_key, 1, 0, config.window)
  if err then
    kong.log.err("Failed to increment counter: ", err)
    return kong.response.exit(500, { message = "Rate limiting error" })
  end
  
  kong.log.debug("Rate limit check - tier: ", tier, " count: ", current_count, " limit: ", config.limit)
  
  -- Set rate limit headers
  kong.response.set_header("X-RateLimit-Limit", config.limit)
  kong.response.set_header("X-RateLimit-Remaining", math.max(0, config.limit - current_count))
  kong.response.set_header("X-RateLimit-Reset", window_start + config.window)
  
  -- Check if limit exceeded
  if current_count > config.limit then
    kong.log.warn("Rate limit exceeded for tier: ", tier, " identifier: ", identifier)
    return kong.response.exit(429, {
      message = "Rate limit exceeded",
      tier = tier,
      limit = config.limit,
      retry_after = (window_start + config.window) - current_time
    })
  end
  
  -- Set custom headers for upstream
  kong.service.request.set_header("X-Client-Tier", tier)
  kong.service.request.set_header("X-Client-Id", identifier)
end

return KeycloakRateLimitHandler