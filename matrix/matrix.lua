local cjson = require("cjson")
local class = require("middleclass")
local http = require("resty.http")
local plugin = require("bunkerweb.plugin")
local utils = require("bunkerweb.utils")

local matrix = class("matrix", plugin)

local ngx = ngx
local ngx_req = ngx.req
local ERR = ngx.ERR
local WARN = ngx.WARN
local INFO = ngx.INFO
local ngx_timer = ngx.timer
local HTTP_INTERNAL_SERVER_ERROR = ngx.HTTP_INTERNAL_SERVER_ERROR
local HTTP_TOO_MANY_REQUESTS = ngx.HTTP_TOO_MANY_REQUESTS
local HTTP_OK = ngx.HTTP_OK
local http_new = http.new
local has_variable = utils.has_variable
local get_variable = utils.get_variable
local get_reason = utils.get_reason
local tostring = tostring
local encode = cjson.encode

-- Matrix API Parameter
local base_url = self.variables["MATRIX_BASE_URL"]
local access_token = self.variables["MATRIX_ACCESS_TOKEN"]
local room_id = self.variables["MATRIX_ROOM_ID"]
local txn_id = tostring(os.time())

function matrix:initialize(ctx)
	-- Call parent initialize
	plugin.initialize(self, "matrix", ctx)
end

function matrix:log(bypass_use_matrix)
	-- Check if matrix is enabled
	if not bypass_use_matrix then
		if self.variables["USE_MATRIX"] ~= "yes" then
			return self:ret(true, "matrix plugin not enabled")
		end
	end
	-- Check if request is denied
	local reason, reason_data = get_reason(self.ctx)
	if reason == nil then
		return self:ret(true, "request not denied")
	end
	-- Compute data
	local request_time = ngx.var.time_iso8601
	local request_host = ngx.var.host or "unknown host"
	local remote_addr = self.ctx.bw.remote_addr
	local data = {}
	local message_key = self.variables["MESSAGE_KEY"] or "content"
	data[message_key] = "Denied request from IP " .. remote_addr .. " to " .. request_host .. " at " .. request_time .. ".\n"
	data[message_key] = data[message_key] .. "Reason " .. reason .. " (" .. encode(reason_data or {}) .. ").\n\n"
	data[message_key] = data[message_key] .. ngx.var.request .. "\n"
	-- Add headers if enabled
	if self.variables["INCLUDE_HEADERS"] == "yes" then
		local headers, err = ngx_req.get_headers()
		if not headers then
			data[message_key] = data[message_key] .. "error while getting headers: " .. err .. "\n"
		else
			for header, value in pairs(headers) do
				data[message_key] = data[message_key] .. header .. ": " .. value .. "\n"
			end
		end
	end
	-- Anonymize IP if enabled
	if self.variables["ANONYMIZE_IP"] == "yes" then
		remote_addr = string.gsub(remote_addr, "%d+%.%d+$", "xxx.xxx")
		data[message_key] = string.gsub(data[message_key], self.ctx.bw.remote_addr, remote_addr)
	end
	-- Send request via matrix
	local hdr, err = ngx_timer.at(0, self.send, self, data)
	if not hdr then
		return self:ret(true, "can't create report timer: " .. err)
	end
	return self:ret(true, "scheduled timer")
end

-- luacheck: ignore 212
function matrix.send(premature, self, data)
	local httpc, err = http_new()
	if not httpc then
		self.logger:log(ERR, "can't instantiate http object : " .. err)
	end
	-- URL für den API-Request
        local url = string.format("%s/_matrix/client/r0/rooms/%s/send/m.room.message/%s", base_url, room_id, txn_id)
    
        -- JSON-Daten kodieren
        local message_data = {
            msgtype = "m.text",
            body = data["html"]
        }
        local post_data = cjson.encode(message_data)
        -- Sende HTTP-Request (PUT) mit Authorization Bearer Token
        local res, err_http = httpc:request_uri(url, {
            method = "PUT",
            body = post_data,
            headers = {
                ["Content-Type"] = "application/json",
                ["Authorization"] = "Bearer " .. access_token  -- Access Token im Header
            }
        })
	httpc:close()
	if not res then
		self.logger:log(ERR, "error while sending request : " .. err_http)
	end
	if res.status < 200 or res.status > 299 then
		self.logger:log(ERR, "request returned status " .. tostring(res.status))
		return
	end
	self.logger:log(INFO, "request sent to matrix")
end

function matrix:log_default()
	-- Check if matrix is activated
	local check, err = has_variable("USE_MATRIX", "yes")
	if check == nil then
		return self:ret(false, "error while checking variable USE_MATRIX (" .. err .. ")")
	end
	if not check then
		return self:ret(true, "matrix plugin not enabled")
	end
	-- Check if default server is disabled
	check, err = get_variable("DISABLE_DEFAULT_SERVER", false)
	if check == nil then
		return self:ret(false, "error while getting variable DISABLE_DEFAULT_SERVER (" .. err .. ")")
	end
	if check ~= "yes" then
		return self:ret(true, "default server not disabled")
	end
	-- Call log method
	return self:log(true)
end

function matrix:api()
	if self.ctx.bw.uri == "/matrix/ping" and self.ctx.bw.request_method == "POST" then
		-- Check matrix connection
		local check, err = has_variable("USE_MATRIX", "yes")
		if check == nil then
			return self:ret(true, "error while checking variable USE_MATRIX (" .. err .. ")")
		end
		if not check then
			return self:ret(true, "matrix plugin not enabled")
		end

		-- Send test data to matrix room
		local data = {}
		local message_key = self.variables["MESSAGE_KEY"] or "content"
		data[message_key] = "```Test message from bunkerweb```"
		-- Send request
		local httpc
		httpc, err = http_new()
		if not httpc then
			self.logger:log(ERR, "can't instantiate http object : " .. err)
		end
		local res, err_http = httpc:request_uri(self.variables["MATRIX_BASE_URL"], {
		--TODO: url verwenden
			method = "POST",
			headers = {
				["Content-Type"] = "application/json",
			},
			body = encode(data),
		})
		httpc:close()
		if not res then
			self.logger:log(ERR, "error while sending request : " .. err_http)
		end
		if res.status < 200 or res.status > 299 then
			return self:ret(true, "request returned status " .. tostring(res.status), HTTP_INTERNAL_SERVER_ERROR)
		end
		return self:ret(true, "request sent to matrix", HTTP_OK)
	end
	return self:ret(false, "success")
end

return matrix