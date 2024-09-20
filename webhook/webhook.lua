local cjson = require("cjson")
local class = require("middleclass")
local http = require("resty.http")
local plugin = require("bunkerweb.plugin")
local utils = require("bunkerweb.utils")

local webhook = class("webhook", plugin)

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
local get_country = utils.get_country
local get_asn = utils.get_asn
local tostring = tostring
local encode = cjson.encode

function webhook:initialize(ctx)
	-- Call parent initialize
	plugin.initialize(self, "webhook", ctx)
end

function webhook:log(bypass_use_webhook)
	-- Check if webhook is enabled
	if not bypass_use_webhook then
		if self.variables["USE_WEBHOOK"] ~= "yes" then
			return self:ret(true, "webhook plugin not enabled")
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
        local request_method = self.ctx.bw.request_method
        local country, err = get_country(self.ctx.bw.remote_addr)
        if not country then
            elf.logger:log(ERR, "can't get Country of IP " .. remote_addr .. " : " .. err)
            country = "Country unknown"
        else
            country = "Country " .. tostring(country)
        end
        local asn, err = get_asn(remote_addr)
        if not asn then
            self.logger:log(ERR, "can't get ASN of IP " .. remote_addr .. " : " .. err)
            asn = "ASN unknown"
        else
            asn = "ASN " .. tostring(asn)
        end
	local data = {}
	local message_key = self.variables["MESSAGE_KEY"] or "content"
        data[message_key] = request_time .. ":<br>"
	data[message_key] = data[message_key] .. "Denied " .. request_method .. " from <b>" .. remote_addr .. "</b> (" .. country .. " | " .. asn .. ") to " .. request_host .. self.ctx.bw.uri .. "<br>"
	data[message_key] = data[message_key] .. "Reason " .. reason .. " (" .. encode(reason_data or {}) .. ").<br>"
        -- Add headers if enabled
	if self.variables["INCLUDE_HEADERS"] == "yes" then
                data[message_key] = data[message_key] .. "<br>"
		local headers, err = ngx_req.get_headers()
		if not headers then
			data[message_key] = data[message_key] .. "error while getting headers: " .. err .. "<br>"
		else
			for header, value in pairs(headers) do
				data[message_key] = data[message_key] .. header .. ": " .. value .. "<br>"
			end
		end
	end
	-- Anonymize IP if enabled
	if self.variables["ANONYMIZE_IP"] == "yes" then
		remote_addr = string.gsub(remote_addr, "%d+%.%d+$", "xxx.xxx")
		data[message_key] = string.gsub(data[message_key], self.ctx.bw.remote_addr, remote_addr)
	end
	-- Send request via webhook
	local hdr, err = ngx_timer.at(0, self.send, self, data)
	if not hdr then
		return self:ret(true, "can't create report timer: " .. err)
	end
	return self:ret(true, "scheduled timer")
end

-- luacheck: ignore 212
function webhook.send(premature, self, data)
	local httpc, err = http_new()
	if not httpc then
		self.logger:log(ERR, "can't instantiate http object : " .. err)
	end
	local res, err_http = httpc:request_uri(self.variables["WEBHOOK_URL"], {
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
	if self.variables["WEBHOOK_RETRY_IF_LIMITED"] == "yes" and res.status == 429 and res.headers["Retry-After"] then
		self.logger:log(WARN, "HTTP endpoint is rate-limiting us, retrying in " .. res.headers["Retry-After"] .. "s")
		local hdr
		hdr, err = ngx_timer.at(res.headers["Retry-After"], self.send, self, data)
		if not hdr then
			self.logger:log(ERR, "can't create report timer : " .. err)
			return
		end
		return
	end
	if res.status < 200 or res.status > 299 then
		self.logger:log(ERR, "request returned status " .. tostring(res.status))
		return
	end
	self.logger:log(INFO, "request sent to webhook")
end

function webhook:log_default()
	-- Check if webhook is activated
	local check, err = has_variable("USE_WEBHOOK", "yes")
	if check == nil then
		return self:ret(false, "error while checking variable USE_WEBHOOK (" .. err .. ")")
	end
	if not check then
		return self:ret(true, "webhook plugin not enabled")
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

function webhook:api()
	if self.ctx.bw.uri == "/webhook/ping" and self.ctx.bw.request_method == "POST" then
		-- Check webhook connection
		local check, err = has_variable("USE_WEBHOOK", "yes")
		if check == nil then
			return self:ret(true, "error while checking variable USE_WEBHOOK (" .. err .. ")")
		end
		if not check then
			return self:ret(true, "Webhook plugin not enabled")
		end

		-- Send test data to webhook webhook
		local data = {}
		local message_key = self.variables["MESSAGE_KEY"] or "content"
		data[message_key] = "```Test message from bunkerweb```"
		-- Send request
		local httpc
		httpc, err = http_new()
		if not httpc then
			self.logger:log(ERR, "can't instantiate http object : " .. err)
		end
		local res, err_http = httpc:request_uri(self.variables["WEBHOOK_URL"], {
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
		if self.variables["WEBHOOK_RETRY_IF_LIMITED"] == "yes" and res.status == 429 and res.headers["Retry-After"] then
			return self:ret(
				true,
				"webhook API is rate-limiting us, retry in " .. res.headers["Retry-After"] .. "s",
				HTTP_TOO_MANY_REQUESTS
			)
		end
		if res.status < 200 or res.status > 299 then
			return self:ret(true, "request returned status " .. tostring(res.status), HTTP_INTERNAL_SERVER_ERROR)
		end
		return self:ret(true, "request sent to webhook", HTTP_OK)
	end
	return self:ret(false, "success")
end

return webhook