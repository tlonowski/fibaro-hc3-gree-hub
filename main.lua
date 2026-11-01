--[[
%% autostart
%% properties
%% events
%% globals
]]

---@diagnostic disable: inject-field, undefined-global, undefined-field, param-type-mismatch, assign-type-mismatch, need-check-nil, redundant-parameter

--[[
GREE AC QuickApp Hub / Gateway (Fibaro Home Center 3)
Wersja 2.0 – Architektura Hub + Urządzenia Potomne (Child Devices)

Autor: Tomasz Lonowski
- Główny QuickApp działa jako Bramka / Hub sieciowy Gree:
  * Zarządza pojedynczym gniazdem UDP na porcie 7000 (brak konfliktów portów w HC3).
  * Automatycznie skanuje sieć LAN (broadcast 255.255.255.255:7000) w poszukiwaniu wszystkich klimatyzatorów Gree w domu.
  * Tworzy dedykowane urządzenia potomne w HC3 dla każdego wykrytego klimatyzatora.
  * Każde urządzenie potomne posiada pełny zestaw kontrolek UI oraz własne zmienne (ac_ip, ac_mac, ac_cid, ac_key, refreshSec).
  * Własny, niezależny cykl odpytywania statusu oraz Auto-Reconnect przy zanikach Wi-Fi.
]]

local hubId = (plugin and plugin.mainDeviceId) or ""
__TAG = "GREE HUB" .. tostring(hubId)
QuickApp.version = 2.00
QuickApp._VERSION = "2.00"

-- Central UDP Socket (managed by Hub)
local udp
do
	local ok, sock = pcall(function()
		if net and net.UDPSocket then
			return net.UDPSocket({ broadcast = true, timeout = 5000 })
		end
	end)
	if ok and sock then
		udp = sock
	else
		local o = { _stub = true }
		function o:sendTo(_msg, _ip, _port, cb)
			if cb and cb.error then
				cb.error("net.UDPSocket not available in this environment")
			end
		end
		function o:receive(cb)
			if cb and cb.error then
				cb.error("net.UDPSocket not available in this environment")
			end
		end
		udp = o
	end
end

local function canonicalMac(mac)
	if not mac or mac == "" then
		return ""
	end
	local s = tostring(mac):gsub("[:%-%s]", "")
	return string.lower(s)
end

local function formatMacAddress(mac)
	if not mac then
		return ""
	end
	local clean = tostring(mac):gsub("[:%-%s]", ""):upper()
	if #clean ~= 12 then
		return tostring(mac)
	end
	local parts = {}
	for i = 1, 12, 2 do
		table.insert(parts, clean:sub(i, i + 1))
	end
	return table.concat(parts, ":")
end

local function isValidIPv4(ip)
	if type(ip) ~= "string" then
		return false
	end
	local a, b, c, d = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
	a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
	if not a or not b or not c or not d then
		return false
	end
	local function inRange(x)
		return x >= 0 and x <= 255
	end
	return inRange(a) and inRange(b) and inRange(c) and inRange(d)
end

local function parseIpv4Subnet(netStr, maskStr)
	if not netStr or netStr == "" then
		return nil
	end
	local ipPart, cidrPart = tostring(netStr):match("^%s*([%d%.]+)%s*/%s*(%d+)%s*$")
	if not ipPart then
		ipPart = tostring(netStr):match("^%s*([%d%.]+)%s*$")
	end
	if not ipPart then
		return nil
	end

	local a, b, c, d = ipPart:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
	a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
	if not a or not b or not c or not d or a > 255 or b > 255 or c > 255 or d > 255 then
		return nil
	end

	local prefix = 24
	if cidrPart then
		prefix = tonumber(cidrPart) or 24
	elseif maskStr and maskStr ~= "" then
		local ma, mb, mc, md = tostring(maskStr):match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
		ma, mb, mc, md = tonumber(ma), tonumber(mb), tonumber(mc), tonumber(md)
		if ma and mb and mc and md then
			local function octetToBits(x)
				local bits = 0
				for i = 7, 0, -1 do
					local p = 2 ^ i
					if x >= p then
						bits = bits + 1
						x = x - p
					else
						break
					end
				end
				return bits
			end
			prefix = octetToBits(ma) + octetToBits(mb) + octetToBits(mc) + octetToBits(md)
		else
			prefix = tonumber(maskStr) or 24
		end
	end

	if prefix < 8 or prefix > 30 then
		prefix = 24
	end

	local ipNum = a * 16777216 + b * 65536 + c * 256 + d
	local hostBits = 32 - prefix
	local numHosts = 2 ^ hostBits
	local netNum = math.floor(ipNum / numHosts) * numHosts
	local bcastNum = netNum + numHosts - 1

	local function numToIp(n)
		local o1 = math.floor(n / 16777216) % 256
		local o2 = math.floor(n / 65536) % 256
		local o3 = math.floor(n / 256) % 256
		local o4 = math.floor(n) % 256
		return string.format("%d.%d.%d.%d", o1, o2, o3, o4)
	end

	return {
		network = numToIp(netNum),
		broadcast = numToIp(bcastNum),
		prefix = prefix,
		firstHostNum = netNum + 1,
		lastHostNum = bcastNum - 1,
		hostCount = math.max(0, numHosts - 2),
		numToIp = numToIp,
	}
end

function QuickApp:fnEncrypt(data, key)
	local k = tostring(key or self.openssl_key or "")
	local key1 = { string.byte(padding.padPKCS7(k, 16, true), 1, 16) }
	local paddedData1 = padding.padPKCS7(tostring(data or ""))
	local response = aeslib.encryptString(key1, paddedData1, ciphermode.encryptECB)
	return base64.to_base64(response)
end

function QuickApp:fnDecrypt(data, key)
	local k = tostring(key or self.openssl_key or "")
	local key1 = { string.byte(padding.padPKCS7(k, 16, true), 1, 16) }
	local decodedData = base64.from_base64(data)
	local ok, res = pcall(function()
		return padding.unpadPKCS7(aeslib.decryptString(key1, decodedData, ciphermode.decryptECB))
	end)
	return (ok and res) or nil
end

function QuickApp:recreateUdpSocket()
	local ok, sock = pcall(function()
		if net and net.UDPSocket then
			return net.UDPSocket({ broadcast = true, timeout = 5000 })
		end
	end)
	if ok and sock then
		if udp and type(udp.close) == "function" then
			pcall(function()
				udp:close()
			end)
		end
		udp = sock
		return true
	end
	return false
end

function QuickApp:getTranslation(category, key, fallback)
	local lang = self.language or "en"
	local tr = QuickApp.translations
		and (QuickApp.translations[lang] or QuickApp.translations["en"] or QuickApp.translations["pl"])
	if tr and tr[category] and tr[category][key] then
		return tr[category][key]
	end
	if
		QuickApp.translations
		and QuickApp.translations["en"]
		and QuickApp.translations["en"][category]
		and QuickApp.translations["en"][category][key]
	then
		return QuickApp.translations["en"][category][key]
	end
	return fallback or key
end

local function makeUiRow(components)
	return {
		type = "horizontal",
		style = { weight = "1.0" },
		components = components,
	}
end

local function makeUiButton(name, text, onReleased)
	return {
		type = "button",
		name = name,
		text = text,
		visible = true,
		style = { weight = "1.0" },
		eventBinding = {
			onReleased = {
				{
					params = {
						actionName = "UIAction",
						args = { "onReleased", name },
					},
					type = "deviceAction",
				},
			},
		},
		onReleased = onReleased or "UIHandler",
	}
end

local function hasValidUiActionBindings(uiView)
	if type(uiView) ~= "table" or #uiView == 0 then
		return false
	end
	local buttonCount = 0
	for _, row in ipairs(uiView) do
		for _, comp in ipairs(row.components or {}) do
			if comp.type == "button" then
				buttonCount = buttonCount + 1
				local eb = comp.eventBinding and comp.eventBinding.onReleased and comp.eventBinding.onReleased[1]
				if not eb or eb.type ~= "deviceAction" or not eb.params or eb.params.actionName ~= "UIAction" then
					return false
				end
			end
		end
	end
	return buttonCount > 0
end

local function extractUiCallbacks(uiView)
	local callbacks = {}
	local seen = {}
	for _, row in ipairs(uiView or {}) do
		for _, comp in ipairs(row.components or {}) do
			if comp.type == "button" and comp.name and not seen[comp.name] then
				seen[comp.name] = true
				table.insert(callbacks, {
					name = comp.name,
					eventType = "onReleased",
					callback = comp.onReleased or "UIHandler",
				})
			end
		end
	end
	return callbacks
end

function QuickApp:bindUiCallbacks(target, uiView)
	if not target then
		return {}
	end
	local callbacks = extractUiCallbacks(uiView)
	target.uiCallbacks = target.uiCallbacks or {}
	for _, cb in ipairs(callbacks) do
		if type(target.registerUICallback) == "function" then
			pcall(function()
				target:registerUICallback(cb.name, cb.eventType, cb.callback)
			end)
		end
		target.uiCallbacks[cb.name] = target.uiCallbacks[cb.name] or {}
		target.uiCallbacks[cb.name][cb.eventType] = cb.callback
	end
	return callbacks
end

local function makeUiLabel(name, text)
	return {
		type = "label",
		name = name,
		text = text,
		visible = true,
		style = { weight = "1.0" },
	}
end

function QuickApp:getHubUiView(childCount)
	local lang = self.language or "en"
	local tr = (QuickApp.translations and QuickApp.translations[lang])
		or (QuickApp.translations and QuickApp.translations["en"])
		or {}
	local ui = tr.ui or {}
	local labels = tr.labels or {}
	local count = childCount
	if count == nil then
		count = 0
		for _, _ in pairs(self.childDevices or {}) do
			count = count + 1
		end
	end

	return {
		makeUiRow({ makeUiLabel("labelAcStatus", "GREE GATEWAY / HUB 🌐") }),
		makeUiRow({ makeUiLabel("labelAcMode", labels.hub_autodiscovery or "Auto-discovery: ACTIVE") }),
		makeUiRow({
			makeUiLabel("labelPair", string.format(labels.hub_ac_count or "AC devices in network: %d ✅", count)),
		}),
		makeUiRow({ makeUiLabel("labelAcTemperature", labels.hub_scan_hint or "Click below to scan local network") }),
		makeUiRow({ makeUiButton("buttonScan", ui.buttonScan or "🔍 Scan LAN network") }),
		makeUiRow({
			makeUiButton("turnOn", ui.hub_turn_on_all or "⚡ Turn all ON"),
			makeUiButton("turnOff", ui.hub_turn_off_all or "🛑 Turn all OFF"),
		}),
		makeUiRow({ makeUiButton("buttonRemoveAll", ui.buttonRemoveAll or "🗑 Usuń wszystkie") }),
	}
end

function QuickApp:getChildUiView(state)
	local lang = self.language or "en"
	local tr = (QuickApp.translations and QuickApp.translations[lang])
		or (QuickApp.translations and QuickApp.translations["en"])
		or {}
	local ui = tr.ui or {}
	local labels = tr.labels or {}

	local statusTxt = (state and state.status == 1) and (labels.ac_on or "✅ AC Is ON")
		or (labels.ac_off or "❌ AC Is OFF")
	local pairTxt = labels.pair_ok or "Urządzenie połączone ✅"
	if state and state.isReconnecting then
		pairTxt = labels.pair_failed or "Urządzenie niepołączone ❌"
	end

	local modeVal = (state and state.mode) or 1
	local modeTxt = labels.mode_auto or "AC mode: AUTO 🤖"
	if modeVal == 1 then
		modeTxt = labels.mode_cool or "AC mode: COOL ❄️"
	elseif modeVal == 2 then
		modeTxt = labels.mode_dry or "AC mode: DRY 🌀"
	elseif modeVal == 3 then
		modeTxt = labels.mode_fan or "AC mode: FAN ✇"
	elseif modeVal == 4 then
		modeTxt = labels.mode_heat or "AC mode: HEAT 🔥"
	end

	local tempVal = (state and state.temp) or 24
	local tempTxt = (labels.temperature or "Temperature: ") .. tostring(tempVal) .. " C"

	local fanVal = (state and state.fan) or 0
	local fanTxt = labels.windspeed_auto or "Fan Set: AUTO"
	if fanVal == 1 then
		fanTxt = labels.windspeed_low or "Fan Set: LOW"
	elseif fanVal == 2 then
		fanTxt = labels.windspeed_medium_low or "Fan Set: MEDIUM LOW"
	elseif fanVal == 3 then
		fanTxt = labels.windspeed_medium_high or "Fan Set: MEDIUM HIGH"
	elseif fanVal >= 4 then
		fanTxt = labels.windspeed_high or "Fan Set: HIGH"
	end

	local swingVal = (state and state.swing) or 0
	local swingTxt = labels.swing_default or "Swing mode: Default"
	if swingVal == 1 then
		swingTxt = labels.swing_full or "Swing mode: Full Swing"
	elseif swingVal == 3 then
		swingTxt = labels.swing_middle or "Swing mode: Fixed in the middle position"
	end

	local lightTxt = (state and state.light == 0) and (labels.lights_off or "Lights off ❌")
		or (labels.lights_on or "Lights on ✅")
	local quietTxt = (state and state.quiet == 1) and (labels.quiet_on or "Quiet mode On ✅")
		or (labels.quiet_off or "Quiet mode Off ❌")
	local energyTxt = (state and state.energy == 1) and (labels.energy_on or "Save Energy On ✅")
		or (labels.energy_off or "Save Energy Off ❌")

	return {
		makeUiRow({ makeUiLabel("labelAcStatus", statusTxt) }),
		makeUiRow({ makeUiLabel("labelPair", pairTxt) }),
		makeUiRow({ makeUiLabel("labelAcMode", modeTxt) }),
		makeUiRow({
			makeUiButton("buttonModeAuto", ui.buttonModeAuto or "Auto 🤖"),
			makeUiButton("buttonModeCool", ui.buttonModeCool or "Cool ❄️"),
			makeUiButton("buttonModeDry", ui.buttonModeDry or "Dry 🌀"),
			makeUiButton("buttonModeFan", ui.buttonModeFan or "Fan ✇"),
			makeUiButton("buttonModeHeat", ui.buttonModeHeat or "Heat 🔥"),
		}),
		makeUiRow({ makeUiLabel("labelAcTemperature", tempTxt) }),
		makeUiRow({
			makeUiButton("buttonDecreasTemp", ui.buttonDecreasTemp or "- 1°C 🔽"),
			makeUiButton("buttonIncreaseTemp", ui.buttonIncreaseTemp or "+ 1°C 🔼"),
		}),
		makeUiRow({ makeUiLabel("labelWdspd", fanTxt) }),
		makeUiRow({ makeUiButton("buttonFanSpeed", ui.buttonFanSpeed or "Fan Speed 💨") }),
		makeUiRow({ makeUiLabel("labelSwingStatus", swingTxt) }),
		makeUiRow({
			makeUiButton("buttonSwingDefault", ui.buttonSwingDefault or "Default"),
			makeUiButton("buttonSwingFull", ui.buttonSwingFull or "Full Swing"),
			makeUiButton("buttonSwingMiddle", ui.buttonSwingMiddle or "Middle"),
		}),
		makeUiRow({
			makeUiLabel("labelLightStatus", lightTxt),
			makeUiLabel("labelQuietStatus", quietTxt),
			makeUiLabel("labelEnergySavingStatus", energyTxt),
		}),
		makeUiRow({
			makeUiButton("buttonLight", ui.buttonLight or "Light 💡"),
			makeUiButton("buttonQuiet", ui.buttonQuiet or "Quiet 🌙"),
			makeUiButton("energy", ui.energy or "Eco 🌿"),
		}),
	}
end

function QuickApp:getAcTemplateUiView(state)
	return self:getChildUiView(state)
end

function QuickApp:ensureChildUiView(child, devData)
	if not child then
		return
	end
	local state = self._childStates[child.id]
	local view = self:getChildUiView(state)
	local callbacks = self:bindUiCallbacks(child, view)

	local props = (devData and devData.properties) or {}
	local uv = props.uiView or (devData and devData.uiView) or {}
	local uc = props.uiCallbacks or (devData and devData.uiCallbacks) or {}
	local useUv = props.useUiView

	local hasOldConnecting = false
	for _, row in ipairs(uv) do
		for _, comp in ipairs(row.components or {}) do
			if comp.name == "labelPair" and comp.text then
				local t = tostring(comp.text)
				if t:find("Łączenie", 1, true) or t:find("Connecting", 1, true) then
					hasOldConnecting = true
				end
			end
		end
	end

	local validBindings = hasValidUiActionBindings(uv)
	if not useUv or #uv ~= #view or #uc ~= #callbacks or hasOldConnecting or not validBindings then
		self:debug(
			string.format(
				"🛠 Aktualizacja definicji UI potomka [%s] (wiersze: %d->%d, callbacks: %d->%d, bindings: %s)",
				tostring(child.id),
				#uv,
				#view,
				#uc,
				#callbacks,
				tostring(validBindings)
			)
		)
		pcall(function()
			api.put("/devices/" .. tostring(child.id), {
				uiView = view,
				uiCallbacks = callbacks,
				properties = {
					uiView = view,
					uiCallbacks = callbacks,
					useUiView = true,
					deviceRole = "AirConditioner",
					categories = { "climate" },
				},
			})
		end)
	end
end

function QuickApp:syncChildUiView(child)
	if not child then
		return
	end
	local state = self._childStates[child.id]
	local view = self:getChildUiView(state)
	self:bindUiCallbacks(child, view)
end

function QuickApp:getMappedAcName(cid, mac, ip)
	local acNamesVar = self:getVariable("ac_names") or ""
	if acNamesVar ~= "" then
		local cCid = cid and tostring(cid):lower() or ""
		local cMac = mac and canonicalMac(mac):lower() or ""
		local cIp = ip and tostring(ip) or ""

		for entry in acNamesVar:gmatch("[^,;]+") do
			local key, val = entry:match("^%s*([^=:]+)%s*[=:]%s*(.-)%s*$")
			if key and val and val ~= "" then
				local k = key:lower():gsub("[:-]", "")
				if
					(cCid ~= "" and cCid:find(k, 1, true))
					or (cMac ~= "" and cMac:find(k, 1, true))
					or (cIp ~= "" and cIp == key)
				then
					return val
				end
			end
		end
	end
	return nil
end

function QuickApp:detectLanguage()
	-- 1. Jawna zmienna QuickApp Variable "language" (pl, en, de, fr lub auto)
	local langVar = self:getVariable("language")
	if langVar and langVar ~= "" and langVar:lower() ~= "auto" then
		local code = langVar:lower():match("^%s*([a-z][a-z])")
		if code and QuickApp.translations and QuickApp.translations[code] then
			return code, "variable"
		end
	end

	-- 2. Automatyczne pobranie domyślnego języka z ustawień centrali HC3
	local ok, info = pcall(function()
		return api.get("/settings/info")
	end)
	if ok and type(info) == "table" and info.defaultLanguage then
		local code = tostring(info.defaultLanguage):lower():match("^%s*([a-z][a-z])")
		if code and QuickApp.translations and QuickApp.translations[code] then
			return code, "hc3_settings"
		end
	end

	-- 3. Domyślny fallback: angielski (rekomendowany m.in. dla weryfikacji Fibaro Marketplace)
	return "en", "default"
end

function QuickApp:prepareEnvironment()
	self:debug("🛠 [Setup] Przygotowywanie środowiska (zmienne i konfiguracja)...")

	local hubVars = {
		{ name = "language", value = "auto" },
		{ name = "scan_network", value = "10.88.20.0/24" },
		{ name = "scan_mask", value = "255.255.255.0" },
		{ name = "refreshSec", value = "120" },
		{ name = "showDebug", value = "true" },
		{ name = "ac_names", value = "1ef92c54=Salon, 1ef92afc=Sypialnia, 1ee2f5e9=Gabinet" },
		{ name = "ac_ip", value = "10.88.20.108" },
		{ name = "ac_name", value = "Salon" },
	}

	-- Bezpieczne ustawienie brakujących zmiennych natywną metodą QuickApp
	for _, def in ipairs(hubVars) do
		local current = self:getVariable(def.name)
		if current == nil or current == "" then
			pcall(function()
				self:setVariable(def.name, def.value)
			end)
		end
	end
end

-- ============================================================================
-- CYKL ŻYCIA GŁÓWNEGO QUICKAPP (HUB / BRAMKA GREE)
-- ============================================================================
function QuickApp:onInit()
	self.showDebug = true
	self.openssl_key = "a3K8Bx%2r8Y7#xDh"
	self._childStates = {}
	self._udpQueue = {}

	-- 1. Przygotowanie środowiska (zmienne i konfiguracja)
	self:prepareEnvironment()

	-- 2. Wybór języka interfejsu (zmienna QuickApp lub automatycznie z centrali HC3)
	local lang, langSrc = self:detectLanguage()
	self.language = lang
	self:debug(string.format("🌐 Język interfejsu: %s (źródło: %s)", tostring(self.language), tostring(langSrc)))

	self:debug("🚀 Inicjalizacja Gree AC Gateway / Hub (v" .. tostring(self.version) .. ")...")

	-- 3. Przygotowanie gniazda UDP
	self:recreateUdpSocket()

	-- 2. Załadowanie i zainicjowanie istniejących urządzeń potomnych
	if type(self.initChildDevices) == "function" then
		pcall(function()
			local map = {}
			if QuickAppChild then
				map["com.fibaro.binarySwitch"] = QuickAppChild
			end
			self:initChildDevices(map)
		end)
	end
	local count = 0
	for id, child in pairs(self.childDevices or {}) do
		if child then
			local devData = api.get("/devices/" .. tostring(id))
			local role = (devData and devData.properties and devData.properties.deviceRole) or ""
			local uv = (devData and devData.properties and devData.properties.uiView) or {}

			if role ~= "AirConditioner" or #uv == 0 then
				self:debug(
					"⚠️ Urządzenie potomne ["
						.. tostring(id)
						.. "] ma niepełny interfejs (rola: "
						.. tostring(role)
						.. ", kontrolki: "
						.. tostring(#uv)
						.. "). Usuwam w celu ponownego wygenerowania z pełnym panelem..."
				)
				pcall(function()
					self:removeChildDevice(id)
				end)
			else
				count = count + 1
				self:debug(
					"Załadowano urządzenie potomne klimatyzatora: [" .. tostring(id) .. "] " .. tostring(child.name)
				)
				self:initChildState(child, devData)
			end
		end
	end
	self:debug("Liczba poprawnych urządzeń potomnych w HC3: " .. count)

	-- 3. Zastosowanie widoku i etykiet dla Huba
	self:ensureHubUiView()
	self:updateHubView(count)

	-- 4. Migracja: tylko jeśli brak potomków w HC3, a w zmiennych Huba pozostały dane ze starej wersji 1.0
	if count == 0 then
		local vars = (self.properties and self.properties.quickAppVariables) or {}
		local function getHubVar(vName)
			for _, v in ipairs(vars) do
				if v.name == vName and v.value and v.value ~= "" then
					return v.value
				end
			end
			return nil
		end
		local ip = getHubVar("ac_ip")
		local key = getHubVar("ac_key")
		if ip and isValidIPv4(ip) and key and key ~= "false" then
			self:debug(
				"Wykryto dane klimatyzatora w zmiennych Hub (IP: " .. ip .. ") -> tworzenie urządzenia potomnego..."
			)
			self:createChildFromInfo({
				ip = ip,
				mac = getHubVar("ac_mac") or "",
				cid = getHubVar("ac_cid") or "",
				key = key,
				name = getHubVar("ac_name") or "Salon",
				brand = "gree",
				refreshSec = 120,
			})
		end
	end

	-- 5. Pobranie konfiguracji skanowania innej sieci / VLANu
	self.scan_network = self:getVariable("scan_network")
	if not self.scan_network or self.scan_network == "" then
		self.scan_network = "10.88.20.0/24"
	end
	self.scan_mask = self:getVariable("scan_mask")
	if not self.scan_mask or self.scan_mask == "" then
		self.scan_mask = "255.255.255.0"
	end

	-- 6. Automatyczne skanowanie przy starcie tylko gdy brak urządzeń potomnych w HC3
	if count == 0 then
		self._initialScanTimer = fibaro.setTimeout(1500, function()
			self:scanNetwork()
		end)
	end

	-- 7. Pętla okresowego odpytywania statusów dla wszystkich podłączonych klimatyzatorów (pierwszy odczyt po 1s)
	self:startPollingLoop()

	-- 9. Cykliczne ponawianie skanowania sieci w tle (co 15 minut)
	local function scheduleScanTimer()
		self._scanIntervalTimer = fibaro.setTimeout(15 * 60 * 1000, function()
			self:scanNetwork()
			scheduleScanTimer()
		end)
	end
	scheduleScanTimer()
end

function QuickApp:onQuickAppVariableChanged(name, value)
	if name == "language" then
		local lang, src = self:detectLanguage()
		self.language = lang
		self:debug(string.format("🌐 Zmiana języka na: %s (źródło: %s)", tostring(self.language), tostring(src)))
		local count = 0
		for _, child in pairs(self.childDevices or {}) do
			if child then
				count = count + 1
				self:applyChildTranslations(child)
				self:syncChildUiView(child)
			end
		end
		self:ensureHubUiView(true)
		self:updateHubView(count)
	elseif name == "showDebug" then
		self.showDebug = (tostring(value):lower() == "true")
	end
end

function QuickApp:ensureHubUiView(force)
	local ok, res = pcall(function()
		local devData = api.get("/devices/" .. tostring(self.id))
		local props = (devData and devData.properties) or {}
		local uv = props.uiView or (devData and devData.uiView) or {}
		local uc = props.uiCallbacks or (devData and devData.uiCallbacks) or {}
		local useUv = props.useUiView
		local hubView = self:getHubUiView()
		local hubCallbacks = self:bindUiCallbacks(self, hubView)

		local validBindings = hasValidUiActionBindings(uv)
		self:debug(
			string.format(
				"🔍 [Hub UI Check] useUiView: %s, wiersze: %d (oczekiwane: %d), callbacks: %d (oczekiwane: %d), bindings: %s",
				tostring(useUv),
				#uv,
				#hubView,
				#uc,
				#hubCallbacks,
				tostring(validBindings)
			)
		)

		if force or not useUv or #uv == 0 or #uv ~= #hubView or #uc ~= #hubCallbacks or not validBindings then
			self:debug("🛠 Wgrywanie definicji UI dla Hub [ID: " .. tostring(self.id) .. "]...")
			local putPayload = {
				uiView = hubView,
				uiCallbacks = hubCallbacks,
				properties = {
					useUiView = true,
					uiView = hubView,
					uiCallbacks = hubCallbacks,
				},
			}
			local _, putCode = api.put("/devices/" .. tostring(self.id), putPayload)
			self:debug(
				string.format("✅ Zaktualizowano definicję UI Huba w HC3 (status: %s)", tostring(putCode or "OK"))
			)
		end
	end)
	if not ok then
		self:error("Błąd w ensureHubUiView: " .. tostring(res))
	end
end

function QuickApp:initHubUi()
	return self:ensureHubUiView(true)
end

function QuickApp:updateHubView(childCount)
	childCount = childCount or 0
	pcall(function()
		local hubView = self:getHubUiView(childCount)
		self:bindUiCallbacks(self, hubView)
		self:updateView("labelAcStatus", "text", "GREE GATEWAY / HUB 🌐")
		self:updateView(
			"labelAcMode",
			"text",
			self:getTranslation("labels", "hub_autodiscovery", "Auto-discovery: ACTIVE")
		)
		self:updateView(
			"labelPair",
			"text",
			string.format(self:getTranslation("labels", "hub_ac_count", "AC devices in network: %d ✅"), childCount)
		)
		self:updateView(
			"labelAcTemperature",
			"text",
			self:getTranslation("labels", "hub_scan_hint", "Click below to scan local network")
		)
		self:updateView("buttonScan", "text", self:getTranslation("ui", "buttonScan", "🔍 Scan LAN network"))
		self:updateView("turnOn", "text", self:getTranslation("ui", "hub_turn_on_all", "⚡ Turn all ON"))
		self:updateView("turnOff", "text", self:getTranslation("ui", "hub_turn_off_all", "🛑 Turn all OFF"))
		self:updateView("buttonRemoveAll", "text", self:getTranslation("ui", "buttonRemoveAll", "🗑 Usuń wszystkie"))
	end)
end

-- Inicjalizacja stanu dla pojedynczego urządzenia potomnego
function QuickApp:initChildState(child, devData)
	if not child then
		return
	end
	local id = child.id
	local vars = (devData and devData.properties and devData.properties.quickAppVariables)
		or (child.properties and child.properties.quickAppVariables)
		or {}
	local function getVar(vName)
		for _, v in ipairs(vars) do
			if v.name == vName and v.value and v.value ~= "" then
				return tostring(v.value)
			end
		end
		return child:getVariable(vName) or ""
	end

	local ip = getVar("ac_ip")
	local mac = getVar("ac_mac")
	local key = getVar("ac_key")
	local cid = getVar("ac_cid")
	local refreshSec = tonumber(getVar("refreshSec")) or 120

	self._childStates[id] = {
		id = id,
		name = child.name,
		ip = ip,
		mac = mac,
		cid = cid,
		key = key,
		refreshSec = refreshSec,
		status = 0,
		mode = 1,
		temp = 24,
		fan = 0,
		swing = 0,
		light = 1,
		quiet = 0,
		energy = 0,
		bulkTimeouts = 0,
		reconnectAttempts = 0,
		isReconnecting = false,
		lastRefresh = 0,
	}

	local mappedName = self:getMappedAcName(cid, mac, ip)
	local acPrefix = self:getTranslation("labels", "ac_device_prefix", "AC ")
	if mappedName and mappedName ~= "" then
		local targetName = acPrefix .. mappedName
		if child.name ~= targetName then
			self:debug("Aktualizacja nazwy potomka [" .. tostring(child.id) .. "] wg mapowania: " .. targetName)
			pcall(function()
				api.put("/devices/" .. tostring(child.id), { name = targetName })
			end)
			child.name = targetName
		end
	end

	-- Zapisujemy w bazie HC3 czysty widok tylko gdy struktura wymaga aktualizacji (bez pętli restartów)
	self:ensureChildUiView(child, devData)
	self:applyChildTranslations(child)
	pcall(function()
		child:updateView("labelPair", "text", self:getTranslation("labels", "pair_ok", "Urządzenie połączone ✅"))
	end)
end

function QuickApp:applyClimateClassification(devId)
	if not devId then
		return
	end
	pcall(function()
		api.put("/devices/" .. tostring(devId), {
			properties = {
				deviceRole = "AirConditioner",
				categories = { "climate" },
			},
		})
	end)
end

function QuickApp:applyChildTranslations(child)
	if not child then
		return
	end
	local lang = self.language or "en"
	local tr = (QuickApp.translations and QuickApp.translations[lang])
		or (QuickApp.translations and QuickApp.translations["en"])
		or {}
	local ui = tr.ui or {}
	local ids = {
		"buttonModeAuto",
		"buttonModeCool",
		"buttonModeDry",
		"buttonModeFan",
		"buttonModeHeat",
		"buttonDecreasTemp",
		"buttonIncreaseTemp",
		"buttonFanSpeed",
		"buttonSwingDefault",
		"buttonSwingFull",
		"buttonSwingMiddle",
		"buttonLight",
		"buttonQuiet",
		"energy",
	}
	for _, elemId in ipairs(ids) do
		local text = ui[elemId]
		if text and text ~= "" then
			pcall(function()
				child:updateView(elemId, "text", text)
			end)
		end
	end
end

-- ============================================================================
-- SKANOWANIE SIECI (DISCOVERY) I TWORZENIE DZIECI
-- ============================================================================
function QuickApp:scanNetwork()
	if self._scanInProgress then
		self:debug("Skanowanie sieci jest już w toku...")
		return
	end
	if self._udpBusy then
		if not self._scanDeferredLogged then
			self._scanDeferredLogged = true
			self:debug(
				"⏳ [Discovery] Kolejka UDP jest zajęta (trwa aktywne zapytanie) - czekam na zakończenie zapytań..."
			)
		end
		fibaro.setTimeout(1500, function()
			self:scanNetwork()
		end)
		return
	end
	self._scanDeferredLogged = false
	self._scanInProgress = true
	self._cancelScan = false
	self:debug("🔍 [Discovery] Rozpoczynam skanowanie sieci LAN w poszukiwaniu klimatyzatorów GREE...")
	pcall(function()
		self:updateView(
			"labelPair",
			"text",
			self:getTranslation("labels", "hub_scanning", "Scanning LAN in progress... 🔍")
		)
	end)

	if not udp or type(udp.sendTo) ~= "function" then
		self:recreateUdpSocket()
	end

	local discovered = {}
	local timedOut = false
	fibaro.setTimeout(6500, function()
		timedOut = true
		self:recreateUdpSocket()
		self:onScanCompleted(discovered)
	end)

	local function listenDiscovery()
		if timedOut then
			return
		end
		udp:receive({
			success = function(data, remoteIp)
				if timedOut then
					return
				end
				local ok, resp = self:parseDiscoveryPacket(data, remoteIp)
				if ok and resp and resp.mac then
					local mac = formatMacAddress(resp.mac)
					if not discovered[mac] then
						local mappedName = self:getMappedAcName(resp.cid, mac, remoteIp or resp.ip)
						discovered[mac] = {
							ip = remoteIp or resp.ip,
							mac = mac,
							cid = resp.cid,
							name = mappedName or resp.name or ("Klimatyzator " .. resp.cid),
							brand = resp.brand or "gree",
						}
						self:debug(
							"✅ [Discovery] Wykryto klimatyzator: "
								.. tostring(discovered[mac].name)
								.. " [IP: "
								.. tostring(discovered[mac].ip)
								.. ", MAC: "
								.. mac
								.. "]"
						)
					end
				end
				listenDiscovery()
			end,
			error = function() end,
		})
	end

	-- 1. Broadcast w sieci lokalnej Huba (255.255.255.255:7000)
	udp:sendTo('{"t":"scan"}', "255.255.255.255", 7000, {
		success = function()
			self:debug("Broadcast scan wysłany pomyślnie na 255.255.255.255:7000")
			listenDiscovery()
		end,
		error = function(err)
			self:debug("Błąd wysyłania broadcast scan: " .. tostring(err))
			listenDiscovery()
		end,
	})

	-- 2. Unicast do znanego IP klimatyzatora (jeśli skonfigurowano w zmiennych Hub)
	if self.ac_ip and isValidIPv4(self.ac_ip) then
		udp:sendTo('{"t":"scan"}', self.ac_ip, 7000, { success = function() end, error = function() end })
	end

	-- 3. Skanowanie innej sieci / VLAN (zmienne scan_network i scan_mask)
	local scanNetVar = self:getVariable("scan_network") or self.scan_network or ""
	local scanMaskVar = self:getVariable("scan_mask") or self.scan_mask or "255.255.255.0"
	if scanNetVar and scanNetVar ~= "" then
		self:scanConfiguredSubnets(scanNetVar, scanMaskVar)
	end
end

function QuickApp:scanConfiguredSubnets(netStr, maskStr)
	if not netStr or netStr == "" then
		return
	end
	for rawSubnet in string.gmatch(tostring(netStr), "[^,;]+") do
		local trimmed = rawSubnet:match("^%s*(.-)%s*$")
		if trimmed and trimmed ~= "" then
			local subnetInfo = parseIpv4Subnet(trimmed, maskStr)
			if subnetInfo then
				self:debug(
					string.format(
						"🌐 [Subnet Scan] Skanowanie podsieci: %s/%d (Broadcast: %s, Zakres: %s - %s)...",
						subnetInfo.network,
						subnetInfo.prefix,
						subnetInfo.broadcast,
						subnetInfo.numToIp(subnetInfo.firstHostNum),
						subnetInfo.numToIp(subnetInfo.lastHostNum)
					)
				)

				-- A) Directed Broadcast na adres podsieci (np. 10.88.20.255:7000)
				if subnetInfo.broadcast and subnetInfo.broadcast ~= "" then
					udp:sendTo('{"t":"scan"}', subnetInfo.broadcast, 7000, {
						success = function()
							self:debug("Wysłano directed broadcast do: " .. subnetInfo.broadcast .. ":7000")
						end,
						error = function(err)
							self:debug("Błąd wysyłania directed broadcast: " .. tostring(err))
						end,
					})
				end

				-- B) Skanowanie poszczególnych hostów (Subnet Sweep), aby ominąć blokowanie broadcastów między VLANami na routerze
				if subnetInfo.hostCount > 0 and subnetInfo.hostCount <= 256 then
					local currentHost = subnetInfo.firstHostNum
					local lastHost = subnetInfo.lastHostNum
					local batchSize = 25

					local function sendNextBatch()
						local sentInBatch = 0
						while currentHost <= lastHost and sentInBatch < batchSize do
							local targetIp = subnetInfo.numToIp(currentHost)
							udp:sendTo(
								'{"t":"scan"}',
								targetIp,
								7000,
								{ success = function() end, error = function() end }
							)
							currentHost = currentHost + 1
							sentInBatch = sentInBatch + 1
						end

						if currentHost <= lastHost then
							fibaro.setTimeout(35, sendNextBatch)
						end
					end

					sendNextBatch()
				end
			elseif isValidIPv4(trimmed) then
				self:debug("🌐 [Subnet Scan] Skanowanie pojedynczego adresu IP: " .. trimmed .. ":7000")
				udp:sendTo('{"t":"scan"}', trimmed, 7000, { success = function() end, error = function() end })
			else
				self:debug("⚠️ Niepoprawny format adresu sieci/maski: " .. tostring(trimmed))
			end
		end
	end
end

function QuickApp:scanSubnet(network, mask)
	local net = (network and network ~= "" and network) or self:getVariable("scan_network") or self.scan_network or ""
	local msk = (mask and mask ~= "" and mask) or self:getVariable("scan_mask") or self.scan_mask or "255.255.255.0"
	if net == "" then
		self:debug("scanSubnet: Brak zdefiniowanego adresu sieci w zmiennej scan_network")
		return false
	end
	self:debug("Ręczne skanowanie podsieci: " .. net .. " (maska: " .. msk .. ")...")
	self:scanConfiguredSubnets(net, msk)
	return true
end

function QuickApp:parseDiscoveryPacket(data, _remoteIp)
	local okJ, jsonData = pcall(function()
		return json.decode(tostring(data))
	end)
	if not okJ or not jsonData or not jsonData.pack then
		return false, nil
	end

	local encryptedData = base64.from_base64(jsonData.pack)
	local key1 = { string.byte(padding.padPKCS7(self.openssl_key, 16, true), 1, 16) }
	local okDec, response = pcall(function()
		return padding.unpadPKCS7(aeslib.decryptString(key1, encryptedData, ciphermode.decryptECB))
	end)
	if not okDec or not response then
		return false, nil
	end

	local okD, respData = pcall(function()
		return json.decode(response)
	end)
	if not okD or type(respData) ~= "table" then
		return false, nil
	end

	return true, respData
end

function QuickApp:onScanCompleted(discovered)
	self._scanInProgress = false
	if self._cancelScan then
		self._cancelScan = false
		self:debug("🛑 [Discovery] Skanowanie sieci zostało anulowane (wywołano czyszczenie urządzeń).")
		return
	end
	local count = 0
	for _ in pairs(discovered) do
		count = count + 1
	end
	self:debug("🔍 [Discovery] Zakończono skanowanie sieci. Wykryto urządzeń Gree: " .. count)

	for mac, devInfo in pairs(discovered) do
		local okEns, errEns = pcall(function()
			self:ensureChildDeviceForAc(devInfo)
		end)
		if not okEns then
			self:error("Błąd w ensureChildDeviceForAc dla " .. tostring(mac) .. ": " .. tostring(errEns))
		end
	end

	local totalChildren = 0
	for _, _ in pairs(self.childDevices or {}) do
		totalChildren = totalChildren + 1
	end
	self:updateHubView(totalChildren)
	self:processUdpQueue()
end

function QuickApp:findChildByMacOrCid(mac, cid)
	local targetMac = canonicalMac(mac)
	local targetCid = tostring(cid or ""):lower()
	for _, child in pairs(self.childDevices or {}) do
		local cMac = canonicalMac(child:getVariable("ac_mac") or "")
		local cCid = tostring(child:getVariable("ac_cid") or ""):lower()
		if (targetMac ~= "" and cMac == targetMac) or (targetCid ~= "" and cCid == targetCid) then
			return child
		end
	end
	return nil
end

function QuickApp:ensureChildDeviceForAc(devInfo)
	local existing = self:findChildByMacOrCid(devInfo.mac, devInfo.cid)
	if existing then
		local devData = api.get("/devices/" .. tostring(existing.id))
		local role = (devData and devData.properties and devData.properties.deviceRole) or ""
		local uv = (devData and devData.properties and devData.properties.uiView) or {}
		if role ~= "AirConditioner" or #uv == 0 then
			self:debug(
				"⚠️ Istniejące dziecko ["
					.. tostring(existing.id)
					.. "] ma niepełny interfejs (rola: "
					.. tostring(role)
					.. "). Usuwam w celu poprawnego odtworzenia..."
			)
			pcall(function()
				self:removeChildDevice(existing.id)
			end)
			existing = nil
		else
			self:debug(
				"Klimatyzator " .. tostring(devInfo.name) .. " już istnieje jako dziecko [ID: " .. existing.id .. "]"
			)
			local state = self._childStates[existing.id]
			if not state then
				self:initChildState(existing, devData)
				state = self._childStates[existing.id]
			end

			if devInfo.ip and isValidIPv4(devInfo.ip) then
				if existing:getVariable("ac_ip") ~= devInfo.ip then
					self:debug("Aktualizacja adresu IP dziecka " .. existing.id .. ": " .. devInfo.ip)
					pcall(function()
						existing:setVariable("ac_ip", devInfo.ip)
					end)
				end
				if state then
					state.ip = devInfo.ip
				end
			end

			local mappedName = self:getMappedAcName(devInfo.cid, devInfo.mac, devInfo.ip)
			local acPrefix = self:getTranslation("labels", "ac_device_prefix", "AC ")
			if mappedName and mappedName ~= "" then
				local targetName = acPrefix .. mappedName
				if existing.name ~= targetName then
					self:debug(
						"Aktualizacja nazwy dziecka [" .. tostring(existing.id) .. "] wg mapowania: " .. targetName
					)
					pcall(function()
						api.put("/devices/" .. tostring(existing.id), { name = targetName })
					end)
					existing.name = targetName
					pcall(function()
						existing:setVariable("ac_name", mappedName)
					end)
				end
			end

			local currentKey = (state and state.key and state.key ~= "" and state.key ~= "false" and state.key)
				or existing:getVariable("ac_key")
			if not currentKey or currentKey == "" or currentKey == "false" or (state and state.isReconnecting) then
				self:debug(
					"🔑 [Discovery] Pobieram klucz sesji (bind) dla "
						.. tostring(devInfo.name)
						.. " [IP: "
						.. devInfo.ip
						.. "]..."
				)
				self:bindAcDevice(devInfo.ip, devInfo.mac, devInfo.cid, function(okBind, key)
					if okBind and key then
						pcall(function()
							existing:setVariable("ac_key", key)
						end)
						if state then
							state.key = key
							state.ip = devInfo.ip
							state.bulkTimeouts = 0
							state.reconnectAttempts = 0
							state.isReconnecting = false
						end
						self:debug("✅ Uzyskano klucz sesji dla " .. devInfo.name)
						pcall(function()
							existing:updateView(
								"labelPair",
								"text",
								self:getTranslation("labels", "pair_ok", "Urządzenie połączone ✅")
							)
						end)
						self:syncChildUiView(existing)
						fibaro.setTimeout(300, function()
							self:queryChildStatus(existing)
						end)
					end
				end)
			else
				if state then
					state.ip = devInfo.ip
					state.key = currentKey
					state.isReconnecting = false
				end
				pcall(function()
					existing:updateView(
						"labelPair",
						"text",
						self:getTranslation("labels", "pair_ok", "Urządzenie połączone ✅")
					)
				end)
				self:syncChildUiView(existing)
				fibaro.setTimeout(300, function()
					self:queryChildStatus(existing)
				end)
			end
			return
		end
	end

	self:debug(
		"Rozpoczynam parowanie (Step 2 bind) dla nowego klimatyzatora "
			.. tostring(devInfo.name)
			.. " [IP: "
			.. devInfo.ip
			.. "]..."
	)
	self:bindAcDevice(devInfo.ip, devInfo.mac, devInfo.cid, function(ok, key)
		if ok and key then
			devInfo.key = key
			self:createChildFromInfo(devInfo)
		else
			self:debug("❌ Nie udało się uzyskać klucza sesji dla klimatyzatora: " .. tostring(devInfo.name))
		end
	end)
end

function QuickApp:bindAcDevice(ip, mac, cid, callback)
	if not ip or not isValidIPv4(ip) then
		if callback then
			callback(false, nil)
		end
		return
	end

	local macCanon = canonicalMac(mac)
	local sPack = '{"mac": "' .. macCanon .. '", "t": "bind","uid": 0}'
	local key1 = { string.byte(padding.padPKCS7(self.openssl_key, 16, true), 1, 16) }
	local paddedData1 = padding.padPKCS7(sPack)
	local sEncPack = base64.to_base64(aeslib.encryptString(key1, paddedData1, ciphermode.encryptECB))
	local targetCid = (cid and cid ~= "" and tostring(cid)) or macCanon
	local msg = '{"cid": "'
		.. targetCid
		.. '", "i": 1, "pack": "'
		.. sEncPack
		.. '", "t": "pack", "tcid": "app", "uid": 0}'

	self:debug(
		"📡 [Bind Request] Wysyłam parowanie do: " .. ip .. " [cid: " .. targetCid .. ", mac: " .. macCanon .. "]"
	)
	self:queueUdpJob({
		type = "bind",
		payload = msg,
		ip = ip,
		mac = macCanon,
		callback = callback,
	})
end

function QuickApp:createChildFromInfo(info)
	local mappedName = self:getMappedAcName(info.cid, info.mac, info.ip)
	local name = mappedName or info.name
	local acPrefix = self:getTranslation("labels", "ac_device_prefix", "AC ")
	if not name or name == "" then
		name = acPrefix .. tostring(info.cid or info.mac or "Gree")
	elseif
		not name:lower():match("klimatyzator")
		and not name:lower():match("ac")
		and not name:lower():match("klimaanlage")
		and not name:lower():match("climatiseur")
	then
		name = acPrefix .. name
	end

	local templateUi = self:getAcTemplateUiView()
	local templateCallbacks = extractUiCallbacks(templateUi)
	local childData = {
		name = name,
		type = "com.fibaro.binarySwitch",
		useUiView = true,
		uiView = templateUi,
		uiCallbacks = templateCallbacks,
		initialProperties = {
			useUiView = true,
			uiView = templateUi,
			uiCallbacks = templateCallbacks,
			deviceRole = "AirConditioner",
			categories = { "climate" },
			quickAppVariables = {
				{ name = "ac_ip", value = tostring(info.ip or "") },
				{ name = "ac_mac", value = tostring(info.mac or "") },
				{ name = "ac_cid", value = tostring(info.cid or "") },
				{ name = "ac_key", value = tostring(info.key or "") },
				{ name = "ac_name", value = tostring(info.name or name) },
				{ name = "ac_brand", value = tostring(info.brand or "gree") },
				{ name = "refreshSec", value = tostring(info.refreshSec or 120) },
				{ name = "showDebug", value = "true" },
			},
		},
	}

	local okCreate, child = pcall(function()
		return self:createChildDevice(childData)
	end)
	if okCreate and child then
		self:debug("🎉 Pomyślnie utworzono urządzenie potomne: " .. name .. " [ID: " .. tostring(child.id) .. "]")
		self:initChildState(child)
		-- Pierwszy odczyt statusu nowego dziecka
		fibaro.setTimeout(1000, function()
			self:queryChildStatus(child)
		end)
		return child
	else
		self:debug("Błąd tworzenia urządzenia potomnego: " .. tostring(child))
	end
	return nil
end

-- ============================================================================
-- CENTRALNA PĘTLA ODPYTYWANIA STATUSÓW I OBSŁUGA UDP
-- ============================================================================
function QuickApp:startPollingLoop()
	if self._pollingTimer then
		pcall(function()
			fibaro.clearTimeout(self._pollingTimer)
		end)
	end

	local function tick()
		if not self._scanInProgress then
			local now = os.time()
			for id, child in pairs(self.childDevices or {}) do
				local state = self._childStates[id]
				if state and not state.isReconnecting then
					local interval = state.refreshSec or 120
					if (now - state.lastRefresh) >= interval then
						state.lastRefresh = now
						self:queryChildStatus(child)
					end
				end
			end
		end
		self._pollingTimer = fibaro.setTimeout(5000, tick)
	end

	self._pollingTimer = fibaro.setTimeout(3000, tick)
end

function QuickApp:queryChildStatus(child)
	if not child then
		return
	end
	local state = self._childStates[child.id]
	if not state then
		return
	end
	if not state.key or state.key == "" or state.key == "false" then
		self:debug("🔑 Brak klucza sesji dla " .. child.name .. " -> uruchamiam pobieranie sesji (bind)...")
		self:reconnectChildAc(child)
		return
	end

	self:debug("📡 [Status Query] Odpytuję klimatyzator: " .. child.name .. " (IP: " .. tostring(state.ip) .. ")...")
	local cols = { "Pow", "Mod", "SetTem", "WdSpd", "SwUpDn", "Lig", "Quiet", "SvSt" }
	local macCanon = canonicalMac(state.mac)
	local sPack = '{"cols": ["' .. table.concat(cols, '","') .. '"], "mac": "' .. macCanon .. '", "t": "status"}'

	local sendPack = self:fnEncrypt(sPack, state.key)
	local tcid = canonicalMac(state.mac)
	local pack = '{"cid": "app", "i": 0, "pack": "'
		.. tostring(sendPack)
		.. '", "t": "pack", "tcid": "'
		.. tcid
		.. '", "uid": 0 }'

	self:queueUdpJob({
		childId = child.id,
		type = "bulk",
		payload = pack,
		ip = state.ip,
		key = state.key,
	})
end

function QuickApp:queueUdpJob(job)
	self._udpQueue = self._udpQueue or {}
	table.insert(self._udpQueue, job)
	self:processUdpQueue()
end

function QuickApp:processUdpQueue()
	if self._udpBusy or self._scanInProgress then
		return
	end
	if not self._udpQueue or #self._udpQueue == 0 then
		return
	end

	self._udpBusy = true
	local job = table.remove(self._udpQueue, 1)

	local timedOut = false
	local tm = fibaro.setTimeout(4000, function()
		timedOut = true
		self:recreateUdpSocket()
		self._udpBusy = false
		if job.type == "bind" then
			if job.callback then
				job.callback(false, nil)
			end
		else
			self:onUdpJobFailed(job, "Timeout (brak odpowiedzi)")
		end
		self:processUdpQueue()
	end)

	udp:sendTo(job.payload, job.ip, 7000, {
		success = function()
			udp:receive({
				success = function(data)
					if timedOut then
						return
					end
					pcall(function()
						fibaro.clearTimeout(tm)
					end)
					self._udpBusy = false

					if job.type == "bind" then
						local okJ, jsonData = pcall(function()
							return json.decode(tostring(data))
						end)
						if okJ and jsonData and jsonData.pack then
							local enc = base64.from_base64(jsonData.pack)
							local key1 = { string.byte(padding.padPKCS7(self.openssl_key, 16, true), 1, 16) }
							local okDec, dec = pcall(function()
								return padding.unpadPKCS7(aeslib.decryptString(key1, enc, ciphermode.decryptECB))
							end)
							if okDec and dec then
								local okD, resp = pcall(function()
									return json.decode(dec)
								end)
								if okD and resp and resp.key then
									self:debug(
										"🎉 [Bind Response] Sukces parowania z "
											.. tostring(job.ip)
											.. "! Klucz sesji: "
											.. tostring(resp.key)
									)
									if job.callback then
										job.callback(true, resp.key)
									end
									fibaro.setTimeout(50, function()
										self:processUdpQueue()
									end)
									return
								else
									self:debug(
										"⚠️ [Bind Response] Odszyfrowano pakiet, ale brak pola 'key': "
											.. tostring(dec)
									)
								end
							else
								self:debug(
									"⚠️ [Bind Response] Błąd deszyfracji pakietu bind z " .. tostring(job.ip)
								)
							end
						else
							self:debug(
								"⚠️ [Bind Response] Nieoczekiwany format odpowiedzi z "
									.. tostring(job.ip)
									.. ": "
									.. tostring(data)
							)
						end
						if job.callback then
							job.callback(false, nil)
						end
						fibaro.setTimeout(50, function()
							self:processUdpQueue()
						end)
						return
					end

					local ok, resp = self:decryptAcPack(data, job.key)
					local isSuccess = false
					if ok and resp then
						if job.type == "bulk" then
							if resp.t == "dat" or (resp.cols and resp.dat) or resp.r == 200 then
								isSuccess = true
							end
						elseif job.type == "cmd" then
							if resp.r == 200 or resp.t == "res" or resp.t == "dat" then
								isSuccess = true
							end
						else
							if resp.r == 200 or resp.t == "dat" or resp.t == "res" or (resp.cols and resp.dat) then
								isSuccess = true
							end
						end
					end

					if isSuccess then
						local okS, errS = pcall(function()
							self:onUdpJobSuccess(job, resp)
						end)
						if not okS then
							self:error("Błąd w onUdpJobSuccess: " .. tostring(errS))
						end
					else
						local errDesc = "Błąd deszyfracji"
						if ok and resp then
							errDesc = "Nieoczekiwana odpowiedź (typ: "
								.. tostring(resp.t)
								.. ", kod: "
								.. tostring(resp.r)
								.. ")"
						end
						pcall(function()
							self:onUdpJobFailed(job, errDesc)
						end)
					end

					fibaro.setTimeout(50, function()
						self:processUdpQueue()
					end)
				end,
				error = function(err)
					if timedOut then
						return
					end
					pcall(function()
						fibaro.clearTimeout(tm)
					end)
					self:recreateUdpSocket()
					self._udpBusy = false
					if job.type == "bind" then
						if job.callback then
							job.callback(false, nil)
						end
					else
						self:onUdpJobFailed(job, tostring(err))
					end
					fibaro.setTimeout(50, function()
						self:processUdpQueue()
					end)
				end,
			})
		end,
		error = function(err)
			if timedOut then
				return
			end
			pcall(function()
				fibaro.clearTimeout(tm)
			end)
			self:recreateUdpSocket()
			self._udpBusy = false
			if job.type == "bind" then
				if job.callback then
					job.callback(false, nil)
				end
			else
				self:onUdpJobFailed(job, "Send error: " .. tostring(err))
			end
			fibaro.setTimeout(50, function()
				self:processUdpQueue()
			end)
		end,
	})
end

function QuickApp:onUdpJobSuccess(job, resp)
	local child = (self.childDevices or {})[job.childId]
	local state = self._childStates[job.childId]
	if not child or not state then
		return
	end

	if job.type == "bulk" then
		state.bulkTimeouts = 0
		state.reconnectAttempts = 0
		if state.isReconnecting then
			state.isReconnecting = false
			self:debug("✅ Połączenie z klimatyzatorem " .. child.name .. " przywrócone!")
		end
		pcall(function()
			child:updateView(
				"labelPair",
				"text",
				self:getTranslation("labels", "pair_ok", "Urządzenie połączone ✅")
			)
		end)

		if type(resp.cols) == "table" and type(resp.dat) == "table" then
			for i, col in ipairs(resp.cols) do
				local v = resp.dat[i]
				if type(v) == "table" then
					v = v[1]
				end
				v = tonumber(v) or 0
				self:updateChildDashboard(child, "status_" .. col, v)
			end
			self:debug(
				"📊 Odebrano aktualny status dla "
					.. child.name
					.. " (Temp: "
					.. tostring(state.temp)
					.. "°C, Stan: "
					.. ((state.status == 1 and "ON") or "OFF")
					.. ")"
			)
		end
		self:syncChildUiView(child)
	elseif job.type == "cmd" then
		self:updateChildDashboard(child, job.command, job.value)
		self:syncChildUiView(child)
		fibaro.setTimeout(300, function()
			self:queryChildStatus(child)
		end)
	end
end

function QuickApp:onUdpJobFailed(job, err)
	local child = (self.childDevices or {})[job.childId]
	local state = self._childStates[job.childId]
	if not child or not state then
		return
	end

	if job.type == "bulk" then
		state.bulkTimeouts = (state.bulkTimeouts or 0) + 1
		self:debug(
			"Błąd odczytu klimatyzatora " .. child.name .. " (" .. state.bulkTimeouts .. "): " .. tostring(err)
		)
		if state.bulkTimeouts >= 2 and not state.isReconnecting then
			state.isReconnecting = true
			self:debug(
				"⚠️ Utrata łączności lub nieaktualna sesja dla "
					.. child.name
					.. ". Uruchamiam Auto-Reconnect (bind)..."
			)
			pcall(function()
				child:updateView(
					"labelPair",
					"text",
					self:getTranslation("labels", "pair_failed", "Urządzenie niepołączone ❌")
				)
			end)
			self:syncChildUiView(child)
			self:reconnectChildAc(child)
		end
	elseif job.type == "cmd" then
		self:debug("Błąd wykonania polecenia na " .. child.name .. ": " .. tostring(err))
		if not state.isReconnecting then
			state.isReconnecting = true
			self:reconnectChildAc(child)
		end
	end
end

function QuickApp:reconnectChildAc(child)
	local state = self._childStates[child.id]
	if not state then
		return
	end

	state.reconnectAttempts = (state.reconnectAttempts or 0) + 1
	self:debug(
		"🔄 [Auto-Reconnect #"
			.. state.reconnectAttempts
			.. "] Odnawianie połączenia z "
			.. child.name
			.. " (IP: "
			.. state.ip
			.. ")..."
	)

	local cid = state.cid
	if not cid or cid == "" then
		cid = canonicalMac(state.mac)
	end

	self:bindAcDevice(state.ip, state.mac, cid, function(okBind, newKey)
		if okBind and newKey then
			state.key = newKey
			pcall(function()
				child:setVariable("ac_key", newKey)
			end)
			state.bulkTimeouts = 0
			state.reconnectAttempts = 0
			state.isReconnecting = false
			self:debug(
				"✅ [Auto-Reconnect] Klimatyzator "
					.. child.name
					.. " pomyślnie wznowił sesję! (Klucz: "
					.. newKey
					.. ")"
			)
			pcall(function()
				child:updateView(
					"labelPair",
					"text",
					self:getTranslation("labels", "pair_ok", "Urządzenie połączone ✅")
				)
			end)
			self:syncChildUiView(child)
			fibaro.setTimeout(300, function()
				self:queryChildStatus(child)
			end)
		else
			if state.reconnectAttempts % 3 == 0 and not self._scanInProgress then
				self:debug(
					"🔍 [Auto-Reconnect] Brak odpowiedzi z IP "
						.. state.ip
						.. " -> uruchamiam skanowanie podsieci w tle..."
				)
				self:scanNetwork()
			end
			self:onChildReconnectFailed(child)
		end
	end)
end

function QuickApp:onChildReconnectFailed(child)
	local state = self._childStates[child.id]
	if not state then
		return
	end
	local delay = 15
	if state.reconnectAttempts > 10 then
		delay = 60
	elseif state.reconnectAttempts > 3 then
		delay = 30
	end

	self:debug("⏳ [Auto-Reconnect] " .. child.name .. " nie odpowiedział. Następna próba za " .. delay .. "s...")
	pcall(function()
		child:updateView(
			"labelPair",
			"text",
			self:getTranslation("labels", "pair_failed", "Urządzenie niepołączone ❌")
		)
	end)
	self:syncChildUiView(child)

	fibaro.setTimeout(delay * 1000, function()
		if state.isReconnecting then
			self:reconnectChildAc(child)
		end
	end)
end

function QuickApp:decryptAcPack(data, key)
	local okJ, jsonData = pcall(function()
		return json.decode(tostring(data))
	end)
	if not okJ or not jsonData or not jsonData.pack then
		return false, nil
	end

	local k = tostring(key or "")
	local key1 = { string.byte(padding.padPKCS7(k, 16, true), 1, 16) }
	local enc = base64.from_base64(jsonData.pack)
	local okDec, dec = pcall(function()
		return padding.unpadPKCS7(aeslib.decryptString(key1, enc, ciphermode.decryptECB))
	end)
	if not okDec or not dec then
		return false, nil
	end

	local okD, resp = pcall(function()
		return json.decode(dec)
	end)
	if not okD or type(resp) ~= "table" then
		return false, nil
	end

	return true, resp
end

-- ============================================================================
-- OBSŁUGA AKCJI I INTERFEJSU UI DLA URZĄDZEŃ POTOMNYCH
-- ============================================================================
function QuickApp:onAction(action)
	if not action or type(action) ~= "table" then
		return
	end
	local devId = tonumber(action.deviceId)
	local actionName = tostring(action.actionName or "")
	local args = action.args or {}

	self:debug(string.format("⚡ [onAction] devId: %s, action: %s", tostring(devId), actionName))

	if devId and devId ~= self.id then
		local child = (self.childDevices or {})[devId]
		if child then
			if actionName == "turnOn" then
				return self:childSendPow(child, 1)
			elseif actionName == "turnOff" then
				return self:childSendPow(child, 0)
			elseif actionName == "setTargetTemperature" then
				local val = tonumber(args[1]) or 24
				return self:childAdjustTemp(child, 0, val)
			elseif actionName == "setThermostatMode" then
				local m = 0
				local modeStr = tostring(args[1] or ""):lower()
				if modeStr == "cool" then
					m = 1
				elseif modeStr == "dry" then
					m = 2
				elseif modeStr == "fan" then
					m = 3
				elseif modeStr == "heat" then
					m = 4
				elseif modeStr == "off" then
					return self:childSendPow(child, 0)
				end
				self:childSendPow(child, 1)
				return self:childSetMode(child, m)
			elseif actionName == "UIAction" then
				local evType = tostring(args[1] or "onReleased")
				local elName = tostring(args[2] or "")
				return self:handleChildUiEvent(child, {
					deviceId = devId,
					elementName = elName,
					eventType = evType,
					values = { args[3] },
				})
			elseif actionName == "UIHandler" then
				local ev = args[1] or { deviceId = devId }
				ev.deviceId = ev.deviceId or devId
				return self:UIHandler(ev)
			elseif child[actionName] then
				return child[actionName](child, table.unpack(args))
			elseif self[actionName] then
				return self[actionName](self, { deviceId = devId, elementName = actionName, eventType = "onReleased" })
			else
				self:warning(
					string.format("Urządzenie potomne [%s] nie obsługuje akcji: %s", tostring(devId), actionName)
				)
			end
		end
	else
		-- Akcja skierowana do Huba
		if actionName == "turnOn" then
			return self:turnOn()
		elseif actionName == "turnOff" then
			return self:turnOff()
		elseif actionName == "UIAction" then
			local evType = tostring(args[1] or "onReleased")
			local elName = tostring(args[2] or "")
			return self:UIHandler({
				deviceId = self.id,
				elementName = elName,
				eventType = evType,
				values = { args[3] },
			})
		elseif actionName == "UIHandler" then
			return self:UIHandler(args[1] or { deviceId = self.id })
		elseif self[actionName] then
			return self[actionName](self, table.unpack(args))
		end
	end
end

function QuickApp:UIAction(eventType, elementName, arg)
	return self:UIHandler({
		deviceId = self.id,
		elementName = elementName,
		eventType = eventType or "onReleased",
		values = { arg },
	})
end

function QuickApp:UIHandler(event)
	if not event or type(event) ~= "table" then
		return
	end
	local devId = event.deviceId or event.deviceID or self.id

	if devId ~= self.id then
		local child = (self.childDevices or {})[devId]
		if child then
			return self:handleChildUiEvent(child, event)
		end
	else
		return self:uiEvent(event)
	end
end

function QuickApp:uiEvent(event)
	if not event or type(event) ~= "table" then
		return
	end
	if event.eventType == "onPressed" then
		return
	end
	local devId = event.deviceId or event.deviceID or self.id
	if devId ~= self.id then
		local child = (self.childDevices or {})[devId]
		if child then
			return self:handleChildUiEvent(child, event)
		end
	end

	local el = event.elementName or event.elementId or event.name
	if el == "turnOn" then
		self:turnOn()
	elseif el == "turnOff" then
		self:turnOff()
	elseif el == "buttonScan" then
		self:scanNetwork()
	elseif el == "buttonRemoveAll" then
		self:removeAllChildren()
	else
		local child = nil
		for _, c in pairs(self.childDevices or {}) do
			child = c
			break
		end
		if child then
			return self:handleChildUiEvent(child, event)
		else
			self:debug("Kliknięcie w Hub: wymuszam skanowanie sieci...")
			self:scanNetwork()
		end
	end
end

function QuickApp:handleChildUiEvent(child, event)
	if not event or type(event) ~= "table" then
		return
	end
	local el = event.elementName or event.elementId or event.name or event.action
	local et = event.eventType

	-- W centrali HC3 i aplikacji Yubii kliknięcie przycisku emituje onPressed oraz onReleased.
	-- Ignorujemy tylko onPressed, aby zapobiec podwójnemu wykonaniu akcji (np. skok temp. o 2°C).
	if et == "onPressed" then
		return
	end

	if not el or el == "" then
		return
	end

	if el == "turnOn" then
		self:childSendPow(child, 1)
	elseif el == "turnOff" then
		self:childSendPow(child, 0)
	elseif el == "buttonModeAuto" then
		self:childSetMode(child, 0)
	elseif el == "buttonModeCool" then
		self:childSetMode(child, 1)
	elseif el == "buttonModeDry" then
		self:childSetMode(child, 2)
	elseif el == "buttonModeFan" then
		self:childSetMode(child, 3)
	elseif el == "buttonModeHeat" then
		self:childSetMode(child, 4)
	elseif el == "buttonIncreaseTemp" then
		self:childAdjustTemp(child, 1)
	elseif el == "buttonDecreasTemp" then
		self:childAdjustTemp(child, -1)
	elseif el == "buttonFanSpeed" then
		self:childCycleFan(child)
	elseif el == "buttonSwingDefault" then
		self:childSetSwing(child, 0)
	elseif el == "buttonSwingFull" then
		self:childSetSwing(child, 1)
	elseif el == "buttonSwingMiddle" then
		self:childSetSwing(child, 3)
	elseif el == "buttonLight" then
		self:childToggleFeature(child, "Lig", "light")
	elseif el == "buttonQuiet" then
		self:childToggleFeature(child, "Quiet", "quiet")
	elseif el == "energy" then
		self:childToggleFeature(child, "SvSt", "energy")
	else
		self:debug("Nieobsługiwany element UI: " .. tostring(el))
	end
end

function QuickApp:sendChildCommand(child, opt, val, cmdName)
	local state = self._childStates[child.id]
	if not state or not state.key or state.key == "" or state.key == "false" then
		self:warning(
			"⚠️ Brak aktywnej sesji (klucza) dla klimatyzatora " .. child.name .. ". Wznawiam połączenie..."
		)
		self:reconnectChildAc(child)
		return
	end

	local sPack = '{"opt": ["' .. opt .. '"], "p": [' .. tostring(val) .. '], "t": "cmd"}'
	local innerPack = '{"uid":0, ' .. sPack:sub(2)
	local sendPack = self:fnEncrypt(innerPack, state.key)
	local tcid = canonicalMac(state.mac)
	local msg = '{"t": "pack", "i": 0, "uid": 0, "cid": "app", "tcid": "'
		.. tcid
		.. '", "pack": "'
		.. tostring(sendPack)
		.. '"}'

	-- Natychmiastowa aktualizacja UI dla płynnej reakcji na kliknięcie
	self:updateChildDashboard(child, cmdName, val)
	self:syncChildUiView(child)

	self:queueUdpJob({
		childId = child.id,
		type = "cmd",
		payload = msg,
		ip = state.ip,
		key = state.key,
		command = cmdName,
		value = val,
	})
end

function QuickApp:childSendPow(child, val)
	self:sendChildCommand(child, "Pow", val, "pow")
end

function QuickApp:childSetMode(child, mode)
	self:sendChildCommand(child, "Mod", mode, "mod")
end

function QuickApp:childAdjustTemp(child, delta, directValue)
	local state = self._childStates[child.id]
	local cur = (state and state.temp) or 24
	local target = directValue or (cur + (delta or 0))
	target = math.max(16, math.min(30, tonumber(target) or 24))
	if state then
		state.temp = target
	end
	self:sendChildCommand(child, "SetTem", target, "settemp")
end

function QuickApp:childCycleFan(child)
	local state = self._childStates[child.id]
	local speed = ((state and state.fan) or 0) + 1
	if speed > 4 then
		speed = 0
	end
	if state then
		state.fan = speed
	end
	self:sendChildCommand(child, "WdSpd", speed, "wdspd")
end

function QuickApp:childSetSwing(child, pos)
	local state = self._childStates[child.id]
	if state then
		state.swing = pos
	end
	self:sendChildCommand(child, "SwUpDn", pos, "swupdn")
end

function QuickApp:childToggleFeature(child, opt, featName)
	local state = self._childStates[child.id]
	local cur = (state and state[featName]) or 1
	local nextVal = (cur == 1) and 0 or 1
	if state then
		state[featName] = nextVal
	end
	self:sendChildCommand(child, opt, nextVal, opt:lower())
end

function QuickApp:updateChildDashboard(child, command, value)
	local cmd = tostring(command or ""):lower():gsub("^status_", "")
	if cmd == "settem" then
		cmd = "settemp"
	end
	local lang = self.language or "en"
	local labels = (QuickApp.translations and QuickApp.translations[lang] and QuickApp.translations[lang].labels)
		or (QuickApp.translations and QuickApp.translations["en"] and QuickApp.translations["en"].labels)
		or {}
	local state = self._childStates[child.id]

	if cmd == "pow" then
		if value == 0 then
			pcall(function()
				child:updateView("labelAcStatus", "text", labels.ac_off or "❌ AC Is OFF")
			end)
			pcall(function()
				child:updateProperty("value", false)
			end)
		elseif value == 1 then
			pcall(function()
				child:updateView("labelAcStatus", "text", labels.ac_on or "✅ AC Is ON")
			end)
			pcall(function()
				child:updateProperty("value", true)
			end)
		end
		if state then
			state.status = value
		end
	end

	if cmd == "mod" then
		local txt = labels.mode_auto or "AC mode: AUTO 🤖"
		if value == 1 then
			txt = labels.mode_cool or "AC mode: COOL ❄️"
		elseif value == 2 then
			txt = labels.mode_dry or "AC mode: DRY 🌀"
		elseif value == 3 then
			txt = labels.mode_fan or "AC mode: FAN ✇"
		elseif value == 4 then
			txt = labels.mode_heat or "AC mode: HEAT 🔥"
		end
		pcall(function()
			child:updateView("labelAcMode", "text", txt)
		end)
		if state then
			state.mode = value
		end
	end

	if cmd == "settemp" then
		local tempText = self:getTranslation("labels", "temperature", "Temperature: ")
		pcall(function()
			child:updateView("labelAcTemperature", "text", tempText .. tostring(value) .. " C")
		end)
		pcall(function()
			child:updateProperty("targetTemperature", value)
		end)
		if state then
			state.temp = value
		end
	end

	if cmd == "wdspd" then
		local txt = labels.windspeed_auto or "Fan Set: AUTO"
		if value == 1 then
			txt = labels.windspeed_low or "Fan Set: LOW"
		elseif value == 2 then
			txt = labels.windspeed_medium_low or "Fan Set: MEDIUM LOW"
		elseif value == 3 then
			txt = labels.windspeed_medium_high or "Fan Set: MEDIUM HIGH"
		elseif value >= 4 then
			txt = labels.windspeed_high or "Fan Set: HIGH"
		end
		pcall(function()
			child:updateView("labelWdspd", "text", txt)
		end)
		if state then
			state.fan = value
		end
	end

	if cmd == "swupdn" then
		local txt = labels.swing_default or "Swing mode: Default"
		if value == 1 then
			txt = labels.swing_full or "Swing mode: Full Swing"
		elseif value == 3 then
			txt = labels.swing_middle or "Swing mode: Fixed in the middle position"
		end
		pcall(function()
			child:updateView("labelSwingStatus", "text", txt)
		end)
		if state then
			state.swing = value
		end
	end

	if cmd == "lig" then
		local txt = (value == 1) and (labels.lights_on or "Lights on ✅") or (labels.lights_off or "Lights off ❌")
		pcall(function()
			child:updateView("labelLightStatus", "text", txt)
		end)
		if state then
			state.light = value
		end
	end

	if cmd == "quiet" then
		local txt = (value == 1) and (labels.quiet_on or "Quiet mode On ✅")
			or (labels.quiet_off or "Quiet mode Off ❌")
		pcall(function()
			child:updateView("labelQuietStatus", "text", txt)
		end)
		if state then
			state.quiet = value
		end
	end

	if cmd == "svst" then
		local txt = (value == 1) and (labels.energy_on or "Save Energy On ✅")
			or (labels.energy_off or "Save Energy Off ❌")
		pcall(function()
			child:updateView("labelEnergySavingStatus", "text", txt)
		end)
		if state then
			state.energy = value
		end
	end
end

-- Ręczne dodanie klimatyzatora po adresie IP
function QuickApp:addAcByIp(ip)
	if not isValidIPv4(ip) then
		self:debug("Niepoprawny adres IPv4: " .. tostring(ip))
		return false
	end
	self:debug("Ręczne skanowanie adresu IP: " .. ip .. "...")
	udp:sendTo('{"t":"scan"}', ip, 7000, {
		success = function()
			udp:receive({
				success = function(data, remoteIp)
					local ok, resp = self:parseDiscoveryPacket(data, remoteIp or ip)
					if ok and resp and resp.mac then
						resp.ip = remoteIp or ip
						self:ensureChildDeviceForAc(resp)
					end
				end,
				error = function(err)
					self:debug("Brak odpowiedzi z adresu " .. ip .. ": " .. tostring(err))
				end,
			})
		end,
		error = function(err)
			self:debug("Błąd wysyłania do " .. ip .. ": " .. tostring(err))
		end,
	})
	return true
end

-- Globalne włączanie/wyłączanie wszystkich klimatyzatorów z poziomu Hub
function QuickApp:turnOn()
	self:debug("Hub: Włączanie wszystkich klimatyzatorów...")
	for _, child in pairs(self.childDevices or {}) do
		self:childSendPow(child, 1)
	end
end

function QuickApp:turnOff()
	self:debug("Hub: Wyłączanie wszystkich klimatyzatorów...")
	for _, child in pairs(self.childDevices or {}) do
		self:childSendPow(child, 0)
	end
end

function QuickApp:buttonScan(_event)
	self:scanNetwork()
end

function QuickApp:removeAllChildren()
	self:debug("🗑 [Hub] Usuwanie wszystkich urządzeń potomnych klimatyzatorów...")
	if self._initialScanTimer then
		pcall(function()
			fibaro.clearTimeout(self._initialScanTimer)
		end)
		self._initialScanTimer = nil
	end
	self._cancelScan = true
	self._scanInProgress = false
	self._udpQueue = {}
	self._udpBusy = false

	local toRemove = {}
	for id, _ in pairs(self.childDevices or {}) do
		local numId = tonumber(id)
		if numId then
			toRemove[numId] = true
		end
	end

	if plugin and type(plugin.getChildDevices) == "function" then
		local okP, pDevs = pcall(function()
			return plugin.getChildDevices(self.id)
		end)
		if okP and type(pDevs) == "table" then
			for _, d in ipairs(pDevs) do
				local numId = type(d) == "table" and tonumber(d.id) or tonumber(d)
				if numId then
					toRemove[numId] = true
				end
			end
		end
	end

	local okApi, devs = pcall(function()
		return api.get("/devices?parentId=" .. tostring(self.id))
	end)
	if okApi and type(devs) == "table" then
		for _, d in ipairs(devs) do
			if d and d.id then
				local numId = tonumber(d.id)
				if numId then
					toRemove[numId] = true
				end
			end
		end
	end

	local removedCount = 0
	for id, _ in pairs(toRemove) do
		self:debug("🗑 Usuwam urządzenie potomne [ID: " .. tostring(id) .. "]...")
		pcall(function()
			self:removeChildDevice(id)
		end)
		if plugin and type(plugin.deleteDevice) == "function" then
			pcall(function()
				plugin.deleteDevice(id)
			end)
		end
		pcall(function()
			api.delete("/plugins/removeChildDevice/" .. tostring(id))
		end)
		pcall(function()
			api.delete("/devices/" .. tostring(id))
		end)
		if self.childDevices then
			self.childDevices[id] = nil
			self.childDevices[tostring(id)] = nil
		end
		if self._childStates then
			self._childStates[id] = nil
			self._childStates[tostring(id)] = nil
		end
		removedCount = removedCount + 1
	end

	self:updateHubView(0)
	self:debug(string.format("✅ [Hub] Usunięto wszystkie urządzenia potomne (łącznie: %d).", removedCount))
end

function QuickApp:buttonRemoveAll(_event)
	self:removeAllChildren()
end

function QuickApp:onUIEvent(event)
	if not event or type(event) ~= "table" then
		return
	end
	event.deviceId = event.deviceId or self.id
	return self:UIHandler(event)
end

-- Lista przycisków kontrolek klimatyzatora (UI potomków)
local childButtons = {
	"buttonModeAuto",
	"buttonModeCool",
	"buttonModeDry",
	"buttonModeFan",
	"buttonModeHeat",
	"buttonDecreasTemp",
	"buttonIncreaseTemp",
	"buttonFanSpeed",
	"buttonSwingDefault",
	"buttonSwingFull",
	"buttonSwingMiddle",
	"buttonLight",
	"buttonQuiet",
	"energy",
}

-- Rejestracja bezpośrednich metod callback na poziomie głównego QuickApp (Hub)
-- Centrala HC3 w zależności od wersji wywołuje callbacki bezpośrednio na obiekcie nadrzędnym QuickApp z event.deviceId
for _, btnName in ipairs(childButtons) do
	QuickApp[btnName] = function(self, event)
		local ev = (type(event) == "table" and event) or {}
		ev.elementName = ev.elementName or ev.elementId or ev.name or btnName
		ev.eventType = ev.eventType or "onReleased"
		local devId = ev.deviceId or ev.deviceID

		if devId and devId ~= self.id then
			local child = (self.childDevices or {})[devId]
			if child then
				return self:handleChildUiEvent(child, ev)
			end
		end

		-- Jeśli devId nie zostało przekazane w zdarzeniu lub jest równe self.id:
		for _, child in pairs(self.childDevices or {}) do
			return self:handleChildUiEvent(child, ev)
		end
	end
end

-- ============================================================================
-- METODY DLA URZĄDZEŃ POTOMNYCH (SCENY HC3, UI I APLIKACJA YUBII)
-- ============================================================================
if QuickAppChild then
	function QuickAppChild:getHub()
		return self.parent or quickApp or QuickApp
	end

	function QuickAppChild:getVariable(name)
		if self.properties and self.properties.quickAppVariables then
			for _, v in ipairs(self.properties.quickAppVariables) do
				if v.name == name and v.value and v.value ~= "" then
					return v.value
				end
			end
		end
		local ok, dev = pcall(function()
			return api.get("/devices/" .. tostring(self.id))
		end)
		if ok and dev and dev.properties and dev.properties.quickAppVariables then
			self.properties = self.properties or {}
			self.properties.quickAppVariables = dev.properties.quickAppVariables
			for _, v in ipairs(dev.properties.quickAppVariables) do
				if v.name == name and v.value and v.value ~= "" then
					return v.value
				end
			end
		end
		return nil
	end

	function QuickAppChild:setVariable(name, value)
		local valStr = tostring(value or "")
		local okDev, dev = pcall(function()
			return api.get("/devices/" .. tostring(self.id))
		end)
		local vars = (okDev and dev and dev.properties and dev.properties.quickAppVariables)
			or (self.properties and self.properties.quickAppVariables)
			or {}
		local found = false
		for _, v in ipairs(vars) do
			if v.name == name then
				v.value = valStr
				found = true
				break
			end
		end
		if not found then
			table.insert(vars, { name = name, value = valStr })
		end
		self.properties = self.properties or {}
		self.properties.quickAppVariables = vars
		pcall(function()
			api.put("/devices/" .. tostring(self.id), {
				properties = {
					quickAppVariables = vars,
				},
			})
		end)
	end

	function QuickAppChild:UIAction(eventType, elementName, arg)
		local hub = self:getHub()
		if hub and hub.handleChildUiEvent then
			hub:handleChildUiEvent(self, {
				deviceId = self.id,
				elementName = elementName,
				eventType = eventType or "onReleased",
				values = { arg },
			})
		end
	end

	function QuickAppChild:UIHandler(event)
		local hub = self:getHub()
		if hub and hub.handleChildUiEvent then
			hub:handleChildUiEvent(self, event)
		end
	end

	function QuickAppChild:onUIEvent(event)
		local hub = self:getHub()
		if hub and hub.handleChildUiEvent then
			hub:handleChildUiEvent(self, event)
		end
	end

	function QuickAppChild:uiEvent(event)
		local hub = self:getHub()
		if hub and hub.handleChildUiEvent then
			hub:handleChildUiEvent(self, event)
		end
	end

	-- Bezpośrednie callbacki przycisków na instancji QuickAppChild
	for _, btnName in ipairs(childButtons) do
		QuickAppChild[btnName] = function(self, event)
			local hub = self:getHub()
			if hub and hub.handleChildUiEvent then
				local ev = (type(event) == "table" and event) or { elementName = btnName, eventType = "onReleased" }
				ev.elementName = ev.elementName or ev.elementId or ev.name or btnName
				hub:handleChildUiEvent(self, ev)
			end
		end
	end

	function QuickAppChild:turnOn()
		local hub = self:getHub()
		if hub and hub.childSendPow then
			hub:childSendPow(self, 1)
		end
	end

	function QuickAppChild:turnOff()
		local hub = self:getHub()
		if hub and hub.childSendPow then
			hub:childSendPow(self, 0)
		end
	end

	function QuickAppChild:setTargetTemperature(value)
		local hub = self:getHub()
		if hub and hub.sendChildCommand then
			local target = math.max(16, math.min(30, tonumber(value) or 24))
			hub:sendChildCommand(self, "SetTem", target, "settemp")
		end
	end

	function QuickAppChild:setThermostatMode(mode)
		local hub = self:getHub()
		if hub and hub.childSetMode then
			local m = 0
			local modeStr = tostring(mode or ""):lower()
			if modeStr == "cool" then
				m = 1
			elseif modeStr == "dry" then
				m = 2
			elseif modeStr == "fan" then
				m = 3
			elseif modeStr == "heat" then
				m = 4
			end
			hub:childSetMode(self, m)
		end
	end
end
