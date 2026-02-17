import asyncio
import os
import base64
import traceback
from datetime import timedelta
from importlib import import_module
import re
from homeassistant.config_entries import ConfigEntry
from homeassistant.util.json import load_json

try:
    from homeassistant.helpers.json import save_json
except ImportError:
    from homeassistant.util.json import save_json
from homeassistant.helpers.typing import ConfigType
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.core import (
    HomeAssistant,
)
from homeassistant.const import (
    Platform,
    CONF_TYPE,
    CONF_PORT,
    CONF_MODEL,
    CONF_IP_ADDRESS,
    CONF_DEVICE_ID,
    CONF_PROTOCOL,
    CONF_TOKEN,
    CONF_NAME,
    CONF_DEVICE,
    CONF_ENTITIES
)

from .core.logger import MideaLogger
from .core.device import MiedaDevice
from .data_coordinator import MideaDataUpdateCoordinator
from .core.cloud import get_midea_cloud
from .const import (
    DOMAIN,
    DEVICES,
    CONF_REFRESH_INTERVAL,
    CONFIG_PATH,
    CONF_KEY,
    CONF_ACCOUNT,
    CONF_SN8,
    CONF_SN,
    CONF_MODEL_NUMBER,
    CONF_SERVERS, STORAGE_PATH, CONF_MANUFACTURER_CODE,
    CONF_SELECTED_HOMES, CONF_SMART_PRODUCT_ID, STORAGE_PLUGIN_PATH,
    CONF_HOME_ID, CONF_HOME_NAME, CONF_ACCOUNT_ID
)
from .const import CONF_PASSWORD as CONF_PASSWORD_KEY, CONF_SERVER as CONF_SERVER_KEY

PLATFORMS: list[Platform] = [
    Platform.BINARY_SENSOR,
    Platform.SENSOR,
    Platform.SWITCH,
    Platform.CLIMATE,
    Platform.SELECT,
    Platform.WATER_HEATER,
    Platform.FAN,
    Platform.LIGHT,
    Platform.HUMIDIFIER,
    Platform.NUMBER,
    Platform.BUTTON,
    Platform.VACUUM
]

_LOGIN_LOCKS: dict[str, asyncio.Lock] = {}
_CLOUD_CACHE: dict[str, tuple] = {}

async def import_module_async(module_name):
    return await asyncio.to_thread(import_module, module_name, __package__)

def get_sn8_used(hass: HomeAssistant, sn8):
    entries = hass.config_entries.async_entries(DOMAIN)
    count = 0
    for entry in entries:
        if sn8 == entry.data.get("sn8"):
            count += 1
    return count


def remove_device_config(hass: HomeAssistant, sn8):
    config_file = hass.config.path(f"{CONFIG_PATH}/{sn8}.json")
    try:
        os.remove(config_file)
    except FileNotFoundError:
        pass


async def load_device_config(hass: HomeAssistant, device_type, sn8):
    def _ensure_dir_and_load(path_dir: str, path_file: str):
        os.makedirs(path_dir, exist_ok=True)
        return load_json(path_file, default={})

    config_dir = hass.config.path(CONFIG_PATH)
    config_file = hass.config.path(f"{CONFIG_PATH}/{sn8}.json")
    raw = await hass.async_add_executor_job(_ensure_dir_and_load, config_dir, config_file)
    json_data = {}
    device_path = f".device_mapping.{'T0x%02X' % device_type}"
    try:
        mapping_module = await import_module_async(device_path)
        for key, config in mapping_module.DEVICE_MAPPING.items():
            if (key == sn8) or (isinstance(key, tuple) and sn8 in key) or (isinstance(key, str) and re.match(key, sn8)):
                json_data = config
                break
        if not json_data:
            if "default" in mapping_module.DEVICE_MAPPING:
                json_data = mapping_module.DEVICE_MAPPING["default"]
            else:
                MideaLogger.warning(f"No mapping found for sn8 {sn8} in type {'T0x%02X' % device_type}")
    except ModuleNotFoundError:
        MideaLogger.warning(f"Can't load mapping file for type {'T0x%02X' % device_type}")

    save_data = {sn8: json_data}
    await hass.async_add_executor_job(save_json, config_file, save_data)
    return json_data

async def update_listener(hass: HomeAssistant, config_entry: ConfigEntry):
    device_id = config_entry.data.get(CONF_DEVICE_ID)
    if device_id is not None:
        ip_address = config_entry.options.get(
            CONF_IP_ADDRESS, None
        )
        refresh_interval = config_entry.options.get(
            CONF_REFRESH_INTERVAL, None
        )
        device: MiedaDevice = hass.data[DOMAIN][DEVICES][device_id][CONF_DEVICE]
        if device:
            if ip_address is not None:
                device.set_ip_address(ip_address)
            if refresh_interval is not None:
                device.set_refresh_interval(refresh_interval)


async def async_setup(hass: HomeAssistant, config: ConfigType):
    hass.data.setdefault(DOMAIN, {})
    os.makedirs(hass.config.path(STORAGE_PATH), exist_ok=True)
    lua_path = hass.config.path(STORAGE_PATH)

    cjson = os.path.join(lua_path, "cjson.lua")
    bit = os.path.join(lua_path, "bit.lua")

    if not os.path.exists(cjson):
        from .const import CJSON_LUA
        cjson_lua = base64.b64decode(CJSON_LUA.encode("utf-8")).decode("utf-8")
        try:
            with open(cjson, "wt", encoding="utf-8") as fp:
                fp.write(cjson_lua)
        except PermissionError as e:
            MideaLogger.error(f"Failed to create cjson.lua at {cjson}: {e}")
            import tempfile
            temp_dir = tempfile.gettempdir()
            cjson = os.path.join(temp_dir, "cjson.lua")
            with open(cjson, "wt", encoding="utf-8") as fp:
                fp.write(cjson_lua)
            MideaLogger.warning(f"Using temporary file for cjson.lua: {cjson}")

    if not os.path.exists(bit):
        from .const import BIT_LUA
        bit_lua = base64.b64decode(BIT_LUA.encode("utf-8")).decode("utf-8")
        try:
            with open(bit, "wt", encoding="utf-8") as fp:
                fp.write(bit_lua)
        except PermissionError as e:
            MideaLogger.error(f"Failed to create bit.lua at {bit}: {e}")
            import tempfile
            temp_dir = tempfile.gettempdir()
            bit = os.path.join(temp_dir, "bit.lua")
            with open(bit, "wt", encoding="utf-8") as fp:
                fp.write(bit_lua)
            MideaLogger.warning(f"Using temporary file for bit.lua: {bit}")

    return True

async def _get_or_login_cloud(
    hass: HomeAssistant,
    account: str,
    password: str,
    server: int,
    account_id: str
):
    global _LOGIN_LOCKS, _CLOUD_CACHE
    
    if account_id not in _LOGIN_LOCKS:
        _LOGIN_LOCKS[account_id] = asyncio.Lock()
    
    login_lock = _LOGIN_LOCKS[account_id]
    
    async with login_lock:
        if account_id in _CLOUD_CACHE:
            cached_cloud, cached_homes = _CLOUD_CACHE[account_id]
            try:
                homes = await cached_cloud.list_home()
                if homes:
                    MideaLogger.debug(f"Using cached cloud session for account {account}")
                    return cached_cloud, homes
            except Exception as e:
                MideaLogger.warning(f"Cached cloud session invalid, re-login: {e}")
                del _CLOUD_CACHE[account_id]
        
        cloud_name = CONF_SERVERS.get(server)
        cloud = get_midea_cloud(
            cloud_name=cloud_name,
            session=async_get_clientsession(hass),
            account=account,
            password=password,
        )
        
        if not cloud or not await cloud.login():
            MideaLogger.error("Midea cloud login failed")
            return None, None
        
        try:
            homes = await cloud.list_home()
            if homes:
                _CLOUD_CACHE[account_id] = (cloud, homes)
                MideaLogger.debug(f"Cached cloud session for account {account}")
                return cloud, homes
        except Exception as e:
            MideaLogger.error(f"Failed to list homes: {e}")
            return None, None
        
        return None, None

async def async_setup_entry(hass: HomeAssistant, config_entry: ConfigEntry):
    device_type = config_entry.data.get(CONF_TYPE)
    MideaLogger.debug(f"async_setup_entry type={device_type} data={config_entry.data}")
    
    if device_type == CONF_ACCOUNT:
        account = config_entry.data.get(CONF_ACCOUNT)
        password = config_entry.data.get(CONF_PASSWORD_KEY)
        server = config_entry.data.get(CONF_SERVER_KEY)
        account_id = config_entry.data.get(CONF_ACCOUNT_ID, f"{account}_{server}")
        home_id = config_entry.data.get(CONF_HOME_ID)
        home_name = config_entry.data.get(CONF_HOME_NAME, f"家庭 {home_id}")
        
        cloud, homes = await _get_or_login_cloud(hass, account, password, server, account_id)
        
        if not cloud or not homes:
            MideaLogger.error(f"Failed to get cloud session for account {account}")
            return False
        
        if home_id is None:
            selected_homes = config_entry.data.get(CONF_SELECTED_HOMES, [])
            if selected_homes:
                home_ids = []
                for selected_home in selected_homes:
                    if selected_home in homes:
                        home_ids.append(selected_home)
                    elif str(selected_home) in homes:
                        home_ids.append(str(selected_home))
                    elif int(selected_home) in homes:
                        home_ids.append(int(selected_home))
            else:
                home_ids = list(homes.keys())
        else:
            home_ids = [home_id]
        
        MideaLogger.debug(f"Processing home_ids: {home_ids}")
        
        hass.data.setdefault(DOMAIN, {})
        hass.data[DOMAIN].setdefault("accounts", {})
        
        bucket = {"device_list": {}, "coordinator_map": {}}
        
        for current_home_id in home_ids:
            appliances = await cloud.list_appliances(current_home_id)
            if appliances is None:
                continue

            for appliance_code, info in appliances.items():
                MideaLogger.debug(f"info={info} ")

                os.makedirs(hass.config.path(STORAGE_PATH), exist_ok=True)
                path = hass.config.path(STORAGE_PATH)
                file = await cloud.download_lua(
                    path=path,
                    device_type=info.get(CONF_TYPE),
                    sn=info.get(CONF_SN),
                    model_number=info.get(CONF_MODEL_NUMBER),
                    manufacturer_code=info.get(CONF_MANUFACTURER_CODE),
                )
                try:
                    os.makedirs(hass.config.path(STORAGE_PLUGIN_PATH), exist_ok=True)
                    plugin_path = hass.config.path(STORAGE_PLUGIN_PATH)
                    await cloud.download_plugin(
                        path=plugin_path,
                        appliance_code=appliance_code,
                        smart_product_id=info.get(CONF_SMART_PRODUCT_ID),
                        device_type=info.get(CONF_TYPE),
                        sn=info.get(CONF_SN),
                        sn8=info.get(CONF_SN8),
                        model_number=info.get(CONF_MODEL_NUMBER),
                        manufacturer_code=info.get(CONF_MANUFACTURER_CODE),
                    )
                except Exception as e:
                    traceback.print_exc()

                try:
                    device = MiedaDevice(
                        name=info.get(CONF_NAME),
                        device_id=appliance_code,
                        device_type=info.get(CONF_TYPE),
                        ip_address=None,
                        port=None,
                        token=None,
                        key=None,
                        connected=info.get("online"),
                        protocol=info.get(CONF_PROTOCOL) or 2,
                        model=info.get(CONF_MODEL),
                        subtype=info.get(CONF_MODEL_NUMBER),
                        manufacturer_code=info.get(CONF_MANUFACTURER_CODE),
                        sn=info.get(CONF_SN),
                        sn8=info.get(CONF_SN8),
                        lua_file=file,
                        cloud=cloud,
                    )
                    try:
                        mapping = await load_device_config(
                            hass,
                            info.get(CONF_TYPE) or info.get("type"),
                            info.get(CONF_SN8) or info.get("sn8"),
                        ) or {}
                    except Exception:
                        mapping = {}

                    try:
                        device.set_queries(mapping.get("queries", [{}]))
                    except Exception:
                        pass
                    try:
                        device.set_centralized(mapping.get("centralized", []))
                    except Exception:
                        pass
                    try:
                        device.set_calculate(mapping.get("calculate", {}))
                    except Exception:
                        pass

                    try:
                        default_values = {}
                        entities_cfg = (mapping.get("entities") or {})
                        for platform_cfg in entities_cfg.values():
                            if not isinstance(platform_cfg, dict):
                                continue
                            for entity_key, ecfg in platform_cfg.items():
                                if not isinstance(ecfg, dict):
                                    continue
                                if "default_value" in ecfg:
                                    attr_name = ecfg.get("attribute", entity_key)
                                    default_values[attr_name] = ecfg["default_value"]
                        device.set_default_values(default_values)
                    except Exception:
                        traceback.print_exc()

                    try:
                        preset_keys = set(mapping.get("centralized", []))
                        entities_cfg = (mapping.get("entities") or {})
                        for platform_cfg in entities_cfg.values():
                            if not isinstance(platform_cfg, dict):
                                continue
                            for _, ecfg in platform_cfg.items():
                                if not isinstance(ecfg, dict):
                                    continue
                                for k in [
                                    "power",
                                    "aux_heat",
                                    "current_temperature",
                                    "target_temperature",
                                    "oscillate",
                                    "min_temp",
                                    "max_temp",
                                ]:
                                    v = ecfg.get(k)
                                    if isinstance(v, str):
                                        preset_keys.add(v)
                                    elif isinstance(v, list):
                                        for vv in v:
                                            if isinstance(vv, str):
                                                preset_keys.add(vv)
                                for map_key in [
                                    "hvac_modes",
                                    "preset_modes",
                                    "swing_modes",
                                    "fan_modes",
                                    "operation_list",
                                    "options",
                                ]:
                                    maps = ecfg.get(map_key) or {}
                                    if isinstance(maps, dict):
                                        for _, cond in maps.items():
                                            if isinstance(cond, dict):
                                                for attr_name in cond.keys():
                                                    preset_keys.add(attr_name)
                        for platform_name, platform_cfg in entities_cfg.items():
                            if not isinstance(platform_cfg, dict):
                                continue
                            platform_str = str(platform_name)
                            if platform_str in [
                                str(Platform.SENSOR),
                                str(Platform.BINARY_SENSOR),
                                str(Platform.SWITCH),
                                str(Platform.FAN),
                                str(Platform.SELECT),
                                str(Platform.VACUUM),
                            ]:
                                for entity_key in platform_cfg.keys():
                                    preset_keys.add(entity_key)
                        for k in preset_keys:
                            if k not in device.attributes:
                                device.attributes[k] = None
                        if device.device_type == 0xD9:
                            device.attributes["db_location_selection"] = "left"
                    except Exception:
                        pass

                    coordinator = MideaDataUpdateCoordinator(hass, config_entry, device, cloud=cloud)
                    hass.async_create_task(coordinator.async_config_entry_first_refresh())
                    bucket["device_list"][appliance_code] = info
                    bucket["coordinator_map"][appliance_code] = coordinator
                except Exception as e:
                    MideaLogger.error(f"Init device failed: {appliance_code}, error: {e}")
        
        hass.data[DOMAIN]["accounts"][config_entry.entry_id] = bucket

        await hass.config_entries.async_forward_entry_setups(config_entry, PLATFORMS)
        return True


async def async_unload_entry(hass: HomeAssistant, config_entry: ConfigEntry):
    device_id = config_entry.data.get(CONF_DEVICE_ID)
    device_type = config_entry.data.get(CONF_TYPE)
    if device_type == CONF_ACCOUNT:
        unload_ok = await hass.config_entries.async_unload_platforms(config_entry, PLATFORMS)
        if unload_ok:
            try:
                hass.data.get(DOMAIN, {}).get("accounts", {}).pop(config_entry.entry_id, None)
            except Exception:
                pass
        return unload_ok
    if device_id is not None:
        device: MiedaDevice = hass.data[DOMAIN][DEVICES][device_id][CONF_DEVICE]
        if device is not None:
            if get_sn8_used(hass, device.sn8) == 1:
                remove_device_config(hass, device.sn8)
        hass.data[DOMAIN][DEVICES].pop(device_id)
    for platform in PLATFORMS:
        await hass.config_entries.async_forward_entry_unload(config_entry, platform)
    return True
