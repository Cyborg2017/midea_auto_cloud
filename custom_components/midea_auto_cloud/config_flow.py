import voluptuous as vol
import logging
from typing import Any
from homeassistant.helpers.aiohttp_client import async_create_clientsession
from homeassistant import config_entries
from homeassistant.config_entries import ConfigFlowResult
from homeassistant.core import callback
from homeassistant.const import (
    CONF_TYPE,
)
import homeassistant.helpers.config_validation as cv
from .const import (
    CONF_ACCOUNT,
    CONF_PASSWORD,
    DOMAIN,
    CONF_SERVER, CONF_SERVERS,
    CONF_HOMES,
    CONF_SELECTED_HOMES,
    CONF_HOME_ID,
    CONF_HOME_NAME,
    CONF_ACCOUNT_ID
)
from .core.cloud import get_midea_cloud

_LOGGER = logging.getLogger(__name__)

class ConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    _session = None
    _cloud = None
    _homes = None
    _user_input = None
    _home_device_counts = None
    _home_online_counts = None
    _selected_homes = None
    _account_id = None

    VERSION = 1

    @staticmethod
    @callback
    def async_get_options_flow(config_entry):
        return OptionsFlowHandler(config_entry)

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        if self._session is None:
            self._session = async_create_clientsession(self.hass)
        if user_input is not None:
            cloud = get_midea_cloud(
                session=self._session,
                cloud_name=CONF_SERVERS[user_input[CONF_SERVER]],
                account=user_input[CONF_ACCOUNT],
                password=user_input[CONF_PASSWORD]
            )
            try:
                if await cloud.login():
                    self._cloud = cloud
                    self._user_input = user_input
                    
                    homes = await cloud.list_home()
                    if homes and len(homes) > 0:
                        _LOGGER.debug(f"Found homes: {homes}")
                        self._homes = homes
                        
                        self._home_device_counts = {}
                        self._home_online_counts = {}
                        for home_id, home_info in homes.items():
                            appliances = await cloud.list_appliances(home_id)
                            device_count = len(appliances) if appliances else 0
                            online_count = 0
                            if appliances:
                                for appliance_info in appliances.values():
                                    if isinstance(appliance_info, dict) and appliance_info.get("online"):
                                        online_count += 1
                            self._home_device_counts[home_id] = device_count
                            self._home_online_counts[home_id] = online_count
                        
                        return await self.async_step_select_homes()
                    else:
                        errors["base"] = "no_homes"
                else:
                    errors["base"] = "login_failed"
            except Exception as e:
                _LOGGER.exception("Login error: %s", e)
                errors["base"] = "login_failed"
        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema({
                vol.Required(CONF_ACCOUNT): str,
                vol.Required(CONF_PASSWORD): str,
                vol.Required(CONF_SERVER, default=2): vol.In(CONF_SERVERS)
            }),
            errors=errors,
        )

    async def async_step_select_homes(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        
        if user_input is not None:
            selected_homes = user_input.get(CONF_SELECTED_HOMES, [])
            if not selected_homes:
                errors["base"] = "no_homes_selected"
            else:
                self._selected_homes = selected_homes
                return await self.async_step_confirm()
        
        home_options = {}
        for home_id, home_info in self._homes.items():
            home_id_str = str(home_id)
            if isinstance(home_info, dict):
                home_name = home_info.get("name", f"家庭 {home_id}")
            else:
                home_name = str(home_info) if home_info else f"家庭 {home_id}"
            device_count = self._home_device_counts.get(home_id, 0)
            home_options[home_id_str] = f"{home_name} ({device_count}台设备)"
        
        default_selected = list(home_options.keys())
        _LOGGER.debug(f"Home options: {home_options}")
        _LOGGER.debug(f"Default selected: {default_selected}")
        
        return self.async_show_form(
            step_id="select_homes",
            data_schema=vol.Schema({
                vol.Required(CONF_SELECTED_HOMES, default=default_selected): vol.All(
                    cv.multi_select(home_options)
                )
            }),
            errors=errors,
        )

    async def async_step_confirm(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        if user_input is not None:
            return await self._create_entries()
        
        total_devices = sum(
            self._home_device_counts.get(int(home_id), 0) 
            for home_id in self._selected_homes
        )
        
        home_names = []
        for home_id_str in self._selected_homes:
            home_id = int(home_id_str) if home_id_str.isdigit() else home_id_str
            home_info = self._homes.get(home_id)
            if isinstance(home_info, dict):
                home_names.append(home_info.get("name", f"家庭 {home_id}"))
            else:
                home_names.append(str(home_info) if home_info else f"家庭 {home_id}")
        
        description = f"即将创建 {len(self._selected_homes)} 个家庭配置条目\n"
        description += f"设备总数: {total_devices} 台\n\n"
        description += "选中的家庭:\n"
        for i, home_id_str in enumerate(self._selected_homes):
            home_id = int(home_id_str) if home_id_str.isdigit() else home_id_str
            device_count = self._home_device_counts.get(home_id, 0)
            description += f"  - {home_names[i]} ({device_count}台设备)\n"
        
        return self.async_show_form(
            step_id="confirm",
            description_placeholders={
                "homes_count": str(len(self._selected_homes)),
                "devices_count": str(total_devices),
                "homes_list": description
            },
        )

    async def _create_entries(self) -> ConfigFlowResult:
        account = self._user_input[CONF_ACCOUNT]
        password = self._user_input[CONF_PASSWORD]
        server = self._user_input[CONF_SERVER]
        
        account_id = f"{account}_{server}"
        self._account_id = account_id
        
        entries_to_create = []
        for home_id_str in self._selected_homes:
            home_id = int(home_id_str) if home_id_str.isdigit() else home_id_str
            home_info = self._homes.get(home_id)
            
            if isinstance(home_info, dict):
                home_name = home_info.get("name", f"家庭 {home_id}")
            else:
                home_name = str(home_info) if home_info else f"家庭 {home_id}"
            
            device_count = self._home_device_counts.get(home_id, 0)
            online_count = self._home_online_counts.get(home_id, 0)
            entry_title = f"{account} | {home_name} ({device_count}台设备, {online_count}台在线)"
            unique_id = f"{account_id}_{home_id}"
            
            entries_to_create.append({
                "title": entry_title,
                "unique_id": unique_id,
                "home_id": home_id,
                "home_name": home_name,
            })
        
        existing_entries = self._async_current_entries()
        existing_unique_ids = {entry.unique_id for entry in existing_entries}
        
        for entry_info in entries_to_create:
            if entry_info["unique_id"] in existing_unique_ids:
                for entry in existing_entries:
                    if entry.unique_id == entry_info["unique_id"]:
                        self.hass.config_entries.async_update_entry(
                            entry,
                            title=entry_info["title"],
                            data={
                                CONF_TYPE: CONF_ACCOUNT,
                                CONF_ACCOUNT: account,
                                CONF_PASSWORD: password,
                                CONF_SERVER: server,
                                CONF_HOME_ID: entry_info["home_id"],
                                CONF_HOME_NAME: entry_info["home_name"],
                                CONF_ACCOUNT_ID: account_id,
                            }
                        )
                        _LOGGER.debug(f"Updated existing entry for home: {entry_info['home_name']}")
                        break
        
        new_entries = [
            entry_info for entry_info in entries_to_create
            if entry_info["unique_id"] not in existing_unique_ids
        ]
        
        if not new_entries:
            return self.async_abort(reason="entries_created")
        
        first_entry = new_entries[0]
        await self.async_set_unique_id(first_entry["unique_id"])
        
        for entry_info in new_entries[1:]:
            new_entry = config_entries.ConfigEntry(
                version=self.VERSION,
                minor_version=1,
                domain=DOMAIN,
                title=entry_info["title"],
                data={
                    CONF_TYPE: CONF_ACCOUNT,
                    CONF_ACCOUNT: account,
                    CONF_PASSWORD: password,
                    CONF_SERVER: server,
                    CONF_HOME_ID: entry_info["home_id"],
                    CONF_HOME_NAME: entry_info["home_name"],
                    CONF_ACCOUNT_ID: account_id,
                },
                source=config_entries.SOURCE_USER,
                unique_id=entry_info["unique_id"],
                options={},
                discovery_keys=set(),
                subentries_data=None,
            )
            await self.hass.config_entries.async_add(new_entry)
            _LOGGER.debug(f"Created additional entry for home: {entry_info['home_name']}")
        
        return self.async_create_entry(
            title=first_entry["title"],
            data={
                CONF_TYPE: CONF_ACCOUNT,
                CONF_ACCOUNT: account,
                CONF_PASSWORD: password,
                CONF_SERVER: server,
                CONF_HOME_ID: first_entry["home_id"],
                CONF_HOME_NAME: first_entry["home_name"],
                CONF_ACCOUNT_ID: account_id,
            },
        )


class OptionsFlowHandler(config_entries.OptionsFlow):
    def __init__(self, config_entry: config_entries.ConfigEntry):
        self._config_entry = config_entry

    async def async_step_init(self, user_input=None, error=None):
        if user_input is not None:
            if user_input["option"] == "change_credentials":
                return await self.async_step_change_credentials()
        
        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema({
                vol.Required("option", default="change_credentials"): vol.In({
                    "change_credentials": "修改账号密码",
                })
            }),
            errors=error
        )

    async def async_step_change_credentials(self, user_input=None, error=None):
        errors: dict[str, str] = {}
        
        if user_input is not None:
            cloud = get_midea_cloud(
                session=async_create_clientsession(self.hass),
                cloud_name=CONF_SERVERS[user_input[CONF_SERVER]],
                account=user_input[CONF_ACCOUNT],
                password=user_input[CONF_PASSWORD]
            )
            try:
                if await cloud.login():
                    current_data = dict(self._config_entry.data)
                    current_data.update({
                        CONF_ACCOUNT: user_input[CONF_ACCOUNT],
                        CONF_PASSWORD: user_input[CONF_PASSWORD],
                        CONF_SERVER: user_input[CONF_SERVER]
                    })
                    
                    self.hass.config_entries.async_update_entry(
                        self._config_entry,
                        data=current_data
                    )
                    return self.async_create_entry(title="", data={})
                else:
                    errors["base"] = "login_failed"
            except Exception as e:
                _LOGGER.exception("Login error: %s", e)
                errors["base"] = "login_failed"
        
        current_data = self._config_entry.data
        
        return self.async_show_form(
            step_id="change_credentials",
            data_schema=vol.Schema({
                vol.Required(CONF_ACCOUNT, default=current_data.get(CONF_ACCOUNT, "")): str,
                vol.Required(CONF_PASSWORD, default=""): str,
                vol.Required(CONF_SERVER, default=current_data.get(CONF_SERVER, 2)): vol.In(CONF_SERVERS)
            }),
            errors=errors,
        )
