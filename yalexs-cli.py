#!/usr/bin/env python3
"""
yalexs-cli.py — Thin JSON CLI around the yalexs (Yale Home cloud) library.

Usage (seed tokens from Home Assistant, then operate):
  ./yalexs-cli.py auth seed \
      --access "<ACCESS_TOKEN>" \
      --refresh "<REFRESH_TOKEN>" \
      --expires-at 1765028565.57 \
      --brand YALE_GLOBAL

  ./yalexs-cli.py locks
  ./yalexs-cli.py status <LOCK_ID>
  ./yalexs-cli.py lock <LOCK_ID>
  ./yalexs-cli.py unlock <LOCK_ID>
  ./yalexs-cli.py offline-keys --brand YALE_GLOBAL <LOCK_ID>

  ./yalexs-cli.py status-ble [--index <INDEX> | --serial <SERIAL>]
  ./yalexs-cli.py lock-ble [--index <INDEX> | --serial <SERIAL>]
  ./yalexs-cli.py unlock-ble [--index <INDEX> | --serial <SERIAL>]

Config/Cache files:
  ~/.config/yalexs-cli/settings.json
"""

import argparse
import asyncio
import dataclasses
import enum
import datetime
import json
import os
import sys
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, Optional

from aiohttp import ClientSession

# ----------- resilient yalexs imports (version changes happen) -----------
try:
    from yalexs.api_async import ApiAsync  # common path
except Exception:  # pragma: no cover
    # Fallback older/newer
    from yalexs.api import ApiAsync  # type: ignore

try:
    from yalexs.const import Brand
except Exception:  # pragma: no cover
    # Some versions export brands at top-level
    from yalexs import Brand  # type: ignore

# =================== Files & helpers ===================

def _config_dir() -> Path:
    if os.name == "nt":
        return Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming")) / "yalexs-cli"
    return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "yalexs-cli"

CFG_DIR = _config_dir()
SETTINGS_PATH = CFG_DIR / "settings.json"  # <--- single file now

def _ensure_dirs():
    CFG_DIR.mkdir(parents=True, exist_ok=True)

def _load_settings() -> Dict:
    try:
        data = json.loads(SETTINGS_PATH.read_text())
        # Backfill missing defaults
        base = _default_settings()
        base.update(data.get("settings", {}))
        return base
    except FileNotFoundError:
        return _default_settings()
    except Exception as e:
        _fail("SETTINGS_READ_FAILED", str(e))

def _save_settings(d: Dict):
    # Load existing file if present, preserve tokens
    try:
        data = json.loads(SETTINGS_PATH.read_text())
    except Exception:
        data = {}
    data["settings"] = d
    SETTINGS_PATH.write_text(json.dumps(data, indent=2))

def _select_offline_key(args):
    try:
        data = json.loads(SETTINGS_PATH.read_text())
        offline_keys = data.get("offlineKey", [])
        if not offline_keys:
            _fail("NO_OFFLINE_KEY", "No offlineKey entries in settings.json. Run 'offline-keys' first.")
        if args.serial:
            for k in offline_keys:
                if k.get("serial") == args.serial:
                    return k
            _fail("NO_MATCHING_SERIAL", f"No offlineKey entry with serial {args.serial}")
        idx = args.index if args.index is not None else 0
        if idx < 0 or idx >= len(offline_keys):
            _fail("INDEX_OUT_OF_RANGE", f"offlineKey index {idx} out of range.")
        return offline_keys[idx]
    except FileNotFoundError:
        _fail("NO_SETTINGS_FILE", "settings.json not found. Run 'auth seed' and 'offline-keys' first.")
    except Exception as e:
        _fail("SETTINGS_READ_FAILED", str(e))

@dataclass
class Tokens:
    access_token: str
    refresh_token: Optional[str] = None
    expires_at: Optional[float] = None
    token_type: Optional[str] = "Bearer"
    scope: Optional[str] = None

def _load_tokens() -> Tokens:
    try:
        data = json.loads(SETTINGS_PATH.read_text())
        tokens = data.get("tokens")
        if not tokens:
            _fail("NO_TOKENS", "No tokens stored. Run 'auth seed' first.")
        return Tokens(**tokens)
    except FileNotFoundError:
        _fail("NO_TOKENS", "No tokens stored. Run 'auth seed' first.")
    except Exception as e:
        _fail("TOKENS_READ_FAILED", str(e))

def _save_tokens(t: Tokens):
    # Load existing file if present, preserve settings
    try:
        data = json.loads(SETTINGS_PATH.read_text())
    except Exception:
        data = {}
    data["tokens"] = asdict(t)
    SETTINGS_PATH.write_text(json.dumps(data, indent=2))

def _brand_from(s: Optional[str]) -> Brand:
    val = (s or _load_settings().get("brand") or "YALE_GLOBAL").upper()
    try:
        return getattr(Brand, val)
    except Exception:
        _fail("BAD_BRAND", f"Unknown brand '{val}'. Try YALE_GLOBAL or AUGUST.")
        raise

def _default_settings() -> Dict:
    # Defaults match Yale Global cloud
    return {
        "brand": "YALE_GLOBAL",
        "token_url": "https://oauth.aaecosystem.com/oauth2/token",
        "authorize_url": "https://oauth.aaecosystem.com/authorization",
        "scope": "openid profile email offline_access",
        # "client_id": "...",  # Optional, can be set later
    }

# =================== Auth commands ===================

async def cmd_auth_seed(args):
    """
    Seed tokens/settings from Home Assistant (or any source) so we can operate & refresh.
    """
    _ensure_dirs()
    settings = _load_settings()
    if args.brand:
        settings["brand"] = args.brand
    if args.token_url:
        settings["token_url"] = args.token_url
    if args.client_id:
        settings["client_id"] = args.client_id
    # persist settings
    _save_settings(settings)

    expires_at = float(args.expires_at) if args.expires_at is not None else None
    tokens = Tokens(
        access_token=args.access,
        refresh_token=args.refresh,
        expires_at=expires_at,
        token_type="Bearer",
        scope=settings.get("scope"),
    )
    _save_tokens(tokens)
    _ok({"seeded": True, "settings_path": str(SETTINGS_PATH)})

async def _refresh_if_needed():
    """
    If token is within 120s of expiry, refresh it.
    """
    tokens = _load_tokens()
    if tokens.expires_at and time.time() <= tokens.expires_at - 120:
        return tokens  # still good
    # need refresh (or no expiry recorded)
    class _Args:
        token_url: Optional[str] = None
        client_id: Optional[str] = None
    await cmd_auth_refresh(_Args())
    return _load_tokens()

async def cmd_auth_refresh(args):
    """
    Refresh the access token using stored refresh_token.
    """
    _ensure_dirs()
    settings = _load_settings()
    tokens = _load_tokens()

    token_url = args.token_url or settings.get("token_url")
    client_id = args.client_id or settings.get("client_id")

    if not token_url:
        _fail("NO_TOKEN_URL", "No token_url configured. Seed settings or pass --token-url.")
    if not tokens.refresh_token:
        _fail("NO_REFRESH_TOKEN", "No refresh_token available. Run 'auth seed' again.")

    async with ClientSession() as s:
        form = {
            "grant_type": "refresh_token",
            "refresh_token": tokens.refresh_token,
        }
        if client_id:
            form["client_id"] = client_id
        async with s.post(token_url, data=form) as resp:
            txt = await resp.text()
            if resp.status != 200:
                _fail("REFRESH_FAILED", f"{resp.status}: {txt}")
            payload = json.loads(txt)

    access_token = payload.get("access_token")
    if not access_token:
        _fail("NO_ACCESS_TOKEN", "Refresh response missing access_token.")
    tokens.access_token = access_token
    tokens.refresh_token = payload.get("refresh_token", tokens.refresh_token)
    if isinstance(payload.get("expires_in"), (int, float)):
        tokens.expires_at = time.time() + float(payload["expires_in"])
    tokens.token_type = payload.get("token_type", tokens.token_type)
    tokens.scope = payload.get("scope", tokens.scope)
    _save_tokens(tokens)

    _ok({"message": "Refreshed", "expires_at": tokens.expires_at})

# =================== Yale operations ===================

async def cmd_locks(args):
    tokens = await _refresh_if_needed()
    brand = _brand_from(args.brand)
    async with ClientSession() as session:
        api = ApiAsync(session, timeout=20, brand=brand)
        # yalexs versions differ: try sync-like then async variant
        try:
            locks = api.get_locks(tokens.access_token)  # type: ignore[attr-defined]
        except AttributeError:
            locks = await api.async_get_locks(tokens.access_token)  # type: ignore[attr-defined]

        out = []
        for lk in locks:
            out.append({
                "id": getattr(lk, "device_id", None) or getattr(lk, "lock_id", None),
                "name": getattr(lk, "device_name", None) or getattr(lk, "name", None),
                "model": getattr(lk, "model", None),
                "serial": getattr(lk, "serial_number", None),
            })
        _ok({"locks": out})

def _to_jsonable(obj):
    """Recursively convert yalexs model objects, dataclasses, Enums, datetimes, etc. into JSON-safe structures."""
    if isinstance(obj, enum.Enum):
        return obj.value
    if isinstance(obj, (datetime.datetime, datetime.date)):
        return obj.isoformat()
    if dataclasses.is_dataclass(obj):
        return {k: _to_jsonable(v) for k, v in dataclasses.asdict(obj).items()}
    if hasattr(obj, "dict") and callable(obj.dict):
        try:
            return {k: _to_jsonable(v) for k, v in obj.dict().items()}
        except Exception:
            pass
    if isinstance(obj, dict):
        return {k: _to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [_to_jsonable(v) for v in obj]
    if hasattr(obj, "__dict__") and not isinstance(obj, type):
        return {k: _to_jsonable(v) for k, v in vars(obj).items()}
    return obj

async def cmd_status(args):
    tokens = await _refresh_if_needed()
    brand = _brand_from(args.brand)
    async with ClientSession() as session:
        api = ApiAsync(session, timeout=20, brand=brand)
        st = None
        last_err = None
        for meth in (
            "async_get_lock_status",
            "async_get_lock_detail",
            "async_get_door_status",
        ):
            func = getattr(api, meth, None)
            if func:
                try:
                    st = await func(tokens.access_token, args.id)
                    break
                except Exception as e:
                    last_err = str(e)
        if st is None:
            _fail("STATUS_FAILED", f"No usable status method. Last error: {last_err or 'unknown'}")

        # ✅ Ensure conversion here
        st_data = _to_jsonable(st)
        _ok(st_data)

async def cmd_status_ble(args):
    """
    Get just Door and Lock state via BLE using yalexs_ble.
    Requires offlineKey in settings.json with fields:
      - key (hex string)
      - slot (int)
      - serial (string)
    """

    offline_key = _select_offline_key(args)
    key_hex = offline_key["key"]
    key_index = offline_key["slot"]
    serial = offline_key["serial"]

    # --- Imports ---
    try:
        from bleak import BleakScanner
        from yalexs_ble import serial_to_local_name
        from yalexs_ble.lock import Lock
    except ImportError as e:
        _fail("BLE_NOT_AVAILABLE", f"Missing dependency: {e}")

    # --- Compute BLE local name from serial ---
    local_name = serial_to_local_name(serial)

    # --- Scan once to find the device we want (by local_name) ---
    found_event = asyncio.Event()
    found_device = None

    def detection_callback(device, advertisement_data):
        nonlocal found_device
        if device and device.name == local_name:
            # We have our target
            found_device = device
            found_event.set()

    try:
        # Bleak 1.x supports passing the callback at construction; filters may be ignored on some backends
        try:
            scanner = BleakScanner(
                detection_callback=detection_callback,
                filters={"LocalName": local_name},
            )
        except TypeError:
            scanner = BleakScanner(detection_callback=detection_callback)

        await scanner.start()
        try:
            await asyncio.wait_for(found_event.wait(), timeout=5)
        except asyncio.TimeoutError:
            _fail("LOCK_NOT_FOUND", f"No BLE advertisements for {local_name} within 5s.")
        finally:
            await scanner.stop()
    except Exception as e:
        _fail("BLE_SCAN_FAILED", f"Scan failed: {e}")

    # --- Callbacks expected by yalexs_ble.Lock ---
    # Lock.connect() will call this WITH NO ARGS; it must return the BLEDevice
    def ble_device_callback():
        return found_device

    # Optional; noop to avoid signature surprises
    def state_callback(state):
        return

    # --- Connect and query only what we need ---
    try:
        lock = Lock(
            ble_device_callback=ble_device_callback,
            keyString=key_hex,          # hex string from settings
            keyIndex=key_index,         # slot/index (int)
            name=local_name,            # BLE local name derived from serial
            state_callback=state_callback,
        )

        await lock.connect()
        try:
            door_state = await lock.door_status()
            lock_state = await lock.lock_status()
        finally:
            await lock.disconnect()

        # Normalize enums to strings
        door_text = getattr(door_state, "name", str(door_state))
        lock_text = getattr(lock_state, "name", str(lock_state))

        _ok({"door": door_text, "lock": lock_text})

    except Exception as e:
        _fail("BLE_STATUS_FAILED", f"Failed to get BLE status: {e}")

async def cmd_lock_ble(args):
    """
    Lock the lock via BLE using offlineKey (keyString, keyIndex, and serial) from settings.json.
    Works cross-platform using yalexs_ble.
    """

    offline_key = _select_offline_key(args)
    key_hex = offline_key["key"]
    key_index = offline_key["slot"]
    serial = offline_key["serial"]

    # --- Imports ---
    try:
        from bleak import BleakScanner
        from yalexs_ble import serial_to_local_name
        from yalexs_ble.lock import Lock
    except ImportError as e:
        _fail("BLE_NOT_AVAILABLE", f"Failed to import BLE dependencies: {str(e)}")

    local_name = serial_to_local_name(serial)
    found_event = asyncio.Event()
    found_device = None

    # --- Detection callback ---
    def detection_callback(device, advertisement_data):
        nonlocal found_device
        if device and device.name == local_name:
            found_device = device
            found_event.set()

    # --- Scan for lock ---
    try:
        try:
            scanner = BleakScanner(
                detection_callback=detection_callback,
                filters={"LocalName": local_name},
            )
        except TypeError:
            scanner = BleakScanner(detection_callback=detection_callback)

        await scanner.start()
        try:
            await asyncio.wait_for(found_event.wait(), timeout=5)  # 5 sec scan
        except asyncio.TimeoutError:
            await scanner.stop()
            _fail("LOCK_NOT_FOUND", f"No BLE advertisement from {local_name} in range.")
        finally:
            await scanner.stop()
    except Exception as e:
        _fail("BLE_SCAN_FAILED", f"Failed during BLE scan: {str(e)}")

    # --- Callbacks expected by yalexs_ble.Lock ---
    def ble_device_callback():
        return found_device

    def state_callback(state):
        print(f"Lock state callback: {state}")

    # --- Connect and lock ---
    try:
        lock = Lock(
            ble_device_callback=ble_device_callback,
            keyString=key_hex,
            keyIndex=key_index,
            name=local_name,
            state_callback=state_callback,
        )

        await lock.connect()
        try:
            await lock.lock()
            _ok({"result": "LOCK_COMMAND_SENT"})
        finally:
            await lock.disconnect()
    except Exception as e:
        _fail("BLE_LOCK_FAILED", f"Failed to lock via BLE: {str(e)}")

async def cmd_unlock_ble(args):
    """
    Unlock the lock via BLE using offlineKey (keyString, keyIndex, and serial) from settings.json.
    Works cross-platform using yalexs_ble.
    """

    offline_key = _select_offline_key(args)
    keyString = offline_key["key"]
    keyIndex = offline_key["slot"]
    serial = offline_key["serial"]

    # --- Imports ---
    try:
        from bleak import BleakScanner
        from yalexs_ble import serial_to_local_name
        from yalexs_ble.lock import Lock
    except ImportError as e:
        _fail("BLE_NOT_AVAILABLE", f"Failed to import BLE dependencies: {str(e)}")

    local_name = serial_to_local_name(serial)
    found_event = asyncio.Event()
    found_device = None

    # --- Detection callback ---
    def detection_callback(device, advertisement_data):
        nonlocal found_device
        if device and device.name == local_name:
            found_device = device
            found_event.set()

    # --- Scan for lock ---
    try:
        try:
            scanner = BleakScanner(
                detection_callback=detection_callback,
                filters={"LocalName": local_name},
            )
        except TypeError:
            scanner = BleakScanner(detection_callback=detection_callback)

        await scanner.start()
        try:
            await asyncio.wait_for(found_event.wait(), timeout=5)  # 5 sec scan
        except asyncio.TimeoutError:
            await scanner.stop()
            _fail("LOCK_NOT_FOUND", f"No BLE advertisement from {local_name} in range.")
        finally:
            await scanner.stop()
    except Exception as e:
        _fail("BLE_SCAN_FAILED", f"Failed during BLE scan: {str(e)}")

    # --- Callbacks expected by yalexs_ble.Lock ---
    def ble_device_callback():
        return found_device

    def state_callback(state):
        print(f"Lock state callback: {state}")

    # --- Connect and unlock ---
    try:
        lock = Lock(
            ble_device_callback=ble_device_callback,
            keyString=keyString,
            keyIndex=keyIndex,
            name=local_name,
            state_callback=state_callback,
        )

        await lock.connect()
        try:
            await lock.unlock()
            _ok({"result": "UNLOCK_COMMAND_SENT"})
        finally:
            await lock.disconnect()
    except Exception as e:
        _fail("BLE_UNLOCK_FAILED", f"Failed to unlock via BLE: {str(e)}")

async def _do_action(lock_id: str, action: str, brand: Brand, tokens: Tokens):
    async with ClientSession() as session:
        api = ApiAsync(session, timeout=20, brand=brand)
        # Try common action names first
        try_methods = []
        if action == "lock":
            try_methods = ["async_lock", "async_lock_operation"]
        else:
            try_methods = ["async_unlock", "async_lock_operation"]

        last_err = None
        for meth in try_methods:
            fn = getattr(api, meth, None)
            if not fn:
                continue
            try:
                if meth == "async_lock_operation":
                    # expected signature: (access_token, lock_id, "lock"|"unlock")
                    await fn(tokens.access_token, lock_id, action)
                else:
                    # expected signature: (access_token, lock_id)
                    await fn(tokens.access_token, lock_id)
                _ok({"id": lock_id, "action": action})
            except Exception as e:
                last_err = str(e)

        _fail("LOCK_ACTION_FAILED", f"{action} failed. {last_err or 'No usable method on this yalexs version.'}")

async def cmd_lock(args):
    tokens = await _refresh_if_needed()
    brand = _brand_from(args.brand)
    await _do_action(args.id, "lock", brand, tokens)

async def cmd_unlock(args):
    tokens = await _refresh_if_needed()
    brand = _brand_from(args.brand)
    await _do_action(args.id, "unlock", brand, tokens)

async def cmd_offline_keys(args):
    tokens = await _refresh_if_needed()
    brand = _brand_from(args.brand)

    async with ClientSession() as session:
        api = ApiAsync(session, timeout=20, brand=brand)
        st = None
        last_err = None

        # Try the most likely API method first
        for meth in ("async_get_lock_detail",):
            func = getattr(api, meth, None)
            if func:
                try:
                    st = await func(tokens.access_token, args.id)
                    break
                except Exception as e:
                    last_err = str(e)

        if st is None:
            _fail("OFFLINE_KEYS_FAILED", f"No usable method. Last error: {last_err or 'unknown'}")

        # Convert to JSON-safe dict
        try:
            data_json = _to_jsonable(st)
        except Exception as e:
            _fail("LOCK_DETAIL_PARSE_FAILED", f"Unable to parse lock detail: {str(e)}")

        # Try to extract offline keys
        offline_keys = data_json.get("_data", {}).get("OfflineKeys")
        if offline_keys is None:
            _fail("NO_OFFLINE_KEYS", "No offline keys found for this lock")

        # Also extract serial if available
        serial_val = (
            data_json.get("_data", {}).get("serial")
            or data_json.get("_data", {}).get("SerialNumber")
            or data_json.get("_data", {}).get("LockID")
        )
        if not serial_val:
            print(f"No serial found in lock detail; BLE commands may not work without it.")

        # Save key, slot, and serial to settings.json at top-level offlineKey (now an array)
        key_obj = None
        loaded = offline_keys.get("loaded", [])
        if loaded and isinstance(loaded, list):
            first = loaded[0]
            key_val = first.get("key")
            slot_val = first.get("slot")
            if key_val and slot_val is not None:
                try:
                    settings_data = json.loads(SETTINGS_PATH.read_text())
                except Exception:
                    settings_data = {}
                offline_keys_arr = settings_data.get("offlineKey", [])
                # Remove any with same serial
                offline_keys_arr = [k for k in offline_keys_arr if k.get("serial") != serial_val]
                # Add new
                new_entry = {
                    "key": key_val,
                    "slot": slot_val,
                    "serial": serial_val,
                }
                offline_keys_arr.append(new_entry)
                settings_data["offlineKey"] = offline_keys_arr
                SETTINGS_PATH.write_text(json.dumps(settings_data, indent=2))
                key_obj = new_entry

        _ok({
            "offline_keys": offline_keys,
            "offlineKey_saved": key_obj
        })

# =================== CLI wiring ===================

def _build_parser():
    p = argparse.ArgumentParser(
        prog="yalexs-cli",
        description="Thin JSON CLI around yalexs (Yale Home cloud). Defaults to YALE_GLOBAL."
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    # Parent parser for commands needing brand
    brand_parent = argparse.ArgumentParser(add_help=False)
    brand_parent.add_argument("--brand", default=None, help="Brand (default from settings)")

    # -------------------------
    # auth group
    pa = sub.add_parser("auth", help="Authentication & token management")
    asub = pa.add_subparsers(dest="auth_cmd", required=True)

    seed = asub.add_parser("seed", help="Seed tokens/settings (e.g., copy from Home Assistant)")
    seed.add_argument("--access", required=True, help="Access token")
    seed.add_argument("--refresh", required=True, help="Refresh token")
    seed.add_argument("--expires-at", type=float, help="Access token expiry (epoch seconds)")
    seed.add_argument("--brand", default="YALE_GLOBAL", help="Brand (YALE_GLOBAL/AUGUST). Default YALE_GLOBAL")
    seed.add_argument("--token-url", default=None, help="OAuth token endpoint URL")
    seed.add_argument("--client-id", default=None, help="OAuth client_id")
    seed.set_defaults(func=cmd_auth_seed)

    # -------------------------
    # operations
    lk = sub.add_parser("locks", parents=[brand_parent], help="List locks")
    lk.set_defaults(func=cmd_locks)

    st = sub.add_parser("status", parents=[brand_parent], help="Get status for a lock")
    st.add_argument("id", help="Lock ID")
    st.set_defaults(func=cmd_status)

    lka = sub.add_parser("lock", parents=[brand_parent], help="Lock a device")
    lka.add_argument("id")
    lka.set_defaults(func=cmd_lock)

    uka = sub.add_parser("unlock", parents=[brand_parent], help="Unlock a device")
    uka.add_argument("id") 
    uka.set_defaults(func=cmd_unlock)

    ok = sub.add_parser("offline-keys", parents=[brand_parent], help="Get offline keys for a lock")
    ok.add_argument("id", help="Lock ID")
    ok.set_defaults(func=cmd_offline_keys)

    # -------------------------
    # BLE status
    ble_st = sub.add_parser("status-ble", help="Get lock status via BLE")
    ble_st.set_defaults(func=cmd_status_ble)

    # -------------------------
    # BLE lock
    ble_lk = sub.add_parser("lock-ble", help="Lock a lock via BLE")
    ble_lk.set_defaults(func=cmd_lock_ble)

    # -------------------------
    # BLE unlock
    ble_un = sub.add_parser("unlock-ble", help="Unlock a lock via BLE")
    ble_un.set_defaults(func=cmd_unlock_ble)

    for ble_cmd in [ble_st, ble_lk, ble_un]:
        ble_cmd.add_argument("--serial", help="Serial number of lock to use from offlineKey array")
        ble_cmd.add_argument("--index", type=int, help="Index in offlineKey array to use (default 0)")

    return p

def _ok(obj):
    print(json.dumps(obj, indent=2))
    sys.exit(0)

def _fail(code, msg):
    print(json.dumps({"error": code, "message": msg}), file=sys.stderr)
    sys.exit(1)

def main():
    _ensure_dirs()
    parser = _build_parser()
    args = parser.parse_args()
    asyncio.run(args.func(args))

if __name__ == "__main__":
    main()
