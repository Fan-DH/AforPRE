"""Track dependency discovery. Read-only analysis remains usable without Pin."""
import os
import platform
from pathlib import Path

from tools.engine_info import EngineInfo, register_engine

ROOT = Path(__file__).resolve().parents[3] / "track"


def paths():
    pin_root = Path(os.environ.get("APRE_PIN_ROOT") or os.environ.get("PIN_ROOT") or ROOT / ".deps/pin")
    return str((pin_root / "pin").resolve()), str(Path(os.environ.get("APRE_TRACK_PLUGIN") or ROOT / "obj-intel64/pretrace.so").resolve())


def probe_environment():
    pin, plugin = paths()
    supported = platform.system() == "Linux" and platform.machine() in ("x86_64", "amd64")
    installed = os.path.isfile(pin) and os.access(pin, os.X_OK) and os.path.isfile(plugin)
    return {"installed": installed, "available": installed and supported,
            "pin_path": pin, "plugin_path": plugin, "platform_supported": supported,
            "execution_tested": False, "offline_analysis_available": True,
            "limitations": ["路径/平台检查不证明 Pin 能实际运行；ptrace、SDK 与插件兼容性在采集时验证。"],
            "dependencies": [], "unavailable_dependencies": []}


def get_install_details():
    return {"install_hint": "使用项目原生 track；不自动下载或编译。",
            "install_steps": [f"在 {ROOT} 执行 ./scripts/bootstrap.sh（下载固定 SDK），然后 make -j2。",
                              "也可设置 APRE_PIN_ROOT（兼容 PIN_ROOT）和 APRE_TRACK_PLUGIN；重新启动 MCP 后复检。"],
            "offline_analysis_available": True}


register_engine(EngineInfo(name="track", prefix="track_", is_available=lambda: probe_environment()["available"],
                          get_details=get_install_details, provider_module="tools.track.main",
                          provider_class="TrackProvider", probe_environment=probe_environment, required=False))
