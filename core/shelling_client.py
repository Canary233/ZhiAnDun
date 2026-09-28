# -*- coding: utf-8 -*-
"""
智安盾 · Shelling 扫描平台接口客户端
=====================================
对接 Shelling（Hack Scan AI）开放 API，实现「一键发起扫描 → 回收漏洞结果」：

    登录换取 JWT → 创建扫描任务 → 轮询进度 → 拉取漏洞 → 转换为智安盾统一发现格式

依赖 Shelling 后端服务（默认 http://host.docker.internal:8000，即宿主机 8000 端口）。
账号密码仅保存在本机 config.json 的 shelling 段，不写入数据库、不出现在报告与日志中。
"""
import time
import threading
import logging

import requests

from config import get_cfg
from core.scanners import _finding, summarize_findings

logger = logging.getLogger(__name__)

# 令牌提前 60 秒视为过期，避免边界处 401
_TOKEN_SAFETY = 60
_TIMEOUT_CONNECT = 15
# 扫描已结束（终态）状态集合
FINISHED = ("COMPLETED", "FAILED", "CANCELLED")

STATUS_CN = {
    "PENDING": "排队中", "RUNNING": "扫描中", "PAUSED": "已暂停",
    "COMPLETED": "已完成", "FAILED": "失败", "CANCELLED": "已取消",
}


def status_cn(status) -> str:
    return STATUS_CN.get(str(status or "").upper(), str(status or "未知"))


class ShellingError(Exception):
    """Shelling 接口调用异常（msg 为可直接展示给用户的中文信息）"""


def _brief(resp) -> str:
    """从错误响应里提取一句简短说明"""
    try:
        data = resp.json()
    except ValueError:
        return (resp.text or "")[:200]
    if isinstance(data, dict):
        return str(data.get("detail") or data.get("message") or data)[:200]
    return str(data)[:200]


class ShellingClient:
    """Shelling 平台 API 客户端（线程安全，内部缓存并自动续期 JWT）"""

    def __init__(self, base_url, username, password, timeout=600):
        self.base_url = (base_url or "").rstrip("/")
        self.username = username or ""
        self.password = password or ""
        self.timeout = int(timeout or 600)
        self._token = None
        self._token_exp = 0.0
        self._lock = threading.Lock()

    # ---------------- 认证 ----------------
    def _login(self):
        if not self.base_url:
            raise ShellingError("未配置 Shelling 服务地址，请先在「系统设置 → Shelling 扫描平台」中填写")
        try:
            r = requests.post(f"{self.base_url}/api/v1/auth/login",
                              json={"username": self.username, "password": self.password},
                              timeout=_TIMEOUT_CONNECT)
        except requests.RequestException as e:
            raise ShellingError(f"无法连接 Shelling 服务（{self.base_url}）：{e}")
        if r.status_code != 200:
            raise ShellingError(f"Shelling 登录失败（HTTP {r.status_code}），请核对账号密码")
        try:
            tok = r.json()["token"]
            self._token = tok["access_token"]
            self._token_exp = time.time() + float(tok.get("expires_in") or 1800) - _TOKEN_SAFETY
        except (KeyError, TypeError, ValueError) as e:
            raise ShellingError(f"Shelling 登录响应格式异常：{e}")
        return self._token

    def _get_token(self, force=False):
        with self._lock:
            if force or not self._token or time.time() >= self._token_exp:
                return self._login()
            return self._token

    def _request(self, method, path, json_body=None, retry_on_401=True):
        token = self._get_token()
        try:
            r = requests.request(method, f"{self.base_url}{path}", json=json_body,
                                 headers={"Authorization": f"Bearer {token}"},
                                 timeout=_TIMEOUT_CONNECT)
        except requests.RequestException as e:
            raise ShellingError(f"请求 Shelling 失败：{e}")
        if r.status_code == 401 and retry_on_401:
            # 令牌过期/被吊销：强制续期后重试一次
            self._get_token(force=True)
            return self._request(method, path, json_body, retry_on_401=False)
        if r.status_code >= 400:
            raise ShellingError(f"Shelling 接口错误（HTTP {r.status_code}）：{_brief(r)}")
        if not r.content:
            return {}
        try:
            return r.json()
        except ValueError:
            return {}

    # ---------------- 业务接口 ----------------
    def ping(self):
        """连通性与认证检查，返回可用扫描器信息"""
        data = self._request("GET", "/api/v1/scanners")
        names = data.get("available_scanners") or []
        return {"base_url": self.base_url, "scanner_count": len(names), "scanners": names}

    def create_scan(self, target, scan_type="quick", remark="", config=None):
        body = {"target": target, "scan_type": scan_type or "quick"}
        if remark:
            body["remark"] = remark
        if config:
            body["config"] = config
        return self._request("POST", "/api/v1/scans", json_body=body)

    def get_scan(self, scan_id):
        return self._request("GET", f"/api/v1/scans/{scan_id}")

    def get_progress(self, scan_id):
        return self._request("GET", f"/api/v1/scans/{scan_id}/progress")

    def get_vulnerabilities(self, scan_id):
        data = self._request("GET", f"/api/v1/scans/{scan_id}/vulnerabilities")
        return data.get("items") or []

    def cancel_scan(self, scan_id):
        return self._request("POST", f"/api/v1/scans/{scan_id}/cancel")

    def wait_for_scan(self, scan_id, timeout=None, interval=3.0, on_tick=None):
        """阻塞等待扫描结束（供脚本/同步场景使用），返回最终 progress"""
        deadline = time.time() + (timeout or self.timeout)
        while True:
            prog = self.get_progress(scan_id)
            if on_tick:
                on_tick(prog)
            if str(prog.get("status") or "").upper() in FINISHED:
                return prog
            if time.time() >= deadline:
                raise ShellingError(f"扫描超时（超过 {timeout or self.timeout} 秒）")
            time.sleep(interval)


# ---------------- 结果转换 ----------------
def to_findings(items, target=""):
    """
    把 Shelling 的 VulnerabilityResponse 列表转换为智安盾统一 raw_findings 结构：
        {"source": "shelling", "data": {title, severity, url, evidence, description, raw}}
    """
    findings = []
    for v in items or []:
        if not isinstance(v, dict):
            continue
        location = v.get("location") or target or ""
        evidence = []
        if v.get("evidence"):
            evidence.append(str(v["evidence"]))
        if v.get("category"):
            evidence.append(f"漏洞类别：{v['category']}")
        if v.get("llm_false_positive_score") is not None:
            evidence.append(f"AI 误报评分：{v['llm_false_positive_score']}")
        desc = []
        if v.get("description"):
            desc.append(str(v["description"]))
        if v.get("llm_analysis"):
            desc.append("AI 分析：" + str(v["llm_analysis"]))
        if v.get("llm_remediation"):
            desc.append("整改建议：" + str(v["llm_remediation"]))
        findings.append(_finding(
            "shelling", v.get("name") or "未知漏洞", v.get("severity"),
            location, "\n".join(evidence), "\n".join(desc), raw=v,
        ))
    return findings


def summarize(items, target=""):
    """便捷方法：转换并统计"""
    findings = to_findings(items, target=target)
    return findings, summarize_findings(findings)


# ---------------- 客户端工厂 ----------------
def make_client(base_url=None, username=None, password=None, timeout=None) -> ShellingClient:
    """按传入值（优先）或 config.json 中的 shelling 配置构造客户端"""
    sh = get_cfg().get("shelling") or {}
    return ShellingClient(
        base_url=base_url or sh.get("base_url") or "",
        username=username or sh.get("username") or "",
        password=password or sh.get("password") or "",
        timeout=timeout or sh.get("timeout") or 600,
    )


_default_client = None
_default_lock = threading.Lock()


def get_client() -> ShellingClient:
    """获取进程内复用的默认客户端（缓存 JWT，避免每次请求都登录）"""
    global _default_client
    with _default_lock:
        if _default_client is None:
            _default_client = make_client()
        return _default_client


def reset_client():
    """配置变更后丢弃缓存客户端（连同其 JWT）"""
    global _default_client
    with _default_lock:
        _default_client = None