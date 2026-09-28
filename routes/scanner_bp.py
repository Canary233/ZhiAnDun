# -*- coding: utf-8 -*-
"""扫描器结果文件智能解析路由 + Shelling 扫描平台联动路由"""
from flask import Blueprint, request, jsonify

from core import scanners, shelling_client

bp = Blueprint("scanner", __name__)

# 允许上传的扫描结果文件类型
ALLOWED_EXT = {".json", ".jsonl", ".txt", ".xml", ".log", ".csv"}
MAX_SIZE = 20 * 1024 * 1024  # 20MB

# Shelling 支持的扫描类型与中文名
SCAN_TYPES = ("quick", "full", "custom")
SCAN_TYPE_CN = {"quick": "快速扫描", "full": "全量扫描", "custom": "自定义扫描"}

# 严重等级中文名
_SEV_CN = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危",
           "info": "信息", "unknown": "未知"}


@bp.post("/api/scanner/parse")
def parse_file():
    f = request.files.get("file")
    if not f:
        return jsonify(code=1, msg="请选择扫描结果文件"), 400
    fname = f.filename or ""
    ext = "." + fname.rsplit(".", 1)[-1].lower() if "." in fname else ""
    if ext and ext not in ALLOWED_EXT:
        return jsonify(code=1, msg=f"暂不支持 {ext} 文件，支持 JSON/JSONL/XML/TXT/LOG/CSV"), 400
    content = f.read(MAX_SIZE + 1)
    if len(content) > MAX_SIZE:
        return jsonify(code=1, msg="文件过大（限制 20MB）"), 400
    try:
        result = scanners.parse_scanner_content(fname, content)
    except Exception as e:
        return jsonify(code=1, msg=f"解析失败：{e}"), 500
    stats = scanners.summarize_findings(result["findings"])
    return jsonify(code=0, msg="解析成功", data={
        "source": result["source"],
        "source_cn": {"nuclei": "Nuclei", "burp": "Burp Suite", "json": "通用 JSON",
                      "text": "纯文本"}.get(result["source"], result["source"]),
        "count": result["count"],
        "severity_stats": stats,
        "severity_stats_cn": {_SEV_CN.get(k, k): v for k, v in stats.items()},
        "findings": result["findings"],
    })


# ==================== Shelling 扫描平台联动 ====================
@bp.get("/api/scanner/shelling/options")
def shelling_options():
    """返回可选扫描类型，供前端下拉框渲染"""
    return jsonify(code=0, data={
        "scan_types": [{"value": t, "label": SCAN_TYPE_CN[t]} for t in SCAN_TYPES],
    })


@bp.post("/api/scanner/shelling/start")
def shelling_start():
    """在 Shelling 平台创建扫描任务，立即返回任务 ID（进度由前端轮询）"""
    data = request.get_json(silent=True) or {}
    target = (data.get("target") or "").strip()
    if not target:
        return jsonify(code=1, msg="请填写扫描目标（域名 / IP / URL）"), 400
    scan_type = (data.get("scan_type") or "quick").strip().lower()
    if scan_type not in SCAN_TYPES:
        scan_type = "quick"
    remark = (data.get("remark") or "").strip() or "智安盾发起"
    config = data.get("config") if isinstance(data.get("config"), dict) else None
    try:
        task = shelling_client.get_client().create_scan(
            target, scan_type=scan_type, remark=remark, config=config)
    except shelling_client.ShellingError as e:
        return jsonify(code=1, msg=str(e)), 502
    return jsonify(code=0, msg="扫描任务已提交", data={
        "scan_id": task.get("id"),
        "target": task.get("target") or target,
        "scan_type": task.get("scan_type") or scan_type,
        "scan_type_cn": SCAN_TYPE_CN.get(task.get("scan_type") or scan_type, ""),
        "status": task.get("status"),
        "status_cn": shelling_client.status_cn(task.get("status")),
    })


@bp.get("/api/scanner/shelling/status/<scan_id>")
def shelling_status(scan_id):
    """查询扫描进度（含子 Agent 明细）"""
    try:
        prog = shelling_client.get_client().get_progress(scan_id)
    except shelling_client.ShellingError as e:
        return jsonify(code=1, msg=str(e)), 502
    status = str(prog.get("status") or "").upper()
    return jsonify(code=0, data={
        "scan_id": prog.get("scan_id") or scan_id,
        "status": status,
        "status_cn": shelling_client.status_cn(status),
        "phase": prog.get("phase") or "",
        "message": prog.get("message") or "",
        "finished": status in shelling_client.FINISHED,
        "ok": status == "COMPLETED",
        "sub_agents": [{
            "name": s.get("name") or "",
            "role": s.get("role") or "",
            "status": s.get("status") or "",
            "progress": s.get("progress") or 0,
            "findings_count": s.get("findings_count") or 0,
            "summary": s.get("summary") or "",
        } for s in (prog.get("sub_agents") or [])],
    })


@bp.get("/api/scanner/shelling/result/<scan_id>")
def shelling_result(scan_id):
    """拉取扫描结果并转换为智安盾统一发现格式（可直接填入 AI 生成流程）"""
    try:
        client = shelling_client.get_client()
        task = client.get_scan(scan_id)
        vulns = client.get_vulnerabilities(scan_id)
    except shelling_client.ShellingError as e:
        return jsonify(code=1, msg=str(e)), 502
    findings = shelling_client.to_findings(vulns, target=task.get("target") or "")
    stats = scanners.summarize_findings(findings)
    return jsonify(code=0, msg="已获取扫描结果", data={
        "scan_id": scan_id,
        "target": task.get("target") or "",
        "scan_type_cn": SCAN_TYPE_CN.get(task.get("scan_type") or "", task.get("scan_type") or ""),
        "status": task.get("status"),
        "status_cn": shelling_client.status_cn(task.get("status")),
        "llm_summary": task.get("llm_summary") or "",
        "llm_risk_score": task.get("llm_risk_score"),
        "count": len(findings),
        "severity_stats": stats,
        "severity_stats_cn": {_SEV_CN.get(k, k): v for k, v in stats.items()},
        "findings": findings,
    })


@bp.post("/api/scanner/shelling/cancel/<scan_id>")
def shelling_cancel(scan_id):
    """请求取消正在进行的扫描"""
    try:
        shelling_client.get_client().cancel_scan(scan_id)
    except shelling_client.ShellingError as e:
        return jsonify(code=1, msg=str(e)), 502
    return jsonify(code=0, msg="已请求取消扫描")
