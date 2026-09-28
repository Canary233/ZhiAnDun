# -*- coding: utf-8 -*-
"""扫描器结果文件智能解析路由"""
from flask import Blueprint, request, jsonify

from core import scanners

bp = Blueprint("scanner", __name__)

# 允许上传的扫描结果文件类型
ALLOWED_EXT = {".json", ".jsonl", ".txt", ".xml", ".log", ".csv"}
MAX_SIZE = 20 * 1024 * 1024  # 20MB


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
    sev_cn = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危",
              "info": "信息", "unknown": "未知"}
    return jsonify(code=0, msg="解析成功", data={
        "source": result["source"],
        "source_cn": {"nuclei": "Nuclei", "burp": "Burp Suite", "json": "通用 JSON",
                      "text": "纯文本"}.get(result["source"], result["source"]),
        "count": result["count"],
        "severity_stats": stats,
        "severity_stats_cn": {sev_cn.get(k, k): v for k, v in stats.items()},
        "findings": result["findings"],
    })
