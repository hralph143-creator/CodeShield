USER_ERRORS = {
    "SCAN-001": "所选项目目录不存在。",
    "SCAN-002": "无法读取所选项目目录。",
    "SCAN-003": "扫描任务发生异常。",
    "DB-001": "本地数据库无法打开。",
    "RULE-001": "检测规则无效。",
    "REPORT-001": "报告写入失败。",
}


def user_error(code: str) -> str:
    return f"{USER_ERRORS.get(code, '操作失败。')}（{code}）"
