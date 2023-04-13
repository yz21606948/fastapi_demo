# -*- coding:utf-8 -*-
"""
@Time : 2023/4/11
@Author: billy
@Des: 公共
"""
from fastapi import Request
from models.base import AccessLog


async def write_access_log(req: Request, user_id: int,  note: str = None):
    """
    写入访问日志
    :param user_id: 用户ID
    :param req: 请求头
    :param note: 备注
    :return:
    """
    data = {
        "user_id": user_id,
        "target_url": req.get("path"),
        "user_agent": req.headers.get('user-agent'),
        "request_params": {
            "method": req.method,
            "params": dict(req.query_params),
            "body": bytes(await req.body()).decode()
        },
        "ip": req.headers.get('x-forwarded-for'),
        "note": note
    }
    await AccessLog.create(**data)
    