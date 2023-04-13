# -*- coding:utf-8 -*-
"""
@Time : 2023/4/4
@Author: billy
@Des: mysql数据库
"""

from fastapi import FastAPI
from tortoise.contrib.fastapi import register_tortoise
from config import settings

# -----------------------数据库配置-----------------------------------
DB_ORM_CONFIG = {
    "connections": {
        "base": {
            'engine': 'tortoise.backends.mysql',
            "credentials": {
                'host': settings.BASE_HOST,
                'user': settings.BASE_USER,
                'password': settings.BASE_PASSWORD,
                'port': settings.BASE_PORT,
                'database': settings.BASE_DB,
            }
        }

    },
    "apps": {
        "base": {"models": ["models.base"], "default_connection": "base"},
    },
    'use_tz': False,
    'timezone': 'Asia/Shanghai'
}

async def register_mysql(app: FastAPI):
    # 注册数据库
    register_tortoise(
        app,
        config=DB_ORM_CONFIG,
        generate_schemas=False,
        add_exception_handlers=True,
    )
    