# -*- coding:utf-8 -*-
"""
@Created on : 2023/4/4
@Author: billy
@Des: 基本配置文件
"""

from dotenv import dotenv_values
from pydantic import BaseSettings
from typing import List

class Config(BaseSettings):
    # 加载环境变量
    configuration = dotenv_values(".env")
    # 调试模式
    APP_DEBUG: bool = True
    # 项目信息
    VERSION: str = "0.0.1"
    PROJECT_NAME: str = "fastapi"
    DESCRIPTION: str = '<a href="/redoc" target="_blank">redoc</a>'
    # 跨域请求
    CORS_ORIGINS: List[str] = ['*']
    CORS_ALLOW_CREDENTIALS: bool = True
    CORS_ALLOW_METHODS: List[str] = ['*']
    CORS_ALLOW_HEADERS: List[str] = ['*']
    # Session
    SECRET_KEY = "session"
    SESSION_COOKIE = "session_id"
    SESSION_MAX_AGE = 14 * 24 * 60 * 60
    # Jwt
    JWT_SECRET_KEY = configuration["JWT_SECRET_KEY"]
    JWT_ALGORITHM = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES = 24 * 60
    # MySQL数据库
    BASE_HOST = configuration["BASE_HOST"]
    BASE_USER = configuration["BASE_USER"]
    BASE_PASSWORD = configuration["BASE_PASSWORD"]
    BASE_PORT = configuration["BASE_PORT"]
    BASE_DB = configuration["BASE_DB"]

    SWAGGER_UI_OAUTH2_REDIRECT_URL = "/api/v1/test/oath2"
    
    # 二维码过期时间
    QRCODE_EXPIRE = 60 * 1
    
settings = Config()
