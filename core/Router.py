# -*- coding:utf-8 -*-
"""
@Time : 2023/4/4
@Author: billy
@Des: 路由聚合
"""
from api.api import api_router
from fastapi import APIRouter

router = APIRouter()
# API路由
router.include_router(api_router)
