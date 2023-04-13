# -*- coding:utf-8 -*-
"""
@Time : 2023/4/10
@Author: billy
@Des: 用户管理
"""

import os
import time

from api.endpoints.common import write_access_log
from core.Response import success, fail, res_antd
from models.base import User, Role, Access, AccessLog
from schemas import user
from core.Utils import en_password, check_password, random_str
from core.Auth import create_access_token, check_permissions
from fastapi import Request, Query, APIRouter, Security, File, UploadFile
from config import settings
from typing import List
from tortoise.queryset import F

from schemas.user import UpdateUserInfo, ModifyMobile

router = APIRouter(prefix='/user')


@router.post("", summary="用户添加", dependencies=[Security(check_permissions, scopes=["user_add"])])
async def user_add(post: user.CreateUser):
    """
    创建用户
    :param post: CreateUser
    :return:
    """
    # 过滤用户
    get_user = await User.get_or_none(username=post.username)
    if get_user:
        return fail(msg=f"用户名{post.username}已经存在!")
    post.password = en_password(post.password)

    # 创建用户
    create_user = await User.create(**post.dict())
    if not create_user:
        return fail(msg=f"用户{post.username}创建失败!")
    if post.roles:
        # 有分配角色
        roles = await Role.filter(id__in=post.roles, role_status=True)
        await create_user.role.add(*roles)
    return success(msg=f"用户{create_user.username}创建成功")


@router.delete("", summary="用户删除", dependencies=[Security(check_permissions, scopes=["user_delete"])])
async def user_del(req: Request, user_id: int):
    """
    删除用户
    :param req:
    :param user_id: int
    :return:
    """
    if req.state.user_id == user_id:
        return fail(msg="你不能把自己踢出局吧?")
    delete_action = await User.filter(pk=user_id).delete()
    if not delete_action:
        return fail(msg=f"用户{user_id}删除失败!")
    return success(msg="删除成功")


@router.put("", summary="用户修改", dependencies=[Security(check_permissions, scopes=["user_update"])])
async def user_update(req: Request, post: user.UpdateUser):
    """
    更新用户信息
    :param post:
    :return:
    """
    # 只有超级管理员可以修改用户
    if not req.state.user_type:
        return fail(msg="只有超级管理员才可以修改用户!")

    user_check = await User.get_or_none(pk=post.id)
    # 不存在的用户
    if not user_check:
        return fail(msg="用户不存在") 
    if user_check.username != post.username:
        check_username = await User.get_or_none(username=post.username)
        if check_username:
            return fail(msg=f"用户名{check_username.username}已存在")
    # 新密码
    if post.password:
        post.password = en_password(post.password)

    data = post.dict(exclude_none=True)
    if not post.password:
        data.pop("password")
    data.pop("id")
    await User.filter(pk=post.id).update(**data)
    return success(msg="更新成功!")


@router.put("/set/role", summary="角色分配", dependencies=[Security(check_permissions, scopes=["user_role"])])
async def set_role(post: user.SetRole):
    """
    角色分配
    :param post:
    :return:
    """
    user_obj = await User.get_or_none(pk=post.user_id)
    if not user_obj:
        return fail(msg="用户不存在!")
    # 清空角色
    await user_obj.role.clear()
    # 修改权限
    if post.roles:
        roles = await Role.filter(role_status=True, id__in=post.roles).all()
        # 分配角色
        await user_obj.role.add(*roles)

    return success(msg="角色分配成功!")


@router.get("",
            summary="用户列表",
            response_model=user.UserListData,
            dependencies=[Security(check_permissions, scopes=["user_query"])]
            )
async def user_list(
        pageSize: int = 10,
        current: int = 1,
        username: str = Query(None),
        user_phone: str = Query(None),
        user_status: bool = Query(None),
        create_time: List[str] = Query(None)

):
    """
    获取所有管理员
    :return:
    """
    # 查询条件
    query = {}
    if username:
        query.setdefault('username', username)
    if user_phone:
        query.setdefault('user_phone', user_phone)
    if user_status is not None:
        query.setdefault('user_status', user_status)
    if create_time:
        query.setdefault('create_time__range', create_time)

    user_data = User.annotate(key=F("id")).filter(**query).filter(id__not=1).all()
    # 总数
    total = await user_data.count()
    # 查询
    data = await user_data.limit(pageSize).offset(pageSize * (current - 1)).order_by("-create_time") \
        .values(
        "key", "id", "username", "user_type", "user_phone", "user_email",
        "user_status", "header_img", "sex", "remarks", "create_time", "update_time")

    return res_antd(code=True, data=data, total=total)


@router.get("/info",
            summary="获取当前用户信息",
            response_model=user.CurrentUser,
            dependencies=[Security(check_permissions)]
            )
async def user_info(req: Request):
    """
    获取当前登陆用户信息
    :return:
    """
    user_data = await User.get_or_none(pk=req.state.user_id)
    if not user_data:
        return fail(msg=f"用户ID{req.state.user_id}不存在!")
    # 非超级管理员
    access = []
    if not req.state.user_type:
        # 二级菜单权限
        two_level_access = await Access.filter(role__user__id=req.state.user_id, is_check=True).values_list("parent_id")
        two_level_access = [i[0] for i in two_level_access]
        # 一级菜单权限
        one_level_access = await Access.filter(id__in=list(set(two_level_access))).values_list("parent_id")
        one_level_access = [i[0] for i in one_level_access]

        query_access = await Access.filter(id__in=list(set(one_level_access + two_level_access))).values_list("scopes")
        access = [i[0] for i in query_access]
    # 处理手机号 ****
    if user_data.user_phone:
        user_data.user_phone = user_data.user_phone.replace(user_data.user_phone[3:7], "****")
    # 将作用域加入到用户信息中
    user_data.__setattr__("scopes", access)

    return success(msg="用户信息", data=user_data.__dict__)


@router.post("/account/login", response_model=user.UserLogin, summary="用户登陆")
async def account_login(req: Request, post: user.AccountLogin):
    """
    用户登陆
    :param req:
    :param post:
    :return: jwt token
    """
    if post.username and post.password:
        # 账号密码登陆
        get_user = await User.get_or_none(username=post.username)
        if not get_user:
            return fail(msg=f"用户{post.username}密码验证失败!")
        if not get_user.password:
            return fail(msg=f"用户{post.username}密码验证失败!")
        if not check_password(post.password, get_user.password):
            return fail(msg=f"用户{post.username}密码验证失败!")
        if not get_user.user_status:
            return fail(msg=f"用户{post.username}已被管理员禁用!")
        jwt_data = {
            "user_id": get_user.pk,
            "user_type": get_user.user_type
        }
        jwt_token = create_access_token(data=jwt_data)
        data = {"token": jwt_token, "expires_in": settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60}
        await write_access_log(req, get_user.pk, "通过用户名登陆了系统!")
        return success(msg="登陆成功", data=data)

    return fail(msg="登陆失败!")

@router.post("/account/admin_register", summary="超级管理员注册", description="本接口不开放, 只针对超级管理员注册, 这里注册的是普通管理员, 需要在数据库自行修改成超管.")
async def account_register(post: user.AccountLogin):
    """
    超管注册
    :param post:
    :return:
    """
    if post.username and post.password:
        # 过滤用户
        get_user = await User.get_or_none(username=post.username)
        if get_user:
            return fail(msg=f"用户名{post.username}已经存在!")
        post.password = en_password(post.password)
        # 创建用户
        create_user = await User.create(**post.dict())
        if not create_user:
            return fail(msg=f"超管{post.username}创建失败!")
        return success(msg=f"超管{create_user.username}创建成功, 请返回登陆!")
    return fail(msg="超管创建失败!")



@router.get("/access/log", dependencies=[Security(check_permissions)], summary="用户访问记录")
async def get_access_log(req: Request):
    """
    查询当前用户访问记录
    :param req:
    :return:
    """
    log = await AccessLog().filter(user_id=req.state.user_id).limit(10).order_by("-create_time") \
        .values("create_time", "ip", "note", "id")

    return success(msg="access log", data=log)


@router.put("/info", dependencies=[Security(check_permissions)], summary="用户基本信息修改")
async def update_user_info(req: Request, post: UpdateUserInfo):
    """
    修改个人信息
    :param req:
    :param post:
    :return:
    """
    await User.filter(id=req.state.user_id).update(**post.dict(exclude_none=True))
    return success(msg="更新成功!")
